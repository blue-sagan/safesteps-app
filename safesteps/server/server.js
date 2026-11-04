'use strict';

/**
 * SafeSteps trusted server.
 *
 * Responsibilities:
 *   • serve the offline-first PWA (unchanged static assets),
 *   • add HTTP security headers to every response,
 *   • force HTTPS (and never serve sensitive routes over plain HTTP),
 *   • terminate the public API surface and proxy to Supabase with server-side
 *     authentication, validation, rate limiting and bot checks,
 *   • keep every secret (service-role key, SMTP credentials, pepper) out of
 *     anything that can reach a browser.
 *
 * Zero runtime dependencies: node:http + built-ins only, so the dependency
 * surface (and therefore the vulnerability surface) is as small as possible.
 */

const http = require('node:http');
const { URL } = require('node:url');

const config = require('./lib/config');
const { securityHeaders } = require('./lib/security-headers');
const api = require('./lib/api');
const staticFiles = require('./lib/static');
const bot = require('./lib/bot-protection');
const session = require('./lib/session');
const { clientIpHash } = require('./lib/http');

const SENSITIVE_PREFIXES = ['/api/auth', '/api/vault', '/api/uploads', '/api/account'];

function isHttps(req) {
  if (req.socket && req.socket.encrypted) return true;
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return proto === 'https';
}

/**
 * Force HTTPS. In production a plain-HTTP request is redirected, except for
 * the health probe. Sensitive endpoints never proceed over HTTP.
 */
function enforceHttps(req, res, url) {
  if (!config.isProduction) return false;
  if (isHttps(req)) return false;
  if (url.pathname === '/healthz') return false;

  const isSensitive = SENSITIVE_PREFIXES.some((prefix) => url.pathname.startsWith(prefix));
  if (isSensitive) {
    res.writeHead(403, {
      'Content-Type': 'application/json; charset=utf-8',
      ...securityHeaders('', { isApi: true }),
    });
    res.end(JSON.stringify({ error: 'https_required', message: 'This endpoint requires HTTPS.' }));
    return true;
  }

  // Upgrade everything else rather than fail the navigation.
  const host = String(req.headers.host || '').replace(/:\d+$/, '');
  const location = `https://${host}${url.pathname}${url.search}`;
  res.writeHead(308, { Location: location, ...securityHeaders('') });
  res.end();
  return true;
}

/** Reject requests whose Host header does not match the configured origin. */
function hostAllowed(req) {
  if (!config.publicOrigin) return true; // dev without PUBLIC_ORIGIN
  const host = String(req.headers.host || '').toLowerCase();
  const allowed = new URL(config.publicOrigin).host.toLowerCase();
  // Allow localhost/127.0.0.1 probes so container/platform health checks pass.
  const bare = host.replace(/:\d+$/, '');
  if (bare === 'localhost' || bare === '127.0.0.1' || bare === '[::1]') return true;
  return host === allowed;
}

async function requestListener(req, res) {
  res.setHeader('X-Request-Id', require('node:crypto').randomUUID());

  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad request');
    return;
  }

  // Method allow-list: no TRACE/TRACK/CONNECT/PUT/PATCH on the static surface.
  const allowedMethods = new Set(['GET', 'HEAD', 'POST', 'OPTIONS', 'DELETE']);
  if (!allowedMethods.has(req.method)) {
    res.writeHead(405, { Allow: 'GET, HEAD, POST, OPTIONS', ...securityHeaders('', { isApi: true }) });
    res.end();
    return;
  }

  if (!hostAllowed(req)) {
    res.writeHead(421, { 'Content-Type': 'text/plain; charset=utf-8', ...securityHeaders('') });
    res.end('Misdirected request');
    return;
  }

  if (enforceHttps(req, res, url)) return;

  if (url.pathname === '/healthz') {
    // Liveness + which optional capabilities are configured. No secrets: only
    // booleans and a warning count, so this is safe on a public probe.
    const capabilities = config.capabilities();
    const degraded = Object.values(capabilities).some((value) => !value);
    res.writeHead(200, { 'Content-Type': 'application/json', ...securityHeaders('', { isApi: true }) });
    res.end(
      JSON.stringify({
        status: 'ok', // the process is serving; `degraded` flags missing config
        degraded,
        uptime: Math.round(process.uptime()),
        capabilities,
        configWarnings: (config.warnings || []).length,
      })
    );
    return;
  }

  if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
    // Every API response is non-cacheable and same-origin only.
    for (const [name, value] of Object.entries(securityHeaders('', { isApi: true }))) {
      res.setHeader(name, value);
    }
    if (req.method === 'OPTIONS') {
      // We do not do CORS: the app is served from this same origin.
      res.writeHead(204, { Allow: 'GET, HEAD, POST, DELETE, OPTIONS' });
      res.end();
      return;
    }
    // CSRF: state-changing API calls must prove same-origin.
    if (req.method === 'POST' || req.method === 'DELETE') {
      try {
        session.assertSameOrigin(req);
      } catch (error) {
        res.writeHead(error.status || 403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: error.code || 'forbidden', message: error.message }));
        return;
      }
    }
    await api.handle(req, res, url);
    return;
  }

  if (!hostAllowed(req)) return;
  staticFiles.serve(req, res, url.pathname);
}

function createServer() {
  const server = http.createServer((req, res) => {
    requestListener(req, res).catch((error) => {
      console.error('[fatal]', error);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      }
      res.end(JSON.stringify({ error: 'server_error', message: 'Something went wrong.' }));
    });
  });

  // Slowloris protection: cap header size and total request time.
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 60;

  return server;
}

if (require.main === module) {
  const server = createServer();
  server.listen(config.port, config.host, () => {
    console.info(
      `SafeSteps server listening on http://${config.host}:${config.port} ` +
        `(${config.isProduction ? 'production' : 'development'} mode)`
    );
    console.info(`Challenge difficulty: ${bot.DIFFICULTY} leading hex zeros`);
  });

  const shutdown = (signal) => {
    console.info(`[${signal}] draining…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => console.error('[unhandledRejection]', reason));
  process.on('uncaughtException', (error) => {
    console.error('[uncaughtException]', error);
    // Fail closed: a corrupted process should not keep serving traffic.
    process.exit(1);
  });
}

module.exports = { createServer, requestListener, enforceHttps, hostAllowed };
