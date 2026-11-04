'use strict';

/**
 * Small HTTP helpers: body reading with a hard cap, cookie parsing, client
 * fingerprinting and JSON responses that never leak internals.
 */

const crypto = require('node:crypto');
const { MAX_BODY_BYTES, ValidationError } = require('./validate');
const config = require('./config');

/** Read the request body with a hard byte cap (rejects early, before buffering it all). */
function readBody(req, { limit = MAX_BODY_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] || 0);
    if (declared && declared > limit) {
      const err = new ValidationError({ _: 'Request body too large.' });
      err.status = 413;
      reject(err);
      req.resume();
      return;
    }

    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        const err = new ValidationError({ _: 'Request body too large.' });
        err.status = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req, { limit = MAX_BODY_BYTES } = {}) {
  const type = String(req.headers['content-type'] || '');
  if (!type.toLowerCase().startsWith('application/json')) {
    const err = new ValidationError({ _: 'Content-Type must be application/json.' });
    err.status = 415;
    throw err;
  }
  const buffer = await readBody(req, { limit });
  if (buffer.length === 0) return {};
  let parsed;
  try {
    parsed = JSON.parse(buffer.toString('utf8'));
  } catch {
    const err = new ValidationError({ _: 'Malformed JSON body.' });
    err.status = 400;
    throw err;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    const err = new ValidationError({ _: 'Body must be a JSON object.' });
    err.status = 400;
    throw err;
  }
  return parsed;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = Object.create(null);
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      /* ignore malformed cookie */
    }
  }
  return out;
}

/** Narrow the silly-and-wider toolchain: only allow cookie *values* we issued. */
const COOKIE_VALUE_RE = /^[A-Za-z0-9._~+/=-]{8,4096}$/;

function readSessionCookie(req) {
  const cookies = parseCookies(req);
  const name = config.isProduction ? config.security.sessionCookie : config.security.sessionCookie.replace('__Host-', '');
  const value = cookies[name];
  if (!value || !COOKIE_VALUE_RE.test(value)) return null;
  return value;
}

function readRefreshCookie(req) {
  const cookies = parseCookies(req);
  const name = config.isProduction ? config.security.refreshCookie : config.security.refreshCookie.replace('__Host-', '');
  const value = cookies[name];
  if (!value || !COOKIE_VALUE_RE.test(value)) return null;
  return value;
}

/**
 * Client identifier for rate limiting.
 * Uses the proxy-provided address when trusted; the value is hashed before it
 * is ever stored, so we never keep raw IP addresses.
 */
function clientKey(req) {
  const forwarded = config.trustProxy ? String(req.headers['x-forwarded-for'] || '') : '';
  const ip = (forwarded.split(',')[0] || '').trim() || req.socket.remoteAddress || 'unknown';
  const ua = String(req.headers['user-agent'] || '').slice(0, 200);
  return `${ip}|${ua}`;
}

function clientIpHash(req) {
  return crypto.createHash('sha256').update(clientKey(req)).digest('hex').slice(0, 32);
}

function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

/**
 * Error responder. Only validation errors (which we authored) and explicit
 * `status < 500` errors surface to clients; everything else becomes a generic
 * 500 so stack traces, SQL text and upstream URLs never reach the browser.
 */
function sendError(res, error, headers = {}) {
  const status = Number(error && error.status) || 500;
  if (status >= 500) {
    console.error('[error]', error && error.message ? error.message : error);
    sendJson(res, 500, { error: 'server_error', message: 'Something went wrong. Please try again.' }, headers);
    return;
  }
  const payload = { error: error.code || 'invalid_request', message: error.message || 'Invalid request.' };
  if (error.fields) payload.fields = error.fields;
  if (error.retryAfter) headers['Retry-After'] = String(error.retryAfter);
  sendJson(res, status, payload, headers);
}

module.exports = {
  readBody,
  readJson,
  parseCookies,
  readSessionCookie,
  readRefreshCookie,
  clientKey,
  clientIpHash,
  sendJson,
  sendError,
};
