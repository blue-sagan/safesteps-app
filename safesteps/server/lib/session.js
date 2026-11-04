'use strict';

/**
 * Session handling.
 *
 * The browser never stores a token in localStorage / sessionStorage / IndexedDB
 * where any XSS payload could read it. Instead the server issues cookies:
 *
 *   __Host-ss_session   access token (JWT), HttpOnly, Secure, SameSite=Strict,
 *                       Path=/, Max-Age 1h, __Host- prefix (no Domain, no
 *                       parent-path scope, cannot be overwritten by a sibling
 *                       host or a plain-HTTP origin).
 *   __Host-ss_refresh   refresh token, HttpOnly, Secure, SameSite=Strict,
 *                       Path=/api/auth, Max-Age 30d.
 *   __Host-ss_csrf      double-submit CSRF token, readable by JS on purpose,
 *                       must be echoed in the X-CSRF-Token header.
 *
 * Supabase refresh-token rotation is enabled on the project, and the server
 * keeps only the rotated pair it last issued.
 */

const crypto = require('node:crypto');
const config = require('./config');

function cookieName(kind) {
  const names = {
    session: config.security.sessionCookie,
    refresh: config.security.refreshCookie,
    csrf: config.security.sessionCookie.replace('session', 'csrf'),
  };
  const name = names[kind];
  // `__Host-` requires Secure + Path=/ + no Domain. Browsers drop such cookies
  // over plain HTTP, so local development uses the bare name instead.
  return config.isProduction ? name : name.replace(/^__Host-/, '');
}

function serialize(name, value, { maxAge, path = '/', httpOnly = true } = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
    'SameSite=Strict',
  ];
  if (httpOnly) parts.push('HttpOnly');
  if (config.isProduction) parts.push('Secure');
  // `__Host-` forbids Domain entirely — never emit one.
  return parts.join('; ');
}

function csrfToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function setSessionCookies(res, { accessToken, refreshToken, csrf }) {
  const s = config.security;
  const cookies = [
    serialize(cookieName('session'), accessToken, { maxAge: s.sessionMaxAgeSeconds, path: '/' }),
    serialize(cookieName('refresh'), refreshToken, {
      maxAge: s.refreshMaxAgeSeconds,
      path: config.isProduction ? '/api/auth' : '/api/auth',
    }),
    // Readable by the app so it can echo it back in the header.
    serialize(cookieName('csrf'), csrf, {
      maxAge: s.refreshMaxAgeSeconds,
      path: '/',
      httpOnly: false,
    }),
  ];
  appendCookies(res, cookies);
}

/** Refresh only (the access token cookie keeps its own 1h sliding lifetime). */
function setAccessCookie(res, accessToken) {
  appendCookies(res, [
    serialize(cookieName('session'), accessToken, {
      maxAge: config.security.sessionMaxAgeSeconds,
      path: '/',
    }),
  ]);
}

function clearSessionCookies(res) {
  const expired = [
    serialize(cookieName('session'), '', { maxAge: 0, path: '/' }),
    serialize(cookieName('refresh'), '', { maxAge: 0, path: '/api/auth' }),
    serialize(cookieName('csrf'), '', { maxAge: 0, path: '/', httpOnly: false }),
  ];
  appendCookies(res, expired);
}

function appendCookies(res, cookies) {
  const existing = res.getHeader('Set-Cookie');
  const list = existing ? [].concat(existing, cookies) : cookies;
  res.setHeader('Set-Cookie', list);
}

/**
 * CSRF defence for state-changing requests:
 *  - SameSite=Strict already blocks cross-site cookie attachment.
 *  - Additionally require Origin/Referer to match this origin, and a
 *    double-submit token (cookie value === header value).
 */
function assertSameOrigin(req) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const expected = config.publicOrigin || `http://${req.headers.host}`;
  const candidate = origin || (referer ? new URL(referer).origin : '');
  if (!candidate) {
    // Some same-origin form posts omit both on very old browsers; the
    // double-submit token still protects us, so only log.
    return;
  }
  if (candidate !== expected && candidate !== `http://${req.headers.host}` && candidate !== `https://${req.headers.host}`) {
    const err = new Error('Cross-origin request blocked.');
    err.status = 403;
    err.code = 'csrf_origin_mismatch';
    throw err;
  }
}

function assertCsrf(req, cookies) {
  const header = req.headers['x-csrf-token'];
  const cookie = cookies[cookieName('csrf')];
  if (!header || !cookie) {
    const err = new Error('Missing CSRF token. Reload the app and try again.');
    err.status = 403;
    err.code = 'csrf_missing';
    throw err;
  }
  const a = Buffer.from(String(header));
  const b = Buffer.from(String(cookie));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    const err = new Error('Invalid CSRF token. Reload the app and try again.');
    err.status = 403;
    err.code = 'csrf_invalid';
    throw err;
  }
}

module.exports = {
  cookieName,
  csrfToken,
  setSessionCookies,
  setAccessCookie,
  clearSessionCookies,
  assertSameOrigin,
  assertCsrf,
};
