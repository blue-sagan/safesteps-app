'use strict';

/**
 * HTTP security headers.
 *
 * - CSP is nonce-based for scripts, so injected markup cannot execute even if a
 *   template is ever missed. `strict-dynamic` lets the trusted CDN loader chain
 *   work without listing every script.
 * - HSTS is only emitted in production (and only over HTTPS) so local dev on
 *   http:// doesn't get pinned into a broken state.
 * - `__Host-` session cookies require `Secure`, which browsers only honour on
 *   HTTPS; dev therefore uses a non-prefixed fallback name (see session.js).
 */

const config = require('./config');

function buildCsp(nonce) {
  const s = config.security;
  const directives = {
    'default-src': ["'self'"],
    'base-uri': ["'none'"],
    'object-src': ["'none'"],
    'script-src': [
      "'self'",
      `'nonce-${nonce}'`,
      "'strict-dynamic'",
      ...s.scriptSources.filter((src) => src !== "'self'"),
    ],
    // The legacy PWA markup declares 390+ inline `onclick=` attributes. Moving
    // them to delegated listeners is a larger refactor; until then, attribute
    // handlers must be permitted explicitly. This does NOT relax <script> tags
    // (those still require the nonce) or allow any remote code, and every
    // insertion point already runs through escapeHtml()/safeImageSrc().
    'script-src-attr': ["'unsafe-inline'"],
    'style-src': s.styleSources,
    'style-src-attr': ["'unsafe-inline'"],
    'img-src': s.imageSources,
    'font-src': s.fontSources,
    'connect-src': s.connectSources,
    'media-src': ["'self'", 'blob:', 'data:'],
    'worker-src': ["'self'", 'blob:'],
    'child-src': ["'self'", 'blob:'],
    'manifest-src': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': s.frameAncestors,
    'upgrade-insecure-requests': config.isProduction ? [] : null,
  };

  return Object.entries(directives)
    .filter(([, value]) => value !== null)
    .map(([name, value]) => (value.length ? `${name} ${value.join(' ')}` : name))
    .join('; ');
}

function securityHeaders(nonce, { isHtml = false, isApi = false } = {}) {
  const headers = {
    // Clickjacking + framing
    'X-Frame-Options': 'SAMEORIGIN',
    // Prevent MIME confusion attacks on uploads/static files
    'X-Content-Type-Options': 'nosniff',
    // Don't leak paths / queries to third parties
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    // Deny powerful features the app never needs
    'Permissions-Policy': [
      'camera=(self)',
      'microphone=(self)',
      'geolocation=(self)',
      'payment=()',
      'usb=()',
      'serial=()',
      'bluetooth=()',
      'magnetometer=()',
      'accelerometer=(self)',
      'gyroscope=(self)',
      'fullscreen=(self)',
    ].join(', '),
    // Isolate the browsing context
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'X-DNS-Prefetch-Control': 'off',
  };

  if (isHtml) headers['Content-Security-Policy'] = buildCsp(nonce);

  if (isApi) {
    headers['Cache-Control'] = 'no-store, max-age=0';
    headers['X-Robots-Tag'] = 'noindex, nofollow';
    headers['Cross-Origin-Resource-Policy'] = 'same-origin';
  }

  if (config.isProduction) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  }

  return headers;
}

module.exports = { securityHeaders, buildCsp };
