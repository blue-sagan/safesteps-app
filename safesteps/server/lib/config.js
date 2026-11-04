'use strict';

/**
 * Central configuration. Everything read here comes from the environment —
 * there are no hard-coded credentials anywhere in this repository.
 *
 * Hard rule enforced by test/security.test.js: only SUPABASE_URL and
 * SUPABASE_PUBLISHABLE_KEY may ever be handed to the browser.
 */

const path = require('node:path');
const crypto = require('node:crypto');

// Minimal .env loader (no third-party dependency). Existing environment
// variables always win, so container/platform config is authoritative.
function loadDotEnv(file) {
  const fs = require('node:fs');
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!Object.prototype.hasOwnProperty.call(process.env, key)) {
      process.env[key] = value;
    }
  }
}

loadDotEnv(path.join(__dirname, '..', '.env'));

const isProduction = process.env.NODE_ENV === 'production';

function required(name, { allowInDev = false } = {}) {
  const value = (process.env[name] || '').trim();
  if (value) return value;
  if (!isProduction && allowInDev) return '';
  throw new Error(
    `Missing required environment variable ${name}. ` +
      'Copy server/.env.example to server/.env and fill it in.'
  );
}

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value));
}

const supabaseUrl = required('SUPABASE_URL').replace(/\/+$/, '');
const publishableKey = required('SUPABASE_PUBLISHABLE_KEY');

// Server-only. Optional at boot so the app still starts (and fails closed on
// the one flow that needs it) rather than crash-looping in production.
const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

const verificationPepper =
  (process.env.VERIFICATION_PEPPER || '').trim() ||
  (isProduction ? required('VERIFICATION_PEPPER') : crypto.randomBytes(32).toString('hex'));

const serverDataKey = (process.env.SERVER_DATA_KEY || '').trim();

const config = {
  isProduction,
  port: Number(process.env.PORT || 8080),
  host: process.env.HOST || '0.0.0.0',
  publicOrigin: (process.env.PUBLIC_ORIGIN || '').replace(/\/+$/, ''),
  trustProxy: bool(process.env.TRUST_PROXY, true),

  supabase: {
    url: supabaseUrl,
    // Public by design. RLS is what protects the data, not this key's secrecy.
    publishableKey,
    // Secret. Never leaves the server process.
    serviceRoleKey,
  },

  security: {
    verificationPepper,
    serverDataKey,
    // Session cookie name/lifetime. The cookie carries ONLY the Supabase access
    // token; the refresh token stays in the httpOnly refresh cookie.
    sessionCookie: '__Host-ss_session',
    refreshCookie: '__Host-ss_refresh',
    sessionMaxAgeSeconds: 60 * 60, // 1 hour, matches Supabase JWT exp
    refreshMaxAgeSeconds: 60 * 60 * 24 * 30,
    // Rolling-window limits: [maxRequests, windowMs]
    rateLimits: {
      login: [10, 15 * 60 * 1000],
      register: [5, 60 * 60 * 1000],
      verify: [10, 15 * 60 * 1000],
      forgot: [5, 60 * 60 * 1000],
      api: [300, 60 * 1000],
      upload: [30, 60 * 1000],
      global: [1200, 60 * 1000],
    },
    // Upload policy. MIME allow-list is checked against the *sniffed* bytes,
    // not the client-supplied Content-Type.
    uploads: {
      maxBytes: 8 * 1024 * 1024,
      allowed: new Set([
        'image/jpeg',
        'image/png',
        'image/webp',
        'audio/webm',
        'audio/mpeg',
        'video/mp4',
        'video/webm',
      ]),
    },
    // Hosts the browser may be told to connect to (CSP connect-src).
    connectSources: [
      "'self'",
      supabaseUrl,
      'https://api.open-meteo.com',
      'https://*.tile.openstreetmap.org',
      'https://mt1.google.com',
    ],
    scriptSources: [
      "'self'",
      'https://cdnjs.cloudflare.com',
      'https://cdn.jsdelivr.net',
    ],
    styleSources: [
      "'self'",
      "'unsafe-inline'", // Leaflet sets inline styles at runtime
      'https://cdnjs.cloudflare.com',
      'https://cdn.jsdelivr.net',
      'https://fonts.googleapis.com',
    ],
    imageSources: [
      "'self'",
      'data:',
      'blob:',
      'https://*.tile.openstreetmap.org',
      'https://mt1.google.com',
      'https://maps.google.com',
    ],
    fontSources: ["'self'", 'data:', 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
    frameAncestors: ["'self'"],
  },

  paths: {
    // The PWA itself ships from safesteps/ unchanged (offline-first).
    staticRoot: path.join(__dirname, '..', '..'),
  },
};

if (isProduction && !config.publicOrigin) {
  throw new Error('PUBLIC_ORIGIN must be set in production (used for CORS and cookies).');
}

module.exports = config;
