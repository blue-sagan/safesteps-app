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

/**
 * A missing credential must never take the whole app down: the PWA and every
 * offline feature are useful with zero configuration, and a hard crash at boot
 * only turns a partial outage into a total one. So required values degrade with
 * a loud warning, and the features that need them fail with an explicit,
 * actionable error instead (see `config.warnings` and GET /healthz).
 */
const warnings = [];

function required(name, { allowInDev = false } = {}) {
  const value = (process.env[name] || '').trim();
  if (value) return value;
  if (!isProduction && allowInDev) return '';
  warnings.push(
    `${name} is not set — features that require it will respond with a clear ` +
      '503 instead of working. See server/.env.example.'
  );
  return '';
}

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value));
}

const supabaseUrl = required('SUPABASE_URL').replace(/\/+$/, '');
const publishableKey = required('SUPABASE_PUBLISHABLE_KEY');

/**
 * Supabase's Send Email Hook. When set, the auth service mails through us
 * instead of its own mailer — which is what lets /verify return a real session
 * without the service-role key.
 */
function hookConfigured() {
  return Boolean((process.env.SEND_EMAIL_HOOK_SECRET || '').trim());
}

/** True when at least one outbound transport can actually deliver. */
function mailTransportConfigured() {
  return Boolean(
    (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) ||
      (process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID && process.env.EMAILJS_PUBLIC_KEY) ||
      (supabaseUrl && publishableKey)
  );
}

// Features that cannot work without credentials, checked at request time.
const capabilities = () => ({
  auth: Boolean(supabaseUrl && publishableKey),
  // Email sign-in works in two shapes, neither of which needs us to write a
  // "confirmed" flag:
  //   hook  — the auth service issues the code, posts it to
  //           /api/hooks/send-email, we relay it, and /verify trades the code
  //           for a session. No service-role key anywhere in the flow.
  //   admin — no hook, so we generate the code and confirm the address through
  //           the admin API, which does need the service-role key.
  emailVerification: Boolean(
    supabaseUrl && publishableKey && (hookConfigured() || (serviceRoleKey && mailTransportConfigured()))
  ),
  // True when at least one transport can actually deliver: SMTP, the EmailJS
  // REST API, or Supabase Auth's own mailer. The specific transport is reported
  // separately (booleans only) by config.mailTransports().
  mailTransport: mailTransportConfigured(),
  atRestEncryption: Boolean(serverDataKey),
});

// Server-only. Optional at boot so the app still starts (and fails closed on
// the one flow that needs it) rather than crash-looping in production.
const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

let verificationPepper = (process.env.VERIFICATION_PEPPER || '').trim();
if (!verificationPepper) {
  if (isProduction) {
    required('VERIFICATION_PEPPER');
  }
  // Ephemeral pepper: codes issued before a restart stop validating. Acceptable
  // for a dev/sandbox run, never for production — hence the warning above.
  verificationPepper = crypto.randomBytes(32).toString('hex');
  if (!isProduction && !process.env.VERIFICATION_PEPPER) {
    warnings.push('VERIFICATION_PEPPER not set — using an ephemeral value (codes expire on restart).');
  }
}

const serverDataKey = (process.env.SERVER_DATA_KEY || '').trim();
if (!serverDataKey) {
  warnings.push(
    'SERVER_DATA_KEY not set — queued mail is stored unencrypted and /api/vault is disabled.'
  );
}

/**
 * Which environment this process is.
 *
 * `NODE_ENV` alone is not enough: it says "not production" for both a developer
 * laptop and a staging deployment that holds near-real data. The brief asks for
 * a distinct visual banner in production and unique credentials per environment,
 * and both need a name more specific than a boolean.
 *
 *   production  NODE_ENV=production  (or SAFESTEPS_ENV=production)
 *   staging     SAFESTEPS_ENV=staging
 *   development everything else
 *
 * A value that is set but unrecognised is treated as production, not as
 * development. Guessing "development" for a typo would silently disable the
 * production banner and the production credential checks, which is exactly the
 * mistake this is meant to prevent.
 */
function resolveEnvironment() {
  const declared = String(process.env.SAFESTEPS_ENV || '').trim().toLowerCase();
  if (declared === 'production' || declared === 'staging' || declared === 'development') return declared;
  if (declared) {
    warnings.push(
      `SAFESTEPS_ENV="${declared}" is not a known environment (production|staging|development). ` +
        'Treating this process as production, because assuming development would hide the production banner.'
    );
    return 'production';
  }
  return isProduction ? 'production' : 'development';
}

const environment = resolveEnvironment();

const config = {
  isProduction,
  environment,
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
      // Completing a reset is a code-guessing surface, so it is capped tighter
      // than login rather than looser.
      reset: [5, 15 * 60 * 1000],
      api: [300, 60 * 1000],
      // Bug reports. A real user hitting several genuine defects in one session
      // must not be locked out (5/hour, the forgot-password budget, did exactly
      // that) and reporting a bug must not consume the password-reset budget.
      // Still far too few to use as a message queue.
      bugreport: [20, 60 * 60 * 1000],
      upload: [30, 60 * 1000],
      // Deleting records. Deliberately tight: a legitimate user tidies a handful
      // of reports, they do not issue dozens of delete calls a minute. This also
      // caps how fast a stolen session could churn through a user's history.
      deletion: [20, 60 * 1000],
      global: [1200, 60 * 1000],
      // Analytics ingest. Generous enough for real use (events are batched, so a
      // session is a handful of requests) but low enough that it cannot be used
      // to flood the events table.
      analytics: [60, 60 * 1000],
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
  warnings.push(
    'PUBLIC_ORIGIN is not set. Cookies, CSRF origin checks and email links rely on it; ' +
      'requests are accepted from the Host header instead, which is weaker.'
  );
}

config.warnings = warnings;

if (warnings.length) {
  console.warn('\nSafeSteps configuration warnings:');
  for (const warning of warnings) console.warn(`  • ${warning}`);
  console.warn('');
}

/**
 * Environment isolation checks.
 *
 * The brief asks for separate databases and unique credentials per environment.
 * Those are provisioning decisions, and no amount of application code can create
 * a second project — but code CAN refuse to start in the most dangerous
 * misconfiguration: a production process wired to a development database, or
 * two environments sharing a project ref.
 *
 * `SAFESTEPS_EXPECTED_PROJECT_REF` is the pin. When set, this process refuses to
 * serve unless the configured SUPABASE_URL is that project. That turns "we
 * deployed with last month's .env" from a silent data-mixing bug into a boot
 * failure.
 */
function projectRefFromUrl(url) {
  const match = String(url || '').match(/^https?:\/\/([a-z0-9]{20})\.supabase\.(co|in)/i);
  return match ? match[1] : null;
}

const projectRef = projectRefFromUrl(supabaseUrl);
const expectedRef = String(process.env.SAFESTEPS_EXPECTED_PROJECT_REF || '').trim();

config.projectRef = projectRef;

config.environmentIsolation = () => {
  const problems = [];

  // 1. A pinned project that does not match is a hard error, not a warning:
  //    continuing would write production data into the wrong database.
  if (expectedRef && supabaseUrl) {
    if (!projectRef) {
      problems.push(
        `SAFESTEPS_EXPECTED_PROJECT_REF is set to ${expectedRef}, but SUPABASE_URL is not a recognised Supabase project URL.`
      );
    } else if (projectRef !== expectedRef) {
      problems.push(
        `This process is pinned to project ${expectedRef} but SUPABASE_URL points at ${projectRef}. ` +
          'Refusing to mix environments.'
      );
    }
  }

  // 2. Production must not be pointed at a project it shares with a named
  //    development run. There is no way to detect this from inside one process;
  //    what can be detected is the common slip of running "production" locally.
  if (environment === 'production') {
    const host = String(process.env.PUBLIC_ORIGIN || '');
    if (/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:|\/|$)/i.test(host)) {
      problems.push(
        'SAFESTEPS_ENV is production but PUBLIC_ORIGIN is a loopback address. ' +
          'This looks like a production build pointed at a local database.'
      );
    }
  }

  return { ok: problems.length === 0, problems, projectRef, expectedRef: expectedRef || null };
};

config.capabilities = capabilities;

/**
 * Which mail transports are configured — never the credentials themselves.
 * Reporting these lets an operator confirm "EmailJS is live" from /healthz
 * without ever exposing the key.
 */
/**
 * Which route confirms an address:
 *   'hook'  — Supabase Send Email Hook (no service-role key needed)
 *   'admin' — service-role key + our own code
 *   'none'  — email sign-in cannot complete
 * Operator information, not a capability, so it never affects `degraded`.
 */
config.confirmRoute = () => {
  if (hookConfigured()) return 'hook';
  if (supabaseUrl && publishableKey && serviceRoleKey) return 'admin';
  return 'none';
};

config.mailTransports = () => ({
  smtp: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
  emailjs: Boolean(
    process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID && process.env.EMAILJS_PUBLIC_KEY
  ),
  supabaseAuth: Boolean(supabaseUrl && publishableKey),
});

module.exports = config;
