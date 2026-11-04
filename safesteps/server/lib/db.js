'use strict';

/**
 * Parameterised database access.
 *
 * The production path is PostgREST over HTTP, which is parameterised by
 * construction (values travel as query parameters / JSON body, never
 * concatenated into SQL). For local deployments and tests we speak to SQLite
 * through node:sqlite's prepared statements — again, every value is bound as a
 * parameter.
 *
 * This module exists as the single choke point so that a future swap to a
 * different driver cannot introduce string-built SQL: callers only get
 * `query(sql, params)` with an explicit placeholder array.
 */

const crypto = require('node:crypto');

/* ------------------------------------------------------------------------- */
/* Local SQLite-backed store (used for the verification/rate-limit path when   */
/* the server runs standalone without Supabase service credentials).          */
/* ------------------------------------------------------------------------- */

let db = null;
let sqlite = null;

function getDb() {
  if (db) return db;
  // node:sqlite is shipped with Node 22+; keep the import lazy so the server
  // still boots on runtimes without it (Supabase path is then mandatory).
  ({ DatabaseSync: sqlite } = require('node:sqlite'));
  const file = process.env.SQLITE_PATH || ':memory:';
  db = new sqlite(file);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS verification_challenges (
      id            TEXT PRIMARY KEY,
      email_hash    TEXT NOT NULL,
      code_hash     TEXT NOT NULL,
      name_hash     TEXT NOT NULL,
      expires_at    INTEGER NOT NULL,
      attempts      INTEGER NOT NULL DEFAULT 0,
      consumed_at   INTEGER,
      created_at    INTEGER NOT NULL,
      user_id       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_challenges_email
      ON verification_challenges (email_hash, created_at DESC);

    CREATE TABLE IF NOT EXISTS rate_limits (
      bucket       TEXT NOT NULL,
      key_hash     TEXT NOT NULL,
      window_start INTEGER NOT NULL,
      count        INTEGER NOT NULL DEFAULT 0,
      expires_at   INTEGER NOT NULL,
      PRIMARY KEY (bucket, key_hash, window_start)
    );

    CREATE TABLE IF NOT EXISTS outbound_mail (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient  TEXT NOT NULL,
      subject    TEXT NOT NULL,
      body       TEXT NOT NULL,
      channel    TEXT NOT NULL DEFAULT 'email',
      status     TEXT NOT NULL DEFAULT 'queued',
      error      TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS community_counts (
      category   TEXT NOT NULL,
      counted_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_audit (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      event      TEXT NOT NULL,
      detail     TEXT,
      created_at INTEGER NOT NULL
    );
  `);
  return db;
}

/** Run a parameterised statement. Never interpolate values into `sql`. */
function query(sql, params = []) {
  if (typeof sql !== 'string') throw new TypeError('query() expects a SQL string');
  if (!Array.isArray(params)) throw new TypeError('query() expects a params array');
  const statement = getDb().prepare(sql);
  const verb = sql.trim().split(/\s+/)[0].toUpperCase();
  if (verb === 'SELECT' || verb === 'WITH') return statement.all(...params);
  return statement.run(...params);
}

/* ------------------------------------------------------------------------- */
/* PostgREST helpers (parameterised over HTTPS, RLS enforced server-side)     */
/* ------------------------------------------------------------------------- */

function restUrl(pathname, searchParams) {
  const base = process.env.SUPABASE_URL.replace(/\/+$/, '');
  const url = new URL(`${base}/rest/v1/${pathname.replace(/^\/+/, '')}`);
  for (const [key, value] of Object.entries(searchParams || {})) {
    if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
  }
  return url;
}

/**
 * Call PostgREST as the given user. `accessToken` is the *user's* JWT, so
 * Postgres evaluates RLS as `authenticated` and every query is additionally
 * filtered by the row policies — there is no way to reach another user's rows.
 */
async function rest(pathname, { method = 'GET', accessToken, body, searchParams, prefer } = {}) {
  const key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!key) throw new Error('SUPABASE_PUBLISHABLE_KEY is not configured');
  const headers = {
    apikey: key,
    Authorization: `Bearer ${accessToken || key}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (prefer) headers.Prefer = prefer;

  const response = await fetch(restUrl(pathname, searchParams), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await response.text();
  const parsed = text ? safeJson(text) : null;
  return { ok: response.ok, status: response.status, body: parsed, raw: text };
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------- */
/* Crypto helpers (used for fingerprints and server-side encryption)          */
/* ------------------------------------------------------------------------- */

/**
 * Keyed hash. We store *fingerprints* of emails and verification codes rather
 * than the values themselves: a database dump cannot be used to enumerate
 * accounts or forge a code.
 */
function fingerprint(value, pepper) {
  return crypto.createHmac('sha256', pepper).update(String(value)).digest('hex');
}

function timingSafeEqualHex(a, b) {
  const bufA = Buffer.from(String(a), 'hex');
  const bufB = Buffer.from(String(b), 'hex');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * AES-256-GCM at rest encryption for server-held data (outbound mail bodies,
 * anything the server must be able to read back). Format: v1.iv.tag.ct (base64).
 */
function encryptAtRest(plaintext, keyBase64) {
  if (!keyBase64) throw new Error('SERVER_DATA_KEY is not configured');
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) throw new Error('SERVER_DATA_KEY must be 32 bytes (base64)');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64'), tag.toString('base64'), ciphertext.toString('base64')].join('.');
}

function decryptAtRest(payload, keyBase64) {
  const [version, ivB64, tagB64, ctB64] = String(payload).split('.');
  if (version !== 'v1') throw new Error('Unsupported ciphertext version');
  const key = Buffer.from(keyBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

module.exports = {
  query,
  getDb,
  rest,
  restUrl,
  fingerprint,
  timingSafeEqualHex,
  encryptAtRest,
  decryptAtRest,
  safeJson,
};
