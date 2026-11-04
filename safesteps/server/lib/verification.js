'use strict';

/**
 * Server-side email verification codes.
 *
 * Replaces the old client-side scheme where the 4-digit code was generated in
 * JavaScript, written to localStorage AND shown in a toast — i.e. trivially
 * readable by anyone at the keyboard and forgeable by anyone with the file.
 *
 * Now:
 *  - the code is generated with crypto.randomInt (8 digits, high entropy),
 *  - only an HMAC fingerprint of (code + email) is stored, so the plaintext
 *    code exists only inside the outbound email,
 *  - the challenge expires in 15 minutes, allows 5 attempts, and is consumed on
 *    success (single use),
 *  - verification is compared in constant time,
 *  - no endpoint ever returns or echoes the code.
 */

const crypto = require('node:crypto');
const config = require('./config');
const db = require('./db');
const mailer = require('./mailer');

const TTL_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const CODE_DIGITS = 8;

function pepper() {
  return config.security.verificationPepper;
}

function fp(value) {
  return db.fingerprint(value, pepper());
}

function newCode() {
  return String(crypto.randomInt(0, 10 ** CODE_DIGITS)).padStart(CODE_DIGITS, '0');
}

function subjectAndBody({ name, code, purpose }) {
  const isReset = purpose === 'reset';
  const subject = isReset
    ? 'Your SafeSteps password reset code'
    : 'Your SafeSteps verification code';
  const body = [
    `Hello ${name || 'there'},`,
    '',
    `Your SafeSteps ${isReset ? 'password reset' : 'verification'} code is:`,
    '',
    `    ${code}`,
    '',
    `This code expires in 15 minutes and can be used once.`,
    'If you did not request it, you can ignore this message — nobody can use the code without access to this mailbox.',
    '',
    '— SafeSteps Kenya (Project 360° Shield)',
  ].join('\n');
  return { subject, body };
}

/**
 * Create (or replace) a verification challenge and mail it out.
 * Always resolves the same way whether or not the address is already
 * registered, so the endpoint cannot be used to enumerate accounts.
 */
async function startChallenge({ email, name, purpose = 'signup', userId = null }) {
  const code = newCode();
  const now = Date.now();

  const record = {
    id: crypto.randomUUID(),
    emailHash: fp(email),
    codeHash: fp(`${email}|${code}`),
    nameHash: fp(name || ''),
    expiresAt: now + TTL_MS,
    userId,
    purpose,
  };

  if (config.supabase.serviceRoleKey) {
    try {
      // NOTE: `private` is not exposed through PostgREST, so this table must be
      // reached through the service-role-only RPC. It also carries the user id
      // link, which is what lets the verify step confirm the email.
      const persisted = await fetch(`${config.supabase.url}/rest/v1/rpc/api_create_challenge`, {
        method: 'POST',
        headers: {
          apikey: config.supabase.serviceRoleKey,
          Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          p_id: record.id,
          p_email_hash: record.emailHash,
          p_code_hash: record.codeHash,
          p_name_hash: record.nameHash,
          p_expires_at: new Date(record.expiresAt).toISOString(),
          p_user_id: userId || null,
        }),
        signal: AbortSignal.timeout(4000),
      });
      if (!persisted.ok) {
        console.error('[verify] challenge persist failed', persisted.status);
      }
    } catch (error) {
      console.error('[verify] challenge persist note:', error.message);
    }
  }

  // Local mirror (also the source of truth in standalone deployments).
  db.query(
    `INSERT INTO verification_challenges
       (id, email_hash, code_hash, name_hash, expires_at, attempts, created_at, user_id)
     VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
    [record.id, record.emailHash, record.codeHash, record.nameHash, record.expiresAt, now, userId]
  );

  const { subject, body } = subjectAndBody({ name, code, purpose });
  // When no SMTP transport exists, fall back to the auth service's own mailer.
  // Callers can disable it (purpose 'reset' uses the recovery link instead).
  const delivery = await mailer.enqueue({
    recipient: email,
    subject,
    body,
    provider: purpose === 'signup' ? () => require('./auth').sendEmailOtp(email) : null,
  });

  return {
    challengeId: record.id,
    expiresInSeconds: Math.floor(TTL_MS / 1000),
    delivered: delivery.delivered,
    via: delivery.via || null,
  };
}

/**
 * Check a submitted code. Returns { ok, userId } and never throws on a wrong
 * code (callers translate that into a generic 400 + attempt counter).
 */
function verifyChallenge({ email, code }) {
  const now = Date.now();
  const rows = db.query(
    `SELECT id, code_hash, attempts, expires_at, consumed_at, user_id
       FROM verification_challenges
      WHERE email_hash = ? AND consumed_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1`,
    [fp(email)]
  );
  const row = rows[0];
  if (!row) return { ok: false, reason: 'no_challenge' };
  if (row.consumed_at) return { ok: false, reason: 'consumed' };
  if (row.expires_at < now) return { ok: false, reason: 'expired' };
  if (row.attempts >= MAX_ATTEMPTS) return { ok: false, reason: 'locked' };

  const expected = row.code_hash;
  const actual = fp(`${email}|${code}`);
  const match = db.timingSafeEqualHex(expected, actual);

  if (!match) {
    db.query('UPDATE verification_challenges SET attempts = attempts + 1 WHERE id = ?', [row.id]);
    const remaining = MAX_ATTEMPTS - (row.attempts + 1);
    return { ok: false, reason: 'mismatch', remaining: Math.max(remaining, 0) };
  }

  db.query('UPDATE verification_challenges SET consumed_at = ? WHERE id = ?', [now, row.id]);
  return { ok: true, challengeId: row.id, userId: row.user_id || null, email };
}

/**
 * Ask the database who owns a verified address. Used only to repair a missing
 * link (e.g. the server restarted between sign-up and verification). This is a
 * server-side, service-role lookup — the browser can never call it.
 */
async function lookupUserIdByEmail(email) {
  if (!config.supabase.serviceRoleKey) return null;
  try {
    const response = await fetch(`${config.supabase.url}/rest/v1/rpc/api_user_id_by_email`, {
      method: 'POST',
      headers: {
        apikey: config.supabase.serviceRoleKey,
        Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_email: email }),
      signal: AbortSignal.timeout(4000),
    });
    if (!response.ok) return null;
    const id = await response.json();
    return typeof id === 'string' && id.length === 36 ? id : null;
  } catch {
    return null;
  }
}

/** Invalidate outstanding codes for an address (used on password reset / resend). */
function invalidate(email) {
  db.query(
    'UPDATE verification_challenges SET consumed_at = ? WHERE email_hash = ? AND consumed_at IS NULL',
    [Date.now(), fp(email)]
  );
}

module.exports = {
  startChallenge, verifyChallenge, invalidate, lookupUserIdByEmail,
  TTL_MS, MAX_ATTEMPTS, CODE_DIGITS,
};
