'use strict';

/**
 * Bot protection for the sensitive unauthenticated endpoints (register, login,
 * verify, forgot-password).
 *
 * Layered, no third-party CAPTCHA (which would need another secret and leaks
 * user traffic to a vendor):
 *
 *   1. Proof-of-work challenge — the client must burn a little CPU before its
 *      request is accepted. Cheap for one human, expensive for a script farm.
 *      Challenges are HMAC-signed and stateless; solving them requires no
 *      cookie or server-side storage.
 *   2. Honeypot field — hidden input a human never fills. Bots that scrape the
 *      form and fill everything are rejected.
 *   3. Dwell time — a form submitted faster than any human could type it is
 *      rejected.
 *   4. User-agent sanity — empty/known-script agents are refused on auth routes.
 *
 * Rejections are deliberately vague so an attacker cannot tune their bot.
 */

const crypto = require('node:crypto');
const config = require('./config');

const CHALLENGE_TTL_MS = 10 * 60 * 1000;
const MIN_DWELL_MS = 1200;
const DIFFICULTY = 4; // leading hex zeros required → ~65k hashes average

function sign(payload) {
  return crypto
    .createHmac('sha256', config.security.verificationPepper)
    .update(payload)
    .digest('base64url');
}

function issueChallenge() {
  const salt = crypto.randomBytes(16).toString('hex');
  const issuedAt = Date.now();
  const payload = `${salt}.${issuedAt}`;
  const signature = sign(payload);
  return {
    challenge: `${payload}.${signature}`,
    difficulty: DIFFICULTY,
    algorithm: 'sha256-hex-leading-zeros',
    expiresInSeconds: Math.floor(CHALLENGE_TTL_MS / 1000),
  };
}

function leadingZeroHexChars(hex) {
  let count = 0;
  for (const char of hex) {
    if (char !== '0') break;
    count += 1;
  }
  return count;
}

function verifySolution(challenge, nonce) {
  if (typeof challenge !== 'string' || typeof nonce !== 'string') return false;
  const parts = challenge.split('.');
  if (parts.length !== 3) return false;
  const [salt, issuedAtRaw, signature] = parts;
  const payload = `${salt}.${issuedAtRaw}`;
  const expected = sign(payload);
  // Constant-time compare of the signature.
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  const issuedAt = Number(issuedAtRaw);
  if (!Number.isFinite(issuedAt)) return false;
  const age = Date.now() - issuedAt;
  if (age < MIN_DWELL_MS || age > CHALLENGE_TTL_MS) return false;
  if (!/^[0-9]{1,12}$/.test(nonce)) return false;

  const digest = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
  return leadingZeroHexChars(digest) >= DIFFICULTY;
}

const BAD_AGENT_RE = /(curl|wget|python-requests|go-http-client|java\/|scrapy|nikto|sqlmap|masscan|zgrab|bot\b|spider|crawler)/i;

function looksAutomated(req) {
  const ua = String(req.headers['user-agent'] || '').trim();
  if (ua.length < 10) return true;
  if (BAD_AGENT_RE.test(ua)) return true;
  // A real browser always sends at least one of these on a form POST.
  const hasLanguage = Boolean(req.headers['accept-language']);
  const hasOrigin = Boolean(req.headers.origin || req.headers.referer);
  return !hasLanguage || !hasOrigin;
}

/**
 * Validate the full anti-bot envelope on a sensitive request.
 * @returns {string|null} rejection reason (safe to log), or null when clean
 */
function validateEnvelope(req, body, { requireChallenge = true } = {}) {
  if (looksAutomated(req)) return 'automated_client';

  // Honeypot: must be present in the form schema, must stay empty.
  if (body && typeof body.website === 'string' && body.website.trim() !== '') return 'honeypot_tripped';

  if (!requireChallenge) return null;

  if (!body || typeof body.botChallenge !== 'string' || typeof body.botNonce !== 'string') {
    return 'missing_challenge';
  }
  if (!verifySolution(body.botChallenge, body.botNonce)) return 'invalid_challenge';
  return null;
}

module.exports = {
  issueChallenge,
  verifySolution,
  validateEnvelope,
  looksAutomated,
  DIFFICULTY,
  MIN_DWELL_MS,
  CHALLENGE_TTL_MS,
};
