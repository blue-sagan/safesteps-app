'use strict';

/**
 * Input validation for every server-side entry point.
 *
 * Rules:
 *  - Validate on the server BEFORE anything touches the database or mailer,
 *    even when the client already validated. The client is untrusted.
 *  - Normalise (trim, collapse whitespace, canonicalise email/phone).
 *  - Reject unknown keys so a caller cannot smuggle `role`, `user_id`, `score`
 *    or `status` into a write.
 *  - Hard length caps everywhere, so oversized payloads are refused instead of
 *    being stored and rendered later.
 */

const MAX_BODY_BYTES = 32 * 1024;

class ValidationError extends Error {
  constructor(fields) {
    super('Validation failed');
    this.name = 'ValidationError';
    this.status = 400;
    this.fields = fields; // { fieldName: message } — safe to return to client
  }
}

// RFC-5322 is enormous; this pragmatic pattern blocks the injection-shaped
// addresses we actually care about while accepting normal mail.
const EMAIL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const E164_RE = /^\+[1-9][0-9]{7,14}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isString(value) {
  return typeof value === 'string';
}

function cleanText(value, { min = 0, max = 500, allowNewlines = true, label = 'value' } = {}) {
  if (typeof value !== 'string') throw new ValidationError({ [label]: 'Must be text.' });
  // Strip control characters (including NUL and lone surrogates) that could
  // break logging, headers or JSON; keep \n and \t when newlines are allowed.
  const stripped = value
    .normalize('NFKC')
    .replace(allowNewlines ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g, '')
    .trim()
    .replace(/[ \t]{2,}/g, ' ');
  if (stripped.length < min) {
    throw new ValidationError({ [label]: `Must be at least ${min} characters.` });
  }
  if (stripped.length > max) {
    throw new ValidationError({ [label]: `Must be at most ${max} characters.` });
  }
  return stripped;
}

function cleanEmail(value, label = 'email') {
  if (!isString(value)) throw new ValidationError({ [label]: 'Enter a valid email address.' });
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email) || email.includes('..')) {
    throw new ValidationError({ [label]: 'Enter a valid email address.' });
  }
  return email;
}

function cleanPhone(value, label = 'phone') {
  if (value === null || value === undefined || value === '') return null;
  if (!isString(value)) throw new ValidationError({ [label]: 'Enter a valid phone number.' });
  let phone = value.replace(/[\s()-]/g, '');
  if (/^0[17][0-9]{8}$/.test(phone)) phone = '+254' + phone.slice(1); // Kenyan local form
  if (/^254[17][0-9]{8}$/.test(phone)) phone = '+' + phone;
  if (!E164_RE.test(phone)) {
    throw new ValidationError({ [label]: 'Use international format, e.g. +254712345678.' });
  }
  return phone;
}

/**
 * Password policy: length is the dominant factor, with a small blocklist of
 * the passwords people actually choose. The value is passed straight to
 * Supabase Auth (GoTrue), which hashes with bcrypt server-side — this server
 * never hashes, stores or logs passwords.
 */
const WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '123456789', '12345678',
  'qwerty', 'qwerty123', 'letmein', 'welcome', 'admin', 'admin123', 'iloveyou',
  'safesteps', 'safesteps123', 'abc123', 'monkey', 'dragon', '111111', '123123',
]);

function cleanPassword(value, label = 'password') {
  if (!isString(value)) throw new ValidationError({ [label]: 'Enter a password.' });
  if (value.length < 10) {
    throw new ValidationError({ [label]: 'Use at least 10 characters.' });
  }
  if (value.length > 200) {
    throw new ValidationError({ [label]: 'Must be at most 200 characters.' });
  }
  if (WEAK_PASSWORDS.has(value.toLowerCase())) {
    throw new ValidationError({ [label]: 'That password is too common — choose another.' });
  }
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) {
    throw new ValidationError({ [label]: 'Include at least one letter and one number.' });
  }
  return value;
}

function cleanOtp(value, label = 'code') {
  if (!isString(value)) throw new ValidationError({ [label]: 'Enter the code from your email.' });
  const code = value.replace(/\s/g, '');
  if (!/^[0-9]{6,8}$/.test(code)) {
    throw new ValidationError({ [label]: 'The code must be 6–8 digits.' });
  }
  return code;
}

function cleanUuid(value, label = 'id') {
  if (!isString(value) || !UUID_RE.test(value)) {
    throw new ValidationError({ [label]: 'Invalid identifier.' });
  }
  return value.toLowerCase();
}

function cleanNumber(value, { min, max, label = 'value', integer = false } = {}) {
  const num = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(num)) throw new ValidationError({ [label]: 'Must be a number.' });
  if (integer && !Number.isInteger(num)) throw new ValidationError({ [label]: 'Must be a whole number.' });
  if (min !== undefined && num < min) throw new ValidationError({ [label]: `Must be at least ${min}.` });
  if (max !== undefined && num > max) throw new ValidationError({ [label]: `Must be at most ${max}.` });
  return num;
}

function cleanBoolean(value, label = 'value') {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new ValidationError({ [label]: 'Must be true or false.' });
}

function cleanEnum(value, allowed, label = 'value') {
  if (!isString(value) || !allowed.includes(value)) {
    throw new ValidationError({ [label]: `Must be one of: ${allowed.join(', ')}.` });
  }
  return value;
}

/**
 * Enforce an allow-list of keys. Any extra key is a 400, not silently dropped,
 * so tampering attempts are visible in logs instead of being ignored.
 */
function only(body, allowedKeys) {
  const extra = Object.keys(body || {}).filter((key) => !allowedKeys.includes(key));
  if (extra.length) {
    throw new ValidationError({ _: `Unexpected field(s): ${extra.join(', ')}` });
  }
  return body || {};
}

function assertPayloadSize(rawLength) {
  if (rawLength > MAX_BODY_BYTES) {
    const err = new ValidationError({ _: 'Request body too large.' });
    err.status = 413;
    throw err;
  }
}

module.exports = {
  ValidationError,
  MAX_BODY_BYTES,
  EMAIL_RE,
  E164_RE,
  UUID_RE,
  cleanText,
  cleanEmail,
  cleanPhone,
  cleanPassword,
  cleanOtp,
  cleanUuid,
  cleanNumber,
  cleanBoolean,
  cleanEnum,
  only,
  assertPayloadSize,
};
