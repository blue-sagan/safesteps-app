'use strict';

/**
 * Supabase "Send Email Hook" receiver.
 *
 * WHY THIS EXISTS
 * ---------------
 * Two separate problems had the same root cause: the auth service, not our
 * server, owned the verification code.
 *
 *   1. **Confirmation needed the service-role key.** Our server generated its own
 *      code, so the only way to mark the address confirmed was
 *      `PUT /auth/v1/admin/users/:id` — a full RLS bypass held in a web process.
 *   2. **The code in the mail was ours, so GoTrue would not accept it.** The
 *      `/verify` endpoint rejects a token it did not issue.
 *
 * A Send Email Hook fixes both at the source. GoTrue stops using its own mailer,
 * generates the token itself, and POSTs it here, signed with a Standard-Webhooks
 * signature. We relay it through EmailJS and — crucially — we now KNOW the token,
 * so the verification screen can hand it straight back to `/verify` and get a
 * real session. No admin key, no derived passwords, no pretending.
 *
 * SECURITY SHAPE
 * --------------
 *   • The endpoint is public by necessity (Supabase must reach it), so the only
 *     thing standing between the internet and "send any mail to anyone" is the
 *     signature. Every request is verified with HMAC-SHA256 over
 *     `id.timestamp.body` using SEND_EMAIL_HOOK_SECRET, in constant time, with a
 *     timestamp bound to stop replays.
 *   • The recipient is taken from `user.email` in the signed payload — never
 *     from a query string or an unsigned field.
 *   • When no secret is configured the endpoint refuses everything (503) rather
 *     than trusting unauthenticated input.
 *   • Bodies are rate limited by the same global limiter as the rest of the API.
 */

const crypto = require('node:crypto');

const MAX_CLOCK_SKEW_SECONDS = 5 * 60;

function secret() {
  const raw = (process.env.SEND_EMAIL_HOOK_SECRET || '').trim();
  if (!raw) return null;
  // Supabase shows the secret as "v1,whsec_<base64>"; the signing key is the
  // base64 part.
  return raw.replace(/^v1,/, '').replace(/^whsec_/, '');
}

function isConfigured() {
  return Boolean(secret());
}

/**
 * Standard Webhooks signature check.
 * Signed content is `${id}.${timestamp}.${body}`; the header carries one or more
 * space-separated `v1,<base64 signature>` entries (rotation can leave several).
 */
function verifySignature({ headers, rawBody }) {
  const key = secret();
  if (!key) return { ok: false, reason: 'not_configured' };

  const id = String(headers['webhook-id'] || '');
  const timestamp = String(headers['webhook-timestamp'] || '');
  const signatures = String(headers['webhook-signature'] || '');
  if (!id || !timestamp || !signatures) return { ok: false, reason: 'missing_signature' };

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > MAX_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: 'stale_timestamp' };
  }

  const signed = `${id}.${timestamp}.${rawBody}`;
  const expected = crypto.createHmac('sha256', Buffer.from(key, 'base64')).update(signed).digest();

  for (const candidate of signatures.split(' ')) {
    const value = candidate.includes(',') ? candidate.split(',')[1] : candidate;
    if (!value) continue;
    let provided;
    try {
      provided = Buffer.from(value, 'base64');
    } catch {
      continue;
    }
    if (provided.length === expected.length && crypto.timingSafeEqual(provided, expected)) {
      return { ok: true };
    }
  }
  return { ok: false, reason: 'bad_signature' };
}

/** Human copy for each action GoTrue can ask us to deliver. */
function render({ actionType, token, siteUrl }) {
  const link = siteUrl || process.env.PUBLIC_ORIGIN || '';
  switch (actionType) {
    case 'signup':
    case 'reauthentication':
      return {
        subject: 'Your SafeSteps verification code',
        text: [
          'Hello,',
          '',
          'Your SafeSteps verification code is:',
          '',
          `    ${token}`,
          '',
          'Enter it in the app to finish signing in.',
          'It expires in 15 minutes and can be used once.',
          '',
          'If you did not request it, you can ignore this message.',
          '',
          '— SafeSteps Kenya (Project 360° Shield)',
        ].join('\n'),
        code: token,
      };
    case 'recovery':
      return {
        subject: 'Reset your SafeSteps password',
        text: [
          'Hello,',
          '',
          'Use the code below to reset your SafeSteps password:',
          '',
          `    ${token}`,
          '',
          `Or open the app: ${link}`,
          'It expires in 15 minutes and can be used once.',
          '',
          '— SafeSteps Kenya (Project 360° Shield)',
        ].join('\n'),
        code: token,
      };
    case 'email_change':
      return {
        subject: 'Confirm your new SafeSteps email address',
        text: ['Hello,', '', 'Confirm this address with the code below:', '', `    ${token}`, ''].join('\n'),
        code: token,
      };
    case 'invite':
      return {
        subject: "You've been invited to SafeSteps",
        text: ['Hello,', '', 'You have been invited to SafeSteps.', '', `    ${token}`, ''].join('\n'),
        code: token,
      };
    default:
      return {
        subject: 'Your SafeSteps security code',
        text: ['Hello,', '', `Your code is:`, '', `    ${token}`, ''].join('\n'),
        code: token,
      };
  }
}

module.exports = { isConfigured, verifySignature, render, secret, MAX_CLOCK_SKEW_SECONDS };
