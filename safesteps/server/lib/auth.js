'use strict';

/**
 * Thin, explicit wrapper over Supabase Auth (GoTrue).
 *
 * Why a wrapper instead of calling GoTrue from the browser: it lets the server
 *  - apply its own rate limits and bot checks before any auth attempt,
 *  - keep the refresh token out of JavaScript's reach (httpOnly cookie),
 *  - return uniform error messages so account enumeration is not possible,
 *  - never expose anything but the publishable key to the client.
 *
 * Passwords are handed to GoTrue over TLS and hashed there with bcrypt. This
 * process never hashes, stores, logs or echoes a password.
 */

const config = require('./config');
const v = require('./validate');

class AuthError extends Error {
  constructor(message, { status = 400, code = 'auth_error' } = {}) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
    // Every message this class is constructed with is written here, in this
    // file, for a person to read — none of them interpolate upstream text.
    // Without this flag sendError() replaced all 5xx bodies with "Something
    // went wrong", so a Supabase outage (or a paused free-plan project) showed
    // users a dead end instead of the actionable message authored below.
    this.expose = true;
  }
}

/**
 * Turn an upstream failure into something a user can act on.
 *
 * These are the failures that actually interrupt this app on a free plan:
 * a paused project, an exhausted quota, and a plain outage. They are worth
 * distinguishing because the remedy differs — wait, upgrade, or nothing at all.
 */
function classifyUpstream(status, upstream) {
  const text = String(upstream || '').toLowerCase();

  // Supabase pauses a project that exceeds free-plan limits; Postgres reports a
  // full disk as 53100/53400 ("No space left on device").
  const paused =
    text.includes('paused') ||
    text.includes('no space left') ||
    text.includes('53100') ||
    text.includes('53400') ||
    text.includes('disk_full') ||
    text.includes('exceeded') && (text.includes('quota') || text.includes('limit'));

  if (paused) {
    return new AuthError(
      'SafeSteps is temporarily read-only while its storage is being restored. Everything already on this device still works. Please try again later.',
      { status: 503, code: 'service_paused' }
    );
  }

  if (status === 502 || status === 503 || status === 504) {
    return new AuthError(
      'The sign-in service is temporarily unavailable. Please try again in a moment.',
      { status: 503, code: 'auth_unavailable' }
    );
  }

  return null;
}

function baseUrl() {
  return `${config.supabase.url}/auth/v1`;
}

async function call(pathname, { method = 'POST', body, accessToken, headers: extraHeaders } = {}) {
  const url = `${baseUrl()}${pathname}`;
  const headers = {
    apikey: config.supabase.publishableKey,
    'Content-Type': 'application/json',
    ...extraHeaders,
  };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
  } catch (error) {
    throw new AuthError('Authentication service is unreachable. Please try again.', {
      status: 503,
      code: 'auth_unavailable',
    });
  }

  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  if (!response.ok) {
    // Map GoTrue responses onto a small, uniform vocabulary. Raw upstream
    // messages are logged, never returned.
    const upstream = String((parsed && (parsed.msg || parsed.message || parsed.error_description)) || '');
    // Classification looks at EVERY field, not just the one that gets logged:
    // Postgres reports a full disk in error_description while `message` says
    // only "lack of resources", and matching on the first field alone missed it.
    const upstreamAll = String(
      parsed ? [parsed.msg, parsed.message, parsed.error_description, parsed.error, parsed.code, parsed.detail].filter(Boolean).join(' ') : ''
    );
    console.warn('[auth]', response.status, pathname, upstream.slice(0, 200));

    if (response.status === 429) {
      throw new AuthError('Too many attempts. Please wait a few minutes and try again.', {
        status: 429,
        code: 'rate_limited',
      });
    }

    // Paused project / full disk / gateway error. Checked before the generic
    // cases below so the user gets a diagnosis instead of "try again".
    const classified = classifyUpstream(response.status, upstreamAll);
    if (classified) throw classified;
    if (upstream.toLowerCase().includes('already registered')) {
      throw new AuthError('If that address can be used, we have sent you an email with next steps.', {
        status: 200,
        code: 'signup_received',
      });
    }
    if (upstream.toLowerCase().includes('invalid login credentials')) {
      throw new AuthError('Invalid email or password.', { status: 401, code: 'invalid_credentials' });
    }
    if (upstream.toLowerCase().includes('password should be') || upstream.toLowerCase().includes('weak password')) {
      throw new AuthError('Choose a stronger password (6 to 8 characters, with letters and numbers).', {
        status: 400,
        code: 'weak_password',
      });
    }
    if (upstream.toLowerCase().includes('email not confirmed')) {
      throw new AuthError('Please confirm your email address before signing in.', {
        status: 403,
        code: 'email_unconfirmed',
      });
    }
    throw new AuthError('We could not complete that request. Please try again.', {
      status: 400,
      code: 'auth_failed',
    });
  }

  return parsed;
}

async function signUp({ email, password, fullName }) {
  const result = await call('/signup', {
    body: {
      email,
      password,
      // Metadata is copied into public.profiles by the server-side trigger.
      // No phone: the SMS fallback was removed, so no phone number is collected.
      data: { full_name: fullName },
    },
  });
  // Normalise: GoTrue returns either the user object directly or { user }.
  // The id is needed to link the verification challenge to the account later;
  // without it, a correct code could be validated but never confirm the email.
  const user = (result && result.user) || result || null;
  return {
    id: user && user.id ? user.id : null,
    email: user && user.email ? user.email : email,
    alreadyRegistered: Boolean(user && user.id && Array.isArray(user.identities) && user.identities.length === 0),
  };
}

async function signIn({ email, password }) {
  return call('/token?grant_type=password', { body: { email, password } });
}

async function refresh(refreshToken) {
  return call('/token?grant_type=refresh_token', { body: { refresh_token: refreshToken } });
}

async function logout(accessToken) {
  try {
    await call('/logout', { method: 'POST', accessToken, body: {} });
  } catch (error) {
    // Revocation is best-effort; the cookies are cleared regardless.
    console.warn('[auth] logout upstream note:', error.message);
  }
}

async function requestPasswordReset(email, redirectTo) {
  const suffix = redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : '';
  return call(`/recover${suffix}`, { body: { email } });
}

/**
 * Ask the auth service to email a one-time code to the address.
 *
 * This is the path used when the deployment has no SMTP credentials of its own:
 * the code is generated and delivered by Supabase Auth, so the value the user
 * types in is one the auth service itself will accept. It is only ever called
 * after our own rate limits and bot checks have passed, so it cannot be used to
 * spray email.
 */
async function sendEmailOtp(email) {
  return call('/otp', { body: { email, create_user: false } });
}

async function getUser(accessToken) {
  return call('/user', { method: 'GET', accessToken });
}

async function resendConfirmation(email) {
  return call('/resend', { body: { type: 'signup', email } });
}

/** Verify an email OTP (6–8 digits) — used by our own verification screen. */
async function verifyEmailOtp({ email, token }) {
  return call('/verify', { body: { type: 'email', email, token } });
}

/**
 * Server-trusted email confirmation. Only reachable with the service-role key,
 * which lives in this process only. Used after our server validates the
 * single-use code it mailed out itself.
 */
/**
 * Exchange a recovery code for a session.
 *
 * GoTrue's recovery flow is a link that lands back in the app with a token; the
 * token is single-use. We accept the code the user was mailed and turn it into a
 * short-lived session, then immediately use that session to set a new password —
 * so the reset never needs the service-role key.
 */
async function verifyRecovery({ email, token }) {
  return call('/verify', { body: { type: 'recovery', email, token } });
}

/**
 * Set a new password using the caller's own session. The auth service checks the
 * bearer token, so this can only ever change the password of the account that
 * just proved control of the mailbox.
 */
async function updatePassword({ accessToken, password }) {
  // Same policy as sign-up: one validator, so the two cannot drift apart.
  const checked = v.cleanPassword(password);
  return call('/user', {
    method: 'PUT',
    accessToken,
    body: { password: checked },
  });
}

/** Admin route: set a password for a specific user (needs the service-role key). */
async function adminSetPassword({ userId, password }) {
  if (!config.supabase.serviceRoleKey) {
    throw new AuthError('Password recovery is not configured on this server.', {
      status: 503,
      code: 'reset_unavailable',
    });
  }
  const url = `${config.supabase.url}/auth/v1/admin/users/${encodeURIComponent(userId)}`;
  const checked = v.cleanPassword(password);
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      apikey: config.supabase.serviceRoleKey,
      Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ password: checked }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    const detail = await response.text();
    console.error('[auth] admin set password failed', response.status, detail.slice(0, 200));
    throw new AuthError('Could not update the password. Please try again.', {
      status: 502,
      code: 'reset_failed',
    });
  }
  return response.json();
}

async function adminConfirmEmail(userId) {
  if (!config.supabase.serviceRoleKey) {
    throw new AuthError('Verification service is not configured.', { status: 503, code: 'verify_unavailable' });
  }
  const url = `${config.supabase.url}/auth/v1/admin/users/${encodeURIComponent(userId)}`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      apikey: config.supabase.serviceRoleKey,
      Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email_confirm: true }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    const detail = await response.text();
    console.error('[auth] admin confirm failed', response.status, detail.slice(0, 200));
    throw new AuthError('We could not confirm that account. Please contact support.', {
      status: 502,
      code: 'verify_failed',
    });
  }
  return response.json();
}

/**
 * Admin route: delete a user's sign-in record entirely.
 *
 * Needed because erasing a user's rows is not the same as deleting their
 * account. Without this, "Delete My Account" removed every row and left
 * `auth.users` intact — so the same email and password still signed in, and the
 * user reasonably believed deletion had failed. The privacy policy promises the
 * account is erased; this is what makes that true.
 *
 * Idempotent: a 404 (already gone) counts as success, so a retry after a
 * half-finished deletion still completes.
 */
async function adminDeleteUser(userId) {
  if (!config.supabase.serviceRoleKey) {
    throw new AuthError(
      'Account deletion is not fully configured on this server. Your data was erased; contact support to remove the sign-in record.',
      { status: 503, code: 'delete_unavailable' }
    );
  }
  const url = `${config.supabase.url}/auth/v1/admin/users/${encodeURIComponent(userId)}`;
  const response = await fetch(url, {
    method: 'DELETE',
    headers: {
      apikey: config.supabase.serviceRoleKey,
      Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
    },
    signal: AbortSignal.timeout(10000),
  });
  if (response.ok || response.status === 404) return { deleted: true };
  const detail = await response.text();
  console.error('[auth] admin delete user failed', response.status, detail.slice(0, 200));
  throw new AuthError('Could not remove the sign-in record. Please contact support.', {
    status: 502,
    code: 'delete_failed',
  });
}

module.exports = {
  AuthError,
  signUp,
  signIn,
  refresh,
  logout,
  requestPasswordReset,
  getUser,
  resendConfirmation,
  verifyEmailOtp,
  verifyRecovery,
  updatePassword,
  adminSetPassword,
  sendEmailOtp,
  adminConfirmEmail,
  adminDeleteUser,
};
