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

class AuthError extends Error {
  constructor(message, { status = 400, code = 'auth_error' } = {}) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
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
    console.warn('[auth]', response.status, pathname, upstream.slice(0, 200));

    if (response.status === 429) {
      throw new AuthError('Too many attempts. Please wait a few minutes and try again.', {
        status: 429,
        code: 'rate_limited',
      });
    }
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
      throw new AuthError('Choose a stronger password (at least 10 characters).', {
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

async function signUp({ email, password, fullName, phone }) {
  const result = await call('/signup', {
    body: {
      email,
      password,
      // Metadata is copied into public.profiles by the server-side trigger.
      data: { full_name: fullName, phone: phone || null },
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
  sendEmailOtp,
  adminConfirmEmail,
};
