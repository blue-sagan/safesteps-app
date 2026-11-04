'use strict';

/**
 * JSON API.
 *
 * Every handler: authenticate → authorise → validate → act → trim response.
 * Nothing here trusts a client-supplied identity, role or ownership field.
 */

const config = require('./config');
const auth = require('./auth');
const db = require('./db');
const uploads = require('./uploads');
const sendEmailHook = require('./send-email-hook');
const verification = require('./verification');
const bot = require('./bot-protection');
const rateLimit = require('./rate-limit');
const session = require('./session');
const mailer = require('./mailer');
const {
  readJson,
  readBody,
  parseCookies,
  readSessionCookie,
  readRefreshCookie,
  clientKey,
  clientIpHash,
  sendJson,
  sendError,
} = require('./http');
const v = require('./validate');

/* ------------------------------------------------------------------ */
/* Authentication middleware                                           */
/* ------------------------------------------------------------------ */

async function requireUser(req) {
  const token = readSessionCookie(req);
  if (!token) {
    const err = new Error('Please sign in to continue.');
    err.status = 401;
    err.code = 'unauthenticated';
    throw err;
  }

  let user;
  try {
    user = await auth.getUser(token);
  } catch {
    const err = new Error('Your session has expired. Please sign in again.');
    err.status = 401;
    err.code = 'session_expired';
    throw err;
  }

  return {
    id: user.id,
    email: user.email,
    emailConfirmedAt: user.email_confirmed_at || null,
    fullName: (user.user_metadata && user.user_metadata.full_name) || null,
    accessToken: token,
  };
}

/**
 * Same as requireUser but returns null instead of throwing. Used only where a
 * guest must be able to complete the action (feedback); every privileged
 * endpoint still uses requireUser.
 */
async function readOptionalUser(req) {
  if (!readSessionCookie(req)) return null;
  try {
    return await requireUser(req);
  } catch {
    return null;
  }
}

/** Reject unconfirmed accounts on endpoints that must not accept them. */
function requireConfirmed(user) {
  if (!user.emailConfirmedAt) {
    const err = new Error('Please confirm your email address to continue.');
    err.status = 403;
    err.code = 'email_unconfirmed';
    throw err;
  }
}

/**
 * Guard a sensitive, unauthenticated POST: origin check, bot envelope, rate
 * limits. Returns the parsed body.
 */
async function guardSensitive(req, policy) {
  session.assertSameOrigin(req);
  await rateLimit.enforce(policy, clientIpHash(req));
  const body = await readJson(req);
  const rejection = bot.validateEnvelope(req, body);
  if (rejection) {
    db.query('INSERT INTO security_audit (event, detail, created_at) VALUES (?, ?, ?)', [
      'bot_rejected',
      `${policy}:${rejection}`,
      Date.now(),
    ]);
    const err = new Error('Could not verify this request. Please reload the app and try again.');
    err.status = 400;
    err.code = 'bot_check_failed';
    throw err;
  }
  return body;
}

/* ------------------------------------------------------------------ */
/* Capability guards                                                   */
/* ------------------------------------------------------------------ */

/**
 * Fail with an explanation, not a stack trace. When a deployment is missing a
 * credential the operator needs to know *which* one and what to do about it.
 */
function requireCapability(name, hint) {
  if (config.capabilities()[name]) return;
  const err = new Error(`This feature is not available on this server yet. ${hint}`);
  err.status = 503;
  err.code = 'feature_unavailable';
  err.expose = true; // operator-facing: the message names the missing setting
  throw err;
}

const AUTH_HINT = 'An administrator must set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY on the server.';
const VERIFY_HINT = 'An administrator must set SUPABASE_SERVICE_ROLE_KEY on the server.';

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async function handleConfig(req, res) {
  // Only public-safe values leave this endpoint.
  sendJson(res, 200, {
    supabaseUrl: config.supabase.url,
    supabasePublishableKey: config.supabase.publishableKey,
    passwordMinLength: v.PASSWORD_MIN,
    passwordMaxLength: v.PASSWORD_MAX,
    hsts: config.isProduction,
    // Public-safe capability flags so the UI can disable what cannot work
    // instead of letting the user hit an error they cannot fix.
    capabilities: config.capabilities(),
  });
}

async function handleChallenge(req, res) {
  await rateLimit.enforce('api', clientIpHash(req));
  const challenge = bot.issueChallenge();
  sendJson(res, 200, challenge);
}

async function handleRegister(req, res) {
  requireCapability('auth', AUTH_HINT);
  const body = await guardSensitive(req, 'register');
  // `phone` is deliberately absent: the SMS fallback was removed, so the
  // server no longer accepts or stores a phone number for an account.
  v.only(body, ['fullName', 'email', 'password', 'website', 'botChallenge', 'botNonce']);

  const fullName = v.cleanText(body.fullName, { min: 2, max: 80, allowNewlines: false, label: 'fullName' });
  const email = v.cleanEmail(body.email);
  const password = v.cleanPassword(body.password);

  // Per-address limit in addition to the per-IP one, so one IP cannot spray
  // registrations across many addresses or hammer a single victim address.
  await rateLimit.enforce('register', `email:${email}`);

  const result = await auth.signUp({ email, password, fullName });

  // Which code the user receives depends on who generated it.
  //
  // Hook configured: the auth service generated a token during /signup and handed
  // it to /api/hooks/send-email, which relayed it. `/verify` will accept it, so
  // we must NOT compose a second, competing code here — that is exactly the bug
  // that made every code unusable before.
  //
  // No hook: our own challenge, mailed by our own transport, confirmed through
  // the admin API.
  const challenge = sendEmailHook.isConfigured()
    ? { delivered: true }
    : await verification.startChallenge({
        email,
        name: fullName,
        purpose: 'signup',
        userId: result.id || null,
      });

  // Be explicit about delivery. Silently claiming "check your email" when no
  // transport is configured is how sign-up becomes an unexplainable dead end.
  sendJson(res, 202, {
    status: 'verification_required',
    message: challenge.delivered
      ? 'Check your email for the verification code.'
      : 'Your account was created, but this server could not deliver email. Ask the administrator to configure a mail transport (see SECURITY.md).',
    delivered: Boolean(challenge.delivered),
    codeLength: verification.CODE_DIGITS,
    expiresInSeconds: Math.floor(verification.TTL_MS / 1000),
  });
}

async function handleVerify(req, res) {
  requireCapability('emailVerification', VERIFY_HINT);
  const body = await guardSensitive(req, 'verify');
  v.only(body, ['email', 'code', 'website', 'botChallenge', 'botNonce']);

  const email = v.cleanEmail(body.email);
  const code = v.cleanOtp(body.code);

  // PREFERRED PATH — Send Email Hook configured.
  //
  // The auth service generated this code and will accept it, so handing it back
  // to /verify both confirms the address and returns a real session. That is why
  // no service-role key is needed: nothing has to be flipped by us, and GoTrue
  // is the only party deciding whether the code is right.
  if (sendEmailHook.isConfigured()) {
    try {
      const tokens = await auth.verifyEmailOtp({ email, token: code });
      const csrf = session.csrfToken();
      session.setSessionCookies(res, {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        csrf,
      });
      const user = (tokens && tokens.user) || {};
      sendJson(res, 200, {
        status: 'verified',
        message: 'Email verified. You are signed in.',
        user: {
          id: user.id,
          email: user.email,
          fullName: (user.user_metadata && user.user_metadata.full_name) || null,
          emailVerified: true,
        },
        expiresIn: (tokens && tokens.expires_in) || 3600,
      });
      return;
    } catch (error) {
      db.query('INSERT INTO security_audit (event, detail, created_at) VALUES (?, ?, ?)', [
        'verify_failed',
        clientIpHash(req),
        Date.now(),
      ]);
      // One message for every failure mode: the endpoint must not become an
      // oracle for whether an address has a pending code.
      const err = new Error('That code is not correct or has expired. Request a new one.');
      err.status = 400;
      err.code = 'invalid_code';
      throw err;
    }
  }

  const result = verification.verifyChallenge({ email, code });
  if (!result.ok) {
    const messages = {
      no_challenge: 'Request a new code, then try again.',
      consumed: 'That code has already been used. Request a new one.',
      expired: 'That code has expired. Request a new one.',
      locked: 'Too many incorrect attempts. Request a new code.',
      mismatch: `That code is not correct.${result.remaining !== undefined ? ` ${result.remaining} attempt(s) left.` : ''}`,
    };
    const err = new Error(messages[result.reason] || 'That code is not valid.');
    err.status = 400;
    err.code = 'invalid_code';
    throw err;
  }

  // The code is generated and validated on the server, so the account may now
  // be confirmed in a trusted way. This uses the service-role key, which exists
  // only in this process — the browser can never confirm an address itself.
  //
  // IMPORTANT: reporting "verified" without actually confirming the address
  // would leave the user unable to sign in ("email not confirmed") with no
  // explanation, so a missing link is repaired, and a failure is surfaced.
  let userId = result.userId;
  if (!userId) {
    userId = await verification.lookupUserIdByEmail(email);
  }
  if (!userId) {
    const err = new Error('We could not find the account for that code. Please sign up again.');
    err.status = 400;
    err.code = 'no_pending_account';
    throw err;
  }
  if (!config.supabase.serviceRoleKey) {
    const err = new Error(
      'Email confirmation is not configured on this server. An administrator must set SUPABASE_SERVICE_ROLE_KEY.'
    );
    err.status = 503;
    err.code = 'verify_unavailable';
    err.expose = true;
    throw err;
  }
  try {
    await auth.adminConfirmEmail(userId);
  } catch (error) {
    console.error('[verify] confirm failed:', error.message);
    const err = new Error('The code was correct, but we could not activate the account. Please try again shortly.');
    err.status = 502;
    err.code = 'verify_incomplete';
    throw err;
  }

  sendJson(res, 200, {
    status: 'verified',
    message: 'Email verified. You can now sign in.',
  });
}

async function handleLogin(req, res) {
  requireCapability('auth', AUTH_HINT);
  const body = await guardSensitive(req, 'login');
  v.only(body, ['email', 'password', 'website', 'botChallenge', 'botNonce']);

  const email = v.cleanEmail(body.email);
  if (typeof body.password !== 'string' || body.password.length === 0 || body.password.length > 200) {
    const err = new Error('Enter your email and password.');
    err.status = 400;
    err.code = 'invalid_credentials';
    throw err;
  }

  // Tight, per-address limit *in addition to* per-IP: slows credential stuffing
  // against a single account while still allowing a shared campus IP.
  await rateLimit.enforce('login', `email:${email}`);

  let tokens;
  try {
    tokens = await auth.signIn({ email, password: body.password });
  } catch (error) {
    db.query('INSERT INTO security_audit (event, detail, created_at) VALUES (?, ?, ?)', [
      'login_failed',
      clientIpHash(req),
      Date.now(),
    ]);
    throw error;
  }

  const csrf = session.csrfToken();
  session.setSessionCookies(res, {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    csrf,
  });

  db.query('INSERT INTO security_audit (event, detail, created_at) VALUES (?, ?, ?)', [
    'login_success',
    clientIpHash(req),
    Date.now(),
  ]);

  // Trimmed: the browser needs an identity, not the whole token envelope.
  sendJson(res, 200, {
    user: {
      id: tokens.user.id,
      email: tokens.user.email,
      fullName: (tokens.user.user_metadata && tokens.user.user_metadata.full_name) || null,
      emailVerified: Boolean(tokens.user.email_confirmed_at),
    },
    expiresIn: tokens.expires_in,
  });
}

async function handleRefresh(req, res) {
  session.assertSameOrigin(req);
  await rateLimit.enforce('api', clientIpHash(req));
  const cookies = parseCookies(req);
  session.assertCsrf(req, cookies);

  const refreshToken = readRefreshCookie(req);
  if (!refreshToken) {
    const err = new Error('Your session has expired. Please sign in again.');
    err.status = 401;
    err.code = 'session_expired';
    throw err;
  }

  const tokens = await auth.refresh(refreshToken);
  session.setSessionCookies(res, {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    csrf: cookies[session.cookieName('csrf')],
  });
  sendJson(res, 200, { ok: true, expiresIn: tokens.expires_in });
}

async function handleLogout(req, res) {
  session.assertSameOrigin(req);
  const cookies = parseCookies(req);
  session.assertCsrf(req, cookies);
  const token = readSessionCookie(req);
  if (token) await auth.logout(token);
  session.clearSessionCookies(res);
  sendJson(res, 200, { ok: true });
}

async function handleMe(req, res) {
  const user = await requireUser(req);

  // Read the caller's own profile through PostgREST *as the user*, so RLS is
  // the final authority on what comes back.
  const profile = await db.rest('profiles', {
    accessToken: user.accessToken,
    searchParams: { select: 'id,display_name,county,email_verified_at,created_at', id: `eq.${user.id}` },
  });

  sendJson(res, 200, {
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      emailVerified: Boolean(user.emailConfirmedAt),
      profile: profile.ok && Array.isArray(profile.body) ? profile.body[0] || null : null,
    },
  });
}

async function handleForgot(req, res) {
  const body = await guardSensitive(req, 'forgot');
  v.only(body, ['email', 'website', 'botChallenge', 'botNonce']);
  const email = v.cleanEmail(body.email);

  // Always the same response: no account enumeration.
  try {
    await verification.startChallenge({ email, name: '', purpose: 'reset' });
    await auth.requestPasswordReset(email, `${config.publicOrigin || ''}/`);
  } catch (error) {
    console.warn('[forgot]', error.message);
  }
  sendJson(res, 202, { status: 'sent', message: 'If that address has an account, a reset link is on its way.' });
}

async function handleResend(req, res) {
  const body = await guardSensitive(req, 'forgot');
  v.only(body, ['email', 'website', 'botChallenge', 'botNonce']);
  const email = v.cleanEmail(body.email);
  let delivered = false;
  try {
    verification.invalidate(email);
    const challenge = await verification.startChallenge({ email, name: '', purpose: 'signup' });
    delivered = Boolean(challenge.delivered);
  } catch (error) {
    console.warn('[resend]', error.message);
  }
  sendJson(res, 202, {
    status: 'sent',
    delivered,
    message: delivered
      ? 'If verification is pending, a new code has been sent.'
      : 'If verification is pending, a new code was created, but this server has no mail transport configured.',
  });
}

/* ----------------------------- records ---------------------------- */

async function handleListReports(req, res, url) {
  const user = await requireUser(req);
  requireConfirmed(user);

  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') || 20), 1), 50);
  const result = await db.rest('safety_reports', {
    accessToken: user.accessToken,
    // Explicit column list = trimmed response. `user_id` is not requested and
    // `select=*` is never used.
    searchParams: {
      select: 'id,category,county,note,lat,lng,status,created_at',
      order: 'created_at.desc',
      limit: String(limit),
    },
  });
  if (!result.ok) throw Object.assign(new Error('Could not load your reports.'), { status: 502 });
  sendJson(res, 200, { reports: result.body || [] });
}

async function handleCreateReport(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);
  await rateLimit.enforce('api', user.id);

  const body = await readJson(req);
  v.only(body, ['category', 'county', 'note', 'lat', 'lng']);

  const record = {
    category: v.cleanEnum(body.category, ['crash', 'near_miss', 'pothole', 'roadblock', 'flooding', 'signage', 'other'], 'category'),
    county: body.county === undefined || body.county === null ? null : v.cleanText(body.county, { max: 60, allowNewlines: false, label: 'county' }),
    note: v.cleanText(body.note, { min: 3, max: 1000, label: 'note' }),
    lat: body.lat === undefined || body.lat === null ? null : v.cleanNumber(body.lat, { min: -90, max: 90, label: 'lat' }),
    lng: body.lng === undefined || body.lng === null ? null : v.cleanNumber(body.lng, { min: -180, max: 180, label: 'lng' }),
  };

  // Note: no user_id / status in the payload — the database binds ownership to
  // auth.uid() and keeps status server-owned.
  const result = await db.rest('safety_reports', {
    method: 'POST',
    accessToken: user.accessToken,
    body: record,
    prefer: 'return=representation',
  });
  if (!result.ok) throw Object.assign(new Error('Could not save that report.'), { status: 502 });

  const saved = Array.isArray(result.body) ? result.body[0] : result.body;
  sendJson(res, 201, {
    report: saved
      ? {
          id: saved.id,
          category: saved.category,
          county: saved.county,
          status: saved.status,
          created_at: saved.created_at,
        }
      : null,
  });
}

async function handleQuizAttempt(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);
  await rateLimit.enforce('api', user.id);

  const body = await readJson(req);
  v.only(body, ['category', 'score', 'total', 'correct']);
  const total = v.cleanNumber(body.total, { min: 1, max: 100, integer: true, label: 'total' });
  const correct = v.cleanNumber(body.correct, { min: 0, max: total, integer: true, label: 'correct' });

  const result = await db.rest('quiz_attempts', {
    method: 'POST',
    accessToken: user.accessToken,
    body: {
      category: v.cleanText(body.category, { min: 1, max: 40, allowNewlines: false, label: 'category' }),
      score: Math.round((correct / total) * 100),
      total,
      correct,
    },
    prefer: 'return=representation',
  });
  if (!result.ok) throw Object.assign(new Error('Could not save that attempt.'), { status: 502 });
  const saved = Array.isArray(result.body) ? result.body[0] : result.body;
  sendJson(res, 201, {
    attempt: saved ? { id: saved.id, score: saved.score, completed_at: saved.completed_at } : null,
  });
}

async function handleVaultPut(req, res) {
  requireCapability('atRestEncryption', 'An administrator must set SERVER_DATA_KEY on the server.');
  const user = await requireUser(req);
  requireConfirmed(user);

  const body = await readJson(req, { limit: 2 * 1024 * 1024 });
  v.only(body, ['kdfSalt', 'kdfIterations', 'wrappedKey', 'wrappedKeyIv', 'ciphertext', 'iv', 'version']);

  const record = {
    user_id: user.id,
    kdf_salt: v.cleanText(body.kdfSalt, { min: 16, max: 128, allowNewlines: false, label: 'kdfSalt' }),
    kdf_iterations: v.cleanNumber(body.kdfIterations, { min: 100000, max: 2000000, integer: true, label: 'kdfIterations' }),
    wrapped_key: v.cleanText(body.wrappedKey, { min: 16, max: 512, allowNewlines: false, label: 'wrappedKey' }),
    wrapped_key_iv: v.cleanText(body.wrappedKeyIv, { min: 12, max: 64, allowNewlines: false, label: 'wrappedKeyIv' }),
    ciphertext: v.cleanText(body.ciphertext, { min: 16, max: 2000000, allowNewlines: false, label: 'ciphertext' }),
    iv: v.cleanText(body.iv, { min: 12, max: 64, allowNewlines: false, label: 'iv' }),
    version: v.cleanNumber(body.version || 1, { min: 1, max: 1000, integer: true, label: 'version' }),
  };

  const result = await db.rest('user_vaults', {
    method: 'POST',
    accessToken: user.accessToken,
    body: record,
    prefer: 'resolution=merge-duplicates,return=minimal',
  });
  if (!result.ok) throw Object.assign(new Error('Could not save your encrypted vault.'), { status: 502 });
  sendJson(res, 200, { ok: true, bytes: record.ciphertext.length });
}

async function handleVaultGet(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);

  const result = await db.rest('user_vaults', {
    accessToken: user.accessToken,
    // Named columns only; `user_id` is never returned (the caller knows who they are).
    searchParams: {
      select: 'kdf_salt,kdf_iterations,wrapped_key,wrapped_key_iv,ciphertext,iv,version,updated_at',
      limit: '1',
    },
  });
  if (!result.ok) throw Object.assign(new Error('Could not load your vault.'), { status: 502 });

  const row = Array.isArray(result.body) ? result.body[0] : null;
  sendJson(res, 200, {
    vault: row
      ? {
          kdfSalt: row.kdf_salt,
          kdfIterations: row.kdf_iterations,
          wrappedKey: row.wrapped_key,
          wrappedKeyIv: row.wrapped_key_iv,
          ciphertext: row.ciphertext,
          iv: row.iv,
          version: row.version,
          updatedAt: row.updated_at,
        }
      : null,
  });
}

/**
 * Anonymous hazard tallies. Deliberately aggregate-only: no user id, no
 * coordinates, no free text — so contributing cannot de-anonymise a reporter.
 */
const HAZARD_CATEGORIES = ['crash', 'near_miss', 'pothole', 'roadblock', 'flooding', 'signage', 'other'];

async function handleCommunityHazard(req, res) {
  await rateLimit.enforce('api', clientIpHash(req));
  const body = await readJson(req);
  v.only(body, ['category']);
  const category = v.cleanEnum(body.category, HAZARD_CATEGORIES, 'category');

  if (!config.capabilities().auth) {
    // Still accept and count locally so the feature works before the DB is set up.
    db.query(
      'INSERT INTO community_counts (category, counted_at) VALUES (?, ?)',
      [category, Date.now()]
    );
    return sendJson(res, 202, { status: 'counted' });
  }

  const result = await db.rest('rpc/api_increment_hazard', { method: 'POST', body: { p_category: category } });
  if (!result.ok) throw Object.assign(new Error('Could not record that.'), { status: 502 });
  sendJson(res, 202, { status: 'counted' });
}

async function handleCommunityInsights(req, res) {
  await rateLimit.enforce('api', clientIpHash(req));
  if (!config.capabilities().auth) {
    const rows = db.query(
      "SELECT category, COUNT(*) AS count FROM community_counts WHERE counted_at > ? GROUP BY category ORDER BY count DESC",
      [Date.now() - 30 * 24 * 3600 * 1000]
    );
    return sendJson(res, 200, { counts: rows, window: '30d' });
  }
  const result = await db.rest('rpc/api_hazard_counts', { method: 'POST', body: {} });
  if (!result.ok) throw Object.assign(new Error('Could not load insights.'), { status: 502 });
  sendJson(res, 200, { counts: Array.isArray(result.body) ? result.body : [], window: '30d' });
}

/* ----------------------------- uploads ---------------------------- */

async function handleUpload(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);
  await rateLimit.enforce('upload', user.id);

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > config.security.uploads.maxBytes) {
    const err = new Error('File too large.');
    err.status = 413;
    throw err;
  }

  const buffer = await readBody(req, { limit: config.security.uploads.maxBytes });
  const info = uploads.inspect(buffer, String(req.headers['x-file-name'] || ''), String(req.headers['content-type'] || ''));
  const key = uploads.objectKey(user.id, info.ext);

  const upload = await fetch(
    `${config.supabase.url}/storage/v1/object/integrity-evidence/${key}`,
    {
      method: 'POST',
      headers: {
        apikey: config.supabase.publishableKey,
        Authorization: `Bearer ${user.accessToken}`,
        'Content-Type': info.mime,
        'x-upsert': 'false',
      },
      body: buffer,
      signal: AbortSignal.timeout(20000),
    }
  );
  if (!upload.ok) throw Object.assign(new Error('Could not store that file.'), { status: 502 });

  // Trimmed response: the client only needs the object reference + integrity hash.
  sendJson(res, 201, { path: key, mime: info.mime, bytes: info.bytes, sha256: info.sha256 });
}

/**
 * Encrypted whistleblower dossier. The narrative arrives as ciphertext; the
 * server never sees plaintext. Ownership, case reference and status are all
 * bound/derived server-side, so a caller cannot forge or re-point a report.
 */
async function handleCreateIntegrityReport(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);
  await rateLimit.enforce('api', user.id);
  await rateLimit.enforce('forgot', `integrity:${user.id}`);

  const body = await readJson(req);
  v.only(body, ['category', 'county', 'anonymous', 'narrativeCiphertext', 'narrativeIv', 'narrativeSalt', 'mediaPath', 'mediaMime', 'mediaSha256']);

  const record = {
    is_anonymous: body.anonymous === undefined ? true : v.cleanBoolean(body.anonymous, 'anonymous'),
    category: v.cleanEnum(body.category, ['bribery', 'extortion', 'harassment', 'unsafe_vehicle', 'document_fraud', 'other'], 'category'),
    county: body.county ? v.cleanText(body.county, { max: 60, allowNewlines: false, label: 'county' }) : null,
    narrative_ciphertext: v.cleanText(body.narrativeCiphertext, { min: 16, max: 200000, allowNewlines: false, label: 'narrativeCiphertext' }),
    narrative_iv: v.cleanText(body.narrativeIv, { min: 12, max: 64, allowNewlines: false, label: 'narrativeIv' }),
    narrative_salt: v.cleanText(body.narrativeSalt, { min: 16, max: 128, allowNewlines: false, label: 'narrativeSalt' }),
  };

  if (body.mediaPath) {
    record.media_path = v.cleanText(body.mediaPath, { min: 10, max: 160, allowNewlines: false, label: 'mediaPath' });
    // The object key must live under the caller's own folder — this is the
    // authorisation check for evidence attachments.
    if (!record.media_path.startsWith(`${user.id}/`)) {
      const err = new Error('That evidence file does not belong to you.');
      err.status = 403;
      err.code = 'wrong_owner';
      throw err;
    }
    record.media_mime = v.cleanEnum(body.mediaMime, [...config.security.uploads.allowed], 'mediaMime');
    record.media_sha256 = v.cleanText(body.mediaSha256, { min: 64, max: 64, allowNewlines: false, label: 'mediaSha256' });
    if (!/^[0-9a-f]{64}$/.test(record.media_sha256)) {
      throw new v.ValidationError({ mediaSha256: 'Invalid digest.' });
    }
  }

  const result = await db.rest('integrity_reports', {
    method: 'POST',
    accessToken: user.accessToken,
    body: record,
    prefer: 'return=representation',
  });
  if (!result.ok) throw Object.assign(new Error('Could not store that dossier.'), { status: 502 });

  const saved = Array.isArray(result.body) ? result.body[0] : result.body;
  // Trimmed: the case reference is the only handle needed client-side.
  sendJson(res, 201, {
    report: saved ? { caseReference: saved.case_reference, status: saved.status, createdAt: saved.created_at } : null,
  });
}

/* --------------------------- mail handoff ------------------------- */

/**
 * Feedback / hazard / near-miss handoff. The browser used to send these itself
 * with a public EmailJS key; now the server owns the mailbox credentials and
 * applies per-user and per-IP limits so it cannot be abused as a relay.
 */
async function handleFeedback(req, res) {
  // Feedback must work for guests (the app is usable without an account), so
  // this is the one mail path open to anonymous callers — it is therefore the
  // most tightly limited: 5 per hour per client, 3 per hour per address.
  const user = await readOptionalUser(req);
  await rateLimit.enforce('forgot', user ? user.id : clientIpHash(req));
  if (user) await rateLimit.enforce('api', user.id);

  const body = await readJson(req);
  v.only(body, ['subject', 'message', 'replyTo']);

  const subject = v.cleanText(body.subject, { min: 3, max: 120, allowNewlines: false, label: 'subject' });
  const message = v.cleanText(body.message, { min: 5, max: 4000, label: 'message' });
  const replyTo = body.replyTo ? v.cleanEmail(body.replyTo, 'replyTo') : (user ? user.email : null);

  await mailer.enqueue({
    recipient: process.env.FEEDBACK_EMAIL || 'safestepske@gmail.com',
    subject: `[SafeSteps] ${subject}`,
    body: `From: ${user ? user.id : 'guest'} <${replyTo || 'no-reply-address'}>\n\n${message}`,
  });

  // Trimmed acknowledgement only — no internal ids, no mail server details.
  sendJson(res, 202, { status: 'queued' });
}

/**
 * Multi-agency integrity referral. Deliberately narrow: the caller supplies a
 * case reference and a short summary, never a recipient list, so the endpoint
 * cannot be turned into an open relay or used to spam arbitrary addresses.
 */
async function handleIntegrityDispatch(req, res) {
  const user = await requireUser(req);
  requireConfirmed(user);
  await rateLimit.enforce('api', user.id);
  // Referrals are expensive and legally sensitive: a handful per hour at most.
  await rateLimit.enforce('forgot', `dispatch:${user.id}`);

  const body = await readJson(req);
  v.only(body, ['caseReference', 'subject', 'summary', 'anonymous']);

  const caseReference = v.cleanText(body.caseReference, { min: 3, max: 40, allowNewlines: false, label: 'caseReference' });
  const subject = v.cleanText(body.subject, { min: 3, max: 120, allowNewlines: false, label: 'subject' });
  const summary = v.cleanText(body.summary, { min: 5, max: 1500, label: 'summary' });
  const anonymous = body.anonymous === undefined ? true : v.cleanBoolean(body.anonymous, 'anonymous');

  // Fixed desk list — never taken from the request.
  const desks = ['report@eacc.go.ke', 'complaints@kenyapolice.go.ke', 'integrity@ntsa.go.ke'];
  const referrer = anonymous ? 'Anonymous whistleblower (identity withheld by SafeSteps)' : `${user.id} <${user.email}>`;

  for (const desk of desks) {
    await mailer.enqueue({
      recipient: desk,
      subject: `[${caseReference}] ${subject}`,
      body: [
        'OFFICIAL WHISTLEBLOWER REFERRAL — SafeSteps Kenya (Project 360° Shield)',
        '',
        `Case reference: ${caseReference}`,
        `Referring party: ${referrer}`,
        '',
        'Summary of allegation:',
        summary,
        '',
        'Full evidence (ciphertext) is held in the SafeSteps integrity vault and is released only to an authorised desk on request, quoting the case reference.',
      ].join('\n'),
    });
  }

  sendJson(res, 202, { status: 'queued', caseReference });
}

/* --------------------- Supabase Send Email Hook -------------------- */

/**
 * Receives GoTrue's auth mail and relays it through our own transport.
 *
 * Public endpoint by necessity, so the signature is the security boundary: see
 * lib/send-email-hook.js for the Standard-Webhooks check. A request that does
 * not verify is refused before the body is even parsed into anything useful.
 */
async function handleSendEmailHook(req, res) {
  if (!sendEmailHook.isConfigured()) {
    const err = new Error('This endpoint is not enabled on this server.');
    err.status = 503;
    err.code = 'hook_not_configured';
    throw err;
  }

  // Raw body is required: the signature covers the exact bytes sent.
  const raw = await readBody(req, { limit: 64 * 1024 });
  const rawBody = raw.toString('utf8');

  const verdict = sendEmailHook.verifySignature({ headers: req.headers, rawBody });
  if (!verdict.ok) {
    console.warn('[hook] rejected send-email request: %s', verdict.reason);
    const err = new Error('Invalid signature.');
    err.status = 401;
    err.code = 'invalid_signature';
    throw err;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw Object.assign(new Error('Malformed payload.'), { status: 400, code: 'invalid_request' });
  }

  const emailData = (payload && payload.email_data) || {};
  const user = (payload && payload.user) || {};
  const recipient = typeof user.email === 'string' ? user.email.trim().toLowerCase() : '';
  if (!recipient) {
    throw Object.assign(new Error('Payload has no recipient.'), { status: 400, code: 'invalid_request' });
  }

  const { subject, text, code } = sendEmailHook.render({
    actionType: emailData.email_action_type,
    token: emailData.token,
    siteUrl: emailData.site_url,
  });

  const delivery = await mailer.enqueue({
    recipient,
    subject,
    body: text,
    verificationCode: code || null,
  });

  // GoTrue retries on a non-2xx, so only report failure when we genuinely could
  // not hand the message to a transport.
  if (!delivery.delivered) {
    console.error('[hook] mail transport could not deliver auth mail');
    const err = new Error('Mail transport unavailable.');
    err.status = 502;
    err.code = 'mail_undeliverable';
    throw err;
  }

  // Empty object is the documented success response.
  sendJson(res, 200, {});
}

/* ------------------------------ account --------------------------- */

async function handleDeleteAccount(req, res) {
  const user = await requireUser(req);
  session.assertSameOrigin(req);
  session.assertCsrf(req, parseCookies(req));

  // Erases this user's rows via a SECURITY DEFINER function that only ever
  // touches auth.uid()'s own data.
  const result = await db.rest('rpc/api_delete_my_account', {
    method: 'POST',
    accessToken: user.accessToken,
    body: {},
  });
  if (!result.ok) throw Object.assign(new Error('Could not erase your data.'), { status: 502 });

  session.clearSessionCookies(res);
  sendJson(res, 200, { ok: true, message: 'Your SafeSteps data has been erased.' });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

async function handle(req, res, url) {
  const pathname = url.pathname.replace(/\/+$/, '') || '/api';
  const route = `${req.method} ${pathname}`;

  const routes = {
    'GET /api/config': handleConfig,
    'GET /api/auth/challenge': handleChallenge,
    'POST /api/auth/register': handleRegister,
    'POST /api/auth/verify': handleVerify,
    'POST /api/auth/login': handleLogin,
    'POST /api/auth/refresh': handleRefresh,
    'POST /api/auth/logout': handleLogout,
    'GET /api/auth/me': handleMe,
    'POST /api/auth/forgot': handleForgot,
    'POST /api/auth/resend': handleResend,
    'POST /api/reports': handleCreateReport,
    'GET /api/reports': handleListReports,
    'POST /api/quiz-attempts': handleQuizAttempt,
    'POST /api/vault': handleVaultPut,
    'GET /api/vault': handleVaultGet,
    'POST /api/community/hazard': handleCommunityHazard,
    'POST /api/community/insights': handleCommunityInsights,
    'GET /api/community/insights': handleCommunityInsights,
    'POST /api/integrity': handleCreateIntegrityReport,
    'POST /api/feedback': handleFeedback,
    'POST /api/integrity/dispatch': handleIntegrityDispatch,
    'POST /api/uploads': handleUpload,
    'POST /api/account/delete': handleDeleteAccount,
    // Supabase Auth "Send Email Hook" target (signed, not session-authenticated).
    'POST /api/hooks/send-email': handleSendEmailHook,
  };

  const handler = routes[route];
  if (!handler) {
    sendJson(res, 404, { error: 'not_found', message: 'Unknown endpoint.' });
    return;
  }

  try {
    // Global per-client ceiling on the whole API surface.
    await rateLimit.enforce('global', clientIpHash(req));
    await handler(req, res, url);
  } catch (error) {
    if (error instanceof v.ValidationError) {
      sendError(res, error);
      return;
    }
    if (error instanceof auth.AuthError) {
      // A 200 from the auth layer means "accepted, do not disclose more".
      if (error.status === 200) {
        sendJson(res, 202, { status: error.code, message: error.message });
        return;
      }
      sendError(res, error);
      return;
    }
    if (error instanceof uploads.UploadError) {
      sendError(res, error);
      return;
    }
    sendError(res, error);
  }
}

module.exports = { handle, requireUser };
