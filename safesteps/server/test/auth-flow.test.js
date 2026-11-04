'use strict';

/**
 * End-to-end auth flow test.
 *
 * The sandbox has no route to *.supabase.co, so instead of hand-waving that
 * "email login works", this file stands up a faithful fake of the exact
 * endpoints the server calls (GoTrue: /signup, /otp, /token, /admin/users/:id,
 * /user; PostgREST: the service-role RPCs) and drives the real SafeSteps server
 * through the whole journey:
 *
 *   register → verification email → verify code → login → authenticated profile
 *
 * Everything under test is our code: challenge linking, the no-SMTP provider
 * fallback, trusted email confirmation, delivery reporting, cookie issuance and
 * the "email not confirmed" path.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

const PORT = 8130;

/* ------------------------------------------------------------------ */
/* Fake auth platform                                                  */
/* ------------------------------------------------------------------ */
const state = {
  users: new Map(), // email -> { id, password, confirmed, identities }
  challenges: new Map(), // id -> { emailHash, userId }
  otpRequests: [],
  adminConfirms: [],
  loginsAttempted: 0,
  queue: [], // emails handed to the (fake) Postgres queue
};

let fakeServer;

function readJsonBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        resolve({});
      }
    });
  });
}

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

async function fakePlatform(req, res) {
  const url = new URL(req.url, 'http://fake');
  const body = req.method === 'POST' || req.method === 'PUT' ? await readJsonBody(req) : {};

  // ---- GoTrue ----
  if (url.pathname === '/auth/v1/signup') {
    const existing = state.users.get(body.email);
    if (existing) {
      // GoTrue obfuscates: returns a user shape with no identities.
      return json(res, 200, { id: existing.id, email: body.email, identities: [] });
    }
    const user = {
      id: crypto.randomUUID(),
      email: body.email,
      password: body.password,
      confirmed: false,
      identities: [{ provider: 'email' }],
    };
    state.users.set(body.email, user);
    return json(res, 200, { id: user.id, email: user.email, identities: user.identities, email_confirmed_at: null });
  }

  if (url.pathname === '/auth/v1/otp') {
    state.otpRequests.push(body.email);
    return json(res, 200, {});
  }

  if (url.pathname === '/auth/v1/token' && url.searchParams.get('grant_type') === 'password') {
    state.loginsAttempted += 1;
    const user = state.users.get(body.email);
    if (!user || user.password !== body.password) {
      return json(res, 400, { error: 'invalid_grant', error_description: 'Invalid login credentials' });
    }
    if (!user.confirmed) {
      return json(res, 400, { error: 'invalid_grant', error_description: 'Email not confirmed' });
    }
    return json(res, 200, {
      access_token: `access-${user.id}`,
      refresh_token: `refresh-${user.id}`,
      token_type: 'bearer',
      expires_in: 3600,
      user: { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString(), user_metadata: {} },
    });
  }

  if (url.pathname === '/auth/v1/token' && url.searchParams.get('grant_type') === 'refresh_token') {
    const user = [...state.users.values()][0];
    return json(res, 200, {
      access_token: `access2-${user.id}`,
      refresh_token: `refresh2-${user.id}`,
      expires_in: 3600,
      user: { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString(), user_metadata: {} },
    });
  }

  if (url.pathname === '/auth/v1/logout') return json(res, 204, {});

  if (url.pathname === '/auth/v1/user') {
    const token = String(req.headers.authorization || '').replace('Bearer ', '');
    const user = [...state.users.values()].find((u) => token === `access-${u.id}` || token === `access2-${u.id}`);
    if (!user || !user.confirmed) return json(res, 401, { msg: 'invalid claim' });
    return json(res, 200, {
      id: user.id,
      email: user.email,
      email_confirmed_at: new Date().toISOString(),
      user_metadata: { full_name: 'Probe User' },
    });
  }

  const adminMatch = url.pathname.match(/^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})$/);
  if (adminMatch) {
    const user = [...state.users.values()].find((u) => u.id === adminMatch[1]);
    if (!user) return json(res, 404, { msg: 'user not found' });
    user.confirmed = true;
    state.adminConfirms.push(user.id);
    return json(res, 200, { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString() });
  }

  // ---- PostgREST (service-role RPCs used by the server) ----
  if (url.pathname === '/rest/v1/rpc/api_create_challenge') {
    state.challenges.set(body.p_id, { emailHash: body.p_email_hash, userId: body.p_user_id });
    return json(res, 204, {});
  }
  if (url.pathname === '/rest/v1/rpc/api_user_id_by_email') {
    const user = state.users.get(body.p_email);
    return json(res, 200, user ? user.id : null);
  }
  if (url.pathname === '/rest/v1/profiles') {
    return json(res, 200, [
      { id: 'x', display_name: 'Probe User', county: null, email_verified_at: null, created_at: new Date().toISOString() },
    ]);
  }
  if (url.pathname === '/rest/v1/rpc/api_enqueue_mail') {
    state.queue.push({ to: body.p_recipient, subject: body.p_subject, body: body.p_body });
    return json(res, 204, {});
  }
  if (url.pathname === '/rest/v1/rpc/api_check_rate_limit') {
    return json(res, 200, [{ allowed: true, remaining: 99, retry_after: 0 }]);
  }

  return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
}

/* ------------------------------------------------------------------ */
/* Boot: fake platform + the real SafeSteps server                     */
/* ------------------------------------------------------------------ */

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = `http://127.0.0.1:${PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
process.env.VERIFICATION_PEPPER = 'test-pepper';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8131';
process.env.SQLITE_PATH = ':memory:';
// Deliberately NO SMTP_* and NO SERVER_DATA_KEY: this exercises the hardest
// deployment shape (no local mail transport, code readable from the queue).

const { createServer } = require('../server');
const config = require('../lib/config');
const db = require('../lib/db');

let appServer;
let base;

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121 Safari/537.36',
  'accept-language': 'en-KE,en;q=0.9',
  origin: process.env.PUBLIC_ORIGIN,
  referer: `${process.env.PUBLIC_ORIGIN}/`,
};

function solveChallenge(challenge) {
  const [salt] = challenge.split('.');
  const difficulty = 4;
  for (let nonce = 0; nonce < 5_000_000; nonce += 1) {
    const hex = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
    if (hex.startsWith('0'.repeat(difficulty))) return String(nonce);
  }
  throw new Error('no solution');
}

async function botProof() {
  const issued = await (await fetch(`${base}/api/auth/challenge`)).json();
  const nonce = solveChallenge(issued.challenge);
  // The server enforces a 1.2s dwell floor, so wait like a human would.
  await new Promise((r) => setTimeout(r, config.security ? 1250 : 1250));
  return { botChallenge: issued.challenge, botNonce: nonce };
}

/**
 * Pull the verification code out of the queued (not yet delivered) email.
 * Checks both stores: the remote queue when it accepted the write, the local
 * queue otherwise (the fallback path must work too).
 */
function codeFromQueue() {
  const bodies = state.queue.map((m) => m.body);
  if (!bodies.length) {
    for (const row of db.query('SELECT body FROM outbound_mail ORDER BY id DESC LIMIT 5')) {
      bodies.push(row.body);
    }
  }
  assert.ok(bodies.length, 'a verification email should have been queued');
  for (let body of bodies) {
    // The spool is encrypted at rest when SERVER_DATA_KEY is set — which is the
    // production behaviour we want, so decrypt here rather than weaken it.
    if (typeof body === 'string' && body.startsWith('v1.') && config.security.serverDataKey) {
      assert.match(body, /^v1\.[^.]*\.[^.]*\.[A-Za-z0-9+/=]+$/, 'spooled mail must be ciphertext');
      body = db.decryptAtRest(body, config.security.serverDataKey);
    }
    const match = String(body).match(/\b(\d{8})\b/);
    if (match) return match[1];
  }
  assert.fail(`expected an 8-digit code in: ${String(bodies[0]).slice(0, 200)}`);
}

test.before(async () => {
  fakeServer = http.createServer((req, res) => {
    fakePlatform(req, res).catch((err) => json(res, 500, { msg: err.message }));
  });
  await new Promise((r) => fakeServer.listen(PORT, '127.0.0.1', r));

  appServer = createServer();
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${appServer.address().port}`;
});

test.after(() => {
  if (appServer) appServer.close();
  if (fakeServer) fakeServer.close();
});

/* ------------------------------------------------------------------ */
/* The flow                                                            */
/* ------------------------------------------------------------------ */

const EMAIL = 'probe.user@example.org';
const PASSWORD = 'ProbePassw0rd1';

test('email sign-up, verification, then login — the whole journey', async (t) => {
  const bot = await botProof();

  await t.test('1. registration creates the account and issues a challenge', async () => {
    const response = await fetch(`${base}/api/auth/register`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Probe User',
        email: EMAIL,
        password: PASSWORD,
        website: '',
        ...bot,
      }),
    });
    const body = await response.json();
    assert.equal(response.status, 202, JSON.stringify(body));
    assert.equal(body.status, 'verification_required');
    // The fallback provider mails the code, so delivery must be reported true.
    assert.equal(body.delivered, true, 'verification email should be delivered via the provider fallback');
    assert.equal(body.codeLength, 8);

    // The provider path was used (no SMTP configured).
    assert.deepEqual(state.otpRequests, [EMAIL]);
    // …and the challenge was persisted with the user id link.
    const [challenge] = [...state.challenges.values()];
    assert.ok(challenge, 'challenge should be persisted to the database');
    const user = state.users.get(EMAIL);
    assert.equal(challenge.userId, user.id, 'challenge must be linked to the new user');
    assert.equal(user.confirmed, false, 'account stays unconfirmed until the code is verified');
  });

  await t.test('2. login before verification is refused with a clear reason', async () => {
    const response = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD, ...(await botProof()) }),
    });
    const body = await response.json();
    assert.equal(response.status, 403);
    assert.equal(body.error, 'email_unconfirmed');
  });

  await t.test('3. a wrong code is rejected and counted', async () => {
    const response = await fetch(`${base}/api/auth/verify`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, code: '00000000', ...(await botProof()) }),
    });
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.equal(body.error, 'invalid_code');
  });

  await t.test('4. the emailed code confirms the address server-side', async () => {
    const code = codeFromQueue();
    const response = await fetch(`${base}/api/auth/verify`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, code, ...(await botProof()) }),
    });
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(body.status, 'verified');
    // The trusted (service-role) confirmation actually ran.
    assert.equal(state.users.get(EMAIL).confirmed, true);
    assert.deepEqual(state.adminConfirms, [state.users.get(EMAIL).id]);
  });

  await t.test('5. the code is single-use', async () => {
    const code = codeFromQueue();
    const response = await fetch(`${base}/api/auth/verify`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, code, ...(await botProof()) }),
    });
    assert.equal(response.status, 400, 'a consumed code must not work twice');
  });

  await t.test('6. login now succeeds and sets hardened cookies', async () => {
    const response = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD, ...(await botProof()) }),
    });
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));

    // Trimmed response: identity only, no token envelope.
    assert.deepEqual(Object.keys(body.user).sort(), ['email', 'emailVerified', 'fullName', 'id']);
    assert.equal(body.user.email, EMAIL);
    assert.equal(body.user.emailVerified, true);
    assert.equal(JSON.stringify(body).includes('access-'), false, 'tokens must not leak to the client');
    assert.equal(body.refresh_token, undefined);

    const cookies = response.headers.getSetCookie();
    const session = cookies.find((c) => c.startsWith('ss_session='));
    const refresh = cookies.find((c) => c.startsWith('ss_refresh='));
    const csrf = cookies.find((c) => c.startsWith('ss_csrf='));
    assert.ok(session && refresh && csrf, `expected session/refresh/csrf cookies, got: ${cookies.join(' | ')}`);
    assert.match(session, /HttpOnly/);
    assert.match(session, /SameSite=Strict/);
    assert.match(refresh, /Path=\/api\/auth/);
    assert.equal(/HttpOnly/.test(csrf), false, 'CSRF cookie must be readable by the app');

    // The session cookie now authenticates a real request.
    const cookieHeader = [session, csrf].map((c) => c.split(';')[0]).join('; ');
    const me = await fetch(`${base}/api/auth/me`, { headers: { ...BROWSER, cookie: cookieHeader } });
    assert.equal(me.status, 200);
    const profile = await me.json();
    assert.equal(profile.user.email, EMAIL);
    assert.equal(profile.user.emailVerified, true);
  });

  await t.test('7. a registered address does not reveal itself', async () => {
    const response = await fetch(`${base}/api/auth/register`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Probe User',
        email: EMAIL,
        password: PASSWORD,
        website: '',
        ...(await botProof()),
      }),
    });
    // Same shape as a brand-new sign-up: no enumeration signal.
    assert.equal(response.status, 202);
    assert.equal((await response.json()).status, 'verification_required');
  });
});

test('verification reports the missing account instead of silently succeeding', async () => {
  // A code that was never issued for this address.
  const response = await fetch(`${base}/api/auth/verify`, {
    method: 'POST',
    headers: { ...BROWSER, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'nobody@example.org', code: '12345678', ...(await botProof()) }),
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_code');
});
