'use strict';

/**
 * Password reset.
 *
 * The properties under test are the ones that make a reset safe rather than
 * merely present:
 *
 *   • the request endpoint is not an account-enumeration oracle;
 *   • a wrong or used code is refused, and the failure is indistinguishable from
 *     "no such account";
 *   • the new password obeys the same policy as sign-up;
 *   • completing a reset does NOT hand back a session, so a stolen reset code
 *     cannot become a live login;
 *   • the code is single-use.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

const PLATFORM_PORT = 8170;
const MAIL_PORT = 8171;

const HOOK_SECRET_BASE64 = crypto.randomBytes(24).toString('base64');
const HOOK_SECRET = `v1,whsec_${HOOK_SECRET_BASE64}`;

const platform = {
  users: new Map(), // email -> { id, password, recoveryToken }
  verifyCalls: [],
  updateCalls: [],
  adminCalls: [],
};
const mailbox = [];

let platformServer;
let mailServer;
let appServer;
let base;

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

async function fakePlatform(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const raw = await readBody(req);
  const body = raw ? JSON.parse(raw) : {};
  const auth = req.headers.authorization || '';

  if (url.pathname === '/auth/v1/recover') {
    const user = platform.users.get(body.email);
    if (user) {
      // GoTrue would invoke the Send Email hook with this token.
      user.recoveryToken = String(crypto.randomInt(0, 100000000)).padStart(8, '0');
    }
    return json(res, 200, {});
  }

  if (url.pathname === '/auth/v1/verify') {
    platform.verifyCalls.push(body);
    const user = platform.users.get(body.email);
    if (!user || body.type !== 'recovery' || !user.recoveryToken || user.recoveryToken !== body.token) {
      return json(res, 403, { error_code: 'otp_expired', msg: 'Token has expired or is invalid' });
    }
    user.recoveryToken = null; // single use
    return json(res, 200, {
      access_token: 'recovery-session-token',
      refresh_token: 'recovery-refresh',
      expires_in: 900,
      user: { id: user.id, email: user.email },
    });
  }

  if (url.pathname === '/auth/v1/user' && req.method === 'PUT') {
    platform.updateCalls.push({ auth, body });
    if (auth !== 'Bearer recovery-session-token') {
      return json(res, 401, { msg: 'invalid claim: missing sub claim' });
    }
    const user = [...platform.users.values()][0];
    user.password = body.password;
    return json(res, 200, { id: user.id, email: user.email });
  }

  if (url.pathname.startsWith('/auth/v1/admin/users/')) {
    platform.adminCalls.push(url.pathname);
    return json(res, 200, {});
  }

  if (url.pathname === '/auth/v1/token') {
    const user = platform.users.get(body.email);
    if (!user || user.password !== body.password) {
      return json(res, 400, { error_code: 'invalid_credentials', msg: 'Invalid login credentials' });
    }
    return json(res, 200, {
      access_token: 'access-after-reset',
      refresh_token: 'refresh-after-reset',
      expires_in: 3600,
      user: { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString() },
    });
  }

  if (url.pathname.startsWith('/rest/v1/rpc/')) {
    return json(res, 201, {});
  }

  return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
}

/* ------------------------------------------------------------------ */

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SERVICE_ROLE_KEY = '';
process.env.VERIFICATION_PEPPER = 'reset-test-pepper';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8172';
process.env.SQLITE_PATH = ':memory:';
process.env.SERVER_DATA_KEY = crypto.randomBytes(32).toString('base64');
process.env.SMTP_HOST = '';
process.env.SMTP_USER = '';
process.env.SMTP_PASS = '';
process.env.EMAILJS_SERVICE_ID = 'service_reset';
process.env.EMAILJS_TEMPLATE_ID = 'template_default';
process.env.EMAILJS_PUBLIC_KEY = 'public_key_reset';
process.env.EMAILJS_API_URL = `http://127.0.0.1:${MAIL_PORT}/api/v1.0/email/send`;
process.env.SEND_EMAIL_HOOK_SECRET = HOOK_SECRET;

const { createServer } = require('../server');

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36',
  'accept-language': 'en-KE,en;q=0.9',
  origin: process.env.PUBLIC_ORIGIN,
  referer: `${process.env.PUBLIC_ORIGIN}/`,
};

async function botProof() {
  const issued = await (await fetch(`${base}/api/auth/challenge`, { headers: BROWSER })).json();
  const [salt] = issued.challenge.split('.');
  for (let nonce = 0; nonce < 5_000_000; nonce += 1) {
    const hex = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
    let zeros = 0;
    for (const char of hex) {
      if (char !== '0') break;
      zeros += 1;
    }
    if (zeros >= issued.difficulty) {
      await new Promise((r) => setTimeout(r, 1400));
      return { botChallenge: issued.challenge, botNonce: String(nonce) };
    }
  }
  throw new Error('could not solve the bot challenge');
}

function post(pathname, payload) {
  return fetch(`${base}${pathname}`, {
    method: 'POST',
    headers: { ...BROWSER, 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// ---------------------------------------------------------------------------
// Runtime guard: the local store needs node:sqlite, which ships in Node 22.
//
// These tests exercise the non-Supabase path (challenge storage, outbound mail,
// rate-limit counters) and therefore need the local SQLite store. On Node 20
// `node:sqlite` does not exist, so the honest outcome is "skipped for a stated
// reason" rather than a red build that looks like a real regression. The rest of
// the suite, including every Supabase-path test, still runs on Node 20 — which
// is the point of testing the floor declared in package.json.
// ---------------------------------------------------------------------------
if (!require('../lib/db').isAvailable()) {
  const runtime = process.version;
  require('node:test')(
    `local-store tests skipped: this runtime (${runtime}) has no node:sqlite`,
    { skip: `node:sqlite requires Node 22+; running ${runtime}` },
    () => {}
  );
  return;
}

test.before(async () => {
  platformServer = http.createServer((req, res) => {
    fakePlatform(req, res).catch((err) => json(res, 500, { msg: err.message }));
  });
  await new Promise((r) => platformServer.listen(PLATFORM_PORT, '127.0.0.1', r));

  mailServer = http.createServer((req, res) => {
    readBody(req).then((raw) => {
      try {
        mailbox.push(JSON.parse(raw));
      } catch {
        mailbox.push({ raw });
      }
      res.writeHead(200);
      res.end('OK');
    });
  });
  await new Promise((r) => mailServer.listen(MAIL_PORT, '127.0.0.1', r));

  appServer = createServer();
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${appServer.address().port}`;

  platform.users.set('rider@example.org', {
    id: crypto.randomUUID(),
    email: 'rider@example.org',
    password: 'OldPass1',
    recoveryToken: null,
  });
});

test.after(() => {
  if (appServer) appServer.close();
  if (mailServer) mailServer.close();
  if (platformServer) platformServer.close();
});

/* ------------------------------------------------------------------ */

const EMAIL = 'rider@example.org';

test('a reset request does not reveal whether an account exists', async () => {
  const known = await post('/api/auth/forgot', { email: EMAIL, website: '', ...(await botProof()) });
  const knownBody = await known.json();
  assert.equal(known.status, 202);

  const unknown = await post('/api/auth/forgot', { email: 'nobody@example.org', website: '', ...(await botProof()) });
  const unknownBody = await unknown.json();
  assert.equal(unknown.status, 202);

  // Byte-identical responses: the only reliable way to avoid enumeration.
  assert.deepEqual(knownBody, unknownBody);
});

test('a wrong code is refused and changes nothing', async () => {
  const user = platform.users.get(EMAIL);
  user.recoveryToken = '12345678';
  const before = platform.updateCalls.length;

  const response = await post('/api/auth/reset-password', {
    email: EMAIL,
    code: '87654321',
    password: 'NewPass1',
    website: '',
    ...(await botProof()),
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_code');
  assert.equal(platform.updateCalls.length, before, 'a wrong code must not reach the password update');
  assert.equal(user.password, 'OldPass1');
});

test('the password policy is enforced on reset too', async () => {
  const user = platform.users.get(EMAIL);
  user.recoveryToken = '22334455';
  const response = await post('/api/auth/reset-password', {
    email: EMAIL,
    code: '22334455',
    password: 'far-too-long-a-password',
    website: '',
    ...(await botProof()),
  });
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.match(JSON.stringify(body.fields || body), /6 to 8/);
});

test('a correct code sets the password, and does not hand back a session', async () => {
  const user = platform.users.get(EMAIL);
  user.recoveryToken = '55667788';

  const response = await post('/api/auth/reset-password', {
    email: EMAIL,
    code: '55667788',
    password: 'NewPass1',
    website: '',
    ...(await botProof()),
  });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.status, 'reset');

  // The password really changed, through the session the recovery code earned.
  const update = platform.updateCalls.at(-1);
  assert.ok(update, 'the password update must have been attempted');
  assert.equal(update.body.password, 'NewPass1');
  assert.equal(update.auth, 'Bearer recovery-session-token');

  // No session cookie is issued: a stolen reset code must not become a login.
  const cookies = response.headers.getSetCookie ? response.headers.getSetCookie().join('; ') : '';
  assert.equal(/ss_session=[^;]+/.test(cookies), false, 'reset must not issue a session');

  // No token material in the body either.
  assert.equal(/access_token|refresh_token|recovery-session-token/.test(JSON.stringify(body)), false);
});

test('the reset code is single-use', async () => {
  const response = await post('/api/auth/reset-password', {
    email: EMAIL,
    code: '55667788',
    password: 'Other12',
    website: '',
    ...(await botProof()),
  });
  assert.equal(response.status, 400);
  assert.equal(platform.users.get(EMAIL).password, 'NewPass1');
});

test('the new password is the one that now works, and the old one does not', async () => {
  const withOld = await post('/api/auth/login', { email: EMAIL, password: 'OldPass1', ...(await botProof()) });
  assert.equal(withOld.status, 401);

  const withNew = await post('/api/auth/login', { email: EMAIL, password: 'NewPass1', ...(await botProof()) });
  const body = await withNew.json();
  assert.equal(withNew.status, 200, JSON.stringify(body));
  assert.equal(body.user.email, EMAIL);
});
