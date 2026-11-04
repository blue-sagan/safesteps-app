'use strict';

/**
 * Supabase Send Email Hook → EmailJS → `/verify`.
 *
 * This is the shape that makes email sign-in work with **no service-role key**:
 * the auth service generates the code, signs a request to
 * /api/hooks/send-email, we relay it through EmailJS, and the code the user
 * types goes straight back to GoTrue's /verify, which returns a real session.
 *
 * The tests that matter here are the negative ones — the endpoint is public by
 * necessity, so the signature is the only thing preventing it from being an open
 * relay for mail to arbitrary addresses.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

const PLATFORM_PORT = 8160;
const MAIL_PORT = 8161;

const HOOK_SECRET_BASE64 = crypto.randomBytes(24).toString('base64');
const HOOK_SECRET = `v1,whsec_${HOOK_SECRET_BASE64}`;

const mailbox = [];
const platform = {
  users: new Map(),
  otpTokens: new Map(), // email -> token the auth service will accept
  verifyCalls: [],
  adminCalls: [],
};

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

  if (url.pathname === '/auth/v1/signup') {
    const user = { id: crypto.randomUUID(), email: body.email };
    platform.users.set(body.email, user);
    // GoTrue would now invoke the Send Email Hook. This file invokes it itself,
    // so it can sign the request exactly as Supabase does.
    const token = String(crypto.randomInt(0, 100000000)).padStart(8, '0');
    platform.otpTokens.set(body.email, token);
    return json(res, 200, { id: user.id, email: user.email, identities: [{ id: user.id }] });
  }

  if (url.pathname === '/auth/v1/verify') {
    platform.verifyCalls.push(body);
    const expected = platform.otpTokens.get(body.email);
    if (!expected || expected !== body.token) {
      return json(res, 403, { error_code: 'otp_expired', msg: 'Token has expired or is invalid' });
    }
    platform.otpTokens.delete(body.email);
    const user = platform.users.get(body.email);
    return json(res, 200, {
      access_token: 'hook-access-token',
      refresh_token: 'hook-refresh-token',
      expires_in: 3600,
      user: { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString() },
    });
  }

  if (url.pathname.startsWith('/auth/v1/admin/users/')) {
    platform.adminCalls.push(url.pathname);
    return json(res, 200, {});
  }

  if (url.pathname === '/auth/v1/user') {
    const user = [...platform.users.values()][0];
    return json(res, 200, { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString() });
  }

  if (url.pathname.startsWith('/rest/v1/rpc/')) {
    return json(res, 201, {});
  }

  return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
}

/* ------------------------------------------------------------------ */
/* Configuration: hook + EmailJS, deliberately NO service-role key     */
/* ------------------------------------------------------------------ */

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SERVICE_ROLE_KEY = '';
process.env.VERIFICATION_PEPPER = 'hook-test-pepper';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8162';
process.env.SQLITE_PATH = ':memory:';
process.env.SERVER_DATA_KEY = crypto.randomBytes(32).toString('base64');
process.env.SMTP_HOST = '';
process.env.SMTP_USER = '';
process.env.SMTP_PASS = '';
process.env.EMAILJS_SERVICE_ID = 'service_hook';
process.env.EMAILJS_TEMPLATE_ID = 'template_default';
process.env.EMAILJS_TEMPLATE_VERIFICATION = 'template_verify';
process.env.EMAILJS_PUBLIC_KEY = 'public_key_hook';
process.env.EMAILJS_API_URL = `http://127.0.0.1:${MAIL_PORT}/api/v1.0/email/send`;
process.env.SEND_EMAIL_HOOK_SECRET = HOOK_SECRET;

const { createServer } = require('../server');
const config = require('../lib/config');
const hook = require('../lib/send-email-hook');

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36',
  'accept-language': 'en-KE,en;q=0.9',
  origin: process.env.PUBLIC_ORIGIN,
  referer: `${process.env.PUBLIC_ORIGIN}/`,
};

/** Sign a body exactly the way Standard Webhooks (and Supabase) do. */
function signHook(rawBody, { id = crypto.randomUUID(), timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const key = Buffer.from(HOOK_SECRET_BASE64, 'base64');
  const signature = crypto
    .createHmac('sha256', key)
    .update(`${id}.${timestamp}.${rawBody}`)
    .digest('base64');
  return {
    headers: {
      'content-type': 'application/json',
      'webhook-id': id,
      'webhook-timestamp': String(timestamp),
      'webhook-signature': `v1,${signature}`,
    },
    body: rawBody,
  };
}

function hookPayload(email, token, actionType = 'signup') {
  return JSON.stringify({
    user: { email, id: 'x' },
    email_data: {
      token,
      token_hash: 'hash',
      redirect_to: '',
      email_action_type: actionType,
      site_url: process.env.PUBLIC_ORIGIN,
    },
  });
}

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
});

test.after(() => {
  if (appServer) appServer.close();
  if (mailServer) mailServer.close();
  if (platformServer) platformServer.close();
});

/* ------------------------------------------------------------------ */
/* The signature is the security boundary                              */
/* ------------------------------------------------------------------ */

test('the hook endpoint refuses unsigned and tampered requests', async () => {
  const payload = hookPayload('victim@example.org', '12345678');

  // No signature at all.
  const unsigned = await fetch(`${base}/api/hooks/send-email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: payload,
  });
  assert.equal(unsigned.status, 401);

  // Correct signature, tampered body — the classic replay-to-someone-else.
  const signed = signHook(payload);
  const tampered = JSON.stringify({
    user: { email: 'attacker-chosen@example.org', id: 'x' },
    email_data: { token: '87654321', email_action_type: 'signup', site_url: '' },
  });
  const tamperedResponse = await fetch(`${base}/api/hooks/send-email`, {
    method: 'POST',
    headers: signed.headers,
    body: tampered,
  });
  assert.equal(tamperedResponse.status, 401);

  // A stale timestamp (replay) is refused even with a valid signature.
  const stale = signHook(payload, { timestamp: Math.floor(Date.now() / 1000) - 3600 });
  const staleResponse = await fetch(`${base}/api/hooks/send-email`, {
    method: 'POST',
    headers: stale.headers,
    body: stale.body,
  });
  assert.equal(staleResponse.status, 401);

  // Nothing reached the mail transport for any of those.
  assert.equal(mailbox.length, 0, 'rejected requests must not send mail');
});

test('the hook endpoint is inert when no secret is configured', async () => {
  const saved = process.env.SEND_EMAIL_HOOK_SECRET;
  process.env.SEND_EMAIL_HOOK_SECRET = '';
  try {
    const hookModulePath = require.resolve('../lib/send-email-hook');
    delete require.cache[hookModulePath];
    const fresh = require('../lib/send-email-hook');
    assert.equal(fresh.isConfigured(), false);
  } finally {
    process.env.SEND_EMAIL_HOOK_SECRET = saved;
    delete require.cache[require.resolve('../lib/send-email-hook')];
  }
  // The live module still honours its own configured state.
  assert.equal(hook.isConfigured(), true);
});

test('a correctly signed request is relayed through EmailJS', async () => {
  const payload = hookPayload('driver@example.org', '24681357');
  const signed = signHook(payload);
  const response = await fetch(`${base}/api/hooks/send-email`, {
    method: 'POST',
    headers: signed.headers,
    body: signed.body,
  });
  assert.equal(response.status, 200, await response.text());

  assert.equal(mailbox.length, 1);
  const sent = mailbox[0];
  assert.equal(sent.template_id, 'template_verify');
  assert.equal(sent.template_params.to_email, 'driver@example.org');
  assert.equal(String(sent.template_params.verification_code), '24681357');
  assert.ok(String(sent.template_params.message).includes('24681357'));
  // The hook secret must never be forwarded to the mail provider.
  assert.equal(JSON.stringify(sent).includes(HOOK_SECRET_BASE64), false);
});

/* ------------------------------------------------------------------ */
/* The whole journey, with no admin key                                */
/* ------------------------------------------------------------------ */

test('sign-up → hooked code → verify issues a session, with no service-role key', async (t) => {
  const email = 'hookflow@example.org';

  await t.test('registration reports delivery and does not send a second code', async () => {
    const before = mailbox.length;
    const response = await fetch(`${base}/api/auth/register`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Hook Flow',
        email,
        password: 'Probe1x',
        website: '',
        ...(await botProof()),
      }),
    });
    const body = await response.json();
    assert.equal(response.status, 202, JSON.stringify(body));
    assert.equal(body.delivered, true);
    // Exactly no extra mail: the auth service owns the code now.
    assert.equal(mailbox.length, before, 'the server must not compose a competing code');
  });

  await t.test('a wrong code is refused by the auth service', async () => {
    const response = await fetch(`${base}/api/auth/verify`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email, code: '00000001', ...(await botProof()) }),
    });
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error, 'invalid_code');
  });

  await t.test('the correct code returns a session in hardened cookies', async () => {
    const response = await fetch(`${base}/api/auth/verify`, {
      method: 'POST',
      headers: { ...BROWSER, 'content-type': 'application/json' },
      body: JSON.stringify({ email, code: platform.otpTokens.get(email), ...(await botProof()) }),
    });
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(body.status, 'verified');
    assert.equal(body.user.email, email);
    assert.equal(body.user.emailVerified, true);

    const cookies = response.headers.getSetCookie
      ? response.headers.getSetCookie().join('; ')
      : response.headers.get('set-cookie');
    // This run is not production, so the cookie is `ss_session`; the `__Host-`
    // prefix only applies with Secure (see security.test.js for that assertion).
    assert.match(cookies, /(?:__Host-)?ss_session=/);
    assert.match(cookies, /HttpOnly/);
    assert.match(cookies, /SameSite=Strict/);
    assert.match(cookies, /ss_refresh=/);
    // No token in the JSON.
    assert.equal(/access_token|refresh_token|hook-access-token/.test(JSON.stringify(body)), false);

    // The admin API was never used: this whole flow works without it.
    assert.equal(platform.adminCalls.length, 0);
  });
});
