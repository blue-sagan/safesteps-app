'use strict';

/**
 * End-to-end email sign-up through the **EmailJS** transport.
 *
 * Why a separate file: `auth-flow.test.js` deliberately has no transport at all
 * so it can prove the provider fallback. This file proves the opposite shape —
 * EmailJS configured, no SMTP, no provider fallback — and asserts the property
 * that matters most about it: the key is used server-side only, and the
 * verification code reaches the message that EmailJS is asked to send.
 *
 * There is no route to api.emailjs.com from this environment, so the transport
 * points at a local receiver that speaks the same request shape. Everything
 * else (challenge, linking, mail composition, delivery reporting) is the real
 * server.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

const EMAILJS_PORT = 8140;

const received = [];
let emailjsServer;
// Minimal stand-in for the auth service: this test is about the *mail
// transport*, so the fake only has to accept a sign-up. The full auth journey
// (confirmation, cookies, sessions) lives in auth-flow.test.js.
const authUsers = new Map();
let authServer;
const AUTH_PORT = 8142;

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(JSON.parse(raw || '{}'));
      } catch {
        resolve({ raw });
      }
    });
  });
}

async function fakeEmailJs(req, res) {
  const body = await readBody(req);
  received.push({ path: req.url, headers: req.headers, body });
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
}

/* ------------------------------------------------------------------ */
/* Configuration: EmailJS on, everything else that could send off      */
/* ------------------------------------------------------------------ */

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = `http://127.0.0.1:${AUTH_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
// No service-role key: no provider fallback and no remote queue, so the
// EmailJS transport is the only thing that can deliver.
process.env.SUPABASE_SERVICE_ROLE_KEY = '';
process.env.VERIFICATION_PEPPER = 'test-pepper-emailjs';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8141';
process.env.SQLITE_PATH = ':memory:';
process.env.SERVER_DATA_KEY = crypto.randomBytes(32).toString('base64');

process.env.SMTP_HOST = '';
process.env.SMTP_USER = '';
process.env.SMTP_PASS = '';

process.env.EMAILJS_SERVICE_ID = 'service_under_test';
process.env.EMAILJS_TEMPLATE_ID = 'template_default';
process.env.EMAILJS_TEMPLATE_VERIFICATION = 'template_verify';
process.env.EMAILJS_PUBLIC_KEY = 'public_key_under_test';
process.env.EMAILJS_PRIVATE_KEY = 'private_key_under_test';

const { createServer } = require('../server');
const config = require('../lib/config');

let appServer;
let base;

const BROWSER = {
  'user-agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124 Safari/537.36',
  'accept-language': 'en-KE,en;q=0.9',
  origin: process.env.PUBLIC_ORIGIN,
  referer: `${process.env.PUBLIC_ORIGIN}/`,
};

function botProof() {
  return (async () => {
    const issued = await (await fetch(`${base}/api/auth/challenge`, { headers: BROWSER })).json();
    const [salt] = issued.challenge.split('.');
    for (let nonce = 0; nonce < 5_000_000; nonce += 1) {
      const hex = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
      let zeros = 0;
      for (const char of hex) {
        if (char !== '0') break;
        zeros += 1;
      }
      if (zeros >= issued.difficulty) return { botChallenge: issued.challenge, botNonce: String(nonce) };
    }
    throw new Error('could not solve the bot challenge');
  })();
}

async function fakeAuth(req, res) {
  const body = await readBody(req);
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/auth/v1/signup') {
    const id = crypto.randomUUID();
    authUsers.set(body.email, { id, email: body.email });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id, email: body.email, identities: [{ id }] }));
    return;
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ msg: `fake auth: unhandled ${req.method} ${url.pathname}` }));
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
  authServer = http.createServer((req, res) => {
    fakeAuth(req, res).catch(() => {
      res.writeHead(500);
      res.end();
    });
  });
  await new Promise((resolve) => authServer.listen(AUTH_PORT, '127.0.0.1', resolve));

  emailjsServer = http.createServer((req, res) => {
    fakeEmailJs(req, res).catch(() => {
      res.writeHead(500);
      res.end();
    });
  });
  await new Promise((resolve) => emailjsServer.listen(EMAILJS_PORT, '127.0.0.1', resolve));
  process.env.EMAILJS_API_URL = `http://127.0.0.1:${EMAILJS_PORT}/api/v1.0/email/send`;

  // The dwell-time bot check rejects anything submitted too quickly.
  await new Promise((resolve) => setTimeout(resolve, 1300));

  appServer = createServer();
  await new Promise((resolve) => appServer.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${appServer.address().port}`;
});

test.after(() => {
  if (appServer) appServer.close();
  if (emailjsServer) emailjsServer.close();
  if (authServer) authServer.close();
});

test('EmailJS is reported as the live transport, with no credential exposed', async () => {
  assert.equal(config.capabilities().mailTransport, true);
  assert.deepEqual(config.mailTransports(), { smtp: false, emailjs: true, supabaseAuth: true });

  const health = await (await fetch(`${base}/healthz`)).json();
  assert.equal(health.mailTransports.emailjs, true);
  // Booleans only — the values must not appear anywhere in the payload.
  const raw = JSON.stringify(health);
  assert.equal(/service_under_test|public_key_under_test|private_key_under_test/.test(raw), false);
});

test('sign-up delivers the 8-digit code through EmailJS', async () => {
  const email = `emailjs.user.${Date.now()}@example.org`;
  const solved = await botProof();
  // The challenge must be older than the dwell-time floor (a form cannot be
  // filled in instantly), so wait it out the way a person would.
  await new Promise((resolve) => setTimeout(resolve, 1400));

  const response = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { ...BROWSER, 'content-type': 'application/json' },
    body: JSON.stringify({
      fullName: 'EmailJS Probe',
      email,
      password: 'Probe1x',
      website: '',
      ...solved,
    }),
  });

  const body = await response.json();
  assert.equal(response.status, 202, JSON.stringify(body));
  assert.equal(body.delivered, true, 'the server must report the transport delivered the mail');
  assert.equal(body.codeLength, 8);

  assert.equal(received.length, 1, 'exactly one message should have been sent');
  const sent = received[0].body;

  // Request shape the EmailJS API requires.
  assert.equal(sent.service_id, 'service_under_test');
  assert.equal(sent.user_id, 'public_key_under_test');
  assert.equal(sent.accessToken, 'private_key_under_test');
  assert.equal(sent.template_id, 'template_verify', 'verification mail uses the verification template');

  // Delivery target and content.
  assert.equal(sent.template_params.to_email, email);
  assert.match(String(sent.template_params.subject).toLowerCase(), /verif|code|safesteps/);
  assert.match(String(sent.template_params.verification_code), /^\d{8}$/, 'the code must arrive as its own template variable');
  // The same code must appear in the rendered body, so a template that only
  // prints `message` still shows it.
  assert.ok(String(sent.template_params.message).includes(sent.template_params.verification_code));

  // The key travels in the body over TLS to the provider, never to a browser.
  const page = await (await fetch(`${base}/`)).text();
  assert.equal(/public_key_under_test|private_key_under_test|service_under_test/.test(page), false);
  for (const header of ['set-cookie', 'x-emailjs-key']) {
    assert.equal(received[0].headers[header], undefined, `${header} must not be used to carry the key`);
  }
});
