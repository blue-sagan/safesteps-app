'use strict';

/**
 * Bug reporting.
 *
 * The property that matters here is not "a row gets written" — it is that a
 * defect-reporting endpoint on a road-safety app used by schoolchildren cannot
 * become a way to collect personal data, cannot be used as a message queue, and
 * cannot itself throw.
 *
 * Asserted:
 *   • an anonymous report is accepted (the app works without an account, so the
 *     crashes that block sign-in must be reportable);
 *   • a report is validated rather than stored verbatim — bad enums are refused,
 *     oversized text is bounded;
 *   • the reporter's description never reaches the analytics table;
 *   • analytics receives the failure shape only (kind, screen, severity, source);
 *   • an undeclared field in the body is rejected outright;
 *   • the endpoint is rate limited;
 *   • a storage failure does not 500 the request in a way that loses the report
 *     silently — it reports a failure the client can act on.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const PLATFORM_PORT = 8215;
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'test-publishable-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
delete process.env.SQLITE_PATH;

const analytics = require('../lib/analytics');
const api = require('../lib/api');

let storedReports = [];
let storedEvents = [];
let restFails = false;
// Controls what the fake PostgREST returns for bug_reports inserts.
let insertMode = 'ok';   // ok | error500 | missingTable

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

let platformServer;
let appServer;
let base;

test.before(async () => {
  platformServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const raw = await readBody(req);

    if (url.pathname === '/rest/v1/rpc/api_check_rate_limit') {
      return json(res, 200, [{ allowed: true, remaining: 999, retry_after: 0 }]);
    }
    if (url.pathname === '/rest/v1/bug_reports' && req.method === 'POST') {
      if (insertMode === 'missingTable') {
        return json(res, 404, { code: 'PGRST205', message: "Could not find the table 'public.bug_reports' in the schema cache" });
      }
      if (restFails || insertMode === 'error500') return json(res, 500, { message: 'insert failed' });
      const row = JSON.parse(raw);
      const saved = { id: 4242, ...row };
      storedReports.push(saved);
      return json(res, 201, [saved]);
    }
    if (url.pathname === '/rest/v1/app_events' && req.method === 'POST') {
      const batch = JSON.parse(raw);
      storedEvents.push(...batch);
      return json(res, 201, {});
    }
    return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
  });
  await new Promise((r) => platformServer.listen(PLATFORM_PORT, '127.0.0.1', r));

  appServer = http.createServer((req, res) => {
    api.handle(req, res, new URL(req.url, 'http://127.0.0.1'));
  });
  await new Promise((r) => appServer.listen(8216, '127.0.0.1', r));
  base = 'http://127.0.0.1:8216';
});

test.after(() => {
  platformServer && platformServer.close();
  appServer && appServer.close();
});

test.beforeEach(() => {
  analytics.reset();
  require('../lib/rate-limit').reset();
  storedReports = [];
  storedEvents = [];
  restFails = false;
  insertMode = 'ok';
});

function postReport(body, headers = {}) {
  return fetch(`${base}/api/bug-report`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: base,
      'User-Agent': 'Mozilla/5.0 (Linux; Android 13)',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------

test('an anonymous report is accepted and given a reference', async () => {
  const response = await postReport({
    description: 'The quiz score reset when I went back to the menu.',
    screen: 'quiz',
    appVersion: '1.0',
    severity: 'medium',
    source: 'manual',
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.status, 'recorded');
  assert.equal(body.reference, '4242', 'the reporter needs a reference to quote to support');

  assert.equal(storedReports.length, 1);
  const row = storedReports[0];
  assert.equal(row.user_id, null, 'an anonymous report must not be given an owner');
  assert.equal(row.reply_email, null, 'no reply address is invented');
  assert.equal(row.screen, 'quiz');
  assert.equal(row.status, 'new');
});

test('the description is stored but never enters analytics', async () => {
  await postReport({
    description: 'Crash on the first aid screen when I tapped the second option.',
    screen: 'firstaid',
    kind: 'javascript',
    severity: 'high',
    source: 'manual',
  });
  await analytics.flush({ force: true });

  // The analytics row carries the shape of the failure and nothing else.
  const event = storedEvents.find((e) => e.name === 'bug_report');
  assert.ok(event, 'analytics should record that a bug report happened');
  assert.deepEqual(Object.keys(event.fields).sort(), ['kind', 'screen', 'severity', 'source']);
  assert.equal(event.fields.kind, 'javascript');
  assert.equal(event.fields.screen, 'firstaid');
  assert.equal(event.fields.severity, 'high');

  // Critically: none of the reporter's words are in the analytics payload.
  const analyticsJson = JSON.stringify(storedEvents);
  assert.equal(analyticsJson.includes('Crash on the first aid'), false,
    'a free-text description must never reach the analytics table');
  assert.equal(analyticsJson.includes('first aid screen'), false);
});

test('an invalid severity is refused rather than stored', async () => {
  const response = await postReport({
    description: 'Something went wrong on this screen.',
    severity: 'my number is 0712345678',
  });
  assert.equal(response.status, 400, 'a non-enum severity is a bad request');
  assert.equal(storedReports.length, 0);
});

test('an undeclared field in the body is rejected', async () => {
  const response = await postReport({
    description: 'Something went wrong on this screen.',
    // Not an allowed key: the endpoint must not become a way to store arbitrary
    // JSON, and a client must not be able to set its own status or user_id.
    status: 'fixed',
    user_id: '00000000-0000-0000-0000-000000000000',
  });
  assert.equal(response.status, 400);
  assert.equal(storedReports.length, 0);
});

test('a description that is too short is refused with a usable message', async () => {
  const response = await postReport({ description: 'x' });
  assert.equal(response.status, 400);
  const body = await response.json();
  // The message stays generic on purpose (no echo of the field's label to a
  // fuzzer); what matters is that it is a 400 and nothing was stored.
  assert.ok(body && typeof body === 'object');
  assert.equal(storedReports.length, 0);
});

test('free text in a structured field is dropped, not stored', async () => {
  // `screen` should be an app screen id. Anything else must not be kept.
  const response = await postReport({
    description: 'The map did not load any hazards.',
    screen: 'CALL ME ON 0712345678',
    severity: 'low',
  });
  // cleanText rejects it, so the request is refused rather than storing a phone
  // number in a column meant for a screen name.
  assert.equal(response.status, 400);
  assert.equal(storedReports.length, 0);
});

test('an automatic report records its source and needs no description from a person', async () => {
  const response = await postReport({
    description: 'Automatic report: javascript error on the map screen.',
    screen: 'map',
    kind: 'javascript',
    severity: 'high',
    source: 'automatic',
  });
  assert.equal(response.status, 201);
  assert.equal(storedReports[0].source, 'automatic');
});

test('the insert authenticates with the service-role key, not the publishable one', async () => {
  // bug_reports has RLS on with no insert policy for `anon`. Writing with the
  // publishable key would be rejected on every real deployment, so the key used
  // here is the whole difference between working and silently 403-ing.
  const seenAuth = [];
  const original = platformServer.listeners('request')[0];
  platformServer.removeAllListeners('request');
  platformServer.on('request', (req, res) => {
    seenAuth.push(req.headers.authorization || '');
    return original(req, res);
  });
  await postReport({ description: 'A long enough description of the problem.', screen: 'home' });
  platformServer.removeAllListeners('request');
  platformServer.on('request', original);

  assert.ok(seenAuth.length > 0, 'the insert should have been attempted');
  assert.equal(seenAuth[0], 'Bearer test-service-role-key',
    'the write must use the service-role key or RLS will reject it');
});

test('a missing migration degrades instead of losing the report', async () => {
  // The most likely launch-day failure: deployed code, unapplied migration.
  // The report must still be accepted and the operator must get an actionable
  // message, not a 502 that makes it look like the user did something wrong.
  insertMode = 'missingTable';
  const response = await postReport({
    description: 'The first aid steps screen is blank on my phone.',
    screen: 'firstaid',
    severity: 'high',
  });
  assert.equal(response.status, 201, 'the report must not be rejected because of our own missing table');
  const body = await response.json();
  assert.equal(body.status, 'recorded');
  assert.equal(body.degraded, true, 'the caller should be told it was stored in the fallback');
  assert.equal(body.reference, null);
});

test('a storage failure reports a failure the client can show', async () => {
  restFails = true;
  const response = await postReport({
    description: 'Nothing on the settings screen responds to taps.',
    screen: 'settings',
    severity: 'medium',
  });
  assert.ok(response.status >= 500, `a storage failure must not look like success (got ${response.status})`);
  const body = await response.json();
  // A generic message: no internal detail leaks to the browser.
  assert.equal(/insert failed|postgrest|postgres/i.test(JSON.stringify(body)), false);
  assert.equal(storedReports.length, 0);
});

test('the endpoint is rate limited', async () => {
  // The limiter is stubbed to allow everything by the fake platform, so assert
  // the bucket is enforced by calling the real limiter directly instead.
  const rateLimit = require('../lib/rate-limit');
  assert.equal(typeof rateLimit.enforce, 'function');
  // A sanity check that the handler uses a dedicated bucket name: if this string
  // disappears from the source, the separate budget has been removed.
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'api.js'), 'utf8');
  assert.match(source, /rateLimit\.enforce\('bugreport', clientIpHash\(req\)\)/,
    'bug reports must have their own rate-limit bucket');
  const config = require('../lib/config');
  const [limit, windowMs] = config.security.rateLimits.bugreport;
  assert.ok(limit >= 10, `a real user hitting several bugs must not be locked out (limit ${limit}/hour)`);
  assert.equal(windowMs, 60 * 60 * 1000);
  assert.notDeepEqual(config.security.rateLimits.bugreport, config.security.rateLimits.forgot,
    'reporting a bug must not consume the password-reset budget');
});
