'use strict';

/**
 * Analytics and error monitoring.
 *
 * Section E. The thing worth testing about analytics is not that it counts —
 * it is that it cannot be turned into a personal-data collection system, and
 * that it cannot take the app down.
 *
 * Asserted here:
 *   • only declared event names are accepted;
 *   • a field that looks like an email address, a URL or free text is dropped;
 *   • identifiers are never stored, because there is nowhere to put one;
 *   • the ingest endpoint is rate limited, so it cannot flood the table;
 *   • a batch is capped;
 *   • the endpoint reveals nothing (always 204, no body);
 *   • a storage failure does not break the request that triggered it;
 *   • metrics require the service-role key;
 *   • the buffer is bounded, so a burst cannot exhaust memory.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const PLATFORM_PORT = 8205;
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'test-publishable-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
delete process.env.SQLITE_PATH;

const analytics = require('../lib/analytics');
const api = require('../lib/api');

let insertedBatches = [];
let insertFails = false;

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
    if (url.pathname === '/rest/v1/app_events' && req.method === 'POST') {
      if (insertFails) return json(res, 500, { message: 'insert failed' });
      insertedBatches.push(JSON.parse(raw));
      return json(res, 201, {});
    }
    return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
  });
  await new Promise((r) => platformServer.listen(PLATFORM_PORT, '127.0.0.1', r));

  appServer = http.createServer((req, res) => {
    api.handle(req, res, new URL(req.url, 'http://127.0.0.1'));
  });
  await new Promise((r) => appServer.listen(8206, '127.0.0.1', r));
  base = 'http://127.0.0.1:8206';
});

test.after(() => {
  platformServer && platformServer.close();
  appServer && appServer.close();
});

test.beforeEach(() => {
  analytics.reset();
  insertedBatches = [];
  insertFails = false;
});

// ---------------------------------------------------------------------------
// Acceptance rules
// ---------------------------------------------------------------------------

test('only declared event names are accepted', () => {
  assert.equal(analytics.record('app_open', {}), true);
  assert.equal(analytics.record('screen_view', { screen: 'home' }), true);

  // Anything not in the list is refused, including a plausible-looking name.
  assert.equal(analytics.record('user_signed_up_with_email', {}), false);
  assert.equal(analytics.record('__proto__', {}), false);
  assert.equal(analytics.record('constructor', {}), false);
  assert.equal(analytics.record('', {}), false);
  assert.equal(analytics.record(null, {}), false);

  const snap = analytics.snapshot();
  assert.equal(snap.accepted, 2);
  assert.equal(snap.rejected, 5);
});

test('an email address in a field is dropped', () => {
  analytics.record('api_error', { route: 'amina@example.com', status: '500' });
  const snap = analytics.snapshot();
  assert.equal(snap.accepted, 1);
  // The value must not have survived in any form.
  assert.equal(JSON.stringify(snap).includes('amina'), false);
});

test('a URL, free text or an oversized value is dropped', () => {
  analytics.record('api_error', { route: 'https://example.com/a/b', status: '500' });
  analytics.record('api_error', { route: 'please call me about the crash on Thika road', status: '500' });
  analytics.record('api_error', { route: 'x'.repeat(300), status: '500' });
  analytics.record('api_error', { route: '/api/auth/login', status: '500' });

  return analytics.flush({ force: true }).then(() => {
    const sent = insertedBatches.flat();
    assert.equal(sent.length, 4);
    const routes = sent.map((e) => e.fields.route);
    assert.deepEqual(routes.slice(0, 3), [null, null, null], 'unsafe values must be dropped, not truncated');
    assert.equal(routes[3], '/api/auth/login', 'a normal route survives');
  });
});

test('an undeclared field is discarded', () => {
  analytics.record('app_open', { outcome: 'ok', email: 'amina@example.com', userId: '123' });
  return analytics.flush({ force: true }).then(() => {
    const sent = insertedBatches.flat();
    assert.equal(sent.length, 1);
    assert.deepEqual(Object.keys(sent[0].fields), ['outcome'],
      'only the fields declared for the event may be stored');
    assert.equal(JSON.stringify(sent[0]).includes('amina'), false);
  });
});

test('an event row carries no identifier beyond the declared fields', () => {
  analytics.record('login_success', {});
  return analytics.flush({ force: true }).then(() => {
    const row = insertedBatches.flat()[0];
    // Exactly the columns the table has. There is no user_id, ip, session or
    // device column to accidentally populate.
    assert.deepEqual(Object.keys(row).sort(), ['fields', 'name', 'occurred_at']);
    assert.deepEqual(row.fields, {});
  });
});

// ---------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------

async function postEvents(events, headers = {}) {
  return fetch(`${base}/api/events`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: base,
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
      ...headers,
    },
    body: JSON.stringify({ events }),
  });
}

test('the ingest endpoint accepts a batch and reveals nothing', async () => {
  const ok = await postEvents([{ name: 'app_open', fields: {} }, { name: 'screen_view', fields: { screen: 'home' } }]);
  assert.equal(ok.status, 204);
  assert.equal((await ok.text()).length, 0, 'no body: nothing to probe');

  // An unknown event gets exactly the same answer as a known one.
  const unknown = await postEvents([{ name: 'totally_made_up', fields: {} }]);
  assert.equal(unknown.status, 204);
  assert.equal((await unknown.text()).length, 0);

  const snap = analytics.snapshot();
  assert.equal(snap.accepted, 2);
  assert.equal(snap.rejected, 1);
});

test('a huge batch is capped at 20 events', async () => {
  const many = Array.from({ length: 200 }, () => ({ name: 'app_open', fields: {} }));
  const response = await postEvents(many);
  assert.equal(response.status, 204);
  assert.equal(analytics.snapshot().accepted, 20, 'the batch cap must hold');
});

test('malformed input does not 500', async () => {
  const cases = [
    [{ name: 123 }],
    [{ fields: { screen: 'home' } }],
    [null],
    ['not an object'],
    [{ name: 'screen_view', fields: 'not an object' }],
  ];
  for (const events of cases) {
    const response = await postEvents(events);
    assert.equal(response.status, 204, `input ${JSON.stringify(events)} should be accepted-and-ignored`);
  }
});

test('a storage failure never reaches the caller', async () => {
  insertFails = true;
  analytics.record('app_open', {});
  const result = await analytics.flush({ force: true });
  assert.equal(result.error, true);
  // The event is kept for retry rather than lost.
  assert.equal(analytics.snapshot().buffered, 1);

  // And a request that triggers analytics still succeeds.
  const response = await postEvents([{ name: 'app_open', fields: {} }]);
  assert.equal(response.status, 204);
});

test('the buffer is bounded under a burst', () => {
  for (let i = 0; i < analytics.MAX_BUFFER + 500; i += 1) {
    analytics.record('screen_view', { screen: 'home' });
  }
  const snap = analytics.snapshot();
  assert.equal(snap.buffered, analytics.MAX_BUFFER, 'the buffer must not grow without bound');
  assert.ok(snap.dropped >= 500, 'the overflow must be counted, not silent');
});

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

test('metrics require the service-role key', async () => {
  const anonymous = await fetch(`${base}/api/metrics`);
  assert.equal(anonymous.status, 401);

  const wrong = await fetch(`${base}/api/metrics`, { headers: { Authorization: 'Bearer nope' } });
  assert.equal(wrong.status, 401);

  analytics.record('app_open', {});
  const authed = await fetch(`${base}/api/metrics`, {
    headers: { Authorization: 'Bearer test-service-role-key' },
  });
  assert.equal(authed.status, 200);
  const body = await authed.json();
  assert.equal(typeof body.analytics.accepted, 'number');
  assert.equal(body.analytics.accepted, 1);
  // Counts, not contents.
  assert.equal(JSON.stringify(body).includes('fields'), false);
});

test('metrics never leak event field contents', async () => {
  analytics.record('api_error', { route: '/api/auth/login', status: '502' });
  const body = await (
    await fetch(`${base}/api/metrics`, { headers: { Authorization: 'Bearer test-service-role-key' } })
  ).json();
  assert.equal(JSON.stringify(body).includes('/api/auth/login'), false);
  assert.equal(JSON.stringify(body).includes('502'), false);
});
