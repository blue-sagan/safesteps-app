'use strict';

/**
 * Account deletion — the right to erasure, end to end.
 *
 * Section D (legal) and B (data protection).
 *
 * THE BUG THESE TESTS EXIST FOR
 * The server exposed POST /api/account/delete and the client had no caller, so
 * a user could not delete their account at all. Worse, once the UI was added it
 * turned out the endpoint only erased *rows*: `auth.users` survived, so the same
 * email and password still signed in afterwards. The privacy policy promises the
 * account is erased. It was not.
 *
 * What is asserted here:
 *
 *   • a signed-in user can delete their account;
 *   • the sign-in record is actually removed, so the credential stops working;
 *   • the user's rows are erased as well as the login;
 *   • the session cookie is cleared;
 *   • an anonymous caller cannot delete anything;
 *   • if the sign-in record cannot be removed, the response says so — it must
 *     never look like a clean success;
 *   • deletion failure messages survive sendError instead of becoming
 *     "Something went wrong", because after a deletion attempt the user must be
 *     able to tell what happened.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const PLATFORM_PORT = 8195;
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'test-publishable-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
process.env.SERVER_DATA_KEY = 'c'.repeat(64);
process.env.VERIFICATION_PEPPER = 'd'.repeat(64);
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8196';

const SESSION_TOKEN = 'live-session-token';
let deletedUsers = [];
let rpcCalls = [];
let deleteStatus = 200;

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

    // Who is this token?
    if (url.pathname === '/auth/v1/user' && req.method === 'GET') {
      const auth = req.headers.authorization || '';
      if (auth !== `Bearer ${SESSION_TOKEN}`) return json(res, 401, { msg: 'invalid claim' });
      return json(res, 200, {
        id: '11111111-1111-4111-8111-111111111111',
        email: 'amina@example.com',
        email_confirmed_at: new Date().toISOString(),
      });
    }

    // Admin delete of the sign-in record.
    if (url.pathname.startsWith('/auth/v1/admin/users/') && req.method === 'DELETE') {
      if (req.headers.apikey !== 'test-service-role-key') return json(res, 401, { msg: 'no key' });
      if (deleteStatus !== 200) return json(res, deleteStatus, { msg: 'boom' });
      deletedUsers.push(url.pathname.split('/').pop());
      return json(res, 200, {});
    }

    // The durable rate limiter. This must answer with the row shape the app
    // expects — an empty object reads as `allowed: false`, and every request in
    // the suite then fails with 429 instead of reaching the handler. That was
    // the first version of this stub, and it wasted a debugging cycle.
    if (url.pathname === '/rest/v1/rpc/api_check_rate_limit') {
      return json(res, 200, [{ allowed: true, remaining: 999, retry_after: 0 }]);
    }

    // Row erasure (used only when no service-role key is configured).
    if (url.pathname.startsWith('/rest/v1/rpc/')) {
      rpcCalls.push(url.pathname);
      return json(res, 200, {});
    }

    // Logout
    if (url.pathname === '/auth/v1/logout') return json(res, 204, {});

    return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
  });

  await new Promise((r) => platformServer.listen(PLATFORM_PORT, '127.0.0.1', r));

  const api = require('../lib/api');
  appServer = http.createServer((req, res) => {
    api.handle(req, res, new URL(req.url, 'http://127.0.0.1'));
  });
  await new Promise((r) => appServer.listen(8196, '127.0.0.1', r));
  base = 'http://127.0.0.1:8196';
});

test.after(() => {
  platformServer && platformServer.close();
  appServer && appServer.close();
});

function browserHeaders(extra = {}) {
  return {
    Origin: 'http://127.0.0.1:8196',
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1',
    Cookie: `ss_session=${SESSION_TOKEN}; ss_csrf=csrf-value`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

test.beforeEach(() => {
  deletedUsers = [];
  rpcCalls = [];
  deleteStatus = 200;
});

test('an anonymous caller cannot delete anything', async () => {
  const response = await fetch(`${base}/api/account/delete`, {
    method: 'POST',
    headers: { Origin: 'http://127.0.0.1:8196', 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
    body: '{}',
  });
  assert.equal(response.status, 401);
  assert.equal(deletedUsers.length, 0, 'nothing may be deleted without a session');
});

test('deleting an account removes the sign-in record, not just the rows', async () => {
  const response = await fetch(`${base}/api/account/delete`, {
    method: 'POST',
    headers: browserHeaders({ 'X-CSRF-Token': 'csrf-value' }),
    body: '{}',
  });
  const body = await response.json();

  // This is the assertion the original code would have failed: the auth record
  // must be gone, otherwise the old password still works.
  assert.deepEqual(deletedUsers, ['11111111-1111-4111-8111-111111111111'],
    'the auth.users record must be deleted, or the credential stays valid');

  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.ok, true);
  assert.match(body.message, /deleted/i);

  // With the auth record removed, the row-erasure RPC is unnecessary and is not
  // attempted (it could not run under a token for a deleted user anyway).
  assert.deepEqual(rpcCalls, [], 'should not call the row RPC when the auth record was deleted');
});

test('the session cookie is cleared so the deletion takes effect immediately', async () => {
  const response = await fetch(`${base}/api/account/delete`, {
    method: 'POST',
    headers: browserHeaders({ 'X-CSRF-Token': 'csrf-value' }),
    body: '{}',
  });
  const cookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
  const joined = cookies.join(';');
  assert.match(joined, /ss_session=/, 'the session cookie must be cleared');
  assert.match(joined, /Expires=Thu, 01 Jan 1970|Max-Age=0/i, 'the session cookie must be expired, not merely overwritten');
});

test('a failure to remove the sign-in record is reported, never disguised as success', async () => {
  deleteStatus = 500;
  const response = await fetch(`${base}/api/account/delete`, {
    method: 'POST',
    headers: browserHeaders({ 'X-CSRF-Token': 'csrf-value' }),
    body: '{}',
  });
  const body = await response.json();

  assert.notEqual(response.status, 200, 'a failed deletion must not return success');
  assert.ok(response.status >= 500, `expected 5xx, got ${response.status}`);
  // And the message must survive sendError rather than becoming
  // "Something went wrong. Please try again."
  assert.doesNotMatch(body.message, /Something went wrong/i);
  assert.match(body.message, /sign-in record|contact support/i);
  assert.equal(body.error, 'delete_failed');
});

test('deletion on a server without a service-role key erases rows and admits the limit', async () => {
  // Re-require the API with no service-role key configured, so the fallback path
  // is exercised: rows are erased, but the sign-in record cannot be.
  const path = require.resolve('../lib/api');
  const configPath = require.resolve('../lib/config');
  const originalKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;

  delete require.cache[path];
  delete require.cache[configPath];
  const fallbackApi = require('../lib/api');
  const fallbackServer = http.createServer((req, res) => {
    fallbackApi.handle(req, res, new URL(req.url, 'http://127.0.0.1'));
  });
  await new Promise((r) => fallbackServer.listen(8197, '127.0.0.1', r));

  try {
    const response = await fetch('http://127.0.0.1:8197/api/account/delete', {
      method: 'POST',
      headers: { ...browserHeaders({ 'X-CSRF-Token': 'csrf-value' }), Origin: 'http://127.0.0.1:8196' },
      body: '{}',
    });
    const body = await response.json();

    // Rows were erased...
    assert.ok(rpcCalls.some((c) => c.includes('api_delete_my_account')), 'the row erasure must still run');
    // ...but the account is not fully gone, and the user is told, rather than
    // being shown a success for a half-done job.
    assert.notEqual(response.status, 200);
    assert.equal(body.error, 'delete_partial');
    assert.match(body.message, /sign-in record could not be removed/i);
  } finally {
    process.env.SUPABASE_SERVICE_ROLE_KEY = originalKey;
    fallbackServer.close();
    delete require.cache[path];
    delete require.cache[configPath];
    require('../lib/api');
  }
});

test('a cross-origin delete is refused', async () => {
  const response = await fetch(`${base}/api/account/delete`, {
    method: 'POST',
    headers: { ...browserHeaders({ 'X-CSRF-Token': 'csrf-value' }), Origin: 'https://evil.example' },
    body: '{}',
  });
  assert.ok([403, 400].includes(response.status), `expected refusal, got ${response.status}`);
  assert.equal(deletedUsers.length, 0, 'a cross-origin request must delete nothing');
});
