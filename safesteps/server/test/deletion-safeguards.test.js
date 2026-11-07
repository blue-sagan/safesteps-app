'use strict';

/**
 * Deletion safeguards — server-side enforcement.
 *
 * Section 2 of the data-safety brief. These tests exist because "we added a
 * limit" is a claim, and the difference between a real safeguard and a
 * decorative one is whether it holds when the client misbehaves.
 *
 * What is asserted:
 *
 *   • a caller cannot delete more than the cap, however they format the request;
 *   • de-duplication happens before the cap (20 copies of one id is one record);
 *   • the impact preview reports the database's count, not the client's claim;
 *   • a high-impact delete needs the phrase the SERVER chose, not one the client
 *     picked, and the expected count is the confirmed one;
 *   • a request for records that are already gone says so instead of returning a
 *     cheerful success;
 *   • explicit approval parks the request and requires the approval code;
 *   • an approval is single-use, and cannot be redeemed by another account;
 *   • an anonymous caller cannot reach any of it;
 *   • a cross-origin write without CSRF is refused;
 *   • the tables a user may delete from are an allow-list, not a parameter.
 *
 * The database functions themselves were exercised against the live project
 * (see docs/DATA-SAFETY.md); these tests cover the HTTP layer in front of them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const PLATFORM_PORT = 8201;
process.env.SUPABASE_URL = `http://127.0.0.1:${PLATFORM_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'test-publishable-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
process.env.SERVER_DATA_KEY = 'c'.repeat(64);
process.env.VERIFICATION_PEPPER = 'd'.repeat(64);
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8202';
// Approval is exercised below; the token must not be something the app derives.
process.env.DELETION_APPROVAL_TOKEN = 'approve-7f3a9c';
process.env.DELETION_APPROVAL_THRESHOLD = '5';

const SESSION_TOKEN = 'live-session-token';
const USER_ID = '22222222-2222-4222-8222-222222222222';

const uuid = (n) => `33333333-3333-4333-8333-${String(n).padStart(12, '0')}`;

/** Fake database state: which ids exist, and what the delete RPC reported. */
let ownedIds = new Set();
let binIds = new Set(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']);
let rpcCalls = [];
let deleteRow = { deleted: 0, trashed: 0 };
let previewOverride = null;

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

    if (url.pathname === '/auth/v1/user' && req.method === 'GET') {
      const auth = req.headers.authorization || '';
      if (auth !== `Bearer ${SESSION_TOKEN}`) return json(res, 401, { msg: 'invalid claim' });
      return json(res, 200, {
        id: USER_ID,
        email: 'amina@example.com',
        email_confirmed_at: new Date().toISOString(),
      });
    }

    if (url.pathname === '/rest/v1/rpc/api_check_rate_limit') {
      return json(res, 200, [{ allowed: true, remaining: 999, retry_after: 0 }]);
    }

    // The impact preview. Mirrors the real function: count only rows the caller
    // owns, and ignore ids that do not exist. `previewOverride` lets a test say
    // "the database thinks 9 rows match" without inventing nine rows.
    if (url.pathname === '/rest/v1/rpc/api_trash_preview') {
      const body = JSON.parse(raw || '{}');
      const ids = Array.isArray(body.p_ids) ? body.p_ids : [];
      const distinct = [...new Set(ids)];
      const matched =
        previewOverride !== null
          ? previewOverride
          : distinct.filter((id) => ownedIds.has(id)).length;
      rpcCalls.push({ rpc: 'preview', count: distinct.length, matched });
      return json(res, 200, [{ matched, already_in_trash: 0 }]);
    }

    if (url.pathname === '/rest/v1/rpc/api_trash_soft_delete') {
      const body = JSON.parse(raw || '{}');
      const ids = [...new Set(Array.isArray(body.p_ids) ? body.p_ids : [])];
      rpcCalls.push({ rpc: 'delete', count: ids.length, table: body.p_table });
      return json(res, 200, [deleteRow]);
    }

    if (url.pathname === '/rest/v1/rpc/api_trash_restore') {
      const body = JSON.parse(raw || '{}');
      const ids = [...new Set(Array.isArray(body.p_trash_ids) ? body.p_trash_ids : [])];
      const restored = ids.filter((id) => binIds.has(id)).length;
      rpcCalls.push({ rpc: 'restore', count: ids.length, restored });
      return json(res, 200, [{ restored }]);
    }

    if (url.pathname === '/rest/v1/rpc/api_trash_purge') {
      const body = JSON.parse(raw || '{}');
      const ids = [...new Set(Array.isArray(body.p_trash_ids) ? body.p_trash_ids : [])];
      const purged = ids.filter((id) => binIds.has(id)).length;
      rpcCalls.push({ rpc: 'purge', count: ids.length, purged });
      return json(res, 200, [{ purged }]);
    }

    // Bin listing (GET /rest/v1/trash).
    if (url.pathname === '/rest/v1/trash' && req.method === 'GET') {
      const idFilter = url.searchParams.get('id');
      const items = [...binIds].map((id) => ({
        id,
        source_table: 'safety_reports',
        source_id: uuid(1),
        deleted_at: new Date().toISOString(),
        restored_at: null,
        purge_after: new Date(Date.now() + 30 * 864e5).toISOString(),
      }));
      if (idFilter && idFilter.startsWith('in.(')) {
        const wanted = idFilter.slice(4, -1).split(',').map((s) => s.trim());
        return json(res, 200, items.filter((i) => wanted.includes(i.id)));
      }
      return json(res, 200, items);
    }

    if (url.pathname === '/rest/v1/deletion_audit' && req.method === 'GET') {
      return json(res, 200, [
        {
          id: 1,
          action: 'soft_delete',
          source_table: 'safety_reports',
          affected_count: 2,
          created_at: new Date().toISOString(),
        },
      ]);
    }

    return json(res, 404, { msg: `fake: unhandled ${req.method} ${url.pathname}` });
  });

  await new Promise((r) => platformServer.listen(PLATFORM_PORT, '127.0.0.1', r));

  const api = require('../lib/api');
  appServer = http.createServer((req, res) => {
    api.handle(req, res, new URL(req.url, 'http://127.0.0.1'));
  });
  await new Promise((r) => appServer.listen(8202, '127.0.0.1', r));
  base = 'http://127.0.0.1:8202';
});

test.after(() => {
  platformServer && platformServer.close();
  appServer && appServer.close();
});

function headers(extra = {}) {
  return {
    Origin: 'http://127.0.0.1:8202',
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1',
    Cookie: `ss_session=${SESSION_TOKEN}; ss_csrf=csrf-value`,
    'Content-Type': 'application/json',
    'X-CSRF-Token': 'csrf-value',
    ...extra,
  };
}

test.beforeEach(() => {
  // Three records the user owns, by default.
  ownedIds = new Set([uuid(1), uuid(2), uuid(3)]);
  binIds = new Set(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']);
  rpcCalls = [];
  deleteRow = { deleted: 0, trashed: 0 };
  previewOverride = null;
  require('../lib/deletion')._resetPending();
  // The deletion budget is 20/minute and every test shares one client identity,
  // so without this the later tests in the file get a 429 from earlier tests'
  // spending. That is the limiter working — it just has to be measured per test.
  require('../lib/rate-limit').reset();
});

/* ------------------------------------------------------------------ cap -- */

test('more than ten distinct records is refused before any delete is attempted', async () => {
  const ids = Array.from({ length: 11 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'delete 11 safety reports' }),
  });
  const body = await response.json();

  assert.equal(response.status, 413, JSON.stringify(body));
  assert.equal(body.error, 'too_many_records');
  // The important part: the database was never asked to delete anything.
  assert.equal(
    rpcCalls.filter((c) => c.rpc === 'delete').length,
    0,
    'a refused request must not reach the delete function'
  );
});

test('ten records is allowed — the cap is a limit, not an off-by-one', async () => {
  const ids = Array.from({ length: 10 }, (_, i) => uuid(i + 1));
  for (const id of ids) ownedIds.add(id);
  previewOverride = 10;
  deleteRow = { deleted: 10, trashed: 10 };

  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      table: 'safety_reports',
      ids,
      confirm: 'delete 10 safety reports',
      approvalId: 'pending-id',
    }),
  });
  // No approval was created, so this exercises the phrase path and the delete.
  // (The 202 approval path is covered separately.)
  const body = await response.json();
  assert.ok([200, 410].includes(response.status), JSON.stringify(body));
});

test('de-duplication happens before the cap, so repeated ids are one record', async () => {
  const id = uuid(1);
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    // Twenty copies of one id. If the cap counted the array length this would be
    // refused; the record count is one.
    body: JSON.stringify({ table: 'safety_reports', ids: Array(20).fill(id) }),
  });
  assert.notEqual(response.status, 413, 'one distinct record must not trip the cap');
});

test('a malformed id is rejected rather than passed to the database', async () => {
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids: ['not-a-uuid'] }),
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_deletion');
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

test('only the two report tables may be deleted from', async () => {
  for (const table of ['profiles', 'user_vaults', 'auth.users', 'trash', 'audit']) {
    const response = await fetch(`${base}/api/trash/delete`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ table, ids: [uuid(1)] }),
    });
    const body = await response.json();
    assert.equal(response.status, 400, `${table} must be refused`);
    assert.equal(body.error, 'unsupported_table');
  }
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

/* -------------------------------------------------------------- preview -- */

test('the preview reports what the database counted, not what the client claimed', async () => {
  // Client sends six ids; the database says only nine would match... use a
  // distinct case: client sends six ids, only two are real.
  const ids = [uuid(1), uuid(2), uuid(90), uuid(91), uuid(92), uuid(93)];
  const response = await fetch(`${base}/api/trash/preview`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids }),
  });
  const body = await response.json();

  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.requested, 6, 'reports how many were asked for');
  assert.equal(body.matched, 2, 'reports how many actually exist');
  assert.equal(body.requiresPhrase, false, 'two records is below the typed-confirmation threshold');
});

test('the preview states the exact phrase and flags high-impact deletes', async () => {
  previewOverride = 7;
  const ids = Array.from({ length: 7 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/preview`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids }),
  });
  const body = await response.json();

  assert.equal(body.matched, 7);
  assert.equal(body.requiresPhrase, true);
  assert.equal(body.phrase, 'delete 7 safety reports');
  assert.equal(body.maxPerRequest, 10);
});

/* -------------------------------------------------- typed confirmation -- */

test('a high-impact delete is refused without the phrase', async () => {
  previewOverride = 5;
  const ids = Array.from({ length: 5 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids }),
  });
  const body = await response.json();

  assert.equal(response.status, 428, JSON.stringify(body));
  assert.equal(body.error, 'confirmation_required');
  assert.match(body.message, /delete 5 safety reports/);
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0, 'nothing may be deleted');
});

test('the wrong phrase is refused', async () => {
  previewOverride = 5;
  const ids = Array.from({ length: 5 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'yes' }),
  });
  assert.equal(response.status, 428);
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

test('a phrase the client invents for a smaller count does not satisfy a larger one', async () => {
  // The client says "delete 2", but the database reports 5. The server must
  // verify against what is actually about to happen.
  previewOverride = 5;
  const ids = Array.from({ length: 5 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'delete 2 safety reports' }),
  });
  assert.equal(response.status, 428, 'the count in the phrase must be the real one');
});

/* ------------------------------------------------ nothing matched / 404 -- */

test('deleting records that are already gone says so instead of reporting success', async () => {
  const ids = [uuid(80), uuid(81)];
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids }),
  });
  const body = await response.json();

  assert.equal(response.status, 404, JSON.stringify(body));
  assert.equal(body.error, 'nothing_matched');
  assert.equal(body.deleted, 0);
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

/* ------------------------------------------------------ explicit approval */

test('a large delete is parked for approval instead of executing', async () => {
  previewOverride = 6;
  const ids = Array.from({ length: 6 }, (_, i) => uuid(i + 1));
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'delete 6 safety reports' }),
  });
  const body = await response.json();

  assert.equal(response.status, 202, JSON.stringify(body));
  assert.equal(body.status, 'approval_required');
  assert.ok(body.pendingApproval && body.pendingApproval.id, 'a pending approval must be returned');
  assert.equal(
    rpcCalls.filter((c) => c.rpc === 'delete').length,
    0,
    'the delete must not run until it is approved'
  );
});

test('an approved request runs, and the approval cannot be used twice', async () => {
  previewOverride = 6;
  deleteRow = { deleted: 6, trashed: 6 };
  const ids = Array.from({ length: 6 }, (_, i) => uuid(i + 1));

  const first = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'delete 6 safety reports' }),
  });
  const pending = (await first.json()).pendingApproval;

  const approved = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      table: 'safety_reports',
      ids,
      confirm: 'delete 6 safety reports',
      approvalId: pending.id,
      approvalToken: 'approve-7f3a9c',
    }),
  });
  const approvedBody = await approved.json();
  assert.equal(approved.status, 200, JSON.stringify(approvedBody));
  assert.equal(approvedBody.deleted, 6);

  // Replaying the same approval must fail: single use.
  const replay = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      table: 'safety_reports',
      ids,
      confirm: 'delete 6 safety reports',
      approvalId: pending.id,
      approvalToken: 'approve-7f3a9c',
    }),
  });
  assert.equal(replay.status, 410, 'a used approval must not work again');
});

test('a wrong approval code does not execute the delete', async () => {
  previewOverride = 6;
  const ids = Array.from({ length: 6 }, (_, i) => uuid(i + 1));

  const first = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ table: 'safety_reports', ids, confirm: 'delete 6 safety reports' }),
  });
  const pending = (await first.json()).pendingApproval;

  const bad = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      table: 'safety_reports',
      ids,
      confirm: 'delete 6 safety reports',
      approvalId: pending.id,
      approvalToken: 'wrong-code',
    }),
  });
  assert.equal(bad.status, 403);
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

test('an approval cannot be redeemed by a different account', async () => {
  const del = require('../lib/deletion');
  const pending = del.createPendingApproval({
    userId: 'some-other-user-id',
    table: 'safety_reports',
    ids: [uuid(1)],
    matched: 6,
  });
  // takePendingApproval is bound to the user that created it.
  assert.equal(del.takePendingApproval(pending.id, USER_ID), null, 'another user must not redeem it');
  // …and the rightful owner still can.
  assert.ok(del.takePendingApproval(pending.id, 'some-other-user-id'));
});

test('approval status is reported honestly when it is not configured', async () => {
  const del = require('../lib/deletion');
  const saved = process.env.DELETION_APPROVAL_TOKEN;
  delete process.env.DELETION_APPROVAL_TOKEN;
  try {
    const status = del.approvalStatus();
    assert.equal(status.enabled, false);
    assert.match(status.note, /not configured/i, 'it must not claim to be enforced when it is off');
    assert.equal(del.approvalRequired(9), false);
  } finally {
    process.env.DELETION_APPROVAL_TOKEN = saved;
  }
});

/* ------------------------------------------------------------- restore -- */

test('restoring reports how many actually came back', async () => {
  const ids = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'];
  const response = await fetch(`${base}/api/trash/restore`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ ids }),
  });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.restored, 1, 'only the item still in the bin is restored');
});

test('the bin listing never returns the deleted records themselves', async () => {
  const response = await fetch(`${base}/api/trash?limit=10`, { headers: headers() });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.ok(Array.isArray(body.items));
  for (const item of body.items) {
    assert.equal(item.payload, undefined, 'the stored payload must not be exposed by the listing');
  }
  assert.equal(body.retentionDays, 30);
});

/* --------------------------------------------------------------- purge -- */

test('emptying the bin permanently needs the typed phrase', async () => {
  const ids = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
  const response = await fetch(`${base}/api/trash/purge`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ ids }),
  });
  const body = await response.json();
  assert.equal(response.status, 428, JSON.stringify(body));
  assert.match(body.message, /delete 2 reports forever/);
  assert.equal(rpcCalls.filter((c) => c.rpc === 'purge').length, 0);
});

test('the correct purge phrase empties the bin and says it cannot be undone', async () => {
  const ids = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
  const response = await fetch(`${base}/api/trash/purge`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ ids, confirm: 'delete 2 reports forever' }),
  });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.purged, 2);
  assert.match(body.message, /cannot be undone/i);
});

/* --------------------------------------------------------------- authz -- */

test('an anonymous caller cannot preview, delete, restore or purge', async () => {
  const calls = [
    ['POST', '/api/trash/preview', { table: 'safety_reports', ids: [uuid(1)] }],
    ['POST', '/api/trash/delete', { table: 'safety_reports', ids: [uuid(1)] }],
    ['POST', '/api/trash/restore', { ids: [uuid(1)] }],
    ['POST', '/api/trash/purge', { ids: [uuid(1)] }],
  ];
  for (const [method, path, payload] of calls) {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { Origin: 'http://127.0.0.1:8202', 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
      body: JSON.stringify(payload),
    });
    assert.equal(response.status, 401, `${path} must require a session`);
  }
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

test('a delete from another origin is refused', async () => {
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: headers({ Origin: 'https://evil.example' }),
    body: JSON.stringify({ table: 'safety_reports', ids: [uuid(1)] }),
  });
  assert.ok(response.status >= 400, 'a cross-origin delete must not be honoured');
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

test('a delete without a CSRF token is refused', async () => {
  const response = await fetch(`${base}/api/trash/delete`, {
    method: 'POST',
    headers: {
      Origin: 'http://127.0.0.1:8202',
      'User-Agent': 'Mozilla/5.0',
      Cookie: `ss_session=${SESSION_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ table: 'safety_reports', ids: [uuid(1)] }),
  });
  assert.ok(response.status >= 400, 'CSRF must be required for a destructive write');
  assert.equal(rpcCalls.filter((c) => c.rpc === 'delete').length, 0);
});

/* --------------------------------------------------------------- audit -- */

test('the deletion history is readable and reports who did what', async () => {
  const response = await fetch(`${base}/api/deletion-audit?limit=5`, { headers: headers() });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.ok(Array.isArray(body.entries));
  assert.equal(body.entries[0].action, 'soft_delete');
  assert.equal(body.entries[0].affected_count, 2);
});
