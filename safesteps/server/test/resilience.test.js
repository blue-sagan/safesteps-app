'use strict';

/**
 * Resilience when the platform is not healthy.
 *
 * Section C: "handle free-plan service limits/quotas".
 *
 * The failure this guards against is not exotic. A Supabase project on the free
 * plan pauses when it exceeds its limits, and the moment it does, every auth
 * request fails upstream. Before these tests, that surfaced to the user as
 * `500 {"error":"auth_unavailable","message":"Something went wrong."}` — the
 * careful message written in auth.js was being flattened by sendError() because
 * AuthError did not set `expose`. A user mid-sign-up got a dead end.
 *
 * What is asserted here:
 *
 *   • an unreachable platform returns 503 with a message that says what happened
 *   • a paused project is distinguished from a plain outage
 *   • a full disk (53100) is treated as a pause, even though Postgres reports it
 *     in a different JSON field from the human message
 *   • no upstream text, stack trace or internal URL reaches the client
 *   • the failure is still a 5xx, so monitoring sees it as an error rather than
 *     a client mistake
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

// The auth layer reads config at require time, so the environment is set before
// anything is required.
const STUB_PORT = 8185;
process.env.SUPABASE_URL = `http://127.0.0.1:${STUB_PORT}`;
process.env.SUPABASE_PUBLISHABLE_KEY = 'test-publishable-key';
process.env.SERVER_DATA_KEY = 'a'.repeat(64);
process.env.VERIFICATION_PEPPER = 'b'.repeat(64);

const auth = require('../lib/auth');
const { sendError } = require('../lib/http');

/** Run an upstream failure through the real error responder. */
function respondWith(error) {
  const captured = { status: 0, body: null, headers: {} };
  const res = {
    writeHead(status, headers) {
      captured.status = status;
      captured.headers = headers || {};
    },
    end(body) {
      captured.body = body;
    },
  };
  sendError(res, error);
  captured.json = captured.body ? JSON.parse(captured.body) : null;
  return captured;
}

let stubMode = 'paused';
let stubServer;

function startStub() {
  return new Promise((resolve) => {
    stubServer = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const send = (status, payload) => {
          const body = JSON.stringify(payload);
          res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
          res.end(body);
        };

        if (stubMode === 'paused') {
          // What the Supabase gateway returns for a paused project.
          return send(503, { message: 'Project is paused. Restore it from the dashboard.' });
        }
        if (stubMode === 'disk') {
          // Postgres reports the real cause in error_description, and the
          // human-readable `message` says something far less specific.
          return send(500, {
            message: 'canceling statement due to lack of resources',
            error_description: '53100: No space left on device',
          });
        }
        if (stubMode === 'gateway') {
          return send(503, { message: 'upstream connect error or disconnect/reset before headers' });
        }
        if (stubMode === 'leaky') {
          // An upstream that puts internals in its message must not leak them.
          return send(500, {
            message: 'pg connection failed: postgres://postgres:hunter2@db.internal:5432/postgres',
          });
        }
        return send(400, { error_code: 'invalid_credentials', msg: 'Invalid login credentials' });
      });
    });
    stubServer.listen(STUB_PORT, '127.0.0.1', resolve);
  });
}

test.before(startStub);
test.after(() => stubServer && stubServer.close());

test('a paused project returns 503 and says so, not a bare 500', async () => {
  stubMode = 'paused';
  await assert.rejects(
    () => auth.signIn({ email: 'amina@example.com', password: 'abc123' }),
    (error) => {
      const out = respondWith(error);
      assert.equal(out.status, 503, 'must be 503, not the flattened 500');
      assert.equal(out.json.error, 'service_paused');
      assert.match(out.json.message, /temporarily read-only/i);
      // The reassurance matters: it is the difference between "try later" and
      // "your saved work is gone".
      assert.match(out.json.message, /device still works/i);
      return true;
    }
  );
});

test('a full disk is recognised as a pause even when the message field is vague', async () => {
  stubMode = 'disk';
  await assert.rejects(
    () => auth.signIn({ email: 'amina@example.com', password: 'abc123' }),
    (error) => {
      const out = respondWith(error);
      assert.equal(out.status, 503);
      assert.equal(out.json.error, 'service_paused', '53100 in error_description must be classified, not lost');
      return true;
    }
  );
});

test('a plain upstream outage returns 503 auth_unavailable', async () => {
  stubMode = 'gateway';
  await assert.rejects(
    () => auth.signIn({ email: 'amina@example.com', password: 'abc123' }),
    (error) => {
      const out = respondWith(error);
      assert.equal(out.status, 503);
      assert.equal(out.json.error, 'auth_unavailable');
      assert.match(out.json.message, /temporarily unavailable/i);
      return true;
    }
  );
});

test('an unreachable host is a 503, not a crash or a 500', async () => {
  // Point at a port where nothing is listening.
  const authModulePath = require.resolve('../lib/auth');
  const originalUrl = process.env.SUPABASE_URL;
  process.env.SUPABASE_URL = 'http://127.0.0.1:9';

  delete require.cache[authModulePath];
  // config caches its own read; refreshing it keeps the two in step.
  delete require.cache[require.resolve('../lib/config')];
  const freshAuth = require('../lib/auth');

  try {
    await assert.rejects(
      () => freshAuth.signIn({ email: 'amina@example.com', password: 'abc123' }),
      (error) => {
        const out = respondWith(error);
        assert.equal(out.status, 503);
        assert.equal(out.json.error, 'auth_unavailable');
        assert.ok(out.json.message.length > 10, 'the user must be told something');
        return true;
      }
    );
  } finally {
    process.env.SUPABASE_URL = originalUrl;
    delete require.cache[authModulePath];
    delete require.cache[require.resolve('../lib/config')];
    require('../lib/auth');
  }
});

test('upstream internals never reach the client', async () => {
  stubMode = 'leaky';
  await assert.rejects(
    () => auth.signIn({ email: 'amina@example.com', password: 'abc123' }),
    (error) => {
      const out = respondWith(error);
      const serialized = JSON.stringify(out.json);
      assert.doesNotMatch(serialized, /postgres:\/\//, 'connection string leaked');
      assert.doesNotMatch(serialized, /hunter2/, 'password leaked');
      assert.doesNotMatch(serialized, /db\.internal/, 'internal hostname leaked');
      assert.doesNotMatch(serialized, /\bat .*\.js:\d+/, 'stack trace leaked');
      return true;
    }
  );
});

test('a genuine bad password is still a 4xx, not disguised as an outage', async () => {
  stubMode = 'healthy';
  await assert.rejects(
    () => auth.signIn({ email: 'amina@example.com', password: 'wrong1' }),
    (error) => {
      const out = respondWith(error);
      assert.ok(out.status >= 400 && out.status < 500, `expected a 4xx, got ${out.status}`);
      assert.notEqual(out.json.error, 'service_paused');
      assert.notEqual(out.json.error, 'auth_unavailable');
      return true;
    }
  );
});
