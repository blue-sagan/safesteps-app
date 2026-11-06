'use strict';

/**
 * Security regression tests.
 *
 * These are deliberately behavioural: they boot the real server and assert the
 * properties the security work is supposed to guarantee. Run with `npm test`
 * from server/ (uses node:test — no test framework dependency).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Deterministic, throwaway configuration for the test run.
process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test_key';
process.env.SUPABASE_SERVICE_ROLE_KEY = '';
process.env.VERIFICATION_PEPPER = 'test-pepper-do-not-use-in-production';
process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:8123';
process.env.SQLITE_PATH = ':memory:';
// Force the *unconfigured* shape regardless of any local .env: this suite
// asserts the degraded behaviour (and must be reproducible on any machine).
process.env.SERVER_DATA_KEY = '';
process.env.SMTP_HOST = '';
process.env.SMTP_USER = '';
process.env.SMTP_PASS = '';

const { createServer } = require('../server');
const config = require('../lib/config');
const uploads = require('../lib/uploads');
const bot = require('../lib/bot-protection');
const validation = require('../lib/validate');
const db = require('../lib/db');
const staticFiles = require('../lib/static');
const { securityHeaders } = require('../lib/security-headers');

let server;
let base;

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
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server && server.close());

function browserHeaders(extra = {}) {
  return {
    'user-agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Safari/537.36',
    'accept-language': 'en-KE,en;q=0.9',
    referer: config.publicOrigin,
    origin: config.publicOrigin,
    ...extra,
  };
}

test.after(() => server && server.close());

/* ------------------------------------------------------------------ */
/* A. Secrets never ship to the browser                                */
/* ------------------------------------------------------------------ */

test('browser code contains no hard-coded credentials', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'index.html'), 'utf8');
  const client = fs.readFileSync(path.join(__dirname, '..', '..', 'assets', 'security.js'), 'utf8');

  const forbidden = [
    /service_role/i,
    /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9/, // JWT literal
    /EMAILJS_(PUBLIC|SERVICE|TEMPLATE)/,
    /emailjs\.init|emailjs\.send/,
    /passwordHash:\s*(btoa|atob)/,
    /apiKey:\s*["'][A-Za-z0-9]{8,}/,
    /localStorage\.getItem\(["']safesteps_at_api_key["']\)/,
    /localStorage\.getItem\(["']safesteps_email_webhook["']\)/,
  ];
  for (const pattern of forbidden) {
    assert.equal(pattern.test(html), false, `index.html must not contain ${pattern}`);
    assert.equal(pattern.test(client), false, `security.js must not contain ${pattern}`);
  }

  // Legacy credentials that older builds stored locally must be actively
  // purged on boot (the key names appear only in the purge list).
  assert.match(html, /localStorage\.removeItem\("safesteps_at_api_key"\)/);
  assert.match(html, /localStorage\.removeItem\("safesteps_emailjs_config"\)/);
  assert.match(html, /localStorage\.removeItem\("safesteps_pending_code"\)/);

  // The one key the browser may receive is the publishable key, and it is not
  // written into any file — it comes from /api/config at runtime.
  assert.equal(/sb_secret_|service_apikey/i.test(html), false);
});

test('/api/config exposes only public values', async () => {
  const response = await fetch(`${base}/api/config`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(body).sort(), [
    'capabilities',
    'hsts',
    'passwordMaxLength',
    'passwordMinLength',
    'supabasePublishableKey',
    'supabaseUrl',
  ]);
  // Capability flags are booleans only — no credential material.
  for (const value of Object.values(body.capabilities)) assert.equal(typeof value, 'boolean');
  // A service-role key must never be reachable here.
  assert.equal(/eyJhbGciOi/.test(JSON.stringify(body)), false);
  assert.equal(body.supabaseServiceRoleKey, undefined);
});

/* ------------------------------------------------------------------ */
/* D. Headers, HTTPS and static serving                                */
/* ------------------------------------------------------------------ */

test('HTML responses carry a strict security header set', async () => {
  const response = await fetch(`${base}/`);
  assert.equal(response.status, 200);

  const csp = response.headers.get('content-security-policy');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /frame-ancestors 'self'/);
  assert.match(csp, /script-src [^;]*'nonce-/);
  assert.match(csp, /script-src [^;]*'strict-dynamic'/);
  // No wildcard script sources.
  assert.equal(/script-src[^;]*\*/.test(csp), false);

  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(response.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.match(response.headers.get('permissions-policy'), /payment=\(\)/);
  assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('CSP actually covers every network target the app uses', async () => {
  // A CSP that blocks the app's own requests is a security regression in
  // disguise (it gets disabled to "make things work"). So: enumerate every
  // absolute URL in the client code and assert the relevant directive covers
  // the host.
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'index.html'), 'utf8');
  const client = fs.readFileSync(path.join(__dirname, '..', '..', 'assets', 'security.js'), 'utf8');
  const source = html + client;
  const csp = (await (await fetch(`${base}/`)).headers.get('content-security-policy')) || '';

  const directive = (name) => {
    const match = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith(`${name} `));
    return match ? match.split(/\s+/).slice(1) : [];
  };
  // CSP sources may be "https://host", "host", "*.host" or "*". Compare hosts.
  const allowed = (host, sources) =>
    sources.some((raw) => {
      const source = raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
      if (source === '*' || source === host) return true;
      if (source.startsWith('*.')) {
        const suffix = source.slice(1); // ".example.com"
        return host === source.slice(2) || host.endsWith(suffix);
      }
      return false;
    });

  const hosts = new Set();
  for (const match of source.matchAll(/https:\/\/([a-z0-9.-]+)/gi)) hosts.add(match[1].toLowerCase());
  // Hosts that are only ever *displayed* (citations, docs, mailto links) are
  // navigation targets, not subresources.
  const displayOnly = new Set([
    'www.ntsa.go.ke', 'ntsa.go.ke', 'www.emailjs.com', 'www.edpb.europa.eu', 'fpf.org',
    'cppa.ca.gov', 'digital-strategy.ec.europa.eu', 'www.google.com', 'www.w3.org',
    'openstreetmap.org', 'www.openstreetmap.org', 'creativecommons.org', 'wa.me',
    'api.ntsa.go.ke', 'api.africastalking.com', 'safesteps.example.org',
  ]);

  const unreachable = [];
  for (const host of hosts) {
    if (displayOnly.has(host)) continue;
    if (/^(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|fonts\.googleapis\.com|fonts\.gstatic\.com)$/.test(host)) continue;
    const fetchable = allowed(host, directive('connect-src'));
    const imagable = allowed(host, directive('img-src'));
    if (!fetchable && !imagable) unreachable.push(host);
  }
  assert.deepEqual(unreachable, [], `CSP would block: ${unreachable.join(', ')}`);

  // Explicit budget checks for the directive that matters most.
  const scriptSrc = directive('script-src');
  assert.ok(scriptSrc.includes("'nonce-") === false, 'nonce is per-response');
  assert.match(csp, /script-src-[^;]*'unsafe-inline'/);
  // script-src itself must never be relaxed to unsafe-inline.
  assert.equal(/script-src (?!.*nonce)[^;]*unsafe-inline/.test(csp), false);

  // Form submissions and framing are locked down.
  assert.deepEqual(directive('form-action'), ["'self'"]);
  assert.deepEqual(directive('frame-ancestors'), ["'self'"]);
  assert.deepEqual(directive('object-src'), ["'none'"]);
});

test('HSTS is only emitted in production', async () => {
  const response = await fetch(`${base}/`);
  if (config.isProduction) {
    assert.match(response.headers.get('strict-transport-security'), /max-age=/);
  } else {
    assert.equal(response.headers.get('strict-transport-security'), null);
  }
});

test('inline scripts receive a per-response nonce', async () => {
  const first = await (await fetch(`${base}/`)).text();
  const second = await (await fetch(`${base}/`)).text();
  const nonceA = first.match(/<script nonce="([^"]+)"/)[1];
  const nonceB = second.match(/<script nonce="([^"]+)"/)[1];
  assert.notEqual(nonceA, nonceB, 'nonces must not be reusable across responses');
  // EVERY script tag needs the nonce: with `strict-dynamic` the host
  // allow-list is ignored, so an un-nonced <script src> would be blocked.
  const scriptTags = (first.match(/<script\b/gi) || []).length;
  const nonceCount = (first.match(/<script nonce=/gi) || []).length;
  assert.equal(scriptTags, nonceCount, 'every script tag must carry the nonce');
  const inlineCount = (first.match(/<script(?![^>]*\bsrc=)/gi) || []).length;
  assert.ok(inlineCount >= 2, 'inline bootstrap scripts expected');
  const cdnScripts = (first.match(/<script nonce="[^"]+"[^>]*\bsrc=/gi) || []).length;
  assert.ok(cdnScripts >= 5, `CDN libraries must be nonced too (found ${cdnScripts})`);
});

test('path traversal and server source are not reachable', async () => {
  for (const attempt of [
    '/../server/lib/config.js',
    '/%2e%2e/server/lib/config.js',
    '/server/lib/config.js',
    '/.git/config',
    '/.env',
    '/%00/index.html',
  ]) {
    const response = await fetch(`${base}${attempt}`);
    assert.ok([400, 404].includes(response.status), `${attempt} → ${response.status}`);
  }
});

test('a missing file returns the branded 404 page with a 404 status', async () => {
  // Before this, a dead link showed plain text "Not found" — no branding, no way
  // back into the app, no emergency numbers. The status must stay 404 so search
  // engines and uptime checks do not treat dead URLs as real pages.
  for (const attempt of ['/definitely-not-here.png', '/js/nope.js', '/assets/missing.png']) {
    const response = await fetch(`${base}${attempt}`);
    assert.equal(response.status, 404, `${attempt} must be 404, got ${response.status}`);
    assert.match(response.headers.get('content-type') || '', /text\/html/,
      `${attempt} should serve the HTML 404 page`);
    const body = await response.text();
    assert.match(body, /We couldn't find that page/, `${attempt} should show the 404 copy`);
    // The page must offer a way out, including a dialable emergency number.
    assert.match(body, /href="\.\/index\.html"/, '404 page needs a link back to the app');
    assert.match(body, /href="tel:112"/, '404 page should offer the emergency number');
  }
});

test('the 404 page keeps a strict status even for a deep missing path', async () => {
  const response = await fetch(`${base}/a/b/c/d/deep-missing.png`);
  assert.equal(response.status, 404);
  const body = await response.text();
  assert.match(body, /<title>Page not found \(404\)/, 'the tab title should say 404');
});

test('extension-less routes still fall back to the app shell, not the 404 page', async () => {
  // The app is a single-page document with hash routes. A deep link like
  // /some-route must still open the app, which is what makes an installed PWA
  // and a shared link work.
  const response = await fetch(`${base}/some-client-route`);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /SafeSteps - Road Safety Companion/);
});

test('the app ships a real favicon set and an HTML 404 page', () => {
  for (const file of ['favicon.ico', '404.html', 'icons/apple-touch-icon-180.png']) {
    assert.ok(fs.existsSync(path.join(staticFiles.ROOT, file)), `${file} is missing`);
  }
  const index = fs.readFileSync(path.join(staticFiles.ROOT, 'index.html'), 'utf8');
  assert.match(index, /<link rel="icon" href="favicon\.ico"/, 'index.html must reference favicon.ico');
  // A page without an icon shows a blank tab; legal.html had none at all.
  const legal = fs.readFileSync(path.join(staticFiles.ROOT, 'legal.html'), 'utf8');
  assert.match(legal, /<link rel="icon"/, 'legal.html must declare an icon');
});

test('responses are compressed, and the CSP nonce still matches after decompression', async () => {
  // The app shell is ~840 KB uncompressed on every load. Compression is the single
  // biggest thing that makes it usable on a mobile connection — but it must not
  // break the CSP, which relies on the nonce in the header matching the nonce
  // injected into every <script> in the body. A cached compressed body would
  // carry a stale nonce and every script would be blocked.
  const response = await fetch(`${base}/`, { headers: { 'Accept-Encoding': 'br, gzip' } });
  assert.equal(response.status, 200);
  const encoding = response.headers.get('content-encoding');
  assert.ok(['br', 'gzip'].includes(encoding), `expected a compressed response, got "${encoding}"`);
  assert.equal(response.headers.get('vary'), 'Accept-Encoding');

  // undici decompresses transparently, so this is the original bytes.
  const body = await response.text();
  const headerCsp = response.headers.get('content-security-policy') || '';
  const headerNonce = /'nonce-([^']+)'/.exec(headerCsp);
  assert.ok(headerNonce, 'the CSP must contain a nonce');
  const bodyNonces = new Set([...body.matchAll(/<script nonce="([^"]+)"/g)].map((m) => m[1]));
  assert.equal(bodyNonces.size, 1, 'every script tag must carry exactly one nonce');
  assert.equal([...bodyNonces][0], headerNonce[1],
    'the nonce in the body must match the one in the header, or every script is blocked');

  // A client that cannot decompress must still get a usable page.
  const plain = await fetch(`${base}/`, { headers: { 'Accept-Encoding': 'identity' } });
  assert.equal(plain.status, 200);
  assert.equal(plain.headers.get('content-encoding'), null);
  assert.match(await plain.text(), /<title>SafeSteps/);
});

test('already-compressed assets are not re-compressed', async () => {
  // Re-compressing a PNG costs CPU and makes it bigger. The icon must be served
  // byte-for-byte, with no Content-Encoding.
  const response = await fetch(`${base}/icons/icon-192.png`, { headers: { 'Accept-Encoding': 'br, gzip' } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-encoding'), null, 'a PNG must not be gzip/brotli-encoded');
  const bytes = Buffer.from(await response.arrayBuffer());
  const onDisk = fs.readFileSync(path.join(staticFiles.ROOT, 'icons', 'icon-192.png'));
  assert.equal(bytes.length, onDisk.length, 'the image must be served unmodified');
  assert.ok(bytes[0] === 0x89 && bytes[1] === 0x50, 'still a PNG signature');
});

test('static assets are revalidated rather than pinned stale', async () => {
  // `immutable` on an unversioned URL would pin a stale file after a deploy.
  const response = await fetch(`${base}/assets/security.js`);
  const cacheControl = response.headers.get('cache-control') || '';
  assert.match(cacheControl, /no-cache/, 'assets must revalidate so a deploy is picked up');
  assert.doesNotMatch(cacheControl, /immutable/, 'immutable would prevent picking up a deploy');
  const etag = response.headers.get('etag');
  assert.ok(etag, 'a revalidating asset needs an ETag');

  const revalidated = await fetch(`${base}/assets/security.js`, { headers: { 'If-None-Match': etag } });
  assert.equal(revalidated.status, 304, 'a matching ETag must produce a 304, not a download');
});

test('the service worker cache version moves with the app shell', () => {
  // A stale cache would keep serving an old index.html after a deploy, which is
  // how a "fix" appears not to have shipped.
  const sw = fs.readFileSync(path.join(staticFiles.ROOT, 'sw.js'), 'utf8');
  const version = /CACHE_VERSION = '(v\d+)'/.exec(sw);
  assert.ok(version, 'sw.js must declare CACHE_VERSION');
  assert.ok(Number(version[1].slice(1)) >= 49, `CACHE_VERSION should be v49 or later, got ${version[1]}`);
  for (const asset of ['./favicon.ico', './icons/apple-touch-icon-180.png', './404.html']) {
    assert.ok(sw.includes(`'${asset}'`), `${asset} should be in the offline app shell`);
  }
});

test('static resolver refuses to escape its root', () => {
  assert.equal(staticFiles.resolveSafe('/../etc/passwd'), null);
  assert.equal(staticFiles.resolveSafe('/server/server.js'), null);
  assert.equal(staticFiles.resolveSafe('/%00'), null);
  assert.ok(staticFiles.resolveSafe('/index.html').startsWith(staticFiles.ROOT));
});

/* ------------------------------------------------------------------ */
/* B/C. Authentication, brute force and bot protection                 */
/* ------------------------------------------------------------------ */

test('anonymous callers cannot reach account endpoints', async () => {
  for (const route of ['/api/auth/me', '/api/reports']) {
    const response = await fetch(`${base}${route}`, { headers: browserHeaders() });
    assert.equal(response.status, 401, `${route} should require a session`);
  }
  // /api/vault reports the missing SERVER_DATA_KEY (503) before auth in this
  // unconfigured test run; with a key configured it must be 401. Both are
  // "refused", which is the property under test.
  const vault = await fetch(`${base}/api/vault`, {
    method: 'POST',
    headers: browserHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({}),
  });
  assert.ok([401, 503].includes(vault.status), `/api/vault should refuse anonymous callers, got ${vault.status}`);
});

test('missing configuration degrades with an actionable 503, not a crash', async () => {
  // This run has no SUPABASE_* credentials, so auth endpoints must explain
  // themselves rather than throwing an opaque 500.
  const health = await (await fetch(`${base}/healthz`)).json();

  // The process is serving, so this is never 'unavailable'. It says 'degraded'
  // when something it needs is missing — which is the case in this test run.
  // (The status used to be a flat 'ok' regardless, which made the health check
  // unable to distinguish "fine" from "cannot sign anyone in".)
  assert.notEqual(health.status, 'unavailable');
  assert.ok(['ok', 'degraded'].includes(health.status), health.status);
  assert.equal(health.status, 'degraded');

  // Platform reachability must be reported, and must be a boolean — this is the
  // field an uptime monitor alerts on when a free-plan project is paused.
  assert.equal(typeof health.platform, 'object');
  assert.equal(typeof health.platform.reachable, 'boolean');
  assert.equal(typeof health.platform.reason, 'string');

  // Degraded because no service-role key / data key — auth itself is configured
  // in this test run, so capabilities must reflect each piece separately.
  assert.equal(health.degraded, true);
  assert.equal(health.capabilities.emailVerification, false);
  assert.equal(health.capabilities.atRestEncryption, false);

  const response = await fetch(`${base}/api/auth/verify`, {
    method: 'POST',
    headers: browserHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ email: 'a@b.co', code: '12345678' }),
  });
  const body = await response.json();
  assert.equal(response.status, 503);
  // Either the bot check or the capability guard may answer first; both must be
  // an explicit, non-500 refusal that names the missing setting when relevant.
  assert.ok(['feature_unavailable', 'bot_check_failed'].includes(body.error), body.error);
  if (body.error === 'feature_unavailable') {
    assert.match(body.message, /SUPABASE_SERVICE_ROLE_KEY/);
  }
  // The operator-facing name is included, but never a secret value.
  assert.equal(/eyJ|sb_secret|sb_publishable_test_key/.test(JSON.stringify(body)), false);
});

test('/healthz leaks no secrets', async () => {
  const text = await (await fetch(`${base}/healthz`)).text();
  assert.equal(/eyJ|sb_secret|service_role|test-pepper/i.test(text), false);
  assert.equal(/SUPABASE_|SMTP_|SERVER_DATA_KEY/.test(text), false);
});

test('state-changing API calls require a same-origin request', async () => {
  const response = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: browserHeaders({ origin: 'https://evil.example', referer: 'https://evil.example/' }),
    body: JSON.stringify({ email: 'a@b.co', password: 'x' }),
  });
  assert.equal(response.status, 403);
});

test('login is rate limited per client', async () => {
  const [limit, windowMs] = config.security.rateLimits.login;
  let sawLimit = false;
  for (let attempt = 0; attempt < limit + 3; attempt += 1) {
    const response = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: browserHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ email: `user${attempt}@example.org`, password: 'SomePassword1' }),
    });
    if (response.status === 429) {
      sawLimit = true;
      assert.ok(response.headers.get('retry-after'), 'Retry-After must be present');
      break;
    }
  }
  assert.ok(sawLimit, `expected a 429 within ${windowMs}ms window`);
});

test('missing or forged bot proof is rejected', async () => {
  const response = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: browserHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({
      fullName: 'Test Person',
      email: 'test.person@example.org',
      password: 'CorrectHorse1',
      botChallenge: 'deadbeef.1.forged',
      botNonce: '1',
    }),
  });
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error, 'bot_check_failed');
});

test('a honeypot field rejects the submission', async () => {
  const challenge = await (await fetch(`${base}/api/auth/challenge`)).json();
  const response = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: browserHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({
      fullName: 'Test Person',
      email: 'test.person@example.org',
      password: 'CorrectHorse1',
      website: 'https://spam.example',
      botChallenge: challenge.challenge,
      botNonce: '0',
    }),
  });
  assert.equal(response.status, 400);
});

test('proof-of-work challenges verify only when solved', () => {
  const { challenge, difficulty } = bot.issueChallenge();
  assert.equal(bot.verifySolution(challenge, '0'), false);

  // Solve it the way the client does, then confirm the server agrees.
  const salt = challenge.split('.')[0];
  let solution = null;
  for (let nonce = 0; nonce < 2000000; nonce += 1) {
    const digest = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
    if (digest.startsWith('0'.repeat(difficulty))) {
      solution = String(nonce);
      break;
    }
  }
  assert.ok(solution, 'solver should find a solution');
  // Dwell-time floor: an instantly returned solution is treated as automated.
  assert.equal(bot.verifySolution(challenge, solution), false);

  // A tampered challenge must not verify.
  assert.equal(bot.verifySolution(`${challenge}x`, solution), false);
});

/* ------------------------------------------------------------------ */
/* C. Input validation and upload restrictions                          */
/* ------------------------------------------------------------------ */

test('validation rejects injection-shaped input', () => {
  // ValidationError carries a per-field message map; check both the type and
  // the field key so the API can return a useful (and safe) error.
  const fieldOf = (fn) => {
    try {
      fn();
    } catch (error) {
      assert.equal(error.name, 'ValidationError');
      return Object.keys(error.fields || {});
    }
    assert.fail('expected a ValidationError');
    return [];
  };

  assert.deepEqual(fieldOf(() => validation.cleanEmail('victim@example.org\r\nBcc: attacker@evil.test')), ['email']);
  assert.deepEqual(fieldOf(() => validation.cleanEmail("'; drop table users; --")), ['email']);
  assert.deepEqual(fieldOf(() => validation.cleanEmail('no-at-sign.example.org')), ['email']);
  assert.deepEqual(fieldOf(() => validation.cleanPassword('shrt1')), ['password']); // 5 chars, below the floor
  assert.deepEqual(fieldOf(() => validation.cleanPassword('toolongpassword1')), ['password']);
  assert.deepEqual(fieldOf(() => validation.cleanPassword('password')), ['password']);
  assert.deepEqual(fieldOf(() => validation.cleanPassword('alllettersonly')), ['password']);
  assert.deepEqual(fieldOf(() => validation.cleanOtp('12')), ['code']);
  assert.deepEqual(fieldOf(() => validation.cleanUuid('1 or 1=1')), ['id']);
  assert.deepEqual(fieldOf(() => validation.only({ email: 'a@b.co', role: 'admin' }, ['email'])), ['_']);
  assert.deepEqual(fieldOf(() => validation.cleanText('abcdefgh', { max: 5 })), ['value']);

  // And the messages themselves are helpful.
  assert.throws(() => validation.cleanPassword('shrt1'), (error) => /6 to 8/.test(error.fields.password));
  // The upper bound is enforced too, so the published policy and the check agree.
  assert.throws(() => validation.cleanPassword('toolongpass1'), (error) => /6 to 8/.test(error.fields.password));
  assert.equal(validation.cleanPassword('Horse1x2'), 'Horse1x2'); // 8 chars, not a common password
  assert.throws(() => validation.cleanOtp('12'), (error) => /6–8 digits/.test(error.fields.code));
});

test('control characters are stripped from free text', () => {
  const cleaned = validation.cleanText('Safe\u0000Steps\u0007 notes', { max: 100 });
  assert.equal(cleaned, 'SafeSteps notes');
});

test('uploads: type is decided by magic bytes, not by the filename', () => {
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(64, 1),
  ]);
  const info = uploads.inspect(png, 'evidence.png', 'image/png');
  assert.equal(info.mime, 'image/png');
  assert.equal(info.ext, 'png');
  assert.match(info.sha256, /^[0-9a-f]{64}$/);

  // An executable renamed to .png is refused.
  const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64, 0)]);
  assert.throws(() => uploads.inspect(exe, 'photo.png'), /Unsupported/);

  // HTML/SVG are refused even when they would sniff as text.
  assert.throws(
    () => uploads.inspect(Buffer.from('<!DOCTYPE html><script>alert(1)</script>'), 'x.png'),
    /not accepted|Unsupported/
  );
  assert.throws(() => uploads.inspect(png, 'payload.svg'), /not accepted/);

  // Oversized payloads are refused before storage.
  const huge = Buffer.concat([png, Buffer.alloc(config.security.uploads.maxBytes)]);
  assert.throws(() => uploads.inspect(huge, 'big.png'), /smaller than/);

  // A mislabelled content type is refused.
  assert.throws(() => uploads.inspect(png, 'evidence.png', 'image/jpeg'), /do not match/);
});

test('object keys are owner-scoped and non-guessable', () => {
  const userId = '11111111-1111-4111-8111-111111111111';
  const key = uploads.objectKey(userId, 'jpg');
  assert.match(key, new RegExp(`^${userId}/[0-9a-f-]{36}\\.jpg$`));
  assert.notEqual(uploads.objectKey(userId, 'jpg'), key);
  assert.throws(() => uploads.objectKey("../etc", 'jpg'), /Invalid owner/);
});

/* ------------------------------------------------------------------ */
/* B. Session cookies                                                  */
/* ------------------------------------------------------------------ */

test('session cookies are HttpOnly, SameSite=Strict and path-scoped', () => {
  const session = require('../lib/session');
  const captured = [];
  const fakeRes = { getHeader: () => undefined, setHeader: (name, value) => captured.push(...[].concat(value)) };
  session.setSessionCookies(fakeRes, { accessToken: 'a'.repeat(40), refreshToken: 'r'.repeat(40), csrf: 'c'.repeat(40) });

  const [access, refresh, csrf] = captured;
  assert.match(access, /HttpOnly/);
  assert.match(access, /SameSite=Strict/);
  assert.match(access, /Path=\//);
  // The refresh token must not be sent on ordinary requests.
  assert.match(refresh, /Path=\/api\/auth/);
  assert.match(refresh, /HttpOnly/);
  // The CSRF cookie is intentionally readable; it carries no authority alone.
  assert.equal(/HttpOnly/.test(csrf), false);

  if (config.isProduction) {
    assert.match(access, /Secure/);
    assert.match(access, /^__Host-ss_session=/);
    assert.equal(/Domain=/.test(access), false);
  }
});

test('CSRF double-submit is enforced', () => {
  const session = require('../lib/session');
  const req = { headers: { 'x-csrf-token': 'abc' } };
  assert.throws(() => session.assertCsrf(req, { __HostSsCsrf: 'def', ss_csrf: 'def' }), /Invalid CSRF/);
  assert.throws(() => session.assertCsrf(req, {}), /Missing CSRF/);
  assert.doesNotThrow(() => session.assertCsrf({ headers: { 'x-csrf-token': 'abc' } }, { ss_csrf: 'abc' }));
  // The production cookie name is used when NODE_ENV=production.
  assert.equal(session.cookieName('csrf'), config.isProduction ? '__Host-ss_csrf' : 'ss_csrf');
});

/* ------------------------------------------------------------------ */
/* A. Encryption at rest and password handling                         */
/* ------------------------------------------------------------------ */

test('at-rest encryption round-trips and detects tampering', () => {
  const key = crypto.randomBytes(32).toString('base64');
  const payload = 'verification code 12345678';
  const sealed = db.encryptAtRest(payload, key);
  assert.notEqual(sealed, payload);
  assert.equal(db.decryptAtRest(sealed, key), payload);

  const parts = sealed.split('.');
  const tampered = [parts[0], parts[1], parts[2], Buffer.from('evil').toString('base64')].join('.');
  assert.throws(() => db.decryptAtRest(tampered, key));
});

test('verification codes are stored only as keyed fingerprints', () => {
  const verification = require('../lib/verification');
  const email = `code.test.${Date.now()}@example.org`;
  // startChallenge enqueues mail; that path is exercised via the local queue.
  return verification.startChallenge({ email, name: 'Code Tester', purpose: 'signup' }).then(() => {
    const rows = db.query('SELECT code_hash, email_hash FROM verification_challenges ORDER BY created_at DESC LIMIT 1');
    assert.equal(rows.length, 1);
    assert.match(rows[0].code_hash, /^[0-9a-f]{64}$/);
    assert.match(rows[0].email_hash, /^[0-9a-f]{64}$/);
    // The raw address must not be recoverable from the row.
    assert.equal(JSON.stringify(rows[0]).includes(email), false);
    // Codes never appear in the plaintext mail queue body when encryption is on.
    const queue = db.query('SELECT body FROM outbound_mail ORDER BY id DESC LIMIT 1');
    if (queue.length && config.security.serverDataKey) {
      assert.equal(/^\d{8}$/.test(queue[0].body), false);
      assert.match(queue[0].body, /^v1\./);
    }
  });
});

test('verification rejects wrong codes and locks after five attempts', () => {
  const verification = require('../lib/verification');
  const email = `lockout.${Date.now()}@example.org`;
  return verification.startChallenge({ email, name: 'Lockout', purpose: 'signup' }).then(() => {
    for (let i = 0; i < verification.MAX_ATTEMPTS; i += 1) {
      const result = verification.verifyChallenge({ email, code: '00000000' });
      assert.equal(result.ok, false);
    }
    const locked = verification.verifyChallenge({ email, code: '00000000' });
    assert.equal(locked.reason, 'locked');
  });
});

/* ------------------------------------------------------------------ */
/* A. Parameterised queries                                            */
/* ------------------------------------------------------------------ */

test('local store uses bound parameters (injection is inert)', () => {
  db.query('CREATE TABLE IF NOT EXISTS injection_probe (id INTEGER PRIMARY KEY, name TEXT)');
  const hostile = "x'); DROP TABLE injection_probe; --";
  db.query('INSERT INTO injection_probe (name) VALUES (?)', [hostile]);
  const rows = db.query('SELECT name FROM injection_probe WHERE name = ?', [hostile]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, hostile);
  // The table still exists — the payload was data, not SQL.
  assert.doesNotThrow(() => db.query('SELECT COUNT(*) AS n FROM injection_probe'));
});

test('db.query refuses to interpolate a non-array param list', () => {
  assert.throws(() => db.query('SELECT ?', 'not-an-array'), /params array/);
});

/* ------------------------------------------------------------------ */
/* D. Response trimming                                                */
/* ------------------------------------------------------------------ */

test('error responses do not leak internals', async () => {
  const response = await fetch(`${base}/api/does-not-exist`, { headers: browserHeaders() });
  assert.equal(response.status, 404);
  const body = await response.json();
  assert.equal(body.error, 'not_found');
  assert.equal(/stack|at .*\.js:|postgres|supabase\.co/i.test(JSON.stringify(body)), false);
});

test('API responses are marked non-cacheable', async () => {
  const response = await fetch(`${base}/api/config`);
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
});

test('unknown methods are refused', async () => {
  // fetch() refuses to emit a TRACE, so exercise the raw socket.
  const status = await new Promise((resolve, reject) => {
    const socket = require('node:net').connect(Number(new URL(base).port), '127.0.0.1', () => {
      socket.write('TRACE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
    });
    socket.once('data', (chunk) => {
      resolve(Number(chunk.toString('utf8').split(' ')[1]));
      socket.destroy();
    });
    socket.on('error', reject);
  });
  assert.equal(status, 405);
});

/* ------------------------------------------------------------------ */
/* D. Dependency surface                                               */
/* ------------------------------------------------------------------ */

test('server has no third-party runtime dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
});

test('every security header helper agrees with the response', () => {
  const headers = securityHeaders('abc123', { isHtml: true });
  assert.match(headers['Content-Security-Policy'], /nonce-abc123/);
  assert.equal(headers['X-Content-Type-Options'], 'nosniff');
});

/* ------------------------------------------------------------------ */
/* A6. EmailJS is a server-side transport, never a client key          */
/* ------------------------------------------------------------------ */

test('no EmailJS credential exists in anything a browser can load', () => {
  const appRoot = path.join(__dirname, '..', '..');
  const files = ['index.html', 'sw.js', path.join('assets', 'security.js')];
  for (const file of files) {
    const source = fs.readFileSync(path.join(appRoot, file), 'utf8');
    assert.equal(/EMAILJS_(PUBLIC|PRIVATE|SERVICE|TEMPLATE)/.test(source), false, file);
    assert.equal(/emailjs\.(init|send)/.test(source), false, file);
    assert.equal(/api\.emailjs\.com/.test(source), false, file);
  }
});

test('/healthz and /api/config never reveal a mail credential', async () => {
  // Configure a fake EmailJS transport just for this assertion.
  process.env.EMAILJS_SERVICE_ID = 'service_testonly';
  process.env.EMAILJS_TEMPLATE_ID = 'template_testonly';
  process.env.EMAILJS_PUBLIC_KEY = 'key_testonly_do_not_use';
  process.env.EMAILJS_PRIVATE_KEY = 'private_testonly_do_not_use';

  try {
    const config = require('../lib/config');
    assert.equal(config.capabilities().mailTransport, true);
    assert.deepEqual(config.mailTransports(), { smtp: false, emailjs: true, supabaseAuth: true });

    // Read fresh (capabilities are computed per call, not cached).
    for (const route of ['/healthz', '/api/config']) {
      const body = await (await fetch(`${base}${route}`)).text();
      assert.equal(/testonly/.test(body), false, `${route} leaked a credential-shaped value`);
      assert.equal(/EMAILJS_/.test(body), false, `${route} leaked an environment variable name`);
    }
  } finally {
    delete process.env.EMAILJS_SERVICE_ID;
    delete process.env.EMAILJS_TEMPLATE_ID;
    delete process.env.EMAILJS_PUBLIC_KEY;
    delete process.env.EMAILJS_PRIVATE_KEY;
  }
});

test('a mail transport is only "configured" when every part is present', () => {
  const mailer = require('../lib/mailer');
  process.env.EMAILJS_SERVICE_ID = 'service_testonly';
  process.env.EMAILJS_TEMPLATE_ID = '';
  process.env.EMAILJS_PUBLIC_KEY = 'key_testonly';
  try {
    assert.equal(mailer.transports().emailjs, false, 'a partial configuration must not claim to work');
  } finally {
    delete process.env.EMAILJS_SERVICE_ID;
    delete process.env.EMAILJS_TEMPLATE_ID;
    delete process.env.EMAILJS_PUBLIC_KEY;
  }
});

test('EmailJS delivery: the request is well-formed and reports success', async () => {
  // No egress from the test environment, so point the transport at a local
  // endpoint that records exactly what would have been sent. This exercises the
  // real send path (payload shape, auth fields, template selection) without a
  // network dependency.
  const http = require('node:http');
  const received = [];
  const receiver = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      received.push({ headers: req.headers, body: JSON.parse(body) });
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('OK');
    });
  });
  await new Promise((resolve) => receiver.listen(0, '127.0.0.1', resolve));

  process.env.EMAILJS_SERVICE_ID = 'service_testonly';
  process.env.EMAILJS_TEMPLATE_ID = 'template_default';
  process.env.EMAILJS_TEMPLATE_VERIFICATION = 'template_verify';
  process.env.EMAILJS_PUBLIC_KEY = 'key_testonly';
  process.env.EMAILJS_PRIVATE_KEY = 'private_testonly';
  process.env.EMAILJS_API_URL = `http://127.0.0.1:${receiver.address().port}/api/v1.0/email/send`;

  try {
    const mailer = require('../lib/mailer');
    const result = await mailer.enqueue({
      recipient: 'driver@example.org',
      subject: 'Your SafeSteps verification code',
      body: 'Use the code below to finish signing in.',
      verificationCode: '49382716',
    });

    assert.equal(result.delivered, true);
    assert.equal(result.via, 'emailjs');
    assert.equal(received.length, 1);

    const sent = received[0].body;
    assert.equal(sent.service_id, 'service_testonly');
    assert.equal(sent.template_id, 'template_verify', 'the verification template must be preferred when a code is present');
    assert.equal(sent.user_id, 'key_testonly');
    assert.equal(sent.accessToken, 'private_testonly', 'the private key authenticates the call when provided');
    assert.equal(sent.template_params.to_email, 'driver@example.org');
    assert.equal(sent.template_params.verification_code, '49382716');
    assert.match(sent.template_params.subject, /verification code/i);
    assert.match(String(received[0].headers['content-type']), /application\/json/);

    // Ordinary mail uses the default template and carries no code.
    await mailer.enqueue({
      recipient: 'desk@eacc.go.ke',
      subject: 'Case reference ABC-123',
      body: 'Summary of allegation.',
    });
    const second = received[1].body;
    assert.equal(second.template_id, 'template_default');
    assert.equal('verification_code' in second.template_params, false);
  } finally {
    await new Promise((resolve) => receiver.close(resolve));
    for (const key of [
      'EMAILJS_SERVICE_ID', 'EMAILJS_TEMPLATE_ID', 'EMAILJS_TEMPLATE_VERIFICATION',
      'EMAILJS_PUBLIC_KEY', 'EMAILJS_PRIVATE_KEY', 'EMAILJS_API_URL',
    ]) delete process.env[key];
  }
});

test('a failing EmailJS call reports delivered:false instead of claiming success', async () => {
  const http = require('node:http');
  const receiver = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { res.writeHead(422, { 'Content-Type': 'text/plain' }); res.end('The recipient address is invalid'); });
  });
  await new Promise((resolve) => receiver.listen(0, '127.0.0.1', resolve));

  process.env.EMAILJS_SERVICE_ID = 'service_testonly';
  process.env.EMAILJS_TEMPLATE_ID = 'template_default';
  process.env.EMAILJS_PUBLIC_KEY = 'key_testonly';
  process.env.EMAILJS_API_URL = `http://127.0.0.1:${receiver.address().port}/send`;

  try {
    const mailer = require('../lib/mailer');
    const result = await mailer.enqueue({
      recipient: 'nobody@example.org',
      subject: 'Test',
      body: 'Test body',
    });
    // Supabase Auth's mailer is "available" from the URL/key pair, and the code
    // falls back to it — but with no provider callback supplied it cannot
    // deliver, so the honest answer is still false.
    assert.equal(result.delivered, false);
  } finally {
    await new Promise((resolve) => receiver.close(resolve));
    for (const key of [
      'EMAILJS_SERVICE_ID', 'EMAILJS_TEMPLATE_ID', 'EMAILJS_PUBLIC_KEY', 'EMAILJS_API_URL',
    ]) delete process.env[key];
  }
});
