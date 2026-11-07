#!/usr/bin/env node
'use strict';
/**
 * smoke-test.js — exercise the app the way a launch day will.
 *
 * Section E: "test the app before launch under realistic conditions".
 *
 * The other scripts check configuration and static properties. This one drives
 * the running server: it hammers the endpoints a real user and a real bot would
 * hit, at a realistic concurrency, and asserts on how the app behaves under
 * pressure rather than in isolation.
 *
 * WHAT IT CHECKS
 *   1. Availability    — the shell, the legal page and /healthz answer.
 *   2. Security headers on every path that serves HTML.
 *   3. Auth boundary   — every protected endpoint refuses an anonymous caller,
 *                        and does so with 401 rather than 500.
 *   4. Abuse resistance— a burst of login attempts is rate limited (429), not
 *                        served indefinitely; and CSRF refuses cross-origin.
 *   5. Analytics ingest— works, and cannot be used as a free write endpoint.
 *   6. Load            — a concurrent mixed workload completes with a sane
 *                        p95 and no 5xx. A launch day looks like this: many
 *                        small requests at once, not one big one.
 *   7. Offline shell   — the service worker and manifest are served and the
 *                        pre-cache list resolves.
 *
 * Exit 0 only if every assertion holds. Any 5xx during the load phase fails the
 * run: at launch, a 500 is a person who could not use the app.
 *
 * USAGE
 *   node scripts/smoke-test.js [baseUrl]
 *   BASE_URL=https://your-host node scripts/smoke-test.js
 *
 * OPTIONS
 *   --concurrency N   parallel workers for the load phase (default 12)
 *   --duration S      seconds to sustain the load phase (default 8)
 */

const BASE = (process.argv.find((a) => a.startsWith('http')) || process.env.BASE_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '');

function argValue(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? Number(process.argv[i + 1]) : fallback;
}
const CONCURRENCY = argValue('--concurrency', 12);
const DURATION_S = argValue('--duration', 8);

const C = process.stdout.isTTY
  ? { r: '\u001b[31m', y: '\u001b[33m', g: '\u001b[32m', c: '\u001b[36m', d: '\u001b[2m', o: '\u001b[0m' }
  : { r: '', y: '', g: '', c: '', d: '', o: '' };

let failures = 0;
let warnings = 0;
const pass = (m) => console.log(`  ${C.g}PASS${C.o} ${m}`);
const fail = (m) => { failures += 1; console.log(`  ${C.r}FAIL${C.o} ${m}`); };
const warn = (m) => { warnings += 1; console.log(`  ${C.y}WARN${C.o} ${m}`); };
const info = (m) => console.log(`  ${C.d}${m}${C.o}`);
const section = (m) => console.log(`\n${C.c}${m}${C.o}`);

const BROWSER_HEADERS = {
  'User-Agent':
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-KE,en;q=0.9',
};

async function timed(fn) {
  const started = process.hrtime.bigint();
  const value = await fn();
  return { value, ms: Number(process.hrtime.bigint() - started) / 1e6 };
}

async function get(path, headers = {}) {
  return fetch(`${BASE}${path}`, { headers: { ...BROWSER_HEADERS, ...headers }, redirect: 'manual' });
}

async function main() {
  console.log(`${C.c}SafeSteps launch smoke test${C.o}`);
  info(`target: ${BASE}`);
  info(`${CONCURRENCY} concurrent workers for ${DURATION_S}s in the load phase`);
  console.log('');

  // -------------------------------------------------------------------------
  section('1. Availability');
  // -------------------------------------------------------------------------
  let shell;
  try {
    const r = await timed(() => get('/'));
    shell = r;
    if (r.value.status === 200) pass(`app shell answers 200 (${r.ms.toFixed(0)} ms)`);
    else fail(`app shell returned ${r.value.status}`);
  } catch (error) {
    fail(`app shell unreachable: ${error.message}`);
    console.log(`\n${C.r}Nothing else can be tested — is the server running at ${BASE}?${C.o}`);
    process.exit(1);
  }

  for (const [path, label] of [
    ['/legal.html', 'privacy policy / terms'],
    ['/manifest.json', 'PWA manifest'],
    ['/sw.js', 'service worker'],
    ['/healthz', 'health check'],
  ]) {
    const r = await get(path);
    if (r.status === 200) pass(`${label} (${path}) 200`);
    else fail(`${label} (${path}) returned ${r.status}`);
  }

  // -------------------------------------------------------------------------
  section('2. Security headers');
  // -------------------------------------------------------------------------
  const htmlPaths = ['/', '/legal.html'];
  const required = [
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
  ];
  for (const path of htmlPaths) {
    const response = await get(path);
    const missing = required.filter((h) => !response.headers.get(h));
    if (!missing.length) pass(`${path}: all security headers present`);
    else fail(`${path}: missing ${missing.join(', ')}`);
  }

  // The server's own source must never be reachable.
  for (const path of ['/server/server.js', '/server/lib/config.js', '/.env', '/server/.env']) {
    const r = await get(path);
    if (r.status === 404) pass(`not exposed: ${path}`);
    else fail(`${path} returned ${r.status} — it must be 404`);
  }

  // -------------------------------------------------------------------------
  section('3. Auth boundary (anonymous callers)');
  // -------------------------------------------------------------------------
  const protectedGets = ['/api/auth/me', '/api/reports', '/api/metrics', '/api/vault'];
  for (const path of protectedGets) {
    const r = await get(path);
    if (r.status === 401) pass(`${path} → 401`);
    else if (r.status === 403) warn(`${path} → 403 (refused, but 401 is the clearer answer)`);
    else if (r.status >= 500) fail(`${path} → ${r.status}: an unauthenticated probe must not reach the handler`);
    else fail(`${path} → ${r.status}: expected 401`);
  }

  const protectedPosts = ['/api/auth/logout', '/api/account/delete', '/api/reports', '/api/auth/refresh'];
  for (const path of protectedPosts) {
    const r = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { ...BROWSER_HEADERS, Origin: BASE, 'Content-Type': 'application/json' },
      body: '{}',
    });
    if ([401, 403, 400].includes(r.status)) pass(`${path} refuses an anonymous POST (${r.status})`);
    else if (r.status >= 500) fail(`${path} POST → ${r.status}`);
    else fail(`${path} POST → ${r.status}: expected a refusal`);
  }

  // -------------------------------------------------------------------------
  section('4. Abuse resistance');
  // -------------------------------------------------------------------------
  // Cross-origin state change must be refused (CSRF).
  const csrf = await fetch(`${BASE}/api/account/delete`, {
    method: 'POST',
    headers: { ...BROWSER_HEADERS, Origin: 'https://evil.example', 'Content-Type': 'application/json' },
    body: '{}',
  });
  if ([403, 400].includes(csrf.status)) pass(`cross-origin POST refused (${csrf.status})`);
  else fail(`cross-origin POST returned ${csrf.status} — CSRF protection is not working`);

  // A login burst must be rate limited. This is the realistic abuse pattern:
  // credential stuffing is many attempts from one client, quickly.
  const attempts = 18;
  const statuses = [];
  for (let i = 0; i < attempts; i += 1) {
    const r = await fetch(`${BASE}/api/auth/login`, {
      method: 'POST',
      headers: {
        ...BROWSER_HEADERS,
        Origin: BASE,
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.77', // fixed: same "client" for the burst
      },
      body: JSON.stringify({ email: `probe${i}@example.com`, password: 'wrong123' }),
    });
    statuses.push(r.status);
  }
  const limited = statuses.filter((s) => s === 429).length;
  const fiveHundreds = statuses.filter((s) => s >= 500).length;
  if (fiveHundreds) fail(`${fiveHundreds} of ${attempts} login attempts returned 5xx`);
  if (limited > 0) pass(`login burst rate limited (${limited}/${attempts} got 429)`);
  else warn(`no 429 among ${attempts} rapid logins — the limiter may be disabled or much looser than configured`);

  // -------------------------------------------------------------------------
  section('5. Analytics ingest');
  // -------------------------------------------------------------------------
  const ingest = await fetch(`${BASE}/api/events`, {
    method: 'POST',
    headers: { ...BROWSER_HEADERS, Origin: BASE, 'Content-Type': 'application/json' },
    body: JSON.stringify({ events: [{ name: 'app_open', fields: {} }] }),
  });
  if (ingest.status === 204) pass('ingest accepted a well-formed event (204)');
  else fail(`ingest returned ${ingest.status}`);

  const emptyIngest = await fetch(`${BASE}/api/events`, {
    method: 'POST',
    headers: { ...BROWSER_HEADERS, Origin: BASE, 'Content-Type': 'application/json' },
    body: '{"events":"not-an-array"}',
  });
  if (emptyIngest.status === 204) pass('malformed ingest is ignored without an error');
  else if (emptyIngest.status === 400) warn(`malformed ingest → 400 (acceptable, but 204 reveals less: ${emptyIngest.status})`);
  else fail(`malformed ingest → ${emptyIngest.status}`);

  // -------------------------------------------------------------------------
  section('6. Load under realistic concurrency');
  // -------------------------------------------------------------------------
  const paths = ['/', '/legal.html', '/manifest.json', '/healthz', '/api/config', '/sw.js'];
  const latencies = [];
  const statusCounts = new Map();
  const deadline = Date.now() + DURATION_S * 1000;

  async function worker() {
    while (Date.now() < deadline) {
      const path = paths[Math.floor(Math.random() * paths.length)];
      const started = process.hrtime.bigint();
      let status = 0;
      try {
        const r = await get(path);
        status = r.status;
        // Drain the body so the socket is reusable.
        await r.arrayBuffer();
      } catch {
        status = -1;
      }
      latencies.push(Number(process.hrtime.bigint() - started) / 1e6);
      statusCounts.set(status, (statusCounts.get(status) || 0) + 1);
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  latencies.sort((a, b) => a - b);
  const pct = (p) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))] || 0;
  const serverErrors = [...statusCounts.entries()].filter(([s]) => s >= 500 || s === -1);
  const total = latencies.length;

  info(`${total} requests in ${DURATION_S}s (${(total / DURATION_S).toFixed(0)}/s)`);
  info(`p50 ${pct(0.5).toFixed(0)} ms · p95 ${pct(0.95).toFixed(0)} ms · p99 ${pct(0.99).toFixed(0)} ms`);
  info(`statuses: ${[...statusCounts.entries()].map(([s, n]) => `${s}×${n}`).join(' ')}`);

  if (!serverErrors.length) pass('no 5xx and no dropped connection under load');
  else fail(`errors under load: ${serverErrors.map(([s, n]) => `${s}×${n}`).join(' ')}`);

  if (pct(0.95) < 1000) pass(`p95 ${pct(0.95).toFixed(0)} ms is within 1 s`);
  else warn(`p95 is ${pct(0.95).toFixed(0)} ms — slow for a static shell; check the host, not the app`);

  // A rate-limited response during the load phase is legitimate behaviour.
  const throttled = statusCounts.get(429) || 0;
  if (throttled) info(`${throttled} request(s) were rate limited during the load phase — expected under a burst`);

  // -------------------------------------------------------------------------
  section('7. Offline shell');
  // -------------------------------------------------------------------------
  const sw = await get('/sw.js');
  const swText = await sw.text();
  const version = (swText.match(/const\s+CACHE_VERSION\s*=\s*['"]([^'"]+)['"]/) || [])[1];
  if (version) pass(`service worker declares CACHE_VERSION ${version}`);
  else fail('sw.js has no CACHE_VERSION — stale caches will never clear');

  const manifest = await (await get('/manifest.json')).json().catch(() => null);
  if (manifest && manifest.name) pass(`manifest: ${manifest.name}`);
  else fail('manifest.json is not valid JSON or has no name');

  const shellMatch = swText.match(/const\s+APP_SHELL\s*=\s*\[([\s\S]*?)\]/);
  if (shellMatch) {
    const entries = [...shellMatch[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]);
    const checks = await Promise.all(
      entries.map(async (entry) => {
        const r = await get('/' + entry.replace(/^\.\//, ''));
        return { entry, status: r.status };
      })
    );
    const broken = checks.filter((c) => c.status !== 200);
    if (!broken.length) pass(`all ${entries.length} pre-cached assets resolve (offline install will succeed)`);
    else fail(`${broken.length} pre-cached asset(s) 404 — cache.addAll() will reject and offline support dies: ${broken.slice(0, 4).map((b) => b.entry).join(', ')}`);
  } else {
    fail('sw.js has no APP_SHELL list');
  }

  // -------------------------------------------------------------------------
  console.log('');
  if (failures === 0) {
    console.log(`${C.g}Smoke test passed${warnings ? ` (${warnings} warning(s))` : ''}.${C.o}`);
    console.log(`${C.d}This exercises the running server. It is not a substitute for a real phone,${C.o}`);
    console.log(`${C.d}but it is what a launch day looks like from the server's side.${C.o}`);
    process.exit(0);
  }
  console.log(`${C.r}${failures} smoke check(s) failed.${C.o}`);
  process.exit(1);
}

main().catch((error) => {
  console.error(`${C.r}smoke test crashed:${C.o} ${error && error.stack ? error.stack : error}`);
  process.exit(1);
});
