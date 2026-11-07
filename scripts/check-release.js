#!/usr/bin/env node
'use strict';
/**
 * check-release.js — pre-deploy and rollback safety checks.
 *
 * Section C: "test updates before deployment" and "implement rollback
 * procedures".
 *
 * The specific failure this exists to prevent: a deploy ships new HTML, but
 * `CACHE_VERSION` in sw.js is not bumped. The service worker then keeps serving
 * the OLD app shell from cache, so the fix appears not to work — and, worse, a
 * rollback to a previous release can be silently ignored for exactly the same
 * reason. Users stay on stale code and nothing in the logs says so.
 *
 * CHECKS
 *   1. CACHE_VERSION is present and looks like a version.
 *   2. If this is compared against a git ref (--since <ref>), the app shell,
 *      any cached data file, or the service worker itself changed => the cache
 *      version MUST have been bumped.
 *   3. Every asset in the service worker's APP_SHELL exists on disk. A typo
 *      there makes `cache.addAll()` reject, which kills offline support
 *      wholesale — the app then fails to install its cache and the failure is
 *      invisible until someone is offline.
 *   4. Every file in APP_SHELL is inside the deployed static root (no path
 *      escaping to server code).
 *   5. A rollback target is recorded, so there is something to go back to.
 *
 * USAGE
 *   node scripts/check-release.js                  # static checks only
 *   node scripts/check-release.js --since origin/main   # + cache-bump gate
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const APP = path.join(ROOT, 'safesteps');
const SW = path.join(APP, 'sw.js');

const C = process.stdout.isTTY
  ? { r: '\u001b[31m', y: '\u001b[33m', g: '\u001b[32m', c: '\u001b[36m', d: '\u001b[2m', o: '\u001b[0m' }
  : { r: '', y: '', g: '', c: '', d: '', o: '' };

let failures = 0;
let warnings = 0;
const pass = (m) => console.log(`  ${C.g}PASS${C.o} ${m}`);
const fail = (m) => { failures += 1; console.log(`  ${C.r}FAIL${C.o} ${m}`); };
const warn = (m) => { warnings += 1; console.log(`  ${C.y}WARN${C.o} ${m}`); };
const info = (m) => console.log(`  ${C.d}${m}${C.o}`);

if (!fs.existsSync(SW)) {
  console.error(`${C.r}sw.js not found at ${SW}${C.o}`);
  process.exit(1);
}
const sw = fs.readFileSync(SW, 'utf8');

console.log(`${C.c}SafeSteps release check${C.o}\n`);

// ---------------------------------------------------------------------------
// 1. The cache version exists
// ---------------------------------------------------------------------------
const versionMatch = sw.match(/const\s+CACHE_VERSION\s*=\s*['"]([^'"]+)['"]/);
if (!versionMatch) {
  fail('sw.js has no CACHE_VERSION — stale caches would never be cleared');
} else {
  const version = versionMatch[1];
  if (!/^v\d+/.test(version)) warn(`CACHE_VERSION "${version}" does not look like v<number>; bumping is manual, so the format is a convention, not a requirement`);
  else pass(`CACHE_VERSION is ${version}`);
}

// ---------------------------------------------------------------------------
// 2. Every cached asset exists
// ---------------------------------------------------------------------------
const shellMatch = sw.match(/const\s+APP_SHELL\s*=\s*\[([\s\S]*?)\]/);
if (!shellMatch) {
  fail('sw.js has no APP_SHELL array — cannot verify what gets pre-cached');
} else {
  const entries = [...shellMatch[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]);
  info(`${entries.length} assets in the pre-cache list`);

  let missing = 0;
  let escaping = 0;
  for (const entry of entries) {
    const rel = entry.replace(/^\.\//, '');
    // Anything that leaves the static root would be served 404 at best, and at
    // worst would mean the service worker tries to cache server source.
    if (rel.includes('..')) {
      escaping += 1;
      fail(`APP_SHELL entry escapes the static root: ${entry}`);
      continue;
    }
    const abs = path.join(APP, rel);
    if (!fs.existsSync(abs)) {
      missing += 1;
      console.log(`  ${C.r}MISS${C.o} ${entry}`);
    }
  }
  if (missing === 0 && escaping === 0) {
    pass('every pre-cached asset exists on disk');
  } else if (missing > 0) {
    fail(`${missing} asset(s) missing — cache.addAll() rejects, and offline support dies silently`);
  }
}

// ---------------------------------------------------------------------------
// 3. Dynamic data files also exist
// ---------------------------------------------------------------------------
const dynMatch = sw.match(/const\s+DYNAMIC_DATA_FILES\s*=\s*\[([\s\S]*?)\]/);
if (dynMatch) {
  const entries = [...dynMatch[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]);
  const missing = entries.filter((e) => !fs.existsSync(path.join(APP, e.replace(/^\.\//, ''))));
  if (missing.length) fail(`dynamic data file(s) missing: ${missing.join(', ')}`);
  else pass(`all ${entries.length} dynamic data files exist`);
}

// ---------------------------------------------------------------------------
// 4. The cache-bump gate (only when a ref to compare against is given)
// ---------------------------------------------------------------------------
const sinceIdx = process.argv.indexOf('--since');
if (sinceIdx !== -1 && process.argv[sinceIdx + 1]) {
  const ref = process.argv[sinceIdx + 1];
  let changed = [];
  try {
    // Two ranges on purpose:
    //   ref...HEAD      commits on this branch that are not on ref
    //   ref             the working tree, including uncommitted edits
    // Checking only the first made the gate blind exactly when it is most
    // useful — while the change is still sitting uncommitted before a deploy.
    const read = (cmd) =>
      execSync(cmd, { cwd: ROOT, encoding: 'utf8' })
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
    changed = [...new Set([...read(`git diff --name-only ${ref}...HEAD`), ...read(`git diff --name-only ${ref}`)])];
  } catch (e) {
    warn(`could not diff against ${ref} (${String(e.message).split('\n')[0]}) — skipping the cache-bump gate`);
  }

  if (changed.length) {
    // Files the service worker serves from cache. If any of these changed and
    // the cache version did not, users keep the old copy.
    const shellSensitive = changed.filter(
      (f) =>
        f === 'safesteps/index.html' ||
        f === 'safesteps/sw.js' ||
        f === 'safesteps/manifest.json' ||
        (f.startsWith('safesteps/data/') && f.endsWith('.json')) ||
        f.startsWith('safesteps/assets/') ||
        f.startsWith('safesteps/icons/')
    );
    const swChanged = changed.includes('safesteps/sw.js');

    if (!shellSensitive.length) {
      pass('no cached app-shell file changed — no cache bump needed');
    } else if (!swChanged) {
      fail(
        `${shellSensitive.length} cached file(s) changed but sw.js did not — ` +
          'CACHE_VERSION was not bumped, so existing users keep the old shell ' +
          '(and a rollback would be ignored too)'
      );
      shellSensitive.slice(0, 8).forEach((f) => console.log(`       ${C.d}${f}${C.o}`));
    } else {
      let bumped = false;
      try {
        const oldSw = execSync(`git show ${ref}:safesteps/sw.js`, { cwd: ROOT, encoding: 'utf8' });
        const oldVersion = (oldSw.match(/const\s+CACHE_VERSION\s*=\s*['"]([^'"]+)['"]/) || [])[1];
        const newVersion = (sw.match(/const\s+CACHE_VERSION\s*=\s*['"]([^'"]+)['"]/) || [])[1];
        bumped = Boolean(oldVersion && newVersion && oldVersion !== newVersion);
        info(`CACHE_VERSION ${oldVersion} -> ${newVersion}`);
      } catch {
        warn(`could not read sw.js at ${ref}; assuming the bump is real`);
        bumped = true;
      }
      if (bumped) pass('cached files changed and CACHE_VERSION was bumped');
      else fail('sw.js changed but CACHE_VERSION is identical — old caches will not be cleared');
    }
  }
} else {
  info('no --since <ref> given: skipped the cache-bump gate (CI passes origin/main)');
}

// ---------------------------------------------------------------------------
// 5. A rollback target is recorded
// ---------------------------------------------------------------------------
try {
  const head = execSync('git rev-parse --short HEAD', { cwd: ROOT, encoding: 'utf8' }).trim();
  const tag = execSync('git tag --points-at HEAD', { cwd: ROOT, encoding: 'utf8' }).trim();
  if (tag) pass(`a release tag points at HEAD (${tag}) — rollback target exists`);
  else warn(`HEAD (${head}) is not tagged; tag releases so there is a named rollback target (see docs/ROLLBACK.md)`);
} catch {
  info('not a git checkout — rollback tagging not checked');
}

console.log('');
if (failures === 0) {
  console.log(`${C.g}Release checks passed${warnings ? ` (${warnings} warning(s))` : ''}.${C.o}`);
  process.exit(0);
}
console.log(`${C.r}${failures} release check(s) failed.${C.o}`);
process.exit(1);
