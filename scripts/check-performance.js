#!/usr/bin/env node
'use strict';
/**
 * check-performance.js — measure what a phone actually has to download.
 *
 * There is no browser engine in this environment and no network, so this is not a
 * Lighthouse run and does not claim to be one. What it does is measure the things
 * that dominate load time on a mobile connection and that a code change can
 * silently undo: bytes on the wire, request count before first paint,
 * render-blocking resources, unconstrained images, and missing compression.
 *
 * Exit code 1 on a regression, so CI catches "someone added a 2 MB image" and
 * "someone deleted the compression" the same way it catches a broken test.
 *
 * USAGE
 *   node scripts/check-performance.js [--json]
 *   node scripts/check-performance.js --baseline   # rewrite the recorded budget
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..', 'safesteps');
const BUDGET_FILE = path.join(__dirname, 'performance-budget.json');
const jsonOut = process.argv.includes('--json');
const writeBaseline = process.argv.includes('--baseline');

const findings = [];
function problem(msg) { findings.push({ level: 'FAIL', msg }); }
function note(msg) { findings.push({ level: 'INFO', msg }); }

/** Bytes on disk, and bytes over the wire as the browser would receive them. */
function measure(file) {
  const abs = path.join(ROOT, file);
  if (!fs.existsSync(abs)) return null;
  const raw = fs.readFileSync(abs);
  return {
    file,
    bytes: raw.length,
    gzip: zlib.gzipSync(raw, { level: 6 }).length,
    brotli: zlib.brotliCompressSync(raw, {
      params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 },
    }).length,
  };
}

// ---------------------------------------------------------------------------
// 1. The app shell
// ---------------------------------------------------------------------------
const shell = measure('index.html');
if (!shell) {
  problem('index.html is missing — this check cannot run');
}

// ---------------------------------------------------------------------------
// 2. What the browser must fetch before it can paint
// ---------------------------------------------------------------------------
const html = shell ? fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8') : '';

// Strip <script>/<style> bodies and comments first. Without this, a comment like
// `// rendered as <img src="...">, so ...` and a template literal inside the app
// script (`<img src="${safePhoto}" alt="...">`) are both read as real markup —
// a checker that reports phantom problems gets ignored.
const markupOnly = html
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
  .replace(/<!--[\s\S]*?-->/g, '');

const headEnd = markupOnly.indexOf('</head>');
const head = headEnd > -1 ? markupOnly.slice(0, headEnd) : '';
const blockingCss = [...head.matchAll(/<link[^>]+rel=["']stylesheet["'][^>]*>/gi)]
  .filter((m) => !/media=["']print["']/.test(m[0]))
  .map((m) => (/href=["']([^"']+)["']/.exec(m[0]) || [])[1])
  .filter(Boolean);

// A @import inside CSS is the worst case: it serialises discovery behind parsing.
const cssText = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]).join('\n');
const imports = [...cssText.matchAll(/@import\s+url\(['"]?([^'")]+)/gi)].map((m) => m[1]);

const syncScripts = [...html.matchAll(/<script(?![^>]*\bdefer\b)(?![^>]*\basync\b)[^>]*src=["']([^"']+)["'][^>]*>/gi)]
  .map((m) => m[1])
  .filter((src) => !/^https?:/.test(src));   // third-party handled separately below

const cdnScripts = [...markupOnly.matchAll(/<script[^>]*src=["'](https?:\/\/[^"']+)["'][^>]*>/gi)].map((m) => m[1]);
const cdnHosts = new Set(cdnScripts.map((u) => new URL(u).host));

// ---------------------------------------------------------------------------
// 3. Images: unconstrained or unnecessarily eager
// ---------------------------------------------------------------------------
const imgTags = [...markupOnly.matchAll(/<img\b[^>]*>/gi)].map((m) => m[0]);
// A width attribute, a max-width, or a width in the style attribute constrains it.
const unconstrained = imgTags.filter((t) =>
  !/\bwidth=/.test(t) && !/max-width/.test(t) && !/style=["'][^"']*\bwidth\s*:/.test(t));
const noAlt = imgTags.filter((t) => !/\balt=/.test(t));

// Images actually referenced by the page, and their weight.
const referenced = new Set();
for (const m of markupOnly.matchAll(/(?:src|href)=["']([^"']+\.(?:png|jpe?g|webp|gif|svg|ico))["']/gi)) {
  const f = m[1].replace(/^\.\//, '');
  if (!/^https?:/.test(f)) referenced.add(f);
}
const imageSizes = [...referenced]
  .map((f) => measure(f))
  .filter(Boolean)
  .sort((a, b) => b.bytes - a.bytes);

const EAGER_IMAGE_LIMIT = 120 * 1024;
const eagerHeavy = imageSizes.filter((i) => {
  const abs = path.join(ROOT, i.file);
  const tag = imgTags.find((t) => t.includes(i.file));
  if (!tag) return false;                                    // referenced, not an <img>
  const lazy = /loading=["']lazy["']/.test(tag);
  return !lazy && i.bytes > EAGER_IMAGE_LIMIT;
});

// ---------------------------------------------------------------------------
// 4. Server-side compression
// ---------------------------------------------------------------------------
const staticSrc = fs.readFileSync(path.join(__dirname, '..', 'safesteps', 'server', 'lib', 'static.js'), 'utf8');
const compressModule = path.join(__dirname, '..', 'safesteps', 'server', 'lib', 'compress.js');
const hasCompression = fs.existsSync(compressModule) && /compress\.sendCompressed|compress\.streamCompressed/.test(staticSrc);

// ---------------------------------------------------------------------------
// 5. Compare against the recorded budget
// ---------------------------------------------------------------------------
const budget = fs.existsSync(BUDGET_FILE) ? JSON.parse(fs.readFileSync(BUDGET_FILE, 'utf8')) : null;

const measured = {
  shellBytes: shell ? shell.bytes : 0,
  shellBrotli: shell ? shell.brotli : 0,
  shellGzip: shell ? shell.gzip : 0,
  imageBytes: imageSizes.reduce((a, i) => a + i.bytes, 0),
  largestImage: imageSizes.length ? imageSizes[0].bytes : 0,
  blockingCss: blockingCss.length,
  cssImports: imports.length,
  syncLocalScripts: syncScripts.length,
  cdnHosts: cdnHosts.size,
};

if (writeBaseline) {
  fs.writeFileSync(BUDGET_FILE, JSON.stringify(measured, null, 2) + '\n');
  console.log(`Baseline written to ${path.relative(process.cwd(), BUDGET_FILE)}`);
  console.log(JSON.stringify(measured, null, 2));
  process.exit(0);
}

// Hard limits, independent of the baseline.
if (measured.cssImports > 0) {
  problem(`${measured.cssImports} @import rule(s) in CSS — each one serialises font/style discovery behind parsing; use <link>`);
}
if (!hasCompression) {
  problem('the server does not compress responses (lib/compress.js not wired into static.js)');
}
if (shell && measured.shellBrotli > 300 * 1024) {
  problem(`the app shell is ${(measured.shellBrotli / 1024).toFixed(0)} KB brotli — over the 300 KB budget`);
}
if (measured.largestImage > 400 * 1024) {
  problem(`the largest referenced image is ${(measured.largestImage / 1024).toFixed(0)} KB — over the 400 KB budget`);
}
for (const img of eagerHeavy) {
  problem(`${img.file} (${(img.bytes / 1024).toFixed(0)} KB) is loaded eagerly — add loading="lazy" if it is below the fold`);
}
if (unconstrained.length) {
  problem(`${unconstrained.length} <img> without a width or max-width — a large one will overflow a phone`);
}
if (noAlt.length) {
  problem(`${noAlt.length} <img> without alt text`);
}

// Regression against the baseline: tolerate small drift, catch real changes.
if (budget) {
  const pct = (a, b) => (b === 0 ? 0 : ((a - b) / b) * 100);
  const drift = pct(measured.shellBrotli, budget.shellBrotli);
  if (drift > 10) {
    problem(`the app shell grew ${drift.toFixed(1)}% in brotli bytes (${budget.shellBrotli} → ${measured.shellBrotli})`);
  }
  const imgDrift = pct(measured.imageBytes, budget.imageBytes);
  if (imgDrift > 15) {
    problem(`total referenced image bytes grew ${imgDrift.toFixed(1)}% (${budget.imageBytes} → ${measured.imageBytes})`);
  }
  if (measured.cssImports > budget.cssImports) {
    problem(`CSS @import count went from ${budget.cssImports} to ${measured.cssImports}`);
  }
  if (measured.blockingCss > budget.blockingCss) {
    problem(`render-blocking stylesheet count went from ${budget.blockingCss} to ${measured.blockingCss}`);
  }
  note(`drift vs baseline: shell ${drift >= 0 ? '+' : ''}${drift.toFixed(1)}%, images ${imgDrift >= 0 ? '+' : ''}${imgDrift.toFixed(1)}%`);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const kb = (n) => `${(n / 1024).toFixed(0)} KB`;

if (jsonOut) {
  console.log(JSON.stringify({ measured, findings, ok: !findings.some((f) => f.level === 'FAIL') }, null, 2));
} else {
  console.log('SafeSteps performance check\n');
  console.log('  App shell');
  console.log(`    on disk          ${kb(measured.shellBytes)}`);
  console.log(`    brotli on wire   ${kb(measured.shellBrotli)}  (${((1 - measured.shellBrotli / measured.shellBytes) * 100).toFixed(0)}% smaller)`);
  console.log(`    gzip on wire     ${kb(measured.shellGzip)}`);
  console.log('  Requests before first paint');
  console.log(`    render-blocking stylesheets  ${measured.blockingCss}`);
  console.log(`    CSS @import chains           ${measured.cssImports}`);
  console.log(`    synchronous local scripts    ${measured.syncLocalScripts}`);
  console.log(`    third-party hosts            ${measured.cdnHosts} (${[...cdnHosts].join(', ') || 'none'})`);
  console.log('  Images referenced by the shell');
  console.log(`    total            ${kb(measured.imageBytes)}`);
  if (imageSizes.length) {
    for (const i of imageSizes.slice(0, 4)) {
      console.log(`    ${i.file.padEnd(34)} ${kb(i.bytes)}`);
    }
  }
  console.log('');
  const fails = findings.filter((f) => f.level === 'FAIL');
  const infos = findings.filter((f) => f.level === 'INFO');
  for (const f of fails) console.log(`  FAIL ${f.msg}`);
  for (const f of infos) console.log(`  INFO ${f.msg}`);
  if (!fails.length) console.log('  No performance regressions.\n');
}

process.exit(findings.some((f) => f.level === 'FAIL') ? 1 : 0);
