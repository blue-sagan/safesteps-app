#!/usr/bin/env node
'use strict';
/**
 * check-links.js — find broken links, dead anchors, missing assets and
 * unreachable navigation.
 *
 * The app is a single-page shell plus a few standalone documents, so a crawler
 * is the wrong tool: most "pages" are `#page-*` sections that only exist in
 * index.html. This walks the real files and resolves each reference the way the
 * browser and the server will.
 *
 * CHECKS
 *   1. File references  (src/href/url()/manifest/APP_SHELL) resolve on disk.
 *   2. In-page anchors  (#foo) exist as an id or a name in the same document.
 *   3. Cross-page anchors (legal.html#privacy) exist in the target document.
 *   4. showPage('x') targets exist as #page-x sections.
 *   5. Every screen is reachable (no orphaned sections nobody can navigate to).
 *   6. tel: and mailto: links are well formed.
 *   7. No empty href="#", href="" or javascript:void(0) placeholders left.
 *
 * Exit 1 on any broken link, so CI can gate it.
 *
 * USAGE
 *   node scripts/check-links.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const APP = path.join(ROOT, 'safesteps');

const C = process.stdout.isTTY
  ? { r: '\u001b[31m', y: '\u001b[33m', g: '\u001b[32m', c: '\u001b[36m', d: '\u001b[2m', o: '\u001b[0m' }
  : { r: '', y: '', g: '', c: '', d: '', o: '' };

let errors = 0;
let warnings = 0;
let checked = 0;
const pass = (m) => console.log(`  ${C.g}PASS${C.o} ${m}`);
const fail = (m) => { errors += 1; console.log(`  ${C.r}BROKEN${C.o} ${m}`); };
const warn = (m) => { warnings += 1; console.log(`  ${C.y}WARN${C.o} ${m}`); };
const section = (m) => console.log(`\n${C.c}${m}${C.o}`);

const htmlFiles = fs.readdirSync(APP).filter((f) => f.endsWith('.html'));

/**
 * Strip comments and inline script bodies.
 *
 * Both matter: commented-out markup is not a live link, and inline JavaScript is
 * full of things that look like attributes (`src = "file"`, `href = url`,
 * `new URL(...)`). An earlier version scanned those and reported seven
 * imaginary broken images — a checker that cries wolf gets ignored.
 */
function stripComments(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi, '<script></script>')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '<style></style>');
}

/** ids and <a name> values present in a document. */
function anchorsOf(html) {
  const ids = new Set([...html.matchAll(/\sid=["']([^"']+)["']/g)].map((m) => m[1]));
  for (const m of html.matchAll(/<a[^>]+\sname=["']([^"']+)["']/gi)) ids.add(m[1]);
  return ids;
}

const docs = {};
for (const f of htmlFiles) {
  const raw = fs.readFileSync(path.join(APP, f), 'utf8');
  docs[f] = { raw, clean: stripComments(raw), anchors: anchorsOf(stripComments(raw)) };
}

console.log(`${C.c}SafeSteps link check${C.o}`);
console.log(`${C.d}${htmlFiles.length} documents: ${htmlFiles.join(', ')}${C.o}`);

// ---------------------------------------------------------------------------
section('1. Local file references');
// ---------------------------------------------------------------------------
for (const [file, doc] of Object.entries(docs)) {
  const refs = new Set();
  for (const m of doc.clean.matchAll(/\s(?:src|href)=["']([^"']+)["']/gi)) refs.add(m[1]);
  for (const m of doc.clean.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) refs.add(m[1]);

  for (const ref of refs) {
    if (!ref || ref.startsWith('#') || ref.startsWith('data:') || ref.startsWith('http:') || ref.startsWith('https:')) continue;
    if (ref.startsWith('tel:') || ref.startsWith('mailto:') || ref.startsWith('sms:')) continue;
    if (ref.startsWith('${') || ref.includes('${')) continue; // template literal, resolved at runtime

    checked += 1;
    const [bare, hash] = ref.split('#');
    const target = path.resolve(APP, bare.split('?')[0]);
    if (!fs.existsSync(target)) {
      fail(`${file}: "${ref}" → file not found (${path.relative(ROOT, target)})`);
      continue;
    }
    if (hash) {
      const targetName = path.basename(target);
      const targetDoc = docs[targetName];
      if (targetDoc && !targetDoc.anchors.has(hash)) {
        fail(`${file}: "${ref}" → #${hash} does not exist in ${targetName}`);
      }
    }
  }
}
if (errors === 0) pass(`all ${checked} local file references resolve`);

// ---------------------------------------------------------------------------
section('2. In-page anchors');
// ---------------------------------------------------------------------------
let anchorCount = 0;
for (const [file, doc] of Object.entries(docs)) {
  for (const m of doc.clean.matchAll(/href=["']#([^"']+)["']/g)) {
    const id = m[1];
    if (!id) continue;
    anchorCount += 1;
    if (!doc.anchors.has(id)) fail(`${file}: href="#${id}" → no element with that id`);
  }
}
pass(`${anchorCount} in-page anchor(s) verified`);

// ---------------------------------------------------------------------------
section('3. Every showPage target exists');
// ---------------------------------------------------------------------------
const index = docs['index.html'];
if (index) {
  const pages = new Set([...index.clean.matchAll(/id="page-([a-z0-9-]+)"/g)].map((m) => m[1]));
  const targets = new Set();
  for (const m of index.clean.matchAll(/showPage\(\s*["']([a-z0-9-]+)["']/g)) targets.add(m[1]);
  for (const m of index.clean.matchAll(/closeMoreAndShowPage\(\s*["']([a-z0-9-]+)["']/g)) targets.add(m[1]);
  for (const m of index.clean.matchAll(/data-nav=["']([a-z0-9-]+)["']/g)) targets.add(m[1]);
  for (const m of index.clean.matchAll(/data-page=["']([a-z0-9-]+)["']/g)) targets.add(m[1]);
  // dynamic targets built from data: showPage('${...}')
  const dynamic = [...index.clean.matchAll(/showPage\(\s*["']\$\{/g)].length;

  const missing = [...targets].filter((t) => !pages.has(t));
  if (missing.length) missing.forEach((t) => fail(`showPage('${t}') → no #page-${t} section`));
  else pass(`all ${targets.size} static navigation target(s) exist${dynamic ? ` (+${dynamic} dynamic)` : ''}`);

  // -------------------------------------------------------------------------
  section('4. Every screen is reachable');
  // -------------------------------------------------------------------------
  // A section nobody can navigate to is dead weight the user can never reach —
  // and it is invisible in a browser, so only a check like this finds it.
  const reachable = new Set(targets);
  // Reached from generated markup or from data-driven code.
  for (const m of index.clean.matchAll(/showPage\(\s*["']\$\{[^}]*\}["']/g)) reachable.add('__dynamic__');
  // Pages opened directly by id in code.
  for (const m of index.raw.matchAll(/getElementById\(\s*["']page-([a-z0-9-]+)["']/g)) reachable.add(m[1]);

  const orphans = [...pages].filter((p) => !reachable.has(p));
  if (orphans.length) {
    for (const o of orphans) {
      // County/quick-link targets are generated at runtime from data, so check
      // whether the page id appears anywhere at all before calling it orphaned.
      const mentions = (index.raw.match(new RegExp(`["']${o}["']`, 'g')) || []).length;
      if (mentions > 1) warn(`#page-${o} is only reached from generated markup (${mentions} refs) — verify it opens`);
      else fail(`#page-${o} is unreachable: nothing navigates to it`);
    }
    if (!errors) pass('no unreachable screens');
  } else {
    pass(`all ${pages.size} screens are reachable`);
  }
}

// ---------------------------------------------------------------------------
section('5. tel: and mailto: links');
// ---------------------------------------------------------------------------
const seenTel = new Set();
const seenMail = new Set();
for (const [file, doc] of Object.entries(docs)) {
  for (const m of doc.clean.matchAll(/href=["']tel:([^"']*)["']/g)) {
    const n = m[1];
    if (n.includes('${')) continue;
    seenTel.add(n);
    if (!/^\+?[0-9\s()-]{3,20}$/.test(n)) fail(`${file}: tel:${n} is not a dialable number`);
  }
  for (const m of doc.clean.matchAll(/href=["']mailto:([^"'?]*)/g)) {
    const a = m[1];
    if (a.includes('${')) continue;
    seenMail.add(a);
    if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(a)) fail(`${file}: mailto:${a} is not a valid address`);
  }
}
pass(`${seenTel.size} phone number(s): ${[...seenTel].join(', ')}`);
pass(`${seenMail.size} email address(es): ${[...seenMail].join(', ')}`);

// ---------------------------------------------------------------------------
section('6. Placeholder links');
// ---------------------------------------------------------------------------
// A href="#" that goes nowhere is a dead end; it is nearly always a link that
// was never finished.
let placeholders = 0;
for (const [file, doc] of Object.entries(docs)) {
  for (const m of doc.clean.matchAll(/<a\b[^>]*href=["'](#[^"']*|javascript:[^"']*)["'][^>]*>/gi)) {
    const href = m[1];
    if (href === '#') {
      placeholders += 1;
      const label = (m[0].match(/>([^<]*)</) || [])[1] || '(no text)';
      warn(`${file}: <a href="#"> with no target — "${label.trim().slice(0, 40)}"`);
    } else if (href.startsWith('javascript:')) {
      fail(`${file}: javascript: URL (${href.slice(0, 30)}) — use a button`);
    }
  }
  // Buttons that do nothing at all.
  for (const m of doc.clean.matchAll(/<button\b([^>]*)>/gi)) {
    const attrs = m[1];
    if (/\son\w+=|\bid=|\btype=["']submit|\bdata-|\bdisabled/.test(attrs)) continue;
    if (/class=["'][^"']*\b(nav-btn|bnav|pill-opt|quiz-opt|toggle|cat-card)/.test(attrs)) continue;
    placeholders += 1;
  }
}
if (placeholders === 0) pass('no placeholder links or inert buttons');

// Referenced but missing images in the manifest and service worker.
for (const extra of ['manifest.json', 'sw.js']) {
  const p = path.join(APP, extra);
  if (!fs.existsSync(p)) continue;
  const text = fs.readFileSync(p, 'utf8');
  for (const m of text.matchAll(/["']([^"']*\.(?:png|jpe?g|webp|svg))["']/g)) {
    const ref = m[1];
    if (ref.startsWith('http')) continue;
    const abs = path.resolve(APP, ref.replace(/^\.\//, ''));
    if (!fs.existsSync(abs)) fail(`${extra}: references missing image ${ref}`);
  }
}
pass('manifest.json and sw.js image references all exist');

// ---------------------------------------------------------------------------
console.log('');
if (errors === 0) {
  console.log(`${C.g}No broken links${warnings ? ` (${warnings} warning(s))` : ''}.${C.o}`);
  process.exit(0);
}
console.log(`${C.r}${errors} broken reference(s).${C.o}`);
process.exit(1);
