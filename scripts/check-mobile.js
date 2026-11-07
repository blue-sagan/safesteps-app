#!/usr/bin/env node
'use strict';
/**
 * check-mobile.js — layout audit across the phone sizes SafeSteps must survive.
 *
 * Section C: "test mobile compatibility across phone sizes".
 *
 * WHY THIS IS A STATIC/COMPUTED-STYLE CHECK
 * There is no browser engine available in this environment (no Chromium, no
 * Playwright browser binaries, and no egress to download them), so anything
 * claiming to be a real screenshot test here would be fiction. What this does
 * instead is catch the failures that actually break a layout on a small phone,
 * using CSS as parsed by the document itself:
 *
 *   1. Horizontal overflow  — a min-width, a fixed px width, or a long
 *      unbreakable string that cannot fit inside the narrowest viewport.
 *   2. Tap targets          — interactive elements smaller than 44x44 CSS px
 *      (WCAG 2.5.5 / Apple HIG), which on a phone is a mis-tap.
 *   3. Text size            — body copy below 12px, which phones render
 *      illegibly when the viewport is zoomed out.
 *   4. Fixed-position safety — full-bleed overlays must not run under the notch
 *      or the home indicator (safe-area insets).
 *   5. Viewport meta        — must allow scaling, or pinch-zoom is disabled.
 *
 * Exit code 1 on any ERROR, so it can gate CI.
 *
 * USAGE
 *   node scripts/check-mobile.js [path/to/index.html]
 *   node scripts/check-mobile.js --strict   # warnings also fail the run
 *
 * REQUIRES happy-dom (dev-only, not a runtime dependency):
 *   npm install --no-save happy-dom
 */

const fs = require('fs');
const path = require('path');

const DEVICES = [
  { name: 'iPhone SE (1st gen)', width: 320, height: 568, dpr: 2 },
  { name: 'iPhone SE (2/3)', width: 375, height: 667, dpr: 2 },
  { name: 'iPhone 12/13 mini', width: 375, height: 812, dpr: 3 },
  { name: 'iPhone 14/15', width: 390, height: 844, dpr: 3 },
  { name: 'iPhone 15 Pro Max', width: 430, height: 932, dpr: 3 },
  { name: 'Galaxy S8 (narrow)', width: 360, height: 740, dpr: 4 },
  { name: 'Pixel 7', width: 412, height: 915, dpr: 2.6 },
  { name: 'Foldable closed', width: 344, height: 882, dpr: 3 },
];

const MIN_TAP = 44;
const MIN_FONT = 12;

const args = process.argv.slice(2);
const strict = args.includes('--strict');
const target = args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'safesteps', 'index.html');

let Window;
try {
  ({ Window } = require('happy-dom'));
} catch {
  console.error('check-mobile: happy-dom is required.  npm install --no-save happy-dom');
  process.exit(2);
}

const DOCUMENTS = [
  { name: 'app shell', file: 'index.html' },
  { name: 'legal', file: 'legal.html' },
  { name: '404', file: '404.html' },
];

// Pick the documents to audit: an explicit path audits only that file, otherwise
// every HTML page the app serves. "Every page is mobile optimised" is only true
// if it was checked for every page — legal.html and 404.html were never audited.
const explicit = args.find((a) => !a.startsWith('--'));
const rootDir = path.join(__dirname, '..', 'safesteps');
const docsToCheck = explicit
  ? [{ name: path.basename(explicit), file: path.basename(explicit), abs: path.resolve(explicit) }]
  : DOCUMENTS
      .map((d) => ({ ...d, abs: path.join(rootDir, d.file) }))
      .filter((d) => fs.existsSync(d.abs));

const errors = [];
const warnings = [];
const notes = [];

let currentScreen = 'page';
let currentDoc = 'index.html';
function err(device, msg) { errors.push({ doc: currentDoc, device, msg, screen: currentScreen }); }
function warn(device, msg) { warnings.push({ doc: currentDoc, device, msg, screen: currentScreen }); }

// ---------------------------------------------------------------------------
// 0. Static checks that do not need a layout engine
// ---------------------------------------------------------------------------
function staticChecks(html) {
  const viewport = html.match(/<meta[^>]+name=["']viewport["'][^>]*>/i);
  if (!viewport) {
    err('all', 'no <meta name="viewport"> — the page renders at 980px on every phone');
  } else {
    const content = viewport[0];
    if (/user-scalable\s*=\s*no/i.test(content)) err('all', 'viewport disables pinch-zoom (user-scalable=no)');
    if (/maximum-scale\s*=\s*1(\.0)?["'\s>]/i.test(content)) warn('all', 'viewport caps zoom at 1.0 (maximum-scale=1)');
    if (!/width\s*=\s*device-width/i.test(content)) err('all', 'viewport does not set width=device-width');
    notes.push(`${currentDoc} viewport: ${content.replace(/\s+/g, ' ')}`);
  }

  // Any declaration that forces a minimum width wider than the narrowest phone
  // will overflow no matter what the parent is.
  const minWidths = [...html.matchAll(/min-width\s*:\s*(\d+)px/gi)].map((m) => +m[1]).filter((n) => n > 0);
  for (const mw of new Set(minWidths)) {
    if (mw > 320) err('all', `min-width:${mw}px cannot fit a 320px viewport (iPhone SE 1st gen)`);
    else if (mw > 300) warn('all', `min-width:${mw}px leaves only ${320 - mw}px on a 320px screen`);
  }

  // Grid/flex tracks with fixed px columns that sum past the narrowest screen.
  const gridTracks = [...html.matchAll(/grid-template-columns\s*:\s*([^;"]+)/gi)].map((m) => m[1]);
  for (const t of gridTracks) {
    const px = [...t.matchAll(/(\d+)px/g)].map((m) => +m[1]);
    const sum = px.reduce((a, b) => a + b, 0);
    if (px.length > 1 && sum > 320) err('all', `grid-template-columns "${t.trim()}" needs ${sum}px, wider than a 320px screen`);
  }

  // Safe-area awareness for anything pinned to an edge.
  if (/position\s*:\s*fixed/i.test(html) && !/env\(safe-area-inset/i.test(html)) {
    warn('all', 'fixed-position elements exist but no env(safe-area-inset-*) is used — content can sit under the notch/home bar');
  }

  // Text inputs below 16px trigger an automatic zoom on iOS that never zooms back.
  // Scan ONLY the <style> blocks: an earlier version ran this over the whole file
  // and matched a JavaScript line (`input.value = ""; ... {`), inventing a CSS
  // rule that did not exist. A checker that reports phantom problems gets ignored,
  // which is worse than not having it.
  const cssText = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1]).join('\n');
  const inputRules = [...cssText.matchAll(/([^{}]*\b(?:input|textarea|select)\b[^{}]*)\{([^}]*)\}/gi)];
  const inputFontSizes = [];
  for (const [, sel, body] of inputRules) {
    const m = body.match(/font-size\s*:\s*([\d.]+)px/i);
    if (m && !/type\s*=\s*["']?checkbox/i.test(sel)) inputFontSizes.push(+m[1]);
  }
  // Inline style attributes on inputs bypass the stylesheet, so check them too.
  for (const m of html.matchAll(/<(?:input|textarea|select)\b[^>]*style="[^"]*font-size\s*:\s*([\d.]+)px[^"]*"/gi)) {
    inputFontSizes.push(+m[1]);
  }
  const tinyInputs = inputFontSizes.filter((n) => n < 16);
  if (tinyInputs.length) {
    warn('all', `${tinyInputs.length} input rule(s) set font-size below 16px (${[...new Set(tinyInputs)].join(', ')}) — iOS zooms the page on focus and does not zoom back`);
  }

  // The document itself must not be allowed to scroll sideways. Without this a
  // single over-wide child silently gives the whole page a horizontal scrollbar.
  // Only count a real declaration, not a selector or media condition.
  const hasClip = /(?:^|[}{])\s*(?:[^{}@]*,\s*)?(?:html|body)\b[^{}]*\{[^}]*overflow-x\s*:\s*(?:clip|hidden)/i.test(cssText)
    || /\*\s*\{[^}]*overflow-x\s*:\s*(?:clip|hidden)/i.test(cssText);
  if (!hasClip) {
    warn('all', 'no overflow-x guard on html/body — one over-wide child gives the page a horizontal scrollbar');
  }

  // Images without a max-width can be wider than the phone.
  if (/<img\b/i.test(html) && !/(?:^|[},;\s])img\b[^{}@]*\{[^}]*max-width\s*:\s*100%/i.test(cssText)) {
    warn('all', 'images are not constrained with max-width:100% — a large image overflows the screen');
  }
}

// ---------------------------------------------------------------------------
// 1. Per-device computed-style walk
// ---------------------------------------------------------------------------
function walk(window, device, screen) {
  currentScreen = screen || 'page';
  const doc = window.document;
  const body = doc.body;
  const vw = device.width;

  // Compute every element's style ONCE and keep it. Getting a computed style is
  // cheap individually but the ancestor walk below multiplies it by nesting
  // depth, and an earlier version of this script exhausted the heap doing that
  // 33 screens x 8 devices over. One pass, then look up.
  const all = [...doc.querySelectorAll('*')].filter(
    (el) => !['SCRIPT', 'STYLE', 'META', 'LINK', 'HEAD', 'TITLE', 'NOSCRIPT'].includes(el.tagName)
  );
  const styles = new Map();
  for (const el of all) styles.set(el, window.getComputedStyle(el));

  // An element is rendered only if no ancestor is display:none. Propagate that
  // down the tree in a single walk instead of re-walking ancestors per element.
  const hidden = new Map();
  const isHidden = (el) => {
    if (hidden.has(el)) return hidden.get(el);
    const st = styles.get(el);
    const self = st && st.display === 'none';
    const parent = el.parentElement && el.parentElement !== body ? isHidden(el.parentElement) : false;
    const val = self || parent;
    hidden.set(el, val);
    return val;
  };

  let widestEl = { tag: '', width: 0, cls: '' };

  for (const el of all) {
    if (isHidden(el)) continue;
    const st = styles.get(el);
    if (!st) continue;
    const cls = el.className && typeof el.className === 'string' ? el.className : '';
    const label = `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${cls ? '.' + cls.trim().split(/\s+/).join('.') : ''}`;

    // --- fixed widths that cannot shrink ---
    const w = st.width;
    if (w && /^\d+(\.\d+)?px$/.test(w)) {
      const px = parseFloat(w);
      const noMax = !st.maxWidth || st.maxWidth === 'none' || parseFloat(st.maxWidth) >= px;
      if (px > vw && noMax) {
        err(device.name, `${label} is ${px}px wide with no max-width — overflows a ${vw}px screen`);
      }
      if (px > widestEl.width) widestEl = { tag: label, width: px, cls };
    }

    // --- explicit box wider than the screen ---
    const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
    if (rect && rect.width > vw + 1) {
      const noMax = !st.maxWidth || st.maxWidth === 'none';
      if (noMax) err(device.name, `${label} lays out at ${Math.round(rect.width)}px on a ${vw}px screen`);
    }

    // --- tap targets ---
    const interactive = ['BUTTON', 'A', 'INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName) ||
      st.cursor === 'pointer' || typeof el.onclick === 'function' ||
      el.getAttribute('role') === 'button';
    if (interactive && !String(st.display).startsWith('inline')) {
      const h = parseFloat(st.height);
      const wpx = parseFloat(st.width);
      const hh = rect && rect.height ? rect.height : NaN;
      const ww = rect && rect.width ? rect.width : NaN;
      const effH = !Number.isNaN(hh) && hh > 0 ? hh : h;
      const effW = !Number.isNaN(ww) && ww > 0 ? ww : wpx;
      const isInlineLink = el.tagName === 'A' && String(st.display).startsWith('inline') && !cls;
      if (!isInlineLink && Number.isFinite(effH) && Number.isFinite(effW) && effH > 0 && effW > 0) {
        if (effH < MIN_TAP - 0.5 || effW < MIN_TAP - 0.5) {
          warn(device.name, `tap target ${label} is ${effW.toFixed(0)}x${effH.toFixed(0)}px (minimum ${MIN_TAP}x${MIN_TAP})`);
        }
      }
    }

    // --- font size ---
    if (['P', 'SPAN', 'DIV', 'LI', 'SMALL', 'BUTTON', 'A', 'LABEL', 'TD'].includes(el.tagName)) {
      const fs_ = parseFloat(st.fontSize);
      if (Number.isFinite(fs_) && fs_ > 0 && fs_ < MIN_FONT) {
        const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
        if (own) warn(device.name, `text in ${label} is ${fs_}px (below ${MIN_FONT}px)`);
      }
    }
  }

  // --- document-level overflow ---
  const docWidth = Math.max(body.scrollWidth || 0, doc.documentElement.scrollWidth || 0, body.offsetWidth || 0);
  if (docWidth > vw + 1) {
    err(device.name, `document scrollWidth is ${docWidth}px on a ${vw}px viewport — page scrolls sideways`);
  }

  if (widestEl.width > device.width * 0.8) {
    notes.push(`${device.name} · ${screen}: widest element is ${widestEl.tag} at ${widestEl.width}px (${Math.round((widestEl.width / device.width) * 100)}% of the screen)`);
  }
}

// ---------------------------------------------------------------------------
// 2. Run every device, for every screen
// ---------------------------------------------------------------------------
// Only one screen is visible at a time (`.page{display:none}`, `.page.active`
// shows). Auditing just the default view therefore says nothing about the other
// 32 — and the pages are exactly where a dense table or a long route name will
// overflow. Each screen is activated in turn and measured on its own.
function screensOf(doc) {
  const pages = [...doc.querySelectorAll('section.page')].map((el) => ({ kind: 'page', el }));
  const others = [...doc.querySelectorAll('.screen')].map((el) => ({ kind: 'screen', el }));
  return [...pages, ...others];
}

let screenCount = 0;
const perDoc = [];

for (const doc_ of docsToCheck) {
  const html = fs.readFileSync(doc_.abs, 'utf8');
  currentDoc = doc_.file;

  // Static pass for this document.
  currentScreen = 'page';
  staticChecks(html);

  // A document with no screens (a flat legal page, the 404) still needs the
  // document-level overflow check, so it is audited as a single screen.
  const declaredScreens = (html.match(/<section\b[^>]*class="[^"]*\bpage\b/gi) || []).length
    + (html.match(/<div\b[^>]*class="[^"]*\bscreen\b/gi) || []).length;
  const docScreens = declaredScreens || 1;

  for (const device of DEVICES) {
    const window = new Window({ width: device.width, height: device.height, url: 'https://safesteps.local/' });
    window.document.write(html);
    window.document.close();
    try {
      const doc = window.document;
      const screens = screensOf(doc);
      if (screens.length) screenCount = screens.length;

      if (!screens.length) {
        // Flat document: one audit pass over the whole page.
        currentScreen = doc_.file;
        try {
          walk(window, device, doc_.file);
        } catch (e) {
          err(device.name, `audit crashed: ${e.message}`);
        }
        continue;
      }

      // Normalise the starting state first: the HTML ships one page with
      // class="active" already, so without this the first audit screen and the
      // markup's default page are both visible and findings get mis-attributed.
      for (const s of screens) {
        if (s.kind === 'page') s.el.classList.remove('active');
        else s.el.style.display = 'none';
      }

      let prev = null;
      for (const { el } of screens) {
        const label = el.id || (typeof el.className === 'string' ? el.className : '') || el.tagName.toLowerCase();
        const isPage = el.tagName === 'SECTION' && el.classList.contains('page');

        // Show this one, hide the others, exactly as the router does. Only the
        // previous screen and this one are touched: each style mutation
        // invalidates the computed-style cache, so toggling all 33 per screen made
        // the run quadratic and ran the heap out of memory.
        if (prev) {
          if (prev.kind === 'page') prev.el.classList.remove('active');
          else prev.el.style.display = 'none';
        }
        if (isPage) el.classList.add('active');
        else el.style.display = 'flex';
        prev = { kind: isPage ? 'page' : 'screen', el };

        currentScreen = label;
        try {
          walk(window, device, label);
        } catch (e) {
          err(device.name, `audit of ${label} crashed: ${e.message}`);
        }
      }
    } catch (e) {
      err(device.name, `audit crashed: ${e.message}`);
    } finally {
      window.happyDOM?.cancelAsync?.();
    }
  }
  perDoc.push({ file: doc_.file, screens: docScreens });
}

// ---------------------------------------------------------------------------
// 3. Report
// ---------------------------------------------------------------------------
const C = process.stdout.isTTY
  ? { r: '\u001b[31m', y: '\u001b[33m', g: '\u001b[32m', c: '\u001b[36m', d: '\u001b[2m', o: '\u001b[0m' }
  : { r: '', y: '', g: '', c: '', d: '', o: '' };

console.log(`${C.c}SafeSteps mobile layout audit${C.o}`);
for (const d of perDoc) {
  console.log(`${C.d}${d.file.padEnd(12)} ${d.screens} screen${d.screens === 1 ? '' : 's'}${C.o}`);
}
console.log(`${C.d}${DEVICES.length} viewports (${DEVICES.map((d) => d.width).join(', ')}px) across ${perDoc.length} document(s)${C.o}\n`);

for (const n of notes) console.log(`  ${C.d}·${C.o} ${n}`);

// Collapse the same finding repeated on every device into one line.
function summarize(list) {
  const map = new Map();
  for (const { doc, device, msg, screen } of list) {
    if (!map.has(msg)) map.set(msg, { devices: new Set(), screens: new Set(), docs: new Set(), msg });
    map.get(msg).devices.add(device);
    if (screen) map.get(msg).screens.add(screen);
    if (doc) map.get(msg).docs.add(doc);
  }
  return [...map.values()].sort((a, b) => b.devices.size - a.devices.size);
}

const errs = summarize(errors);
const warns = summarize(warnings);

if (errs.length) {
  console.log(`\n${C.r}Errors${C.o} (these break the layout)`);
  for (const e of errs) {
    const d = e.devices.size >= DEVICES.length ? 'all sizes' : [...e.devices].join(', ');
    const where = e.screens.size && e.screens.size < 6 ? ' in ' + [...e.screens].join(', ') : '';
    console.log(`  ${C.r}FAIL${C.o} ${e.msg}\n       ${C.d}[${[...e.docs].join(', ')}] ${d}${where}${C.o}`);
  }
}

if (warns.length) {
  console.log(`\n${C.y}Warnings${C.o} (usability, not breakage)`);
  for (const w of warns) {
    const d = w.devices.size >= DEVICES.length ? 'all sizes' : [...w.devices].join(', ');
    const where = w.screens.size && w.screens.size < 6 ? ' in ' + [...w.screens].join(', ') : '';
    console.log(`  ${C.y}WARN${C.o} ${w.msg}\n       ${C.d}[${[...w.docs].join(', ')}] ${d}${where}${C.o}`);
  }
}

console.log('');
if (errs.length === 0 && (!strict || warns.length === 0)) {
  console.log(`${C.g}Layout is safe on every tested phone size.${C.o}`);
  console.log(`${C.d}Not a substitute for a real device: this checks computed CSS and constraints, not pixels.${C.o}`);
  process.exit(0);
}

console.log(`${C.r}${errs.length} error(s), ${warns.length} warning(s).${C.o}`);
process.exit(1);
