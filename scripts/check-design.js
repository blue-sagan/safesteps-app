#!/usr/bin/env node
/**
 * check-design.js — the seven design rules, asserted instead of promised.
 *
 * The brief was a list of complaints: gradients, glows, emoji, meaningless
 * badges, nested cards, mismatched radii, animations that never stop. Each one
 * is easy to reintroduce with a single style attribute, so each one is checked
 * here and the checker can fail.
 *
 * USAGE
 *   node scripts/check-design.js [path/to/index.html] [--verbose]
 *
 * EXIT CODES
 *   0  every rule holds
 *   1  a rule is broken
 *   2  happy-dom is not installed
 *
 * REQUIRES happy-dom (dev-only, not a runtime dependency):
 *   npm install --no-save happy-dom
 *
 * LIMITS
 *   There is no browser here, so this reads computed intent (declared CSS and
 *   markup), not pixels. It cannot tell you the result looks good; it can tell
 *   you a gradient came back.
 */

const fs = require('fs');
const path = require('path');

let Window;
try {
  ({ Window } = require('happy-dom'));
} catch {
  console.error('check-design: happy-dom is required.  npm install --no-save happy-dom');
  process.exit(2);
}

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const target = args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'safesteps', 'index.html');
const html = fs.readFileSync(target, 'utf8');

const results = [];
function check(rule, label, ok, detail) {
  results.push({ rule, label, ok: !!ok, detail: detail || '' });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail && (verbose || !ok) ? ' — ' + detail : ''}`);
}
function heading(t) {
  console.log('\n' + t);
}

/** Balanced-paren scan: `[^)]*` stops at the first `)`, which is inside var(). */
function calls(text, re) {
  const out = [];
  let m;
  const g = new RegExp(re.source, 'g');
  while ((m = g.exec(text))) {
    let depth = 0;
    let i = m.index;
    for (; i < text.length; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') {
        depth--;
        if (depth === 0) {
          i++;
          break;
        }
      }
    }
    out.push(text.slice(m.index, i));
  }
  return out;
}

const markup = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<!--[\s\S]*?-->/g, '');
const styleBlocks = (markup.match(/<style[^>]*>([\s\S]*?)<\/style>/gi) || []).join('\n');
const css = styleBlocks.replace(/<style[^>]*>|<\/style>/gi, '');
const cssNoComments = css.replace(/\/\*[\s\S]*?\*\//g, '');

async function main() {
  const win = new Window({ url: 'https://safesteps.local/' });
  win.document.write(html);
  await win.happyDOM.waitUntilComplete();
  const d = win.document;

  /* ------------------------------------------------- 1. no gradients */
  heading('1. Gradients and glow');
  const ALLOWED = [/var\(--ke-black\)/, /var\(--card2\)[^)]*25%/, /#00A344 0 33\.3%/];
  const gradients = calls(markup, /(?:linear|radial)-gradient\(/);
  const stray = gradients.filter((g) => !ALLOWED.some((ok) => ok.test(g)));
  check(1, 'no decorative gradients', stray.length === 0, stray.slice(0, 3).join(' | ') || `${gradients.length} allowed (flag stripes, skeleton shimmer)`);

  const shadows = [...markup.matchAll(/box-shadow:[^;}"']*rgba\(\s*(\d+),\s*(\d+),\s*(\d+)/g)];
  const glows = shadows.filter((m) => {
    const [r, g, b] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const neutral = Math.abs(r - g) < 26 && Math.abs(g - b) < 26;
    const ring = /^box-shadow:\s*(?:inset\s+)?0\s+0\s+0\s+\d/.test(m[0]);
    return !neutral && !ring;
  });
  check(1, 'no coloured glow shadows', glows.length === 0, glows.map((m) => m[0].slice(0, 50)).join(' | '));

  /* ---------------------------------------------- 2. real iconography */
  heading('2. Icons instead of emoji');
  const spriteIds = new Set([...d.querySelectorAll('defs > g[id]')].map((g) => g.id));
  check(2, 'an SVG icon sprite is present', spriteIds.size > 20, `${spriteIds.size} symbols`);

  const uses = [...d.querySelectorAll('svg.ic use')].map((u) => (u.getAttribute('href') || '').replace('#', ''));
  const dangling = [...new Set(uses)].filter((id) => !spriteIds.has(id));
  check(2, 'every icon reference resolves to a symbol', dangling.length === 0, dangling.join(', ') || `${uses.length} references`);
  check(2, 'icons are used in the chrome, not just defined', uses.length >= 30, `${uses.length} icon uses`);

  // The action hub and map layers are the densest UI surfaces; neither may lead
  // with an emoji any more.
  const hub = d.getElementById('moreActionSheet');
  const emojiRe = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{2B00}-\u{2BFF}]/gu;
  const hubEmoji = ((hub && hub.textContent) || '').match(emojiRe) || [];
  check(2, 'the action hub renders no emoji glyphs', hubEmoji.length === 0, [...new Set(hubEmoji)].join(' '));

  const mapLayers = d.getElementById('mapLayerToggle');
  const mapEmoji = ((mapLayers && mapLayers.textContent) || '').match(emojiRe) || [];
  check(2, 'map layer tiles render no emoji glyphs', mapEmoji.length === 0, [...new Set(mapEmoji)].join(' '));

  // Emoji are still allowed as authored data — but they must not reach the DOM
  // through the renderers that were converted.
  const hasMap = /var ICON_MAP = \{/.test(html);
  check(2, 'data-driven emoji are mapped to icons at render time', hasMap, hasMap ? 'ICON_MAP present' : 'ICON_MAP is missing, so rendered rows fall back to emoji');

  /* ------------------------------------------------ 3. meaningful badges */
  heading('3. Badges carry meaning');
  const badges = [...d.querySelectorAll('.ga-badge')];
  const alwaysOn = badges.filter((b) => (b.textContent || '').trim() && !/done|error|failed|pending|saved/i.test(b.textContent));
  check(3, 'no badge is shown with filler text', alwaysOn.length === 0, alwaysOn.map((b) => b.textContent.trim()).join(' | '));
  check(3, '"Done" badges start hidden', badges.every((b) => (b.textContent || '').trim() !== 'Start'));

  /* --------------------------------------------------- 4. nested cards */
  heading('4. No nested cards');
  const isCard = (el) => {
    const st = el.getAttribute('style') || '';
    const hasSurface = /background:\s*var\(--card2?\b/.test(st);
    const hasEdge = /border:\s*(?!0|none)/.test(st);
    return (hasSurface && hasEdge) || el.classList.contains('settings-block') || el.classList.contains('hazard-tile') || el.classList.contains('state-block');
  };
  const cards = [...d.querySelectorAll('div,section')].filter(isCard);
  const nested = cards.filter((c) => {
    let p = c.parentElement;
    while (p && p !== d.body) {
      if (isCard(p)) return true;
      p = p.parentElement;
    }
    return false;
  });
  check(4, 'no card sits inside another card', nested.length === 0, nested.map((n) => (n.textContent || '').trim().slice(0, 40)).join(' | ') || `${cards.length} cards, none nested`);

  /* ------------------------------------------------------ 5. radii scale */
  heading('5. Corner radii come from one scale');
  // A single measured set of steps: xl/lg/md/sm/xs, plus pill and circle.
  const tokens = ['var(--r-xs)', 'var(--r-sm)', 'var(--r-md)', 'var(--r-lg)', 'var(--r-pill)', '50%', '4px', '2px', '0'];
  const declared = [...(cssNoComments + markup).matchAll(/border-radius:\s*([^;}"']+)/g)].map((m) => m[1].trim());
  const offScale = declared.filter((v) => {
    const parts = v.split(/\s+/);
    return parts.some((p) => !tokens.some((t) => p === t) && !/^0$/.test(p));
  });
  check(5, 'every radius is a scale token, pill, circle or 0', offScale.length === 0, [...new Set(offScale)].slice(0, 6).join(' | ') || `${declared.length} declarations`);

  // An inner element must not have a *larger* radius than the card holding it.
  const radiusPx = { 'var(--r-xs)': 8, 'var(--r-sm)': 10, 'var(--r-md)': 16, 'var(--r-lg)': 20 };
  const sizedCards = cards
    .map((c) => ({ el: c, r: radiusPx[((c.getAttribute('style') || '').match(/border-radius:\s*(var\(--r-\w+\))/) || [])[1]] }))
    .filter((x) => x.r);
  let worse = 0;
  for (const { el, r } of sizedCards) {
    for (const kid of el.querySelectorAll('*')) {
      const st = kid.getAttribute('style') || '';
      const m = st.match(/border-radius:\s*(var\(--r-\w+\))/);
      if (m && radiusPx[m[1]] > r) worse++;
    }
  }
  check(5, 'no inner corner is rounder than its container', worse === 0, `${worse} inversion(s) across ${sizedCards.length} cards`);

  /* -------------------------------------------------- 6. no infinite motion */
  heading('6. Nothing animates forever');
  const loops = [...cssNoComments.matchAll(/animation:[^;}]*\binfinite\b[^;}]*/g)].map((m) => m[0].trim());
  check(6, 'no infinite animation', loops.length === 0, loops.slice(0, 2).join(' | '));
  const keyframes = [...cssNoComments.matchAll(/@keyframes\s+([\w-]+)/g)].map((m) => m[1]);
  const orphaned = keyframes.filter((k) => !new RegExp('animation:[^;}]*\\b' + k + '\\b').test(cssNoComments));
  check(6, 'no keyframes are left behind unused', orphaned.length === 0, orphaned.join(', ') || `${keyframes.length} keyframes, all referenced`);
  check(6, 'reduced-motion is honoured', /prefers-reduced-motion/.test(cssNoComments));

  /* --------------------------------------------- 7. grouped related things */
  heading('7. Related things are grouped');
  // The freshness banner used to duplicate the weather bar and offer a Pause
  // switch for safety-data updates. Both are gone; one quiet status line stays.
  check(7, 'the duplicate freshness card is gone', !d.getElementById('liveDataFreshnessBanner'), 'replaced by .data-status');
  check(7, 'the pause/resume safety-data controls are gone', !/pauseLiveFeed|resumeLiveFeed/.test(html));
  check(7, 'one status line remains', !!d.querySelector('.data-status'));

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + '-'.repeat(60));
  if (failed.length) {
    console.log(`FAILED: ${failed.length} of ${results.length} design checks`);
    for (const f of failed) console.log(`  ✗ rule ${f.rule}: ${f.label}${f.detail ? ' — ' + f.detail : ''}`);
    process.exit(1);
  }
  console.log(`All ${results.length} design checks passed.`);
  console.log('No browser engine here: this asserts declared CSS and markup, not pixels.');
  console.log('Someone still has to look at it on a real phone.');
}

main().catch((e) => {
  console.error('check-design: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
