#!/usr/bin/env node
/**
 * check-requests.js — prove the app doesn't download the same file twice.
 *
 * "Prevent duplicate calls" is easy to claim and easy to lose: the lessons
 * loader set a `loaded` flag but never read it, so every visit to Learn
 * re-downloaded lessons.json, and opening Learn during start-up fetched it
 * twice concurrently. Nothing caught that, because a duplicate GET is invisible
 * in the UI — it just costs a phone on a metered connection money.
 *
 * This runs the page's real loaders in a DOM against a counting fetch stub and
 * asserts on the number of requests per file.
 *
 * USAGE
 *   node scripts/check-requests.js [path/to/index.html] [--verbose]
 *
 * EXIT CODES
 *   0  every dataset is fetched exactly once unless explicitly refreshed
 *   1  a loader re-fetched, or a retry/refresh did not actually fetch
 *   2  happy-dom is not installed
 *
 * REQUIRES happy-dom (dev-only, not a runtime dependency):
 *   npm install --no-save happy-dom
 */

const fs = require('fs');
const path = require('path');

let Window;
try {
  ({ Window } = require('happy-dom'));
} catch {
  console.error('check-requests: happy-dom is required.  npm install --no-save happy-dom');
  process.exit(2);
}

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const target = args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'safesteps', 'index.html');
const html = fs.readFileSync(target, 'utf8').replace(/<script[^>]+src="https?:[^"]+"[^>]*><\/script>/g, '');

function grab(src, name) {
  const re = new RegExp('\\n(?:async )?function ' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(src);
  if (!m) throw new Error('missing function ' + name);
  let i = m.index + m[0].length - 1;
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') {
      depth--;
      if (!depth) return src.slice(m.index, j + 1);
    }
  }
  throw new Error('unbalanced braces in ' + name);
}

const results = [];
function check(label, ok, detail) {
  results.push({ label, ok: !!ok, detail: detail || '' });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail && (verbose || !ok) ? ' — ' + detail : ''}`);
}

async function main() {
  const win = new Window({ url: 'https://safesteps.local/' });
  win.document.write(html);
  await win.happyDOM.waitUntilComplete();

  // Count every request by filename. The stub answers with plausible JSON so
  // the loaders take their success path.
  const calls = Object.create(null);
  win.fetch = async (url) => {
    const name = String(url).replace(/^\.?\//, '').split('?')[0];
    calls[name] = (calls[name] || 0) + 1;
    const bodies = {
      'data/lessons.json': { lessons: [{ id: 'l1', title: 'Look both ways', body: 'x', category: 'core' }] },
      'data/quiz.json': { categories: [{ key: 'k', label: 'K' }], questions: [{ q: 'q', options: ['a'], answer: 0, cat: 'k' }] },
      'data/signs.json': { signs: [{ txt: 'STOP', shape: 'octagon' }] },
      'data/accidents.json': { hotspots: [], lastUpdated: '2026-01-01' },
    };
    return {
      ok: true,
      status: 200,
      json: async () => JSON.parse(JSON.stringify(bodies[name] || {})),
      clone() { return this; },
      text: async () => '',
    };
  };

  // Side-effect stand-ins: nothing here should touch the DOM for real.
  win.eval('function announceToScreenReader(){} function showToast(){} function showErrorToast(){} function showSuccessToast(){}');
  win.eval("function escapeHtml(s){return String(s);}");
  win.eval('function renderLessons(){} function renderLessonsLoadError(){} function renderQuiz(){} function renderQuizCategories(){} function renderSigns(){} function renderQuizCategories(){}');
  win.eval('var state = {quizScore:0, reports:[], lessonsRead:{}, quizScores:{}}; function persist(){}');

  // State the loaders read/write. Declared in the page; redeclare here since we
  // only lift the functions themselves.
  win.eval('var lessonsDataMeta = {loaded:false, failed:false};');
  win.eval('var quizDataMeta = {loaded:false, failed:false};');
  win.eval('var signsDataMeta = {loaded:false, failed:false};');
  win.eval('var hotspotDataMeta = {loaded:false, failed:false, lastUpdated:null};');
  win.eval('var lessons = [], quizCategories = [], quizBank = [], signs = [], officialHotspots = [];');
  win.eval('var _inFlightGets = Object.create(null);');

  const LOADERS = ['dedupeGet', 'fetchSafetyJson', 'fetchSafetyJsonOnce', 'loadLessonsData', 'loadQuizData', 'loadSignsData', 'loadHotspotData'];
  const missing = [];
  for (const n of LOADERS) {
    try {
      win.eval(grab(html, n));
    } catch (e) {
      missing.push(n + ' (' + e.message + ')');
    }
  }
  console.log('Loaders under test');
  check('all data loaders parse', missing.length === 0, missing.join('; ') || LOADERS.length + ' loaders');

  const count = (f) => calls[f] || 0;
  const reset = () => Object.keys(calls).forEach((k) => delete calls[k]);

  // --- lessons: the bug this file exists for -------------------------------
  console.log('\nLessons (the one that re-downloaded every visit)');
  win.eval('loadLessonsData()');
  await new Promise((r) => setTimeout(r, 10));
  check('first visit downloads lessons.json', count('data/lessons.json') === 1, count('data/lessons.json') + ' request(s)');

  win.eval('loadLessonsData()'); // second visit to Learn
  await new Promise((r) => setTimeout(r, 10));
  check('second visit does not re-download it', count('data/lessons.json') === 1, count('data/lessons.json') + ' request(s)');

  win.eval('loadLessonsData()'); // third, for good measure
  await new Promise((r) => setTimeout(r, 10));
  check('and it stays at one across further visits', count('data/lessons.json') === 1, count('data/lessons.json') + ' request(s)');

  // Two concurrent calls (start-up warm-up + Learn opened immediately).
  reset();
  win.eval('lessonsDataMeta.loaded = false; lessonsDataMeta.failed = false;');
  win.eval('loadLessonsData(); loadLessonsData();');
  await new Promise((r) => setTimeout(r, 10));
  check('two concurrent loads fetch once', count('data/lessons.json') === 1, count('data/lessons.json') + ' request(s)');

  // Explicit refresh must still reach the network.
  win.eval('loadLessonsData(true)');
  await new Promise((r) => setTimeout(r, 10));
  check('an explicit refresh still fetches', count('data/lessons.json') === 2, count('data/lessons.json') + ' request(s)');

  // The deliberate behaviour, stated so it cannot silently drift: after a
  // failure the guard stops automatic retries on every screen open (that would
  // hammer a dead connection), and the visible "Try again" calls
  // loadLessonsData(true), which must reach the network.
  reset();
  win.eval('lessonsDataMeta.loaded = false; lessonsDataMeta.failed = true;');
  win.eval('loadLessonsData()');
  await new Promise((r) => setTimeout(r, 10));
  check('a failed load does not auto-retry on every screen open', count('data/lessons.json') === 0, count('data/lessons.json') + ' request(s) (Try again forces it)');
  win.eval('loadLessonsData(true)');
  await new Promise((r) => setTimeout(r, 10));
  check('the visible Try again does reach the network', count('data/lessons.json') === 1, count('data/lessons.json') + ' request(s)');

  // --- the loaders that already guarded correctly --------------------------
  console.log('\nQuiz, signs and hotspots (already guarded)');
  for (const [fn, file] of [
    ['loadQuizData', 'data/quiz.json'],
    ['loadSignsData', 'data/signs.json'],
    ['loadHotspotData', 'data/accidents.json'],
  ]) {
    reset();
    win.eval(`${fn}(); ${fn}(); ${fn}();`);
    await new Promise((r) => setTimeout(r, 10));
    check(`${file} fetched once across three calls`, count(file) === 1, count(file) + ' request(s)');
    // The start-up warm-up and an early tap on the screen both call these.
    reset();
    win.eval(`${fn}(); ${fn}(); ${fn}();`);
    await new Promise((r) => setTimeout(r, 10));
    check(`${file} not re-fetched after it finished either`, count(file) === 0, count(file) + ' request(s)');
  }

  // --- no loader hits an absolute third-party host ------------------------
  console.log('\nThird-party requests at start-up');
  const externalLoaders = ['fetchSafetyJson', 'loadLessonsData', 'loadQuizData', 'loadSignsData', 'loadHotspotData']
    .map((n) => grab(html, n))
    .join('\n');
  check('dataset loaders only use local paths', !/fetch\(\s*["'`]https?:/.test(externalLoaders));

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + '-'.repeat(60));
  if (failed.length) {
    console.log(`FAILED: ${failed.length} of ${results.length} request checks`);
    for (const f of failed) console.log('  ✗ ' + f.label + (f.detail ? ' — ' + f.detail : ''));
    console.log('\nA duplicate GET costs a phone on a metered connection real money.');
    process.exit(1);
  }
  console.log(`All ${results.length} request checks passed — no dataset is downloaded twice.`);
}

main().catch((err) => {
  console.error('check-requests: ' + (err && err.message ? err.message : err));
  process.exit(1);
});
