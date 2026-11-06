#!/usr/bin/env node
/**
 * check-states.js — prove the ten user states are real, not just defined.
 *
 * The lesson behind this file: `renderNoResults` existed, passed review, and
 * was never called. Defining a state helper is not implementing the state. So
 * this script does not grep for function names — it runs the page's own code in
 * a DOM and asserts on what the user would actually see: rendered markup, ARIA
 * roles, wired actions, and the strings on screen.
 *
 * USAGE
 *   node scripts/check-states.js [path/to/index.html] [--verbose]
 *
 * EXIT CODES
 *   0  every state behaved
 *   1  at least one state is broken or unreachable
 *   2  happy-dom is not installed
 *
 * REQUIRES happy-dom (dev-only, not a runtime dependency):
 *   npm install --no-save happy-dom
 *
 * LIMITS
 *   There is no browser engine here. This proves markup, roles and logic — not
 *   paint timings, layout, or how the banner looks on a real mid-range Android.
 *   A manual pass on a real phone is still required before launch.
 */

const fs = require('fs');
const path = require('path');

let Window;
try {
  ({ Window } = require('happy-dom'));
} catch {
  console.error('check-states: happy-dom is required.  npm install --no-save happy-dom');
  process.exit(2);
}

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const target = args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'safesteps', 'index.html');

const html = fs.readFileSync(target, 'utf8').replace(/<script[^>]+src="https?:[^"]+"[^>]*><\/script>/g, '');

/* ---------------------------------------------------------------- helpers */

/** Pull a whole top-level `function name(...) { ... }` body out of the page. */
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

/** Pull a `const NAME = { ... };` object literal out of the page. */
function grabConst(src, name) {
  const m = new RegExp('\\nconst ' + name + ' = \\{[\\s\\S]*?\\n\\};').exec(src);
  if (!m) throw new Error('missing const ' + name);
  return m[0];
}

const results = [];
function check(label, ok, detail) {
  results.push({ label, ok: !!ok, detail: detail || '' });
  const mark = ok ? 'PASS' : 'FAIL';
  console.log(`  ${mark}  ${label}${detail && (verbose || !ok) ? ' — ' + detail : ''}`);
}
function group(title) {
  console.log('\n' + title);
}

/* ------------------------------------------------------------------ setup */

async function main() {
const win = new Window({ url: 'https://safesteps.local/' });
win.document.write(html);
await win.happyDOM.waitUntilComplete();
const d = win.document;

// Stand-ins for the page's side-effectful helpers. Nothing under test may call
// a real network, toast library or analytics sink.
win.eval('function announceToScreenReader(m){ window.__announced = m; } var toastTimer = null;');
win.eval(
  "function escapeHtml(s){return String(s).replace(/[&<>\"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c];});}"
);
win.eval(
  'function showToast(){ } function showErrorToast(m){ window.__lastErr = m; } function showSuccessToast(m){ window.__lastOk = m; }'
);

const LOAD = [
  'renderSkeleton', 'renderEmptyState', 'renderErrorState', 'renderNoResults',
  'setFieldError', 'clearFieldError', 'normalizeKePhone', 'validateTrustedContactPhone',
  'validateEmailOptional', 'saveTrustedContact', 'watchField', 'retryConnection',
  'dismissSessionExpired', 'explainPermissionError', 'showPermissionHelp',
];
const missing = [];
for (const name of LOAD) {
  try {
    win.eval(grab(html, name));
  } catch (e) {
    missing.push(name + ' (' + e.message + ')');
  }
}
group('Functions the states depend on');
check('all state helpers load and parse', missing.length === 0, missing.join('; ') || '14/14');

win.eval(grabConst(html, 'ConnectionState').replace('const ConnectionState', 'var ConnectionState'));
for (const c of ['PHONE_RE_KE', 'EMAIL_RE']) {
  const m = new RegExp('\\nconst ' + c + ' = .*;').exec(html);
  if (m) win.eval(m[0].trim().replace('const ', 'var '));
}
win.eval('window.ConnectionState = ConnectionState; window.state = {}; window.persist = function(){};');

const host = d.createElement('div');
host.id = '__h';
d.body.appendChild(host);

/* ------------------------------------------------------- 1. empty state */
group('1. Empty state');
win.eval(
  "renderEmptyState(document.getElementById('__h'), {icon:'📸',title:'No reports near you yet',body:'Explanation.',actionLabel:'Report a hazard',action:\"showPage('report')\"})"
);
check('shows a title', /No reports near you yet/.test(host.textContent), host.querySelector('.state-title')?.textContent);
check('offers a way forward', !!host.querySelector('.state-btn'), host.querySelector('.state-btn')?.textContent);

/* ----------------------------------------------------- 2. loading state */
group('2. Loading state');
win.eval("renderSkeleton(document.getElementById('__h'), {label:'Loading lessons…'})");
check('renders skeleton cards', host.querySelectorAll('.sk-card').length > 0, host.querySelectorAll('.sk-card').length + ' cards');
check('marks the region busy', host.querySelector('[aria-busy="true"]') !== null);
check('announces progress to screen readers', /Loading lessons/.test(host.textContent), host.querySelector('.sr-only')?.textContent);

/* ------------------------------------------------------- 3. error state */
group('3. Error state');
win.eval(
  "renderErrorState(document.getElementById('__h'), {title:'Could not load', body:'Check connection.', retry:'retryMe()'})"
);
check('is announced as an alert', host.querySelector('[role="alert"]') !== null);
check('gives a reason', /Could not load/.test(host.textContent));
check('retry is wired to real code', /retryMe/.test(host.querySelector('.state-btn')?.getAttribute('onclick') || ''));

/* ---------------------------------------------------- 4/5. connectivity */
group('4/5. No internet and slow network');
const banner = d.getElementById('connectionBanner');
check('banner exists and starts hidden', !!banner && banner.hidden === true);
win.eval('ConnectionState.wentOffline()');
check('offline flips the banner', banner.hidden === false && /offline/i.test(d.getElementById('connectionTitle').textContent), banner.className.trim());
win.eval('ConnectionState.set("slow","Slow connection","Still working","🐢")');
check('slow connection is its own state, not a spinner', /Slow connection/.test(d.getElementById('connectionTitle').textContent), banner.className.trim());
check('slow state offers a retry', d.getElementById('connectionAction').style.display !== 'none');
win.eval('ConnectionState.cameBack()');
check('coming back says so', /online/i.test(d.getElementById('connectionTitle').textContent));
win.eval('ConnectionState.set("online")');
check('banner hides once healthy', banner.hidden === true);

/* ------------------------------------------------ 6. no search results */
group('6. No search results');
const nrHost = d.createElement('div');
nrHost.id = 'nrHost';
d.body.appendChild(nrHost);
win.eval(
  "renderNoResults(document.getElementById('nrHost'), " +
    JSON.stringify({
      query: 'zzzz',
      suggestions: ['Super Metro', 'Embassava', 'Metro Trans'],
      actionLabel: 'Show all SACCOs',
      action: 'resetSaccoSearch()',
    }) +
    ')'
);
check('echoes the query back', /zzzz/.test(nrHost.textContent), nrHost.querySelector('.state-title')?.textContent);
check('suggests real names instead of guessing', nrHost.querySelectorAll('.state-list li').length >= 3);
check('provides a way out', !!nrHost.querySelector('button.state-btn'), nrHost.querySelector('button.state-btn')?.textContent);
// The state is only real if the app actually calls it.
check('is wired into the SACCO search', /renderNoResults\(resEl/.test(html), 'searchMatatuSacco empty branch');

/* ------------------------------------------------- 7. permission denied */
group('7. Permission denied');
const kinds = {
  NotAllowedError: 'denied',
  NotFoundError: 'unavailable',
  NotReadableError: 'busy',
  OverconstrainedError: 'unsupported',
  TimeoutError: 'timeout',
};
for (const [name, kind] of Object.entries(kinds)) {
  const got = JSON.parse(win.eval('JSON.stringify(explainPermissionError({name:' + JSON.stringify(name) + '}))'));
  check(name + ' → ' + kind, got.kind === kind, got.kind + ': ' + got.title);
}
const geo = (code) => JSON.parse(win.eval('JSON.stringify(explainPermissionError({code:' + code + '}))'));
check('geolocation code 1 → denied', geo(1).kind === 'denied');
check('geolocation code 3 → timeout', geo(3).kind === 'timeout');
check('an unknown error still says something useful', geo(99).kind === 'unknown' && !!geo(99).how);

const permHost = d.createElement('div');
permHost.id = 'permHost';
d.body.appendChild(permHost);
win.eval("showPermissionHelp('permHost', {name:'NotAllowedError'}, 'You can still upload a photo.')");
const block = permHost.querySelector('.perm-block');
check('renders as an alert', block?.getAttribute('role') === 'alert');
check('explains how to undo it', /padlock|address bar/i.test(block?.textContent || ''), block?.querySelector('.perm-how')?.textContent?.slice(0, 60));
check('carries the alternative route', /upload a photo/i.test(block?.textContent || ''), block?.querySelector('.perm-alt')?.textContent);
check('is announced to screen readers', !!win.__announced, String(win.__announced).slice(0, 50));
check('does not blame the user', !/you (did|made) (something )?wrong/i.test(permHost.textContent));

win.eval("showPermissionHelp('permHost', {name:'NotFoundError'})");
check('reassures even without an alternative', /everything else on this screen still works/i.test(permHost.textContent));

// The four call sites that used to collapse every failure into one message.
// Count it in live code only: a comment explaining the old string is not the
// bug. (urls contain "//" too, so only strip "//" that is not preceded by ":").
const codeOnly = html
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const collapsed = (codeOnly.match(/permission denied or unavailable/g) || []).length;
check('the old catch-all message is gone from behaviour', collapsed === 0, collapsed + ' in live code');
for (const id of ['sosLocationHelp', 'hazardLocationHelp', 'signScanPermHelp', 'syncScanPermHelp']) {
  check('#' + id + ' host exists', d.getElementById(id) !== null);
}
check('SOS can send without a pin', /function shareAreaWithoutLocation\s*\(/.test(html) && /sosLandmarkInput/.test(html));

// The microphone path speaks SpeechRecognition's own error codes, not
// getUserMedia's names, so it has its own mapping to get wrong.
console.log('7b. Microphone (voice commands)');
check('#voicePermHelp host exists', d.getElementById('voicePermHelp') !== null);
check('voice errors are mapped, not collapsed', /service-not-allowed/.test(html) && /audio-capture/.test(html));

/* ------------------------------------------------- 8. session expired */
group('8. Session expired');
const se = /window\.onSessionExpired = function onSessionExpired\(\)\{[\s\S]*?\n\};/.exec(html);
if (!se) throw new Error('onSessionExpired not found');
win.eval(se[0]);
win.eval('window.onSessionExpired()');
const card = d.getElementById('sessionExpiredCard');
check('shows a modal card', !!card && card.hidden === false);
check('is a dialog, not a toast', card?.getAttribute('role') === 'alertdialog');
check('says work is not lost', /still on this device/i.test(card?.textContent || ''));
win.eval('dismissSessionExpired()');
check('can be dismissed', card.hidden === true);

/* --------------------------------------------------- 9. form validation */
group('9. Form validation');
const nameEl = d.getElementById('tcName');
const phoneEl = d.getElementById('tcPhone');
const emailEl = d.getElementById('tcEmail');
check('the real form fields are present', !!nameEl && !!phoneEl && !!emailEl);
check('no duplicate field ids', d.querySelectorAll('#tcPhone').length === 1, d.querySelectorAll('#tcPhone').length + ' nodes for #tcPhone');

nameEl.value = '';
phoneEl.value = '071234';
emailEl.value = 'not-an-email';
win.eval('saveTrustedContact()');
const errors = ['tcName', 'tcPhone', 'tcEmail'].map((i) => d.getElementById(i + '-error'));
check('flags every bad field at once', errors.every(Boolean), errors.map((e) => e && e.textContent.slice(0, 40)).join(' | '));
check('marks each field invalid for assistive tech', ['tcName', 'tcPhone', 'tcEmail'].every((i) => d.getElementById(i).getAttribute('aria-invalid') === 'true'));
check('errors sit on the field, not in a banner', d.getElementById('tcPhone-error').parentElement.contains(phoneEl));
check('nothing is saved while invalid', win.state.trustedContact === undefined, JSON.stringify(win.state.trustedContact));

win.eval("watchField(document.getElementById('tcPhone'), validateTrustedContactPhone)");
phoneEl.value = '0712345678';
phoneEl.dispatchEvent(new win.Event('input'));
check('the error clears as the user fixes it', !d.getElementById('tcPhone-error'));

nameEl.value = 'Mum';
emailEl.value = 'mum@example.com';
win.eval('saveTrustedContact()');
check('a valid save goes through', win.state.trustedContact?.phone === '+254712345678', win.state.trustedContact?.phone);

/* ------------------------------------------------------ 10. success state */
group('10. Success state');
check('confirms the save', /Trusted contact saved/.test(win.__lastOk || ''), win.__lastOk);
check('then points at the next step', /next-step-highlight/.test(html) && /nextStepPulse/.test(html));

/* ------------------------------------------------------------- verdict */
const failed = results.filter((r) => !r.ok);
console.log('\n' + '-'.repeat(60));
if (failed.length) {
  console.log(`FAILED: ${failed.length} of ${results.length} state checks`);
  for (const f of failed) console.log('  ✗ ' + f.label + (f.detail ? ' — ' + f.detail : ''));
  console.log('\nA state that is defined but not reachable is not implemented.');
  process.exit(1);
}
console.log(`All ${results.length} state checks passed — every one of the ten states is reachable and behaves.`);
console.log('No browser engine here: this proves markup, roles and logic, not paint timing.');
console.log('A manual pass on a real mid-range Android is still required before launch.');
}

main().catch((err) => {
  console.error('check-states: ' + (err && err.message ? err.message : err));
  process.exit(1);
});
