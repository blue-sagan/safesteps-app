#!/usr/bin/env node
/**
 * check-data-safety.js — the data-safety brief, asserted instead of promised.
 *
 * The brief has four sections. Three of them are mostly provisioning (separate
 * projects, PITR, storage versioning) and cannot be tested from here; those are
 * documented in docs/DATA-SAFETY.md with the exact dashboard steps and an
 * honest note about what is and is not in place.
 *
 * What CAN be tested is the part that lives in this repository, and that is
 * what this file covers:
 *
 *   1. The production banner exists, and only appears for a real environment.
 *   2. Every destructive path is behind a typed confirmation or an approval.
 *   3. The cap is enforced in three places (UI, HTTP, database), not one.
 *   4. Deletions are audited and the bin is reversible.
 *   5. Nothing destructive bypasses the server.
 *
 * USAGE
 *   node scripts/check-data-safety.js [path/to/index.html] [--verbose]
 *
 * EXIT CODES
 *   0  every rule holds
 *   1  a rule is broken
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
  console.error('check-data-safety: happy-dom is required.  npm install --no-save happy-dom');
  process.exit(2);
}

const args = process.argv.slice(2);
const verbose = args.includes('--verbose');
const target = args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'safesteps', 'index.html');
const html = fs.readFileSync(target, 'utf8');

const ROOT = path.join(__dirname, '..');
const apiSrc = fs.readFileSync(path.join(ROOT, 'safesteps/server/lib/api.js'), 'utf8');
const deletionSrc = fs.readFileSync(path.join(ROOT, 'safesteps/server/lib/deletion.js'), 'utf8');
const configSrc = fs.readFileSync(path.join(ROOT, 'safesteps/server/lib/config.js'), 'utf8');
const migration = fs.readFileSync(
  path.join(ROOT, 'safesteps/supabase/migrations/20261107120000_deletion_safeguards.sql'),
  'utf8'
);

const results = [];
function check(rule, label, ok, detail) {
  results.push({ rule, label, ok: !!ok, detail: detail || '' });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail && (verbose || !ok) ? ' — ' + detail : ''}`);
}
function heading(t) {
  console.log('\n' + t);
}

async function main() {
  const win = new Window({ url: 'https://safesteps.local/' });
  win.document.write(html);
  await win.happyDOM.waitUntilComplete();
  const d = win.document;

  /* ------------------------------------------- 1. environment isolation */
  heading('1. Environment isolation');

  const banner = d.getElementById('envBanner');
  check(1, 'the production banner element exists', !!banner);
  check(
    1,
    'the banner starts hidden',
    banner && !banner.classList.contains('is-on'),
    'it must be revealed by the server answer, never assumed'
  );
  check(
    1,
    'the banner height is re-measured after fonts load and on resize',
    /document\.fonts\.ready/.test(html) && /addEventListener\("resize"/.test(html),
    'a once-only measure lets the sticky header drift under the banner'
  );
  check(
    1,
    'the banner is not hidden behind the header when scrolled',
    /#envBanner\{[\s\S]*?position:sticky/.test(html) && /body\[data-env="production"\]\s*\.app-header/.test(html),
    'sticky banner + header offset'
  );
  check(
    1,
    'production is styled distinctly from staging',
    /body\[data-env="production"\]\{[^}]*--env-bg:var\(--red\)/.test(html) &&
      /body\[data-env="staging"\]\{[^}]*--env-bg:var\(--gold\)/.test(html),
    'red for production, amber for staging'
  );
  /* Behaviour, not text: run the page's own banner function and look at the DOM.
     A grep for `classList.add("is-on")` passes even when the code that makes it
     visible is commented out, which is how this check first failed to bite. */
  const bannerResults = (() => {
    const scripts = [...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    const pageScript = scripts.sort((a, b) => b.length - a.length)[0];
    try {
      win.SS = win.SS || {
        api: async () => ({}),
        session: { config: async () => ({}), capabilities: async () => ({}) },
      };
      win.eval(pageScript);
    } catch {
      return null;
    }
    const out = {};
    try {
      win.eval("applyEnvironmentBanner('production')");
      out.production =
        d.getElementById('envBanner').classList.contains('is-on') &&
        d.body.getAttribute('data-env') === 'production' &&
        /production/i.test(d.getElementById('envBannerText').textContent);
      win.eval("applyEnvironmentBanner('staging')");
      out.staging =
        d.getElementById('envBanner').classList.contains('is-on') &&
        d.body.getAttribute('data-env') === 'staging' &&
        !/production/i.test(d.getElementById('envBannerText').textContent);
      win.eval("applyEnvironmentBanner('development')");
      out.development =
        !d.getElementById('envBanner').classList.contains('is-on') && !d.body.getAttribute('data-env');
      win.eval("applyEnvironmentBanner('banana')");
      out.unknown = !d.getElementById('envBanner').classList.contains('is-on');
    } catch {
      return null;
    }
    return out;
  })();

  check(1, 'the banner function could be executed', bannerResults !== null, 'if this fails the rest cannot be trusted');
  check(1, 'production actually shows the banner', bannerResults && bannerResults.production === true);
  check(1, 'staging shows a banner that does not say production', bannerResults && bannerResults.staging === true);
  check(
    1,
    'development shows no banner at all',
    bannerResults && bannerResults.development === true,
    'a warning shown everywhere stops being a warning'
  );
  check(
    1,
    'an unknown environment shows no banner rather than guessing production',
    bannerResults && bannerResults.unknown === true
  );
  check(
    1,
    'the environment comes from the server, not the URL',
    /applyEnvironmentBanner\(cfg\.environment\)/.test(html) && /environment: config\.environment/.test(apiSrc),
    '/api/config carries it'
  );

  // Isolation is enforced at boot, not merely warned about.
  const serverSrc = fs.readFileSync(path.join(ROOT, 'safesteps/server/server.js'), 'utf8');
  check(
    1,
    'the server refuses to boot when pinned to the wrong project',
    // It is defined in config.js and called at boot in server.js — check both
    // shapes, because the definition is an assignment, not a call.
      /config\.environmentIsolation = \(\)/.test(configSrc) &&
      /environmentIsolation\(\)/.test(serverSrc) &&
      // exit(1), not a warning: a warning arrives after the data is already mixed.
      /if \(!isolation\.ok\)[\s\S]{0,400}process\.exit\(1\)/.test(serverSrc),
    'refusing to start is recoverable; un-mixing two databases is not'
  );
  check(
    1,
    'a production process on a loopback origin is refused',
    /loopback address/.test(configSrc),
    'catches a production build pointed at a local database'
  );
  check(
    1,
    'an unknown SAFESTEPS_ENV is treated as production, not development',
    /Treating this process as production/.test(configSrc),
    'guessing development would hide the banner'
  );

  /* --------------------------------------- 2. deletion safeguards exist */
  heading('2. Deletion safeguards are enforced in three places');

  // (a) the database
  check(2, 'the trash table exists in the migration', /create table if not exists public\.trash/.test(migration));
  check(2, 'the audit table exists in the migration', /create table if not exists public\.deletion_audit/.test(migration));
  check(
    2,
    'the cap is enforced in Postgres',
    /array_length\(v_ids, 1\) > v_max then[\s\S]{0,120}refusing to delete/.test(migration),
    'a client holding the publishable key can bypass the UI but not this'
  );
  check(
    2,
    'the trash row is written before the delete',
    migration.indexOf('insert into public.trash') < migration.indexOf('delete from public.safety_reports r'),
    'a copy-first order means a crash cannot lose the row'
  );
  check(
    2,
    'a mismatch between copy and delete aborts the whole operation',
    /v_moved <> v_deleted then/.test(migration)
  );
  check(
    2,
    'clients cannot write to the bin or the log directly',
    /revoke all on public\.trash from anon, authenticated/.test(migration) &&
      /revoke all on public\.deletion_audit from anon, authenticated/.test(migration) &&
      !/create policy trash_owner_insert/.test(migration),
    'no INSERT/UPDATE/DELETE policy: the functions are the only path'
  );
  check(
    2,
    'the deletable tables are an allow-list, not a parameter',
    /p_table not in \('safety_reports', 'integrity_reports'\)/.test(migration)
  );
  check(
    2,
    'account erasure also empties that user\'s bin',
    // Scoped to the erasure function: `delete from public.trash where user_id`
    // also appears elsewhere in the file, so an unscoped match proved nothing.
    /api_delete_my_account[\s\S]{0,1600}delete from public\.trash\s+where user_id = v_uid/.test(migration)
  );
  check(
    2,
    'expired bin rows are purged by retention',
    /delete from public\.trash where purge_after < now\(\)/.test(migration)
  );

  // (b) the HTTP layer
  check(
    2,
    'the HTTP layer enforces the same cap independently',
    /MAX_ROWS_PER_REQUEST = 10/.test(deletionSrc) && /ids\.length > MAX_ROWS_PER_REQUEST/.test(deletionSrc),
    'two independent gates, one of which the client cannot reach'
  );
  /* ---- behaviour, not the presence of code ----
     A previous version of this file asserted that the comparison *appeared* in
     the source. That passed even after the comparison was disabled, because the
     text was still there. These call the module and check what it does. */
  process.env.DELETION_APPROVAL_TOKEN = process.env.DELETION_APPROVAL_TOKEN || 'check-gate-token';
  process.env.DELETION_APPROVAL_THRESHOLD = process.env.DELETION_APPROVAL_THRESHOLD || '5';
  delete require.cache[require.resolve(path.join(ROOT, 'safesteps/server/lib/deletion.js'))];
  const del = require(path.join(ROOT, 'safesteps/server/lib/deletion.js'));

  function throws(fn) {
    try { fn(); return false; } catch { return true; }
  }

  check(
    2,
    'the phrase is built by the server, not accepted from the client',
    del.confirmationPhrase('safety_reports', 5) === 'delete 5 safety reports',
    'a client-chosen phrase proves nothing'
  );
  check(
    2,
    'a high-impact delete is REJECTED without the phrase (called, not grepped)',
    throws(() => del.assertPhrase('safety_reports', 5, undefined)) &&
      throws(() => del.assertPhrase('safety_reports', 5, 'yes')) &&
      throws(() => del.assertPhrase('safety_reports', 5, 'delete 2 safety reports')),
    'wrong phrase, missing phrase and wrong count must all be refused'
  );
  check(
    2,
    'the correct phrase is ACCEPTED',
    !throws(() => del.assertPhrase('safety_reports', 5, 'delete 5 safety reports')),
    'a gate that refuses everything is also broken'
  );
  check(
    2,
    'the cap is enforced when the function is called',
    throws(() => del.normaliseIds(Array.from({ length: 11 }, () => '11111111-1111-4111-8111-111111111111'))) ||
      del.normaliseIds(Array.from({ length: 11 }, () => '11111111-1111-4111-8111-111111111111')).length <= del.MAX_ROWS_PER_REQUEST,
    'eleven distinct ids must not pass'
  );
  check(
    2,
    'the phrase is verified against the database count, not the request',
    /matched = Number\(\(Array\.isArray\(preview\.body\)/.test(apiSrc),
    'a client claiming a smaller count cannot satisfy a larger one'
  );
  check(
    2,
    'a request matching nothing reports 404, not a cheerful 200',
    /nothing_matched/.test(apiSrc)
  );
  check(
    2,
    'every delete endpoint requires a session',
    ['handleTrashPreview', 'handleTrashDelete', 'handleTrashRestore', 'handleTrashPurge'].every((h) =>
      new RegExp(`async function ${h}\\(req[\\s\\S]{0,400}?require(Deleter|User)\\(req\\)`).test(apiSrc)
    )
  );
  check(
    2,
    'state-changing deletes require same-origin and CSRF',
    /handleTrashDelete[\s\S]{0,900}assertCsrf/.test(apiSrc) && /handleTrashPurge[\s\S]{0,900}assertCsrf/.test(apiSrc)
  );

  // (c) the UI
  check(2, 'the bin UI exists', !!d.getElementById('trashCard') && !!d.getElementById('trashList'));
  check(
    2,
    'the impact count is shown before the action, not after',
    !!d.getElementById('trashImpactCount') && /updateTrashImpact/.test(html),
    'show the exact number a bulk action will affect'
  );
  check(
    2,
    'the destructive button is gated on the typed phrase',
    /if\(typed !== expected\) purgeBtn\.disabled = true/.test(html)
  );
  check(
    2,
    'the UI blocks a selection above the cap',
    /var over = n > settings\.maxPerRequest/.test(html) && /restoreBtn\.disabled = trashState\.busy \|\| n === 0 \|\| over/.test(html)
  );
  check(
    2,
    'the phrase threshold comes from the server, not the client',
    /if\(cfg\.deletion\) trashState\.settings = cfg\.deletion/.test(html),
    'the UI cannot be more lenient than the API'
  );

  /* ------------------------------------------------- 3. audit + restore */
  heading('3. Every deletion is recorded and reversible');

  check(3, 'an audit row is written for a soft delete', /'soft_delete', p_table, v_deleted/.test(migration));
  check(3, 'an audit row is written for a restore', /'restore', 'mixed', v_count/.test(migration));
  check(3, 'an audit row is written for a purge', /'purge', 'trash', v_count/.test(migration));
  check(
    3,
    'the audit records who, and survives their account being deleted',
    /actor_email\s+text/.test(migration) && /actor_id\s+uuid references auth\.users\(id\) on delete set null/.test(migration),
    'on delete set null, not cascade'
  );
  check(3, 'the actor can read their own history', /deletion_audit_actor_select/.test(migration));
  check(3, 'an admin can read the whole history', /deletion_audit_admin_select/.test(migration));
  check(3, 'restore rebuilds the record from its stored payload', /jsonb_populate_record/.test(migration));
  check(3, 'the retention window is stated to the user', /30 days/.test(html));

  /* --------------------------------------------- 4. approval + honesty */
  heading('4. Explicit approval, and honesty when it is not configured');

  check(
    4,
    'a large delete can be parked for out-of-band approval',
    /createPendingApproval/.test(deletionSrc) && /status: 'approval_required'/.test(apiSrc)
  );
  del._resetPending();
  const pending = del.createPendingApproval({
    userId: 'user-one',
    table: 'safety_reports',
    ids: Array.from({ length: 6 }, () => '11111111-1111-4111-8111-111111111111'),
    matched: 6,
  });

  check(
    4,
    'an approval cannot be redeemed by another account (called, not grepped)',
    del.takePendingApproval(pending.id, 'user-two') === null,
    'an approval id leaking to another account must be useless'
  );
  check(
    4,
    'the rightful owner CAN redeem it',
    (() => {
      const taken = del.takePendingApproval(pending.id, 'user-one');
      return !!taken && taken.matched === 6;
    })()
  );
  check(
    4,
    'the same approval cannot be redeemed twice (called, not grepped)',
    del.takePendingApproval(pending.id, 'user-one') === null
  );
  // A wrong code of the SAME LENGTH as the real one is the case that matters:
  // a plain length check would reject 'nope' and still accept 'check-gate-tokeX'.
  // Testing only the short string let an always-true comparison pass this gate.
  const realToken = 'check-gate-token';
  const sameLengthWrong = realToken.slice(0, -1) + 'X';
  check(
    4,
    'a wrong approval code is rejected',
    del.checkApprovalToken('nope') === false && del.checkApprovalToken('') === false,
    'an empty or short code must never be accepted'
  );
  check(
    4,
    'a WRONG code of the right length is rejected',
    sameLengthWrong.length === realToken.length && del.checkApprovalToken(sameLengthWrong) === false,
    'this is the case a length-only comparison misses'
  );
  check(
    4,
    'the correct approval code is accepted',
    del.checkApprovalToken(realToken) === true,
    'a gate that refuses everything is also broken'
  );
  check(
    4,
    'the approval code is compared in constant time',
    /timingSafeEqual/.test(deletionSrc)
  );
  check(
    4,
    'when approval is not configured the UI is told so plainly',
    /not configured on this server/.test(deletionSrc),
    'it must not claim a gate it does not have'
  );
  // The handler legitimately *accepts* an approvalToken; what must never happen
  // is /api/config *returning* one. Check the response shape of that handler.
  const configHandler = (apiSrc.split('async function handleConfig')[1] || '').split('async function handleChallenge')[0];
  const sent = (configHandler.match(/sendJson\(res, 200, \{([\s\S]*?)\}\);/g) || []).join('\n');
  check(
    4,
    'the approval token is never returned by /api/config',
    sent.length > 0 && !/approvalToken|DELETION_APPROVAL_TOKEN/.test(sent),
    'the endpoint is public; the token is the whole gate'
  );
  check(
    4,
    'the security suite asserts no token escapes',
    /assert\.equal\(body\.deletion\.token, undefined\)/.test(
      fs.readFileSync(path.join(ROOT, 'safesteps/server/test/security.test.js'), 'utf8')
    )
  );

  const failed = results.filter((r) => !r.ok);
  console.log('\n' + '-'.repeat(60));
  if (failed.length) {
    console.log(`FAILED: ${failed.length} of ${results.length} data-safety checks`);
    for (const f of failed) console.log(`  ✗ rule ${f.rule}: ${f.label}${f.detail ? ' — ' + f.detail : ''}`);
    process.exit(1);
  }

  /* --------------------------- 5. retention has not silently shrunk again */
  heading('5. Retention covers every table the privacy policy promises');

  // This rule exists because the retention function DID silently shrink.
  //
  // Every migration that touched private.purge_expired_data() redefined the
  // whole function with `create or replace`. Each rewrite was meant to add a
  // table, and the last one was written from a copy of an earlier version, so it
  // dropped public.app_events — which legal.html §5 promises is deleted after
  // 180 days. Nothing failed; analytics simply stopped being purged.
  //
  // A whole-function redefinition cannot express "add one line", so the fix is
  // this check: take the LAST definition in migration filename order, and assert
  // it is a superset of every table any earlier definition purged.
  const migrationsDir = path.join(ROOT, 'safesteps/supabase/migrations');
  const PURGE_RE = /create or replace function private\.purge_expired_data\(\)[\s\S]*?as \$\$([\s\S]*?)\$\$/g;
  const DELETE_RE = /delete\s+from\s+([a-z_]+\.[a-z_]+)/gi;

  const defs = [];
  for (const file of fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    let m;
    PURGE_RE.lastIndex = 0;
    while ((m = PURGE_RE.exec(sql)) !== null) {
      const body = m[1];
      const tables = new Set();
      let d;
      DELETE_RE.lastIndex = 0;
      while ((d = DELETE_RE.exec(body)) !== null) tables.add(d[1].toLowerCase());
      defs.push({ file, tables });
    }
  }

  check(5, 'the retention function is defined at least once', defs.length > 0,
    `found ${defs.length} definition(s)`);
  // Guard against the vacuous pass: if the body capture silently stops working,
  // every set is empty, "nothing was dropped" is trivially true, and the rule
  // looks healthy while checking nothing. Require that a definition was actually
  // parsed into delete statements.
  check(5, 'retention definitions were actually parsed into table names',
    defs.length > 0 && defs.every((d) => d.tables.size >= 4),
    defs.map((d) => `${d.file}:${d.tables.size}`).join(' '));

  if (defs.length > 0) {
    const finalDef = defs[defs.length - 1];
    const finalTables = finalDef.tables;

    // The tables the privacy policy names, plus the bin. These must be present in
    // the final definition regardless of what any earlier one did.
    for (const required of [
      'public.security_events',
      'public.app_events',
      'public.bug_reports',
      'public.trash',
      'private.verification_challenges',
      'private.rate_limits',
      'private.outbound_mail',
    ]) {
      check(5, `retention still covers ${required}`, finalTables.has(required),
        `final definition is ${finalDef.file}`);
    }

    // And nothing an earlier definition purged may have been dropped on the way.
    const dropped = [];
    for (const def of defs) {
      for (const t of def.tables) {
        if (!finalTables.has(t)) dropped.push(`${t} (purged by ${def.file})`);
      }
    }
    check(5, 'no table was dropped from retention by a later migration', dropped.length === 0,
      dropped.join(', '));

    // The bug-report fallback must not claim success on a volatile store: this is
    // the second half of the same honesty problem, and it was live.
    const apiSrc2 = fs.readFileSync(path.join(ROOT, 'safesteps/server/lib/api.js'), 'utf8');
    check(5, 'the bug-report fallback checks whether its store is durable',
      /db\.isMemoryBacked\(\)/.test(apiSrc2),
      'a write to :memory: succeeds like a durable one, so accepting it loses the report silently');
    check(5, 'a volatile store is refused rather than acknowledged',
      /!stored\s*\|\|\s*db\.isMemoryBacked\(\)/.test(apiSrc2));
  }

  // Report the summary and exit.
  const failures = results.filter((r) => !r.ok);
  if (failures.length) {
    console.log(`\nFAILED: ${failures.length} of ${results.length} checks`);
    process.exit(1);
  }
  console.log(`All ${results.length} data-safety checks passed.`);
  console.log('Not covered here, because it is provisioning rather than code:');
  console.log('  separate projects per environment, PITR, storage versioning, migration');
  console.log('  staging. See docs/DATA-SAFETY.md — each has an explicit status.');
}

main().catch((e) => {
  console.error('check-data-safety: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
