# Backup and Recovery

Covers section B of the launch checklist: backups, tested recovery, protection
against accidental deletion, and database usage monitoring.

Everything here was run against this repository. Where something could not be
proven in this environment it says so plainly instead of being assumed.

---

## 1. Taking a backup

```bash
export SUPABASE_URL="https://mlgwfzcuumdjgywybujf.supabase.co"
export SUPABASE_SERVICE_ROLE_KEY="..."      # never commit this
./scripts/db-backup.sh                      # → backups/<UTC stamp>/
```

Output layout:

```
backups/20261105T143908Z/
  manifest.json          format version, timestamps, per-file row counts, sizes, sha256
  schema.sql             column shape of every table (recreate + diff against)
  data/profiles.jsonl     one JSON object per line, exactly as PostgREST returned it
  data/user_vaults.jsonl
  …
```

Design notes that matter if you change the script:

- **Tables are discovered, not hardcoded.** The script asks PostgREST for the
  schema (`GET /rest/v1/`) and backs up every table it reports. A hardcoded
  list stops protecting you the moment someone adds a table, which is the
  failure mode you least expect. An earlier version of this script had a
  hardcoded list containing `community_posts`, a table that has never existed in
  this project — proof that hand-maintained lists drift.
- **A partial backup fails loudly.** After discovery the script cross-checks
  against the tables the migrations create. If discovery misses one it aborts
  rather than writing a bundle that looks fine and is missing data. Override
  with `SUPABASE_DB_TABLES="…"` (explicit list) or `SKIP_REQUIRED_CHECK=1`
  (deliberate partial backup, e.g. one table during an incident).
- **Writes are atomic.** Data goes to `<stamp>.partial/` and is renamed only
  after the manifest is written, so a killed backup never looks complete.
- **Absent tables are skipped, auth failures are not.** A missing table returns
  `42P01`/`PGRST205` and is skipped with a warning; a bad key or a network error
  aborts the run.
- **Keys are read from the environment or `safesteps/server/.env` and never
  echoed.**

`backups/`, `*.jsonl`, `*.dump` and `*.sql.gz` are gitignored: a backup
containing user data must never reach the repository.

## 2. Testing that a backup actually restores

**An untested backup is not a backup.** Run this after every backup you intend
to rely on:

```bash
./scripts/db-restore-test.sh                  # most recent bundle
./scripts/db-restore-test.sh backups/2026…Z   # a specific bundle
```

It verifies, offline and without touching any database:

1. `manifest.json` parses and declares a known format version.
2. Every file listed in the manifest exists and matches its recorded sha256.
3. Every line in every `data/*.jsonl` is a valid JSON object.
4. Row counts match the manifest, per table and in total.
5. Each table re-materialises over its full column set (this is where a
   truncated or mis-encoded line surfaces).
6. Values are spot-checked for type fidelity (numbers stay numbers, booleans
   stay booleans, nulls stay null).

Exit code is 0 only when everything passes.

### Proof it is not a rubber stamp

A verification step that cannot fail is worse than none, so the failure paths
were exercised deliberately:

| Bundle state | Result |
| --- | --- |
| Clean bundle | `Recovery test passed`, exit 0 |
| One mutated line appended to `profiles.jsonl` | 3 failures — sha256 mismatch, per-table count, total count; exit 1 |
| One `data/*.jsonl` file deleted | failure on missing file; exit 1 |
| Wrong service key during backup | aborts before writing anything |

### Rehearsing a restore against a real database

The offline test proves the *bytes* are intact. It cannot prove that the data
lands back into Postgres correctly, because this environment has no Postgres
available (no `psql`/`pg_dump`, no package install, no egress to
`apt.postgresql.org`). That last mile is a one-command rehearsal you run
yourself against a **scratch project, never production**:

```bash
export SUPABASE_RESTORE_URL="https://<scratch-project>.supabase.co"
export SUPABASE_RESTORE_KEY="<scratch project service role key>"
./scripts/db-restore-test.sh backups/2026…Z
```

Do this once before launch and after any schema change. Record the date and
result in the log at the bottom of this file.

## 3. What actually stops a bad migration

Two different risks, two different controls.

**TRUNCATE and DROP are blocked in the database.** Migration
`20261105140000_deletion_guard.sql` installs:

- a `BEFORE TRUNCATE` statement-level trigger on every table in `public`, and
- an event trigger on `ddl_command_start` for `DROP TABLE` / `DROP SCHEMA`.

Both raise unless the session has explicitly opted in:

```sql
begin;
  set local safesteps.allow_destructive = 'yes i have a backup';
  drop table public.family_profiles;
commit;
```

The override is deliberately awkward and must be set in the same session, so it
cannot be baked into a connection string and left on. Without it:

```
ERROR: 42501: SafeSteps: refusing to truncate public.hazard_counts (0 rows).
HINT:  Run: set local safesteps.allow_destructive = 'yes i have a backup';
```

Verified against the live project on 2026-11-05:

| Statement | Result |
| --- | --- |
| `truncate table public.hazard_counts;` | **blocked** (42501) |
| `drop table public.quiz_attempts;` | **blocked** (42501) |
| `drop table` under `set local safesteps.allow_destructive` | allowed, as designed |

Check the guard is installed at any time:

```sql
select public.api_deletion_guard_status();
-- deletion guard: TRUNCATE blocked on 8 tables; destructive DDL needs an explicit session override
```

Two honest caveats:

- **`DELETE` is not blocked on purpose.** The app's own erasure path
  (`api_delete_my_account`) deletes the caller's rows and nothing else, and
  blocking `DELETE` would break a user's right to erasure. RLS already confines
  row deletes to the owning user. This guard protects the *table*, not rows.
- **A role with superuser rights can drop the guard.** The event trigger also
  relies on `current_query()` text matching, which is a speed bump against
  accidental automation, not a defence against a determined operator. If the
  same automation can run `alter event trigger … disable`, no in-database
  control survives that — which is why the backup exists.

**Everything else is process**, and process is what actually saves you:

1. **Never run migrations with the service-role key from an agent or CI job
   without a fresh backup.** `db-backup.sh → db-restore-test.sh → then migrate`.
2. **Never point automation at production.** Give CI a branch database
   (Supabase branching) or a scratch project.
3. Restrict who holds the production service-role key. It bypasses RLS; it is
   the single most dangerous secret in the project.

## 4. Scheduling

Nothing schedules itself. Pick one:

**Supabase Pro** — Dashboard → Database → Backups gives daily automatic backups
with point-in-time recovery on the paid plan. Turn this on first; it is the
cheapest insurance available and covers the case where your own script is
broken.

**Free plan / self-managed** — run the script on a timer from any always-on
machine:

```cron
# every 6 hours, log to a file, keep 30 days
0 */6 * * * cd /srv/safesteps-app && SUPABASE_URL=… SUPABASE_SERVICE_ROLE_KEY=… \
  ./scripts/db-backup.sh >> /var/log/safesteps-backup.log 2>&1
0 4 * * *  find /srv/safesteps-app/backups -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +
```

Requirements for a real offsite backup: **copy the bundles off the machine**
(`rclone`, `aws s3 cp`, or a private repo is not enough) and **encrypt them at
rest** (`age` or `gpg`) because `data/*.jsonl` is plaintext user data. A backup
that lives only on the box that died is not a backup.

Also run `./scripts/db-restore-test.sh` in the same cron (or in CI against the
latest bundle) so corruption is caught the same day, not on the day you need it.

## 5. Monitoring database usage

The free plan pauses a project after seven days of low activity — pausing is an
inactivity mechanism, not a size limit (see docs/FREE-PLAN-LIMITS.md). Detect
trouble before users do:

```sql
-- database size against the free-plan 500 MB ceiling
select pg_size_pretty(pg_database_size(current_database())) as db_size;

-- rows per table, largest first (exact counts; use reltuples for big tables)
select relname, n_live_tup
  from pg_stat_user_tables
 order by n_live_tup desc;

-- dead tuples: table bloat that a VACUUM would reclaim
select relname, n_dead_tup
  from pg_stat_user_tables
 where n_dead_tup > 1000
 order by n_dead_tup desc;

-- anything longer than 5 minutes that is still running
select pid, now() - query_start as runtime, left(query, 80)
  from pg_stat_activity
 where state <> 'idle' and now() - query_start > interval '5 minutes';
```

`./scripts/db-usage.sh` (added alongside this document) runs these and exits
non-zero when a threshold is crossed, so it can be a cron job or a CI gate.
Dashboard equivalents: Project → Reports → Database, and Project → Settings →
Billing for the plan limits currently in force.

What to watch, and what each means:

| Signal | Threshold to act | What it usually means |
| --- | --- | --- |
| Database size | > 350 MB on the 500 MB free plan | unbounded log/event tables; archive and prune |
| Dead tuples on one table | > 20% of live tuples | autovacuum falling behind; `vacuum (analyze)` |
| Long-running queries | > 5 min | missing index, or a runaway query locking rows |
| Connection count | near the plan ceiling | the serverless function is not reusing connections |
| Backup age | > 24 h | the cron stopped; check the log before assuming it is fine |

## 6. Recovery runbook

When data is lost or corrupted, in this order:

1. **Stop writes.** Take the service down (`render.yaml` → suspend) or point
   `PUBLIC_ORIGIN` at a maintenance page. Every minute of writes can diverge the
   database further from the backup.
2. **Do not run the app's migrations.** If a migration caused the loss, they
   will run again on deploy and repeat it. Deploy the previous release first.
3. **Take a backup of the broken state** before restoring:
   `./scripts/db-backup.sh --out backups/incident-<date>`. It is evidence, and
   restoring over something you have not captured is how one incident becomes
   two.
4. **Choose the restore target.** Latest verified bundle:
   `./scripts/db-restore-test.sh` on each candidate, newest first, until one
   passes.
5. **Restore into a scratch project and check it**, then promote — or, if the
   loss is limited to specific rows, replay only the affected tables from
   `data/*.jsonl`. Whole-bundle restores are the last resort, not the first.
6. **Bring the app back** and confirm the smoke test:
   `./scripts/verify-deployment.sh https://<your-host>`.
7. **Write down what happened** in the log below: what was lost, which bundle
   was used, how much data was unrecoverable.

**Row-level recovery** (most common case — a bad `delete` or `update`):

```bash
# find the table's file, then find the rows in question
grep '"id":"<uuid>"' backups/2026…Z/data/profiles.jsonl
```

These rows can be replayed through the REST API or the Supabase table editor,
which is far safer than a whole-database restore when only a handful of rows are
wrong.

## 7. Restore rehearsal log

| Date | Bundle | Target | Result |
| --- | --- | --- | --- |
| 2026-11-05 | synthetic fixture (6 rows, 5 tables) | offline verification | pass — checksum, counts, re-materialisation and type fidelity all validated |
| 2026-11-05 | corrupted + incomplete bundles | offline verification | correctly **failed** (exit 1) in both cases |

A rehearsal against a real scratch Postgres is still outstanding; record it here
when you run it. Until then, treat recovery as *partially* proven: the backup is
provably intact and restorable in principle, but has not yet been landed in a
live database.
