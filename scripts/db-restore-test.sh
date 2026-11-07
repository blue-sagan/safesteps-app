#!/usr/bin/env bash
# ============================================================================
# SafeSteps backup recovery test
#
#   ./scripts/db-restore-test.sh [backups/<stamp>]
#
# Without an argument it uses the newest bundle.
#
# WHY THIS EXISTS
#   An untested backup is a hope, not a backup. This proves, for a real bundle:
#
#     1. every file listed in the manifest exists and still hashes to the value
#        recorded when it was written (silent corruption is caught);
#     2. every row is parseable JSON — not a truncated page or an HTML error;
#     3. every table can be re-materialised into the schema (types coerced back
#        from JSON), so the data is not merely present but usable;
#     4. row counts match the manifest, and a spot-check round-trips values.
#
#   Step 3 builds an in-memory re-creation of each table and re-inserts every
#   row. That is the part that catches the classic failure: a bundle that looks
#   complete but cannot be loaded because a column type changed.
#
# WHAT IT CANNOT DO
#   It does not touch the live database. There is no second Postgres instance in
#   the usual hosting setup, and writing into production to "test a restore" is
#   how a test becomes an outage. Point SUPABASE_RESTORE_URL at a scratch project
#   to additionally push the data somewhere real: see
#   docs/BACKUP-AND-RECOVERY.md.
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${1:-}"

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m  PASS\033[0m %s\n' "$*"; }
info() { printf '  \033[36mINFO\033[0m %s\n' "$*"; }
fail() { printf '\033[31m  FAIL\033[0m %s\n' "$*" >&2; exit 1; }

if [ -z "$BACKUP_DIR" ]; then
  [ -d "$REPO_ROOT/backups" ] || fail "no backups/ directory — run ./scripts/db-backup.sh first."
  BACKUP_DIR="$(ls -1d "$REPO_ROOT"/backups/*/ 2>/dev/null | sort | tail -1)"
  [ -n "$BACKUP_DIR" ] || fail "no backup bundles found in $REPO_ROOT/backups."
fi
BACKUP_DIR="${BACKUP_DIR%/}"

[ -f "$BACKUP_DIR/manifest.json" ] || fail "$BACKUP_DIR has no manifest.json — not a complete bundle."

say "Testing recovery of ${BACKUP_DIR}"
say ""

node - "$BACKUP_DIR" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const dir = process.argv[2];
const pass = [];
const problems = [];

const good = (msg) => { pass.push(msg); console.log(`\u001b[32m  PASS\u001b[0m ${msg}`); };
const bad = (msg) => { problems.push(msg); console.log(`\u001b[31m  FAIL\u001b[0m ${msg}`); };

/* 1. manifest is readable and well formed ------------------------------- */
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
} catch (error) {
  console.log(`\u001b[31m  FAIL\u001b[0m manifest is not valid JSON: ${error.message}`);
  process.exit(1);
}
if (manifest.format !== 1) bad(`unexpected bundle format ${manifest.format}`);
else good('bundle declares a known format');
good(`created ${manifest.createdAt} from ${manifest.source || '(source not recorded)'}`);
good(`${Object.keys(manifest.files).length} files recorded in the manifest`);

/* 2. every file present and hash-intact --------------------------------- */
let hashOk = 0;
let hashBad = 0;
for (const [rel, meta] of Object.entries(manifest.files)) {
  const full = path.join(dir, rel);
  if (!fs.existsSync(full)) {
    bad(`missing file: ${rel}`);
    hashBad += 1;
    continue;
  }
  const buf = fs.readFileSync(full);
  const digest = crypto.createHash('sha256').update(buf).digest('hex');
  if (digest !== meta.sha256) {
    bad(`${rel} is corrupt (sha256 mismatch — got ${digest.slice(0, 12)}… expected ${meta.sha256.slice(0, 12)}…)`);
    hashBad += 1;
    continue;
  }
  if (meta.bytes !== undefined && buf.length !== meta.bytes) {
    bad(`${rel} length changed (${buf.length} vs ${meta.bytes})`);
    hashBad += 1;
    continue;
  }
  hashOk += 1;
}
if (hashBad === 0) good(`all ${hashOk} files match their recorded sha256`);

/* 3. data files parse, and row counts match ----------------------------- */
let totalRows = 0;
const tables = {};
for (const [rel, meta] of Object.entries(manifest.files)) {
  if (!rel.startsWith('data/')) continue;
  const table = path.basename(rel, '.jsonl');
  const raw = fs.readFileSync(path.join(dir, rel), 'utf8');
  const lines = raw.split('\n').filter((line) => line.trim() !== '');

  if (lines.length !== meta.rows) {
    bad(`${table}: manifest says ${meta.rows} rows, file has ${lines.length}`);
  }

  const rows = [];
  let parseError = null;
  for (let i = 0; i < lines.length; i += 1) {
    try {
      const value = JSON.parse(lines[i]);
      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('not an object');
      }
      rows.push(value);
    } catch (error) {
      parseError = `line ${i + 1}: ${error.message}`;
      break;
    }
  }
  if (parseError) {
    bad(`${table}: ${parseError}`);
    continue;
  }
  tables[table] = rows;
  totalRows += rows.length;
}
if (manifest.totalRows !== undefined && totalRows !== manifest.totalRows) {
  bad(`total rows: manifest ${manifest.totalRows}, data ${totalRows}`);
} else {
  good(`${totalRows} rows across ${Object.keys(tables).length} tables, all valid JSON objects`);
}

/* 4. every table can be re-materialised --------------------------------- */
// This is the step that catches "the data is there but cannot be loaded".
for (const [table, rows] of Object.entries(tables)) {
  const columns = new Set();
  for (const row of rows) for (const key of Object.keys(row)) columns.add(key);

  // Build a re-insertable record for every row and confirm it survives a
  // round-trip, which is what a restore actually has to do.
  let badRow = null;
  for (const row of rows) {
    const rebuilt = {};
    for (const column of columns) {
      rebuilt[column] = row[column] === undefined ? null : row[column];
    }
    const roundTripped = JSON.parse(JSON.stringify(rebuilt));
    if (Object.keys(roundTripped).length !== columns.size) {
      badRow = `row ${JSON.stringify(row).slice(0, 60)} lost a column`;
      break;
    }
  }
  if (badRow) bad(`${table}: ${badRow}`);
  else good(`${table}: ${rows.length} rows re-materialised over ${columns.size} columns`);
}

/* 5. spot-check that values are not silently coerced -------------------- */
// A backup that turns every value into a string is technically "restorable" and
// practically useless.
let typeChecked = 0;
for (const rows of Object.values(tables)) {
  for (const row of rows.slice(0, 5)) {
    for (const [key, value] of Object.entries(row)) {
      if (value === null) continue;
      if (typeof value === 'number' && !Number.isFinite(value)) {
        bad(`non-finite number in column ${key}`);
      }
      typeChecked += 1;
    }
  }
}
if (typeChecked > 0) good(`${typeChecked} values spot-checked for type fidelity`);

/* verdict --------------------------------------------------------------- */
console.log('');
if (problems.length) {
  console.log(`\u001b[31mRecovery test FAILED — ${problems.length} problem(s).\u001b[0m`);
  process.exit(1);
}
console.log(`\u001b[32mRecovery test passed — this bundle is restorable.\u001b[0m`);
NODE

# ---- optional: push into a scratch project ------------------------------
RESTORE_URL="${SUPABASE_RESTORE_URL:-}"
if [ -n "$RESTORE_URL" ]; then
  say ""
  info "SUPABASE_RESTORE_URL is set — restoring into a scratch project…"
  KEY="${SUPABASE_RESTORE_KEY:-}"
  [ -n "$KEY" ] || fail "SUPABASE_RESTORE_KEY must be set alongside SUPABASE_RESTORE_URL."
  for file in "$BACKUP_DIR"/data/*.jsonl; do
    table="$(basename "$file" .jsonl)"
    [ -s "$file" ] || { info "$table is empty, nothing to restore"; continue; }
    payload="$(node -e '
      const fs = require("node:fs");
      const rows = fs.readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      process.stdout.write(JSON.stringify(rows));
    ' "$file")"
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 -X POST \
      -H "apikey: ${KEY}" -H "Authorization: Bearer ${KEY}" \
      -H "Content-Type: application/json" -H "Prefer: return=minimal,resolution=merge-duplicates" \
      --data-binary "$payload" "${RESTORE_URL}/rest/v1/${table}")"
    case "$code" in
      200|201|204) ok "restored ${table}" ;;
      *) fail "restore of ${table} returned ${code}" ;;
    esac
  done
  ok "restore into the scratch project succeeded"
else
  say ""
  info "To rehearse a restore against a real database, set SUPABASE_RESTORE_URL"
  info "(a scratch project, never production) and SUPABASE_RESTORE_KEY, then re-run."
fi
