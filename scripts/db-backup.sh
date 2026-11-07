#!/usr/bin/env bash
# ============================================================================
# SafeSteps database backup
#
#   ./scripts/db-backup.sh                 # snapshot into ./backups (git-ignored)
#   ./scripts/db-backup.sh --out DIR       # snapshot somewhere else
#
# WHAT IT DOES
#   Reads the public schema over the REST API (PostgREST) using a service-role
#   key, and writes a restorable bundle:
#
#     backups/<timestamp>/schema.sql     table + column + constraint shape
#     backups/<timestamp>/data/*.jsonl   one JSON object per line, per table
#     backups/<timestamp>/manifest.json  row counts, sha256 per file, timestamp
#
#   PostgREST is used instead of pg_dump on purpose: it is the connection the
#   app already trusts, it needs no direct Postgres port (which Supabase does not
#   expose on the free plan), and it cannot touch anything outside the exposed
#   schema. The trade-off is documented in SECURITY.md: this captures *data*, not
#   functions, indexes or RLS policies. Those live in
#   safesteps/supabase/migrations/ under version control, which is the right
#   home for them — restoring code from a database dump is how migrations rot.
#
#   Private tables (private.*) are NOT readable through PostgREST by design, so
#   they are absent here. They hold in-flight verification challenges and the
#   mail spool: both are short-lived, and both are rebuilt by the server.
#
# SAFETY
#   • Refuses to overwrite an existing directory.
#   • Writes to a temporary name and renames at the end, so an interrupted run
#     never leaves a bundle that looks complete.
#   • The service-role key is read from the environment or server/.env, is never
#     echoed, and never lands in the output.
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${REPO_ROOT}/backups"
ENV_FILE="${SAFESTEPS_ENV_FILE:-$REPO_ROOT/safesteps/server/.env}"

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_ROOT="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m  OK\033[0m %s\n' "$*"; }
fail() { printf '\033[31m  FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# ---- credentials (never echoed) -------------------------------------------
env_value() { [ -f "$ENV_FILE" ] || return 1; sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }

SUPABASE_URL="${SUPABASE_URL:-$(env_value SUPABASE_URL || true)}"
KEY="${SUPABASE_SERVICE_ROLE_KEY:-$(env_value SUPABASE_SERVICE_ROLE_KEY || true)}"

[ -n "${SUPABASE_URL:-}" ] || fail "SUPABASE_URL is not set (env or $ENV_FILE)."
[ -n "${KEY:-}" ] || fail "SUPABASE_SERVICE_ROLE_KEY is not set — a backup needs read access to every table."

command -v curl >/dev/null || fail "curl is required."
command -v node >/dev/null || fail "node is required."

# Tables are DISCOVERED from the live schema rather than hardcoded. A hardcoded
# list silently stops protecting you the moment someone adds a table — and a
# phantom name in it (community_posts) sent the first run looking for a table
# that has never existed. Discovery asks the database what it actually holds.
TABLES=""
if [ -n "${SUPABASE_DB_TABLES:-}" ]; then
  TABLES="$SUPABASE_DB_TABLES"   # explicit override, useful for tests
else
  TABLES="$(curl -sS --max-time 45 \
    -H "apikey: ${KEY}" -H "Authorization: Bearer ${KEY}" \
    -H "Accept: application/json" \
    "${SUPABASE_URL}/rest/v1/?select=*" 2>/dev/null \
    | node -e '
      let raw = ""; process.stdin.on("data", c => raw += c); process.stdin.on("end", () => {
        try {
          const spec = JSON.parse(raw);
          const defs = (spec && spec.definitions) || (spec && spec.components && spec.components.schemas) || {};
          const names = Object.keys(defs).filter(n => !n.startsWith("_")).sort();
          if (!names.length) { console.error("discovery returned no tables"); process.exit(1); }
          process.stdout.write(names.join(" "));
        } catch (e) { console.error("discovery failed: " + e.message); process.exit(1); }
      });' 2>/dev/null || true)"
  [ -n "$TABLES" ] || fail "could not discover tables (set SUPABASE_DB_TABLES to override)."
fi

# Cross-check discovery against the tables the migrations create. Discovery is
# the source of truth, but if it silently parses nothing useful (an API-shape
# change, a key with too little visibility) the backup would "succeed" while
# protecting almost nothing. Missing a required table is a hard failure.
REQUIRED_TABLES="profiles user_vaults family_profiles safety_reports integrity_reports quiz_attempts security_events hazard_counts"
if [ "${SKIP_REQUIRED_CHECK:-}" != "1" ]; then
  missing=""
  for rt in $REQUIRED_TABLES; do
    case " $TABLES " in *" $rt "*) : ;; *) missing="$missing $rt" ;; esac
  done
  [ -z "$missing" ] || fail "discovery missed required table(s):$missing — refusing to write a partial backup."
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${OUT_ROOT}/${STAMP}"
[ -e "$TARGET" ] && fail "$TARGET already exists — refusing to overwrite."
WORK="${TARGET}.partial"
mkdir -p "$WORK/data"
trap 'rm -rf "$WORK"' EXIT

say "Backing up ${SUPABASE_URL}"
say "  → ${TARGET}"

PAGE=1000
for table in $TABLES; do
  offset=0
  rows=0
  : > "$WORK/data/${table}.jsonl"

  while : ; do
    body="$(curl -sS --max-time 45 \
      -H "apikey: ${KEY}" -H "Authorization: Bearer ${KEY}" \
      -H "Accept: application/json" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=${PAGE}&offset=${offset}" 2>/dev/null || echo '__CURL_FAILED__')"

    case "$body" in
      '__CURL_FAILED__') fail "could not read ${table} (network)"; ;;
    esac
    case "$body" in
      '['*) : ;;
      *)
        # A table that does not exist yet is not a backup failure; an auth
        # failure is. Distinguish them rather than silently writing an empty file.
        case "$body" in
          *'"code":"42P01"'*|*'PGRST205'*) 
            printf '  \033[33mSKIP\033[0m %s (table not present)\n' "$table"
            rm -f "$WORK/data/${table}.jsonl"
            continue 2 ;;
          *) fail "could not read ${table}: $(printf '%s' "$body" | head -c 200)" ;;
        esac
        ;;
    esac

    # node writes the JSONL page to a file and prints ONLY the row count, so the
    # count can be captured without mixing it into the data stream.
    page_rows="$(printf '%s' "$body" | node -e '
      const fs = require("node:fs");
      const out = process.argv[1];
      let raw = "";
      process.stdin.on("data", (c) => (raw += c));
      process.stdin.on("end", () => {
        let rows = [];
        try { rows = JSON.parse(raw); } catch { process.exit(3); }
        fs.writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : ""));
        process.stdout.write(String(rows.length));
      });
    ' "$WORK/data/${table}.page")" || fail "could not parse ${table}"

    [ -s "$WORK/data/${table}.page" ] && cat "$WORK/data/${table}.page" >> "$WORK/data/${table}.jsonl"
    rm -f "$WORK/data/${table}.page"
    page_rows="${page_rows:-0}"
    rows=$((rows + page_rows))
    [ "$page_rows" -lt "$PAGE" ] && break
    offset=$((offset + PAGE))
  done

  printf '  \033[32mOK\033[0m   %-20s %s rows\n' "$table" "$rows"
done

# ---- schema shape (enough to recreate the tables) -------------------------
say "Recording schema shape…"
curl -sS --max-time 45 -H "apikey: ${KEY}" -H "Authorization: Bearer ${KEY}" \
  "${SUPABASE_URL}/rest/v1/" > "$WORK/openapi.json" 2>/dev/null || true

node - "$WORK" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const work = process.argv[2];

const specPath = path.join(work, 'openapi.json');
let spec = {};
try {
  spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
} catch {
  spec = {};
}
fs.rmSync(specPath, { force: true });

const defs = spec.definitions || spec.components?.schemas || {};
const lines = [
  '-- SafeSteps schema shape, recovered from the PostgREST OpenAPI description.',
  '-- Informational: the authoritative DDL lives in safesteps/supabase/migrations/.',
  '-- Restoring a backup should run the migrations first, then re-insert data.',
  '',
];
for (const [table, def] of Object.entries(defs)) {
  lines.push(`-- ${table}`);
  for (const [column, meta] of Object.entries(def.properties || {})) {
    lines.push(`--   ${column}  ${meta.format || meta.type || 'unknown'}`);
  }
  lines.push('');
}
fs.writeFileSync(path.join(work, 'schema.sql'), lines.join('\n'));
NODE

# ---- manifest with hashes -------------------------------------------------
node - "$WORK" "$STAMP" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [work, stamp] = process.argv.slice(2);

const dataDir = path.join(work, 'data');
const files = {};
let total = 0;
for (const name of fs.readdirSync(dataDir).sort()) {
  const full = path.join(dataDir, name);
  const buf = fs.readFileSync(full);
  // Count newline-delimited objects, not raw lines, so a file with one row and
  // no trailing newline is still counted correctly.
  const rows = buf.length === 0 ? 0 : buf.toString('utf8').trim().split('\n').filter(Boolean).length;
  total += rows;
  files[`data/${name}`] = {
    rows,
    bytes: buf.length,
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
  };
}
const schemaPath = path.join(work, 'schema.sql');
if (fs.existsSync(schemaPath)) {
  const buf = fs.readFileSync(schemaPath);
  files['schema.sql'] = { bytes: buf.length, sha256: crypto.createHash('sha256').update(buf).digest('hex') };
}

fs.writeFileSync(path.join(work, 'manifest.json'), JSON.stringify({
  format: 1,
  createdAt: new Date().toISOString(),
  stamp,
  source: process.env.SUPABASE_URL,
  totalRows: total,
  files,
}, null, 2));
console.log(`  rows total: ${total}`);
NODE

mv "$WORK" "$TARGET"
trap - EXIT
ok "backup complete: ${TARGET}"
say "  Verify it restores:  ./scripts/db-restore-test.sh ${TARGET}"
