#!/usr/bin/env bash
# =============================================================================
# db-usage.sh — watch the database so a quota pause never surprises you.
#
# Section B: "monitor DB usage to prevent unexpected interruptions".
#
# Needs one SQL endpoint. Either:
#   SUPABASE_DB_URL      a Postgres connection string      (preferred, psql)
#   SUPABASE_ACCESS_TOKEN + SUPABASE_PROJECT_REF           (Management API)
#
# SUPABASE_API_URL overrides the Management API base URL; it exists so the
# threshold logic can be exercised against a stub in tests.
#
# Exits 0 when everything is inside limits, 1 when a threshold is crossed, 2 when
# it could not measure — so a cron job or CI step can act on it.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/safesteps/server/.env}"

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; CYN=$'\033[36m'; DIM=$'\033[2m'; OFF=$'\033[0m'
if [ ! -t 1 ]; then RED=""; YEL=""; GRN=""; CYN=""; DIM=""; OFF=""; fi

fail() { printf '%s  FAIL%s %s\n' "$RED" "$OFF" "$*" >&2; exit 2; }
say()  { printf '%s\n' "$*"; }

env_value() { # read a key from an env file without echoing the whole file
  [ -f "$ENV_FILE" ] || return 1
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" | tail -1 | sed 's/^["'\'']//; s/["'\'']$//'
}

# Free-plan ceilings. Adjust if the plan changes; being explicit about the
# number being watched is the point.
DB_LIMIT_MB="${DB_LIMIT_MB:-500}"
WARN_PCT="${WARN_PCT:-70}"     # warn at 70% of the disk ceiling
DEAD_PCT="${DEAD_PCT:-20}"     # dead tuples vs live tuples, per table

SQL_SIZE="select pg_size_pretty(pg_database_size(current_database())), round(pg_database_size(current_database())/1048576.0, 1);"
SQL_TABLES="select relname, n_live_tup, n_dead_tup from pg_stat_user_tables order by n_live_tup desc limit 12;"
SQL_DEAD="select relname, n_live_tup, n_dead_tup, round(100.0*n_dead_tup/greatest(n_live_tup,1),1) as pct from pg_stat_user_tables where n_dead_tup > 1000 and n_dead_tup > greatest(n_live_tup,1)*0.2 order by n_dead_tup desc;"
SQL_LONG="select pid, round(extract(epoch from now()-query_start)/60.0,1) as minutes, left(regexp_replace(query,'\s+',' ','g'), 70) from pg_stat_activity where state <> 'idle' and query_start is not null and now()-query_start > interval '5 minutes' and pid <> pg_backend_pid();"
SQL_CONNS="select count(*) from pg_stat_activity;"
SQL_BLOAT="select relname, pg_size_pretty(pg_total_relation_size(relid)) from pg_stat_user_tables order by pg_total_relation_size(relid) desc limit 5;"

run_sql() { # run_sql "<sql>" -> raw stdout, non-zero on failure
  if [ -n "${SUPABASE_DB_URL:-}" ] && command -v psql >/dev/null; then
    psql "$SUPABASE_DB_URL" -At -F '|' -v ON_ERROR_STOP=1 -c "$1"
  elif [ -n "${SUPABASE_ACCESS_TOKEN:-}" ] && [ -n "${SUPABASE_PROJECT_REF:-}" ]; then
    curl -sS --max-time 30 -X POST \
      -H "Authorization: Bearer ${SUPABASE_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      "${SUPABASE_API_URL:-https://api.supabase.com}/v1/projects/${SUPABASE_PROJECT_REF}/database/query" \
      -d "$(node -e 'process.stdout.write(JSON.stringify({query:process.argv[1]}))' "$1")" \
      | node -e '
        let r=""; process.stdin.on("data",c=>r+=c); process.stdin.on("end",()=>{
          let j; try { j = JSON.parse(r); } catch { console.error("bad response: "+r.slice(0,200)); process.exit(1); }
          if (j.message) { console.error(j.message); process.exit(1); }
          const rows = j.rows || j.result || [];
          for (const row of rows) console.log(Object.values(row).join("|"));
        });'
  else
    return 3
  fi
}

SUPABASE_ACCESS_TOKEN="${SUPABASE_ACCESS_TOKEN:-$(env_value SUPABASE_ACCESS_TOKEN || true)}"
SUPABASE_PROJECT_REF="${SUPABASE_PROJECT_REF:-$(env_value SUPABASE_PROJECT_REF || true)}"

say "${CYN}SafeSteps database usage${OFF}"$'\n'

if ! run_sql "select 1" >/dev/null 2>&1; then
  cat <<EOF
${YEL}  SKIP${OFF} no SQL endpoint configured — nothing was measured.

  This is not a pass. Provide one of:
    SUPABASE_DB_URL="postgres://…"                       (needs psql)
    SUPABASE_ACCESS_TOKEN=… SUPABASE_PROJECT_REF=…       (Management API)

  Dashboard alternative: Project → Reports → Database for size and activity,
  Project → Settings → Billing for the limits your plan enforces.
EOF
  exit 2
fi

problems=0
warn() { printf '%s  WARN%s %s\n' "$YEL" "$OFF" "$*"; problems=$((problems+1)); }
ok()   { printf '%s  OK%s   %s\n' "$GRN" "$OFF" "$*"; }

# --- 1. database size vs the plan ceiling -----------------------------------
size_line="$(run_sql "$SQL_SIZE" 2>/dev/null | head -1)"
if [ -z "$size_line" ]; then
  warn "could not read database size"
else
  pretty="${size_line%%|*}"; mb="${size_line##*|}"
  pct=$(node -e "process.stdout.write(String(Math.round((${mb}/${DB_LIMIT_MB})*100)))" 2>/dev/null || echo 0)
  if [ "$pct" -ge 100 ]; then
    warn "database is ${pretty} — ${pct}% of the ${DB_LIMIT_MB} MB ceiling; writes will start failing"
  elif [ "$pct" -ge "$WARN_PCT" ]; then
    warn "database is ${pretty} — ${pct}% of the ${DB_LIMIT_MB} MB ceiling"
  else
    ok "database is ${pretty} — ${pct}% of the ${DB_LIMIT_MB} MB ceiling"
  fi
fi

# --- 2. dead tuples ----------------------------------------------------------
dead_rows="$(run_sql "$SQL_DEAD" 2>/dev/null)"
if [ -z "$dead_rows" ]; then
  ok "no table is carrying significant dead tuples"
else
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    warn "dead tuples: $(printf '%s' "$line" | tr '|' ' ')"
  done <<< "$dead_rows"
fi

# --- 3. long-running queries -------------------------------------------------
long_rows="$(run_sql "$SQL_LONG" 2>/dev/null)"
if [ -n "$long_rows" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    warn "query running > 5 min: $(printf '%s' "$line" | tr '|' ' ')"
  done <<< "$long_rows"
else
  ok "no query has been running longer than 5 minutes"
fi

# --- 4. connections ----------------------------------------------------------
conns="$(run_sql "$SQL_CONNS" 2>/dev/null | head -1)"
if [ -n "$conns" ]; then
  if [ "$conns" -gt 50 ] 2>/dev/null; then
    warn "${conns} database connections open — check the free-plan connection limit"
  else
    ok "${conns} database connections open"
  fi
fi

# --- 5. largest tables -------------------------------------------------------
say ""
say "  ${DIM}largest tables${OFF}"
while IFS= read -r line; do
  [ -n "$line" ] || continue
  say "    $(printf '%s' "$line" | tr '|' ' ')"
done <<< "$(run_sql "$SQL_BLOAT" 2>/dev/null)"

# --- 6. backup age -----------------------------------------------------------
say ""
BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
newest="$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1)"
if [ -z "$newest" ]; then
  warn "no backup bundle found under $BACKUP_ROOT — run scripts/db-backup.sh"
else
  age_h=$(node -e "
    const fs=require('fs');
    const t=fs.statSync(process.argv[1]).mtimeMs;
    process.stdout.write(String(Math.floor((Date.now()-t)/3600000)));" "$newest" 2>/dev/null || echo 9999)
  if [ "$age_h" -gt 24 ]; then
    warn "newest backup is ${age_h} h old ($(basename "$newest")) — has the schedule stopped?"
  else
    ok "newest backup is ${age_h} h old ($(basename "$newest"))"
  fi
fi

say ""
if [ "$problems" -eq 0 ]; then
  say "${GRN}All checks inside limits.${OFF}"
  exit 0
fi
say "${YEL}${problems} item(s) need attention.${OFF}"
exit 1
