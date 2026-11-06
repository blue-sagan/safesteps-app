#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# package-release.sh — build a zip of exactly what is committed on this branch.
#
# The archive is built from `git ls-files`, so it can never contain a stray
# secret, a node_modules tree, a local database or an untracked scratch file.
# .gitignore is not trusted for this: a secret that was force-added would still
# be tracked, so the audit below refuses to package if one is found.
#
# USAGE
#   ./scripts/package-release.sh [output.zip]
#
# EXIT CODES
#   0  archive written and verified by reading it back
#   1  a pre-flight check failed (nothing is written)
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
COMMIT="$(git rev-parse --short HEAD)"
STAMP="$(git log -1 --format=%cd --date=format:%Y%m%d)"
OUT="${1:-safesteps-${STAMP}-${COMMIT}.zip}"
OUT_DIR="$(cd "$(dirname "$OUT")" 2>/dev/null && pwd || echo "$ROOT")"
OUT_PATH="$OUT_DIR/$(basename "$OUT")"

say() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

echo "Packaging SafeSteps ($BRANCH @ $COMMIT)"

# --- 1. The working tree must be clean -------------------------------------
# A zip that silently omits the fix someone just made is worse than no zip.
if [ -n "$(git status --porcelain)" ]; then
  say "uncommitted changes:"
  git status --short | sed 's/^/    /'
  fail "commit or stash first — the archive is built from committed content only"
fi
say "working tree clean"

# --- 2. Never ship a credential -------------------------------------------
# Belt and braces: the same patterns security-audit.sh looks for, applied to
# the exact file list this archive will contain.
TRACKED="$(git ls-files)"
BAD_ENV="$(printf '%s\n' "$TRACKED" | grep -E '(^|/)\.env($|\.)' | grep -v '\.env\.example$' || true)"
[ -z "$BAD_ENV" ] || fail "environment file is tracked: $BAD_ENV"

BAD_KEY="$(printf '%s\n' "$TRACKED" | grep -E '\.(pem|key|p12)$' || true)"
[ -z "$BAD_KEY" ] || fail "private key material is tracked: $BAD_KEY"

BAD_DB="$(printf '%s\n' "$TRACKED" | grep -E '\.(db|db-wal|db-shm|dump|sql\.gz|jsonl)$' || true)"
[ -z "$BAD_DB" ] || fail "database or dump file is tracked: $BAD_DB"

# Service-role keys are JWTs with the Supabase role claim. A real one in the
# client bundle would hand over the whole database.
if printf '%s\n' "$TRACKED" | grep -q '^safesteps/index.html$'; then
  if grep -qE 'service_role|"role":"service_role"|SUPABASE_SERVICE_ROLE_KEY=[A-Za-z0-9]' safesteps/index.html; then
    fail "a service-role key or variable is embedded in safesteps/index.html"
  fi
fi
say "no credentials, keys or database files tracked"

# --- 3. The tests that matter must be green -------------------------------
# Packaging a broken build wastes the reviewer's time and looks careless.
if [ -d safesteps/server/node_modules ] || [ -f safesteps/server/package.json ]; then
  ( cd safesteps/server && node --test test/*.test.js >/tmp/pkg-tests.log 2>&1 ) \
    || { tail -20 /tmp/pkg-tests.log; fail "server tests failed — not packaging a broken build"; }
  say "server tests pass ($(grep -E '^# pass' /tmp/pkg-tests.log | awk '{print $3}') tests)"
fi

node scripts/check-links.js >/tmp/pkg-links.log 2>&1 \
  || { tail -5 /tmp/pkg-links.log; fail "broken links"; }
say "no broken links"

node scripts/check-release.js --since origin/main >/tmp/pkg-release.log 2>&1 \
  || { tail -5 /tmp/pkg-release.log; fail "release gate failed"; }
say "release gate passed"

# --- 4. Build the archive -------------------------------------------------
rm -f "$OUT_PATH"
# -X drops platform metadata so the same commit produces a stable archive.
git archive --format=zip --prefix="safesteps-app/" -o "$OUT_PATH" HEAD
say "wrote $(basename "$OUT_PATH") ($(du -h "$OUT_PATH" | cut -f1))"

# --- 5. Read it back ------------------------------------------------------
# Verifying the archive by listing it is the difference between "I made a file"
# and "the file is what I say it is".
COUNT_TRACKED="$(printf '%s\n' "$TRACKED" | wc -l)"
COUNT_ZIP="$(unzip -Z1 "$OUT_PATH" | grep -v '/$' | grep -vc '^safesteps-app/$' || true)"
[ "$COUNT_ZIP" -eq "$COUNT_TRACKED" ] \
  || fail "archive holds $COUNT_ZIP files but $COUNT_TRACKED are tracked"

for must in \
  "safesteps-app/safesteps/index.html" \
  "safesteps-app/safesteps/sw.js" \
  "safesteps-app/safesteps/server/server.js" \
  "safesteps-app/README.md" \
  "safesteps-app/docs/PERFORMANCE.md" \
  "safesteps-app/docs/USER-STATES.md" \
  "safesteps-app/scripts/check-states.js"
do
  unzip -Z1 "$OUT_PATH" | grep -qx "$must" || fail "archive is missing $must"
done
say "archive verified: $COUNT_ZIP files, entry points present"

# No .env or key may have slipped in via the archive itself.
if unzip -Z1 "$OUT_PATH" | grep -qE '(^|/)\.env$|\.(pem|key|p12)$'; then
  rm -f "$OUT_PATH"
  fail "archive contained a credential file — deleted"
fi

echo
echo "Ready: $OUT_PATH"
echo "Commit ${COMMIT} on ${BRANCH}. Unzip and read RELEASE-NOTES.md first."
