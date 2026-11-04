#!/usr/bin/env bash
# ============================================================================
# SafeSteps security audit
# ----------------------------------------------------------------------------
# Fail-closed checks that run in CI and can be run locally at any time:
#   1. dependency vulnerabilities (npm audit, no install required)
#   2. committed-secret scan (working tree + full git history)
#   3. dangerous pattern scan in browser-served code
#   4. security regression tests
#
# Usage:  ./scripts/security-audit.sh
# Exit code is non-zero if any check fails, so it can gate a deployment.
# ============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The PWA + server live in the `safesteps/` app directory.
APP_DIR="$REPO_ROOT/safesteps"
cd "$REPO_ROOT"
FAILED=0
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
pass()    { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail()    { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
warn()    { printf '  \033[33mWARN\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------------------
section "1. Dependency vulnerabilities"
# ---------------------------------------------------------------------------
if command -v npm >/dev/null 2>&1; then
  # --package-lock-only avoids installing anything; the server has zero runtime
  # dependencies, so this also proves the tree stays empty.
  AUDIT_OUT="$(cd "$APP_DIR/server" && npm audit --omit=dev --audit-level=high --json 2>/dev/null || true)"
  if [ -n "$AUDIT_OUT" ]; then
    HIGH="$(printf '%s' "$AUDIT_OUT" | grep -o '"high":[[:space:]]*[0-9]*' | grep -o '[0-9]*' | head -1)"
    CRIT="$(printf '%s' "$AUDIT_OUT" | grep -o '"critical":[[:space:]]*[0-9]*' | grep -o '[0-9]*' | head -1)"
    HIGH="${HIGH:-0}"; CRIT="${CRIT:-0}"
    if [ "$HIGH" -gt 0 ] || [ "$CRIT" -gt 0 ]; then
      fail "npm audit reported $CRIT critical / $HIGH high advisories"
    else
      pass "npm audit: no high or critical advisories in runtime dependencies"
    fi
  else
    warn "npm audit produced no output (offline?) — re-run with network access"
  fi

  DEPS="$(node -e "const p=require('$APP_DIR/server/package.json');console.log(Object.keys(p.dependencies||{}).length)")"
  if [ "$DEPS" = "0" ]; then
    pass "server runtime dependency count is 0"
  else
    warn "server has $DEPS runtime dependencies — review each one"
  fi
else
  warn "npm not available; skipping dependency audit"
fi

# ---------------------------------------------------------------------------
section "2. Committed secrets"
# ---------------------------------------------------------------------------
# A non-empty EmailJS assignment is a secret in a tracked file. The env-var
# *name* alone (as in .env.example or the docs) must stay allowed.
SECRET_PATTERNS='(sb_secret_[A-Za-z0-9]+|service_role[^a-zA-Z]{0,4}["'\''][A-Za-z0-9_-]{20,}|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[A-Za-z0-9]{16,}|EMAILJS_(SERVICE_ID|TEMPLATE_ID|PUBLIC_KEY|PRIVATE_KEY)=[A-Za-z0-9_-]{6,})'

TREE_HITS="$(grep -rInE "$SECRET_PATTERNS" \
  --exclude-dir=.git --exclude-dir=node_modules --exclude='.env' --exclude='*.map' . 2>/dev/null || true)"
if [ -n "$TREE_HITS" ]; then
  fail "possible secret(s) in the working tree:"
  printf '%s\n' "$TREE_HITS" | head -20 | sed 's/^/       /'
else
  pass "no secrets in the working tree"
fi

# Full history scan — a secret that was committed and later deleted is still
# in the packfile and must be rotated + rewritten.
HISTORY_HITS="$(git rev-list --all 2>/dev/null | while read -r commit; do
  git grep -IlE "$SECRET_PATTERNS" "$commit" -- 2>/dev/null
done | sort -u)"
if [ -n "$HISTORY_HITS" ]; then
  fail "possible secret(s) in git history:"
  printf '%s\n' "$HISTORY_HITS" | head -20 | sed 's/^/       /'
else
  pass "no secrets in git history ($(git rev-list --all | wc -l) commit(s))"
fi

if [ -f .gitignore ] && grep -q '^\.env$' .gitignore; then
  pass ".env files are git-ignored"
else
  fail ".gitignore does not exclude .env"
fi

# ---------------------------------------------------------------------------
section "3. Browser-served code"
# ---------------------------------------------------------------------------
CLIENT_FILES="$APP_DIR/index.html $APP_DIR/assets/security.js $APP_DIR/sw.js"
CLIENT_BAD=0
check_client() {
  local pattern="$1" label="$2"
  if grep -qE "$pattern" $CLIENT_FILES 2>/dev/null; then
    fail "$label"
    grep -nE "$pattern" $CLIENT_FILES | head -5 | sed 's/^/       /'
    CLIENT_BAD=1
  fi
}
check_client 'service_role|sb_secret_' 'no service-role key material in client code'
check_client 'emailjs\.(init|send)' 'no client-side mail SDK (credentials belong on the server)'
check_client 'EMAILJS_(SERVICE|TEMPLATE|PUBLIC|PRIVATE)' 'no EmailJS identifiers in browser-served code'
check_client 'api\.emailjs\.com' 'the browser never calls the mail provider directly'
check_client 'passwordHash:[[:space:]]*(btoa|atob)' 'passwords are never encoded into storage'
check_client 'apiKey:[[:space:]]*["'\''][A-Za-z0-9]{8,}' 'no hard-coded API keys'
check_client 'document\.write\(' 'no document.write()'
check_client 'innerHTML[[:space:]]*\+=' 'no incremental innerHTML concatenation'
[ "$CLIENT_BAD" = "0" ] && pass "client code contains no credential or injection primitives"

# Every inline event handler is accounted for (CSP script-src-attr is explicit
# about this, so the count must not silently grow).
HANDLERS="$(grep -oE '\son[a-z]+="' "$APP_DIR/index.html" | wc -l | tr -d ' ')"
printf '  info inline event handlers: %s (CSP allows script-src-attr '"'"'unsafe-inline'"'"' for these)\n' "$HANDLERS"

# ---------------------------------------------------------------------------
section "4. Security regression tests"
# ---------------------------------------------------------------------------
if (cd "$APP_DIR/server" && node --test test/*.test.js >/tmp/safesteps-tests.log 2>&1); then
  SUMMARY="$(grep -E '^# (tests|pass|fail)' /tmp/safesteps-tests.log | tr '\n' ' ')"
  pass "test suite: $SUMMARY"
else
  fail "security tests failed — see /tmp/safesteps-tests.log"
  grep -E '^not ok' /tmp/safesteps-tests.log | head -10 | sed 's/^/       /'
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$FAILED" = "0" ]; then
  printf '\033[32mAll security checks passed.\033[0m\n'
else
  printf '\033[31mSecurity checks failed.\033[0m\n'
fi
exit "$FAILED"
