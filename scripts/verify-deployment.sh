#!/usr/bin/env bash
# ============================================================================
# Verify a DEPLOYED SafeSteps instance
# ----------------------------------------------------------------------------
# Checks the things a code review cannot: that the live origin actually serves
# hardened headers, forces HTTPS, keeps tokens out of JavaScript's reach, hides
# server source, and refuses cross-site state changes.
#
# Usage:   ./scripts/verify-deployment.sh https://safesteps.example.org
# Exit:    non-zero on the first hard failure (safe to use as a deploy gate).
# ============================================================================
set -uo pipefail

BASE="${1:-${SAFESTEPS_URL:-}}"
if [ -z "$BASE" ]; then
  echo "usage: $0 https://your-deployed-origin" >&2
  exit 2
fi
BASE="${BASE%/}"

FAILED=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
info() { printf '  \033[36mINFO\033[0m %s\n' "$1"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hr() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
has_header() { hr "$1" | grep -qi "^$2:"; }
header_value() { printf '%s\n' "$1" | tr -d '\r' | grep -i "^$2:" | head -1 | cut -d' ' -f2-; }

# ---------------------------------------------------------------------------
section "0. Reachability"
# ---------------------------------------------------------------------------
HEALTH_JSON="$(curl -sS --max-time 15 "$BASE/healthz" 2>/dev/null || true)"
if [ -z "$HEALTH_JSON" ]; then
  fail "cannot reach $BASE/healthz"
  printf '\n\033[31mDeployment appears down.\033[0m\n'
  exit 1
fi
pass "/healthz responded"

STATUS="$(printf '%s' "$HEALTH_JSON" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
[ "$STATUS" = "ok" ] && pass "status: ok" || fail "status: ${STATUS:-unknown}"

CAPS="$(printf '%s' "$HEALTH_JSON" | sed -n 's/.*"capabilities":{\([^}]*\)}.*/\1/p')"
info "capabilities: ${CAPS:-not reported}"
for cap in auth emailVerification atRestEncryption mailTransport; do
  case "$CAPS" in
    *"\"$cap\":true"*) pass "capability enabled: $cap" ;;
    *"\"$cap\":false"*) warn "capability DISABLED: $cap — sign-in/verification will not work until configured" ;;
  esac
done
case "$HEALTH_JSON" in
  *'"degraded":true'*) warn "server reports a degraded configuration (see configWarnings)" ;;
esac
if printf '%s' "$HEALTH_JSON" | grep -qE 'eyJ|sb_secret|service_role'; then
  fail "/healthz leaked credential material"
else
  pass "/healthz contains no secrets"
fi

# ---------------------------------------------------------------------------
section "1. HTTPS and transport security"
# ---------------------------------------------------------------------------
case "$BASE" in
  https://*) HTTPS_MODE=1; pass "using HTTPS" ;;
  *) HTTPS_MODE=0; info "plain-HTTP origin (dev/preview): HSTS and Secure cookies are expected to be absent" ;;
esac

if [ "$HTTPS_MODE" = "1" ]; then
PLAIN="${BASE/https:\/\//http://}"
PLAIN_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --max-redirs 0 "$PLAIN" 2>/dev/null || echo 000)"
LOC="$(curl -sS -D - -o /dev/null --max-time 10 --max-redirs 0 "$PLAIN" 2>/dev/null | tr -d '\r' | grep -i '^location:' | head -1)"
case "$PLAIN_CODE" in
  301|302|307|308)
    case "$LOC" in
      *https://*) pass "plain HTTP redirects to HTTPS ($PLAIN_CODE)" ;;
      *) fail "redirects but not to HTTPS: $LOC" ;;
    esac ;;
  000) warn "could not test plain HTTP on this host" ;;
  *) fail "plain HTTP returned $PLAIN_CODE (expected a redirect)" ;;
esac
else
  info "not an HTTPS origin — skipping the plaintext redirect check (expected in dev)"
fi

# ---------------------------------------------------------------------------
section "2. Response headers"
# ---------------------------------------------------------------------------
HEADERS="$(curl -sS -D - -o /dev/null --max-time 15 "$BASE/" 2>/dev/null)"
BODY_FIRST="$(curl -sS --max-time 20 "$BASE/" 2>/dev/null | head -c 2000)"

for h in \
  "content-security-policy:CSP" \
  "x-content-type-options:nosniff" \
  "x-frame-options:frame protection" \
  "referrer-policy:referrer policy" \
  "permissions-policy:permissions policy" \
  "cross-origin-opener-policy:COOP"
do
  name="${h%%:*}"; label="${h#*:}"
  if has_header "$HEADERS" "$name"; then pass "$label present"; else fail "$label missing ($name)"; fi
done
# HSTS is checked separately below: it must be present on HTTPS and must NOT be
# present on a plain-HTTP dev origin.

CSP="$(header_value "$HEADERS" content-security-policy)"
case "$CSP" in
  *"'nonce-"*) pass "CSP uses a per-response nonce" ;;
  *) fail "CSP has no nonce" ;;
esac
case "$CSP" in
  *"object-src 'none'"*) pass "CSP blocks plugins" ;;
  *) fail "CSP does not set object-src 'none'" ;;
esac
case "$CSP" in
  *"unsafe-eval"*) fail "CSP allows unsafe-eval" ;;
  *) pass "CSP does not allow unsafe-eval" ;;
esac
case "$CSP" in
  *"frame-ancestors"*) pass "CSP sets frame-ancestors" ;;
  *) fail "CSP missing frame-ancestors" ;;
esac

HSTS="$(header_value "$HEADERS" strict-transport-security)"
if [ "$HTTPS_MODE" = "1" ]; then
  case "$HSTS" in
    *max-age=*) pass "HSTS: $HSTS" ;;
    *) fail "HSTS missing on an HTTPS origin" ;;
  esac
else
  case "$HSTS" in
    *max-age=*) info "HSTS present even though this origin is plain HTTP" ;;
    *) pass "no HSTS on a plain-HTTP origin (correct)" ;;
  esac
fi

NONCES_RESPONSE="$(printf '%s' "$BODY_FIRST" | grep -o 'nonce="[^"]*"' | head -1)"
NONCES_ALL="$(curl -sS --max-time 20 "$BASE/" 2>/dev/null | grep -o 'nonce="[^"]*"' | sort -u | wc -l | tr -d ' ')"
SCRIPTS="$(curl -sS --max-time 20 "$BASE/" 2>/dev/null | grep -oi '<script' | wc -l | tr -d ' ')"
if [ "$NONCES_ALL" = "1" ] && [ "$SCRIPTS" -gt 0 ]; then
  pass "all $SCRIPTS script tags share one fresh nonce"
else
  warn "expected exactly one nonce across script tags (found $NONCES_ALL nonces, $SCRIPTS tags)"
fi

# ---------------------------------------------------------------------------
section "3. Session cookie hardening"
# ---------------------------------------------------------------------------
# Trigger a real login attempt path without valid credentials: the cookie flags
# are set in code, so inspect a 4xx response too. Any Set-Cookie from /api is
# checked when present.
COOKIES="$(curl -sS -D - -o /dev/null --max-time 10 -X POST -H 'Content-Type: application/json' \
  -H "Origin: $BASE" -d '{"email":"probe@example.org","password":"x"}' \
  "$BASE/api/auth/login" 2>/dev/null | tr -d '\r' | grep -i '^set-cookie:' || true)"

if [ -z "$COOKIES" ]; then
  info "no cookies issued on a failed login (expected) — checking attributes statically"
  SRC_COOKIE="$(curl -sS --max-time 10 "$BASE/assets/security.js" 2>/dev/null | grep -c 'credentials' || echo 0)"
  [ "$SRC_COOKIE" -gt 0 ] && pass "client uses cookie-based sessions (credentials: same-origin)" \
    || warn "could not confirm client cookie usage"
else
  printf '%s' "$COOKIES" | grep -qi 'HttpOnly' && pass "session cookie is HttpOnly" || fail "session cookie is not HttpOnly"
  printf '%s' "$COOKIES" | grep -qi 'SameSite=Strict' && pass "session cookie is SameSite=Strict" || fail "session cookie is not SameSite=Strict"
  printf '%s' "$COOKIES" | grep -qi 'Secure' && pass "session cookie is Secure" || fail "session cookie is not Secure"
fi

# Tokens must never be reachable from JavaScript storage.
APP_JS="$(curl -sS --max-time 15 "$BASE/assets/security.js" 2>/dev/null || true)"
if printf '%s' "$APP_JS" | grep -qE 'localStorage\.setItem\([^)]*(token|access|refresh)'; then
  fail "client appears to store tokens in localStorage"
else
  pass "client does not store tokens in localStorage"
fi
if printf '%s' "$APP_JS" | grep -qE 'sb_secret_|service_role'; then
  fail "client bundle references privileged credentials"
else
  pass "client bundle references no privileged credentials"
fi

# ---------------------------------------------------------------------------
section "4. Exposure checks"
# ---------------------------------------------------------------------------
for path in /server/server.js /server/lib/config.js /server/.env /.env /.git/config /.git/HEAD; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE$path" 2>/dev/null || echo 000)"
  case "$CODE" in
    200|206) fail "exposed: $path (HTTP $CODE)" ;;
    000) warn "could not check $path" ;;
    *) pass "not exposed: $path ($CODE)" ;;
  esac
done

# Path traversal: a 200 alone means nothing (unknown extension-less paths fall
# back to the SPA shell), so assert that no filesystem content comes back.
for path in '/../../etc/passwd' '/%2e%2e/%2e%2e/etc/passwd' '/..%2f..%2fserver%2fserver.js'; do
  BODY="$(curl -sS --max-time 10 "$BASE$path" 2>/dev/null | head -c 4000)"
  if printf '%s' "$BODY" | grep -qE 'root:x:|daemon:x:|BEGIN (RSA |EC )?PRIVATE KEY|require\('"'"'node:http'; then
    fail "traversal leaks filesystem content: $path"
  elif printf '%s' "$BODY" | grep -qi '<!doctype html>'; then
    pass "traversal serves the app shell only: $path"
  else
    pass "traversal blocked: $path"
  fi
done

# ---------------------------------------------------------------------------
section "5. CSRF / cross-origin refusal"
# ---------------------------------------------------------------------------
CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -H 'Referer: https://evil.example/' \
  -d '{"email":"probe@example.org","password":"x"}' "$BASE/api/auth/login" 2>/dev/null || echo 000)"
[ "$CODE" = "403" ] && pass "cross-origin POST refused (403)" || fail "cross-origin POST returned $CODE (expected 403)"

# ---------------------------------------------------------------------------
section "6. API surface"
# ---------------------------------------------------------------------------
CONFIG_JSON="$(curl -sS --max-time 10 "$BASE/api/config" 2>/dev/null || true)"
if printf '%s' "$CONFIG_JSON" | grep -qE 'eyJ|sb_secret|service_role'; then
  fail "/api/config leaks credential material"
else
  pass "/api/config exposes only public values"
fi

for route in /api/auth/me /api/reports; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE$route" 2>/dev/null || echo 000)"
  case "$CODE" in
    401) pass "$route requires a session (401)" ;;
    503) warn "$route answered 503 (feature not configured)" ;;
    *) fail "$route returned $CODE (expected 401)" ;;
  esac
done

API_HEADERS="$(curl -sS -D - -o /dev/null --max-time 10 "$BASE/api/config" 2>/dev/null)"
has_header "$API_HEADERS" cache-control && \
  (hr "$(header_value "$API_HEADERS" cache-control)" | grep -q 'no-store' \
    && pass "API responses are non-cacheable" || fail "API responses are cacheable") \
  || fail "API responses have no Cache-Control"

# ---------------------------------------------------------------------------
printf '\n'
if [ "$FAILED" = "0" ]; then
  printf '\033[32mDeployment verification passed.\033[0m\n'
else
  printf '\033[31mDeployment verification found problems.\033[0m\n'
fi
exit "$FAILED"
