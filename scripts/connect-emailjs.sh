#!/usr/bin/env bash
# ============================================================================
# Connect EmailJS as the server-side mail transport.
#
# SafeSteps never puts an EmailJS key in browser code. This script writes the
# four values into safesteps/server/.env (git-ignored), prompts without echoing,
# and then proves the transport is live by asking the running server.
#
#   ./scripts/connect-emailjs.sh                 # write to safesteps/server/.env
#   ./scripts/connect-emailjs.sh --check         # only report current state
#
# Secrets are read from the terminal, never from a command argument, so they do
# not end up in your shell history, in `ps`, or in CI logs.
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${SAFESTEPS_ENV_FILE:-$REPO_ROOT/safesteps/server/.env}"
ORIGIN="${ORIGIN:-http://127.0.0.1:8080}"

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m  PASS\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  WARN\033[0m %s\n' "$*"; }
fail() { printf '\033[31m  FAIL\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- read state
env_value() { # env_value KEY
  [ -f "$ENV_FILE" ] || return 1
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

has_all() {
  local service template key
  service="$(env_value EMAILJS_SERVICE_ID || true)"
  template="$(env_value EMAILJS_TEMPLATE_ID || true)"
  key="$(env_value EMAILJS_PUBLIC_KEY || true)"
  [ -n "$service" ] && [ -n "$template" ] && [ -n "$key" ]
}

report() {
  say ""
  say "EmailJS configuration in safesteps/server/.env:"
  local name value
  for name in EMAILJS_SERVICE_ID EMAILJS_TEMPLATE_ID EMAILJS_PUBLIC_KEY EMAILJS_PRIVATE_KEY EMAILJS_TEMPLATE_VERIFICATION; do
    value="$(env_value "$name" || true)"
    if [ -z "$value" ]; then
      say "  $name = (empty)"
    else
      # Show a recognisable prefix only — enough to compare against the
      # dashboard, not enough to reuse.
      say "  $name = ${value:0:4}…(${#value} chars)"
    fi
  done

  if command -v curl >/dev/null 2>&1; then
    local health
    health="$(curl -sS --max-time 4 "$ORIGIN/healthz" 2>/dev/null || true)"
    if [ -n "$health" ]; then
      say ""
      say "Server at $ORIGIN reports:"
      printf '%s' "$health" | sed 's/,/,\n  /g'
      say ""
      case "$health" in
        *'"emailjs":true'*) ok "the running server sees EmailJS as a live transport" ;;
        *'"emailjs":false'*) warn "the running server does not see EmailJS yet — restart it after writing .env" ;;
      esac
    else
      warn "no server reachable at $ORIGIN (start it with: cd safesteps/server && ./start.sh)"
    fi
  fi
}

if [ "${1:-}" = "--check" ]; then
  report
  has_all && ok "all three required values are present" || fail "required values are missing"
  exit 0
fi

# ---------------------------------------------------------------- collect
say ""
say "Connect EmailJS"
say "  Get these from https://dashboard.emailjs.com/admin"
say "    Service ID  →  Email Services  →  your service"
say "    Template ID →  Email Templates →  the template that sends the code"
say "    Public Key  →  Account → General → API Keys"
say "  Input is hidden and written only to safesteps/server/.env (git-ignored)."
say ""

prompt_secret() { # prompt_secret VAR "Label"
  local value=""
  printf '  %s: ' "$2"
  # -s: no echo. Reading from /dev/tty keeps it working when piped.
  read -rs value < /dev/tty || true
  printf '\n'
  printf -v "$1" '%s' "$value"
}

SERVICE_ID=""; TEMPLATE_ID=""; PUBLIC_KEY=""; PRIVATE_KEY=""
prompt_secret SERVICE_ID "Service ID"
prompt_secret TEMPLATE_ID "Template ID"
prompt_secret PUBLIC_KEY "Public Key"
say ""
say "  Private Key (optional — blank if your account does not provide one)"
prompt_secret PRIVATE_KEY "Private Key"

for pair in "SERVICE_ID:${SERVICE_ID}" "TEMPLATE_ID:${TEMPLATE_ID}" "PUBLIC_KEY:${PUBLIC_KEY}"; do
  if [ -z "${pair#*:}" ]; then
    fail "${pair%%:*} is required."
    exit 1
  fi
done

# ---------------------------------------------------------------- write
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

set_env() { # set_env KEY VALUE  — replaces an existing line or appends
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  # Escape characters that are special on the sed replacement side.
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
}

set_env EMAILJS_SERVICE_ID "$SERVICE_ID"
set_env EMAILJS_TEMPLATE_ID "$TEMPLATE_ID"
set_env EMAILJS_PUBLIC_KEY "$PUBLIC_KEY"
if [ -n "$PRIVATE_KEY" ]; then
  set_env EMAILJS_PRIVATE_KEY "$PRIVATE_KEY"
fi
# Do not leave a stale endpoint override behind from an earlier experiment.
if grep -q '^EMAILJS_API_URL=.*127\.0\.0\.1' "$ENV_FILE" 2>/dev/null; then
  set_env EMAILJS_API_URL "https://api.emailjs.com/api/v1.0/email/send"
  warn "reset EMAILJS_API_URL, which pointed at a local test receiver"
fi

ok "wrote EmailJS settings to safesteps/server/.env (mode 600)"
say ""
say "Restart the server so it picks them up, then verify:"
say "  cd safesteps/server && ./start.sh"
say "  ./scripts/connect-emailjs.sh --check"
say ""

report
