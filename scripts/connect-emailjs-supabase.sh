#!/usr/bin/env bash
# ============================================================================
# Connect EmailJS to Supabase — the way that actually works.
#
# EmailJS has no SMTP relay of its own; a "service" in EmailJS is a mailbox you
# connected (Gmail, Outlook, Mailtrap…). So it can NOT be pasted into Supabase's
# SMTP settings. The supported route is Supabase's **Send Email Hook**: GoTrue
# stops using its own mailer and POSTs each auth email to our server, which
# relays it through EmailJS.
#
# That also fixes login: the code becomes GoTrue's own, so /verify can trade it
# for a session with no service-role key anywhere.
#
#   ./scripts/connect-emailjs-supabase.sh            # write config + print steps
#   ./scripts/connect-emailjs-supabase.sh --check    # report current state
#
# Everything secret is generated here or entered without echo. Nothing is
# committed, printed in full, or sent through chat.
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${SAFESTEPS_ENV_FILE:-$REPO_ROOT/safesteps/server/.env}"
ORIGIN="${ORIGIN:-http://127.0.0.1:8080}"

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m  PASS\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  WARN\033[0m %s\n' "$*"; }
fail() { printf '\033[31m  FAIL\033[0m %s\n' "$*"; }

env_value() { [ -f "$ENV_FILE" ] || return 1; sed -n "s/^$1=//p" "$ENV_FILE" | tail -1; }

set_env() { # set_env KEY VALUE
  touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  local escaped; escaped="$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
}

report() {
  say ""
  say "Server configuration ($ENV_FILE):"
  local name value
  for name in EMAILJS_SERVICE_ID EMAILJS_TEMPLATE_ID EMAILJS_PUBLIC_KEY EMAILJS_PRIVATE_KEY SEND_EMAIL_HOOK_SECRET; do
    value="$(env_value "$name" || true)"
    if [ -z "$value" ]; then say "  $name = (empty)"; else say "  $name = ${value:0:4}…(${#value} chars)"; fi
  done

  if command -v curl >/dev/null 2>&1; then
    local health
    health="$(curl -sS --max-time 4 "$ORIGIN/healthz" 2>/dev/null || true)"
    if [ -n "$health" ]; then
      say ""; say "Server at $ORIGIN reports:"
      printf '%s' "$health" | sed 's/,/,\n  /g'; say ""
      case "$health" in
        *'"confirmRoute":"hook"'*) ok "confirmRoute=hook — email sign-in works WITHOUT a service-role key" ;;
        *'"confirmRoute":"admin"'*) warn "confirmRoute=admin — hook secret not seen by the running server (restart it)" ;;
        *'"confirmRoute":"none"'*)  fail "confirmRoute=none — no way to confirm an address is configured" ;;
      esac
    else
      warn "no server reachable at $ORIGIN (start it: cd safesteps/server && ./start.sh)"
    fi
  fi
}

if [ "${1:-}" = "--check" ]; then
  report
  exit 0
fi

say ""
say "Connect EmailJS → Supabase (Send Email Hook)"
say ""
say "You need four values from https://dashboard.emailjs.com/admin"
say "  Service ID  → Email Services → your connected mailbox"
say "  Template ID → Email Templates → the one that sends the code"
say "  Public Key  → Account → General → API Keys"
say "  Private Key → optional, if your account has one"
say ""
say "Input is hidden and written only to server/.env (git-ignored, mode 600)."
say ""

prompt_secret() { local value=""; printf '  %s: ' "$2"; read -rs value < /dev/tty || true; printf '\n'; printf -v "$1" '%s' "$value"; }

SERVICE_ID=""; TEMPLATE_ID=""; PUBLIC_KEY=""; PRIVATE_KEY=""
prompt_secret SERVICE_ID  "Service ID"
prompt_secret TEMPLATE_ID "Template ID"
prompt_secret PUBLIC_KEY  "Public Key"
say ""
say "  Private Key (optional — press Enter if your account has none)"
prompt_secret PRIVATE_KEY "Private Key"

[ -n "$SERVICE_ID" ]  || { fail "Service ID is required."; exit 1; }
[ -n "$TEMPLATE_ID" ] || { fail "Template ID is required."; exit 1; }
[ -n "$PUBLIC_KEY" ]  || { fail "Public Key is required."; exit 1; }

set_env EMAILJS_SERVICE_ID "$SERVICE_ID"
set_env EMAILJS_TEMPLATE_ID "$TEMPLATE_ID"
set_env EMAILJS_PUBLIC_KEY "$PUBLIC_KEY"
[ -n "$PRIVATE_KEY" ] && set_env EMAILJS_PRIVATE_KEY "$PRIVATE_KEY"

# The hook signing secret: generate it rather than making the operator invent one.
# Supabase expects the "v1,whsec_<base64>" form.
EXISTING_SECRET="$(env_value SEND_EMAIL_HOOK_SECRET || true)"
if [ -z "$EXISTING_SECRET" ]; then
  GENERATED="v1,whsec_$(openssl rand -base64 32 | tr -d '\n')"
  set_env SEND_EMAIL_HOOK_SECRET "$GENERATED"
  ok "generated SEND_EMAIL_HOOK_SECRET"
  NEW_SECRET=1
else
  ok "kept the existing SEND_EMAIL_HOOK_SECRET"
  NEW_SECRET=0
fi

SECRET_VALUE="$(env_value SEND_EMAIL_HOOK_SECRET)"

say ""
say "──────────────────────────────────────────────────────────────"
say "Now point Supabase at this server (Dashboard → Authentication → Hooks)"
say ""
say "  Hook          Send Email"
say "  Type          HTTP"
say "  URL           https://<your-public-origin>/api/hooks/send-email"
say "  Secret        (copy from the command below — shown once)"
say ""
say "  To reveal it:   grep '^SEND_EMAIL_HOOK_SECRET=' $ENV_FILE"
say ""
say "  ⚠  The URL must be publicly reachable over HTTPS. Supabase cannot call"
say "     a localhost address. Deploy first (render.yaml / Docker), then set it."
say "──────────────────────────────────────────────────────────────"
say ""
if [ "$NEW_SECRET" = "1" ]; then
  ok "wrote a new signing secret — paste it into the Supabase dashboard now"
else
  warn "reusing the existing secret — make sure the dashboard holds the same value"
fi

say ""
say "Then restart and verify:"
say "  cd safesteps/server && ./start.sh"
say "  ./scripts/connect-emailjs-supabase.sh --check"
say ""
say "Expected: confirmRoute=hook, and a test sign-up delivers a code you can"
say "enter on the verification screen to be signed in — with no service-role key."
say ""

report
