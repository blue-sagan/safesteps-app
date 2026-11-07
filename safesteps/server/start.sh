#!/usr/bin/env bash
# Start the SafeSteps server with sensible defaults for a local/preview run.
# Secrets stay out of Git: this file only *generates* throwaway values when a
# real .env is absent, so the app always boots instead of crash-looping.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -f .env ]; then
  echo "No .env found — creating one with ephemeral development values."
  echo "For production, copy .env.example and fill in real credentials."
  cat > .env <<ENVEOF
NODE_ENV=development
PORT=${PORT:-8080}
PUBLIC_ORIGIN=${PUBLIC_ORIGIN:-}
SUPABASE_URL=${SUPABASE_URL:-https://mlgwfzcuumdjgywybujf.supabase.co}
SUPABASE_PUBLISHABLE_KEY=${SUPABASE_PUBLISHABLE_KEY:-}
SUPABASE_SERVICE_ROLE_KEY=
VERIFICATION_PEPPER=$(openssl rand -hex 32)
SERVER_DATA_KEY=$(openssl rand -base64 32)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
MAIL_FROM=SafeSteps Kenya <no-reply@safesteps.local>
ENVEOF
fi

exec node server.js
