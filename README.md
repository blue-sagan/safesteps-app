# SafeSteps — Road Safety Companion (Kenya)

An offline-first road-safety PWA built with the Kenya Scouts Association
(Project 360° Shield): lessons, quizzes, hazard mapping, route planning, SOS and
an encrypted integrity/whistleblower portal.

* Lessons, quizzes, hazard data, maps and the encrypted local vault work with no
  connection at all (service worker + bundled datasets).
* Accounts, cross-device sync and encrypted evidence upload require the network.

## Repository layout

```
safesteps/                 the PWA itself (static, offline-first)
  index.html               the app
  assets/security.js       client security module (API client, Web Crypto, CSRF)
  sw.js                    service worker (never caches /api)
  data/*.json              bundled safety datasets
  supabase/migrations/     database schema: tables, RLS, triggers, grants
  server/                  the trusted server (secrets + API live here only)
scripts/security-audit.sh  secrets + dependency + header + regression checks
scripts/verify-deployment.sh  the same gate, against a running/deployed origin
scripts/connect-emailjs-supabase.sh  EmailJS via Supabase's Send Email Hook (recommended)
SECURITY.md                what was hardened, and how to verify it
```

## Running locally

```bash
cd safesteps/server
cp .env.example .env          # then fill in SUPABASE_PUBLISHABLE_KEY and peppers
npm start                     # http://localhost:8080
```

or, with no `.env` at all, `./start.sh` — it generates throwaway secrets so the
app boots instead of crash-looping. **Nothing is required to run it**: the PWA,
the lessons, the maps and the local vault are fully offline. Missing credentials
only disable the features that need them, and the app says so explicitly rather
than failing at submit time (see `GET /api/config` → `capabilities`).

There are no runtime dependencies to install — the server is Node built-ins only.
Set `NODE_ENV=production` for HSTS, `Secure`/`__Host-` cookies and HTTPS
enforcement. `PUBLIC_ORIGIN` is required in production.

Required environment (see `server/.env.example`):

| Variable | Purpose |
| --- | --- |
| `SUPABASE_URL` | project URL (public) |
| `SUPABASE_PUBLISHABLE_KEY` | public/anon key — the only key the browser may see |
| `SUPABASE_SERVICE_ROLE_KEY` | **server only**; verification bookkeeping |
| `VERIFICATION_PEPPER` | HMAC pepper for code/rate-limit fingerprints |
| `SERVER_DATA_KEY` | base64 32-byte AES-256-GCM key for at-rest encryption |
| `SMTP_*`, `MAIL_FROM` | optional; without them the server falls back to Supabase's mailer, then to an encrypted local spool |

**Email sign-in needs a mail path.** The one that works end to end is Supabase's
**Send Email Hook**: GoTrue mails through this server, which relays via EmailJS
or SMTP. Because the code is then GoTrue's own, `/verify` returns a real session
and **no service-role key is required**.

```bash
./scripts/connect-emailjs-supabase.sh          # EmailJS keys + generated hook secret
# then Dashboard → Authentication → Hooks → Send Email: HTTP,
#   https://<origin>/api/hooks/send-email, secret from server/.env
./scripts/connect-emailjs-supabase.sh --check  # expects confirmRoute=hook
```

EmailJS has **no SMTP relay** of its own (a "service" is a mailbox you connected),
so it cannot be pasted into Supabase's SMTP settings — the hook is the supported
route. Without the hook, the fallback generates its own code and needs
`SUPABASE_SERVICE_ROLE_KEY`. See SECURITY.md → "Enabling email sign-in".

## Tests and audit

```bash
cd safesteps/server && npm test                  # 55 behavioural security tests
./scripts/security-audit.sh                      # secrets in tree+history, deps, headers, tests
./scripts/verify-deployment.sh http://localhost:8080   # 36 checks against a *running* server
```

The audit exits non-zero on failure and runs in CI
(`.github/workflows/security.yml`) on every push, every PR, and weekly.
`verify-deployment.sh` is the same gate for a deployed origin: point it at the
public URL and it checks headers, CSP nonces, cookie flags, exposure, traversal
and auth on the live server, not on the source.

## Deploying

The server is a single static+API process with zero dependencies, so it runs
anywhere Node 20+ does. Three ready-made paths:

| Path | How |
| --- | --- |
| **Render** (easiest) | New Blueprint → this repo. `render.yaml` sets `rootDir: safesteps/server`, the health check and the env-var list. |
| **Docker** | `docker build -f safesteps/server/Dockerfile -t safesteps . && docker run -p 8080:8080 --env-file safesteps/server/.env safesteps` |
| **Any PaaS with a Procfile** | `web: node server.js` (from `safesteps/server/Procfile`). Mount the repo root so the static files resolve. |

Set these in the host's dashboard — never in Git:

| Variable | Notes |
| --- | --- |
| `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | required for accounts |
| `SUPABASE_SERVICE_ROLE_KEY` | required for email verification; server only |
| `VERIFICATION_PEPPER` | `openssl rand -hex 32` |
| `SERVER_DATA_KEY` | `openssl rand -base64 32` — **keep it stable**, losing it makes existing vault data unreadable |
| `PUBLIC_ORIGIN` | the exact public origin, e.g. `https://safesteps.example` |
| `SMTP_HOST/PORT/USER/PASS`, `MAIL_FROM` | optional mail transport (first choice) |
| `EMAILJS_SERVICE_ID`, `EMAILJS_TEMPLATE_ID`, `EMAILJS_PUBLIC_KEY`, `EMAILJS_PRIVATE_KEY` | optional mail transport (second choice), server-side only |
| `EMAILJS_TEMPLATE_VERIFICATION` | optional dedicated template for verification codes |
| `SEND_EMAIL_HOOK_SECRET` | Supabase Send Email Hook signing secret — preferred path, no service-role key needed |
| `NODE_ENV=production` | turns on HSTS, `Secure`/`__Host-` cookies and HTTPS enforcement |

Then prove it: `./scripts/verify-deployment.sh https://your-origin.example`.

Until the credentials are set the deployment is *degraded, not broken*:
`/healthz` returns `{"status":"ok","degraded":true,"capabilities":{...}}` and the
sign-in forms show a notice instead of pretending to work.

## Security

Read **[SECURITY.md](SECURITY.md)**: it maps every control (API keys, secrets,
RLS, encryption, session cookies, password hashing, rate limiting, bot
protection, parameterised queries, validation, escaping, uploads, response
trimming, headers, HTTPS, dependency scanning) to the code that implements it
and the test that proves it.

**Rotate the credentials that were previously committed** — the EmailJS key and
Africa's Talking key that shipped in the client are public and must be deleted in
those dashboards. When reconnecting EmailJS, mint a fresh key and give it to the
server only; never put it back in `index.html`.
