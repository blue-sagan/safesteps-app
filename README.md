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
SECURITY.md                what was hardened, and how to verify it
```

## Running locally

```bash
cd safesteps/server
cp .env.example .env          # then fill in SUPABASE_PUBLISHABLE_KEY and peppers
npm start                     # http://localhost:8080
```

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

**Email sign-in needs a mail transport.** Either set `SMTP_*`, or rely on the
Supabase project's mailer (the server falls back to it automatically). Without
either, sign-up still works but the app reports that no email could be sent
rather than pretending otherwise. See SECURITY.md → "Enabling email sign-in". 

## Tests and audit

```bash
cd safesteps/server && npm test     # 30 behavioural security tests
./scripts/security-audit.sh         # secrets in tree+history, deps, headers, tests
```

The audit exits non-zero on failure and runs in CI
(`.github/workflows/security.yml`) on every push, every PR, and weekly.

## Security

Read **[SECURITY.md](SECURITY.md)**: it maps every control (API keys, secrets,
RLS, encryption, session cookies, password hashing, rate limiting, bot
protection, parameterised queries, validation, escaping, uploads, response
trimming, headers, HTTPS, dependency scanning) to the code that implements it
and the test that proves it.

**Rotate the credentials that were previously committed** — the EmailJS public
key and Africa's Talking key that shipped in the client are public and must be
deleted in those dashboards.
