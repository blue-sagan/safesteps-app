# SafeSteps — Security Handbook

This document describes what was changed to harden SafeSteps, why, and how each
control is verified. It is written so a reviewer (or a future maintainer) can
check the claims rather than take them on trust.

**Threat model in one line:** a community PWA that anyone can install, run
offline, and tamper with, holding account credentials, children's profile data,
and whistleblower evidence. So: the client is untrusted, the server is the only
authority, and sensitive data is encrypted before it leaves the device.

---

## A. API keys and data security

### A1. API keys are off the client

| Before | After |
| --- | --- |
| EmailJS public key + service/template ids hard-coded in `index.html` | No mail credentials in client code at all: EmailJS is now called *from the server* (`lib/mailer.js`) with env-only keys, alongside SMTP; the browser sends nothing but the account request |
| Africa's Talking API key read from `localStorage` and used from the browser | Removed entirely — the SMS fallback is gone, and the sign-up form no longer collects a phone number |
| NTSA `apiKey` slot in client config | Still `null`, documented as server-side only |

Credentials now live only in `server/.env` (git-ignored) and in Supabase project
secrets. The browser receives exactly one credential-ish value, from
`GET /api/config`:

```json
{ "supabaseUrl": "https://<ref>.supabase.co",
  "supabasePublishableKey": "sb_publishable_...",
  "passwordMinLength": 10, "hsts": true }
```

`sb_publishable_…` is public by design — it grants only what RLS allows. The
`service_role` key exists only in the server process.

*Verified by:* `test/security.test.js` → "browser code contains no hard-coded
credentials" and "/api/config exposes only public values"; plus
`scripts/security-audit.sh` section 3.

### A2. Git history is clean

Full-history scan (`git rev-list --all` + pattern match for JWTs, `sb_secret_`,
`service_role`, `AKIA…`, `ghp_…`, private-key headers, `sk_live_…`). The
repository has a single commit and contains no secrets, so no history rewrite was
required. `.gitignore` now excludes `.env*`, keys, databases and audit reports.

If a secret is ever committed: rotate it first, then rewrite history
(`git filter-repo --path … --invert-paths`), force-push, and invalidate every
session/credential that could have been copied.

*Verified by:* `scripts/security-audit.sh` section 2 (runs on every CI push,
with `fetch-depth: 0`).

### A3. Only the public key is used, with policies behind it

Frontend uses the publishable/anon key exclusively. Its effective privileges are
defined in the database, not in the key: every table has RLS enabled with
explicit per-command policies, and column-level `GRANT`s mean the API cannot even
address columns it has no business reading.

Notably: `anon` has **no** privileges on any table. Reading or writing anything
requires a signed-in user *and* a row that belongs to them.

### A4. Row Level Security

Seven tables, RLS enabled, deny-by-default (no policy = no access):

| Table | anon | authenticated |
| --- | --- | --- |
| `profiles` | ✗ | select/update **own row only**; `role`, `email_verified_at`, `id`, `created_at` are server-owned |
| `user_vaults` | ✗ | own row only (encrypted blob) |
| `family_profiles` | ✗ | own rows only |
| `safety_reports` | ✗ | own rows only; `status` server-owned |
| `integrity_reports` | ✗ | own rows only (create/read/withdraw); admins may read |
| `quiz_attempts` | ✗ | insert + read own; **no update/delete policy = append-only** |
| `security_events` | ✗ | insert + read own |

Private tables (`verification_challenges`, `rate_limits`, `outbound_mail`) live
in the `private` schema: `USAGE` is granted only so policies/triggers can call
helper functions, every table privilege is revoked, RLS is on, and there are no
policies — unreachable with the publishable key.

Definition: `safesteps/supabase/migrations/20261104120000_security_schema.sql`.

*Verified by:* live Postgres tests (see "How the database was verified" below).

### A5. Encryption of sensitive data

Two independent layers:

1. **Vault / dossiers — envelope encryption in the browser.**
   - A random 256-bit data key (AES-256-GCM) encrypts the payload.
   - That data key is wrapped with a key derived from the user's password using
     **PBKDF2-HMAC-SHA256, 310,000 iterations**, 16-byte random salt.
   - Only ciphertext, IV, salt, iteration count and the wrapped key are uploaded.
   - Whistleblower narratives use a **non-extractable** AES-GCM `CryptoKey` held
     in IndexedDB, so the key cannot be read out by script at all.
   - Consequence: a full database dump yields no readable profile, medical,
     children's or evidence data.
2. **Server-side at-rest encryption** for anything the server itself must read
   (`AES-256-GCM`, `SERVER_DATA_KEY`, format `v1.iv.tag.ciphertext`).

Transport is encrypted by TLS end to end; HSTS is set for a year with
`includeSubDomains; preload` in production.

*Verified by:* "at-rest encryption round-trips and detects tampering",
"verification codes are stored only as keyed fingerprints".

---

## B. Authentication and access control

### B1. Authentication is verified server-side

`requireUser()` calls the auth service with the cookie's access token and uses
the **returned** user id — never an id from the request body or query string.
Every write then goes to PostgREST *as that user's JWT*, so Postgres evaluates
RLS in addition to the server's own checks.

### B2. Records cannot be reached across users

Three independent barriers:

1. Policy: `using (user_id = (select auth.uid()))` on every PII table.
2. Trigger: `private.bind_owner()` rewrites `user_id` to `auth.uid()` on insert
   and pins it to the stored value on update — a forged `user_id` is *ignored*,
   not merely rejected.
3. Grant: `user_id` is not in any `UPDATE` column list.

### B3. Field tampering is blocked

- `profiles`: `role`, `email_verified_at`, `id`, `created_at` are copied from the
  stored row before the update is applied — a `PATCH {"role":"admin"}` succeeds
  as a no-op on that column.
- `safety_reports.status` and `integrity_reports.status/case_reference/media_sha256`
  are server-owned the same way.
- API layer independently rejects unknown keys (`400 ... Unexpected field(s)`),
  so a tampering attempt is visible in logs.

### B4. Session cookies

```
__Host-ss_session  HttpOnly; Secure; SameSite=Strict; Path=/;        Max-Age=3600
__Host-ss_refresh  HttpOnly; Secure; SameSite=Strict; Path=/api/auth; Max-Age=2592000
__Host-ss_csrf     Secure;  SameSite=Strict; Path=/;  (readable: double-submit token)
```

`__Host-` forbids `Domain` and requires `Secure` + `Path=/`, so a sibling
subdomain or an HTTP origin cannot overwrite the cookie. Tokens are never placed
in `localStorage`/`sessionStorage`, so XSS cannot exfiltrate a session. Refresh
tokens rotate on every use (Supabase refresh-token rotation enabled), and are
scoped to `/api/auth` so they are not attached to ordinary requests. State
changes additionally require a matching `Origin`/`Referer` **and** the
double-submit CSRF header.

### B5. Password hashing

Passwords are sent over TLS to the server and passed to the auth service, which
hashes them with **bcrypt** (server-side, per user, salted). This repo never
implements its own password hashing — the previous `btoa(password)` (encryption
that is neither salted nor slow, and trivially reversible) is removed, and any
stored `passwordHash` left behind by older builds is purged from `localStorage`
on boot.

Policy: **6–8 characters**, at least one letter and one number, plus a
common-password blocklist. The bounds are exact (not a floor) because the
product specifies a short PIN-style password; `validation.cleanPassword` is the
single server-side gate and `SS.input.password` mirrors it exactly, so the client
cannot offer a value the server will reject. The `minlength`/`maxlength`
attributes on the sign-up and sign-in inputs match as well.

Short passwords shift weight onto the other controls, which is why they are
non-optional here: bcrypt hashing in the auth service, per-address login
throttling (10 / 15 min) on top of per-IP limiting, the proof-of-work bot check
on register/login/verify, and `__Host-` session cookies. If the password policy
is ever relaxed further, those limits must not be relaxed with it.

---

## C. Protection against attacks

### C1. Login rate limiting

Two layers, keyed by sha256 fingerprints (no raw IP or email ever stored):

- per client (IP + user-agent): 10 login attempts / 15 min
- per account (email): 10 / 15 min — slows credential stuffing against one user
- register 5/hour per IP *and* per address; verify 10/15 min; forgot-password 5/hour
- durable counters in Postgres (`private.check_rate_limit`), so limits survive
  restarts and work across instances; the in-process window catches bursts.
- Responses carry `Retry-After`. Upstream 429s are normalised to a generic 429.

### C2. Bot protection

On register/login/verify/forgot:

1. **Proof-of-work** — HMAC-signed, stateless challenge; the client must find a
   nonce whose `sha256(salt:nonce)` has 4 leading zero hex chars (~65k hashes
   ≈ tens of ms for a person, linear cost for a bot farm).
2. **Honeypot** field (`website`) — hidden from humans, filled by form scrapers.
3. **Dwell time** — a challenge answered in under 1.2 s is treated as automated.
4. **User-agent/header sanity** — no `Accept-Language`/`Origin` on a browser form
   POST is refused.
5. The old client-side arithmetic CAPTCHA is gone: its answer shipped in the page.

### C3. Parameterised queries

The production path is PostgREST (values travel as query parameters/JSON — never
concatenated SQL). The local store uses `node:sqlite` **prepared statements**:
`db.query(sql, params)` is the only entry point and it rejects a non-array param
list, so string-built SQL cannot creep back in. A test inserts
`x'); DROP TABLE injection_probe; --` and asserts the table still exists.

### C4. Server-side input validation

Every endpoint validates before acting: type checks, normalisation (NFKC,
control-character stripping, whitespace collapse), length bounds, enum
allow-lists, canonical email/E.164 phone, coordinate ranges, JSON body must be an
object, `Content-Type: application/json`, and a 32 KB body cap (2 MB for the
vault, 8 MB for uploads). Unknown keys are rejected. Errors return per-field
messages but never internals.

### C5. User content is escaped

- `escapeHtml()` (HTML, now also escaping backtick and solidus) and
  `SS.escapeHtml` for every interpolation into `innerHTML`.
- Typed allow-lists for media (`safeImageSrc`/`safeVideoSrc`/`safeAudioSrc`) so a
  poisoned sync payload cannot smuggle `javascript:`.
- Two XSS holes found and closed during this work:
  1. family **share codes** interpolated base64-of-user-JSON directly into a
     quoted inline handler (`onclick="…('${code}')"`) — a `'` in a profile name
     escaped into markup. Now built as DOM nodes.
  2. **imported** share codes flowed into `innerHTML` unescaped — a hostile code
     was a stored-XSS primitive on the receiving device. Now sanitised
     (`sanitizeSharedProfileData`) and length-bounded.
- Lesson content and other JSON-driven templates are escaped too.
- CSP is nonce-based (`script-src 'self' 'nonce-…' 'strict-dynamic'`, no
  `unsafe-inline` for `<script>`), so injected markup cannot execute even if a
  template is missed. `style-src-attr`/`script-src-attr` allow inline attributes
  because the legacy markup declares 393 `onclick=` handlers — that exception is
  explicit, and no remote code is permitted.

### C6. Uploads are restricted

- 8 MB cap in the browser, at the HTTP layer, and on the storage bucket.
- MIME allow-list **checked against magic bytes**, not the client's
  `Content-Type` or the filename: JPEG, PNG, WebP, WebM audio/video, MP3, MP4.
- Explicit deny-list (HTML, SVG, JS, PHP, executables, archives, PDFs) and a
  markup-prefix check.
- Filenames are discarded; objects are stored as `<userId>/<uuid>.<canonical-ext>`
  in a **private** bucket whose policies require the first path segment to equal
  `auth.uid()`. A SHA-256 digest is stored with the report so evidence integrity
  can be verified later.

---

## D. API and deployment security

### D1. Trimmed responses

- Column-level `GRANT`s: the API can only address the columns it needs.
- `select=*` is never used; each handler names its columns.
- Responses carry only what the client uses: e.g. login returns
  `{user:{id,email,fullName,emailVerified}, expiresIn}` — not the token envelope,
  not the refresh token, not provider metadata.
- `user_id`, `role`, audit detail and mail-queue internals never appear in a
  client response.

### D2. Security headers

```
Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none';
  script-src 'self' 'nonce-<per-response>' 'strict-dynamic' <cdn hosts>;
  script-src-attr 'unsafe-inline'; style-src …; img-src …; connect-src <allow-list>;
  form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff        X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(self), microphone=(self), geolocation=(self), payment=(), …
Cross-Origin-Opener-Policy: same-origin   Cross-Origin-Resource-Policy: same-origin
X-Permitted-Cross-Domain-Policies: none   X-DNS-Prefetch-Control: off
```

**Every** `<script>` tag (inline *and* CDN) is nonced per response: under
`strict-dynamic` the host allow-list is ignored, so an un-nonced `src=` tag would
be blocked. Nonces are never reused across responses.

### D3. HTTPS enforced

- HSTS for a year (preload-eligible) in production.
- Plain-HTTP requests are 308-redirected to HTTPS; sensitive endpoints
  (`/api/auth`, `/api/vault`, `/api/uploads`, `/api/account`) **refuse** to run
  over HTTP with a 403 rather than redirecting.
- `Secure` on all cookies; `__Host-` prefix pins them to the exact origin.
- `.env.example` documents `PUBLIC_ORIGIN`/`NODE_ENV` so a deployment cannot
  silently run in the weaker development mode.

### D4. Dependency scanning

- The server has **zero runtime dependencies** (`"dependencies": {}`), so the
  vulnerable-dependency surface is only Node itself.
- `npm audit --omit=dev --audit-level=high` runs in `scripts/security-audit.sh`.
- `.github/workflows/security.yml` runs the full audit on every push and PR, plus
  weekly on a schedule, and can curl a deployed origin to assert the live headers.
- Client libraries are pinned to exact versions via the CDNs already in use.

### D5. Deployment: one command to prove a live origin

Shipping the code is not the same as shipping the controls. `render.yaml`,
`safesteps/server/Dockerfile` and `safesteps/server/Procfile` deploy the same
server anywhere; `scripts/verify-deployment.sh` then proves the deployed origin
still enforces everything in this document.

```bash
./scripts/verify-deployment.sh https://your-origin.example   # 36 checks, exit 1 on any failure
```

| Section | What it asserts against the *live* origin |
| --- | --- |
| 1. Health | `/healthz` answers, reports `capabilities` as booleans, and leaks no credential-shaped string |
| 2. Transport | plain-HTTP → HTTPS redirect; HSTS present in production (gated by `HTTPS_MODE`) |
| 3. Headers | CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP |
| 4. Nonces | a fresh CSP nonce per response, and every `<script>` tag carries it |
| 5. Cookies | `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite` on the session cookie |
| 6. Exposure | no tokens in `localStorage`; `/server/*`, `/.env`, `/.git/*` are 404; path traversal returns no file content; cross-origin `POST` is 403; `/api/config` carries no secrets; `/api/auth/me` and `/api/reports` are 401; API responses are `no-store` |

### D6. Degraded configuration is honest, not silent

A missing credential must not crash-loop the server and must not produce a
misleading success. `lib/config.js` therefore collects warnings instead of
throwing, and every gated feature reports itself:

- `GET /api/config` and `GET /healthz` return a **boolean-only** capability map —
  `{auth, emailVerification, mailTransport, atRestEncryption}` — plus `degraded`
  and a warning *count* (never the values).
- Calling a feature whose capability is `false` returns
  `503 feature_unavailable` naming the exact setting to add, e.g.
  `{"error":"feature_unavailable","message":"Email sign-in is not configured on this server. Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY."}`.
- The PWA reads that map at boot (`SS.session.capabilities()`): when `auth` is
  false the sign-in/sign-up forms are replaced with an explicit notice instead of
  failing on submit. Offline lessons, quizzes, maps and the local vault continue
  to work with **zero** configuration.
- `/healthz` stays `200` while degraded so a load balancer does not flap, but the
  `degraded: true` flag is what alerting should key on.

---

## How the database was verified

RLS was not assumed from reading the policy text — it was exercised in Postgres
as the real `authenticated` role, inside a transaction that was rolled back:

```
insert into auth.users …            -- two throwaway identities
set local role authenticated;
set local request.jwt.claim.sub = '<user A>';
insert into safety_reports (category, note) values ('crash','A own note');
  → user_id bound to A even though none was supplied
update safety_reports set note='edited', status='published';
  → note changed, status refused (server-owned column)
select count(*) from safety_reports;               → 1  (only A's own row)
select count(*) … where note = 'B private note';   → 0  (B's row invisible)
update profiles set role='admin';
  → role unchanged (tampering ignored)
rollback;
```

Two real defects were found this way and fixed:

1. `FORCE ROW LEVEL SECURITY` on `profiles` would also have applied to the table
   owner (`postgres`), which is the definer of the sign-up trigger and of
   `api_delete_my_account()` — i.e. **sign-up would have failed**. Removed;
   plain `ENABLE` still denies `anon`/`authenticated`, since PostgREST never
   connects as `postgres`.
2. Policies/triggers run as `authenticated` and could not execute the `private`
   helper functions (schema `USAGE` / function `EXECUTE` were missing). Granted
   the minimum, with the helpers pinned `SECURITY DEFINER` + fixed `search_path`.

## Enabling email sign-in (required for email login to work)

Email login is fully implemented, but it depends on three things being present in
the deployment. Nothing here is a code change:

1. **A mail transport.** In this order, first configured wins:
   - `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` in `server/.env` (the server's own
     mailer — any mailbox, no third-party rate limit), **or**
   - **EmailJS** — `EMAILJS_SERVICE_ID` / `EMAILJS_TEMPLATE_ID` /
     `EMAILJS_PUBLIC_KEY` (plus `EMAILJS_PRIVATE_KEY` if your account has one),
     **or**
   - the Supabase project's built-in mailer, which the server falls back to
     automatically (`POST /auth/v1/otp`) when no other transport exists.

   If none is available the account is still created, but the API returns
   `delivered: false` and the app says so plainly — it never claims an email was
   sent when one wasn't. The message is encrypted and kept in the `outbound_mail`
   spool so it can be drained once a transport is configured.

   **The settled route: Supabase's Send Email Hook.** EmailJS has no SMTP relay
   of its own — a "service" is a mailbox you connected — so it cannot be pasted
   into Supabase's SMTP settings. Instead, enable the **Send Email** auth hook
   (Dashboard → Authentication → Hooks) pointing at
   `https://<origin>/api/hooks/send-email`. GoTrue then posts each auth email to
   this server, signed with Standard Webhooks, and we relay it through EmailJS.

   Two things fall out of that, both of which fix the login problem:

   1. **No service-role key is needed.** The code is GoTrue's own, so `/verify`
      returns a real session instead of us having to write a "confirmed" flag
      through the admin API. `confirmRoute` in `/healthz` reads `hook`.
   2. **The code the user receives is one `/verify` will accept.** Previously the
      server generated its own code, which GoTrue would always reject — the
      underlying reason sign-in never completed.

   ```bash
   ./scripts/connect-emailjs-supabase.sh         # writes EmailJS keys + generates the hook secret
   ./scripts/connect-emailjs-supabase.sh --check  # expects confirmRoute=hook
   ```

   The endpoint is public by necessity, so the signature is the boundary:
   HMAC-SHA256 over `id.timestamp.body` with the hook secret, constant-time
   compare, and a 5-minute timestamp window against replay. The recipient always
   comes from the signed `user.email` — never from the request URL. With no
   secret configured the endpoint answers 503 and trusts nothing.

   **Without the hook**, the older route still works: the server generates the
   code and confirms the address with `SUPABASE_SERVICE_ROLE_KEY` (that is
   `confirmRoute: admin`). It needs the key and it puts an RLS-bypassing
   credential in the web process, which is why the hook is preferred.

   **EmailJS, server-side only.** The key lives in the server environment and is
   used from `lib/mailer.js` against `api.emailjs.com` — the browser never
   receives it, there is no `emailjs.init()` in the client, and nothing is read
   from `localStorage`. That is the whole difference between this and the old
   build, which shipped the key in `index.html`. Wiring it up:

   ```bash
   ./scripts/connect-emailjs-supabase.sh        # prompts without echo, writes server/.env (mode 600)
   ./scripts/connect-emailjs-supabase.sh --check
   ```

   The template receives `to_email`, `subject`, `message`/`body` and — for
   verification mail — `verification_code`, so the code can be its own variable
   instead of being parsed out of the body. A separate verification template can
   be named with `EMAILJS_TEMPLATE_VERIFICATION`. Verification mail is the only
   mail that carries a code, and the code is never logged.
   `GET /healthz` reports `mailTransports: {smtp, emailjs, supabaseAuth}` as
   booleans so you can confirm the transport is live without reading the key.

   Verified two ways, because "it compiles" proves nothing about delivery:
   `test/emailjs-flow.test.js` drives a real sign-up against a receiver that
   speaks the EmailJS request shape and asserts the 8-digit code arrives as
   `verification_code` *and* in the rendered body; and a live run of the server
   with the transport enabled was confirmed to emit the exact `email/send`
   payload (service id, template id, public key, `accessToken`, template params)
   for an ordinary message.

2. **`SUPABASE_SERVICE_ROLE_KEY`.** Confirming an address is a trusted,
   server-only operation (`PUT /auth/v1/admin/users/:id`). Without this key the
   verify step fails with `503 verify_unavailable` instead of pretending to
   succeed and leaving the user stuck on "email not confirmed".

3. **A deliverable mailbox.** Supabase's default mailer only sends to addresses
   on the project's team and is rate limited; for real users, point the project's
   SMTP settings (or `SMTP_*` here) at a transactional provider.

Two project settings also matter (both are already set on `safesteps`):
`mailer_autoconfirm = false` (so an address must be verified) and
`mailer_otp_length = 8`.

### How the flow was verified

`server/test/auth-flow.test.js` stands up a faithful fake of the exact endpoints
the server calls (`/signup`, `/otp`, `/token`, `/admin/users/:id`, `/user`, and
the service-role RPCs) and drives the real server through the complete journey:

```
register → challenge linked to the new user → verification email queued
        → login refused ("email unconfirmed")
        → wrong code rejected → correct code confirms the address server-side
        → code is single-use → login succeeds → hardened cookies set
        → session authenticates /api/auth/me → response contains no tokens
```

That test caught three real defects, now fixed:

1. `signUp()` never returned the new user id, so the challenge was stored with
   `user_id = null` and verification could not confirm the account.
2. `handleVerify()` only called the confirmation step *if* that id existed, and
   otherwise returned `200 verified` — reporting success while leaving the
   account unconfirmed (login then failed with no explanation). It now repairs a
   missing link via `api_user_id_by_email`, and fails loudly if it cannot.
3. The verification challenge was written straight to `private.*` through
   PostgREST, which is not exposed — so the write silently failed. It now goes
   through the service-role RPC `api_create_challenge`, and a failed remote
   queue write falls back to the local spool instead of dropping the message.

## Operational notes

- **Rotate now**: the EmailJS key and Africa's Talking key that were committed in
  earlier builds should be considered burned (they were public in a public
  build). If you are reconnecting EmailJS, mint a **new** key in the dashboard
  rather than reusing the leaked one, and put it in the server environment — not
  in `index.html`, not in a build variable, not in `localStorage`.
- **Never** put `SUPABASE_SERVICE_ROLE_KEY` in the client, a build variable, or
  a CI log. It bypasses RLS entirely.
- Backups containing `user_vaults` are safe to lose to an attacker only in the
  sense that they are ciphertext — but the *metadata* (who reported what, when,
  which county) is not encrypted, so treat dumps as sensitive.
- Keep the audit in the deploy gate: `./scripts/security-audit.sh` exits non-zero
  on any regression, and `./scripts/verify-deployment.sh <origin>` exits non-zero
  if a deployed origin loses a header, a cookie flag or an auth check.
- **Deployment checklist** (dashboards only; the code is already done):
  set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SERVICE_ROLE_KEY`,
  `VERIFICATION_PEPPER` (`openssl rand -hex 32`), `SERVER_DATA_KEY`
  (`openssl rand -base64 32`, **keep it stable** — rotating it makes queued mail
  and existing vault blobs unreadable), `PUBLIC_ORIGIN`, and the `SMTP_*` values.
  Then run `scripts/verify-deployment.sh` against the deployed URL before
  announcing it.
- `SERVER_DATA_KEY` is the one secret where loss means data loss rather than a
  re-login; store it in a password manager, not only in the host dashboard.
