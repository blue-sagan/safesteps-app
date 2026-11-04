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
| EmailJS public key + service/template ids hard-coded in `index.html` | No mail credentials in client code at all; the server owns SMTP and enqueues mail |
| Africa's Talking API key read from `localStorage` and used from the browser | Removed; SMS is a server-side concern |
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
on boot. Policy: ≥10 characters, letter+number, common-password blocklist,
enforced on the server and mirrored in the client for instant feedback.

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

## Operational notes

- **Rotate now**: the EmailJS public key and Africa's Talking key that were in
  the repo should be considered burned (they were public in a public build).
  Delete both accounts/keys in their dashboards.
- **Never** put `SUPABASE_SERVICE_ROLE_KEY` in the client, a build variable, or
  a CI log. It bypasses RLS entirely.
- Backups containing `user_vaults` are safe to lose to an attacker only in the
  sense that they are ciphertext — but the *metadata* (who reported what, when,
  which county) is not encrypted, so treat dumps as sensitive.
- Keep the audit in the deploy gate: `./scripts/security-audit.sh` exits non-zero
  on any regression.
