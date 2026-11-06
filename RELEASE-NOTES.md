# SafeSteps — release notes

This archive is the complete source of the SafeSteps road-safety PWA: the
offline-first client, the trusted server (where the secrets live), the database
migrations, the operational runbooks and the checks that gate a release.

Everything in the archive is committed on the branch it was built from. The
build script refuses to package a dirty working tree, a tracked credential, a
failing test suite or a broken link, and reads the archive back afterwards to
confirm the file count and entry points.

## What to read first

| If you want to… | Read |
| --- | --- |
| run it locally | `README.md` — "Run it locally" |
| deploy it | `render.yaml`, `README.md` — deployment section |
| know what the user sees when things fail | `docs/USER-STATES.md` |
| know what was measured and what was skipped | `docs/PERFORMANCE.md` |
| understand the bug-report pipeline | `docs/BUG-REPORTING-AT-SCALE.md` |
| handle a bad release | `docs/ROLLBACK.md` |
| take or restore a backup | `docs/BACKUP-AND-RECOVERY.md` |

## Layout

```
safesteps/            the app itself (index.html is the whole client shell)
  server/             API, auth, mail, compression — all secrets live here only
  supabase/           migrations: tables, RLS, triggers, grants
  data/               bundled safety datasets (lessons, quiz, signs, hotspots)
  audio/, icons/, screenshots/, assets/
docs/                 runbooks and the design records
scripts/              gates: states, requests, performance, layout, release, security
.github/workflows/    CI: audit, tests on Node 20 + 22, client and layout checks
```

## Run it

```bash
cd safesteps/server
npm install          # there are no runtime dependencies; this is a no-op
node server.js       # http://localhost:8080
```

The client works without the server (it is offline-first and ships its own
datasets). The server is needed for accounts, e-mail verification, hazard
upload, bug reports and the whistleblower referral.

## Check it

```bash
cd safesteps/server && node --test test/*.test.js   # 104 tests
npm install --no-save happy-dom                     # dev-only, for the DOM checks
node scripts/check-states.js                        # all ten user states
node scripts/check-requests.js                      # no dataset downloaded twice
node scripts/check-mobile.js                        # 8 phone sizes × every page
node scripts/check-performance.js                   # byte budget on the wire
node scripts/check-links.js                         # every page and anchor
node scripts/check-release.js --since origin/main   # cache busting, pre-cached assets
./scripts/security-audit.sh                         # secrets, deps, headers
```

There is no browser engine in the build environment, so those DOM checks prove
markup, ARIA roles and logic — not paint timings. One pass on a real mid-range
Android phone over a throttled connection is still required before launch, and
`docs/PERFORMANCE.md` says exactly which numbers are unmeasured.

## What this build does not include

Stated plainly, because a release note that promises more than the code does is
the most expensive kind of bug:

- **No shared troop/county feed.** `connectFirebase()`, `loadFirebaseSDK()`,
  `initCloudSyncIfConfigured()` and the `syncPostToFirebase()` family are
  deliberate no-ops. Community posts, likes and comments are saved on the device
  and never leave it. Wiring this up needs a Firebase project, its config keys
  and a privacy-policy update.
- **No AI auto-fix loop.** There is no LLM provider or API key in this project,
  and no model call anywhere. The five-step pipeline a real one needs is
  documented in `docs/BUG-REPORTING-AT-SCALE.md`, including which steps already
  exist as CI gates and the one that needs the owner's credentials.
- **No CDN, no Redis, no load balancer, no SSR.** None of these components
  exist in this deployment. Where the brief asked for them, the answer is a
  recommendation with its prerequisites, not a pretend change — see the
  server/data-layer table in `docs/PERFORMANCE.md`.
- **No third-party analytics or error tracking.** Monitoring is
  first-party-only, which is a privacy decision, not an omission.

## Before going live — the manual steps

These need private facts or a human decision, so they are not done in the repo:

1. **Apply the migrations**, including `20261106120000_bug_reports.sql`, which is
   written but not yet applied to the live project.
2. **Set the server-side secrets**: `SUPABASE_SERVICE_ROLE_KEY`,
   `VERIFICATION_PEPPER`, `SERVER_DATA_KEY`, and the mail transport credentials.
   They belong in the host's environment, never in this archive.
3. **Configure the mail path** (`./scripts/connect-emailjs-supabase.sh`, then
   Dashboard → Auth → Hooks → Send Email). Email verification is a real gate and
   must stay one.
4. **Deploy behind HTTPS** and set `PUBLIC_ORIGIN` to the real origin. Move
   `site_url` off `localhost:3000`.
5. **Do one real restore** into a scratch project, and rehearse the rollback in
   `docs/ROLLBACK.md`. A backup nobody has restored is a hope, not a backup.
6. **Legal**: the registered legal name and postal address are placeholders on the
   privacy page, and the Kenyan counsel review is still outstanding.

## Testing caveats worth knowing

- `safesteps/server` has **zero runtime dependencies** by design. Any change that
  adds one should be a deliberate decision, not a convenience.
- The service worker's `CACHE_VERSION` must be bumped whenever the app shell
  changes, or every existing install keeps serving the old HTML and a rollback
  is silently ignored. `check-release.js` enforces this.
- `scripts/smoke-test.js` does not send `Accept-Encoding`, so it exercises the
  gzip path rather than Brotli. This is documented because it once made a
  Brotli tuning experiment look like it had no effect.
