# Bugs at Scale

The brief asked for four things: enable bug reporting (automatic and manual,
with friendly messaging), route logs to a backend, automate fixes with AI, and
review before shipping. Three are built. The fourth cannot be built here, and
this file says why rather than implying otherwise.

## 1. Reporting — manual and automatic

| Path | Where | What it does |
| ---- | ----- | ------------ |
| Manual | Settings → **Report a Problem** | Asks for a description in the user's own words, attaches `APP_VERSION`, the current screen id and the browser string. Never asks for a password or a location. |
| Automatic | `reportBugAutomatically(kind, detail)` | Wired to `window.addEventListener("error")` and `window.addEventListener("unhandledrejection")`. Sends the *shape* of the failure — kind, message, screen — once per distinct signature, never the free text a user typed into a form. |

Both paths POST to `POST /api/bug-report`. The messaging is deliberately plain:
"Something went wrong and we've noted it" beats a stack trace, and the box never
claims a fix is coming because nobody has read the report yet.

Automatic reporting respects the analytics opt-out: `reportBugAutomatically` is
gated on `SS.analytics.allowed()`. Turning analytics off stops crash reports
too — verified 1/0/1 through `/tmp/optout.mjs` style checks rather than assumed.

## 2. Logs to the backend

`POST /api/bug-report` → `201 { status: 'recorded', reference }`.

- Anonymous reports are accepted with `user_id: null`.
- The description never enters `app_events` — it goes to `bug_reports` only, so
  a crash report cannot leak user text into an analytics table.
- Free text in the `screen` field is rejected with `400` (the field is an id,
  not a place to smuggle prose).
- If the table is missing, the server answers `201 { degraded: true }` instead of
  failing the user's report.
- If the database is unreachable, `503 storage_unavailable` — honest, and the
  client keeps the report rather than dropping it silently.

Rate limit: **20 per hour** per account/IP. Schema lives in
`supabase/migrations/20261106120000_bug_reports.sql` (`public.bug_reports`, three
`CHECK` constraints, RLS select/delete-own, `revoke all from anon`, 180-day
purge via `private.purge_expired_data()`).

## 3. Automate fixes with AI — not implemented, on purpose

This was in the brief and it is **not** in the codebase. There is no LLM
provider, no API key, and no model call anywhere in this repository. Building an
"AI fixes it" loop without one would mean shipping a button that does nothing,
which is the exact class of bug this round has been removing.

What a real pipeline needs, in order:

1. **A provider and a key.** Anthropic, OpenAI or similar, plus a spend cap. The
   key is server-side only; it must never reach the browser. This is a decision
   for whoever owns the hosting bill.
2. **A reproducible failure.** A bug report is a sentence, not a test. Before a
   model can fix anything, the failure needs a stack trace or a failing test.
   `reportBugAutomatically` already captures the shape; a source-mapped stack is
   the next real step.
3. **An isolated workspace.** The model works on a branch in a sandbox with no
   production credentials, exactly as this repository's own CI does.
4. **A gate the model cannot pass by claiming success.** The checks already in
   `scripts/` are that gate: `check-states.js`, `check-requests.js`,
   `check-mobile.js`, `check-performance.js`, `check-release.js`, the 104-test
   server suite, and `security-audit.sh`. A proposed fix that breaks any of them
   is rejected automatically.
5. **Human review before merge.** Every AI-authored change arrives as a pull
   request with a diff and green checks, and a person merges it. No model gets
   push access to `main`.

Steps 2–5 exist. Step 1 requires the user's private facts, so it stops there
rather than being faked.

## 4. Review before shipping

`.github/workflows/` runs on every push and PR: secrets and dependency audit,
header checks, server tests on Node 20 and 22, client syntax, mobile layout on
eight phone sizes, the ten user states, the request budget, the performance
budget, and the release gate. `check-release.js --since origin/main` additionally
catches the failure that actually bites: an app-shell change without a
`CACHE_VERSION` bump, after which every existing install serves the old HTML and
a rollback is silently ignored.

## The bug this round kept finding

Defined-but-never-called is this codebase's signature failure:

- `renderNoResults` existed, passed review, and nothing called it.
- `dedupeGet` existed, was credited in `docs/PERFORMANCE.md`, and nothing called
  it — while `lessons.json` was re-downloaded on every visit.
- The whistleblower screen said a referral "will be sent when you reconnect"
  while the retry queue only ever replayed feedback.
- The changelog promised a shared troop/county feed backed by four empty stubs.

The lesson is now enforced rather than remembered: `check-states.js` and
`check-requests.js` run the real code and assert on what the user gets, and both
were shown to exit 1 when the behaviour is removed.
