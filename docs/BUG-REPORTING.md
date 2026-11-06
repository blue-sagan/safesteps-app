# Bug reporting

How a defect gets from a user's phone to a fix, and why there is no AI writing
patches into this repository automatically.

## The two paths

**Manual.** Settings → *Report a Problem*. The user describes what happened in
their own words. No technical knowledge is required and none is requested: the
screen id, app version and error class are attached by the app.

**Automatic.** An uncaught error, an unhandled promise rejection, or a failing
same-origin API call produces one report per screen-and-error-class per session.
Capped at five per session so a broken render loop cannot send thousands.

Both go to `POST /api/bug-report`.

## What a report contains

| Field | Notes |
|---|---|
| `description` | The reporter's own words, 3–2000 characters |
| `screen` | An app screen id (`map`, `quiz`, …). Shape-checked; free text is refused |
| `app_version` | e.g. `1.0` |
| `kind` | `network` / `javascript` / `storage` / `permission` / `timeout` / `render` / `other` |
| `severity` | `low` / `medium` / `high` / `crash` |
| `source` | `manual` / `automatic` |
| `reply_email` | Only if the reporter ticked the box to be contacted |
| `user_id` | Only when signed in; `null` for anonymous reports |

Never sent: location, contacts, phone number, screen contents, anything the user
did not write, IP address, device fingerprint.

## Storage

`public.bug_reports` (migration `20261106120000_bug_reports.sql`).

This table is deliberately **separate from `app_events`**. `app_events` is an
aggregate analytics table whose whole guarantee is that it contains no personal
data and no free text. A bug report is a message from one person containing a
sentence they typed. Mixing them would quietly destroy that guarantee, so they
have different tables, different access rules and different rate limits.

Analytics still records *that* a bug report happened — `bug_report` with
`kind`, `screen`, `severity`, `source` only. Never the description. There is a
test asserting that.

Retention: 180 days, purged by `private.purge_expired_data()` alongside
everything else. A signed-in user may read and delete their own reports.

## The response to a report

```
curl -s -X POST https://<host>/api/bug-report \
  -H 'Content-Type: application/json' \
  -d '{"description":"Quiz score reset after going back","screen":"quiz","severity":"medium","source":"manual"}'
```

```json
{ "status": "recorded", "reference": "4242" }
```

The reference is the row id, so a user can quote it in an e-mail without either
side exchanging personal details.

## The review pipeline, and the honest limits

The recommendation behind this work was: enable reporting → route logs to the
backend → let an AI read the reports and generate a fix → have a human approve
before shipping.

**Steps 1 and 2 are implemented and tested.** Reports are captured on the device
and stored server-side with the service-role key.

**Steps 3 and 4 are not automated, on purpose.** No part of this repository lets
a model write to the working tree, open a pull request, or merge one. That is a
deliberate boundary, not an omission:

- The app is used by schoolchildren and its failure modes are safety-relevant. A
  plausible-looking generated patch to the SOS screen or the first-aid steps is
  worse than no patch.
- A report contains a user's own words. Feeding those to a third-party model
  turns an anonymous bug report into data processing that the privacy policy does
  not currently describe, and would need a new processor disclosure.
- Anything that can write to the repo unsupervised is a supply-chain surface.

If that automation is added later, the minimum bar is: reports triaged into a
queue a human reads, generated changes opened as a *draft* pull request, the full
gate (`npm test`, `check-links`, `check-mobile`, `check-release`,
`security-audit.sh`) required to pass, and a named human approving. Until then the
loop is: read the report, reproduce it, fix it, add a regression test.

### Triage queries

```sql
-- Newest first, for a daily read.
select id, severity, source, screen, kind, created_at, description
  from public.bug_reports
 where status = 'new'
 order by
   case severity when 'crash' then 0 when 'high' then 1 when 'medium' then 2 else 3 end,
   created_at desc;

-- Grouped by screen, to find the screen that breaks most often.
select screen, kind, count(*) as reports
  from public.bug_reports
 where created_at > now() - interval '30 days'
 group by screen, kind
 order by reports desc;

-- Mark one as fixed.
update public.bug_reports
   set status = 'fixed', resolution = 'Short note on the fix', resolved_at = now()
 where id = 4242;
```

## Operational notes

- The endpoint has its own rate-limit bucket (`bugreport`, 20/hour) so reporting
  bugs cannot consume the password-reset budget.
- If the `bug_reports` table does not exist yet — deployed code, unapplied
  migration — the report is stored in the local fallback and the endpoint still
  returns `201` with `degraded: true`. It never silently drops a report.
- If the database is unreachable, the endpoint returns `503` so the client knows
  to keep the user's text and offer a retry.
