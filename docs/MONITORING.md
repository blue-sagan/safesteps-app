# Monitoring, analytics and cost control

Section E: "install analytics; monitor errors; monitor resource consumption
(API requests, DB usage, costs); test before launch under realistic conditions".

Everything here is first-party. No analytics vendor, no error-tracking SaaS, no
third-party script in the browser. The reasoning is in
`lib/analytics.js` — briefly: this app is used by schoolchildren, and the four
questions worth answering at launch ("is it up", "can people sign in", "which
screens are used", "what is failing") do not require shipping anyone's behaviour
to a vendor.

---

## 1. What is measured

### Analytics (`/api/events` → `public.app_events`)

A closed list of events, each with a closed list of fields
(`lib/analytics.js → EVENTS`). Nothing else can be recorded — the server rejects
any name it does not declare.

| Event | Fields | Answers |
| --- | --- | --- |
| `app_open` | `outcome` | is the app being opened at all |
| `screen_view` | `screen` | which screens are actually used |
| `signup_start` / `signup_success` / `signup_fail` | `outcome`, `reason` | whether the sign-up funnel works |
| `login_success` / `login_fail` | `reason` | whether sign-in works, and why it fails |
| `password_reset_request` / `password_reset_complete` | `outcome` | whether the reset flow completes |
| `report_submit` | `outcome`, `category` | whether reporting works |
| `quiz_complete` | `outcome` | engagement |
| `offline_use` | `outcome` | whether offline mode is carrying real load |
| `api_error` | `route`, `status` | which endpoints fail, with what status |
| `client_error` | `kind` | network / javascript / storage / permission |
| `account_delete` | `outcome` | whether erasure completes |

**What is never recorded:** any identifier. There is no user id, session id,
email, IP, fingerprint or free text — and the table has no column to hold one,
so this cannot drift. The one exception worth naming: `api_error.route` records
a path like `/api/auth/login`, with numeric ids normalised to `/:id`.

Read the traffic directly:

```sql
select * from public.api_analytics_summary(7);   -- name, occurrences, last_seen
```

```sql
-- the sign-in funnel for the last day, which is the number that matters at launch
select name, count(*) as n
  from public.app_events
 where occurred_at > now() - interval '1 day'
   and name like '%login%' or name like '%signup%'
 group by name order by n desc;
```

### Errors

Two layers, both counted rather than dumped:

1. **Client** — `window.onerror` and `unhandledrejection` are classified into
   `network` / `javascript` / `storage` / `permission` / `other`. The message and
   stack are deliberately **not** sent: a stack trace routinely contains what the
   user typed, which must not land in an analytics table. Cross-origin
   `Script error.` noise is ignored.
2. **Server** — a wrapped `fetch` records any 5xx from `/api/*` as
   `api_error` with the route and status.

Server-side failures that a user should never see are also written to
`security_events` / `security_audit` (sign-in failures, rate-limit store
outages), and printed to the platform log.

### Health

`GET /healthz` is the single operational endpoint:

```json
{
  "status": "ok | degraded",
  "degraded": false,
  "platform": { "reachable": true, "reason": "ok" },
  "uptime": 1234,
  "capabilities": { "auth": true, "emailVerification": true, "atRestEncryption": true, "mailTransport": true },
  "confirmRoute": "hook",
  "analytics": { "accepted": 42, "flushFailures": 0, "buffered": 0, ... }
}
```

It returns **200 even when the platform is unreachable**, and that is deliberate:
SafeSteps is offline-first, and a 503 would make Render restart an instance that
is still serving the entire offline app. **Alert on the body, not the status
code** — specifically `platform.reachable === false`.

`GET /api/metrics` (bearer: the service-role key) returns the analytics counters
for a dashboard.

## 2. What to alert on

Set these up as uptime-monitor checks or platform alerts. Anything without a
check here will be discovered by a user instead.

| # | Signal | How to check | Alert when |
| --- | --- | --- | --- |
| 1 | App is up | `GET /healthz` returns 200 | 2 consecutive failures |
| 2 | Database reachable | `healthz` → `platform.reachable` | `false` for > 5 min |
| 3 | Sign-in works | `healthz` → `capabilities.auth` | `false` |
| 4 | Analytics flushing | `healthz` → `analytics.flushFailures` rising, or `buffered` pinned at 500 | any increase, or buffered stays at max |
| 5 | Database size | `./scripts/db-usage.sh` | > 70% of the plan ceiling |
| 6 | Backup freshness | `./scripts/db-usage.sh` | newest bundle > 24 h old |
| 7 | Disk / dead tuples | `./scripts/db-usage.sh` | warns on its own thresholds |
| 8 | Server errors | `app_events` where `name = 'api_error'` | any sustained 5xx on a core route |
| 9 | Sign-in failure spike | `app_events` where `name = 'login_fail'` | rate jumps well above baseline |
| 10 | Cost / plan limits | host + Supabase dashboards (§4) | approaching any quota |

A cron that covers 5–7 in one line:

```cron
0 * * * * cd /srv/safesteps-app && ./scripts/db-usage.sh >/dev/null || echo "db-usage needs attention" | mail -s "SafeSteps DB" you@example.com
```

## 3. Quotas: what will run out first

Detailed in `docs/FREE-PLAN-LIMITS.md`. The short version, in order:

1. **Supabase pauses a free project after 7 days of low activity** — the most
   likely interruption for a new app, and it happens during the quiet weeks. The
   owner gets an email ~a week ahead; make sure that address is one you read.
2. **Database size** — 500 MB free. Currently ~11 MB. `app_events` is the table
   to watch; it purges after 180 days, but a burst of traffic is what would move
   it.
3. **Egress** — 5 GB free. The app is offline-first and caches its shell, so
   this moves slowly.
4. **Host plan** — `render.yaml` requests `plan: starter` (paid). A free Render
   service sleeps and takes ~50 s to wake, which looks like an outage to the
   first user of the day.

## 4. Cost control

- **Nothing here bills per event.** Analytics are rows in a database you already
  pay for, bounded by a 180-day purge and rate limited at 60 requests/min per
  client.
- **The analytics buffer is capped at 500 events.** If storage fails, events are
  dropped (and counted in `dropped`) rather than growing memory until the process
  dies. Losing analytics is acceptable; losing the app is not.
- **Set a billing alert** on both accounts even on the free plan, so a surprise
  is an email rather than a suspended service.
- **The cheapest way to control cost is to stay offline-first.** Every feature
  that works from the cached shell is a feature that generates no egress.

## 5. Pre-launch: the realistic-conditions test

```bash
node scripts/smoke-test.js http://127.0.0.1:8080
node scripts/smoke-test.js https://<your-host> --concurrency 20 --duration 20
```

It drives the running server: availability, security headers on every HTML
response, the anonymous auth boundary on all protected endpoints, CSRF refusal,
a login burst that must be rate limited, analytics ingest, the service-worker
pre-cache list, and a sustained concurrent load phase.

Last run (local, 2026-11-05, 12 workers × 8 s):

```
5435 requests in 8s (679/s)
p50 15 ms · p95 40 ms · p99 53 ms
statuses: 200×5435
PASS no 5xx and no dropped connection under load
PASS login burst rate limited (8/18 got 429)
PASS all 29 pre-cached assets resolve
```

Any 5xx during the load phase fails the run, because at launch a 500 is a person
who could not use the app.

## 6. Which questions this cannot answer

Being explicit, so nobody assumes coverage that is not there:

- **It cannot tell you about a real phone.** No browser engine is available in
  this environment (see `scripts/check-mobile.js`). Layout is checked from
  computed CSS across 8 viewports; touch behaviour, real fonts, camera access and
  PWA install need a device. Do one manual pass on a cheap Android phone before
  launch.
- **There is no session recording, heatmap or funnel visualisation.** If those
  are wanted later, they are a third-party decision with a privacy-policy
  consequence — do not add one silently.
- **An `unhandledrejection` with a non-Error value** is classified as `other`;
  the underlying value is not recorded, by design.
- **Alerts do not create themselves.** §2 is a checklist of what to configure in
  your monitor and host; nothing in this repository sends you a message.
