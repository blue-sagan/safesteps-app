# Free-plan limits and quotas

Section C: "handle free-plan service limits/quotas".

Figures here come from Supabase's own documentation (checked 2026-11-05) and are
quoted so you can re-verify them, not so you can trust them forever — plans
change. What does *not* change is which of these will actually hurt SafeSteps,
and that is what this page is for.

## 1. The limits that apply

| Limit | Free plan | Will it bite SafeSteps? |
| --- | --- | --- |
| **Project pausing** | paused after **7 days of low activity** | **Yes — this is the real risk.** See below. |
| Database size | 500 MB per project | Not soon: the project is 11 MB today. |
| Egress | 5 GB/month | Only with many users; the app is offline-first by design. |
| Monthly active users | 50,000 MAU | Not a launch concern. |
| Storage size | 1 GB | Only if photo/video uploads get heavy. |
| Edge function invocations | 500,000 | Not used — there are no edge functions. |
| Realtime connections | 200 peak | Not used — the app syncs on demand, no subscriptions. |
| Project count | 2 free projects | Relevant if you spin up a scratch project for restore rehearsals. |

Sources: [billing and quotas](https://supabase.com/docs/guides/platform/billing-on-supabase),
[free project pausing](https://supabase.com/docs/guides/platform/free-project-pausing).

## 2. Pausing is an inactivity mechanism, not a size limit

This distinction matters and is easy to get wrong. A free project is paused when
it receives **too few user database queries over a seven-day window** — roughly,
a few requests per day keeps it awake. Exceeding the 500 MB database size does
not by itself pause the project.

For a new app waiting for its first users, that is a genuine trap: the weeks
when nobody is using SafeSteps are exactly the weeks it can be paused, and it
will then be paused on the day the first class of Scouts tries to sign up.

What Supabase does about it:

- an email to the project owner about a week before a pause;
- another once the project is paused;
- a **one-year** window to restore, with data and configuration intact.

To restore: Dashboard → the organization → the paused project → **Resume
project**.

To prevent it, either upgrade to Pro (paid projects are never paused for
inactivity) or generate real database activity during the quiet weeks.

### What this app does about it

1. **Pausing is diagnosed, not guessed at.** `lib/auth.js` classifies an
   upstream failure as `service_paused` and tells the user the app is
   temporarily read-only while *also* saying that everything on the device still
   works — which is true, because the lesson library, quizzes, route planner and
   hazard map are all local. See `test/resilience.test.js`.
2. **`/healthz` reports platform reachability**, cached for 60 seconds so a
   monitor polling every few seconds cannot itself burn quota. It deliberately
   returns **200** even when the platform is unreachable: SafeSteps is
   offline-first, and a 503 would make Render restart or withdraw an instance
   that is still serving the entire offline app. Alert on
   `platform.reachable === false`, not on the status code.
3. **`scripts/verify-deployment.sh` fails** when the platform is unreachable, so
   a paused project is caught by a deploy check rather than by a user.
4. **Read-only-by-default client behaviour** keeps most usage on the device:
   lessons, quizzes, signs, route planning, hazard map and the offline chatbot
   all work with no database at all. A pause degrades sync and sign-in; it does
   not blank the app.

### Keeping it awake honestly

If you want to prevent pausing during a quiet period, the honest way is real
usage. The blunt option is a scheduled request that touches the database:

```bash
# once a day is enough to count as activity; do not poll every minute
0 9 * * * curl -s -o /dev/null -H "apikey: $SUPABASE_PUBLISHABLE_KEY" \
  "$SUPABASE_URL/rest/v1/profiles?select=id&limit=1"
```

Weigh it up: a synthetic heartbeat that keeps a project awake is also a request
you are not monitoring for correctness, and it does not exercise anything a user
does. If SafeSteps is going to sit idle for weeks, **upgrade or expect a pause**
and make sure the owner's email still reaches you, because the warning goes to
the owner and nowhere else.

## 3. How to watch the numbers

`scripts/db-usage.sh` checks the things that can be measured from SQL:

```bash
export SUPABASE_DB_URL="postgres://…"        # or SUPABASE_ACCESS_TOKEN + SUPABASE_PROJECT_REF
./scripts/db-usage.sh
```

It warns when: database size passes 70% of the ceiling, any table carries more
than 20% dead tuples, a query has run for over 5 minutes, connections pass 50,
or the newest backup is more than 24 hours old. It exits **2** when it cannot
measure at all, rather than reporting a false pass — a monitor that says "fine"
without checking is worse than no monitor.

The live dashboard equivalents are Project → Reports → Database (size,
activity) and Project → Settings → Billing (the limits currently in force).

## 4. Hosting limits (Render)

The `render.yaml` blueprint requests `plan: starter`, which is a **paid** Render
plan — free Render web services spin down after inactivity and take ~50 seconds
to wake, which would make the first user of the day wait. If you switch to free
hosting, expect that cold start and do not confuse it with a Supabase pause: the
symptom is a slow first load, not a failed sign-in.

Nothing in this repository depends on the plan tier. The server is a single
zero-dependency Node process; `/healthz` is the health check path.

## 5. What is verified here vs. what is not

Verified: the pause/outage/disk-full classification (6 tests), the `/healthz`
platform probe against healthy and paused stubs, and `db-usage.sh` thresholds
against a stubbed Management API, including its failure exits.

Not verified: an actual paused project — the live project is active and cannot be
paused deliberately without taking the app down. The behaviour is tested against
a stub that returns Supabase's documented failure responses, which is the
closest thing to a rehearsal that does not involve an outage.
