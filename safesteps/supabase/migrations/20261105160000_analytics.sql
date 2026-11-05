-- ============================================================================
-- 20261105160000_analytics.sql
--
-- Storage for the app's own analytics and error monitoring (lib/analytics.js).
--
-- WHY NOT A THIRD-PARTY ANALYTICS PROVIDER
-- SafeSteps is used by schoolchildren, and it is a road-safety app, not a
-- marketing site. Adding Google Analytics or similar would mean a third-party
-- script on every page, a cookie banner question, a processor to name in the
-- privacy policy, and a copy of every user's behaviour leaving the system. The
-- only questions worth answering at launch are "is it up", "can people sign in",
-- "which screens are used", and "what is failing" — and all four can be answered
-- from our own database with no personal data at all.
--
-- WHAT THIS TABLE NEVER CONTAINS
-- No user id, no session id, no email, no IP address, no device fingerprint, no
-- free text. `fields` is a small JSONB object whose keys and values are both
-- restricted by lib/analytics.js before they ever reach here. There is no column
-- for an identifier, so a future change cannot start collecting one by accident.
-- ============================================================================

create table if not exists public.app_events (
  id          bigserial primary key,
  name        text        not null,
  fields      jsonb       not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  created_at  timestamptz not null default now()
);

comment on table public.app_events is
  'Aggregate product analytics. Contains no personal data by design — see lib/analytics.js.';
comment on column public.app_events.fields is
  'Small closed-vocabulary object. Never free text, never an identifier.';

create index if not exists idx_app_events_name_time on public.app_events (name, occurred_at desc);
create index if not exists idx_app_events_time      on public.app_events (occurred_at desc);

-- ---------------------------------------------------------------------------
-- Access: the server writes with the service-role key; nobody else touches it.
-- ---------------------------------------------------------------------------
alter table public.app_events enable row level security;

-- Deliberately no policy for `anon` or `authenticated`: with RLS on and no
-- policy, every request from those roles is denied. The service-role key
-- bypasses RLS, which is exactly the access the server needs and nothing more.
revoke all on public.app_events from anon, authenticated;
revoke all on sequence public.app_events_id_seq from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Retention: analytics are useful for a quarter, not forever.
-- ---------------------------------------------------------------------------
create or replace function private.purge_old_analytics()
returns void
language sql
security definer
set search_path = private, public, pg_temp
as $$
  delete from public.app_events where occurred_at < now() - interval '180 days';
$$;

revoke all on function private.purge_old_analytics() from public, anon, authenticated;

-- Fold it into the existing purge helper so there is one retention job, not two.
create or replace function private.purge_expired_data()
returns void
language sql
security definer
set search_path = private, public, pg_temp
as $$
  delete from private.verification_challenges where expires_at < now() - interval '1 day';
  delete from private.rate_limits where expires_at < now() - interval '1 day';
  delete from private.outbound_mail where created_at < now() - interval '90 days';
  delete from public.security_events where created_at < now() - interval '365 days';
  delete from public.app_events where occurred_at < now() - interval '180 days';
$$;

revoke all on function private.purge_expired_data() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- A read-only summary, for the operator (not the app).
-- ---------------------------------------------------------------------------
-- Call this from the SQL editor or a dashboard. It is revoked from the API roles
-- so it cannot be reached over PostgREST by a signed-in user.
create or replace function public.api_analytics_summary(p_days integer default 7)
returns table (name text, occurrences bigint, last_seen timestamptz)
language sql
security definer
set search_path = public, pg_temp
as $$
  select e.name,
         count(*)::bigint as occurrences,
         max(e.occurred_at) as last_seen
    from public.app_events e
   where e.occurred_at > now() - make_interval(days => greatest(p_days, 1))
   group by e.name
   order by occurrences desc;
$$;

revoke all on function public.api_analytics_summary(integer) from public, anon, authenticated;
