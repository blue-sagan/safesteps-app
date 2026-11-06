-- ============================================================================
-- 20261106120000_bug_reports.sql
--
-- Storage for user-submitted and automatically captured bug reports.
--
-- WHY THIS IS SEPARATE FROM app_events
-- app_events is an aggregate analytics table: closed vocabulary, no free text, no
-- identifiers, never a personal record. A bug report is the opposite — it is a
-- message from one person about one problem, and it usually contains a sentence
-- they typed. Mixing the two would destroy the guarantee that app_events holds no
-- personal data, so they are deliberately different tables with different rules.
--
-- WHAT THIS TABLE CONTAINS
--   * a short description the reporter chose to send (or an auto-generated one)
--   * the screen they were on, the app version, and the clamped error class
--   * an optional reply address, only if they asked for a reply
--   * no user id for anonymous reports; a user id only when signed in, so the
--     report is tied to an account the person can actually see and delete
--
-- RETENTION
-- 180 days, same window as analytics, purged by private.purge_expired_data().
-- ============================================================================

create table if not exists public.bug_reports (
  id            bigserial primary key,
  -- Who sent it. Both null for an anonymous report, which is allowed on purpose:
  -- the app is usable without an account and its bug reporting must be too.
  user_id       uuid        references auth.users (id) on delete set null,
  reply_email   text,
  -- What happened.
  description   text        not null,
  screen        text,
  app_version   text,
  kind          text,
  severity      text        not null default 'medium',
  source        text        not null default 'manual',
  -- Resolution. The server sets these; a client cannot.
  status        text        not null default 'new',
  resolution    text,
  resolved_at   timestamptz,
  created_at    timestamptz not null default now()
);

comment on table public.bug_reports is
  'User-reported and automatically captured defects. Purging is handled by private.purge_expired_data().';
comment on column public.bug_reports.description is
  'Free text from the reporter, bounded by lib/validate.js before it reaches here.';
comment on column public.bug_reports.user_id is
  'Null for anonymous reports. Set when signed in so the report can be found and erased with the account.';

-- Triage reads newest-first, and resolving reads by status.
create index if not exists idx_bug_reports_created on public.bug_reports (created_at desc);
create index if not exists idx_bug_reports_status  on public.bug_reports (status, created_at desc);
create index if not exists idx_bug_reports_user    on public.bug_reports (user_id) where user_id is not null;

-- Only these values are meaningful. A CHECK is the last line of defence if a
-- future code path forgets to validate.
alter table public.bug_reports drop constraint if exists bug_reports_severity_check;
alter table public.bug_reports
  add constraint bug_reports_severity_check
  check (severity in ('low', 'medium', 'high', 'crash'));

alter table public.bug_reports drop constraint if exists bug_reports_status_check;
alter table public.bug_reports
  add constraint bug_reports_status_check
  check (status in ('new', 'triaged', 'fixed', 'wontfix', 'duplicate'));

alter table public.bug_reports drop constraint if exists bug_reports_source_check;
alter table public.bug_reports
  add constraint bug_reports_source_check
  check (source in ('manual', 'automatic'));

-- ---------------------------------------------------------------------------
-- Access: written by the server with the service-role key, read by the operator.
-- No anonymous role may read this table — it contains other people's words.
-- ---------------------------------------------------------------------------
alter table public.bug_reports enable row level security;

-- A signed-in user may read their own reports, so the app can show them and let
-- the person delete one. There is deliberately no insert policy: reports arrive
-- through the server, which validates and rate-limits them first.
drop policy if exists bug_reports_select_own on public.bug_reports;
create policy bug_reports_select_own on public.bug_reports
  for select to authenticated
  using (user_id = auth.uid());

drop policy if exists bug_reports_delete_own on public.bug_reports;
create policy bug_reports_delete_own on public.bug_reports
  for delete to authenticated
  using (user_id = auth.uid());

revoke all on public.bug_reports from anon;
revoke insert, update on public.bug_reports from authenticated;

-- ---------------------------------------------------------------------------
-- Retention: fold bug reports into the existing purge so there is still exactly
-- one retention job. The signature and language must match the existing function
-- (SQL, not plpgsql) or `create or replace` would fail on the return type.
-- ---------------------------------------------------------------------------
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
  delete from public.bug_reports where created_at < now() - interval '180 days';
$$;

revoke all on function private.purge_expired_data() from public, anon, authenticated;
