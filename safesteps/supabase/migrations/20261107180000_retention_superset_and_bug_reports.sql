-- ============================================================================
-- 20261107180000_retention_superset_and_bug_reports.sql
--
-- Two defects, one migration, because they are the same defect twice.
--
-- DEFECT 1: the retention function had been silently shrinking.
-- Every migration that touched private.purge_expired_data() redefined the whole
-- function with `create or replace`. Each rewrite was meant to ADD a table:
--
--   security_schema        security_events
--   analytics            + app_events
--   bug_reports          + bug_reports
--   deletion_safeguards  + trash            <-- and - app_events
--
-- The last one was written from a copy of the analytics-era function, so its
-- superset was missing a table that three migrations before it had added. The
-- result: app_events rows older than 180 days were never deleted, while the
-- privacy policy states, in writing, that they are.
--
-- A whole-function `create or replace` cannot express "add one line". That is
-- the trap, and it will stay a trap as long as the function is redefined here.
-- The fix is to write the complete function once, with every table in it, and
-- make every table's retention window explicit in one place.
--
-- DEFECT 2: public.bug_reports was never created.
-- The migration that adds it (20261106120000_bug_reports.sql) was written but
-- never applied, so in production the bug-report endpoint hit PGRST205, fell
-- back to the local SQLite path, and — with SQLITE_PATH unset — wrote to
-- ':memory:'. Reports were accepted, the reporter was told "recorded", and the
-- bytes were discarded on the next restart or deploy.
--
-- This migration is idempotent and safe to apply whether or not the older
-- bug_reports migration is ever applied. Do NOT apply the older one afterwards:
-- it would redefine the function with the pre-trash, pre-fix body and undo both
-- fixes. It is superseded by this file.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Bug reports
-- ---------------------------------------------------------------------------
-- Copied from 20261106120000_bug_reports.sql, unchanged in shape. A report is a
-- message from one person about one problem and usually contains a sentence they
-- typed, so it is deliberately not in app_events (closed vocabulary, no free
-- text, no identifiers).
create table if not exists public.bug_reports (
  id            bigserial primary key,
  -- Both null for an anonymous report: the app works without an account and so
  -- must its bug reporting.
  user_id       uuid        references auth.users (id) on delete set null,
  reply_email   text,
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
  'User-reported and automatically captured defects. Purged by private.purge_expired_data() after 180 days.';
comment on column public.bug_reports.description is
  'Free text from the reporter, bounded by lib/validate.js before it reaches here.';
comment on column public.bug_reports.user_id is
  'Null for anonymous reports. Set when signed in so the report is erased with the account.';

create index if not exists idx_bug_reports_created on public.bug_reports (created_at desc);
create index if not exists idx_bug_reports_status  on public.bug_reports (status, created_at desc);
create index if not exists idx_bug_reports_user    on public.bug_reports (user_id) where user_id is not null;

-- A CHECK is the last line of defence if a future code path forgets to validate.
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
-- 2. Access: written by the server with the service-role key.
-- ---------------------------------------------------------------------------
-- No anonymous role may read this table — it holds other people's words. There
-- is deliberately no insert policy: reports arrive through the server, which
-- validates and rate-limits them first.
alter table public.bug_reports enable row level security;

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
-- 3. Retention — the complete set, in one place
-- ---------------------------------------------------------------------------
-- This is now the ONLY definition of the function, and it must stay a superset
-- of every earlier one. If you add a table, add it here and do not write a new
-- whole-function redefinition anywhere else; a standalone `delete from` in the
-- same migration would be safer still.
--
-- Window per table, matching the privacy policy:
--   verification_challenges  1 day    (expired challenges are useless)
--   rate_limits              1 day    (expired buckets are useless)
--   outbound_mail            90 days  (delivery diagnostics)
--   security_events          365 days (abuse investigation)
--   app_events               180 days (analytics — promised in legal.html §5)
--   bug_reports              180 days (promised in legal.html §3b)
--   trash                    purge_after (30 days, set per row at deletion)
create or replace function private.purge_expired_data()
returns void
language sql
security definer
set search_path = private, public, pg_temp
as $$
  delete from private.verification_challenges where expires_at < now() - interval '1 day';
  delete from private.rate_limits            where expires_at < now() - interval '1 day';
  delete from private.outbound_mail          where created_at < now() - interval '90 days';
  delete from public.security_events         where created_at < now() - interval '365 days';
  delete from public.app_events              where occurred_at < now() - interval '180 days';
  delete from public.bug_reports             where created_at < now() - interval '180 days';
  delete from public.trash                   where purge_after < now();
$$;

revoke all on function private.purge_expired_data() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. Fold bug reports into account erasure
-- ---------------------------------------------------------------------------
-- A report carrying a user_id is that user's personal data, so deleting the
-- account must remove it. This function is otherwise reproduced verbatim from
-- 20261107120000_deletion_safeguards.sql — a whole-function `create or replace`
-- is exactly how the retention defect above happened, so the only change here is
-- the one the fix requires.
--
-- Note the asymmetry, which is deliberate: the delete is by user_id, so an
-- anonymous report (user_id null) survives. It cannot be attributed to anyone,
-- and deleting it would mean guessing whose it was.
--
-- log_deletion receives the report COUNT, not the report text. The audit log
-- outlives the account, and the description is the personal data we were asked
-- to erase — copying it into the log would move the data rather than remove it.
create or replace function public.api_delete_my_account()
returns void
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_uid     uuid := auth.uid();
  v_reports integer;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  select count(*) into v_reports from public.bug_reports where user_id = v_uid;
  perform private.log_deletion(
    v_uid, null, 'purge', 'account', 1, array[v_uid], 'account_erasure',
    jsonb_build_object('bugReportsErased', v_reports)
  );
  delete from public.user_vaults        where user_id = v_uid;
  delete from public.integrity_reports  where user_id = v_uid;
  delete from public.safety_reports     where user_id = v_uid;
  delete from public.family_profiles    where user_id = v_uid;
  delete from public.quiz_attempts      where user_id = v_uid;
  delete from public.security_events    where user_id = v_uid;
  delete from public.bug_reports        where user_id = v_uid;
  delete from public.trash              where user_id = v_uid;
  delete from public.profiles           where id      = v_uid;
end $$;

revoke all on function public.api_delete_my_account() from public, anon;
grant execute on function public.api_delete_my_account() to authenticated;
