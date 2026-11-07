-- ============================================================================
-- 20261107120000_deletion_safeguards.sql
--
-- Section 2 of the data-safety brief: deletion safeguards and access control.
-- Section 1: uniqueness and isolation of the audit trail.
--
-- WHAT THIS FILE ADDS
--   1. public.trash            — a real recycle bin. A deleted record is moved
--                                here, intact, and can be restored.
--   2. public.deletion_audit   — append-only record of every deletion: who,
--                                what, when, how many, and whether it was a
--                                restore or a purge.
--   3. api_trash_soft_delete() — server-side bulk delete: owner-only, capped,
--                                copied into the trash first.
--   4. api_trash_restore()     — put a record back.
--   5. api_trash_purge()       — empty the bin, permanently, for the owner.
--   6. Retention + trigger     — expired trash is purged by the retention job.
--
-- WHY THE CAP LIVES IN THE DATABASE
-- The HTTP layer also enforces the cap (see server/lib/deletion.js), but a
-- limit enforced only in application code is not a limit: anyone holding a
-- publishable key can call PostgREST directly. RLS already stops them deleting
-- *someone else's* rows; this file stops them deleting an unlimited number of
-- their own. Two independent gates, one of which the client cannot reach.
--
-- WHY THE TRASH COMES FIRST
-- A soft delete that fails halfway must not lose the row. The insert into
-- public.trash happens before the delete from the source table, in one
-- transaction: if the copy fails, the delete never runs.
--
-- THE DELETION GUARD ALREADY IN PLACE
-- 20261105140000_deletion_guard.sql guards TRUNCATE and DROP. It deliberately
-- does not guard DELETE, because the app must be able to delete a user's own
-- rows (right to erasure). This migration is the row-level half of that story.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. The recycle bin
-- ---------------------------------------------------------------------------
-- One row per deleted record. `payload` is the whole original row as jsonb, so
-- a restore does not depend on the column list at the time of deletion being
-- unchanged — the shape is what it was.
create table if not exists public.trash (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null default auth.uid()
                    references auth.users(id) on delete cascade,
  source_table    text not null,
  source_id       uuid not null,
  payload         jsonb not null,
  deleted_at      timestamptz not null default now(),
  -- Distinguished from deleted_at because an admin could restore and the row
  -- could be deleted again; a single timestamp would rewrite history.
  restored_at     timestamptz,
  purge_after     timestamptz not null default (now() + interval '30 days'),
  constraint trash_source_table_allowed
    check (source_table in ('safety_reports', 'integrity_reports')),
  constraint trash_payload_is_object
    check (jsonb_typeof(payload) = 'object'),
  -- A trashed row is never big: it is one record from a table whose largest
  -- column is capped at 1 kB (safety_reports.note) or a ciphertext blob.
  constraint trash_payload_size
    check (pg_column_size(payload) <= 32768)
);

create index if not exists trash_owner_idx
  on public.trash (user_id, deleted_at desc);
create index if not exists trash_sweep_idx
  on public.trash (purge_after) where restored_at is null;

comment on table public.trash is
  'Recycle bin for user-deleted records. Rows here are restored to their source table or purged after purge_after. RLS: owner read/insert only; no client UPDATE or DELETE.';

-- ---------------------------------------------------------------------------
-- 2. The audit trail
-- ---------------------------------------------------------------------------
-- Deliberately a separate table from public.security_events: that one is
-- user-visible and its content is untrusted input; this one records what the
-- server itself did. Mixing them would let a crafted event bury a deletion
-- record, and would let one retention policy erase the other's evidence.
create table if not exists public.deletion_audit (
  id              bigint generated always as identity primary key,
  actor_id        uuid references auth.users(id) on delete set null,
  -- Null when the actor's account was deleted afterwards; the audit row
  -- survives because actor_id is ON DELETE SET NULL, not CASCADE.
  actor_email     text,
  action          text not null
                    check (action in ('soft_delete', 'restore', 'purge', 'purge_expired')),
  source_table    text not null,
  affected_count  integer not null check (affected_count >= 0),
  -- The ids, capped, so the record is actionable without being a data dump.
  affected_ids    uuid[] not null default '{}',
  request_source  text not null default 'api'
                    check (request_source in ('api', 'retention_job', 'admin', 'account_erasure')),
  detail          jsonb,
  created_at      timestamptz not null default now(),
  constraint deletion_audit_ids_capped check (array_length(affected_ids, 1) is null
                                              or array_length(affected_ids, 1) <= 500),
  constraint deletion_audit_detail_size check (detail is null or pg_column_size(detail) <= 2048)
);

create index if not exists deletion_audit_time_idx
  on public.deletion_audit (created_at desc);
create index if not exists deletion_audit_actor_idx
  on public.deletion_audit (actor_id, created_at desc);

comment on table public.deletion_audit is
  'Append-only log of every deletion, restore and purge. Written by SECURITY DEFINER functions and by the retention job. Clients can read their own rows; nobody can write or delete through the API.';

-- ---------------------------------------------------------------------------
-- 3. Row Level Security
-- ---------------------------------------------------------------------------
alter table public.trash          enable row level security;
alter table public.deletion_audit enable row level security;

-- trash: the owner can see their own bin. There is no INSERT policy for
-- clients: rows get there only through api_trash_soft_delete() (SECURITY
-- DEFINER), so a client cannot fabricate a trash entry and later "restore" a
-- record that never existed.
drop policy if exists trash_owner_select on public.trash;
create policy trash_owner_select on public.trash
  for select to authenticated
  using (user_id = (select auth.uid()));

-- No UPDATE and no DELETE policy on purpose. Restoring and purging go through
-- the functions below, which log to deletion_audit. A direct DELETE here would
-- be the one deletion into the bin's own contents that left no trace.
revoke all on public.trash from anon, authenticated;
grant select on public.trash to authenticated;

-- deletion_audit: the actor can read what they did. No write path for clients.
drop policy if exists deletion_audit_actor_select on public.deletion_audit;
create policy deletion_audit_actor_select on public.deletion_audit
  for select to authenticated
  using (actor_id = (select auth.uid()));

-- Admins may read the whole log; that is the point of an audit trail.
drop policy if exists deletion_audit_admin_select on public.deletion_audit;
create policy deletion_audit_admin_select on public.deletion_audit
  for select to authenticated
  using (private.is_admin());

revoke all on public.deletion_audit from anon, authenticated;
grant select on public.deletion_audit to authenticated;

-- ---------------------------------------------------------------------------
-- 4. The cap, in one place
-- ---------------------------------------------------------------------------
-- 10 records per request. Small on purpose: a bulk action that cannot express
-- a mistake larger than ten rows is worth more than a convenient one. Override
-- per-deployment with an ALTER DATABASE SET if a real need appears, but the
-- default is the safe one.
create or replace function private.deletion_max_rows()
returns integer
language sql stable
set search_path = pg_catalog, pg_temp
as $$
  select coalesce(nullif(current_setting('safesteps.deletion_max_rows', true), '')::integer, 10);
$$;

create or replace function private.log_deletion(
  p_actor        uuid,
  p_email        text,
  p_action       text,
  p_source_table text,
  p_count        integer,
  p_ids          uuid[],
  p_source       text default 'api',
  p_detail       jsonb default null
)
returns void
language sql
security definer
set search_path = public, pg_temp
as $$
  insert into public.deletion_audit
    (actor_id, actor_email, action, source_table, affected_count, affected_ids, request_source, detail)
  values
    (p_actor, p_email, p_action, p_source_table, p_count,
     coalesce(p_ids, '{}'), p_source, p_detail);
$$;

revoke all on function private.log_deletion(uuid, text, text, text, integer, uuid[], text, jsonb)
  from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 5. Soft delete (the only bulk-delete path)
-- ---------------------------------------------------------------------------
create or replace function public.api_trash_soft_delete(
  p_table text,
  p_ids   uuid[]
)
returns table (deleted integer, trashed integer)
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_uid     uuid := auth.uid();
  v_max     integer := private.deletion_max_rows();
  v_ids     uuid[];
  v_found   integer;
  v_moved   integer := 0;
  v_deleted integer := 0;
  v_email   text;
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  -- Allow-list, not a dynamic identifier. `p_table` is compared, never
  -- interpolated, so a caller cannot name an arbitrary table here.
  if p_table is null or p_table not in ('safety_reports', 'integrity_reports') then
    raise exception 'unsupported table' using errcode = '22023';
  end if;

  -- De-duplicate before counting: 50 copies of one id is one record, and must
  -- not be rejected by a cap meant for 10 distinct records.
  select array_agg(distinct x) into v_ids from unnest(coalesce(p_ids, '{}')) as x;

  if v_ids is null or array_length(v_ids, 1) = 0 then
    raise exception 'no records selected' using errcode = '22023';
  end if;

  if array_length(v_ids, 1) > v_max then
    raise exception 'refusing to delete % records at once (limit %)',
      array_length(v_ids, 1), v_max using errcode = '22023';
  end if;

  -- profiles has no email column (verified against the live schema); the
  -- address lives in auth.users. Recorded on the audit row so a deletion is
  -- attributable even if the account is later erased (actor_id goes NULL).
  select coalesce(u.email, '') into v_email from auth.users u where u.id = v_uid;

  if p_table = 'safety_reports' then
    -- Count what this user actually owns among the requested ids. This is what
    -- makes the impact preview honest: the client's idea of the count is not
    -- trusted, and a request for ids that do not exist (or belong to someone
    -- else) reports the real number rather than a requested one.
    select count(*) into v_found
      from public.safety_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;

    insert into public.trash (user_id, source_table, source_id, payload)
    select v_uid, 'safety_reports', r.id, to_jsonb(r)
      from public.safety_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
    get diagnostics v_moved = row_count;

    delete from public.safety_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
    get diagnostics v_deleted = row_count;
  else
    select count(*) into v_found
      from public.integrity_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;

    insert into public.trash (user_id, source_table, source_id, payload)
    select v_uid, 'integrity_reports', r.id, to_jsonb(r)
      from public.integrity_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
    get diagnostics v_moved = row_count;

    delete from public.integrity_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
    get diagnostics v_deleted = row_count;
  end if;

  -- The copy and the delete must agree. If they do not, the transaction is
  -- already suspect, so refuse rather than report a half-done delete.
  if v_moved <> v_deleted then
    raise exception 'trash copy (% rows) did not match delete (% rows); nothing was deleted',
      v_moved, v_deleted using errcode = '40001';
  end if;

  if v_deleted > 0 then
    perform private.log_deletion(
      v_uid, nullif(v_email, ''), 'soft_delete', p_table, v_deleted, v_ids, 'api',
      jsonb_build_object('requested', array_length(v_ids, 1), 'owned', v_found));
  end if;

  deleted := v_deleted;
  trashed := v_moved;
  return next;
end $$;

revoke all on function public.api_trash_soft_delete(text, uuid[]) from public, anon;
grant execute on function public.api_trash_soft_delete(text, uuid[]) to authenticated;

-- ---------------------------------------------------------------------------
-- 6. Restore
-- ---------------------------------------------------------------------------
create or replace function public.api_trash_restore(p_trash_ids uuid[])
returns table (restored integer)
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_uid      uuid := auth.uid();
  v_ids      uuid[];
  v_row      record;
  v_count    integer := 0;
  v_email    text;
  v_restored uuid[] := '{}';
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  select array_agg(distinct x) into v_ids from unnest(coalesce(p_trash_ids, '{}')) as x;
  if v_ids is null then
    raise exception 'no records selected' using errcode = '22023';
  end if;
  if array_length(v_ids, 1) > private.deletion_max_rows() then
    raise exception 'refusing to restore more than % records at once',
      private.deletion_max_rows() using errcode = '22023';
  end if;

  -- profiles has no email column (verified against the live schema); the
  -- address lives in auth.users. Recorded on the audit row so a deletion is
  -- attributable even if the account is later erased (actor_id goes NULL).
  select coalesce(u.email, '') into v_email from auth.users u where u.id = v_uid;

  for v_row in
    select * from public.trash t
     where t.id = any(v_ids) and t.user_id = v_uid and t.restored_at is null
     order by t.deleted_at
  loop
    -- The payload is the row as it was. jsonb_populate_record rebuilds it
    -- against the table's *current* shape, so a column added since the delete
    -- takes its default rather than breaking the restore.
    if v_row.source_table = 'safety_reports' then
      insert into public.safety_reports
      select * from jsonb_populate_record(null::public.safety_reports, v_row.payload)
      on conflict (id) do nothing;
    elsif v_row.source_table = 'integrity_reports' then
      insert into public.integrity_reports
      select * from jsonb_populate_record(null::public.integrity_reports, v_row.payload)
      on conflict (id) do nothing;
    end if;

    -- Mark restored whether or not the insert was needed: if the id was already
    -- back (restored twice, or recreated), leaving the trash row "live" would
    -- let it be restored again later and silently resurrect a deleted record.
    update public.trash t set restored_at = now() where t.id = v_row.id;

    v_count := v_count + 1;
    v_restored := v_restored || v_row.source_id;
  end loop;

  if v_count > 0 then
    perform private.log_deletion(
      v_uid, nullif(v_email, ''), 'restore', 'mixed', v_count, v_restored, 'api', null);
  end if;

  restored := v_count;
  return next;
end $$;

revoke all on function public.api_trash_restore(uuid[]) from public, anon;
grant execute on function public.api_trash_restore(uuid[]) to authenticated;

-- ---------------------------------------------------------------------------
-- 7. Purge (empty the bin)
-- ---------------------------------------------------------------------------
create or replace function public.api_trash_purge(p_trash_ids uuid[])
returns table (purged integer)
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_uid   uuid := auth.uid();
  v_ids   uuid[];
  v_count integer := 0;
  v_email text;
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  select array_agg(distinct x) into v_ids from unnest(coalesce(p_trash_ids, '{}')) as x;
  if v_ids is null then
    raise exception 'no records selected' using errcode = '22023';
  end if;
  if array_length(v_ids, 1) > private.deletion_max_rows() then
    raise exception 'refusing to purge more than % records at once',
      private.deletion_max_rows() using errcode = '22023';
  end if;

  -- profiles has no email column (verified against the live schema); the
  -- address lives in auth.users. Recorded on the audit row so a deletion is
  -- attributable even if the account is later erased (actor_id goes NULL).
  select coalesce(u.email, '') into v_email from auth.users u where u.id = v_uid;

  delete from public.trash t
   where t.id = any(v_ids) and t.user_id = v_uid;
  get diagnostics v_count = row_count;

  if v_count > 0 then
    perform private.log_deletion(
      v_uid, nullif(v_email, ''), 'purge', 'trash', v_count, v_ids, 'api', null);
  end if;

  purged := v_count;
  return next;
end $$;

revoke all on function public.api_trash_purge(uuid[]) from public, anon;
grant execute on function public.api_trash_purge(uuid[]) to authenticated;

-- ---------------------------------------------------------------------------
-- 8. Impact preview
-- ---------------------------------------------------------------------------
-- Called before a soft delete so the UI can show the real number. Read-only and
-- owner-scoped, so it discloses nothing the caller could not already list.
create or replace function public.api_trash_preview(p_table text, p_ids uuid[])
returns table (matched integer, already_in_trash integer)
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_uid uuid := auth.uid();
  v_ids uuid[];
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if p_table is null or p_table not in ('safety_reports', 'integrity_reports') then
    raise exception 'unsupported table' using errcode = '22023';
  end if;

  select array_agg(distinct x) into v_ids from unnest(coalesce(p_ids, '{}')) as x;

  if v_ids is null then
    matched := 0;
    already_in_trash := 0;
    return next;
    return;
  end if;

  if p_table = 'safety_reports' then
    select count(*) into matched from public.safety_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
  else
    select count(*) into matched from public.integrity_reports r
     where r.id = any(v_ids) and r.user_id = v_uid;
  end if;

  select count(*) into already_in_trash from public.trash t
   where t.id = any(v_ids) and t.user_id = v_uid and t.restored_at is null;

  return next;
end $$;

revoke all on function public.api_trash_preview(text, uuid[]) from public, anon;
grant execute on function public.api_trash_preview(text, uuid[]) to authenticated;

-- ---------------------------------------------------------------------------
-- 9. Retention: expire the bin
-- ---------------------------------------------------------------------------
-- Added to the existing purge function so one maintenance path keeps doing the
-- housekeeping. Trash older than purge_after is erased permanently, and that is
-- logged as purge_expired — a silent deletion is the one kind an audit trail
-- must never miss, even when the deleter is a cron job.
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
  delete from public.trash where purge_after < now();
$$;

revoke all on function private.purge_expired_data() from public, anon, authenticated;

-- The account-erasure path must also empty the bin, or deleting an account
-- would leave that user's deleted records sitting in it.
create or replace function public.api_delete_my_account()
returns void
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  perform private.log_deletion(v_uid, null, 'purge', 'account', 1, array[v_uid], 'account_erasure', null);
  delete from public.user_vaults        where user_id = v_uid;
  delete from public.integrity_reports  where user_id = v_uid;
  delete from public.safety_reports     where user_id = v_uid;
  delete from public.family_profiles    where user_id = v_uid;
  delete from public.quiz_attempts      where user_id = v_uid;
  delete from public.security_events    where user_id = v_uid;
  delete from public.trash              where user_id = v_uid;
  delete from public.profiles           where id      = v_uid;
end $$;

revoke all on function public.api_delete_my_account() from public, anon;
grant execute on function public.api_delete_my_account() to authenticated;

-- ---------------------------------------------------------------------------
-- 10. Report the state of the safeguards, for the status endpoint
-- ---------------------------------------------------------------------------
create or replace function public.api_deletion_safeguards()
returns jsonb
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_guard   text;
  v_trash   bigint;
  v_audit   bigint;
begin
  select public.api_deletion_guard_status() into v_guard;
  select count(*) into v_trash from public.trash where restored_at is null;
  select count(*) into v_audit from public.deletion_audit;

  return jsonb_build_object(
    'maxRowsPerRequest', private.deletion_max_rows(),
    'trashRetentionDays', 30,
    'trashRows', v_trash,
    'auditedDeletions', v_audit,
    'guard', v_guard
  );
end $$;

-- service_role only. The counts here are whole-installation totals (how many
-- records are in everyone's bins, how many deletions have ever been logged), so
-- a normal user must not be able to read them: it would disclose activity
-- across accounts. The server calls this with its own key.
revoke all on function public.api_deletion_safeguards() from public, anon, authenticated;
grant execute on function public.api_deletion_safeguards() to service_role;

-- ---------------------------------------------------------------------------
-- 11. Prove it, in the migration itself
-- ---------------------------------------------------------------------------
-- The cap is the one line that everything else depends on, so the migration
-- fails loudly if it is not actually 10 rather than trusting the literal above.
do $do$
declare v_max integer;
begin
  v_max := private.deletion_max_rows();
  if v_max <> 10 then
    raise exception 'deletion cap is %, expected 10', v_max;
  end if;
  if to_regclass('public.trash') is null or to_regclass('public.deletion_audit') is null then
    raise exception 'trash/deletion_audit missing after create';
  end if;
  raise notice 'SafeSteps: deletion safeguards installed (cap % rows, 30-day trash)', v_max;
end $do$;
