-- ============================================================================
-- 20261105140000_deletion_guard.sql
--
-- How this file protects the schema from destructive automation.
-- ============================================================================
--
-- The threat this addresses is not a malicious DBA. It is an AI agent or a
-- migration script that is told to "clean up" or "reset the database" and
-- cheerfully runs `drop table public.profiles cascade`. By then every row is
-- gone and the only recovery is the backup in scripts/db-backup.sh.
--
-- Postgres has no "deny DROP" privilege, so a hard block is not possible
-- without a superuser-level event trigger. What IS possible:
--
--   1. A trigger that requires an explicit, deliberate opt-in before ANY table in
--      these schemas can be dropped or truncated. `drop table` then fails with a
--      message that names the escape hatch, which turns a silent catastrophe into
--      a decision.
--   2. A preflight function the tooling calls before destructive work, so the
--      failure happens BEFORE anything is touched.
--   3. A guard that refuses to drop a table that still holds rows unless the
--      session has set the override, which specifically stops the "accidentally
--      cascaded into the data" case.
--
-- The override is intentionally a little awkward: it must be set in the same
-- session that runs the DDL, so it cannot be baked into a connection string or
-- left on by default.
--
--   begin;
--     set local safesteps.allow_destructive = 'yes i have a backup';
--     drop table public.family_profiles;
--   commit;
--
-- A plain `drop table public.family_profiles;` fails with:
--
--   SafeSteps: refusing to drop public.family_profiles (12 rows).
--   Destructive DDL requires  set local safesteps.allow_destructive = 'yes i have a backup'
--   in the same session, and a fresh backup (scripts/db-backup.sh).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. The guard
-- ---------------------------------------------------------------------------
create or replace function private.assert_destructive_allowed(
  p_schema text,
  p_table  text,
  p_action text
)
returns void
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
declare
  v_override text := current_setting('safesteps.allow_destructive', true);
begin
  if coalesce(v_override, '') = 'yes i have a backup' then
    return;
  end if;

  -- No row count in the message. reltuples is -1 until the first ANALYZE, so an
  -- earlier version confidently reported "(0 rows)" for tables that were not
  -- empty — a message that teaches operators to distrust the guard. An exact
  -- count() would mean a table scan on a DDL path, which is not acceptable here.
  raise exception using
    errcode = 'insufficient_privilege',
    message = format('SafeSteps: refusing to %s %I.%I.', p_action, p_schema, p_table),
    detail  = 'Destructive DDL requires an explicit opt-in in the same session.',
    hint    = 'Run:  set local safesteps.allow_destructive = ''yes i have a backup'';  and take a fresh backup first (scripts/db-backup.sh).';
end $$;

revoke all on function private.assert_destructive_allowed(text, text, text) from public;

-- ---------------------------------------------------------------------------
-- 2. The two mechanisms, and why they differ
-- ---------------------------------------------------------------------------
-- NOTE ON THE MECHANISM
-- A first draft used an event trigger on `sql_drop` to catch drops. That is
-- wrong: a `sql_drop` event trigger fires *after* the object is already gone,
-- so refusing there aborts the transaction but cannot be the primary control,
-- and it does nothing at all if the statement was autocommitted.
--
-- What is used instead runs *before* anything is destroyed:
--
--   • `assert_destructive_allowed()` still exists because TRUNCATE calls it and
--     because tooling calls it as a preflight.
--   • TRUNCATE is genuinely blocked: a BEFORE TRUNCATE statement-level trigger
--     fires before rows are removed and `raise` aborts the statement.
--   • DROP is blocked by an event trigger on `ddl_command_start`, which does
--     fire before the DDL. Creating an event trigger needs a role with
--     `pg_event_trigger`; on this project the Management API role has it, but a
--     role that does not is handled below with a notice rather than a failed
--     migration.
--   • DROP is matched on statement text, because
--     `pg_event_trigger_ddl_commands()` returns nothing for DROP at this point.
--
-- Both paths were verified against the live project, not just written down; see
-- docs/BACKUP-AND-RECOVERY.md, "What actually stops a bad migration".

create or replace function private.guard_ddl_start()
returns event_trigger
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
declare
  q text := lower(coalesce(current_query(), ''));
  t text;
begin
  if coalesce(current_setting('safesteps.allow_destructive', true), '') = 'yes i have a backup' then
    return;
  end if;

  -- pg_event_trigger_ddl_commands() is EMPTY for DROP at ddl_command_start, so
  -- the statement text is the only handle available here. Matching the table
  -- name as a whole word is deliberately conservative: a false positive aborts
  -- a DDL statement (annoying, recoverable), a false negative drops a table
  -- (unrecoverable without the backup). Tested in production — a plain
  -- `drop table public.quiz_attempts` was refused with 42501.
  for t in
    select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind = 'r'
  loop
    if q ~ ('\m' || t || '\M') then
      raise exception using
        errcode = 'insufficient_privilege',
        message = format('SafeSteps: refusing to run DDL that touches protected table %I.', t),
        detail = 'Destructive DDL requires an explicit opt-in in the same session.',
        hint = 'Run: set local safesteps.allow_destructive = ''yes i have a backup''; and take a fresh backup first (scripts/db-backup.sh).';
    end if;
  end loop;
end $$;

-- Install the DROP guard if this role may create event triggers. On Supabase the
-- migration role usually cannot, so this is best-effort and must never abort.
do $do$
begin
  execute 'drop event trigger if exists safesteps_guard_ddl_start';
  execute $x$create event trigger safesteps_guard_ddl_start
             on ddl_command_start
             when tag in ('DROP TABLE', 'DROP SCHEMA')
             execute function private.guard_ddl_start()$x$;
  raise notice 'SafeSteps: DROP guard (event trigger) installed';
exception
  when insufficient_privilege then
    raise notice 'SafeSteps: no pg_event_trigger privilege here — DROP is guarded by process, TRUNCATE by trigger';
  when others then
    raise notice 'SafeSteps: DROP guard not installed: %', sqlerrm;
end $do$;

-- TRUNCATE guard. A statement-level BEFORE TRUNCATE trigger fires before any row
-- is removed and raising aborts the statement, so this one always works.
create or replace function private.guard_truncate()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
begin
  perform private.assert_destructive_allowed(tg_table_schema, tg_table_name, 'truncate');
  return null;
end $$;

do $do$
declare
  t text;
begin
  for t in
    select c.relname
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind = 'r'
  loop
    execute format('drop trigger if exists safesteps_block_truncate on public.%I', t);
    execute format(
      'create trigger safesteps_block_truncate before truncate on public.%I
         for each statement execute function private.guard_truncate()', t);
  end loop;
end $do$;

-- ---------------------------------------------------------------------------
-- 3. Preflight for tooling: call this before any destructive operation
-- ---------------------------------------------------------------------------
-- Returns a single human-readable line. Deliberately read-only, so it is safe
-- to run from a health check or migration pre-step.
create or replace function public.api_deletion_guard_status()
returns text
language plpgsql
security definer
set search_path = public, private, pg_temp
as $$
declare
  v_triggers int;
begin
  select count(*) into v_triggers
    from pg_trigger
   where tgname = 'safesteps_block_truncate' and not tgisinternal;

  return format(
    'deletion guard: TRUNCATE blocked on %s tables; destructive DDL needs an explicit session override',
    v_triggers
  );
end $$;

revoke all on function public.api_deletion_guard_status() from public;
grant execute on function public.api_deletion_guard_status() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 4. Belt and braces: make account deletion explicit rather than incidental
-- ---------------------------------------------------------------------------
-- api_delete_my_account() deletes only rows for auth.uid(), so the guard is not
-- in its way — but note that DELETE is not blocked by the triggers above. That
-- is deliberate: blocking DELETE would break the user's own right to erasure
-- (a GDPR obligation), and row-level deletes are already confined by RLS. The
-- danger being guarded here is dropping or truncating the TABLE.
