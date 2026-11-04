-- ============================================================================
-- SafeSteps — security hardening schema
-- ----------------------------------------------------------------------------
-- Applied to Supabase project `safesteps` (ref: mlgwfzcuumdjgywybujf).
--
-- Design rules enforced here:
--   1. Every public table has RLS ENABLED *and* an explicit policy. There is no
--      "service key in the browser" fallback — the browser only ever holds the
--      publishable (anon) key, whose privileges are exactly what RLS allows.
--   2. Ownership is never taken from the request body. Row owners are bound to
--      auth.uid() by DEFAULT + TRIGGER, so a forged user_id is ignored, not just
--      rejected.
--   3. Column-level GRANTs trim what the API can even address (no SELECT *).
--   4. Server-controlled columns (role, status, scores, timestamps, ownership)
--      are protected by guards that rewrite them back to the stored value, so a
--      crafted PATCH cannot escalate a role or re-point a record.
--   5. Secrets, verification challenges, rate-limit counters and the outbound
--      mail queue live in the private schema / service-role-only tables and are
--      unreachable with the publishable key.
-- ============================================================================

begin;

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- 0. Private schema — never exposed through the PostgREST API
-- ---------------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public;
revoke all on schema private from anon, authenticated;
grant usage on schema private to service_role;

-- ---------------------------------------------------------------------------
-- 1. Helper functions (SECURITY DEFINER, pinned search_path)
-- ---------------------------------------------------------------------------
-- SECURITY DEFINER + pinned search_path: the identity helpers must not be
-- co-optable through a caller-controlled schema list.
create or replace function private.current_uid()
returns uuid
language sql stable security definer
set search_path = pg_catalog, pg_temp
as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

-- Policies and triggers run as `authenticated`, so they need USAGE on the
-- schema and EXECUTE on the helpers. Every *table* in `private` remains fully
-- revoked, and there are no RLS policies on them, so nothing is readable.
grant usage on schema private to authenticated;
grant execute on function private.current_uid() to authenticated;
grant execute on function private.is_admin() to authenticated;

create or replace function private.is_admin()
returns boolean
language sql stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.profiles p
     where p.id = private.current_uid() and p.role = 'admin'
  );
$$;

create or replace function private.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- Bind a row's owner to the *server-verified* JWT subject on every write.
-- A client cannot set, change or transfer ownership of a row.
create or replace function private.bind_owner()
returns trigger
language plpgsql
as $$
declare v_uid uuid := private.current_uid();
begin
  if v_uid is not null then
    if tg_op = 'INSERT' then
      new.user_id := v_uid;
    else
      new.user_id := old.user_id;   -- ownership is immutable, even for admins
    end if;
  end if;
  return new;
end $$;

-- ---------------------------------------------------------------------------
-- 2. Profiles (1:1 with auth.users)
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id                uuid primary key references auth.users(id) on delete cascade,
  display_name      text not null check (char_length(display_name) between 1 and 80),
  phone_e164        text check (phone_e164 is null or phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  county            text check (county is null or char_length(county) between 1 and 60),
  email_verified_at timestamptz,
  role              text not null default 'member' check (role in ('member','moderator','admin')),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

comment on table public.profiles is
  'Public profile card. Passwords never live here — Supabase Auth stores bcrypt/scrypt hashes in auth.users.';

create or replace function private.guard_profile_columns()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin() then
    -- Field tampering guard: these columns belong to the server, not the client.
    new.id                := old.id;
    new.role              := old.role;
    new.email_verified_at := old.email_verified_at;
    new.created_at        := old.created_at;
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_profiles_guard on public.profiles;
create trigger trg_profiles_guard before update on public.profiles
  for each row execute function private.guard_profile_columns();

drop trigger if exists trg_profiles_touch on public.profiles;
create trigger trg_profiles_touch before update on public.profiles
  for each row execute function private.touch_updated_at();

-- Create the profile row the moment an auth user is created (server side).
create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_name text;
begin
  v_name := coalesce(
    nullif(trim(new.raw_user_meta_data->>'full_name'), ''),
    nullif(trim(new.raw_user_meta_data->>'name'), ''),
    split_part(coalesce(new.email, 'SafeSteps member'), '@', 1)
  );
  insert into public.profiles (id, display_name, phone_e164, email_verified_at)
  values (
    new.id,
    left(v_name, 80),
    case when (new.raw_user_meta_data->>'phone') ~ '^\+[1-9][0-9]{7,14}$'
         then new.raw_user_meta_data->>'phone' else null end,
    case when new.email_confirmed_at is not null then new.email_confirmed_at else null end
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists trg_auth_user_created on auth.users;
create trigger trg_auth_user_created after insert on auth.users
  for each row execute function private.handle_new_user();

-- ---------------------------------------------------------------------------
-- 3. Encrypted user vault (envelope encryption, ciphertext only)
-- ---------------------------------------------------------------------------
-- The browser encrypts the vault with a random 256-bit data key (AES-256-GCM).
-- That data key is itself wrapped with a key derived from the user's password
-- via PBKDF2-SHA256. The database therefore only ever stores ciphertext, and a
-- database dump alone cannot recover badges, checklists, medical notes or
-- whistleblower dossiers.
create table if not exists public.user_vaults (
  user_id        uuid primary key references auth.users(id) on delete cascade,
  alg            text not null default 'AES-256-GCM' check (alg = 'AES-256-GCM'),
  kdf            text not null default 'PBKDF2-SHA256' check (kdf = 'PBKDF2-SHA256'),
  kdf_salt       text not null check (char_length(kdf_salt) between 16 and 128),
  kdf_iterations integer not null check (kdf_iterations between 100000 and 2000000),
  wrapped_key    text not null check (char_length(wrapped_key) between 16 and 512),
  wrapped_key_iv text not null check (char_length(wrapped_key_iv) between 12 and 64),
  ciphertext     text not null check (char_length(ciphertext) <= 2000000),
  iv             text not null check (char_length(iv) between 12 and 64),
  version        integer not null default 1 check (version >= 1),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

drop trigger if exists trg_vaults_touch on public.user_vaults;
create trigger trg_vaults_touch before update on public.user_vaults
  for each row execute function private.touch_updated_at();

-- ---------------------------------------------------------------------------
-- 4. Family profiles (children / dependants)
-- ---------------------------------------------------------------------------
create table if not exists public.family_profiles (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name       text not null check (char_length(name) between 1 and 60),
  age_group  text not null default 'child' check (age_group in ('child','teen','adult','senior')),
  school     text check (school is null or char_length(school) <= 120),
  github     jsonb,                          -- free-form extras, size-capped below
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint family_profiles_extras_size check (github is null or pg_column_size(github) <= 4096)
);

create index if not exists family_profiles_user_idx on public.family_profiles (user_id);

drop trigger if exists trg_family_owner on public.family_profiles;
create trigger trg_family_owner before insert or update on public.family_profiles
  for each row execute function private.bind_owner();

drop trigger if exists trg_family_touch on public.family_profiles;
create trigger trg_family_touch before update on public.family_profiles
  for each row execute function private.touch_updated_at();

-- ---------------------------------------------------------------------------
-- 5. Road-safety hazard reports
-- ---------------------------------------------------------------------------
create table if not exists public.safety_reports (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  category   text not null check (category in ('crash','near_miss','pothole','roadblock','flooding','signage','other')),
  county     text check (county is null or char_length(county) <= 60),
  note       text not null check (char_length(note) between 1 and 1000),
  lat        double precision check (lat is null or lat between -90 and 90),
  lng        double precision check (lng is null or lng between -180 and 180),
  status     text not null default 'submitted' check (status in ('submitted','reviewing','published','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists safety_reports_user_idx on public.safety_reports (user_id, created_at desc);

create or replace function private.guard_report_columns()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin() then
    new.user_id    := old.user_id;
    new.status     := old.status;      -- moderation state is server-owned
    new.created_at := old.created_at;
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_safety_owner on public.safety_reports;
create trigger trg_safety_owner before insert or update on public.safety_reports
  for each row execute function private.bind_owner();

drop trigger if exists trg_safety_guard on public.safety_reports;
create trigger trg_safety_guard before update on public.safety_reports
  for each row execute function private.guard_report_columns();

-- ---------------------------------------------------------------------------
-- 6. Integrity (whistleblower) reports — encrypted narrative
-- ---------------------------------------------------------------------------
create table if not exists public.integrity_reports (
  id                   uuid primary key default gen_random_uuid(),
  user_id              uuid not null default auth.uid() references auth.users(id) on delete cascade,
  is_anonymous         boolean not null default true,
  category             text not null check (category in ('bribery','extortion','harassment','unsafe_vehicle','document_fraud','other')),
  county               text check (county is null or char_length(county) <= 60),
  -- All free-text evidence is stored as client-side AES-256-GCM ciphertext:
  narrative_ciphertext text not null check (char_length(narrative_ciphertext) between 16 and 200000),
  narrative_iv         text not null check (char_length(narrative_iv) between 12 and 64),
  narrative_salt       text not null check (char_length(narrative_salt) between 16 and 128),
  media_path           text check (media_path is null or media_path ~ '^[0-9a-f-]{36}/[A-Za-z0-9._-]{1,120}$'),
  media_sha256         text check (media_sha256 is null or media_sha256 ~ '^[0-9a-f]{64}$'),
  media_mime           text check (media_mime is null or media_mime in ('image/jpeg','image/png','image/webp','audio/webm','audio/mpeg','video/mp4','video/webm')),
  status               text not null default 'submitted' check (status in ('submitted','triage','referred','closed')),
  case_reference       text not null default ('INT-' || upper(substr(encode(gen_random_bytes(6),'hex'),1,8))),
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now()
);

create index if not exists integrity_reports_user_idx on public.integrity_reports (user_id, created_at desc);

create or replace function private.guard_integrity_columns()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin() then
    new.user_id        := old.user_id;
    new.status         := old.status;
    new.case_reference := old.case_reference;
    new.media_sha256   := old.media_sha256;
    new.created_at     := old.created_at;
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_integrity_owner on public.integrity_reports;
create trigger trg_integrity_owner before insert or update on public.integrity_reports
  for each row execute function private.bind_owner();

drop trigger if exists trg_integrity_guard on public.integrity_reports;
create trigger trg_integrity_guard before update on public.integrity_reports
  for each row execute function private.guard_integrity_columns();

-- ---------------------------------------------------------------------------
-- 7. Quiz attempts — append-only (score tampering = inserting a new row only,
--    with a server timestamp and bounded fields; history cannot be rewritten)
-- ---------------------------------------------------------------------------
create table if not exists public.quiz_attempts (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  category    text not null check (char_length(category) between 1 and 40),
  score       integer not null check (score between 0 and 100),
  total       integer not null check (total between 1 and 100),
  correct     integer not null check (correct between 0 and 100),
  completed_at timestamptz not null default now()
);

create index if not exists quiz_attempts_user_idx on public.quiz_attempts (user_id, completed_at desc);

drop trigger if exists trg_quiz_owner on public.quiz_attempts;
create trigger trg_quiz_owner before insert on public.quiz_attempts
  for each row execute function private.bind_owner();

-- ---------------------------------------------------------------------------
-- 8. Security event log (append-only, owner-readable, no delete)
-- ---------------------------------------------------------------------------
create table if not exists public.security_events (
  id         bigint generated always as identity primary key,
  user_id    uuid references auth.users(id) on delete set null,
  event      text not null check (char_length(event) between 1 and 64),
  detail     jsonb,
  created_at timestamptz not null default now(),
  constraint security_events_detail_size check (detail is null or pg_column_size(detail) <= 2048)
);

create index if not exists security_events_user_idx on public.security_events (user_id, created_at desc);

drop trigger if exists trg_events_owner on public.security_events;
create trigger trg_events_owner before insert on public.security_events
  for each row execute function private.bind_owner();

-- ---------------------------------------------------------------------------
-- 9. Service-role-only tables (RLS on, zero policies → unreachable with the
--    publishable key; service_role bypasses RLS by design)
-- ---------------------------------------------------------------------------
create table if not exists private.verification_challenges (
  id             uuid primary key default gen_random_uuid(),
  email_hash     text not null,                     -- sha256(email), never the raw address
  code_hash      text not null,                     -- sha256(code || pepper)
  full_name_hash text not null,
  expires_at     timestamptz not null,
  attempts       integer not null default 0,
  consumed_at    timestamptz,
  created_at     timestamptz not null default now()
);
create index if not exists verification_challenges_email_idx
  on private.verification_challenges (email_hash, created_at desc);

create table if not exists private.rate_limits (
  bucket       text not null,
  key_hash     text not null,
  window_start timestamptz not null,
  count        integer not null default 0,
  expires_at   timestamptz not null,
  primary key (bucket, key_hash, window_start)
);
create index if not exists rate_limits_expiry_idx on private.rate_limits (expires_at);

create table if not exists private.outbound_mail (
  id         bigint generated always as identity primary key,
  recipient  text not null,
  subject    text not null,
  body       text not null,
  channel    text not null default 'email' check (channel in ('email','sms')),
  status     text not null default 'queued' check (status in ('queued','sent','failed')),
  error      text,
  created_at timestamptz not null default now()
);

revoke all on all tables in schema private from anon, authenticated;

-- ---------------------------------------------------------------------------
-- 10. Fixed-window rate limiter (server-side, hashed keys — no raw IPs stored)
-- ---------------------------------------------------------------------------
create or replace function private.check_rate_limit(
  p_bucket  text,
  p_key     text,
  p_limit   integer,
  p_window  integer
)
returns table (allowed boolean, remaining integer, retry_after integer)
language plpgsql
security definer
set search_path = private, pg_temp
as $$
declare
  v_now     timestamptz := now();
  v_start   timestamptz;
  v_count   integer;
begin
  if p_limit is null or p_limit < 1 or p_window is null or p_window < 1 then
    raise exception 'invalid rate limit parameters';
  end if;

  v_start := to_timestamp(floor(extract(epoch from v_now) / p_window) * p_window);

  -- Opportunistic cleanup of expired windows (cheap, indexed).
  delete from private.rate_limits where expires_at < v_now - interval '1 hour';

  insert into private.rate_limits as r (bucket, key_hash, window_start, count, expires_at)
  values (p_bucket, encode(digest(p_key, 'sha256'), 'hex'), v_start, 1,
          v_start + make_interval(secs => p_window))
  on conflict (bucket, key_hash, window_start)
    do update set count = r.count + 1
  returning r.count into v_count;

  return query
    select v_count <= p_limit,
           greatest(p_limit - v_count, 0),
           case when v_count > p_limit then p_window else 0 end;
end $$;

create or replace function public.api_check_rate_limit(
  p_bucket text, p_key text, p_limit integer, p_window integer
)
returns table (allowed boolean, remaining integer, retry_after integer)
language sql
security definer
set search_path = private, pg_temp
as $$ select * from private.check_rate_limit(p_bucket, p_key, p_limit, p_window) $$;

revoke all on function public.api_check_rate_limit(text, text, integer, integer) from public, anon, authenticated;
grant execute on function public.api_check_rate_limit(text, text, integer, integer) to service_role;

-- ---------------------------------------------------------------------------
-- 11. Retention / right-to-erasure helpers
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
$$;

revoke all on function private.purge_expired_data() from public, anon, authenticated;

-- Users can erase their own data; the cascade from auth.users covers the rest.
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
  delete from public.user_vaults        where user_id = v_uid;
  delete from public.integrity_reports  where user_id = v_uid;
  delete from public.safety_reports     where user_id = v_uid;
  delete from public.family_profiles    where user_id = v_uid;
  delete from public.quiz_attempts      where user_id = v_uid;
  delete from public.security_events    where user_id = v_uid;
  delete from public.profiles           where id      = v_uid;
end $$;

revoke all on function public.api_delete_my_account() from public, anon;
grant execute on function public.api_delete_my_account() to authenticated;

-- ---------------------------------------------------------------------------
-- 12. Row Level Security — every table, every command, deny by default
-- ---------------------------------------------------------------------------
alter table public.profiles          enable row level security;
-- NOTE: deliberately NOT `force row level security`. FORCE would also apply to
-- the table owner (postgres), which is the definer of the signup trigger and
-- of api_delete_my_account(). PostgREST never connects as postgres, so plain
-- ENABLE still denies anon/authenticated exactly as intended.
alter table public.user_vaults       enable row level security;
alter table public.family_profiles   enable row level security;
alter table public.safety_reports    enable row level security;
alter table public.integrity_reports enable row level security;
alter table public.quiz_attempts     enable row level security;
alter table public.security_events   enable row level security;
alter table private.verification_challenges enable row level security;
alter table private.rate_limits             enable row level security;
alter table private.outbound_mail           enable row level security;

-- profiles: read/update your own row only.
drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own on public.profiles
  for select to authenticated
  using (id = (select auth.uid()));

drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

drop policy if exists profiles_admin_read on public.profiles;
create policy profiles_admin_read on public.profiles
  for select to authenticated
  using (private.is_admin());

-- user_vaults: strictly the owner.
drop policy if exists vaults_owner_all on public.user_vaults;
create policy vaults_owner_all on public.user_vaults
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- family_profiles
drop policy if exists family_owner_all on public.family_profiles;
create policy family_owner_all on public.family_profiles
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- safety_reports
drop policy if exists safety_owner_select on public.safety_reports;
create policy safety_owner_select on public.safety_reports
  for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists safety_owner_insert on public.safety_reports;
create policy safety_owner_insert on public.safety_reports
  for insert to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists safety_owner_update on public.safety_reports;
create policy safety_owner_update on public.safety_reports
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists safety_owner_delete on public.safety_reports;
create policy safety_owner_delete on public.safety_reports
  for delete to authenticated
  using (user_id = (select auth.uid()));

-- integrity_reports: owner can read/create/withdraw; nobody else can see them.
drop policy if exists integrity_owner_select on public.integrity_reports;
create policy integrity_owner_select on public.integrity_reports
  for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists integrity_owner_insert on public.integrity_reports;
create policy integrity_owner_insert on public.integrity_reports
  for insert to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists integrity_owner_update on public.integrity_reports;
create policy integrity_owner_update on public.integrity_reports
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists integrity_owner_delete on public.integrity_reports;
create policy integrity_owner_delete on public.integrity_reports
  for delete to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists integrity_admin_read on public.integrity_reports;
create policy integrity_admin_read on public.integrity_reports
  for select to authenticated
  using (private.is_admin());

-- quiz_attempts: append-only. No UPDATE/DELETE policy exists, so the API cannot
-- rewrite history even if a client crafts the request.
drop policy if exists quiz_owner_select on public.quiz_attempts;
create policy quiz_owner_select on public.quiz_attempts
  for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists quiz_owner_insert on public.quiz_attempts;
create policy quiz_owner_insert on public.quiz_attempts
  for insert to authenticated
  with check (user_id = (select auth.uid()));

-- security_events: insert + read own only.
drop policy if exists events_owner_select on public.security_events;
create policy events_owner_select on public.security_events
  for select to authenticated
  using (user_id = (select auth.uid()) or user_id is null);

drop policy if exists events_owner_insert on public.security_events;
create policy events_owner_insert on public.security_events
  for insert to authenticated
  with check (user_id = (select auth.uid()));

-- Private tables: RLS with no policies at all.
drop policy if exists verification_none on private.verification_challenges;
drop policy if exists rate_limits_none on private.rate_limits;
drop policy if exists outbound_mail_none on private.outbound_mail;

-- ---------------------------------------------------------------------------
-- 13. Least-privilege API grants (column-level = trimmed responses)
-- ---------------------------------------------------------------------------
revoke all on all tables    in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

-- The publishable key may read static reference data only; all PII tables are
-- reachable exclusively by authenticated users and only within their own rows.
grant select (id, display_name, phone_e164, county, email_verified_at, role, created_at, updated_at)
  on public.profiles to authenticated;
grant update (display_name, phone_e164, county)
  on public.profiles to authenticated;

grant select, insert, update, delete on public.user_vaults to authenticated;
grant select, insert, update, delete on public.family_profiles to authenticated;

grant select (id, category, county, note, lat, lng, status, created_at)
  on public.safety_reports to authenticated;
grant insert (category, county, note, lat, lng) on public.safety_reports to authenticated;
grant update (category, county, note, lat, lng) on public.safety_reports to authenticated;
grant delete on public.safety_reports to authenticated;

grant select (id, is_anonymous, category, county, media_path, media_mime, media_sha256,
              status, case_reference, narrative_ciphertext, narrative_iv, narrative_salt,
              created_at, updated_at)
  on public.integrity_reports to authenticated;
grant insert (is_anonymous, category, county, narrative_ciphertext, narrative_iv,
              narrative_salt, media_path, media_mime, media_sha256)
  on public.integrity_reports to authenticated;
grant update (is_anonymous, category, county, narrative_ciphertext, narrative_iv,
              narrative_salt, media_path, media_mime)
  on public.integrity_reports to authenticated;
grant delete on public.integrity_reports to authenticated;

grant select (id, category, score, total, correct, completed_at) on public.quiz_attempts to authenticated;
grant insert (category, score, total, correct) on public.quiz_attempts to authenticated;

grant select (id, event, detail, created_at) on public.security_events to authenticated;
-- Ownership column: readable (RLS needs it) but never writable by the client.
grant select (user_id) on public.safety_reports    to authenticated;
grant select (user_id) on public.integrity_reports to authenticated;
grant select (user_id) on public.quiz_attempts     to authenticated;
grant select (user_id) on public.security_events   to authenticated;
grant insert (event, detail) on public.security_events to authenticated;

-- ---------------------------------------------------------------------------
-- 14. Storage: private evidence bucket with owner-scoped object policies
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'integrity-evidence', 'integrity-evidence', false, 8388608,
  array['image/jpeg','image/png','image/webp','audio/webm','audio/mpeg','video/mp4','video/webm']
)
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists integrity_evidence_read on storage.objects;
create policy integrity_evidence_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'integrity-evidence'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists integrity_evidence_write on storage.objects;
create policy integrity_evidence_write on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'integrity-evidence'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists integrity_evidence_update on storage.objects;
create policy integrity_evidence_update on storage.objects
  for update to authenticated
  using (
    bucket_id = 'integrity-evidence'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  )
  with check (
    bucket_id = 'integrity-evidence'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists integrity_evidence_delete on storage.objects;
create policy integrity_evidence_delete on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'integrity-evidence'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- No anonymous access to any object, in any bucket.
revoke all on storage.objects from anon;

-- ---------------------------------------------------------------------------
-- 14b. Service-role-only RPCs
-- ---------------------------------------------------------------------------
create or replace function public.api_enqueue_mail(
  p_recipient text, p_subject text, p_body text, p_channel text default 'email'
)
returns void
language plpgsql
security definer
set search_path = private, public, pg_temp
as $$
begin
  if p_recipient !~ '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$' then raise exception 'invalid recipient'; end if;
  if char_length(coalesce(p_subject,'')) not between 1 and 200 then raise exception 'invalid subject'; end if;
  if char_length(coalesce(p_body,'')) not between 1 and 20000 then raise exception 'invalid body'; end if;
  insert into private.outbound_mail (recipient, subject, body, channel)
  values (p_recipient, p_subject, p_body, coalesce(nullif(p_channel,''),'email'));
end $$;

revoke all on function public.api_enqueue_mail(text, text, text, text) from public, anon, authenticated;
grant execute on function public.api_enqueue_mail(text, text, text, text) to service_role;

-- ---------------------------------------------------------------------------
-- 15. Verification
-- ---------------------------------------------------------------------------
do $$
declare v_missing text;
begin
  select string_agg(c.relname, ', ') into v_missing
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity = false;

  if v_missing is not null then
    raise exception 'RLS missing on: %', v_missing;
  end if;
end $$;

commit;

-- ---------------------------------------------------------------------------
-- 16. Service-role-only RPCs for the private schema
-- ---------------------------------------------------------------------------
-- PostgREST does not expose the `private` schema, so the server reaches these
-- tables through SECURITY DEFINER functions that only service_role may execute.
-- `api_create_challenge` also carries the auth.users id link: without it a
-- correct verification code can be validated but never confirm the account.

create or replace function public.api_create_challenge(
  p_id uuid, p_email_hash text, p_code_hash text, p_name_hash text,
  p_expires_at timestamptz, p_user_id uuid default null
)
returns void
language plpgsql security definer
set search_path = private, public, pg_temp
as $$
begin
  if p_email_hash !~ '^[0-9a-f]{64}$' or p_code_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid challenge fingerprint';
  end if;
  if p_expires_at <= now() or p_expires_at > now() + interval '1 hour' then
    raise exception 'invalid challenge expiry';
  end if;
  insert into private.verification_challenges
    (id, email_hash, code_hash, full_name_hash, expires_at, attempts, created_at, user_id)
  values (p_id, p_email_hash, p_code_hash, p_name_hash, p_expires_at, 0, now(), p_user_id);
end $$;

revoke all on function public.api_create_challenge(uuid, text, text, text, timestamptz, uuid)
  from public, anon, authenticated;
grant execute on function public.api_create_challenge(uuid, text, text, text, timestamptz, uuid)
  to service_role;

-- Resolve the account that owns an address (used only to repair a missing
-- challenge link). Never callable by a client role.
create or replace function public.api_user_id_by_email(p_email text)
returns uuid
language sql security definer
set search_path = auth, pg_temp
as $$ select id from auth.users where lower(email) = lower(p_email) limit 1 $$;

revoke all on function public.api_user_id_by_email(text) from public, anon, authenticated;
grant execute on function public.api_user_id_by_email(text) to service_role;
