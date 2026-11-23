-- CloudVault Concierge — Initial Schema (001_init_schema.sql)
-- Zero-Password-Storage Hybrid Cloud Relay & Audit Ledger

create extension if not exists pgcrypto;

-- 1. Operator PC Nodes (stores ONLY the RSA-4096 public key, NEVER the private key)
create table if not exists public.operator_nodes (
  id uuid primary key default gen_random_uuid(),
  label text not null,
  public_key_pem text not null,
  key_fingerprint_sha256 text not null unique,
  last_heartbeat_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

-- 2. Concierge Migration Jobs
create table if not exists public.migration_jobs (
  id uuid primary key default gen_random_uuid(),
  operator_node_id uuid not null references public.operator_nodes(id) on delete restrict,
  job_code text not null unique,
  customer_display_name text not null,
  service_mode text not null check (service_mode in ('copy_only', 'move_free_space', 'move_and_export')),
  status text not null default 'CREATED' check (
    status in (
      'CREATED',
      'AWAITING_CREDENTIALS',
      'CREDENTIALS_RECEIVED',
      'AWAITING_2FA_ICLOUD',
      'SCANNING_CATALOG',
      'YEAR_SELECTION',
      'DOWNLOADING_VERIFYING',
      'AWAITING_2FA_GOOGLE',
      'UPLOADING_GPHOTOS',
      'AUDIT_READY',
      'AWAITING_5LOCK_APPROVAL',
      'CLEANING_ICLOUD',
      'PURGING_PDPA',
      'COMPLETED',
      'FAILED',
      'CANCELLED'
    )
  ),
  token_hash_sha256 text not null unique,
  target_years int[] not null default '{}',
  album_prefix text not null default 'iCloud_Archive_Google',
  total_files int not null default 0 check (total_files >= 0),
  downloaded_files int not null default 0 check (downloaded_files >= 0),
  verified_sha256_files int not null default 0 check (verified_sha256_files >= 0),
  uploaded_files int not null default 0 check (uploaded_files >= 0),
  total_bytes bigint not null default 0 check (total_bytes >= 0),
  reclaimed_bytes bigint not null default 0 check (reclaimed_bytes >= 0),
  five_lock_approved_by_customer_at timestamptz,
  pdpa_purged_at timestamptz,
  pdpa_purge_certificate jsonb,
  telemetry_snapshot jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 3. Single-Use E2E Encrypted Credential Envelopes (Shredded immediately after RAM decryption)
create table if not exists public.credential_envelopes (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.migration_jobs(id) on delete cascade,
  provider text not null check (provider in ('icloud', 'google_photos')),
  key_fingerprint_sha256 text not null,
  wrapped_key_b64 text not null,
  iv_b64 text not null,
  ciphertext_b64 text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

-- 4. Short-Lived Interactive 2FA OTP Challenges (5-min TTL, auto-shredded on consume)
create table if not exists public.otp_challenges (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.migration_jobs(id) on delete cascade,
  provider text not null check (provider in ('icloud', 'google_photos')),
  prompt_message text not null,
  encrypted_otp_envelope jsonb,
  status text not null default 'WAITING_CUSTOMER' check (status in ('WAITING_CUSTOMER', 'SUBMITTED', 'CONSUMED', 'EXPIRED')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- 5. Per-Year Telemetry & 1:1 Audit Summary
create table if not exists public.job_year_progress (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.migration_jobs(id) on delete cascade,
  year int not null check (year >= 1990 and year <= 2100),
  catalog_count int not null default 0 check (catalog_count >= 0),
  downloaded_count int not null default 0 check (downloaded_count >= 0),
  verified_count int not null default 0 check (verified_count >= 0),
  uploaded_count int not null default 0 check (uploaded_count >= 0),
  cleaned_count int not null default 0 check (cleaned_count >= 0),
  total_bytes bigint not null default 0 check (total_bytes >= 0),
  gphotos_album_title text,
  gphotos_album_url text,
  five_lock_status jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  unique(job_id, year)
);

-- Performance & Foreign Key Indexes
create index if not exists idx_migration_jobs_operator_node_id on public.migration_jobs(operator_node_id);
create index if not exists idx_migration_jobs_status on public.migration_jobs(status);
create index if not exists idx_credential_envelopes_job_id_expires on public.credential_envelopes(job_id, expires_at);
create index if not exists idx_otp_challenges_job_id_status on public.otp_challenges(job_id, status, expires_at);
create index if not exists idx_job_year_progress_job_id on public.job_year_progress(job_id);

-- Automatic updated_at Trigger (explicit empty search_path for security hardening)
create or replace function public.cloudvault_set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

do $$
begin
  if not exists (select 1 from pg_trigger where tgname = 'trg_migration_jobs_updated_at') then
    create trigger trg_migration_jobs_updated_at
      before update on public.migration_jobs
      for each row execute function public.cloudvault_set_updated_at();
  end if;
  if not exists (select 1 from pg_trigger where tgname = 'trg_job_year_progress_updated_at') then
    create trigger trg_job_year_progress_updated_at
      before update on public.job_year_progress
      for each row execute function public.cloudvault_set_updated_at();
  end if;
end;
$$;

-- Strict Row Level Security (Deny-by-default for anon/authenticated)
-- All customer requests go through validated Next.js API Routes (timingSafeEqual token hash check)
-- and all operator requests use SUPABASE_SERVICE_ROLE_KEY strictly on the local PC / server.
alter table public.operator_nodes enable row level security;
alter table public.migration_jobs enable row level security;
alter table public.credential_envelopes enable row level security;
alter table public.otp_challenges enable row level security;
alter table public.job_year_progress enable row level security;
