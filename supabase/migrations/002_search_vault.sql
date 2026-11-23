-- CloudVault Concierge — Zero-Knowledge Encrypted AI Search Vault Schema (002_search_vault.sql)
-- Architecture: One-Way Public-Key E2EE (RSA-OAEP-256 + AES-256-GCM) + Client-Side Encrypted Index Bundle
-- Storage: Encrypted WebP thumbnails (~2.5 GB/100k photos) & gzip-encrypted index bundle stored in Cloudflare R2 (Free 10 GB) or PC Encrypted NAS Tunnel;
--          Supabase stores ONLY vault metadata, public key, and passphrase-encrypted private key blob (Zero-Knowledge At-Rest).

create table if not exists public.search_vaults (
  id uuid primary key default gen_random_uuid(),
  job_id uuid references public.migration_jobs(id) on delete set null,
  vault_code text not null unique,
  owner_display_name text not null,
  owner_email_hash_sha256 text,
  access_token_hash_sha256 text not null unique,
  status text not null default 'AWAITING_CUSTOMER_KEY' check (
    status in (
      'AWAITING_CUSTOMER_KEY',
      'KEY_REGISTERED',
      'INDEXING',
      'READY',
      'LOCKED',
      'REVOKED'
    )
  ),
  -- Customer-generated RSA-OAEP public key (PEM) for One-Way PC -> Customer encryption
  customer_public_key_pem text,
  customer_key_fingerprint_sha256 text,
  -- Passphrase-protected (PBKDF2-SHA256 600k iter + AES-256-GCM) customer private key blob;
  -- NEVER decryptable by Operator PC or Supabase.
  encrypted_private_key_blob jsonb,
  -- Random 32-byte AES-256-GCM vault data key wrapped ONE-WAY with customer_public_key_pem
  wrapped_vault_key_b64 text,
  -- Encrypted object references (Cloudflare R2 Free 10 GB or PC Encrypted NAS Tunnel)
  storage_backend text not null default 'cloudflare_r2' check (
    storage_backend in ('cloudflare_r2', 'pc_tunnel_nas', 'supabase_storage')
  ),
  storage_bucket text,
  index_object_key text,
  index_sha256 text,
  index_size_bytes bigint not null default 0 check (index_size_bytes >= 0),
  thumb_prefix text,
  -- Pluggable Media Source Adapter (Google Photos Shared Album today -> Home NAS / Immich tomorrow)
  media_source_type text not null default 'google_photos_shared' check (
    media_source_type in ('google_photos_shared', 'google_photos_private', 'nas_immich', 'local_hdd')
  ),
  media_source_config jsonb not null default '{}'::jsonb,
  -- Customer's AES-256-GCM encrypted custom person names (e.g., person_001 -> "คุณแม่")
  encrypted_person_labels_blob jsonb,
  -- Non-sensitive aggregate counters for UI status only (zero PII, zero plaintext OCR/faces)
  total_assets int not null default 0 check (total_assets >= 0),
  total_faces int not null default 0 check (total_faces >= 0),
  total_ocr_assets int not null default 0 check (total_ocr_assets >= 0),
  total_thumb_bytes bigint not null default 0 check (total_thumb_bytes >= 0),
  plaintext_purged_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Foreign Key & Lookup Indexes (following supabase-postgres-best-practices)
create index if not exists idx_search_vaults_job_id on public.search_vaults(job_id);
create index if not exists idx_search_vaults_status on public.search_vaults(status);

-- Automatic updated_at Trigger reusing hardened public.cloudvault_set_updated_at()
do $$
begin
  if not exists (select 1 from pg_trigger where tgname = 'trg_search_vaults_updated_at') then
    create trigger trg_search_vaults_updated_at
      before update on public.search_vaults
      for each row execute function public.cloudvault_set_updated_at();
  end if;
end;
$$;

-- Strict Row Level Security (Deny-by-default for anon/authenticated)
-- All customer requests go through validated Next.js API Routes (SHA-256 + timingSafeEqual token check)
-- and all operator writes use SUPABASE_SERVICE_ROLE_KEY strictly on server / local Workbench.
alter table public.search_vaults enable row level security;
