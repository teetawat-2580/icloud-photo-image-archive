# Changelog — CloudVault Concierge

All notable changes to this project are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] - 2026-11-23

### Added
- **Local Operator Workbench UI — Zero-Knowledge AI Search Vault Tab & Cloudflare R2 Setup Wizard (`http://127.0.0.1:8790/#vaults`)**:
  - Added primary workspace switcher tabs (`Migration Jobs` / `AI Search Vault`) in `workbench/ui/index.html` + `workbench/ui/styles.css` and modular safe-DOM controller `workbench/ui/vault-ui.js` (zero `innerHTML`, `OWASP A03` compliant).
  - Added 1-click **Cloudflare R2 (`Free 10 GB · $0 Egress`) Setup & Live Connection Test Wizard** (`GET /api/operator/vaults/r2-status`, `POST /api/operator/vaults/r2-config`, `POST /api/operator/vaults/r2-test`) saving validated keys into local gitignored `workbench/.env` + `web/.env.local` and activating them live in RAM without restart.
  - Added `PATCH /api/operator/vaults/{vault_id}/media-source` and interactive Year $\rightarrow$ Album URL / Home NAS editor directly inside the Workbench UI.
  - Updated `CloudflareR2Config.from_env()` in `workbench/r2_storage_client.py` to accept both `R2_ACCOUNT_ID` and `R2_ENDPOINT_URL` seamlessly and added `head_bucket()` live connectivity verification.

## [0.2.0] - 2026-11-23

### Added
- **Zero-Knowledge Encrypted AI Search Vault (Flagship Add-on — `ADR-0005`)**:
  - **Supabase Live Schema (`supabase/migrations/002_search_vault.sql`)**: Applied `public.search_vaults` with strict deny-by-default RLS, FK/status indexes (`idx_search_vaults_job_id`, `idx_search_vaults_status`), and hardened `trg_search_vaults_updated_at` trigger on project `zhgyiljmzsjbvlgozpfu`.
  - **Local PC Transient AI Worker (`workbench/`)**:
    - `workbench/search_vault_crypto.py`: One-Way Public-Key E2EE (`RSA-OAEP-SHA256` + `AES-256-GCM` + `gzip` + `PBKDF2-SHA256` 600k iterations) with explicit RAM key zeroing and verified binary parity against Browser WebCrypto.
    - `workbench/media_source_adapter.py`: Pluggable Media Source Adapter decoupling `asset_sha256` from destination links (`google_photos_shared` $\rightarrow$ `google_photos_private` / `nas_immich` / `local_hdd`) with `remap_index_media_source` zero-reindex migration.
    - `workbench/r2_storage_client.py`: Zero-dependency pure-Python AWS SigV4 client for Cloudflare R2 (Free 10 GB / `$0` egress) plus path-confined `LocalEncryptedNasStorage` (`pc_tunnel_nas` fallback).
    - `workbench/search_vault_indexer.py`: Transient AI indexing pipeline supporting optional `InsightFace (buffalo_l)` cosine clustering, `RapidOCR / PP-OCRv5` Thai+English OCR, `Multilingual CLIP` bilingual tagging, Pillow WebP thumbnails, ciphertext-only publish, and automatic plaintext purge (`plaintext_purged_at`).
    - `workbench/search_vault_routes.py` & `workbench/supabase_relay.py`: Added `/api/operator/vaults`, `/api/operator/vaults/{vault_id}/build-index`, and `/api/operator/vaults/{vault_id}/blobs/{object_key:path}` on `127.0.0.1:8790`.
  - **Browser WebCrypto Client & Next.js Portal (`web/`)**:
    - `web/src/lib/search-vault-crypto.ts`, `web/src/lib/search-vault-engine.ts`, `web/src/lib/vault-auth.ts`, `web/src/lib/search-vault-demo.ts`: Pure Browser WebCrypto keygen/unlock/decrypt, `< 20 ms` in-RAM Thai OCR + multi-face AND + tag + year search engine, OWASP A03 XSS-safe highlight segmentation & URL allowlisting, scoped object-key validation, and pure-Node Cloudflare R2 SigV4 proxy.
    - 4 token-authenticated API routes: `/api/vaults/[vaultId]/metadata`, `/api/vaults/[vaultId]/register-keys`, `/api/vaults/[vaultId]/person-labels`, and `/api/vaults/[vaultId]/blob`.
    - Responsive mobile-first UI (`/vault/[vaultId]`, `VaultPassphraseGate`, `EncryptedSearchVault`) with lazy-decrypted thumbnail grid (`IntersectionObserver` + `ObjectURL` cleanup), inline E2EE person renaming, Pluggable Media Source switcher (`Google Photos` $\leftrightarrow$ `Home NAS / Immich`), 1-tap `Lock Vault` RAM wipe, interactive Live Zero-Knowledge Sandbox (`/vault/demo-family-archive?demo=1`), and Landing Page callout (`web/src/app/page.tsx`).
  - **Automated Verification**: Added `workbench/tests/test_search_vault.py` (`30/30` Python pytest passing), `web/tests/search-vault.test.mjs` (`8/8` Node WebCrypto/Engine/Auth tests passing), cross-language Python $\leftrightarrow$ WebCrypto binary parity verification, and `docs/adr/0005-zero-knowledge-encrypted-search-vault.md`.

## [0.1.1] - 2026-11-23

### Added
- **GitHub + Vercel CI/CD Integration**:
  - Connected repository `https://github.com/teetawat-2580/icloud-photo-image-archive.git` to Vercel project `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`) with `rootDirectory = "web"`, `framework = "nextjs"`, `nodeVersion = "24.x"`, `ssoProtection = preview` (public Production access for customers), and Vercel Secret Env Vars for Supabase `zhgyiljmzsjbvlgozpfu`.

### Fixed
- **`web/src/app/layout.tsx` & `web/tailwind.config.ts`**: Switched Google Fonts (`Plus Jakarta Sans`, `Noto Sans Thai`, `JetBrains Mono`) from build-time `next/font/google` scraper to deterministic preconnected `<link rel="stylesheet">` tags to eliminate `next/font` Google loader regex failures on Vercel Linux builds.

### Changed
- **`workbench/server.py`**: Added automatic `_load_workbench_env()` loader for `workbench/.env` on startup without overriding explicit environment variables or unit-test injections.
- **`workbench/supabase_relay.py`**: Added compatibility for modern Supabase Secret Keys (`sb_secret_...`) using `apikey`-only PostgREST authentication alongside legacy JWT `service_role` keys.
- **`web/` Token Parameter Compatibility**: Accepted both `?t=` (canonical) and `?token=` query parameters across `web/src/app/job/[jobId]/page.tsx`, `web/src/lib/job-auth.ts`, and `web/src/components/JobLinkOpener.tsx`.

## [0.1.0] - 2026-11-23

### Added
- **Supabase Cloud Relay (`zhgyiljmzsjbvlgozpfu`, `ap-southeast-1`)**:
  - Provisioned live Postgres schema `supabase/migrations/001_init_schema.sql` with 5 strict-RLS tables (`operator_nodes`, `migration_jobs`, `credential_envelopes`, `otp_challenges`, `job_year_progress`), performance indexes, and hardened `cloudvault_set_updated_at()` trigger.
- **Public Cloud Trust Portal (`web/` — Next.js 15 App Router)**:
  - High-trust Editorial Digital Vault Landing Page (`/`) and Customer Job Portal (`/job/[jobId]?t=<token>`).
  - Pure browser WebCrypto E2E encryption (`web/src/lib/crypto-envelope.ts`: `RSA-OAEP-SHA256` + `AES-256-GCM`) and server-side constant-time token verification (`web/src/lib/job-auth.ts`: `SHA-256` + `crypto.timingSafeEqual`).
  - Modular Customer Portal components (`EncryptedHandoffCard`, `LiveOtpPromptBanner`, `MigrationProgressBoard`, `AuditApprovalAndPdpaCard`) and 4 token-authenticated API routes.
- **Local Operator PC Workbench (`workbench/` — Python FastAPI)**:
  - Strictly localhost-bound (`127.0.0.1:8790`) Operator Control Panel with 1-click Job Creation & LINE Link generator, live telemetry relay, `O(log N)` iCloud engine, `5-Lock` fail-closed verification cleaner, and `1-Click PDPA Purge` with RSA-PSS-SHA256 signed Purge Certificate.
  - Windows 1-click launchers (`start_workbench.bat`, `start_workbench_silent.vbs`).
- **Isolated Dedicated Chrome CDP Uploader (`workbench/cdp/`)**:
  - Per-customer Dedicated Chrome Profile manager (`--user-data-dir=<sandbox>/chrome_profile`, dynamic ports `9301..9399`, `0` Chrome `Allow` prompts).
  - Generalized `3-Layer Personal Album Isolation Guard`, `Strict Single-Line Album Menu Item Isolation`, and `100% Selection Completeness Gate`.
- **Root SSoT Documentation & ADRs**:
  - Created `GEMINI.md`, `technical_specification.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `README.md`, `GLOSSARY.md`, and `docs/adr/0001..0004-*.md`.
