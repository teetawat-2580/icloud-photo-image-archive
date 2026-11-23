# Changelog — CloudVault Concierge

All notable changes to this project are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.1] - 2026-11-23

### Added
- **GitHub + Vercel CI/CD Integration**:
  - Connected repository `https://github.com/teetawat-2580/icloud-photo-image-archive.git` to Vercel project `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`) with `rootDirectory = "web"`, `framework = "nextjs"`, `nodeVersion = "24.x"`, `ssoProtection = preview` (public Production access for customers), and Vercel Secret Env Vars for Supabase `zhgyiljmzsjbvlgozpfu`.

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
