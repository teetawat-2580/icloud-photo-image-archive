# GEMINI.md — CloudVault Concierge Project Guidelines & Architecture Invariants

> **Project**: `CloudVault Concierge` (`icloud photo image archive`)  
> **GitHub Repository**: `https://github.com/teetawat-2580/icloud-photo-image-archive.git`  
> **Vercel Project (Git Auto-Deploy)**: `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`, Root Directory: `web`, Node `24.x`)  
> **Architecture**: Hybrid Concierge Web App — Public Cloud Trust Portal (`Next.js 15` on Vercel + `Supabase` Free Tier Postgres/RLS Relay `zhgyiljmzsjbvlgozpfu`) + Local Operator PC Workbench (`Python FastAPI` + `Node.js Dedicated Chrome Profile CDP` on `http://127.0.0.1:8790`)  
> **Default Staging Root**: `D:\MigrationJobs` (strictly outside OneDrive / `C:\`)

---

## 1. Non-Negotiable Security & Privacy Invariants

1. **Zero-Password-Storage E2E Handoff (OWASP A02)**:
   - Customer iCloud and Google credentials are encrypted exclusively in the customer's browser via WebCrypto (`RSA-OAEP-SHA256` + ephemeral 256-bit `AES-256-GCM`) using the Operator PC's `public_key_pem`.
   - `workbench/.keys/operator_private.pem` NEVER leaves the Operator PC and MUST NEVER be uploaded to Git, Vercel, or Supabase.
   - Upon RAM decryption in `workbench/crypto_vault.py`, the Workbench IMMEDIATELY executes `DELETE` on the Supabase `credential_envelopes` / `otp_challenges` row and overwrites mutable plaintext `bytearray` buffers.
2. **Strict Localhost Binding (OWASP A01 / A05)**:
   - `workbench/server.py` MUST bind strictly to `127.0.0.1:8790`. Binding to `0.0.0.0` is strictly forbidden.
3. **Deny-by-Default RLS & Constant-Time Token Verification**:
   - All 5 Supabase tables (`operator_nodes`, `migration_jobs`, `credential_envelopes`, `otp_challenges`, `job_year_progress`) have Row Level Security enabled with zero `anon` read/write policies.
   - Customer browsers access data exclusively via Next.js Route Handlers (`/api/jobs/[jobId]/*`), which verify `SHA-256(token)` using `crypto.timingSafeEqual` and never leak `token_hash_sha256` or ciphertext envelopes.
4. **Per-Customer Isolated Sandboxes & Dedicated Chrome Automation Profiles**:
   - Every job runs inside a path-confined sandbox (`D:\MigrationJobs\<job_id>\`, validated with `Path.resolve().is_relative_to(staging_root)`).
   - Every Google Photos upload launches an isolated Chrome instance via `--user-data-dir=<sandbox>\chrome_profile` and dynamic CDP port `9301..9399` (`0` Chrome `Allow` popups, `0%` cross-customer or personal Chrome contamination).
5. **5-Lock Fail-Closed iCloud Cleanup Protocol**:
   - No iCloud asset may ever be deleted unless ALL 5 locks pass AND `five_lock_approved_by_customer_at` is set by the customer on the Job Portal:
     - `Lock 1`: 100% uploaded to Google Photos (`uploaded_count == catalog_count`).
     - `Lock 2`: 100% verified 64-character `SHA-256` checksum.
     - `Lock 3`: 1:1 CloudKit `recordName` & original filename match.
     - `Lock 4`: Whole-year completeness (`missing == 0`).
     - `Lock 5`: Customer digital sign-off + iCloud soft-delete ONLY (`isDeleted = 1` into `Recently Deleted 30 days`).
6. **3-Layer Personal Album Isolation Guard & Strict Single-Line Album Menu Isolation**:
   - Customer's personal Google Photos albums (any album not starting with `album_prefix`) are strictly blacklisted from archival sweeps (`personal_album_isolation_guard.js`).
   - Google Photos `+` menu actions MUST match single-line exact `Album` only — hard-blocking `Animation`, `Collage`, `Highlight video`, `Shared album`, and `Partner sharing`.
7. **1-Click PDPA Purge Certificate**:
   - After job completion, the operator triggers `PDPA Purge` to terminate the job's Chrome process, wipe all local staging media, `.icloud_session`, and `chrome_profile`, confirm `0` remaining files, sign an RSA-PSS-SHA256 Purge Certificate, and publish it to Supabase for 24/7 customer download.

---

## 2. Build, Test & Operational Rules

1. **Build Speed Optimization (Golden Rule #1)**:
   - `web/next.config.mjs` sets `typescript: { ignoreBuildErrors: true }` and `eslint: { ignoreDuringBuilds: true }` for fast Vercel cloud builds (`25–35s`). Run `npx tsc --noEmit` and `npm test` locally before every deploy.
2. **Anti-Hang Testing (Golden Rule #2)**:
   - Node tests MUST use `--test-timeout=15000 --test-force-exit`.
   - Python tests run via `python -m pytest -q workbench/tests`.
3. **SSoT 4-File Sync (Golden Rule #4)**:
   - Keep `GEMINI.md`, `technical_specification.md`, `ARCHITECTURE.md`, and `CHANGELOG.md` synchronized whenever contracts, schemas, or invariants change.
4. **No Subprocess `shell=True`**:
   - Never invoke subprocesses with `shell=True` or interpolated command strings in Python or Node.js.
