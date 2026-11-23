# Technical Specification — CloudVault Concierge

> **Version**: `0.1.1`  
> **Workspace**: `icloud photo image archive` (`https://github.com/teetawat-2580/icloud-photo-image-archive.git`)  
> **Cloud Web Deployment**: Vercel Project `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`, Root Directory `web`, Node `24.x`)  
> **Cloud Database**: Supabase Project `zhgyiljmzsjbvlgozpfu` (`ap-southeast-1`, Singapore; supports both modern `sb_secret_...` and legacy JWT `service_role` keys)

---

## 1. Product Scope & Service Modes

CloudVault Concierge is a commercial Done-For-You photo migration platform moving selected years from Apple iCloud Photos to Google Photos (and optional local HDD/NAS export) with forensic `1:1 SHA-256` accountability.

### Supported Service Modes (`service_mode`)
1. `copy_only`: Copy selected years from iCloud $\rightarrow$ verify `64-char SHA-256` $\rightarrow$ upload to year-labeled Google Photos albums (`< 20,000 items/album`) $\rightarrow$ publish `1:1 SHA-256 Audit Report` $\rightarrow$ execute `1-Click PDPA Purge`.
2. `move_free_space`: Everything in `copy_only` + wait for customer digital approval on Job Portal (`AWAITING_5LOCK_APPROVAL`) $\rightarrow$ verify all 5 locks $\rightarrow$ iCloud CloudKit soft-delete (`isDeleted = 1`, `Recently Deleted 30 days`) $\rightarrow$ `1-Click PDPA Purge`.
3. `move_and_export`: Everything in `move_free_space` (or `copy_only`) + `2-Level Year/Month` export preserving `100%` original filenames (`IMG_XXXX`) and standalone HTML Audit Report.

---

## 2. Shared Cross-Language E2E Cryptographic Contract

Both `web/src/lib/crypto-envelope.ts` (Browser WebCrypto) and `workbench/crypto_vault.py` (Python `cryptography`) strictly implement:

- **Asymmetric Keypair**: `RSA-4096` (public exponent `65537`), stored locally at `workbench/.keys/operator_private.pem` (owner-only Windows ACL) and `operator_public.pem`.
- **Key Fingerprint**: `key_fingerprint_sha256` = lowercase 64-char hex `SHA-256` of UTF-8 `public_key_pem` bytes.
- **Envelope Encryption**:
  1. Generate ephemeral 256-bit (`32-byte`) AES key + random 96-bit (`12-byte`) IV.
  2. Encrypt UTF-8 JSON payload using `AES-256-GCM` with 128-bit (`16-byte`) authentication tag appended to ciphertext.
  3. Wrap the raw 32-byte AES key using `RSA-OAEP` (`SHA-256` hash + `MGF1(SHA-256)` + empty label).
  4. Transmit opaque JSON:
     ```json
     {
       "version": 1,
       "alg": "RSA-OAEP-256+A256GCM",
       "key_fingerprint_sha256": "<64-char hex>",
       "wrapped_key_b64": "<base64>",
       "iv_b64": "<base64>",
       "ciphertext_b64": "<base64>"
     }
     ```
- **PDPA Purge Certificate Signing**:
  - Canonical JSON (`sort_keys=True`, compact separators `(",", ":")`) signed with `RSA-PSS` (`MGF1(SHA-256)`, `SHA-256`) using the Operator's local private key, verifiable offline against `operator_nodes.public_key_pem`.

---

## 3. Cloud API Contracts (`web/src/app/api/jobs/[jobId]/*`)

All endpoints require a valid high-entropy customer token (`Authorization: Bearer <token>` or `?t=<token>`), validated server-side via `SHA-256(token)` + `crypto.timingSafeEqual`.

| Endpoint | Method | Purpose & Validation |
| :--- | :--- | :--- |
| `/api/jobs/[jobId]/status` | `GET` | Returns sanitized job telemetry, per-year progress rows, active `otp_challenges` metadata (without secrets), and `operator_public_key_pem` + `key_fingerprint_sha256`. |
| `/api/jobs/[jobId]/envelope` | `POST` | Accepts a single-use E2E encrypted credential envelope (`provider`: `icloud` or `google_photos`), enforces `< 32 KB` size ceiling, key fingerprint match, and 15-min TTL (`expires_at`). |
| `/api/jobs/[jobId]/otp` | `POST` | Submits an encrypted 6-digit 2FA OTP payload against an active `WAITING_CUSTOMER` challenge (`5-min TTL`). |
| `/api/jobs/[jobId]/approve-cleanup` | `POST` | Records `five_lock_approved_by_customer_at = now()` when `service_mode != 'copy_only'` and `status == 'AWAITING_5LOCK_APPROVAL'`. |

---

## 4. Local Operator Workbench API (`http://127.0.0.1:8790`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/operator/health` | `GET` | Returns local node status, `key_fingerprint_sha256`, `staging_root`, and Supabase relay mode (`online` / `offline_local`). |
| `/api/operator/jobs` | `GET` / `POST` | Lists active jobs or creates a new Concierge Job (`32-byte` URL token returned once, `SHA-256` token hash saved to Supabase, local sandbox initialized). |
| `/api/operator/jobs/{job_id}/consume-envelope` | `POST` | Pulls & immediately `DELETE`s credential envelope from Supabase, decrypts in RAM, zeroes mutable buffers, and optionally connects isolated `pyicloud` session. |
| `/api/operator/jobs/{job_id}/request-otp` | `POST` | Creates a short-lived (`5-min TTL`) interactive `otp_challenges` prompt pushed to the Customer Portal. |
| `/api/operator/jobs/{job_id}/consume-otp` | `POST` | Pulls & immediately `DELETE`s submitted encrypted 6-digit OTP challenge and decrypts strictly in RAM. |
| `/api/operator/jobs/{job_id}/verify-five-locks` | `POST` | Evaluates Locks 1–5 + `five_lock_approved_by_customer_at` fail-closed before CloudKit soft-delete (`isDeleted = 1`). |
| `/api/operator/jobs/{job_id}/launch-cdp-upload` | `POST` | Dispatches `workbench/cdp/gphotos_uploader.js` (`shell=False`) in an isolated Dedicated Chrome Profile (`9301..9399`). |
| `/api/operator/jobs/{job_id}/pdpa-purge` | `POST` | Terminates job Chrome instance, wipes sandbox files/sessions/profile, confirms `0` files left, signs RSA-PSS PDPA Purge Certificate, and publishes to Supabase. |

---

## 5. Job Lifecycle State Machine

`CREATED` $\rightarrow$ `AWAITING_CREDENTIALS` $\rightarrow$ `CREDENTIALS_RECEIVED` $\rightarrow$ `AWAITING_2FA_ICLOUD` $\rightarrow$ `SCANNING_CATALOG` $\rightarrow$ `YEAR_SELECTION` $\rightarrow$ `DOWNLOADING_VERIFYING` $\rightarrow$ `AWAITING_2FA_GOOGLE` $\rightarrow$ `UPLOADING_GPHOTOS` $\rightarrow$ `AUDIT_READY` $\rightarrow$ (`AWAITING_5LOCK_APPROVAL` $\rightarrow$ `CLEANING_ICLOUD` if `move_*`) $\rightarrow$ `PURGING_PDPA` $\rightarrow$ `COMPLETED`.
