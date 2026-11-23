# System Architecture — CloudVault Concierge

> **Topology**: Hybrid Cloud Relay + Local Operator PC Workbench  
> **GitHub & CI/CD**: `https://github.com/teetawat-2580/icloud-photo-image-archive.git` $\rightarrow$ Vercel Project `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`, Root Directory: `web`, Node `24.x`)  
> **Cloud Tier**: Vercel (Next.js 15 App Router) + Supabase Free Tier (`zhgyiljmzsjbvlgozpfu`, `ap-southeast-1`)  
> **Local Execution**: Windows Operator PC (`http://127.0.0.1:8790`) + Isolated Staging Root (`D:\MigrationJobs`)

---

## 1. End-to-End Hybrid Architecture

```mermaid
flowchart LR
    subgraph Customer["Customer Browser / iPhone"]
        PORTAL["Job Portal\n/job/jobId?t=token"]
        WEBCRYPTO["WebCrypto Engine\nRSA-OAEP-SHA256 + AES-256-GCM"]
    end

    subgraph Cloud["Cloud Layer (Vercel + Supabase)"]
        NEXT["Next.js 15 App Router\nLanding + Job Portal + API Routes"]
        SB["Supabase Postgres + Strict RLS\n(Ciphertext Only + Audit Ledger)"]
    end

    subgraph OperatorPC["Local Operator PC (127.0.0.1:8790)"]
        FASTAPI["FastAPI Control Panel\nserver.py + Local UI"]
        VAULT["Crypto Vault\nRSA-4096 private.pem (RAM Only)"]
        ICLOUD["iCloud Engine (pyicloud)\nO(log N) Scan + SHA-256 + 5-Lock"]
        CDP["Node.js Dedicated Chrome CDP\n--user-data-dir per job (Ports 9301-9399)"]
        SANDBOX["Isolated Sandbox\nD:\\MigrationJobs\\<job_id>\\"]
    end

    PORTAL --> WEBCRYPTO
    WEBCRYPTO -->|"HTTPS Ciphertext Envelope"| NEXT
    NEXT -->|"timingSafeEqual Token Check"| SB
    SB <-->|"Outbound HTTPS Poll (No Port Forward)"| FASTAPI
    FASTAPI --> VAULT
    VAULT -->|"Decrypted in RAM + Immediate Shred"| ICLOUD
    FASTAPI --> CDP
    ICLOUD --> SANDBOX
    SANDBOX --> CDP
```

---

## 2. Component Boundaries

| Directory | Runtime | Responsibility | Trust Boundary |
| :--- | :--- | :--- | :--- |
| `web/` | Next.js 15 (Vercel / Node 24) | Public Landing Page (`/`), Customer Job Portal (`/job/[jobId]`), WebCrypto client encryption, and token-validated API routes. | Holds `SUPABASE_SERVICE_ROLE_KEY` strictly on server routes. Never sees plaintext credentials or Operator private key. |
| `supabase/migrations/` | PostgreSQL 17 (Supabase) | 5 strict-RLS tables (`operator_nodes`, `migration_jobs`, `credential_envelopes`, `otp_challenges`, `job_year_progress`). | Zero `anon` read/write policies. Stores only opaque ciphertext (`< 5s` typical lifetime) and audit metadata. |
| `workbench/` | Python 3.14 (FastAPI + `pyicloud` + `cryptography`) | Local Control Panel (`127.0.0.1:8790`), local RSA-4096 keypair vault, sandbox confinement, `O(log N)` iCloud downloader, `5-Lock` cleaner, and `PDPA Purge` signer. | Highest trust zone — runs strictly on Operator PC (`127.0.0.1`). |
| `workbench/cdp/` | Node.js 24 (`playwright` / CDP) | Per-customer Dedicated Chrome Profile launcher (`9301..9399`), `3-Layer Personal Album Isolation Guard`, `Strict Single-Line Album Menu Isolation`, and Google Photos batch uploader. | Isolated per-job `--user-data-dir`; zero access to operator's personal Chrome profile. |

---

## 3. Per-Customer Isolated Sandbox Layout

```text
D:\MigrationJobs\
└── <job_id>\
    ├── media\
    │   └── <YYYY>\<MM>\IMG_XXXX.HEIC
    ├── manifest\
    │   ├── catalog_index.json
    │   ├── sha256_ledger.json
    │   └── upload_checkpoint.json
    ├── .icloud_session\            # Isolated Apple cookies/tokens for this job only
    ├── chrome_profile\             # Isolated Chrome --user-data-dir (0 Allow prompts)
    └── export\                     # Optional 2-level Year/Month export + HTML Audit Report
```

When `POST /api/operator/jobs/{job_id}/pdpa-purge` runs:
1. Terminates any Chrome process bound to `<job_id>`'s dedicated profile.
2. Recursively deletes `D:\MigrationJobs\<job_id>\` (with path-traversal confinement check).
3. Verifies `0` files and `0` bytes remain on disk.
4. Signs the `pdpa_purge_certificate` payload with `RSA-PSS-SHA256` and persists it to Supabase `migration_jobs`.
