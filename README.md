# CloudVault Concierge

**Hybrid Concierge iCloud Photos $\rightarrow$ Google Photos Migration Platform**  
Built for Done-For-You / Concierge photo archiving with **Zero-Password-Storage E2E Encryption**, **`1:1 SHA-256` Forensic Verification**, **`5-Lock` Safety Space Reclaim**, **Per-Customer Isolated Chrome Profiles**, and **Signed PDPA Purge Certificates**.

---

## Project Layout

- `web/` — Public Cloud Web App (`Next.js 15` App Router, Vercel-ready) with Landing Page (`/`) and Customer Job Portal (`/job/[jobId]?t=<token>`).
- `workbench/` — Local Operator PC Workbench (`Python FastAPI` on `http://127.0.0.1:8790`) + Operator Control Panel UI.
- `workbench/cdp/` — Isolated Per-Customer Dedicated Chrome Profile CDP Uploader (`Node.js 24`).
- `supabase/migrations/` — Strict-RLS Postgres schema (`001_init_schema.sql`).
- `docs/adr/` — Architectural Decision Records (`ADR-0001` through `ADR-0004`).

---

## Quick Start (Local Operator PC + Cloud Portal)

### 1. Paste `SUPABASE_SERVICE_ROLE_KEY` (1-Time Secret Setup)
Your Supabase project **`cloudvault-concierge`** (`zhgyiljmzsjbvlgozpfu`, Singapore `ap-southeast-1`) is already provisioned with the schema applied.

1. Open Supabase Dashboard $\rightarrow$ Project `cloudvault-concierge` $\rightarrow$ **Project Settings** $\rightarrow$ **API Keys**.
2. Copy the `service_role` secret key (NEVER commit it to Git or expose it with `NEXT_PUBLIC_`).
3. Paste it into both:
   - `web/.env.local` $\rightarrow$ `SUPABASE_SERVICE_ROLE_KEY=...`
   - `workbench/.env` $\rightarrow$ `SUPABASE_SERVICE_ROLE_KEY=...`

### 2. Launch Local Operator Workbench (`http://127.0.0.1:8790`)
Double-click `start_workbench.bat` (or run silently via `start_workbench_silent.vbs`):
```powershell
python -m uvicorn workbench.server:app --host 127.0.0.1 --port 8790
```

### 3. Run Locally or Deploy Automatically via GitHub $\rightarrow$ Vercel
```powershell
cd web
npm run dev
# Visit http://localhost:3000
```
- **GitHub Repository**: `https://github.com/teetawat-2580/icloud-photo-image-archive.git`
- **Vercel Auto-Deploy Project**: `icloud-photo-image-archive` (`prj_GBsPsqGtEJdVLRxPDZ0JUDuMALRH`, Root Directory: `web`, Node `24.x`). Every `git push` to `main` automatically builds and deploys Production on Vercel.

---

## Automated Verification Commands

```powershell
# 1. Python Workbench + E2E Crypto + 5-Lock + PDPA Purge tests
python -m pytest -q workbench/tests

# 2. Node.js Dedicated Chrome CDP + 3-Layer Isolation Guard tests
node --test --test-timeout=15000 --test-force-exit workbench/cdp/tests/gphotos_worker.test.js

# 3. Next.js Web App unit tests, type-check & production build
cd web
npm test
npx tsc --noEmit
npm run build
```
