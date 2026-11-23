# ADR-0001: Hybrid Cloud Relay + Local Operator PC Workbench

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
Migrating `100–600 GB` of Apple iCloud Photos into Google Photos requires sustained multi-hour transfers, large local disk staging for `64-char SHA-256` verification, and interactive Chromium automation. Running this entirely on serverless cloud infrastructure (Vercel Functions / Cloud Run) incurs high bandwidth/egress bills, strict function timeout ceilings, and IP blocks from Apple CloudKit. Conversely, exposing a local PC web server directly to the public internet fails behind Thai ISP CGNAT, requires port-forwarding/DDNS, and goes offline whenever the operator turns off the PC.

## Decision
Adopt a **Hybrid Concierge Architecture**:
1. **Public Cloud Layer (`web/` on Vercel + `Supabase` Free Tier)**: Hosts the Landing Page (`/`), Customer Job Portal (`/job/[jobId]?t=<token>`), and strict-RLS Postgres relay tables at \$0/month cloud cost. Available 24/7 for customers to inspect live telemetry, submit E2E-encrypted credentials/2FA OTPs, approve `5-Lock` cleanup, and download Audit Reports & PDPA Purge Certificates.
2. **Local Operator PC Workbench (`workbench/` on `http://127.0.0.1:8790`)**: Performs all heavy downloads, `SHA-256` verification, Dedicated Chrome CDP uploads, `5-Lock` cleanups, and `PDPA Purge` inside `D:\MigrationJobs\<job_id>\`, communicating with Supabase exclusively via outbound HTTPS polling (zero inbound ports required).

## Consequences
- Zero ISP CGNAT/router configuration required.
- Customer portals and PDPA Purge Certificates stay online 24/7 even after the Operator PC powers down.
- Cloud bandwidth cost stays effectively \$0 because binary media files never traverse Vercel or Supabase.
