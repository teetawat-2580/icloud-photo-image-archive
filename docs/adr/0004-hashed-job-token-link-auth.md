# ADR-0004: High-Entropy Hashed Job Link Authentication (No Payment Gateway Bloat in v1.0)

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
Concierge photo migration clients typically contact the operator via LINE Official Account, Facebook Messenger, or phone, agree on scope/years, and want a frictionless 1-tap tracking link on their iPhone without registering yet another username/password account. Payment gateway integration (Stripe/PromptPay webhook billing) adds regulatory overhead not needed for v1.0 concierge onboarding.

## Decision
Use **Operator-Issued High-Entropy Job Links**:
1. When the operator creates a job on `http://127.0.0.1:8790`, the Workbench generates a 32-byte cryptographically random token (`secrets.token_urlsafe(32)`), stores ONLY `SHA-256(token)` in `migration_jobs.token_hash_sha256`, and produces a copy-pasteable link: `https://<app-domain>/job/<job_id>?t=<raw_token>`.
2. Every Next.js API route (`/api/jobs/[jobId]/*`) hashes the presented token with `SHA-256` and compares it against `token_hash_sha256` using `crypto.timingSafeEqual`.
3. Supabase RLS denies all `anon` access so raw links cannot be bypassed by querying PostgREST directly.

## Consequences
- Zero-friction customer UX (1 tap from LINE opens their live portal).
- Even a read-only database dump cannot forge valid customer portal URLs because raw tokens are never stored.
- Payment gateways can be cleanly added in v2.0 without modifying the job authentication or encryption contracts.
