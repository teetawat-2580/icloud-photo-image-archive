# ADR-0005: Zero-Knowledge Encrypted AI Search Vault (One-Way Public-Key E2EE + Cloudflare R2 + Pluggable Media Source Adapter)

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
When photos are viewed through Google Photos Shared Album links (`/share/...`), Google Photos does not index People/Faces or OCR text for viewers (AI Search only operates inside an authenticated user's own primary Library). At the same time, storing 600 GB of full-resolution family originals on a home PC or centralized cloud server is expensive and creates severe PDPA Section 26 (biometric face embeddings) and privacy risks if stored in plaintext.

We need a commercial-grade add-on for `CloudVault Concierge` that:
1. Enables instant Face Recognition (`InsightFace`), Thai/English OCR (`RapidOCR / PP-OCRv5`), and Semantic Tag (`Multilingual CLIP`) search over `~100,000+` archived photos using only lightweight WebP thumbnails (`~2.5 GB`), opening full-resolution originals from Google Photos today.
2. Enforces **Zero-Knowledge At-Rest**: after transient AI indexing finishes on the Operator PC, neither the PC owner, Supabase, nor Cloudflare R2 can decrypt thumbnails, OCR text, face clusters, custom person names, or media links.
3. Stays within `$0/month` free tiers (Supabase Free Tier for metadata + Cloudflare R2 Free 10 GB / `$0` egress or Local PC Tunnel NAS for opaque `.enc` blobs).
4. Decouples the AI index from Google Photos so customers can migrate full-resolution originals to a Home NAS / `Immich` in the future with zero AI re-indexing.

## Decision
1. **One-Way Public-Key E2EE (`RSA-OAEP-SHA256` + `AES-256-GCM`)**:
   - The customer sets a Vault Passphrase strictly in their browser (`web/src/components/VaultPassphraseGate.tsx`).
   - WebCrypto generates an `RSA-OAEP` keypair and encrypts the PKCS#8 private key using `PBKDF2-SHA256` (`600,000` iterations, AAD `cloudvault:customer_private_key:v1`) before uploading ONLY `customer_public_key_pem` and `encrypted_private_key_blob` to `public.search_vaults`.
   - The Local PC AI Worker (`workbench/search_vault_indexer.py`) processes media transiently, generates an ephemeral 32-byte `vault_data_key`, wraps it ONE-WAY to `customer_public_key_pem`, encrypts every WebP thumbnail (`AAD = "${vaultId}:${thumbKey}"`) and gzipped Search Index Bundle (`AAD = "${vaultId}:index_bundle"`), uploads ciphertext only, zeroes `vault_data_key` in RAM, and deletes temporary plaintext files (`plaintext_purged_at`).
2. **Client-Side Encrypted Index Bundle (`< 20 ms` RAM Search)**:
   - On unlock, the customer's browser derives the KEK from their passphrase, unlocks a non-extractable RSA-OAEP `CryptoKey`, unwraps a non-extractable AES-256-GCM `vault_data_key`, fetches & decrypts `index_bundle.json.gz.enc` in RAM, and performs all Thai/English OCR, multi-face AND, tag, and year filtering strictly client-side (`web/src/lib/search-vault-engine.ts`). Supabase never receives plaintext search terms or person names (`encrypted_person_labels_blob` is AES-256-GCM encrypted in browser RAM).
3. **Cloudflare R2 Free 10 GB + PC Tunnel NAS Fallback (Pure SigV4)**:
   - Implemented lightweight zero-SDK AWS SigV4 clients in both Python (`workbench/r2_storage_client.py`) and Node.js (`web/src/lib/vault-auth.ts`) to keep Vercel build times fast (`< 35s`) and avoid Supabase Free Tier's 1 GB Storage ceiling.
   - All blob proxy requests (`/api/vaults/[vaultId]/blob?key=...`) enforce strict object-key confinement (`vaults/<vaultId>/index_bundle.json.gz.enc` or `vaults/<vaultId>/thumbs/<safe>.enc`) to prevent cross-vault IDOR and path traversal.
4. **Pluggable Media Source Adapter**:
   - Every asset in the encrypted index is keyed by immutable `sha256` + `filename` + `captured_at`, decoupled from `media_ref` (`google_photos_shared`, `google_photos_private`, `nas_immich`, `local_hdd`). Switching destinations (`remap_index_media_source`) updates links with zero AI re-indexing, and the browser enforces a strict HTTPS URL allowlist (`resolveSafeMediaUrl`) blocking `javascript:`, `data:`, and untrusted redirect hosts.

## Consequences
- Preserves CloudVault Concierge's core PDPA Zero-Retention promise (`plaintext_purged_at` + Zero-Knowledge At-Rest).
- Eliminates PDPA biometric exposure on cloud servers because raw InsightFace embeddings are discarded after clustering and only opaque AES-256-GCM ciphertext is persisted.
- Requires customers to remember their Vault Passphrase (by cryptographic design, lost passphrases cannot be recovered by the operator and require re-indexing from originals).
