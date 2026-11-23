# ADR-0002: Zero-Password-Storage E2E Envelope Encryption (`RSA-OAEP-SHA256` + `AES-256-GCM`)

- **Status**: Accepted
- **Date**: 2026-11-23

## Context
Customers engaging a concierge migration service must temporarily authorize Apple iCloud and Google Photos sessions (including live 6-digit `2FA` OTPs). Sending plaintext passwords over LINE chat or storing decryptable passwords in a cloud database violates PDPA data-minimization principles and creates catastrophic breach blast radius.

## Decision
Implement a **Zero-Password-Storage One-Time E2E Encrypted Handoff**:
1. The Operator PC generates an `RSA-4096` keypair stored locally (`workbench/.keys/operator_private.pem`, owner-only ACL) and publishes ONLY `public_key_pem` + `key_fingerprint_sha256` to `operator_nodes`.
2. The Customer Job Portal (`web/src/lib/crypto-envelope.ts`) encrypts credentials and 2FA OTPs strictly inside the customer's browser using WebCrypto `AES-256-GCM` (ephemeral 32-byte key + 12-byte IV) wrapped with `RSA-OAEP` (`SHA-256`).
3. Supabase stores ONLY opaque ciphertext (`credential_envelopes` TTL `15 min`, `otp_challenges` TTL `5 min`).
4. `workbench/crypto_vault.py` pulls the ciphertext, immediately issues `DELETE` on Supabase, decrypts strictly in RAM, initializes the isolated session, and zeroes mutable plaintext `bytearray` buffers.

## Consequences
- Neither Vercel logs nor Supabase administrators can ever read customer passwords or 2FA codes.
- Envelopes typically exist in cloud storage for `< 5 seconds` and are cryptographically bound to a specific Operator Node's `key_fingerprint_sha256`.
