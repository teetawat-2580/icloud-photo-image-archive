/**
 * CloudVault Concierge — Server-Side Zero-Knowledge Search Vault Authentication,
 * Scoped Object-Key Validation, and Pure-Node Cloudflare R2 SigV4 Client.
 *
 * Security Invariants (OWASP A01 / A02 / A03 / A10):
 * - Vault authentication uses SHA-256 + `crypto.timingSafeEqual` against `access_token_hash_sha256`.
 * - `access_token_hash_sha256` is NEVER returned in public API responses.
 * - Object keys are strictly confined to `vaults/<vaultId>/index_bundle.json.gz.enc` or
 *   `vaults/<vaultId>/thumbs/<safe-name>.enc` (prevents cross-vault IDOR and path traversal).
 * - Zero heavyweight AWS SDK dependencies (`Golden Rule #1`: Build Speed Optimization 25–35s).
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type {
  EncryptedPersonLabelsBlob,
  EncryptedPrivateKeyBlob,
} from './search-vault-crypto';

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VAULT_CODE_REGEX = /^[A-Za-z0-9_-]{4,64}$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const SAFE_THUMB_FILENAME_REGEX = /^[A-Za-z0-9._-]{1,128}\.enc$/;

const EMPTY_PAYLOAD_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export type SearchVaultStatus =
  | 'AWAITING_CUSTOMER_KEY'
  | 'KEY_REGISTERED'
  | 'INDEXING'
  | 'READY'
  | 'LOCKED'
  | 'REVOKED';

export type SearchVaultStorageBackend =
  | 'cloudflare_r2'
  | 'pc_tunnel_nas'
  | 'supabase_storage';

export type SearchVaultMediaSourceType =
  | 'google_photos_shared'
  | 'google_photos_private'
  | 'nas_immich'
  | 'local_hdd';

export interface SearchVaultPublicMetadata {
  id: string;
  job_id: string | null;
  vault_code: string;
  owner_display_name: string;
  status: SearchVaultStatus;
  customer_public_key_pem: string | null;
  customer_key_fingerprint_sha256: string | null;
  encrypted_private_key_blob: EncryptedPrivateKeyBlob | null;
  wrapped_vault_key_b64: string | null;
  storage_backend: SearchVaultStorageBackend;
  storage_bucket: string | null;
  index_object_key: string | null;
  index_sha256: string | null;
  index_size_bytes: number;
  thumb_prefix: string | null;
  media_source_type: SearchVaultMediaSourceType;
  media_source_config: Record<string, unknown>;
  encrypted_person_labels_blob: EncryptedPersonLabelsBlob | null;
  total_assets: number;
  total_faces: number;
  total_ocr_assets: number;
  total_thumb_bytes: number;
  plaintext_purged_at: string | null;
  created_at: string;
  updated_at: string;
}

export const VAULT_NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
} as const;

function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

function isStrictBase64(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > maxLength) return false;
  if (value.length % 4 !== 0) return false;
  return BASE64_REGEX.test(value);
}

export function verifyVaultToken(rawToken: string, storedHash: string): boolean {
  if (typeof rawToken !== 'string' || typeof storedHash !== 'string') {
    return false;
  }
  if (rawToken.length === 0 || rawToken.length > 512) {
    return false;
  }
  const normalizedStored = storedHash.trim().toLowerCase();
  if (!SHA256_HEX_REGEX.test(normalizedStored)) {
    return false;
  }
  const computedBuf = Buffer.from(sha256Hex(rawToken), 'hex');
  const storedBuf = Buffer.from(normalizedStored, 'hex');
  if (computedBuf.length !== storedBuf.length) {
    return false;
  }
  return timingSafeEqual(computedBuf, storedBuf);
}

export function extractVaultToken(request: Request): string | null {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer.length > 0) return bearer;
  }
  const headerToken =
    request.headers.get('x-vault-token')?.trim() ||
    request.headers.get('x-job-token')?.trim();
  if (headerToken && headerToken.length > 0) return headerToken;

  try {
    const url = new URL(request.url);
    const queryToken =
      url.searchParams.get('t')?.trim() ||
      url.searchParams.get('token')?.trim();
    if (queryToken && queryToken.length > 0) return queryToken;
  } catch {
    return null;
  }
  return null;
}

/**
 * Validate and confine an encrypted blob object key strictly to the authorized `vaultId`.
 * Prevents cross-vault IDOR, directory traversal (`..`), and non-encrypted file reads.
 */
export function validateVaultObjectKey(
  vaultId: string,
  rawKey: string
): string | null {
  if (typeof vaultId !== 'string' || typeof rawKey !== 'string') {
    return null;
  }
  const cleanVaultId = vaultId.trim();
  if (!UUID_REGEX.test(cleanVaultId) && !VAULT_CODE_REGEX.test(cleanVaultId)) {
    return null;
  }

  const key = rawKey.trim();
  if (
    !key ||
    key.length > 512 ||
    key.startsWith('/') ||
    key.includes('\\') ||
    key.includes('..') ||
    key.includes('\0') ||
    /%2e/i.test(key) ||
    /%2f/i.test(key)
  ) {
    return null;
  }

  const expectedPrefix = `vaults/${cleanVaultId}/`;
  if (!key.startsWith(expectedPrefix)) {
    return null;
  }

  const remainder = key.slice(expectedPrefix.length);
  if (remainder === 'index_bundle.json.gz.enc') {
    return key;
  }

  if (remainder.startsWith('thumbs/')) {
    const filename = remainder.slice('thumbs/'.length);
    if (!filename.includes('/') && SAFE_THUMB_FILENAME_REGEX.test(filename)) {
      return key;
    }
  }

  return null;
}

export interface ValidatedKeyRegistration {
  customer_public_key_pem: string;
  customer_key_fingerprint_sha256: string;
  encrypted_private_key_blob: EncryptedPrivateKeyBlob;
}

export function validateVaultKeyRegistrationPayload(
  input: unknown
): { ok: true; data: ValidatedKeyRegistration } | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Key registration payload must be a JSON object.' };
  }
  const rec = input as Record<string, unknown>;

  if (typeof rec.customer_public_key_pem !== 'string') {
    return { ok: false, error: 'customer_public_key_pem is required.' };
  }
  const pem = rec.customer_public_key_pem.replace(/\r\n/g, '\n').trim();
  if (
    !pem.startsWith('-----BEGIN PUBLIC KEY-----') ||
    !pem.endsWith('-----END PUBLIC KEY-----') ||
    pem.length > 8192
  ) {
    return { ok: false, error: 'customer_public_key_pem must be a valid SPKI PEM public key.' };
  }

  if (
    typeof rec.customer_key_fingerprint_sha256 !== 'string' ||
    !SHA256_HEX_REGEX.test(rec.customer_key_fingerprint_sha256.trim())
  ) {
    return {
      ok: false,
      error: 'customer_key_fingerprint_sha256 must be a 64-char SHA-256 hex digest.',
    };
  }

  const blob = rec.encrypted_private_key_blob;
  if (!blob || typeof blob !== 'object' || Array.isArray(blob)) {
    return { ok: false, error: 'encrypted_private_key_blob is required.' };
  }
  const b = blob as Record<string, unknown>;
  if (b.version !== 1) {
    return { ok: false, error: 'encrypted_private_key_blob.version must equal 1.' };
  }
  if (b.kdf !== 'PBKDF2-SHA256') {
    return { ok: false, error: 'encrypted_private_key_blob.kdf must be PBKDF2-SHA256.' };
  }
  if (
    typeof b.iterations !== 'number' ||
    !Number.isInteger(b.iterations) ||
    b.iterations < 100_000 ||
    b.iterations > 2_000_000
  ) {
    return {
      ok: false,
      error: 'PBKDF2 iterations must be an integer between 100,000 and 2,000,000.',
    };
  }
  if (b.alg !== 'AES-256-GCM') {
    return { ok: false, error: 'encrypted_private_key_blob.alg must be AES-256-GCM.' };
  }
  if (!isStrictBase64(b.salt_b64, 64) || Buffer.from(b.salt_b64, 'base64').length !== 16) {
    return { ok: false, error: 'salt_b64 must decode to exactly 16 bytes.' };
  }
  if (!isStrictBase64(b.iv_b64, 32) || Buffer.from(b.iv_b64, 'base64').length !== 12) {
    return { ok: false, error: 'iv_b64 must decode to exactly 12 bytes.' };
  }
  if (!isStrictBase64(b.ciphertext_b64, 32768)) {
    return { ok: false, error: 'ciphertext_b64 must be valid base64 (max 32768 chars).' };
  }

  return {
    ok: true,
    data: {
      customer_public_key_pem: `${pem}\n`,
      customer_key_fingerprint_sha256: rec.customer_key_fingerprint_sha256.trim().toLowerCase(),
      encrypted_private_key_blob: {
        version: 1,
        kdf: 'PBKDF2-SHA256',
        iterations: b.iterations,
        alg: 'AES-256-GCM',
        salt_b64: b.salt_b64,
        iv_b64: b.iv_b64,
        ciphertext_b64: b.ciphertext_b64,
      },
    },
  };
}

export function validateEncryptedPersonLabelsPayload(
  input: unknown
): { ok: true; blob: EncryptedPersonLabelsBlob } | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'encrypted_person_labels_blob must be a JSON object.' };
  }
  const b = input as Record<string, unknown>;
  if (b.version !== 1 || b.alg !== 'AES-256-GCM') {
    return { ok: false, error: 'Unsupported encrypted_person_labels_blob version or algorithm.' };
  }
  if (!isStrictBase64(b.iv_b64, 32) || Buffer.from(b.iv_b64, 'base64').length !== 12) {
    return { ok: false, error: 'iv_b64 must decode to exactly 12 bytes.' };
  }
  if (!isStrictBase64(b.ciphertext_b64, 262144)) {
    return { ok: false, error: 'ciphertext_b64 must be valid base64 (max 256 KB).' };
  }
  return {
    ok: true,
    blob: {
      version: 1,
      alg: 'AES-256-GCM',
      iv_b64: b.iv_b64,
      ciphertext_b64: b.ciphertext_b64,
    },
  };
}

function encodeRfc3986Path(pathname: string): string {
  return pathname
    .split('/')
    .map((segment) =>
      encodeURIComponent(decodeURIComponent(segment)).replace(
        /[!'()*]/g,
        (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
      )
    )
    .join('/');
}

/**
 * Pure-Node AWS SigV4 request signer for Cloudflare R2 (Zero AWS SDK bloat).
 */
export function buildR2SigV4Headers(params: {
  method: 'GET' | 'HEAD' | 'PUT' | 'DELETE';
  url: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
  payloadHash?: string;
  amzDate?: string;
}): Record<string, string> {
  const parsed = new URL(params.url);
  const region = params.region ?? 'auto';
  const service = 's3';
  const payloadHash = params.payloadHash ?? EMPTY_PAYLOAD_SHA256;
  const amzDate =
    params.amzDate ??
    new Date()
      .toISOString()
      .replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const host = parsed.host;
  const canonicalUri = encodeRfc3986Path(parsed.pathname || '/');

  const queryPairs = Array.from(parsed.searchParams.entries()).sort(([a], [b]) =>
    a.localeCompare(b)
  );
  const canonicalQuery = queryPairs
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

  const canonicalRequest = [
    params.method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = hmacSha256(`AWS4${params.secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = createHmac('sha256', kSigning)
    .update(stringToSign, 'utf8')
    .digest('hex');

  return {
    Authorization: `AWS4-HMAC-SHA256 Credential=${params.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
  };
}

function getVaultSupabaseAdmin(): SupabaseClient {
  if (typeof window !== 'undefined') {
    throw new Error('getVaultSupabaseAdmin() cannot run in a browser context.');
  }
  const url =
    process.env.NEXT_PUBLIC_SUPABASE_URL?.trim() ||
    process.env.SUPABASE_URL?.trim();
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  if (!url || !key) {
    throw new Error('SUPABASE_NOT_CONFIGURED');
  }
  return createClient(url, key, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

type DbSearchVaultRow = SearchVaultPublicMetadata & {
  access_token_hash_sha256: string;
};

export type AuthVaultResult =
  | {
      ok: true;
      vault: SearchVaultPublicMetadata;
      supabase: SupabaseClient;
    }
  | {
      ok: false;
      status: number;
      code: string;
      message: string;
    };

export async function authenticateVaultRequest(
  vaultIdParam: string,
  rawToken: string | null
): Promise<AuthVaultResult> {
  const cleanId = typeof vaultIdParam === 'string' ? vaultIdParam.trim() : '';
  const isUuid = UUID_REGEX.test(cleanId);
  if (!isUuid && !VAULT_CODE_REGEX.test(cleanId)) {
    return {
      ok: false,
      status: 400,
      code: 'INVALID_VAULT_ID',
      message: 'Vault identifier format is invalid.',
    };
  }
  if (!rawToken || rawToken.length > 512) {
    return {
      ok: false,
      status: 401,
      code: 'MISSING_VAULT_TOKEN',
      message: 'Valid vault access token is required.',
    };
  }

  let supabase: SupabaseClient;
  try {
    supabase = getVaultSupabaseAdmin();
  } catch {
    return {
      ok: false,
      status: 503,
      code: 'BACKEND_NOT_CONFIGURED',
      message: 'Supabase server credentials are not configured.',
    };
  }

  const lookupCol = isUuid ? 'id' : 'vault_code';
  const { data, error } = await supabase
    .from('search_vaults')
    .select(
      [
        'id',
        'job_id',
        'vault_code',
        'owner_display_name',
        'access_token_hash_sha256',
        'status',
        'customer_public_key_pem',
        'customer_key_fingerprint_sha256',
        'encrypted_private_key_blob',
        'wrapped_vault_key_b64',
        'storage_backend',
        'storage_bucket',
        'index_object_key',
        'index_sha256',
        'index_size_bytes',
        'thumb_prefix',
        'media_source_type',
        'media_source_config',
        'encrypted_person_labels_blob',
        'total_assets',
        'total_faces',
        'total_ocr_assets',
        'total_thumb_bytes',
        'plaintext_purged_at',
        'created_at',
        'updated_at',
      ].join(',')
    )
    .eq(lookupCol, cleanId)
    .maybeSingle();

  if (error) {
    return {
      ok: false,
      status: 500,
      code: 'DB_QUERY_ERROR',
      message: 'Failed to load search vault record.',
    };
  }
  if (!data) {
    return {
      ok: false,
      status: 404,
      code: 'VAULT_NOT_FOUND',
      message: 'Search vault not found.',
    };
  }

  const row = data as unknown as DbSearchVaultRow;
  if (!verifyVaultToken(rawToken, row.access_token_hash_sha256)) {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_VAULT_TOKEN',
      message: 'Vault access token verification failed.',
    };
  }
  if (row.status === 'REVOKED') {
    return {
      ok: false,
      status: 403,
      code: 'VAULT_REVOKED',
      message: 'This search vault has been revoked.',
    };
  }

  const { access_token_hash_sha256: _redacted, ...publicVault } = row;
  void _redacted;

  return {
    ok: true,
    vault: {
      ...publicVault,
      index_size_bytes: Number(publicVault.index_size_bytes ?? 0),
      total_thumb_bytes: Number(publicVault.total_thumb_bytes ?? 0),
      media_source_config:
        publicVault.media_source_config &&
        typeof publicVault.media_source_config === 'object'
          ? publicVault.media_source_config
          : {},
    },
    supabase,
  };
}

/**
 * Fetch an opaque AES-256-GCM encrypted blob from Cloudflare R2 (SigV4) or
 * the operator's encrypted PC Tunnel NAS fallback. Server never decrypts bytes.
 */
export async function fetchEncryptedVaultBlob(
  vault: SearchVaultPublicMetadata,
  validatedObjectKey: string
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; status: number; error: string }> {
  if (vault.storage_backend === 'cloudflare_r2') {
    const endpoint = process.env.R2_ENDPOINT_URL?.trim().replace(/\/+$/, '');
    const bucket = vault.storage_bucket?.trim() || process.env.R2_BUCKET_NAME?.trim();
    const accessKeyId = process.env.R2_ACCESS_KEY_ID?.trim();
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY?.trim();

    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
      return {
        ok: false,
        status: 503,
        error: 'Cloudflare R2 credentials are not configured on this server.',
      };
    }

    const parsedEndpoint = new URL(endpoint);
    if (parsedEndpoint.protocol !== 'https:') {
      return {
        ok: false,
        status: 500,
        error: 'R2_ENDPOINT_URL must use HTTPS.',
      };
    }

    const targetUrl = `${endpoint}/${encodeURIComponent(bucket)}/${validatedObjectKey}`;
    const headers = buildR2SigV4Headers({
      method: 'GET',
      url: targetUrl,
      accessKeyId,
      secretAccessKey,
    });

    const res = await fetch(targetUrl, {
      method: 'GET',
      headers,
      cache: 'no-store',
    });

    if (res.status === 404) {
      return { ok: false, status: 404, error: 'Encrypted vault object not found in R2.' };
    }
    if (!res.ok) {
      return {
        ok: false,
        status: 502,
        error: `Cloudflare R2 fetch failed with HTTP ${res.status}.`,
      };
    }

    return { ok: true, bytes: new Uint8Array(await res.arrayBuffer()) };
  }

  if (vault.storage_backend === 'pc_tunnel_nas') {
    const baseUrl = process.env.PC_TUNNEL_NAS_BASE_URL?.trim().replace(/\/+$/, '');
    if (!baseUrl) {
      return {
        ok: false,
        status: 503,
        error: 'PC_TUNNEL_NAS_BASE_URL is not configured.',
      };
    }
    const parsedBase = new URL(baseUrl);
    const isLocalDev =
      parsedBase.protocol === 'http:' &&
      (parsedBase.hostname === '127.0.0.1' || parsedBase.hostname === 'localhost');
    if (parsedBase.protocol !== 'https:' && !isLocalDev) {
      return {
        ok: false,
        status: 500,
        error: 'PC_TUNNEL_NAS_BASE_URL must use HTTPS (or localhost in dev).',
      };
    }

    const targetUrl = `${baseUrl}/api/operator/vaults/${encodeURIComponent(vault.id)}/blobs/${validatedObjectKey}`;
    const headers: Record<string, string> = {};
    const bearer = process.env.PC_TUNNEL_NAS_BEARER_TOKEN?.trim();
    if (bearer) {
      headers.Authorization = `Bearer ${bearer}`;
    }

    const res = await fetch(targetUrl, {
      method: 'GET',
      headers,
      cache: 'no-store',
    });
    if (res.status === 404) {
      return { ok: false, status: 404, error: 'Encrypted blob not found on PC Tunnel NAS.' };
    }
    if (!res.ok) {
      return {
        ok: false,
        status: 502,
        error: `PC Tunnel NAS fetch failed with HTTP ${res.status}.`,
      };
    }
    return { ok: true, bytes: new Uint8Array(await res.arrayBuffer()) };
  }

  return {
    ok: false,
    status: 501,
    error: `Storage backend '${vault.storage_backend}' is not enabled for direct blob proxy.`,
  };
}
