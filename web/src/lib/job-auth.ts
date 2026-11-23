import { createHash, timingSafeEqual } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { CredentialProvider, EncryptedEnvelope, MigrationJob } from './types';

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/i;
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const JOB_CODE_REGEX = /^[A-Za-z0-9_-]{4,64}$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

const VALID_PROVIDERS = new Set<CredentialProvider>(['icloud', 'google_photos']);

export class SupabaseConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SupabaseConfigError';
  }
}

export function hashJobToken(rawToken: string): string {
  if (typeof rawToken !== 'string' || rawToken.length === 0) {
    throw new Error('Job token must be a non-empty string.');
  }
  return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

export function verifyJobToken(rawToken: string, storedHash: string): boolean {
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

  const computedHex = hashJobToken(rawToken);
  const computedBuf = Buffer.from(computedHex, 'hex');
  const storedBuf = Buffer.from(normalizedStored, 'hex');

  if (computedBuf.length !== storedBuf.length) {
    return false;
  }

  return timingSafeEqual(computedBuf, storedBuf);
}

export function extractJobToken(request: Request): string | null {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer.length > 0) {
      return bearer;
    }
  }

  const headerToken = request.headers.get('x-job-token')?.trim();
  if (headerToken && headerToken.length > 0) {
    return headerToken;
  }

  try {
    const url = new URL(request.url);
    const queryToken =
      url.searchParams.get('t')?.trim() ||
      url.searchParams.get('token')?.trim();
    if (queryToken && queryToken.length > 0) {
      return queryToken;
    }
  } catch {
    return null;
  }

  return null;
}

export function isUuid(value: string): boolean {
  return UUID_REGEX.test(value);
}

export function isValidJobIdentifier(value: string): boolean {
  return UUID_REGEX.test(value) || JOB_CODE_REGEX.test(value);
}

export function isValidProvider(value: unknown): value is CredentialProvider {
  return typeof value === 'string' && VALID_PROVIDERS.has(value as CredentialProvider);
}

export function isStrictBase64(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > maxLength) return false;
  if (value.length % 4 !== 0) return false;
  return BASE64_REGEX.test(value);
}

export function validateEncryptedEnvelopePayload(
  input: unknown
): { ok: true; envelope: EncryptedEnvelope } | { ok: false; error: string } {
  if (!input || typeof input !== 'object') {
    return { ok: false, error: 'Envelope payload must be a JSON object.' };
  }

  const rec = input as Record<string, unknown>;

  if (rec.version !== 1) {
    return { ok: false, error: 'Envelope version must equal 1.' };
  }
  if (rec.alg !== 'RSA-OAEP-256+A256GCM') {
    return {
      ok: false,
      error: 'Envelope algorithm must be RSA-OAEP-256+A256GCM.',
    };
  }
  if (
    typeof rec.key_fingerprint_sha256 !== 'string' ||
    !SHA256_HEX_REGEX.test(rec.key_fingerprint_sha256.trim())
  ) {
    return {
      ok: false,
      error: 'key_fingerprint_sha256 must be a 64-character SHA-256 hex digest.',
    };
  }
  if (!isStrictBase64(rec.wrapped_key_b64, 2048)) {
    return {
      ok: false,
      error: 'wrapped_key_b64 must be valid base64 (max 2048 characters).',
    };
  }
  if (!isStrictBase64(rec.iv_b64, 32)) {
    return {
      ok: false,
      error: 'iv_b64 must be valid base64 representing a 12-byte GCM IV.',
    };
  }
  const ivBytes = Buffer.from(rec.iv_b64, 'base64');
  if (ivBytes.length !== 12) {
    return {
      ok: false,
      error: 'iv_b64 must decode to exactly 12 bytes.',
    };
  }
  if (!isStrictBase64(rec.ciphertext_b64, 32768)) {
    return {
      ok: false,
      error: 'ciphertext_b64 must be valid base64 (max 32768 characters).',
    };
  }

  return {
    ok: true,
    envelope: {
      version: 1,
      alg: 'RSA-OAEP-256+A256GCM',
      key_fingerprint_sha256: rec.key_fingerprint_sha256.trim().toLowerCase(),
      wrapped_key_b64: rec.wrapped_key_b64,
      iv_b64: rec.iv_b64,
      ciphertext_b64: rec.ciphertext_b64,
    },
  };
}

export function getSupabaseAdminClient(): SupabaseClient {
  if (typeof window !== 'undefined') {
    throw new Error('getSupabaseAdminClient() cannot run in a browser context.');
  }

  const supabaseUrl =
    process.env.NEXT_PUBLIC_SUPABASE_URL?.trim() ||
    process.env.SUPABASE_URL?.trim();
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();

  if (!supabaseUrl || !serviceRoleKey) {
    throw new SupabaseConfigError(
      'Supabase server credentials are not configured. Set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.local.'
    );
  }

  return createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

type DbMigrationJobRow = MigrationJob & {
  token_hash_sha256: string;
};

export type AuthJobResult =
  | {
      ok: true;
      job: MigrationJob;
      supabase: SupabaseClient;
    }
  | {
      ok: false;
      status: number;
      code: string;
      message: string;
    };

export async function authenticateJobRequest(
  jobIdParam: string,
  rawToken: string | null
): Promise<AuthJobResult> {
  const cleanJobId = typeof jobIdParam === 'string' ? jobIdParam.trim() : '';
  if (!isValidJobIdentifier(cleanJobId)) {
    return {
      ok: false,
      status: 400,
      code: 'INVALID_JOB_ID',
      message: 'Job identifier format is invalid.',
    };
  }

  if (!rawToken || rawToken.length > 512) {
    return {
      ok: false,
      status: 401,
      code: 'MISSING_TOKEN',
      message: 'Valid job access token is required.',
    };
  }

  let supabase: SupabaseClient;
  try {
    supabase = getSupabaseAdminClient();
  } catch (err) {
    if (err instanceof SupabaseConfigError) {
      return {
        ok: false,
        status: 503,
        code: 'BACKEND_NOT_CONFIGURED',
        message: err.message,
      };
    }
    return {
      ok: false,
      status: 500,
      code: 'BACKEND_INIT_FAILED',
      message: 'Unable to initialize database connection.',
    };
  }

  const lookupColumn = isUuid(cleanJobId) ? 'id' : 'job_code';
  const { data, error } = await supabase
    .from('migration_jobs')
    .select(
      [
        'id',
        'operator_node_id',
        'job_code',
        'customer_display_name',
        'service_mode',
        'status',
        'token_hash_sha256',
        'target_years',
        'album_prefix',
        'total_files',
        'downloaded_files',
        'verified_sha256_files',
        'uploaded_files',
        'total_bytes',
        'reclaimed_bytes',
        'five_lock_approved_by_customer_at',
        'pdpa_purged_at',
        'pdpa_purge_certificate',
        'telemetry_snapshot',
        'created_at',
        'updated_at',
      ].join(',')
    )
    .eq(lookupColumn, cleanJobId)
    .maybeSingle();

  if (error) {
    return {
      ok: false,
      status: 500,
      code: 'DB_QUERY_ERROR',
      message: 'Failed to retrieve job record.',
    };
  }

  if (!data) {
    return {
      ok: false,
      status: 404,
      code: 'JOB_NOT_FOUND',
      message: 'Job not found or link has expired.',
    };
  }

  const row = data as unknown as DbMigrationJobRow;
  if (!verifyJobToken(rawToken, row.token_hash_sha256)) {
    return {
      ok: false,
      status: 401,
      code: 'INVALID_TOKEN',
      message: 'Job access token verification failed.',
    };
  }

  const { token_hash_sha256: _redacted, ...publicJob } = row;
  void _redacted;

  return {
    ok: true,
    job: {
      ...publicJob,
      total_bytes: Number(publicJob.total_bytes ?? 0),
      reclaimed_bytes: Number(publicJob.reclaimed_bytes ?? 0),
    },
    supabase,
  };
}

export function verifyOperatorKeyFingerprint(
  candidateFingerprint: string,
  operatorNode: {
    key_fingerprint_sha256?: string | null;
    public_key_pem?: string | null;
  }
): boolean {
  const cleanCandidate = candidateFingerprint.trim().toLowerCase();
  if (!SHA256_HEX_REGEX.test(cleanCandidate)) {
    return false;
  }

  const allowed = new Set<string>();
  if (operatorNode.key_fingerprint_sha256) {
    allowed.add(operatorNode.key_fingerprint_sha256.trim().toLowerCase());
  }

  if (operatorNode.public_key_pem) {
    const normalizedPem = operatorNode.public_key_pem.replace(/\r\n/g, '\n');
    const pemSha = createHash('sha256').update(normalizedPem, 'utf8').digest('hex');
    allowed.add(pemSha);

    const b64Body = normalizedPem
      .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
      .replace(/-----END [A-Z0-9 ]+-----/g, '')
      .replace(/\s+/g, '');
    if (b64Body) {
      const derSha = createHash('sha256')
        .update(Buffer.from(b64Body, 'base64'))
        .digest('hex');
      allowed.add(derSha);
    }
  }

  const candBuf = Buffer.from(cleanCandidate, 'hex');
  for (const expectedHex of allowed) {
    if (!SHA256_HEX_REGEX.test(expectedHex)) continue;
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (expectedBuf.length === candBuf.length && timingSafeEqual(candBuf, expectedBuf)) {
      return true;
    }
  }
  return false;
}

export const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
} as const;
