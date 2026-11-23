import { NextResponse } from 'next/server';
import {
  authenticateJobRequest,
  extractJobToken,
  isValidProvider,
  NO_STORE_HEADERS,
  validateEncryptedEnvelopePayload,
  verifyOperatorKeyFingerprint,
} from '@/lib/job-auth';

export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 65536;
const ENVELOPE_TTL_MS = 15 * 60 * 1000;
const BLOCKED_JOB_STATES = new Set(['COMPLETED', 'CANCELLED', 'PURGING_PDPA']);

export async function POST(
  request: Request,
  context: { params: Promise<{ jobId: string }> }
) {
  const contentLength = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: 'Payload exceeds maximum allowed size.', code: 'PAYLOAD_TOO_LARGE' },
      { status: 413, headers: NO_STORE_HEADERS }
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: 'Request body must be valid JSON.', code: 'INVALID_JSON' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  if (!body || typeof body !== 'object') {
    return NextResponse.json(
      { error: 'Invalid request payload.', code: 'INVALID_PAYLOAD' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const record = body as Record<string, unknown>;
  if (!isValidProvider(record.provider)) {
    return NextResponse.json(
      {
        error: "provider must be either 'icloud' or 'google_photos'.",
        code: 'INVALID_PROVIDER',
      },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const candidateEnvelope =
    record.envelope && typeof record.envelope === 'object'
      ? record.envelope
      : record;
  const validation = validateEncryptedEnvelopePayload(candidateEnvelope);
  if (!validation.ok) {
    return NextResponse.json(
      { error: validation.error, code: 'INVALID_ENVELOPE' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const { jobId } = await context.params;
  const rawToken = extractJobToken(request);
  const auth = await authenticateJobRequest(jobId, rawToken);
  if (!auth.ok) {
    return NextResponse.json(
      { error: auth.message, code: auth.code },
      { status: auth.status, headers: NO_STORE_HEADERS }
    );
  }

  const { job, supabase } = auth;
  if (BLOCKED_JOB_STATES.has(job.status)) {
    return NextResponse.json(
      {
        error: 'This job is no longer accepting encrypted credentials.',
        code: 'JOB_CLOSED',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  const { data: operatorNode, error: opError } = await supabase
    .from('operator_nodes')
    .select('key_fingerprint_sha256, public_key_pem')
    .eq('id', job.operator_node_id)
    .maybeSingle();

  if (opError || !operatorNode) {
    return NextResponse.json(
      {
        error: 'Assigned operator encryption node could not be verified.',
        code: 'OPERATOR_KEY_UNAVAILABLE',
      },
      { status: 503, headers: NO_STORE_HEADERS }
    );
  }

  if (
    !verifyOperatorKeyFingerprint(
      validation.envelope.key_fingerprint_sha256,
      operatorNode
    )
  ) {
    return NextResponse.json(
      {
        error:
          'Encryption key fingerprint mismatch. Refresh the page to fetch the latest operator public key.',
        code: 'KEY_FINGERPRINT_MISMATCH',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  const expiresAt = new Date(Date.now() + ENVELOPE_TTL_MS).toISOString();

  const { data: inserted, error: insertError } = await supabase
    .from('credential_envelopes')
    .insert({
      job_id: job.id,
      provider: record.provider,
      key_fingerprint_sha256: validation.envelope.key_fingerprint_sha256,
      wrapped_key_b64: validation.envelope.wrapped_key_b64,
      iv_b64: validation.envelope.iv_b64,
      ciphertext_b64: validation.envelope.ciphertext_b64,
      expires_at: expiresAt,
    })
    .select('id, provider, expires_at, created_at')
    .single();

  if (insertError || !inserted) {
    return NextResponse.json(
      {
        error: 'Failed to queue encrypted credential envelope.',
        code: 'ENVELOPE_INSERT_FAILED',
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }

  if (job.status === 'CREATED' || job.status === 'AWAITING_CREDENTIALS') {
    await supabase
      .from('migration_jobs')
      .update({ status: 'CREDENTIALS_RECEIVED' })
      .eq('id', job.id)
      .in('status', ['CREATED', 'AWAITING_CREDENTIALS']);
  }

  return NextResponse.json(
    {
      ok: true,
      envelope_id: inserted.id,
      provider: inserted.provider,
      expires_at: inserted.expires_at,
      created_at: inserted.created_at,
    },
    { status: 201, headers: NO_STORE_HEADERS }
  );
}
