import { NextResponse } from 'next/server';
import {
  authenticateJobRequest,
  extractJobToken,
  isUuid,
  NO_STORE_HEADERS,
  validateEncryptedEnvelopePayload,
  verifyOperatorKeyFingerprint,
} from '@/lib/job-auth';

export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 32768;

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
      { error: 'Invalid OTP submission payload.', code: 'INVALID_PAYLOAD' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const record = body as Record<string, unknown>;
  const challengeId =
    typeof record.challenge_id === 'string' ? record.challenge_id.trim() : '';
  if (!isUuid(challengeId)) {
    return NextResponse.json(
      { error: 'challenge_id must be a valid UUID.', code: 'INVALID_CHALLENGE_ID' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const envelopeCandidate =
    record.encrypted_otp_envelope ?? record.envelope;
  const validation = validateEncryptedEnvelopePayload(envelopeCandidate);
  if (!validation.ok) {
    return NextResponse.json(
      { error: validation.error, code: 'INVALID_OTP_ENVELOPE' },
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

  const [challengeRes, operatorRes] = await Promise.all([
    supabase
      .from('otp_challenges')
      .select('id, job_id, provider, status, expires_at')
      .eq('id', challengeId)
      .eq('job_id', job.id)
      .maybeSingle(),
    supabase
      .from('operator_nodes')
      .select('key_fingerprint_sha256, public_key_pem')
      .eq('id', job.operator_node_id)
      .maybeSingle(),
  ]);

  if (challengeRes.error || operatorRes.error) {
    return NextResponse.json(
      { error: 'Failed to validate OTP challenge.', code: 'OTP_LOOKUP_FAILED' },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }

  const challenge = challengeRes.data;
  if (!challenge) {
    return NextResponse.json(
      { error: 'OTP challenge not found for this job.', code: 'CHALLENGE_NOT_FOUND' },
      { status: 404, headers: NO_STORE_HEADERS }
    );
  }

  if (challenge.status !== 'WAITING_CUSTOMER') {
    return NextResponse.json(
      {
        error: `OTP challenge is already ${challenge.status}.`,
        code: 'CHALLENGE_ALREADY_HANDLED',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  if (new Date(challenge.expires_at).getTime() <= Date.now()) {
    await supabase
      .from('otp_challenges')
      .update({ status: 'EXPIRED' })
      .eq('id', challenge.id)
      .eq('status', 'WAITING_CUSTOMER');

    return NextResponse.json(
      { error: 'OTP challenge has expired. Request a new code.', code: 'CHALLENGE_EXPIRED' },
      { status: 410, headers: NO_STORE_HEADERS }
    );
  }

  if (
    !operatorRes.data ||
    !verifyOperatorKeyFingerprint(
      validation.envelope.key_fingerprint_sha256,
      operatorRes.data
    )
  ) {
    return NextResponse.json(
      {
        error: 'Operator public key fingerprint mismatch for OTP envelope.',
        code: 'KEY_FINGERPRINT_MISMATCH',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  const { data: updated, error: updateError } = await supabase
    .from('otp_challenges')
    .update({
      encrypted_otp_envelope: validation.envelope,
      status: 'SUBMITTED',
    })
    .eq('id', challenge.id)
    .eq('job_id', job.id)
    .eq('status', 'WAITING_CUSTOMER')
    .select('id, status')
    .maybeSingle();

  if (updateError || !updated) {
    return NextResponse.json(
      {
        error: 'Unable to submit OTP challenge. It may have already been consumed.',
        code: 'OTP_UPDATE_FAILED',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      ok: true,
      challenge_id: updated.id,
      status: updated.status,
    },
    { status: 200, headers: NO_STORE_HEADERS }
  );
}
