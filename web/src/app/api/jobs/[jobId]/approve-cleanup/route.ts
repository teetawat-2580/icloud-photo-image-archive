import { NextResponse } from 'next/server';
import {
  authenticateJobRequest,
  extractJobToken,
  NO_STORE_HEADERS,
} from '@/lib/job-auth';

export const dynamic = 'force-dynamic';

export async function POST(
  request: Request,
  context: { params: Promise<{ jobId: string }> }
) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: 'Request body must be valid JSON.', code: 'INVALID_JSON' },
      { status: 400, headers: NO_STORE_HEADERS }
    );
  }

  const confirmText =
    body && typeof body === 'object'
      ? (body as Record<string, unknown>).confirm_text
      : undefined;

  if (confirmText !== 'APPROVE') {
    return NextResponse.json(
      {
        error: 'Confirmation phrase must match "APPROVE" exactly.',
        code: 'CONFIRM_TEXT_MISMATCH',
      },
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

  if (job.service_mode === 'copy_only') {
    return NextResponse.json(
      {
        error:
          'Copy-Only jobs strictly forbid iCloud cleanup and cannot receive Lock 5 approval.',
        code: 'COPY_ONLY_CLEANUP_FORBIDDEN',
      },
      { status: 403, headers: NO_STORE_HEADERS }
    );
  }

  if (job.five_lock_approved_by_customer_at) {
    return NextResponse.json(
      {
        ok: true,
        already_approved: true,
        job_id: job.id,
        five_lock_approved_by_customer_at: job.five_lock_approved_by_customer_at,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  }

  if (job.status !== 'AWAITING_5LOCK_APPROVAL') {
    return NextResponse.json(
      {
        error: `Lock 5 approval can only be signed when job status is AWAITING_5LOCK_APPROVAL (current: ${job.status}).`,
        code: 'INVALID_JOB_STATUS',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  if (
    job.total_files > 0 &&
    (job.verified_sha256_files < job.total_files ||
      job.uploaded_files < job.total_files)
  ) {
    return NextResponse.json(
      {
        error:
          'Cannot approve Lock 5 until 100% of catalog files pass SHA-256 verification and Google Photos upload.',
        code: 'AUDIT_INCOMPLETE',
      },
      { status: 409, headers: NO_STORE_HEADERS }
    );
  }

  const approvedAt = new Date().toISOString();
  const { data: updated, error: updateError } = await supabase
    .from('migration_jobs')
    .update({ five_lock_approved_by_customer_at: approvedAt })
    .eq('id', job.id)
    .eq('status', 'AWAITING_5LOCK_APPROVAL')
    .neq('service_mode', 'copy_only')
    .is('five_lock_approved_by_customer_at', null)
    .select('id, five_lock_approved_by_customer_at')
    .maybeSingle();

  if (updateError || !updated) {
    return NextResponse.json(
      {
        error: 'Unable to record Lock 5 customer approval.',
        code: 'APPROVAL_UPDATE_FAILED',
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      ok: true,
      job_id: updated.id,
      five_lock_approved_by_customer_at: updated.five_lock_approved_by_customer_at,
    },
    { status: 200, headers: NO_STORE_HEADERS }
  );
}
