import { NextResponse } from 'next/server';
import {
  authenticateJobRequest,
  extractJobToken,
  NO_STORE_HEADERS,
} from '@/lib/job-auth';
import type {
  JobStatusResponse,
  JobYearProgress,
  OperatorNodePublic,
  OtpChallenge,
  PendingEnvelopeSummary,
} from '@/lib/types';

export const dynamic = 'force-dynamic';

export async function GET(
  request: Request,
  context: { params: Promise<{ jobId: string }> }
) {
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
  const nowIso = new Date().toISOString();

  const [operatorRes, yearsRes, otpRes, envelopesRes] = await Promise.all([
    supabase
      .from('operator_nodes')
      .select('id, label, public_key_pem, key_fingerprint_sha256, last_heartbeat_at')
      .eq('id', job.operator_node_id)
      .maybeSingle(),
    supabase
      .from('job_year_progress')
      .select(
        'id, job_id, year, catalog_count, downloaded_count, verified_count, uploaded_count, cleaned_count, total_bytes, gphotos_album_title, gphotos_album_url, five_lock_status, updated_at'
      )
      .eq('job_id', job.id)
      .order('year', { ascending: true }),
    supabase
      .from('otp_challenges')
      .select('id, job_id, provider, prompt_message, status, expires_at, created_at')
      .eq('job_id', job.id)
      .in('status', ['WAITING_CUSTOMER', 'SUBMITTED'])
      .gt('expires_at', nowIso)
      .order('created_at', { ascending: false })
      .limit(5),
    supabase
      .from('credential_envelopes')
      .select('id, provider, key_fingerprint_sha256, consumed_at, expires_at, created_at')
      .eq('job_id', job.id)
      .order('created_at', { ascending: false })
      .limit(8),
  ]);

  if (operatorRes.error || yearsRes.error || otpRes.error || envelopesRes.error) {
    return NextResponse.json(
      {
        error: 'Failed to load live job telemetry.',
        code: 'TELEMETRY_QUERY_ERROR',
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }

  const years = ((yearsRes.data ?? []) as JobYearProgress[]).map((row) => ({
    ...row,
    total_bytes: Number(row.total_bytes ?? 0),
    five_lock_status:
      row.five_lock_status && typeof row.five_lock_status === 'object'
        ? row.five_lock_status
        : {},
  }));

  const payload: JobStatusResponse = {
    job,
    operator: (operatorRes.data as OperatorNodePublic | null) ?? null,
    years,
    active_otp_challenges: (otpRes.data ?? []) as OtpChallenge[],
    recent_envelopes: (envelopesRes.data ?? []) as PendingEnvelopeSummary[],
    server_time: nowIso,
  };

  return NextResponse.json(payload, {
    status: 200,
    headers: NO_STORE_HEADERS,
  });
}
