'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import Link from 'next/link';
import {
  AlertCircle,
  ArrowLeft,
  KeyRound,
  RefreshCw,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { AuditApprovalAndPdpaCard } from '@/components/AuditApprovalAndPdpaCard';
import { EncryptedHandoffCard } from '@/components/EncryptedHandoffCard';
import { LiveOtpPromptBanner } from '@/components/LiveOtpPromptBanner';
import { MigrationProgressBoard } from '@/components/MigrationProgressBoard';
import {
  formatDateTimeTh,
  JOB_STATUS_META,
  SERVICE_MODE_META,
} from '@/lib/formatters';
import type { JobStatusResponse } from '@/lib/types';

interface CustomerJobPortalProps {
  jobId: string;
  initialToken: string;
}

const POLL_INTERVAL_MS = 3000;

const STAGE_LABELS = [
  { step: 1, label: 'E2E Handoff' },
  { step: 2, label: '2FA Auth' },
  { step: 3, label: 'Scan Years' },
  { step: 4, label: 'SHA-256' },
  { step: 5, label: 'Upload' },
  { step: 6, label: 'Audit / Lock 5' },
  { step: 7, label: 'Cleanup' },
  { step: 8, label: 'PDPA Cert' },
] as const;

const STATUS_BADGE_CLASSES = {
  neutral: 'border-vault-border bg-vault-well text-vault-muted',
  sky: 'border-sky-200 bg-vault-sky-soft text-vault-sky',
  amber: 'border-amber-300 bg-vault-amber-soft text-vault-amber',
  emerald: 'border-teal-200 bg-vault-emerald-soft text-vault-emerald',
  danger: 'border-red-200 bg-red-50 text-red-700',
} as const;

export function CustomerJobPortal({
  jobId,
  initialToken,
}: CustomerJobPortalProps) {
  const [activeToken, setActiveToken] = useState(initialToken.trim());
  const [tokenDraft, setTokenDraft] = useState(initialToken.trim());
  const [data, setData] = useState<JobStatusResponse | null>(null);
  const [loading, setLoading] = useState(Boolean(initialToken.trim()));
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorState, setErrorState] = useState<{
    status: number;
    code?: string;
    message: string;
  } | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);

  const triggerRefresh = useCallback(() => {
    setRefreshNonce((n) => n + 1);
  }, []);

  useEffect(() => {
    if (!activeToken) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    let activeController: AbortController | null = null;

    async function fetchStatus(isInitial: boolean) {
      if (cancelled) return;
      if (activeController) {
        activeController.abort();
      }
      const controller = new AbortController();
      activeController = controller;

      if (isInitial) {
        setLoading(true);
      } else {
        setIsRefreshing(true);
      }

      try {
        const res = await fetch(
          `/api/jobs/${encodeURIComponent(jobId)}/status`,
          {
            method: 'GET',
            headers: {
              Authorization: `Bearer ${activeToken}`,
            },
            cache: 'no-store',
            signal: controller.signal,
          }
        );

        const body = (await res.json().catch(() => ({}))) as Partial<
          JobStatusResponse & { error: string; code: string }
        >;

        if (cancelled) return;

        if (!res.ok) {
          setErrorState({
            status: res.status,
            code: body.code,
            message:
              body.error || 'ไม่สามารถตรวจสอบสิทธิ์เข้าถึงหน้างานนี้ได้',
          });
          if (res.status === 401 || res.status === 404) {
            setData(null);
          }
          return;
        }

        setData(body as JobStatusResponse);
        setErrorState(null);
        setLastSyncedAt(new Date().toISOString());
      } catch (err) {
        if (cancelled) return;
        if (err instanceof DOMException && err.name === 'AbortError') {
          return;
        }
        setErrorState({
          status: 0,
          code: 'NETWORK_ERROR',
          message: 'การเชื่อมต่อชั่วคราวขัดข้อง กำลังลองเชื่อมต่อใหม่ทุก 3 วินาที…',
        });
      } finally {
        if (!cancelled) {
          setLoading(false);
          setIsRefreshing(false);
        }
      }
    }

    void fetchStatus(true);

    const intervalId = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void fetchStatus(false);
      }
    }, POLL_INTERVAL_MS);

    function handleVisibilityChange() {
      if (document.visibilityState === 'visible') {
        void fetchStatus(false);
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (activeController) {
        activeController.abort();
      }
    };
  }, [jobId, activeToken, refreshNonce]);

  function handleTokenSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const cleaned = tokenDraft.trim();
    if (!cleaned) return;
    setErrorState(null);
    setActiveToken(cleaned);
  }

  // Gate 1: Token Required
  if (!activeToken) {
    return (
      <div className="min-h-screen bg-vault-canvas px-5 py-12 sm:px-8">
        <div className="mx-auto max-w-md">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-vault-muted hover:text-vault-ink"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>กลับหน้าแรก CloudVault Concierge</span>
          </Link>

          <div className="mt-6 rounded-xl border border-vault-border bg-vault-surface p-6 shadow-vault">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-vault-ink text-white">
              <KeyRound className="h-5 w-5" aria-hidden="true" />
            </div>
            <h1 className="mt-4 text-lg font-bold text-vault-ink">
              ยืนยันรหัสเข้าถึงหน้างาน (Access Token)
            </h1>
            <p className="mt-1.5 text-xs leading-relaxed text-vault-muted">
              หน้าติดตามงาน{' '}
              <span className="font-mono font-semibold text-vault-ink">
                {jobId}
              </span>{' '}
              ป้องกันด้วย Access Token เฉพาะบุคคล กรุณากรอก Token ที่ได้รับทาง LINE
            </p>

            <form onSubmit={handleTokenSubmit} className="mt-5 space-y-3">
              <div>
                <label
                  htmlFor="cv-portal-token"
                  className="block text-xs font-semibold text-vault-ink"
                >
                  Job Access Token
                </label>
                <input
                  id="cv-portal-token"
                  type="password"
                  required
                  value={tokenDraft}
                  onChange={(e) => setTokenDraft(e.target.value)}
                  placeholder="วาง Access Token ของงานนี้"
                  autoComplete="off"
                  className="mt-1 w-full rounded-lg border border-vault-border bg-vault-canvas px-3.5 py-2.5 font-mono text-sm text-vault-ink focus:border-vault-sky focus:bg-vault-surface focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="w-full rounded-lg bg-vault-ink px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
              >
                ปลดล็อกหน้าติดตามงาน
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  // Gate 2: Initial Loading
  if (loading && !data) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-vault-canvas px-5">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-vault-border bg-vault-surface text-vault-sky shadow-vault">
            <RefreshCw className="h-5 w-5 animate-spin" aria-hidden="true" />
          </div>
          <p className="text-sm font-semibold text-vault-ink">
            กำลังตรวจสอบสิทธิ์และดึงสถานะงานสด…
          </p>
          <p className="font-mono text-xs text-vault-subtle">{jobId}</p>
        </div>
      </div>
    );
  }

  // Gate 3: Hard Error without cached job data
  if (!data && errorState) {
    return (
      <div className="min-h-screen bg-vault-canvas px-5 py-12 sm:px-8">
        <div className="mx-auto max-w-lg">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-vault-muted hover:text-vault-ink"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>กลับหน้าแรก CloudVault Concierge</span>
          </Link>

          <div className="mt-6 rounded-xl border border-vault-border bg-vault-surface p-6 shadow-vault">
            <div className="flex items-start gap-3">
              <AlertCircle
                className="mt-0.5 h-5 w-5 shrink-0 text-vault-amber"
                aria-hidden="true"
              />
              <div>
                <h1 className="text-base font-bold text-vault-ink">
                  ไม่สามารถเปิดหน้าติดตามงานได้
                </h1>
                <p className="mt-1 text-sm text-vault-muted">
                  {errorState.message}
                </p>
                {errorState.code ? (
                  <p className="mt-1.5 font-mono text-xs text-vault-subtle">
                    Code: {errorState.code} (HTTP {errorState.status || 'ERR'})
                  </p>
                ) : null}
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-2.5 border-t border-vault-border pt-4">
              <button
                type="button"
                onClick={triggerRefresh}
                className="inline-flex items-center gap-2 rounded-lg bg-vault-ink px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>ลองใหม่</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setActiveToken('');
                  setTokenDraft('');
                  setErrorState(null);
                }}
                className="inline-flex items-center gap-2 rounded-lg border border-vault-border bg-vault-canvas px-4 py-2 text-xs font-semibold text-vault-ink hover:bg-vault-well"
              >
                <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                <span>กรอก Access Token ใหม่</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const { job, operator, years, active_otp_challenges, recent_envelopes } = data;
  const statusMeta = JOB_STATUS_META[job.status];
  const serviceMeta = SERVICE_MODE_META[job.service_mode];

  const operatorHeartbeatAgeMs = operator?.last_heartbeat_at
    ? Date.now() - new Date(operator.last_heartbeat_at).getTime()
    : Number.POSITIVE_INFINITY;
  const isOperatorOnline = operatorHeartbeatAgeMs <= 90_000;

  return (
    <div className="min-h-screen bg-vault-canvas text-vault-ink">
      {/* Persistent Concierge Desk Header */}
      <header className="no-print sticky top-0 z-30 border-b border-vault-border bg-vault-surface/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-5 py-3.5 sm:px-8">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              aria-label="กลับหน้าแรก CloudVault Concierge"
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-vault-ink bg-vault-ink text-white transition-colors hover:bg-slate-800"
            >
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </Link>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-bold text-vault-ink">
                  {job.job_code}
                </span>
                <span className="text-xs text-vault-subtle">·</span>
                <span className="text-sm font-semibold text-vault-ink">
                  {job.customer_display_name}
                </span>
              </div>
              <p className="text-xs text-vault-subtle">
                {serviceMeta.titleTh} ({serviceMeta.titleEn})
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold ${
                STATUS_BADGE_CLASSES[statusMeta.tone]
              }`}
            >
              <span>{statusMeta.labelTh}</span>
            </span>

            <button
              type="button"
              onClick={triggerRefresh}
              className="inline-flex items-center gap-1.5 rounded-lg border border-vault-border bg-vault-canvas px-3 py-1.5 text-xs font-medium text-vault-muted transition-colors hover:bg-vault-well hover:text-vault-ink"
              title="รีเฟรชสถานะทันที (อัปเดตอัตโนมัติทุก 3 วินาที)"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-vault-sky' : ''}`}
                aria-hidden="true"
              />
              <span className="hidden sm:inline">Live 3s</span>
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-5 py-6 sm:px-8 sm:py-8">
        {/* Soft transient reconnect notice */}
        {errorState ? (
          <div
            role="status"
            className="no-print flex items-center justify-between gap-3 rounded-lg border border-amber-300 bg-vault-amber-soft px-4 py-2.5 text-xs text-vault-amber"
          >
            <span>{errorState.message}</span>
            <button
              type="button"
              onClick={triggerRefresh}
              className="font-semibold underline"
            >
              ลองใหม่ทันที
            </button>
          </div>
        ) : null}

        {/* Urgent Live 2FA OTP Slot */}
        <LiveOtpPromptBanner
          jobId={jobId}
          token={activeToken}
          challenges={active_otp_challenges}
          operator={operator}
          onSubmitted={triggerRefresh}
        />

        {/* Milestone Progress Strip */}
        <section
          aria-label="Job lifecycle stages"
          className="no-print rounded-xl border border-vault-border bg-vault-surface p-4 shadow-vault"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 text-xs">
            <span className="font-semibold text-vault-ink">
              ขั้นตอนการดำเนินงาน ({statusMeta.labelEn})
            </span>
            <span className="font-mono text-[11px] text-vault-subtle">
              อัปเดตล่าสุด: {formatDateTimeTh(lastSyncedAt || job.updated_at)}
            </span>
          </div>
          <ol className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
            {STAGE_LABELS.map((stage) => {
              const completed = statusMeta.stepIndex > stage.step;
              const current = statusMeta.stepIndex === stage.step;
              return (
                <li
                  key={stage.step}
                  className={`rounded-lg border px-2.5 py-2 text-xs ${
                    current
                      ? 'border-vault-sky bg-vault-sky-soft font-semibold text-vault-sky'
                      : completed
                        ? 'border-teal-200 bg-vault-emerald-soft font-medium text-vault-emerald'
                        : 'border-vault-border bg-vault-canvas text-vault-subtle'
                  }`}
                >
                  <span className="font-mono text-[10px] opacity-75">
                    0{stage.step}
                  </span>
                  <p className="truncate">{stage.label}</p>
                </li>
              );
            })}
          </ol>
        </section>

        {/* Main 2-Column Concierge Desk */}
        <div className="grid gap-6 lg:grid-cols-12 lg:items-start">
          <div className="space-y-6 lg:col-span-8">
            <MigrationProgressBoard job={job} years={years} />
            <AuditApprovalAndPdpaCard
              jobId={jobId}
              token={activeToken}
              job={job}
              years={years}
              onApproved={triggerRefresh}
            />
          </div>

          <aside className="space-y-6 lg:col-span-4">
            <EncryptedHandoffCard
              jobId={jobId}
              token={activeToken}
              jobStatus={job.status}
              operator={operator}
              recentEnvelopes={recent_envelopes}
              onEnvelopeSent={triggerRefresh}
            />

            {/* Operator Node Telemetry Card */}
            <section className="no-print rounded-xl border border-vault-border bg-vault-surface p-5 shadow-vault">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-bold text-vault-ink">
                  <Server className="h-4 w-4 text-vault-sky" aria-hidden="true" />
                  <span>สถานะเครื่อง Operator</span>
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${
                    isOperatorOnline
                      ? 'bg-vault-emerald-soft text-vault-emerald'
                      : 'bg-vault-well text-vault-subtle'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      isOperatorOnline ? 'bg-vault-emerald' : 'bg-slate-400'
                    }`}
                    aria-hidden="true"
                  />
                  <span>{isOperatorOnline ? 'Online' : 'Standby'}</span>
                </span>
              </div>

              <dl className="mt-3 space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-vault-subtle">Node Label</dt>
                  <dd className="font-mono font-medium text-vault-ink">
                    {operator?.label || '—'}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-vault-subtle">Last Heartbeat</dt>
                  <dd className="font-mono text-[11px] text-vault-ink">
                    {formatDateTimeTh(operator?.last_heartbeat_at)}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-vault-subtle">Target Years</dt>
                  <dd className="font-mono text-[11px] text-vault-ink">
                    {job.target_years.length > 0
                      ? job.target_years.join(', ')
                      : 'Pending scan'}
                  </dd>
                </div>
              </dl>
            </section>
          </aside>
        </div>
      </main>
    </div>
  );
}
