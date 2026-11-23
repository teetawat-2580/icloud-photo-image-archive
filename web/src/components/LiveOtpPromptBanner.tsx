'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, Clock, KeyRound, ShieldAlert } from 'lucide-react';
import {
  encryptEnvelope,
  formatShortFingerprint,
  verifyPublicKeyFingerprint,
} from '@/lib/crypto-envelope';
import type { OperatorNodePublic, OtpChallenge } from '@/lib/types';

interface LiveOtpPromptBannerProps {
  jobId: string;
  token: string;
  challenges: OtpChallenge[];
  operator: OperatorNodePublic | null;
  onSubmitted: () => void;
}

function getRemainingSeconds(expiresAt: string, nowMs: number): number {
  const diff = Math.floor((new Date(expiresAt).getTime() - nowMs) / 1000);
  return Math.max(0, diff);
}

function formatCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function LiveOtpPromptBanner({
  jobId,
  token,
  challenges,
  operator,
  onSubmitted,
}: LiveOtpPromptBannerProps) {
  const activeChallenge =
    challenges.find((c) => c.status === 'WAITING_CUSTOMER') ??
    challenges.find((c) => c.status === 'SUBMITTED') ??
    null;

  const [otpCode, setOtpCode] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submittedChallengeId, setSubmittedChallengeId] = useState<string | null>(
    null
  );
  const [nowMs, setNowMs] = useState(() => Date.now());

  const activeId = activeChallenge?.id ?? null;

  useEffect(() => {
    if (!activeId) return;
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, [activeId]);

  if (!activeChallenge) {
    return null;
  }

  const remainingSec = getRemainingSeconds(activeChallenge.expires_at, nowMs);
  const isExpired = remainingSec <= 0;
  const isSubmitted =
    activeChallenge.status === 'SUBMITTED' ||
    submittedChallengeId === activeChallenge.id;
  const providerLabel =
    activeChallenge.provider === 'icloud' ? 'Apple iCloud 2FA' : 'Google Photos 2FA';

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!activeChallenge || submitting || isExpired) return;

    const cleanCode = otpCode.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleanCode)) {
      setErrorMsg('กรุณากรอกรหัสยืนยันตัวเลข 6 หลักให้ครบถ้วน');
      return;
    }

    if (!operator?.public_key_pem) {
      setErrorMsg('ไม่พบกุญแจสาธารณะ RSA-4096 ของเครื่อง Operator กรุณารอสักครู่แล้วลองใหม่');
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);

    try {
      const fpCheck = await verifyPublicKeyFingerprint(
        operator.public_key_pem,
        operator.key_fingerprint_sha256
      );
      if (!fpCheck.matches) {
        throw new Error(
          'Operator key fingerprint mismatch detected in browser. Submission blocked for your safety.'
        );
      }

      const encryptedOtp = await encryptEnvelope(operator.public_key_pem, {
        challenge_id: activeChallenge.id,
        provider: activeChallenge.provider,
        otp_code: cleanCode,
        submitted_at: new Date().toISOString(),
      });

      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          challenge_id: activeChallenge.id,
          encrypted_otp_envelope: encryptedOtp,
        }),
      });

      const data = (await response.json().catch(() => ({}))) as {
        error?: string;
      };
      if (!response.ok) {
        throw new Error(data.error || 'ไม่สามารถส่งรหัส OTP ได้ในขณะนี้');
      }

      setOtpCode('');
      setSubmittedChallengeId(activeChallenge.id);
      onSubmitted();
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'เกิดข้อผิดพลาดในการเข้ารหัส OTP'
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section
      aria-live="polite"
      className="no-print rounded-xl border-2 border-vault-amber bg-vault-amber-soft p-5 shadow-vault"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md bg-vault-amber px-2.5 py-1 text-xs font-semibold text-white">
              <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
              <span>ต้องการรหัสยืนยันสด · {providerLabel}</span>
            </span>
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-300 bg-white px-2.5 py-1 font-mono text-xs font-medium text-vault-amber">
              <Clock className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{isExpired ? 'หมดเวลา' : `เหลือ ${formatCountdown(remainingSec)}`}</span>
            </span>
          </div>

          <p className="text-sm font-semibold text-vault-ink">
            {activeChallenge.prompt_message}
          </p>

          <p className="text-xs text-vault-muted">
            รหัส 6 หลักจะถูกเข้ารหัสในเบราว์เซอร์ของคุณด้วย RSA-4096 ก่อนส่งไปยัง Operator
            {operator ? (
              <span className="ml-1.5 font-mono text-[11px] text-vault-ink">
                ({formatShortFingerprint(operator.key_fingerprint_sha256)})
              </span>
            ) : null}
          </p>
        </div>

        {isSubmitted ? (
          <div className="flex items-center gap-2.5 rounded-lg border border-teal-200 bg-vault-emerald-soft px-4 py-3 text-sm font-semibold text-vault-emerald">
            <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden="true" />
            <span>ส่งรหัส 2FA แบบเข้ารหัสแล้ว กำลังยืนยันบนเครื่อง Operator…</span>
          </div>
        ) : (
          <form
            onSubmit={handleSubmit}
            className="flex flex-col gap-2 sm:flex-row sm:items-center"
          >
            <label htmlFor="cv-otp-input" className="sr-only">
              6-digit verification code
            </label>
            <div className="relative">
              <KeyRound
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-vault-amber"
                aria-hidden="true"
              />
              <input
                id="cv-otp-input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={otpCode}
                onChange={(e) => {
                  const digits = e.target.value.replace(/\D/g, '').slice(0, 6);
                  setOtpCode(digits);
                  if (errorMsg) setErrorMsg(null);
                }}
                disabled={submitting || isExpired}
                placeholder="000000"
                className="w-44 rounded-lg border border-amber-400 bg-white py-2.5 pl-9 pr-3 font-mono text-lg font-semibold tracking-[0.28em] text-vault-ink placeholder:tracking-normal placeholder:text-slate-300 focus:border-vault-amber focus:outline-none disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={submitting || isExpired || otpCode.length !== 6}
              className="inline-flex items-center justify-center rounded-lg bg-vault-amber px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-amber-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? 'กำลังเข้ารหัสและส่ง…' : 'ส่งรหัส OTP เข้ารหัส'}
            </button>
          </form>
        )}
      </div>

      {errorMsg ? (
        <p className="mt-3 text-xs font-medium text-red-700" role="alert">
          {errorMsg}
        </p>
      ) : null}
    </section>
  );
}
