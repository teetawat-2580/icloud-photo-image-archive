'use client';

import { useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowRight, KeyRound, Link2 } from 'lucide-react';

function parseTrackingInput(rawInput: string, manualToken: string): {
  jobId: string;
  token: string;
} | null {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  if (trimmed.includes('/job/')) {
    try {
      const normalized = trimmed.startsWith('http')
        ? trimmed
        : `https://cloudvault.local${trimmed.startsWith('/') ? '' : '/'}${trimmed}`;
      const url = new URL(normalized);
      const match = url.pathname.match(/\/job\/([A-Za-z0-9_-]+)/);
      if (match && match[1]) {
        const tokenFromUrl =
          url.searchParams.get('t')?.trim() ??
          url.searchParams.get('token')?.trim() ??
          '';
        return {
          jobId: match[1],
          token: tokenFromUrl || manualToken.trim(),
        };
      }
    } catch {
      return null;
    }
  }

  if (/^[A-Za-z0-9_-]{4,64}$/.test(trimmed)) {
    return {
      jobId: trimmed,
      token: manualToken.trim(),
    };
  }

  return null;
}

export function JobLinkOpener() {
  const router = useRouter();
  const [trackingInput, setTrackingInput] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const looksLikeUrl = trackingInput.trim().includes('/job/');

  function handleOpen(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);

    const parsed = parseTrackingInput(trackingInput, accessToken);
    if (!parsed) {
      setErrorMessage(
        'กรุณาวางลิงก์ติดตามงาน (เช่น .../job/CV-2026-001?t=...) หรือกรอกรหัสงานที่ได้รับจากทีมงาน'
      );
      return;
    }

    const query = parsed.token
      ? `?t=${encodeURIComponent(parsed.token)}`
      : '';
    router.push(`/job/${encodeURIComponent(parsed.jobId)}${query}`);
  }

  return (
    <form
      onSubmit={handleOpen}
      className="rounded-xl border border-vault-border bg-vault-surface p-4 shadow-vault"
      aria-label="Open Job Tracking Link"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold text-vault-ink">
          <Link2 className="h-4 w-4 text-vault-sky" aria-hidden="true" />
          <span>เปิดลิงก์ติดตามงานของลูกค้า</span>
        </div>
        <span className="text-xs text-vault-subtle">Open Job Tracking Link</span>
      </div>

      <div className="flex flex-col gap-2.5 sm:flex-row">
        <div className="flex-1">
          <label htmlFor="cv-job-input" className="sr-only">
            Job tracking URL or Job Code
          </label>
          <input
            id="cv-job-input"
            type="text"
            value={trackingInput}
            onChange={(e) => {
              setTrackingInput(e.target.value);
              if (errorMessage) setErrorMessage(null);
            }}
            placeholder="วางลิงก์ติดตามงาน หรือกรอกรหัสงาน เช่น CV-2026-001"
            className="w-full rounded-lg border border-vault-border bg-vault-canvas px-3.5 py-2.5 text-sm text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none"
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        {!looksLikeUrl ? (
          <div className="sm:w-48">
            <label htmlFor="cv-token-input" className="sr-only">
              Access Token
            </label>
            <div className="relative">
              <KeyRound
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-vault-subtle"
                aria-hidden="true"
              />
              <input
                id="cv-token-input"
                type="password"
                value={accessToken}
                onChange={(e) => {
                  setAccessToken(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="Access Token"
                className="w-full rounded-lg border border-vault-border bg-vault-canvas py-2.5 pl-8 pr-3 font-mono text-xs text-vault-ink placeholder:font-sans placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none"
                autoComplete="off"
              />
            </div>
          </div>
        ) : null}

        <button
          type="submit"
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-vault-ink px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
        >
          <span>เปิดหน้างาน</span>
          <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {errorMessage ? (
        <p className="mt-2.5 text-xs text-vault-amber" role="alert">
          {errorMessage}
        </p>
      ) : (
        <p className="mt-2.5 text-xs text-vault-subtle">
          วางลิงก์เต็มที่ได้รับทาง LINE ได้ทันที หรือกรอกรหัสงานคู่กับ Access Token เพื่อดูสถานะสดแบบเรียลไทม์
        </p>
      )}
    </form>
  );
}
