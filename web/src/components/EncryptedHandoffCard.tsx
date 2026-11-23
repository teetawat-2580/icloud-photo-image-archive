'use client';

import { useEffect, useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Eye,
  EyeOff,
  Fingerprint,
  Lock,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  encryptEnvelope,
  formatShortFingerprint,
  verifyPublicKeyFingerprint,
} from '@/lib/crypto-envelope';
import { formatDateTimeTh } from '@/lib/formatters';
import type {
  CredentialProvider,
  JobStatus,
  OperatorNodePublic,
  PendingEnvelopeSummary,
} from '@/lib/types';

interface EncryptedHandoffCardProps {
  jobId: string;
  token: string;
  jobStatus: JobStatus;
  operator: OperatorNodePublic | null;
  recentEnvelopes: PendingEnvelopeSummary[];
  onEnvelopeSent: () => void;
}

const CLOSED_STATUSES = new Set<JobStatus>([
  'COMPLETED',
  'CANCELLED',
  'PURGING_PDPA',
]);

export function EncryptedHandoffCard({
  jobId,
  token,
  jobStatus,
  operator,
  recentEnvelopes,
  onEnvelopeSent,
}: EncryptedHandoffCardProps) {
  const [provider, setProvider] = useState<CredentialProvider>('icloud');
  const [accountEmail, setAccountEmail] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [note, setNote] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [verifiedFingerprint, setVerifiedFingerprint] = useState<string | null>(
    null
  );
  const [fingerprintMismatch, setFingerprintMismatch] = useState(false);

  const publicKeyPem = operator?.public_key_pem ?? '';
  const declaredFingerprint = operator?.key_fingerprint_sha256 ?? '';

  useEffect(() => {
    let cancelled = false;
    if (!publicKeyPem) {
      setVerifiedFingerprint(null);
      setFingerprintMismatch(false);
      return;
    }

    verifyPublicKeyFingerprint(publicKeyPem, declaredFingerprint)
      .then((result) => {
        if (cancelled) return;
        setVerifiedFingerprint(result.pemFingerprint);
        setFingerprintMismatch(!result.matches);
      })
      .catch(() => {
        if (cancelled) return;
        setVerifiedFingerprint(null);
        setFingerprintMismatch(true);
      });

    return () => {
      cancelled = true;
    };
  }, [publicKeyPem, declaredFingerprint]);

  const isClosed = CLOSED_STATUSES.has(jobStatus);
  const canEncrypt = Boolean(publicKeyPem) && !fingerprintMismatch && !isClosed;

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!canEncrypt || submitting) return;

    const cleanEmail = accountEmail.trim();
    if (!cleanEmail || !secretValue) {
      setErrorMsg('กรุณากรอกบัญชีอีเมลและรหัสผ่านก่อนเข้ารหัสส่ง');
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const envelope = await encryptEnvelope(publicKeyPem, {
        provider,
        account_email: cleanEmail,
        password: secretValue,
        note: note.trim() || undefined,
        submitted_at: new Date().toISOString(),
      });

      const response = await fetch(
        `/api/jobs/${encodeURIComponent(jobId)}/envelope`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            provider,
            envelope,
          }),
        }
      );

      const data = (await response.json().catch(() => ({}))) as {
        error?: string;
        expires_at?: string;
      };
      if (!response.ok) {
        throw new Error(data.error || 'ไม่สามารถส่งซองข้อมูลเข้ารหัสได้');
      }

      setAccountEmail('');
      setSecretValue('');
      setNote('');
      setShowSecret(false);
      setSuccessMsg(
        `เข้ารหัสและส่งซอง ${
          provider === 'icloud' ? 'Apple iCloud' : 'Google Photos'
        } สำเร็จ (มีอายุ 15 นาทีและจะถูกลบทันทีหลังถอดรหัสใน RAM)`
      );
      onEnvelopeSent();
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'เกิดข้อผิดพลาดระหว่างการเข้ารหัสในเบราว์เซอร์'
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="no-print rounded-xl border border-vault-border bg-vault-surface p-5 shadow-vault">
      <div className="flex items-start justify-between gap-3 border-b border-vault-border pb-4">
        <div>
          <h2 className="text-base font-bold text-vault-ink">
            ส่งข้อมูลเชื่อมต่อแบบเข้ารหัส E2E
          </h2>
          <p className="mt-0.5 text-xs text-vault-subtle">
            In-Browser WebCrypto Handoff (Zero Plaintext Storage)
          </p>
        </div>
        <span className="inline-flex items-center gap-1 rounded-md border border-teal-200 bg-vault-emerald-soft px-2 py-1 text-[11px] font-semibold text-vault-emerald">
          <Lock className="h-3 w-3" aria-hidden="true" />
          <span>RSA-4096</span>
        </span>
      </div>

      {/* Operator Key Fingerprint Verification Badge */}
      <div
        className={`mt-4 rounded-lg border p-3 ${
          fingerprintMismatch
            ? 'border-red-300 bg-red-50'
            : verifiedFingerprint
              ? 'border-teal-200 bg-vault-emerald-soft/60'
              : 'border-vault-border bg-vault-canvas'
        }`}
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-vault-ink">
            {fingerprintMismatch ? (
              <ShieldAlert className="h-4 w-4 text-red-700" aria-hidden="true" />
            ) : (
              <Fingerprint
                className="h-4 w-4 text-vault-emerald"
                aria-hidden="true"
              />
            )}
            <span>Operator SHA-256 Key Fingerprint</span>
          </div>
          {verifiedFingerprint && !fingerprintMismatch ? (
            <span className="text-[11px] font-semibold text-vault-emerald">
              SPKI Verified
            </span>
          ) : null}
        </div>

        <p
          className="mt-1.5 break-all font-mono text-[11px] leading-relaxed text-vault-ink"
          title={verifiedFingerprint ?? declaredFingerprint}
        >
          {verifiedFingerprint
            ? verifiedFingerprint
            : declaredFingerprint
              ? formatShortFingerprint(declaredFingerprint)
              : 'รอเครื่อง Operator ลงทะเบียนกุญแจสาธารณะ…'}
        </p>

        {operator?.label ? (
          <p className="mt-1 text-[11px] text-vault-muted">
            Node: <span className="font-mono">{operator.label}</span>
          </p>
        ) : null}

        {fingerprintMismatch ? (
          <p className="mt-1.5 text-xs font-medium text-red-700">
            ลายนิ้วมือกุญแจสาธารณะไม่ตรงกับที่ประกาศไว้ ระบบระงับการส่งเพื่อความปลอดภัย
          </p>
        ) : null}
      </div>

      {isClosed ? (
        <div className="mt-4 rounded-lg border border-vault-border bg-vault-canvas p-4 text-xs leading-relaxed text-vault-muted">
          งานนี้อยู่ในสถานะ <span className="font-mono font-semibold">{jobStatus}</span>{' '}
          แล้ว ไม่รับซองข้อมูลเชื่อมต่อเพิ่มเติม
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="mt-4 space-y-3.5">
          <div
            className="grid grid-cols-2 rounded-lg border border-vault-border bg-vault-canvas p-1"
            role="tablist"
            aria-label="เลือกบริการที่ต้องการส่งข้อมูลเชื่อมต่อ"
          >
            <button
              type="button"
              role="tab"
              aria-selected={provider === 'icloud'}
              onClick={() => {
                setProvider('icloud');
                setErrorMsg(null);
                setSuccessMsg(null);
              }}
              className={`rounded-md px-3 py-2 text-xs font-semibold transition-colors ${
                provider === 'icloud'
                  ? 'bg-vault-surface text-vault-ink shadow-vault'
                  : 'text-vault-muted hover:text-vault-ink'
              }`}
            >
              Apple iCloud
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={provider === 'google_photos'}
              onClick={() => {
                setProvider('google_photos');
                setErrorMsg(null);
                setSuccessMsg(null);
              }}
              className={`rounded-md px-3 py-2 text-xs font-semibold transition-colors ${
                provider === 'google_photos'
                  ? 'bg-vault-surface text-vault-ink shadow-vault'
                  : 'text-vault-muted hover:text-vault-ink'
              }`}
            >
              Google Photos
            </button>
          </div>

          <div>
            <label
              htmlFor="cv-account-email"
              className="block text-xs font-semibold text-vault-ink"
            >
              {provider === 'icloud' ? 'Apple ID (อีเมล)' : 'บัญชี Google (Gmail)'}
            </label>
            <input
              id="cv-account-email"
              type="email"
              required
              value={accountEmail}
              onChange={(e) => setAccountEmail(e.target.value)}
              disabled={!canEncrypt || submitting}
              placeholder={
                provider === 'icloud' ? 'name@icloud.com' : 'name@gmail.com'
              }
              autoComplete="off"
              className="mt-1 w-full rounded-lg border border-vault-border bg-vault-canvas px-3 py-2 text-sm text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none disabled:opacity-50"
            />
          </div>

          <div>
            <label
              htmlFor="cv-account-secret"
              className="block text-xs font-semibold text-vault-ink"
            >
              {provider === 'icloud'
                ? 'รหัสผ่าน Apple ID (เข้ารหัสก่อนส่งออก)'
                : 'รหัสผ่าน Google (เข้ารหัสก่อนส่งออก)'}
            </label>
            <div className="relative mt-1">
              <input
                id="cv-account-secret"
                type={showSecret ? 'text' : 'password'}
                required
                value={secretValue}
                onChange={(e) => setSecretValue(e.target.value)}
                disabled={!canEncrypt || submitting}
                autoComplete="new-password"
                placeholder="กรอกรหัสผ่านชั่วคราวหรือรหัสผ่านบัญชี"
                className="w-full rounded-lg border border-vault-border bg-vault-canvas py-2 pl-3 pr-10 text-sm text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none disabled:opacity-50"
              />
              <button
                type="button"
                onClick={() => setShowSecret((prev) => !prev)}
                aria-label={showSecret ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-vault-subtle hover:text-vault-ink"
              >
                {showSecret ? (
                  <EyeOff className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <Eye className="h-4 w-4" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>

          <div>
            <label
              htmlFor="cv-handoff-note"
              className="block text-xs font-semibold text-vault-ink"
            >
              หมายเหตุเพิ่มเติมถึง Operator (ไม่บังคับ)
            </label>
            <input
              id="cv-handoff-note"
              type="text"
              maxLength={240}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={!canEncrypt || submitting}
              placeholder="เช่น ปีที่ต้องการเก็บไว้บนเครื่อง หรือชื่ออัลบั้มที่ห้ามแตะ"
              className="mt-1 w-full rounded-lg border border-vault-border bg-vault-canvas px-3 py-2 text-xs text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:bg-vault-surface focus:outline-none disabled:opacity-50"
            />
          </div>

          <button
            type="submit"
            disabled={!canEncrypt || submitting}
            className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-vault-ink px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            <span>
              {submitting
                ? 'กำลังเข้ารหัส RSA-OAEP-256 + AES-256-GCM…'
                : 'เข้ารหัสในเบราว์เซอร์แล้วส่งซอง (15-Min TTL)'}
            </span>
          </button>

          <p className="text-[11px] leading-relaxed text-vault-subtle">
            ข้อมูลของคุณถูกเข้ารหัสในอุปกรณ์นี้ด้วย WebCrypto ก่อนส่งผ่าน HTTPS
            เซิร์ฟเวอร์และฐานข้อมูลไม่สามารถอ่านรหัสผ่านได้
          </p>
        </form>
      )}

      {errorMsg ? (
        <p
          className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700"
          role="alert"
        >
          {errorMsg}
        </p>
      ) : null}

      {successMsg ? (
        <div
          className="mt-3 flex items-start gap-2 rounded-lg border border-teal-200 bg-vault-emerald-soft px-3 py-2 text-xs text-vault-emerald"
          role="status"
        >
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{successMsg}</span>
        </div>
      ) : null}

      {recentEnvelopes.length > 0 ? (
        <div className="mt-5 border-t border-vault-border pt-4">
          <p className="text-xs font-semibold text-vault-ink">
            ประวัติซองเข้ารหัสล่าสุด (Envelope Queue)
          </p>
          <ul className="mt-2 space-y-2">
            {recentEnvelopes.slice(0, 4).map((env) => {
              const expired =
                !env.consumed_at &&
                new Date(env.expires_at).getTime() <= Date.now();
              return (
                <li
                  key={env.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-vault-border bg-vault-canvas px-3 py-2 text-xs"
                >
                  <div>
                    <p className="font-semibold text-vault-ink">
                      {env.provider === 'icloud' ? 'Apple iCloud' : 'Google Photos'}
                    </p>
                    <p className="text-[11px] text-vault-subtle">
                      ส่งเมื่อ {formatDateTimeTh(env.created_at)}
                    </p>
                  </div>
                  {env.consumed_at ? (
                    <span className="rounded bg-vault-emerald-soft px-2 py-0.5 text-[11px] font-semibold text-vault-emerald">
                      รับและทำลายแล้ว
                    </span>
                  ) : expired ? (
                    <span className="rounded bg-vault-well px-2 py-0.5 text-[11px] font-medium text-vault-subtle">
                      หมดอายุ 15 นาที
                    </span>
                  ) : (
                    <span className="rounded bg-vault-sky-soft px-2 py-0.5 text-[11px] font-semibold text-vault-sky">
                      รอ Operator รับ
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
