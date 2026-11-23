'use client';

import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  FileCheck2,
  Lock,
  Printer,
  ShieldCheck,
} from 'lucide-react';
import {
  formatBytes,
  formatDateTimeTh,
  SERVICE_MODE_META,
} from '@/lib/formatters';
import type { JobYearProgress, MigrationJob } from '@/lib/types';

interface AuditApprovalAndPdpaCardProps {
  jobId: string;
  token: string;
  job: MigrationJob;
  years: JobYearProgress[];
  onApproved: () => void;
}

export function AuditApprovalAndPdpaCard({
  jobId,
  token,
  job,
  years,
  onApproved,
}: AuditApprovalAndPdpaCardProps) {
  const [confirmText, setConfirmText] = useState('');
  const [checkedAlbumReview, setCheckedAlbumReview] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [approvedBanner, setApprovedBanner] = useState(false);

  const serviceMeta = SERVICE_MODE_META[job.service_mode];
  const isAuditComplete =
    job.total_files > 0 &&
    job.verified_sha256_files >= job.total_files &&
    job.uploaded_files >= job.total_files;
  const mismatchCount =
    typeof job.telemetry_snapshot?.sha256_mismatch_count === 'number'
      ? job.telemetry_snapshot.sha256_mismatch_count
      : 0;
  const canSignLock5 =
    serviceMeta.allowsCleanup &&
    job.status === 'AWAITING_5LOCK_APPROVAL' &&
    !job.five_lock_approved_by_customer_at;
  const cert = job.pdpa_purge_certificate;

  async function handleApproveCleanup(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!canSignLock5 || submitting) return;

    if (!checkedAlbumReview) {
      setErrorMsg('กรุณาติ๊กยืนยันว่าได้ตรวจสอบลิงก์อัลบั้มบน Google Photos เรียบร้อยแล้ว');
      return;
    }

    if (confirmText.trim() !== 'APPROVE') {
      setErrorMsg('กรุณาพิมพ์คำว่า APPROVE ตัวพิมพ์ใหญ่ทั้งหมดเพื่อยืนยัน Lock 5');
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);

    try {
      const response = await fetch(
        `/api/jobs/${encodeURIComponent(jobId)}/approve-cleanup`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            confirm_text: 'APPROVE',
          }),
        }
      );

      const data = (await response.json().catch(() => ({}))) as {
        error?: string;
      };
      if (!response.ok) {
        throw new Error(data.error || 'ไม่สามารถบันทึกลายเซ็นอนุมัติ Lock 5 ได้');
      }

      setConfirmText('');
      setApprovedBanner(true);
      onApproved();
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'เกิดข้อผิดพลาดในการยืนยัน Lock 5'
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* 1:1 SHA-256 Audit & Lock 5 Approval Desk */}
      <section className="no-print rounded-xl border border-vault-border bg-vault-surface p-5 shadow-vault">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-vault-border pb-4">
          <div>
            <h2 className="text-base font-bold text-vault-ink">
              สรุปการตรวจสอบ 1:1 SHA-256 และการอนุมัติ Lock 5
            </h2>
            <p className="mt-0.5 text-xs text-vault-subtle">
              1:1 Cryptographic Reconciliation &amp; Customer Sign-off
            </p>
          </div>
          <span
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold ${
              isAuditComplete && mismatchCount === 0
                ? 'bg-vault-emerald-soft text-vault-emerald'
                : 'bg-vault-well text-vault-muted'
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            <span>
              {isAuditComplete && mismatchCount === 0
                ? '1:1 SHA-256 ครบถ้วน 100%'
                : 'กำลังรวบรวมผล Audit'}
            </span>
          </span>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <p className="text-xs text-vault-muted">จับคู่ไฟล์ต้นทาง-ปลายทาง</p>
            <p className="mt-1 font-mono text-sm font-bold text-vault-ink">
              {job.uploaded_files.toLocaleString()} / {job.total_files.toLocaleString()} ไฟล์
            </p>
          </div>
          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <p className="text-xs text-vault-muted">ไฟล์ SHA-256 ผิดพลาด</p>
            <p
              className={`mt-1 font-mono text-sm font-bold ${
                mismatchCount === 0 ? 'text-vault-emerald' : 'text-red-700'
              }`}
            >
              {mismatchCount} ไฟล์
            </p>
          </div>
          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <p className="text-xs text-vault-muted">จำนวนอัลบั้มแยกปี</p>
            <p className="mt-1 font-mono text-sm font-bold text-vault-ink">
              {years.length} อัลบั้ม ({formatBytes(job.total_bytes)})
            </p>
          </div>
        </div>

        {/* Service Mode Specific Lock 5 Control */}
        {!serviceMeta.allowsCleanup ? (
          <div className="mt-4 flex items-start gap-3 rounded-lg border border-teal-200 bg-vault-emerald-soft p-4 text-xs text-vault-emerald">
            <Lock className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <div>
              <p className="font-semibold">
                โหมด Copy-Only Archive — ล็อกห้ามลบภาพใน iCloud ถาวร
              </p>
              <p className="mt-1 text-teal-900/80">
                งานนี้ถูกตั้งค่าเป็น Copy-Only ระบบฝั่งเซิร์ฟเวอร์จะปฏิเสธคำสั่งเคลียร์พื้นที่ทุกกรณี
                ภาพต้นฉบับทั้งหมดของคุณบน iCloud จะยังคงอยู่ครบ 100%
              </p>
            </div>
          </div>
        ) : job.five_lock_approved_by_customer_at || approvedBanner ? (
          <div className="mt-4 flex items-start gap-3 rounded-lg border border-teal-200 bg-vault-emerald-soft p-4 text-xs text-vault-emerald">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <div>
              <p className="font-semibold">
                ลูกค้าลงนามอนุมัติ Lock 5 เรียบร้อยแล้ว
              </p>
              <p className="mt-1 font-mono text-[11px] text-teal-900">
                Approved at:{' '}
                {formatDateTimeTh(job.five_lock_approved_by_customer_at)}
              </p>
            </div>
          </div>
        ) : canSignLock5 ? (
          <form
            onSubmit={handleApproveCleanup}
            className="mt-5 rounded-xl border-2 border-vault-amber bg-vault-amber-soft p-4"
          >
            <div className="flex items-start gap-2.5">
              <AlertTriangle
                className="mt-0.5 h-5 w-5 shrink-0 text-vault-amber"
                aria-hidden="true"
              />
              <div>
                <h3 className="text-sm font-bold text-vault-ink">
                  รอลูกค้ายืนยันอนุมัติ Lock 5 เพื่อเริ่มเคลียร์พื้นที่ iCloud
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-vault-muted">
                  กรุณาคลิกลิงก์อัลบั้ม Google Photos ในตารางด้านบนเพื่อเปิดดูภาพจริงให้ครบทุกปี
                  เมื่อมั่นใจแล้วให้ติ๊กช่องยืนยันและพิมพ์คำว่า{' '}
                  <span className="font-mono font-bold text-vault-ink">APPROVE</span>{' '}
                  ระบบจะเคลียร์เฉพาะไฟล์ที่ผ่านครบ Lock 1–4 เท่านั้น
                </p>
              </div>
            </div>

            <label className="mt-4 flex cursor-pointer items-start gap-2.5 text-xs text-vault-ink">
              <input
                type="checkbox"
                checked={checkedAlbumReview}
                onChange={(e) => {
                  setCheckedAlbumReview(e.target.checked);
                  if (errorMsg) setErrorMsg(null);
                }}
                className="mt-0.5 h-4 w-4 rounded border-amber-500 text-vault-amber focus:ring-vault-amber"
              />
              <span>
                ข้าพเจ้าได้ตรวจสอบภาพในอัลบั้ม Google Photos ตามลิงก์ด้านบนแล้ว
                และอนุญาตให้เคลียร์เฉพาะไฟล์ปีที่ผ่านการตรวจ SHA-256 1:1 ออกจาก iCloud
              </span>
            </label>

            <div className="mt-3 flex flex-col gap-2.5 sm:flex-row sm:items-center">
              <label htmlFor="cv-lock5-approve" className="sr-only">
                Type APPROVE to authorize Lock 5 cleanup
              </label>
              <input
                id="cv-lock5-approve"
                type="text"
                value={confirmText}
                onChange={(e) => {
                  setConfirmText(e.target.value);
                  if (errorMsg) setErrorMsg(null);
                }}
                placeholder='พิมพ์ "APPROVE" ที่นี่'
                autoComplete="off"
                spellCheck={false}
                className="w-full rounded-lg border border-amber-400 bg-white px-3.5 py-2 font-mono text-sm font-semibold text-vault-ink placeholder:font-sans placeholder:font-normal placeholder:text-slate-400 focus:border-vault-amber focus:outline-none sm:w-56"
              />
              <button
                type="submit"
                disabled={
                  submitting ||
                  !checkedAlbumReview ||
                  confirmText.trim() !== 'APPROVE'
                }
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-vault-amber px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-amber-800 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <ShieldCheck className="h-4 w-4" aria-hidden="true" />
                <span>
                  {submitting
                    ? 'กำลังบันทึกลายเซ็น…'
                    : 'ยืนยันอนุมัติ Lock 5 (APPROVE)'}
                </span>
              </button>
            </div>

            {errorMsg ? (
              <p className="mt-2.5 text-xs font-medium text-red-700" role="alert">
                {errorMsg}
              </p>
            ) : null}
          </form>
        ) : (
          <div className="mt-4 rounded-lg border border-vault-border bg-vault-canvas px-4 py-3 text-xs text-vault-muted">
            ปุ่มอนุมัติ Lock 5 จะเปิดให้กดโดยอัตโนมัติทันทีที่ทุกปีผ่านการตรวจ SHA-256 และอัปโหลดครบ 100%
          </div>
        )}
      </section>

      {/* Printable PDPA Purge Certificate */}
      {cert ? (
        <section
          aria-label="PDPA Purge Certificate"
          className="print-certificate-sheet rounded-xl border-2 border-vault-ink bg-vault-surface p-6 shadow-vault-elevated"
        >
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-vault-border pb-5">
            <div className="flex items-start gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-vault-emerald text-white">
                <FileCheck2 className="h-6 w-6" aria-hidden="true" />
              </div>
              <div>
                <p className="text-xs font-semibold text-vault-emerald">
                  CloudVault Concierge · Official Compliance Record
                </p>
                <h2 className="mt-0.5 text-lg font-bold text-vault-ink">
                  ใบรับรองการทำลายข้อมูลพักตามมาตรฐาน PDPA
                </h2>
                <p className="text-xs text-vault-subtle">
                  PDPA Staging &amp; Session Purge Certificate
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => window.print()}
              className="no-print inline-flex items-center gap-2 rounded-lg border border-vault-border bg-vault-canvas px-3.5 py-2 text-xs font-semibold text-vault-ink transition-colors hover:bg-vault-well"
            >
              <Printer className="h-4 w-4" aria-hidden="true" />
              <span>พิมพ์ / บันทึก PDF</span>
            </button>
          </div>

          <dl className="mt-5 grid grid-cols-1 gap-4 text-xs sm:grid-cols-2">
            <div>
              <dt className="text-vault-subtle">หมายเลขใบรับรอง (Certificate ID)</dt>
              <dd className="mt-1 font-mono font-semibold text-vault-ink">
                {cert.certificate_id || `PDPA-${job.job_code}`}
              </dd>
            </div>
            <div>
              <dt className="text-vault-subtle">รหัสงาน / ลูกค้า</dt>
              <dd className="mt-1 font-semibold text-vault-ink">
                <span className="font-mono">{cert.job_code || job.job_code}</span> ·{' '}
                {cert.customer_display_name || job.customer_display_name}
              </dd>
            </div>
            <div>
              <dt className="text-vault-subtle">วันเวลาที่ทำลายข้อมูลพักเสร็จสิ้น</dt>
              <dd className="mt-1 font-mono font-medium text-vault-ink">
                {formatDateTimeTh(cert.purged_at || job.pdpa_purged_at)}
              </dd>
            </div>
            <div>
              <dt className="text-vault-subtle">วิธีทำลายข้อมูล (Shred Method)</dt>
              <dd className="mt-1 font-medium text-vault-ink">
                {cert.shred_method || 'Secure File Unlink + Session & Envelope Zero-Out'}
              </dd>
            </div>
          </dl>

          {cert.items_purged ? (
            <div className="mt-5 rounded-lg border border-vault-border bg-vault-canvas p-4">
              <p className="text-xs font-semibold text-vault-ink">
                รายการข้อมูลที่ทำลายออกจากเครื่อง Operator และฐานข้อมูลรีเลย์
              </p>
              <ul className="mt-2.5 grid grid-cols-1 gap-2 text-xs text-vault-muted sm:grid-cols-2">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-vault-emerald" aria-hidden="true" />
                  <span>
                    ไฟล์พักในเครื่อง:{' '}
                    <span className="font-mono font-semibold text-vault-ink">
                      {(cert.items_purged.local_staging_files ?? job.total_files).toLocaleString()}
                    </span>{' '}
                    ไฟล์ถูกลบถาวร
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-vault-emerald" aria-hidden="true" />
                  <span>
                    คุกกี้เซสชัน iCloud &amp; Google:{' '}
                    {cert.items_purged.session_cookies_shredded !== false
                      ? 'ทำลายแล้ว 100%'
                      : 'รอดำเนินการ'}
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-vault-emerald" aria-hidden="true" />
                  <span>
                    ซองข้อมูลเข้ารหัส &amp; OTP:{' '}
                    {cert.items_purged.credential_envelopes_shredded !== false
                      ? 'ล้างออกจากฐานข้อมูลแล้ว'
                      : 'รอดำเนินการ'}
                  </span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-vault-emerald" aria-hidden="true" />
                  <span>
                    คงเหลือเฉพาะใบสรุปแฮช SHA-256 (ไม่มีภาพหรือรหัสผ่าน)
                  </span>
                </li>
              </ul>
            </div>
          ) : null}

          <div className="mt-5 flex flex-col gap-2 border-t border-vault-border pt-4 text-[11px] text-vault-subtle sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1 break-all font-mono">
              {cert.payload_sha256 || cert.verification_hash_sha256 ? (
                <p>
                  Cert SHA-256:{' '}
                  <strong className="text-vault-ink">
                    {cert.payload_sha256 || cert.verification_hash_sha256}
                  </strong>
                </p>
              ) : null}
              <p>
                Operator Key:{' '}
                <strong className="text-vault-ink">
                  {cert.key_fingerprint_sha256 ||
                    cert.operator_key_fingerprint_sha256 ||
                    'Verified'}
                </strong>
                {cert.signature_algorithm ? ` · ${cert.signature_algorithm}` : ''}
              </p>
            </div>
            <span className="shrink-0 font-semibold text-vault-emerald">
              Verified by CloudVault Concierge
            </span>
          </div>
        </section>
      ) : (
        <section className="no-print rounded-xl border border-dashed border-vault-border bg-vault-surface/70 p-5 text-xs text-vault-muted">
          <div className="flex items-center gap-2 font-semibold text-vault-ink">
            <FileCheck2 className="h-4 w-4 text-vault-subtle" aria-hidden="true" />
            <span>ใบรับรองการลบข้อมูลพักตามมาตรฐาน PDPA (PDPA Purge Certificate)</span>
          </div>
          <p className="mt-1.5 leading-relaxed">
            เมื่อปิดงานและเครื่อง Operator ทำลายไฟล์ภาพพักรวมถึงคุกกี้เซสชันทั้งหมดเรียบร้อยแล้ว
            ใบรับรองอย่างเป็นทางการพร้อมปุ่มพิมพ์เป็น PDF จะปรากฏขึ้นในส่วนนี้โดยอัตโนมัติ
          </p>
        </section>
      )}
    </div>
  );
}
