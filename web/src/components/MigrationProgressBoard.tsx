'use client';

import {
  CheckCircle2,
  CloudUpload,
  ExternalLink,
  HardDriveDownload,
  ShieldCheck,
} from 'lucide-react';
import {
  calcPercent,
  formatBytes,
  isSafeExternalUrl,
  SERVICE_MODE_META,
} from '@/lib/formatters';
import type { FiveLockStatus, JobYearProgress, MigrationJob } from '@/lib/types';

interface MigrationProgressBoardProps {
  job: MigrationJob;
  years: JobYearProgress[];
}

const LOCK_DEFINITIONS = [
  {
    key: 'lock1_local_sha256',
    altKeys: ['lock1', 'sha256', 'local_verified'],
    short: 'L1',
    label: 'Local SHA-256',
  },
  {
    key: 'lock2_gphotos_uploaded',
    altKeys: ['lock2', 'uploaded', 'gphotos_verified'],
    short: 'L2',
    label: 'GPhotos Upload',
  },
  {
    key: 'lock3_album_isolated',
    altKeys: ['lock3', 'album_isolated', 'isolation_guard'],
    short: 'L3',
    label: 'Album Isolation',
  },
  {
    key: 'lock4_audit_reconciled',
    altKeys: ['lock4', 'audit_1to1', 'reconciled'],
    short: 'L4',
    label: '1:1 Audit',
  },
  {
    key: 'lock5_customer_approved',
    altKeys: ['lock5', 'customer_approved', 'approved'],
    short: 'L5',
    label: 'Customer Sign-off',
  },
] as const;

function isLockPassed(
  statusObj: FiveLockStatus | undefined,
  primaryKey: string,
  altKeys: readonly string[]
): boolean {
  if (!statusObj || typeof statusObj !== 'object') return false;
  const candidateKeys = [primaryKey, ...altKeys];
  for (const key of candidateKeys) {
    const val = statusObj[key];
    if (val === true || val === 'passed' || val === 'PASSED' || val === 'ok') {
      return true;
    }
  }
  return false;
}

function ProgressBarCell({
  percent,
  countText,
  tone,
}: {
  percent: number;
  countText: string;
  tone: 'sky' | 'emerald' | 'ink';
}) {
  const barColor =
    tone === 'emerald'
      ? 'bg-vault-emerald'
      : tone === 'sky'
        ? 'bg-vault-sky'
        : 'bg-vault-ink';

  return (
    <div className="min-w-[106px]">
      <div className="flex items-baseline justify-between gap-2 font-mono text-xs">
        <span className="font-semibold text-vault-ink">{percent}%</span>
        <span className="text-[11px] text-vault-subtle">{countText}</span>
      </div>
      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-vault-well">
        <div
          className={`h-full rounded-full transition-all duration-300 ${barColor}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

export function MigrationProgressBoard({
  job,
  years,
}: MigrationProgressBoardProps) {
  const downloadPct = calcPercent(job.downloaded_files, job.total_files);
  const shaPct = calcPercent(job.verified_sha256_files, job.total_files);
  const uploadPct = calcPercent(job.uploaded_files, job.total_files);
  const serviceMeta = SERVICE_MODE_META[job.service_mode];

  const currentStepNote =
    typeof job.telemetry_snapshot?.current_step_label === 'string'
      ? job.telemetry_snapshot.current_step_label
      : null;

  return (
    <section className="rounded-xl border border-vault-border bg-vault-surface shadow-vault">
      <div className="border-b border-vault-border p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-vault-ink">
              ความคืบหน้าการย้ายและตรวจแฮชรายปี
            </h2>
            <p className="mt-0.5 text-xs text-vault-subtle">
              Year-by-Year Verification Ledger · Album Prefix:{' '}
              <span className="font-mono text-vault-ink">{job.album_prefix}</span>
            </p>
          </div>
          {currentStepNote ? (
            <span className="rounded-md border border-sky-200 bg-vault-sky-soft px-3 py-1 text-xs font-medium text-vault-sky">
              {currentStepNote}
            </span>
          ) : null}
        </div>

        {/* Summary Counters */}
        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <div className="flex items-center gap-1.5 text-xs text-vault-muted">
              <HardDriveDownload className="h-3.5 w-3.5 text-vault-sky" aria-hidden="true" />
              <span>ดาวน์โหลดแล้ว</span>
            </div>
            <p className="mt-1.5 font-mono text-lg font-bold text-vault-ink">
              {downloadPct}%
            </p>
            <p className="font-mono text-[11px] text-vault-subtle">
              {job.downloaded_files.toLocaleString()} / {job.total_files.toLocaleString()} ไฟล์
            </p>
          </div>

          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <div className="flex items-center gap-1.5 text-xs text-vault-muted">
              <ShieldCheck className="h-3.5 w-3.5 text-vault-emerald" aria-hidden="true" />
              <span>ตรวจ SHA-256</span>
            </div>
            <p className="mt-1.5 font-mono text-lg font-bold text-vault-emerald">
              {shaPct}%
            </p>
            <p className="font-mono text-[11px] text-vault-subtle">
              {job.verified_sha256_files.toLocaleString()} / {job.total_files.toLocaleString()} ไฟล์
            </p>
          </div>

          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <div className="flex items-center gap-1.5 text-xs text-vault-muted">
              <CloudUpload className="h-3.5 w-3.5 text-vault-sky" aria-hidden="true" />
              <span>อัปโหลด GPhotos</span>
            </div>
            <p className="mt-1.5 font-mono text-lg font-bold text-vault-sky">
              {uploadPct}%
            </p>
            <p className="font-mono text-[11px] text-vault-subtle">
              {job.uploaded_files.toLocaleString()} / {job.total_files.toLocaleString()} ไฟล์
            </p>
          </div>

          <div className="rounded-lg border border-vault-border bg-vault-canvas p-3">
            <div className="flex items-center gap-1.5 text-xs text-vault-muted">
              <CheckCircle2 className="h-3.5 w-3.5 text-vault-ink" aria-hidden="true" />
              <span>ปริมาณข้อมูล</span>
            </div>
            <p className="mt-1.5 font-mono text-lg font-bold text-vault-ink">
              {formatBytes(job.total_bytes)}
            </p>
            <p className="font-mono text-[11px] text-vault-subtle">
              {serviceMeta.allowsCleanup
                ? `คืนพื้นที่แล้ว ${formatBytes(job.reclaimed_bytes)}`
                : 'โหมด Copy-Only'}
            </p>
          </div>
        </div>
      </div>

      {/* Per-Year Ledger Table */}
      {years.length === 0 ? (
        <div className="p-6 text-sm text-vault-muted">
          <p className="font-semibold text-vault-ink">
            ยังไม่มีตารางรายปี — รอสแกนสารบัญภาพจาก iCloud
          </p>
          <p className="mt-1 text-xs leading-relaxed text-vault-subtle">
            {job.target_years.length > 0
              ? `ปีเป้าหมายที่เลือกไว้: ${job.target_years.join(', ')} — ตารางตัวเลขจะปรากฏอัตโนมัติทันทีที่เครื่อง Operator สแกนสารบัญเสร็จ`
              : 'เมื่อเชื่อมต่อและสแกนสารบัญ iCloud เรียบร้อย ตารางความคืบหน้ารายปีและลิงก์อัลบั้ม Google Photos จะแสดงที่นี่ทันที'}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[740px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-vault-border bg-vault-well text-[11px] font-semibold text-vault-muted">
                <th className="px-4 py-3">ปี / ขนาด</th>
                <th className="px-4 py-3">ดาวน์โหลด</th>
                <th className="px-4 py-3">SHA-256</th>
                <th className="px-4 py-3">อัปโหลด</th>
                <th className="px-4 py-3">สถานะ 5-Lock</th>
                <th className="px-4 py-3 text-right">อัลบั้ม Google Photos</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-vault-border">
              {years.map((row) => {
                const rowDlPct = calcPercent(row.downloaded_count, row.catalog_count);
                const rowShaPct = calcPercent(row.verified_count, row.catalog_count);
                const rowUpPct = calcPercent(row.uploaded_count, row.catalog_count);
                const hasSafeLink = isSafeExternalUrl(row.gphotos_album_url);

                return (
                  <tr key={row.id} className="align-middle hover:bg-vault-canvas/60">
                    <td className="px-4 py-3.5">
                      <p className="font-mono text-sm font-bold text-vault-ink">
                        {row.year}
                      </p>
                      <p className="font-mono text-[11px] text-vault-subtle">
                        {formatBytes(row.total_bytes)}
                      </p>
                    </td>

                    <td className="px-4 py-3.5">
                      <ProgressBarCell
                        percent={rowDlPct}
                        countText={`${row.downloaded_count.toLocaleString()}/${row.catalog_count.toLocaleString()}`}
                        tone="ink"
                      />
                    </td>

                    <td className="px-4 py-3.5">
                      <ProgressBarCell
                        percent={rowShaPct}
                        countText={`${row.verified_count.toLocaleString()}/${row.catalog_count.toLocaleString()}`}
                        tone="emerald"
                      />
                    </td>

                    <td className="px-4 py-3.5">
                      <ProgressBarCell
                        percent={rowUpPct}
                        countText={`${row.uploaded_count.toLocaleString()}/${row.catalog_count.toLocaleString()}`}
                        tone="sky"
                      />
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="flex flex-wrap items-center gap-1">
                        {LOCK_DEFINITIONS.map((lock) => {
                          const passed =
                            lock.key === 'lock5_customer_approved'
                              ? Boolean(job.five_lock_approved_by_customer_at) ||
                                isLockPassed(row.five_lock_status, lock.key, lock.altKeys)
                              : isLockPassed(row.five_lock_status, lock.key, lock.altKeys);

                          const copyOnlyL5 =
                            lock.key === 'lock5_customer_approved' &&
                            !serviceMeta.allowsCleanup;

                          return (
                            <span
                              key={lock.key}
                              title={`${lock.short}: ${lock.label}`}
                              className={`inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                                copyOnlyL5
                                  ? 'border border-vault-border bg-vault-well text-vault-subtle'
                                  : passed
                                    ? 'bg-vault-emerald-soft text-vault-emerald'
                                    : 'bg-vault-well text-vault-subtle'
                              }`}
                            >
                              {copyOnlyL5 ? 'N/A' : lock.short}
                            </span>
                          );
                        })}
                      </div>
                      {serviceMeta.allowsCleanup && row.cleaned_count > 0 ? (
                        <p className="mt-1 font-mono text-[10px] text-vault-emerald">
                          เคลียร์แล้ว {row.cleaned_count.toLocaleString()} ไฟล์
                        </p>
                      ) : null}
                    </td>

                    <td className="px-4 py-3.5 text-right">
                      {hasSafeLink && row.gphotos_album_url ? (
                        <a
                          href={row.gphotos_album_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-md border border-sky-200 bg-vault-sky-soft px-2.5 py-1.5 text-xs font-semibold text-vault-sky transition-colors hover:bg-sky-100"
                        >
                          <span className="max-w-[160px] truncate">
                            {row.gphotos_album_title || `${job.album_prefix}_${row.year}`}
                          </span>
                          <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        </a>
                      ) : (
                        <span className="text-[11px] text-vault-subtle">
                          {row.gphotos_album_title || 'กำลังสร้างอัลบั้ม…'}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
