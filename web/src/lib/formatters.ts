import type { JobStatus, ServiceMode } from './types';

export function formatBytes(bytes: number | null | undefined): string {
  const safe = typeof bytes === 'number' && Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
  if (safe === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(Math.floor(Math.log(safe) / Math.log(1024)), units.length - 1);
  const value = safe / Math.pow(1024, idx);
  return `${value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[idx]}`;
}

export function calcPercent(done: number, total: number): number {
  if (!Number.isFinite(done) || !Number.isFinite(total) || total <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
}

export function isSafeExternalUrl(url: string | null | undefined): boolean {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function formatDateTimeTh(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('th-TH', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

export interface ServiceModeMeta {
  code: ServiceMode;
  titleTh: string;
  titleEn: string;
  summaryTh: string;
  allowsCleanup: boolean;
}

export const SERVICE_MODE_META: Record<ServiceMode, ServiceModeMeta> = {
  copy_only: {
    code: 'copy_only',
    titleTh: 'สำเนาอย่างเดียว (ไม่ลบต้นฉบับ)',
    titleEn: 'Copy-Only Archive',
    summaryTh:
      'คัดลอกภาพและวิดีโอตามปีที่เลือกลง Google Photos พร้อมตรวจ SHA-256 100% โดยไม่ลบไฟล์ออกจาก iCloud',
    allowsCleanup: false,
  },
  move_free_space: {
    code: 'move_free_space',
    titleTh: 'ย้ายและเคลียร์พื้นที่ iCloud (5-Lock)',
    titleEn: 'Move & Free Space (5-Lock)',
    summaryTh:
      'ย้ายภาพตามปีที่เลือก ตรวจครบ 1:1 SHA-256 และปลดล็อกเคลียร์พื้นที่ iCloud เฉพาะหลังลูกค้าอนุมัติ Lock 5',
    allowsCleanup: true,
  },
  move_and_export: {
    code: 'move_and_export',
    titleTh: 'ย้าย + สำรองลง External Drive / NAS',
    titleEn: 'Move + External Drive / NAS Export',
    summaryTh:
      'ย้ายขึ้น Google Photos แยกอัลบั้มตามปี พร้อมส่งออกไฟล์ต้นฉบับลง External SSD/NAS และเคลียร์ iCloud แบบ 5-Lock',
    allowsCleanup: true,
  },
};

export interface JobStatusMeta {
  labelTh: string;
  labelEn: string;
  tone: 'neutral' | 'sky' | 'amber' | 'emerald' | 'danger';
  stepIndex: number;
}

export const JOB_STATUS_META: Record<JobStatus, JobStatusMeta> = {
  CREATED: {
    labelTh: 'เปิดเคสแล้ว รอรับข้อมูลเข้ารหัส',
    labelEn: 'Job Created',
    tone: 'neutral',
    stepIndex: 1,
  },
  AWAITING_CREDENTIALS: {
    labelTh: 'รอลูกค้าส่งข้อมูลเชื่อมต่อแบบเข้ารหัส E2E',
    labelEn: 'Awaiting Encrypted Handoff',
    tone: 'amber',
    stepIndex: 1,
  },
  CREDENTIALS_RECEIVED: {
    labelTh: 'ได้รับซองเข้ารหัสแล้ว กำลังเริ่มต้น',
    labelEn: 'Encrypted Envelope Received',
    tone: 'sky',
    stepIndex: 2,
  },
  AWAITING_2FA_ICLOUD: {
    labelTh: 'รอยืนยันรหัส 2FA จากอุปกรณ์ Apple',
    labelEn: 'Awaiting Apple 2FA OTP',
    tone: 'amber',
    stepIndex: 2,
  },
  SCANNING_CATALOG: {
    labelTh: 'กำลังสแกนสารบัญภาพแยกตามปี',
    labelEn: 'Scanning iCloud Catalog',
    tone: 'sky',
    stepIndex: 3,
  },
  YEAR_SELECTION: {
    labelTh: 'สรุปรายการปีที่เลือกย้าย',
    labelEn: 'Target Years Confirmed',
    tone: 'sky',
    stepIndex: 3,
  },
  DOWNLOADING_VERIFYING: {
    labelTh: 'กำลังดาวน์โหลดและตรวจแฮช SHA-256',
    labelEn: 'Downloading & SHA-256 Verification',
    tone: 'sky',
    stepIndex: 4,
  },
  AWAITING_2FA_GOOGLE: {
    labelTh: 'รอยืนยันรหัส 2FA สำหรับ Google Photos',
    labelEn: 'Awaiting Google 2FA OTP',
    tone: 'amber',
    stepIndex: 4,
  },
  UPLOADING_GPHOTOS: {
    labelTh: 'กำลังอัปโหลดแยกอัลบั้มบน Google Photos',
    labelEn: 'Uploading Isolated Albums',
    tone: 'sky',
    stepIndex: 5,
  },
  AUDIT_READY: {
    labelTh: 'ตรวจจับคู่ SHA-256 ครบ 1:1 แล้ว',
    labelEn: '1:1 Audit Verified',
    tone: 'emerald',
    stepIndex: 6,
  },
  AWAITING_5LOCK_APPROVAL: {
    labelTh: 'รอลูกค้ายืนยันอนุมัติ Lock 5 เพื่อเคลียร์พื้นที่',
    labelEn: 'Awaiting Lock 5 Approval',
    tone: 'amber',
    stepIndex: 6,
  },
  CLEANING_ICLOUD: {
    labelTh: 'กำลังเคลียร์เฉพาะไฟล์ที่ผ่าน 5-Lock บน iCloud',
    labelEn: 'Cleaning Verified iCloud Items',
    tone: 'sky',
    stepIndex: 7,
  },
  PURGING_PDPA: {
    labelTh: 'กำลังทำลายไฟล์พักและเซสชันตามมาตรฐาน PDPA',
    labelEn: 'Running PDPA Data Purge',
    tone: 'sky',
    stepIndex: 8,
  },
  COMPLETED: {
    labelTh: 'เสร็จสมบูรณ์และออกใบรับรอง PDPA แล้ว',
    labelEn: 'Completed & Certified',
    tone: 'emerald',
    stepIndex: 8,
  },
  FAILED: {
    labelTh: 'หยุดชั่วคราวเนื่องจากพบข้อผิดพลาด',
    labelEn: 'Paused / Attention Needed',
    tone: 'danger',
    stepIndex: 0,
  },
  CANCELLED: {
    labelTh: 'ยกเลิกรายการแล้ว',
    labelEn: 'Cancelled',
    tone: 'neutral',
    stepIndex: 0,
  },
};
