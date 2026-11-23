'use client';

import { useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  generateCustomerVaultKeypairAndEncryptPrivateKey,
  type CustomerVaultKeySetup,
} from '@/lib/search-vault-crypto';
import type { SearchVaultPublicMetadata } from '@/lib/vault-auth';
import { DEMO_VAULT_PASSPHRASE } from '@/lib/search-vault-demo';

interface VaultPassphraseGateProps {
  vault: SearchVaultPublicMetadata;
  isDemo: boolean;
  unlockBusy: boolean;
  unlockError: string | null;
  onUnlock: (passphrase: string) => Promise<void>;
  onRegisterKeys: (setup: CustomerVaultKeySetup) => Promise<void>;
  onRefreshMetadata: () => Promise<void>;
}

function formatShortFingerprint(hex: string | null | undefined): string {
  if (!hex) return 'รอตั้งกุญแจส่วนตัว';
  const clean = hex.trim().toLowerCase();
  if (clean.length < 16) return clean;
  return `${clean.slice(0, 8)}:${clean.slice(8, 16)}…${clean.slice(-8)}`;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function VaultPassphraseGate({
  vault,
  isDemo,
  unlockBusy,
  unlockError,
  onUnlock,
  onRegisterKeys,
  onRefreshMetadata,
}: VaultPassphraseGateProps) {
  const [passphrase, setPassphrase] = useState(isDemo ? DEMO_VAULT_PASSPHRASE : '');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [setupBusy, setSetupBusy] = useState(false);
  const [setupError, setSetupError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const isFirstTimeSetup =
    vault.status === 'AWAITING_CUSTOMER_KEY' || !vault.encrypted_private_key_blob;
  const isWaitingForAiWorker =
    !isFirstTimeSetup &&
    (vault.status === 'KEY_REGISTERED' ||
      vault.status === 'INDEXING' ||
      !vault.wrapped_vault_key_b64 ||
      !vault.index_object_key);

  async function handleSetupSubmit(e: FormEvent) {
    e.preventDefault();
    setSetupError(null);
    if (passphrase.length < 8) {
      setSetupError('กรุณาตั้งรหัสผ่านตู้นิรภัยอย่างน้อย 8 ตัวอักษรเพื่อความปลอดภัยสูงสุด');
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setSetupError('รหัสผ่านทั้งสองช่องไม่ตรงกัน กรุณาตรวจสอบอีกครั้ง');
      return;
    }

    setSetupBusy(true);
    try {
      const setup = await generateCustomerVaultKeypairAndEncryptPrivateKey(passphrase, {
        iterations: 600_000,
        modulusLength: 2048,
      });
      await onRegisterKeys(setup);
      setPassphrase('');
      setConfirmPassphrase('');
    } catch (err) {
      setSetupError(
        err instanceof Error ? err.message : 'ไม่สามารถสร้างกุญแจเข้ารหัสในเบราว์เซอร์ได้'
      );
    } finally {
      setSetupBusy(false);
    }
  }

  async function handleUnlockSubmit(e: FormEvent) {
    e.preventDefault();
    if (!passphrase.trim()) return;
    await onUnlock(passphrase);
  }

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await onRefreshMetadata();
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6 sm:py-12">
      {/* Zero-Knowledge Cryptographic Proof Strip */}
      <div className="mb-6 rounded-xl border border-teal-200 bg-vault-emerald-soft/70 p-4 text-sm text-vault-ink">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-vault-emerald text-white">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="space-y-1">
            <p className="font-semibold text-vault-ink">
              ระบบตู้นิรภัยค้นหาภาพแบบ Zero-Knowledge (เข้ารหัสเฉพาะเจ้าของคลัง)
            </p>
            <p className="text-xs leading-relaxed text-vault-muted">
              กุญแจถอดรหัสและการค้นหาหน้าคน/ข้อความ OCR ทำงานในหน่วยความจำ RAM ของเบราว์เซอร์คุณ 100%
              ฐานข้อมูลกลาง (Supabase) และพื้นที่เก็บ Thumbnail เข้ารหัส (Cloudflare R2) เก็บเฉพาะข้อมูลรหัสลับที่อ่านไม่ออก
            </p>
          </div>
        </div>
      </div>

      {/* Main Vault Gate Card */}
      <section className="rounded-2xl border border-vault-border bg-vault-surface p-6 shadow-vault-elevated sm:p-8">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-vault-border pb-5">
          <div>
            <p className="font-mono text-xs font-semibold uppercase tracking-wider text-vault-sky">
              {vault.vault_code} · {vault.storage_backend === 'cloudflare_r2' ? 'Cloudflare R2 Encrypted' : 'PC Tunnel NAS'}
            </p>
            <h1 className="mt-1 text-2xl font-bold tracking-tight text-vault-ink">
              {vault.owner_display_name}
            </h1>
            <p className="mt-1 text-xs text-vault-subtle">
              Customer Public Key Fingerprint:{' '}
              <span className="font-mono font-medium text-vault-ink">
                {formatShortFingerprint(vault.customer_key_fingerprint_sha256)}
              </span>
            </p>
          </div>

          <span className="inline-flex items-center gap-1.5 rounded-full border border-vault-border bg-vault-canvas px-3 py-1.5 text-xs font-semibold text-vault-ink">
            <Lock className="h-3.5 w-3.5 text-vault-emerald" aria-hidden="true" />
            <span>
              {isFirstTimeSetup
                ? 'ขั้นที่ 1: ตั้งรหัสผ่านครั้งแรก'
                : isWaitingForAiWorker
                  ? 'กำลังรอเครื่องจัดดัชนีเข้ารหัส'
                  : 'ล็อกอยู่ · พร้อมปลดล็อก'}
            </span>
          </span>
        </div>

        {/* Demo Sandbox Helper Banner */}
        {isDemo && (
          <div className="mt-5 rounded-xl border border-sky-200 bg-vault-sky-soft p-4 text-xs text-vault-ink">
            <div className="flex items-start gap-2.5">
              <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-vault-sky" aria-hidden="true" />
              <div className="space-y-1">
                <p className="font-semibold text-vault-sky">
                  โหมดทดลองใช้งานจริง (Live WebCrypto Zero-Knowledge Sandbox)
                </p>
                <p className="leading-relaxed text-vault-muted">
                  เบราว์เซอร์เพิ่งสร้างกุญแจ RSA-OAEP-2048 + เข้ารหัสฐานดัชนี OCR ภาษาไทยและรูป Thumbnail ทั้ง 6 ภาพด้วย AES-256-GCM เสร็จสดๆ
                  คุณสามารถกดปุ่ม <strong className="text-vault-ink">ปลดล็อกตู้นิรภัย</strong> ด้วยรหัสทดสอบ{' '}
                  <code className="rounded bg-white px-1.5 py-0.5 font-mono font-semibold text-vault-ink">
                    {DEMO_VAULT_PASSPHRASE}
                  </code>{' '}
                  หรือลองพิมพ์รหัสผิดเพื่อทดสอบการปฏิเสธของ WebCrypto ได้ทันที
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Vault Aggregate Metrics (Zero PII) */}
        {!isFirstTimeSetup && (
          <div className="mt-5 grid grid-cols-3 gap-3">
            <div className="rounded-xl border border-vault-border bg-vault-canvas p-3 text-center">
              <p className="font-mono text-lg font-bold text-vault-ink">
                {vault.total_assets.toLocaleString()}
              </p>
              <p className="text-[11px] text-vault-muted">ภาพที่จัดดัชนี</p>
            </div>
            <div className="rounded-xl border border-vault-border bg-vault-canvas p-3 text-center">
              <p className="font-mono text-lg font-bold text-vault-ink">
                {vault.total_faces.toLocaleString()}
              </p>
              <p className="text-[11px] text-vault-muted">กลุ่มใบหน้า AI</p>
            </div>
            <div className="rounded-xl border border-vault-border bg-vault-canvas p-3 text-center">
              <p className="font-mono text-lg font-bold text-vault-ink">
                {formatBytes(vault.index_size_bytes + vault.total_thumb_bytes)}
              </p>
              <p className="text-[11px] text-vault-muted">ขนาดเข้ารหัส</p>
            </div>
          </div>
        )}

        {/* STATE 1: First-Time Customer Keypair Setup */}
        {isFirstTimeSetup && (
          <form onSubmit={handleSetupSubmit} className="mt-6 space-y-4">
            <div className="rounded-xl border border-vault-border bg-vault-canvas p-4 text-xs leading-relaxed text-vault-muted">
              <p className="font-semibold text-vault-ink">
                ขั้นตอนสร้างกุญแจส่วนตัวในเบราว์เซอร์ (ทำเพียงครั้งเดียว)
              </p>
              <p className="mt-1">
                ตั้งรหัสผ่านที่จำได้ง่ายสำหรับตัวคุณเอง เบราว์เซอร์จะสร้างคู่กุญแจ{' '}
                <span className="font-mono text-vault-ink">RSA-OAEP + PBKDF2 (600,000 รอบ)</span>{' '}
                แล้วส่งเฉพาะ <strong className="text-vault-ink">กุญแจสาธารณะ (Public Key)</strong>{' '}
                ให้เครื่อง PC นำไปล็อกภาพแบบทางเดียว เพื่อที่เจ้าของเครื่อง PC และฐานข้อมูลคลาวด์จะไม่สามารถเปิดดูได้หลังล็อกเสร็จ
              </p>
            </div>

            <div>
              <label
                htmlFor="vault-setup-pass"
                className="block text-sm font-semibold text-vault-ink"
              >
                ตั้งรหัสผ่านตู้นิรภัยส่วนตัว (อย่างน้อย 8 ตัวอักษร)
              </label>
              <div className="relative mt-1.5">
                <input
                  id="vault-setup-pass"
                  type={showPassphrase ? 'text' : 'password'}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  autoComplete="new-password"
                  placeholder="เช่น MyFamilyArchive2569"
                  required
                  minLength={8}
                  className="min-h-[48px] w-full rounded-xl border border-vault-border bg-vault-surface px-4 pr-12 text-base text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase((v) => !v)}
                  aria-label={showPassphrase ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}
                  className="absolute right-2 top-1/2 flex h-10 w-10 -translate-y-1/2 items-center justify-center rounded-lg text-vault-muted hover:bg-vault-well"
                >
                  {showPassphrase ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>

            <div>
              <label
                htmlFor="vault-setup-confirm"
                className="block text-sm font-semibold text-vault-ink"
              >
                ยืนยันรหัสผ่านอีกครั้ง
              </label>
              <input
                id="vault-setup-confirm"
                type={showPassphrase ? 'text' : 'password'}
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                autoComplete="new-password"
                placeholder="พิมพ์รหัสผ่านเดิมซ้ำอีกครั้ง"
                required
                minLength={8}
                className="mt-1.5 min-h-[48px] w-full rounded-xl border border-vault-border bg-vault-surface px-4 text-base text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:outline-none"
              />
            </div>

            {setupError && (
              <p
                role="alert"
                className="rounded-lg border border-red-200 bg-red-50 px-3.5 py-2.5 text-sm font-medium text-red-700"
              >
                {setupError}
              </p>
            )}

            <button
              type="submit"
              disabled={setupBusy}
              className="inline-flex min-h-[50px] w-full items-center justify-center gap-2 rounded-xl bg-vault-emerald px-5 py-3 text-base font-semibold text-white shadow-vault transition-colors hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <KeyRound className="h-5 w-5" aria-hidden="true" />
              <span>
                {setupBusy
                  ? 'กำลังสร้างกุญแจ RSA-OAEP & PBKDF2 ในเบราว์เซอร์…'
                  : 'สร้างกุญแจส่วนตัวและลงทะเบียนตู้นิรภัย'}
              </span>
            </button>
          </form>
        )}

        {/* STATE 2: Key Registered — Waiting for Local PC AI Worker to Encrypt & Upload */}
        {isWaitingForAiWorker && (
          <div className="mt-6 space-y-4">
            <div className="rounded-xl border border-amber-200 bg-vault-amber-soft p-4 text-sm text-vault-ink">
              <div className="flex items-start gap-2.5">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-vault-emerald" />
                <div className="space-y-1">
                  <p className="font-semibold">
                    ลงทะเบียนกุญแจสาธารณะเรียบร้อยแล้ว (สถานะ: {vault.status})
                  </p>
                  <p className="text-xs leading-relaxed text-vault-muted">
                    เครื่องผู้ช่วยประมวลผล AI (InsightFace + Thai RapidOCR + CLIP) กำลังสร้างดัชนีและล็อกไฟล์ด้วยกุญแจสาธารณะของคุณ
                    เมื่ออัปโหลดไฟล์เข้ารหัสเสร็จและล้างไฟล์ชั่วคราวหมดแล้ว หน้านี้จะเปิดช่องให้ปลดล็อกค้นหาภาพทันที
                  </p>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={handleRefresh}
              disabled={refreshing}
              className="inline-flex min-h-[48px] w-full items-center justify-center gap-2 rounded-xl border border-vault-border bg-vault-surface px-4 py-3 text-sm font-semibold text-vault-ink hover:bg-vault-well"
            >
              <RefreshCw
                className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              <span>{refreshing ? 'กำลังตรวจสอบสถานะล่าสุด…' : 'รีเฟรชตรวจสอบสถานะดัชนี'}</span>
            </button>
          </div>
        )}

        {/* STATE 3: Ready to Unlock in Browser RAM */}
        {!isFirstTimeSetup && !isWaitingForAiWorker && (
          <form onSubmit={handleUnlockSubmit} className="mt-6 space-y-4">
            <div>
              <label
                htmlFor="vault-unlock-pass"
                className="block text-sm font-semibold text-vault-ink"
              >
                กรอกรหัสผ่านตู้นิรภัยของคุณเพื่อปลดล็อกในเครื่องนี้
              </label>
              <div className="relative mt-1.5">
                <input
                  id="vault-unlock-pass"
                  type={showPassphrase ? 'text' : 'password'}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  autoComplete="current-password"
                  placeholder="กรอกรหัสผ่านตู้นิรภัยของคุณ"
                  required
                  className="min-h-[50px] w-full rounded-xl border border-vault-border bg-vault-surface px-4 pr-12 text-base text-vault-ink placeholder:text-vault-subtle focus:border-vault-sky focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase((v) => !v)}
                  aria-label={showPassphrase ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน'}
                  className="absolute right-2 top-1/2 flex h-10 w-10 -translate-y-1/2 items-center justify-center rounded-lg text-vault-muted hover:bg-vault-well"
                >
                  {showPassphrase ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>

            {unlockError && (
              <p
                role="alert"
                className="rounded-lg border border-red-200 bg-red-50 px-3.5 py-2.5 text-sm font-medium text-red-700"
              >
                {unlockError}
              </p>
            )}

            <button
              type="submit"
              disabled={unlockBusy}
              className="inline-flex min-h-[52px] w-full items-center justify-center gap-2 rounded-xl bg-vault-emerald px-5 py-3 text-base font-semibold text-white shadow-vault transition-colors hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Lock className="h-5 w-5" aria-hidden="true" />
              <span>
                {unlockBusy
                  ? 'กำลังถอดรหัสกุญแจและเปิดดัชนีใน RAM…'
                  : 'ปลดล็อกตู้นิรภัยและเริ่มค้นหาภาพ'}
              </span>
            </button>

            {vault.plaintext_purged_at && (
              <p className="text-center text-xs text-vault-subtle">
                ยืนยันการล้างไฟล์ต้นฉบับชั่วคราวบนเครื่องประมวลผลแล้วเมื่อ{' '}
                <span className="font-mono text-vault-ink">
                  {new Date(vault.plaintext_purged_at).toLocaleString('th-TH')}
                </span>
              </p>
            )}
          </form>
        )}
      </section>
    </div>
  );
}
