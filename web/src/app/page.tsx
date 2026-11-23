import {
  Check,
  ExternalLink,
  FileCheck2,
  FolderLock,
  HardDrive,
  Lock,
  MessageCircle,
  ShieldCheck,
  X,
} from 'lucide-react';
import { JobLinkOpener } from '@/components/JobLinkOpener';

const SPECIMEN_LEDGER_ROWS = [
  {
    year: 2015,
    files: '3,412 / 3,412',
    bytes: '18.4 GB',
    hash: '9c4e1a0b…7f32',
    locks: 5,
    status: 'Verified & Cleared',
  },
  {
    year: 2016,
    files: '4,890 / 4,890',
    bytes: '26.1 GB',
    hash: '3f8a22d9…e410',
    locks: 5,
    status: 'Verified & Cleared',
  },
  {
    year: 2017,
    files: '5,120 / 5,120',
    bytes: '31.7 GB',
    hash: 'b10d74cc…882a',
    locks: 4,
    status: 'Awaiting Lock 5 Sign-off',
  },
  {
    year: 2024,
    files: 'Kept on iPhone',
    bytes: 'Untouched',
    hash: 'Excluded by choice',
    locks: 0,
    status: 'Preserved on iCloud',
  },
] as const;

const COMPARISON_ROWS = [
  {
    criterion: 'เลือกย้ายเฉพาะปีที่ต้องการ (เช่น 2011–2020)',
    appleTransfer: 'ไม่ได้ — บังคับย้ายทั้งหมดทั้งคลังในครั้งเดียว',
    cloudVault: 'เลือกได้ละเอียดรายปี เก็บปีล่าสุดไว้ใช้งานบน iPhone ต่อทันที',
  },
  {
    criterion: 'หลักฐานตรวจความครบถ้วนระดับไฟล์ (1:1 Checksum)',
    appleTransfer: 'ไม่มีรายงานตรวจแฮชหรือรายชื่อไฟล์ที่ตกหล่น',
    cloudVault: 'ตรวจ SHA-256 ครบทุกไฟล์ 100% พร้อมตาราง Audit รายปี',
  },
  {
    criterion: 'การจัดระเบียบอัลบั้มบน Google Photos',
    appleTransfer: 'เทรวมลงหน้าคลังหลัก ปะปนกับอัลบั้มส่วนตัวที่มีอยู่เดิม',
    cloudVault: 'แยกอัลบั้มเฉพาะรายปีพร้อมระบบกันชน 3 ชั้น ไม่ยุ่งอัลบั้มเดิม',
  },
  {
    criterion: 'การเคลียร์พื้นที่ iCloud หลังย้ายเสร็จ',
    appleTransfer: 'ต้องไล่เลือกและลบเองบนมือถือ เสี่ยงลบผิดปีหรือลบภาพที่ยังไม่ขึ้น',
    cloudVault: 'เคลียร์เฉพาะไฟล์ที่ผ่านครบ 5-Lock และได้รับลายเซ็น "APPROVE" จากลูกค้า',
  },
  {
    criterion: 'การจัดการความเป็นส่วนตัวและรหัสผ่าน',
    appleTransfer: 'ทำผ่านพอร์ทัลมาตรฐานของ Apple เท่านั้น',
    cloudVault: 'ไม่เก็บรหัสผ่านบนคลาวด์ เข้ารหัส E2E RSA-4096 ในเบราว์เซอร์ + ออกใบรับรอง PDPA',
  },
] as const;

const PACKAGES = [
  {
    id: 'copy_only',
    badge: 'Zero Deletion Guarantee',
    titleTh: 'Copy-Only Archive',
    subtitleTh: 'สำเนาอย่างเดียว ไม่ลบต้นฉบับใน iCloud',
    highlight: false,
    idealFor: 'เหมาะสำหรับผู้ที่ต้องการสำรองภาพเก่าแยกตามปีขึ้น Google Photos เพื่อความอุ่นใจ โดยยังคงภาพเดิมทั้งหมดไว้ใน iCloud',
    features: [
      'เลือกเฉพาะปีที่ต้องการย้ายได้อิสระ',
      'ตรวจแฮช SHA-256 ครบ 100% ก่อนอัปโหลด',
      'แยกอัลบั้มบน Google Photos ตามปีด้วย 3-Layer Isolation',
      'ล็อกระบบฝั่ง API ห้ามสั่งลบไฟล์ใน iCloud เด็ดขาด',
    ],
  },
  {
    id: 'move_free_space',
    badge: 'Recommended — 5-Lock Verified',
    titleTh: 'Move & Free Space (5-Lock)',
    subtitleTh: 'ย้ายขึ้น Google Photos และเคลียร์พื้นที่ iCloud อย่างปลอดภัย',
    highlight: true,
    idealFor: 'เหมาะสำหรับ iPhone หรือ iCloud เต็ม ต้องการลดค่าเช่า iCloud รายเดือน โดยเก็บภาพปีปัจจุบันไว้บนเครื่องตามเดิม',
    features: [
      'ครบทุกขั้นตอนของ Copy-Only + ตรวจจับคู่ 1:1 รายปี',
      'ระบบป้องกัน 5-Lock ตรวจสอบครบ 4 ชั้นก่อนเปิดให้กดยืนยัน',
      'ลูกค้าตรวจลิงก์อัลบั้มจริงแล้วพิมพ์ "APPROVE" เพื่อปลดล็อก Lock 5',
      'เคลียร์เฉพาะไฟล์ที่ผ่าน Audit + ออกใบรับรองลบข้อมูลพักตาม PDPA',
    ],
  },
  {
    id: 'move_and_export',
    badge: 'Dual Custody (Cloud + Physical)',
    titleTh: 'Move + External Drive / NAS Export',
    subtitleTh: 'ย้ายขึ้นคลาวด์พร้อมส่งออกไฟล์ต้นฉบับลง SSD / NAS ส่วนตัว',
    highlight: false,
    idealFor: 'เหมาะสำหรับคลังภาพครอบครัวขนาดใหญ่ที่ต้องการสำเนาออฟไลน์ความละเอียดเต็มเก็บไว้กับตัวควบคู่กับ Google Photos',
    features: [
      'ได้ทั้งอัลบั้มบน Google Photos และโฟลเดอร์แยกปีบน External Drive / NAS',
      'แนบไฟล์ Manifest SHA-256 สำหรับตรวจสอบย้อนหลังได้ตลอดชีพ',
      'เลือกเปิดหรือปิดการเคลียร์พื้นที่ iCloud แบบ 5-Lock ได้ตามต้องการ',
      'ทำลายไฟล์พักในเครื่องทีมงานทันทีหลังส่งมอบ พร้อมใบรับรอง PDPA',
    ],
  },
] as const;

export default function LandingPage() {
  const lineContactUrl =
    process.env.NEXT_PUBLIC_LINE_CONTACT_URL?.trim() ||
    'https://line.me/R/ti/p/@cloudvault-concierge';

  return (
    <div className="min-h-screen bg-vault-canvas text-vault-ink">
      {/* Top Institutional Navigation */}
      <header className="sticky top-0 z-30 border-b border-vault-border bg-vault-canvas/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-5 py-3.5 sm:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-vault-ink bg-vault-ink text-white">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <p className="text-sm font-bold leading-tight tracking-tight text-vault-ink">
                CloudVault Concierge
              </p>
              <p className="text-xs text-vault-subtle">
                Selective iCloud Archive &amp; Verification Desk
              </p>
            </div>
          </div>

          <nav
            aria-label="Primary navigation"
            className="hidden items-center gap-7 text-sm font-medium text-vault-muted md:flex"
          >
            <a href="#comparison" className="transition-colors hover:text-vault-ink">
              ทำไมไม่ใช้ Apple Transfer
            </a>
            <a href="#packages" className="transition-colors hover:text-vault-ink">
              แพ็กเกจบริการ
            </a>
            <a href="#security" className="transition-colors hover:text-vault-ink">
              ความปลอดภัย E2E &amp; PDPA
            </a>
          </nav>

          <a
            href={lineContactUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-vault-emerald px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-teal-800"
          >
            <MessageCircle className="h-4 w-4" aria-hidden="true" />
            <span>ปรึกษาทาง LINE</span>
          </a>
        </div>
      </header>

      <main>
        {/* Asymmetric Editorial Hero + Live Verification Specimen */}
        <section className="border-b border-vault-border bg-vault-surface">
          <div className="mx-auto grid max-w-6xl gap-10 px-5 py-12 sm:px-8 lg:grid-cols-12 lg:items-start lg:py-16">
            <div className="space-y-6 lg:col-span-7">
              <div className="inline-flex items-center gap-2 rounded-full border border-vault-border bg-vault-canvas px-3.5 py-1 text-xs font-medium text-vault-muted">
                <span className="h-2 w-2 rounded-full bg-vault-emerald" aria-hidden="true" />
                <span>Zero-Password-Storage E2E RSA-4096 · 5-Lock Verified Archive</span>
              </div>

              <h1 className="max-w-2xl text-3xl font-bold leading-[1.2] tracking-tight text-vault-ink sm:text-4xl lg:text-[2.65rem]">
                ย้ายภาพ iCloud เก่าตามปีที่เลือก พร้อมหลักฐานตรวจ SHA-256 ครบทุกไฟล์
              </h1>

              <p className="max-w-xl text-base leading-relaxed text-vault-muted sm:text-[1.05rem]">
                เก็บภาพปีล่าสุดไว้ใช้งานบน iPhone ต่อได้ตามปกติ แล้วย้ายเฉพาะปีเก่าขึ้น Google Photos
                แบบแยกอัลบั้มรายปีโดยไม่ปะปนกับอัลบั้มส่วนตัว พร้อมหน้าติดตามงานสด ลายเซ็นยืนยัน
                5-Lock ก่อนเคลียร์พื้นที่ และใบรับรองลบข้อมูลพักตาม PDPA
              </p>

              <div className="flex flex-wrap items-center gap-3 pt-1">
                <a
                  href={lineContactUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg bg-vault-emerald px-5 py-3 text-sm font-semibold text-white shadow-vault transition-colors hover:bg-teal-800"
                >
                  <MessageCircle className="h-4 w-4" aria-hidden="true" />
                  <span>นัดประเมินพื้นที่และเปิดเคสทาง LINE</span>
                  <ExternalLink className="h-3.5 w-3.5 opacity-80" aria-hidden="true" />
                </a>
                <a
                  href="#packages"
                  className="inline-flex items-center gap-2 rounded-lg border border-vault-border bg-vault-surface px-5 py-3 text-sm font-semibold text-vault-ink transition-colors hover:bg-vault-canvas"
                >
                  <span>ดูแพ็กเกจทั้ง 3 รูปแบบ</span>
                </a>
              </div>

              {/* Direct Job Portal Link Opener */}
              <div id="track" className="pt-2">
                <JobLinkOpener />
              </div>
            </div>

            {/* Memorable Centerpiece: Verification Ledger Specimen */}
            <aside
              aria-label="Sample Verification Dossier"
              className="rounded-xl border border-vault-border bg-vault-canvas p-5 shadow-vault-elevated lg:col-span-5"
            >
              <div className="flex items-start justify-between gap-3 border-b border-vault-border pb-4">
                <div>
                  <p className="text-xs font-medium text-vault-subtle">
                    ตัวอย่างบัญชีตรวจรับรองรายปี (Verification Ledger)
                  </p>
                  <p className="mt-0.5 font-mono text-sm font-semibold text-vault-ink">
                    JOB CV-2026-0148 · move_free_space
                  </p>
                </div>
                <span className="inline-flex items-center gap-1.5 rounded-md border border-teal-200 bg-vault-emerald-soft px-2.5 py-1 text-xs font-semibold text-vault-emerald">
                  <Lock className="h-3 w-3" aria-hidden="true" />
                  <span>RSA-4096 E2E</span>
                </span>
              </div>

              <div className="mt-4 overflow-hidden rounded-lg border border-vault-border bg-vault-surface">
                <div className="grid grid-cols-12 border-b border-vault-border bg-vault-well px-3 py-2 text-[11px] font-semibold text-vault-muted">
                  <span className="col-span-2">ปี</span>
                  <span className="col-span-4">จำนวนไฟล์ / ขนาด</span>
                  <span className="col-span-3">SHA-256</span>
                  <span className="col-span-3 text-right">5-Lock</span>
                </div>

                <div className="divide-y divide-vault-border">
                  {SPECIMEN_LEDGER_ROWS.map((row) => (
                    <div
                      key={row.year}
                      className="grid grid-cols-12 items-center px-3 py-2.5 text-xs"
                    >
                      <span className="col-span-2 font-mono font-semibold text-vault-ink">
                        {row.year}
                      </span>
                      <div className="col-span-4">
                        <p className="font-mono text-[11px] font-medium text-vault-ink">
                          {row.files}
                        </p>
                        <p className="text-[11px] text-vault-subtle">{row.bytes}</p>
                      </div>
                      <span className="col-span-3 truncate font-mono text-[11px] text-vault-muted">
                        {row.hash}
                      </span>
                      <div className="col-span-3 flex flex-col items-end gap-1">
                        {row.locks > 0 ? (
                          <div className="flex items-center gap-0.5" aria-label={`${row.locks} of 5 locks passed`}>
                            {[1, 2, 3, 4, 5].map((n) => (
                              <span
                                key={n}
                                className={`h-2 w-2.5 rounded-sm ${
                                  n <= row.locks
                                    ? 'bg-vault-emerald'
                                    : 'bg-amber-300'
                                }`}
                              />
                            ))}
                          </div>
                        ) : (
                          <span className="rounded bg-vault-well px-1.5 py-0.5 text-[10px] font-medium text-vault-muted">
                            ไม่แตะต้อง
                          </span>
                        )}
                        <span
                          className={`text-[10px] font-medium ${
                            row.locks === 5
                              ? 'text-vault-emerald'
                              : row.locks === 4
                                ? 'text-vault-amber'
                                : 'text-vault-subtle'
                          }`}
                        >
                          {row.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-vault-border bg-vault-surface px-3.5 py-2.5 text-xs">
                <span className="text-vault-muted">Operator Key Fingerprint</span>
                <span className="font-mono text-[11px] font-medium text-vault-ink">
                  e7a49b12:0f91c820…4c910a77
                </span>
              </div>
            </aside>
          </div>
        </section>

        {/* Selective Year Archiving vs Apple Transfer */}
        <section id="comparison" className="border-b border-vault-border py-14 sm:py-16">
          <div className="mx-auto max-w-6xl px-5 sm:px-8">
            <div className="max-w-2xl">
              <h2 className="text-2xl font-bold tracking-tight text-vault-ink sm:text-3xl">
                Selective Year Archiving ต่างจาก Apple Transfer อย่างไร
              </h2>
              <p className="mt-3 text-base leading-relaxed text-vault-muted">
                เครื่องมือโอนย้ายของ Apple ถูกออกแบบให้ย้ายทั้งคลังแบบ All-or-Nothing
                แต่ลูกค้าส่วนใหญ่ต้องการเพียงย้ายภาพเก่าหลายปีก่อนออกเพื่อลดพื้นที่ iCloud
                โดยไม่กระทบภาพปีล่าสุดที่ยังเปิดดูทุกวันบน iPhone
              </p>
            </div>

            <div className="mt-8 overflow-x-auto rounded-xl border border-vault-border bg-vault-surface shadow-vault">
              <table className="w-full min-w-[680px] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-vault-border bg-vault-well">
                    <th className="w-[28%] px-5 py-3.5 font-semibold text-vault-ink">
                      หัวข้อเปรียบเทียบ
                    </th>
                    <th className="w-[34%] px-5 py-3.5 font-semibold text-vault-muted">
                      Apple iCloud Transfer (ทั่วไป)
                    </th>
                    <th className="w-[38%] px-5 py-3.5 font-semibold text-vault-emerald">
                      CloudVault Concierge
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-vault-border">
                  {COMPARISON_ROWS.map((row) => (
                    <tr key={row.criterion} className="align-top">
                      <td className="px-5 py-4 font-medium text-vault-ink">
                        {row.criterion}
                      </td>
                      <td className="px-5 py-4 text-vault-muted">
                        <span className="inline-flex items-start gap-2">
                          <X
                            className="mt-0.5 h-4 w-4 shrink-0 text-slate-400"
                            aria-hidden="true"
                          />
                          <span>{row.appleTransfer}</span>
                        </span>
                      </td>
                      <td className="bg-vault-emerald-soft/40 px-5 py-4 font-medium text-vault-ink">
                        <span className="inline-flex items-start gap-2">
                          <Check
                            className="mt-0.5 h-4 w-4 shrink-0 text-vault-emerald"
                            aria-hidden="true"
                          />
                          <span>{row.cloudVault}</span>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* 3 Service Packages */}
        <section id="packages" className="border-b border-vault-border bg-vault-surface py-14 sm:py-16">
          <div className="mx-auto max-w-6xl px-5 sm:px-8">
            <div className="max-w-2xl">
              <h2 className="text-2xl font-bold tracking-tight text-vault-ink sm:text-3xl">
                แพ็กเกจบริการ 3 รูปแบบ ตามระดับความปลอดภัยที่ต้องการ
              </h2>
              <p className="mt-3 text-base leading-relaxed text-vault-muted">
                ทุกรูปแบบใช้มาตรฐานตรวจแฮช SHA-256 ระดับไฟล์และแยกอัลบั้มส่วนตัวเหมือนกัน
                ต่างกันเฉพาะการเคลียร์พื้นที่ iCloud และการส่งออกลงสื่อเก็บข้อมูลภายนอก
              </p>
            </div>

            <div className="mt-8 grid gap-6 lg:grid-cols-3">
              {PACKAGES.map((pkg) => (
                <article
                  key={pkg.id}
                  className={`flex flex-col justify-between rounded-xl border p-6 ${
                    pkg.highlight
                      ? 'border-vault-emerald border-t-4 bg-vault-surface shadow-vault-elevated'
                      : 'border-vault-border bg-vault-canvas shadow-vault'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`inline-flex rounded-md px-2.5 py-1 text-xs font-semibold ${
                          pkg.highlight
                            ? 'bg-vault-emerald-soft text-vault-emerald'
                            : 'bg-vault-well text-vault-muted'
                        }`}
                      >
                        {pkg.badge}
                      </span>
                      <span className="font-mono text-xs text-vault-subtle">
                        {pkg.id}
                      </span>
                    </div>

                    <h3 className="mt-4 text-xl font-bold text-vault-ink">
                      {pkg.titleTh}
                    </h3>
                    <p className="mt-1 text-sm font-medium text-vault-sky">
                      {pkg.subtitleTh}
                    </p>
                    <p className="mt-3 text-sm leading-relaxed text-vault-muted">
                      {pkg.idealFor}
                    </p>

                    <ul className="mt-5 space-y-2.5 border-t border-vault-border pt-5 text-sm text-vault-ink">
                      {pkg.features.map((feature) => (
                        <li key={feature} className="flex items-start gap-2.5">
                          <Check
                            className="mt-0.5 h-4 w-4 shrink-0 text-vault-emerald"
                            aria-hidden="true"
                          />
                          <span>{feature}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="mt-6 pt-2">
                    <a
                      href={lineContactUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`inline-flex w-full items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors ${
                        pkg.highlight
                          ? 'bg-vault-emerald text-white hover:bg-teal-800'
                          : 'border border-vault-border bg-vault-surface text-vault-ink hover:bg-vault-well'
                      }`}
                    >
                      <span>เลือกแพ็กเกจนี้ทาง LINE</span>
                      <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                    </a>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* Security & Trust Architecture */}
        <section id="security" className="border-b border-vault-border py-14 sm:py-16">
          <div className="mx-auto max-w-6xl px-5 sm:px-8">
            <div className="max-w-2xl">
              <h2 className="text-2xl font-bold tracking-tight text-vault-ink sm:text-3xl">
                สถาปัตยกรรมความปลอดภัยที่ตรวจสอบได้จริง ไม่ใช่แค่คำสัญญา
              </h2>
              <p className="mt-3 text-base leading-relaxed text-vault-muted">
                ออกแบบมาเพื่อตัดความเสี่ยงด้านรหัสผ่าน การสลับอัลบั้ม และการลบไฟล์ก่อนตรวจสอบครบ 100%
              </p>
            </div>

            <div className="mt-8 grid gap-6 md:grid-cols-3">
              <div className="rounded-xl border border-vault-border bg-vault-surface p-6 shadow-vault">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-vault-sky-soft text-vault-sky">
                  <Lock className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="mt-4 text-base font-bold text-vault-ink">
                  Zero-Password-Storage E2E RSA-4096
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-vault-muted">
                  เบราว์เซอร์ของลูกค้าเข้ารหัสข้อมูลเชื่อมต่อและรหัส 2FA OTP ด้วยกุญแจสาธารณะ
                  <span className="mx-1 font-mono text-xs text-vault-ink">
                    RSA-OAEP-256 + AES-256-GCM
                  </span>
                  ก่อนส่งออก ฐานข้อมูลกลางเก็บเฉพาะซองเข้ารหัสชั่วคราว 15 นาทีและทำลายทันทีหลังถอดรหัสใน RAM
                </p>
              </div>

              <div className="rounded-xl border border-vault-border bg-vault-surface p-6 shadow-vault">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-vault-emerald-soft text-vault-emerald">
                  <FolderLock className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="mt-4 text-base font-bold text-vault-ink">
                  3-Layer Personal Album Isolation
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-vault-muted">
                  ทุกภาพที่ย้ายถูกจัดเข้าอัลบั้มเฉพาะของแต่ละปี (เช่น
                  <span className="mx-1 font-mono text-xs text-vault-ink">
                    iCloud_Archive_Google_2015
                  </span>
                  ) พร้อมตัวตรวจขอบเขต 3 ชั้น เพื่อรับประกันว่าจะไม่แก้ไขหรือลบอัลบั้มส่วนตัวที่มีอยู่เดิมบน Google Photos
                </p>
              </div>

              <div className="rounded-xl border border-vault-border bg-vault-surface p-6 shadow-vault">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-vault-amber-soft text-vault-amber">
                  <FileCheck2 className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="mt-4 text-base font-bold text-vault-ink">
                  5-Lock Cleanup &amp; PDPA Purge Certificate
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-vault-muted">
                  จะไม่มีการลบภาพใน iCloud จนกว่าครบ Lock 1–4 และลูกค้าตรวจอัลบั้มจริงแล้วพิมพ์ยืนยัน
                  <span className="mx-1 font-mono text-xs font-semibold text-vault-ink">
                    APPROVE
                  </span>
                  เมื่อปิดงาน ระบบจะทำลายไฟล์พักและคุกกี้ทั้งหมดพร้อมออกใบรับรอง PDPA ที่พิมพ์เก็บได้
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Concierge CTA Band */}
        <section className="bg-vault-ink py-12 text-white sm:py-14">
          <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 px-5 sm:px-8 md:flex-row md:items-center">
            <div className="max-w-xl">
              <div className="inline-flex items-center gap-2 text-xs font-medium text-teal-300">
                <HardDrive className="h-4 w-4" aria-hidden="true" />
                <span>รองรับตั้งแต่ 50 GB จนถึงคลังครอบครัวหลาย TB</span>
              </div>
              <h2 className="mt-2 text-2xl font-bold tracking-tight">
                พร้อมเคลียร์พื้นที่ iCloud แบบมีหลักฐานตรวจรับรองครบทุกไฟล์
              </h2>
              <p className="mt-2 text-sm leading-relaxed text-slate-300">
                ทักปรึกษาเพื่อเช็กขนาดคลังและเลือกปีที่ต้องการย้าย ทีมงานจะสร้างลิงก์ติดตามงานส่วนตัวพร้อม
                Operator RSA-4096 Key Fingerprint ให้คุณตรวจสอบก่อนเริ่มงาน
              </p>
            </div>
            <a
              href={lineContactUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-vault-emerald px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-teal-700"
            >
              <MessageCircle className="h-4 w-4" aria-hidden="true" />
              <span>ติดต่อ CloudVault Concierge ทาง LINE</span>
              <ExternalLink className="h-4 w-4 opacity-80" aria-hidden="true" />
            </a>
          </div>
        </section>
      </main>

      <footer className="border-t border-vault-border bg-vault-surface py-6">
        <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-3 px-5 text-xs text-vault-subtle sm:flex-row sm:items-center sm:px-8">
          <p>
            © {new Date().getFullYear()} CloudVault Concierge — Zero-Password-Storage Personal Archive Desk
          </p>
          <p className="font-mono">
            E2E: RSA-OAEP-256 + A256GCM · Audit: SHA-256 1:1
          </p>
        </div>
      </footer>
    </div>
  );
}
