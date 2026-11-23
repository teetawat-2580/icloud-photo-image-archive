import type { Metadata } from 'next';
import './globals.css';

const GOOGLE_FONTS_HREF =
  'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Noto+Sans+Thai:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap';

export const metadata: Metadata = {
  title: 'CloudVault Concierge — Selective iCloud Photo Archive & SHA-256 Verification Desk',
  description:
    'บริการย้ายและจัดเก็บภาพ iCloud ตามปีที่เลือก พร้อมตรวจ SHA-256 ครบ 1:1 เข้ารหัส E2E RSA-4096 แบบไม่เก็บรหัสผ่าน และออกใบรับรองลบข้อมูลตามมาตรฐาน PDPA',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="th">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link rel="stylesheet" href={GOOGLE_FONTS_HREF} />
      </head>
      <body className="min-h-screen bg-vault-canvas font-sans text-vault-ink antialiased">
        {children}
      </body>
    </html>
  );
}
