import type { Metadata } from 'next';
import {
  JetBrains_Mono,
  Noto_Sans_Thai,
  Plus_Jakarta_Sans,
} from 'next/font/google';
import './globals.css';

const plusJakartaSans = Plus_Jakarta_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-plus-jakarta',
  display: 'swap',
});

const notoSansThai = Noto_Sans_Thai({
  subsets: ['thai', 'latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-noto-sans-thai',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
});

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
    <html
      lang="th"
      className={`${plusJakartaSans.variable} ${notoSansThai.variable} ${jetbrainsMono.variable}`}
    >
      <body className="min-h-screen bg-vault-canvas font-sans text-vault-ink antialiased">
        {children}
      </body>
    </html>
  );
}
