import type { Metadata } from 'next';
import { EncryptedSearchVault } from '@/components/EncryptedSearchVault';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Zero-Knowledge Encrypted AI Search Vault — CloudVault Concierge',
  description:
    'ค้นหาใบหน้า ข้อความภาษาไทยในภาพ (OCR) และหมวดหมู่ความทรงจำแบบ Zero-Knowledge E2EE ถอดรหัสในเบราว์เซอร์ของคุณ 100%',
};

export default async function SearchVaultPage({
  params,
  searchParams,
}: {
  params: Promise<{ vaultId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { vaultId } = await params;
  const sp = await searchParams;
  const rawToken =
    (typeof sp.t === 'string' ? sp.t : undefined) ??
    (typeof sp.token === 'string' ? sp.token : undefined) ??
    '';
  const isDemo =
    sp.demo === '1' ||
    sp.demo === 'true' ||
    vaultId.toLowerCase() === 'demo-family-archive';

  return (
    <EncryptedSearchVault
      vaultId={vaultId}
      initialToken={rawToken}
      isDemo={isDemo}
    />
  );
}
