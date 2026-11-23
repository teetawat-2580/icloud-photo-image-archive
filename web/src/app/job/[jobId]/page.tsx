import type { Metadata } from 'next';
import { CustomerJobPortal } from '@/components/CustomerJobPortal';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Job Verification Desk — CloudVault Concierge',
  robots: {
    index: false,
    follow: false,
  },
};

export default async function CustomerJobPage({
  params,
  searchParams,
}: {
  params: Promise<{ jobId: string }>;
  searchParams: Promise<{ t?: string | string[]; token?: string | string[] }>;
}) {
  const [{ jobId }, resolvedSearch] = await Promise.all([params, searchParams]);
  const pickParam = (val?: string | string[]): string =>
    Array.isArray(val) ? val[0] ?? '' : val ?? '';
  const rawToken = pickParam(resolvedSearch.t) || pickParam(resolvedSearch.token);

  return <CustomerJobPortal jobId={jobId} initialToken={rawToken} />;
}
