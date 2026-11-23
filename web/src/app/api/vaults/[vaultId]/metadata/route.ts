import { NextResponse } from 'next/server';
import {
  authenticateVaultRequest,
  extractVaultToken,
  VAULT_NO_STORE_HEADERS,
} from '@/lib/vault-auth';

export const dynamic = 'force-dynamic';

export async function GET(
  request: Request,
  context: { params: Promise<{ vaultId: string }> }
) {
  const { vaultId } = await context.params;
  const rawToken = extractVaultToken(request);

  const auth = await authenticateVaultRequest(vaultId, rawToken);
  if (!auth.ok) {
    return NextResponse.json(
      { error: auth.message, code: auth.code },
      { status: auth.status, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      vault: auth.vault,
      server_time: new Date().toISOString(),
    },
    { status: 200, headers: VAULT_NO_STORE_HEADERS }
  );
}
