import { NextResponse } from 'next/server';
import {
  authenticateVaultRequest,
  extractVaultToken,
  fetchEncryptedVaultBlob,
  validateVaultObjectKey,
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

  const url = new URL(request.url);
  const rawKey = url.searchParams.get('key')?.trim() ?? '';
  const validatedKey = validateVaultObjectKey(auth.vault.id, rawKey);
  if (!validatedKey) {
    return NextResponse.json(
      {
        error: 'Invalid or out-of-scope encrypted vault object key.',
        code: 'INVALID_OBJECT_KEY',
      },
      { status: 400, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  const blobRes = await fetchEncryptedVaultBlob(auth.vault, validatedKey);
  if (!blobRes.ok) {
    return NextResponse.json(
      { error: blobRes.error, code: 'BLOB_FETCH_FAILED' },
      { status: blobRes.status, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  const payload = new Uint8Array(blobRes.bytes.byteLength);
  payload.set(blobRes.bytes);

  return new NextResponse(payload.buffer, {
    status: 200,
    headers: {
      ...VAULT_NO_STORE_HEADERS,
      'Content-Type': 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Vault-Storage-Backend': auth.vault.storage_backend,
    },
  });
}
