import { NextResponse } from 'next/server';
import {
  authenticateVaultRequest,
  extractVaultToken,
  validateEncryptedPersonLabelsPayload,
  VAULT_NO_STORE_HEADERS,
} from '@/lib/vault-auth';

export const dynamic = 'force-dynamic';

export async function PATCH(
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

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: 'Request body must be valid JSON.', code: 'INVALID_JSON' },
      { status: 400, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  const candidate =
    body && typeof body === 'object' && 'encrypted_person_labels_blob' in body
      ? (body as Record<string, unknown>).encrypted_person_labels_blob
      : body;

  const validation = validateEncryptedPersonLabelsPayload(candidate);
  if (!validation.ok) {
    return NextResponse.json(
      { error: validation.error, code: 'INVALID_PERSON_LABELS_BLOB' },
      { status: 400, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  const { error } = await auth.supabase
    .from('search_vaults')
    .update({
      encrypted_person_labels_blob: validation.blob,
    })
    .eq('id', auth.vault.id);

  if (error) {
    return NextResponse.json(
      { error: 'Failed to store encrypted person labels.', code: 'SAVE_LABELS_FAILED' },
      { status: 500, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      ok: true,
      updated_at: new Date().toISOString(),
    },
    { status: 200, headers: VAULT_NO_STORE_HEADERS }
  );
}
