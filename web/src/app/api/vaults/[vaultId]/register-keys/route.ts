import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import {
  authenticateVaultRequest,
  extractVaultToken,
  validateVaultKeyRegistrationPayload,
  VAULT_NO_STORE_HEADERS,
} from '@/lib/vault-auth';

export const dynamic = 'force-dynamic';

export async function POST(
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

  if (
    auth.vault.customer_public_key_pem ||
    auth.vault.status !== 'AWAITING_CUSTOMER_KEY'
  ) {
    return NextResponse.json(
      {
        error: 'Customer vault keypair is already registered and locked against overwrite.',
        code: 'KEY_ALREADY_REGISTERED',
      },
      { status: 409, headers: VAULT_NO_STORE_HEADERS }
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

  const validation = validateVaultKeyRegistrationPayload(body);
  if (!validation.ok) {
    return NextResponse.json(
      { error: validation.error, code: 'INVALID_KEY_REGISTRATION' },
      { status: 400, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  // Verify fingerprint parity with the submitted public key PEM
  const expectedPemSha = createHash('sha256')
    .update(validation.data.customer_public_key_pem, 'utf8')
    .digest('hex');
  const trimmedPemSha = createHash('sha256')
    .update(validation.data.customer_public_key_pem.trimEnd(), 'utf8')
    .digest('hex');
  const submittedFp = validation.data.customer_key_fingerprint_sha256;
  if (submittedFp !== expectedPemSha && submittedFp !== trimmedPemSha) {
    return NextResponse.json(
      {
        error: 'customer_key_fingerprint_sha256 does not match customer_public_key_pem.',
        code: 'KEY_FINGERPRINT_MISMATCH',
      },
      { status: 400, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  const { data, error } = await auth.supabase
    .from('search_vaults')
    .update({
      customer_public_key_pem: validation.data.customer_public_key_pem,
      customer_key_fingerprint_sha256: validation.data.customer_key_fingerprint_sha256,
      encrypted_private_key_blob: validation.data.encrypted_private_key_blob,
      status: 'KEY_REGISTERED',
    })
    .eq('id', auth.vault.id)
    .eq('status', 'AWAITING_CUSTOMER_KEY')
    .select('id, vault_code, status, customer_key_fingerprint_sha256, updated_at')
    .maybeSingle();

  if (error || !data) {
    return NextResponse.json(
      { error: 'Failed to save customer vault public key.', code: 'KEY_SAVE_FAILED' },
      { status: 500, headers: VAULT_NO_STORE_HEADERS }
    );
  }

  return NextResponse.json(
    {
      ok: true,
      vault: data,
    },
    { status: 200, headers: VAULT_NO_STORE_HEADERS }
  );
}
