import test from 'node:test';
import assert from 'node:assert/strict';

import {
  decryptPersonLabels,
  decryptSearchIndexBundle,
  decryptVaultBlobAesGcm,
  encryptPersonLabels,
  encryptSearchIndexBundleForTest,
  encryptVaultBlobAesGcm,
  generateCustomerVaultKeypairAndEncryptPrivateKey,
  unlockCustomerPrivateKey,
  unwrapVaultDataKey,
  wrapVaultDataKeyWithPublicPem,
} from '../src/lib/search-vault-crypto.ts';
import {
  buildSafeHighlightSegments,
  resolveSafeMediaUrl,
  searchEncryptedVaultIndex,
} from '../src/lib/search-vault-engine.ts';
import {
  buildR2SigV4Headers,
  validateVaultKeyRegistrationPayload,
  validateVaultObjectKey,
} from '../src/lib/vault-auth.ts';

test('WebCrypto One-Way Public-Key E2EE: customer passphrase unlocks private key, unwraps PC vault key, decrypts Thai OCR index & WebP thumbnail, and rejects tampering', async () => {
  const passphrase = 'Mom-Vault-Secret-2569!';
  const setup = await generateCustomerVaultKeypairAndEncryptPrivateKey(passphrase, {
    iterations: 10_000, // Fast override strictly for unit test speed; production default is 600,000
    modulusLength: 2048,
  });

  assert.match(setup.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/);
  assert.match(setup.keyFingerprintSha256, /^[a-f0-9]{64}$/);
  assert.equal(setup.encryptedPrivateKeyBlob.kdf, 'PBKDF2-SHA256');
  assert.equal(setup.encryptedPrivateKeyBlob.alg, 'AES-256-GCM');

  // Wrong passphrase MUST reject
  await assert.rejects(
    () => unlockCustomerPrivateKey(setup.encryptedPrivateKeyBlob, 'Wrong-Passphrase!'),
    /OperationError|decrypt|passphrase|failed/i
  );

  // Correct passphrase unlocks non-extractable RSA-OAEP private key in RAM
  const privateKey = await unlockCustomerPrivateKey(setup.encryptedPrivateKeyBlob, passphrase);
  assert.equal(privateKey.extractable, false);

  // Operator PC generates ephemeral 32-byte AES data key and wraps it ONE-WAY using ONLY customer public key
  const rawVaultKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const wrappedKeyB64 = await wrapVaultDataKeyWithPublicPem(rawVaultKey, setup.publicKeyPem);

  // Customer unwraps non-extractable AES-256-GCM vault key in RAM
  const vaultDataKey = await unwrapVaultDataKey(wrappedKeyB64, privateKey);
  assert.equal(vaultDataKey.extractable, false);

  const vaultId = '11111111-2222-4333-8444-555555555555';
  const sampleIndex = {
    schema_version: 2,
    vault_id: vaultId,
    generated_at: '2026-11-23T08:00:00Z',
    media_source_type: 'google_photos_shared',
    media_source_config: {},
    people: [
      { person_id: 'person_001', default_label: 'คนที่ 1', photo_count: 1, avatar_thumb_key: `vaults/${vaultId}/thumbs/cake.enc` },
    ],
    assets: [
      {
        sha256: 'a'.repeat(64),
        filename: 'IMG_2018_CAKE.JPG',
        captured_at: '2018-12-31T21:12:24+07:00',
        year: 2018,
        thumb_key: `vaults/${vaultId}/thumbs/cake.enc`,
        face_ids: ['person_001'],
        ocr_text: 'สวัสดีปีใหม่ 2562 Happy New Year',
        semantic_tags: ['เค้ก / วันเกิด', 'ครอบครัว'],
        media_ref: {
          provider: 'google_photos_shared',
          album_key: '2005-2008',
          album_title: 'Family_Archive_Google (2005-2008)',
          url: 'https://photos.app.goo.gl/ExampleShared2005To2008',
        },
      },
    ],
  };

  const encryptedBundle = await encryptSearchIndexBundleForTest(sampleIndex, rawVaultKey, vaultId);
  const bundleText = new TextDecoder().decode(encryptedBundle);
  assert.equal(bundleText.includes('สวัสดีปีใหม่'), false);

  const decryptedIndex = await decryptSearchIndexBundle(encryptedBundle, vaultDataKey, vaultId);
  assert.deepEqual(decryptedIndex, sampleIndex);

  // Wrong AAD (wrong vaultId) MUST fail
  await assert.rejects(
    () => decryptSearchIndexBundle(encryptedBundle, vaultDataKey, 'other-vault-id'),
    /OperationError|decrypt|failed/i
  );

  // Thumbnail AES-256-GCM round-trip
  const rawThumb = new TextEncoder().encode('RIFF....WEBPVP8-MOCK-THUMBNAIL');
  const thumbKey = `vaults/${vaultId}/thumbs/cake.enc`;
  const encThumb = await encryptVaultBlobAesGcm(rawThumb, rawVaultKey, `${vaultId}:${thumbKey}`);
  const decThumb = await decryptVaultBlobAesGcm(encThumb, vaultDataKey, `${vaultId}:${thumbKey}`);
  assert.deepEqual(decThumb, rawThumb);

  // Encrypted custom person labels round-trip
  const encLabels = await encryptPersonLabels({ person_001: 'คุณแม่' }, vaultDataKey, vaultId);
  const decLabels = await decryptPersonLabels(encLabels, vaultDataKey, vaultId);
  assert.deepEqual(decLabels, { person_001: 'คุณแม่' });
});

test('Client-Side Zero-Knowledge Search Engine supports Thai OCR, multi-face AND filter, custom person names, semantic tags, XSS-safe highlights, and Pluggable Media Source URL allowlisting', () => {
  const index = {
    schema_version: 2,
    vault_id: 'v1',
    generated_at: '2026-11-23T08:00:00Z',
    media_source_type: 'google_photos_shared',
    media_source_config: {},
    people: [
      { person_id: 'person_001', default_label: 'คนที่ 1', photo_count: 2, avatar_thumb_key: 't1' },
      { person_id: 'person_002', default_label: 'คนที่ 2', photo_count: 1, avatar_thumb_key: 't2' },
    ],
    assets: [
      {
        sha256: '1'.repeat(64),
        filename: 'IMG_CAKE_2562.JPG',
        captured_at: '2018-12-31T21:12:24+07:00',
        year: 2018,
        thumb_key: 't1',
        face_ids: ['person_001', 'person_002'],
        ocr_text: 'สวัสดีปีใหม่ 2562 เค้กปีใหม่',
        semantic_tags: ['เค้ก / วันเกิด', 'ครอบครัว'],
        media_ref: { provider: 'google_photos_shared', url: 'https://photos.app.goo.gl/Example1' },
      },
      {
        sha256: '2'.repeat(64),
        filename: 'IMG_SLIP_2019.JPG',
        captured_at: '2019-06-15T10:00:00+07:00',
        year: 2019,
        thumb_key: 't2',
        face_ids: ['person_001'],
        ocr_text: 'โอนเงินสำเร็จ ธนาคารกสิกรไทย 15,000 บาท',
        semantic_tags: ['เอกสาร / สลิป'],
        media_ref: { provider: 'google_photos_shared', url: 'https://photos.app.goo.gl/Example2' },
      },
    ],
  };

  const customLabels = { person_001: 'คุณแม่', person_002: 'คุณยาย' };

  // Thai OCR substring search
  const resCake = searchEncryptedVaultIndex(index, { query: 'สวัสดีปีใหม่ 2562' }, customLabels);
  assert.equal(resCake.length, 1);
  assert.equal(resCake[0].filename, 'IMG_CAKE_2562.JPG');

  // Search by renamed custom person label ("คุณยาย")
  const resByName = searchEncryptedVaultIndex(index, { query: 'คุณยาย' }, customLabels);
  assert.equal(resByName.length, 1);
  assert.equal(resByName[0].sha256, '1'.repeat(64));

  // Multi-face AND filter
  const resBothFaces = searchEncryptedVaultIndex(
    index,
    { selectedPersonIds: ['person_001', 'person_002'] },
    customLabels
  );
  assert.equal(resBothFaces.length, 1);

  // Semantic tag + year filter
  const resSlip = searchEncryptedVaultIndex(
    index,
    { selectedTag: 'เอกสาร / สลิป', selectedYear: 2019 },
    customLabels
  );
  assert.equal(resSlip.length, 1);
  assert.equal(resSlip[0].filename, 'IMG_SLIP_2019.JPG');

  // Pluggable Media Source resolver & XSS URL blocking
  assert.equal(
    resolveSafeMediaUrl({
      provider: 'google_photos_shared',
      url: 'https://photos.app.goo.gl/Example1',
    }),
    'https://photos.app.goo.gl/Example1'
  );
  assert.equal(
    resolveSafeMediaUrl({
      provider: 'nas_immich',
      url: 'https://nas.family.example.com/photos/asset-123',
    }),
    'https://nas.family.example.com/photos/asset-123'
  );
  assert.equal(
    resolveSafeMediaUrl({
      provider: 'google_photos_shared',
      url: 'javascript:alert(document.cookie)',
    }),
    null
  );
  assert.equal(
    resolveSafeMediaUrl({
      provider: 'google_photos_shared',
      url: 'https://evil.attacker.example/phish',
    }),
    null
  );

  // Safe React highlight segments (no HTML injection)
  const segments = buildSafeHighlightSegments('สวัสดีปีใหม่ <script>2562</script>', '2562');
  assert.equal(segments.some((s) => s.match && s.text === '2562'), true);
});

test('Server-side Vault Auth, Scoped Object Key Validation, and Pure-Node Cloudflare R2 SigV4 headers enforce OWASP A01/A02/A10', () => {
  const vaultId = '11111111-2222-4333-8444-555555555555';

  // Scoped vault object keys pass; traversal & cross-vault IDOR fail
  assert.equal(
    validateVaultObjectKey(vaultId, `vaults/${vaultId}/index_bundle.json.gz.enc`),
    `vaults/${vaultId}/index_bundle.json.gz.enc`
  );
  assert.equal(validateVaultObjectKey(vaultId, `vaults/other-vault/index_bundle.json.gz.enc`), null);
  assert.equal(validateVaultObjectKey(vaultId, `vaults/${vaultId}/../other/secret.enc`), null);
  assert.equal(validateVaultObjectKey(vaultId, `vaults/${vaultId}/plain.jpg`), null);

  // Key registration validator enforces minimum 100k PBKDF2 iterations & 12-byte GCM IV
  const weakKdf = validateVaultKeyRegistrationPayload({
    customer_public_key_pem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----',
    customer_key_fingerprint_sha256: 'a'.repeat(64),
    encrypted_private_key_blob: {
      version: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: 1000,
      alg: 'AES-256-GCM',
      salt_b64: Buffer.alloc(16).toString('base64'),
      iv_b64: Buffer.alloc(12).toString('base64'),
      ciphertext_b64: Buffer.from('cipher-payload-16bytes').toString('base64'),
    },
  });
  assert.equal(weakKdf.ok, false);

  const validKdf = validateVaultKeyRegistrationPayload({
    customer_public_key_pem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----',
    customer_key_fingerprint_sha256: 'a'.repeat(64),
    encrypted_private_key_blob: {
      version: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: 600_000,
      alg: 'AES-256-GCM',
      salt_b64: Buffer.alloc(16).toString('base64'),
      iv_b64: Buffer.alloc(12).toString('base64'),
      ciphertext_b64: Buffer.from('cipher-payload-16bytes').toString('base64'),
    },
  });
  assert.equal(validKdf.ok, true);

  // Pure-Node R2 SigV4 header generation
  const headers = buildR2SigV4Headers({
    method: 'GET',
    url: `https://acct123.r2.cloudflarestorage.com/cloudvault-blobs/vaults/${vaultId}/index_bundle.json.gz.enc`,
    accessKeyId: 'AKIAEXAMPLE',
    secretAccessKey: 'SecretExampleKey',
    amzDate: '20261123T080000Z',
  });
  assert.ok(headers.Authorization.startsWith('AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261123/auto/s3/aws4_request'));
  assert.equal(headers['x-amz-date'], '20261123T080000Z');
});
