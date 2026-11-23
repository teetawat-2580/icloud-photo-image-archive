/**
 * CloudVault Concierge — Zero-Knowledge Encrypted AI Search Vault (Browser WebCrypto).
 *
 * Cross-language binary parity with `workbench/search_vault_crypto.py`:
 * - Customer Keypair: RSA-OAEP (SHA-256), Public Key uploaded as SPKI PEM; Private Key PKCS#8 PEM
 *   encrypted in browser RAM using PBKDF2-SHA256 (default 600,000 iterations) + AES-256-GCM
 *   with AAD `cloudvault:customer_private_key:v1`.
 * - One-Way Vault Key Wrapping: PC Operator wraps random 32-byte AES data key using ONLY Customer Public Key.
 * - Encrypted Blobs: `[12-byte IV][ciphertext || 16-byte GCM auth tag]` with UTF-8 AAD:
 *   - Search Index Bundle: gzipped UTF-8 JSON with AAD `${vaultId}:index_bundle`
 *   - Thumbnail Blobs: WebP bytes with AAD `${vaultId}:${thumbKey}`
 *   - Custom Person Labels: JSON `{ version: 1, alg: 'AES-256-GCM', iv_b64, ciphertext_b64 }` with AAD `${vaultId}:person_labels`
 *
 * ZERO Node-only imports so this module executes identically in Chrome, Safari 16.4+, Firefox, and Node 22+.
 */

export interface EncryptedPrivateKeyBlob {
  version: 1;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  alg: 'AES-256-GCM';
  salt_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
}

export interface EncryptedPersonLabelsBlob {
  version: 1;
  alg: 'AES-256-GCM';
  iv_b64: string;
  ciphertext_b64: string;
}

export interface SearchVaultPerson {
  person_id: string;
  default_label: string;
  photo_count: number;
  avatar_thumb_key: string | null;
}

export interface SearchVaultMediaRef {
  provider: 'google_photos_shared' | 'google_photos_private' | 'nas_immich' | 'local_hdd';
  album_key?: string | null;
  album_title?: string | null;
  url?: string | null;
  local_path?: string | null;
  filename?: string | null;
}

export interface SearchVaultAsset {
  sha256: string;
  filename: string;
  captured_at: string;
  year: number;
  thumb_key: string;
  face_ids: string[];
  ocr_text: string;
  semantic_tags: string[];
  media_ref: SearchVaultMediaRef;
}

export interface DecryptedSearchIndex {
  schema_version: number;
  vault_id: string;
  generated_at: string;
  media_source_type: string;
  media_source_config: Record<string, unknown>;
  people: SearchVaultPerson[];
  assets: SearchVaultAsset[];
}

export interface CustomerVaultKeySetup {
  publicKeyPem: string;
  keyFingerprintSha256: string;
  encryptedPrivateKeyBlob: EncryptedPrivateKeyBlob;
}

const PRIVATE_KEY_AAD = 'cloudvault:customer_private_key:v1';
const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const MIN_PBKDF2_ITERATIONS = 10_000;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const PBKDF2_SALT_BYTES = 16;

const PEM_HEADER_REGEX = /-----BEGIN [A-Z0-9 ]+-----/g;
const PEM_FOOTER_REGEX = /-----END [A-Z0-9 ]+-----/g;
const WHITESPACE_REGEX = /\s+/g;

function getSubtleCrypto(): SubtleCrypto {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error(
      'WebCrypto API (crypto.subtle) is unavailable in this environment. HTTPS or localhost is required.'
    );
  }
  return cryptoObj.subtle;
}

function toArrayBufferView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

function encodeUtf8(value: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(value);
  return toArrayBufferView(encoded);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const cleaned = b64.replace(WHITESPACE_REGEX, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function derBytesToPem(derBytes: Uint8Array, label: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
  const b64 = bytesToBase64(derBytes);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function pemToDerBytes(pem: string): Uint8Array<ArrayBuffer> {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new Error('PEM key must be a non-empty string.');
  }
  const body = pem
    .replace(PEM_HEADER_REGEX, '')
    .replace(PEM_FOOTER_REGEX, '')
    .replace(WHITESPACE_REGEX, '');
  if (!body) {
    throw new Error('PEM key contains no base64 payload.');
  }
  return base64ToBytes(body);
}

export async function computePublicKeyFingerprintSha256(publicKeyPem: string): Promise<string> {
  const subtle = getSubtleCrypto();
  const normalized = publicKeyPem.replace(/\r\n/g, '\n');
  const digest = await subtle.digest('SHA-256', encodeUtf8(normalized));
  return bytesToHex(new Uint8Array(digest));
}

async function derivePassphraseKek(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  if (typeof passphrase !== 'string' || passphrase.length < 6) {
    throw new Error('Vault passphrase must be at least 6 characters.');
  }
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS) {
    throw new Error(`PBKDF2 iterations must be an integer >= ${MIN_PBKDF2_ITERATIONS}.`);
  }

  const subtle = getSubtleCrypto();
  const baseKey = await subtle.importKey(
    'raw',
    encodeUtf8(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

/**
 * Generate a fresh customer RSA-OAEP keypair in browser RAM and immediately encrypt
 * the PKCS#8 Private Key PEM using PBKDF2-SHA256 + AES-256-GCM before returning.
 * The raw private key never leaves the browser unencrypted.
 */
export async function generateCustomerVaultKeypairAndEncryptPrivateKey(
  passphrase: string,
  options?: { iterations?: number; modulusLength?: 2048 | 4096 }
): Promise<CustomerVaultKeySetup> {
  const subtle = getSubtleCrypto();
  const iterations = options?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const modulusLength = options?.modulusLength ?? 2048;

  const keypair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
  );

  const [spkiBuf, pkcs8Buf] = await Promise.all([
    subtle.exportKey('spki', keypair.publicKey),
    subtle.exportKey('pkcs8', keypair.privateKey),
  ]);

  const spkiBytes = new Uint8Array(spkiBuf);
  const pkcs8Bytes = new Uint8Array(pkcs8Buf);
  const publicKeyPem = derBytesToPem(spkiBytes, 'PUBLIC KEY');
  const privateKeyPem = derBytesToPem(pkcs8Bytes, 'PRIVATE KEY');
  const privateKeyUtf8 = encodeUtf8(privateKeyPem);

  const salt = globalThis.crypto.getRandomValues(
    new Uint8Array(new ArrayBuffer(PBKDF2_SALT_BYTES))
  );
  const iv = globalThis.crypto.getRandomValues(
    new Uint8Array(new ArrayBuffer(GCM_IV_BYTES))
  );

  try {
    const [keyFingerprintSha256, kek] = await Promise.all([
      computePublicKeyFingerprintSha256(publicKeyPem),
      derivePassphraseKek(passphrase, salt, iterations, ['encrypt']),
    ]);

    const encryptedBuf = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeUtf8(PRIVATE_KEY_AAD),
      },
      kek,
      privateKeyUtf8
    );

    return {
      publicKeyPem,
      keyFingerprintSha256,
      encryptedPrivateKeyBlob: {
        version: 1,
        kdf: 'PBKDF2-SHA256',
        iterations,
        alg: 'AES-256-GCM',
        salt_b64: bytesToBase64(salt),
        iv_b64: bytesToBase64(iv),
        ciphertext_b64: bytesToBase64(new Uint8Array(encryptedBuf)),
      },
    };
  } finally {
    pkcs8Bytes.fill(0);
    privateKeyUtf8.fill(0);
  }
}

/**
 * Unlock the customer's RSA-OAEP private key strictly in browser RAM as a NON-EXTRACTABLE CryptoKey.
 */
export async function unlockCustomerPrivateKey(
  blob: EncryptedPrivateKeyBlob,
  passphrase: string
): Promise<CryptoKey> {
  if (
    !blob ||
    blob.version !== 1 ||
    blob.kdf !== 'PBKDF2-SHA256' ||
    blob.alg !== 'AES-256-GCM'
  ) {
    throw new Error('Unsupported encrypted private key blob format.');
  }

  const subtle = getSubtleCrypto();
  const salt = base64ToBytes(blob.salt_b64);
  const iv = base64ToBytes(blob.iv_b64);
  const ciphertext = base64ToBytes(blob.ciphertext_b64);

  if (iv.byteLength !== GCM_IV_BYTES) {
    throw new Error('Invalid AES-GCM IV length for encrypted private key.');
  }

  const kek = await derivePassphraseKek(passphrase, salt, blob.iterations, ['decrypt']);

  let plainBuf: ArrayBuffer;
  try {
    plainBuf = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encodeUtf8(PRIVATE_KEY_AAD),
      },
      kek,
      ciphertext
    );
  } catch {
    throw new Error('Vault passphrase decryption failed (wrong passphrase or corrupted key blob).');
  }

  const plainBytes = new Uint8Array(plainBuf);
  const pemText = new TextDecoder().decode(plainBytes);
  const pkcs8Der = pemToDerBytes(pemText);

  try {
    return await subtle.importKey(
      'pkcs8',
      pkcs8Der,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['unwrapKey', 'decrypt']
    );
  } finally {
    plainBytes.fill(0);
    pkcs8Der.fill(0);
  }
}

/**
 * Wrap a raw 32-byte AES-256-GCM vault key ONE-WAY using ONLY the customer's RSA-OAEP(SHA-256) public key PEM.
 * Matches `workbench/search_vault_crypto.py::wrap_vault_data_key_for_customer`.
 */
export async function wrapVaultDataKeyWithPublicPem(
  rawVaultKey: Uint8Array,
  customerPublicKeyPem: string
): Promise<string> {
  if (rawVaultKey.byteLength !== 32) {
    throw new Error('rawVaultKey must be exactly 32 bytes (AES-256).');
  }

  const subtle = getSubtleCrypto();
  const spkiDer = pemToDerBytes(customerPublicKeyPem);
  const rsaPublicKey = await subtle.importKey(
    'spki',
    spkiDer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );

  const wrappedBuf = await subtle.encrypt(
    { name: 'RSA-OAEP' },
    rsaPublicKey,
    toArrayBufferView(rawVaultKey)
  );
  return bytesToBase64(new Uint8Array(wrappedBuf));
}

/**
 * Unwrap the 32-byte AES-256-GCM vault data key in browser RAM as a NON-EXTRACTABLE CryptoKey.
 */
export async function unwrapVaultDataKey(
  wrappedVaultKeyB64: string,
  customerPrivateKey: CryptoKey
): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const wrappedBytes = base64ToBytes(wrappedVaultKeyB64);

  try {
    return await subtle.unwrapKey(
      'raw',
      wrappedBytes,
      customerPrivateKey,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt', 'encrypt']
    );
  } catch {
    throw new Error('Failed to unwrap vault data key with customer private key.');
  }
}

async function resolveAesCryptoKey(
  keyOrBytes: CryptoKey | Uint8Array,
  usage: 'encrypt' | 'decrypt'
): Promise<CryptoKey> {
  if (!(keyOrBytes instanceof Uint8Array)) {
    return keyOrBytes;
  }
  if (keyOrBytes.byteLength !== 32) {
    throw new Error('Raw AES-256-GCM key must be exactly 32 bytes.');
  }
  const subtle = getSubtleCrypto();
  return subtle.importKey(
    'raw',
    toArrayBufferView(keyOrBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

/**
 * Encrypt raw binary bytes into `[12-byte IV][ciphertext + 16-byte GCM auth tag]`.
 */
export async function encryptVaultBlobAesGcm(
  plaintextBytes: Uint8Array,
  vaultKey: CryptoKey | Uint8Array,
  aad?: string
): Promise<Uint8Array<ArrayBuffer>> {
  const subtle = getSubtleCrypto();
  const aesKey = await resolveAesCryptoKey(vaultKey, 'encrypt');
  const iv = globalThis.crypto.getRandomValues(
    new Uint8Array(new ArrayBuffer(GCM_IV_BYTES))
  );

  const algorithm: AesGcmParams = aad
    ? { name: 'AES-GCM', iv, additionalData: encodeUtf8(aad) }
    : { name: 'AES-GCM', iv };

  const ciphertextBuf = await subtle.encrypt(
    algorithm,
    aesKey,
    toArrayBufferView(plaintextBytes)
  );
  const ciphertext = new Uint8Array(ciphertextBuf);
  const combined = new Uint8Array(new ArrayBuffer(GCM_IV_BYTES + ciphertext.byteLength));
  combined.set(iv, 0);
  combined.set(ciphertext, GCM_IV_BYTES);
  return combined;
}

/**
 * Decrypt `[12-byte IV][ciphertext + 16-byte GCM auth tag]` using AES-256-GCM with optional AAD.
 */
export async function decryptVaultBlobAesGcm(
  encryptedBlob: Uint8Array,
  vaultKey: CryptoKey | Uint8Array,
  aad?: string
): Promise<Uint8Array<ArrayBuffer>> {
  if (encryptedBlob.byteLength < GCM_IV_BYTES + GCM_TAG_BYTES) {
    throw new Error('Encrypted blob is shorter than minimum AES-GCM IV + tag length.');
  }
  const subtle = getSubtleCrypto();
  const aesKey = await resolveAesCryptoKey(vaultKey, 'decrypt');
  const iv = toArrayBufferView(encryptedBlob.subarray(0, GCM_IV_BYTES));
  const ciphertext = toArrayBufferView(encryptedBlob.subarray(GCM_IV_BYTES));

  const algorithm: AesGcmParams = aad
    ? { name: 'AES-GCM', iv, additionalData: encodeUtf8(aad) }
    : { name: 'AES-GCM', iv };

  const plainBuf = await subtle.decrypt(algorithm, aesKey, ciphertext);
  return new Uint8Array(plainBuf);
}

async function gzipCompress(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof CompressionStream !== 'function') {
    throw new Error('Browser CompressionStream(gzip) is not supported in this runtime.');
  }
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  const writePromise = writer.write(toArrayBufferView(data)).then(() => writer.close());
  const readPromise = new Response(cs.readable).arrayBuffer();
  const [, compressedBuf] = await Promise.all([writePromise, readPromise]);
  return new Uint8Array(compressedBuf);
}

async function gzipDecompress(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof DecompressionStream !== 'function') {
    throw new Error('Browser DecompressionStream(gzip) is not supported in this runtime.');
  }
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  const writePromise = writer.write(toArrayBufferView(data)).then(() => writer.close());
  const readPromise = new Response(ds.readable).arrayBuffer();
  const [, decompressedBuf] = await Promise.all([writePromise, readPromise]);
  return new Uint8Array(decompressedBuf);
}

/**
 * Serialize JSON -> gzip -> AES-256-GCM encrypt with AAD `${vaultId}:index_bundle`.
 * Used for unit tests and the interactive Live Zero-Knowledge Demo Sandbox.
 */
export async function encryptSearchIndexBundleForTest(
  indexObj: DecryptedSearchIndex,
  vaultKey: CryptoKey | Uint8Array,
  vaultId: string
): Promise<Uint8Array<ArrayBuffer>> {
  const jsonBytes = encodeUtf8(JSON.stringify(indexObj));
  const compressed = await gzipCompress(jsonBytes);
  return encryptVaultBlobAesGcm(compressed, vaultKey, `${vaultId}:index_bundle`);
}

/**
 * Decrypt and gunzip the Search Index Bundle strictly in browser RAM.
 */
export async function decryptSearchIndexBundle(
  encryptedBundle: Uint8Array,
  vaultKey: CryptoKey | Uint8Array,
  vaultId: string
): Promise<DecryptedSearchIndex> {
  const compressed = await decryptVaultBlobAesGcm(
    encryptedBundle,
    vaultKey,
    `${vaultId}:index_bundle`
  );
  const rawJsonBytes = await gzipDecompress(compressed);
  const parsed = JSON.parse(new TextDecoder().decode(rawJsonBytes)) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Decrypted search index bundle must be a JSON object.');
  }
  return parsed as DecryptedSearchIndex;
}

/**
 * Encrypt customer's custom face-cluster names (e.g. `{ person_001: 'คุณแม่' }`)
 * with AES-256-GCM and AAD `${vaultId}:person_labels` so Supabase never sees family names.
 */
export async function encryptPersonLabels(
  labels: Record<string, string>,
  vaultKey: CryptoKey | Uint8Array,
  vaultId: string
): Promise<EncryptedPersonLabelsBlob> {
  const subtle = getSubtleCrypto();
  const aesKey = await resolveAesCryptoKey(vaultKey, 'encrypt');
  const iv = globalThis.crypto.getRandomValues(
    new Uint8Array(new ArrayBuffer(GCM_IV_BYTES))
  );
  const plaintext = encodeUtf8(JSON.stringify(labels));
  const ciphertextBuf = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: encodeUtf8(`${vaultId}:person_labels`),
    },
    aesKey,
    plaintext
  );
  return {
    version: 1,
    alg: 'AES-256-GCM',
    iv_b64: bytesToBase64(iv),
    ciphertext_b64: bytesToBase64(new Uint8Array(ciphertextBuf)),
  };
}

/**
 * Decrypt customer's custom face-cluster names strictly in browser RAM.
 */
export async function decryptPersonLabels(
  blob: EncryptedPersonLabelsBlob,
  vaultKey: CryptoKey | Uint8Array,
  vaultId: string
): Promise<Record<string, string>> {
  if (!blob || blob.version !== 1 || blob.alg !== 'AES-256-GCM') {
    throw new Error('Unsupported encrypted person labels blob.');
  }
  const subtle = getSubtleCrypto();
  const aesKey = await resolveAesCryptoKey(vaultKey, 'decrypt');
  const iv = base64ToBytes(blob.iv_b64);
  const ciphertext = base64ToBytes(blob.ciphertext_b64);
  if (iv.byteLength !== GCM_IV_BYTES) {
    throw new Error('Invalid AES-GCM IV length for person labels.');
  }

  const plainBuf = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: encodeUtf8(`${vaultId}:person_labels`),
    },
    aesKey,
    ciphertext
  );

  const parsed = JSON.parse(new TextDecoder().decode(plainBuf)) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {};
  }
  const result: Record<string, string> = {};
  for (const [key, val] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof key === 'string' && typeof val === 'string') {
      const trimmed = val.trim();
      if (trimmed) {
        result[key] = trimmed;
      }
    }
  }
  return result;
}
