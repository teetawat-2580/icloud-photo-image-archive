import type { EncryptedEnvelope } from './types';

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

export function normalizePemNewlines(pem: string): string {
  return pem.replace(/\r\n/g, '\n');
}

export function pemToSpkiArrayBuffer(pem: string): ArrayBuffer {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new Error('PEM public key must be a non-empty string.');
  }
  const body = pem
    .replace(PEM_HEADER_REGEX, '')
    .replace(PEM_FOOTER_REGEX, '')
    .replace(WHITESPACE_REGEX, '');

  if (!body) {
    throw new Error('PEM public key contains no base64 payload.');
  }

  const bytes = base64ToBytes(body);
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Computes canonical SHA-256 hex digest of UTF-8 PEM (LF normalized),
 * matching `workbench/crypto_vault.py::compute_public_key_fingerprint` 1:1.
 */
export async function computePemFingerprintSha256(pem: string): Promise<string> {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new Error('PEM public key must be a non-empty string.');
  }
  const subtle = getSubtleCrypto();
  const normalizedBytes = new TextEncoder().encode(normalizePemNewlines(pem));
  const digest = await subtle.digest('SHA-256', normalizedBytes);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Computes SHA-256 hex digest of the binary SubjectPublicKeyInfo (SPKI DER) bytes.
 */
export async function computeSpkiFingerprintSha256(pem: string): Promise<string> {
  const subtle = getSubtleCrypto();
  const spkiBuffer = pemToSpkiArrayBuffer(pem);
  const digest = await subtle.digest('SHA-256', spkiBuffer);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Verifies a declared operator key fingerprint against either canonical LF-UTF8 PEM SHA-256
 * or SPKI DER SHA-256 (matching `OperatorCryptoVault._matches_local_fingerprint`).
 */
export async function verifyPublicKeyFingerprint(
  publicKeyPem: string,
  declaredFingerprint: string
): Promise<{
  matches: boolean;
  pemFingerprint: string;
  spkiFingerprint: string;
}> {
  const [pemFingerprint, spkiFingerprint] = await Promise.all([
    computePemFingerprintSha256(publicKeyPem),
    computeSpkiFingerprintSha256(publicKeyPem),
  ]);
  const cleanDeclared = declaredFingerprint.trim().toLowerCase();
  const matches =
    cleanDeclared.length === 0 ||
    cleanDeclared === pemFingerprint ||
    cleanDeclared === spkiFingerprint;

  return { matches, pemFingerprint, spkiFingerprint };
}

export async function encryptEnvelope(
  publicKeyPem: string,
  payload: unknown
): Promise<EncryptedEnvelope> {
  const subtle = getSubtleCrypto();
  const spkiBuffer = pemToSpkiArrayBuffer(publicKeyPem);

  const [pemFingerprint, rsaPublicKey, aesKey] = await Promise.all([
    computePemFingerprintSha256(publicKeyPem),
    subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['wrapKey']
    ),
    subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']),
  ]);

  const iv = globalThis.crypto.getRandomValues(new Uint8Array(new ArrayBuffer(12)));
  const serialized =
    typeof payload === 'string' ? payload : JSON.stringify(payload);
  const plaintextBytes = new TextEncoder().encode(serialized);

  const [wrappedKeyBuffer, ciphertextBuffer] = await Promise.all([
    subtle.wrapKey('raw', aesKey, rsaPublicKey, { name: 'RSA-OAEP' }),
    subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintextBytes),
  ]);

  return {
    version: 1,
    alg: 'RSA-OAEP-256+A256GCM',
    key_fingerprint_sha256: pemFingerprint,
    wrapped_key_b64: bytesToBase64(new Uint8Array(wrappedKeyBuffer)),
    iv_b64: bytesToBase64(iv),
    ciphertext_b64: bytesToBase64(new Uint8Array(ciphertextBuffer)),
  };
}

export async function decryptEnvelopeWithPrivatePem(
  privateKeyPkcs8Pem: string,
  envelope: EncryptedEnvelope
): Promise<string> {
  if (envelope.version !== 1 || envelope.alg !== 'RSA-OAEP-256+A256GCM') {
    throw new Error('Unsupported encrypted envelope version or algorithm.');
  }

  const subtle = getSubtleCrypto();
  const pkcs8Buffer = pemToSpkiArrayBuffer(privateKeyPkcs8Pem);

  const rsaPrivateKey = await subtle.importKey(
    'pkcs8',
    pkcs8Buffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['unwrapKey']
  );

  const wrappedKeyBytes = base64ToBytes(envelope.wrapped_key_b64);
  const ivBytes = base64ToBytes(envelope.iv_b64);
  const ciphertextBytes = base64ToBytes(envelope.ciphertext_b64);

  if (ivBytes.byteLength !== 12) {
    throw new Error('Invalid AES-GCM IV length (expected 12 bytes).');
  }

  const aesKey = await subtle.unwrapKey(
    'raw',
    wrappedKeyBytes,
    rsaPrivateKey,
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plaintextBuffer = await subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    aesKey,
    ciphertextBytes
  );

  return new TextDecoder().decode(plaintextBuffer);
}

export function formatShortFingerprint(hex: string | null | undefined): string {
  if (!hex) return 'UNVERIFIED';
  const clean = hex.trim().toLowerCase();
  if (clean.length < 16) return clean;
  return `${clean.slice(0, 8)}:${clean.slice(8, 16)}…${clean.slice(-8)}`;
}
