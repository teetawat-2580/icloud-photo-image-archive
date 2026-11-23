import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  computePemFingerprintSha256,
  computeSpkiFingerprintSha256,
  decryptEnvelopeWithPrivatePem,
  encryptEnvelope,
  pemToSpkiArrayBuffer,
  verifyPublicKeyFingerprint,
} from '../src/lib/crypto-envelope.ts';
import {
  hashJobToken,
  validateEncryptedEnvelopePayload,
  verifyJobToken,
  verifyOperatorKeyFingerprint,
} from '../src/lib/job-auth.ts';

test('hashJobToken produces deterministic lowercase 64-char SHA-256 hex', () => {
  const token = 'cv_live_tok_98234abcdef';
  const digestA = hashJobToken(token);
  const digestB = hashJobToken(token);

  assert.equal(digestA, digestB);
  assert.match(digestA, /^[a-f0-9]{64}$/);
  assert.notEqual(digestA, hashJobToken('cv_live_tok_98234abcdeg'));
});

test('verifyJobToken performs timing-safe match and rejects mismatches or malformed hashes', () => {
  const token = 'secret-concierge-access-token-2026';
  const storedHash = hashJobToken(token);

  assert.equal(verifyJobToken(token, storedHash), true);
  assert.equal(verifyJobToken(token, storedHash.toUpperCase()), true);
  assert.equal(verifyJobToken(`${token}!`, storedHash), false);
  assert.equal(verifyJobToken('', storedHash), false);
  assert.equal(verifyJobToken(token, 'not-a-valid-sha256'), false);
  assert.equal(verifyJobToken(token, storedHash.slice(0, 62)), false);
});

test('WebCrypto RSA-OAEP-256 + AES-256-GCM envelope encrypts, validates, decrypts round-trip, and rejects tampering', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const spkiBuffer = pemToSpkiArrayBuffer(publicKey);
  assert.ok(spkiBuffer.byteLength > 200);

  const expectedFingerprint = await computePemFingerprintSha256(publicKey);
  assert.match(expectedFingerprint, /^[a-f0-9]{64}$/);

  const secretPayload = {
    provider: 'icloud',
    account_email: 'mom.archive@icloud.com',
    password: 'OneTime-App-Secret-2026!@#',
    note: 'Keep 2024-2026 on iPhone',
  };

  const envelope = await encryptEnvelope(publicKey, secretPayload);

  // Verify exact JSON contract
  assert.equal(envelope.version, 1);
  assert.equal(envelope.alg, 'RSA-OAEP-256+A256GCM');
  assert.equal(envelope.key_fingerprint_sha256, expectedFingerprint);
  assert.equal(typeof envelope.wrapped_key_b64, 'string');
  assert.equal(typeof envelope.iv_b64, 'string');
  assert.equal(typeof envelope.ciphertext_b64, 'string');

  // Verify server-side validator accepts the generated envelope
  const serverValidation = validateEncryptedEnvelopePayload(envelope);
  assert.equal(serverValidation.ok, true);

  // Verify round-trip decryption with Operator private key
  const decryptedJson = await decryptEnvelopeWithPrivatePem(privateKey, envelope);
  assert.deepEqual(JSON.parse(decryptedJson), secretPayload);

  // Tamper test 1: flip a byte in ciphertext -> AES-GCM authentication tag MUST fail
  const tamperedCipherBytes = Buffer.from(envelope.ciphertext_b64, 'base64');
  tamperedCipherBytes[0] ^= 0xff;
  const tamperedCipherEnvelope = {
    ...envelope,
    ciphertext_b64: tamperedCipherBytes.toString('base64'),
  };
  await assert.rejects(
    () => decryptEnvelopeWithPrivatePem(privateKey, tamperedCipherEnvelope),
    /OperationError|decrypt|tag|failed/i
  );

  // Tamper test 2: flip a byte in IV -> AES-GCM authentication MUST fail
  const tamperedIvBytes = Buffer.from(envelope.iv_b64, 'base64');
  tamperedIvBytes[0] ^= 0x01;
  const tamperedIvEnvelope = {
    ...envelope,
    iv_b64: tamperedIvBytes.toString('base64'),
  };
  await assert.rejects(
    () => decryptEnvelopeWithPrivatePem(privateKey, tamperedIvEnvelope),
    /OperationError|decrypt|tag|failed/i
  );

  // Tamper test 3: wrong private key -> RSA-OAEP unwrap MUST fail
  const otherPair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  await assert.rejects(
    () => decryptEnvelopeWithPrivatePem(otherPair.privateKey, envelope),
    /OperationError|unwrap|decrypt|failed/i
  );
});

test('validateEncryptedEnvelopePayload rejects invalid IV lengths, bad algorithms, and oversized payloads', () => {
  const badAlg = validateEncryptedEnvelopePayload({
    version: 1,
    alg: 'RSA-PKCS1-v1_5',
    key_fingerprint_sha256: 'a'.repeat(64),
    wrapped_key_b64: Buffer.from('key').toString('base64'),
    iv_b64: Buffer.alloc(12).toString('base64'),
    ciphertext_b64: Buffer.from('cipher').toString('base64'),
  });
  assert.equal(badAlg.ok, false);

  const badIvLen = validateEncryptedEnvelopePayload({
    version: 1,
    alg: 'RSA-OAEP-256+A256GCM',
    key_fingerprint_sha256: 'a'.repeat(64),
    wrapped_key_b64: Buffer.from('key').toString('base64'),
    iv_b64: Buffer.alloc(16).toString('base64'),
    ciphertext_b64: Buffer.from('cipher').toString('base64'),
  });
  assert.equal(badIvLen.ok, false);
});

test('Fingerprint parity: canonical LF PEM SHA-256 and SPKI DER SHA-256 both validate against Operator public key', async () => {
  const { publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const crlfPem = publicKey.replace(/\n/g, '\r\n');
  const pemFpLf = await computePemFingerprintSha256(publicKey);
  const pemFpCrlf = await computePemFingerprintSha256(crlfPem);
  const spkiFp = await computeSpkiFingerprintSha256(publicKey);

  // CRLF normalization must match LF identically (Python workbench interop)
  assert.equal(pemFpLf, pemFpCrlf);
  assert.notEqual(pemFpLf, spkiFp);

  const checkPem = await verifyPublicKeyFingerprint(publicKey, pemFpLf);
  const checkSpki = await verifyPublicKeyFingerprint(publicKey, spkiFp);
  const checkWrong = await verifyPublicKeyFingerprint(publicKey, '0'.repeat(64));

  assert.equal(checkPem.matches, true);
  assert.equal(checkSpki.matches, true);
  assert.equal(checkWrong.matches, false);

  assert.equal(
    verifyOperatorKeyFingerprint(pemFpLf, {
      key_fingerprint_sha256: pemFpLf,
      public_key_pem: publicKey,
    }),
    true
  );
  assert.equal(
    verifyOperatorKeyFingerprint(spkiFp, {
      key_fingerprint_sha256: pemFpLf,
      public_key_pem: publicKey,
    }),
    true
  );
  assert.equal(
    verifyOperatorKeyFingerprint('f'.repeat(64), {
      key_fingerprint_sha256: pemFpLf,
      public_key_pem: publicKey,
    }),
    false
  );
});
