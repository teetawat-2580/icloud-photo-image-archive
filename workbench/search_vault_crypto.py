"""
CloudVault Concierge — Zero-Knowledge Search Vault Cryptographic Primitives.

Cross-language binary parity with `web/src/lib/search-vault-crypto.ts` (Browser WebCrypto):
- One-Way Key Wrapping: Random 32-byte `vault_data_key` wrapped to Customer's RSA-OAEP(SHA-256) public key.
  The Operator PC NEVER holds the customer's private key or Vault Passphrase.
- Blob Encryption (`AES-256-GCM`): Wire format is `[12-byte random IV][ciphertext || 16-byte GCM tag]`,
  authenticated with deterministic UTF-8 AAD (`f"{vault_id}:{object_key}"`).
- Search Index Bundle: UTF-8 JSON -> gzip compressed -> AES-256-GCM encrypted with AAD `f"{vault_id}:index_bundle"`.
- Passphrase-Protected Private Key Blob (client-side KDF reference & interop test helper):
  PBKDF2-HMAC-SHA256 (default 600,000 iterations per OWASP 2025/2026) -> 256-bit AES-GCM KEK.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from workbench.crypto_vault import _zero_bytearray, compute_public_key_fingerprint

AES_KEY_BYTES = 32
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16
PBKDF2_SALT_BYTES = 16
PBKDF2_ITERATIONS_DEFAULT = 600_000


def generate_vault_data_key() -> bytearray:
    """Allocate a fresh ephemeral 32-byte AES-256-GCM data key in a mutable bytearray for explicit zeroing."""
    return bytearray(secrets.token_bytes(AES_KEY_BYTES))


def zero_key_buffer(buf: bytearray | None) -> None:
    """Securely zero an in-memory mutable key buffer."""
    _zero_bytearray(buf)


def generate_customer_rsa_keypair(key_size: int = 2048) -> dict[str, str]:
    """Generate a customer RSA-OAEP keypair (helper for CLI tools & cross-language unit tests)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8").replace("\r\n", "\n")
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8").replace("\r\n", "\n")
    return {
        "public_key_pem": pub_pem,
        "private_key_pkcs8_pem": priv_pem,
        "key_fingerprint_sha256": compute_public_key_fingerprint(pub_pem),
    }


def _derive_kek_pbkdf2(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 6:
        raise ValueError("Vault passphrase must be at least 6 characters")
    if iterations < 10_000:
        raise ValueError("PBKDF2 iteration count must be at least 10,000")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_private_key_with_passphrase(
    private_key_pkcs8_pem: str,
    passphrase: str,
    *,
    iterations: int = PBKDF2_ITERATIONS_DEFAULT,
) -> dict[str, Any]:
    """
    Encrypt a customer PKCS#8 private key PEM with a passphrase-derived AES-256-GCM KEK.
    Matches Browser WebCrypto PBKDF2-SHA256 + AES-256-GCM 1:1.
    """
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    iv = secrets.token_bytes(GCM_IV_BYTES)
    kek_buf = bytearray(_derive_kek_pbkdf2(passphrase, salt, iterations))
    plain_buf = bytearray(private_key_pkcs8_pem.replace("\r\n", "\n").encode("utf-8"))
    try:
        ct = AESGCM(bytes(kek_buf)).encrypt(iv, bytes(plain_buf), b"cloudvault:customer_private_key:v1")
    finally:
        _zero_bytearray(kek_buf)
        _zero_bytearray(plain_buf)

    return {
        "version": 1,
        "kdf": "PBKDF2-SHA256",
        "iterations": iterations,
        "alg": "AES-256-GCM",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
    }


def decrypt_private_key_with_passphrase(blob: dict[str, Any], passphrase: str) -> str:
    """Decrypt a passphrase-protected customer PKCS#8 private key PEM blob."""
    if not isinstance(blob, dict) or blob.get("version") != 1:
        raise ValueError("Unsupported encrypted private key blob version")
    if blob.get("kdf") != "PBKDF2-SHA256" or blob.get("alg") != "AES-256-GCM":
        raise ValueError("Unsupported KDF or cipher algorithm")

    iterations = int(blob["iterations"])
    salt = base64.b64decode(blob["salt_b64"], validate=True)
    iv = base64.b64decode(blob["iv_b64"], validate=True)
    ct = base64.b64decode(blob["ciphertext_b64"], validate=True)
    if len(iv) != GCM_IV_BYTES:
        raise ValueError("Invalid IV length (expected 12 bytes)")

    kek_buf = bytearray(_derive_kek_pbkdf2(passphrase, salt, iterations))
    try:
        plain = AESGCM(bytes(kek_buf)).decrypt(iv, ct, b"cloudvault:customer_private_key:v1")
        return plain.decode("utf-8")
    finally:
        _zero_bytearray(kek_buf)


def wrap_vault_data_key_for_customer(vault_data_key: bytes | bytearray, customer_public_key_pem: str | bytes) -> str:
    """
    Wrap the 32-byte AES vault data key ONE-WAY using ONLY the customer's RSA-OAEP(SHA-256) public key.
    Once wrapped and the ephemeral `vault_data_key` is zeroed, the Operator PC cannot recover it.
    """
    raw_key = bytes(vault_data_key)
    if len(raw_key) != AES_KEY_BYTES:
        raise ValueError(f"vault_data_key must be exactly {AES_KEY_BYTES} bytes")

    pem_str = (
        customer_public_key_pem.decode("utf-8")
        if isinstance(customer_public_key_pem, bytes)
        else str(customer_public_key_pem)
    ).replace("\r\n", "\n")
    pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Customer public key must be an RSA public key")

    wrapped = pub_key.encrypt(
        raw_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode("ascii")


def unwrap_vault_data_key(wrapped_vault_key_b64: str, customer_private_key_pkcs8_pem: str | bytes) -> bytes:
    """Unwrap the 32-byte AES vault data key using the customer's PKCS#8 private key PEM."""
    pem_bytes = (
        customer_private_key_pkcs8_pem
        if isinstance(customer_private_key_pkcs8_pem, bytes)
        else str(customer_private_key_pkcs8_pem).replace("\r\n", "\n").encode("utf-8")
    )
    priv_key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(priv_key, rsa.RSAPrivateKey):
        raise ValueError("Customer private key must be an RSA private key")

    wrapped_bytes = base64.b64decode(wrapped_vault_key_b64.strip(), validate=True)
    try:
        raw_key = priv_key.decrypt(
            wrapped_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise ValueError(f"Failed to unwrap vault data key: {exc}") from exc

    if len(raw_key) != AES_KEY_BYTES:
        raise ValueError(f"Unexpected unwrapped key size: {len(raw_key)} bytes")
    return raw_key


def encrypt_vault_blob_aes_gcm(
    plaintext_bytes: bytes,
    vault_data_key: bytes | bytearray,
    *,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt arbitrary binary payload (e.g. WebP thumbnail or gzipped index) -> `[12-byte IV][ciphertext+tag]`."""
    raw_key = bytes(vault_data_key)
    if len(raw_key) != AES_KEY_BYTES:
        raise ValueError(f"vault_data_key must be exactly {AES_KEY_BYTES} bytes")
    iv = secrets.token_bytes(GCM_IV_BYTES)
    ct = AESGCM(raw_key).encrypt(iv, plaintext_bytes, aad)
    return iv + ct


def decrypt_vault_blob_aes_gcm(
    encrypted_blob: bytes,
    vault_data_key: bytes | bytearray,
    *,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt `[12-byte IV][ciphertext+tag]` encrypted with `encrypt_vault_blob_aes_gcm`."""
    raw_key = bytes(vault_data_key)
    if len(raw_key) != AES_KEY_BYTES:
        raise ValueError(f"vault_data_key must be exactly {AES_KEY_BYTES} bytes")
    if len(encrypted_blob) < GCM_IV_BYTES + GCM_TAG_BYTES:
        raise ValueError("Encrypted blob is too short")
    iv = encrypted_blob[:GCM_IV_BYTES]
    ct = encrypted_blob[GCM_IV_BYTES:]
    return AESGCM(raw_key).decrypt(iv, ct, aad)


def encrypt_search_index_bundle(
    index_dict: dict[str, Any],
    vault_data_key: bytes | bytearray,
    vault_id: str,
) -> tuple[bytes, str]:
    """
    Serialize JSON index -> gzip compress -> AES-256-GCM encrypt with AAD `f"{vault_id}:index_bundle"`.
    Returns `(encrypted_bytes, sha256_of_encrypted_bytes)`.
    """
    json_bytes = json.dumps(index_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(json_bytes, compresslevel=6)
    aad = f"{vault_id}:index_bundle".encode("utf-8")
    encrypted = encrypt_vault_blob_aes_gcm(compressed, vault_data_key, aad=aad)
    return encrypted, hashlib.sha256(encrypted).hexdigest()


def decrypt_search_index_bundle(
    encrypted_bytes: bytes,
    vault_data_key: bytes | bytearray,
    vault_id: str,
) -> dict[str, Any]:
    """Decrypt and decompress a Search Index Bundle produced by `encrypt_search_index_bundle`."""
    aad = f"{vault_id}:index_bundle".encode("utf-8")
    compressed = decrypt_vault_blob_aes_gcm(encrypted_bytes, vault_data_key, aad=aad)
    raw_json = gzip.decompress(compressed)
    parsed = json.loads(raw_json.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decrypted search index bundle must be a JSON object")
    return parsed
