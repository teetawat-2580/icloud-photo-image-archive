"""
CloudVault Concierge — Local Operator Cryptographic Vault (RSA-4096 + AES-256-GCM).

Security invariants:
- RSA-4096 private key NEVER leaves the local operator PC (`workbench/.keys/operator_private.pem`).
- Public key PEM uses deterministic LF newlines so SHA-256 fingerprints match WebCrypto / Node.js 1:1.
- Hybrid envelopes (RSA-OAEP(SHA-256) wrapped 32-byte AES key + AES-256-GCM ciphertext with
  16-byte trailing authentication tag) are decrypted strictly in RAM and mutable buffers are
  explicitly zeroed in a `finally` block.
- PDPA Purge Certificates are signed with RSA-PSS-SHA256 (salt_length=32, WebCrypto-compatible).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_KEYS_DIR = Path(__file__).resolve().parent / ".keys"
PRIVATE_KEY_FILENAME = "operator_private.pem"
PUBLIC_KEY_FILENAME = "operator_public.pem"
RSA_KEY_SIZE_BITS = 4096
AES_KEY_BYTES = 32
GCM_IV_BYTES = 12
PSS_SALT_LENGTH = 32


def _zero_bytearray(buf: bytearray | None) -> None:
    """Overwrite every byte of a mutable bytearray with zeros in place."""
    if buf is None:
        return
    for idx in range(len(buf)):
        buf[idx] = 0
    buf.clear()


def compute_public_key_fingerprint(public_key_pem: str | bytes) -> str:
    """Compute SHA-256 hex digest of UTF-8 public PEM (normalized LF line endings)."""
    if isinstance(public_key_pem, bytes):
        text = public_key_pem.decode("utf-8")
    else:
        text = str(public_key_pem)
    normalized = text.replace("\r\n", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON bytes for signing and digesting."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64decode_strict(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid base64 field: {field_name}")
    try:
        return base64.b64decode(value.strip(), validate=True)
    except Exception as exc:
        raise ValueError(f"Malformed base64 in field '{field_name}': {exc}") from exc


def encrypt_envelope_with_public_pem(
    payload: dict[str, Any],
    public_key_pem: str | bytes,
    aad: bytes | None = None,
) -> dict[str, Any]:
    """
    Encrypt a JSON-serializable dict into a WebCrypto-compatible hybrid envelope:
    - 32-byte random AES-256-GCM key wrapped via RSA-OAEP(SHA-256)
    - 12-byte random IV
    - AES-256-GCM ciphertext with 16-byte trailing authentication tag
    """
    pem_str = (
        public_key_pem.decode("utf-8")
        if isinstance(public_key_pem, bytes)
        else str(public_key_pem)
    ).replace("\r\n", "\n")
    pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Public key must be an RSA public key")

    fingerprint = compute_public_key_fingerprint(pem_str)
    aes_key_buf = bytearray(secrets.token_bytes(AES_KEY_BYTES))
    iv_bytes = secrets.token_bytes(GCM_IV_BYTES)
    plaintext_buf = bytearray(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    try:
        aesgcm = AESGCM(bytes(aes_key_buf))
        ciphertext_with_tag = aesgcm.encrypt(iv_bytes, bytes(plaintext_buf), aad)
        wrapped_key = pub_key.encrypt(
            bytes(aes_key_buf),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    finally:
        _zero_bytearray(aes_key_buf)
        _zero_bytearray(plaintext_buf)

    envelope: dict[str, Any] = {
        "version": 1,
        "alg": "RSA-OAEP-256+A256GCM",
        "key_fingerprint_sha256": fingerprint,
        "wrapped_key_b64": base64.b64encode(wrapped_key).decode("ascii"),
        "iv_b64": base64.b64encode(iv_bytes).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext_with_tag).decode("ascii"),
    }
    if aad is not None:
        envelope["aad_b64"] = base64.b64encode(aad).decode("ascii")
    return envelope


class OperatorCryptoVault:
    """Manages local RSA-4096 operator keys, RAM-only envelope decryption, and PDPA signing."""

    def __init__(self, keys_dir: Path | str | None = None, key_size: int = RSA_KEY_SIZE_BITS):
        env_dir = os.environ.get("OPERATOR_KEYS_DIR")
        resolved_dir = Path(keys_dir) if keys_dir is not None else (Path(env_dir) if env_dir else DEFAULT_KEYS_DIR)
        self.keys_dir = resolved_dir.resolve()
        self.private_key_path = self.keys_dir / PRIVATE_KEY_FILENAME
        self.public_key_path = self.keys_dir / PUBLIC_KEY_FILENAME
        self._key_size = key_size
        self._private_key: rsa.RSAPrivateKey
        self._public_key: rsa.RSAPublicKey
        self._public_key_pem: str
        self._key_fingerprint_sha256: str
        self._spki_fingerprint_sha256: str
        self._load_or_generate_keypair()

    def _compute_spki_fingerprint(self) -> str:
        der_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der_bytes).hexdigest()

    def _load_or_generate_keypair(self) -> None:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        if self.private_key_path.exists():
            raw_priv = self.private_key_path.read_bytes()
            loaded = serialization.load_pem_private_key(raw_priv, password=None)
            if not isinstance(loaded, rsa.RSAPrivateKey):
                raise ValueError("Loaded operator private key is not an RSA key")
            self._private_key = loaded
            self._public_key = self._private_key.public_key()
            pub_pem_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            pub_pem_str = pub_pem_bytes.decode("utf-8").replace("\r\n", "\n")
            if not self.public_key_path.exists():
                self._write_text_lf(self.public_key_path, pub_pem_str)
            else:
                # Ensure public PEM on disk stays strictly synchronized with the private key
                disk_pem = self.public_key_path.read_text(encoding="utf-8").replace("\r\n", "\n")
                if disk_pem != pub_pem_str:
                    self._write_text_lf(self.public_key_path, pub_pem_str)
            self._public_key_pem = pub_pem_str
            self._key_fingerprint_sha256 = compute_public_key_fingerprint(pub_pem_str)
            self._spki_fingerprint_sha256 = self._compute_spki_fingerprint()
            return

        # Generate a fresh RSA-4096 keypair locally
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self._key_size,
        )
        self._public_key = self._private_key.public_key()

        priv_pem_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_pem_str = priv_pem_bytes.decode("utf-8").replace("\r\n", "\n")
        pub_pem_str = pub_pem_bytes.decode("utf-8").replace("\r\n", "\n")

        self._write_text_lf(self.private_key_path, priv_pem_str, restrict_mode=True)
        self._write_text_lf(self.public_key_path, pub_pem_str, restrict_mode=False)
        self._public_key_pem = pub_pem_str
        self._key_fingerprint_sha256 = compute_public_key_fingerprint(pub_pem_str)
        self._spki_fingerprint_sha256 = self._compute_spki_fingerprint()

    @staticmethod
    def _write_text_lf(path: Path, text: str, restrict_mode: bool = False) -> None:
        tmp_path = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp_path, path)
        if restrict_mode:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    @property
    def public_key_pem(self) -> str:
        return self._public_key_pem

    @property
    def key_fingerprint_sha256(self) -> str:
        return self._key_fingerprint_sha256

    @property
    def spki_fingerprint_sha256(self) -> str:
        return self._spki_fingerprint_sha256

    def export_public_identity(self) -> dict[str, str]:
        return {
            "public_key_pem": self._public_key_pem,
            "key_fingerprint_sha256": self._key_fingerprint_sha256,
            "spki_fingerprint_sha256": self._spki_fingerprint_sha256,
            "key_algorithm": f"RSA-{self._private_key.key_size}",
        }

    def encrypt_envelope(self, payload: dict[str, Any], aad: bytes | None = None) -> dict[str, Any]:
        """Encrypt payload to this vault's own public key (helpful for local workflows & tests)."""
        return encrypt_envelope_with_public_pem(payload, self._public_key_pem, aad=aad)

    def _matches_local_fingerprint(self, candidate: str) -> bool:
        """Accept either canonical UTF-8 PEM SHA-256 or WebCrypto SPKI DER SHA-256 of THIS key."""
        cand = candidate.strip().lower()
        return hmac.compare_digest(cand, self._key_fingerprint_sha256.lower()) or hmac.compare_digest(
            cand, self._spki_fingerprint_sha256.lower()
        )

    def decrypt_envelope(self, envelope_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Decrypt a WebCrypto RSA-OAEP(SHA-256) + AES-256-GCM hybrid envelope strictly in RAM.

        Raises:
            ValueError: on missing fields, key fingerprint mismatch, wrong AES key size, or bad JSON.
            InvalidTag: on AES-GCM ciphertext or authentication tag tampering.
        """
        if not isinstance(envelope_dict, dict):
            raise ValueError("Envelope must be a JSON object")

        fingerprint = envelope_dict.get("key_fingerprint_sha256") or envelope_dict.get("public_key_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            raise ValueError("Envelope is missing required 'key_fingerprint_sha256'")
        if not self._matches_local_fingerprint(fingerprint):
            raise ValueError(
                f"Key fingerprint mismatch: envelope={fingerprint[:16]}... local={self._key_fingerprint_sha256[:16]}..."
            )

        wrapped_key_field = (
            envelope_dict.get("wrapped_key_b64")
            or envelope_dict.get("encrypted_aes_key_b64")
            or envelope_dict.get("encrypted_key_b64")
        )
        wrapped_key = _b64decode_strict(wrapped_key_field, "wrapped_key_b64")
        iv_bytes = _b64decode_strict(envelope_dict.get("iv_b64", ""), "iv_b64")
        ciphertext_bytes = _b64decode_strict(envelope_dict.get("ciphertext_b64", ""), "ciphertext_b64")
        aad_bytes: bytes | None = None
        if envelope_dict.get("aad_b64"):
            aad_bytes = _b64decode_strict(envelope_dict["aad_b64"], "aad_b64")

        if len(iv_bytes) < 12:
            raise ValueError(f"Invalid AES-GCM IV length: {len(iv_bytes)} bytes (expected >= 12)")
        if len(ciphertext_bytes) < 16:
            raise ValueError("Ciphertext too short to include 16-byte AES-GCM auth tag")

        aes_key_buf: bytearray | None = None
        plaintext_buf: bytearray | None = None

        try:
            raw_aes_key = self._private_key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            aes_key_buf = bytearray(raw_aes_key)
            if len(aes_key_buf) != AES_KEY_BYTES:
                raise ValueError(f"Unexpected unwrapped AES key length: {len(aes_key_buf)} bytes (expected 32)")

            aesgcm = AESGCM(bytes(aes_key_buf))
            raw_plaintext = aesgcm.decrypt(iv_bytes, ciphertext_bytes, aad_bytes)
            plaintext_buf = bytearray(raw_plaintext)

            decoded = json.loads(plaintext_buf.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("Decrypted envelope payload must be a JSON object")
            return decoded
        except InvalidTag:
            raise
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Envelope decryption failed: {exc}") from exc
        finally:
            _zero_bytearray(aes_key_buf)
            _zero_bytearray(plaintext_buf)

    def sign_pdpa_certificate(self, payload_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Sign a PDPA Purge Certificate payload with RSA-PSS-SHA256 (salt_length=32)
        and attach a canonical SHA-256 digest for customer verification.
        """
        if not isinstance(payload_dict, dict):
            raise ValueError("PDPA certificate payload must be a dict")

        unsigned_payload = {
            k: v
            for k, v in payload_dict.items()
            if k not in ("signature_b64", "payload_sha256", "signature_algorithm", "key_fingerprint_sha256")
        }
        canonical_bytes = _canonical_json_bytes(unsigned_payload)
        payload_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        signature = self._private_key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )

        signed_cert = dict(unsigned_payload)
        signed_cert["payload_sha256"] = payload_sha256
        signed_cert["signature_algorithm"] = "RSA-PSS-SHA256"
        signed_cert["signature_b64"] = base64.b64encode(signature).decode("ascii")
        signed_cert["key_fingerprint_sha256"] = self._key_fingerprint_sha256
        return signed_cert

    def verify_pdpa_certificate(
        self,
        cert_dict: dict[str, Any],
        public_key_pem: str | bytes | None = None,
    ) -> bool:
        """Verify canonical SHA-256 digest and RSA-PSS-SHA256 signature of a PDPA certificate."""
        if not isinstance(cert_dict, dict):
            return False
        sig_b64 = cert_dict.get("signature_b64")
        claimed_digest = cert_dict.get("payload_sha256")
        claimed_fp = cert_dict.get("key_fingerprint_sha256")
        if not sig_b64 or not claimed_digest or not claimed_fp:
            return False

        if public_key_pem is not None:
            pem_str = (
                public_key_pem.decode("utf-8")
                if isinstance(public_key_pem, bytes)
                else str(public_key_pem)
            ).replace("\r\n", "\n")
            pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
            expected_fp = compute_public_key_fingerprint(pem_str)
        else:
            pub_key = self._public_key
            expected_fp = self._key_fingerprint_sha256

        if not isinstance(pub_key, rsa.RSAPublicKey):
            return False
        if not hmac.compare_digest(str(claimed_fp).lower(), expected_fp.lower()):
            return False

        unsigned_payload = {
            k: v
            for k, v in cert_dict.items()
            if k not in ("signature_b64", "payload_sha256", "signature_algorithm", "key_fingerprint_sha256")
        }
        canonical_bytes = _canonical_json_bytes(unsigned_payload)
        actual_digest = hashlib.sha256(canonical_bytes).hexdigest()
        if not hmac.compare_digest(str(claimed_digest).lower(), actual_digest.lower()):
            return False

        try:
            signature = _b64decode_strict(str(sig_b64), "signature_b64")
            pub_key.verify(
                signature,
                canonical_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=PSS_SALT_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError):
            return False


def _cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CloudVault Concierge — Operator Crypto Vault CLI (WebCrypto interop helper)"
    )
    parser.add_argument("--keys-dir", type=str, default=None, help="Directory for operator RSA-4096 keys")
    parser.add_argument("--export-public-key", action="store_true", help="Print JSON with public_key_pem & fingerprint")
    parser.add_argument("--raw-pem", action="store_true", help="With --export-public-key, emit raw PEM only")
    parser.add_argument("--decrypt-stdin", action="store_true", help="Decrypt hybrid JSON envelope read from stdin")
    parser.add_argument("--sign-pdpa-stdin", action="store_true", help="Sign PDPA payload JSON read from stdin")
    parser.add_argument("--verify-cert-stdin", action="store_true", help="Verify signed PDPA certificate from stdin")
    args = parser.parse_args(argv)

    vault = OperatorCryptoVault(keys_dir=args.keys_dir)

    if args.export_public_key:
        if args.raw_pem:
            sys.stdout.write(vault.public_key_pem)
        else:
            sys.stdout.write(json.dumps(vault.export_public_identity(), ensure_ascii=False))
        return 0

    if args.decrypt_stdin:
        raw_input = sys.stdin.read()
        envelope = json.loads(raw_input)
        decrypted = vault.decrypt_envelope(envelope)
        sys.stdout.write(json.dumps(decrypted, ensure_ascii=False))
        return 0

    if args.sign_pdpa_stdin:
        payload = json.loads(sys.stdin.read())
        signed = vault.sign_pdpa_certificate(payload)
        sys.stdout.write(json.dumps(signed, ensure_ascii=False))
        return 0

    if args.verify_cert_stdin:
        cert = json.loads(sys.stdin.read())
        ok = vault.verify_pdpa_certificate(cert)
        sys.stdout.write(json.dumps({"valid": ok}, ensure_ascii=False))
        return 0 if ok else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
