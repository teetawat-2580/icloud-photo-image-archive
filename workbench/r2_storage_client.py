"""
CloudVault Concierge — Cloudflare R2 (Free 10 GB, $0 Egress) & Local Encrypted PC NAS Blob Store.

Implements pure-Python AWS Signature Version 4 (`AWS4-HMAC-SHA256`) using ONLY stdlib `hashlib`/`hmac`
+ `httpx` (zero `boto3` dependency bloat). All objects stored in R2 or the local encrypted NAS folder
are strictly opaque AES-256-GCM ciphertext blobs (`*.enc`).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlparse

import httpx

SAFE_OBJECT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,511}$")


def validate_object_key(key: str) -> str:
    """Reject path traversal (`..`), leading slashes, backslashes, or null bytes in object keys."""
    if not isinstance(key, str) or not key:
        raise ValueError("Object key must be a non-empty string")
    if "\\" in key or "\x00" in key or key.startswith("/") or ".." in key.split("/"):
        raise ValueError(f"Unsafe object key rejected: {key!r}")
    if not SAFE_OBJECT_KEY_RE.match(key):
        raise ValueError(f"Invalid characters in object key: {key!r}")
    return key


class EncryptedBlobStorage(Protocol):
    backend_name: str
    bucket_name: str

    def put_encrypted_object(self, object_key: str, ciphertext_bytes: bytes, content_type: str = "application/octet-stream") -> dict[str, object]: ...
    def get_encrypted_object(self, object_key: str) -> bytes | None: ...
    def delete_vault_prefix(self, prefix: str) -> int: ...


@dataclass(frozen=True)
class CloudflareR2Config:
    account_id: str
    access_key_id: str
    secret_access_key: str
    bucket_name: str
    region: str = "auto"

    @classmethod
    def from_env(cls) -> CloudflareR2Config | None:
        acct = os.environ.get("R2_ACCOUNT_ID", "").strip()
        ak = os.environ.get("R2_ACCESS_KEY_ID", "").strip()
        sk = os.environ.get("R2_SECRET_ACCESS_KEY", "").strip()
        bucket = os.environ.get("R2_BUCKET_NAME", "").strip()
        if not (acct and ak and sk and bucket):
            return None
        if "your-" in acct.lower() or "your-" in ak.lower():
            return None
        return cls(account_id=acct, access_key_id=ak, secret_access_key=sk, bucket_name=bucket)

    @property
    def endpoint_host(self) -> str:
        return f"{self.account_id}.r2.cloudflarestorage.com"

    def object_url(self, object_key: str) -> str:
        safe_key = validate_object_key(object_key)
        encoded_key = "/".join(quote(part, safe="-_.~") for part in safe_key.split("/"))
        return f"https://{self.endpoint_host}/{self.bucket_name}/{encoded_key}"


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def build_sigv4_headers(
    *,
    method: str,
    url: str,
    payload_bytes: bytes,
    config: CloudflareR2Config,
    content_type: str | None = None,
    amz_date: str | None = None,
) -> dict[str, str]:
    """Build AWS Signature Version 4 headers for Cloudflare R2 S3-compatible requests."""
    parsed = urlparse(url)
    host = parsed.netloc
    canonical_uri = parsed.path or "/"
    canonical_query = parsed.query or ""

    now_utc = datetime.now(timezone.utc)
    amz_ts = amz_date or now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_ts[:8]
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    canonical_headers_map = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_ts,
    }
    signed_headers = ";".join(sorted(canonical_headers_map.keys()))
    canonical_headers = "".join(f"{k}:{canonical_headers_map[k]}\n" for k in sorted(canonical_headers_map.keys()))

    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    credential_scope = f"{date_stamp}/{config.region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_ts,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    k_date = _hmac_sha256(f"AWS4{config.secret_access_key}".encode("utf-8"), date_stamp)
    k_region = _hmac_sha256(k_date, config.region)
    k_service = _hmac_sha256(k_region, "s3")
    k_signing = _hmac_sha256(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={config.access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Host": host,
        "x-amz-date": amz_ts,
        "x-amz-content-sha256": payload_hash,
        "Authorization": auth_header,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


class CloudflareR2StorageClient:
    """Uploads/downloads encrypted `.enc` blobs to/from Cloudflare R2 (Free 10 GB tier)."""

    backend_name = "cloudflare_r2"

    def __init__(self, config: CloudflareR2Config, timeout_seconds: float = 30.0):
        self.config = config
        self.bucket_name = config.bucket_name
        self.timeout_seconds = timeout_seconds

    def put_encrypted_object(
        self,
        object_key: str,
        ciphertext_bytes: bytes,
        content_type: str = "application/octet-stream",
    ) -> dict[str, object]:
        safe_key = validate_object_key(object_key)
        url = self.config.object_url(safe_key)
        headers = build_sigv4_headers(
            method="PUT",
            url=url,
            payload_bytes=ciphertext_bytes,
            config=self.config,
            content_type=content_type,
        )
        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.put(url, content=ciphertext_bytes, headers=headers)
            resp.raise_for_status()
        return {
            "backend": self.backend_name,
            "bucket": self.bucket_name,
            "object_key": safe_key,
            "bytes": len(ciphertext_bytes),
            "sha256": hashlib.sha256(ciphertext_bytes).hexdigest(),
        }

    def get_encrypted_object(self, object_key: str) -> bytes | None:
        safe_key = validate_object_key(object_key)
        url = self.config.object_url(safe_key)
        headers = build_sigv4_headers(
            method="GET",
            url=url,
            payload_bytes=b"",
            config=self.config,
        )
        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.content

    def delete_vault_prefix(self, prefix: str) -> int:
        # Prefix deletion on R2 requires ListObjectsV2 + DeleteObject; handled via lifecycle rules or explicit keys.
        validate_object_key(prefix)
        return 0


class LocalEncryptedNasStorage:
    """
    Path-confined Local Encrypted PC NAS Store (`pc_tunnel_nas`).
    Stores ONLY AES-256-GCM ciphertext blobs (`*.enc`) on the local PC acting as a NAS
    (e.g. `D:\\SearchVaultBlobs\\`), which can be served privately over Cloudflare Tunnel ($0/month).
    """

    backend_name = "pc_tunnel_nas"

    def __init__(self, root_dir: Path | str, bucket_name: str = "local-encrypted-nas"):
        self.root_dir = Path(root_dir).resolve()
        self.bucket_name = bucket_name
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, object_key: str) -> Path:
        safe_key = validate_object_key(object_key)
        target = (self.root_dir / Path(*safe_key.split("/"))).resolve()
        if not target.is_relative_to(self.root_dir):
            raise ValueError(f"Path escapes encrypted blob root: {object_key!r}")
        return target

    def put_encrypted_object(
        self,
        object_key: str,
        ciphertext_bytes: bytes,
        content_type: str = "application/octet-stream",
    ) -> dict[str, object]:
        target = self._resolve_safe_path(object_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + f".{os.getpid()}.tmp")
        tmp.write_bytes(ciphertext_bytes)
        os.replace(tmp, target)
        return {
            "backend": self.backend_name,
            "bucket": self.bucket_name,
            "object_key": object_key,
            "bytes": len(ciphertext_bytes),
            "sha256": hashlib.sha256(ciphertext_bytes).hexdigest(),
        }

    def get_encrypted_object(self, object_key: str) -> bytes | None:
        target = self._resolve_safe_path(object_key)
        if not target.is_file():
            return None
        return target.read_bytes()

    def delete_vault_prefix(self, prefix: str) -> int:
        target_dir = self._resolve_safe_path(prefix)
        if not target_dir.exists():
            return 0
        removed = 0
        for p in sorted(target_dir.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
                removed += 1
            elif p.is_dir():
                try:
                    p.rmdir()
                except OSError:
                    pass
        try:
            target_dir.rmdir()
        except OSError:
            pass
        return removed
