"""
CloudVault Concierge — Local Operator Workbench Routes for Zero-Knowledge Search Vaults.

Mounted strictly on `http://127.0.0.1:8790` via `workbench/server.py`:
- `POST /api/operator/vaults` — creates a Search Vault, returns one-time Vault Link (`/vault/<id>?t=<raw_token>`).
- `GET /api/operator/vaults` — lists Search Vaults.
- `POST /api/operator/vaults/{vault_id}/build-index` — runs transient AI indexing (InsightFace + RapidOCR Thai + CLIP)
  using ONLY `customer_public_key_pem`, uploads ciphertext to Cloudflare R2 / Local Encrypted PC NAS,
  purges all plaintext artifacts, and publishes metadata to Supabase.
- `GET /api/operator/vaults/{vault_id}/blobs/{object_key:path}` — serves opaque `.enc` ciphertext blobs when
  running the PC in `pc_tunnel_nas` mode (Zero plaintext ever leaves the PC).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from workbench.job_sandbox import JobSandboxManager
from workbench.media_source_adapter import MediaSourceConfig
from workbench.r2_storage_client import (
    CloudflareR2Config,
    CloudflareR2StorageClient,
    EncryptedBlobStorage,
    LocalEncryptedNasStorage,
    validate_object_key,
)
from workbench.search_vault_indexer import SearchVaultIndexer
from workbench.supabase_relay import SupabaseRelayClient

DEFAULT_ENCRYPTED_BLOBS_ROOT = Path(os.environ.get("SEARCH_VAULT_BLOBS_ROOT", r"D:\SearchVaultBlobs"))


class CreateSearchVaultRequest(BaseModel):
    owner_display_name: str = Field(..., min_length=1, max_length=120)
    job_id: str | None = Field(default=None, max_length=64)
    owner_email: str | None = Field(default=None, max_length=180)
    storage_backend: Literal["cloudflare_r2", "pc_tunnel_nas"] = "cloudflare_r2"
    media_source_type: Literal["google_photos_shared", "google_photos_private", "nas_immich", "local_hdd"] = "google_photos_shared"
    media_source_config: dict[str, Any] = Field(default_factory=dict)


class BuildVaultIndexRequest(BaseModel):
    source_dir: str = Field(..., min_length=1, max_length=400)
    customer_public_key_pem: str | None = Field(default=None, max_length=4096)
    media_source_type: Literal["google_photos_shared", "google_photos_private", "nas_immich", "local_hdd"] | None = None
    media_source_config: dict[str, Any] | None = None
    max_files: int = Field(default=200_000, ge=1, le=500_000)


def _select_storage_client(
    backend: str,
    local_blobs_root: Path,
) -> EncryptedBlobStorage:
    if backend == "cloudflare_r2":
        r2_cfg = CloudflareR2Config.from_env()
        if r2_cfg is not None:
            return CloudflareR2StorageClient(r2_cfg)
    return LocalEncryptedNasStorage(local_blobs_root)


def register_search_vault_routes(
    app: FastAPI,
    *,
    relay: SupabaseRelayClient,
    sandbox: JobSandboxManager,
    web_base_url: str,
    encrypted_blobs_root: Path | str | None = None,
    indexer: SearchVaultIndexer | None = None,
) -> None:
    blobs_root = (
        Path(encrypted_blobs_root).resolve()
        if encrypted_blobs_root is not None
        else Path(os.environ.get("SEARCH_VAULT_BLOBS_ROOT", str(DEFAULT_ENCRYPTED_BLOBS_ROOT))).resolve()
    )
    active_indexer = indexer or SearchVaultIndexer()

    @app.get("/api/operator/vaults")
    def list_vaults() -> dict[str, Any]:
        return {"vaults": relay.list_search_vaults()}

    @app.post("/api/operator/vaults")
    def create_vault(body: CreateSearchVaultRequest) -> dict[str, Any]:
        vault_id = str(uuid.uuid4())
        short_code = f"VLT-{datetime.now(timezone.utc).strftime('%Y')}-{secrets.token_hex(2).upper()}"
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        email_hash = (
            hashlib.sha256(body.owner_email.strip().lower().encode("utf-8")).hexdigest()
            if body.owner_email and body.owner_email.strip()
            else None
        )

        record = relay.create_search_vault(
            {
                "id": vault_id,
                "job_id": body.job_id,
                "vault_code": short_code,
                "owner_display_name": body.owner_display_name.strip(),
                "owner_email_hash_sha256": email_hash,
                "access_token_hash_sha256": token_hash,
                "status": "AWAITING_CUSTOMER_KEY",
                "storage_backend": body.storage_backend,
                "media_source_type": body.media_source_type,
                "media_source_config": body.media_source_config,
            }
        )
        vault_link = f"{web_base_url}/vault/{vault_id}?t={raw_token}"
        return {
            "vault": {k: v for k, v in record.items() if k != "access_token_hash_sha256"},
            "vault_access_token": raw_token,
            "customer_vault_url": vault_link,
        }

    @app.post("/api/operator/vaults/{vault_id}/build-index")
    def build_vault_index(vault_id: str, body: BuildVaultIndexRequest) -> dict[str, Any]:
        vault_row = relay.get_search_vault(vault_id)
        if vault_row is None:
            raise HTTPException(status_code=404, detail=f"Search vault '{vault_id}' not found")

        pub_pem = (body.customer_public_key_pem or vault_row.get("customer_public_key_pem") or "").strip()
        if not pub_pem or "BEGIN PUBLIC KEY" not in pub_pem:
            raise HTTPException(
                status_code=409,
                detail="Customer public key is not registered yet. Ask the customer to set their Vault Passphrase on the portal first.",
            )

        src_dir = Path(body.source_dir).resolve()
        if not src_dir.is_dir():
            raise HTTPException(status_code=400, detail=f"Source directory does not exist: {body.source_dir}")

        image_exts = {".jpg", ".jpeg", ".png", ".webp", ".heic"}
        source_files: list[dict[str, Any]] = []
        for p in sorted(src_dir.rglob("*")):
            if len(source_files) >= body.max_files:
                break
            if p.is_file() and p.suffix.lower() in image_exts:
                year_val: int | None = None
                for part in p.parts:
                    if len(part) >= 4 and part[:4].isdigit():
                        cand = int(part[:4])
                        if 1970 <= cand <= 2100:
                            year_val = cand
                            break
                source_files.append(
                    {
                        "path": p,
                        "filename": p.name,
                        "year": year_val,
                        "relative_path": str(p.relative_to(src_dir)).replace("\\", "/"),
                    }
                )

        if not source_files:
            raise HTTPException(status_code=400, detail="No supported image files found in source_dir")

        relay.update_search_vault(vault_id, {"status": "INDEXING"})

        src_type = body.media_source_type or vault_row.get("media_source_type") or "google_photos_shared"
        src_cfg_dict = body.media_source_config if body.media_source_config is not None else (vault_row.get("media_source_config") or {})
        media_cfg = MediaSourceConfig(
            source_type=src_type,
            albums=src_cfg_dict.get("albums") or {},
            nas_base_url=str(src_cfg_dict.get("nas_base_url") or ""),
            local_root_label=str(src_cfg_dict.get("local_root_label") or ""),
        )

        storage_client = _select_storage_client(
            str(vault_row.get("storage_backend") or "cloudflare_r2"),
            blobs_root,
        )
        temp_work_dir = sandbox.staging_root / f"_vault_tmp_{vault_id}"

        pub = active_indexer.build_and_publish_encrypted_vault(
            vault_id=vault_id,
            source_files=source_files,
            customer_public_key_pem=pub_pem,
            storage_client=storage_client,
            media_source_config=media_cfg,
            temp_work_dir=temp_work_dir,
        )

        updated = relay.update_search_vault(
            vault_id,
            {
                "status": "READY",
                "wrapped_vault_key_b64": pub["wrapped_vault_key_b64"],
                "storage_backend": pub["storage_backend"],
                "storage_bucket": pub["storage_bucket"],
                "index_object_key": pub["index_object_key"],
                "index_sha256": pub["index_sha256"],
                "index_size_bytes": pub["index_size_bytes"],
                "thumb_prefix": pub["thumb_prefix"],
                "media_source_type": pub["media_source_type"],
                "media_source_config": pub["media_source_config"],
                "total_assets": pub["total_assets"],
                "total_faces": pub["total_faces"],
                "total_ocr_assets": pub["total_ocr_assets"],
                "total_thumb_bytes": pub["total_thumb_bytes"],
                "plaintext_purged_at": pub["plaintext_purged_at"],
            },
        )
        return {"published": pub, "vault": updated}

    @app.get("/api/operator/vaults/{vault_id}/blobs/{object_key:path}")
    def serve_encrypted_blob_from_pc_nas(vault_id: str, object_key: str) -> Response:
        """
        Serves strictly opaque `.enc` AES-256-GCM blobs stored on the local PC acting as NAS.
        Path-confined to `vaults/{vault_id}/...`.
        """
        try:
            safe_key = validate_object_key(object_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not safe_key.startswith(f"vaults/{vault_id}/") or not safe_key.endswith(".enc"):
            raise HTTPException(status_code=403, detail="Encrypted blob key outside vault scope")

        store = LocalEncryptedNasStorage(blobs_root)
        data = store.get_encrypted_object(safe_key)
        if data is None:
            raise HTTPException(status_code=404, detail="Encrypted blob not found")
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Cache-Control": "private, max-age=86400"},
        )
