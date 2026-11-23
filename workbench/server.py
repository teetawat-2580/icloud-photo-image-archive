"""
CloudVault Concierge — Local Operator PC Workbench FastAPI Server.

Security invariants:
- Binds STRICTLY to `127.0.0.1:8790` (NEVER `0.0.0.0`).
- Customer raw tracking token (`secrets.token_urlsafe(32)`) is returned ONCE upon job creation;
  ONLY `token_hash_sha256` is stored in Supabase / local state.
- Credential & OTP envelopes are decrypted strictly in RAM and shredded immediately.
- Subprocesses (such as `node workbench/cdp/gphotos_uploader.js`) are launched with array
  arguments (`shell=False`) and strictly isolated `--user-data-dir` + CDP port (`9301..9399`).
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import uvicorn
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from workbench.crypto_vault import OperatorCryptoVault
from workbench.icloud_engine import ICloudJobEngine, verify_five_locks
from workbench.job_sandbox import JobSandboxManager, is_onedrive_path
from workbench.search_vault_routes import register_search_vault_routes
from workbench.supabase_relay import SupabaseRelayClient

WORKBENCH_DIR = Path(__file__).resolve().parent
UI_DIR = WORKBENCH_DIR / "ui"
CDP_UPLOADER_SCRIPT = WORKBENCH_DIR / "cdp" / "gphotos_uploader.js"
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8790
BRAND_NAME = "CloudVault Concierge"


def _mask_account_identifier(account: str) -> str:
    """Mask email/account identifier for operator UI without exposing raw PII in logs."""
    cleaned = str(account or "").strip()
    if "@" in cleaned:
        local, domain = cleaned.split("@", 1)
        prefix = local[:2] if len(local) >= 2 else local[:1]
        return f"{prefix}***@{domain}"
    if len(cleaned) <= 3:
        return "***"
    return f"{cleaned[:2]}***"


# ----------------------------------------------------------------------
# Pydantic Request Models
# ----------------------------------------------------------------------
class CreateJobRequest(BaseModel):
    customer_name: str = Field(..., min_length=1, max_length=120)
    service_mode: Literal["copy_only", "move_free_space", "move_and_export"] = "copy_only"
    album_prefix: str = Field(default="iCloud_Archive_Google", min_length=1, max_length=80)
    staging_drive: str | None = Field(default=None, max_length=260)
    target_years: list[int] = Field(default_factory=list)


class ConsumeEnvelopeRequest(BaseModel):
    provider: Literal["icloud", "google_photos"] | None = None
    envelope: dict[str, Any] | None = None
    connect_icloud: bool = False


class RequestOtpBody(BaseModel):
    provider: Literal["icloud", "google_photos"] = "icloud"
    prompt_message: str = Field(
        default="กรุณากรอกรหัสยืนยัน 2FA 6 หลักที่แสดงบนอุปกรณ์ Apple ของคุณ",
        min_length=4,
        max_length=300,
    )
    ttl_seconds: int = Field(default=300, ge=30, le=900)


class ConsumeOtpBody(BaseModel):
    challenge_id: str | None = None
    encrypted_otp_envelope: dict[str, Any] | None = None


class VerifyFiveLocksBody(BaseModel):
    target_year: int = Field(..., ge=1990, le=2600)
    manifest_data: dict[str, Any] | None = None
    customer_approved_at: str | None = None


class LaunchCdpUploadBody(BaseModel):
    album_prefix: str | None = Field(default=None, max_length=80)
    dry_run: bool = False


# ----------------------------------------------------------------------
# Application Factory
# ----------------------------------------------------------------------
def create_app(
    *,
    staging_root: Path | str | None = None,
    keys_dir: Path | str | None = None,
    local_state_path: Path | str | None = None,
    public_web_url: str | None = None,
    supabase_url: str | None = None,
    service_role_key: str | None = None,
    cdp_uploader_script: Path | str | None = None,
) -> FastAPI:
    vault = OperatorCryptoVault(keys_dir=keys_dir)
    sandbox = JobSandboxManager(staging_root=staging_root)
    relay = SupabaseRelayClient(
        supabase_url=supabase_url,
        service_role_key=service_role_key,
        local_state_path=local_state_path,
    )
    web_base_url = (
        public_web_url
        if public_web_url is not None
        else os.environ.get("PUBLIC_WEB_URL", "http://localhost:3000")
    ).rstrip("/")
    uploader_path = Path(cdp_uploader_script) if cdp_uploader_script is not None else CDP_UPLOADER_SCRIPT

    node_label = os.environ.get("OPERATOR_NODE_LABEL", f"Operator-PC-{os.environ.get('COMPUTERNAME', 'Local')}")
    operator_node = relay.register_operator_node(
        label=node_label,
        public_key_pem=vault.public_key_pem,
        key_fingerprint_sha256=vault.key_fingerprint_sha256,
    )

    # RAM-only session registry per job_id (never persisted to disk; wiped on PDPA purge)
    ram_sessions: dict[str, dict[str, Any]] = {}
    icloud_engines: dict[str, ICloudJobEngine] = {}

    app = FastAPI(
        title=f"{BRAND_NAME} — Local Operator Workbench",
        version="1.0.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # Attach services on app.state for direct inspection in tests
    app.state.vault = vault
    app.state.sandbox = sandbox
    app.state.relay = relay
    app.state.operator_node = operator_node
    app.state.ram_sessions = ram_sessions

    def _require_job(job_id: str) -> dict[str, Any]:
        try:
            sandbox.validate_job_id(job_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = relay.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
        return job

    def _get_or_create_engine(job_id: str) -> ICloudJobEngine:
        if job_id not in icloud_engines:
            info = sandbox.allocate_sandbox(job_id)
            icloud_engines[job_id] = ICloudJobEngine(
                job_id=job_id,
                staging_dir=info["staging_dir"],
                icloud_session_dir=info["icloud_session_dir"],
                logs_dir=info["logs_dir"],
            )
        return icloud_engines[job_id]

    # ------------------------------------------------------------------
    # Operator REST API Endpoints
    # ------------------------------------------------------------------
    @app.get("/api/operator/health")
    def get_health() -> dict[str, Any]:
        jobs = relay.list_jobs()
        return {
            "status": "ok",
            "brand": BRAND_NAME,
            "bind_host": DEFAULT_BIND_HOST,
            "port": DEFAULT_BIND_PORT,
            "operator_node_id": operator_node["id"],
            "operator_node_label": node_label,
            "key_fingerprint_sha256": vault.key_fingerprint_sha256,
            "public_key_pem": vault.public_key_pem,
            "staging_root": str(sandbox.staging_root),
            "staging_in_onedrive": is_onedrive_path(sandbox.staging_root),
            "supabase_mode": relay.mode,
            "public_web_url": web_base_url,
            "jobs_count": len(jobs),
        }

    @app.get("/api/operator/jobs")
    def list_jobs() -> dict[str, Any]:
        jobs = relay.list_jobs()
        enriched: list[dict[str, Any]] = []
        for job in jobs:
            jid = job["id"]
            sb_info = sandbox.get_sandbox_info(jid) if re.fullmatch(r"^[a-zA-Z0-9_-]{4,64}$", str(jid)) else {}
            enriched.append(
                {
                    **job,
                    "sandbox": sb_info,
                    "has_ram_session": jid in ram_sessions,
                    "ram_session_summary": ram_sessions.get(jid),
                }
            )
        return {"jobs": enriched}

    @app.post("/api/operator/jobs", status_code=201)
    def create_job(body: CreateJobRequest) -> dict[str, Any]:
        if body.staging_drive and is_onedrive_path(body.staging_drive):
            raise HTTPException(
                status_code=400,
                detail="Staging drive must NEVER reside inside OneDrive. Use a local non-synced drive such as D:\\MigrationJobs.",
            )

        job_id = str(uuid.uuid4())
        date_stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        job_code = f"CV-{date_stamp}-{secrets.token_hex(3).upper()}"

        # Generate 32-byte URL-safe raw customer tracking token & store ONLY its SHA-256 hash
        raw_token = secrets.token_urlsafe(32)
        token_hash_sha256 = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        sandbox_meta = sandbox.allocate_sandbox(job_id)

        cleaned_years = sorted({int(y) for y in body.target_years if 1990 <= int(y) <= 2100})
        telemetry_init = {
            "staging_drive": body.staging_drive or str(sandbox.staging_root),
            "cdp_port": sandbox_meta["cdp_port"],
            "created_by_node": operator_node["id"],
        }

        created_job = relay.create_job(
            {
                "id": job_id,
                "operator_node_id": operator_node["id"],
                "job_code": job_code,
                "customer_display_name": body.customer_name.strip(),
                "service_mode": body.service_mode,
                "status": "AWAITING_CREDENTIALS",
                "token_hash_sha256": token_hash_sha256,
                "target_years": cleaned_years,
                "album_prefix": body.album_prefix.strip(),
                "telemetry_snapshot": telemetry_init,
            }
        )

        tracking_link = f"{web_base_url}/job/{job_id}?t={raw_token}"
        return {
            "job": created_job,
            "sandbox": sandbox_meta,
            "customer_tracking_link": tracking_link,
            "raw_token": raw_token,
            "token_storage_policy": "raw_token_returned_once_only_sha256_stored",
        }

    @app.post("/api/operator/jobs/{job_id}/consume-envelope")
    def consume_envelope(job_id: str, body: ConsumeEnvelopeRequest | None = None) -> dict[str, Any]:
        job = _require_job(job_id)
        req = body or ConsumeEnvelopeRequest()

        envelope = req.envelope
        if envelope is None:
            envelope = relay.fetch_and_shred_envelope(job_id, provider=req.provider)
        if envelope is None:
            raise HTTPException(
                status_code=404,
                detail="No pending credential envelope available for this job (already shredded or not submitted yet).",
            )

        try:
            decrypted = vault.decrypt_envelope(envelope)
        except (ValueError, InvalidTag) as exc:
            raise HTTPException(status_code=422, detail=f"Envelope decryption rejected: {exc}") from exc

        provider = req.provider or envelope.get("provider") or decrypted.get("provider") or "icloud"
        account_id = str(decrypted.get("apple_id") or decrypted.get("email") or decrypted.get("account") or "")
        password = decrypted.get("password")
        account_masked = _mask_account_identifier(account_id)

        session_state: dict[str, Any] = {
            "provider": provider,
            "account_masked": account_masked,
            "consumed_at": datetime.now(timezone.utc).isoformat(),
            "requires_2fa": False,
            "authenticated": False,
        }

        try:
            if req.connect_icloud and provider == "icloud" and account_id:
                engine = _get_or_create_engine(job_id)
                conn = engine.connect(account_id, str(password) if password is not None else None)
                session_state["requires_2fa"] = conn["requires_2fa"]
                session_state["authenticated"] = conn["authenticated"]
            else:
                _get_or_create_engine(job_id)
                session_state["authenticated"] = bool(account_id and password)
        finally:
            # Drop decrypted credential dict references promptly after establishing session state
            decrypted.clear()
            password = None

        ram_sessions[job_id] = session_state
        next_status = "AWAITING_2FA_ICLOUD" if session_state["requires_2fa"] else "CREDENTIALS_RECEIVED"
        relay.update_job(
            job_id,
            {
                "status": next_status,
                "telemetry_snapshot": {
                    **(job.get("telemetry_snapshot") or {}),
                    "last_envelope_provider": provider,
                    "account_masked": account_masked,
                    "envelope_shredded_at": session_state["consumed_at"],
                },
            },
        )
        return {
            "job_id": job_id,
            "provider": provider,
            "account_masked": account_masked,
            "envelope_shredded": True,
            "requires_2fa": session_state["requires_2fa"],
            "status": next_status,
        }

    @app.post("/api/operator/jobs/{job_id}/request-otp")
    def request_otp(job_id: str, body: RequestOtpBody) -> dict[str, Any]:
        _require_job(job_id)
        challenge = relay.create_otp_challenge(
            job_id=job_id,
            provider=body.provider,
            prompt_message=body.prompt_message,
            ttl_seconds=body.ttl_seconds,
        )
        next_status = "AWAITING_2FA_ICLOUD" if body.provider == "icloud" else "AWAITING_2FA_GOOGLE"
        relay.update_job(job_id, {"status": next_status})
        return {"job_id": job_id, "status": next_status, "challenge": challenge}

    @app.post("/api/operator/jobs/{job_id}/consume-otp")
    def consume_otp(job_id: str, body: ConsumeOtpBody | None = None) -> dict[str, Any]:
        _require_job(job_id)
        req = body or ConsumeOtpBody()

        otp_envelope = req.encrypted_otp_envelope
        challenge_id = req.challenge_id
        if otp_envelope is None:
            challenge = relay.fetch_and_shred_otp(job_id, challenge_id=req.challenge_id)
            if challenge is None:
                raise HTTPException(
                    status_code=404,
                    detail="No submitted OTP challenge available for this job (not submitted yet or already shredded).",
                )
            challenge_id = challenge.get("id")
            otp_envelope = challenge.get("encrypted_otp_envelope")

        if not isinstance(otp_envelope, dict):
            raise HTTPException(status_code=422, detail="OTP challenge is missing encrypted_otp_envelope")

        try:
            decrypted = vault.decrypt_envelope(otp_envelope)
        except (ValueError, InvalidTag) as exc:
            raise HTTPException(status_code=422, detail=f"OTP decryption rejected: {exc}") from exc

        code_raw = str(decrypted.get("otp_code") or decrypted.get("code") or "")
        digits = re.sub(r"\D+", "", code_raw)
        decrypted.clear()

        if len(digits) != 6:
            raise HTTPException(status_code=422, detail="Decrypted OTP code must be exactly 6 digits")

        session_validated = False
        engine = icloud_engines.get(job_id)
        if engine is not None and getattr(engine, "_api", None) is not None:
            session_validated = engine.submit_2fa_code(digits)

        relay.update_job(job_id, {"status": "SCANNING_CATALOG"})
        return {
            "job_id": job_id,
            "challenge_id": challenge_id,
            "otp_received": True,
            "otp_shredded": True,
            "session_validated": session_validated,
            "status": "SCANNING_CATALOG",
        }

    @app.post("/api/operator/jobs/{job_id}/verify-five-locks")
    def api_verify_five_locks(job_id: str, body: VerifyFiveLocksBody) -> dict[str, Any]:
        job = _require_job(job_id)
        manifest_data = body.manifest_data
        if manifest_data is None:
            engine = _get_or_create_engine(job_id)
            manifest_data = engine.load_manifest()

        approved_at = (
            body.customer_approved_at
            if body.customer_approved_at is not None
            else job.get("five_lock_approved_by_customer_at")
        )
        result = verify_five_locks(manifest_data, body.target_year, approved_at)

        next_status = "CLEANING_ICLOUD" if result["passed"] else "AWAITING_5LOCK_APPROVAL"
        telemetry = {
            **(job.get("telemetry_snapshot") or {}),
            "last_five_lock_check": result,
        }
        relay.push_telemetry_snapshot(
            job_id=job_id,
            snapshot=telemetry,
            status=next_status,
            year_progress_rows=[
                {
                    "year": result["target_year"],
                    "catalog_count": result["expected_catalog_count"],
                    "verified_count": result["locks"]["lock_2_local_sha256"]["verified"],
                    "uploaded_count": result["locks"]["lock_1_gphotos_uploaded"]["verified"],
                    "five_lock_status": result,
                }
            ],
        )
        return result

    @app.post("/api/operator/jobs/{job_id}/launch-cdp-upload")
    def launch_cdp_upload(job_id: str, body: LaunchCdpUploadBody | None = None) -> dict[str, Any]:
        job = _require_job(job_id)
        req = body or LaunchCdpUploadBody()
        sb_meta = sandbox.allocate_sandbox(job_id)
        album_prefix = (req.album_prefix or job.get("album_prefix") or "iCloud_Archive_Google").strip()

        if not uploader_path.exists():
            raise HTTPException(status_code=404, detail=f"CDP uploader script not found at {uploader_path}")
        if sandbox.has_active_process(job_id):
            raise HTTPException(status_code=409, detail=f"Job '{job_id}' already has an active CDP upload subprocess running.")

        engine = _get_or_create_engine(job_id)
        if not engine.manifest_path.exists():
            engine.save_manifest(engine.load_manifest())

        # Strictly array arguments with shell=False (immune to OS Command Injection)
        cmd = [
            "node", str(uploader_path),
            "--job-id", job_id,
            "--profile-dir", sb_meta["chrome_profile_dir"],
            "--cdp-port", str(sb_meta["cdp_port"]),
            "--manifest", str(engine.manifest_path),
            "--album-prefix", album_prefix,
            "--sandbox-dir", sb_meta["job_root"],
        ]
        if req.dry_run:
            cmd.append("--dry-run")

        log_file_path = sandbox.resolve_sandbox_subpath(job_id, "logs", "cdp_uploader.log")
        log_handle = open(log_file_path, "ab")
        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                cwd=str(WORKBENCH_DIR.parent),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to spawn CDP uploader: {exc}") from exc
        finally:
            log_handle.close()

        sandbox.register_process(job_id, proc)
        relay.update_job(job_id, {"status": "UPLOADING_GPHOTOS"})
        return {
            "job_id": job_id, "pid": proc.pid, "cdp_port": sb_meta["cdp_port"],
            "chrome_profile_dir": sb_meta["chrome_profile_dir"], "album_prefix": album_prefix,
            "log_file": str(log_file_path), "status": "UPLOADING_GPHOTOS",
        }

    @app.post("/api/operator/jobs/{job_id}/pdpa-purge")
    def pdpa_purge(job_id: str) -> dict[str, Any]:
        _require_job(job_id)
        try:
            cert = sandbox.execute_pdpa_purge(job_id, vault)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        ram_sessions.pop(job_id, None)
        icloud_engines.pop(job_id, None)
        relay.publish_pdpa_certificate(job_id, cert)
        return {
            "job_id": job_id,
            "status": "COMPLETED",
            "pdpa_certificate": cert,
        }

    # ------------------------------------------------------------------
    # Zero-Knowledge Encrypted Search Vault Routes (`002_search_vault.sql`)
    # ------------------------------------------------------------------
    register_search_vault_routes(
        app,
        relay=relay,
        sandbox=sandbox,
        web_base_url=web_base_url,
    )

    # ------------------------------------------------------------------
    # Local Operator Control Panel UI Static Serving
    # ------------------------------------------------------------------
    if UI_DIR.exists():
        app.mount("/ui", StaticFiles(directory=str(UI_DIR)), name="ui_assets")

    @app.get("/", include_in_schema=False)
    def serve_index() -> FileResponse:
        index_file = UI_DIR / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="Operator UI index.html not found")
        return FileResponse(str(index_file))

    return app


def _load_workbench_env() -> None:
    """Load key=value pairs from `workbench/.env` without overriding existing env vars."""
    env_file = WORKBENCH_DIR / ".env"
    if not env_file.is_file():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and val and key not in os.environ:
            os.environ[key] = val


_DEFAULT_APP: FastAPI | None = None


def get_default_app() -> FastAPI:
    global _DEFAULT_APP
    if _DEFAULT_APP is None:
        _load_workbench_env()
        _DEFAULT_APP = create_app()
    return _DEFAULT_APP


def __getattr__(name: str) -> Any:
    if name == "app":
        return get_default_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def run_server() -> None:
    """Launch uvicorn bound strictly to localhost `127.0.0.1:8790` (NEVER `0.0.0.0`)."""
    _load_workbench_env()
    host = os.environ.get("WORKBENCH_HOST", DEFAULT_BIND_HOST).strip()
    if host not in ("127.0.0.1", "localhost"):
        raise RuntimeError(
            f"Security violation: Operator Workbench MUST bind strictly to 127.0.0.1 (refused host='{host}')."
        )
    port = int(os.environ.get("WORKBENCH_PORT", str(DEFAULT_BIND_PORT)))
    uvicorn.run(get_default_app(), host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    run_server()
