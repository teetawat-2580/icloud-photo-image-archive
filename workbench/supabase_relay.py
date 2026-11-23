"""
CloudVault Concierge — Lightweight Supabase PostgREST Relay Client with Offline Local Fallback.

Uses `httpx` with `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` loaded from `workbench/.env`.
When Supabase credentials are not configured yet (or offline mode is selected), all methods
operate transparently against an atomic local JSON store (`workbench/.local_state/jobs.json`)
so the Operator PC Workbench can be launched, demonstrated, and unit-tested immediately.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]


WORKBENCH_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_PATH = WORKBENCH_DIR / ".env"
DEFAULT_LOCAL_STATE_PATH = WORKBENCH_DIR / ".local_state" / "jobs.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utc_future_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _empty_local_state() -> dict[str, Any]:
    return {
        "operator_nodes": {},
        "migration_jobs": {},
        "credential_envelopes": {},
        "otp_challenges": {},
        "job_year_progress": {},
        "search_vaults": {},
    }


class SupabaseRelayClient:
    """
    Hybrid PostgREST client targeting Supabase schema `001_init_schema.sql`:
      - `operator_nodes`
      - `migration_jobs`
      - `credential_envelopes`
      - `otp_challenges`
      - `job_year_progress`
    Falls back seamlessly to local atomic JSON persistence when Supabase env vars are absent.
    """

    def __init__(
        self,
        supabase_url: str | None = None,
        service_role_key: str | None = None,
        local_state_path: Path | str | None = None,
        env_path: Path | str | None = DEFAULT_ENV_PATH,
        timeout_seconds: float = 15.0,
    ):
        if load_dotenv is not None and env_path is not None and Path(env_path).exists():
            load_dotenv(dotenv_path=env_path, override=False)

        raw_url = supabase_url if supabase_url is not None else os.environ.get("SUPABASE_URL", "")
        raw_key = service_role_key if service_role_key is not None else os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

        self.supabase_url = raw_url.strip().rstrip("/")
        self.service_role_key = raw_key.strip()
        self.timeout_seconds = timeout_seconds
        self.local_state_path = Path(local_state_path) if local_state_path is not None else DEFAULT_LOCAL_STATE_PATH
        self._lock = threading.RLock()

        # Treat placeholder values from .env.example as offline mode
        placeholder_url = not self.supabase_url or "your-project-ref" in self.supabase_url.lower()
        placeholder_key = not self.service_role_key or "your-service-role-key" in self.service_role_key.lower()
        self.online_mode = not (placeholder_url or placeholder_key)

    @property
    def mode(self) -> str:
        return "online" if self.online_mode else "offline_local"

    def _headers(self, prefer: str | None = None) -> dict[str, str]:
        headers = {
            "apikey": self.service_role_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Legacy JWT service_role keys require Authorization: Bearer <jwt>,
        # whereas modern Supabase Secret Keys (`sb_secret_...`) authenticate via `apikey` only.
        if not self.service_role_key.startswith("sb_secret_"):
            headers["Authorization"] = f"Bearer {self.service_role_key}"
        if prefer:
            headers["Prefer"] = prefer
        return headers

    def _rest_url(self, table: str) -> str:
        return f"{self.supabase_url}/rest/v1/{table}"

    def _load_local_state(self) -> dict[str, Any]:
        if not self.local_state_path.exists():
            return _empty_local_state()
        try:
            data = json.loads(self.local_state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                base = _empty_local_state()
                base.update(data)
                return base
        except Exception:
            pass
        return _empty_local_state()

    def _save_local_state(self, state: dict[str, Any]) -> None:
        self.local_state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.local_state_path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.local_state_path)

    def _request(
        self,
        method: str,
        table: str,
        *,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        prefer: str | None = None,
    ) -> Any:
        with httpx.Client(timeout=self.timeout_seconds) as client:
            resp = client.request(
                method,
                self._rest_url(table),
                headers=self._headers(prefer=prefer),
                params=params,
                json=json_body,
            )
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    # ------------------------------------------------------------------
    # 1. Operator Node Registration
    # ------------------------------------------------------------------
    def register_operator_node(
        self,
        label: str,
        public_key_pem: str,
        key_fingerprint_sha256: str,
    ) -> dict[str, Any]:
        now_iso = _utc_now_iso()
        if self.online_mode:
            payload = {
                "label": label,
                "public_key_pem": public_key_pem,
                "key_fingerprint_sha256": key_fingerprint_sha256,
                "last_heartbeat_at": now_iso,
            }
            rows = self._request(
                "POST",
                "operator_nodes",
                params={"on_conflict": "key_fingerprint_sha256"},
                json_body=payload,
                prefer="resolution=merge-duplicates,return=representation",
            )
            if isinstance(rows, list) and rows:
                return rows[0]
            return payload

        with self._lock:
            state = self._load_local_state()
            existing = state["operator_nodes"].get(key_fingerprint_sha256)
            node = {
                "id": existing["id"] if existing else str(uuid.uuid4()),
                "label": label,
                "public_key_pem": public_key_pem,
                "key_fingerprint_sha256": key_fingerprint_sha256,
                "last_heartbeat_at": now_iso,
                "created_at": existing["created_at"] if existing else now_iso,
            }
            state["operator_nodes"][key_fingerprint_sha256] = node
            self._save_local_state(state)
            return node

    # ------------------------------------------------------------------
    # 2. Migration Jobs CRUD
    # ------------------------------------------------------------------
    def create_job(self, job_payload: dict[str, Any]) -> dict[str, Any]:
        """Persist a new migration job (MUST contain only `token_hash_sha256`, NEVER raw token)."""
        if "raw_token" in job_payload or "token" in job_payload:
            raise ValueError("Refusing to persist raw customer token; only token_hash_sha256 may be stored.")

        now_iso = _utc_now_iso()
        record = {
            "id": job_payload.get("id") or str(uuid.uuid4()),
            "operator_node_id": job_payload["operator_node_id"],
            "job_code": job_payload["job_code"],
            "customer_display_name": job_payload["customer_display_name"],
            "service_mode": job_payload["service_mode"],
            "status": job_payload.get("status", "AWAITING_CREDENTIALS"),
            "token_hash_sha256": job_payload["token_hash_sha256"],
            "target_years": job_payload.get("target_years", []),
            "album_prefix": job_payload.get("album_prefix", "iCloud_Archive_Google"),
            "total_files": int(job_payload.get("total_files", 0)),
            "downloaded_files": int(job_payload.get("downloaded_files", 0)),
            "verified_sha256_files": int(job_payload.get("verified_sha256_files", 0)),
            "uploaded_files": int(job_payload.get("uploaded_files", 0)),
            "total_bytes": int(job_payload.get("total_bytes", 0)),
            "reclaimed_bytes": int(job_payload.get("reclaimed_bytes", 0)),
            "five_lock_approved_by_customer_at": job_payload.get("five_lock_approved_by_customer_at"),
            "pdpa_purged_at": job_payload.get("pdpa_purged_at"),
            "pdpa_purge_certificate": job_payload.get("pdpa_purge_certificate"),
            "telemetry_snapshot": job_payload.get("telemetry_snapshot", {}),
        }

        if self.online_mode:
            rows = self._request(
                "POST",
                "migration_jobs",
                json_body=record,
                prefer="return=representation",
            )
            return rows[0] if isinstance(rows, list) and rows else record

        with self._lock:
            state = self._load_local_state()
            stored = dict(record)
            stored["created_at"] = now_iso
            stored["updated_at"] = now_iso
            state["migration_jobs"][stored["id"]] = stored
            self._save_local_state(state)
            return stored

    def list_jobs(self) -> list[dict[str, Any]]:
        if self.online_mode:
            rows = self._request(
                "GET",
                "migration_jobs",
                params={"select": "*", "order": "created_at.desc"},
            )
            return list(rows or [])

        with self._lock:
            state = self._load_local_state()
            jobs = list(state["migration_jobs"].values())
            jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
            return jobs

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        if self.online_mode:
            rows = self._request(
                "GET",
                "migration_jobs",
                params={"id": f"eq.{job_id}", "select": "*", "limit": "1"},
            )
            if isinstance(rows, list) and rows:
                return rows[0]
            rows_code = self._request(
                "GET",
                "migration_jobs",
                params={"job_code": f"eq.{job_id}", "select": "*", "limit": "1"},
            )
            return rows_code[0] if isinstance(rows_code, list) and rows_code else None

        with self._lock:
            state = self._load_local_state()
            if job_id in state["migration_jobs"]:
                return state["migration_jobs"][job_id]
            for job in state["migration_jobs"].values():
                if job.get("job_code") == job_id:
                    return job
            return None

    def update_job(self, job_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        if "raw_token" in patch or "token" in patch:
            raise ValueError("Refusing to persist raw customer token.")

        if self.online_mode:
            rows = self._request(
                "PATCH",
                "migration_jobs",
                params={"id": f"eq.{job_id}"},
                json_body=patch,
                prefer="return=representation",
            )
            return rows[0] if isinstance(rows, list) and rows else None

        with self._lock:
            state = self._load_local_state()
            job = state["migration_jobs"].get(job_id)
            if job is None:
                return None
            job.update(patch)
            job["updated_at"] = _utc_now_iso()
            state["migration_jobs"][job_id] = job
            self._save_local_state(state)
            return job

    # ------------------------------------------------------------------
    # 3. Single-Use E2E Credential Envelopes (Fetch + Immediate Shred)
    # ------------------------------------------------------------------
    def enqueue_envelope_local(self, job_id: str, provider: str, envelope: dict[str, Any]) -> dict[str, Any]:
        """Store an encrypted envelope in offline local state (for offline mode / tests)."""
        env_id = str(uuid.uuid4())
        rec = {
            "id": env_id,
            "job_id": job_id,
            "provider": provider,
            "key_fingerprint_sha256": envelope["key_fingerprint_sha256"],
            "wrapped_key_b64": envelope.get("wrapped_key_b64") or envelope.get("encrypted_aes_key_b64"),
            "iv_b64": envelope["iv_b64"],
            "ciphertext_b64": envelope["ciphertext_b64"],
            "expires_at": _utc_future_iso(600),
            "created_at": _utc_now_iso(),
        }
        with self._lock:
            state = self._load_local_state()
            state["credential_envelopes"].setdefault(job_id, []).append(rec)
            self._save_local_state(state)
        return rec

    def fetch_and_shred_envelope(
        self,
        job_id: str,
        provider: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Pull the latest credential envelope for `job_id` and IMMEDIATELY issue `DELETE`
        so zero ciphertext remains in Supabase or local state.
        """
        if self.online_mode:
            params: dict[str, str] = {
                "job_id": f"eq.{job_id}",
                "order": "created_at.desc",
                "limit": "1",
            }
            if provider:
                params["provider"] = f"eq.{provider}"
            rows = self._request("GET", "credential_envelopes", params=params)
            if not isinstance(rows, list) or not rows:
                return None
            envelope = rows[0]
            env_id = envelope["id"]
            # Immediately shred from Supabase PostgREST
            self._request("DELETE", "credential_envelopes", params={"id": f"eq.{env_id}"})
            return envelope

        with self._lock:
            state = self._load_local_state()
            bucket = state["credential_envelopes"].get(job_id, [])
            if not bucket:
                return None
            match_idx = None
            for idx in range(len(bucket) - 1, -1, -1):
                if provider is None or bucket[idx].get("provider") == provider:
                    match_idx = idx
                    break
            if match_idx is None:
                return None
            envelope = bucket.pop(match_idx)
            if not bucket:
                state["credential_envelopes"].pop(job_id, None)
            else:
                state["credential_envelopes"][job_id] = bucket
            self._save_local_state(state)
            return envelope

    # ------------------------------------------------------------------
    # 4. Short-Lived Interactive 2FA OTP Challenges
    # ------------------------------------------------------------------
    def create_otp_challenge(
        self,
        job_id: str,
        provider: str,
        prompt_message: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if provider not in ("icloud", "google_photos"):
            raise ValueError("provider must be 'icloud' or 'google_photos'")

        payload = {
            "job_id": job_id,
            "provider": provider,
            "prompt_message": prompt_message,
            "status": "WAITING_CUSTOMER",
            "expires_at": _utc_future_iso(max(30, min(int(ttl_seconds), 900))),
        }

        if self.online_mode:
            rows = self._request(
                "POST",
                "otp_challenges",
                json_body=payload,
                prefer="return=representation",
            )
            return rows[0] if isinstance(rows, list) and rows else payload

        with self._lock:
            state = self._load_local_state()
            rec = {
                "id": str(uuid.uuid4()),
                **payload,
                "encrypted_otp_envelope": None,
                "created_at": _utc_now_iso(),
            }
            state["otp_challenges"].setdefault(job_id, []).append(rec)
            self._save_local_state(state)
            return rec

    def submit_otp_local(
        self,
        job_id: str,
        challenge_id: str,
        encrypted_otp_envelope: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Attach an encrypted OTP envelope in offline mode (for tests/demos)."""
        with self._lock:
            state = self._load_local_state()
            for item in state["otp_challenges"].get(job_id, []):
                if item["id"] == challenge_id:
                    item["encrypted_otp_envelope"] = encrypted_otp_envelope
                    item["status"] = "SUBMITTED"
                    self._save_local_state(state)
                    return item
        return None

    def fetch_and_shred_otp(
        self,
        job_id: str,
        challenge_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch submitted OTP challenge for `job_id` and immediately DELETE it."""
        if self.online_mode:
            params: dict[str, str] = {
                "job_id": f"eq.{job_id}",
                "status": "eq.SUBMITTED",
                "order": "created_at.desc",
                "limit": "1",
            }
            if challenge_id:
                params["id"] = f"eq.{challenge_id}"
            rows = self._request("GET", "otp_challenges", params=params)
            if not isinstance(rows, list) or not rows:
                return None
            challenge = rows[0]
            self._request("DELETE", "otp_challenges", params={"id": f"eq.{challenge['id']}"})
            return challenge

        with self._lock:
            state = self._load_local_state()
            bucket = state["otp_challenges"].get(job_id, [])
            match_idx = None
            for idx in range(len(bucket) - 1, -1, -1):
                item = bucket[idx]
                if challenge_id and item.get("id") != challenge_id:
                    continue
                if item.get("status") == "SUBMITTED" and item.get("encrypted_otp_envelope"):
                    match_idx = idx
                    break
            if match_idx is None:
                return None
            challenge = bucket.pop(match_idx)
            if not bucket:
                state["otp_challenges"].pop(job_id, None)
            else:
                state["otp_challenges"][job_id] = bucket
            self._save_local_state(state)
            return challenge

    # ------------------------------------------------------------------
    # 5. Telemetry & Signed PDPA Purge Certificate Publishing
    # ------------------------------------------------------------------
    def push_telemetry_snapshot(
        self,
        job_id: str,
        snapshot: dict[str, Any],
        counters: dict[str, int] | None = None,
        status: str | None = None,
        year_progress_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        patch: dict[str, Any] = {"telemetry_snapshot": snapshot}
        if status:
            patch["status"] = status
        if counters:
            for field in (
                "total_files",
                "downloaded_files",
                "verified_sha256_files",
                "uploaded_files",
                "total_bytes",
                "reclaimed_bytes",
            ):
                if field in counters:
                    patch[field] = max(0, int(counters[field]))

        updated = self.update_job(job_id, patch)

        if year_progress_rows:
            if self.online_mode:
                rows_to_upsert = [{**row, "job_id": job_id} for row in year_progress_rows]
                self._request(
                    "POST",
                    "job_year_progress",
                    params={"on_conflict": "job_id,year"},
                    json_body=rows_to_upsert,
                    prefer="resolution=merge-duplicates,return=minimal",
                )
            else:
                with self._lock:
                    state = self._load_local_state()
                    y_bucket = state["job_year_progress"].setdefault(job_id, {})
                    for row in year_progress_rows:
                        y_bucket[str(row["year"])] = {**row, "job_id": job_id, "updated_at": _utc_now_iso()}
                    self._save_local_state(state)

        return updated

    def publish_pdpa_certificate(
        self,
        job_id: str,
        certificate: dict[str, Any],
    ) -> dict[str, Any] | None:
        patch = {
            "pdpa_purged_at": certificate.get("purged_at") or _utc_now_iso(),
            "pdpa_purge_certificate": certificate,
            "status": "COMPLETED",
        }
        return self.update_job(job_id, patch)

    # ------------------------------------------------------------------
    # 6. Zero-Knowledge Encrypted Search Vaults (`002_search_vault.sql`)
    # ------------------------------------------------------------------
    def create_search_vault(self, vault_record: dict[str, Any]) -> dict[str, Any]:
        now_iso = _utc_now_iso()
        record = dict(vault_record)
        record.setdefault("id", str(uuid.uuid4()))
        record.setdefault("status", "AWAITING_CUSTOMER_KEY")
        record.setdefault("storage_backend", "cloudflare_r2")
        record.setdefault("media_source_type", "google_photos_shared")
        record.setdefault("media_source_config", {})
        record.setdefault("created_at", now_iso)
        record["updated_at"] = now_iso

        if self.online_mode:
            rows = self._request(
                "POST",
                "search_vaults",
                json_body=record,
                prefer="return=representation",
            )
            if isinstance(rows, list) and rows:
                return rows[0]
            return record

        with self._lock:
            state = self._load_local_state()
            state.setdefault("search_vaults", {})[record["id"]] = record
            self._save_local_state(state)
            return record

    def get_search_vault(self, vault_id: str) -> dict[str, Any] | None:
        if self.online_mode:
            rows = self._request("GET", "search_vaults", params={"id": f"eq.{vault_id}", "limit": "1"})
            return rows[0] if isinstance(rows, list) and rows else None

        with self._lock:
            state = self._load_local_state()
            return state.get("search_vaults", {}).get(vault_id)

    def list_search_vaults(self) -> list[dict[str, Any]]:
        if self.online_mode:
            rows = self._request("GET", "search_vaults", params={"order": "created_at.desc"})
            return rows if isinstance(rows, list) else []

        with self._lock:
            state = self._load_local_state()
            items = list(state.get("search_vaults", {}).values())
            items.sort(key=lambda r: r.get("created_at", ""), reverse=True)
            return items

    def update_search_vault(self, vault_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        update_data = dict(patch)
        update_data["updated_at"] = _utc_now_iso()
        if self.online_mode:
            rows = self._request(
                "PATCH",
                "search_vaults",
                params={"id": f"eq.{vault_id}"},
                json_body=update_data,
                prefer="return=representation",
            )
            return rows[0] if isinstance(rows, list) and rows else None

        with self._lock:
            state = self._load_local_state()
            bucket = state.setdefault("search_vaults", {})
            existing = bucket.get(vault_id)
            if existing is None:
                return None
            existing.update(update_data)
            bucket[vault_id] = existing
            self._save_local_state(state)
            return existing
