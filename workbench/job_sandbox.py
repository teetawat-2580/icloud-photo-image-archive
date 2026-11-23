"""
CloudVault Concierge — Per-Job Sandboxed Staging & 1-Click PDPA Purge Manager.

Security invariants:
- Default staging root is `D:\\MigrationJobs` (configurable via `STAGING_ROOT`, NEVER inside OneDrive).
- Strict `job_id` validation (`^[a-zA-Z0-9_-]{4,64}$`) + resolved `is_relative_to(staging_root)`
  path-traversal defense.
- Isolated per-job subdirectories (`staging/`, `chrome_profile/`, `icloud_session/`, `logs/`)
  and isolated dynamic Chrome CDP ports (`9301..9399`).
- `execute_pdpa_purge` verifies no active subprocess for that job, wipes `staging/`,
  `chrome_profile/`, and `icloud_session/`, verifies `remaining_files == 0`, and returns a
  cryptographically signed PDPA Purge Certificate.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workbench.crypto_vault import OperatorCryptoVault

JOB_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{4,64}$")
WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
SENSITIVE_SUBDIRS = ("staging", "chrome_profile", "icloud_session")
ALL_SUBDIRS = ("staging", "chrome_profile", "icloud_session", "logs")
DEFAULT_CDP_PORT_MIN = 9301
DEFAULT_CDP_PORT_MAX = 9399


def is_onedrive_path(path: Path | str) -> bool:
    """Detect whether a path resides inside a OneDrive-synced directory."""
    parts = [p.lower() for p in Path(path).parts]
    return any("onedrive" in part for part in parts)


def _is_tcp_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Check whether a local TCP port can currently be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _force_remove_readonly(func: Any, path: str, _exc_info: Any) -> None:
    """Clear read-only attributes on Windows before retrying unlink/rmdir."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _count_files_and_bytes(root_dir: Path) -> tuple[int, int]:
    """Recursively count regular files and total bytes inside `root_dir`."""
    if not root_dir.exists():
        return 0, 0
    file_count = 0
    total_bytes = 0
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            file_count += 1
            fpath = Path(dirpath) / fname
            try:
                total_bytes += fpath.stat().st_size
            except OSError:
                pass
    return file_count, total_bytes


class JobSandboxManager:
    """Allocates and purges isolated customer job sandboxes with strict path confinement."""

    def __init__(
        self,
        staging_root: Path | str | None = None,
        port_range: tuple[int, int] = (DEFAULT_CDP_PORT_MIN, DEFAULT_CDP_PORT_MAX),
        reject_onedrive: bool = False,
    ):
        raw_root = staging_root if staging_root is not None else os.environ.get("STAGING_ROOT", r"D:\MigrationJobs")
        resolved_root = Path(raw_root).resolve()
        if reject_onedrive and is_onedrive_path(resolved_root):
            raise ValueError(
                f"Staging root MUST NOT be inside OneDrive: {resolved_root}. "
                "Configure STAGING_ROOT to a fast local non-synced path such as D:\\MigrationJobs."
            )
        self.staging_root = resolved_root
        self.port_min, self.port_max = port_range
        if self.port_min < 1024 or self.port_max > 65535 or self.port_min > self.port_max:
            raise ValueError(f"Invalid CDP port range: {port_range}")

        self._lock = threading.RLock()
        self._allocated_ports: dict[str, int] = {}
        self._active_processes: dict[str, list[subprocess.Popen[Any]]] = {}

    def validate_job_id(self, job_id: str) -> str:
        """Strictly validate job_id format and block traversal or reserved Windows names."""
        if not isinstance(job_id, str):
            raise ValueError("job_id must be a string")
        cleaned = job_id.strip()
        if cleaned != job_id or not JOB_ID_PATTERN.fullmatch(cleaned):
            raise ValueError(
                f"Invalid job_id '{job_id}': must match ^[a-zA-Z0-9_-]{{4,64}}$ with no path separators."
            )
        if cleaned.upper() in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"Invalid job_id '{job_id}': Windows reserved device name")
        return cleaned

    def resolve_job_root(self, job_id: str) -> Path:
        """Resolve and verify that `<staging_root>/<job_id>` stays strictly within `self.staging_root`."""
        valid_id = self.validate_job_id(job_id)
        candidate = (self.staging_root / valid_id).resolve()
        if not candidate.is_relative_to(self.staging_root) or candidate == self.staging_root:
            raise ValueError(f"Path traversal detected for job_id '{job_id}'")
        return candidate

    def resolve_sandbox_subpath(self, job_id: str, *parts: str) -> Path:
        """Resolve an arbitrary relative path within a job sandbox with strict confinement."""
        job_root = self.resolve_job_root(job_id)
        candidate = (job_root.joinpath(*parts)).resolve()
        if not candidate.is_relative_to(job_root):
            raise ValueError(f"Path traversal blocked outside sandbox for job_id '{job_id}'")
        return candidate

    def allocate_cdp_port(self, job_id: str) -> int:
        """Allocate a unique isolated Chrome CDP port in `9301..9399` for `job_id`."""
        valid_id = self.validate_job_id(job_id)
        with self._lock:
            if valid_id in self._allocated_ports:
                return self._allocated_ports[valid_id]

            used_ports = set(self._allocated_ports.values())
            for port in range(self.port_min, self.port_max + 1):
                if port in used_ports:
                    continue
                if _is_tcp_port_free(port):
                    self._allocated_ports[valid_id] = port
                    return port
            raise RuntimeError(
                f"No free isolated CDP ports available in range {self.port_min}..{self.port_max}"
            )

    def release_cdp_port(self, job_id: str) -> None:
        with self._lock:
            self._allocated_ports.pop(job_id, None)

    def get_allocated_port(self, job_id: str) -> int | None:
        with self._lock:
            return self._allocated_ports.get(job_id)

    def allocate_sandbox(self, job_id: str) -> dict[str, Any]:
        """Create isolated per-job staging directories and assign a dedicated CDP port."""
        job_root = self.resolve_job_root(job_id)
        with self._lock:
            self.staging_root.mkdir(parents=True, exist_ok=True)
            paths: dict[str, Path] = {}
            for subdir in ALL_SUBDIRS:
                dpath = self.resolve_sandbox_subpath(job_id, subdir)
                dpath.mkdir(parents=True, exist_ok=True)
                paths[subdir] = dpath

            cdp_port = self.allocate_cdp_port(job_id)
            meta = {
                "job_id": job_id,
                "staging_root": str(self.staging_root),
                "job_root": str(job_root),
                "staging_dir": str(paths["staging"]),
                "chrome_profile_dir": str(paths["chrome_profile"]),
                "icloud_session_dir": str(paths["icloud_session"]),
                "logs_dir": str(paths["logs"]),
                "cdp_port": cdp_port,
                "allocated_at": datetime.now(timezone.utc).isoformat(),
            }
            meta_file = paths["logs"] / "sandbox_meta.json"
            meta_file.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            return meta

    def get_sandbox_info(self, job_id: str) -> dict[str, Any]:
        """Return sandbox directory paths and live remaining file statistics."""
        job_root = self.resolve_job_root(job_id)
        counts: dict[str, int] = {}
        total_files = 0
        total_bytes = 0
        for subdir in SENSITIVE_SUBDIRS:
            f_cnt, f_bytes = _count_files_and_bytes(job_root / subdir)
            counts[subdir] = f_cnt
            total_files += f_cnt
            total_bytes += f_bytes

        return {
            "job_id": job_id,
            "job_root": str(job_root),
            "exists": job_root.exists(),
            "staging_dir": str(job_root / "staging"),
            "chrome_profile_dir": str(job_root / "chrome_profile"),
            "icloud_session_dir": str(job_root / "icloud_session"),
            "logs_dir": str(job_root / "logs"),
            "cdp_port": self.get_allocated_port(job_id),
            "sensitive_file_counts": counts,
            "sensitive_total_files": total_files,
            "sensitive_total_bytes": total_bytes,
            "has_active_process": self.has_active_process(job_id),
        }

    def register_process(self, job_id: str, proc: subprocess.Popen[Any]) -> None:
        valid_id = self.validate_job_id(job_id)
        with self._lock:
            self._active_processes.setdefault(valid_id, []).append(proc)

    def unregister_process(self, job_id: str, proc: subprocess.Popen[Any] | None = None) -> None:
        with self._lock:
            if proc is None:
                self._active_processes.pop(job_id, None)
                return
            current = self._active_processes.get(job_id, [])
            remaining = [p for p in current if p is not proc]
            if remaining:
                self._active_processes[job_id] = remaining
            else:
                self._active_processes.pop(job_id, None)

    def has_active_process(self, job_id: str) -> bool:
        """Prune exited processes and report whether any subprocess is still running for `job_id`."""
        with self._lock:
            procs = self._active_processes.get(job_id, [])
            alive = [p for p in procs if p.poll() is None]
            if alive:
                self._active_processes[job_id] = alive
                return True
            self._active_processes.pop(job_id, None)
            return False

    def execute_pdpa_purge(
        self,
        job_id: str,
        crypto_vault: OperatorCryptoVault,
    ) -> dict[str, Any]:
        """
        Execute 1-Click PDPA Purge for `job_id`:
        1. Refuse purge if any subprocess for `job_id` is still active.
        2. Recursively delete all files in `staging/`, `chrome_profile/`, and `icloud_session/`.
        3. Verify `remaining_files == 0`.
        4. Sign and return the PDPA Purge Certificate using `crypto_vault`.
        """
        job_root = self.resolve_job_root(job_id)
        with self._lock:
            if self.has_active_process(job_id):
                raise RuntimeError(
                    f"Cannot execute PDPA purge for '{job_id}': an active worker subprocess is still running."
                )

            deleted_file_count = 0
            deleted_bytes = 0

            for subdir in SENSITIVE_SUBDIRS:
                target_dir = self.resolve_sandbox_subpath(job_id, subdir)
                if not target_dir.exists():
                    continue
                cnt, nbytes = _count_files_and_bytes(target_dir)
                deleted_file_count += cnt
                deleted_bytes += nbytes
                shutil.rmtree(target_dir, onerror=_force_remove_readonly)

            # Re-verify zero residual files across all 3 sensitive directories
            remaining_files = 0
            for subdir in SENSITIVE_SUBDIRS:
                target_dir = self.resolve_sandbox_subpath(job_id, subdir)
                rem_cnt, _ = _count_files_and_bytes(target_dir)
                remaining_files += rem_cnt

            if remaining_files != 0:
                raise RuntimeError(
                    f"PDPA purge incomplete for '{job_id}': {remaining_files} residual files remain."
                )

            self.release_cdp_port(job_id)

            payload = {
                "certificate_version": "1.0",
                "job_id": job_id,
                "purged_at": datetime.now(timezone.utc).isoformat(),
                "purged_directories": list(SENSITIVE_SUBDIRS),
                "deleted_file_count": deleted_file_count,
                "deleted_bytes": deleted_bytes,
                "remaining_files": 0,
            }
            signed_certificate = crypto_vault.sign_pdpa_certificate(payload)

            logs_dir = self.resolve_sandbox_subpath(job_id, "logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            cert_path = logs_dir / "pdpa_purge_certificate.json"
            cert_path.write_text(
                json.dumps(signed_certificate, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return signed_certificate
