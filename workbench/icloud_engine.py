"""
CloudVault Concierge — Multi-Tenant iCloud Photo Archive Engine & 5-Lock Safety Gate.

Generalized from proven high-throughput iCloud archival patterns with ZERO hardcoded
emails, paths, or account identifiers. Every job operates strictly inside its assigned
sandbox (`staging_dir`, `icloud_session_dir`, `logs_dir`).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from workbench.audit_report import generate_standalone_audit_html

try:
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    HTTPAdapter = None  # type: ignore[assignment]

try:
    from pyicloud import PyiCloudService
    from pyicloud.base import PyiCloudSession
    from pyicloud.services.photos.service import BasePhotoLibrary, DirectionEnum

    # Bypass strict CheckIndexingState == FINISHED check for large (100k+ item) libraries
    BasePhotoLibrary._ensure_indexing_ready = lambda self: setattr(self, "_indexing_state", "FINISHED")

    _SESSION_SAVE_LOCK = threading.Lock()
    _ORIG_SAVE_SESSION_DATA = PyiCloudSession._save_session_data

    def _threadsafe_save_session_data(self: Any) -> None:
        with _SESSION_SAVE_LOCK:
            try:
                _ORIG_SAVE_SESSION_DATA(self)
            except OSError:
                pass

    PyiCloudSession._save_session_data = _threadsafe_save_session_data
except ImportError:  # pragma: no cover
    PyiCloudService = None  # type: ignore[assignment]
    DirectionEnum = None  # type: ignore[assignment]


THAI_MONTHS: dict[int, str] = {
    1: "01 - มกราคม",
    2: "02 - กุมภาพันธ์",
    3: "03 - มีนาคม",
    4: "04 - เมษายน",
    5: "05 - พฤษภาคม",
    6: "06 - มิถุนายน",
    7: "07 - กรกฎาคม",
    8: "08 - สิงหาคม",
    9: "09 - กันยายน",
    10: "10 - ตุลาคม",
    11: "11 - พฤศจิกายน",
    12: "12 - ธันวาคม",
}

_WIN_FORBIDDEN_TRANS = str.maketrans({ch: "-" for ch in '<>:"/\\|?*'})
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_VIDEO_EXTS = frozenset({".mov", ".mp4", ".m4v", ".3gp", ".avi"})


def normalize_year(year: int) -> int:
    """Convert accidental Buddhist Era EXIF years (e.g. 2563) to Gregorian AD (2020)."""
    y = int(year)
    if y > 2400:
        return y - 543
    return y


def get_year_folder_name(year: int) -> str:
    """Format canonical bilingual year folder: `YYYY (พ.ศ. YYYY+543)`."""
    y_ad = normalize_year(year)
    if y_ad <= 1970:
        return "0000 - ไม่ระบุวันที่ (No Date)"
    return f"{y_ad} (พ.ศ. {y_ad + 543})"


def get_month_folder_name(month: int) -> str:
    """Format canonical Thai month folder: `01 - มกราคม` .. `12 - ธันวาคม`."""
    m = int(month)
    return THAI_MONTHS.get(m, f"{m:02d}")


def sanitize_windows_filename(name: str) -> str:
    """
    Replace Windows NTFS forbidden filename characters (`<>:"/\\|?*`) with `-`
    (e.g. `2563-02-19 16:31:09.mp4` -> `2563-02-19 16-31-09.mp4`),
    while preserving standard filenames (`IMG_1234.JPG`) 100% intact.
    Callers MUST retain the original unmodified `original_filename` in manifest metadata.
    """
    if not name or not str(name).strip():
        return "unnamed"
    # Strip any control characters and translate NTFS-forbidden symbols to hyphen
    raw = "".join(ch if ord(ch) >= 32 else "-" for ch in str(name))
    cleaned = raw.translate(_WIN_FORBIDDEN_TRANS).strip().rstrip(".")
    # Neutralize dot-only segments
    if not cleaned or cleaned in (".", ".."):
        return "unnamed"
    return cleaned


def compute_sha256(file_path: str | Path) -> str:
    """Stream-compute 64-character lowercase SHA-256 hex digest (1 MiB chunks)."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def safe_target_path(
    folder_path: str | Path,
    original_filename: str,
    expected_size: int | None = None,
) -> tuple[str, bool]:
    """
    Allocate a safe Windows target path inside `folder_path` using `sanitize_windows_filename`.
    Returns `(final_path, already_exists_and_matches)`.
    """
    dest_dir = Path(folder_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_windows_filename(original_filename)
    candidate = dest_dir / safe_name

    if not candidate.exists():
        return str(candidate), False
    if expected_size is not None and expected_size > 0 and candidate.stat().st_size == expected_size:
        return str(candidate), True

    stem = candidate.stem
    ext = candidate.suffix
    idx = 2
    while True:
        alt = dest_dir / f"{stem} ({idx}){ext}"
        if not alt.exists():
            return str(alt), False
        if expected_size is not None and expected_size > 0 and alt.stat().st_size == expected_size:
            return str(alt), True
        idx += 1


def binary_search_year_bounds(
    total: int,
    target_year: int,
    get_year_at: Callable[[int], int],
    margin: int = 30,
) -> tuple[int, int]:
    """
    O(log N) CloudKit rank window discovery for `target_year` in a descending stream
    where rank `0` is newest and rank `total - 1` is oldest.

    Returns `(start_rank, end_rank)` inclusive (expanded by `margin` and clamped to `[0, total - 1]`),
    or `(0, -1)` if `total <= 0` or `target_year` is not present.
    """
    if total <= 0:
        return (0, -1)

    target = normalize_year(target_year)

    # 1. First rank where year <= target
    lo, hi = 0, total - 1
    first_le = total
    while lo <= hi:
        mid = (lo + hi) // 2
        yr = normalize_year(get_year_at(mid))
        if yr <= target:
            first_le = mid
            hi = mid - 1
        else:
            lo = mid + 1

    if first_le >= total:
        return (0, -1)

    # 2. First rank >= first_le where year < target (strictly older)
    lo, hi = first_le, total - 1
    first_older = total
    while lo <= hi:
        mid = (lo + hi) // 2
        yr = normalize_year(get_year_at(mid))
        if yr < target:
            first_older = mid
            hi = mid - 1
        else:
            lo = mid + 1

    if first_older <= first_le:
        return (0, -1)

    safe_margin = max(0, int(margin))
    start_rank = max(0, first_le - safe_margin)
    end_rank = min(total - 1, (first_older - 1) + safe_margin)
    return (start_rank, end_rank)


def _collect_year_files(manifest_data: dict[str, Any], target_year: int) -> tuple[str, list[dict[str, Any]]]:
    yr_ad = normalize_year(target_year)
    yr_folder = get_year_folder_name(yr_ad)
    years_map = manifest_data.get("years", {}) if isinstance(manifest_data, dict) else {}
    ydata = years_map.get(yr_folder) or years_map.get(str(yr_ad))
    if not isinstance(ydata, dict):
        return yr_folder, []

    files: list[dict[str, Any]] = []
    months = ydata.get("months", {})
    if isinstance(months, dict):
        for mn_key in sorted(months.keys()):
            minfo = months[mn_key]
            if isinstance(minfo, dict) and isinstance(minfo.get("files"), list):
                files.extend(minfo["files"])
    return yr_folder, files


def verify_five_locks(
    manifest_data: dict[str, Any],
    target_year: int,
    customer_approved_at: str | None,
) -> dict[str, Any]:
    """
    Fail-Closed 5-Lock Safety Gate. ALL 5 locks MUST pass before soft-delete (`asset.delete()`):
      Lock 1: 100% of files have `gphotos_uploaded == True`
      Lock 2: 100% of files have `local_verified == True` AND valid 64-char hex `sha256`
      Lock 3: 100% of files have unique non-empty CloudKit `id` AND non-empty `original_filename`
      Lock 4: `len(files) >= year_catalog_counts[year] > 0`
      Lock 5: `customer_approved_at` is a non-empty timestamp string (explicit customer consent)
    """
    yr_ad = normalize_year(target_year)
    yr_folder, files = _collect_year_files(manifest_data, yr_ad)
    total_files = len(files)

    catalog_counts = manifest_data.get("year_catalog_counts", {}) if isinstance(manifest_data, dict) else {}
    raw_expected = catalog_counts.get(str(yr_ad), catalog_counts.get(yr_ad, 0))
    try:
        expected_catalog = int(raw_expected) if raw_expected is not None else 0
    except (TypeError, ValueError):
        expected_catalog = 0

    blocking_reasons: list[str] = []

    # Lock 1: Google Photos uploaded 100%
    lock1_ok_cnt = sum(1 for item in files if item.get("gphotos_uploaded") is True)
    lock1_passed = total_files > 0 and lock1_ok_cnt == total_files
    lock1_reason = (
        f"Uploaded {lock1_ok_cnt}/{total_files} files to Google Photos."
        if lock1_passed
        else f"Lock 1 blocked: only {lock1_ok_cnt}/{total_files} files confirmed uploaded to Google Photos."
    )
    if not lock1_passed:
        blocking_reasons.append(lock1_reason)

    # Lock 2: Local verified & 64-char hex SHA-256
    lock2_ok_cnt = sum(
        1
        for item in files
        if item.get("local_verified") is True
        and isinstance(item.get("sha256"), str)
        and bool(_SHA256_HEX_RE.fullmatch(item["sha256"]))
    )
    lock2_passed = total_files > 0 and lock2_ok_cnt == total_files
    lock2_reason = (
        f"Verified {lock2_ok_cnt}/{total_files} files with 64-char SHA-256 checksums."
        if lock2_passed
        else f"Lock 2 blocked: only {lock2_ok_cnt}/{total_files} files have local_verified=True & valid 64-char SHA-256."
    )
    if not lock2_passed:
        blocking_reasons.append(lock2_reason)

    # Lock 3: 1:1 unique CloudKit Record ID & original_filename
    seen_ids: set[str] = set()
    duplicate_ids = 0
    lock3_ok_cnt = 0
    for item in files:
        rec_id = item.get("id")
        orig_name = item.get("original_filename")
        if isinstance(rec_id, str) and rec_id.strip() and isinstance(orig_name, str) and orig_name.strip():
            if rec_id in seen_ids:
                duplicate_ids += 1
            else:
                seen_ids.add(rec_id)
                lock3_ok_cnt += 1
    lock3_passed = total_files > 0 and lock3_ok_cnt == total_files and duplicate_ids == 0
    lock3_reason = (
        f"Matched 1:1 unique CloudKit id & original_filename for {lock3_ok_cnt}/{total_files} files."
        if lock3_passed
        else (
            f"Lock 3 blocked: 1:1 identity check matched {lock3_ok_cnt}/{total_files} files "
            f"(duplicates={duplicate_ids})."
        )
    )
    if not lock3_passed:
        blocking_reasons.append(lock3_reason)

    # Lock 4: Whole-year catalog completeness
    lock4_passed = expected_catalog > 0 and total_files >= expected_catalog
    lock4_reason = (
        f"Catalog completeness verified ({total_files} >= {expected_catalog})."
        if lock4_passed
        else f"Lock 4 blocked: manifest has {total_files} files vs expected iCloud catalog count {expected_catalog}."
    )
    if not lock4_passed:
        blocking_reasons.append(lock4_reason)

    # Lock 5: Explicit customer approval timestamp
    approved_str = customer_approved_at.strip() if isinstance(customer_approved_at, str) else ""
    lock5_passed = bool(approved_str)
    lock5_reason = (
        f"Customer approved 5-Lock cleanup at {approved_str}."
        if lock5_passed
        else "Lock 5 blocked: awaiting explicit customer approval timestamp (customer_approved_at is missing)."
    )
    if not lock5_passed:
        blocking_reasons.append(lock5_reason)

    all_passed = lock1_passed and lock2_passed and lock3_passed and lock4_passed and lock5_passed
    return {
        "passed": all_passed,
        "can_soft_delete": all_passed,
        "target_year": yr_ad,
        "year_folder": yr_folder,
        "total_files": total_files,
        "expected_catalog_count": expected_catalog,
        "customer_approved_at": approved_str or None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "locks": {
            "lock_1_gphotos_uploaded": {
                "passed": lock1_passed,
                "verified": lock1_ok_cnt,
                "total": total_files,
                "reason": lock1_reason,
            },
            "lock_2_local_sha256": {
                "passed": lock2_passed,
                "verified": lock2_ok_cnt,
                "total": total_files,
                "reason": lock2_reason,
            },
            "lock_3_identity_1to1": {
                "passed": lock3_passed,
                "verified": lock3_ok_cnt,
                "total": total_files,
                "duplicate_ids": duplicate_ids,
                "reason": lock3_reason,
            },
            "lock_4_catalog_completeness": {
                "passed": lock4_passed,
                "actual": total_files,
                "expected": expected_catalog,
                "reason": lock4_reason,
            },
            "lock_5_customer_approval": {
                "passed": lock5_passed,
                "approved_at": approved_str or None,
                "reason": lock5_reason,
            },
        },
        "blocking_reasons": blocking_reasons,
    }


class ICloudJobEngine:
    """Per-job isolated multi-tenant iCloud Photos service wrapper."""

    def __init__(
        self,
        job_id: str,
        staging_dir: Path | str,
        icloud_session_dir: Path | str,
        logs_dir: Path | str,
    ):
        self.job_id = job_id
        self.staging_dir = Path(staging_dir).resolve()
        self.icloud_session_dir = Path(icloud_session_dir).resolve()
        self.logs_dir = Path(logs_dir).resolve()
        self.manifest_path = self.logs_dir / "archive_manifest.json"
        self.deleted_ledger_path = self.logs_dir / "deleted_audit_ledger.json"
        self._api: Any = None
        self._lock = threading.RLock()

    def connect(self, apple_id: str, password: str | None = None) -> dict[str, Any]:
        """Connect to a customer's iCloud account using strictly isolated job cookies."""
        if PyiCloudService is None:
            raise RuntimeError("pyicloud package is not installed in this Python environment")
        self.icloud_session_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            api = PyiCloudService(
                apple_id,
                password,
                cookie_directory=str(self.icloud_session_dir),
            )
            if HTTPAdapter is not None and hasattr(api, "session") and api.session is not None:
                adapter = HTTPAdapter(pool_connections=24, pool_maxsize=24)
                api.session.mount("https://", adapter)
                api.session.mount("http://", adapter)
            self._api = api
            return {
                "job_id": self.job_id,
                "requires_2fa": bool(getattr(api, "requires_2fa", False)),
                "requires_2sa": bool(getattr(api, "requires_2sa", False)),
                "authenticated": not bool(getattr(api, "requires_2fa", False) or getattr(api, "requires_2sa", False)),
            }

    def submit_2fa_code(self, code: str) -> bool:
        """Submit a 6-digit Apple 2FA OTP code and trust the isolated session."""
        cleaned = re.sub(r"\D+", "", str(code or ""))
        if len(cleaned) != 6:
            raise ValueError("Apple 2FA code must be exactly 6 digits")
        with self._lock:
            if self._api is None:
                raise RuntimeError("No active iCloud session for this job")
            valid = bool(self._api.validate_2fa_code(cleaned))
            if valid and hasattr(self._api, "trust_session"):
                try:
                    self._api.trust_session()
                except Exception:
                    pass
            return valid

    def load_manifest(self) -> dict[str, Any]:
        if self.manifest_path.exists():
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return {"job_id": self.job_id, "year_catalog_counts": {}, "years": {}}

    def save_manifest(self, manifest_data: dict[str, Any]) -> Path:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(manifest_data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.manifest_path)
        return self.manifest_path

    def discover_year_bounds(self, target_year: int, margin: int = 30) -> tuple[int, int]:
        """Discover CloudKit rank window for `target_year` using O(log N) binary search."""
        if self._api is None or DirectionEnum is None:
            raise RuntimeError("iCloud session is not connected")
        all_album = self._api.photos.all
        total = len(all_album)

        def get_year_at(rank: int) -> int:
            items = list(all_album._get_photos_at(rank, DirectionEnum.ASCENDING, 1))
            if not items:
                return 0
            dt = items[0].asset_date or items[0].created
            return normalize_year(dt.year) if dt else 0

        return binary_search_year_bounds(total, target_year, get_year_at, margin=margin)

    @staticmethod
    def verify_five_locks(
        manifest_data: dict[str, Any],
        target_year: int,
        customer_approved_at: str | None,
    ) -> dict[str, Any]:
        return verify_five_locks(manifest_data, target_year, customer_approved_at)

    def soft_delete_verified_year(
        self,
        manifest_data: dict[str, Any],
        target_year: int,
        customer_approved_at: str | None,
        assets_by_id: dict[str, Any] | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Soft-delete verified iCloud assets for `target_year` (moves to Recently Deleted 30 days).
        STRICT FAIL-CLOSED: refuses execution unless ALL 5 locks pass!
        """
        gate = verify_five_locks(manifest_data, target_year, customer_approved_at)
        if not gate["passed"]:
            raise PermissionError(
                f"5-Lock Safety Gate blocked soft-delete for year {target_year}: "
                + "; ".join(gate["blocking_reasons"])
            )

        _, files = _collect_year_files(manifest_data, target_year)
        deleted_ids: list[str] = []
        if not dry_run:
            if not assets_by_id:
                raise RuntimeError("assets_by_id map is required when dry_run=False")
            for item in files:
                rec_id = item["id"]
                asset = assets_by_id.get(rec_id)
                if asset is not None and asset.delete():
                    deleted_ids.append(rec_id)
            ledger = {
                "job_id": self.job_id,
                "target_year": normalize_year(target_year),
                "soft_deleted_at": datetime.now(timezone.utc).isoformat(),
                "deleted_ids": deleted_ids,
            }
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            self.deleted_ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8")

        return {
            "gate": gate,
            "dry_run": dry_run,
            "soft_deleted_count": len(deleted_ids),
            "deleted_ids": deleted_ids,
        }

    def generate_standalone_audit_html(
        self,
        job_meta: dict[str, Any],
        manifest_data: dict[str, Any],
        output_path: str | Path | None = None,
    ) -> Path:
        target = Path(output_path) if output_path is not None else (self.logs_dir / f"audit_report_{self.job_id}.html")
        return generate_standalone_audit_html(job_meta, manifest_data, target)
