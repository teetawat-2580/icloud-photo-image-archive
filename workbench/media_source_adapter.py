"""
CloudVault Concierge — Pluggable Media Source Adapter.

Decouples immutable AI search indices (keyed by `asset_sha256`, `original_filename`, `captured_at`)
from where the full-resolution media is currently hosted:
- Phase 1 (Family Shared Archive): `google_photos_shared` (links directly to Mom's 8 shared albums)
- Standard Concierge Customer: `google_photos_private` (`https://photos.google.com/photo/<id>`)
- Phase 2 (Future Home NAS / Immich): `nas_immich` (`https://<nas-domain>/photos/<asset_id>`)
- Offline Export Package: `local_hdd` (`2018/12/IMG_XXXX.JPG`)

Enables zero-reindex migration from Google Photos -> Home NAS/Immich simply by remapping
`asset_sha256 -> new_media_ref` without re-running InsightFace, RapidOCR, or Multilingual CLIP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

MediaSourceType = Literal[
    "google_photos_shared",
    "google_photos_private",
    "nas_immich",
    "local_hdd",
]

# Example multi-year album preset template (zero PII — load real customer/family album URLs
# strictly from gitignored `workbench/.local_state/media_albums.json` or runtime `media_source_config`).
EXAMPLE_SHARED_ALBUMS_TEMPLATE: dict[str, dict[str, Any]] = {
    "2005-2008": {
        "title": "Family_Archive_Google (2005-2008)",
        "years": [1970, 2005, 2006, 2007, 2008, 2017, 2018],
        "short_url": "https://photos.app.goo.gl/ExampleShared2005To2008",
        "item_count": 8674,
    },
    "2010": {
        "title": "Family_Archive_Google (2010)",
        "years": [2010],
        "short_url": "https://photos.app.goo.gl/ExampleShared2010",
        "item_count": 2478,
    },
    "2011": {
        "title": "Family_Archive_Google (2011)",
        "years": [2011],
        "short_url": "https://photos.app.goo.gl/ExampleShared2011",
        "item_count": 10123,
    },
    "2012": {
        "title": "Family_Archive_Google (2012)",
        "years": [2012],
        "short_url": "https://photos.app.goo.gl/ExampleShared2012",
        "item_count": 11421,
    },
    "2013-1": {
        "title": "Family_Archive_Google (2013 - Part 1)",
        "years": [2013],
        "short_url": "https://photos.app.goo.gl/ExampleShared2013Part1",
        "item_count": 19934,
    },
    "2013-2": {
        "title": "Family_Archive_Google (2013 - Part 2)",
        "years": [2013],
        "short_url": "https://photos.app.goo.gl/ExampleShared2013Part2",
        "item_count": 296,
    },
    "2014-2016": {
        "title": "Family_Archive_Google (2014-2016)",
        "years": [2014, 2015, 2016],
        "short_url": "https://photos.app.goo.gl/ExampleShared2014To2016",
        "item_count": 8848,
    },
    "2019": {
        "title": "Family_Archive_Google (2019)",
        "years": [2019],
        "short_url": "https://photos.app.goo.gl/ExampleShared2019",
        "item_count": 14766,
    },
}

ALLOWED_GOOGLE_HOSTS = frozenset({"photos.google.com", "photos.app.goo.gl"})


@dataclass(frozen=True)
class MediaSourceConfig:
    source_type: MediaSourceType = "google_photos_shared"
    albums: dict[str, dict[str, Any]] = field(default_factory=dict)
    nas_base_url: str = ""
    local_root_label: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "albums": self.albums,
            "nas_base_url": self.nas_base_url.rstrip("/"),
            "local_root_label": self.local_root_label,
        }


def validate_safe_https_url(url: str, *, allowed_hosts: frozenset[str] | None = None) -> str:
    """Strictly allow https:// URLs only (blocks javascript:, data:, file:, vbscript: XSS vectors)."""
    cleaned = str(url or "").strip()
    if not cleaned:
        raise ValueError("Media URL must not be empty")
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"Unsafe or non-HTTPS media URL rejected: {cleaned[:48]}")
    host = (parsed.hostname or "").lower()
    if allowed_hosts is not None and host not in allowed_hosts:
        raise ValueError(f"Media host '{host}' is not in allowlist")
    return cleaned


def _find_album_for_year(year: int | None, albums: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    if year is None:
        return None
    for key, info in albums.items():
        years = info.get("years") or []
        if year in years:
            return key, info
    return None


def resolve_asset_destination(asset_meta: dict[str, Any], config: MediaSourceConfig) -> dict[str, Any]:
    """
    Resolve an asset's clickable original-media destination reference using the active MediaSourceConfig.
    """
    direct_url = asset_meta.get("direct_url")
    if direct_url:
        if config.source_type in ("google_photos_shared", "google_photos_private"):
            safe_url = validate_safe_https_url(str(direct_url), allowed_hosts=ALLOWED_GOOGLE_HOSTS)
        else:
            safe_url = validate_safe_https_url(str(direct_url))
        return {
            "provider": config.source_type,
            "album_key": str(asset_meta.get("album_key") or ""),
            "album_title": str(asset_meta.get("album_title") or ""),
            "url": safe_url,
        }

    if config.source_type == "google_photos_shared":
        album_key = str(asset_meta.get("album_key") or "")
        album_info = config.albums.get(album_key) if album_key else None
        if album_info is None:
            matched = _find_album_for_year(asset_meta.get("year"), config.albums)
            if matched:
                album_key, album_info = matched
        if album_info and album_info.get("short_url"):
            safe_url = validate_safe_https_url(str(album_info["short_url"]), allowed_hosts=ALLOWED_GOOGLE_HOSTS)
            return {
                "provider": "google_photos_shared",
                "album_key": album_key,
                "album_title": str(album_info.get("title") or album_key),
                "url": safe_url,
            }
        return {
            "provider": "google_photos_shared",
            "album_key": album_key,
            "album_title": "",
            "url": "https://photos.google.com/albums",
        }

    if config.source_type == "google_photos_private":
        photo_id = str(asset_meta.get("gphotos_photo_id") or "").strip()
        if photo_id:
            url = validate_safe_https_url(f"https://photos.google.com/photo/{photo_id}", allowed_hosts=ALLOWED_GOOGLE_HOSTS)
        else:
            url = "https://photos.google.com/"
        return {
            "provider": "google_photos_private",
            "photo_id": photo_id,
            "url": url,
        }

    if config.source_type == "nas_immich":
        base = validate_safe_https_url(config.nas_base_url).rstrip("/")
        asset_id = str(asset_meta.get("asset_id") or "").strip()
        rel_path = str(asset_meta.get("relative_path") or asset_meta.get("filename") or "").strip()
        url = f"{base}/photos/{asset_id}" if asset_id else base
        return {
            "provider": "nas_immich",
            "asset_id": asset_id,
            "relative_path": rel_path,
            "url": url,
        }

    # local_hdd
    rel_path = str(asset_meta.get("relative_path") or asset_meta.get("filename") or "").strip()
    return {
        "provider": "local_hdd",
        "local_root_label": config.local_root_label,
        "relative_path": rel_path,
        "url": "",
    }


def remap_index_media_source(
    index_dict: dict[str, Any],
    new_source_config: MediaSourceConfig,
    sha256_to_new_ref: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Zero-Reindex Migration Utility:
    Switches an existing decrypted search index from one storage backend (e.g. `google_photos_shared`)
    to another (e.g. `nas_immich` or `local_hdd`) by matching `asset_sha256`, preserving 100% of
    previously computed InsightFace clusters, Thai/English OCR text, and semantic tags.
    """
    mapping = sha256_to_new_ref or {}
    remapped_assets: list[dict[str, Any]] = []
    for asset in index_dict.get("assets", []):
        sha = str(asset.get("sha256") or "")
        override = mapping.get(sha, {})
        merged_meta = {
            "sha256": sha,
            "year": asset.get("year"),
            "filename": asset.get("filename"),
            **override,
        }
        new_asset = dict(asset)
        new_asset["media_ref"] = resolve_asset_destination(merged_meta, new_source_config)
        remapped_assets.append(new_asset)

    updated = dict(index_dict)
    updated["media_source_type"] = new_source_config.source_type
    updated["media_source_config"] = new_source_config.to_public_dict()
    updated["assets"] = remapped_assets
    return updated
