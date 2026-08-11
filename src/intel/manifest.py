"""Manifest of intel catalog freshness and counts.

I record last success/error and on-disk paths so the GUI Intel panel can show
whether NVD, MITRE, and CTI packs are ready, stale, or missing.
"""


from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.config import PathConfig
from src.workspace import intel_dir


def now_iso() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


def manifest_path(paths: PathConfig) -> Path:
    return intel_dir(paths) / "manifest.json"


def _default_manifest() -> dict[str, Any]:
    return {
        "nvd": {
            "status": "missing",
            "backend": "sqlite",
            "path": None,
            "cve_count": 0,
            "last_success_at": None,
            "last_error": None,
            "source": None,
        },
        "mitre": {
            "status": "missing",
            "path": None,
            "technique_count": 0,
            "attack_version": None,
            "last_success_at": None,
            "last_error": None,
            "source": None,
        },
        "cti": {
            "status": "missing",
            "pack_count": 0,
            "last_success_at": None,
            "last_error": None,
            "source": None,
        },
    }


def load_manifest(paths: PathConfig) -> dict[str, Any]:
    path = manifest_path(paths)
    if not path.is_file():
        return _default_manifest()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_manifest()
    if not isinstance(payload, dict):
        return _default_manifest()
    base = _default_manifest()
    for key in base:
        if isinstance(payload.get(key), dict):
            base[key].update(payload[key])
    return base


def save_manifest(paths: PathConfig, manifest: dict[str, Any]) -> Path:
    path = manifest_path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def patch_catalog(
    paths: PathConfig,
    catalog: str,
    **fields: Any,
) -> dict[str, Any]:
    manifest = load_manifest(paths)
    if catalog not in manifest:
        raise ValueError(f"Unknown intel catalog: {catalog}")
    manifest[catalog].update(fields)
    save_manifest(paths, manifest)
    return manifest


def intel_status(paths: PathConfig) -> dict[str, Any]:
    """Fresh status with live counts from on-disk stores when present."""
    from src.intel import cti, mitre, nvd

    manifest = load_manifest(paths)
    nvd_path = nvd.default_cve_db_path(paths)
    if nvd_path.is_file():
        count = nvd.cve_count(nvd_path)
        manifest["nvd"]["path"] = str(nvd_path)
        manifest["nvd"]["cve_count"] = count
        if count and manifest["nvd"].get("status") == "missing":
            manifest["nvd"]["status"] = "ready"
    mitre_path = mitre.techniques_path(paths)
    if mitre_path.is_file():
        count = mitre.technique_count(paths)
        manifest["mitre"]["path"] = str(mitre_path)
        manifest["mitre"]["technique_count"] = count
        if count and manifest["mitre"].get("status") == "missing":
            manifest["mitre"]["status"] = "ready"
    packs = cti.list_cti_packs(paths)
    manifest["cti"]["pack_count"] = len(packs)
    if packs and manifest["cti"].get("status") == "missing":
        manifest["cti"]["status"] = "ready"
    return {
        "intel_dir": str(intel_dir(paths)),
        "catalogs": manifest,
    }
