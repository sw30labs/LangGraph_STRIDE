"""Local MITRE ATT&CK technique catalog.

I normalize enterprise-attack STIX (or a pre-normalized techniques list) into
a small JSON file. The chain editor and search endpoints read that file. Online
download is opt-in and never runs inside unit tests.
"""


from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from src.config import PathConfig
from src.intel.manifest import now_iso, patch_catalog
from src.workspace import intel_dir

# Official MITRE CTI enterprise-attack STIX bundle (operator-triggered only).
MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


def techniques_path(paths: PathConfig) -> Path:
    return intel_dir(paths) / "mitre" / "techniques.json"


def technique_count(paths: PathConfig) -> int:
    path = techniques_path(paths)
    if not path.is_file():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if isinstance(payload, dict) and isinstance(payload.get("techniques"), list):
        return len(payload["techniques"])
    if isinstance(payload, list):
        return len(payload)
    return 0


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id")
            if eid:
                return str(eid)
    return None


def _tactic_names(obj: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        if isinstance(phase, dict) and phase.get("phase_name"):
            names.append(str(phase["phase_name"]))
    return names


def normalize_stix_bundle(payload: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Normalize MITRE STIX bundle or pre-normalized techniques list."""
    objects: list[Any]
    version = None
    if isinstance(payload, dict):
        objects = payload.get("objects") if isinstance(payload.get("objects"), list) else []
        version = payload.get("spec_version") or payload.get("attack_version")
        if isinstance(payload.get("techniques"), list):
            techniques = []
            for row in payload["techniques"]:
                if isinstance(row, dict) and row.get("technique_id"):
                    techniques.append(
                        {
                            "technique_id": str(row["technique_id"]),
                            "name": str(row.get("name") or ""),
                            "tactics": list(row.get("tactics") or []),
                            "platforms": list(row.get("platforms") or []),
                            "url": str(row.get("url") or ""),
                            "is_subtechnique": bool(row.get("is_subtechnique")),
                            "parent_id": row.get("parent_id"),
                            "description": str(row.get("description") or "")[:500],
                        }
                    )
            return {
                "attack_version": payload.get("attack_version") or version,
                "techniques": techniques,
                "source": payload.get("source") or "normalized",
            }
    elif isinstance(payload, list):
        objects = payload
    else:
        objects = []

    techniques: list[dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True:
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            continue
        name = str(obj.get("name") or "")
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = None
        if is_sub and "." in technique_id:
            parent_id = technique_id.split(".", 1)[0]
        url = ""
        for ref in obj.get("external_references") or []:
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and ref.get("url"):
                url = str(ref["url"])
                break
        techniques.append(
            {
                "technique_id": technique_id,
                "name": name,
                "tactics": _tactic_names(obj),
                "platforms": list(obj.get("x_mitre_platforms") or []),
                "url": url,
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "description": str(obj.get("description") or "")[:500],
            }
        )
    techniques.sort(key=lambda row: row["technique_id"])
    return {
        "attack_version": version,
        "techniques": techniques,
        "source": "mitre-cti-stix",
    }


def save_techniques(paths: PathConfig, catalog: dict[str, Any]) -> Path:
    path = techniques_path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    patch_catalog(
        paths,
        "mitre",
        status="ready",
        path=str(path),
        technique_count=len(catalog.get("techniques") or []),
        attack_version=catalog.get("attack_version"),
        last_success_at=now_iso(),
        last_error=None,
        source=catalog.get("source") or "offline-import",
    )
    return path


def import_mitre_file(paths: PathConfig, path: Path | str) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"MITRE import file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc
    catalog = normalize_stix_bundle(payload)
    if not catalog["techniques"]:
        raise ValueError("No ATT&CK techniques found in import payload")
    catalog["source"] = "offline-import"
    out = save_techniques(paths, catalog)
    return {
        "path": str(out),
        "technique_count": len(catalog["techniques"]),
        "attack_version": catalog.get("attack_version"),
        "source_file": str(source),
    }


def load_techniques(paths: PathConfig) -> list[dict[str, Any]]:
    path = techniques_path(paths)
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, dict) and isinstance(payload.get("techniques"), list):
        return [row for row in payload["techniques"] if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def search_techniques(
    paths: PathConfig,
    q: str = "",
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query = q.strip().casefold()
    rows = load_techniques(paths)
    if not query:
        return rows[: max(1, min(limit, 500))]
    hits = []
    for row in rows:
        hay = " ".join(
            [
                str(row.get("technique_id") or ""),
                str(row.get("name") or ""),
                " ".join(row.get("tactics") or []),
            ]
        ).casefold()
        if query in hay:
            hits.append(row)
        if len(hits) >= limit:
            break
    return hits


def update_mitre_online(
    paths: PathConfig,
    *,
    url: str = MITRE_ENTERPRISE_URL,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    owns = client is None
    http = client or httpx.Client(timeout=120.0, headers={"User-Agent": "langgraph-stride-intel/0.1"})
    try:
        patch_catalog(paths, "mitre", status="updating", last_error=None)
        response = http.get(url)
        response.raise_for_status()
        payload = response.json()
        catalog = normalize_stix_bundle(payload)
        if not catalog["techniques"]:
            raise ValueError("Online MITRE download contained no techniques")
        catalog["source"] = "mitre-cti-stix"
        out = save_techniques(paths, catalog)
        return {
            "path": str(out),
            "technique_count": len(catalog["techniques"]),
            "attack_version": catalog.get("attack_version"),
            "source_url": url,
        }
    except Exception as exc:
        patch_catalog(paths, "mitre", status="error", last_error=str(exc))
        raise
    finally:
        if owns:
            http.close()
