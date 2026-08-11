"""CTI packs: short local intel notes tied to ATT&CK techniques.

I store one JSON file per pack under output/workspace/intel/cti/packs/. When
the scenario CTI stage runs, I inject packs whose techniques overlap the
selected attack chain so the model has grounded context.
"""


from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.config import PathConfig
from src.intel.manifest import now_iso, patch_catalog
from src.workspace import intel_dir


def packs_dir(paths: PathConfig) -> Path:
    return intel_dir(paths) / "cti" / "packs"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")
    return slug or "pack"


def normalize_pack(raw: dict[str, Any]) -> dict[str, Any]:
    title = str(raw.get("title") or raw.get("name") or "").strip()
    pack_id = str(raw.get("id") or _slug(title)).strip()
    if not title:
        raise ValueError("CTI pack title is required")
    if not pack_id:
        pack_id = _slug(title)
    techniques = []
    for item in raw.get("techniques") or []:
        if isinstance(item, str):
            techniques.append(item.strip())
        elif isinstance(item, dict) and item.get("technique_id"):
            techniques.append(str(item["technique_id"]))
    return {
        "id": pack_id,
        "title": title,
        "actors": [str(a) for a in (raw.get("actors") or [])],
        "techniques": techniques,
        "iocs": [str(i) for i in (raw.get("iocs") or [])],
        "notes": str(raw.get("notes") or raw.get("summary") or ""),
        "source": str(raw.get("source") or "user"),
        "updated_at": str(raw.get("updated_at") or now_iso()),
    }


def list_cti_packs(paths: PathConfig) -> list[dict[str, Any]]:
    directory = packs_dir(paths)
    if not directory.is_dir():
        return []
    packs = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            try:
                packs.append(normalize_pack(payload))
            except ValueError:
                continue
    return packs


def upsert_cti_pack(paths: PathConfig, pack: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_pack(pack)
    normalized["updated_at"] = now_iso()
    directory = packs_dir(paths)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{normalized['id']}.json"
    path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    packs = list_cti_packs(paths)
    patch_catalog(
        paths,
        "cti",
        status="ready",
        pack_count=len(packs),
        last_success_at=now_iso(),
        last_error=None,
        source="workspace",
    )
    return normalized


def delete_cti_pack(paths: PathConfig, pack_id: str) -> None:
    path = packs_dir(paths) / f"{pack_id}.json"
    if not path.is_file():
        raise ValueError(f"No CTI pack: {pack_id}")
    path.unlink()
    packs = list_cti_packs(paths)
    patch_catalog(
        paths,
        "cti",
        status="ready" if packs else "missing",
        pack_count=len(packs),
        last_success_at=now_iso(),
        last_error=None,
    )


def ingest_cti_pack(paths: PathConfig, path: Path | str) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"CTI pack file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc
    if isinstance(payload, list):
        written = [upsert_cti_pack(paths, row) for row in payload if isinstance(row, dict)]
        return {"written": len(written), "packs": written}
    if not isinstance(payload, dict):
        raise ValueError("CTI pack must be a JSON object or array of objects")
    pack = upsert_cti_pack(paths, payload)
    return {"written": 1, "packs": [pack]}


def matching_cti_packs(
    paths: PathConfig,
    technique_ids: list[str] | None = None,
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    wanted = {tid.strip().upper() for tid in (technique_ids or []) if tid and tid.strip()}
    packs = list_cti_packs(paths)
    if not wanted:
        return packs[:limit]
    ranked: list[tuple[int, dict[str, Any]]] = []
    for pack in packs:
        pack_ids = {str(t).upper() for t in pack.get("techniques") or []}
        overlap = len(wanted & pack_ids)
        if overlap:
            ranked.append((overlap, pack))
    ranked.sort(key=lambda item: (-item[0], item[1]["title"].casefold()))
    return [pack for _, pack in ranked[:limit]]


def format_packs_for_prompt(packs: list[dict[str, Any]]) -> str:
    if not packs:
        return ""
    blocks = []
    for pack in packs:
        blocks.append(
            "\n".join(
                [
                    f"### {pack['title']} ({pack['id']})",
                    f"Actors: {', '.join(pack.get('actors') or []) or 'n/a'}",
                    f"Techniques: {', '.join(pack.get('techniques') or []) or 'n/a'}",
                    f"IOCs: {', '.join(pack.get('iocs') or []) or 'n/a'}",
                    f"Notes: {pack.get('notes') or ''}",
                ]
            )
        )
    return "\n\n".join(blocks)
