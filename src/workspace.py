"""Workspace store for CMDB, attack chains, and the navigator tree.

I keep package fixtures under src/data/ as seed-only copies. When the operator
edits apps or chains, I write them into output/workspace/ so site-packages stay
read-only. I also scan output/stride and output/scenarios to build the
Application -> threat model -> scenario hierarchy the GUI needs.
"""


from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.config import PACKAGE_ROOT, PathConfig

TECHNIQUE_RE = re.compile(
    r"^(?P<name>.*?)(?:\s*\((?P<technique_id>T\d{4}(?:\.\d{3})?)\))?\s*$"
)


def now_iso() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


def package_data_dir() -> Path:
    return PACKAGE_ROOT / "data"


def workspace_dir(paths: PathConfig) -> Path:
    return paths.output_dir / "workspace"


def intel_dir(paths: PathConfig) -> Path:
    return workspace_dir(paths) / "intel"


def cmdb_path(paths: PathConfig) -> Path:
    return workspace_dir(paths) / "cmdb.json"


def attack_templates_path(paths: PathConfig) -> Path:
    return workspace_dir(paths) / "attack_templates.json"


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ── CMDB ──────────────────────────────────────────────────────────────────


CMDB_REQUIRED = ("aa_id", "name")

# Map internal snake_case ↔ legacy space-case keys used by prompts/workflows.
CMDB_TO_LEGACY = {
    "aa_id": "AA ID",
    "name": "Application Name",
    "swc_description": "SWC Description",
    "solution_description": "Solution Description",
    "owner_stream": "SWC Responsible SDU/Stream",
    "confidentiality": "Confidentiality",
    "integrity": "Integrity",
    "availability": "Technology BCM",
    "platform": "Platform",
    "externally_facing": "Externally facing",
    "development_category": "Development Category",
    "cid_handling": "CID handling",
}
LEGACY_TO_CMDB = {value: key for key, value in CMDB_TO_LEGACY.items()}
LEGACY_TO_CMDB["Technology BCH"] = "availability"  # historical typo alias


def normalize_cmdb_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a package or workspace CMDB row to canonical keys."""
    record: dict[str, Any] = {}
    for key, value in raw.items():
        if key in LEGACY_TO_CMDB:
            record[LEGACY_TO_CMDB[key]] = value
        elif key in CMDB_TO_LEGACY:
            record[key] = value
        elif key == "updated_at":
            record["updated_at"] = value
    if "aa_id" not in record and raw.get("AA ID"):
        record["aa_id"] = raw["AA ID"]
    if "name" not in record and raw.get("Application Name"):
        record["name"] = raw["Application Name"]
    platform = record.get("platform", [])
    if isinstance(platform, str):
        record["platform"] = [part.strip() for part in platform.split(",") if part.strip()]
    elif not isinstance(platform, list):
        record["platform"] = []
    else:
        record["platform"] = [str(item) for item in platform]
    for field in (
        "swc_description",
        "solution_description",
        "owner_stream",
        "confidentiality",
        "integrity",
        "availability",
        "externally_facing",
        "development_category",
        "cid_handling",
    ):
        record.setdefault(field, "")
        if record[field] is None:
            record[field] = ""
        else:
            record[field] = str(record[field]) if not isinstance(record[field], str) else record[field]
    record["aa_id"] = str(record.get("aa_id") or "").strip()
    record["name"] = str(record.get("name") or "").strip()
    record.setdefault("updated_at", now_iso())
    return record


def to_legacy_cmdb(record: dict[str, Any]) -> dict[str, Any]:
    """Convert canonical CMDB to the space-case shape workflows expect."""
    normalized = normalize_cmdb_record(record)
    legacy = {legacy_key: normalized.get(canon, "") for canon, legacy_key in CMDB_TO_LEGACY.items()}
    legacy["aa_id"] = normalized["aa_id"]
    return legacy


def validate_cmdb_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_cmdb_record(record)
    missing = [field for field in CMDB_REQUIRED if not normalized.get(field)]
    if missing:
        raise ValueError(f"CMDB record missing required fields: {', '.join(missing)}")
    if not re.fullmatch(r"AA\d+", normalized["aa_id"]):
        # Allow flexible IDs but prefer AA-style; only reject empty (already handled).
        if not normalized["aa_id"]:
            raise ValueError("aa_id is required")
    return normalized


def load_package_cmdb(data_dir: Path | None = None) -> list[dict[str, Any]]:
    path = (data_dir or package_data_dir()) / "cmdb.json"
    rows = _read_json(path, [])
    if not isinstance(rows, list):
        return []
    return [normalize_cmdb_record(row) for row in rows if isinstance(row, dict)]


def load_cmdb(paths: PathConfig) -> list[dict[str, Any]]:
    """Load workspace CMDB, seeding from package when workspace file is absent."""
    path = cmdb_path(paths)
    if not path.is_file():
        return load_package_cmdb(paths.data_dir)
    rows = _read_json(path, [])
    if not isinstance(rows, list):
        return []
    return [normalize_cmdb_record(row) for row in rows if isinstance(row, dict)]


def save_cmdb(paths: PathConfig, records: list[dict[str, Any]]) -> Path:
    normalized = [validate_cmdb_record(row) for row in records]
    ids = [row["aa_id"] for row in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("CMDB contains duplicate aa_id values")
    path = cmdb_path(paths)
    _write_json(path, normalized)
    return path


def seed_cmdb(paths: PathConfig, *, force: bool = False) -> Path:
    path = cmdb_path(paths)
    if path.is_file() and not force:
        return path
    records = load_package_cmdb(paths.data_dir)
    return save_cmdb(paths, records)


def get_cmdb_entry(paths: PathConfig, aa_id: str) -> dict[str, Any]:
    for row in load_cmdb(paths):
        if row["aa_id"] == aa_id:
            return row
    raise ValueError(f"No CMDB entry for AA ID: {aa_id}")


def get_cmdb_entry_legacy(paths: PathConfig, aa_id: str) -> dict[str, Any]:
    """CMDB row in legacy space-case keys for existing workflows."""
    return to_legacy_cmdb(get_cmdb_entry(paths, aa_id))


def upsert_cmdb_entry(paths: PathConfig, record: dict[str, Any]) -> dict[str, Any]:
    seed_cmdb(paths)
    normalized = validate_cmdb_record(record)
    normalized["updated_at"] = now_iso()
    rows = load_cmdb(paths)
    for index, row in enumerate(rows):
        if row["aa_id"] == normalized["aa_id"]:
            rows[index] = normalized
            save_cmdb(paths, rows)
            return normalized
    rows.append(normalized)
    save_cmdb(paths, rows)
    return normalized


def delete_cmdb_entry(paths: PathConfig, aa_id: str) -> None:
    seed_cmdb(paths)
    current = load_cmdb(paths)
    rows = [row for row in current if row["aa_id"] != aa_id]
    if len(rows) == len(current):
        raise ValueError(f"No CMDB entry for AA ID: {aa_id}")
    save_cmdb(paths, rows)


# ── Attack chains ─────────────────────────────────────────────────────────


def parse_technique_label(label: str) -> dict[str, Any]:
    """Parse 'Exploit Public-Facing Application (T1190)' into structured step."""
    text = str(label).strip()
    match = TECHNIQUE_RE.match(text)
    if not match:
        return {"technique_id": None, "name": text, "tactic": None, "raw": text}
    name = (match.group("name") or "").strip() or text
    technique_id = match.group("technique_id")
    return {
        "technique_id": technique_id,
        "name": name,
        "tactic": None,
        "raw": text,
    }


def format_technique_label(step: dict[str, Any]) -> str:
    name = str(step.get("name") or step.get("raw") or "").strip()
    technique_id = step.get("technique_id")
    if technique_id:
        return f"{name} ({technique_id})" if name else str(technique_id)
    return name or str(step.get("raw") or "")


def slugify_chain_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "chain"


def normalize_chain(raw: dict[str, Any] | str, *, techniques: list[Any] | None = None) -> dict[str, Any]:
    """Normalize a chain record or legacy name→list entry."""
    if isinstance(raw, str):
        name = raw
        steps_raw = techniques or []
        chain_id = slugify_chain_id(name)
        description = ""
        tags: list[str] = []
        source = "seed"
        updated_at = now_iso()
    else:
        name = str(raw.get("name") or raw.get("id") or "").strip()
        chain_id = str(raw.get("id") or slugify_chain_id(name)).strip()
        description = str(raw.get("description") or "")
        tags = [str(tag) for tag in (raw.get("tags") or [])]
        source = str(raw.get("source") or "user")
        updated_at = str(raw.get("updated_at") or now_iso())
        steps_raw = raw.get("steps") if raw.get("steps") is not None else raw.get("techniques") or []

    steps: list[dict[str, Any]] = []
    for item in steps_raw:
        if isinstance(item, str):
            steps.append(parse_technique_label(item))
        elif isinstance(item, dict):
            if item.get("raw") or item.get("name") or item.get("technique_id"):
                step = {
                    "technique_id": item.get("technique_id"),
                    "name": str(item.get("name") or "").strip(),
                    "tactic": item.get("tactic"),
                    "raw": item.get("raw") or format_technique_label(item),
                }
                if not step["name"] and step["raw"]:
                    parsed = parse_technique_label(str(step["raw"]))
                    step["name"] = parsed["name"]
                    step["technique_id"] = step["technique_id"] or parsed["technique_id"]
                steps.append(step)
    if not name:
        raise ValueError("Attack chain name is required")
    if not chain_id:
        chain_id = slugify_chain_id(name)
    return {
        "id": chain_id,
        "name": name,
        "description": description,
        "tags": tags,
        "steps": steps,
        "updated_at": updated_at,
        "source": source,
    }


def chain_technique_labels(chain: dict[str, Any]) -> list[str]:
    return [format_technique_label(step) for step in chain.get("steps") or []]


def load_package_chains(data_dir: Path | None = None) -> list[dict[str, Any]]:
    path = (data_dir or package_data_dir()) / "predefined_attack_templates.json"
    payload = _read_json(path, {})
    if isinstance(payload, dict):
        return [
            normalize_chain(name, techniques=techniques if isinstance(techniques, list) else [])
            for name, techniques in payload.items()
        ]
    if isinstance(payload, list):
        return [normalize_chain(row) for row in payload if isinstance(row, dict) or isinstance(row, str)]
    return []


def load_chains(paths: PathConfig) -> list[dict[str, Any]]:
    path = attack_templates_path(paths)
    if not path.is_file():
        return load_package_chains(paths.data_dir)
    payload = _read_json(path, [])
    if isinstance(payload, dict):
        # legacy map format in workspace
        return [
            normalize_chain(name, techniques=techniques if isinstance(techniques, list) else [])
            for name, techniques in payload.items()
        ]
    if not isinstance(payload, list):
        return []
    return [normalize_chain(row) for row in payload if isinstance(row, dict)]


def save_chains(paths: PathConfig, chains: list[dict[str, Any]]) -> Path:
    normalized = [normalize_chain(chain) for chain in chains]
    ids = [chain["id"] for chain in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("Attack chains contain duplicate id values")
    path = attack_templates_path(paths)
    _write_json(path, normalized)
    return path


def seed_attack_templates(paths: PathConfig, *, force: bool = False) -> Path:
    path = attack_templates_path(paths)
    if path.is_file() and not force:
        return path
    return save_chains(paths, load_package_chains(paths.data_dir))


def get_chain(paths: PathConfig, chain_id_or_name: str) -> dict[str, Any]:
    key = chain_id_or_name.strip()
    for chain in load_chains(paths):
        if chain["id"] == key or chain["name"] == key:
            return chain
    raise ValueError(f"No attack chain: {chain_id_or_name}")


def get_chain_techniques(paths: PathConfig, chain_id_or_name: str) -> list[str]:
    return chain_technique_labels(get_chain(paths, chain_id_or_name))


def upsert_chain(paths: PathConfig, chain: dict[str, Any]) -> dict[str, Any]:
    seed_attack_templates(paths)
    normalized = normalize_chain(chain)
    normalized["updated_at"] = now_iso()
    chains = load_chains(paths)
    for index, row in enumerate(chains):
        if row["id"] == normalized["id"] or row["name"] == normalized["name"]:
            # keep stable id if renaming by name match only
            if row["id"] != normalized["id"] and row["name"] == normalized["name"]:
                normalized["id"] = row["id"]
            chains[index] = normalized
            save_chains(paths, chains)
            return normalized
    chains.append(normalized)
    save_chains(paths, chains)
    return normalized


def delete_chain(paths: PathConfig, chain_id_or_name: str) -> None:
    seed_attack_templates(paths)
    key = chain_id_or_name.strip()
    current = load_chains(paths)
    chains = [chain for chain in current if chain["id"] != key and chain["name"] != key]
    if len(chains) == len(current):
        raise ValueError(f"No attack chain: {chain_id_or_name}")
    save_chains(paths, chains)


def seed_workspace(paths: PathConfig, *, force: bool = False) -> dict[str, str]:
    """Ensure workspace CMDB and attack chains exist."""
    workspace_dir(paths).mkdir(parents=True, exist_ok=True)
    intel_dir(paths).mkdir(parents=True, exist_ok=True)
    return {
        "cmdb": str(seed_cmdb(paths, force=force)),
        "attack_templates": str(seed_attack_templates(paths, force=force)),
    }


# ── Navigator index ───────────────────────────────────────────────────────


def _assessment_timestamp_from_name(name: str) -> str | None:
    match = re.search(r"security_assessment_[^_]+_(\d{14})\.json$", name)
    return match.group(1) if match else None


def _load_json_object(path: Path) -> dict[str, Any] | None:
    payload = _read_json(path, None)
    return payload if isinstance(payload, dict) else None


def build_navigator(paths: PathConfig) -> dict[str, Any]:
    """Build AA → threat models → scenarios graph from workspace + outputs."""
    apps = {row["aa_id"]: {**row, "threat_models": []} for row in load_cmdb(paths)}
    stride_dir = paths.output_dir / "stride"
    scenario_dir = paths.output_dir / "scenarios"
    feedback_dir = paths.output_dir / "feedback"

    assessments: dict[str, dict[str, Any]] = {}
    if stride_dir.is_dir():
        for path in sorted(stride_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            data = _load_json_object(path)
            if data is None:
                continue
            meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
            system = data.get("system_metadata") if isinstance(data.get("system_metadata"), dict) else {}
            aa_id = str(
                meta.get("aa_id")
                or system.get("aa_id")
                or system.get("AA ID")
                or ""
            ).strip()
            if not aa_id:
                continue
            if aa_id not in apps:
                apps[aa_id] = {
                    "aa_id": aa_id,
                    "name": str(system.get("Application Name") or aa_id),
                    "threat_models": [],
                }
            artifact_id = str(meta.get("artifact_id") or f"tm_{aa_id}_{_assessment_timestamp_from_name(path.name) or path.stem}")
            created_at = str(meta.get("created_at") or "")
            threat_count = 0
            for key, value in data.items():
                if key in {"system_metadata", "dread_assessment", "_meta"}:
                    continue
                if isinstance(value, list):
                    threat_count += len(value)
            dread = data.get("dread_assessment")
            max_dread = None
            if isinstance(dread, list):
                scores = []
                for row in dread:
                    if not isinstance(row, dict):
                        continue
                    for field in ("Damage Potential", "score", "Score"):
                        if field in row:
                            try:
                                scores.append(float(row[field]))
                            except (TypeError, ValueError):
                                pass
                if scores:
                    max_dread = max(scores)
            rel = str(path.relative_to(paths.project_root)) if path.is_relative_to(paths.project_root) else str(path)
            node = {
                "artifact_id": artifact_id,
                "path": rel,
                "absolute_path": str(path.resolve()),
                "created_at": created_at,
                "threat_count": threat_count,
                "max_dread": max_dread,
                "scenarios": [],
                "feedback": [],
                "timestamp_key": _assessment_timestamp_from_name(path.name),
            }
            assessments[artifact_id] = node
            apps[aa_id]["threat_models"].append(node)

    # Feedback by aa_id + timestamp
    if feedback_dir.is_dir():
        for path in feedback_dir.glob("*.json"):
            match = re.match(r"(stride|dread|final)_feedback_(.+)_(\d{14})\.json$", path.name)
            if not match:
                continue
            kind, aa_id, ts = match.groups()
            data = _load_json_object(path)
            rel = str(path.relative_to(paths.project_root)) if path.is_relative_to(paths.project_root) else str(path)
            for node in apps.get(aa_id, {}).get("threat_models", []):
                if node.get("timestamp_key") == ts:
                    node["feedback"].append(
                        {
                            "kind": kind,
                            "path": rel,
                            "pass": bool((data or {}).get("pass")) if data else None,
                        }
                    )

    # Scenarios
    if scenario_dir.is_dir():
        for path in sorted(scenario_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            data = _load_json_object(path)
            if data is None:
                continue
            meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
            aa_id = str(meta.get("aa_id") or data.get("SWC_ID") or "").strip()
            source_id = meta.get("source_threat_model_id")
            source_path = meta.get("source_threat_model_path")
            rel = str(path.relative_to(paths.project_root)) if path.is_relative_to(paths.project_root) else str(path)
            scenario_node = {
                "artifact_id": str(meta.get("artifact_id") or f"sc_{path.stem}"),
                "path": rel,
                "attack_template": meta.get("attack_template") or data.get("Attack_Template"),
                "created_at": meta.get("created_at") or "",
            }
            attached = False
            if source_id and source_id in assessments:
                assessments[source_id]["scenarios"].append(scenario_node)
                attached = True
            elif source_path:
                for node in assessments.values():
                    if node["path"] == source_path or node["absolute_path"].endswith(str(source_path)):
                        node["scenarios"].append(scenario_node)
                        attached = True
                        break
            if not attached and aa_id in apps and apps[aa_id]["threat_models"]:
                # Fallback: newest assessment for AA
                apps[aa_id]["threat_models"][0]["scenarios"].append(scenario_node)

    applications = sorted(apps.values(), key=lambda row: row.get("aa_id") or "")
    for app in applications:
        for model in app["threat_models"]:
            model.pop("absolute_path", None)
            model.pop("timestamp_key", None)
    return {
        "applications": applications,
        "counts": {
            "applications": len(applications),
            "threat_models": sum(len(app["threat_models"]) for app in applications),
            "scenarios": sum(
                len(model["scenarios"])
                for app in applications
                for model in app["threat_models"]
            ),
        },
    }
