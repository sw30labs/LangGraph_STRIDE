"""CTI packs: short local intel notes tied to ATT&CK techniques.

I store one JSON file per pack under output/workspace/intel/cti/packs/. When
the scenario CTI stage runs, I inject packs whose techniques overlap the
selected attack chain so the model has grounded context.

CISA KEV (Known Exploited Vulnerabilities) is the first public feed: free JSON,
no API key, high-signal actively-exploited CVEs. I map CWE + description hints
onto ATT&CK technique IDs so packs can match attack chains.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import Any

import httpx

from src.config import PathConfig
from src.intel.manifest import now_iso, patch_catalog
from src.workspace import intel_dir

# Official CISA KEV catalog (public, no auth).
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Heuristic CWE → ATT&CK for pack matching (not a full MITRE CAPEC map).
CWE_TO_TECHNIQUES: dict[str, list[str]] = {
    "CWE-22": ["T1190", "T1083"],
    "CWE-77": ["T1190", "T1059"],
    "CWE-78": ["T1190", "T1059"],
    "CWE-79": ["T1189", "T1059"],
    "CWE-89": ["T1190", "T1059"],
    "CWE-94": ["T1190", "T1059"],
    "CWE-119": ["T1203", "T1068"],
    "CWE-121": ["T1203", "T1190"],
    "CWE-200": ["T1552", "T1005"],
    "CWE-259": ["T1078", "T1552"],
    "CWE-269": ["T1068", "T1078"],
    "CWE-284": ["T1078", "T1190"],
    "CWE-287": ["T1078", "T1190"],
    "CWE-288": ["T1078", "T1190"],
    "CWE-306": ["T1190", "T1078"],
    "CWE-311": ["T1040", "T1557"],
    "CWE-352": ["T1189", "T1078"],
    "CWE-416": ["T1068", "T1203"],
    "CWE-434": ["T1190", "T1105", "T1505.003"],
    "CWE-502": ["T1190", "T1059"],
    "CWE-639": ["T1078", "T1134"],
    "CWE-829": ["T1195", "T1059"],
    "CWE-918": ["T1190", "T1090"],
}

DESC_HINTS: list[tuple[re.Pattern[str], list[str]]] = [
    (re.compile(r"remote code execution|rce|arbitrary code", re.I), ["T1190", "T1203", "T1059"]),
    (re.compile(r"sql injection", re.I), ["T1190", "T1059"]),
    (re.compile(r"command injection|os command", re.I), ["T1190", "T1059"]),
    (re.compile(r"privilege escalat", re.I), ["T1068", "T1078"]),
    (re.compile(r"authentication bypass|auth bypass", re.I), ["T1078", "T1190"]),
    (re.compile(r"deserialization", re.I), ["T1190", "T1059"]),
    (re.compile(r"path traversal|directory traversal", re.I), ["T1190", "T1083"]),
    (re.compile(r"cross-site scripting|xss", re.I), ["T1189", "T1059"]),
    (re.compile(r"denial of service|dos condition", re.I), ["T1499", "T1498"]),
    (re.compile(r"ransomware", re.I), ["T1486", "T1490"]),
]


def packs_dir(paths: PathConfig) -> Path:
    return intel_dir(paths) / "cti" / "packs"


def kev_cache_path(paths: PathConfig) -> Path:
    return intel_dir(paths) / "cti" / "cisa_kev.json"


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


def cwe_list(row: dict[str, Any]) -> list[str]:
    raw = row.get("cwes") or row.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        text = str(item).strip().upper()
        if not text:
            continue
        if not text.startswith("CWE-"):
            text = f"CWE-{text}" if text.isdigit() else text
        out.append(text)
    return out


def techniques_from_kev_row(row: dict[str, Any]) -> list[str]:
    """Map a KEV vulnerability row onto ATT&CK technique IDs for pack matching."""
    found: set[str] = set()
    for cwe in cwe_list(row):
        for tid in CWE_TO_TECHNIQUES.get(cwe, []):
            found.add(tid)
    blob = " ".join(
        str(row.get(key) or "")
        for key in ("vulnerabilityName", "shortDescription", "requiredAction", "notes")
    )
    for pattern, tids in DESC_HINTS:
        if pattern.search(blob):
            found.update(tids)
    if str(row.get("knownRansomwareCampaignUse") or "").strip().casefold() == "known":
        found.update(["T1486", "T1490", "T1489"])
    # Default: public-facing exploit is the common KEV story.
    if not found:
        found.add("T1190")
    return sorted(found)


def kev_row_to_pack(row: dict[str, Any]) -> dict[str, Any]:
    cve = str(row.get("cveID") or row.get("cve_id") or "").strip().upper()
    if not cve:
        raise ValueError("KEV row missing cveID")
    vendor = str(row.get("vendorProject") or "").strip()
    product = str(row.get("product") or "").strip()
    name = str(row.get("vulnerabilityName") or cve).strip()
    title = f"CISA KEV: {name}"
    if len(title) > 120:
        title = f"CISA KEV: {cve} ({vendor} {product})".strip()
    ransomware = str(row.get("knownRansomwareCampaignUse") or "Unknown").strip()
    actors = ["in-the-wild-exploiters"]
    if ransomware.casefold() == "known":
        actors = ["ransomware-operators", "in-the-wild-exploiters"]
    notes_parts = [
        f"CVE: {cve}",
        f"Vendor/Product: {vendor} / {product}",
        f"Date added to KEV: {row.get('dateAdded') or 'n/a'}",
        f"Due date: {row.get('dueDate') or 'n/a'}",
        f"Known ransomware campaign use: {ransomware}",
        f"Description: {row.get('shortDescription') or ''}",
        f"Required action: {row.get('requiredAction') or ''}",
        f"CWEs: {', '.join(cwe_list(row)) or 'n/a'}",
        f"Notes/refs: {row.get('notes') or ''}",
        "Source: CISA Known Exploited Vulnerabilities Catalog",
    ]
    pack_id = f"cisa-kev-{cve.casefold().replace('_', '-')}"
    return {
        "id": pack_id,
        "title": title,
        "actors": actors,
        "techniques": techniques_from_kev_row(row),
        "iocs": [cve],
        "notes": "\n".join(notes_parts),
        "source": "cisa-kev",
    }


def _sort_kev_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: str(row.get("dateAdded") or ""),
        reverse=True,
    )


def import_cisa_kev_payload(
    paths: PathConfig,
    payload: dict[str, Any] | list[Any],
    *,
    recent_limit: int = 40,
    ransomware_limit: int = 25,
    replace_previous_kev: bool = True,
) -> dict[str, Any]:
    """Turn a CISA KEV catalog JSON into CTI packs.

    Writes:
      - one rollup pack (always)
      - up to ``recent_limit`` newest individual CVE packs
      - up to ``ransomware_limit`` packs marked Known for ransomware use
    """
    if isinstance(payload, list):
        vulns = [row for row in payload if isinstance(row, dict)]
        meta = {"catalogVersion": "unknown", "count": len(vulns), "dateReleased": ""}
    elif isinstance(payload, dict):
        raw = payload.get("vulnerabilities")
        vulns = [row for row in raw if isinstance(row, dict)] if isinstance(raw, list) else []
        meta = {
            "catalogVersion": str(payload.get("catalogVersion") or "unknown"),
            "count": int(payload.get("count") or len(vulns)),
            "dateReleased": str(payload.get("dateReleased") or ""),
            "title": str(payload.get("title") or "CISA KEV"),
        }
    else:
        raise ValueError("CISA KEV payload must be a JSON object or array")
    if not vulns:
        raise ValueError("CISA KEV payload has no vulnerabilities")

    # Cache the raw catalog for offline re-import / audit.
    cache = kev_cache_path(paths)
    cache.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, (dict, list)):
        cache.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if replace_previous_kev:
        for existing in list_cti_packs(paths):
            if str(existing.get("source") or "") == "cisa-kev":
                with contextlib.suppress(ValueError):
                    delete_cti_pack(paths, existing["id"])

    ordered = _sort_kev_rows(vulns)
    recent = ordered[: max(0, int(recent_limit))]
    ransomware = [
        row
        for row in ordered
        if str(row.get("knownRansomwareCampaignUse") or "").casefold() == "known"
    ][: max(0, int(ransomware_limit))]

    # Deduplicate individual packs by CVE.
    chosen: dict[str, dict[str, Any]] = {}
    for row in recent + ransomware:
        try:
            pack = kev_row_to_pack(row)
        except ValueError:
            continue
        chosen[pack["id"]] = pack

    written: list[dict[str, Any]] = []
    for pack in chosen.values():
        written.append(upsert_cti_pack(paths, pack))

    recent_lines = []
    for row in recent[:15]:
        cve = row.get("cveID") or "?"
        name = row.get("vulnerabilityName") or ""
        recent_lines.append(f"- {cve}: {name}")
    ransomware_cves = [str(row.get("cveID") or "") for row in ransomware if row.get("cveID")]
    rollup = {
        "id": "cisa-kev-rollup",
        "title": "CISA Known Exploited Vulnerabilities (rollup)",
        "actors": ["in-the-wild-exploiters", "ransomware-operators"],
        "techniques": sorted(
            {tid for pack in written for tid in (pack.get("techniques") or [])}
            | {"T1190", "T1203", "T1068", "T1078", "T1486"}
        ),
        "iocs": [str(row.get("cveID") or "") for row in recent[:30] if row.get("cveID")],
        "notes": "\n".join(
            [
                f"Catalog: {meta.get('title') or 'CISA KEV'}",
                f"Version: {meta.get('catalogVersion')}",
                f"Released: {meta.get('dateReleased') or 'n/a'}",
                f"Total KEV entries: {meta.get('count')}",
                f"Imported individual packs: {len(written)} "
                f"(recent≤{recent_limit}, ransomware≤{ransomware_limit})",
                f"Ransomware-linked CVEs in this pull: {', '.join(ransomware_cves[:20]) or 'none'}",
                "Recent additions:",
                *recent_lines,
                "Source URL: " + CISA_KEV_URL,
                "Use individual cisa-kev-* packs for CVE-specific context; "
                "this rollup is a high-level briefing for scenario CTI generation.",
            ]
        ),
        "source": "cisa-kev",
    }
    written.append(upsert_cti_pack(paths, rollup))

    packs = list_cti_packs(paths)
    patch_catalog(
        paths,
        "cti",
        status="ready",
        pack_count=len(packs),
        last_success_at=now_iso(),
        last_error=None,
        source="cisa-kev",
        kev_version=meta.get("catalogVersion"),
        kev_count=meta.get("count"),
        kev_cache=str(cache),
    )
    return {
        "written": len(written),
        "pack_count": len(packs),
        "individual_packs": len(chosen),
        "catalog_version": meta.get("catalogVersion"),
        "kev_count": meta.get("count"),
        "cache_path": str(cache),
        "source": "cisa-kev",
    }


def import_cisa_kev_file(
    paths: PathConfig,
    path: Path | str,
    *,
    recent_limit: int = 40,
    ransomware_limit: int = 25,
) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"CISA KEV file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc
    result = import_cisa_kev_payload(
        paths,
        payload,
        recent_limit=recent_limit,
        ransomware_limit=ransomware_limit,
    )
    result["source_file"] = str(source)
    return result


def update_cisa_kev_online(
    paths: PathConfig,
    *,
    recent_limit: int = 40,
    ransomware_limit: int = 25,
    client: httpx.Client | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Download the live CISA KEV catalog and materialize CTI packs."""
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        response = http.get(CISA_KEV_URL)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        patch_catalog(
            paths,
            "cti",
            status="error",
            last_error=f"cisa-kev: {type(exc).__name__}: {exc}",
        )
        raise
    finally:
        if owns_client:
            http.close()
    if not isinstance(payload, (dict, list)):
        raise ValueError("CISA KEV response was not JSON object/array")
    result = import_cisa_kev_payload(
        paths,
        payload,
        recent_limit=recent_limit,
        ransomware_limit=ransomware_limit,
    )
    result["url"] = CISA_KEV_URL
    return result
