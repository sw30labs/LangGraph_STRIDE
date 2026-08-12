"""Intel projection for Neo4j: CVEs, CWEs, actors, and advisories.

Extends the chain-library projection with the intel catalogs so multi-hop
queries can walk paths like
(:CVE)-[:EXPLOITS_TECHNIQUE]->(:Technique)<-[:USES]-(:Actor). Heuristic edges
carry a ``confidence`` property so analytics can separate gold data (MITRE
"uses", advisory-cited technique IDs) from mined hints (KEV CWE/description
mapping). Payload builders are pure functions — unit tests never need a live
Neo4j.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from src.config import PathConfig
from src.intel.cti import cwe_list, kev_cache_path, list_cti_packs, techniques_from_kev_row
from src.intel.mitre import load_techniques
from src.intel.nvd import default_cve_db_path

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

CONFIDENCE_KEV = "heuristic-kev"
CONFIDENCE_MITRE = "mitre-attack"
CONFIDENCE_ADVISORY = "advisory-mined"


def technique_names(paths: PathConfig) -> dict[str, str]:
    return {
        str(row.get("technique_id")): str(row.get("name") or "")
        for row in load_techniques(paths)
        if row.get("technique_id")
    }


def cve_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """Merge the NVD sqlite store and the cached KEV catalog per CVE ID."""
    merged: dict[str, dict[str, Any]] = {}

    def skeleton(cve_id: str) -> dict[str, Any]:
        return {
            "cve_id": cve_id,
            "description": "",
            "cvss": None,
            "vector": "",
            "published": "",
            "platforms": [],
            "cwes": [],
            "in_kev": False,
            "kev_date_added": "",
            "kev_due_date": "",
            "kev_ransomware": "",
            "vendor": "",
            "product": "",
            "kev_name": "",
            "techniques": [],
        }

    db_path = default_cve_db_path(paths)
    if db_path.is_file():
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            for row in conn.execute(
                "SELECT cve_id, description, cvss, vector, cwe, published, platforms FROM cves"
            ):
                cve_id = str(row["cve_id"] or "").strip().upper()
                if not cve_id:
                    continue
                entry = skeleton(cve_id)
                entry["description"] = str(row["description"] or "")
                entry["cvss"] = row["cvss"]
                entry["vector"] = str(row["vector"] or "")
                entry["published"] = str(row["published"] or "")
                entry["platforms"] = [
                    part.strip() for part in str(row["platforms"] or "").split(",") if part.strip()
                ]
                entry["cwes"] = [
                    part.strip()
                    for part in str(row["cwe"] or "").split(",")
                    if part.strip().startswith("CWE-")
                ]
                merged[cve_id] = entry

    cache = kev_cache_path(paths)
    payload: Any = None
    if cache.is_file():
        try:
            payload = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else payload
    for row in vulns if isinstance(vulns, list) else []:
        if not isinstance(row, dict):
            continue
        cve_id = str(row.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entry = merged.setdefault(cve_id, skeleton(cve_id))
        entry["in_kev"] = True
        entry["kev_date_added"] = str(row.get("dateAdded") or "")
        entry["kev_due_date"] = str(row.get("dueDate") or "")
        entry["kev_ransomware"] = str(row.get("knownRansomwareCampaignUse") or "")
        entry["vendor"] = str(row.get("vendorProject") or "")
        entry["product"] = str(row.get("product") or "")
        entry["kev_name"] = str(row.get("vulnerabilityName") or "")
        entry["cwes"] = sorted(set(entry["cwes"]) | set(cwe_list(row)))
        entry["techniques"] = techniques_from_kev_row(row)
        if not entry["description"]:
            entry["description"] = str(row.get("shortDescription") or "")

    return sorted(merged.values(), key=lambda item: item["cve_id"])


def actor_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """MITRE group packs → actor rows with real 'uses' technique edges."""
    rows = []
    for pack in list_cti_packs(paths):
        if pack.get("source") != "mitre-attack-group":
            continue
        actors = [str(a) for a in (pack.get("actors") or []) if str(a).strip()]
        rows.append(
            {
                "id": pack["id"],
                "name": actors[0] if actors else str(pack.get("title") or pack["id"]),
                "aliases": actors[1:],
                "techniques": [
                    str(t).upper()
                    for t in (pack.get("techniques") or [])
                    if TECHNIQUE_ID.match(str(t).strip().upper())
                ],
                "notes": str(pack.get("notes") or "")[:4000],
            }
        )
    return sorted(rows, key=lambda item: item["id"])


def advisory_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """CISA advisory packs → advisory rows with nexus attribution labels."""
    rows = []
    for pack in list_cti_packs(paths):
        if pack.get("source") != "cisa-advisory":
            continue
        rows.append(
            {
                "id": pack["id"],
                "title": str(pack.get("title") or pack["id"]),
                "nexus": [str(a) for a in (pack.get("actors") or []) if str(a).strip()],
                "techniques": [
                    str(t).upper()
                    for t in (pack.get("techniques") or [])
                    if TECHNIQUE_ID.match(str(t).strip().upper())
                ],
                "notes": str(pack.get("notes") or "")[:4000],
            }
        )
    return sorted(rows, key=lambda item: item["id"])


def build_intel_payload(paths: PathConfig) -> dict[str, Any]:
    """All intel rows plus flattened edge pairs, ready for UNWIND writes."""
    names = technique_names(paths)
    cves = cve_rows(paths)
    actors = actor_rows(paths)
    advisories = advisory_rows(paths)

    def tech(tid: str) -> dict[str, Any]:
        return {
            "tid": tid,
            "name": names.get(tid, ""),
            "is_sub": "." in tid,
        }

    cwe_pairs = [{"cve": row["cve_id"], "cwe": cwe} for row in cves for cwe in row["cwes"]]
    kev_tech_edges = [
        {"cve": row["cve_id"], **tech(tid)}
        for row in cves
        for tid in row["techniques"]
        if TECHNIQUE_ID.match(tid)
    ]
    actor_tech_edges = [
        {"actor": row["id"], **tech(tid)} for row in actors for tid in row["techniques"]
    ]
    advisory_tech_edges = [
        {"advisory": row["id"], **tech(tid)} for row in advisories for tid in row["techniques"]
    ]
    nexus_edges = [
        {"advisory": row["id"], "nexus": label} for row in advisories for label in row["nexus"]
    ]
    return {
        "cves": cves,
        "actors": actors,
        "advisories": advisories,
        "cwe_pairs": cwe_pairs,
        "kev_tech_edges": kev_tech_edges,
        "actor_tech_edges": actor_tech_edges,
        "advisory_tech_edges": advisory_tech_edges,
        "nexus_edges": nexus_edges,
    }


def sync_intel_to_neo4j(session, paths: PathConfig) -> dict[str, int]:
    """Write the intel projection into an open session (full rebuild context)."""
    payload = build_intel_payload(paths)

    session.run(
        """
        UNWIND $rows AS row
        MERGE (c:CVE {cve_id: row.cve_id})
        SET c.description = row.description,
            c.cvss = row.cvss,
            c.vector = row.vector,
            c.published = row.published,
            c.platforms = row.platforms,
            c.in_kev = row.in_kev,
            c.kev_date_added = row.kev_date_added,
            c.kev_due_date = row.kev_due_date,
            c.kev_ransomware = row.kev_ransomware,
            c.vendor = row.vendor,
            c.product = row.product,
            c.kev_name = row.kev_name
        """,
        rows=payload["cves"],
    )
    session.run(
        """
        UNWIND $pairs AS pair
        MERGE (w:CWE {name: pair.cwe})
        WITH pair, w
        MATCH (c:CVE {cve_id: pair.cve})
        MERGE (c)-[:HAS_CWE]->(w)
        """,
        pairs=payload["cwe_pairs"],
    )
    # KEV heuristic technique edges; MERGE reuses chain-library technique nodes.
    session.run(
        """
        UNWIND $edges AS edge
        MERGE (t:Technique {key: edge.tid})
        ON CREATE SET
            t.technique_id = edge.tid,
            t.name = edge.name,
            t.frequency = 0,
            t.is_subtechnique = edge.is_sub
        WITH edge, t
        MATCH (c:CVE {cve_id: edge.cve})
        MERGE (c)-[r:EXPLOITS_TECHNIQUE]->(t)
        ON CREATE SET r.confidence = $confidence
        """,
        edges=payload["kev_tech_edges"],
        confidence=CONFIDENCE_KEV,
    )
    session.run(
        """
        UNWIND $rows AS row
        MERGE (a:Actor {id: row.id})
        SET a.name = row.name, a.aliases = row.aliases, a.notes = row.notes
        """,
        rows=payload["actors"],
    )
    session.run(
        """
        UNWIND $edges AS edge
        MERGE (t:Technique {key: edge.tid})
        ON CREATE SET
            t.technique_id = edge.tid,
            t.name = edge.name,
            t.frequency = 0,
            t.is_subtechnique = edge.is_sub
        WITH edge, t
        MATCH (a:Actor {id: edge.actor})
        MERGE (a)-[r:USES]->(t)
        ON CREATE SET r.confidence = $confidence
        """,
        edges=payload["actor_tech_edges"],
        confidence=CONFIDENCE_MITRE,
    )
    session.run(
        """
        UNWIND $rows AS row
        MERGE (d:Advisory {id: row.id})
        SET d.title = row.title, d.nexus = row.nexus, d.notes = row.notes
        """,
        rows=payload["advisories"],
    )
    session.run(
        """
        UNWIND $edges AS edge
        MERGE (t:Technique {key: edge.tid})
        ON CREATE SET
            t.technique_id = edge.tid,
            t.name = edge.name,
            t.frequency = 0,
            t.is_subtechnique = edge.is_sub
        WITH edge, t
        MATCH (d:Advisory {id: edge.advisory})
        MERGE (d)-[r:MENTIONS]->(t)
        ON CREATE SET r.confidence = $confidence
        """,
        edges=payload["advisory_tech_edges"],
        confidence=CONFIDENCE_ADVISORY,
    )
    session.run(
        """
        UNWIND $edges AS edge
        MERGE (n:Nexus {name: edge.nexus})
        WITH edge, n
        MATCH (d:Advisory {id: edge.advisory})
        MERGE (d)-[:ATTRIBUTES_ACTIVITY_TO]->(n)
        """,
        edges=payload["nexus_edges"],
    )
    return {
        "cves": len(payload["cves"]),
        "cves_kev": sum(1 for row in payload["cves"] if row["in_kev"]),
        "cwes": len({pair["cwe"] for pair in payload["cwe_pairs"]}),
        "actors": len(payload["actors"]),
        "advisories": len(payload["advisories"]),
        "kev_tech_edges": len(payload["kev_tech_edges"]),
        "actor_tech_edges": len(payload["actor_tech_edges"]),
        "advisory_tech_edges": len(payload["advisory_tech_edges"]),
    }
