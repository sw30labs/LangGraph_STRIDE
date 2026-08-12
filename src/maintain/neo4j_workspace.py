"""Workspace/artifact projection for Neo4j: applications, threat models,
scenarios, and QA feedback.

P1 layer on top of the chain + intel projections: it connects the operator's
inventory and generated artifacts into the same graph, unlocking path queries
like (:Application)<-[:FOR_APP]-(:Scenario)-[:SELECTED_CHAIN]->(:Chain)
-[:USES]->(:Technique)<-[:USES]-(:Actor). Payload builders are pure functions
— unit tests never need a live Neo4j.

DREAD rows stay a JSON-string property of the threat-model node: they are
keyed by STRIDE category + free-text scenario, which does not join cleanly
onto named threat nodes. STRIDE threats (name + category) become (:Threat)
nodes instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.config import PathConfig
from src.intel.cti import DESC_HINTS
from src.maintain.neo4j_intel import technique_names
from src.workspace import load_chains, load_cmdb

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

FEEDBACK_STAGE = re.compile(
    r"^(?P<stage>stride|dread|final)_feedback_(?P<aa>[A-Za-z0-9]+)_(?P<ts>\d+)\.json$"
)

EXPLICIT_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

CONFIDENCE_THREAT = "heuristic-threat"


def threat_techniques(name: str, description: str, impact: str) -> list[str]:
    """Map a free-text threat onto ATT&CK IDs: explicit citations first, then
    the shared keyword hints. Heuristic — edges carry confidence accordingly."""
    blob = f"{name} {description} {impact}"
    found = {tid.upper() for tid in EXPLICIT_TECHNIQUE.findall(blob)}
    for pattern, tids in DESC_HINTS:
        if pattern.search(blob):
            found.update(tids)
    return sorted(found)[:8]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")
    return slug or "unknown"


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def application_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """CMDB applications → graph rows (canonical workspace keys)."""
    rows = []
    for record in load_cmdb(paths):
        aa_id = str(record.get("aa_id") or "").strip()
        if not aa_id:
            continue
        rows.append(
            {
                "aa_id": aa_id,
                "name": str(record.get("name") or aa_id),
                "swc_description": str(record.get("swc_description") or ""),
                "solution_description": str(record.get("solution_description") or ""),
                "owner_stream": str(record.get("owner_stream") or ""),
                "confidentiality": str(record.get("confidentiality") or ""),
                "integrity": str(record.get("integrity") or ""),
                "availability": str(record.get("availability") or ""),
                "platform": [str(p) for p in (record.get("platform") or [])],
                "externally_facing": str(record.get("externally_facing") or ""),
                "dev_category": str(record.get("dev_category") or ""),
                "cid_handling": str(record.get("cid_handling") or ""),
            }
        )
    return sorted(rows, key=lambda row: row["aa_id"])


def _artifact_id(payload: dict[str, Any], path: Path, prefix: str) -> str:
    meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
    artifact_id = str(meta.get("artifact_id") or "").strip()
    if artifact_id:
        return artifact_id
    # security_assessment_AA123456_20260811172229.json → tm_AA123456_20260811172229
    match = re.search(r"(?P<aa>AA\d+)_(?P<ts>\d{14})", path.name)
    if match:
        return f"{prefix}_{match.group('aa')}_{match.group('ts')}"
    return f"{prefix}_{_slug(path.stem)[:48]}"


def threat_model_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """output/stride/*.json → threat-model rows with threats + DREAD scores."""
    root = paths.project_root
    rows = []
    for path in sorted(paths.output_dir.glob("stride/*.json")):
        payload = _read_json(path)
        if payload is None:
            continue
        meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
        sys_meta = (
            payload.get("system_metadata")
            if isinstance(payload.get("system_metadata"), dict)
            else {}
        )
        threats = []
        for category in STRIDE_CATEGORIES:
            entries = payload.get(category)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("threat_name"):
                    continue
                threats.append(
                    {
                        "key": _slug(str(entry["threat_name"])),
                        "name": str(entry["threat_name"]),
                        "category": category,
                        "description": str(entry.get("description") or ""),
                        "impact": str(entry.get("impact") or ""),
                        "mitigation": str(entry.get("mitigation") or ""),
                        "techniques": threat_techniques(
                            str(entry["threat_name"]),
                            str(entry.get("description") or ""),
                            str(entry.get("impact") or ""),
                        ),
                    }
                )
        dread = []
        for entry in payload.get("dread_assessment") or []:
            if not isinstance(entry, dict):
                continue
            dread.append(
                {
                    "threat_type": str(entry.get("Threat Type") or ""),
                    "scenario": str(entry.get("Scenario") or ""),
                    "damage": str(entry.get("Damage Potential") or ""),
                    "reproducibility": str(entry.get("Reproducibility") or ""),
                    "exploitability": str(entry.get("Exploitability") or ""),
                    "affected_users": str(entry.get("Affected Users") or ""),
                    "discoverability": str(entry.get("Discoverability") or ""),
                }
            )
        rows.append(
            {
                "artifact_id": _artifact_id(payload, path, "tm"),
                "path": _rel(path, root),
                "aa_id": str(meta.get("aa_id") or sys_meta.get("aa_id") or ""),
                "created_at": str(meta.get("created_at") or ""),
                "provider": str(meta.get("provider") or ""),
                "model": str(meta.get("model") or ""),
                "threats": threats,
                "dread": dread,
                "dread_json": json.dumps(dread),
            }
        )
    return sorted(rows, key=lambda row: row["artifact_id"])


def scenario_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """output/scenarios/*.json → scenario rows with lineage pointers."""
    root = paths.project_root
    chain_ids = {str(c.get("name") or "").casefold(): str(c.get("id")) for c in load_chains(paths)}
    rows = []
    for path in sorted(paths.output_dir.glob("scenarios/*.json")):
        payload = _read_json(path)
        if payload is None:
            continue
        meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
        template = str(meta.get("attack_template") or payload.get("Attack_Template") or "")
        rows.append(
            {
                "artifact_id": _artifact_id(payload, path, "sc"),
                "path": _rel(path, root),
                "aa_id": str(meta.get("aa_id") or payload.get("SWC_ID") or ""),
                "title": str(payload.get("titleThreatScenario") or ""),
                "template": template,
                "chain_id": chain_ids.get(template.casefold(), ""),
                "created_at": str(
                    meta.get("created_at") or payload.get("Threat_Report_Date") or ""
                ),
                "provider": str(meta.get("provider") or payload.get("Provider") or ""),
                "model": str(meta.get("model") or ""),
                "source_threat_model_path": str(meta.get("source_threat_model_path") or ""),
                "complete": str(payload.get("Complete") or ""),
            }
        )
    return sorted(rows, key=lambda row: row["artifact_id"])


def feedback_rows(paths: PathConfig) -> list[dict[str, Any]]:
    """output/feedback/*.json → QA verdicts keyed by threat-model artifact id."""
    rows = []
    for path in sorted(paths.output_dir.glob("feedback/*.json")):
        match = FEEDBACK_STAGE.match(path.name)
        payload = _read_json(path)
        if not match or payload is None:
            continue
        rows.append(
            {
                "stage": match.group("stage"),
                "artifact_id": f"tm_{match.group('aa')}_{match.group('ts')}",
                "passed": bool(payload.get("pass")),
                "score": payload.get("score"),
            }
        )
    return rows


def qa_suspect_techniques(paths: PathConfig, *, limit: int = 15) -> list[dict[str, Any]]:
    """Techniques mapped from threats in QA-rejected threat models.

    File-based twin of the ``qa_rejected_techniques`` canned query, so the
    forge cards can consume the feedback loop offline: reports operators
    rejected flag the heuristic threat→technique mappings behind them as
    suspect.
    """
    failed = {row["artifact_id"] for row in feedback_rows(paths) if not row["passed"]}
    counts: dict[str, int] = {}
    for model in threat_model_rows(paths):
        if model["artifact_id"] not in failed:
            continue
        for threat in model["threats"]:
            for tid in threat["techniques"]:
                counts[tid] = counts.get(tid, 0) + 1
    names = technique_names(paths)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [
        {"tid": tid, "name": names.get(tid, ""), "rejected_threats": count} for tid, count in ranked
    ]


def sync_workspace_to_neo4j(session, paths: PathConfig) -> dict[str, int]:
    """Write the workspace/artifact projection into an open session."""
    apps = application_rows(paths)
    models = threat_model_rows(paths)
    scenarios = scenario_rows(paths)
    feedback = feedback_rows(paths)

    session.run(
        """
        UNWIND $rows AS row
        MERGE (a:Application {aa_id: row.aa_id})
        SET a.name = row.name,
            a.swc_description = row.swc_description,
            a.solution_description = row.solution_description,
            a.owner_stream = row.owner_stream,
            a.confidentiality = row.confidentiality,
            a.integrity = row.integrity,
            a.availability = row.availability,
            a.platform = row.platform,
            a.externally_facing = row.externally_facing,
            a.dev_category = row.dev_category,
            a.cid_handling = row.cid_handling
        """,
        rows=apps,
    )
    session.run(
        """
        UNWIND $rows AS row
        MERGE (m:ThreatModel {artifact_id: row.artifact_id})
        SET m.path = row.path,
            m.created_at = row.created_at,
            m.provider = row.provider,
            m.model = row.model,
            m.dread_json = row.dread_json
        WITH row, m
        WHERE row.aa_id <> ''
        MERGE (a:Application {aa_id: row.aa_id})
        ON CREATE SET a.name = row.aa_id
        MERGE (m)-[:FOR_APP]->(a)
        """,
        rows=models,
    )
    threat_edges = [
        {"model": row["artifact_id"], **threat} for row in models for threat in row["threats"]
    ]
    session.run(
        """
        UNWIND $edges AS edge
        MERGE (t:Threat {key: edge.key})
        ON CREATE SET t.name = edge.name
        WITH edge, t
        MATCH (m:ThreatModel {artifact_id: edge.model})
        MERGE (m)-[r:RAISED]->(t)
        ON CREATE SET
            r.category = edge.category,
            r.description = edge.description,
            r.impact = edge.impact,
            r.mitigation = edge.mitigation
        """,
        edges=threat_edges,
    )
    names = technique_names(paths)
    threat_tech_edges = [
        {
            "threat": threat["key"],
            "tid": tid,
            "name": names.get(tid, ""),
            "is_sub": "." in tid,
        }
        for threat in threat_edges
        for tid in threat["techniques"]
    ]
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
        MATCH (th:Threat {key: edge.threat})
        MERGE (th)-[r:MAPS_TO]->(t)
        ON CREATE SET r.confidence = $confidence
        """,
        edges=threat_tech_edges,
        confidence=CONFIDENCE_THREAT,
    )
    session.run(
        """
        UNWIND $rows AS row
        MERGE (s:Scenario {artifact_id: row.artifact_id})
        SET s.path = row.path,
            s.title = row.title,
            s.template = row.template,
            s.created_at = row.created_at,
            s.provider = row.provider,
            s.model = row.model,
            s.complete = row.complete
        WITH row, s
        WHERE row.aa_id <> ''
        MERGE (a:Application {aa_id: row.aa_id})
        ON CREATE SET a.name = row.aa_id
        MERGE (s)-[:FOR_APP]->(a)
        """,
        rows=scenarios,
    )
    session.run(
        """
        UNWIND $rows AS row
        MATCH (s:Scenario {artifact_id: row.artifact_id})
        MATCH (m:ThreatModel {path: row.source_threat_model_path})
        MERGE (s)-[:DERIVED_FROM]->(m)
        """,
        rows=[row for row in scenarios if row["source_threat_model_path"]],
    )
    session.run(
        """
        UNWIND $rows AS row
        MATCH (s:Scenario {artifact_id: row.artifact_id})
        MATCH (c:Chain {id: row.chain_id})
        MERGE (s)-[:SELECTED_CHAIN]->(c)
        """,
        rows=[row for row in scenarios if row["chain_id"]],
    )
    session.run(
        """
        UNWIND $rows AS row
        MATCH (m:ThreatModel {artifact_id: row.artifact_id})
        SET m[row.stage + '_pass'] = row.passed,
            m[row.stage + '_score'] = row.score
        """,
        rows=feedback,
    )
    return {
        "applications": len(apps),
        "threat_models": len(models),
        "threats": len(threat_edges),
        "threat_tech_edges": len(threat_tech_edges),
        "scenarios": len(scenarios),
        "scenario_lineage": sum(1 for row in scenarios if row["source_threat_model_path"]),
        "scenario_chains": sum(1 for row in scenarios if row["chain_id"]),
        "feedback": len(feedback),
    }
