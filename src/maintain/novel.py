"""Novel attack-chain forge: graph constraints + LLM draft + LLM judge loop."""

from __future__ import annotations

import csv
import json
from typing import Any

from src.config import AppConfig
from src.inference_client import OpenAICompatibleClient, client_from_config
from src.intel.mitre import search_techniques
from src.maintain.graph import (
    build_chain_graph,
    candidate_keys_from_steps,
    jaccard,
    kill_chain_progression_score,
    library_fingerprint,
    max_jaccard_against_library,
    normalize_technique_id,
    write_maintain_artifact,
)
from src.maintain.research import default_search_query, duckduckgo_spark, format_sparks_for_prompt
from src.threat_model import parse_json_object
from src.workspace import get_cmdb_entry, load_cmdb, normalize_chain, now_iso, package_data_dir


def _stage(name: str) -> None:
    print(f"STAGE: {name}", flush=True)


def _ask(client: OpenAICompatibleClient, config: AppConfig, prompt: str) -> str:
    return client.chat(
        [{"role": "user", "content": prompt}],
        max_tokens=config.inference.max_tokens,
        disable_thinking=config.inference.disable_thinking,
        reasoning_strength=config.inference.reasoning_strength,
        require_complete=True,
    )


def _load_controls_summary(limit: int = 24) -> list[dict[str, str]]:
    path = package_data_dir() / "control_taxonomy.csv"
    if not path.is_file():
        return []
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(
                {
                    "id": str(row.get("ID") or ""),
                    "topic": str(row.get("Topic") or ""),
                    "title": str(row.get("Title") or ""),
                    "description": str(row.get("Description") or "")[:220],
                }
            )
            if len(rows) >= limit:
                break
    return rows


def _mitre_hints(paths, query: str = "", limit: int = 40) -> list[dict[str, Any]]:
    try:
        return search_techniques(paths, query, limit=limit)
    except Exception:
        return []


def _normalize_candidate(raw: dict[str, Any], *, source: str) -> dict[str, Any]:
    steps_in = raw.get("steps") or raw.get("techniques") or []
    steps: list[dict[str, Any]] = []
    for item in steps_in:
        if isinstance(item, str):
            steps.append({"raw": item, "name": item, "technique_id": normalize_technique_id(item)})
        elif isinstance(item, dict):
            tid = normalize_technique_id(item.get("technique_id")) or normalize_technique_id(
                str(item.get("raw") or item.get("name") or "")
            )
            name = str(item.get("name") or item.get("raw") or "").strip()
            if tid and name.endswith(f"({tid})"):
                name = name[: -len(tid) - 2].strip()
            steps.append(
                {
                    "technique_id": tid,
                    "name": name,
                    "tactic": item.get("tactic"),
                    "raw": item.get("raw")
                    or (f"{name} ({tid})" if tid and name else name or tid or ""),
                }
            )
    chain = normalize_chain(
        {
            "name": str(raw.get("name") or "Untitled Novel Chain").strip(),
            "description": str(raw.get("description") or "").strip(),
            "tags": list(raw.get("tags") or []) + ["maintain-forge", source],
            "steps": steps,
            "source": source,
        }
    )
    return chain


def deterministic_gate(
    chain: dict[str, Any],
    paths,
    *,
    max_jaccard: float,
) -> dict[str, Any]:
    keys = candidate_keys_from_steps(chain.get("steps") or [])
    best, rival = max_jaccard_against_library(keys, paths)
    progression = kill_chain_progression_score(chain.get("steps") or [])
    reasons: list[str] = []
    ok = True
    if len(keys) < 5:
        ok = False
        reasons.append(f"too few techniques ({len(keys)}); need at least 5")
    if len(keys) > 22:
        ok = False
        reasons.append(f"too many techniques ({len(keys)}); keep the chain operable (≤22)")
    if best > max_jaccard:
        ok = False
        reasons.append(
            f"Jaccard {best:.3f} vs existing chain '{rival}' exceeds max {max_jaccard:.3f}"
        )
    if progression < 0.45:
        ok = False
        reasons.append(f"weak kill-chain progression score {progression:.2f}")
    # Prefer real technique IDs
    with_ids = sum(1 for step in chain.get("steps") or [] if step.get("technique_id"))
    if with_ids < max(3, len(keys) // 2):
        ok = False
        reasons.append("prefer concrete MITRE technique IDs on most steps")
    return {
        "pass": ok,
        "max_jaccard": round(best, 4),
        "nearest_chain": rival,
        "progression": round(progression, 4),
        "technique_count": len(keys),
        "reasons": reasons,
    }


def judge_prompt(
    chain: dict[str, Any],
    fingerprints: list[dict[str, Any]],
    gate: dict[str, Any],
) -> str:
    return f"""You are a red-team library curator and adversarial novelty judge.

Decide whether this candidate attack template is worth adding to a threat-modeling library.

Hard requirements:
1. NOVEL vs the existing library fingerprints (not a slight remix of the same technique mix).
2. Operationally coherent kill chain (recon/access → exec/persist → actions on objectives).
3. Realistic adversary tradecraft (no fantasy zero-days as the only plot; prefer abuse of
   trust, identity, supply chain, cloud control planes, OT bridges, AI/ML supply when claimed).
4. Steps must be distinct and purposeful — not a kitchen-sink of popular T-codes.

Existing library fingerprints (technique key sets):
{json.dumps(fingerprints, indent=2)[:12000]}

Deterministic gate already ran:
{json.dumps(gate, indent=2)}

Candidate:
{json.dumps(chain, indent=2)[:12000]}

Respond with ONLY a JSON object:
{{
  "pass": true/false,
  "novelty": 0.0-1.0,
  "realism": 0.0-1.0,
  "coherence": 0.0-1.0,
  "non_duplication": 0.0-1.0,
  "summary": "one paragraph",
  "critique": ["actionable fix 1", "fix 2"],
  "nearest_existing": "name or id if any"
}}

Set pass=true only if novelty>=0.72 AND realism>=0.65 AND coherence>=0.7 AND non_duplication>=0.75.
"""


def draft_prompt(
    *,
    mode: str,
    graph: dict[str, Any],
    fingerprints: list[dict[str, Any]],
    steer: str,
    sparks: list[dict[str, str]],
    extra_context: dict[str, Any],
    critique: list[str] | None,
    max_jaccard: float,
) -> str:
    mode_brief = {
        "dark_matter": (
            "Build a chain that deliberately combines DARK-MATTER pairs (techniques that "
            "never co-occur in this library) and rare nodes. Avoid the overused "
            "phishing→PowerShell→LSASS→exfil stencil."
        ),
        "control_counter": (
            "Design a chain that routes around the densest enterprise control clusters "
            "in the control taxonomy. Prefer trusted-path abuse, identity federation, "
            "ticket/process gaps, and living-off-the-land over 'disable antivirus'."
        ),
        "app_adversary": (
            "Shape the chain to the specific CMDB application profile (platforms, facing, "
            "data sensitivity). Do not emit a generic ransomware chain unless the app "
            "profile actually warrants impact-via-encryption."
        ),
        "blind_spot_fill": (
            "You MUST meaningfully cover the weak/missing tactics listed. The library is "
            "blind there. Do not pad with redundant initial-access clones."
        ),
        "kev_forge": (
            "Anchor the chain on the listed CISA KEV technique gaps — techniques "
            "actively exploited in the wild that this library does not simulate yet. "
            "Build the intrusion the way real operators chain those techniques; the "
            "novelty gate still applies, so do not stop at a single-gap stencil."
        ),
    }.get(mode, "Invent a novel attack chain.")

    common = json.dumps(graph.get("technique_frequency", [])[:10], indent=2)
    return f"""You are a senior adversary simulation designer for MITRE ATT&CK templates.

Mission mode: {mode}
{mode_brief}

Novelty bar:
- Maximum technique-set Jaccard vs any existing chain: {max_jaccard}
- Prefer rare techniques and never-together pairs from the graph analytics
- Do not produce slight combinations of almost the same mix already in the library
- Exhaust internal adversarial knowledge; external sparks are optional hints only

Optional operator steer (DIRECTED if non-empty):
{steer.strip() or "(none — undirected forge)"}

Graph analytics (truncated):
dark_matter_pairs: {json.dumps(graph.get("dark_matter_pairs", [])[:12], indent=2)}
rare_techniques: {json.dumps(graph.get("rare_techniques", [])[:12], indent=2)}
weak_tactics: {json.dumps(graph.get("weak_tactics", []), indent=2)}
common_techniques_to_avoid_overusing: {common}

QA feedback signal: these techniques sit behind threat-model reports that
failed QA — their threat→technique mappings are operator-rejected. If you use
one, make that step's rationale explicit and specific.
qa_suspect_techniques: {json.dumps(extra_context.get("qa_suspect_techniques") or [])}

Existing library fingerprints (do not remix these sets):
{json.dumps(fingerprints, indent=2)[:10000]}

Extra context:
{json.dumps(extra_context, indent=2)[:8000]}

External sparks (optional, may be empty/noisy):
{format_sparks_for_prompt(sparks)}

Prior judge critique to fix (if any):
{json.dumps(critique or [], indent=2)}

Return ONLY a JSON object:
{{
  "name": "distinctive campaign-style name",
  "description": "2-4 sentences on adversary goal and twist",
  "tags": ["tag1", "tag2"],
  "novelty_thesis": "why this is not a slight remix",
  "steps": [
    {{
      "tactic": "initial-access",
      "technique_id": "Txxxx or Txxxx.xxx",
      "name": "Technique Name",
      "rationale": "why this step earns its place"
    }}
  ]
}}

Constraints on steps:
- 6 to 14 steps
- Include technique_id whenever you know a real ATT&CK ID
- Tactics should progress through the kill chain
- Every step needs a purpose; no filler
"""


def forge_novel_chain(
    config: AppConfig,
    *,
    mode: str,
    steer: str = "",
    max_jaccard: float = 0.45,
    web_spark: bool = False,
    aa_id: str | None = None,
    client: OpenAICompatibleClient | None = None,
) -> dict[str, Any]:
    """Generate a novel chain with deterministic gates + LLM judge retries."""
    client = client or client_from_config(config.inference)
    paths = config.paths

    _stage("build_graph")
    graph = build_chain_graph(paths)
    fingerprints = library_fingerprint(paths)

    extra: dict[str, Any] = {"mode": mode}
    if mode == "control_counter":
        _stage("load_controls")
        extra["controls"] = _load_controls_summary()
    if mode == "app_adversary":
        _stage("load_cmdb")
        if not aa_id:
            cmdb = load_cmdb(paths)
            if not cmdb:
                raise ValueError("CMDB is empty — add an application first")
            aa_id = str(cmdb[0].get("aa_id") or cmdb[0].get("AA ID") or "")
        extra["application"] = get_cmdb_entry(paths, str(aa_id))
    if mode == "blind_spot_fill":
        extra["blind_tactics"] = graph.get("blind_tactics") or []
        extra["weak_tactics"] = graph.get("weak_tactics") or []
    if mode == "kev_forge":
        _stage("kev_gaps")
        from src.maintain.neo4j_intel import kev_gap_rows

        extra["kev_gaps"] = kev_gap_rows(paths)
        if not extra["kev_gaps"]:
            raise ValueError("No KEV gaps — ingest the CISA KEV catalog first")

    _stage("mitre_hints")
    extra["mitre_sample"] = _mitre_hints(paths, limit=30)

    from src.maintain.neo4j_workspace import qa_suspect_techniques

    extra["qa_suspect_techniques"] = qa_suspect_techniques(paths)

    sparks: list[dict[str, str]] = []
    if web_spark:
        _stage("web_spark")
        sparks = duckduckgo_spark(default_search_query(mode, steer))

    critique: list[str] = []
    attempts: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    max_attempts = config.workflow.qa_attempts

    for attempt in range(1, max_attempts + 1):
        _stage(f"draft_attempt_{attempt}")
        prompt = draft_prompt(
            mode=mode,
            graph=graph,
            fingerprints=fingerprints,
            steer=steer,
            sparks=sparks,
            extra_context=extra,
            critique=critique,
            max_jaccard=max_jaccard,
        )
        try:
            raw_text = _ask(client, config, prompt)
            raw = parse_json_object(raw_text)
        except Exception as exc:
            attempts.append({"attempt": attempt, "error": f"draft_parse: {exc}"})
            critique = [f"Previous draft failed to parse as JSON: {exc}"]
            continue

        chain = _normalize_candidate(raw, source=f"maintain:{mode}")
        gate = deterministic_gate(chain, paths, max_jaccard=max_jaccard)

        _stage(f"judge_attempt_{attempt}")
        try:
            judge_text = _ask(client, config, judge_prompt(chain, fingerprints, gate))
            judgment = parse_json_object(judge_text)
        except Exception as exc:
            judgment = {
                "pass": False,
                "error": str(exc),
                "critique": ["Judge response was not valid JSON"],
            }

        # Absolute floor: deterministic gate must pass for overall pass
        overall_pass = bool(gate.get("pass")) and bool(judgment.get("pass"))
        record = {
            "attempt": attempt,
            "gate": gate,
            "judgment": judgment,
            "pass": overall_pass,
            "chain": chain,
            "novelty_thesis": raw.get("novelty_thesis"),
        }
        attempts.append(record)
        if best is None or (
            (gate.get("max_jaccard", 1) < best.get("gate", {}).get("max_jaccard", 1))
            and gate.get("technique_count", 0) >= 5
        ):
            best = record
        if overall_pass:
            best = record
            break

        critique = list(judgment.get("critique") or [])
        critique.extend(gate.get("reasons") or [])
        if not critique:
            critique = ["Increase structural novelty and reduce overlap with library fingerprints."]

    accepted = bool(best and best.get("pass"))
    result = {
        "card": mode,
        "accepted": accepted,
        "steer": steer,
        "directed": bool(steer.strip()),
        "max_jaccard": max_jaccard,
        "web_spark_used": web_spark,
        "sparks": sparks,
        "attempts": [
            {
                "attempt": row.get("attempt"),
                "pass": row.get("pass"),
                "gate": row.get("gate"),
                "judgment": {
                    k: v
                    for k, v in (row.get("judgment") or {}).items()
                    if k
                    in {
                        "pass",
                        "novelty",
                        "realism",
                        "coherence",
                        "non_duplication",
                        "summary",
                        "critique",
                        "error",
                    }
                },
                "chain_name": (row.get("chain") or {}).get("name"),
            }
            for row in attempts
        ],
        "proposal": best.get("chain") if best else None,
        "gate": best.get("gate") if best else None,
        "judgment": best.get("judgment") if best else None,
        "novelty_thesis": best.get("novelty_thesis") if best else None,
        "graph_summary": {
            "counts": graph.get("counts"),
            "weak_tactics": graph.get("weak_tactics"),
            "dark_matter_pairs": (graph.get("dark_matter_pairs") or [])[:8],
        },
        "committed": False,
        "created_at": now_iso(),
    }

    _stage("persist_proposal")
    path = write_maintain_artifact(paths, f"proposal_{mode}", result)
    result["artifact_path"] = str(path)
    if accepted:
        print(f"RESULT: accepted proposal → {path}", flush=True)
    else:
        print(f"RESULT: no proposal passed gates → {path}", flush=True)
    return result


def score_candidate_overlap(
    steps: list[dict[str, Any]],
    other_steps: list[dict[str, Any]],
) -> float:
    return jaccard(
        candidate_keys_from_steps(steps),
        candidate_keys_from_steps(other_steps),
    )
