"""Dispatch Maintain studio cards to deterministic or LLM-backed runners."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.config import AppConfig
from src.inference_client import OpenAICompatibleClient
from src.maintain.cards import get_card
from src.maintain.graph import build_chain_graph, clone_pairs, write_maintain_artifact
from src.maintain.neo4j_graph import (
    neo4j_status,
    sync_library_to_neo4j,
    try_sync_after_build,
    visualization_payload,
)
from src.maintain.novel import forge_novel_chain
from src.workspace import now_iso, upsert_chain


def _stage(name: str) -> None:
    print(f"STAGE: {name}", flush=True)


def run_technique_galaxy(config: AppConfig) -> dict[str, Any]:
    _stage("technique_galaxy")
    graph = visualization_payload(config.paths, neo=config.neo4j)
    _stage("neo4j_sync")
    neo = try_sync_after_build(config, graph)
    graph["neo4j"] = neo4j_status(config.neo4j) if neo.get("synced") else graph.get("neo4j") or neo
    # Drop bulky fingerprints from the artifact written to disk
    artifact_body = {k: v for k, v in graph.items() if k != "fingerprints"}
    path = write_maintain_artifact(config.paths, "technique_galaxy", artifact_body)
    return {
        "card": "technique_galaxy",
        "accepted": True,
        "artifact_path": str(path),
        "graph": graph,
        "neo4j": graph.get("neo4j"),
        "created_at": now_iso(),
    }


def run_neo4j_sync(config: AppConfig, *, force: bool = False) -> dict[str, Any]:
    _stage("neo4j_sync")
    # Ensure analytics sqlite exists even if Neo4j is down.
    build_chain_graph(config.paths)
    result = sync_library_to_neo4j(config, force=force)
    result["status"] = neo4j_status(config.neo4j)
    return result


def run_clone_autopsy(config: AppConfig, *, threshold: float = 0.55) -> dict[str, Any]:
    _stage("clone_autopsy")
    pairs = clone_pairs(config.paths, threshold=threshold)
    payload = {
        "card": "clone_autopsy",
        "accepted": True,
        "threshold": threshold,
        "pair_count": len(pairs),
        "pairs": pairs,
        "created_at": now_iso(),
    }
    path = write_maintain_artifact(config.paths, "clone_autopsy", payload)
    payload["artifact_path"] = str(path)
    print(f"RESULT: {len(pairs)} pair(s) at threshold {threshold} → {path}", flush=True)
    return payload


def run_maintain_card(
    config: AppConfig,
    card_id: str,
    *,
    steer: str = "",
    max_jaccard: float = 0.45,
    web_spark: bool = False,
    aa_id: str | None = None,
    threshold: float = 0.55,
    commit: bool = False,
    client: OpenAICompatibleClient | None = None,
) -> dict[str, Any]:
    """Run one Maintain card and optionally commit an accepted forge to the library."""
    card = get_card(card_id)

    if card_id == "technique_galaxy":
        return run_technique_galaxy(config)
    if card_id == "clone_autopsy":
        return run_clone_autopsy(config, threshold=threshold)

    if not card.get("llm"):
        raise ValueError(f"Card {card_id} has no runner")

    result = forge_novel_chain(
        config,
        mode=card_id,
        steer=steer,
        max_jaccard=max_jaccard,
        web_spark=web_spark,
        aa_id=aa_id,
        client=client,
    )

    if commit and result.get("accepted") and result.get("proposal"):
        _stage("commit_chain")
        saved = upsert_chain(config.paths, result["proposal"])
        result["committed"] = True
        result["committed_chain"] = saved
        build_chain_graph(config.paths)
        print(f"RESULT: committed chain {saved['id']}", flush=True)

    return result


def commit_proposal_file(config: AppConfig, proposal_path: str) -> dict[str, Any]:
    """Commit a previously forged proposal JSON into the attack-template library."""
    path = Path(proposal_path)
    if not path.is_file():
        alt = config.paths.project_root / proposal_path
        path = alt if alt.is_file() else path
    if not path.is_file():
        raise ValueError(f"Proposal not found: {proposal_path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    proposal = payload.get("proposal") if isinstance(payload, dict) else None
    if not isinstance(proposal, dict):
        raise ValueError("Proposal file has no proposal object")
    if payload.get("accepted") is False:
        raise ValueError("Refusing to commit a proposal that failed novelty gates")
    saved = upsert_chain(config.paths, proposal)
    build_chain_graph(config.paths)
    return {"committed_chain": saved, "from": str(path)}
