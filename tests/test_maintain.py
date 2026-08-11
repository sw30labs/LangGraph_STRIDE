"""Maintain studio: graph analytics, novelty gates, card catalog."""

from __future__ import annotations

import json
from pathlib import Path

from src.config import AppConfig, PathConfig, build_inference_config
from src.maintain.cards import CARD_CATALOG, get_card
from src.maintain.graph import (
    build_chain_graph,
    clone_pairs,
    kill_chain_progression_score,
)
from src.maintain.novel import deterministic_gate
from src.maintain.workflows import run_maintain_card
from src.workspace import normalize_chain, seed_attack_templates


def _paths(tmp_path: Path) -> PathConfig:
    data = tmp_path / "data"
    data.mkdir()
    (data / "predefined_attack_templates.json").write_text(
        json.dumps(
            {
                "Alpha Phish": [
                    "Phishing (T1566)",
                    "Command and Scripting Interpreter: PowerShell (T1059.001)",
                    "OS Credential Dumping: LSASS Memory (T1003.001)",
                    "Exfiltration Over C2 Channel (T1041)",
                    "Valid Accounts (T1078)",
                ],
                "Alpha Remix": [
                    "Phishing (T1566)",
                    "PowerShell (T1059.001)",
                    "LSASS Memory (T1003.001)",
                    "Exfiltration Over C2 Channel (T1041)",
                    "Valid Accounts (T1078)",
                    "Scheduled Task/Job (T1053)",
                ],
                "Cloud Oddity": [
                    "Cloud Service Discovery (T1526)",
                    "Valid Accounts (T1078)",
                    "Data from Cloud Storage (T1530)",
                    "Account Manipulation (T1098)",
                    "Impair Defenses (T1562)",
                ],
            }
        )
    )
    return PathConfig(
        project_root=tmp_path,
        data_dir=data,
        prompts_dir=tmp_path / "prompts",
        output_dir=tmp_path / "output",
    )


def test_jaccard_and_clone_detection(tmp_path):
    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    pairs = clone_pairs(paths, threshold=0.5)
    assert pairs
    assert pairs[0]["jaccard"] >= 0.5
    names = {pairs[0]["a_name"], pairs[0]["b_name"]}
    assert "Alpha Phish" in names
    assert "Alpha Remix" in names


def test_technique_galaxy_builds_sqlite_and_heatmap(tmp_path):
    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    graph = build_chain_graph(paths)
    assert graph["counts"]["chains"] == 3
    assert graph["counts"]["techniques"] >= 5
    assert graph["heatmap"]["chains"]
    assert graph["dark_matter_pairs"] is not None
    assert (paths.output_dir / "workspace" / "attack_graph.sqlite").is_file()


def test_deterministic_gate_rejects_library_clone(tmp_path):
    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    chain = normalize_chain(
        {
            "name": "Clone Attempt",
            "steps": [
                {"technique_id": "T1566", "name": "Phishing", "tactic": "initial-access"},
                {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
                {"technique_id": "T1003.001", "name": "LSASS", "tactic": "credential-access"},
                {"technique_id": "T1041", "name": "Exfil C2", "tactic": "exfiltration"},
                {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "persistence"},
            ],
        }
    )
    gate = deterministic_gate(chain, paths, max_jaccard=0.45)
    assert gate["pass"] is False
    assert gate["max_jaccard"] > 0.45


def test_deterministic_gate_accepts_novel_progression(tmp_path):
    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    chain = normalize_chain(
        {
            "name": "OT Historian Whisper",
            "steps": [
                {
                    "technique_id": "T1195.002",
                    "name": "Compromise Software Supply Chain",
                    "tactic": "initial-access",
                },
                {
                    "technique_id": "T0883",
                    "name": "Internet Accessible Device",
                    "tactic": "initial-access",
                },
                {
                    "technique_id": "T0859",
                    "name": "Valid Accounts ICS",
                    "tactic": "persistence",
                },
                {
                    "technique_id": "T0846",
                    "name": "Remote System Discovery",
                    "tactic": "discovery",
                },
                {
                    "technique_id": "T0801",
                    "name": "Monitor Process State",
                    "tactic": "collection",
                },
                {
                    "technique_id": "T0889",
                    "name": "Modify Program",
                    "tactic": "impact",
                },
            ],
        }
    )
    gate = deterministic_gate(chain, paths, max_jaccard=0.45)
    assert gate["technique_count"] >= 5
    assert gate["max_jaccard"] < 0.45
    assert gate["pass"] is True


def test_card_catalog_contains_flagship_cards():
    ids = {card["id"] for card in CARD_CATALOG}
    assert "dark_matter" in ids
    assert "clone_autopsy" in ids
    assert "technique_galaxy" in ids
    assert get_card("dark_matter")["llm"] is True


def test_run_offline_cards(tmp_path):
    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    config = AppConfig(inference=build_inference_config("omlx"), paths=paths)
    galaxy = run_maintain_card(config, "technique_galaxy")
    assert galaxy["accepted"] is True
    assert galaxy["graph"]["counts"]["chains"] == 3
    autopsy = run_maintain_card(config, "clone_autopsy", threshold=0.5)
    assert autopsy["pair_count"] >= 1
    assert Path(autopsy["artifact_path"]).is_file()


def test_kill_chain_progression_scores_advancing_tactics():
    steps = [
        {"tactic": "initial-access"},
        {"tactic": "execution"},
        {"tactic": "credential-access"},
        {"tactic": "exfiltration"},
    ]
    assert kill_chain_progression_score(steps) == 1.0
    messy = [{"tactic": "impact"}, {"tactic": "initial-access"}]
    assert kill_chain_progression_score(messy) < 0.5


def test_force_layout_and_visualization_payload(tmp_path):
    from src.maintain.neo4j_graph import force_layout, visualization_payload

    paths = _paths(tmp_path)
    seed_attack_templates(paths, force=True)
    laid = force_layout(
        [
            {"id": "a", "label": "A", "weight": 2},
            {"id": "b", "label": "B", "weight": 1},
            {"id": "c", "label": "C", "weight": 3},
        ],
        [{"source": "a", "target": "b", "weight": 1}, {"source": "b", "target": "c", "weight": 2}],
        iterations=20,
    )
    assert len(laid) == 3
    assert all("x" in node and "y" in node for node in laid)

    viz = visualization_payload(paths, neo=None)
    assert "layouts" in viz
    assert viz["layouts"]["cooccurrence"]["nodes"]
    assert viz["layouts"]["bipartite"]["edges"] is not None


def test_neo4j_status_does_not_raise_when_down():
    from src.config import Neo4jConfig
    from src.maintain.neo4j_graph import neo4j_status

    status = neo4j_status(
        Neo4jConfig(uri="bolt://127.0.0.1:1", password="nope", enabled=True)
    )
    assert status["ready"] is False
    assert status["detail"]
