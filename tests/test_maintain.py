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

    status = neo4j_status(Neo4jConfig(uri="bolt://127.0.0.1:1", password="nope", enabled=True))
    assert status["ready"] is False
    assert status["detail"]


FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "intel"


def test_intel_payload_merges_nvd_and_kev(tmp_path):
    from src.intel.cti import kev_cache_path
    from src.intel.nvd import import_nvd_file
    from src.maintain.neo4j_intel import build_intel_payload, cve_rows

    paths = _paths(tmp_path)
    import_nvd_file(paths, FIXTURES / "nvd_sample.json")
    cache = kev_cache_path(paths)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text((FIXTURES / "cisa_kev_sample.json").read_text(), encoding="utf-8")

    rows = {row["cve_id"]: row for row in cve_rows(paths)}
    assert "CVE-2024-0001" in rows  # NVD-only
    assert "CVE-2024-2222" in rows  # KEV-only
    kev = rows["CVE-2024-2222"]
    assert kev["in_kev"] is True
    assert kev["kev_ransomware"] == "Known"
    assert "CWE-502" in kev["cwes"]
    assert kev["techniques"]  # heuristic mapping applied
    nvd = rows["CVE-2024-0001"]
    assert nvd["in_kev"] is False
    assert nvd["cvss"] is not None

    payload = build_intel_payload(paths)
    assert payload["cwe_pairs"]
    assert payload["kev_tech_edges"]
    for edge in payload["kev_tech_edges"]:
        assert edge["tid"].startswith("T")
        assert edge["is_sub"] == ("." in edge["tid"])


def test_intel_payload_actor_and_advisory_rows(tmp_path):
    from src.intel.cti import upsert_cti_pack
    from src.maintain.neo4j_intel import actor_rows, advisory_rows

    paths = _paths(tmp_path)
    upsert_cti_pack(
        paths,
        {
            "id": "mitre-group-g9999",
            "title": "MITRE group: Test Bear (G9999)",
            "actors": ["Test Bear", "TB Alias"],
            "techniques": ["T1190", "not-a-tid", "T1059.001"],
            "notes": "fictional",
            "source": "mitre-attack-group",
        },
    )
    upsert_cti_pack(
        paths,
        {
            "id": "cisa-adv-test",
            "title": "CISA advisory: Test",
            "actors": ["russia-nexus"],
            "techniques": ["T1059"],
            "source": "cisa-advisory",
        },
    )

    actors = actor_rows(paths)
    assert len(actors) == 1
    assert actors[0]["name"] == "Test Bear"
    assert actors[0]["aliases"] == ["TB Alias"]
    assert actors[0]["techniques"] == ["T1190", "T1059.001"]  # invalid id dropped

    advisories = advisory_rows(paths)
    assert advisories[0]["nexus"] == ["russia-nexus"]
    assert advisories[0]["techniques"] == ["T1059"]


def test_canned_queries_cover_intel_layers():
    from src.maintain.neo4j_graph import CANNED_QUERIES

    assert "kev_gaps" in CANNED_QUERIES
    assert "EXPLOITS_TECHNIQUE" in CANNED_QUERIES["kev_gaps"]["cypher"]
    assert "actor_coverage" in CANNED_QUERIES
    # intel-only techniques (frequency 0) must not flood chain dark matter
    assert "frequency >= 1" in CANNED_QUERIES["dark_matter"]["cypher"]


def _workspace_fixture(paths: PathConfig) -> None:
    (paths.data_dir / "cmdb.json").write_text(
        json.dumps(
            [
                {
                    "AA ID": "AA123456",
                    "Application Name": "Payments",
                    "Externally facing": "Yes - Internet",
                    "Platform": ["Linux Platform"],
                }
            ]
        ),
        encoding="utf-8",
    )
    stride_dir = paths.output_dir / "stride"
    stride_dir.mkdir(parents=True)
    (stride_dir / "security_assessment_AA123456_20260101000000.json").write_text(
        json.dumps(
            {
                "system_metadata": {"aa_id": "AA123456"},
                "Spoofing": [
                    {
                        "threat_name": "Token Replay",
                        "description": "replay of bearer tokens",
                        "impact": "account takeover",
                        "mitigation": "short TTL",
                    }
                ],
                "dread_assessment": [
                    {
                        "Threat Type": "Spoofing",
                        "Scenario": "token replay against the API",
                        "Damage Potential": "8",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    scen_dir = paths.output_dir / "scenarios"
    scen_dir.mkdir(parents=True)
    (scen_dir / "scenario_AA123456_20260101000001.json").write_text(
        json.dumps(
            {
                "SWC_ID": "AA123456",
                "Attack_Template": "Alpha Phish",
                "Complete": "True",
                "_meta": {
                    "artifact_id": "sc_AA123456_20260101000001",
                    "aa_id": "AA123456",
                    "attack_template": "Alpha Phish",
                    "source_threat_model_path": (
                        "output/stride/security_assessment_AA123456_20260101000000.json"
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    fb_dir = paths.output_dir / "feedback"
    fb_dir.mkdir(parents=True)
    (fb_dir / "stride_feedback_AA123456_20260101000000.json").write_text(
        json.dumps({"pass": True, "score": 8}),
        encoding="utf-8",
    )


def test_cti_briefing_aggregates_and_formats(monkeypatch):
    import src.maintain.neo4j_graph as ng
    from src.config import Neo4jConfig

    def fake_run_cypher(config, query, params=None, *, limit=100):
        assert params["tids"] == ["T1059", "T1190"]
        return [
            {
                "tid": "T1190",
                "actors": ["APT28", "Lazarus"],
                "advisories": ["AA25-141A"],
                "kev_cves": ["CVE-2024-1"],
            },
            {
                "tid": "T1059",
                "actors": ["APT28"],
                "advisories": [],
                "kev_cves": ["CVE-2024-1", "CVE-2024-2"],
            },
        ]

    monkeypatch.setattr(ng, "run_cypher", fake_run_cypher)
    briefing = ng.cti_briefing(Neo4jConfig(), ["T1190", "t1059", ""])
    # ranked by technique coverage; deduped case-insensitively
    assert briefing["actors"][0] == {"name": "APT28", "techniques": ["T1059", "T1190"]}
    assert briefing["kev_cves"][0]["name"] == "CVE-2024-1"
    text = ng.format_cti_briefing(briefing)
    assert "APT28" in text and "CVE-2024-2" in text and "AA25-141A" in text
    assert ng.format_cti_briefing({"actors": [], "advisories": [], "kev_cves": []}) == ""


def test_workspace_projection_rows(tmp_path):
    from src.maintain.neo4j_workspace import (
        application_rows,
        feedback_rows,
        scenario_rows,
        threat_model_rows,
    )

    paths = _paths(tmp_path)
    _workspace_fixture(paths)

    apps = application_rows(paths)
    assert apps[0]["aa_id"] == "AA123456"
    assert apps[0]["name"] == "Payments"  # legacy CMDB keys normalized
    assert apps[0]["platform"] == ["Linux Platform"]

    models = threat_model_rows(paths)
    assert models[0]["artifact_id"] == "tm_AA123456_20260101000000"  # filename fallback
    assert models[0]["aa_id"] == "AA123456"
    assert models[0]["threats"][0]["key"] == "token-replay"
    assert models[0]["threats"][0]["category"] == "Spoofing"
    assert models[0]["dread"][0]["threat_type"] == "Spoofing"

    scenarios = scenario_rows(paths)
    assert scenarios[0]["artifact_id"] == "sc_AA123456_20260101000001"
    assert scenarios[0]["chain_id"]  # "Alpha Phish" resolved to a chain id
    assert scenarios[0]["source_threat_model_path"].endswith("000000.json")

    feedback = feedback_rows(paths)
    assert feedback == [
        {
            "stage": "stride",
            "artifact_id": "tm_AA123456_20260101000000",
            "passed": True,
            "score": 8,
        }
    ]
