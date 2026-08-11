import json
from pathlib import Path

import pytest

from src.config import PathConfig
from src.workspace import (
    build_navigator,
    delete_cmdb_entry,
    format_technique_label,
    get_chain,
    get_chain_techniques,
    get_cmdb_entry,
    load_chains,
    load_cmdb,
    normalize_chain,
    parse_technique_label,
    seed_workspace,
    upsert_chain,
    upsert_cmdb_entry,
)

ROOT = Path(__file__).resolve().parents[1]


def paths(tmp_path: Path) -> PathConfig:
    return PathConfig(
        project_root=tmp_path,
        data_dir=ROOT / "src" / "data",
        prompts_dir=ROOT / "src" / "prompts",
        output_dir=tmp_path / "output",
    )


def test_parse_technique_label_extracts_mitre_id():
    step = parse_technique_label("Exploit Public-Facing Application (T1190)")
    assert step["technique_id"] == "T1190"
    assert step["name"] == "Exploit Public-Facing Application"
    assert format_technique_label(step) == "Exploit Public-Facing Application (T1190)"


def test_seed_workspace_copies_package_cmdb_and_chains(tmp_path):
    cfg = paths(tmp_path)
    seeded = seed_workspace(cfg)
    assert Path(seeded["cmdb"]).is_file()
    assert Path(seeded["attack_templates"]).is_file()
    apps = load_cmdb(cfg)
    assert len(apps) == 3
    assert apps[0]["aa_id"].startswith("AA")
    chains = load_chains(cfg)
    assert len(chains) == 27
    zero_day = get_chain(cfg, "Zero-Day Exploit [New]")
    assert zero_day["steps"]
    assert get_chain_techniques(cfg, "Zero-Day Exploit [New]")


def test_cmdb_upsert_and_delete(tmp_path):
    cfg = paths(tmp_path)
    seed_workspace(cfg)
    row = upsert_cmdb_entry(
        cfg,
        {
            "aa_id": "AA999999",
            "name": "Test App",
            "confidentiality": "High",
            "platform": ["Linux"],
        },
    )
    assert row["aa_id"] == "AA999999"
    assert get_cmdb_entry(cfg, "AA999999")["name"] == "Test App"
    delete_cmdb_entry(cfg, "AA999999")
    with pytest.raises(ValueError, match="No CMDB entry"):
        get_cmdb_entry(cfg, "AA999999")


def test_chain_upsert_normalizes_steps(tmp_path):
    cfg = paths(tmp_path)
    seed_workspace(cfg)
    chain = upsert_chain(
        cfg,
        {
            "name": "Custom Chain",
            "steps": ["Phishing (T1566)", {"technique_id": "T1059.001", "name": "PowerShell"}],
        },
    )
    assert chain["id"] == "custom-chain"
    assert chain["steps"][0]["technique_id"] == "T1566"
    assert get_chain(cfg, "custom-chain")["name"] == "Custom Chain"


def test_normalize_chain_from_legacy_map_entry():
    chain = normalize_chain("API Exposure", techniques=["Exploit Public-Facing Application (T1190)"])
    assert chain["name"] == "API Exposure"
    assert chain["steps"][0]["technique_id"] == "T1190"


def test_build_navigator_nests_models_and_scenarios(tmp_path):
    cfg = paths(tmp_path)
    seed_workspace(cfg)
    stride = cfg.output_dir / "stride"
    scenarios = cfg.output_dir / "scenarios"
    feedback = cfg.output_dir / "feedback"
    stride.mkdir(parents=True)
    scenarios.mkdir(parents=True)
    feedback.mkdir(parents=True)

    assessment = {
        "system_metadata": {"aa_id": "AA123456", "Application Name": "Payments"},
        "Spoofing": [{"threat_name": "A"}, {"threat_name": "B"}],
        "dread_assessment": [{"Damage Potential": "9"}],
        "_meta": {
            "artifact_type": "threat_model",
            "artifact_id": "tm_AA123456_20260101120000",
            "aa_id": "AA123456",
            "created_at": "2026-01-01T12:00:00+00:00",
        },
    }
    assessment_path = stride / "security_assessment_AA123456_20260101120000.json"
    assessment_path.write_text(json.dumps(assessment), encoding="utf-8")
    (feedback / "stride_feedback_AA123456_20260101120000.json").write_text(
        json.dumps({"pass": True}), encoding="utf-8"
    )
    scenario = {
        "SWC_ID": "AA123456",
        "Attack_Template": "Zero-Day Exploit [New]",
        "_meta": {
            "artifact_type": "scenario",
            "artifact_id": "sc_AA123456_20260101130000",
            "aa_id": "AA123456",
            "source_threat_model_id": "tm_AA123456_20260101120000",
            "source_threat_model_path": str(assessment_path.relative_to(tmp_path)),
            "attack_template": "Zero-Day Exploit [New]",
            "created_at": "2026-01-01T13:00:00+00:00",
        },
    }
    (scenarios / "Zero-Day_AA123456_20260101130000.json").write_text(
        json.dumps(scenario), encoding="utf-8"
    )

    nav = build_navigator(cfg)
    assert nav["counts"]["threat_models"] >= 1
    assert nav["counts"]["scenarios"] >= 1
    app = next(item for item in nav["applications"] if item["aa_id"] == "AA123456")
    model = app["threat_models"][0]
    assert model["artifact_id"] == "tm_AA123456_20260101120000"
    assert model["threat_count"] == 2
    assert model["max_dread"] == 9.0
    assert model["scenarios"][0]["attack_template"] == "Zero-Day Exploit [New]"
    assert model["feedback"][0]["kind"] == "stride"
