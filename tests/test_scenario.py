import json
from pathlib import Path

import pytest

from src.config import AppConfig, PathConfig, build_inference_config
from src.scenario import ScenarioWorkflow, load_controls

ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.prompts = []

    def chat(self, messages, **kwargs):
        self.prompts.append(messages[-1]["content"])
        return next(self.responses)


def source_model(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "system_metadata": {
                    "aa_id": "AA123456",
                    "Application Name": "Payments",
                    "SWC Description": "Payment service",
                    "Solution Description": "Processes payments",
                    "Platform": ["Linux", "llama.cpp"],
                    "Confidentiality": "High",
                    "Integrity": "High",
                },
                "Spoofing": [{"threat_name": "Replay"}],
                "dread_assessment": [{"threat": "Replay", "score": 8}],
            }
        ),
        encoding="utf-8",
    )


def config(tmp_path):
    return AppConfig(
        inference=build_inference_config("omlx"),
        paths=PathConfig(
            data_dir=ROOT / "data",
            prompts_dir=ROOT / "prompts",
            output_dir=tmp_path / "output",
        ),
    )


def test_public_scenario_assets_are_complete():
    templates = json.loads((ROOT / "data" / "predefined_attack_templates.json").read_text())
    vulnerabilities = json.loads((ROOT / "data" / "demo_critical_vulnerability.json").read_text())
    assert len(templates) == 27
    assert len(vulnerabilities) == 1
    # The source contains 20 rows and 19 unique IDs; its dict loader keeps the latter.
    assert len(load_controls(ROOT / "data" / "control_taxonomy.csv")) == 19


def test_workflow_generates_all_reports_and_uses_platform_field(tmp_path):
    model = tmp_path / "model.json"
    source_model(model)
    client = FakeClient(["CVE report", "CTI report", "Threat scenario report"])
    workflow = ScenarioWorkflow(config(tmp_path), client=client)
    path = workflow.run(model, "Zero-Day Exploit [New]", min_cvss=9.1)
    report = json.loads(path.read_text())
    assert report["Complete"] is True
    assert report["CVE_Report"] == "CVE report"
    assert report["CTI_Report"] == "CTI report"
    assert report["Threat_Report"] == "Threat scenario report"
    assert report["customer_platforms_supporting_the_customer_Application"] == "Linux"
    assert len(client.prompts) == 3


def test_attack_template_is_required(tmp_path):
    model = tmp_path / "model.json"
    source_model(model)
    workflow = ScenarioWorkflow(config(tmp_path), client=FakeClient([]))
    with pytest.raises(ValueError, match="required"):
        workflow.run(model, "")


def test_missing_system_metadata_is_rejected(tmp_path):
    model = tmp_path / "model.json"
    model.write_text("{}")
    workflow = ScenarioWorkflow(config(tmp_path), client=FakeClient([]))
    with pytest.raises(ValueError, match="system_metadata"):
        workflow.run(model, "Zero-Day Exploit [New]")
