"""I check that assessment and scenario JSON become real PDF files."""

from __future__ import annotations

import json
from pathlib import Path

from src.config import PathConfig
from src.export_pdf import export_artifact_pdf

ROOT = Path(__file__).resolve().parents[1]


def test_export_threat_model_pdf(tmp_path):
    artifact = tmp_path / "assessment.json"
    artifact.write_text(
        json.dumps(
            {
                "system_metadata": {
                    "aa_id": "AA1",
                    "Application Name": "Demo",
                    "Confidentiality": "High",
                },
                "Spoofing": [
                    {
                        "threat_name": "Replay",
                        "description": "Replay attack",
                        "impact": "Access",
                        "mitigation": "MFA",
                    }
                ],
                "dread_assessment": [{"Scenario": "Replay", "Damage Potential": "8"}],
                "_meta": {"artifact_type": "threat_model", "aa_id": "AA1"},
            }
        ),
        encoding="utf-8",
    )
    paths = PathConfig(project_root=tmp_path, output_dir=tmp_path / "output")
    pdf = export_artifact_pdf(artifact, paths=paths)
    data = pdf.read_bytes()
    assert data.startswith(b"%PDF")
    assert pdf.stat().st_size > 200
    assert pdf.parent.name == "exports"


def test_export_scenario_pdf(tmp_path):
    artifact = tmp_path / "scenario.json"
    artifact.write_text(
        json.dumps(
            {
                "SWC_ID": "AA1",
                "SWC_NAME": "Demo",
                "Attack_Template": "API Exposure",
                "Threat_Report": "Long narrative about the attack chain.",
                "CTI_Report": "CTI notes.",
                "CVE_Report": "CVE notes.",
                "_meta": {"artifact_type": "scenario", "aa_id": "AA1"},
            }
        ),
        encoding="utf-8",
    )
    pdf = export_artifact_pdf(artifact, paths=PathConfig(output_dir=tmp_path / "out"))
    assert pdf.read_bytes().startswith(b"%PDF")
