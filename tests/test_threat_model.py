import json
from pathlib import Path

import pytest

from src.config import AppConfig, PathConfig, build_inference_config
from src.threat_model import (
    STRIDE_CATEGORIES,
    ThreatModelWorkflow,
    load_cmdb_entry,
    parse_json_object,
    parse_stride_response,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.prompts = []

    def chat(self, messages, **kwargs):
        self.prompts.append(messages[-1]["content"])
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def stride_payload():
    threat = {
        "threat_name": "Credential replay",
        "description": "An attacker reuses a credential.",
        "impact": "Unauthorized access.",
        "mitigation": "Require phishing-resistant MFA.",
    }
    return {category.lower(): [threat, threat, threat] for category in STRIDE_CATEGORIES}


def test_parse_json_object_accepts_fenced_and_wrapped_json():
    assert parse_json_object('```json\n{"pass": true}\n```') == {"pass": True}
    assert parse_json_object('Result follows: {"pass": false} done') == {"pass": False}


def test_parse_stride_response_matches_categories_case_insensitively():
    parsed = parse_stride_response(json.dumps(stride_payload()))
    assert all(len(parsed[category]) == 3 for category in STRIDE_CATEGORIES)


def test_load_cmdb_entry_and_missing_id():
    entry = load_cmdb_entry(ROOT / "src" / "data", "AA123456")
    assert entry["AA ID"] == "AA123456"
    with pytest.raises(ValueError, match="No CMDB entry"):
        load_cmdb_entry(ROOT / "src" / "data", "missing")


def test_workflow_writes_model_and_feedback(tmp_path):
    final = {"system_metadata": {"aa_id": "AA123456"}, "complete": True}
    client = FakeClient(
        [
            json.dumps(stride_payload()),
            '{"pass": true}',
            '{"Risk Assessment": [{"threat": "Credential replay", "score": 8}]}',
            '{"pass": true}',
            json.dumps(final),
        ]
    )
    config = AppConfig(
        inference=build_inference_config("omlx"),
        paths=PathConfig(
            data_dir=ROOT / "src" / "data",
            prompts_dir=ROOT / "src" / "prompts",
            output_dir=tmp_path / "output",
        ),
    )
    path = ThreatModelWorkflow(config, client=client).run("AA123456")
    saved = json.loads(path.read_text())
    assert saved["system_metadata"] == final["system_metadata"]
    assert saved["complete"] is True
    assert saved["_meta"]["artifact_type"] == "threat_model"
    assert saved["_meta"]["aa_id"] == "AA123456"
    assert saved["_meta"]["artifact_id"].startswith("tm_AA123456_")
    assert saved["_meta"]["provider"] == "omlx"
    feedback = sorted((tmp_path / "output" / "feedback").glob("*.json"))
    assert len(feedback) == 3
    assert len(client.prompts) == 5


def test_stride_qa_retries_until_pass(tmp_path):
    client = FakeClient(
        [
            json.dumps(stride_payload()),
            '{"pass": false, "feedback": "add detail"}',
            json.dumps(stride_payload()),
            '{"pass": true}',
            '{"Risk Assessment": []}',
            '{"pass": true}',
            '{"complete": true}',
        ]
    )
    config = AppConfig(
        inference=build_inference_config("omlx"),
        paths=PathConfig(
            data_dir=ROOT / "src" / "data",
            prompts_dir=ROOT / "src" / "prompts",
            output_dir=tmp_path,
        ),
    )
    ThreatModelWorkflow(config, client=client).run("AA123456")
    assert "QA Feedback" in client.prompts[2]


def test_stride_qa_inference_error_enters_retry_loop(tmp_path):
    client = FakeClient(
        [
            json.dumps(stride_payload()),
            RuntimeError("temporary QA failure"),
            json.dumps(stride_payload()),
            '{"pass": true}',
            '{"Risk Assessment": []}',
            '{"pass": true}',
            '{"complete": true}',
        ]
    )
    workflow = ThreatModelWorkflow(
        AppConfig(
            inference=build_inference_config("omlx"),
            paths=PathConfig(
                data_dir=ROOT / "src" / "data",
                prompts_dir=ROOT / "src" / "prompts",
                output_dir=tmp_path,
            ),
        ),
        client=client,
    )
    workflow.run("AA123456")
    assert "temporary QA failure" in client.prompts[2]


def test_final_qa_transport_error_falls_back_to_assembled_model(tmp_path):
    client = FakeClient(
        [
            json.dumps(stride_payload()),
            '{"pass": true}',
            '{"Risk Assessment": []}',
            '{"pass": true}',
            RuntimeError("final QA unavailable"),
        ]
    )
    workflow = ThreatModelWorkflow(
        AppConfig(
            inference=build_inference_config("omlx"),
            paths=PathConfig(
                data_dir=ROOT / "src" / "data",
                prompts_dir=ROOT / "src" / "prompts",
                output_dir=tmp_path,
            ),
        ),
        client=client,
    )
    report = json.loads(workflow.run("AA123456").read_text())
    assert report["system_metadata"]["aa_id"] == "AA123456"
    assert "dread_assessment" in report
