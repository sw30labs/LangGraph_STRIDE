import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

import pytest

from src import gui
from src.config import AppConfig, PathConfig, build_inference_config


@pytest.fixture
def gui_workspace(tmp_path, monkeypatch):
    data = tmp_path / "data"
    prompts = tmp_path / "prompts"
    output = tmp_path / "output"
    data.mkdir()
    prompts.mkdir()
    output.mkdir()
    (data / "cmdb.json").write_text(
        json.dumps([{"AA ID": "AA1", "Application Name": "Example", "Platform": ["Linux"]}])
    )
    (data / "predefined_attack_templates.json").write_text(json.dumps({"Template": ["T1"]}))
    config = AppConfig(
        inference=build_inference_config("omlx"),
        paths=PathConfig(
            project_root=tmp_path,
            data_dir=data,
            prompts_dir=prompts,
            output_dir=output,
        ),
    )
    monkeypatch.setattr(gui, "CONFIG", config)
    gui.JOBS.clear()
    return tmp_path


def test_status_lists_data_outputs_and_jobs(gui_workspace):
    report = gui_workspace / "output" / "stride" / "report.json"
    report.parent.mkdir()
    report.write_text('{"ok": true}')
    gui.JOBS["one"] = gui.Job("one", "threat-model", ["python"])

    status = gui.status_payload()

    assert status["cmdb"][0]["aa_id"] == "AA1"
    assert status["attack_templates"][0]["name"] == "Template"
    assert status["outputs"]["stride"][0]["path"] == "output/stride/report.json"
    assert status["jobs"][0]["id"] == "one"


def test_repo_file_guard_rejects_traversal(gui_workspace, tmp_path):
    inside = gui_workspace / "report.json"
    inside.write_text("{}")
    assert gui.ensure_repo_file("report.json") == inside

    outside = tmp_path.parent / "outside.json"
    outside.write_text("{}")
    with pytest.raises(ValueError, match="stay inside"):
        gui.ensure_repo_file(str(outside))


def test_job_builders_use_canonical_cli_and_provider_alias(gui_workspace, monkeypatch):
    model_file = gui_workspace / "output" / "model.json"
    model_file.write_text("{}")

    def capture(kind, command):
        return gui.Job("test", kind, command)

    monkeypatch.setattr(gui, "start_job", capture)
    model = gui.build_model_job({"aa_id": "AA1", "provider": "mlx"})
    scenario = gui.build_scenario_job(
        {"json_file": "output/model.json", "attack_template": "Template", "provider": "mlx"}
    )
    maintain = gui.build_maintain_job(
        {
            "card": "dark_matter",
            "provider": "mlx",
            "steer": "identity-only",
            "web_spark": False,
            "max_jaccard": 0.4,
        }
    )

    assert model.command[1:5] == ["-m", "src.cli", "threat-model", "AA1"]
    assert model.command[model.command.index("--backend") + 1] == "omlx"
    assert scenario.command[1:4] == ["-m", "src.cli", "scenario"]
    assert scenario.command[scenario.command.index("--backend") + 1] == "omlx"
    assert "--data-dir" in scenario.command
    assert maintain.command[1:5] == ["-m", "src.cli", "maintain", "run"]
    assert "dark_matter" in maintain.command
    assert maintain.command[maintain.command.index("--backend") + 1] == "omlx"
    assert "--steer" in maintain.command
    assert "--no-web-spark" in maintain.command


def test_job_builders_pass_thinking_controls(gui_workspace, monkeypatch):
    model_file = gui_workspace / "output" / "model.json"
    model_file.write_text("{}")

    def capture(kind, command):
        return gui.Job("test", kind, command)

    monkeypatch.setattr(gui, "start_job", capture)
    model = gui.build_model_job(
        {
            "aa_id": "AA1",
            "provider": "openai",
            "thinking": True,
            "reasoning_strength": "medium",
        }
    )
    scenario = gui.build_scenario_job(
        {
            "json_file": "output/model.json",
            "attack_template": "Template",
            "provider": "openai",
            "thinking": False,
        }
    )

    assert "--thinking" in model.command
    assert model.command[model.command.index("--reasoning-strength") + 1] == "medium"
    assert "--no-thinking" in scenario.command
    assert "--reasoning-strength" not in scenario.command


def test_status_exposes_thinking_defaults(gui_workspace):
    status = gui.status_payload()
    assert status["thinking"]["reasoning_strengths"] == ["low", "medium", "high", "xhigh"]
    assert status["thinking"]["reasoning_strength"] in status["thinking"]["reasoning_strengths"]
    assert isinstance(status["thinking"]["enabled"], bool)
    assert "navigator" in status
    assert "counts" in status["navigator"]
    assert status["attack_templates"]
    assert "id" in status["attack_templates"][0]
    assert "techniques" in status["attack_templates"][0]


def test_cmdb_and_chain_api_mutations(gui_workspace):
    row = gui.upsert_cmdb_entry(
        gui.CONFIG.paths,
        {"aa_id": "AA000001", "name": "API App", "platform": ["Linux"]},
    )
    assert row["aa_id"] == "AA000001"
    chain = gui.upsert_chain(
        gui.CONFIG.paths,
        {"name": "GUI Chain", "steps": ["Phishing (T1566)"]},
    )
    assert chain["steps"][0]["technique_id"] == "T1566"
    status = gui.status_payload()
    assert any(item["aa_id"] == "AA000001" for item in status["cmdb"])
    assert any(item["name"] == "GUI Chain" for item in status["attack_templates"])


def test_http_status_jobs_and_static_assets(gui_workspace):
    server = ThreadingHTTPServer(("127.0.0.1", 0), gui.GuiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(f"{base}/api/status") as response:
            assert json.load(response)["cmdb"][0]["aa_id"] == "AA1"
        with urlopen(f"{base}/api/jobs") as response:
            assert json.load(response) == []
        with urlopen(f"{base}/app.js") as response:
            assert b"refreshStatus" in response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_static_asset_bundle_is_complete():
    assert {path.name for path in gui.WEB_DIR.iterdir()} == {"app.js", "index.html", "styles.css"}
