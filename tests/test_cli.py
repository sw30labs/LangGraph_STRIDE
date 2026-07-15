from typer.main import get_command
from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()


def test_cli_exposes_ported_and_contract_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("threat-model", "scenario", "info", "models", "smoke-inference", "serve"):
        assert command in result.output


def test_direct_inference_commands_expose_neutral_and_provider_aliases():
    for command in ("models", "smoke-inference"):
        click_command = get_command(app).commands[command]
        exposed = {option for parameter in click_command.params for option in parameter.opts}
        for option in (
            "--inference-url",
            "--vllm-url",
            "--omlx-url",
            "--inference-model",
            "--vllm-model",
            "--omlx-model",
            "--inference-api-key",
            "--vllm-api-key",
            "--omlx-api-key",
            "--device",
            "--batch-size",
        ):
            assert option in exposed


def test_info_json_reports_resolved_provider(monkeypatch):
    monkeypatch.setenv("STRIDE_BACKEND", "vllm")
    result = runner.invoke(app, ["info", "--json"])
    assert result.exit_code == 0
    assert '"backend": "vllm"' in result.output


def test_threat_model_can_start_metrics_on_explicit_port(monkeypatch, tmp_path):
    started = []

    class FakeWorkflow:
        def __init__(self, config):
            self.config = config

        def run(self, aa_id):
            assert aa_id == "AA123456"
            return tmp_path / "report.json"

    monkeypatch.setattr("src.cli.ThreatModelWorkflow", FakeWorkflow)
    monkeypatch.setattr("src.cli.start_http_server", started.append)
    result = runner.invoke(app, ["threat-model", "AA123456", "--metrics-port", "9108"])
    assert result.exit_code == 0
    assert started == [9108]


def test_threat_model_honors_metrics_port_from_environment(monkeypatch, tmp_path):
    started = []

    class FakeWorkflow:
        def __init__(self, config):
            assert config.inference.device == "cpu"
            assert config.inference.concurrency == 6

        def run(self, aa_id):
            return tmp_path / f"{aa_id}.json"

    monkeypatch.setenv("STRIDE_METRICS_PORT", "9109")
    monkeypatch.setattr("src.cli.ThreatModelWorkflow", FakeWorkflow)
    monkeypatch.setattr("src.cli.start_http_server", started.append)
    result = runner.invoke(
        app,
        ["threat-model", "AA123456", "--device", "cpu", "--batch-size", "6"],
    )
    assert result.exit_code == 0
    assert started == [9109]
