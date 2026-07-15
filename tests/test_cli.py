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
        ):
            assert option in exposed


def test_info_json_reports_resolved_provider(monkeypatch):
    monkeypatch.setenv("STRIDE_BACKEND", "vllm")
    result = runner.invoke(app, ["info", "--json"])
    assert result.exit_code == 0
    assert '"backend": "vllm"' in result.output
