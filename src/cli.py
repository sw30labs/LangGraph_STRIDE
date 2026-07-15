"""Command-line interface for LangGraph STRIDE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from prometheus_client import start_http_server

from src.config import AppConfig, PathConfig, WorkflowConfig, build_inference_config
from src.inference_client import client_from_config
from src.scenario import ScenarioWorkflow
from src.threat_model import ThreatModelWorkflow

app = typer.Typer(no_args_is_help=True, add_completion=False)

BackendOption = Annotated[str | None, typer.Option("--backend", help="vllm, omlx/mlx, or openai")]
UrlOption = Annotated[
    str | None,
    typer.Option("--inference-url", "--vllm-url", "--omlx-url", help="OpenAI-compatible API URL"),
]
ModelOption = Annotated[
    str | None,
    typer.Option("--inference-model", "--vllm-model", "--omlx-model", help="Served model id"),
]
KeyOption = Annotated[
    str | None,
    typer.Option(
        "--inference-api-key", "--vllm-api-key", "--omlx-api-key", help="Endpoint API key"
    ),
]


def _inference(backend: str | None, url: str | None, key: str | None, model: str | None):
    return build_inference_config(backend, base_url=url, api_key=key, model=model)


@app.command()
def info(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Show resolved platform and inference defaults."""
    config = AppConfig()
    payload = config.model_dump(mode="json")
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(
        f"backend={config.inference.backend.value} device={config.inference.device} "
        f"concurrency={config.inference.concurrency} model={config.inference.model}"
    )


@app.command()
def models(
    backend: BackendOption = None,
    inference_url: UrlOption = None,
    inference_model: ModelOption = None,
    inference_api_key: KeyOption = None,
) -> None:
    """List models served by an OpenAI-compatible endpoint."""
    config = _inference(backend, inference_url, inference_api_key, inference_model)
    for model_id in client_from_config(config).list_models():
        typer.echo(model_id)


@app.command("smoke-inference")
def smoke_inference(
    backend: BackendOption = None,
    inference_url: UrlOption = None,
    inference_model: ModelOption = None,
    inference_api_key: KeyOption = None,
) -> None:
    """Send one small request through the same inference seam as the workflows."""
    config = _inference(backend, inference_url, inference_api_key, inference_model)
    result = client_from_config(config).chat(
        [{"role": "user", "content": "langgraph-stride smoke"}],
        max_tokens=64,
        disable_thinking=False,
        require_complete=True,
    )
    typer.echo(result)


@app.command("threat-model")
def threat_model(
    aa_id: Annotated[str, typer.Argument(help="Application AA ID from the CMDB sample")],
    backend: BackendOption = None,
    inference_url: UrlOption = None,
    inference_model: ModelOption = None,
    inference_api_key: KeyOption = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
    prompts_dir: Annotated[Path | None, typer.Option("--prompts-dir")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    metrics_port: Annotated[int | None, typer.Option("--metrics-port", min=1, max=65_535)] = None,
) -> None:
    """Generate a STRIDE model and DREAD assessment for one application."""
    config = AppConfig(
        inference=_inference(backend, inference_url, inference_api_key, inference_model),
        paths=PathConfig(
            data_dir=data_dir or PathConfig().data_dir,
            prompts_dir=prompts_dir or PathConfig().prompts_dir,
            output_dir=output_dir or PathConfig().output_dir,
        ),
        workflow=WorkflowConfig(metrics_port=metrics_port),
    )
    if config.workflow.metrics_port is not None:
        start_http_server(config.workflow.metrics_port)
    path = ThreatModelWorkflow(config).run(aa_id)
    typer.echo(path)


@app.command()
def scenario(
    json_file: Annotated[Path, typer.Option("--json-file", exists=True, dir_okay=False)],
    attack_template: Annotated[str, typer.Option("--attack-template")],
    backend: BackendOption = None,
    inference_url: UrlOption = None,
    inference_model: ModelOption = None,
    inference_api_key: KeyOption = None,
    min_cvss: Annotated[float, typer.Option("--min-cvss", min=0, max=10)] = 8.5,
    db_path: Annotated[str, typer.Option("--db-path")] = "cve_database.db",
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
    prompts_dir: Annotated[Path | None, typer.Option("--prompts-dir")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Generate CVE, CTI, and threat-scenario reports from a threat model."""
    defaults = PathConfig()
    config = AppConfig(
        inference=_inference(backend, inference_url, inference_api_key, inference_model),
        paths=PathConfig(
            data_dir=data_dir or defaults.data_dir,
            prompts_dir=prompts_dir or defaults.prompts_dir,
            output_dir=output_dir or defaults.output_dir,
        ),
    )
    path = ScenarioWorkflow(config).run(
        json_file, attack_template, min_cvss=min_cvss, db_path=db_path
    )
    typer.echo(path)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8765,
) -> None:
    """Serve the local browser console."""
    from src.gui import serve as serve_gui

    serve_gui(host, port)


if __name__ == "__main__":
    app()
