"""Command-line interface for LangGraph STRIDE."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from src.config import AppConfig, build_inference_config
from src.inference_client import client_from_config

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


if __name__ == "__main__":
    app()
