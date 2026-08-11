"""Command-line interface for LangGraph STRIDE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from prometheus_client import start_http_server

from src.config import (
    REASONING_STRENGTHS,
    AppConfig,
    PathConfig,
    WorkflowConfig,
    build_inference_config,
)
from src.inference_client import client_from_config
from src.scenario import ScenarioWorkflow
from src.threat_model import ThreatModelWorkflow
from src.intel.cti import delete_cti_pack, ingest_cti_pack, list_cti_packs, upsert_cti_pack
from src.intel.manifest import intel_status
from src.intel.mitre import import_mitre_file, search_techniques, update_mitre_online
from src.intel.nvd import import_nvd_file, query_cves, seed_demo_cves, update_nvd_online
from src.workspace import (
    build_navigator,
    delete_chain,
    delete_cmdb_entry,
    get_chain,
    get_cmdb_entry,
    load_chains,
    load_cmdb,
    seed_workspace,
    upsert_chain,
    upsert_cmdb_entry,
)

app = typer.Typer(no_args_is_help=True, add_completion=False)
cmdb_app = typer.Typer(no_args_is_help=True, help="Maintain the workspace CMDB inventory.")
chains_app = typer.Typer(no_args_is_help=True, help="Maintain attack-chain templates.")
intel_app = typer.Typer(no_args_is_help=True, help="Ingest and update NVD / MITRE / CTI intel.")
app.add_typer(cmdb_app, name="cmdb")
app.add_typer(chains_app, name="chains")
app.add_typer(intel_app, name="intel")

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
DeviceOption = Annotated[str | None, typer.Option("--device", help="cuda, mps, or cpu")]
BatchOption = Annotated[
    int | None,
    typer.Option("--batch-size", "--concurrency", min=1, help="Maximum inference connections"),
]
ThinkingOption = Annotated[
    bool | None,
    typer.Option(
        "--thinking/--no-thinking",
        help="Enable model thinking/reasoning (default from STRIDE_ENABLE_THINKING)",
    ),
]
ReasoningStrengthOption = Annotated[
    str | None,
    typer.Option(
        "--reasoning-strength",
        help=f"Muse-style reasoning budget: {', '.join(REASONING_STRENGTHS)}",
    ),
]


def _inference(
    backend: str | None,
    url: str | None,
    key: str | None,
    model: str | None,
    device: str | None,
    batch_size: int | None,
    thinking: bool | None = None,
    reasoning_strength: str | None = None,
):
    disable_thinking = None if thinking is None else (not thinking)
    return build_inference_config(
        backend,
        base_url=url,
        api_key=key,
        model=model,
        device=device,
        concurrency=batch_size,
        disable_thinking=disable_thinking,
        reasoning_strength=reasoning_strength,
    )


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
    device: DeviceOption = None,
    batch_size: BatchOption = None,
    thinking: ThinkingOption = None,
    reasoning_strength: ReasoningStrengthOption = None,
) -> None:
    """List models served by an OpenAI-compatible endpoint."""
    config = _inference(
        backend,
        inference_url,
        inference_api_key,
        inference_model,
        device,
        batch_size,
        thinking,
        reasoning_strength,
    )
    for model_id in client_from_config(config).list_models():
        typer.echo(model_id)


@app.command("smoke-inference")
def smoke_inference(
    backend: BackendOption = None,
    inference_url: UrlOption = None,
    inference_model: ModelOption = None,
    inference_api_key: KeyOption = None,
    device: DeviceOption = None,
    batch_size: BatchOption = None,
    thinking: ThinkingOption = None,
    reasoning_strength: ReasoningStrengthOption = None,
) -> None:
    """Send one small request through the same inference seam as the workflows."""
    config = _inference(
        backend,
        inference_url,
        inference_api_key,
        inference_model,
        device,
        batch_size,
        thinking,
        reasoning_strength,
    )
    result = client_from_config(config).chat(
        [{"role": "user", "content": "langgraph-stride smoke"}],
        max_tokens=64,
        disable_thinking=config.disable_thinking,
        reasoning_strength=config.reasoning_strength,
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
    device: DeviceOption = None,
    batch_size: BatchOption = None,
    thinking: ThinkingOption = None,
    reasoning_strength: ReasoningStrengthOption = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
    prompts_dir: Annotated[Path | None, typer.Option("--prompts-dir")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    metrics_port: Annotated[int | None, typer.Option("--metrics-port", min=1, max=65_535)] = None,
) -> None:
    """Generate a STRIDE model and DREAD assessment for one application."""
    config = AppConfig(
        inference=_inference(
            backend,
            inference_url,
            inference_api_key,
            inference_model,
            device,
            batch_size,
            thinking,
            reasoning_strength,
        ),
        paths=PathConfig(
            data_dir=data_dir or PathConfig().data_dir,
            prompts_dir=prompts_dir or PathConfig().prompts_dir,
            output_dir=output_dir or PathConfig().output_dir,
        ),
        workflow=WorkflowConfig()
        if metrics_port is None
        else WorkflowConfig(metrics_port=metrics_port),
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
    device: DeviceOption = None,
    batch_size: BatchOption = None,
    thinking: ThinkingOption = None,
    reasoning_strength: ReasoningStrengthOption = None,
    min_cvss: Annotated[float, typer.Option("--min-cvss", min=0, max=10)] = 8.5,
    db_path: Annotated[str, typer.Option("--db-path")] = "cve_database.db",
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
    prompts_dir: Annotated[Path | None, typer.Option("--prompts-dir")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Generate CVE, CTI, and threat-scenario reports from a threat model."""
    defaults = PathConfig()
    config = AppConfig(
        inference=_inference(
            backend,
            inference_url,
            inference_api_key,
            inference_model,
            device,
            batch_size,
            thinking,
            reasoning_strength,
        ),
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


@app.command()
def navigator(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    """Print the Application → threat model → scenario hierarchy as JSON."""
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    typer.echo(json.dumps(build_navigator(paths), indent=2))


@cmdb_app.command("list")
def cmdb_list(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    """List CMDB applications (workspace, else package seed)."""
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    typer.echo(json.dumps(load_cmdb(paths), indent=2))


@cmdb_app.command("show")
def cmdb_show(
    aa_id: Annotated[str, typer.Argument()],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    typer.echo(json.dumps(get_cmdb_entry(paths, aa_id), indent=2))


@cmdb_app.command("upsert")
def cmdb_upsert(
    aa_id: Annotated[str, typer.Option("--aa-id")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    confidentiality: Annotated[str, typer.Option("--confidentiality")] = "",
    integrity: Annotated[str, typer.Option("--integrity")] = "",
    platform: Annotated[str, typer.Option("--platform", help="Comma-separated")] = "",
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    record = upsert_cmdb_entry(
        paths,
        {
            "aa_id": aa_id,
            "name": name,
            "swc_description": description,
            "confidentiality": confidentiality,
            "integrity": integrity,
            "platform": [part.strip() for part in platform.split(",") if part.strip()],
        },
    )
    typer.echo(json.dumps(record, indent=2))


@cmdb_app.command("delete")
def cmdb_delete(
    aa_id: Annotated[str, typer.Argument()],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    delete_cmdb_entry(paths, aa_id)
    typer.echo(aa_id)


@cmdb_app.command("seed")
def cmdb_seed(
    force: Annotated[bool, typer.Option("--force")] = False,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    seeded = seed_workspace(paths, force=force)
    typer.echo(json.dumps(seeded, indent=2))


@chains_app.command("list")
def chains_list(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    typer.echo(json.dumps(load_chains(paths), indent=2))


@chains_app.command("show")
def chains_show(
    chain_id: Annotated[str, typer.Argument(help="Chain id or exact name")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    typer.echo(json.dumps(get_chain(paths, chain_id), indent=2))


@chains_app.command("upsert")
def chains_upsert(
    name: Annotated[str, typer.Option("--name")],
    techniques: Annotated[
        str,
        typer.Option("--techniques", help="Semicolon-separated technique labels"),
    ] = "",
    chain_id: Annotated[str | None, typer.Option("--id")] = None,
    description: Annotated[str, typer.Option("--description")] = "",
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    steps = [part.strip() for part in techniques.split(";") if part.strip()]
    record = upsert_chain(
        paths,
        {
            "id": chain_id or "",
            "name": name,
            "description": description,
            "steps": steps,
            "source": "user",
        },
    )
    typer.echo(json.dumps(record, indent=2))


@chains_app.command("delete")
def chains_delete(
    chain_id: Annotated[str, typer.Argument()],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    data_dir: Annotated[Path | None, typer.Option("--data-dir")] = None,
) -> None:
    paths = PathConfig(
        data_dir=data_dir or PathConfig().data_dir,
        output_dir=output_dir or PathConfig().output_dir,
    )
    delete_chain(paths, chain_id)
    typer.echo(chain_id)


def _paths(
    output_dir: Path | None = None,
    data_dir: Path | None = None,
) -> PathConfig:
    defaults = PathConfig()
    return PathConfig(
        data_dir=data_dir or defaults.data_dir,
        output_dir=output_dir or defaults.output_dir,
        project_root=defaults.project_root,
    )


@intel_app.command("status")
def intel_status_cmd(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Show NVD / MITRE / CTI catalog freshness and counts."""
    typer.echo(json.dumps(intel_status(_paths(output_dir=output_dir)), indent=2))


@intel_app.command("ingest-nvd")
def intel_ingest_nvd(
    path: Annotated[Path, typer.Argument(help="NVD 2.0 JSON or demo CVE JSON")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    db_path: Annotated[Path | None, typer.Option("--db-path")] = None,
) -> None:
    """Offline ingest of NVD/CVE JSON into the local store."""
    result = import_nvd_file(_paths(output_dir=output_dir), path, db_path=db_path)
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("seed-nvd")
def intel_seed_nvd(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Seed the CVE store from the packaged demo vulnerability fixture."""
    typer.echo(json.dumps(seed_demo_cves(_paths(output_dir=output_dir)), indent=2))


@intel_app.command("update-nvd")
def intel_update_nvd(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    max_pages: Annotated[int, typer.Option("--max-pages", min=1, max=50)] = 2,
    results_per_page: Annotated[int, typer.Option("--results-per-page", min=1, max=200)] = 50,
    min_cvss: Annotated[float | None, typer.Option("--min-cvss")] = 7.0,
) -> None:
    """Online NVD API 2.0 pull (bounded; set NVD_API_KEY for higher rate limits)."""
    result = update_nvd_online(
        _paths(output_dir=output_dir),
        max_pages=max_pages,
        results_per_page=results_per_page,
        min_cvss=min_cvss,
    )
    typer.echo(json.dumps(result, indent=2))


@intel_app.command("search-cve")
def intel_search_cve(
    q: Annotated[str, typer.Option("--q")] = "",
    min_cvss: Annotated[float, typer.Option("--min-cvss")] = 0.0,
    limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 20,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    rows = query_cves(_paths(output_dir=output_dir), min_cvss=min_cvss, q=q, limit=limit)
    typer.echo(json.dumps(rows, indent=2))


@intel_app.command("ingest-mitre")
def intel_ingest_mitre(
    path: Annotated[Path, typer.Argument(help="enterprise-attack STIX or techniques JSON")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Offline ingest of MITRE ATT&CK techniques."""
    typer.echo(json.dumps(import_mitre_file(_paths(output_dir=output_dir), path), indent=2))


@intel_app.command("update-mitre")
def intel_update_mitre(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Online download of MITRE enterprise-attack STIX bundle."""
    typer.echo(json.dumps(update_mitre_online(_paths(output_dir=output_dir)), indent=2))


@intel_app.command("search-mitre")
def intel_search_mitre(
    q: Annotated[str, typer.Option("--q")] = "",
    limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 30,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    typer.echo(json.dumps(search_techniques(_paths(output_dir=output_dir), q, limit=limit), indent=2))


@intel_app.command("ingest-cti")
def intel_ingest_cti(
    path: Annotated[Path, typer.Argument(help="CTI pack JSON object or array")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    """Offline ingest of one or more CTI packs."""
    typer.echo(json.dumps(ingest_cti_pack(_paths(output_dir=output_dir), path), indent=2))


@intel_app.command("list-cti")
def intel_list_cti(
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    typer.echo(json.dumps(list_cti_packs(_paths(output_dir=output_dir)), indent=2))


@intel_app.command("upsert-cti")
def intel_upsert_cti(
    title: Annotated[str, typer.Option("--title")],
    techniques: Annotated[str, typer.Option("--techniques", help="Comma-separated T#### ids")] = "",
    actors: Annotated[str, typer.Option("--actors", help="Comma-separated")] = "",
    notes: Annotated[str, typer.Option("--notes")] = "",
    pack_id: Annotated[str | None, typer.Option("--id")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    pack = upsert_cti_pack(
        _paths(output_dir=output_dir),
        {
            "id": pack_id or "",
            "title": title,
            "techniques": [part.strip() for part in techniques.split(",") if part.strip()],
            "actors": [part.strip() for part in actors.split(",") if part.strip()],
            "notes": notes,
            "source": "user",
        },
    )
    typer.echo(json.dumps(pack, indent=2))


@intel_app.command("delete-cti")
def intel_delete_cti(
    pack_id: Annotated[str, typer.Argument()],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
) -> None:
    delete_cti_pack(_paths(output_dir=output_dir), pack_id)
    typer.echo(pack_id)


if __name__ == "__main__":
    app()
