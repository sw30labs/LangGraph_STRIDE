"""Local HTTP console for the threat-model and scenario workflows."""

from __future__ import annotations

import json
import mimetypes
import os
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from src.config import (
    REASONING_STRENGTHS,
    AppConfig,
    InferenceBackend,
    build_inference_config,
    parse_backend,
    parse_reasoning_strength,
)
from src.export_pdf import export_artifact_pdf
from src.intel.cti import (
    delete_cti_pack,
    import_cisa_kev_file,
    ingest_cti_pack,
    list_cti_packs,
    update_cisa_kev_online,
    upsert_cti_pack,
)
from src.intel.manifest import intel_status
from src.intel.mitre import import_mitre_file, search_techniques, update_mitre_online
from src.intel.nvd import (
    import_nvd_file,
    query_cves,
    seed_demo_cves,
    update_nvd_online,
)
from src.maintain.cards import cards_payload
from src.maintain.graph import clone_pairs
from src.maintain.neo4j_graph import (
    CANNED_QUERIES,
    canned_query,
    neo4j_status,
    try_sync_after_build,
    visualization_payload,
)
from src.maintain.workflows import commit_proposal_file, run_neo4j_sync
from src.workspace import (
    build_navigator,
    chain_technique_labels,
    delete_chain,
    delete_cmdb_entry,
    get_chain,
    get_cmdb_entry,
    load_chains,
    load_cmdb,
    seed_attack_templates,
    seed_cmdb,
    seed_workspace,
    upsert_chain,
    upsert_cmdb_entry,
)

WEB_DIR = Path(__file__).with_name("web")
MAX_BODY_BYTES = 1_000_000
CONFIG = AppConfig()


def now_iso() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


@dataclass
class Job:
    id: str
    kind: str
    command: list[str]
    status: str = "running"
    returncode: int | None = None
    started_at: str = field(default_factory=now_iso)
    ended_at: str | None = None
    log: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "command": self.command,
            "status": self.status,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "log": self.log[-500:],
        }


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def rel_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(CONFIG.paths.project_root.resolve()))
    except ValueError:
        return str(path.resolve())


def ensure_repo_file(value: str) -> Path:
    """Resolve a file while rejecting paths outside the configured workspace."""
    candidate = Path(value)
    root = CONFIG.paths.project_root.resolve()
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    if root not in (resolved, *resolved.parents):
        raise ValueError("Path must stay inside the project workspace")
    if not resolved.is_file():
        raise ValueError(f"File not found: {value}")
    return resolved


def load_json_file(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def list_json_outputs(subdir: str) -> list[dict[str, Any]]:
    directory = CONFIG.paths.output_dir / subdir
    if not directory.is_dir():
        return []
    result = []
    for path in sorted(
        directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True
    ):
        stat = path.stat()
        result.append(
            {
                "name": path.name,
                "path": rel_path(path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )
    return result


def load_cmdb_entries() -> list[dict[str, Any]]:
    return [
        {
            "aa_id": row.get("aa_id", ""),
            "name": row.get("name", ""),
            "description": row.get("swc_description", ""),
            "solution_description": row.get("solution_description", ""),
            "owner_stream": row.get("owner_stream", ""),
            "platform": row.get("platform", []),
            "confidentiality": row.get("confidentiality", ""),
            "integrity": row.get("integrity", ""),
            "availability": row.get("availability", ""),
            "externally_facing": row.get("externally_facing", ""),
            "development_category": row.get("development_category", ""),
            "cid_handling": row.get("cid_handling", ""),
            "updated_at": row.get("updated_at", ""),
        }
        for row in load_cmdb(CONFIG.paths)
    ]


def load_attack_templates() -> list[dict[str, Any]]:
    return [
        {
            "id": chain["id"],
            "name": chain["name"],
            "description": chain.get("description") or "",
            "tags": chain.get("tags") or [],
            "techniques": chain_technique_labels(chain),
            "steps": chain.get("steps") or [],
            "updated_at": chain.get("updated_at") or "",
            "source": chain.get("source") or "",
        }
        for chain in sorted(load_chains(CONFIG.paths), key=lambda item: item["name"].casefold())
    ]


def _probe_provider(base_url: str, api_key: str) -> tuple[bool, str]:
    """I ping /models quickly so the UI does not claim a provider is ready when auth fails."""
    if not api_key:
        return False, "API key missing"
    try:
        import httpx

        from src.inference_client import normalize_base_url

        url = f"{normalize_base_url(base_url)}/models"
        with httpx.Client(timeout=0.8, trust_env=False) as client:
            response = client.get(url, headers={"Authorization": f"Bearer {api_key}"})
        if response.status_code == 401:
            return (
                False,
                "API key rejected (401) — check MLX_API_KEY / OPENAI_API_KEY / VLLM_API_KEY",
            )
        if response.status_code >= 400:
            return False, f"Endpoint returned HTTP {response.status_code}"
        return True, "ok"
    except Exception as exc:
        return False, f"Unreachable: {type(exc).__name__}"


def provider_status() -> dict[str, Any]:
    providers = []
    labels = {
        InferenceBackend.vllm: "vLLM",
        InferenceBackend.omlx: "oMLX",
        InferenceBackend.openai: "OpenAI",
    }
    for backend in InferenceBackend:
        inference = build_inference_config(backend)
        ready, detail = _probe_provider(inference.base_url, inference.api_key)
        if ready:
            detail = (
                "Hosted model endpoint"
                if backend is InferenceBackend.openai
                else "Local OpenAI-compatible endpoint"
            )
        providers.append(
            {
                "id": backend.value,
                "label": labels[backend],
                "ready": ready,
                "model": inference.model,
                "base_url": inference.base_url,
                "detail": detail,
            }
        )
    return {"default": CONFIG.inference.backend.value, "providers": providers}


def thinking_defaults() -> dict[str, Any]:
    return {
        "enabled": not CONFIG.inference.disable_thinking,
        "reasoning_strength": CONFIG.inference.reasoning_strength,
        "reasoning_strengths": list(REASONING_STRENGTHS),
    }


def parse_thinking_flag(data: dict[str, Any]) -> bool | None:
    """Return CLI thinking override, or None to keep env/config default."""
    if "thinking" not in data and "enable_thinking" not in data:
        return None
    raw = data["thinking"] if "thinking" in data else data["enable_thinking"]
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    raise ValueError("thinking must be a boolean")


def thinking_cli_arguments(data: dict[str, Any]) -> list[str]:
    """Map GUI thinking controls onto CLI flags."""
    args: list[str] = []
    thinking = parse_thinking_flag(data)
    if thinking is True:
        args.append("--thinking")
    elif thinking is False:
        args.append("--no-thinking")
    if "reasoning_strength" in data and data.get("reasoning_strength") not in (None, ""):
        strength = parse_reasoning_strength(str(data.get("reasoning_strength")))
        args.extend(["--reasoning-strength", strength])
    return args


def status_payload() -> dict[str, Any]:
    with JOBS_LOCK:
        jobs = [
            job.snapshot()
            for job in sorted(JOBS.values(), key=lambda item: item.started_at, reverse=True)
        ]
    navigator = build_navigator(CONFIG.paths)
    return {
        "workspace": str(CONFIG.paths.project_root),
        "workspace_paths": {
            "output_dir": str(CONFIG.paths.output_dir),
            "workspace_dir": str(CONFIG.paths.workspace_dir),
            "intel_dir": str(CONFIG.paths.intel_dir),
        },
        "provider": provider_status(),
        "thinking": thinking_defaults(),
        "cmdb": load_cmdb_entries(),
        "attack_templates": load_attack_templates(),
        "navigator": navigator,
        "intel": intel_status(CONFIG.paths),
        "outputs": {
            "stride": list_json_outputs("stride"),
            "scenarios": list_json_outputs("scenarios"),
            "feedback": list_json_outputs("feedback"),
        },
        "jobs": jobs,
    }


def build_intel_job(data: dict[str, Any]) -> Job:
    """Background CLI job for long-running online intel updates."""
    catalog = str(data.get("catalog") or "").strip().lower()
    mode = str(data.get("mode") or "online").strip().lower()
    if catalog not in {"nvd", "mitre", "cti", "kev", "advisories"}:
        raise ValueError("catalog must be nvd, mitre, cti, kev, or advisories")
    if mode not in {"online", "offline"}:
        raise ValueError("mode must be online or offline")
    command = [sys.executable, "-m", "src.cli", "intel"]
    if catalog == "nvd" and mode == "online":
        command.append("update-nvd")
        if data.get("max_pages") is not None:
            command.extend(["--max-pages", str(int(data["max_pages"]))])
    elif catalog == "nvd" and mode == "offline":
        source = str(data.get("path") or "").strip()
        if not source:
            raise ValueError("path is required for offline NVD ingest")
        command.extend(["ingest-nvd", str(ensure_repo_file(source))])
    elif catalog == "mitre" and mode == "online":
        command.append("update-mitre")
    elif catalog == "mitre" and mode == "offline":
        source = str(data.get("path") or "").strip()
        if not source:
            raise ValueError("path is required for offline MITRE ingest")
        command.extend(["ingest-mitre", str(ensure_repo_file(source))])
    elif catalog in {"cti", "kev"} and mode == "online":
        command.append("update-cti-kev")
        if data.get("recent") is not None:
            command.extend(["--recent", str(int(data["recent"]))])
        if data.get("ransomware") is not None:
            command.extend(["--ransomware", str(int(data["ransomware"]))])
    elif catalog in {"cti", "kev"} and mode == "offline":
        source = str(data.get("path") or "").strip()
        if not source:
            raise ValueError("path is required for offline KEV ingest")
        command.extend(["ingest-kev", str(ensure_repo_file(source))])
    elif catalog == "advisories" and mode == "online":
        command.append("update-cti-advisories")
        if data.get("limit") is not None:
            command.extend(["--limit", str(int(data["limit"]))])
    elif catalog == "advisories" and mode == "offline":
        source = str(data.get("path") or "").strip()
        if not source:
            raise ValueError("path is required for offline advisories ingest")
        command.extend(["ingest-cisa-advisories", str(ensure_repo_file(source))])
    else:
        raise ValueError(f"Unsupported intel job: catalog={catalog} mode={mode}")
    command.extend(["--output-dir", str(CONFIG.paths.output_dir)])
    return start_job(f"intel-{catalog}-{mode}", command)


def read_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length") or "0")
    if length > MAX_BODY_BYTES:
        raise ValueError("Request body is too large")
    raw = handler.rfile.read(length) if length else b"{}"
    data = json.loads(raw.decode("utf-8")) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def start_job(kind: str, command: list[str]) -> Job:
    job = Job(id=uuid.uuid4().hex[:12], kind=kind, command=command)
    with JOBS_LOCK:
        JOBS[job.id] = job
    threading.Thread(target=run_job, args=(job,), daemon=True).start()
    return job


def run_job(job: Job) -> None:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        process = subprocess.Popen(
            job.command,
            cwd=CONFIG.paths.project_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if process.stdout is None:
            raise RuntimeError("Job output stream is unavailable")
        for line in process.stdout:
            with JOBS_LOCK:
                job.log.append(line.rstrip())
        returncode = process.wait()
        with JOBS_LOCK:
            job.returncode = returncode
            job.status = "succeeded" if returncode == 0 else "failed"
            job.ended_at = now_iso()
    except Exception as exc:
        with JOBS_LOCK:
            job.status = "failed"
            job.returncode = -1
            job.ended_at = now_iso()
            job.log.append(f"{type(exc).__name__}: {exc}")


def _path_arguments() -> list[str]:
    return [
        "--data-dir",
        str(CONFIG.paths.data_dir),
        "--prompts-dir",
        str(CONFIG.paths.prompts_dir),
        "--output-dir",
        str(CONFIG.paths.output_dir),
    ]


def build_model_job(data: dict[str, Any]) -> Job:
    aa_id = str(data.get("aa_id") or "").strip()
    if not aa_id:
        raise ValueError("AA ID is required")
    backend = parse_backend(str(data.get("provider") or CONFIG.inference.backend.value)).value
    command = [
        sys.executable,
        "-m",
        "src.cli",
        "threat-model",
        aa_id,
        "--backend",
        backend,
        *thinking_cli_arguments(data),
        *_path_arguments(),
    ]
    return start_job("threat-model", command)


def build_scenario_job(data: dict[str, Any]) -> Job:
    json_file = str(data.get("json_file") or "").strip()
    attack_template = str(data.get("attack_template") or "").strip()
    if not json_file:
        raise ValueError("Threat model JSON file is required")
    if not attack_template:
        raise ValueError("Attack template is required")
    model_file = ensure_repo_file(json_file)
    backend = parse_backend(str(data.get("provider") or CONFIG.inference.backend.value)).value
    min_cvss = float(data.get("min_cvss", 8.5))
    if not 0 <= min_cvss <= 10:
        raise ValueError("Minimum CVSS must be between 0 and 10")
    command = [
        sys.executable,
        "-m",
        "src.cli",
        "scenario",
        "--json-file",
        str(model_file),
        "--attack-template",
        attack_template,
        "--backend",
        backend,
        *thinking_cli_arguments(data),
        "--min-cvss",
        str(min_cvss),
        "--db-path",
        str(data.get("db_path") or "cve_database.db"),
        *_path_arguments(),
    ]
    return start_job("scenario", command)


def build_maintain_job(data: dict[str, Any]) -> Job:
    """Background Maintain studio card (forge / autopsy / galaxy)."""
    card = str(data.get("card") or data.get("card_id") or "").strip()
    if not card:
        raise ValueError("card is required")
    backend = parse_backend(str(data.get("provider") or CONFIG.inference.backend.value)).value
    command = [
        sys.executable,
        "-m",
        "src.cli",
        "maintain",
        "run",
        card,
        "--backend",
        backend,
        *thinking_cli_arguments(data),
        *_path_arguments(),
    ]
    steer = str(data.get("steer") or "").strip()
    if steer:
        command.extend(["--steer", steer])
    if data.get("max_jaccard") not in (None, ""):
        command.extend(["--max-jaccard", str(float(data["max_jaccard"]))])
    if data.get("threshold") not in (None, ""):
        command.extend(["--threshold", str(float(data["threshold"]))])
    if data.get("web_spark"):
        command.append("--web-spark")
    else:
        command.append("--no-web-spark")
    aa_id = str(data.get("aa_id") or "").strip()
    if aa_id:
        command.extend(["--aa-id", aa_id])
    if data.get("commit"):
        command.append("--commit")
    else:
        command.append("--no-commit")
    return start_job(f"maintain-{card}", command)


class GuiHandler(BaseHTTPRequestHandler):
    server_version = "LangGraphStrideGUI/0.1"

    def do_HEAD(self) -> None:
        self.serve_static(urlparse(self.path).path, head_only=True)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/status":
                self.send_json(status_payload())
            elif parsed.path == "/api/navigator":
                self.send_json(build_navigator(CONFIG.paths))
            elif parsed.path == "/api/cmdb":
                self.send_json(load_cmdb_entries())
            elif parsed.path.startswith("/api/cmdb/"):
                aa_id = unquote(parsed.path.rsplit("/", 1)[-1])
                self.send_json(get_cmdb_entry(CONFIG.paths, aa_id))
            elif parsed.path == "/api/chains":
                self.send_json(load_attack_templates())
            elif parsed.path.startswith("/api/chains/"):
                chain_id = unquote(parsed.path.rsplit("/", 1)[-1])
                chain = get_chain(CONFIG.paths, chain_id)
                self.send_json(
                    {
                        **chain,
                        "techniques": chain_technique_labels(chain),
                    }
                )
            elif parsed.path == "/api/intel/status":
                self.send_json(intel_status(CONFIG.paths))
            elif parsed.path == "/api/cve/search":
                query = parse_qs(parsed.query)
                rows = query_cves(
                    CONFIG.paths,
                    min_cvss=float((query.get("min_cvss") or ["0"])[0] or 0),
                    q=(query.get("q") or [""])[0],
                    limit=int((query.get("limit") or ["25"])[0] or 25),
                )
                self.send_json(rows)
            elif parsed.path == "/api/mitre/techniques":
                query = parse_qs(parsed.query)
                rows = search_techniques(
                    CONFIG.paths,
                    (query.get("q") or [""])[0],
                    limit=int((query.get("limit") or ["50"])[0] or 50),
                )
                self.send_json(rows)
            elif parsed.path == "/api/cti":
                self.send_json(list_cti_packs(CONFIG.paths))
            elif parsed.path == "/api/maintain/cards":
                self.send_json(cards_payload())
            elif parsed.path == "/api/maintain/graph":
                # Observatory payload: analytics + force layouts; best-effort Neo4j sync.
                query = parse_qs(parsed.query)
                sync = (query.get("sync") or ["1"])[0].lower() not in {"0", "false", "no"}
                graph = visualization_payload(CONFIG.paths, neo=CONFIG.neo4j)
                if sync and CONFIG.neo4j.enabled:
                    try_sync_after_build(CONFIG, graph)
                    graph["neo4j"] = neo4j_status(CONFIG.neo4j)
                self.send_json(graph)
            elif parsed.path == "/api/maintain/clones":
                query = parse_qs(parsed.query)
                threshold = float((query.get("threshold") or ["0.55"])[0] or 0.55)
                self.send_json(clone_pairs(CONFIG.paths, threshold=threshold))
            elif parsed.path == "/api/maintain/neo4j":
                self.send_json(neo4j_status(CONFIG.neo4j))
            elif parsed.path == "/api/maintain/neo4j/queries":
                self.send_json(
                    {
                        "queries": [
                            {"id": key, "title": meta["title"]}
                            for key, meta in CANNED_QUERIES.items()
                        ]
                    }
                )
            elif parsed.path.startswith("/api/maintain/neo4j/query/"):
                name = unquote(parsed.path.rsplit("/", 1)[-1])
                query = parse_qs(parsed.query)
                params = {}
                if query.get("chain_id"):
                    params["chain_id"] = query["chain_id"][0]
                self.send_json(canned_query(CONFIG.neo4j, name, params or None))
            elif parsed.path == "/api/jobs":
                with JOBS_LOCK:
                    self.send_json([job.snapshot() for job in JOBS.values()])
            elif parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                with JOBS_LOCK:
                    job = JOBS.get(job_id)
                if job is None:
                    self.send_error_json(HTTPStatus.NOT_FOUND, "Job not found")
                else:
                    self.send_json(job.snapshot())
            elif parsed.path == "/api/file":
                raw_path = unquote((parse_qs(parsed.query).get("path") or [""])[0])
                path = ensure_repo_file(raw_path)
                self.send_json({"path": rel_path(path), "content": load_json_file(path, None)})
            elif parsed.path == "/api/export/download":
                # I stream a generated PDF (or other export) when it stays inside the workspace.
                raw_path = unquote((parse_qs(parsed.query).get("path") or [""])[0])
                path = ensure_repo_file(raw_path)
                body = path.read_bytes()
                content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{path.name}"',
                )
                self.end_headers()
                self.wfile.write(body)
            else:
                self.serve_static(parsed.path)
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            data = read_body(self)
            if parsed.path == "/api/jobs/model":
                self.send_json(build_model_job(data).snapshot(), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/jobs/scenario":
                self.send_json(build_scenario_job(data).snapshot(), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/jobs/maintain":
                self.send_json(build_maintain_job(data).snapshot(), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/maintain/commit":
                raw_path = str(data.get("path") or "").strip()
                if not raw_path:
                    raise ValueError("path is required")
                # Allow absolute proposal paths written under output/, else repo-relative.
                try:
                    proposal = ensure_repo_file(raw_path)
                    result = commit_proposal_file(CONFIG, str(proposal))
                except ValueError:
                    result = commit_proposal_file(CONFIG, raw_path)
                self.send_json(
                    {**result, "chains": load_attack_templates()},
                    HTTPStatus.CREATED,
                )
            elif parsed.path == "/api/maintain/neo4j/sync":
                self.send_json(run_neo4j_sync(CONFIG), HTTPStatus.CREATED)
            elif parsed.path == "/api/cmdb":
                self.send_json(upsert_cmdb_entry(CONFIG.paths, data), HTTPStatus.CREATED)
            elif parsed.path == "/api/cmdb/seed":
                path = seed_cmdb(CONFIG.paths, force=bool(data.get("force")))
                self.send_json({"path": rel_path(path), "cmdb": load_cmdb_entries()})
            elif parsed.path == "/api/chains":
                self.send_json(upsert_chain(CONFIG.paths, data), HTTPStatus.CREATED)
            elif parsed.path == "/api/chains/seed":
                path = seed_attack_templates(CONFIG.paths, force=bool(data.get("force")))
                self.send_json({"path": rel_path(path), "chains": load_attack_templates()})
            elif parsed.path == "/api/workspace/seed":
                seeded = seed_workspace(CONFIG.paths, force=bool(data.get("force")))
                self.send_json(
                    {
                        "paths": seeded,
                        "cmdb": load_cmdb_entries(),
                        "chains": load_attack_templates(),
                    }
                )
            elif parsed.path == "/api/intel/seed-nvd":
                self.send_json(seed_demo_cves(CONFIG.paths))
            elif parsed.path == "/api/intel/import":
                catalog = str(data.get("catalog") or "").strip().lower()
                source = str(data.get("path") or "").strip()
                if not source:
                    raise ValueError("path is required")
                file_path = ensure_repo_file(source)
                if catalog == "nvd":
                    self.send_json(import_nvd_file(CONFIG.paths, file_path))
                elif catalog == "mitre":
                    self.send_json(import_mitre_file(CONFIG.paths, file_path))
                elif catalog == "cti":
                    self.send_json(ingest_cti_pack(CONFIG.paths, file_path))
                else:
                    raise ValueError("catalog must be nvd, mitre, or cti")
            elif parsed.path == "/api/intel/update":
                # Synchronous small ops or background job for online pulls
                catalog = str(data.get("catalog") or "").strip().lower()
                mode = str(data.get("mode") or "online").strip().lower()
                if mode == "online" and catalog in {"nvd", "mitre", "cti", "kev", "advisories"}:
                    if data.get("background", True):
                        self.send_json(build_intel_job(data).snapshot(), HTTPStatus.ACCEPTED)
                    elif catalog == "nvd":
                        self.send_json(
                            update_nvd_online(
                                CONFIG.paths,
                                max_pages=int(data.get("max_pages") or 2),
                            )
                        )
                    elif catalog == "mitre":
                        self.send_json(update_mitre_online(CONFIG.paths))
                    else:
                        self.send_json(
                            update_cisa_kev_online(
                                CONFIG.paths,
                                recent_limit=int(data.get("recent") or 40),
                                ransomware_limit=int(data.get("ransomware") or 25),
                            )
                        )
                elif mode == "offline" and catalog in {"cti", "kev"} and data.get("path"):
                    self.send_json(
                        import_cisa_kev_file(CONFIG.paths, ensure_repo_file(str(data["path"])))
                    )
                else:
                    self.send_json(
                        build_intel_job({**data, "mode": mode}).snapshot(), HTTPStatus.ACCEPTED
                    )
            elif parsed.path == "/api/cti":
                self.send_json(upsert_cti_pack(CONFIG.paths, data), HTTPStatus.CREATED)
            elif parsed.path == "/api/export/pdf":
                # I turn a workspace JSON artifact into a PDF under output/exports/.
                raw_path = str(data.get("path") or "").strip()
                if not raw_path:
                    raise ValueError("path is required")
                source = ensure_repo_file(raw_path)
                kind = data.get("kind")
                if kind is not None:
                    kind = str(kind)
                pdf_path = export_artifact_pdf(
                    source,
                    paths=CONFIG.paths,
                    kind=kind if kind in {"threat_model", "scenario"} else None,
                )
                self.send_json(
                    {
                        "path": rel_path(pdf_path),
                        "absolute_path": str(pdf_path.resolve()),
                        "size": pdf_path.stat().st_size,
                    },
                    HTTPStatus.CREATED,
                )
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        try:
            data = read_body(self)
            if parsed.path.startswith("/api/cmdb/"):
                aa_id = unquote(parsed.path.rsplit("/", 1)[-1])
                data = {**data, "aa_id": data.get("aa_id") or aa_id}
                if str(data.get("aa_id")) != aa_id:
                    raise ValueError("aa_id in body must match URL")
                self.send_json(upsert_cmdb_entry(CONFIG.paths, data))
            elif parsed.path.startswith("/api/chains/"):
                chain_id = unquote(parsed.path.rsplit("/", 1)[-1])
                data = {**data, "id": data.get("id") or chain_id}
                self.send_json(upsert_chain(CONFIG.paths, data))
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path.startswith("/api/cmdb/"):
                aa_id = unquote(parsed.path.rsplit("/", 1)[-1])
                delete_cmdb_entry(CONFIG.paths, aa_id)
                self.send_json({"deleted": aa_id})
            elif parsed.path.startswith("/api/chains/"):
                chain_id = unquote(parsed.path.rsplit("/", 1)[-1])
                delete_chain(CONFIG.paths, chain_id)
                self.send_json({"deleted": chain_id})
            elif parsed.path.startswith("/api/cti/"):
                pack_id = unquote(parsed.path.rsplit("/", 1)[-1])
                delete_cti_pack(CONFIG.paths, pack_id)
                self.send_json({"deleted": pack_id})
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def serve_static(self, request_path: str, *, head_only: bool = False) -> None:
        relative = "index.html" if request_path in ("", "/") else request_path.lstrip("/")
        path = (WEB_DIR / relative).resolve()
        root = WEB_DIR.resolve()
        if root not in (path, *path.parents) or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        self.send_json({"error": message}, status)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[gui] {self.address_string()} {fmt % args}\n")


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the local console until interrupted."""
    server = ThreadingHTTPServer((host, port), GuiHandler)
    print(f"LangGraph STRIDE GUI: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping GUI server")
    finally:
        server.server_close()
