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

from src.config import AppConfig, InferenceBackend, build_inference_config, parse_backend

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
    entries = load_json_file(CONFIG.paths.data_dir / "cmdb.json", [])
    if not isinstance(entries, list):
        return []
    return [
        {
            "aa_id": row.get("AA ID", ""),
            "name": row.get("Application Name", ""),
            "description": row.get("SWC Description", ""),
            "platform": row.get("Platform", []),
            "confidentiality": row.get("Confidentiality", ""),
            "integrity": row.get("Integrity", ""),
            "externally_facing": row.get("Externally facing", ""),
            "development_category": row.get("Development Category", ""),
        }
        for row in entries
        if isinstance(row, dict)
    ]


def load_attack_templates() -> list[dict[str, Any]]:
    data = load_json_file(CONFIG.paths.data_dir / "predefined_attack_templates.json", {})
    if not isinstance(data, dict):
        return []
    return [
        {"name": name, "techniques": techniques if isinstance(techniques, list) else []}
        for name, techniques in sorted(data.items())
    ]


def provider_status() -> dict[str, Any]:
    providers = []
    labels = {
        InferenceBackend.vllm: "vLLM",
        InferenceBackend.omlx: "oMLX",
        InferenceBackend.openai: "OpenAI",
    }
    for backend in InferenceBackend:
        inference = build_inference_config(backend)
        providers.append(
            {
                "id": backend.value,
                "label": labels[backend],
                "ready": bool(inference.api_key),
                "model": inference.model,
                "base_url": inference.base_url,
                "detail": "Hosted model endpoint"
                if backend is InferenceBackend.openai
                else "Local OpenAI-compatible endpoint",
            }
        )
    return {"default": CONFIG.inference.backend.value, "providers": providers}


def status_payload() -> dict[str, Any]:
    with JOBS_LOCK:
        jobs = [
            job.snapshot()
            for job in sorted(JOBS.values(), key=lambda item: item.started_at, reverse=True)
        ]
    return {
        "workspace": str(CONFIG.paths.project_root),
        "provider": provider_status(),
        "cmdb": load_cmdb_entries(),
        "attack_templates": load_attack_templates(),
        "outputs": {
            "stride": list_json_outputs("stride"),
            "scenarios": list_json_outputs("scenarios"),
            "feedback": list_json_outputs("feedback"),
        },
        "jobs": jobs,
    }


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
        "--min-cvss",
        str(min_cvss),
        "--db-path",
        str(data.get("db_path") or "cve_database.db"),
        *_path_arguments(),
    ]
    return start_job("scenario", command)


class GuiHandler(BaseHTTPRequestHandler):
    server_version = "LangGraphStrideGUI/0.1"

    def do_HEAD(self) -> None:
        self.serve_static(urlparse(self.path).path, head_only=True)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/status":
                self.send_json(status_payload())
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
