"""Platform-aware configuration for the shared threat-modeling pipeline."""

from __future__ import annotations

import os
import platform
from enum import StrEnum
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_VLLM_MODEL = "nvidia/Qwen3.6-27B-NVFP4"
DEFAULT_CONTEXT_SIZE = 32_768
# Muse Glimmer (and similar) controllable reasoning budgets.
REASONING_STRENGTHS = ("low", "medium", "high", "xhigh")
DEFAULT_REASONING_STRENGTH = "high"


def load_dotenv_if_present() -> None:
    """Load local settings without overriding values exported by the shell."""
    candidates = [Path.cwd() / ".env", PROJECT_ROOT / ".env"]
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen and resolved.is_file():
            load_dotenv(resolved, override=False)
            seen.add(resolved)


load_dotenv_if_present()


class InferenceBackend(StrEnum):
    """OpenAI-compatible providers supported by the application."""

    vllm = "vllm"
    omlx = "omlx"
    openai = "openai"


def parse_backend(value: str | InferenceBackend) -> InferenceBackend:
    """Parse provider names while retaining the source repo's `mlx` alias."""
    if isinstance(value, InferenceBackend):
        return value
    normalized = value.strip().lower()
    if normalized == "mlx":
        normalized = InferenceBackend.omlx.value
    return InferenceBackend(normalized)


def parse_reasoning_strength(value: str | None = None) -> str:
    """Parse Muse-style reasoning budgets: low, medium, high, xhigh."""
    if value is None or not str(value).strip():
        return DEFAULT_REASONING_STRENGTH
    normalized = str(value).strip().lower()
    if normalized not in REASONING_STRENGTHS:
        allowed = ", ".join(REASONING_STRENGTHS)
        raise ValueError(f"reasoning_strength must be one of: {allowed}")
    return normalized


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def is_dgx_spark_host() -> bool:
    """Return whether defaults should target NVIDIA DGX Spark."""
    return platform.system() == "Linux" and platform.machine().lower() in {"aarch64", "arm64"}


def is_apple_silicon_host() -> bool:
    """Return whether defaults should target Apple Silicon."""
    return platform.system() == "Darwin" and platform.machine().lower() in {"aarch64", "arm64"}


def default_inference_backend() -> InferenceBackend:
    configured = os.getenv("STRIDE_BACKEND") or os.getenv("LLM_PROVIDER")
    if configured:
        try:
            return parse_backend(configured)
        except ValueError:
            pass
    return InferenceBackend.vllm if is_dgx_spark_host() else InferenceBackend.omlx


def default_device() -> str:
    configured = os.getenv("STRIDE_DEVICE")
    if configured:
        return configured
    if is_dgx_spark_host():
        return "cuda"
    return "mps" if is_apple_silicon_host() else "cpu"


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def default_concurrency() -> int:
    configured = os.getenv("STRIDE_CONCURRENCY") or os.getenv("STRIDE_BATCH_SIZE")
    if configured:
        try:
            return int(configured)
        except ValueError:
            pass
    return 2 if is_dgx_spark_host() else 4


def resolve_base_url(backend: InferenceBackend) -> str:
    if backend is InferenceBackend.vllm:
        return os.getenv("VLLM_BASE_URL", "http://127.0.0.1:8000/v1")
    if backend is InferenceBackend.openai:
        return os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    return os.getenv("MLX_BASE_URL") or os.getenv("OMLX_BASE_URL") or "http://127.0.0.1:8000/v1"


def resolve_api_key(backend: InferenceBackend) -> str:
    if backend is InferenceBackend.vllm:
        return os.getenv("VLLM_API_KEY", "local")
    if backend is InferenceBackend.openai:
        return os.getenv("OPENAI_API_KEY", "")
    return os.getenv("MLX_API_KEY") or os.getenv("OMLX_API_KEY") or "local"


def resolve_model(backend: InferenceBackend) -> str:
    if backend is InferenceBackend.vllm:
        return os.getenv("VLLM_MODEL", DEFAULT_VLLM_MODEL)
    if backend is InferenceBackend.openai:
        return os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL") or "gpt-4o"
    return os.getenv("MLX_MODEL") or os.getenv("OMLX_MODEL") or os.getenv("LLM_MODEL") or "default"


def resolve_context_size(backend: InferenceBackend) -> int:
    configured = os.getenv("STRIDE_CONTEXT_SIZE")
    if configured:
        return _int_env("STRIDE_CONTEXT_SIZE", DEFAULT_CONTEXT_SIZE)
    if backend is InferenceBackend.vllm:
        return _int_env("VLLM_MAX_MODEL_LEN", DEFAULT_CONTEXT_SIZE)
    return _int_env("MLX_CONTEXT_SIZE", DEFAULT_CONTEXT_SIZE)


class InferenceConfig(BaseModel):
    backend: InferenceBackend = Field(default_factory=default_inference_backend)
    device: str = Field(default_factory=default_device)
    concurrency: int = Field(default_factory=default_concurrency, ge=1)
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    context_size: int = Field(default=DEFAULT_CONTEXT_SIZE, ge=1)
    max_tokens: int = Field(default=DEFAULT_CONTEXT_SIZE, ge=1)
    timeout: float = Field(default=120.0, gt=0)
    disable_thinking: bool = True
    reasoning_strength: str = DEFAULT_REASONING_STRENGTH


def build_inference_config(
    backend: str | InferenceBackend | None = None,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    device: str | None = None,
    concurrency: int | None = None,
    disable_thinking: bool | None = None,
    reasoning_strength: str | None = None,
) -> InferenceConfig:
    """Resolve one complete provider persona with optional CLI overrides."""
    selected = parse_backend(backend) if backend else default_inference_backend()
    if disable_thinking is None:
        disable_thinking = not _bool_env("STRIDE_ENABLE_THINKING", False)
    strength = parse_reasoning_strength(
        reasoning_strength
        if reasoning_strength is not None
        else os.getenv("STRIDE_REASONING_STRENGTH")
    )
    return InferenceConfig(
        backend=selected,
        device=device or default_device(),
        concurrency=concurrency or default_concurrency(),
        base_url=base_url or resolve_base_url(selected),
        api_key=api_key if api_key is not None else resolve_api_key(selected),
        model=model or resolve_model(selected),
        context_size=resolve_context_size(selected),
        max_tokens=_int_env("STRIDE_MAX_TOKENS", DEFAULT_CONTEXT_SIZE),
        timeout=_float_env("LLM_TIMEOUT", 120.0),
        disable_thinking=disable_thinking,
        reasoning_strength=strength,
    )


class PathConfig(BaseModel):
    project_root: Path = Field(default_factory=Path.cwd)
    data_dir: Path = PACKAGE_ROOT / "data"
    prompts_dir: Path = PACKAGE_ROOT / "prompts"
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "output")

    @property
    def workspace_dir(self) -> Path:
        """Mutable workspace root (CMDB, attack chains, intel catalogs)."""
        return self.output_dir / "workspace"

    @property
    def intel_dir(self) -> Path:
        return self.workspace_dir / "intel"


def default_metrics_port() -> int | None:
    configured = os.getenv("STRIDE_METRICS_PORT")
    if not configured:
        return None
    try:
        port = int(configured)
    except ValueError:
        return None
    return port if 1 <= port <= 65_535 else None


class WorkflowConfig(BaseModel):
    qa_attempts: int = Field(default=3, ge=1)
    metrics_port: int | None = Field(default_factory=default_metrics_port, ge=1, le=65_535)


class Neo4jConfig(BaseModel):
    """Dedicated STRIDE attack-graph store (not TwinOps).

    Defaults target compose.neo4j.yaml: HTTP 7475, Bolt 7688.
    """

    enabled: bool = Field(default_factory=lambda: _bool_env("STRIDE_NEO4J_ENABLED", True))
    uri: str = Field(
        default_factory=lambda: os.getenv("STRIDE_NEO4J_URI", "bolt://127.0.0.1:7688")
    )
    user: str = Field(default_factory=lambda: os.getenv("STRIDE_NEO4J_USER", "neo4j"))
    password: str = Field(
        default_factory=lambda: os.getenv("STRIDE_NEO4J_PASSWORD", "stride-graph-dev")
    )
    database: str = Field(default_factory=lambda: os.getenv("STRIDE_NEO4J_DATABASE", "neo4j"))
    browser_url: str = Field(
        default_factory=lambda: os.getenv("STRIDE_NEO4J_BROWSER", "http://127.0.0.1:7475")
    )


class AppConfig(BaseModel):
    inference: InferenceConfig = Field(default_factory=build_inference_config)
    paths: PathConfig = Field(default_factory=PathConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
