# NVIDIA DGX Spark

DGX Spark runs the same Python package and LangGraph workflows as Apple Silicon. `src/config.py` changes the zero-override defaults to vLLM, CUDA, and concurrency two; no workflow module branches on the host.

## Architecture and service ownership

The application talks to `VLLM_BASE_URL` through `OpenAICompatibleClient`. `llm-up` first queries `/v1/models` and reuses a service only when both `VLLM_MODEL` and the advertised context satisfy `VLLM_MAX_MODEL_LEN`. A different model, smaller context, opaque port occupant, or unavailable custom endpoint is fatal. This prevents the helper from replacing or stopping a service owned by another stack.

`llm-down` and `llm-logs` act only when this repository's Compose project has an `llm` container. Shared services remain untouched.

## Prerequisites

- NVIDIA DGX Spark (Linux/ARM64 with GB10 visible through `nvidia-smi`).
- Docker, the Compose plugin, and NVIDIA Container Runtime.
- Python 3.12 with `venv` support.
- About 70 GiB free for the first image/model pull.
- A Hugging Face read token only when this repository must start its own model.

The helper installs pinned CUDA 13 wheels (`torch==2.11.0+cu130`, `torchvision==0.26.0+cu130`) before the editable application and verifies that CUDA is usable. Generic PyPI torch wheels are not substituted.

## One-time setup and validation

```bash
(umask 077; touch .env)
chmod 600 .env
# Add HF_TOKEN=hf_... only if no exact shared endpoint is already ready.
./setup_and_run_dgx.sh doctor
./setup_and_run_dgx.sh setup
```

The helper parses a strict whitelist of literal `.env` assignments; it never executes the file as shell code, and exported nonempty variables win.

## Run

```bash
./setup_and_run_dgx.sh llm-up
./setup_and_run_dgx.sh llm-wait
./setup_and_run_dgx.sh smoke
./setup_and_run_dgx.sh run serve
```

The Compose service is ARM64, digest-pinned, model-revision-pinned, loopback-only, `restart: "no"`, host IPC, and bounded to memory utilization 0.45, two sequences, 8,192 batched tokens, and an explicit context ceiling. Hugging Face and vLLM caches remain under `.local-models/` across container replacement.

## Command reference

| Command | Purpose |
|---|---|
| `doctor` | Validate host, Python, NVIDIA, Docker/Compose, token need, and exact-service reuse |
| `setup` | Create/reuse `.venv-dgx`, install pinned CUDA wheels and `.[dev,graph]`, validate CUDA |
| `llm-up` | Reuse an exact service or start this repository's container |
| `llm-wait` | Wait for exact model and context readiness |
| `llm-down` | Stop only this repository's Compose service |
| `llm-logs` | Follow only this repository's model logs |
| `smoke` | Send one live request through the application client |
| `run [ARGS...]` | Force vLLM/CUDA/concurrency-two defaults and execute the CLI; defaults to `serve` |

## Configuration and sizing

Use `.env.example` as the catalog. The most important settings are `VLLM_IMAGE`, `VLLM_MODEL`, `VLLM_MODEL_REVISION`, `VLLM_BASE_URL`, `VLLM_MAX_MODEL_LEN`, `VLLM_GPU_MEMORY_UTILIZATION`, `VLLM_START_TIMEOUT`, and the two cache paths. Do not raise memory utilization, context, batched tokens, or concurrency independently; measure unified-memory pressure across the complete workload.

## Troubleshooting

- **Wrong model/context:** change the application configuration or fix the service at its owning stack. The helper intentionally refuses reuse.
- **Port 8000 occupied:** identify the owner; do not use `llm-down` unless this repository created the container.
- **Container exits while loading:** run `llm-logs`, then inspect token access, disk, model revision, and available memory.
- **CUDA check fails:** verify driver/runtime visibility and rerun `doctor`; do not replace the checked CUDA index with generic wheels.
- **Timeout:** large first pulls may need a higher positive `VLLM_START_TIMEOUT`.

Apple Silicon remains supported by the same repository through `setup_and_run_macos.sh` and an oMLX OpenAI-compatible endpoint.

