# 0005. Dual-platform launchers with explicit service ownership

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The DGX Spark and the Mac may already run inference servers that belong to other stacks. One example is the shared `127.0.0.1:8000` endpoint. A launcher that blindly starts, reuses or stops containers could break those stacks or quietly use the wrong model.

## Decision

- **DGX Spark** (`setup_and_run_dgx.sh` + `compose.dgx-spark.yaml`) provides:
  - `doctor`/`setup`: Python 3.12 venv, CUDA 13 PyTorch pinned to `2.11.0+cu130`, `.[dev,graph]`.
  - `llm-up`/`llm-wait`/`llm-down`/`llm-logs`/`smoke`/`run`.
  - `llm-up` reuses an existing endpoint only when it serves the exact configured model and context length (it checks `max_model_len` from `/v1/models`). Otherwise it refuses.
  - `llm-down` and `llm-logs` act only on this project's own Compose container.
  - The vLLM image is pinned by digest, the model by revision. It binds to loopback, uses `restart: "no"`, `--max-num-seqs 2` and `--gpu-memory-utilization 0.45`.
  - `.env` goes through a whitelist parser (`load_repo_dotenv`) and is never sourced. `run` forces `vllm`/`cuda`/2.
- **macOS** (`setup_and_run_macos.sh`) uses a Conda env with Python 3.11 and `.[dev,graph]`. It defaults to `omlx`/`mps`/4, expects an external oMLX server, defaults to the web console, never overwrites `.env`, and redirects to the DGX helper when run on a DGX host.

## Consequences

### Positive
- The project will not take over or stop a service it does not own, and it will not run against a mismatched model or context length.
- Pinned image digest, model revision and torch wheels make DGX setups reproducible. Tests check the bounds by reading the scripts (`tests/test_dgx_spark.py`).

### Negative
- The two platforms run different Python versions (3.12 vs 3.11), so the matrix has to cover both.
- Pinned digests and revisions go stale and must be bumped by hand.
- The launchers are bash scripts, checked only for syntax (`bash -n`) and for string presence.

## Alternatives considered
- One generic launcher, or Docker on macOS. Not evidenced. oMLX runs natively outside the repo (inferred).
- Let the GUI manage inference servers. Rejected in the README "Local GUI" section: the console "does not start, stop, or reuse model servers".

## Evidence
- `setup_and_run_dgx.sh`, `setup_and_run_macos.sh`, `compose.dgx-spark.yaml`, `docs/DGX_SPARK.md`, `README.md` "Install and run", `.env.example`
- `tests/test_dgx_spark.py`; `PORT_PLAN.md` Assumption 7
- Commits `0f62f72`, `1c18420` (harden dual-platform launchers), `46fc544`, `49e724b`
