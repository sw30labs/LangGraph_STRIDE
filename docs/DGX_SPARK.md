# NVIDIA DGX Spark

DGX Spark runs the same application code as Apple Silicon. Its defaults select the bounded vLLM service, CUDA, and concurrency two; `src/config.py` is the only place where host detection changes those values.

## Prerequisites and setup

Install Docker with the NVIDIA runtime, Docker Compose, Python 3.12, and an NVIDIA driver visible through `nvidia-smi`. Create a private `.env` and add a Hugging Face read token only when this repository must start its own container:

```bash
(umask 077; touch .env)
chmod 600 .env
./setup_and_run_dgx.sh doctor
./setup_and_run_dgx.sh setup
./setup_and_run_dgx.sh llm-up
./setup_and_run_dgx.sh smoke
```

`llm-up` first asks the configured endpoint for its model list. It reuses an exact-model service, refuses to replace a different service on the same port, and starts this repository's Compose service only when the port is free. `llm-down` and `llm-logs` address only this repository's Compose project.

## Command reference

- `doctor`: validate Linux/ARM64, Docker/Compose, and NVIDIA visibility.
- `setup`: create `.venv-dgx` with Python 3.12 and install the app.
- `llm-up`, `llm-wait`, `llm-down`, `llm-logs`: manage or reuse inference safely.
- `smoke`: send a real request through the application client.
- `run [ARGS...]`: export DGX defaults and execute the CLI.

The service is loopback-only, digest-pinned, revision-pinned, non-restarting, and bounded to two sequences with explicit memory and context ceilings. Cache directories live under `.local-models/` and survive container replacement.

If readiness fails, compare `VLLM_MODEL`, `VLLM_BASE_URL`, the served `/v1/models` response, Docker logs, and available unified memory. Do not raise concurrency or memory utilization without measuring the full workload.

Apple Silicon remains supported by the same codebase through `setup_and_run_macos.sh` and an oMLX endpoint.

