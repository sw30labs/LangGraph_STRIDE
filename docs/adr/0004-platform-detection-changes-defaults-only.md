# 0004. Platform detection changes defaults only; configuration lives in one Pydantic module

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

One codebase has to behave correctly on Linux/ARM64 (DGX Spark), Darwin/ARM64 (Apple Silicon) and other hosts, without forking workflow code.

## Decision

`src/config.py` is the only module that turns host detection (`platform.system()`/`machine()`) into defaults:

| Host | Backend | Device | Concurrency |
|---|---|---|---|
| Linux/ARM64 | vLLM | CUDA | 2 |
| Darwin/ARM64 | oMLX | MPS | 4 |
| Other | oMLX | CPU | 4 |

Settings are typed Pydantic models (`InferenceConfig`, `PathConfig`, `WorkflowConfig`, `Neo4jConfig`, `AppConfig`), each with environment-driven default factories. `.env` is loaded from the current directory and the project root with `override=False`, so exported shell variables win. CLI flags override the environment. AGENTS.md: "Never add Darwin/Linux branches to workflow, GUI, or inference business logic."

## Consequences

### Positive
- Host behaviour is testable by monkeypatching `platform` (`tests/test_config.py`, `tests/test_cases.yaml`).
- Workflows, the GUI and the client get a resolved config and stay host-neutral.

### Negative
- `.env` is loaded as an import side effect of `src.config`.
- Unknown `STRIDE_BACKEND` values are silently ignored and fall back to host defaults instead of raising an error.
- `device` is only a label (an HTTP header and the request pool); no local compute uses it.

## Alternatives considered
- Per-platform code paths or separate packages. Explicitly forbidden by AGENTS.md and PORT_PLAN "Target architecture".

## Evidence
- `src/config.py` (`is_dgx_spark_host`, `default_inference_backend`, `default_device`, `default_concurrency`, `load_dotenv_if_present`)
- `AGENTS.md`; `CLAUDE.md`; `README.md` "Platform defaults"; `tests/test_config.py`; `tests/test_cases.yaml`
- Commits `0f62f72`, `46fc544` (device/concurrency wiring), `b3ca292`
