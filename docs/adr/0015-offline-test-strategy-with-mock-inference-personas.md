# 0015. Offline test strategy: mock inference personas, fixtures, and a single gate script

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The source had no tests. The port must be verified in sandboxes with no GPU, no Apple Silicon, no model server and no network, and still show the differences between the vLLM and oMLX personas.

## Decision

- `tests/mock_inference_server.py` is a stdlib OpenAI-compatible stub with two personas. `vllm` serves an NVIDIA model id. `omlx` serves an MLX id and emits `<think>` unless `enable_thinking=false`. It also serves a dashboard URL and can emulate truncation.
- `tests/run_contract_e2e.py` drives the real CLI (`info`, `models` through a dashboard URL, `smoke-inference`) against each persona.
- Unit tests use fake clients, `httpx.MockTransport`, monkeypatched `platform`, and offline intel fixtures under `tests/fixtures/intel/`.
- `gate.sh` is the one acceptance command: `ruff format --check`, `ruff check`, `pytest`, an import smoke and both persona e2e runs. Real-hardware smoke tests (`setup_and_run_dgx.sh smoke`, `setup_and_run_macos.sh smoke-inference`) are listed as live scenarios in `tests/test_cases.yaml` and kept out of pytest.
- Documentation is tested too (`tests/test_docs.py`): README command coverage, the required document set, the CLAUDE.md Karpathy clause, and the package-data declaration.

## Consequences

### Positive
- The full gate runs anywhere in seconds, and persona differences such as thinking stripping and URL normalisation are covered.

### Negative
- Nothing in the repo exercises real model quality or real server quirks; that relies on manual live smoke runs.
- There is no CI workflow in the repo yet (the README roadmap lists CI runners as future work), so the gate runs only when someone runs it.

## Alternatives considered
- Record and replay real model responses. Not evidenced.
- Hosted CI with scheduled on-hardware smoke tests. Deferred, not rejected: it is on the README roadmap.

## Evidence
- `tests/mock_inference_server.py`, `tests/run_contract_e2e.py`, `tests/test_cases.yaml`, `tests/test_*.py`, `tests/fixtures/intel/*`, `gate.sh`
- `PORT_PLAN.md` Assumption 9 and "Test inventory map"; `PORT_REPORT.md`
- Commits `0f62f72`, `000f560` (lock provider-neutral CLI surface), `b3ca292` (adds `tests/test_docs.py`), `49e724b`
