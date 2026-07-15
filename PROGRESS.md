# Port progress

## Phase 0-1 — preflight and recon

- Item: establish the source baseline and immutable port plan.
- Toolchain: the bundled preflight script was run. Its Linux-only `--break-system-packages` flag failed under macOS system Python 3.9.6, so dependency-ladder rung 1 continued with an isolated Python 3.11 environment. Pytest 9.1.1, Ruff 0.15.21, PyYAML, Pydantic, Typer, Rich, and HTTPX installed successfully.
- Recon: the source working tree is intentionally dirty; 58 non-Git files were fingerprinted without reading or copying `.env`.
- Source tests: none.
- Gate status: not yet materialized; Phase 2 scaffold is next.

## Iteration 1 — dual-platform scaffold and inference seam

- Item: scaffold the package and implement the neutral OpenAI-compatible client.
- Work: added PEP 621 metadata, platform-aware Pydantic config, vLLM/oMLX/OpenAI client, Typer `info`/`models`/`smoke-inference` commands, bundled mock server, contract runner, bounded Compose service, both launchers, and the required documentation skeleton.
- Dependency note: installing `.[dev]` in the isolated Python 3.11 environment supplied `python-dotenv`, LangGraph, Prometheus, and transitive runtime packages.
- Subagent gate claim: not applicable; Phase 2 was orchestrator-owned.
- Orchestrator verified gate: PASS — Ruff format/lint, 13 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: begin fresh-agent Ralph iterations with the threat-model workflow.

## Iteration 2 — threat-model workflow

- Item: port the STRIDE/DREAD workflow and its public assets.
- Work: copied the current CMDB and STRIDE prompts, added a host-neutral six-node LangGraph flow, tolerant JSON extraction, the fixed case-insensitive category mapping, three-attempt QA routing, final metadata/feedback/report persistence, and the `threat-model` CLI command.
- Subagent gate claim: two delegated attempts stalled before an implementation/gate result; the second copied only the approved public assets. The orchestrator decomposed and completed parser/graph/output plus CLI/tests directly under the Ralph escalation rule.
- Orchestrator verified gate: PASS — Ruff format/lint, 18 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: port the independent scenario workflow and its public assets.
