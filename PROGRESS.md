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

## Iteration 3 — CVE, CTI, and threat-scenario workflow

- Item: port the scenario workflow and its public data/prompt assets.
- Work: copied the current vulnerability, attack-template, controls-taxonomy, scenario-prompt, and scenario-template assets; added the eight-stage host-neutral LangGraph flow, required attack-template validation, corrected `Platform` handling with legacy fallback, deterministic QA approvals matching the source, report persistence, and the `scenario` CLI command.
- Subagent gate claim: the delegated iteration copied approved assets but stalled before code or a gate result; the orchestrator completed the decomposed workflow/CLI/tests.
- Orchestrator verified gate: PASS — Ruff format/lint, 22 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Source-data note: the controls CSV contains 20 rows but 19 unique IDs; the source's dict construction intentionally keeps the 19 unique keys.
- Next: wire the local web GUI to the canonical CLI commands.

## Iteration 4 — CLI and dual-persona contract surface

- Item: complete the Typer command and mock-persona contract surface.
- Work: audited the already-integrated `threat-model`, `scenario`, `info`, `models`, and `smoke-inference` commands; added tests for every command plus provider-neutral URL/model/key flags and their vLLM/oMLX aliases. The contract runner continues to boot and exercise both mock personas through real CLI subprocesses.
- Subagent gate claim: the delegated audit stalled before edits or a result; the orchestrator completed the small test-only delta.
- Orchestrator verified gate: PASS — Ruff format/lint, 25 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: port the local web GUI.
