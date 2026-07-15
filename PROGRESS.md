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

## Iteration 5 — local web GUI

- Item: port the local browser console onto the canonical CLI and configuration paths.
- Work: added the packaged HTML/CSS/JavaScript console, repo-confined JSON preview, status and job APIs, in-memory job logs, provider alias handling, and background commands that invoke `python -m src.cli threat-model` or `scenario` with explicit configured paths. Added the `serve` CLI command and focused tests for status data, traversal rejection, command construction, jobs, and static serving without starting inference subprocesses.
- Subagent gate claim: PASS — Ruff format/lint, 30 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Orchestrator verified gate: PASS — independently rerun with the same 30 tests and both persona e2e checks.
- Next: harden the platform operations files and their surface tests.

## Iteration 6 — platform operations hardening

- Item: harden the DGX Spark Compose service and both platform launchers.
- Work: added literal whitelisted `.env` parsing with exported values winning, exact model/context reuse checks, external-service ownership guards, repository-owned down/log behavior, Python 3.12 and pinned CUDA 13 torch wheels on Spark, live seam smoke, Apple Silicon Conda Python 3.11 validation, and default GUI launch. Compose remains digest/revision pinned, loopback-only, non-restarting, and bounded to two sequences.
- Subagent gate claim: the delegated iteration tightened Compose scalar quoting but stalled before launcher completion.
- Orchestrator verified gate: PASS — Bash syntax, Ruff format/lint, 31 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: reconcile all documentation and environment/test matrices with the implemented application.

## Iteration 7 — documentation and machine-readable scenarios

- Item: reconcile the full documentation set with the completed port.
- Work: replaced scaffold-era README text with complete install, configuration, command, input/output, structure, verification, and roadmap sections; expanded agent and architecture guidance; documented DGX service ownership, pinned CUDA setup, command lifecycle, sizing, and troubleshooting; expanded the test-case matrix with all three platform defaults, both persona contracts, live smokes, and domain examples; added documentation consistency tests. The Karpathy clause remains verbatim.
- Subagent gate claim: the delegated documentation iteration stalled before edits or a result.
- Orchestrator verified gate: PASS — Ruff format/lint, 34 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: harden the complete repository and run independent clean-clone verification.

## Iteration 8 — pre-verifier hardening

- Item: audit unused configuration/dependencies, inference edge cases, and source preservation.
- Work: made the source Prometheus feature explicit and opt-in through `STRIDE_METRICS_PORT`/`--metrics-port`, removed the unused log-path option, added non-fatal truncation warnings, accepted the `mlx` alias in direct client construction, and implemented one structured vLLM context-error retry using `/tokenize` when available or server-managed remaining context otherwise.
- Source verification: HEAD, dirty-status digest, and all-file digest exactly match the Phase 0 baseline.
- Orchestrator verified gate: PASS — Ruff format/lint, 38 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Next: focused seam review, then independent clean-clone verification.

## Iteration 9 — focused seam review fixes

- Review verdict: FAIL with three findings — environment metrics were suppressed by an explicit CLI `None`, device/concurrency lacked runtime and direct-command wiring, and a 2xx non-JSON `/tokenize` response bypassed the intended fallback.
- Fixes: preserved `WorkflowConfig`'s environment default when the flag is absent; added `--device` and `--batch-size`/`--concurrency` across inference and workflow commands; used concurrency for the HTTP connection pool and device for request observability; made tokenizer JSON decode failures fall back to a server-managed completion budget.
- Orchestrator gate: PASS — Ruff format/lint, 39 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Focused seam re-review: PASS at `46fc544`; all three findings have regression coverage.
- Next: independent clean-clone verification.

## Iteration 10 — independent-verifier findings

- Independent clean-clone verdict: FAIL with four findings — QA transport errors escaped the source-style retry/fallback path, the client cache lacked focused tests, runtime data/prompts were missing from built wheels, and DGX doctor did not execute or report every prerequisite claimed by the docs.
- Fixes: made STRIDE/DREAD QA errors enter the bounded retry loop and final-QA errors retain the assembled report; added cache identity/persona regression coverage; relocated public assets into package data with workspace-local output defaults; and made DGX doctor validate Python 3.12, query the GB10 GPU, and report host, Python, Docker, and Compose versions.
- Next: run the complete gate, verify a built wheel, and repeat independent clean-clone verification.

## Iteration 11 — clean-clone verifier pass

- Independent verdict: PASS at `49e724b` from a fresh clone and Python 3.11.15 environment.
- Packaging: a built wheel installed outside the checkout with all four data assets and three prompt assets; generated output resolved below the non-checkout working directory.
- Gate: PASS — Ruff format/lint, 43 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Manual quickstarts: `info`, `models`, and `smoke-inference` passed separately against both vLLM and oMLX mock servers with no thinking-tag leakage.
- Source verification: HEAD `ab67d6c7ca46149b370062ec94137b5bd18b9a10`, status digest `ff5478dbd4bc365543e922d10635f2ed56215429b17bec5583d74ad3b94bda0a`, 58-file digest `726b2fa48e8f6a63f7e779653bdc6d6b87af0db1d67712f9e65dc1e02f54b061`, and zero source tests all matched the baseline.
- Cleanliness: the verifier's clone and the original target both had zero status entries.
- Next: write the final port report, rerun the gate, and leave the committed tree clean.

## Iteration 12 — completion report

- Item: record final architecture, compatibility decisions, source preservation, test inventory, independent evidence, and live hardware smoke instructions.
- Work: added `PORT_REPORT.md` and closed the complete Ralph worklist.
- Final gate: PASS — Ruff format/lint, 43 tests, import smoke, vLLM persona e2e, and oMLX persona e2e.
- Final source audit: HEAD, status digest, 58-file count, and non-Git file-tree digest all match the immutable baseline.
- Handoff: this documentation-only delta is the final commit; the clean-tree confirmation follows it.
