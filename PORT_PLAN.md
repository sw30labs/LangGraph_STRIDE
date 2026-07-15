# LangGraph STRIDE dual-platform port plan

This is the immutable implementation specification for porting the current working-tree snapshot of `/Users/spider/REPOS/langgraph-stride` into a separate ScreenLens-style repository. Only the Assumptions section may be appended after this commit.

## Source baseline

- Source HEAD: `ab67d6c7ca46149b370062ec94137b5bd18b9a10`.
- The source is intentionally dirty and its working tree, not HEAD, is the port input.
- Baseline status digest: `ff5478dbd4bc365543e922d10635f2ed56215429b17bec5583d74ad3b94bda0a`.
- Baseline non-Git file-tree digest: `726b2fa48e8f6a63f7e779653bdc6d6b87af0db1d67712f9e65dc1e02f54b061` across 58 files.
- Source test inventory: zero test files, zero test functions, zero fixtures, and no test configuration.
- The source `.env` is private input and must never be read, copied, committed, or overwritten.

## Source inventory

| Source area | Current behavior | Target disposition |
|---|---|---|
| `src/python/model.py` | LangGraph STRIDE generation, DREAD scoring, QA retry loops, JSON and feedback output | Port to `src/threat_model.py` behind the neutral inference seam |
| `src/python/scenario.py` | LangGraph CVE, CTI, and threat-scenario workflow with JSON output | Port to `src/scenario.py` behind the same inference seam |
| `src/python/utils.py` | OpenAI/oMLX selection, environment resolution, URL normalization | Replace with `src/config.py` and `src/inference_client.py` |
| `src/python/gui.py` and `src/gui/*` | Local web console, job execution, output browsing | Port to `src/gui.py` plus packaged static assets |
| `src/python/threatModel.py`, `threatScenario.py` | Earlier near-duplicate refactors of the two authoritative scripts | Merge their reusable cleanup into canonical snake-case modules; no duplicate runtime path |
| `src/yaml/*` | STRIDE, DREAD, QA, CVE, CTI, and scenario prompts/templates | Preserve current snapshot as package data and validate with tests |
| `data/cmdb.json` | Three sample application records | Preserve as sample data |
| `data/demo_critical_vulnerability.json` | One deterministic vulnerability fixture | Preserve as sample data |
| `data/predefined_attack_templates.json` | 27 attack templates, including uncommitted additions | Preserve current snapshot as sample data |
| `data/control_taxonomy.csv` | 20 security controls | Preserve as sample data |
| `requirements.txt` | Python runtime dependency list | Replace with PEP 621 metadata in `pyproject.toml` |
| `README.md`, `CLAUDE.md`, `LICENSE` | Project docs and Apache-2.0 terms | Rewrite docs for the port; retain Apache-2.0 |
| `logs/`, `output/`, deleted historical data | Generated or absent in the current snapshot | Do not port; keep generated paths gitignored |
| `.humanize/`, `.DS_Store`, `.env` | Local tooling, OS metadata, secrets | Do not port |

## User-facing compatibility surface

- Threat-model input: AA ID plus an inference provider selection.
- Scenario input: threat-model JSON path, attack-template name, minimum CVSS value, and the retained `db_path` compatibility option.
- Outputs: timestamped threat-model, QA-feedback, and scenario JSON files under `output/`.
- Local browser UI: status, CMDB and attack-template selection, job launch, logs, and report preview.
- Hosted OpenAI remains an explicit optional backend because it is a current source feature; vLLM and oMLX are the platform defaults.
- `mlx` and `omlx` remain accepted aliases. Provider-neutral URL/model/key options also expose `--vllm-*` and `--omlx-*` aliases.

## Target architecture

```text
Typer CLI / local web UI
        |
        v
AppConfig (platform-aware defaults only)
        |
        v
OpenAICompatibleClient
   | vLLM (DGX Spark) | oMLX (Apple Silicon) | OpenAI (explicit)
        |
        v
Shared LangGraph workflows
   | threat model | scenario generation |
        |
        v
Local JSON artifacts
```

Business logic never branches on the host platform. `src/config.py` is the only module allowed to translate host detection into backend, device, and concurrency defaults.

## Seams

| Capability | Source coupling | Port seam | Acceptance evidence |
|---|---|---|---|
| Text inference | `ChatOpenAI` created inside workflow helpers | `OpenAICompatibleClient` configured for `vllm`, `omlx`, or explicit `openai` | Client unit tests and dual-persona contract e2e |
| Platform selection | No host detection | `AppConfig` default factories | Linux/ARM64, Darwin/ARM64, and other-host tests |
| Endpoint quirks | oMLX-only helper | Provider-neutral URL normalization, thinking stripping, context reservation, model listing, and truncation policy | Focused inference-client tests |
| Filesystem inputs/outputs | Global repo-relative string paths | Typed `PathConfig` passed into workflows | Temporary-directory workflow and GUI tests |
| Metrics | Unconditional Prometheus server on port 8000, conflicting with local inference | Optional, separately configured metrics port; disabled by default | Config and CLI tests |
| GUI subprocesses | Hard-coded source script paths | Console-script commands using the same config contract | GUI job-construction and HTTP tests |

No camera, media, embedding, or vision capability exists in this application, so those hardware seams are intentionally not invented.

## Milestones and acceptance criteria

1. **Scaffold and config** — PEP 621 package, gate, config tree, platform matrix, mock server, and an initially green gate.
2. **Neutral inference seam** — URL normalization, backend resolution, model listing, thinking stripping, token-budget behavior, truncation handling, and cache all have focused tests.
3. **Threat-model workflow** — current prompt/data behavior, QA retry ceiling, tolerant JSON parsing, metadata, feedback, and output naming pass unit and mocked workflow tests.
4. **Scenario workflow** — current CVE/CTI/scenario stages, templates, control taxonomy, compatibility options, and output schema pass unit and mocked workflow tests.
5. **CLI and contract e2e** — all core verbs, neutral flags/aliases, `info`, `models`, and both mock personas pass through `gate.sh`.
6. **Local web GUI** — current status, safe file preview, job construction, static serving, and report browsing are preserved and tested.
7. **Platform operations** — bounded DGX Compose service, ownership-safe DGX helper, Apple Silicon Conda helper, doctor/setup/service/smoke/run commands, and syntax/surface tests pass.
8. **Documentation and environment taxonomy** — README, AGENTS, CLAUDE, DGX guide, `.env.example`, Apache license, and machine-readable test cases accurately match code.
9. **Hardening and verification** — full gate is green, source digests match baseline, clean clone installs and passes, verifier reports PASS, and `PORT_REPORT.md` records final evidence.

## Test-inventory map

The source has no tests to port. This explicit empty map is complete:

| Source test | Target counterpart | Disposition |
|---|---|---|
| _None_ | New port tests under `tests/` | No source tests existed; target coverage is contract-derived |

Target tests must cover config, inference, prompt/data loaders, both workflows, CLI, GUI, launchers/Compose, and dual-persona e2e. Live hardware calls stay in launcher `smoke` commands, never in pytest.

## Assumptions

1. The present dirty working tree is intentional user work and is the only defensible source of truth; HEAD-only behavior would discard the GUI, oMLX support, CMDB migration, controls taxonomy, and attack-template additions.
2. `model.py` and `scenario.py` are authoritative because README invokes them and they include token tracking. The same-timestamp `threatModel.py` and `threatScenario.py` are near-duplicates, not separate products.
3. Port correctness includes repairing obvious source defects rather than preserving them: `cat.lower` is changed to `cat.lower()`, `PLatform` to `Platform`, scenario attack-template input is required before save, and shell exports keep precedence over `.env`.
4. The Prometheus service is optional and moves away from inference port 8000; inference must work without metrics.
5. The source's unused `db_path` option is retained for CLI compatibility and clearly documented as reserved for a future external CVE database.
6. Generated logs and reports are runtime artifacts, not source fixtures. The current sample data and prompt files are source fixtures and will be preserved.
7. Core quickstart verification uses `info`, `models`, and a real seam-level `smoke-inference` command against the bundled mock server. Full domain workflows require structured model output and are tested with deterministic response fixtures.
8. The bundled Ultraport contract outranks drift in the live ScreenLens exemplar for Ruff, the other-host test, import smoke, and dual-persona e2e. Live ScreenLens hardening patterns outrank the distilled examples for URL cleanup, proxy bypass, `max_tokens >= context` omission, and service ownership.
9. Target runtime fixtures live under `src/data/` and `src/prompts/` so wheel installs preserve the source assets; generated output remains workspace-local.
