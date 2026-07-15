# Ultraport completion report

## Result

`langgraph-stride` was ported into this separate repository as one shared application for NVIDIA DGX Spark with vLLM and Apple Silicon with oMLX. The original workflows, public fixtures, browser console, and CLI behavior are retained behind a provider-neutral OpenAI-compatible inference seam. Platform detection changes configuration defaults only; workflow code has no host branches.

The independent clean-clone verifier returned **PASS** at target commit `49e724bd0c9df05b77ce61493da1579c918cdd8e`. The verification-record and report commits contain documentation only.

## Source preservation

The source repository `/Users/spider/REPOS/langgraph-stride` was treated as read-only. Its intentionally dirty working tree was the authoritative snapshot, because it contains current functionality absent from HEAD. No source `.env` was read or copied.

| Check | Baseline and final result |
|---|---|
| Git HEAD | `ab67d6c7ca46149b370062ec94137b5bd18b9a10` |
| `git status --porcelain=v1 -z` SHA-256 | `ff5478dbd4bc365543e922d10635f2ed56215429b17bec5583d74ad3b94bda0a` |
| Sorted non-`.git` file-tree SHA-256 | `726b2fa48e8f6a63f7e779653bdc6d6b87af0db1d67712f9e65dc1e02f54b061` |
| Non-`.git` file count | 58 |
| Source test inventory | 0 tests |

All four values matched again after the port and during independent verification.

## Architecture and portability seams

| Area | Ported design |
|---|---|
| Configuration | Typed Pydantic tree with environment aliases and host-aware backend, device, and concurrency defaults |
| Inference | One cached `OpenAICompatibleClient` for vLLM, oMLX, or explicit OpenAI; normalizes `/v1`, bypasses loopback proxies, strips thinking tags, reserves context, and handles truncation |
| Threat modeling | Shared six-node LangGraph for STRIDE generation, bounded QA retry, DREAD generation, bounded QA retry, final QA, feedback, and persistence |
| Scenarios | Shared eight-node LangGraph for CVE selection, CTI generation, controls, threat scenario generation, QA, and persistence |
| User interfaces | Typer CLI plus a packaged local browser console; GUI jobs call the canonical CLI surface |
| Runtime assets | Public data, prompts, and web assets are package data; generated reports remain workspace-local |
| Metrics | Optional and disabled by default, avoiding inference port 8000 |

| Host | Default backend | Device | Concurrency | Launcher |
|---|---|---|---:|---|
| Linux/ARM64 DGX Spark | vLLM | CUDA | 2 | `setup_and_run_dgx.sh` |
| Darwin/ARM64 Apple Silicon | oMLX | MPS | 4 | `setup_and_run_macos.sh` |
| Other host | oMLX | CPU | 4 | Manual CLI install |

## Compatibility decisions

- Preserved the current CMDB, STRIDE/DREAD, CVE/CTI/scenario, controls-taxonomy, local GUI, provider aliases, and JSON output surfaces.
- Retained `mlx` as an alias for `omlx`, plus provider-neutral and vLLM/oMLX-specific CLI aliases.
- Retained the source's `--db-path` scenario option as a documented compatibility placeholder; deterministic tracked vulnerability data remains authoritative today.
- Repaired clear source defects: case-insensitive STRIDE category matching, the misspelled `Platform` access, required scenario-template selection, environment precedence, and inference-error QA retry/fallback behavior.
- Merged near-duplicate legacy workflow files into the current canonical implementations instead of shipping parallel stale entry points.
- Did not port `.env`, `.humanize/`, `.DS_Store`, generated logs/reports, deleted historical fixtures, or local caches.

## Verification evidence

| Verification | Result |
|---|---|
| Ruff format and lint | PASS |
| Port pytest inventory | 43 passed |
| CLI import smoke | PASS |
| vLLM mock contract e2e | PASS |
| oMLX mock contract e2e | PASS |
| Wheel build and isolated install | PASS, 82,348-byte wheel |
| Wheel runtime assets | PASS, 4 data files and 3 prompt files installed |
| Non-checkout output default | PASS, output resolved below the current workspace |
| Manual README `info`, `models`, `smoke-inference` with vLLM mock | PASS |
| Manual README `info`, `models`, `smoke-inference` with oMLX mock | PASS |
| Fresh-clone and original-target cleanliness | PASS, zero target status entries |
| Independent verifier | PASS |

The source had no test suite, so all 43 target tests are new contract, workflow, configuration, GUI, platform, packaging, and regression coverage.

## On-hardware smoke instructions

DGX Spark requires Linux/ARM64, a visible GB10 GPU, Docker/Compose with NVIDIA runtime, Python 3.12, and a Hugging Face token only when this repository must start its own model:

```bash
./setup_and_run_dgx.sh doctor
./setup_and_run_dgx.sh setup
./setup_and_run_dgx.sh llm-up
./setup_and_run_dgx.sh smoke
./setup_and_run_dgx.sh run serve
```

Apple Silicon requires Conda and a running oMLX OpenAI-compatible endpoint:

```bash
./setup_and_run_macos.sh smoke-inference
./setup_and_run_macos.sh serve
```

Actual GB10/CUDA and MPS model execution could not run on the verifier's Apple host. The launchers own these explicit live checks; hardware calls are intentionally excluded from pytest. See `README.md`, `.env.example`, and `docs/DGX_SPARK.md` for setup, service ownership, configuration, and troubleshooting.

## Final acceptance

The port meets the immutable acceptance plan: separate repository, source preserved, shared business logic, dual platform defaults, bounded DGX service, Apple oMLX path, packaged assets, complete documentation, green full gate, independent clean-clone PASS, and a committed clean target tree.
