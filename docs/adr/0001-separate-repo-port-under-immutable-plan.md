# 0001. Port the legacy langgraph-stride app into a separate repository under an immutable port plan

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

An earlier, test-less LangGraph STRIDE app lived in a different local working tree (a dirty tree on top of source HEAD `ab67d6c`). It mixed OpenAI and oMLX selection into workflow helpers, kept near-duplicate scripts (`model.py`/`threatModel.py`, `scenario.py`/`threatScenario.py`), ran Prometheus on port 8000 (the same port as local inference), and used repo-relative string paths. The goal was to run the same app on NVIDIA DGX Spark (vLLM) and Apple Silicon (oMLX).

## Decision

Build the port in a **new, ScreenLens-style repository** that follows the bundled "Ultraport" contract, and leave the source read-only. The work follows an "immutable implementation specification" (`PORT_PLAN.md`): a source inventory with SHA-256 digests, the user-facing compatibility surface, the target architecture, the seams, nine milestones, an explicitly empty test-inventory map, and an Assumptions section that may only be appended to. Progress is tracked in a "Ralph loop" worklist (`fix_plan.md`) and a per-iteration log (`PROGRESS.md`). The port finishes with an independent clean-clone verifier and a completion report (`PORT_REPORT.md`) that re-checks the source digests.

## Consequences

### Positive
- Source preservation can be audited: the HEAD, status digest and file-tree digest were re-verified after the port.
- Every compatibility decision is written down (e.g. kept the `mlx` alias and the `--db-path` placeholder; fixed `cat.lower`/`PLatform` defects).
- Review findings (seam review, clean-clone verifier) became tracked worklist items with regression tests.

### Negative
- `PORT_PLAN.md`, `PORT_REPORT.md`, `PROGRESS.md` and `fix_plan.md` describe the July 2026 port and are now historical. The August 2026 features (workspace, intel, Maintain, Neo4j) are not reflected there.
- The "immutable" rule for `PORT_PLAN.md` is a convention only; nothing enforces it.

## Alternatives considered
- Refactor the source repository in place. Not chosen, because the plan treats the source as read-only and its dirty tree as authoritative (PORT_PLAN Assumption 1).
- Copy the ScreenLens exemplar's live drift wholesale. Ruled out by PORT_PLAN Assumption 8: the bundled Ultraport contract wins for Ruff, other-host tests, import smoke and dual-persona e2e.
- Port from source HEAD only. Rejected in PORT_PLAN Assumption 1: it would drop the GUI, oMLX support, CMDB migration, controls taxonomy and template additions.

## Evidence
- `PORT_PLAN.md` (source baseline, inventory, seams, milestones, Assumptions 1–9); `PORT_REPORT.md`; `PROGRESS.md`; `fix_plan.md`
- Commits `1a9306b` (scaffold port plan), `0f62f72` (dual-platform foundation), `49e724b` (clean-clone findings), `e1eec2e`, `b480191` (verified port report)
