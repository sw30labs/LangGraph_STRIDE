# Architecture Decision Records

These are retrospective ADRs, reconstructed on 2026-11-27 from a full read of the repository at commit `baa8eb2`. Where a rationale is inferred rather than documented, the ADR says so, and the inference is logged in [`../assumptions.md`](../assumptions.md).

| # | Title | Status |
|---|---|---|
| [0001](0001-separate-repo-port-under-immutable-plan.md) | Port the legacy langgraph-stride app into a separate repository under an immutable port plan | Accepted (retrospective, inferred 2026-11-27) |
| [0002](0002-langgraph-stategraph-workflows.md) | Use LangGraph StateGraph for the threat-model and scenario workflows | Accepted (retrospective, inferred 2026-11-27) |
| [0003](0003-provider-neutral-openai-compatible-client.md) | One provider-neutral OpenAI-compatible inference client | Accepted (retrospective, inferred 2026-11-27) |
| [0004](0004-platform-detection-changes-defaults-only.md) | Platform detection changes defaults only; configuration lives in one Pydantic module | Accepted (retrospective, inferred 2026-11-27) |
| [0005](0005-dual-platform-launchers-with-service-ownership.md) | Dual-platform launchers with explicit service ownership | Accepted (retrospective, inferred 2026-11-27) |
| [0006](0006-packaged-prompts-and-tolerant-json-parsing.md) | Prompts as packaged YAML; tolerant JSON parsing of model output | Accepted (retrospective, inferred 2026-11-27) |
| [0007](0007-workspace-local-state-and-artifact-lineage.md) | Mutable workspace under output/, package data as seed-only, and `_meta` artifact lineage | Accepted (retrospective, inferred 2026-11-27) |
| [0008](0008-offline-first-local-intel-catalogs.md) | Offline-first local intel catalogs (NVD SQLite, MITRE JSON, CTI pack files) | Accepted (retrospective, inferred 2026-11-27) |
| [0009](0009-heuristic-attack-mapping-with-confidence-labels.md) | Heuristic ATT&CK and actor mapping, labelled by confidence | Accepted (retrospective, inferred 2026-11-27) |
| [0010](0010-optional-dedicated-neo4j-full-rebuild-projection.md) | Neo4j as an optional, dedicated, full-rebuild projection with a shrink guard | Accepted (retrospective, inferred 2026-11-27) |
| [0011](0011-graph-grounded-cti-with-file-pack-fallback.md) | Graph-grounded CTI generation with silent fallback to file packs | Accepted (retrospective, inferred 2026-11-27) |
| [0012](0012-local-stdlib-gui-running-cli-subprocess-jobs.md) | Local standard-library GUI that runs CLI subprocess jobs | Accepted (retrospective, inferred 2026-11-27) |
| [0013](0013-dependency-free-pdf-export.md) | Dependency-free PDF export | Accepted (retrospective, inferred 2026-11-27) |
| [0014](0014-maintain-forge-deterministic-gate-plus-llm-judge.md) | Maintain forge: deterministic novelty gate plus LLM judge, with a human commit step | Accepted (retrospective, inferred 2026-11-27) |
| [0015](0015-offline-test-strategy-with-mock-inference-personas.md) | Offline test strategy: mock inference personas, fixtures, and a single gate script | Accepted (retrospective, inferred 2026-11-27) |
| [0016](0016-opt-in-metrics-on-a-separate-port.md) | Prometheus metrics opt-in, on a port separate from inference | Accepted (retrospective, inferred 2026-11-27) |
| [0017](0017-thinking-off-by-default-with-reasoning-strength.md) | Model thinking off by default, with explicit thinking and reasoning-strength controls | Accepted (retrospective, inferred 2026-11-27) |

New ADRs should use the next free number and the same section layout: Status, Context, Decision, Consequences, Alternatives considered, Evidence.
