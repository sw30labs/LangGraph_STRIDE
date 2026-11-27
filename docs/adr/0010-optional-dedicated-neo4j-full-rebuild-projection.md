# 0010. Neo4j as an optional, dedicated, full-rebuild projection with a shrink guard

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The Maintain studio wants graph analytics: hub and orphan techniques, near-duplicate chains, KEV gaps, actor coverage, and so on. The host may already run another Neo4j (TwinOps) on the default ports 7474/7687.

## Decision

- A **dedicated** `neo4j:5-community` container (`compose.neo4j.yaml`, `stride-neo4j`) runs on loopback-only ports 7475/7688 with APOC. Credentials come from `STRIDE_NEO4J_*` and default to a dev password.
- The JSON attack-chain library stays the source of truth. `maintain graph sync` is a **full rebuild**: `MATCH (n) DETACH DELETE n`, then the projection is recreated:
  - chains, steps, techniques, tactics, co-occurrence and `SIMILAR_TO` edges
  - an optional intel layer: CVE/CWE/KEV, actors, advisories
  - an optional workspace layer: applications, threat models, threats, DREAD rows, scenarios, QA feedback
- `rebuild_guard_reason` refuses a sync when the graph holds at least 10 chains and the incoming library is smaller than half of that. The guard catches a "wrong-path sync" collapsing to demo seeds. `--force` overrides it.
- Canned Cypher queries back the GUI. The SQLite cache `attack_graph.sqlite` and the in-process analytics/force layout work without Neo4j. `neo4j_status` never raises when the database is down.
- The `neo4j` driver ships in the `graph` extra, and the launchers install `.[dev,graph]`.

## Consequences

### Positive
- The graph can always be rebuilt from files, so there is no drift or migration burden.
- The core studio works with Neo4j down (`tests/test_maintain.py::test_neo4j_status_does_not_raise_when_down`).

### Negative
- A sync wipes the **entire** database, so `STRIDE_NEO4J_URI` must never point at a shared instance. Only the port convention and docs enforce this.
- `neo4j` is listed in core `dependencies` as well as in the `graph` extra, so the extra adds nothing. This contradicts the docs, which say the extra is required.
- `Neo4jConfig.enabled` defaults to true, so status checks probe Bolt by default. The compose file uses `restart: unless-stopped`, unlike the vLLM service's `restart: "no"`.
- Two code-level issues:
  - The `SIMILAR_TO` edge `verdict` reads a key that `clone_pairs` does not emit, so it is always `related`.
  - The workspace projection reads `dev_category`, while the canonical CMDB key is `development_category`.

## Alternatives considered
- Incremental MERGE-only sync. Not chosen; a full rebuild was preferred, with the shrink guard added later (`486a837`).
- Reuse the TwinOps Neo4j. Explicitly rejected in `docs/NEO4J.md` ("**Not** the TwinOps graph").

## Evidence
- `compose.neo4j.yaml`; `docs/NEO4J.md`; `src/maintain/neo4j_graph.py` (`sync_attack_graph`, `rebuild_guard_reason`, `CANNED_QUERIES`, `neo4j_status`); `src/maintain/neo4j_intel.py`; `src/maintain/neo4j_workspace.py`; `src/maintain/graph.py` (`clone_pairs`)
- `pyproject.toml` (`dependencies`, `[project.optional-dependencies].graph`); `src/config.py` `Neo4jConfig`
- Commits `2f62188` (Maintain studio, Neo4j), `3aabf14`/`fc29840` (graph extra), `a92f226`, `5742411`, `31650aa`, `486a837` (shrink guard)
