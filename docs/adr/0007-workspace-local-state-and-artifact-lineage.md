# 0007. Mutable workspace under output/, package data as seed-only, and `_meta` artifact lineage

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Packaged files in `src/data` are read-only fixtures in an installed wheel. Operators still need to edit the CMDB and the attack-chain library, and to trace each scenario back to the threat model it came from.

## Decision

- `PathConfig` sets `output_dir = cwd/output`. `output/workspace/` holds the editable `cmdb.json` and `attack_templates.json`, both seeded once from `src/data`. Legacy CMDB keys are normalised to canonical lowercase keys. Chains are normalised to `{id, name, steps[{technique_id, name, tactic}]}`.
- Workflows always write under `output/`: `stride/`, `feedback/`, `scenarios/`, `exports/`, `maintain/`, `workspace/intel/`.
- Every threat model and scenario carries `_meta`: artifact id, type, AA id, created_at, provider/model and, for scenarios, `source_threat_model_id`/`path` plus the attack template and catalog sources.
- `build_navigator` rebuilds the application → threat model → scenario/feedback tree from those files. Older artifacts fall back to filename timestamps and newest-assessment matching.

## Consequences

### Positive
- Package data never changes at runtime. Each working directory gets its own workspace.
- Lineage is stored with the artifacts themselves, with no separate database.

### Negative
- The workspace depends on the current working directory: running from another directory silently creates a new, empty-seeded workspace. Neo4j sync from the wrong directory is a known risk (see ADR 0010's shrink guard).
- Every navigator refresh rescans all JSON files under `output/`. That costs O(artifacts) per GUI poll.
- Two schemas coexist: legacy CMDB keys ("AA ID", "Application Name") and canonical keys.

## Alternatives considered
- SQLite or Neo4j as the primary store. Not chosen. Neo4j is a projection only, and the JSON library stays the source of truth (`docs/NEO4J.md`).

## Evidence
- `src/config.py` `PathConfig`; `src/workspace.py` (`seed_workspace`, `normalize_cmdb_entry`, `normalize_chain`, `build_navigator`); `src/threat_model.py` `_save`; `src/scenario.py` `_save`
- `README.md` "Workspace, intel, and lineage"; `tests/test_workspace.py`
- Commits `38dd3fb` (message: "a mutable workspace under output/ so package fixtures stay seed-only"), `49e724b` (output under cwd)
