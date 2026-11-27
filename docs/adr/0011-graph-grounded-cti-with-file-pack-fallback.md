# 0011. Graph-grounded CTI generation with silent fallback to file packs

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Once intel was projected into Neo4j (ADR 0010), the graph could give richer CTI context for a scenario's techniques (actors, advisories, KEV CVEs) than file-pack overlap alone. Neo4j is still optional.

## Decision

`ScenarioWorkflow._generate_cti` always builds the baseline from `matching_cti_packs`. When Neo4j is enabled, it also calls `cti_briefing` for the chain's technique IDs and appends the formatted briefing to the CTI prompt. The briefing ranks actors by technique coverage and de-duplicates IDs case-insensitively. Any graph error is swallowed, and the run continues with file packs only.

## Consequences

### Positive
- When the graph is available, the CTI prompt gets better grounding, and nothing breaks when it is not (`tests/test_intel.py` graph-briefing and graph-outage tests).

### Negative
- The fallback is silent: neither the report nor `_meta` records whether the graph contributed. Lineage cannot tell grounded runs from ungrounded ones.
- Briefing quality depends on the heuristic edges in ADR 0009.

## Alternatives considered
- Graph-only CTI. Not chosen, because Neo4j is optional.
- Fail when the graph is unreachable. Not chosen; the outage test asserts that the run completes.

## Evidence
- `src/scenario.py` `_generate_cti`; `src/maintain/neo4j_graph.py` (`cti_briefing`, `format_cti_briefing`)
- `tests/test_intel.py` (`test_scenario_cti_uses_graph_briefing_when_available`, `test_scenario_cti_survives_graph_outage`); `tests/test_maintain.py::test_cti_briefing_aggregates_and_formats`
- Commit `3566166` (graph-grounded CTI generation and threat-actor paths)
