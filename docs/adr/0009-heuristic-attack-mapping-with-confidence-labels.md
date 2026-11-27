# 0009. Heuristic ATT&CK and actor mapping, labelled by confidence

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Most public feeds (CISA KEV, CISA advisories, vendor research RSS) do not ship ATT&CK technique IDs or a structured attribution. Only MITRE ATT&CK provides curated actor → technique links.

## Decision

- Technique IDs are derived by keyword heuristics: CWE ids and description hints map to ATT&CK, for example SQL injection to T1190 and privilege escalation to T1068. Explicit `T####` IDs found in fetched page bodies are added on top.
- Actors are reduced to coarse nexus labels (`russia-nexus`, `prc-nexus`, `dprk-nexus`, `iran-nexus`, `ransomware-operators`) using `ACTOR_HINTS`. Geointel keeps only attributed items.
- In the Neo4j projection, every derived edge carries a `confidence` property:
  - `mitre-attack`: curated
  - `heuristic-kev`
  - `advisory-mined`
  - `heuristic-threat`: technique IDs found in threat-model text

  Analytics that need gold data filter on `confidence = 'mitre-attack'`.

## Consequences

### Positive
- Free, keyless feeds become usable graph and CTI context.
- Readers and queries can tell curated links from inferred ones.

### Negative
- The heuristics are coarse. False positives and negatives are expected, and the keyword tables need manual tuning.
- Nexus labels are deliberately low-resolution and can mislabel vendor research.
- CTI packs on disk carry no confidence field, so the distinction exists only in Neo4j.

## Alternatives considered
- An LLM-based extractor for techniques and actors. Not evidenced; the deterministic approach keeps tests offline (inferred).
- Commercial or keyed CTI feeds. Not evidenced; all ingesters are public and keyless except the optional NVD key (inferred).

## Evidence
- `src/intel/cti.py` (CWE/description hint maps), `src/intel/advisories.py` (`ACTOR_HINTS`, page-body mining), `src/intel/geointel.py` (`attributed_only`)
- `src/maintain/neo4j_intel.py` (`CONFIDENCE_*`), `src/maintain/neo4j_workspace.py` (`CONFIDENCE_THREAT`), `src/maintain/neo4j_graph.py` schema docstring and canned queries
- `tests/test_intel.py`; `tests/test_maintain.py`
- Commits `1be6f27`, `95c4864`, `24fcb6b`, `a92f226` (intel projection), `5742411` (workspace projection), `baa8eb2`
