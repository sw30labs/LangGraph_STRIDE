# 0014. Maintain forge: deterministic novelty gate plus LLM judge, with a human commit step

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The attack-chain library (27 seeded templates) needed tooling to find gaps and propose new chains without filling the library with near-clones of existing ones.

## Decision

- A card catalog (`dark_matter`, `control_counter`, `app_adversary`, `blind_spot_fill`, `kev_forge`, `clone_autopsy`, `technique_galaxy`) drives `maintain run`. Offline cards (galaxy, clone autopsy) are pure analytics over a SQLite cache.
- LLM cards run `forge_novel_chain` for up to `workflow.qa_attempts` rounds: draft, then `deterministic_gate`, then the LLM judge, then a critique fed back into the next round.
  - The deterministic gate requires 5–22 techniques, a maximum Jaccard similarity to the library at or below `--max-jaccard` (default 0.45), a kill-chain progression of at least 0.45, and mostly real ATT&CK IDs.
  - The judge passes only if novelty ≥ 0.72, realism ≥ 0.65, coherence ≥ 0.7 and non-duplication ≥ 0.75.
- Prompts can include graph signals (KEV-gap techniques, QA-rejected techniques), an optional DuckDuckGo "web spark" and a steer string.
- Proposals are written to `output/maintain/`. A separate explicit `maintain commit` (or GUI commit) adds them to the library. Proposals marked `accepted: false` are refused.

## Consequences

### Positive
- Cheap deterministic checks catch obvious clones before any LLM judgement. Library changes always need an explicit commit.
- Gate behaviour is unit-tested (`tests/test_maintain.py`).

### Negative
- Judge thresholds and Jaccard and progression cut-offs are hand-picked constants, and nothing records how they were tuned.
- The optional web spark sends steering text to an external search engine when enabled.
- The QA-rejected signal depends on feedback files, and the `final` stage always passes (ADR 0002).

## Alternatives considered
- LLM-only acceptance. Not chosen; the deterministic gate runs first (inferred from the design).
- Auto-committing accepted proposals. Not chosen; commit is a separate operator action.

## Evidence
- `src/maintain/cards.py`, `src/maintain/novel.py` (`deterministic_gate`, `judge_prompt`, `draft_prompt`, `forge_novel_chain`), `src/maintain/graph.py`, `src/maintain/workflows.py` (`commit_proposal_file`), `src/maintain/web_spark.py`
- `tests/test_maintain.py`
- Commits `2f62188`, `31650aa` (P2 analytics, KEV-gap forge), `864a249` (consume QA feedback in the forge)
