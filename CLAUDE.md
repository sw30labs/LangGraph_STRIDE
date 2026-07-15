# LangGraph STRIDE project guide

The project has two LangGraph workflows and one OpenAI-compatible inference client for DGX Spark/vLLM, Apple Silicon/oMLX, and explicit hosted OpenAI. Resolve settings in `src/config.py`, then pass them into workflow code. Never introduce platform branches into business logic.

Architecture:

- `src/config.py` owns `.env` loading, platform defaults, provider fallbacks, paths, and workflow limits.
- `src/inference_client.py` owns endpoint normalization, model listing, thinking removal, truncation policy, context reservation, proxy bypass for loopback, and the client cache.
- `src/threat_model.py` runs STRIDE generation, QA retry, DREAD generation, QA retry, final QA, and timestamped assessment/feedback persistence.
- `src/scenario.py` selects a prior threat model and source fixtures, then produces CVE, CTI, combined scenario, and the dated output report.
- `src/gui.py` exposes local-only workflow jobs, logs, CMDB/templates, and safe JSON preview; packaged assets live under `src/web/`.

Common commands:

```bash
pip install -e ".[dev]"
./gate.sh
python -m src.cli info
python -m src.cli threat-model AA123456
python -m src.cli serve
python tests/run_contract_e2e.py --persona vllm
python tests/run_contract_e2e.py --persona omlx
```

Data layout: tracked public fixtures are under `data/` and `prompts/`; generated assessments, feedback, and scenarios are under gitignored `output/`; runtime logs, `.env`, virtual environments, and model caches are also gitignored.

Things to watch for: DGX concurrency stays at two; root and dashboard endpoint URLs normalize to `/v1`; complete reports raise on token-limit truncation; prompt JSON must use the tolerant parser; port 8000 belongs to inference, so optional metrics must use another port; the source controls CSV has 20 rows but 19 unique IDs; shell exports take precedence over `.env`; `llm-down` must never stop an externally owned service.

## Coding Guidelines
Behavioral guidelines to reduce common LLM coding mistakes, on LLM coding pitfalls.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
