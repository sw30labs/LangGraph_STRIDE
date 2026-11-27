# 0002. Use LangGraph StateGraph for the threat-model and scenario workflows

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The product makes two multi-stage LLM artefacts: a STRIDE/DREAD threat model for one CMDB application, and a CVE → CTI → threat-scenario report built from a saved threat model. The source app already used LangGraph, and the README badge and project name commit to it.

## Decision

Each workflow is a compiled `langgraph.graph.StateGraph` over a `TypedDict` state:

- **Threat model** (`src/threat_model.py`) has six nodes: `generate_stride → qa_stride →(conditional) generate_dread → qa_dread →(conditional) final_qa → save`. The STRIDE and DREAD QA nodes loop back to their generators until QA passes or `WorkflowConfig.qa_attempts` (default 3) runs out. QA transport errors count as failed attempts. A final-QA error falls back to the assembled model.
- **Scenario** (`src/scenario.py`) has eight nodes in a straight line: `select → generate_cve → qa_cve → generate_cti → qa_cti → generate_scenario → qa_scenario → save`. The three QA nodes always approve, "matching the source" (PROGRESS iteration 3).

Each node prints a `STAGE: <name>` line so the GUI job log can show progress.

## Consequences

### Positive
- The retry ceiling is bounded and testable. Tests drive both graphs with fake clients (`tests/test_threat_model.py`, `tests/test_scenario.py`).
- Workflows receive an injected client and config, so they never branch on the host platform (ADR 0004).

### Negative
- Scenario QA is a placeholder: generated CVE/CTI/scenario reports get no model review.
- Final QA always records `{"pass": true}`, so the `final` QA stage can never mark a real run as failed. This weakens the QA-feedback analytics in ADR 0010/0014.
- Final QA asks the LLM to return the entire threat model and replaces the assembled model with whatever JSON object comes back. The structure is not validated.

## Alternatives considered
- Plain sequential Python functions. Not evidenced as considered. LangGraph was kept from the source (inferred).
- Model-driven scenario QA, as in the source's `customer_qa_agent` prompt, which is still in `scenario_prompts.yml`. It was not wired; the deterministic approvals were kept (inferred from PROGRESS iteration 3).

## Evidence
- `src/threat_model.py` (`ThreatModelWorkflow._build_graph`, `_after_stride_qa`, `_after_dread_qa`, `_final_qa`); `src/scenario.py` (`ScenarioWorkflow._build_graph`, `_qa_*`)
- `src/config.py` `WorkflowConfig.qa_attempts`; `src/prompts/scenario_prompts.yml` (`scenario_menu_gen_system_message_customer_qa_agent`, unused)
- Commits `5bbdc8c` (port STRIDE threat model), `2ac1f87` (port scenario graph), `49e724b` (QA transport errors enter retry), `c1e5c49` (STAGE lines)
