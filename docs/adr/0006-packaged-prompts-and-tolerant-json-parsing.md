# 0006. Prompts as packaged YAML; tolerant JSON parsing of model output

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Every stage is prompt-driven, and local reasoning models often wrap JSON in prose or Markdown fences. The clean-clone verifier found that a wheel install was missing its runtime assets.

## Decision

- Prompts live in YAML under `src/prompts/`: `stride_prompts.yml` (stride/stride_qa/dread/dread_qa/final_qa), `scenario_prompts.yml` and `scenario_templates.yml`. Prompts are filled with `str.format`. Demo data lives under `src/data/`. Both, plus `src/web/`, ship as setuptools package data (`"data/*"`, `"prompts/*"`, `"web/*"`).
- `parse_json_object` tries strict JSON, then a fenced block, then the outermost `{…}`. STRIDE rows need all four fields. Each category must end up with at least three valid rows (capped at five), and categories are matched case-insensitively.
- Structured stages ask for `require_complete=True`, so truncated JSON fails loudly instead of being half-parsed.

## Consequences

### Positive
- Installed wheels and non-repo working directories work. `tests/test_docs.py` checks the package-data declaration.
- Prompt edits need no code changes.

### Negative
- `str.format` templating means any literal `{`/`}` in a prompt has to be escaped.
- `scenario_templates.yml` and the scenario prompts are long, domain-specific documents with a fictional bank; editing them is a content task, not a code task.
- The tolerant parser can accept JSON that is valid but semantically wrong. Shape is checked only for STRIDE rows.

## Alternatives considered
- Provider-native structured output or JSON mode. Not evidenced; the client stays at the lowest common denominator across vLLM and oMLX (inferred).
- Keep data and prompts at the repo root. This was the original layout, moved in `49e724b` after the clean-clone finding.

## Evidence
- `pyproject.toml` `[tool.setuptools.package-data]`; `src/prompts/*.yml`; `src/threat_model.py` (`parse_json_object`, `parse_stride_response`, `_normalize_stride_threats`)
- `tests/test_docs.py::test_runtime_assets_are_declared_as_package_data`; `tests/test_threat_model.py`
- Commits `5bbdc8c`, `49e724b` (data/prompts moved into `src/`)
