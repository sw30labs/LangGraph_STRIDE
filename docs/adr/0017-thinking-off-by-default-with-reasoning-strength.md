# 0017. Model thinking off by default, with explicit thinking and reasoning-strength controls

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

Local Qwen-style reasoning models emit `<think>` blocks. Those blocks waste tokens and can break JSON parsing. Some users still want deeper reasoning for some runs.

## Decision

- `STRIDE_ENABLE_THINKING` is off by default (`InferenceConfig.disable_thinking=True`). By default the client sends `chat_template_kwargs.enable_thinking=false` and always strips thinking tags from responses.
- `--thinking/--no-thinking` and `--reasoning-strength {low,medium,high,xhigh}`, plus the GUI equivalents, turn thinking on. When it is on, the client adds `reasoning_strength` to `chat_template_kwargs` and prepends a `Reasoning strength: <level>` system message unless one is already there. The README calls this the "Muse Glimmer" convention.

## Consequences

### Positive
- Deterministic, parseable output by default. Opting in is explicit, and the same switch works in the CLI and the GUI (`tests/test_inference_client.py`, `tests/test_gui.py`).

### Negative
- The `reasoning_strength` kwarg and the system-message convention depend on the server. Servers that ignore them silently use their default behaviour.

## Alternatives considered
- Leave thinking on and only strip it. Not chosen; thinking is disabled at the template level by default (inferred: cost and parse robustness).

## Evidence
- `src/inference_client.py` (`with_reasoning_strength`, `strip_thinking`, `chat`); `src/config.py` (`parse_reasoning_strength`, `REASONING_STRENGTHS`)
- `tests/test_inference_client.py`; `tests/test_gui.py::test_job_builders_pass_thinking_controls`
- `README.md` environment table (`STRIDE_ENABLE_THINKING`, `STRIDE_REASONING_STRENGTH`)
- Commit `38dd3fb` (message: "thinking / reasoning strength is selectable in the GUI and CLI")
