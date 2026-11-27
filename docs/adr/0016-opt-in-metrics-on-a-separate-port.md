# 0016. Prometheus metrics opt-in, on a port separate from inference

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The source started a Prometheus HTTP server on port 8000. That is the same port the local vLLM and oMLX endpoints conventionally use (`127.0.0.1:8000`), so starting metrics could collide with inference.

## Decision

Metrics are off by default. They start only for `--metrics-port N` or `STRIDE_METRICS_PORT=N`, via `prometheus_client.start_http_server`, and only for the workflow commands.

## Consequences

### Positive
- No port conflict with inference, and nothing listens unless asked (`tests/test_cli.py`, `tests/test_config.py`).

### Negative
- Existing scrapers that expected port 8000 have to be reconfigured. This is a deliberate compatibility break, documented in PORT_PLAN.

## Alternatives considered
- Keep port 8000. Rejected in PORT_PLAN Assumption 4.
- A fixed alternative port. Not evidenced.

## Evidence
- `src/cli.py` (`--metrics-port`, `start_http_server`); `src/config.py` `WorkflowConfig.metrics_port`
- `PORT_PLAN.md` Assumption 4; `tests/test_cli.py`; `tests/test_config.py::test_optional_metrics_port`
- Commits `7066af3` (harden context and metrics), `46fc544`
