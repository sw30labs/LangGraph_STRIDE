# 0003. One provider-neutral OpenAI-compatible inference client

## Status

Accepted (retrospective, inferred 2026-11-27)

## Context

The app must talk to vLLM on DGX Spark, oMLX on Apple Silicon, and, as an explicit opt-in, hosted OpenAI. In the source app, `ChatOpenAI` was created inside workflow helpers, and an oMLX-only helper handled URL quirks.

## Decision

`src/inference_client.py` provides a single `OpenAICompatibleClient`, built on `httpx`, that every workflow and Maintain forge goes through:

- `normalize_base_url` rewrites root and `/admin…` dashboard URLs to `/v1`.
- Proxy settings are ignored (`trust_env=False`) for loopback hosts.
- `strip_thinking` removes complete, closing-only and dangling `<think>` blocks.
- `max_tokens` is left out when it is not smaller than the served context.
- On `finish_reason == "length"`, the client raises `InferenceTruncatedError` when complete output is required, and otherwise emits a `RuntimeWarning`.
- For a vLLM 400 "maximum context length" error, it retries once, sizing the budget with `/tokenize` and falling back to a server-managed budget.
- 401 responses produce a clear error.
- `client_from_config` reuses one client per persona through an `lru_cache`.

The connection-pool size comes from `concurrency`, and an `X-LangGraph-Stride-Device` header carries the device label. Backends are an `InferenceBackend` enum (`vllm`, `omlx`, `openai`), and `mlx` is accepted as an alias.

## Consequences

### Positive
- Business logic has a single seam. The mock server and `httpx.MockTransport` tests exercise every quirk.
- The workflows contain no LangChain chat-model dependency (only `langgraph` is a runtime dependency).

### Negative
- The client is chat-only: no streaming, no tool calls, no embeddings.
- Thinking control relies on server-specific `chat_template_kwargs` (Qwen-style `enable_thinking`, "Muse Glimmer" `reasoning_strength`), which other servers may ignore.

## Alternatives considered
- Keep LangChain `ChatOpenAI` per stage. Replaced, per the PORT_PLAN "Seams" table.
- The official `openai` Python SDK. Not evidenced as considered.

## Evidence
- `src/inference_client.py`; `src/config.py` (`InferenceBackend`, `parse_backend`, `build_inference_config`)
- `tests/test_inference_client.py`; `tests/mock_inference_server.py`; `tests/run_contract_e2e.py`
- `PORT_PLAN.md` "Seams" table and Assumption 8
- Commits `0f62f72`, `7066af3` (harden context and metrics), `46fc544` (seam review fixes), `49e724b` (client cache coverage)
