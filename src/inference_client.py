"""Provider-neutral client for OpenAI-compatible inference servers."""

from __future__ import annotations

import re
import warnings
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.config import InferenceBackend, InferenceConfig, parse_backend


class InferenceTruncatedError(RuntimeError):
    """Raised when a response must be complete but the server hit its token limit."""


def normalize_base_url(url: str) -> str:
    """Normalize root or dashboard URLs to an OpenAI `/v1` endpoint."""
    parsed = urlsplit(url.strip())
    path = parsed.path.rstrip("/")
    if not path or path.startswith("/admin"):
        path = "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def strip_thinking(value: str) -> str:
    """Remove complete, closing-only, and dangling model thinking blocks."""
    cleaned = re.sub(r"(?is)<think>.*?</think>", "", value)
    cleaned = re.sub(r"(?is)^.*?</think>", "", cleaned)
    cleaned = re.sub(r"(?is)<think>.*$", "", cleaned)
    return cleaned.strip()


class OpenAICompatibleClient:
    """Small shared client used by vLLM, oMLX, and explicit OpenAI endpoints."""

    def __init__(
        self,
        *,
        backend: InferenceBackend,
        base_url: str,
        api_key: str,
        model: str,
        context_size: int,
        timeout: float = 120.0,
    ) -> None:
        self.backend = backend
        self.base_url = normalize_base_url(base_url)
        self.api_key = api_key
        self.model = model
        self.context_size = context_size
        host = urlsplit(self.base_url).hostname
        self._http = httpx.Client(
            timeout=timeout,
            trust_env=host not in {"127.0.0.1", "localhost", "::1"},
            headers={"Authorization": f"Bearer {api_key}"},
        )

    @classmethod
    def from_endpoint(
        cls,
        backend: str | InferenceBackend,
        base_url: str,
        api_key: str,
        model: str,
        context_size: int,
        timeout: float = 120.0,
    ) -> OpenAICompatibleClient:
        selected = parse_backend(backend)
        return cls(
            backend=selected,
            base_url=base_url,
            api_key=api_key,
            model=model,
            context_size=context_size,
            timeout=timeout,
        )

    def close(self) -> None:
        self._http.close()

    def list_models(self) -> list[str]:
        response = self._http.get(f"{self.base_url}/models")
        response.raise_for_status()
        payload = response.json()
        return [
            str(row["id"])
            for row in payload.get("data", [])
            if isinstance(row, dict) and row.get("id")
        ]

    def chat(
        self,
        messages: list[dict[str, object]],
        *,
        max_tokens: int | None = None,
        disable_thinking: bool = True,
        require_complete: bool = False,
    ) -> str:
        payload: dict[str, object] = {"model": self.model, "messages": messages}
        if max_tokens is not None and max_tokens < self.context_size:
            payload["max_tokens"] = max_tokens
        if disable_thinking:
            payload["chat_template_kwargs"] = {"enable_thinking": False}

        body = self._post_chat(payload)
        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("Inference response did not include a choice")
        choice = choices[0]
        content = str((choice.get("message") or {}).get("content") or "")
        if choice.get("finish_reason") == "length":
            if require_complete:
                raise InferenceTruncatedError("Inference response was truncated at the token limit")
            warnings.warn(
                "Inference response ended at the token limit and may be incomplete",
                RuntimeWarning,
                stacklevel=2,
            )
        return strip_thinking(content)

    def _tokenize_url(self) -> str:
        parsed = urlsplit(self.base_url)
        path = parsed.path.rstrip("/")
        if path.endswith("/v1"):
            path = path[:-3]
        return urlunsplit((parsed.scheme, parsed.netloc, f"{path}/tokenize", "", ""))

    def _tokenize_chat(self, payload: dict[str, object]) -> tuple[int, int] | None:
        token_payload = {
            key: payload[key]
            for key in ("model", "messages", "chat_template_kwargs")
            if key in payload
        }
        response = self._http.post(self._tokenize_url(), json=token_payload)
        if response.status_code >= 400:
            return None
        body = response.json()
        try:
            return int(body["count"]), int(body["max_model_len"])
        except (KeyError, TypeError, ValueError):
            return None

    def _context_retry_payload(
        self, payload: dict[str, object], response: httpx.Response
    ) -> dict[str, object] | None:
        if self.backend is not InferenceBackend.vllm or response.status_code != 400:
            return None
        try:
            error = response.json().get("error", {})
        except ValueError:
            return None
        if not isinstance(error, dict):
            return None
        message = str(error.get("message", "")).lower()
        if error.get("param") not in {"max_tokens", "max_completion_tokens"}:
            return None
        if "maximum context length" not in message:
            return None
        requested = payload.get("max_tokens")
        if not isinstance(requested, int):
            return None

        retry = dict(payload)
        tokenized = self._tokenize_chat(payload)
        if tokenized is None:
            retry.pop("max_tokens", None)
            return retry
        prompt_tokens, served_context = tokenized
        available = served_context - prompt_tokens
        if available <= 0:
            raise RuntimeError(
                f"vLLM prompt uses {prompt_tokens} tokens, exceeding its "
                f"{served_context}-token context before generation"
            )
        retry["max_tokens"] = min(requested, available)
        return retry if retry["max_tokens"] < requested else None

    def _post_chat(self, payload: dict[str, object]) -> dict[str, object]:
        response = self._http.post(f"{self.base_url}/chat/completions", json=payload)
        retry = self._context_retry_payload(payload, response)
        if retry is not None:
            response = self._http.post(f"{self.base_url}/chat/completions", json=retry)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("Inference response was not a JSON object")
        return body


@lru_cache(maxsize=16)
def _cached_client(
    backend: InferenceBackend,
    base_url: str,
    api_key: str,
    model: str,
    context_size: int,
    timeout: float,
) -> OpenAICompatibleClient:
    return OpenAICompatibleClient(
        backend=backend,
        base_url=base_url,
        api_key=api_key,
        model=model,
        context_size=context_size,
        timeout=timeout,
    )


def client_from_config(config: InferenceConfig) -> OpenAICompatibleClient:
    """Return a client shared by stages using the same provider persona."""
    return _cached_client(
        config.backend,
        normalize_base_url(config.base_url),
        config.api_key,
        config.model,
        config.context_size,
        config.timeout,
    )
