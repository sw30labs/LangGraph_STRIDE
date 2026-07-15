import httpx
import pytest

from src.config import InferenceBackend
from src.inference_client import (
    InferenceTruncatedError,
    OpenAICompatibleClient,
    normalize_base_url,
    strip_thinking,
)


def test_normalize_root_and_dashboard_urls():
    assert normalize_base_url("http://host:8000") == "http://host:8000/v1"
    assert normalize_base_url("http://host:8000/admin/dashboard?x=1") == "http://host:8000/v1"
    assert normalize_base_url("http://host:8000/v1/") == "http://host:8000/v1"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("<think>secret</think>answer", "answer"),
        ("orphan</think>answer", "answer"),
        ("answer<think>dangling", "answer"),
    ],
)
def test_strip_thinking(value, expected):
    assert strip_thinking(value) == expected


def _client(handler):
    client = OpenAICompatibleClient(
        backend=InferenceBackend.vllm,
        base_url="http://example.test/v1",
        api_key="local",
        model="test-model",
        context_size=32,
    )
    client._http.close()
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def test_chat_omits_full_context_reservation():
    def handler(request):
        assert "max_tokens" not in __import__("json").loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )

    assert _client(handler).chat([{"role": "user", "content": "x"}], max_tokens=32) == "ok"


def test_chat_raises_when_complete_output_is_truncated():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "partial"}, "finish_reason": "length"}]},
        )

    with pytest.raises(InferenceTruncatedError):
        _client(handler).chat(
            [{"role": "user", "content": "x"}], max_tokens=4, require_complete=True
        )


def test_chat_warns_when_optional_output_is_truncated():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "partial"}, "finish_reason": "length"}]},
        )

    with pytest.warns(RuntimeWarning, match="token limit"):
        assert _client(handler).chat([{"role": "user", "content": "x"}], max_tokens=4) == "partial"


def test_vllm_context_error_retries_without_reservation_when_tokenize_is_absent():
    calls = []

    def handler(request):
        calls.append((request.url.path, __import__("json").loads(request.content)))
        if request.url.path == "/v1/chat/completions" and len(calls) == 1:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "param": "max_tokens",
                        "message": "requested tokens exceed maximum context length",
                    }
                },
            )
        if request.url.path == "/tokenize":
            return httpx.Response(404, json={"error": "not found"})
        assert "max_tokens" not in calls[-1][1]
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )

    assert _client(handler).chat([{"role": "user", "content": "x"}], max_tokens=4) == "ok"
    assert [path for path, _ in calls] == [
        "/v1/chat/completions",
        "/tokenize",
        "/v1/chat/completions",
    ]
