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
