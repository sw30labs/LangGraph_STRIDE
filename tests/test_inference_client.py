import httpx
import pytest

from src.config import InferenceBackend, build_inference_config, parse_reasoning_strength
from src.inference_client import (
    InferenceTruncatedError,
    OpenAICompatibleClient,
    _cached_client,
    client_from_config,
    normalize_base_url,
    strip_thinking,
    with_reasoning_strength,
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


def test_parse_reasoning_strength_accepts_muse_levels():
    assert parse_reasoning_strength(None) == "high"
    assert parse_reasoning_strength("LOW") == "low"
    assert parse_reasoning_strength("xhigh") == "xhigh"
    with pytest.raises(ValueError, match="reasoning_strength"):
        parse_reasoning_strength("ultra")


def test_with_reasoning_strength_injects_system_message():
    messages = with_reasoning_strength([{"role": "user", "content": "hi"}], "medium")
    assert messages[0] == {"role": "system", "content": "Reasoning strength: medium"}
    assert messages[1]["role"] == "user"


def test_with_reasoning_strength_skips_when_already_present():
    original = [{"role": "system", "content": "Reasoning strength: low\nBe brief."}]
    assert with_reasoning_strength(original, "high") is original


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


def test_chat_disables_thinking_via_template_kwargs():
    def handler(request):
        payload = __import__("json").loads(request.content)
        assert payload["chat_template_kwargs"] == {"enable_thinking": False}
        assert payload["messages"] == [{"role": "user", "content": "x"}]
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )

    assert (
        _client(handler).chat(
            [{"role": "user", "content": "x"}],
            max_tokens=8,
            disable_thinking=True,
        )
        == "ok"
    )


def test_chat_enables_thinking_with_reasoning_strength():
    def handler(request):
        payload = __import__("json").loads(request.content)
        assert payload["chat_template_kwargs"] == {
            "enable_thinking": True,
            "reasoning_strength": "xhigh",
        }
        assert payload["messages"][0] == {
            "role": "system",
            "content": "Reasoning strength: xhigh",
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )

    assert (
        _client(handler).chat(
            [{"role": "user", "content": "x"}],
            max_tokens=8,
            disable_thinking=False,
            reasoning_strength="xhigh",
        )
        == "ok"
    )


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
            return httpx.Response(200, text="not-json")
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


def test_client_cache_reuses_identity_and_separates_personas():
    _cached_client.cache_clear()
    vllm = build_inference_config("vllm", base_url="http://127.0.0.1:18001/v1", model="vllm-test")
    omlx = build_inference_config("omlx", base_url="http://127.0.0.1:18002/v1", model="omlx-test")
    first = client_from_config(vllm)
    assert client_from_config(vllm) is first
    second = client_from_config(omlx)
    assert second is not first
    assert (first.backend.value, first.base_url, first.model) != (
        second.backend.value,
        second.base_url,
        second.model,
    )
    first.close()
    second.close()
    _cached_client.cache_clear()
