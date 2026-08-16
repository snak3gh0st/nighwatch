from __future__ import annotations

import json

import pytest

import agentsec.llm as llm
from agentsec.llm import OllamaConfig, OllamaConfigError, OllamaClient, ToolDefinition


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return self._body


def test_remote_ollama_is_denied_by_default() -> None:
    with pytest.raises(OllamaConfigError):
        OllamaConfig(base_url="http://10.0.0.8:11434")


def test_chat_uses_structured_output_and_parses_tool_calls(monkeypatch) -> None:
    captured: dict = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse({
            "model": "gpt-oss:20b",
            "message": {
                "role": "assistant",
                "content": "{\"ok\":true}",
                "tool_calls": [{"function": {"name": "propose", "arguments": {"risk": "read_only"}}}],
            },
            "prompt_eval_count": 11,
            "eval_count": 4,
        })

    monkeypatch.setattr(llm, "urlopen", fake_urlopen)
    client = OllamaClient(OllamaConfig(model="test-model", max_tokens=123))
    response = client.chat(
        [{"role": "user", "content": "Return JSON"}],
        tools=[ToolDefinition("propose", "make a proposal", {"type": "object"})],
        response_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
    )

    assert captured["url"].endswith("/api/chat")
    assert captured["timeout"] == 120.0
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["format"]["type"] == "object"
    assert captured["payload"]["tools"][0]["function"]["name"] == "propose"
    assert response.tool_calls[0].name == "propose"
    assert response.prompt_eval_count == 11


def test_list_models_parses_names(monkeypatch) -> None:
    monkeypatch.setattr(llm, "urlopen", lambda _request, timeout: FakeResponse({"models": [{"name": "gpt-oss:20b"}, {"name": "qwen3"}]}))
    assert OllamaClient().list_models() == ["gpt-oss:20b", "qwen3"]
