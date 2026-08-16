"""Local Ollama client used by the planning layer.

The client talks only to Ollama's local HTTP API by default. It does not
execute tools, follow model-supplied URLs, or log prompts and responses.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class OllamaError(RuntimeError):
    """Base error for local model communication."""


class OllamaConfigError(OllamaError):
    """Raised for an unsafe or malformed Ollama configuration."""


class OllamaUnavailable(OllamaError):
    """Raised when the configured local Ollama service cannot be reached."""


@dataclass(frozen=True)
class OllamaConfig:
    base_url: str = "http://127.0.0.1:11434"
    model: str = "gpt-oss:20b"
    timeout_seconds: float = 120.0
    temperature: float = 0.0
    max_tokens: int = 2048
    allow_remote: bool = False

    def __post_init__(self) -> None:
        base = self.base_url.rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise OllamaConfigError("Ollama base URL must be an http(s) URL with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise OllamaConfigError("Ollama base URL must not contain credentials")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise OllamaConfigError("Ollama base URL must point to the server root, not a path or query")
        if not self.allow_remote and parsed.hostname.lower() not in {"127.0.0.1", "localhost", "::1"}:
            raise OllamaConfigError(
                "remote Ollama is disabled by default; use allow_remote only for an explicitly trusted endpoint"
            )
        if not self.model.strip():
            raise OllamaConfigError("Ollama model cannot be empty")
        if self.timeout_seconds <= 0:
            raise OllamaConfigError("Ollama timeout must be greater than zero")
        if self.max_tokens <= 0:
            raise OllamaConfigError("Ollama max_tokens must be greater than zero")
        if not 0 <= self.temperature <= 2:
            raise OllamaConfigError("Ollama temperature must be between 0 and 2")
        object.__setattr__(self, "base_url", base)

    @classmethod
    def from_env(cls, model_override: str | None = None) -> "OllamaConfig":
        base_url = os.getenv(
            "NIGHWATCH_OLLAMA_BASE_URL",
            os.getenv("AGENTSEC_OLLAMA_BASE_URL", os.getenv("OLLAMA_BASE_URL", cls.base_url)),
        )
        model = model_override or os.getenv(
            "NIGHWATCH_OLLAMA_MODEL",
            os.getenv("AGENTSEC_OLLAMA_MODEL", os.getenv("OLLAMA_MODEL", cls.model)),
        )
        allow_remote = os.getenv(
            "NIGHWATCH_OLLAMA_ALLOW_REMOTE",
            os.getenv("AGENTSEC_OLLAMA_ALLOW_REMOTE", ""),
        ).lower() in {"1", "true", "yes"}

        try:
            timeout = float(os.getenv(
                "NIGHWATCH_OLLAMA_TIMEOUT_SECONDS",
                os.getenv("AGENTSEC_OLLAMA_TIMEOUT_SECONDS", str(cls.timeout_seconds)),
            ))
            temperature = float(os.getenv(
                "NIGHWATCH_OLLAMA_TEMPERATURE",
                os.getenv("AGENTSEC_OLLAMA_TEMPERATURE", str(cls.temperature)),
            ))
            max_tokens = int(os.getenv(
                "NIGHWATCH_OLLAMA_MAX_TOKENS",
                os.getenv("AGENTSEC_OLLAMA_MAX_TOKENS", str(cls.max_tokens)),
            ))
        except ValueError as exc:
            raise OllamaConfigError("invalid Ollama numeric environment variable") from exc

        return cls(
            base_url=base_url,
            model=model,
            timeout_seconds=timeout,
            temperature=temperature,
            max_tokens=max_tokens,
            allow_remote=allow_remote,
        )

    def endpoint(self, path: str) -> str:
        return f"{self.base_url}/api/{path.lstrip('/')}"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class OllamaToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class OllamaResponse:
    model: str
    content: str
    tool_calls: tuple[OllamaToolCall, ...]
    prompt_eval_count: int | None
    eval_count: int | None
    raw: dict[str, Any]


class OllamaClient:
    def __init__(self, config: OllamaConfig | None = None) -> None:
        self.config = config or OllamaConfig.from_env()

    def _request(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.config.endpoint(endpoint), data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read()
        except HTTPError as exc:
            detail = exc.read(512).decode("utf-8", errors="replace")
            raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OllamaUnavailable(
                f"cannot reach Ollama at {self.config.base_url}; start Ollama or verify the local endpoint"
            ) from exc

        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OllamaError("Ollama returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama returned a non-object JSON response")
        return result

    def list_models(self) -> list[str]:
        result = self._request("GET", "tags")
        models = result.get("models", [])
        if not isinstance(models, list):
            raise OllamaError("Ollama /api/tags returned an invalid models list")
        names = []
        for item in models:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
        return names

    def chat(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: Sequence[ToolDefinition] = (),
        response_schema: dict[str, Any] | None = None,
    ) -> OllamaResponse:
        validated_messages: list[dict[str, Any]] = []
        for message in messages:
            if not isinstance(message, dict):
                raise OllamaError("each chat message must be an object")
            role = message.get("role")
            content = message.get("content")
            if role not in {"system", "user", "assistant", "tool"}:
                raise OllamaError(f"unsupported chat role: {role!r}")
            if not isinstance(content, str):
                raise OllamaError("chat message content must be a string")
            validated_messages.append(dict(message))

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": validated_messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }
        if tools:
            payload["tools"] = [tool.to_dict() for tool in tools]
        if response_schema is not None:
            if not isinstance(response_schema, dict) or response_schema.get("type") != "object":
                raise OllamaError("response_schema must be a JSON object schema")
            payload["format"] = response_schema

        result = self._request("POST", "chat", payload)
        message = result.get("message")
        if not isinstance(message, dict):
            raise OllamaError("Ollama chat response did not contain a message")
        content = message.get("content", "")
        if not isinstance(content, str):
            raise OllamaError("Ollama chat message content was not a string")

        parsed_calls: list[OllamaToolCall] = []
        raw_calls = message.get("tool_calls", [])
        if raw_calls is not None:
            if not isinstance(raw_calls, list):
                raise OllamaError("Ollama tool_calls was not a list")
            for raw_call in raw_calls:
                try:
                    function = raw_call["function"]
                    name = function["name"]
                    arguments = function.get("arguments", {})
                except (KeyError, TypeError) as exc:
                    raise OllamaError("Ollama returned a malformed tool call") from exc
                if not isinstance(name, str) or not isinstance(arguments, dict):
                    raise OllamaError("Ollama tool call must contain a name and object arguments")
                parsed_calls.append(OllamaToolCall(name=name, arguments=arguments))

        return OllamaResponse(
            model=str(result.get("model", self.config.model)),
            content=content,
            tool_calls=tuple(parsed_calls),
            prompt_eval_count=_optional_int(result.get("prompt_eval_count")),
            eval_count=_optional_int(result.get("eval_count")),
            raw=result,
        )


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None
