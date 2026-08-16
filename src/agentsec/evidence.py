"""Local, append-only evidence records for authorized observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from .security import redact_headers, redact_url


_SENSITIVE_BODY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "password",
    "secret",
    "session",
    "signature",
    "token",
}
_TOKEN_PATTERN = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")


def _redact_json(value: Any, key: str | None = None) -> Any:
    if key is not None and key.lower() in _SENSITIVE_BODY_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact_json(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    return value


def redact_body_preview(body: bytes, max_bytes: int = 8192) -> tuple[str, bool]:
    """Return a bounded preview while avoiding common credential fields."""
    bounded = body[:max_bytes]
    truncated = len(body) > max_bytes
    text = bounded.decode("utf-8", errors="replace")
    if not truncated:
        try:
            text = json.dumps(_redact_json(json.loads(text)), sort_keys=True, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    text = _TOKEN_PATTERN.sub("[REDACTED]", text)
    return text, truncated


class EvidenceStore:
    """Write evidence as permission-restricted JSONL records.

    Raw authentication headers are never written. Response bodies are hashed;
    only an optional, bounded and redacted preview is stored.
    """

    def __init__(self, root: str | Path, body_preview_bytes: int = 8192) -> None:
        if body_preview_bytes <= 0 or body_preview_bytes > 1_048_576:
            raise ValueError("body_preview_bytes must be between 1 and 1048576")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.events_path = self.root / "evidence.jsonl"
        self.body_preview_bytes = body_preview_bytes
        self._lock = threading.RLock()

    def append(self, kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not kind.strip():
            raise ValueError("evidence kind cannot be empty")
        base = {
            "evidence_id": f"ev_{uuid.uuid4().hex}",
            "kind": kind,
            "created_at": time.time(),
            "payload": dict(payload),
        }
        canonical = json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        record = {**base, "record_sha256": hashlib.sha256(canonical).hexdigest()}
        encoded = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")

        with self._lock:
            fd = os.open(self.events_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                with os.fdopen(fd, "ab", closefd=True) as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                os.chmod(self.events_path, 0o600)
        return record

    def record_http(
        self,
        *,
        engagement_id: str,
        policy_hash: str,
        action_id: str,
        auth_profile: str | None,
        method: str,
        url: str,
        request_headers: Mapping[str, str],
        response_status: int | None,
        response_reason: str | None,
        response_headers: Mapping[str, str] | None,
        response_body: bytes = b"",
        response_truncated: bool = False,
        elapsed_ms: float | None = None,
        error: str | None = None,
        capture_body: bool = False,
    ) -> dict[str, Any]:
        preview = None
        preview_was_truncated = False
        if capture_body and response_body:
            preview, preview_was_truncated = redact_body_preview(response_body, self.body_preview_bytes)

        response: dict[str, Any] | None = None
        if response_status is not None:
            response = {
                "status": response_status,
                "reason": response_reason,
                "headers": redact_headers(dict(response_headers or {})),
                "body_sha256": hashlib.sha256(response_body).hexdigest(),
                "body_length": len(response_body),
                "body_truncated": response_truncated,
                "body_hash_scope": "captured_prefix" if response_truncated else "full_response",
                "elapsed_ms": elapsed_ms,
            }
            if preview is not None:
                response["body_preview"] = preview
                response["body_preview_truncated"] = preview_was_truncated

        return self.append(
            "http_exchange",
            {
                "engagement_id": engagement_id,
                "policy_hash": policy_hash,
                "action_id": action_id,
                "auth_profile": auth_profile,
                "request": {
                    "method": method.upper(),
                    "url": redact_url(url),
                    "headers": redact_headers(dict(request_headers)),
                },
                "response": response,
                "error": error,
            },
        )
