"""Structured application mapping from bounded HTTP observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .evidence import _SENSITIVE_BODY_KEYS
from .security import redact_url


_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.IGNORECASE)


def _path_template(path: str) -> tuple[str, list[str]]:
    segments = path.split("/")
    refs: list[str] = []
    rendered: list[str] = []
    for segment in segments:
        if _ID_SEGMENT.match(segment):
            refs.append(segment)
            rendered.append("{id}")
        else:
            rendered.append(segment)
    return "/".join(rendered) or "/", refs


def _json_field_names(body: bytes) -> list[str]:
    if not body:
        return []
    try:
        value = json.loads(body[:65_536].decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        return []
    if not isinstance(value, dict):
        return []
    return sorted(
        str(key)
        for key in value
        if str(key).lower() not in _SENSITIVE_BODY_KEYS
    )[:100]


class ApplicationMapStore:
    """Maintain a small JSON map without storing response values."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "endpoints": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"application map is unreadable: {self.path}") from exc
        if not isinstance(value, dict) or not isinstance(value.get("endpoints", {}), dict):
            raise ValueError("application map must contain an endpoints object")
        return value

    def observe(
        self,
        *,
        method: str,
        url: str,
        auth_profile: str | None,
        status: int,
        response_body: bytes,
        evidence_id: str,
    ) -> str:
        parsed = urlsplit(url)
        path, object_refs = _path_template(parsed.path or "/")
        query_params = sorted({
            key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in _SENSITIVE_BODY_KEYS
        })
        origin = f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
        identity = f"{method.upper()}|{origin}{path}|{','.join(query_params)}"
        endpoint_id = f"ep_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}"
        endpoints = self._data.setdefault("endpoints", {})
        endpoint = endpoints.setdefault(endpoint_id, {
            "endpoint_id": endpoint_id,
            "method": method.upper(),
            "origin": origin,
            "path_template": path,
            "query_params": [],
            "object_refs": [],
            "observed_auth_profiles": [],
            "status_codes": [],
            "response_fields": [],
            "evidence_ids": [],
        })
        for field, values in {
            "query_params": query_params,
            "object_refs": object_refs,
            "observed_auth_profiles": [auth_profile] if auth_profile else [],
            "status_codes": [status],
            "response_fields": _json_field_names(response_body),
            "evidence_ids": [evidence_id],
        }.items():
            current = set(endpoint.get(field, []))
            current.update(values)
            endpoint[field] = sorted(current, key=str)
        endpoint["last_observed_url"] = redact_url(url)
        self._save()
        return endpoint_id

    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._data))

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        endpoint = self._data.get("endpoints", {}).get(endpoint_id)
        return json.loads(json.dumps(endpoint)) if isinstance(endpoint, dict) else None

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
