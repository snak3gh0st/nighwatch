"""Permission-restricted state for bounded multi-step investigations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ConfigError, EngagementConfig
from .planner import TaskProposal


_SECRET_TEXT_PATTERN = re.compile(
    r"(?i)\b(?:bearer|basic|cookie|set-cookie|authorization|x-api-key|token|secret|password)\b"
    r"(?:\s*[:=]\s*|\s+)[^\s,;]+"
)


def _safe_model_text(value: str, limit: int = 600) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")[:limit]
    return _SECRET_TEXT_PATTERN.sub("[REDACTED]", text)


@dataclass(frozen=True)
class InvestigationStep:
    index: int
    observation_sha256: str
    proposal: dict[str, Any]
    status: str
    reason: str
    validation: dict[str, Any] | None
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "observation_sha256": self.observation_sha256,
            "proposal": self.proposal,
            "status": self.status,
            "reason": self.reason,
            "validation": self.validation,
            "created_at": self.created_at,
        }


class InvestigationStateStore:
    """Atomically persist only bounded, sanitized investigation metadata."""

    def __init__(self, path: str | Path, config: EngagementConfig) -> None:
        self.path = Path(path)
        self.config = config
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if self.path.exists():
            os.chmod(self.path, 0o600)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "version": 1,
                "engagement_id": self.config.engagement_id,
                "policy_hash": self.config.policy_hash,
                "steps": [],
            }
        try:
            current = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"investigation state is unreadable: {self.path}") from exc
        if current.get("engagement_id") != self.config.engagement_id:
            raise ConfigError("investigation state belongs to a different engagement")
        if current.get("policy_hash") != self.config.policy_hash:
            raise ConfigError("investigation state policy hash does not match the active configuration")
        if not isinstance(current.get("steps"), list):
            raise ConfigError("investigation state steps must be a list")
        return current

    def append(
        self,
        *,
        observation: str,
        proposal: TaskProposal,
        status: str,
        reason: str,
        validation: dict[str, Any] | None,
    ) -> InvestigationStep:
        current = self._read()
        index = len(current["steps"])
        safe_proposal = proposal.to_dict()
        safe_proposal["reason"] = _safe_model_text(str(safe_proposal["reason"]))
        safe_proposal["expected_evidence"] = [
            _safe_model_text(item, 300) for item in safe_proposal.get("expected_evidence", [])[:16]
        ]
        safe_validation = None
        if validation is not None:
            safe_validation = dict(validation)
            safe_validation["reason"] = _safe_model_text(str(safe_validation.get("reason", "")))
            safe_validation["endpoint"] = "[REDACTED_ENDPOINT]"
        step = InvestigationStep(
            index=index,
            observation_sha256=hashlib.sha256(observation.encode("utf-8")).hexdigest(),
            proposal=safe_proposal,
            status=status,
            reason=_safe_model_text(reason),
            validation=safe_validation,
            created_at=time.time(),
        )
        current["steps"].append(step.to_dict())
        current["updated_at"] = step.created_at
        encoded = json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return step

    def snapshot(self) -> dict[str, Any]:
        return self._read()
