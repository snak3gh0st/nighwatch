"""Bounded active payload probing through the HTTP execution boundary."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from .http_executor import HttpExecutor, HttpObservation
from .models import EngagementConfig


class ActiveProbeError(ValueError):
    """Raised when a payload probe exceeds the engagement limits."""


@dataclass(frozen=True)
class ActiveProbeResult:
    url: str
    method: str
    cases_requested: int
    cases_executed: int
    evidence_ids: tuple[str, ...]
    statuses: tuple[int, ...]
    payload_hashes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "method": self.method,
            "cases_requested": self.cases_requested,
            "cases_executed": self.cases_executed,
            "evidence_ids": list(self.evidence_ids),
            "statuses": list(self.statuses),
            "payload_hashes": list(self.payload_hashes),
            "finding_created": False,
            "note": "probe observations require an independent validator before becoming a finding",
        }


class ActiveProbeEngine:
    """Substitute bounded canaries into an operator-supplied body template."""

    PLACEHOLDER = "{{NIGHWATCH_PAYLOAD}}"

    def __init__(self, config: EngagementConfig, executor: HttpExecutor) -> None:
        self.config = config
        self.executor = executor

    def run(
        self,
        url: str,
        *,
        method: str,
        body_template: str,
        payloads: Iterable[str],
        auth_profile: str | None = None,
        approval_id: str | None = None,
        content_type: str = "application/json",
        payload_label: str = "bounded active canary",
    ) -> ActiveProbeResult:
        normalized_method = method.upper()
        if normalized_method not in {"POST", "PUT", "PATCH"}:
            raise ActiveProbeError("active probes support only POST, PUT, and PATCH")
        if self.PLACEHOLDER not in body_template:
            raise ActiveProbeError(f"body template must contain {self.PLACEHOLDER}")
        if len(body_template.encode("utf-8")) > self.config.active_testing.max_payload_bytes:
            raise ActiveProbeError("body template exceeds active_testing.max_payload_bytes")
        values: list[str] = []
        for payload in payloads:
            if not isinstance(payload, str):
                raise ActiveProbeError("payloads must be strings")
            if len(values) >= self.config.active_testing.max_cases:
                raise ActiveProbeError(
                    f"payload count exceeds active_testing.max_cases ({self.config.active_testing.max_cases})"
                )
            values.append(payload)
        if not values:
            raise ActiveProbeError("at least one payload is required")
        observations: list[HttpObservation] = []
        payload_hashes: list[str] = []
        for index, payload in enumerate(values, start=1):
            if not isinstance(payload, str):
                raise ActiveProbeError("payloads must be strings")
            body = body_template.replace(self.PLACEHOLDER, payload)
            encoded = body.encode("utf-8")
            if len(encoded) > self.config.active_testing.max_payload_bytes:
                raise ActiveProbeError(
                    f"payload case {index} exceeds active_testing.max_payload_bytes"
                )
            observation = self.executor.execute(
                url,
                method=normalized_method,
                auth_profile=auth_profile,
                approval_id=approval_id,
                body=encoded,
                request_headers={"Content-Type": content_type},
                payload_label=f"{payload_label} #{index}",
                purpose="bounded active payload observation",
            )
            observations.append(observation)
            payload_hashes.append(hashlib.sha256(payload.encode("utf-8")).hexdigest())
        return ActiveProbeResult(
            url=url,
            method=normalized_method,
            cases_requested=len(values),
            cases_executed=len(observations),
            evidence_ids=tuple(item.evidence_id for item in observations),
            statuses=tuple(item.response.status for item in observations),
            payload_hashes=tuple(payload_hashes),
        )
