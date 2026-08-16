"""Secure-by-default execution primitives.

These primitives do not make network calls. They are the boundary that future
HTTP, browser, scanner, and shell adapters must use before execution.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import ActionPolicy, EngagementConfig, RiskLevel, ScopeDecision


class ScopeViolation(PermissionError):
    """Raised when an adapter tries to execute outside the effective scope."""

    def __init__(self, decision: ScopeDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class ScopeGuard:
    """Single policy entry point for future network and browser adapters."""

    def __init__(self, config: EngagementConfig) -> None:
        self._config = config

    @property
    def policy_hash(self) -> str:
        return self._config.policy_hash

    def check(self, target: str, method: str = "GET") -> ScopeDecision:
        return self._config.check_url(target, method)

    def require(self, target: str, method: str = "GET") -> ScopeDecision:
        decision = self.check(target, method)
        if not decision.allowed:
            raise ScopeViolation(decision)
        return decision


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    tool: str
    target: str
    method: str
    risk: RiskLevel
    purpose: str
    approval_id: str | None = None


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    reason: str
    action_id: str


class ActionApprover:
    def __init__(self, policy: ActionPolicy, approval_lookup: Callable[[str], bool] | None = None) -> None:
        self._policy = policy
        self._approval_lookup = approval_lookup or (lambda _approval_id: False)

    def evaluate(self, request: ActionRequest) -> ApprovalDecision:
        if not self._policy.allows(request.risk):
            return ApprovalDecision(
                False,
                f"{request.risk.value} actions are disabled by engagement policy",
                request.action_id,
            )
        if request.risk == RiskLevel.READ_ONLY and self._policy.read_only:
            return ApprovalDecision(True, "risk level is allowed by engagement policy", request.action_id)
        if request.risk == RiskLevel.STATE_CHANGE and self._policy.state_mutation and not self._policy.require_state_change_approval:
            return ApprovalDecision(True, "state-changing actions are enabled without per-action approval", request.action_id)
        if request.risk == RiskLevel.DESTRUCTIVE and self._policy.destructive and not self._policy.require_destructive_approval:
            return ApprovalDecision(True, "destructive actions are enabled without per-action approval", request.action_id)
        if request.approval_id and self._approval_lookup(request.approval_id):
            return ApprovalDecision(True, "explicit approval is valid", request.action_id)
        return ApprovalDecision(False, f"action risk {request.risk.value} requires explicit approval", request.action_id)


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    wait_seconds: float
    reason: str
    request_count: int


class RateLimiter:
    """Deterministic request budget and pacing gate.

    The adapter must wait for ``wait_seconds`` and call ``acquire`` again. A
    denied decision never consumes budget.
    """

    def __init__(self, config: EngagementConfig, clock: Callable[[], float] | None = None) -> None:
        self._limits = config.limits
        self._clock = clock or time.monotonic
        self._last_request_at: float | None = None
        self._request_count = 0
        self._lock = threading.Lock()

    @property
    def request_count(self) -> int:
        return self._request_count

    def acquire(self, now: float | None = None) -> RateDecision:
        with self._lock:
            current = self._clock() if now is None else now
            if self._request_count >= self._limits.max_requests:
                return RateDecision(False, 0.0, "request budget exhausted", self._request_count)

            interval = 1.0 / self._limits.requests_per_second
            if self._last_request_at is not None:
                elapsed = current - self._last_request_at
                if elapsed < interval:
                    return RateDecision(True, interval - elapsed, "rate limit requires pacing", self._request_count)

            self._last_request_at = current
            self._request_count += 1
            return RateDecision(True, 0.0, "request permitted", self._request_count)


class KillSwitch:
    """Process and file based emergency stop checked before each action."""

    def __init__(self, configured_file: str | None = None) -> None:
        self._configured_file = configured_file

    def tripped(self) -> bool:
        value = os.getenv("NIGHWATCH_KILL_SWITCH", "").strip().lower()
        if value in {"1", "true", "yes", "on", "stop"}:
            return True
        path = os.getenv("NIGHWATCH_KILL_SWITCH_FILE") or self._configured_file
        return bool(path and os.path.isfile(path))


class KillSwitchTripped(PermissionError):
    """Raised when the operator emergency stop is active."""


@contextmanager
def bounded_slot(semaphore: threading.BoundedSemaphore):
    """Hold one configured concurrent-execution slot for an adapter action."""
    semaphore.acquire()
    try:
        yield
    finally:
        semaphore.release()


_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "code",
    "csrf",
    "password",
    "secret",
    "session",
    "signature",
    "state",
    "token",
}

_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, "[REDACTED]" if key.lower() in _SENSITIVE_QUERY_KEYS else value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: "[REDACTED]" if key.lower() in _SENSITIVE_HEADERS else value
        for key, value in headers.items()
    }


@dataclass(frozen=True)
class ActionReceipt:
    action_id: str
    engagement_id: str
    tool: str
    target: str
    method: str
    risk: str
    scope_allowed: bool
    scope_reason: str
    approval_allowed: bool
    approval_reason: str
    policy_hash: str
    created_at: float
    request_count: int
    rate_ready: bool
    rate_wait_seconds: float
    rate_reason: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class ReceiptLogger:
    """Append-only JSONL logger for decisions, not raw secrets."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, receipt: ActionReceipt) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(receipt.to_json() + "\n")
