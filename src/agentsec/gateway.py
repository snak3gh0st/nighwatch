"""Execution boundary shared by every future tool adapter."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable
import threading
from contextlib import contextmanager

from .models import ConfigError, EngagementConfig, RiskLevel, ScopeDecision
from .security import (
    ActionApprover,
    ActionReceipt,
    ActionRequest,
    ApprovalDecision,
    RateDecision,
    RateLimiter,
    ReceiptLogger,
    redact_url,
    KillSwitch,
    KillSwitchTripped,
    ScopeGuard,
)


@dataclass(frozen=True)
class GatewayDecision:
    ready: bool
    reason: str
    scope: ScopeDecision
    approval: ApprovalDecision
    rate: RateDecision


class GatewayBlocked(PermissionError):
    """Raised when a tool request cannot pass the execution boundary."""

    def __init__(self, decision: GatewayDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class ToolGateway:
    """Authorize every adapter action before it can perform I/O."""

    def __init__(
        self,
        config: EngagementConfig,
        receipt_logger: ReceiptLogger | None = None,
        clock: Callable[[], float] | None = None,
        approved_approval_ids: Iterable[str] | None = None,
    ) -> None:
        self.config = config
        self.scope = ScopeGuard(config)
        approved = frozenset(str(item).strip() for item in (approved_approval_ids or ()) if str(item).strip())
        self.approvals = ActionApprover(config.actions, approval_lookup=lambda value: value in approved)
        self.rate_limiter = RateLimiter(config, clock=clock)
        self.receipt_logger = receipt_logger
        self.kill_switch = KillSwitch(config.active_testing.kill_switch_file)
        self._concurrency = threading.BoundedSemaphore(config.limits.max_concurrent_requests)

    def authorize(self, request: ActionRequest, now: float | None = None) -> GatewayDecision:
        scope = self.scope.check(request.target, request.method)
        if not scope.allowed:
            return GatewayDecision(
                False,
                f"scope blocked: {scope.reason}",
                scope,
                ApprovalDecision(False, "not evaluated after scope denial", request.action_id),
                RateDecision(False, 0.0, "not evaluated after scope denial", self.rate_limiter.request_count),
            )

        if self.kill_switch.tripped():
            return GatewayDecision(
                False,
                "kill switch is active",
                scope,
                ApprovalDecision(False, "kill switch is active", request.action_id),
                RateDecision(False, 0.0, "not evaluated while kill switch is active", self.rate_limiter.request_count),
            )

        if request.risk != RiskLevel.READ_ONLY and not self.config.active_testing.enabled:
            return GatewayDecision(
                False,
                "active testing is disabled by engagement policy",
                scope,
                ApprovalDecision(False, "active testing is disabled by engagement policy", request.action_id),
                RateDecision(False, 0.0, "not evaluated while active testing is disabled", self.rate_limiter.request_count),
            )

        approval = self.approvals.evaluate(request)
        if not approval.allowed:
            return GatewayDecision(
                False,
                f"approval blocked: {approval.reason}",
                scope,
                approval,
                RateDecision(False, 0.0, "not evaluated after approval denial", self.rate_limiter.request_count),
            )

        rate = self.rate_limiter.acquire(now=now)
        if not rate.allowed:
            return GatewayDecision(False, f"rate blocked: {rate.reason}", scope, approval, rate)
        if rate.wait_seconds > 0:
            return GatewayDecision(False, f"rate wait required: {rate.wait_seconds:.3f}s", scope, approval, rate)
        return GatewayDecision(True, "action passed all pre-execution gates", scope, approval, rate)

    def assert_live(self) -> None:
        if self.kill_switch.tripped():
            raise KillSwitchTripped("kill switch is active")

    @contextmanager
    def execution_slot(self):
        """Hold a concurrency slot while remaining responsive to the kill switch."""
        while not self._concurrency.acquire(timeout=0.25):
            self.assert_live()
        try:
            yield
        finally:
            self._concurrency.release()

    def dry_run(self, request: ActionRequest, now: float | None = None) -> ActionReceipt:
        decision = self.authorize(request, now=now)
        receipt = self.record_decision(request, decision, now=now)
        if not decision.ready:
            raise GatewayBlocked(decision)
        return receipt

    def record_decision(
        self,
        request: ActionRequest,
        decision: GatewayDecision,
        now: float | None = None,
    ) -> ActionReceipt:
        """Persist the gate decision without implying network execution."""
        safe_target = request.target
        if request.target.startswith(("http://", "https://")):
            try:
                safe_target = redact_url(request.target)
            except (ConfigError, ValueError):
                safe_target = "[REDACTED_INVALID_HTTP_TARGET]"
        receipt = ActionReceipt(
            action_id=request.action_id,
            engagement_id=self.config.engagement_id,
            tool=request.tool,
            target=safe_target,
            method=request.method.upper(),
            risk=request.risk.value,
            scope_allowed=decision.scope.allowed,
            scope_reason=decision.scope.reason,
            approval_allowed=decision.approval.allowed,
            approval_reason=decision.approval.reason,
            policy_hash=self.config.policy_hash,
            created_at=now if now is not None else time.time(),
            request_count=decision.rate.request_count,
            rate_ready=decision.rate.allowed and decision.rate.wait_seconds == 0,
            rate_wait_seconds=decision.rate.wait_seconds,
            rate_reason=decision.rate.reason,
        )
        if self.receipt_logger is not None:
            self.receipt_logger.write(receipt)
        return receipt
