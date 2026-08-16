"""Execution boundary shared by every future tool adapter."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

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
    """Authorize actions before any adapter is allowed to execute.

    ``dry_run`` is the only execution mode currently exposed. Future adapters
    must be registered behind this object rather than called by an agent.
    """

    def __init__(
        self,
        config: EngagementConfig,
        receipt_logger: ReceiptLogger | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.scope = ScopeGuard(config)
        self.approvals = ActionApprover(config.actions)
        self.rate_limiter = RateLimiter(config, clock=clock)
        self.receipt_logger = receipt_logger

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
