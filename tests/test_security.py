from __future__ import annotations

from urllib.parse import unquote

from agentsec.models import ActionPolicy, EngagementConfig, RiskLevel
from agentsec.gateway import GatewayBlocked, ToolGateway
from agentsec.security import (
    ActionApprover,
    ActionRequest,
    RateLimiter,
    redact_headers,
    redact_url,
    ScopeGuard,
    ScopeViolation,
)
from tests.test_models import config_dict


def test_action_policy_denies_mutation_by_default() -> None:
    approver = ActionApprover(ActionPolicy())
    request = ActionRequest("a-1", "http", "https://authorized.example.com", "POST", RiskLevel.STATE_CHANGE, "test")
    decision = approver.evaluate(request)
    assert decision.allowed is False


def test_action_policy_accepts_valid_explicit_approval() -> None:
    approver = ActionApprover(
        ActionPolicy(state_mutation=True),
        approval_lookup=lambda value: value == "approval-1",
    )
    request = ActionRequest("a-1", "http", "https://authorized.example.com", "POST", RiskLevel.STATE_CHANGE, "test", "approval-1")
    assert approver.evaluate(request).allowed is True


def test_explicit_approval_cannot_enable_disabled_risk_class() -> None:
    approver = ActionApprover(ActionPolicy(), approval_lookup=lambda value: value == "approval-1")
    request = ActionRequest("a-1", "http", "https://authorized.example.com", "POST", RiskLevel.STATE_CHANGE, "test", "approval-1")
    decision = approver.evaluate(request)
    assert decision.allowed is False
    assert "disabled by engagement policy" in decision.reason


def test_rate_limiter_paces_and_exhausts_budget() -> None:
    config = EngagementConfig.from_dict(config_dict())
    limiter = RateLimiter(config)
    first = limiter.acquire(now=10.0)
    second = limiter.acquire(now=10.1)
    third = limiter.acquire(now=10.5)
    fourth = limiter.acquire(now=11.0)
    fifth = limiter.acquire(now=11.5)
    assert first.allowed is True and first.wait_seconds == 0
    assert second.allowed is True and second.wait_seconds > 0
    assert third.allowed is True
    assert fourth.allowed is True
    assert fifth.allowed is False


def test_sensitive_url_and_headers_are_redacted() -> None:
    url = redact_url("https://authorized.example.com/callback?token=secret&item=1")
    headers = redact_headers({"Authorization": "Bearer secret", "X-Test": "ok"})
    assert "secret" not in url
    assert "[REDACTED]" in unquote(url)
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["X-Test"] == "ok"


def test_scope_guard_is_the_adapter_entry_point() -> None:
    config = EngagementConfig.from_dict(config_dict())
    guard = ScopeGuard(config)
    assert guard.require("https://authorized.example.com/api/health", "GET").allowed is True
    try:
        guard.require("https://outside.example.com/", "GET")
    except ScopeViolation as exc:
        assert exc.decision.allowed is False
    else:
        raise AssertionError("out-of-scope request was not blocked")


def test_tool_gateway_blocks_out_of_scope_before_consuming_budget(tmp_path) -> None:
    config = EngagementConfig.from_dict(config_dict())
    gateway = ToolGateway(config)
    request = ActionRequest("a-2", "future.http", "https://outside.example.com/", "GET", RiskLevel.READ_ONLY, "test")
    try:
        gateway.dry_run(request, now=10.0)
    except GatewayBlocked as exc:
        assert exc.decision.scope.allowed is False
        assert gateway.rate_limiter.request_count == 0
    else:
        raise AssertionError("out-of-scope action was not blocked")


def test_tool_gateway_writes_a_receipt_for_a_dry_run(tmp_path) -> None:
    config = EngagementConfig.from_dict(config_dict())
    from agentsec.security import ReceiptLogger

    log_path = tmp_path / "receipts.jsonl"
    gateway = ToolGateway(config, receipt_logger=ReceiptLogger(log_path))
    request = ActionRequest("a-3", "future.http", "https://authorized.example.com/api/health", "GET", RiskLevel.READ_ONLY, "test")
    receipt = gateway.dry_run(request, now=10.0)
    assert receipt.scope_allowed is True
    assert receipt.rate_ready is True
    assert log_path.read_text(encoding="utf-8").count("a-3") == 1
