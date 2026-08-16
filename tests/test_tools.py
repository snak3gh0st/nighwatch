from __future__ import annotations

import json

import pytest

from agentsec.evidence import EvidenceStore
from agentsec.gateway import ToolGateway
from agentsec.models import EngagementConfig, RiskLevel
from agentsec.security import ReceiptLogger
from agentsec.tools import DeterministicToolRunner, ToolExecutionBlocked, ToolRegistry, ToolSpec
from tests.test_models import config_dict


def test_tool_registry_is_fixed_and_plan_is_non_executing(tmp_path) -> None:
    config = EngagementConfig.from_dict(config_dict())
    evidence = EvidenceStore(tmp_path / "evidence")
    runner = DeterministicToolRunner(
        config,
        ToolGateway(config, receipt_logger=ReceiptLogger(tmp_path / "receipts.jsonl")),
        evidence,
    )

    plan = runner.plan("httpx", "https://authorized.example.com/api/orders/1")
    assert plan.direct_execution is False
    assert "-rate-limit" in plan.argv
    assert json.dumps(plan.to_dict())


def test_tool_registry_rejects_out_of_scope_target(tmp_path) -> None:
    config = EngagementConfig.from_dict(config_dict())
    runner = DeterministicToolRunner(
        config,
        ToolGateway(config),
        EvidenceStore(tmp_path / "evidence"),
    )
    with pytest.raises(ToolExecutionBlocked, match="tool target blocked"):
        runner.plan("httpx", "https://outside.example.com/")


def test_fixed_adapter_can_run_local_process_through_proxy_environment(tmp_path) -> None:
    raw = config_dict()
    raw["allowed_origins"][0]["scheme"] = "http"
    raw["allowed_origins"][0]["host"] = "127.0.0.1"
    raw["allowed_origins"][0]["ports"] = [80]
    raw["allowed_origins"][0]["methods"] = ["GET"]
    raw["network"] = {"allow_private_addresses": True}
    raw["active_testing"] = {"enabled": True}
    config = EngagementConfig.from_dict(raw)
    evidence_dir = tmp_path / "evidence"
    runner = DeterministicToolRunner(
        config,
        ToolGateway(config, receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl")),
        EvidenceStore(evidence_dir),
        ToolRegistry((ToolSpec("local-echo", "echo", "local fixed adapter", RiskLevel.READ_ONLY, False, (), True),)),
    )

    result = runner.run(
        "local-echo",
        "http://127.0.0.1/api/health",
        proxy_url="http://127.0.0.1:43127",
    )
    assert result.exit_code == 0
    assert result.tool == "local-echo"
