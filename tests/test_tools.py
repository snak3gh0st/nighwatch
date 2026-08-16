from __future__ import annotations

import json

import pytest

from agentsec.evidence import EvidenceStore
from agentsec.gateway import ToolGateway
from agentsec.models import EngagementConfig
from agentsec.security import ReceiptLogger
from agentsec.tools import DeterministicToolRunner, ToolExecutionBlocked, ToolRegistry
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

