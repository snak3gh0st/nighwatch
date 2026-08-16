from __future__ import annotations

import json

import pytest

from agentsec.browser import BrowserExecutorError, PlaywrightBrowserExecutor
from agentsec.evidence import EvidenceStore
from agentsec.gateway import ToolGateway
from agentsec.models import EngagementConfig
from agentsec.security import ReceiptLogger
from tests.test_models import config_dict


def _browser_executor(tmp_path) -> PlaywrightBrowserExecutor:
    config = EngagementConfig.from_dict(config_dict())
    evidence = EvidenceStore(tmp_path / "evidence")
    gateway = ToolGateway(config, receipt_logger=ReceiptLogger(tmp_path / "receipts.jsonl"))
    return PlaywrightBrowserExecutor(config, gateway, evidence)


def test_browser_rejects_out_of_scope_before_optional_dependency(tmp_path) -> None:
    executor = _browser_executor(tmp_path)
    with pytest.raises(BrowserExecutorError, match="browser target blocked"):
        executor.validate_target("https://outside.example.com/")


def test_browser_observation_model_is_json_safe(tmp_path) -> None:
    executor = _browser_executor(tmp_path)
    assert executor.config.policy_hash
    assert json.dumps({"timeout": executor.timeout_seconds})

