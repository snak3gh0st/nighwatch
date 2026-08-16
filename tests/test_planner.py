from __future__ import annotations

import json

import pytest

from agentsec.llm import OllamaResponse
from agentsec.models import EngagementConfig
from agentsec.planner import OllamaPlanner, PlannerError, TaskProposal
from tests.test_models import config_dict


class FakePlannerClient:
    def __init__(self, content: str) -> None:
        self.content = content
        self.messages = None
        self.schema = None

    def chat(self, messages, *, response_schema=None, tools=()):
        self.messages = messages
        self.schema = response_schema
        return OllamaResponse("fake", self.content, (), 1, 1, {})


def test_planner_accepts_one_opaque_read_only_task() -> None:
    client = FakePlannerClient(json.dumps({
        "task_kind": "compare_authorization",
        "target_ref": "endpoint:ep_001",
        "reason": "the observation shows an object identifier used by an authenticated operation",
        "auth_profiles": ["owner", "non-owner"],
        "expected_evidence": ["owner response", "non-owner response"],
        "risk_level": "read_only",
        "confidence": 0.8,
        "approval_required": False,
    }))
    proposal = OllamaPlanner(client).plan(EngagementConfig.from_dict(config_dict()), "The app exposed an order endpoint.")
    assert proposal.task_kind == "compare_authorization"
    assert proposal.target_ref == "endpoint:ep_001"
    assert client.schema["type"] == "object"
    assert "untrusted" in client.messages[1]["content"].lower()


def test_planner_rejects_raw_url_from_model() -> None:
    client = FakePlannerClient(json.dumps({
        "task_kind": "map_application",
        "target_ref": "https://authorized.example.com/api",
        "reason": "map it",
        "auth_profiles": [],
        "expected_evidence": [],
        "risk_level": "read_only",
        "confidence": 0.4,
        "approval_required": False,
    }))
    with pytest.raises(PlannerError):
        OllamaPlanner(client).plan(EngagementConfig.from_dict(config_dict()), "observation")


def test_task_proposal_rejects_state_change_without_approval() -> None:
    raw = {
        "task_kind": "test_business_logic",
        "target_ref": "endpoint:ep_002",
        "reason": "state transition requires review",
        "auth_profiles": [],
        "expected_evidence": ["state diff"],
        "risk_level": "state_change",
        "confidence": 0.5,
        "approval_required": False,
    }
    with pytest.raises(PlannerError):
        TaskProposal.from_dict(raw)
