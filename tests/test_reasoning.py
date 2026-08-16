from __future__ import annotations

from agentsec.findings import AuthorizationValidation
from agentsec.models import EngagementConfig, RiskLevel
from agentsec.planner import TaskProposal
from agentsec.reasoning import ReasoningLoop
from tests.test_models import config_dict


class FakePlanner:
    def __init__(self, proposal: TaskProposal) -> None:
        self.proposal = proposal

    def plan(self, _config: EngagementConfig, _observation: str) -> TaskProposal:
        return self.proposal


class FakeValidator:
    def __init__(self) -> None:
        self.calls = []

    def compare(self, url: str, *, owner_profile: str, subject_profile: str, impact_fields: set[str] | None = None):
        self.calls.append((url, owner_profile, subject_profile, impact_fields))
        return AuthorizationValidation(
            status="candidate",
            reason="test result",
            endpoint=url,
            owner_profile=owner_profile,
            subject_profile=subject_profile,
            impact_fields=(),
            evidence_ids=(),
            report_path=None,
        )


def _proposal(task_kind: str) -> TaskProposal:
    return TaskProposal(
        task_kind=task_kind,
        target_ref="endpoint:ep_001",
        reason="compare the authorized profiles",
        auth_profiles=("owner", "non-owner"),
        expected_evidence=("owner response", "subject response"),
        risk_level=RiskLevel.READ_ONLY,
        confidence=0.9,
        approval_required=False,
    )


def test_reasoning_loop_executes_only_allowlisted_task() -> None:
    validator = FakeValidator()
    result = ReasoningLoop(FakePlanner(_proposal("compare_authorization")), validator).run(
        EngagementConfig.from_dict(config_dict()),
        "The observation shows an object endpoint.",
        url="https://authorized.example.com/api/orders/1",
        owner_profile="owner",
        subject_profile="non-owner",
        impact_fields={"email"},
    )

    assert result.status == "candidate"
    assert validator.calls == [(
        "https://authorized.example.com/api/orders/1",
        "owner",
        "non-owner",
        {"email"},
    )]


def test_reasoning_loop_does_not_execute_unimplemented_task() -> None:
    validator = FakeValidator()
    result = ReasoningLoop(FakePlanner(_proposal("map_application")), validator).run(
        EngagementConfig.from_dict(config_dict()),
        "Map the application.",
        url="https://authorized.example.com/api/orders/1",
        owner_profile="owner",
        subject_profile="non-owner",
    )

    assert result.status == "planned"
    assert validator.calls == []
