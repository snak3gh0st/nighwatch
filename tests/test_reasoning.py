from __future__ import annotations

from agentsec.findings import AuthorizationValidation
from agentsec.models import EngagementConfig, RiskLevel
from agentsec.planner import TaskProposal
from agentsec.reasoning import ReasoningLoop
from agentsec.state import InvestigationStateStore
from tests.test_models import config_dict


class FakePlanner:
    def __init__(self, proposal: TaskProposal) -> None:
        self.proposal = proposal

    def plan(self, _config: EngagementConfig, _observation: str) -> TaskProposal:
        return self.proposal


class SequencePlanner:
    def __init__(self, proposals: list[TaskProposal]) -> None:
        self.proposals = list(proposals)

    def plan(self, _config: EngagementConfig, _observation: str) -> TaskProposal:
        if self.proposals:
            return self.proposals.pop(0)
        return _proposal("inspect_api")


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


def test_reasoning_loop_persists_bounded_multi_step_state(tmp_path) -> None:
    config = EngagementConfig.from_dict(config_dict())
    validator = FakeValidator()
    loop = ReasoningLoop(
        SequencePlanner([_proposal("compare_authorization"), _proposal("inspect_api")]),
        validator,
    )
    state_store = InvestigationStateStore(tmp_path / "investigation.json", config)
    result = loop.run_many(
        config,
        "The observation shows an object endpoint.",
        url="https://authorized.example.com/api/orders/1",
        owner_profile="owner",
        subject_profile="non-owner",
        impact_fields={"email"},
        max_steps=3,
        state_store=state_store,
    )

    assert result.status == "planned"
    assert len(result.steps) == 2
    assert len(validator.calls) == 1
    assert state_store.snapshot()["engagement_id"] == "eng-test"
    assert (tmp_path / "investigation.json").stat().st_mode & 0o777 == 0o600
