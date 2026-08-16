"""Bounded observe -> reason -> test -> verify investigation loops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import AuthorizationValidation, AuthorizationValidator
from .models import EngagementConfig
from .planner import OllamaPlanner, TaskProposal
from .state import InvestigationStateStore, InvestigationStep


@dataclass(frozen=True)
class InvestigationResult:
    status: str
    reason: str
    proposal: TaskProposal
    validation: AuthorizationValidation | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "proposal": self.proposal.to_dict(),
            "validation": self.validation.to_dict() if self.validation is not None else None,
        }


@dataclass(frozen=True)
class MultiStepInvestigationResult:
    status: str
    reason: str
    steps: tuple[InvestigationStep, ...]
    last_result: InvestigationResult
    state_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "steps": [step.to_dict() for step in self.steps],
            "last_result": self.last_result.to_dict(),
            "state_path": self.state_path,
        }


class ReasoningLoop:
    """Keep model choice bounded while allowing a few real read-only actions."""

    _EXECUTABLE_TASKS = frozenset({"compare_authorization", "validate_candidate"})

    def __init__(self, planner: OllamaPlanner, validator: AuthorizationValidator) -> None:
        self.planner = planner
        self.validator = validator

    def run(
        self,
        config: EngagementConfig,
        observation: str,
        *,
        url: str,
        owner_profile: str,
        subject_profile: str,
        impact_fields: set[str] | None = None,
    ) -> InvestigationResult:
        proposal = self.planner.plan(config, observation)
        return self._execute_proposal(
            config,
            proposal,
            url=url,
            owner_profile=owner_profile,
            subject_profile=subject_profile,
            impact_fields=impact_fields,
        )

    def _execute_proposal(
        self,
        config: EngagementConfig,
        proposal: TaskProposal,
        *,
        url: str,
        owner_profile: str,
        subject_profile: str,
        impact_fields: set[str] | None,
    ) -> InvestigationResult:
        if proposal.task_kind not in self._EXECUTABLE_TASKS:
            return InvestigationResult(
                status="planned",
                reason="the proposed task has no executable adapter in this bounded cycle",
                proposal=proposal,
                validation=None,
            )
        validation = self.validator.compare(
            url,
            owner_profile=owner_profile,
            subject_profile=subject_profile,
            impact_fields=impact_fields,
        )
        return InvestigationResult(
            status=validation.status,
            reason="planner proposal executed through the authorization validator",
            proposal=proposal,
            validation=validation,
        )

    def run_many(
        self,
        config: EngagementConfig,
        observation: str,
        *,
        url: str,
        owner_profile: str,
        subject_profile: str,
        impact_fields: set[str] | None = None,
        max_steps: int = 3,
        state_store: InvestigationStateStore,
    ) -> MultiStepInvestigationResult:
        """Run at most ``max_steps`` and stop on repetition or terminal status.

        The model can choose a task kind, but the URL, profiles, maximum step
        count, and executable adapters remain operator-controlled. A candidate
        result is fed back as a short observation summary; raw response bodies
        never enter the next prompt automatically.
        """
        if max_steps < 1 or max_steps > 10:
            raise ValueError("max_steps must be between 1 and 10")
        if not observation.strip():
            raise ValueError("observation cannot be empty")

        current_observation = observation[:16_000]
        seen: set[tuple[str, str]] = set()
        steps: list[InvestigationStep] = []
        last_result: InvestigationResult | None = None
        terminal_reason = "maximum investigation steps reached"

        for _ in range(max_steps):
            proposal = self.planner.plan(config, current_observation)
            proposal_key = (proposal.task_kind, proposal.target_ref)
            if proposal_key in seen:
                last_result = InvestigationResult(
                    status="planned",
                    reason="repeated proposal stopped to prevent an investigation loop",
                    proposal=proposal,
                    validation=None,
                )
            else:
                seen.add(proposal_key)
                last_result = self._execute_proposal(
                    config,
                    proposal,
                    url=url,
                    owner_profile=owner_profile,
                    subject_profile=subject_profile,
                    impact_fields=impact_fields,
                )
            validation_dict = last_result.validation.to_dict() if last_result.validation is not None else None
            steps.append(state_store.append(
                observation=current_observation,
                proposal=last_result.proposal,
                status=last_result.status,
                reason=last_result.reason,
                validation=validation_dict,
            ))

            if last_result.status in {"verified", "rejected", "planned"}:
                terminal_reason = last_result.reason
                break
            if last_result.validation is None:
                terminal_reason = last_result.reason
                break
            current_observation = (
                "Previous bounded authorization validation result:\n"
                f"status={last_result.validation.status}\n"
                f"reason={last_result.validation.reason}\n"
                f"impact_fields={','.join(last_result.validation.impact_fields) or 'none'}\n"
                "Choose the smallest next verification task. Do not invent URLs or credentials."
            )

        assert last_result is not None
        return MultiStepInvestigationResult(
            status=last_result.status,
            reason=terminal_reason,
            steps=tuple(steps),
            last_result=last_result,
            state_path=str(state_store.path),
        )
