"""One bounded observe -> reason -> test -> verify investigation cycle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import AuthorizationValidation, AuthorizationValidator
from .models import EngagementConfig
from .planner import OllamaPlanner, TaskProposal


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


class ReasoningLoop:
    """Keep model choice bounded while allowing one real read-only action."""

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
