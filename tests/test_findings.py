from __future__ import annotations

import json
from pathlib import Path

from agentsec.evidence import EvidenceStore
from agentsec.findings import AuthorizationValidator
from agentsec.http_executor import HttpObservation, HttpResponse


class FakeExecutor:
    def __init__(self, responses: list[HttpResponse], fingerprints: dict[str, str] | None = None) -> None:
        self.responses = iter(responses)
        self.fingerprints = fingerprints or {"owner": "owner-fingerprint", "subject": "subject-fingerprint"}

    def profile_fingerprint(self, profile: str) -> str:
        return self.fingerprints[profile]

    def execute(self, url: str, *, auth_profile: str, purpose: str) -> HttpObservation:
        response = next(self.responses)
        return HttpObservation(
            action_id=f"action-{auth_profile}-{purpose}",
            evidence_id=f"evidence-{auth_profile}-{purpose}",
            endpoint_id="ep_order",
            auth_profile=auth_profile,
            response=response,
        )


def _response(body: dict, status: int = 200) -> HttpResponse:
    encoded = json.dumps(body, sort_keys=True).encode()
    return HttpResponse(
        url="https://authorized.example.com/api/orders/123",
        method="GET",
        status=status,
        reason="OK",
        headers={"Content-Type": "application/json"},
        body=encoded,
        body_truncated=False,
        elapsed_ms=1.0,
    )


def test_validator_requires_reproduction_and_writes_verified_report(tmp_path) -> None:
    responses = [_response({"id": 123, "owner": "alice", "email": "a@example.com"}) for _ in range(4)]
    store = EvidenceStore(tmp_path / "evidence")
    result = AuthorizationValidator(
        FakeExecutor(responses),
        store,
        tmp_path / "reports",
    ).compare(
        "https://authorized.example.com/api/orders/123?token=secret",
        owner_profile="owner",
        subject_profile="subject",
        impact_fields={"email"},
    )

    assert result.status == "verified"
    assert result.report_path is not None
    assert Path(result.report_path).exists()
    assert "token=secret" not in Path(result.report_path).read_text(encoding="utf-8")


def test_validator_keeps_missing_impact_as_candidate(tmp_path) -> None:
    responses = [_response({"id": 123, "name": "public-looking"}) for _ in range(4)]
    result = AuthorizationValidator(
        FakeExecutor(responses),
        EvidenceStore(tmp_path / "evidence"),
        tmp_path / "reports",
    ).compare(
        "https://authorized.example.com/api/orders/123",
        owner_profile="owner",
        subject_profile="subject",
    )

    assert result.status == "candidate"
    assert result.report_path is None
