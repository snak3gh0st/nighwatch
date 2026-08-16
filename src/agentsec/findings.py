"""Independent authorization validation and human-reviewable reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore
from .http_executor import HttpExecutor, HttpObservation, HttpResponse
from .security import redact_url


_IMPACT_FIELDS = {
    "address",
    "balance",
    "customer_id",
    "document",
    "document_url",
    "email",
    "internal_id",
    "owner",
    "payment",
    "phone",
    "phone_number",
    "role",
    "secret",
    "ssn",
}
_ID_FIELDS = {"id", "uuid", "user_id", "account_id", "order_id", "object_id", "resource_id"}
_VOLATILE_FIELDS = {"created_at", "updated_at", "timestamp", "request_id", "trace_id", "nonce"}


@dataclass(frozen=True)
class ResponseSignature:
    status: int
    body_sha256: str
    object_ids: tuple[str, ...]
    fields: tuple[str, ...]
    normalized_hash: str


def _signature(response: HttpResponse) -> ResponseSignature:
    body_hash = hashlib.sha256(response.body).hexdigest()
    object_ids: list[str] = []
    fields: list[str] = []
    normalized: Any = None
    try:
        value = json.loads(response.body.decode("utf-8", errors="replace"))
        if isinstance(value, dict):
            fields = sorted(str(key) for key in value)
            for key, item in value.items():
                if str(key).lower() in _ID_FIELDS and isinstance(item, (str, int, float)):
                    object_ids.append(f"{key}={item}")
            normalized = {
                str(key): item
                for key, item in value.items()
                if str(key).lower() not in _VOLATILE_FIELDS
            }
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        normalized = None
    normalized_hash = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    return ResponseSignature(
        status=response.status,
        body_sha256=body_hash,
        object_ids=tuple(sorted(object_ids)),
        fields=tuple(fields),
        normalized_hash=normalized_hash,
    )


@dataclass(frozen=True)
class AuthorizationValidation:
    status: str
    reason: str
    endpoint: str
    owner_profile: str
    subject_profile: str
    impact_fields: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    report_path: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "endpoint": self.endpoint,
            "owner_profile": self.owner_profile,
            "subject_profile": self.subject_profile,
            "impact_fields": list(self.impact_fields),
            "evidence_ids": list(self.evidence_ids),
            "report_path": self.report_path,
        }


class AuthorizationValidator:
    """Require independent, repeatable evidence before writing a report."""

    def __init__(
        self,
        executor: HttpExecutor,
        evidence_store: EvidenceStore,
        report_dir: str | Path | None = None,
    ) -> None:
        self.executor = executor
        self.evidence_store = evidence_store
        self.report_dir = Path(report_dir) if report_dir is not None else None

    def compare(
        self,
        url: str,
        *,
        owner_profile: str,
        subject_profile: str,
        impact_fields: set[str] | None = None,
    ) -> AuthorizationValidation:
        if owner_profile == subject_profile:
            raise ValueError("owner and subject profiles must be different")
        owner_fingerprint = self.executor.profile_fingerprint(owner_profile)
        subject_fingerprint = self.executor.profile_fingerprint(subject_profile)
        if owner_fingerprint == subject_fingerprint:
            return self._finish(
                status="rejected",
                reason="auth profiles resolve to the same credential fingerprint",
                url=url,
                owner_profile=owner_profile,
                subject_profile=subject_profile,
                impact_fields=(),
                evidence_ids=(),
            )

        owner = self.executor.execute(url, auth_profile=owner_profile, purpose="authorization baseline")
        subject = self.executor.execute(url, auth_profile=subject_profile, purpose="authorization comparison")
        owner_reproduction = self.executor.execute(url, auth_profile=owner_profile, purpose="independent authorization baseline")
        subject_reproduction = self.executor.execute(url, auth_profile=subject_profile, purpose="independent authorization reproduction")

        owner_sig = _signature(owner.response)
        subject_sig = _signature(subject.response)
        owner_repro_sig = _signature(owner_reproduction.response)
        subject_repro_sig = _signature(subject_reproduction.response)
        success = lambda status: 200 <= status < 300
        same_object = bool(set(owner_sig.object_ids) & set(subject_sig.object_ids))
        repeated_subject = subject_sig.status == subject_repro_sig.status and (
            subject_sig.body_sha256 == subject_repro_sig.body_sha256
            or subject_sig.normalized_hash == subject_repro_sig.normalized_hash
        )
        stable_owner = owner_sig.status == owner_repro_sig.status and (
            owner_sig.body_sha256 == owner_repro_sig.body_sha256
            or owner_sig.normalized_hash == owner_repro_sig.normalized_hash
        )
        requested_fields = {field.lower() for field in (impact_fields or set())}
        field_pool = requested_fields or _IMPACT_FIELDS
        observed_impact = tuple(sorted({field for field in subject_sig.fields if field.lower() in field_pool}))

        if not success(owner_sig.status) or not success(subject_sig.status):
            status = "rejected"
            reason = "subject profile did not receive a successful response"
        elif not same_object:
            status = "candidate"
            reason = "both profiles succeeded, but the returned resource could not be matched safely"
        elif not repeated_subject or not stable_owner:
            status = "candidate"
            reason = "the access behavior was not stable across independent reproductions"
        elif not observed_impact:
            status = "candidate"
            reason = "the subject received the resource, but no demonstrable impact field was observed"
        else:
            status = "verified"
            reason = "distinct profiles repeatedly received the same resource and impact fields were observed"

        evidence_ids = tuple(
            item.evidence_id
            for item in (owner, subject, owner_reproduction, subject_reproduction)
        )
        return self._finish(
            status=status,
            reason=reason,
            url=url,
            owner_profile=owner_profile,
            subject_profile=subject_profile,
            impact_fields=observed_impact,
            evidence_ids=evidence_ids,
        )

    def _finish(
        self,
        *,
        status: str,
        reason: str,
        url: str,
        owner_profile: str,
        subject_profile: str,
        impact_fields: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> AuthorizationValidation:
        report_path = None
        validation = AuthorizationValidation(
            status=status,
            reason=reason,
            endpoint=redact_url(url),
            owner_profile=owner_profile,
            subject_profile=subject_profile,
            impact_fields=impact_fields,
            evidence_ids=evidence_ids,
            report_path=None,
        )
        record = self.evidence_store.append("authorization_validation", validation.to_dict())
        if status == "verified" and self.report_dir is not None:
            report_path = self._write_report(validation, str(record["evidence_id"]))
            validation = AuthorizationValidation(
                status=validation.status,
                reason=validation.reason,
                endpoint=validation.endpoint,
                owner_profile=validation.owner_profile,
                subject_profile=validation.subject_profile,
                impact_fields=validation.impact_fields,
                evidence_ids=validation.evidence_ids,
                report_path=report_path,
            )
        return validation

    def _write_report(self, validation: AuthorizationValidation, validation_evidence_id: str) -> str:
        assert self.report_dir is not None
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.chmod(0o700)
        filename = "authorization-validation.md"
        path = self.report_dir / filename
        lines = [
            "# Broken object-level authorization validation",
            "",
            "## Status",
            "",
            "Verified by independent reproduction. Human review is still required before submission.",
            "",
            "## Endpoint",
            "",
            f"- URL: `{validation.endpoint}`",
            f"- Owner profile: `{validation.owner_profile}`",
            f"- Subject profile: `{validation.subject_profile}`",
            f"- Observed impact fields: {', '.join(f'`{field}`' for field in validation.impact_fields)}",
            "- Suggested severity: assess according to the program's impact rubric",
            "",
            "## Reproduction",
            "",
            "1. Authenticate as the owner profile and request the endpoint.",
            "2. Authenticate as the subject profile and request the same object.",
            "3. Repeat both requests independently.",
            "4. Compare the sanitized responses and confirm the impact fields.",
            "",
            "## Evidence",
            "",
            f"- Validation record: `{validation_evidence_id}`",
            *[f"- HTTP evidence: `{evidence_id}`" for evidence_id in validation.evidence_ids],
            "",
            "## Validation rationale",
            "",
            validation.reason,
            "",
            "Response bodies are intentionally stored as hashes plus bounded redacted previews. Re-check sensitive values locally before submitting a report.",
            "",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        path.chmod(0o600)
        return str(path)
