"""Fixed-argument registry for traditional security tools.

The registry is deliberately a planning surface first. Direct execution of
network scanners is disabled until an adapter can enforce per-request scope,
DNS/address checks, rate limits, kill-switch behavior, and evidence capture.
No model or CLI argument can add arbitrary subprocess arguments.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Any, Sequence

from .evidence import EvidenceStore
from .gateway import ToolGateway
from .models import ConfigError, EngagementConfig, RiskLevel
from .security import redact_url


class ToolExecutionBlocked(PermissionError):
    """Raised when a registered tool is not safe to execute directly."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    description: str
    risk: RiskLevel
    direct_execution: bool
    fixed_flags: tuple[str, ...]

    def argv(self, target: str) -> tuple[str, ...]:
        return (self.binary, *self.fixed_flags, target)


@dataclass(frozen=True)
class ToolPlan:
    tool: str
    binary: str
    argv: tuple[str, ...]
    target: str
    available: bool
    direct_execution: bool
    risk: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        safe_argv = list(self.argv)
        if safe_argv:
            safe_argv[-1] = redact_url(safe_argv[-1])
        return {
            "tool": self.tool,
            "binary": self.binary,
            "argv": safe_argv,
            "target": redact_url(self.target),
            "available": self.available,
            "direct_execution": self.direct_execution,
            "risk": self.risk,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ToolObservation:
    tool: str
    evidence_id: str
    action_id: str
    exit_code: int
    stdout_preview: str
    stderr_preview: str
    timed_out: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "evidence_id": self.evidence_id,
            "action_id": self.action_id,
            "exit_code": self.exit_code,
            "stdout_preview": self.stdout_preview,
            "stderr_preview": self.stderr_preview,
            "timed_out": self.timed_out,
        }


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "httpx",
        "httpx",
        "single-target HTTP metadata probe",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-json", "-no-color", "-timeout", "5", "-retries", "0", "-rate-limit", "1", "-u"),
    ),
    ToolSpec(
        "katana",
        "katana",
        "bounded URL crawler",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-jsonl", "-depth", "1", "-crawl-duration", "10s", "-rate-limit", "1", "-u"),
    ),
    ToolSpec(
        "subfinder",
        "subfinder",
        "passive subdomain discovery",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-all", "-recursive", "-d"),
    ),
    ToolSpec(
        "nuclei",
        "nuclei",
        "template-based vulnerability checks",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-no-color", "-rate-limit", "1", "-bulk-size", "1", "-concurrency", "1", "-u"),
    ),
    ToolSpec(
        "ffuf",
        "ffuf",
        "content and parameter fuzzing",
        RiskLevel.STATE_CHANGE,
        False,
        ("-s", "-rate", "1", "-t", "1", "-u"),
    ),
)


class ToolRegistry:
    def __init__(self, specs: Sequence[ToolSpec] = TOOL_SPECS) -> None:
        self._specs = {spec.name: spec for spec in specs}

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise ConfigError(f"tool is not in the fixed registry: {name}") from exc

    def list(self) -> list[dict[str, Any]]:
        result = []
        for spec in sorted(self._specs.values(), key=lambda item: item.name):
            path = shutil.which(spec.binary)
            result.append({
                "name": spec.name,
                "binary": spec.binary,
                "description": spec.description,
                "risk": spec.risk.value,
                "available": path is not None,
                "resolved_path": path,
                "direct_execution": spec.direct_execution,
                "fixed_flags": list(spec.fixed_flags),
            })
        return result


class DeterministicToolRunner:
    """Build fixed tool commands and refuse unsafe direct execution."""

    def __init__(
        self,
        config: EngagementConfig,
        gateway: ToolGateway,
        evidence_store: EvidenceStore,
        registry: ToolRegistry | None = None,
        *,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 65_536,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 0 and 300")
        if max_output_bytes <= 0 or max_output_bytes > 1_048_576:
            raise ValueError("max_output_bytes must be between 1 and 1048576")
        self.config = config
        self.gateway = gateway
        self.evidence_store = evidence_store
        self.registry = registry or ToolRegistry()
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def plan(self, name: str, target: str) -> ToolPlan:
        spec = self.registry.get(name)
        decision = self.config.check_url(target, "GET")
        if not decision.allowed:
            raise ToolExecutionBlocked(f"tool target blocked: {decision.reason}")
        available = shutil.which(spec.binary) is not None
        reason = (
            "direct execution is disabled until the tool is routed through the per-request egress adapter"
            if not spec.direct_execution
            else "fixed-argument adapter is enabled"
        )
        return ToolPlan(
            tool=spec.name,
            binary=spec.binary,
            argv=spec.argv(target),
            target=target,
            available=available,
            direct_execution=spec.direct_execution,
            risk=spec.risk.value,
            reason=reason,
        )

    def run(self, name: str, target: str) -> ToolObservation:
        self.plan(name, target)
        raise ToolExecutionBlocked(
            "direct network-tool execution is disabled; use the fixed plan only "
            "until a per-request egress adapter is installed"
        )
