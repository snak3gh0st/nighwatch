"""Fixed-argument registry for traditional security tools.

Network tools can execute only through the reviewed loopback proxy adapter.
Direct execution remains disabled, and no model or CLI argument can add
arbitrary subprocess arguments.
"""

from __future__ import annotations

import hashlib
import os
import signal
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Sequence
from urllib.parse import urlsplit

from .evidence import EvidenceStore, redact_body_preview
from .gateway import ToolGateway
from .models import ConfigError, EngagementConfig, RiskLevel
from .security import redact_url


class ToolExecutionBlocked(PermissionError):
    """Raised when a registered tool is not safe to execute directly."""


def _stop_process(process: subprocess.Popen[bytes], force: bool = False) -> None:
    """Stop only the process group created for this fixed adapter."""
    signal_value = signal.SIGKILL if force else signal.SIGTERM
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal_value)
            return
        except (ProcessLookupError, PermissionError):
            return
    try:
        (process.kill if force else process.terminate)()
    except ProcessLookupError:
        return


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    description: str
    risk: RiskLevel
    direct_execution: bool
    fixed_flags: tuple[str, ...]
    proxy_execution: bool = False
    proxy_flag: str = "-proxy"

    def argv(self, target: str, proxy_url: str | None = None) -> tuple[str, ...]:
        proxy = (self.proxy_flag, proxy_url) if proxy_url and self.proxy_execution else ()
        return (self.binary, *proxy, *self.fixed_flags, target)


@dataclass(frozen=True)
class ToolPlan:
    tool: str
    binary: str
    argv: tuple[str, ...]
    target: str
    available: bool
    direct_execution: bool
    proxy_execution: bool
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
            "proxy_execution": self.proxy_execution,
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
        True,
    ),
    ToolSpec(
        "katana",
        "katana",
        "bounded URL crawler",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-jsonl", "-depth", "1", "-crawl-duration", "10s", "-rate-limit", "1", "-u"),
        True,
    ),
    ToolSpec(
        "subfinder",
        "subfinder",
        "passive subdomain discovery",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-all", "-recursive", "-d"),
        False,
    ),
    ToolSpec(
        "nuclei",
        "nuclei",
        "template-based vulnerability checks",
        RiskLevel.READ_ONLY,
        False,
        ("-silent", "-no-color", "-rate-limit", "1", "-bulk-size", "1", "-concurrency", "1", "-u"),
        True,
    ),
    ToolSpec(
        "ffuf",
        "ffuf",
        "content and parameter fuzzing",
        RiskLevel.STATE_CHANGE,
        False,
        ("-s", "-rate", "1", "-t", "1", "-u"),
        True,
        "-x",
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
                "proxy_execution": spec.proxy_execution,
                "proxy_flag": spec.proxy_flag,
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

    def plan(self, name: str, target: str, proxy_url: str | None = None) -> ToolPlan:
        spec = self.registry.get(name)
        decision = self.config.check_url(target, "GET")
        if not decision.allowed:
            raise ToolExecutionBlocked(f"tool target blocked: {decision.reason}")
        if proxy_url:
            parsed_proxy = urlsplit(proxy_url)
            if (
                parsed_proxy.scheme != "http"
                or parsed_proxy.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed_proxy.username is not None
                or parsed_proxy.password is not None
            ):
                raise ToolExecutionBlocked("tool proxy must be an unauthenticated local HTTP proxy")
        available = shutil.which(spec.binary) is not None
        if not spec.proxy_execution:
            reason = "this tool has no request-aware proxy adapter"
        elif not proxy_url:
            reason = "direct execution is disabled; provide a local request-aware proxy"
        else:
            reason = "fixed-argument proxy adapter is enabled"
        return ToolPlan(
            tool=spec.name,
            binary=spec.binary,
            argv=spec.argv(target, proxy_url),
            target=target,
            available=available,
            direct_execution=spec.direct_execution,
            proxy_execution=spec.proxy_execution,
            risk=spec.risk.value,
            reason=reason,
        )

    def run(
        self,
        name: str,
        target: str,
        *,
        proxy_url: str,
        approval_id: str | None = None,
    ) -> ToolObservation:
        if not self.config.active_testing.enabled:
            raise ToolExecutionBlocked("active testing is disabled by engagement policy")
        spec = self.registry.get(name)
        if not spec.proxy_execution:
            raise ToolExecutionBlocked(f"{name} has no request-aware proxy adapter")
        if urlsplit(target).scheme != "http":
            raise ToolExecutionBlocked("proxy tool execution currently accepts HTTP targets only; HTTPS CONNECT is disabled")
        plan = self.plan(name, target, proxy_url)
        executable = shutil.which(spec.binary)
        if executable is None:
            raise ToolExecutionBlocked(f"tool binary is not installed: {spec.binary}")

        from .security import ActionRequest

        action = ActionRequest(
            action_id=f"act_tool_{time.time_ns()}",
            tool=f"nighwatch.tool.{spec.name}",
            target=target,
            method="GET",
            risk=spec.risk,
            purpose=f"fixed-argument {spec.name} observation through local proxy",
            approval_id=approval_id,
        )
        while True:
            decision = self.gateway.authorize(action)
            if decision.ready:
                break
            if decision.rate.allowed and decision.rate.wait_seconds > 0:
                if decision.rate.wait_seconds > 60:
                    raise ToolExecutionBlocked("rate limiter requires an unsafe wait interval")
                time.sleep(decision.rate.wait_seconds)
                continue
            self.gateway.record_decision(action, decision)
            raise ToolExecutionBlocked(decision.reason)
        self.gateway.record_decision(action, decision)

        command = list(plan.argv)
        command[0] = executable
        environment = dict(os.environ)
        environment.update({
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
        })
        for key in list(environment):
            if key.startswith("NIGHWATCH_AUTH_") or key.startswith("AGENTSEC_AUTH_"):
                environment.pop(key, None)
        started = time.monotonic()
        timed_out = False
        killed = False
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            self.gateway.assert_live()
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                cwd=None,
                env=environment,
                start_new_session=os.name == "posix",
            )
            while process.poll() is None:
                if self.gateway.kill_switch.tripped():
                    killed = True
                    _stop_process(process)
                    break
                if time.monotonic() - started > self.timeout_seconds:
                    timed_out = True
                    _stop_process(process)
                    break
                time.sleep(0.1)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _stop_process(process, force=True)
                process.wait(timeout=2)
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(self.max_output_bytes)
            stderr = stderr_file.read(self.max_output_bytes)
            exit_code = int(process.returncode if process.returncode is not None else 124)

        stdout_preview, _ = redact_body_preview(stdout, self.max_output_bytes)
        stderr_preview, _ = redact_body_preview(stderr, self.max_output_bytes)
        evidence = self.evidence_store.append(
            "tool_observation",
            {
                "engagement_id": self.config.engagement_id,
                "policy_hash": self.config.policy_hash,
                "action_id": action.action_id,
                "tool": spec.name,
                "target": redact_url(target),
                "argv": [spec.binary, *spec.fixed_flags, "[REDACTED_TARGET]"],
                "exit_code": exit_code,
                "timed_out": timed_out,
                "kill_switch_terminated": killed,
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stdout_preview": stdout_preview,
                "stderr_preview": stderr_preview,
            },
        )
        return ToolObservation(
            tool=spec.name,
            evidence_id=str(evidence["evidence_id"]),
            action_id=action.action_id,
            exit_code=exit_code,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            timed_out=timed_out,
        )
