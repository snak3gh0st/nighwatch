"""Typed engagement models used by the policy and CLI layers.

The first implementation intentionally uses the standard library only. This
keeps the policy kernel small enough to audit before adding browser, HTTP, or
LLM dependencies.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit


class ConfigError(ValueError):
    """Raised when an engagement configuration is unsafe or malformed."""


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"


def _strict_bool(raw: Any, field: str, default: bool) -> bool:
    value = default if raw is None else raw
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be a boolean")
    return value


def normalize_host(host: str) -> str:
    """Normalize a DNS name without resolving it.

    Resolution is deliberately outside this pure function. The future egress
    layer must resolve and pin addresses immediately before connecting.
    """

    value = host.strip().rstrip(".").lower()
    if not value:
        raise ConfigError("host cannot be empty")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigError(f"invalid host: {host!r}") from exc


def _path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    if not prefixes:
        return True
    for prefix in prefixes:
        normalized = prefix if prefix.startswith("/") else f"/{prefix}"
        normalized = normalized.rstrip("/") or "/"
        if normalized == "/":
            return True
        if path == normalized or path.startswith(f"{normalized}/"):
            return True
    return False


@dataclass(frozen=True)
class ScopeOrigin:
    scheme: str
    host: str
    ports: tuple[int, ...]
    path_prefixes: tuple[str, ...]
    methods: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ScopeOrigin":
        if not isinstance(raw, dict):
            raise ConfigError("each allowed origin must be an object")

        scheme = str(raw.get("scheme", "")).lower()
        if scheme not in {"http", "https"}:
            raise ConfigError("allowed origin scheme must be http or https")

        host = normalize_host(str(raw.get("host", "")))
        ports_raw = raw.get("ports")
        if not isinstance(ports_raw, list) or not ports_raw:
            raise ConfigError(f"allowed origin {host} must declare at least one port")

        try:
            ports = tuple(sorted({int(port) for port in ports_raw}))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"invalid ports for {host}") from exc
        if any(port < 1 or port > 65535 for port in ports):
            raise ConfigError(f"invalid port for {host}")

        prefixes_raw = raw.get("path_prefixes", ["/"])
        if not isinstance(prefixes_raw, list) or any(not isinstance(item, str) for item in prefixes_raw):
            raise ConfigError(f"path_prefixes for {host} must be a list of strings")

        methods_raw = raw.get("methods", ["GET"])
        if not isinstance(methods_raw, list) or any(not isinstance(item, str) for item in methods_raw):
            raise ConfigError(f"methods for {host} must be a list of strings")
        methods = tuple(sorted({item.upper() for item in methods_raw}))
        if not methods:
            raise ConfigError(f"methods for {host} cannot be empty")

        return cls(
            scheme=scheme,
            host=host,
            ports=ports,
            path_prefixes=tuple(prefixes_raw),
            methods=methods,
        )


@dataclass(frozen=True)
class RateLimits:
    requests_per_second: float = 1.0
    max_requests: int = 100
    max_concurrent_requests: int = 1
    max_cost_usd: float = 1.0

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "RateLimits":
        raw = raw or {}
        try:
            result = cls(
                requests_per_second=float(raw.get("requests_per_second", 1.0)),
                max_requests=int(raw.get("max_requests", 100)),
                max_concurrent_requests=int(raw.get("max_concurrent_requests", 1)),
                max_cost_usd=float(raw.get("max_cost_usd", 1.0)),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError("limits contain an invalid numeric value") from exc

        if result.requests_per_second <= 0:
            raise ConfigError("requests_per_second must be greater than zero")
        if result.max_requests <= 0:
            raise ConfigError("max_requests must be greater than zero")
        if result.max_concurrent_requests <= 0:
            raise ConfigError("max_concurrent_requests must be greater than zero")
        if result.max_cost_usd < 0:
            raise ConfigError("max_cost_usd cannot be negative")
        return result


@dataclass(frozen=True)
class ActionPolicy:
    read_only: bool = True
    state_mutation: bool = False
    destructive: bool = False
    require_state_change_approval: bool = True
    require_destructive_approval: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "ActionPolicy":
        raw = raw or {}
        return cls(
            read_only=_strict_bool(raw.get("read_only"), "actions.read_only", True),
            state_mutation=_strict_bool(raw.get("state_mutation"), "actions.state_mutation", False),
            destructive=_strict_bool(raw.get("destructive"), "actions.destructive", False),
            require_state_change_approval=_strict_bool(
                raw.get("require_state_change_approval"),
                "actions.require_state_change_approval",
                True,
            ),
            require_destructive_approval=_strict_bool(
                raw.get("require_destructive_approval"),
                "actions.require_destructive_approval",
                True,
            ),
        )

    def allows(self, risk: RiskLevel) -> bool:
        return {
            RiskLevel.READ_ONLY: self.read_only,
            RiskLevel.STATE_CHANGE: self.state_mutation,
            RiskLevel.DESTRUCTIVE: self.destructive,
        }[risk]


@dataclass(frozen=True)
class ActiveTestingPolicy:
    """Limits for active requests and bounded payload probing."""

    enabled: bool = False
    max_payload_bytes: int = 8_192
    max_cases: int = 25
    kill_switch_file: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "ActiveTestingPolicy":
        raw = raw or {}
        enabled = _strict_bool(raw.get("enabled"), "active_testing.enabled", False)
        try:
            max_payload_bytes = int(raw.get("max_payload_bytes", 8_192))
            max_cases = int(raw.get("max_cases", 25))
        except (TypeError, ValueError) as exc:
            raise ConfigError("active_testing limits contain an invalid numeric value") from exc
        if max_payload_bytes <= 0 or max_payload_bytes > 1_048_576:
            raise ConfigError("active_testing.max_payload_bytes must be between 1 and 1048576")
        if max_cases <= 0 or max_cases > 10_000:
            raise ConfigError("active_testing.max_cases must be between 1 and 10000")
        kill_switch_file = raw.get("kill_switch_file")
        if kill_switch_file is not None and (not isinstance(kill_switch_file, str) or not kill_switch_file.strip()):
            raise ConfigError("active_testing.kill_switch_file must be a non-empty string or null")
        return cls(
            enabled=enabled,
            max_payload_bytes=max_payload_bytes,
            max_cases=max_cases,
            kill_switch_file=kill_switch_file.strip() if isinstance(kill_switch_file, str) else None,
        )


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    method: str
    policy_hash: str


@dataclass(frozen=True)
class EngagementConfig:
    engagement_id: str
    allowed_origins: tuple[ScopeOrigin, ...]
    excluded_hosts: tuple[str, ...]
    auth_profiles: tuple[str, ...]
    limits: RateLimits
    actions: ActionPolicy
    authorization_artifact_id: str
    allow_private_addresses: bool = False
    active_testing: ActiveTestingPolicy = ActiveTestingPolicy()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EngagementConfig":
        if not isinstance(raw, dict):
            raise ConfigError("configuration must be a JSON object")

        engagement_id = str(raw.get("engagement_id", "")).strip()
        if not engagement_id:
            raise ConfigError("engagement_id is required")

        authorization = raw.get("authorization")
        if not isinstance(authorization, dict) or not str(authorization.get("artifact_id", "")).strip():
            raise ConfigError("authorization.artifact_id is required")

        origins_raw = raw.get("allowed_origins")
        if not isinstance(origins_raw, list) or not origins_raw:
            raise ConfigError("allowed_origins is required and cannot be empty")

        excluded_raw = raw.get("excluded_hosts", [])
        if not isinstance(excluded_raw, list) or any(not isinstance(item, str) for item in excluded_raw):
            raise ConfigError("excluded_hosts must be a list of strings")

        auth_raw = raw.get("auth_profiles", [])
        if not isinstance(auth_raw, list) or any(not isinstance(item, str) for item in auth_raw):
            raise ConfigError("auth_profiles must be a list of profile identifiers")

        network_raw = raw.get("network", {})
        if not isinstance(network_raw, dict):
            raise ConfigError("network must be an object")
        allow_private_addresses = _strict_bool(
            network_raw.get("allow_private_addresses"),
            "network.allow_private_addresses",
            False,
        )

        return cls(
            engagement_id=engagement_id,
            allowed_origins=tuple(ScopeOrigin.from_dict(item) for item in origins_raw),
            excluded_hosts=tuple(normalize_host(item) for item in excluded_raw),
            auth_profiles=tuple(item.strip() for item in auth_raw if item.strip()),
            limits=RateLimits.from_dict(raw.get("limits")),
            actions=ActionPolicy.from_dict(raw.get("actions")),
            authorization_artifact_id=str(authorization["artifact_id"]).strip(),
            allow_private_addresses=allow_private_addresses,
            active_testing=ActiveTestingPolicy.from_dict(raw.get("active_testing")),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "EngagementConfig":
        file_path = Path(path)
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"configuration file not found: {file_path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"configuration is not valid JSON: {exc.msg}") from exc
        return cls.from_dict(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "authorization": {"artifact_id": self.authorization_artifact_id},
            "allowed_origins": [asdict(origin) for origin in self.allowed_origins],
            "excluded_hosts": list(self.excluded_hosts),
            "auth_profiles": list(self.auth_profiles),
            "limits": asdict(self.limits),
            "actions": asdict(self.actions),
            "network": {"allow_private_addresses": self.allow_private_addresses},
            "active_testing": asdict(self.active_testing),
        }

    @property
    def policy_hash(self) -> str:
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def check_url(self, url: str, method: str = "GET") -> ScopeDecision:
        target = str(url).strip()
        normalized_method = str(method).upper()
        try:
            parsed = urlsplit(target)
            host = normalize_host(parsed.hostname or "")
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except (ValueError, ConfigError) as exc:
            return ScopeDecision(False, f"invalid URL: {exc}", target, normalized_method, self.policy_hash)

        if parsed.scheme.lower() not in {"http", "https"}:
            return ScopeDecision(False, "only http and https are allowed", target, normalized_method, self.policy_hash)
        if parsed.username is not None or parsed.password is not None:
            return ScopeDecision(False, "URL userinfo is not allowed", target, normalized_method, self.policy_hash)
        if parsed.fragment:
            return ScopeDecision(False, "URL fragments are not allowed in an HTTP target", target, normalized_method, self.policy_hash)
        if host in self.excluded_hosts:
            return ScopeDecision(False, f"host {host} is explicitly excluded", target, normalized_method, self.policy_hash)

        path = parsed.path or "/"
        for origin in self.allowed_origins:
            if (
                parsed.scheme.lower() == origin.scheme
                and host == origin.host
                and port in origin.ports
            ):
                if normalized_method not in origin.methods:
                    return ScopeDecision(False, f"method {normalized_method} is not allowed for {host}", target, normalized_method, self.policy_hash)
                if not _path_matches(path, origin.path_prefixes):
                    return ScopeDecision(False, f"path {path} is not allowed for {host}", target, normalized_method, self.policy_hash)
                return ScopeDecision(True, "target is in scope", target, normalized_method, self.policy_hash)

        return ScopeDecision(False, f"origin {parsed.scheme}://{host}:{port} is not in scope", target, normalized_method, self.policy_hash)


def canonical_url(url: str) -> str:
    """Return a comparison-safe URL without credentials or fragments."""

    parsed: SplitResult = urlsplit(url)
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("URL userinfo is not allowed")
    return urlunsplit((parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.path or "/", parsed.query, ""))
