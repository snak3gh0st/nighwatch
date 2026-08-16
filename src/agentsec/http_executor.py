"""Bounded HTTP executor behind the Nighwatch policy gateway."""

from __future__ import annotations

import http.client
import hashlib
import ipaddress
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from .evidence import EvidenceStore
from .gateway import GatewayBlocked, ToolGateway
from .mapping import ApplicationMapStore
from .models import ConfigError, EngagementConfig, RiskLevel
from .security import ActionRequest


class HttpExecutorError(RuntimeError):
    """Raised when a bounded HTTP observation cannot be completed."""


_AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}
_FORWARD_HEADER_NAMES = _AUTH_HEADER_NAMES | {"accept", "content-type", "user-agent"}
_SUPPORTED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


def _risk_for_method(method: str) -> RiskLevel:
    if method in {"GET", "HEAD", "OPTIONS"}:
        return RiskLevel.READ_ONLY
    if method == "DELETE":
        return RiskLevel.DESTRUCTIVE
    return RiskLevel.STATE_CHANGE


def _validate_forward_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in (headers or {}).items():
        normalized_name = str(name).lower()
        if normalized_name not in _FORWARD_HEADER_NAMES:
            raise ConfigError(f"request header is not permitted through the egress boundary: {name}")
        if "\r" in str(name) or "\n" in str(name) or "\r" in str(value) or "\n" in str(value):
            raise ConfigError("request header contains a line break")
        result[str(name)] = str(value)
    return result


def _safe_profile_suffix(profile: str) -> str:
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", profile).strip("_").upper()
    if not suffix:
        raise ConfigError("auth profile identifier cannot be converted to an environment variable")
    return suffix


def resolve_auth_headers(
    config: EngagementConfig,
    profile: str | None,
    explicit_profiles: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, str]:
    """Load a profile secret from memory or environment, never from config."""
    if profile is None:
        return {}
    if profile not in config.auth_profiles:
        raise ConfigError(f"auth profile is not declared in the engagement: {profile}")

    if explicit_profiles and profile in explicit_profiles:
        headers = dict(explicit_profiles[profile])
    else:
        suffix = _safe_profile_suffix(profile)
        bearer = os.getenv(f"NIGHWATCH_AUTH_{suffix}_BEARER") or os.getenv(f"AGENTSEC_AUTH_{suffix}_BEARER")
        cookie = os.getenv(f"NIGHWATCH_AUTH_{suffix}_COOKIE") or os.getenv(f"AGENTSEC_AUTH_{suffix}_COOKIE")
        headers = {}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if cookie:
            headers["Cookie"] = cookie
    if not headers:
        raise ConfigError(f"no secret is loaded for auth profile: {profile}")
    for name, value in headers.items():
        if str(name).lower() not in _AUTH_HEADER_NAMES:
            raise ConfigError(f"auth profile header is not permitted: {name}")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", str(name)) or "\r" in str(value) or "\n" in str(value):
            raise ConfigError("auth profile contains an invalid HTTP header")
    return {str(name): str(value) for name, value in headers.items()}


@dataclass(frozen=True)
class HttpResponse:
    url: str
    method: str
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    body_truncated: bool
    elapsed_ms: float


@dataclass(frozen=True)
class HttpObservation:
    action_id: str
    evidence_id: str
    endpoint_id: str | None
    auth_profile: str | None
    response: HttpResponse


def _resolve_allowed_address(host: str, port: int, allow_private: bool) -> tuple[int, tuple]:
    try:
        candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise HttpExecutorError(f"DNS resolution failed for authorized host: {host}") from exc

    for family, socket_type, _proto, _canonname, sockaddr in candidates:
        if socket_type != socket.SOCK_STREAM:
            continue
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not allow_private and (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified
        ):
            continue
        return family, sockaddr
    raise HttpExecutorError("authorized host resolved only to a private or otherwise restricted address")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, family: int, sockaddr: tuple, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._nighwatch_family = family
        self._nighwatch_sockaddr = sockaddr

    def connect(self) -> None:
        sock = socket.socket(self._nighwatch_family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._nighwatch_sockaddr)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, family: int, sockaddr: tuple, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._nighwatch_server_hostname = host
        self._nighwatch_family = family
        self._nighwatch_sockaddr = sockaddr

    def connect(self) -> None:
        sock = socket.socket(self._nighwatch_family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._nighwatch_sockaddr)
            self.sock = self._context.wrap_socket(sock, server_hostname=self._nighwatch_server_hostname)
        except BaseException:
            sock.close()
            raise


class HttpExecutor:
    """Execute policy-gated HTTP requests and persist reproducible evidence."""

    def __init__(
        self,
        config: EngagementConfig,
        gateway: ToolGateway,
        evidence_store: EvidenceStore,
        map_store: ApplicationMapStore | None = None,
        *,
        explicit_profiles: Mapping[str, Mapping[str, str]] | None = None,
        timeout_seconds: float = 15.0,
        max_body_bytes: int = 1_048_576,
        capture_body: bool = False,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be between 0 and 60")
        if max_body_bytes <= 0 or max_body_bytes > 10_485_760:
            raise ValueError("max_body_bytes must be between 1 and 10485760")
        self.config = config
        self.gateway = gateway
        self.evidence_store = evidence_store
        self.map_store = map_store
        self.explicit_profiles = explicit_profiles
        self.timeout_seconds = timeout_seconds
        self.max_body_bytes = max_body_bytes
        self.capture_body = capture_body

    def profile_fingerprint(self, profile: str) -> str:
        headers = resolve_auth_headers(self.config, profile, self.explicit_profiles)
        canonical = "\n".join(f"{key.lower()}:{value}" for key, value in sorted(headers.items()))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def execute(
        self,
        url: str,
        *,
        method: str = "GET",
        auth_profile: str | None = None,
        purpose: str = "authorized application observation",
        body: bytes | str | None = None,
        request_headers: Mapping[str, str] | None = None,
        approval_id: str | None = None,
        payload_label: str | None = None,
    ) -> HttpObservation:
        normalized_method = method.upper()
        if normalized_method not in _SUPPORTED_METHODS:
            raise HttpExecutorError(f"unsupported HTTP method: {normalized_method}")
        if normalized_method == "HEAD" and body:
            raise HttpExecutorError("HEAD requests cannot carry a request body")
        if isinstance(body, str):
            body = body.encode("utf-8")
        if body is None:
            body = b""
        if len(body) > self.config.active_testing.max_payload_bytes:
            raise HttpExecutorError(
                f"request body exceeds active_testing.max_payload_bytes ({self.config.active_testing.max_payload_bytes})"
            )
        if normalized_method in {"GET", "HEAD", "OPTIONS"} and body:
            raise HttpExecutorError(f"{normalized_method} requests cannot carry an active request body")
        safe_request_headers = _validate_forward_headers(request_headers)
        if auth_profile is not None and any(name.lower() in _AUTH_HEADER_NAMES for name in safe_request_headers):
            raise ConfigError("request_headers cannot contain auth headers when --profile is used")

        risk = _risk_for_method(normalized_method)
        action_id = f"act_{uuid.uuid4().hex}"
        request = ActionRequest(
            action_id=action_id,
            tool="nighwatch.http",
            target=url,
            method=normalized_method,
            risk=risk,
            purpose=purpose,
            approval_id=approval_id,
        )

        while True:
            decision = self.gateway.authorize(request)
            if decision.ready:
                break
            if decision.rate.allowed and decision.rate.wait_seconds > 0:
                if decision.rate.wait_seconds > 60:
                    raise HttpExecutorError("rate limiter requires an unsafe wait interval")
                time.sleep(decision.rate.wait_seconds)
                continue
            self.gateway.record_decision(request, decision)
            raise GatewayBlocked(decision)

        receipt = self.gateway.record_decision(request, decision)
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "User-Agent": "Nighwatch/0.2 controlled-active",
        }
        headers.update(safe_request_headers)
        headers.update(resolve_auth_headers(self.config, auth_profile, self.explicit_profiles))
        if body and "content-type" not in {name.lower() for name in headers}:
            headers["Content-Type"] = "application/octet-stream"
        started = time.monotonic()
        try:
            with self.gateway.execution_slot():
                self.gateway.assert_live()
                response = self._request(url, normalized_method, headers, body)
        except (OSError, http.client.HTTPException, HttpExecutorError) as exc:
            error = f"{type(exc).__name__}: {str(exc).replace(chr(10), ' ')[:300]}"
            self.evidence_store.record_http(
                engagement_id=self.config.engagement_id,
                policy_hash=self.config.policy_hash,
                action_id=receipt.action_id,
                auth_profile=auth_profile,
                method=normalized_method,
                url=url,
                request_headers=headers,
                request_body=body,
                payload_label=payload_label,
                response_status=None,
                response_reason=None,
                response_headers=None,
                elapsed_ms=(time.monotonic() - started) * 1000,
                error=error,
                capture_body=False,
            )
            raise HttpExecutorError(error) from exc

        evidence = self.evidence_store.record_http(
            engagement_id=self.config.engagement_id,
            policy_hash=self.config.policy_hash,
            action_id=receipt.action_id,
            auth_profile=auth_profile,
            method=normalized_method,
            url=url,
            request_headers=headers,
            request_body=body,
            payload_label=payload_label,
            response_status=response.status,
            response_reason=response.reason,
            response_headers=response.headers,
            response_body=response.body,
            response_truncated=response.body_truncated,
            elapsed_ms=response.elapsed_ms,
            capture_body=self.capture_body,
        )
        endpoint_id = None
        if self.map_store is not None:
            endpoint_id = self.map_store.observe(
                method=normalized_method,
                url=url,
                auth_profile=auth_profile,
                status=response.status,
                response_body=response.body,
                evidence_id=str(evidence["evidence_id"]),
            )
        return HttpObservation(
            action_id=receipt.action_id,
            evidence_id=str(evidence["evidence_id"]),
            endpoint_id=endpoint_id,
            auth_profile=auth_profile,
            response=response,
        )

    def _request(self, url: str, method: str, headers: dict[str, str], body: bytes = b"") -> HttpResponse:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        family, sockaddr = _resolve_allowed_address(host, port, self.config.allow_private_addresses)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection: http.client.HTTPConnection
        if parsed.scheme.lower() == "https":
            connection = _PinnedHTTPSConnection(host, port, family, sockaddr, self.timeout_seconds)
        else:
            connection = _PinnedHTTPConnection(host, port, family, sockaddr, self.timeout_seconds)
        started = time.monotonic()
        try:
            connection.request(method, path, body=body or None, headers=headers)
            response = connection.getresponse()
            body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
            truncated = len(body) > self.max_body_bytes
            if truncated:
                body = body[: self.max_body_bytes]
            return HttpResponse(
                url=url,
                method=method,
                status=int(response.status),
                reason=str(response.reason or ""),
                headers={str(key): str(value) for key, value in response.getheaders()},
                body=body,
                body_truncated=truncated,
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
        finally:
            connection.close()
