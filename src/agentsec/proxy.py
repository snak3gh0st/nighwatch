"""Request-aware local egress proxy for fixed tool adapters.

The proxy accepts HTTP absolute-form requests and forwards them through the
same HttpExecutor used by the CLI. HTTPS CONNECT is intentionally rejected:
a CONNECT tunnel would hide method, path, payload, redirects, and response
evidence from the policy layer. HTTPS tool support must use a reviewed TLS
interception adapter before it is enabled.
"""

from __future__ import annotations

import http.server
import socketserver
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .evidence import EvidenceStore
from .gateway import ToolGateway
from .http_executor import HttpExecutor, HttpExecutorError
from .mapping import ApplicationMapStore
from .models import ConfigError, EngagementConfig
from .security import ReceiptLogger


class EgressProxyError(RuntimeError):
    """Raised when the local egress proxy cannot be started or used."""


_FORWARDED_HEADERS = {
    "accept",
    "authorization",
    "content-type",
    "cookie",
    "user-agent",
    "x-api-key",
    "x-auth-token",
}
_CONTROL_HEADERS = {
    "x-nighwatch-approval-id",
    "x-nighwatch-auth-profile",
    "x-nighwatch-payload-label",
}
_HOP_BY_HOP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass(frozen=True)
class ProxyAddress:
    host: str
    port: int


class _ThreadingProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    server: _ThreadingProxyServer
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._forward()

    def do_CONNECT(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_error(501, "HTTPS CONNECT is disabled until TLS interception is installed")

    def _forward(self) -> None:
        target = self.path.strip()
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            self.send_error(400, "proxy requests must use an absolute http(s) URL")
            return
        if parsed.fragment:
            self.send_error(400, "URL fragments are not valid proxy targets")
            return

        try:
            body = self._read_body()
            control = {name.lower(): value for name, value in self.headers.items()}
            auth_profile = (
                control.get("x-nighwatch-auth-profile")
                or self.server.default_auth_profile  # type: ignore[attr-defined]
                or None
            )
            approval_id = (
                control.get("x-nighwatch-approval-id")
                or self.server.default_approval_id  # type: ignore[attr-defined]
                or None
            )
            payload_label = control.get("x-nighwatch-payload-label") or None
            forwarded = self._forward_headers(auth_profile)
            result = self.server.executor.execute(
                target,
                method=self.command,
                auth_profile=auth_profile,
                request_headers=forwarded,
                body=body,
                approval_id=approval_id,
                payload_label=payload_label,
                purpose="controlled tool request through local egress proxy",
            )
        except (ConfigError, EgressProxyError, HttpExecutorError, PermissionError, OSError) as exc:
            message = str(exc).replace("\r", " ").replace("\n", " ")[:300]
            self.send_error(502, message)
            return

        response = result.response
        self.send_response(response.status, response.reason)
        for name, value in response.headers.items():
            if name.lower() in _HOP_BY_HOP_RESPONSE_HEADERS or name.lower() == "content-length":
                continue
            try:
                self.send_header(name, value)
            except (TypeError, ValueError):
                continue
        self.send_header("Content-Length", str(len(response.body) if self.command != "HEAD" else 0))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and response.body:
            self.wfile.write(response.body)

    def _read_body(self) -> bytes:
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if transfer_encoding and transfer_encoding != "identity":
            raise EgressProxyError("chunked proxy request bodies are not supported")
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise EgressProxyError("invalid Content-Length") from exc
        if length < 0 or length > self.server.config.active_testing.max_payload_bytes:
            raise EgressProxyError("proxy request body exceeds the active payload limit")
        return self.rfile.read(length) if length else b""

    def _forward_headers(self, auth_profile: str | None) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in self.headers.items():
            lower_name = name.lower()
            if lower_name in _CONTROL_HEADERS or lower_name in {"host", "connection", "content-length", "proxy-connection"}:
                continue
            if lower_name not in _FORWARDED_HEADERS:
                continue
            if auth_profile and lower_name in {"authorization", "cookie", "x-api-key", "x-auth-token"}:
                continue
            if "\r" in value or "\n" in value:
                raise EgressProxyError("request header contains a line break")
            result[name] = value
        return result

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class EgressProxyServer:
    """Foreground local proxy that delegates every request to HttpExecutor."""

    def __init__(
        self,
        config: EngagementConfig,
        evidence_dir: str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        approved_approval_ids: set[str] | None = None,
        default_approval_id: str | None = None,
        default_auth_profile: str | None = None,
    ) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise EgressProxyError("the local egress proxy may bind only to loopback")
        approvals = set(approved_approval_ids or ())
        if default_approval_id:
            approvals.add(default_approval_id)
        evidence_store = EvidenceStore(evidence_dir)
        gateway = ToolGateway(
            config,
            receipt_logger=ReceiptLogger(f"{evidence_dir}/receipts.jsonl"),
            approved_approval_ids=approvals,
        )
        self.config = config
        self.default_approval_id = default_approval_id
        self.default_auth_profile = default_auth_profile
        self.gateway = gateway
        self.executor = HttpExecutor(
            config,
            gateway,
            evidence_store,
            ApplicationMapStore(f"{evidence_dir}/application_map.json"),
            capture_body=True,
        )
        self._server = _ThreadingProxyServer((host, port), _ProxyHandler)
        self._server.config = config  # type: ignore[attr-defined]
        self._server.executor = self.executor  # type: ignore[attr-defined]
        self._server.default_approval_id = default_approval_id  # type: ignore[attr-defined]
        self._server.default_auth_profile = default_auth_profile  # type: ignore[attr-defined]

    @property
    def address(self) -> ProxyAddress:
        host, port = self._server.server_address[:2]
        return ProxyAddress(str(host), int(port))

    def serve_forever(self) -> None:
        self._server.serve_forever(poll_interval=0.2)

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
