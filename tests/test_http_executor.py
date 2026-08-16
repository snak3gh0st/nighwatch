from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from threading import Thread

import pytest

from agentsec.evidence import EvidenceStore
from agentsec.gateway import GatewayBlocked, ToolGateway
from agentsec.http_executor import HttpExecutor, HttpExecutorError, _PinnedHTTPSConnection
from agentsec.mapping import ApplicationMapStore
from agentsec.models import EngagementConfig
from agentsec.security import ReceiptLogger


class _Handler(BaseHTTPRequestHandler):
    server_version = "NighwatchTest/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.server.seen.append((self.path, self.headers.get("Authorization")))  # type: ignore[attr-defined]
        payload = json.dumps({"id": 123, "owner": "owner_user", "name": "sample"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args) -> None:
        return


class _LocalHTTPServer(ThreadingHTTPServer):
    """Avoid reverse-DNS lookup in the macOS test harness."""

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def _config(port: int, *, allow_private: bool) -> EngagementConfig:
    return EngagementConfig.from_dict({
        "engagement_id": "eng-http-test",
        "authorization": {"artifact_id": "auth-http-test"},
        "allowed_origins": [{
            "scheme": "http",
            "host": "127.0.0.1",
            "ports": [port],
            "path_prefixes": ["/api"],
            "methods": ["GET", "HEAD"],
        }],
        "auth_profiles": ["owner_user", "non_owner_user"],
        "limits": {
            "requests_per_second": 100,
            "max_requests": 10,
            "max_concurrent_requests": 1,
            "max_cost_usd": 1,
        },
        "actions": {"read_only": True, "state_mutation": False, "destructive": False},
        "network": {"allow_private_addresses": allow_private},
    })


@pytest.fixture
def test_server():
    server = _LocalHTTPServer(("127.0.0.1", 0), _Handler)
    server.seen = []  # type: ignore[attr-defined]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_executor_records_evidence_and_maps_auth_profiles(tmp_path, test_server) -> None:
    config = _config(test_server.server_port, allow_private=True)
    evidence_dir = tmp_path / "evidence"
    executor = HttpExecutor(
        config,
        ToolGateway(config, receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl")),
        EvidenceStore(evidence_dir, body_preview_bytes=4096),
        ApplicationMapStore(evidence_dir / "application_map.json"),
        explicit_profiles={
            "owner_user": {"Authorization": "Bearer owner-secret"},
            "non_owner_user": {"Authorization": "Bearer non-owner-secret"},
        },
        capture_body=True,
    )

    first = executor.execute(
        f"http://127.0.0.1:{test_server.server_port}/api/orders/123",
        auth_profile="owner_user",
    )
    second = executor.execute(
        f"http://127.0.0.1:{test_server.server_port}/api/orders/123",
        auth_profile="non_owner_user",
    )

    assert first.response.status == 200
    assert second.response.status == 200
    assert first.endpoint_id == second.endpoint_id
    assert [item[1] for item in test_server.seen] == ["Bearer owner-secret", "Bearer non-owner-secret"]

    evidence_text = (evidence_dir / "evidence.jsonl").read_text(encoding="utf-8")
    assert "owner-secret" not in evidence_text
    assert "non-owner-secret" not in evidence_text
    assert first.evidence_id in evidence_text
    assert second.evidence_id in evidence_text

    mapping = json.loads((evidence_dir / "application_map.json").read_text(encoding="utf-8"))
    endpoint = mapping["endpoints"][first.endpoint_id]
    assert endpoint["path_template"] == "/api/orders/{id}"
    assert endpoint["observed_auth_profiles"] == ["non_owner_user", "owner_user"]
    assert len(endpoint["evidence_ids"]) == 2


def test_http_executor_blocks_out_of_scope_before_network_or_budget(tmp_path, test_server) -> None:
    config = _config(test_server.server_port, allow_private=True)
    evidence_dir = tmp_path / "evidence"
    gateway = ToolGateway(config)
    executor = HttpExecutor(config, gateway, EvidenceStore(evidence_dir))

    with pytest.raises(GatewayBlocked):
        executor.execute(f"http://127.0.0.1:{test_server.server_port}/outside")

    assert gateway.rate_limiter.request_count == 0
    assert test_server.seen == []


def test_http_executor_denies_private_resolution_by_default(tmp_path, test_server) -> None:
    config = _config(test_server.server_port, allow_private=False)
    evidence_dir = tmp_path / "evidence"
    executor = HttpExecutor(config, ToolGateway(config), EvidenceStore(evidence_dir))

    with pytest.raises(HttpExecutorError, match="private"):
        executor.execute(f"http://127.0.0.1:{test_server.server_port}/api/health")

    assert test_server.seen == []
    assert "private" in (evidence_dir / "evidence.jsonl").read_text(encoding="utf-8")


def test_pinned_https_connection_uses_explicit_server_hostname(monkeypatch) -> None:
    class _FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return

        def connect(self, _sockaddr: tuple) -> None:
            return

        def close(self) -> None:
            return

    class _FakeContext:
        def __init__(self) -> None:
            self.server_hostname = None

        def wrap_socket(self, sock, *, server_hostname: str):
            self.server_hostname = server_hostname
            return sock

    context = _FakeContext()
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: _FakeSocket())
    connection = _PinnedHTTPSConnection("bterminal.io", 443, socket.AF_INET, ("127.0.0.1", 443), 1.0)
    connection._context = context
    connection.connect()
    assert context.server_hostname == "bterminal.io"
