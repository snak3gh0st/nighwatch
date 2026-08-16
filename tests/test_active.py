from __future__ import annotations

import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from threading import Thread

import pytest

from agentsec.active import ActiveProbeEngine
from agentsec.evidence import EvidenceStore
from agentsec.gateway import GatewayBlocked, ToolGateway
from agentsec.http_executor import HttpExecutor
from agentsec.mapping import ApplicationMapStore
from agentsec.models import EngagementConfig
from agentsec.proxy import EgressProxyServer
from agentsec.security import ReceiptLogger


class _ActiveHandler(BaseHTTPRequestHandler):
    seen: list[tuple[str, bytes]]

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.server.seen.append((self.command, b""))  # type: ignore[attr-defined]
        self._send(200, {"ok": True, "id": 1})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.seen.append((self.command, body))  # type: ignore[attr-defined]
        self._send(201, {"ok": True, "received": body.decode("utf-8", errors="replace")})

    def _send(self, status: int, value: dict) -> None:
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args) -> None:
        return


class _LocalHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def _config(port: int, *, active: bool = True) -> EngagementConfig:
    return EngagementConfig.from_dict({
        "engagement_id": "eng-active-test",
        "authorization": {"artifact_id": "auth-active-test"},
        "allowed_origins": [{
            "scheme": "http",
            "host": "127.0.0.1",
            "ports": [port],
            "path_prefixes": ["/api"],
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        }],
        "auth_profiles": [],
        "limits": {
            "requests_per_second": 100,
            "max_requests": 50,
            "max_concurrent_requests": 2,
            "max_cost_usd": 1,
        },
        "actions": {
            "read_only": True,
            "state_mutation": True,
            "destructive": True,
            "require_state_change_approval": True,
            "require_destructive_approval": True,
        },
        "network": {"allow_private_addresses": True},
        "active_testing": {
            "enabled": active,
            "max_payload_bytes": 4096,
            "max_cases": 5,
        },
    })


@pytest.fixture
def target_server():
    server = _LocalHTTPServer(("127.0.0.1", 0), _ActiveHandler)
    server.seen = []
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _executor(config: EngagementConfig, root, *, approvals: set[str] | None = None) -> HttpExecutor:
    evidence_dir = root / "evidence"
    return HttpExecutor(
        config,
        ToolGateway(
            config,
            receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"),
            approved_approval_ids=approvals,
        ),
        EvidenceStore(evidence_dir),
        ApplicationMapStore(evidence_dir / "application_map.json"),
        capture_body=True,
    )


def test_active_method_requires_explicit_approval_and_records_payload(tmp_path, target_server) -> None:
    config = _config(target_server.server_port)
    url = f"http://127.0.0.1:{target_server.server_port}/api/submit"
    blocked = _executor(config, tmp_path)
    with pytest.raises(GatewayBlocked):
        blocked.execute(url, method="POST", body=b'{"name":"canary"}', approval_id="approve-1")
    assert target_server.seen == []

    executor = _executor(config, tmp_path, approvals={"approve-1"})
    result = executor.execute(
        url,
        method="POST",
        body=b'{"name":"canary"}',
        request_headers={"Content-Type": "application/json"},
        approval_id="approve-1",
        payload_label="test canary",
    )
    assert result.response.status == 201
    assert target_server.seen == [("POST", b'{"name":"canary"}')]
    evidence_text = (tmp_path / "evidence" / "evidence.jsonl").read_text(encoding="utf-8")
    assert "test canary" in evidence_text
    assert hashlib.sha256(b'{"name":"canary"}').hexdigest() in evidence_text


def test_active_probe_is_bounded_and_uses_gateway_for_each_case(tmp_path, target_server) -> None:
    config = _config(target_server.server_port)
    executor = _executor(config, tmp_path, approvals={"approve-1"})
    result = ActiveProbeEngine(config, executor).run(
        f"http://127.0.0.1:{target_server.server_port}/api/submit",
        method="POST",
        body_template='{"name":"{{NIGHWATCH_PAYLOAD}}"}',
        payloads=["alpha", "<canary>"],
        approval_id="approve-1",
    )
    assert result.cases_executed == 2
    assert len(result.evidence_ids) == 2
    assert len(target_server.seen) == 2


def test_kill_switch_blocks_active_network_action(tmp_path, target_server, monkeypatch) -> None:
    config = _config(target_server.server_port)
    monkeypatch.setenv("NIGHWATCH_KILL_SWITCH", "1")
    executor = _executor(config, tmp_path, approvals={"approve-1"})
    with pytest.raises(GatewayBlocked, match="kill switch"):
        executor.execute(
            f"http://127.0.0.1:{target_server.server_port}/api/submit",
            method="POST",
            body=b"{}",
            approval_id="approve-1",
        )
    assert target_server.seen == []


def test_local_egress_proxy_forwards_absolute_http_request(tmp_path, target_server) -> None:
    config = _config(target_server.server_port)
    proxy = EgressProxyServer(config, str(tmp_path / "proxy-evidence"))
    thread = Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        import http.client

        connection = http.client.HTTPConnection(proxy.address.host, proxy.address.port, timeout=5)
        connection.request("GET", f"http://127.0.0.1:{target_server.server_port}/api/health")
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 200
        assert json.loads(body)["ok"] is True
    finally:
        proxy.shutdown()
        thread.join(timeout=2)


def test_local_egress_proxy_applies_default_approval_to_active_request(tmp_path, target_server) -> None:
    config = _config(target_server.server_port)
    proxy = EgressProxyServer(
        config,
        str(tmp_path / "proxy-evidence"),
        default_approval_id="approve-1",
    )
    thread = Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        import http.client

        connection = http.client.HTTPConnection(proxy.address.host, proxy.address.port, timeout=5)
        connection.request(
            "POST",
            f"http://127.0.0.1:{target_server.server_port}/api/submit",
            body=b'{"name":"proxy-canary"}',
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        connection.close()
        assert response.status == 201
        assert target_server.seen == [("POST", b'{"name":"proxy-canary"}')]
    finally:
        proxy.shutdown()
        thread.join(timeout=2)
