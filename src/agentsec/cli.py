"""Nighwatch command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .active import ActiveProbeEngine, ActiveProbeError
from .browser import BrowserExecutorError, PlaywrightBrowserExecutor
from .config import write_template
from .evidence import EvidenceStore
from .findings import AuthorizationValidator
from .gateway import GatewayBlocked, ToolGateway
from .http_executor import HttpExecutor, HttpExecutorError
from .llm import OllamaClient, OllamaConfig, OllamaError
from .mapping import ApplicationMapStore
from .models import ConfigError, EngagementConfig, RiskLevel
from .planner import OllamaPlanner
from .reasoning import ReasoningLoop
from .security import ActionRequest, KillSwitchTripped, ReceiptLogger, redact_url
from .state import InvestigationStateStore
from .tools import DeterministicToolRunner, ToolExecutionBlocked, ToolRegistry
from .proxy import EgressProxyError, EgressProxyServer

DISPLAY_NAME = "NIGHWATCH"


def _print_banner() -> None:
    """Show the interactive CLI identity without contaminating stdout/JSON."""
    if not sys.stderr.isatty():
        return

    color = "\033[38;5;45m"
    muted = "\033[38;5;245m"
    reset = "\033[0m"
    print(
        f"{color}╭──────────────────────────────────────────────────────╮\n"
        f"│  {DISPLAY_NAME:<50}│\n"
        f"│  scope-enforced AI security lab                     │\n"
        f"│  by snak3gh0st                                      │\n"
        f"│  AUTHORIZED TARGETS ONLY • EVERY ACTION LOGGED      │\n"
        f"╰──────────────────────────────────────────────────────╯{reset}\n"
        f"{muted}ready: policy first, evidence always{reset}",
        file=sys.stderr,
    )


def _load(path: str) -> EngagementConfig:
    return EngagementConfig.from_file(path)


def _read_bounded_bytes(path: str | Path, max_bytes: int, label: str) -> bytes:
    file_path = Path(path)
    try:
        with file_path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read {label}: {exc}") from exc
    if len(data) > max_bytes:
        raise ConfigError(f"{label} exceeds the configured input limit ({max_bytes} bytes)")
    return data


def _read_bounded_text(path: str | Path, max_bytes: int, label: str) -> str:
    try:
        return _read_bounded_bytes(path, max_bytes, label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{label} is not valid UTF-8") from exc


def build_parser() -> argparse.ArgumentParser:
    invoked_as = Path(sys.argv[0]).name.lower()
    program = invoked_as if invoked_as in {"nighwatch", "nightwatch", "agentsec"} else "nighwatch"
    parser = argparse.ArgumentParser(prog=program, description="Nighwatch secure-by-default AI security testing control plane")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--no-banner", action="store_true", help="suppress the interactive startup banner")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a non-secret engagement template")
    init.add_argument("--output", required=True)

    scope = commands.add_parser("scope", help="validate and inspect scope")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)

    validate = scope_commands.add_parser("validate")
    validate.add_argument("--config", required=True)

    check = scope_commands.add_parser("check")
    check.add_argument("--config", required=True)
    check.add_argument("--url", required=True)
    check.add_argument("--method", default="GET")

    policy = commands.add_parser("policy", help="inspect the effective policy")
    policy.add_argument("--config", required=True)

    run = commands.add_parser("run", help="show a safe plan; use http or active commands for controlled execution")
    run.add_argument("--config", required=True)
    run.add_argument("--dry-run", action="store_true")

    llm = commands.add_parser("llm", help="inspect the local Ollama provider")
    llm_commands = llm.add_subparsers(dest="llm_command", required=True)
    health = llm_commands.add_parser("health")
    health.add_argument("--model")

    plan = commands.add_parser("plan", help="ask local Ollama for one structured next-task proposal")
    plan.add_argument("--config", required=True)
    plan.add_argument("--observation", required=True, help="path to an observation text file")
    plan.add_argument("--model")

    http = commands.add_parser("http", help="perform a bounded authorized HTTP request")
    http_commands = http.add_subparsers(dest="http_command", required=True)
    request = http_commands.add_parser("request", help="execute an in-scope request through the policy gateway")
    request.add_argument("--config", required=True)
    request.add_argument("--url", required=True)
    request.add_argument("--method", choices=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"], default="GET")
    request.add_argument("--profile", help="declared auth profile; secret is loaded from the environment")
    request.add_argument("--body-file", help="request body file for active methods; never put secrets in shell arguments")
    request.add_argument("--content-type", default="application/json")
    request.add_argument("--approval-id", help="explicit approval identifier for state-changing or destructive actions")
    request.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")
    request.add_argument("--timeout", type=float, default=15.0)
    request.add_argument("--max-body-bytes", type=int, default=1_048_576)
    request.add_argument("--capture-body", action="store_true", help="store a bounded redacted body preview")
    request.add_argument("--purpose", default="authorized application observation")

    authz = commands.add_parser("authz", help="compare declared authenticated profiles")
    authz_commands = authz.add_subparsers(dest="authz_command", required=True)
    compare = authz_commands.add_parser("compare", help="independently validate object-level authorization")
    compare.add_argument("--config", required=True)
    compare.add_argument("--url", required=True)
    compare.add_argument("--owner-profile", required=True)
    compare.add_argument("--subject-profile", required=True)
    compare.add_argument("--impact-field", action="append", default=[], help="field that must be visible to demonstrate impact")
    compare.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")
    compare.add_argument("--timeout", type=float, default=15.0)
    compare.add_argument("--max-body-bytes", type=int, default=1_048_576)

    investigate = commands.add_parser("investigate", help="run one bounded observe-reason-test-verify cycle")
    investigate.add_argument("--config", required=True)
    investigate.add_argument("--observation", required=True, help="path to an untrusted observation text file")
    investigate.add_argument("--url", required=True, help="explicit in-scope URL for the bounded authorization test")
    investigate.add_argument("--owner-profile", required=True)
    investigate.add_argument("--subject-profile", required=True)
    investigate.add_argument("--impact-field", action="append", default=[])
    investigate.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")
    investigate.add_argument("--model")
    investigate.add_argument("--timeout", type=float, default=15.0)
    investigate.add_argument("--max-body-bytes", type=int, default=1_048_576)
    investigate.add_argument("--max-steps", type=int, default=3, help="bounded planner/validator steps (1-10)")
    investigate.add_argument("--state-file", help="permission-restricted investigation state file")

    active = commands.add_parser("active", help="run bounded active payload observations")
    active_commands = active.add_subparsers(dest="active_command", required=True)
    probe = active_commands.add_parser("probe", help="substitute bounded canaries into an operator-owned body template")
    probe.add_argument("--config", required=True)
    probe.add_argument("--url", required=True)
    probe.add_argument("--method", choices=["POST", "PUT", "PATCH"], default="POST")
    probe.add_argument("--body-template-file", required=True)
    probe.add_argument("--payload-file", required=True)
    probe.add_argument("--profile")
    probe.add_argument("--content-type", default="application/json")
    probe.add_argument("--approval-id", help="explicit approval identifier for state-changing actions")
    probe.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")
    probe.add_argument("--timeout", type=float, default=15.0)
    probe.add_argument("--max-body-bytes", type=int, default=1_048_576)

    browser = commands.add_parser("browser", help="inspect one page through the controlled Playwright adapter")
    browser_commands = browser.add_subparsers(dest="browser_command", required=True)
    inspect = browser_commands.add_parser("inspect", help="observe a page without form submission or downloads")
    inspect.add_argument("--config", required=True)
    inspect.add_argument("--url", required=True)
    inspect.add_argument("--profile", help="declared auth profile; secret is loaded from the environment")
    inspect.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")
    inspect.add_argument("--timeout", type=float, default=30.0)
    inspect.add_argument(
        "--wait-until",
        choices=["commit", "domcontentloaded", "load", "networkidle"],
        default="domcontentloaded",
    )

    tools = commands.add_parser("tools", help="inspect the fixed deterministic tool registry")
    tools_commands = tools.add_subparsers(dest="tools_command", required=True)
    tools_commands.add_parser("list", help="list registered tools and whether their binaries are installed")
    tool_plan = tools_commands.add_parser("plan", help="show a fixed-argument plan without executing it")
    tool_plan.add_argument("--config", required=True)
    tool_plan.add_argument("--tool", required=True, choices=["ffuf", "httpx", "katana", "nuclei", "subfinder"])
    tool_plan.add_argument("--target", required=True)
    tool_plan.add_argument("--proxy-url", help="local request-aware egress proxy URL")
    tool_run = tools_commands.add_parser("run", help="execute an enabled fixed-argument adapter")
    tool_run.add_argument("--config", required=True)
    tool_run.add_argument("--tool", required=True, choices=["ffuf", "httpx", "katana", "nuclei", "subfinder"])
    tool_run.add_argument("--target", required=True)
    tool_run.add_argument("--proxy-url", required=True, help="local request-aware egress proxy URL")
    tool_run.add_argument("--approval-id", help="explicit approval identifier for active tool actions")
    tool_run.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")

    proxy = commands.add_parser("proxy", help="start the local request-aware egress proxy")
    proxy_commands = proxy.add_subparsers(dest="proxy_command", required=True)
    proxy_start = proxy_commands.add_parser("start", help="run in the foreground on loopback")
    proxy_start.add_argument("--config", required=True)
    proxy_start.add_argument("--host", default="127.0.0.1")
    proxy_start.add_argument("--port", type=int, default=0)
    proxy_start.add_argument("--approval-id", action="append", default=[])
    proxy_start.add_argument("--auth-profile", help="declared auth profile applied to proxied requests")
    proxy_start.add_argument("--evidence-dir", help="local evidence directory (default: evidence/<engagement_id>)")

    return parser


def _cmd_scope_validate(args: argparse.Namespace) -> int:
    config = _load(args.config)
    print(json.dumps({"valid": True, "engagement_id": config.engagement_id, "policy_hash": config.policy_hash}, indent=2))
    return 0


def _cmd_scope_check(args: argparse.Namespace) -> int:
    config = _load(args.config)
    decision = config.check_url(args.url, args.method)
    print(json.dumps({
        "allowed": decision.allowed,
        "reason": decision.reason,
        "target": decision.target,
        "method": decision.method,
        "policy_hash": decision.policy_hash,
    }, indent=2))
    return 0 if decision.allowed else 2


def _cmd_policy(args: argparse.Namespace) -> int:
    config = _load(args.config)
    print(json.dumps({"policy_hash": config.policy_hash, "config": config.to_dict()}, indent=2))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    config = _load(args.config)
    if not args.dry_run:
        print(
            "execution blocked: the general orchestrator is not enabled yet; "
            "use http request, active probe, browser inspect, or a proxied tool adapter",
            file=sys.stderr,
        )
        return 3

    gateway = ToolGateway(config)
    origin = config.allowed_origins[0]
    port = origin.ports[0]
    path = origin.path_prefixes[0] if origin.path_prefixes else "/"
    sample_target = f"{origin.scheme}://{origin.host}:{port}{path}"
    sample_action = ActionRequest(
        action_id="dry-run-001",
        tool="future.http",
        target=sample_target,
        method="GET",
        risk=RiskLevel.READ_ONLY,
        purpose="display bounded execution plan",
    )
    receipt = gateway.dry_run(sample_action)
    print(json.dumps({
        "dry_run": True,
        "engagement_id": config.engagement_id,
        "policy_hash": config.policy_hash,
        "authorized_origins": len(config.allowed_origins),
        "request_budget": config.limits.max_requests,
        "first_action_approval": receipt.approval_allowed,
        "first_rate_decision": {
            "ready": receipt.rate_ready,
            "wait_seconds": receipt.rate_wait_seconds,
            "reason": receipt.rate_reason,
            "request_count": receipt.request_count,
        },
        "network_executed": False,
    }, indent=2))
    return 0


def _cmd_llm_health(args: argparse.Namespace) -> int:
    client = OllamaClient(OllamaConfig.from_env(model_override=args.model))
    models = client.list_models()
    print(json.dumps({
        "provider": "ollama",
        "base_url": client.config.base_url,
        "configured_model": client.config.model,
        "models": models,
        "configured_model_available": client.config.model in models,
    }, indent=2))
    return 0 if client.config.model in models else 1


def _cmd_plan(args: argparse.Namespace) -> int:
    config = _load(args.config)
    try:
        observation = Path(args.observation).read_text(encoding="utf-8")[:16_001]
    except OSError as exc:
        raise ConfigError(f"cannot read observation file: {exc}") from exc
    if len(observation) > 16_000:
        raise ConfigError("observation file exceeds the 16,000 character planning limit")
    planner = OllamaPlanner(OllamaClient(OllamaConfig.from_env(model_override=args.model)))
    proposal = planner.plan(config, observation)
    print(json.dumps(proposal.to_dict(), indent=2))
    return 0


def _cmd_http_request(args: argparse.Namespace) -> int:
    config = _load(args.config)
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    evidence_store = EvidenceStore(evidence_dir)
    gateway = ToolGateway(
        config,
        receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"),
        approved_approval_ids={args.approval_id} if args.approval_id else None,
    )
    map_store = ApplicationMapStore(evidence_dir / "application_map.json")
    executor = HttpExecutor(
        config,
        gateway,
        evidence_store,
        map_store,
        timeout_seconds=args.timeout,
        max_body_bytes=args.max_body_bytes,
        capture_body=args.capture_body,
    )
    body = None
    if args.body_file:
        body = _read_bounded_bytes(
            args.body_file,
            config.active_testing.max_payload_bytes,
            "request body",
        )
    request_headers = {"Content-Type": args.content_type} if body else None
    observation = executor.execute(
        args.url,
        method=args.method,
        auth_profile=args.profile,
        body=body,
        request_headers=request_headers,
        approval_id=args.approval_id,
        purpose=args.purpose,
    )
    response = observation.response
    print(json.dumps({
        "executed": True,
        "engagement_id": config.engagement_id,
        "policy_hash": config.policy_hash,
        "action_id": observation.action_id,
        "evidence_id": observation.evidence_id,
        "endpoint_id": observation.endpoint_id,
        "auth_profile": observation.auth_profile,
        "request": {"method": response.method, "url": redact_url(args.url)},
        "response": {
            "status": response.status,
            "reason": response.reason,
            "body_length": len(response.body),
            "body_truncated": response.body_truncated,
            "elapsed_ms": response.elapsed_ms,
        },
        "evidence_dir": str(evidence_dir),
        "network_executed": True,
    }, indent=2))
    return 0


def _cmd_authz_compare(args: argparse.Namespace) -> int:
    config = _load(args.config)
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    evidence_store = EvidenceStore(evidence_dir)
    gateway = ToolGateway(config, receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"))
    map_store = ApplicationMapStore(evidence_dir / "application_map.json")
    executor = HttpExecutor(
        config,
        gateway,
        evidence_store,
        map_store,
        timeout_seconds=args.timeout,
        max_body_bytes=args.max_body_bytes,
        capture_body=True,
    )
    result = AuthorizationValidator(
        executor,
        evidence_store,
        report_dir=evidence_dir / "reports",
    ).compare(
        args.url,
        owner_profile=args.owner_profile,
        subject_profile=args.subject_profile,
        impact_fields={field.strip() for field in args.impact_field if field.strip()},
    )
    print(json.dumps(result.to_dict(), indent=2))
    return {"verified": 0, "candidate": 1, "rejected": 2}[result.status]


def _cmd_investigate(args: argparse.Namespace) -> int:
    config = _load(args.config)
    try:
        observation = Path(args.observation).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read observation file: {exc}") from exc
    if len(observation) > 16_000:
        raise ConfigError("observation file exceeds the 16,000 character planning limit")

    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    evidence_store = EvidenceStore(evidence_dir)
    gateway = ToolGateway(config, receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"))
    state_store = InvestigationStateStore(
        Path(args.state_file) if args.state_file else evidence_dir / "investigation.json",
        config,
    )
    executor = HttpExecutor(
        config,
        gateway,
        evidence_store,
        ApplicationMapStore(evidence_dir / "application_map.json"),
        timeout_seconds=args.timeout,
        max_body_bytes=args.max_body_bytes,
        capture_body=True,
    )
    result = ReasoningLoop(
        OllamaPlanner(OllamaClient(OllamaConfig.from_env(model_override=args.model))),
        AuthorizationValidator(executor, evidence_store, evidence_dir / "reports"),
    ).run_many(
        config,
        observation,
        url=args.url,
        owner_profile=args.owner_profile,
        subject_profile=args.subject_profile,
        impact_fields={field.strip() for field in args.impact_field if field.strip()},
        max_steps=args.max_steps,
        state_store=state_store,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return {"verified": 0, "candidate": 1, "rejected": 2, "planned": 1}[result.status]


def _cmd_active_probe(args: argparse.Namespace) -> int:
    config = _load(args.config)
    body_template = _read_bounded_text(
        args.body_template_file,
        config.active_testing.max_payload_bytes,
        "active probe body template",
    )
    payload_file_limit = min(
        16 * 1024 * 1024,
        config.active_testing.max_payload_bytes * config.active_testing.max_cases
        + config.active_testing.max_cases,
    )
    payload_lines = _read_bounded_text(
        args.payload_file,
        payload_file_limit,
        "active probe payload file",
    ).splitlines()
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    evidence_store = EvidenceStore(evidence_dir)
    gateway = ToolGateway(
        config,
        receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"),
        approved_approval_ids={args.approval_id} if args.approval_id else None,
    )
    executor = HttpExecutor(
        config,
        gateway,
        evidence_store,
        ApplicationMapStore(evidence_dir / "application_map.json"),
        timeout_seconds=args.timeout,
        max_body_bytes=args.max_body_bytes,
        capture_body=True,
    )
    result = ActiveProbeEngine(config, executor).run(
        args.url,
        method=args.method,
        body_template=body_template,
        payloads=payload_lines,
        auth_profile=args.profile,
        approval_id=args.approval_id,
        content_type=args.content_type,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def _cmd_browser_inspect(args: argparse.Namespace) -> int:
    config = _load(args.config)
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    evidence_store = EvidenceStore(evidence_dir)
    gateway = ToolGateway(config, receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"))
    executor = PlaywrightBrowserExecutor(
        config,
        gateway,
        evidence_store,
        ApplicationMapStore(evidence_dir / "application_map.json"),
        timeout_seconds=args.timeout,
    )
    result = asyncio.run(executor.inspect(args.url, auth_profile=args.profile, wait_until=args.wait_until))
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.error is None else 1


def _cmd_tools_list(_args: argparse.Namespace) -> int:
    print(json.dumps({"tools": ToolRegistry().list()}, indent=2))
    return 0


def _tool_runner(args: argparse.Namespace) -> DeterministicToolRunner:
    config = _load(args.config)
    evidence_dir = Path(args.evidence_dir) if getattr(args, "evidence_dir", None) else Path("evidence") / config.engagement_id
    return DeterministicToolRunner(
        config,
        ToolGateway(
            config,
            receipt_logger=ReceiptLogger(evidence_dir / "receipts.jsonl"),
            approved_approval_ids={args.approval_id} if getattr(args, "approval_id", None) else None,
        ),
        EvidenceStore(evidence_dir),
    )


def _cmd_tools_plan(args: argparse.Namespace) -> int:
    runner = _tool_runner(args)
    print(json.dumps(runner.plan(args.tool, args.target, args.proxy_url).to_dict(), indent=2))
    return 0


def _cmd_tools_run(args: argparse.Namespace) -> int:
    runner = _tool_runner(args)
    print(json.dumps(
        runner.run(args.tool, args.target, proxy_url=args.proxy_url, approval_id=args.approval_id).to_dict(),
        indent=2,
    ))
    return 0


def _cmd_proxy_start(args: argparse.Namespace) -> int:
    config = _load(args.config)
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else Path("evidence") / config.engagement_id
    server = EgressProxyServer(
        config,
        str(evidence_dir),
        host=args.host,
        port=args.port,
        approved_approval_ids=set(args.approval_id),
        default_approval_id=args.approval_id[0] if args.approval_id else None,
        default_auth_profile=args.auth_profile,
    )
    address = server.address
    print(json.dumps({
        "proxy": f"http://{address.host}:{address.port}",
        "engagement_id": config.engagement_id,
        "policy_hash": config.policy_hash,
        "https_connect": "disabled",
        "default_auth_profile": args.auth_profile,
        "default_approval_configured": bool(args.approval_id),
        "evidence_dir": str(evidence_dir),
        "message": "press Ctrl-C to stop",
    }, indent=2), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_banner:
        _print_banner()
    try:
        if args.command == "init":
            write_template(args.output)
            print(f"created non-secret engagement template: {args.output}")
            return 0
        if args.command == "scope" and args.scope_command == "validate":
            return _cmd_scope_validate(args)
        if args.command == "scope" and args.scope_command == "check":
            return _cmd_scope_check(args)
        if args.command == "policy":
            return _cmd_policy(args)
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "llm" and args.llm_command == "health":
            return _cmd_llm_health(args)
        if args.command == "plan":
            return _cmd_plan(args)
        if args.command == "http" and args.http_command == "request":
            return _cmd_http_request(args)
        if args.command == "authz" and args.authz_command == "compare":
            return _cmd_authz_compare(args)
        if args.command == "investigate":
            return _cmd_investigate(args)
        if args.command == "active" and args.active_command == "probe":
            return _cmd_active_probe(args)
        if args.command == "browser" and args.browser_command == "inspect":
            return _cmd_browser_inspect(args)
        if args.command == "tools" and args.tools_command == "list":
            return _cmd_tools_list(args)
        if args.command == "tools" and args.tools_command == "plan":
            return _cmd_tools_plan(args)
        if args.command == "tools" and args.tools_command == "run":
            return _cmd_tools_run(args)
        if args.command == "proxy" and args.proxy_command == "start":
            return _cmd_proxy_start(args)
    except (
        ConfigError,
        FileExistsError,
        GatewayBlocked,
        HttpExecutorError,
        ActiveProbeError,
        BrowserExecutorError,
        EgressProxyError,
        ToolExecutionBlocked,
        KillSwitchTripped,
        OllamaError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
