"""Controlled Playwright inspection behind the Nighwatch execution gateway.

The browser adapter is intentionally observation-only. It can navigate to one
operator-supplied URL, inspect the rendered page, and observe network metadata.
It cannot click forms, submit state-changing requests, download files, grant
permissions, evaluate arbitrary model-supplied JavaScript, or follow a request
outside the effective scope.

Playwright is an optional dependency so the policy and HTTP layers remain
usable without browser binaries installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .evidence import EvidenceStore, redact_body_preview
from .gateway import ToolGateway
from .http_executor import _resolve_allowed_address, resolve_auth_headers
from .mapping import ApplicationMapStore
from .models import EngagementConfig, RiskLevel
from .security import ActionRequest, redact_url


class BrowserExecutorError(RuntimeError):
    """Raised when controlled browser inspection cannot be completed."""


@dataclass(frozen=True)
class BrowserObservation:
    action_id: str
    evidence_id: str
    endpoint_id: str | None
    auth_profile: str | None
    final_url: str
    status: int | None
    title: str | None
    request_count: int
    blocked_count: int
    cookies: tuple[dict[str, Any], ...]
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "evidence_id": self.evidence_id,
            "endpoint_id": self.endpoint_id,
            "auth_profile": self.auth_profile,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title,
            "request_count": self.request_count,
            "blocked_count": self.blocked_count,
            "cookies": list(self.cookies),
            "error": self.error,
        }


def _safe_error(exc: BaseException) -> str:
    cleaned = re.sub(r"[\\r\\n]+", " ", str(exc))
    return f"{type(exc).__name__}: {cleaned[:300]}"


def _cookie_metadata(cookie: Mapping[str, Any]) -> dict[str, Any]:
    """Keep cookie identity and flags, never cookie values."""
    return {
        "name": str(cookie.get("name", ""))[:120],
        "domain": str(cookie.get("domain", ""))[:255],
        "path": str(cookie.get("path", ""))[:255],
        "secure": bool(cookie.get("secure", False)),
        "http_only": bool(cookie.get("httpOnly", False)),
        "same_site": cookie.get("sameSite"),
    }


class PlaywrightBrowserExecutor:
    """Inspect one authorized page with all browser requests policy-gated."""

    def __init__(
        self,
        config: EngagementConfig,
        gateway: ToolGateway,
        evidence_store: EvidenceStore,
        map_store: ApplicationMapStore | None = None,
        *,
        explicit_profiles: Mapping[str, Mapping[str, str]] | None = None,
        timeout_seconds: float = 30.0,
        max_text_bytes: int = 32_768,
        max_network_records: int = 200,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("timeout_seconds must be between 0 and 120")
        if max_text_bytes <= 0 or max_text_bytes > 1_048_576:
            raise ValueError("max_text_bytes must be between 1 and 1048576")
        if max_network_records <= 0 or max_network_records > 1_000:
            raise ValueError("max_network_records must be between 1 and 1000")
        self.config = config
        self.gateway = gateway
        self.evidence_store = evidence_store
        self.map_store = map_store
        self.explicit_profiles = explicit_profiles
        self.timeout_seconds = timeout_seconds
        self.max_text_bytes = max_text_bytes
        self.max_network_records = max_network_records

    def validate_target(self, url: str) -> None:
        """Perform pure scope plus DNS-address checks before importing Playwright."""
        decision = self.config.check_url(url, "GET")
        if not decision.allowed:
            raise BrowserExecutorError(f"browser target blocked: {decision.reason}")
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        try:
            _resolve_allowed_address(host, port, self.config.allow_private_addresses)
        except Exception as exc:
            raise BrowserExecutorError(f"browser DNS/address check failed: {exc}") from exc

    @staticmethod
    def _load_playwright() -> Any:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserExecutorError(
                "Playwright is optional; install with `python -m pip install 'nighwatch[browser]'` "
                "and run `playwright install chromium`"
            ) from exc
        return async_playwright

    async def inspect(
        self,
        url: str,
        *,
        auth_profile: str | None = None,
        wait_until: str = "domcontentloaded",
    ) -> BrowserObservation:
        self.validate_target(url)
        if wait_until not in {"commit", "domcontentloaded", "load", "networkidle"}:
            raise BrowserExecutorError("unsupported browser wait_until value")

        auth_headers = resolve_auth_headers(self.config, auth_profile, self.explicit_profiles)
        async_playwright = self._load_playwright()
        root_origin = self._origin(url)
        action_id = f"act_{uuid.uuid4().hex}"
        request_records: list[dict[str, Any]] = []
        blocked_records: list[dict[str, Any]] = []
        action_ids: list[str] = []
        response_status: int | None = None
        final_url = redact_url(url)
        title: str | None = None
        body_preview: str | None = None
        body_hash = hashlib.sha256(b"").hexdigest()
        body_truncated = False
        cookies: tuple[dict[str, Any], ...] = ()
        endpoint_id: str | None = None
        error: str | None = None
        playwright = browser = context = page = None

        async def handle_route(route: Any) -> None:
            request = route.request
            target = request.url
            method = str(request.method).upper()
            risk = RiskLevel.READ_ONLY if method in {"GET", "HEAD"} else RiskLevel.STATE_CHANGE
            nested_action_id = f"act_{uuid.uuid4().hex}"
            nested = ActionRequest(
                action_id=nested_action_id,
                tool="nighwatch.browser",
                target=target,
                method=method,
                risk=risk,
                purpose="controlled browser observation",
            )
            action_ids.append(nested_action_id)
            while True:
                decision = self.gateway.authorize(nested)
                if decision.ready:
                    break
                if decision.rate.allowed and decision.rate.wait_seconds > 0:
                    if decision.rate.wait_seconds > 60:
                        blocked_records.append({"url": redact_url(target), "reason": "unsafe rate wait"})
                        self.gateway.record_decision(nested, decision)
                        try:
                            await route.abort("blockedbyclient")
                        except Exception:
                            pass
                        return
                    await asyncio.sleep(decision.rate.wait_seconds)
                    continue
                self.gateway.record_decision(nested, decision)
                blocked_records.append({
                    "url": redact_url(target),
                    "method": method,
                    "reason": decision.reason[:240],
                })
                try:
                    await route.abort("blockedbyclient")
                except Exception:
                    pass
                return

            self.gateway.record_decision(nested, decision)
            try:
                parsed = urlsplit(target)
                target_origin = self._origin(target)
                if target_origin != root_origin:
                    # The scope guard may contain several explicitly authorized
                    # origins, but credentials are only attached to the operator's
                    # selected origin.
                    request_headers = dict(await request.all_headers())
                else:
                    request_headers = dict(await request.all_headers())
                    request_headers.update(auth_headers)
                _resolve_allowed_address(
                    parsed.hostname or "",
                    parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                    self.config.allow_private_addresses,
                )
                if len(request_records) < self.max_network_records:
                    request_records.append({
                        "action_id": nested_action_id,
                        "method": method,
                        "url": redact_url(target),
                        "resource_type": str(request.resource_type),
                        "allowed": True,
                    })
                await route.continue_(headers=request_headers)
            except Exception as exc:
                if len(blocked_records) < self.max_network_records:
                    blocked_records.append({
                        "url": redact_url(target),
                        "method": method,
                        "reason": _safe_error(exc),
                    })
                try:
                    await route.abort("blockedbyclient")
                except Exception:
                    pass

        def handle_response(response: Any) -> None:
            if len(request_records) >= self.max_network_records:
                return
            try:
                request = response.request
                request_records.append({
                    "action_id": None,
                    "method": str(request.method).upper(),
                    "url": redact_url(response.url),
                    "resource_type": str(request.resource_type),
                    "status": int(response.status),
                    "allowed": True,
                })
            except Exception:
                return

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                accept_downloads=False,
                ignore_https_errors=False,
                service_workers="block",
            )
            await context.route("**/*", handle_route)
            page = await context.new_page()
            page.on("response", handle_response)
            response = await page.goto(
                url,
                wait_until=wait_until,
                timeout=int(self.timeout_seconds * 1000),
            )
            if response is not None:
                response_status = int(response.status)
            final_url = redact_url(page.url or url)
            title = await page.title()
            try:
                body_text = await page.locator("body").inner_text(timeout=int(self.timeout_seconds * 1000))
            except Exception:
                body_text = ""
            body_bytes = body_text.encode("utf-8", errors="replace")
            body_hash = hashlib.sha256(body_bytes).hexdigest()
            body_preview, body_truncated = redact_body_preview(body_bytes, self.max_text_bytes)
            try:
                cookies = tuple(_cookie_metadata(cookie) for cookie in await context.cookies([url]))
            except Exception:
                cookies = ()
        except Exception as exc:
            error = _safe_error(exc)
        finally:
            if context is not None:
                try:
                    cookies = tuple(_cookie_metadata(cookie) for cookie in await context.cookies([url]))
                except Exception:
                    pass
            for resource in (page, context, browser):
                if resource is not None:
                    try:
                        await resource.close()
                    except Exception:
                        pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except Exception:
                    pass

        evidence = self.evidence_store.append(
            "browser_observation",
            {
                "engagement_id": self.config.engagement_id,
                "policy_hash": self.config.policy_hash,
                "action_id": action_id,
                "auth_profile": auth_profile,
                "request_count": len(action_ids),
                "blocked_count": len(blocked_records),
                "requests": request_records[: self.max_network_records],
                "blocked_requests": blocked_records[: self.max_network_records],
                "page": {
                    "url": redact_url(url),
                    "final_url": final_url,
                    "status": response_status,
                    "title": title,
                    "body_sha256": body_hash,
                    "body_preview": body_preview,
                    "body_preview_truncated": body_truncated,
                },
                "cookies": list(cookies),
                "action_ids": action_ids[: self.max_network_records],
                "error": error,
            },
        )
        if self.map_store is not None:
            endpoint_id = self.map_store.observe(
                method="GET",
                url=url,
                auth_profile=auth_profile,
                status=response_status or 0,
                response_body=(body_preview or "").encode("utf-8"),
                evidence_id=str(evidence["evidence_id"]),
            )
        return BrowserObservation(
            action_id=action_id,
            evidence_id=str(evidence["evidence_id"]),
            endpoint_id=endpoint_id,
            auth_profile=auth_profile,
            final_url=final_url,
            status=response_status,
            title=title,
            request_count=len(action_ids),
            blocked_count=len(blocked_records),
            cookies=cookies,
            error=error,
        )

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}://{host}:{port}"
