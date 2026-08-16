from __future__ import annotations

import pytest

from agentsec.models import ConfigError, EngagementConfig


def config_dict() -> dict:
    return {
        "engagement_id": "eng-test",
        "authorization": {"artifact_id": "auth-test"},
        "allowed_origins": [
            {
                "scheme": "https",
                "host": "authorized.example.com",
                "ports": [443],
                "path_prefixes": ["/api"],
                "methods": ["GET", "POST"],
            }
        ],
        "excluded_hosts": ["excluded.example.com"],
        "auth_profiles": ["owner", "non-owner"],
        "limits": {"requests_per_second": 2, "max_requests": 3, "max_concurrent_requests": 1, "max_cost_usd": 1},
        "actions": {"read_only": True, "state_mutation": False, "destructive": False},
    }


def test_scope_allows_exact_origin_path_and_method() -> None:
    config = EngagementConfig.from_dict(config_dict())
    decision = config.check_url("https://authorized.example.com/api/orders/1", "GET")
    assert decision.allowed is True
    assert decision.policy_hash == config.policy_hash


def test_scope_rejects_path_prefix_boundary_bypass() -> None:
    config = EngagementConfig.from_dict(config_dict())
    decision = config.check_url("https://authorized.example.com/apiv2/orders", "GET")
    assert decision.allowed is False
    assert "path" in decision.reason


def test_scope_rejects_host_method_and_exclusion() -> None:
    config = EngagementConfig.from_dict(config_dict())
    assert config.check_url("https://outside.example.com/api", "GET").allowed is False
    assert config.check_url("https://authorized.example.com/api", "DELETE").allowed is False
    assert config.check_url("https://excluded.example.com/api", "GET").allowed is False


@pytest.mark.parametrize(
    "url",
    [
        "ftp://authorized.example.com/api",
        "https://user:pass@authorized.example.com/api",
        "https://authorized.example.com/api#fragment",
        "https://authorized.example.com:8443/api",
    ],
)
def test_scope_rejects_unsafe_url_shapes(url: str) -> None:
    config = EngagementConfig.from_dict(config_dict())
    assert config.check_url(url, "GET").allowed is False


def test_missing_authorization_or_scope_fails_closed() -> None:
    raw = config_dict()
    del raw["authorization"]
    with pytest.raises(ConfigError):
        EngagementConfig.from_dict(raw)

    raw = config_dict()
    raw["allowed_origins"] = []
    with pytest.raises(ConfigError):
        EngagementConfig.from_dict(raw)
