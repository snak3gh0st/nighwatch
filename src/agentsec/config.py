"""Helpers for creating and displaying engagement configurations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def template_config() -> dict[str, Any]:
    return {
        "engagement_id": "eng_local_001",
        "authorization": {
            "artifact_id": "replace-with-written-authorization-reference"
        },
        "allowed_origins": [
            {
                "scheme": "https",
                "host": "authorized.example.com",
                "ports": [443],
                "path_prefixes": ["/"],
                "methods": ["GET"]
            }
        ],
        "excluded_hosts": [],
        "auth_profiles": ["owner_user", "non_owner_user"],
        "limits": {
            "requests_per_second": 1.0,
            "max_requests": 100,
            "max_concurrent_requests": 1,
            "max_cost_usd": 1.0
        },
        "actions": {
            "read_only": True,
            "state_mutation": False,
            "destructive": False
        }
    }


def write_template(path: str | Path) -> None:
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {target}")
    target.write_text(json.dumps(template_config(), indent=2) + "\n", encoding="utf-8")
