from __future__ import annotations

import json

from agentsec.cli import main


def test_cli_init_and_scope_validation(tmp_path, capsys) -> None:
    config_path = tmp_path / "engagement.json"
    assert main(["init", "--output", str(config_path)]) == 0
    assert config_path.exists()

    assert main(["scope", "validate", "--config", str(config_path)]) == 0
    output = capsys.readouterr().out
    assert '"valid": true' in output


def test_cli_run_requires_dry_run(tmp_path, capsys) -> None:
    config_path = tmp_path / "engagement.json"
    assert main(["init", "--output", str(config_path)]) == 0
    assert main(["run", "--config", str(config_path)]) == 3
    assert "execution blocked" in capsys.readouterr().err


def test_cli_scope_check_returns_nonzero_for_out_of_scope(tmp_path, capsys) -> None:
    config_path = tmp_path / "engagement.json"
    assert main(["init", "--output", str(config_path)]) == 0
    capsys.readouterr()
    assert main([
        "scope", "check", "--config", str(config_path),
        "--url", "https://outside.example.com/",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["allowed"] is False


def test_cli_no_banner_flag_is_accepted(tmp_path, capsys) -> None:
    config_path = tmp_path / "engagement.json"
    assert main(["--no-banner", "init", "--output", str(config_path)]) == 0
    assert "NIGHTWATCH" not in capsys.readouterr().err
