"""Config loading is strict and fails closed.

Bad or missing configuration must raise ConfigError and never silently widen
access (no permissive fallback).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from neon_guard_mcp.config import ConfigError, GuardConfig, load_config

VALID: dict[str, Any] = {
    "allowed_projects": ["proj-allowed"],
    "branch_naming_prefix": "ai-test-",
    "enforce_parent_branch": "main",
    "branch_data_mode": "schema-only",
    "branch_expiry_hours": 24,
    "allow_branch_deletion": False,
    "max_ai_branches": 10,
    "connection": {
        "default_database": "appdb",
        "default_role": "appuser",
        "pooled": True,
    },
    "disabled_tools": [],
}


def _write(tmp_path, data: Any) -> str:
    path = tmp_path / "neon-guard.json"
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return str(path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "does-not-exist.json"))


def test_invalid_json_raises(tmp_path):
    path = _write(tmp_path, "{ not valid json ")
    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_key_rejected(tmp_path):
    bad = {**VALID, "surprise": "value"}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


def test_empty_allowed_projects_rejected(tmp_path):
    bad = {**VALID, "allowed_projects": []}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


def test_empty_string_project_entry_rejected(tmp_path):
    bad = {**VALID, "allowed_projects": ["proj-allowed", ""]}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


@pytest.mark.parametrize("prefix", ["", "Ai-Test", "-leading-dash", "has_underscore", "UPPER"])
def test_invalid_prefix_rejected(tmp_path, prefix):
    bad = {**VALID, "branch_naming_prefix": prefix}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


def test_bad_data_mode_enum_rejected(tmp_path):
    bad = {**VALID, "branch_data_mode": "everything"}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


@pytest.mark.parametrize("value", [0, -1, -10])
def test_non_positive_max_ai_branches_rejected(tmp_path, value):
    bad = {**VALID, "max_ai_branches": value}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


def test_empty_enforce_parent_rejected(tmp_path):
    bad = {**VALID, "enforce_parent_branch": ""}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, bad))


def test_valid_config_loads_and_exposes_fields(tmp_path):
    cfg = load_config(_write(tmp_path, VALID))
    assert isinstance(cfg, GuardConfig)
    assert cfg.allowed_projects == ["proj-allowed"]
    assert cfg.branch_naming_prefix == "ai-test-"
    assert cfg.enforce_parent_branch == "main"
    assert cfg.branch_data_mode == "schema-only"
    assert cfg.branch_expiry_hours == 24
    assert cfg.allow_branch_deletion is False
    assert cfg.max_ai_branches == 10
    assert cfg.connection.default_database == "appdb"
    assert cfg.connection.default_role == "appuser"
    assert cfg.connection.pooled is True
    assert cfg.disabled_tools == []


def test_defaults_applied_for_optional_fields(tmp_path):
    minimal = {
        "allowed_projects": ["proj-allowed"],
        "branch_naming_prefix": "ai-test-",
        "enforce_parent_branch": "main",
        "connection": {"default_database": "appdb", "default_role": "appuser"},
    }
    cfg = load_config(_write(tmp_path, minimal))
    assert cfg.branch_data_mode == "schema-only"
    assert cfg.branch_expiry_hours == 24
    assert cfg.allow_branch_deletion is False
    assert cfg.max_ai_branches == 10
    assert cfg.connection.pooled is True
    assert cfg.disabled_tools == []


def test_env_path_precedence(tmp_path, monkeypatch):
    path = _write(tmp_path, VALID)
    monkeypatch.setenv("NEON_GUARD_CONFIG", path)
    cfg = load_config()
    assert cfg.allowed_projects == ["proj-allowed"]


def test_non_utf8_config_fails_closed(tmp_path):
    # A non-UTF-8 file must raise ConfigError, not an uncaught UnicodeDecodeError.
    path = tmp_path / "neon-guard.json"
    path.write_bytes(b'{"allowed_projects": ["\xff bad"]}')
    with pytest.raises(ConfigError):
        load_config(str(path))


def test_deeply_nested_config_fails_closed(tmp_path):
    # Pathological input (recursion/parse failure) must surface as ConfigError.
    path = tmp_path / "neon-guard.json"
    path.write_text("[" * 50000)
    with pytest.raises(ConfigError):
        load_config(str(path))
