"""Strict, fail-closed configuration loading for neon-guard-mcp."""

from __future__ import annotations

import json
import os
import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    ValidationError,
    field_validator,
)

DEFAULT_CONFIG_PATH = "neon-guard.json"
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ConnectionConfig(BaseModel):
    """Connection defaults used when minting branch connection strings."""

    model_config = ConfigDict(extra="forbid")

    default_database: str = Field(min_length=1)
    default_role: str = Field(min_length=1)
    pooled: bool = True


class GuardConfig(BaseModel):
    """Top-level guard policy. Strict + fail-closed: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    allowed_projects: list[str]
    branch_naming_prefix: str
    enforce_parent_branch: str
    branch_data_mode: Literal["schema-only", "full"] = "schema-only"
    branch_expiry_hours: PositiveInt | None = 24
    allow_branch_deletion: bool = False
    max_ai_branches: PositiveInt = 10
    connection: ConnectionConfig
    disabled_tools: list[str] = Field(default_factory=list)

    @field_validator("allowed_projects")
    @classmethod
    def _projects_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowed_projects must contain at least one project id")
        if any(not item for item in value):
            raise ValueError("allowed_projects entries must be non-empty strings")
        return value

    @field_validator("branch_naming_prefix")
    @classmethod
    def _prefix_format(cls, value: str) -> str:
        if not _PREFIX_RE.match(value):
            raise ValueError(
                "branch_naming_prefix must match ^[a-z0-9][a-z0-9-]*$"
            )
        return value

    @field_validator("enforce_parent_branch")
    @classmethod
    def _parent_non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("enforce_parent_branch must be a non-empty string")
        return value


class ConfigError(Exception):
    """Raised when configuration cannot be loaded or is invalid."""


def load_config(path: str | None = None) -> GuardConfig:
    """Load and validate guard config; fail closed on any problem.

    Path precedence: explicit arg, else NEON_GUARD_CONFIG env, else default.
    """
    resolved = path or os.environ.get("NEON_GUARD_CONFIG") or DEFAULT_CONFIG_PATH
    try:
        with open(resolved, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {resolved}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"config file is not valid JSON: {resolved}") from e
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ConfigError(f"config file could not be parsed: {resolved}") from e
    except OSError as e:
        raise ConfigError(f"could not read config file: {resolved}") from e
    try:
        return GuardConfig.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"invalid config: {e}") from e
