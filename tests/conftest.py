"""Shared fixtures for the neon-guard test suite.

Everything here is pure and offline: a FakeNeon stands in for NeonClient so no
test ever opens a socket or reaches the real Neon API. The FakeNeon mirrors the
async method surface of NeonClient and records calls for assertions.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from neon_guard_mcp.config import ConnectionConfig, GuardConfig
from neon_guard_mcp.server import GuardedTools
from neon_guard_mcp.state import ProvenanceStore

PROJECT_ID = "proj-allowed"
PARENT_NAME = "main"
PREFIX = "ai-test-"


def _main_branch() -> dict[str, Any]:
    """The protected, default production branch (never guard-touchable)."""
    return {
        "id": "br-main",
        "name": PARENT_NAME,
        "parent_id": None,
        "default": True,
        "protected": True,
        "current_state": "ready",
        "created_at": "2026-01-01T00:00:00Z",
    }


class FakeNeon:
    """In-memory stand-in for NeonClient.

    Constructed with seed branch + project dicts. Holds them in mutable lists
    so guard helpers observe live server metadata. Records create/delete/restore
    calls so tests can assert exactly what hit the (fake) API.
    """

    def __init__(
        self,
        branches: list[dict[str, Any]] | None = None,
        projects: list[dict[str, Any]] | None = None,
        create_operations: list[dict[str, Any]] | None = None,
        op_responses: list[list[dict[str, Any]]] | None = None,
    ) -> None:
        self.branches: list[dict[str, Any]] = copy.deepcopy(branches or [])
        self.projects: list[dict[str, Any]] = copy.deepcopy(
            projects
            if projects is not None
            else [{"id": PROJECT_ID, "name": "Allowed Project"}]
        )
        self.created: list[dict[str, Any]] = []
        self.deleted: list[tuple[str, str, bool]] = []
        self.restored: list[tuple[str, str, dict[str, Any]]] = []
        self.connection_calls: list[dict[str, Any]] = []
        self._new_counter = 0
        # Operations attached to a create_branch response, and a queue of
        # successive list_operations responses (the last entry repeats). When
        # both are unset, branch creation reports no ops and is instantly ready.
        self._create_operations = create_operations or []
        self._op_responses = list(op_responses) if op_responses is not None else None
        self.op_calls = 0

    async def list_projects(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.projects)

    async def list_branches(self, project_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.branches)

    async def create_branch(
        self, project_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        self.created.append({"project_id": project_id, "body": copy.deepcopy(body)})
        branch_body = body["branch"]
        self._new_counter += 1
        new_id = "br-new" if self._new_counter == 1 else f"br-new-{self._new_counter}"
        branch = {
            "id": new_id,
            "name": branch_body["name"],
            "parent_id": branch_body["parent_id"],
            "default": False,
            "protected": False,
            "current_state": "ready",
            "created_at": "2026-06-20T00:00:00Z",
        }
        # Reflect the new branch into live server state so follow-up lookups see it.
        self.branches.append(copy.deepcopy(branch))
        return {"branch": branch, "operations": copy.deepcopy(self._create_operations)}

    async def get_connection_uri(
        self,
        project_id: str,
        *,
        branch_id: str,
        database_name: str,
        role_name: str,
        pooled: bool,
    ) -> str:
        self.connection_calls.append(
            {
                "project_id": project_id,
                "branch_id": branch_id,
                "database_name": database_name,
                "role_name": role_name,
                "pooled": pooled,
            }
        )
        return "postgresql://u:p@h/db"

    async def delete_branch(
        self, project_id: str, branch_id: str, hard_delete: bool = False
    ) -> dict[str, Any]:
        self.deleted.append((project_id, branch_id, hard_delete))
        self.branches = [b for b in self.branches if b["id"] != branch_id]
        return {}

    async def restore_branch(
        self, project_id: str, branch_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        self.restored.append((project_id, branch_id, copy.deepcopy(body)))
        return {}

    async def list_operations(self, project_id: str) -> list[dict[str, Any]]:
        self.op_calls += 1
        # Default: no ops -> _await_ready returns True immediately (no polling).
        if self._op_responses is None:
            return []
        # Drain the queue one response per poll; the final entry repeats so a
        # steady "running" state can drive the timeout path.
        if len(self._op_responses) > 1:
            return copy.deepcopy(self._op_responses.pop(0))
        return copy.deepcopy(self._op_responses[0]) if self._op_responses else []


@pytest.fixture
def fake_neon_cls() -> type[FakeNeon]:
    """Expose the FakeNeon class so tests can build bespoke instances."""
    return FakeNeon


@pytest.fixture
def connection_config() -> ConnectionConfig:
    return ConnectionConfig(default_database="appdb", default_role="appuser", pooled=True)


@pytest.fixture
def make_config(connection_config: ConnectionConfig):
    """Factory for a valid GuardConfig with overridable fields."""

    def _make(**overrides: Any) -> GuardConfig:
        base: dict[str, Any] = {
            "allowed_projects": [PROJECT_ID],
            "branch_naming_prefix": PREFIX,
            "enforce_parent_branch": PARENT_NAME,
            "branch_data_mode": "schema-only",
            "branch_expiry_hours": 24,
            "allow_branch_deletion": False,
            "max_ai_branches": 10,
            "connection": connection_config,
            "disabled_tools": [],
        }
        base.update(overrides)
        return GuardConfig.model_validate(base)

    return _make


@pytest.fixture
def config(make_config) -> GuardConfig:
    """A valid GuardConfig with branch deletion DISABLED (the secure default)."""
    return make_config()


@pytest.fixture
def store(tmp_path) -> ProvenanceStore:
    """A ProvenanceStore backed by a fresh file under tmp_path."""
    return ProvenanceStore(str(tmp_path / "state.json"))


@pytest.fixture
def main_branch() -> dict[str, Any]:
    return _main_branch()


@pytest.fixture
def fake(main_branch) -> FakeNeon:
    """A FakeNeon seeded with the protected main branch only."""
    return FakeNeon(branches=[main_branch])


@pytest.fixture
def make_tools(config, fake, store):
    """Build a GuardedTools, optionally swapping config/neon/store."""

    def _make(
        cfg: GuardConfig | None = None,
        neon: FakeNeon | None = None,
        prov: ProvenanceStore | None = None,
    ) -> GuardedTools:
        return GuardedTools(cfg or config, neon or fake, prov or store)

    return _make


@pytest.fixture
def tools(make_tools) -> GuardedTools:
    return make_tools()


@pytest.fixture
def register_guard_branch(fake, store):
    """Register a branch as guard-created: in provenance AND in live metadata.

    Returns the branch dict so the test can read its id/name.
    """

    def _register(suffix: str = "feature-x", branch_id: str = "br-guard") -> dict[str, Any]:
        name = PREFIX + suffix
        branch = {
            "id": branch_id,
            "name": name,
            "parent_id": "br-main",
            "default": False,
            "protected": False,
            "current_state": "ready",
            "created_at": "2026-06-20T00:00:00Z",
        }
        fake.branches.append(branch)
        store.add(PROJECT_ID, branch_id, name, "2026-06-20T00:00:00Z", None)
        return branch

    return _register
