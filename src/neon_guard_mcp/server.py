"""Guard core: a default-deny MCP proxy for safe Neon TEST branching.

Every authorization decision is made from SERVER-FETCHED branch metadata plus
this proxy's own provenance store — never from a caller-supplied string. The
branch-name prefix is a naming convention, NOT the trust boundary: a branch may
be operated on only if (a) this proxy created it, (b) it is neither the default
nor a protected branch, and (c) it is not the enforced parent branch.

The master NEON_API_KEY lives only in this process's environment and is never
exposed to the LLM. Only a small whitelist of safe tools is registered; every
destructive Neon endpoint without a tool is therefore unreachable.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from .config import ConfigError, GuardConfig, load_config
from .logging import get_logger, redact, setup_logging
from .neon_client import NeonAPIError, NeonClient
from .state import ProvenanceStore, StateError

log = get_logger(__name__)

_SUFFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_MAX_NAME_LEN = 63

# Bounds for the create-branch readiness poll (fail-open to ready=False, never hang).
_MAX_POLLS = 20
_MAX_WALL_SECONDS = 30.0
_POLL_INTERVAL = 1.5


def _guard_errors(
    fn: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Wrap a tool method so Neon/state failures become safe ToolErrors.

    NeonAPIError -> a redacted, status-prefixed ToolError (no secrets, no
    transport detail). StateError -> a generic internal-state ToolError.
    ToolError and any other exception pass through unchanged.
    """

    @wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except ToolError:
            raise
        except NeonAPIError as e:
            raise ToolError(
                redact(f"Neon API error ({e.status_code}): {e.message}")
            ) from None
        except StateError:
            raise ToolError("internal state error") from None

    return wrapper


class GuardedTools:
    """All MCP tool logic plus the guard helpers that gate every decision."""

    def __init__(
        self,
        config: GuardConfig,
        neon: NeonClient,
        state: ProvenanceStore,
    ) -> None:
        self._config = config
        self._neon = neon
        self._state = state
        # Serializes the cap-check -> create -> provenance-write critical section
        # so concurrent calls cannot both slip past max_ai_branches.
        self._create_lock = asyncio.Lock()

    # --- guard helpers (private) ------------------------------------------

    async def _branches(self, project_id: str) -> list[dict[str, Any]]:
        """Fetch the project's branches live from Neon (never cached)."""
        return await self._neon.list_branches(project_id)

    def _assert_project_allowed(self, project_id: str) -> None:
        """Deny any project id not on the configured allow-list."""
        if project_id not in self._config.allowed_projects:
            raise ToolError("project is not allowed")

    def _find_branch(
        self, branches: list[dict[str, Any]], branch_id: str
    ) -> dict[str, Any]:
        """Return the branch with the given id, or deny if absent.

        An empty/missing id is rejected up front so an id-equality guard can
        never match a live branch that itself lacks an "id" key.
        """
        if not branch_id:
            raise ToolError("branch not found")
        for branch in branches:
            if branch.get("id") == branch_id:
                return branch
        raise ToolError("branch not found")

    def _find_parent(self, branches: list[dict[str, Any]]) -> dict[str, Any]:
        """Resolve the enforced parent branch by name; fail closed on ambiguity."""
        matches = [
            b
            for b in branches
            if b.get("name") == self._config.enforce_parent_branch
        ]
        if len(matches) != 1:
            raise ToolError("enforced parent branch could not be resolved")
        return matches[0]

    def _assert_created_branch(
        self,
        project_id: str,
        branches: list[dict[str, Any]],
        branch: dict[str, Any],
    ) -> None:
        """Allow operation only on a guard-created, non-default, non-protected,
        non-parent branch. Every condition is derived from server metadata and
        provenance — never a caller string."""
        branch_id = branch.get("id")
        if (
            not self._state.contains(project_id, branch_id)
            or branch.get("default")
            or branch.get("protected")
            or branch_id == self._find_parent(branches)["id"]
        ):
            raise ToolError("branch is not managed by this proxy")

    def _build_full_name(self, name_suffix: str) -> str:
        """Validate the suffix and compose the full prefixed branch name.

        The suffix is NFKC-normalized then must match ^[a-z0-9][a-z0-9-]*$;
        a non-compliant suffix is REJECTED (not silently stripped). The final
        prefixed name must fit within Neon's 63-char branch-name limit.
        """
        norm = unicodedata.normalize("NFKC", name_suffix)
        if not _SUFFIX_RE.match(norm):
            raise ToolError(
                "name_suffix must match ^[a-z0-9][a-z0-9-]*$"
            )
        full = self._config.branch_naming_prefix + norm
        if len(full) > _MAX_NAME_LEN:
            raise ToolError("resulting branch name is too long")
        return full

    # --- tools ------------------------------------------------------------

    @_guard_errors
    async def list_safe_projects(self) -> list[dict[str, Any]]:
        """List the Neon projects this proxy is permitted to operate on.

        Returns each allowed project's id and name (the intersection of the
        configured allow-list with the projects visible to the API key).
        """
        allowed = set(self._config.allowed_projects)
        return [
            {"id": p.get("id"), "name": p.get("name")}
            for p in await self._neon.list_projects()
            if p.get("id") in allowed
        ]

    @_guard_errors
    async def list_safe_branches(self, project_id: str) -> list[dict[str, Any]]:
        """List branches of an allowed project with their guard provenance.

        Each entry reports id, name, parent_id, default, protected, and
        created_by_guard (whether this proxy created the branch).
        """
        self._assert_project_allowed(project_id)
        branches = await self._branches(project_id)
        return [
            {
                "id": b.get("id"),
                "name": b.get("name"),
                "parent_id": b.get("parent_id"),
                "default": b.get("default"),
                "protected": b.get("protected"),
                "created_by_guard": self._state.contains(
                    project_id, b.get("id")
                ),
            }
            for b in branches
        ]

    @_guard_errors
    async def create_test_branch(
        self, project_id: str, name_suffix: str
    ) -> dict[str, Any]:
        """Create an isolated TEST branch off the enforced parent branch.

        The branch name is the configured prefix plus the validated suffix.
        Data is schema-only or full per policy, and the branch may carry an
        expiry. Subject to the configured per-project branch cap. Returns the
        new branch id, name, readiness, parent name, data mode, and expiry.
        """
        self._assert_project_allowed(project_id)
        full_name = self._build_full_name(name_suffix)
        branches = await self._branches(project_id)
        parent = self._find_parent(branches)

        branch_body: dict[str, Any] = {
            "name": full_name,
            "parent_id": parent["id"],
        }
        if self._config.branch_data_mode == "schema-only":
            branch_body["init_source"] = "schema-only"
        if self._config.branch_expiry_hours:
            expires = datetime.now(timezone.utc) + timedelta(
                hours=self._config.branch_expiry_hours
            )
            branch_body["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")

        body = {
            "branch": branch_body,
            "endpoints": [{"type": "read_write"}],
        }

        # Critical section: enforce the cap, create, and record provenance
        # atomically so concurrent calls cannot exceed max_ai_branches.
        async with self._create_lock:
            if self._state.count(project_id) >= self._config.max_ai_branches:
                raise ToolError("branch limit reached for this project")
            if any(b.get("name") == full_name for b in branches):
                raise ToolError("a branch with this name already exists")
            result = await self._neon.create_branch(project_id, body)
            b = result["branch"]
            try:
                self._state.add(
                    project_id,
                    b["id"],
                    b["name"],
                    b.get("created_at", ""),
                    branch_body.get("expires_at"),
                )
            except StateError:
                # Provenance write failed: delete the branch rather than leave
                # it orphaned (unmanageable and outside the cap) in Neon.
                await self._safe_delete(project_id, b["id"])
                raise ToolError("internal state error") from None

        try:
            ready = await self._await_ready(
                project_id, result.get("operations", [])
            )
        except ToolError:
            # Creation operation failed/cancelled: drop provenance so the dead
            # branch can never be mistaken for a usable guard branch.
            try:
                self._state.remove(project_id, b["id"])
            except StateError:
                pass
            raise

        return {
            "branch_id": b["id"],
            "name": b["name"],
            "ready": ready,
            "parent": parent["name"],
            "data_mode": self._config.branch_data_mode,
            "expires_at": branch_body.get("expires_at"),
        }

    async def _safe_delete(self, project_id: str, branch_id: str) -> None:
        """Best-effort compensating delete; never raises (logs on failure)."""
        try:
            await self._neon.delete_branch(project_id, branch_id, hard_delete=False)
        except NeonAPIError:
            log.error(
                "could not clean up branch %s after a state failure", branch_id
            )

    async def _await_ready(
        self, project_id: str, operations: list[dict[str, Any]]
    ) -> bool:
        """Poll until the given operations finish, within a hard bound.

        Returns True once every tracked op is "finished"; raises ToolError if
        any op fails or is cancelled; returns False if the poll budget (max
        polls or wall-clock seconds) is exhausted while still pending.
        """
        op_ids = {op["id"] for op in operations if "id" in op}
        if not op_ids:
            return True

        deadline = time.monotonic() + _MAX_WALL_SECONDS
        for _ in range(_MAX_POLLS):
            current = await self._neon.list_operations(project_id)
            statuses = {
                op["id"]: op.get("status")
                for op in current
                if op.get("id") in op_ids
            }
            if any(
                statuses.get(oid) in {"failed", "cancelled"} for oid in op_ids
            ):
                raise ToolError("branch creation operation failed")
            if all(statuses.get(oid) == "finished" for oid in op_ids):
                return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(_POLL_INTERVAL)
        return False

    @_guard_errors
    async def get_branch_connection_string(
        self, project_id: str, branch_id: str
    ) -> dict[str, Any]:
        """Mint a connection URI for a guard-created TEST branch.

        Only branches this proxy created (and which are not the default,
        protected, or enforced-parent branch) are eligible. The returned URI
        embeds a live password and is never logged.
        """
        self._assert_project_allowed(project_id)
        branches = await self._branches(project_id)
        branch = self._find_branch(branches, branch_id)
        self._assert_created_branch(project_id, branches, branch)
        uri = await self._neon.get_connection_uri(
            project_id,
            branch_id=branch_id,
            database_name=self._config.connection.default_database,
            role_name=self._config.connection.default_role,
            pooled=self._config.connection.pooled,
        )
        return {"connection_uri": uri}

    @_guard_errors
    async def get_branch_status(
        self, project_id: str, branch_id: str
    ) -> dict[str, Any]:
        """Report the live state and guard provenance of one branch.

        Returns the branch id, name, current_state, and whether this proxy
        created it.
        """
        self._assert_project_allowed(project_id)
        branches = await self._branches(project_id)
        branch = self._find_branch(branches, branch_id)
        return {
            "id": branch["id"],
            "name": branch["name"],
            "current_state": branch.get("current_state"),
            "created_by_guard": self._state.contains(project_id, branch_id),
        }

    @_guard_errors
    async def delete_test_branch(
        self, project_id: str, branch_id: str
    ) -> dict[str, Any]:
        """Soft-delete a guard-created TEST branch that has no child branches.

        Only branches this proxy created (and which are not the default,
        protected, or enforced-parent branch) may be deleted.
        """
        self._assert_project_allowed(project_id)
        branches = await self._branches(project_id)
        branch = self._find_branch(branches, branch_id)
        self._assert_created_branch(project_id, branches, branch)
        if any(b.get("parent_id") == branch_id for b in branches):
            raise ToolError("branch has child branches")
        await self._neon.delete_branch(project_id, branch_id, hard_delete=False)
        self._state.remove(project_id, branch_id)
        return {"deleted": branch_id}

    @_guard_errors
    async def reset_test_branch(
        self, project_id: str, branch_id: str
    ) -> dict[str, Any]:
        """Reset a guard-created TEST branch to the state of its parent.

        Only branches this proxy created (and which are not the default,
        protected, or enforced-parent branch) may be reset.
        """
        self._assert_project_allowed(project_id)
        branches = await self._branches(project_id)
        branch = self._find_branch(branches, branch_id)
        self._assert_created_branch(project_id, branches, branch)
        parent_id = branch.get("parent_id")
        if not parent_id:
            raise ToolError("branch has no parent to reset from")
        await self._neon.restore_branch(
            project_id, branch_id, {"source_branch_id": parent_id}
        )
        return {"reset": branch_id, "restored_from": parent_id}


def build_app(
    config: GuardConfig, neon: NeonClient, state: ProvenanceStore
) -> FastMCP:
    """Build the FastMCP app, registering only the enabled, allowed tools.

    Always-on tools are read-only or strictly scoped to guard-created
    branches. Branch deletion/reset tools are registered only when policy
    explicitly opts in. Any tool named in config.disabled_tools is skipped,
    so a destructive endpoint without a registered tool is unreachable.
    """
    mcp = FastMCP(name="neon-guard", mask_error_details=True)
    tools = GuardedTools(config, neon, state)

    registry: dict[str, Callable[..., Awaitable[Any]]] = {
        "list_safe_projects": tools.list_safe_projects,
        "list_safe_branches": tools.list_safe_branches,
        "create_test_branch": tools.create_test_branch,
        "get_branch_connection_string": tools.get_branch_connection_string,
        "get_branch_status": tools.get_branch_status,
    }
    if config.allow_branch_deletion:
        registry["delete_test_branch"] = tools.delete_test_branch
        registry["reset_test_branch"] = tools.reset_test_branch

    for name, fn in registry.items():
        if name in config.disabled_tools:
            log.info("tool %s is disabled by config", name)
            continue
        mcp.tool(fn, name=name)
    return mcp


def main() -> None:
    """Entry point: load config + key, then serve the guard over stdio.

    Fails CLOSED: if config is invalid or NEON_API_KEY is unset, the proxy
    starts with NO tools rather than widening access. The error is logged
    (redacted) to stderr; stdout stays a clean JSON-RPC channel.
    """
    setup_logging()
    try:
        config = load_config()
        api_key = os.environ.get("NEON_API_KEY")
        if not api_key:
            raise ConfigError("NEON_API_KEY environment variable is not set")
    except Exception as e:  # noqa: BLE001 - any startup failure must fail CLOSED
        # Serve a tool-less server rather than crash or widen access. The error
        # is logged (redacted) to stderr; stdout stays a clean JSON-RPC channel.
        log.error("neon-guard starting with NO tools: %s", e)
        FastMCP(name="neon-guard").run(transport="stdio", show_banner=False)
        return

    neon = NeonClient(api_key)
    state = ProvenanceStore()
    build_app(config, neon, state).run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
