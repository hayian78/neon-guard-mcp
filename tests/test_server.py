"""The security core: provenance-gated authorization and fail-closed guards.

These tests encode the attacker model. The branch-name prefix is NOT a trust
boundary: authorization to mint a connection string, delete, or reset is gated
by the provenance store AND live server metadata. Both must hold.
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from neon_guard_mcp.server import build_app

pytestmark = pytest.mark.asyncio

# Mirror the conftest constants locally (the tests package is importable as a
# package, so we keep these self-contained rather than reaching into conftest).
PROJECT_ID = "proj-allowed"
PARENT_NAME = "main"
PREFIX = "ai-test-"
OTHER_PROJECT = "proj-forbidden"


# --------------------------------------------------------------------------
# create_test_branch
# --------------------------------------------------------------------------

async def test_create_branch_prepends_prefix_and_forces_parent(tools, fake):
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")

    assert result["name"] == PREFIX + "feature-a"
    assert result["parent"] == PARENT_NAME
    assert result["data_mode"] == "schema-only"
    assert result["ready"] is True

    # The branch actually sent to Neon used the resolved parent's real id.
    body = fake.created[0]["body"]["branch"]
    assert body["name"] == PREFIX + "feature-a"
    assert body["parent_id"] == "br-main"


async def test_create_branch_records_provenance(tools, store):
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")
    assert store.contains(PROJECT_ID, result["branch_id"]) is True
    assert store.count(PROJECT_ID) == 1


async def test_create_branch_sets_schema_only_and_expiry(tools, fake):
    await tools.create_test_branch(PROJECT_ID, "feature-a")
    body = fake.created[0]["body"]["branch"]
    assert body["init_source"] == "schema-only"
    assert "expires_at" in body
    assert body["expires_at"].endswith("Z")


async def test_create_branch_full_mode_has_no_init_source(make_config, make_tools, fake_neon_cls):
    cfg = make_config(branch_data_mode="full")
    fake = fake_neon_cls(branches=[_main()])
    tools = make_tools(cfg=cfg, neon=fake)
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")
    body = fake.created[0]["body"]["branch"]
    assert "init_source" not in body
    assert result["data_mode"] == "full"


async def test_create_branch_no_expiry_when_disabled(make_config, make_tools, fake_neon_cls):
    cfg = make_config(branch_expiry_hours=None)
    fake = fake_neon_cls(branches=[_main()])
    tools = make_tools(cfg=cfg, neon=fake)
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")
    body = fake.created[0]["body"]["branch"]
    assert "expires_at" not in body
    assert result["expires_at"] is None


@pytest.mark.parametrize(
    "bad_suffix",
    [
        "Bad_Name",          # underscore + uppercase
        "",                  # empty
        "Has Space",         # space
        "UPPER",             # uppercase
        "-leading",          # leading dash
        "slash/inject",      # path separator
        "naïve",             # non-ascii (does not NFKC-fold to ascii)
        "аdmin",             # cyrillic homoglyph 'а' (stays non-ascii after NFKC)
        "tab\tchar",         # control character
        "semi;colon",        # punctuation
    ],
)
async def test_create_branch_rejects_noncompliant_suffix(tools, bad_suffix):
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, bad_suffix)


async def test_create_branch_allows_compliant_suffix_forms(tools, fake):
    # The suffix regex ^[a-z0-9][a-z0-9-]*$ permits internal/trailing dashes
    # and digits; these must be accepted (only non-conforming input is denied).
    await tools.create_test_branch(PROJECT_ID, "trailing-")
    await tools.create_test_branch(PROJECT_ID, "1numeric-start")
    names = {c["body"]["branch"]["name"] for c in fake.created}
    assert PREFIX + "trailing-" in names
    assert PREFIX + "1numeric-start" in names


async def test_create_branch_nfkc_folds_fullwidth_to_ascii(tools, fake):
    # Fullwidth digits/letters NFKC-fold to plain ascii, so the suffix becomes
    # compliant and the branch is created under the NORMALIZED (ascii) name —
    # never the raw fullwidth form, preventing visually-confusable duplicates.
    await tools.create_test_branch(PROJECT_ID, "ｆｕｌｌwidth")
    body = fake.created[0]["body"]["branch"]
    assert body["name"] == PREFIX + "fullwidth"


async def test_create_branch_homoglyph_does_not_impersonate(tools, fake):
    # A cyrillic 'а' must be rejected, never normalized into ascii 'admin'.
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "аdmin")
    assert fake.created == []


async def test_create_branch_enforces_max_ai_branches(make_config, make_tools, store, fake_neon_cls):
    cfg = make_config(max_ai_branches=2)
    fake = fake_neon_cls(branches=[_main()])
    tools = make_tools(cfg=cfg, neon=fake, prov=store)
    await tools.create_test_branch(PROJECT_ID, "one")
    await tools.create_test_branch(PROJECT_ID, "two")
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "three")
    assert store.count(PROJECT_ID) == 2


async def test_create_branch_rejects_overlong_name(make_config, make_tools, fake_neon_cls):
    cfg = make_config(branch_naming_prefix="ai-test-")
    fake = fake_neon_cls(branches=[_main()])
    tools = make_tools(cfg=cfg, neon=fake)
    long_suffix = "a" * 60  # prefix(8) + 60 = 68 > 63
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, long_suffix)


async def test_create_branch_rejects_duplicate_name(tools, fake):
    # Pre-seed a branch with the exact name the next create would produce.
    fake.branches.append(
        {
            "id": "br-dupe",
            "name": PREFIX + "feature-a",
            "parent_id": "br-main",
            "default": False,
            "protected": False,
        }
    )
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "feature-a")


# --------------------------------------------------------------------------
# ATTACK: get_branch_connection_string is provenance-gated
# --------------------------------------------------------------------------

async def test_conn_string_rejects_main_branch(tools):
    # main is default + protected and was NOT created by the proxy.
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "br-main")


async def test_conn_string_rejects_spoofed_prefix_branch(tools, fake):
    # An attacker creates a branch with the trusted prefix OUT OF BAND. It is
    # not in provenance, so it must be refused despite the "trusted" name.
    fake.branches.append(
        {
            "id": "br-spoof",
            "name": PREFIX + "totally-legit",
            "parent_id": "br-main",
            "default": False,
            "protected": False,
        }
    )
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "br-spoof")


async def test_conn_string_rejects_any_branch_not_in_provenance(tools, fake):
    fake.branches.append(
        {
            "id": "br-random",
            "name": "some-other-branch",
            "parent_id": "br-main",
            "default": False,
            "protected": False,
        }
    )
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "br-random")


async def test_conn_string_rejects_unknown_branch_id(tools):
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "br-nonexistent")


async def test_conn_string_succeeds_for_guard_created_branch(tools, fake, register_guard_branch):
    branch = register_guard_branch()
    result = await tools.get_branch_connection_string(PROJECT_ID, branch["id"])
    assert result["connection_uri"] == "postgresql://u:p@h/db"
    # The right connection params were used.
    call = fake.connection_calls[-1]
    assert call["branch_id"] == branch["id"]
    assert call["database_name"] == "appdb"
    assert call["role_name"] == "appuser"


async def test_conn_string_round_trip_from_create(tools):
    created = await tools.create_test_branch(PROJECT_ID, "feature-a")
    result = await tools.get_branch_connection_string(PROJECT_ID, created["branch_id"])
    assert result["connection_uri"].startswith("postgresql://")


# --------------------------------------------------------------------------
# _find_parent fails closed on ambiguity
# --------------------------------------------------------------------------

async def test_find_parent_zero_matches_fails_closed(make_tools, fake_neon_cls):
    # No branch named "main" exists.
    fake = fake_neon_cls(
        branches=[
            {"id": "br-x", "name": "develop", "parent_id": None, "default": True, "protected": True}
        ]
    )
    tools = make_tools(neon=fake)
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "feature-a")


async def test_find_parent_multiple_matches_fails_closed(make_tools, fake_neon_cls):
    # Two branches both named "main" -> ambiguous parent -> must refuse.
    fake = fake_neon_cls(
        branches=[
            {"id": "br-main", "name": PARENT_NAME, "parent_id": None, "default": True, "protected": True},
            {"id": "br-main-2", "name": PARENT_NAME, "parent_id": None, "default": False, "protected": False},
        ]
    )
    tools = make_tools(neon=fake)
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "feature-a")


# --------------------------------------------------------------------------
# Non-allowed project is refused on EVERY tool
# --------------------------------------------------------------------------

async def test_non_allowed_project_refused_everywhere(tools):
    with pytest.raises(ToolError):
        await tools.list_safe_branches(OTHER_PROJECT)
    with pytest.raises(ToolError):
        await tools.create_test_branch(OTHER_PROJECT, "feature-a")
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(OTHER_PROJECT, "br-main")
    with pytest.raises(ToolError):
        await tools.get_branch_status(OTHER_PROJECT, "br-main")


async def test_non_allowed_project_refused_on_destructive_tools(make_config, make_tools):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    with pytest.raises(ToolError):
        await tools.delete_test_branch(OTHER_PROJECT, "br-x")
    with pytest.raises(ToolError):
        await tools.reset_test_branch(OTHER_PROJECT, "br-x")


async def test_list_safe_projects_intersects_allowlist(make_tools, fake_neon_cls):
    fake = fake_neon_cls(
        branches=[_main()],
        projects=[
            {"id": PROJECT_ID, "name": "Allowed"},
            {"id": OTHER_PROJECT, "name": "Forbidden"},
        ],
    )
    tools = make_tools(neon=fake)
    projects = await tools.list_safe_projects()
    ids = {p["id"] for p in projects}
    assert ids == {PROJECT_ID}


async def test_list_safe_branches_flags_guard_created(tools, register_guard_branch):
    register_guard_branch()
    branches = await tools.list_safe_branches(PROJECT_ID)
    by_id = {b["id"]: b for b in branches}
    assert by_id["br-main"]["created_by_guard"] is False
    assert by_id["br-guard"]["created_by_guard"] is True


# --------------------------------------------------------------------------
# build_app: conditional + disabled tool registration
# --------------------------------------------------------------------------

async def test_build_app_omits_destructive_tools_by_default(config, fake, store):
    mcp = build_app(config, fake, store)
    names = set(await mcp.get_tools())
    assert "delete_test_branch" not in names
    assert "reset_test_branch" not in names
    # Always-on tools are present.
    assert "create_test_branch" in names
    assert "get_branch_connection_string" in names
    assert "list_safe_projects" in names


async def test_build_app_includes_destructive_tools_when_enabled(make_config, fake, store):
    cfg = make_config(allow_branch_deletion=True)
    mcp = build_app(cfg, fake, store)
    names = set(await mcp.get_tools())
    assert "delete_test_branch" in names
    assert "reset_test_branch" in names


async def test_build_app_skips_disabled_tools(make_config, fake, store):
    cfg = make_config(disabled_tools=["get_branch_status"])
    mcp = build_app(cfg, fake, store)
    names = set(await mcp.get_tools())
    assert "get_branch_status" not in names
    assert "create_test_branch" in names


async def test_build_app_can_disable_a_destructive_tool(make_config, fake, store):
    cfg = make_config(allow_branch_deletion=True, disabled_tools=["delete_test_branch"])
    mcp = build_app(cfg, fake, store)
    names = set(await mcp.get_tools())
    assert "delete_test_branch" not in names
    assert "reset_test_branch" in names


# --------------------------------------------------------------------------
# delete / reset semantics
# --------------------------------------------------------------------------

async def test_delete_refuses_branch_with_children(make_config, make_tools, fake, register_guard_branch):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    parent = register_guard_branch(suffix="parent", branch_id="br-parent")
    # A child branch points at the guard branch.
    fake.branches.append(
        {
            "id": "br-child",
            "name": PREFIX + "child",
            "parent_id": parent["id"],
            "default": False,
            "protected": False,
        }
    )
    with pytest.raises(ToolError):
        await tools.delete_test_branch(PROJECT_ID, parent["id"])
    assert fake.deleted == []


async def test_delete_succeeds_for_childless_guard_branch(make_config, make_tools, fake, store, register_guard_branch):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    branch = register_guard_branch(branch_id="br-guard")
    result = await tools.delete_test_branch(PROJECT_ID, branch["id"])
    assert result["deleted"] == branch["id"]
    assert fake.deleted and fake.deleted[0][1] == branch["id"]
    assert fake.deleted[0][2] is False  # soft delete
    assert store.contains(PROJECT_ID, branch["id"]) is False


async def test_delete_refuses_main_branch(make_config, make_tools, fake):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    with pytest.raises(ToolError):
        await tools.delete_test_branch(PROJECT_ID, "br-main")
    assert fake.deleted == []


async def test_delete_refuses_non_provenance_branch(make_config, make_tools, fake):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    fake.branches.append(
        {
            "id": "br-spoof",
            "name": PREFIX + "spoof",
            "parent_id": "br-main",
            "default": False,
            "protected": False,
        }
    )
    with pytest.raises(ToolError):
        await tools.delete_test_branch(PROJECT_ID, "br-spoof")
    assert fake.deleted == []


async def test_reset_restores_from_own_parent_only(make_config, make_tools, fake, register_guard_branch):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    branch = register_guard_branch(branch_id="br-guard")  # parent_id == br-main
    result = await tools.reset_test_branch(PROJECT_ID, branch["id"])
    assert result["reset"] == branch["id"]
    assert result["restored_from"] == "br-main"
    # The restore call used the branch's OWN parent id as source.
    proj, bid, body = fake.restored[-1]
    assert bid == branch["id"]
    assert body == {"source_branch_id": "br-main"}


async def test_reset_refuses_non_provenance_branch(make_config, make_tools, fake):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    with pytest.raises(ToolError):
        await tools.reset_test_branch(PROJECT_ID, "br-main")
    assert fake.restored == []


# --------------------------------------------------------------------------
# get_branch_status (read-only, but still project-gated)
# --------------------------------------------------------------------------

async def test_get_branch_status_reports_guard_flag(tools, register_guard_branch):
    register_guard_branch(branch_id="br-guard")
    status = await tools.get_branch_status(PROJECT_ID, "br-guard")
    assert status["id"] == "br-guard"
    assert status["created_by_guard"] is True

    main_status = await tools.get_branch_status(PROJECT_ID, "br-main")
    assert main_status["created_by_guard"] is False


# --------------------------------------------------------------------------
# create readiness polling + failure compensation
# --------------------------------------------------------------------------

async def test_await_ready_true_when_all_ops_finished(make_tools, fake_neon_cls, monkeypatch):
    import neon_guard_mcp.server as srv
    monkeypatch.setattr(srv, "_POLL_INTERVAL", 0)
    fake = fake_neon_cls(
        branches=[_main()],
        create_operations=[{"id": "op-1", "status": "running"}],
        op_responses=[[{"id": "op-1", "status": "finished"}]],
    )
    tools = make_tools(neon=fake)
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")
    assert result["ready"] is True
    assert fake.op_calls >= 1


async def test_await_ready_false_on_timeout(make_tools, fake_neon_cls, store, monkeypatch):
    import neon_guard_mcp.server as srv
    monkeypatch.setattr(srv, "_POLL_INTERVAL", 0)
    monkeypatch.setattr(srv, "_MAX_WALL_SECONDS", 0.0)  # deadline passes immediately
    fake = fake_neon_cls(
        branches=[_main()],
        create_operations=[{"id": "op-1", "status": "running"}],
        op_responses=[[{"id": "op-1", "status": "running"}]],  # never finishes
    )
    tools = make_tools(neon=fake, prov=store)
    result = await tools.create_test_branch(PROJECT_ID, "feature-a")
    assert result["ready"] is False
    # A not-yet-ready branch is still genuinely created, so provenance is kept.
    assert store.contains(PROJECT_ID, result["branch_id"]) is True


async def test_failed_op_raises_and_drops_provenance(make_tools, fake_neon_cls, store, monkeypatch):
    import neon_guard_mcp.server as srv
    monkeypatch.setattr(srv, "_POLL_INTERVAL", 0)
    fake = fake_neon_cls(
        branches=[_main()],
        create_operations=[{"id": "op-1", "status": "running"}],
        op_responses=[[{"id": "op-1", "status": "failed"}]],
    )
    tools = make_tools(neon=fake, prov=store)
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "feature-a")
    # The branch was created in Neon, but its failed creation must NOT remain
    # tracked as a usable guard branch.
    assert len(fake.created) == 1
    assert store.count(PROJECT_ID) == 0


async def test_state_write_failure_triggers_compensating_delete(make_tools, fake, store, monkeypatch):
    from neon_guard_mcp.state import StateError

    def _boom(*args, **kwargs):
        raise StateError("disk full")

    monkeypatch.setattr(store, "add", _boom)
    tools = make_tools(neon=fake, prov=store)
    with pytest.raises(ToolError):
        await tools.create_test_branch(PROJECT_ID, "feature-a")
    # Provenance could not be recorded, so the orphan branch must be deleted.
    assert any(bid == "br-new" for _proj, bid, _hard in fake.deleted)


# --------------------------------------------------------------------------
# fail-closed parent resolution reaches the credential + destructive paths
# --------------------------------------------------------------------------

async def test_conn_string_fails_closed_when_parent_unresolvable(tools, fake, register_guard_branch):
    register_guard_branch(branch_id="br-guard")
    # Drop the unique enforced parent: _assert_created_branch must deny even for
    # an in-provenance branch (the gate calls _find_parent, which fails closed).
    fake.branches = [b for b in fake.branches if b["name"] != PARENT_NAME]
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "br-guard")


async def test_destructive_paths_fail_closed_on_ambiguous_parent(
    make_config, make_tools, fake, register_guard_branch
):
    cfg = make_config(allow_branch_deletion=True)
    tools = make_tools(cfg=cfg)
    register_guard_branch(branch_id="br-guard")
    fake.branches.append(
        {"id": "br-main-2", "name": PARENT_NAME, "parent_id": None,
         "default": False, "protected": False}
    )
    for call in (
        tools.get_branch_connection_string,
        tools.delete_test_branch,
        tools.reset_test_branch,
    ):
        with pytest.raises(ToolError):
            await call(PROJECT_ID, "br-guard")
    assert fake.deleted == []
    assert fake.restored == []


async def test_conn_string_rejects_empty_branch_id(tools):
    with pytest.raises(ToolError):
        await tools.get_branch_connection_string(PROJECT_ID, "")


# --------------------------------------------------------------------------
# the FastMCP error-masking backstop + fail-closed startup
# --------------------------------------------------------------------------

async def test_unexpected_exception_is_masked_from_client(config, fake, store, monkeypatch):
    from fastmcp import Client
    from neon_guard_mcp.server import GuardedTools

    async def _boom(self):
        raise ValueError("leak napi_SECRETkey123 and postgresql://u:p4ssw0rd@h/db")

    monkeypatch.setattr(GuardedTools, "list_safe_projects", _boom)
    app = build_app(config, fake, store)
    async with Client(app) as client:
        try:
            result = await client.call_tool("list_safe_projects", {})
            text = str(getattr(result, "content", result))
        except Exception as e:  # FastMCP raises a masked ToolError to the client
            text = str(e)
    assert "napi_SECRETkey123" not in text
    assert "p4ssw0rd" not in text


async def test_main_fails_closed_with_no_tools(monkeypatch):
    import neon_guard_mcp.server as srv

    captured: dict = {}
    monkeypatch.setattr(srv.FastMCP, "run", lambda self, *a, **k: captured.update(app=self))
    monkeypatch.delenv("NEON_API_KEY", raising=False)
    monkeypatch.setenv("NEON_GUARD_CONFIG", "/nonexistent-neon-guard-xyz.json")
    srv.main()
    assert await captured["app"].get_tools() == {}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _main() -> dict:
    return {
        "id": "br-main",
        "name": PARENT_NAME,
        "parent_id": None,
        "default": True,
        "protected": True,
        "current_state": "ready",
        "created_at": "2026-01-01T00:00:00Z",
    }
