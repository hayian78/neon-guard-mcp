"""The provenance store persists durably, atomically, and fails closed."""

from __future__ import annotations

import os
import stat

import pytest

from neon_guard_mcp.state import ProvenanceStore, StateError

PROJ = "proj-allowed"


def test_add_contains_count_ids_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    store = ProvenanceStore(path)

    assert store.count(PROJ) == 0
    assert store.contains(PROJ, "br-1") is False
    assert store.ids(PROJ) == set()

    store.add(PROJ, "br-1", "ai-test-a", "2026-06-20T00:00:00Z", None)
    store.add(PROJ, "br-2", "ai-test-b", "2026-06-20T00:00:00Z", "2026-06-21T00:00:00Z")

    assert store.contains(PROJ, "br-1") is True
    assert store.contains(PROJ, "br-2") is True
    assert store.count(PROJ) == 2
    assert store.ids(PROJ) == {"br-1", "br-2"}


def test_persistence_across_fresh_instance(tmp_path):
    path = str(tmp_path / "state.json")
    ProvenanceStore(path).add(PROJ, "br-1", "ai-test-a", "2026-06-20T00:00:00Z", None)

    # A brand-new instance on the same path must observe the prior write.
    reopened = ProvenanceStore(path)
    assert reopened.contains(PROJ, "br-1") is True
    assert reopened.count(PROJ) == 1
    assert reopened.ids(PROJ) == {"br-1"}


def test_add_is_idempotent_per_branch_id(tmp_path):
    store = ProvenanceStore(str(tmp_path / "state.json"))
    store.add(PROJ, "br-1", "ai-test-a", "t0", None)
    store.add(PROJ, "br-1", "ai-test-a", "t0", None)
    assert store.count(PROJ) == 1


def test_remove_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    store = ProvenanceStore(path)
    store.add(PROJ, "br-1", "ai-test-a", "t0", None)
    store.add(PROJ, "br-2", "ai-test-b", "t0", None)

    store.remove(PROJ, "br-1")
    assert store.contains(PROJ, "br-1") is False
    assert store.count(PROJ) == 1

    # Persisted: a fresh instance sees the removal too.
    assert ProvenanceStore(path).ids(PROJ) == {"br-2"}

    store.remove(PROJ, "missing")  # no-op, must not raise
    assert store.count(PROJ) == 1


def test_count_and_ids_isolated_per_project(tmp_path):
    store = ProvenanceStore(str(tmp_path / "state.json"))
    store.add("p1", "br-1", "n", "t", None)
    store.add("p2", "br-2", "n", "t", None)
    assert store.count("p1") == 1
    assert store.ids("p1") == {"br-1"}
    assert store.count("p2") == 1
    assert store.count("other") == 0


def test_state_file_has_0600_mode(tmp_path):
    path = str(tmp_path / "state.json")
    store = ProvenanceStore(path)
    store.add(PROJ, "br-1", "ai-test-a", "t0", None)

    assert os.path.exists(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_corrupt_json_raises_state_error(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ this is not valid json")
    store = ProvenanceStore(str(path))
    with pytest.raises(StateError):
        store.contains(PROJ, "br-1")
    with pytest.raises(StateError):
        store.count(PROJ)


def test_non_dict_state_structure_raises(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[1, 2, 3]")
    store = ProvenanceStore(str(path))
    # Every read path must fail closed on a structurally invalid state file.
    with pytest.raises(StateError):
        store.count(PROJ)
    with pytest.raises(StateError):
        store.contains(PROJ, "br-1")
    with pytest.raises(StateError):
        store.ids(PROJ)


def test_missing_file_is_empty_not_error(tmp_path):
    store = ProvenanceStore(str(tmp_path / "nope.json"))
    assert store.count(PROJ) == 0
    assert store.ids(PROJ) == set()
    assert store.contains(PROJ, "x") is False


def test_corrupt_list_entry_raises_state_error(tmp_path):
    # A list whose ENTRIES are not dicts must fail closed via StateError on every
    # read path, not a raw AttributeError/TypeError that bypasses the guard.
    path = tmp_path / "state.json"
    path.write_text('{"proj-allowed": ["not-a-dict", 1]}')
    store = ProvenanceStore(str(path))
    with pytest.raises(StateError):
        store.count(PROJ)
    with pytest.raises(StateError):
        store.contains(PROJ, "br-1")
    with pytest.raises(StateError):
        store.ids(PROJ)


def test_add_rejects_empty_branch_id(tmp_path):
    store = ProvenanceStore(str(tmp_path / "state.json"))
    with pytest.raises(StateError):
        store.add(PROJ, "", "n", "t", None)


def test_contains_is_false_for_empty_branch_id(tmp_path):
    store = ProvenanceStore(str(tmp_path / "state.json"))
    store.add(PROJ, "br-1", "n", "t", None)
    assert store.contains(PROJ, "") is False
