"""Provenance store: branches THIS proxy created. Atomic + fail-closed."""

from __future__ import annotations

import json
import os
import tempfile

DEFAULT_STATE_PATH = ".neon-guard-state.json"


def _silent_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class StateError(Exception):
    """Raised when on-disk state is corrupt or cannot be persisted."""


class ProvenanceStore:
    """Tracks branches created by this proxy, keyed by project id.

    On-disk JSON shape:
        {project_id: [{"branch_id", "name", "created_at", "expires_at"}]}
    """

    def __init__(self, path: str | None = None) -> None:
        self._path = path or os.environ.get("NEON_GUARD_STATE") or DEFAULT_STATE_PATH

    def _load(self) -> dict[str, list[dict]]:
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as e:
            raise StateError("state file is unreadable or corrupt") from e
        if not isinstance(data, dict):
            raise StateError("state file has an invalid structure")
        for value in data.values():
            if not isinstance(value, list) or any(
                not isinstance(entry, dict) for entry in value
            ):
                raise StateError("state file has an invalid structure")
        return data

    def _save(self, data: dict[str, list[dict]]) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".neon-guard-state.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
        except OSError as e:
            os.close(fd)  # fdopen has not taken ownership yet; close to avoid a leak.
            _silent_unlink(tmp)
            raise StateError("could not persist state file") from e
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self._path)
        except OSError as e:
            _silent_unlink(tmp)
            raise StateError("could not persist state file") from e

    def add(
        self,
        project_id: str,
        branch_id: str,
        name: str,
        created_at: str,
        expires_at: str | None,
    ) -> None:
        """Record a created branch; no-op if branch_id is already present."""
        if not branch_id:
            raise StateError("refusing to record a branch with an empty id")
        data = self._load()
        entries = data.setdefault(project_id, [])
        if any(e.get("branch_id") == branch_id for e in entries):
            return
        entries.append(
            {
                "branch_id": branch_id,
                "name": name,
                "created_at": created_at,
                "expires_at": expires_at,
            }
        )
        self._save(data)

    def contains(self, project_id: str, branch_id: str) -> bool:
        """True iff this proxy created the given branch (never for an empty id)."""
        if not branch_id:
            return False
        entries = self._load().get(project_id, [])
        return any(e.get("branch_id") == branch_id for e in entries)

    def remove(self, project_id: str, branch_id: str) -> None:
        """Drop a branch from provenance; no-op if absent."""
        data = self._load()
        entries = data.get(project_id)
        if not entries:
            return
        remaining = [e for e in entries if e.get("branch_id") != branch_id]
        if len(remaining) == len(entries):
            return
        if remaining:
            data[project_id] = remaining
        else:
            del data[project_id]
        self._save(data)

    def count(self, project_id: str) -> int:
        """Number of branches this proxy created for a project."""
        return len(self._load().get(project_id, []))

    def ids(self, project_id: str) -> set[str]:
        """Set of branch ids this proxy created for a project."""
        return {e["branch_id"] for e in self._load().get(project_id, []) if "branch_id" in e}
