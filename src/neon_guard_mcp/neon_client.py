"""Async client for the Neon REST API (v2).

NeonAPIError carries ONLY an HTTP status code and the Neon JSON "message"
field — never an httpx exception repr, never request/response headers, never
the API key or a connection URI. Errors are always raised `from None` so no
chained exception can leak transport detail into a traceback.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .logging import redact

NEON_API_BASE = "https://console.neon.tech/api/v2"


class NeonAPIError(Exception):
    """A Neon API failure carrying only a status code and safe message.

    The message is redacted on construction as defense-in-depth, so even an
    upstream payload that echoed a credential can never leak through str(err).
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = redact(message)
        super().__init__(f"Neon API error {status_code}: {self.message}")


class NeonClient:
    """Thin async wrapper over the Neon v2 REST API.

    Holds the master API key in the Authorization header of a single shared
    httpx.AsyncClient. The key is never logged or surfaced in errors.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = NEON_API_BASE,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a request and return parsed JSON, failing closed and safe.

        On transport error -> NeonAPIError(0, generic). On HTTP 429 retry
        exactly once. On status >= 400 -> NeonAPIError(status, Neon message).
        """
        try:
            resp = await self._client.request(
                method, path, params=params, json=json
            )
        except httpx.HTTPError:
            # Never surface the httpx exception detail (may carry URL/headers).
            raise NeonAPIError(0, "network error contacting Neon API") from None

        if resp.status_code == 429:
            await asyncio.sleep(1.0)
            try:
                resp = await self._client.request(
                    method, path, params=params, json=json
                )
            except httpx.HTTPError:
                raise NeonAPIError(
                    0, "network error contacting Neon API"
                ) from None

        if resp.status_code >= 400:
            message = "request failed"
            try:
                body = resp.json()
                if isinstance(body, dict) and isinstance(
                    body.get("message"), str
                ):
                    message = body["message"]
            except ValueError:
                pass
            raise NeonAPIError(resp.status_code, message) from None

        if not resp.content:
            return {}
        try:
            data = resp.json()
        except ValueError:
            raise NeonAPIError(0, "unexpected response format from Neon API") from None
        if not isinstance(data, dict):
            raise NeonAPIError(0, "unexpected response format from Neon API") from None
        return data

    async def list_projects(self) -> list[dict[str, Any]]:
        """Return all projects visible to the API key."""
        data = await self._request("GET", "/projects")
        return data.get("projects", [])

    async def list_branches(self, project_id: str) -> list[dict[str, Any]]:
        """Return all branches for a project."""
        data = await self._request(
            "GET", f"/projects/{project_id}/branches"
        )
        return data.get("branches", [])

    async def create_branch(
        self, project_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a branch; returns the BranchOperations response dict.

        The response must carry a branch with an id/name, else callers could
        record incomplete provenance for a branch they cannot manage.
        """
        data = await self._request(
            "POST", f"/projects/{project_id}/branches", json=body
        )
        branch = data.get("branch")
        if not isinstance(branch, dict) or not branch.get("id") or not branch.get("name"):
            raise NeonAPIError(0, "unexpected create-branch response from Neon API") from None
        return data

    async def get_connection_uri(
        self,
        project_id: str,
        *,
        branch_id: str,
        database_name: str,
        role_name: str,
        pooled: bool,
    ) -> str:
        """Return the connection URI (embeds a live password — a secret)."""
        data = await self._request(
            "GET",
            f"/projects/{project_id}/connection_uri",
            params={
                "branch_id": branch_id,
                "database_name": database_name,
                "role_name": role_name,
                "pooled": pooled,
            },
        )
        uri = data.get("uri")
        if not isinstance(uri, str) or not uri:
            raise NeonAPIError(0, "connection URI missing from Neon response") from None
        return uri

    async def delete_branch(
        self, project_id: str, branch_id: str, hard_delete: bool = False
    ) -> dict[str, Any]:
        """Delete a branch (soft by default)."""
        return await self._request(
            "DELETE",
            f"/projects/{project_id}/branches/{branch_id}",
            params={"hard_delete": hard_delete},
        )

    async def restore_branch(
        self, project_id: str, branch_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Restore (reset) a branch from a source branch."""
        return await self._request(
            "POST",
            f"/projects/{project_id}/branches/{branch_id}/restore",
            json=body,
        )

    async def list_operations(self, project_id: str) -> list[dict[str, Any]]:
        """Return the operations log for a project."""
        data = await self._request(
            "GET", f"/projects/{project_id}/operations"
        )
        return data.get("operations", [])
