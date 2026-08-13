"""Hexomatic API client -- scraping and workflow automation.

Endpoints are documented at https://hexomatic.com/api-documentation/.

**Known ceiling:** the public API can list, read, toggle, and delete workflows,
but it exposes *no endpoint that executes one*. Running a workflow on demand
requires Hexomatic's own scheduler or an external trigger integration. This is
a limit of the published API, not an omission here -- see ``docs/API.md``.
"""

from __future__ import annotations

from typing import Any

from .http import path_segment, request

BASE_URL = "https://api.hexomatic.com/v2/app/services/v1"


def _call(key: str, path: str, **kwargs: Any) -> dict[str, Any]:
    return request(BASE_URL, path, key, **kwargs)


def list_workflows(key: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Workflows on the account, paginated."""
    return _call(key, "workflows", params={"limit": limit, "offset": offset})


def get_workflow(key: str, workflow_id: int) -> dict[str, Any]:
    """One workflow including its completed results."""
    return _call(key, f"workflows/{path_segment(workflow_id)}")


def workflow_logs(key: str, workflow_id: int) -> dict[str, Any]:
    """Execution history for one workflow."""
    return _call(key, "workflow-logs", params={"workflow_id": workflow_id})


def set_active(key: str, workflow_ids: list[int], active: bool) -> dict[str, Any]:
    """Enable or disable workflows in bulk."""
    if not workflow_ids:
        raise ValueError("At least one workflow id is required")
    return _call(key, "workflows", method="PUT",
                 body={"workflows_ids": workflow_ids, "active": active})


def delete_workflows(key: str, workflow_ids: list[int]) -> dict[str, Any]:
    """Permanently delete workflows. There is no undo on the API side."""
    if not workflow_ids:
        raise ValueError("At least one workflow id is required")
    return _call(key, "workflows", method="DELETE",
                 body={"workflows_ids": workflow_ids})
