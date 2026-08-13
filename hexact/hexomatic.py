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


# --- GraphQL: what REST cannot reach ---------------------------------------
# REST gives `workflows` and `workflow-logs`. Neither returns the data a
# workflow actually produced, and neither reports credit consumption -- which
# on a 10,000-credit/month lifetime plan is the number that decides whether the
# month is affordable. Both live on the gateway.
#
# Input-object shapes here were recovered the same inert way as everything
# else, from `Field "workflow_idZz" is not defined by type
# GetWorkflowResultJSONInput. Did you mean workflow_id?`.

from . import graphql  # noqa: E402  (kept below the REST client it complements)

WORKFLOWS_QUERY = """
query {
  HexomaticWorkflow {
    getWorkflows {
      count
      error_code
      workflows {
        id name active status credit premiumCredit frequency
        created_at updated_at started_at description
      }
    }
  }
}
"""

WORKFLOW_RESULT_JSON_QUERY = """
query($settings: GetWorkflowResultJSONInput) {
  HexomaticWorkflow {
    getWorkflowResultJSON(settings: $settings) { error_code json_url }
  }
}
"""

WORKFLOW_RESULT_PREVIEW_QUERY = """
query($settings: GetWorkflowResultPreview) {
  HexomaticWorkflow {
    getWorkflowResultPreview(settings: $settings) { error_code result }
  }
}
"""

CREDIT_USAGE_QUERY = """
query {
  HexomaticAutomation {
    getAutomationCreditUsage { data }
  }
}
"""

CREDIT_SERIES_QUERY = """
query($settings: AutomationCreditTimeSeriesSettings) {
  HexomaticAutomation {
    getAutomationCreditTimeSeries(settings: $settings) {
      error message time_series
    }
  }
}
"""


def list_workflows_detailed(token: str) -> dict[str, Any]:
    """Workflows with credit cost, schedule and status.

    REST's `v1/workflows` reports neither `credit` nor `premiumCredit`, so the
    per-workflow cost of a run is invisible there.
    """
    data = graphql.execute(WORKFLOWS_QUERY, token=token)
    return graphql.unwrap(data, "HexomaticWorkflow", "getWorkflows")


def workflow_result_url(token: str, workflow_id: int, scan_id: str | None = None) -> dict[str, Any]:
    """A URL to the workflow's output as JSON.

    The gateway hands back a link rather than the rows themselves -- the result
    set can be large -- so this returns `json_url`, and fetching it is the
    caller's decision rather than something that happens inside a list command.
    """
    settings: dict[str, Any] = {"workflow_id": int(workflow_id)}
    if scan_id is not None:
        settings["scanId"] = scan_id
    data = graphql.execute(WORKFLOW_RESULT_JSON_QUERY, {"settings": settings}, token=token)
    return graphql.unwrap(data, "HexomaticWorkflow", "getWorkflowResultJSON")


def workflow_result_preview(token: str, workflow_id: int) -> dict[str, Any]:
    """The first rows of a workflow's output, inline.

    `result` arrives as a JSON *string*, not an object -- the gateway serialises
    it. Callers that want structure must parse it, and must not assume it
    parses: an error path can put a bare message there.
    """
    data = graphql.execute(
        WORKFLOW_RESULT_PREVIEW_QUERY,
        {"settings": {"workflow_id": int(workflow_id)}},
        token=token,
    )
    return graphql.unwrap(data, "HexomaticWorkflow", "getWorkflowResultPreview")


def credit_usage(token: str) -> dict[str, Any]:
    """Automation credit consumption. `data` is a JSON-encoded string."""
    data = graphql.execute(CREDIT_USAGE_QUERY, token=token)
    return graphql.unwrap(data, "HexomaticAutomation", "getAutomationCreditUsage")


def credit_series(
    token: str, *, since: str | None = None, until: str | None = None,
    page: int | None = None, page_size: int | None = None,
) -> dict[str, Any]:
    """Credit consumption over time. `time_series` is a JSON-encoded string."""
    settings = {"from": since, "to": until, "page": page, "pageSize": page_size}
    settings = {k: v for k, v in settings.items() if v is not None}
    data = graphql.execute(
        CREDIT_SERIES_QUERY, {"settings": settings or None}, token=token
    )
    return graphql.unwrap(data, "HexomaticAutomation", "getAutomationCreditTimeSeries")
