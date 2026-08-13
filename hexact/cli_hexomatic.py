"""Hexomatic commands that only the GraphQL gateway can serve.

Two things REST cannot answer, both of which matter on a lifetime plan with a
fixed monthly credit allowance:

**What a workflow produced.** REST returns the workflow and its execution log,
never the rows it scraped. The gateway does, either as a link to the full JSON
or as an inline preview.

**What it cost.** Neither `credit` nor `premiumCredit` appears in REST's
workflow payload, and there is no usage endpoint at all, so the only way to know
how much of a 10,000-credit month is gone was to open the dashboard.

Still absent, and stated here so nobody re-derives it: **nothing runs a
workflow.** All 11 fields of `HexomaticWorkflowOps` were enumerated; none of
them is a run, execute or trigger. That is a measured absence, not an untried
guess.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from . import auth, hexomatic
from .output import EXIT_OK, emit


def _maybe_json(value: Any) -> Any:
    """Parse a field the gateway serialised as a JSON string, or keep it as-is.

    `data` and `time_series` arrive as strings rather than objects. Parsing must
    not be assumed to succeed: an error path can put a bare message in the same
    field, and turning that into a crash would replace a readable failure with a
    stack trace.
    """
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value


def cmd_credits(args: argparse.Namespace) -> int:
    """Automation credit consumption — the number REST does not expose."""
    token = auth.access_token()

    if args.series:
        result = hexomatic.credit_series(
            token, since=args.since, until=args.until) or {}
        payload = {"time_series": _maybe_json(result.get("time_series")),
                   "error": result.get("error"), "message": result.get("message")}

        def render(data: dict[str, Any]) -> None:
            series = data.get("time_series")
            if not series:
                print("The gateway returned no time series for that period.")
                return
            print(json.dumps(series, indent=2, default=str))
    else:
        result = hexomatic.credit_usage(token) or {}
        payload = {"usage": _maybe_json(result.get("data"))}

        def render(data: dict[str, Any]) -> None:
            usage = data.get("usage")
            if isinstance(usage, dict):
                for key, value in usage.items():
                    print(f"  {key:32} {value}")
            elif usage:
                print(usage)
            else:
                print("The gateway returned no credit usage.")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_workflows_detailed(args: argparse.Namespace) -> int:
    """Workflows with their credit cost, schedule and status."""
    token = auth.access_token()
    result = hexomatic.list_workflows_detailed(token) or {}
    rows = result.get("workflows") or []

    def render(data: dict[str, Any]) -> None:
        workflows = data.get("workflows") or []
        print(f"{len(workflows)} of {data.get('count')} workflow(s):\n")
        for row in workflows:
            state = "on " if row.get("active") else "off"
            credit = row.get("credit")
            premium = row.get("premiumCredit")
            cost = f"{credit} credit" + (f" + {premium} premium" if premium else "")
            print(f"  [{row.get('id')}] {state} {str(row.get('status') or ''):12} "
                  f"{str(cost):24} {row.get('name')}")

    emit({"count": result.get("count"), "workflows": rows}, args.json, render)
    return EXIT_OK


def cmd_results(args: argparse.Namespace) -> int:
    """A workflow's actual output — the rows it scraped.

    Defaults to the inline preview, because that is the answer to "what did this
    produce" without leaving the terminal. `--url` asks the gateway for a link
    to the complete result set instead; it is deliberately not fetched here, so
    a list command never silently downloads a large file.
    """
    token = auth.access_token()

    if args.url:
        result = hexomatic.workflow_result_url(token, args.workflow_id) or {}
        payload = {"workflow_id": args.workflow_id,
                   "json_url": result.get("json_url"),
                   "error_code": result.get("error_code")}

        def render(data: dict[str, Any]) -> None:
            if data.get("json_url"):
                print(data["json_url"])
            else:
                print(f"No result URL. error_code={data.get('error_code')!r} — "
                      f"a workflow that has never completed a run has no output.")
    else:
        result = hexomatic.workflow_result_preview(token, args.workflow_id) or {}
        payload = {"workflow_id": args.workflow_id,
                   "result": _maybe_json(result.get("result")),
                   "error_code": result.get("error_code")}

        def render(data: dict[str, Any]) -> None:
            rows = data.get("result")
            if not rows:
                print(f"No preview. error_code={data.get('error_code')!r} — "
                      f"a workflow that has never completed a run has no output.")
                return
            print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))

    emit(payload, args.json, render)
    return EXIT_OK
