"""Hexomatic commands, over both transports.

`workflows`, `workflow`, `logs` and `enable`/`disable` are the documented REST
endpoints and need only an API key. `credits`, `detail` and `results` need a
session token, because the gateway is the only thing that serves them -- and two
of those matter on a lifetime plan with a fixed monthly credit allowance:

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
from .cli_common import _rows, reject_duration_for_a_date_flag
from .config import HEXOMATIC, resolve_key
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
    # This --since is a calendar date, unlike `watch changes --since`. Typing a
    # duration here used to be handed to the gateway to interpret however it
    # liked, which is not a question anybody measured the answer to.
    reject_duration_for_a_date_flag(args.since)
    reject_duration_for_a_date_flag(args.until)
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


def cmd_workflows(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    payload = hexomatic.list_workflows(key, limit=args.limit)

    def render(data: dict[str, Any]) -> None:
        rows = _rows(data, "workflows", "data")
        if not rows:
            print("No workflows found.")
            return
        print(f"{len(rows)} workflow(s):\n")
        for row in rows:
            state = "active" if row.get("active") else "inactive"
            print(f"  [{row.get('id')}] {row.get('name') or '(unnamed)'}  ({state})")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_workflow(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    payload = hexomatic.get_workflow(key, args.workflow_id)
    emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_workflow_logs(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    payload = hexomatic.workflow_logs(key, args.workflow_id)
    emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_workflow_toggle(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    active = args.state == "enable"
    payload = hexomatic.set_active(key, args.ids, active)
    emit(payload, args.json,
          lambda _: print(f"{args.state}d workflow(s) {', '.join(map(str, args.ids))}."))
    return EXIT_OK
