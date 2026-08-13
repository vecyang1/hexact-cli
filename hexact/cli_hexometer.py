"""Hexometer commands, over both transports.

`properties`, `health` and `errors` are REST and need a per-property API key.
`overview` and `issues` need a session token and go to the gateway, which is
what makes them possible at all:

REST needs a **per-property** API key and has no endpoint that lists properties,
so an account cannot even enumerate what it monitors without knowing the ids
already. The session token covers all of them.

Writes stay unwired on purpose -- see :mod:`hexact.hexometer`.
"""

from __future__ import annotations

import argparse
from typing import Any

from . import auth, hexometer
from .cli_common import _rows
from .config import HEXOMETER, resolve_key
from .output import EXIT_OK, emit


def cmd_overview(args: argparse.Namespace) -> int:
    """Every property on the account, with its open-issue counts."""
    token = auth.access_token()
    rows = hexometer.properties_detailed(token)
    rows = rows if isinstance(rows, list) else [rows]

    def render(data: list[dict[str, Any]]) -> None:
        if not data:
            print("No Hexometer properties on this account.")
            return
        print(f"{len(data)} propert{'y' if len(data) == 1 else 'ies'}:\n")
        for row in data:
            counts = row.get("taskCounts") or {}
            state = "paused" if row.get("paused") else "active"
            print(f"  [{row.get('id')}] {state:6} {str(row.get('address') or row.get('hostname'))}")
            print(f"      issues: general {counts.get('general')}  "
                  f"meta {counts.get('metaTags')}  resolved {counts.get('resolved')}")

    emit(rows, args.json, render)
    return EXIT_OK


def cmd_issues(args: argparse.Namespace) -> int:
    """Detected issues, paged."""
    token = auth.access_token()
    result = hexometer.issues(
        token, page=args.page, limit=args.limit, tool=args.tool) or {}
    rows = result.get("issues") or []

    def render(data: dict[str, Any]) -> None:
        issues = data.get("issues") or []
        if not issues:
            print("No issues returned for that page.")
            return
        print(f"{len(issues)} issue(s), page {args.page}:\n")
        for row in issues:
            mark = "resolved" if row.get("resolved") else "open"
            print(f"  [{row.get('id')}] {mark:8} {str(row.get('level') or ''):8} "
                  f"{str(row.get('tool') or ''):22} {row.get('address')}")

    emit({"issues": rows, "message": result.get("message")}, args.json, render)
    return EXIT_OK


def cmd_properties(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMETER)
    payload = hexometer.list_properties(key)

    def render(data: dict[str, Any]) -> None:
        rows = _rows(data, "properties", "result", "data")
        if not rows:
            print("No properties found.")
            return
        print(f"{len(rows)} propert(ies):\n")
        for row in rows:
            print(f"  [{row.get('id')}] {row.get('name') or row.get('url') or '(unnamed)'}")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_health(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMETER)
    if args.status is None:
        payload = hexometer.health_link_statuses(key, args.property_id)
    else:
        payload = hexometer.health_links(key, args.property_id, args.status)
    emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_errors(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMETER)
    payload = hexometer.detected_errors(key, args.property_id, args.tool_name)
    emit(payload, True, lambda data: None)
    return EXIT_OK
