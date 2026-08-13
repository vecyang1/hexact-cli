"""Hexowatch commands served by the documented REST API.

The six endpoints that need only an API key: listing monitors, reading detected
changes and their diffs, forcing a scan, pausing and resuming, and creating a
monitor. Everything Hexowatch can do *beyond* these lives in
:mod:`hexact.cli_hexowatch`, because the gateway needs a session token instead.

`cmd_duplicates` is the one that is not a thin wrapper, and the comment inside
it is load-bearing: grouping by URL alone reported 18 redundant monitors on an
account that had 1.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import hexowatch
from .cli_common import _parse_timestamp, _rows, _state_label, parse_since
from .config import HEXOWATCH, resolve_key
from .http import HexactAPIError
from .output import EXIT_OK, EXIT_USAGE, emit

def cmd_monitors(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOWATCH)
    payload = hexowatch.list_monitored_urls(key)

    def render(data: dict[str, Any]) -> None:
        monitors = _rows(data, "monitored_urls", "data", "urls")
        if not monitors:
            print("No monitors found.")
            return
        states = [_state_label(m) for m in monitors]
        summary = ", ".join(
            f"{states.count(s)} {s}" for s in ("active", "paused", "unknown")
            if states.count(s)
        )
        print(f"{len(monitors)} monitor(s): {summary}\n")
        for monitor in monitors:
            name = monitor.get("name") or monitor.get("title") or "(unnamed)"
            print(f"  [{monitor.get('id')}] {name}  ({_state_label(monitor)})")
            print(f"       {monitor.get('address')}")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_changes(args: argparse.Namespace) -> int:
    """Recent detected changes across every monitor -- the alert-email replacement.

    This walks each monitor's log separately because the API exposes no
    account-wide change feed, so cost grows with monitor count. ``--limit``
    caps the per-monitor page size, not the number of monitors visited.
    """
    key = resolve_key(HEXOWATCH)
    cutoff = parse_since(args.since)
    monitors = _rows(hexowatch.list_monitored_urls(key), "monitored_urls", "data", "urls")

    collected: list[dict[str, Any]] = []
    skipped: list[str] = []
    for monitor in monitors:
        monitor_id = monitor.get("id")
        if monitor_id is None:
            continue
        try:
            logs = hexowatch.monitoring_logs(key, monitor_id, limit=args.limit)
        except HexactAPIError as exc:
            skipped.append(f"monitor {monitor_id}: {exc}")
            continue

        # `tool` rides on the log envelope, so a later `scan` call does not have
        # to be told which tool produced the result.
        tool = logs.get("tool")
        for entry in _rows(logs, "monitoring_results", "monitoring_logs", "logs", "data"):
            stamp = _parse_timestamp(entry.get("date"))
            if stamp is not None and stamp < cutoff:
                continue
            if args.changed_only and not entry.get("event_detected"):
                continue
            percentage = entry.get("percentage")
            if (
                args.min_percent is not None
                and isinstance(percentage, (int, float))
                and percentage < args.min_percent
            ):
                continue
            collected.append(
                {
                    "monitor_id": monitor_id,
                    "monitor_name": monitor.get("name") or monitor.get("title"),
                    "address": monitor.get("address"),
                    "tool": tool,
                    "date": entry.get("date"),
                    "scan_result_id": entry.get("scan_result_id"),
                    "event_detected": entry.get("event_detected"),
                    "percentage": percentage,
                }
            )

    collected.sort(key=lambda row: str(row.get("date") or ""), reverse=True)
    result = {"since": args.since, "count": len(collected), "changes": collected}
    if skipped:
        # Surfaced, never swallowed: a partial sweep must not read as a clean one.
        result["skipped"] = skipped

    def render(data: dict[str, Any]) -> None:
        if not data["changes"]:
            print(f"No changes detected in the last {data['since']}.")
        else:
            print(f"{data['count']} change(s) in the last {data['since']}:\n")
            for row in data["changes"]:
                percent = row.get("percentage")
                suffix = f"  ({percent}% changed)" if percent not in (None, "") else ""
                print(f"  {row.get('date')}  [{row['monitor_id']}] "
                      f"{row.get('monitor_name') or row.get('address')}{suffix}")
                print(f"       scan_result_id: {row.get('scan_result_id')}")
        for problem in data.get("skipped", []):
            print(f"  ! skipped {problem}", file=sys.stderr)

    emit(result, args.json, render)
    return EXIT_OK


def _normalise_address(address: str) -> str:
    """Collapse cosmetic URL differences so real duplicates group together.

    Deliberately conservative: scheme, ``www.``, a trailing slash, and case in
    the host are treated as noise, but the path and query are preserved. Two
    monitors on the same page with different query strings are genuinely
    different targets and must not be merged.
    """
    text = address.strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            break
    if text.lower().startswith("www."):
        text = text[4:]
    host, _, rest = text.partition("/")
    path = rest.rstrip("/")
    # `example.com/` and `example.com` are the same page, so an empty path must
    # not keep its separator -- otherwise the two never group together.
    return host.lower() + (f"/{path}" if path else "")


def resolve_tool_from_payload(payload: dict[str, Any]) -> str | None:
    """The ``tool`` carried by a ``monitoring_logs`` envelope, or ``None``.

    Returns ``None`` rather than a placeholder when the tool is absent, because
    the caller must be able to tell "no tool" apart from "some tool" -- a
    monitor with no scan history yet would otherwise group with every other
    unscanned monitor and be reported as a duplicate of it.
    """
    tool = payload.get("tool")
    return str(tool) if tool else None


def resolve_tool(key: str, monitoring_id: Any) -> str | None:
    """The tool a monitor runs, or ``None`` when it cannot be established.

    ``v1/monitored_urls`` returns only ``id``, ``address``, ``name`` and
    ``paused`` -- the tool is not among them, and there is no monitor-detail
    endpoint (measured: ``GET v1/monitored_urls/{id}`` is a 404). The only place
    the tool surfaces is the ``monitoring_logs`` envelope, so establishing it
    costs one request per monitor.
    """
    try:
        payload = hexowatch.monitoring_logs(key, int(monitoring_id), limit=1)
    except (HexactAPIError, ValueError, TypeError):
        return None
    return resolve_tool_from_payload(payload)


def cmd_duplicates(args: argparse.Namespace) -> int:
    """Group monitors that watch the same address *with the same tool*.

    Address alone is the wrong key and produces confidently destructive advice.
    Measured against the live account on 2026-08-13: grouping by address
    reported 18 redundant monitors out of 48; grouping by address **and** tool
    found **1**. The other 17 were the same page watched by different tools --
    visual, sitemap, techStack, automaticAI -- which is a deliberate
    configuration, not duplication. Acting on the address-only answer would have
    paused real coverage.

    Establishing the tool costs one extra request per monitor (see
    :func:`resolve_tool`). Correctness is worth the requests: the output of this
    command is a list of things to switch off.

    Hexowatch exposes no delete endpoint, so the remedy printed is a pause
    command -- and it is printed, not executed.
    """
    key = resolve_key(HEXOWATCH)
    monitors = _rows(hexowatch.list_monitored_urls(key), "monitored_urls", "data", "urls")

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    unresolved: list[dict[str, Any]] = []
    for monitor in monitors:
        address = monitor.get("address")
        if not address:
            continue
        tool = resolve_tool(key, monitor.get("id"))
        if tool is None:
            # Fail safe: never call a monitor redundant when we could not
            # establish what it does.
            unresolved.append({"id": monitor.get("id"), "address": address})
            continue
        groups.setdefault((_normalise_address(str(address)), tool), []).append(monitor)

    duplicates = {pair: rows for pair, rows in groups.items() if len(rows) > 1}
    redundant = [
        # Keep the lowest id in each group -- the oldest monitor holds the
        # longest change history, which is the one worth preserving.
        monitor
        for rows in duplicates.values()
        for monitor in sorted(rows, key=lambda m: m.get("id") or 0)[1:]
    ]
    result = {
        "monitors": len(monitors),
        "compared": len(monitors) - len(unresolved),
        "duplicate_groups": len(duplicates),
        "redundant_monitors": len(redundant),
        "redundant_ids": [m.get("id") for m in redundant],
        "groups": [
            {
                "address": addr,
                "tool": tool,
                "ids": [m.get("id") for m in sorted(rows, key=lambda m: m.get("id") or 0)],
            }
            for (addr, tool), rows in sorted(duplicates.items())
        ],
        "unresolved": unresolved,
    }

    def render(data: dict[str, Any]) -> None:
        scope = f"{data['compared']} of {data['monitors']} monitors"
        if not data["duplicate_groups"]:
            print(f"No duplicates among {scope} "
                  f"(same address AND same tool).")
        else:
            print(f"{data['duplicate_groups']} duplicate group(s) across {scope}; "
                  f"{data['redundant_monitors']} redundant:\n")
            for group in data["groups"]:
                keep, *drop = group["ids"]
                print(f"  {group['address']}  [{group['tool']}]")
                print(f"      keep {keep}  |  redundant: {', '.join(map(str, drop))}")
            ids = " ".join(str(i) for i in data["redundant_ids"])
            print(f"\n  Hexowatch has no delete endpoint. To stop the extra checks "
                  f"and notifications:\n    hexact watch pause {ids}")
        for row in data["unresolved"]:
            print(f"  ! tool unknown, not compared: {row['id']} {row['address']}",
                  file=sys.stderr)

    emit(result, args.json, render)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOWATCH)
    payload = hexowatch.scan_result(key, args.scan_result_id, args.tool)
    emit(payload, True, lambda data: None)  # diffs are structured; always JSON
    return EXIT_OK


def cmd_action(args: argparse.Namespace) -> int:
    if not args.ids and not args.all:
        print("Refusing to act on every monitor implicitly. "
              "Pass monitor ids, or --all to mean the whole account.", file=sys.stderr)
        return EXIT_USAGE

    key = resolve_key(HEXOWATCH)
    payload = hexowatch.act(key, args.action, args.ids or None)
    target = "all monitors" if args.all else f"monitor(s) {', '.join(map(str, args.ids))}"
    emit(payload, args.json, lambda _: print(f"{args.action} applied to {target}."))
    return EXIT_OK


def cmd_create(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOWATCH)
    options: dict[str, Any] = {
        "monitoring_interval": args.interval,
        "webhook": args.webhook,
        "tags": args.tag or None,
        "change_notification_level": args.level,
    }
    if args.silent:
        # Overrides any --webhook, which would be a delivery channel.
        options.update(hexowatch.silent_monitor_kwargs())

    payload = hexowatch.create_monitor(
        key, tool=args.tool, addresses=args.url, **options
    )

    def render(data: dict[str, Any]) -> None:
        ids = data.get("monitoring_ids") or data.get("data") or []
        print(f"Created monitor(s): {ids}")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_levels(args: argparse.Namespace) -> int:
    """Show which change_notification_level values each tool accepts.

    Offline: this is documented schema, not account state, so it needs no key.
    """
    payload = {
        "levels": {tool: list(values)
                   for tool, values in hexowatch.NOTIFICATION_LEVELS.items()},
        "mute_mechanism": "notification_integrations: []  (use --silent)",
        "note": (
            "No change_notification_level value suppresses notifications; the "
            "narrowest available still notifies. GE_n values are undocumented "
            "beyond their names."
        ),
    }

    def render(data: dict[str, Any]) -> None:
        for tool, values in data["levels"].items():
            print(f"  {tool}")
            print(f"      {', '.join(values)}")
        print(f"\n  To keep monitoring without notifications: {data['mute_mechanism']}")
        print(f"  {data['note']}")

    emit(payload, args.json, render)
    return EXIT_OK


def cmd_integrations(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOWATCH)
    payload = hexowatch.list_integrations(key)

    def render(data: dict[str, Any]) -> None:
        rows = _rows(data, "result", "integrations", "data")
        if not rows:
            print("No notification integrations configured.\n"
                  "  With no channel registered, change alerts fall back to email.")
            return
        for row in rows:
            label = row.get("type") or row.get("name")
            print(f"  [{row.get('id')}] {label}  {row.get('data', '')}")

    emit(payload, args.json, render)
    return EXIT_OK
