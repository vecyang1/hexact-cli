"""Command-line interface for the Hexact suite.

Every command accepts ``--json`` so an agent can consume the raw payload, while
the default rendering stays readable for a human. Exit codes are meaningful:
0 success, 1 an API or credential failure, 2 a usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from . import auth, graphql, hexomatic, hexometer, hexowatch
from .config import HEXOMATIC, HEXOMETER, HEXOWATCH, CredentialError, resolve_key
from .http import HexactAPIError, redact

EXIT_OK, EXIT_FAILURE, EXIT_USAGE = 0, 1, 2

_DURATION = re.compile(r"^(\d+)([hdwm])$")
_DURATION_UNITS = {"h": "hours", "d": "days", "w": "weeks"}


def parse_since(value: str) -> datetime:
    """Turn ``24h`` / ``7d`` / ``2w`` / ``1m`` into an aware UTC cutoff."""
    match = _DURATION.match(value.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid duration {value!r}. Use forms like 24h, 7d, 2w, 1m."
        )
    amount, unit = int(match.group(1)), match.group(2)
    delta = timedelta(days=amount * 30) if unit == "m" else timedelta(
        **{_DURATION_UNITS[unit]: amount}
    )
    return datetime.now(timezone.utc) - delta


def _parse_timestamp(raw: Any) -> datetime | None:
    """Best-effort parse of the API's date field, which is not schema-stable."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        seconds = raw / 1000 if raw > 1e11 else raw  # tolerate epoch millis
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    text = str(raw).strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _emit(payload: Any, as_json: bool, render) -> None:
    if as_json:
        json.dump(payload, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        render(payload)


def _rows(payload: dict[str, Any], *names: str) -> list[dict[str, Any]]:
    """Pull the first present list field out of an API envelope.

    Field names are taken from observed responses, not guessed. Two of them bit
    hard during the first live run and are worth stating: monitors carry
    ``paused`` (not ``active``), and scan history arrives under
    ``monitoring_results`` (not ``monitoring_logs``). Guessing either produced
    confident, wrong, non-erroring output -- every monitor rendered as paused,
    and a real change history rendered as "no changes".
    """
    for name in names:
        value = payload.get(name)
        if isinstance(value, list):
            return value
    return []


def _is_paused(monitor: dict[str, Any]) -> bool | None:
    """True when a monitor is paused, None when the payload does not say.

    The state flag is genuinely inconsistent in this API. The documentation
    specifies ``active`` (true = running); the live endpoint was observed
    returning ``paused`` (true = stopped) on 2026-08-13, and the docs' own
    apiMonitoringTool example also shows ``paused``. Both are handled, with
    ``paused`` preferred because that is what the live API actually sends.

    Returning None for an unrecognised shape matters: defaulting to "running"
    would silently report a stopped account as healthy.
    """
    if "paused" in monitor:
        return bool(monitor["paused"])
    if "active" in monitor:
        return not bool(monitor["active"])
    return None


def _state_label(monitor: dict[str, Any]) -> str:
    paused = _is_paused(monitor)
    if paused is None:
        return "unknown"
    return "paused" if paused else "active"


# --------------------------------------------------------------------------
# Hexowatch commands
# --------------------------------------------------------------------------

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

    _emit(payload, args.json, render)
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

    _emit(result, args.json, render)
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

    _emit(result, args.json, render)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOWATCH)
    payload = hexowatch.scan_result(key, args.scan_result_id, args.tool)
    _emit(payload, True, lambda data: None)  # diffs are structured; always JSON
    return EXIT_OK


def cmd_action(args: argparse.Namespace) -> int:
    if not args.ids and not args.all:
        print("Refusing to act on every monitor implicitly. "
              "Pass monitor ids, or --all to mean the whole account.", file=sys.stderr)
        return EXIT_USAGE

    key = resolve_key(HEXOWATCH)
    payload = hexowatch.act(key, args.action, args.ids or None)
    target = "all monitors" if args.all else f"monitor(s) {', '.join(map(str, args.ids))}"
    _emit(payload, args.json, lambda _: print(f"{args.action} applied to {target}."))
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

    _emit(payload, args.json, render)
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

    _emit(payload, args.json, render)
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

    _emit(payload, args.json, render)
    return EXIT_OK


# --------------------------------------------------------------------------
# Hexomatic commands
# --------------------------------------------------------------------------

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

    _emit(payload, args.json, render)
    return EXIT_OK


def cmd_workflow(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    payload = hexomatic.get_workflow(key, args.workflow_id)
    _emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_workflow_logs(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    payload = hexomatic.workflow_logs(key, args.workflow_id)
    _emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_workflow_toggle(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMATIC)
    active = args.state == "enable"
    payload = hexomatic.set_active(key, args.ids, active)
    _emit(payload, args.json,
          lambda _: print(f"{args.state}d workflow(s) {', '.join(map(str, args.ids))}."))
    return EXIT_OK


# --------------------------------------------------------------------------
# Hexometer commands
# --------------------------------------------------------------------------

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

    _emit(payload, args.json, render)
    return EXIT_OK


def cmd_health(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMETER)
    if args.status is None:
        payload = hexometer.health_link_statuses(key, args.property_id)
    else:
        payload = hexometer.health_links(key, args.property_id, args.status)
    _emit(payload, True, lambda data: None)
    return EXIT_OK


def cmd_errors(args: argparse.Namespace) -> int:
    key = resolve_key(HEXOMETER)
    payload = hexometer.detected_errors(key, args.property_id, args.tool_name)
    _emit(payload, True, lambda data: None)
    return EXIT_OK


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def cmd_doctor(args: argparse.Namespace) -> int:
    """Prove each credential actually authenticates, without printing any key.

    A product with no credential configured is reported as ``skipped``, not as
    a failure -- these are three independent products and owning one does not
    imply owning the others.
    """
    checks = (
        ("hexowatch", HEXOWATCH, lambda key: hexowatch.list_monitored_urls(key)),
        ("hexomatic", HEXOMATIC, lambda key: hexomatic.list_workflows(key, limit=1)),
        ("hexometer", HEXOMETER, lambda key: hexometer.list_properties(key)),
    )
    results: dict[str, Any] = {}
    worst = EXIT_OK

    for label, service, probe in checks:
        try:
            key = resolve_key(service)
        except CredentialError:
            results[label] = {"ok": None, "stage": "skipped",
                              "detail": "no credential configured"}
            continue
        try:
            probe(key)
        except HexactAPIError as exc:
            results[label] = {"ok": False, "stage": "authentication", "detail": str(exc)}
            worst = EXIT_FAILURE
            continue
        results[label] = {"ok": True, "stage": "authenticated",
                          "detail": f"key resolved and accepted ({len(key)} chars)"}

    def render(data: dict[str, Any]) -> None:
        marks = {True: "OK  ", False: "FAIL", None: "SKIP"}
        for label, outcome in data.items():
            print(f"[{marks[outcome['ok']]}] {label}: {outcome['detail']}")

    _emit(results, args.json, render)
    return worst


# --------------------------------------------------------------------------
# GraphQL-only operations
#
# Everything below needs a session token rather than an API key, because the
# REST API has no delete and no update -- measured, not assumed. See
# hexact/graphql.py for the traps that shape this.
# --------------------------------------------------------------------------

def cmd_auth_login(args: argparse.Namespace) -> int:
    """Exchange email + password for a stored refresh token.

    The password is read from the terminal, never from a flag: argv is visible
    to every process on the machine and lands in shell history. It is used for
    one request and never written anywhere.
    """
    password = auth.prompt_password()
    if not password:
        print("No password entered; nothing was sent.", file=sys.stderr)
        return EXIT_USAGE

    refresh = auth.login(args.email, password)
    path = auth.store_refresh_token(refresh)

    # A receipt, deliberately not the token. Printing it would put a
    # full-account credential into terminal scrollback and any agent transcript.
    result = {"stored": str(path), "email": args.email, "token_length": len(refresh)}
    _emit(result, args.json, lambda d: print(
        f"Stored a refresh token for {d['email']} in {d['stored']} (owner-only).\n"
        f"The token itself was not printed. Verify with: hexact auth status"))
    return EXIT_OK


def cmd_auth_status(args: argparse.Namespace) -> int:
    """Report whether the stored token actually works.

    Distinguishes ``unknown`` (the gateway was unreachable) from ``rejected``
    (it answered and refused). Collapsing those is how a working credential
    gets rotated for no reason.
    """
    verdict, detail = auth.status()
    marks = {"authenticated": "OK  ", "rejected": "FAIL",
             "missing": "SKIP", "unknown": "????"}
    _emit({"verdict": verdict, "detail": detail}, args.json,
          lambda d: print(f"[{marks[d['verdict']]}] {d['verdict']}: {d['detail']}"))
    return EXIT_OK if verdict == "authenticated" else EXIT_FAILURE


def cmd_watch_show(args: argparse.Namespace) -> int:
    """One monitor's real configuration.

    REST returns four fields and no tool; this returns what the monitor is
    actually set to do, which is also what makes a subsequent write verifiable.
    """
    token = auth.access_token()
    monitor = graphql.get_watch_property(token, args.monitoring_id)
    try:
        monitor["integrations"] = graphql.get_watch_property_integrations(
            token, args.monitoring_id)
    except HexactAPIError as exc:
        monitor["integrations"] = None
        monitor["integrations_error"] = str(exc)

    def render(data: dict[str, Any]) -> None:
        for field in ("id", "name", "url", "tool", "active",
                      "change_notification_level", "createdAt"):
            print(f"  {field:28} {data.get(field)}")
        channels = (data.get("integrations") or {}).get("integrations")
        if channels is None:
            print(f"  {'integrations':28} unavailable: {data.get('integrations_error')}")
        else:
            print(f"  {'integrations':28} {len(channels)} attached")
            for channel in channels:
                label = channel.get("slackIntegration") or (
                    (channel.get("email") or {}).get("email")) or ""
                print(f"      [{channel.get('id')}] {channel.get('type')} {label}")

    _emit(monitor, args.json, render)
    return EXIT_OK


def cmd_watch_delete(args: argparse.Namespace) -> int:
    """Permanently delete monitors. Irreversible, so it asks first.

    Prints what each id actually is before doing anything: an id is not a
    recognisable thing, and "delete 337094" is not something anyone can sanity
    check without being told it means a duplicate meetup.com visual monitor.
    """
    # Refuse before touching the network. A command that will decline anyway has
    # no business spending a request, and this keeps the guard verifiable
    # without mocking a transport.
    if not args.yes:
        listed = " ".join(str(i) for i in args.ids)
        print(f"Refusing to delete {len(args.ids)} monitor(s) without --yes: {listed}\n"
              f"Hexowatch has no undo and no trash.\n"
              f"Inspect first:  hexact watch show {args.ids[0]}\n"
              f"Then:           hexact watch delete {listed} --yes", file=sys.stderr)
        return EXIT_USAGE

    token = auth.access_token()

    targets = []
    for monitoring_id in args.ids:
        try:
            monitor = graphql.get_watch_property(token, monitoring_id)
            targets.append({"id": monitoring_id, "url": monitor.get("url"),
                            "tool": monitor.get("tool"), "name": monitor.get("name")})
        except HexactAPIError as exc:
            targets.append({"id": monitoring_id, "url": None, "tool": None,
                            "error": str(exc)})

    graphql.delete_monitors(token, list(args.ids))

    # A mutation answering `{"error": false}` is a claim, not proof. Read each
    # id back: the delete is confirmed by the monitor no longer resolving.
    confirmed, still_present = [], []
    for target in targets:
        try:
            graphql.get_watch_property(token, target["id"])
            still_present.append(target["id"])
        except graphql.AuthError:
            confirmed.append(target["id"])
        except HexactAPIError:
            confirmed.append(target["id"])

    result = {"requested": list(args.ids), "deleted": confirmed,
              "still_present": still_present, "targets": targets}

    def render(data: dict[str, Any]) -> None:
        print(f"Deleted {len(data['deleted'])} of {len(data['requested'])} monitor(s), "
              f"confirmed by read-back.")
        for target in data["targets"]:
            state = "gone" if target["id"] in data["deleted"] else "STILL PRESENT"
            print(f"  {target['id']}  {state}  {target.get('url') or ''}")

    _emit(result, args.json, render)
    return EXIT_OK if not still_present else EXIT_FAILURE


def cmd_watch_retune(args: argparse.Namespace) -> int:
    """Change the alert threshold or interval on existing monitors.

    This is the lever the REST API never had. ``--level GE_5`` on the visual and
    content monitors is what addresses sub-1% alert noise at source, rather than
    filtering it after delivery.
    """
    if args.level is None and args.interval is None:
        raise ValueError("Nothing to change: pass --level and/or --interval.")

    token = auth.access_token()
    before = {}
    for monitoring_id in args.ids:
        try:
            monitor = graphql.get_watch_property(token, monitoring_id)
            before[monitoring_id] = {
                "tool": monitor.get("tool"),
                "change_notification_level": monitor.get("change_notification_level"),
            }
        except HexactAPIError as exc:
            before[monitoring_id] = {"error": str(exc)}

    graphql.update_monitors(
        token, list(args.ids),
        change_notification_level=args.level,
        monitoring_interval=args.interval,
    )

    # Read back. `GE_n`'s exact meaning is undocumented, so the one thing that
    # can be proven immediately is that the value persisted -- which is worth
    # proving, because a silently ignored setting looks identical to a working
    # one until the alerts keep arriving.
    changes = []
    for monitoring_id in args.ids:
        after = graphql.get_watch_property(token, monitoring_id)
        was = before.get(monitoring_id, {}).get("change_notification_level")
        now = after.get("change_notification_level")
        changes.append({"id": monitoring_id, "tool": after.get("tool"),
                        "level_before": was, "level_after": now,
                        "applied": (args.level is None) or (now == args.level)})

    result = {"requested_level": args.level, "requested_interval": args.interval,
              "changes": changes,
              "applied": sum(1 for c in changes if c["applied"])}

    def render(data: dict[str, Any]) -> None:
        print(f"{data['applied']} of {len(data['changes'])} monitor(s) confirmed by "
              f"read-back:\n")
        for change in data["changes"]:
            mark = "ok " if change["applied"] else "NOT APPLIED"
            print(f"  [{mark}] {change['id']}  {change['tool']}  "
                  f"{change['level_before']} -> {change['level_after']}")
        if data["requested_level"]:
            print("\n  The setting persisted. Whether it actually suppresses smaller "
                  "changes is undocumented and takes days of observation to confirm.")

    _emit(result, args.json, render)
    return EXIT_OK if result["applied"] == len(changes) else EXIT_FAILURE


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hexact",
        description="Agentic CLI for the Hexact suite (Hexowatch, Hexomatic).",
    )
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="verify credentials authenticate").set_defaults(
        func=cmd_doctor
    )

    watch = subparsers.add_parser("watch", help="Hexowatch: website change monitoring")
    watch_sub = watch.add_subparsers(dest="watch_command", required=True)

    watch_sub.add_parser("monitors", help="list monitors").set_defaults(func=cmd_monitors)
    watch_sub.add_parser("integrations", help="list notification channels").set_defaults(
        func=cmd_integrations
    )
    watch_sub.add_parser("duplicates", help="find monitors watching the same URL").set_defaults(
        func=cmd_duplicates
    )

    changes = watch_sub.add_parser("changes", help="recent detected changes")
    changes.add_argument("--since", default="24h", help="lookback window (default 24h)")
    changes.add_argument("--limit", type=int, default=10,
                         help="log entries per monitor (default 10)")
    changes.add_argument("--min-percent", type=float, default=None,
                         help="hide changes below this percent (noise filter; "
                              "visual monitors routinely fire at 0.06%%)")
    changes.add_argument("--all-scans", dest="changed_only", action="store_false",
                         help="include scans where nothing was detected")
    changes.set_defaults(func=cmd_changes, changed_only=True)

    scan = watch_sub.add_parser("scan", help="full diff for one scan result")
    scan.add_argument("scan_result_id")
    scan.add_argument("--tool", required=True, choices=hexowatch.SCAN_RESULT_TOOLS)
    scan.set_defaults(func=cmd_scan)

    for action in hexowatch.ACTIONS:
        sub = watch_sub.add_parser(action, help=f"{action} monitors")
        sub.add_argument("ids", nargs="*", type=int)
        sub.add_argument("--all", action="store_true", help="apply to every monitor")
        sub.set_defaults(func=cmd_action, action=action)

    create = watch_sub.add_parser("create", help="create a monitor")
    create.add_argument("--url", action="append", required=True, help="repeatable")
    create.add_argument("--tool", required=True, choices=hexowatch.TOOLS)
    create.add_argument("--interval", choices=hexowatch.INTERVALS,
                        help=f"default {hexowatch.DEFAULT_INTERVAL}")
    create.add_argument("--webhook")
    create.add_argument("--tag", action="append")
    create.add_argument("--level", help="change_notification_level; valid values "
                                        "differ per tool (see `hexact watch levels`)")
    create.add_argument("--silent", action="store_true",
                        help="record changes without notifying: sends "
                             "notification_integrations=[] and no webhook")
    create.set_defaults(func=cmd_create)

    watch_sub.add_parser(
        "levels", help="notification levels valid for each tool"
    ).set_defaults(func=cmd_levels)

    show = watch_sub.add_parser(
        "show", help="one monitor's real configuration (GraphQL; needs `auth login`)")
    show.add_argument("monitoring_id", type=int)
    show.set_defaults(func=cmd_watch_show)

    delete = watch_sub.add_parser(
        "delete", help="permanently delete monitors (GraphQL; needs `auth login`)")
    delete.add_argument("ids", nargs="+", type=int)
    delete.add_argument("--yes", action="store_true",
                        help="required: deletion is irreversible and has no trash")
    delete.set_defaults(func=cmd_watch_delete)

    retune = watch_sub.add_parser(
        "retune", help="change alert threshold or interval (GraphQL; needs `auth login`)")
    retune.add_argument("ids", nargs="+", type=int)
    retune.add_argument("--level", help="change_notification_level, e.g. GE_5 "
                                        "(see `hexact watch levels`)")
    retune.add_argument("--interval", choices=hexowatch.INTERVALS)
    retune.set_defaults(func=cmd_watch_retune)

    auth_parser = subparsers.add_parser(
        "auth", help="session tokens for the GraphQL gateway (delete/update)")
    auth_sub = auth_parser.add_subparsers(dest="auth_command", required=True)

    auth_login = auth_sub.add_parser(
        "login", help="prompt for a password and store a refresh token")
    auth_login.add_argument("--email", required=True)
    auth_login.set_defaults(func=cmd_auth_login)

    auth_sub.add_parser(
        "status", help="check whether the stored token is accepted"
    ).set_defaults(func=cmd_auth_status)

    matic = subparsers.add_parser("matic", help="Hexomatic: scraping and workflows")
    matic_sub = matic.add_subparsers(dest="matic_command", required=True)

    workflows = matic_sub.add_parser("workflows", help="list workflows")
    workflows.add_argument("--limit", type=int, default=50)
    workflows.set_defaults(func=cmd_workflows)

    workflow = matic_sub.add_parser("workflow", help="one workflow with results")
    workflow.add_argument("workflow_id", type=int)
    workflow.set_defaults(func=cmd_workflow)

    logs = matic_sub.add_parser("logs", help="workflow execution history")
    logs.add_argument("workflow_id", type=int)
    logs.set_defaults(func=cmd_workflow_logs)

    for state in ("enable", "disable"):
        sub = matic_sub.add_parser(state, help=f"{state} workflows")
        sub.add_argument("ids", nargs="+", type=int)
        sub.set_defaults(func=cmd_workflow_toggle, state=state)

    meter = subparsers.add_parser("meter", help="Hexometer: site health and SEO")
    meter_sub = meter.add_subparsers(dest="meter_command", required=True)

    meter_sub.add_parser("properties", help="list monitored properties").set_defaults(
        func=cmd_properties
    )

    health = meter_sub.add_parser("health", help="health links, or their statuses")
    health.add_argument("property_id", type=int)
    health.add_argument("--status", help="omit to list available statuses first")
    health.set_defaults(func=cmd_health)

    errors = meter_sub.add_parser("errors", help="errors detected by one tool")
    errors.add_argument("property_id", type=int)
    errors.add_argument("--tool-name", required=True, dest="tool_name",
                        help=f"e.g. {hexometer.EXAMPLE_TOOL_NAME}")
    errors.set_defaults(func=cmd_errors)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CredentialError as exc:
        print(f"Credential error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
    except auth.LoginError as exc:
        print(f"Login failed: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
    except graphql.AuthError as exc:
        # Ahead of HexactAPIError, which it subclasses, so the remedy stays
        # specific: an expired session token is not a generic API failure.
        print(f"Not authenticated: {exc}\nRun: hexact auth login --email <you>",
              file=sys.stderr)
        return EXIT_FAILURE
    except HexactAPIError as exc:
        print(f"API error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except ValueError as exc:
        print(f"Usage error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001
        # Last line of defence. An uncaught exception prints a traceback, and a
        # traceback that contains a URL contains the API key -- which is exactly
        # how a control character in an id leaked a live key to stderr before
        # `path_segment` existed. Never let an unexpected type reach the default
        # handler; a redacted message plus a non-zero exit is always safer.
        print(f"Unexpected {type(exc).__name__}: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
