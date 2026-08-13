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

    if args.store == "1password":
        reference = auth.store_refresh_token_1password(
            refresh, item_title=args.op_item, vault=args.op_vault)
        result = {"stored": reference, "backend": "1password", "email": args.email,
                  "next": f"export HEXOWATCH_REFRESH_OP_REF='{reference}'"}
        receipt = (f"Stored a refresh token for {result['email']} as "
                   f"{result['stored']}.\nThe token itself was not printed.\n\n"
                   f"  {result['next']}\n\nVerify with: hexact auth status")
    else:
        path = auth.store_refresh_token(refresh)
        result = {"stored": str(path), "backend": "file", "email": args.email,
                  "next": "hexact auth status"}
        receipt = (f"Stored a refresh token for {result['email']} in "
                   f"{result['stored']} (owner-only).\nThe token itself was not "
                   f"printed. Verify with: hexact auth status")

    # A receipt, deliberately not the token. Printing it would put a
    # full-account credential into terminal scrollback and any agent transcript.
    _emit(result, args.json, lambda d: print(receipt))
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
                      "change_notification_level", "monitoring_interval",
                      "alertCount", "createdAt"):
            print(f"  {field:28} {data.get(field)}")
        tags = data.get("tags") or []
        if tags:
            print(f"  {'tags':28} {', '.join(t.get('name', '') for t in tags)}")
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


def cmd_watch_channels(args: argparse.Namespace) -> int:
    """Every notification channel on the account, and what it is.

    Worth running before any mute: the account had two *separate* email
    channels registered, which means every alert was delivered twice and
    halving the noise needed no configuration change at all.
    """
    token = auth.access_token()
    result = graphql.get_user_integrations(token)
    channels = (result or {}).get("integrations") or []

    def render(data: dict[str, Any]) -> None:
        rows = data.get("integrations") or []
        if not rows:
            print("No notification channels registered.")
            return
        print(f"{len(rows)} channel(s):\n")
        for row in rows:
            # `email` is an object here, not a string -- selecting it as a
            # scalar is an HTTP 400, which is how this was found.
            email = (row.get("email") or {}).get("email") or ""
            label = row.get("slackIntegration") or email
            print(f"  [{row.get('id')}] {str(row.get('type')):8} {label}")
        emails = [r for r in rows if str(r.get("type")).lower() == "email"]
        if len(emails) > 1:
            print(f"\n  {len(emails)} separate email channels are registered, so any "
                  f"monitor attached to both is alerting you twice.")

    _emit({"integrations": channels}, args.json, render)
    return EXIT_OK


def cmd_watch_settings(args: argparse.Namespace) -> int:
    """Account-level notification settings — email recipients and webhooks."""
    token = auth.access_token()
    settings = graphql.get_watch_settings(token) or {}

    def render(data: dict[str, Any]) -> None:
        emails = data.get("emails") or []
        print(f"Email recipients ({len(emails)}):")
        for row in emails:
            state = "on " if row.get("enabled") else "OFF"
            verified = "" if row.get("verified") else "  (unverified)"
            print(f"  [{state}] {row.get('email')}{verified}")
        hooks = data.get("webhooks") or []
        print(f"\nAccount webhooks ({len(hooks)}):")
        for row in hooks:
            print(f"  {row.get('subscriptionId')}  type={row.get('type')}")
        if not hooks:
            print("  none — `hexact watch webhook set URL` to add one")

    _emit(settings, args.json, render)
    return EXIT_OK


def cmd_watch_email(args: argparse.Namespace) -> int:
    """Turn account-wide notification email on or off.

    The blunt instrument, and often the right one. `watch mute` detaches
    channels from one monitor; this stops notification email for the whole
    account in a single call, including the default delivery that fires for
    monitors with no channel attached at all.
    """
    token = auth.access_token()
    graphql.set_email_notifications(token, args.enable)

    # Read back against the account settings, not the mutation envelope.
    settings = graphql.get_watch_settings(token) or {}
    emails = settings.get("emails") or []
    still_on = [e.get("email") for e in emails if e.get("enabled")]
    payload = {"requested": "on" if args.enable else "off",
               "recipients_enabled": still_on, "recipients": emails}

    def render(data: dict[str, Any]) -> None:
        if args.enable:
            print(f"Notification email ON. Enabled recipients: "
                  f"{', '.join(data['recipients_enabled']) or 'none'}")
            return
        if data["recipients_enabled"]:
            print("Requested OFF, but these recipients still read as enabled:")
            for address in data["recipients_enabled"]:
                print(f"  {address}")
            print("\nThe account switch and the per-recipient flags are separate "
                  "settings; this reports what the server says, not what was asked.")
        else:
            print("Notification email OFF for the whole account. "
                  "Monitors keep checking and keep recording changes.")

    _emit(payload, args.json, render)
    if args.enable:
        return EXIT_OK
    return EXIT_OK if not still_on else EXIT_FAILURE


def cmd_watch_webhook(args: argparse.Namespace) -> int:
    """Manage the account-level webhook — fires for every monitor.

    With one of these pointed at an endpoint you control, every change arrives
    as structured JSON and email becomes optional rather than the only channel.
    """
    token = auth.access_token()
    if args.webhook_action == "set":
        graphql.set_account_webhook(token, args.url)
    elif args.webhook_action == "clear":
        graphql.remove_account_webhook(token, args.subscription_id)

    settings = graphql.get_watch_settings(token) or {}
    hooks = settings.get("webhooks") or []

    def render(data: dict[str, Any]) -> None:
        print(f"Account webhooks ({len(data['webhooks'])}):")
        for row in data["webhooks"]:
            print(f"  {row.get('subscriptionId')}  type={row.get('type')}")
        if not data["webhooks"]:
            print("  none")

    _emit({"webhooks": hooks}, args.json, render)
    return EXIT_OK


def cmd_watch_mute(args: argparse.Namespace) -> int:
    """Silence monitors that already exist, or restore their channels.

    The distinction this command exists for: muting is *not* pausing. A paused
    monitor stops checking, loses its history continuity, and stops being a
    record of anything. A muted monitor keeps checking on schedule and keeps
    recording every change -- it just stops routing them to a channel. "Keep
    tracking, stop notifying" is only expressible this way.

    Unmute takes explicit channel ids rather than restoring a remembered set:
    the previous set is not stored anywhere, and inventing one would be worse
    than asking.
    """
    token = auth.access_token()
    targets = [int(i) for i in args.ids]
    channel_ids = [] if args.mute else [int(i) for i in args.channels]

    if not args.mute and not channel_ids:
        raise ValueError(
            "unmute needs at least one --channel id. Run `hexact watch channels` "
            "to list them; there is no stored record of what a monitor used to "
            "notify, so it cannot be restored automatically."
        )

    results = []
    for monitoring_id in targets:
        entry: dict[str, Any] = {"id": monitoring_id}
        try:
            graphql.set_monitor_integrations(token, monitoring_id, channel_ids)
        except HexactAPIError as exc:
            entry["error"] = str(exc)
            results.append(entry)
            continue
        # Read back, for the same reason every other write here does: the
        # envelope's `error: false` is the server's opinion, not evidence.
        try:
            after = graphql.get_watch_property_integrations(token, monitoring_id)
            attached = [c.get("id") for c in (after or {}).get("integrations") or []]
            entry["attached_after"] = attached
            entry["applied"] = sorted(attached) == sorted(channel_ids)
        except HexactAPIError as exc:
            entry["applied"] = None
            entry["verify_error"] = str(exc)
        results.append(entry)

    verb = "Muted" if args.mute else "Unmuted"
    applied = sum(1 for r in results if r.get("applied"))
    payload = {"action": "mute" if args.mute else "unmute",
               "channels": channel_ids, "results": results, "applied": applied}

    def render(data: dict[str, Any]) -> None:
        print(f"{verb} {applied} of {len(results)} monitor(s), confirmed by read-back:\n")
        for row in data["results"]:
            if row.get("error"):
                state = f"FAILED: {row['error']}"
            elif row.get("applied") is None:
                state = f"UNVERIFIED: {row.get('verify_error')}"
            elif row["applied"]:
                state = f"{len(row['attached_after'])} channel(s) attached"
            else:
                state = f"NOT APPLIED (still {row.get('attached_after')})"
            print(f"  {row['id']}  {state}")
        if args.mute and applied:
            print("\n  These keep checking and keep recording changes. Whether an "
                  "empty channel list also stops the account's default email is "
                  "undocumented -- watch the inbox for a day to find out.")

    _emit(payload, args.json, render)
    return EXIT_OK if applied == len(results) else EXIT_FAILURE


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
    # id back.
    #
    # Two things this loop got wrong when it was first run against the live
    # server, both of which reported the opposite of the truth:
    #
    # 1. A deleted monitor does NOT stop resolving. `getWatchProperty` returns a
    #    perfectly normal object with every field null, so "the call returned"
    #    meant "still present" and a successful delete printed STILL PRESENT and
    #    exited non-zero. Absence is `id is None`, not an exception.
    # 2. An `AuthError` was counted as proof of deletion. A token expiring
    #    mid-loop would therefore report every monitor successfully deleted --
    #    the failure mode that most needs to be loud, silently reported as
    #    success. Auth failure proves nothing; it goes in its own bucket.
    confirmed, still_present, unverified = [], [], []
    for target in targets:
        try:
            monitor = graphql.get_watch_property(token, target["id"])
        except graphql.AuthError as exc:
            unverified.append({"id": target["id"], "reason": str(exc)})
            continue
        except HexactAPIError as exc:
            # NOT proof of absence. This branch used to count any API error as
            # a successful delete, and it fired for real: a malformed selection
            # in the read-back query returned HTTP 400, and every delete
            # reported "gone" on the strength of a syntax error. The only
            # evidence of absence is a query that SUCCEEDS and returns a null
            # id. Anything else is unverified.
            unverified.append({"id": target["id"], "reason": str(exc)})
            continue
        if not monitor or monitor.get("id") in (None, "", 0):
            confirmed.append(target["id"])
        else:
            still_present.append(target["id"])

    result = {"requested": list(args.ids), "deleted": confirmed,
              "still_present": still_present, "unverified": unverified,
              "targets": targets}

    def render(data: dict[str, Any]) -> None:
        print(f"Deleted {len(data['deleted'])} of {len(data['requested'])} monitor(s), "
              f"confirmed by read-back.")
        unverified_ids = {u["id"] for u in data["unverified"]}
        for target in data["targets"]:
            if target["id"] in data["deleted"]:
                state = "gone"
            elif target["id"] in unverified_ids:
                state = "UNVERIFIED (auth failed during read-back)"
            else:
                state = "STILL PRESENT"
            print(f"  {target['id']}  {state}  {target.get('url') or ''}")

    _emit(result, args.json, render)
    if still_present or unverified:
        return EXIT_FAILURE
    return EXIT_OK


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
                "monitoring_interval": monitor.get("monitoring_interval"),
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
    #
    # Verify every field that was actually requested. An earlier version checked
    # only `change_notification_level`, so `retune --interval 1_MONTH` compared
    # the level to itself, found it unchanged-as-expected, and printed
    # "confirmed by read-back: ANY -> ANY" without ever looking at the interval.
    # A confirmation that does not read the field it changed is worse than none.
    changes = []
    for monitoring_id in args.ids:
        after = graphql.get_watch_property(token, monitoring_id)
        prior = before.get(monitoring_id, {})
        entry = {
            "id": monitoring_id,
            "tool": after.get("tool"),
            "level_before": prior.get("change_notification_level"),
            "level_after": after.get("change_notification_level"),
            "interval_before": prior.get("monitoring_interval"),
            "interval_after": after.get("monitoring_interval"),
        }
        checks = []
        if args.level is not None:
            checks.append(entry["level_after"] == args.level)
        if args.interval is not None:
            checks.append(entry["interval_after"] == args.interval)
        entry["applied"] = all(checks) if checks else False
        changes.append(entry)

    result = {"requested_level": args.level, "requested_interval": args.interval,
              "changes": changes,
              "applied": sum(1 for c in changes if c["applied"])}

    def render(data: dict[str, Any]) -> None:
        print(f"{data['applied']} of {len(data['changes'])} monitor(s) confirmed by "
              f"read-back:\n")
        for change in data["changes"]:
            mark = "ok " if change["applied"] else "NOT APPLIED"
            moved = []
            if data["requested_level"] is not None:
                moved.append(f"level {change['level_before']} -> {change['level_after']}")
            if data["requested_interval"] is not None:
                moved.append(
                    f"interval {change['interval_before']} -> {change['interval_after']}"
                )
            print(f"  [{mark}] {change['id']}  {change['tool']}  "
                  f"{'; '.join(moved)}")
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

    watch_sub.add_parser(
        "channels",
        help="list the account's notification channels (GraphQL; needs `auth login`)"
    ).set_defaults(func=cmd_watch_channels)

    watch_sub.add_parser(
        "settings", help="account-level notification settings (email + webhooks)"
    ).set_defaults(func=cmd_watch_settings)

    email = watch_sub.add_parser(
        "email", help="turn account-wide notification EMAIL on or off")
    email_state = email.add_mutually_exclusive_group(required=True)
    email_state.add_argument("--off", dest="enable", action="store_false",
                             help="stop all notification email for the account")
    email_state.add_argument("--on", dest="enable", action="store_true",
                             help="resume notification email")
    email.set_defaults(func=cmd_watch_email)

    webhook = watch_sub.add_parser(
        "webhook", help="account-level webhook — fires for every monitor")
    webhook_sub = webhook.add_subparsers(dest="webhook_action", required=True)
    webhook_sub.add_parser("show").set_defaults(func=cmd_watch_webhook)
    webhook_set = webhook_sub.add_parser("set")
    webhook_set.add_argument("url")
    webhook_set.set_defaults(func=cmd_watch_webhook)
    webhook_clear = webhook_sub.add_parser("clear")
    webhook_clear.add_argument("subscription_id")
    webhook_clear.set_defaults(func=cmd_watch_webhook)

    mute = watch_sub.add_parser(
        "mute",
        help="stop an EXISTING monitor notifying, without pausing its checks")
    mute.add_argument("ids", nargs="+", type=int)
    mute.set_defaults(func=cmd_watch_mute, mute=True, channels=[])

    unmute = watch_sub.add_parser(
        "unmute", help="attach notification channels back to a monitor")
    unmute.add_argument("ids", nargs="+", type=int)
    unmute.add_argument("--channel", dest="channels", action="append", default=[],
                        type=int, metavar="ID",
                        help="repeatable; see `hexact watch channels`")
    unmute.set_defaults(func=cmd_watch_mute, mute=False)

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
    auth_login.add_argument("--store", choices=("1password", "file"), default="1password",
                            help="where to keep the refresh token (default 1password)")
    auth_login.add_argument("--op-vault", default="Agent Automation",
                            help="1Password vault (default 'Agent Automation')")
    auth_login.add_argument("--op-item", default="Hexowatch Session - refresh token",
                            help="1Password item title")
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
