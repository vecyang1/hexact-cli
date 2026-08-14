"""Command-line interface for the Hexact suite.

Every command accepts ``--json`` so an agent can consume the raw payload, while
the default rendering stays readable for a human. Exit codes are meaningful:
0 success, 1 an API or credential failure, 2 a usage error.

**This module is the parser and the top-level error handler, and nothing else.**
Command bodies live in per-product modules -- `cli_watch_rest`, `cli_hexowatch`,
`cli_hexomatic`, `cli_hexometer`, `cli_hexospark`, `cli_auth` -- with the shared
rendering helpers in `cli_common`. They are imported by name here because the
parser genuinely refers to each of them, and a reader tracing `hexact watch
noise` should land on the function, not on a lookup table.

`doctor` is the exception that stays: it is the one command that is about the
CLI itself rather than about a product, and it has to know all three.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__, auth, graphql, hexomatic, hexometer, hexowatch
from .cli_auth import cmd_auth_login, cmd_auth_status
from .cli_hexomatic import (
    cmd_credits, cmd_results, cmd_workflow, cmd_workflow_logs,
    cmd_workflow_toggle, cmd_workflows, cmd_workflows_detailed,
)
from .cli_hexometer import cmd_errors, cmd_health, cmd_issues, cmd_overview, cmd_properties
from .cli_hexospark import cmd_campaigns, cmd_contacts
from .cli_hexowatch import (
    cmd_alerts, cmd_monitors_full, cmd_noise, cmd_tag_create, cmd_tag_delete,
    cmd_tag_set, cmd_tags, cmd_watch_channels, cmd_watch_delete, cmd_watch_email,
    cmd_watch_mute, cmd_watch_retune, cmd_watch_settings, cmd_watch_show,
    cmd_watch_webhook,
)
from .cli_watch_rest import (
    cmd_action, cmd_changes, cmd_create, cmd_duplicates, cmd_integrations,
    cmd_levels, cmd_monitors, cmd_scan,
)
from .config import HEXOMATIC, HEXOMETER, HEXOWATCH, CredentialError, resolve_key
from .http import HexactAPIError, redact
from .output import EXIT_FAILURE, EXIT_OK, EXIT_USAGE, emit


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def cmd_doctor(args: argparse.Namespace) -> int:
    """Prove each credential actually authenticates, without printing any key.

    Covers four credentials: the three REST API keys and the gateway session
    that every GraphQL command needs. A product with no credential configured
    is reported as ``skipped``, not as a failure -- these are independent
    products and owning one does not imply owning the others.

    But *every* product skipped is a different answer again. Until 0.7.0 this
    exited ``0`` after examining nothing, and the README's quickstart ran it
    immediately after ``pipx install`` -- so the very first command a new user
    ran printed three ``SKIP`` lines and a success, before any credential
    existed. That is the project's own "check the denominator" rule failing in
    its own front door: a run that verified zero things must never be phrased
    as a pass. Three outcomes now, matching ``tools/validate_documents.py``:
    ``0`` something authenticated, ``1`` something was refused, ``2`` nothing
    was checked.
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

    # The gateway is not a fourth product, it is the other half of this one.
    # doctor probed three REST keys and stopped, so an account with all three
    # configured printed [OK] [OK] [OK] and exited 0 while every GraphQL
    # command -- `watch list`, `spark contacts`, `meter overview`, over half
    # the read surface -- failed on a credential nothing had looked at.
    verdict, detail = auth.status()
    results["gateway"] = {
        "ok": {"authenticated": True, "rejected": False}.get(verdict),
        "stage": verdict,
        "detail": detail.splitlines()[0] if detail else verdict,
    }
    if verdict == "rejected":
        worst = EXIT_FAILURE

    def render(data: dict[str, Any]) -> None:
        marks = {True: "OK  ", False: "FAIL", None: "SKIP"}
        for label, outcome in data.items():
            print(f"[{marks[outcome['ok']]}] {label}: {outcome['detail']}")

    emit(results, args.json, render)

    if worst == EXIT_OK and not any(o["ok"] for o in results.values()):
        # stderr, so `--json` stays a clean pipe while a human still sees that
        # the tick underneath means nothing. Flush first: the two streams
        # buffer differently, and without this the summary printed *above* the
        # lines it is summarising whenever output was captured rather than a tty.
        sys.stdout.flush()
        print(
            "\nNo verdict: no credential was configured for any product, so "
            "nothing was verified.\nThis is not a pass. Set at least one key "
            "and run again:\n"
            "  export HEXOWATCH_API_KEY=...        # or HEXOMATIC_/HEXOMETER_\n"
            "  export HEXOWATCH_OP_REF='op://Vault/Item/field'   # 1Password\n"
            "Then: hexact doctor",
            file=sys.stderr,
        )
        return EXIT_USAGE
    return worst


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hexact",
        description="Agentic CLI for the Hexact suite (Hexowatch, Hexomatic).",
    )
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    # Read from __init__ rather than typed here. A CLI that cannot say which
    # build it is makes every bug report start with a guess, and a version
    # string maintained in a second place eventually disagrees with the first
    # -- which already happened to this project's User-Agent.
    parser.add_argument("--version", action="version",
                        version=f"hexact {__version__}")
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
    changes.add_argument(
        "--since", default="24h",
        help="lookback duration: h/d/w/m where m is MONTHS (24h, 7d, 2w, 3m). "
             "No minute form. Default 24h.")
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

    # --- Gateway-only Hexowatch surface (tags, filtered listing, alerts) ---
    tags = watch_sub.add_parser(
        "tags", help="monitor tags — REST has no tag concept at all")
    tags_sub = tags.add_subparsers(dest="tag_action", required=True)
    tags_sub.add_parser("list", help="every tag on the account").set_defaults(
        func=cmd_tags)
    tag_create = tags_sub.add_parser("create", help="create a tag")
    tag_create.add_argument("--name", required=True)
    tag_create.add_argument("--color", required=True, metavar="HEX",
                            help="e.g. '#4c8bf5'")
    tag_create.set_defaults(func=cmd_tag_create)
    tag_delete = tags_sub.add_parser("delete", help="delete a tag account-wide")
    tag_delete.add_argument("tag_id", type=int)
    tag_delete.set_defaults(func=cmd_tag_delete)
    tag_set = tags_sub.add_parser(
        "set", help="REPLACE one monitor's tags with exactly this list")
    tag_set.add_argument("monitoring_id", type=int)
    tag_set.add_argument("--tag", dest="tags", action="append", default=[],
                         type=int, metavar="ID", help="repeatable")
    tag_set.add_argument("--clear", action="store_true",
                         help="required to remove every tag; an empty --tag "
                              "list is refused so a replace cannot wipe tags "
                              "by accident")
    tag_set.set_defaults(func=cmd_tag_set)

    full = watch_sub.add_parser(
        "list",
        help="monitors with tool, interval and tags, filtered server-side "
             "(GraphQL; needs `auth login`)")
    full.add_argument("--tag", dest="tags", action="append", default=[],
                      type=int, metavar="ID", help="repeatable")
    full.add_argument("--tool", choices=hexowatch.TOOLS)
    full.add_argument("--search", metavar="TEXT")
    full.add_argument("--page", type=int, default=1)
    full.add_argument("--limit", type=int, default=50)
    state = full.add_mutually_exclusive_group()
    state.add_argument("--active", dest="active", action="store_true", default=None)
    state.add_argument("--paused", dest="active", action="store_false")
    full.set_defaults(func=cmd_monitors_full)

    noise = watch_sub.add_parser(
        "noise", help="notification volume, counted by the server")
    noise.add_argument(
        "--since", metavar="DATE",
        help="calendar date, sent to the gateway as-is (e.g. 2026-08-01). "
             "Not a duration -- `watch changes --since` is the one that is.")
    noise.add_argument("--until", metavar="DATE")
    noise.set_defaults(func=cmd_noise)

    alerts = watch_sub.add_parser(
        "alerts", help="the dashboard's alert inbox — untouchable from REST")
    alerts_sub = alerts.add_subparsers(dest="alert_action", required=True)
    alerts_read = alerts_sub.add_parser("read", help="mark alerts as read")
    read_scope = alerts_read.add_mutually_exclusive_group(required=True)
    read_scope.add_argument("--all", action="store_true",
                            help="every alert on the account")
    read_scope.add_argument("--id", dest="ids", action="append", default=[],
                            type=int, metavar="ID", help="repeatable")
    alerts_read.set_defaults(func=cmd_alerts, yes=False)
    alerts_delete = alerts_sub.add_parser("delete", help="delete alerts")
    alerts_delete.add_argument("--id", dest="ids", action="append", default=[],
                               type=int, metavar="ID", required=True)
    alerts_delete.add_argument("--yes", action="store_true",
                               help="required: deleting alerts is irreversible")
    alerts_delete.set_defaults(func=cmd_alerts, all=False)

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
    auth_login.add_argument(
        "--password-stdin", action="store_true",
        help="read the password from stdin instead of prompting, for runs with "
             "no terminal; keeps it out of argv and shell history")
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

    # --- Gateway-only Hexomatic surface (credit burn, actual output) ---
    credits = matic_sub.add_parser(
        "credits",
        help="automation credit consumption — absent from REST entirely "
             "(GraphQL; needs `auth login`)")
    credits.add_argument("--series", action="store_true",
                         help="consumption over time instead of the totals")
    credits.add_argument(
        "--since", metavar="DATE",
        help="calendar date, sent to the gateway as-is (e.g. 2026-08-01). "
             "Not a duration -- `watch changes --since` is the one that is.")
    credits.add_argument("--until", metavar="DATE")
    credits.set_defaults(func=cmd_credits)

    detailed = matic_sub.add_parser(
        "detail", help="workflows with credit cost, schedule and status")
    detailed.set_defaults(func=cmd_workflows_detailed)

    results = matic_sub.add_parser(
        "results",
        help="what a workflow actually produced — REST returns only its logs")
    results.add_argument("workflow_id", type=int)
    results.add_argument("--url", action="store_true",
                         help="return a link to the full JSON instead of an "
                              "inline preview; the file is not downloaded")
    results.set_defaults(func=cmd_results)

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

    # Gateway-served Hexometer reads. REST needs a per-property key and cannot
    # list properties at all, so these are the only way to enumerate them.
    meter_sub.add_parser(
        "overview",
        help="every property with its open-issue counts (GraphQL; needs `auth login`)"
    ).set_defaults(func=cmd_overview)
    issues = meter_sub.add_parser("issues", help="detected issues, paged")
    issues.add_argument("--page", type=int, default=1)
    issues.add_argument("--limit", type=int, default=50)
    issues.add_argument("--tool", metavar="NAME")
    issues.set_defaults(func=cmd_issues)

    # Hexospark has no REST API at all -- these exist only here. Reads only:
    # the campaign writes send mail to real people and are refused by the
    # mutation allowlist.
    spark = subparsers.add_parser(
        "spark", help="Hexospark: CRM and outreach (GraphQL only; no REST API exists)")
    spark_sub = spark.add_subparsers(dest="spark_command", required=True)
    contacts = spark_sub.add_parser(
        "contacts", help="CRM contacts with their outreach counters")
    contacts.add_argument("--campaign", metavar="ID")
    contacts.add_argument("--search", metavar="TEXT")
    contacts.set_defaults(func=cmd_contacts)
    campaigns = spark_sub.add_parser(
        "campaigns", help="outreach campaigns with schedule and status")
    campaigns.add_argument("--search", metavar="TEXT")
    campaigns.set_defaults(func=cmd_campaigns)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CredentialError as exc:
        print(f"Credential error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
    except auth.SessionError as exc:
        # Ahead of LoginError, which it subclasses. Thirteen commands reach the
        # gateway through `auth.access_token()` without anyone logging in, and
        # labelling those "Login failed" told the reader their credentials had
        # been rejected at a login they never performed.
        print(f"Session error: {redact(str(exc))}", file=sys.stderr)
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
