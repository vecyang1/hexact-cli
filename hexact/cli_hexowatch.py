"""Hexowatch commands that only the GraphQL gateway can serve.

Three capabilities REST has no concept of at all -- not undocumented, absent:

**Tags.** The account runs 48 monitors with no grouping. `WatchTagOps` creates
them and `Watch.getUserWatchProperties(tags:)` filters by them, which makes them
the only server-side way to ask about a subset of monitors instead of matching
URLs by hand.

**A real monitor listing.** REST's `v1/monitored_urls` returns id, address, name
and paused for everything at once -- no tool, no interval, no tags, no total, no
filter. This returns all of that, filtered and paged by the server.

**The alert inbox.** The dashboard's unread list is a separate thing from
monitors and from changes, and nothing in REST touches it.

New commands live here rather than in `cli.py` because that file is already
well past the 800-line ceiling this project sets for itself. Splitting by
product is the direction; this is the first module of it.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import auth, graphql
from .cli_common import reject_duration_for_a_date_flag
from .http import HexactAPIError
from .output import EXIT_FAILURE, EXIT_OK, EXIT_USAGE, emit


def cmd_tags(args: argparse.Namespace) -> int:
    """Every tag on the account, with the ids the monitor filter takes."""
    token = auth.access_token()
    result = graphql.get_user_tags(token) or {}
    tags = result.get("tags") or []

    def render(data: dict[str, Any]) -> None:
        rows = data.get("tags") or []
        if not rows:
            print("No tags on this account.\n"
                  "  Create one:  hexact watch tags create --name staging --color '#4c8bf5'")
            return
        print(f"{len(rows)} tag(s):\n")
        for row in rows:
            print(f"  [{row.get('id')}] {str(row.get('name')):24} {row.get('color')}")
        # `watch monitors` is the REST listing and takes no options at all;
        # tags exist only on the gateway, so `watch list` is the one that
        # filters. Printed for months as a command that exits 2.
        print("\nFilter monitors by one:  hexact watch list --tag <id>")

    emit({"tags": tags}, args.json, render)
    return EXIT_OK


def cmd_tag_create(args: argparse.Namespace) -> int:
    """Create a tag, then read the account's tags back to prove it exists.

    The gateway answers `{"error": false}` for a create, which is a claim. The
    read-back is what makes it evidence, and it is the project's rule for every
    other write.
    """
    token = auth.access_token()
    created = graphql.create_tag(token, args.name, args.color)
    tag_id = created.get("watch_tag_id")

    after = (graphql.get_user_tags(token) or {}).get("tags") or []
    confirmed = next((t for t in after if t.get("id") == tag_id), None)

    def render(data: dict[str, Any]) -> None:
        if data["confirmed"]:
            tag = data["confirmed"]
            print(f"Created tag [{tag['id']}] {tag['name']} {tag['color']}, "
                  f"confirmed by reading the account's tags back.")
        else:
            print(f"The gateway reported success for tag id {data['watch_tag_id']}, "
                  f"but it is not in the account's tag list. Treat it as not created.")

    emit({"watch_tag_id": tag_id, "confirmed": confirmed}, args.json, render)
    return EXIT_OK if confirmed else EXIT_USAGE


def cmd_tag_delete(args: argparse.Namespace) -> int:
    """Delete a tag account-wide, and confirm it is gone."""
    token = auth.access_token()
    graphql.delete_tag(token, args.tag_id)
    after = (graphql.get_user_tags(token) or {}).get("tags") or []
    still_there = any(t.get("id") == args.tag_id for t in after)

    emit(
        {"tag_id": args.tag_id, "deleted": not still_there},
        args.json,
        lambda d: print(
            f"Tag {d['tag_id']} deleted; the account's tag list no longer contains it."
            if d["deleted"] else
            f"Tag {d['tag_id']} is still present after the delete. Nothing was removed."
        ),
    )
    return EXIT_OK if not still_there else EXIT_USAGE


def cmd_tag_set(args: argparse.Namespace) -> int:
    """Replace one monitor's tags with exactly the given list.

    A replace, like `updateWatchPropertyIntegrations` -- passing no `--tag`
    clears every tag on the monitor. That is a real operation, so it is allowed,
    but it has to be asked for explicitly rather than being what an empty
    argument list happens to do.
    """
    if not args.tags and not args.clear:
        print("No --tag given. This mutation REPLACES the monitor's tags, so an "
              "empty list would remove all of them. Pass --clear if that is what "
              "you mean.", file=sys.stderr)
        return EXIT_USAGE

    token = auth.access_token()
    graphql.set_property_tags(token, args.monitoring_id, args.tags)
    after = (graphql.get_property_tags(token, args.monitoring_id) or {}).get("tags") or []
    names = [t.get("name") for t in after]

    emit(
        {"monitoring_id": args.monitoring_id, "tags": after},
        args.json,
        lambda d: print(
            f"Monitor {d['monitoring_id']} now carries {len(d['tags'])} tag(s): "
            f"{', '.join(names) if names else '(none)'}"
        ),
    )
    return EXIT_OK


def cmd_monitors_full(args: argparse.Namespace) -> int:
    """Monitors with tool, interval and tags, filtered and paged server-side."""
    token = auth.access_token()
    result = graphql.list_monitors(
        token, page=args.page, limit=args.limit, active=args.active,
        search=args.search, tags=args.tags or None, tool=args.tool,
    )
    rows = (result or {}).get("watchProperties") or []
    total = (result or {}).get("totalCount")

    def render(data: dict[str, Any]) -> None:
        shown = data.get("watchProperties") or []
        print(f"{len(shown)} of {data.get('totalCount')} monitor(s) "
              f"(page {args.page}, limit {args.limit}):\n")
        for row in shown:
            tags = ", ".join(t.get("name", "") for t in (row.get("tags") or []))
            state = "active" if row.get("active") else "paused"
            print(f"  [{row.get('id')}] {state:6} {str(row.get('tool')):26} "
                  f"{str(row.get('monitoring_interval') or ''):12} {row.get('url')}")
            if tags:
                print(f"      tags: {tags}")

    emit({"totalCount": total, "watchProperties": rows}, args.json, render)
    return EXIT_OK


def cmd_noise(args: argparse.Namespace) -> int:
    """Notification volume grouped by the gateway's own categories.

    The account's measured problem is alert volume, and it was previously
    counted client-side by pulling every change and grouping in Python. The
    server keeps the same figures per period.
    """
    reject_duration_for_a_date_flag(args.since)
    reject_duration_for_a_date_flag(args.until)
    token = auth.access_token()
    rows = graphql.notification_breakdown(token, since=args.since, until=args.until) or []

    def render(data: list[dict[str, Any]]) -> None:
        if not data:
            print("The gateway returned no notification breakdown for that period.")
            return
        total = sum(int(r.get("count") or 0) for r in data)
        print(f"{total} notification(s)"
              + (f" from {args.since}" if args.since else "")
              + (f" to {args.until}" if args.until else "") + ":\n")
        for row in sorted(data, key=lambda r: -int(r.get("count") or 0)):
            count = int(row.get("count") or 0)
            share = (count / total * 100) if total else 0
            print(f"  {str(row.get('field')):32} {count:6}  {share:5.1f}%")

    emit(rows, args.json, render)
    return EXIT_OK


def cmd_alerts(args: argparse.Namespace) -> int:
    """Mark alerts read, or delete them. Monitors and history are untouched."""
    # Before the credential, not after. `delete` used to resolve a token first
    # and only then check `--yes`, so an unconfirmed delete still reached the
    # network and failed for the wrong reason -- and the unit test missed it,
    # because it mocked `access_token` and therefore could not observe the
    # ordering at all. A refusal must cost nothing.
    if args.alert_action == "delete" and not args.yes:
        print("Deleting alerts is irreversible. Re-run with --yes.", file=sys.stderr)
        return EXIT_USAGE

    token = auth.access_token()

    if args.alert_action == "read":
        if args.all:
            result = graphql.mark_all_alerts_read(token)
            summary = "every alert on the account marked read"
        else:
            result = graphql.mark_alerts_read(token, args.ids)
            summary = f"{len(args.ids)} alert(s) marked read"
    else:
        result = graphql.delete_alerts(token, args.ids)
        summary = f"{len(args.ids)} alert(s) deleted"

    # No read-back here, deliberately. The alert inbox has no list query on this
    # gateway (`WatchAlert.get` takes a single monitoringLog reference), so
    # there is nothing to re-read; saying so beats implying a confirmation that
    # did not happen.
    emit({"action": args.alert_action, "result": result, "verified": False},
         args.json,
         lambda d: print(f"{summary}. The gateway reported success; this could "
                         f"not be confirmed by reading back, because the alert "
                         f"inbox has no list query."))
    return EXIT_OK


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

    emit(monitor, args.json, render)
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

    emit({"integrations": channels}, args.json, render)
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

    emit(settings, args.json, render)
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

    emit(payload, args.json, render)
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

    emit({"webhooks": hooks}, args.json, render)
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
    # Usage before credentials. `watch delete`, `watch alerts delete` and
    # `watch tags set` all refuse first and this one did not, so forgetting
    # --channel with nothing configured produced a credential error about the
    # wrong thing -- and with a working credential, paid a round trip to say no.
    targets = [int(i) for i in args.ids]
    channel_ids = [] if args.mute else [int(i) for i in args.channels]

    if not args.mute and not channel_ids:
        raise ValueError(
            "unmute needs at least one --channel id. Run `hexact watch channels` "
            "to list them; there is no stored record of what a monitor used to "
            "notify, so it cannot be restored automatically."
        )

    token = auth.access_token()
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

    emit(payload, args.json, render)
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

    emit(result, args.json, render)
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

    emit(result, args.json, render)
    return EXIT_OK if result["applied"] == len(changes) else EXIT_FAILURE
