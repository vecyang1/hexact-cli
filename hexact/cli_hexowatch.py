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
from .output import EXIT_OK, EXIT_USAGE, emit


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
        print("\nFilter monitors by one:  hexact watch monitors --tag <id>")

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
