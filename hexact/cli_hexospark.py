"""Hexospark commands. Read-only, by design.

`docs/API.md` says Hexospark publishes no REST API, and that is true. What it
could not see is that the shared gateway carries the whole product, so the CRM
and its campaigns are reachable after all.

Only reads are wired. The writes exist -- create a campaign, attach contacts,
add steps -- and they put mail in front of real people, which is not something a
client an agent can drive unattended should be able to do. `hexact.graphql`'s
allowlist refuses every Hexospark mutation, so the boundary holds even if this
file changes.
"""

from __future__ import annotations

import argparse
from typing import Any

from . import auth, hexospark
from .output import EXIT_OK, emit


def cmd_contacts(args: argparse.Namespace) -> int:
    """CRM contacts with their per-contact outreach counters."""
    token = auth.access_token()
    result = hexospark.crm_contacts(
        token, campaign_id=args.campaign, filter_text=args.search) or {}
    rows = result.get("contacts") or []

    def render(data: dict[str, Any]) -> None:
        contacts = data.get("contacts") or []
        print(f"{len(contacts)} of {data.get('count')} contact(s):\n")
        for row in contacts:
            name = " ".join(filter(None, [row.get("firstName"), row.get("lastName")]))
            step = f"{row.get('currentStep')}/{row.get('totalStep')}"
            print(f"  [{row.get('id')}] {str(row.get('email')):38} {name[:24]:24} "
                  f"{str(row.get('status') or ''):12} step {step}")
            print(f"      sent {row.get('email_sent')}  opened {row.get('email_open')}"
                  f"  clicked {row.get('clicked')}  replied {row.get('replied')}")

    emit({"count": result.get("count"), "contacts": rows}, args.json, render)
    return EXIT_OK


def cmd_campaigns(args: argparse.Namespace) -> int:
    """Outreach campaigns with schedule, status and contact count."""
    token = auth.access_token()
    result = hexospark.campaigns(token, filter_text=args.search) or {}
    rows = result.get("campaigns") or []

    def render(data: dict[str, Any]) -> None:
        campaigns = data.get("campaigns") or []
        print(f"{len(campaigns)} of {data.get('count')} campaign(s):\n")
        for row in campaigns:
            state = "on " if row.get("active") else "off"
            done = "completed" if row.get("isCompleted") else str(row.get("status") or "")
            print(f"  [{row.get('id')}] {state} {done:14} "
                  f"{str(row.get('contactsCount')):>6} contacts  {row.get('name')}")

    emit({"count": result.get("count"), "campaigns": rows}, args.json, render)
    return EXIT_OK
