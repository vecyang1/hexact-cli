"""Hexospark -- the CRM and outreach product, reachable only through GraphQL.

`docs/API.md` recorded, correctly, that Hexospark publishes **no REST API**;
that was verified by control-diffing its documentation URLs against a page that
cannot exist. What that finding could not see is that the shared gateway carries
24 Hexospark namespaces, so the product is not unreachable -- only undocumented.

**This module is read-only, and that is a decision rather than an omission.**
`HexosparkCampaignOps` can create campaigns, attach contacts and add steps;
those writes put mail in front of real people. Reading an account's own CRM is
an operation whose blast radius is the terminal it prints to. Sending is not,
and it does not belong in a client that an agent can drive unattended. The
mutation allowlist in :mod:`hexact.graphql` refuses every Hexospark operation,
so this boundary is enforced rather than merely intended.
"""

from __future__ import annotations

from typing import Any

from . import graphql

CRM_CONTACTS_QUERY = """
query($settings: GetCrmContactsInput) {
  HexosparkCrmContact {
    getCrmContacts(settings: $settings) {
      count
      error_code
      contacts {
        id email firstName lastName position source status lead_status
        email_sent email_open clicked replied currentStep totalStep
        created_at updated_at
      }
    }
  }
}
"""

CAMPAIGNS_QUERY = """
query($settings: GetCampaignsInput) {
  HexosparkCampaign {
    getCampaigns(settings: $settings) {
      count
      error_code
      campaigns {
        id name description active status isCompleted contactsCount
        scheduler_start_at scheduler_end_at created_at updated_at
      }
    }
  }
}
"""


def crm_contacts(
    token: str, *, campaign_id: str | None = None, filter_text: str | None = None,
) -> dict[str, Any]:
    """Contacts in the Hexospark CRM, with their outreach counters.

    `email_sent` / `email_open` / `clicked` / `replied` are the per-contact
    engagement counters the dashboard shows; nothing in the documented REST
    surface of any Hexact product exposes them.
    """
    settings = {"campaign_id": campaign_id, "filter": filter_text}
    settings = {k: v for k, v in settings.items() if v is not None}
    # Omit `settings` entirely rather than sending it as null: a
    # present-and-null filter matches nothing on this gateway.
    data = graphql.execute(CRM_CONTACTS_QUERY,
                           graphql.only_supplied({"settings": settings or None}),
                           token=token)
    return graphql.unwrap(data, "HexosparkCrmContact", "getCrmContacts")


def campaigns(token: str, *, filter_text: str | None = None) -> dict[str, Any]:
    """Outreach campaigns with their schedule, status and contact count."""
    settings = {"filter": filter_text} if filter_text else None
    data = graphql.execute(CAMPAIGNS_QUERY,
                           graphql.only_supplied({"settings": settings}),
                           token=token)
    return graphql.unwrap(data, "HexosparkCampaign", "getCampaigns")
