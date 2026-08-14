"""The Hexact GraphQL gateway -- everything the REST API cannot do.

`https://api.hexowatch.com/v2/ql` is the backend the dashboard itself talks to.
It shares a host with the documented REST API (``v2/app`` is REST, ``v2/ql`` is
GraphQL) but is a different contract in every other respect: different
authentication, different error semantics, and no public documentation at all.

Why this module exists: the REST API has **no delete and no update**. That is
measured, not assumed -- ``DELETE`` in five path shapes and ``PUT``/``PATCH`` in
three all return the backend's Express 404, against controls that behaved. The
mutations here are the only programmatic way to retire or retune a monitor.

Three traps, each of which produces confidently wrong output rather than an
error:

1. **A REST API key does not authenticate here.** Tested five ways
   (``authorization``, ``Bearer``, ``x-api-key``, ``?key=`` query, URL param);
   every one returned ``null``, byte-identical to sending no credential at all.
   This gateway wants a session token from :mod:`hexact.auth`.

2. **Unauthenticated reads return HTTP 200 with ``null``, not an error.** A
   bogus token is indistinguishable from no token. So ``null`` must never reach
   a caller as "no data" -- an empty monitor list and a failed login would look
   identical, and the CLI would cheerfully report a healthy account with zero
   monitors. :func:`unwrap` is where that is stopped, and it is the single most
   load-bearing function in this file.

3. **The schema is undocumented and unversioned.** It was recovered from a
   date-stamped dashboard bundle and re-verified against the live server. There
   is no compatibility promise, so the operation names are pinned in tests: a
   silent vendor rename should fail loudly rather than quietly return nothing.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .http import (
    CERT_HINT, DEFAULT_TIMEOUT_SECONDS, USER_AGENT, HexactAPIError,
    has_trust_store, ssl_context,
)

GRAPHQL_URL = "https://api.hexowatch.com/v2/ql"

# Only these mutations may be sent. This is a containment boundary, not a
# convenience: the credential this module carries is a *session* token, which
# unlike the scoped REST key can reach the whole account -- including billing
# mutations such as `HexometerUserSettingsOpts.updateHexometerPackage`. An
# allowlist checked before the request is built makes those unreachable by
# construction rather than by anyone remembering not to call them.
MUTATION_ALLOWLIST = frozenset({
    "WatchOps.deleteWatchProperty",
    "WatchOps.deleteWatchProperties",
    "WatchOps.updateWatchProperty",
    "WatchOps.updateWatchProperties",
    # Notification routing. `updateWatchPropertyIntegrations` with an empty list
    # is the only way to silence a monitor that already exists -- the REST
    # `notification_integrations: []` field applies at creation time and there
    # is no REST update, so 48 existing noisy monitors were unreachable without
    # this one mutation.
    "WatchIntegrationOps.updateWatchPropertyIntegrations",
    "WatchIntegrationOps.deleteWatchPropertyIntegration",
    "WatchIntegrationOps.deleteWatchIntegration",
    # Account-level notification settings. `docs/API.md` recorded the
    # account-level webhook as "dashboard-only and not API-reachable"; it is
    # reachable, here, and `update(emailEnabled:)` is the switch that turns off
    # notification email for the whole account -- the thing 48 per-monitor
    # mutes could only approximate.
    "UserWatchSettingsOps.update",
    "UserWatchSettingsOps.subscribeWebhook",
    "UserWatchSettingsOps.unsubscribeWebhook",
    # Tags. The account runs 48 monitors with no grouping at all, and REST has
    # no concept of a tag; `Watch.getUserWatchProperties(tags:)` can filter by
    # one, so tagging is the only way to ask "how are the Bokksu monitors
    # doing" without matching URLs by hand.
    "WatchTagOps.createUserWatchTag",
    "WatchTagOps.updateUserWatchTag",
    "WatchTagOps.deleteUserWatchTag",
    "WatchTagOps.updateWatchPropertyTags",
    "WatchTagOps.addWatchPropertyTag",
    "WatchTagOps.deleteWatchPropertyTag",
    # The dashboard's alert list. Read state and deletion only -- these touch
    # the notification inbox, never a monitor's configuration or its data.
    "WatchAlertOps.setAllWatchAlertsReadState",
    "WatchAlertOps.setWatchAlertReadState",
    "WatchAlertOps.deleteWatchAlerts",
})

# Namespaces that must never be reachable, listed explicitly so the intent
# survives a future widening of the allowlist above.
FORBIDDEN_NAMESPACES = frozenset({
    "HexometerUserSettingsOpts",  # subscription and card changes
    "UserOps",                    # logout, password, web push -- auth.py owns this
    "PropertyOps",                # Hexometer's namespace, not ours
})

# The resolver answers this when the token is missing, expired, or bogus. It
# arrives inside a normal `{"error": true}` envelope with HTTP 200.
_UNAUTHENTICATED_MARKERS = (
    "should be authenticated",
    "should be authorized",
    "unauthorized",
    "unauthenticated",
)


class AuthError(HexactAPIError):
    """The gateway did not accept the session token.

    Separate from :class:`HexactAPIError` because the remedy is different and
    specific: re-run ``hexact auth login``. Collapsing it into a generic API
    error is what turns an expired token into "your account has no monitors".
    """


def redact_token(text: str, token: str | None) -> str:
    """Remove a session token from a string destined for a human or a log.

    The token rides in a header rather than the URL, so it is far less
    leak-prone than the REST scheme -- but ``urllib`` exceptions can still
    echo request state, and this credential is broader than the API key.
    """
    if not token or len(token) < 8:
        return text
    return text.replace(token, "***REDACTED***")


def execute(
    query: str,
    variables: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Send one GraphQL document and return its ``data`` object.

    Raises :class:`AuthError` when the gateway rejects the token, and
    :class:`HexactAPIError` for transport failures and GraphQL errors.
    """
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["authorization"] = token

    request = urllib.request.Request(GRAPHQL_URL, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=ssl_context()) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:500]
        except Exception:  # noqa: BLE001 - the status is the useful part
            pass
        raise HexactAPIError(
            redact_token(f"HTTP {exc.code} from the GraphQL gateway"
                         + (f": {detail}" if detail else ""), token)
        ) from None
    except Exception as exc:
        # Deliberately a catch-all, for the same reason as hexact.http.request:
        # enumerating the exception types that can echo request state has
        # already failed once in this codebase (http.client.InvalidURL is not an
        # OSError). Redact whatever arrives instead of predicting it.
        hint = "" if has_trust_store() else f"\n{CERT_HINT}"
        raise HexactAPIError(
            redact_token(f"{type(exc).__name__} calling the GraphQL gateway: {exc}", token)
            + hint
        ) from None

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HexactAPIError(
            redact_token(f"Non-JSON response from the GraphQL gateway: {raw[:200]!r}", token)
        ) from exc

    errors = payload.get("errors")
    if errors:
        message = str(errors[0].get("message", "unknown"))
        if any(marker in message.lower() for marker in _UNAUTHENTICATED_MARKERS):
            # Carry the remedy here rather than letting the top-level handler
            # bolt a generic one onto every AuthError. This is the one raise
            # site where the *server* said the credential was rejected, so
            # "log in again" is the right advice; the null-shaped failures
            # below cannot tell rejection from missing entitlement and must be
            # allowed to say so instead of being overwritten.
            raise AuthError(
                redact_token(message, token)
                + "\n  The gateway rejected the session credential.\n"
                "  Run: hexact auth login --email <you>"
            )
        raise HexactAPIError(redact_token(f"GraphQL error: {message}", token))

    data = payload.get("data")
    if not isinstance(data, dict):
        raise HexactAPIError("GraphQL response carried no data object")
    return data


def unwrap(data: dict[str, Any], namespace: str, field: str) -> Any:
    """Pull ``data[namespace][field]`` out, treating ``null`` as an auth failure.

    This is the guard described at the top of the module. The gateway answers an
    unauthenticated read with HTTP 200 and a null field rather than an error, so
    a caller that reads ``null`` as "nothing there" reports an empty account to
    someone whose token merely expired. Verified against the live server: no
    token, a bogus token, and a valid REST API key all produce exactly this
    shape, and none of them is distinguishable from a genuinely empty result.

    Because that ambiguity is real and cannot be resolved from the response
    alone, this fails closed. A genuinely empty collection is returned by the
    gateway as ``[]``, not ``null``, so nothing legitimate is lost.

    **This guard is not sufficient on its own.** It covers the two levels
    GraphQL wraps every answer in, and an unauthenticated read can hand back a
    non-null container whose members are all null -- which passes here and was
    then rendered as an empty account by three commands. See
    :func:`reject_all_null`, which every accessor returning a container must
    also use.
    """
    # Both messages name every cause that reaches them, not the commonest one.
    # This function is shared by every gateway read across four products, so a
    # sentence asserting "your token is bad" also greets someone with a working
    # token who simply does not own Hexospark -- and sends them to re-
    # authenticate a credential that was never the problem.
    scope = data.get(namespace)
    if scope is None:
        raise AuthError(
            f"The GraphQL gateway returned null for {namespace}. It does not "
            "mean the account is empty -- this client refuses to render a null "
            "as 'no data'. Either the session token is missing, expired or "
            "rejected, or this account has no access to "
            f"{namespace.replace('Ops', '')}.\n"
            "  Check which: hexact auth status"
        )
    value = scope.get(field)
    if value is None:
        raise AuthError(
            f"The GraphQL gateway returned null for {namespace}.{field}. It "
            "does not mean there is no data. Either the session token is "
            "missing, expired or rejected, or this account cannot read that "
            "field.\n"
            "  Check which: hexact auth status"
        )
    return value


def reject_all_null(payload: dict[str, Any], keys: tuple[str, ...], *, source: str) -> dict[str, Any]:
    """Refuse a container whose every member is ``null``.

    :func:`unwrap` guards the two levels GraphQL wraps every answer in and stops
    there, which is one level short. Measured 2026-08-14 with a deliberately
    invalid token, against an account REST simultaneously reported as 48
    monitors and 3 notification channels, the gateway returned a **non-null
    container of nulls** and sailed past ``unwrap`` every time::

        Watch.getUserWatchProperties      {"totalCount": null, "watchProperties": null}
        WatchIntegration.getUserIntegrations  {"integrations": null}
        UserWatchSettings.get             {"emails": null, "webhooks": null}

    Each renderer then applied ``or []`` and reported the account as empty. The
    server was honest throughout; the zero was invented here.

    The test is *every* member, not any member, and that is deliberate. A single
    null member is ordinary -- an account with recipients but no webhooks looks
    like that -- so refusing on the first null would break working reads. All
    members null is the shape no live account produces, because a live read
    fills at least the field the caller asked for.
    """
    if payload and all(payload.get(key) is None for key in keys):
        raise AuthError(
            f"{source} came back with every field null "
            f"({', '.join(keys)}). It does not mean the account is empty -- a "
            "live read fills at least one of them, so this client refuses to "
            "render it as zero. Either the session token is missing, expired "
            "or rejected, or this account cannot read that field.\n"
            "  Check which: hexact auth status"
        )
    return payload


def only_supplied(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop the entries the caller never set.

    An omitted variable and an explicit ``null`` are different questions to
    this gateway, and the second one matches nothing. Measured 2026-08-14
    against REST as a control: `getUserWatchProperties` returned 45 monitors
    with `page`+`limit` alone and **0** with the same call plus null filters.
    No error, no null container -- a stated zero, which is precisely what
    :func:`reject_all_null` is unable to catch.

    `is not None` rather than truthiness: `active=False` and `limit=0` are
    answers, `None` is the absence of one.
    """
    return {name: value for name, value in mapping.items() if value is not None}


def mutate(
    operation: str,
    arguments: dict[str, tuple[str, Any]],
    *,
    token: str,
    selection: str = "error message",
) -> dict[str, Any]:
    """Run one allowlisted mutation, named ``Namespace.field``.

    ``arguments`` maps each GraphQL argument to a ``(type, value)`` pair, so the
    call is sent with real GraphQL variables rather than interpolated strings --
    values never become part of the query document.

    The allowlist is checked *before* the document is built, so a forbidden
    operation cannot reach the network even if the rest of this function is
    later changed.
    """
    namespace, _, field = operation.partition(".")
    if namespace in FORBIDDEN_NAMESPACES:
        raise HexactAPIError(
            f"{operation} is in a forbidden namespace. This client deliberately "
            "cannot reach account or billing mutations."
        )
    if operation not in MUTATION_ALLOWLIST:
        raise HexactAPIError(
            f"{operation} is not in MUTATION_ALLOWLIST. Add it there explicitly "
            "if it is genuinely needed; the list is a containment boundary, not "
            "an oversight."
        )

    supplied = {name: spec for name, spec in arguments.items() if spec[1] is not None}
    declarations = ", ".join(f"${name}: {spec[0]}" for name, spec in supplied.items())
    passthrough = ", ".join(f"{name}: ${name}" for name in supplied)
    header = f"mutation({declarations})" if declarations else "mutation"
    call = f"{field}({passthrough})" if passthrough else field
    query = f"{header} {{ {namespace} {{ {call} {{ {selection} }} }} }}"

    data = execute(query, {name: spec[1] for name, spec in supplied.items()}, token=token)
    result = unwrap(data, namespace, field)

    # Mutations report failure inside the envelope with HTTP 200, exactly like
    # the REST API does.
    if isinstance(result, dict) and result.get("error"):
        message = str(result.get("message") or "unknown")
        if any(marker in message.lower() for marker in _UNAUTHENTICATED_MARKERS):
            raise AuthError(message)
        raise HexactAPIError(f"{operation} failed: {message}")
    return result if isinstance(result, dict) else {"result": result}


# --- Reads -----------------------------------------------------------------
# The REST `v1/monitored_urls` returns only id/address/name/paused, and there is
# no monitor-detail endpoint (measured: `GET v1/monitored_urls/{id}` is a 404).
# These queries are the only way to see what a monitor is actually configured to
# do -- which is also what makes a write verifiable afterwards.

# `monitoring_interval` is not decoration: without it, `watch retune --interval`
# could only read back `change_notification_level` and would report "confirmed"
# after verifying a field it had not changed. Select what the writes write.
WATCH_PROPERTY_QUERY = """
query($watch_property_id: Int!) {
  Watch {
    getWatchProperty(watch_property_id: $watch_property_id) {
      id name url active change_notification_level monitoring_interval
      createdAt tool alertCount tags { id name }
    }
  }
}
"""

WATCH_INTEGRATIONS_QUERY = """
query($watch_property_id: Int!) {
  WatchIntegration {
    getWatchPropertyIntegrations(watch_property_id: $watch_property_id) {
      integrations { id type slackIntegration email { email enabled verified } }
    }
  }
}
"""

USER_INTEGRATIONS_QUERY = """
query {
  WatchIntegration {
    getUserIntegrations {
      integrations { id type slackIntegration email { email enabled verified } }
    }
  }
}
"""

WATCH_SETTINGS_QUERY = """
query {
  UserWatchSettings {
    get {
      emails { email enabled verified }
      webhooks { subscriptionId type }
    }
  }
}
"""

STATISTICS_QUERY = """
query {
  Watch {
    getUserWatchPropertiesStatistics {
      tools_usage { tool_name count }
      properties_status { active paused }
    }
  }
}
"""


def get_watch_property(token: str, monitoring_id: int) -> dict[str, Any]:
    """One monitor's real configuration, including the tool and alert level."""
    data = execute(WATCH_PROPERTY_QUERY, {"watch_property_id": int(monitoring_id)}, token=token)
    return unwrap(data, "Watch", "getWatchProperty")


def get_watch_property_integrations(token: str, monitoring_id: int) -> Any:
    """The notification channels attached to one monitor."""
    data = execute(
        WATCH_INTEGRATIONS_QUERY, {"watch_property_id": int(monitoring_id)}, token=token
    )
    return unwrap(data, "WatchIntegration", "getWatchPropertyIntegrations")


def get_user_integrations(token: str) -> Any:
    """Every notification channel on the account, with its id and type."""
    data = execute(USER_INTEGRATIONS_QUERY, token=token)
    return reject_all_null(
        unwrap(data, "WatchIntegration", "getUserIntegrations"),
        ("integrations",),
        source="WatchIntegration.getUserIntegrations",
    )


def get_watch_settings(token: str) -> Any:
    """Account-level notification settings: email recipients and webhooks."""
    data = execute(WATCH_SETTINGS_QUERY, token=token)
    return reject_all_null(
        unwrap(data, "UserWatchSettings", "get"),
        ("emails", "webhooks"),
        source="UserWatchSettings.get",
    )


def set_email_notifications(token: str, enabled: bool) -> dict[str, Any]:
    """The account-wide notification-email switch.

    Broader than `set_monitor_integrations`, and the difference matters. Muting
    a monitor detaches *its* channels; this turns off notification email for
    the whole account in one call, including the default delivery that fires
    even for monitors with no channel attached. That default is what made
    "does an empty channel list also stop the email?" unanswerable -- the
    question had no lever until this mutation.
    """
    return mutate(
        "UserWatchSettingsOps.update",
        {"emailEnabled": ("Boolean", bool(enabled))},
        token=token,
        selection="error message",
    )


def set_account_webhook(token: str, webhook_url: str) -> dict[str, Any]:
    """Subscribe an account-level webhook -- fires for every monitor.

    Distinct from `WatchOps.subscribeWebhook`, which takes a
    `watch_property_id` and is per-monitor. This one takes only a URL.
    """
    return mutate(
        "UserWatchSettingsOps.subscribeWebhook",
        {"webhookUrl": ("String", webhook_url)},
        token=token,
        selection="error message",
    )


def remove_account_webhook(token: str, subscription_id: str) -> dict[str, Any]:
    """Unsubscribe an account-level webhook by its subscriptionId."""
    return mutate(
        "UserWatchSettingsOps.unsubscribeWebhook",
        {"subscriptionId": ("String", subscription_id)},
        token=token,
        selection="error message",
    )


def get_statistics(token: str) -> dict[str, Any]:
    """Fleet-wide counts: monitors per tool, and active vs paused."""
    data = execute(STATISTICS_QUERY, token=token)
    return unwrap(data, "Watch", "getUserWatchPropertiesStatistics")


# --- Writes ----------------------------------------------------------------


def delete_monitors(token: str, monitoring_ids: list[int]) -> dict[str, Any]:
    """Permanently delete monitors. The whole list goes in one call."""
    return mutate(
        "WatchOps.deleteWatchProperties",
        {"watch_properties_ids": ("[Int]!", [int(i) for i in monitoring_ids])},
        token=token,
    )


def update_monitors(
    token: str,
    monitoring_ids: list[int],
    *,
    change_notification_level: str | None = None,
    monitoring_interval: str | None = None,
    active: bool | None = None,
) -> dict[str, Any]:
    """Retune monitors in bulk. Arguments left as ``None`` are not sent."""
    return mutate(
        "WatchOps.updateWatchProperties",
        {
            "watch_properties_ids": ("[Int]!", [int(i) for i in monitoring_ids]),
            "change_notification_level": ("String", change_notification_level),
            "monitoring_interval": ("String", monitoring_interval),
            "active": ("Boolean", active),
        },
        token=token,
    )


def set_monitor_integrations(
    token: str, monitoring_id: int, integration_ids: list[int]
) -> dict[str, Any]:
    """Replace one monitor's notification channels with exactly this list.

    An **empty list mutes the monitor**: it keeps checking and keeps recording
    changes, and stops routing them anywhere. That is the distinction the
    account owner actually wanted -- "keep tracking, stop telling me" -- and it
    was unreachable before, because the REST API can only set channels at
    creation time.

    The list is a replacement, not a delta. Read the current channels first if
    the intent is to remove only one; :func:`detach_monitor_integration` does
    that without a read.
    """
    return mutate(
        "WatchIntegrationOps.updateWatchPropertyIntegrations",
        {
            "watch_property_id": ("Int!", int(monitoring_id)),
            # `[]` must survive to the wire. `mutate` filters on `is not None`
            # rather than truthiness precisely so that this empty list is sent
            # rather than silently dropped -- dropping it would turn "mute" into
            # "change nothing" and report success.
            "watch_integration_ids": ("[Int]!", [int(i) for i in integration_ids]),
        },
        token=token,
    )


def detach_monitor_integration(
    token: str, monitoring_id: int, integration_id: int
) -> dict[str, Any]:
    """Remove one channel from one monitor, leaving its others in place."""
    return mutate(
        "WatchIntegrationOps.deleteWatchPropertyIntegration",
        {
            "watch_property_id": ("Int!", int(monitoring_id)),
            "watch_integration_id": ("Int!", int(integration_id)),
        },
        token=token,
    )


def delete_integration(token: str, integration_id: int) -> dict[str, Any]:
    """Delete a notification channel **account-wide**.

    Wider than it looks: this removes the channel from every monitor using it,
    not just the one in front of you. Use :func:`detach_monitor_integration` for
    a single monitor.
    """
    return mutate(
        "WatchIntegrationOps.deleteWatchIntegration",
        {"watch_integration_id": ("Int!", int(integration_id))},
        token=token,
    )


# --- Tags ------------------------------------------------------------------
# REST has no tag concept at all -- not undocumented, absent. `docs/GATEWAY.md`
# `WatchTagOps` (6 fields) and `WatchTag` (2) are the whole feature, and
# `Watch.getUserWatchProperties(tags: [Int])` is what makes them worth having:
# it is the only server-side way to select a subset of monitors.

USER_TAGS_QUERY = """
query {
  WatchTag {
    getUserWatchTags {
      tags { id name color }
    }
  }
}
"""

PROPERTY_TAGS_QUERY = """
query($watch_property_id: Int!) {
  WatchTag {
    getWatchPropertyTags(watch_property_id: $watch_property_id) {
      tags { id name color }
    }
  }
}
"""


def get_user_tags(token: str) -> Any:
    """Every tag on the account, with the ids the filter takes."""
    data = execute(USER_TAGS_QUERY, token=token)
    return unwrap(data, "WatchTag", "getUserWatchTags")


def get_property_tags(token: str, monitoring_id: int) -> Any:
    """The tags attached to one monitor."""
    data = execute(
        PROPERTY_TAGS_QUERY, {"watch_property_id": int(monitoring_id)}, token=token
    )
    return unwrap(data, "WatchTag", "getWatchPropertyTags")


def create_tag(token: str, name: str, color: str) -> dict[str, Any]:
    """Create a tag. Returns the new `watch_tag_id`."""
    return mutate(
        "WatchTagOps.createUserWatchTag",
        {"name": ("String!", name), "color": ("String!", color)},
        token=token,
        selection="error message watch_tag_id",
    )


def delete_tag(token: str, tag_id: int) -> dict[str, Any]:
    """Delete a tag account-wide. Monitors keep existing; they lose the label."""
    return mutate(
        "WatchTagOps.deleteUserWatchTag",
        {"watch_tag_id": ("Int!", int(tag_id))},
        token=token,
    )


def set_property_tags(token: str, monitoring_id: int, tag_ids: list[int]) -> dict[str, Any]:
    """Replace a monitor's tags with exactly this list.

    A *replace*, not an add -- the same shape as `updateWatchPropertyIntegrations`,
    and the same trap: passing `[]` clears every tag rather than doing nothing.
    Callers that mean "add one" should read the current list and send the union.
    """
    return mutate(
        "WatchTagOps.updateWatchPropertyTags",
        {
            "watch_property_id": ("Int!", int(monitoring_id)),
            "tags": ("[Int]!", [int(t) for t in tag_ids]),
        },
        token=token,
    )


# --- Filtered, paged monitor listing ---------------------------------------
# REST `v1/monitored_urls` returns id/address/name/paused for every monitor at
# once, with no total, no filter and no sort. This returns the same monitors
# with their tool, interval, tags and active state, filtered server-side.

USER_PROPERTIES_QUERY = """
query($page: Int!, $limit: Int!, $active: Boolean, $searchQuery: String,
      $sortBy: String, $sortDir: String, $tags: [Int], $tool: String) {
  Watch {
    getUserWatchProperties(page: $page, limit: $limit, active: $active,
                           searchQuery: $searchQuery, sortBy: $sortBy,
                           sortDir: $sortDir, tags: $tags, tool: $tool) {
      totalCount
      watchProperties {
        id name url tool active monitoring_interval createdAt user_agent
        tags { id name color }
      }
    }
  }
}
"""


def list_monitors(
    token: str, *, page: int = 1, limit: int = 50, active: bool | None = None,
    search: str | None = None, tags: list[int] | None = None,
    tool: str | None = None, sort_by: str | None = None,
    sort_dir: str | None = None,
) -> dict[str, Any]:
    """Monitors with their real configuration, filtered and paged server-side.

    **An omitted variable and an explicit ``null`` are not the same thing here,
    and the difference is 45 monitors.** Measured 2026-08-14 with a valid
    session, against REST reporting 45 at the same moment::

        page+limit only                      totalCount=45  rows=45
        page+limit plus null filters         totalCount=0   rows=0

    The server treats a filter that is present-and-null as a filter, and
    nothing matches it. No error, no warning -- a stated, confident zero, which
    `reject_all_null` cannot catch precisely because it is not a null. So build
    the variables from what the caller actually asked for.

    `is not None` rather than truthiness: `active=False` is a real filter and
    must survive, while `active=None` means "did not ask".
    """
    variables: dict[str, Any] = {"page": int(page), "limit": int(limit)}
    optional = {
        "active": active,
        "searchQuery": search,
        "sortBy": sort_by,
        "sortDir": sort_dir,
        "tags": [int(t) for t in tags] if tags else None,
        "tool": tool,
    }
    variables.update(only_supplied(optional))
    data = execute(USER_PROPERTIES_QUERY, variables, token=token)
    return reject_all_null(
        unwrap(data, "Watch", "getUserWatchProperties"),
        ("totalCount", "watchProperties"),
        source="Watch.getUserWatchProperties",
    )


# --- Notification volume ---------------------------------------------------
# The account's measured problem is alert volume, and until now it was counted
# client-side by pulling every change and grouping in Python. The gateway keeps
# the same figures and will return them per period.

NOTIFICATIONS_PIE_QUERY = """
query($from: String, $to: String) {
  WatchNotification {
    watchNotificationsPieChart(from: $from, to: $to) { field count }
  }
}
"""


def notification_breakdown(
    token: str, *, since: str | None = None, until: str | None = None
) -> Any:
    """Notification counts grouped by the gateway's own categories."""
    data = execute(NOTIFICATIONS_PIE_QUERY,
                   only_supplied({"from": since, "to": until}), token=token)
    return unwrap(data, "WatchNotification", "watchNotificationsPieChart")


# --- Alert inbox -----------------------------------------------------------
# Distinct from monitors and from changes: this is the dashboard's own unread
# list. Nothing in REST touches it, so an account with months of alerts has no
# programmatic way to clear them.

def mark_all_alerts_read(token: str) -> dict[str, Any]:
    """Mark every alert on the account as read. No arguments, no undo."""
    return mutate("WatchAlertOps.setAllWatchAlertsReadState", {}, token=token)


def mark_alerts_read(token: str, alert_ids: list[int]) -> dict[str, Any]:
    """Mark specific alerts as read."""
    return mutate(
        "WatchAlertOps.setWatchAlertReadState",
        {"watch_alert_ids": ("[Int]", [int(i) for i in alert_ids])},
        token=token,
    )


def delete_alerts(token: str, alert_ids: list[int]) -> dict[str, Any]:
    """Delete alerts from the inbox. The monitors and their history are untouched."""
    return mutate(
        "WatchAlertOps.deleteWatchAlerts",
        {"watchAlertIds": ("[Int]", [int(i) for i in alert_ids])},
        token=token,
    )
