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

from .http import DEFAULT_TIMEOUT_SECONDS, USER_AGENT, HexactAPIError

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
        with urllib.request.urlopen(request, timeout=timeout) as response:
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
        raise HexactAPIError(
            redact_token(f"{type(exc).__name__} calling the GraphQL gateway: {exc}", token)
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
            raise AuthError(redact_token(message, token))
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
    """
    scope = data.get(namespace)
    if scope is None:
        raise AuthError(
            f"The GraphQL gateway returned null for {namespace}. This means the "
            "session token was missing, expired or rejected -- it does not mean "
            "the account is empty. Run: hexact auth login"
        )
    value = scope.get(field)
    if value is None:
        raise AuthError(
            f"The GraphQL gateway returned null for {namespace}.{field}. This "
            "means the session token was missing, expired or rejected -- it "
            "does not mean there is no data. Run: hexact auth login"
        )
    return value


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
    return unwrap(data, "WatchIntegration", "getUserIntegrations")


def get_watch_settings(token: str) -> Any:
    """Account-level notification settings: email recipients and webhooks."""
    data = execute(WATCH_SETTINGS_QUERY, token=token)
    return unwrap(data, "UserWatchSettings", "get")


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
