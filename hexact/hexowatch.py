"""Hexowatch API client -- website change monitoring.

Complete coverage of the documented surface at
https://hexowatch.com/api-documentation/ (6 endpoints; there is no seventh).
Note the split version prefix: five routes live under ``v1/`` while monitor
creation is ``v2/monitor``, both below the same ``/v2/app/services/`` base.

Three documented absences, each confirmed against the full page rather than
assumed, because each one shapes what callers can be offered:

* **No update endpoint.** Nothing changes an existing monitor's interval,
  notification level, integrations, or webhook. Hexowatch's changelog advertises
  monitor editing, but that is the dashboard only.
* **No delete endpoint.** ``pause`` is the strongest available retirement.
* **Only 8 of the 13 tools can be created.** ``sitemapTool``,
  ``apiMonitoringTool``, ``htmlElementMonitoringTool``, ``automaticAITool`` and
  ``rssTool`` appear in scan results but have no documented creation schema.
"""

from __future__ import annotations

from typing import Any

from .http import path_segment, request

BASE_URL = "https://api.hexowatch.com/v2/app/services"

# Tools with a documented `tool_settings` creation schema. Picking the narrowest
# one that answers the question is what protects the monthly check allowance --
# a full visual monitor spends far more than an HTML element monitor watching a
# single price, and it also fires on sub-pixel rendering noise.
TOOLS = (
    "techStackTool",
    "keywordTool",
    "visualMonitoringTool",
    "availabilityMonitoringTool",
    "sourceCodeMonitoringTool",
    "domainWhoisTool",
    "contentMonitoringTool",
    "backlinkTool",
)

# Tools that can appear in a scan result. A superset of TOOLS: these five are
# readable but not creatable through the documented API.
READ_ONLY_TOOLS = (
    "sitemapTool",
    "apiMonitoringTool",
    "htmlElementMonitoringTool",
    "automaticAITool",
    "rssTool",
)
SCAN_RESULT_TOOLS = TOOLS + READ_ONLY_TOOLS

INTERVALS = (
    "5_MINUTE", "10_MINUTE", "15_MINUTE", "30_MINUTE",
    "1_HOUR", "2_HOUR", "3_HOUR", "4_HOUR", "5_HOUR", "6_HOUR", "12_HOUR",
    "1_DAY", "2_DAY", "3_DAY",
    "1_WEEK", "2_WEEK",
    "1_MONTH", "2_MONTH", "3_MONTH",
)
DEFAULT_INTERVAL = "1_DAY"

ACTIONS = ("pause", "resume", "check_now")

API_HOST_CODES = ("EUROPE", "USA", "ASIA")

DEVICES = (
    "MOBILE_SMALL", "MOBILE_MEDIUM", "MOBILE_LARGE", "TABLET",
    "LAPTOP_SMALL", "LAPTOP_MEDIUM", "LAPTOP_LARGE", "DESKTOP_4K",
)

# `change_notification_level` is tool-specific, and this is the single most
# misread field in the API. It is a change *classification* filter, not a
# delivery switch: no tool offers an "off"/"none"/"silent" value, and the
# narrowest setting available anywhere still notifies (GE_50 = the largest
# documented threshold). To keep monitoring without being notified, send
# `notification_integrations: []` and no `webhook` -- see `silent_monitor_kwargs`.
#
# The `GE_n` values are undocumented beyond their names. `GE_` is a conventional
# "greater or equal" prefix and `monitoring_logs` reports a `percentage` per
# scan, so `GE_5` very likely means "at least 5% changed" -- but the docs never
# say so, so this module does not present it as fact.
_GE_LEVELS = (
    "ANY", "GE_1", "GE_2", "GE_3", "GE_4", "GE_5", "GE_6", "GE_7", "GE_8",
    "GE_9", "GE_10", "GE_11", "GE_12", "GE_13", "GE_14", "GE_15",
    "GE_20", "GE_25", "GE_50",
)
NOTIFICATION_LEVELS: dict[str, tuple[str, ...]] = {
    "techStackTool": ("ANY", "ADDED", "UPDATED", "DELETED"),
    "visualMonitoringTool": _GE_LEVELS,
    "contentMonitoringTool": _GE_LEVELS,
    "keywordTool": ("ANY",),
    "availabilityMonitoringTool": ("ANY",),
    "sourceCodeMonitoringTool": ("ANY",),
    "domainWhoisTool": ("ANY",),
    "backlinkTool": ("ANY",),
}

# Documented `mode` values per tool, with the documented default first.
TOOL_MODES: dict[str, tuple[str, ...]] = {
    "techStackTool": ("ANY_CHANGE", "SPECIFIC_TECH_STACK_SEARCH"),
    "keywordTool": ("SEARCH",),
    "visualMonitoringTool": ("FULL_SCREEN",),
    "sourceCodeMonitoringTool": ("FULL_CODE", "SPECIFIC_CODE"),
    "domainWhoisTool": ("ANY_CHANGE", "SPECIFIC_FIELDS"),
    "contentMonitoringTool": ("FULL_CONTENT", "SPECIFIC_CONTENT"),
    "backlinkTool": ("FULL_DATA",),
}

SOURCE_FILE_TYPES = ("HTML", "CSS", "JS")
KEYWORD_OPERATORS = ("OR", "AND")
WHOIS_FIELDS = (
    "registeredAt", "lastModified", "fullText", "expiresAt",
    "exists", "domain", "url", "dnsData", "status",
)


def silent_monitor_kwargs() -> dict[str, Any]:
    """Settings that keep a monitor running while sending no notification.

    Deliberately explicit rather than relying on documented defaults, so the
    intent survives a reader who does not know the defaults.

    Caveat the caller must know: Hexowatch also supports an **account-level**
    webhook, configured in dashboard settings, that fires for every monitor on
    the account. It is not reachable through this API, so these settings cannot
    disable it. Whether the account's default email integration still applies
    when ``notification_integrations`` is empty is not documented.
    """
    return {
        "notification_integrations": [],   # no discord/slack/telegram/email delivery
        "webhook": None,                   # no per-monitor webhook
        "pause_after_first_change_event": False,  # keep monitoring, do not stop
    }


def _call(key: str, path: str, **kwargs: Any) -> dict[str, Any]:
    return request(BASE_URL, path, key, **kwargs)


def list_integrations(key: str) -> dict[str, Any]:
    """Notification channels and their IDs, under a ``result`` list.

    Each entry is ``{"id", "type", "data"}`` where ``type`` is one of slack,
    telegram, discord, email. The ``id`` is what ``create_monitor`` expects in
    ``notification_integrations``.
    """
    return _call(key, "v1/integrations")


def list_monitored_urls(key: str) -> dict[str, Any]:
    """Every monitor on the account, under ``monitored_urls``.

    Entries are ``{"id", "address", "name", ...}`` plus a state flag whose key
    is genuinely inconsistent: the documentation specifies ``active``, while the
    live API was observed returning ``paused`` (2026-08-13), and the docs' own
    apiMonitoringTool example also shows ``paused``. Callers must handle both.
    """
    return _call(key, "v1/monitored_urls")


def create_monitor(
    key: str,
    *,
    tool: str,
    addresses: list[str],
    notification_integrations: list[int] | None = None,
    tool_settings: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    webhook: str | None = None,
    monitoring_interval: str | None = None,
    change_notification_level: str | None = None,
    pause_after_first_change_event: bool | None = None,
) -> dict[str, Any]:
    """Create one monitor per address. Returns ``monitoring_ids``.

    ``notification_integrations=[]`` is meaningful and is preserved: it is the
    documented way to create a monitor that records changes without notifying.
    """
    if tool not in TOOLS:
        extra = ""
        if tool in READ_ONLY_TOOLS:
            extra = (f" {tool!r} can appear in scan results but has no documented "
                     "creation schema, so it cannot be created through the API.")
        raise ValueError(
            f"Unknown tool {tool!r}. Creatable tools: {', '.join(TOOLS)}.{extra}"
        )
    if not addresses:
        raise ValueError("At least one address is required")
    if monitoring_interval and monitoring_interval not in INTERVALS:
        raise ValueError(
            f"Unknown interval {monitoring_interval!r}. "
            f"Expected one of: {', '.join(INTERVALS)}"
        )
    if change_notification_level is not None:
        allowed = NOTIFICATION_LEVELS[tool]
        if change_notification_level not in allowed:
            raise ValueError(
                f"change_notification_level {change_notification_level!r} is not "
                f"valid for {tool}. Allowed: {', '.join(allowed)}. Note that no "
                "value suppresses notifications -- pass notification_integrations=[] "
                "for that."
            )

    body: dict[str, Any] = {"tool": tool, "address_list": addresses}
    optional = {
        # `notification_integrations` is checked against None, not falsiness, so
        # an explicit empty list (the mute setting) is sent rather than dropped.
        "notification_integrations": notification_integrations,
        "tool_settings": tool_settings,
        "tags": tags,
        "webhook": webhook,
        "monitoring_interval": monitoring_interval,
        "change_notification_level": change_notification_level,
        "pause_after_first_change_event": pause_after_first_change_event,
    }
    body.update({name: value for name, value in optional.items() if value is not None})

    return _call(key, "v2/monitor", method="POST", body=body)


def act(key: str, action: str, monitoring_ids: list[int] | None = None) -> dict[str, Any]:
    """Pause, resume, or force an immediate check.

    ``monitoring_ids=None`` applies the action to *every* monitor on the
    account -- the API's documented behaviour, and rarely what anyone wants by
    accident, so the CLI requires an explicit ``--all`` to reach it.

    The success body for this endpoint is not documented; only the error shape
    is. Do not depend on any particular field coming back.
    """
    if action not in ACTIONS:
        raise ValueError(f"Unknown action {action!r}. Expected one of: {', '.join(ACTIONS)}")
    return _call(key, "v1/action", method="PATCH",
                 body={"action": action, "monitoring_ids": monitoring_ids})


def monitoring_logs(
    key: str,
    monitoring_id: int,
    *,
    limit: int = 10,
    page: int = 1,
    only_detected_changes: bool = True,
) -> dict[str, Any]:
    """Scan history for one monitor, under ``monitoring_results``.

    Entries are ``{"scan_result_id", "date", "event_detected", "percentage"}``
    and the envelope carries the monitor's ``tool``, so a follow-up
    :func:`scan_result` call does not need to be told which tool to use.

    The docs describe these as *body* parameters on a GET. Many HTTP stacks drop
    a GET body, so they are sent as query parameters here. ``Only_detected_changes``
    is capitalised exactly as documented -- inconsistent with every other
    snake_case field, and not a transcription error.
    """
    return _call(
        key,
        f"v1/monitoring_logs/{path_segment(monitoring_id)}",
        params={
            "limit": limit,
            "page": page,
            "Only_detected_changes": only_detected_changes,
        },
    )


def scan_result(key: str, scan_result_id: str | int, tool: str) -> dict[str, Any]:
    """The actual diff for one scan, under ``scanResult`` as ``newData``/``oldData``.

    ``tool`` must match the monitor that produced the scan; the API cannot infer
    it from the ID. Sent as a query parameter rather than the documented
    alternative GET body, since GET bodies are widely dropped in transit.
    """
    if tool not in SCAN_RESULT_TOOLS:
        raise ValueError(
            f"Unknown tool {tool!r}. Expected one of: {', '.join(SCAN_RESULT_TOOLS)}"
        )
    return _call(key, f"v1/scan_result/{path_segment(scan_result_id)}",
                 params={"tool": tool})
