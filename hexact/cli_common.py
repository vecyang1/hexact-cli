"""Rendering helpers shared by the per-product command modules.

These are the small decisions that have to be made the same way everywhere, or
two commands describe the same account differently: what counts as paused, what
a missing timestamp means, and where a payload actually keeps its rows.

`_rows` earns its place here. These APIs return a list under one of several
key names depending on the endpoint, and reaching for the wrong one yields an
empty list rather than an error -- an account with monitors renders as an
account with none. Asking for every known name in one place is what stops that
being re-decided per command.
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta, timezone
from typing import Any

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
