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

import re
from datetime import datetime, timedelta, timezone
from typing import Any

_DURATION = re.compile(r"^(\d+)([hdwm])$")
_DURATION_UNITS = {"h": "hours", "d": "days", "w": "weeks"}

# `m` is months, and there is no minute form at all. Spelled out here because
# the old help text advertised "24h, 7d, 2w, 1m" -- putting `m` in a list that
# opens with hours, where most readers take it for minutes. `--since 30m` then
# returned a 900-day window: no error, no warning, just a confidently wrong
# answer that the caller goes on to summarise.
_DURATION_HELP = (
    "Use <number><unit> where unit is h (hours), d (days), w (weeks) or "
    "m (MONTHS, 30 days each) -- e.g. 24h, 7d, 2w, 3m. Minutes are not "
    "supported; `30m` means thirty months."
)
_DAYS_PER_MONTH = 30


def parse_since(value: str) -> datetime:
    """Turn ``24h`` / ``7d`` / ``2w`` / ``3m`` into an aware UTC cutoff.

    Raises :class:`ValueError`, not ``argparse.ArgumentTypeError``. The latter
    inherits straight from ``Exception``, so it fell past the CLI's
    ``except ValueError -> exit 2`` branch into the last-resort handler and a
    plain typo was reported as ``Unexpected ArgumentTypeError`` with exit 1 --
    an API failure, as far as any script could tell. Nothing passes this
    function to argparse as a ``type=`` callable, so nothing wanted the other
    class.
    """
    match = _DURATION.match(value.strip().lower())
    if not match:
        raise ValueError(f"Invalid duration {value!r}. {_DURATION_HELP}")
    amount, unit = int(match.group(1)), match.group(2)
    delta = (timedelta(days=amount * _DAYS_PER_MONTH) if unit == "m"
             else timedelta(**{_DURATION_UNITS[unit]: amount}))
    return datetime.now(timezone.utc) - delta


def reject_duration_for_a_date_flag(value: str | None) -> str | None:
    """Guard the *other* ``--since``, which takes a calendar date.

    Two flags share one name and take different things: ``watch changes
    --since`` is a lookback duration parsed here, while ``watch noise --since``
    and ``matic credits --since`` are calendar dates handed to the gateway
    untouched. Typing ``7d`` at the second pair is the obvious mistake and the
    gateway's answer to it is unknown, so refuse it locally and name the flag
    that does want a duration.

    Deliberately does *not* validate the date itself. The accepted formats were
    never measured, and refusing something the gateway would have accepted is a
    worse failure than passing it through.
    """
    if value is None:
        return None
    if _DURATION.match(value.strip().lower()):
        raise ValueError(
            f"{value!r} is a lookback duration, but this flag takes a calendar "
            "date that is sent to the gateway as-is (e.g. 2026-08-01). "
            "`hexact watch changes --since` is the flag that takes durations."
        )
    return value


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
