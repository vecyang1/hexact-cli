"""Shared HTTP layer for the Hexact REST APIs.

Two properties of these APIs shape this module, and both are traps:

1. **The API key travels as a query parameter.** Every URL therefore contains a
   live credential, so any exception, log line, or traceback that echoes a URL
   leaks it. Every outward-facing string goes through :func:`redact` first.

2. **HTTP 200 does not mean success.** The APIs answer with an envelope,
   ``{"error": false, ...}`` on success and ``{"error": true, "message": ...}``
   on failure, and the failure case still arrives as a 200. Checking the status
   code alone silently accepts errors as data.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import __version__

DEFAULT_TIMEOUT_SECONDS = 60

# Cloudflare sits in front of both APIs and rejects urllib's default
# `Python-urllib/3.x` agent with error 1010 (`browser_signature_banned`) -- a
# 403 that arrives *before* the key is examined, so it reads exactly like an
# auth failure and sends you to rotate a perfectly good credential. Measured
# 2026-08-13: curl's own `curl/8.x` agent passes, so the block targets the
# urllib signature specifically rather than demanding a browser. An honest
# self-identifying agent is therefore enough; do not spoof a browser here.
# Built from `__version__` rather than typed, because it was typed in two files
# and a version bump updated neither. A User-Agent that lies about its version
# is worse than an unversioned one: it makes a server-side log claim a release
# that was never the one running.
USER_AGENT = f"hexact-cli/{__version__} (+https://github.com/vecyang1/hexact-cli)"

# Matches the credential in `?key=...` / `&key=...` regardless of position.
_KEY_PATTERN = re.compile(r"([?&]key=)[^&\s]*")


class HexactAPIError(RuntimeError):
    """An API call failed -- by transport, by status code, or by envelope."""


def redact(text: str) -> str:
    """Replace any ``key=<secret>`` occurrence with ``key=***REDACTED***``."""
    return _KEY_PATTERN.sub(r"\1***REDACTED***", text)


def path_segment(value: Any) -> str:
    """Escape one value for safe interpolation into a URL path.

    Path components are IDs that arrive from CLI arguments and from API
    responses, and an unescaped one is a credential-disclosure bug rather than
    a cosmetic one: a single control character makes ``http.client`` raise
    ``InvalidURL`` with the **whole URL** -- including ``key=`` -- in its
    message. That exception is a bare ``HTTPException``, so it inherits from
    neither ``URLError`` nor ``OSError`` and slips past the handlers below.
    Encoding here stops the exception being raised at all; :func:`request`
    redacts as the second line of defence.
    """
    return urllib.parse.quote(str(value), safe="")


def _build_url(base: str, path: str, key: str, params: dict[str, Any] | None) -> str:
    query: dict[str, Any] = {"key": key}
    for name, value in (params or {}).items():
        if value is None:
            continue
        # urlencode renders Python bools as "True"/"False"; these APIs want
        # lowercase JSON-style booleans.
        query[name] = str(value).lower() if isinstance(value, bool) else value
    return f"{base.rstrip('/')}/{path.lstrip('/')}?{urllib.parse.urlencode(query)}"


def request(
    base: str,
    path: str,
    key: str,
    *,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Call a Hexact endpoint and return its decoded payload.

    Raises :class:`HexactAPIError` on transport failure, a non-2xx status, an
    undecodable body, or an ``error: true`` envelope. Every message is redacted.
    """
    url = _build_url(base, path, key, params)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:500]
        except Exception:  # noqa: BLE001 - the status is the useful part
            pass
        raise HexactAPIError(
            redact(f"HTTP {exc.code} from {url}" + (f": {detail}" if detail else ""))
        ) from None
    except urllib.error.URLError as exc:
        raise HexactAPIError(redact(f"Could not reach {url}: {exc.reason}")) from None
    except Exception as exc:
        # Catch-all, and deliberately last. Anything urllib or http.client can
        # raise may embed the full URL -- and therefore the key -- in its
        # message; http.client.InvalidURL is the known case and is not an
        # OSError, so nothing above sees it. Enumerating exception types here
        # has already failed once, so redact whatever arrives instead.
        raise HexactAPIError(
            redact(f"{type(exc).__name__} calling {path}: {exc}")
        ) from None

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HexactAPIError(
            redact(f"Non-JSON response from {url}: {raw[:200]!r}")
        ) from exc

    # The envelope check. Without it, a 200 carrying `error: true` is returned
    # to the caller as if it were data.
    if isinstance(payload, dict) and payload.get("error"):
        message = payload.get("message") or payload.get("error_message") or "unknown"
        raise HexactAPIError(redact(f"API error from {path}: {message}"))

    return payload if isinstance(payload, dict) else {"data": payload}
