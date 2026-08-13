"""Hexometer API client -- website health, performance, SEO and security monitoring.

Documented at https://hexometer.com/api-documentation/. Four endpoints, all
authenticated with the same ``?key=`` query parameter as the other Hexact
products; the key comes from a *property's* settings rather than the account's.

**Do not identify a Hexact product by its hostname.** All Hexact API hosts sit
behind one shared backend: ``api.hexospark.com`` and ``api.hexofy.com`` answer
Hexowatch's and Hexometer's routes with byte-identical responses, including a
plausible ``{"error": true, "message": "invalid api key"}``. Probing a hostname
therefore proves nothing about which product exists, and building a client that
routes by host would ship a "Hexospark" feature that silently returns Hexometer
data. Products are distinguished by their *documented endpoints*, which is why
this module exists separately rather than parameterising a base URL.
"""

from __future__ import annotations

from typing import Any

from .http import request

BASE_URL = "https://api.hexometer.com/v2/app/services/v1"

# Observed on the documented `detected_errors` endpoint. Not an exhaustive
# enum -- the docs give this as an example value rather than a closed list, so
# it is not validated against.
EXAMPLE_TOOL_NAME = "Security_Domain_&_DNS"


def _call(key: str, path: str, **kwargs: Any) -> dict[str, Any]:
    return request(BASE_URL, path, key, **kwargs)


def list_properties(key: str) -> dict[str, Any]:
    """Every monitored property on the account."""
    return _call(key, "properties")


def health_link_statuses(key: str, property_id: int) -> dict[str, Any]:
    """Available health-link statuses for one property."""
    return _call(key, "health_links/statuses", method="POST",
                 body={"property_id": property_id})


def health_links(key: str, property_id: int, status: Any) -> dict[str, Any]:
    """Health links for one property, filtered by status.

    Call :func:`health_link_statuses` first to discover valid ``status`` values;
    the documentation does not publish them as a fixed enum.
    """
    return _call(key, "health_links", method="POST",
                 body={"property_id": property_id, "status": status})


def detected_errors(key: str, property_id: int, tool_name: str) -> dict[str, Any]:
    """Errors detected by one Hexometer tool on one property."""
    return _call(key, "detected_errors", method="POST",
                 body={"property_id": property_id, "tool_name": tool_name})
