"""Session tokens for the Hexact GraphQL gateway.

The gateway does not accept API keys -- verified five ways, all producing the
same ``null`` as sending nothing. It wants the two-stage token the dashboard
uses:

    UserOps.authRefreshToken(email, password) -> refresh token   (long-lived)
    UserOps.authAccessToken(refreshToken)     -> access token    (short-lived)

Only the **refresh token** is ever stored. The password is read once, used once,
and never written anywhere; access tokens live in process memory for the
duration of a single command and are never persisted.

``UserOps`` sits in :data:`hexact.graphql.FORBIDDEN_NAMESPACES`, so the generic
:func:`hexact.graphql.mutate` path cannot reach it. That is intentional and this
module is the deliberate exception: it uses :func:`hexact.graphql.execute`
directly with two fixed, hardcoded documents. The allowlist exists to stop
*arbitrary* account mutations, not to stop logging in -- but the exception is
narrow enough to read in one screen, which is the point.
"""

from __future__ import annotations

import getpass
import os
import stat
from pathlib import Path
from typing import Any

from . import graphql
from .config import HEXOWATCH_SESSION, CredentialError, credentials_path, resolve_key

_REFRESH_MUTATION = """
mutation($email: String!, $password: String!) {
  UserOps {
    authRefreshToken(email: $email, password: $password) {
      token error message
    }
  }
}
"""

_ACCESS_MUTATION = """
mutation($refreshToken: String!) {
  UserOps {
    authAccessToken(refreshToken: $refreshToken) {
      token error message
    }
  }
}
"""

# Reaches its resolver with no arguments and answers with an explicit message
# rather than a silent null, which makes it the one honest way to ask "is this
# token good?". A read query cannot answer that question: it returns null for a
# bad token and null for an empty account, indistinguishably.
_AUTH_PROBE = """
mutation { WatchOps { updateWatchProperty { error message } } }
"""


class LoginError(RuntimeError):
    """Login was refused, or returned no token."""


def _token_from_response(data: dict[str, Any], field: str) -> str:
    result = (data.get("UserOps") or {}).get(field)
    if not isinstance(result, dict):
        raise LoginError(
            f"UserOps.{field} returned no object. The gateway's schema may have "
            "changed; re-derive it from the dashboard bundle."
        )
    if result.get("error"):
        raise LoginError(str(result.get("message") or "login refused"))
    token = result.get("token")
    if not token:
        raise LoginError(
            f"UserOps.{field} reported success but returned no token. Treating "
            "that as a failure rather than continuing with an empty credential."
        )
    return str(token)


def login(email: str, password: str) -> str:
    """Exchange credentials for a refresh token.

    ``password`` is used for exactly this call and is never stored, logged, or
    echoed. Callers should source it from :func:`prompt_password`.
    """
    data = graphql.execute(_REFRESH_MUTATION, {"email": email, "password": password})
    return _token_from_response(data, "authRefreshToken")


def access_token(refresh_token: str | None = None) -> str:
    """Mint a short-lived access token for this process.

    Never persisted: an access token on disk is a liability with no benefit,
    since minting a fresh one costs a single request.
    """
    refresh = refresh_token or resolve_key(HEXOWATCH_SESSION)
    data = graphql.execute(_ACCESS_MUTATION, {"refreshToken": refresh})
    return _token_from_response(data, "authAccessToken")


def prompt_password(prompt: str = "Hexowatch password: ") -> str:
    """Read a password from the terminal without echoing it.

    Deliberately not accepted as a command-line argument: argv is visible to
    every process on the machine and lands in shell history.
    """
    return getpass.getpass(prompt)


def store_refresh_token(token: str) -> Path:
    """Write the refresh token to the credentials file, owner-only.

    Returns the path so the caller can print a receipt. The token itself is
    never returned to a caller that might print it.
    """
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    if path.is_file():
        lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith("HEXOWATCH_REFRESH_TOKEN=")
        ]
    lines.append(f"HEXOWATCH_REFRESH_TOKEN={token}")

    # Create with the right mode from the start rather than chmod-ing after:
    # between the write and the chmod there is a window where the secret is
    # world-readable.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def status() -> tuple[str, str]:
    """Report whether the stored token actually works.

    Returns ``(verdict, detail)`` where verdict is one of ``authenticated``,
    ``rejected``, ``missing`` or ``unknown``.

    ``unknown`` is a real outcome and is not collapsed into ``rejected``: a
    network failure is not evidence about a credential, and reporting it as one
    is how a working token gets needlessly rotated.
    """
    try:
        refresh = resolve_key(HEXOWATCH_SESSION)
    except CredentialError as exc:
        return "missing", str(exc)

    try:
        token = access_token(refresh)
    except LoginError as exc:
        return "rejected", f"refresh token was not accepted: {exc}"
    except graphql.AuthError as exc:
        return "rejected", str(exc)
    except graphql.HexactAPIError as exc:
        return "unknown", f"could not reach the gateway: {exc}"

    try:
        data = graphql.execute(_AUTH_PROBE, token=token)
    except graphql.AuthError as exc:
        return "rejected", str(exc)
    except graphql.HexactAPIError as exc:
        return "unknown", f"could not reach the gateway: {exc}"

    result = (data.get("WatchOps") or {}).get("updateWatchProperty") or {}
    message = str(result.get("message") or "")
    if "authenticat" in message.lower() or "authoriz" in message.lower():
        return "rejected", message
    return "authenticated", "access token minted and accepted by the gateway"
