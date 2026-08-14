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

import base64
import datetime
import getpass
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import graphql
from .config import (
    HEXOWATCH_ACCESS,
    HEXOWATCH_SESSION,
    CredentialError,
    credentials_path,
    resolve_key,
)

# Writing an item is not gated on a biometric prompt for a service account, but
# it is for an interactive one. A bounded wait turns "hung forever in cron" into
# a clear failure, matching hexact/config.py's read timeout.
_OP_WRITE_TIMEOUT_SECONDS = 30

# `UserLoginResponse` carries BOTH `token` and `refresh_token`, and they are
# not interchangeable. `token` is a short-lived JWT usable directly in the
# `authorization` header; `refresh_token` is the long-lived one that
# `authAccessToken` accepts. Selecting only `token` here and persisting it
# produced a credential that worked for about an hour and then could never be
# renewed -- `authAccessToken` answered `error: false` with every field null,
# which is this gateway's house style for "no" and is indistinguishable from
# success unless you check the token itself.
_REFRESH_MUTATION = """
mutation($email: String!, $password: String!) {
  UserOps {
    authRefreshToken(email: $email, password: $password) {
      token refresh_token error message
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


class SessionError(LoginError):
    """A *stored* session credential could not be exchanged.

    Distinct from :class:`LoginError` because the top-level handler prefixes
    the latter with "Login failed", and until 0.7.0 that sentence was printed
    by thirteen commands where nobody had attempted a login -- `spark
    contacts`, `meter overview`, `matic credits` and the rest all reach the
    gateway through :func:`access_token`. A reader concluded their credentials
    had just been rejected at a login they never performed. Subclasses
    ``LoginError`` so any existing ``except`` keeps working.
    """


# An access token from this gateway is minted with a one-hour life; the refresh
# token's is far longer. That gap is the only thing that tells the two apart
# offline, and it is enough: anything this short-lived in the refresh slot is
# the wrong credential, whatever produced it.
_ACCESS_TOKEN_MAX_LIFETIME_SECONDS = 2 * 60 * 60


def classify_credential(token: str) -> dict[str, Any]:
    """Say what a token *is*, offline, without ever revealing it.

    Returns ``kind`` (``access`` / ``refresh`` / ``opaque``), and for a JWT the
    issued/expiry epochs and whether it has already lapsed. Only the timing
    claims are read; the rest of the payload is never touched, since it carries
    account identifiers that have no business in a log or an agent transcript.

    Why this exists. `login` has selected `refresh_token` since the bug that
    named it was fixed, and the stored credential was *still* an access token a
    day later -- written by an older build, never replaced, and unrenewable.
    Nothing in the system could tell, because both values authenticate and both
    are opaque strings. Choosing the right field was never the guarantee;
    checking what actually landed is. Cheap, offline, and decidable, so it runs
    on the way in and on the way out.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {"kind": "opaque", "issued_at": None, "expires_at": None,
                "expired": None, "lifetime_seconds": None}
    try:
        segment = parts[1]
        payload = json.loads(
            base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        )
    except Exception:  # noqa: BLE001 - a malformed JWT is just "opaque" here
        return {"kind": "opaque", "issued_at": None, "expires_at": None,
                "expired": None, "lifetime_seconds": None}

    issued, expires = payload.get("iat"), payload.get("exp")
    lifetime = (expires - issued) if isinstance(issued, int) and isinstance(expires, int) else None
    kind = "refresh"
    if lifetime is not None and lifetime <= _ACCESS_TOKEN_MAX_LIFETIME_SECONDS:
        kind = "access"
    return {
        "kind": kind,
        "issued_at": issued,
        "expires_at": expires,
        "expired": bool(isinstance(expires, int) and expires < time.time()),
        "lifetime_seconds": lifetime,
    }


def describe_credential(token: str) -> str:
    """One human-readable line about a token. Never contains the token."""
    facts = classify_credential(token)
    if facts["kind"] == "opaque":
        return "an opaque token (not a JWT), so its lifetime cannot be read offline"
    stamp = (
        datetime.datetime.fromtimestamp(facts["expires_at"], datetime.timezone.utc)
        .isoformat() if facts["expires_at"] else "unknown"
    )
    hours = (facts["lifetime_seconds"] / 3600) if facts["lifetime_seconds"] else None
    life = f"{hours:.1f}h life" if hours is not None else "unknown life"
    state = "EXPIRED" if facts["expired"] else "still valid"
    article = "an" if facts["kind"][0] in "aeiou" else "a"
    return f"{article} {facts['kind']} token ({life}, expires {stamp}, {state})"


def _token_from_response(
    data: dict[str, Any],
    field: str,
    *,
    field_name: str = "token",
    remedy: str,
    error_type: type[LoginError] = LoginError,
) -> str:
    """Pull one token out of a ``UserOps`` envelope, or raise with a true remedy.

    ``remedy`` is required rather than defaulted because the two callers are in
    genuinely different situations and the shared wording used to describe only
    one of them. Until 0.7.0 both printed *"Most likely cause: the stored value
    is an access token"* -- which on the login path names a stored value that
    does not exist yet (the user has just typed a password), and prescribes as
    the fix the exact command that produced the error.
    """
    result = (data.get("UserOps") or {}).get(field)
    if not isinstance(result, dict):
        raise error_type(
            f"UserOps.{field} returned no object. The gateway's schema may have "
            "changed; re-derive it from the dashboard bundle."
        )
    if result.get("error"):
        raise error_type(str(result.get("message") or "login refused"))
    token = result.get(field_name)
    if not token:
        raise error_type(
            f"UserOps.{field} reported success but returned no {field_name!r}. "
            "Treating that as a failure rather than continuing with an empty "
            f"credential.\n{remedy}"
        )
    return str(token)


def _exchange_failure_remedy(refresh: str) -> str:
    """Explain a failed exchange from what the credential in hand actually is.

    The wrong-field diagnosis is real and cost a day, so it is worth naming --
    but only when the evidence supports it. Asserting it unconditionally
    produced output that contradicted itself two lines later: *"Most likely
    cause: the stored value is an access token"* directly above *"What is
    stored: an opaque token (not a JWT)"*, since :func:`classify_credential`
    can only ever return ``access`` for a readable JWT. A revoked or expired
    token is far commoner, and sending that reader to look for the wrong field
    wastes the one message they will read.
    """
    common = (
        "  Fix: re-run `hexact auth login --email <you>`. Or set "
        "HEXOWATCH_ACCESS_TOKEN to use an access token directly for the next "
        "hour."
    )
    if classify_credential(refresh)["kind"] == "access":
        return (
            "  Cause: the stored value is an access token, not a refresh token "
            f"({describe_credential(refresh)}). They are different fields on "
            "UserLoginResponse and only the refresh token can be exchanged.\n"
            + common
        )
    return (
        "  Cause: the gateway refused the stored refresh token. The commonest "
        "reasons are that it was revoked, that the account's password changed, "
        f"or that it simply expired -- it is {describe_credential(refresh)}.\n"
        + common
    )


def login(email: str, password: str) -> str:
    """Exchange credentials for a **refresh** token.

    ``password`` is used for exactly this call and is never stored, logged, or
    echoed. Callers should source it from :func:`prompt_password`.

    Returns ``refresh_token``, not ``token``. Returning the latter is the bug
    this function exists to not have: it authenticates, so every check passes,
    and it stops working an hour later with no way to renew it.
    """
    data = graphql.execute(_REFRESH_MUTATION, {"email": email, "password": password})
    token = _token_from_response(
        data, "authRefreshToken", field_name="refresh_token",
        # Nothing is stored yet -- the password was typed seconds ago -- so the
        # remedy must not describe a stored credential, and must not be "run
        # the command you just ran".
        remedy=(
            "  Cause: the gateway accepted the request but did not return the "
            "field this client reads. That is a change in UserLoginResponse, "
            "not something wrong with your account.\n"
            "  Fix: re-derive the login mutation from the dashboard bundle "
            "before trusting this path again. Nothing was stored."
        ),
    )

    # Selecting the right field is not proof that the right value arrived. Check
    # what is actually in hand before any caller can persist it -- the failure
    # this catches is silent for an hour and then permanent.
    if classify_credential(token)["kind"] == "access":
        raise LoginError(
            "authRefreshToken returned what looks like an ACCESS token: "
            f"{describe_credential(token)}. Refusing to hand it back as a "
            "refresh token -- it would authenticate today and be unrenewable "
            "tomorrow. The gateway's response shape may have changed; re-derive "
            "UserLoginResponse before trusting this path again."
        )
    return token


def verify_renewable(refresh_token: str) -> None:
    """Prove a refresh token can actually mint an access token. Raises if not.

    The project's rule for mutations is that an ``{"error": false}`` answer is a
    claim rather than proof, and every write is read back. The credential path
    was the one place that rule was never applied: a token was stored on the
    strength of the response that produced it, and nothing exercised it until
    the next command -- or, as happened here, the next day.

    One extra request at login turns "unrenewable credential" from a silent
    failure discovered later into a loud one discovered now.
    """
    minted = access_token(refresh_token=refresh_token)
    if not minted:
        raise LoginError(
            "the refresh token was accepted but minted no access token; "
            "refusing to store a credential that cannot be exchanged."
        )


def access_token(refresh_token: str | None = None) -> str:
    """Mint a short-lived access token for this process.

    Never persisted: an access token on disk is a liability with no benefit,
    since minting a fresh one costs a single request.
    """
    # An access token supplied directly wins: it needs no exchange, and it lets
    # a caller hold the narrower of the two credentials. Only consulted when no
    # explicit refresh token was passed in, so tests stay deterministic.
    if refresh_token is None:
        try:
            return resolve_key(HEXOWATCH_ACCESS)
        except CredentialError:
            pass

    refresh = refresh_token or resolve_key(HEXOWATCH_SESSION)
    data = graphql.execute(_ACCESS_MUTATION, {"refreshToken": refresh})
    return _token_from_response(
        data, "authAccessToken",
        remedy=_exchange_failure_remedy(refresh),
        error_type=SessionError,
    )


def _terminal_available() -> bool:
    """Whether a password can be read without it being echoed somewhere.

    Mirrors what :mod:`getpass` itself tries: the controlling terminal first,
    then stdin. Asking ``sys.stdin.isatty()`` alone would be wrong in both
    directions -- ``hexact auth login --email you < notes.txt`` typed at a real
    terminal still has a perfectly good ``/dev/tty`` to prompt on.
    """
    try:
        with open("/dev/tty"):
            return True
    except OSError:
        return sys.stdin.isatty()


def prompt_password(prompt: str = "Hexowatch password: ") -> str:
    """Read a password from the terminal without echoing it.

    Deliberately not accepted as a command-line argument: argv is visible to
    every process on the machine and lands in shell history.

    Refuses outright when no terminal can be reached, because :mod:`getpass`
    answers that case by falling back to a *plain, echoing* read of stdin. It
    says so -- "Warning: Password input may be echoed." -- and carries on, which
    in a CI job, a pipeline or an agent tool call writes the account password
    into whatever is capturing that stream. Measured 2026-08-14 on the shipped
    0.6.0 binary: the fallback then raised ``EOFError`` on the empty pipe, so
    the run ended at the top-level handler for *unforeseen* exceptions as
    "Unexpected EOFError:" -- no diagnosis, no remedy, for a condition that is
    entirely foreseeable. Refuse by name instead, and offer the routes that
    exist.
    """
    if not _terminal_available():
        raise LoginError(
            "No terminal is available to type a password into, so nothing was "
            "sent. Reading it from a pipe is refused rather than done quietly: "
            "without a terminal the password would be echoed into this "
            "command's own output.\n"
            "  Interactive: run this from a real terminal.\n"
            "  Automation:  hexact auth login --email <you> --password-stdin\n"
            "               (reads one line from stdin; never touches argv)\n"
            "  Already hold a token: export HEXOWATCH_REFRESH_TOKEN=... or "
            "HEXOWATCH_REFRESH_OP_REF='op://Vault/Item/field'"
        )
    try:
        return getpass.getpass(prompt)
    except EOFError as exc:
        raise LoginError(
            "The password prompt was closed before anything was typed; "
            "nothing was sent."
        ) from exc
    except KeyboardInterrupt as exc:
        raise LoginError("Cancelled at the password prompt; nothing was sent.") from exc


def read_password_from_stdin() -> str:
    """Read exactly one line of password from stdin, for automation.

    The conventional shape (``docker login``, ``gh auth login``): the caller
    pipes the secret in, so it never appears in argv or in shell history. Kept
    separate from :func:`prompt_password` on purpose -- one is a terminal read
    and the other is a pipe read, and conflating them is precisely how the
    echoing fallback got in.

    Only the line terminator is stripped. ``.strip()`` would silently mangle a
    password that legitimately ends in a space, and the failure would look like
    a wrong password rather than like a bug here.

    Refuses when stdin *is* a terminal, which is the mirror of the bug this
    function was added for: with no pipe attached, ``readline`` would sit there
    echoing every character the user types.
    """
    if sys.stdin.isatty():
        raise LoginError(
            "--password-stdin expects a pipe, but stdin is a terminal -- you "
            "would be typing the password in the clear. Nothing was sent. Drop "
            "the flag to get a hidden prompt instead."
        )
    line = sys.stdin.readline()
    if not line.rstrip("\r\n"):
        raise LoginError(
            "--password-stdin was given but stdin carried no password; "
            "nothing was sent. Pipe it in, e.g. "
            "`... | hexact auth login --email <you> --password-stdin`."
        )
    return line.rstrip("\r\n")


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


def store_refresh_token_1password(
    token: str,
    *,
    item_title: str,
    vault: str,
    op_cmd: list[str] | None = None,
) -> str:
    """Store the refresh token as a 1Password item, without exposing it.

    The token is passed in a **JSON template file** created mode 600, never as a
    command-line assignment. 1Password's own CLI says so: ``op item create``
    documents that sensitive values belong in a template rather than an
    assignment statement, because argv is readable by every process on the
    machine.

    The child's stdout is discarded rather than returned, since ``op item
    create`` echoes the item it made -- which in an agent session would put the
    credential straight into a captured transcript.

    Returns the ``op://`` reference to put in ``HEXOWATCH_REFRESH_OP_REF``.
    """
    command = op_cmd or shlex.split(os.environ.get("HEXACT_OP_CMD", "op"))
    template = {
        "title": item_title,
        "category": "API_CREDENTIAL",
        "fields": [
            {"id": "credential", "type": "CONCEALED", "label": "credential",
             "value": token},
            {"id": "notesPlain", "type": "STRING", "label": "notesPlain",
             "value": ("Hexowatch GraphQL refresh token, written by `hexact auth "
                       "login`. Full-account scope -- broader than the REST API "
                       "key. Mint access tokens with UserOps.authAccessToken.")},
        ],
    }

    handle, path = tempfile.mkstemp(prefix="hexact-op-", suffix=".json")
    try:
        os.fchmod(handle, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(template, stream)
        completed = subprocess.run(
            [*command, "item", "create", "--vault", vault, "--template", path],
            capture_output=True, text=True, timeout=_OP_WRITE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LoginError(
            f"{command[0]!r} is not installed, so the token could not be stored "
            "in 1Password. Re-run with --store file, or set HEXACT_OP_CMD."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LoginError(
            f"Timed out after {_OP_WRITE_TIMEOUT_SECONDS}s writing to 1Password. "
            "An interactive unlock cannot succeed unattended; use a service account."
        ) from exc
    finally:
        # The window where the token exists on disk is this function's body, and
        # the file is owner-only for all of it.
        try:
            os.unlink(path)
        except OSError:
            pass

    if completed.returncode != 0:
        # `op` reports the item and the vault, not the secret, so this is safe
        # to surface.
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise LoginError(f"Could not create the 1Password item: {detail}")

    return f"op://{vault}/{item_title}/credential"


def status() -> tuple[str, str]:
    """Report whether the stored token actually works.

    Returns ``(verdict, detail)`` where verdict is one of ``authenticated``,
    ``rejected``, ``missing`` or ``unknown``.

    ``unknown`` is a real outcome and is not collapsed into ``rejected``: a
    network failure is not evidence about a credential, and reporting it as one
    is how a working token gets needlessly rotated.
    """
    # Ask for a credential the same way the real commands do, instead of
    # re-implementing the ladder. Checking only HEXOWATCH_SESSION made `status`
    # report "missing" on a session where every other command worked off
    # HEXOWATCH_ACCESS_TOKEN -- a health check that says broken while the thing
    # it checks is fine trains people to ignore it.
    try:
        token = access_token()
    except CredentialError as exc:
        return "missing", str(exc)
    except LoginError as exc:
        # Name what is actually stored. "Not accepted" sends the reader to the
        # network or the account; the real cause here was an access token sitting
        # in the refresh slot, which only the token's own claims reveal. Best
        # effort: an unreadable credential must not turn a diagnosis into a crash.
        try:
            stored = describe_credential(resolve_key(HEXOWATCH_SESSION))
        except Exception:  # noqa: BLE001
            stored = None
        detail = f"stored token was not accepted: {exc}"
        if stored:
            detail += f"\n  What is stored: {stored}."
        return "rejected", detail
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
