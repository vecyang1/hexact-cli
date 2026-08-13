"""Credential resolution for the Hexact APIs.

The one rule this module exists to enforce: **an API key is never written to,
read from, or defaulted into anything inside the repository.** Keys are
resolved at runtime from a source the operator controls, in a fixed order, and
the repository only ever contains a *pointer* to that source.

Resolution order (first hit wins), per service:

1. Environment variable -- ``HEXOWATCH_API_KEY`` / ``HEXOMATIC_API_KEY``.
2. 1Password secret reference -- ``HEXOWATCH_OP_REF`` / ``HEXOMATIC_OP_REF``,
   an ``op://Vault/Item/field`` URI read via the 1Password CLI.
3. Credentials file -- ``~/.config/hexact/credentials.env`` (or ``$HEXACT_HOME``),
   a ``KEY=value`` file that must not be group- or world-readable.

The 1Password route is the recommended one for anything that runs unattended.
``HEXACT_OP_CMD`` overrides the executable used to reach it, so an operator
whose vault is behind a service-account wrapper can point at that wrapper
without patching this file.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
from pathlib import Path

# Fields the credentials file and 1Password item are expected to use.
HEXOWATCH = "hexowatch"
HEXOMATIC = "hexomatic"
HEXOMETER = "hexometer"

# Not an API key. The GraphQL gateway refuses API keys outright (measured five
# ways), so delete and update need a session credential instead. It resolves
# through the same ladder because the ladder is about *where secrets live*, not
# about what they authenticate.
#
# Worth knowing before storing one: this credential is broader than the API
# keys above. An API key reaches the six documented REST endpoints; a refresh
# token reaches the whole account. `hexact.graphql.MUTATION_ALLOWLIST` is the
# mitigation, and it is enforced in code rather than by convention.
HEXOWATCH_SESSION = "hexowatch_session"

# A already-minted access token, used as-is without an exchange. Two callers
# need this: CI, which should be handed a short-lived credential rather than a
# refresh token that reaches the whole account, and anyone recovering from a
# login that stored the wrong field -- see `auth.login`.
HEXOWATCH_ACCESS = "hexowatch_access"

_ENV_VARS = {
    HEXOWATCH: "HEXOWATCH_API_KEY",
    HEXOMATIC: "HEXOMATIC_API_KEY",
    HEXOMETER: "HEXOMETER_API_KEY",
    HEXOWATCH_SESSION: "HEXOWATCH_REFRESH_TOKEN",
    HEXOWATCH_ACCESS: "HEXOWATCH_ACCESS_TOKEN",
}
_OP_REF_VARS = {
    HEXOWATCH: "HEXOWATCH_OP_REF",
    HEXOMATIC: "HEXOMATIC_OP_REF",
    HEXOMETER: "HEXOMETER_OP_REF",
    HEXOWATCH_SESSION: "HEXOWATCH_REFRESH_OP_REF",
    HEXOWATCH_ACCESS: "HEXOWATCH_ACCESS_OP_REF",
}

# `op read` blocks on a biometric prompt when it has to unlock interactively.
# A short timeout turns "hung forever in a cron job" into a clear failure.
_OP_TIMEOUT_SECONDS = 30


class CredentialError(RuntimeError):
    """Raised when no key could be resolved, or a source is unsafe to use."""


def _config_dir() -> Path:
    override = os.environ.get("HEXACT_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "hexact"


def credentials_path() -> Path:
    return _config_dir() / "credentials.env"


def _from_env(service: str) -> str | None:
    value = os.environ.get(_ENV_VARS[service], "").strip()
    return value or None


def _from_1password(service: str) -> str | None:
    ref = os.environ.get(_OP_REF_VARS[service], "").strip()
    if not ref:
        return None
    if not ref.startswith("op://"):
        raise CredentialError(
            f"{_OP_REF_VARS[service]} must be an op:// secret reference, got {ref!r}"
        )

    # Default to the stock CLI; HEXACT_OP_CMD lets an operator route through a
    # service-account wrapper instead. Split as a shell word list so the
    # override can carry its own arguments.
    op_cmd = shlex.split(os.environ.get("HEXACT_OP_CMD", "op"))
    try:
        completed = subprocess.run(
            [*op_cmd, "read", ref],
            capture_output=True,
            text=True,
            timeout=_OP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CredentialError(
            f"{_OP_REF_VARS[service]} is set but {op_cmd[0]!r} is not installed. "
            "Install the 1Password CLI, or set HEXACT_OP_CMD to your wrapper."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CredentialError(
            f"Timed out after {_OP_TIMEOUT_SECONDS}s reading {ref}. This usually "
            "means the CLI is waiting on an interactive unlock, which cannot "
            "succeed in an unattended run. Use a service account for that lane."
        ) from exc

    if completed.returncode != 0:
        # stderr from `op` names the item, not the secret, so it is safe to show.
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise CredentialError(f"Could not read {ref}: {detail}")

    return completed.stdout.strip() or None


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip().strip("'\"")
    return values


def _from_file(service: str) -> str | None:
    path = credentials_path()
    if not path.is_file():
        return None

    # A secrets file other users can read is a finding, not a warning. Refuse it
    # rather than silently loading a key that has already leaked locally.
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CredentialError(
            f"{path} is group- or world-accessible. Run: chmod 600 {path}"
        )

    return _parse_env_file(path).get(_ENV_VARS[service]) or None


def resolve_key(service: str) -> str:
    """Return the API key for ``service``, or raise :class:`CredentialError`.

    The error message deliberately lists every configured source, because the
    common failure is "I set it in the place this run does not read".
    """
    if service not in _ENV_VARS:
        raise ValueError(f"Unknown service {service!r}")

    for source in (_from_env, _from_1password, _from_file):
        key = source(service)
        if key:
            return key

    if service == HEXOWATCH_SESSION:
        # This message must name neither a product nor an operation, because
        # one session token serves the whole suite and every GraphQL command
        # raises this same error. Measured 2026-08-14 across six command
        # families: the previous wording, "No Hexowatch session token found.
        # Delete and update are GraphQL-only...", was printed verbatim by
        # `matic credits`, `spark contacts` and `meter overview` -- naming a
        # product the user may not own and an operation they did not run. The
        # remedy underneath was correct, which is what made it expensive: a
        # reader who does not use Hexowatch reasonably concludes the error is
        # about something else and never reaches the fix. An accurate
        # diagnosis with a correct remedy is not the same as a wrong diagnosis
        # with a correct remedy.
        raise CredentialError(
            "No Hexact session token found. This command reads the GraphQL "
            "gateway, which the REST API keys do not authenticate against -- "
            "it needs the dashboard session credential instead. One session "
            "covers the whole suite; Hexowatch, Hexomatic, Hexometer and "
            "Hexospark share the same gateway.\n"
            "  Run: hexact auth login --email <you>\n"
            f"  Or set {_OP_REF_VARS[service]}='op://Vault/Item/field'"
        )

    raise CredentialError(
        f"No API key found for {service}. Set one of:\n"
        f"  1. export {_ENV_VARS[service]}=...\n"
        f"  2. export {_OP_REF_VARS[service]}='op://Vault/Item/field'  (recommended)\n"
        f"  3. echo '{_ENV_VARS[service]}=...' >> {credentials_path()} "
        f"&& chmod 600 {credentials_path()}\n"
        f"Keys come from the API/Webhook section of the {service} dashboard settings."
    )
