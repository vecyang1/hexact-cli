"""Session login and status.

Separated from the commands that consume the session because the thing being
handled here is a password, and a file that touches one should be short enough
to read in a sitting.
"""

from __future__ import annotations

import argparse
import sys

from . import auth
from .output import EXIT_FAILURE, EXIT_OK, EXIT_USAGE, emit

def cmd_auth_login(args: argparse.Namespace) -> int:
    """Exchange email + password for a stored refresh token.

    The password is read from the terminal, or from stdin with
    ``--password-stdin``; never from a flag. argv is visible to every process on
    the machine and lands in shell history. It is used for one request and never
    written anywhere.
    """
    password = (auth.read_password_from_stdin() if args.password_stdin
                else auth.prompt_password())
    if not password:
        print("No password entered; nothing was sent.", file=sys.stderr)
        return EXIT_USAGE

    tokens = auth.login(args.email, password)
    refresh, access = tokens["refresh"], tokens["access"]

    # STORE FIRST. The previous order -- verify, then store -- meant a failure
    # of the *second* call threw away a credential the first call had just
    # issued correctly. Measured 2026-08-14: a genuine 360-hour refresh token,
    # classified as such, valid for another fortnight, discarded because
    # `authAccessToken` refused it; the user had typed their password and ended
    # with nothing stored at all. Verification reports; it does not decide
    # whether the credential survives.
    if args.store == "1password":
        where = auth.store_refresh_token_1password(
            refresh, item_title=args.op_item, vault=args.op_vault)
        backend, follow_up = "1password", f"export HEXOWATCH_REFRESH_OP_REF='{where}'"
    else:
        where, backend = str(auth.store_refresh_token(refresh)), "file"
        follow_up = "hexact auth status"

    # The access token from the same response, kept in the local credentials
    # file whichever backend holds the refresh token. It is the narrower of the
    # two and it expires by itself, and it is what keeps the CLI usable in the
    # hour after a login whose exchange failed.
    access_path = auth.store_access_token(access) if access else None

    renewal, detail = "proven", None
    try:
        auth.verify_renewable(refresh)
    except auth.LoginError as exc:
        renewal, detail = "unproven", str(exc)

    result = {"stored": where, "backend": backend, "email": args.email,
              "access_token_stored": bool(access_path), "renewal": renewal,
              "detail": detail, "next": follow_up}

    def render(d: dict) -> None:
        # A receipt, deliberately not the token. Printing either would put a
        # credential into terminal scrollback and any agent transcript.
        print(f"Stored a refresh token for {d['email']} in {d['stored']} "
              f"({'1Password' if d['backend'] == '1password' else 'owner-only'}).")
        if d["access_token_stored"]:
            print(f"Also kept the access token from the same response in "
                  f"{auth.credentials_path()}, so commands work now.")
        print("Neither token was printed.\n")
        if d["renewal"] == "proven":
            print(f"Renewal proven against the gateway.\n\n  {d['next']}")
        else:
            print("RENEWAL IS UNPROVEN. The login succeeded and both tokens are\n"
                  "stored, but UserOps.authAccessToken would not exchange the\n"
                  "refresh token, so this will stop working when the access\n"
                  "token expires and you will have to log in again.\n\n"
                  f"{d['detail']}", file=sys.stderr)

    emit(result, args.json, render)
    return EXIT_OK if renewal == "proven" else EXIT_FAILURE


# A verdict is not a two-way switch. `auth.status()` goes to some trouble to
# keep "the gateway said no" apart from "the gateway never answered", and until
# 0.7.0 the exit code threw that away by returning 1 for both -- so a network
# outage was indistinguishable from a dead credential to anything scripting it,
# which is exactly how a working token gets rotated during an outage.
_STATUS_EXIT = {
    "authenticated": EXIT_OK,       # verified
    "rejected": EXIT_FAILURE,       # a real finding
    "missing": EXIT_USAGE,          # nothing to check
    "unknown": EXIT_USAGE,          # could not check
}
_STATUS_MARKS = {"authenticated": "OK  ", "rejected": "FAIL",
                 "missing": "NONE", "unknown": "????"}


def cmd_auth_status(args: argparse.Namespace) -> int:
    """Report whether the stored token actually works.

    Distinguishes ``unknown`` (the gateway was unreachable) from ``rejected``
    (it answered and refused). Collapsing those is how a working credential
    gets rotated for no reason.
    """
    verdict, detail = auth.status()
    code = _STATUS_EXIT[verdict]

    def render(data: dict[str, str]) -> None:
        line = f"[{_STATUS_MARKS[data['verdict']]}] {data['verdict']}: {data['detail']}"
        # Anything other than a pass goes to stderr, like every other failure
        # in this CLI. `auth status` was the one command printing its bad news
        # on stdout, so `hexact auth status > /dev/null` hid the reason.
        print(line, file=sys.stdout if code == EXIT_OK else sys.stderr)

    emit({"verdict": verdict, "detail": detail}, args.json, render)
    return code
