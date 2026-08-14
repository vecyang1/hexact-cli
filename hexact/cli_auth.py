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

    refresh = auth.login(args.email, password)

    # Exercise the credential before persisting it. Storing first and finding
    # out later is exactly how an unrenewable token sat in 1Password for a day
    # looking healthy: it authenticated when written and could never be
    # exchanged again. One request closes that window.
    auth.verify_renewable(refresh)

    if args.store == "1password":
        reference = auth.store_refresh_token_1password(
            refresh, item_title=args.op_item, vault=args.op_vault)
        result = {"stored": reference, "backend": "1password", "email": args.email,
                  "next": f"export HEXOWATCH_REFRESH_OP_REF='{reference}'"}
        receipt = (f"Stored a refresh token for {result['email']} as "
                   f"{result['stored']}.\nThe token itself was not printed.\n\n"
                   f"  {result['next']}\n\nVerify with: hexact auth status")
    else:
        path = auth.store_refresh_token(refresh)
        result = {"stored": str(path), "backend": "file", "email": args.email,
                  "next": "hexact auth status"}
        receipt = (f"Stored a refresh token for {result['email']} in "
                   f"{result['stored']} (owner-only).\nThe token itself was not "
                   f"printed. Verify with: hexact auth status")

    # A receipt, deliberately not the token. Printing it would put a
    # full-account credential into terminal scrollback and any agent transcript.
    emit(result, args.json, lambda d: print(receipt))
    return EXIT_OK


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
