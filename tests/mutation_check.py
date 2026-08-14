#!/usr/bin/env python3
"""Break the code on purpose and confirm the suite notices.

A passing test proves nothing until you have watched it fail. This applies each
mutation to a **fresh copy** of the tree and asserts the pattern was actually
found first, because the failure mode of a mutation harness is silent and green:
copy the source to the wrong place, or fail to match the pattern, and every
mutation reports CAUGHT while the untouched suite passes underneath.

Run:  python3 tests/mutation_check.py
Exit: 0 when every mutation was caught, 1 when any survived.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

# (label, file, find, replace) -- each must break a real guarantee.
MUTATIONS = [
    (
        "null response returns None instead of raising AuthError",
        "hexact/graphql.py",
        '    scope = data.get(namespace)\n    if scope is None:',
        '    scope = data.get(namespace)\n    if False:',
    ),
    (
        "null field returns None instead of raising AuthError",
        "hexact/graphql.py",
        '    value = scope.get(field)\n    if value is None:',
        '    value = scope.get(field)\n    if False:',
    ),
    (
        "mutation allowlist is not enforced",
        "hexact/graphql.py",
        '    if operation not in MUTATION_ALLOWLIST:',
        '    if False:',
    ),
    (
        "forbidden namespace check is removed",
        "hexact/graphql.py",
        '    if namespace in FORBIDDEN_NAMESPACES:',
        '    if False:',
    ),
    (
        "mutation arguments are interpolated into the query document",
        "hexact/graphql.py",
        '    passthrough = ", ".join(f"{name}: ${name}" for name in supplied)',
        '    passthrough = ", ".join(f"{name}: {spec[1]}" for name, spec in supplied.items())',
    ),
    (
        "delete stops requiring --yes",
        "hexact/cli_hexowatch.py",
        '    if not args.yes:\n        listed = " ".join(str(i) for i in args.ids)',
        '    if False:\n        listed = " ".join(str(i) for i in args.ids)',
    ),
    (
        "an unreachable gateway is reported as a rejected credential",
        "hexact/auth.py",
        '        return "unknown", f"could not reach the gateway: {exc}"\n\n    try:\n        data = graphql.execute',
        '        return "rejected", f"could not reach the gateway: {exc}"\n\n    try:\n        data = graphql.execute',
    ),
    (
        "login continues with an empty token",
        "hexact/auth.py",
        '    token = result.get(field_name)\n    if not token:',
        '    token = result.get(field_name)\n    if False:',
    ),
    (
        # The bug this file exists to prevent recurring: `token` and
        # `refresh_token` are both real fields, so selecting the wrong one
        # authenticates for an hour and then dies unrenewable.
        "login stores the access token instead of the refresh token",
        "hexact/auth.py",
        '        data, "authRefreshToken", field_name="refresh_token",',
        '        data, "authRefreshToken", field_name="token",',
    ),
    (
        "a deleted monitor reading back as all-nulls counts as still present",
        "hexact/cli_hexowatch.py",
        '        if not monitor or monitor.get("id") in (None, "", 0):',
        '        if False:',
    ),
    (
        "an API error during delete read-back counts as proof of deletion",
        "hexact/cli_hexowatch.py",
        '            unverified.append({"id": target["id"], "reason": str(exc)})\n            continue\n        if not monitor',
        '            confirmed.append(target["id"])\n            continue\n        if not monitor',
    ),
    (
        "mute drops the empty list instead of sending it",
        "hexact/graphql.py",
        '    supplied = {name: spec for name, spec in arguments.items() if spec[1] is not None}',
        '    supplied = {name: spec for name, spec in arguments.items() if spec[1]}',
    ),
    (
        "the stored credentials file is world-readable",
        "hexact/auth.py",
        '    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)',
        '    os.chmod(path, 0o644)',
    ),
    (
        "duplicates group by address, ignoring the tool",
        "hexact/cli_watch_rest.py",
        'groups.setdefault((_normalise_address(str(address)), tool), []).append(monitor)',
        'groups.setdefault((_normalise_address(str(address)), "X"), []).append(monitor)',
    ),
    (
        "the 1Password write passes the token as a command-line argument",
        "hexact/auth.py",
        '            [*command, "item", "create", "--vault", vault, "--template", path],',
        '            [*command, "item", "create", "--vault", vault, f"credential={token}"],',
    ),
    (
        "a failed 1Password write leaves the token on disk",
        "hexact/auth.py",
        '    finally:\n        # The window where the token exists on disk is this function\'s body, and\n        # the file is owner-only for all of it.\n        try:\n            os.unlink(path)\n        except OSError:\n            pass',
        '    finally:\n        pass',
    ),
    (
        "login stops classifying what it hands back",
        "hexact/auth.py",
        '    if classify_credential(token)["kind"] == "access":',
        '    if False:',
    ),
    (
        "login stores a credential without exchanging it first",
        "hexact/cli_auth.py",
        '    auth.verify_renewable(refresh)',
        '    pass  # mutation: skip the exchange',
    ),
    (
        "a tag create trusts the gateway instead of reading it back",
        "hexact/cli_hexowatch.py",
        '    confirmed = next((t for t in after if t.get("id") == tag_id), None)',
        '    confirmed = {"id": tag_id, "name": "?", "color": "?"}',
    ),
    (
        "a tag delete reports success without checking the tag is gone",
        "hexact/cli_hexowatch.py",
        '    still_there = any(t.get("id") == args.tag_id for t in after)',
        '    still_there = False',
    ),
    (
        "replacing tags with an empty list stops being refused",
        "hexact/cli_hexowatch.py",
        '    if not args.tags and not args.clear:',
        '    if False:',
    ),
    (
        "deleting alerts stops requiring --yes",
        "hexact/cli_hexowatch.py",
        '    if args.alert_action == "delete" and not args.yes:',
        '    if False:',
    ),
    (
        "a gateway JSON string that will not parse becomes a crash",
        "hexact/cli_hexomatic.py",
        '    try:\n        return json.loads(value)\n    except (ValueError, TypeError):\n        return value',
        '    return json.loads(value)',
    ),
    (
        "monitor filters are interpolated into the query document",
        "hexact/graphql.py",
        '            "searchQuery": search, "sortBy": sort_by, "sortDir": sort_dir,',
        '            "searchQuery": None, "sortBy": sort_by, "sortDir": sort_dir,',
    ),
    (
        "an unreachable gateway is reported as schema drift",
        "tools/validate_documents.py",
        '              f"unknown, not as \'no drift\'.", file=sys.stderr)\n        return 2',
        '              f"unknown, not as \'no drift\'.", file=sys.stderr)\n        return 1',
    ),
    (
        "a non-JSON body is parsed as a verdict instead of raising",
        "tools/validate_documents.py",
        '        raise GatewaySilent(f"HTTP {exc.code} with a non-JSON body") from inner',
        '        return {"_http": exc.code}',
    ),
    (
        # Not a code guarantee -- a documentation one. The README's description
        # of the write boundary is derived from the allowlist, so drift in
        # either direction has to be visible.
        "the README's allowlist namespaces drift from the code",
        "README.md",
        "`UserWatchSettingsOps`, `WatchAlertOps`, `WatchIntegrationOps`, `WatchOps`,\n`WatchTagOps`",
        "`UserWatchSettingsOps`, `WatchAlertOps`, `WatchIntegrationOps`, `WatchOps`",
    ),
    (
        "the shared session error goes back to naming one product and one operation",
        "hexact/config.py",
        '            "No Hexact session token found. This command reads the GraphQL "',
        '            "No Hexowatch session token found. Delete and update are GraphQL-only "',
    ),
    (
        # The pre-0.7.0 behaviour exactly: let getpass decide, and it answers
        # "no terminal" by echoing the password into whatever is capturing the
        # stream. The mutation is a one-word lie, which is why it needs a test.
        "the password prompt stops checking for a terminal before reading",
        "hexact/auth.py",
        "    if not _terminal_available():",
        "    if False:",
    ),
    (
        "--password-stdin stops refusing a terminal and echoes what is typed",
        "hexact/auth.py",
        "    if sys.stdin.isatty():",
        "    if False:",
    ),
    (
        # Reverting doctor to two outcomes. Nothing errors, nothing looks
        # different -- the tick just stops meaning anything.
        "doctor reports a pass again after examining zero credentials",
        "hexact/cli.py",
        '    if worst == EXIT_OK and not any(o["ok"] for o in results.values()):',
        "    if False:",
    ),
    (
        "doctor stops looking at the gateway credential half the commands need",
        "hexact/cli.py",
        '    if verdict == "rejected":',
        "    if False:",
    ),
    (
        "a stored token failing is labelled a failed login again",
        "hexact/cli.py",
        '        print(f"Session error: {redact(str(exc))}", file=sys.stderr)',
        '        print(f"Login failed: {redact(str(exc))}", file=sys.stderr)',
    ),
    (
        # The output that contradicted itself: "the stored value is an access
        # token" printed directly above "an opaque token (not a JWT)".
        "the wrong-field diagnosis is asserted again without the evidence",
        "hexact/auth.py",
        '    if classify_credential(refresh)["kind"] == "access":',
        "    if True:",
    ),
    (
        "a printed command drifts from the parser that has to accept it",
        "hexact/cli_hexowatch.py",
        "hexact watch list --tag <id>",
        "hexact watch monitors --tag <id>",
    ),
    (
        "unmute resolves a credential before checking it was called correctly",
        "hexact/cli_hexowatch.py",
        "    targets = [int(i) for i in args.ids]\n"
        "    channel_ids = [] if args.mute else [int(i) for i in args.channels]",
        "    token = auth.access_token()\n"
        "    targets = [int(i) for i in args.ids]\n"
        "    channel_ids = [] if args.mute else [int(i) for i in args.channels]",
    ),
    (
        "a bad --since is hidden behind credential resolution again",
        "hexact/cli_watch_rest.py",
        "    cutoff = parse_since(args.since)\n    key = resolve_key(HEXOWATCH)",
        "    key = resolve_key(HEXOWATCH)\n    cutoff = parse_since(args.since)",
    ),
    (
        "the date flags stop refusing a duration and let the gateway guess",
        "hexact/cli_common.py",
        "    if _DURATION.match(value.strip().lower()):",
        "    if False:",
    ),
    (
        "the duration help stops saying m means months",
        "hexact/cli_common.py",
        '    "m (MONTHS, 30 days each) -- e.g. 24h, 7d, 2w, 3m. Minutes are not "',
        '    "m -- e.g. 24h, 7d, 2w, 1m. Minutes are not "',
    ),
    (
        "an unreachable gateway and a refused token collapse to one exit code",
        "hexact/cli_auth.py",
        '    "missing": EXIT_USAGE,          # nothing to check',
        '    "missing": EXIT_FAILURE,        # nothing to check',
    ),
    (
        "a null gateway field asserts bad auth again for accounts that lack access",
        "hexact/graphql.py",
        '            "rejected, or this account has no access to "',
        '            "rejected. Run: hexact auth login --email <you> "',
    ),
    (
        "the Hexometer key pointer goes back to naming the account settings page",
        "hexact/config.py",
        '    HEXOMETER: ("Hexometer\'s key is issued per PROPERTY, not per account -- open "',
        '    HEXOMETER: ("The key is in the API/Webhook section of Hexometer\'s settings. "',
    ),
    (
        "a container of nulls is rendered as an empty account again",
        "hexact/graphql.py",
        '    if payload and all(payload.get(key) is None for key in keys):',
        '    if False:',
    ),
    (
        "the monitor listing folds an unreadable page back into an empty one",
        "hexact/cli_hexowatch.py",
        '        shown = data.get("watchProperties")\n        if shown is None:',
        '        shown = data.get("watchProperties") or []\n        if False:',
    ),
    (
        "unreadable webhooks are counted as zero webhooks again",
        "hexact/cli_hexowatch.py",
        '        hooks = data.get("webhooks")\n        if hooks is None:',
        '        hooks = data.get("webhooks") or []\n        if False:',
    ),
    (
        "the top-level handler bolts a second, contradicting remedy back on",
        "hexact/cli.py",
        '        print(f"Not authenticated: {exc}", file=sys.stderr)',
        '        print(f"Not authenticated: {exc}\\nRun: hexact auth login --email <you>",'
        '\n              file=sys.stderr)',
    ),
    (
        "a server-rejected credential is left with no remedy at all",
        "hexact/graphql.py",
        '                + "\\n  The gateway rejected the session credential.\\n"\n'
        '                "  Run: hexact auth login --email <you>"',
        '                + ""',
    ),
]


def run(label: str, relative: str, find: str, replace: str) -> bool:
    source = (REPO / relative).read_text(encoding="utf-8")
    if find not in source:
        print(f"  [ERROR   ] {label}\n              pattern not found in {relative} "
              f"-- this mutation proves nothing; fix the pattern.")
        return False

    workdir = tempfile.mkdtemp(prefix="hexact-mut-")
    try:
        # A fresh copy per mutation. Layering them, or copying into a directory
        # that already exists, nests the tree and edits a file nothing imports.
        target = os.path.join(workdir, "repo")
        shutil.copytree(REPO, target,
                        ignore=shutil.ignore_patterns("__pycache__", ".git", "*.pyc"))
        pathlib.Path(target, relative).write_text(source.replace(find, replace, 1),
                                                  encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=target, capture_output=True, text=True, timeout=300,
            # A mutated build may reach a blocking read the real one cannot.
            # Measured: deleting the terminal check from `prompt_password` lets
            # `getpass` open /dev/tty, and with a terminal inherited from the
            # harness it waits there forever -- the 300s timeout then aborts
            # the whole run, so a mutation that the suite catches perfectly
            # well reports as a crash instead. Detach stdin and the same
            # mutation is caught in under two seconds.
            stdin=subprocess.DEVNULL,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    caught = completed.returncode != 0
    print(f"  [{'CAUGHT  ' if caught else 'SURVIVED'}] {label}")
    if not caught:
        print("              No test failed. That guarantee is unverified.")
    return caught


def main() -> int:
    baseline = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=REPO, capture_output=True, text=True, timeout=300,
        stdin=subprocess.DEVNULL,  # same reason as in `run` above
    )
    if baseline.returncode != 0:
        print("Baseline suite is already failing; fix that before mutating.")
        print(baseline.stderr[-2000:])
        return 1
    # Read the count, not the exit code: a suite that collected nothing also
    # exits 0, and would make every mutation below "survive" for the wrong reason.
    collected = [line for line in baseline.stderr.splitlines() if line.startswith("Ran ")]
    print(f"Baseline: {collected[0] if collected else 'UNKNOWN COUNT'}\n")

    print(f"Applying {len(MUTATIONS)} mutations, each to a fresh copy:")
    results = [run(*mutation) for mutation in MUTATIONS]

    survived = results.count(False)
    print(f"\n{results.count(True)}/{len(results)} caught.")
    if survived:
        print(f"{survived} mutation(s) survived -- those guarantees are not tested.")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
