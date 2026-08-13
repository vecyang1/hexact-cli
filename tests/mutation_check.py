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
        "hexact/cli.py",
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
        'token = _token_from_response(data, "authRefreshToken", field_name="refresh_token")',
        'token = _token_from_response(data, "authRefreshToken", field_name="token")',
    ),
    (
        "a deleted monitor reading back as all-nulls counts as still present",
        "hexact/cli.py",
        '        if not monitor or monitor.get("id") in (None, "", 0):',
        '        if False:',
    ),
    (
        "an API error during delete read-back counts as proof of deletion",
        "hexact/cli.py",
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
        "hexact/cli.py",
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
        "hexact/cli.py",
        '    auth.verify_renewable(refresh)',
        '    pass  # mutation: skip the exchange',
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
