#!/usr/bin/env python3
"""Check every GraphQL document this client can send against the live schema.

The problem this solves. The gateway is undocumented and unversioned, and its
schema was recovered by inference, so a selection set can name a field that does
not exist. Unit tests cannot catch that -- they assert against fakes built from
the same inference. The only authority is the server, and asking the server
normally means *running* the query, which for a mutation is not a test, it is
the thing happening.

The trick is a **validation canary**: one field that certainly does not exist,
added at the root of the operation.

    query { __zzzCanary Watch { getWatchProperty(watch_property_id: $id) { id } } }

graphql-js validates the whole document before executing any of it, and a single
unknown field makes validation fail. So `data` comes back null, no resolver on
any level is entered -- and the error list still contains a report for *every*
other mistake in the document. If the canary error is the only one, every field
and argument named in the rest of the document is real.

That gives a credential-free, side-effect-free proof that a mutation is
well-formed against the live schema, which is otherwise impossible to obtain
without firing it at a real account.

What this does NOT prove: that the operation is permitted, that the arguments
are semantically sensible, or that the response means what the caller assumes.
It proves the document would be accepted. That is a floor, not a ceiling, and
it is a floor nothing else was checking.

Run:  python3 tools/validate_documents.py
Exit: 0 when every document validates, 1 otherwise.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hexact import auth, graphql  # noqa: E402

CANARY = "__zzzCanaryFieldThatCannotExist"
CANARY_ERROR = re.compile(rf'Cannot query field "{CANARY}"')
# The operation header ends at the first `{` that opens the selection set.
OPERATION_OPEN = re.compile(r"^(?P<head>\s*(?:query|mutation)\b[^{]*)\{", re.MULTILINE)


def with_canary(document: str) -> str:
    """Insert the canary as the first root-level selection."""
    match = OPERATION_OPEN.search(document)
    if not match:
        raise ValueError(f"could not find an operation header in: {document[:80]}")
    end = match.end()
    return f"{document[:end]} {CANARY} {document[end:]}"


def post(document: str, variables: dict | None = None) -> dict:
    request = urllib.request.Request(
        graphql.GRAPHQL_URL,
        data=json.dumps({"query": document, "variables": variables or {}}).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": f"hexact-cli-validate/{graphql.__name__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode())
        except Exception:  # noqa: BLE001
            return {"_http": exc.code}


def collect_documents() -> dict[str, str]:
    """Every document the client can emit, gathered from the modules themselves.

    Read off the modules rather than listed by hand: a document added to the
    package but forgotten here would leave the check passing over a smaller set
    than it claims to cover, which is the failure mode this whole file exists to
    stop elsewhere.
    """
    documents: dict[str, str] = {}
    # Every module in the package, discovered rather than listed. A hardcoded
    # tuple covers the modules that existed when it was written; the next
    # product module added would simply not be checked, and the summary line
    # would still read "N/N validate" -- shrinking the denominator without
    # shrinking the claim.
    modules = [graphql, auth]
    package = Path(graphql.__file__).parent
    for path in sorted(package.glob("*.py")):
        if path.stem.startswith("_"):
            continue
        modules.append(importlib.import_module(f"hexact.{path.stem}"))

    for module in dict.fromkeys(modules):
        for name in dir(module):
            if not name.isupper():
                continue
            value = getattr(module, name)
            if isinstance(value, str) and re.search(r"\b(query|mutation)\b", value) \
                    and "{" in value:
                documents[f"{module.__name__.split('.')[-1]}.{name}"] = value
    return documents


def check(label: str, document: str) -> bool:
    payload = post(with_canary(document))

    if payload.get("data") is not None:
        print(f"  [UNSAFE  ] {label}: the canary did not stop execution -- "
              f"a resolver ran. Do not use this technique until that is "
              f"understood.")
        return False

    messages = [e.get("message", "") for e in (payload.get("errors") or [])]
    if not any(CANARY_ERROR.search(m) for m in messages):
        print(f"  [ERROR   ] {label}: the canary produced no error, so this "
              f"check proves nothing. Messages: {messages[:3]}")
        return False

    others = [m for m in messages if not CANARY_ERROR.search(m)]
    # Variables declared but unused by the trimmed document are not a schema
    # defect in what we are testing; nothing else is excused.
    others = [m for m in others if "is never used" not in m]
    if others:
        print(f"  [INVALID ] {label}")
        for message in others[:5]:
            print(f"              {message}")
        return False

    print(f"  [VALID   ] {label}")
    return True


def main() -> int:
    documents = collect_documents()
    if not documents:
        print("No documents found. This check would pass vacuously; refusing.",
              file=sys.stderr)
        return 1

    print(f"Validating {len(documents)} document(s) against "
          f"{graphql.GRAPHQL_URL}, anonymously:\n")
    results = [check(label, doc) for label, doc in sorted(documents.items())]

    bad = results.count(False)
    print(f"\n{results.count(True)}/{len(results)} validate against the live schema.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
