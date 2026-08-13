#!/usr/bin/env python3
"""Map the Hexact GraphQL gateway without credentials and without side effects.

The vendor publishes no schema for `https://api.hexowatch.com/v2/ql` and Apollo
introspection is disabled (`GraphQL introspection is not allowed`). What is left
is the validator, which is talkative: it suggests real sibling names for a
misspelled field, and it names required arguments. This walks that oracle to a
fixpoint and emits JSON, so `docs/GATEWAY.md` can be *derived* rather than
hand-maintained.

TWO SAFETY RULES, both load-bearing:

1. **Never send a credential.** Every request here is anonymous. That is what
   makes the whole exercise inert: a resolver that does run has nothing to act
   on and answers "should be authenticated" or "Permission denied".

2. **Every probe carries a bogus argument.** This is not cosmetic. A mutation
   field with no *required* arguments will otherwise reach its resolver and
   run: measured, `mutation { WatchOps { exportAll { __typename } } }` returned
   `ExportAllType` -- the export actually executed. Adding `(zzzNotAnArg: 1)`
   makes the document fail validation ("Unknown argument"), so `data` is null
   and no resolver is entered, while the *same* error list still reports every
   required argument. Verified inert on `contactFormSubmit`, the one top-level
   mutation that looks like it emails somebody.

Usage:
    python3 tools/schema_map.py                 # full walk -> schema_map.json
    python3 tools/schema_map.py --host hexomatic # compare another host
    python3 tools/schema_map.py --quick          # namespaces only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

USER_AGENT = "hexact-cli/0.3.0 (+https://github.com/vecyang1/hexact-cli)"
HOSTS = {
    "hexowatch": "https://api.hexowatch.com/v2/ql",
    "hexomatic": "https://api.hexomatic.com/v2/ql",
    "hexospark": "https://api.hexospark.com/v2/ql",
    "hexometer": "https://api.hexometer.com/v2/ql",
}
BOGUS_ARG = "zzzNotAnArg: 1"
SUGGESTION = re.compile(r'Did you mean (.+?)\?(?:\s|$)')
REQUIRED_ARG = re.compile(
    r'Field "(?P<field>[^"]+)" argument "(?P<arg>[^"]+)" of type "(?P<type>[^"]+)" is required'
)
UNKNOWN_FIELD = re.compile(r'Cannot query field "(?P<field>[^"]+)" on type "(?P<parent>[^"]+)"')

_print_lock = threading.Lock()


def log(message: str) -> None:
    with _print_lock:
        print(message, file=sys.stderr, flush=True)


class Gateway:
    def __init__(self, url: str) -> None:
        self.url = url
        self.requests = 0
        self._lock = threading.Lock()

    def post(self, document: str) -> dict:
        request = urllib.request.Request(
            self.url,
            data=json.dumps({"query": document}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        with self._lock:
            self.requests += 1
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return json.loads(raw)
            except Exception:  # noqa: BLE001
                return {"_http": exc.code, "_raw": raw[:200]}
        except Exception as exc:  # noqa: BLE001
            return {"_error": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def messages(payload: dict) -> list[str]:
        return [e.get("message", "") for e in (payload.get("errors") or [])]

    @classmethod
    def suggestions(cls, payload: dict) -> set[str]:
        names: set[str] = set()
        for message in cls.messages(payload):
            for match in SUGGESTION.finditer(message):
                for candidate in re.split(r",|\bor\b", match.group(1)):
                    cleaned = candidate.strip().strip('".,').strip()
                    if cleaned and " " not in cleaned:
                        names.add(cleaned)
        return names


# --- Name-space walking -----------------------------------------------------
# Apollo returns at most ~5 suggestions per misspelling, ranked by lexical
# distance, so a single seed can never enumerate a wide namespace. Instead this
# runs to a fixpoint: every name discovered becomes the stem for new near-miss
# probes, which surface *its* lexical neighbours. Generic prefixes only find the
# names near them; the closure finds the rest.

# graphql-js `suggestionList` only offers names within
# `floor(len(input) * 0.4) + 1` edits, so a SHORT generic probe can never reach
# a long field name. A first attempt seeded `createZz`/`updateZz` and reported
# `WatchOps: 1 field` against a hand-verified ground truth of 9 -- the numbers
# were a floor, not a finding.
#
# Two fixes. Seeds are built at roughly the length of the names being hunted, by
# crossing verbs with the namespace's own stem (`WatchIntegrationOps` ->
# `deleteWatchIntegrationZz`, one edit from the real `deleteWatchIntegration`).
# And every discovered name seeds its own near-misses, so the reach compounds.

VERBS = (
    "create", "update", "delete", "get", "set", "add", "remove", "list", "send",
    "run", "execute", "start", "stop", "pause", "resume", "export", "import",
    "subscribe", "check", "search", "count", "move", "copy", "bulk", "upsert",
    "assign", "verify", "cancel", "archive", "restore", "enable", "disable",
    "schedule", "trigger", "duplicate", "admin", "user",
)


def namespace_stem(namespace: str) -> str:
    for suffix in ("Opts", "Ops"):
        if namespace.endswith(suffix):
            return namespace[: -len(suffix)]
    return namespace


def seeds_for(namespace: str) -> list[str]:
    """Probe names sized like the real thing, none of which can exist."""
    stem = namespace_stem(namespace)
    seeds = [f"{verb}Zz" for verb in VERBS]
    seeds += [f"{verb}{stem}Zz" for verb in VERBS]
    seeds += [f"{verb}{stem}sZz" for verb in ("get", "list", "update", "delete")]
    seeds.append(f"{stem[0].lower()}{stem[1:]}Zz")
    return seeds


def variants(name: str) -> list[str]:
    """Near-misses of a real name, none of which can be a real field."""
    return [name + "Zz", (name[:-1] + "Zz") if len(name) > 3 else name + "Qz"]


def walk_fields(
    gateway: Gateway,
    namespace: str,
    kind: str,
    pool: ThreadPoolExecutor,
    prior: set[str] | None = None,
) -> set[str]:
    """Enumerate one namespace's fields by closure over the suggester.

    Discovery probes carry the bogus argument too, not just the signature
    probes. Necessary since seeds are now derived from the namespace name and
    so are *likely* to collide with a real field: an unguarded probe that
    happens to name a real no-required-argument mutation would run it.

    **This returns a lower bound, not the field list.** Calibrated against nine
    hand-verified `WatchOps` fields: the walk found 13 (five genuinely new) but
    still missed `adminDelete`, which no seed came within the suggester's edit
    threshold of. A lexically isolated name is invisible to this method and
    there is no way to know from inside how many are missing. Passing `prior`
    seeds the closure with names already known, so repeated runs accumulate
    instead of re-rolling the same dice.
    """
    known: set[str] = set(prior or ())
    frontier = seeds_for(namespace) + [v for name in known for v in variants(name)]
    seen_probes: set[str] = set()

    for _ in range(8):  # bounded; converges in 3-4 in practice
        frontier = [p for p in frontier if p not in seen_probes]
        if not frontier:
            break
        seen_probes.update(frontier)
        documents = [
            f"{kind} {{ {namespace} {{ {probe}({BOGUS_ARG}) }} }}" for probe in frontier
        ]
        found: set[str] = set()
        for payload in pool.map(gateway.post, documents):
            found |= gateway.suggestions(payload)
        fresh = {name for name in found - known if name != namespace}
        if not fresh:
            break
        known |= fresh
        frontier = [v for name in fresh for v in variants(name)]
    return known


def walk_roots(gateway: Gateway, kind: str, pool: ThreadPoolExecutor) -> set[str]:
    known: set[str] = set()
    frontier = [
        "WatchZz", "UserZz", "HexomaticZz", "HexosparkZz", "HexometerZz",
        "AlertZz", "ScraperZz", "TaskZz", "PropertyZz", "BillingZz", "TeamZz",
        "KeywordZz", "ShortlinkZz", "TagZz", "AdminZz", "NotificationZz",
        "IntegrationZz", "CampaignZz", "ContactZz", "WorkflowZz", "LogZz",
    ]
    seen: set[str] = set()
    for _ in range(8):
        frontier = [p for p in frontier if p not in seen]
        if not frontier:
            break
        seen.update(frontier)
        documents = [f"{kind} {{ {probe} {{ __typename }} }}" for probe in frontier]
        found: set[str] = set()
        for payload in pool.map(gateway.post, documents):
            found |= gateway.suggestions(payload)
        fresh = found - known
        if not fresh:
            break
        known |= fresh
        frontier = [v for name in fresh for v in variants(name)]
    return known


def signature(gateway: Gateway, namespace: str, field: str, kind: str) -> dict:
    """Required arguments for one field, WITHOUT entering its resolver.

    The bogus argument is the whole point -- see the module docstring.
    """
    payload = gateway.post(
        f"{kind} {{ {namespace} {{ {field}({BOGUS_ARG}) {{ __typename }} }} }}"
    )
    arguments = [
        {"name": m.group("arg"), "type": m.group("type")}
        for message in gateway.messages(payload)
        for m in [REQUIRED_ARG.search(message)] if m and m.group("field") == field
    ]
    executed = payload.get("data") is not None
    return {"required_arguments": arguments, "resolver_was_entered": executed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="hexowatch", choices=sorted(HOSTS))
    parser.add_argument("--quick", action="store_true", help="namespaces only")
    parser.add_argument("--out", default=None)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument(
        "--merge", default=None,
        help="prior schema_map JSON; its names seed this walk so runs accumulate",
    )
    args = parser.parse_args()

    prior_fields: dict[str, set[str]] = {}
    if args.merge and Path(args.merge).is_file():
        previous = json.loads(Path(args.merge).read_text(encoding="utf-8"))
        for key, entry in previous.get("namespaces", {}).items():
            prior_fields[key] = set(entry.get("fields", {}))
        log(f"seeding from {args.merge}: "
            f"{sum(len(v) for v in prior_fields.values())} known names")

    gateway = Gateway(HOSTS[args.host])
    result: dict = {"host": args.host, "url": gateway.url, "namespaces": {}}

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for kind in ("query", "mutation"):
            roots = sorted(walk_roots(gateway, kind, pool))
            log(f"[{args.host}] {kind}: {len(roots)} namespaces")
            for root in roots:
                entry: dict = {"kind": kind, "fields": {}}
                if not args.quick:
                    fields = sorted(walk_fields(
                        gateway, root, kind, pool, prior_fields.get(f"{kind}:{root}")))
                    log(f"    {root}: {len(fields)} fields")
                    signatures = pool.map(
                        lambda f, r=root, k=kind: signature(gateway, r, f, k), fields
                    )
                    entry["fields"] = dict(zip(fields, signatures))
                result["namespaces"][f"{kind}:{root}"] = entry

    result["request_count"] = gateway.requests
    entered = [
        f"{key}.{field}"
        for key, entry in result["namespaces"].items()
        for field, spec in entry["fields"].items()
        if spec.get("resolver_was_entered")
    ]
    result["resolvers_entered"] = entered
    if entered:
        # Should be empty. If it is not, the bogus-argument guard failed and the
        # walk was not inert -- say so loudly rather than burying it in JSON.
        log(f"WARNING: {len(entered)} probe(s) reached a resolver: {entered[:5]}")

    destination = Path(args.out or f"schema_map_{args.host}.json")
    destination.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    total = sum(len(e["fields"]) for e in result["namespaces"].values())
    log(f"[{args.host}] {len(result['namespaces'])} namespaces, {total} fields, "
        f"{gateway.requests} requests -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
