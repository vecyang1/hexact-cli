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

USER_AGENT = "hexact-cli/0.4.0 (+https://github.com/vecyang1/hexact-cli)"
HOSTS = {
    "hexowatch": "https://api.hexowatch.com/v2/ql",
    "hexomatic": "https://api.hexomatic.com/v2/ql",
    "hexospark": "https://api.hexospark.com/v2/ql",
    "hexometer": "https://api.hexometer.com/v2/ql",
}
BOGUS_ARG = "zzzNotAnArg: 1"
MAX_FRONTIER = 90
SUGGESTION = re.compile(r'Did you mean (.+?)\?(?:\s|$)')
REQUIRED_ARG = re.compile(
    r'Field "(?P<field>[^"]+)" argument "(?P<arg>[^"]+)" of type "(?P<type>[^"]+)" is required'
)
UNKNOWN_FIELD = re.compile(r'Cannot query field "(?P<field>[^"]+)" on type "(?P<parent>[^"]+)"')
# One guarded probe carries three separate facts. They must be parsed by message
# shape, not by scanning for "Did you mean" globally: the return-type message
# carries its own suggestion (`update { ... }`) which is not a name.
RETURN_TYPE = re.compile(
    r'Field "(?P<field>[^"]+)" of type "(?P<type>[^"]+)" must have a selection'
)
UNKNOWN_ARG = re.compile(
    r'Unknown argument "(?P<given>[^"]+)" on field "(?P<field>[^"]+)" of type '
    r'"(?P<parent>[^"]+)"\.(?:\s*Did you mean (?P<suggest>.+?)\?)?'
)
ARG_TYPE = re.compile(r'Expected type (?P<type>.+?), found')

# Argument names cluster around a small vocabulary. Same edit-distance limit
# applies, so these are sized like real argument names rather than generic.
ARG_SEEDS = (
    "idZz", "idsZz", "limitZz", "offsetZz", "pageZz", "searchZz", "filterZz",
    "sortZz", "orderZz", "nameZz", "urlZz", "emailZz", "enabledZz", "activeZz",
    "statusZz", "typeZz", "settingsZz", "inputZz", "dataZz", "tokenZz",
    "user_idZz", "workspace_idZz", "property_idZz", "campaign_idZz",
    "contact_idZz", "workflow_idZz", "tag_idZz", "automation_idZz",
    "watch_property_idZz", "dateZz", "fromZz", "toZz", "countZz", "valueZz",
    "keyZz", "queryZz", "textZz", "titleZz", "descriptionZz", "webhookUrlZz",
)

# Every argument name seen anywhere, fed back as a seed everywhere. Seeded with
# names recovered by hand so the first run already benefits.
ARG_VOCABULARY: set[str] = {
    "emailEnabled", "emails", "settings", "webhookUrl", "subscriptionId",
    "watch_property_id", "watch_properties_ids", "watch_integration_id",
    "watch_integration_ids", "monitoring_interval", "change_notification_level",
    "pause_after_first_change_event", "tool_settings", "address", "address_list",
    "tool", "active", "tags", "user_agent", "workflow_id", "workflows_ids",
    "property_id", "workspace_id", "campaign_id", "contact_id", "limit",
    "offset", "search", "sort", "order", "ids", "id", "name", "type", "status",
}
_vocabulary_lock = threading.Lock()


def remember_arguments(names: set[str]) -> None:
    with _vocabulary_lock:
        ARG_VOCABULARY.update(names)


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


def _arg_suggestions(gateway: Gateway, payload: dict, field: str) -> set[str]:
    """Argument names, parsed only from the Unknown-argument message.

    Deliberately not the global "Did you mean" scan used for field names: the
    return-type error carries `Did you mean "update { ... }"?`, which is a
    selection hint, not an argument.
    """
    names: set[str] = set()
    for message in gateway.messages(payload):
        match = UNKNOWN_ARG.search(message)
        if not match or match.group("field") != field or not match.group("suggest"):
            continue
        for candidate in re.split(r",|\bor\b", match.group("suggest")):
            cleaned = candidate.strip().strip('".,').strip()
            if cleaned and " " not in cleaned:
                names.add(cleaned)
    return names


def describe_field(
    gateway: Gateway, namespace: str, field: str, kind: str, pool: ThreadPoolExecutor
) -> dict:
    """Full signature for one field, WITHOUT entering its resolver.

    Recovers three things the first version missed. **Return type**, from
    `Field "x" of type "T" must have a selection of subfields`. **Optional
    argument names** -- the first version reported only *required* ones, so a
    field like `UserWatchSettingsOps.update` rendered as taking no arguments
    when it in fact takes `emailEnabled` and `emails`, i.e. the reference
    understated the API rather than merely being terse. And **argument types**,
    from `Expected type T, found ...` when a value of the wrong type is sent.

    Every probe here carries the bogus argument -- the base signature probe, the
    argument-name discovery probes, and the argument-type probes alike. That is
    load-bearing and was learned the hard way. An earlier version of this
    function guarded only the base probe; the type probe
    `field(realOptionalArg: "zZq")` is a *valid* document for any field whose
    remaining arguments are all optional, so it entered 34 resolvers on a live
    gateway (`forgotPassword`, `updateWebhook`, `updateWatchProperty`, ...). Every
    request was anonymous and every value was garbage (`"zZq"` / `123`), so no
    account was touched -- but the inert *guarantee* was broken, which is the
    thing this file exists to keep. The `resolver_was_entered` self-check caught
    it and `main` reports it loudly; `render_gateway_doc.py` now refuses to
    render a walk whose `resolvers_entered` is non-empty. A guard proven on one
    probe shape does not extend to probe shapes added later -- guard every shape.
    """
    # No selection set on purpose. `{ __typename }` satisfies the leaf rule, so
    # the server never emits `must have a selection of subfields` and the return
    # type stays hidden -- the first version of this function asked with a
    # selection and recovered `returns: None` for every object field. Omitting
    # it is still inert because the bogus argument fails validation first.
    base = gateway.post(f"{kind} {{ {namespace} {{ {field}({BOGUS_ARG}) }} }}")
    messages = gateway.messages(base)
    required = [
        {"name": m.group("arg"), "type": m.group("type")}
        for message in messages
        for m in [REQUIRED_ARG.search(message)] if m and m.group("field") == field
    ]
    returns = next(
        (m.group("type") for message in messages
         for m in [RETURN_TYPE.search(message)] if m and m.group("field") == field),
        None,
    )
    entered = base.get("data") is not None

    # Closure over argument names: seeds, then near-misses of what they found.
    #
    # `ARG_VOCABULARY` is the fix for the second miss found during calibration.
    # Argument names repeat heavily across a schema, and the suggester's reach
    # is bounded by edit distance from the *probe*, so a generic seed like
    # `emailZz` never reaches `emailEnabled` (distance 5, threshold 4). Feeding
    # every name discovered anywhere back in as a seed everywhere means the
    # walk gets strictly better the more it sees, instead of re-rolling the
    # same too-short seeds per field.
    known_args: set[str] = {a["name"] for a in required}
    with _vocabulary_lock:
        vocabulary = sorted(ARG_VOCABULARY)
    # Capped: the vocabulary grows as the walk proceeds, and an uncapped
    # frontier would make per-field cost climb without bound over 342 fields.
    frontier = list(dict.fromkeys(
        list(ARG_SEEDS) + [v for name in vocabulary for v in variants(name)]
    ))[:MAX_FRONTIER]
    for _ in range(3):
        if not frontier:
            break
        documents = [
            f"{kind} {{ {namespace} {{ {field}({probe}: 1, {BOGUS_ARG}) {{ __typename }} }} }}"
            for probe in frontier
        ]
        found: set[str] = set()
        for payload in pool.map(gateway.post, documents):
            found |= _arg_suggestions(gateway, payload, field)
            entered = entered or payload.get("data") is not None
        fresh = found - known_args
        if not fresh:
            break
        known_args |= fresh
        remember_arguments(fresh)
        frontier = [v for name in fresh for v in variants(name)]

    # Type of each argument: send an Int and read what it expected instead.
    optional = sorted(known_args - {a["name"] for a in required})
    types: dict[str, str] = {}
    for literal in ('"zZq"', "123"):
        pending = [name for name in optional if name not in types]
        if not pending:
            break
        documents = [
            f"{kind} {{ {namespace} {{ {field}({name}: {literal}, {BOGUS_ARG}) {{ __typename }} }} }}"
            for name in pending
        ]
        for name, payload in zip(pending, pool.map(gateway.post, documents)):
            entered = entered or payload.get("data") is not None
            for message in gateway.messages(payload):
                match = ARG_TYPE.search(message)
                if match:
                    types[name] = match.group("type").strip()
                    break

    return {
        "returns": returns,
        "required_arguments": required,
        "optional_arguments": [
            {"name": name, "type": types.get(name, "UNKNOWN")} for name in optional
        ],
        "resolver_was_entered": entered,
    }


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
                    entry["fields"] = {
                        f: describe_field(gateway, root, f, kind, pool) for f in fields
                    }
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
