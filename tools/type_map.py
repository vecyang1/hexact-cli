#!/usr/bin/env python3
"""Recover the *shape* of the Hexact gateway's return types, without credentials.

`tools/schema_map.py` answers "what fields exist and what do they return". It
stops at the type *name*. That is one level short of usable: GraphQL requires a
selection set, so knowing `Watch.getWatchProperty` returns `WatchPropertyType`
still leaves you unable to write the query. Every field inside that type has to
be guessed, and a wrong guess is a validation error rather than a partial
answer.

Same oracle, one level deeper. `Cannot query field "idZz" on type
"WatchPropertyType". Did you mean "id"?` is the suggester talking about an
*output* type, and it obeys the same rules as the field-name walk: at most ~5
suggestions, only within `floor(len(probe) * 0.4) + 1` edits, so results are a
**lower bound** and a type that answers nothing is undiscovered rather than
empty.

THREE SAFETY RULES. The first two are inherited and non-negotiable; the third is
new here and exists because this file's probes are shaped differently from
`schema_map.py`'s, and "a guard proven on one probe shape does not extend to
shapes added later" is a lesson this project already paid for once (a type probe
that dropped the guard entered 34 live resolvers).

1. **Never send a credential.** Every request is anonymous.

2. **The path field always carries a bogus argument.** One invalid argument
   anywhere makes the whole document fail *validation*, so `data` is null and no
   resolver on any level is entered -- while the validator still reports the
   field-name and return-type errors that carry the payload. This works even for
   a path field that takes no arguments at all: `Unknown argument` is an error
   regardless.

3. **Inertness is asserted per response, not tallied at the end.** Any response
   carrying non-null `data` aborts the walk immediately. A counter you read
   afterwards tells you what you already broke; this stops before the second one.

Two calibrations behind the request budget, both measured against the live
gateway rather than assumed:

- Batching is safe. Thirty bogus subfields in one document produced thirty
  separate `Cannot query field` errors with their suggestions intact -- no
  truncation. One request now does what thirty did.
- Reach is still edit-distance bound. In that same request, `zzzNotAField`
  produced no suggestion at all while `idZz` produced `id`. Seeds must be sized
  and spelled like the names being hunted; generic short probes find nothing.

Usage:
    python3 tools/type_map.py --out /tmp/hexact-types/v1.json
    python3 tools/type_map.py --only WatchPropertyType --max-depth 2
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from schema_map import (  # noqa: E402  (path juggling above is deliberate)
    BOGUS_ARG,
    HOSTS,
    Gateway,
    log,
    variants,
)

# `Cannot query field "x" on type "T"` -- the field-name oracle, one level down.
UNKNOWN_SUBFIELD = re.compile(
    r'Cannot query field "(?P<probe>[^"]+)" on type "(?P<parent>[^"]+)"\.'
    r'(?:\s*Did you mean (?P<suggest>.+?)\?)?'
)
# `Field "x" of type "T" must have a selection of subfields` -- how a field is
# known to be an object rather than a leaf, and how its type is recovered.
NEEDS_SELECTION = re.compile(
    r'Field "(?P<field>[^"]+)" of type "(?P<type>[^"]+)" must have a selection'
)

# Sized like real result-object field names. A three-letter probe reaches
# nothing: the suggester's threshold is floor(len * 0.4) + 1 edits.
FIELD_SEEDS = (
    "idZz", "nameZz", "urlZz", "toolZz", "errorZz", "messageZz", "dataZz",
    "countZz", "totalZz", "activeZz", "statusZz", "typeZz", "valueZz",
    "emailZz", "addressZz", "settingsZz", "createdAtZz", "updatedAtZz",
    "created_atZz", "updated_atZz", "pageZz", "limitZz", "offsetZz", "tagsZz",
    "userZz", "intervalZz", "levelZz", "webhookZz", "percentageZz",
    "resultZz", "resultsZz", "itemsZz", "listZz", "pausedZz", "enabledZz",
    "titleZz", "descriptionZz", "colorZz", "tokenZz", "workspaceIdZz",
    "campaignIdZz", "contactIdZz", "workflowIdZz", "propertyIdZz",
    "monitoring_intervalZz", "watch_property_idZz", "scan_idZz", "oldDataZz",
    "newDataZz", "screenshotZz", "creditsZz", "usageZz", "chartZz", "dateZz",
    "fromZz", "toZz", "firstNameZz", "lastNameZz", "companyZz", "phoneZz",
    "subjectZz", "bodyZz", "sentZz", "openedZz", "clickedZz", "repliedZz",
    "bouncedZz", "unsubscribedZz", "integrationZz", "integrationsZz",
    "notificationZz", "logsZz", "recordsZz", "rowsZz", "columnsZz", "fileZz",
    "csvZz", "jsonZz", "linkZz", "hashZz", "sizeZz", "durationZz", "stateZz",
    "subscriptionIdZz", "subscription_idZz", "error_codeZz", "totalCountZz",
    "changeZz", "changesZz", "screenshot_urlZz", "json_urlZz", "csv_urlZz",
    "notificationsZz", "workspaceZz", "workspacesZz", "automationZz",
    "automationsZz", "workflowZz", "workflowsZz", "campaignZz", "campaignsZz",
    "contactZz", "contactsZz", "propertyZz", "propertiesZz", "monitorZz",
    "recipeZz", "recipesZz", "promptZz", "stepsZz", "logZz", "scanZz",
    "scansZz", "issueZz", "issuesZz", "packageZz", "planZz", "creditZz",
    "premium_creditZz", "verifiedZz", "is_activeZz", "deletedZz", "ownerZz",
    # Seed breadth is the only lever on coverage here, and probes are batched
    # 25 to a request, so a wider list costs almost nothing. Measured: the type
    # `webhook` reported zero fields until `eventZz` was added -- it has
    # `events` and none of id/url/type/subscriptionId, so every "obvious" seed
    # missed it. Absence in this map means unreached, never empty.
    "eventZz", "eventsZz", "keyZz", "slugZz", "codeZz", "reasonZz", "detailZz",
    "detailsZz", "metaZz", "metadataZz", "configZz", "optionsZz", "paramsZz",
    "fieldsZz", "headersZz", "payloadZz", "contentZz", "htmlZz", "textZz",
    "imageZz", "imagesZz", "thumbnailZz", "previewZz", "diffZz", "beforeZz",
    "afterZz", "oldValueZz", "newValueZz", "startZz", "endZz", "startDateZz",
    "endDateZz", "timestampZz", "lastRunZz", "nextRunZz", "frequencyZz",
    "scheduleZz", "successZz", "failedZz", "pendingZz", "runningZz",
    "completedZz", "progressZz", "sourceZz", "targetZz", "destinationZz",
    "providerZz", "channelZz", "channelsZz", "recipientZz", "recipientsZz",
    "senderZz", "replyZz", "stepZz", "orderZz", "positionZz", "indexZz",
    "parentZz", "childrenZz", "groupZz", "categoryZz", "categoriesZz",
    "labelZz", "displayZz", "visibleZz", "publicZz", "privateZz", "sharedZz",
    "planNameZz", "quotaZz", "remainingZz", "usedZz", "balanceZz", "priceZz",
    "currencyZz", "countryZz", "languageZz", "timezoneZz", "avatarZz",
)

# Wrappers vendors put around a payload type; stripping them yields the noun the
# type is actually about, which makes a seed the suggester can reach.
TYPE_AFFIXES = (
    "MutationResultType", "MutationResult", "MutaionResult", "ResultType",
    "ResponseType", "Response", "Result", "Payload", "Type",
)

_vocabulary_lock = threading.Lock()
SUBFIELD_VOCABULARY: set[str] = set()


class ResolverEntered(RuntimeError):
    """A probe produced non-null data, so the walk was not inert. Abort."""


def remember(names: set[str]) -> None:
    with _vocabulary_lock:
        SUBFIELD_VOCABULARY.update(names)


def vocabulary() -> list[str]:
    with _vocabulary_lock:
        return sorted(SUBFIELD_VOCABULARY)


def base_type(name: str) -> str:
    """`[Foo!]!` -> `Foo`. List and non-null wrappers are not the type."""
    return name.replace("[", "").replace("]", "").replace("!", "").strip()


def type_stem(name: str) -> str:
    stem = base_type(name)
    if stem.startswith("Get"):
        stem = stem[3:]
    for affix in TYPE_AFFIXES:
        if stem.endswith(affix) and len(stem) > len(affix):
            stem = stem[: -len(affix)]
            break
    return stem


def seeds_for_type(name: str) -> list[str]:
    stem = type_stem(name)
    seeds = list(FIELD_SEEDS)
    if stem:
        lower = stem[0].lower() + stem[1:]
        seeds += [f"{lower}Zz", f"{lower}sZz"]
        # Vendors mix camel and snake in the same schema; probe both spellings.
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", stem).lower()
        if snake != lower.lower():
            seeds.append(f"{snake}Zz")
    return list(dict.fromkeys(seeds))


# --- Document construction ---------------------------------------------------


def build_document(path: dict, probes: list[str]) -> str:
    """Nest `probes` at the end of `path`, with the guard on the path field.

    Only the outermost field needs the bogus argument: validation is
    all-or-nothing for a document, so one invalid argument keeps every resolver
    on every level unreached.
    """
    body = " ".join(probes)
    for step in reversed(path["chain"]):
        body = f"{step} {{ {body} }}"
    return (
        f'{path["kind"]} {{ {path["namespace"]} {{ '
        f'{path["field"]}({BOGUS_ARG}) {{ {body} }} }} }}'
    )


def post_checked(gateway: Gateway, document: str) -> dict:
    payload = gateway.post(document)
    if payload.get("data") is not None:
        raise ResolverEntered(
            "a probe returned non-null data, so it was NOT inert. "
            f"document: {document[:200]}"
        )
    return payload


# --- Walking one type --------------------------------------------------------


def parse_subfields(payload: dict, parent: str) -> set[str]:
    """Real field names of `parent`, from its Cannot-query-field suggestions.

    Filtered by parent type on purpose. A nested path produces errors about
    several types in one response, and attributing a suggestion to the wrong
    type would silently corrupt the map with plausible-looking names.
    """
    names: set[str] = set()
    for message in Gateway.messages(payload):
        match = UNKNOWN_SUBFIELD.search(message)
        if not match or match.group("parent") != parent or not match.group("suggest"):
            continue
        for candidate in re.split(r",|\bor\b", match.group("suggest")):
            cleaned = candidate.strip().strip('".,').strip()
            if cleaned and " " not in cleaned:
                names.add(cleaned)
    return names


def discover_fields(
    gateway: Gateway, type_name: str, path: dict, pool: ThreadPoolExecutor,
    batch: int, rounds: int = 4,
) -> set[str]:
    """Closure over the suggester until it stops offering new names."""
    known: set[str] = set()
    frontier = seeds_for_type(type_name)
    tried: set[str] = set()
    used_vocabulary = False

    while True:
        for _ in range(rounds):
            frontier = [p for p in frontier if p not in tried]
            if not frontier:
                break
            tried.update(frontier)
            chunks = [frontier[i:i + batch] for i in range(0, len(frontier), batch)]
            documents = [build_document(path, chunk) for chunk in chunks]
            found: set[str] = set()
            for payload in pool.map(lambda d: post_checked(gateway, d), documents):
                found |= parse_subfields(payload, base_type(type_name))
            fresh = found - known
            if not fresh:
                break
            known |= fresh
            remember(fresh)
            frontier = [v for name in fresh for v in variants(name)]

        # Last resort for a type that answered nothing, and only then: result
        # objects reuse field names across a schema heavily, so a name that no
        # seed can reach is often one edit from a sibling type's real field.
        # Gated on `known` because the vocabulary grows into the hundreds and
        # spending it on every one of ~241 types would cost more than the whole
        # rest of the walk. An earlier version put this check inside the loop,
        # where `if not fresh: break` exited first and it could never fire --
        # a fallback that cannot run is worse than no fallback, because the
        # coverage number it was meant to raise still looks deliberate.
        if known or used_vocabulary:
            break
        used_vocabulary = True
        frontier = [v for n in vocabulary() for v in variants(n) if v not in tried]
        if not frontier:
            break
    return known


def classify_fields(
    gateway: Gateway, type_name: str, path: dict, fields: set[str],
    pool: ThreadPoolExecutor, batch: int,
) -> dict[str, str | None]:
    """Split leaves from objects, and name each object's type.

    Selecting a real object field with no selection set is a validation error
    that names the type -- which is both the classification and the next hop.
    A field producing no such error is a leaf (scalar or enum).
    """
    ordered = sorted(fields)
    result: dict[str, str | None] = {name: None for name in ordered}
    chunks = [ordered[i:i + batch] for i in range(0, len(ordered), batch)]
    documents = [build_document(path, chunk) for chunk in chunks]
    for payload in pool.map(lambda d: post_checked(gateway, d), documents):
        for message in Gateway.messages(payload):
            match = NEEDS_SELECTION.search(message)
            if match and match.group("field") in result:
                result[match.group("field")] = match.group("type")
    return result


# --- Input: the committed reference, not a scratch file ----------------------

GATEWAY_ROW = re.compile(r"^\| `(?P<field>\w+)` \| (?P<returns>—|`[^`]+`) \|")
GATEWAY_HEADING = re.compile(r"^### `(?P<kind>query|mutation) (?P<ns>\w+)`")


def paths_from_gateway_doc(doc: Path) -> dict[str, dict]:
    """One reachable path per return type, parsed from `docs/GATEWAY.md`.

    Deliberately reads the *committed* reference rather than a JSON file in
    `/tmp`. The scratch output of a previous walk is not guaranteed to exist,
    and a tool that cannot run from a fresh clone is a tool that silently
    becomes unrunnable. Shorter paths win ties so probe documents stay small.
    """
    paths: dict[str, dict] = {}
    kind = namespace = None
    for line in doc.read_text(encoding="utf-8").splitlines():
        heading = GATEWAY_HEADING.match(line)
        if heading:
            kind, namespace = heading.group("kind"), heading.group("ns")
            continue
        row = GATEWAY_ROW.match(line)
        if not row or not namespace or row.group("returns") == "—":
            continue
        returns = row.group("returns").strip("`")
        name = base_type(returns)
        if name and name not in paths:
            paths[name] = {
                "kind": kind, "namespace": namespace,
                "field": row.group("field"), "chain": [], "raw_type": returns,
            }
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="hexowatch", choices=sorted(HOSTS))
    parser.add_argument("--gateway-doc", default="docs/GATEWAY.md")
    parser.add_argument("--out", default="type_map.json")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--batch", type=int, default=25,
                        help="bogus subfields per document (30 verified safe)")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--only", nargs="*", default=None,
                        help="walk just these types (plus what they reach)")
    args = parser.parse_args()

    doc = Path(args.gateway_doc)
    if not doc.is_file():
        print(f"missing {doc}; run tools/schema_map.py and render it first",
              file=sys.stderr)
        return 2
    roots = paths_from_gateway_doc(doc)
    if args.only:
        roots = {k: v for k, v in roots.items() if k in set(args.only)}
        if not roots:
            print(f"none of {args.only} appear as a return type in {doc}",
                  file=sys.stderr)
            return 2
    log(f"{len(roots)} distinct return types reachable from {doc}")

    gateway = Gateway(HOSTS[args.host])
    types: dict[str, dict] = {}
    queue = [(name, path, 0) for name, path in sorted(roots.items())]

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            while queue:
                name, path, depth = queue.pop(0)
                if name in types or depth > args.max_depth:
                    continue
                fields = discover_fields(gateway, name, path, pool, args.batch)
                classified = (
                    classify_fields(gateway, name, path, fields, pool, args.batch)
                    if fields else {}
                )
                types[name] = {
                    "depth": depth,
                    "path": f'{path["kind"]} {path["namespace"]}.{path["field"]}'
                            + ("." + ".".join(path["chain"]) if path["chain"] else ""),
                    "fields": {k: v for k, v in sorted(classified.items())},
                }
                log(f"  [{depth}] {name}: {len(fields)} field(s)")
                for field, field_type in classified.items():
                    if not field_type:
                        continue
                    child = base_type(field_type)
                    if child in types or depth + 1 > args.max_depth:
                        continue
                    queue.append((child, {**path, "chain": [*path["chain"], field]},
                                  depth + 1))
    except ResolverEntered as exc:
        log(f"ABORTED, walk was not inert: {exc}")
        return 3

    result = {
        "host": args.host,
        "url": gateway.url,
        "request_count": gateway.requests,
        # Zero by construction: post_checked raises on the first non-null data,
        # so a completed run cannot have entered one. Recorded anyway so the
        # renderer's gate reads the same field it reads for schema_map output.
        "resolvers_entered": [],
        "types": types,
    }
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True),
                              encoding="utf-8")
    known = sum(1 for t in types.values() if t["fields"])
    total = sum(len(t["fields"]) for t in types.values())
    log(f"{len(types)} types ({known} with fields, {len(types) - known} undiscovered), "
        f"{total} subfields, {gateway.requests} requests -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
