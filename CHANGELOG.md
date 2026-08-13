# Changelog

Notable changes per release. Dates are when the version was cut.

The entries say what changed *and*, where it matters, what was believed before —
several of these releases exist because an earlier claim in this repository
turned out to be wrong, and a changelog that hides that teaches the next reader
to trust the wrong sentence.

## 0.6.0 — 2026-08-14

**It can be installed now.** `pyproject.toml` with a `hexact` console script, so
`pipx install git+https://github.com/vecyang1/hexact-cli`, `uv tool install`
and `pip install .` all work. Previously the README asked you to hand-write a
shell wrapper into `/usr/local/bin`. Dependencies stay empty and the packaging
metadata reads its version from `hexact/__init__.py` rather than restating it.

- **`--version`.** The CLI could not say which build it was.
- **Fixed: the "no session token" error named the wrong product and the wrong
  operation.** It read *"No Hexowatch session token found. Delete and update are
  GraphQL-only…"* and was printed verbatim by `matic credits`, `spark contacts`
  and `meter overview`. One session token serves all six products, so the
  message now says that and names no operation. The remedy line underneath was
  always correct, which is what made the wrong diagnosis costly rather than
  merely untidy.
- **`cli.py` split by product.** It had reached 1364 lines against this
  project's own 800-line ceiling. Command bodies moved to `cli_watch_rest`,
  `cli_hexowatch`, `cli_hexomatic`, `cli_hexometer`, `cli_hexospark` and
  `cli_auth`; `cli_common` holds the shared rendering helpers; `cli.py` is the
  parser and the top-level error handler. A test now enforces the ceiling, and
  two tests that had been patching a name the implementation no longer read
  were repointed at the module that owns it.
- **Schema drift is detectable.** `tools/validate_documents.py` existed but
  nothing ran it. CI now does, on a schedule — a client assembled from a
  reverse-engineered schema fails when the vendor renames a field, and this is
  the only instrument that sees it coming.

## 0.5.0 — 2026-08-14

Five surfaces REST has no concept of, reached through the gateway: `watch tags`,
`watch list` (server-side filtering with a total count), `watch noise`,
`watch alerts`, `matic credits` / `matic detail`, `matic results` (**what a
workflow produced**, where REST returns only its logs), `spark contacts` /
`spark campaigns`, and `meter overview` / `meter issues`.

- **Hexospark is reachable after all.** "Hexospark publishes no REST API" was
  true and incomplete: the shared gateway carries the whole product. Reads only,
  on purpose — campaign writes put mail in front of real people, and the
  mutation allowlist refuses them rather than a comment asking nicely.
- **Hexometer writes stay unwired** for the same kind of reason: they consume
  scan quota and billable work.
- `docs/TYPES.md`: the shape of all 357 return types, recovered inertly. Without
  it most of the gateway is uncallable — GraphQL rejects a document that selects
  an object without naming its subfields.
- `tools/validate_documents.py`: proves a document is well-formed against the
  live schema without executing it, using a field that cannot exist.
- **Fixed: a stored credential could be unrenewable.** `login` now classifies
  what it is about to save and exchanges it once before writing it. An access
  token in the refresh slot authenticates for an hour and then dies, and nothing
  at the time of storing it can tell.

## 0.4.0 — 2026-08-13

Account-level notification controls: `watch email --off`, `watch webhook
set/show/clear`. Both were previously recorded here as dashboard-only and not
API-reachable. That was wrong — `UserWatchSettingsOps` has them.

## 0.3.0 — 2026-08-13

`watch mute` / `unmute` / `channels` / `settings`, and the first full map of the
gateway. **Mute is not pause**: a muted monitor keeps checking and keeps
recording, it just stops routing anywhere. REST cannot express that at all,
because `notification_integrations` applies only at creation time.

## 0.2.0 — 2026-08-13

`watch show`, `delete` and `retune` through the GraphQL gateway. The REST API
has no update and no delete — measured across five path shapes and three
methods, not assumed from the documentation.

- **Fixed: duplicate detection grouped by URL alone**, reporting 11 groups and
  18 redundant monitors on an account that had exactly one. Running several
  tools against the same page is the normal configuration; the key is
  (URL, tool). Acting on the old number would have paused 17 working monitors.

## 0.1.0 — 2026-08-13

First release. Hexowatch, Hexomatic and Hexometer over the documented REST
endpoints, `--json` on everything, and `doctor` to prove each credential
actually authenticates instead of merely being present.
