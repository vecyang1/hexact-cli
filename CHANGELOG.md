# Changelog

Notable changes per release. Dates are when the version was cut.

The entries say what changed *and*, where it matters, what was believed before —
several of these releases exist because an earlier claim in this repository
turned out to be wrong, and a changelog that hides that teaches the next reader
to trust the wrong sentence.

## 0.7.0 — 2026-08-14

**Everything here was found by installing 0.6.0 and using it**, which nobody had
done: 0.6.0 shipped a CI job proving a wheel builds and installs into a clean
virtualenv on a runner, and that job is why `pipx install` worked first try —
but no runner ever touches your shell's `PATH`, and the first person to type
`hexact` on a real machine got `command not found`.

- **Fixed, security: `auth login` echoed the password when there was no
  terminal.** `getpass` cannot open `/dev/tty` in a pipeline, a CI job or an
  agent tool call, so it falls back to a *plain, echoing* read of stdin — it
  prints `Warning: Password input may be echoed.` and continues, putting the
  account password into whatever is capturing that stream. It then raised
  `EOFError` on the empty pipe, and the run ended at the top-level handler for
  *unforeseen* exceptions as `Unexpected EOFError:` — no diagnosis, no remedy,
  for a condition that is entirely foreseeable. `login` now refuses before
  prompting and names the routes that exist.
- **`auth login --password-stdin`**, the conventional shape (`docker login`,
  `gh auth login`): reads one line from a pipe, strips only the newline so a
  password ending in a space survives, and refuses when stdin is a terminal —
  the mirror of the same bug, since with no pipe attached it would sit there
  echoing what you type. The password still never reaches argv.
- **Fixed: `hexact doctor` reported a pass after examining nothing.** With no
  credential configured it printed three `[SKIP]` lines and exited `0`,
  indistinguishable from three products authenticating — and the README put it
  in the Install block, twenty-two lines *above* the credentials table, so it
  was the first command a new user ran. Three outcomes now, matching
  `tools/validate_documents.py`: `0` something authenticated, `1` something was
  refused, `2` nothing was checked. One product skipped is still `SKIP` and
  still `0`.
- **Docs: the `PATH` claim was wrong by omission.** The README said the install
  "puts a `hexact` binary on your `PATH`". pipx writes to `~/.local/bin`
  whether or not that is on `PATH`, and nothing in the repo mentioned
  `pipx ensurepath` or the words `command not found`. Install now opens with
  `hexact --version` and says what to do when it fails.
- **Docs: `HEXACT_OP_CMD` is in the credentials table**, not only in prose
  beneath it, and now says *why* it exists — stock `op read` blocks on a
  biometric unlock, so an unattended run times out rather than prompting
  anybody.

Then all 27 read-only commands were run from outside the source tree in three
states — no credential, a rejected credential, a malformed argument — which is
where the rest of this came from. None of it was visible from inside the repo.

- **Fixed: `Login failed:` was printed by thirteen commands where nobody had
  logged in.** `spark contacts`, `meter overview`, `matic credits` and the rest
  reach the gateway through `auth.access_token()`; when a *stored* token failed
  to exchange, the shared handler told the reader their credentials had just
  been rejected at a login they never performed. New `auth.SessionError`
  (a subclass, so nothing that caught `LoginError` changes) renders as
  `Session error:`.
- **Fixed: a rejected session token was diagnosed as "you stored an access
  token", and the next line disproved it.** That cause is real — it cost a day
  — but it only applies to a readable JWT, and the same output said *"an opaque
  token (not a JWT)"* two lines down. The diagnosis is now derived from
  `classify_credential`; anything else says the token was refused and names
  revocation and expiry, which is what usually happened.
- **Fixed: on the login path the same message described a stored value that did
  not exist** — the user had just typed a password — and prescribed as the fix
  the exact command that had failed.
- **Fixed: `hexact watch tags list` printed a command that cannot run.**
  *"Filter monitors by one: hexact watch monitors --tag <id>"*. `watch monitors`
  is the REST listing and takes no options at all; `watch list` is the one that
  filters. The old test only asked whether `auth login` mentions carried
  `--email`, so it could not see this; the check now grades **every** command
  string the source prints, 29 of them, against the real parser.
- **Fixed: a mistyped `--since` exited 1 as an API failure.**
  `argparse.ArgumentTypeError` inherits from `Exception`, not `ValueError`, so
  it fell past the usage branch into the last-resort handler and printed
  `Unexpected ArgumentTypeError`. It raises `ValueError` now and exits 2.
- **Fixed: `--since 30m` silently meant 900 days.** `m` is months and there is
  no minute form, but the error text advertised `1m` in a list that opened with
  `24h`. No error, no warning — just a confidently wrong window. The help now
  says `MONTHS` and says minutes are unsupported. Separately, `watch noise
  --since` and `matic credits --since` are *calendar dates* passed to the
  gateway untouched; typing a duration at those is now refused locally, naming
  the flag that does want one.
- **Fixed: `watch unmute` resolved a credential before checking it was called
  correctly**, so a missing `--channel` with nothing configured produced a
  credential error about the wrong thing — and against a working credential,
  paid a round trip to say no. `watch changes` had the same order, hiding a
  typo behind a missing key.
- **Fixed: `unwrap()` told users their token was bad when the account simply
  lacked access.** It is shared by every gateway read across four products, so
  someone with a perfectly good session who does not own Hexospark was sent to
  re-authenticate. It names both causes now and points at `hexact auth status`.
- **Fixed: the "no API key" message sent Hexometer users to the wrong page.**
  Hexometer's key is issued per *property*; `hexact/hexometer.py` said so in its
  own docstring while the shared sentence said account settings. The location
  is carried per product now, and the message says "Hexometer" rather than the
  internal id `hexometer`.
- **Fixed: the session-token error listed two of its four routes**, omitting
  `HEXOWATCH_REFRESH_TOKEN` and the credentials file — so a reader who already
  held a token had no supported way to use it. This module's docstring had
  promised every source, and the API-key message beside it delivered.
- **`hexact auth status`: four verdicts, three exit codes, failures on
  stderr.** `authenticated` 0, `rejected` 1, `missing`/`unknown` 2. It used to
  return 1 for all three failures, so a network outage was indistinguishable
  from a dead credential — the one distinction `auth.status()` goes out of its
  way to preserve internally. It was also the only command printing its bad
  news on stdout.
- **`hexact doctor` checks the gateway too.** It probed three REST keys and
  stopped, so an account with all three configured printed `[OK] [OK] [OK]` and
  exited 0 while every GraphQL command — over half the read surface — failed on
  a credential nothing had looked at.

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
