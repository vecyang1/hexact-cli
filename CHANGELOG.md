# Changelog

Notable changes per release. Dates are when the version was cut.

The entries say what changed *and*, where it matters, what was believed before —
several of these releases exist because an earlier claim in this repository
turned out to be wrong, and a changelog that hides that teaches the next reader
to trust the wrong sentence.

## 0.7.4 — 2026-08-14

- **`graphql.only_supplied()`** — the omit-a-null-filter rule from 0.7.3 now has
  one owner instead of a copy per call site, and the two remaining places that
  handed the gateway a present-and-null variable use it: the notification
  breakdown (`from`/`to`) and Hexospark's `settings`, which was sent as `null`
  whenever the caller passed no filter.
- **Measured, not assumed, for the four commands that still return nothing:**
  `watch noise` and `matic credits` come back null at the *namespace* level and
  `spark contacts` / `spark campaigns` return an empty list with a null total —
  the same after the fix as before it, with a working session and REST
  answering 45 monitors as a control. So these are entitlement or genuinely
  empty, not the null-filter bug, and the client keeps refusing to render them
  as "no data".

## 0.7.3 — 2026-08-14

`hexact watch list` has reported an empty account for as long as it has
existed, and this is the first release where anyone had a working session to
notice.

- **Fixed: an unset filter was sent as an explicit `null`, and the server reads
  that as a filter.** With a valid session, REST reporting 45 monitors at the
  same minute:

  ```
  page+limit only                totalCount=45  rows=45
  page+limit plus null filters   totalCount=0   rows=0
  ```

  Not an error, not a null container, but a stated `0` — which is why
  `reject_all_null` sails past it: the zero is real, the *question* was wrong.
  `list_monitors` now sends only the filters the caller actually set.
  `is not None`, not truthiness, so `--paused` (`active=False`) still filters.

- **Fixed: `--tool` offered names the gateway does not use.** The choices came
  from the REST *creation* vocabulary. On this account the 16 monitors the
  dashboard calls visual come back as `sectionScreenTool`, and `automaticAITool`
  was not in the list at all — so `--tool visualMonitoringTool` was an
  *offered, validated choice* that matched nothing and reported a confident
  zero. `watch list --tool` now takes a free-form name and lets the server
  judge it; `watch create --tool` keeps its validated list, because there a
  typo builds the wrong kind of monitor. When a filtered listing comes back
  empty, the command now says where the real values are instead of leaving the
  reader to conclude they have none.

## 0.7.2 — 2026-08-14

**Fixed: on a Python with no CA certificates, every single request failed and
blamed the network.** A zero-dependency client inherits whatever trust store the
interpreter has, and a python.org build has *none* — `ssl.create_default_context()`
returns 0 certificates and points at a `cert.pem` that only exists after someone
runs "Install Certificates.command". Nobody runs it, least of all when the
interpreter was picked for them by `pipx --python`. The visible symptom was

```
API error: URLError calling the GraphQL gateway:
  <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] … unable to get local issuer certificate>
```

directly after typing a password, which reads as a server or network fault and
sends the reader nowhere near their own interpreter. Measured on this machine:
Homebrew 3.14 verifies fine but `pipx`'s `uv` backend refuses it (empty
`platform.mac_ver()`), while the python.org 3.12 that `uv` accepts cannot verify
anything — so *which* interpreter pipx settles on decides whether the client
works at all.

`hexact.http.ssl_context()` now falls back to the platform CA bundle
(`/etc/ssl/cert.pem` and the usual Linux/Homebrew locations) when Python brought
none, and both transports use it. **Verification is never disabled** — that is
asserted by a test that will outlive this note. When no bundle exists anywhere
it still fails closed, and the error now names the cause instead of the network.

- The printed-command gate learned to tell commands from English. "reinstall
  hexact on an interpreter…" was graded as the command `hexact on an` and
  reported as a finding — the failure mode that gets a useful test deleted. It
  now grades only mentions whose first word is a real top-level command, which
  is the honest scope; 33 of them, still RED-proved against the defect it was
  written for.

## 0.7.1 — 2026-08-14

The first real login since the exchange broke, and it cost the user their
credential.

- **Fixed: a failed exchange threw away a perfectly good refresh token.**
  `auth login` verified before storing, so when `UserOps.authAccessToken`
  refused the token, nothing was written — the user typed their password, the
  gateway issued a genuine 360-hour refresh token valid until 2026-08-29,
  `classify_credential` agreed it was a refresh token, and `auth status` then
  reported `missing`. The order was written for the wrong failure: it assumed a
  bad token, and it also fires when the token is perfect and the *exchange* is
  broken. **Store first, then verify and report.** The command exits 1 when
  renewal is unproven, and says so in as many words.
- **`login` keeps the access token from the same response.** `UserLoginResponse`
  carries both; earlier builds dropped `token` on the reasoning that an access
  token on disk is a liability with no benefit. That held until the mint stopped
  working — it is now the only thing that makes the CLI usable, it is the
  narrower of the two credentials, and it expires on its own. It goes into the
  same owner-only `credentials.env` under `HEXOWATCH_ACCESS_TOKEN`, which the
  resolver already reads.
- **Fixed: the exchange failure invented a cause.** It said the token had been
  *"revoked, the password changed, or it simply expired"* on the same line as
  its own evidence that the token was **still valid**. Measured against the live
  gateway: `authAccessToken` answers a deliberately garbage token with
  byte-identical `{"token": null, "error": false, "message": ""}`, so the
  response carries no information about which happened. It now says that, and
  names no cause it cannot support. The login path also stopped describing "the
  stored value" — nothing is stored at that point — and stopped prescribing the
  command that had just failed.
- **Fixed, hermeticity: the test suite wrote to the real `~/.config/hexact/`.**
  `HEXACT_HOME` was *scrubbed* at import along with the credential variables,
  and scrubbing it selects the developer's actual credential store rather than
  nothing. Adding a second writer to the login command — one the existing test
  did not patch — put a one-character fake token into the real
  `credentials.env` and broke `hexact` on the machine running the tests. The
  variable now points at a disposable directory for the whole session, so the
  guarantee is structural instead of per-test discipline.

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

Running the gateway reads against an account whose session had expired, with
REST answering at the same moment as a control, produced the rest.

- **Fixed, correctness: `watch list`, `watch channels` and `watch settings`
  reported an expired session as an empty account.** They printed
  `0 of None monitor(s)`, `No notification channels registered.` and
  `Email recipients (0)` — and exited `0` — for an account REST simultaneously
  reported as 48 monitors and 3 channels. A deliberately invalid token produced
  byte-identical output, so nothing on screen distinguished them. `--json` was
  worse: it emitted `"watchProperties": []`, which a script cannot tell from a
  real answer at all.

  The gateway was honest throughout. It returns a non-null *container* whose
  members are all null (`{"totalCount": null, "watchProperties": null}`), which
  `graphql.unwrap` passes because it guards the two levels GraphQL wraps every
  answer in and the nulls are one level below that. The empty list was invented
  locally, by an `or []` in each renderer. New `graphql.reject_all_null` refuses
  a container whose every member is null — *every*, not any, so an account with
  recipients but no webhooks still reads fine — and the renderers now print
  "unreadable" for a single null member instead of `0`. Believed before: that
  `unwrap` alone was sufficient, on the grounds that a genuinely empty
  collection comes back as `[]`. True at the field level, false one level down.
- **Fixed: two remedies, disagreeing, one line apart.** The top-level handler
  appended `Run: hexact auth login --email <you>` to every `AuthError`,
  including the ones whose own message had deliberately said
  `Check which: hexact auth status` because they cannot tell an expired token
  from an account that never had access to that namespace. The handler no
  longer appends anything; the one raise site where the *server* rejected the
  credential now carries the login remedy itself.
- **Fixed: `watch duplicates` recommended the weaker of the two remedies it
  ships.** It printed "Hexowatch has no delete endpoint" and offered only
  `watch pause`, for as long as `watch delete` has existed in this repository —
  the claim was true of REST and was never rescoped. The one command whose
  output is a list of things to switch off now leads with the delete, names its
  irreversibility and its `auth login` prerequisite, and keeps pause as the
  fallback.
- **Fixed: `tests/mutation_check.py` could hang instead of reporting.** A
  mutated build can reach a blocking read the real one cannot — deleting the
  terminal check from `prompt_password` lets `getpass` open `/dev/tty` — and
  with a terminal inherited from the harness it waited there until the 300s
  timeout aborted the whole run. A mutation the suite catches in under two
  seconds was reporting as a crash. The child now runs with stdin detached.

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
