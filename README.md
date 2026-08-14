# hexact-cli

An agentic command-line client for the [Hexact](https://hexact.io) suite —
**Hexowatch** (website change monitoring), **Hexomatic** (scraping and workflow
automation), and **Hexometer** (site health, SEO, security).

Zero dependencies. Python 3.10+. Every command speaks `--json`, so an agent can
consume it as readily as a human can read it.

```bash
hexact watch changes --since 24h --min-percent 5   # what actually changed
hexact watch duplicates                            # monitors watching the same URL
hexact watch check_now 273810                      # force a scan
hexact matic workflows                             # scraping workflows
hexact meter properties                            # monitored properties
```

## Why this exists

Hexowatch's change alerts arrive as email that contains **no change data** — just
a link back to the dashboard. On a real account, 79% of those alerts were
sub-1% changes and 22% reported *exactly 0%* change. The API returns the actual
`oldData`/`newData` diff and a `percentage`, so you can filter on magnitude
instead of reading everything.

No official CLI, SDK, or MCP server exists for any of these products.

## Install

```bash
pipx install git+https://github.com/vecyang1/hexact-cli   # or: uv tool install git+https://github.com/vecyang1/hexact-cli
hexact --version
```

Either tool builds a `hexact` binary in its own virtualenv. There is nothing to
resolve — the dependency list is empty — so the install cannot conflict with
anything already on the machine.

**If that second line prints `command not found`**, the install worked and the
directory it wrote to is not on your `PATH`. pipx puts binaries in
`~/.local/bin`; `pipx ensurepath` adds it, then open a new shell. `pipx list`
confirms what is actually installed. This is the one step CI cannot prove for
you — it builds and installs the wheel into a clean virtualenv, but a runner
never exercises your shell's `PATH`.

Configure a credential next, then verify with `hexact doctor` — see
[Credentials](#credentials). Running `doctor` before any key exists reports
`[SKIP]` for every product and exits **2**, because a check that examined
nothing is not a pass.

From a clone, `pip install .` gives the same binary:

```bash
git clone https://github.com/vecyang1/hexact-cli && cd hexact-cli
pip install .
```

Or run it out of the clone without installing anything, which works for the
same reason:

```bash
python3 -m hexact doctor
```

Python 3.10+.

## Credentials

Keys never live in this repository. They are resolved at runtime, first hit wins:

| Order | Source | Set with |
| --- | --- | --- |
| 1 | Environment | `export HEXOWATCH_API_KEY=…` |
| 2 | 1Password | `export HEXOWATCH_OP_REF='op://Vault/Item/credential'` |
| 2a | 1Password, unattended | also `export HEXACT_OP_CMD='<your service-account wrapper>'` |
| 3 | File | `~/.config/hexact/credentials.env`, mode `600` |

The 1Password route is the one to use for anything unattended — the repo holds
only an `op://` pointer, which is not a secret. Row 2a is not optional for a
cron job or an agent: stock `op read` blocks on an interactive biometric unlock,
which in an unattended run means a 30-second timeout and a `CredentialError`,
not a prompt anyone can answer. `HEXACT_OP_CMD` replaces the executable (shell
word list, so it may carry its own arguments), letting a service-account
wrapper stand in without editing code.

Substitute `HEXOMATIC_` / `HEXOMETER_` for the other products. Each is
independent; `doctor` reports one unconfigured product as `SKIP`, not `FAIL` —
but *every* product skipped exits 2, since nothing was verified.

Get the keys from the **API/Webhook** section of each dashboard's settings
(Hexometer's key is per-*property*, not per-account).

## Commands

### Hexowatch — `hexact watch`

| Command | Purpose |
| --- | --- |
| `monitors` | List monitors with active/paused state |
| `changes --since 7d [--min-percent N]` | Detected changes, with a noise filter |
| `duplicates` | Monitors watching the same URL |
| `scan <id> --tool <tool>` | The actual before/after diff |
| `check_now <ids…>` / `pause` / `resume` | Force, stop, or restart scanning |
| `create --url U --tool T [--silent]` | Create a monitor |
| `levels` | Valid `change_notification_level` per tool (offline) |
| `integrations` | Notification channels and their IDs |
| `show <id>` | A monitor's real config — tool, level, interval, channels † |
| `channels` | Account notification channels and their IDs † |
| `mute <ids…>` | Stop an **existing** monitor notifying, without pausing it † |
| `unmute <ids…> --channel ID` | Attach channels back † |
| `settings` | Account-level email recipients + webhooks † |
| `email --off` / `--on` | Account-wide notification email switch † |
| `webhook set URL` / `show` / `clear ID` | Account-level webhook, fires for every monitor † |
| `delete <ids…> --yes` | **Permanently delete** monitors † |
| `retune <ids…> --level GE_5` | Change alert threshold or interval † |
| `tags list` / `create` / `delete` / `set` | Monitor tags — REST has no tag concept at all † |
| `list [--tag N] [--tool T] [--search S]` | Monitors with tool, interval and tags, filtered server-side † |
| `noise [--since] [--until]` | Notification volume counted by the server, not by pulling every change † |
| `alerts read --all` / `delete --id N --yes` | The dashboard's alert inbox † |

**Mute is not pause.** A paused monitor stops checking and stops being a record
of anything. A muted monitor keeps checking on schedule and keeps recording
every change — it just stops routing them anywhere. If what you want is "keep
tracking, stop telling me", `mute` is the only thing that says it.

This is also the one thing the REST API cannot do at all: `notification_integrations`
applies at creation time, and there is no REST update, so monitors that already
exist were unreachable.

† GraphQL-only. Needs `hexact auth login` — see below.

### Session — `hexact auth`

`login --email you@example.com [--password-stdin]`, `status`.

The REST API has **no delete and no update**. Not undocumented — absent: `DELETE`
in five path shapes and `PUT`/`PATCH` in three all return the backend's Express
404, against controls that behaved. The dashboard's own GraphQL gateway
(`api.hexowatch.com/v2/ql`) has both, so `show`, `delete` and `retune` go there.

It does not accept the REST API key. Tested five ways (`authorization`,
`Bearer`, `x-api-key`, `?key=` query, URL param) — all five returned `null`,
identical to sending no credential. It wants the dashboard's session token:

```bash
hexact auth login --email you@example.com   # prompts; the password is never stored
hexact auth status                          # confirms the gateway accepts it
```

Only the long-lived refresh token is saved, into the same credentials file
(mode `600`). The password is read with `getpass` — never a flag, since argv is
visible to every process and lands in shell history — used for one request, and
never written. Short-lived access tokens are minted per command and held in
memory only.

**With no terminal, `login` refuses instead of prompting.** `getpass` answers
that case by falling back to a *plain, echoing* read of stdin — it prints
`Warning: Password input may be echoed.` and carries on — which in a CI job, a
pipeline or an agent tool call writes the account password into whatever is
capturing that stream. For automation, pipe it in explicitly:

```bash
some-secret-source | hexact auth login --email you@example.com --password-stdin
```

`--password-stdin` reads exactly one line, strips only the newline, and refuses
if stdin is a terminal — because with no pipe attached it would sit there
echoing what you type. Either way the password never reaches argv.

**This credential is broader than the API keys.** A REST key reaches six
documented endpoints; a refresh token reaches the whole account, including
billing. Two mitigations, both in code rather than convention.

`graphql.MUTATION_ALLOWLIST` is checked before a request is built, and every
operation in it belongs to one of five namespaces:

<!-- allowlist-namespaces -->
`UserWatchSettingsOps`, `WatchAlertOps`, `WatchIntegrationOps`, `WatchOps`,
`WatchTagOps`
<!-- /allowlist-namespaces -->

Monitors, their tags, their notification routing, the alert inbox, and the
account's notification settings. Nothing from Hexomatic, Hexometer or Hexospark
is writable through this client even though the same token reaches all of them.
The list above is not maintained by hand — a test regenerates it from the code
and fails if this paragraph falls behind. `graphql.FORBIDDEN_NAMESPACES` makes
account and billing operations unreachable, and `delete` refuses without
`--yes`, before touching the network.

Every write is confirmed by reading it back. A mutation answering
`{"error": false}` is a claim, not proof.

### Hexomatic — `hexact matic`

`workflows`, `workflow <id>`, `logs <id>`, `enable`/`disable <ids…>`.

| Command | Purpose |
| --- | --- |
| `credits [--series]` | Automation credit burn — absent from REST entirely † |
| `detail` | Workflows with per-run credit cost, schedule and status † |
| `results <id> [--url]` | **What a workflow actually produced.** REST returns only its logs † |

**There is no endpoint that runs a workflow.** Measured, not assumed: all 11
fields of `HexomaticWorkflowOps` were enumerated and none of them is a run,
execute or trigger. Triggering requires Hexomatic's own scheduler or an
external integration.

### Hexometer — `hexact meter`

`properties`, `health <property_id> [--status S]`, `errors <property_id> --tool-name T`.

| Command | Purpose |
| --- | --- |
| `overview` | Every property with its open-issue counts † |
| `issues [--page N] [--tool T]` | Detected issues, paged † |

REST needs a **per-property** key and has no endpoint that lists properties, so
`overview` is the only way to enumerate what the account monitors. Hexometer's
*writes* — rescan, report generation, sub-property CRUD — exist on the gateway
and are deliberately **not** wired: they consume scan quota and billable work,
so `PropertyOps` stays in `graphql.FORBIDDEN_NAMESPACES`.

### Hexospark — `hexact spark`

| Command | Purpose |
| --- | --- |
| `contacts [--campaign ID] [--search T]` | CRM contacts with sent/opened/clicked/replied counters † |
| `campaigns [--search T]` | Outreach campaigns with schedule, status and contact count † |

**Hexospark publishes no REST API** — verified by control-diffing its
documentation URLs against a page that cannot exist. That finding was right and
incomplete: the shared gateway carries 24 Hexospark namespaces, so the product
is undocumented rather than unreachable.

**Read-only, on purpose.** `HexosparkCampaignOps` can create campaigns, attach
contacts and add steps; those writes put mail in front of real people, which is
not something a client an agent can drive unattended should do. The mutation
allowlist refuses every Hexospark operation, so the boundary is enforced rather
than intended, and a test pins it.

## Monitoring without notifications

`change_notification_level` **cannot** mute anything — no tool's enum has an
off/none/silent value, and the narrowest setting still notifies. The documented
way to keep monitoring while staying quiet is an empty integration list:

```bash
hexact watch create --url https://example.com --tool visualMonitoringTool --silent
```

which sends `notification_integrations: []`, no `webhook`, and
`pause_after_first_change_event: false`. Then poll `hexact watch changes` on
your own schedule.

Two caveats worth knowing before relying on this:

- Hexowatch also supports an **account-level webhook** that fires for *every*
  monitor. This was previously recorded here as dashboard-only and not
  API-reachable. That was wrong: it is `UserWatchSettingsOps.subscribeWebhook`
  on the gateway, and `hexact watch webhook set URL` drives it.
- Whether the account's default email still applies when
  `notification_integrations` is empty is **not documented**. There is now a
  blunter lever that does not depend on the answer —
  `hexact watch email --off` (`UserWatchSettingsOps.update(emailEnabled:)`)
  switches notification email off account-wide.

### Quietening monitors that already exist

`--silent` only applies at creation, and REST cannot edit a monitor afterwards.
`retune` can:

```bash
hexact watch retune 285438 --level GE_5   # alert only on larger changes
```

This is the lever for alert noise dominated by trivial diffs — visual monitors
routinely fire at 0.06%. **`GE_n`'s exact meaning is undocumented**; the `GE_`
prefix and the `percentage` field in scan results make "≥ n%" the obvious
reading, but the vendor never states it. `retune` reads the value back so you
can see it persisted; whether it actually suppresses smaller changes takes days
of observation to confirm. Change one monitor first.

## Choosing a monitor type

Cost and false-positive rate both follow this order. Pick the narrowest one that
answers your question.

| Want to know | Tool |
| --- | --- |
| Is it up? | `availabilityMonitoringTool` |
| Did this specific text change? | `contentMonitoringTool` + `SPECIFIC_CONTENT` |
| Did a keyword appear or vanish? | `keywordTool` |
| Did the markup change? | `sourceCodeMonitoringTool` |
| Did their stack change? | `techStackTool` |
| Did the page *look* different? | `visualMonitoringTool` |

`visualMonitoringTool` is last for a reason: on a real account it fired on
0.0616% pixel differences, daily, for months. If you only care about a price or
a headline, a content monitor scoped to that element will not.

## Notes on the API

Full endpoint reference in [docs/API.md](docs/API.md), which links two generated
companions: [docs/GATEWAY.md](docs/GATEWAY.md) (every namespace, field, argument
and return type on the gateway) and [docs/TYPES.md](docs/TYPES.md) (the shape of
each return type, with a paste-ready selection set). Both were recovered from
validator error messages without credentials and without entering a resolver —
`tools/schema_map.py` and `tools/type_map.py` regenerate them.

`tools/validate_documents.py` checks every GraphQL document this client can send
against the live schema, anonymously and inertly, by adding one field that
cannot exist so validation fails before execution. That is how a mutation is
proved well-formed without firing it at a real account.

The things that cost real debugging time:

- **HTTP 200 can carry a failure.** The envelope is `{"error": true, "message": …}`
  with a 200 status. Checking the status code alone accepts errors as data.
- **Cloudflare rejects `Python-urllib`** with a 403 (error 1010,
  `browser_signature_banned`) *before* looking at the key — indistinguishable
  from a bad key. `curl`'s own agent passes, so an honest `User-Agent` is
  enough; no browser spoofing required.
- **A wrong key and a valid key can return byte-identical errors.** Send a
  deliberately fake key as a control before concluding a key is bad.
- **Hostnames do not identify products.** All Hexact API hosts share one
  backend, so `api.hexospark.com` answers Hexometer's routes with a plausible
  `invalid api key`. Identify a product by its documented endpoints.
- **Hexowatch's *REST* API has no update and no delete.** Scope the claim to the
  transport you tested: the GraphQL gateway has both, and this CLI ships them as
  `watch delete` and `watch retune`. Reading "no endpoint" as "impossible" is
  what made earlier versions of this file prescribe pause-and-recreate.

## Products without an API

**Hexospark** and **Hexofy** publish no API — verified by control-diffing their
documentation URLs against a page that cannot exist, not by status code alone.
The only programmatic path into the Hexospark CRM is a first-party
[Hexomatic → Hexospark automation](https://hexomatic.com/automation/hexospark).

## Development

Three checks, and they answer different questions. Running only the first is
the mistake worth naming.

```bash
python3 -m unittest discover -s tests -v   # behaviour, against fakes
python3 tests/mutation_check.py            # prove those tests can fail
python3 tools/validate_documents.py        # prove the GraphQL is still real
```

Tests are hermetic: every environment variable the package reads is scrubbed at
import, so a suite run cannot pass because the developer happened to have a real
key exported.

`mutation_check.py` breaks each guarantee on purpose, in a fresh copy of the
tree, and fails if any mutation survives — a green suite is not evidence until
you have watched it go red. It also refuses a mutation whose pattern it could
not find, so a test that quietly stopped covering moved code is reported rather
than counted as a pass.

`validate_documents.py` is the one that needs no credential and still tells you
something a unit test cannot. Every query in this client was recovered from an
undocumented gateway by reading validator errors, so the risk that outlives any
mock is Hexact renaming a field. It sends each document with one field that
cannot exist, which makes validation fail *before* execution — nothing runs, no
account is touched — while the error list still reports every other problem. If
the only complaint is the canary, the document is still valid. CI runs it on a
schedule for exactly that reason.

Code layout: `cli.py` is the parser and the top-level error handler. Command
bodies live in per-product modules (`cli_watch_rest`, `cli_hexowatch`,
`cli_hexomatic`, `cli_hexometer`, `cli_hexospark`, `cli_auth`), shared rendering
helpers in `cli_common`, and a test enforces the project's 800-line-per-file
ceiling so the split does not quietly undo itself.

`hexact --version` reports the running build; the value has exactly one home,
`hexact/__init__.py`, and the packaging metadata and User-Agent both derive from
it. What changed between builds is in
[CHANGELOG.md](CHANGELOG.md), and a test fails the suite if a release has no
entry there.

## License

MIT
