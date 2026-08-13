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
git clone https://github.com/vecyang1/hexact-cli && cd hexact-cli
python3 -m hexact doctor
```

Optionally put it on your `PATH`:

```bash
printf '#!/bin/sh\nexec python3 -m hexact "$@"\n' > /usr/local/bin/hexact && chmod +x /usr/local/bin/hexact
```

## Credentials

Keys never live in this repository. They are resolved at runtime, first hit wins:

| Order | Source | Set with |
| --- | --- | --- |
| 1 | Environment | `export HEXOWATCH_API_KEY=…` |
| 2 | 1Password | `export HEXOWATCH_OP_REF='op://Vault/Item/credential'` |
| 3 | File | `~/.config/hexact/credentials.env`, mode `600` |

The 1Password route is the one to use for anything unattended — the repo holds
only an `op://` pointer, which is not a secret. `HEXACT_OP_CMD` overrides the
executable, so a service-account wrapper can be used without editing code.

Substitute `HEXOMATIC_` / `HEXOMETER_` for the other products. Each is
independent; `doctor` reports an unconfigured product as `SKIP`, not `FAIL`.

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

**Mute is not pause.** A paused monitor stops checking and stops being a record
of anything. A muted monitor keeps checking on schedule and keeps recording
every change — it just stops routing them anywhere. If what you want is "keep
tracking, stop telling me", `mute` is the only thing that says it.

This is also the one thing the REST API cannot do at all: `notification_integrations`
applies at creation time, and there is no REST update, so monitors that already
exist were unreachable.

† GraphQL-only. Needs `hexact auth login` — see below.

### Session — `hexact auth`

`login --email you@example.com`, `status`.

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

**This credential is broader than the API keys.** A REST key reaches six
documented endpoints; a refresh token reaches the whole account, including
billing. Two mitigations, both in code rather than convention:
`graphql.MUTATION_ALLOWLIST` permits exactly ten mutations — Watch, watch
integrations, and account notification settings — and is checked before a
request is built, and `graphql.FORBIDDEN_NAMESPACES` makes account and
billing operations unreachable. `delete` additionally refuses without `--yes`,
before touching the network.

Every write is confirmed by reading it back. A mutation answering
`{"error": false}` is a claim, not proof.

### Hexomatic — `hexact matic`

`workflows`, `workflow <id>`, `logs <id>`, `enable`/`disable <ids…>`.

**There is no endpoint that runs a workflow.** The API can list, read, toggle,
and delete; triggering requires Hexomatic's own scheduler or an external
integration.

### Hexometer — `hexact meter`

`properties`, `health <property_id> [--status S]`, `errors <property_id> --tool-name T`.

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

Full endpoint reference in [docs/API.md](docs/API.md). The things that cost real
debugging time:

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
- **Hexowatch has no update and no delete endpoint.** Retiring a monitor means
  pausing it; retuning one means recreating it.

## Products without an API

**Hexospark** and **Hexofy** publish no API — verified by control-diffing their
documentation URLs against a page that cannot exist, not by status code alone.
The only programmatic path into the Hexospark CRM is a first-party
[Hexomatic → Hexospark automation](https://hexomatic.com/automation/hexospark).

## Development

```bash
python3 -m unittest discover -s tests -v
```

Tests are hermetic: every environment variable the package reads is scrubbed at
import, so a suite run cannot pass because the developer happened to have a real
key exported.

## License

MIT
