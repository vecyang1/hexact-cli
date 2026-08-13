# Hexact API reference

Extracted from the vendor documentation on 2026-08-13 and cross-checked against
live responses. Where the two disagree, both are recorded — the disagreements
are real and a client has to handle them.

Sources: [Hexowatch API](https://hexowatch.com/api-documentation/) ·
[Hexowatch webhooks](https://hexowatch.com/webhook/) ·
[Hexomatic API](https://hexomatic.com/api-documentation/) ·
[Hexometer API](https://hexometer.com/api-documentation/)

## Authentication

Every product uses the same scheme: `?key={API_KEY}` as a **query parameter**.
No header auth is documented. Because the credential is in the URL, anything
that echoes a URL — a log line, an exception, a traceback — discloses it. See
`hexact/http.py`.

Hexowatch and Hexomatic keys are per-account, from the dashboard's API/Webhook
settings. Hexometer's key is **per-property**.

## Hexowatch — `https://api.hexowatch.com/v2/app/services`

Six endpoints. There is no seventh: **no update endpoint and no delete
endpoint** exist here. Measured 2026-08-13, not inferred from the docs —
`DELETE` in five path shapes and `PUT`/`PATCH` in three all return the
backend's Express 404 (`Cannot DELETE /api/app/services/v2/monitor`), against
controls that behaved correctly.

Both operations do exist on the **GraphQL gateway** — see that section below.
"Absent from REST" and "impossible" are different claims, and only the first
one is true.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `v1/integrations` | Notification channels → `result[]` of `{id, type, data}` |
| POST | `v2/monitor` | Create monitors → `{monitoring_ids: []}` |
| GET | `v1/monitored_urls` | All monitors → `monitored_urls[]` |
| PATCH | `v1/action` | `pause` / `resume` / `check_now` |
| GET | `v1/monitoring_logs/{id}` | Scan history → `monitoring_results[]` |
| GET | `v1/scan_result/{id}?tool=…` | The diff → `scanResult.{newData,oldData}` |

Note the version split: creation is under `v2/`, everything else under `v1/`.

### `POST v2/monitor` body

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `tool` | string | — | **Required.** One of the 8 creatable tools below |
| `address_list` | string[] | — | **Required.** One monitor created per address |
| `notification_integrations` | number[] | `[]` | IDs from `v1/integrations`. **Empty = no notifications** |
| `change_notification_level` | string | `"ANY"` | Values differ per tool; none of them mute |
| `monitoring_interval` | string | `"1_DAY"` | 19 values |
| `pause_after_first_change_event` | boolean | `false` | `true` *stops monitoring* after one change |
| `tags` | string[] | `[]` | |
| `webhook` | string | `null` | A creation-time failure to reach it aborts the create |
| `tool_settings` | object | per tool | See below |

There is no `name` field, no per-address settings, and no scheduling/timezone field.

### Creatable tools (8) and their `tool_settings`

`sitemapTool`, `apiMonitoringTool`, `htmlElementMonitoringTool`,
`automaticAITool` and `rssTool` appear in scan results but have **no documented
creation schema** — 13 readable, 8 creatable.

| Tool | `mode` values (default first) | Other settings |
| --- | --- | --- |
| `techStackTool` | `ANY_CHANGE`, `SPECIFIC_TECH_STACK_SEARCH` | `specific_tech_stacks[]` (required in search mode; 1195 known values) |
| `keywordTool` | `SEARCH` | `keywords[]` **required**; `operators` `OR`/`AND` required when >1 keyword |
| `visualMonitoringTool` | `FULL_SCREEN` | `adblock`, `device` (8 values, Pro), `full_stack` |
| `availabilityMonitoringTool` | — | none beyond the shared fields |
| `sourceCodeMonitoringTool` | `FULL_CODE`, `SPECIFIC_CODE` | `specific_codes[]`; `file_type` `HTML`/`CSS`/`JS` |
| `domainWhoisTool` | `ANY_CHANGE`, `SPECIFIC_FIELDS` | `specific_fields[]` (9 values); `alertDay` (20 values); **no `proxy`** |
| `contentMonitoringTool` | `FULL_CONTENT`, `SPECIFIC_CONTENT` | `contents[]` |
| `backlinkTool` | `FULL_DATA` | `keyword` **required** |

Shared by all except `domainWhoisTool`: `proxy` (`{type:"premium", country_code}`,
139 countries, Pro plan), `api_host_code` (`EUROPE`/`USA`/`ASIA`, default `USA`),
`user_agent` (default `false`).

### `change_notification_level`

A change *classification* filter, **not** a delivery switch.

| Tool | Allowed values |
| --- | --- |
| `techStackTool` | `ANY`, `ADDED`, `UPDATED`, `DELETED` |
| `visualMonitoringTool`, `contentMonitoringTool` | `ANY`, `GE_1`…`GE_15`, `GE_20`, `GE_25`, `GE_50` |
| all five others | `ANY` only |

No value means "off". The meaning of each value — including what `GE_n` measures
— **is not documented**. `GE_` is a conventional "greater or equal" prefix and
scan results carry a `percentage`, so `GE_5` plausibly means ≥5%; the vendor
never states this, so do not rely on it.

To monitor without notifications, send `notification_integrations: []` and no
`webhook`. This cannot disable the **account-level** webhook configured in
dashboard settings, which fires for every monitor and is not API-reachable.

### `monitoring_interval` (19)

`5_MINUTE` `10_MINUTE` `15_MINUTE` `30_MINUTE` `1_HOUR` `2_HOUR` `3_HOUR`
`4_HOUR` `5_HOUR` `6_HOUR` `12_HOUR` `1_DAY` `2_DAY` `3_DAY` `1_WEEK` `2_WEEK`
`1_MONTH` `2_MONTH` `3_MONTH`. Which values are plan-gated is not documented.

### Response shapes

```jsonc
// v1/monitored_urls
{"error": false, "monitored_urls": [{"id": 273810, "address": "...", "name": "...", "paused": false}]}

// v1/monitoring_logs/{id}
{"error": false, "monitoring_id": "337094", "tool": "visualMonitoringTool",
 "monitoring_results": [
   {"scan_result_id": "6a7cc8ff…", "date": "2026-08-12T19:26:55.309Z",
    "event_detected": true, "percentage": 0.0616}]}
```

The state key is **inconsistent**: the docs specify `active` (true = running),
the live API returned `paused` (true = stopped), and the docs' own
apiMonitoringTool example also shows `paused`. Handle both.

`Only_detected_changes` is capitalised exactly that way — inconsistent with
every other snake_case parameter, and not a transcription error.

`monitoring_logs` and `scan_result` are documented as GETs that take a **request
body**. Many HTTP stacks drop GET bodies, so send these as query parameters.

The success body of `PATCH v1/action` is not documented. Do not depend on any
field coming back.

### Webhook payload

A JSON **array**. Method, headers, retries, and signature verification are not
documented. Two flavours: account-level (settings; fires for every monitor) and
per-monitor (the `webhook` field).

Per element: `id`, `title`, `monitoredUrl`, `name`, `createdDate`,
`changePercentage`, `link`, `old_data`, `new_data`, `diff_data`,
`condition_values`, `tags`, `element_content`, `element_content_keyword`,
`element_parsed_data`, plus ten `*ToolData` objects each shaped
`{deletions, updates, additions}`.

Those ten keys use a **third naming scheme**, distinct from both the creation
tool names and the scan-result tool names — `sectionScreenToolData` ↔ visual,
`pingToolData` ↔ availability, `httpRequestToolData` ↔ API monitor. The mapping
is not documented, and there is no `tool` discriminator: infer the monitor type
from which `*ToolData` key is populated.

## The GraphQL gateway — `https://api.hexowatch.com/v2/ql`

Undocumented by the vendor. Recovered from the dashboard bundle and verified
against the live server on 2026-08-13. `v2/app` (REST) and `v2/ql` (GraphQL) are
two prefixes on **one gateway**.

This is where delete and update live. Confirmed present by omitting required
arguments, so GraphQL validation rejects the call before any resolver runs,
against a control field that correctly read absent:

One gateway carries the **whole suite**: 27 query and 21 mutation namespaces,
recovered with the "Did you mean" oracle described below. Beyond `Watch*`
there are `HexomaticWorkflow(Ops)`, `HexosparkCampaignOps`
(`create` `update` `createSteps` `addContacts` `deleteAll`),
`HexosparkCrmContactOps` (`create` `update` `updateBulk` `move`),
`Hexospark{Common,Tag,User}Ops`, `HexometerIssuesOps`, `Scraper`, `Keyword`,
`Task`, `Shortlink`, `Alert`, `Billing`, `Admin`.

**"Hexospark has no API" is true only of REST.** Its CRM and campaign
mutations are on this gateway. That correction matters because the earlier
verdict was recorded without the qualifier.

`WatchOps` in full: `createWatchProperty` `updateWatchProperty`
`updateWatchProperties` `deleteWatchProperty` `deleteWatchProperties`
`subscribeWebhook` `updateWebhook` `exportAll` `adminDelete`.

| Operation | Signature |
| --- | --- |
| `WatchOps.deleteWatchProperty` | `(watch_property_id: Int!)` |
| `WatchOps.deleteWatchProperties` | `(watch_properties_ids: [Int]!)` |
| `WatchOps.createWatchProperty` | `(address: String!, tool: String!, tool_settings: WatchToolSettingsMapping!, monitoring_interval: String!, pause_after_first_change_event: Boolean!)` |
| `WatchOps.subscribeWebhook` | `(webhookUrl: String!, watch_property_id: Int!)` — **per monitor**, not account-level |
| `WatchOps.updateWebhook` | `(subscriptionId: String!, updateWebhook: String!, watch_property_id: Int!)` |
| `WatchOps.exportAll` | no required arguments |
| `WatchIntegrationOps.updateWatchPropertyIntegrations` | `(watch_property_id: Int!, watch_integration_ids: [Int]!)` — **empty list = mute** |
| `WatchIntegrationOps.deleteWatchPropertyIntegration` | `(watch_property_id: Int!, watch_integration_id: Int!)` |
| `WatchIntegrationOps.deleteWatchIntegration` | `(watch_integration_id: Int!)` — account-wide |
| `WatchOps.updateWatchProperty` | `(watch_property_id, active, monitoring_interval, change_notification_level, pause_after_first_change_event, name, alert_notification_settings, scheduling_settings, tool_settings)` |
| `WatchOps.updateWatchProperties` | `(watch_properties_ids: [Int]!, active, monitoring_interval, change_notification_level, tags, watch_integration_ids, tool_settings)` |

Reads: `Watch.getWatchProperty(watch_property_id)` returns `id name url active
change_notification_level createdAt tool tool_settings{…}` — the monitor detail
REST has no endpoint for. Also `WatchIntegration.getWatchPropertyIntegrations`
and `Watch.getUserWatchPropertiesStatistics`.

### Authentication is different from REST

`?key=` does **not** work here. Measured five ways — `authorization`, `Bearer`,
`x-api-key`, `?key=` query parameter, URL parameter — every one returned `null`,
byte-identical to sending no credential at all.

```
UserOps.authRefreshToken(email: String!, password: String!) -> { token hash }
UserOps.authAccessToken(refreshToken: String!)              -> { token }
```

The access token goes in an `authorization` header. That is strictly safer than
the REST scheme, which puts a live credential in every URL.

### The trap: a deleted monitor still resolves

`getWatchProperty` on an id that no longer exists returns **HTTP 200 with a
normal object whose every field is null** — not an error, not an empty result.
So "the read-back succeeded" means nothing on its own, and a client that reads
absence as an exception reports a successful delete as a failure. Measured
2026-08-13: `watch delete` printed `STILL PRESENT` and exited 1 while the
monitor count went 49 → 48.

The mirror of it is worse. Treating *any* exception as proof of absence makes
an expired token, or a malformed selection set, confirm every deletion — both
observed in the same session, the second because a newly added `tags` field was
selected as a scalar and returned HTTP 400. **Absence is a query that succeeds
and returns a null `id`.** Nothing else counts.

Selecting object fields as scalars is a recurring shape here: `tags`
(`[WatchTagType]`), `email` (`UserWatchSettingsEmailType`) and
`properties_status` all need subfield selections and answer HTTP 400 otherwise.

### Also selectable on WatchProperty

`monitoring_interval` `tags { id name }` `alertCount` `tool_settings`
`scheduling_settings` `webhooks`, none of which the first client selected —
which is why `retune --interval` could "confirm" a write by reading a field it
had never changed.

### The trap: null is an auth failure, not empty data

An unauthenticated read returns **HTTP 200** with:

```json
{"data":{"Watch":{"getUserWatchPropertiesStatistics":{"properties_status":null}}}}
```

No token, a bogus token, and a valid REST API key all produce exactly this.
Nothing in the response distinguishes them from an account that genuinely has no
monitors, so a client that renders `null` as "empty" tells a user with an expired
token that their account is fine and empty. Fail closed: the gateway returns
`[]` for genuinely empty collections, so nothing legitimate is lost.

`WatchOps.updateWatchProperty` with no arguments is the honest probe — it reaches
its resolver and answers `"You should be authenticated to perform this action!"`.

### Introspection is disabled

`GraphQL introspection is not allowed by Apollo Server` (HTTP 400). But the
error messages carry "Did you mean" suggestions, which is a usable schema
oracle. Operation names are unversioned with no compatibility promise, so
`tests/test_hexact.py` pins them: a silent rename should fail loudly.

## Hexomatic — `https://api.hexomatic.com/v2/app/services/v1`

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `workflows?limit=&offset=` | List workflows |
| GET | `workflows/{id}` | One workflow with completed results |
| GET | `workflow-logs?workflow_id=` | Execution history |
| PUT | `workflows` | `{workflows_ids: [], active: bool}` |
| DELETE | `workflows` | `{workflows_ids: []}` |

**No endpoint executes a workflow.** Triggering requires Hexomatic's own
scheduler or an external integration.

## Hexometer — `https://api.hexometer.com/v2/app/services/v1`

| Method | Path | Body |
| --- | --- | --- |
| GET | `properties` | — |
| POST | `health_links/statuses` | `{property_id}` |
| POST | `health_links` | `{property_id, status}` |
| POST | `detected_errors` | `{tool_name, property_id}` |

## Hexospark / Hexofy

No public API. Verified by control-diffing `/api-documentation/` against a URL
that cannot exist: both returned bodies byte-identical to the 404 control,
while Hexometer's returned 907 KB of real documentation.

**A hostname probe proves nothing here.** All Hexact API hosts share one
backend, so `api.hexospark.com/v2/app/services/v1/properties` returns a
plausible `{"error": true, "message": "invalid api key"}` — the same response
`api.hexometer.com` gives. Identify a product by documented endpoints, never by
host.

The only programmatic write path into the Hexospark CRM is the first-party
[Hexomatic → Hexospark automation](https://hexomatic.com/automation/hexospark).

## Not documented anywhere

HTTP status-code semantics, rate limits, quotas, pagination caps, retry policy;
the success body of `PATCH v1/action`; the meaning of any
`change_notification_level` value; the semantics of `user_agent`, `full_stack`,
`alertDay`'s sign, `device` pixel sizes, and techStack `categories` IDs;
whether an empty `notification_integrations` also suppresses default account
email; webhook HTTP method, headers, signature, and retries.
