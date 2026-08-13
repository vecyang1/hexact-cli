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
endpoint** exist. The dashboard can edit monitors; the API cannot.

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
