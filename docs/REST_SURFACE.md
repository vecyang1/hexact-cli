# Hexact REST surface — reverse-engineered with a route-existence oracle

Method: a **credential-free route-existence oracle**. On these hosts the backend
is an Express app. A request whose **method+path pair is not registered** returns
Express's own 404 with an HTML body `Cannot <METHOD> /api/app/services/<path>`.
A request whose method+path pair **is** registered gets past routing into the
handler, which — with no valid key — returns an HTTP 200/400 JSON body such as
`{"error":true,"message":"invalid api key"}`. So *route existence is decidable
with no key at all*, and every probe below carried `?key=probe` (a fake key), so
nothing could touch a real account.

- Probed 2026-08-13. Discovery host: `api.hexowatch.com` (proven equivalent to
  the others below).
- User-Agent used on every request:
  `hexact-cli/0.4.0 (+https://github.com/vecyang1/hexact-cli)`.
  `Python-urllib` is banned by Cloudflare with `403 browser_signature_banned`;
  that is a client-signature block, not auth. An honest `curl` UA passes.
- Writes were sent only against non-existent ids / empty id arrays
  (`{"ids":[]}`), and the fake key is the real safety guarantee — nothing is
  mutable without a real key.

---

## 1. Controls (both required, both shown)

Without a positive and a negative control the oracle means nothing. Both behaved
as the method predicts.

### Control A — a route known to EXIST (expect JSON)

`GET https://api.hexowatch.com/v2/app/services/v1/monitored_urls?key=probe`

```
HTTP 400
{"error":true,"message":"invalid api key"}
```

The request reached the handler; the handler rejected the fake key. Route EXISTS.

### Control B — a route that CANNOT exist (expect Express 404)

`GET https://api.hexowatch.com/v2/app/services/v1/zzz_definitely_not_a_route_9f3a?key=probe`

```
HTTP 404
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /api/app/services/v1/zzz_definitely_not_a_route_9f3a</pre>
</body>
</html>
```

Routing found no handler and returned the framework 404. Route ABSENT.

The two responses are unmistakably different (JSON 400 vs HTML `Cannot GET` 404),
so every result below is a real yes/no, not a guess.

---

## 2. Host equivalence — one shared router behind all six hosts

Four paths were probed on all six `api.*` hosts. Every host returned a
**byte-identical** body for the same path, including the *same two distinct JSON
error dialects* (see §4). This is strong evidence that all six hostnames front
**one shared REST router**, not six separate product APIs.

| path (`/v2/app/services/…`) | api.hexowatch | api.hexomatic | api.hexospark | api.hexometer | api.hexofy | api.hexoscope |
| --- | --- | --- | --- | --- | --- | --- |
| `v1/monitored_urls` GET | 400 `invalid api key` | same | same | same | same | same |
| `v1/workflows` GET | 400 `INVALID_KEY` | same | same | same | same | same |
| `v1/properties` GET | 400 `invalid api key` | same | same | same | same | same |
| `v1/zzz_nope_9f3a` GET | 404 `Cannot GET` | same | same | same | same | same |

**Consequence (confirms prior project knowledge):** a hostname probe proves
nothing about a product. The Hexowatch monitor routes, the Hexomatic workflow
routes, and the Hexometer property routes are all reachable through
`api.hexospark.com` and `api.hexofy.com` too — even though Hexospark and Hexofy
themselves ship no product REST API (see §6). "Which product owns a route" is not
answerable from the router; it is answerable only from the docs and the
handler's error dialect.

---

## 3. Route table — every route found to EXIST, with methods it accepts

Each cell was decided by the same oracle: a JSON body = method routed (YES);
`Cannot <METHOD> …` = method not routed (NO). All 13 paths × 5 methods = 65
probes were re-run under slow, retried, foreground conditions after an initial
run was corrupted by Cloudflare rate-limiting (see §7).

| Path (`/v2/app/services/…`) | GET | POST | PUT | PATCH | DELETE | Handler's fake-key error (evidence) |
| --- | :-: | :-: | :-: | :-: | :-: | --- |
| `v1/monitored_urls` | ✅ | — | — | — | — | `{"error":true,"message":"invalid api key"}` |
| `v1/integrations` | ✅ | — | — | — | — | `{"error":true,"message":"Bad request"}` |
| `v1/properties` | ✅ | — | — | — | — | `{"error":true,"message":"invalid api key"}` |
| `v1/workflows` | ✅ | — | ✅ | — | ✅ | GET→`INVALID_KEY`; PUT/DELETE→`Workflow ids is required.` |
| `v1/workflow-logs` | ✅ | — | — | — | — | `{"error":true,"message":"Workflow_id is required."}` |
| `v1/monitor` | — | ✅ | — | — | — | `{"error":true,"message":"Invalid api key","monitoring_ids":[]}` |
| `v2/monitor` | — | ✅ | — | — | — | `{"error":true,"message":"Invalid api key","monitoring_ids":[]}` |
| `v1/action` | — | — | — | ✅ | — | `{"error":true,"message":"bad request"}` |
| `v1/health_links` | — | ✅ | — | — | — | `{"error":true,"message":"Property id is required"}` |
| `v1/health_links/statuses` | — | ✅ | — | — | — | `{"error":true,"message":"Property id is required"}` |
| `v1/detected_errors` | — | ✅ | — | — | — | `{"error":true,"message":"Property id is required"}` |
| `v1/monitoring_logs/{id}` | ✅ | — | — | — | — | `{"error":true,"message":"Invalid api key"}` (probed id `999999999`) |
| `v1/scan_result/{id}` | ✅ | — | — | — | — | `{"error":true,"message":"Invalid api key"}` (probed id `999999999`) |

✅ = method routed · — = `Cannot <METHOD>` (not routed).

### What matches the documented baseline

Every documented route resolved exactly as documented, including the method
split: `v2/monitor` is POST-only, `v1/action` is PATCH-only, `v1/workflows`
accepts GET/PUT/DELETE (not POST/PATCH), `health_links` / `health_links/statuses`
/ `detected_errors` are POST-only, and `monitoring_logs/{id}` / `scan_result/{id}`
are GET-only. `DELETE`/`PUT`/`PATCH` on the monitor and monitored-url paths remain
Express-404 — consistent with "no REST update/delete for monitors" (those live on
the GraphQL gateway, out of scope here).

### The one undocumented finding

- **`POST v1/monitor` EXISTS** and returns the *same* create-shape as the
  documented `POST v2/monitor`
  (`{"error":true,"message":"Invalid api key","monitoring_ids":[]}`). The
  published Hexowatch surface documents only `v2/monitor` for creation; a `v1/`
  alias is present on the router and was not in the baseline. Only POST is routed
  on it — GET/PUT/PATCH/DELETE all return `Cannot …`.
  - **Not overstated:** existence ≠ usefulness. Whether `v1/monitor` accepts the
    same body, behaves identically, or is a deprecated/forwarding alias is
    **UNKNOWN** without a real key. All that is proven is that the POST route is
    registered and enters the same create handler shape.

### Two error dialects = at least two microservices behind one gateway

The router mixes two error envelopes, a useful fingerprint:

- **`{"error":true,"message":"…"}`** — monitor, monitored_urls, integrations,
  properties, workflow-logs, health_links, detected_errors, action,
  monitoring_logs, scan_result. (Hexowatch/Hexometer family.)
- **`{"error_code":"INVALID_KEY","error_message":"…"}`** — `v1/workflows` GET
  only. (Hexomatic family; and note `v1/workflows` PUT/DELETE fall back to the
  *first* dialect — `Workflow ids is required.` — so even one path straddles two
  middlewares.)

This is consistent with one Express gateway proxying several product backends.

---

## 4. Routes probed and confirmed ABSENT

A 128-noun wordlist (plural/singular pairs) was swept under both `v1/` and `v2/`
prefixes with GET, and the full list was swept again under `v1/` with POST to
catch write-only routes a GET sweep is structurally blind to (see §7).

**Confidently absent** — returned `Cannot GET` **and** `Cannot POST` on `v1/`
(120 nouns); every one also absent under the `v2/` GET sweep:

```
account accounts activity alert alerts api_keys apikeys audit audits automation
automations backlink backlinks billing campaign campaigns check checks contact
contacts credits dashboard dashboards data domain domains email emails error
errors event events export exports file files folder folders health healthchecks
history integration invoice invoices issue issues job jobs keyword keywords links
logs me member members metrics monitor_logs monitors notification notifications
organization organizations payment payments permissions plan plans profile
project projects property property_urls query recipe recipes report reports
result results role roles scan scans schedule schedules scraper scrapers search
setting settings sitemap sitemaps statistics stats status statuses subscription
subscriptions tag tags task tasks team teams template templates token tokens
usage user users webhook webhooks workflow workflows-logs workspace workspaces
```

Notable **negatives worth stating plainly** (these do *not* exist as REST routes
on the shared router): `users`/`user`, `account`/`settings`, `webhooks`,
`teams`/`workspaces`, `automations`, `scrapers`, `recipes`, `billing`/`credits`/
`usage`/`plans`/`subscriptions`, `tags`, `campaigns`, `contacts`, `export`,
`stats`/`statistics`, `notifications`, `keywords`/`backlinks`/`sitemaps`.

Also **absent under both `v1/` and `v2/`** as bare nouns: everything above under
`v2/` (the `v2/` prefix carries essentially only `monitor`).

### Caveat — three "absent-looking" nouns that actually EXIST

The GET+POST sweep flags these as absent because it never tried the right method
or an id segment. The method matrix (§3) proves they exist:

- `action` — absent for GET and POST, but **`PATCH v1/action` EXISTS**.
- `monitoring_logs` — bare path 404s, but **`GET v1/monitoring_logs/{id}` EXISTS**.
- `scan_result` — bare path 404s, but **`GET v1/scan_result/{id}` EXISTS**.

This is the central limitation, generalized in §7: a noun "absent" from one
method/shape is not absent from the router.

---

## 5. API documentation pages (control-diffed per host)

Each `/api-documentation/` page was compared against a URL that cannot exist on
the same host (`/zzz-not-a-page-9f3a/`) so a SPA soft-404 is not mistaken for a
real page.

| Host | `/api-documentation/` | control (`/zzz…/`) | verdict |
| --- | --- | --- | --- |
| hexowatch.com | 200, 700 993 B | 404, 516 257 B | **REAL PAGE** (distinct status + size) |
| hexomatic.com | 200, 563 052 B | 404, 495 462 B | **REAL PAGE** |
| hexometer.com | 200, 907 372 B | 404, 210 B | **REAL PAGE** |
| hexospark.com | 404, 355 590 B | 404, 355 590 B | **no page** (byte-identical soft-404) |
| hexofy.com | 404, 514 644 B | 404, 514 644 B | **no page** (byte-identical soft-404) |
| hexoscope.com | 404, 421 213 B | 404, 421 213 B | **no page** (byte-identical soft-404) |

Only Hexowatch, Hexomatic, and Hexometer publish an API documentation page.
Hexospark, Hexofy, and Hexoscope return a soft-404 identical to their own
not-found control — consistent with those products shipping no public REST API,
even though their `api.*` subdomain still fronts the shared router.

---

## 6. Summary of findings

- **13 REST routes exist** on the shared router (11 documented + the
  `v1/health_links/statuses` sub-route + the **undocumented `POST v1/monitor`**).
- **1 undocumented route:** `POST v1/monitor`, a version alias of the documented
  `POST v2/monitor` (behaviour/parameters UNKNOWN).
- **All six `api.*` hosts serve one identical router** — hostname is not a
  product boundary.
- **Two error dialects** on the router betray at least two product backends
  behind one Express gateway.
- **No REST routes** for users, accounts, settings, webhooks, teams, workspaces,
  automations, scrapers, recipes, billing, tags, campaigns, contacts, export,
  stats, notifications, keywords, backlinks, or sitemaps.
- **API docs pages** exist only for Hexowatch, Hexomatic, Hexometer.

---

## 7. Limits of this method (read before trusting the negatives)

1. **A negative is per method+path, not per path.** Express registers
   `METHOD path` pairs and 404s any unregistered pair. A GET sweep cannot see a
   POST-only route; that is exactly why `monitor`, `health_links`, and
   `detected_errors` were invisible to GET and only surfaced under POST. Three
   nouns (`action`, `monitoring_logs`, `scan_result`) still looked absent to the
   GET+POST sweep and exist only under PATCH, or under GET with an `{id}` segment.
   **The §4 "absent" list is therefore "absent for the methods/shapes probed",
   not "provably nonexistent".** Routes needing an unguessed sub-path
   (`.../statuses`) or a nested segment could exist and read as absent.
2. **Existence ≠ usefulness.** A registered route says nothing about its real
   parameters, response schema, auth model, side effects, or stability. Every
   "purpose" here is inferred from the fake-key error string, which is weak
   evidence. Do not build a client against a route from this document alone.
3. **The oracle depends on Express's default 404 staying in place.** If a future
   deploy adds a catch-all handler or a custom 404, `Cannot <METHOD>` disappears
   and the oracle silently breaks. Re-establish both controls (§1) before reusing
   this technique.
4. **Rate-limiting corrupts results silently.** An early bursted matrix run came
   back with empty bodies and empty status codes for *every* cell, which naive
   parsing scored as "method routed (YES)" across the board — a false positive on
   every line. The trustworthy matrix in §3 was produced foreground, slowly, with
   retry-on-empty, and every cell here carries a non-empty status code as
   evidence. Treat any empty-body probe as **inconclusive**, never as a hit.
5. **Wordlist bias.** Only ~128 English nouns (plus known routes) were tried.
   Routes with unguessed names, non-English tokens, uuid-style segments, or a
   third API version were not reachable by this list and are recorded as neither
   present nor absent — i.e. **UNKNOWN**.
6. **GraphQL is out of scope.** Monitor update/delete are known to live on the
   GraphQL gateway (`/v2/ql`), not REST. Their absence from REST here is expected
   and is not evidence they are unavailable.

## Appendix — reproduction

```bash
UA='hexact-cli/0.4.0 (+https://github.com/vecyang1/hexact-cli)'
# Control A (exists → JSON 400):
curl -sS -A "$UA" 'https://api.hexowatch.com/v2/app/services/v1/monitored_urls?key=probe'
# Control B (absent → Cannot GET 404):
curl -sS -A "$UA" 'https://api.hexowatch.com/v2/app/services/v1/zzz_nope_9f3a?key=probe'
# Method probe (Cannot <METHOD> = not routed):
curl -sS -A "$UA" -X DELETE -H 'Content-Type: application/json' -d '{"ids":[]}' \
  'https://api.hexowatch.com/v2/app/services/v2/monitor?key=probe'
```

Always send `?key=probe` (a fake key). The fake key is the safety guarantee —
never substitute a real one to "get a cleaner error".
