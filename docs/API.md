# API Reference

Base URL: `http://192.168.1.50` (your Shield's IP, or http://esp32-shield.local). Everything is JSON over HTTP; the live feed is a WebSocket.

**Shape authority note:** CONTRACTS.md §8 defers exact JSON shapes to this document, so the shapes below are binding for Team D's implementation. Where the contract only named a category (e.g. "wifi"), this doc pins the field names — those pins are marked *(pinned here)*. Request/response shapes the contract *did* specify are reproduced verbatim.

## Authentication

Protected routes require the API token in the `Authorization` header:

```
Authorization: Bearer <api_token>
```

The token is 32 lowercase hex chars, generated once on first boot and stored in NVS (`api_token`). Copy it from the serial log on first boot — it's the only time it's displayed. The dashboard prompts for it once and keeps it in the browser's `localStorage`.

**Public routes (no token):** `GET /api/status`, `GET /setup*` (provisioning mode only), and `/` (redirect / setup page).

**Auth failure:** wrong or missing token on a protected route →

```http
HTTP/1.1 401 Unauthorized
{"error":"unauthorized"}
```

All curl examples below assume:

```bash
IP=192.168.1.50
TOKEN=<your 32-char hex token>   # e.g. TOKEN=9f3a...; use TOKEN=$TOKEN in headers
```

## Status & stats

### `GET /api/status` — public

Device identity, version, uptime, Wi-Fi, filtering state, blocklist meta, upstreams. Deliberately public (no token) so monitoring tools and the "is it alive?" check don't need a secret — it exposes no credentials.

```bash
curl http://$IP/api/status
```

```jsonc
{
  "device": "esp32-shield",          // device_name
  "version": "0.4.0",                // FIRMWARE_VERSION
  "uptime_s": 86412,
  "wifi": {                          // (pinned here)
    "connected": true,
    "ssid": "HomeNet",
    "ip": "192.168.1.50",
    "rssi": -61
  },
  "filtering": {                     // (pinned here)
    "enabled": true,                 // filtering_enabled
    "block_mode": 0                  // 0=NULL_IP, 1=NXDOMAIN, 2=NODATA
  },
  "blocklist": {                     // (pinned here)
    "active_slot": "A",
    "entries": 58931,
    "updated_at": 1699991200         // seconds since boot when activated (V1 has no wall clock)
  },
  "upstream": {                      // (pinned here)
    "primary": "1.1.1.1",
    "secondary": "1.0.0.1",
    "timeout_ms": 2500
  }
}
```

### `GET /api/stats` — protected

`StatsSnapshot` as JSON plus computed rates.

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/stats
```

```jsonc
{
  "total_queries": 42391,
  "blocked_queries": 11204,
  "cache_hits": 25934,
  "upstream_queries": 16457,
  "uptime_s": 86412,
  "top_blocked": [                   // up to 10, fixed-size on device
    {"domain": "doubleclick.net", "count": 1832},
    {"domain": "ads.example.com", "count": 977}
  ],
  "block_rate": 26.4,                // (pinned here) 100 * blocked_queries / total_queries
  "cache_hit_rate": 61.2             // (pinned here) 100 * cache_hits / total_queries
}
```

Rates are `0.0` when `total_queries` is 0.

### `GET /api/devices` — protected

Array of `DeviceEntry` (32-slot table, keyed by IP). `ip` is rendered as a dotted quad *(pinned here)*; `hostname` is empty in V1 (no hostname resolution yet — see [ROADMAP](ROADMAP.md)).

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/devices
```

```json
[
  {
    "ip": "192.168.1.10",
    "hostname": "",
    "queries": 12043,
    "blocked": 3211,
    "first_seen_s": 120,
    "last_seen_s": 86399
  }
]
```

Timestamps are seconds since boot.

### `GET /api/queries?limit=50` — protected

Newest-first array of `QueryLogEntry`. `limit` defaults to 50, max 200 (the ring buffer size).

```bash
curl -H "Authorization: Bearer $TOKEN" "http://$IP/api/queries?limit=10"
```

```jsonc
[
  {
    "ts_s": 86399,                   // seconds since boot
    "client_ip": "192.168.1.10",     // (pinned here) dotted quad
    "domain": "doubleclick.net",
    "qtype": 1,                      // 1=A, 28=AAAA, ...
    "decision": "block",             // (pinned here) "allow" | "block" | "nxdomain"
    "cached": false
  }
]
```

## Config

### `GET /api/config` — protected

Returns the NVS `shield` keys as JSON. **`wifi_pass` and `api_token` are never returned** *(pinned here — they're write-only/secrets)*.

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/config
```

```json
{
  "wifi_ssid": "HomeNet",
  "device_name": "esp32-shield",
  "upstream_primary": "1.1.1.1",
  "upstream_secondary": "1.0.0.1",
  "upstream_timeout_ms": 2500,
  "filtering_enabled": 1,
  "block_mode": 0,
  "update_interval_h": 24,
  "cache_entries": 256,
  "stats_flush_min": 5
}
```

### `PUT /api/config` — protected

Partial update: send only the keys you want to change. Values are validated (ranges, dotted-quad format for upstreams); invalid → `400 {"error":"<reason>"}`. `api_token` cannot be set this way. Setters commit to NVS immediately; upstream/filtering/block-mode changes apply live, Wi-Fi credential changes apply on next reboot.

```bash
curl -X PUT http://$IP/api/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"upstream_primary":"9.9.9.9","block_mode":1,"filtering_enabled":1}'
```

```json
{ "updated": ["upstream_primary", "block_mode", "filtering_enabled"] }   // (pinned here)
```

## Blocklist

### `GET /api/blocklist` — protected

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/blocklist
```

```jsonc
{
  "active_slot": "A",
  "entries": 58931,
  "updated_at": 1699991200,          // seconds since boot when activated
  "sources": [                       // (pinned here)
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://someonewhocares.org/hosts/zero/hosts"
  ]
}
```

### `POST /api/blocklist/update` — protected

Starts an update in a background task and returns immediately. Poll `GET /api/blocklist` until `entries`/`updated_at` change — there is no progress endpoint in V1.

```bash
curl -X POST http://$IP/api/blocklist/update \
  -H "Authorization: Bearer $TOKEN"
```

```json
{"status":"started"}
```

See [BLOCKLISTS.md](BLOCKLISTS.md) for sources, formats, validation, and A/B safety.

## Allowlist

Suffix-matched, highest precedence (see [ARCHITECTURE.md](ARCHITECTURE.md#3-rule-engine-precedence)).

### `GET /api/allowlist` — protected

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/allowlist
```

```json
{"domains": ["example.com", "cdn.example.net"]}
```

### `POST /api/allowlist` — protected

Accepts either a single domain or a batch *(both shapes from CONTRACTS.md §8)*. Domains are normalized on receipt (lowercase, trailing dot stripped).

```bash
curl -X POST http://$IP/api/allowlist \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'

# or batch:
curl -X POST http://$IP/api/allowlist \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domains":["a.com","b.com"]}'
```

```json
{"added": ["example.com"]}   // (pinned here) echoes normalized domains
```

### `DELETE /api/allowlist?domain=x` — protected

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://$IP/api/allowlist?domain=example.com"
```

```json
{"removed": "example.com"}   // (pinned here)
```

Unknown domain → `404 {"error":"not_found"}` *(pinned here)*.

## Custom rules

Longest-suffix match, evaluated between allowlist and blocklist. `action` is `"block"` or `"allow"`; new rules are `enabled: true` by default.

### `GET /api/rules` — protected

```bash
curl -H "Authorization: Bearer $TOKEN" http://$IP/api/rules
```

```json
{
  "rules": [
    {"id": 3, "domain": "x.com", "action": "block", "enabled": true}
  ]
}
```

### `POST /api/rules` — protected

```bash
curl -X POST http://$IP/api/rules \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"annoying-ads.example","action":"block"}'
```

```json
{"id": 4, "domain": "annoying-ads.example", "action": "block", "enabled": true}   // (pinned here)
```

### `DELETE /api/rules/:id` — protected

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://$IP/api/rules/3
```

```json
{"removed": 3}   // (pinned here)
```

Unknown id → `404 {"error":"not_found"}` *(pinned here)*.

## System

### `POST /api/reboot` — protected

```bash
curl -X POST http://$IP/api/reboot -H "Authorization: Bearer $TOKEN"
```

```json
{"status":"rebooting"}   // (pinned here) — device reboots immediately after responding
```

### `POST /api/ota` — protected

Starts an HTTPS OTA from the given URL (`OtaManager::begin`). After flashing, the device reboots and must pass its DNS self-test within 60 s or it rolls back (see [ARCHITECTURE.md](ARCHITECTURE.md#10-ota-with-rollback)).

```bash
curl -X POST http://$IP/api/ota \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/firmware/esp32-shield-0.5.0.bin"}'
```

```json
{"status":"started"}   // (pinned here) — update proceeds in the background
```

Only `https://` URLs are accepted → `400 {"error":"https_required"}` *(pinned here)*.

## Provisioning (AP mode only)

On first boot (no Wi-Fi credentials), the Shield runs an open AP `ESP32-Shield-XXXX` with DNS hijacked to the AP IP. These routes exist **only in provisioning mode**:

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Setup page (HTML form) |
| `GET` | `/setup*` | Setup assets (public) |
| `POST` | `/setup` | Form fields `wifi_ssid`, `wifi_pass`, `device_name` → saved to NVS, device reboots into station mode |

```bash
# equivalent of submitting the form:
curl -X POST http://192.168.4.1/setup \
  -d "wifi_ssid=HomeNet&wifi_pass=s3cret&device_name=esp32-shield"
```

In normal (station) mode `GET /` serves the dashboard (public HTML shell; the token is entered in-page).

## WebSocket `/ws`

Live stats push every 2 seconds. Message format (exact, from CONTRACTS.md §8):

```json
{"type":"stats","ts":1699999999,"total":42391,"blocked":11204,
 "block_rate":26.4,"cache_hit_rate":61.2,"devices":8}
```

`ts` is seconds since boot in V1 (no wall clock); the dashboard renders it as uptime.

```bash
# websocat (https://github.com/vi/websocat)
websocat ws://192.168.1.50/ws
```

> **Auth on `/ws`:** CONTRACTS.md doesn't specify whether the WebSocket upgrade requires the Bearer token. Team D: either require `Authorization: Bearer` on the upgrade request (preferred — `websocat -H "Authorization: Bearer $TOKEN" ws://…/ws`) or restrict to same-origin. This doc will be updated once decided.

## Errors

| Status | Body | When |
|---|---|---|
| 401 | `{"error":"unauthorized"}` | missing/invalid Bearer token on a protected route |
| 400 | `{"error":"<reason>"}` | validation failure (`PUT /api/config` range/format, non-HTTPS OTA URL, malformed rule) |
| 404 | `{"error":"not_found"}` | unknown rule id / allowlist domain *(pinned here)* |

Only the 401 shape is fixed by the contract; the `{"error":"…"}` envelope for the rest is pinned here for consistency.
