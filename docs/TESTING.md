# Testing

Three layers: portable-core unit tests on your Linux machine (fast, no hardware), the ESP-IDF firmware build, and on-device verification with real DNS queries.

## Host unit tests

The portable core (`main/core/`) is pure C++17 with zero ESP-IDF includes, so it compiles and runs on any Linux box with `g++`. No external dependencies — the tests in `tests/host/` use a self-contained mini-framework.

```bash
cd tests/host
./run_tests.sh
```

`run_tests.sh` builds with `g++ -std=c++17 -I../../../main` and runs the suite. It must pass cleanly. Coverage targets (Team A):

| Module | What's tested |
|---|---|
| `domain_matcher` | normalization (case, whitespace, trailing dot), suffix walk order + early stop, FNV-1a stability |
| `bloom_filter` | sizing math (m, k), no false negatives, measured FP rate near configured 1% |
| `dns_codec` | strict parse: truncation, label-pointer loops, QDCOUNT≠1, non-IN class rejected; block-response shapes per `BlockMode`/qtype |
| `rule_engine` | precedence: allowlist > custom rule > blocklist; suffix matching; disabled ⇒ all ALLOW; garbage input never asserts |
| `dns_cache` | store/lookup round-trip, transaction-ID patching, TTL clamping to [60, 86400] s, capacity eviction |

Per [CONTRACTS.md](../CONTRACTS.md) §10: portable core returns `bool`/values, never asserts on input — the tests feed it garbage deliberately.

## Firmware build

```bash
idf.py set-target esp32   # or esp32s3
idf.py build
```

> **Build verification status: VERIFIED ✅** — compiled clean on 2026-10-15 with
> ESP-IDF **v5.1.4** (target `esp32`, default `partitions.csv`, `-Os`):
> `idf.py build` exits 0 with **zero warnings** in project code.
> Final binary: `esp32-network-shield.bin` = **1,130,656 bytes (0x1140A0)**,
> fitting the 1.25 MB app partitions with ~14% headroom.
> (`idf.py size` reports ~1.12 MB flash use; the classic ESP32 still has
> ~90 KB DRAM / ~40 KB IRAM free at boot.)

**Fixes found by the real build** (the code was written against the contracts
before a toolchain existed here): `esp_littlefs.h` is the managed LittleFS
header (not `esp_vfs_littlefs.h`); `mdns` is a *managed* component in v5.1
(`espressif/mdns`, added to `main/idf_component.yml`); `CONFIG_HTTPD_WS_SUPPORT=y`
is required for the WebSocket API; `esp_random()` moved to `esp_random.h`;
`esp_ota_mark_app_valid()` was renamed to
`esp_ota_mark_app_valid_cancel_rollback()`; `httpd_req_t.uri` is a fixed char
array (never NULL); the query helper is `httpd_query_key_value()` (no
`httpd_query_get_val`); `esp_crt_bundle.h` lives in the `mbedtls` component;
C++ exceptions need `CONFIG_COMPILER_CXX_EXCEPTIONS=y`; the partition table
grew an `otadata` partition (OTA was broken without it) and app partitions are
1.25 MB because the binary exceeds 1 MB.

## On-device verification

Flash with `idf.py -p PORT flash monitor`, provision Wi-Fi via the captive portal ([Getting Started](GETTING_STARTED.md#4-provision-wi-fi-via-the-captive-portal)), then run these from any machine on the LAN. Below, `192.168.1.50` is the Shield's IP — substitute yours.

### 1. Blocking works

```bash
dig @192.168.1.50 doubleclick.net +short
# expect: 0.0.0.0            (default block_mode = NULL_IP)

dig @192.168.1.50 www.doubleclick.net +short
# expect: 0.0.0.0            (suffix match — subdomains are covered)
```

`doubleclick.net` is guaranteed present by the updater's validation spot-check, so it's the canonical "must be blocked" probe. (`ads.example.com` is *not* in any list — don't use it as a test.)

### 2. Forwarding works

```bash
dig @192.168.1.50 google.com +short
# expect: a real IP, e.g. 142.250.x.x   (exact value varies)

dig @192.168.1.50 google.com AAAA +short
# expect: a real IPv6 address           (AAAA path through the forwarder)
```

`google.com` is guaranteed *absent* by the same validation spot-check — the canonical "must be allowed" probe.

### 3. Cache works (timing test)

```bash
dig @192.168.1.50 google.com | grep "Query time"
# first run:   ;; Query time: 38 msec   (went upstream)

dig @192.168.1.50 google.com | grep "Query time"
# second run:  ;; Query time: 0 msec    (cache hit)
```

Second query should report ~0–1 ms. Confirm on the dashboard that `cache_hit_rate` climbs.

### 4. Block modes

```bash
# switch to NXDOMAIN mode (needs the API token from first boot)
curl -X PUT http://192.168.1.50/api/config \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"block_mode":1}'

dig @192.168.1.50 doubleclick.net
# expect: status: NXDOMAIN

# switch back
curl -X PUT http://192.168.1.50/api/config \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"block_mode":0}'
```

### 5. API + dashboard smoke test

```bash
curl http://192.168.1.50/api/status            # public, no token
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.50/api/stats
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.50/api/devices
```

Open http://192.168.1.50 in a browser, enter the token, and confirm: counters move, the live query log shows your `dig` probes, and `doubleclick.net` appears in the top-blocked table.

### Serial monitor: log lines to expect

Exact TAG text is per Team E's implementation, but a healthy boot shows these milestones in order (illustrative):

```
I (...) shield: NVS initialized, namespace "shield"
I (...) shield: generated new API token          <- FIRST BOOT ONLY: copy this
I (...) wifi: connected, ip=192.168.1.50
I (...) shield: mDNS started: esp32-shield.local
I (...) shield: blocklist loaded: slot A, 58931 entries, Bloom 479253 bits
I (...) shield: DNS server listening on UDP :53
I (...) shield: HTTP server started on :80
```

Then, every 10 s, the health monitor logs a heartbeat (Wi-Fi status, upstream health, stats flush, heap watermark). Red flags: `blocklist loaded: slot A, 0 entries` (no list yet — trigger `POST /api/blocklist/update`), repeated upstream timeouts (check `upstream_primary`), or a shrinking heap watermark (possible leak — file it against the owning team).

### Blocklist update end-to-end

```bash
curl -X POST http://192.168.1.50/api/blocklist/update \
  -H "Authorization: Bearer $TOKEN"
# → {"status":"started"}

# poll until entries/updated_at change:
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.50/api/blocklist
```

Takes a few minutes on first run (two HTTPS downloads + parse + sort on-device). The active slot is never touched until validation passes — see [BLOCKLISTS.md](BLOCKLISTS.md#ab-update-safety).
