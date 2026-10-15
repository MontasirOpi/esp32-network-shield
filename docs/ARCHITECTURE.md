# Architecture

This is the deep-dive companion to [CONTRACTS.md](../CONTRACTS.md). The contract is the law (names, signatures, file formats); this document explains *why* it's shaped that way and how the pieces fit at runtime. If you're the next maintainer, read this first, then the contract.

## 1. Network placement

The Shield is a bump-in-the-wire **DNS server** on your LAN. It is not a gateway — traffic doesn't flow *through* it, only name lookups go *to* it.

```
                        Internet
                           │
                    ┌──────┴──────┐
                    │    ISP      │
                    └──────┬──────┘
                           │ WAN
              ┌────────────┴────────────┐
              │   Router (gateway)      │
              │   DHCP: DNS = Shield IP │
              └─┬─────────┬─────────┬───┘
                │         │         │
           ┌────┴───┐ ┌───┴────┐ ┌──┴───────┐      ┌────────────────┐
           │ Phone  │ │ Laptop │ │ Smart TV │      │  ESP32 Shield  │
           │        │ │        │ │          │      │                │
           │ DNS queries ──────┼────────────┼─────►│  UDP :53       │
           └────────┘ └────────┘ └──────────┘      │  HTTP :80      │
                                                  │  upstream:     │
                                                  │  1.1.1.1 /     │
                                                  │  1.0.0.1 ──────┼──► Internet
                                                  └────────────────┘
```

- The router's DHCP option hands the Shield's IP to every client as *the* DNS server.
- Allowed queries are forwarded to the configured upstreams (default Cloudflare `1.1.1.1` / `1.0.0.1`); blocked ones never leave the LAN.
- The dashboard is plain HTTP on port 80, advertised as `esp32-shield.local` via mDNS.

## 2. DNS pipeline

`main.cpp` (Team E) wires the pipeline. Every UDP datagram on port 53 goes through it:

```
UDP :53
  │
  ▼
parse_dns_query()            strict, bounds-checked; QDCOUNT must be 1, QCLASS IN
  │  └─ false → dropped, no response (see §9 open questions)
  ▼
DnsCache::lookup(qname, qtype)          ID bytes are zeroed on store,
  │  └─ hit → patch transaction ID,    patched on lookup
  │           reply immediately
  ▼  miss
RuleEngine::decide(qname)
  │
  ├─ BLOCK ──► build_block_response(block_mode, qtype) ──► reply
  │                 NULL_IP: A→0.0.0.0 / AAAA→::
  │                 NXDOMAIN: RCODE 3
  │                 NODATA: NOERROR, ANCOUNT 0
  │
  └─ ALLOW ──► DnsForwarder::forward() ──► DnsCache::store() ──► reply
                raw bytes, EDNS0/flags      TTL clamped to
                preserved, primary →        [60 s, 86400 s]
                secondary failover
  │
  ▼ (both paths)
StatsEngine::record_query() · DeviceTracker::note_query() · QueryLogger::log()
```

Notes for maintainers:

- **Ordering quirk (known): the cache is consulted *before* the rule engine.** If a domain was resolved and cached while allowed, then later added to the blocklist, the stale cached answer keeps being served until its TTL expires. Blocklist updates don't flush the cache in V1. Workarounds: wait out the TTL, or reboot (cache is RAM-only).
- **Blocked answers are never cached** — only upstream responses go into the cache.
- **TTL clamping rationale:** tiny TTLs (0–5 s, used by some trackers to defeat caches) are raised to 60 s so the cache actually helps; absurd TTLs (weeks) are capped at 24 h so entries go stale sanely.
- **UDP only in V1.** Queries and upstream forwarding are UDP. A truncated upstream reply (TC bit) is forwarded as-is; the client is expected to retry over TCP — which the Shield doesn't serve yet (see [ROADMAP](ROADMAP.md)).

## 3. Rule engine precedence

`RuleEngine::decide()` (portable core, Team A). All matching is **suffix-based** via `for_each_parent_domain()`: a query for `cdn.ads.example.com` is tested against `cdn.ads.example.com`, then `ads.example.com`, then `example.com`. One list entry therefore covers all subdomains.

```
decide("cdn.ads.example.com")
  │
  filtering_enabled == false? ──yes──► ALLOW   (master kill-switch)
  │ no
  ▼
  allowlist suffix match? ──yes──► ALLOW       (highest precedence:
  │ no                              user says "never block this")
  ▼
  custom rule suffix match? ──yes──► rule.block ? BLOCK : ALLOW
  │ no                               (longest suffix wins)
  ▼
  blocklist suffix walk? ──yes──► BLOCK        (hash → Bloom → flash verify)
  │ no
  ▼
  ALLOW
```

- The engine returns `BLOCK` or `ALLOW` only. `DnsDecision::NXDOMAIN` exists in the types, but in V1 the *response shape* for a blocked query is decided later by `BlockMode` — the engine doesn't pick it.
- `normalize_domain()` lowercases, trims whitespace, strips one trailing dot; empty/reject → `""`. **IDN/punycode is not handled in V1** (documented limitation): internationalized domains are matched as their raw ASCII form.

## 4. Blocklist A/B update flow

The blocklist lives in two on-flash slots; only one is active at a time. The updater **never writes to the active slot**, so a failed download, a corrupt parse, or a power cut can't take down filtering.

```
BlocklistUpdater::update_now()
  │
  ▼
download sources (HTTPS)          default: StevenBlack + someonewhocares
  │                               (see BLOCKLISTS.md)
  ▼
parse: hosts-format lines         normalize → lowercase, strip dot
       + plain domain lists       sort ascending
  │
  ▼
BlocklistFile::write_slot(INACTIVE, sorted_hashes)
  │   writes slot_b.bl if A active, else slot_a.bl
  ▼
validate()  — ALL must pass:
  │   1. entry count ≥ 1000
  │   2. doubleclick.net present   (known-bad spot check)
  │   3. google.com absent         (known-good spot check)
  │   4. magic "ESBL", version 1, count matches file size
  │   └─ any failure → abort, active slot untouched
  ▼
BlocklistManager::activate_slot(new)
  │   1. rebuild RAM Bloom from the NEW slot file
  │   2. set_active_slot(): atomic rename of active.txt temp file
  │   3. old slot file is KEPT — instant manual fallback
  ▼
done — queries now verify against the new slot
```

The active-slot switch is a single atomic file rename, so there is no window where queries see a half-written list. The Bloom rebuild happens *before* the switch, so the RAM filter and the active file are never out of sync.

## 5. Storage layout

LittleFS is mounted at `/littlefs` by System (Team E) before any filtering call. NVS holds config; the blocklist itself is **never** stored in NVS (it's far too big).

```
/littlefs/
├── blocklists/
│   ├── slot_a.bl        binary hash slot (see §7)
│   ├── slot_b.bl        binary hash slot
│   └── active.txt       "A" or "B"  (single byte + newline)
├── allowlist.json       {"domains":["example.com", ...]}
├── custom_rules.json    [{"domain":"x.com","action":"block","enabled":true,"id":3}, ...]
└── stats.json           persisted counters (flushed every stats_flush_min)

NVS namespace "shield"   (config keys — see §8)
OTA partitions           factory / ota_0 (+ ota_1 on 8 MB builds)  (see §10)
```

### Flash / LittleFS layout (`partitions.csv`, 4 MB flash)

| Partition | Offset | Size | Purpose |
|---|---|---|---|
| nvs | 0x9000 | 0x6000 (24 KB) | config namespace `shield` |
| phy_init | 0xf000 | 0x1000 | PHY calibration |
| factory | 0x10000 | 0x140000 (1.25 MB) | factory app |
| ota_0 | 0x150000 | 0x140000 (1.25 MB) | OTA slot (single — see note) |
| otadata | 0x290000 | 0x2000 | OTA state (required for `esp_https_ota`) |
| littlefs | 0x292000 | 0x16E000 (~1.44 MB) | blocklist slots, JSON configs, stats |

**Why one OTA slot:** the app binary is ~1.13 MB and the two default blocklist
sources yield ~73.7k unique domains = ~1.15 MB for A/B slots (measured).
3 app slots × 1.25 MB + A/B blocklists do not fit in 4 MB, so the 4 MB table
keeps a single OTA slot — OTA updates work, but there is **no rollback slot**.
`partitions-8mb.csv` (ESP32-S3, 8 MB flash) restores the full layout:
factory + ota_0 + ota_1 (1.5 MB each) with rollback + ~3.42 MB LittleFS.

**Slot sizing math:** one slot = 16-byte header + 8 bytes per entry.
73,680 entries → 589,456 B (~576 KB) per slot; two slots ≈ 1.15 MB, leaving
~290 KB in the 1.44 MB LittleFS partition for JSON files and FS overhead.

## 6. Module map

| Area | Directory | Owner | Owns |
|---|---|---|---|
| Portable core | `main/core/` | Team A | Pure C++17, **zero ESP-IDF includes**, host-testable: `domain_matcher` (normalize, suffix walk, FNV-1a), `bloom_filter`, `dns_codec` (strict parser, block-response builder), `rule_engine` (precedence), `dns_cache` (TTL-clamped response cache) |
| Network | `main/network/` | Team B | `dns_server` (UDP :53 + query-handler hook), `dns_forwarder` (raw-packet forward, EDNS0-preserving, primary→secondary failover), `wifi_manager` (STA vs provisioning AP), `mdns_advertise` (`<hostname>.local` + `_http._tcp`), captive portal (`GET /` setup page, `POST /setup`, DNS hijack to AP IP) |
| Filtering | `main/filtering/` | Team C | `blocklist_manager` (RAM Bloom + flash verify, suffix walk), `blocklist_updater` (download → parse → validate → A/B activate), `allowlist` (RAM set + JSON), `custom_rules` (longest-suffix match + JSON) |
| Storage | `main/storage/` | Team C | `blocklist_file` — the `ESBL` slot format, seek-only binary search, atomic active-slot swap |
| Web | `main/web/` | Team D | `esp_http_server` on :80, Bearer-token auth, REST `/api/*`, WebSocket `/ws` (2 s stats push), single-file dashboard embedded via `EMBED_FILES` |
| System | `main/system/` | Team E | `config_manager` (NVS `shield`, immediate commit), `stats_engine` (RAM counters → `stats.json`), `device_tracker` (32-slot per-IP table), `query_logger` (200-entry ring), `ota_manager` (HTTPS OTA + self-test rollback), `main.cpp` pipeline wiring, 10 s health monitor task |

Cross-cutting rules: everything lives in namespace `shield`; IDF code logs with `ESP_LOGx` and per-module TAGs; portable core never logs (returns status); portable core never `assert()`s on input.

## 7. Slot file format spec

`BlocklistFile` (`main/storage/blocklist_file.h`). Directory `/littlefs/blocklists/`, files `slot_a.bl`, `slot_b.bl`, `active.txt`.

```
offset  size  field
0       4     magic: ASCII "ESBL"
4       4     version: u32 little-endian = 1
8       8     count: u64 little-endian = N
16      8*N   N × u64 little-endian: FNV-1a-64 of NORMALIZED domains, SORTED ascending
```

- `contains(slot, hash)` binary-searches **without loading the file**: it seeks to the midpoint records and compares, so RAM use is O(1) regardless of list size. Two disk seeks per probe on average — fine at DNS rates.
- `write_slot()` writes the full sorted array; `read_count()` reads just the header.
- `set_active_slot()` writes a temp file then renames it over `active.txt` — atomic on LittleFS, so a crash mid-swap can't corrupt the pointer.
- Hashes are FNV-1a-64 of the *normalized* domain (lowercase, no trailing dot). The Bloom filter in RAM is built from these same hashes at boot/activation.

## 8. Config keys (NVS namespace `"shield"`)

Copied from CONTRACTS.md §3 — the contract is authoritative if this table ever drifts:

| Key | Type | Default | Notes |
|---|---|---|---|
| `wifi_ssid` | string | `""` | empty ⇒ first-boot provisioning AP |
| `wifi_pass` | string | `""` | |
| `device_name` | string | `esp32-shield` | used for mDNS + AP suffix |
| `upstream_primary` | string | `1.1.1.1` | IPv4 dotted |
| `upstream_secondary` | string | `1.0.0.1` | IPv4 dotted |
| `upstream_timeout_ms` | u32 | `2500` | per-upstream socket timeout |
| `filtering_enabled` | u8 | `1` | master kill-switch |
| `block_mode` | u8 | `0` | 0=NULL_IP, 1=NXDOMAIN, 2=NODATA |
| `update_interval_h` | u32 | `24` | blocklist auto-update cadence |
| `api_token` | string | _(generated)_ | 32 lowercase hex chars, created on first boot |
| `cache_entries` | u16 | `256` | DNS cache capacity |
| `stats_flush_min` | u8 | `5` | stats persist cadence |
| `mode` | string | `"dns"` | `"dns"` = router-DNS mode; `"travel"` = AP+STA portable mode (reboot to apply) |
| `ap_ssid` | string | `""` | travel AP SSID; empty ⇒ `Shield-XXXX` from MAC (reboot to apply) |
| `ap_pass` | string | _(generated)_ | travel AP WPA2 password; generated on first travel boot if empty; empty via API ⇒ regenerate on next boot |

Rules: setters commit immediately (`nvs_commit`); never store the blocklist in NVS. The API token is generated once and never changes unless NVS is erased — see [API.md](API.md#authentication).

## 9. RAM budget (classic ESP32, ~320 KB DRAM)

Computed honestly from the contract's data structures and capacities. "Typical" = expected at runtime; measure yours via the heap-watermark log the health monitor prints.

| Component | Typical | Worst case | Basis |
|---|---|---|---|
| Bloom filter (50k domains, 1% FP) | **~58.5 KiB** | same (fixed) | m = ⌈−(50000·ln 0.01)/(ln 2)²⌉ = 479,253 bits = 59,907 B; k = round((m/n)·ln2) = 7 probes |
| DNS cache (256 entries) | ~40–60 KB | unbounded ⚠️ | typical upstream response ~100–200 B + per-entry overhead; **no cap on stored response size in V1** — a flood of large EDNS0 responses could blow this. Recommend a store-size cap (open item for Team A/E). |
| Query log ring (200 entries) | **~27 KiB** | same (fixed) | `QueryLogEntry` = 4+4+128+2+1+1 = 140 B × 200 |
| Device table (32 slots) | **~2.6 KiB** | same (fixed) | `DeviceEntry` = 4+64+4·4 = 84 B × 32 |
| Stats + top-blocked counting | ~4 KiB | same (fixed) | fixed snapshot ~1 KB + 32-slot counting array (~2.7 KB); new domains past 32 slots are dropped, not stored |
| Allowlist + custom rules | ~1–5 KB | user-dependent | typical home use is dozens of entries |
| DNS server task + UDP buffers | ~8–12 KB | — | socket buffers + task stack |
| HTTP server (dashboard/API) | ~20–30 KB | — | workers + buffers; the HTML itself is served from flash, not RAM |
| LwIP + Wi-Fi driver | ~50–70 KB | — | the usual big-ticket items; tunable in menuconfig |
| FreeRTOS, NVS, app overhead | ~30–50 KB | — | task stacks, timers, misc |
| TLS (transient, OTA/update) | 0 idle | ~30–50 KB | only during HTTPS download |
| **Total steady-state** | **~250–300 KB** | — | fits the ~320 KB budget, but it's tight — hence the design below |

**The design decision this table justifies:** a naive blocklist (50k domain strings in RAM) would cost 1–2 MB — impossible. Storing 50k *hashes* (400 KB) is still too big. So the hot path keeps only the **~60 KB Bloom filter** in RAM (a negative answer is definitive — the domain is *definitely* not blocked), and Bloom positives are verified by **binary-searching the sorted hash file on flash** with O(1) RAM. False positives from the 1% FP rate just cost a couple of flash seeks and then resolve to ALLOW. That's the whole trick that makes a 50k-domain filter fit a classic ESP32.

On ESP32-S3 builds with 8 MB PSRAM this pressure disappears; the cache capacity (`cache_entries`) is the obvious knob to turn up first.

## 10. OTA with rollback

`OtaManager` (Team E) uses `esp_https_ota` against a URL supplied via `POST /api/ota`. After flashing and rebooting, the new firmware must **prove itself**: the app runs a self-test — a real DNS `A` query for `google.com` through the forwarder — and only calls `confirm_boot_ok()` (`esp_ota_mark_app_valid_cancel_rollback()`) if it succeeds **within 60 s**. If the self-test fails or the device crashes before confirming, the bootloader rolls back to the previous OTA slot on the next boot. Bad updates can't brick your DNS.

## 11. Improvements over the original proposal

The user's original architecture proposal got us started; the list below is what changed during design review, and it supersedes the proposal wherever they differ:

1. **mDNS (`esp32-shield.local`).** The dashboard and API are reachable by name — no more hunting for a DHCP-assigned IP. `_http._tcp` is advertised on port 80 alongside the hostname (from the `device_name` config key).
2. **LittleFS instead of SPIFFS.** Directories (`blocklists/`), crash-safe operation, and wear leveling — SPIFFS's flat namespace and fragility were wrong for A/B slot files.
3. **Bearer-token API auth.** Every protected route requires `Authorization: Bearer <api_token>`; the token is a 32-char hex secret auto-generated on first boot. The original proposal had no API auth story.
4. **Raw-packet forwarding preserving EDNS0.** The forwarder never parses or rebuilds queries — bytes go upstream untouched, so EDNS0 options, flags, and DO bit survive. Only *which* upstream is tried changes (primary → secondary on timeout/error).
5. **Upstream failover + health tracking.** The 10-second health monitor task checks upstream health and the forwarder fails over per query; Wi-Fi reconnects are handled in the same task.
6. **64-bit FNV-1a hashes + Bloom-in-RAM / flash-binary-search.** The original proposal kept the blocklist lookup vague; the final design keeps ~60 KB in RAM and seeks the sorted flash file for verification — the only way a 50k-domain list fits the classic ESP32 budget (§9).
7. **Captive-portal provisioning.** First boot = open AP `ESP32-Shield-XXXX` with DNS hijacked to the AP IP and a setup page at `GET /`; `POST /setup` writes credentials and reboots. No serial provisioning, no hardcoded secrets.
8. **UDP-only DNS in V1 (documented limitation).** TCP fallback for truncated/large responses is explicitly deferred — see [ROADMAP](ROADMAP.md).
9. **Configurable block modes.** `NULL_IP` (answer `0.0.0.0`/`::`, the default), `NXDOMAIN` (RCODE 3), and `NODATA` (NOERROR, zero answers) are all selectable via the `block_mode` key — the proposal had only the null-IP sinkhole.
10. **Travel mode (AP+STA).** The proposal's "Mode 3 — Access Point" was a sketch; it is now a full implementation — see §12.

## 12. Travel mode (portable plug-and-play AP)

For networks where you have **no router admin access** (hotels, cafés, a friend's house): the Shield becomes its own Wi-Fi network with ad blocking, needing only power and an upstream Wi-Fi to join. Select it with the `mode` key (`"dns"` = default router-DNS behavior, `"travel"` = this mode; changing it reboots).

```
                        Internet
                           │
                    ┌──────┴──────┐
                    │  Upstream   │  (hotel / café / home Wi-Fi)
                    │  Wi-Fi AP   │
                    └──────┬──────┘
                           │ STA (DHCP client)
                ┌──────────┴──────────┐
                │    ESP32 Shield     │
                │    (travel mode)    │
                │                     │
                │  AP "Shield-XXXX"   │◄──── Phone / Laptop join here
                │  192.168.4.1/24     │      (WPA2, DHCP + DNS = Shield IP)
                │  UDP :53, HTTP :80  │
                │  NAPT ──────────────┼──► internet via STA
                └─────────────────────┘
```

How it works:

- **Concurrent AP+STA** (`WIFI_MODE_APSTA`). STA joins the upstream network with the provisioned credentials (same NVS keys, same captive-portal flow — in travel mode the portal runs on the travel AP itself, so the SSID/password you joined with persist after the reboot and your clients stay connected).
- **The AP** is `Shield-XXXX` (`XXXX` = last two MAC bytes; overridable via `ap_ssid`), WPA2 with the `ap_pass` password. The password is auto-generated (12 unambiguous chars) on first travel boot, printed on the serial log, and shown/changed in the dashboard — never an unchangeable hardcoded default.
- **DHCP on the AP** (default pool `192.168.4.2`–`192.168.4.101`, 100 leases) advertises the AP IP (`192.168.4.1`) as the DNS server, so joining clients get filtered DNS with zero manual configuration. The DNS server binds all interfaces, so AP-side queries flow through the normal pipeline (cache → rule engine → forwarder).
- **NAPT** (`esp_netif_napt_enable()` on the STA netif, `CONFIG_LWIP_IPV4_NAPT=y`) routes AP clients to the internet through the STA uplink. It is enabled once the STA gets its IP and re-armed on reconnects.
- **Dashboard, REST, WebSocket, and mDNS** all bind all interfaces, so `http://192.168.4.1` and `http://esp32-shield.local` work from AP clients too.
- **Device tracking improves in travel mode:** the DHCP server's lease events (`IP_EVENT_AP_STAIPASSIGNED`) give us each client's MAC + assigned IP, recorded in the device table (visible as `mac` in `GET /api/devices`) — better than the IP-only tracking in dns mode. (DHCP hostnames are not captured; the `hostname` field stays empty for now.)
- **WPS push-button provisioning:** `POST /api/wps/start` (dashboard button too) starts a WPS-PBC enrollee session on the STA interface — press the router's WPS button within ~2 minutes and the credentials are saved + the device reboots. Only in travel mode, only while the STA is idle. Not all routers support WPS; the captive portal remains the fallback.

**Throughput honesty:** the ESP32's software NAT tops out at **tens of Mbps** in practice. That's plenty for browsing, video streaming, and hotel/café use — it is not a gigabit-router replacement. If you need full speed, use dns mode on your home router instead.
