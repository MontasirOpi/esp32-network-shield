# ESP32 Network Shield — Module Contracts

All implementers MUST follow this file. It defines shared types, naming, error
conventions, config keys, file formats, and inter-module interfaces so modules
written in parallel fit together without rework.

Target: ESP-IDF v5.1+, C++17, no Arduino. Classic ESP32 RAM budget (~320 KB DRAM).

## 1. Naming & layout

- Namespace: `shield` for everything.
- Files: `snake_case.h` / `snake_case.cpp`. Classes: `CamelCase`. Methods: `snake_case`.
- Portable core (`main/core/`): pure C++17, **zero** ESP-IDF includes. Must compile
  with `g++ -std=c++17` on Linux for host tests.
- IDF modules (`main/network/`, `main/filtering/`, `main/storage/`, `main/web/`,
  `main/system/`): may use ESP-IDF v5 APIs only. No `tcpip_adapter` (v4 API),
  no SPIFFS-as-default (use LittleFS).
- Logging: IDF code uses `ESP_LOGx` with per-module TAG. Portable core is silent
  (returns status; no logging dependency).

## 2. Shared types — `main/core/types.h` (pure C++17)

```cpp
namespace shield {

enum class DnsDecision : uint8_t { ALLOW = 0, BLOCK = 1, NXDOMAIN = 2 };
// NOTE: DnsDecision::BLOCK means "blocked"; HOW to answer is BlockMode.

enum class BlockMode : uint8_t {
  NULL_IP  = 0,  // answer A=0.0.0.0 / AAAA=::   (default)
  NXDOMAIN = 1,  // RCODE 3
  NODATA   = 2,  // NOERROR, ANCOUNT 0
};

struct DnsQuestionInfo {
  char     qname[256];   // normalized, no trailing dot, lowercased
  uint16_t qtype;        // e.g. 1=A, 28=AAAA
  uint16_t qclass;       // normally 1 (IN)
  uint32_t client_ip;    // IPv4, network byte order
};

struct StatsSnapshot {
  uint32_t total_queries   = 0;
  uint32_t blocked_queries = 0;
  uint32_t cache_hits      = 0;
  uint32_t upstream_queries= 0;
  uint32_t uptime_s        = 0;
  // top-N blocked domains, fixed size to avoid heap churn on device
  static constexpr int kMaxTop = 10;
  struct Entry { char domain[64]; uint32_t count; };
  Entry top_blocked[kMaxTop];
  int   top_blocked_count = 0;
};

struct DeviceEntry {
  uint32_t ip;                 // network byte order
  char     hostname[64];       // may be empty
  uint32_t queries   = 0;
  uint32_t blocked   = 0;
  uint32_t first_seen_s = 0;   // seconds since boot
  uint32_t last_seen_s  = 0;
};

struct QueryLogEntry {
  uint32_t    ts_s;            // seconds since boot
  uint32_t    client_ip;       // network byte order
  char        domain[128];     // normalized
  uint16_t    qtype;
  DnsDecision decision;
  bool        cached;
};

}  // namespace shield
```

## 3. Config — NVS namespace `"shield"` (`main/system/config_manager.h`)

| Key                   | Type   | Default        | Notes                              |
|-----------------------|--------|----------------|------------------------------------|
| `wifi_ssid`           | string | `""`           | empty ⇒ first-boot provisioning AP |
| `wifi_pass`           | string | `""`           |                                    |
| `device_name`         | string | `esp32-shield` | used for mDNS + AP suffix          |
| `upstream_primary`    | string | `1.1.1.1`      | IPv4 dotted                        |
| `upstream_secondary`  | string | `1.0.0.1`      | IPv4 dotted                        |
| `upstream_timeout_ms` | u32    | `2500`         | per-upstream socket timeout        |
| `filtering_enabled`   | u8     | `1`            | master kill-switch                 |
| `block_mode`          | u8     | `0`            | maps to BlockMode                  |
| `update_interval_h`   | u32    | `24`           | blocklist auto-update cadence      |
| `api_token`           | string | _(generated)_  | 32 lowercase hex chars, first boot |
| `cache_entries`       | u16    | `256`          | DNS cache capacity                 |
| `stats_flush_min`     | u8     | `5`            | stats persist cadence              |

`ConfigManager` API (singleton):

```cpp
class ConfigManager {
 public:
  static ConfigManager& instance();
  bool init();  // nvs_flash_init + open namespace; generates api_token if missing
  bool get_str(const char* key, char* out, size_t out_len) const;
  bool set_str(const char* key, const char* value);   // commits
  bool get_u32(const char* key, uint32_t* out) const;
  bool set_u32(const char* key, uint32_t value);
  bool get_u8(const char* key, uint8_t* out) const;
  bool set_u8(const char* key, uint8_t value);
  bool get_u16(const char* key, uint16_t* out) const;
  bool set_u16(const char* key, uint16_t value);
};
```

Rules: setters commit immediately (`nvs_commit`). Never store the blocklist in NVS.

## 4. Portable core API (`main/core/`) — implemented by Team A

### `domain_matcher.h`
```cpp
std::string normalize_domain(const std::string& raw);
// lowercase, trim whitespace, strip ONE trailing dot, reject empties → "".
// IDN/punycode: NOT handled in V1 (documented limitation).

// Calls fn(suffix) for "cdn.ads.example.com" → "cdn.ads.example.com",
// "ads.example.com", "example.com". Stops early if fn returns false.
template <typename Fn> void for_each_parent_domain(const std::string& normalized, Fn&& fn);

uint64_t fnv1a_64(const std::string& s);  // hash of NORMALIZED domain
```

### `bloom_filter.h`
```cpp
class BloomFilter {
 public:
  // Sizes bit array for expected_items at false-positive rate fp_rate.
  // m = ceil(-(n*ln p)/(ln2)^2), k = round((m/n)*ln2), k clamped [1,16].
  BloomFilter(size_t expected_items = 50000, double fp_rate = 0.01);
  void add(uint64_t hash);
  bool possibly_contains(uint64_t hash) const;  // false ⇒ DEFINITELY absent
  void clear();
  size_t bit_count() const;
};
```
Hash derivation: FNV-1a 64 of the 8-byte hash mixed with splitmix64-style
 avalanche for the i-th probe (double hashing). Document the math in comments.

### `dns_codec.h`
```cpp
struct DnsQuestion { std::string qname_raw; uint16_t qtype; uint16_t qclass; };

// Strict, bounds-checked. Requires QDCOUNT==1, QCLASS==IN.
// Returns false on any truncation, compression-loop, or QDCOUNT!=1.
bool parse_dns_query(const uint8_t* buf, size_t len, uint16_t* id_out, DnsQuestion* q_out);

// Build a response that copies ID + question section verbatim from the request.
// qtype decides the answer shape for NULL_IP (A→0.0.0.0, AAAA→::).
// Returns bytes written, 0 on output-buffer overflow.
size_t build_block_response(const uint8_t* req, size_t req_len, BlockMode mode,
                            uint16_t qtype, uint8_t* out, size_t out_cap);
```
Max DNS/UDP message: 512 bytes classic (we accept up to 4096 for EDNS0 but never
generate >512 ourselves).

### `rule_engine.h`
```cpp
class RuleEngine {
 public:
  using BlocklistLookup = std::function<bool(const std::string& normalized_domain)>;
  void set_allowlist(std::unordered_set<std::string> domains);  // normalized expected
  void set_custom_rules(std::unordered_map<std::string, bool> domain_to_block);
  void set_blocklist_lookup(BlocklistLookup fn);
  void set_enabled(bool enabled);   // false ⇒ everything ALLOWs
  // Precedence: allowlist (suffix) > custom rule (suffix) > blocklist (suffix).
  // Returns DnsDecision::BLOCK or ::ALLOW (NXDOMAIN decided by BlockMode later).
  DnsDecision decide(const std::string& raw_qname) const;
};
```

### `dns_cache.h`
```cpp
class DnsCache {
 public:
  using NowMs = std::function<uint32_t()>;  // injected; host tests use fake clock
  explicit DnsCache(size_t capacity = 256, NowMs now = nullptr);
  // Stores raw response bytes; TTL clamped to [60, 86400]s; ID bytes zeroed on store.
  void store(const std::string& normalized_qname, uint16_t qtype,
             const uint8_t* resp, size_t resp_len, uint32_t ttl_s);
  // On hit: copies bytes, patches transaction ID, returns true.
  bool lookup(const std::string& normalized_qname, uint16_t qtype, uint16_t query_id,
              std::vector<uint8_t>& out);
  void clear();
  size_t size() const;
};
```

## 5. Network API (`main/network/`) — Team B

```cpp
// dns_server.h
class DnsServer {
 public:
  // Return true if the handler produced a response (resp_len set).
  using QueryHandler = std::function<bool(const uint8_t* req, size_t req_len,
                                          uint32_t client_ip /* net order */,
                                          uint8_t* resp, size_t* resp_len)>;
  bool start(uint16_t port = 53);
  void stop();
  void set_query_handler(QueryHandler h);
};

// dns_forwarder.h
class DnsForwarder {
 public:
  bool init(const char* primary_ip, const char* secondary_ip, uint32_t timeout_ms);
  // Raw packet forward: preserves EDNS0/flags; tries primary, fails over to
  // secondary on timeout/error. Never modifies the query.
  bool forward(const uint8_t* req, size_t req_len,
               uint8_t* resp, size_t* resp_len, uint32_t* rtt_ms_out);
  void set_upstreams(const char* primary_ip, const char* secondary_ip, uint32_t timeout_ms);
};

// wifi_manager.h
class WifiManager {
 public:
  static WifiManager& instance();
  // STA if creds in NVS, else provisioning AP "ESP32-Shield-XXXX" (+captive portal).
  bool init();          // reads ConfigManager, starts STA or AP-provisioning
  bool is_connected() const;
  bool get_ip(char* out, size_t len) const;   // dotted quad of STA/AP interface
  int8_t rssi() const;
};

// mdns_advertise.h
namespace mdns_advertise {
bool start(const char* hostname);  // "<hostname>.local" + _http._tcp on port 80
}
```

Captive portal (provisioning AP mode): DNS server hijacks ALL queries to the
AP IP; HTTP `GET /` serves setup page; `POST /setup` saves `wifi_ssid`/`wifi_pass`
/`device_name` to NVS and reboots. Owned by Team B (reuse `DnsServer` +
a minimal `esp_http_server` instance on the AP interface).

## 6. Filtering & storage (`main/filtering/`, `main/storage/`) — Team C

LittleFS is mounted at `/littlefs` by System (Team E) before any filtering call.

### Slot file format — `main/storage/blocklist_file.h`
Directory `/littlefs/blocklists/`. Files `slot_a.bl`, `slot_b.bl`, `active.txt`
(`active.txt` contains `A` or `B`).

```
offset 0:  magic "ESBL" (4 bytes)
offset 4:  version u32 LE = 1
offset 8:  count u64 LE = N
offset 16: N × u64 LE, FNV-1a 64 of NORMALIZED domains, SORTED ascending
```
API:
```cpp
class BlocklistFile {
 public:
  static bool write_slot(char slot /*'A' or 'B'*/, const std::vector<uint64_t>& sorted_hashes);
  static bool read_count(char slot, uint64_t* count_out);
  // Binary search WITHOUT loading the file: seeks only. Returns true if found.
  static bool contains(char slot, uint64_t hash);
  static char active_slot();            // 'A'/'B' from active.txt, default 'A'
  static bool set_active_slot(char slot);  // atomic via rename of temp file
};
```

### `filtering/blocklist_manager.h`
```cpp
class BlocklistManager {
 public:
  static BlocklistManager& instance();
  bool init();  // builds RAM Bloom from ACTIVE slot file; count=0 if none
  // Exact check: Bloom negative ⇒ false fast; Bloom positive ⇒ binary-search flash.
  bool is_blocked(const std::string& normalized_domain);  // does suffix walk internally
  uint64_t entry_count() const;
  size_t   bloom_bits() const;
  // Called by updater after a validated slot file is written:
  bool activate_slot(char slot);  // set_active_slot + rebuild Bloom; old slot file kept
};
```
Suffix walk lives in the manager: for each parent suffix, hash → bloom → verify.

### `filtering/blocklist_updater.h`
```cpp
struct UpdateResult { bool ok; uint64_t entries; char message[128]; };
class BlocklistUpdater {
 public:
  static BlocklistUpdater& instance();
  // Downloads sources, parses hosts-format + plain-domain lists, normalizes,
  // sorts, writes to INACTIVE slot, validates, then atomically activates.
  // NEVER touches the active slot file. Returns detailed result.
  UpdateResult update_now();
  void set_sources(const std::vector<std::string>& urls);
};
```
Validation (all must pass before activation): entry count ≥ 1000; spot-check
`doubleclick.net` present; spot-check `google.com` absent; file magic/count sane.
Default sources (documented in docs/BLOCKLISTS.md):
- `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
- `https://someonewhocares.org/hosts/zero/hosts`

### Allowlist & custom rules
- `/littlefs/allowlist.json`: `{"domains":["example.com", ...]}` (normalized on load)
- `/littlefs/custom_rules.json`: `[{"domain":"x.com","action":"block","enabled":true,"id":3}]`
```cpp
// filtering/allowlist.h — RAM unordered_set, persisted to JSON
class Allowlist {
 public:
  static Allowlist& instance();
  bool init();  // loads JSON (missing file ⇒ empty)
  bool contains(const std::string& normalized_domain) const;  // suffix walk
  bool add(const std::string& domain);     // normalizes, persists
  bool remove(const std::string& domain);  // persists
  std::vector<std::string> list() const;
};
// filtering/custom_rules.h
struct CustomRule { uint32_t id; std::string domain; bool block; bool enabled; };
class CustomRules {
 public:
  static CustomRules& instance();
  bool init();
  uint32_t add(const std::string& domain, bool block);  // returns id, persists
  bool remove(uint32_t id);                             // persists
  // Longest-suffix match; returns true if a rule matched (out_block set).
  bool match(const std::string& normalized_domain, bool* out_block) const;
  std::vector<CustomRule> list() const;
};
```

## 7. System (`main/system/`) — Team E

```cpp
// stats_engine.h — RAM counters; persist to /littlefs/stats.json every N min.
class StatsEngine {
 public:
  static StatsEngine& instance();
  void init(uint8_t flush_interval_min);
  void record_query(const std::string& domain, DnsDecision d, bool cache_hit);
  void snapshot(StatsSnapshot* out);   // top_blocked computed from fixed array
  void loop();  // call from monitor task: flushes to flash when due
};

// device_tracker.h — 32-slot table keyed by source IP
class DeviceTracker {
 public:
  static DeviceTracker& instance();
  void note_query(uint32_t ip_net_order, bool blocked);
  void set_hostname(uint32_t ip_net_order, const char* hostname);
  void get_devices(std::vector<DeviceEntry>& out);
};

// query_logger.h — RAM ring buffer, 200 entries
class QueryLogger {
 public:
  static QueryLogger& instance();
  void log(const QueryLogEntry& e);
  void get_entries(std::vector<QueryLogEntry>& out, size_t max_n);
};

// ota_manager.h
class OtaManager {
 public:
  static OtaManager& instance();
  // esp_https_ota; after reboot, app marks itself valid ONLY if a self-test
  // DNS query (A google.com via forwarder) succeeds within 60 s, else rollback.
  bool begin(const char* url);
  void confirm_boot_ok();  // called by self-test; esp_ota_mark_app_valid
};
```

`main.cpp` wires the pipeline (Team E owns):
```
UDP :53 → parse (dns_codec) → cache lookup → rule_engine.decide()
  → BLOCK: build_block_response(block_mode)   → stats/device/log
  → ALLOW: cache? no → forwarder → cache store → stats/device/log
```
Health monitor task (10 s): Wi-Fi reconnect if lost, upstream health check,
stats flush, heap watermark log.

## 8. Web (`main/web/`) — Team D

- `esp_http_server` on port 80. Bearer auth: `Authorization: Bearer <api_token>`.
  Public (no token): `GET /api/status`, `GET /setup*` (provisioning), `/` redirect.
  Token wrong/missing on protected routes ⇒ `401 {"error":"unauthorized"}`.
- WebSocket `/ws`: every 2 s push
  `{"type":"stats","ts":1699999999,"total":42391,"blocked":11204,
    "block_rate":26.4,"cache_hit_rate":61.2,"devices":8}`.
- REST (JSON; exact shapes in docs/API.md):
  - `GET /api/status` → device, version (`FIRMWARE_VERSION`), uptime, wifi, filtering, blocklist meta, upstream
  - `GET /api/stats` → StatsSnapshot as JSON + rates
  - `GET /api/devices` → array of DeviceEntry
  - `GET /api/queries?limit=50` → newest-first QueryLogEntry array
  - `GET /api/config` / `PUT /api/config` (JSON keys = NVS keys table §3; PUT validates ranges)
  - `GET /api/blocklist` → `{active_slot, entries, updated_at, sources[]}`
  - `POST /api/blocklist/update` → `{status:"started"}` (async task)
  - `GET /api/allowlist`, `POST /api/allowlist` `{domains:[...]}` / `{domain:"..."}`
  - `DELETE /api/allowlist?domain=x` (extra; document it)
  - `GET /api/rules`, `POST /api/rules` `{domain, action:"block"|"allow"}`, `DELETE /api/rules/:id`
  - `POST /api/reboot`, `POST /api/ota` `{"url":"https://..."}`
- Dashboard: single-file `main/web_dashboard/index.html`, embedded via
  `EMBED_FILES` in `main/CMakeLists.txt`, served at `/`. Must include: status
  card, counters (devices/queries/blocked/allowed/block rate), top blocked
  table, live query log (WebSocket), config form (upstream DNS, block mode,
  toggles), blocklist update button, token prompt stored in `localStorage`.

## 9. Project files — Team E

- `CMakeLists.txt` (root): `cmake_minimum_required(VERSION 3.16)`,
  `include($ENV{IDF_PATH}/tools/cmake/project.cmake)`, `project(esp32-network-shield)`.
- `main/CMakeLists.txt`: `idf_component_register(SRCS <every .cpp> INCLUDE_DIRS "." PRIV_REQUIRES nvs_flash esp_wifi esp_netif esp_http_server esp_https_ota app_update esp_timer mdns littlefs EMBED_FILES web_dashboard/index.html)`.
- `main/idf_component.yml`: `dependencies: { joltwallet/littlefs: "^1.20.0" }`.
- `sdkconfig.defaults`: `CONFIG_IDF_TARGET="esp32"` (+ note for esp32s3),
  custom partition table from `partitions.csv`, `CONFIG_COMPILER_CXX_STANDARD_GNUCXX17=y`.
- `partitions.csv` (4 MB flash, default): `nvs 0x9000 0x6000; phy_init 0xf000
  0x1000; factory 0x10000 0x140000; ota_0 0x150000 0x140000;
  otadata 0x290000 0x2000; littlefs 0x292000 0x16E000` (ends exactly at
  0x400000; app partitions are 64 KB-aligned).
  ONE OTA slot on 4 MB: 3 app slots x 1.25 MB + A/B blocklist slots
  (~1.15 MB for ~73.7k default-source domains, measured) do not fit in 4 MB,
  so OTA updates work but without a rollback slot. `partitions-8mb.csv`
  (ESP32-S3) restores factory + ota_0 + ota_1 with full rollback.
- `FIRMWARE_VERSION`: define in `main/CMakeLists.txt` via
  `target_compile_definitions(${COMPONENT_LIB} PRIVATE FIRMWARE_VERSION="0.4.0")`
  (we ship V0.4 feature level: DNS+blocking+cache+dashboard+updater basic).
- `.gitignore`: `build/`, `sdkconfig`, `sdkconfig.old`, `dependencies.lock`,
  `.vscode/`, `__pycache__/`.

## 10. Error & testing conventions

- Portable core: return `bool` / value types; never `assert` on input (tests feed garbage).
- Host tests (`tests/host/`, Team A): self-contained mini-framework, no external
  deps, `run_tests.sh` builds with `g++ -std=c++17 -I../../../main` and runs.
  Must PASS in this Linux VM — the coordinator runs them.
- Every tricky bit gets a comment: DNS label-pointer loops, Bloom sizing math,
  A/B slot swap atomicity, TTL clamping rationale.
