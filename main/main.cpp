// ESP32 Network Shield — application entry point (Team E).
//
// Pipeline (CONTRACTS.md §7):
//   UDP :53 → parse (dns_codec) → cache lookup → rule_engine.decide()
//     → BLOCK: build_block_response(block_mode)            → stats/device/log
//     → ALLOW: forwarder → cache store (TTL from response) → stats/device/log
//
// In provisioning AP mode the Wi-Fi manager owns a hijack DNS server on :53,
// so the pipeline DnsServer is NOT started then.

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_littlefs.h"  // managed component joltwallet/littlefs (NOT esp_vfs_littlefs.h)

#include "core/types.h"
#include "core/dns_codec.h"
#include "core/domain_matcher.h"
#include "core/rule_engine.h"
#include "core/dns_cache.h"
#include "network/dns_server.h"
#include "network/dns_forwarder.h"
#include "network/wifi_manager.h"
#include "network/mdns_advertise.h"
#include "filtering/blocklist_manager.h"
#include "filtering/blocklist_updater.h"
#include "filtering/allowlist.h"
#include "filtering/custom_rules.h"
#include "web/http_server.h"
#include "web/api_handlers.h"  // register_dns_forwarder()
#include "system/config_manager.h"
#include "system/stats_engine.h"
#include "system/device_tracker.h"
#include "system/query_logger.h"
#include "system/ota_manager.h"

namespace {

constexpr const char* TAG = "shield_main";
// CONTRACTS.md §4: we accept up to 4096 bytes (EDNS0); Team B's DnsServer hands
// the handler a scratch response buffer of at least this size.
constexpr size_t kMaxDnsMsg = 4096;

// Pipeline objects with static lifetime: the query handler is a std::function
// capturing them, and app_main never returns, so references stay valid.
shield::RuleEngine g_engine;
shield::DnsForwarder g_forwarder;
shield::DnsServer g_server;
shield::DnsCache* g_cache = nullptr;  // capacity comes from NVS at boot

uint32_t uptime_s() {
  return static_cast<uint32_t>((xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000);
}

// Provisioning AP mode ⇔ no Wi-Fi credentials stored. In that mode
// WifiManager runs its own hijack DNS on :53, so main must not bind :53.
// (Team B: please expose this as WifiManager::provisioning_active(); this
// helper derives it from the same NVS keys wifi_manager.init() reads.)
bool in_provisioning_mode() {
  char ssid[64] = {0};
  shield::ConfigManager::instance().get_str("wifi_ssid", ssid, sizeof(ssid));
  return ssid[0] == '\0';
}

// Minimal TTL parse: first answer RR's TTL field, network byte order.
// DnsCache::store clamps to [60, 86400] anyway; this just feeds it a sane value.
uint32_t dns_ttl_from_response(const uint8_t* resp, size_t len) {
  constexpr uint32_t kDefaultTtl = 300;
  if (resp == nullptr || len < 12) return kDefaultTtl;
  const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
  if (ancount == 0) return kDefaultTtl;

  // Skip the question section: labels, then QTYPE/QCLASS.
  size_t off = 12;
  for (int guard = 0; guard < 128 && off < len; ++guard) {
    const uint8_t l = resp[off];
    if (l == 0) { ++off; break; }
    if ((l & 0xC0) == 0xC0) { off += 2; break; }  // (shouldn't appear in QNAME)
    off += 1u + l;
  }
  if (off + 4 > len) return kDefaultTtl;
  off += 4;  // QTYPE + QCLASS

  // First answer RR: NAME (labels or pointer), TYPE, CLASS, TTL, RDLENGTH.
  if (off >= len) return kDefaultTtl;
  if ((resp[off] & 0xC0) == 0xC0) {
    off += 2;  // compressed name pointer
  } else {
    for (int guard = 0; guard < 128 && off < len; ++guard) {
      const uint8_t l = resp[off];
      if (l == 0) { ++off; break; }
      if ((l & 0xC0) == 0xC0) { off += 2; break; }
      off += 1u + l;
    }
  }
  if (off + 10 > len) return kDefaultTtl;
  const uint32_t ttl = (static_cast<uint32_t>(resp[off + 4]) << 24) |
                       (static_cast<uint32_t>(resp[off + 5]) << 16) |
                       (static_cast<uint32_t>(resp[off + 6]) << 8) |
                       static_cast<uint32_t>(resp[off + 7]);
  return ttl == 0 ? 60 : ttl;
}

void record_pipeline_result(const std::string& domain, uint16_t qtype,
                            uint32_t client_ip, shield::DnsDecision decision,
                            bool cached) {
  shield::StatsEngine::instance().record_query(domain, decision, cached);
  shield::DeviceTracker::instance().note_query(
      client_ip, decision == shield::DnsDecision::BLOCK);
  shield::QueryLogEntry e = {};
  e.ts_s = uptime_s();
  e.client_ip = client_ip;
  strncpy(e.domain, domain.c_str(), sizeof(e.domain) - 1);
  e.qtype = qtype;
  e.decision = decision;
  e.cached = cached;
  shield::QueryLogger::instance().log(e);
}

bool dns_pipeline_handler(const uint8_t* req, size_t req_len, uint32_t client_ip,
                          uint8_t* resp, size_t* resp_len) {
  using namespace shield;

  // 1. Parse (strict; QDCOUNT==1, QCLASS==IN, no truncation/pointer loops).
  uint16_t query_id = 0;
  DnsQuestion q;
  if (!parse_dns_query(req, req_len, &query_id, &q)) return false;

  // 2. Normalize.
  const std::string norm = normalize_domain(q.qname_raw);
  if (norm.empty()) return false;

  // 3. Cache lookup (hit: ID patched by the cache, response ready).
  std::vector<uint8_t> cached;
  if (g_cache->lookup(norm, q.qtype, query_id, cached)) {
    if (cached.size() > kMaxDnsMsg) return false;
    memcpy(resp, cached.data(), cached.size());
    *resp_len = cached.size();
    record_pipeline_result(norm, q.qtype, client_ip, DnsDecision::ALLOW, true);
    return true;
  }

  // 4. Rule engine.
  const DnsDecision decision = g_engine.decide(norm);
  if (decision == DnsDecision::BLOCK) {
    uint8_t mode_u8 = 0;  // BlockMode::NULL_IP default
    ConfigManager::instance().get_u8("block_mode", &mode_u8);
    const size_t n = build_block_response(req, req_len,
                                          static_cast<BlockMode>(mode_u8),
                                          q.qtype, resp, kMaxDnsMsg);
    if (n == 0) return false;
    *resp_len = n;
    record_pipeline_result(norm, q.qtype, client_ip, DnsDecision::BLOCK, false);
    return true;
  }

  // 5. Forward upstream (raw packet, primary → secondary failover inside).
  uint32_t rtt_ms = 0;
  if (!g_forwarder.forward(req, req_len, resp, resp_len, &rtt_ms)) {
    ESP_LOGW(TAG, "upstream forward failed for %s (client times out)",
             norm.c_str());
    return false;  // no response: client times out; logged above
  }

  // 6. Cache the upstream answer with its own TTL, then reply verbatim.
  g_cache->store(norm, q.qtype, resp, *resp_len,
                 dns_ttl_from_response(resp, *resp_len));
  record_pipeline_result(norm, q.qtype, client_ip, DnsDecision::ALLOW, false);
  return true;
}

void self_test_task(void* arg) {
  (void)arg;
  // Rollback guard: mark the app valid ONLY if the self-test passes.
  if (shield::OtaManager::instance().self_test_dns()) {
    shield::OtaManager::instance().confirm_boot_ok();
  } else {
    ESP_LOGE(TAG, "self-test FAILED: app stays unconfirmed, bootloader will "
                  "roll back to the previous image on next reset");
  }
  vTaskDelete(nullptr);
}

void health_monitor_task(void* arg) {
  (void)arg;
  bool self_test_started = false;
  int cycle = 0;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(10000));  // 10 s cadence
    ++cycle;
    const bool provisioning = in_provisioning_mode();

    // Wi-Fi reconnect if STA link dropped (but never during a WPS session —
    // esp_wifi_connect() would fight the WPS handshake).
    if (!provisioning && !shield::WifiManager::instance().is_connected() &&
        !shield::WifiManager::instance().wps_active()) {
      ESP_LOGW(TAG, "Wi-Fi link lost; attempting reconnect");
      // Team B may add WifiManager::reconnect(); esp_wifi_connect() reuses
      // the STA config already applied by wifi_manager.init().
      esp_wifi_connect();
    }

    // Upstream health re-check via the forwarder (every ~60 s).
    if (!provisioning && cycle % 6 == 0) {
      if (shield::OtaManager::instance().self_test_dns()) {
        ESP_LOGI(TAG, "upstream health OK");
      } else {
        ESP_LOGW(TAG, "upstream health check failed");
      }
    }

    shield::StatsEngine::instance().loop();  // stats flush when due

    ESP_LOGI(TAG, "heap free=%lu min_free=%lu",
             static_cast<unsigned long>(esp_get_free_heap_size()),
             static_cast<unsigned long>(esp_get_minimum_free_heap_size()));

    // OTA anti-brick: confirm once, at 30 s uptime, in its own task.
    // Skipped in provisioning mode: there is no STA uplink, so the DNS
    // self-test would fail spuriously (and factory images don't need the
    // pending-verify confirmation anyway).
    if (!self_test_started && !provisioning && uptime_s() >= 30) {
      self_test_started = true;
      xTaskCreate(self_test_task, "selftest", 6144, nullptr, 5, nullptr);
    }
  }
}

}  // namespace

extern "C" void app_main(void) {
  using namespace shield;
  ESP_LOGI(TAG, "ESP32 Network Shield firmware %s booting", FIRMWARE_VERSION);

  // 1. NVS + configuration (also generates api_token on first boot).
  if (!ConfigManager::instance().init()) {
    ESP_LOGE(TAG, "config init failed; continuing degraded");
  }

  // 2. LittleFS at /littlefs (filtering/storage depend on it).
  esp_vfs_littlefs_conf_t lfs = {};
  lfs.base_path = "/littlefs";
  lfs.partition_label = "littlefs";
  lfs.format_if_mount_failed = true;
  if (esp_vfs_littlefs_register(&lfs) != ESP_OK) {
    // Degraded: blocklist/allowlist/stats persist unavailable, RAM path continues.
    ESP_LOGE(TAG, "LittleFS mount failed; continuing degraded (no persistence)");
  } else {
    size_t total = 0, used = 0;
    esp_littlefs_info("littlefs", &total, &used);
    ESP_LOGI(TAG, "LittleFS mounted: total=%u used=%u", (unsigned)total,
             (unsigned)used);
  }

  // 3. Filtering + system singletons.
  BlocklistManager::instance().init();
  Allowlist::instance().init();
  CustomRules::instance().init();
  uint8_t flush_min = 5;
  ConfigManager::instance().get_u8("stats_flush_min", &flush_min);
  StatsEngine::instance().init(flush_min);
  // DeviceTracker and QueryLogger are pure-RAM; no init needed.

  // 4. Rule engine: allowlist (suffix) > custom rules (suffix) > blocklist.
  {
    std::unordered_set<std::string> allow;
    for (const auto& d : Allowlist::instance().list()) allow.insert(d);
    g_engine.set_allowlist(std::move(allow));

    std::unordered_map<std::string, bool> rules;
    for (const auto& r : CustomRules::instance().list()) {
      if (r.enabled) rules[r.domain] = r.block;
    }
    g_engine.set_custom_rules(std::move(rules));

    g_engine.set_blocklist_lookup(
        [](const std::string& norm) { return BlocklistManager::instance().is_blocked(norm); });

    uint8_t filtering_enabled = 1;
    ConfigManager::instance().get_u8("filtering_enabled", &filtering_enabled);
    g_engine.set_enabled(filtering_enabled != 0);
  }

  // 5. DNS cache (capacity from NVS; millisecond clock from esp_timer).
  // app_main never returns, so a heap object with static lifetime is safe.
  uint16_t cache_entries = 256;
  ConfigManager::instance().get_u16("cache_entries", &cache_entries);
  g_cache = new DnsCache(cache_entries, []() -> uint32_t {
    return static_cast<uint32_t>(esp_timer_get_time() / 1000);
  });

  // Initialize TCP/IP stack and event loop before any network sockets are created.
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  // 6. Wi-Fi (STA if credentials exist, else provisioning AP + captive portal).
  WifiManager::instance().init();

  // 7. Upstream forwarder.
  char primary[32] = "1.1.1.1", secondary[32] = "1.0.0.1";
  uint32_t timeout_ms = 2500;
  ConfigManager::instance().get_str("upstream_primary", primary, sizeof(primary));
  ConfigManager::instance().get_str("upstream_secondary", secondary, sizeof(secondary));
  ConfigManager::instance().get_u32("upstream_timeout_ms", &timeout_ms);
  g_forwarder.init(primary, secondary, timeout_ms);
  // Lets PUT /api/config push new upstreams live without a reboot.
  register_dns_forwarder(&g_forwarder);
  // Blocklist sources: the updater's constructor already carries the default
  // URLs (single source of truth); re-asserted here so boot logs show them.
  BlocklistUpdater::instance().set_sources({
      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
      "https://someonewhocares.org/hosts/zero/hosts",
  });

  // 8. DNS server — skipped in provisioning mode (AP hijack owns :53).
  g_server.set_query_handler(dns_pipeline_handler);
  if (in_provisioning_mode()) {
    ESP_LOGI(TAG, "provisioning mode: AP hijack DNS owns :53; pipeline server not started");
  } else if (!g_server.start(53)) {
    ESP_LOGE(TAG, "DNS server failed to start on :53");
  }

  // 9. mDNS + web dashboard.
  // In provisioning mode the captive portal already owns port 80, so the
  // main dashboard server is skipped there (the portal serves / and /setup).
  char device_name[64] = "esp32-shield";
  ConfigManager::instance().get_str("device_name", device_name, sizeof(device_name));
  mdns_advertise::start(device_name);
  if (in_provisioning_mode()) {
    ESP_LOGI(TAG, "provisioning mode: captive portal owns :80; dashboard not started");
  } else {
    HttpServer::instance().start();  // Team D: web/http_server.h, port 80
  }

  // 10. Health monitor (10 s): reconnect, upstream health, stats flush,
  // heap watermark, one-shot OTA self-test confirm at 30 s uptime.
  xTaskCreate(health_monitor_task, "health", 4096, nullptr, 5, nullptr);

  ESP_LOGI(TAG, "boot complete");
}
