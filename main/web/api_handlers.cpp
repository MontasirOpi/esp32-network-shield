// REST + WebSocket route handlers. JSON shapes follow CONTRACTS.md §8.
// Auth: every handler except handle_root and api_get_status calls
// require_auth() (→ 401 {"error":"unauthorized"} on failure).

#include "api_handlers.h"

#include "http_server.h"

#include <cJSON.h>

#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <sys/stat.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../core/types.h"
#include "../filtering/allowlist.h"
#include "../filtering/blocklist_manager.h"
#include "../filtering/blocklist_updater.h"
#include "../filtering/custom_rules.h"
#include "../network/wifi_manager.h"
#include "../storage/blocklist_file.h"
#include "../system/config_manager.h"
#include "../system/device_tracker.h"
#include "../system/ota_manager.h"
#include "../system/query_logger.h"
#include "../system/stats_engine.h"

#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "0.5.0"
#endif

namespace shield {

namespace {

constexpr const char* TAG = "webapi";

// Documented default blocklist sources (docs/BLOCKLISTS.md). Shown by
// GET /api/blocklist; main.cpp should configure the same URLs on
// BlocklistUpdater via set_sources().
constexpr const char* kBlocklistSources[] = {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
};
constexpr size_t kBlocklistSourceCount =
    sizeof(kBlocklistSources) / sizeof(kBlocklistSources[0]);

// Set by main.cpp via register_dns_forwarder() so PUT /api/config can apply
// upstream changes live without a reboot.
DnsForwarder* g_forwarder = nullptr;

// ---- small helpers -------------------------------------------------------

esp_err_t send_json_obj(httpd_req_t* req, cJSON* root) {
  if (root == nullptr) root = cJSON_CreateObject();
  char* s = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (s == nullptr) {
    httpd_resp_send_500(req);
    return ESP_OK;
  }
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, s, strlen(s));
  cJSON_free(s);
  return ESP_OK;
}

esp_err_t send_error(httpd_req_t* req, const char* status, const char* msg) {
  httpd_resp_set_status(req, status);
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "error", msg);
  return send_json_obj(req, root);
}

// Returns true when the request is authorized; otherwise sends
// 401 {"error":"unauthorized"} and returns false.
bool require_auth(httpd_req_t* req) {
  if (HttpServer::check_auth(req)) return true;
  send_error(req, "401 Unauthorized", "unauthorized");
  return false;
}

// Reads the full request body (cap 8 KB). Returns false on truncation/error.
bool read_body(httpd_req_t* req, std::string& out) {
  const size_t len = req->content_len;
  if (len == 0 || len > 8192) return false;
  out.resize(len);
  size_t received = 0;
  while (received < len) {
    const int r = httpd_req_recv(req, out.data() + received, len - received);
    if (r <= 0) return false;
    received += static_cast<size_t>(r);
  }
  return true;
}

int query_int(httpd_req_t* req, const char* name, int dflt) {
  char query[160] = {0};
  if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) return dflt;
  char val[32] = {0};
  if (httpd_query_key_value(query, name, val, sizeof(val)) != ESP_OK) return dflt;
  return atoi(val);
}

bool query_str(httpd_req_t* req, const char* name, char* out, size_t out_len) {
  char query[256] = {0};
  if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) return false;
  return httpd_query_key_value(query, name, out, out_len) == ESP_OK;
}

// URI path without the "?query" part (req->uri is a fixed char array in
// IDF v5, never NULL).
void path_copy(httpd_req_t* req, char* out, size_t out_len) {
  const char* uri = req->uri;
  size_t n = 0;
  while (uri[n] != '\0' && uri[n] != '?' && n + 1 < out_len) {
    out[n] = uri[n];
    ++n;
  }
  out[n] = '\0';
}

// Prints an IPv4 address stored in network byte order (POSIX s_addr
// convention, as used for DnsQuestionInfo.client_ip / DeviceEntry.ip /
// QueryLogEntry.client_ip): the first octet is the least-significant byte
// of the u32 on little-endian targets.
void ip_to_str(uint32_t ip_net_order, char* out, size_t out_len) {
  snprintf(out, out_len, "%u.%u.%u.%u", (unsigned)(ip_net_order & 0xff),
           (unsigned)((ip_net_order >> 8) & 0xff),
           (unsigned)((ip_net_order >> 16) & 0xff),
           (unsigned)((ip_net_order >> 24) & 0xff));
}

const char* decision_str(DnsDecision d) {
  // DnsDecision::NXDOMAIN is produced by BlockMode::NXDOMAIN, i.e. the query
  // was blocked — report it as "block" per the API contract.
  return (d == DnsDecision::ALLOW) ? "allow" : "block";
}

uint32_t uptime_s() { return (uint32_t)(esp_timer_get_time() / 1000000ULL); }

bool valid_ipv4(const char* s) {
  if (s == nullptr || *s == '\0') return false;
  int a = -1, b = -1, c = -1, d = -1;
  char extra = 0;
  if (sscanf(s, "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4) return false;
  return a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 &&
         d >= 0 && d <= 255;
}

// mtime of the active slot file → "updated_at" (0 if unknown / no SNTP yet).
uint64_t blocklist_updated_at(char slot) {
  char path[64];
  snprintf(path, sizeof(path), "/littlefs/blocklists/slot_%c.bl",
           (slot == 'B') ? 'b' : 'a');
  struct stat st;
  if (stat(path, &st) != 0) return 0;
  return (uint64_t)st.st_mtime;
}

}  // namespace

void register_dns_forwarder(DnsForwarder* fwd) { g_forwarder = fwd; }

// ---- dashboard + websocket ------------------------------------------------

// Embedded by the build (EMBED_FILES web_dashboard/index.html in
// main/CMakeLists.txt — wired by the coordinator).
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[] asm("_binary_index_html_end");

esp_err_t handle_root(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;  // "/" is public; check_auth passes it
  const size_t len = (size_t)(index_html_end - index_html_start);
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, reinterpret_cast<const char*>(index_html_start), len);
  return ESP_OK;
}

esp_err_t handle_ws(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  const int fd = httpd_req_to_sockfd(req);

  if (req->method == HTTP_GET) {
    // This first call is the WebSocket handshake — register the session.
    // The 2 s push task in http_server.cpp sends stats frames to all
    // registered sessions via httpd_ws_send_frame_async.
    HttpServer::instance().ws_add(fd);
    ESP_LOGI(TAG, "WS client connected (fd=%d)", fd);
    return ESP_OK;
  }

  // Subsequent calls carry incoming frames. We don't need client→server
  // messages; just drain them. Any error means the session is dead.
  httpd_ws_frame_t ws_pkt;
  memset(&ws_pkt, 0, sizeof(ws_pkt));
  ws_pkt.type = HTTPD_WS_TYPE_TEXT;
  esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
  if (ret == ESP_OK && ws_pkt.len > 0) {
    uint8_t* buf = (uint8_t*)malloc(ws_pkt.len + 1);
    if (buf != nullptr) {
      ws_pkt.payload = buf;
      ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
      free(buf);
    }
  }
  if (ret != ESP_OK) {
    HttpServer::instance().ws_remove(fd);
    ESP_LOGI(TAG, "WS client disconnected (fd=%d)", fd);
  }
  return ret;
}

// ---- status / stats / devices / queries ------------------------------------

esp_err_t api_get_status(httpd_req_t* req) {
  // Public per CONTRACTS.md §8 (no require_auth here).
  auto& cfg = ConfigManager::instance();
  char device[40] = {0};
  char ssid[40] = {0};
  char primary[24] = {0};
  char secondary[24] = {0};
  uint8_t filtering = 1;
  cfg.get_str("device_name", device, sizeof(device));
  cfg.get_str("wifi_ssid", ssid, sizeof(ssid));
  cfg.get_str("upstream_primary", primary, sizeof(primary));
  cfg.get_str("upstream_secondary", secondary, sizeof(secondary));
  cfg.get_u8("filtering_enabled", &filtering);

  char ip[20] = "0.0.0.0";
  int8_t rssi = 0;
  auto& wifi = WifiManager::instance();
  if (wifi.is_connected()) {
    wifi.get_ip(ip, sizeof(ip));
    rssi = wifi.rssi();
  }

  const char slot = BlocklistFile::active_slot();
  char slot_str[2] = {(slot == 'B') ? 'B' : 'A', '\0'};

  char mode[16] = {0};
  cfg.get_str("mode", mode, sizeof(mode));
  if (mode[0] == '\0') strncpy(mode, "dns", sizeof(mode) - 1);

  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "device", device);
  cJSON_AddStringToObject(root, "version", FIRMWARE_VERSION);
  cJSON_AddNumberToObject(root, "uptime_s", uptime_s());
  cJSON_AddStringToObject(root, "mode", mode);

  cJSON* w = cJSON_CreateObject();
  cJSON_AddStringToObject(w, "ssid", ssid);
  cJSON_AddNumberToObject(w, "rssi", rssi);
  cJSON_AddStringToObject(w, "ip", ip);
  cJSON_AddItemToObject(root, "wifi", w);

  // Travel mode extras: the client-facing AP (SSID/IP/associated count).
  if (wifi.travel_active()) {
    char ap_ssid[40] = {0}, ap_ip[20] = "0.0.0.0";
    wifi.get_ap_ssid(ap_ssid, sizeof(ap_ssid));
    wifi.get_ap_ip(ap_ip, sizeof(ap_ip));
    cJSON* ap = cJSON_CreateObject();
    cJSON_AddStringToObject(ap, "ssid", ap_ssid);
    cJSON_AddStringToObject(ap, "ip", ap_ip);
    cJSON_AddNumberToObject(ap, "clients", wifi.ap_client_count());
    cJSON_AddItemToObject(root, "ap", ap);
    cJSON_AddBoolToObject(root, "wps_active", wifi.wps_active());
  }

  cJSON_AddBoolToObject(root, "filtering_enabled", filtering != 0);

  cJSON* bl = cJSON_CreateObject();
  cJSON_AddNumberToObject(bl, "entries",
                          (double)BlocklistManager::instance().entry_count());
  cJSON_AddNumberToObject(bl, "updated_at", (double)blocklist_updated_at(slot));
  cJSON_AddStringToObject(bl, "active_slot", slot_str);
  cJSON_AddItemToObject(root, "blocklist", bl);

  cJSON* up = cJSON_CreateObject();
  cJSON_AddStringToObject(up, "primary", primary);
  cJSON_AddStringToObject(up, "secondary", secondary);
  cJSON_AddItemToObject(root, "upstream", up);

  return send_json_obj(req, root);
}

esp_err_t api_get_stats(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  StatsSnapshot snap;
  StatsEngine::instance().snapshot(&snap);

  const uint32_t allowed = snap.total_queries >= snap.blocked_queries
                               ? snap.total_queries - snap.blocked_queries
                               : 0;
  const double block_rate = snap.total_queries
                                ? 100.0 * snap.blocked_queries / snap.total_queries
                                : 0.0;
  const double cache_hit_rate = snap.total_queries
                                    ? 100.0 * snap.cache_hits / snap.total_queries
                                    : 0.0;

  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "total_queries", snap.total_queries);
  cJSON_AddNumberToObject(root, "blocked_queries", snap.blocked_queries);
  cJSON_AddNumberToObject(root, "allowed_queries", allowed);
  cJSON_AddNumberToObject(root, "cache_hits", snap.cache_hits);
  cJSON_AddNumberToObject(root, "cache_hit_rate", cache_hit_rate);
  cJSON_AddNumberToObject(root, "block_rate", block_rate);
  cJSON_AddNumberToObject(root, "uptime_s", uptime_s());

  cJSON* top = cJSON_CreateArray();
  for (int i = 0; i < snap.top_blocked_count; ++i) {
    cJSON* e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "domain", snap.top_blocked[i].domain);
    cJSON_AddNumberToObject(e, "count", snap.top_blocked[i].count);
    cJSON_AddItemToArray(top, e);
  }
  cJSON_AddItemToObject(root, "top_blocked", top);

  return send_json_obj(req, root);
}

esp_err_t api_get_devices(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  std::vector<DeviceEntry> devices;
  DeviceTracker::instance().get_devices(devices);

  cJSON* root = cJSON_CreateArray();
  char ip[20];
  for (const auto& d : devices) {
    ip_to_str(d.ip, ip, sizeof(ip));
    cJSON* e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "ip", ip);
    cJSON_AddStringToObject(e, "mac", d.mac);
    cJSON_AddStringToObject(e, "hostname", d.hostname);
    cJSON_AddNumberToObject(e, "queries", d.queries);
    cJSON_AddNumberToObject(e, "blocked", d.blocked);
    cJSON_AddNumberToObject(e, "first_seen_s", d.first_seen_s);
    cJSON_AddNumberToObject(e, "last_seen_s", d.last_seen_s);
    cJSON_AddItemToArray(root, e);
  }
  return send_json_obj(req, root);
}

esp_err_t api_get_queries(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  int limit = query_int(req, "limit", 50);
  if (limit < 1) limit = 1;
  if (limit > 200) limit = 200;  // QueryLogger ring buffer holds 200

  std::vector<QueryLogEntry> entries;
  QueryLogger::instance().get_entries(entries, (size_t)limit);

  // The contract requires newest-first. If the logger returned oldest-first
  // (ascending timestamps), flip it; the flip is harmless when all ts are
  // equal or there is a single entry.
  if (entries.size() > 1 && entries.front().ts_s < entries.back().ts_s) {
    std::reverse(entries.begin(), entries.end());
  }

  cJSON* root = cJSON_CreateArray();
  char ip[20];
  for (const auto& e : entries) {
    ip_to_str(e.client_ip, ip, sizeof(ip));
    cJSON* o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "ts_s", e.ts_s);
    cJSON_AddStringToObject(o, "client", ip);
    cJSON_AddStringToObject(o, "domain", e.domain);
    cJSON_AddNumberToObject(o, "qtype", e.qtype);
    cJSON_AddStringToObject(o, "decision", decision_str(e.decision));
    cJSON_AddBoolToObject(o, "cached", e.cached);
    cJSON_AddItemToArray(root, o);
  }
  return send_json_obj(req, root);
}

// ---- config ----------------------------------------------------------------

esp_err_t api_get_config(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  // All NVS keys from CONTRACTS.md §3 EXCEPT wifi_pass and api_token,
  // which must never leave the device. ap_pass IS exposed: the dashboard
  // needs to show the travel AP password (it's the user's own credential,
  // visible only to authenticated API callers).
  auto& cfg = ConfigManager::instance();
  cJSON* root = cJSON_CreateObject();

  const char* str_keys[] = {"wifi_ssid", "device_name", "upstream_primary",
                            "upstream_secondary", "mode", "ap_ssid", "ap_pass"};
  for (const char* k : str_keys) {
    char v[64] = {0};
    cfg.get_str(k, v, sizeof(v));
    cJSON_AddStringToObject(root, k, v);
  }

  const char* u32_keys[] = {"upstream_timeout_ms", "update_interval_h"};
  for (const char* k : u32_keys) {
    uint32_t v = 0;
    cfg.get_u32(k, &v);
    cJSON_AddNumberToObject(root, k, v);
  }

  uint16_t cache_entries = 0;
  cfg.get_u16("cache_entries", &cache_entries);
  cJSON_AddNumberToObject(root, "cache_entries", cache_entries);

  uint8_t filtering = 0, block_mode = 0, flush_min = 0;
  cfg.get_u8("filtering_enabled", &filtering);
  cfg.get_u8("block_mode", &block_mode);
  cfg.get_u8("stats_flush_min", &flush_min);
  cJSON_AddBoolToObject(root, "filtering_enabled", filtering != 0);
  cJSON_AddNumberToObject(root, "block_mode", block_mode);
  cJSON_AddNumberToObject(root, "stats_flush_min", flush_min);

  return send_json_obj(req, root);
}

namespace {

// Validate one PUT /api/config key. Returns true, or false with err set.
// No side effects — the apply pass runs only after every key validates.
bool validate_config_item(const char* key, const cJSON* item, std::string& err) {
  const auto num_int = [&]() -> long {
    return cJSON_IsNumber(item) ? (long)item->valuedouble : LONG_MIN;
  };
  const auto str_val = [&]() -> const char* {
    return cJSON_IsString(item) ? item->valuestring : nullptr;
  };

  if (strcmp(key, "upstream_primary") == 0 || strcmp(key, "upstream_secondary") == 0) {
    const char* v = str_val();
    if (v == nullptr || !valid_ipv4(v)) {
      err = std::string(key) + " must be a dotted-quad IPv4 address";
      return false;
    }
    return true;
  }
  if (strcmp(key, "upstream_timeout_ms") == 0) {
    const long v = num_int();
    if (v < 500 || v > 10000) {
      err = "upstream_timeout_ms out of range (500..10000)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "cache_entries") == 0) {
    const long v = num_int();
    if (v < 64 || v > 2048) {
      err = "cache_entries out of range (64..2048)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "block_mode") == 0) {
    const long v = num_int();
    if (v < 0 || v > 2) {
      err = "block_mode out of range (0..2)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "update_interval_h") == 0) {
    const long v = num_int();
    if (v < 1 || v > 168) {
      err = "update_interval_h out of range (1..168)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "filtering_enabled") == 0) {
    if (cJSON_IsBool(item)) return true;
    const long v = num_int();
    if (v != 0 && v != 1) {
      err = "filtering_enabled must be true/false or 0/1";
      return false;
    }
    return true;
  }
  if (strcmp(key, "stats_flush_min") == 0) {
    const long v = num_int();
    if (v < 1 || v > 255) {
      err = "stats_flush_min out of range (1..255)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "wifi_ssid") == 0 || strcmp(key, "device_name") == 0) {
    const char* v = str_val();
    if (v == nullptr || *v == '\0' || strlen(v) > 32) {
      err = std::string(key) + " must be 1..32 chars";
      return false;
    }
    return true;
  }
  if (strcmp(key, "wifi_pass") == 0) {
    const char* v = str_val();
    if (v != nullptr && strlen(v) > 64) {
      err = "wifi_pass must be 0..64 chars";
      return false;
    }
    return true;
  }
  if (strcmp(key, "api_token") == 0) {
    err = std::string(key) + " cannot be changed via this API";
    return false;
  }
  if (strcmp(key, "mode") == 0) {
    const char* v = str_val();
    if (v == nullptr || (strcmp(v, "dns") != 0 && strcmp(v, "travel") != 0)) {
      err = "mode must be \"dns\" or \"travel\" (takes effect after reboot)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "ap_ssid") == 0) {
    const char* v = str_val();
    // Empty string = auto ("Shield-XXXX" from the MAC).
    if (v == nullptr || strlen(v) > 32) {
      err = "ap_ssid must be 0..32 chars (empty = auto)";
      return false;
    }
    return true;
  }
  if (strcmp(key, "ap_pass") == 0) {
    const char* v = str_val();
    // Empty string = generate a fresh random password on next boot.
    const size_t n = v == nullptr ? 0 : strlen(v);
    if (n != 0 && (n < 8 || n > 63)) {
      err = "ap_pass must be empty or 8..63 chars (WPA2 requirement)";
      return false;
    }
    return true;
  }
  // Unknown keys are ignored (forward compatibility), not an error.
  return true;
}

// Apply one already-validated key. Returns true if it affects the upstream
// forwarder (primary/secondary/timeout). Sets reboot_needed when the change
// only takes effect after a reboot (operating mode, travel AP settings).
bool apply_config_item(const char* key, const cJSON* item, bool& reboot_needed) {
  auto& cfg = ConfigManager::instance();
  const long num = cJSON_IsNumber(item) ? (long)item->valuedouble : 0;

  if (strcmp(key, "mode") == 0) {
    char cur[16] = {0};
    cfg.get_str("mode", cur, sizeof(cur));
    if (cur[0] == '\0') strncpy(cur, "dns", sizeof(cur) - 1);  // unset ⇒ dns
    if (strcmp(cur, item->valuestring) != 0) {
      cfg.set_str(key, item->valuestring);
      reboot_needed = true;
    }
    return false;
  }
  if (strcmp(key, "ap_ssid") == 0 || strcmp(key, "ap_pass") == 0) {
    char cur[64] = {0};
    cfg.get_str(key, cur, sizeof(cur));
    if (strcmp(cur, item->valuestring) != 0) {
      cfg.set_str(key, item->valuestring);
      // AP credentials apply when the AP (re)starts.
      reboot_needed = true;
    }
    return false;
  }

  if (strcmp(key, "wifi_ssid") == 0) {
    char cur[64] = {0};
    cfg.get_str("wifi_ssid", cur, sizeof(cur));
    if (strcmp(cur, item->valuestring) != 0) {
      cfg.set_str("wifi_ssid", item->valuestring);
      reboot_needed = true;
    }
    return false;
  }
  if (strcmp(key, "wifi_pass") == 0) {
    const char* v = item->valuestring;
    if (v != nullptr && *v != '\0') {
      char cur[65] = {0};
      cfg.get_str("wifi_pass", cur, sizeof(cur));
      if (strcmp(cur, v) != 0) {
        cfg.set_str("wifi_pass", v);
        reboot_needed = true;
      }
    }
    return false;
  }

  if (strcmp(key, "upstream_primary") == 0 || strcmp(key, "upstream_secondary") == 0 ||
      strcmp(key, "device_name") == 0) {
    cfg.set_str(key, item->valuestring);
    return strcmp(key, "upstream_primary") == 0 || strcmp(key, "upstream_secondary") == 0;
  }
  if (strcmp(key, "upstream_timeout_ms") == 0) {
    cfg.set_u32(key, (uint32_t)num);
    return true;
  }
  if (strcmp(key, "update_interval_h") == 0) {
    cfg.set_u32(key, (uint32_t)num);
    return false;
  }
  if (strcmp(key, "cache_entries") == 0) {
    cfg.set_u16(key, (uint16_t)num);
    return false;
  }
  if (strcmp(key, "block_mode") == 0 || strcmp(key, "stats_flush_min") == 0) {
    cfg.set_u8(key, (uint8_t)num);
    return false;
  }
  if (strcmp(key, "filtering_enabled") == 0) {
    const uint8_t v = cJSON_IsBool(item) ? (cJSON_IsTrue(item) ? 1 : 0) : (uint8_t)num;
    cfg.set_u8(key, v);
    return false;
  }
  return false;  // unknown key: ignored
}

}  // namespace

esp_err_t api_put_config(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;

  std::string body;
  if (!read_body(req, body)) return send_error(req, "400 Bad Request", "bad request body");
  cJSON* json = cJSON_ParseWithLength(body.data(), body.size());
  if (json == nullptr || !cJSON_IsObject(json)) {
    cJSON_Delete(json);
    return send_error(req, "400 Bad Request", "invalid JSON object");
  }

  // Pass 1: validate everything before touching NVS (atomic-ish update).
  std::string err;
  cJSON* item = nullptr;
  cJSON_ArrayForEach(item, json) {
    if (item->string == nullptr) continue;
    if (!validate_config_item(item->string, item, err)) {
      cJSON_Delete(json);
      return send_error(req, "400 Bad Request", err.c_str());
    }
  }

  // Pass 2: apply via ConfigManager (setters commit to NVS immediately).
  bool upstream_changed = false;
  bool reboot_needed = false;
  cJSON_ArrayForEach(item, json) {
    if (item->string == nullptr) continue;
    if (apply_config_item(item->string, item, reboot_needed)) upstream_changed = true;
  }
  cJSON_Delete(json);

  // Upstream/timeout changes apply live — no reboot needed.
  if (upstream_changed && g_forwarder != nullptr) {
    auto& cfg = ConfigManager::instance();
    char primary[24] = {0}, secondary[24] = {0};
    uint32_t timeout = 2500;
    cfg.get_str("upstream_primary", primary, sizeof(primary));
    cfg.get_str("upstream_secondary", secondary, sizeof(secondary));
    cfg.get_u32("upstream_timeout_ms", &timeout);
    g_forwarder->set_upstreams(primary, secondary, timeout);
    ESP_LOGI(TAG, "upstreams updated live: %s / %s (%u ms)", primary, secondary,
             (unsigned)timeout);
  }

  cJSON* root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "ok", true);
  cJSON_AddBoolToObject(root, "reboot_required", reboot_needed);
  return send_json_obj(req, root);
}

// ---- blocklist --------------------------------------------------------------

esp_err_t api_get_blocklist(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  const char slot = BlocklistFile::active_slot();
  char slot_str[2] = {(slot == 'B') ? 'B' : 'A', '\0'};

  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "active_slot", slot_str);
  cJSON_AddNumberToObject(root, "entries",
                          (double)BlocklistManager::instance().entry_count());
  cJSON_AddNumberToObject(root, "updated_at", (double)blocklist_updated_at(slot));

  cJSON* sources = cJSON_CreateArray();
  for (size_t i = 0; i < kBlocklistSourceCount; ++i) {
    cJSON_AddItemToArray(sources, cJSON_CreateString(kBlocklistSources[i]));
  }
  cJSON_AddItemToObject(root, "sources", sources);

  return send_json_obj(req, root);
}

namespace {

void blocklist_update_task(void*) {
  const UpdateResult r = BlocklistUpdater::instance().update_now();
  ESP_LOGI(TAG, "blocklist update finished: ok=%d entries=%llu msg=%s", r.ok,
           (unsigned long long)r.entries, r.message);
  vTaskDelete(nullptr);
}

}  // namespace

esp_err_t api_post_blocklist_update(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  // Async: the updater downloads, validates and swaps slots on its own task.
  if (xTaskCreate(blocklist_update_task, "bl_update", 8192, nullptr, 5, nullptr) !=
      pdPASS) {
    return send_error(req, "500 Internal Server Error", "task create failed");
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "status", "started");
  return send_json_obj(req, root);
}

// ---- allowlist ---------------------------------------------------------------

esp_err_t api_get_allowlist(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  const std::vector<std::string> domains = Allowlist::instance().list();
  cJSON* root = cJSON_CreateObject();
  cJSON* arr = cJSON_CreateArray();
  for (const auto& d : domains) {
    cJSON_AddItemToArray(arr, cJSON_CreateString(d.c_str()));
  }
  cJSON_AddItemToObject(root, "domains", arr);
  return send_json_obj(req, root);
}

esp_err_t api_post_allowlist(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  std::string body;
  if (!read_body(req, body)) return send_error(req, "400 Bad Request", "bad request body");
  cJSON* json = cJSON_ParseWithLength(body.data(), body.size());
  if (json == nullptr || !cJSON_IsObject(json)) {
    cJSON_Delete(json);
    return send_error(req, "400 Bad Request", "invalid JSON object");
  }

  int added = 0;
  auto& allow = Allowlist::instance();
  const cJSON* single = cJSON_GetObjectItemCaseSensitive(json, "domain");
  if (cJSON_IsString(single) && single->valuestring[0] != '\0') {
    if (allow.add(single->valuestring)) ++added;
  }
  const cJSON* many = cJSON_GetObjectItemCaseSensitive(json, "domains");
  if (cJSON_IsArray(many)) {
    const cJSON* d = nullptr;
    cJSON_ArrayForEach(d, many) {
      if (cJSON_IsString(d) && d->valuestring[0] != '\0') {
        if (allow.add(d->valuestring)) ++added;
      }
    }
  }
  cJSON_Delete(json);

  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "added", added);
  return send_json_obj(req, root);
}

esp_err_t api_delete_allowlist(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  char domain[128] = {0};
  if (!query_str(req, "domain", domain, sizeof(domain)) || domain[0] == '\0') {
    return send_error(req, "400 Bad Request", "missing ?domain=");
  }
  // remove() normalizes internally; returns false when absent — still report
  // ok:true since the end state (domain not listed) is what was asked for.
  Allowlist::instance().remove(domain);
  cJSON* root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "ok", true);
  return send_json_obj(req, root);
}

// ---- custom rules --------------------------------------------------------------

esp_err_t api_get_rules(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  const std::vector<CustomRule> rules = CustomRules::instance().list();

  cJSON* root = cJSON_CreateObject();
  cJSON* arr = cJSON_CreateArray();
  for (const auto& r : rules) {
    cJSON* o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", r.id);
    cJSON_AddStringToObject(o, "domain", r.domain.c_str());
    cJSON_AddStringToObject(o, "action", r.block ? "block" : "allow");
    cJSON_AddBoolToObject(o, "enabled", r.enabled);
    cJSON_AddItemToArray(arr, o);
  }
  cJSON_AddItemToObject(root, "rules", arr);
  return send_json_obj(req, root);
}

esp_err_t api_post_rules(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  std::string body;
  if (!read_body(req, body)) return send_error(req, "400 Bad Request", "bad request body");
  cJSON* json = cJSON_ParseWithLength(body.data(), body.size());
  if (json == nullptr || !cJSON_IsObject(json)) {
    cJSON_Delete(json);
    return send_error(req, "400 Bad Request", "invalid JSON object");
  }

  const cJSON* jd = cJSON_GetObjectItemCaseSensitive(json, "domain");
  const cJSON* ja = cJSON_GetObjectItemCaseSensitive(json, "action");
  bool ok = cJSON_IsString(jd) && jd->valuestring[0] != '\0' && cJSON_IsString(ja);
  bool block = false;
  if (ok) {
    if (strcmp(ja->valuestring, "block") == 0) {
      block = true;
    } else if (strcmp(ja->valuestring, "allow") == 0) {
      block = false;
    } else {
      ok = false;
    }
  }
  if (!ok) {
    cJSON_Delete(json);
    return send_error(req, "400 Bad Request",
                      "need {\"domain\":\"...\",\"action\":\"block\"|\"allow\"}");
  }
  const uint32_t id = CustomRules::instance().add(jd->valuestring, block);
  cJSON_Delete(json);

  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "id", id);
  return send_json_obj(req, root);
}

esp_err_t api_delete_rule(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  // Wildcard route "/api/rules/*": the id follows the last '/'.
  char path[64];
  path_copy(req, path, sizeof(path));
  const char* slash = strrchr(path, '/');
  if (slash == nullptr || *(slash + 1) == '\0') {
    return send_error(req, "400 Bad Request", "missing rule id");
  }
  char* end = nullptr;
  const unsigned long id = strtoul(slash + 1, &end, 10);
  if (end == slash + 1 || *end != '\0') {
    return send_error(req, "400 Bad Request", "invalid rule id");
  }

  if (!CustomRules::instance().remove((uint32_t)id)) {
    return send_error(req, "404 Not Found", "not found");
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "ok", true);
  return send_json_obj(req, root);
}

// ---- reboot / ota --------------------------------------------------------------

namespace {

void reboot_task(void*) {
  // Small delay so the HTTP 200 response is flushed before the reset.
  vTaskDelay(pdMS_TO_TICKS(500));
  ESP_LOGI(TAG, "rebooting on API request");
  esp_restart();
}

void ota_task(void* arg) {
  char* url = static_cast<char*>(arg);
  const bool ok = OtaManager::instance().begin(url);
  ESP_LOGI(TAG, "OTA begin(%s) -> %s", url, ok ? "started" : "failed");
  free(url);
  vTaskDelete(nullptr);
}

}  // namespace

esp_err_t api_post_reboot(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  if (xTaskCreate(reboot_task, "api_reboot", 2048, nullptr, 5, nullptr) != pdPASS) {
    return send_error(req, "500 Internal Server Error", "task create failed");
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "ok", true);
  return send_json_obj(req, root);
}

// ---- WPS push-button provisioning (travel mode) ----------------------------
// Starts a WPS PBC session on the STA interface. The user must press the WPS
// button on the upstream router within ~2 minutes. On success the received
// credentials are saved to NVS and the device reboots into travel AP+STA.
// Not all routers support WPS — the captive portal remains the fallback.
esp_err_t api_post_wps(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  auto& wifi = WifiManager::instance();
  if (!wifi.travel_active()) {
    return send_error(req, "400 Bad Request",
                      "WPS is only available in travel mode");
  }
  if (wifi.wps_active()) {
    return send_error(req, "409 Conflict", "WPS session already in progress");
  }
  if (!wifi.start_wps()) {
    return send_error(req, "500 Internal Server Error",
                      "could not start WPS (STA may already be connected)");
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "status", "started");
  cJSON_AddStringToObject(
      root, "message",
      "WPS started: press the WPS button on your router within ~2 minutes. "
      "The device reboots automatically on success.");
  return send_json_obj(req, root);
}

esp_err_t api_post_ota(httpd_req_t* req) {
  if (!require_auth(req)) return ESP_OK;
  std::string body;
  if (!read_body(req, body)) return send_error(req, "400 Bad Request", "bad request body");
  cJSON* json = cJSON_ParseWithLength(body.data(), body.size());
  if (json == nullptr || !cJSON_IsObject(json)) {
    cJSON_Delete(json);
    return send_error(req, "400 Bad Request", "invalid JSON object");
  }
  const cJSON* ju = cJSON_GetObjectItemCaseSensitive(json, "url");
  const bool valid_url =
      cJSON_IsString(ju) && (strncmp(ju->valuestring, "https://", 8) == 0 ||
                             strncmp(ju->valuestring, "http://", 7) == 0);
  char* url = valid_url ? strdup(ju->valuestring) : nullptr;
  cJSON_Delete(json);
  if (url == nullptr) {
    return send_error(req, "400 Bad Request", "{\"url\":\"https://...\"} required");
  }
  // OtaManager::begin() blocks (esp_https_ota), so run it on its own task.
  if (xTaskCreate(ota_task, "api_ota", 8192, url, 5, nullptr) != pdPASS) {
    free(url);
    return send_error(req, "500 Internal Server Error", "task create failed");
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "status", "started");
  return send_json_obj(req, root);
}

}  // namespace shield
