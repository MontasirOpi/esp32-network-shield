// HttpServer: esp_http_server lifecycle, bearer auth, WS session tracking,
// and the 2 s WebSocket stats push task.

#include "http_server.h"

#include "api_handlers.h"

#include <esp_log.h>
#include <esp_timer.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstring>
#include <string>

#include <cJSON.h>

#include "../core/types.h"
#include "../system/config_manager.h"
#include "../system/device_tracker.h"
#include "../system/stats_engine.h"

namespace shield {

namespace {

constexpr const char* TAG = "web";

// Compare two NUL-terminated strings in (roughly) constant time so a wrong
// token doesn't fail faster than a right one. Empty inputs never match —
// this also guards against strcmp("", "") succeeding when no token is set.
bool token_matches(const char* a, const char* b) {
  if (a == nullptr || b == nullptr) return false;
  const size_t la = strlen(a);
  const size_t lb = strlen(b);
  if (la == 0 || lb == 0) return false;
  if (la != lb) return false;
  volatile unsigned char diff = 0;
  for (size_t i = 0; i < la; ++i) {
    // Plain assignment (not |=): compound assignment on volatile is
    // deprecated in C++20 and warns under -Wvolatile.
    diff = static_cast<unsigned char>(
        diff | (static_cast<unsigned char>(a[i]) ^
                static_cast<unsigned char>(b[i])));
  }
  return diff == 0;
}

// Strip query string ("?a=b") from a URI for path comparisons.
std::string path_of(const char* uri) {
  std::string p = uri ? uri : "";
  const size_t q = p.find('?');
  if (q != std::string::npos) p.resize(q);
  return p;
}

bool starts_with(const std::string& s, const char* prefix) {
  return s.compare(0, strlen(prefix), prefix) == 0;
}

}  // namespace

HttpServer& HttpServer::instance() {
  static HttpServer inst;
  return inst;
}

bool HttpServer::check_auth(httpd_req_t* req) {
  const std::string path = path_of(req->uri);

  // Public paths: dashboard, status, and Team B's provisioning routes.
  if (path == "/" || path == "/api/status") return true;
  if (starts_with(path, "/setup")) return true;

  // Expected token from NVS. Never logged.
  char expected[64] = {0};
  if (!ConfigManager::instance().get_str("api_token", expected, sizeof(expected))) {
    return false;
  }

  // Primary: Authorization: Bearer <token> header.
  char auth[96] = {0};
  if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) == ESP_OK) {
    constexpr const char* kPrefix = "Bearer ";
    if (strncmp(auth, kPrefix, strlen(kPrefix)) == 0) {
      return token_matches(auth + strlen(kPrefix), expected);
    }
    return false;
  }

  // Fallback for /ws only: browsers cannot set headers on a WebSocket
  // handshake, so the dashboard passes ?token=<api_token> instead.
  if (path == "/ws") {
    char query[128] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
      char tok[64] = {0};
      if (httpd_query_key_value(query, "token", tok, sizeof(tok)) == ESP_OK) {
        return token_matches(tok, expected);
      }
    }
  }
  return false;
}

void HttpServer::ws_add(int fd) {
  std::lock_guard<std::mutex> lock(ws_mutex_);
  for (int f : ws_fds_) {
    if (f == fd) return;
  }
  ws_fds_.push_back(fd);
}

void HttpServer::ws_remove(int fd) {
  std::lock_guard<std::mutex> lock(ws_mutex_);
  for (auto it = ws_fds_.begin(); it != ws_fds_.end(); ++it) {
    if (*it == fd) {
      ws_fds_.erase(it);
      return;
    }
  }
}

void HttpServer::ws_broadcast(httpd_ws_frame_t* frame) {
  std::lock_guard<std::mutex> lock(ws_mutex_);
  for (auto it = ws_fds_.begin(); it != ws_fds_.end();) {
    // httpd_ws_send_frame_async copies the frame payload into the queued work
    // item (IDF v5), so the caller's buffer may be reused/freed immediately
    // after this call returns.
    if (httpd_ws_send_frame_async(server_, *it, frame) != ESP_OK) {
      // Session is dead (client went away); prune it.
      it = ws_fds_.erase(it);
    } else {
      ++it;
    }
  }
}

// Builds {"type":"stats",...} and pushes it to every open WS session.
// Runs on its own FreeRTOS task (not on the httpd task) because
// httpd_ws_send_frame_async is explicitly designed for cross-task use: it
// queues the send on the httpd work queue instead of touching sockets
// directly. A static payload buffer is used so the payload stays valid no
// matter how the async send is implemented.
void HttpServer::ws_push_task(void* arg) {
  auto* self = static_cast<HttpServer*>(arg);
  static char payload[512];  // static: always valid for queued async sends

  while (self->ws_task_run_.load()) {
    vTaskDelay(pdMS_TO_TICKS(2000));
    if (!self->ws_task_run_.load()) break;

    StatsSnapshot snap;
    StatsEngine::instance().snapshot(&snap);
    std::vector<DeviceEntry> devices;
    DeviceTracker::instance().get_devices(devices);

    const double block_rate =
        snap.total_queries ? 100.0 * snap.blocked_queries / snap.total_queries : 0.0;
    const double cache_hit_rate =
        snap.total_queries ? 100.0 * snap.cache_hits / snap.total_queries : 0.0;

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "stats");
    cJSON_AddNumberToObject(root, "ts", (double)(esp_timer_get_time() / 1000000ULL));
    cJSON_AddNumberToObject(root, "total", snap.total_queries);
    cJSON_AddNumberToObject(root, "blocked", snap.blocked_queries);
    cJSON_AddNumberToObject(root, "block_rate", block_rate);
    cJSON_AddNumberToObject(root, "cache_hit_rate", cache_hit_rate);
    cJSON_AddNumberToObject(root, "devices", (double)devices.size());
    char* s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (s == nullptr) continue;

    strncpy(payload, s, sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';
    cJSON_free(s);

    httpd_ws_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.final = true;
    frame.fragmented = false;
    frame.type = HTTPD_WS_TYPE_TEXT;
    frame.payload = reinterpret_cast<uint8_t*>(payload);
    frame.len = strlen(payload);

    self->ws_broadcast(&frame);
  }
  self->ws_task_ = nullptr;  // signal stop() that we are gone
  vTaskDelete(nullptr);
}

namespace {

// Builds an httpd_uri_t without triggering -Wmissing-field-initializers:
// value-initialize everything, then assign the fields we care about.
httpd_uri_t make_route(const char* uri, httpd_method_t method,
                       esp_err_t (*handler)(httpd_req_t*), bool ws = false) {
  httpd_uri_t r = {};
  r.uri = uri;
  r.method = method;
  r.handler = handler;
  r.user_ctx = nullptr;
  r.is_websocket = ws;
  return r;
}

}  // namespace

bool HttpServer::register_routes() {
  // Keep in sync with api_handlers.h. httpd_config max_uri_handlers = 24.
  static const httpd_uri_t routes[] = {
      make_route("/", HTTP_GET, handle_root),
      make_route("/ws", HTTP_GET, handle_ws, true),
      make_route("/api/status", HTTP_GET, api_get_status),
      make_route("/api/stats", HTTP_GET, api_get_stats),
      make_route("/api/devices", HTTP_GET, api_get_devices),
      make_route("/api/queries", HTTP_GET, api_get_queries),
      make_route("/api/config", HTTP_GET, api_get_config),
      make_route("/api/config", HTTP_PUT, api_put_config),
      make_route("/api/blocklist", HTTP_GET, api_get_blocklist),
      make_route("/api/blocklist/update", HTTP_POST, api_post_blocklist_update),
      make_route("/api/allowlist", HTTP_GET, api_get_allowlist),
      make_route("/api/allowlist", HTTP_POST, api_post_allowlist),
      make_route("/api/allowlist", HTTP_DELETE, api_delete_allowlist),
      make_route("/api/rules", HTTP_GET, api_get_rules),
      make_route("/api/rules", HTTP_POST, api_post_rules),
      make_route("/api/rules/*", HTTP_DELETE, api_delete_rule),
      make_route("/api/reboot", HTTP_POST, api_post_reboot),
      make_route("/api/ota", HTTP_POST, api_post_ota),
      make_route("/api/wps/start", HTTP_POST, api_post_wps),
  };
  static_assert(sizeof(routes) / sizeof(routes[0]) <= 24, "too many URI handlers");

  for (const auto& r : routes) {
    if (httpd_register_uri_handler(server_, &r) != ESP_OK) {
      ESP_LOGE(TAG, "failed to register %s", r.uri);
      return false;
    }
  }
  return true;
}

bool HttpServer::start() {
  if (server_ != nullptr) return true;

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = 80;
  config.stack_size = 6144;
  config.max_uri_handlers = 24;
  config.lru_purge_enable = true;
  // Required for the "/api/rules/*" wildcard route (default matcher is exact).
  config.uri_match_fn = httpd_uri_match_wildcard;

  if (httpd_start(&server_, &config) != ESP_OK) {
    ESP_LOGE(TAG, "httpd_start failed");
    server_ = nullptr;
    return false;
  }
  if (!register_routes()) {
    httpd_stop(server_);
    server_ = nullptr;
    return false;
  }

  ws_task_run_.store(true);
  if (xTaskCreate(ws_push_task, "ws_push", 4096, this, 5, &ws_task_) != pdPASS) {
    ESP_LOGE(TAG, "ws push task create failed");
    ws_task_run_.store(false);
    httpd_stop(server_);
    server_ = nullptr;
    return false;
  }

  ESP_LOGI(TAG, "HTTP server started on port 80");
  return true;
}

void HttpServer::stop() {
  ws_task_run_.store(false);
  // Let the push task exit and delete itself (it clears ws_task_ on exit).
  for (int i = 0; i < 100 && ws_task_ != nullptr; ++i) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  ws_task_ = nullptr;
  {
    std::lock_guard<std::mutex> lock(ws_mutex_);
    ws_fds_.clear();
  }
  if (server_ != nullptr) {
    httpd_stop(server_);
    server_ = nullptr;
  }
  ESP_LOGI(TAG, "HTTP server stopped");
}

}  // namespace shield
