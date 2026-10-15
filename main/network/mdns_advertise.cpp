#include "mdns_advertise.h"

#include "esp_log.h"
#include "mdns.h"

namespace shield {
namespace mdns_advertise {

namespace {
const char* TAG = "mdns";
}  // namespace

bool start(const char* hostname) {
  if (hostname == nullptr || hostname[0] == '\0') {
    ESP_LOGW(TAG, "empty hostname; mDNS not started");
    return false;
  }
  if (mdns_init() != ESP_OK) {
    ESP_LOGW(TAG, "mdns_init failed; mDNS disabled");
    return false;
  }
  if (mdns_hostname_set(hostname) != ESP_OK) {
    ESP_LOGW(TAG, "mdns_hostname_set failed");
    return false;
  }
  // Best-effort extras: the host is still advertised as <hostname>.local
  // even if the friendly name or the service record fails.
  if (mdns_instance_name_set("ESP32 Network Shield") != ESP_OK) {
    ESP_LOGW(TAG, "mdns_instance_name_set failed");
  }
  if (mdns_service_add(nullptr, "_http", "_tcp", 80, nullptr, 0) != ESP_OK) {
    ESP_LOGW(TAG, "_http._tcp service registration failed");
  }
  ESP_LOGI(TAG, "advertising %s.local (+ _http._tcp:80)", hostname);
  return true;
}

}  // namespace mdns_advertise
}  // namespace shield
