#include "system/config_manager.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_random.h"  // esp_random() (moved out of esp_system.h in IDF v5)
#include "esp_system.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace shield {

namespace {
constexpr const char* TAG = "config";
constexpr const char* kNamespace = "shield";
constexpr const char* kApiTokenKey = "api_token";

const char* nvs_key(const char* key) {
  if (key == nullptr) return "";
  if (strcmp(key, "upstream_primary") == 0) return "up_primary";
  if (strcmp(key, "upstream_secondary") == 0) return "up_secondary";
  if (strcmp(key, "upstream_timeout_ms") == 0) return "up_timeout_ms";
  if (strcmp(key, "filtering_enabled") == 0) return "filter_enabled";
  if (strcmp(key, "update_interval_h") == 0) return "upd_interval_h";
  return key;
}
}  // namespace

ConfigManager& ConfigManager::instance() {
  static ConfigManager inst;
  return inst;
}

bool ConfigManager::init() {
  if (initialized_) return true;

  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_LOGW(TAG, "NVS init needs erase (%s); erasing", esp_err_to_name(err));
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "nvs_flash_init failed: %s", esp_err_to_name(err));
    return false;
  }

  nvs_handle_t h = 0;
  err = nvs_open(kNamespace, NVS_READWRITE, &h);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "nvs_open(%s) failed: %s", kNamespace, esp_err_to_name(err));
    return false;
  }
  nvs_handle_ = reinterpret_cast<void*>(static_cast<uintptr_t>(h));
  initialized_ = true;

  ensure_api_token();
  return true;
}

void ConfigManager::ensure_api_token() {
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  size_t len = 0;
  esp_err_t err = nvs_get_str(h, kApiTokenKey, nullptr, &len);
  if (err != ESP_OK || len <= 1) {
    // Generate 32 lowercase hex chars = 16 random bytes.
    char token[33];
    for (int i = 0; i < 16; ++i) {
      // 2 hex chars + NUL per snprintf call; token[i*2..i*2+1] filled each pass.
      snprintf(token + i * 2, 3, "%02x", static_cast<unsigned>(esp_random() & 0xFF));
    }
    token[32] = '\0';

    if (nvs_set_str(h, kApiTokenKey, token) == ESP_OK) {
      nvs_commit(h);
      ESP_LOGI(TAG, "generated new api_token (first boot)");
    } else {
      ESP_LOGE(TAG, "failed to store generated api_token");
    }
  }

  char current[33] = {0};
  if (get_str(kApiTokenKey, current, sizeof(current))) {
    ESP_LOGI(TAG, "API token: %s", current);
  }
}

bool ConfigManager::get_str(const char* key, char* out, size_t out_len) const {
  if (!initialized_ || key == nullptr || out == nullptr || out_len == 0) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  size_t needed = 0;
  const char* nk = nvs_key(key);
  if (nvs_get_str(h, nk, nullptr, &needed) == ESP_OK && needed <= out_len) {
    return nvs_get_str(h, nk, out, &needed) == ESP_OK;
  }
  if (strcmp(key, "upstream_primary") == 0) {
    strncpy(out, "1.1.1.1", out_len - 1);
    out[out_len - 1] = '\0';
    return true;
  }
  if (strcmp(key, "upstream_secondary") == 0) {
    strncpy(out, "1.0.0.1", out_len - 1);
    out[out_len - 1] = '\0';
    return true;
  }
  if (strcmp(key, "device_name") == 0) {
    strncpy(out, "esp32-shield", out_len - 1);
    out[out_len - 1] = '\0';
    return true;
  }
  return false;
}

bool ConfigManager::set_str(const char* key, const char* value) {
  if (!initialized_ || key == nullptr || value == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_set_str(h, nvs_key(key), value) != ESP_OK) return false;
  return nvs_commit(h) == ESP_OK;  // setters commit immediately (§3)
}

bool ConfigManager::get_u32(const char* key, uint32_t* out) const {
  if (!initialized_ || key == nullptr || out == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_get_u32(h, nvs_key(key), out) == ESP_OK) return true;
  if (strcmp(key, "upstream_timeout_ms") == 0) {
    *out = 2500;
    return true;
  }
  if (strcmp(key, "update_interval_h") == 0) {
    *out = 24;
    return true;
  }
  return false;
}

bool ConfigManager::set_u32(const char* key, uint32_t value) {
  if (!initialized_ || key == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_set_u32(h, nvs_key(key), value) != ESP_OK) return false;
  return nvs_commit(h) == ESP_OK;
}

bool ConfigManager::get_u8(const char* key, uint8_t* out) const {
  if (!initialized_ || key == nullptr || out == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_get_u8(h, nvs_key(key), out) == ESP_OK) return true;
  if (strcmp(key, "filtering_enabled") == 0) {
    *out = 1;
    return true;
  }
  if (strcmp(key, "block_mode") == 0) {
    *out = 0;
    return true;
  }
  if (strcmp(key, "stats_flush_min") == 0) {
    *out = 5;
    return true;
  }
  return false;
}

bool ConfigManager::set_u8(const char* key, uint8_t value) {
  if (!initialized_ || key == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_set_u8(h, nvs_key(key), value) != ESP_OK) return false;
  return nvs_commit(h) == ESP_OK;
}

bool ConfigManager::get_u16(const char* key, uint16_t* out) const {
  if (!initialized_ || key == nullptr || out == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_get_u16(h, nvs_key(key), out) == ESP_OK) return true;
  if (strcmp(key, "cache_entries") == 0) {
    *out = 256;
    return true;
  }
  return false;
}

bool ConfigManager::set_u16(const char* key, uint16_t value) {
  if (!initialized_ || key == nullptr) return false;
  auto h = static_cast<nvs_handle_t>(reinterpret_cast<uintptr_t>(nvs_handle_));
  if (nvs_set_u16(h, nvs_key(key), value) != ESP_OK) return false;
  return nvs_commit(h) == ESP_OK;
}

}  // namespace shield
