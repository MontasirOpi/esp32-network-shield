#pragma once

// ConfigManager — NVS-backed configuration, namespace "shield" (CONTRACTS.md §3).
// Singleton. Setters commit immediately. api_token is generated on first boot
// (32 lowercase hex chars from esp_random()) if missing or empty.

#include <cstddef>
#include <cstdint>

namespace shield {

class ConfigManager {
 public:
  static ConfigManager& instance();

  // nvs_flash_init (erase on NO_FREE_PAGES / NEW_VERSION_FOUND) + nvs_open.
  // Generates api_token if missing/empty. Returns false on fatal NVS error.
  bool init();

  bool get_str(const char* key, char* out, size_t out_len) const;  // false if missing
  bool set_str(const char* key, const char* value);                // commits
  bool get_u32(const char* key, uint32_t* out) const;
  bool set_u32(const char* key, uint32_t value);                   // commits
  bool get_u8(const char* key, uint8_t* out) const;
  bool set_u8(const char* key, uint8_t value);                     // commits
  bool get_u16(const char* key, uint16_t* out) const;
  bool set_u16(const char* key, uint16_t value);                   // commits

  ConfigManager(const ConfigManager&) = delete;
  ConfigManager& operator=(const ConfigManager&) = delete;

 private:
  ConfigManager() = default;
  void ensure_api_token();

  mutable void* nvs_handle_ = nullptr;  // nvs_handle_t; void* keeps IDF type out of header
  bool initialized_ = false;
};

}  // namespace shield
