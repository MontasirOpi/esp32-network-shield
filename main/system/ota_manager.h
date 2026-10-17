#pragma once

// OtaManager — esp_https_ota wrapper with anti-brick rollback (CONTRACTS.md §7).
// begin(url) downloads in a background task and reboots on success.
// confirm_boot_ok() calls esp_ota_mark_app_valid_cancel_rollback() and must ONLY be called
// after self_test_dns() passes (main spawns the self-test ~30 s after boot);
// otherwise the bootloader rolls back to the previous app on next reset.

#include <cstdint>

namespace shield {

class DnsForwarder;

class OtaManager {
 public:
  static OtaManager& instance();

  // Starts an OTA download from url in a background task. On success the
  // device reboots into the new image (still marked pending until the
  // self-test confirms it). Returns false if the task could not start.
  bool begin(const char* url);

  // Self-test: resolves "google.com" A via the primary upstream through
  // DnsForwarder with a 5 s timeout. True only on a valid A response
  // (matching transaction ID, RCODE 0, ANCOUNT > 0). If forwarder is supplied,
  // reuses its existing socket instead of opening a new one.
  bool self_test_dns(DnsForwarder* forwarder = nullptr);

  // Called by main after self_test_dns() passes.
  void confirm_boot_ok();

  OtaManager(const OtaManager&) = delete;
  OtaManager& operator=(const OtaManager&) = delete;

 private:
  OtaManager() = default;
  static void ota_task(void* arg);
};

}  // namespace shield
