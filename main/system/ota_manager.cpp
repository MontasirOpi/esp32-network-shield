#include "system/ota_manager.h"

#include <cstdlib>
#include <cstring>
#include <memory>

#include "esp_crt_bundle.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"  // esp_random() for the self-test query ID
#include "esp_system.h"  // esp_restart
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "network/dns_forwarder.h"
#include "system/config_manager.h"

namespace shield {

namespace {
constexpr const char* TAG = "ota";

// Builds a minimal DNS query for <labels> A IN. Returns length, 0 on overflow.
size_t build_a_query(const char* labels[], size_t nlabels, uint8_t* out, size_t cap) {
  uint8_t tmp[256];
  size_t n = 0;
  auto put16 = [&](uint16_t v) {
    if (n + 2 > sizeof(tmp)) return false;
    tmp[n++] = static_cast<uint8_t>(v >> 8);
    tmp[n++] = static_cast<uint8_t>(v & 0xFF);
    return true;
  };
  const uint16_t id = static_cast<uint16_t>(esp_random() & 0xFFFF);
  if (!put16(id) || !put16(0x0100) || !put16(1) || !put16(0) || !put16(0) || !put16(0))
    return 0;
  for (size_t i = 0; i < nlabels; ++i) {
    const size_t L = strlen(labels[i]);
    if (L == 0 || L > 63 || n + 1 + L + 5 > sizeof(tmp)) return 0;
    tmp[n++] = static_cast<uint8_t>(L);
    memcpy(tmp + n, labels[i], L);
    n += L;
  }
  if (n + 1 + 4 > sizeof(tmp)) return 0;
  tmp[n++] = 0;  // root label
  if (!put16(1) || !put16(1)) return 0;  // QTYPE=A, QCLASS=IN
  if (n > cap) return 0;
  memcpy(out, tmp, n);
  return n;
}
}  // namespace

OtaManager& OtaManager::instance() {
  static OtaManager inst;
  return inst;
}

bool OtaManager::begin(const char* url) {
  if (url == nullptr || url[0] == '\0') return false;
  char* copy = strdup(url);  // freed by the task
  if (copy == nullptr) return false;
  BaseType_t ok = xTaskCreate(ota_task, "ota", 8192, copy, 5, nullptr);
  if (ok != pdPASS) {
    free(copy);
    ESP_LOGE(TAG, "failed to start OTA task");
    return false;
  }
  ESP_LOGI(TAG, "OTA task started");
  return true;
}

void OtaManager::ota_task(void* arg) {
  char* url = static_cast<char*>(arg);
  esp_http_client_config_t http_cfg = {};
  http_cfg.url = url;
  http_cfg.timeout_ms = 30000;
  // Verify the server against the embedded CA bundle (IDF default); without
  // this an OTA image could be served by a MITM. Requires
  // CONFIG_MBEDTLS_CERTIFICATE_BUNDLE (default y in IDF v5).
  http_cfg.crt_bundle_attach = esp_crt_bundle_attach;
  esp_https_ota_config_t ota_cfg = {};
  ota_cfg.http_config = &http_cfg;

  ESP_LOGI(TAG, "starting OTA from %s", url);
  esp_err_t ret = esp_https_ota(&ota_cfg);
  free(url);

  if (ret == ESP_OK) {
    ESP_LOGI(TAG, "OTA image written OK; rebooting (app stays pending "
                  "until self-test confirms it)");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
  } else {
    ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(ret));
  }
  vTaskDelete(nullptr);
}

bool OtaManager::self_test_dns() {
  char primary[32] = "1.1.1.1";
  ConfigManager::instance().get_str("upstream_primary", primary, sizeof(primary));

  auto fwd = std::make_unique<DnsForwarder>();
  if (!fwd->init(primary, primary, 5000)) {  // 5 s timeout per task spec
    ESP_LOGW(TAG, "self-test: forwarder init failed");
    return false;
  }

  const char* labels[] = {"google", "com"};
  uint8_t req[256];
  const size_t req_len = build_a_query(labels, 2, req, sizeof(req));
  if (req_len == 0) return false;

  auto resp = std::make_unique<uint8_t[]>(1500);
  size_t resp_len = 1500;
  uint32_t rtt_ms = 0;
  if (!fwd->forward(req, req_len, resp.get(), &resp_len, &rtt_ms)) {
    ESP_LOGW(TAG, "self-test: forward failed");
    return false;
  }
  if (resp_len < 12) return false;

  const uint16_t id_req = static_cast<uint16_t>((req[0] << 8) | req[1]);
  const uint16_t id_resp = static_cast<uint16_t>((resp[0] << 8) | resp[1]);
  if (id_req != id_resp) return false;         // transaction ID must match
  if ((resp[3] & 0x0F) != 0) return false;     // RCODE must be 0 (NOERROR)
  const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
  if (ancount == 0) return false;              // need at least one A answer

  ESP_LOGI(TAG, "self-test: google.com A resolved via %s in %lu ms",
           primary, static_cast<unsigned long>(rtt_ms));
  return true;
}

void OtaManager::confirm_boot_ok() {
  // IDF v5.1 renamed esp_ota_mark_app_valid() to
  // esp_ota_mark_app_valid_cancel_rollback().
  esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "app marked valid (self-test passed)");
  } else {
    ESP_LOGE(TAG, "esp_ota_mark_app_valid_cancel_rollback failed: %s",
             esp_err_to_name(err));
  }
}

}  // namespace shield
