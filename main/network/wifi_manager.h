#pragma once

// Wi-Fi manager (singleton): STA client when credentials exist in NVS, else a
// first-boot provisioning AP ("ESP32-Shield-XXXX") with a captive portal.
//
// Provisioning mode runs a DnsServer that hijacks EVERY query to the AP IP plus
// a minimal esp_http_server: GET / serves the setup form, POST /setup saves
// wifi_ssid/wifi_pass/device_name to NVS and reboots. Auto-reconnects on STA
// disconnect via the Wi-Fi event handler.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_bit_defs.h"  // BIT0 for the event-group bit
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"

#include "dns_server.h"
#include "../system/config_manager.h"

namespace shield {

class WifiManager {
 public:
  static WifiManager& instance();

  // Reads ConfigManager (NVS "shield"): if wifi_ssid is non-empty, starts STA
  // and waits up to 15 s for an IP; otherwise starts the provisioning AP +
  // captive portal. Returns true if an IP was obtained (STA) or the AP is up.
  // Background auto-reconnect keeps running regardless of the return value.
  bool init();

  // True once IP_EVENT_STA_GOT_IP has fired and no disconnect since.
  bool is_connected() const;

  // Dotted-quad of the STA interface (or the AP interface in provisioning
  // mode). out must hold at least 16 bytes. Returns false if unavailable.
  bool get_ip(char* out, size_t len) const;

  // RSSI of the associated AP in dBm, or 0 when not connected.
  int8_t rssi() const;

 private:
  WifiManager();
  ~WifiManager() = default;
  WifiManager(const WifiManager&) = delete;
  WifiManager& operator=(const WifiManager&) = delete;

  static constexpr EventBits_t kGotIpBit = BIT0;

  bool net_init_common();
  bool start_sta(const char* ssid, const char* pass);
  bool start_provisioning_ap(const char* device_name);

  static void event_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data);
  static esp_err_t portal_root_handler(httpd_req_t* req);
  static esp_err_t portal_setup_handler(httpd_req_t* req);
  static void restart_task(void* arg);

  EventGroupHandle_t events_ = nullptr;
  esp_netif_t* sta_netif_ = nullptr;
  esp_netif_t* ap_netif_ = nullptr;
  esp_event_handler_instance_t wifi_evt_ = nullptr;
  esp_event_handler_instance_t ip_evt_ = nullptr;
  std::atomic<bool> connected_{false};
  bool provisioning_ = false;
  uint32_t ap_ip_ = 0;  // AP interface IPv4, network byte order

  DnsServer portal_dns_;          // captive-portal DNS hijack
  httpd_handle_t portal_ = nullptr;
};

}  // namespace shield
