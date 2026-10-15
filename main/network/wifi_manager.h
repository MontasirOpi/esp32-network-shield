#pragma once

// Wi-Fi manager (singleton), now with two operating modes (NVS "mode").
//
// "dns" (default): STA client when credentials exist in NVS, else a first-boot
// provisioning AP ("ESP32-Shield-XXXX", open) with a captive portal. This is
// the original router-DNS behavior and is unchanged.
//
// "travel": concurrent AP+STA (WIFI_MODE_APSTA) for zero-router-admin use.
//   - STA joins the upstream home/hotel/cafe Wi-Fi (same provisioning flow).
//   - AP "Shield-XXXX" (WPA2, password in NVS "ap_pass", generated on first
//     boot) serves client devices; its DHCP server advertises the ESP32's AP
//     IP as the DNS server, and NAPT on the STA interface routes AP clients
//     to the internet through the STA uplink.
//   - With no STA credentials yet, the travel AP doubles as the provisioning
//     AP (same SSID/password); after the portal saves credentials and the
//     device reboots, the AP persists so joined clients stay connected.
//   - WPS push-button provisioning is available in travel mode via start_wps().
//
// Provisioning mode (either mode, no STA credentials) runs a DnsServer that
// hijacks EVERY query to the AP IP plus a minimal esp_http_server:
// GET / serves the setup form, POST /setup saves wifi_ssid/wifi_pass/
// device_name to NVS and reboots. Auto-reconnects on STA disconnect via the
// Wi-Fi event handler.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_bit_defs.h"  // BIT0 for the event-group bit
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_wifi_types.h"  // wifi_event_sta_wps_er_success_t (WPS enrollee)

#include "dns_server.h"
#include "../system/config_manager.h"

namespace shield {

class WifiManager {
 public:
  static WifiManager& instance();

  // Mode-aware init. Reads ConfigManager (NVS "shield"):
  //   mode="dns"    → start_sta() if wifi_ssid set, else start_provisioning_ap()
  //   mode="travel" → start_travel(): AP+STA; provisioning portal on the
  //                   travel AP when no STA credentials exist yet.
  // Returns true if an IP was obtained (STA) or an AP is up. Background
  // auto-reconnect keeps running regardless of the return value.
  bool init();

  // True once IP_EVENT_STA_GOT_IP has fired and no disconnect since.
  bool is_connected() const;

  // Dotted-quad of the STA interface (or the AP interface in provisioning
  // mode). out must hold at least 16 bytes. Returns false if unavailable.
  bool get_ip(char* out, size_t len) const;

  // RSSI of the associated AP in dBm, or 0 when not connected.
  int8_t rssi() const;

  // ---- travel mode ----
  // True when init() brought up the travel AP+STA interface pair.
  bool travel_active() const;
  // Dotted-quad of the travel AP interface (e.g. "192.168.4.1").
  bool get_ap_ip(char* out, size_t len) const;
  // Effective travel AP SSID ("Shield-XXXX" or the configured ap_ssid).
  bool get_ap_ssid(char* out, size_t len) const;
  // Stations currently associated to the AP, or -1 if the AP isn't up.
  int ap_client_count() const;
  // True while a WPS session started by start_wps() is in progress.
  bool wps_active() const;

  // WPS push-button provisioning (travel mode only). The STA interface must
  // be up and idle (not connected). On success the received credentials are
  // saved to NVS and the device reboots into travel AP+STA. Returns false
  // when not in travel mode, already connected, or a session is running.
  // The user must press the WPS button on their router within ~2 minutes.
  bool start_wps();

 private:
  WifiManager();
  ~WifiManager() = default;
  WifiManager(const WifiManager&) = delete;
  WifiManager& operator=(const WifiManager&) = delete;

  static constexpr EventBits_t kGotIpBit = BIT0;

  bool net_init_common();
  bool start_sta(const char* ssid, const char* pass);
  bool start_provisioning_ap(const char* device_name);
  // Travel mode: AP+STA. sta_ssid empty ⇒ STA stays idle and the captive
  // portal runs on the travel AP until credentials are provisioned.
  bool start_travel(const char* sta_ssid, const char* sta_pass);
  // Captive-portal services shared by both provisioning paths: DNS hijack
  // (all queries → AP IP) + minimal HTTP server (GET /, POST /setup).
  // Requires ap_netif_ to be up and ap_ip_ set.
  bool start_portal_services(const char* ap_ssid_for_log);
  // Idempotent: enables lwIP NAPT on the STA (upstream) interface.
  void enable_napt_once();
  // Reads NVS "ap_pass"; generates + stores a random one on first boot.
  void ensure_ap_password(char* out, size_t len);
  // Effective travel AP SSID: NVS "ap_ssid", or "Shield-XXXX" from the MAC.
  void effective_ap_ssid(char* out, size_t len);

  static void event_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data);
  // Handles WIFI_EVENT_STA_WPS_ER_SUCCESS: saves credentials, reboots.
  void on_wps_success(wifi_event_sta_wps_er_success_t* evt);
  static esp_err_t portal_root_handler(httpd_req_t* req);
  static esp_err_t portal_setup_handler(httpd_req_t* req);
  static void restart_task(void* arg);

  EventGroupHandle_t events_ = nullptr;
  esp_netif_t* sta_netif_ = nullptr;
  esp_netif_t* ap_netif_ = nullptr;
  esp_event_handler_instance_t wifi_evt_ = nullptr;
  esp_event_handler_instance_t ip_evt_ = nullptr;
  std::atomic<bool> connected_{false};
  std::atomic<bool> travel_active_{false};
  std::atomic<bool> wps_active_{false};
  std::atomic<bool> napt_enabled_{false};
  bool provisioning_ = false;
  uint32_t ap_ip_ = 0;  // AP interface IPv4, network byte order
  char ap_ssid_[33] = {0};  // effective travel AP SSID ("" when AP not up)

  DnsServer portal_dns_;          // captive-portal DNS hijack
  httpd_handle_t portal_ = nullptr;
};

}  // namespace shield
