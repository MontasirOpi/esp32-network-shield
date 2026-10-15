#include "wifi_manager.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wps.h"
#include "freertos/task.h"
#include "lwip/inet.h"  // htonl for the AP-IP fallback constant

#include "../system/device_tracker.h"

namespace shield {

namespace {
const char* TAG = "wifi_manager";

// Fallback AP address 192.168.4.1 as a host-order constant; htonl() is
// applied where it is used so the in-memory bytes are network order
// (matching esp_netif_ip_info_t::ip.addr).
constexpr uint32_t kDefaultApIp = 0xC0A80401;

// Alphabet for generated AP passwords: unambiguous chars only
// (no 0/O, 1/l/I) so they can be read off the serial log reliably.
constexpr const char* kPassAlphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
constexpr int kApPassLen = 12;

// ---------------------------------------------------------------------------
// Captive-portal DNS hijack.
//
// Builds a response that answers ANY query with a single A record pointing at
// the AP IP. Deliberately self-contained: the network layer does not depend on
// core/dns_codec, so the provisioning portal works even if core changes.
//
// Layout: 12-byte header (ID echo, flags 0x8180, QD=1 AN=1 NS=0 AR=0) +
// question section echoed verbatim + fixed 16-byte A answer (name pointer
// 0xC00C, TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, RDATA=ap_ip).
// Returns the response length, or 0 if the question section is malformed
// (caller then stays silent).
// ---------------------------------------------------------------------------
size_t build_hijack_response(const uint8_t* req, size_t req_len,
                             uint32_t ap_ip_net_order, uint8_t* out,
                             size_t out_cap) {
  if (req_len < 12 || out_cap < 12 + 16 + 5) {
    return 0;
  }
  // Walk the QNAME labels: <len><bytes>... terminated by a zero length octet.
  size_t pos = 12;
  while (pos < req_len) {
    uint8_t lab = req[pos];
    if (lab == 0) {
      pos += 1;
      break;
    }
    if (lab & 0xC0) {
      return 0;  // compression pointers never appear in a query question
    }
    if (pos + 1 + lab > req_len || pos - 12 > 255) {
      return 0;  // truncated label or absurdly long name
    }
    pos += 1 + lab;
  }
  if (pos + 4 > req_len) {
    return 0;  // need QTYPE + QCLASS
  }
  size_t qlen = (pos + 4) - 12;
  size_t total = 12 + qlen + 16;
  if (total > out_cap) {
    return 0;
  }

  out[0] = req[0];
  out[1] = req[1];          // transaction ID echo
  out[2] = 0x81;
  out[3] = 0x80;            // response, RD+RA, NOERROR
  out[4] = 0x00;
  out[5] = 0x01;            // QDCOUNT = 1
  out[6] = 0x00;
  out[7] = 0x01;            // ANCOUNT = 1
  out[8] = 0x00;
  out[9] = 0x00;            // NSCOUNT = 0
  out[10] = 0x00;
  out[11] = 0x00;           // ARCOUNT = 0
  memcpy(out + 12, req + 12, qlen);  // question echo, verbatim

  uint8_t* a = out + 12 + qlen;
  a[0] = 0xC0;
  a[1] = 0x0C;  // NAME: pointer to the QNAME at offset 12
  a[2] = 0x00;
  a[3] = 0x01;  // TYPE = A
  a[4] = 0x00;
  a[5] = 0x01;  // CLASS = IN
  a[6] = 0x00;
  a[7] = 0x00;
  a[8] = 0x00;
  a[9] = 0x3C;  // TTL = 60 s (short: portal answers shouldn't linger)
  a[10] = 0x00;
  a[11] = 0x04;  // RDLENGTH = 4
  memcpy(a + 12, &ap_ip_net_order, 4);
  return total;
}

// Builds an httpd_uri_t without triggering -Wmissing-field-initializers:
// value-initialize everything, then assign the fields we care about.
httpd_uri_t make_uri(const char* uri, httpd_method_t method,
                     esp_err_t (*handler)(httpd_req_t*), void* user_ctx) {
  httpd_uri_t r = {};
  r.uri = uri;
  r.method = method;
  r.handler = handler;
  r.user_ctx = user_ctx;
  return r;
}

// Provisioning setup page served at GET /.
const char kSetupPage[] =
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>ESP32 Shield Setup</title>"
    "<style>body{font-family:sans-serif;max-width:420px;margin:2em auto;"
    "padding:0 1em}input{width:100%;padding:.6em;margin:.4em 0;"
    "box-sizing:border-box}button{width:100%;padding:.7em;background:#1a73e8;"
    "color:#fff;border:0;border-radius:4px;font-size:1em}</style></head>"
    "<body><h2>ESP32 Network Shield</h2>"
    "<p>Enter your Wi-Fi details. The device will reboot and connect.</p>"
    "<form method=\"POST\" action=\"/setup\">"
    "<label>Wi-Fi SSID<input name=\"ssid\" maxlength=\"32\" required></label>"
    "<label>Password<input name=\"pass\" type=\"password\" maxlength=\"64\">"
    "</label><label>Device name<input name=\"device\" maxlength=\"32\" "
    "value=\"esp32-shield\"></label>"
    "<button type=\"submit\">Save &amp; Reboot</button>"
    "</form></body></html>";

}  // namespace

WifiManager::WifiManager() = default;

WifiManager& WifiManager::instance() {
  static WifiManager inst;
  return inst;
}

bool WifiManager::net_init_common() {
  esp_err_t err = esp_netif_init();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    ESP_LOGE(TAG, "esp_netif_init: %s", esp_err_to_name(err));
    return false;
  }
  err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    ESP_LOGE(TAG, "esp_event_loop_create_default: %s", esp_err_to_name(err));
    return false;
  }
  return true;
}

void WifiManager::event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
  auto* self = static_cast<WifiManager*>(arg);
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {
    self->connected_.store(false);
    if (self->events_) {
      xEventGroupClearBits(self->events_, kGotIpBit);
    }
    // Don't fight an in-progress WPS handshake with reconnect attempts.
    if (self->wps_active_.load()) {
      ESP_LOGI(TAG, "STA disconnected during WPS; leaving the session alone");
    } else {
      ESP_LOGI(TAG, "STA disconnected; reconnecting...");
      esp_wifi_connect();  // auto-reconnect
    }
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    auto* evt = static_cast<ip_event_got_ip_t*>(event_data);
    self->connected_.store(true);
    if (self->events_) {
      xEventGroupSetBits(self->events_, kGotIpBit);
    }
    ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&evt->ip_info.ip));
    if (self->travel_active_.load()) {
      self->enable_napt_once();  // AP clients need NAT once the uplink is up
    }
  } else if (event_base == IP_EVENT &&
             event_id == IP_EVENT_AP_STAIPASSIGNED) {
    // Travel mode: the DHCP server just leased an IP to an AP client.
    // Record MAC+IP so the device tracker shows real clients, not just IPs.
    auto* evt = static_cast<ip_event_ap_staipassigned_t*>(event_data);
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", evt->mac[0],
             evt->mac[1], evt->mac[2], evt->mac[3], evt->mac[4], evt->mac[5]);
    DeviceTracker::instance().note_client(evt->ip.addr, mac);
    ESP_LOGI(TAG, "AP client joined: %s (" IPSTR ")", mac, IP2STR(&evt->ip));
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_WPS_ER_SUCCESS) {
    self->on_wps_success(
        static_cast<wifi_event_sta_wps_er_success_t*>(event_data));
  } else if (event_base == WIFI_EVENT &&
             (event_id == WIFI_EVENT_STA_WPS_ER_FAILED ||
              event_id == WIFI_EVENT_STA_WPS_ER_TIMEOUT ||
              event_id == WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP)) {
    ESP_LOGW(TAG, "WPS failed/timeout (event %ld); use the captive portal instead",
             (long)event_id);
    esp_wifi_wps_disable();
    self->wps_active_.store(false);
  }
}

bool WifiManager::start_sta(const char* ssid, const char* pass) {
  sta_netif_ = esp_netif_create_default_wifi_sta();
  if (!sta_netif_) {
    ESP_LOGE(TAG, "esp_netif_create_default_wifi_sta failed");
    return false;
  }

  wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&wcfg) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_init failed");
    return false;
  }
  // RAM storage: ConfigManager (NVS "shield") is the single source of truth
  // for credentials; don't also persist them in the IDF wifi NVS blob.
  esp_wifi_set_storage(WIFI_STORAGE_RAM);

  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                      &WifiManager::event_handler, this,
                                      &wifi_evt_);
  esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                      &WifiManager::event_handler, this,
                                      &ip_evt_);

  if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_mode(STA) failed");
    return false;
  }
  wifi_config_t wc = {};
  strncpy(reinterpret_cast<char*>(wc.sta.ssid), ssid, sizeof(wc.sta.ssid) - 1);
  strncpy(reinterpret_cast<char*>(wc.sta.password), pass ? pass : "",
          sizeof(wc.sta.password) - 1);
  // Default auth threshold (open) so open networks also work.
  if (esp_wifi_set_config(WIFI_IF_STA, &wc) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_config(STA) failed");
    return false;
  }
  if (esp_wifi_start() != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_start failed");
    return false;
  }
  // esp_wifi_connect() is issued from the WIFI_EVENT_STA_START handler.

  ESP_LOGI(TAG, "STA started, joining '%s'...", ssid);
  EventBits_t bits = xEventGroupWaitBits(events_, kGotIpBit, pdFALSE, pdTRUE,
                                         pdMS_TO_TICKS(15000));
  if (bits & kGotIpBit) {
    ESP_LOGI(TAG, "STA connected");
    return true;
  }
  ESP_LOGW(TAG, "no IP within 15 s; background auto-reconnect continues");
  return false;
}

// Shared by start_provisioning_ap() (dns mode) and start_travel() (travel
// mode without STA credentials): DNS hijack (every query → AP IP) + minimal
// HTTP server (GET / setup form, POST /setup saves + reboots).
// Requires ap_netif_ up and ap_ip_ already populated.
bool WifiManager::start_portal_services(const char* ap_ssid_for_log) {
  // Captive portal DNS: hijack EVERY query to the AP IP.
  portal_dns_.set_query_handler(
      [this](const uint8_t* req, size_t req_len, uint32_t client_ip,
             uint8_t* resp, size_t* resp_len) -> bool {
        (void)client_ip;
        size_t n = build_hijack_response(req, req_len, ap_ip_, resp,
                                         DnsServer::kMaxMessage);
        if (n == 0) {
          return false;
        }
        *resp_len = n;
        return true;
      });
  if (!portal_dns_.start(53)) {
    ESP_LOGE(TAG, "portal DNS server failed to start");
    return false;
  }

  httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
  hcfg.uri_match_fn = httpd_uri_match_wildcard;
  if (httpd_start(&portal_, &hcfg) != ESP_OK) {
    ESP_LOGE(TAG, "httpd_start failed");
    portal_dns_.stop();
    return false;
  }
  const httpd_uri_t root = make_uri("/", HTTP_GET,
                                    &WifiManager::portal_root_handler, this);
  const httpd_uri_t setup = make_uri("/setup", HTTP_POST,
                                     &WifiManager::portal_setup_handler, this);
  httpd_register_uri_handler(portal_, &root);
  httpd_register_uri_handler(portal_, &setup);

  provisioning_ = true;
  esp_ip4_addr_t a;
  a.addr = ap_ip_;
  char ip_str[16] = "?";
  esp_ip4addr_ntoa(&a, ip_str, sizeof(ip_str));
  ESP_LOGI(TAG, "provisioning portal on AP '%s': open http://%s",
           ap_ssid_for_log, ip_str);
  return true;
}

bool WifiManager::start_provisioning_ap(const char* device_name) {
  (void)device_name;
  ap_netif_ = esp_netif_create_default_wifi_ap();
  if (!ap_netif_) {
    ESP_LOGE(TAG, "esp_netif_create_default_wifi_ap failed");
    return false;
  }

  wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&wcfg) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_init failed");
    return false;
  }
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                      &WifiManager::event_handler, this,
                                      &wifi_evt_);

  // SSID "ESP32-Shield-XXXX": XXXX = last 2 bytes of the STA MAC as hex.
  uint8_t mac[6] = {0};
  char ap_ssid[32];
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
    snprintf(ap_ssid, sizeof(ap_ssid), "ESP32-Shield-%02X%02X", mac[4], mac[5]);
  } else {
    ESP_LOGW(TAG, "esp_read_mac failed; using fallback SSID");
    snprintf(ap_ssid, sizeof(ap_ssid), "ESP32-Shield-0000");
  }

  if (esp_wifi_set_mode(WIFI_MODE_AP) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_mode(AP) failed");
    return false;
  }
  wifi_config_t wc = {};
  strncpy(reinterpret_cast<char*>(wc.ap.ssid), ap_ssid, sizeof(wc.ap.ssid) - 1);
  wc.ap.ssid_len = strlen(ap_ssid);
  wc.ap.channel = 6;
  wc.ap.authmode = WIFI_AUTH_OPEN;
  wc.ap.max_connection = 8;
  if (esp_wifi_set_config(WIFI_IF_AP, &wc) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_config(AP) failed");
    return false;
  }
  if (esp_wifi_start() != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_start(AP) failed");
    return false;
  }

  // AP IP (normally 192.168.4.1); read the real value from the netif.
  ap_ip_ = htonl(kDefaultApIp);
  esp_netif_ip_info_t ip_info = {};
  if (esp_netif_get_ip_info(ap_netif_, &ip_info) == ESP_OK &&
      ip_info.ip.addr != 0) {
    ap_ip_ = ip_info.ip.addr;
  }

  if (!start_portal_services(ap_ssid)) {
    return false;
  }
  ESP_LOGI(TAG, "provisioning AP '%s' up (open network)", ap_ssid);
  return true;
}

void WifiManager::ensure_ap_password(char* out, size_t len) {
  auto& cm = ConfigManager::instance();
  char cur[65] = {0};
  if (cm.get_str("ap_pass", cur, sizeof(cur)) && cur[0] != '\0') {
    strncpy(out, cur, len - 1);
    out[len - 1] = '\0';
    return;
  }
  // First boot: generate a 12-char password from unambiguous alphabet.
  const size_t alpha_len = strlen(kPassAlphabet);
  char gen[kApPassLen + 1];
  for (int i = 0; i < kApPassLen; ++i) {
    gen[i] = kPassAlphabet[esp_random() % alpha_len];
  }
  gen[kApPassLen] = '\0';
  if (cm.set_str("ap_pass", gen)) {
    ESP_LOGI(TAG, "generated travel AP password (first boot)");
  } else {
    ESP_LOGE(TAG, "failed to store generated ap_pass; using RAM-only value");
  }
  strncpy(out, gen, len - 1);
  out[len - 1] = '\0';
}

void WifiManager::effective_ap_ssid(char* out, size_t len) {
  auto& cm = ConfigManager::instance();
  char cfg[33] = {0};
  if (cm.get_str("ap_ssid", cfg, sizeof(cfg)) && cfg[0] != '\0') {
    strncpy(out, cfg, len - 1);
    out[len - 1] = '\0';
    return;
  }
  // Default "Shield-XXXX": XXXX = last 2 bytes of the STA MAC as hex.
  uint8_t mac[6] = {0};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
    snprintf(out, len, "Shield-%02X%02X", mac[4], mac[5]);
  } else {
    ESP_LOGW(TAG, "esp_read_mac failed; using fallback AP SSID");
    snprintf(out, len, "Shield-0000");
  }
}

void WifiManager::enable_napt_once() {
  bool expected = false;
  if (!napt_enabled_.compare_exchange_strong(expected, true)) {
    return;  // already enabled
  }
  if (sta_netif_ == nullptr) {
    napt_enabled_.store(false);
    return;
  }
  // NAT the AP subnet out through the STA uplink (requires
  // CONFIG_LWIP_IPV4_NAPT=y). AP clients reach the internet via the STA IP.
  const esp_err_t err = esp_netif_napt_enable(sta_netif_);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "esp_netif_napt_enable failed: %s (retry on next GOT_IP)",
             esp_err_to_name(err));
    napt_enabled_.store(false);  // allow a retry on the next GOT_IP
  } else {
    ESP_LOGI(TAG, "NAPT enabled: AP clients route through the STA uplink");
  }
}

bool WifiManager::start_travel(const char* sta_ssid, const char* sta_pass) {
  sta_netif_ = esp_netif_create_default_wifi_sta();
  ap_netif_ = esp_netif_create_default_wifi_ap();
  if (!sta_netif_ || !ap_netif_) {
    ESP_LOGE(TAG, "failed to create STA/AP netifs");
    return false;
  }

  wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&wcfg) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_init failed");
    return false;
  }
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                      &WifiManager::event_handler, this,
                                      &wifi_evt_);
  // ANY_ID (not just STA_GOT_IP): we also need IP_EVENT_AP_STAIPASSIGNED
  // for MAC tracking of AP clients.
  esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                      &WifiManager::event_handler, this,
                                      &ip_evt_);

  if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_mode(APSTA) failed");
    return false;
  }

  const bool have_sta = sta_ssid != nullptr && sta_ssid[0] != '\0';
  if (have_sta) {
    wifi_config_t stacfg = {};
    strncpy(reinterpret_cast<char*>(stacfg.sta.ssid), sta_ssid,
            sizeof(stacfg.sta.ssid) - 1);
    strncpy(reinterpret_cast<char*>(stacfg.sta.password), sta_pass ? sta_pass : "",
            sizeof(stacfg.sta.password) - 1);
    if (esp_wifi_set_config(WIFI_IF_STA, &stacfg) != ESP_OK) {
      ESP_LOGE(TAG, "esp_wifi_set_config(STA) failed");
      return false;
    }
  }

  char ap_ssid[33] = {0};
  char ap_pass[65] = {0};
  effective_ap_ssid(ap_ssid, sizeof(ap_ssid));
  ensure_ap_password(ap_pass, sizeof(ap_pass));
  strncpy(ap_ssid_, ap_ssid, sizeof(ap_ssid_) - 1);

  wifi_config_t apcfg = {};
  strncpy(reinterpret_cast<char*>(apcfg.ap.ssid), ap_ssid,
          sizeof(apcfg.ap.ssid) - 1);
  apcfg.ap.ssid_len = strlen(ap_ssid);
  strncpy(reinterpret_cast<char*>(apcfg.ap.password), ap_pass,
          sizeof(apcfg.ap.password) - 1);
  apcfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
  apcfg.ap.channel = 6;  // driver moves the AP onto the STA channel on connect
  apcfg.ap.max_connection = 8;
  if (esp_wifi_set_config(WIFI_IF_AP, &apcfg) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_set_config(AP) failed");
    return false;
  }

  if (esp_wifi_start() != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_start(APSTA) failed");
    return false;
  }
  // esp_wifi_connect() for the STA side is issued from WIFI_EVENT_STA_START.

  // AP IP (normally 192.168.4.1); read the real value from the netif.
  ap_ip_ = htonl(kDefaultApIp);
  esp_netif_ip_info_t ip_info = {};
  if (esp_netif_get_ip_info(ap_netif_, &ip_info) == ESP_OK &&
      ip_info.ip.addr != 0) {
    ap_ip_ = ip_info.ip.addr;
  }

  // DHCP on the default AP netif auto-starts with the interface, and its
  // DNS-server option defaults to the AP's own IP — exactly what travel mode
  // needs, so joining clients use the Shield as their DNS server with zero
  // manual setup. (Deliberately no esp_netif_dhcps_option() call: setting
  // options fails once the server is running, and forcing the OFFER_DNS flag
  // would switch the offered address to the unset dns_server field = 0.0.0.0.)

  travel_active_.store(true);

  if (!have_sta) {
    // No upstream credentials yet: the travel AP doubles as the provisioning
    // AP (same SSID/password). After the portal saves credentials and the
    // device reboots, the AP persists — joined clients stay connected.
    if (!start_portal_services(ap_ssid)) {
      return false;
    }
  } else {
    ESP_LOGI(TAG, "travel STA: joining '%s'...", sta_ssid);
    const EventBits_t bits = xEventGroupWaitBits(
        events_, kGotIpBit, pdFALSE, pdTRUE, pdMS_TO_TICKS(15000));
    if (bits & kGotIpBit) {
      enable_napt_once();  // also armed in the GOT_IP handler for reconnects
    } else {
      ESP_LOGW(TAG, "no STA IP within 15 s; background reconnect continues — "
                    "AP clients get internet once the uplink is up");
    }
  }

  char ip_str[16] = "?";
  esp_ip4_addr_t a;
  a.addr = ap_ip_;
  esp_ip4addr_ntoa(&a, ip_str, sizeof(ip_str));
  ESP_LOGI(TAG, "travel AP '%s' up (WPA2) at %s — password: %s", ap_ssid, ip_str,
           ap_pass);
  ESP_LOGI(TAG, "note: ESP32 NAT throughput is limited (~tens of Mbps); fine "
                "for browsing/streaming, not a gigabit replacement");
  return true;
}

bool WifiManager::init() {
  auto& cfg = ConfigManager::instance();
  if (!cfg.init()) {
    ESP_LOGW(TAG, "ConfigManager::init failed; continuing with defaults");
  }
  char ssid[33] = {0};
  char pass[65] = {0};
  char devname[64] = {0};
  char mode[16] = {0};
  cfg.get_str("wifi_ssid", ssid, sizeof(ssid));
  cfg.get_str("wifi_pass", pass, sizeof(pass));
  cfg.get_str("device_name", devname, sizeof(devname));
  cfg.get_str("mode", mode, sizeof(mode));  // missing/unknown ⇒ "dns"
  if (devname[0] == '\0') {
    strncpy(devname, "esp32-shield", sizeof(devname) - 1);
  }

  events_ = xEventGroupCreate();
  if (!events_) {
    ESP_LOGE(TAG, "event group create failed");
    return false;
  }
  if (!net_init_common()) {
    return false;
  }

  if (strcmp(mode, "travel") == 0) {
    ESP_LOGI(TAG, "mode=travel: starting AP+STA");
    return start_travel(ssid, pass);
  }
  if (ssid[0] != '\0') {
    return start_sta(ssid, pass);
  }
  ESP_LOGI(TAG, "no Wi-Fi credentials; entering provisioning AP mode");
  return start_provisioning_ap(devname);
}

bool WifiManager::is_connected() const { return connected_.load(); }

bool WifiManager::travel_active() const { return travel_active_.load(); }

bool WifiManager::wps_active() const { return wps_active_.load(); }

bool WifiManager::get_ip(char* out, size_t len) const {
  if (!out || len < 16) {
    return false;
  }
  esp_netif_t* nif = provisioning_ ? ap_netif_ : sta_netif_;
  if (!nif) {
    return false;
  }
  esp_netif_ip_info_t info = {};
  if (esp_netif_get_ip_info(nif, &info) != ESP_OK) {
    return false;
  }
  esp_ip4addr_ntoa(&info.ip, out, len);
  return true;
}

bool WifiManager::get_ap_ip(char* out, size_t len) const {
  if (!out || len < 16 || ap_netif_ == nullptr) {
    return false;
  }
  esp_netif_ip_info_t info = {};
  if (esp_netif_get_ip_info(ap_netif_, &info) != ESP_OK) {
    return false;
  }
  esp_ip4addr_ntoa(&info.ip, out, len);
  return true;
}

bool WifiManager::get_ap_ssid(char* out, size_t len) const {
  if (!out || len == 0 || ap_ssid_[0] == '\0') {
    return false;
  }
  strncpy(out, ap_ssid_, len - 1);
  out[len - 1] = '\0';
  return true;
}

int WifiManager::ap_client_count() const {
  if (ap_netif_ == nullptr) {
    return -1;
  }
  wifi_sta_list_t list = {};
  if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) {
    return -1;
  }
  return static_cast<int>(list.num);
}

int8_t WifiManager::rssi() const {
  if (!connected_.load()) {
    return 0;
  }
  wifi_ap_record_t ap = {};
  if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
    return 0;
  }
  return ap.rssi;
}

bool WifiManager::start_wps() {
  if (!travel_active_.load()) {
    ESP_LOGW(TAG, "WPS is only available in travel mode");
    return false;
  }
  if (connected_.load()) {
    ESP_LOGW(TAG, "WPS refused: STA already connected");
    return false;
  }
  bool expected = false;
  if (!wps_active_.compare_exchange_strong(expected, true)) {
    ESP_LOGW(TAG, "WPS session already in progress");
    return false;
  }
  esp_wps_config_t wps_cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PBC);
  if (esp_wifi_wps_enable(&wps_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_wps_enable failed");
    wps_active_.store(false);
    return false;
  }
  if (esp_wifi_wps_start(0) != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_wps_start failed");
    esp_wifi_wps_disable();
    wps_active_.store(false);
    return false;
  }
  ESP_LOGI(TAG, "WPS PBC started: press the WPS button on the upstream router "
                "within ~2 minutes");
  return true;
}

void WifiManager::on_wps_success(wifi_event_sta_wps_er_success_t* evt) {
  wps_active_.store(false);
  esp_wifi_wps_disable();
  if (evt == nullptr || evt->ap_cred_cnt == 0) {
    ESP_LOGE(TAG, "WPS succeeded but carried no credentials");
    return;
  }
  // Credential arrays are fixed-size and may not be NUL-terminated.
  char ssid[33] = {0};
  char pass[65] = {0};
  memcpy(ssid, evt->ap_cred[0].ssid, MAX_SSID_LEN);
  memcpy(pass, evt->ap_cred[0].passphrase, MAX_PASSPHRASE_LEN);
  ssid[sizeof(ssid) - 1] = '\0';
  pass[sizeof(pass) - 1] = '\0';
  if (ssid[0] == '\0') {
    ESP_LOGE(TAG, "WPS returned an empty SSID");
    return;
  }
  auto& cm = ConfigManager::instance();
  if (!cm.set_str("wifi_ssid", ssid) || !cm.set_str("wifi_pass", pass)) {
    ESP_LOGE(TAG, "failed to save WPS credentials to NVS");
    return;
  }
  ESP_LOGI(TAG, "WPS success: credentials for '%s' saved; rebooting into "
                "travel AP+STA",
           ssid);
  xTaskCreate(&WifiManager::restart_task, "wifi_restart", 2048, nullptr, 5,
              nullptr);
}

esp_err_t WifiManager::portal_root_handler(httpd_req_t* req) {
  httpd_resp_set_type(req, "text/html");
  return httpd_resp_send(req, kSetupPage, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WifiManager::portal_setup_handler(httpd_req_t* req) {
  auto* self = static_cast<WifiManager*>(req->user_ctx);
  (void)self;
  if (req->content_len <= 0 || req->content_len > 2048) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  char* body = static_cast<char*>(malloc(req->content_len + 1));
  if (!body) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  // httpd_req_recv may return short reads; loop until the body is complete.
  size_t got = 0;
  while (got < req->content_len) {
    int r = httpd_req_recv(req, body + got, req->content_len - got);
    if (r <= 0) {
      break;
    }
    got += static_cast<size_t>(r);
  }
  body[got] = '\0';

  char ssid[33] = {0};
  char pass[65] = {0};
  char dev[64] = {0};
  // httpd_query_key_value URL-decodes into the destination buffers.
  bool ok = httpd_query_key_value(body, "ssid", ssid, sizeof(ssid)) == ESP_OK &&
            ssid[0] != '\0';
  httpd_query_key_value(body, "pass", pass, sizeof(pass));    // may be empty
  httpd_query_key_value(body, "device", dev, sizeof(dev));    // may be empty
  free(body);

  if (!ok) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ssid is required");
    return ESP_FAIL;
  }
  if (dev[0] == '\0') {
    strncpy(dev, "esp32-shield", sizeof(dev) - 1);
  }

  auto& cm = ConfigManager::instance();
  bool saved = cm.set_str("wifi_ssid", ssid) &&
               cm.set_str("wifi_pass", pass) &&
               cm.set_str("device_name", dev);
  if (!saved) {
    ESP_LOGE(TAG, "failed to save provisioning config to NVS");
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "provisioning saved (ssid='%s', device='%s'); rebooting", ssid,
           dev);
  httpd_resp_set_type(req, "text/plain");
  httpd_resp_send(req, "Saved. Rebooting...", HTTPD_RESP_USE_STRLEN);
  // Reboot from a detached task so the HTTP response flushes first.
  xTaskCreate(&WifiManager::restart_task, "wifi_restart", 2048, nullptr, 5,
              nullptr);
  return ESP_OK;
}

void WifiManager::restart_task(void* arg) {
  (void)arg;
  vTaskDelay(pdMS_TO_TICKS(1500));
  esp_restart();
}

}  // namespace shield
