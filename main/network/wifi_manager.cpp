#include "wifi_manager.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/task.h"
#include "lwip/inet.h"  // htonl for the AP-IP fallback constant

namespace shield {

namespace {
const char* TAG = "wifi_manager";

// Fallback AP address 192.168.4.1 as a host-order constant; htonl() is
// applied where it is used so the in-memory bytes are network order
// (matching esp_netif_ip_info_t::ip.addr).
constexpr uint32_t kDefaultApIp = 0xC0A80401;

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
    ESP_LOGI(TAG, "STA disconnected; reconnecting...");
    esp_wifi_connect();  // auto-reconnect
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    auto* evt = static_cast<ip_event_got_ip_t*>(event_data);
    self->connected_.store(true);
    if (self->events_) {
      xEventGroupSetBits(self->events_, kGotIpBit);
    }
    ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&evt->ip_info.ip));
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
  ESP_LOGI(TAG, "provisioning AP '%s' up; portal at http://" IPSTR, ap_ssid,
           IP2STR(&ip_info.ip));
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
  cfg.get_str("wifi_ssid", ssid, sizeof(ssid));
  cfg.get_str("wifi_pass", pass, sizeof(pass));
  cfg.get_str("device_name", devname, sizeof(devname));
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

  if (ssid[0] != '\0') {
    return start_sta(ssid, pass);
  }
  ESP_LOGI(TAG, "no Wi-Fi credentials; entering provisioning AP mode");
  return start_provisioning_ap(devname);
}

bool WifiManager::is_connected() const { return connected_.load(); }

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
