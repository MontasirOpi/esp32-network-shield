#pragma once

// One handler per REST/WebSocket route, registered by HttpServer.
// JSON shapes follow CONTRACTS.md §8 exactly. All handlers are plain
// functions (never members) so they fit httpd_uri_t::handler.

#include <esp_http_server.h>

#include "../network/dns_forwarder.h"

namespace shield {

// Dashboard + WebSocket
esp_err_t handle_root(httpd_req_t* req);  // GET /  (public)
esp_err_t handle_ws(httpd_req_t* req);    // GET /ws (auth; WS handshake)

// REST
esp_err_t api_get_status(httpd_req_t* req);            // GET  /api/status (public)
esp_err_t api_get_stats(httpd_req_t* req);             // GET  /api/stats
esp_err_t api_get_devices(httpd_req_t* req);           // GET  /api/devices
esp_err_t api_get_queries(httpd_req_t* req);           // GET  /api/queries?limit=
esp_err_t api_get_config(httpd_req_t* req);            // GET  /api/config
esp_err_t api_put_config(httpd_req_t* req);            // PUT  /api/config
esp_err_t api_get_blocklist(httpd_req_t* req);         // GET  /api/blocklist
esp_err_t api_post_blocklist_update(httpd_req_t* req);  // POST /api/blocklist/update
esp_err_t api_get_allowlist(httpd_req_t* req);         // GET  /api/allowlist
esp_err_t api_post_allowlist(httpd_req_t* req);        // POST /api/allowlist
esp_err_t api_delete_allowlist(httpd_req_t* req);      // DELETE /api/allowlist?domain=
esp_err_t api_get_rules(httpd_req_t* req);             // GET  /api/rules
esp_err_t api_post_rules(httpd_req_t* req);            // POST /api/rules
esp_err_t api_delete_rule(httpd_req_t* req);           // DELETE /api/rules/* (wildcard)
esp_err_t api_post_reboot(httpd_req_t* req);           // POST /api/reboot
esp_err_t api_post_ota(httpd_req_t* req);              // POST /api/ota

// Called by main.cpp after the DNS forwarder is created so that
// PUT /api/config can push new upstreams live via DnsForwarder::set_upstreams
// (no reboot required for upstream/timeout changes). May be left null.
void register_dns_forwarder(DnsForwarder* fwd);

}  // namespace shield
