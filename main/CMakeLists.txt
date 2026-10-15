# ESP32 Network Shield — main component (CONTRACTS.md §9).
#
# SRCS lists every .cpp in the component:
#   core 5 (portable, zero IDF includes) + network 4 + filtering 4 +
#   storage 1 + web 2 + system 5 + main.cpp = 22 files.
#
# NOTE for other teams: the non-system filenames below (network/*,
# filtering/*, storage/*, web/*) follow CONTRACTS.md module layout; confirm
# exact .cpp names match your implementation (web/http_server.cpp and
# web/api_handlers.cpp are Team D's to confirm).

idf_component_register(
  SRCS
    "main.cpp"
    # core — portable C++17, must also build with g++ on Linux (Team A)
    "core/domain_matcher.cpp"
    "core/bloom_filter.cpp"
    "core/dns_codec.cpp"
    "core/rule_engine.cpp"
    "core/dns_cache.cpp"
    # network (Team B)
    "network/dns_server.cpp"
    "network/dns_forwarder.cpp"
    "network/wifi_manager.cpp"
    "network/mdns_advertise.cpp"
    # filtering + storage (Team C)
    "filtering/blocklist_manager.cpp"
    "filtering/blocklist_updater.cpp"
    "filtering/allowlist.cpp"
    "filtering/custom_rules.cpp"
    "storage/blocklist_file.cpp"
    # web dashboard / API (Team D)
    "web/http_server.cpp"
    "web/api_handlers.cpp"
    # system (Team E)
    "system/config_manager.cpp"
    "system/stats_engine.cpp"
    "system/device_tracker.cpp"
    "system/query_logger.cpp"
    "system/ota_manager.cpp"
  INCLUDE_DIRS "."
  PRIV_REQUIRES
    nvs_flash
    esp_wifi
    esp_netif
    esp_http_server
    esp_http_client  # blocklist_updater.cpp includes esp_http_client.h directly
    mbedtls          # esp_crt_bundle.h (HTTPS trust for updater + OTA)
    esp_https_ota
    app_update
    esp_timer
    esp_hw_support # esp_random.h
    mdns
    littlefs      # managed component (see idf_component.yml)
    json          # cJSON, used by stats_engine / config JSON files
    wpa_supplicant # esp_wps.h (WPS push-button provisioning, travel mode)
  EMBED_FILES "web_dashboard/index.html"
)

# Firmware feature level (§9): 0.5 = 0.4 + travel mode (AP+STA NAT),
# WPS provisioning, AP client MAC tracking.
target_compile_definitions(${COMPONENT_LIB} PRIVATE FIRMWARE_VERSION="0.5.0")
