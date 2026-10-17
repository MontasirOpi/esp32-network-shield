# ESP32 Network Shield

**A DIY network-wide ad blocker and DNS filter on a $5 ESP32 — point your router's DNS at it and ads, trackers, and malware domains die on every device in your home.**

Instead of installing ad blockers on every phone, laptop, and smart TV, the Shield sits on your LAN as the DNS server for the whole network. When a device asks "where is `ads.example.com`?", the Shield answers `0.0.0.0` (or NXDOMAIN — your choice) for anything on its blocklist, and forwards everything else to a real upstream resolver like Cloudflare. A web dashboard shows live queries, top blocked domains, and per-device stats.

## Features

- **DNS filtering** — every DNS query on your LAN is inspected and either blocked or forwarded.
- **Blocklist engine** — ~50k+ ad/tracker/malware domains in a RAM Bloom filter backed by flash binary-search verification, so a full-size blocklist fits the classic ESP32 RAM budget.
- **DNS cache** — 256-entry response cache (configurable) cuts repeat-query latency to ~0 ms and reduces upstream load.
- **Dashboard** — single-page web UI with live query log (WebSocket), top blocked domains, device list, and config forms. No app install needed.
- **REST + WebSocket API** — everything the dashboard does is scriptable (`/api/*`, `/ws`).
- **OTA with rollback** — firmware updates over HTTPS; the device self-tests after reboot and rolls back if DNS breaks.
- **Captive-portal provisioning** — first boot creates a setup Wi-Fi network; join it, enter your Wi-Fi credentials in the browser, done. No hardcoded secrets, no serial cable required after flashing.
- **Travel mode** — portable AP+STA operation for networks you don't administer (hotels, cafés): the Shield hosts its own WPA2 Wi-Fi (`Shield-XXXX`) with DHCP-advertised DNS and NAT to the upstream link, so joining devices get ad blocking with zero router changes. Includes WPS push-button provisioning.
- **Device tracking** — per-IP query/block counters so you can see which device is the chattiest (plus MAC addresses from DHCP leases in travel mode).

## Hardware

| | Recommended | Minimum (prototype) |
|---|---|---|
| Board | ESP32-S3, 8 MB PSRAM, 8–16 MB flash | Any classic ESP32 (4 MB flash) |
| Why | PSRAM removes all RAM pressure; bigger flash fits larger blocklists and longer OTA headroom | The firmware is designed for the ~320 KB DRAM budget, so it runs — just tighter |

The default `partitions.csv` targets 4 MB flash (single OTA slot, ~1.44 MB LittleFS). For ESP32-S3 8 MB builds, use `partitions-8mb.csv` for the full layout with OTA rollback + ~3.4 MB LittleFS (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#flash--littlefs-layout)).

## How it works

```
                        ┌─────────────────────────────────────────────┐
                        │              Your home network               │
                        │                                              │
  ┌──────────┐   DNS    │   ┌──────────────┐      ┌─────────────────┐   │     ┌──────────┐
  │ Phone /  │  :53     │   │ ESP32 Shield │      │  Router / DHCP  │   │     │ Internet │
  │ Laptop / ├─────────►│   │              │      │  DNS ──► Shield │   │     │          │
  │ Smart TV │          │   │  ┌────────┐  │      └─────────────────┘   │     │ 1.1.1.1  │
  └──────────┘          │   │  │ Block? ├──Yes──► 0.0.0.0 / NXDOMAIN │   │     │ 1.0.0.1  │
                        │   │  └───┬────┘  │                           │     └────▲─────┘
                        │   │      │ No    │      ┌──────────────┐     │          │ upstream
                        │   │      ▼       │      │  Dashboard   │     │     (forward allowed
                        │   │  ┌────────┐  │      │  :80 + /ws   │     │      queries here)
                        │   │  │ Cache? ├──Yes─►│  (browser)     │     │
                        │   │  └───┬────┘  │      └──────────────┘     │
                        │   │      │ No    │                           │
                        │   │      └───────┼───► forward upstream ─────┼─────────────┘
                        │   └──────────────┘                           │
                        └─────────────────────────────────────────────┘
```

1. Your router's DHCP tells every device: "use the Shield as your DNS server."
2. The Shield parses each query, checks its cache, then runs the rule engine.
3. Blocked domains get a sinkhole answer (`0.0.0.0`, `::`, NXDOMAIN, or empty — configurable). Everything else is forwarded byte-for-byte to the upstream resolver and cached.

## Quickstart

1. **Install ESP-IDF v5.1+** — follow the [Get Started guide](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/index.html) for your OS, then run `install.sh` (Linux/macOS) or `install.bat` (Windows) in `$IDF_PATH` and source `export.sh` / `export.bat`.
2. **Build** — `idf.py set-target esp32` (use `esp32s3` for the S3 board), then `idf.py build`.
3. **Flash** — `idf.py -p PORT flash monitor` (e.g. `-p /dev/ttyUSB0`, or `COM5` on Windows).
4. **Provision Wi-Fi** — on first boot the Shield creates an open AP called `ESP32-Shield-XXXX`. Join it, open http://192.168.4.1, enter your Wi-Fi SSID/password, and save. The device reboots onto your network.
5. **Point your router's DNS at the Shield** — in your router's LAN/DHCP settings, set the DNS server to the Shield's IP (find it via the serial log, your router's client list, or http://esp32-shield.local). Then verify: `dig @<shield-ip> doubleclick.net` should return `0.0.0.0`.

Full walkthrough: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

## Repository layout

```
esp32-network-shield/
├── CMakeLists.txt            # root project file
├── partitions.csv            # 4 MB flash: nvs, factory, ota_0, otadata, littlefs
├── partitions-8mb.csv        # 8 MB flash (ESP32-S3): + ota_1 rollback slot
├── sdkconfig.defaults        # target, -Os, custom partitions, WS + exceptions
├── CONTRACTS.md              # module contracts — read this before touching code
├── main/
│   ├── CMakeLists.txt        # component registration, EMBED_FILES dashboard
│   ├── idf_component.yml     # littlefs dependency
│   ├── main.cpp              # pipeline wiring (Team E)
│   ├── core/                 # portable C++17, zero ESP-IDF includes (Team A)
│   │                         # domain_matcher, bloom_filter, dns_codec, rule_engine, dns_cache
│   ├── network/              # Team B: dns_server, dns_forwarder, wifi_manager, mdns
│   ├── filtering/            # Team C: blocklist_manager, blocklist_updater, allowlist, custom_rules
│   ├── storage/              # Team C: blocklist_file (A/B slot format)
│   ├── web/                  # Team D: REST API, WebSocket, dashboard
│   │   └── web_dashboard/index.html
│   └── system/               # Team E: config_manager, stats, devices, query log, OTA
├── tests/host/               # host unit tests, no external deps (Team A)
└── docs/
    ├── SYSTEM_GUIDE_EN.md    # Master system & architecture guide (English)
    ├── SYSTEM_GUIDE_BN.md    # মাস্টার সিস্টেম ও আর্কিটেকচার গাইড (বাংলা)
    ├── ARCHITECTURE.md       # deep dive: diagrams, RAM budget, file formats
    ├── FLASHING.md           # connect the board via USB, drivers, upload firmware
    ├── FLASHING_BN.md        # সম্পূর্ণ বাংলা ফ্ল্যাশিং গাইড
    ├── USER_GUIDE_BN.md      # সম্পূর্ণ বাংলা ব্যবহার নির্দেশিকা (Dashboard & Router Setup)
    ├── GETTING_STARTED.md    # install → flash → provision → verify
    ├── API.md                # REST + WebSocket reference
    ├── TESTING.md            # host tests, build, on-device checks
    ├── BLOCKLISTS.md         # sources, formats, updates, A/B safety
    └── ROADMAP.md            # version history and future plans
```

## Docs

- [Master System & Architecture Guide (EN)](docs/SYSTEM_GUIDE_EN.md) — complete guide on how the system works, is built, and operates.
- [মাস্টার সিস্টেম ও আর্কিটেকচার গাইড (বাংলা)](docs/SYSTEM_GUIDE_BN.md) — সিস্টেম আর্কিটেকচার, মেকিং ও ব্যবহারের সম্পূর্ণ বাংলা গাইড।
- [Architecture](docs/ARCHITECTURE.md) — deep dive on memory budgets, diagrams, and LittleFS formats.
- [Flashing](docs/FLASHING.md) — connect the ESP32 over USB and upload the code, step by step.
- [ফ্ল্যাশিং গাইড (বাংলা)](docs/FLASHING_BN.md) — ESP32 সংযোগ ও ফ্ল্যাশ করার সম্পূর্ণ বাংলা গাইড।
- [ব্যবহার নির্দেশিকা (বাংলা)](docs/USER_GUIDE_BN.md) — ড্যাশবোর্ড ব্যবহার, রাউটার ও ডিভাইস কনফিগারেশন গাইড।
- [Getting started](docs/GETTING_STARTED.md) — flash it and get it on your network.
- [API reference](docs/API.md) — REST + WebSocket.
- [Testing](docs/TESTING.md) — host unit tests and on-device verification.
- [Blocklists](docs/BLOCKLISTS.md) — sources, formats, and safe updates.
- [Roadmap](docs/ROADMAP.md) — what's done and what's next.

## What it does NOT do

> **No TLS interception.** The Shield is a DNS filter, not a man-in-the-middle proxy. It never sees inside HTTPS traffic — it only decides which *domain names* resolve. That means it can't strip ads embedded inside a page you intentionally loaded (e.g. YouTube in-video ads served from `youtube.com` itself), and it can't filter by URL path. If a whole domain is bad, it disappears; if a domain is mixed, blocking it blocks all of it. This is a deliberate design choice: your encrypted traffic stays encrypted and the device stays simple and fast.
