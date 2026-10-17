# ESP32 Network Shield — Master System & Architecture Guide

This comprehensive document details the complete design, runtime architecture, construction process, and usage instructions for the **ESP32 Network Shield** — a network-wide DNS ad-blocker and hardware NAT gateway running on an ESP32 microcontroller.

---

## Table of Contents

1. [System Overview & Working Principle](#1-system-overview--working-principle)
2. [Runtime Architecture & Dataflow](#2-runtime-architecture--dataflow)
   - [DNS Pipeline & Rule Hierarchy](#dns-pipeline--rule-hierarchy)
   - [Memory Strategy: Bloom Filter & Flash Binary Search](#memory-strategy-bloom-filter--flash-binary-search)
   - [Operating Modes: DNS Mode vs. Travel Mode (Hardware NAPT)](#operating-modes-dns-mode-vs-travel-mode-hardware-napt)
   - [Web Dashboard & REST/WebSocket Engine](#web-dashboard--restwebsocket-engine)
   - [FreeRTOS Task & Memory Budgeting](#freertos-task--memory-budgeting)
3. [How the System is Built (Engineering & Construction)](#3-how-the-system-is-built-engineering--construction)
   - [Hardware Requirements & Specifications](#hardware-requirements--specifications)
   - [Partition Table Layout](#partition-table-layout)
   - [NVS Storage & Configuration Pre-provisioning](#nvs-storage--configuration-pre-provisioning)
   - [Automated GitHub Actions CI/CD Pipeline](#automated-github-actions-cicd-pipeline)
   - [Firmware Flashing with `esptool.py`](#firmware-flashing-with-esptoolpy)
4. [How to Use the System (Practical Operation)](#4-how-to-use-the-system-practical-operation)
   - [Option 1: Travel Mode (Dedicated Ad-Blocking Wi-Fi Hotspot)](#option-1-travel-mode-dedicated-ad-blocking-wi-fi-hotspot)
   - [Option 2: Network-Wide Router DHCP Setup](#option-2-network-wide-router-dhcp-setup)
   - [Option 3: Per-Device Manual DNS Configuration](#option-3-per-device-manual-dns-configuration)
   - [Dashboard Management & API Token](#dashboard-management--api-token)
   - [Allowlist & Custom Rules Management](#allowlist--custom-rules-management)
   - [Blocklist Updates & A/B Slot Safety](#blocklist-updates--ab-slot-safety)
5. [Documentation Map & GitHub Pipeline Workflow](#5-documentation-map--github-pipeline-workflow)
   - [Repository Documentation Graph](#repository-documentation-graph)
   - [Git & GitHub CI/CD Automation Flow](#git--github-cicd-automation-flow)

---

## 1. System Overview & Working Principle

Modern web applications, smartphones, smart TVs, and IoT appliances frequently communicate with thousands of tracking servers and advertising networks. Standard software ad-blockers (such as browser extensions) cannot protect devices like smart TVs, mobile apps, or game consoles.

The **ESP32 Network Shield** operates at Layer 3/4 and Layer 7 (DNS):
1. **Network Placement**: It connects to your local network (or hosts its own Wi-Fi) and functions as the primary **DNS Resolver** on port 53 (UDP).
2. **Filtering Decision**: When any device requests the IP address for a domain (e.g. `doubleclick.net`), the Shield checks its internal rules:
   - **Allowed Domains**: Forwarded to trusted upstream recursive resolvers (such as Cloudflare `1.1.1.1` or Google `8.8.8.8`) and cached locally.
   - **Blocked Domains (Ads/Trackers)**: Sinkholed immediately by responding with `0.0.0.0` (IPv4) and `::` (IPv6), or NXDOMAIN.
3. **Zero Interception**: The Shield filters strictly by domain name. It does not perform TLS man-in-the-middle decryption, preserving user privacy, cryptographic integrity, and line-speed DNS resolution.

```
+---------------+     DNS Query (:53)     +----------------------+      Upstream Query (:53)      +------------------+
| Client Device | ---------------------> | ESP32 Network Shield | -----------------------------> | Upstream DNS     |
| (Phone/PC/TV) | <--------------------- | (Bloom + Rule Engine)| <----------------------------- | (Cloudflare/1.1) |
+---------------+     Blocked: 0.0.0.0   +----------------------+      Allowed: Valid IP         +------------------+
```

---

## 2. Runtime Architecture & Dataflow

### DNS Pipeline & Rule Hierarchy

Every incoming UDP packet on port 53 is processed by the pipeline handler (`dns_pipeline_handler` in [main/main.cpp](../main/main.cpp)):

```
Incoming UDP Datagram (Port 53)
   │
   ▼
[1] parse_dns_query() ──────────► Malformed / Non-IN / Multiple Questions ──► Dropped
   │
   ▼
[2] normalize_domain() ─────────► Lowercase, strip trailing dot, FQDN validation
   │
   ▼
[3] DnsCache::lookup() ─────────► Cache HIT ──► Patch Query ID & Send Response
   │ (Cache Miss)
   ▼
[4] RuleEngine::decide()
   ├── Check Allowlist ─────────► Exact match or suffix match ──► ALLOW
   ├── Check Custom Rules ──────► Custom allow/block entries ──► MATCHED DECISION
   └── Check Blocklist ─────────► Bloom Filter check:
                                    ├── Negative (Not in bloom) ──► ALLOW
                                    └── Positive (Candidate)   ──► Binary Search on Flash Slot
                                                                    ├── Found ──► BLOCK
                                                                    └── Absent ─► ALLOW
   │
   ├── If BLOCK: build_block_response(block_mode) ──► Send 0.0.0.0 / :: / NXDOMAIN
   └── If ALLOW: DnsForwarder::forward() ──────────► Upstream resolver ──► Store in Cache ──► Send
```

### Memory Strategy: Bloom Filter & Flash Binary Search

A classic ESP32 has ~320 KB internal DRAM, which cannot store 50,000+ domain strings in memory. The Shield uses a hybrid two-tier lookup:
1. **RAM Bloom Filter**: An in-memory bit array (~60 KB) with 3 independent FNV-1a hash functions. If a domain is not in the blocklist, the Bloom filter rejects it in $O(1)$ time with zero flash reads.
2. **Flash Binary Search (`BlocklistFile`)**: If the Bloom filter yields a match (which may have a small false-positive rate), the system verifies the 64-bit hash against a pre-sorted binary file on LittleFS flash using $O(\log N)$ binary search.

### Operating Modes: DNS Mode vs. Travel Mode (Hardware NAPT)

The firmware supports two distinct operating modes configured via NVS:

#### 1. DNS Mode (`mode = "dns"`)
- The ESP32 acts as a standard Wi-Fi station (`WIFI_MODE_STA`) on your home network.
- Router DHCP points all clients to the ESP32's LAN IP (e.g. `192.168.0.156`).
- Web dashboard is accessible via LAN IP or mDNS (`http://esp32-shield.local`).

#### 2. Travel Mode (`mode = "travel"`)
- The ESP32 operates simultaneously as a Wi-Fi station and Access Point (`WIFI_MODE_APSTA`).
- **Station Interface**: Connects to the upstream hotel, cafe, or home Wi-Fi (`Fahim_EXT`).
- **SoftAP Interface**: Broadcasts its own secure WPA2 Wi-Fi (e.g. `Shield-AdBlock`, default IP `192.168.4.1`).
- **Hardware NAPT**: Enables lwIP IPv4 Network Address and Port Translation (`CONFIG_LWIP_IP_FORWARD=y` and `CONFIG_LWIP_IPV4_NAPT=y`). All client packets joining `Shield-AdBlock` are masqueraded through the ESP32 station link.
- **Automatic Protection**: AP DHCP leases configure the ESP32 (`192.168.4.1`) as the default gateway and DNS server. Clients receive immediate ad-blocking with zero configuration.

### Web Dashboard & REST/WebSocket Engine

The web dashboard is a lightweight, zero-dependency SPA embedded directly into the firmware image:
- **Embedded Binary**: `main/web_dashboard/index.html` is compiled into the app image via `EMBED_FILES`.
- **REST Endpoints**:
  - `GET /api/status` — Public health and device status.
  - `GET /api/config` & `PUT /api/config` — Configuration management (Bearer Token authenticated).
  - `GET /api/stats` — Metrics snapshot (total, blocked, allowed, cache hits).
  - `GET /api/devices` — Tracked client IP/MAC addresses.
  - `POST /api/blocklist/update` — Background blocklist download & slot swap.
  - `POST /api/reboot` — Graceful system restart.
- **Real-Time WebSocket (`/ws`)**: Streams live DNS queries and rolling metrics directly to the browser.

### FreeRTOS Task & Memory Budgeting

| Task Name | Stack Size | Priority | Responsibility |
|---|---|---|---|
| `dns_server` | 6144 B | 5 | Listens on UDP port 53, executes pipeline handler |
| `httpd` | 4096 B | 5 | Handles HTTP/REST requests and static dashboard delivery |
| `ws_server` | 4096 B | 4 | Pushes live telemetry events over WebSockets |
| `bl_update` | 8192 B | 5 | Downloads blocklists over TLS and writes to LittleFS |
| `health` | 4096 B | 5 | Periodically flushes stats, audits heap, monitors STA |

---

## 3. How the System is Built (Engineering & Construction)

### Hardware Requirements & Specifications

- **Microcontroller**: ESP32-D0WD-V3 (Dual Core Xtensa LX6 @ 240 MHz, 520 KB SRAM).
- **Flash Memory**: 4 MB SPI Flash (DIO mode @ 40 MHz).
- **USB Interface**: CP2102 or CH340 USB-to-UART bridge.
- **Power Budget**: 5V micro-USB / Type-C (peak ~300 mA during RF transmission).

### Partition Table Layout

Defined in [partitions.csv](../partitions.csv) spanning 4 MB:

```csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x6000,
phy_init, data, phy,     0xf000,   0x1000,
factory,  app,  factory, 0x10000,  0x140000,
ota_0,    app,  ota_0,   0x150000, 0x140000,
otadata,  data, ota,     0x290000, 0x2000,
littlefs, data, 0x83,    0x292000, 0x16e000,
```

- `factory`: Holds the primary bootable application (~1.28 MB max).
- `ota_0` & `otadata`: Enables remote firmware upgrades over HTTPS.
- `littlefs`: Mount point `/littlefs` (~1.44 MB) holding A/B blocklist files, custom rules, and persistent statistics.

### NVS Storage & Configuration Pre-provisioning

ESP-IDF Non-Volatile Storage (NVS) stores device secrets and runtime settings under the `shield` namespace. 
Because the ESP-IDF NVS key limit is **15 characters**, keys exceeding this limit are mapped internally:

| Logical Parameter | NVS Key (<= 15 chars) | Description |
|---|---|---|
| `wifi_ssid` | `wifi_ssid` | Upstream Wi-Fi SSID |
| `wifi_pass` | `wifi_pass` | Upstream Wi-Fi Password |
| `api_token` | `api_token` | 32-character hex authentication token |
| `mode` | `mode` | Operating mode (`dns` or `travel`) |
| `ap_ssid` | `ap_ssid` | Travel mode Access Point SSID |
| `ap_pass` | `ap_pass` | Travel mode Access Point Password |
| `upstream_primary` | `up_primary` | Primary upstream DNS IP (`1.1.1.1`) |
| `upstream_secondary` | `up_secondary` | Secondary upstream DNS IP (`1.0.0.1`) |
| `upstream_timeout_ms` | `up_timeout_ms` | Upstream query timeout (ms) |
| `filtering_enabled` | `filter_enabled` | Boolean toggle for rule enforcement |

NVS partitions can be generated before flashing using `esp-idf-nvs-partition-gen`:
```bash
python -m esp_idf_nvs_partition_gen.nvs_partition_gen generate nvs.csv nvs.bin 0x6000
```

### Automated GitHub Actions CI/CD Pipeline

To ensure reproducible builds without requiring a local toolchain on Windows, the repository contains an automated build workflow in [`.github/workflows/build.yml`](../.github/workflows/build.yml):

```yaml
name: Build Firmware
on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: espressif/idf:v5.1.4
    steps:
      - uses: actions/checkout@v4
      - name: Build with ESP-IDF
        run: |
          idf.py set-target esp32
          idf.py build
      - name: Publish Artifacts & Release
        # Releases bootloader.bin, partition-table.bin, esp32-network-shield.bin
```

When changes are pushed to `main`, GitHub Actions spins up the official `espressif/idf:v5.1.4` Docker environment, compiles the C++17 codebase with size optimizations (`-Os`), and uploads fresh release assets to GitHub Releases `v0.5.0`.

### Firmware Flashing with `esptool.py`

Once binaries are downloaded from CI/CD, they are written to the ESP32 using `esptool`:

```bash
# 1. Bootloader
python -m esptool --chip esp32 -p COM7 -b 460800 write_flash 0x1000 bootloader.bin

# 2. Partition Table
python -m esptool --chip esp32 -p COM7 -b 460800 write_flash 0x8000 partition-table.bin

# 3. NVS Configuration
python -m esptool --chip esp32 -p COM7 -b 460800 write_flash 0x9000 nvs.bin

# 4. Application Firmware
python -m esptool --chip esp32 -p COM7 -b 460800 write_flash 0x10000 esp32-network-shield.bin
```

---

## 4. How to Use the System (Practical Operation)

### Option 1: Travel Mode (Dedicated Ad-Blocking Wi-Fi Hotspot)

⭐ **The easiest and most flexible method — zero router changes required.**

1. Enable Travel Mode via Dashboard (or verify it is active):
   - **Mode**: `travel`
   - **SSID**: `Shield-AdBlock`
   - **Password**: `shield1234`
2. Search for Wi-Fi on your smartphone, PC, or tablet.
3. Connect to **`Shield-AdBlock`** using password **`shield1234`**.
4. You are immediately connected to the internet with full network-level ad blocking!

### Option 2: Network-Wide Router DHCP Setup

Protect all devices in your home simultaneously:
1. Log into your home router's admin panel (typically `192.168.0.1` or `192.168.1.1`).
2. Navigate to **DHCP Server** &rarr; **DNS Settings**.
3. Set **Primary DNS** to the ESP32's IP: `192.168.0.156`.
4. Set **Secondary DNS** to empty or `192.168.0.156` (do not set an external DNS like 8.8.8.8, or devices may bypass the Shield).
5. Save settings and reconnect your devices to renew their DHCP leases.

### Option 3: Per-Device Manual DNS Configuration

If you only want specific devices protected without modifying the router:
- **Windows 10/11**: `Settings` &rarr; `Network & internet` &rarr; `Wi-Fi` &rarr; Network Properties &rarr; `DNS Assignment: Manual` &rarr; IPv4 Preferred DNS: `192.168.0.156`.
- **Android**: `Settings` &rarr; `Wi-Fi` &rarr; Network Details (⚙️) &rarr; `IP Settings: Static` &rarr; DNS 1: `192.168.0.156`.
- **iOS (iPhone/iPad)**: `Settings` &rarr; `Wi-Fi` &rarr; Network Info (ⓘ) &rarr; `Configure DNS: Manual` &rarr; Server: `192.168.0.156`.

### Dashboard Management & API Token

Access the dashboard from any connected browser:
- **URL**: `http://192.168.0.156/` (or `http://192.168.4.1/` when connected to `Shield-AdBlock`).
- **Authentication**: When prompted, enter the API Token:
  ```text
  b8365d8e59b59d9d3eac0d69009de2d8
  ```
- **Dashboard Sections**:
  - **Counters**: Displays total queries, blocked count, allowed count, block rate %, and cache hit %.
  - **Top Blocked Domains**: Real-time table of the most frequent ad/tracker domains sinkholed.
  - **Live Query Log**: WebSocket-driven live stream of incoming client queries and decisions.
  - **Configuration**: Dynamic modification of upstreams, block modes, and operating modes.

### Allowlist & Custom Rules Management

- **Allowlist**: If a domain or service is inadvertently blocked, enter the domain in the **Allowlist** card (e.g. `analytics.google.com`) and click **Add**. All allowlist entries override blocklists.
- **Custom Rules**: Explicitly set custom domains to either `block` or `allow`.

### Blocklist Updates & A/B Slot Safety

The Shield features an atomic **A/B Slot** update mechanism:
1. Blocklists are fetched from upstream sources (e.g. StevenBlack hosts).
2. Parsed hashes are written exclusively to the **inactive** slot (e.g. Slot B if Slot A is active).
3. The new slot is strictly validated (minimum entry check, canary test: `doubleclick.net` must be blocked, `google.com` must not be blocked).
4. Only upon 100% validation success is the pointer swapped to the new slot. The active slot is never corrupted by network timeouts or malformed source files.

---

## 5. Documentation Map & GitHub Pipeline Workflow

### Repository Documentation Graph

The project's markdown documents are organized hierarchically:

```
                                  [ README.md ]
                     (Entrypoint, Overview & Feature Summary)
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
[ SYSTEM_GUIDE_EN.md ]        [ SYSTEM_GUIDE_BN.md ]            [ CONTRACTS.md ]
(Complete Master Guide - EN)  (Complete Master Guide - BN)      (Interface Specification)
        │                               │                               │
        ├───────────────────────┬───────┴───────────────────────┐       │
        ▼                       ▼                               ▼       ▼
[ ARCHITECTURE.md ]     [ GETTING_STARTED.md ]        [ USER_GUIDE_BN.md ]
(Deep-dive Architecture) (Quickstart & Setup)          (Bengali User Manual)
        │                       │                               │
        ├───────────────────────┼───────────────────────────────┤
        ▼                       ▼                               ▼
 [ FLASHING.md ]         [ FLASHING_BN.md ]                 [ API.md ]
(Flashing Steps - EN)   (Flashing Steps - BN)           (REST & WS Endpoints)
        │                       │                               │
        ▼                       ▼                               ▼
 [ TESTING.md ]          [ BLOCKLISTS.md ]               [ ROADMAP.md ]
(Unit & Device Tests)   (Blocklist Mechanics)           (Milestones & Releases)
```

### Git & GitHub CI/CD Automation Flow

The end-to-end development and deployment lifecycle follows this streamlined workflow:

```
1. Local Edits (main/..., docs/...)
   │
   ▼
2. Git Commit & Push
   git add .
   git commit -m "feat/fix: description"
   git push origin main
   │
   ▼
3. GitHub Actions Triggered (.github/workflows/build.yml)
   ├── Pulls official Docker container: espressif/idf:v5.1.4
   ├── Configures chip: idf.py set-target esp32
   ├── Compiles firmware: idf.py build (-Os, C++17)
   └── Updates GitHub Release v0.5.0 with fresh binaries
   │
   ▼
4. Local Device Deployment
   ├── Download release binaries via curl
   └── Flash to ESP32 over COM7 using esptool.py
```

This ensures that the firmware is always reproducibly compiled, verified, and ready for deployment without platform-dependent discrepancies.
