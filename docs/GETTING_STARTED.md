# Getting Started

From zero to network-wide ad blocking in about 30 minutes. You'll need: an ESP32 board, a USB cable, and a computer with a USB port.

> Connecting the board for the first time? Start with [FLASHING.md](FLASHING.md) — USB drivers, finding the COM port, and uploading the firmware step by step — then come back here for provisioning and router setup.

## 1. Install ESP-IDF v5.1+

The firmware builds with **ESP-IDF v5.1 or newer**, C++17, no Arduino layer.

- **Start here (all OSes):** [ESP-IDF v5.1 Get Started](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/index.html)
- **Windows:** use the [Windows Installer](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/windows-setup.html) (recommended), or manual setup.
- **Linux / macOS:** [manual setup](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/linux-macos-setup.html): clone IDF, then run the install script.

```bash
# inside $IDF_PATH, one time:
./install.sh        # Linux / macOS
install.bat         # Windows

# every new terminal:
source $IDF_PATH/export.sh        # Linux / macOS
$IDF_PATH\export.bat              # Windows
```

Verify with `idf.py --version` — you want v5.1 or later.

## 2. Build the firmware

```bash
git clone <this-repo-url> esp32-network-shield
cd esp32-network-shield

idf.py set-target esp32     # classic ESP32 (4 MB flash, default partitions.csv:
                            # factory + ONE ota slot + ~1.44 MB LittleFS —
                            # OTA works, but no rollback slot on 4 MB)
# idf.py set-target esp32s3 # ESP32-S3 build — use partitions-8mb.csv for the
                            # full layout (factory + ota_0 + ota_1 with
                            # rollback + ~3.4 MB LittleFS):
                            # CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions-8mb.csv"
                            # CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y

idf.py build   # verified clean on ESP-IDF v5.1.4: 0 errors, 0 warnings
```

The build registers all of `main/` as one component, pulls `joltwallet/littlefs` via the component manager, and embeds `main/web_dashboard/index.html` into flash. Expect it to take several minutes the first time.

> **Build verification status: VERIFIED ✅** — see [TESTING.md](TESTING.md#firmware-build) for the build report.

## 3. Flash and watch it boot

```bash
idf.py -p PORT flash monitor
# Linux:   -p /dev/ttyUSB0   (check dmesg for the actual device)
# macOS:   -p /dev/cu.usbserial-*
# Windows: -p COM5           (check Device Manager)
```

`flash` writes the factory app + partitions; `monitor` attaches the serial console (exit with `Ctrl-]`). On first boot you'll see NVS initialize, a new API token generated (**copy it** — you need it for the dashboard and API), and then provisioning mode start because no Wi-Fi credentials exist yet.

## 4. Provision Wi-Fi via the captive portal

1. On your phone or laptop, join the open Wi-Fi network **`ESP32-Shield-XXXX`** (the `XXXX` suffix comes from your device's MAC — it's unique per board).
2. A captive-portal page should pop up automatically; if not, open **http://192.168.4.1** in a browser.
3. Enter your home Wi-Fi **SSID** and **password** (and optionally a device name — this becomes `<name>.local`).
4. Save. The Shield writes the credentials to NVS and **reboots** onto your network as a station.

If you mistype the password, the device can't connect and drops back into provisioning AP mode — just join it again and retry. To force re-provisioning later, erase the `wifi_ssid` key (or full NVS) and reboot.

## 5. Point your router's DNS at the Shield

> **No router admin access?** (Hotel, café, someone else's network.) Skip this step and use **travel mode** instead — see [§7](#7-travel-mode-portable-ap).

1. **Find the Shield's IP.** Any of: the serial log line after Wi-Fi connects, your router's DHCP client list, or http://esp32-shield.local (mDNS — works on macOS/Windows 10+ out of the box; Linux needs Avahi).
2. **Router settings → LAN / DHCP settings → DNS server.** Set the primary DNS to the Shield's IP (e.g. `192.168.1.50`). Generic wording because every router's UI differs — look for "DHCP", "LAN settings", or "DNS".
   - *Trade-off:* if you list only the Shield and it's powered off, your network loses DNS. Listing a public DNS (e.g. `1.1.1.1`) as secondary keeps you online but lets some queries bypass filtering. Most people pick Shield-only once they trust it.
3. **Reconnect your devices** (or wait for DHCP renewal) so they pick up the new DNS server.

## 6. Verify it's working

```bash
# Blocked: a known tracker domain → sinkhole answer (default block mode NULL_IP)
dig @192.168.1.50 doubleclick.net +short
# → 0.0.0.0

# Allowed: a normal domain → real IP from upstream
dig @192.168.1.50 google.com +short
# → 142.250.x.x   (a real IP — exact value varies)

# Suffix matching: subdomains of a blocked domain are blocked too
dig @192.168.1.50 www.doubleclick.net +short
# → 0.0.0.0
```

Windows (no `dig`? it's built into Windows 10+; otherwise):

```cmd
nslookup doubleclick.net 192.168.1.50
```

Then open the dashboard at **http://192.168.1.50** (or http://esp32-shield.local), paste your API token when prompted (it's stored in the browser's `localStorage`), and watch live queries roll in.

Having trouble? Check the [testing checklist](TESTING.md#on-device-verification) and the serial log — the boot milestones are listed there.

## 7. Travel mode (portable AP)

When you **can't touch the router** — a hotel, café, Airbnb, or a friend's house — travel mode turns the Shield into its own ad-blocking Wi-Fi network. You only need power and the upstream Wi-Fi credentials.

**When to use it:** any network where you can't change DHCP/DNS settings. **When not to:** at home, where dns mode (this guide's default) gives the Shield your router's full speed instead of the ESP32's software NAT (~tens of Mbps — fine for browsing/streaming).

**Switching modes** (either direction) — dashboard → Configuration → **Mode** → Save, then System → **Reboot device**. Or via API:

```bash
# dns → travel
curl -X PUT http://$IP/api/config -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"travel"}'
# → {"ok":true,"reboot_required":true}
curl -X POST http://$IP/api/reboot -H "Authorization: Bearer $TOKEN"
```

**Using travel mode:**

1. Switch to travel mode and reboot (above).
2. **First boot in travel mode:** the Shield creates the AP **`Shield-XXXX`** (WPA2). The password was auto-generated — read it from the serial log (`travel AP 'Shield-XXXX' up (WPA2) ... password: ...`), or set your own via `PUT /api/config {"ap_pass":"..."}` before switching. The AP SSID is also customizable (`ap_ssid`; empty = auto).
3. Join `Shield-XXXX` from your phone/laptop. The captive portal appears (no upstream credentials yet) — enter the hotel/café/home **upstream Wi-Fi** SSID and password. The Shield reboots; the `Shield-XXXX` AP comes back with the **same SSID and password**, so your devices stay joined — now with internet, NAT'd through the upstream link.
4. That's it: every device on `Shield-XXXX` gets DNS from the Shield (advertised automatically by DHCP), so ads/trackers are blocked network-wide. Dashboard at **http://192.168.4.1** (or `http://esp32-shield.local`).

**WPS shortcut:** instead of typing the upstream password into the portal, you can use Wi-Fi Protected Setup — dashboard → Travel mode → **Start WPS**, then press the WPS button on the upstream router within ~2 minutes. The Shield saves the credentials and reboots itself. API: `POST /api/wps/start`. Note: many hotel/captive-portal networks don't support WPS (or need a browser login the Shield can't do) — the portal remains the fallback, and WPS only works while the Shield isn't already connected upstream.

**Notes:**
- AP clients are NAT'd through the STA uplink — expect tens of Mbps, not gigabit.
- The dashboard shows the AP's client count, and `GET /api/devices` includes each client's MAC (from DHCP leases) in travel mode.
- Switching back to `dns` mode reboots into the classic STA-only behavior; your router-DNS setup from §5 applies again.
