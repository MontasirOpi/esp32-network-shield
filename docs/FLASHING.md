# Flashing the ESP32 Network Shield

How to physically connect your ESP32 board to your computer and upload the firmware — step by step, no ESP32 experience assumed. No wiring or soldering needed: this project uses USB only.

If you've flashed an ESP32 before, you can skip to [Upload the firmware](#step-4--upload-the-firmware).

## What you need

- An ESP32 development board (any classic ESP32 works for the prototype; ESP32-S3 recommended — see README).
- A **USB cable that carries data**. This is the #1 cause of "it doesn't work": many cheap cables are charge-only and will power the board while showing no COM port. If no port appears in Step 1, swap the cable before anything else.
- A computer running Windows, Linux, or macOS.

## Step 1 — Connect the board and find its port

1. Plug the board into your computer with the USB cable. A power LED on the board should light up.
2. **Install the USB-to-serial driver** if no new port appears. Look at the small chip next to the USB port on your board:
   - **CP2102** (square chip) → install the [Silicon Labs CP210x driver](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers).
   - **CH340 / CH341** (rectangular chip) → install the [WCH CH341SER driver](https://www.wch.cn/downloads/CH341SER_ZIP.html).
   
   Most inexpensive devkits use CH340; many others use CP2102. Windows 10/11 often installs one of them automatically — only install manually if no port shows up.
3. **Find the port name** — you'll need it for flashing:
   - **Windows:** open Device Manager → *Ports (COM & LPT)* → look for `USB-SERIAL CH340 (COM5)` or similar. Note the `COMx` number.
   - **Linux:** run `dmesg | tail` right after plugging in; you'll see something like `ch341-uart converter now attached to ttyUSB0` → your port is `/dev/ttyUSB0`. If you get "permission denied" later, add yourself to the dialout group: `sudo usermod -aG dialout $USER`, then log out and back in.
   - **macOS:** run `ls /dev/cu.*` → look for `/dev/cu.usbserial-*` or `/dev/cu.wchusbserial*`.

## Step 2 — Install ESP-IDF (one time)

The firmware builds with **ESP-IDF v5.1 or newer**. Full instructions: [Espressif Get Started](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/index.html). Condensed:

- **Windows (recommended):** run the [ESP-IDF Windows Installer](https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32/get-started/windows-setup.html). It installs everything and gives you an **"ESP-IDF PowerShell"** shortcut — always use that terminal for the commands below.
- **Linux / macOS:** clone ESP-IDF and run its install script once, then the export script in every new terminal:
  ```bash
  # one time, inside $IDF_PATH:
  ./install.sh
  # every new terminal:
  source $IDF_PATH/export.sh
  ```

Verify with `idf.py --version` — you want v5.1 or later.

## Step 3 — Get the code and build it

```bash
git clone https://github.com/MontasirOpi/esp32-network-shield.git
cd esp32-network-shield

idf.py set-target esp32     # classic ESP32 (default). For ESP32-S3 use:
                            # idf.py set-target esp32s3  (then switch the
                            # partition table to partitions-8mb.csv —
                            # see GETTING_STARTED.md)

idf.py build
```

The first build takes several minutes (it compiles the whole framework once); later builds are incremental and fast. Success ends with something like `Project build complete` and zero errors/warnings.

## Step 4 — Upload the firmware

```bash
idf.py -p PORT flash
# Windows:  idf.py -p COM5 flash
# Linux:    idf.py -p /dev/ttyUSB0 flash
# macOS:    idf.py -p /dev/cu.usbserial-0001 flash
```

This writes three things to the board: the bootloader, the partition table, and the Shield app. It takes ~1 minute.

**"Failed to connect to ESP32"?** Most devkits enter download mode automatically, but some need a manual nudge:
1. Press and **hold the BOOT button** (sometimes labeled IO0).
2. While holding BOOT, briefly press/release the **EN** (reset) button.
3. Release BOOT once flashing starts.

If it still fails, retry at a lower speed: `idf.py -p PORT -b 115200 flash`.

### Watch it boot

```bash
idf.py -p PORT monitor
```

(Exit with `Ctrl-]`. On Windows use `Ctrl+]` in the ESP-IDF PowerShell.)

A healthy first boot prints: NVS init → Wi-Fi stack up → **a freshly generated API token (copy it — you need it for the dashboard)** → provisioning AP `ESP32-Shield-XXXX` starting. If you see this, the upload worked.

## Step 5 — What happens next

The board is now running but not on your Wi-Fi yet. Continue with [GETTING_STARTED.md](GETTING_STARTED.md#4-provision-wi-fi-via-the-captive-portal): join the `ESP32-Shield-XXXX` network, open `http://192.168.4.1`, enter your Wi-Fi credentials, then point your router's DHCP DNS at the Shield's IP.

## Updating the firmware later

- **Over USB:** just run `idf.py -p PORT flash` again. No need to erase anything first.
- **Over the air:** once the Shield is on your network, use the dashboard's OTA update (POST `/api/ota`). Note: the default 4 MB partition layout has a single OTA slot (updates work, no rollback); the ESP32-S3 8 MB layout has full A/B rollback — see [ARCHITECTURE.md](ARCHITECTURE.md#flash--littlefs-layout).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No COM port appears at all | Charge-only USB cable, or missing driver | Swap the cable first; then install the CP2102/CH340 driver for your board's chip |
| `Permission denied` on `/dev/ttyUSB0` (Linux) | User not in `dialout` group | `sudo usermod -aG dialout $USER`, log out and back in |
| `Failed to connect to ESP32` during flash | Board didn't enter download mode | Hold BOOT, tap EN, release BOOT when flashing starts; or `-b 115200` |
| Brownout resets / random reboots while flashing | Weak USB power | Use a different USB port (preferably USB 2.0 / rear ports on desktops), shorter cable, or a powered hub |
| Boots but immediately boot-loops | Wrong target or flash size (e.g. built for S3, flashed to classic) | `idf.py set-target esp32`, `idf.py erase-flash`, then `flash` again |
| `monitor` shows garbage characters | Baud mismatch | Monitor defaults to 115200; if you changed console baud, match it: `idf.py -p PORT monitor -b <baud>` |
| No `ESP32-Shield-XXXX` AP on first boot | Board was already provisioned earlier | Erase saved Wi-Fi: `idf.py -p PORT erase-flash` then flash again, or clear NVS from the dashboard/API |
| Flash succeeds but dashboard never loads | Board didn't join your Wi-Fi (wrong password at provisioning) | It falls back to provisioning AP mode — join `ESP32-Shield-XXXX` again and re-enter credentials |

Still stuck? Open an issue on the repo with your board model, the exact command you ran, and the last ~30 lines of output — that's everything needed to diagnose it.

## Next: travel mode (optional)

Flashing and first boot always start in **dns mode** (the classic router-DNS setup above). If you'll use the Shield somewhere you can't administer the router — hotel, café, Airbnb — switch to **travel mode** after provisioning: dashboard → Configuration → Mode → `travel` → Save, then System → Reboot. The Shield then hosts its own WPA2 Wi-Fi (`Shield-XXXX`) with ad blocking for anyone who joins. Full walkthrough: [GETTING_STARTED.md](GETTING_STARTED.md#7-travel-mode-portable-ap).
