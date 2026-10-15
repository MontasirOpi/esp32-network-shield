# Roadmap

Version history mapped to the original proposal's milestones, plus what's planned next. Status legend: ✅ shipped · 🔜 planned · 💡 idea (no commitment).

## Shipped

The firmware declares `FIRMWARE_VERSION "0.5.0"` — V0.5 feature level.

| Milestone | Status | Notes |
|---|---|---|
| **V0.1 — network proof** | ✅ | UDP DNS server on :53, strict query parser, raw-packet forwarder with primary→secondary failover. A query goes in, an answer comes out. |
| **V0.2 — ad blocking** | ✅ | Rule engine (allowlist > custom rules > blocklist), Bloom-in-RAM + flash-binary-search blocklist lookup, configurable block modes (NULL_IP / NXDOMAIN / NODATA). |
| **V0.3 — performance** | ✅ | 256-entry DNS cache with TTL clamping and transaction-ID patching; ~0 ms repeat queries; EDNS0-preserving forwarder. |
| **V0.4 — dashboard** | ✅ | Single-file embedded web UI: status card, counters, top-blocked table, live query log over WebSocket, config forms, blocklist update button; full REST + WebSocket API. |
| **V0.5 — auto blocklists** | ✅ basic | `BlocklistUpdater`: HTTPS download of the compiled-in sources (StevenBlack + someonewhocares), hosts/plain-list parsing, A/B slot update with 4-point validation, `update_interval_h` cadence. *Basic* = sources are compiled defaults; no custom-source API yet. |
| **V0.6 — device monitoring** | ✅ basic | Per-IP query/block counters (32-slot table), device list API, query ring buffer. *Basic* = IP-based only; **no hostname resolution yet** — `hostname` is empty in V1. |
| **V0.7 — OTA** | ✅ basic | HTTPS OTA via `POST /api/ota`, post-reboot DNS self-test. Rollback needs *two* OTA partitions — present in `partitions-8mb.csv` (S3), but the default 4 MB `partitions.csv` has a single OTA slot, so 4 MB builds update without rollback. *Basic* = manual URL trigger; no update server / version-check channel. |
| **V0.8 — Flutter app** | 🔜 Phase 2 | Deliberately deferred. The REST + WebSocket API is the app's backend contract and is stable — a mobile app can be built against [API.md](API.md) without firmware changes. |
| **V0.9 — travel mode** | ✅ | Portable AP+STA operation: `mode` key (`dns`/`travel`), WPA2 AP `Shield-XXXX` with auto-generated password, DHCP advertising the Shield as DNS, NAPT to the STA uplink, captive-portal provisioning on the travel AP, WPS push-button provisioning (`POST /api/wps/start`), MAC tracking from DHCP leases. NAT throughput is tens of Mbps — fine for browsing/streaming, not a gigabit replacement. |

## Future

Roughly in the order they'd matter to a home user:

- **DoH/DoT upstream** — DNS-over-HTTPS / DNS-over-TLS for upstream queries, so the ISP can't snoop or tamper with resolutions. Needs mbedTLS client work beyond what OTA already uses, plus config for provider templates.
- **TCP DNS fallback** — serve DNS over TCP (and retry upstream over TCP on truncated UDP replies). Currently UDP-only; truncated large responses are forwarded as-is and the client is on its own.
- **Custom blocklist-source API** — `PUT /api/blocklist/sources` (proposed in [BLOCKLISTS.md](BLOCKLISTS.md#custom-sources)): persist user-supplied URLs, apply on next update. The updater already supports `set_sources()`; only the API + persistence are missing.
- **Hostname discovery** — fill in the empty `hostname` field: DHCP snooping, mDNS/Bonjour listening, and/or NetBIOS. Turns "192.168.1.10" into "living-room-tv" in the device list.
- **Gateway mode** — optional NAT/routing so the Shield can be the network's gateway, not just its DNS. Much bigger blast radius (all traffic, not just DNS); strictly opt-in if ever.
- **Per-device policies** — different blocklists/block modes per client (kids' devices vs. adults'), building on the device tracker + custom rules.
- **Query analytics retention** — currently stats live in RAM + a periodic `stats.json` flush; longer history and trends need either more flash budgeting or an export endpoint.

## Non-goals

Things that will *not* be built, because they contradict the project's design:

- **TLS interception / HTTPS filtering.** The Shield will never MITM your traffic. DNS-level blocking is the whole product; content inspection would break encryption trust and explode complexity. (See the README callout.)
- **SPIFFS.** LittleFS won; not revisiting.
- **Arduino framework.** ESP-IDF only — the component structure, partitions, and OTA rollback depend on it.
