# Blocklists

The blocklist is the heart of the Shield: ~50k+ ad, tracker, and malware domains compiled into a sorted binary hash file on flash, fronted by a RAM Bloom filter. This doc covers where the domains come from, what formats are understood, how updates work, and why an update can never break filtering.

## Default sources

Compiled into the firmware (V1 defaults — see [Custom sources](#custom-sources)):

| Source | URL | What it is |
|---|---|---|
| StevenBlack/hosts | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | The unified hosts file: adware + malware domains merged from multiple well-known lists. Tens of thousands of entries. |
| someonewhocares — zero hosts | `https://someonewhocares.org/hosts/zero/hosts` | Dan Pollock's long-running hosts list in `0.0.0.0` format. |

Both are fetched over HTTPS on every update, parsed, merged, deduplicated, and sorted. `GET /api/blocklist` reports the active source list.

## Supported formats

The updater (`BlocklistUpdater`) understands two line formats, mixed freely in one file:

```
# comment lines start with # and are ignored (blank lines too)
0.0.0.0 ads.example.com          <- hosts-file line: IP, then domain
127.0.0.1 tracker.example.net    <- hosts-file line: loopback IP also accepted
plain-domain.example.org         <- bare domain list: one domain per line
```

Parsing rules:

- `#` comments and blank lines are skipped.
- Hosts lines: the IP token (`0.0.0.0`, `127.0.0.1`, …) is discarded; the **first domain token** after it is kept. (StevenBlack's file uses `0.0.0.0`; some lists use `127.0.0.1` — both parse.)
- Bare lines are treated as domains directly.
- Every domain is **normalized** before hashing: lowercased, whitespace trimmed, one trailing dot stripped. `Ads.Example.COM.` and `ads.example.com` become the same entry.
- **IDN/punycode is not handled in V1** — internationalized domains match only in their raw ASCII form.
- After merging all sources: deduplicate → FNV-1a-64 hash each → sort ascending → write the slot file.

Note: the updater only *adds* what's in the sources. Removals (a domain taken off a list upstream) take effect on the next update because each update rebuilds the slot from scratch — there's no incremental state to go stale.

## Custom sources

**Honest status for V1:** `BlocklistUpdater::set_sources()` exists in the firmware, but **no REST route calls it** — so the source list is effectively the compiled-in defaults. To use different sources today you must change the default URL list in the firmware and rebuild/reflash.

**Proposed (not implemented):** a future API along these lines, persisting the list to LittleFS/NVS and applying it on the next update:

```http
PUT /api/blocklist/sources            (PROPOSED — does not exist in V1)
{"urls": ["https://my.server/list.txt"]}
```

If you need a custom source now and can't rebuild: the allowlist/custom-rules APIs cover one-off additions, and a full custom list can be staged by building with modified defaults. Track this in [ROADMAP.md](ROADMAP.md).

## Update validation

Before a freshly written slot goes live, **all** of these must pass:

1. **Entry count ≥ 1000** — catches truncated downloads and empty parses (a real list is tens of thousands).
2. **`doubleclick.net` is present** — known-bad spot check. If the internet's most infamous ad domain isn't in the parsed output, parsing broke.
3. **`google.com` is absent** — known-good spot check. If a benign giant is listed, the source or parser is corrupt (and you'd nuke your own network).
4. **File sanity** — magic is `"ESBL"`, version is 1, and the `count` header matches the actual file size.

Any failure aborts the update: the new slot file is left in place but **never activated**, and the previous slot keeps serving. The result (ok/fail + message) is available to the firmware via `UpdateResult`; surfaced to users through `GET /api/blocklist` no longer changing.

## A/B update safety

The design goal: **there is no moment — not during download, parse, flash write, power loss, or validation failure — when filtering stops working or serves a corrupt list.**

- **Two slots, one active.** `/littlefs/blocklists/` holds `slot_a.bl`, `slot_b.bl`, and `active.txt` (`A`/`B`). Queries always verify against the *active* slot.
- **The updater only ever writes the inactive slot.** The active file is never opened for writing by the updater — a crash mid-download corrupts at worst a file nobody reads.
- **Validate, then switch.** Only a slot that passed all four validation checks is eligible for activation.
- **Atomic activation.** `set_active_slot()` writes a temp file and renames it over `active.txt` — a single atomic filesystem operation. There is no torn-write window.
- **Bloom rebuilt under lock after the switch.** `BlocklistManager::activate_slot()` flips the active pointer first (the new slot file was already fully validated, so a crash here still leaves a good list active), then rebuilds the RAM Bloom filter while holding the manager mutex — queries are briefly serialized during the rebuild, never served from a half-built filter.
- **The old slot is kept.** If a new list misbehaves in production (over-blocking), the previous slot file is still on flash for instant manual fallback — no re-download needed.
- **Boot is safe too.** `BlocklistManager::init()` builds the Bloom filter from whatever slot `active.txt` points at. If no slot exists yet (first boot before any update), the count is 0 and everything is allowed until the first successful update — filtering degrades to *open*, never to *broken*.

Trigger updates manually with `POST /api/blocklist/update`, or let the automatic cadence (`update_interval_h`, default 24 h) handle it.

## For maintainers

- **Slot file format** is specified in [ARCHITECTURE.md](ARCHITECTURE.md#7-slot-file-format-spec): 16-byte header + sorted FNV-1a-64 hashes.
- **RAM math** (why Bloom + flash instead of a RAM hash set) is in [ARCHITECTURE.md](ARCHITECTURE.md#9-ram-budget-classic-esp32-320-kb-dram).
- **Flash sizing**: ~8 bytes/entry/slot. 50k entries ≈ 391 KB per slot; the default 960 KB LittleFS partition fits two such slots with ~180 KB headroom. Bigger lists → grow `littlefs` in `partitions.csv` (8–16 MB flash S3 builds).
- **Update-time RAM.** Parsed hashes accumulate in a flat vector (8 bytes/entry — no hash-set node overhead), allocated from SPIRAM first when the board has it (ESP32-S3 or PSRAM-fitted modules: ~65k default-source entries ≈ 520 KB, comfortably inside 8 MB PSRAM). On SPIRAM-less classic ESP32 the working set is capped at 15k entries (~120 KB) so an update degrades to a *partial* list with a warning instead of OOM-crashing; the active slot is untouched either way. Updates run in their own task, never in the DNS hot path.
