#pragma once
// Blocklist slot-file storage (CONTRACTS.md section 6). ESP-IDF v5, C++17.
// LittleFS is mounted at /littlefs by System (Team E) before any call here.

#include <cstddef>  // size_t
#include <cstdint>
#include <type_traits>  // std::is_same for the write_slot() template
#include <vector>

namespace shield {

// Base directory for blocklist slot files. inline (C++17): this header is
// included by several translation units, and a plain namespace-scope
// `const char*` would violate the one-definition rule at link time.
inline constexpr const char* kBlocklistDir = "/littlefs/blocklists";

// Slot file format ("slot_a.bl" / "slot_b.bl"):
//   offset 0:  magic "ESBL" (4 bytes)
//   offset 4:  version u32 LE = 1
//   offset 8:  count u64 LE = N
//   offset 16: N x u64 LE, FNV-1a 64 of NORMALIZED domains, SORTED ascending
//
// A/B SAFETY INVARIANT (read before touching this file):
//   - Exactly one slot is ACTIVE (named in active.txt); the DNS hot path only
//     ever reads the active slot.
//   - write_slot() REFUSES to write the active slot (returns false + logs).
//     Updates always go to the INACTIVE slot, which is fully validated BEFORE
//     activation. The active slot file is therefore never half-written.
//   - Both slot files and active.txt are published via temp-file + rename(),
//     so a crash/power-loss can never leave a partially written file behind:
//     at worst the previous complete file (and previous active slot) remains.
//   - activate_slot() in BlocklistManager flips active.txt only after the new
//     slot file passed validation; the old slot file is kept for rollback.
class BlocklistFile {
 public:
  // Writes magic + version + count + hashes to slot_X.bl.tmp, then renames to
  // slot_X.bl (atomic publish). sorted_hashes MUST be sorted ascending.
  // Returns false (and logs) if slot is invalid OR slot is the ACTIVE slot.
  static bool write_slot(char slot /* 'A' or 'B' */,
                         const std::vector<uint64_t>& sorted_hashes);

  // Contiguous-range overload: accepts e.g. the updater's SPIRAM-backed
  // HashVec (std::vector<uint64_t, SpiramFirstAlloc<uint64_t>>) without
  // copying it into a default-allocator vector first.
  template <typename Container>
  static bool write_slot(char slot, const Container& sorted_hashes) {
    static_assert(std::is_same<typename Container::value_type,
                               uint64_t>::value,
                  "write_slot container must hold uint64_t");
    return write_slot_raw(slot, sorted_hashes.data(), sorted_hashes.size());
  }

  // Reads count from the slot header (verifies magic + version). Returns false
  // if the file is missing/unreadable/corrupt; callers may treat missing as
  // "no blocklist yet".
  static bool read_count(char slot, uint64_t* count_out);

  // Binary search WITHOUT loading the file: fopen "rb", then only seeks and
  // 8-byte reads (offset 16 + mid*8). Returns true iff hash is present.
  static bool contains(char slot, uint64_t hash);

  // Reads /littlefs/blocklists/active.txt; returns 'A' if missing/unreadable
  // or the content is anything other than 'B'.
  static char active_slot();

  // Atomically points the active slot at 'A'/'B' (temp file + rename).
  static bool set_active_slot(char slot);

 private:
  // Core writer behind both write_slot() overloads.
  static bool write_slot_raw(char slot, const uint64_t* data, size_t count);
};

}  // namespace shield
