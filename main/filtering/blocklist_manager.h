#pragma once
// RAM blocklist lookup: Bloom filter (fast negative) + binary search on the
// active slot file (exact verify). CONTRACTS.md section 6. ESP-IDF v5, C++17.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "core/bloom_filter.h"

namespace shield {

class BlocklistManager {
 public:
  static BlocklistManager& instance();

  // Builds the RAM Bloom filter from the ACTIVE slot file. A missing slot file
  // is fine (empty filter, count 0); a corrupt header is an error.
  bool init();

  // Exact check: Bloom negative => false fast (no flash I/O); Bloom positive
  // => verified with a binary search on flash to rule out false positives.
  // Does the suffix walk internally ("a.b.c" also matches "b.c").
  bool is_blocked(const std::string& normalized_domain);

  uint64_t entry_count() const;
  size_t bloom_bits() const;

  // Called by the updater AFTER a validated slot file was written:
  // flips active.txt, then rebuilds the Bloom from the new slot.
  // The old slot file is kept on flash (instant rollback = flip back).
  // Serialized against is_blocked() by mutex_.
  bool activate_slot(char slot);

 private:
  BlocklistManager();
  bool load_slot_locked(char slot);  // caller must hold mutex_

  mutable std::mutex mutex_;  // guards is_blocked() vs rebuild
  std::unique_ptr<BloomFilter> bloom_;
  uint64_t entry_count_ = 0;
  char active_slot_ = 'A';
};

}  // namespace shield
