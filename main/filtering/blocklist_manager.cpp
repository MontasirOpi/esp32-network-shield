#include "filtering/blocklist_manager.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "esp_log.h"

#include "core/domain_matcher.h"
#include "storage/blocklist_file.h"

namespace shield {
namespace {

const char* TAG = "blocklist_mgr";
constexpr double kBloomFpRate = 0.01;
constexpr size_t kMinBloomItems = 1000;  // never size the filter below this

}  // namespace

BlocklistManager::BlocklistManager() = default;

BlocklistManager& BlocklistManager::instance() {
  static BlocklistManager inst;
  return inst;
}

bool BlocklistManager::init() {
  std::lock_guard<std::mutex> lock(mutex_);
  active_slot_ = BlocklistFile::active_slot();
  return load_slot_locked(active_slot_);
}

bool BlocklistManager::load_slot_locked(char slot) {
  uint64_t count = 0;
  // Missing/unreadable slot file => treat as empty (first boot, no update
  // yet). read_count() already verified magic + version when it returns true.
  BlocklistFile::read_count(slot, &count);

  // Size the filter for max(count, 1000) at 1% FP rate, per contracts.
  size_t sizing = (size_t)std::max<uint64_t>(count, kMinBloomItems);
  bloom_ = std::make_unique<BloomFilter>(sizing, kBloomFpRate);

  if (count == 0) {
    entry_count_ = 0;
    active_slot_ = slot;
    ESP_LOGI(TAG, "slot '%c': empty, bloom sized for %u items (%u bits)", slot,
             (unsigned)sizing, (unsigned)bloom_->bit_count());
    return true;
  }

  // Stream the slot file sequentially, adding one hash per fread. The file is
  // never bulk-loaded: only the 16-byte header + one 8-byte hash are in RAM.
  char path[96];
  snprintf(path, sizeof(path), "%s/slot_%c.bl", kBlocklistDir,
           slot == 'A' ? 'a' : 'b');
  FILE* f = fopen(path, "rb");
  if (!f) {
    ESP_LOGE(TAG, "load slot '%c': open failed", slot);
    return false;
  }
  uint8_t hdr[16];
  bool ok = fread(hdr, 1, 16, f) == 16 && memcmp(hdr, "ESBL", 4) == 0;
  uint64_t added = 0;
  uint8_t buf[8];
  while (ok && added < count) {
    if (fread(buf, 1, 8, f) != 8) {
      ok = false;
      break;
    }
    uint64_t h = 0;
    for (int i = 0; i < 8; ++i) h |= (uint64_t)buf[i] << (8 * i);  // u64 LE
    bloom_->add(h);
    ++added;
  }
  fclose(f);
  if (!ok) {
    ESP_LOGE(TAG, "load slot '%c': truncated/corrupt file", slot);
    bloom_->clear();
    entry_count_ = 0;
    return false;
  }
  entry_count_ = count;
  active_slot_ = slot;
  ESP_LOGI(TAG, "slot '%c' loaded: %llu entries, bloom %u bits", slot,
           (unsigned long long)count, (unsigned)bloom_->bit_count());
  return true;
}

bool BlocklistManager::is_blocked(const std::string& normalized_domain) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!bloom_ || normalized_domain.empty()) return false;
  const char slot = active_slot_;  // snapshot under lock; rebuild swaps both
  bool blocked = false;
  // Suffix walk (most specific first): "a.b.c" -> "a.b.c", "b.c". Hash each
  // suffix; a Bloom negative is an exact "not blocked"; a Bloom positive is
  // verified against flash (binary search) to rule out false positives
  // before we block anything.
  for_each_parent_domain(normalized_domain, [&](const std::string& suffix) {
    uint64_t h = fnv1a_64(suffix);
    if (bloom_->possibly_contains(h) && BlocklistFile::contains(slot, h)) {
      blocked = true;
      return false;  // stop the walk
    }
    return true;
  });
  return blocked;
}

uint64_t BlocklistManager::entry_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return entry_count_;
}

size_t BlocklistManager::bloom_bits() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return bloom_ ? bloom_->bit_count() : 0;
}

bool BlocklistManager::activate_slot(char slot) {
  if (slot != 'A' && slot != 'B') {
    ESP_LOGE(TAG, "activate_slot: invalid slot '%c'", slot);
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  // 1. Flip the pointer first: the new slot file was already fully written and
  //    validated by the updater, so after this point a crash still leaves a
  //    valid, complete slot active.
  if (!BlocklistFile::set_active_slot(slot)) {
    ESP_LOGE(TAG, "activate_slot: set_active_slot failed");
    return false;
  }
  // 2. Rebuild the Bloom from the new slot. is_blocked() is serialized here,
  //    so no query can observe a half-built filter. The old slot file stays
  //    on flash: rollback is just another activate_slot() of the old letter.
  if (!load_slot_locked(slot)) {
    ESP_LOGE(TAG, "activate_slot: bloom rebuild failed for slot '%c'", slot);
    return false;
  }
  ESP_LOGI(TAG, "activated slot '%c' (%llu entries)", slot,
           (unsigned long long)entry_count_);
  return true;
}

}  // namespace shield
