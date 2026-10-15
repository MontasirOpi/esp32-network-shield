#pragma once

// StatsEngine — RAM query counters persisted to /littlefs/stats.json every N
// minutes (CONTRACTS.md §7). Top-blocked domains tracked in a fixed 32-slot
// array (linear search, no heap churn). Thread-safe via std::mutex.

#include <cstdint>
#include <mutex>
#include <string>

#include "core/types.h"

namespace shield {

class StatsEngine {
 public:
  static StatsEngine& instance();

  // Loads totals from /littlefs/stats.json if present; sets persist cadence.
  // Must be called after LittleFS is mounted.
  void init(uint8_t flush_interval_min);

  void record_query(const std::string& domain, DnsDecision d, bool cache_hit);
  void snapshot(StatsSnapshot* out);  // top_blocked: top 10, sorted desc
  void loop();                        // call from monitor task; flushes when due

  StatsEngine(const StatsEngine&) = delete;
  StatsEngine& operator=(const StatsEngine&) = delete;

 private:
  StatsEngine() = default;

  static constexpr int kTopSlots = 32;
  struct TopSlot {
    uint64_t hash = 0;
    char domain[64] = {0};
    uint32_t count = 0;  // 0 == free slot
  };

  void load();
  void flush();

  std::mutex mutex_;
  uint32_t total_ = 0;
  uint32_t blocked_ = 0;
  uint32_t cache_hits_ = 0;
  TopSlot top_[kTopSlots];
  uint8_t flush_min_ = 5;
  uint32_t last_flush_ms_ = 0;  // esp_timer ms clock
  bool initialized_ = false;
};

}  // namespace shield
