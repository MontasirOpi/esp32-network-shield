#pragma once

// DeviceTracker — 32-slot table of client devices keyed by source IP
// (CONTRACTS.md §7). Full table evicts the least-recently-seen device.
// Timestamps are seconds since boot. Thread-safe via std::mutex.

#include <cstdint>
#include <mutex>
#include <vector>

#include "core/types.h"

namespace shield {

class DeviceTracker {
 public:
  static DeviceTracker& instance();

  void note_query(uint32_t ip_net_order, bool blocked);
  void set_hostname(uint32_t ip_net_order, const char* hostname);
  void get_devices(std::vector<DeviceEntry>& out);

  DeviceTracker(const DeviceTracker&) = delete;
  DeviceTracker& operator=(const DeviceTracker&) = delete;

 private:
  DeviceTracker() = default;
  static constexpr int kMaxDevices = 32;

  struct Slot {
    uint32_t ip = 0;  // network byte order; 0 == free slot
    char hostname[64] = {0};
    uint32_t queries = 0;
    uint32_t blocked = 0;
    uint32_t first_seen_s = 0;
    uint32_t last_seen_s = 0;
  };

  static uint32_t now_s();

  std::mutex mutex_;
  Slot slots_[kMaxDevices];
};

}  // namespace shield
