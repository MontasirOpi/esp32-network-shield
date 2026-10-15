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
  // Records (or refreshes) a client known by MAC, e.g. from the DHCP server's
  // IPASSIGNED event in travel mode. Does NOT count a query; creates the slot
  // so the MAC is visible even before the client's first DNS query.
  void note_client(uint32_t ip_net_order, const char* mac);
  void set_hostname(uint32_t ip_net_order, const char* hostname);
  void get_devices(std::vector<DeviceEntry>& out);

  DeviceTracker(const DeviceTracker&) = delete;
  DeviceTracker& operator=(const DeviceTracker&) = delete;

 private:
  DeviceTracker() = default;
  static constexpr int kMaxDevices = 32;

  struct Slot {
    uint32_t ip = 0;  // network byte order; 0 == free slot
    char mac[18] = {0};  // "AA:BB:CC:DD:EE:FF"; empty if unknown
    char hostname[64] = {0};
    uint32_t queries = 0;
    uint32_t blocked = 0;
    uint32_t first_seen_s = 0;
    uint32_t last_seen_s = 0;
  };

  static uint32_t now_s();

  // Finds the slot for ip, or allocates one (free slot preferred, else evict
  // the least-recently-seen). Initializes a fresh slot. Caller holds mutex_.
  Slot* find_or_alloc_slot(uint32_t ip_net_order, uint32_t now_s);

  std::mutex mutex_;
  Slot slots_[kMaxDevices];
};

}  // namespace shield
