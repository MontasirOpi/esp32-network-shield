#include "system/device_tracker.h"

#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace shield {

DeviceTracker& DeviceTracker::instance() {
  static DeviceTracker inst;
  return inst;
}

DeviceTracker::Slot* DeviceTracker::find_or_alloc_slot(uint32_t ip_net_order,
                                                      uint32_t now) {
  for (auto& s : slots_) {
    if (s.ip == ip_net_order) return &s;
  }
  // Prefer a free slot; when full, evict the oldest last_seen.
  Slot* slot = nullptr;
  Slot* oldest = nullptr;
  for (auto& s : slots_) {
    if (s.ip == 0) {
      slot = &s;
      break;
    }
    if (oldest == nullptr || s.last_seen_s < oldest->last_seen_s) oldest = &s;
  }
  if (slot == nullptr) slot = oldest;  // table full: reuse oldest entry
  slot->ip = ip_net_order;
  slot->mac[0] = '\0';
  slot->hostname[0] = '\0';
  slot->queries = 0;
  slot->blocked = 0;
  slot->first_seen_s = now;
  return slot;
}

uint32_t DeviceTracker::now_s() {
  // Uptime seconds from the FreeRTOS tick count (ticks * ms/tick = ms, /1000).
  return static_cast<uint32_t>((xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000);
}

void DeviceTracker::note_query(uint32_t ip_net_order, bool blocked) {
  if (ip_net_order == 0) return;
  std::lock_guard<std::mutex> lock(mutex_);
  const uint32_t now = now_s();

  Slot* slot = find_or_alloc_slot(ip_net_order, now);
  ++slot->queries;
  if (blocked) ++slot->blocked;
  slot->last_seen_s = now;
}

// Upsert a client by IP+MAC without counting a query (DHCP lease events).
void DeviceTracker::note_client(uint32_t ip_net_order, const char* mac) {
  if (ip_net_order == 0 || mac == nullptr || mac[0] == '\0') return;
  std::lock_guard<std::mutex> lock(mutex_);
  const uint32_t now = now_s();

  Slot* slot = find_or_alloc_slot(ip_net_order, now);
  strncpy(slot->mac, mac, sizeof(slot->mac) - 1);
  slot->mac[sizeof(slot->mac) - 1] = '\0';
  slot->last_seen_s = now;
}

void DeviceTracker::set_hostname(uint32_t ip_net_order, const char* hostname) {
  if (ip_net_order == 0 || hostname == nullptr) return;
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& s : slots_) {
    if (s.ip == ip_net_order) {
      strncpy(s.hostname, hostname, sizeof(s.hostname) - 1);
      s.hostname[sizeof(s.hostname) - 1] = '\0';
      return;
    }
  }
}

void DeviceTracker::get_devices(std::vector<DeviceEntry>& out) {
  std::lock_guard<std::mutex> lock(mutex_);
  out.clear();
  out.reserve(kMaxDevices);
  for (const auto& s : slots_) {
    if (s.ip == 0) continue;
    DeviceEntry e;
    e.ip = s.ip;
    strncpy(e.mac, s.mac, sizeof(e.mac) - 1);
    e.mac[sizeof(e.mac) - 1] = '\0';
    strncpy(e.hostname, s.hostname, sizeof(e.hostname) - 1);
    e.hostname[sizeof(e.hostname) - 1] = '\0';
    e.queries = s.queries;
    e.blocked = s.blocked;
    e.first_seen_s = s.first_seen_s;
    e.last_seen_s = s.last_seen_s;
    out.push_back(e);
  }
}

}  // namespace shield
