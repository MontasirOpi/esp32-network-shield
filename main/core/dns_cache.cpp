// DNS response cache (CONTRACTS.md section 4). Pure C++17.

#include "core/dns_cache.h"

#include <chrono>

namespace shield {

namespace {
// TTL clamp bounds (seconds). Rationale: upstream TTLs below 60s cause
// excessive re-queries (and let trackers rotate answers quickly), while
// TTLs above a day risk serving stale blocks/allows long after a list
// update. Clamping keeps cache behavior predictable.
constexpr uint32_t kMinTtlS = 60;
constexpr uint32_t kMaxTtlS = 86400;
}  // namespace

uint32_t DnsCache::default_now_ms() {
  using namespace std::chrono;
  return static_cast<uint32_t>(
      duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
          .count());
}

DnsCache::DnsCache(size_t capacity, NowMs now)
    : capacity_(capacity), now_(std::move(now)) {
  if (!now_) now_ = default_now_ms;  // host-safe default; on device main.cpp
                                     // injects an esp_timer-based clock
}

std::string DnsCache::make_key(const std::string& qname, uint16_t qtype) {
  std::string key;
  key.reserve(qname.size() + 3);
  key += qname;
  key.push_back('\0');  // separator: qnames never contain NUL
  key.push_back(static_cast<char>(qtype >> 8));
  key.push_back(static_cast<char>(qtype & 0xFF));
  return key;
}

void DnsCache::store(const std::string& normalized_qname, uint16_t qtype,
                     const uint8_t* resp, size_t resp_len, uint32_t ttl_s) {
  if (capacity_ == 0 || resp == nullptr || resp_len < 2) return;
  const uint32_t ttl =
      ttl_s < kMinTtlS ? kMinTtlS : (ttl_s > kMaxTtlS ? kMaxTtlS : ttl_s);
  const uint64_t expires = static_cast<uint64_t>(now_()) +
                           static_cast<uint64_t>(ttl) * 1000ULL;
  const std::string key = make_key(normalized_qname, qtype);

  const auto it = map_.find(key);
  if (it != map_.end()) {
    // Refresh in place and mark most-recently-used.
    it->second.first.bytes.assign(resp, resp + resp_len);
    it->second.first.bytes[0] = 0;
    it->second.first.bytes[1] = 0;
    it->second.first.expires_ms = expires;
    lru_.erase(it->second.second);
    lru_.push_front(key);
    it->second.second = lru_.begin();
    return;
  }
  if (map_.size() >= capacity_) {
    map_.erase(lru_.back());  // evict least-recently-used
    lru_.pop_back();
  }
  Entry e;
  e.bytes.assign(resp, resp + resp_len);
  e.bytes[0] = 0;  // zero the transaction ID: it varies per query
  e.bytes[1] = 0;
  e.expires_ms = expires;
  lru_.push_front(key);
  map_.emplace(key, std::make_pair(std::move(e), lru_.begin()));
}

bool DnsCache::lookup(const std::string& normalized_qname, uint16_t qtype,
                      uint16_t query_id, std::vector<uint8_t>& out) {
  const auto it = map_.find(make_key(normalized_qname, qtype));
  if (it == map_.end()) return false;
  if (static_cast<uint64_t>(now_()) >= it->second.first.expires_ms) {
    lru_.erase(it->second.second);  // expired: purge and report a miss
    map_.erase(it);
    return false;
  }
  out = it->second.first.bytes;
  out[0] = static_cast<uint8_t>(query_id >> 8);  // patch the query's ID in
  out[1] = static_cast<uint8_t>(query_id & 0xFF);
  lru_.erase(it->second.second);  // mark most-recently-used
  lru_.push_front(it->first);
  it->second.second = lru_.begin();
  return true;
}

void DnsCache::clear() {
  map_.clear();
  lru_.clear();
}

}  // namespace shield
