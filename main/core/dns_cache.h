#pragma once
// DNS response cache with TTL and LRU eviction (CONTRACTS.md section 4).
// Pure C++17. Key = normalized_qname + '\0' + qtype.

#include <cstdint>
#include <functional>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

namespace shield {

class DnsCache {
 public:
  using NowMs = std::function<uint32_t()>;  // injected; host tests use fake clock
  explicit DnsCache(size_t capacity = 256, NowMs now = nullptr);

  // Stores raw response bytes. The 2 transaction-ID bytes are zeroed on
  // store; TTL is clamped to [60, 86400] seconds. Evicts the
  // least-recently-used entry when full.
  void store(const std::string& normalized_qname, uint16_t qtype,
             const uint8_t* resp, size_t resp_len, uint32_t ttl_s);

  // On hit: copies the stored bytes, patches in query_id, returns true.
  // Expired entries are purged and report a miss.
  bool lookup(const std::string& normalized_qname, uint16_t qtype,
              uint16_t query_id, std::vector<uint8_t>& out);

  void clear();
  size_t size() const { return map_.size(); }

 private:
  struct Entry {
    std::vector<uint8_t> bytes;  // ID bytes zeroed
    uint64_t expires_ms = 0;
  };

  static std::string make_key(const std::string& qname, uint16_t qtype);
  static uint32_t default_now_ms();  // steady_clock; used when now == nullptr

  size_t capacity_;
  NowMs now_;
  std::list<std::string> lru_;  // front = most recently used
  std::unordered_map<std::string,
                     std::pair<Entry, std::list<std::string>::iterator>>
      map_;
};

}  // namespace shield
