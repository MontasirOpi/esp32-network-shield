#pragma once
// Shared types for the ESP32 Network Shield (CONTRACTS.md section 2).
// Pure C++17: no ESP-IDF includes, no logging.

#include <cstddef>
#include <cstdint>

namespace shield {

enum class DnsDecision : uint8_t { ALLOW = 0, BLOCK = 1, NXDOMAIN = 2 };
// NOTE: DnsDecision::BLOCK means "blocked"; HOW to answer is BlockMode.

enum class BlockMode : uint8_t {
  NULL_IP  = 0,  // answer A=0.0.0.0 / AAAA=::   (default)
  NXDOMAIN = 1,  // RCODE 3
  NODATA   = 2,  // NOERROR, ANCOUNT 0
};

struct DnsQuestionInfo {
  char     qname[256];   // normalized, no trailing dot, lowercased
  uint16_t qtype;        // e.g. 1=A, 28=AAAA
  uint16_t qclass;       // normally 1 (IN)
  uint32_t client_ip;    // IPv4, network byte order
};

struct StatsSnapshot {
  uint32_t total_queries   = 0;
  uint32_t blocked_queries = 0;
  uint32_t cache_hits      = 0;
  uint32_t upstream_queries= 0;
  uint32_t uptime_s        = 0;
  // top-N blocked domains, fixed size to avoid heap churn on device
  static constexpr int kMaxTop = 10;
  struct Entry { char domain[64]; uint32_t count; };
  Entry top_blocked[kMaxTop];
  int   top_blocked_count = 0;
};

struct DeviceEntry {
  uint32_t ip;                 // network byte order
  char     mac[18];            // "AA:BB:CC:DD:EE:FF", empty if unknown
  char     hostname[64];       // may be empty
  uint32_t queries   = 0;
  uint32_t blocked   = 0;
  uint32_t first_seen_s = 0;   // seconds since boot
  uint32_t last_seen_s  = 0;
};

struct QueryLogEntry {
  uint32_t    ts_s;            // seconds since boot
  uint32_t    client_ip;       // network byte order
  char        domain[128];     // normalized
  uint16_t    qtype;
  DnsDecision decision;
  bool        cached;
};

}  // namespace shield
