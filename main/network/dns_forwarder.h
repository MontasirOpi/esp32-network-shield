#pragma once

// Raw DNS forwarder: sends a query verbatim to an upstream resolver over UDP
// and returns the response verbatim (EDNS0 and flags preserved; the query is
// NEVER modified). Fails over from primary to secondary on timeout/error and
// tracks per-upstream health (last RTT + consecutive failures) for /api/status.

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace shield {

class DnsForwarder {
 public:
  // Callers must provide response buffers of at least this size.
  static constexpr size_t kMaxMessage = 4096;

  // Health snapshot for one upstream, consumed by the /api/status endpoint.
  struct UpstreamHealth {
    char ip[16] = {0};               // dotted quad
    uint32_t last_rtt_ms = 0;        // RTT of the last successful query
    uint32_t consecutive_failures = 0;
    bool reachable = true;           // false while failures are outstanding
  };

  DnsForwarder();
  ~DnsForwarder();

  DnsForwarder(const DnsForwarder&) = delete;
  DnsForwarder& operator=(const DnsForwarder&) = delete;

  // Opens the UDP socket and stores upstreams. Re-callable to reconfigure.
  // timeout_ms is the per-upstream receive timeout.
  bool init(const char* primary_ip, const char* secondary_ip, uint32_t timeout_ms);

  // Forwards req verbatim to the primary upstream; on timeout/error retries
  // with the secondary. Response sanity: transaction ID must match the query
  // and QDCOUNT >= 1. Returns false if both upstreams fail. Thread-safe.
  // resp must point to at least kMaxMessage bytes.
  bool forward(const uint8_t* req, size_t req_len,
               uint8_t* resp, size_t* resp_len, uint32_t* rtt_ms_out);

  // Replaces the upstream pair and timeout (keeps the socket). Thread-safe.
  void set_upstreams(const char* primary_ip, const char* secondary_ip, uint32_t timeout_ms);

  // Copies health for upstream 0 (primary) or 1 (secondary). Thread-safe.
  bool upstream_health(int index, UpstreamHealth* out) const;

 private:
  bool try_upstream(int idx, const uint8_t* req, size_t req_len,
                    uint8_t* resp, size_t* resp_len, uint32_t* rtt_ms_out);
  void note_success(int idx, uint32_t rtt_ms);
  void note_failure(int idx);
  bool apply_timeout();

  mutable std::mutex mutex_;
  char primary_[16] = {0};
  char secondary_[16] = {0};
  uint32_t timeout_ms_ = 2500;
  int sock_ = -1;
  UpstreamHealth health_[2];
  // Receive scratch in BSS (not on the caller's stack); only touched while
  // mutex_ is held by forward(), so it is safe to share across calls.
  uint8_t rx_buf_[kMaxMessage];
};

}  // namespace shield
