#pragma once

// Minimal UDP DNS server for the ESP32 Network Shield.
//
// Owns a BSD lwIP UDP socket bound to port 53 (all interfaces) and a pinned
// FreeRTOS task that feeds each incoming packet to a user-supplied handler.
// If the handler produces a response, it is sent back to the packet source.
// Used by the filtering pipeline (Team E) and by the captive-portal hijack
// in provisioning mode (WifiManager).

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace shield {

class DnsServer {
 public:
  // Largest DNS message accepted/generated (EDNS0-sized UDP datagram).
  // Handlers must never set *resp_len above this.
  static constexpr size_t kMaxMessage = 4096;
  // Packets shorter than a DNS header are silently ignored.
  static constexpr size_t kMinQuery = 12;

  // Return true if the handler produced a response (sets *resp_len, which must
  // be <= kMaxMessage). client_ip is the querier's IPv4 address, network byte
  // order. Runs on the server task: keep it short and non-blocking.
  using QueryHandler = std::function<bool(const uint8_t* req, size_t req_len,
                                          uint32_t client_ip /* net order */,
                                          uint8_t* resp, size_t* resp_len)>;

  DnsServer();
  ~DnsServer();

  DnsServer(const DnsServer&) = delete;
  DnsServer& operator=(const DnsServer&) = delete;

  // Binds UDP port (default 53) on all interfaces and starts the server task
  // (pinned to core 0, 4 KB stack, priority 5). Returns true if already running.
  bool start(uint16_t port = 53);

  // Shuts down the socket and ends the server task. Idempotent; safe to call
  // when not running.
  void stop();

  // Installs the query handler. Must be called before start() (or after stop());
  // not safe to swap while the server is running.
  void set_query_handler(QueryHandler h);

 private:
  static void task_entry(void* arg);
  void run();

  std::mutex mutex_;
  std::atomic<bool> running_{false};
  // Incremented on every start(); lets a stale task tell itself apart from a
  // newer generation after a quick stop()+start() (fd numbers get reused).
  std::atomic<uint32_t> gen_{0};
  QueryHandler handler_;
  int sock_ = -1;
  uint16_t port_ = 53;
  TaskHandle_t task_ = nullptr;
  // Per-instance packet buffers in BSS: kept off the 4 KB task stack and not
  // shared between instances (unlike function-static buffers).
  uint8_t req_buf_[kMaxMessage];
  uint8_t resp_buf_[kMaxMessage];
};

}  // namespace shield
