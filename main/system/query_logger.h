#pragma once

// QueryLogger — RAM ring buffer of the last 200 DNS queries (CONTRACTS.md §7).
// get_entries() returns newest-first. Thread-safe via std::mutex.

#include <cstddef>
#include <mutex>
#include <vector>

#include "core/types.h"

namespace shield {

class QueryLogger {
 public:
  static QueryLogger& instance();

  void log(const QueryLogEntry& e);
  void get_entries(std::vector<QueryLogEntry>& out, size_t max_n);

  QueryLogger(const QueryLogger&) = delete;
  QueryLogger& operator=(const QueryLogger&) = delete;

 private:
  QueryLogger() = default;
  static constexpr size_t kCapacity = 200;

  std::mutex mutex_;
  QueryLogEntry buf_[kCapacity];
  size_t head_ = 0;   // next write index
  size_t count_ = 0;  // valid entries, <= kCapacity
};

}  // namespace shield
