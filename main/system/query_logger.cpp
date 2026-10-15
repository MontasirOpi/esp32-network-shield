#include "system/query_logger.h"

namespace shield {

QueryLogger& QueryLogger::instance() {
  static QueryLogger inst;
  return inst;
}

void QueryLogger::log(const QueryLogEntry& e) {
  std::lock_guard<std::mutex> lock(mutex_);
  buf_[head_] = e;
  head_ = (head_ + 1) % kCapacity;
  if (count_ < kCapacity) ++count_;
}

void QueryLogger::get_entries(std::vector<QueryLogEntry>& out, size_t max_n) {
  std::lock_guard<std::mutex> lock(mutex_);
  out.clear();
  const size_t n = (max_n < count_) ? max_n : count_;
  out.reserve(n);
  // Newest first: walk backwards from the most recent write.
  for (size_t i = 0; i < n; ++i) {
    const size_t idx = (head_ + kCapacity - 1 - i) % kCapacity;
    out.push_back(buf_[idx]);
  }
}

}  // namespace shield
