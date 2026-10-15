#pragma once
// Blocklist updater: downloads sources, parses, validates, and atomically
// activates the new slot. CONTRACTS.md section 6. ESP-IDF v5, C++17.
//
// Runs SYNCHRONOUSLY (can take minutes on slow links); the web layer must call
// update_now() from a worker task, never from the HTTP handler or DNS path.

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace shield {

struct UpdateResult {
  bool ok = false;
  uint64_t entries = 0;
  char message[128] = {};
};

class BlocklistUpdater {
 public:
  static BlocklistUpdater& instance();

  // Downloads all sources, parses hosts-format + plain-domain lists,
  // normalizes, dedupes, sorts, writes the INACTIVE slot, validates it, and
  // only then activates it. NEVER touches the active slot file: on ANY failure
  // the active slot is left untouched and ok=false with message explaining.
  // Default sources (docs/BLOCKLISTS.md):
  //   https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  //   https://someonewhocares.org/hosts/zero/hosts
  UpdateResult update_now();

  void set_sources(const std::vector<std::string>& urls);

 private:
  BlocklistUpdater();

  std::mutex mutex_;  // serializes concurrent update_now() calls
  std::vector<std::string> sources_;
};

}  // namespace shield
