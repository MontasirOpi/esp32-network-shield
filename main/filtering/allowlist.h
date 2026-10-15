#pragma once
// Allowlist: RAM unordered_set of normalized domains, persisted to
// /littlefs/allowlist.json as {"domains":[...]}. CONTRACTS.md section 6.
// ESP-IDF v5, C++17.

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace shield {

// contains() does a suffix walk: allowing "example.com" also allows
// "ads.example.com". add()/remove() normalize the input and persist the JSON
// atomically (temp file + rename).
class Allowlist {
 public:
  static Allowlist& instance();

  bool init();  // loads JSON; missing file => empty set, still returns true
  bool contains(const std::string& normalized_domain) const;  // suffix walk
  bool add(const std::string& domain);      // normalizes, persists
  bool remove(const std::string& domain);   // normalizes, persists;
                                            // returns true iff it was present
  std::vector<std::string> list() const;    // sorted, for the web UI

 private:
  Allowlist();
  bool load_locked();
  bool save_locked() const;

  mutable std::mutex mutex_;
  std::unordered_set<std::string> domains_;
};

}  // namespace shield
