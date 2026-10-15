#pragma once
// Custom per-domain rules, persisted to /littlefs/custom_rules.json as
// [{"domain":"x.com","action":"block","enabled":true,"id":3}].
// CONTRACTS.md section 6. ESP-IDF v5, C++17.

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace shield {

struct CustomRule {
  uint32_t id = 0;  // 0 = invalid / none
  std::string domain;  // normalized
  bool block = true;   // true = block, false = allow (exception)
  bool enabled = true;
};

class CustomRules {
 public:
  static CustomRules& instance();

  bool init();  // loads JSON; missing file => empty, still returns true

  // Adds a rule (or updates the existing rule for the same domain, keeping
  // its id) and persists. Returns the rule id, or 0 on invalid domain /
  // persist failure. Ids are monotonic (max(id)+1 restored on load).
  uint32_t add(const std::string& domain, bool block);

  bool remove(uint32_t id);  // persists; returns true iff a rule was removed

  // Longest-suffix match among ENABLED rules: the walk yields the most
  // specific suffix first, so the first enabled rule hit wins. Returns true
  // if a rule matched (out_block set); false => no rule applies.
  bool match(const std::string& normalized_domain, bool* out_block) const;

  std::vector<CustomRule> list() const;  // sorted by id, for the web UI

 private:
  CustomRules();
  bool load_locked();
  bool save_locked() const;

  mutable std::mutex mutex_;
  std::vector<CustomRule> rules_;
  uint32_t next_id_ = 1;  // monotonic; restored as max(id)+1 on load
};

}  // namespace shield
