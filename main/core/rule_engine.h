#pragma once
// Filtering decision engine (CONTRACTS.md section 4). Pure C++17.
// Precedence: allowlist (suffix) > custom rule (suffix) > blocklist (suffix).
// Returns DnsDecision::BLOCK or ::ALLOW (NXDOMAIN is decided by BlockMode
// later, in build_block_response).

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "core/domain_matcher.h"
#include "core/types.h"

namespace shield {

class RuleEngine {
 public:
  using BlocklistLookup = std::function<bool(const std::string& normalized_domain)>;

  void set_allowlist(std::unordered_set<std::string> domains);  // normalized expected
  void set_custom_rules(std::unordered_map<std::string, bool> domain_to_block);
  void set_blocklist_lookup(BlocklistLookup fn);
  void set_enabled(bool enabled);  // false => everything ALLOWs

  DnsDecision decide(const std::string& raw_qname) const;

 private:
  std::unordered_set<std::string> allowlist_;
  std::unordered_map<std::string, bool> custom_;
  BlocklistLookup blocklist_lookup_;
  bool enabled_ = true;
};

}  // namespace shield
