// Filtering decision engine (CONTRACTS.md section 4). Pure C++17.

#include "core/rule_engine.h"

namespace shield {

void RuleEngine::set_allowlist(std::unordered_set<std::string> domains) {
  allowlist_ = std::move(domains);
}

void RuleEngine::set_custom_rules(
    std::unordered_map<std::string, bool> domain_to_block) {
  custom_ = std::move(domain_to_block);
}

void RuleEngine::set_blocklist_lookup(BlocklistLookup fn) {
  blocklist_lookup_ = std::move(fn);
}

void RuleEngine::set_enabled(bool enabled) { enabled_ = enabled; }

DnsDecision RuleEngine::decide(const std::string& raw_qname) const {
  if (!enabled_) return DnsDecision::ALLOW;  // master kill-switch
  const std::string name = normalize_domain(raw_qname);
  if (name.empty()) return DnsDecision::ALLOW;
  DnsDecision result = DnsDecision::ALLOW;
  // Most-specific suffix first; at each level allowlist wins over a custom
  // rule, which wins over the blocklist. A match stops the walk immediately.
  for_each_parent_domain(name, [&](const std::string& suffix) {
    if (allowlist_.find(suffix) != allowlist_.end()) {
      result = DnsDecision::ALLOW;
      return false;
    }
    const auto it = custom_.find(suffix);
    if (it != custom_.end()) {
      result = it->second ? DnsDecision::BLOCK : DnsDecision::ALLOW;
      return false;
    }
    if (blocklist_lookup_ && blocklist_lookup_(suffix)) {
      result = DnsDecision::BLOCK;
      return false;
    }
    return true;  // no match at this level: walk up to the parent domain
  });
  return result;
}

}  // namespace shield
