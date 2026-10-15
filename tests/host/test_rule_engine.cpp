// Host tests for RuleEngine (precedence, suffix walk, kill-switch).

#include <string>

#include "core/rule_engine.h"
#include "test_framework.h"

using namespace shield;

TEST(rule_engine_disabled_allows_all) {
  RuleEngine re;
  re.set_enabled(false);
  re.set_blocklist_lookup([](const std::string&) { return true; });
  re.set_custom_rules({{"evil.com", true}});
  CHECK(re.decide("evil.com") == DnsDecision::ALLOW);
  CHECK(re.decide("anything.example.net") == DnsDecision::ALLOW);
  // Re-enabling restores blocking.
  re.set_enabled(true);
  CHECK(re.decide("evil.com") == DnsDecision::BLOCK);
}

TEST(rule_engine_allowlist_beats_blocklist_on_parent) {
  RuleEngine re;
  re.set_allowlist({"example.com"});
  // Blocklist also matches the parent domain...
  re.set_blocklist_lookup(
      [](const std::string& s) { return s == "example.com"; });
  // ...but the allowlist wins at that level.
  CHECK(re.decide("www.example.com") == DnsDecision::ALLOW);
  CHECK(re.decide("example.com") == DnsDecision::ALLOW);
  // Unrelated domains still consult the blocklist normally.
  CHECK(re.decide("other.org") == DnsDecision::ALLOW);
}

TEST(rule_engine_custom_block_beats_blocklist) {
  RuleEngine re;
  re.set_custom_rules({{"evil.com", true}});
  re.set_blocklist_lookup([](const std::string& s) { return s == "evil.com"; });
  CHECK(re.decide("evil.com") == DnsDecision::BLOCK);
  CHECK(re.decide("sub.evil.com") == DnsDecision::BLOCK);
}

TEST(rule_engine_custom_allow_beats_blocklist) {
  RuleEngine re;
  re.set_custom_rules({{"evil.com", false}});  // explicit allow
  re.set_blocklist_lookup([](const std::string& s) { return s == "evil.com"; });
  CHECK(re.decide("evil.com") == DnsDecision::ALLOW);
  CHECK(re.decide("sub.evil.com") == DnsDecision::ALLOW);
}

TEST(rule_engine_allowlist_beats_custom_block) {
  RuleEngine re;
  re.set_allowlist({"example.com"});
  re.set_custom_rules({{"example.com", true}});
  re.set_blocklist_lookup([](const std::string&) { return false; });
  CHECK(re.decide("example.com") == DnsDecision::ALLOW);
  CHECK(re.decide("www.example.com") == DnsDecision::ALLOW);
}

TEST(rule_engine_subdomain_walk_blocks) {
  RuleEngine re;
  // Blocklist matches only the parent "example.com".
  re.set_blocklist_lookup(
      [](const std::string& s) { return s == "example.com"; });
  CHECK(re.decide("cdn.ads.example.com") == DnsDecision::BLOCK);
  CHECK(re.decide("ads.example.com") == DnsDecision::BLOCK);
  CHECK(re.decide("example.com") == DnsDecision::BLOCK);
  CHECK(re.decide("example.com.evil.org") == DnsDecision::ALLOW);
  CHECK(re.decide("other.org") == DnsDecision::ALLOW);
}

TEST(rule_engine_normalizes_input) {
  RuleEngine re;
  re.set_blocklist_lookup(
      [](const std::string& s) { return s == "example.com"; });
  CHECK(re.decide("WWW.EXAMPLE.COM.") == DnsDecision::BLOCK);
  CHECK(re.decide("  www.example.com  ") == DnsDecision::BLOCK);
  CHECK(re.decide("WwW.ExAmPlE.CoM") == DnsDecision::BLOCK);
}

TEST(rule_engine_empty_and_garbage_allow) {
  RuleEngine re;
  re.set_blocklist_lookup([](const std::string&) { return true; });
  CHECK(re.decide("") == DnsDecision::ALLOW);
  CHECK(re.decide("   ") == DnsDecision::ALLOW);
  CHECK(re.decide(".") == DnsDecision::ALLOW);
}

TEST(rule_engine_no_lists_configured_allows) {
  RuleEngine re;  // nothing set: no allowlist, no custom, no lookup
  CHECK(re.decide("anything.example") == DnsDecision::ALLOW);
}

TEST(rule_engine_setters_replace) {
  RuleEngine re;
  re.set_allowlist({"a.com"});
  re.set_allowlist({"b.com"});  // replaces, does not merge
  re.set_blocklist_lookup([](const std::string&) { return true; });
  CHECK(re.decide("a.com") == DnsDecision::BLOCK);
  CHECK(re.decide("b.com") == DnsDecision::ALLOW);
}
