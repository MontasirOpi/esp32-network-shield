// Host tests for domain_matcher (normalize, parent walk, FNV-1a).

#include <vector>

#include "core/domain_matcher.h"
#include "test_framework.h"

using namespace shield;

TEST(domain_matcher_normalize_basic) {
  CHECK_STR_EQ(normalize_domain("Example.COM"), "example.com");
  CHECK_STR_EQ(normalize_domain("www.example.com"), "www.example.com");
  CHECK_STR_EQ(normalize_domain("MiXeD.CaSe.NeT"), "mixed.case.net");
  CHECK_STR_EQ(normalize_domain("a"), "a");
  CHECK_STR_EQ(normalize_domain("123.456"), "123.456");
}

TEST(domain_matcher_normalize_trailing_dot) {
  // Exactly ONE trailing dot is stripped.
  CHECK_STR_EQ(normalize_domain("www.example.com."), "www.example.com");
  CHECK_STR_EQ(normalize_domain("example.com.."), "example.com.");
  CHECK_STR_EQ(normalize_domain("example.com. "), "example.com");
}

TEST(domain_matcher_normalize_whitespace) {
  CHECK_STR_EQ(normalize_domain("  spaced.example.com  "), "spaced.example.com");
  CHECK_STR_EQ(normalize_domain("\t\nExample.COM.\r\n"), "example.com");
  CHECK_STR_EQ(normalize_domain(""), "");
  CHECK_STR_EQ(normalize_domain("   "), "");
  CHECK_STR_EQ(normalize_domain("\t \n"), "");
}

TEST(domain_matcher_normalize_empty_results) {
  // Degenerate inputs collapse to "" (rejected as unusable).
  CHECK_STR_EQ(normalize_domain(""), "");
  CHECK_STR_EQ(normalize_domain("."), "");
  CHECK_STR_EQ(normalize_domain(" . "), "");
}

TEST(domain_matcher_parent_walk_order) {
  std::vector<std::string> seen;
  for_each_parent_domain("cdn.ads.example.com", [&](const std::string& s) {
    seen.push_back(s);
    return true;
  });
  CHECK_EQ(seen.size(), 3u);
  if (seen.size() == 3) {
    CHECK_STR_EQ(seen[0], "cdn.ads.example.com");
    CHECK_STR_EQ(seen[1], "ads.example.com");
    CHECK_STR_EQ(seen[2], "example.com");  // stops before bare TLD "com"
  }
}

TEST(domain_matcher_parent_walk_short_names) {
  std::vector<std::string> seen;
  for_each_parent_domain("example.com", [&](const std::string& s) {
    seen.push_back(s);
    return true;
  });
  CHECK_EQ(seen.size(), 1u);
  if (!seen.empty()) CHECK_STR_EQ(seen[0], "example.com");

  seen.clear();
  for_each_parent_domain("localhost", [&](const std::string& s) {
    seen.push_back(s);
    return true;
  });
  CHECK_EQ(seen.size(), 1u);
  if (!seen.empty()) CHECK_STR_EQ(seen[0], "localhost");
}

TEST(domain_matcher_parent_walk_early_stop) {
  std::vector<std::string> seen;
  for_each_parent_domain("a.b.c.d", [&](const std::string& s) {
    seen.push_back(s);
    return seen.size() < 2;  // stop after two yields
  });
  CHECK_EQ(seen.size(), 2u);
  if (seen.size() == 2) {
    CHECK_STR_EQ(seen[0], "a.b.c.d");
    CHECK_STR_EQ(seen[1], "b.c.d");
  }
}

TEST(domain_matcher_parent_walk_full_depth) {
  std::vector<std::string> seen;
  for_each_parent_domain("a.b.c.d", [&](const std::string& s) {
    seen.push_back(s);
    return true;
  });
  CHECK_EQ(seen.size(), 3u);  // a.b.c.d, b.c.d, c.d (never bare "d")
}

TEST(domain_matcher_fnv1a_known_vector) {
  // Contract: fnv1a_64("") == 14695981039346656037 (the offset basis).
  CHECK_EQ(fnv1a_64(""), 14695981039346656037ULL);
}

TEST(domain_matcher_fnv1a_properties) {
  CHECK_EQ(fnv1a_64("example.com"), fnv1a_64("example.com"));  // deterministic
  CHECK(fnv1a_64("example.com") != fnv1a_64("example.org"));   // sensitive
  CHECK(fnv1a_64("a") != fnv1a_64("b"));
  CHECK(fnv1a_64("") != fnv1a_64("a"));
  // Case matters pre-normalization (callers normalize first).
  CHECK(fnv1a_64("ABC") != fnv1a_64("abc"));
}
