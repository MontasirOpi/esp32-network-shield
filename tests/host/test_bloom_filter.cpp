// Host tests for BloomFilter (sizing math, no false negatives, FP rate).

#include <cstdio>
#include <string>

#include "core/bloom_filter.h"
#include "core/domain_matcher.h"
#include "test_framework.h"

using namespace shield;

static uint64_t hash_of(const std::string& s) { return fnv1a_64(s); }

TEST(bloom_sizing_math) {
  // m = ceil(-(n*ln p)/(ln2)^2), k = round((m/n)*ln2) clamped to [1,16].
  // n=50000, p=0.01 -> m=479253 bits, k=7 probes.
  BloomFilter bf(50000, 0.01);
  CHECK_EQ(bf.bit_size(), 479253u);
  CHECK_EQ(bf.hash_count(), 7u);
}

TEST(bloom_sizing_clamps) {
  BloomFilter tiny(1, 0.5);
  CHECK(tiny.bit_size() >= 1u);
  CHECK(tiny.hash_count() >= 1u);
  CHECK(tiny.hash_count() <= 16u);
  BloomFilter huge(1000000, 0.0001);
  CHECK(huge.hash_count() <= 16u);
  CHECK(huge.hash_count() >= 1u);
  BloomFilter zero_n(0, 0.01);  // degenerate input must not crash/div-by-zero
  CHECK(zero_n.bit_size() >= 1u);
}

TEST(bloom_no_false_negatives) {
  BloomFilter bf(2000, 0.01);
  for (int i = 0; i < 2000; ++i) {
    bf.add(hash_of("member-" + std::to_string(i) + ".example.com"));
  }
  int missing = 0;
  for (int i = 0; i < 2000; ++i) {
    if (!bf.possibly_contains(
            hash_of("member-" + std::to_string(i) + ".example.com"))) {
      ++missing;
    }
  }
  CHECK_EQ(missing, 0);  // a Bloom filter NEVER has false negatives
}

TEST(bloom_false_positive_rate_sanity) {
  BloomFilter bf(2000, 0.01);
  for (int i = 0; i < 2000; ++i) {
    bf.add(hash_of("member-" + std::to_string(i) + ".example.com"));
  }
  int fp = 0;
  for (int i = 0; i < 2000; ++i) {
    if (bf.possibly_contains(
            hash_of("nonmember-" + std::to_string(i) + ".other.net"))) {
      ++fp;
    }
  }
  const double rate = static_cast<double>(fp) / 2000.0;
  std::printf("    [info] measured FP rate: %.3f (%d/2000), bits set: %u\n",
              rate, fp, (unsigned)bf.bit_count());
  CHECK(rate < 0.05);  // sized for 1%; 5% is a generous sanity bound
}

TEST(bloom_clear_and_bit_count) {
  BloomFilter bf(100, 0.01);
  CHECK_EQ(bf.bit_count(), 0u);
  CHECK(!bf.possibly_contains(12345ULL));
  bf.add(12345ULL);
  CHECK(bf.possibly_contains(12345ULL));
  CHECK(bf.bit_count() > 0u);
  // Adding twice is idempotent for membership.
  const size_t bits_after_first = bf.bit_count();
  bf.add(12345ULL);
  CHECK(bf.possibly_contains(12345ULL));
  CHECK_EQ(bf.bit_count(), bits_after_first);
  bf.clear();
  CHECK_EQ(bf.bit_count(), 0u);
  CHECK(!bf.possibly_contains(12345ULL));
}

TEST(bloom_double_hash_spread) {
  // Distinct inputs should (almost always) set distinct bit patterns;
  // guards against a degenerate h2 (e.g. h2==0 collapsing all probes).
  BloomFilter bf(5000, 0.01);
  for (int i = 0; i < 5000; ++i) {
    bf.add(hash_of("spread-" + std::to_string(i) + ".test"));
  }
  // 5000 items * 7 probes worst case = 35000 bits; expect far fewer set
  // only if probes collide pathologically.
  CHECK(bf.bit_count() > 20000u);
  CHECK(bf.bit_count() <= 35000u);
}
