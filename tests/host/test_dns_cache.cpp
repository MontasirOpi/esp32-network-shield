// Host tests for DnsCache (TTL, ID patching, LRU, clamping).

#include <cstdint>
#include <vector>

#include "core/dns_cache.h"
#include "test_framework.h"

using namespace shield;

static uint32_t fake_now_ms = 0;  // controllable clock for tests

static std::vector<uint8_t> make_resp(uint16_t id, size_t len = 32) {
  std::vector<uint8_t> r(len, 0xAB);
  r[0] = static_cast<uint8_t>(id >> 8);
  r[1] = static_cast<uint8_t>(id & 0xFF);
  return r;
}

TEST(dns_cache_store_lookup_and_id_patch) {
  fake_now_ms = 1000000;
  DnsCache c(16, [] { return fake_now_ms; });
  const auto resp = make_resp(0xAAAA);
  c.store("www.example.com", 1, resp.data(), resp.size(), 300);
  CHECK_EQ(c.size(), 1u);

  std::vector<uint8_t> out;
  CHECK(c.lookup("www.example.com", 1, 0x1234, out));
  CHECK_EQ(out.size(), resp.size());
  // Transaction ID patched to the querying client's ID...
  CHECK_EQ((int)out[0], 0x12);
  CHECK_EQ((int)out[1], 0x34);
  // ...everything else byte-identical to what was stored.
  for (size_t i = 2; i < out.size(); ++i) {
    CHECK_EQ((int)out[i], (int)resp[i]);
  }
  // Stored copy keeps zeroed ID bytes: a second lookup patches again.
  std::vector<uint8_t> out2;
  CHECK(c.lookup("www.example.com", 1, 0x5678, out2));
  CHECK_EQ((int)out2[0], 0x56);
  CHECK_EQ((int)out2[1], 0x78);
}

TEST(dns_cache_miss_wrong_name_or_qtype) {
  fake_now_ms = 0;
  DnsCache c(16, [] { return fake_now_ms; });
  const auto resp = make_resp(1);
  c.store("www.example.com", 1, resp.data(), resp.size(), 300);
  std::vector<uint8_t> out;
  CHECK(!c.lookup("other.example.com", 1, 9, out));  // wrong name
  CHECK(!c.lookup("www.example.com", 28, 9, out));  // wrong qtype (key has qtype)
  CHECK(!c.lookup("WWW.EXAMPLE.COM", 1, 9, out));   // keys are exact (normalized by caller)
}

TEST(dns_cache_ttl_expiry) {
  fake_now_ms = 0;
  DnsCache c(16, [] { return fake_now_ms; });
  const auto resp = make_resp(1);
  c.store("www.example.com", 1, resp.data(), resp.size(), 100);  // 100 s TTL
  std::vector<uint8_t> out;
  fake_now_ms = 99u * 1000u;
  CHECK(c.lookup("www.example.com", 1, 1, out));  // still fresh
  fake_now_ms = 100u * 1000u;
  CHECK(!c.lookup("www.example.com", 1, 1, out));  // expired -> miss
  CHECK_EQ(c.size(), 0u);                          // expired entry purged
}

TEST(dns_cache_ttl_clamped_to_minimum) {
  fake_now_ms = 0;
  DnsCache c(16, [] { return fake_now_ms; });
  const auto resp = make_resp(1);
  c.store("www.example.com", 1, resp.data(), resp.size(), 5);  // -> 60 s
  std::vector<uint8_t> out;
  fake_now_ms = 59u * 1000u;
  CHECK(c.lookup("www.example.com", 1, 1, out));
  fake_now_ms = 61u * 1000u;
  CHECK(!c.lookup("www.example.com", 1, 1, out));
}

TEST(dns_cache_ttl_clamped_to_maximum) {
  fake_now_ms = 0;
  DnsCache c(16, [] { return fake_now_ms; });
  const auto resp = make_resp(1);
  c.store("www.example.com", 1, resp.data(), resp.size(), 999999);  // -> 86400 s
  std::vector<uint8_t> out;
  fake_now_ms = 86399u * 1000u;
  CHECK(c.lookup("www.example.com", 1, 1, out));
  fake_now_ms = 86401u * 1000u;
  CHECK(!c.lookup("www.example.com", 1, 1, out));
}

TEST(dns_cache_lru_eviction) {
  fake_now_ms = 0;
  DnsCache c(3, [] { return fake_now_ms; });
  const auto r = make_resp(1);
  c.store("a.com", 1, r.data(), r.size(), 300);
  c.store("b.com", 1, r.data(), r.size(), 300);
  c.store("c.com", 1, r.data(), r.size(), 300);
  CHECK_EQ(c.size(), 3u);
  std::vector<uint8_t> out;
  CHECK(c.lookup("a.com", 1, 1, out));  // touch a.com -> most recently used
  c.store("d.com", 1, r.data(), r.size(), 300);  // full: evict LRU (b.com)
  CHECK_EQ(c.size(), 3u);
  CHECK(c.lookup("a.com", 1, 1, out));
  CHECK(!c.lookup("b.com", 1, 1, out));  // evicted
  CHECK(c.lookup("c.com", 1, 1, out));
  CHECK(c.lookup("d.com", 1, 1, out));
}

TEST(dns_cache_store_refreshes_existing) {
  fake_now_ms = 0;
  DnsCache c(4, [] { return fake_now_ms; });
  const auto r1 = make_resp(1);
  c.store("a.com", 1, r1.data(), r1.size(), 300);
  const auto r2 = make_resp(2, 40);
  c.store("a.com", 1, r2.data(), r2.size(), 300);  // same key: refresh
  CHECK_EQ(c.size(), 1u);
  std::vector<uint8_t> out;
  CHECK(c.lookup("a.com", 1, 9, out));
  CHECK_EQ(out.size(), 40u);  // refreshed payload won
  CHECK_EQ((int)out[2], 0xAB);
}

TEST(dns_cache_clear) {
  fake_now_ms = 0;
  DnsCache c(4, [] { return fake_now_ms; });
  const auto r = make_resp(1);
  c.store("a.com", 1, r.data(), r.size(), 300);
  c.store("b.com", 28, r.data(), r.size(), 300);
  CHECK_EQ(c.size(), 2u);
  c.clear();
  CHECK_EQ(c.size(), 0u);
  std::vector<uint8_t> out;
  CHECK(!c.lookup("a.com", 1, 1, out));
}

TEST(dns_cache_default_clock_works) {
  // nullptr NowMs -> steady_clock default; must not crash and must hit.
  DnsCache c(4);
  const auto r = make_resp(1);
  c.store("a.com", 1, r.data(), r.size(), 300);
  std::vector<uint8_t> out;
  CHECK(c.lookup("a.com", 1, 7, out));
  CHECK_EQ((int)out[0], 0x00);
  CHECK_EQ((int)out[1], 0x07);
}

TEST(dns_cache_ignores_degenerate_store) {
  fake_now_ms = 0;
  DnsCache c(4, [] { return fake_now_ms; });
  const uint8_t one[1] = {0xFF};
  c.store("a.com", 1, one, 1, 300);       // too short for ID bytes
  c.store("b.com", 1, nullptr, 32, 300);  // null buffer
  CHECK_EQ(c.size(), 0u);
}
