// Host tests for dns_codec (parse strictness, block responses).

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "core/dns_codec.h"
#include "test_framework.h"

using namespace shield;

// Build a minimal DNS query packet by hand: header + QNAME labels + qtype/qclass.
static std::vector<uint8_t> build_query(uint16_t id, const std::string& dotted,
                                        uint16_t qtype) {
  std::vector<uint8_t> p;
  p.push_back(static_cast<uint8_t>(id >> 8));
  p.push_back(static_cast<uint8_t>(id & 0xFF));
  p.push_back(0x01);
  p.push_back(0x00);  // flags: RD set
  p.push_back(0x00);
  p.push_back(0x01);  // QDCOUNT = 1
  p.push_back(0x00);
  p.push_back(0x00);  // ANCOUNT = 0
  p.push_back(0x00);
  p.push_back(0x00);  // NSCOUNT = 0
  p.push_back(0x00);
  p.push_back(0x00);  // ARCOUNT = 0
  size_t start = 0;
  for (size_t i = 0; i <= dotted.size(); ++i) {
    if (i == dotted.size() || dotted[i] == '.') {
      const size_t lab = i - start;
      p.push_back(static_cast<uint8_t>(lab));
      for (size_t j = start; j < i; ++j) p.push_back(static_cast<uint8_t>(dotted[j]));
      start = i + 1;
    }
  }
  p.push_back(0x00);  // root label
  p.push_back(static_cast<uint8_t>(qtype >> 8));
  p.push_back(static_cast<uint8_t>(qtype & 0xFF));
  p.push_back(0x00);
  p.push_back(0x01);  // QCLASS = IN
  return p;
}

TEST(dns_codec_parse_valid_a_query) {
  // www.example.com: 12 header + (3+1)+(7+1)+(3+1)+1 name + 4 = 33 bytes.
  const auto pkt = build_query(0x1234, "www.example.com", 1);
  CHECK_EQ(pkt.size(), 33u);
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(parse_dns_query(pkt.data(), pkt.size(), &id, &q));
  CHECK_EQ(id, 0x1234u);
  CHECK_STR_EQ(q.qname_raw, "www.example.com");
  CHECK_EQ(q.qtype, 1u);
  CHECK_EQ(q.qclass, 1u);
}

TEST(dns_codec_parse_valid_aaaa_query) {
  const auto pkt = build_query(0xABCD, "example.org", 28);
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(parse_dns_query(pkt.data(), pkt.size(), &id, &q));
  CHECK_EQ(id, 0xABCDu);
  CHECK_STR_EQ(q.qname_raw, "example.org");
  CHECK_EQ(q.qtype, 28u);
  CHECK_EQ(q.qclass, 1u);
}

TEST(dns_codec_rejects_truncation) {
  const auto pkt = build_query(0x1234, "www.example.com", 1);
  // Every strict prefix shorter than the full packet must fail.
  for (size_t len = 1; len < pkt.size(); ++len) {
    uint16_t id = 0;
    DnsQuestion q;
    if (parse_dns_query(pkt.data(), len, &id, &q)) {
      std::printf("    [info] truncation unexpectedly parsed at len=%u\n",
                  (unsigned)len);
    }
    CHECK(!parse_dns_query(pkt.data(), len, &id, &q));
  }
  // Full length parses; trailing garbage bytes are tolerated.
  {
    uint16_t id = 0;
    DnsQuestion q;
    CHECK(parse_dns_query(pkt.data(), pkt.size(), &id, &q));
  }
  {
    std::vector<uint8_t> longer = pkt;
    longer.insert(longer.end(), {0xDE, 0xAD, 0xBE, 0xEF});
    uint16_t id = 0;
    DnsQuestion q;
    CHECK(parse_dns_query(longer.data(), longer.size(), &id, &q));
  }
  // Empty / null input fails.
  {
    uint16_t id = 0;
    DnsQuestion q;
    CHECK(!parse_dns_query(pkt.data(), 0, &id, &q));
    CHECK(!parse_dns_query(nullptr, 33, &id, &q));
  }
}

TEST(dns_codec_rejects_bad_qdcount) {
  auto pkt = build_query(0x1234, "www.example.com", 1);
  uint16_t id = 0;
  DnsQuestion q;
  pkt[4] = 0x00;
  pkt[5] = 0x00;  // QDCOUNT = 0
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
  pkt[4] = 0x00;
  pkt[5] = 0x02;  // QDCOUNT = 2
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
}

TEST(dns_codec_rejects_non_in_class) {
  auto pkt = build_query(0x1234, "www.example.com", 1);
  pkt[pkt.size() - 1] = 0x03;  // QCLASS = CH
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
}

TEST(dns_codec_rejects_pointer_loop) {
  // Question name is a compression pointer to itself (offset 12).
  std::vector<uint8_t> pkt = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01};
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
}

TEST(dns_codec_rejects_pointer_out_of_bounds) {
  // Pointer target lies beyond the packet end.
  std::vector<uint8_t> pkt = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01};
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
}

TEST(dns_codec_rejects_reserved_label_type) {
  // 0x40 has top bits 01: a reserved label type, not a pointer.
  std::vector<uint8_t> pkt = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x40, 0x00, 0x01, 0x00, 0x01};
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(!parse_dns_query(pkt.data(), pkt.size(), &id, &q));
}

TEST(dns_codec_parse_compressed_name_ok) {
  // A question whose name uses a compression pointer must still parse;
  // loop protection only trips on actual cycles. Layout: header, then at
  // offset 12 the name "www" + forward pointer to offset 22, qtype/qclass
  // right after the pointer, and the target labels ("example.com") at 22.
  std::vector<uint8_t> pkt = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  pkt.push_back(3);  // offset 12: label "www"
  pkt.push_back('w');
  pkt.push_back('w');
  pkt.push_back('w');
  pkt.push_back(0xC0);
  pkt.push_back(0x16);  // -> offset 22
  pkt.push_back(0x00);
  pkt.push_back(0x01);  // qtype A (offsets 18-19)
  pkt.push_back(0x00);
  pkt.push_back(0x01);  // qclass IN (offsets 20-21)
  pkt.push_back(7);     // offset 22: "example.com" labels
  for (char c : std::string("example")) pkt.push_back(static_cast<uint8_t>(c));
  pkt.push_back(3);
  for (char c : std::string("com")) pkt.push_back(static_cast<uint8_t>(c));
  pkt.push_back(0x00);
  CHECK_EQ(pkt.size(), 35u);
  uint16_t id = 0;
  DnsQuestion q;
  CHECK(parse_dns_query(pkt.data(), pkt.size(), &id, &q));
  CHECK_STR_EQ(q.qname_raw, "www.example.com");
  CHECK_EQ(q.qtype, 1u);
  CHECK_EQ(q.qclass, 1u);
}

// --- build_block_response ---

static void check_header_common(const uint8_t* out, uint16_t want_id,
                                uint16_t want_ancount, uint8_t want_rcode) {
  CHECK_EQ((int)out[0], (int)(want_id >> 8));
  CHECK_EQ((int)out[1], (int)(want_id & 0xFF));
  const uint16_t flags = (static_cast<uint16_t>(out[2]) << 8) | out[3];
  CHECK(flags & 0x8000);              // QR set
  CHECK_EQ((int)(flags & 0x000F), (int)want_rcode);
  CHECK_EQ((int)out[4], 0);
  CHECK_EQ((int)out[5], 1);           // QDCOUNT = 1
  CHECK_EQ((int)out[6], (int)(want_ancount >> 8));
  CHECK_EQ((int)out[7], (int)(want_ancount & 0xFF));
  CHECK_EQ((int)out[8], 0);
  CHECK_EQ((int)out[9], 0);           // NSCOUNT = 0
  CHECK_EQ((int)out[10], 0);
  CHECK_EQ((int)out[11], 0);          // ARCOUNT = 0
}

TEST(dns_codec_block_null_ip_a) {
  const auto req = build_query(0x1234, "www.example.com", 1);
  uint8_t out[512];
  const size_t n =
      build_block_response(req.data(), req.size(), BlockMode::NULL_IP, 1, out, sizeof(out));
  // 12 header + 21 question + (2+2+2+4+2+4) answer = 49
  CHECK_EQ(n, 49u);
  CHECK(n <= 512u);
  check_header_common(out, 0x1234, 1, 0);
  // Question section copied verbatim.
  CHECK(memcmp(out + 12, req.data() + 12, 21) == 0);
  // Answer: pointer to qname, A/IN, TTL, rdlen=4, 0.0.0.0
  size_t p = 12 + 21;
  CHECK_EQ((int)out[p++], 0xC0);
  CHECK_EQ((int)out[p++], 0x0C);
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x01);  // type A
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x01);  // class IN
  p += 4;                         // TTL
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x04);  // rdlength = 4
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x00);  // 0.0.0.0
  CHECK_EQ(p, n);
}

TEST(dns_codec_block_null_ip_aaaa) {
  const auto req = build_query(0xBEEF, "ads.example.net", 28);
  uint8_t out[512];
  const size_t qlen = req.size() - 12;
  const size_t n = build_block_response(req.data(), req.size(), BlockMode::NULL_IP,
                                        28, out, sizeof(out));
  CHECK_EQ(n, 12u + qlen + 12u + 16u);
  check_header_common(out, 0xBEEF, 1, 0);
  CHECK(memcmp(out + 12, req.data() + 12, qlen) == 0);
  size_t p = 12 + qlen;
  CHECK_EQ((int)out[p++], 0xC0);
  CHECK_EQ((int)out[p++], 0x0C);
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 28);  // type AAAA
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 0x01);  // class IN
  p += 4;                        // TTL
  CHECK_EQ((int)out[p++], 0x00);
  CHECK_EQ((int)out[p++], 16);  // rdlength = 16
  for (int i = 0; i < 16; ++i) CHECK_EQ((int)out[p++], 0x00);  // ::
  CHECK_EQ(p, n);
}

TEST(dns_codec_block_nxdomain) {
  for (uint16_t qtype : {1u, 28u}) {
    const auto req = build_query(0x1234, "www.example.com", qtype);
    uint8_t out[512];
    const size_t n = build_block_response(req.data(), req.size(),
                                          BlockMode::NXDOMAIN, qtype, out, sizeof(out));
    CHECK_EQ(n, 12u + 21u);  // header + question only
    check_header_common(out, 0x1234, 0, 3);  // RCODE 3, no answers
    CHECK(memcmp(out + 12, req.data() + 12, 21) == 0);
  }
}

TEST(dns_codec_block_nodata) {
  for (uint16_t qtype : {1u, 28u}) {
    const auto req = build_query(0x1234, "www.example.com", qtype);
    uint8_t out[512];
    const size_t n = build_block_response(req.data(), req.size(), BlockMode::NODATA,
                                          qtype, out, sizeof(out));
    CHECK_EQ(n, 12u + 21u);  // header + question only
    check_header_common(out, 0x1234, 0, 0);  // NOERROR, ANCOUNT 0
    CHECK(memcmp(out + 12, req.data() + 12, 21) == 0);
  }
}

TEST(dns_codec_block_id_echo) {
  const auto req = build_query(0xABCD, "www.example.com", 1);
  uint8_t out[512];
  const size_t n = build_block_response(req.data(), req.size(), BlockMode::NULL_IP,
                                        1, out, sizeof(out));
  CHECK(n > 0u);
  CHECK_EQ((int)out[0], 0xAB);
  CHECK_EQ((int)out[1], 0xCD);
}

TEST(dns_codec_block_buffer_too_small) {
  const auto req = build_query(0x1234, "www.example.com", 1);
  uint8_t out[512];
  CHECK_EQ(build_block_response(req.data(), req.size(), BlockMode::NULL_IP, 1, out, 44), 0u);
  CHECK_EQ(build_block_response(req.data(), req.size(), BlockMode::NULL_IP, 1, out, 0), 0u);
  CHECK_EQ(build_block_response(req.data(), req.size(), BlockMode::NXDOMAIN, 1, out, 32), 0u);
  // Exact fit works (12 header + 21 question = 33).
  CHECK_EQ(build_block_response(req.data(), req.size(), BlockMode::NXDOMAIN, 1, out, 33), 33u);
}

TEST(dns_codec_block_rejects_garbage_request) {
  uint8_t out[512];
  const uint8_t tiny[5] = {1, 2, 3, 4, 5};
  CHECK_EQ(build_block_response(tiny, sizeof(tiny), BlockMode::NULL_IP, 1, out, sizeof(out)), 0u);
  CHECK_EQ(build_block_response(nullptr, 33, BlockMode::NULL_IP, 1, out, sizeof(out)), 0u);
}
