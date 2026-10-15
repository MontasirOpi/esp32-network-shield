// Minimal DNS message codec (CONTRACTS.md section 4). Pure C++17.

#include "core/dns_codec.h"

#include <cstring>

namespace shield {
namespace {

// A compression pointer may legally point anywhere earlier in the packet,
// so a malicious packet can make a name point at itself. Cap total pointer
// jumps so decoding always terminates instead of looping forever.
constexpr size_t kMaxPointerJumps = 128;
// Max wire length of a domain name (RFC 1035 section 3.1).
constexpr size_t kMaxNameLen = 255;

// Decode a possibly-compressed domain name starting at `off`.
// Appends dotted labels to `out` (no trailing dot). On success, `after` is
// set to the offset just past the name's bytes in the ORIGINAL stream, i.e.
// past the terminating zero byte, or past the first compression pointer if
// one was used (fields after the name follow the pointer, not its target).
// Returns false on any bound violation, reserved label type, overlong name,
// pointer outside the packet, or pointer loop.
bool decode_name(const uint8_t* buf, size_t len, size_t off, std::string* out,
                 size_t* after) {
  size_t jumps = 0;
  size_t pos = off;          // decode cursor (follows pointers)
  size_t after_ptr = 0;      // stream offset just past the first pointer seen
  bool first_label = true;
  for (;;) {
    if (pos >= len) return false;  // truncated
    const uint8_t b = buf[pos];
    if ((b & 0xC0) == 0xC0) {
      // Compression pointer: this byte + next, 14-bit offset.
      if (pos + 1 >= len) return false;
      if (++jumps > kMaxPointerJumps) return false;  // pointer loop
      const size_t target =
          (static_cast<size_t>(b & 0x3F) << 8) | buf[pos + 1];
      if (target >= len) return false;  // points outside the packet
      if (after_ptr == 0) after_ptr = pos + 2;  // pos+2 >= 2, never 0
      pos = target;
      continue;
    }
    if (b & 0xC0) return false;  // reserved label types 01/10: reject
    if (b == 0) {
      *after = (after_ptr != 0) ? after_ptr : pos + 1;
      return true;
    }
    const size_t lab_len = b;
    if (pos + 1 + lab_len > len) return false;  // label overruns packet
    if (out->size() + (first_label ? 0 : 1) + lab_len > kMaxNameLen) {
      return false;
    }
    if (!first_label) out->push_back('.');
    first_label = false;
    out->append(reinterpret_cast<const char*>(buf + pos + 1), lab_len);
    pos += 1 + lab_len;
  }
}

}  // namespace

bool parse_dns_query(const uint8_t* buf, size_t len, uint16_t* id_out,
                     DnsQuestion* q_out) {
  if (!buf || !id_out || !q_out) return false;
  if (len < 12) return false;  // not even a full header
  const uint16_t qdcount = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
  if (qdcount != 1) return false;
  DnsQuestion q;
  size_t after = 0;
  if (!decode_name(buf, len, 12, &q.qname_raw, &after)) return false;
  if (after + 4 > len) return false;  // truncated qtype/qclass
  q.qtype = (static_cast<uint16_t>(buf[after]) << 8) | buf[after + 1];
  q.qclass = (static_cast<uint16_t>(buf[after + 2]) << 8) | buf[after + 3];
  if (q.qclass != 1) return false;  // IN class only
  *id_out = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
  *q_out = q;
  return true;
}

size_t build_block_response(const uint8_t* req, size_t req_len, BlockMode mode,
                            uint16_t qtype, uint8_t* out, size_t out_cap) {
  if (!req || !out) return 0;
  if (req_len < 12 || out_cap < 12) return 0;
  // Measure the question section so it can be copied verbatim.
  std::string dummy;
  size_t name_end = 0;
  if (!decode_name(req, req_len, 12, &dummy, &name_end)) return 0;
  if (name_end + 4 > req_len) return 0;  // truncated qtype/qclass
  const size_t qlen = (name_end + 4) - 12;

  // Answer section: name ptr(2) + type(2) + class(2) + ttl(4) + rdlen(2).
  // AAAA gets 16 zero bytes (::); anything else gets 4 zero bytes (0.0.0.0),
  // which is a harmless null payload for exotic qtypes under NULL_IP.
  size_t rdlen = 0;
  if (mode == BlockMode::NULL_IP) rdlen = (qtype == 28) ? 16 : 4;
  const size_t total = 12 + qlen + (rdlen != 0 ? 12 + rdlen : 0);
  if (total > 512) return 0;  // never generate more than 512 bytes
  if (total > out_cap) return 0;

  // Header: echo the transaction ID, set QR/AA/RA, copy RD, set RCODE.
  out[0] = req[0];
  out[1] = req[1];
  const uint16_t req_flags = (static_cast<uint16_t>(req[2]) << 8) | req[3];
  uint16_t flags = 0x8000;  // QR: this is a response
  flags |= 0x0400;          // AA: authoritative for this block answer
  flags |= 0x0080;          // RA: recursion available (we forward upstream)
  if (req_flags & 0x0100) flags |= 0x0100;  // copy RD from the query
  if (mode == BlockMode::NXDOMAIN) flags |= 3;  // RCODE 3
  out[2] = static_cast<uint8_t>(flags >> 8);
  out[3] = static_cast<uint8_t>(flags & 0xFF);
  out[4] = 0;
  out[5] = 1;  // QDCOUNT = 1
  const uint16_t ancount = (mode == BlockMode::NULL_IP) ? 1 : 0;
  out[6] = static_cast<uint8_t>(ancount >> 8);
  out[7] = static_cast<uint8_t>(ancount & 0xFF);
  out[8] = 0;
  out[9] = 0;  // NSCOUNT = 0
  out[10] = 0;
  out[11] = 0;  // ARCOUNT = 0

  memcpy(out + 12, req + 12, qlen);  // question section, verbatim

  if (mode == BlockMode::NULL_IP) {
    size_t p = 12 + qlen;
    out[p++] = 0xC0;
    out[p++] = 0x0C;  // NAME: compression pointer to the question name
    out[p++] = static_cast<uint8_t>(qtype >> 8);
    out[p++] = static_cast<uint8_t>(qtype & 0xFF);
    out[p++] = 0;
    out[p++] = 1;  // CLASS IN
    const uint32_t ttl = 60;  // short TTL so unblocking propagates quickly
    out[p++] = static_cast<uint8_t>(ttl >> 24);
    out[p++] = static_cast<uint8_t>((ttl >> 16) & 0xFF);
    out[p++] = static_cast<uint8_t>((ttl >> 8) & 0xFF);
    out[p++] = static_cast<uint8_t>(ttl & 0xFF);
    out[p++] = static_cast<uint8_t>(rdlen >> 8);
    out[p++] = static_cast<uint8_t>(rdlen & 0xFF);
    memset(out + p, 0, rdlen);  // 0.0.0.0 or ::
  }
  return total;
}

}  // namespace shield
