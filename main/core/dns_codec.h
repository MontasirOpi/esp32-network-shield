#pragma once
// Minimal DNS message codec (CONTRACTS.md section 4). Pure C++17.
// Max DNS/UDP message: 512 bytes classic; we accept up to 4096 for EDNS0
// but never generate more than 512 bytes ourselves.

#include <cstddef>
#include <cstdint>
#include <string>

#include "core/types.h"

namespace shield {

struct DnsQuestion {
  std::string qname_raw;  // decoded dotted name, e.g. "www.example.com"
  uint16_t qtype = 0;     // e.g. 1=A, 28=AAAA
  uint16_t qclass = 0;    // 1=IN
};

// Strict, bounds-checked parse. Requires QDCOUNT==1 and QCLASS==IN.
// Handles label compression pointers with loop protection (max 128 jumps).
// Returns false on any truncation, compression loop, or QDCOUNT!=1.
bool parse_dns_query(const uint8_t* buf, size_t len, uint16_t* id_out,
                     DnsQuestion* q_out);

// Build a response that copies the transaction ID and the question section
// verbatim from the request. qtype decides the answer shape for NULL_IP
// (A -> 0.0.0.0, AAAA -> ::); NXDOMAIN sets RCODE=3 with no answers;
// NODATA returns NOERROR with ANCOUNT=0.
// Returns bytes written, or 0 if the output buffer is too small (or the
// request is malformed / the response would exceed 512 bytes).
size_t build_block_response(const uint8_t* req, size_t req_len, BlockMode mode,
                            uint16_t qtype, uint8_t* out, size_t out_cap);

}  // namespace shield
