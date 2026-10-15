// Bloom filter (CONTRACTS.md section 4). Pure C++17.

#include "core/bloom_filter.h"

#include <cmath>

namespace shield {

BloomFilter::BloomFilter(size_t expected_items, double fp_rate) {
  // --- Sizing math ------------------------------------------------------
  // For n expected items at target false-positive rate p, the optimal
  // bit-array size is
  //     m = ceil( -(n * ln p) / (ln 2)^2 )
  // (minimizes p for given n and m), and the optimal number of hash
  // probes is
  //     k = round( (m / n) * ln 2 ),
  // clamped to [1, 16] so a lookup stays cheap on the ESP32.
  // Example: n=50000, p=0.01 -> m=479253 bits (~59 KiB), k=7.
  // ----------------------------------------------------------------------
  if (expected_items == 0) expected_items = 1;
  if (!(fp_rate > 0.0) || fp_rate >= 1.0) fp_rate = 0.01;  // also catches NaN
  const double kLn2 = 0.6931471805599453;
  const double m =
      -(static_cast<double>(expected_items) * std::log(fp_rate)) / (kLn2 * kLn2);
  m_bits_ = static_cast<size_t>(std::ceil(m));
  if (m_bits_ == 0) m_bits_ = 1;
  long k_probes = std::lround((static_cast<double>(m_bits_) /
                               static_cast<double>(expected_items)) *
                              kLn2);
  if (k_probes < 1) k_probes = 1;
  if (k_probes > 16) k_probes = 16;
  k_ = static_cast<size_t>(k_probes);
  words_.assign((m_bits_ + 63) / 64, 0);
}

uint64_t BloomFilter::splitmix64_avalanche(uint64_t x) {
  // splitmix64 finalizer: a fast 64-bit avalanche mixer. Used to derive
  // the second hash from the input hash for double hashing.
  uint64_t z = x + 0x9e3779b97f4a7c15ULL;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

uint64_t BloomFilter::fnv1a_64_bytes(const uint8_t* data, size_t len) {
  uint64_t h = 14695981039346656037ULL;  // FNV offset basis
  for (size_t i = 0; i < len; ++i) {
    h ^= data[i];
    h *= 1099511628211ULL;  // FNV prime
  }
  return h;
}

void BloomFilter::add(uint64_t hash) {
  // Double hashing (Kirsch-Mitzenmacher): the i-th probe is
  //     (h1 + i * h2) mod m,
  // which behaves like k independent hash functions.
  //   h1 = FNV-1a 64 of the 8 input-hash bytes (little-endian),
  //   h2 = splitmix64 avalanche of the input hash.
  // h2 is forced odd so the probe sequence can never collapse to a
  // single bit when h2 would otherwise be 0.
  uint8_t bytes[8];
  for (int i = 0; i < 8; ++i) {
    bytes[i] = static_cast<uint8_t>(hash >> (8 * i));
  }
  const uint64_t h1 = fnv1a_64_bytes(bytes, 8);
  const uint64_t h2 = splitmix64_avalanche(hash) | 1ULL;
  for (size_t i = 0; i < k_; ++i) {
    const size_t bit = (h1 + i * h2) % m_bits_;
    words_[bit / 64] |= (1ULL << (bit % 64));
  }
}

bool BloomFilter::possibly_contains(uint64_t hash) const {
  uint8_t bytes[8];
  for (int i = 0; i < 8; ++i) {
    bytes[i] = static_cast<uint8_t>(hash >> (8 * i));
  }
  const uint64_t h1 = fnv1a_64_bytes(bytes, 8);
  const uint64_t h2 = splitmix64_avalanche(hash) | 1ULL;
  for (size_t i = 0; i < k_; ++i) {
    const size_t bit = (h1 + i * h2) % m_bits_;
    if ((words_[bit / 64] & (1ULL << (bit % 64))) == 0) return false;
  }
  return true;
}

void BloomFilter::clear() {
  for (auto& w : words_) w = 0;
}

size_t BloomFilter::bit_count() const {
  size_t n = 0;
  for (uint64_t w : words_) n += static_cast<size_t>(__builtin_popcountll(w));
  return n;
}

}  // namespace shield
