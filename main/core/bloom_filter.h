#pragma once
// Bloom filter for the blocklist (CONTRACTS.md section 4). Pure C++17.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace shield {

class BloomFilter {
 public:
  // Sizes bit array for expected_items at false-positive rate fp_rate.
  // m = ceil(-(n*ln p)/(ln2)^2), k = round((m/n)*ln2), k clamped [1,16].
  BloomFilter(size_t expected_items = 50000, double fp_rate = 0.01);
  void add(uint64_t hash);
  bool possibly_contains(uint64_t hash) const;  // false => DEFINITELY absent
  void clear();
  size_t bit_count() const;
  size_t bit_size() const { return m_bits_; }  // sized m (introspection/tests)
  size_t hash_count() const { return k_; }     // probe count k

 private:
  static uint64_t splitmix64_avalanche(uint64_t x);
  static uint64_t fnv1a_64_bytes(const uint8_t* data, size_t len);

  size_t m_bits_ = 0;
  size_t k_ = 1;
  std::vector<uint64_t> words_;
};

}  // namespace shield
