#pragma once
// Domain normalization + suffix walking + FNV-1a (CONTRACTS.md section 4).
// Pure C++17.

#include <cstdint>
#include <string>

namespace shield {

// Lowercase, trim surrounding whitespace, strip ONE trailing dot.
// Returns "" for empty/whitespace-only input (and for ".").
// IDN/punycode: NOT handled in V1 (documented limitation).
std::string normalize_domain(const std::string& raw);

// Calls fn(suffix) for "cdn.ads.example.com" -> "cdn.ads.example.com",
// "ads.example.com", "example.com" (most specific first, stops before the
// bare TLD). Stops early if fn returns false.
template <typename Fn>
void for_each_parent_domain(const std::string& normalized, Fn&& fn) {
  std::string current = normalized;
  for (;;) {
    if (!fn(current)) return;
    std::string::size_type dot = current.find('.');
    if (dot == std::string::npos) return;
    // Only strip the leftmost label if what remains still contains a dot;
    // this stops the walk at "example.com" instead of descending to "com".
    if (current.find('.', dot + 1) == std::string::npos) return;
    current = current.substr(dot + 1);
  }
}

// 64-bit FNV-1a hash of a (normalized) domain string.
// fnv1a_64("") == 14695981039346656037 (the offset basis).
uint64_t fnv1a_64(const std::string& s);

}  // namespace shield
