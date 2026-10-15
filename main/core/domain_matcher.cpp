// Domain normalization + FNV-1a (CONTRACTS.md section 4). Pure C++17.

#include "core/domain_matcher.h"

#include <cctype>

namespace shield {

std::string normalize_domain(const std::string& raw) {
  // Trim ASCII whitespace from both ends.
  size_t start = 0;
  size_t end = raw.size();
  while (start < end && std::isspace(static_cast<unsigned char>(raw[start]))) {
    ++start;
  }
  while (end > start && std::isspace(static_cast<unsigned char>(raw[end - 1]))) {
    --end;
  }
  if (start >= end) return "";
  // Lowercase (ASCII only; IDN/punycode not handled in V1).
  std::string out;
  out.reserve(end - start);
  for (size_t i = start; i < end; ++i) {
    out.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(raw[i]))));
  }
  // Strip ONE trailing dot ("example.com." -> "example.com").
  if (!out.empty() && out.back() == '.') out.pop_back();
  return out;  // "" if the input was e.g. "." or whitespace-only
}

uint64_t fnv1a_64(const std::string& s) {
  // Standard 64-bit FNV-1a.
  uint64_t hash = 14695981039346656037ULL;  // offset basis
  for (char c : s) {
    hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
    hash *= 1099511628211ULL;  // FNV prime
  }
  return hash;
}

}  // namespace shield
