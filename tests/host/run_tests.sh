#!/bin/bash
# Host tests for the ESP32 Network Shield portable core (CONTRACTS.md §10).
# Builds with g++ -std=c++17 -I<project>/main (paths relative to this script's
# directory) into /tmp, then runs the single test binary.
# Exits nonzero if the build fails or any test fails.
set -u

cd "$(dirname "$0")"

# NOTE: the project tree is <root>/main + <root>/tests/host, so from this
# script's directory the main tree is ../../main.
MAIN_DIR="../../main"
OUT_BIN="/tmp/esp32_shield_host_tests"
MAIN_CPP="/tmp/esp32_shield_test_main.cpp"

# The framework (test_framework.h) provides testfw::run_all(); the tiny
# main() below lives in /tmp so no extra repo file is needed.
cat > "$MAIN_CPP" <<'EOF'
#include "test_framework.h"
int main() { return testfw::run_all(); }
EOF

echo "== building host tests =="
g++ -std=c++17 -Wall -Wextra -I"$MAIN_DIR" -I. \
  "$MAIN_CPP" \
  test_domain_matcher.cpp \
  test_bloom_filter.cpp \
  test_dns_codec.cpp \
  test_rule_engine.cpp \
  test_dns_cache.cpp \
  "$MAIN_DIR"/core/domain_matcher.cpp \
  "$MAIN_DIR"/core/bloom_filter.cpp \
  "$MAIN_DIR"/core/dns_codec.cpp \
  "$MAIN_DIR"/core/rule_engine.cpp \
  "$MAIN_DIR"/core/dns_cache.cpp \
  -o "$OUT_BIN" || { echo "BUILD FAILED"; exit 1; }

echo "== running host tests =="
"$OUT_BIN"
rc=$?
echo "== exit code: $rc =="
exit $rc
