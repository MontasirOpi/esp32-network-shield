#include "system/stats_engine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "cJSON.h"
#include "core/domain_matcher.h"  // fnv1a_64 (pure C++; safe to include from IDF code)
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace shield {

namespace {
constexpr const char* TAG = "stats";
constexpr const char* kStatsPath = "/littlefs/stats.json";
constexpr const char* kStatsTmpPath = "/littlefs/stats.json.tmp";

uint32_t now_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

// Uptime in seconds. xTaskGetTickCount() ticks * ms-per-tick = ms, /1000 = s.
// (CONTRACTS.md phrases it as xTaskGetTickCount()/portTICK_PERIOD_MS/1000;
// the correct dimensional conversion is ticks * portTICK_PERIOD_MS / 1000.)
uint32_t uptime_s() {
  return static_cast<uint32_t>((xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000);
}
}  // namespace

StatsEngine& StatsEngine::instance() {
  static StatsEngine inst;
  return inst;
}

void StatsEngine::init(uint8_t flush_interval_min) {
  std::lock_guard<std::mutex> lock(mutex_);
  flush_min_ = flush_interval_min;
  last_flush_ms_ = now_ms();
  initialized_ = true;
  load();  // totals only; top-blocked starts empty each boot
}

void StatsEngine::record_query(const std::string& domain, DnsDecision d, bool cache_hit) {
  std::lock_guard<std::mutex> lock(mutex_);
  ++total_;
  if (cache_hit) ++cache_hits_;
  if (d != DnsDecision::BLOCK) return;
  ++blocked_;

  // Top-N: linear search over fixed slots; no allocation on the hot path.
  const uint64_t h = fnv1a_64(domain);
  TopSlot* free_slot = nullptr;
  for (auto& s : top_) {
    if (s.count != 0 && s.hash == h) {
      ++s.count;
      return;
    }
    if (s.count == 0 && free_slot == nullptr) free_slot = &s;
  }
  if (free_slot != nullptr) {
    free_slot->hash = h;
    strncpy(free_slot->domain, domain.c_str(), sizeof(free_slot->domain) - 1);
    free_slot->domain[sizeof(free_slot->domain) - 1] = '\0';
    free_slot->count = 1;
  }
  // Slots full: drop the new domain (documented; 32 slots cover the heavy tail).
}

void StatsEngine::snapshot(StatsSnapshot* out) {
  if (out == nullptr) return;
  std::lock_guard<std::mutex> lock(mutex_);
  out->total_queries = total_;
  out->blocked_queries = blocked_;
  out->cache_hits = cache_hits_;
  // Only non-blocked, non-cached queries reach an upstream, so derive it with
  // saturating arithmetic rather than a fourth counter.
  const uint32_t non_upstream = blocked_ + cache_hits_;
  out->upstream_queries = (total_ >= non_upstream) ? (total_ - non_upstream) : 0;
  out->uptime_s = uptime_s();

  // Copy used slots, selection-sort desc by count (tiny N), take top 10.
  TopSlot sorted[kTopSlots];
  int n = 0;
  for (const auto& s : top_) {
    if (s.count != 0) sorted[n++] = s;
  }
  for (int i = 0; i < n; ++i) {
    int best = i;
    for (int j = i + 1; j < n; ++j) {
      if (sorted[j].count > sorted[best].count) best = j;
    }
    if (best != i) std::swap(sorted[i], sorted[best]);
  }
  out->top_blocked_count = std::min(n, StatsSnapshot::kMaxTop);
  for (int i = 0; i < out->top_blocked_count; ++i) {
    strncpy(out->top_blocked[i].domain, sorted[i].domain,
            sizeof(out->top_blocked[i].domain) - 1);
    out->top_blocked[i].domain[sizeof(out->top_blocked[i].domain) - 1] = '\0';
    out->top_blocked[i].count = sorted[i].count;
  }
}

void StatsEngine::loop() {
  if (!initialized_ || flush_min_ == 0) return;
  const uint32_t now = now_ms();
  bool due = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (now - last_flush_ms_ >= static_cast<uint32_t>(flush_min_) * 60000u) {
      last_flush_ms_ = now;
      due = true;
    }
  }
  if (due) flush();
}

void StatsEngine::load() {
  FILE* f = fopen(kStatsPath, "r");
  if (f == nullptr) {
    ESP_LOGI(TAG, "no %s yet; starting counters at zero", kStatsPath);
    return;
  }
  fseek(f, 0, SEEK_END);
  const long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (len <= 0 || len > 4096) {
    fclose(f);
    return;
  }
  std::string buf(static_cast<size_t>(len), '\0');
  if (fread(buf.data(), 1, buf.size(), f) != buf.size()) {
    fclose(f);
    return;
  }
  fclose(f);

  cJSON* root = cJSON_Parse(buf.c_str());
  if (root == nullptr) {
    ESP_LOGW(TAG, "corrupt %s; ignoring", kStatsPath);
    return;
  }
  cJSON* t = cJSON_GetObjectItemCaseSensitive(root, "total");
  cJSON* b = cJSON_GetObjectItemCaseSensitive(root, "blocked");
  cJSON* c = cJSON_GetObjectItemCaseSensitive(root, "cache_hits");
  if (cJSON_IsNumber(t)) total_ = static_cast<uint32_t>(t->valuedouble);
  if (cJSON_IsNumber(b)) blocked_ = static_cast<uint32_t>(b->valuedouble);
  if (cJSON_IsNumber(c)) cache_hits_ = static_cast<uint32_t>(c->valuedouble);
  cJSON_Delete(root);
  ESP_LOGI(TAG, "loaded totals: total=%lu blocked=%lu cache_hits=%lu",
           static_cast<unsigned long>(total_), static_cast<unsigned long>(blocked_),
           static_cast<unsigned long>(cache_hits_));
}

void StatsEngine::flush() {
  uint32_t total, blocked, hits;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    total = total_;
    blocked = blocked_;
    hits = cache_hits_;
  }
  cJSON* root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "total", total);
  cJSON_AddNumberToObject(root, "blocked", blocked);
  cJSON_AddNumberToObject(root, "cache_hits", hits);
  char* json = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (json == nullptr) return;

  // Write temp + rename: a power loss mid-write never corrupts stats.json.
  bool ok = false;
  FILE* f = fopen(kStatsTmpPath, "w");
  if (f != nullptr) {
    if (fputs(json, f) < 0) {
      fclose(f);  // write error: close once, report failure
    } else {
      ok = (fclose(f) == 0);
    }
  }
  if (ok) ok = rename(kStatsTmpPath, kStatsPath) == 0;
  if (!ok) {
    ESP_LOGW(TAG, "stats flush failed");
    remove(kStatsTmpPath);
  }
  cJSON_free(json);
}

}  // namespace shield
