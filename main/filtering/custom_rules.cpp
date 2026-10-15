#include "filtering/custom_rules.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include <cJSON.h>
#include "esp_log.h"

#include "core/domain_matcher.h"

namespace shield {
namespace {

const char* TAG = "custom_rules";
constexpr char kPath[] = "/littlefs/custom_rules.json";

// File-local copies of the tiny JSON file helpers (also present in
// allowlist.cpp): kept per-module so filtering modules stay independent.
bool read_file(const char* path, std::string& out) {
  FILE* f = fopen(path, "rb");
  if (!f) return false;
  bool ok = false;
  if (fseek(f, 0, SEEK_END) == 0) {
    long len = ftell(f);
    if (len >= 0 && fseek(f, 0, SEEK_SET) == 0) {
      out.resize((size_t)len);
      ok = fread(out.data(), 1, (size_t)len, f) == (size_t)len;
    }
  }
  fclose(f);
  return ok;
}

bool write_file_atomic(const char* path, const char* data) {
  char tmp[160];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE* f = fopen(tmp, "w");
  if (!f) return false;
  bool ok;
  if (fputs(data, f) < 0) {
    ok = false;
    fclose(f);
  } else {
    ok = (fclose(f) == 0);
  }
  if (ok) ok = rename(tmp, path) == 0;
  if (!ok) remove(tmp);
  return ok;
}

}  // namespace

CustomRules::CustomRules() = default;

CustomRules& CustomRules::instance() {
  static CustomRules inst;
  return inst;
}

bool CustomRules::init() {
  std::lock_guard<std::mutex> lock(mutex_);
  return load_locked();
}

bool CustomRules::load_locked() {
  rules_.clear();
  next_id_ = 1;
  std::string text;
  if (!read_file(kPath, text)) {
    ESP_LOGI(TAG, "no %s, starting empty", kPath);  // missing => empty
    return true;
  }
  cJSON* root = cJSON_Parse(text.c_str());
  if (!root || !cJSON_IsArray(root)) {
    ESP_LOGE(TAG, "%s: JSON parse error (expected array)", kPath);
    cJSON_Delete(root);
    return false;
  }
  int n = cJSON_GetArraySize(root);
  for (int i = 0; i < n; ++i) {
    cJSON* item = cJSON_GetArrayItem(root, i);
    cJSON* jdomain = cJSON_GetObjectItemCaseSensitive(item, "domain");
    if (!cJSON_IsString(jdomain) || !jdomain->valuestring) continue;
    std::string d = normalize_domain(jdomain->valuestring);
    if (d.empty()) continue;
    cJSON* jaction = cJSON_GetObjectItemCaseSensitive(item, "action");
    bool block = true;  // default action is "block"
    if (cJSON_IsString(jaction) && jaction->valuestring)
      block = strcmp(jaction->valuestring, "allow") != 0;
    cJSON* jenabled = cJSON_GetObjectItemCaseSensitive(item, "enabled");
    bool enabled = !cJSON_IsFalse(jenabled);  // default true
    cJSON* jid = cJSON_GetObjectItemCaseSensitive(item, "id");
    uint32_t id = cJSON_IsNumber(jid) ? (uint32_t)jid->valuedouble : 0;
    if (id == 0) continue;  // 0 is reserved as "invalid id"
    rules_.push_back(CustomRule{id, d, block, enabled});
    if (id >= next_id_) next_id_ = id + 1;  // monotonic counter restore
  }
  cJSON_Delete(root);
  ESP_LOGI(TAG, "loaded %u rules, next_id=%u", (unsigned)rules_.size(),
           (unsigned)next_id_);
  return true;
}

bool CustomRules::save_locked() const {
  cJSON* root = cJSON_CreateArray();
  for (const CustomRule& r : rules_) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "domain", r.domain.c_str());
    cJSON_AddStringToObject(item, "action", r.block ? "block" : "allow");
    cJSON_AddItemToObject(item, "enabled", cJSON_CreateBool(r.enabled));
    cJSON_AddNumberToObject(item, "id", (double)r.id);
    cJSON_AddItemToArray(root, item);
  }
  char* txt = cJSON_PrintUnformatted(root);
  bool ok = false;
  if (txt) {
    ok = write_file_atomic(kPath, txt);
    free(txt);  // cJSON uses plain malloc/free by default
  }
  cJSON_Delete(root);
  if (!ok) ESP_LOGE(TAG, "persist failed");
  return ok;
}

uint32_t CustomRules::add(const std::string& domain, bool block) {
  std::string d = normalize_domain(domain);
  if (d.empty()) {
    ESP_LOGW(TAG, "add: invalid domain");
    return 0;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (CustomRule& r : rules_) {
    if (r.domain == d) {
      // Update in place, keep the original id; roll back if persist fails.
      bool old_block = r.block, old_enabled = r.enabled;
      r.block = block;
      r.enabled = true;
      if (!save_locked()) {
        r.block = old_block;
        r.enabled = old_enabled;
        return 0;
      }
      return r.id;
    }
  }
  CustomRule r;
  r.id = next_id_++;
  r.domain = d;
  r.block = block;
  r.enabled = true;
  rules_.push_back(r);
  if (!save_locked()) {
    rules_.pop_back();
    --next_id_;
    return 0;
  }
  return r.id;
}

bool CustomRules::remove(uint32_t id) {
  if (id == 0) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<CustomRule> next;
  next.reserve(rules_.size());
  bool found = false;
  for (const CustomRule& r : rules_) {
    if (r.id == id) {
      found = true;
      continue;
    }
    next.push_back(r);
  }
  if (!found) return false;
  // Commit in-memory only if the persist succeeds.
  std::vector<CustomRule> old = rules_;
  rules_.swap(next);
  if (!save_locked()) {
    rules_.swap(old);
    return false;
  }
  return true;
}

bool CustomRules::match(const std::string& normalized_domain,
                        bool* out_block) const {
  if (!out_block || normalized_domain.empty()) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  // for_each_parent_domain yields the most specific suffix first, so the
  // first enabled rule hit IS the longest-suffix match.
  const CustomRule* hit = nullptr;
  for_each_parent_domain(normalized_domain, [&](const std::string& suffix) {
    for (const CustomRule& r : rules_) {
      if (r.enabled && r.domain == suffix) {
        hit = &r;
        return false;  // stop the walk
      }
    }
    return true;
  });
  if (!hit) return false;
  *out_block = hit->block;
  return true;
}

std::vector<CustomRule> CustomRules::list() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<CustomRule> out = rules_;
  std::sort(out.begin(), out.end(), [](const CustomRule& a, const CustomRule& b) {
    return a.id < b.id;
  });
  return out;
}

}  // namespace shield
