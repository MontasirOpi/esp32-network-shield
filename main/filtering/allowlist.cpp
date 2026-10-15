#include "filtering/allowlist.h"

#include <algorithm>
#include <cstdio>
#include <string>

#include <cJSON.h>
#include "esp_log.h"

#include "core/domain_matcher.h"

namespace shield {
namespace {

const char* TAG = "allowlist";
constexpr char kPath[] = "/littlefs/allowlist.json";

// Reads an entire (small) file into a string. These JSON files are KBs at
// most; the blocklist itself never goes through this helper.
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

// Atomic write: temp file + rename, so a crash never leaves half a JSON.
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

Allowlist::Allowlist() = default;

Allowlist& Allowlist::instance() {
  static Allowlist inst;
  return inst;
}

bool Allowlist::init() {
  std::lock_guard<std::mutex> lock(mutex_);
  return load_locked();
}

bool Allowlist::load_locked() {
  domains_.clear();
  std::string text;
  if (!read_file(kPath, text)) {
    ESP_LOGI(TAG, "no %s, starting empty", kPath);  // missing => empty
    return true;
  }
  cJSON* root = cJSON_Parse(text.c_str());
  if (!root) {
    ESP_LOGE(TAG, "%s: JSON parse error", kPath);
    return false;
  }
  bool ok = true;
  cJSON* arr = cJSON_GetObjectItemCaseSensitive(root, "domains");
  if (!cJSON_IsArray(arr)) {
    ESP_LOGE(TAG, "%s: missing 'domains' array", kPath);
    ok = false;
  } else {
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; ++i) {
      cJSON* item = cJSON_GetArrayItem(arr, i);
      if (!cJSON_IsString(item) || !item->valuestring) continue;
      std::string d = normalize_domain(item->valuestring);
      if (!d.empty()) domains_.insert(d);
    }
  }
  cJSON_Delete(root);
  ESP_LOGI(TAG, "loaded %u allowlist domains", (unsigned)domains_.size());
  return ok;
}

bool Allowlist::save_locked() const {
  cJSON* root = cJSON_CreateObject();
  cJSON* arr = cJSON_CreateArray();
  for (const std::string& d : domains_)
    cJSON_AddItemToArray(arr, cJSON_CreateString(d.c_str()));
  cJSON_AddItemToObject(root, "domains", arr);
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

bool Allowlist::contains(const std::string& normalized_domain) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (normalized_domain.empty() || domains_.empty()) return false;
  bool found = false;
  for_each_parent_domain(normalized_domain, [&](const std::string& suffix) {
    if (domains_.count(suffix) > 0) {
      found = true;
      return false;  // stop the walk
    }
    return true;
  });
  return found;
}

bool Allowlist::add(const std::string& domain) {
  std::string d = normalize_domain(domain);
  if (d.empty()) {
    ESP_LOGW(TAG, "add: invalid domain");
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  domains_.insert(d);
  return save_locked();
}

bool Allowlist::remove(const std::string& domain) {
  std::string d = normalize_domain(domain);
  if (d.empty()) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  if (domains_.erase(d) == 0) return false;  // not present: nothing to persist
  return save_locked();
}

std::vector<std::string> Allowlist::list() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> out(domains_.begin(), domains_.end());
  std::sort(out.begin(), out.end());
  return out;
}

}  // namespace shield
