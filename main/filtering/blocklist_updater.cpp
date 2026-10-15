#include "filtering/blocklist_updater.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>  // std::bad_alloc
#include <string>
#include <vector>

#include <cJSON.h>
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "core/domain_matcher.h"
#include "filtering/blocklist_manager.h"
#include "storage/blocklist_file.h"

namespace shield {
namespace {

const char* TAG = "blocklist_upd";

// Cap on TOTAL lines parsed across all sources: bounds RAM/CPU if a source
// grows unexpectedly. Lines beyond the cap are skipped (logged once); the
// update proceeds with what was parsed.
constexpr uint64_t kMaxTotalLines = 600000;
// A single line longer than this is discarded (protects the line buffer from
// a pathological source); parsing resumes at the next newline.
constexpr size_t kMaxLineLen = 65536;
// Validation: a real blocklist must have at least this many entries.
constexpr uint64_t kMinValidEntries = 1000;
// Spot-check sentinels: must be present / must be absent after a good update.
constexpr char kMustContain[] = "doubleclick.net";
constexpr char kMustNotContain[] = "google.com";

// ---- Working-set memory strategy -------------------------------------------
// The classic ESP32 has ~320 KB of internal DRAM, so the tens of thousands of
// hashes parsed from blocklist sources must NOT live in node-based containers
// (std::unordered_set ≈ 32-40 bytes/entry → megabytes). Instead we collect
// hashes in a flat vector (8 bytes/entry), then sort + unique for dedupe.
//
// The vector's allocator prefers SPIRAM (present on ESP32-S3 and PSRAM-fitted
// classic modules). On boards WITHOUT SPIRAM the working set is capped at
// kMaxHashesNoSpiram entries so an update degrades to a partial list instead
// of crashing with an OOM; the active slot is untouched either way.
template <typename T>
struct SpiramFirstAlloc {
  using value_type = T;
  SpiramFirstAlloc() = default;
  template <typename U>
  SpiramFirstAlloc(const SpiramFirstAlloc<U>&) {}
  T* allocate(std::size_t n) {
    const size_t bytes = n * sizeof(T);
    void* p = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p)
      p = heap_caps_malloc(bytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!p) throw std::bad_alloc();
    return static_cast<T*>(p);
  }
  void deallocate(T* p, std::size_t) noexcept { heap_caps_free(p); }
  template <typename U>
  struct rebind {
    using other = SpiramFirstAlloc<U>;
  };
};
template <typename T, typename U>
bool operator==(const SpiramFirstAlloc<T>&, const SpiramFirstAlloc<U>&) {
  return true;
}
template <typename T, typename U>
bool operator!=(const SpiramFirstAlloc<T>&, const SpiramFirstAlloc<U>&) {
  return false;
}

using HashVec = std::vector<uint64_t, SpiramFirstAlloc<uint64_t>>;

// 15k hashes ≈ 120 KB of internal DRAM: safe headroom on a SPIRAM-less
// classic ESP32. With SPIRAM the cap is effectively the line cap (600k).
constexpr size_t kMaxHashesNoSpiram = 15000;

bool have_spiram() {
  return heap_caps_get_free_size(MALLOC_CAP_SPIRAM) > 0;
}

// Sink that enforces the working-set cap during parsing.
struct HashSink {
  HashVec hashes;
  size_t cap;
  bool capped = false;
  void add(uint64_t h) {
    if (hashes.size() >= cap) {
      if (!capped) {
        ESP_LOGW(TAG,
                 "hash cap %u reached — board has no SPIRAM, keeping a "
                 "partial list; add PSRAM for full blocklist updates",
                 (unsigned)cap);
        capped = true;
      }
      return;
    }
    hashes.push_back(h);
  }
};

// Hostnames that appear as local/admin entries in hosts files; never block
// targets, so skip them even if a source lists them.
bool is_local_hostname(const std::string& d) {
  return d == "localhost" || d == "localhost.localdomain" ||
         d == "broadcasthost" || d == "local" || d == "localhost6";
}

// True for an IPv4 ("127.0.0.1") or IPv6 ("::1") address token.
bool is_ip_token(const std::string& tok) {
  if (tok.empty()) return false;
  if (tok.find(':') != std::string::npos) return true;
  bool has_dot = false;
  for (char c : tok) {
    if (c == '.') {
      has_dot = true;
      continue;
    }
    if (c < '0' || c > '9') return false;
  }
  return has_dot;
}

void set_msg(UpdateResult& r, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(r.message, sizeof(r.message), fmt, ap);
  va_end(ap);
}

// Parses one line of a hosts-format or plain-domain list:
//   "127.0.0.1 ads.example.com" / "0.0.0.0 ads.example.com # comment"
//   "ads.example.com"
// Comments (#) and blank lines are skipped. Every candidate domain is
// normalized via core; invalid ones (empty, >253 chars, no dot, local
// hostnames) are skipped. Valid ones are APPENDED as FNV-1a hashes — dedupe
// happens later via sort + unique, which keeps peak RAM at 8 bytes/entry.
void parse_line(const std::string& raw, HashSink& sink) {
  size_t end = raw.size();
  while (end > 0 &&
         (raw[end - 1] == '\r' || raw[end - 1] == ' ' || raw[end - 1] == '\t'))
    --end;
  size_t beg = 0;
  while (beg < end && (raw[beg] == ' ' || raw[beg] == '\t')) ++beg;
  if (beg >= end || raw[beg] == '#') return;

  size_t pos = beg;
  bool first = true;
  while (pos < end) {
    while (pos < end && (raw[pos] == ' ' || raw[pos] == '\t')) ++pos;
    if (pos >= end) break;
    if (raw[pos] == '#') break;  // inline comment: ignore the rest of the line
    size_t tok_end = pos;
    while (tok_end < end && raw[tok_end] != ' ' && raw[tok_end] != '\t')
      ++tok_end;
    std::string tok(raw, pos, tok_end - pos);
    pos = tok_end;
    if (first) {
      first = false;
      if (is_ip_token(tok)) continue;  // hosts line: skip the address token
      // else: plain-domain line; fall through and treat this token as a domain
    }
    std::string d = normalize_domain(tok);
    if (d.empty() || d.size() > 253) continue;
    if (d.find('.') == std::string::npos) continue;  // must look like a domain
    if (is_local_hostname(d)) continue;
    sink.add(fnv1a_64(d));
  }
}

// Streams one URL with esp_http_client (open + fetch_headers + read loop),
// parsing line-by-line on the fly so only a small chunk buffer plus the flat
// hash vector live in RAM. Returns false on network/HTTP error. total_lines is
// cumulative across sources; when the cap is hit, reading stops (hit_cap set)
// but already-parsed data is kept.
bool fetch_and_parse(const std::string& url, HashSink& sink,
                     uint64_t& total_lines, bool& hit_cap) {
  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.timeout_ms = 60000;  // 60 s per the update contract
  // HTTPS trust via the embedded certificate bundle (default in IDF v5;
  // requires CONFIG_MBEDTLS_CERTIFICATE_BUNDLE). Redirects are followed by
  // default (disable_auto_redirect=false, up to 10 hops).
  config.crt_bundle_attach = esp_crt_bundle_attach;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    ESP_LOGE(TAG, "http init failed: %s", url.c_str());
    return false;
  }

  bool net_ok = false;
  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "http open failed: %s (%s)", url.c_str(),
             esp_err_to_name(err));
  } else {
    int content_len = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    ESP_LOGI(TAG, "GET %s -> %d (%d bytes)", url.c_str(), status, content_len);
    if (status != 200) {
      ESP_LOGE(TAG, "HTTP %d for %s", status, url.c_str());
    } else {
      net_ok = true;
      std::string carry;
      carry.reserve(512);
      bool discarding = false;  // skipping an over-long line
      char chunk[2048];
      int n = 0;
      bool cont = true;
      while (cont && (n = esp_http_client_read(client, chunk, sizeof(chunk))) >
                         0) {
        size_t start = 0;
        for (int i = 0; i < n && cont; ++i) {
          if (discarding) {
            if (chunk[i] == '\n') discarding = false;
            start = i + 1;
            continue;
          }
          if (chunk[i] == '\n') {
            std::string line = carry;
            line.append(chunk + start, (size_t)(i - start));
            carry.clear();
            start = i + 1;
            if (total_lines >= kMaxTotalLines) {
              if (!hit_cap) {
                ESP_LOGW(TAG, "line cap %llu reached, skipping the rest",
                         (unsigned long long)kMaxTotalLines);
                hit_cap = true;
              }
              cont = false;
              break;
            }
            ++total_lines;
            parse_line(line, sink);
          }
        }
        if (cont && !discarding && start < (size_t)n) {
          carry.append(chunk + start, (size_t)n - start);
          if (carry.size() > kMaxLineLen) {
            ESP_LOGW(TAG, "over-long line discarded");
            carry.clear();
            discarding = true;
          }
        }
      }
      if (n < 0) {
        ESP_LOGE(TAG, "http read error: %s", url.c_str());
        net_ok = false;
      } else if (cont && !discarding && !carry.empty() &&
                 total_lines < kMaxTotalLines) {
        ++total_lines;  // last line without a trailing newline
        parse_line(carry, sink);
      }
    }
    esp_http_client_close(client);
  }
  esp_http_client_cleanup(client);
  return net_ok;
}

// Writes /littlefs/blocklists/meta.json and /littlefs/blocklists/updated_at.
// Best-effort: failures are logged but never fail the update itself.
// updated_at is boot-relative seconds (no SNTP/RTC in this module's scope).
void write_meta(char slot, uint64_t entries,
                const std::vector<std::string>& sources) {
  char path[96], tmp[104];
  snprintf(path, sizeof(path), "%s/meta.json", kBlocklistDir);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);

  bool ok = false;
  cJSON* root = cJSON_CreateObject();
  if (root) {
    cJSON_AddStringToObject(root, "slot", slot == 'A' ? "A" : "B");
    cJSON_AddNumberToObject(root, "entries", (double)entries);
    cJSON_AddNumberToObject(root, "updated_at_s",
                            (double)(esp_timer_get_time() / 1000000));
    cJSON* arr = cJSON_CreateArray();
    for (const std::string& s : sources)
      cJSON_AddItemToArray(arr, cJSON_CreateString(s.c_str()));
    cJSON_AddItemToObject(root, "sources", arr);
    char* txt = cJSON_PrintUnformatted(root);
    if (txt) {
      FILE* f = fopen(tmp, "w");
      if (f) {
        ok = fputs(txt, f) >= 0 && fclose(f) == 0;
        if (ok) ok = rename(tmp, path) == 0;
        if (!ok) remove(tmp);
      }
      free(txt);  // cJSON uses plain malloc/free by default
    }
    cJSON_Delete(root);
  }
  if (!ok) ESP_LOGW(TAG, "meta.json write failed (non-fatal)");

  snprintf(path, sizeof(path), "%s/updated_at", kBlocklistDir);
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE* f = fopen(tmp, "w");
  if (f) {
    fprintf(f, "%lld", (long long)(esp_timer_get_time() / 1000000));
    if (fclose(f) == 0 && rename(tmp, path) == 0) return;
    remove(tmp);
  }
  ESP_LOGW(TAG, "updated_at write failed (non-fatal)");
}

}  // namespace

BlocklistUpdater::BlocklistUpdater()
    : sources_({
          "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
          "https://someonewhocares.org/hosts/zero/hosts",
      }) {}

BlocklistUpdater& BlocklistUpdater::instance() {
  static BlocklistUpdater inst;
  return inst;
}

void BlocklistUpdater::set_sources(const std::vector<std::string>& urls) {
  std::lock_guard<std::mutex> lock(mutex_);
  sources_ = urls;
}

UpdateResult BlocklistUpdater::update_now() {
  std::lock_guard<std::mutex> lock(mutex_);
  UpdateResult r;

  // A/B SAFETY: we only ever write the INACTIVE slot. The active slot file is
  // never opened for writing (write_slot() would refuse it anyway).
  const char active = BlocklistFile::active_slot();
  const char inactive = (active == 'A') ? 'B' : 'A';
  ESP_LOGI(TAG, "update start: active='%c', target inactive='%c'", active,
           inactive);

  // (1) Download + parse. Hashes accumulate in a flat SPIRAM-preferring
  // vector (8 bytes/entry); dedupe is sort + unique below. std::bad_alloc
  // (e.g. SPIRAM exhausted) is caught: the active slot stays untouched.
  HashSink sink;
  sink.cap = have_spiram() ? kMaxTotalLines : kMaxHashesNoSpiram;
  ESP_LOGI(TAG, "SPIRAM %s; hash working-set cap %u", have_spiram() ? "present" : "absent",
           (unsigned)sink.cap);
  uint64_t total_lines = 0;
  bool download_ok = true;
  try {
    for (const std::string& url : sources_) {
      if (total_lines >= kMaxTotalLines) {
        ESP_LOGW(TAG, "total line cap reached, skipping remaining sources");
        break;
      }
      bool hit_cap = false;
      if (!fetch_and_parse(url, sink, total_lines, hit_cap)) {
        set_msg(r, "fetch failed: %s", url.c_str());
        download_ok = false;
        break;
      }
      ESP_LOGI(TAG, "parsed %s: %u hashes so far", url.c_str(),
               (unsigned)sink.hashes.size());
    }
  } catch (const std::bad_alloc&) {
    set_msg(r, "out of memory while parsing (active slot untouched)");
    download_ok = false;
  }
  if (!download_ok) {
    ESP_LOGE(TAG, "%s (active slot '%c' untouched)", r.message, active);
    return r;  // active slot untouched
  }

  if (sink.hashes.empty()) {
    set_msg(r, "no domains parsed from sources");
    ESP_LOGE(TAG, "%s (active slot '%c' untouched)", r.message, active);
    return r;
  }

  // (2) Sort ascending (slot-file order) + unique for dedupe.
  HashVec& sorted = sink.hashes;
  std::sort(sorted.begin(), sorted.end());
  sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
  ESP_LOGI(TAG, "deduplicated to %u unique hashes", (unsigned)sorted.size());

  // (3) Write the INACTIVE slot (temp + rename inside write_slot).
  if (!BlocklistFile::write_slot(inactive, sorted)) {
    set_msg(r, "write_slot failed for '%c'", inactive);
    ESP_LOGE(TAG, "%s (active slot '%c' untouched)", r.message, active);
    return r;
  }

  // (4) VALIDATE before activation. Every check must pass; on ANY failure the
  // active slot stays exactly as it was.
  uint64_t count = 0;
  if (!BlocklistFile::read_count(inactive, &count)) {
    // read_count already verified magic "ESBL" + version 1.
    set_msg(r, "slot '%c': bad magic/header", inactive);
  } else if (count < kMinValidEntries) {
    set_msg(r, "slot '%c': only %llu entries (< %llu)", inactive,
            (unsigned long long)count, (unsigned long long)kMinValidEntries);
  } else if (!BlocklistFile::contains(inactive, fnv1a_64(kMustContain))) {
    set_msg(r, "slot '%c': missing %s", inactive, kMustContain);
  } else if (BlocklistFile::contains(inactive, fnv1a_64(kMustNotContain))) {
    set_msg(r, "slot '%c': unexpectedly blocks %s", inactive, kMustNotContain);
  } else if (!BlocklistManager::instance().activate_slot(inactive)) {
    // (5) Activate: flip active.txt + rebuild the Bloom. Old slot file kept.
    set_msg(r, "activate_slot('%c') failed", inactive);
  } else {
    write_meta(inactive, count, sources_);
    r.ok = true;
    r.entries = count;
    set_msg(r, "updated: %llu entries (slot '%c')",
            (unsigned long long)count, inactive);
    ESP_LOGI(TAG, "%s", r.message);
    return r;
  }
  ESP_LOGE(TAG, "%s (active slot '%c' untouched)", r.message, active);
  return r;
}

}  // namespace shield
