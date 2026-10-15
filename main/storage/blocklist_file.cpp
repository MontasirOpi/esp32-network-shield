#include "storage/blocklist_file.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include "esp_log.h"

namespace shield {
namespace {

const char* TAG = "blocklist_file";

constexpr uint32_t kVersion = 1;
constexpr char kMagic[4] = {'E', 'S', 'B', 'L'};
constexpr size_t kHeaderSize = 16;  // 4 magic + 4 version + 8 count

bool valid_slot(char slot) { return slot == 'A' || slot == 'B'; }

void slot_path(char slot, char* out, size_t out_len) {
  snprintf(out, out_len, "%s/slot_%c.bl", kBlocklistDir, slot == 'A' ? 'a' : 'b');
}

uint32_t read_u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

uint64_t read_u64_le(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
  return v;
}

void write_u32_le(uint8_t* p, uint32_t v) {
  for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

void write_u64_le(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

// Ensures kBlocklistDir exists. LittleFS itself is mounted by System (Team E)
// before any filtering call; mkdir is a no-op if the dir already exists.
bool ensure_dir() {
  if (mkdir(kBlocklistDir, 0755) == 0) return true;
  return errno == EEXIST;
}

}  // namespace

bool BlocklistFile::write_slot(char slot,
                               const std::vector<uint64_t>& sorted_hashes) {
  return write_slot_raw(slot, sorted_hashes.data(), sorted_hashes.size());
}

bool BlocklistFile::write_slot_raw(char slot, const uint64_t* data,
                                   size_t count) {
  if (!valid_slot(slot)) {
    ESP_LOGE(TAG, "write_slot: invalid slot '%c'", slot);
    return false;
  }
  // A/B SAFETY: never overwrite the ACTIVE slot file. The updater writes the
  // inactive slot, validates it, then flips active.txt atomically. Refusing
  // here is the last line of defense against corrupting the live blocklist.
  if (slot == active_slot()) {
    ESP_LOGE(TAG, "write_slot: REFUSED to overwrite ACTIVE slot '%c'", slot);
    return false;
  }
  if (!ensure_dir()) {
    ESP_LOGE(TAG, "write_slot: cannot create %s: %s", kBlocklistDir,
             strerror(errno));
    return false;
  }

  char final_path[96], tmp_path[104];
  slot_path(slot, final_path, sizeof(final_path));
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

  FILE* f = fopen(tmp_path, "wb");
  if (!f) {
    ESP_LOGE(TAG, "write_slot: fopen %s failed: %s", tmp_path, strerror(errno));
    return false;
  }
  bool ok = false;
  uint8_t hdr[kHeaderSize];
  memcpy(hdr, kMagic, 4);
  write_u32_le(hdr + 4, kVersion);
  write_u64_le(hdr + 8, (uint64_t)count);
  if (fwrite(hdr, 1, kHeaderSize, f) == kHeaderSize) {
    ok = true;
    uint8_t buf[8];
    for (size_t i = 0; i < count; ++i) {
      write_u64_le(buf, data[i]);
      if (fwrite(buf, 1, 8, f) != 8) {
        ok = false;
        break;
      }
    }
  }
  // fclose before rename: flushes and surfaces delayed write errors.
  if (fclose(f) != 0) ok = false;

  if (!ok) {
    ESP_LOGE(TAG, "write_slot: write failed for slot '%c'", slot);
    remove(tmp_path);
    return false;
  }
  // Atomic publish: temp -> final. A crash before this leaves the old slot
  // file intact; a crash after leaves the complete new file. Never partial.
  if (rename(tmp_path, final_path) != 0) {
    ESP_LOGE(TAG, "write_slot: rename failed: %s", strerror(errno));
    remove(tmp_path);
    return false;
  }
  ESP_LOGI(TAG, "slot '%c' written: %d hashes", slot,
           (int)count);
  return true;
}

bool BlocklistFile::read_count(char slot, uint64_t* count_out) {
  if (!valid_slot(slot) || !count_out) return false;
  char path[96];
  slot_path(slot, path, sizeof(path));
  FILE* f = fopen(path, "rb");
  if (!f) return false;  // missing slot file: caller decides (usually "empty")
  uint8_t hdr[kHeaderSize];
  bool ok = fread(hdr, 1, kHeaderSize, f) == kHeaderSize &&
            memcmp(hdr, kMagic, 4) == 0 && read_u32_le(hdr + 4) == kVersion;
  if (ok) {
    *count_out = read_u64_le(hdr + 8);
  } else {
    ESP_LOGW(TAG, "read_count: bad magic/version in slot '%c'", slot);
  }
  fclose(f);
  return ok;
}

bool BlocklistFile::contains(char slot, uint64_t hash) {
  uint64_t count = 0;
  if (!read_count(slot, &count) || count == 0) return false;
  char path[96];
  slot_path(slot, path, sizeof(path));
  FILE* f = fopen(path, "rb");
  if (!f) return false;
  // Binary search using seeks + 8-byte reads only. The file stays on flash;
  // it is NEVER loaded into RAM (slot files can be several MB).
  uint64_t lo = 0, hi = count;
  uint8_t buf[8];
  bool found = false;
  while (lo < hi) {
    uint64_t mid = lo + (hi - lo) / 2;
    if (fseek(f, (long)(kHeaderSize + mid * 8), SEEK_SET) != 0) break;
    if (fread(buf, 1, 8, f) != 8) break;
    uint64_t v = read_u64_le(buf);
    if (v == hash) {
      found = true;
      break;
    }
    if (v < hash) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  fclose(f);
  return found;
}

char BlocklistFile::active_slot() {
  char path[96];
  snprintf(path, sizeof(path), "%s/active.txt", kBlocklistDir);
  FILE* f = fopen(path, "r");
  if (!f) return 'A';  // first boot: default to 'A'
  int c = fgetc(f);
  fclose(f);
  return (c == 'B') ? 'B' : 'A';  // anything unexpected -> 'A'
}

bool BlocklistFile::set_active_slot(char slot) {
  if (!valid_slot(slot)) {
    ESP_LOGE(TAG, "set_active_slot: invalid slot '%c'", slot);
    return false;
  }
  if (!ensure_dir()) {
    ESP_LOGE(TAG, "set_active_slot: cannot create %s: %s", kBlocklistDir,
             strerror(errno));
    return false;
  }
  char final_path[96], tmp_path[104];
  snprintf(final_path, sizeof(final_path), "%s/active.txt", kBlocklistDir);
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);
  FILE* f = fopen(tmp_path, "w");
  if (!f) {
    ESP_LOGE(TAG, "set_active_slot: fopen failed: %s", strerror(errno));
    return false;
  }
  fputc(slot, f);
  bool ok = fclose(f) == 0;
  // Atomic flip: readers either see the old letter or the new one, never a
  // torn file. The newly activated slot file was already fully validated.
  if (ok) ok = rename(tmp_path, final_path) == 0;
  if (!ok) {
    ESP_LOGE(TAG, "set_active_slot: failed: %s", strerror(errno));
    remove(tmp_path);
    return false;
  }
  ESP_LOGI(TAG, "active slot -> '%c'", slot);
  return true;
}

}  // namespace shield
