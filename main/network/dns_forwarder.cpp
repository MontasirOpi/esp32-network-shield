#include "dns_forwarder.h"

#include <cerrno>
#include <cstring>
#include <mutex>  // (also in header; kept for IWYU clarity)
#include <sys/time.h>  // struct timeval for SO_RCVTIMEO
#include <unistd.h>  // close()

#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

namespace shield {

namespace {
const char* TAG = "dns_forwarder";
}  // namespace

DnsForwarder::DnsForwarder() {
  // Health entries start "reachable" until proven otherwise; IPs filled by init().
  health_[0].reachable = true;
  health_[1].reachable = true;
}

DnsForwarder::~DnsForwarder() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sock_ >= 0) {
    close(sock_);
    sock_ = -1;
  }
}

bool DnsForwarder::apply_timeout() {
  struct timeval tv {};
  tv.tv_sec = timeout_ms_ / 1000;
  tv.tv_usec = static_cast<suseconds_t>((timeout_ms_ % 1000) * 1000);
  return setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

bool DnsForwarder::init(const char* primary_ip, const char* secondary_ip,
                        uint32_t timeout_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sock_ >= 0) {
    close(sock_);
    sock_ = -1;
  }

  struct in_addr tmp {};
  if (!primary_ip || inet_pton(AF_INET, primary_ip, &tmp) != 1) {
    ESP_LOGE(TAG, "bad primary IP");
    return false;
  }
  if (!secondary_ip || inet_pton(AF_INET, secondary_ip, &tmp) != 1) {
    ESP_LOGE(TAG, "bad secondary IP");
    return false;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "socket() failed: errno %d", errno);
    return false;
  }

  strncpy(primary_, primary_ip, sizeof(primary_) - 1);
  strncpy(secondary_, secondary_ip, sizeof(secondary_) - 1);
  strncpy(health_[0].ip, primary_ip, sizeof(health_[0].ip) - 1);
  strncpy(health_[1].ip, secondary_ip, sizeof(health_[1].ip) - 1);
  timeout_ms_ = timeout_ms;
  sock_ = sock;
  if (!apply_timeout()) {
    ESP_LOGW(TAG, "SO_RCVTIMEO failed: errno %d", errno);
  }
  ESP_LOGI(TAG, "upstreams %s / %s, timeout %u ms", primary_, secondary_,
           (unsigned)timeout_ms_);
  return true;
}

void DnsForwarder::set_upstreams(const char* primary_ip,
                                 const char* secondary_ip,
                                 uint32_t timeout_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  struct in_addr tmp {};
  bool ok = primary_ip && secondary_ip &&
            inet_pton(AF_INET, primary_ip, &tmp) == 1 &&
            inet_pton(AF_INET, secondary_ip, &tmp) == 1;
  if (!ok) {
    ESP_LOGE(TAG, "set_upstreams: bad IP, keeping old upstreams");
    return;
  }
  strncpy(primary_, primary_ip, sizeof(primary_) - 1);
  strncpy(secondary_, secondary_ip, sizeof(secondary_) - 1);
  strncpy(health_[0].ip, primary_ip, sizeof(health_[0].ip) - 1);
  strncpy(health_[1].ip, secondary_ip, sizeof(health_[1].ip) - 1);
  timeout_ms_ = timeout_ms;
  if (sock_ >= 0) {
    apply_timeout();
  }
  ESP_LOGI(TAG, "upstreams now %s / %s, timeout %u ms", primary_, secondary_,
           (unsigned)timeout_ms_);
}

void DnsForwarder::note_success(int idx, uint32_t rtt_ms) {
  health_[idx].last_rtt_ms = rtt_ms;
  health_[idx].consecutive_failures = 0;
  health_[idx].reachable = true;
}

void DnsForwarder::note_failure(int idx) {
  health_[idx].consecutive_failures++;
  health_[idx].reachable = false;
}

bool DnsForwarder::try_upstream(int idx, const uint8_t* req, size_t req_len,
                                uint8_t* resp, size_t* resp_len,
                                uint32_t* rtt_ms_out) {
  const char* ip = (idx == 0) ? primary_ : secondary_;

  struct sockaddr_in dst {};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(53);
  if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
    ESP_LOGE(TAG, "bad upstream IP '%s'", ip);
    note_failure(idx);
    return false;
  }
  if (req_len < 12 || req_len > kMaxMessage) {
    ESP_LOGW(TAG, "dropping malformed query (%u bytes)", (unsigned)req_len);
    return false;  // local validation failure, not an upstream failure
  }
  uint16_t qid = (static_cast<uint16_t>(req[0]) << 8) | req[1];

  // Raw forward: query bytes are never modified (preserves EDNS0/flags).
  if (sendto(sock_, req, req_len, 0, reinterpret_cast<struct sockaddr*>(&dst),
             sizeof(dst)) < 0) {
    ESP_LOGW(TAG, "sendto %s failed: errno %d", ip, errno);
    note_failure(idx);
    return false;
  }

  int64_t start_us = esp_timer_get_time();
  int64_t deadline_us = start_us + static_cast<int64_t>(timeout_ms_) * 1000;
  uint8_t* buf = rx_buf_;  // BSS scratch; safe: forward() holds mutex_ here.

  while (true) {
    // Recompute the remaining timeout each lap so stray packets can't extend
    // the wait beyond one timeout_ms_ window in total.
    int64_t now_us = esp_timer_get_time();
    if (now_us >= deadline_us) {
      ESP_LOGW(TAG, "%s: timeout after %u ms", ip, (unsigned)timeout_ms_);
      note_failure(idx);
      return false;
    }
    struct timeval tv {};
    int64_t remain_us = deadline_us - now_us;
    tv.tv_sec = remain_us / 1000000;
    tv.tv_usec = static_cast<suseconds_t>(remain_us % 1000000);
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in from {};
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(sock_, buf, kMaxMessage, 0,
                         reinterpret_cast<struct sockaddr*>(&from), &flen);
    if (n < 0) {
      // EAGAIN/EWOULDBLOCK (timeout) or a real socket error: upstream failed.
      ESP_LOGW(TAG, "%s: recv failed: errno %d", ip, errno);
      note_failure(idx);
      return false;
    }
    // Basic sanity: transaction ID matches the query and QDCOUNT >= 1.
    // Anything else (late duplicates, stray traffic) is ignored while the
    // deadline allows.
    if (n >= 12) {
      uint16_t rid = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
      uint16_t qdcount = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
      if (rid == qid && qdcount >= 1) {
        memcpy(resp, buf, static_cast<size_t>(n));
        *resp_len = static_cast<size_t>(n);
        uint32_t rtt_ms =
            static_cast<uint32_t>((esp_timer_get_time() - start_us) / 1000);
        if (rtt_ms_out) {
          *rtt_ms_out = rtt_ms;
        }
        note_success(idx, rtt_ms);
        return true;
      }
    }
    ESP_LOGD(TAG, "%s: ignoring %d-byte stray packet", ip, (int)n);
  }
}

bool DnsForwarder::forward(const uint8_t* req, size_t req_len, uint8_t* resp,
                           size_t* resp_len, uint32_t* rtt_ms_out) {
  if (!req || !resp || !resp_len || req_len == 0) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (sock_ < 0) {
    ESP_LOGE(TAG, "forward() before init()");
    return false;
  }

  uint32_t rtt = 0;
  size_t rlen = 0;
  if (try_upstream(0, req, req_len, resp, &rlen, &rtt)) {
    *resp_len = rlen;
    if (rtt_ms_out) {
      *rtt_ms_out = rtt;
    }
    return true;
  }
  ESP_LOGW(TAG, "primary %s failed; failing over to %s", primary_, secondary_);
  if (try_upstream(1, req, req_len, resp, &rlen, &rtt)) {
    *resp_len = rlen;
    if (rtt_ms_out) {
      *rtt_ms_out = rtt;
    }
    return true;
  }
  ESP_LOGE(TAG, "both upstreams failed");
  return false;
}

bool DnsForwarder::upstream_health(int index, UpstreamHealth* out) const {
  if (!out || index < 0 || index > 1) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  *out = health_[index];
  return true;
}

}  // namespace shield
