#include "dns_server.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>  // close()

#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

namespace shield {

namespace {
const char* TAG = "dns_server";
}  // namespace

DnsServer::DnsServer() = default;

DnsServer::~DnsServer() { stop(); }

bool DnsServer::start(uint16_t port) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (running_.load()) {
    ESP_LOGW(TAG, "already running on port %u", port_);
    return true;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "socket() failed: errno %d", errno);
    return false;
  }
  int reuse = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    ESP_LOGE(TAG, "bind(:%u) failed: errno %d", port, errno);
    close(sock);
    return false;
  }

  sock_ = sock;
  port_ = port;
  const uint32_t gen = ++gen_;
  running_.store(true);
  // Pinned to core 0 (protocol CPU), 4 KB stack, priority 5 per design.
  BaseType_t ok = xTaskCreatePinnedToCore(&DnsServer::task_entry, "dns_server",
                                          4096, this, 5, &task_, 0);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "task create failed");
    running_.store(false);
    close(sock_);
    sock_ = -1;
    task_ = nullptr;
    return false;
  }
  ESP_LOGI(TAG, "listening on UDP :%u (gen %u)", (unsigned)port,
           (unsigned)gen);
  return true;
}

void DnsServer::stop() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!running_.load()) {
    return;
  }
  running_.store(false);
  if (sock_ >= 0) {
    // shutdown() unblocks the recvfrom() in run(); the task then exits itself.
    shutdown(sock_, SHUT_RDWR);
    close(sock_);
    sock_ = -1;
  }
  task_ = nullptr;  // task deletes itself after leaving run()
  ESP_LOGI(TAG, "stopped");
}

void DnsServer::set_query_handler(QueryHandler h) {
  std::lock_guard<std::mutex> lock(mutex_);
  handler_ = std::move(h);
}

void DnsServer::task_entry(void* arg) {
  static_cast<DnsServer*>(arg)->run();
}

void DnsServer::run() {
  // req_buf_/resp_buf_ are per-instance BSS buffers, so the 4 KB task stack
  // stays small and concurrent DnsServer instances never share memory.
  uint8_t* req = req_buf_;
  uint8_t* resp = resp_buf_;
  // Generation captured at task start; see stop()/start() race note in start().
  const uint32_t my_gen = gen_.load(std::memory_order_acquire);

  while (running_.load()) {
    struct sockaddr_in src {};
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(sock_, req, kMaxMessage, 0,
                         reinterpret_cast<struct sockaddr*>(&src), &slen);
    if (n < 0) {
      // Stale generation (stop() then start() reused the fd) or a real
      // stop(): exit. Otherwise it was transient; keep serving.
      if (gen_.load(std::memory_order_acquire) != my_gen ||
          !running_.load()) {
        break;
      }
      continue;
    }
    if (static_cast<size_t>(n) < kMinQuery) {
      continue;  // ignore runt packets
    }

    size_t resp_len = kMaxMessage;
    bool answered = false;
    // handler_ is installed before start(); no lock here (hot path).
    if (handler_) {
      answered = handler_(req, static_cast<size_t>(n),
                          src.sin_addr.s_addr /* net order */, resp, &resp_len);
      if (resp_len > kMaxMessage) {
        ESP_LOGW(TAG, "handler overran buffer; truncating");
        resp_len = kMaxMessage;
      }
    }
    if (answered && resp_len > 0) {
      sendto(sock_, resp, resp_len, 0,
             reinterpret_cast<struct sockaddr*>(&src), slen);
    }
  }
  vTaskDelete(nullptr);
}

}  // namespace shield
