#pragma once

// Web layer: owns the esp_http_server instance (port 80) and the WebSocket
// stats push task. All REST handlers live in api_handlers.{h,cpp}; this class
// only manages server lifetime, bearer auth, and WS session bookkeeping.

#include <esp_http_server.h>

#include <freertos/FreeRTOS.h>

#include <atomic>
#include <mutex>
#include <vector>

namespace shield {

class HttpServer {
 public:
  static HttpServer& instance();

  // Starts httpd (port 80, stack 6144, max 24 URI handlers), registers every
  // route, and spawns the 2 s WebSocket stats push task. Returns false on
  // httpd_start failure.
  bool start();
  void stop();
  bool running() const { return server_ != nullptr; }
  httpd_handle_t handle() const { return server_; }

  // Bearer auth for protected routes.
  //   - Public (always pass): "/" (dashboard), "/api/status", "/setup*"
  //     (provisioning routes owned by Team B; this helper just lets them
  //     through when they are registered).
  //   - Protected: requires header "Authorization: Bearer <api_token>"
  //     matching ConfigManager "api_token" (constant-time-ish compare;
  //     empty tokens never match).
  //   - "/ws": additionally accepts ?token=<api_token> as a query parameter,
  //     because browsers cannot set headers on a WebSocket handshake.
  // Never logs the token.
  static bool check_auth(httpd_req_t* req);

  // WebSocket session bookkeeping (called from the /ws handler and the push
  // task). Broadcast sends a frame to every registered fd via
  // httpd_ws_send_frame_async and prunes dead sessions.
  void ws_add(int fd);
  void ws_remove(int fd);
  void ws_broadcast(httpd_ws_frame_t* frame);

 private:
  HttpServer() = default;
  ~HttpServer() = default;
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  bool register_routes();

  // WebSocket stats push task body (2 s cadence).
  static void ws_push_task(void* arg);

  httpd_handle_t server_ = nullptr;
  TaskHandle_t ws_task_ = nullptr;
  std::atomic<bool> ws_task_run_{false};

  std::mutex ws_mutex_;
  std::vector<int> ws_fds_;
};

}  // namespace shield
