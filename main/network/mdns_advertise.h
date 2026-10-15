#pragma once

// mDNS advertisement for the shield: "<hostname>.local" plus an _http._tcp
// service on port 80 so the dashboard is discoverable on the LAN.

namespace shield {
namespace mdns_advertise {

// Starts mDNS (mdns_init + hostname + instance name + _http._tcp:80).
// Returns false gracefully — without crashing — if mDNS fails to start.
bool start(const char* hostname);

}  // namespace mdns_advertise
}  // namespace shield
