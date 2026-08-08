#pragma once

#include <cstdint>

namespace utils::lan_policy {
namespace ipv4 {
constexpr uint32_t prefix_mask(const uint8_t prefix_length) {
  return prefix_length == 0
             ? 0
             : 0xFFFFFFFFu << (32u - static_cast<uint32_t>(prefix_length));
}

constexpr bool is_private(const uint32_t address) {
  return (address & 0xFF000000u) == 0x0A000000u ||
         (address & 0xFFF00000u) == 0xAC100000u ||
         (address & 0xFFFF0000u) == 0xC0A80000u;
}

constexpr bool contains(const uint32_t local_address, const uint32_t mask,
                        const uint32_t remote_address) {
  return (local_address & mask) == (remote_address & mask);
}

constexpr uint32_t directed_broadcast(const uint32_t address,
                                      const uint32_t mask) {
  return (address & mask) | ~mask;
}
} // namespace ipv4

constexpr bool is_allowed_lobby_message(const int32_t message_type) {
  switch (message_type) {
  case 0x00: // info request
  case 0x01: // info response
  case 0x02: // private lobby state
  case 0x03: // game lobby state
  case 0x05: // custom game lobby state
  case 0x07: // host heartbeat
  case 0x08: // host disconnect
  case 0x09: // host disconnect client
  case 0x0A: // host leave with party
  case 0x0B: // client heartbeat
  case 0x0C: // client disconnect
  case 0x0D: // client reliable data
  case 0x0E: // client content
  case 0x10: // join lobby
  case 0x11: // join response
  case 0x12: // join agreement request
  case 0x13: // join agreement response
  case 0x14: // join complete
  case 0x15: // join member info
    return true;
  default:
    return false;
  }
}
} // namespace utils::lan_policy
