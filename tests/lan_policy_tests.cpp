#include <utils/lan_policy.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

int main() {
  using namespace utils::lan_policy;

  static_assert(ipv4::prefix_mask(0) == 0);
  static_assert(ipv4::prefix_mask(24) == 0xFFFFFF00u);
  static_assert(ipv4::prefix_mask(30) == 0xFFFFFFFCu);
  static_assert(ipv4::is_private(0x0A000001u));
  static_assert(ipv4::is_private(0xAC100001u));
  static_assert(ipv4::is_private(0xC0A80101u));
  static_assert(!ipv4::is_private(0x64400001u));
  static_assert(ipv4::contains(0xC0A8010Au, 0xFFFFFF00u, 0xC0A80163u));
  static_assert(!ipv4::contains(0xC0A8010Au, 0xFFFFFF00u, 0xC0A80263u));
  static_assert(ipv4::directed_broadcast(0xC0A8010Au, 0xFFFFFF00u) ==
                0xC0A801FFu);

  constexpr std::array allowed{0x00, 0x01, 0x02, 0x03, 0x05, 0x07, 0x08,
                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x10,
                               0x11, 0x12, 0x13, 0x14, 0x15};
  for (int32_t type = -1; type <= 0x21; ++type) {
    const bool expected =
        std::find(allowed.begin(), allowed.end(), type) != allowed.end();
    assert(is_allowed_lobby_message(type) == expected);
  }

  return 0;
}
