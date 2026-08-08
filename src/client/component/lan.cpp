#include <std_include.hpp>

#include "lan.hpp"
#include "network.hpp"

#include <game/game.hpp>
#include <game/utils.hpp>
#include <utils/flags.hpp>

namespace lan {
namespace {
struct interface_address {
  uint32_t address{};
  uint32_t mask{};
  uint32_t broadcast{};
};

std::mutex interface_mutex;
std::vector<interface_address> cached_interfaces;
uint64_t interfaces_cached_at{};

bool is_physical_lan_adapter(const IP_ADAPTER_ADDRESSES &adapter) {
  if (adapter.OperStatus != IfOperStatusUp ||
      adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
      adapter.IfType == IF_TYPE_TUNNEL) {
    return false;
  }

  return adapter.IfType == IF_TYPE_ETHERNET_CSMACD ||
         adapter.IfType == IF_TYPE_IEEE80211;
}

std::vector<interface_address> enumerate_interfaces() {
  ULONG size = 0;
  constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                          GAA_FLAG_SKIP_DNS_SERVER;
  if (GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size) !=
          ERROR_BUFFER_OVERFLOW ||
      size == 0) {
    return {};
  }

  std::vector<uint8_t> buffer(size);
  auto *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
  if (GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size) !=
      NO_ERROR) {
    return {};
  }

  std::vector<interface_address> result;
  for (auto *adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    if (!is_physical_lan_adapter(*adapter)) {
      continue;
    }

    for (auto *unicast = adapter->FirstUnicastAddress; unicast != nullptr;
         unicast = unicast->Next) {
      if (unicast->Address.lpSockaddr == nullptr ||
          unicast->Address.lpSockaddr->sa_family != AF_INET ||
          unicast->OnLinkPrefixLength == 0 ||
          unicast->OnLinkPrefixLength > 30) {
        continue;
      }

      const auto *socket_address =
          reinterpret_cast<const sockaddr_in *>(unicast->Address.lpSockaddr);
      const uint32_t address = ntohl(socket_address->sin_addr.s_addr);
      if (!ipv4::is_private(address)) {
        continue;
      }

      const uint32_t mask = ipv4::prefix_mask(unicast->OnLinkPrefixLength);
      const uint32_t broadcast = ipv4::directed_broadcast(address, mask);
      if (broadcast == address) {
        continue;
      }

      const interface_address entry{address, mask, broadcast};
      if (std::ranges::find(result, entry.broadcast,
                            &interface_address::broadcast) == result.end()) {
        result.push_back(entry);
      }
    }
  }

  return result;
}

void refresh_interfaces() {
  const uint64_t now = GetTickCount64();
  if (cached_interfaces.empty() || now - interfaces_cached_at >= 5000) {
    cached_interfaces = enumerate_interfaces();
    interfaces_cached_at = now;
  }
}
} // namespace

std::vector<game::net::netadr_t> get_broadcast_targets(const uint16_t port) {
  std::lock_guard lock(interface_mutex);
  refresh_interfaces();

  std::vector<game::net::netadr_t> targets;
  for (const auto &iface : cached_interfaces) {
    targets.push_back(network::address_from_ip(htonl(iface.broadcast), port));
  }
  return targets;
}

std::optional<game::net::netadr_t>
get_local_endpoint_for(const game::net::netadr_t &peer) {
  if (!network::is_ip_address(peer)) {
    return std::nullopt;
  }

  const uint32_t remote = ntohl(peer.addr);
  std::lock_guard lock(interface_mutex);
  refresh_interfaces();

  const auto selected = std::ranges::find_if(
      cached_interfaces, [remote](const interface_address &iface) {
        return ipv4::contains(iface.address, iface.mask, remote) &&
               remote != iface.broadcast;
      });
  if (selected == cached_interfaces.end()) {
    return std::nullopt;
  }

  uint16_t port = game::port();
  sockaddr_in socket_address{};
  int socket_address_size = sizeof(socket_address);
  if (*game::net::ip_socket != INVALID_SOCKET &&
      getsockname(*game::net::ip_socket,
                  reinterpret_cast<sockaddr *>(&socket_address),
                  &socket_address_size) == 0 &&
      socket_address.sin_port != 0) {
    port = ntohs(socket_address.sin_port);
  }

  return network::address_from_ip(htonl(selected->address), port);
}

bool is_same_subnet(const game::net::netadr_t &address) {
  if (!network::is_ip_address(address) || address.addr == 0 ||
      address.ipv4.a == 127 || address.ipv4.a >= 224) {
    return false;
  }

  const uint32_t remote = ntohl(address.addr);
  if (!ipv4::is_private(remote)) {
    return false;
  }

  std::lock_guard lock(interface_mutex);
  refresh_interfaces();
  const bool allow_local_address = utils::flags::has_flag("lan-local-test");
  for (const auto &iface : cached_interfaces) {
    if ((allow_local_address || remote != iface.address) &&
        ipv4::contains(iface.address, iface.mask, remote) &&
        remote != iface.broadcast) {
      return true;
    }
  }

  return false;
}

bool is_zombies_system_link() {
  if (game::is_server() ||
      !game::com::Com_SessionMode_IsMode(game::eModes::ZOMBIES)) {
    return false;
  }

  // The two-Bottle harness can restore each prefix into a different saved
  // frontend lobby. Treat Zombies as System Link in this explicitly test-only
  // mode so the harness tests discovery/join transport rather than UI state.
  if (utils::flags::has_flag("lan-local-test")) {
    return true;
  }

  // These two native states transition independently while entering and
  // leaving a pre-game System Link lobby. Requiring both at the instant a
  // getInfo request arrives makes an otherwise joinable host disappear from
  // discovery. Either LAN signal is sufficient; same-subnet validation still
  // gates discovery and native lobby traffic.
  return game::com::Com_SessionMode_GetNetworkMode() ==
             game::eNetworkModes::SYSTEMLINK ||
         game::lobby::base::LobbyBase_GetNetworkMode() ==
             game::lobby::LobbyNetworkMode::LAN;
}
} // namespace lan
