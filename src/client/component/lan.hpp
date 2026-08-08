#pragma once

#include <game/game.hpp>
#include <utils/lan_policy.hpp>

namespace lan {
namespace ipv4 = ::utils::lan_policy::ipv4;

std::vector<game::net::netadr_t> get_broadcast_targets(uint16_t port = 27017);
std::optional<game::net::netadr_t>
get_local_endpoint_for(const game::net::netadr_t &peer);

bool is_same_subnet(const game::net::netadr_t &address);
bool is_zombies_system_link();
} // namespace lan
