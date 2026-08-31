#include <game/game.hpp>
#include <game/utils.hpp>
#include <loader/component_loader.hpp>
#include <std_include.hpp>

#include "auth.hpp"
#include "friends.hpp"
#include "lan.hpp"
#include "network.hpp"
#include "network_password.hpp"
#include "party.hpp"
#include "profile_infos.hpp"
#include "scheduler.hpp"
#include "toast.hpp"
#include "workshop.hpp"

#include <game/utils.hpp>
#include <utils/concurrency.hpp>
#include <utils/cryptography.hpp>
#include <utils/hook.hpp>
#include <utils/info_string.hpp>
#include <utils/string.hpp>

#include <game/impl/cl/cl.hpp>

namespace party {
game::EngineDependentDvarMut cl_connected_to_dedi;
namespace {
constexpr uint16_t default_server_port = 27017;

std::atomic_bool is_connecting_to_dedi{false};
game::net::netadr_t connect_host{{}, {}, game::net::NA_BAD, {}};

std::mutex hostname_mutex;
std::string cached_server_hostname;
int cached_server_max_clients = 0;

std::string normalize_connect_address(std::string address) {
  utils::string::trim(address);

  const size_t separator = address.find(':');
  const std::string host = address.substr(0, separator);
  if (utils::string::to_lower(host) == "localhost") {
    address.replace(0, host.size(), "127.0.0.1");
  }

  if (separator == std::string::npos) {
    address.append(":" + std::to_string(default_server_port));
  }

  return address;
}

void update_dedi_dvar(bool on_dedi) { cl_connected_to_dedi.set(on_dedi); }

struct server_query {
  bool sent{false};
  game::net::netadr_t host{};
  std::string challenge{};
  query_callback callback{};
  std::chrono::high_resolution_clock::time_point query_time{};
};

utils::concurrency::container<std::vector<server_query>> &get_server_queries() {
  static utils::concurrency::container<std::vector<server_query>>
      server_queries;
  return server_queries;
}

struct lan_query {
  bool active{};
  uint64_t generation{};
  std::string challenge{};
  std::chrono::high_resolution_clock::time_point query_time{};
  std::unordered_set<game::net::netadr_t> discovered{};
  lan_query_response_callback response_callback{};
  lan_query_complete_callback complete_callback{};
};

std::mutex lan_query_mutex;
lan_query active_lan_query{};

void send_lan_query_probe(
    const uint64_t generation, const std::string &challenge,
    const std::vector<game::net::netadr_t> &targets) {
  {
    std::lock_guard lock(lan_query_mutex);
    if (!active_lan_query.active ||
        active_lan_query.generation != generation ||
        active_lan_query.challenge != challenge) {
      return;
    }
  }

  for (const auto &target : targets) {
    network::send(target, "getInfo", challenge);
  }
}

using lan_auth_callback = std::function<void(bool)>;
struct pending_lan_auth {
  game::net::netadr_t host{};
  std::string client_nonce{};
  std::string local_endpoint{};
  std::string server_nonce{};
  std::chrono::high_resolution_clock::time_point started{};
  lan_auth_callback callback{};
};

struct incoming_lan_auth {
  std::string client_nonce{};
  std::string server_nonce{};
  std::chrono::high_resolution_clock::time_point started{};
};

std::mutex lan_auth_mutex;
std::optional<pending_lan_auth> pending_auth;
std::unordered_map<uint64_t, incoming_lan_auth> incoming_auths;
std::unordered_map<uint64_t, std::chrono::high_resolution_clock::time_point>
    authorized_lan_peers;

uint64_t lan_peer_key(const game::net::netadr_t &peer) {
  return static_cast<uint64_t>(peer.addr) << 16 | peer.port;
}

void authorize_lan_peer(const game::net::netadr_t &peer) {
  std::lock_guard lock(lan_auth_mutex);
  authorized_lan_peers[lan_peer_key(peer)] =
      std::chrono::high_resolution_clock::now() + 30min;
}

bool is_lan_peer_authorized_internal(const game::net::netadr_t &peer) {
  if (!network_password::is_password_set()) {
    return true;
  }

  std::lock_guard lock(lan_auth_mutex);
  const auto authorization = authorized_lan_peers.find(lan_peer_key(peer));
  return authorization != authorized_lan_peers.end() &&
         authorization->second >= std::chrono::high_resolution_clock::now();
}

void handle_lan_auth_request(const game::net::netadr_t &peer,
                             const network::data_view &data,
                             game::LocalClientNum_t) {
  if (!lan::is_zombies_system_link() || !lan::is_same_subnet(peer) ||
      !network_password::is_password_set() || data.size() > 512) {
    return;
  }

  const utils::info_string info{data};
  const std::string client_nonce = info.get("nonce");
  if (client_nonce.empty() || client_nonce.size() > 128) {
    return;
  }

  const std::string server_nonce = utils::cryptography::random::get_challenge();
  {
    std::lock_guard lock(lan_auth_mutex);
    const uint64_t key = lan_peer_key(peer);
    if (incoming_auths.size() >= 64 && !incoming_auths.contains(key)) {
      return;
    }
    incoming_auths[key] = {client_nonce, server_nonce,
                           std::chrono::high_resolution_clock::now()};
  }

  utils::info_string challenge;
  challenge.set("nonce", client_nonce);
  challenge.set("challenge", server_nonce);
  network::send(peer, "lanAuthChallenge", challenge.build(), '\n');
}

void handle_lan_auth_challenge(const game::net::netadr_t &host,
                               const network::data_view &data,
                               game::LocalClientNum_t) {
  if (!lan::is_same_subnet(host) || data.size() > 512) {
    return;
  }

  const utils::info_string info{data};
  const std::string client_nonce = info.get("nonce");
  const std::string server_nonce = info.get("challenge");
  std::string local_endpoint;
  {
    std::lock_guard lock(lan_auth_mutex);
    if (!pending_auth || pending_auth->host != host ||
        pending_auth->client_nonce != client_nonce || client_nonce.empty() ||
        server_nonce.empty() || server_nonce.size() > 128 ||
        !pending_auth->server_nonce.empty()) {
      return;
    }
    pending_auth->server_nonce = server_nonce;
    local_endpoint = pending_auth->local_endpoint;
  }

  const std::string proof = network_password::create_connect_proof(
      client_nonce + ":" + server_nonce, "boiii-lan-auth-v1", local_endpoint);
  if (proof.empty()) {
    return;
  }

  utils::info_string response;
  response.set("nonce", client_nonce);
  response.set("challenge", server_nonce);
  response.set("proof", utils::cryptography::base64::encode(proof));
  network::send(host, "lanAuthProof", response.build(), '\n');
}

void handle_lan_auth_proof(const game::net::netadr_t &peer,
                           const network::data_view &data,
                           game::LocalClientNum_t) {
  if (!lan::is_zombies_system_link() || !lan::is_same_subnet(peer) ||
      !network_password::is_password_set() || data.size() > 512) {
    return;
  }

  const utils::info_string info{data};
  const std::string client_nonce = info.get("nonce");
  const std::string server_nonce = info.get("challenge");
  const std::string encoded_proof = info.get("proof");
  if (client_nonce.empty() || client_nonce.size() > 128 ||
      server_nonce.empty() || server_nonce.size() > 128 ||
      encoded_proof.empty() || encoded_proof.size() > 128) {
    return;
  }

  {
    std::lock_guard lock(lan_auth_mutex);
    const auto incoming = incoming_auths.find(lan_peer_key(peer));
    if (incoming == incoming_auths.end() ||
        incoming->second.client_nonce != client_nonce ||
        incoming->second.server_nonce != server_nonce ||
        std::chrono::high_resolution_clock::now() - incoming->second.started >=
            1500ms) {
      return;
    }
    incoming_auths.erase(incoming);
  }

  const std::string proof = utils::cryptography::base64::decode(encoded_proof);
  if (!network_password::verify_connect_proof(
          proof, client_nonce + ":" + server_nonce, "boiii-lan-auth-v1",
          network::address_to_string(peer))) {
    return;
  }

  authorize_lan_peer(peer);
  network::send(peer, "lanAuthResponse", client_nonce);
}

void handle_lan_auth_response(const game::net::netadr_t &host,
                              const network::data_view &data,
                              game::LocalClientNum_t) {
  lan_auth_callback callback;
  {
    std::lock_guard lock(lan_auth_mutex);
    if (!pending_auth || pending_auth->host != host ||
        pending_auth->client_nonce.size() != data.size() ||
        std::memcmp(pending_auth->client_nonce.data(), data.data(),
                    data.size()) != 0) {
      return;
    }
    callback = std::move(pending_auth->callback);
    pending_auth.reset();
    authorized_lan_peers[lan_peer_key(host)] =
        std::chrono::high_resolution_clock::now() + 30min;
  }

  if (callback) {
    callback(true);
  }
}

void authenticate_lan_peer(const game::net::netadr_t &host,
                           lan_auth_callback callback) {
  const auto local_endpoint = lan::get_local_endpoint_for(host);
  if (!local_endpoint || !network_password::is_password_set()) {
    callback(false);
    return;
  }

  const std::string nonce = utils::cryptography::random::get_challenge();
  utils::info_string info;
  info.set("nonce", nonce);

  lan_auth_callback replaced_callback;
  {
    std::lock_guard lock(lan_auth_mutex);
    if (pending_auth) {
      replaced_callback = std::move(pending_auth->callback);
    }
    pending_auth = pending_lan_auth{host,
                                    nonce,
                                    network::address_to_string(*local_endpoint),
                                    {},
                                    std::chrono::high_resolution_clock::now(),
                                    std::move(callback)};
  }

  if (replaced_callback) {
    replaced_callback(false);
  }
  network::send(host, "lanAuth", info.build(), '\n');
}

void connect_to_lobby(const game::ControllerIndex_t controllerIndex,
                      const game::net::netadr_t &addr,
                      const std::string &mapname, const std::string &gamemode,
                      const std::string &usermap_id,
                      const std::string &mod_id) {

  auth::clear_stored_guids();
  auth::clear_stored_challenge();
  workshop::setup_same_mod_as_host(
      game::com::Com_ControllerIndex_GetLocalClientNum(controllerIndex),
      usermap_id, mod_id, true);

  game::net::XSESSION_INFO info{};

  int32_t publicSlots = 0;
  for (game::LocalClientNum_t localClientIdx = game::LOCAL_CLIENT_0;
       localClientIdx < game::LOCAL_CLIENT_COUNT; localClientIdx++) {

    if (game::com::Com_LocalClient_IsBeingUsed(localClientIdx)) {

      publicSlots++;
    }
  }

  // publicSlots is entirely unused within CL_ConnectFromLobby, but just
  // for the sake of completeness, we will pass the correct value.
  game::cl::CL_ConnectFromLobby(controllerIndex, &info, &addr, publicSlots, 0,
                                mapname.data(), gamemode.data(),
                                usermap_id.data());
}

void launch_mode(const game::eModes mode) {
  scheduler::once(
      [=] {
        const game::LocalClientNum_t local_client = game::INVALID_LOCAL_CLIENT;
        const game::eModes current_mode = game::com::Com_SessionMode_GetMode();
        game::com::Com_SwitchMode(local_client, current_mode, mode, 6);
      },
      scheduler::main);
}

bool ensure_networkmode_online() {
  using namespace game;
  using namespace game::lobby;
  switch (com::Com_SessionMode_GetNetworkMode()) {
  case eNetworkModes::ONLINE:
  case eNetworkModes::SYSTEMLINK:
    switch (base::LobbyBase_GetNetworkMode()) {
    case LobbyNetworkMode::LAN:
    case LobbyNetworkMode::LIVE:
      return true;
    default:
      break;
    }
  default:
    break;
  }

  base::LobbyBase_SetNetworkMode(LobbyNetworkMode::LIVE);
  return false;
}

void connect_to_lobby_with_mode_internal(const game::net::netadr_t &addr,
                                         const game::eModes mode,
                                         const std::string &mapname,
                                         const std::string &gametype,
                                         const std::string &usermap_id,
                                         const std::string &mod_id,
                                         const bool was_retried = false) {

  const bool was_online = ensure_networkmode_online();
  if (was_online && game::com::Com_SessionMode_IsMode(mode)) {
    game::com::Com_SessionMode_SetGameMode(
        game::eGameModes::MATCHMAKING_PLAYLIST);

    connect_to_lobby(
        game::com::Com_LocalClient_GetControllerIndex(game::LOCAL_CLIENT_0),
        addr, mapname, gametype, usermap_id, mod_id);

    return;
  }

  if (!was_retried) {
    scheduler::once(
        [=] {
          connect_to_lobby_with_mode_internal(addr, mode, mapname, gametype,
                                              usermap_id, mod_id, true);
        },
        scheduler::main, 5s);

    launch_mode(mode);
  }
}

game::lobby::LobbyMainMode convert_mode(const game::eModes mode) {
  switch (mode) {
  case game::eModes::CAMPAIGN:
    return game::lobby::LobbyMainMode::CP;
  case game::eModes::MULTIPLAYER:
    return game::lobby::LobbyMainMode::MP;
  case game::eModes::ZOMBIES:
    return game::lobby::LobbyMainMode::ZM;
  default:
    return game::lobby::LobbyMainMode::INVALID;
  }
}

void connect_to_session(const game::net::netadr_t &addr,
                        const std::string &hostname, const uint64_t xuid,
                        const game::eModes mode, const bool requires_password,
                        const bool was_retried = false,
                        const bool authenticated = false) {
  if (mode != game::eModes::ZOMBIES || !lan::is_same_subnet(addr)) {
    toast::show("Connect failed", "Host is not on the local network",
                "t7_icon_connect_overlays");
    return;
  }

  if (!game::com::Com_SessionMode_IsMode(game::eModes::ZOMBIES)) {
    if (!was_retried) {
      scheduler::once(
          [=] {
            connect_to_session(addr, hostname, xuid, mode, requires_password,
                               true, authenticated);
          },
          scheduler::main, 5s);
      launch_mode(game::eModes::ZOMBIES);
    } else {
      toast::show("Connect failed", "Could not enter Zombies mode",
                  "t7_icon_connect_overlays");
    }
    return;
  }

  game::lobby::base::LobbyBase_SetNetworkMode(
      game::lobby::LobbyNetworkMode::LAN);

  if (requires_password && !authenticated) {
    authenticate_lan_peer(addr, [=](const bool success) {
      scheduler::once(
          [=] {
            if (!success) {
              toast::show("Connect failed",
                          "LAN password authentication failed",
                          "t7_icon_connect_overlays");
              return;
            }
            connect_to_session(addr, hostname, xuid, mode, true, was_retried,
                               true);
          },
          scheduler::main);
    });
    return;
  }

  authorize_lan_peer(addr);

  if (!game::lobby::session::LobbyJoin_Begin(0, game::CONTROLLER_INDEX_FIRST,
                                             game::lobby::LobbyType::PRIVATE,
                                             game::lobby::LobbyType::PRIVATE)) {
    toast::show("Connect failed", "Another lobby join is already in progress",
                "t7_icon_connect_overlays");
    return;
  }

  game::lobby::Join &join = *game::lobby::session::s_join;

  game::lobby::JoinHost &host = join.hostList[0];
  memset(&host, 0, sizeof(host));

  host.info.netAdr = addr;
  host.info.netAdr.type = game::net::NA_IP;
  host.info.xuid = xuid;
  utils::string::copy(host.info.name, hostname.data());

  host.lobbyType = game::lobby::LobbyType::PRIVATE;
  host.lobbyParams.networkMode = game::lobby::LobbyNetworkMode::LAN;
  host.lobbyParams.mainMode = convert_mode(mode);

  host.retryCount = 0;
  host.retryTime = game::sys::Sys_Milliseconds();

  join.hostCount = 1;
  join.processedCount = 0;

  if (!game::lobby::session::LobbyJoinSource_Finalize()) {
    toast::show("Connect failed", "Could not finalize the LAN lobby join",
                "t7_icon_connect_overlays");
  }
}

void handle_connect_query_response(const bool success,
                                   const game::net::netadr_t &target,
                                   const utils::info_string &info,
                                   uint32_t ping) {
  if (!success) {
    const std::string msg = utils::string::va(
        "No response from server %u.%u.%u.%u:%hu", target.ipv4.a, target.ipv4.b,
        target.ipv4.c, target.ipv4.d, target.port);
    printf("Connect failed: %s\n", msg.c_str());
    toast::show("Connect failed", "No response from server",
                "t7_icon_connect_overlays");
    return;
  }

  is_connecting_to_dedi = info.get("dedicated") == "1";
  update_dedi_dvar(is_connecting_to_dedi.load());

  {
    std::lock_guard lock(hostname_mutex);
    cached_server_hostname = info.get("hostname");
    const std::string max_clients_str = info.get("sv_maxclients");
    cached_server_max_clients =
        max_clients_str.empty() ? 0 : atoi(max_clients_str.data());
  }

  if (atoi(info.get("protocol").data()) != PROTOCOL) {
    const char *msg = "Invalid protocol.";
    printf("Connect failed: %s\n", msg);
    toast::show("Connect failed", msg, "t7_icon_connect_overlays");
    return;
  }

  const int32_t sub_protocol = atoi(info.get("sub_protocol").data());
  if (sub_protocol != SUB_PROTOCOL && sub_protocol != (SUB_PROTOCOL - 1)) {
    const char *msg = "Invalid sub-protocol.";
    printf("Connect failed: %s\n", msg);
    toast::show("Connect failed", msg, "t7_icon_connect_overlays");
    return;
  }

  const std::string gamename = info.get("gamename");
  if (gamename != "T7"s) {
    const char *msg = "Invalid gamename.";
    printf("Connect failed: %s\n", msg);
    toast::show("Connect failed", msg, "t7_icon_connect_overlays");
    return;
  }

  // The server validates the challenge-bound proof during authenticated
  // connect.
  const std::string net_password_required = info.get("net_password_required");
  if (net_password_required == "1") {
    if (info.get("net_password_scheme") != "1") {
      const char *msg = "Server uses an unsupported network password scheme.";
      printf("Connect failed: %s\n", msg);
      toast::show("Connect failed", msg, "t7_icon_connect_overlays");
      return;
    }

    if (!network_password::is_password_set()) {
      const char *msg = "Server requires a network password.";
      printf("Connect failed: %s\n", msg);
      toast::show("Connect failed", msg, "t7_icon_connect_overlays");
      return;
    }
  } else {
    // Compatibility with older boiii servers. This is not authoritative.
    const std::string server_net_hash = info.get("net_password_hash");
    if (!server_net_hash.empty() && server_net_hash != "0") {
      if (!network_password::is_password_set()) {
        const char *msg = "Server requires a network password.";
        printf("Connect failed: %s\n", msg);
        toast::show("Connect failed", msg, "t7_icon_connect_overlays");
        return;
      }

      if (network_password::get_password_hash_string() != server_net_hash) {
        const char *msg = "Network password mismatch.";
        printf("Connect failed: %s\n", msg);
        toast::show("Connect failed", msg, "t7_icon_connect_overlays");
        return;
      }
    }
  }

  if (net_password_required.empty() && info.get("net_password_hash").empty() &&
      network_password::is_password_set()) {
    printf("Client has network password set but server does not. Allowing "
           "connection.\n");
  }

  const std::string hostname = info.get("sv_hostname").empty()
                                   ? info.get("hostname")
                                   : info.get("sv_hostname");
  const std::string playmode = info.get("playmode");
  const game::eModes mode =
      static_cast<game::eModes>(std::atoi(playmode.data()));
  const game::XUID xuid = strtoull(info.get("xuid").data(), nullptr, 16);
  const std::string mapname = info.get("mapname");
  const std::string sv_running = info.get("sv_running");
  const std::string lobby_state = info.get("lobby_state");
  const bool is_pregame_host =
      (!is_connecting_to_dedi.load() &&
       (sv_running == "0" || lobby_state == "pregame" ||
        mapname == "core_frontend"));

  if (is_pregame_host) {
    if (mode != game::eModes::ZOMBIES || !lan::is_same_subnet(target)) {
      const char *msg = "Pre-game joins are limited to local Zombies lobbies.";
      printf("Connect failed: %s\n", msg);
      toast::show("Connect failed", msg, "t7_icon_connect_overlays");
      return;
    }

    scheduler::once(
        [=] {
          printf("Connecting to host pre-game party session at %s...\n",
                 network::address_to_string(target).c_str());
          connect_to_session(target, hostname, xuid, mode,
                             net_password_required == "1");
        },
        scheduler::main);
    return;
  }

  network::set_packet_protection(target, net_password_required == "1");

  if (mapname.empty() || mapname == "core_frontend") {
    const char *msg =
        mapname.empty() ? "Invalid map." : "Server is not in a playable lobby.";
    printf("Connect failed: %s\n", msg);
    toast::show("Connect failed", msg, "t7_icon_connect_overlays");
    return;
  }

  const std::string gametype = info.get("gametype");
  if (gametype.empty()) {
    const char *msg = "Invalid gametype.";
    printf("Connect failed: %s\n", msg);
    toast::show("Connect failed", msg, "t7_icon_connect_overlays");
    return;
  }

  const std::string mod_id = info.get("modId");

  const std::string workshop_id = info.get("workshop_id").empty()
                                      ? info.get("usermapId")
                                      : info.get("workshop_id");
  const std::string base_uri = info.get("sv_wwwBaseURL").empty()
                                   ? info.get("sv_wwwBaseUrl")
                                   : info.get("sv_wwwBaseURL");

  scheduler::once(
      [=] {
        const char *addr_str =
            utils::string::va("%i.%i.%i.%i:%hu", target.ipv4.a, target.ipv4.b,
                              target.ipv4.c, target.ipv4.d, target.port);

        // Always save latest address for mod reconnect (mod unload/reload)
        workshop::set_pending_mod_reconnect(addr_str);

        const std::string usermap_id =
            workshop::get_usermap_publisher_id(mapname);

        if (workshop::check_valid_usermap_id(mapname, usermap_id, workshop_id,
                                             base_uri) &&
            workshop::check_valid_mod_id(mod_id, workshop_id)) {
          connect_to_lobby_with_mode_internal(target, mode, mapname, gametype,
                                              usermap_id, mod_id);
        } else {
          const char *msg = utils::string::va(
              "Missing or invalid workshop/map dependencies for server %s.",
              addr_str);
          printf("Connect failed: %s\n", msg);
          toast::show("Connect failed", "Missing workshop/map dependencies",
                      "t7_icon_connect_overlays");
          // Save download reconnect
          workshop::set_pending_download_reconnect(addr_str);
        }
      },
      scheduler::main);
}

void connect_finish(const game::net::netadr_t &target, const char *address) {
  connect_host = target;

  profile_infos::clear_profile_infos();

  if (address) {
    std::string game_info = friends::get_friend_game_info_by_address(target);
    if (!game_info.empty()) {
      std::vector<std::string> parts = utils::string::split(game_info, '|');
      if (parts.size() >= 4) {
        std::string mapname = parts[1];
        std::string gametype = parts[2];
        game::eModes mode =
            static_cast<game::eModes>(std::atoi(parts[3].c_str()));
        std::string mod_id = parts.size() >= 5 ? parts[4] : "";

        if (!mapname.empty() && !gametype.empty()) {
          scheduler::once(
              [=]() {
                std::string usermap_id =
                    workshop::get_usermap_publisher_id(mapname);
                connect_to_lobby_with_mode_internal(
                    connect_host, mode, mapname, gametype, usermap_id, mod_id);
              },
              scheduler::pipeline::main);
          return;
        }
      }
    }
  }

  query_server(connect_host, handle_connect_query_response);
}

void connect_stub(const char *address) {
  if (address) {
    const std::string address_copy = normalize_connect_address(address);

    if (const auto friend_id = friends::find_browser_route(address_copy)) {
      if (!friends::connect_to_friend(friend_id))
        toast::show("Friend unavailable", "No joinable match was found",
                    "t7_icon_connect_overlays");
      return;
    }

    if (address_copy == "0.0.0.0" || address_copy.starts_with("0.0.0.0:")) {
      toast::show("Friend unavailable",
                  "Friend is offline or their party is closed",
                  "t7_icon_connect_overlays");
      return;
    }

    toast::show("Connecting", address_copy, "t7_icon_connect_overlays");

    network::resolvedAddrCallback_t resolveCb =
        [address_copy](game::net::netadr_t target) -> void {
      scheduler::once(
          [address_copy, target] {
            if (target.type == game::net::NA_BAD) {
              printf("Connect failed: invalid address \"%s\"\n",
                     address_copy.c_str());
              toast::show("Connect failed", "Invalid address",
                          "t7_icon_connect_overlays");
              return;
            }

            if (network::is_ip_address(target) &&
                (target.addr == 0 || target.port == 0)) {
              toast::show("Friend unavailable",
                          "Friend is offline or their party is closed",
                          "t7_icon_connect_overlays");
              return;
            }

            connect_finish(target, address_copy.c_str());
          },
          scheduler::main);
    };
    // Resolve the address on a background thread.
    network::address_from_string_async(address_copy, resolveCb);
  } else {
    connect_finish(connect_host, nullptr);
  }
}

void send_server_query(server_query &query) {
  network::set_packet_protection(query.host, false);
  query.sent = true;
  query.query_time = std::chrono::high_resolution_clock::now();
  query.challenge = utils::cryptography::random::get_challenge();

  network::send(query.host, "getInfo", query.challenge);
}

void handle_info_response(const game::net::netadr_t &target,
                          const network::data_view &data,
                          game::LocalClientNum_t clientNum) {

  bool found_query = false;
  server_query query{};

  const utils::info_string info{data};

  get_server_queries().access([&](std::vector<server_query> &server_queries) {
    for (std::vector<server_query>::iterator i = server_queries.begin();
         i != server_queries.end(); ++i) {
      if (i->host == target && i->challenge == info.get("challenge")) {
        found_query = true;
        query = std::move(*i);
        i = server_queries.erase(i);
        break;
      }
    }
  });

  if (found_query) {
    const std::chrono::nanoseconds ping =
        std::chrono::high_resolution_clock::now() - query.query_time;
    const std::chrono::milliseconds::rep ping_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(ping).count();

    query.callback(true, query.host, info, static_cast<uint32_t>(ping_ms));
  }

  lan_query_response_callback response_callback;
  uint32_t lan_ping = 0;
  {
    std::lock_guard lock(lan_query_mutex);
    // The random challenge correlates a discovery response with this scan, and
    // the source must be local. `systemlink_lan` is only diagnostic metadata:
    // native frontend state changes asynchronously and must not hide a local
    // Zombies pre-game lobby from the Server Browser.
    if (active_lan_query.active && lan::is_same_subnet(target) &&
        active_lan_query.challenge == info.get("challenge") &&
        info.get("gamename") == "T7" &&
        std::atoi(info.get("playmode").data()) ==
            static_cast<int>(game::eModes::ZOMBIES) &&
        active_lan_query.discovered.insert(target).second) {
      const auto elapsed = std::chrono::high_resolution_clock::now() -
                           active_lan_query.query_time;
      lan_ping = static_cast<uint32_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
              .count());
      response_callback = active_lan_query.response_callback;
    }
  }

  if (response_callback) {
    response_callback(target, info, lan_ping);
  }
}

void cleanup_queried_servers() {
  std::vector<server_query> removed_queries{};

  if (game::com::Com_IsRunningUILevel()) {
    get_server_queries().access([&](std::vector<server_query> &server_queries) {
      size_t sent_queries = 0;

      const std::chrono::high_resolution_clock::time_point now =
          std::chrono::high_resolution_clock::now();
      for (std::vector<server_query>::iterator i = server_queries.begin();
           i != server_queries.end();) {
        if (!i->sent) {
          if (++sent_queries < 40) {
            send_server_query(*i);
          }

          ++i;
          continue;
        }

        if ((now - i->query_time) < 1s) {
          ++i;
          continue;
        }

        removed_queries.emplace_back(std::move(*i));
        i = server_queries.erase(i);
      }
    });

    const utils::info_string empty{};
    for (const server_query &query : removed_queries) {
      query.callback(false, query.host, empty, 0);
    }
  }

  lan_query_complete_callback lan_complete;
  {
    std::lock_guard lock(lan_query_mutex);
    if (active_lan_query.active && std::chrono::high_resolution_clock::now() -
                                           active_lan_query.query_time >=
                                       2500ms) {
      active_lan_query.active = false;
      lan_complete = std::move(active_lan_query.complete_callback);
      active_lan_query.response_callback = {};
    }
  }

  if (lan_complete) {
    lan_complete();
  }

  lan_auth_callback expired_auth_callback;
  {
    std::lock_guard lock(lan_auth_mutex);
    const auto now = std::chrono::high_resolution_clock::now();
    std::erase_if(authorized_lan_peers, [now](const auto &authorization) {
      return authorization.second < now;
    });
    std::erase_if(incoming_auths, [now](const auto &authorization) {
      return now - authorization.second.started >= 1500ms;
    });
    if (pending_auth && now - pending_auth->started >= 1500ms) {
      expired_auth_callback = std::move(pending_auth->callback);
      pending_auth.reset();
    }
  }

  if (expired_auth_callback) {
    expired_auth_callback(false);
  }
}
} // namespace

void connect(const game::net::netadr_t &target) {
  connect_finish(target, nullptr);
}

void query_server(const game::net::netadr_t &host, query_callback callback) {
  server_query query{};
  query.sent = false;
  query.host = host;
  query.callback = std::move(callback);

  get_server_queries().access([&](std::vector<server_query> &server_queries) {
    server_queries.emplace_back(std::move(query));
  });
}

void query_lan_servers(lan_query_response_callback response_callback,
                       lan_query_complete_callback complete_callback) {
  std::vector<game::net::netadr_t> targets;
  constexpr uint16_t first_port = 27017;
  constexpr uint16_t port_count = 11;
  for (uint16_t port = first_port; port < first_port + port_count; ++port) {
    auto port_targets = lan::get_broadcast_targets(port);
    targets.insert(targets.end(), port_targets.begin(), port_targets.end());
  }
  const std::string challenge = utils::cryptography::random::get_challenge();
  lan_query_complete_callback complete_without_scan;
  uint64_t generation{};

  {
    std::lock_guard lock(lan_query_mutex);
    generation = ++active_lan_query.generation;
    active_lan_query.active = !targets.empty();
    active_lan_query.challenge = challenge;
    active_lan_query.query_time = std::chrono::high_resolution_clock::now();
    active_lan_query.discovered.clear();
    active_lan_query.response_callback = std::move(response_callback);
    active_lan_query.complete_callback = std::move(complete_callback);

    if (targets.empty()) {
      complete_without_scan = std::move(active_lan_query.complete_callback);
      active_lan_query.response_callback = {};
    }
  }

  if (complete_without_scan) {
    scheduler::once(
        [callback = std::move(complete_without_scan)] { callback(); },
        scheduler::async, 50ms);
    return;
  }

  // Steam's API contract returns the request handle before callbacks begin.
  // A synchronous localhost broadcast can beat that return and BO3 discards
  // the first ServerResponded notification. Defer the first probe and retry
  // to cover both that race and ordinary UDP loss.
  for (const auto delay : {50ms, 450ms, 900ms}) {
    scheduler::once(
        [generation, challenge, targets] {
          send_lan_query_probe(generation, challenge, targets);
        },
        scheduler::async, delay);
  }
}

void cancel_lan_query() {
  std::lock_guard lock(lan_query_mutex);
  ++active_lan_query.generation;
  active_lan_query.active = false;
  active_lan_query.discovered.clear();
  active_lan_query.response_callback = {};
  active_lan_query.complete_callback = {};
}

void connect_to_lobby_with_mode(const game::net::netadr_t &addr,
                                const game::eModes mode,
                                const std::string &mapname,
                                const std::string &gametype,
                                const std::string &usermap_id,
                                const std::string &mod_id) {
  connect_to_lobby_with_mode_internal(addr, mode, mapname, gametype, usermap_id,
                                      mod_id, false);
}

game::net::netadr_t
get_connected_server(game::LocalClientNum_t localClientNum) {
  return game::cl::CL_GetLocalClientConnection(localClientNum)->serverAddress;
}

game::net::netadr_t get_connect_host() { return connect_host; }

bool is_host(const game::net::netadr_t &addr) {
  return get_connected_server() == addr || connect_host == addr;
}

void join_session(const game::net::netadr_t &addr, const std::string &hostname,
                  const uint64_t xuid, const game::eModes mode) {
  connect_to_session(addr, hostname, xuid, mode, false);
}

bool is_lan_peer_authorized(const game::net::netadr_t &addr) {
  return is_lan_peer_authorized_internal(addr);
}

uint16_t get_local_port() { return game::port(); }

std::string get_server_hostname() {
  std::lock_guard lock(hostname_mutex);
  return cached_server_hostname;
}

int get_server_max_clients() {
  std::lock_guard lock(hostname_mutex);
  return cached_server_max_clients;
}

void clear_server_info() {
  std::lock_guard lock(hostname_mutex);
  cached_server_hostname.clear();
  cached_server_max_clients = 0;
}

struct component final : client_component {
  void post_unpack() override {
    cl_connected_to_dedi =
        game::register_dvar_bool("cl_connected_to_dedi", false, game::DVAR_NONE,
                                 "True when connected to a dedicated server");

    utils::hook::jump(0x141EE5FE0_g, &connect_stub);

    network::on("infoResponse", handle_info_response);
    network::on("lanAuth", handle_lan_auth_request);
    network::on("lanAuthChallenge", handle_lan_auth_challenge);
    network::on("lanAuthProof", handle_lan_auth_proof);
    network::on("lanAuthResponse", handle_lan_auth_response);

    scheduler::loop(cleanup_queried_servers, scheduler::async, 100ms);
  }

  void pre_destroy() override {
    get_server_queries().access([](std::vector<server_query> &s) { s = {}; });
    cancel_lan_query();
    std::lock_guard lock(lan_auth_mutex);
    pending_auth.reset();
    incoming_auths.clear();
    authorized_lan_peers.clear();
  }
};
} // namespace party

REGISTER_COMPONENT(party::component)
