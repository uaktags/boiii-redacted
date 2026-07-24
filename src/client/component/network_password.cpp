#include <std_include.hpp>
#include <loader/component_loader.hpp>
#include <game/game.hpp>
#include <game/utils.hpp>

#include "network_password.hpp"
#include "hash.hpp"
#include "scheduler.hpp"

#include <utils/cryptography.hpp>
#include <utils/hook.hpp>
#include <utils/string.hpp>

#include <mutex>

namespace network_password {
namespace {
game::EngineDependentDvar net_password_dvar;

struct password_snapshot {
  uint64_t current{};
  uint64_t previous{};
  uint64_t changed_at{};
  bool set{};
};

std::mutex password_state_mutex;
password_snapshot password_state{};

std::string get_password() {
  return std::string(net_password_dvar.get_string().value_or(""));
}

std::string build_proof_payload(const std::string_view challenge,
                                const std::string_view public_key,
                                const std::string_view connect_data) {
  std::string payload{"boiii-net-password-v1"};

  const auto append_field = [&payload](const std::string_view field) {
    const auto size = static_cast<uint32_t>(field.size());
    payload.append(reinterpret_cast<const char *>(&size), sizeof(size));
    payload.append(field);
  };

  append_field(challenge);
  append_field(public_key);
  append_field(connect_data);
  return payload;
}

bool constant_time_equal(const std::string_view left,
                         const std::string_view right) {
  if (left.size() != right.size()) {
    return false;
  }

  uint8_t difference = 0;
  for (size_t i = 0; i < left.size(); ++i) {
    difference |= static_cast<uint8_t>(left[i]) ^
                  static_cast<uint8_t>(right[i]);
  }

  return difference == 0;
}

password_snapshot get_password_snapshot() {
  const std::string password = get_password();
  const uint64_t hash = password.empty() ? 0 : hash_password(password);

  std::lock_guard lock(password_state_mutex);
  if (password_state.current != hash) {
    password_state.previous = password_state.current;
    password_state.current = hash;
    password_state.changed_at = GetTickCount64();
  }

  password_state.set = !password.empty();
  return password_state;
}
}

std::string get_password_hash_string() {
  // Retained only for connecting to older servers that advertise this hash.
  const password_snapshot snapshot = get_password_snapshot();
  if (!snapshot.set) {
    return "0";
  }

  return utils::string::va("%llu", snapshot.current);
}

bool is_password_set() {
  return get_password_snapshot().set;
}

uint64_t current_hash() { return get_password_snapshot().current; }

size_t marker_size() {
  const password_snapshot snapshot = get_password_snapshot();
  return ((snapshot.current >> 16) & 0xFFU) != 0 ? 2 : 0;
}

std::string protect_packet(const std::string_view packet,
                           const size_t marker_offset) {
  const password_snapshot snapshot = get_password_snapshot();
  if (!snapshot.set) {
    return std::string(packet);
  }

  std::string protected_packet(packet);
  const uint8_t marker = static_cast<uint8_t>(snapshot.current >> 16);
  if (marker != 0) {
    if (marker_offset > protected_packet.size()) {
      return {};
    }

    protected_packet.insert(marker_offset, 1,
                            static_cast<char>(marker));
    protected_packet.insert(marker_offset + 1, 1,
                            static_cast<char>(snapshot.current >> 24));
  }

  const uint16_t checksum = static_cast<uint16_t>(
      calculate_checksum(reinterpret_cast<const uint8_t *>(protected_packet.data()),
                         protected_packet.size()) ^
      static_cast<uint16_t>(snapshot.current));
  protected_packet.push_back(static_cast<char>(checksum & 0xFF));
  protected_packet.push_back(static_cast<char>(checksum >> 8));
  return protected_packet;
}

bool validate_packet(const uint8_t *packet, const size_t length,
                     const size_t marker_offset, size_t &payload_length) {
  const password_snapshot snapshot = get_password_snapshot();
  if (!snapshot.set || packet == nullptr || length < 2) {
    return false;
  }

  payload_length = length - 2;
  const uint16_t received = static_cast<uint16_t>(packet[payload_length]) |
                            static_cast<uint16_t>(packet[payload_length + 1])
                                << 8;
  const uint16_t checksum = calculate_checksum(packet, payload_length);
  const uint16_t current_checksum =
      static_cast<uint16_t>(checksum ^ static_cast<uint16_t>(snapshot.current));

  bool valid = received == current_checksum;
  if (!valid && GetTickCount64() <= snapshot.changed_at + 1500) {
    const uint16_t previous_checksum = static_cast<uint16_t>(
        checksum ^ static_cast<uint16_t>(snapshot.previous));
    valid = received == previous_checksum;
  }

  if (!valid) {
    return false;
  }

  if (((snapshot.current >> 16) & 0xFFU) == 0) {
    return true;
  }

  if (marker_offset > payload_length || payload_length - marker_offset < 2 ||
      packet[marker_offset] != static_cast<uint8_t>(snapshot.current >> 16) ||
      packet[marker_offset + 1] !=
          static_cast<uint8_t>(snapshot.current >> 24)) {
    return false;
  }

  return true;
}

std::string create_connect_proof(const std::string_view challenge,
                                 const std::string_view public_key,
                                 const std::string_view connect_data) {
  const std::string password = get_password();
  if (password.empty()) {
    return {};
  }

  return utils::cryptography::hmac_sha1::compute(
      build_proof_payload(challenge, public_key, connect_data), password);
}

bool verify_connect_proof(const std::string_view proof,
                          const std::string_view challenge,
                          const std::string_view public_key,
                          const std::string_view connect_data) {
  if (!is_password_set()) {
    return true;
  }

  const std::string expected =
      create_connect_proof(challenge, public_key, connect_data);
  return constant_time_equal(proof, expected);
}

struct component final : generic_component {
  void post_unpack() override {
    scheduler::once(
        [] {
          net_password_dvar = game::register_dvar_string(
              "net_password", "", game::DVAR_NONE,
              "Network password for private server isolation");
        },
        scheduler::pipeline::main);
  }
};
} // namespace network_password

REGISTER_COMPONENT(network_password::component)
