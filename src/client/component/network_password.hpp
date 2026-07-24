#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace network_password {
constexpr uint64_t hash_password(const std::string_view password) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (const unsigned char character : password) {
    const unsigned char lower =
        character >= 'A' && character <= 'Z' ? character + ('a' - 'A')
                                             : character;
    hash ^= static_cast<uint64_t>(lower);
    hash *= 0x100000001b3ULL;
  }

  return hash & 0x7FFFFFFFFFFFFFFFULL;
}

static_assert(hash_password("Password") == 0x4B1A493507B3A318ULL);

std::string get_password_hash_string();
bool is_password_set();

uint64_t current_hash();
constexpr uint16_t calculate_checksum(const uint8_t *data,
                                      const size_t length) {
  uint32_t checksum = 0;
  size_t offset = 0;

  while (offset + 1 < length) {
    checksum += static_cast<uint32_t>(data[offset] << 8 | data[offset + 1]);
    offset += 2;
  }

  if (offset < length) {
    checksum += data[offset];
  }

  while ((checksum >> 16) != 0) {
    checksum = (checksum & 0xFFFFU) + (checksum >> 16);
  }

  return static_cast<uint16_t>(~checksum);
}

static_assert([] {
  constexpr uint8_t data[] = {'a', 'b', 'c'};
  return calculate_checksum(data, sizeof(data)) == 0x9E3A;
}());

// Protects a connectionless packet by inserting the password marker at the
// command payload boundary and appending the password-mixed checksum.
std::string protect_packet(std::string_view packet, size_t marker_offset);

// Validates a protected packet and returns its length without the checksum.
bool validate_packet(const uint8_t *packet, size_t length, size_t marker_offset,
                    size_t &payload_length);
size_t marker_size();

std::string create_connect_proof(std::string_view challenge,
                                 std::string_view public_key,
                                 std::string_view connect_data);
bool verify_connect_proof(std::string_view proof, std::string_view challenge,
                          std::string_view public_key,
                          std::string_view connect_data);
} // namespace network_password
