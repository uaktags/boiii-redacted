#include <std_include.hpp>
#include "fragment_handler.hpp"

namespace game::fragment_handler {
namespace {
constexpr size_t MAX_FRAGMENTS = 100;
constexpr size_t MAX_FRAGMENT_SIZE = 0x400;
constexpr size_t MAX_PACKET_SIZE = MAX_FRAGMENTS * MAX_FRAGMENT_SIZE;

using fragments = std::unordered_map<size_t, std::string>;

struct fragmented_packet {
  size_t fragment_count{0};
  fragments fragments{};
  std::chrono::high_resolution_clock::time_point insertion_time =
      std::chrono::high_resolution_clock::now();
};

using id_fragment_map = std::unordered_map<uint64_t, fragmented_packet>;
using address_fragment_map = std::unordered_map<net::netadr_t, id_fragment_map>;

utils::concurrency::container<address_fragment_map> global_map{};

std::vector<std::string> construct_fragments(const void *data,
                                             const size_t length) {
  std::vector<std::string> fragments{};

  for (size_t i = 0; i < length; i += MAX_FRAGMENT_SIZE) {
    const auto current_fragment_size =
        std::min(length - i, MAX_FRAGMENT_SIZE);

    std::string fragment(static_cast<const char *>(data) + i,
                         current_fragment_size);
    fragments.push_back(std::move(fragment));
  }

  return fragments;
}
} // namespace

bool handle(const net::netadr_t &target, utils::byte_buffer &buffer,
            std::string &final_packet) {
  try {
    const auto fragment_id = buffer.read<uint64_t>();
    const size_t fragment_count = buffer.read<uint32_t>();
    const size_t fragment_index = buffer.read<uint32_t>();
    auto fragment_data = buffer.get_remaining_data();

    if (fragment_index >= fragment_count || !fragment_count ||
        fragment_count > MAX_FRAGMENTS ||
        fragment_data.size() > MAX_FRAGMENT_SIZE) {
      return false;
    }

    return global_map.access<bool>([&](address_fragment_map &map) {
      auto map_entry = map.try_emplace(target).first;
      auto &user_map = map_entry->second;
      if (!user_map.contains(fragment_id) &&
          user_map.size() >= MAX_FRAGMENTS) {
        return false;
      }

      auto queue_entry = user_map.try_emplace(fragment_id).first;
      auto &packet_queue = queue_entry->second;
      if (packet_queue.fragment_count == 0) {
        packet_queue.fragment_count = fragment_count;
      }

      if (packet_queue.fragment_count != fragment_count ||
          packet_queue.fragments.contains(fragment_index)) {
        return false;
      }

      packet_queue.fragments.emplace(fragment_index, std::move(fragment_data));
      if (packet_queue.fragments.size() != fragment_count) {
        return false;
      }

      size_t packet_size = 0;
      for (size_t i = 0; i < fragment_count; ++i) {
        const auto fragment = packet_queue.fragments.find(i);
        if (fragment == packet_queue.fragments.end() ||
            fragment->second.size() > MAX_PACKET_SIZE - packet_size) {
          return false;
        }
        packet_size += fragment->second.size();
      }

      final_packet.clear();
      final_packet.reserve(packet_size);
      for (size_t i = 0; i < fragment_count; ++i) {
        final_packet.append(packet_queue.fragments.at(i));
      }

      user_map.erase(queue_entry);
      if (user_map.empty()) {
        map.erase(map_entry);
      }
      return true;
    });
  } catch (const std::exception &) {
    return false;
  }
}

void clean() {
  global_map.access([](address_fragment_map &map) {
    for (auto i = map.begin(); i != map.end();) {
      auto &user_map = i->second;

      for (auto j = user_map.begin(); j != user_map.end();) {
        const auto now = std::chrono::high_resolution_clock::now();
        const auto diff = now - j->second.insertion_time;

        if (diff > 5s) {
          j = user_map.erase(j);
        } else {
          ++j;
        }
      }

      if (user_map.empty()) {
        i = map.erase(i);
      } else {
        ++i;
      }
    }
  });
}

void fragment_data(
    const void *data, const size_t size,
    const std::function<void(const utils::byte_buffer &buffer)> &callback) {
  static std::atomic_uint64_t current_id{0};
  const auto id = current_id++;

  const auto fragments = construct_fragments(data, size);

  for (size_t i = 0; i < fragments.size(); ++i) {
    utils::byte_buffer buffer{};
    buffer.write(id);
    buffer.write(static_cast<uint32_t>(fragments.size()));
    buffer.write(static_cast<uint32_t>(i));

    auto &fragment = fragments.at(i);
    buffer.write(fragment.data(), fragment.size());

    callback(buffer);
  }
}
} // namespace game::fragment_handler
