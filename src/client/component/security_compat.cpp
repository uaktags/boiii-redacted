#include <std_include.hpp>
#include <loader/component_loader.hpp>

#include <game/game.hpp>

#include <utils/hook.hpp>
#include <utils/string.hpp>

#include "command.hpp"

namespace security_compat {
namespace {
utils::hook::detour qmemcpy_hook;

constexpr const char *blocked_menu_responses[] = {
    "killserverpc", "endgame", "endround", "restart_level_zm"};

void *qmemcpy_safe(void *destination, const void *source, const int32_t size) {
  if (size < 0) {
    return destination;
  }

  return qmemcpy_hook.invoke<void *>(destination, source, size);
}

bool is_menu_response_allowed(const int *entity, const bool cached) {
  const command::params_sv params;
  if (params.size() != 4) {
    return false;
  }

  std::string response = params[3];
  if (cached) {
    const auto get_event_name = reinterpret_cast<const char *(*)(int, int)>(
        game::select(0x1400A78A0, 0x140044070));
    const char *event_name = get_event_name(0, atoi(response.c_str()));
    response = event_name ? event_name : "";
  }

  if (utils::string::to_lower(response) == "badspawn") {
    return false;
  }

  if (*entity == 0) {
    return true;
  }

  const std::string normalized = utils::string::to_lower(response);
  return std::ranges::none_of(blocked_menu_responses,
                              [&normalized](const char *blocked) {
                                return normalized == blocked;
                              });
}

void menu_response_safe(int *entity) {
  if (is_menu_response_allowed(entity, false)) {
    utils::hook::invoke<void>(game::select(0x14195F0E0, 0x140297AB0),
                              entity);
  }
}

void menu_response_cached_safe(int *entity) {
  if (is_menu_response_allowed(entity, true)) {
    utils::hook::invoke<void>(game::select(0x14195EF80, 0x140297950), entity);
  }
}
} // namespace

struct component final : generic_component {
  void post_unpack() override {
    if (GetModuleHandleA("ext.dll") != nullptr) {
      return;
    }

    qmemcpy_hook.create(game::select(0x142C3D960, 0x140AB6E50), qmemcpy_safe);

    // Ignore malformed remote `sl` commands instead of terminating via
    // Com_Error for an invalid argument count or entity index.
    utils::hook::nop(game::select(0x141964687, 0x140297F0C), 5);
    utils::hook::nop(game::select(0x141964746, 0x140298FD0), 5);

    // Disable the stock migration response path; boiii uses its authenticated
    // challenge/connect flow instead.
    utils::hook::nop(game::select(0x14134CF1D, 0x14018ECD9), 6);

    utils::hook::call(game::select(0x14193FE2F, 0x140295E60),
                      menu_response_safe);
    utils::hook::call(game::select(0x14193FE51, 0x140295E82),
                      menu_response_cached_safe);
  }
};
} // namespace security_compat

REGISTER_COMPONENT(security_compat::component)
