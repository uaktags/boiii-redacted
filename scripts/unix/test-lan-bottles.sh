#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
game_dir="${BOIII_GAME_DIR:-/home/tim/t7_full_game}"
host_bottle="${BOIII_HOST_BOTTLE:-Boiii}"
guest_bottle="${BOIII_GUEST_BOTTLE:-Boiii-Guest}"
lan_password="${BOIII_LAN_PASSWORD:-}"
ready_timeout="${BOIII_LAN_READY_TIMEOUT:-240}"
release_binary="${repo_root}/build/bin/x64/Release/boiii.exe"
test_binary="${game_dir}/boiii-lan-test.exe"
bottles_prefixes="${BOIII_BOTTLES_PREFIXES:-${HOME}/.var/app/com.usebottles.bottles/data/bottles/bottles}"

if ! [[ "${ready_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  echo "BOIII_LAN_READY_TIMEOUT must be a positive integer (seconds)." >&2
  exit 1
fi

if [[ ! -f "${release_binary}" ]]; then
  echo "Missing ${release_binary}; run ./scripts/unix/cross.sh --release first." >&2
  exit 1
fi

if [[ ! -f "${game_dir}/BlackOps3.exe" ]]; then
  echo "BlackOps3.exe was not found in ${game_dir}." >&2
  exit 1
fi

if ! command -v flatpak >/dev/null 2>&1; then
  echo "flatpak is required to launch the two Bottles prefixes." >&2
  exit 1
fi

if ! command -v ss >/dev/null 2>&1; then
  echo "ss is required to detect when each game socket is ready." >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required by the Bottles test harness." >&2
  exit 1
fi

bottle_list="$(flatpak run --command=bottles-cli com.usebottles.bottles list bottles 2>&1)"
for bottle in "${host_bottle}" "${guest_bottle}"; do
  if ! rg -Fq -- "- ${bottle}" <<<"${bottle_list}"; then
    echo "Bottles prefix '${bottle}' is missing." >&2
    exit 1
  fi
done

if [[ ! -f "${test_binary}" ]] || ! cmp -s "${release_binary}" "${test_binary}"; then
  install -m 0644 "${release_binary}" "${test_binary}"
fi
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/boiii-lan-bottles.XXXXXX")"
echo "Logs: ${log_dir}"

common_args=(
  -launch
  -noupdate
  -nointro
  -nosteam
  -windowed
  -lan-local-test
  -filelogs
  -lan-trace
  +set r_fullscreen 0
)

if [[ -n "${lan_password}" ]]; then
  common_args+=(
    -lan-test-password "${lan_password}"
  )
fi

launch_client() {
  local bottle="$1"
  local port="$2"
  local player_name="$3"
  local log_file="$4"
  shift 4

  flatpak run --command=bottles-cli com.usebottles.bottles run \
    -b "${bottle}" -e "${test_binary}" --args-replace -- \
    "${common_args[@]}" "$@" +set net_port "${port}" +set name "${player_name}" \
    >"${log_file}" 2>&1 &
  launched_pid="$!"
}

wait_for_udp_port() {
  local launcher_pid="$1"
  local port="$2"
  local log_file="$3"
  local elapsed=0
  local timeout="${ready_timeout}"

  while (( elapsed < timeout )); do
    if ss -H -lun "sport = :${port}" | rg -Fq -- ":${port}"; then
      return 0
    fi

    if ! kill -0 "${launcher_pid}" 2>/dev/null; then
      echo "The launcher exited before UDP ${port} was ready. See ${log_file}" >&2
      return 1
    fi

    sleep 2
    ((elapsed += 2))
  done

  echo "Timed out waiting for UDP ${port}. See ${log_file}" >&2
  return 1
}

console_log_paths() {
  local bottle="$1"
  shopt -s nullglob
  printf '%s\n' \
    "${bottles_prefixes}/${bottle}/drive_c/users/"*"/AppData/Local/boiii/logs/boiii_console.log"
  shopt -u nullglob
}

truncate_console_logs() {
  local src
  while IFS= read -r src; do
    [[ -f "${src}" ]] || continue
    : > "${src}"
  done < <(console_log_paths "${host_bottle}"; console_log_paths "${guest_bottle}")
}

wait_for_host_frontend() {
  local log_file="$1"
  local elapsed=0

  # DXVK recreates the swapchain ("Buffer size:") as the host's frontend settles
  # on its real resolution. A process stuck in shader warm-up only ever presents
  # the single 800x600 startup window, which is the documented two-instance
  # black-window hazard. Wait until a non-startup size appears so the guest's
  # warm-up does not collide with a still-loading host. The host *can* be ready
  # at 800x600 (windowed PRIVATE GAME) even when DXVK never resizes, so also
  # accept the boiii frontend asset as loaded as a readiness signal.
  while (( elapsed < ready_timeout )); do
    if rg -N 'Buffer size:' "${log_file}" | rg -qv '800x600'; then
      return 0
    fi

    # Fallback: frontend fastfiles loaded => host is at menu even at 800x600.
    # Pick the non-empty console log among the Wine users (steamuser is empty).
    local console_log
    console_log=""
    while IFS= read -r console_log_candidate; do
      [[ -s "${console_log_candidate}" ]] || continue
      console_log="${console_log_candidate}"
      break
    done < <(console_log_paths "${host_bottle}")
    if [[ -n "${console_log}" ]] && rg -q "XZONE_LOADED.*core_frontend" "${console_log}" 2>/dev/null; then
      # Give the frontend a moment to settle after the fastfile.
      sleep 3
      return 0
    fi

    if ! kill -0 "${host_pid}" 2>/dev/null; then
      echo "The host exited before its frontend finished loading. See ${log_file}" >&2
      return 1
    fi

    sleep 2
    ((elapsed += 2))
  done

  echo "Host has not rendered past the 800x600 startup window after ${ready_timeout}s." >&2
  echo "It may still be in DXVK warm-up; starting the guest now risks a frozen host." >&2
}

copy_console_logs() {
  local bottle src dest
  for bottle in "${host_bottle}" "${guest_bottle}"; do
    while IFS= read -r src; do
      [[ -s "${src}" ]] || continue
      dest="${log_dir}/${bottle,,}-console.log"
      cp -f "${src}" "${dest}"
      echo "Copied ${bottle} console log to ${dest}"
    done < <(console_log_paths "${bottle}")
  done
}

launched_pid=""
truncate_console_logs
launch_client "${host_bottle}" 27017 LAN-Host "${log_dir}/host.log"
host_pid="${launched_pid}"
echo "Host launch started (PID ${host_pid}); waiting for engine initialization..."
wait_for_udp_port "${host_pid}" 27017 "${log_dir}/host.log"
echo "Host UDP 27017 is ready; waiting for the frontend to finish loading..."
wait_for_host_frontend "${log_dir}/host.log"
echo "Host frontend is ready; starting the guest..."

launch_client "${guest_bottle}" 27018 LAN-Guest "${log_dir}/guest.log" \
  -lan-test-guest
guest_pid="${launched_pid}"

echo "Guest launch started (PID ${guest_pid}); waiting for engine initialization..."
wait_for_udp_port "${guest_pid}" 27018 "${log_dir}/guest.log"
echo "Guest UDP 27018 is ready."
if [[ -n "${lan_password}" ]]; then
  echo "Password for both instances: ${lan_password}"
else
  echo "Password protection: disabled for the baseline LAN test"
fi
echo
echo "Host window: Zombies -> Local -> create a private lobby."
echo "Guest window: Zombies -> Local -> Server Browser -> LAN, then join the host row."
echo "Close both game windows normally when the test is complete."
echo "This harness will remain attached until both Bottles launchers exit."

wait "${host_pid}" "${guest_pid}"
copy_console_logs
