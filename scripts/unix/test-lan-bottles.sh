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
    "${common_args[@]}" "$@" +set net_port "${port}" +name "${player_name}" \
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

launched_pid=""
launch_client "${host_bottle}" 27017 LAN-Host "${log_dir}/host.log"
host_pid="${launched_pid}"
echo "Host launch started (PID ${host_pid}); waiting for engine initialization..."
wait_for_udp_port "${host_pid}" 27017 "${log_dir}/host.log"
echo "Host UDP 27017 is ready; starting the guest..."
sleep 5

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
