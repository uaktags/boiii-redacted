# ext.dll / t7patch Security Patch Map

This document records the current reverse-engineering map between:

- the `ext.dll` loaded by boiii;
- security and compatibility code in the current boiii source tree; and
- the community `t7patch.dll` implementation.

The goal is to preserve enough intent and implementation detail to maintain or
reimplement the safety patches. Addresses refer to the binaries currently
annotated in the `T7Stuff` Ghidra project. Names in backticks are the names now
applied in Ghidra.

Do not assign CVE identifiers from this document alone. Several fixes address
known BO3/T7 exploit classes, but the exact public vulnerability identifier has
not yet been established for every patch.

## How boiii Loads ext.dll

`src/client/component/extension.cpp` treats `ext.dll` as another boiii
component:

| boiii lifecycle       | ext.dll export | ext.dll behavior                                              |
| --------------------- | -------------- | ------------------------------------------------------------- |
| component constructor | DLL load       | Load from `game::get_appdata_path() / "ext.dll"`              |
| `post_load()`         | `_1`           | Validate the host build and construct matching ext components |
| `post_unpack()`       | `_2`           | Invoke each constructed component's patch-install method      |
| `pre_destroy()`       | `_3`           | Component shutdown/cleanup                                    |

The local Ghidra target is the current v69 binary with two blocking
`MessageBoxA` calls replaced by NOPs. Those two local changes do not alter any
security-patch function documented below.

## ext.dll Architecture

### Component loader

RTTI identifies five registered component classes:

| Component                         | Registration                        | Construction                         | Patch installation                     |
| --------------------------------- | ----------------------------------- | ------------------------------------ | -------------------------------------- |
| `auth::component`                 | `register_auth_component`           | `auth_component_construct`           | `auth_component_post_unpack`           |
| `check::component`                | `register_check_component`          | `check_component_construct`          | Constructor-driven checks              |
| `scheduler::component`            | `register_scheduler_component`      | `scheduler_component_construct`      | `scheduler_component_post_unpack`      |
| anonymous `_component::component` | `register_anon_component`           | `anon_component_construct`           | `anon_component_post_unpack`           |
| `tls_descriptor::component`       | `register_tls_descriptor_component` | `tls_descriptor_component_construct` | `tls_descriptor_component_post_unpack` |

`component_register` appends a 0x48-byte installer record to the registry at
`0x180115a60`. `component_construct_filtered` is called by `_1` and constructs
the components selected for the current executable build.
`component_post_unpack_dispatch` is called by `_2` and invokes the patch method
on each constructed component.

### Supported builds

ext.dll selects game addresses by checking the host PE
`OptionalHeader.CheckSum`:

| Check                                        | Checksum    |
| -------------------------------------------- | ----------- |
| `is_supported_build_a`                       | `0x14c28b4` |
| `is_supported_build_b`                       | `0x888c368` |
| inline check in `anon_component_post_unpack` | `0x8880704` |

This explains why raw game offsets usually do not match the analyzed
`t7patch.dll`: the projects target different executable builds. The compiled
address-selection expressions are the same pattern produced by boiii's
`game::select(client_address, dedicated_address)` helper.

### Hook primitives

| Ghidra name                      | Purpose                                               |
| -------------------------------- | ----------------------------------------------------- |
| `get_host_base`                  | Cached base of the host game executable               |
| `hook_install`                   | Install a direct hook/detour                          |
| `hook_install_ex`                | Extended hook variant                                 |
| `patch_nop`                      | Replace a game range with NOPs                        |
| `patch_write_bytes`              | Copy replacement bytes to a game address              |
| `hook_asmjit_build`              | Generate a runtime stub with `utils::hook::assembler` |
| `scheduler_install_frame_detour` | MinHook-style scheduler frame detour setup            |

## Confirmed Security Patches

### Server-only command guard

**Purpose:** prevent remote clients from invoking privileged server commands.

| Binary      | Function                                       | Behavior                                                                                                   |
| ----------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| ext.dll     | `cmdguard_server_command_hook` (`0x18000cd74`) | Blocks `killserverpc`, `endgame`, `endround`, and `restart_level_zm`; local/host commands pass             |
| t7patch.dll | `cmdguard_server_command_hook` (`0x180012c9c`) | Same four-command list; additionally rejects `badspawn` and executes `tempBanClient %i` against the sender |

This is a high-confidence behavioral mapping. The code is independently
implemented, but the command list and control-flow purpose are the same.

ext.dll installs `cmdguard_dispatch_killserverpc` and
`cmdguard_dispatch_endgame` as trampolines. Each calls the common guard and only
forwards to the original game handler when the command is allowed.

t7patch's handler uses the script VM for forwarding. Its call at game-relative
`0x12e9a30` is canonically `game::scr::Scr_AddString` (`0x1412E9A30`) in
`src/client/game/symbols/scr/core.hpp`.

### TeamOps arbitrary-write guard

**Purpose:** prevent remote TeamOps input from selecting an out-of-range indexed
write.

ext.dll patches the exact game site `0x1401155D5` with a generated trampoline:

- `teamops_arbitrary_write_fix_codegen` emits the trampoline.
- `teamops_bounded_write_guard` permits only `index <= 0x14`.
- A valid index performs `*(uint32_t *)(base + index * 4 + 0x2e17b4) = value`.
- An invalid index returns without writing.

Current boiii source fixes the same site in
`src/client/component/dedicated_patches2.cpp` by NOPing the vulnerable
seven-byte inlined write. The source identifies it explicitly as the "TeamOps
arbitrary write fix". This was added in commit `30cf99ca` together with other
security patches.

No matching TeamOps implementation has yet been identified in the analyzed
t7patch.dll.

### Challenge/authentication hardening

ext.dll's `auth::component` replaces and augments the stock challenge flow:

| Function                           | Confirmed role/source anchor                                                                                                                    |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth_is_getchallenge`             | Runtime-built comparison against `getchallenge`                                                                                                 |
| `auth_is_getchallenge_response`    | Runtime-built comparison against `getChallengeResponse`                                                                                         |
| `auth_sv_auth_client_hook`         | Hooks dedicated `game::sv::SV_AuthClient` at `0x140475BB0`; generates a 32-character challenge, timestamps it, and sends `getChallengeResponse` |
| `auth_get_challenge_hook`          | Hooks `game::select(0x1412E15E0, 0x14016DDC0)`, the same `get_challenge` pair used by boiii `auth.cpp`                                          |
| `auth_send_challenge_request_hook` | Hooks inside `game::cl::CL_CheckForResend`; caches the destination address and calls `game::net::NET_OutOfBandPrint` at `0x142173710`           |
| `auth_asmjit_trampoline_codegen`   | Mid-function auth trampoline                                                                                                                    |

Current boiii source provides the intended higher-level protocol in
`src/client/component/auth.cpp`:

1. request a 32-byte challenge;
2. sign it with the client's ECC key;
3. send the public key, signature, profile information, and connect payload;
4. verify the signature server-side;
5. require the supplied XUID to equal the public-key hash; and
6. reject invalid player names before `SV_DirectConnect`.

`src/client/game/impl/cl/cl.cpp` also documents why `getchallenge` must be sent
once per server connection rather than once per local client: the stock server
stores challenges per IP, so a second local client's request can overwrite the
first client's challenge before signature verification.

The exact t7patch counterpart for this newer ECC/fragmented-connect flow has not
yet been identified.

### Client command and chat/follow sanitization

ext.dll's `cmdguard_chat_follow_filter` is installed inside the server client
command dispatcher:

- client build hook: `0x14193FC78`;
- dedicated build hook: `0x140295C95`;
- the dedicated address lies inside the function whose current boiii
  continuation is called at `0x140295C40` by `client_command.cpp`.

It recognizes or neutralizes:

- `mr`, `mrp`;
- `chat`, `say`, `say_team`; and
- `follownext`, `follownextalive`, `followprev`.

Rejected input is rewritten to `bad`. Current boiii separates this older
combined logic between `client_command.cpp` and `chat.cpp`.

This command list was not found in t7patch.dll and appears to be an ext/t7x
addition.

## t7patch-only Security Patches

### Native friends-only admission enforcement

T7Patch does not rely only on the LobbyVM Lua patch. Exported `SetFriendsOnly`
controls a native request filter:

- `lobby_validate_join_request` validates incoming lobby requests;
- requesters must use the expected Steam-style XUID namespace; and
- `friends_cache_contains_xuid` must find the requester in the platform friends
  set.

The friends cache is refreshed from the game's friends interface at most once
every 30 seconds. Non-friends are rejected before the normal join path
continues.

boiii now has two partial equivalents: `auth.cpp` checks authenticated XUIDs for
the custom connection path, and `ui_scripting.cpp` installs the guarded LobbyVM
chunk described below. The t7patch native request filter and its 30-second
friends-cache refresh behavior have not been reproduced in the native game-lobby
path. No equivalent enforcement was found in current ext.dll.

### Protocol-level network password

T7Patch's exported `SetNetworkPassword` updates a hash used directly by packet
serialization and validation:

- `network_password_write_marker` writes password-derived marker bytes;
- `network_password_validate_marker` validates those bytes;
- `network_password_mix_checksum` XORs the packet checksum with the low 16 bits
  of the password hash; and
- `network_password_validate_checksum` rejects packets without a matching
  password-mixed checksum.

`network_password_set_hash` retains the previous hash when the password is
changed. The validator accepts that previous hash for 1500 ms so packets that
were already in flight are not dropped during rotation.

Before the native replacement, boiii's `net_password` implementation computed an
unsalted FNV-1a hash, advertised it in getinfo, and compared it only in the
joining client's party preflight. A modified client could therefore bypass the
preflight, while T7Patch's packet path requires the password state. This was a
second confirmed T7Patch-only protection.

The native replacement now covers boiii's own connectionless protocol in
`network.cpp` and `network_password.cpp`:

- password state uses the same lowercase FNV-1a-64 hash and retains the previous
  hash for the 1500 ms rotation window;
- protected packets carry the two marker bytes after the command separator and a
  little-endian password-mixed checksum over the complete datagram;
- the fragmented `connect` path in `auth.cpp` (`send_fragmented_connect_packet`)
  now wraps each fragment in the same envelope via
  `network_password::protect_packet` when a password is set, closing the gap
  where fragmented connects previously bypassed the password; and
- discovery remains unprotected until `net_password_required=1` is received,
  after which the peer is protected. A local password-protected server requires
  the initial `connect` command to use the protected envelope.

This is deliberately implemented at boiii's connectionless boundary. The
game-native serializer/parser targets used by T7Patch (`base+0x1ef6a30`,
`base+0x1ef7990`, `base+0x21778e0`, and `base+0x2177980`) are separate from the
custom raw-socket path and are not claimed as covered by this implementation.

### LobbyVM JoinableCheck patch

`lobbyvm_install_joinablecheck_patch` (`0x180009a60`) injects an embedded Lua
chunk into the game's Lobby VM.

Canonical game symbol mapping from boiii:

- game-relative `0x157588d0` is `game::ui::lua::hks::s_lobbyLuaVM` at
  `0x1557588D0`;
- `lua_load_bridge`, `lua_pcall_bridge`, and `lua_reader_cb` compile and execute
  the chunk.

The chunk replaces `LobbyVM.JoinableCheck` to:

- preserve the original result for local requests;
- enforce `Dvar.party_maxplayers` and the actual available slot count;
- reject closed parties;
- reject non-friends from friends-only parties using XUID checks; and
- replace `LobbyVM.OnDisconnect` with a no-op.

No Lua payload or LobbyVM strings exist in ext.dll, so this patch is not part of
the current ext implementation.

boiii now installs an equivalent guarded chunk from
`src/client/component/ui_scripting.cpp` after `UI_CoD_LobbyUI_Init`. It executes
on `s_lobbyLuaVM`, uses the VM's `pcall`, and preserves the original
`JoinableCheck` result before applying the max-player, privacy, and friends-only
checks. This is client-only; the dedicated-server Lua VM is not present in the
current symbol map.

### Atomic unpatch and CFG support

`infra_thread_freeze_thaw_unload` (`0x18001f500`) suspends every thread in the
current process except the caller, clears `CONTEXT.Dr7`, applies unpatch/setup
operations, then resumes all threads.

`infra_cfg_dispatch_hook_install` (`0x1800162c4`) identifies known target
prologues and writes `_guard_check_icall` into a protected CFG dispatch slot
using `VirtualProtect`. This permits t7patch's indirect hooks to operate in a
CFG-instrumented game.

No direct equivalents have been identified in ext.dll's component code.

### Anti-cheat self-tests

`ac_self_test_1` and `ac_self_test_2` back the exported
`ANTICHEAT_TEST_FUNCTION` functions. They use sentinel `0x8f7fecc4` and enter an
`int 0x29` fast-fail path when validation detects tampering.

## Confirmed Compatibility and Infrastructure Behavior

These are important to client operation but are not currently classified as RCE
fixes.

### Scheduler

ext.dll uses three observed scheduler pipelines:

| Pipeline  | Caller                                                          |
| --------- | --------------------------------------------------------------- |
| 0, async  | `scheduler_thread_main` (thread name: `Faster Async Scheduler`) |
| 1, server | `scheduler_clear_vehicle_inputs_stub`                           |
| 2, frame  | `scheduler_frame_detour_stub`                                   |

The lineage matches `src/client/component/scheduler.cpp`, including the
`G_ClearVehicleInputs` hook. ext.dll's call site is six bytes away from the
current boiii source address, consistent with a source/build vintage change.

### TLS descriptor and Wine

`is_wine` checks `ntdll.dll!wine_get_version`.
`tls_descriptor_component_construct` skips native TLS setup under Wine. On
native Windows, `tls_descriptor_component_post_unpack` NOPs three game TLS or
platform validation sites. This is tagged `drm-bypass` and `wine-compat` in
Ghidra rather than `rce-fix`.

### Other anonymous-component patches

`anon_component_post_unpack` contains:

- a bot formatter redirect at exact call site `0x142249097`, also used by
  current boiii `bots.cpp` for `format_bot_string`;
- a command whitelist bypass in the same function region as current boiii
  `command.cpp`'s `update_whitelist_stub`;
- `qmemcpy` (`0x142C3D960` / `0x140AB6E50`): detoured to `safe_memcpy_clamped`
  to prevent negative length parameters from sign-extending to huge positive
  copies;
- `sv_client_command_sl` NOPs (`0x141964687` / `0x140297F0C` and `0x141964746` /
  `0x140298FD0`): suppresses `Com_Error` crashes on invalid argument counts and
  entity indexes;
- `cl_connectionless_packet_dispatch` NOP (`0x14134CF1D` / `0x14018ECD9`):
  disables the unauthenticated stock migration response path; and
- `cmd_menu_response` / `cmd_menu_response_cached` hooks (`0x14193FE2F` /
  `0x14193FE51` and `0x140295E60` / `0x140295E82`): filters dangerous menu
  responses (`badspawn`, `killserverpc`, `endgame`, `endround`,
  `restart_level_zm`).

All client-side anonymous patch sites are now natively implemented in boiii's
`src/client/component/security_compat.cpp` and active when `ext.dll` is not
loaded.

## Performance and FPS Behavior

The official T7Patch FAQ states that the patch fixes the BO3 FPS issue, but it
does not identify one implementation detail as the sole fix. The released source
and current binary establish the following comparison.

### Steam DLC query suppression

T7Patch replaces three entries in the game's Steam apps interface from
`protection_install` (`0x18003eca0`):

| Function                                                 | Behavior                                                                                             |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `steam_get_owns_content_cached` (`0x18002d7b0`)          | Calls ownership vtable entry 6 only on the first query for an app ID, then returns the cached result |
| `steam_get_owns_content2_cached` (`0x18002d930`)         | Calls ownership vtable entry 7 only on the first query for an app ID and shares the same cache       |
| `steam_get_dlc_download_progress_cached` (`0x18002cf60`) | Caches downloaded/total byte counts and refreshes them at most once every 300000 ms                  |

The ownership functions write a `now + 600000 ms` deadline to the source global
`check_dlc_next`, but no code reads that global. Ownership results are therefore
effectively cached for the life of the process, not ten minutes.

boiii already avoids this expensive Steam path more completely. Its custom
`ISteamApps` implementation in `src/client/steam/interfaces/apps.cpp`:

- computes campaign, multiplayer, and zombies installation state from three
  `std::filesystem::exists` calls cached in function-static values;
- answers both `BIsSubscribedApp` and `BIsDlcInstalled` locally; and
- returns zero/false from `GetDlcDownloadProgress` without calling Steam.

This covers the strongest source-level candidate for T7Patch's advertised FPS
fix. Copying T7Patch's additional DLC cache into boiii would not provide a new
optimization because boiii's replacement interface never reaches those Steam
calls.

### CPU affinity workaround

Both projects temporarily restrict startup execution to four logical CPUs and
restore affinity one second later:

- T7Patch uses `amd_affinity_workaround_step` (`0x180008d90`) through
  `amd_affinity_schedule_callback` (`0x18000a400`). It intersects cores 0-3 with
  the process's original allowed mask and restores the captured original mask.
- boiii uses `fix_amd_cpu_stuttering` in
  `src/client/component/client_patches.cpp`. It constructs a mask for cores 0-3
  without intersecting the current process mask, then restores the system mask
  rather than the original process mask.

The workaround itself is already present in boiii. T7Patch's preservation of the
original process mask is a concrete robustness improvement for systems where
affinity was restricted before launch.

### Process priority

`run_patching` (`0x1800153a4`) unconditionally calls
`SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)`. boiii
deliberately NOPs the stock game's process-priority modification at
`0x142334C98`, leaving the process at its inherited/default priority instead.
This is a genuine policy difference, but the available source does not prove
that above-normal priority is the primary FPS fix or that adopting it would be
beneficial on all systems.

### GPU and voice handling

The combined ZBR source contains a DirectX `GpuPreference=2` registry helper,
but it is guarded by `!IS_PATCH_ONLY`. The analyzed standalone T7Patch binary
contains neither the registry string nor that helper. boiii already provides
both vendor high-performance GPU exports in `src/client/std_include.cpp` and the
DirectX registry preference in `src/client/main.cpp`.

T7Patch sets `maxvoicepacketsperframe` to `0` during `run_patching`. boiii takes
the stronger compatibility approach of disabling the stock voice packet path and
microphone access, so this is not a missing boiii performance feature.

## Ghidra Tags

The current Ghidra programs use these tags for navigation:

- `rce-fix`, `cve-candidate`;
- `cmdguard`, `auth`, `teamops`, `chat`;
- `component`, `infra`, `hook-engine`, `asmjit`;
- `scheduler`, `thread`, `build-check`;
- `performance`, `steam`, `cache`, `compatibility`, `patch-installer`;
- `lobby`, `lua`, `lua-bridge`;
- `drm-bypass`, `wine-compat`; and
- `anticheat`.

## Standalone Client Parity Status

All critical security, compatibility, and performance fixes reverse-engineered
from `ext.dll` and `t7patch.dll` are now natively implemented within `boiii`'s
C++ codebase. The client runs completely standalone without requiring `ext.dll`
or `t7patch.dll` to be present.

- **`security_compat.cpp`**: Native replacements for `qmemcpy` length clamping,
  `sl` command handling, migration response NOPs, and menu response filtering
  when `ext.dll` is missing.
- **`client_command.cpp` & `cmdguard.cpp`**: Server-only command guards
  (`killserverpc`, `endgame`, `endround`, `restart_level_zm`).
- **`dedicated_patches2.cpp`**: TeamOps arbitrary write fix.
- **`auth.cpp`**: ECC challenge/connect flow, server-side signature
  verification, and password-envelope wrapping of fragmented `connect` packets.
- **`network.cpp` & `network_password.cpp`**: FNV-1a network password
  marker/checksum protection with rotation window, a null guard on the password
  dvar, and a host-scoped passthrough for protected `error` replies.
- **`ui_scripting.cpp`**: LobbyVM JoinableCheck HKS patch.
- **`apps.cpp`**: Custom `ISteamApps` implementation replacing Steam DLC calls.

## Remaining Work & Dedicated Server Verification

1. Dedicated Server Executable (`BlackOps3_UnrankedDedicatedServer.exe`) is now
   available in `/home/tim/t7_full_game/`. Symbol relocations for dedicated mode
   are handled via `boiii`'s `_g` runtime relocator in `client_command.cpp`
   (`0x14052F81B_g`) and `dedicated_patches.cpp`.
2. Identify the t7patch implementation, if any, corresponding to ext.dll's
   challenge/ECC flow.
3. Establish exact public exploit/CVE names only after matching each behavior to
   an authoritative advisory or upstream patch description.
4. Continue annotating t7patch's procedural patch installers and map their game
   symbols through `src/client/game/symbols`.
