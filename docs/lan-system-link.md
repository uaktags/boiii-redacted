# Zombies System Link LAN Lobbies

## Implemented Scope

The built-in LAN browser now discovers and joins player-hosted Zombies System
Link sessions without requiring `/connect <ip>:27017`. Version one is
deliberately limited to private RFC1918 subnets on active physical Ethernet or
Wi-Fi adapters. Internet, VPN/tunnel, public-match, theater, migration, P2P,
voice, and demo traffic are outside this path.

The old standalone LAN daemon was removed. It could advertise a synthetic
server, but it could not reproduce the game's lobby membership, readiness, or
launch state. The game host is now the source of truth for all of those states.

## Discovery and Join Flow

1. `RequestLANServerList` starts a cancellable 1.5-second scan and clears the
   previous LAN rows.
2. `lan.cpp` enumerates active Ethernet and Wi-Fi IPv4 addresses with
   `GetAdaptersAddresses`. Only RFC1918 addresses with usable prefix lengths
   are retained.
3. The client sends a challenge-bearing `getInfo` request to each interface's
   directed broadcast address on UDP 27017. It never uses the global
   `255.255.255.255` broadcast.
4. `party.cpp` accepts a response only when the challenge matches, the source is
   on one of the retained local subnets, `gamename` is `T7`, and `playmode` is
   Zombies. `systemlink_lan` remains advertised for diagnostics but is not a
   listing gate: native frontend flags can lag the pre-game lobby state.
   Endpoints are deduplicated.
5. Each valid response becomes a normal Steam LAN browser row. Refresh,
   cancellation, release, details, count, and per-row refresh are implemented
   with generation checks so stale callbacks cannot update a newer request.
6. Selecting a pre-game listen host (`lobby_state=pregame`, `sv_running=0`, or
   `mapname=core_frontend`) no longer falls through to the active-match path.
   BO3 can report `server_running=1` while its private lobby is still on
   `core_frontend`, so the frontend map is an explicit pre-game signal. The
   client enters Zombies and LAN network mode, calls the
   native `LobbyJoin_Begin`, fills `hostList[0]`, leaves `processedCount=0`, and
   calls the native finalize routine. The game's join state machine then owns
   association, membership, readiness, and synchronized launch.
7. Active matches continue through the existing map/game connection path.

Ghidra validation against `boiii.exe` established that `0x141ED94D0` wraps the
native join-begin routine and `0x141ED94F0` wraps join-source finalization. The
`CONNECT_TO_NEXT_HOST` handler copies `hostList[processedCount]` into
`potentialHost`, increments `processedCount`, and starts association. This is
why the implementation does not manually force `ASSOCIATING` as the earlier
prototype did.

## Security Boundary

Remote native lobby packets remain disabled by default. A packet reaches the
game handler only when all of these conditions are true:

- this is the client/listen-host binary, not the dedicated server;
- the lobby type is private or game;
- the process is in Zombies, `SYSTEMLINK`, and LobbyBase `LAN` mode;
- the source is a different RFC1918 address on a retained physical subnet;
- the unread payload is at most `0x2000` bytes and has valid message bounds;
- the native lobby reader accepts the message; and
- its type is on the private-lobby allowlist.

The allowlist covers info exchange, private/custom lobby state, heartbeats,
disconnect/content/reliable control, and join/agreement/member messages. Public
game state, theater, modified stats, server-list, P2P, migration, voice, relay,
demo, unknown, malformed, truncated, overflowed, and oversized messages fail
closed. Message families with detailed inspectors continue through those
inspectors before admission.

`net_password` is advertised as password-required in discovery and now marks
the browser row as protected. Before starting the native join, the client proves
password knowledge with an HMAC response to a fresh host-issued challenge. The
proof covers both client and host nonces and is bound to the client's physical
LAN endpoint; it cannot be reused for a later challenge or a different source.
The host authorizes that endpoint for native lobby traffic only after the proof
passes. These preflight messages deliberately bypass the negotiated packet
wrapper because they establish that negotiation; the proof itself supplies the
authentication. The password prompt also writes both the native `password`
dvar and boiii's `net_password` dvar.

## Repeatable Checks

Run the pure policy test on any host with a C++20 compiler:

```bash
clang++ -std=c++20 -Isrc/common tests/lan_policy_tests.cpp -o /tmp/boiii-lan-policy-test
/tmp/boiii-lan-policy-test
```

Run the Windows release cross-build with the repository's documented toolchain:

```bash
WINDOWS_MSVC_SYSROOT=/path/to/windows-msvc-sysroot \
  ./scripts/unix/cross.sh --release
```

The unit test proves the deterministic address and message-type policy. The
build proves compilation and linkage. Neither proves that BO3's live lobby
state machine completes across two PCs.

## Two-PC Acceptance Matrix

Use two Windows PCs on the same Ethernet/Wi-Fi subnet, each with the same build
and content. Capture the boiii console logs and, for failure investigation, a
Wireshark trace filtered to `udp.port == 27017`.

| Scenario | Expected result |
| --- | --- |
| Host opens Zombies System Link private lobby; guest opens LAN tab | Host row appears within two seconds without manual IP entry |
| Guest selects the pre-game row while host is on `core_frontend` | Guest becomes a visible private-lobby member; no `/connect` command is needed |
| Guest changes ready state and host changes map/settings | State propagates to the other PC |
| Host launches | Both players transition into the same Zombies match |
| Match ends or host returns to lobby | Both clients return without a stuck join state and can launch again |
| Host sets `net_password`; guest enters the correct password | Row is marked protected and join succeeds |
| Guest enters a wrong or empty password | Join fails and guest never becomes a lobby member |
| Guest is on another routed subnet, a VPN/tunnel only, or the Internet | Host is not discovered and native lobby packets are rejected |
| Crafted unknown, public, migration, voice, demo, malformed, or >`0x2000` native message | Packet is rejected without a crash or state change |
| Repeated refresh/cancel/reopen of LAN tab | No duplicate/stale rows; refresh state completes consistently |

Passing all rows, with packet captures showing directed discovery and native
lobby exchange only between the two physical-subnet addresses, is the minimum
evidence for declaring the feature operational. Longer malformed-packet fuzzing
and soak tests remain part of `security-performance-verification.md`.

## Local Two-Bottle Harness

For development on one Linux machine, `scripts/unix/test-lan-bottles.sh` starts
two separate Wine prefixes. The host listens on UDP 27017 and the guest on UDP
27018. Both receive `-lan-local-test`, an explicit test-only escape hatch that
allows the machine's own physical IPv4 address through the same-subnet check.
The guest also receives `-lan-test-guest`, which selects boiii's alternate local
identity key so the native lobby sees two distinct players despite the cloned
prefix. Without these flags, self-address traffic remains rejected and normal
identity selection is unchanged. Every other gate in this document—including
Zombies/System Link mode, the host-issued password challenge, endpoint
authorization, native parsing, and the message allowlist—remains active. The
baseline run leaves password protection disabled so discovery and native lobby
joining can be isolated from password-handshake failures.

The harness expects Bottles named `Boiii` and `Boiii-Guest`, copies the current
Release build to `boiii-lan-test.exe` beside the game, and writes separate host
and guest logs to a newly created temporary directory. It waits for the host's
UDP socket before starting the guest, because two simultaneous DXVK warm-ups
can leave both windows black for several minutes. Readiness defaults to 240
seconds per instance and can be overridden with `BOIII_LAN_READY_TIMEOUT`.
Run the unprotected baseline from the repository root:

```bash
./scripts/unix/test-lan-bottles.sh
```

To exercise the protected path, set the same test password for both instances:

```bash
BOIII_LAN_PASSWORD=test123 ./scripts/unix/test-lan-bottles.sh
```

The test-only password flag initializes `net_password` after the boiii dvar is
registered, avoiding the engine's too-early `+set` handling. Startup
self-connects remain on BO3's native loopback transport and are never wrapped
as remote password packets.

Close both game windows normally after testing. The copied test executable can
then be removed; it is not part of the repository or a release artifact.
