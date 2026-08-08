# Security and Performance Verification Plan

This document defines how to turn boiii's security and performance claims into
repeatable evidence. It is a research and implementation roadmap, not a claim
that the current code has already passed these tests.

## What Counts as Evidence

A successful build proves only that the selected source compiles and links. A
security or performance claim needs all of the following:

1. a written invariant or measurable hypothesis;
2. an oracle that distinguishes acceptable and unacceptable behavior;
3. boundary, malformed, and adversarial inputs;
4. runtime coverage of the installed hook or integration path; and
5. a reproducible baseline and acceptance threshold.

Unit tests can prove behavior for enumerated inputs and properties. Fuzzing and
sanitizers can find broad classes of memory and parser failures, but cannot
prove that no vulnerability exists. Performance evidence must report effect size
and variance, not just one FPS number.

## Current Testability and Open Questions

The tree now has a first host-native policy test in
`tests/lan_policy_tests.cpp`. It exhaustively checks the LAN native-message
allowlist over the defined message-type range and verifies private IPv4,
netmask, subnet, and directed-broadcast vectors. The GitHub workflows still do
not run a general first-party test suite. The password hash and checksum have
one compile-time known vector each in
`src/client/component/network_password.hpp`.

Most security logic is coupled to global dvars, Windows time APIs, absolute game
symbols, hook objects, or static process state. The first implementation task is
to separate pure policy and codec code from the runtime adapters that install
hooks or call the engine.

Two behaviors require characterization before they are declared correct:

- `network_password::validate_packet` accepts a checksum mixed with the previous
  password hash for 1500 ms, but marker validation still compares only with the
  current hash. A packet using the previous marker will normally fail during the
  documented rotation window. The first password-state suite should expose this
  with a controllable clock.
- `handle_packet_internal_stub` now admits non-loopback native lobby packets
  only for Zombies System Link on a physical same-subnet RFC1918 peer.
  `ezzsec::AllowLanPacket` fails closed on bounds/read/parse failures and applies
  the private-lobby allowlist plus the available detailed inspectors. Two-PC
  integration and raw-message fuzzing are still required to prove that every
  allowed control message is necessary and safely parsed by the live engine.

## Proposed Test Architecture

Keep the injected runtime code thin and move deterministic logic into a
host-native core that does not include `std_include.hpp`, Windows headers, game
symbols, or hook machinery. Suggested layout:

```text
src/common/security/
  network_password_codec.hpp/.cpp
  fragment_reassembler.hpp/.cpp
  command_policy.hpp/.cpp
  connect_policy.hpp/.cpp
tests/
  unit/
  fuzz/
  benchmark/
  integration/
  corpus/
```

The runtime adapters should supply explicit inputs such as the current and
previous password hashes, rotation timestamp, current time, packet bytes, client
identity, and party policy. Fragment reassembly should become an instance with
injected limits and a clock instead of relying on a file-static map and
`high_resolution_clock`.

Use a separate host-native Premake workspace under `tests/` so Linux unit and
fuzz targets are not forced through the product workspace's global Windows
target. Recommended tools are:

- [GoogleTest](https://google.github.io/googletest/) for independent, repeatable
  C++ unit and fixture tests;
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html) for coverage-guided packet
  and parser fuzzing;
- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) and
  [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
  on host-native tests and fuzzers;
- [Windows AddressSanitizer](https://learn.microsoft.com/en-us/cpp/sanitizers/asan)
  for Windows-only adapters and integration harnesses where compatible; and
- [Google Benchmark](https://google.github.io/benchmark/user_guide.html) for
  repeatable microbenchmarks with warmup, repetitions, randomized interleaving,
  and JSON output.

Pin test dependencies just like the existing submodules. Do not link sanitizer
runtimes into release artifacts.

## Security Verification Matrix

| Area                   | Unit and property tests                                                                                                                             | Fuzz or integration evidence                                                                                               |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Password hash/checksum | Known vectors, ASCII case folding, even/odd/empty payloads, marker-present and marker-absent hashes                                                 | Mutate every byte of a valid packet; truncated packets and arbitrary marker offsets must reject without sanitizer findings |
| Password envelope      | Protect/validate round trips; wrong password, wrong checksum, missing marker, appended bytes, and offset boundaries                                 | Two-process UDP test for protected and unprotected peers                                                                   |
| Password rotation      | Old packets accepted before the defined deadline and rejected after it; new packets always accepted                                                 | Fake-clock test at 1499, 1500, and 1501 ms, followed by a real UDP rotation test                                           |
| Connect proof/auth     | Deterministic HMAC vectors; changes to either LAN nonce, endpoint, public key, connect data, or password reject; duplicate/stale LAN challenges reject; XUID must equal key hash; invalid names reject | Fuzz serialized connect data under ASan/UBSan; client/server test for each rejection reason and a captured-proof replay attempt |
| Fragment reassembly    | In-order and shuffled completion; duplicates; changing counts; zero or over-100 counts; over-`0x400` fragments; 100-ID/address cap; 5-second expiry | Stateful sequence fuzzer plus a memory-bounded flood/soak test                                                             |
| Lobby inspectors       | Boundary counts around 18, truncated fields, failed reader operations, unknown and blocked packet types                                             | Fake package-reader functions for deterministic paths, then a raw-message fuzzer and remote client/server test             |
| Menu/server commands   | Host/non-host matrix, case folding, wrong argument count, `badspawn`, and all privileged command names                                              | Runtime command injection from a test client must be rejected while allowed commands still work                            |
| `qmemcpy` guard        | Negative sizes perform no copy; zero and valid sizes preserve normal behavior                                                                       | Guard-page integration test catches any out-of-bounds copy                                                                 |
| TeamOps write patch    | Patch address and expected original bytes are validated before installation                                                                         | Dedicated-server canary test confirms out-of-range indexes cannot change adjacent memory                                   |
| Friends-only admission | Local, friend, non-friend, malformed XUID, open, private, and full-lobby policy matrix                                                              | Remote join tests through both custom auth and native lobby paths                                                          |

For hook-only fixes, add installation assertions: verify the expected original
bytes or function prologue before modifying memory, record the selected
client/dedicated address, and fail closed on an unknown binary. Unit tests of a
helper function do not establish that the live game calls that helper.

## Initial Fuzz Targets

Each target should accept a byte span and never require the game process:

1. protected packet validation;
2. fragment-header parsing and stateful reassembly;
3. serialized connect request parsing;
4. `ezzsec` LAN lobby message inspection through a fake reader; and
5. info-string and command-policy parsing.

Seed corpora should include valid captures, every documented rejection case,
minimum and maximum lengths, and regressions found in production. Pull-request
runs can replay the corpus under ASan/UBSan; scheduled runs can perform longer
coverage-guided fuzzing and retain minimized crashing inputs.

## Performance Verification

### Microbenchmarks

Measure the cost and throughput of:

- checksum-only and password-protected packet handling at 0, 64, 512, 1024, and
  maximum supported sizes;
- fragment creation and shuffled reassembly at 1, 2, 50, and 100 fragments;
- malformed-packet rejection, including map-cap floods;
- lobby inspection by packet type; and
- cached DLC queries after the first filesystem probe.

Record ns/operation, bytes/second, allocations, and peak retained state.
Benchmarks should compare the parent/baseline implementation and candidate in
randomized order. Google Benchmark's
[`compare.py`](https://google.github.io/benchmark/tools.html) can report a
Mann-Whitney U comparison, but an effect-size threshold must also be chosen so a
statistically detectable yet irrelevant change does not fail the build.

### Windows system tests

The two documented user-visible performance claims need full Windows A/B runs:

- **Startup affinity workaround:** extract and unit-test mask selection, then
  verify that the original process affinity is captured, reduced to at most four
  already-allowed CPUs, and restored after one second. Compare enabled and
  disabled builds on affected and unaffected CPUs.
- **Steam DLC query suppression:** use an instrumented fake Steam interface or
  ETW trace to prove that repeated ownership/progress queries do not cross into
  Steam. Measure first-call filesystem cost separately from cached calls.

Use [PresentMon](https://github.com/GameTechDev/PresentMon) to capture per-frame
CPU, GPU, and display timing and
[Windows Performance Recorder](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options)
for ETW CPU, scheduling, file-I/O, and process-start traces. Preserve raw CSV or
ETL artifacts with the commit, build type, game scenario, map, hardware,
drivers, OS version, and command line.

Run release binaries without sanitizers for performance measurement. Use a fixed
replay or scripted scene, warm up caches, randomize baseline/candidate order,
and collect enough paired runs to report median, p95/p99 frame time, stutter
counts, startup duration, CPU time, and confidence intervals. Define the
practical improvement or regression threshold before collecting results.

## CI and Acceptance Gates

Suggested progression:

1. **Characterization:** add expected tests around current behavior, including
   deliberately failing tests for disputed requirements.
2. **Pure-core extraction:** move password, fragment, and command policy code
   without changing runtime behavior.
3. **Pull-request gate:** unit tests, regression corpus, ASan, and UBSan.
4. **Scheduled security gate:** longer libFuzzer runs and state/memory soak
   tests.
5. **Windows integration gate:** product build plus loopback client/server
   scenarios and hook-installation assertions.
6. **Performance gate:** stable microbenchmarks on controlled hardware;
   PresentMon/ETW A/B runs for release candidates rather than noisy shared CI.

The first useful milestone is a host-native test target containing these tests:

- `PasswordCodec.RoundTripAndSingleByteMutation`
- `PasswordState.PreviousHashAndMarkerDuringRotation`
- `FragmentReassembler.RejectsInvalidCountsAndDuplicates`
- `FragmentReassembler.EnforcesPerAddressStateCap`
- `CommandPolicy.BlocksPrivilegedRemoteResponses`
- `LobbyPolicy.DefinesRemoteNonLoopbackBehavior` (the pure allowlist portion is
  now covered by `tests/lan_policy_tests.cpp`)

That milestone will both validate the proposed architecture and turn the two
open code-review findings into explicit decisions.
