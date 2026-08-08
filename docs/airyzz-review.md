# Airyzz `boiii-redacted` Review

This document preserves the one-time review of `Airyzz/boiii-redacted`. Airyzz
is not a tracked upstream and no Airyzz commit was merged into this repository.

## Comparison Snapshot

The comparison was performed on 2026-08-07 after synchronizing
`Ezz-lol/boiii-free`'s `beta` branch.

| Item                                        | Value                                      |
| ------------------------------------------- | ------------------------------------------ |
| Airyzz tip reviewed                         | `c086c335d929aa09ddd5995fde1e5160d0147ee3` |
| Tip date                                    | 2024-08-04                                 |
| Common ancestor with Ezz `beta`             | `bb6faf661dad5f15f9cea5f6b1a7559c8136c55a` |
| Common-ancestor date                        | 2023-06-10                                 |
| Commits unique to Airyzz                    | 40                                         |
| Commits unique to Ezz `beta`                | 864                                        |
| Final Airyzz delta from the common ancestor | 26 files, 571 insertions, 26 deletions     |

The Airyzz remote and its remote-tracking references were removed after the
review. The fetched `Redacted`, `Redacted-2`, `ezz-7`, and `ezz-8` tags were
also removed. This document is the only retained project record of that
comparison.

## Changes Reviewed

### Theater and demo support

Most of the unique work attempted to make theater files and demos usable:

- a replacement fileshare UI data source;
- demo recording hooks and commands;
- local Demonware upload/download behavior;
- HTTP byte-range responses for large demo files;
- metadata associating demos with a loaded mod or Workshop item; and
- mode switching and Workshop-map loading during theater playback.

The feature idea is potentially useful, but the implementation is not suitable
for a direct port. It targets a 2023/2024 source and game-offset layout,
disables checksum and target validations with hard-coded NOPs, and depends on
old source files that no longer exist in the current Ezz tree.

The HTTP range implementation also reads the complete file into memory, parses
untrusted range values with throwing conversions, and does not establish that
the requested end offset is within the file. The fileshare Lua is a copied
decompiled function rather than a small maintained patch. Any future theater
work should be designed against the current source with bounded streaming,
strict parsers, explicit storage limits, and tests; it should not be recovered
by cherry-picking these commits.

### Dvar changes

Airyzz added a `dvar_remove_flags` helper and removed flags from selected dvars.
The helper has since been implemented independently in current Ezz code. The
Airyzz branch additionally iterated over the entire dvar pool and stripped
`DVAR_CHANGEABLE_RESET` and an unknown flag globally. That broad mutation could
break engine invariants and was rejected.

### Steam and DLC behavior

Airyzz removed a guard that prevents duplicate Steam client initialization and
reported campaign DLC as installed unconditionally. Both changes can hide
missing content or initialize incompatible Steam paths, so neither was adopted.
Current boiii already answers the relevant DLC queries locally without the
expensive stock Steam calls.

### Discord behavior

The Discord changes generated random party sizes, timestamps, and instance
values in join callbacks. That creates inaccurate presence information and is
not a functional join implementation. It was rejected.

### Developer and command conveniences

The branch included local-data-directory overrides, optional ReShade loading,
branding changes, and an `execute` command that reads an arbitrary local file
and passes it to the engine command buffer. These are either development-policy
choices or unnecessary attack surface, not upstream enhancements.

### Cosmetic and resource changes

Console-hook ordering, README edits, branding, and icon/resource changes did not
provide a current functional or security benefit.

## Decision

No Airyzz changes were adopted. The only idea worth reconsidering is theater and
demo support, and that requires a clean implementation against current Ezz
`beta`. Ezz remains the sole upstream source; this repository's own changes
remain limited to reviewed security, compatibility, performance, and local
feature work.
