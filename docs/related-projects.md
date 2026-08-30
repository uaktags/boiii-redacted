# Related Projects (Field Survey)

Similar boiii/T7 client-patching projects observed in the field. Reference for
behavior comparison only — per ADR-0005 we read third-party code to learn
behavior, never copy code verbatim.

## notnightwolf/cleanopsT7

- <https://github.com/notnightwolf/cleanopsT7/tree/main>
- "A Patch for Call of Duty: Black Ops 3 - Multiplayer (Steam)."
- Auto-removes previously identified cheaters from multiplayer matches when a
  patched player joins; also fixes most known exploits.
- Relevance: independent exploit-fix catalog; useful cross-check against our
  `docs/ext-t7patch-security-map.md` for overlap or gaps we have not mapped.

## ahrimd0n/t7x (fork of alterware/t7x)

- <https://github.com/ahrimd0n/t7x>
- T7x client; per upstream docs it is cross-compatible with the BOIII client
  (same servers), described as newer, and does not require owning BO3.
- Relevance: parallel client lineage with its own auth/network stack; useful
  comparison point for challenge handling and server compatibility decisions.
