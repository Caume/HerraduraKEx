# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

### 155. Arduino/AVR CI job fails: `.bss` overflows the ATmega2560's 8KB SRAM by ~51 bytes under the GitHub-runner toolchain (Build/CI, Low)

**Background:** TODO #153's new CI workflow runs `build_arduino.sh` on `ubuntu-latest`
(`arduino-core-avr 1.8.6+dfsg-1` / `avr-gcc 7.3.0` from Ubuntu 24.04's apt repos). The
suite `.ino` build fails deterministically at the link step on both PR #167 CI runs, at
the identical address:
```
avr/bin/ld: address 0x802233 of Herradura cryptographic suite_avr.elf section `.bss'
is not within region `data'
collect2: error: ld returned 1 exit status
```
The ATmega2560's SRAM `data` region ends at `0x802200` (8192 bytes from `0x800200`), so
the linked binary needs the static (`.data`+`.bss`) storage to fit within that budget —
here it overflows by `0x802233 - 0x802200 = 0x33` = 51 bytes. This is not present in
`build_arduino.sh`'s own header-comment margin note (which already flags the ATmega328P/
Uno as insufficient at ~2.5KB BSS from the Ring-LWR polynomial arrays) — the ATmega2560
target normally has comfortable headroom, so this looks like a toolchain-version-specific
regression: the CI runner's `arduino-core-avr`/Arduino-core build apparently has a
slightly larger static footprint than whatever local toolchain this target was last
verified against, tipping a previously-fine build over the edge by a small margin. The CI
job is marked `continue-on-error: true` (best-effort, per TODO #153 work item 3), so this
does not block merges, but it means the Arduino target is currently unverified in CI.

**Work items:**

1. Reproduce locally with the same toolchain versions as the CI runner
   (`arduino-core-avr 1.8.6+dfsg-1`, `avr-gcc 7.3.0`, Ubuntu 24.04) to confirm the
   overflow is toolchain-driven rather than a pre-existing latent bug.
2. Identify which static buffer(s) account for the ~51-byte overrun (`avr-size` /
   `avr-nm --size-sort` on the linked `.elf`) and trim them — likely candidates are
   Ring-LWR polynomial arrays or Stern-F buffers already called out as memory-tight in
   `build_arduino.sh`'s header comments.
3. Verify the fix under `simavr` (`run_arduino.sh tests`) and re-run the CI Arduino job
   to confirm it goes green before considering this fixed — the job should then have
   `continue-on-error` reconsidered (keep it as a safety net regardless, but a green
   Arduino job matters for catching future regressions of this kind).

Status: **OPEN**
