# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

---

### #234: The ARM / NASM i386 / Arduino test harnesses cannot fail their CI jobs either

TODO #233 gave the C, Go and Python harnesses an aggregate exit status. The assembly and
Arduino harnesses were left out of that item's scope and still have the defect it fixed:
`CryptosuiteTests/Herradura_tests.s` ends in a hard-coded `mov r0, #0; bl exit` regardless
of outcome, across 19 separate `[FAIL]` emission sites, and `Herradura_tests.asm` and
`Herradura_tests.ino` are the same shape. So `arm-i386` and `arduino` — two more required,
blocking CI jobs — go green whenever an assembly security test fails.

They also carry #233's third finding. Tests [1]-[18] include [18] HPKE-Stern-F
encap/decap at N=32, t=2, where the code is not uniquely decodable: 43.46% of keys admit
at least one weight-2 syndrome collision and 0.38% of error vectors brute-force to a
different `e'` (measured over 5000 keys). Whatever trial count the assembly [18] uses, it
reports a spurious `[FAIL]` at that rate, and always has.

**Work.**

1. Fix [18]'s ambiguity accounting in `.s`, `.asm` and `.ino`, the way #233 did for C/Go/
   Python: a syndrome with two weight-t preimages is not a decoder failure.
2. Audit the remaining `[FAIL]` sites in each for the same "probabilistic property
   asserted as deterministic" class before gating — that audit is what turned up [4] and
   [18] in #233, and neither was in the original item text.
3. Then aggregate: a failure counter and a non-zero exit. ARM's exit is already a
   `bl exit` call, so it is a counter and a load, not a restructure.
4. Arduino runs under simavr via `run_arduino.sh`; check how (and whether) an exit status
   propagates there before assuming step 3 is sufficient for that target.

Both toolchains build and run locally on the dev host (`arm-linux-gnueabi-gcc`, `nasm`,
`qemu-arm`/`qemu-i386`), so this is testable without CI round-trips.

Status: **OPEN**
