# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

---

### #233: The C/Go/Python test harnesses cannot fail their CI jobs, and test [45] fails ~22-38% of the time

Found while measuring TODO #225; unrelated to that item's subject, and more serious.

**1. No harness propagates a failure.** All three suites print `[PASS]`/`[FAIL]` as
text and return 0 regardless. `CryptosuiteTests/Herradura_tests.py` contains no
`sys.exit`, no `assert`, and no failure aggregation of any kind; the C harness's
`exit(1)` calls are all I/O-error paths, not test outcomes; the Go harness has no
`os.Exit` at all. Verified empirically: a Python run that printed `[FAIL]` exited **0**.

So `native-c`, `native-go` and `native-python` — three required, blocking jobs — go
green whenever a security test fails. They can only fail on a crash, or via the
`CliTest/*.sh` scripts, which do assert properly. Every "all 29 checks pass" on a recent
PR carries that caveat.

**2. And a test really is failing.** Security test [45]'s `stern_synd_reject` check signs
with HPKS-Stern-F at `n=32, rounds=8`, then requires a 1-bit-corrupted syndrome to be
rejected — every time, over N trials. Stern-F's soundness error is `(2/3)^rounds` per
trial, so a corrupted syndrome is *expected* to verify sometimes. Measured over 400
trials: **19/400 = 4.75% accepted**, against the theoretical `(2/3)^8 = 3.90%`. That puts
test [45]'s failure probability at **21.6% for N=5 and 38.5% for N=10** (N=10 is the
default). Observed directly: 2 of 12 runs on a pristine checkout, 1 of 12 with #225's
changes applied.

The implementation is not wrong — the test asserts a probabilistic property as if it
were deterministic. Either raise the round count for this check until the soundness
error is negligible, or assert a bound over many trials rather than perfection over ten.

**Work.**

1. Fix [45] first. Fixing (2) before (1) is mandatory: turning on failure propagation
   while [45] still flakes would make three required jobs fail a third of the time.
2. Then give each harness an aggregate exit status. A shared "failures seen" counter and
   a non-zero exit is the whole change in each language.
3. Audit for intentional failures before gating. The C harness's own header text
   describes `[4] Bit-frequency bias` as an "expected FAIL — FSCX is not a PRF", though
   [4] currently passes in a Python run; any grep-based or counter-based gate needs that
   settled first, in all three languages.
4. Re-run the full matrix and see what else has been failing silently. This item should
   not be closed on the assumption that [45] is the only one — that is exactly the
   assumption the missing exit status made untestable.

Status: **OPEN**

