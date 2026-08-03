# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### 169. Port the NL-FSCX v2 affine weak-key guard to the assembly and Arduino targets (Security, Low)

**Background:** TODO #168 added `nl_v2_key_is_valid` to the Python, C (`herradura.h`) and
Go suites and enforced it in all three CLIs, rejecting the key class for which NL-FSCX
v2's permutation degenerates to GF(2)-affine ($\delta(K) \in \{0, 2^{n-1}\}$ — see
`SecurityProofs-2.md` §11.19.2). The ARM Thumb-2, NASM i386 and Arduino targets also
implement NL-FSCX v2 and HSKE-NL-A2, but were left unguarded.

They are materially more exposed than the 256-bit deployment, because the class density
scales with word size. The $\delta = 0$ class is every $K$ divisible by
$2^{\lceil (n+1)/2 \rceil}$, and the $\delta = 2^{n-1}$ class is additionally non-empty
whenever $8 \mid n$. Exhaustive counts over the full key space give a total affine
density of $2^{-16.7}$ at the assembly targets' $n = 32$ — roughly 1 key in $105{,}000$ —
against $\approx 2^{-129}$ at $n = 256$.

TODO #168 deliberately did not attempt this: those targets are demo-only, and the
development host has no ARM cross-toolchain, so the change could not have been built or
tested (writing unverifiable assembly was judged worse than leaving a documented gap).

**Work items:**

1. Install an ARM cross-toolchain (`arm-linux-gnueabi-gcc`) and confirm `build_arm.sh`
   plus `qemu-arm` run the existing suite/tests before touching anything — see the
   portability notes in CLAUDE.md's Build Commands section.
2. Add the `delta(K) not in {0, 2^(n-1)}` check to the 32-bit NL-FSCX v2 paths in
   `Herradura cryptographic suite.s`, `Herradura cryptographic suite.asm` and
   `Herradura cryptographic suite.ino`, matching the C predicate's semantics exactly.
3. Decide and document the failure mode for these targets: they have no CLI error path,
   so the choices are a return-code convention or a visible test-harness assertion.
   Whichever is chosen, keep it consistent across all three.
4. Extend `CryptosuiteTests/Herradura_tests.{s,asm,ino}` with the equivalent of test
   `[45]`'s `v2_weak_key_reject` sub-check at $n = 32$ (e.g. $K = 2^{17}$, which has
   $\delta = 0$ at that width), and run them under qemu/simavr per `run_arduino.sh`.
5. Update `SecurityProofs-2.md` §11.19.2, which currently records this as open follow-up
   work.

Status: **OPEN**

### 170. Re-split `SecurityProofs-*.md` — two of three parts now exceed GitHub's KaTeX limit (Documentation, High)

**Background:** `SecurityProofsCode/KATEX_RULES.md` documents a hard GitHub constraint:
past roughly **750 math expressions per page**, every expression beyond the threshold
renders as "Unable to render expression" — a client-side cascade failure with no syntax
fix. That limit is why `SecurityProofs.md` was split into three parts in the first place.

Two of the three parts have since grown back past it. Measured with
`SecurityProofsCode/validate_katex.js` (2026-08-03):

| File | Expressions | Status |
|---|---|---|
| `SecurityProofs-1.md` | 914 | **over** the ~750 limit |
| `SecurityProofs-2.md` | 1434 | **far over** — nearly 2x |
| `SecurityProofs-3.md` | 501 | under |

So both files currently render incorrectly on GitHub past their threshold, even though
the local validator reports `0 FAIL` — the validator checks per-expression syntax, not
the per-page count, so it cannot catch this. The recent research-review sections (§11.15
through §11.19, added by TODO #161/#162/#165/#166/#159) are the bulk of part 2's growth.

CLAUDE.md's own structure table is stale on all three counts (it records ~753 / ~873 /
~121 against the measured 914 / 1434 / 501) and on part 2's section range (it says
"§11–§11.9", but the file now also carries §11.15–§11.19).

**Work items:**

1. Split at section boundaries so every resulting part stays comfortably under ~750 — a
   4-way split is the obvious shape, e.g. moving §11.15–§11.19 (the TODO-specific
   research-review sections) into a new `SecurityProofs-4.md`, then re-checking whether
   part 1 needs a further cut.
2. Re-measure every part with `validate_katex.js` after splitting and record the actual
   counts, rather than estimates.
3. Update `SecurityProofs.md`'s split index, every cross-reference between parts, and the
   `SecurityProofs-*.md` references in `README.md`, `SECURITY.md`, `CLAUDE.md`,
   `llms.txt`, and the `SecurityProofsCode/` script docstrings that cite section numbers.
4. Fix CLAUDE.md's structure table: correct all three expression counts and part 2's
   section range.
5. Add a guard against silent regrowth — e.g. teach `validate_katex.js` to warn when a
   file exceeds ~700 expressions, so the next section added to a near-full part surfaces
   the problem at authoring time instead of on GitHub.

Status: **OPEN**
