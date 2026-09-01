# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #250: re-evaluate the BGF decoder variants for HPKE-Stern-KEM

`SecurityProofs-5.md` §11.8.7 closes with a question TODO #218 asked and explicitly did not
answer: whether the near-codeword-aware and failure-recycling BGF variants in the recent
literature close the DFR gap without a wire-format change.

**Precondition, from §11.8.7 itself.**  "At parameters this far from the target the answer
would not change the classification", and a decoder improvement that leaves `r = 523` in
place cannot deliver `2^-128` on its own.  So this item is **conditional**: it is worth doing
alongside a QC-MDPC parameter change, and close to worthless before one.  Filed so the
question is not lost, explicitly deprioritised until a parameter item exists.

**If it runs:** measure the candidate variants against the deployed decoder on the same
harness `qcmdpc_dfr_weak_keys.py` uses, and report DFR at the deployed parameters and along
the `r` curve — the existing DFR(r) fit is a lower bound (waterfall concavity) and any new
decoder needs its own.

Status: **OPEN**

### #257: the width extrapolation for both trail axes (merges #252 and #254)

**This item is the merger of TODO #252 and TODO #254**, closed in v5.2.4.  Both had been
reduced, by three passes each, to the same remaining question about the same kind of
object, and were carrying it in two entries whose third-pass blocks were byte-identical.
Nothing was dropped in the merge; the state below is the union of what they left.

**What is settled, and stays settled.**  The asymptotic per-round trail weight is a
MINIMUM MEAN CYCLE -- of the difference graph on the differential axis (SecurityProofs-8.md
§11.35), of the mask graph on the linear one (§11.36) -- and is therefore exactly
computable per key by Howard's policy iteration, with the transient and the `0.6n`
codebook ceiling both cancelling rather than being defeated.  Measured:
`s_diff` = 1.279 / 1.349 / 1.717 / 1.903 at `n` = 7 / 8 / 10 / 11, and `s_lin` reaching
`n = 13` at 1.154.  Both clear their criteria (`4/3`, `2/3`) at the widest exact width,
both rise monotonely, and the failing fraction thins at every step.

**What is owed.**  The criteria are stated at `n = 256` and the graphs have `2^n` nodes,
so no width above 13 is exactly reachable.  Since both criteria are already met where the
answer is exact, what is owed is not a limit but MONOTONICITY: that the sequence never
turns around between 13 and 256.

**What will not supply it** (all closed by measurement in SecurityProofs-9.md §11.37, none to be retried):
an embedding between widths -- there is none, `M` and `delta` both depend on `n` and only
a third of optimal-cycle nodes keep their image at `n+1`, so no proof can come from
comparing two graphs; sparse-subgraph search at `n = 256` -- optimal cycles are dense,
`0.6n` to `0.86n`; a guessed LP-dual potential -- Howard's bias correlates with no natural
node statistic, largest 0.37; and SAMPLING the edge-weight distribution at `n = 256` --
the threshold is a `2^-n` quantile, and the sampler returns 157 there against 0.48 at
`n = 13` where the exact answer is 1.154.

**What is left to try.**  SecurityProofs-9.md §11.37's annealed first-moment model, which predicts the slope
from the edge-weight distribution and the out-degree alone and tracks the exact answer to
within a few percent by `n = 11` on both axes.  It reduces the width question to one
statement with no FSCX in it -- the largest correlation and the largest `xdp+` of addition
with a CONSTANT, as a function of `n`.  Wallen does not apply to it (§11.30.4), so it
needs its own argument.

**First pass done in v5.2.4 — the model is EVALUATED at n = 256, and the shape of the
answer is not what any earlier pass assumed.**  See SecurityProofs-9.md §11.38 and
`SecurityProofsCode/annealed_moment_ladder.py`.

* **The sampling route is reopened and walked.**  §11.37.5 closed it because the annealed
  threshold sits in a `2^-n` quantile.  True, and not the obstacle: the model consumes the
  weight distribution only through its MOMENTS, and `A_t` = sum of (path count)^t counts
  t-TUPLES of paths, so it is one linear DP over a tensor power -- `O(n * t * 2^t)`, with
  no dependence on the number of edges.  Exact at n = 256 in milliseconds.  The 157 that
  §11.37.5 recorded as an artefact, with the instruction not to quote it, is **48.44**.
* **Two pieces of machinery, both validated exhaustively.**  A carry-pair automaton for
  `xdp+` of addition with a CONSTANT -- the output difference is not free, since
  `beta_i = alpha_i xor c_i xor c'_i`, so a differential is a prescribed constraint
  sequence and its probability is a path count (checked against the full DDT at n = 6, 7,
  every addend, every pair).  And a concavity lemma making the INTEGER lattice exact
  rather than merely a lower bound: the threshold's numerator is concave in t, so it lies
  above its chord and below either flanking secant, and both bounds are extremal at the
  endpoints.  The bracket closes to 1e-12.
* **THE SLOPE IS LINEAR IN n.**  This item, #252, #254 and #247 all asked what the
  per-round slope CONVERGES to.  It does not converge; `lambda*/n` does, at about 0.19
  differential and 0.088 linear, with the per-key spread of that ratio narrowing as the
  width grows.  The criteria are fixed numbers, so the margin GROWS with width and
  **n = 256 is the easiest width in the table, not the hardest**: 48.4 against `4/3` and
  22.4 against `2/3`, margins of 36x and 34x, at every key and every tz class sampled.
* **It retro-explains the inherited measurements.**  §11.35.6 and §11.36.5 both reported
  mu rising monotonely over n = 7..13 and neither could say why a bounded-looking quantity
  kept climbing.  It is not bounded: their EXACT medians 1.279 / 1.349 / 1.717 / 1.903 are
  0.183 / 0.169 / 0.172 / 0.173 of n, the same constant the model approaches from below.
* **Two corrections.**  §11.30.2's scale-invariance theorem stands -- the CRITERION does
  not depend on n -- but its reading that "no key size moves it" is wrong taken as
  *widening buys nothing here*; widening faces the same criterion with proportionally more
  margin.  Nothing recommends widening: 36x is already the margin.  And §11.37.6's
  per-trailing-zero offset is NOT width-independent (0.40 and 0.19 per zero against
  0.10-0.13 at n <= 11), while its conclusion survives a fortiori -- the whole tz span is
  under 6% of the largest class where one zero cost 5-7% before.
* **The linear axis reaches only EVEN moments**, because a correlation's sign is not
  affine in the masks -- fitted over GF(2) and rejected at every addend, exactly half the
  nonzero entries negative.  It brackets to 1-7% instead of closing, and the lower end is
  the conservative one.

**What is left, and it is the whole of what is left.**  (1) The model is an ESTIMATOR:
annealed, a first moment, which bounds nothing on its own since a first moment can be
carried by rare graphs, and validated against exact mu only at n <= 13, where it runs
3-15% BELOW the truth and converging upward.  The cheapest upgrade is named precisely --
the annealed count over-counts cycles sharing edges, so the gap is a SECOND-MOMENT
question about the same two inputs, both exactly computable by the machinery now in place.
(2) The LINEAR HULL, unchanged from §11.36.9: a trail statement is not a hull statement,
and nothing in this line of work reaches the hull.

**Reach.**  No production-track row.  HSKE-NL-A2 and `twk` are demo-only for reasons on
other axes (#243, #244, #248), and #254's three production-track rows -- HSKE-NL-A1,
HFSCX-256 and everything inheriting the hash -- left the scope of a trail bound entirely
in §11.36.8, because in both those modes the attacked input is the round CONSTANT, which
enters every round at once, so there is no trail to bound.  This item can therefore move
no rating in either direction, and is filed as an outstanding proof obligation behind
figures already published, not as a gate on anything.

Status: **OPEN**


### #261: full 4-way capability parity — C, Go, Python and Java run the exact same algorithms and tests

**Distinct from TODO #260, and the direction matters.**  #260 is "Java catches up to
C/Go/Python" — every gap it lists is something the other three have and Java lacks.  This
item is the symmetric closure: no language may have an algorithm, protocol variant, or
security test that any of the other three is missing, **in either direction**.  Once #260
lands, this item is what keeps all four in lockstep going forward, and it already has at
least one confirmed gap #260 does not cover, because #260 explicitly excluded it.

**Confirmed asymmetry #1 — HCRED-KKW, named in the request that opened this item.**  The
KKW preprocessing-model transcript variant (`hcred_prove_kkw`/`hcred_verify_kkw`, ~11x
smaller proofs than the ZKBoo-(2,3) path at production parameters) exists **only in
Python**:

```
Herradura cryptographic suite.c   -- absent
Herradura cryptographic suite.go  -- absent
Herradura cryptographic suite.py  -- hcred_prove_kkw / hcred_verify_kkw, ~113 lines
bindings/java/herradurakex/Hcred.java -- absent, and says so explicitly:
    "The KKW preprocessing-model transcript variant ... is out of scope for
     this port -- the ZKBoo-(2,3) path here is sufficient for interop."
```

Java's own doc comment is a documented, deliberate exclusion — which is exactly the
ACKNOWLEDGED outcome this item should produce for anything that turns out to be a genuine
per-language reason, rather than four different implicit answers to the same question.  C
and Go have never addressed it at all.  Resolve it one of two ways when this item is worked:
port KKW to C, Go and Java so all four match Python; or downgrade Python's KKW path to
explicitly ACKNOWLEDGED non-parity (a research/demo convenience, not a security-relevant
divergence) and record why in `SECURITY.md`/`spec/`.  Don't leave it as an unstated fact
four different files each know a different piece of.

**v5.4.4 tried the ACKNOWLEDGED route; reconsidered (v5.4.5) — port it instead.**
`SECURITY.md` briefly recorded `hcred_prove_kkw`/`hcred_verify_kkw` as ACKNOWLEDGED
non-parity (no CLI surface for the other three to be missing, research-tier protocol), with
matching pointer comments at `herradura.h`'s `hcred_prove` and `herradura/herradura.go`'s
`HcredProve`.  That resolution is withdrawn: asymmetry #1's scope is now **port KKW to C, Go
and Java so all four match Python**, the other option this item's opening paragraph always
named.  The ACKNOWLEDGED wording added in v5.4.4 needs pulling back out of `SECURITY.md` and
both pointer comments once the ports land.

Task breakdown for the port (mirroring Python's `hcred_prove_kkw`/`hcred_verify_kkw`, ~113
lines, `Herradura cryptographic suite.py` line 3061 on — KKW encoding, cut-and-choose over
`M` emulations opening `M-τ`, `N`-party preprocessing, the batched output check):
- **Go (DONE, v5.5.0):** `HcredProveKkw`/`HcredVerifyKkw` added to `herradura/herradura.go`,
  a 1:1 port of every Python helper (`hcred_kkw_gates`/`_tree`/`_tree_open`/`_tree_recover`/
  `_party`/`_pre`/`_state_com`/`_outmap`/`_targets`/`_fs_ints`) plus the two entry points, all
  unexported except the entry points and the two exported proof-carrying types
  (`HcredKkwProof`, `KkwOnlineProof`, `KkwPathEntry`). Wired into
  `Herradura cryptographic suite.go`'s existing HCRED demo section, right after the ZKBoo
  path, reusing the same enrolment keys. **Caught one real transcription bug in review**:
  the "reveal `aux` when party N-1 is opened" condition was inverted on the first pass
  (`pb == N_par-1` instead of Python's `pb != N_par-1`) — every genuine proof failed
  verification until a fail-point-tagged debug pass isolated it to that one line. Verified
  structurally (no fixed-vector KAT exists for KKW in any language yet, matching Python):
  ~20 repeated prove→verify round trips all passed, plus targeted rejection checks — wrong
  message, flipped `W`, flipped a party's `U` broadcast, flipped a `T` gate broadcast,
  flipped a preprocessing root seed byte, and a relabeled `Pbar` (claimed hidden party) —
  each one independently caught by `HcredVerifyKkw`. Demo run and the full Go suite/CliTest
  gates are clean (see CHANGELOG v5.5.0).
- **C (DONE, v5.6.0):** `hcred_prove_kkw`/`hcred_verify_kkw` added to `herradura.h`,
  translated from the Go port line-by-line (gates/tree/tree-open/tree-recover/party/pre/
  state-com/outmap/targets/fs-ints, `HcredKkwProof`/`HcredKkwOnline`/`HcredKkwPathEntry`,
  manually heap-managed since C has no GC — every allocation is freed on every exit path,
  checked clean under ASan+UBSan). Wired into `Herradura cryptographic suite.c`'s existing
  HCRED demo section, right after the ZKBoo path. **Caught two real bugs before either
  shipped, both found by writing a standalone test harness first rather than trusting the
  translation:**
  1. A genuine **buffer overflow** in `hcred_kkw_state_com`: its size calculation omitted
     the 2-byte emulation-index field it then wrote, caught by `-Wstringop-overflow` on a
     first compile (not by a crash — the under-allocation was 2 bytes on a much larger
     buffer, exactly the class of bug a sanitizer or a careful compiler catches and a
     casual test run does not).
  2. A **bit-endianness mismatch**: `hcred_kkw_outmap`'s per-row check tested `H[r]`'s bit
     `i` little-endian-style (`b[i/8]`), where this file's `BitArray` convention (used by
     `hcred_phi` and every existing HCRED/Stern function) is big-endian (`b[KEYBYTES-1-i/8]`).
     This is NOT a copy-paste error from Go/Python — Go's own `.Val.Bit(i)` on a `big.Int`
     and Python's integer `>>`/`&` both give the *correct* bit regardless of byte layout,
     so this bug is specific to C's byte-array `BitArray` representation and had no Go/Python
     analogue to catch it by comparison. Found by an isolated linearity test
     (`outmap(a+b,c+d) == outmap(a,c)+outmap(b,d)`, which passed, ruling out the outmap
     formula itself) followed by a direct real-witness test (`outmap(w_in,z_real) ==
     targets`, which failed with small residuals concentrated exactly in the row-check
     block) — the same divide-and-conquer approach the Go debugging session used, applied
     one layer deeper since this bug was C-specific.
  Verified the same way as Go: no fixed-vector KAT exists for KKW in any language, so
  round-trips (clean across repeated runs) plus the same six rejection axes (wrong message,
  flipped `W`, flipped `u`, flipped `t`, flipped a preprocessing root byte, relabeled
  `pbar`) — all independently caught. `build_c.sh`'s full suite build and the demo run both
  clean (`*** OK: no check reported [FAIL] ***`).
- **Java (DONE, v5.7.0):** `Hcred.proveKkw`/`Hcred.verifyKkw` added to
  `bindings/java/herradurakex/Hcred.java`, translated from the Go port. Java's `BigInteger`
  bit convention (`.testBit(i)`) is layout-independent — no analogue of C's byte-array
  endianness bug was possible here, and none was found. One structural difference from
  Go/C worth noting for future readers: `HcredKkwProof`/`KkwOnlineProof`'s fields are
  `public final`, matching this file's existing `Proof`/`ProofRound` style — a proof is
  Java-idiomatically immutable once built (a real tamper attempt has to forge a byte/int
  differently from a test poking a field, which is closer to what verification is actually
  defending against). Wired into `Demo.java`'s HCRED section, right after the ZKBoo path.
  Verified structurally: 21 prove→verify round trips across repeated runs plus five
  in-place-mutable-field rejection checks (tampered message, `t`, `comH`, `zin`, a
  preprocessing root byte — the primitive-typed `W`/`pbar`/`u` fields being `final` int
  make an in-place tamper of those three specifically require constructing a distinct
  proof object rather than mutating one, so they weren't exercised this pass), all
  correctly caught, plus a same-object re-verify-after-restore on every run confirming no
  check has a side effect. `bindings/java/build.sh`, the full `Demo.java` run, and
  `CliTest/test_java_bindings.sh` all clean.
- Still **not** a CLI subcommand in any language — Python's (and now Go's, C's and Java's)
  KKW path has none either, so parity here means the suite files and the demos, not
  `cred-prove --transcript kkw`.
- KAT/test coverage is the one piece left un-decided: no fixed-vector KAT for KKW exists in
  any language, so a byte-exact cross-language check needs one added first — every language
  ships today verified only structurally (round-trips + rejection checks), which is the
  standard the rest of HCRED already uses too.
- **Asymmetry #1 is now closed in all four languages.**

**Confirmed asymmetry #2 — test coverage, not just algorithm coverage.**  The request is
explicit that tests are in scope, not only the primitives:

```
CryptosuiteTests/Herradura_tests.c   32 `test_*` functions
CryptosuiteTests/Herradura_tests.go  37 `test*` functions
CryptosuiteTests/Herradura_tests.py  36 `test_*` functions
bindings/java/herradurakex/SelfTest.java  ~20 PASS/fail checks, unnumbered
```

C/Go/Python additionally share a **numbered** test convention ([1]-[48], stable IDs cited
throughout `CHANGELOG.md`/`TODO_DONE.md` — e.g. "test [45] runs its Stern-F sub-check at
`rounds=32`", "test [46] is TODO #242's regression guard").  `SelfTest.java` has no
equivalent numbering, so a Java gap can't even be cited by the same vocabulary the other
three use to talk about test coverage.  Bringing Java's test count up (TODO #260, item 2)
should also adopt the numbered convention, not just close the count gap.

**Relationship to #260 and sequencing.**  Work #260 first — most of what #261 would flag
today is exactly #260's Java list, and fixing it there is the direct fix.  What #261 adds on
top: (a) the reverse-direction check (does every OTHER language have what Python/Go/C
individually grew, like KKW), and (b) turning "parity" from a one-time audit into something
checked mechanically going forward, so a fifth divergence doesn't accumulate silently the
way KKW apparently did.

**Proposed mechanism, to design when this item is worked, not decided here.**  The repo
already has two coverage guards in this family — `ci.yml`'s native-interop step failing if a
`CliTest/*.sh` script isn't claimed by exactly one job, and `check_part_index.py` failing if
`SecurityProofs-*.md`'s banners disagree.  A `check_language_parity.py` in the same spirit —
enumerating each language's public functions/CLI subcommands/numbered tests and diffing the
four sets — would turn every future asymmetry (Java or otherwise) into a caught CI failure
instead of a fact three other files quietly don't know.  Scope, false-positive rate (a
language-appropriate helper that isn't a protocol function shouldn't count), and where it
runs are all open design questions for whoever picks this up.

**Acceptance criterion.**  For every protocol/primitive and every named security test, the
four-language table has either all four cells filled, or a cell marked ACKNOWLEDGED with a
recorded reason (never a silent absence) — checked by the mechanism above rather than by a
one-time read of the source tree, so it stays true.

Status: **OPEN**
