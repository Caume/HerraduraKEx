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

### #252: a two-sided trail bound at n = 256

TODO #247 got proven optimal key-averaged trail weights to n = 64 and stopped.  This is the
remaining half.

**What exists.**  Proven optima 2.0 / 4.0 / 7.0 at r = 2/3/4, identical at n = 16, 32 and 64,
plus 10.0 at r = 5 for n = 16.  Identical values at three widths a factor of four apart is
strong evidence of width-independence.

**What does not.**  A bound at the deployed width, in either direction.  #247 initially
justified carrying the figure to n = 256 with a locality argument and **withdrew it**: the
optimal trail returned at n = 64 spans all 64 bit positions, so nothing demonstrates a narrow
optimum, and an embedding argument would also have to handle carry propagation past a window
boundary.

**Why CBC is not enough.**  n = 64 at r = 4 took 864 s; n = 32 at r = 5 and n = 64 at r = 4
under a shorter limit both returned untrustworthy answers, one of them a 4-round "optimum"
cheaper than its own 3-round optimum.  Scaling to 256 is not a matter of patience.

**Routes worth trying, in the order they should be tried.**
1. A stronger backend — HiGHS via scipy, or Gurobi under an academic licence.  Cheapest to
   attempt; may simply not close either.
2. A structural argument.  Either prove a narrow optimum exists (restoring locality and with
   it the embedding), or derive a per-round lower bound from the round function directly —
   each active round costs at least one bit unless the difference is MSB-only, and an MSB-only
   difference cannot persist through `M`, which is the germ of a wide-trail-style argument.
3. A matrix-power / transfer-matrix formulation over difference classes rather than
   individual differences, which is how some ARX bounds are made to scale.

Route 2 is the one that would actually settle it; routes 1 and 3 might only push the wall.

**First pass done in v5.0.5 — the bound is still open, and the stall is now explained.**  See
SecurityProofs-7.md §11.31 and `SecurityProofsCode/diff_bound_window.py`.

* **The target is a scalar**, `s_diff >= 4/3`, carried from #254's scale-invariance result.
  Not a bound at n = 256.
* **The stall was never solver time.**  An increment series has a cheap TRANSIENT (every key
  has a probability-1 one-round differential, so the first rounds are near-free) and a CEILING
  at ~`0.6n`.  The asymptote lives between them, and the window is `0.6n/s - transient` rounds
  wide: **zero or one round at every width an exhaustive DDT can reach** (n <= 13).  So the
  quantity is not measurable exhaustively at all, not merely slowly.
* **This invalidates the "what exists" paragraph above.**  The proven optima 2.0 / 4.0 / 7.0,
  identical at n = 16/32/64, are the TRANSIENT — width-independent for a structural reason and
  not the quantity the criterion needs.  Their agreement across widths was never the evidence
  it was read as.  Every per-round differential figure in this repo is affected.
* **Route 1 is re-motivated with a different target**: not a larger width but a larger ROUND
  COUNT at n = 32-64, where the window is wide and CBC already reaches.  Measured distance to
  that target: at n = 16, r = 4/5/6 prove in 8 s / 35 s / 365 s and r = 7 does not close in
  600 s; at n = 32, r = 4 and 5 prove in 68 s and 635 s and r = 6 does not close in 900 s.
  n = 32 r = 5 sits at `0.31n`, so the width is right and the ROUND COUNT is the whole gap —
  the target is r ≈ 10-14, several orders of magnitude away.  A stronger backend, not a longer
  time limit.  **This is now the first thing to try.**
* **The transient's width-independence is now directly confirmed**: n = 16 and n = 32 give
  identical proven optima at r = 4 and r = 5 (7.0 and 10.0) — the same agreement #247 saw and
  read as evidence about the asymptote.
* **Route 2 is demoted.**  As sketched it yields `s_diff >= 1` against a 4/3 criterion, so it
  cannot close the gap even fully proven, and the two-round strengthening it would need is
  contradicted by four consecutive near-free rounds measured at n = 11.
* **A weak-key lead, filed not concluded**: the per-key increment tracks the signed-digit (NAF)
  weight of `delta(B)`, not its Hamming weight (`d` and `-d` behave identically).  Whether the
  threshold is a constant NAF weight (density ~`2^-240` at n = 256, irrelevant) or scales with
  `n` (not irrelevant) is undetermined and is the part worth resolving.

**Revised route order: 1, then 3.**  Route 2 is set aside.

Status: **OPEN**

### #254: a linear-trail bound at realistic width — the binding axis for the NL-FSCX family

TODO #248 found that linear cryptanalysis, not differential, is the binding axis for both
NL-FSCX v1 and v2, and that nobody had measured it until TODO #247 §(c) — which was never
written up.  This is the item that closes it.  See SecurityProofs-7.md §11.29.4.

**What exists.**  Exact optimal linear-trail weights by fast Walsh-Hadamard transform plus a
dynamic program over mask states, at `n = 7, 8, 10`, on typical keys.  Slopes: v2 0.49–0.87
bits/round, v1 0.47–0.69.  Both rise with width.  The correlation-1 mask subspace has the
same `tz(delta)` structure #253 found on the differential side, and is equally harmless at
`n = 256` (about `tz/2` free rounds at probability `2^-tz`).

**What does not.**  Anything at a realistic width, on either primitive.  Projected over the
deployed round counts the measured range spans roughly 100–190 bits of correlation weight for
A2's 192 rounds; the bottom of that range is under the 128 a 256-bit block needs.  That is an
unmeasured quantity, not an attack — and the *rise* with width is the reassuring direction.

**Why it matters more than #252.**  #252 asks for a two-sided **differential** bound, on an
axis #247 already showed to be width-stable and #253 showed to be comfortable per-key.  This
axis is weaker in absolute terms AND its slope is not width-stable, so the extrapolation
everyone has been relying on is on worse ground here than there.  If only one of the two gets
done, it should be this one.

**Reach — four rows, three of them production-track.**  HSKE-NL-A2 and `twk` (demo-only,
gated on exactly this by #248), plus **HSKE-NL-A1, HFSCX-256** and everything inheriting the
hash: HPKS-WOTS, HPKS-XMSS, and every Fiat-Shamir transform in the suite.  #248 deliberately
did not re-rate the v1 rows on a slope read at `n <= 10`; this item is what would justify
moving any of them, in either direction.

**Both directions are live.**  If the slope at realistic width lands where the trend points,
A2 and `twk` meet the standard the six production-track rows in §11.29.2 meet and should be
promoted together.  If it does not, the v1 rows are the ones needing re-examination, and that
is the more consequential outcome — it reaches the hash.

**Method notes, so this does not repeat #247's wall.**  Widths where `M` is singular (`n = 9`,
12, 15, 18, ...) are not usable.  The exhaustive LAT is `2^2n` per key and will not reach far;
the routes worth trying are the linear analogue of #247's MILP formulation (correlation weight
is additive over rounds in the same way, so the same encoding shape applies), and the
transfer-matrix idea in #252's route 3, which suits masks at least as well as differences.

**First pass done in v5.0.4 — the bound is still open, but the target changed.**  See
SecurityProofs-7.md §11.30 and `SecurityProofsCode/fscx_scaling_and_linear.py`.

* **The question is a scalar, not a curve.**  Because `r = 3n/4` is tied to the block size, the
  criterion is *width-independent*: `s_lin >= 2/3`, `s_diff >= 4/3`.  So this item no longer
  needs "a bound at n = 256" — it needs the asymptotic per-round slope, establishable at any
  width where saturation is not binding.  That reopens widths this item had written off.
* **No key size moves it.**  n = 512 faces the identical criterion at 4x the cost per block.
  Recorded because it was a natural proposal and it does not work.
* **The MILP route named above is CLOSED**, and not for want of solver effort: addition of a
  *constant* has correlations that are not powers of two, so Wallén's characterisation and every
  ARX bit-level encoding built on it are inapplicable.  A carry-automaton model computes single
  paths where the true correlation sums them, overstating the weight — built and discarded
  before it could be quoted.  **The transfer-matrix route is now first choice**, and it suits
  masks better than differences: mask propagation through `M` is deterministic, so a trail is
  fixed by its starting mask and the search is over `2^n` starting masks rather than trails.
* **Saturation invalidated the earlier numbers**, #248's included.  Corrected, the slope is
  0.42 / 0.77 / 0.88 / 1.03 at n = 7 / 8 / 10 / 11, crossing 2/3 between 7 and 8 and clearing it
  by 55% at the widest.  Encouraging; four widths with the slope still rising is not a bound.
  **Re-corrected in v5.0.5 (#252 §11.31.5)** for the TRANSIENT as well as the ceiling — the
  figures above were read at r = 3-5, partly inside it.  Settled: 0.59 / 0.75 / 0.93 / 0.95.
  The conclusion is unchanged (every width above n = 7 clears 2/3), but **"the slope rises with
  width" is weakened**: settled it is flattening, +0.03 between the two widest against +0.16
  between the two narrowest.  Do not expect wider widths to keep improving.
* **#248's "linear is the binding axis" is withdrawn** — the thresholds differ by the same
  factor of two the slopes do, so the raw comparison was never normalised.  Normalised,
  differential is the tighter axis, which raises #252's priority relative to this item.

**What remains, in priority order.**  (1) The two modes: §11.30.1 is derived for a block cipher
and does **not** transfer unexamined to HSKE-NL-A1 (counter-mode PRF) or HFSCX-256
(Davies–Meyer), each of which runs `n/4` rounds; deriving their criteria is the part of this
item that reaches three production-track rows.  (2) The transfer-matrix bound on `s_lin`.
(3) The same treatment for `s_diff`, which is #252 — and by the correction above, #252 is now
the more urgent of the two.

Status: **OPEN**

### #255: NL-FSCX v3 — ship candidate B as a new primitive alongside v2

TODO #251 declined to migrate v2 to candidate B, on the grounds that a five-construction
MAJOR is not warranted against a deployed round that passes every test that exists.  This is
the alternative it named: **add** the design rather than **replace** with it.

**Why this shape is better than #251's.**  Nothing breaks.  `v2` is untouched, so every stored
key, ciphertext and signature keeps working and `MIGRATING.md` is not involved.  The change is
additive CLI/API surface, so it is a **MINOR**, not a MAJOR.  It is reversible: a v3 that turns
out badly can be deprecated without stranding anyone.  And it decouples the design question
(is B better? — answered, §11.32) from the deployment question (must everyone move? — no).

**What v3 is.**  The deployed v2 round followed by a χ layer over short odd rows,
`256 = 47×5 + 3×7` — fifty parts, all odd, so χ is a bijection over the whole state; inverse
degree ≤ 4, bit-parallel; inside the regime Keccak's own analysis covers.  This is candidate B
exactly as #246 specified and §11.32 re-validated; **no redesign is in scope here.**

**Round count must be DERIVED, not inherited — and it may go down.**  χ changes the per-round
weight, so `R_VALUE = 3n/4` carries no justification for v3.  Use §11.30.1's scale-invariant
criteria: safety needs `s_lin · r >= n/2` and `s_diff · r >= n`.  §11.32 measures v3's
round-1/early weights at roughly 2-3× v2's, so the honest expectation is that v3 needs
materially fewer than 192 rounds — possibly enough to offset the +57% per-round cost outright,
making v3 no slower than v2 and stronger.  **Determine this before choosing constants**; do not
assume either direction, and state the margin chosen.

**Weak-key classes need re-deriving, and two may simply vanish.**  Both known v2 classes are
artefacts of the round being linear-then-add-constant, which v3 is not:

* the affine class `delta(B) ∈ {0, 2^(n-1)}` (§11.19.2) — v2 degenerates to affine there, but
  χ is non-linear, so v3 plausibly does not.  If so, v3 needs no `nl_v3_key_is_valid` at all.
* the zero-weight-trail class `tz(delta(B)) >= 4` (§11.28.3) — this is the MSB freebie, and
  §11.32.3 measured v3's round-1 weight at 1.81-2.00 where v2's is 0.00, so it is already
  known to be gone.

Verify both rather than assuming; a *new* weak class specific to χ is also possible and must
be looked for.

**Scope — what gets a v3 consumer.**  The same five v2 consumers, each as a new variant with
the v2 one left in place:

| existing | new | surface |
|---|---|---|
| `hske-nla2` | `hske-nla3` | `--algo` |
| `hpke-nl` | `hpke-nl3` | `--algo` |
| `hske-duplex` | `hske-duplex3` | `--algo` |
| `fpe` | `fpe --v3` | flag on the subcommand |
| `twk` | `twk --v3` | flag on the subcommand |

`fpe`/`twk` take a flag rather than new subcommands because they are already filed under
`cli_binding` in `spec/` rather than under an `--algo` tag.  Decide the flag-vs-subcommand
question explicitly and record it; either is defensible.

**Out of scope, explicitly.**  NL-FSCX v1 and everything on it (HFSCX-256, HSKE-NL-A1, WOTS,
XMSS, every Fiat-Shamir transform) — v3 does not touch v1.  The classical quartet.  Key
exchange (#230's impossibility is about HKEX agreement and does not arise).  Arduino and
assembly, following #242 and #245: separate 32-bit construction, no wire compatibility, and
adding a second primitive there is a cost with no consumer.

**Ratings — v3 does NOT arrive production-track.**  This is the trap #237, #238, #243, #244 and
#248 were each filed to close.  v3 has a wider margin than v2 but the same *missing* items:
no PRP/SPRP reduction, and no trail bound at realistic width on either axis (#252, #254 are
unchanged by v3 existing).  **Ship v3 demo-only**, with a row saying precisely that its margin
is wider and that the same two measurements are outstanding.  A promotion is #248-shaped work
on separate evidence.

**Must land with it.**
* C (`herradura.h`), Go, Python and Java in lockstep — `nl_fscx_v3`, `nl_fscx_revolve_v3`, its
  inverse, and the key check if §above finds one is needed.
* `spec/` entries and `SECURITY.md` rows for all five new variants; `spec/check_security_md.py`
  and `generate_spec.py --check --require-schema` must pass.
* KAT vectors for v3 in `KAT/`, generator updated, `--check` current; `verify_kat.go` and the
  Java `KatVerify` extended.
* `CliTest/` coverage: every new script claimed by exactly one `native-*` job, or the
  coverage-guard step fails.  `test_cross_lang_matrix.sh` extended to the v3 family.
* Tests in all four harnesses; the `[FAIL]`-scanning gate picks them up with no registration.
* `docs/TUTORIAL.md`, `llms.txt`'s CLI section, and this file's CLI/test sections (TODO #145).
* A benchmark against v2 at the derived round count, since the cost question is live.

**Version.**  MINOR — new `--algo` values and new public API, no existing surface changed.

**Do not start** until the round count is derived; every other step depends on it.

Status: **OPEN**
