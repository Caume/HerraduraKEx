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

**Second pass done in v5.2.1 — the MEASUREMENT PROBLEM IS SOLVED; only the width
extrapolation is left.**  See SecurityProofs-8.md §11.35 and
`SecurityProofsCode/diff_cycle_mean.py`.

* **The first pass's central conclusion is WITHDRAWN.**  §11.31.2 said the asymptotic
  increment "is NOT MEASURABLE BY EXHAUSTIVE SEARCH AT ANY REACHABLE WIDTH -- not slowly,
  but at all".  That is true of reading a slope off a finite increment series, which is what
  every pass had done, and false of the asymptote.  `s_diff` is the **MINIMUM MEAN CYCLE** of
  the difference graph -- nodes are differences, `a -> b` weighted `-log2 xdp(M(a) -> b)`,
  and `W(r) = c + mu*r + o(1)`.  The transient IS the constant `c` and cancels in a cycle
  mean; the ceiling is a statement about a codebook and a cycle is not compared to one.
  Both brackets dissolve rather than being defeated.
* **Exactly computable, and computed.**  Howard's policy iteration, cross-checked against
  Karp's theorem and against value iteration run far past the ceiling -- seven cases, three
  methods sharing no machinery, agreement to 1e-9.
* **The numbers, per key, at every usable width** (n = 9, 12 excluded: M singular).  Median
  `mu` = 1.279 / 1.349 / 1.717 / 1.903 at n = 7 / 8 / 10 / 11: **monotone rising**, clearing
  the 4/3 criterion from n = 8 on, with the fraction of keys below it **monotone falling**,
  63.4% -> 27.3%.  Every key measured already passes the deployed `nl_v2_key_is_valid`.
* **A tail remains and is documented, not screened**, following #253's disposition: p10 is
  below the criterion at every width, and thinning more slowly than the median rises.
* **#247 §(d)'s "3.0 bits per round" is corrected.**  The r = 3..5 read misses the exact
  key-averaged asymptote by -7% to +17% with **no consistent sign**, so 3.0 is not a
  per-round increment and the 256/3 = 86-round projection has no support.  §11.28.6's
  separate claim that the per-key figure is about half the key-averaged one SURVIVES and is
  now measured directly: 1.717 / 2.751 = 0.62 at n = 10.
* **Route 1 is quantified and CLOSED.**  HiGHS beats CBC by 1.4x at r = 4 and by more than
  3.7x at r = 5, and proves n = 32 at r = 5 (weight 10.0) and r = 6 (weight 14.0), which CBC
  could not -- two new rows for #247's width-agreement table.  But growth is 3.6-4.0x per
  added round with no flattening, so r = 10-14 is four to seven orders of magnitude away.
  It is closed because the target was unnecessary, not because it failed: r = 10-14 existed
  only to open a window, and there is no longer a window to open.  **Route 3 is superseded**
  -- it was proposed to make the computation scale, and Howard's already does.
* **A caution for the remaining work:** embedding is the obvious tool for relating widths and
  it points the WRONG WAY.  A surviving-cycle argument would prove `mu` non-increasing, and
  widening also adds candidate cycles, so the naive count points down too.  `mu` rises
  anyway, so the rise comes from width DESTROYING cheap cycles and a structural proof must
  explain that first.

**What is left, and it is the whole of what is left: the width extrapolation.**  `mu` is
exact at the width measured and cannot be read at n = 256 -- the graph has `2^n` nodes, so
the exhaustive-DDT wall that stopped every previous pass stops this one too.  But the
residual question is now the limit of a monotone sequence of EXACT values rather than a
slope read through two sources of contamination.  Cheapest next steps: extend to n = 13 and
n = 14 (cost is the DDT's `2^2n`, not the cycle computation); and carry the same
reformulation to the LINEAR axis, which is #254 and where mask propagation through M is
deterministic, so it should transfer more cleanly still.

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
