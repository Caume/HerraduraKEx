# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #249: finish the constant-time audit scope TODO #129 opened

`SecurityProofs-7.md` §11.16 records that TODO #129's original item-2 scope was never
completed, and names what is outstanding.  It has sat unfiled across several batches.

* **`stern_apply_perm`'s memory-access pattern**, flagged in Batch 2 and still unaddressed.
* **A residual timing signal** that survived the absolute-gap collapse and interop re-test.
  Chasing it needs cache/power instrumentation — hardware performance counters, or a
  controlled non-degenerate "fixed" class — which a wall-clock `dudect` harness cannot
  provide.  Decide whether to acquire that capability or to document the limit and stop;
  either is a defensible close, silence is not.
* **HKEX-RNL, ZKP-RNL and HCRED are entirely unaudited** for constant-time behaviour.  They
  fall inside #129's stated scope and no batch has touched them.

**Worth stating plainly:** this is the one open item that concerns a side channel rather
than a structural property, and side channels are the class this suite has audited least.
`SECURITY.md` should say so if the answer is "not audited".

Status: **OPEN**

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

### #251: ship the AND-based nonlinear layer for NL-FSCX v2 (migration)

TODO #246 decided the design and could not ship it.  This is the migration, held back
deliberately rather than for lack of work done.

**What ships, if it ships.**  Candidate B: the deployed v2 round followed by a χ layer over
short odd rows, `256 = 47×5 + 3×7` — fifty parts, all odd, so χ is a bijection over the whole
state; inverse degree ≤ 4, bit-parallel; inside the regime Keccak's own analysis covers.  The
existing round is untouched and χ is appended, which is the smallest diff that achieves the
goal.  Identically in C, Go, Python and Java.

**Why it is blocked, and this is the point of the item.**  #246 step 3 named a realistic-width
bound as the condition for shipping, and TODO #247 established that condition cannot currently
be met: CBC proves optima only to n = 64, and #247 further found the dominant uncertainty is
the **key-averaged/per-key gap**, not width.  All the evidence favouring candidate B is
small-width and comparative.  Shipping a new round function on that basis would be exactly the
under-evidenced move TODO #237, #238, #243, #244 and #245 exist to prevent — with the
aggravating factor that it is a five-construction MAJOR.

**Unblocked by** either #252 (a two-sided bound at n = 256) or #253 (a fixed-key treatment
showing the per-key gap does not sink the margin), or by a decision to accept small-width
comparative evidence as sufficient — which is a legitimate call, but must be made explicitly
and recorded, not arrived at by default.

**Reach.**  `hske-nla2`, `hpke-nl`, `hske-duplex`, `fpe`, `twk` — the same five as TODO #245.
One MAJOR, one `MIGRATING.md` section, and the silent-failure warning `fpe`/`twk` need, since
both are unauthenticated permutations.  Arduino and assembly stay unchanged, as in #242 and
#245: separate 32-bit construction, no wire compatibility.

**Must land with it.**  Round-count re-derivation (χ changes the per-round weight, so 192 is
no longer justified by inheritance); masked-cost measurement on AVR; a KAT refresh; and the
regression tests that already exist for `fpe`/`twk` extended to the new layer.

**Explicitly not in scope.**  Re-rating anything.  That remains #248.

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

Status: **OPEN**
