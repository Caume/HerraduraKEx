# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #248: re-review the v2 family ratings once #245's successors land

TODO #245 shipped round constants and deliberately did not re-rate anything, on the grounds
that removing a structural objection is not supplying a proof.  It named this successor in
its own text and in SecurityProofs-7.md §11.27.4.

**The question.**  HSKE-NL-A2 (downgraded to demo-only by #244) and `twk` (kept demo-only by
#243) both rest on `nl_fscx_revolve_v2` being a PRP/SPRP.  #245 removed the self-similarity
objections — the slide structure and the fixed-point deviation are gone — so the trail bounds
are now the binding constraint.  Do they bind tightly enough to move either rating?

**Gated on evidence, not on time.**  This item must not run until the evidence exists.
Opening it earlier would repeat exactly the error #244 was filed to correct: treating "the
objections I know about are answered" as equivalent to "analysed".

**Amended after TODO #247: the gate is not the one this item was filed with.**  As written
above, this item assumed the blocker was width extrapolation — bounds at n = 256 rather than
projections from small widths.  #247 measured that and found the opposite: the trail slope is
width-stable at 1.40–1.70 across every reachable width, bracketing #214's 1.87, so the width
extrapolation is in better shape than anyone assumed.  What #247 *did* surface is a larger
problem — real keys sit at roughly **half** the key-averaged trail weight, with a per-key
spread wider than the mean.  Halving #247's proven 3.0 bits/round puts the per-key
requirement above 170 rounds and makes the deployed 192 marginal.

So the binding gate is **TODO #253** (fixed-key trail analysis), not #252 (the two-sided
bound at n = 256).  #252 would be welcome and would tighten the picture, but a two-sided
*key-averaged* bound would not answer the question this rating actually turns on.  If #251
ships the AND layer, the analysis must be redone against the round function that ships.

**Re-derive, do not inherit.**  Whatever the outcome, A2's three constraints and `twk`'s
must be re-derived against the then-current construction.  #237 and #238 exist because
propagated rows go stale.

**Both directions are live outcomes.**  A promotion is possible.  So is confirming
demo-only, in which case the useful deliverable is a row that says precisely what is missing
rather than one that reads as an unexplained caution.

Status: **OPEN**

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

### #253: fixed-key trail analysis — the gap #247 found is the dominant uncertainty

TODO #247(b) measured what TODO #214 had flagged qualitatively, and it is larger than the
thing everyone has been caveating.

**The finding.**  Optimal 5-round trail weight at n = 11 ranges from **0.70 to 7.71 across
six keys, on a mean of 4.73** — a spread wider than the mean.  And the key-averaged model
systematically overstates: real keys sit at roughly **half** the averaged trail weight
(per-key DP 0.41 / 1.88 / 3.40 at r = 2/3/4, n = 10, against a key-averaged 1.80 / 3.43 /
5.82).  Halving #247's proven 3.0 bits/round puts the per-key round requirement above 170 and
makes the deployed 192 **marginal rather than comfortable**.

**Why it bites here specifically.**  NL-FSCX has no key schedule: the same `B` is the XOR mask
in every round, so per-round deviations correlate instead of averaging out.  A key-averaged
bound is the right currency for comparing designs — it is what ARX practice reports and what
#214 correctly produced — but it is not a per-key security claim, and for this construction
the two differ by more than a caveat's worth.

**What to establish.**
* Whether the ~2× gap persists at larger widths, or is a small-width artefact.  This is the
  first question and it may dissolve the item.
* The shape of the weak tail: is there an identifiable class, as with the QC-MDPC weak keys
  TODO #235 screened, or is it a smooth distribution with no screenable structure?
* If there is a class: whether a keygen screen is possible.  Note `nl_v2_key_is_valid` covers
  only the degenerate affine class and says nothing about trail behaviour.
* If there is not: whether the honest figure for `SECURITY.md` is the weak-tail value rather
  than the mean.

**Why it is filed separately from #248.**  #248 is the rating decision; this is the evidence
it needs.  #248's own text currently assumes the open question is width extrapolation, which
#247 showed it is not — that text is amended to point here.

**Blocks** #248, and informs #251: if the per-key gap is real at scale, it is an argument for
the AND layer rather than against it, since candidate B's margin is far wider.

Status: **OPEN**
