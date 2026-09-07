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
alongside a QC-MDPC parameter change, and close to worthless before one.

**That parameter item now exists: TODO #276.**  Until it was filed, this entry was gated on
something nobody had written down, which is its own failure mode -- a conditional item whose
condition is not itself tracked is indistinguishable from an abandoned one.  #250 stays
deprioritised behind #276 and should be re-pointed at whatever parameters #276 selects, since
a decoder comparison at `r = 523` measures the wrong instance.

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

**Item (1) is CLOSED as posed (v6.5.7).**  See SecurityProofs-9.md §11.39 and
`SecurityProofsCode/pair_correlation_second_moment.py`.  #257 was right that it needed
no new machinery: the whole pair correlation is one ratio, R(t) = M(2t)/M(t)^2, because
a shared edge contributes M(2t) to the joint exponential moment where independence
would give M(t)^2 -- and M(2t) is a higher rung of the SAME A_t ladder (t* = 3
differential needs A_6; t* = 4-6 linear needs A_8..A_12, both already inside TD/TL).

  * **The ratio that matters is R/E, and it is LINEAR IN n:** log2(R/E) ~ -0.653n
    differential, -0.917n linear, over n = 10..256 on both axes.  R alone is enormous
    (2^226 at n = 256) but the edge count grows faster.  L enters only as 2*log2(L), so
    ANY polynomial cycle length is swamped -- even the absurd L = n^2 only shifts the
    curve by a constant.
  * E[N^2]/E[N]^2 = 1 + 2^-151 (differential) and 1 + 2^-219 (linear) at n = 256.
    Within the annealed ensemble the first moment is NOT carried by rare graphs, which
    is exactly the objection item (1) raised.
  * **It also explains the gap it was asked about.**  §11.38 reported the model 3-15%
    BELOW exact mu at n <= 13 "and converging upward" with no account of why.  The
    correction crosses 1 at n ~ 11-12 and is O(1) across n = 10..13 -- the entire range
    where exact mu exists, and nowhere above -- and its SIGN matches: an over-count
    inflates E[N], moving the E[N] = 1 crossing to a cheaper threshold, so the model
    runs low.  The discrepancy is a property of the validation range, not of the model.
  * Validated against a brute-force enumeration of the whole edge set at n = 6..9, four
    addends each: edge counts exact, every moment and R to 4e-15.

**What is left.**  (1') The residue of item (1): this is CONCENTRATION OF AN ANNEALED
ENSEMBLE, not a bound on the deterministic object.  It says the ensemble's typical
member is representative; it does not say one fixed round function is a typical member.
That is a QUENCHED argument and none is attempted, so §11.38's n = 256 figures remain an
exactly-evaluated ESTIMATOR -- now with its internal consistency established rather than
assumed.  (2) The LINEAR HULL, unchanged from §11.36.9: a trail statement is not a hull
statement, and nothing in this line of work reaches the hull.

**Reach.**  No production-track row.  HSKE-NL-A2 and `twk` are demo-only for reasons on
other axes (#243, #244, #248), and #254's three production-track rows -- HSKE-NL-A1,
HFSCX-256 and everything inheriting the hash -- left the scope of a trail bound entirely
in §11.36.8, because in both those modes the attacked input is the round CONSTANT, which
enters every round at once, so there is no trail to bound.  This item can therefore move
no rating in either direction, and is filed as an outstanding proof obligation behind
figures already published, not as a gate on anything.

Status: **OPEN**

### #276: move HPKE-Stern-KEM to a parameter set that reaches a stated security level

**This is the parameter item TODO #250 is explicitly waiting on.**  #250 asks whether the
near-codeword-aware and failure-recycling BGF variants close the DFR gap, and answers its
own question about timing: "a decoder improvement that leaves `r = 523` in place cannot
deliver `2^-128` on its own ... worth doing alongside a parameter change, and close to
worthless before one."  Nothing has filed that parameter change until now, so #250 has
been gated on an item that did not exist.

Same shape as TODO #223, which did this job for HKEX-RNL: #216 measured the deployed ring
at ~32 Core-SVP bits against a 128-bit claim, and #223 then rejected n=768 on a structural
ground, measured the DFR floor, and landed on n=1024.  `SecurityProofsCode/rnl_parameter_selection.py`
is the model for what closing this looks like.

**What is already established, so it is not re-derived** (SecurityProofs-5.md §11.8.7,
`SecurityProofsCode/qcmdpc_dfr_weak_keys.py`):

* Deployed: `r = 523`, `d = 15`, `t = 18`, `NB_ITER = 20`, identical in all four languages.
  The source itself calls them toy parameters.
* Measured DFR **0.264% = 2^-8.6** over 120,000 round trips, where IND-CCA2 wants `2^-128`.
* Holding `d` and `t` fixed, `log2(DFR) = -0.0996r + 43.69` (R^2 = 0.985) puts `r ~ 1723` at
  `2^-128` -- but that is a **LOWER BOUND**, not an estimate, for two reasons both pointing
  the same way: the DFR curve is concave (every fitted point is in the waterfall, none in
  the error floor), and the fit says nothing about whether `r` is the right knob, since
  BIKE-128 reaches its DFR through `r`, `d` and `t` together.
* BIKE-128, the closest standardised comparison: `r = 12323`, `w = 142` (`d = 71`),
  `t = 134`.  §11.8.5 already records that the PRF substitution leaves the QCSD instance
  unchanged, "so BIKE's production parameters carry over directly".

**THE FIRST QUESTION IS NOT `r`, AND IT HAS NO ANSWER ON RECORD.**  §11.8.7 and SECURITY.md
both say the underlying QC syndrome-decoding instance at these parameters is "far below any
usable security level" -- with **no number anywhere**.  The only concrete figure in the
neighbourhood is a brute-force count, `C(1046,18) ~ 2^124`, which is not an attack cost.
The repository does carry a concrete ISD estimate -- `2^56`-`2^60` classical, `2^30`-`2^40`
quantum (§11.8.3, BJMM/Kirshanova) -- but it is for a DIFFERENT instance: the Stern-F
SIGNATURE at `(N, k, t) = (256, 128, 16)`.  The KEM is `(N, k, t) = (1046, 523, 18)` and has
none.  Nor can the signature's be scaled to it: §11.8.3's own caveat says the asymptotic
exponents "apply in the regime where `N` is large and the rate `k/N` and relative distance
`t/N` are fixed", and the KEM's `t/N` is an order of magnitude smaller (`18/1046` against
`16/256`), which is the regime where ISD is cheapest per bit.  Naively applying `2^(0.054N)`
to `N = 1046` gives ~56 bits and is exactly the extrapolation that caveat forbids.  Until a
real estimate exists, "raise `r` to 1723" is unjustified -- `r` is the DFR knob, and if the binding
constraint is ISD then `d` and `t` move too, which is exactly how BIKE-128 differs from a
scaled-up 523.  So the item starts by computing what the deployed instance is actually
worth, classically and quantumly, against the estimators §11.8.3's table already names
(Prange/BJMM, Kirshanova).  That number decides whether this is a retune or a wholesale
adoption of BIKE-128, and it is cheap to produce.

**Cost class: MAJOR, with a `MIGRATING.md` entry.**  `r` sizes the wire format --
`QCMDPC_RBYTES = (r+7)/8 = 66` today -- so every HPKE-STERN-KEM key and ciphertext, and
every HYBRID-RNL-STERN artifact that carries one, becomes unreadable.  #223's own migration
is the precedent for how that is written.  This is not a reason to defer: the row is
demo-only, so no deployment is being broken, and the artifacts have no compatibility claim
to keep.

**What moves with the parameters, and is easy to miss:**

* **The weak-key screen's bound.**  `QCMDPC_MAX_MULT = 5` was read off a measured cliff --
  multiplicity 6 is where DFR first departs from the ordinary rate -- and that cliff was
  measured at `d = 15`, `r = 523`.  At new parameters the multiplicity distribution and the
  cliff both move, so the constant must be **re-measured, not carried over**.  It is
  duplicated in all four languages (`herradura.h`'s `QCMDPC_MAX_MULT`, Go's unexported
  `qcMdpcMaxMult`, Python's `_QCMDPC_MAX_MULT`, `Stern.java`'s `QCMDPC_MAX_MULT`).  The manifest pins the
  FUNCTION `qcmdpc-max-multiplicity` in all four, but nothing anywhere compares the
  CONSTANT'S VALUE across them -- `spec/`'s parameter block reads `herradura.h` alone -- so a
  partial update would not be caught by any existing check.
* **Test [51]** pins its distance-spectrum supports at `QCMDPC_D = 15`, with the accept case
  sitting exactly ON the threshold, and C's `qcmdpc_key_is_strong` takes a fixed-width
  `QcMdpcPriv`.  New `d` means new pinned supports in four languages plus a C struct change.
* **`CliTest/lib_dfr.sh`.**  Its retry policy exists because the DFR is high enough to be hit
  in ordinary testing.  At a DFR near the target the retries become dead code -- which is
  fine, but the guard in `ci.yml` that requires every decapsulating script to source it
  should then be re-justified rather than left asserting something vacuous.
* **`spec/`, `SECURITY.md`.**  The demo-only classification and its stated reasons are
  checked against each other by `spec/check_security_md.py`, so the row cannot be moved in
  one place only.
* **Cost.**  Decapsulation is ~9 ms in Python at `r = 523`; BIKE-128's `r` is 23.6x larger
  and the decoder is superlinear.  Whether the Python CLI remains usable at the chosen
  parameters is part of the choice, not a discovery to make afterwards.

**Acceptance.**  A script in `SecurityProofsCode/` following #223's shape: the ISD cost of
the deployed instance stated with its estimator; a candidate set with its DFR **measured**
rather than extrapolated where that is affordable, and its extrapolation labelled a bound
where it is not; the weak-key cliff re-measured at the chosen `d`; and a recorded reason for
rejecting the alternatives considered, including plain adoption of BIKE-128.  It exits
non-zero if a finding stops reproducing, as the other analysis scripts do.  On landing,
#250 becomes worth running and should be re-pointed at the new parameters.

---

**FIRST PASS (v6.5.8): the selection is settled; the port is not.**

`SecurityProofsCode/qcmdpc_parameter_selection.py` and SecurityProofs-5.md §11.8.9 close
the *analysis* half of this item.  **Adopt BIKE-128 verbatim: `r = 12323`, `d = 71`,
`t = 134`, with BIKE's threshold rule and `NbIter = 5`.**  What that pass established, so
the port does not re-litigate it:

* **The deployed instance is worth ~`2^21` classical**, Dumer with the quasi-cyclic
  speedups, calibrated against BIKE's three published levels (+8.0 bits, spread 0.9 over a
  3.3x range of `r`).  That is the number this item said had no answer on record.  It is
  *below* §11.8.3's `2^56`-`2^60` for the Stern-F signature despite four times the length.
  (This item's own text called the relative-distance gap "an order of magnitude"; it is
  3.6x.  The conclusion is unchanged and the overstatement is corrected in §11.8.9.)
* **`t` and `d` are set by ISD essentially independently of `r`; `r` is then set by DFR
  alone.**  Min `t` moves by 6 and min `d` by 2 over a 12.3x range of `r`.  So the
  hypothesis in this item's opening -- that `r` alone cannot be the answer -- is now a
  measurement, and #218's `r = 1723` buys **four bits** with `d` and `t` unchanged.
* `r = 1723` is **separately inadmissible**: `ord_2(1723) = 574`, not 1722, so `x^r - 1`
  has four irreducible factors over GF(2) and the ring has proper quotients -- the same
  class of structural defect that made #223 reject `n = 768`.  Any candidate `r` must be
  checked there first.  (`8191` fails the same way.)
* At `r = 12323` the ISD frontier lands on **exactly** BIKE-128's `(t, d) = (134, 71)`,
  from an independent direction.  There is nothing left to choose, which is why inventing
  a set is rejected: `r`'s only remaining job is the DFR, the one quantity this repository
  cannot measure and BIKE has published.

**Two things the analysis found that this item did not anticipate, and which the port must
carry:**

* **The threshold rule is a FUNCTION, not a constant.**  BIKE's is affine in the *syndrome
  weight*; the deployed one is affine in `d` and ignores the syndrome entirely.  Each fails
  outright at the other's `d` -- BIKE's floor of 36 exceeds a `d = 15` row, and the
  deployed rule stalls at 47-of-71 as the syndrome thins.  Measured at `(12323, 71)`: the
  adaptive rule takes 30 failures across the transition against 114, at **four times fewer
  iterations**.  The DFR claim belongs to BIKE's decoder, not to BIKE's `(r, d, t)` under
  an arbitrary one.  `NB_ITER` 20 -> 5 comes with it.
* **The shipped Python decoder is a blocker, not a cost line.**  It computes its
  unsatisfied-parity counts in an interpreter loop over `r * d` positions: 5.4 s per
  decapsulation at `r = 12323` against 16 ms today.  Not intrinsic -- the bit-sliced
  representation the analysis uses does the same instance in 8 ms in the same interpreter
  -- but the rewrite is a **prerequisite**, not a follow-up.  C and Go need no
  representation change; C's `qcmdpc_bgf_decode` does grow to ~123 KB of stack work arrays
  from ~7 KB, which is fine but should be a deliberate decision.

**The FSCX layer carries it, with a ceiling one level up (now TODO #277).**  §11.8.5's "BIKE's production
parameters carry over directly" is a claim about the *instance*, not the sampler, and was
never checked against the sizes.  `qcprf_uniform_idx` draws **16-bit** words, and
encapsulation samples modulo `2r`, not `r`: BIKE-128's 24646 is accepted 75% of the time,
BIKE-192's 49318 is the last multiple that works at all, and BIKE-256's 81946 gives
`lim = 0` and a **non-terminating** rejection loop (`w >= 0` is vacuously true for a
`uint16_t`).  So BIKE-256 would need the PRF widened to 32-bit words -- not a reason against
BIKE-128, but a limit invisible from the parameters, and **TODO #277** owns it -- including
the guard, which is worth landing whether or not this item's parameter change ever does,
since today the overflow HANGS rather than erroring.  Output volume rises ~6x, 2 blocks per
operation to 10-12.  And the *shipped* sampler's supports are not distinguishable from the
ideal ones the `MAX_MULT` figure was read off (two-sample chi2 held to 6x its dof), so that
constant transfers rather than needing re-derivation against the FSCX PRF.

**One acceptance criterion is NOT met, and cannot be.**  This item asked for "the weak-key
cliff re-measured at the chosen `d`".  #218 could locate that cliff at `r = 523` precisely
*because* the DFR was `2^-8.6`; at the new parameters the measurement that justified
`QCMDPC_MAX_MULT` is the one the parameter change exists to eliminate.  A surrogate is used
instead, stated in advance rather than fitted -- keep the screen a tail cut costing under
one keygen retry in 200 -- giving **`QCMDPC_MAX_MULT = 6`**, recorded as a retry-budget
choice and not as a cliff.  (An exact quantile match to the deployed 0.03% was tried first
and discarded: it sits at the sampler's resolution floor and flips between 6 and 7 with the
trial count.)  The cliff question passes to #250, which owns decoder behaviour.

**What remains, to close this item.**  The port itself, MAJOR, with a `MIGRATING.md` entry:

* the four constants in four languages, plus `QCMDPC_RBYTES`/`RWORDS` following `r`;
* the threshold rule and `NB_ITER` in four languages;
* the Python decoder rewritten bit-sliced, first;
* `QCMDPC_MAX_MULT` 5 -> 6, in four languages that nothing cross-checks (`spec/` reads
  `herradura.h` alone);
* test [51]'s pinned distance-spectrum supports, all at `d = 15`, in four languages, plus
  C's fixed-width `QcMdpcPriv`;
* `KAT/` for any pinned Stern-KEM artifact;
* `CliTest/lib_dfr.sh` -- its retries become dead code, which is the desired end state, but
  `ci.yml`'s guard then mandates sourcing a policy that can never fire and should be
  re-justified rather than left asserting nothing;
* `spec/` and `SECURITY.md`, held to each other by `check_security_md.py`;
* the `.s`/`.asm`/`.ino` targets stay at `r = 32` and are labelled demo-only, as #223 did.

Status: **OPEN**

### #277: widen the QC-MDPC index draw past 16 bits

TODO #276 §8 found the ceiling: `qcprf_uniform_idx` draws **16-bit** words and rejects above
`lim = floor(65536/m)*m`.  Keygen samples modulo `r`, but **encapsulation samples modulo
`2r`**, which is the binding one and the one nobody would think to look at.

| modulus | | 16-bit `lim` | acceptance |
|---|---|---|---|
| deployed encap | `2r` = 1046 | 64852 | 98.96% |
| BIKE-128 encap | `2r` = 24646 | 49292 | 75.21% |
| BIKE-192 encap | `2r` = 49318 | 49318 | 75.25% — the last multiple that works at all |
| BIKE-256 encap | `2r` = 81946 | **0** | **0% — non-terminating** |

**The defect is the failure MODE, not the ceiling.**  Above 65536 there is no guard anywhere
in any of the four languages: `lim` is 0 and the rejection loop spins forever.  In C it is
`do { w = qcprf_word16(prf); } while (w >= lim);` on a `uint16_t`, where `w >= 0` is
vacuously true, so the compiler is entitled to assume the loop never exits.  Python's
`while True: ... if w < lim` is the same shape.  A caller who raises the parameters gets a
hang with no diagnostic, not an error.

**Two parts, and the first is worth doing on its own.**

1. **Guard it now**, independently of any parameter change and independently of #276
   landing.  A `lim == 0` check that raises is three lines per language and converts a hang
   into a message.  The suite already has the right pattern one file over:
   `_stern_random_weight_t` uses 4-byte rejection and *documents* its domain -- "eliminates
   modular bias for any n <= 2^32".  The QC-MDPC sampler is the only one of the four
   sampling sites in the suite with an undocumented ceiling.
2. **Widen the draw**, which is what actually unblocks BIKE-192 and BIKE-256.

**Widening is not free, and the arithmetic is counter-intuitive.**  A 256-bit PRF block
yields 16 words at 16 bits but only 8 at 32, while acceptance rises from 75% to 99.9998%.
Net, at BIKE-128, the blocks per operation go **up**:

| | 16-bit | 32-bit |
|---|---|---|
| keygen (142 indices mod `r`) | 151 draws, 10 blocks | 142 draws, **18 blocks** |
| encap (134 indices mod `2r`) | 178 draws, 12 blocks | 134 draws, **17 blocks** |

So "widen to 32 bits" costs ~50-80% more `nl_fscx_revolve_v1` invocations at the parameters
#276 recommends, buying headroom that BIKE-128 does not need.  **24-bit draws are the
natural middle** and already have precedent in this suite -- `_rnl_rand_poly` uses 3-byte
rejection sampling for `Z_q` -- giving ~100% acceptance to 2^24 = 16.7M (well past
BIKE-256's 81946) at 10 words per block, so ~14 blocks.  Sizing the draw from the modulus
(`ceil(log2(m)/8)` bytes) is the general form and costs nothing at the deployed parameters.
Pick deliberately; do not reach for 32 because it is the round number.

**Scope.**  Four languages (`herradura.h` `qcprf_uniform_idx`, Go, Python `_QcMdpcPrf`,
`Stern.java`).  Changing the draw width **changes the keystream consumption pattern and
therefore every key and error vector a given seed produces**, so it is KAT-breaking for any
pinned QC-MDPC artifact even though it is not wire-format breaking.  Doing it in the same
release as #276's parameter change costs nothing extra; doing it separately means two
regenerations of the same vectors.  Note also `uint16_t sup0[QCMDPC_D]` and
`uint16_t sup_e[QCMDPC_T]` in C, which independently cap `2r` at 65536 and must widen with
the draw or the ceiling simply moves one line down.

Status: **OPEN**

### #278: the width axis — which primitives cap the security parameter, and do the four languages agree?

#277 is one instance of a general question this repository has never asked: **for each
primitive, what is the largest security parameter it can express, is that limit deliberate,
and is it the same in C, Go, Python and Java?**  Every cross-language check in `spec/`
answers a different question, and there are five of them:

* `check_language_parity.py`'s manifest and census — does the primitive EXIST in each language;
* `cli_support` — does each CLI DISPATCH the `--algo` tag;
* `cli_flag_matrix` (#267) — does each CLI DEFINE the flag;
* `cli_flag_value_gaps` (#269) — which VALUES does each CLI accept for it;
* `check_docs_consistency.py` (#265) — do the narrative documents restate the sources correctly.

**None of them compares a numeric parameter's VALUE across languages.**  #276 hit this from
the other side: `QCMDPC_MAX_MULT` is duplicated in all four languages, the manifest pins the
*function* `qcmdpc-max-multiplicity` in all four, and nothing anywhere compares the constant,
so a partial update would be invisible.

**A verified anchor for how invisible.**  `spec/generate_spec.py`'s own docstring says
"Protocol parameter constants: herradura.h (#define) **and herradura/herradura.go** (const
block), grepped by name."  It is not true: line 1354 assigns `go_src = read(HERRADURA_GO)`
and never uses it.  Every parameter in `spec/herradura-protocol-spec.json` comes from C
alone, and the dead read is what makes the docstring assert a cross-language check that does
not happen.  Deleting the variable or making the claim true is a decision this item should
make, not leave.

**What is already known to differ, so the audit does not start from zero:**

* **ZKP-NL is capped at 32 in Go and 64 in C, Python and Java** — and it is a *type* limit,
  not a policy: `ZkpNlVerify(B, y uint32, ...)` and `[3]uint32` shares throughout, against
  `ZKP_NL_MAX_N = 64` elsewhere.  Both the Python and Java sources carry a comment saying so.
  Go therefore cannot verify a statement the other three can produce, at a width the suite's
  own test [22] exercises.
* **HCRED is a compile-time 256 in C (`HCRED_N`, static-asserted against `RNL_ALT_N`) and
  Java (`Hcred.N`), and a runtime argument in Python and Go**, which both demo at n = 32.
  `KAT/hcred_kkw.json` already records that the four "have never proved the same statement
  size" and ships two vector sets because of it.
* **`RNL_N` is compile-time in C**, which is why `KAT/pem/` skips the C CLI at n = 64.
* The four sampling sites use three different draw widths — RNL 24-bit, Stern-F 32-bit
  (documented to 2^32), QC-MDPC 16-bit (undocumented, #277) — plus one *guarded* limit,
  `hpke_stern_f_decap`'s refusal above `C(n,t) > 2^32`, which is the only one that fails
  loudly.
* `KEYBITS = 256` is structural for the classical quartet, and the assembly/Arduino targets
  run 32-bit GF and `RNL_N = 32`; both are recorded demo-only positions, not defects.

**What this item should produce.**  A table, one row per primitive, four cells plus a
maximum and a reason — the same shape `check_language_parity.py`'s manifest already uses,
which is why it is the natural place to put it.  Then the question each row forces: is the
narrowest cell deliberate (assembly widths, demo-only rows) or accidental (a `uint32` chosen
before anyone asked how wide the statement needed to be)?  Only the accidental ones are work;
the point of the table is that today nobody can tell them apart.

**Make it self-invalidating, like every other table in `spec/`.**  A primitive with no width
row fails generation, and a row whose four cells have CONVERGED fails until it is deleted --
the orphan rule #269 uses one level down, which is what stops a fixed asymmetry leaving a
stale claim behind.  That is the part that keeps this from becoming a document nobody reruns.

**Not in scope:** raising any width.  This item establishes what the widths ARE and which
disagreements are accidental.  Acting on a row is that row's own item, as #277 is for the
QC-MDPC draw.

Status: **OPEN**
