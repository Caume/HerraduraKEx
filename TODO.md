# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

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

---

### #288: `qcmdpc_bgf_variants.py` measures hybrid parameter sets and labels them "deployed"

Found by surveying all 33 exit-status-gating `SecurityProofsCode` scripts after TODO #286
(31 pass; this is the second of two that do not).  `qcmdpc_bgf_variants.py` -- TODO #250's
decoder-variant comparison -- **exits 1 with 6 of its 18 recorded findings not reproducing**,
at head, under both `--quick` (480 s) and the full run:

```
[FAIL] POL_BASE reproduces the shipped decoder on 60 instances
[FAIL] the pinning sample contains both outcomes
[FAIL] a failure leaves a residual error far heavier than t/2
[FAIL] [deployed] the tuning grid separates rules at all
[FAIL] a genuine low-weight COMPLETION essentially never fires, as §2 predicted
[FAIL] the fitted r* for the shipped decoder is in the same range as §11.8.7's 1723 (within 2x)
```

**The cause is a HALF-updated script**, and it is the same family as #286 leg A without being
the same mistake: that one read "before" from the present tense, this one reads *some* of the
parameters from the suite and hardcodes the rest, so it measures instances that correspond to
no real parameter set.

* line 637: `(467, SUITE._QCMDPC_D, SUITE._QCMDPC_T, "deployed", ...)` -- `r = 467` is a
  literal chosen relative to the retired `d = 15`, paired with the suite's current `d = 71`
  and `t = 134`.  The result is `(467, 71, 134)`, which is neither the retired set nor
  BIKE-128, and it carries the tag `"deployed"`.
* line 640: `th_ship = max(ceil(0.66 d), (d+1)//2 + 2)` -- the PRE-#276 threshold rule,
  recomputed at `d = 71`.  So the grid's "baseline point" is the old rule at the new width,
  which is neither the shipped rule (BIKE L1, affine in the SYNDROME WEIGHT) nor the old one
  at its own width.  That is why the §1 pinning fails, and §1 is explicitly the gate
  everything else rests on: "a variant comparison whose baseline is not the deployed decoder
  measures the wrong thing, so this runs first and everything below is gated on it."
* line 642: `for _ in range(30 if d == 15 else 10)` -- sample-size logic still branching on
  the retired `d`.
* line 723: the §5 section title hardcodes `"Paired DFR at the deployed parameters (r = 523,
  d = 15, t = 18)"` while line 730 reads `r, d, t` from the suite.  **The title and the
  measurement disagree**: it measures BIKE-128 and titles it as the toy set.
* the `r*` finding compares against §11.8.7's fitted `1723`, which TODO #285 replaced
  outright -- that fit was at `d = 15`, `t = 18`, and the deployed instance has no such
  figure.  So this finding cannot reproduce even in principle and needs re-pointing at
  #285 §3's `2^-67` bound rather than repair.

**Not a wrong CONCLUSION, as far as the run shows.**  The four findings that carry #250's
actual answer -- that no decoder-side variant closes the DFR gap, that the ranking transfers
to the mid-scale set, that ranking by DFR at one `r` does not rank by `r*`, and that the
available improvement is real -- all still report OK.  What has broken is the evidence
chain, not the verdict.  The fix is to decide, per section, whether it measures the RETIRED
instance (then name it with a literal, as #286 did) or the DEPLOYED one (then read all three
parameters, and take the shipped threshold rule with them), and to re-point the `r*`
comparison at #285's replacement figure.

**And it exposes a blind spot in check B'', shipped hours earlier in v7.0.4.**  Line 723 is a
textbook currency claim -- a currency word next to `r = 523`, `d = 15`, `t = 18` -- and B''
does NOT flag it, because B'' requires a protocol-FAMILY token in the window and this file
never names its family in a sentence: the entire file is about QC-MDPC, so it never needs to.
Requiring the family token is what took that check from 35 findings (33 of them false) to
one, so the requirement is right and the consequence is a false negative for exactly the
files most likely to carry the defect.  The fix is a per-FILE family default: a script whose
name or module docstring establishes the family should not have to repeat it per sentence.
That is a small change to `_CURRENCY_PATTERNS` plus a family-from-filename map, and it must
be re-validated against the 33-script corpus, because loosening the window is precisely how
the 33 false positives came back last time.

Status: **OPEN**

---

### #289: which analysis scripts does CI run, and what is the rule?

Three items in a row have now added ONE script to `native-python`'s findings-gate step and
excluded the rest on runtime grounds, and twice the excluded set has turned out to contain a
script that was already failing:

| item | added | excluded | what the exclusion cost |
|---|---|---|---|
| #285 | `qcmdpc_dfr_weak_keys.py` (~3.5 min) | everything else | `qcmdpc_parameter_selection.py` was failing at that moment, three gates |
| #286 | `qcmdpc_parameter_selection.py` (~58 s) | `qcmdpc_bgf_variants.py` at ~11 min | `qcmdpc_bgf_variants.py` was failing at that moment, six findings (TODO #288) |
| #287 | -- | -- | -- |

Each exclusion was individually defensible and the pattern is not: "too slow for a step" has
now twice been the reason a broken script stayed broken, and the next exclusion is
`qcmdpc_bgf_variants.py` again.  This item is the DECISION, not another one-off.

**What the survey established, so the decision rests on numbers.**  All 33 scripts run at
head; measured `--quick` (or plain, where there is no `--quick`) runtimes:

* under 90 s: 19 scripts
* 90 s to 10 min: 12 scripts, the slowest being `nl_fscx_v2_round_constants.py` at 608 s
* over 10 min: 2 -- `annealed_moment_ladder.py` at 1601 s and `qcmdpc_bgf_variants.py` at
  960 s under `--quick` (~72 min with `--full`)

So the whole corpus is roughly 85 minutes of `--quick`, dominated by two scripts.  That is
too much for a step inside `native-python` and entirely reasonable for a SEPARATE job, which
is the option none of the three items considered: CI already runs eleven jobs in parallel,
and a twelfth that does nothing but collect these exit statuses would add no wall-clock time
to the critical path while removing the excuse permanently.

**Options, with the recommendation first.**

1. **A new `analysis-findings` job** running all 33 under `--quick`, non-blocking at first if
   the flake risk is unknown, promoted once a few runs confirm it is stable -- the route
   TODO #185 used for the `arduino` job.  Costs one runner for ~85 min of its own time,
   nothing on the critical path.
2. Keep the step and add the two cheap tiers (under 10 min), leaving only the two heavy
   scripts excluded -- better than today, still leaves `qcmdpc_bgf_variants.py` out, which is
   the one that just broke.
3. A scheduled weekly run rather than per-push, as `codeql.yml` does.  Cheapest, but a
   finding then breaks quietly for up to a week, and both defects found so far had been
   broken across releases.

Whichever is chosen, record it where the next item will look: `ci.yml`'s step comment
currently says "add a script here only when its `--quick` runtime is minutes, not tens of
minutes", which is the rule that produced the pattern above.

Status: **OPEN**
