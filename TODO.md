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

**Third pass (v9.5.24) — the quenched check, by measurement, and the model is NOT
conservative.**  See SecurityProofs-9.md §11.40 and
`SecurityProofsCode/quenched_exact_ladder.py`.  No proof is attempted; what is done is
the comparison §11.39.3 made a prediction about and nobody had run past n = 11.

  * **Exact mu was limited by construction, not size.**  `diff_cycle_mean.py` built each
    graph from a 2^(2n) DDT.  Enumerating a node's out-edges from §11.38.1's carry-pair
    automaton costs (out-degree x n), so the FIXED round's exact minimum mean cycle now
    reaches n = 13, 14, 16 and 17 (~30 s per key at 16).  n = 19 is offered under
    `--full` and no key completed (one passed 4.6 GB and half an hour of CPU).
    Checked edge for edge against the DDT-built graph at n = 8, 10, 11.
  * **The model's error changes sign.**  §11.39.3 said the gap was an over-count dying as
    2^-0.65n, so the model would converge from the SAFE side.  Measured, exact/annealed
    falls 1.18 -> 1.10 -> 1.07 -> 1.04 over n = 7, 8, 10, 11, crosses 1 between 11 and
    13, and is below 1 for EVERY sampled key at n = 14, 16 and 17 (median 0.94, 0.93,
    ~0.93; the fall slowing).  §11.39.3's account is WITHDRAWN.  The linear axis (exact
    only to n = 11 here) falls the same way, 1.23 -> 1.08, and has not crossed.
  * **What that does to §11.38's n = 256 figures.**  They become an estimator of UNKNOWN
    sign.  The 36x margin is UNSUPPORTED, not lost: losing 4/3 would need the ratio to
    fall to ~1/36, against ~0.93 at the widest width measured.
  * **The measured lead on mechanism.**  The keys the model over-states most have long
    RUNS of equal bits (and many trailing zeros) in delta.  Over a run the carry is near-
    deterministic, so a difference at its top passes addition for ~2^-run bits.  Where the
    runs sit is a property of ONE constant, which an independent-edge ensemble cannot
    see -- the quenched effect itself.  At n = 256 six fixed keys each carry an explicit
    two-round trail under half a bit, cheapest on the longest run.
  * **A rigorous route tried and dropped**, recorded so it is not re-derived: mu >= W_k/k
    via a componentwise-max relaxation of the k-round carry-pair product automaton is
    sound and nearly tight at n = 8 (1.54 exact at k = 2, 3.41 vs 3.54 at k = 3) once the
    cyclic boundary of M is enforced, and useless without it (0 at k = 1..3).  But at
    n = 256 the k-round transient is nearly free for exactly the run reason above, and
    the state grows as 2^(3(k+1)), so no affordable k gets W_k/k anywhere near 4/3.

**What is left**, sharpened: (1') a quenched argument, which must now control the RUN
STRUCTURE of delta rather than the weight distribution alone, since the latter is
demonstrably not enough; and (2) the linear hull, unchanged.

**Fourth pass (v9.5.25) — exact mu on both axes to n = 20, and the ratio does NOT
settle.**  See SecurityProofs-9.md §11.41 and `SecurityProofsCode/certified_cycle_ladder.py`.

  * **A certificate makes a pruned graph exact.**  Build only the edges below a per-node
    threshold W_u, solve, take the shortest-path potential p of w - mu', and raise W_u
    wherever W_u < mu' - p(u).  When no node fails, p is feasible on the FULL graph, so
    the subgraph's mu is the full graph's.  Pruning inside a row is sound because
    partial weight only grows (the l1 norm of the linear carry vector; the at-most-
    doubling of the differential path count).  ~3-25 edges per node against ~2^n/3, so
    the LINEAR axis goes from n = 11 to n = 20 and the differential from 17 to 20.
    Exact to 1e-9 against both exhaustive builders; a negative control (fixed W = 1,
    loop off) over-states mu on 13 of 18 keys and the test flags all 13.
  * **v9.5.24's "the fall slows near 0.93" is withdrawn.**  At 8 keys n = 17 is 0.90,
    then 0.81 at n = 19 and 0.75 at n = 20.  The linear axis crosses between 13 and 14
    and falls about half as fast, to 0.82 at n = 20.  No constant-factor correction to
    §11.38's 48.44 / 22.40 exists, so they lose their basis entirely.
  * **What IS flat is the exact slope.**  Median exact mu/n stays at 0.14-0.16
    (differential) and 0.07-0.08 (linear) from n = 13 to 20, while the model's lambda*/n
    climbs to ~0.2 / ~0.09.  Within a width, exact mu rises only ~0.6 per unit of
    lambda* at n = 17: the keys the model rates strongest are over-stated most, which
    fits §11.40.3's run-structure cap.  Read as a slope, n = 256 lands near 36 and 18,
    ~27x both criteria -- a reading of eight widths, not a bound, replacing the
    model-based 36x/34x.
  * **Tried and not finished:** n = 22 (4M nodes) passed 2.3 GB on its first key
    within an hour on an 8-core SBC already running seven other keys, and was stopped
    for memory; it is not claimed.

**What is left**, re-aimed: (1'') a quenched argument whose target is the EXACT slope
(flat at 0.14-0.16 over eight widths), not the annealed model's error, which is not
converging; and (2) the linear hull, unchanged.

**Fifth pass (v9.5.26) — the exact slope with enough keys: not flat, still growing.**
See SecurityProofs-9.md §11.42 and `SecurityProofsCode/exact_slope_ladder.py`.

  * **The same certified solver in C** (`certified_cycle_mean.c`), fed the automaton
    tables from the Python sources and checked against the Python solver on mu, edges
    kept AND certificate rounds.  ~40x faster with in-place edge compaction, so 32-96
    keys per width to n = 20, 8 at n = 22 and 3 at n = 23 (~5 and ~8 GB per key).
  * **The fourth pass's "flat at 0.14-0.16" is withdrawn, and so are its ~36 / ~18
    (27x).**  Exact mu rises with the number of runs in delta (~0.13 per run
    differential, ~0.074 linear) and the n = 20 sample was run-heavy (0.60 n runs).  At a
    typical run count the differential per-bit median is ~0.15 at n = 13-14 and ~0.13 at
    n = 19-23; keys already near n/2 runs show the same step without a regression.
    Levelling or still falling: not resolved.  Linear: no trend beyond scatter.
  * **Exact mu grows at every width step to n = 23** (run-adjusted 1.96 -> 2.95 and
    0.95 -> 1.63), ending at 2.2x / 2.4x the criteria.  That is §11.37's monotonicity
    residue with ten widths behind it.
  * **The model's error is a scale error**: it ranks keys right (corr 0.98) but credits
    each run of delta ~0.21 where exact mu gains ~0.12, so the slope of exact on lambda*
    across keys falls from 1.0 to 0.1-0.6 by n = 20-23, and the keys converge (IQR/median
    0.3 -> ~0.03-0.1).
  * **No single n = 256 figure is supported.**  A power law reads ~13 / ~11 (10x / 17x);
    a levelled per-bit median ~33 / ~17 (25x).  The data do not choose.
  * **Tried and dropped:** the optimal cycles at n = 13-17 are long (5-37 edges) and
    pass through dense differences, so there is no small structural family to search
    for at n = 256 as an upper bound.
  * **Part 9 is at 726 of ~750 KaTeX spans**: the next section of this item belongs in
    a new Part 10.

**What is left**, re-aimed again: (1''') an argument that exact mu is NON-DECREASING in n
(the criterion then holds at n = 256 by the measured margin at n = 23), which cannot come
from comparing graphs since there is no embedding between widths; and (2) the linear
hull, unchanged.

**Sixth pass (v9.5.27) — the local certificate: a route that would have been a proof
at n = 256, built and measured, and why it does not get there.**  See
SecurityProofs-10.md §11.43 (the new Part 10; Part 9 was at 726 spans) and
`SecurityProofsCode/local_potential_certificate.py`.

  * **The certificate.**  For ANY phi, mu >= min over edges of w(a,b) + phi(a) - phi(b),
    and with phi unrestricted that IS mu.  With phi a sum of w-bit WINDOW functions,
    the minimum is a bit-position DP (the §11.38.1 carry-pair automaton plus window
    bits), linear in n and so evaluable at n = 256; the best phi per window is an LP
    (HiGHS).  The DP must keep the carry SLOT and merge by componentwise max -- sound,
    and close to the LP at the optimal phi; dropping the slot gives mu = 0 on every key
    (the negative control).
  * **The window it needs grows with n.**  Median w* (first window at which the bound
    equals mu) is n-1, n-2, n-3 at n = 7, 8, 10 -- about 0.7n.
  * **At a fixed window it does not grow.**  w = 5 certifies a FALLING share of mu
    (median 0.94, 0.87, 0.81, 0.71, 0.70 at n = 8, 10, 11, 13, 14), and the bound itself
    is lower at n = 13-14 (1.27, 1.32) than at n = 10-11 (1.43, 1.50) while exact mu is
    not (1.79, 1.87 against 1.63, 1.83).
  * **Why.**  The LP dual is a distribution over edges with locally balanced window
    statistics, not a cycle, and it sits on LIGHT differences (dual-weighted popcount
    ~0.42n -> 0.34n over n = 8..11) where the optimal cycles are dense (0.6-0.86n).  It
    never sees M grow the support, so the bound is set by the cheapest local
    neighbourhoods of delta while mu is global.  The DP costs ~4^w per bit, so a window
    that grows with n is not available at 256.

**What is left**, unchanged in substance and narrowed in method: (1''') monotonicity of
exact mu in n, by an argument that carries NON-LOCAL information -- support growth under
M being the obvious candidate, since that is exactly what the local certificate cannot
see; and (2) the linear hull.

**Seventh pass (v9.5.28) — the local certificate SOLVED at n = 256: positive, and below
4/3.**  See SecurityProofs-10.md §11.44 and `SecurityProofsCode/local_certificate_n256.py`
(with `local_certificate_dp.c` and the pinned `local_certificate_n256.json`).

  * **Non-local information at small n does not change the trend.**  A global statistic
    (popcount, run count) alone certifies ~0.3 of mu; added to w = 5 windows it buys
    0.03-0.04; two-round paths buy 0.05-0.07.  The share still falls from n = 8 to 11
    in every row.
  * **The LP solved without listing the graph.**  Constraint generation from exact edge
    weights, separated by the sound DP's traces AND an exact single-carry-path Viterbi
    (the Viterbi alone overstates the LP and its potential certifies ~0.1 against an
    optimum ~1 -- the negative control), with the potential's box grown in stages.  One
    SHARED table F[a-window][delta window] costs 2-7% against a table per position and
    keeps the LP one size at every width.  The DP is renormalised per bit position; the
    sixth pass's overflows a double at n = 256.
  * **Solved per width, the bound does not grow.**  Median certified bound 0.81 / 1.50 /
    1.36 / 0.98 / 1.03 at n = 16 / 20 / 24 / 32 / 48 (LP), 0.72 / 0.76 / 0.67 / 0.77 /
    0.66 at n = 64 / 96 / 128 / 192 / 256 (supergradient ascent; the LP takes ~30 min a
    key at n = 64 and its rows grow faster than n).  Exact mu grows ~0.14 per bit, so the
    certified share falls roughly as 1/n -- §11.43's extrapolation, now measured.
  * **At n = 256 four keys get mu >= 0.54 / 0.58 / 0.74 / 0.90**, re-verified from the
    pinned tables by the pure-Python DP: the first NONZERO lower bound at the deployed
    width (the trivial one is 0), and every one BELOW the 4/3 criterion.  The 192-round
    corollary is weak (phi spans 77-98 bits, so 13-95 bits certified against 256).
  * **No shortcut**: a table solved jointly over six keys at n = 24 is NEGATIVE on every
    unseen n = 256 key.  The certificate must be solved per key, at the width.

**What is left**, sharpened: (1''') monotonicity of exact mu in n.  What a window misses
is neither density nor a few rounds of support growth; it is that a LIGHT difference
cannot stay light around a whole cycle (the LP dual stitches sparse, locally balanced
edges; real cheap cycles are dense).  The next route has to bound, globally, the weight
a sparse difference sheds under M per round.  (2) The linear hull, unchanged.

**Eighth pass (v9.5.29) — the linear hull, MEASURED: a proportional correction that
grows slowly with width, and about one round.**  See SecurityProofs-10.md §11.45 and `SecurityProofsCode/hull_exact.py` (with
`hull_exact.c`).  Item (2) had been carried forward unchanged by all seven passes.

  * **The object is the cipher, not a model.**  For a fixed key the r-round map of the
    SHIPPED round -- with #245's round constants, which only flip signs on a trail and
    so were invisible to every trail measurement -- is built as a table, and its whole
    correlation and difference tables are scanned for the largest nontrivial entry.  No
    trail, no independence, no key averaging.  Beside it: the best r-round trail on
    each axis, and the same scan over uniformly random permutations (the floor).  The
    helper matches the shipped `nl_fscx_revolve_v2` on all 65536 inputs at n = 16, and
    a pure-Python brute force at n = 7.  NEGATIVE CONTROL: the round with "+" replaced
    by "^" (affine) reads 0 bits at every round.
  * **Clustering is real, and it is a SHARE that FALLS.**  Before the hull saturates
    it runs below the best trail.  At the last round before saturation it keeps a
    median 0.91 / 0.86 / 0.89 / 0.87 / 0.82 of the trail's weight on the linear axis and
    0.97 / 0.95 / 0.95 / 0.90 / 0.90 on the differential at n = 10 / 11 / 13 / 14 / 16,
    about -0.011 per bit on both axes; no key keeps less than 0.71.  A draft read
    n = 10-14 alone as "no downward trend" and called it a fixed factor; the n = 16
    run (--full) withdrew that before it shipped.
  * **In rounds it costs about one, at every width.**  The hull reaches the ideal
    floor 0-2 rounds after the best trail (median 1), outside #253's tz(delta) >= 4
    class, which is slow on the trail already.
  * **Seven cells are LATE, not stuck.**  Their trail clears the floor by r = 3n/4
    and their hull does not (six at n <= 11, one at n = 16), but each reaches it within
    two more rounds, and an ideal cipher would put ~3.4 of the n <= 13 cells below the
    threshold anyway.  It is the one-round lag crossing 3n/4.
  * **NOT carried to n = 256.**  Exact mu at n = 23 is 2.4x / 2.2x the criteria
    (§11.42); the hull eats that margin only below a share of 0.42 / 0.45.  No key at
    n <= 16 comes close (worst 0.71), but a straight line through the medians reaches
    it near n = 50 -- recorded as a question, not an answer, since #257 has withdrawn
    four extrapolations of that kind.

**What is left**: (1''') monotonicity of exact mu in n, unchanged from the seventh pass.
(2') how the hull's share of the trail weight behaves above n = 16 -- it falls slowly
over n = 10-16, and no exact method reaches further (an exact hull costs n * 4^n per
round).  Item (2) is no longer "unreached"; it now has the same shape as item (1).

**Ninth pass (v9.5.30) — where the optimal cycles pay, and the local-potential route
closed with a control.**  See SecurityProofs-10.md §11.46 and
`SecurityProofsCode/live_region_certificate.py`.  It took the seventh pass's instruction
literally -- give the certificate non-local information about how a difference moves --
and found a true fact that does not help.

  * **A live-region lemma, exhaustive.**  Addition with a constant keeps a difference's
    LOWEST active bit (below it the two carries agree), and M moves it down by one bit
    per round, or resets it to 0 when the MSB is set.  The linear axis is the mirror: a
    nonzero correlation needs equal HIGHEST mask bits.  So every cycle must reset, and
    every step of every optimal cycle measured obeys it.
  * **Where mu is paid.**  Each optimal-cycle edge split bit by bit along the carry
    automaton (exact; it sums to the solver's weight).  The cost sits at delta's RUN
    BOUNDARIES -- 0.88-0.93 of the differential weight on or one above a boundary,
    against ~0.62 of the positions, a position above a boundary costing 3-4x an
    ordinary one -- because the carry is near-deterministic inside a run and a fresh
    bit just after one.  delta's trailing ZEROS are never paid for, which is #253's
    tz(delta) weak class from the cycle side.  This is the mechanism under the fifth
    pass's "mu rises with the run count", which was a regression until now.
  * **Not pinned at the wrap.**  Rounds whose extreme bit has left the bottom grow
    from 0.25 to 0.64 of a cycle over n = 13-17, so cycles are not a finite problem at
    the wrap boundary either.
  * **Not a figure for n = 256.**  mu per boundary is ~0.31 / ~0.15 over n = 13-17, but
    it FALLS as boundaries crowd (correlation -0.5 to -0.6 with boundary density), and
    single rounds with many boundaries live can cost ~0, so no per-round bound of that
    shape exists: any argument must amortise.
  * **The certificate, told.**  The window LP plus a table on the live region's
    position, its boundary count, both extreme bits, or windows anchored at the extreme
    bit: every one leaves the share FALLING from n = 8 to 10.  The CONTROL -- a random
    labelling with the same number of classes -- ties the n-class features and beats
    every richer one, so the gains are class count, not content (an anchored feature hit
    1.000 at n = 8 with 4096 classes for 256 nodes).  At n = 256 a random labelling has
    no structure for the DP, so this was the bar a usable feature had to clear.

**What is left**, unchanged in substance: (1''') monotonicity of exact mu in n -- now
with the LOCAL-POTENTIAL ROUTE CLOSED after three passes (windows; global statistics and
two-round paths; the live region), so a bound at n = 256 needs an argument about CYCLES
rather than edge-local potentials; the cost-at-boundaries picture is what such an
argument would have to account for.  (2') the hull share above n = 16, unchanged.

**Reach.**  No production-track row.  HSKE-NL-A2 and `twk` are demo-only for reasons on
other axes (#243, #244, #248), and #254's three production-track rows -- HSKE-NL-A1,
HFSCX-256 and everything inheriting the hash -- left the scope of a trail bound entirely
in §11.36.8, because in both those modes the attacked input is the round CONSTANT, which
enters every round at once, so there is no trail to bound.  This item can therefore move
no rating in either direction, and is filed as an outstanding proof obligation behind
figures already published, not as a gate on anything.

Status: **OPEN**

---


### #309: an entropy-injection seam for the four CLIs — env var and explicit flag

**TODO #306 stated this limit in `CLI_DRAW_COVERAGE`'s header rather than after the fact,
and deliberately did not act on it.**  59 raw-entropy draws sit in the four CLIs across 17
roles, 9 of them `cli_only` -- drawn nowhere but the CLI, so no suite-level pin can reach
them however much pinning is done.  The reason is one sentence: **no CLI takes an entropy
source as a parameter in any of the four languages.**  Closing that is a change to the
shipped surface, not to a checker, which is why it is its own item.

**The machinery already exists in every language; it is the CLI that has no seam.**  Each
of the four KAT consumers #296 and #297 built injects a fixed stream today:

| language | how the CLI draws now | seam that already works elsewhere |
|---|---|---|
| C | `fopen("/dev/urandom", "rb")`, once per subcommand (8+ call sites in `herradura_cli.c`) | `fmemopen` over a byte array — `verify_kat_c.c:140`; every suite sampler already takes `FILE *urnd` |
| Go | `rand.Read` inside `NewRandBitArray` | `rand.Reader = <fixed>`, a documented package variable — `verify_kat.go:576` |
| Python | `os.urandom`, `BitArray.random`, `secrets.token_bytes` — three spellings, no chokepoint | `generate_kat.py --check`'s regenerate-and-diff IS the replay |
| Java | `private static final SecureRandom RNG` in `HerraduraCli.java:88` | `FixedRandom extends SecureRandom` — `KatVerify.java:387` |

So the work is not inventing a mechanism.  It is (a) giving each CLI ONE entropy
chokepoint where it currently has many, and (b) letting that chokepoint be pointed at a
file.  C's is the largest change and the most mechanical: replace the per-subcommand
`fopen` with a single accessor.  Python's is the subtlest, because three spellings have to
converge before there is anything to point.

**What it buys, concretely.**  Every `cli_only` role in `CLI_DRAW_COVERAGE` becomes
pinnable, and two of them are the ones worth pinning: `hske_nla1_nonce` (A1 is
`E = P ^ ks` — a repeated nonce under one key is a two-time pad outright) and
`threshold_commit_nonce` (`s_j = k_j - a_j.e`, so a repeat recovers that signer's share).
Both are drawn in all four CLIs with nothing comparing the four draws.  The axis would
then report a `pinned` status beside `suite` / `cli_only` / `owed`, and rows would retire
into it the way #305's `transitive` rows retire when an operation row is added.

**THE HAZARD, and it is the reason this item needs arguing rather than implementing.**  An
environment variable that replaces the CSPRNG in a shipped binary is the sharpest footgun
this repo could add.  Set it by accident -- in a Dockerfile, a CI job, a systemd unit, a
shell profile -- and `genpkey` emits a deterministic private key that looks exactly like a
real one, with no artifact recording that it was produced under a fixed stream.  That is
strictly worse than the gap it closes.  Any design must answer all of these IN THE ITEM,
not in review:

* **Fail-closed, not fail-open.**  #274's and #287's finding was the same shape twice: an
  unrecognised input silently taking the weaker branch.  A named stream file that is
  missing, short, or unreadable must ABORT, never fall back to `/dev/urandom`.
* **Loud, on stderr, every invocation.**  Not once, not behind `--verbose`.
* **Marked in the artifact, or argued why not.**  A key produced under a fixed stream and
  a key produced from `/dev/urandom` are currently indistinguishable on disk.  The
  strongest version refuses to write private key material at all under injection and only
  serves the operations a replay vector needs; the weakest stamps the PEM.  Neither is
  obviously right and the choice belongs in this item.
* **Compile-time gating is on the table and is not free.**  `#ifdef`-ing it out of release
  builds makes the CLI under test a different binary from the CLI that ships, which is the
  defect `CliTest/test_param_bounds.sh` exists because of -- a bound that is declared but
  not enforced on the path people actually run.  Argue it either way; do not assume it.
* **Env var AND flag, and they are not the same hazard.**  A flag (`--entropy-file`) is
  visible in `ps` and in shell history and cannot be inherited by a child process; an env
  var (`HERRADURA_TEST_ENTROPY`) is what a harness sets without rewriting argv and is
  exactly what leaks into every subprocess. If both ship, the flag should be the primary
  and the env var should require the flag, or the env var should be dropped.

**Scope note.**  This is a new public surface with nothing existing changed, so **MINOR**,
not MAJOR -- no PEM label, no `--algo` value and no existing flag moves.  It touches all
four CLIs and `spec/check_docs_consistency.py`'s `cli_flag_matrix` / `cli_flag_value_gaps`
axes, which will see a new flag in four ports and fail until it is in all four or a
`CLI_FLAG_PARITY` row explains the gap.

**Ordering against #308.**  #308 moves the classical Schnorr nonce OUT of the CLI and into
a suite operation, where the existing replay already reaches it.  Doing #308 first shrinks
this item's target -- `schnorr_nonce` leaves `CLI_DRAW_COVERAGE` entirely -- and settles
whether the remaining `cli_only` roles are best closed by a seam or by the same move.  If
most of them turn out to be #308-shaped (a draw that belongs in a suite function the CLI
should be calling), this item is smaller than it looks and possibly unnecessary; that
question should be answered before any shipped surface is added.

**What must NOT happen.**  Shipping the seam and then treating the `cli_only` rows as
closed without actually adding vectors.  The seam is a precondition for pinning, not
pinning -- #296's own diagnosis of #294 was a harness built and then thrown away while the
documents went on asserting in the present tense that the check existed.

**DEMOTED by TODO #311 (v8.2.1), which answered the ordering question above.**  The nine
`cli_only` roles split 7 / 2, and the split is adverse to this item.  Seven --
`pem_envelope_salt`, `classical_privkey`, `rnl_kex_nonce_a`, `rnl_kex_nonce_b`,
`hybrid_kex_nonce_b`, `hcred_seed_h`, `hash_sig_master_seed` -- are a single uniform draw
of one fixed width handed straight to a function that already takes it as an argument,
with no loop, no rejection and no second draw, so **a fixed stream pins the identity
function and the seam would teach nothing about any of them**.  The remaining two are
`hske_nla1_nonce` and `threshold_commit_nonce` -- which are exactly the two this item
nominates above as "the ones worth pinning", and are also the only two where the CLI
transcribes a multi-step operation rather than drawing a parameter.  One of them
(`hske_nla1_nonce`) is #308-shaped outright and is now **TODO #312**; the other was
examined and filed as a considered no.

So the seam's whole remaining target is a case the #308 move reaches more cheaply and
without adding a shipped surface.  **This item is not closed** -- the hazard analysis it
owes is owed in full if it is ever revived, and nothing above is withdrawn -- but it is
not next, and it should not be implemented as posed.  Revisit only if a future `cli_only`
role appears that is neither parameter-fed nor movable.

Status: **OPEN**

---

---

