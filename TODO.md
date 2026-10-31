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

**Tenth pass (v9.5.33) — two routes without a potential, both closed.**  See
SecurityProofs-10.md §11.47 and `SecurityProofsCode/width_lift_closure.py`.  The ninth pass
asked for an argument about CYCLES; two cycle-level routes need no certificate at all.

  * **An upper bound by construction.**  The only bound that could REFUTE one of §11.42's
    two n = 256 readings (~13, ~33).  The cheapest-edge map (best-first over the carry
    automaton, exact against the certified solver's rows) must close a cycle, and the
    cycle's mean bounds mu from above.  It does, soundly -- and it closes like a random
    mapping: log2 rho grows 0.48 bits per bit over n = 14..26 (0.34 over 14..22 alone),
    so closure at n = 256 lies past 2^80 steps.  Breadth-first exploration found no
    cycle in 20 000 nodes at n = 32 or 64.  Where it closes it is 1.27-2.03x exact mu
    (median 1.47), so even a closed walk could only confirm a low value.
  * **The lift between widths.**  §11.37's "no embedding" is true of the GRAPHS, not of
    the KEYS: stretching a run of delta by one bit is a natural map n -> n + 1 keeping the
    boundary sequence.  Exact mu is NOT monotone along it -- it falls on 23-30% of all
    (key, run) lifts, on both axes, at n = 13 and 16, by up to 0.25 -- and the fixed-width
    boundary insertion (flip an interior bit) is not monotone either, though it raises mu
    on nearly every key.
  * **What sets the sign is the run length.**  Stretching a length-1 run adds 0.17-0.19
    (differential) / 0.06-0.08 (linear); a run of length >= 3 moves mu by -0.012..+0.030.
    Width without a boundary adds no cost: exact mu grows with n through delta's
    boundary count, which is §11.46.2 stated about n.  "Stretching the lowest zero run
    lowers mu most often" was true at n = 13 and false at n = 16, withdrawn before it
    shipped -- it moves mu by ~0, those bits being free.

**What is left**, re-stated: (1''') monotonicity of exact mu -- now necessarily a
DISTRIBUTIONAL statement about typical keys as boundaries are added at density 1/2, since
no pointwise chain of the two natural local operations is monotone, and no upper bound at
n = 256 is available to test it against; (2') the hull share above n = 16, unchanged.

**Eleventh pass (v9.5.34) — the coupled ladder.**  See SecurityProofs-10.md §11.48 and
`SecurityProofsCode/coupled_width_increment.py`.  The tenth pass re-stated (1''') as a
DISTRIBUTIONAL statement; this pass measures it with an exact coupling instead of
independent samples.

  * **The coupling is exact.**  A uniform bit inserted at a uniform position of a uniform
    delta is uniform one width up (checked exhaustively), so E[mu_{n+1}] - E[mu_n] is a
    mean of PAIRED differences.  Pairing cuts the standard error a median 4.2x against
    an unpaired comparison of the same numbers.  Deployed keys (delta over odd B) are a
    pseudo-random half of delta-space whose run-count law is within 1% of uniform's.
  * **E[mu] rises at every step from n = 4 to 17, on both axes** (smallest lower 3-sigma
    bound +0.04), while single pairs fall on up to 49% / 36% of draws.  Monotone in
    expectation, not pointwise -- the tenth pass's finding from the other side.
  * **Single steps are not stationary; periods of three widths are.**  Neighbouring
    steps disagree by up to 5.9 / 4.6 standard errors (a period-3 term: M's singular
    widths), but summed over a period the increment is FLAT from n = 10 to 16 --
    0.364 / 0.370 differential, 0.206 / 0.209 linear, i.e. 0.122 / 0.069 per bit, within
    5% of the fifth pass's levelled per-bit medians by an independent method.
  * **It does not decide §11.42's two n = 256 readings.**  A power law predicts the last
    period at 0.92x / 0.96x the one before; measured 1.02 +- 0.09 / 1.01 +- 0.08 (1.2 / 0.6 sigma).  Carried
    flat the series reads ~32 / ~18 at n = 256 -- a reading, not a bound.
  * **A hang fixed in the certified solver.**  SPFA ran on w - mu' with Howard's mu'
    rounded as a cycle's sum / length; on n = 17, delta = 0x1f6ef the two roundings
    disagree by < 1e-11, the optimal cycle is a negative cycle to SPFA, and it never
    terminated.  No fixed seed had met such a key; uniform sampling did.  Both solvers
    (C and Python) now run SPFA at mu' - 1e-9 with a relaxation budget; the five earlier
    gates that use them reproduce unchanged.

**What is left**, narrowed: (1''') monotonicity of E[mu] is now MEASURED at every step to
n = 17; what is owed is either a reason the per-period increment stays bounded away from
zero, or enough further periods to separate §11.42's readings (each costs exact mu at
n = 19-20+ per pair); (2') the hull share above n = 16, unchanged.

**Twelfth pass (v9.5.35) — the period exponent, and two eleventh-pass claims withdrawn.**
See SecurityProofs-10.md §11.49 and `SecurityProofsCode/period_exponent.py`.

  * **The eleventh pass's errors were understated.**  It drew several insertions per
    base delta and divided by sqrt(pairs); the insertions share mu(delta), so clustered
    by key every error is 1.4-1.6x larger.  `coupled_width_increment.py` is corrected
    and prints both.  Monotonicity survives (every step still rises at 3 sigma; the
    weakest, differential 16 -> 17, by +0.009); its linear "single steps are not
    stationary" does not (~3 sigma clustered, and an independent 3000-pair run per step
    resolves no such term) and is WITHDRAWN.
  * **A better estimator.**  The coupling is exact for any k, so a whole PERIOD is one
    three-bit insertion -- one solver call, checked exhaustively -- and the change in
    run count is a control variate with an EXACT mean (k/2, corrected for the two
    excluded degenerate deltas, checked against brute force).
  * **The per-period increment FALLS on both axes.**  ~8000 pairs per period on
    independent seeds: P = 0.451 / 0.382 / 0.362 (differential) and 0.227 / 0.207 /
    0.199 (linear) at n = 7 / 10 / 13.  Local exponent over 10 -> 13: -0.23 +- 0.06
    and -0.18 +- 0.05, 4.0 and 3.5 sigma below a levelled rate (the gate's smaller
    sample: 5.3 and 1.9 sigma, so it scores the differential one).  The eleventh pass's
    "flat from n = 10" -- and the ~32 / ~18 it read for n = 256 -- are WITHDRAWN.
  * **Neither of §11.42's readings describes it.**  The levelled one (~33 / ~17) loses
    its premise; the power law (~13 / ~11) is not confirmed, because the differential
    exponent drifts from -0.55 to -0.23 across two adjacent intervals (~3.6 sigma, the
    shared P(10) included; the replication's, not resolved at the gate's seeds), so
    the decline is itself slowing.  The n = 256 value sits between them.

**What is left**, narrowed again: (1''') a reason the per-period increment stays
bounded away from zero as it declines -- monotonicity is measured at every step to
n = 17 and the decline is slowing, but nothing bounds it; (2') the hull share above
n = 16, unchanged.

**Thirteenth pass (v9.5.42) — one period further, to n = 19: the fall STEEPENS.**  See
SecurityProofs-10.md §11.50 and `SecurityProofsCode/period_series_n19.py` (with the pinned
`period_series_n19.json`).

  * **The sample.**  P(n) at every start the singular widths allow -- 7, 10, 13, 16 and
    8, 11, 14 (a period cannot start at 3 | n, where mu is identically 0) -- one
    three-bit insertion per key, 11 700 pairs per axis, 500 of them solved exactly at
    n = 19 (~30 s each).  P(13) reproduces the twelfth pass's replication (0.9 / 0.1
    sigma) and E[mu_16] agrees between two independent samples.
  * **E[mu] still rises over every period, to n = 19**, by 24 standard errors or more.
    E[mu_19] = 2.61 differential, 1.31 linear: 1.95x and 1.96x the criteria.
  * **But the fall steepens, and "the decline is slowing" is WITHDRAWN.**  In the
    n = 1 (mod 3) series the twelfth pass used, P = 0.447 / 0.384 / 0.357 / 0.244
    (differential) and 0.225 / 0.210 / 0.199 / 0.157 (linear) at n = 7 / 10 / 13 / 16;
    the local exponent moves from -0.32 to -2.02 (6.2 sigma) and -0.23 to -1.26 (4.5
    sigma).  The n = 2 (mod 3) series also falls at every step (0.505 / 0.365 / 0.308
    and 0.211 / 0.206 / 0.176); it steepens on the linear axis and not on the
    differential one, so that is printed, not scored.
  * **Both n = 256 readings lose their premise.**  Neither a fixed exponent (~13 / ~11)
    nor a levelled rate (~33 / ~17) describes a decline that is accelerating.  At the
    last period the increment is 0.081 / 0.052 per bit; if it reaches zero within a few
    more periods E[mu] levels at about twice the criteria, and if it goes negative
    nothing here says where it stops.
  * **A Howard non-termination, fixed in all four solvers** (`certified_cycle_mean.c`,
    `quenched_exact_ladder.py`, `diff_cycle_mean.py`, `width_residue.py`).  On
    n = 14, delta = 0x1500, linear, policy iteration never stopped: every node held
    the optimal mean, but h was rooted wherever the scan entered a cycle, and two
    cycles of EQUAL mean then have incomparable h.  h is now rooted at each cycle's
    smallest node.  mu and the certificate do not depend on the root; 744 random keys
    at n = 7..16 give identical mu, edges and rounds, and the gate's negative control
    shows the old root not terminating in certificate round 2.

**What is left**, re-aimed: (1'''') whether E[mu] stays above the criteria at all --
monotonicity is measured to n = 19, but the per-period increment is now falling FASTER,
so the question is no longer which growth curve holds, and the margin at the widest
measured width is ~2x, not ~10x.  The next period, P(17) to n = 20, costs ~60-100 s per
solve; (2') the hull share above n = 16, unchanged.

**Fourteenth pass (v9.5.43) — P(17) to n = 20: the n = 2 series falls by the same
factor.**  See SecurityProofs-10.md §11.51 and `SecurityProofsCode/period_series_n20.py`
(with the pinned `period_series_n20.json`).

  * **The sample.**  500 pairs per axis from the thirteenth pass's own draws() at
    start n = 17, one exact n = 20 solve each (1-2 min, up to 4.1 GB differential,
    against 0.83 GB at n = 19); ~26 CPU hours, so pinned.  E[mu_17] agrees between
    two independent samples (0.3 / 1.1 sigma).
  * **E[mu] still rises, to n = 20**: P(17) = 0.210 differential, 0.147 linear, 27 /
    33 standard errors above zero.  E[mu_20] = 2.67 / 1.35: 2.00x and 2.03x the
    criteria -- the same margin as at n = 19.
  * **P falls again** from P(14) (9.6 / 5.2 sigma), **by the same factor as the n = 1
    series**: P(16)/P(13) and P(17)/P(14) are 0.684 / 0.682 differential and
    0.789 / 0.835 linear (0.1 / 1.1 sigma apart).  The n = 2 series' differential
    exponent now steepens too, -0.80 to -2.17 (4.4 sigma).
  * **A constant ratio, printed not scored**, would level E[mu] near 3.12 / 1.98
    (2.3x / 3.0x the criteria).  It is the optimistic end: the n = 1 series' ratio
    already fell once, 0.93 to 0.68.

**What is left (1''''')**: whether the per-period ratio holds or keeps falling -- that is
now the whole question, since a held ratio levels E[mu] comfortably above the criteria
and a falling one leaves it near 2x or below.  The next period, P(19), needs n = 22
solves; peak memory grew ~5x per bit from n = 19 to n = 20, so it needs a lower-memory
solver or a larger host, or an argument that bounds the ratio below; (2') the hull
share above n = 16, unchanged; (3) **NL-FSCX v3's linear slope at realistic width**,
against v3's own bar s_lin >= 0.8 (TODO #342, SecurityProofs-10.md §11.52).  v3's
differential axis is closed at every width by §11.34.3's round-level floor; its linear
axis has only the layer-wise 1-bit floor, and the round-level floor is 0.1926.  At n = 10
the exact slope clears 0.8 for all 1024 keys, least 1.178 (1.47x).  **v9.5.46
(§11.53, nl_fscx_v3_linear_width.py):** certified exact slopes at n = 14 (rows 7/7,
2048 keys, least 1.607) and n = 17 (rows 5/5/7, 24 keys, least 1.415), every key
clearing 0.8.  And a proven CEILING: the LSB row gets no carry in, so its LAT entries
depend on delta(B) mod 2^L only, at every width n >= L + 2; its least cycle mean
(1.4150 for a 5-row, at delta = 5 mod 8, one key in eight at n = 256) bounds the
worst key's slope from ABOVE at n = 256 -- the linear margin is at most 1.77x.  What
is left is the FLOOR: whether a cycle through carry-receiving rows undercuts the LSB
row's value as n grows.  On the 5-row-LSB widths the least rose (1.178 at n = 10 to
1.415 at n = 17) and 67% of n = 17 keys sit exactly on their LSB-row value, but that
is one exhaustive and one sampled width.

**Methodology correction (TODO #343, v9.5.47, SecurityProofs-10.md §11.54).**  Every
E[mu] above was sampled over uniform delta, which overstates the key average by a few
percent, and held to mu * 3n/4 >= n, which drops a transient of about -0.3n
(differential) / -0.15n (linear) at the deployed round count.  Read the margins against
the corrected bars, about 1.71 and 0.87: n = 20 sits near 1.5x, not 2x.  The fixes to
the sampler and the solver were tracked in #343 (closed v9.5.65).  **v9.5.50 (§11.57):** the transient
deepens with width, so at n = 19 the bars are 1.89 / 0.94 and the key average sits about
1.3x above them.  **v9.5.51 (§11.57.4):** at n = 20, 1.91 / 0.97 and 1.34x / 1.36x; the
deepening has not slowed.

**Split out: the n/4-round v1 criterion (from #254) became TODO #346, closed in v9.5.67 with an adverse finding; its follow-up is TODO #347.**

**Ratings now rest on this item (TODO #345, v9.5.66).**  HSKE-NL-A2, `twk`, HSKE-NL-A3 and `twk --v3` are production-track under conjectures this item measures: v2's key-averaged per-round cost at n = 256 >= 1.71 / 0.865, and v3's linear slope >= 0.8.  A v2 measurement past n = 23 below the bar, the linear share failing in the unfavourable direction, or a v3 key below 0.8 outside a negligible class reopens all four.

**From TODO #343, closed in v9.5.65.**  #343 re-measured everything above on key samples
with the deployed criterion, to n = 23 (SecurityProofs-10.md §11.54-§11.67).  At n = 23
(50 keys) E[mu] is 2.813 / 1.482, 1.65x / 1.71x the share-held bars 1.710 / 0.865, with
lambda = 0.171 / 0.158 and 1.7% / 2.6% of keys below the bar.  Its open refinements are
now this item's:

  * **Whether E[mu] levels.**  Class increments alternate rather than shrink (n = 2 mod 3:
    +0.37 +0.38 +0.16 +0.22).  n = 25 is TIMED (v9.5.63): 17-26 h per key, peaks 5.3-6.1 GB
    linear, so a 12-15 key sample is ~11-14 days serial on a 16 GB host; two n = 25 keys
    clear the criterion (mu 2.97 / 1.60 and 3.01 / 1.58).
  * **The linear share check is near its edge.**  `v2_series_n23.py` holds lambda(23)
    within 0.015 of the pooled value; it passes by 0.001, drifting in the FAVOURABLE
    direction.  If a later width fails it that way, restate the check, do not loosen it.
  * **A larger n = 22 sample**, if its fail share (1.9% +/- 0.8%, six keys) matters.
  * **The gap-bit cost** past n = 20 (§11.66.2: flat from 20 to 23 within its error).

**Reach (restated in v12.0.1; the earlier text predated #345 and #351).**  Four
production-track rows rest on this item: HSKE-NL-A2, `twk`, HSKE-NL-A3 and `twk --v3`,
each under the conjecture named in the "Ratings now rest on this item" block above, and
a measurement failing one of those conjectures reopens all four
(`SecurityProofsCode/v2_v3_rating_review.py` holds SECURITY.md to that verdict).  No other row does.  The v1
rows fall outside it, each for its own reason.  HSKE-NL-A1's attacked input is v1's round
CONSTANT (`K xor ctr`), which enters every round at once, so there is no trail to bound
(§11.36.8); its 3n/4 criterion was #346/#347's.  HFSCX-256 has carried the message in v1's
first input since its Matyas-Meyer-Oseas compression (#351, v11.0.0), so a trail does exist
there, but it is bounded directly at n = 256 (§11.75.4: at least 336 over 192 rounds), not
by extrapolating a width series.  The rows inheriting the hash (HPKS-WOTS, HPKS-XMSS,
ZKP-RNL and, since v12.0.0, the HPKS-NL challenge and the Stern hash) inherit that bound.
This item can therefore DEMOTE those four rows but cannot promote anything: their
ratings are already production-track (conjectured), and no measurement short of a bound
at n = 256 would remove the conjecture.

Status: **OPEN**

### #352: who chooses NL-FSCX v2's and v3's B? — the #348 audit for the other two rounds

**Why now.**  #348 (v12.0.0) and #351 (v11.0.0) both came from one question the trail
model cannot ask: an input FIXED at a degenerate value is not a trail, so a
trail-weight floor says nothing about it.  For v1 the answer is now recorded:
`SecurityProofsCode/v1_remaining_sites.py`'s `B_SETTER` table names who sets B at every
remaining v1 call, and its census fails on a new one.  Nothing does the same for v2 and
v3, which back four production-track rows (HSKE-NL-A2, `twk`, HSKE-NL-A3, `twk --v3`,
TODO #345) besides the demo and research rows.  **This is a gap to check, not a known
flaw.**

**What is known about v2's B.**  Both of v2's degenerate classes are classes of B:
- **the affine class**, `delta(B) in {0, 2^(n-1)}` (about 2^-129 at n = 256), refused by
  `nl_v2_key_is_valid` (herradura.h, TODO #159/#168);
- **the zero-weight-trail class**, every B with `tz(delta(B)) >= 4` (TODO #253,
  SecurityProofs-7.md §11.28.3), accepted ON PURPOSE.  The reason is in
  `nl_v2_key_is_valid`'s SCOPE comment: "a random key loses at most 3 rounds with
  probability 1/16".  **That argument holds only where B is a random key.**  Where a party
  can steer B, or can try many B and keep the cheap ones, it is not the argument that
  applies, and this item asks whether any site lets them.

v3 is documented as having no weak class (SecurityProofs-8.md §11.34.4), which is why
`fpe_twk_v3_derive_b` and `hske-nla3` skip the check.  §11.34.4 is about the AFFINE
class; whether chi also removes the `tz(delta(B)) >= 4` zero-weight trail is part of this
item.

**The sites, and who sets B** (C reference; the other ports and 32-bit targets must agree):

| site | B | who sets it | screened |
|---|---|---|---|
| HSKE-NL-A2 (`hske-nla2`) | the key itself | key holder | affine class, in the CLI |
| HPKE-NL (`hpke-nl`), decrypt | `R^a`, R read from the ciphertext | **the sender**, through R | affine class, in the CLI; refusal is a `die` |
| FPE / `twk` (v2) | HFSCX-256-DS(len‖key‖ctx or sector‖bidx) | key holder; the attacker chooses the tweak | affine class, rehash loop in `fpe_twk_derive_b` |
| FPE-V3 / `twk --v3` | the same, tags 0x22/0x23 | as above | none, by design (§11.34.4) |
| HSKE-NL-A3 (`hske-nla3`) | the key itself | key holder | none, by design |
| HSKE-Duplex / -V3 | HFSCX-256(DS‖key‖nonce) | key holder; nonce public | none |

Three rows need a real answer rather than a table entry:
1. **HPKE-NL decrypt.**  The sender picks R.  A small-order R confines `R^a` to a small set
   (the Pohlig–Hellman exposure SECURITY.md already cites).  Can a sender also steer `R^a`
   into `tz(delta) >= 4` more often than 1/16?  And is the CLI's refusal on the affine
   class a one-bit oracle on `a`?  The row is demo-only, so the likely outcome is a
   documented note, not a change.
2. **`twk` / FPE tweaks.**  In the STPRP model the attacker chooses the tweak.  Without the
   key they cannot compute B, so they cannot pick the cheap tweaks.  But about 1/16 of all
   tweaks land in the zero-weight class anyway, so a many-tweak attacker always has
   cheap-B blocks to work with.  Check that the rating's conjecture is stated over a
   random tweak's B and survives the attacker averaging over tweaks.
3. **v3 and the zero-weight class** (above).

**Work.**
1. A gate `SecurityProofsCode/v2_v3_b_setter.py` in `v1_remaining_sites.py`'s shape:
   - a census of every v2/v3 call in the four ports, the four CLIs and the 32-bit targets,
     failing on a new one;
   - a `B_SETTER` table naming who sets each site's B and which check applies;
   - controls showing it fires on a planted call and on a site whose screen is removed.
2. Answer questions 1–3 with measurements where possible: steer rates for (1), a
   per-tweak fraction for (2), an exact zero-weight search on v3 at small width for (3).
3. Write up as a new SecurityProofs-10.md subsection.  Change SECURITY.md only if an answer
   moves a row.

**Reach.**  Expected PATCH: a gate and a write-up.  If an answer moves a row, or calls for a
new refusal, that is a separate decision: a new refusal makes an existing `--algo` accept
less, which CLAUDE.md treats as MAJOR.

Status: **OPEN**

---
