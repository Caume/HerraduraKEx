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

### #291: the OTHER 46 analysis scripts have no verdict — a printed `FAIL` exits 0

TODO #289 asked "which findings-gating scripts does CI run?" and answered it structurally:
`run_findings_gates.py` DISCOVERS them, so nothing has to be added anywhere and "nobody got
round to it" can no longer look like "it passes".  #290 then found the first thing that
discovery could not see (a spelling: `--fast`, not `--quick`).  Both items are about the
set of scripts that gate.  **Neither touches the prior question: which scripts gate at
all.**

**The census, measured at head** (`run_findings_gates.py --list`, plus a scan of
`SecurityProofs-*.md` and `CLAUDE.md` for each filename):

| | scripts |
|---|---|
| `SecurityProofsCode/*.py` | 81 |
| discovered as findings gates (#289) | 35 |
| **not gates** | **46** (45 analyses + the runner itself) |
| of those, CITED by `SecurityProofs-*.md` or `CLAUDE.md` as backing a claim | 33 |
| of those, printing a PASS/FAIL-shaped verdict and exiting 0 regardless | 22 (16 of them cited) |

So a little over half of the analysis corpus produces output that nothing reads, and
**22 scripts contain the exact defect TODO #233 removed from the test harnesses** — a
verdict computed, printed, and then discarded by an exit status of 0 — one layer out, in
the layer that backs the security documents rather than the one that tests the code.

**The exemplar, and it is not a hypothetical.**  `qc_mdpc_bgf_prototype.py` (cited in
`SecurityProofs-5.md`) ends `main()` with

```
    print(f"  PRF uniformity: {'PASS' if ok_prf else 'FAIL'}")
    print(f"  BGF decoder DFR at toy scale: {fails} failures (see §4)")
```

and `main()` returns `None` to a bare `if __name__ == "__main__": main()`.  `ok_prf`
False prints `FAIL` and exits 0.  It also carries a PRIVATE `bgf_decode` with a threshold
schedule "tuned empirically at r=523, d=15, t=18" and no import from the suite — the twin-
decoder class TODO #285 retired from `qcmdpc_dfr_weak_keys.py` after finding it had
diverged from the shipped decoder twice.  Nothing compares the two, and nothing would say
so if the comparison failed.

**The second exemplar is the one that should settle the question.**
`hkex_rnl_failure_rate.py` is the script whose §6 printed a security table in which every
row was wrong in the unsafe direction, found and withdrawn by TODO #286 — three documented
paragraphs of it in `CLAUDE.md`.  It is still not a gate.  Whatever repair #286 made to it
cannot be defended by CI, and the next drift in it is invisible for the same reason the
first one was.

**Scope.**

1. **Triage all 45 non-gating analyses into three buckets**, with the bucket recorded, not
   inferred: (a) holds a claim a document cites → make its exit status its verdict, the
   `sys.exit(main())` shape the other 35 use; (b) holds no claim — a demo, an
   exploration, a superseded construction — → declared non-gating WITH A REASON;
   (c) obsolete → deleted, and its citations with it.  The 12 uncited scripts
   (`hkex_cfscx_*.py`, `hkex_pake_demo.py`, `hpks_threshold_demo.py`,
   `nl_fscx_v2_kex.py`, `nl_fscx_v2_orbit.py`, `oprf_demo.py`, `stern_ct_demo.py`,
   `vdf_demo.py`) are the likely (b)/(c) population; the 16 that already PRINT a verdict
   are the likely (a) population and are where the work should start, because for them
   "what is the finding?" is already answered in their own source.
2. **The declaration must be self-invalidating**, like `EXCLUDED`, `CLI_FLAG_PARITY`,
   `PARAM_DIVERGENCE` and every other curated table in this repo: an entry naming a file
   that is absent, or that HAS since become a gate, fails.  Otherwise bucket (b) is just
   the old exclusion list with better manners.
3. **Close discovery's remaining hole in the other direction.**  Today the runner errors
   when a script ADVERTISES a gate and is not discovered.  It cannot error when a script
   neither advertises, gates, nor is declared — which is precisely the 46.  After (1) and
   (2) every `SecurityProofsCode/*.py` is discovered or declared, and the runner should
   fail on anything that is neither.  That is the check that makes this item unrepeatable;
   the triage alone is a one-off.
4. **Cost, which is the reason to expect resistance.**  The 35 current gates cost 73.4 min
   under `--quick` on the reference SBC and 58% of that is five scripts.  The 45 are
   UNMEASURED — several are large (`zkp_pqc_exploration.py` at 59 KB,
   `nl_fscx_prf_analysis.py` at 50 KB, the four `hkex_cfscx_*.py` at 34-48 KB each) and
   some may be hours.  Measure before converting, and where a script is genuinely too
   slow, the answer is a `--quick` mode in that script, NOT an exclusion — #289's whole
   finding was that the exclusion route produces a defensible-looking list with broken
   scripts in it.
5. **Do not invent thresholds.**  A script that explores rather than concludes has no
   finding to gate, and forcing one on it manufactures a false gate — worse than no gate,
   because it reads as coverage.  Bucket (b) with an honest reason is the correct outcome
   for those, and a triage that lands most of the corpus in (a) should be treated as a
   sign the reasons were not written carefully.

**Knock-on.**  `CLAUDE.md`'s "35 findings-gating scripts" figure is held to what the runner
reports by `check_docs_consistency.py`'s check E (TODO #287), so it follows the conversion
automatically; the `SecurityProofsCode/` inventory in `CLAUDE.md` and the run instructions
in the Testing section will need re-checking by hand, per TODO #145's rule.  Any script
promoted into the gate set also enters `analysis-findings`, which is still
`continue-on-error: true` — that job's promotion to required is #289's decision 1 and is
NOT this item; converting scripts under a non-blocking job first is the right order.

**Explicitly out of scope.**  (i) The CONTENT of any finding: this item makes verdicts
observable, it does not re-derive them, and a script that turns out to be failing gets its
own item the way #286 and #288 did.  (ii) The 35 existing gates.  (iii) Promoting
`analysis-findings` to blocking.

Status: **OPEN**
