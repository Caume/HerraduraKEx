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

### #316: which NUMBERED TESTS decide a verdict from a fresh sample against a fixed threshold

**TODO #310's closing question, filed.**  That item found `[53]` failing about **one run
in 16** in two of four ports, from two independent false-failure terms that multiplied to
~7.0% per run and hid each other — at a combined rate that high, nobody asks which of the
two coins landed badly, and the second only became visible once the first was gone.  It
then said what it had not done: `[4]`, `[18]` and `[45]` were fixed by #233 and #234 by
making the threshold follow the statistic, each found by somebody tripping over it, and
**no census exists** of whether any other numbered test has the same shape.  That sentence
is `CLAUDE.md`'s Testing section today and it is nobody's item.  This is it.

**The precedent is built and it found things.**  TODO #300 asked exactly this question of
the 76 findings gates, and `SAMPLED_GATES` in `run_findings_gates.py` is the answer: every
sampled gate carries a verdict code (`exact` / `negligible` / `replicated` / `follows`) and
either a DERIVED RATE or a STATED ARGUMENT, with the two counted separately in the runner's
banner so the distinction cannot quietly erode.  It turned up three defects, and the third
is the one to remember — `qcmdpc_bgf_failure_rate.py` had a single `return 0`, so it was
discovered, run every CI run, and could not go red.  A gate that cannot fail is not a gate.

**Why the numbered tests are the more expensive place to have this.**  The findings gates
live in `analysis-findings`, which is `continue-on-error`.  The numbered tests live in
`native-c`, `native-go`, `native-python` and `native-java`, which are REQUIRED, so a flake
there is a red required check on an unrelated PR — and TODO #233's whole point is that
those harnesses now fail the build.

**What is owed.**

1. **The census itself**, in `spec/check_language_parity.py` rather than in a new file:
   that checker already reads all four harnesses, already parses numbered `[N]` markers for
   its contiguity and set-alignment checks, and is already run by `native-python`.  The
   corpus is 54 / 60 / 54 / 42 numbered assertions in Python / C / Go / Java.
2. **A rate is per (test, PORT), not per test.**  This is #310's finding stated as a design
   constraint: the same `[53]` code failed one run in 16 in Python and Go and one run in
   65536 in C and Java, because the two pairs run it at different `(N, t)`.  A single cell
   per row would have recorded the lucky number and called the class closed.
3. **Ask how many TERMS a rate has, not what the rate is.**  #310's own lesson, and the
   reason `[53]`'s second term survived the first fix.
4. **Self-invalidating in both directions**, like every other curated table in that file:
   an entry naming a test that no longer exists fails, and so does a numbered test that
   draws fresh entropy and is named by no entry.

**Known hazard, from #310's own known limit.**  Verifying a rate STATISTICALLY costs a
harness run per sample, and the C and Go suites take 10+ minutes each — so a measured null
is affordable in Python and is not affordable four times over.  Where a rate is exact
arithmetic (`2^-t`, `(2/3)^rounds`) one reading of the construction carries to all four;
where it is not, say which port was measured, as #310 did.

**FIRST PASS (Python harness, 54 numbered assertions) — one defect found, and it is
not the shape #310 predicted.**

* **`[17]`'s Eve-forge sub-check is a sampled gate at `(1/3)^SDF_ROUNDS` = 1.5e-5 per
  run, and its failure mode is an UNCAUGHT `TypeError` that takes the whole harness
  down** rather than a `[FAIL]` line — in a REQUIRED job.  The forgery claims
  `fake_chal = [0] * SDF_ROUNDS`; `hpks_stern_f_verify` RECOMPUTES the Fiat-Shamir
  challenge and rejects on the first round that disagrees, so the `b = 0` branch is
  reached only when every recomputed challenge is 0.  On that branch the response pair
  carried a `BitArray` where a real one carries an int, and `BitArray(n, sr)` raises.
  **Measured, and it is exactly the predicted geometric:** TypeError in 0.342 / 0.118 /
  0.0130 / 0.0000 of 2000 attempts at rounds = 1 / 2 / 4 / 8 against `(1/3)^R` =
  0.3333 / 0.1111 / 0.01235 / 0.000152.
* **The fix is #310's — CONSTRUCT, do not hope — and it makes the assertion stronger.**
  Typing the pair correctly does not lower the rate, it removes the sampling: the
  verifier then RUNS the `b = 0` branch and rejects on the merits, because `c1` was
  built without `ds=2` and #298's `wt(respA ^ respB) == t` binding fails at weight 0.
  Measured: 0 accepted and 0 raised in 6000 forgeries at rounds = 1, where that branch
  is reached about 2000 times — i.e. the branch the check used to crash through is now
  the branch it tests.  Giving it its own round count was considered and is the WRONG
  fix here: it would push a crash from 1.5e-5 to 1e-9 and leave the b = 0 path still
  unexercised.
* **It is PYTHON-ONLY, which is #310's per-port rule paying off in the other direction.**
  #310's `[53]` was the same code at two parameter sets; this sub-check does not exist in
  C, Go or Java at all — their `[17]` asserts completeness only — so the cell is
  (Python 1.5e-5, C/Go/Java absent), and a table with one cell per test would have
  recorded "absent" and closed the row.

**What the first pass classified as sound, with the reason, because a census that only
reports defects cannot be checked.**

* `[2]` (`2.9 <= mean <= 3.1`) is EXACT despite looking like the worst row in the file:
  FSCX is linear, so flipping one input bit moves the output by `M . e_j` of weight
  exactly 3 at every `n >= 3`.  The statistic has zero variance and the window is legacy
  slack.
* `[11]`'s 98% non-linearity threshold has a **genuinely nonzero null** — 4 coincidences
  in 20 000 at n = 32, i.e. 2.0e-4, not the 2^-32 a reader would assume — so the slack
  is load-bearing rather than generous, and the derived rate is `P(Binom(500, 2e-4) >=
  11)` ~ 1e-14.  `[10]`'s 95% no-period threshold measured 4000/4000 at n = 32 and 64.
  Neither is #234-vacuous: a v2 that became linear scores `nl_ok` ~ 0 and a v1 that lost
  aperiodicity scores `no_period` ~ 0, so both gates still fire on the regression they
  defend.
* `[18]` is the REFERENCE ROW and should be read before any other: #233 separated the
  ambiguous-syndrome branch from the failure branch and scores only `bad`, which is how a
  probabilistic subject gets an exact verdict without slack.
* `[20]` runs the ring at rounds = 4 — the count this repo's Testing section warns
  about — and is exact because it asserts COMPLETENESS ONLY.  Adding a rejection case
  there would carry a 19.75% soundness error, which is the warning stated as a live
  constraint rather than as history.
* `[50]`'s six tamper axes pick `e0`/`r0` from the proof's OWN opened lists, so the poked
  field is always one the verifier checks: exact, not lucky.
* `[14]` rests on an ARGUMENT (Peikert reconciliation eliminates agreement failures), and
  under #310's rule that is the row to distrust, not the row to wave through — a reason
  exact about the wrong object reads exactly like a correct one.  Measured here: 0
  disagreements in 20 000 at n = 32, which bounds the per-trial rate at 1.5e-4 (95%) and
  is NOT tight enough to derive a run-level rate from, so the row cites
  `hkex_rnl_failure_rate.py` §5/§7 rather than re-deriving.  Note RNL_SIZES includes 32
  while the test's own comment says the error probability is negligible "at n >= 64".
* `[19]`'s collision and boundary checks are birthday terms against a 256-bit digest
  (~4e-75) and `[5]`'s `mean >= size // 4` sits `sqrt(size * N) / 2` sigma from its null.
  Both `negligible` with the rate stated, per #300's rule that a stated rate beats a
  generous-looking threshold.

* `[22]` is `[17]`'S TERM AT A SAFE ROUND COUNT, and the pair is the most useful thing in
  this pass.  `_zkp_nl_verify` hashes ALL commitments into `ch_seed` and checks every
  round's claimed challenge against the recomputed one, so flipping a bit of round 0's
  `com_1` is missed only if all 16 recomputed challenges still match the claimed ones:
  `(1/3)^16` = 2.3e-8 per trial, 2.3e-7 per run over the 10 trials it trials.  Identical
  MECHANISM to `[17]`'s defect -- Fiat-Shamir challenge recomputation is what rejects --
  and the only difference is 16 rounds against 8.  **So the round count is the whole
  distance between 2.3e-7 and 1.5e-5**, and a reviewer comparing the two by eye sees two
  tamper checks that look equally safe.  `[22]` also has no crash mode: past the challenge
  check it meets stale responses and returns False.  (Sampling it directly is not
  affordable -- ZKBoo at n = 32, 16 rounds costs ~7 s per trial, so 12 trials in 85 s;
  the rate is derived from the mechanism, and the 12 trials only confirm the sign.)
* **Two rows draw NOTHING and are out of scope, one of them interestingly so.**  `[27]`
  seeds from the literals `test-seed-{i}` / `seed-alice`, and `[29]`'s DRBG is seeded from
  `bytes(range(32))` and `b'ent-monobit'` throughout -- so `[29]`'s `0.48 <= frac <= 0.52`
  monobit window is applied to a CONSTANT.  It cannot flake, and it is the inverse
  fragility rather than a defect: the die is rolled once per change to the DRBG, not once
  per run, so a future construction change either always passes it or always fails it.
  Worth a sentence in the census and no code change.

**SECOND FINDING, and it is the four-port split this item was filed to look for —
`[21]`/`[30]` disagrees with itself in all four languages about what an exhausted
rejection limit MEANS.**  `rnl_sigma_sign` draws its ZK mask `y` by rejection sampling
and gives up after 1000 attempts; that is a legitimate outcome of the signer, not a wrong
answer, and every port scores it differently and none of them correctly:

| port | on exhaustion | consequence |
|---|---|---|
| Python | `n_run -= 1; continue` | if EVERY trial exhausted, all five counters and `n_run` are 0, the five comparisons hold, and it prints `0/0 [PASS]` |
| C | `N = i + 1; break` | leaves `ok_verify == i` against `N == i + 1`, so ANY exhaustion is a FAILING build |
| Go | `N = i + 1; break` | same as C |
| Java | `fails++` | fails the build, **and its own comment says the opposite** |

Java's is the one to keep in mind: the comment reads "Rejection sampling can legitimately
fail, so a null proof is reported rather than counted as a verify failure", directly above
`fails++`.  That is TODO #295's false-reason finding — a curated reason wrong about its own
code — aimed at a TEST instead of at a constant, and no checker in this repo can see it.

**Fixed in all four, to the same rule** (#291: a section that did not run must not be
scored).  C and Go exclude the trial from the denominator (`N = i`) instead of counting it
against them; Python and both of them now guard `N > 0`, so a run that completed no trial
FAILS rather than passing vacuously; Java retries the sign up to 8 times, each call
redrawing `y`, and fails only if every attempt exhausts.  Verified: Python 5/5 at n = 32
and 256, C 3/3 at both, Java `PASS [30]`, Go pending.

**Measured exhaustion rate: 0 in 1166 signs at n = 32 and 0 in 136 at n = 256**, so no
port is failing today — but `_sigma_params`' own comment records that the retired
`max(4, n // 16)` gave `t = 64` at n = 1024, where acceptance collapses to ~3e-4 and the
signer exhausts about **72%** of the time.  The margin is a parameter choice, not a
property, which is exactly why the row belongs in a census rather than in a reviewer's
memory.

**The Python side is now COMPLETE — all 54 assertions classified.**  `[46]`, `[48]`'s
`same_as_v2` / `fpe_eq_twk` and `[19]`'s collision checks are all 2^-256 coincidence terms
(`negligible`, rate stated).  `[47]`'s chi identities and `[48]`'s round-trips are
algebraic and hold for every input, so the draws change which instance is tested and not
the outcome (`exact`).  `[49]`'s accept-control is the one with a derived rate worth
writing down: the guard rejects a peer `m_blind` whose nonzero count is below `n/4` or
whose coefficient RANGE is below `q/4`, and a genuine uniform draw trips the second at
about `n * (1/4)^(n-1)` = 1.5e-17 at n = 32 — negligible, but it is a real term rather
than an impossibility, and the accept-control is there precisely because a guard that
rejected everything would pass the four rejection cases perfectly.  `[51]` and `[52]`
draw NOTHING (pinned supports, pinned PRF vectors), so they are out of scope in the same
way `[27]` and `[29]` are.  `[50]` is exact for the reason recorded above.

**C AND GO, first pass.**  Their numbered sets are IDENTICAL to Python's `[1]`-`[53]`
(the `[64]`/`[4096]` hits a naive scan reports are array sizes, not test numbers), so the
per-port question is not which tests exist but what PARAMETERS they run at — which is
#310's finding stated as a method.  Three things it found.

* **Go runs `[17]`/`[20]` at `sdfTestRounds = 4` where C and Python use 8.**  It is safe
  only because Go has no Eve-forge sub-check at all; had it carried Python's, the term
  would be `(1/3)^4` = 1.2%, one run in 81 — 81x Python's.  The same code at two
  parameter sets is `[53]`'s shape, and this is the near-miss that shows the census has
  to record the NUMBER, not the presence.
* **The already-fixed rows check out and carry their rates in the source**: `[45]`'s bad
  syndrome is caught only on a `b = 0` round, `(2/3)^32` = 2.4e-6 over 2 trials (#233,
  after the same check at rounds = 8 made all of `[45]` fail 38.5% of runs); `[53]` runs
  its forgery sub-check at `FRND = 64` and its ring half at 12 (#310); `[18]`'s ambiguous
  syndromes are counted separately from failures in C exactly as in Python.
* **The rest mirror Python row for row** — `[2]`'s 2.9/3.1, `[4]`'s `tol`, `[5]`'s
  `size/4`, `[10]`'s 95% and `[11]`'s 98% are the same expressions with the same nulls,
  and `[46]`/`[49]`/`[51]`/`[52]` are the same coincidence, guard-range, pinned-support
  and pinned-vector rows.

**JAVA, complete (35 numbered checks, its own numbering).**  Nothing of `[17]`'s kind:
its verdicts are boolean conjunctions of round-trips and tamper rejections, and every
probabilistic one is already at a safe count with the rate IN THE SOURCE — `[12]` signs
at `Stern.SDFR = 32` with a comment deriving why 8 would flake (the corrupt-syndrome
check needs a `b = 2` round, `(2/3)^32` = 2.4e-6); `[26]` at `demoRounds = 32` after
TODO #260 caught it flaking at 8; `[35]` at `forgeRounds = 64` after #310.  `[14]` is the
interesting shape and is CORRECT: QC-MDPC decapsulation has a real DFR, and under #235's
implicit rejection a DFR event is an output mismatch, so it fails only if all 20 trials
miss — `DFR^20`.  `[21]` and `[22]` seed from literals and draw nothing, so Java carries
`[29]`'s constant-monobit shape too.

**One correction made on the way out**: `[14]`'s comment quoted "~0.225% measured" for
the DFR in the present tense.  That is the RETIRED (r=523, d=15, t=18) set; TODO #276
adopted BIKE-128, where #285 §2 found the rate is not observable at any trial count.  The
verdict is unaffected (`DFR^20`, and a smaller DFR is safer), so the figure was stale
rather than wrong — but a parameter claim in the present tense is exactly what check B''
exists to catch, and **B'''s corpus stops at `SecurityProofsCode/`**, so no checker in
this repo could see it.  That is a second corpus-boundary finding of #306's kind, one
axis over.

**THE TABLE: design settled, and the design is a finding.**  The plan was a cell per
(test, port) with a reason each.  Measuring first killed that: **about 50 of the 53
numbered tests in each language draw fresh entropy**, so a four-cell table is ~200 rows
whose overwhelming majority would say "exact: a round-trip, every trial must succeed".
TODO #296 met this exact problem and its answer is the precedent to follow — "there are
109, and a hundred prose reasons rot", so `RANDOMNESS_CENSUS` is a NAME SET derived from
source every run, with reasons only where something departs from the default.  So:
a derived SET of the (lang, test) pairs that draw, compared every run so that adding,
removing or renaming a numbered test forces the question; and curated entries ONLY where
the verdict rests on a threshold or a probabilistic outcome, each carrying #300's verdict
code plus a rate or an argument.

**And the detector has to be validated before it is trusted, which measuring also
showed.**  A first Go pattern matching `randBA` and `crypto/rand` found 32 of 53 tests
drawing; adding `NewRandBitArray`, `mrand.` and `mrand.Read` took it to **49** — seventeen
tests invisible, including all of `[23]`-`[31]`.  An under-matching detector makes the
completeness rule pass VACUOUSLY, which is #295's recorded rule that getting the corpus
wrong in the LENIENT direction is the dangerous direction, and #306's sixth-spelling
hazard for the fourth time.  Note `mrand` is `math/rand`, not a CSPRNG: auto-seeded since
Go 1.20, so it is still a fresh sample every run and still counts for flake purposes even
though it would not count for #296's randomness census.

**Still owed**: implementing that table in `spec/check_language_parity.py`.

**Not in scope.**  The `CliTest/*.sh` scripts, which decide verdicts from fresh keys too
but whose retry policy is already `lib_dfr.sh`'s subject (TODO #221, #235), and the
assembly/Arduino harnesses, whose `[1]`–`[18]` are a subset run at parameters the Testing
section already warns about separately.  Both are a different axis and folding them in
converges on completeness again — #298's rule.

Status: **OPEN**

---
