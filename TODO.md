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


### #307: the four pins TODO #305's coverage census left OWED

**TODO #305 built the coverage table and classified every censused raw-entropy consumer
as `transitive`, `unpinned` or `owed`.  This item is the `owed` column** -- the rows
where pinning applies, a reason would be an excuse, and #305 deliberately refused to let
a prose sentence stand in for the work.

Four rows, in the order their absence is most likely to hide something.

* **`qcmdpc_keygen`** (Go, Python, Java; C takes the PRF as a parameter -- and TODO #306
  found where C's seed actually comes from: `herradura_cli.c`'s `cmd_genpkey` draws it
  and calls `qcprf_init`, so when this row is pinned, three ports supply the stream to
  the suite function and C supplies it in the CLI.  `CLI_DRAW_COVERAGE`'s
  `qcmdpc_keygen_prf_seed` row records that, and `qcmdpc_encap_prf_seed` and
  `hybrid_kem_prf_seed` do the same for the two encapsulation sites).  TODO #277
  found a 3-vs-1 byte-order split inside the PRF this drives, and only a dedicated
  pinned vector -- numbered test [52] -- could catch it.  That pins the PRF; it does not
  pin the DRAW ORDER around it.  #284 pinned KEM artifacts, which are verify-side, and
  #303 is the precedent for why that is a different statement: a pinned key says nothing
  about how it was sampled.  Needs a stream chosen to clear the weak-key screen and the
  invertibility retry first time, on the `rnl_sigma_sign` row's recorded precedent, and
  the generator must ASSERT that rather than assume it.
* **`qcmdpc_encap`** (same three).  The error vector's support is drawn here, by the
  rejection sampler whose acceptance limit `qcmdpc_parameter_selection.py` computes --
  and a rejection loop is exactly what #296 found carrying three different consumption
  orders across four ports, twice.
* **`zkp_nl_pp_prove`** (all four).  TODO #302 §6 said ZKB++ was "covered twice over".
  #305 narrowed that: the two halves are the CIRCUIT and the seed LENGTH, and neither is
  the seed ORDER.  §6 now asserts the absence, so pinning this row FIRES that section
  and forces its prose to be corrected -- the same self-invalidating handoff #302 left
  for #303.
* **`hcred_prove`** (all four).  HCRED's other prover, beside the KKW one #303 pinned:
  same file, same witness, and #266's transcription bug was in this family.  Python and
  Java censure the inner round rather than the outer prove, which is the same operation
  one frame down.

**Cost is the reason this is not folded into #305.**  #303 was ONE operation row and the
measured cost of adding it -- generator, C header arrays, and a consumer in each of
`verify_kat_c.c`, `verify_kat.go` and `KatVerify.java` -- was the whole item.  Four rows
is four times that, and two of them (the QC-MDPC pair at BIKE-128) have a keygen cost
that has to be measured before a row is written, exactly as #303 measured KKW's before
choosing `(N_par, M, tau)`.

**What must NOT happen.**  Silently converting an `owed` row to `unpinned` because the
pin turned out to be expensive.  #305 separated the two statuses so that cost is argued
in the open; a reason written after the fact to retire work is #300's third rule -- slack
wide enough never to fire -- in table form.

Status: **OPEN**

---

### #308: three of four CLIs sign with an unpinned transcription of the Schnorr signer

**Found by TODO #306 while widening the randomness corpus, and it is not a pattern
problem.**  `herradura.h` exports `hpks_sign`, which draws its own nonce and which
`KAT/classical_quartet.json` pins four ways.  `HerraduraCli/herradura_cli.c` does not
call it: `cmd_sign` transcribes the whole signer inline -- `ba_rand`, `gf_pow_ba`,
`ba_fscx_revolve`, `ba_mul_mod_ord`, `ba_sub_mod_ord` -- and the suite copy is reached
only by `docs/examples/c/hello_herradura.c` and `bindings/ffi/herradura_shim.c`.  Go and
Python never had the operation at all; their `REPLAY_COVERAGE` cells are `None` for that
reason.  Java's CLI is the one that calls the suite
(`Herradura.hpksSign(msgInt, pk.priv, RNG)`, `HerraduraCli.java:1414`).

**So the pinned function and the shipped path are different code in the only port that
has both.**  That is #295's recorded dead-code limit -- reachability is not liveness --
aimed at a sampler rather than at a constant, and it is why #305's `hpks_sign` coverage
row reads as reassuring while saying nothing about what `sign --algo hpks` runs.

**Why this is `owed` and not `cli_only`.**  `CLI_DRAW_COVERAGE`'s `schnorr_nonce` row is
the one `owed` entry in that table, and the fix it owes is not a vector.  A fixed stream
cannot reach a CLI (no port takes an entropy source as a parameter), so pinning the draw
where it is would need a new shipped surface.  Making the three CLIs CALL the operation
they copy moves the draw to a suite function the existing replay machinery already
reaches -- and for C that is a function which is already pinned.

**What is owed.**

* C: replace `cmd_sign`'s inline Schnorr block with a call to `hpks_sign`, and check the
  signature is byte-identical before and after (it is the same arithmetic; if it is not,
  that is the finding).
* Go and Python: the suite has no such operation, so one has to be ADDED -- a new public
  API surface, hence a MINOR bump, with `PRIMITIVES` manifest entries in all four cells
  and the `CLI_FLAG_PARITY` `hpks-sign` acknowledgement re-examined, since the asymmetry
  it records is the one being removed.
* Then the `hpks_sign` `REPLAY_COVERAGE` row's `go`/`python` cells stop being `None`, and
  `CLI_DRAW_COVERAGE`'s `schnorr_nonce` row must be DELETED -- which the site-count check
  forces, because those draws will no longer be in the CLI.

**What must NOT happen.**  Retitling `schnorr_nonce` to `cli_only` on the ground that no
CLI draw can be pinned.  That is true of the draw's CURRENT LOCATION and is exactly the
retire-by-reclassification #305 built the status split to prevent; the draw's location is
what is in question.

**Note on severity.**  No defect is claimed in any of the three transcriptions -- they
were read side by side and compute the same signature.  The claim is that nothing would
notice if one stopped doing so, and a Schnorr nonce is the draw where that matters most:
reuse across two signatures under one key yields the private key by subtraction.

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

Status: **OPEN**

---
