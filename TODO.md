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

### #312: HSKE-NL-A1's plain mode has no suite function in three of four ports

**TODO #311's triage found this and it is TODO #308 verbatim, one protocol over.**  Java's
suite carries `HerraduraNl.hskeNlA1Encrypt(pt, key, nonce)` and `hskeNlA1Decrypt`, and
`HerraduraCli.java` CALLS them (lines 986 and 1107).  C, Go and Python have **no such
suite function at all** — their CLIs transcribe the four-step construction inline:

```
base = K XOR nonce;  seed = rnl_kdf_seed(base);
ks   = nl_fscx_revolve_v1(seed, base, I_VALUE);  E = P XOR ks
```

`herradura_cli.c` (cmd_enc / cmd_dec), `herradura_cli.go` (cmdEnc / cmdDec) and
`herradura.py` (cmd_enc / cmd_dec) each carry it TWICE — once per direction, six
transcriptions of a shipped primitive — plus the `encfile` / `decfile` container path.

**The AEAD sibling is a suite function in every port.**  `hske_nl_aead_encrypt` exists in
C, Go, Python and Java and is called by all four CLIs.  So `enc --algo hske-nla1 --aead`
runs a suite primitive and `enc --algo hske-nla1` runs a transcription, in the same branch
of the same function, three ports out of four.

**Python's transcription is the worst of the three**, and it is the class CLAUDE.md's
Testing section already names: it does not call the suite's KDF-seed derivation, it
RE-DERIVES it inline —

```python
seed = BitArray(nbits, base.rotated(nbits // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - nbits)))
```

— a second copy of a domain constant with nothing cross-checking it against the shipped
one.  Numbered tests [46], [47], [49] and [51] all exist because Python's harness
re-implements a primitive and each one cross-checks the copy against the suite; here there
is no suite function to cross-check against, so the copy is unguarded.  Go calls the real
`RnlKdfSeed` and C the real `ba_rnl_kdf_seed`, so the divergence is Python-only and is a
DERIVATION divergence, not a consumption-order one — invisible to the randomness axis
(#296), to `PARAM_USE_CORPUS` (#295, which reads whether a constant is read, not which
copy) and to every round-trip, because all four copies currently agree.

**The fix is #308's fix.**  Adopt Java's shape verbatim in C, Go and Python — a suite
`hske_nla1_encrypt(pt, key, nonce)` whose decrypt is the same function — on the standing
precedent (#294, #296, #308) that adopting an existing correct port beats inventing a
fourth API.  The nonce stays a PARAMETER, as it is in Java and as it is in the AEAD
sibling, so the CLI keeps the draw and `CLI_DRAW_COVERAGE`'s `hske_nla1_nonce` row stays
`cli_only` — **this item does not close that row and must not be read as closing it.**
What it buys is that the OPERATION becomes pinnable by the machinery #296 and #297 built,
and that Python's second copy of the KDF-seed derivation goes away.

**What #311 measured, so it is not re-litigated here.**  This is one of only two
`cli_only` roles whose CLI transcribes a multi-step operation; the other seven are a
single uniform draw consumed immediately as a parameter.  It is the only one of the nine
where a suite function already exists in a port and is not called by the other three.

**Ordering.**  Ahead of #309, which #311 demoted: the seam #309 would build exists to
reach draws like this one, and moving the operation is the cheaper half of that.

Status: **OPEN**

---

