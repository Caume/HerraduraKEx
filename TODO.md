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

### #313: HSKE-NL-A1 interoperates at 256 bits only — four ports, four keystreams, and `dec` exits 0

**Found by TODO #312 while giving the operation a suite home, and it is why that item
preserved each port's behaviour instead of unifying it.**  `enc --algo hske-nla1` accepts a
session key of any width the `kex` that produced it was run at (`--bits 32/64/128` are
supported and used by the demo rings).  At `n = 256` all four CLIs agree.  **At every other
width all four disagree, and they disagree in four different ways.**

Measured, one 128-bit session key, one Python-produced ciphertext, the four CLIs asked to
decrypt it — with the `n = 256` control passing 4/4 first:

| port | plaintext recovered at n = 128 |
|---|---|
| Python | `41420000…`  (correct — it wrote the ciphertext) |
| Go | `5928c968…` |
| C | `9208e37d…` |
| Java | `9d3c1af7…` |

**Three independent causes, which is why this is one item and not three.**

1. **The KDF domain constant is truncated at opposite ends.**  `_RNL_KDF_DC_256` is defined
   at 256 bits; below that, Python takes its **HIGH** `n` bits (`DC >> (256 - nbits)`) and
   Go's `RnlKdfSeed` takes its **LOW** `n` bits (`RnlKdfDC[32-n/8:]`).  At `n = 128` those
   are `6a09e667…f53a` and `510e527f…cd19` — disjoint halves of the same constant.
2. **C ignores the declared width entirely.**  `load_sym_key` calls `ba_from_ra` into a
   fixed `KEYBITS` `BitArray`, so a 128-bit session key is silently zero-extended to 256
   and the whole construction runs at 256.  This is not a truncation choice; the width
   never reaches the primitive.  C is compiled for one `KEYBITS`, so it has nowhere to put
   the answer even if it wanted one.
3. **Java is 256-fixed too** (`Herradura.rol(base, N / 8)`, full-width `RNL_KDF_DC_256`)
   and still differs from C, so the two 256-fixed ports do not even agree with each other
   about how a narrow key becomes a wide one.

**Why nothing caught it.**  `hske-nla1` is a raw XOR keystream with **no authentication
tag** — that is the whole difference from its AEAD sibling — so a wrong keystream is not a
detectable event.  `dec` writes garbage and **exits 0**.  This is TODO #235's implicit-
rejection shape (a silent mismatch rather than an error) arriving by a different route, and
it defeats every test the repo has: the 4x4 interop matrix, `test_encrypt.sh`,
`test_c_encrypt.sh` and `test_aead.sh` all run at the default 256 bits, where the four
genuinely agree.  `KAT/classical_quartet.json` pins `n = 256`.  Nothing anywhere exercises
`hske-nla1` at another width, so a four-way divergence sat under a green matrix.

**It is not confined to `hske-nla1`.**  `rnl_kdf_seed` is shared: its own comment says
"wherever an HKEX-RNL KDF or HSKE-NL-A1 seed is required".  Anything that derives a seed at
a width other than 256 inherits cause (1).  Establishing the full blast radius is part of
this item and was deliberately not guessed at in #312.

**THE DECISION THIS ITEM OWES, and it is not obviously MAJOR.**  CLAUDE.md reserves MAJOR
for "a change to what an existing `--algo` value produces or accepts" and for making an
existing artifact "unreadable by a newer build".  Converging the ports would do the second
— a Python-written 128-bit A1 ciphertext would stop decrypting — **but it cannot break
interoperability, because there is none to break at those widths**: today no two ports
agree, so no cross-port artifact at `n != 256` has ever been readable.  The only thing
broken is a port reading back its own old narrow ciphertexts.  Weigh that against the
alternative, which is to keep four incompatible behaviours documented as such.  Three
routes, and the item must pick one IN THE ITEM:

* **Converge on one rule** (and `MIGRATING.md` regardless of which version component
  moves, per CLAUDE.md).  Go's LOW-bits truncation is the better-founded one — it is what a
  fixed-size byte array naturally yields and it is what C's `_RNL_KDF_DC[i]` loop does at
  256 — but Python's HIGH-bits rule is what the deployed Python CLI has always written.
  Whichever wins, C cannot follow without a variable-width `BitArray`, which it does not
  have.
* **Refuse `n != 256` for `hske-nla1`** in all four CLIs.  Fails closed, is a one-line
  change per port, makes the divergence unreachable rather than resolved, and costs the
  demo rings a mode they may not actually use — check before assuming they do.
* **Document the width as 256-only and leave the code alone.**  The weakest option and the
  one this repo's own history argues against: #274, #287 and #269 are all the same finding,
  an unrecognised or out-of-contract input silently taking a weaker branch.

**What must NOT happen.**  Picking the rule that makes the smallest diff.  The three causes
have different costs — (1) is a constant, (2) is C's whole fixed-width design — and a fix
that unifies (1) while leaving (2) would make C and Java agree with nobody while reporting
that the divergence was closed.

**Prerequisite for anything here:** a test that runs `hske-nla1` at a width other than 256
across all four CLIs.  There is none today, which is the reason this shipped, and it should
land before the fix rather than after it.

**Route 1 is not available today, and TODO #314 is what would make it so.**  Converging on
one truncation rule cannot be done in C, which is compiled for a single `KEYBITS` and
cannot represent a 128-bit A1 operation at all — so a convergence now would leave C
differing while reporting the divergence closed, which is what "what must NOT happen"
above names.  #314 (one internally-developed variable-width BitArray in all four
languages) removes that obstacle.  **This item is NOT blocked on it**: the defect is live,
the path to it is `genpkey --algo hkex-gf --bits 128` -> `kex` -> `enc --algo hske-nla1`,
and routes 2 and 3 are both available now.

**Evidence gathered for the route choice (v8.3.0, after filing).**  Route 2's cost was
listed above as "costs the demo rings a mode they may not actually use — check before
assuming they do".  Checked: **no `CliTest` script anywhere runs `hske-nla1` at a width
other than 256.**  All 42 invocations feed from default-width session keys; the eleven
`--bits 64` uses are HKEX-RNL, which since TODO #228 derives a 256-bit session key at
every ring dimension; the `--bits 32` uses are the Stern matrix dimension `N`; the single
`--bits 128` is a comment.  Route 2 would therefore break nothing in the test suite.  It
also has precedent already in the tree: Python and Go refuse `enc --aead` below 256 with
an explicit message, Java refuses `hske-nla3` below 256, and C is 256-fixed by
construction — so A1's AUTHENTICATED sibling already does what route 2 proposes, and the
unauthenticated path is the one that does not.

**Blast radius, corrected.**  It is not only `hske-nla1`.  `encfile` / `decfile` take the
width from the key and share the seed derivation, so they carry cause (1) too.  The AEAD
path is protected by its own 256-bit guard.

**THE PREREQUISITE HAS LANDED (v8.3.1): `CliTest/test_narrow_width_matrix.sh`**, claimed by
`cross-lang-compat`.  It pins the KNOWN DEFECT rather than asserting the contract, because
this item is undecided and a script asserting the correct contract would be red today and
would have to be ignored — the allow-list CLAUDE.md's Testing section refuses to have.
Both negative controls were checked and FIRE: changing one expectation cell fails, and so
does claiming an encryptor no longer refuses.  It carries an independent count check, so a
PARTIAL fix cannot pass quietly.

**Measuring it properly changed the picture, in four ways the original filing missed.**
The matrix is deterministic run to run — the divergence is structural, not key-dependent.
At n = 128 and n = 64, identically (rows = encryptor, columns = decryptor):

| | py | c | go | java |
|---|---|---|---|---|
| **py** | ok | wrong | wrong | wrong |
| **c** | wrong | ok | **ok** | wrong |
| **go** | wrong | wrong | ok | wrong |
| **java** | *enc refuses (exit 1)* | | | |

1. **Java's `enc --algo hske-nla1` already REFUSES a narrow key** (exit 1).  Java does this
   item's route 2 on the encrypt side today.
2. **C's `genpkey` does not accept `--bits` at all** — exit 2, "unrecognised flag".  C
   already fails CLOSED when asked to CREATE a narrow key; it fails OPEN only when
   IMPORTING one made elsewhere.  So the reachable path needs a second CLI to mint the key,
   which is exactly what the repro does.
3. **(c -> go) works while (go -> c) does not**, and the asymmetry names cause (2)
   precisely: C writes `der_i_n256` into every ciphertext regardless of the key's declared
   width, so C's artifact is LABELLED 256 and Go — which honours the label — follows it up
   to 256 and agrees.  Go's own artifact is labelled 128, and C reads it at 256 anyway.
   The mislabelling is a third defect, distinct from the truncation split.
4. **Java's `dec` returns ALL-ZERO plaintext with exit 0** on C's ciphertext — wrong in the
   particularly bad way of looking like a legitimately empty result rather than garbage.

**16 cells across the two widths exit 0 with the wrong plaintext.**  Zero cells refuse at
`dec` in any port.

**This strengthens route 2 and weakens route 3.**  Two of the four already refuse somewhere
on the path (Java at `enc`, C at `genpkey`), so route 2 is partly implemented by accident
rather than being a new policy; and route 3 (document 256-only, change nothing) would be
documenting that 16 cells silently return wrong plaintext, which is not a documentable
position.

Status: **OPEN**


---

### #314: one internally-developed variable-width BitArray in all four languages, replacing the three embedded bignum types

**TODO #313 is the symptom; this is the shape underneath it.**  #313 found `hske-nla1`
producing four different keystreams below 256 bits, from a domain constant truncated at
opposite ends in two ports and a width silently ignored in the other two.  That is not a
bug in one function.  It is what happens when four ports implement "an n-bit unsigned
value" four different ways and only ever compare notes at one width.

**The current state, which no document states in one place.**

| port | representation | width | backing |
|---|---|---|---|
| C | `uint8_t b[KEYBYTES]`, big-endian | **FIXED at compile time** (`KEYBITS` = 256, with an `#error` if the GF constants do not match) | its own byte array |
| Go | `BitArray{ Val big.Int; size int }` | variable | **`math/big`** (stdlib) |
| Python | `BitArray` over a Python `int` + `_size` | variable | **embedded arbitrary-precision int** |
| Java | bare `BigInteger` against a static `N = 256` | **FIXED at 256** | **`java.math.BigInteger`** (stdlib) |

So three of the four delegate the arithmetic to a type the project does not control, and
two of the four cannot represent a non-256-bit value at all.  Two are variable-width, two
are not, and no two of the four share an implementation of a single operation.

**What this item asks for.**  One BitArray library, written here, ported to all four
languages as the SAME algorithm over the SAME representation (a fixed-radix limb array,
explicit width, explicit endianness), used for every operation where the four are supposed
to be doing equivalent work: `xor`, `and`, `rol`/`ror`, shifts, masking, compare, the
GF(2^n) multiply and power, and the width-taking helpers (`rnl_kdf_seed` and friends).  No
`math/big`, no `BigInteger`, no reliance on Python's int, in the shipped primitives.

**Three reasons, and the third is the one that is easy to miss.**

1. **Compatibility.**  A shared implementation is the only thing that makes "the four
   agree" a property of the code rather than of four people's care at one width.  #313's
   constant-truncation split is exactly the class that cannot survive a common library,
   because there would be one truncation, in one place.
2. **Error tracking.**  An embedded bignum reports what IT considers an error, not what
   the protocol considers one.  A narrow value silently zero-extends, a negative
   intermediate silently becomes huge, an out-of-range shift is a language-defined result
   in three different languages.  A library written here can define and REPORT those as
   protocol errors, identically in four ports.
3. **Constant time, which is already conceded away in writing.**  `Herradura.java`'s own
   header says the C branchless tricks were not ported because "java.math.BigInteger gives
   no constant-time guarantee regardless".  That is a security property abandoned because
   of a dependency choice, and it is recorded in the source as settled.  A library written
   here can carry C's discipline into the other three; it does not get that for free, but
   it becomes possible instead of ruled out.

**Scope, honestly stated.**  This is the largest refactor the repo has had.  It reaches
every primitive in four languages, `herradura.h`'s fixed-width struct most of all, and C's
variable-width version has to keep working on AVR, ARM Thumb-2 and i386 where the
assembly ports use 32-bit operands by design.  The assembly and Arduino targets are
NOT in scope for variable width and should stay at their current fixed widths — this
item is about the four MAJOR languages, as named.

**The acceptance oracle already exists, and that is what makes this tractable.**  The
rewrite must be BEHAVIOUR-PRESERVING at 256 bits, and 256 bits is where everything is
pinned: `KAT/` (the classical quartet, `hkex_rnl.json`, `pem/`, `nl_fscx_v3.json`,
`hcred_kkw.json`, `sampler_replay.json`, `operation_replay.json`), the 4x4
`test_cross_lang_matrix.sh` at 518 assertions, and the numbered tests in all four
languages.  A port that changes one byte at 256 fails immediately and loudly.  **Do not
start this without running that whole set first and recording the baseline.**

**Sequencing against #313.**  This item is what makes #313's route 1 (converge on one
truncation rule) actually available — today it is not, because C cannot represent a
128-bit A1 operation at all, so "converge" would leave C differing while reporting the
divergence closed.  **#313 should NOT wait for this.**  #313 is a live defect with a
reachable path (`genpkey --algo hkex-gf --bits 128` -> `kex` -> `enc --algo hske-nla1`)
and needs a decision on its own timescale; this item may later make a different decision
possible, and #313 should say so rather than being blocked on it.

**Versioning.**  Behaviour-preserving at every width the four currently agree on, so in
principle PATCH/MINOR — but it changes `herradura.h`'s exported `BitArray` type, which is
a public C API surface that `bindings/ffi` and `docs/examples` use, so it needs a
`MIGRATING.md` entry and should be treated as **MAJOR** unless the type can be kept
source-compatible.  Decide that in the item, not in review.

**What must NOT happen.**  A fifth implementation.  The precedent across #294, #296, #297
and #308 is that an existing correct port is adopted verbatim rather than a new one
invented; here there is no existing correct port to adopt, because none of the four is
both variable-width and self-implemented, so the reference has to be WRITTEN and then
ported unchanged — and the first port to be written should be the one whose tests are
fastest to run against, not the one that is easiest to write.

Status: **OPEN**

