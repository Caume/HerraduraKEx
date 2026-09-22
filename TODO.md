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

**WHAT #313 DID, and what it leaves this item (v9.0.0).**  #313 took ROUTE 2: all four
CLIs now REFUSE `hske-nla1` at any width but 256, so the divergence is unreachable rather
than resolved.  That changes this item's standing in two ways worth recording.  It is no
longer holding back a live defect — nothing silently returns wrong plaintext any more —
so the pressure behind it is capability, not correctness.  And it acquires a concrete,
testable acceptance case it did not have: when this lands, `MIGRATING.md` §19's refusal is
what gets RELAXED, and `CliTest/test_narrow_width_matrix.sh` is what gets rewritten a
second time, from "all four refuse" to "all four agree".  **Relaxing a refusal breaks
nothing**, which is why route 2 was safe to take first and why this item is not now harder
to do.  A convergence is only worth doing if all four can be made to agree; C is the
constraint, and C is what this item is about.

**What must NOT happen.**  A fifth implementation.  The precedent across #294, #296, #297
and #308 is that an existing correct port is adopted verbatim rather than a new one
invented; here there is no existing correct port to adopt, because none of the four is
both variable-width and self-implemented, so the reference has to be WRITTEN and then
ported unchanged — and the first port to be written should be the one whose tests are
fastest to run against, not the one that is easiest to write.

**FIRST PASS DONE IN v9.0.1 — the specification, the conformance oracle, and the one
decision that gated everything else.**  `BITARRAY.md` is now the normative contract,
`KAT/bitarray.json` its 378 pinned cases at widths 32/64/128/256, and
`KAT/generate_bitarray_kat.py` the reference implementation that produced them.  No port
is converted; passes 2-6 are tabulated in `BITARRAY.md` §8.  Six things came out of the
pass, and four of them changed the item.

1. **THE VERSIONING QUESTION IS SETTLED, AND THE ANSWER IS NO.**  This item said to decide
   in the item, not in review, whether `BitArray` can stay source-compatible, and treated
   MAJOR as the likely answer because `bindings/ffi` and `docs/examples` use the type.
   Measured, they do not.  `bindings/ffi/herradura_shim.h` mentions `BitArray` **zero
   times** — the FFI ABI is flat `uint8_t[KEYBYTES]` buffers by the shim's own design, so
   the type is not on it, and the shim's `.c` body needs one mechanical
   `memcpy(ba.b, …)` → `ba_from_bytes(…)` pass with no exported signature moving.
   `docs/examples/c/hello_herradura.c` declares `BitArray` values and calls `ba_*` only,
   never touching `.b[]` or `KEYBYTES`, so it compiles unchanged.  All 95 direct-internals
   accesses outside `herradura.h` are in three in-tree files (the CLI, the tests, the
   suite walkthrough).  And `herradura.h` is header-only, so every consumer recompiles
   from the same header and there is no ABI boundary for the type to break at all.
   **So MAJOR is not forced on the C-API ground**, and passes 2-5 are MINOR at most.

2. **THE TRUNCATION RULE IS DECIDED: HIGH BITS, the big-endian prefix** (`BITARRAY.md`
   §4.4).  Not a coin toss.  It is the representation-natural rule — truncating a
   big-endian octet string is a slice, where low-bit truncation is arithmetic, and
   arithmetic is where the ports diverged.  Two of the four already say high bits:
   Python's `rnl_kdf_seed` does `_RNL_KDF_DC_256 >> (256 - n)`, and C's own declared
   narrow constants `_RNL_KDF_DC_32 = 0x6A09E667` / `_RNL_KDF_DC_64 = 0x6A09E667BB67AE85`
   are the high 32 and high 64 bits of the same value.  **Go is the outlier, and its rule
   was measured rather than read**: `ROL(k, n/8) XOR (DC_256 & (2^n - 1))` reproduces Go's
   output exactly at n = 32, 64 and 128.  The point of the decision is that there is then
   ONE truncation in ONE place, which is this item's reason 1 realised.

3. **REASON 2 IS NO LONGER AN ARGUMENT, IT IS A MEASUREMENT — and it is worse than the
   item claimed.**  The item said an embedded bignum "reports what IT considers an error,
   not what the protocol considers one".  The two variable-width ports do not merely fail
   to report; they return two DIFFERENT wrong answers to one expression.  A 64-bit array
   XORed with a 256-bit one gives, in Go, a value declaring `size = 64` whose `Val` is 201
   bits, which `Bytes()` then renders as **eight zero octets** — it copies nothing when the
   value overflows the declared width, so an over-wide intermediate reads back as zero with
   no error and no panic.  The same expression in Python masks to the left operand and
   **silently discards the right one entirely**.  C and Java cannot pose the question.
   That is TODO #313's shape one layer down: not four keystreams, but two ports and two
   silent wrong answers to a single XOR.  `BITARRAY.md` §3 makes it `E_MIXED_WIDTH`.

4. **THE REFERENCE IS BEHAVIOUR-PRESERVING, DEMONSTRATED ACROSS THREE PORTS.**  The
   acceptance standard this item set was that a port moving one octet at 256 fails
   immediately; the reference had to clear that bar first, or every later port would be
   chasing a new opinion rather than the existing agreed one.  It reproduces the shipped
   C suite at n = 256 on xor / rol / ror / fscx / fscx_revolve / gf_mul / rnl_kdf_seed /
   popcount, the shipped Go package on the same eight at 256, and the shipped Python suite
   on all eight at **32, 64, 128 and 256** — zero mismatches anywhere.  So the contract is
   the existing behaviour with the width rules made explicit, not a redesign.

5. **THE ORACLE SAYS OUT LOUD WHAT IT DOES NOT YET PROVE.**  A vector generated by the
   reference and checked only by the reference proves that nobody edited the file and
   nothing more; that is #234's vacuous pass waiting to happen, so `BITARRAY.md` §7 and the
   `CliTest/test_kat_vectors.sh` block both state it rather than letting currency look like
   coverage.  It becomes load-bearing at the first port and decisive at the second, because
   two independent implementations against one pinned answer is exactly what no round-trip
   or interop test can supply — those compare a port against another port's opinion.
   Both controls were verified to FIRE: a one-field edit to `bitarray.json` makes `--check`
   exit 1, and flipping the reference's truncation to low bits flips the report's
   `rnl_kdf_seed` row from `conforms` to `DIVERGES`.

6. **THE CONFORMANCE REPORT IS A REPORT, NOT A GATE, and that is deliberate.**  Every
   unconverted port is expected to diverge, and `CLAUDE.md`'s Testing section allows no
   failing test — there is no allow-list.  So `--check` (currency) gates and
   `--report` (per-port conformance) does not; a port joins the gating set when it is
   converted, one port one release.  Python today: 7 checked, 5 conforming, **2 diverging**
   — mixed-width `xor`, and `from_uint` masking `2^32` to 0 where §4.1 requires `E_RANGE`.

**What the pass did NOT do, stated so it is not re-derived as an oversight.**  No shipped
port was touched: this is a specification, a vector file and a generator, and the suite,
the four CLIs and every existing test are byte-for-byte unchanged.  The item's own
instruction was to record the baseline before starting, and it is recorded — 518/0
cross-language, 252/0 malformed-PEM, 48/0 narrow-width, 21/0 param-bounds, both KAT
generators current, all four `spec/` checkers OK, at v9.0.0.

Status: **OPEN**

