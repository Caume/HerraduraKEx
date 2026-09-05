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
alongside a QC-MDPC parameter change, and close to worthless before one.  Filed so the
question is not lost, explicitly deprioritised until a parameter item exists.

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

**What is left, and it is the whole of what is left.**  (1) The model is an ESTIMATOR:
annealed, a first moment, which bounds nothing on its own since a first moment can be
carried by rare graphs, and validated against exact mu only at n <= 13, where it runs
3-15% BELOW the truth and converging upward.  The cheapest upgrade is named precisely --
the annealed count over-counts cycles sharing edges, so the gap is a SECOND-MOMENT
question about the same two inputs, both exactly computable by the machinery now in place.
(2) The LINEAR HULL, unchanged from §11.36.9: a trail statement is not a hull statement,
and nothing in this line of work reaches the hull.

**Reach.**  No production-track row.  HSKE-NL-A2 and `twk` are demo-only for reasons on
other axes (#243, #244, #248), and #254's three production-track rows -- HSKE-NL-A1,
HFSCX-256 and everything inheriting the hash -- left the scope of a trail bound entirely
in §11.36.8, because in both those modes the attacked input is the round CONSTANT, which
enters every round at once, so there is no trail to bound.  This item can therefore move
no rating in either direction, and is filed as an outstanding proof obligation behind
figures already published, not as a gate on anything.

Status: **OPEN**
### #268: port the passphrase-encrypted private-key envelope to C, Go and Java

**Made visible by TODO #267's flag matrix**, where it is `spec/`'s largest single
`defect` cluster: `genpkey --passphrase`, `genpkey --kdf-iterations`,
`pkey --passphrase` and `pkey --decrypt` are all Python-only, so a key exported this
way is unreadable by three of the four CLIs.  TODO #166 (v1.9.134) scoped it to Python
deliberately, matching its own Low priority; that was a reasonable call then and the
note lived only in #166's text, which is the drift #267 exists to catch.

**Not a thin port.**  It needs PBKDF2-HFSCX-256, which needs `hmac_hfscx_256` in Java
first — TODO #261's primitive manifest already carries that as `acknowledged` for
exactly this reason, so closing this closes both the missing primitive and the missing
flag.  Then the `HERRADURA ENCRYPTED PRIVATE KEY` envelope, and a fail-closed read path
in every subcommand that loads a key: an encrypted key reaching a build that does not
understand the envelope must be refused, never mis-parsed.

**Acceptance.**  All four CLIs write and read the envelope, cross-checked in
`CliTest/` as a 4x4 matrix (writer x reader) rather than each against Python — the
shape `test_zkp_hybrid_family.sh` adopted after #261 found a pair that had never
interoperated because every test compared to Python.  A KAT/pem/ artifact pins the
envelope's bytes.  On success the four `defect` rows and #261's `hmac-hfscx-256`
acknowledgement are deleted, and `generate_spec.py --check` FAILS until they are —
that is the anchor-lost direction working as designed.

Status: **OPEN**

### #271: the HPKST AGGREGATE PEM's trailing `n` is DER-encoded at two different widths

**Found while verifying TODO #270** by comparing aggregate PEMs byte-for-byte across
CLIs -- something no test had done, because every threshold test checks that the
artifacts INTEROPERATE and none checks that they are IDENTICAL.

For the same commitments and message, Python and Java emit the final `n` field as a
4-byte DER INTEGER (`02 04 00 00 01 00`) while C and Go emit the minimal 2-byte form
(`02 02 01 00`). Both decode to 256, every CLI accepts either, and the whole 4x4
threshold matrix passes -- so this is a wire-format inconsistency with no functional
symptom today.

**It predates #270** (confirmed by rebuilding the pre-change C and Python CLIs and
re-comparing), and #270 did not touch it.

**Why it is worth an item.** `spec/` treats PEM bytes as a contract -- `KAT/pem/`
exists precisely to pin them, and TODO #240's malformed-PEM matrix rests on the four
CLIs agreeing about field widths. A field whose width depends on which CLI wrote it
is a latent difference in any byte-comparison, and the fix direction is not obvious:

1. **Converge on minimal width** (C/Go's form) -- matches DER's own canonical
   encoding rules and shortens the artifact, but changes the bytes Python and Java
   have been emitting since the subcommand shipped.
2. **Converge on fixed width** (Python/Java's form) -- changes C and Go instead.
3. **Leave it, and document that this field's width is not pinned** -- honest, but it
   means `KAT/pem/` can never gain an aggregate vector.

Either convergence changes bytes on the wire for two of the four CLIs. Since every
reader accepts both, no stored artifact becomes unreadable, so this is very likely a
`MIGRATING.md` note rather than a MAJOR bump -- but that call belongs to whoever
takes it.

**First step for whoever does:** audit the OTHER multi-CLI PEMs the same way. This was
found by accident on one field of one label; nothing has ever compared the rest
byte-for-byte across all four writers, and `test_rand.sh` gained exactly that check
for `HDRBG STATE` in v6.3.0 (where all four already agreed).

Status: **OPEN**

### #272: the C CLI's 64-value list-flag limit is arbitrary, undocumented, and unmatched

**Found while verifying TODO #270**, by driving `threshold-aggregate` with 70
commitments in each CLI and comparing each one's result against its own 64-signer
result.

C collects `--commits`/`--commit` and `--partials`/`--partial` values into a fixed
64-entry array. Until v6.4.0 it stopped filling that array **silently and returned
success**, so a ceremony with more than 64 signers produced an aggregate over the
first 64 in C while Python, Go and Java used every one — the same command line
yielding a different signature depending on which CLI aggregated it, with no
diagnostic anywhere. Pre-existing (verified against a rebuilt pre-#270 binary) and
invisible to every test, because nothing had ever run a ceremony larger than a handful
of signers.

**v6.4.0 made it fail loudly** (`--commits: at most 64 values supported`), asserted in
`CliTest/test_threshold_interop.sh` along with the boundary case. **That is the
containment, not the fix**, and this item is the fix.

**The open question is what the limit should be.** The three facts that shape it:

* Python, Go and Java impose no limit at all, so 64 is not a protocol constant — it is
  one implementation's buffer size, and nothing in `spec/` or `SPEC.md` mentions it.
* HPKS-T is an n-of-n scheme, so the signer count is a deployment choice, not a
  parameter. There is no principled ceiling to point at.
* C's arrays are stack-allocated in three call sites plus `get_arg_multi2`'s two
  scratch buffers, so raising the number naively raises stack usage in all of them.

Options: heap-allocate and drop the limit (matching the other three, at the cost of C's
current allocation-free argument parsing); raise it to a documented constant and put
that constant in `spec/`; or declare 64 a deliberate protocol-wide maximum and enforce
it in all four, which is the only option that makes the CLIs agree rather than merely
making C honest.

**Worth checking at the same time:** whether any other C list-flag or fixed-size
argument buffer truncates the same way. `get_arg_multi` was the one this surfaced
through; nothing has audited the rest.

Status: **OPEN**

### #273: port HSKE-NL-AEAD to Java (`enc --aead`)

**Split out of TODO #269**, which had carried it as one of "Java's five missing
flag/subcommand capabilities" on the premise that all five were CLI wiring over
primitives `bindings/java/` already had.  For `--aead` that premise is wrong, and
leaving it in #269 is what made that item look cheap: `bindings/java/` has no AEAD
primitive at all.  TODO #261's manifest already records this, carrying
`hske-nl-aead-xor-ks`, `hske-nl-aead-tag` and `hske-nl-aead-streams` as
`acknowledged` for Java.

**Cost class is TODO #268's, not #269's.**  Three parts, in order: the AEAD
primitive itself (keystream XOR, the tag, and the two-stream derivation); a codec
change, since format tag 2 carries a nonce and an auth tag that the Java codec has
no shape for; and only then the CLI flag on `enc` and `dec`.

**Acceptance.**  All four CLIs encrypt and decrypt the format, cross-checked as a
4x4 (encryptor x decryptor) matrix rather than each against Python -- the shape
`test_zkp_hybrid_family.sh` adopted after TODO #261 found a pair that had never
interoperated because every test compared to Python.  `CliTest/test_aead.sh` is
the existing 9-way script and grows to 16.  A tag that fails to verify must be
refused rather than returning plaintext, and that rejection is asserted in every
language.  On success the `("enc", "--aead")` row in `spec/generate_spec.py`'s
`CLI_FLAG_PARITY` and #261's three `acknowledged` manifest cells are deleted, and
`generate_spec.py --check` FAILS until they are.

Status: **OPEN**
