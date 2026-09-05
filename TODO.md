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

### #269: the Java CLI's five missing flag/subcommand capabilities

**Made visible by TODO #267's flag matrix.**  Originally filed as "much cheaper than
#268 — the primitives are already in `bindings/java/`; what is missing is the CLI
wiring."  **That premise was half wrong, and finding out which half is the main result
of the first pass.**

**`--digest` — DONE in v6.2.0.**  The correctness one, and it is fixed.  Java's
`cmdSign`/`cmdVerify`/`cmdThresholdAggregate` now apply the `hfscx-256` pre-hash at
READ time through one `readMessage(opt, cmd)` helper, which is where Python and Go
apply it and where C applies it in each of its three early-returning branches.
`CliTest/test_digest_matrix.sh` is the guard, claimed by `cross-lang-compat`: a 4x4
signer x verifier matrix on `hpks` and `hpks-nl` plus a rotated `threshold-aggregate`,
over a 768-byte message (24x the 32-byte key width, so raw and pre-hashed actually
differ).  It caught 39 failures against the pre-fix build and 0 after.

Two things worth keeping from how it had to be written.  (1) **The negative control is
what earns the file**, not the matrix: a CLI that parsed `--digest` and ignored it
would pass every positive cell, which is precisely how Java passed every existing
signature test, so each pair is also asserted to FAIL across the flag.  (2) It could
only ever have been caught cross-language — every signature test in the repo signs and
verifies within one language or compares PEM bytes, and a raw-message signature and a
digest signature are byte-identical in shape.

It also forced a fix to #267's own extractor: the call-graph followed only `cmd*`
handlers, so factoring three duplicated `--in` reads into `readMessage` made `sign --in`
read as ABSENT FROM JAVA.  It now follows any callee handed the subcommand's argument
container.  Verified to change no other cell of the matrix.

**`enc --aead` — RE-SCOPED, and it does not belong in this item.**  It is not CLI
wiring: `bindings/java/` has no AEAD primitive at all.  TODO #261's manifest already
records this, carrying `hske-nl-aead-xor-ks`, `hske-nl-aead-tag` and
`hske-nl-aead-streams` as `acknowledged` for Java.  So `--aead` is a primitive port
plus a codec change (format tag 2 carries a nonce and an auth tag) plus the CLI, which
puts it in #268's cost class, not this one.  **It should be re-filed as its own item**
alongside #268 rather than closed here; leaving it in #269 is what made this item look
cheap.

**`rand` — confirmed pure CLI wiring.**  `bindings/java/herradurakex/Hdrbg.java`
exists and is complete; only the subcommand and its seven flags are missing.

**`kex --kdf` — pure wiring for `hfscx-256`, but DO NOT PORT IT WITHOUT READING THIS.**
The port itself is a post-hash of the session-key bytes and Java has `Hfscx256.hash`.
The trap is what porting it DESTROYS: `--kdf`'s value sets differ (Python takes
`none`/`hfscx-256`/`sp800227` per TODO #165; C and Go take `none`/`hfscx-256`), and
#267's matrix is at FLAG granularity, so the only record of that value-level
divergence anywhere is the `reason` on the `kex --kdf` gap.  Giving Java the flag puts
`--kdf` at flag parity, which DELETES that gap row and with it the only written record
of the `sp800227` asymmetry.  That is #267's "anchor lost" failure reproduced one level
down, at the granularity its own matrix deliberately does not reach.

So the order is forced: **record the value-level axis first, port `--kdf` second.**
The cheapest honest form is a curated value-set table in `generate_spec.py`
alongside `CLI_FLAG_PARITY`, validated the same way in both directions.  Deriving
enumerated values mechanically is possible for Python (argparse `choices=`) but not
reliably for C/Go/Java, where the accepted set is a chain of string comparisons -- so a
derived-Python / curated-other-three split, with the Python side self-invalidating, is
probably the right shape.

**Remaining acceptance.**  `rand` and `--kdf` each delete their `CLI_FLAG_PARITY` /
`CLI_SUBCOMMAND_PARITY` entry, and `--check` fails until they do.  `--aead` moves to
its own item.

Status: **OPEN**

### #270: the `--commits` / `--commit` spelling split in the threshold subcommands

**Made visible by TODO #267's flag matrix, and the only gap there that is not a
capability difference at all.**  `threshold-aggregate` and `threshold-respond` take
`--commits a b c` in Python and Java and `--commit a --commit b` in C and Go;
`threshold-combine` splits the same way on `--partials` / `--partial`.  All four
implement threshold signing, produce identical PEMs, and interoperate — a documented
command line simply does not port between them.  Every parity check before #267
compared `--algo` tags and PEM bytes, which is precisely why this survived.

**This one is a MAJOR-version decision, and that is the reason it is filed separately
rather than folded into #269.**  Per CLAUDE.md, renaming or removing a CLI flag breaks
the stable 2.0.0 CLI surface and needs a `MIGRATING.md` entry.  The options are not
equal:

1. **Accept both spellings everywhere** — additive, MINOR, no migration entry, and it
   leaves four `defect` rows that must be re-stated as `acknowledged`.
2. **Converge on one spelling** — MAJOR, `MIGRATING.md`, and it breaks scripts.
   `--commit`/`--partial` (repeat the flag) is the more conventional CLI idiom and
   needs no `nargs`; `--commits`/`--partials` matches the two CLIs whose users are
   most likely to be scripting.
3. **Leave it, upgrading the four rows to `acknowledged`** with the reason that the
   capability is present in all four and only the spelling differs.

Option 1 is the recommendation: it makes every documented command line portable at no
compatibility cost.  Whichever is chosen, the outcome must be written into
`CLI_FLAG_PARITY`, which is what makes this closable.

Status: **OPEN**
