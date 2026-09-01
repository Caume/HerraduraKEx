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


### #260: bring Java to full parity with C/Go/Python — functions, demo, tests, CLI, CI, cross-interop

Java (`bindings/java/`) has been a genuine, mostly-complete port since TODO #196-#203, and
gets carried along with most new work (#245, #255, #258/#259's audit all touched it). But it
has never been held to full parity, and several past items documented the gap and explicitly
declined to close it rather than losing track of it: TODO #240 ("**Not in scope.** Adding
`hpks-ring` to the Java CLI ... stays out of scope and remains a gap"), TODO #241/#242/v4.0.0
("Landed identically in C, Go and Python (Java ships neither)"), TODO #255 ("Java ships no
duplex, fpe or twk"). This item is where that stops being scattered across other items' scope
notes and becomes its own tracked gap, closed a piece at a time the way #255's four passes
closed the v3 primitive.

**Progress.**  v5.3.0 ported the 78.C ratchet (`Ratchet.java`); v5.3.1 added HDRBG
(`Hdrbg.java`, TODO #96); v5.3.2 added HPKS-T (`HpksT.java`, TODO #98); v5.3.3 added FPE/twk
and their v3 variants (`FpeTwk.java`, TODO #78.A/#78.B/#255); v5.3.4 added
HSKE-NL-V2/V3-Duplex (`Duplex.java`, TODO #95 Option 2/#255); v5.3.5 added HPKS-Stern-Ring
(`SternRing.java`, TODO #78.I) — **all seven** missing primitives listed below are now
ported, each with its own `SelfTest.java` round-trip coverage.  Five of the seven (Ratchet,
HDRBG, FPE, twk, Duplex) were cross-checked byte-for-byte against Python's output for the
same fixed inputs (there is no
KAT vector for any of them in `KAT/`); HPKS-Stern-Ring and HPKS-T are inherently randomized
protocols (fresh nonces/challenges each call, matching all three existing languages), so
those two are checked structurally instead — round-trip validity, tamper rejection, and (for
the ring signature) rejection of a forged signature from a secret matching no ring member's
syndrome, run repeatedly and at every ring position.  HPKS-T, FPE and twk unlike
Ratchet/HDRBG/Duplex DO have CLI subcommands in C/Go/Python (`--algo hpks-t` TODO #106;
`fpe`/`twk` subcommands); HPKS-Stern-Ring also has one (`sign --ring`/`verify --ring` or
equivalent — audit the exact flag shape against the C/Go/Python CLIs when step 3 is worked,
rather than assumed here).  Every pass through v5.3.5 ported only the library primitive +
`SelfTest` coverage (step 1 of the scope below); step 1 is COMPLETE.  v5.3.6 started step 3
(CLI subcommands) with `fpe`/`twk` (both v2 and v3) in `HerraduraCli.java`, verified
byte-exact against `herradura.py`'s CLI output and cross-language round-tripped.  Step 2
(numbered-test parity matching C/Go/Python's [44]-[48]) remains open — `SelfTest.java`'s
existing per-primitive coverage (round-trip, tamper rejection, and protocol-specific checks
like forward secrecy or forgery rejection) is comparable in kind but was never explicitly
checked against the C/Go/Python test numbering for gaps.  Steps 3 (remaining: `hpks-t`,
`duplex`, `hpks-ring`), 4 (Java demo), 5 (its CI step), and 6 (interop coverage) are all
still open.

**What is actually missing, confirmed against the current tree, not assumed:**

* **Library functions/protocols.**  All seven primitives that were missing are now
  ported — Ratchet (78.C), HDRBG (#96), HPKS-T, FPE/twk (both v2 and v3),
  HSKE-NL-V2/V3-Duplex, and HPKS-Stern-Ring (78.I) — see Progress above. This bullet is
  DONE; the remaining gaps are the demo, CLI subcommands, the CI step, and interop
  coverage below.
* **Library demo.**  C, Go and Python each have a `Herradura cryptographic suite.{c,go,py}`
  that exercises every protocol end to end with human-readable +/- verdicts (and, since
  TODO #258/#259, an unambiguous `[FAIL]` gate).  Java has no equivalent — `SelfTest.java`
  is a compact round-trip test harness, not the narrated demo the other three languages
  ship, so a reader comparing "what does using this protocol from Java look like" has
  nothing to run.
* **CLI capabilities.**  `HerraduraCli.java` gained `fpe`/`twk` (both v2 and v3) in
  v5.3.6 — see Progress above.  Still missing: `hpks-t`, `hpks-ring`, and the research
  `duplex` AEAD subcommand.  `hpks-t`'s library primitive is ported, but its multi-round
  threshold-signing CLI protocol (TODO #106 in C/Go/Python) is not; the research `duplex`
  AEAD's and `hpks-ring`'s library primitives (duplex both v2 and v3) are ported, but
  neither has a CLI subcommand (including whatever ring-signature flag shape C/Go/Python
  use).  (`pkey` and `hdrbg`/OPRF/aPAKE-adjacent subcommands: audit
  against `spec/herradura-protocol-spec.json`'s `cli_binding` map when this item is worked,
  rather than assumed here.)
* **CI checks.**  `native-java` never runs a demo-equivalent step, because none exists; it
  cannot inherit #258/#259's `[FAIL]`-gated demo run without #260 shipping the demo first.
  `SelfTest.java`'s own pass/fail gate (a direct `fails` counter, `System.exit(1)`) is
  functionally sound but is a third gating idiom next to C's output-scanning `hprintf`, Go's
  `os.Stdout` pipe, and Python's `print` shadow — worth noting, not necessarily worth
  unifying for its own sake.
* **Cross-interoperability checks.**  `cross-lang-compat`'s `test_cross_lang_matrix.sh` and
  `test_malformed_pem_matrix.sh`, and `CliTest/test_v3_family.sh`, all degrade to a NOTE or
  skip Java's cell for exactly the families above — `test_v3_family.sh`'s own header says so
  explicitly.  Every function/CLI gap above is therefore also an interop-coverage gap: there
  is no `test_java_*_interop.sh` for a protocol Java cannot run.

**Explicitly out of scope, and why.**  HCRED-KKW (`hcred_prove_kkw`/`hcred_verify_kkw`) is
NOT a Java gap — it exists only in the Python suite file today, absent from C, Go, *and*
Java alike, so it is a separate Python-only-feature item, not a C/Go/Python-vs-Java
asymmetry.  Don't fold it in here.  Likewise the assembly/Arduino targets are not this
item's concern — they are deliberately narrower ports (N=32, t=2, demo-only) and were never
held to suite-language parity.

**Scope for the work, expected to land in stages like #255 did, each its own PATCH or MINOR
bump per CLAUDE.md's versioning rule (a new CLI subcommand is MINOR):**
1. Port each missing primitive to `bindings/java/herradurakex/` (Ratchet, HDRBG, HPKS-T,
   HPKS-Stern-Ring, FPE, twk, HSKE-NL-V2-Duplex, and the v3 variants of the latter three),
   cross-checked against the existing KAT vectors the way `KatVerify.java` already does for
   everything else.
2. Add `SelfTest.java` round-trip coverage for each, matching the granularity the C/Go/Python
   test [44]-[48] additions used.
3. Add the CLI subcommands to `HerraduraCli.java` and regenerate `spec/` (`generate_spec.py`)
   so `cli_binding` picks them up — `check_security_md.py` and the schema gate must stay green.
4. Write the Java suite demo (`bindings/java/herradurakex/Demo.java` or similar — name it
   when the work starts, don't presume it here) mirroring the other three's protocol-by-
   protocol narration, with the same `[FAIL]`-marker gate #259 gave C/Go/Python.
5. Add a `native-java` CI step that runs it, gated the same way.
6. Add or extend the `CliTest/test_java_*_interop.sh` / `test_cross_lang_matrix.sh` /
   `test_v3_family.sh` coverage so every newly-ported feature gets a real 4-way (or
   3-way, where a feature predates v3) interop check instead of a NOTE.

**Acceptance criterion.**  Done means every `grep`/scope note above finds nothing: no
protocol, CLI subcommand, demo section, test, or interop script that exists for C, Go and
Python but not Java, and no cross-lang-compat script that skips Java's cell with a NOTE for
a feature reason (a language-inherent reason, if any turns up during the work, gets
documented as ACKNOWLEDGED instead of silently left as OPEN forever).

Status: **OPEN**

### #261: full 4-way capability parity — C, Go, Python and Java run the exact same algorithms and tests

**Distinct from TODO #260, and the direction matters.**  #260 is "Java catches up to
C/Go/Python" — every gap it lists is something the other three have and Java lacks.  This
item is the symmetric closure: no language may have an algorithm, protocol variant, or
security test that any of the other three is missing, **in either direction**.  Once #260
lands, this item is what keeps all four in lockstep going forward, and it already has at
least one confirmed gap #260 does not cover, because #260 explicitly excluded it.

**Confirmed asymmetry #1 — HCRED-KKW, named in the request that opened this item.**  The
KKW preprocessing-model transcript variant (`hcred_prove_kkw`/`hcred_verify_kkw`, ~11x
smaller proofs than the ZKBoo-(2,3) path at production parameters) exists **only in
Python**:

```
Herradura cryptographic suite.c   -- absent
Herradura cryptographic suite.go  -- absent
Herradura cryptographic suite.py  -- hcred_prove_kkw / hcred_verify_kkw, ~113 lines
bindings/java/herradurakex/Hcred.java -- absent, and says so explicitly:
    "The KKW preprocessing-model transcript variant ... is out of scope for
     this port -- the ZKBoo-(2,3) path here is sufficient for interop."
```

Java's own doc comment is a documented, deliberate exclusion — which is exactly the
ACKNOWLEDGED outcome this item should produce for anything that turns out to be a genuine
per-language reason, rather than four different implicit answers to the same question.  C
and Go have never addressed it at all.  Resolve it one of two ways when this item is worked:
port KKW to C, Go and Java so all four match Python; or downgrade Python's KKW path to
explicitly ACKNOWLEDGED non-parity (a research/demo convenience, not a security-relevant
divergence) and record why in `SECURITY.md`/`spec/`.  Don't leave it as an unstated fact
four different files each know a different piece of.

**Confirmed asymmetry #2 — test coverage, not just algorithm coverage.**  The request is
explicit that tests are in scope, not only the primitives:

```
CryptosuiteTests/Herradura_tests.c   32 `test_*` functions
CryptosuiteTests/Herradura_tests.go  37 `test*` functions
CryptosuiteTests/Herradura_tests.py  36 `test_*` functions
bindings/java/herradurakex/SelfTest.java  ~20 PASS/fail checks, unnumbered
```

C/Go/Python additionally share a **numbered** test convention ([1]-[48], stable IDs cited
throughout `CHANGELOG.md`/`TODO_DONE.md` — e.g. "test [45] runs its Stern-F sub-check at
`rounds=32`", "test [46] is TODO #242's regression guard").  `SelfTest.java` has no
equivalent numbering, so a Java gap can't even be cited by the same vocabulary the other
three use to talk about test coverage.  Bringing Java's test count up (TODO #260, item 2)
should also adopt the numbered convention, not just close the count gap.

**Relationship to #260 and sequencing.**  Work #260 first — most of what #261 would flag
today is exactly #260's Java list, and fixing it there is the direct fix.  What #261 adds on
top: (a) the reverse-direction check (does every OTHER language have what Python/Go/C
individually grew, like KKW), and (b) turning "parity" from a one-time audit into something
checked mechanically going forward, so a fifth divergence doesn't accumulate silently the
way KKW apparently did.

**Proposed mechanism, to design when this item is worked, not decided here.**  The repo
already has two coverage guards in this family — `ci.yml`'s native-interop step failing if a
`CliTest/*.sh` script isn't claimed by exactly one job, and `check_part_index.py` failing if
`SecurityProofs-*.md`'s banners disagree.  A `check_language_parity.py` in the same spirit —
enumerating each language's public functions/CLI subcommands/numbered tests and diffing the
four sets — would turn every future asymmetry (Java or otherwise) into a caught CI failure
instead of a fact three other files quietly don't know.  Scope, false-positive rate (a
language-appropriate helper that isn't a protocol function shouldn't count), and where it
runs are all open design questions for whoever picks this up.

**Acceptance criterion.**  For every protocol/primitive and every named security test, the
four-language table has either all four cells filled, or a cell marked ACKNOWLEDGED with a
recorded reason (never a silent absence) — checked by the mechanism above rather than by a
one-time read of the source tree, so it stays true.

Status: **OPEN**
