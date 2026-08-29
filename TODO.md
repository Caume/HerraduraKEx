# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

New items go here with `Status: **OPEN**`; see CLAUDE.md.

---

### #246: give the NL-FSCX v2 cipher family an AND-based nonlinear layer

The v2 family — HSKE-NL-A2, HPKE-NL, HSKE-Duplex, `fpe`, `twk` — is rated demo-only, and
TODO #243/#244 identified exactly why: there is no PRP/SPRP reduction for
`nl_fscx_revolve_v2` at any round count, and the only quantitative evidence is TODO #214's
key-averaged differential trail bounds, which #214 itself calls an order-of-magnitude
indication rather than a bound.  TODO #245 removed the structural objections (round
constants), which puts those bounds back in the binding position.  This item attacks the
bounds themselves, by changing what they are bounds *on*.

**The gap, precisely.**  `FSCX(A,B) = M(A ⊕ B)` is GF(2)-**affine** — algebraic degree 1.
All of v2's nonlinearity comes from one modular addition, `+ δ(B)`, whose degree grows only
through carry propagation.  That is a thin and highly structured source of nonlinearity,
and it is why the trail bounds are what they are.

**Scope, and why this is not blocked by the impossibility theorems.**  TODO #210, #224 and
#230 rule out non-linear step functions for **HKEX-style agreement** — #230's
characterization theorem shows *any* step function admitting that agreement hands Eve the
session key.  That is a statement about key exchange.  **No shipped protocol uses
FSCX_REVOLVE for agreement any more**: HKEX-GF is Diffie-Hellman over GF(2^n)*, HKEX-RNL is
Ring-LWR, and every remaining `fscx_revolve`/`nl_fscx_revolve_v2` call site in the CLI is an
encrypt or decrypt.  So the cipher family is free to become non-linear; only the (already
retired) agreement construction was not.  **Verify this claim still holds before starting** —
it is the load-bearing premise of the whole item.

**Design constraint that eliminates most candidates: invertibility.**  `dec`, `decfile`,
`fpe --decrypt` and `twk --decrypt` all ship, so any new layer must be a bijection on the
256-bit block.  A bare AND or OR layer is not — and is not balanced either
(`P(a∧b=1) = 1/4`, `P(a∨b=1) = 3/4`).

**Two candidates, both measured (see the research notes below).**

*A. Simon-style Feistel round.*  `(x, y) → (y, x ⊕ (y⋘1 ∧ y⋘8) ⊕ y⋘2 ⊕ k)` on two 128-bit
halves.  **Invertible by structure**, whatever the F-function does, at any block size —
verified.  Degree 2 per round.  Has a decade of third-party cryptanalysis to borrow bounds
and methodology from, which is the entire point: it makes a *provable* differential/linear
bound reachable rather than conjectural.  Cost: a Feistel round diffuses half the state per
round, so the round count needs re-deriving rather than inheriting 192.

*B. Keccak's χ.*  `a_i ← a_i ⊕ (¬a_{i+1} ∧ a_{i+2})`, degree 2, one AND and one XOR per bit —
the cheapest option.  **But it is a bijection only on odd-length rows**, verified
exhaustively for lengths 3–12, and `256 = 2^8` has **no odd divisor greater than 1**, so a
256-bit state admits no uniform odd-length row decomposition.  χ cannot be dropped in as-is.
Workarounds to evaluate: 255 bits of χ with one bit passed through; non-uniform rows; or a
state resize.  Each changes the block or the wire format, so cost this before committing.

**On the OR half of the proposal.**  `b ∨ c = b ⊕ c ⊕ (b ∧ c)`, so any OR-based layer is an
AND-based layer plus linear terms.  OR adds no algebraic degree that AND does not, and used
bare it biases the state.  The balanced idiom — used by both χ and Simon — is to XOR the AND
term *into* the state.  Recommend AND only; record OR as considered and redundant rather
than silently dropped.

**The cost nobody should discover late: masking.**  TODO #78.H's Boolean masking is *free*
today precisely because FSCX is GF(2)-linear —
`fscx_revolve(A⊕r, B) ⊕ fscx_revolve(r, 0) = fscx_revolve(A, B)`, with no secret bit in any
intermediate.  **An AND gate destroys that identity.**  Masking an AND needs an ISW/DOM
gadget: `d` shares cost `O(d²)` AND operations plus fresh randomness per gate, per round.
Quantify this before choosing a candidate, and quantify it *on AVR*, which has the tightest
budget and a known SRAM ceiling (TODO #155).  It is entirely possible the honest outcome is
"stronger cipher, masking moves from free to expensive" — that is a legitimate trade, but it
must be a decided one, and `SECURITY.md`'s masking claims would need revisiting.

**Plan.**
1. Re-verify the scope premise (no shipped agreement use of FSCX_REVOLVE).
2. Prototype both candidates at reduced width in `SecurityProofsCode/`; confirm
   invertibility, measure algebraic degree growth and avalanche against current v2.
3. Run TODO #214's exact `xdp+` SMT search against each new round function — this is where
   the item either pays off or does not, and it is also why **#247 should land first or
   alongside**: the current tooling does not scale to n = 256 and a new round function needs
   bounds at least as good as the ones it replaces.
4. Measure masked and unmasked cost in C, Go, Python and on AVR.
5. Only then choose, and write the migration.

**Reach.**  Changing the v2 round function breaks HSKE-NL-A2, HPKE-NL, HSKE-Duplex, `fpe`
and `twk` together — the same five as TODO #245, one deliberate MAJOR and one
`MIGRATING.md` section, with the silent-failure warning that `fpe`/`twk` need.

**Explicitly not in scope.**  Re-rating anything.  That is #248, and it must not be granted
by the item that performs the work — the failure mode #237, #238, #243, #244 and #245 have
all been about.

**Progress — steps 1 and 2 are done.**  `SecurityProofsCode/nl_fscx_v2_and_layer.py`.

* *Step 1, premise re-verified and narrower than feared.*  `hkex-gf` agrees via `gf_pow`,
  `hkex-rnl` via `_rnl_agree`; the single FSCX in a kex path is a **v1 KDF applied after
  agreement**.  So this touches no key exchange, and no v1 consumer either — HFSCX-256 and
  HSKE-NL-A1 are out of scope.  Affected: exactly the five listed above.
* *The parity obstruction dissolves.*  χ is applied per row and the rows need not be equal;
  a sum of odd parts is even iff the number of parts is even.  **Rows of 127 + 129** give a
  bijective χ over the whole 256-bit state — no passthrough bit, no resize.  Verified.
* *Both candidates are bijections* at reduced width, and both keep `M`.
* *Measured, and the ordering holds at two widths* (n = 10 exhaustive, n = 14 sampled; both
  widths chosen with `M` invertible).  Max differential probability:

  | rounds | current v2 | A: Feistel + AND | B: v2 then χ |
  |---|---|---|---|
  | 1 | 1.000 | 1.000 | 0.281 |
  | 2 | 1.000 | 0.250 | 0.086 |
  | 3 | **1.000** | 0.125 | 0.018 |
  | 4 | 0.375 | 0.031 | 0.014 |

  At n = 14 the margin is wider: B is at the random-permutation floor by round 3 (0.00085)
  where the deployed round is still at 0.102.

* *A finding about the CURRENT construction, not just the candidates:* deployed v2 has a
  **probability-one differential through three rounds**, and is still at 0.375 after four.
* *Raw algebraic degree is not the deficiency.*  The deployed round already reaches degree 5
  in one round at n = 10, from carry propagation — "FSCX is affine" is true of FSCX, not of
  v2.  The deficiency is differential behaviour.

**Interim recommendation: candidate B**, and TODO #247(c) has since confirmed it holds on
the *linear* axis too (B 3.48 bits over three rounds at n = 10, A 2.00, deployed v2 0.16),
so the recommendation is not an artefact of having looked only at differentials.  On
measurement and on smallest-diff grounds.  But
candidate A's advantage is different in kind and should not be dismissed — a Simon-style
Feistel inherits a large third-party literature, and the point of this item is to make a
*provable* bound reachable, which a better-measured construction with no literature may not.

**Step 3, tractable half done.**  Optimal single-trail weight is the currency #214 reports,
so it was computed *exactly* — full one-round DDT, then a dynamic program over difference
states, giving proven optima rather than solver output that might have timed out.  Averaged
over 3 keys, `-log2(p)`:

| rounds | v2 (n=10) | A | B | | v2 (n=11) | A | B |
|---|---|---|---|---|---|---|---|
| 1 | 0.00 | 0.00 | 1.78 | | 0.00 | 0.00 | 2.00 |
| 2 | 0.06 | 2.00 | 4.66 | | 0.39 | 2.00 | 4.83 |
| 3 | **0.39** | 3.00 | 7.52 | | 2.18 | 3.00 | 7.74 |
| 4 | 1.86 | 5.00 | 10.42 | | 4.36 | 5.00 | 11.00 |

The deployed round accumulates **0.39 bits of trail weight over three rounds** at n = 10 — a
trail of probability 0.76.  Candidate B has more weight after one round than v2 has after
three.  Cross-checks against the §4 differentials are consistent throughout (a differential
is at least as likely as its best trail).

**A caveat the numbers themselves reveal.**  B hits 11.00 bits at n = 11 after 4 rounds —
the full width — so it has *saturated* and its slope is truncated.  A slope read off a
saturated series is a lower bound, and comparing slopes when one construction saturates and
another does not is unreliable.  The rounds 2→4 window gives ~2.0 bits/round for v2
(consistent with #214's 1.87), 1.5 for A, and *at least* 3.1 for B — the last being exactly
the untrustworthy one.  These widths saturate too fast to extrapolate from, which is the
argument for #247's MILP rather than a bigger version of this.

**Remaining.**  (3, rest) bounds at realistic width — **#247 gates the decision**; nothing
here is a bound at n = 256.  (4) Masked and unmasked cost in four languages and on AVR.
(5) Migration.  **Open technical risk in candidate B:** χ is normally applied to equal,
short rows, and 127 + 129 is neither — whether Keccak's own symmetry arguments survive
unequal long rows is unexamined, and it is the main reason not to treat B as settled.

Status: **OPEN**

### #247: provable trail bounds — MILP scaling, fixed-key differentials, exact Walsh

TODO #214 closed with three explicit recommendations that were never filed.  They matter
more now than when they were written: TODO #243 and #244 both had to lean on #214's bounds,
and both had to caveat them as key-averaged and order-of-magnitude — which is a large part
of why HSKE-NL-A2 was downgraded and `twk` not promoted.  #246 will also need them.

**(a) A MILP formulation that scales toward n = 256.**  #214's SMT search closes only for
small widths and small round counts; everything at the deployed width is extrapolation, and
#214 labels that projection its own weakest step.  MILP is the standard tool for ARX and
AND-based trail bounds at realistic widths.

**(b) A fixed-key differential treatment.**  #214 flagged this as "the open question this
analysis surfaces rather than settles", and it bites unusually hard here: NL-FSCX reuses one
key in every round, so per-round deviations correlate instead of averaging out.  #214
measured, at n = 8, that every key has some differential running well above its key-averaged
value.  A key-averaged bound is the right currency for comparing designs and is what ARX
practice reports, but it is **not** a per-key security claim, and no document currently says
so outside #214's own text.

**(c) An exact Walsh-Hadamard transform at small width.**  #214 deferred the Walsh-spectrum
sub-item because as written it asked to resolve a `2^-16` bias by sampling — about `2^32`
evaluations per functional, out of reach.  The tractable substitute is an exact transform at
reduced width, which #214 said "deserves its own item rather than a rushed appendix".  This
is that item.

**Why this is worth doing even if #246 is not.**  These three would let the existing v2
family be described accurately rather than conservatively.  It is possible the outcome is
"the bounds are fine and the family was under-rated" — that would be a real result, and
#248 is where it would be acted on.

**Progress — (b) and (c) done, (a) done as far as exact methods reach.**
`SecurityProofsCode/nl_fscx_v2_bounds.py`.  Everything exact: full DDT/LAT, then a DP over
difference or mask states, so each figure is a proven optimum rather than a sample.

*(a) The slope is width-stable, which SUPPORTS #214.*  Optimal trail weight for the
deployed round at every exactly-reachable width with `M` invertible, 6 keys each:

| n | r=3 | r=5 | slope | saturated? |
|---|---|---|---|---|
| 8 | 2.03 | 4.83 | 1.40 | yes (>0.6n) |
| 10 | 1.88 | 5.12 | 1.62 | yes |
| 11 | 1.86 | 4.73 | 1.44 | no |
| 13 | 1.47 | 4.87 | 1.70 | no |

Range 1.40–1.70, no monotone drift, bracketing #214's independently measured 1.87 closely
enough that its methodology is not in question.  **A near-miss worth recording:** an earlier
2-key run gave 1.30 at n = 13 and appeared to show the slope collapsing with width — which
would have meant #214's projection and the 137-round figure were optimistic.  It does not
reproduce at 6 keys.  Two keys is not a sample for a statistic with this spread.

*(b) The per-key spread is large.*  Optimal 5-round trail weight across keys at n = 11 runs
from 0.70 to 7.71 on a mean of 4.73 — a spread wider than the mean.  A key at the weak end
has almost no 5-round trail resistance while the averaged figure advertises ~4.7, and
nothing screens for it: there is no trail-behaviour analogue of TODO #235's QC-MDPC
weak-key screen, and `nl_v2_key_is_valid` covers only the degenerate affine class.  Not a
new attack — the reason "key-averaged" must stay attached to every figure, and the reason a
rating cannot rest on an averaged bound.

*(c) Exact linear cryptanalysis, an axis nobody had measured.*  Optimal linear-trail weight
`-log2|c|` at n = 10: deployed v2 reaches **0.16 bits over three rounds** — correlation ≈ 0.90,
very nearly deterministic — against 2.00 for candidate A and 3.48 for candidate B.  Run
specifically to test whether #246's recommendation was an artefact of looking only at
differentials.  **It was not:** B leads on both axes.

*(d) The MILP half — backend added, and it closes further than expected.*  `pulp` (CBC) is
now an **optional, analysis-only** dependency: absent, §(d) prints a NOTE with install
instructions and the file still runs, the same pattern #214 uses for z3.  Documented in
CLAUDE.md's new *Third-party dependencies* table.  The shipped primitives still have none.

Two things had to be got right before any MILP number was usable, and the first attempt got
both wrong:

* **What it models.**  `xdp+` assumes both addends vary; here one is a constant, so the LM
  formula computes the **key-averaged** behaviour, not a per-key bound.  Validated against
  its own reference — a DDT averaged over 64 keys, then the exact DP — giving 1.80/3.43/5.82
  at n = 10 against the MILP's 2.00/4.00/7.00.  It tracks, slightly conservative.
* **When a result is proven.**  A time-limited CBC run reports `Optimal` for merely feasible
  solutions.  An early pass at n = 128 returned a 4-round optimum *cheaper* than its own
  3-round optimum — impossible — so anything consuming its time limit is now reported
  unproven.

**Proven optima are identical at every width that closes** — n = 16 gives 2.0/4.0/7.0/10.0
for r = 2/3/4/5; n = 32 gives 2.0/4.0/7.0 (r = 5 hit the limit at 13.0); n = 64 gives 2.0/4.0
(r = 4 hit the limit at 16.0).  Three widths agree at r = 2 and r = 3, two at r = 4.  The optimal trail is **local** — narrower than the
state, never wrapping — and `M` is rotation-invariant, so *the same trail exists at n = 256*.

That yields a one-sided statement at the deployed width **with no extrapolation**: a 5-round
trail of probability 2^-10 exists, and a 4-round one of 2^-7.  It does not yield the
converse (no better trail at 256), which is what a two-sided bound needs and which CBC does
not close beyond n = 32.

The proven series is exactly linear at **3.0 bits/round**, which taken at face value gives
~86 rounds for 2^-256 — more optimistic than #214's 137, making 192 comfortable.  Three
reasons not to take it at face value, in increasing order of weight: three points only; the
trail may stop being local at larger r; and decisively, **this is key-averaged while (b)
measured real keys at roughly half the averaged weight** — halving 3.0 puts the per-key
requirement above 170 rounds and 192 becomes marginal.

**Net:** the round count is still not known to be adequate or inadequate, but the
uncertainty is now bracketed by proven numbers at both ends rather than one extrapolated
slope — and the dominant term in it is the key-averaged/per-key gap, **not** the width
extrapolation everyone has been caveating.  That reframes what #248 has to resolve.

**Remaining:** a two-sided bound at n = 256.  CBC stops at n = 32; a stronger backend
(HiGHS/Gurobi) or a structural argument would be needed, and it is not clear the former
suffices.

Status: **OPEN**

### #248: re-review the v2 family ratings once #245's successors land

TODO #245 shipped round constants and deliberately did not re-rate anything, on the grounds
that removing a structural objection is not supplying a proof.  It named this successor in
its own text and in SecurityProofs-7.md §11.27.4.

**The question.**  HSKE-NL-A2 (downgraded to demo-only by #244) and `twk` (kept demo-only by
#243) both rest on `nl_fscx_revolve_v2` being a PRP/SPRP.  #245 removed the self-similarity
objections — the slide structure and the fixed-point deviation are gone — so the trail bounds
are now the binding constraint.  Do they bind tightly enough to move either rating?

**Gated on evidence, not on time.**  This item must not run until #247 has produced bounds
that are not order-of-magnitude extrapolations, and — if #246 lands — until they are bounds
on the round function that actually ships.  Opening it earlier would repeat exactly the
error #244 was filed to correct: treating "the objections I know about are answered" as
equivalent to "analysed".

**Re-derive, do not inherit.**  Whatever the outcome, A2's three constraints and `twk`'s
must be re-derived against the then-current construction.  #237 and #238 exist because
propagated rows go stale.

**Both directions are live outcomes.**  A promotion is possible.  So is confirming
demo-only, in which case the useful deliverable is a row that says precisely what is missing
rather than one that reads as an unexplained caution.

Status: **OPEN**

### #249: finish the constant-time audit scope TODO #129 opened

`SecurityProofs-7.md` §11.16 records that TODO #129's original item-2 scope was never
completed, and names what is outstanding.  It has sat unfiled across several batches.

* **`stern_apply_perm`'s memory-access pattern**, flagged in Batch 2 and still unaddressed.
* **A residual timing signal** that survived the absolute-gap collapse and interop re-test.
  Chasing it needs cache/power instrumentation — hardware performance counters, or a
  controlled non-degenerate "fixed" class — which a wall-clock `dudect` harness cannot
  provide.  Decide whether to acquire that capability or to document the limit and stop;
  either is a defensible close, silence is not.
* **HKEX-RNL, ZKP-RNL and HCRED are entirely unaudited** for constant-time behaviour.  They
  fall inside #129's stated scope and no batch has touched them.

**Worth stating plainly:** this is the one open item that concerns a side channel rather
than a structural property, and side channels are the class this suite has audited least.
`SECURITY.md` should say so if the answer is "not audited".

Status: **OPEN**

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
