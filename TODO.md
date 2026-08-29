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

**Interim recommendation: candidate B**, on measurement and on smallest-diff grounds.  But
candidate A's advantage is different in kind and should not be dismissed — a Simon-style
Feistel inherits a large third-party literature, and the point of this item is to make a
*provable* bound reachable, which a better-measured construction with no literature may not.

**Remaining, and step 3 gates the decision.**  (3) TODO #247's MILP/SMT bounds against both
candidates — the numbers above are comparative, not bounds.  (4) Masked and unmasked cost in
four languages and on AVR.  (5) Migration.  **Open technical risk in candidate B:** χ is
normally applied to equal, short rows, and 127 + 129 is neither — whether Keccak's own
symmetry arguments survive unequal long rows is unexamined.

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
