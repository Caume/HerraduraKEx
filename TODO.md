# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### #213: Closed-form O(log i) `fscx_revolve` — bit-exact, no primitive change

Because `fscx_revolve(A, B, i) = M^i·A ⊕ T_i·B` with everything living in
GF(2)[x]/(x^n + 1), the i sequential rotate-XOR rounds can be replaced by
square-and-multiply on `m(x)^i` plus a closed form for `S_i` — O(log i)
polynomial multiplications instead of O(i) rounds, producing byte-identical
output. At the deployed parameters that is 64 (encrypt) and 192 (decrypt)
rounds collapsing to ~7–8 multiplications, and `_m_inv`'s bootstrap
(`fscx_revolve(1, 0, n/2 − 1)`) becomes a single inversion.

FSCX and FSCX_REVOLVE keep their definitions exactly — this is an
evaluation strategy, not a redefinition, and the KAT vectors in `KAT/` are
the correctness oracle.

Scope:
- Benchmark the polynomial route against today's loop in C/Go/Python:
  schoolbook (n²/w word ops) vs carryless-multiply intrinsics vs the
  existing rotate loop; the rotate loop may well win at n=256 for small i,
  and a negative result is a perfectly good outcome to record in
  `benchmarks/`.
- If it wins, note that it only applies to classical FSCX_REVOLVE. The NL
  variants are non-linear by construction and stay iterative — which is
  itself worth documenting, since it makes the cost gap between the
  classical and NL protocols explicit.
- Keep assembly/Arduino targets out of scope unless the win is large;
  their n=32 parameters give little room.

Status: **OPEN**

### #214: Exact differential/linear analysis of NL-FSCX v1/v2 against current ARX tooling

The only non-linearity in either NL-FSCX variant is the carry chain of one
modular addition per round (`ROL((A+B) mod 2^n, n/4)` in v1, the additive
`delta(B)` in v2). That places both squarely in the ARX/RX family, where
exact rather than heuristic tools exist and are standard practice:
Lipmaa–Moriai gives exact XOR-differential probabilities of modular
addition in O(log n), and MILP/SMT trail search over the resulting model
gives provable bounds rather than sampled ones. Today's coverage
(`nl_fscx_rot_analysis.py`, `nl_fscx_rx_exact_search.py`,
`nl_fscx_rx_differential_2025.py`, `nl_fscx_prf_analysis.py`) is sampling
and small-n exhaustive search; this item asks for the bound.

- Build the exact xdp+/xdp-RX model of one v1 and one v2 round and search
  for optimal trails over the deployed step counts with an SMT/MILP
  backend, reporting the best trail probability as a function of rounds and
  the number of rounds needed to drop below 2^-256.
- Settle the [[#210]] follow-up properly: compute the full Walsh spectrum
  of the v2 revolve restricted to the 126-dimensional subspace that the
  classical map leaks, with enough samples to resolve a bias of 2^-16
  (the current 400-sample spot check resolves nothing below ~2^-4).
- Include the rotation amount `n/4` in the search space. It is a free
  parameter that changes trail structure but not the primitive, so an
  optimal-rotation table across candidate amounts is exactly the kind of
  parameter tuning that is in scope, feeding a follow-up if some amount
  dominates.
- Cross-check the carry-degeneracy characterisation from [[#159]]/[[#168]]
  against the trail model.

**Deliverable:** `SecurityProofsCode/nl_fscx_exact_trail_search.py` plus a
`SecurityProofs-5.md` subsection with the bound table and the rotation
recommendation.

Status: **OPEN**

### #216: Re-estimate HKEX-RNL against the 2026 lattice-attack landscape

`SECURITY.md` puts HKEX-RNL (n=256) at ~105 classical / ~100 quantum
Core-SVP bits and promotes HKEX-RNL-128 (n=512) as production-track. Those
numbers predate the current round of dual- and hybrid-attack improvements
(e.g. enhanced hybrid decoding against Module/Ring-LWE, eprint 2026/366,
reporting up to ~13 bits over previously-best attacks on ring parameter
sets), and Core-SVP is a deliberately crude lower bound.

- Re-run the deployed parameters (n=256 and n=512, q=65537, p=4096, pp=4,
  CBD η=1) through the current `lattice-estimator` across primal, dual, and
  hybrid families, recording estimator commit and cost model rather than a
  bare bit count.
- Check the LWR-specific translation explicitly: rounding noise from
  q=65537 → p=4096 is deterministic, and η=1 is a very narrow secret, both
  of which have historically been where sparse/small-secret hybrid attacks
  bite hardest.
- Report whether n=512 still clears 128 bits under the current models. If
  it does not, propose the parameter move (n, q, p, or η) in a follow-up —
  ring parameters are adjustable without touching FSCX.

Status: **OPEN**

### #217: Validate HPKS-Stern-F's round count against multi-round Fiat–Shamir forgery attacks

The production figure `rounds = 219` comes from the textbook
`(2/3)^r ≤ 2^-128`. Recent work on multi-round Fiat–Shamir (the CROSS
security revision presented at the 6th NIST PQC standardization
conference, and the fixed-weight-repetition forgery improving on
Kales–Zaverucha) shows that the naive parallel-repetition bound overstates
security for several deployed schemes — up to ~24% in the worst case
reported. Stern here is a 3-pass with uniform (not fixed-weight)
repetition and one-shot challenge derivation, which is the favourable
case, but the bound should be derived rather than assumed.

- Derive the forgery cost for this exact construction under the current
  multi-round FS analysis and confirm (or correct) 219, including the
  grinding strategy where an attacker re-randomises commitments for a
  subset of rounds.
- Audit the challenge expansion itself: `hpks_stern_f_sign` hashes
  `msg || all commitments` once, then chains `ch_st = nl_fscx_v1(ch_st,
  BitArray(n, i))` per round and takes `(ch_st & 0xFFFFFFFF) % 3`. Two
  things to check — that the reduction bias (2^32 mod 3 = 1, so ~2^-32) is
  genuinely negligible at 219 rounds, and that chaining a **non-bijective**
  map as challenge PRG cannot be steered into short cycles or low-entropy
  runs by commitment grinding. The bias question was touched for ring
  signatures in `stern_ring_challenge_bias.py`; this is the signature path.
- If the derived bound exceeds 219, update `_STERN_F_PRODUCTION_ROUNDS`,
  the `sign --rounds` guidance, and the C CLI's `-DSDF_ROUNDS` default
  across all language targets.

Status: **OPEN**

### #220: `SecurityProofs-1.md` is approaching the ~750-expression KaTeX limit

`SecurityProofsCode/validate_katex.js` now warns on `SecurityProofs-1.md`: it
holds 708 math expressions against GitHub's roughly 750-per-page client-side
KaTeX limit, past which *every* expression on the page silently renders as
"Unable to render expression" — a cascade failure with no syntax error to find.
`SecurityProofs-4.md` sits at 716 with the same warning. The warning threshold
(700) exists precisely to catch this before it bites; TODO #170 already re-split
these documents once for the same reason.

Part 1 grew from 581 to 708 across TODO #210 and #211, both of which added
material to §1.3 (the FSCX_REVOLVE subsections). §1.3.2's additions were trimmed
back once already, converting prose-adjacent math to plain text to buy headroom,
which is a stopgap rather than a fix. The remaining open analysis items — #213
through #218 — will each want a subsection somewhere, and several of them belong
in Parts 1 and 4.

- Pick split points at section boundaries, as TODO #170 did, so each part lands
  comfortably under the warning threshold rather than just under the hard limit.
  Part 1's §1 (Algebraic Foundations) has grown enough to stand alone.
- Update every cross-reference: `SecurityProofs.md`'s index, the "Continued in
  Part N" footers, `CLAUDE.md`'s Repository Structure listing with its per-file
  expression counts, `SecurityProofsCode/KATEX_RULES.md`'s split rationale, and
  the many `SecurityProofs-N.md §X` citations scattered across `SECURITY.md`,
  `SPEC.md`, `README.md` and the other parts.
- Re-run the validator on every part afterwards and record the new counts in the
  two places that track them.

Status: **OPEN**
