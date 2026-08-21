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
`SecurityProofs-7.md` subsection with the bound table and the rotation
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
