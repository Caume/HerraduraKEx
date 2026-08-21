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
