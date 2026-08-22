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


### #222: Decide whether the 128-bit round count should be 219 or 220

TODO #217 confirmed `r = 219` = ⌈128 / log₂(3/2)⌉ is the correct
parallel-repetition figure and found no exploitable bias in the challenge
expansion, but it also recorded a margin the analysis cannot close from the
inside:

- `(3/2)^219` = 128.107 bits — a margin of **0.107 bits** over the 128-bit
  target.
- The same script's own experimental resolution floor, from the summed
  per-position chi-square excess bound over 48,000 seeds, is **0.4418 bits**.

So the measurement can only certify that no bias larger than ~0.44 bits is
present; it cannot certify 128.000 bits at r = 219. `r = 220` gives 128.692
bits, clearing the floor, at roughly 0.5% cost in signature size and
verification time.

- Decide whether to move the production figure to 220, or to keep 219 and
  document the margin explicitly as an accepted assumption.
- If moving: `_STERN_F_PRODUCTION_ROUNDS`, `_ZKP_NL_PROD_ROUNDS`, the HCRED
  production-rounds note, the C CLI's `-DSDF_ROUNDS=` guidance, and the
  `README.md` / `SECURITY.md` / `SPEC.md` round-count text all carry 219 and
  must move together across C/Go/Python/Java. Note this does **not** break
  the wire format — `--rounds` is already a parameter and existing
  signatures stay verifiable — so it is not a MAJOR bump, but it does change
  what a default-parameter signature looks like.
- If keeping 219: state the 0.107-bit margin and the 0.44-bit resolution
  floor in `SECURITY.md` so the assumption is on the record rather than only
  in `SecurityProofs-5.md` §11.8.8.

Status: **OPEN**

### #223: Move HKEX-RNL to a parameter set that actually reaches 128 bits

TODO #216 computed the deployed sets directly and found both far below target:
n=256 gives ~32 classical / ~29 quantum Core-SVP bits, and HKEX-RNL-128 at n=512
gives ~87/~79. n=512 was the documented answer to n=256 being short, so there is
currently no HKEX-RNL parameter set that meets the 128-bit claim.

The sweep in `SecurityProofsCode/hkex_rnl_lattice_2026.py` §7 rules out retuning:
no (p, η) combination brings n=512 to 128 quantum bits. Ring dimension is the only
lever that closes the gap.

- Decide between the two candidates. `n=1024, p=4096` clears both targets with
  margin (~206 classical / ~187 quantum) and stays a power of two, so
  `_rnl_poly_mul` keeps its Cooley-Tukey NTT path; cost is 4x the key material.
  `n=768, p=4096` clears both more narrowly (~145/~131) at 1.5x the key material,
  but 768 is not a power of two and x^n+1 has no negacyclic NTT there — Kyber
  solves exactly this with a module (k rings at n=256) rather than one large ring,
  which is a third option and the largest change of the three.
- Whatever is chosen, re-run `hkex_rnl_failure_rate.py`: p and reconciliation
  reliability are the same knob, and the failure rate at the new (n, p, pp) has to
  be re-measured, not extrapolated.
- Port across C/Go/Python/Java and the assembly/Arduino targets as their widths
  allow, and re-run `hkex_rnl_lattice_2026.py` against the new deployed values —
  it reads its parameters from the suite, so it will follow automatically.
- This changes the HKEX-RNL wire format (ring elements change size), so it needs a
  `MIGRATING.md` entry. Existing HKEX-RNL PEM keys will not be readable by the new
  build. Weigh that against the alternative, which is shipping a key exchange
  documented as post-quantum at ~32 bits.
- Until this lands, `SECURITY.md`, `spec/`, and SecurityProofs-4.md §11.4.3 all
  mark HKEX-RNL and ZKP-RNL as not production-track at any size.

Status: **OPEN**
