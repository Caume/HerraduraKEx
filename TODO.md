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

### #224: Explore a masked-step / hash-based HKEX PQC variant (MFSCX-KEX)

Every HKEX variant shipped so far derives its hardness from one of two places:
GF(2^n)* discrete log (HKEX-GF — classically broken by Shor, and the FSCX layer
around it is affine) or Ring-LWR (HKEX-RNL — which TODO #216/#223 showed is far
below its claimed level at the deployed parameters). This item is the exploratory
track for a third construction that leans on symmetric/hash-style hardness
instead, using FSCX itself as the mixing function.

**Proposed construction (MFSCX_REVOLVE).** Add a per-step, non-uniform seed
injection to the revolve loop. With `M = I ⊕ ROL ⊕ ROR` as today:

```
MFSCX_REVOLVE(A, B, i; S):
    for j = 0 .. i-1:
        A <- FSCX(A, B) ⊕ (S_j & mask_j)
```

where `S_j` is a seed-derived subkey for step `j` and `mask_j` selects *which*
bits of `S_j` actually get XORed in. Two mask regimes to evaluate:

- **static P-box** — `mask_j` fixed at compile time (a published permutation/
  selection box, same for all sessions);
- **dynamic P-box** — `mask_j` derived from the seed itself, or from the current
  state `A`, so the injection pattern is session- (or state-) dependent.

**The central tension, to be settled before any implementation.** The two-party
agreement in every FSCX-based construction rests on the XOR homomorphism of the
affine map, and that same affinity is exactly what `hkex_classical_break.py`
exploits (`sk = S_{r+1}·(C ⊕ C2)`, computable from the wire values alone).

- A **static** mask keeps the whole map affine over GF(2): it only changes the
  constant term, `MFSCX(A,B) = M^i·A ⊕ T_i·B ⊕ c(S)`, and `c(S)` cancels in
  `C ⊕ C2` whenever both parties use the same public S. First task is therefore
  to check whether the existing break generalizes verbatim — the expectation is
  that it does, and that finding alone would close the static branch.
- A **dynamic** (state-dependent) mask does destroy affinity, but it also
  destroys the homomorphism that makes `C_A ⊕ C_B` a shared value at all. The
  open question is whether there is any middle ground: a mask schedule that is
  non-linear in the seed while remaining commutative in the two parties'
  contributions. `hkex_nonce_impossibility.py` already proves no *nonce* choice
  rescues HKEX; the argument there is algebraic and may extend to any
  seed-injection schedule. Extending it (or finding the gap) is the real work.

**Hash-based hardness — state the ceiling up front.** "Hash-based key exchange"
is not a free substitution for a trapdoor. Hash-based *signatures* (already here
as HPKS-WOTS-F / HPKS-XMSS-F) work because signing needs no trapdoor; key
exchange does. Against a random-oracle-only adversary the Impagliazzo–Rudich
separation caps black-box key agreement at Merkle-puzzle quadratic security —
2^128 target means ~2^64 honest work, which is not shippable. So the plan must
pick its honest goal early:

1. **Interactive/authenticated setting** — MFSCX as a KDF or ratchet over an
   already-shared secret (this is HSKE territory, and works, but is not a KEX);
2. **Merkle-puzzle-style KEX** — real, provable, and quantifiably too slow;
   worth a cost table so the number is on the record rather than assumed;
3. **MFSCX as the symmetric layer inside a structured PQC KEM** — e.g. as the
   hash/KDF/error-sampler inside the QC-MDPC or Ring-LWR path, where hardness
   comes from the code/lattice and MFSCX only has to be a good PRF. This is the
   only branch with a plausible production endpoint.

**Plan.**

1. Add `SecurityProofsCode/mfscx_kex_analysis.py`, self-contained like its
   neighbours. Sections: (a) formalize MFSCX_REVOLVE for both mask regimes;
   (b) re-run the `hkex_classical_break.py` recovery against the static-mask
   variant across widths, expecting success — i.e. a disproof; (c) measure
   algebraic degree / branch number of the dynamic-mask variant, reusing the
   method in `fscx_branch_number.py` and `nl_fscx_owf_analysis.py`;
   (d) test whether two-party agreement survives dynamic masking at all
   (it likely does not — record the failure rate); (e) the Merkle-puzzle cost
   table for option 2.
2. Reuse `fscx_revolve_corank.py`'s machinery to compute the co-rank of the
   masked key map `T_i` under a static P-box, at the deployed `i = n/4`,
   `r = 3n/4` — if the mask shrinks the image, that is a second independent
   reason to reject the static branch.
3. Check the dynamic-mask permutation for orbit collapse the way
   `nl_fscx_v2_orbit.py` does: a seed-derived mask that lands in a short cycle
   silently degrades to a static one.
4. Only if steps 1–3 leave a branch alive, write it up as a new SecurityProofs
   subsection (§11.21, in `SecurityProofs-7.md` — mind the ~750-expression
   KaTeX budget per TODO #220) and open a separate implementation TODO. Do not
   add an `--algo` tag, PEM label, or `spec/` entry from this item.
5. If all branches close, the deliverable is still worth having: land the script
   plus a short negative-result section, the same way `hkex_cy_test.py` and
   `hkex_cfscx_*.py` record constructions that were tried and rejected. A
   documented dead end is the point of this item, not a failure of it.

**Success criterion.** Either a construction with a written hardness assumption
that is not restatable as "FSCX is affine", or a clear negative result saying
why seed-masked FSCX cannot give key agreement. Anything that only *looks*
non-linear while `C ⊕ C2` still determines `sk` does not count.

Status: **OPEN**
