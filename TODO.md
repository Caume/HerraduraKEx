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

### #225: CI headroom for `native-python` after the n=1024 ring move

TODO #223 moved HKEX-RNL's ring from 256 to 1024. The NTT is O(n log n), so the
Python reference's ring multiply went from 1.7 ms to 8.9 ms — 5.2x — measured on
a host without numpy (`_NUMPY = False`, the pure-Python `_ntt_inplace` path).

`native-python` is already the longest CI job at roughly 23 minutes. It passed on
PR #217, so this is precaution rather than a live failure, but the margin is now
unknown and the next RNL-touching change could cross it.

- Measure what the job actually spends on RNL work now, rather than inferring it
  from the microbenchmark: the suite's `-r`/`-t` caps bound per-test time, so the
  5.2x does not translate directly into 5.2x job time.
- Check whether CI runners have numpy available. `_rnl_poly_mul` takes the
  vectorised path when they do, and the whole question may be moot there —
  confirm rather than assume, since the 5.2x above was measured without it.
- If headroom is thin, the options in rough order of preference: lower the RNL
  tests' iteration caps (they are correctness checks, not benchmarks); split
  `native-python` the way TODO #205 split the combined `native` job; or raise the
  job timeout, which hides the trend rather than addressing it.
- Record the resulting job time in `benchmarks/` so the next ring-parameter
  change has a baseline to compare against.

Status: **OPEN**


### #227: Wire-format-level KAT vectors for the CLI layer

TODO #226 added HKEX-RNL known-answer vectors, but they pin the *suite* layer:
ring multiplication, rounding, reconciliation, hint packing, and the KDF. They do
not pin the CLI layer — PEM/DER field layout, which field carries the ring
dimension, or the key width a response PEM is read at.

That distinction is not academic. Every bug TODO #223 shipped and CI caught lived
in the CLI layer, not the suite layer:

- `loadKey` (Go) and `_decode_session_key` (Python) read an RNL RESPONSE PEM's
  ring-dimension field as the derived key width.
- C's hybrid-rnl-stern response encoder wrote a hardcoded n=256 in that field.
- Python's and Go's hybrid combiners serialised K1 at the ring dimension rather
  than the key width, so all three hashed different transcripts.

#226's vectors would have caught none of these. Cross-language CLI tests did
eventually, but only after two CI rounds, and only where a test happened to use
default parameters — `test_encrypt.sh` pins `--bits 64`, where ring and key width
coincide, and so was structurally blind to the whole class.

- Add fixed PEM artifacts to `KAT/`: a private key, a public key, a kex response,
  and a session key, byte-for-byte, for `hkex-rnl` and `hybrid-rnl-stern`.
- Verify by having each CLI *consume* the checked-in PEMs and reproduce the
  expected session key, not merely by regenerating them — consumption is the
  direction the bugs broke.
- Cover both the default ring and a small ring, since the small-ring path is
  exactly where ring dimension and key width coincide and hide this bug class.
- Consider extending to the classical quartet's PEMs while the harness is being
  built; the same argument applies, it simply has not bitten yet.

Status: **OPEN**
