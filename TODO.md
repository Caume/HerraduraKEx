# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Research review — 2025-2026 cryptanalysis and primitive developments

The following items (#156-#163) were opened from a literature review of cryptanalysis
and cryptographic-primitive research published in roughly the 12 months prior to
2026-07-31, cross-checked against this repo's existing TODO/SecurityProofs coverage so
only genuinely new angles are recorded here (constant-time auditing, rotational
differential analysis of NL-FSCX, QC-MDPC decoder trapdoors, and hybrid Ring-LWR+Stern-F
credentials were already tracked as #41/#75/#83/#123/#125/#126/#128/#129 and are not
re-opened).

### 168. Reject NL-FSCX v2 affine weak keys (delta(K) in {0, 2^(n-1)}) (Security, Low)

**Background:** TODO #159's second stress-testing pass (`SecurityProofs-2.md` §11.19.2,
`SecurityProofsCode/nl_fscx_carry_degeneracy_2026.py`) established the exact
characterisation

    pi_K is GF(2)-affine  <=>  delta(K) in {0, 2^(n-1)}

for NL-FSCX v2's permutation $\pi_K(A) = (M(A \oplus K) + \delta(K)) \bmod 2^n$, verified
exhaustively at $n = 8$ and $n = 16$ (the characterisation holds at every power-of-two $n$,
where $M$ is invertible). Addition of a constant $c$ is affine over GF(2) for every input
exactly when $c = 0$ or $c = 2^{n-1}$, the latter because the top carry is discarded mod
$2^n$.

Such keys exist at the deployed size: every $K$ divisible by $2^{129}$ gives
$\delta(K) = 0$ at $n = 256$ (a class of $2^{127}$ keys), and $K = 2^{96}$ gives
$\delta(K) = 2^{255}$. For any of them HSKE-NL-A2 and HPKE-NL collapse to an affine map
that is fully recoverable from a handful of known plaintexts by linear algebra.

**Severity:** class density is about $2^{-129}$, so a uniformly random 256-bit key is not
at risk and this is **not** a break of the deployed construction. It matters only if keys
are structured, low-entropy, or attacker-influenced — but the check is one line and the
suite already performs weak-key rejection elsewhere (test `[45]`, TODO #141/#144), so the
asymmetry is worth closing.

**Work items:**

1. Add a `delta(K) not in {0, 2^(n-1)}` guard to the NL-FSCX v2 entry points
   (`nl_fscx_v2`, `nl_fscx_revolve_v2`, and the inverse variants) in the Python, C
   (`herradura.h`), and Go suites, rejecting rather than silently proceeding.
2. Mirror the guard at the CLI layer wherever an HSKE-NL-A2 / HPKE-NL key is loaded,
   following the existing weak-key rejection precedent from TODO #141.
3. Extend the existing weak-key/malformed-input rejection test `[45]` in
   `CryptosuiteTests/Herradura_tests.{c,go,py}` with an NL-FSCX v2 affine-key case (e.g.
   $K = 2^{129}$ and $K = 2^{96}$ at $n = 256$), keeping the three languages in parity.
4. Cross-check whether the assembly/Arduino targets (which use 32-bit operands) need the
   same guard, and record the answer either way.

Status: **OPEN**
