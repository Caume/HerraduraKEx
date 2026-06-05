# Formal Cryptographic Analysis — Part 3

> **This document is Part 3 of the Herradura Cryptographic Suite security proofs.**
>
> - **Part 1 — §1–§10** (SecurityProofs-1.md): Algebraic Foundations · Protocol Analysis · Security Analysis · Quantum Attack Analysis · v1.4.0 Migration
> - **Part 2 — §11–§11.9** (SecurityProofs-2.md): Non-linearity and Post-quantum Extensions · HFSCX-256
> - **Part 3 — §11.10** (this file): Zero-Knowledge Proof Extensions

---

## 11.10 Zero-Knowledge Proof Extensions (TODO #76)

This section surveys and prototypes zero-knowledge proof (ZKP) constructions for the two PQC hardness pillars not yet covered by existing ZKP infrastructure.  The third pillar (B2, syndrome decoding) is already covered by the Stern identification protocol + Fiat-Shamir (§11.8.4, Theorem 17, SecurityProofs-2.md).

Full prototype code with completeness and soundness tests: `SecurityProofsCode/zkp_pqc_exploration.py`.

### 11.10.1 Applicability Matrix

| Hardness assumption | ZKP framework | Status |
|---|---|---|
| B2: Syndrome decoding SD(N,t) | Stern identification + Fiat-Shamir | **Implemented** v1.5.18, §11.8.4 |
| B2: Syndrome decoding | MPC-in-the-head (ZKBoo) | Prototype §11.10.3 |
| B1: Ring-LWR (HKEX-RNL) | Lyubashevsky $\Sigma$-protocol | Prototype §11.10.2 |
| B1: Ring-LWR | BDLOP commitments + linear proof | Option (linear relations) |
| A: NL-FSCX OWF/PRF | MPC-in-the-head (ZKBoo) | Prototype §11.10.3 |
| A: NL-FSCX OWF/PRF | ZKB++ / Picnic variant | Option (smaller proofs) |

Primary use case for §11.10.2: **anonymous credentials** — prove knowledge of an HKEX-RNL private key matching a given public key without revealing the key, enabling privacy-preserving authentication.  The Stern construction (§11.8.4) applies to syndrome decoding witnesses only and does not directly extend to Ring-LWR keys.

### 11.10.2 Ring-LWR $\Sigma$-Protocol

**Statement.** A pair $(m, C)$ where $m \in \mathbb{Z}_q^n$ is the blinding polynomial and $C \in \mathbb{Z}_p^n$ is the public key (HKEX-RNL output).

**Witness.** $s \in \{-1,0,1\}^n$ satisfying $C = \text{round-p}(m \cdot s \bmod q)$ in $\mathbb{Z}_q[x]/(x^n+1)$.

**Parameters (toy/production).** $n \in \{32, 256\}$, $q = 65537$, $p = 4096$, $\gamma \in \{4096, 8192\}$, challenge weight $t \in \{4, 16\}$.

**Protocol (one Fiat-Shamir round).**

1. **Commit.** Sample mask $y$ with each coefficient uniform in $[-\gamma, \gamma]$.  Compute $w = m \cdot y \bmod q$ (centred coefficients in $(-q/2, q/2]$).
2. **Challenge.** Derive $c = H(m, C, w)$ via Fiat-Shamir — a sparse ternary polynomial with $t$ nonzero $\pm 1$ terms.
3. **Respond.** Compute $z = y + c \cdot s$ (ring multiplication in $\mathbb{Z}_q[x]/(x^n+1)$).  If $\|z\|_\infty > \gamma - t$, restart from step 1 (rejection sampling).  Otherwise send $z$.
4. **Verify.** Accept iff all three hold:
   - $\|z\|_\infty \leq \gamma - t$,
   - $c = H(m, C, w)$ (Fiat-Shamir check),
   - $\|m \cdot z - w - c \cdot \text{lift}(C)\|_\infty \leq t \cdot \lceil q/(2p) \rceil$ (rounding slack $\leq 32$ for $t=4$).

**Completeness proof sketch.** $m \cdot z = m \cdot y + c \cdot (m \cdot s) = w + c \cdot \text{lift}(C) + c \cdot \varepsilon$, where $\varepsilon = m \cdot s - \text{lift}(C)$ satisfies $\|\varepsilon\|_\infty \leq q/(2p)$ by the definition of rounding.  Hence $\|m \cdot z - w - c \cdot \text{lift}(C)\|_\infty \leq t \cdot q/(2p)$.

**Soundness.** Under the Fiat-Shamir ROM assumption, one round suffices for computational soundness.  Special soundness: given two accepting transcripts $(w, c, z)$ and $(w, c', z')$ with $c \neq c'$, the response difference $(z - z') \cdot (c - c')^{-1} \approx s$ in the ring, contradicting Ring-LWR hardness.

**Zero-knowledge.** Rejection sampling ensures $z$ is statistically close to $\text{Unif}([-\gamma+t, \gamma-t]^n)$, independent of $s$.  The triple $(w, c, z)$ can be simulated without $s$ by choosing $z$ uniformly and setting $w = m \cdot z - c \cdot \text{lift}(C)$.

**Empirical results** (`zkp_pqc_exploration.py §2`, $n=32$):

| Test | Trials | Result |
|---|---|---|
| Completeness (honest prover) | 1 000 | 0 failures [PASS] |
| Soundness (naive cheat: random $z$, no $s$) | 200 | 0 passes [PASS] |

**Proof sizes:**

| $n$ | $w$ (bytes) | $c$ (bytes) | $z$ (bytes) | Total |
|---|---|---|---|---|
| 32 | 68 | 8 | 56 | **132 B** |
| 256 | 544 | 32 | 480 | **1 056 B** (1.03 KB) |

At $n=256$, one proof is 1.03 KB — smaller than ML-DSA-44 (2 420 B).

**Honest limitation.** The security reduction is heuristic: it relies on the Ring-LWR hardness assumption for the suite's specific blinding polynomial $m$ (derived from the HKEX-RNL session) rather than a provably-secure reduction to a standard lattice problem.  See Lyubashevsky 2012 for the standard-model reduction template.

### 11.10.3 NL-FSCX ZKP via MPC-in-the-Head (ZKBoo)

**Statement.** Public values $(B, y)$ with $B, y \in \{0,\ldots,2^n-1\}$.

**Witness.** $A \in \{0,\ldots,2^n-1\}$ satisfying $F_1(A, B) = y$ (one step of NL-FSCX v1).

**Circuit decomposition.** With $B$ public, the circuit has two parts:

- *Linear part* $\text{FSCX}(A, B)$: all XOR and rotation gates — free in ZKBoo (each party applies locally).
- *Carry chain* for $(A + B) \bmod 2^n$: $n-1$ AND gates (one per carry bit $c_1, \ldots, c_{n-1}$, each gating two secret wires: $A_i$ and $c_i$).

At $n=8$: 7 AND gates per $F_1$ step.  At $n=256$: 255 AND gates per step; $n/4 = 64$ steps for $F_1^{n/4}$ yield 16 320 AND gates total.

**ZKBoo 3-party AND gate** (Giacomelli et al. 2016).  Secret bits $x$ and $y$ are XOR-shared across three parties: $x = x_0 \oplus x_1 \oplus x_2$, $y = y_0 \oplus y_1 \oplus y_2$.  Each party $i$ holds a random coin $r_i = \text{PRF}(k_i, \text{gate-id})$ and computes:

$$z_i = (x_i \wedge y_i) \oplus (x_i \wedge y_{i+1}) \oplus (x_{i+1} \wedge y_i) \oplus r_i \oplus r_{i+1}$$

where indices are taken mod 3.  One verifies $z_0 \oplus z_1 \oplus z_2 = x \wedge y$.

**Protocol ($R$ rounds, Fiat-Shamir).**  Each round: (1) share $A = s_0 \oplus s_1 \oplus s_2$ with random $s_0, s_1$; (2) evaluate the circuit recording per-party gate views; (3) commit $\text{com}_i = H(j, i, k_i, \text{out}_i)$ for each party $i$; (4) derive challenge $e \in \{0,1,2\}$ via $H(\text{all commitments}, B, y)$; (5) reveal views of parties $(e+1) \bmod 3$ and $(e+2) \bmod 3$.

**Verification.** For each round the verifier: (a) re-derives party $(e+1)$'s AND gate outputs from the two revealed views (using shares of parties $e+1$ and $e+2$, both known); (b) checks commitments for the two revealed parties; (c) infers the hidden output as $\text{out}_e = y \oplus \text{out}_{e+1} \oplus \text{out}_{e+2}$.

**Soundness.** A cheating prover without $A$ can prepare at most two consistent view-pairs out of three.  Soundness error per round: $2/3$.  For 128-bit soundness: $R = \lceil 128 / \log_2(3/2) \rceil = 219$ rounds — identical to the HPKS-Stern-F threshold (§11.8.4).

**Empirical results** (`zkp_pqc_exploration.py §3`, $n=8$, $R=4$):

| Test | Trials | Result |
|---|---|---|
| Completeness (honest prover) | 1 000 | 0 failures [PASS] |
| Soundness (wrong $A$, FS mismatch) | 200 | $\approx (1/3)^R \times 200 \approx 1$–$2$ coincidental [PASS] |

The Fiat-Shamir seed includes $y$; a cheating prover supplying wrong $A$ (so $F_1(A,B) \neq y$) faces a different challenge in re-derivation, causing failure in all but $\approx (1/3)^R$ trials by coincidence.

**Proof sizes (ZKBoo):**

| $n$ | AND gates | $R=219$ proof | vs HPKS-Stern-F |
|---|---|---|---|
| 8 (toy) | 14 | 35.5 KB | — |
| 32 | 248 | 49.2 KB | — |
| 256, $r=64$ | 16 320 | **920 KB** | 78 KB (Stern-F) |

At production parameters ($n=256$, $R=219$), basic ZKBoo yields approximately 920 KB.  ZKB++ (Chase et al. 2017) achieves roughly $5\times$ reduction through an optimised decomposition, yielding approximately 180 KB — larger than Stern-F but applicable to NL-FSCX witness statements where Stern does not apply.

**Honest limitation.** The NL-FSCX OWF assumption (§11.8.3) must hold.  The rotational-structure open concern (§11.8.3, TODO #75) affects two-sided rotation only (WOTS hash chain); one-sided rotation (all PRF uses, including the carry-chain circuit) gives coincidence probability $\approx 0$, so the ZKBoo construction is unaffected.

### 11.10.4 Comparison and Recommendations

| Use case | Recommended construction | Proof size | Notes |
|---|---|---|---|
| PQC signature | HPKS-Stern-F (§11.8.4) | 78 KB | Production-ready, v1.5.18 |
| Ring-LWR key proof / anonymous cred | Ring-LWR $\Sigma$-protocol (§11.10.2) | 1 KB | Prototype; heuristic security |
| NL-FSCX witness proof | ZKBoo (§11.10.3) | 920 KB | Research quality |
| NL-FSCX with circuit optimisation | ZKB++ / Picnic variant | ~180 KB (est.) | Future work |

For anonymous credential applications on HKEX-RNL keys, the Ring-LWR $\Sigma$-protocol is the most practical option: its 1 KB proof size is competitive with ML-DSA-44 (2.4 KB).

### 11.10.5 Open Research Directions

1. **Formal Ring-LWR reduction.** Establish a tight security reduction from the $\Sigma$-protocol soundness to Ring-LWR distinguishing hardness.  Quantify the effect of the rounding slack ($\leq t \cdot q/(2p) = 32$) on the security margin relative to the Lyubashevsky 2012 template.

2. **NTT-accelerated $\Sigma$-protocol.** The prototype uses $O(n^2)$ schoolbook multiplication.  Extend to NTT-based negacyclic multiply (already in HKEX-RNL, §11.4.2) for $O(n \log n)$ prover and verifier at $n=256$.

3. **ZKB++ on NL-FSCX.** Implement Chase et al. 2017's optimised MPC-in-the-head decomposition to reduce NL-FSCX ZKBoo proofs from 920 KB to approximately 180 KB.

4. **Hybrid credential scheme.** Combine the Ring-LWR $\Sigma$-protocol with HPKS-Stern-F to prove "I hold a Ring-LWR private key $s$ matching public key $C$ AND a Stern-F signature valid under $s$" — enabling privacy-preserving authentication with a single compound proof.

**References.**
- Lyubashevsky 2012. *Lattice Signatures Without Trapdoors*. Eurocrypt 2012, LNCS 7237, pp. 738–755.
- Giacomelli, Madsen, Orlandi 2016. *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*. USENIX Security 2016, pp. 1069–1083.
- Chase et al. 2017. *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives*. CCS 2017, pp. 1825–1842. (ZKB++)
- Baum, Damgård, Lyubashevsky, Oechsner, Peikert 2018. *More Efficient Commitments from Structured Lattice Assumptions*. SCN 2018, LNCS 11035, pp. 368–385. (BDLOP)
- NIST FIPS 204 (ML-DSA / Dilithium, 2024). NIST FIPS 205 (SLH-DSA / SPHINCS+, 2024).
