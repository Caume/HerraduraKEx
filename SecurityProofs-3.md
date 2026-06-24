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
| B2: Syndrome decoding | MPC-in-the-head (ZKBoo) | **Implemented** v1.9.x, §11.10.3 |
| B1: Ring-LWR (HKEX-RNL) | Lyubashevsky $\Sigma$-protocol | **Implemented** v1.9.x, §11.10.2 |
| B1: Ring-LWR | BDLOP commitments + linear proof | Option (linear relations) |
| A: NL-FSCX OWF/PRF | MPC-in-the-head (ZKBoo) | **Implemented** v1.9.x, §11.10.3 |
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

**Soundness (relaxed special soundness, TODO #94).** Under the Fiat-Shamir ROM assumption, one round suffices for computational soundness.  An earlier version of this argument extracted $(z - z') \cdot (c - c')^{-1} \approx s$, implicitly assuming the challenge difference is invertible in $\mathcal{R}_q$.  That assumption is **not justified** for the suite parameters: $q = 65537$ gives $q - 1 = 2^{16}$, so $2n \mid q - 1$ for every power-of-two $n \leq 256$ and $x^n + 1$ splits into $n$ linear factors over $\mathbb{F}_q$.  The ring $\mathcal{R}_q \cong \mathbb{F}_q^n$ (CRT) therefore contains zero divisors, and a nonzero sparse ternary difference $c - c'$ is non-invertible whenever it vanishes at one of the $n$ roots of $x^n + 1$.  Empirically (`zkp_pqc_exploration.py` §2.6): 3 of 2000 random challenge pairs at $n = 32$ produced a nonzero non-invertible difference (heuristic expectation $n/q \approx 0.0005$, i.e. 0.05 %), so strict special soundness fails with small but nonzero probability.

The argument is therefore restated in the standard *relaxed* form [Lyubashevsky 2012]: given two accepting transcripts $(w, c, z)$ and $(w, c', z')$ with $c \neq c'$, the extractor outputs the pair $(\bar{z}, \bar{c}) = (z - z', c - c')$ **without inverting** $\bar{c}$.  This pair satisfies $\bar{c} \neq 0$ with $\lVert \bar{c} \rVert_\infty \leq 2$ and at most $2t$ nonzero coefficients, $\lVert \bar{z} \rVert_\infty \leq 2(\gamma - t)$, and (subtracting the two verification equations) $\lVert m \cdot \bar{z} - \bar{c} \cdot \text{lift}(C) \rVert_\infty \leq 2t \lceil q/(2p) \rceil$ — a *relaxed witness* for the statement $(m, C)$.  Producing such a short relaxed witness without knowledge of $s$ would distinguish $C$ from rounding noise, contradicting Ring-LWR hardness; the honest witness $s$ itself yields one via $\bar{z} = \bar{c} \cdot s$.  The relaxation widens the extracted-witness norm by a factor of 2, which is accounted for in the security margin discussion (open direction 1, §11.10.6).

**Zero-knowledge.** Rejection sampling ensures $z$ is statistically close to $\text{Unif}([-\gamma+t, \gamma-t]^n)$, independent of $s$.  The triple $(w, c, z)$ can be simulated without $s$ by choosing $z$ uniformly and setting $w = m \cdot z - c \cdot \text{lift}(C)$.

**Empirical results** (`zkp_pqc_exploration.py §2`, $n=32$):

| Test | Trials | Result |
|---|---|---|
| Completeness (honest prover) | 1 000 | 0 failures [PASS] |
| Soundness (naive cheat: random $z$, no $s$) | 200 | 0 passes [PASS] |
| Soundness (wrong-key witness $s' \neq s$, §2.4b) | 200 | 0 passes [PASS] |
| Soundness (tampered $w$ — Fiat-Shamir check, §2.4b) | 200 | 0 passes [PASS] |
| Soundness (perturbed $z$ — residual-norm check, §2.4b) | 200 | 0 passes [PASS] |
| Soundness (challenge grinding, 64 attempts/trial, §2.4b) | 200 | 0 passes [PASS] |
| Challenge-difference invertibility in $\mathcal{R}_q$ (§2.6) | 2 000 pairs | 3 nonzero non-invertible differences — strict special soundness fails; relaxed form required |

The wrong-key, tampered- $w$, perturbed- $z$, and grinding cheats are also exercised in the
language test suites (`CryptosuiteTests/Herradura_tests.py` test [21]) against the deployed
`_rnl_sigma_sign` / `_rnl_sigma_verify` implementation at both $n = 32$ and $n = 256$.

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

At production parameters ($n=256$, $R=219$), basic ZKBoo yields approximately 920 KB.  ZKB++ (Chase et al. 2017) re-encodes each round — input shares from 16-byte seeds, a single online party's AND-gate broadcast (the dominant term drops from $2\times$ to $1\times$), and only the hidden party's commitment.  The often-quoted $5\times$ reduction assumes the per-round *overhead* (commitments, tapes) dominates; for the NL-FSCX circuit the AND-gate broadcast dominates instead (2 040 B/round vs ~224 B overhead/round at $n=256$), so the realistic reduction is governed by the $2\times{\to}1\times$ gate term.  A first-principles accounting (`zkp_pqc_exploration.py` §3.7) gives **≈457 KB at $n=256$, a $2.0\times$ reduction** — not 180 KB.  Reaching ~180 KB would require reducing the AND-gate count itself (e.g. a LowMC-like sparse circuit), a circuit redesign separate from the ZKB++ transcript encoding.

**Honest limitation.** The NL-FSCX OWF assumption (§11.8.3) must hold.  The rotational-structure open concern (§11.8.3, TODO #75) affects two-sided rotation only (WOTS hash chain); one-sided rotation (all PRF uses, including the carry-chain circuit) gives coincidence probability $\approx 0$, so the ZKBoo construction is unaffected.

### 11.10.4 Suite Implementation

Both constructions are now fully implemented in the Herradura Cryptographic Suite — not prototype-only.  The function table below maps each operation to the corresponding symbol in each language target.

| Operation | C (`herradura.h`) | Go (`herradura` pkg) | Python (suite module) |
|---|---|---|---|
| ZKP-RNL keygen | `rnl_keygen` (shared with HKEX-RNL) | `RnlKeygen` | `hkex_rnl_keygen` |
| ZKP-RNL sign | `rnl_sigma_sign` | `RnlSigmaSign` | `_rnl_sigma_sign` |
| ZKP-RNL verify | `rnl_sigma_verify` | `RnlSigmaVerify` | `_rnl_sigma_verify` |
| ZKP-NL keygen | `zkp_nl_keygen` | `ZkpNlKeygen` | `_zkp_nl_keygen` |
| ZKP-NL prove | `zkp_nl_prove` | `ZkpNlProve` | `_zkp_nl_prove` |
| ZKP-NL verify | `zkp_nl_verify` | `ZkpNlVerify` | `_zkp_nl_verify` |

ARM Thumb-2 and NASM i386 targets implement ZKP-RNL only (`rnl_sigma_sign_32`, `rnl_sigma_verify_32`) at n=32.  The Arduino target includes both ZKP-RNL (n=32) and ZKBoo (n=8, R=4 demo).

**Implemented proof sizes:**

| Construction | $n$ | $R$ | Proof size | Targets |
|---|---|---|---|---|
| ZKP-RNL | 32 | — | proportional to $n$ | all (ARM/NASM at n=32) |
| ZKP-RNL | 256 | — | **1,056 B** | C, Go, Python |
| ZKP-NL | 8 | 4 | demo (toy) | all |
| ZKP-NL | 8 | 219 | 35.5 KB | C, Python |
| ZKP-NL | 256 | 219 | 920 KB | C, Go, Python |

**Comparison with HPKS-Stern-F and ML-DSA-44 (from §4):**

ZKP-RNL at n=256 produces a 1,056-byte proof — smaller than both HPKS-Stern-F (78 KB) and the NIST reference scheme ML-DSA-44 (2,420 bytes).  It is therefore the most compact PQC signing option in the suite for Ring-LWR keys, at the cost of heuristic rather than tight security.

ZKP-NL at n=256 and R=219 yields 920 KB, which exceeds practical limits for most use cases.  The CLI defaults to n=8 (35.5 KB) for this reason.  The ZKB++ optimisation (§11.10.6 open direction 3) would reduce the n=256 proof to approximately 457 KB ($2.0\times$, gate-broadcast-dominated — see §11.10.4 size breakdown), not the generic $5\times$/180 KB.

CLI integration is documented in `docs/TUTORIAL.md §ZKP Protocols`.  Cross-language interop is verified by `CliTest/test_zkp_interop.sh` (14-way test: 6 signing directions per protocol, plus 2 tamper-rejection checks).

### 11.10.5 Comparison and Recommendations

| Use case | Recommended construction | Proof size | Notes |
|---|---|---|---|
| PQC signature | HPKS-Stern-F (§11.8.4) | 78 KB | **Demo parameters** ($N=256$, ~30–40 bits security); 128-bit requires $N \geq 17000$ |
| Ring-LWR key proof / anonymous cred | Ring-LWR $\Sigma$-protocol (§11.10.2) | 1 KB | Implemented v1.9.x; heuristic security |
| NL-FSCX witness proof | ZKBoo (§11.10.3) | 920 KB | Implemented v1.9.x; CLI defaults to n=8 |
| NL-FSCX with ZKB++ encoding | ZKB++ / Picnic variant | ~457 KB ($2.0\times$, est.) | Future work |
| NL-FSCX with sparse circuit | ZKB++ + LowMC-like circuit | ~180 KB (est.) | Future work (circuit redesign) |

For anonymous credential applications on HKEX-RNL keys, the Ring-LWR $\Sigma$-protocol is the most practical option: its 1 KB proof size is competitive with ML-DSA-44 (2.4 KB).

### 11.10.6 Open Research Directions

1. **Formal Ring-LWR reduction.** *(Addressed v1.9.65 — conditional reduction in §11.10.7.)*  A reduction from relaxed $\Sigma$-protocol soundness to Ring-LWR is given via an intermediate approximate Ring-SIS step; the rounding slack enters as the SIS modulus $4t \lceil q/(2p) \rceil$ (= $36t$ for the suite's $q, p$).  It remains conditional on the hardness of approximate Ring-SIS for the HKEX-RNL blinding polynomial $m$ (itself implied by Ring-LWR for $m$), so it is not yet a fully tight standard-model reduction.

2. **NTT-accelerated $\Sigma$-protocol.** *(Resolved v1.9.64.)*  The prover and verifier polynomial products in the reference suite (`rnl_poly_mul` / `_rnl_poly_mul` / `RnlPolyMul`) use the negacyclic NTT over $Z_q[x]/(x^n+1)$ (the same path as HKEX-RNL, §11.4.2) at the production degree $n=256$, giving $O(n \log n)$ prover and verifier; the $O(n^2)$ schoolbook multiply is retained only for the $n=32$ didactic demo, where NTT twiddles are not precomputed and the cost is negligible.  `SecurityProofsCode/zkp_pqc_exploration.py` §2.7 cross-checks the NTT result against schoolbook and measures the speedup ($\approx 6.8\times$ at $n=256$, $\approx 12.7\times$ at $n=512$ in pure Python).

3. **ZKB++ on NL-FSCX.** *(Scoped v1.9.66 — see §11.10.4 and `zkp_pqc_exploration.py` §3.7.)*  Implement Chase et al. 2017's optimised MPC-in-the-head decomposition.  A first-principles size accounting shows ZKB++ reduces the $n=256$ proof from 920 KB to **≈457 KB ($2.0\times$)**, not the generic 180 KB — the NL-FSCX circuit is AND-gate-broadcast-dominated, so only the $2\times{\to}1\times$ online-party term helps.  Reaching ~180 KB additionally requires a sparse (LowMC-like) circuit to cut the AND-gate count; that circuit redesign remains open.

4. **Hybrid credential scheme.** *(Scoped v1.9.67 — design sketch in §11.10.8.)*  Combine the Ring-LWR $\Sigma$-protocol with HPKS-Stern-F to prove "I hold a Ring-LWR private key $s$ matching public key $C$ AND a code-based credential bound to $s$" — an AND-composition glued by a binding commitment to $s$, single Fiat-Shamir challenge, estimated proof size $\approx 80$ KB (Stern-F-dominated).  The unresolved crux is the binding map $\phi$ relating the ternary ring secret to the fixed-weight binary Stern witness with a cheap gadget; until that is settled the scheme stays a design sketch.

### 11.10.7 Conditional Reduction of Relaxed Soundness to Ring-LWR (TODO #94 item 3a)

This subsection makes open direction 1 concrete: it reduces the relaxed special soundness of the §11.10.2 $\Sigma$-protocol to the hardness of Ring-LWR, routing through an intermediate *approximate Ring-SIS* problem, and quantifies exactly how the rounding slack enters the security margin.  The reduction is conditional (stated assumptions below) rather than a fully tight standard-model reduction, matching the honest limitation already recorded in §11.10.2.

**Hardness assumptions.**  Work in $\mathcal{R}_q = \mathbb{Z}_q[x]/(x^n+1)$ with $q = 65537$, $p = 4096$.

- **(R-LWR) Decision Ring-LWR with rounding.**  For $m \xleftarrow{R} \mathcal{R}_q$ and ternary $s \xleftarrow{R} \{-1,0,1\}^n$, the pair $(m, \text{round-p}(m \cdot s))$ is computationally indistinguishable from $(m, u)$ with $u \xleftarrow{R} \mathbb{Z}_p^n$.  Write the distinguishing advantage bound as $\epsilon_{\text{RLWR}}$.
- **(aR-SIS) Approximate Ring-SIS for the suite modulus.**  Given $m \xleftarrow{R} \mathcal{R}_q$, it is hard to find a nonzero $v \in \mathcal{R}_q$ with $\lVert v \rVert_\infty \leq \beta$ and $\lVert m \cdot v \rVert_\infty \leq \mu$ for the parameters $(\beta, \mu)$ derived below.  For $m$ sampled as in HKEX-RNL this is implied by R-LWR (a short kernel-like relation for a pseudorandom $m$ would itself distinguish $m \cdot s$ from uniform).

**Extracted relaxed witness (from §11.10.2).**  Forking a cheating prover that succeeds with probability $\delta$ over $Q_H$ random-oracle queries yields, with probability at least $\delta^2/Q_H - \text{negl}$, two accepting transcripts $(w, c, z)$ and $(w, c', z')$ with $c \neq c'$.  Setting $\bar{z} = z - z'$ and $\bar{c} = c - c'$, subtracting the two third verification equations gives

$$\lVert m \cdot \bar{z} - \bar{c} \cdot \text{lift}(C) \rVert_\infty \leq 2t \lceil q/(2p) \rceil, \quad \bar{c} \neq 0, \quad \lVert \bar{z} \rVert_\infty \leq 2(\gamma - t).$$

**Reduction to aR-SIS.**  By definition of rounding, $\text{lift}(C) = m \cdot s - \varepsilon$ with $\lVert \varepsilon \rVert_\infty \leq \lceil q/(2p) \rceil$.  Substitute:

$$m \cdot \bar{z} - \bar{c} \cdot \text{lift}(C) = m \cdot \bar{z} - \bar{c} \cdot (m \cdot s - \varepsilon) = m \cdot (\bar{z} - \bar{c} \cdot s) + \bar{c} \cdot \varepsilon.$$

Let $v = \bar{z} - \bar{c} \cdot s$.  Then $\lVert m \cdot v \rVert_\infty \leq 2t \lceil q/(2p) \rceil + \lVert \bar{c} \cdot \varepsilon \rVert_\infty$.  Since $\bar{c}$ has at most $2t$ nonzero coefficients each of magnitude $\leq 2$ and $\lVert \varepsilon \rVert_\infty \leq \lceil q/(2p) \rceil$, we have $\lVert \bar{c} \cdot \varepsilon \rVert_\infty \leq 2t \lceil q/(2p) \rceil$, hence

$$\lVert m \cdot v \rVert_\infty \leq 4t \lceil q/(2p) \rceil =: \mu, \qquad \lVert v \rVert_\infty \leq 2(\gamma - t) + 2t = 2\gamma =: \beta.$$

**Two cases.**

- **$v \neq 0$:** the pair $v$ is a valid aR-SIS solution for $m$ with slack $\mu$ and norm $\beta$ — directly contradicting (aR-SIS), hence (by the stated implication) R-LWR.
- **$v = 0$:** then $\bar{z} = \bar{c} \cdot s$, so the extractor has recovered a nonzero ring multiple $\bar{c} \cdot s$ of the secret from public data alone.  Recovering a $\bar{c}$-multiple of $s$ given only $(m, C)$ contradicts the pseudorandomness of $C$ under R-LWR (a simulator that learns $\bar{c} \cdot s$ for known sparse $\bar{c}$ can test it against $C$ and so distinguish $C$ from uniform).

In both cases a successful cheating prover breaks R-LWR, up to the forking loss $\delta \mapsto \delta^2/Q_H$ and the $2\times$ witness-norm widening inherent to relaxed soundness.

**Rounding-slack quantification.**  The slack modulus is

$$\mu = 4t \lceil q/(2p) \rceil = 4t \lceil 65537/8192 \rceil = 4t \cdot 9 = 36t.$$

Numerically $\mu = 144$ at $t = 4$ ($n = 32$) and $\mu = 576$ at $t = 16$ ($n = 256$), against $q = 65537$.  The ratio $\mu/q$ is 0.22% and 0.88% respectively — the extracted relation $m \cdot v$ is genuinely short relative to $q$, so the aR-SIS instance is non-trivial (a random $v$ of norm $\beta = 2\gamma$ would give $\lVert m \cdot v \rVert_\infty \approx q/2$).  Relative to the Lyubashevsky 2012 template — prime $q$ and a challenge ring chosen so that $\bar{c}$ is always invertible, yielding an *exact* ($\mu = 0$) inhomogeneous-SIS witness — the suite trades exactness for the rounding slack $\mu = 36t$.  This is the precise quantitative gap requested by open direction 1; it scales linearly in the challenge weight $t$ and is independent of $n$, so wider challenges (stronger soundness per round) cost proportionally more slack.

### 11.10.8 Hybrid Ring-LWR + Stern-F Credential — Design Sketch (TODO #94 item 3d)

This subsection scopes open direction 4: a single compound zero-knowledge proof asserting *"I hold a Ring-LWR secret $s$ matching public key $C$ **and** a code-based credential bound to $s$,"* without revealing $s$ or the credential.  The construction is an AND-composition of the two $\Sigma$-protocols the suite already provides — the §11.10.2 Ring-LWR protocol and the Stern identification protocol underlying HPKS-Stern-F (§11.8.4) — glued by a commitment that forces both to speak about the same secret.

**Statement and witness.**

- *Public:* the Ring-LWR pair $(m, C)$ with $C = \text{round-p}(m \cdot s)$; a binary parity-check matrix $H \in \mathbb{F}_2^{(N-k) \times N}$ and a syndrome $y = H e^{\top}$ (the Stern statement).
- *Witness:* the ternary $s \in \{-1,0,1\}^n$ and a low-weight $e \in \mathbb{F}_2^N$ with $\text{wt}(e) = t_{\text{S}}$, subject to a binding relation $e = \phi(s)$ for a fixed public map $\phi$ (below).

**Binding the two witnesses.**  The two relations live in different algebras — $s$ is ternary in $\mathcal{R}_q$, $e$ is binary in $\mathbb{F}_2^N$ — so "the same $s$" must be enforced explicitly.  The design commits to $s$ once with a binding commitment $\text{cmt}(s; r)$ (a BDLOP-style lattice commitment, or a hash commitment to the bit-decomposition of $s$) and runs both sub-protocols against that single commitment:

1. the Ring-LWR $\Sigma$-protocol proves $C = \text{round-p}(m \cdot s)$ for the committed $s$;
2. a bit-decomposition gadget proves $e = \phi(s)$ (e.g. $\phi$ maps the sign pattern of $s$ to a fixed-weight binary word) for the committed $s$, after which the Stern protocol proves $H e^{\top} = y$ with $\text{wt}(e) = t_{\text{S}}$.

**AND-composition (non-interactive).**  Run both sub-protocols in parallel with independent prover randomness and derive a single Fiat-Shamir challenge $\text{ch} = H_{\text{FS}}(\text{cmt}(s), \text{transcript}_{\text{RLWR}}, \text{transcript}_{\text{Stern}}, m, C, H, y)$, then split $\text{ch}$ into the per-protocol challenges.  Hashing both commitment phases together binds the two proofs to one prover and one $s$.

**Security.**

- *Completeness* follows from the completeness of each sub-protocol.
- *Soundness:* AND-composition of two sound $\Sigma$-protocols is sound — an extractor that rewinds the shared challenge recovers a relaxed Ring-LWR witness (§11.10.7) **and** a Stern witness; the binding of $\text{cmt}(s)$ forces the extracted $s$ to be consistent across both, so a prover lacking either secret fails one branch.  Soundness error is the max of the two per-round errors; both are driven to $2^{-128}$ by their existing round counts ($R = 219$ for Stern; one relaxed FS round for Ring-LWR).
- *Zero-knowledge:* parallel composition with independent randomness preserves honest-verifier ZK; the commitment is hiding, so $\text{cmt}(s)$ leaks nothing.

**Proof size (estimate).**  Additive minus the shared commitment: ZKP-RNL ($\approx 1.03$ KB at $n=256$, §11.10.2) $+$ Stern-F ($\approx 78$ KB at $N=256$, $R=219$) $+$ the bit-decomposition gadget and commitment ($\approx 1$–2 KB) $\approx$ **80 KB**, dominated by the Stern-F component.

**Open problem.**  The crux is the binding map $\phi$ and its gadget: a sound, ZK proof that a committed ternary ring element and a committed fixed-weight binary word are related requires either (a) an arithmetic-circuit proof of the bit-decomposition (expensive), or (b) choosing $\phi$ so the relation is linear over a common ring (restrictive).  Designing $\phi$ so that $\text{wt}(\phi(s)) = t_{\text{S}}$ holds for honest $s$ while keeping the gadget cheap is the main unresolved question; until it is settled the scheme remains a design sketch rather than an implementation.

**References.**
- Lyubashevsky 2012. *Lattice Signatures Without Trapdoors*. Eurocrypt 2012, LNCS 7237, pp. 738–755.
- Giacomelli, Madsen, Orlandi 2016. *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*. USENIX Security 2016, pp. 1069–1083.
- Chase et al. 2017. *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives*. CCS 2017, pp. 1825–1842. (ZKB++)
- Baum, Damgård, Lyubashevsky, Oechsner, Peikert 2018. *More Efficient Commitments from Structured Lattice Assumptions*. SCN 2018, LNCS 11035, pp. 368–385. (BDLOP)
- NIST FIPS 204 (ML-DSA / Dilithium, 2024). NIST FIPS 205 (SLH-DSA / SPHINCS+, 2024).
