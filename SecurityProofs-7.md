# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 7

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 7 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.23** (this file): Zero-Knowledge Proof Extensions · Research-Review Sections

---

## 11.10 Zero-Knowledge Proof Extensions (TODO #76)

This section surveys and prototypes zero-knowledge proof (ZKP) constructions for the two PQC hardness pillars not yet covered by existing ZKP infrastructure.  The third pillar (B2, syndrome decoding) is already covered by the Stern identification protocol + Fiat-Shamir (§11.8.4, Theorem 17, SecurityProofs-5.md).

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

ZKP-NL at n=256 and R=219 yields 920 KB, which exceeds practical limits for most use cases.  The CLI defaults to n=8 (35.5 KB) for this reason.  The ZKB++ encoding (`zkp_nl_prove_pp`, implemented v1.9.81 — §11.10.6 direction 3) reduces the n=256 revolve proof to 464 KB ($1.98\times$, gate-broadcast-dominated — see §11.10.4 size breakdown), not the generic $5\times$/180 KB; the implemented single-step circuit drops to 31 KB ($5.5\times$, overhead-dominated).  The Ligero-lite IOP prototype (v1.9.87 — §11.10.6 direction 3) further reduces the revolve statement to 219 KB unpruned / 163 KB pruned at $\lambda = 128$ with no parallel repetition, reaching the Picnic-range target.

CLI integration is documented in `docs/TUTORIAL.md §ZKP Protocols`.  Cross-language interop is verified by `CliTest/test_zkp_interop.sh` (14-way test: 6 signing directions per protocol, plus 2 tamper-rejection checks).

### 11.10.5 Comparison and Recommendations

| Use case | Recommended construction | Proof size | Notes |
|---|---|---|---|
| PQC signature | HPKS-Stern-F (§11.8.4) | 78 KB | **Demo parameters** ($N=256$, ~30–40 bits security); 128-bit requires $N \geq 17000$ |
| Ring-LWR key proof / anonymous cred | Ring-LWR $\Sigma$-protocol (§11.10.2) | 1 KB | Implemented v1.9.x; heuristic security |
| NL-FSCX witness proof | ZKBoo (§11.10.3) | 920 KB | Implemented v1.9.x; CLI defaults to n=8 |
| NL-FSCX with ZKB++ encoding | ZKB++ (§11.10.3, `zkp_nl_prove_pp`) | 464 KB extrapolated ($1.98\times$); 34 KB for the implemented single-step circuit | Implemented v1.9.81 (Python) |
| NL-FSCX with sparse circuit | ZKB++ + LowMC-like circuit | ruled out (~15% savings only) | Analysed v1.9.83 (`nl_fscx_sparse_circuit.py`): share size, not gate count, dominates |
| NL-FSCX IOP argument | Ligero-lite over $\text{GF}(2^{16})$ (`nl_fscx_ligero.py`) | 219 KB (163 KB with path pruning) at $n=256$, $r=64$; 96 KB (39 KB pruned) single-step | Prototyped v1.9.87; argument of knowledge (ZK randomizer rows pending) |

For anonymous credential applications on HKEX-RNL keys, the Ring-LWR $\Sigma$-protocol is the most practical option: its 1 KB proof size is competitive with ML-DSA-44 (2.4 KB).

### 11.10.6 Open Research Directions

1. **Formal Ring-LWR reduction.** *(Addressed v1.9.65 — conditional reduction in §11.10.7.)*  A reduction from relaxed $\Sigma$-protocol soundness to Ring-LWR is given via an intermediate approximate Ring-SIS step; the rounding slack enters as the SIS modulus $4t \lceil q/(2p) \rceil$ (= $36t$ for the suite's $q, p$).  It remains conditional on the hardness of approximate Ring-SIS for the HKEX-RNL blinding polynomial $m$ (itself implied by Ring-LWR for $m$), so it is not yet a fully tight standard-model reduction.

2. **NTT-accelerated $\Sigma$-protocol.** *(Resolved v1.9.64.)*  The prover and verifier polynomial products in the reference suite (`rnl_poly_mul` / `_rnl_poly_mul` / `RnlPolyMul`) use the negacyclic NTT over $Z_q[x]/(x^n+1)$ (the same path as HKEX-RNL, §11.4.2) at the production degree $n=256$, giving $O(n \log n)$ prover and verifier; the $O(n^2)$ schoolbook multiply is retained only for the $n=32$ didactic demo, where NTT twiddles are not precomputed and the cost is negligible.  `SecurityProofsCode/zkp_pqc_exploration.py` §2.7 cross-checks the NTT result against schoolbook and measures the speedup ($\approx 6.8\times$ at $n=256$, $\approx 12.7\times$ at $n=512$ in pure Python).

3. **ZKB++ on NL-FSCX.** *(Encoding implemented v1.9.81 Python suite + v1.9.82 C/Go ports and CLI — `zkp_nl_prove_pp` / `zkp_nl_verify_pp` (Python), `zkp_nl_pp_prove` / `zkp_nl_pp_verify` (C), `ZkpNlProvepp` / `ZkpNlVerifypp` (Go); `sign/verify --algo nl-zkbpp` in all three CLIs; 10-way interop verified (`CliTest/test_zkbpp.sh`); sparse circuit redesign remains open.)*  Chase et al. 2017's optimised MPC-in-the-head decomposition is implemented with all four transcript optimisations: PRG-derived input shares for parties 0/1 (16-byte seeds), explicit offset share for party 2, single-online-party AND-gate broadcast (bit-packed), and hidden-commitment-only transmission with a Picnic-style challenge recomputation.  Empirical validation (§3.8) confirms the §3.7 first-principles accounting: the $n=256$, $r=64$ revolve circuit drops from 920 KB to **464 KB ($1.98\times$)** — the AND-gate broadcast dominates, so only the $2\times{\to}1\times$ online-party term helps.  For the implemented single-step circuit (255 AND gates), where fixed overhead dominates, the measured reduction is larger: 170.9 KB → 31.0 KB ($5.5\times$) at $n=256$, $R=219$ against the byte-packed basic-ZKBoo transcript.  Reaching ~180 KB for the revolve circuit additionally required a different proof system: the sparse-circuit analysis (v1.9.83, `nl_fscx_sparse_circuit.py`, SecurityProofs-4.md §11.8.2) showed that cutting AND gates saves only ~15% of ZKB++ bytes because the 32-byte per-party share dominates.  The **Ligero-lite IOP prototype** (v1.9.87, `SecurityProofsCode/nl_fscx_ligero.py`) closes the direction: over $\text{GF}(2^{16})$ the NL-FSCX circuit arithmetizes with XOR/rotation as *linear* maps (only the carry-chain AND gates and input booleanity are quadratic), and a single Reed-Solomon-encoded, Merkle-committed witness matrix replaces all parallel repetitions — soundness comes from $t$ column queries (conservative $e < d/3$ regime of Ligero Thm 4.2) plus $\sigma = \lceil \lambda/16 \rceil$ field-sized algebraic-combo repetitions.  Measured results: byte-exact size-model validation at two scales including a real $\lambda = 128$ proof at $n=64$, $r=8$ (102 KB, prove 2.1 s, verify 7.0 s pure Python); at $n=256$, $r=64$, $\lambda = 128$ the modeled proof is **219 KB unpruned / 163 KB with Merkle path pruning** — below the 180 KB Picnic-range target and a further $2.1{-}2.8\times$ under ZKB++'s 464 KB; the single-step statement drops to 96 KB (39 KB pruned).  Remaining production gaps: zero-knowledge randomizer rows (a few KB), a hardened soundness analysis, and constant-time implementation (TODO #122 closed; production hardening would be a new item).

4. **Hybrid credential scheme.** *(Scoped v1.9.67 — design sketch in §11.10.8; binding map resolved v1.9.73 — §11.10.9.)*  Combine the Ring-LWR $\Sigma$-protocol with HPKS-Stern-F to prove "I hold a Ring-LWR private key $s$ matching public key $C$ AND a code-based credential bound to $s$" — an AND-composition glued by a binding commitment to $s$, single Fiat-Shamir challenge, estimated proof size $\approx 80$ KB (Stern-F-dominated).  The formerly unresolved crux — the binding map $\phi$ relating the ternary ring secret to the low-weight binary Stern witness with a cheap gadget — is resolved in §11.10.9: the positive-support bitmap makes the binding relation algebraic of degree 3 over $\mathbb{Z}_q$ (512 multiplication gates at $n=256$, no bit decomposition).  Implementation promotion is tracked as TODO #128.

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

**Open problem.**  *(Resolved v1.9.73 — see §11.10.9.)*  The crux is the binding map $\phi$ and its gadget: a sound, ZK proof that a committed ternary ring element and a committed fixed-weight binary word are related requires either (a) an arithmetic-circuit proof of the bit-decomposition (expensive), or (b) choosing $\phi$ so the relation is linear over a common ring (restrictive).  Designing $\phi$ so that $\text{wt}(\phi(s)) = t_{\text{S}}$ holds for honest $s$ while keeping the gadget cheap is the main unresolved question; §11.10.9 shows the dichotomy was a false choice — a third route (polynomial identities over $\mathbb{Z}_q$) is both cheap and exact.

### 11.10.9 Resolution of the Binding Map φ (TODO #123)

The dichotomy posed in §11.10.8 — bit-decomposition circuit (expensive) versus common-ring linearity (restrictive) — omits a third route that is both cheap and exact.  Choose the **positive-support bitmap**

$$\phi_A(s)_i = 1 \iff s_i = +1.$$

For ternary $s_i \in \{-1, 0, 1\}$ the entire binding relation is then a system of *polynomial identities over the Ring-LWR base field* $\mathbb{Z}_q$, requiring no bit decomposition at all:

$$s_i^3 - s_i = 0 \qquad \text{(ternary membership)}, \qquad e_i = (s_i^2 + s_i) \cdot 2^{-1} \bmod q \qquad \text{(support extraction)}.$$

Both constraints follow from evaluating the polynomials at the three ternary points: $s_i^3 = s_i$ holds exactly on $\{-1,0,1\}$, and $(s_i^2+s_i)/2$ equals $1$ at $s_i = 1$ and $0$ at $s_i \in \{0,-1\}$.  The gadget circuit is two multiplication gates per coefficient ($a_i = s_i \cdot s_i$, $b_i = a_i \cdot s_i$) — **512 multiplication gates at $n = 256$**, all native $\mathbb{Z}_q$ arithmetic, directly compatible with any MPC-in-the-head proof system or lattice product argument over the same modulus.

**Weight leakage.**  Under $\phi_A$ the Stern witness weight becomes $w = \text{wt}_+(s) \sim \text{Binomial}(256, 1/4)$ — mean 64, standard deviation 6.93 — and is revealed to the verifier.  The exact entropy of the weight is 4.84 bits against the 384-bit secret entropy of $s$ (256 coefficients at 1.5 bits each): a 1.3% leak, negligible.  Empirical confirmation over 100 000 CBD(1) samples: mean 64.00, observed range $\lbrack 37, 96 \rbrack$ (`hybrid_credential_phi.py` §2).

**Many-solutions regime — a new security finding.**  Raising the Stern weight from the deployed $t = 16$ to $w \approx 64$ moves the SDP instance from the unique-solution regime into a many-solutions regime.  For the $(N{=}256, k{=}128)$ demo code the expected solution count per syndrome is $2^{203.6 - 128} \approx 2^{75.6}$, and Prange's per-iteration success probability is multiplied by that count: finding *some* weight-64 solution of $H e^{\top} = y$ takes $\approx 2^{3.8}$ iterations.  This enables a **self-registered-key forgery**: an attacker finds any weight-64 solution $e'$, sets $s' = e'$ (which is valid ternary with $\phi_A(s') = e'$), registers $C' = \text{round-p}(m \cdot s')$, and proves the compound statement honestly.  Two mitigations, either sufficient:

1. **Issuer-bound pair** (recommended, zero cost): the credential is an issuer *signature over* $(C, y)$, so a forger must match an existing issued pair — find $s'$ satisfying both $\text{round-p}(m \cdot s') = C$ and $H \phi_A(s')^{\top} = y$ simultaneously, a 128-bit targeted preimage condition on top of Ring-LWR key recovery.  Credentials are issuer-signed in any deployment of §11.10.8, so this constraint is free.
2. **Fixed-weight variant $\phi_D$** (first-16-positives selection): keeps $w = t_{\text{S}} = 16$ and the unique-solution regime, at the cost of a prefix-sum selection circuit ($\approx 2{,}800$ additional Boolean AND gates, $\approx 5.5\times$ the $\phi_A$ gadget).  $\Pr\lbrack \text{wt}_+(s) < 16 \rbrack = 2^{-50.6}$, so the selection never fails for honest keys.

**Gadget cost at $n = 256$, $2^{-128}$ soundness** (`hybrid_credential_phi.py` §4):

| Proof system for the 512-gate gadget | Size | Assumptions |
|---|---|---|
| BDLOP product argument | $\approx 2$ KB | lattice commitment (new primitive for the suite) |
| KKW 64-party MPC-in-the-head, $\tau = 22$ | $\approx 40$ KB | hash-only — **recommended** |
| ZKBoo-(2,3) over $\mathbb{Z}_q$ (prototype) | $\approx 850$ KB | hash-only, unoptimised transcript |
| Boolean-PRF route (candidate B, two NL-FSCX circuits) | $\approx 1.8$ MB | rejected |

Hybrid credential totals: $\approx 81$ KB with the BDLOP gadget (matching the §11.10.8 estimate) or $\approx 120$ KB with the hash-only KKW gadget — Stern-F-dominated either way.

**Prototype verification.**  `SecurityProofsCode/hybrid_credential_phi.py` §5 implements the $\phi_A$ gadget as a ZKBoo-style (2,3)-decomposition over $\mathbb{Z}_q$ with Fiat-Shamir challenges: completeness 30/30 at $n=32$ and end-to-end at $n=256$; false statements ($e \neq \phi_A(s)$) and non-ternary witnesses rejected 500/500 each (unconditional output-sum check); corrupted-view cheating survives at the expected $(1/3)^R$ rate (24 observed vs 18.5 expected at $R=3$ over 500 trials).

**Conclusion.**  The open problem of §11.10.8 is resolved: $\phi = \phi_A$ with issuer-bound $(C, y)$ and a KKW (hash-only) or BDLOP gadget.  Promotion to a suite implementation — the compound prover/verifier, the linkable commitment, and CLI surface — is tracked as TODO #128.

### 11.10.10 HCRED Implementation Notes (TODO #128, Batches 1–2 — v1.9.74/v1.9.75)

The Python suite implements the credential as `hcred_phi`, `hcred_user_keygen`, `hcred_syndrome`, `hcred_issue`, `hcred_cred_verify`, `hcred_prove`, and `hcred_verify`.  Three design refinements emerged during implementation, each departing from the §11.10.8 sketch in ways worth recording; the current architecture (after Batch 2) is a *single unified MPC-in-the-head proof* over $\mathbb{Z}_q$ anchored by an HPKS-Stern-F issuer signature over $H(m \Vert C \Vert \text{seed-H} \Vert y)$ — the issuer binding is what defeats the §11.10.9 self-registered-key forgery.

**Refinement 1 — the Stern sub-protocol is replaced by a single MPC-in-the-head circuit.**  The §11.10.9 gadget prototype treated $e = \phi_A(s)$ as *public*, but in the credential $e$ must stay secret: it reveals the positive support of $s$, halving the secret entropy from 384 to 192 bits.  Rather than proving $e = \phi_A(s)$ against a committed $e$ and separately running Stern on the same commitment (the linkable-commitment problem §11.10.8 deferred to BDLOP), Batch 1 merges the gadget and the syndrome check into one ZKBoo-(2,3) arithmetic circuit over $\mathbb{Z}_q$ in which the $e$-wires are internal linear wires that are never opened:

- ternary membership and support extraction as in §11.10.9 ($2n$ multiplication gates);
- the revealed weight $W = \sum_i e_i$ (linear output, verifier checks $1 \leq W \leq w_{\max}$ with $w_{\max} = \lfloor n/4 + 4\sqrt{3n/16} \rfloor$, i.e. 91 at $n = 256$);
- the syndrome rows as *integer* sums $S_r = \sum_i H_{ri} e_i \leq n < q$ (no wraparound), reduced mod 2 through auxiliary witness bits: $S_r = \sum_t 2^t \beta_{r,t}$ with $\beta_{r,t}^2 = \beta_{r,t}$ ($\lceil \log_2(n{+}1) \rceil$ bit-check gates per row — 1152 gates at $n = 256$) and the public output $\beta_{r,0} = y_r$.

Total: $2n + (n/2)\lceil \log_2(n{+}1) \rceil$ multiplication gates (1664 at $n = 256$).  The mod-2 reduction via bit decomposition is the only structural cost the merge adds over the §11.10.9 gadget, and it eliminates both the standalone Stern branch (78 KB) and its linkage gadget.  The weight bound replaces Stern's exact-weight check; at the demo code $(N{=}256, k{=}128)$, forging a syndrome preimage of weight $\leq 91$ costs roughly $2^{24}$ by multiplicity-adjusted Prange — the same order as the deployed Stern-F demo parameters, and production still requires the longer codes of TODO #91/#126.

**Refinement 2 (Batch 1, superseded) — sequential Fiat-Shamir binding.**  Batch 1 ran the §11.10.2 Ring-LWR $\Sigma$-protocol as a separate branch, bound to the MPCitH branch only through the shared Fiat-Shamir transcript.  That left the collusion-splitting gap: a compound proof demonstrated knowledge of *some* $s'$ for $C$ and *some* $s''$ for $y$, not the same witness.  Batch 2 (v1.9.75) eliminates the gap — and the $\Sigma$-protocol branch itself — as follows.

**Refinement 3 (Batch 2, v1.9.75) — the Ring-LWR relation moves inside the circuit; one witness by construction.**  The key observation: $m \cdot s$ is *linear* in the $s$-wires because $m$ is public, so the Ring-LWR relation $C = \text{round-p}(m \cdot s)$ enters the MPCitH circuit at the cost of only a range check on the rounding error.  Writing $m \cdot s = \text{lift}(C) + \varepsilon$ with honest $\lVert \varepsilon \rVert_\infty \leq \lceil q/(2p) \rceil = 8$, each $\varepsilon_i$ is witnessed by 5 auxiliary bits $\delta_{i,t}$ ($\varepsilon_i = \sum_t 2^t \delta_{i,t} - 16$, range $\lbrack -16, 15 \rbrack$) with bit checks $\delta_{i,t}^2 = \delta_{i,t}$ and the linear public output $\lbrack m \cdot s \rbrack_i - \sum_t 2^t \delta_{i,t} = \text{lift}(C)_i - 16$.  This adds $5n$ multiplication gates (total $2n + (n/2)\lceil \log_2(n{+}1) \rceil + 5n$ — 4224 at $n = 256$, 384 at $n = 32$) and removes the separate $\Sigma$-protocol entirely: the whole compound statement is one proof with one witness, so same-$s$ linkage holds *by construction* and no BDLOP commitment is needed.  The empirical rejection tests confirm both directions: a prover holding $s_2$ (valid for $C_2$) cannot produce a proof against $(C_2, y_1)$, and a prover holding $s_1$ cannot prove against $(C_2, y_1)$ either.

**Relaxed rounding soundness.**  The 5-bit range admits $\lVert \varepsilon \rVert_\infty \leq 15$ rather than the honest 8, so the proven relation is $\lVert m \cdot s - \text{lift}(C) \rVert_\infty \leq 15$ — a cheating witness may sit up to one rounding-bucket boundary away from $C$.  This is the standard LWR-proof relaxation and is *tighter* than the §11.10.2 $\Sigma$-protocol's own aggregate slack $t \lceil q/(2p) \rceil = 144$ at $t = 16$; the security-margin accounting of §11.10.7 absorbs it unchanged.

**Transcript-format soundness note.**  The ZKBoo transcript ships all three parties' cleartext output shares: they must be bound into the Fiat-Shamir hash before the challenge, and shipping only the unopened party's outputs is unsound because the verifier cannot reconstruct the opened parties' outputs before knowing the challenge.  Demo parameters are $n = 32$, $R = 4$ ($R = 219$ for $2^{-128}$ soundness).

**Statement-bound commitments (v1.9.77).**  The presentation nonce enters the statement hash, and the statement hash is bound into *every per-round commitment* — not only into the challenge.  Without this, a proof replayed against a different statement (nonce, key, or syndrome) is caught only when the re-derived challenge trit differs in some opened round, a $(1/3)^R$ false-accept chance ($1/81$ at the demo $R = 4$).  With the statement in the commitment domain, the verifier's recomputation of any opened party's commitment fails deterministically under a changed statement, so replay, wrong-key, and wrong-syndrome are all rejected at every $R$.  The KKW variant is already deterministic here — its cut-and-choose subset derives from a statement-bound preprocessing hash, so a changed statement selects a different subset than the one the proof opens.

**Refinement 4 (Batch 3, v1.9.76) — KKW preprocessing-model transcript.**  `hcred_prove_kkw` / `hcred_verify_kkw` encode the same circuit and statement in the KKW paradigm (Katz-Kolesnikov-Wang 2018): $N$-party additive masking with per-emulation seed trees, cut-and-choose over $M$ preprocessing emulations (opening $M - \tau$ root seeds forces the product-share corrections "aux" to be honest), online broadcasts for the $\tau$ surviving emulations with one hidden party each, and a *batched output check* — all $K$ output wires fold into a single random linear combination with Fiat-Shamir coefficients $\rho \in \mathbb{Z}_q^K$ drawn after the broadcasts are bound, so each party broadcasts one combined mask share instead of $K$ values (the per-emulation escape probability gains only $1/q \approx 2^{-16}$, negligible against the $1/N$ party-hiding term).  Soundness: a prover cheating in $k$ preprocessing emulations survives with probability $\binom{M-k}{M-\tau}/\binom{M}{M-\tau} \cdot (1/N)^{\tau-k}$; the production parameter set $(N, M, \tau) = (64, 343, 27)$ (Picnic2) gives $2^{-128}$.

**Honest size revision.**  TODO #123 projected "$\approx 40$ KB ($20\times$)" for KKW — but that estimate was for the original 512-gate $\phi$-only gadget.  After the Batch-2 unification the circuit is 4224 gates at $n = 256$, and the per-emulation transcript is dominated by three unavoidable 4224-element vectors (hidden party's broadcasts, aux, and the 2688 masked inputs): $\approx 33.6$ KB per online emulation, $\approx 0.9$ MB total at production parameters — an $\approx 11\times$ cut over the ZKBoo transcript ($\approx 9.2$ MB at $R = 219$), not $20\times$.  Measured at the demo scale ($n = 32$): KKW 11.7 KB vs ZKBoo 18.9 KB.  Reaching tens of kilobytes would require a circuit-level change (fewer multiplication gates — e.g. packing the bit checks into polynomial constraints) rather than a better transcript encoding.

**Remaining #128 work.**  C/Go ports (with the unified security test added to all three languages simultaneously), CLI surface, and tutorial.

**References.**
- Lyubashevsky 2012. *Lattice Signatures Without Trapdoors*. Eurocrypt 2012, LNCS 7237, pp. 738–755.
- Giacomelli, Madsen, Orlandi 2016. *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*. USENIX Security 2016, pp. 1069–1083.
- Chase et al. 2017. *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives*. CCS 2017, pp. 1825–1842. (ZKB++)
- Baum, Damgård, Lyubashevsky, Oechsner, Peikert 2018. *More Efficient Commitments from Structured Lattice Assumptions*. SCN 2018, LNCS 11035, pp. 368–385. (BDLOP)
- NIST FIPS 204 (ML-DSA / Dilithium, 2024). NIST FIPS 205 (SLH-DSA / SPHINCS+, 2024).
- Katz, Kolesnikov, Wang 2018. *Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures*. CCS 2018, pp. 525–537. (KKW)
- Prange 1962. *The Use of Information Sets in Decoding Cyclic Codes*. IRE Trans. IT-8, pp. 5–9.

---

### 11.11 Constant-Time Audit of Core Arithmetic Primitives (TODO #129)

**Background.** TODO #126's status note flagged "production gaps (constant-time C, weak-key
rejection)" for the Stern-F/BIKE path specifically. This item extends the check to
`herradura.h` broadly and puts it on empirical footing with a statistical timing-leakage
test rather than code inspection alone. A prior manual audit (SA-01 through SA-09, v1.7.4 —
CHANGELOG.md) already replaced the variable-time `gf_mul_ba`/`gf_pow_ba`/`ba_mul_mod_ord`
with bitmask-select constant-time versions and fixed a `memcmp` early-exit in `ba_equal`;
this section confirms those fixes empirically and extends coverage to `ba_fscx_revolve` and
the protocol entry points.

**Method (Batch 1 — v1.9.94).** `SecurityProofsCode/dudect_timing_audit.c` implements a
simplified dudect (Reparaz et al. 2017) fixed-vs-random test: for each primitive, the
secret-position operand is either held fixed (all-zero) or freshly randomized on every call;
timings are interleaved (fixed/random order alternates per round, both measured every round
to cancel drift) with a 50-call warmup discarded, and a Welch's t-test is computed over the
two distributions. `|t| >= 4.5` is dudect's standard leak-detection threshold.

**Results — audited and clean (empirically confirmed, no timing leak detected at 4000 rounds):**

| Function | Secret-dependent input | \|t\| | Verdict |
|---|---|---|---|
| `gf_mul_ba` | operand `a` (private key material in `gf_pow_ba`) | 0.16 | clean |
| `gf_pow_ba` | exponent (private key / nonce) | 0.63 | clean |
| `ba_mul_mod_ord` | operand `a` (Schnorr scalar) | 0.13 | clean |
| `ba_fscx_revolve` | key operand `b` (HSKE/HPKE/HPKS symmetric key) | 0.55 | clean |

All four are branchless: `gf_mul_ba`/`gf_pow_ba`/`ba_mul_mod_ord` use bitmask select (SA-02
through SA-04), and `ba_fscx` itself (the per-step body of `ba_fscx_revolve`) is a fixed
sequence of XOR/rotate operations with no data-dependent control flow or memory access by
construction — there is no branch to make constant-time in the first place.

**Audited and clean by inspection — protocol entry points (`hkex_`, `hske_`, `hpks_`,
`hpke_` core four).** `hkex_gf_pubkey`, `hkex_gf_agree`, `hske_encrypt`, `hske_decrypt`,
`hpks_sign`, `hpks_verify`, `hpke_encrypt`, `hpke_decrypt` (herradura.h) contain exactly one
class of branch each: the TODO #131 `gf_pub_is_valid()` degenerate-key rejection in
`hkex_gf_agree`/`hpke_encrypt`/`hpke_decrypt`, and the final `ba_equal` comparison in
`hpks_verify`. Both branch on **public** values (the peer's public key; the recomputed
commitment vs. the received one) — a timing difference here reveals no private key material,
only whether a public input was malformed, so these are not leaks. Every call into the
constant-time primitives above uses private key material as the documented secret operand,
with no additional branching in between.

**Not yet audited at the end of Batch 1 — deferred.** `stern_`/`hpks_stern_f_*`/
`hpke_stern_f_*` (Stern ZKP and Niederreiter KEM) and `hpks_wots_*`/`hpks_xmss_*` were
flagged here as plausible leak surfaces and picked up in Batch 2 below, with one confirmed
finding. The `SecurityProofsCode/*.py` prototypes (`nl_fscx_*`, `hkex_rnl_*`) remain out of
scope: they are explicitly non-constant-time reference code (CHANGELOG.md: "the Python
reference implementation is intentionally not constant-time").

**Batch 2 — Stern-F permutation/error handling and WOTS/XMSS (v1.9.95).** Extends
`dudect_timing_audit.c` with three more targets and confirms one real leak:

| Function | Secret-dependent input | \|t\| | Verdict |
|---|---|---|---|
| `hpks_wots_sign` | `master_seed` | 0.06 | clean |
| `stern_gen_perm` | `pi_seed` | 180.85 | **leak confirmed** |
| `stern_apply_perm` (incl. `stern_gen_perm`) | `pi_seed` | 177.26 | **leak confirmed** |

**WOTS-F/XMSS-F — audited and clean.** `_wots_chain_ba`'s iteration count is
`WOTS_W - 1 - digits[i]`, and `digits[]` comes from `_wots_msg_to_digits(msg_hash)` — the
*message* hash, which is public in both sign and verify by construction (the verifier must
know it to recompute the same digits). The chain-hash values themselves never branch or
index memory by secret data (`_wots_h_ba` is a fixed `nl_fscx_revolve_v1_ba` call). So the
data-dependent loop count here leaks only public information, consistent with WOTS's
published design, not the earlier "plausible leak surface" concern this section flagged for
it in Batch 1. `hpks_xmss_sign`/`hpks_xmss_verify` call only `hpks_wots_sign`/
`hpks_wots_recover_pk` plus the already-constant-time-audited `haccum_*` accumulator
(TODO #83, CHANGELOG.md), so no separate finding.

**Stern-F — confirmed leak in `stern_gen_perm`.** The function draws 32-bit words from an
NL-FSCX-keyed PRNG stream and rejects any draw `>= threshold` before reducing mod `range`
(Fisher-Yates with rejection sampling for exact uniformity). The number of state advances
and rejected draws is a function of the PRNG output stream, which is keyed on the *secret*
`pi_seed` — so the number of loop iterations, and hence wall-clock time, varies with
`pi_seed`. The measured effect is large and systematic (fixed all-zero seed: 5195.6 ns;
random seed: 5886.2 ns; a ~12% difference, `|t| = 180.85`, far past the 4.5 threshold) —
this is a real, exploitable-in-principle timing channel, not benign rejection-sampling
noise. `stern_apply_perm` inherits the same signal because every call in the signature
path first regenerates `perm` via `stern_gen_perm`; `stern_apply_perm`'s own body remains
branchless (confirmed by inspection — `herradura.h`'s existing comment on the function),
but it addresses `out->b[]` at a `perm[i]`-dependent byte offset for every `i`, which is a
*memory-access-pattern* leak (cache-timing) that a wall-clock t-test cannot characterise or
rule out either way — that requires cache-timing instrumentation (e.g. `libFLUSH+RELOAD` or
a cache-simulator harness), which is out of scope for this batch.

**Severity in context.** `pi_seed` is a fresh, ephemeral per-round value, not the signer's
long-term secret error vector `e` — and in the `b ∈ {1,2}` response branches it is revealed
in the signature anyway (`resp_a[i] = pi[i]`), so this specific leak does not expose the
long-term Stern-F private key directly. It could still let a *local* or *co-located*
attacker distinguish signing rounds or bias timing-based side-channel attacks against the
challenge/response protocol during signing, and HPKS-Stern-F is already flagged demo-only
at N=256 (SecurityProofs-4.md §11.7) pending TODO #126's production decoder — but "demo
only for cryptanalytic reasons" is a different claim than "the C implementation is
side-channel safe," so this is recorded as a genuine, open finding rather than downgraded.

**Fix scoped, not applied this batch.** The standard fix is to replace the rejection-sampled
modulo reduction with a fixed-cost, single-draw multiply-shift map (Lemire's method:
`j = ((uint64_t)v * range) >> 32`), which removes the `do { } while` entirely — loop count
becomes a fixed function of `N` only, at the cost of a relative modulo bias
`< range / 2^32`, negligible at `range <= 256`. This is *not* applied in this batch because
`stern_gen_perm` (or its Go/Python equivalents) must stay bit-for-bit identical between
signer and verifier, and between all three CLI language implementations, for a signature to
verify at all — changing the sampling algorithm in `herradura.h` alone would silently break
cross-language interop (`CliTest/test_c_interop.sh`, `test_go_interop.sh`) until the same
change lands in the Go and Python suites simultaneously and the 9-way interop tests are
re-run. Tracked as follow-up scope for TODO #129 Batch 3, alongside the `stern_apply_perm`
memory-access-pattern question.

**Batch 3 — CT-01 fix applied across C/Go/Python (v1.9.96).** `stern_gen_perm` (`herradura.h`,
`herradura/herradura.go`, `Herradura cryptographic suite.py`) is changed identically in all
three implementations: the rejection-sampling `do { } while` is replaced with a single
32-bit draw per swap mapped to `[0, range)` via Lemire's multiply-shift,
`j = (v * range) >> 32`. This makes the loop count and PRNG-state-advance count a fixed
function of `N` alone — independent of `pi_seed` — closing the structural rejection-sampling
leak that Batch 2 found. The relative modulo bias this introduces is `< range / 2^32`,
unmeasurable at `range <= 256`. `stern_apply_perm` is unchanged (it was already branchless);
it now inherits whatever timing profile `stern_gen_perm` has.

Because `stern_gen_perm`'s output must be bit-identical between signer and verifier and
across all three language CLIs for a Stern-F signature to verify at all, the three
implementations were changed together and re-validated against `CliTest/test_stern_interop.sh`
(9/9 pass across all C/Go/Python signer↔verifier pairs), `CliTest/test_stern_kem.sh` (9/9),
and `CliTest/test_ring.sh` (21/21, OR-composed Stern ring signatures) — all still pass, so
the change is behavior-preserving at the protocol level even though it changes which
concrete permutation a given `pi_seed` produces.

**Re-measurement.** At 4000 rounds the mean-time gap between fixed and random `pi_seed`
collapsed from 690.6 ns (12.0% of the 5195.6 ns fixed-case mean, Batch 2) to 53.9 ns (1.3%
of the 4126.6 ns fixed-case mean) for `stern_gen_perm` — a ~13x reduction in absolute leak
size. `|t|` dropped from 180.85 to 5.22 at that sample size. However, at 20 000 rounds `|t|`
rises to 30.67 (`stern_gen_perm`) / 38.73 (`stern_apply_perm`) — Welch's t-statistic grows
with sample count for *any* nonzero true mean difference, so this confirms a real, if much
smaller, residual timing difference rather than closing the leak outright.

**Residual leak — likely hardware, not the rejection-sampling structure.** With the
rejection loop removed, control flow (iteration count, state-advance count, branch pattern)
is now provably identical between the fixed all-zero `pi_seed` and any random one. The
remaining ~54 ns/call difference is consistent with data-dependent latency in the
underlying hardware rather than the software algorithm: the fixed all-zero seed drives
`nl_fscx_v1_ba`'s internal state to a degenerate all-zero fixed point (XOR/rotate of zero is
zero), so every draw for the fixed class operates on identical all-zero words, while the
random class touches varying data on every call — a pattern consistent with power-gated or
early-terminating multiply/ALU units on low-power ARM cores (this suite's dudect runs were
taken on an aarch64 SBC), not with a leftover branch. `gf_mul_ba` and `ba_mul_mod_ord`
(Batch 1) also perform 8/32-bit multiplies but stayed clean (`|t| < 1`) under the same
methodology, which weighs against a blanket "this CPU's multiplier always leaks" explanation
and toward something specific to the all-zero degenerate PRNG fixed point used as the test's
"fixed" class — a known dudect methodology wrinkle (an all-zero secret is a valid but
extreme input, and some primitives behave atypically at that one point without implying a
leak across the realistic secret space).

**Disposition.** The rejection-sampling leak item 3 asked to close is closed: the dominant,
easily-measured 12%-magnitude structural leak from Batch 2 is gone, verified by both the
absolute-gap collapse and the interop re-test. The much smaller residual signal is recorded
here rather than hidden, but chasing it further requires cache/power-timing instrumentation
(e.g. hardware performance counters or a controlled non-degenerate "fixed" class) that is
out of scope for a wall-clock dudect harness, and `stern_apply_perm`'s separate
memory-access-pattern question (flagged in Batch 2) remains unaddressed for the same reason.
Both are left open for a future batch alongside the still-unaudited HKEX-RNL/ZKP-RNL/HCRED
functions that TODO #129's original item 2 scope covers but which no batch so far has
touched.

**Batch 4 — HKEX-RNL / ZKP-RNL / HCRED audited by inspection (v1.9.97).** Covers the
remaining item-2 scope: the Ring-LWR key-exchange and ZKP layers, and the HCRED hybrid
credential.

*Audited and clean.* `rnl_keygen`, `rnl_agree`, `rnl_hint`, `rnl_reconcile_bits`, and
`rnl_cbd_poly` (the CBD(eta=1) secret sampler) contain no branch on secret polynomial
coefficients — `rnl_cbd_poly` derives each coefficient from two fresh random bits via
arithmetic only (`(a - b + RNL_Q) % RNL_Q`), and `rnl_agree`'s only branch
(`hint_in == NULL`) selects the *public* reconciler-vs-receiver protocol role, not secret
data.

*Rejection sampling by design — not a new finding.* `rnl_sigma_sign` (the ZKP-RNL
Fiat-Shamir Σ-protocol prover) retries with a variable number of `attempt` iterations
(bounded by `SIGMA_MAX_ATTEMPTS`) until the response `z` falls inside the public rejection
bound — this is Lyubashevsky's Fiat-Shamir-with-aborts construction (2012), the same
abort-and-retry pattern used by the ML-DSA/Dilithium reference implementation, and it is
accepted practice in the lattice-signature literature: the masking value `y` is drawn fresh
per attempt and the accept/reject decision is designed so the *distribution* of accepted
transcripts is (statistically close to) independent of the secret `s`, which is the whole
point of the rejection step. The per-coefficient `do { } while` sampling `y[i]` uniformly in
`[-gamma, gamma]` draws from `/dev/urandom` only, with no dependence on `s`. Recorded here as
audited, not flagged as a leak to close, because "fewer/more Fiat-Shamir aborts" is the
scheme's designed behavior, not an implementation bug — matching how NIST's own ML-DSA
reference code is treated.

*Low-severity finding — `_hcred_witness`'s early-return on syndrome mismatch.*
`herradura.h:4278`, `if ((sr & 1) != syndr_bit) return -1;` inside the per-row syndrome
consistency loop, breaks out as soon as a row disagrees — a data-dependent (secret-witness
dependent) iteration count, structurally the same shape as the SA-08 `ba_equal` finding
this suite already fixed elsewhere. Unlike SA-08, though, `_hcred_witness` is called exactly
once, at the very start of `hcred_prove` (`herradura.h:4484`), directly on the *prover's own*
long-term-valid witness — never on attacker-supplied or externally-timeable input. In
honest operation the syndrome always matches (it is the prover's own consistent secret), so
the early-return path is an assertion against a corrupted local witness, not a check any
other party can trigger or observe the timing of across a trust boundary — there is no
remote or co-tenant oracle here the way there is for, say, `hpks_stern_f_verify`'s
commitment checks. Recorded as a low-severity finding rather than fixed in this batch: fixing
it (unconditional accumulation instead of early return) is low-cost and can be folded into a
future batch's cleanup pass, but it does not block closing #126's "production gap" note the
way the Stern-F permutation leak did.

**Cumulative status after Batch 4.** All eight core `hkex_`/`hske_`/`hpks_`/`hpke_` entry
points, the four core arithmetic primitives, WOTS-F/XMSS-F, and the HKEX-RNL/ZKP-RNL/HCRED
layer are now audited (clean, or — for `_hcred_witness` — a documented low-severity finding).
The Stern-F permutation's structural rejection-sampling leak is closed (Batch 3); the
residual hardware-level signal on `stern_gen_perm`/`stern_apply_perm` and the
memory-access-pattern question for `stern_apply_perm` remain open pending cache/power-timing
instrumentation, which is out of scope for a wall-clock harness. TODO #126's Stern-F
"production gap" note can be narrowed to that residual/cache-timing scope specifically.

**Batch 5 — CT-02: `_hcred_witness` early-return cleanup fixed (v1.9.98).** The two
secret-witness-dependent early returns flagged in Batch 4
(`if ((sr & 1) != syndr_bit) return -1;` and `if (v < 0 || v >= (1 << HCRED_EPS_BITS)) return
-2;`) are replaced with unconditional-iteration loops that accumulate `syndrome_ok`/
`range_ok` flags checked once after each loop completes, so both loops always run to their
full `HCRED_ROWS`/`HCRED_N` length regardless of the witness. The `v` used for the
bit-decomposition into `delta[]` is clamped into `[0, 2^HCRED_EPS_BITS)` when out of range so
the shift/store never goes out of bounds; the caller discards `delta[]` on a nonzero return
code, so the clamped bits are never used. `d = ms[i] - lift_c[i]`'s sign-reduction branch
(`if (d > hq) d -= q;`) is unchanged — it is a fixed-cost per-iteration select, not an
early-loop-exit, so it doesn't change the *iteration count*, only which of two O(1) paths one
iteration takes; left as a possible future micro-hardening item rather than folded into this
fix. Re-verified with `CliTest/test_cred.sh` (5/5) and the suite's `[44]`/`[45]` HCRED and
weak-key rejection tests (both `[PASS]`, including the `synd_reject`/`key_reject` paths that
exercise this exact function's error returns) — behavior is unchanged for all inputs, only
the timing profile of the rejection path changes.

**Cumulative status after Batch 5.** All eight core `hkex_`/`hske_`/`hpks_`/`hpke_` entry
points, the four core arithmetic primitives, WOTS-F/XMSS-F, HKEX-RNL/ZKP-RNL, and HCRED are
audited and either clean or fixed. Two items remain open, both requiring cache/power-timing
instrumentation rather than a code change: the residual hardware-level timing signal on
`stern_gen_perm`/`stern_apply_perm` (Batch 3) and `stern_apply_perm`'s
permutation-index-dependent memory-access pattern (Batch 2). TODO #126's Stern-F "production
gap" note narrows to exactly that scope.

**Batch 6 — CT-03: `stern_apply_perm` made memory-access-oblivious (v1.9.99).** Closes the
memory-access-pattern question Batch 2 flagged as out of a wall-clock harness's reach, with
a structural code fix rather than measurement. The old implementation touched every output
byte exactly once, at address `perm[i]`, for each input bit `i` — the *addresses*, and their
order, varied with the secret permutation. The new implementation instead scans every
candidate output position `j` in `[0, N)` for every input bit `i` and writes into it under a
constant-time `j == perm[i]` mask (`d = pi ^ j; iszero = ((d | (0 - d)) >> 31) ^ 1`, a
standard 8-bit-in-32-bit zero test), so the address sequence touched is always the full
`[0, KEYBYTES) x N` grid regardless of `perm[]` or `v` — fully oblivious, at the cost of
`O(N^2)` instead of `O(N)` masked writes (`<= 65536` at `N = KEYBITS = 256`, negligible next
to the surrounding Stern-F round cost — `test_stern_interop.sh` still exercises 9/9
signer/verifier pairs and `test_ring.sh` 21/21 OR-composed rounds with no observable slowdown
in the demo-parameter benchmarks). This is a pure implementation change: the byte-level
`out` value for any given `(perm, v)` is identical to before, so — unlike the `stern_gen_perm`
fix in Batch 3 — this did **not** need synchronized Go/Python changes for interop; verified
directly with `CliTest/test_stern_interop.sh` (9/9), `test_stern_kem.sh` (9/9), and
`test_ring.sh` (21/21), all unchanged.

**Re-measurement.** At 4000 rounds, `stern_apply_perm`'s own `|t|` (which calls
`stern_gen_perm` internally, so it always carries that residual too) converges onto
`stern_gen_perm`'s number rather than exceeding it: `16.75` vs. `stern_gen_perm`'s `16.65`
(previously `11.78` vs. `5.22` in Batch 3 — a visibly larger apply-specific gap). At 20 000
rounds the same pattern holds: `stern_apply_perm` `|t| = 24.76` against `stern_gen_perm`'s
own `|t| = 44.74` — `stern_apply_perm` no longer shows a *larger* signal than the function it
wraps, consistent with its own memory-access-pattern contribution having been eliminated and
only the inherited `stern_gen_perm` residual (Batch 3, attributed to hardware-level timing at
the degenerate all-zero test point) remaining.

**Status after Batch 6.** Of the two items left open after Batch 5, one — `stern_apply_perm`'s
memory-access-pattern leak — is now closed by a real code fix, confirmed by both the address
argument above and by the disappearance of its independent wall-clock signal. The other —
the hardware-level residual shared by `stern_gen_perm`/`stern_apply_perm` — remains open;
it is intrinsic to `stern_gen_perm`'s PRNG draws hitting a degenerate all-zero fixed point
under the dudect harness's "fixed" test class, not a control-flow or addressing bug, and
closing it further would need cache/power-timing instrumentation (hardware performance
counters, or a non-degenerate "fixed" class methodology) rather than another code change.
TODO #126's Stern-F "production gap" note narrows accordingly: constant-time C is now
addressed at the control-flow and memory-access level; what remains is a documented,
small-magnitude, hardware-attributed residual.

**Batch 7 — CT hypothesis test: is the residual specific to the all-zero test point?
(v1.9.105).** Batch 3/6 attributed the residual `stern_gen_perm`/`stern_apply_perm` signal
to the dudect harness's "fixed" class being the *degenerate all-zero* `pi_seed`, not to a
real secret-dependent code path — but that was an inference from indirect evidence (the
control-flow proof plus a comparison against unrelated multiply primitives), not a direct
test. This batch tests it directly: `SecurityProofsCode/dudect_timing_audit.c` gains a
second "fixed" class, a non-zero, non-degenerate constant bit pattern (`0xA5` repeating,
`10100101` — chosen to have no long runs of identical bits, unlike `0x00` or `0xFF`), run
against the same `setup_rand` random class used throughout this section.

| Function | Fixed secret | \|t\| (4000 rounds) | Verdict |
|---|---|---|---|
| `stern_gen_perm` | all-zero (`0x00`) | 16.11–16.27 | **residual signal** |
| `stern_apply_perm` | all-zero (`0x00`) | 16.04–16.26 | **residual signal** |
| `stern_gen_perm` | `0xA5` pattern | 1.44 | clean |
| `stern_apply_perm` | `0xA5` pattern | 3.54 | clean |

(All-zero rows re-measured in this batch on the same run for a same-session comparison;
consistent with the 5.22–16.65 range recorded in Batches 3 and 6 at this round count across
different runs/hardware.)

**Disposition.** This confirms the Batch 3/6 attribution directly rather than by inference:
swapping only the *value* of the fixed secret — same code path, same loop structure, same
call sequence — takes both functions from a clearly-suspected leak (`|t| > 16`, well past
the 4.5 threshold) to clean (`|t| < 4.5`) with nothing else changed. The residual is
therefore a property of the all-zero `pi_seed` specifically (most plausibly the all-zero
fixed point it drives `nl_fscx_v1_ba`'s internal PRNG state to, per the Batch 3 hardware
hypothesis — identical words on every "fixed" call vs. varying words on every "random"
call), not a secret-dependent control-flow or memory-access leak in `stern_gen_perm` or
`stern_apply_perm` as implemented: a real leak would reproduce at *any* fixed secret value,
not vanish when the fixed value is merely changed to something non-degenerate. TODO #126's
"production gap" note can treat this residual as characterized and low-priority: it is not
evidence of an addressable code-level constant-time bug, and the practical exposure was
already limited (`pi_seed` is ephemeral and revealed in 2 of 3 Stern response branches
regardless, per Batch 4's severity discussion). Cache/power-timing instrumentation to
further characterize the exact hardware mechanism remains out of scope for a wall-clock
dudect harness and is not required to close this item.

**Status after Batch 7.** No further code changes are needed for the items TODO #129
originally scoped (work items 1–4 are all satisfied: leakage tooling exists and was run
against every listed primitive plus the broader `hkex_`/`hske_`/`hpks_`/`hpke_`/`stern_`
surface; two real leaks (Batches 2, 4) were found, fixed (Batches 3, 5, 6), and
re-verified; the one remaining signal is now positively attributed to the dudect
methodology's degenerate test point rather than left as an open hardware guess). TODO #129
is closed as **DONE**, with the residual documented here as a permanent methodology note
for anyone re-running or extending this audit — future batches should prefer a
non-degenerate fixed class (e.g. this batch's `0xA5` pattern) over an all-zero one when
adding new dudect targets, to avoid re-discovering the same artifact.

**Reproduce:**
```bash
gcc -O2 -o /tmp/dudect_timing_audit SecurityProofsCode/dudect_timing_audit.c -lm
/tmp/dudect_timing_audit 4000          # or a larger round count for higher power
```

## 11.12 LLM-Assisted Cryptanalysis Stress-Testing Pass (TODO #159)

**Motivation.** TODO #159 records that LLM-driven cryptanalysis moved from a research
curiosity to a credible methodology in 2026 (Claude's HAWK finding leading to that
scheme's NIST-track withdrawal), distinct in kind from this repo's existing manual/
scripted `SecurityProofsCode/` proofs. This section documents the first bounded pass:
reading HPKS-Stern-Ring's OR-composition (herradura.h `stern_ring_sign`, the equivalent
Python/Go suite code) — chosen as one of the "less battle-tested" constructions per work
item 1 — against its own Fiat-Shamir soundness argument, looking for gaps the existing
manual review missed.

**Finding: modulo-3 bias breaks the signer-slot / non-signer-slot symmetry (now TODO
#164).** The C and Python non-signer challenge simulators each draw one random byte and
reduce mod 3 to choose $b \in \{0,1,2\}$ for every ring member other than the real
signer. Since $256 \not\equiv 0 \pmod 3$, this draw is biased: $\Pr[b=0] = 86/256 \approx
33.59\%$ versus $\Pr[b=1]=\Pr[b=2]=85/256\approx 33.20\%$. Crucially, the real signer's
own displayed challenge is *not* drawn this way at all — the OR-composition forces it as
$b_j = (\text{joint} - \sum_{i \neq j} b_i) \bmod 3$, where `joint` is the Fiat-Shamir
hash-derived challenge (effectively uniform, independent of the simulator's random
draws). A uniform value minus anything, reduced mod 3, is itself exactly uniform — so
the signer's own slot has **zero** skew round to round, while every non-signer's slot
carries the $\approx 0.39\%$ bias. This is not merely a "modulo bias" in the sense TODO
#2 already fixed elsewhere (which only mattered for the uniformity of a secret value);
here the asymmetry it creates between the signer's slot and every other slot is exactly
the kind of statistical distinguisher a ring signature's anonymity property is supposed
to rule out.

`SecurityProofsCode/stern_ring_challenge_bias.py` confirms the exact $86/85/85$-out-of-
$256$ distribution analytically and by $5{,}000{,}000$-trial Monte Carlo, and estimates
the attack cost: at 3-sigma confidence, distinguishing a non-signer's biased slot from
the signer's uniform slot requires on the order of $2.9 \times 10^5$ challenge draws for
residue $0$ alone; at `SDF_ROUNDS = 32` per signature, that is roughly **9,000+
signatures from the same ring**. This makes it a genuine but narrow anonymity concern:
it does not threaten a single signature or even a handful, but it is a real,
previously-undocumented leak for the long-lived/reused-ring use case (anonymous
credentials, whistleblowing channels) that ring signatures specifically target. Go's own
implementation is unaffected — it reduces a full 32-bit random value mod 3 (bias
$\approx 2^{-32}$, negligible) rather than a single byte, so this is a C/Python-specific
implementation gap, not a flaw in the OR-composition protocol design itself. The fix
(rejection sampling, mirroring TODO #2's `_rnl_rand_poly` pattern, or simply widening the
draw to match Go's approach) was tracked as TODO #164 rather than applied inline here,
per TODO #159's own instruction to treat findings as leads requiring the same
verification standard as any other TODO before being folded into a fix.

**Fixed (TODO #164, v1.9.127).** Both `herradura.h`'s `stern_ring_sign` and the Python
suite's `hpks_stern_ring_sign` now reject the single out-of-range byte value (255)
instead of reducing every byte mod 3 — the retained 255 values split exactly 85/85/85
across the three residues, eliminating the skew. Go and the Arduino ring-signature code
needed no change (already draw a wide 32-bit value, bias $\approx 2^{-32}$).
`CliTest/test_ring.sh` (21/21) and `CliTest/test_stern_interop.sh` (9/9) both re-verified
passing after the fix.

**Outcome for the remaining scope.** Work item 1 named three candidate targets; only
HPKS-Stern-Ring's OR-composition has been passed over so far. NL-FSCX v2's CSP-based
construction and the HFSCX-256-DM finalizer remain for a future pass — TODO #159 stays
open for those two. A hit rate of one real (if narrow) finding out of one target reviewed
is consistent with CryptanalysisBench's own observation that LLM cryptanalysis findings
are the exception rather than the rule; the point of this pass was to check whether the
technique surfaces anything at all against this suite's own constructions, and on this
first target, it did.

## 11.13 Physical Side-Channel (Power/EM) Risk Register (TODO #160)

**Scope.** §11.11 (TODO #129) covers *timing* side-channels only —
`dudect_timing_audit.c` measures wall-clock leakage, which is testable on any host. Power
and EM side-channels are a different physical-leakage channel entirely: they require
either real target hardware and an oscilloscope/ChipWhisperer-class capture setup, or a
cycle-accurate power simulator, neither of which this repo has. TODO #160 scopes what is
actually achievable without that hardware: (1) a literature-grounded risk register mapping
this suite's PQC operations to published power-analysis attacks against structurally
similar operations elsewhere, and (2) a static-analysis check for the one class of bug
that *would* be discoverable without physical measurement — secret-dependent branches or
table lookups that create an unmistakable power/EM signature — as a cheap first filter
before deciding whether a genuine hardware-in-the-loop side-channel effort is warranted.

**Published attacks reviewed (2025-2026 review window).**

| Attack | Target operation | Hardware/method | Result |
|---|---|---|---|
| CPA on ML-DSA [Azarderakhsh et al., HOST 2025, ieeexplore.org/document/11050056] | Modular reduction immediately following NTT-domain polynomial pointwise multiplication, in an industry-grade hardware root-of-trust (Caliptra) | Correlation power analysis against a specific reduction algorithm's leakage, aided by the register-zeroization step | First published side-channel break of an industry-grade (not academic-reference) PQC hardware implementation |
| SPA on HQC [Velek-Rabas-Buček, arXiv:2601.07634] | Polynomial multiplication at the start of HQC decryption | Single-trace simple power analysis, ChipWhisperer-Lite | 99.69% private-key recovery over 10,000 attempts |
| Single-trace attack on ML-KEM keygen ("Avengers assemble!", TCHES 2025) | CRYSTALS-Kyber/ML-KEM key generation (NTT-domain secret polynomial sampling/encoding) | Supervised learning + lattice reduction from one power trace | >96% average success rate across all three ML-KEM security levels |

**Mapping to this suite's operations (work item 1).** All three attacks target the same
structural pattern: an NTT-domain (or NTT-adjacent) arithmetic operation that processes a
*secret* polynomial coefficient-by-coefficient, where each coefficient's power/EM trace
leaks Hamming-weight or value information about the secret. HKEX-RNL's closest analogue is
`rnl_ntt`/`rnl_poly_mul` (`herradura.h`): `rnl_poly_mul` computes `ms = m_blind * s` and
`k_poly = s * c_lifted`, both NTT-domain products where `s` (or `s_out`) is the private
CBD($\eta=1$) secret — structurally the same shape as the attacked ML-KEM/HQC
polynomial-multiply step. HPKS/HPKE-Stern-F's closest analogue is the permutation/response
machinery (`stern_gen_perm`, `stern_apply_perm`, the `stern_ring_simulate`/`stern_sign`
response-selection branches) operating on the secret error vector `e`/`r` and permutation
seed `pi_seed`.

**Static-analysis check (work item 2, feasible-without-hardware scope) — no new pattern
found (work item 4 not triggered).** `rnl_ntt`/`rnl_poly_mul`'s control flow (loop bounds,
array indices, butterfly structure) depends only on the public size parameter `n` and
loop counters — never on a secret coefficient's value — so there is no secret-dependent
*branch* or *table-index* pattern to fix at the code level; the residual risk is purely
in the physical power/EM trace of otherwise data-independent arithmetic (each multiply-
accumulate's power draw still correlates with the operand's Hamming weight, which no
amount of branch removal changes). The Stern-F permutation/response code was already
carried through a dedicated constant-time pass under TODO #129 (§11.11, Batches 2-6):
`stern_gen_perm`'s rejection-sampling loop was made branchless with a fixed loop/PRNG-
advance count independent of `pi_seed`, and the `stern_sign`/`stern_ring_sign` response
branches (`if (bv == 0) ... else if (bv == 1) ... else ...`) switch on the Stern
*challenge* `b`, which is public (revealed as part of the signature/proof), not secret —
so branching on it leaks nothing. No clearly-analogous secret-dependent-branch bug was
found in either target; work item 4's conditional follow-up TODO is therefore not opened.

**Residual risk and what remains genuinely open.** The three published attacks all
required either real silicon or a ChipWhisperer-class capture rig running against an
actual implementation — none are reproducible as a pure code-review finding, and this
repo has no such hardware or simulator. The honest state of this risk is: HKEX-RNL's
`rnl_poly_mul` (and, if implemented at production Stern-F parameters some day, any
QC-MDPC polynomial arithmetic per TODO #91/#126) would need masking or blinding
countermeasures before deployment on any platform where power/EM measurement is a
realistic adversary capability (embedded/smart-card/IoT targets — less relevant for a
server-side KEX, more relevant for the Arduino/ARM targets this suite also ships). No
masking scheme is implemented in any language target today. This is recorded here as a
known-risk register entry rather than closed with a fix, consistent with work item 3's
instruction to document the risk even without implementing a countermeasure in this pass.

---

## 11.15 NIST SP 800-227 (September 2025) Audit of KEM Usage (TODO #161)

**Scope.** NIST finalized SP 800-227 ("Recommendations for Key-Encapsulation
Mechanisms") in September 2025, giving general implementation and usage guidance for any
KEM — independent of, and broader than, algorithm-specific standards like FIPS 203
(ML-KEM). This section walks HKEX-RNL (this suite's actual KEM), HKEX-GF (DH-based
analogue), and HPKE-Stern-F (Niederreiter-KEM-based analogue) against SP 800-227's
concrete recommendations, extracted directly from the published PDF
(nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf) rather than a summary.
This repo already has narrower items in the same space — TODO #141 (CLI degenerate-key
rejection) and TODO #144 (Go/Python library-level weak-key rejection) — both of which this
audit's checklist item on input validation folds into rather than duplicates.

**Checklist extracted from SP 800-227 §3–§4, with this suite's status against each.**

| # | SP 800-227 requirement | Section | This suite's status |
|---|---|---|---|
| 1 | Approved cryptographic elements: RBGs per SP 800-90A/B/C; hash functions of adequate strength | §3.1 | **Out of scope by design.** This is a research suite using custom, non-NIST-approved primitives (FSCX/NL-FSCX, HFSCX-256) throughout — not a FIPS-140/CAVP-validated module, and not claiming to be one. RNG source itself is sound in practice: Python uses `os.urandom` (OS CSPRNG), C/Go read `/dev/urandom` directly — acceptable entropy quality even though not a "SP 800-90-approved" DRBG in the formal validation sense. |
| 2 | Input checking on KeyGen/Encaps/Decaps; reject invalid/degenerate keys | §3.2 | **Covered by TODO #131/#141/#144** (degenerate/identity public-key rejection in `herradura.h`, the C CLI, and the Go/Python suite libraries). No new gap found beyond what those items already close. |
| 3 | Destroy intermediate values (seeds, private randomness) as soon as unneeded | §3.2 | **Partial, language-dependent.** C explicitly reads directly from `/dev/urandom` per-use with no long-lived buffers to zero. Python and Go rely on garbage collection for `int`/big-number secrets — neither language offers a real zeroization guarantee (a known, generic limitation of managed-runtime crypto code, not specific to this suite). Not filing a new TODO: no practical fix exists in pure Python/Go without a C extension, and this matches the honest, already-documented tradeoff of implementing crypto in managed languages. |
| 4 | Data at rest: private keys stored securely against leakage/modification | §3.2 | **Gap found and closed (opt-in).** Exported private-key PEM files were always written in cleartext with no passphrase-based encryption option. Filed and resolved as **TODO #166** (§11.18): a new opt-in `genpkey --passphrase`/`pkey --decrypt` pair, without changing the existing default cleartext behavior. |
| 5 | Failures/aborts must not leak information about the cause outside the module | §3.3 | **Verified sound.** Checked the CLI's decrypt/AEAD-tag-mismatch paths (`HerraduraCli/herradura.py` `dec`/`decfile`): both use a single uniform `"authentication tag mismatch — file corrupt or wrong key"` message regardless of which specific check failed, rather than distinguishing sub-causes — the correct behavior per this requirement. HPKE-Stern-F has no adversarial-ciphertext decapsulation-failure path to audit yet, since its decoder is demo-only (known-`e'`, no real QC-MDPC decoder) — this is already tracked under TODO #91/#126, not a new finding. |
| 6 | Side-channel protection (timing, memory leakage) | §3.3 | **Already tracked**: TODO #129 (timing, `dudect`) and TODO #160 (power/EM risk register). No new finding here. |
| 7 | Key derivation via an approved KDM (SP 800-56C one-step/two-step); `OtherInput`/`FixedInfo` should include a domain separator, and combiners should bind ciphertexts/encapsulation keys/party identities | §4.5–§4.6 | **Gap found and closed (opt-in).** HKEX-RNL's default contributory KDF binds per-session nonces but not the public transcript. Filed and resolved as **TODO #165**: a new opt-in `--kdf sp800227` mode (§11.17) binds the full transcript ($C_A$, $m_A$, $C_B$, hint) per SP 800-227's example combiner shape, without changing the existing default's wire format. |
| 8 | Composite/hybrid KEM key combiners should generically preserve IND-CCA if at least one component is IND-CCA (naive `KDF(K1,K2)` does **not** suffice per Giacon et al., cited in §4.6.3) | §4.6.2–§4.6.3 | **Directly relevant to TODO #162** (the hybrid HKEX+Stern-F combiner item next in the backlog) rather than this suite's current single-KEM constructions — cross-referenced there so #162's design work starts from SP 800-227's own recommended combiner shape (`H(K1, K2, c1, c2, ek1, ek2, domain_sep)`) instead of the naive concatenation form the standard explicitly warns against. |

**Outcome.** Two genuine, previously-undocumented gaps were found and filed as their own
follow-up items per this item's own instruction not to fix inline: **TODO #165** (KDF
context binding) and **TODO #166** (private-key-at-rest encryption). Everything else
checked either already has dedicated tracking (TODO #91/#126/#129/#141/#144/#160/#162) or
is an explicit, reasonable non-goal for a research suite that has never claimed FIPS-140
validation.

---

## 11.16 Hybrid HKEX-RNL + HPKE-Stern-KEM Combiner (TODO #162)

**Motivation.** "Hybrid-by-default" — running a lattice-based and a code-based PQC
algorithm in parallel so an attacker must break both — is now the mainstream
post-quantum deployment pattern, matching NIST's own March 2025 rationale for
selecting HQC alongside ML-KEM to diversify away from a single PQC assumption family.
This is distinct from TODO #123/#128's hybrid **Ring-LWR + Stern-F credential** (a
compound ZKP/proof construction for anonymous credentials): this item combines
**HKEX-RNL** (lattice-based key exchange) with **HPKE-Stern-KEM** (the QC-MDPC/Niederreiter
KEM from TODO #126) as two independent KEMs feeding one combined session key, exposed
as `kex --algo hybrid-rnl-stern` in the Python CLI.

**Combiner construction.** TODO #161's SP 800-227 audit (§11.15, item 7/8) found that a
naive `KDF(K1, K2)` combiner does **not** generically preserve IND-CCA security if only
one component KEM is IND-CCA (Giacon et al., cited in SP 800-227 §4.6.2) — the combiner
must bind the shared secrets to the full public transcript. This construction follows
SP 800-227's own worked example shape directly:

$$K = \mathrm{HFSCX\text{-}256\text{-}DS}\bigl(0x05,\ K_1 \| K_2 \| C_A \| m_A \| C_B \| \mathrm{hint} \| h_{\mathrm{pub}} \| \mathrm{syn} \| \texttt{"HERRADURA-HYBRID-RNL-STERN-v1"}\bigr)$$

where $K_1$ is HKEX-RNL's own fully-processed session key (including its existing
contributory-KDF step, §11.4 — reused unmodified, not just the raw DH-style output),
$K_2$ is HPKE-Stern-KEM's shared secret from `qcmdpc_encap`/`qcmdpc_decap_bgf`, $(C_A,
m_A)$ is Alice's HKEX-RNL public transcript, $C_B$/$\mathrm{hint}$ is Bob's HKEX-RNL
response, and $(h_{\mathrm{pub}}, \mathrm{syn})$ are the KEM's public key and
ciphertext. The `0x05` tag is a new `HFSCX-256-DS` domain-separation value (§11.9.7),
distinguishing this combiner from every other suite call site that reuses the same
underlying hash. Binding every public transcript element (not just $K_1, K_2$) is what
gives the IND-CCA-preservation property SP 800-227 requires: an adversary who breaks one
component KEM still cannot forge a consistent combined key without also controlling the
corresponding transcript element, which the honest protocol run fixes independently for
each party.

**Protocol shape.** Alice holds *two* persistent keypairs — an existing HKEX-RNL keypair
and an existing HPKE-Stern-KEM keypair (both from their own unmodified `genpkey`); no new
key-generation algorithm or PEM key format was introduced. Bob is ephemeral per session
(a fresh HKEX-RNL keypair, matching HKEX-RNL's own existing two-round pattern):

1. **Bob** (`--our` = his HKEX-RNL private key, `--their` = Alice's HKEX-RNL public key,
   `--their-kem` = Alice's HPKE-Stern-KEM public key): computes $K_1$ exactly as plain
   `hkex-rnl` would, encapsulates against Alice's KEM public key to get $(K_2,
   \mathrm{syn})$, combines, and writes a new `HYBRID-RNL-STERN RESPONSE` PEM containing
   the combined session key (for his own local use, mirroring the existing
   `HKEX-RNL RESPONSE` convention) plus the public transcript ($C_B$, hint, $\mathrm{syn}$)
   Alice needs.
2. **Alice** (`--our` = her HKEX-RNL private key, `--our-kem` = her HPKE-Stern-KEM
   private key, `--their` = Bob's response): completes $K_1$ exactly as plain `hkex-rnl`
   would, decapsulates $\mathrm{syn}$ with her KEM private key to recover $K_2$
   (recomputing $h_{\mathrm{pub}} = h_1 \cdot h_0^{-1}$ from her stored private key
   fields, matching `qcmdpc_keygen`'s own derivation — no separate own-pubkey file
   needed), and combines identically.

A KEM decapsulation failure (corrupt ciphertext or, in principle, a genuine QC-MDPC
decoding-failure-rate event, §11.8.4) used to be rejected with a clean, distinct error.
As of TODO #235 it is deliberately *not*: that error was the GJS reaction oracle
(§11.8.7), so decapsulation now applies implicit rejection and silently produces a
divergent key instead. `CliTest/test_hybrid_kex.sh` verifies the inverted property — a
wrong KEM private key completes without complaint and yields a session key that does not
agree — alongside the missing-flag misuse cases, whose clean rejection is unaffected.

**Security argument.** The combined scheme is secure if *either* HKEX-RNL or
HPKE-Stern-KEM is secure, by the combiner construction above (SP 800-227 §4.6.2-style
argument, modeling HFSCX-256 as a random oracle — the same modeling assumption this
suite's other HFSCX-256-based reductions already use, e.g. Theorem 17). This gives the
intended "diversify away from a single PQC assumption family" property: a break of
Ring-LWR does not compromise sessions as long as syndrome decoding remains hard, and vice
versa. HPKE-Stern-KEM's own concrete security still tracks TODO #126's QC-MDPC parameters
(BIKE-derived $r=12323$, $w=142$, $t=134$ for 128-bit classical security) — the combiner
adds diversity of assumption, not additional margin on either individual component.

**Implementation status.** Implemented in all three CLI targets: Python
(`HerraduraCli/herradura.py`, TODO #162) and, per TODO #167, Go (`herradura_cli.go`) and
C (`herradura_cli.c`/`herradura_codec.h`), with bit-for-bit identical serialization
across all three. Verified with `CliTest/test_hybrid_kex.sh` (Python-only combiner
behavior, 6/6 passing) and `CliTest/test_hybrid_kex_interop.sh` (full 3x3 cross-language
matrix — every Bob/Alice language pairing derives a byte-identical session key), with no
regressions in `test_vectors.sh`/`test_keygen.sh`/`test_stern_kem.sh`.

---

## 11.17 SP 800-227-Style Context Binding for Plain HKEX-RNL (TODO #165)

**Gap addressed.** TODO #161's SP 800-227 audit (§11.15, item 7) found that HKEX-RNL's
existing contributory KDF (`_rnl_contributory_kdf` = `HFSCX-256(K_raw \| n_A \| n_B)`,
used by every plain `kex --algo hkex-rnl` session) binds the raw shared secret to both
parties' per-session *nonces*, but not to the public *transcript* — the exchanged
polynomials $C_A$, $m_A$, $C_B$, and reconciliation hint. SP 800-227 §4.5–§4.6
recommends binding the KDF's `OtherInput` to the ciphertext/encapsulation-key material
as well as a domain separator.

**Construction.** A new opt-in `--kdf sp800227` mode (Python CLI, alongside the existing
`none`/`hfscx-256` choices):

$$K' = \mathrm{HFSCX\text{-}256\text{-}DS}\bigl(0x06,\ K \| C_A \| m_A \| C_B \| \mathrm{hint} \| \texttt{"HERRADURA-HKEX-RNL-SP800227-v1"}\bigr)$$

applied after the existing contributory KDF, using the same `HFSCX-256-DS` domain-tag
mechanism as TODO #162's hybrid combiner (§11.16) — tag `0x06`, distinct from the
hybrid combiner's `0x05`. Both parties can independently reconstruct the identical
$(C_A, m_A, C_B, \mathrm{hint})$ transcript before applying it: Bob has $C_A$/$m_A$ from
Alice's public key and computes $C_B$/hint himself; Alice has $C_B$/hint from Bob's
response and recomputes $C_A$ from her own private key via `_rnl_derive_C` (the same
technique used in §11.16's hybrid combiner).

**Design choice: opt-in, not a default-behavior change.** Rather than modifying
`_rnl_contributory_kdf` itself (which would silently break wire-compatibility with every
existing HKEX-RNL session and interop test), this is exposed as an explicit `--kdf`
choice both parties must agree to use — matching the CLI's existing pattern for optional
post-processing (`--kdf hfscx-256` already existed as an opt-in plain re-hash). `--kdf
sp800227` is rejected cleanly on `--algo hkex-gf`, where it isn't defined.

**Verification.** `CliTest/test_rnl_sp800227_kdf.sh` (4/4 pass): Alice and Bob derive
the same session key when both opt into `--kdf sp800227` (verified via cross-party
encrypt/decrypt round-trips in both directions); mismatched `--kdf` flags between the
two parties produce genuinely different keys rather than silently agreeing (confirming
this isn't a no-op); and `--kdf sp800227` is rejected on `hkex-gf`. No regressions in
`test_vectors.sh`/`test_hybrid_kex.sh`.

**Scope.** Implemented in the Python CLI only, matching TODO #162's own Python-first
precedent (TODO #25). `herradura.h`'s `ba_rnl_kdf_seed`/`_RNL_KDF_DC` (used by HSKE-NL-A1/
AEAD and HPAKE, not plain HKEX-RNL's own session-key derivation) is a separate, lower-level
helper and was not in scope for this item — the actual target was `_rnl_contributory_kdf`
in `herradura.h`/`Herradura cryptographic suite.py`/`herradura/herradura.go`, all of which
still use the unmodified (nonce-only) contributory KDF as their default; `--kdf sp800227`
exists in Python only, tracked as a Go/C follow-up if this construction is adopted more
broadly.

---

## 11.18 Passphrase-Encrypted Private-Key PEM Export (TODO #166)

**Gap addressed.** TODO #161's SP 800-227 audit (§11.15, item 4) found that all three
CLIs wrote exported private-key PEM files in cleartext only, with no passphrase-based
encryption option — unlike OpenSSL's `-aes256`/PKCS#8-encrypted-key convention. SP
800-227 §3.2 requires private data at rest to be "secure against both leakage and
unauthorized modification."

**Construction.** `genpkey --algo X --passphrase PASS [--out priv.pem]` wraps the
*entire* generated cleartext PEM (any algorithm, unmodified) as opaque bytes inside a
new `HERRADURA ENCRYPTED PRIVATE KEY` envelope:

1. **Key derivation:** $K = \mathrm{PBKDF2}\text{-}\mathrm{HMAC}\text{-}\mathrm{HFSCX}\text{-}256(\mathrm{password}, \mathrm{salt}, \mathrm{iterations})$ — PBKDF2's standard iterated-PRF structure (RFC 8018), substituting this suite's own already-implemented `HMAC-HFSCX-256-DM` (§11.9.6) for HMAC-SHA256. Chosen over inventing a bespoke password-hashing scheme (the other option work item 1 considered) specifically *because* PBKDF2's construction is well-studied — only the underlying PRF is suite-native, keeping the suite free of external dependencies while avoiding an unreviewed novel KDF shape. An arbitrary-length password is first hashed to a fixed 32 bytes via plain `HFSCX-256` before use as the HMAC key, matching standard HMAC over-length-key handling.
2. **Encryption:** the resulting 256-bit $K$ encrypts the cleartext PEM's UTF-8 bytes using the already-implemented, already-tested `HSKE-NL-AEAD` construction (§11.3.1) — a fresh random nonce, key-committing authentication tag, verify-then-decrypt.
3. **Envelope:** `DER-SEQUENCE(salt, iterations, nonce, ciphertext, tag, plaintext_length)`, wrapped under the new PEM label.

**Fail-closed by construction.** The new label doesn't match any existing
`_PRIV_ALGOS` entry, so any code path that reads a private-key PEM and doesn't
explicitly handle `HERRADURA ENCRYPTED PRIVATE KEY` raises immediately — `_decode_privkey`
gives a specific, actionable error naming `pkey --decrypt` rather than misinterpreting
the encrypted bytes as key material or crashing obscurely. A wrong passphrase is
rejected by the AEAD tag check (`_decrypt_pem` raises `ValueError`, never returns
partial or garbage plaintext).

**Iteration count: demo default vs. production guidance.** NIST SP 800-132 recommends
$\geq 200{,}000$ PBKDF2 iterations as of 2026. A pure-Python `HMAC-HFSCX-256` call runs
at only $\approx 300$/sec, so 200,000 iterations would take roughly 10-12 minutes per
`genpkey`/`decrypt` invocation — impractical as a CLI default. Following this repo's
established demo-vs-production-parameter convention (Stern-F: 32 demo / 219 production
rounds; ZKP-NL: 4 demo / 219 production rounds), the default is `--kdf-iterations 1000`
(~3.5 s), with the flag exposed so a caller can opt into the SP 800-132 floor (or
higher) at the cost of a multi-minute wait. This is an explicit, documented tradeoff
specific to the pure-Python reference implementation, not a claim that 1000 iterations
is adequate for production key storage.

**Since this only recovers the byte-for-byte original PEM, it composes with everything
else.** `pkey --decrypt --in enc.pem --passphrase PASS --out plain.pem` recovers the
exact original cleartext PEM regardless of which algorithm it holds; the result can be
piped into any other existing subcommand (`kex`, `sign`, `enc`/`dec`, `pkey --pubout`,
etc.) completely unmodified — no other command needed passphrase-awareness wired in.

**Verification.** `CliTest/test_encrypted_pem.sh` (7/7 pass): distinct PEM label,
clean rejection of direct (non-decrypted) use with an actionable error message,
correct-passphrase round-trip recovering the exact original label/content, the
recovered key working normally with `pkey --pubout`, wrong-passphrase rejection, a
larger-key (`hkex-rnl`) round-trip, and confirmation that omitting `--passphrase`
leaves the existing cleartext default entirely unchanged. No regressions in
`test_keygen.sh`.

**Scope.** Implemented in the Python CLI only, matching this session's established
Python-first precedent (TODO #25, #162, #165). The Go and C CLIs still only support
cleartext private-key export; porting this construction to them is future work if
adopted, not filed as a separate TODO given this item's own "Low" priority.

---

## 11.19 Carry-Degeneracy Pass over NL-FSCX v1/v2 Constructions (TODO #159)

TODO #159's second stress-testing pass covered the two targets its work item 1 named but
the first pass did not reach: HFSCX-256-DM's compression and NL-FSCX v2's CSP
construction.  Both NL-FSCX variants buy their non-linearity from exactly one place — the
carry chain of a modular addition; the FSCX map $M = I \oplus \mathrm{ROL} \oplus
\mathrm{ROR}$, the rotations and the XORs are all GF(2)-linear.  That suggests one
question to ask of each construction: **for which inputs does the addition stop producing
carries?**  Wherever the answer is a non-negligible set, the round function collapses to
an affine map.  Reproduced by
`SecurityProofsCode/nl_fscx_carry_degeneracy_2026.py`.

### 11.19.1 HFSCX-256-DM under an all-zero message block — clean, but load-bearing

With $B = 0$ the sum $A + 0$ produces no carries, so the Davies-Meyer inner function
degenerates to the GF(2)-linear map $L^{n/4}$ with

$$L = 1 + X + X^{n/4} + X^{n-1} \text{ over } \mathrm{GF}(2)[X]/(X^n + 1)$$

Its rank is exactly $n/2$ at every size tested — so at the deployed $n = 256$ the inner
"block cipher" crushes the 256-bit chaining value onto a $2^{128}$ subspace, a
$2^{128}$-to-1 compression:

| $n$ | 16 | 32 | 64 | 128 | 256 |
|---|---|---|---|---|---|
| rank $F(\cdot, 0)$ | 8 | 16 | 32 | 64 | 128 |
| rank $C_{\text{DM}}(\cdot, 0)$ | 16 | 32 | 64 | 128 | 256 |

Collision resistance survives only because the Davies-Meyer feed-forward makes the
compression $C_{\text{DM}}(s, 0) = L^{n/4}(s) \oplus s$, and **that** map is invertible.
Proof: over GF(2), $X^n + 1 = (X+1)^n$, so writing $Y = X + 1$ the quotient ring is local
with maximal ideal $(Y)$.  Expanding, $L = Y^2 u$ for a unit $u$; hence $L^{n/4} =
Y^{n/2} u^{n/4}$, and $L^{n/4} + 1$ has constant term $1$ — a unit in a local ring, and
therefore invertible.  The table above confirms full rank $n$ at every deployed size, and
a brute-force check at $n=16$ finds $|\text{image } F(\cdot,0)| = 256$ against
$|\text{image } C_{\text{DM}}(\cdot,0)| = 65536$.

§11.9.8 already credits Davies-Meyer with ruling out "a structural speed-up from the
non-bijectivity of $F_1$" in general terms.  This sharpens that to a concrete, verified
statement: for the all-zero block the underlying keyed map is not merely non-bijective but
*linear with a kernel of dimension $n/2$*, and the feed-forward is precisely what
prevents cheap zero-block collisions.  **No weakness — but the feed-forward is
load-bearing, and removing it would be catastrophic rather than merely unproven.**

### 11.19.2 NL-FSCX v2 — an affine weak-key class (TODO #168)

NL-FSCX v2's offset $\delta(K)$ enters as an additive **constant**:
$\pi_K(A) = (M(A \oplus K) + \delta(K)) \bmod 2^n$.  Addition of a constant $c$ is
GF(2)-affine for *every* input exactly when $c \in \{0, 2^{n-1}\}$ — for $c = 0$
trivially, and for $c = 2^{n-1}$ because the top carry is discarded mod $2^n$, making the
addition pure XOR.  Since $M$ is invertible at every power-of-two $n$, $M(A \oplus K)$ is
a bijection, giving the exact characterisation

$$\pi_K \text{ is GF(2)-affine} \iff \delta(K) \in \lbrace 0, 2^{n-1} \rbrace$$

verified exhaustively at $n = 8$ and $n = 16$.  (At $n = 12$ the characterisation differs
because $M$ is singular there, rank $10/12$ — but $n=12$ is outside the design regime;
every deployed size is a power of two.)

Such keys exist at the deployed size.  Since $\delta(K) = \mathrm{ROL}(K \lfloor (K+1)/2
\rfloor \bmod 2^n, n/4)$, any even $K = 2^j K'$ with $K'$ odd gives $K \lfloor (K+1)/2
\rfloor = 2^{2j-1} K'^2$, so $\delta(K) = 0$ whenever $2j - 1 \geq n$ — i.e. for **every
$K$ divisible by $2^{129}$** at $n = 256$, a class of $2^{127}$ keys.  Separately
$K = 2^{96}$ gives $\delta(K) = 2^{255}$.  For any such key HSKE-NL-A2 and HPKE-NL
degenerate to an affine map, recoverable in full from a handful of known plaintexts by
linear algebra alone — the script demonstrates this at $n = 16$, predicting 500/500
random inputs from $16$ basis images plus a constant.

**Severity.** The class density is about $2^{-129}$ at $n = 256$, so a uniformly random
256-bit key is not at risk and this is **not** a break of the deployed construction.  It
is a genuine weak-key class that matters if keys are ever structured, low-entropy, or
attacker-influenced, and costs one line to reject.

**Density scales with word size.**  The $\delta = 0$ class is every $K$ divisible by
$2^{\lceil (n+1)/2 \rceil}$, giving density $2^{-\lceil (n+2)/2 \rceil}$.  The second class,
$\delta = 2^{n-1}$, is non-empty exactly when $8 \mid n$ and is smaller but not always
negligible.  Exhaustive counts over the full key space at $n \leq 32$:

| $n$ | 16 | 20 | 24 | 28 | 32 | 256 |
|---|---|---|---|---|---|---|
| $\delta = 0$ keys | $128$ | $512$ | $2048$ | $8192$ | $32768$ | $2^{127}$ |
| $\delta = 2^{n-1}$ keys | $128$ | $0$ | $1024$ | $0$ | $8192$ | $\approx 2^{97}$ |
| total affine keys | $256$ | $512$ | $3072$ | $8192$ | $40960$ | $\approx 2^{127}$ |
| affine density | $2^{-8.0}$ | $2^{-11.0}$ | $2^{-12.4}$ | $2^{-15.0}$ | $2^{-16.7}$ | $\approx 2^{-129}$ |

At $n = 256$ the $\delta = 0$ class dominates ($2^{127}$ against $\approx 2^{97}$), so the
deployed density is $\approx 2^{-129}$ either way.  At small $n$ the two classes are
comparable and the total is what matters.

This matters for the assembly and Arduino targets, which implement NL-FSCX v2 and
HSKE-NL-A2 on **32-bit** operands: there the affine density is $2^{-16.7}$ — roughly 1 key
in $105{,}000$, far more reachable than the deployed 256-bit case.  Those targets are
explicitly demo-only (§11.8.4 records the same $N=32$ toy scoping for Stern-F), which is
why porting the guard was tracked separately as **TODO #169** rather than attempted blind
under TODO #168 — the development host had no ARM cross-toolchain to build or test it
against at the time.

**Resolved (TODO #168, v1.9.140).**  A `nl_v2_key_is_valid` predicate is now exported by
all three suites (Python, `herradura.h`, Go), following the repo's existing
`gf_pub_is_valid` precedent: the predicate is enforced at the **protocol** layer, not
inside the primitive.  That placement is deliberate — `nl_fscx_v2` is also invoked
internally by the FPE, tweakable wide-block, and duplex-sponge constructions with
hash-derived keys, and the suite's own non-linearity tests call it with degenerate
operands, so a primitive-level rejection would change a total function's contract across
three languages for a $2^{-129}$ event.  All three CLIs reject an affine key on
`enc`/`dec --algo hske-nla2` and on `dec --algo hpke-nl`; `enc --algo hpke-nl` instead
resamples its own ephemeral $r$, since that value is the sender's to choose and failing an
honest encryption would be the wrong behaviour.  Test `[45]` covers the class in all three
languages.

Note this is a strictly stronger statement than §11.8.5's existing $\delta$-injectivity
measurement, which records that $\delta$ collides but does not identify the $\delta = 0$
preimage as a class on which the construction's entire claimed non-linearity vanishes.

**Resolved (TODO #169, v1.9.144).**  The ARM cross-toolchain (`arm-linux-gnueabi-gcc`,
`qemu-arm`) was confirmed present on the development host, unblocking the port left open
above.  A `nl_v2_key_is_valid` predicate matching `herradura.h`'s semantics exactly
(returns invalid iff $\delta(K) \in \lbrace 0, 2^{31} \rbrace$ at $n = 32$) is now defined
in `Herradura cryptographic suite.s`, `.asm`, and `.ino`, and duplicated in the
corresponding `CryptosuiteTests/Herradura_tests.{s,asm,ino}` files, which have no shared
header to import it from. Since these targets have no CLI — the enforcement boundary used
by Python/C/Go — the predicate is a plain return-code function, uncalled from the
`nl_fscx_v2`/`nl_fscx_revolve_v2` hot path, consistent with the reference suites (which
likewise only invoke the guard from their CLI's `genpkey`, never from inside the
primitive). It is exercised by a new test `[18]` (`v2_weak_key_reject`) in all three test
harnesses, checking that $K = 2^{17}$ (which has $\delta = 0$ at $n = 32$, per the
$2^{\lceil (n+1)/2 \rceil}$ divisibility rule above) is rejected while an ordinary key is
accepted — verified passing under `qemu-arm`, `qemu-i386`, and `simavr` alongside the
existing tests `[1]`–`[17]`.


## 11.20 Exact Differential Trail Bounds for NL-FSCX v1/v2 (TODO #214)

Both NL-FSCX variants carry exactly one modular addition per round, which puts them
in the ARX family where exact tools replace sampling.  Coverage before this item
(`nl_fscx_rot_analysis.py`, `nl_fscx_rx_exact_search.py`,
`nl_fscx_rx_differential_2025.py`, `nl_fscx_prf_analysis.py`) was sampling and
small-width exhaustive search; this section reports proven bounds.  It is backed by
`SecurityProofsCode/nl_fscx_exact_trail_search.py`, which validates its xdp+ model
exhaustively before using it and pins its round functions against the deployed suite.

### 11.20.1 Both variants reduce to the same core

Writing `M` for the linear FSCX map, so that `fscx(A,B) = M(A xor B)`:

- **v1**: `Y = M(A xor B) xor ROL((A + B) mod 2^n, n/4)`.  A difference `alpha` in `A`
  with none in `B` contributes `M(alpha)` through the linear part exactly, and the
  addition contributes an xdp+ difference: `dY = M(alpha) xor ROL(delta, n/4)` where
  `delta` follows `xdp+(alpha, 0 -> .)`.
- **v2**: `Y = M(A xor B) + delta(B) mod 2^n`.  Since `delta(B)` depends only on the
  key it is a constant offset, and adding a constant to two values differing by
  `M(alpha)` gives `dY ~ xdp+(M(alpha), 0 -> .)`.

So the variants differ only in where `M` sits relative to the addition — v1 mixes
`M(alpha)` back in by XOR *after* it, v2 feeds `M(alpha)` *into* it.  Both are covered
by one model, verified at 6 000 random (difference, key, input) triples with zero
mismatches.

**A consequence worth stating separately:** in v2 the rotation `n/4` is applied to
`delta(B)`, a per-key constant, so it never enters the differential at all.  Rotation
tuning is a v1-only lever.  §11.20.3's table confirms this — every rotation amount
yields identical v2 trail weight.

### 11.20.2 Proven trail weights

Weight is minus the base-2 log of the trail probability.  The search asks "is there a
trail of weight at most `w`?" for increasing `w` rather than minimising directly, so
each UNSAT is a proven lower bound and a search that exhausts its budget still leaves
a usable statement.  Widths are powers of two, matching the deployed `n = 256`: `M` is
invertible exactly when `x^2 + x + 1` does not divide `x^n + 1`, which holds for every
power of two and fails at `n = 24` (measured rank 22), where v2 is not even a
bijection — the same trap TODO #215 hit at `n = 12`.

| rounds | v1 n=8 | v1 n=16 | v1 n=32 | v2 n=8 | v2 n=16 | v2 n=32 |
|---|---|---|---|---|---|---|
| 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| 2 | 2 | 3 | 3 | 2 | 2 | 2 |
| 3 | 4 | 6 | 6 | 4 | 4 | 4 |
| 4 | 6 | 12 | >= 10 | 7 | 7 | 7 |

**v2 is the differentially weaker variant, and its weight does not improve with
width.**  At four rounds v2 sits at weight 7 for every width tested while v1 reaches
12 at `n = 16`.  Structurally this follows from §11.20.1: v2 sets the next state
difference to the addition output directly, so a light trail persists, whereas v1's
XOR of `M(alpha)` forces additional diffusion each round.  This matters because v2 is
the variant deployed for HSKE-NL-A2 and HPKE-NL, chosen for bijectivity and a
closed-form inverse — properties orthogonal to differential strength.

The one-round weight of 0 in both variants is the familiar MSB-difference transition,
which passes an addition with probability 1.

### 11.20.3 The rotation amount

At `n = 16` over three rounds, v1 trail weight by rotation: 2 at rotation 1, 4 at 2,
**6 at 4 (the deployed n/4)**, 6 at 5, 6 at 6, 5 at 8, 2 at 15.  The deployed choice
sits at the optimum, tied with 5 and 6.  v2 gives weight 4 at every rotation, as
§11.20.1 predicts.

No parameter change is recommended.  The table is computed at one small width and
round count, the ordering is not guaranteed to survive to `n = 256`, and changing the
rotation would break the wire format for every stored ciphertext and signature.

### 11.20.4 The bounds are key-averaged, and NL-FSCX has no key schedule

This is the finding that most limits everything above.

xdp+ averages over *both* operands of the addition.  Standard ARX trail analysis then
multiplies per-round probabilities, justified by the Markov-cipher assumption of
independent, uniformly random round keys.  NL-FSCX has no key schedule at all:
`nl_fscx_revolve_v1(A, B, steps)` and its v2 counterpart hold the same `B` constant in
every round, so the hypothesis licensing that multiplication does not hold.

Measured at `n = 8` over all 256 keys and 24 input differences each, comparing true
fixed-key differential probability against key-averaged xdp+: the median key has some
differential running **32x** its xdp+ value (max 128x), and **all 256 of 256 keys**
have some differential at least 8x above it.  A large gap for a single addition is
ordinary and is precisely why the Markov assumption exists.  What is not ordinary is
that the same `B` is reused in all 64 deployed rounds, so per-round deviations
correlate rather than averaging out across a schedule.

The weights in §11.20.2 are therefore a key-averaged design-comparison quantity — the
standard currency of ARX trail analysis, and the right basis for the rotation table
and the v1-vs-v2 comparison.  They are **not** a per-key security guarantee, and no
additional solver time would make them one.

### 11.20.5 Cross-checks and scope

The carry-degenerate key class of §11.19.2 appears in the trail model exactly as
predicted: for keys with `delta(B)` in `{0, 2^(n-1)}` the addition cannot generate a
crossing carry, every differential becomes deterministic, and the round contributes
zero weight.  All sampled affine-class keys at `n = 8` and `n = 16` are
difference-transparent.  `nl_v2_key_is_valid` already rejects them, so this is a
cross-check that passes rather than a new finding.

What this section does **not** establish:

- **No bound at `n = 256`.**  The search does not scale there.  Projecting the measured
  slopes (v1 about 2.2 bits per round, v2 about 1.9) would put 64 deployed rounds near
  `2^-141` and `2^-119` respectively, but the slopes are read off widths 8-32, each
  width closed at a different round count, and per-round weight is not constant in the
  round index — v1 at `n = 16` jumps from 6 at three rounds to 12 at four.  This is an
  order-of-magnitude indication, not a bound.
- **No per-key guarantee**, for the reason in §11.20.4.
- **The Walsh-spectrum sub-item of TODO #214 is not attempted.**  As written it asks to
  resolve a bias of `2^-16` by sampling, which needs roughly `2^32` evaluations per
  functional.  The tractable substitute is an exact Walsh-Hadamard transform at small
  width rather than sampling at 256, and that deserves its own item.

Recommended follow-ups: a MILP formulation with better scaling toward `n = 256`, and a
fixed-key differential treatment, which for a construction with no key schedule is the
open question this analysis surfaces rather than settles.

---

## 11.21 Seed-Masked FSCX Revolve (MFSCX) as a Key Exchange — a Negative Result (TODO #224)

Every HKEX variant shipped so far draws its hardness from `GF(2^n)*` discrete log
(HKEX-GF) or Ring-LWR (HKEX-RNL).  TODO #224 asked whether a third construction could
lean on symmetric/hash-style hardness instead, using FSCX itself as the mixing
function: add a per-step, seed-derived injection to the revolve loop and hope the
resulting map is no longer the affine object that `hkex_classical_break.py` breaks.

The proposed primitive, with `M = I xor ROL xor ROR` as today:

```
MFSCX_REVOLVE(A, B, i; S):
    for j = 0 .. i-1:
        A <- FSCX(A, B) xor u_j,      u_j = S_j and mask_j
```

in two regimes — *static* (`mask_j` published, identical every session) and *dynamic*
(`mask_j` derived from the seed or from the running state `A`).

It does not work, in either regime, and the reason is not a parameter choice.  This
section records why, and what survives.  It is backed by
`SecurityProofsCode/mfscx_kex_analysis.py`.

### 11.21.1 A static mask only moves the constant term

Measured at `n = 32/64/128/256` over 400 random triples each, with zero mismatches:

$$\text{MFSCX-REVOLVE}(A, B, i; S) = M^i \cdot A \oplus T_i \cdot B \oplus \sigma_i(S)$$

where `T_i = M . S_i` is the *unchanged* classical key map of §1.3.1 and

$$\sigma_i(S) = \bigoplus_{j < i} M^{i-1-j} \cdot u_j$$

is a constant in `(A, B)`.  Nothing in the linear part changed.  A static injection is
an affine translation, and affine translations are exactly what the FSCX constructions
already tolerate.

### 11.21.2 The classical break generalises verbatim

Running the honest two-party exchange with both parties using the published schedule,
the cancellation identity `M . S_n = 0` still removes `B`, `A_2` and `B_2`, and Eve's
recovery picks up one extra public constant:

$$sk = S_{r+1} \cdot (C \oplus C_2) \oplus \kappa(S), \qquad \kappa(S) = \sigma_r(S') \oplus M^r \cdot \sigma_i(S)$$

Over 10 000 sessions across the four widths: agreement 10 000/10 000, Eve's recovery
10 000/10 000, at the same `O(n^2)` cost as the unmasked break.  `kappa` is public by
definition of the static regime, and even if it were not, *both parties add the same
`kappa`*, so it never enters the `C xor C2` relation that determines the session key.
The static branch is closed.

Making the P-box seed secret-but-shared does not rescue it either: the residue
`sk xor S_{r+1}.(C xor C2)` took exactly one value across 2 000 sessions, so one known
session key recovers `kappa` for all future ones.  A construction that needs a
pre-shared secret is HSKE, not a key exchange.

### 11.21.3 The mask does not repair the co-rank leak

Because the injection contributes no columns to the key map, the TODO #210 co-rank
table carries over unchanged — 30, 62 and 126 lost dimensions at `n = 64`, `128` and
`256`, in both the encrypt and decrypt directions.  This is a second, independent
reason to reject the static branch.

One positive result does fall out.  The map from a *secret* subkey schedule
`(u_0, ..., u_{i-1})` to `sigma_i` is surjective: `m(1) = 1`, so `M` is a unit in
`GF(2)[X]/(X^n+1)` and every `M^{i-1-j}` is invertible (measured: `min_k rank(M^k) = n`
for all `k < i`, at all three widths).  A secret per-step injection therefore *does*
close the 126-dimensional plaintext leak §1.3.1 found in HSKE and HPKE.  That is a
statement about the pre-shared-key setting — TODO #224's option 1 — not about key
agreement.

### 11.21.4 A dynamic mask destroys agreement

With `mask_j` following the running state, the two parties inject different subkeys
from step 0 onwards.  Over 2 000 trials per width, `sk_A = sk_B` in 0 cases, and the
two derived values differ by `n/2` bits on average — the rate two unrelated values
would show.  The homomorphism that made `C_A xor C_B` a shared quantity at all is gone
along with the affinity.

### 11.21.5 The middle ground does not exist

`hkex_nonce_impossibility.py` proves that no *nonce* rescues HKEX.  The same algebra
covers an entire injection schedule, because the injections reach the session key
through a single accumulator:

$$sk_A = M^r \cdot (C \oplus C_2) \oplus S_r \cdot N \oplus L_A, \qquad L_A = \bigoplus_{j < r} M^{r-1-j} \cdot u_{A,j}$$

and symmetrically for Bob.  Correctness for all independently drawn key pairs forces
`L_A = L_B`, and a value that is equal across two independent private inputs can depend
only on what is common to them — the wire values `C` and `C2`.  Hence `L = h(C, C2)`,
and the session key is once again a function of the transcript alone.

The seed may enter `u_j` through any non-linear map whatsoever; the argument never
differentiates it.  What matters is only whether `u_j` depends on per-party private
data.  Both halves of the dichotomy are exhibited at `n = 128`:

| schedule | agreement | `sk` equals the classical public formula |
|---|---|---|
| private `u_0`, with cancelling partner `u_1 = M . u_0` | 1000/1000 | 1000/1000 |
| private `u_0`, no cancelling partner | 0/1000 | — |

So an injection schedule is either invisible to the session key or fatal to agreement.
"Non-linear in the seed while remaining commutative in the two parties' contributions",
the middle ground TODO #224 asked about, does not name a third case: commutativity here
*is* the requirement that the private part cancel, and a part that cancels contributes
nothing.

For completeness, the seed-derived schedule was also checked for orbit collapse, since
a mask that lands in a short cycle silently degenerates to a static one.  It does not
collapse — iterating NL-FSCX v1 gives mean cycle lengths of 146, 640 and 2264 at
`n = 16`, `20` and `24` against a random-function expectation of 160, 642 and 2567.
Orbit collapse is not what kills the dynamic branch; §11.21.4 and this subsection are.

### 11.21.6 The hash-only ceiling, tabulated

Impagliazzo-Rudich caps black-box key agreement relative to a random oracle at Merkle's
quadratic gap, so "hash-based key exchange" is not a free substitution for a trapdoor —
hash-based *signatures* work (HPKS-WOTS-F, HPKS-XMSS-F) because signing needs no
trapdoor.  Honest work to reach a `2^128` adversary bound, at 32 bytes of puzzle:

| setting | gap | honest oracle calls | wire bytes |
|---|---|---|---|
| classical honest, classical Eve | `N^2` | `2^64` | `2^69` |
| classical honest, quantum Eve | `N^(13/12)` | `2^118` | `2^123` |
| quantum honest, quantum Eve | `N^(3/2)` | `2^85` | `2^90` |

The quadratic row is a ceiling, not merely the best known construction; plain Merkle
falls to `N` against a Grover-equipped Eve, and the two quantum rows are the
Brassard-Hoyer-Kalach-Kaplan-Laplante-Salvail constructions.  `2^64` 32-byte puzzles is
roughly `5.9 x 10^8` TB per handshake.  The middle exponent has been nudged upward since
2011 and may move again; nothing between 1 and 2 changes the conclusion.

### 11.21.7 What survives

| branch | verdict |
|---|---|
| static P-box | closed — affine, break generalises (§11.21.2), co-rank unchanged (§11.21.3) |
| secret shared P-box | not a key exchange — `kappa` recovered from one known session key |
| dynamic P-box | closed — agreement destroyed (§11.21.4), and §11.21.5 leaves no alternative schedule |
| hash-only (Merkle) | provable and unshippable (§11.21.6) |
| MFSCX as PRF/KDF inside a structured KEM | alive, and the only one |

The surviving branch is the one that never needed a trapdoor: MFSCX as a KDF, ratchet,
or error-sampler over an already-shared secret, or as the symmetric layer inside the
QC-MDPC or Ring-LWR path, where hardness comes from the code or lattice and MFSCX only
has to mix.  §11.21.3's surjectivity result is the useful piece there.

TODO #224's success criterion was "either a construction with a written hardness
assumption that is not restatable as *FSCX is affine*, or a clear negative result
saying why seed-masked FSCX cannot give key agreement".  This is the second.  No
`--algo` tag, PEM boundary label, or `spec/` entry follows from it.

---

## 11.22 Every Step Function That Admits HKEX Agreement Is Broken (TODO #230)

TODO #224 closed the seed-masked revolve; TODO #230 asked whether the same result
extends to a substitution layer.  It does — but not by extension.  #224's
impossibility theorem quantifies over *additive* injections, values `u_j` that enter
the step by XOR and reach the session key only through the accumulator
`L = xor_j M^(r-1-j).u_j`.  That linear factoring is the whole engine of the proof,
and an S-box does not factor out of the iteration at all, so #224 is **silent** on the
S-box rather than dispositive.  Measured: the class #224 covers is exactly the set of
step functions with `G(A,B) xor G(A',B)` independent of `B`, which every additive
injection satisfies on 100% of random triples and a nibblewise S-box fails on 100%.

What closes the S-box case is a stronger statement that needs no linearity, no
affineness, and no assumption about the step function whatsoever.  It is backed by
`SecurityProofsCode/sbox_kex_extension.py`.

### 11.22.1 The characterization theorem

Let the public phase iterate `F_B` and the derivation phase iterate `G_B` — both
public — with `i + r = n`.  HKEX-style agreement is the identity

$$G_B^r\bigl(F_{B_2}^i(A_2)\bigr) \oplus A = G_{B_2}^r\bigl(F_B^i(A)\bigr) \oplus A_2$$

required for all `A, B, A_2, B_2`.

**Theorem.** Agreement holds **if and only if** for every pair the composite
`G_B^r . F_B2^i` is the translation `x -> x xor d(B,B2)`.

*Proof.* Fix `(B, B2)` and write `P(A2)`, `Q(A)` for the two composites.  The identity
says `P(A2) xor A2 = Q(A) xor A` for all `A, A2`.  The left side depends only on `A2`
and the right only on `A`, so both equal a constant `d(B,B2)`; exchanging the parties'
roles gives `d(B,B2) = d(B2,B)` for free. □

Four more lines extract the structure.  Fix any `B0` and set `Psi = (G_B0^r)^{-1}`.
The theorem at `B = B0` gives `F_B2^i(x) = Psi(x xor e(B2))` with `e(B2) = d(B0,B2)`.
Substituting that back into the general case gives `G_B^r(y) = Psi^{-1}(y) xor g(B)`
with `e(B2) xor d(B,B2) = g(B)` independent of `B2`, and symmetry of `d` then forces
`g(B) = e(B) xor c` for a single constant `c`.  Hence `Psi^{-1}(C) = A xor e(B)` and
`Psi^{-1}(C2) = A2 xor e(B2)`, so

$$sk = G_B^r(C_2) \oplus A = A \oplus A_2 \oplus e(B) \oplus e(B_2) \oplus c = \Psi^{-1}(C) \oplus \Psi^{-1}(C_2) \oplus c$$

**Corollary (universal attack).** For any construction of this shape,

$$sk = G_{B_0}^r(C) \oplus G_{B_0}^r(C_2) \oplus c, \qquad c = G_{B_0}^r\bigl(F_{B_0}^i(0)\bigr)$$

for an eavesdropper's arbitrary choice of `B0`.  Cost: `2r + i` applications of the
public step function, no private value and no algebraic structure required.

The content of the theorem is that agreement forces the entire key-dependence of the
`i`-fold iterate into an input XOR translation — the family `{F_B^i}` lies in a single
coset of the translation group.  That is the precise sense in which any such
construction is a disguised XOR homomorphism, and it is why the hardness assumption is
always vacuous.

Verified at `n = 32/64/128/256`, 300 sessions each: agreement 300/300, the composite is
a translation 50/50, the universal attack recovers `sk` 300/300, and its output equals
`hkex_classical_break.py`'s `S_(r+1).(C xor C2)` 300/300 — while never evaluating `M`
as a linear map.  §1.3.1, `hkex_nonce_impossibility.py` and §11.21 are all special
cases: `Psi^{-1} = M^r`, the nonce as a public step parameter, and the additive
injection respectively.

### 11.22.2 A linear S-box: not a new construction, but a better co-rank

With `L` linear the step becomes `(L.M).(A xor B)`, i.e. FSCX with `M` replaced by
`M' = L.M`.  Writing `Y = M' + I`, the agreement conditions `M'^n = I` and
`M'.S'_n = 0` are together equivalent to `Y^(n-1) = 0`, and for `i` a power of two the
binomial sum collapses by Lucas' theorem to `S'_i = Y^(i-1)`, giving

$$\text{co-rank}(T_i) = \dim \ker Y^{2^{v_2(i)} - 1}$$

This recovers §1.3.1's `2(2^{v_2(i)} - 1)` as the special case `v(M+I) = 2`.  **The
factor 2 in TODO #210's closed form is exactly the valuation of `M+I`** — a property
of this particular `M`, not of the construction — and a different linear box removes
it.  Measured at `n = 256`, `i = 64`:

| Jordan type of `Y` | agreement | co-rank `T_i` | co-rank `T_r` |
|---|---|---|---|
| single block `(n)` | **no** | 63 | 63 |
| `(n-1, 1)` | yes | **64** | 64 |
| `(n-2, 2)` | yes | 65 | 65 |
| `(n/2, n/2)` | yes | 126 | 126 |
| classical `M` | yes | 126 | 126 |

The first two rows must be read together.  A regular nilpotent `Y` reaches co-rank 63,
but there `Y^(n-1) != 0`, so it **fails agreement**: the unconstrained optimum is
unreachable by any protocol.  The constrained optimum is Jordan type `(n-1, 1)` at
exactly 64, and since `dim ker Y^(i-1) = sum_j min(lambda_j, i-1)` is minimized by the
fewest and largest blocks, 64 is a floor rather than the best found by search.

So a linear box takes the plaintext leak from **126 to 64 of 256** — a real
improvement, and still never 0, because `Y` is nilpotent and `Y^(i-1)` is therefore
singular for every even `i`.  No linear box repairs the leak; none makes the exchange
secure either, since §11.22.1 applies verbatim (agreement 100/100, attack 100/100 at
the `(n-1,1)` box).  This is a finding about HSKE and HPKE, not a licence to change
them.

### 11.22.3 Non-linear S-boxes: unrelated, not noisy

An affine box is the linear case plus §11.21's `kappa`, which both parties add
identically — agreement and the attack are unchanged for a zero, random or all-ones
constant.

For genuinely non-linear boxes, the measurement that matters is not the pass/fail rate
but the *distance distribution*.  A pass/fail count cannot tell a dead construction
from a noisy one: HKEX-RNL also fails exact agreement and is rescued by Peikert
reconciliation (§11.4.2), which needs a small Hamming distance to work with.

| box (applied nibblewise) | agreement, `n = 64` | mean HW | agreement, `n = 128` | mean HW |
|---|---|---|---|---|
| identity (linear) | 300/300 | 0.0 | 300/300 | 0.0 |
| 1 transposition | 0/300 | 32.3 | 0/300 | 64.3 |
| 2 transpositions | 0/300 | 31.5 | 0/300 | 64.5 |
| 4 transpositions | 0/300 | 32.1 | 0/300 | 64.1 |
| PRESENT 4-bit S-box | 0/300 | 32.1 | 0/300 | 63.8 |

A *single transposition* inside one 4-bit box — the smallest departure from linearity
that exists — already saturates the `n/2` random-function baseline and is
indistinguishable from a real S-box.  The two derived values are unrelated, not noisy,
so there is nothing for reconciliation to reconcile.  The one branch that could have
survived this item is measured shut rather than assumed shut.  A `B`-keyed box, which
additionally destroys the shared-box symmetry, behaves the same way.

### 11.22.4 The conjecture was wrong, and the theorem does not need it

TODO #230 conjectured that an agreeing step function must be affine over an abelian
group.  It is **false**.  For the family `G(A,B) = S(A xor B)` with `i = 1`, the
characterization collapses to the single equation `(S.tau_B)^n = tau_c` with one `c`
for every `B`, verified exhaustively to be equivalent to full agreement — which makes
the sweep cheap enough to be genuinely exhaustive:

- all permutations at `n = 2` (24) and `n = 3` (40 320) — `n = 3` admits nothing at
  all, affine included, so it is a degenerate width rather than evidence;
- all 322 560 affine permutations at `n = 4`, of which 25 216 agree;
- all 3 025 920 boxes one transposition away from an agreeing affine box at `n = 4`.

That last family yields **15 360 distinct non-affine permutations that admit full
agreement**, confirmed over all 65 536 tuples for a 40-box sample.  The smallest is the
identity with `0` and `1` swapped.  A sample of 200 000 uniform random permutations at
`n = 4` yields none, so the agreeing set is sparse — but it is not contained in the
affine boxes.

The universal attack wins on every one of them.  Affineness was simply the wrong
invariant; the translation-coset condition is the right one, these boxes satisfy it,
and that is what the theorem is stated in terms of.  The conjecture turning out false
costs the item nothing, which is the point of not having built the argument on it.

### 11.22.5 Scope

All four sub-cases the item named are closed, and closed by one theorem rather than
four measurements.  What the theorem does *not* say: it constrains constructions of the
HKEX template — two parties, one round each, agreement by exact equality.  It says
nothing about multi-round protocols, about constructions whose agreement is approximate
by design (HKEX-RNL, where reconciliation is part of the specification, not a rescue),
or about hardness that lives outside the step function (the lattice and code paths).
Those remain exactly as analysed elsewhere in this document.

No `--algo` tag, PEM boundary label or `spec/` entry follows from this item.
§11.22.2's co-rank result is a finding about HSKE/HPKE and would need its own item,
with wire-format and `MIGRATING.md` analysis, before anything shipped.

---

## 11.23 The Co-Rank Improvement Is Real and Should Not Be Shipped (TODO #232)

§11.22.2 left a loose end: a linear box takes TODO #210's plaintext leak from 126 to
64 of 256, and 64 is a proved floor.  TODO #232 asks whether the suite should act on
it.  It should not, and the reasons are worth recording, because two of them are
positive results in their own right.  Backed by
`SecurityProofsCode/corank_linear_box_decision.py`.

### 11.23.1 The classical `M` is optimal among rotation-based steps

FSCX is built from rotations, so the natural replacement space is the circulants —
polynomials in the rotation `X` over `GF(2)[X]/(X^n + 1)`.  With `n` a power of two
that ring is local with maximal ideal `(Y)`, `Y = X + 1`, so every nilpotent is `Y^v`
times a unit and `dim ker Y^m = min(n, v.m)`.  Agreement needs `Y^(n-1) = 0`, hence
`v.(n-1) >= n`, hence `v >= 2`; and then

`co-rank(T_i) = min(n, v.(i-1)) >= 2(i-1)`

The bound is met exactly at `v = 2`, which is `v(M + I)` for the classical `M`.
Exhaustively over every circulant at `n = 8` (64 admit agreement) and `n = 16` (16 384
admit agreement), the best co-rank found is 2 and 6 — equal to the classical `M`'s, and
equal to the predicted `2(i-1)`.

So **TODO #210's 126 is simultaneously a defect and a floor**: it is the best any
rotation-based step admitting HKEX agreement can do.  §11.22.2's improvement is not a
matter of choosing better shift amounts; it requires leaving the rotation class, which
means the "Full Surroundings" construction the suite is named for stops being what is
implemented.

### 11.23.2 The cheap realisation is worse than what it replaces

§11.22.2 measured a Jordan *type*, not a shipped matrix.  In the standard bit basis
that type is a broken non-cyclic shift, `Y(x) = (x >> 1) & ~(1 << (n-2))` and
`M'(x) = x ^ Y(x)` — three word-ops against FSCX's five.  It satisfies `M'^n = I` and
`Y^(n-1) = 0`, and its co-rank is 64 as advertised.  The expected cost objection does
not materialise; it is *cheaper* than what ships.

The objection is that co-rank counts leaked dimensions and says nothing about how
concentrated the leak is.  Splitting the kernel by functional weight at `n = 256`,
`i = 64`:

| step function | co-rank | raw plaintext bits | min weight found |
|---|---|---|---|
| classical `M` (circulant) | 126 | **0** | 4 |
| Jordan `(n-1, 1)`, bit basis | 64 | **64** | 1 |
| Jordan `(n-1, 1)`, conjugated | 64 | 0 | 75 |

The `(n-1, 1)` box makes 64 ciphertext bits key-independent, and every one of them is a
plaintext bit verbatim: `E[192] = P[192]` through `E[255] = P[255]`.  A quarter of the
plaintext is transmitted in the clear.  The classical `M` leaks 126 dimensions and zero
raw bits — all of its leaked functionals are spread XORs.  **Co-rank is the wrong
figure of merit on its own.**

### 11.23.3 The sound realisation costs cross-target parity

Raw-bit exposure is basis-dependent and co-rank is not, so conjugating by a random
invertible `S` keeps the Jordan type, keeps co-rank 64, and scatters the leak — third
row above, minimum weight 75 against the classical 4.  That box is genuinely better on
both security axes.  It is also dense: ~`n/2` ones per column against 3 for `M`, so a
step costs ~`n` XOR-and-mask operations instead of five rotate/XOR ops, and the matrix
itself is 8 KB at `n = 256`.  The Arduino/AVR target already overflowed SRAM once
(TODO #155) and would not fit it, so the suite would lose the property that every
protocol runs on all six language/architecture targets.

### 11.23.4 It is dominated, and it cannot change a rating

Three routes reach the same leak, and the box is last on every axis:

| route | co-rank | cost | source |
|---|---|---|---|
| odd `i` (65 / 191) | **0** — `T_i` invertible | one parameter | §11.9 companion, TODO #211 |
| secret per-step injection | **0** — `sigma_i` surjective | a subkey schedule | §11.21.3, TODO #224 |
| linear box, cheap | 64, plus 64 raw bits | 3 word-ops | §11.23.2 |
| linear box, conjugated | 64 | ~128x, 8 KB, no AVR | §11.23.3 |

It is also the only route that does not reach 0, and the only one costing a wire-format
break — in fact two, since HPKS's Schnorr challenge `e = fscx_revolve(R, msg, i)` lives
in a subspace of dimension `rank(T_i)`, which the box moves from 130 to 192.  That is a
real gain and a separate MAJOR bump from the HSKE/HPKE one.

And no option touches the affine two-time break.  For any linear `M'` whatsoever, two
messages under one key give `E1 ^ E2 = M'^i.(P1 ^ P2)` — measured 200/200 for both the
classical `M` and the `(n-1, 1)` box, recovered with no key at all.  The fix for
multi-use is the NL quartet, which already ships.  Finally, `SECURITY.md` already rates
HSKE (key-only) "Not suitable for production" and HPKE "Demo-only", each disqualified
by something the co-rank does not reach: a single known-plaintext pair recovers the
HSKE keystream, and HPKE falls to the ~2^36.5 Pohlig-Hellman recovery of §9.2.4.  A
MAJOR break moving 126 to 64 buys no rating change.

### 11.23.5 What the leak actually looks like

One finding here is independent of the decision and applies to what ships today.  "126
dimensions" understates TODO #210: the lightest functional in the kernel has weight 4,

`E[0] ^ E[2] ^ E[128] ^ E[130]  ==  P[0] ^ P[2] ^ P[128] ^ P[130]`

under every key, on the same bit positions on both sides.  Verified 300/300 against the
shipped `fscx_revolve` with a fresh random key each time — four ciphertext bits give
four plaintext bits' parity, with no key and no known plaintext.  `SECURITY.md`'s HSKE
and HPKE rows cite the dimension count; this is the concrete form of it.

### 11.23.6 Verdict

Deprecate.  Document the result, ship nothing, and keep two things from the
investigation: §11.23.1's circulant floor, which reframes #210's 126 as the best an
FSCX-shaped primitive can achieve, and §11.23.5's weight-4 functional, which is the
usable statement of the leak.

---
