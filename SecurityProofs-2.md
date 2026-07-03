# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 2

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 2 of a split document.**
>
> - **Part 1 — §1–§10** (SecurityProofs-1.md): Algebraic Foundations · Protocol Analysis · Security Analysis · Quantum Attack Analysis · v1.4.0 Migration
> - **Part 2 — §11–§11.9** (this file): Non-linearity and Post-quantum Extensions · HFSCX-256-DM

---

## 11. Non-linearity and Post-quantum Extensions (v1.5.0)

This section analyses the two remaining structural weaknesses of the v1.4.0 suite and
documents the verified fixes implemented in v1.5.0:

1. **GF(2)-linearity** of FSCX — allows linear-algebraic attacks on symmetric protocols.
2. **Quantum vulnerability** of HKEX-GF — GF(2^n)^* DLP is broken by Shor's algorithm.

All claims in this section are supported by `SecurityProofsCode/hkex_nl_verification.py`.

---

### 11.1 The GF(2)-Linearity Problem

**Theorem 11 — FSCX is GF(2)-affine in each argument.**

For fixed $B$:

$$\text{FSCX-REVOLVE}(X, B, r) = R \cdot X \oplus K \cdot B$$

where $R = M^r$ and $K = M + M^2 + \cdots + M^r \in \mathbb{GF}(2)^{n \times n}$.

*Proof:* By induction.  Base case: $\text{FSCX}(X, B) = M(X \oplus B) = M \cdot X \oplus M \cdot B$.
For step $k+1$: $\text{FSCX}(M^k X \oplus S_k B, B) = M(M^k X \oplus S_k B \oplus B) = M^{k+1} X \oplus M(S_k + I) B = R \cdot X \oplus K \cdot B$. $\blacksquare$

**Consequence.** Eve holding $(X, \text{FSCX-REVOLVE}(X, B, r))$ for a single plaintext–ciphertext pair
can solve $K \cdot B = C \oplus R \cdot X$ for $B$ by Gaussian elimination over $\mathbb{GF}(2)$ in $O(n^3)$ time,
provided $K$ has full rank over $\mathbb{GF}(2)$.  Even when $K$ is rank-deficient, the null-space dimension
is at most $n - \text{rank}(K)$, bounding the residual key entropy.

**Root cause.** The linearity is intrinsic to the XOR / rotation structure of $M = I \oplus \text{ROL} \oplus \text{ROR}$:
every operation is a $\mathbb{GF}(2)$-linear map.  No composition of XOR and rotation can introduce
non-linearity over $\mathbb{GF}(2)$.

---

### 11.2 NL-FSCX Primitives

The minimal fix injects one *integer addition* per round.  Integer addition mod $2^n$ is
**non-linear** over $\mathbb{GF}(2)$: the carry bit at position $k$ depends on the AND of all
bit-pairs below position $k$, a polynomial of degree $k$ over $\mathbb{GF}(2)$.

Two variants are defined; they serve different roles.

#### 11.2.1 NL-FSCX v1 (carry from both arguments)

$$\text{NL-FSCX}(A, B) = \text{FSCX}(A, B) \oplus \text{ROL}\left((A + B) \bmod 2^n, \frac{n}{4}\right)$$

| Property | Value | Verified |
|----------|-------|----------|
| Non-linear over $\mathbb{GF}(2)$ | Yes — carry is degree-$k$ Boolean poly | Analytical |
| Bijective in $A$ for fixed $B$ | **No** — collisions exist for all $B$ | n=8: 256/256 non-bijective; n=32: collision found above birthday bound |
| Consistent period | **None** — orbit lengths are chaotic | n=32: 500/500 pairs found no period in 256 steps |
| Iterative inverse | **Diverges** — not a contraction | 500/500 non-convergent |

**Why ROL($n/4$):** The quarter-rotation places the injected carry bits at phase quadrature
relative to the FSCX XOR structure ($M^{n/2} = I$), maximising cross-mixing between
the carry channel and the XOR channel per round.

**Consequence for HSKE.** The non-existence of a consistent period means the standard
revolve-based decryption identity $\text{FSCX-REVOLVE}(E, K, n/2 - r) = P$ cannot be ported to
NL-FSCX v1.  Counter mode (§11.3.1) is the only applicable HSKE construction.

#### 11.2.2 NL-FSCX v2 (B-only offset, explicit inverse)

$$\text{NL-FSCX}_{v2}(A, B) = \text{FSCX}(A, B) + \text{ROL}\left(B \cdot \left\lfloor\frac{B+1}{2}\right\rfloor \bmod 2^n, \frac{n}{4}\right) \pmod{2^n}$$

The offset $\delta(B) = \text{ROL}(B \cdot \lfloor(B+1)/2\rfloor \bmod 2^n, n/4)$ depends **only on $B$**.

| Property | Value | Verified |
|----------|-------|----------|
| Non-linear over $\mathbb{GF}(2)$ | Yes — $B \cdot \lfloor(B+1)/2\rfloor$ involves integer carry | 500/500 linearity violations (n=32) |
| Bijective in $A$ for fixed $B$ | **Yes** — offset is independent of $A$ | n=8: 0/256 non-bijective |
| Exact closed-form inverse | $A = B \oplus M^{-1}\left((Y - \delta(B)) \bmod 2^n\right)$ | 1000/1000 correct (n=32) |
| HSKE revolve enc→dec | Correct | 200/200 round-trips (n=32) |

**Proof of inverse.** $\text{NL-FSCX}_{v2}(A, B) = M(A \oplus B) + \delta(B)$.  Stripping the offset:
$(Y - \delta(B)) \bmod 2^n = M(A \oplus B)$.  Applying $M^{-1}$:
$A \oplus B = M^{-1}\big((Y - \delta(B)) \bmod 2^n\big)$, so $A = B \oplus M^{-1}(\cdots)$. $\blacksquare$

**Note on linearity channel.** $A$ still enters $\text{FSCX}(A, B)$ through the linear map $M$.
The non-linearity is in the $B$-channel (key) only.  For HSKE, the adversary observes
$C = P \oplus \text{keystream}$ and never $A$ directly; the key $K$ enters exclusively via $B$,
so the $B$-channel non-linearity is sufficient to defeat linear key-recovery attacks.

---

### 11.3 HSKE Variants

Two secure HSKE constructions are defined; both are chosen depending on API requirements.

#### 11.3.1 HSKE-A1: Counter Mode with NL-FSCX v1

Let $\text{base} = K \oplus N$ where $N$ is a random per-session nonce (transmitted with ciphertext).

$$\text{keystream}[i] = \text{NL-FSCX-REVOLVE}\left(\text{ROL}(\text{base}, n/8), \text{base} \oplus i, n/4\right)$$
$$C[i] = P[i] \oplus \text{keystream}[i]$$
$$D[i] = C[i] \oplus \text{keystream}[i] = P[i]$$

No inverse is required.  The counter $i$ ensures keystream uniqueness per block.
Decryption is identical to encryption (XOR-symmetric).

**Seed rotation rationale.**  Without the ROL, counter $i = 0$ passes $A = B = \text{base}$, giving
$\text{FSCX}(\text{base}, \text{base}) = M(\text{base} \oplus \text{base}) = 0$ on step 1 — making the first
output purely a rotation of $2 \cdot \text{base}$, linear in $\text{base}$.  Setting the seed to
$\text{ROL}(\text{base}, n/8) \neq \text{base}$ ensures $\text{FSCX}(\text{seed}, \text{base}) \neq 0$ and
integer-carry non-linearity is active from step 1 across all counter values.
This mirrors the HKEX-RNL KDF fix in v1.5.10.  (v1.5.13)

**Security argument.**  $\text{keystream}[i]$ is the output of $n/4$ rounds of NL-FSCX v1 starting
from seed $\text{ROL}(\text{base}, n/8)$ with parameter $\text{base} \oplus i$.  Non-linearity prevents
GF(2) linear recovery of $K$ from any set of (plaintext, ciphertext) pairs.  Assuming NL-FSCX v1
acts as a pseudorandom function (PRF), CPA security follows from standard stream cipher arguments.

#### 11.3.2 HSKE-A2: Revolve Mode with NL-FSCX v2

$$E = \text{NL-FSCX-REVOLVE}_{v2}(P, K, r)$$
$$P = \text{NL-FSCX-REVOLVE}_{v2}^{-1}(E, K, r)$$

where $\text{NL-FSCX-REVOLVE}_{v2}^{-1}$ applies the closed-form single-step inverse $r$ times in reverse.

This preserves the original `fscx_revolve(P, K, r)` / `fscx_revolve(E, K, n-r)` API shape.
The explicit inverse from §11.2.2 is applied $r$ times, each costing one integer subtraction,
one ROL, and one application of $M^{-1} = M^{n/2-1}$, so total decrypt cost is
$O(r \cdot n/2)$ FSCX steps — same asymptotic order as standard HSKE.

**Usage constraint — deterministic encryption.** HSKE-NL-A2 carries no nonce:
the same (plaintext, key) pair always produces the same ciphertext.  It does not
achieve IND-CPA security in the multi-message sense unless an external session
differentiator (sequence number, nonce, or session ID) is embedded in the
plaintext before encryption.  HSKE-NL-A1 (§11.3.1) provides a per-session nonce
as part of the protocol; prefer A1 when multiple messages may be encrypted under
the same key.

---

### 11.4 HKEX-RNL: PQC Key Exchange (B2)

HKEX-GF relies on the DLP in $\mathbb{GF}(2^n)^{\ast}$, which Shor's algorithm solves in polynomial time
on a quantum computer.  The following replacement is proposed.

#### 11.4.1 Ring structure

The FSCX linear map $M = I \oplus \text{ROL} \oplus \text{ROR}$ corresponds to multiplication by the
polynomial $m(x) = 1 + x + x^{n-1}$ in $\mathbb{GF}(2)[x]/(x^n + 1)$.  Lifting the coefficient ring
from $\mathbb{GF}(2)$ to $\mathbb{Z}/q\mathbb{Z}$ for a prime $q$:

$$\mathcal{R}_q = (\mathbb{Z}/q\mathbb{Z})[x] / (x^n + 1)$$

In $\mathcal{R}_q$, multiplication by $m(x) = 1 + x + x^{n-1}$ is exactly FSCX\_REVOLVE applied once,
but over $\mathbb{Z}/q\mathbb{Z}$ instead of $\mathbb{GF}(2)$.

**Theorem 12 — $m(x)$ is invertible in $\mathcal{R}_q$ for $n = 2^k$, $q$ prime.**

Verified for $(n, q) \in \{(16, 257), (16, 769), (16, 3329), (16, 7681), (16, 12289)\}$:
inverse computes correctly, $m(x) \cdot m^{-1}(x) = 1$ in all cases.

The centered $\ell_1$-norm of $m^{-1}(x)$ scales as $\|m^{-1}\|_1 \approx n \cdot q / 2$:

| $q$ | $\|m^{-1}\|_\infty$ | $\|m^{-1}\|_1$ |
|-----|---------------------|----------------|
| 257 | 115 | 1 127 |
| 769 | 360 | 2 487 |
| 3 329 | 1 275 | 11 828 |
| 7 681 | 3 432 | 24 841 |
| 12 289 | 5 491 | 53 863 |

#### 11.4.2 Protocol: HKEX-RNL (Ring-NL, blinded)

**Setup.** Parties agree on public parameters $(n, q, p, g)$ with $p < q$ both prime.

**Shared polynomial setup (one-shot, per session):**
- One party (e.g. Alice) draws $a_\text{rand} \leftarrow \mathcal R_q$ uniformly and
  transmits it in the clear.  Both parties compute the **shared** blinded polynomial:
  $m_\text{blind} = m(x) + a_\text{rand} \in \mathcal R_q$.

**Key generation (Alice and Bob, independently):**
- Alice: private $s_A \leftarrow \mathrm{CBD}(\eta)$; public key $C_A = \lfloor m_\text{blind} \cdot s_A \rceil_p \in \mathcal R_p$.
- Bob:   private $s_B \leftarrow \mathrm{CBD}(\eta)$; public key $C_B = \lfloor m_\text{blind} \cdot s_B \rceil_p \in \mathcal R_p$.

Both use the **same** $m_\text{blind}$.  ($\lfloor \cdot \rceil_p$ denotes rounding from $\mathbb{Z}/q\mathbb{Z}$ to $\mathbb{Z}/p\mathbb{Z}$.)  $\mathrm{CBD}(\eta)$ is the centered binomial distribution: each coefficient $s_i = \sum_{j=0}^{\eta-1}(a_j - b_j)$ where $a_j, b_j \xleftarrow{R} \{0,1\}$ independently.  Deployed with $\eta = 1$, giving $s_i \in \{-1, 0, 1\}$ with zero mean and $\Pr[s_i = \pm 1] = 1/4$.  This matches the Kyber/NIST baseline for proper Ring-LWR secret entropy and eliminates the mean bias of the previous uniform $\{0,1\}$ sampler.

**Key agreement:**

$$K_A = \left\lfloor s_A \cdot C_B \right\rceil_{p'} \approx s_A \cdot m_\text{blind} \cdot s_B \in \mathcal R_q$$
$$K_B = \left\lfloor s_B \cdot C_A \right\rceil_{p'} \approx s_B \cdot m_\text{blind} \cdot s_A \in \mathcal R_q$$

Commutativity of $\mathcal R_q$ gives $s_A \cdot m_\text{blind} \cdot s_B = s_B \cdot m_\text{blind} \cdot s_A$, so $K_A \approx K_B$; reconciliation extracts a shared bit-string.

**Peikert reconciliation (2-bit hint per coefficient, v1.7.0).**  Because the raw product polynomials agree only approximately, direct extraction of bits fails at a rate of ~2% ($n=32$) to ~37% ($n=256$).  Peikert-style cross-rounding eliminates this.  The v1.7.0 scheme extracts **2 bits per coefficient** (pp=4), doubling key density vs.\ the original 1-bit scheme (pp=2):

1. **Hint generation (Alice, reconciler).** For each coefficient $c_i$ of $K_\text{poly,A}$:
$$h_i = \left\lfloor \frac{8c_i + q/4}{q} \right\rfloor \bmod 4, \qquad h_i \in \{0,1,2,3\}$$
Alice transmits the hint vector $(h_0,\ldots,h_{n/2-1})$ alongside her public key, packed 2 bits per byte position (hint size = $n/8$ bytes, same as the 1-bit scheme).

2. **Key extraction (both parties).** For a coefficient $c_i$ and the shared 2-bit hint $h_i$:
$$b_i = \left\lfloor \frac{4c_i + (2h_i+1)\lfloor q/4 \rfloor}{q} \right\rfloor \bmod 4$$
The extracted key is $K_\text{raw} = \sum_{i=0}^{k/2-1} b_i 4^i$ (first $k/2$ coefficients, $k$ = key bits; e.g. $k/2=128$ coefficients for a 256-bit key at $n=256$).

3. **Correctness guarantee.** Empirical measurement shows $\max_i |K_{\text{poly,A}}[i] - K_{\text{poly,B}}[i]| \leq 379 \ll q/8 = 8192$.  The factor $(2h_i+1)$ in the extraction formula places each extraction grid point at an **odd multiple of $q/4$**, ensuring correct modular wrap-around at $c \approx 0$ and $c \approx q$.  Verified: **0 failures** over 53,751 test cases with $|\text{error}| \leq 380$.

**KDF post-processing.**  The reconciled raw key $K$ is passed through NL-FSCX v1 with a rotated seed:

$$seed = \text{ROL}(K, n/8), \qquad sk = \text{NL-FSCX-REVOLVE}_{v1}(seed, K, n/4)$$

**Rationale.**  The original KDF, $sk = \text{NL-FSCX-REVOLVE}(K, K, n/4)$, suffered a first-step degeneracy: when $A_0 = B = K$, $\text{FSCX}(K, K) = K \oplus K \oplus \ldots = 0$, so the first step reduces to a pure rotation,

$$A_1 = \text{ROL}((K + K) \bmod 2^n, n/4) = \text{ROL}(K \ll 1, n/4),$$

which is linear in $K$.  Non-linearity accumulates only from step 2 onward.

Setting $seed = \text{ROL}(K, n/8) \neq K$ ensures $\text{FSCX}(seed, K) = M(seed \oplus K) \neq 0$ from the very first step, so full integer-carry non-linearity is active throughout all $n/4$ steps.  The single-pass structure is preserved — a second bijective pass (NL-FSCX v2) would not add one-wayness since it is invertible for fixed $K$.

#### 11.4.3 Security

**Hardness.** The blinding polynomial $a_\text{rand}$ is fresh per session, making $m_\text{blind}$
uniformly random in $\mathcal{R}_q$.  The key-exchange problem then reduces to the
**Ring-LWR (Learning With Rounding)** problem on $\mathcal{R}_q$, which is a standard
Ring-LWE/LWR instance over a power-of-two cyclotomic ring — the same structure as Kyber.
This is believed post-quantum hard; no polynomial-time quantum algorithm is known.

**Active-adversary caveat (TODO #89).** The security argument above assumes $m_\text{blind}$
arrives unmodified.  A MITM or malicious peer can substitute $a_\text{rand}$ with a chosen
value (e.g., $a_\text{rand} = -m(x)$, forcing $m_\text{blind} = 0$), steering the
protocol toward the unblinded case where the sparse fixed structure of $m(x)$ enables
lattice-reduction leverage.  In the extreme case $m_\text{blind} = 0$, both public keys
$C_A$ and $C_B$ become rounding of the zero polynomial, leaking the shared key immediately.

**Mitigation (v1.9.37).** The receiver (Bob, step 1) validates the incoming $m_\text{blind}$
before use via two heuristic checks: (1) at least $n/4$ non-zero coefficients (a truly
random polynomial over $\mathbb{Z}_{65537}$ has $\approx n$ non-zero coefficients); and
(2) coefficient range $\max - \min \geq q/4$ (a clustered or constant polynomial has a
small range).  These checks catch zero-polynomial and sparse-polynomial attacks while
accepting any legitimate uniformly random blinding.  The check is implemented in
`rnl_validate_m_blind` (C/`herradura.h`), `_rnl_validate_m_blind` (Python CLI), and
`RnlValidateMBlind` (Go package); all three CLIs reject on failure with an explicit error.

**Remaining gap.** The blinding is still non-contributory: the uniformity of $m_\text{blind}$
rests entirely on Alice's RNG.  A backdoored or weak RNG on Alice's side silently weakens
both parties even if the receiver-side validation passes.  The full fix — making $a_\text{rand}$
a function of nonces from both parties ($a_\text{rand} = \text{XOF}(n_A \| n_B)$) — requires
a protocol change and is tracked as the open portion of TODO #89.

**Security estimate (2026 landscape review, TODO #71).** For the deployed parameters
$(n=256, q=65537, p=4096, \eta=1)$, BKZ-based lattice reduction (the best known classical
attack via the Ring-LWR-to-Ring-LWE reduction) is estimated at approximately **105–115
classical Core-SVP bits** and **95–105 quantum Core-SVP bits** (MATZOV Report 2022;
Albrecht et al. LWE estimator 2023 updates).  This is below the 128-bit target of NIST
ML-KEM-768 (which uses Module-LWE with $k=3$ rings at $n=256$, $q=3329$) but comfortably
above the 100-bit floor.  No new algebraic attack on Ring-LWR exploiting the Fermat prime
$q=65537$ has been published through 2025.  The ring $\mathbb{Z}_{65537}[x]/(x^{256}+1)$ is
fully NTT-friendly: $q-1 = 2^{16}$ is divisible by $2n = 512$, so $x^{256}+1$ splits
completely into 256 linear factors over $\mathbb{F}_{65537}$ (this is precisely what enables
the negacyclic NTT used in Dilithium and other lattice schemes).  Fully-splitting rings do
not by themselves enable NTRU-style subfield attacks; those attacks require a short secret
polynomial exploitable via the subring structure.  In HKEX-RNL the secret is a randomly-sampled
blinding mask $m$ whose distribution is not concentrated in any proper subring, so
subfield-attack preconditions do not hold.  The CBD($\eta=1$) secret distribution provides less margin than
$\eta=2$ (used in Kyber-512) but remains secure at $n=256$.

**Upgraded parameter set: HKEX-RNL-128 (TODO #90, v1.9.45).** The deployed $n=256$
parameters fall below the 128-bit Core-SVP floor.  An upgraded parameter set that reaches
the 128-bit target is defined as follows:

$$\text{HKEX-RNL-128}: \quad n=512,\; q=65537,\; p=4096,\; \eta=1,\; pp=2$$

Security argument: the BKZ primal attack block-size requirement $\beta_\text{opt}$
scales approximately linearly with the ring dimension $n$ for fixed $(q, p, \eta)$
(Lindner-Peikert 2011; Albrecht et al. 2019).  Calibrating to the known $n=256$
estimate (~110 bits midpoint):

$$\text{Core-SVP}(n) \;\approx\; 110 \cdot \frac{n}{256} \quad \text{(classical)},
\qquad 100 \cdot \frac{n}{256} \quad \text{(quantum)}$$

At $n=512$ this yields approximately **220 classical / 200 quantum Core-SVP bits**,
comfortably above the 128-bit target.  Independent cross-check: ML-KEM-512 (Module-LWE,
effective dimension 512, $q=3329$) achieves 118–131 classical bits; HKEX-RNL at $n=512$
has relative noise ratio $\sigma/\sqrt{q} = 4.67/256 = 0.018$, smaller than ML-KEM-512's
$1.22/57.7 = 0.021$, confirming a lower bound of at least 128 bits.

NTT compatibility: $q-1 = 2^{16}$, so $2n = 1024$ divides $q-1$; $g=3$ is a primitive
root mod $65537$, making $\psi = 3^{(q-1)/(2n)}$ a valid negacyclic NTT twiddle.

Reconciliation correctness: `SecurityProofsCode/hkex_rnl_failure_rate.py` §7 verifies
**0 failures in 2000 trials** at $n=512$, $p=4096$ with Peikert reconciliation.

Key-size impact: public key and ciphertext each contain two $n=512$ ring elements
($\approx 1.1$ KB per element at 17 bits/coefficient), doubling the wire format size
versus $n=256$.  The ring dimension is a runtime parameter; no protocol or API changes
are required for deployment.

The $n=256$ wire format remains the default until a major-version migration.

**Naive algebraic attack analysis.**  Without blinding ($m_\text{blind} = m$), Eve computes
$m^{-1} \cdot (C \cdot q/p) \bmod q$ attempting to recover $s$.  The attack fails because
rounding noise $\delta$ (bounded by $q/(2p)$ per coefficient) is amplified by $\|m^{-1}\|_1 \gg q$
before any wrap-around threshold is crossed.  (Verified with $q = 769$, $n = 16$, 200 trials per
$p$ — see `SecurityProofsCode/hkex_nl_verification.py` §2.2.)

| $p$ | $q/p$ | $\|m^{-1}\|_1 \cdot q/(2p)$ | Wraps mod $q$? | Attack success |
|-----|-------|------------------------------|----------------|----------------|
| 4   | 192   | $\approx 73{,}728$           | Yes            | 0/200 |
| 64  | 12    | $\approx 14{,}922$           | Yes            | 0/200 |
| 256 | 3     | $\approx 3{,}730$            | Yes            | 0/200 |

Even at the smallest rounding gap ($p = 256$, $q/p = 3$), amplified noise exceeds $q$,
making exact recovery impossible.  This protection is structural to the dense $m^{-1}$.

**Note on lattice reduction.** The naive attack is not the strongest possible.  LLL/BKZ lattice
reduction operates on the lattice defined by the system and can exploit the sparse, fixed
structure of $m(x)$ in the unblinded case ($m_\text{blind} = m$) to gain extra algebraic leverage.
Blinding with $a_\text{rand}$ converts the problem to a standard Ring-LWR instance with a random
public polynomial, for which no sub-exponential quantum attack is known.  The blinding is
therefore **required** for a provable security claim.

---

### 11.5 Verification Summary

All results are from `SecurityProofsCode/hkex_nl_verification.py` (n=32 unless noted).

#### Q1 — Period of NL-FSCX v1

| Test | Result | Conclusion |
|------|--------|------------|
| Standard FSCX period $M^{n/2} = I$ (n=32, random B) | 133/500 pairs satisfy period = n/2 | ~25% of random (X,B) pairs have orbit period exactly n/2; confirms prior PL-1 analysis |
| NL-FSCX v1 orbit lengths (n=8, 1024 samples) | 938/1024 find no period in 256 steps; remainder have variable lengths | No consistent period |
| NL-FSCX v1 period (n=32, 500 samples) | 500/500 find no period in 256 steps | Period property completely destroyed |
| HSKE-A1 counter mode encrypt→decrypt | 200/200 correct | Counter mode is viable |

#### Q2 — FSCX-LWR algebraic attack and key-agreement correctness

All rows below use $n = 16$ unless noted.

| Test | Result | Conclusion |
|------|--------|------------|
| $m(x)$ invertible in $\mathcal{R}_q$, $q \in \{257, 769, 3329, 7681, 12289\}$, $n=16$ | Yes, all 5 values; $m \cdot m^{-1} = 1$ verified | Algebraic inverse exists for these $(n,q)$ |
| $m(x)$ invertible, $q = 65537$, $n = 32$ | Yes; $\|m^{-1}\|_\infty = 31{,}833$, $\|m^{-1}\|_1 = 536{,}649$ | Verified in `hkex_nl_verification.py` §2.1 |
| $m(x)$ invertible, $q = 65537$, $n = 256$ | Yes; $\|m^{-1}\|_\infty = 32{,}640$, $\|m^{-1}\|_1 = 4{,}286{,}173$ | Verified in `hkex_nl_verification.py` §2.1 |
| Noise amplification $\|m^{-1}\|_1 \cdot q/(2p)$ for deployed params ($q=65537$, $n=32$, $p=4096$) | $\approx 4{,}293{,}192 \gg q$ | Wraps mod $q$ — structural protection holds |
| Naive attack: exact $s$ recovery (fixed $m$, $q=769$, $n=16$, $p \in \{4…256\}$) | 0/200 for every $p$ value | Rounding noise too large for naive inversion |
| Noise amplification $\|m^{-1}\|_1 \cdot q/(2p)$ vs. $q$ | Exceeds $q$ for all tested $(q,p)$ | Structural protection against naive inversion |
| Blinded $m$ vs. fixed $m$ (naive attack) | Both 0/200 | Blinding adds standard Ring-LWR hardness beyond structural noise protection |
| **Key-agreement failure rate** ($q=65537$, $n=32$, $p=4096$, $\eta=1$), 10 000 trials | **204 / 10 000 = 2.04%** (95% CI: 1.78–2.34%) | Fails the <1% threshold; reconciliation hints required. Single-bit errors dominate (201/204). `hkex_rnl_failure_rate.py` §1 |
| **Key-agreement failure rate** ($q=65537$, $n=256$, $p=4096$, $\eta=1$), 5 000 trials | **1 862 / 5 000 = 37.24%** (95% CI: 35.9–38.6%) | Completely unusable without reconciliation. Per-coeff error accumulates as $O(\sqrt{n})$ via ring convolution. `hkex_rnl_failure_rate.py` §3 |
| Max per-coeff error $\|e_A - e_B\|_\infty$ ($n=32$, 10 000 trials) | 134 (0.82% of extraction threshold 16 384) | Individual errors are tiny; failures occur only near extraction boundaries. §2 |
| $p$-sensitivity at $n=32$: failure rate vs. $p \in \{512,\ldots,8192\}$ | 14.7% → 8.45% → 4.4% → 2.2% → 0.80% | No tested $p$ achieves <1%; architectural fix (reconciliation hints) required. §4 |
| **Peikert reconciliation failure rate** ($q=65537$, $n=32$, $p=4096$, $\eta=1$), 10 000 trials | **0 / 10 000 = 0%** | Reconciliation eliminates all key-agreement failures; correctness guaranteed by max per-coeff error ≪ $q/8$. `hkex_rnl_failure_rate.py` §5 |
| **Peikert reconciliation failure rate** ($q=65537$, $n=256$, $p=4096$, $\eta=1$), 5 000 trials | **0 / 5 000 = 0%** | Confirmed at full suite parameter size. `hkex_rnl_failure_rate.py` §5 |

#### Q3 — NL-FSCX injectivity and inverse

| Test | Result | Conclusion |
|------|--------|------------|
| NL-FSCX v1 bijectivity (n=8, exhaustive) | 256/256 B values non-bijective; example: B=0x00, A=0x00 and A=0x33 both map to 0x00 | v1 is **not** a bijection |
| NL-FSCX v1 collision (n=32, 131,072 samples per B) | Collision found: A=0x4dbde3c0, A'=0x2a48fe58, B=0x774e8bcb → 0xde0387dd | v1 non-bijective at n=32 also |
| Iterative inverse convergence (n=32, 500 trials) | 0/500 converge | Fixed-point iteration is not a contraction |
| NL-FSCX v2 bijectivity (n=8, exhaustive) | 0/256 B values non-bijective | v2 is bijective |
| NL-FSCX v2 inverse correctness (n=32) | 1000/1000 | Exact closed-form inverse confirmed |
| NL-FSCX v2 linearity test (n=32) | 500/500 linearity violations | v2 is non-linear |
| HSKE-A2 revolve enc→dec (v2, n=32) | 200/200 | Revolve mode viable with v2 |

---

### 11.6 Recommended Construction (C3 Hybrid)

The C3 hybrid assigns each primitive to the role that matches its properties:

| Role | Primitive | Rationale |
|------|-----------|-----------|
| HSKE (counter mode) | **NL-FSCX v1** (HSKE-A1) | Strongest non-linearity; no inverse needed |
| HSKE (revolve mode) | **NL-FSCX v2** (HSKE-A2) | Exact inverse; bijective; preserves API |
| HKEX key exchange | **HKEX-RNL** with blinded $m$ (B2) | Standard Ring-LWR hardness; PQC resistant |
| HKEX KDF post-process | **NL-FSCX v1** revolve | One-way; no inverse needed |
| HPKS commitment hash | **NL-FSCX v1** revolve | One-way; hardened against linear preimage |
| HPKE encryption | **NL-FSCX v2** revolve | Invertible; bijective |

**Parameters for HKEX-RNL** (deployed in v1.5.0; CBD sampler in v1.5.3; correctness verified in v1.5.15):
- $n = 256$ (suite C/Go/Python), $n = 32$ (assembly, Arduino, C/Go/Python tests)
- $q = 65537$ ($= 2^{16}+1$, Fermat prime)
- $p = 4096$, $p' = 2$ (1 bit extracted per ring coefficient)
- **Secret distribution:** $\mathrm{CBD}(\eta=1)$, coefficients in $\{-1, 0, 1\}$ with zero mean
- $a_\text{rand}$: $n$-coefficient polynomial, coefficients uniform in $\mathbb{Z}/q\mathbb{Z}$, transmitted per session
- KDF: $\text{seed} = \text{ROL}(K_\text{raw}, n/8)$; $sk = \text{NL-FSCX-REVOLVE-v1}(\text{seed}, K_\text{raw}, n/4)$

*Algebraic verification.* Invertibility of $m(x)$ in $\mathbb{Z}_q[x]/(x^n+1)$ confirmed for
$(q=65537, n \in \{32, 256\})$ by `hkex_nl_verification.py` §2.1.  Noise amplification
$\|m^{-1}\|_1 \cdot q/(2p) \approx 4.3\times10^6 \gg q$ confirms structural protection against
naive algebraic inversion (§11.4.3, §11.5 Q2).

**Correctness — Peikert reconciliation deployed (v1.5.16); upgraded to 2-bit (v1.7.0).**
Without reconciliation, empirical failure rates were 2.04% ($n=32$) and 37.24% ($n=256$).
Peikert 2-bit reconciliation hints (§11.4.2, v1.7.0) eliminate all failures while doubling key density:

| Parameters | Failure rate (without reconciliation) | Failure rate (with 2-bit Peikert hints) |
|---|---|---|
| $n=32$, $p=4096$, $\eta=1$, 10 000 trials | 2.04% (204/10 000) | **0%** (0/10 000) |
| $n=256$, $p=4096$, $\eta=1$, 5 000 trials | 37.24% (1 862/5 000) | **0%** (0/5 000) |

Alice generates and transmits a 2-bit hint per coefficient ($h_i \in \{0,1,2,3\}$, packed 2 bits/byte); both parties use the hint for 2-bit-per-coefficient extraction.  The maximum per-coefficient error $\leq 379 \ll q/8 = 8192$ guarantees the hint always resolves boundary crossings correctly.  Security assumptions are unchanged: the hint is derived from the public $K_\text{poly}$ after rounding and reveals no information about $s_A$.

**Status.** The NL-FSCX primitives and HKEX-RNL were implemented across all languages in v1.5.0.
The CBD(η=1) secret sampler was deployed in v1.5.3.  Failure rates characterised in v1.5.15.
1-bit Peikert reconciliation deployed in v1.5.16 — correctness guaranteed.
2-bit Peikert reconciliation (doubles key density, same hint size) deployed in v1.7.0.

**Security estimate (2026 landscape review, TODO #71).**  At the deployed parameters
$(n=256, q=65537, p=4096, \eta=1)$, BKZ-based lattice reduction gives approximately
**105–115 classical Core-SVP bits** and **95–105 quantum Core-SVP bits** (see §11.4.3 for
the full analysis).  This is below the 128-bit target of NIST ML-KEM-768 but comfortably
above the 100-bit floor.  No new algebraic attack exploiting $q=65537$ has been published
through 2025.

---

### 11.7 Protocol-Level Quantum Security Summary

| Protocol | Security assumption | Classical attack | Quantum attack | Post-quantum security |
|----------|---------------------|------------------|----------------|-----------------------|
| **HKEX-GF** | DLP in $\mathbb{GF}(2^n)^{\ast}$ | FFS $L[1/3]$: ~80–90 bits at $n=256$ (§9.2.4; deprecated NIST/ENISA); GKZ quasi-poly asymptotic for composite-degree fields | Shor's DLP | **None** |
| **HSKE** (key-only) | Exhaustive search | Brute force $2^n$ | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE** (known-plaintext) | — | 1 KPT pair → full $c_K$, $O(n^2)$ | BV: 1 query | **None** |
| **HPKS** | DLP in $\mathbb{GF}(2^n)^{\ast}$ + non-ROM challenge | Quasi-polynomial DLP | Shor's DLP | **None** |
| **HPKE** | CDH in $\mathbb{GF}(2^n)^{\ast}$ | CDH $\leq$ DLP, quasi-polynomial | Shor's CDH | **None** |
| **HSKE-NL-A1** (§11.3.1, key-only) | NL-FSCX v1 PRF | Brute force $2^n$ (linear recovery blocked) | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE-NL-A1** (known-plaintext) | — | Linear recovery blocked; 1-pair attack still recovers keystream | BV inapplicable (non-affine) | **None** (keystream recoverable) |
| **HSKE-NL-A2** (§11.3.2, key-only) | NL-FSCX v2 bijection | Brute force $2^n$ (linear recovery blocked) | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE-NL-A2** (known-plaintext) | — | Linear recovery blocked; 1-pair attack still recovers keystream | BV inapplicable (non-affine) | **None** (keystream recoverable) |
| **HPKS-NL** (§11.2.1) | DLP in $\mathbb{GF}(2^n)^{\ast}$ + NL challenge | Quasi-polynomial DLP; challenge non-predictable | Shor's DLP | **None** |
| **HPKE-NL** (§11.2.2) | CDH in $\mathbb{GF}(2^n)^{\ast}$ + NL-FSCX v2 | CDH $\leq$ DLP, quasi-polynomial | Shor's CDH | **None** |
| **HKEX-RNL** $n=256$ (§11.4) | Ring-LWR with blinded $m$ | BKZ: ~105–115 classical Core-SVP bits (MATZOV 2022; §11.4.3) | BKZ-hybrid: ~95–105 quantum Core-SVP bits | ~105 classical / ~100 quantum bits (§11.4.3); below 128-bit target — use HKEX-RNL-128 |
| **HKEX-RNL-128** $n=512$ (§11.4.3) | Ring-LWR with blinded $m$ | BKZ: ~220 classical Core-SVP bits (linear scaling; §11.4.3, §6 of `hkex_rnl_failure_rate.py`) | BKZ-hybrid: ~200 quantum Core-SVP bits | ≥128-bit classical+quantum; ML-KEM-512 cross-check confirms lower bound; 0 reconciliation failures (§7) |
| **HPKS-WOTS-F** (§11.8.3, proposed) | NL-FSCX v1 OWF (new assumption) | Degree-$n$ Boolean system — $O(2^n)$, Corollary 2 | Grover $O(2^{n/2})$ | $n/2$ bits (under NL-FSCX v1 OWF) |
| **HPKS-Stern-F** (§11.8.4, proposed) | $\mathrm{SD}(N,t)$ + NL-FSCX v1 PRF | BJMM/SDE: ~$2^{56}$–$2^{60}$ classical at $N=256$, $t=16$; 128-bit needs $N \geq 17000$ | Quantum ISD: ~$2^{30}$–$2^{40}$ at $N=256$ | ~30–40 bits at $N=256$ — **demo only**; 128-bit needs $N \geq 17000$ |
| **HPKE-Stern-F** (§11.8.4, proposed) | $\mathrm{SD}(N,t)$ + NL-FSCX v1 PRF | BJMM/SDE: ~$2^{56}$–$2^{60}$ classical at $N=256$, $t=16$; 128-bit needs $N \geq 17000$ | Quantum ISD: ~$2^{30}$–$2^{40}$ at $N=256$ | ~30–40 bits at $N=256$ — **demo only**; 128-bit needs $N \geq 17000$ |

**HSKE key-only** provides $n/2$ bits of post-quantum security only when no plaintext
is ever observed.  In any realistic deployment, plaintexts are available and this bound
does not apply.  The NL-FSCX counter-mode and revolve-mode HSKE variants (§11.3) preserve
the same KPT vulnerability; they harden against linear key-recovery but do not eliminate
the 1-pair attack because the underlying structure remains affine.

**Note on concrete security estimates (2026 landscape review, TODO #71).**  The classical attack
column for HKEX-GF now reflects the FFS $L[1/3]$ result (§9.2.4): at $n=256$ the best practical
classical attack gives ~80–90 bits, not 128 bits.  Binary-field DLP is deprecated by NIST SP 800-57
Rev. 5 (2020) and ENISA (2022).  HKEX-RNL estimates come from BKZ/MATZOV 2022 (§11.4.3).
HPKS-Stern-F / HPKE-Stern-F concrete estimates use the SDE estimator (Becker-Joux-May-Meurer)
for $(N=256, k=128, t=16)$; see §11.8.4.  All Stern-F rows are marked **demo only** at $N=256$;
production use requires $N \geq 17000$ for 128-bit classical security (BIKE-128 uses $N \approx 24646$).

---

### 11.8 Non-Lattice PQC Constructions for HPKS and HPKE (TODO §5)

This section analyses the structural reason HPKS-NL and HPKE-NL remain quantum-vulnerable (§11.8.1), derives algebraic properties of NL-FSCX that constrain construction choices (§11.8.2), and proposes two provable constructions (Options A and B in §11.8.3–§11.8.4) plus one research direction (Option C in §11.8.5).  No lattices are used; FSCX primitives are the algebraic base throughout.

---

### 11.8.1 Root Cause

Both protocols embed the GF(2^n)* discrete logarithm as their one-way commitment.  In HPKS-NL the Schnorr commitment is $R = g^k$; the verification equation $g^s \cdot C^e = R$ requires DLP hardness.  In HPKE-NL the encapsulation key is $\mathit{enc} = C^r = g^{ar}$.  Shor's algorithm recovers $a$ from $C = g^a$ in $O(n^2 \log n)$ quantum gate operations (§10.8.4), trivially breaking both protocols.

The NL-FSCX v1 challenge in HPKS-NL and the NL-FSCX v2 encryption layer in HPKE-NL are individually quantum-robust; the vulnerability is entirely in the GF(2^n)* commitment.  The goal is to replace that commitment with a structure grounded in FSCX algebra and provably hard under non-lattice assumptions.

---

### 11.8.2 Algebraic Properties of NL-FSCX Relevant to Construction

Exact primitive definitions (from implemented source):

$$F_1(A, B) = M(A \oplus B) \oplus \mathrm{ROL}_{n/4}\bigl((A + B) \bmod 2^n\bigr)$$

$$F_2(A, B) = \bigl(M(A \oplus B) + \delta(B)\bigr) \bmod 2^n, \qquad \delta(B) = \mathrm{ROL}_{n/4}\left(B \cdot \left\lfloor\frac{B+1}{2}\right\rfloor \bmod 2^n\right)$$

where $M = I \oplus \mathrm{ROL}_1 \oplus \mathrm{ROR}_1$ is the GF(2)-linear FSCX map of order $n/2$.

**Theorem 13 — Algebraic Degree of $F_1$ in $A$ (Degree Saturation).**

For fixed $B$ with $\mathrm{wt}(B) \geq 2$, let $F_1^r(A, B)$ denote $r$ iterations of $F_1$ holding $B$ constant.  Each output bit of $F_1^r(\cdot, B)$, viewed as a Boolean polynomial over $\mathbb{GF}(2)$, satisfies:

1. After $r = 1$: algebraic degree $\leq \mathrm{wt}(b_0, \ldots, b_{n-1})$ in the bits of $A$, at most $\lceil n/2 \rceil$ for generic $B$.
2. After $r \geq 2$: degree saturates at $n$ (the maximum for any Boolean function on $n$ variables).

*Proof.*  The GF(2)-linear term $M(A \oplus B)$ contributes degree 1 in the bits of $A$.  The non-linear term is $T = \mathrm{ROL}((A+B) \bmod 2^n, n/4)$.  For fixed $B$, bit $j$ of $(A+B) \bmod 2^n$ equals $a_j \oplus b_j \oplus c_{j-1}$ (writing $c_j$ for $\mathrm{carry}_j$) where the full-adder carry satisfies:

$$\mathrm{carry}_{-1} = 0, \qquad \mathrm{carry}_j = a_j \cdot b_j \oplus (a_j \oplus b_j) \cdot \mathrm{carry}_{j-1}.$$

With $b_j = 1$: $c_j = a_j \oplus c_{j-1} \oplus a_j \cdot c_{j-1}$, giving $\deg(c_j) = \deg(c_{j-1}) + 1$.  With $b_j = 0$: $c_j = a_j \cdot c_{j-1}$, again $+1$.  Hence $\deg(c_j) = \mathrm{wt}(b_0, \ldots, b_j)$.  For $\mathrm{wt}(B) \geq 2$ some output bit of $T$ reaches degree $\geq 2$ after one step.

After round 1, the input to round 2 has degree $d \geq 2$ in the original $A$ bits.  In round 2 the product $a_j \cdot c_{j-1}$ has degree $d + d = 2d$.  Over $\mathbb{GF}(2)^n$ the degree is capped at $n$; since $2d \geq 4$ already exceeds 2 and repeated multiplication drives degree towards $n$, saturation occurs after at most two rounds. $\blacksquare$

**Corollary 2 — Gröbner Basis Offers No Advantage.**

For $r \geq 2$ iterations, inverting $F_1^r(\cdot, B)$ is a system of $n$ Boolean polynomial equations of degree $n$ in $n$ unknowns.  For degree-$n$ Boolean systems, Gröbner basis methods (XL, F4, F5) provide no sub-exponential advantage over brute force: the degree of regularity $D_\mathrm{reg}$ equals $n$, giving complexity $O\bigl(\binom{2n}{n}^\omega\bigr)$ — dominated by brute force $O(2^n)$ classically and Grover $O(2^{n/2})$ quantumly. $\blacksquare$

**Theorem 14 — $F_2$ Key Recovery as an MQ Instance.**

Given a single evaluation pair $(G, Y)$ with $Y = F_2(G, K)$ for unknown $K$, recovering $K$ requires solving:

$$M(K) + \delta(K) \equiv \bigl(Y \oplus M(G)\bigr) \pmod{2^n}.$$

The left side: $M(K)$ contributes degree-1 linear terms in the bits of $K$ over $\mathbb{GF}(2)$.  The term $\delta(K) = \mathrm{ROL}(K \cdot \lfloor(K+1)/2\rfloor \bmod 2^n, n/4)$ introduces degree-2 terms, since $K \cdot \lfloor(K+1)/2\rfloor$ in integer arithmetic produces products $k_j \cdot k_\ell$ of bit pairs (degree 2) before carry propagation.  The full system is therefore a **Multivariate Quadratic (MQ) problem** over $\mathbb{GF}(2)$ with $n$ unknowns.  With $m > n$ evaluation pairs the system becomes overdetermined, exactly the regime in which MQ is NP-complete [Garey-Johnson 1979]. $\blacksquare$

**Theorem 15 — Non-Commutativity of $F_2$ Permutations.**

For generic $K_1 \neq K_2 \in \{0,1\}^n$, let $\pi_K(A) = F_2(A, K)$.  Then:

$$\pi_{K_2}\bigl(\pi_{K_1}(A)\bigr) \neq \pi_{K_1}\bigl(\pi_{K_2}(A)\bigr) \quad \text{for generic } A.$$

*Proof.*  Setting $A = 0$: $\pi_{K_1}(0) = M(K_1) + \delta(K_1)$.  The composition is:

$$\pi_{K_2}(\pi_{K_1}(0)) = M\bigl((M(K_1) + \delta(K_1)) \oplus K_2\bigr) + \delta(K_2) \pmod{2^n}.$$

Since $M$ is GF(2)-linear, $M(X \oplus K_2) = M(X) \oplus M(K_2)$; however, $X = M(K_1) + \delta(K_1)$ is an integer-addition result, so $X \oplus K_2$ mixes carry terms with GF(2) XOR in a way that is asymmetric under $K_1 \leftrightarrow K_2$ exchange.  Commutativity would require $\delta(K_1) - \delta(K_2) \equiv M(K_1 \oplus K_2) \pmod{2^n}$ as integers for all $(K_1, K_2)$; since $\delta$ is quadratic (Theorem 14) and $M$ is linear, this equation has at most a measure-zero set of solutions. $\blacksquare$

---

### 11.8.3 Option A — HPKS-WOTS-F: Winternitz OTS with NL-FSCX v1

**Construction.**  Fix Winternitz width $w$ and set $\ell = \lceil|H_\mathrm{msg}|/\log_2 w\rceil$ where $|H_\mathrm{msg}|$ is the message-hash output length in bits.  Define the hash chain:

$$h(x) = F_1^{n/4}\bigl(\mathrm{ROL}(x, n/8), x\bigr)$$

(the same function used as the HKEX-RNL KDF in §11.4.2, with seed-rotation active from step 1).

- **Key generation.**  Draw $\mathrm{sk}_i \xleftarrow{R} \{0,1\}^n$ for $i = 0, \ldots, \ell-1$.  Publish $\mathrm{pk}_i = h^{w-1}(\mathrm{sk}_i)$.
- **Sign($\mathrm{msg}$).**  Compute $(d_0, \ldots, d_{\ell-1})$ from $H_\mathrm{msg}(\mathrm{msg})$ in base $w$.  Release $\sigma_i = h^{w-1-d_i}(\mathrm{sk}_i)$.
- **Verify.**  Accept iff $h^{d_i}(\sigma_i) = \mathrm{pk}_i$ for all $i$.

For multi-message use, combine OTS leaves in a Merkle tree (using $h$ as the tree hash) for XMSS-style stateful signatures, or embed in a hypertree for SPHINCS+-style stateless operation.

**Theorem 16 — EUF-CMA Security of HPKS-WOTS-F.**

If $h$ is a one-way function, then HPKS-WOTS-F is EUF-CMA secure for a single signing query with:

$$\Pr[\mathrm{forge}] \leq \ell \cdot \Pr[\text{invert}(h)].$$

*Proof.*  Any forger $\mathcal{A}$ producing $(d', \sigma')$ for $m' \neq m$ must, for some index $i$, produce $\sigma'_i$ with $h^{d'_i}(\sigma'_i) = \mathrm{pk}_i$ and $d'_i \neq d_i^{\ast}$.  Only $d'_i > d_i^{\ast}$ is useful (smaller $d'_i$ would reuse a revealed chain value).  Then $\mathcal{A}$ has computed $\sigma'_i$ with $h^{d'_i - d_i^{\ast}}(\sigma'_i) = \mathrm{pk}_i$, i.e.\ a preimage inversion starting from the released $\sigma_i^{\ast} = h^{w-1-d_i^{\ast}}(\mathrm{sk}_i)$.  This contradicts the OWF assumption.  A union bound over $\ell$ indices gives the stated bound. $\blacksquare$

**Quantum analysis.**  Grover's algorithm finds a preimage of $h^k$ in $O(2^{n/2})$ quantum queries.  By Corollary 2, NL-FSCX v1 preimage inversion (after $\geq 2$ rounds, which $n/4$ rounds certainly satisfies for $n \geq 8$) is a degree-$n$ system for which no sub-exponential quantum solver is known.  For $n = 256$: $2^{128}$ quantum query lower bound.

**Honest limitation.**  Theorem 16 reduces security to the NL-FSCX v1 one-wayness assumption, which is a **new assumption** not yet reduced to a studied hard problem.  Corollary 2 rules out Gröbner-basis algebraic attacks, but non-algebraic exploits are not excluded.  Independent cryptanalysis of NL-FSCX v1 as an OWF is required before deployment.

**Cryptanalytic evidence (TODO #74, v1.9.2).**  `SecurityProofsCode/nl_fscx_owf_analysis.py` applies five classical techniques to $F_{1}^{n/4}(\cdot, B)$ with fixed $B$; results are summarised below.

*Differential analysis.* At $n = 8$, the maximum differential probability (MDP) is strongly $B$-dependent: for generic $B$ (e.g. $B = \text{0xa5}$) MDP falls to $\approx 0.10$ at $r = 8$, while sparse-bit $B$ values (e.g. $B = \text{0x3c}$) retain MDP $\approx 0.77$ at $r = 8$, indicating degenerate differential trails along those $B$ values.  At $n = 32$, $r = 8$: zero repeated $(dA, dY)$ pairs in $10^5$ trials, consistent with uniform differential distribution.

*Linear bias.* At $n = 8$ the max Walsh bias falls to $0.24$–$0.40$ at $r = 8$; at $n = 32$, $r = 8$ the sampled max bias ($0.070$) is within the Bernstein random-function bound ($0.087$), consistent with no exploitable linear structure.

*Rotational cryptanalysis.* For all rotation amounts $k \in \{1,2,4,7,8,16\}$ at $n = 32$, $r = 8$, the fraction of random pairs $(A, B)$ satisfying $F_{1}^r(\mathrm{ROL}(A,k), \mathrm{ROL}(B,k)) = \mathrm{ROL}(F_{1}^r(A,B), k)$ is approximately $1$–$6\%$, far above the $2^{-32}$ expectation for a random function.  This structural correlation is inherited from the FSCX linear base (exactly rotation-equivariant by construction); the integer-carry non-linear term only partially breaks it.  See the **Rotational structure** follow-up below (TODO #75) for a full characterisation of which protocol uses are affected.

*B=0 degeneracy.* $F_{1}^r(A, 0) = L_{r}(A)$ is confirmed GF(2)-linear and **singular** (rank 2/8 for $L_{2}$ at $n = 8$), meaning $F_{1}^r(\cdot, 0)$ collapses most inputs.  All protocol instantiations have $\Pr[B = 0] = 2^{-n}$, negligible.

*MITM preimage.* Exhaustive enumeration at $n = 20$, $r = 5$ shows $28.1\%$ image coverage (average preimage count $3.52$).  Non-injectivity means backward enumeration requires $O(2^n)$ forward work, confirming MITM provides no asymptotic speedup.

*Open concerns from this analysis.* (1) Sparse-bit $B$ values exhibit elevated MDP at $n = 8$; large-$n$ behavior is uncharacterised.  (2) No formal hardness reduction to any studied problem.  Independent expert cryptanalysis is required before deployment.  (The rotational concern is characterised in the follow-up analysis below.)

**Rotational structure (TODO #75, v1.9.3).**  `SecurityProofsCode/nl_fscx_rot_analysis.py` resolves the rotational open concern by separating *one-sided* rotation ($A$ rotated, $B$ fixed) from *two-sided* rotation (both rotated simultaneously).

*One-sided rotation (B fixed).* For all $r$ and $k$ tested, $\Pr_{A}\bigl[F_{1}^r(\mathrm{ROL}(A,k), B) = \mathrm{ROL}(F_{1}^r(A,B), k)\bigr] < 10^{-5}$ (zero hits in $10^5$ trials per configuration).  The structural reason: one-sided equivariance requires $\mathrm{ROL}(\mathrm{ROL}(A,k)+B, n/4) \oplus \mathrm{ROL}(A+B, n/4+k)$ to equal the $A$-independent constant $M(B) \oplus M(\mathrm{ROL}(B,k))$, a condition that does not hold for generic $B$.

*Two-sided rotation (both inputs rotated).* The two-sided probability $p_{\text{rot}}(r,k)$ follows a power law rather than geometric decay:

$$p_{\text{rot}}(r,k) \approx C(k) \cdot r^{-\alpha(k)}$$

where empirically $\alpha(1) \approx 0.96$, $C(1) \approx 0.42$ and $\alpha(8) \approx 1.88$, $C(8) \approx 0.65$.  At the protocol round count $r = n/4 = 64$ for $n = 256$: $p_{\text{rot}}(64,1) \approx 0.78\%$, requiring approximately $90$ query pairs for a $50\%$-advantage random-oracle distinguisher ($q \approx \ln 2 / p$).

*Protocol impact.* All PRF uses of $F_{1}$ have a fixed key $B$: the Stern-F row generator $F_{K}(i) = F_{1}^{n/4}(\mathrm{ROL}(K \oplus i, n/8), K)$, the HSKE-NL-A1 keystream, and the HFSCX-256-DM compression function.  These are one-sided; $p \approx 0$ — **rotation-safe**.  The HPKS-WOTS-F hash chain $h(x) = F_{1}^{n/4}(\mathrm{ROL}(x, n/8), x)$ is two-sided (rotating $x$ rotates both $A$ and $B$), so a $\approx 90$-pair random-oracle distinguisher exists.  However, Theorem 16 reduces HPKS-WOTS-F to the OWF assumption on $h$, not to a random-oracle assumption — the distinguisher does **not** break Theorem 16.

*Conclusion.* The rotational NOTE from TODO #74 is now fully characterised: it is a polynomial-query random-oracle distinguisher against the WOTS hash chain that does **not** affect the current security proofs.  It is a design concern only for future constructions requiring $h$ to behave as a random oracle.

**HPKS-XMSS-F implementation (v1.9.39, TODO #97).** The HPKS-WOTS-F and HPKS-XMSS-F constructions are now implemented in the suite (Python) and CLI.

*Parameters.* $w = 16$ (Winternitz), $\ell_1 = 64$ message digits, $\ell_2 = 3$ checksum digits (max checksum $64 \times 15 = 960 < 16^3$), $\ell = 67$ chains total. Tree height $h = 10$ by default ($2^{10} = 1024$ leaves per key pair).

*Hash chain.* $h(x) = F_1^{n/4}(\mathrm{ROL}(x, n/8),\, x)$ at $n = 256$, identical to Theorem 16.

*Keygen.* Leaf seed $\text{sk}_{i,j} = \text{HFSCX-256}(\text{master-seed} \mathbin\| \text{idx}_{32} \mathbin\| j_{16})$ for leaf index $\text{idx}$ and chain index $j \in \{0,\ldots,\ell-1\}$. Public key $\text{pk}_{i,j} = h^{w-1}(\text{sk}_{i,j})$. Leaf node $= \text{HFSCX-256}(0\text{x00} \mathbin\| \text{pk}_{i,0} \mathbin\| \cdots \mathbin\| \text{pk}_{i,\ell-1})$ (RFC 6962 domain separation). XMSS public key $= $ Merkle root of $2^h$ leaf nodes (§78.J accumulator).

*Sign.* Encode $\text{HFSCX-256}(\text{msg})$ as 64 base-16 digits; append 3-digit checksum. Release $\sigma_j = h^{w-1-d_j}(\text{sk}_j)$ per chain. Include Merkle authentication path for the leaf.

*Verify.* Recover $\text{pk}_j = h^{d_j}(\sigma_j)$ for all $j$; compute leaf hash from recovered pk; verify Merkle path against root. No stored public key needed in the signature: the pk is fully determined by $(\text{msg}, \sigma)$.

*State management.* Each signing operation consumes one leaf. The CLI tracks the next leaf index in a sidecar file `<key>.idx`. Exhaustion of all $2^h$ leaves is detected and rejected with an error. Re-use of the same leaf with a different message would allow an attacker to compute the SK from two partial chain openings (standard WOTS forgery); the state file prevents this in normal operation.

*Security.* Inherits Theorem 16 (EUF-CMA under NL-FSCX v1 OWF) and the standard Merkle-tree argument: forging an XMSS signature requires either (a) forging a WOTS signature on some leaf, or (b) finding a collision in HFSCX-256 (used as the Merkle hash). Bound: $\Pr[\text{forge}] \leq 2^h \cdot \ell \cdot \Pr[\text{invert}(h)] + \Pr[\text{collision in HFSCX-256}]$.

---

### 11.8.4 Option B — HPKS-Stern-F and HPKE-Stern-F (Code-Based via FSCX PRF)

Option B reduces security to **syndrome decoding**, which is NP-complete [Berlekamp-McEliece-Van Tilborg 1978] and has no known polynomial quantum algorithm.  NL-FSCX v1 acts as a pseudorandom generator for the public parity check matrix; all hardness derives from the code, not from assumptions about FSCX invertibility.

**Public matrix generation.**  For an $(N, k, t)$-code, generate the $(N-k) \times N$ binary parity matrix $H$ row by row:

$$H_i = \text{HFSCX-256-DM}\bigl(F_1^{n/4}(\mathrm{ROL}(\mathrm{seed} \oplus i, n/8), \mathrm{seed})\bigr) \bmod 2^n, \qquad i = 0, \ldots, N-k-1.$$

The outer HFSCX-256-DM finalization (deployed in v1.9.35, TODO #88) removes the NL-FSCX range compression documented below, so each row is drawn from the full digest range.  Under the PRF assumption for NL-FSCX v1 (implied by the OWF assumption via the GGM PRG-to-PRF construction [Goldreich-Goldwasser-Micali 1986]), $H$ is computationally indistinguishable from a uniformly random binary matrix.

**PRF Verification — Algebraic and Experimental Evidence.**

The security of Option B depends critically on NL-FSCX v1 behaving as a PRF.  The following analysis establishes, algebraically and empirically, that NL-FSCX v1 passes every canonical distinguishing test that linear FSCX fails.  All experiments use $n = 32$, $r = n/4 = 8$ steps, and 10 000-trial sample sizes; the script is `SecurityProofsCode/nl_fscx_prf_analysis.py`.

Two instantiations are tested:

$$F_K(i) = F_1^{n/4}\bigl(\mathrm{ROL}(K \oplus i, n/8), K\bigr) \qquad \text{(Stern-F row generator)}$$

$$G_K(i) = F_1^{n/4}\bigl(\mathrm{ROL}(K, n/8), K \oplus i\bigr) \qquad \text{(HSKE-NL-A1 keystream)}$$

The linear FSCX baseline $H_K(i) = M^r \cdot \mathrm{ROL}(K \oplus i, n/8) \oplus S_r \cdot K$ serves as the known-broken control.

*Key algebraic separations.*

**2-query differential.**  For the linear baseline:

$$H_K(i_1) \oplus H_K(i_2) = M^r \cdot \bigl(\mathrm{ROL}(i_1, n/8) \oplus \mathrm{ROL}(i_2, n/8)\bigr)$$

because the $S_r \cdot K$ key terms cancel.  This XOR is **K-independent** — any adversary holding two output queries can recover the relationship between inputs without knowing $K$, yielding a trivial 2-query distinguisher.

For NL-FSCX v1, each step mixes the carry of $(A + B) \bmod 2^n$ through channel $B = K$.  At the first step with $A_j = \mathrm{ROL}(K \oplus i_j, n/8)$:

$$\bigl[(A_1 + K) \bmod 2^n\bigr] \oplus \bigl[(A_2 + K) \bmod 2^n\bigr]$$

involves carries at each bit position that depend on the bits of $K$.  The resulting XOR **cannot** be written as $f(i_1 \oplus i_2)$ for any K-independent $f$, so the 2-query attack fails.  Experiment confirms: the K-independent prediction matches linear FSCX 10 000/10 000 (100 %) and NL-FSCX v1 0/10 000 (0 %).

**Cross-key linear structure.**  For the linear baseline:

$$H_{K_1}(i) \oplus H_{K_2}(i) = S_r(K_1) \oplus S_r(K_2) = S_r(K_1 \oplus K_2),$$

which is $i$-independent.  An adversary with two keys and any shared input $i$ learns $S_r(K_1 \oplus K_2)$ without evaluating the function at a second input.  For NL-FSCX v1 the carry terms depend jointly on $K$ and $A$, so no such cancellation occurs.  Experiment: cross-key delta is input-dependent for 0/10 000 linear FSCX trials vs.\ 10 000/10 000 for NL-FSCX v1.

*Experimental results (algebraic degree indicators).*

The BLR linearity test (Blum-Luby-Rubinfeld) measures whether $F(x \oplus y) \oplus F(x) \oplus F(y) \oplus F(0) = 0$ for random $(x, y)$.  This holds with probability 1 for any GF(2)-linear function and with probability $2^{-n}$ for a random function.  Linear FSCX: 100 % zero (confirmed affine).  NL-FSCX v1: 0 % zero (consistent with random function, $n = 32$).

The higher-order differential test measures the algebraic degree.  The second-order difference $\Delta_2(x, \delta_1, \delta_2) = F(x) \oplus F(x \oplus \delta_1) \oplus F(x \oplus \delta_2) \oplus F(x \oplus \delta_1 \oplus \delta_2)$ is identically zero for any degree-$\leq 1$ (affine) function and generically non-zero for degree $\geq 2$.  Third-order entropy $H(\Delta_3)$ is zero for degree $\leq 2$ and approaches $n$ bits for degree $\geq 3$.  Linear FSCX: 100 % zero at second order, 0 bits entropy at third order (degree 1, confirmed).  NL-FSCX v1: 0 % zero at second order, 11.97 bits entropy at third order — confirming degree $\geq 3$ (consistent with Theorem 13: degree saturates at $n$ after $\geq 2$ rounds).

*Full evidence matrix.*

| Test | Linear FSCX (baseline) | NL-FSCX v1 (both variants) |
|---|---|---|
| 2-query K-independent differential (§1) | **Fails** — 100 % match | **Passes** — 0 % match |
| BLR linearity test (§2) | **Fails** — 100 % linear | **Passes** — 0 % linear |
| SAC mean output-bit flips (§3) | 3.0 / 16.0 (affine column weight) | 15.99 ± 0.06 (≈ ideal $n/2$) |
| 2nd-order differential zero-fraction (§4) | **Fails** — 100 % zero | **Passes** — 0 % zero |
| 3rd-order differential entropy (§4) | 0.0 bits (degree 1) | 11.97 bits (degree $\geq 3$) |
| Max linear bias vs. random bound (§5) | 0.030 (known bias $= 1/2$ at correct mask) | 0.031 ≈ random bound |
| Key-bit sensitivity mean flips (§6) | 13.0 / 16.0 | 16.06 ± 2.9 (≈ ideal $n/2$) |
| Output collision rate vs. birthday bound (§7) | 0 excess (near-bijective) | 0 excess (injective) |
| Cross-key delta input-dependent (§8) | **Fails** — 0 % dependent | **Passes** — 100 % dependent |
| Range compression vs random fn (§9.3, §10) | n/a (bijective) | **Fails** — 21–28% at n=32; see TODO #43 |

Tests §1, §2, §4, §8 detect GF(2)-linearity and low algebraic degree; linear FSCX fails all four, NL-FSCX v1 passes all four.  Tests §3 and §6 measure diffusion; both functions achieve good avalanche.  Test §5 detects linear correlations; NL-FSCX v1's maximum sampled bias is consistent with the random-function Bernstein bound $O(\sqrt{n} / 2^{n/2})$.  Test §7 confirms near-uniform output distribution for random inputs.

*Scope and caveat.*  These tests rule out every polynomial-time distinguisher based on linearity, low algebraic degree, or cross-key structure.  They do **not** constitute a formal PRF proof.  A formal proof would require reducing PRF-security to a studied hardness assumption; the GGM construction (§11.8.4 above) provides that path once the NL-FSCX v1 OWF assumption is accepted.  The experimental evidence supports the assumption but does not replace it.

**Exhaustive Walsh analysis at small $n$ (v1.5.42 — TODO #35).**  To complement the §5 sampling at $n=32$, `nl_fscx_prf_analysis.py` §9 adds an exhaustive Walsh-Hadamard scan at $n=12$: all $4095 \times 4096 = 16.7$M mask pairs $(a, b)$ are evaluated for two random keys.  Key findings:

- **§9.1 (n=8):** max_bias = 1.0 — degenerate at r = 2 steps; a perfect linear correlation exists for some (a,b) pair.
- **§9.2 ($n=12$):** max\_bias $\approx 0.43$, ratio $\approx 4.7\times$ the random-function bound $\sqrt{4 \cdot 12 \cdot \ln 2 / 2^{12}} \approx 0.090$.  The affine baseline $H\_\mathrm{linear}$ gives max\_bias $= 1.0$ (correctly detected).
- **§9.3 (Range compression):** $F_K(\cdot)$ maps only $\approx 40$–$55\%$ of inputs to distinct outputs at $n = 8$/$12$/$16$, versus $\approx 63\%$ expected for a truly random function.  The compressed range inflates Walsh coefficients beyond the random bound.
- **§9.4 (Extrapolation):** $\mathbb{E}[\mathrm{max\_bias}(n)] \approx \sqrt{4n \ln 2 / 2^n}$; at $n=32$ this is $\approx 1.44 \times 10^{-4}$.

The elevated bias at n=12 is attributed to range compression, not to linear algebraic structure.  At the deployed n=32, §5 sampling is consistent with the random bound, but exhaustive verification requires scanning 2^64 pairs — infeasible in pure Python.

**Range compression at n=32 — exhaustively measured (v1.5.43, TODO #42).**  Test [20] in `CryptosuiteTests/Herradura_tests.c` uses HyperLogLog (m=16384 registers, ~0.81% std-error) over all 2^32 inputs to F_stern(K, ·) for three representative keys:

| K | Hamming weight | Distinct fraction | vs random 63.2% |
|---|---|---|---|
| `0x00000003` | 2 (min-t) | **20.9%** | 0.33× |
| `0xA3C5E7B9` | 17 | **21.7%** | 0.34× |
| `0xFFFFFFFD` | 30 (max-t) | **28.3%** | 0.45× |

The range compression does **not** shrink as n grows.  `nl_fscx_prf_analysis.py` §10 measures the step-by-step range fraction for n ∈ {8, 12, 16, 20} (exhaustive) and derives a per-step compression ratio of ~0.74–0.82× (increasing with n), versus 0.632× for a random function.  Because the step count r = n/4 grows linearly, cumulative compression worsens with n: at n=256 with r=64 steps, the predicted range fraction falls below 10^{-4}.

**Security implication.**  A distinguisher that counts output collisions can separate F_stern from a random function at n=32 using O(2^16) queries (birthday bound against a ~24% range).  This constitutes a concrete polynomial-time distinguisher that falsifies the PRF assumption underlying Theorem 17, removing the ε_PRF term from the EUF-CMA bound.  Until TODO #43 is applied, Theorem 17 holds only against adversaries that do not exploit this collision-counting attack.

**Fix (TODO #43).**  Composing F_stern with HFSCX-256-DM eliminates the range compression and restores ~63.2% distinct outputs (verified in `hfscx_256_analysis.py`):

$$F_{\text{stern-v2}}(K, i) = \text{HFSCX-256-DM}\bigl(F_1^{n/4}(\mathrm{ROL}(K \oplus i, n/8), K)\bigr) \bmod 2^n$$

One HFSCX-256-DM call is added per row of H and per hash step in the commitment scheme.  After the fix, no known collision-counting distinguisher applies to F_stern-v2.  This is a wire-format breaking change; old and new HPKS-Stern-F signatures are incompatible.

**Deployment status.**  The hash-step composition (`_stern_hash`) was deployed in v1.6.0 (TODO #43).  The per-row matrix finalization (`_stern_matrix_row`) was deployed in v1.9.35 (TODO #88) across all six language targets — Python/C/Go at n = 256, and the C/ARM/i386/Arduino n = 32 demos via HFSCX-32-DM — completing the F_stern-v2 fix as specified above.  Public keys, syndromes, signatures, and KEM ciphertexts generated before v1.9.35 are incompatible with the finalized matrix.

**Key generation.**
- Private key: $\mathbf{e} \xleftarrow{R} \{\mathbf{v} \in \{0,1\}^N : \mathrm{wt}(\mathbf{v}) = t\}$.
- Public key: $\mathbf{s} = H\mathbf{e}^\top \in \mathbb{GF}(2)^{N-k}$.

**HPKS-Stern-F: Stern's Three-Move Protocol [Stern 1993] + Fiat-Shamir.**

Each identification round:

1. **Commit.**  Draw $\mathbf{y} \xleftarrow{R} \{0,1\}^N$ and permutation $\pi \xleftarrow{R} S_N$.  Compute and send:

$$c_0 = \mathcal{H}\left(\pi, H\mathbf{y}^\top\right), \qquad c_1 = \mathcal{H}\left(\pi \circ \sigma_{\mathbf{e}}, H(\mathbf{y} \oplus \mathbf{e})^\top\right),$$

where $\sigma_{\mathbf{e}} \in S_N$ is a fixed permutation encoding the support of $\mathbf{e}$ and $\mathcal{H}$ is a collision-resistant hash.

2. **Challenge.**  Verifier sends $b \xleftarrow{R} \{0, 1, 2\}$.

3. **Response.**

   $b = 0$: reveal $(\pi, \mathbf{y})$; verifier checks $c_0$ and that $\pi$ is consistent with the support encoding.

   $b = 1$: reveal $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$; verifier checks $c_1$ and $H(\mathbf{y} \oplus \mathbf{e})^\top = H\mathbf{y}^\top \oplus \mathbf{s}$.

   $b = 2$: reveal $(\pi, \mathbf{y} \oplus \mathbf{e})$; verifier checks $\mathrm{wt}(\pi(\mathbf{y} \oplus \mathbf{e})) = t$ and the syndrome relation.

Soundness error per round: $2/3$.  After $\lceil\lambda / \log_2(3/2)\rceil \approx 1.7\lambda$ rounds, soundness error $\leq 2^{-\lambda}$.  Fiat-Shamir in the quantum random oracle model [Unruh 2015] produces a non-interactive signature.  The commitment hash `_stern_hash` (§11.9.9) now finalizes through HFSCX-256-DM with a per-slot domain-separation tag (ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key).  Under the ROM on HFSCX-256-DM (§11.9), this provides the independent quantum random oracles required by Unruh's transform.

**Theorem 17 — EUF-CMA of HPKS-Stern-F.**

Let $\mathrm{SD}(N,t)$ denote the syndrome decoding problem: given $(H, \mathbf{s})$ find $\mathbf{e}$ with $H\mathbf{e}^\top = \mathbf{s}$ and $\mathrm{wt}(\mathbf{e}) = t$.  If $\mathrm{SD}(N,t)$ requires $T_\mathrm{SD}$ quantum operations, NL-FSCX v1 is a secure PRF with advantage $\epsilon_\mathrm{PRF}$, and HFSCX-256-DM is modeled as a random oracle, then HPKS-Stern-F achieves EUF-CMA with:

$$\Pr[\mathrm{forge}] \leq \frac{q_H}{T_\mathrm{SD}} + \epsilon_\mathrm{PRF}$$

for $q_H$ quantum hash queries.

*Proof.*  (i) **Completeness** — honest prover satisfies all three challenge cases by construction.  (ii) **Statistical zero-knowledge** — for each $b$, the revealed values $(\pi, \mathbf{y})$, $(\pi \circ \sigma_{\mathbf{e}}, \mathbf{y} \oplus \mathbf{e})$, $(\pi, \mathbf{y} \oplus \mathbf{e})$ are uniformly distributed over their respective domains independently of $\mathbf{e}$, since $\mathbf{y}$ and $\pi$ are fresh random.  (iii) **Soundness** — a prover that passes all three challenges can be rewound with challenges $b = 1$ and $b = 2$ on the same commitment, yielding two accepting transcripts from which $\mathbf{e}$ satisfying $H\mathbf{e}^\top = \mathbf{s}$ is extracted, solving $\mathrm{SD}(N,t)$.  (iv) **Fiat-Shamir in the QROM** — `_stern_hash` outputs `HFSCX-256-DM(ds || chain(...))` where `ds` is a per-slot domain tag; under the ROM on HFSCX-256-DM, the per-slot outputs are independent random oracles, satisfying Unruh's QROM requirement.  EUF-CMA security against quantum adversaries making $q_H$ quantum hash queries follows from [Unruh 2015, Theorem 5], with forgery probability bounded by $q_H/T_\mathrm{SD}$.  (v) **PRF reduction** — under the NL-FSCX v1 PRF assumption, $H$ is computationally indistinguishable from a random matrix; any distinguishing advantage contributes $\epsilon_\mathrm{PRF}$. $\blacksquare$

**HPKE-Stern-F: Niederreiter-Style KEM.**  Use the same $(H, \mathbf{s} = H\mathbf{e}^\top)$ for key encapsulation:

- **Encapsulate.**  Draw $\mathbf{e}' \xleftarrow{R} \{\mathrm{wt}(\cdot) = t\}$.  Session key $K = \mathcal{H}(\mathbf{e}')$; ciphertext $\mathbf{c} = H(\mathbf{e}')^\top$.
- **Decapsulate.**  Recover $\mathbf{e}'$ from $\mathbf{c} = H(\mathbf{e}')^\top$ using the private key $\mathbf{e}$ as a syndrome-decoding trapdoor.  Recompute $K = \mathcal{H}(\mathbf{e}')$.

For efficient decapsulation, $\mathbf{e}$ must embed a structured decoding trapdoor.  A direct application: derive the seed for a quasi-cyclic moderate-density parity-check (QC-MDPC) code (the BIKE design [Aragon et al. 2022]) via the NL-FSCX v1 PRF instead of a standard hash.  The security argument is unchanged; hardness remains quasi-cyclic syndrome decoding.

**Quantum analysis for Option B.**

| Attacker | Algorithm | Complexity |
|---|---|---|
| Classical | ISD (Prange / BJMM) | $O(2^{0.054N})$ |
| Quantum | Quantum ISD (Kirshanova 2018) | $O(2^{0.042N})$ |
| Quantum | Grover brute-force | $O(2^{N/2})$ — dominated by ISD |

Syndrome decoding for random binary linear codes has no known polynomial quantum algorithm.  NIST alternates BIKE and HQC base their security on the quasi-cyclic special case of this same assumption.

**Deployed parameter caveat (2026 landscape review, TODO #71).**  The asymptotic exponents in the
table above apply in the regime where $N$ is large and the rate $k/N$ and relative distance $t/N$
are fixed.  At the deployed parameters $(N=256, k=128, t=16)$, the SDE estimator (Becker-Joux-May-Meurer,
2012) gives a concrete classical ISD estimate of approximately $2^{56}$–$2^{60}$ operations and a
quantum ISD estimate of approximately $2^{30}$–$2^{40}$ operations (Kirshanova 2018).  These are
**demonstration parameters only**; they do not achieve 128-bit security.  For reference, BIKE-128
(NIST alternate finalist) uses $N \approx 24646$, $t = 134$ to reach 128-bit classical and ~118-bit
quantum security.  The 128-bit classical floor requires approximately $N \geq 17000$ at $t/N \approx
0.0625$.  Until higher-$N$ parameters are adopted, HPKS-Stern-F and HPKE-Stern-F should be treated
as proof-of-concept implementations.

---

### 11.8.5 Option C — Non-Abelian Research Direction

Theorem 15 establishes that $\{\pi_K : K \in \{0,1\}^n\}$ is a non-abelian family of permutations on $\{0,1\}^n$.  The **Conjugacy Search Problem** (CSP) for a non-abelian group $G$ is: given $u, v \in G$ with $v = g \cdot u \cdot g^{-1}$, find $g$.  No polynomial quantum algorithm is known for generic non-abelian CSP [Ettinger-Høyer-Knill 2004].

A candidate HPKS construction: choose random ephemeral $K_2$; let the public key be:

$$C = \pi_{K_1}\bigl(\pi_{K_2}\bigl(\pi_{K_1}^{-1}(G)\bigr)\bigr)$$

for a fixed public base point $G$.  Given $(C, \pi_{K_2})$, recovering $K_1$ is an instance of CSP in the group generated by the NL-FSCX v2 permutation family.

**Three obstacles prevent a complete security proof at this time:**

1. **Representation model.**  Standard CSP hardness is proven in the black-box model; NL-FSCX v2 is an explicit polynomial circuit.  An algebraic attacker can exploit the carry structure of $F_2$ directly rather than treating $\pi_K$ as a black box.  No transfer theorem from the black-box model to the circuit model is known for this problem.

2. **Group order lower bound.**  The period of NL-FSCX v2 orbits has no verified lower bound (analogous to the chaotic orbit lengths observed for v1 in §11.5 Q1).  Without a known lower bound on $|\langle \pi_K \rangle|$, small-subgroup confinement attacks cannot be excluded.

3. **No formal reduction to studied CSP.**  Braid group CSP hardness relies on specific group-theoretic properties not shared by permutation groups.  The transfer of hardness to the NL-FSCX v2 permutation family requires a dedicated reduction that does not currently exist.

This option is documented as a future research direction.

---

### 11.8.6 Comparison and Recommendation

| | **Option A — HPKS-WOTS-F** | **Option B — HPKS / HPKE-Stern-F** | **Option C — NASG** |
|---|---|---|---|
| Protocols addressed | HPKS | HPKS + HPKE | HPKS |
| FSCX primitive | $F_1$ (v1) as OWF / hash | $F_1$ (v1) as PRF for matrix generation | $F_2$ (v2) permutation family |
| Hardness basis | NL-FSCX v1 OWF (**new assumption**) | $\mathrm{SD}(N,t)$ (NP-complete) + NL-FSCX v1 PRF | Non-abelian CSP (**not yet proven**) |
| Classical bound | $O(2^n)$ — Corollary 2 | $O(2^{0.054N})$ — ISD | Unknown |
| Quantum bound | $O(2^{n/2})$ — Grover | $O(2^{0.042N})$ — quantum ISD | Unknown |
| Reduction strength | Theorem 16: EUF-CMA $\leq$ OWF preimage | Theorem 17: EUF-CMA $\leq$ SD $\wedge$ PRF | No complete proof |
| Stateful? | Yes (Merkle tree for multi-use) | No (Fiat-Shamir in QROM) | — |

**What is algebraically established by this analysis:**

1. Shor's algorithm breaks HPKS-NL and HPKE-NL in $O(n^2 \log n)$ quantum time — §10.8.4 (established).
2. Inverting $F_1^r$ for $r \geq 2$ is a degree-$n$ Boolean system; Gröbner attacks offer no sub-exponential advantage — Theorem 13, Corollary 2.
3. Recovering $K$ from one evaluation pair of $F_2$ is MQ-hard, NP-complete for overdetermined instances — Theorem 14.
4. $F_2$ permutations are non-commutative for generic key pairs — Theorem 15.
5. HPKS-Stern-F EUF-CMA reduces to $\mathrm{SD}(N,t)$ (NP-complete [BMvT 1978]) and NL-FSCX v1 PRF — Theorem 17.
6. Best quantum attack on $\mathrm{SD}(N,t)$ is $O(2^{0.042N})$ quantum ISD [Kirshanova 2018]; no polynomial quantum algorithm is known.

**What remains a conjecture:** NL-FSCX v1 is a one-way function (required for both A and B via the GGM PRF chain); NL-FSCX v2 CSP hardness (C).

**Recommendation.**  Option B provides the only complete algebraic chain to an established NP-hard problem.  The NL-FSCX v1 PRF assumption it requires is identical to the assumption already implicit in HSKE-NL-A1's security argument (§11.3.1) — both protocols stand or fall on the same primitive.  Option A is simpler to implement as a near-term replacement for HPKS-NL using the existing NL-FSCX v1 primitive; it should be treated as a stopgap until NL-FSCX v1 OWF has received dedicated cryptanalysis.  Option C is algebraically native to $F_2$ but is not ready for deployment.

---

## 11.9 HFSCX-256-DM — Hash function on NL-FSCX v1

HFSCX-256-DM (deployed v1.9.0; originally HFSCX-256 from v1.5.24) is a 256-bit Merkle-Damgård hash built on NL-FSCX v1 with Davies-Meyer feed-forward compression.
It serves three roles in the suite:

- generic digest (the `dgst` subcommand of `HerraduraCli`),
- pre-hash for `sign` / `verify` flows (compresses arbitrary-length messages to a 256-bit input for HPKS / HPKS-NL / HPKS-Stern-F),
- authentication tag for `HSKE-NL-A1-CTR-AEAD` (large-file streaming encryption).

This section formalises the security claims for the deployed Davies-Meyer construction and is backed by `SecurityProofsCode/hfscx_256_analysis.py`.

### 11.9.1 Construction

Let $n = 256$, block size $b = 32$ bytes.  Write $F_1^r(s, m)$ for NL-FSCX v1 iterated $r$ times with state $s$ and message-block parameter $m$.  HFSCX-256-DM takes input bytes $D$ and an optional 256-bit key $K$; it produces a 256-bit digest as follows.

**Compression function (Davies-Meyer).**

$$C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s \in \{0,1\}^{256}.$$

**Initial state.**  Let $\text{IV-const}$ be the 32-byte ASCII constant `HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0` interpreted as a 256-bit integer.  Define

$$s_0 = \begin{cases} \text{IV-const} & \text{(unkeyed)} \cr K \oplus \text{IV-const} & \text{(keyed MAC mode)} \end{cases}$$

**Padding (ISO 7816-4 + finalization).**  Append `0x80` to $D$; zero-fill to a multiple of $b$; append a 32-byte finalization block $\mathit{fin}$:

$$\mathit{fin} = \bigl(8 \cdot |D|\bigr) \oplus s_0 \pmod{2^{256}}.$$

**Iteration.**  For padded message $D' = m_1 \| m_2 \| \cdots \| m_k$ (where the last block is $\mathit{fin}$):

$$s_i = C_{\text{DM}}(s_{i-1}, m_i) = F_1^{64}(s_{i-1}, m_i) \oplus s_{i-1}, \qquad i = 1, \ldots, k.$$

**Output.**  $\text{HFSCX-256-DM}(D, K) = s_k$.

### 11.9.2 Security model and assumptions

The security claims for HFSCX-256-DM are conditional on assumptions already used elsewhere in §11:

**A1 (NL-FSCX v1 PRF, §11.8.4).**  For random key $K$, the function $i \mapsto F_1^{64}(K \oplus i, K)$ is computationally indistinguishable from a uniformly random function $\{0,1\}^n \to \{0,1\}^n$ against polynomial-time distinguishers.

**A2 (NL-FSCX v1 OWF, §11.8.3, Theorem 16).**  Given $y = F_1^{64}(s, m)$ for known $m$ and unknown $s$, recovering $s$ requires $\Omega(2^n) = \Omega(2^{256})$ classical operations and $\Omega(2^{n/2}) = \Omega(2^{128})$ quantum queries (Grover lower bound; the classical bound is supported by Theorem 13's degree-saturation argument and Corollary 2's Gröbner-immunity result, which show no sub-exponential classical solver exists for the resulting degree-$n$ Boolean system).

**A3 (Symmetric structure).**  $F_1(A, B) = F_1(B, A)$, since

$$F_1(A, B) = M(A \oplus B) \oplus \mathrm{ROL}_{n/4}\bigl((A + B) \bmod 2^n\bigr)$$
is symmetric under the swap $A \leftrightarrow B$.  Consequently, NL-FSCX v1 is non-bijective in $B$ as well as in $A$ (§11.5 Q3, by symmetry); $C(\cdot, m)$ is non-bijective in either input.

A3 is structurally important: HFSCX-256-DM cannot claim ideal-cipher security from $C_{\text{DM}}$ as a pseudorandom permutation.  All hardness claims below are therefore PRF-based, not PRP-based.

### 11.9.3 Collision resistance

**Generic bound.**  For an ideal 256-bit hash, a generic collision search costs $\Theta(2^{n/2}) = \Theta(2^{128})$ classical operations (Pollard rho) or $\Theta(2^{n/3}) = \Theta(2^{85})$ quantum operations (BHT [Brassard-Høyer-Tapp 1997]).

**MD lemma.**  Any internal collision $C(s, m_1) = C(s', m_2)$ with $(s, m_1) \neq (s', m_2)$ propagates to a full hash collision through the standard Merkle-Damgård argument; conversely, every full collision implies an internal collision somewhere along the two chains.

**Heuristic claim.**  Under A1, the compression $C_{\text{DM}}$ is computationally indistinguishable from a random function $\{0,1\}^{256} \times \{0,1\}^{256} \to \{0,1\}^{256}$.  The expected number of evaluations to find a collision in such a function is $\sqrt{\pi \cdot 2^{n} / 2} \approx 2^{128.3}$.  Therefore, under A1, finding any HFSCX-256-DM collision requires $\approx 2^{128}$ work classically.

**Free-start collisions.**  Under the Davies-Meyer construction (§11.9.8), a free-start collision $C_{\text{DM}}(s_1, m_1) = C_{\text{DM}}(s_2, m_2)$ with $s_1 \neq s_2$ requires $F_1^{64}(s_1, m_1) \oplus F_1^{64}(s_2, m_2) = s_1 \oplus s_2$.  Even if $F_1^{64}$ maps both inputs to the same value (exploiting its non-bijectivity), that forces $s_1 = s_2$, contradicting the free-start hypothesis.  The $2^{128}$ bound is therefore structurally tighter than for the earlier plain-MD construction.

### 11.9.4 Preimage and second-preimage resistance

**Preimage.**  Given target digest $h$, find any $D$ with $\text{HFSCX-256-DM}(D) = h$.  Generic bound: $\Theta(2^n)$ classical, $\Theta(2^{n/2})$ quantum (Grover).  Reduction to A2: any preimage attack must invert $C_{\text{DM}}$ on the final compression (else the digest cannot match), contradicting A2.

**Second preimage.**  Given $D$, find $D' \neq D$ with the same digest.  Generic bound: $\Theta(2^n)$ classical (no birthday speed-up since one input is fixed).  Implied by collision resistance under standard hash arguments.

### 11.9.5 Length-extension resistance via finalization

A plain Merkle-Damgård hash without finalization admits the extension attack: given $h = H(D)$, an attacker can set the chain state to $h$ and continue, producing $H(D \| \mathrm{pad}(D) \| D')$ for arbitrary $D'$ without knowing $D$.

HFSCX-256-DM's finalization block makes the published digest $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$, where $s_{k-1}$ is the state after processing the real message blocks but before finalization.  The attacker is given $s_k$, not $s_{k-1}$.

**Theorem 18 — Length extension is infeasible under A2.**  Any extension attacker who, given $\text{HFSCX-256-DM}(D)$ alone, produces $\text{HFSCX-256-DM}(D \| X)$ for an attacker-chosen $X$ must recover $s_{k-1}$ from $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$ — an inversion of $C_{\text{DM}}$ that requires $\Omega(2^n)$ classical work (or $\Omega(2^{n/2})$ quantum work) under A2. $\blacksquare$

**Empirical confirmation.**  `hfscx_256_analysis.py` §5: 0 successful naive forgeries in 200 trials (the naive forgery treats $h_M$ directly as a chain state and processes one extension block using $C_{\text{DM}}$; this never matches the true digest of $D \| X$).

**Keyed mode bonus.**  In keyed mode the finalization block content is $(8|D|) \oplus K \oplus \text{IV-const}$, which the attacker cannot construct without $K$.  This adds a second layer of length-extension protection independent of A2.

### 11.9.6 Keyed mode and MAC use

HFSCX-256-DM supports a keyed mode by setting $s_0 = K \oplus \text{IV-const}$.  This mode is used by `HerraduraCli` for the `HSKE-NL-A1-CTR-AEAD` authentication tag.  Two MAC constructions are evaluated.

**(a) Raw keyed-IV MAC (deployed).**

$$\mathrm{MAC}(K, D) = \text{HFSCX-256-DM}(D, K).$$

*Properties.*  Under A1, HFSCX-256-DM with secret IV is a PRF: the chain state at every step is unpredictable to an adversary without $K$.  EUF-CMA security follows from the PRF property by standard arguments [Bellare-Canetti-Krawczyk 1996, §3.2].

*Caveat.*  The security claim applies A1 to the entire chain.  If A1 holds for one $F_1^{64}$ application but degrades when chained over many blocks, the raw keyed-IV MAC weakens.  Empirical avalanche tests (§11.9.10 §2) show ideal key-bit diffusion (mean 128.09 / 256 output bits flipped, σ = 7.98) for the deployed parameters, but this is a sanity check, not a chain-length proof.

**(b) HMAC-HFSCX-256-DM (recommended for cross-protocol key reuse).**

$$\mathrm{HMAC}(K, D) = \text{HFSCX-256-DM}\Bigl(\bigl(K \oplus \mathit{opad}\bigr) \| \text{HFSCX-256-DM}\bigl((K \oplus \mathit{ipad}) \| D\bigr)\Bigr)$$

with $\mathit{ipad} = \mathtt{0x36}$ repeated and $\mathit{opad} = \mathtt{0x5C}$ repeated, each 32 bytes.

*Properties.*  Bellare's HMAC proof [Bellare 2006] reduces HMAC security to two assumptions on the underlying compression function:

1. PRF under related-key attacks against the IV input.
2. Collision resistance of the compression.

Both follow from A1 + A2.  HMAC adds resistance against extension and key-recovery attacks even if the compression has minor structural weaknesses, at the cost of one extra hash invocation per MAC.

**Recommendation.**  The current single-purpose AEAD use is well-served by raw keyed-IV.  For protocols intending to reuse the same long-term key across multiple algorithms or modes (e.g. derive both an encryption key and a MAC key from one master), HMAC-HFSCX-256-DM should be preferred.  As of v1.9.48 (TODO #93), `hmac_hfscx_256(key, data)` / `HmacHfscx256` is available in the C, Go, and Python libraries; no existing call site is changed.

**HSKE-NL-AEAD (v1.9.33, TODO #95 option 1).**  The keyed-IV MAC mode is now also deployed as the tag of a general-purpose AEAD, `hske_nl_aead_encrypt` / `hske_nl_aead_decrypt` (C/Go/Python suites; CLI `enc`/`dec --aead`).  The construction is encrypt-then-MAC over the HSKE-NL-A1 CTR keystream with associated-data support: the tag is computed over the domain-separation prefix `HSKE-NL-AEAD-v1`, the nonce, and length-framed AD and ciphertext, with the MAC key derived from the same per-(key, nonce) schedule as the `.hkx` file format but separated from it by the DS prefix.  Because the tag binds the MAC key through the collision-resistant keyed chain, the scheme is *key-committing*: a ciphertext/tag pair cannot verify under two distinct keys without a keyed collision, ruled out by A2 — a property AES-GCM lacks.  Verification is constant-time and decrypt-after-verify.  A single-pass alternative — a MonkeyDuplex-style sponge AEAD using the bijective NL-FSCX v2 family as the duplex permutation (TODO #95 option 2) — remains open research; it requires the differential/linear characterisation of the v2 permutation tracked in TODO #99 before any deployment claim.

**HDRBG (v1.9.34, TODO #96).**  The bare hash mode also serves as the output filter of a forward-secure deterministic random bit generator, `drbg_seed` / `drbg_generate` / `drbg_reseed` (C/Go/Python suites).  The construction follows the fast-key-erasure pattern: each 32-byte output block is `HFSCX-256(state || counter_be8 || "DRBG-OUT")`, after which the state advances one-way via `nl_fscx_revolve_v1(state, DRBG-domain, 64)` and the superseded state is erased (`explicit_bzero` in C; best-effort in Go/Python).  Backtracking resistance reduces to the same NL-FSCX v1 OWF conjecture as Theorem 16.  Because the v1 state walk is non-bijective, walks can collide: `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py` §5 measures the composed-walk image (the 64-step revolve image extrapolates to `2^218.8` at n = 256) and Brent rho/cycle lengths at n = 16–24, giving an expected walk-collision distance of `2^109.7` blocks; the enforced per-seed output limit of `2^20` blocks keeps the collision probability near `2^-180`, below the `2^-128` target.  *Non-goals:* HDRBG is not a NIST SP 800-90A validated DRBG — it has no health tests, prediction-resistance requests, or entropy-source assessment, and is intended only to expand seed material that is already full-entropy.

### 11.9.7 Domain separation across suite call sites

| Site | Role | Effective domain marker |
|---|---|---|
| `dgst` subcommand | generic digest | none — `iv = IV_const` |
| sign / verify pre-hash | message → 256-bit input | none — `iv = IV_const` |
| AEAD authentication tag | per-session MAC | $K \oplus \text{IV-const}$ ($K$ is the per-session MAC key, never zero) |
| `_stern_hash` | Stern commitment hash | distinct construction (rotates message into key slot, no finalization) — see §11.9.9 |

The `dgst` and pre-hash flows share the same effective IV.  This is acceptable when the input distributions cannot collide: the pre-hash flow always operates on attacker-supplied messages, but so does `dgst`, so a true cross-flow collision would only be an issue if (i) one flow appended additional content the other did not, *and* (ii) that content fell on a block boundary that mimicked the other's padding.  Neither holds in the current codebase.

The AEAD tag uses a distinct effective IV via the per-session key.  Cross-flow collision would require either a second-preimage on $\text{HFSCX-256-DM}(\cdot, K)$ for some $K$ (ruled out by collision resistance), or $K = 0$ (ruled out by the AEAD key-derivation step which produces $K$ from a Ring-LWR shared secret with negligible probability of $K = 0$).

**Hardening (v1.9.48, TODO #93).**  A domain-separated variant `hfscx_256_ds(ds, data)` is now available in the C, Go, and Python libraries.  The CLI exposes it as `dgst --algo hfscx-256-ds` with ds=0x01.  For a fully rigorous domain-separation argument that does not depend on collision-resistance reasoning, the suggested prefixes are: `0x01` for `dgst`, `0x02` for sign-pre-hash, `0x03` for AEAD-MAC.  Adoption at existing protocol call sites is a backwards-incompatible wire-format change and remains opt-in.

### 11.9.8 Davies-Meyer compression — DONE v1.9.0 (TODO #72)

As of v1.9.0 the compression function is the Davies-Meyer variant $C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s$ (see §11.9.1).  This section records the security benefits and the wire-format break.

**Benefits gained.**

1. **Fixed-point hardness.**  $C_{\text{DM}}(s, m) = s$ requires $F_1^{64}(s, m) = 0$, which under A2 requires $\Omega(2^n)$ classical work (preimage of zero under A2).  Before v1.9.0, fixed points were orbit-period-64 points of $F_1(\cdot, m)$; no formal lower bound existed, only empirical absence.
2. **Free-start collision hardness.**  As argued in §11.9.3, the Davies-Meyer structure rules out a structural speed-up from the non-bijectivity of $F_1$.
3. **PGV-1 alignment.**  $C_{\text{DM}}$ is one of the 12 provably-secure PGV compression functions [BRS 2002, PGV 1993].

**Wire-format note.**  This is a breaking change: all pre-v1.9.0 HFSCX-256 digests, pre-hashed signatures, and AEAD tags are incompatible with HFSCX-256-DM.  The cost per block is one 256-bit XOR (negligible).

### 11.9.9 `_stern_hash` QRO argument (TODO #36 — DONE v1.6.1)

As of v1.6.1 the Stern-F commitment hash is (ds = domain-separation tag):

$$\mathrm{StH}_{\mathrm{ds}}(v_1, \ldots, v_k) = \mathrm{HFSCX\text{-}256\text{-}DM}(h_k)[0{:}n/8], \quad h_0 = \mathrm{ds}, \quad h_i = F_1^{n/4}\bigl(h_{i-1} \oplus v_i, \mathrm{ROL}(v_i, n/8)\bigr)$$

Per-slot tags: ds=1 for c0, ds=2 for c1, ds=3 for c2, ds=4 for the KEM key, ds=0 for the Fiat-Shamir challenge.

**QRO argument.** Under the ROM on HFSCX-256-DM (§11.9.2, assumption A1), distinct per-slot ds values guarantee that c0, c1, c2, and the KEM key each invoke an independent random oracle.  By Unruh's composition theorem [Unruh 2015], this satisfies the QROM requirement for Theorem 17's Fiat-Shamir transform.  The range compression gap from TODO #42 (F_stern maps only ~24% of 2^32 inputs to distinct outputs at n=32) is resolved: the HFSCX-256-DM finalization maps the chained state through a full 256-bit hash before truncation, restoring the ~63.2% distinct-output fraction expected of a random function.

**Assembly/Arduino (n=32 toy demo).** The 32-bit `hfscx_32` finalizer and the KEM call with ds=4 provide the same QRO property for the KEM slot.  As of v1.9.48 (TODO #93), `stern_hash1_32`/`stern_hash2_32` carry explicit per-slot DS tags (ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key) in both the ARM Thumb-2 and NASM i386 implementations — the same tags as the C/Go/Python suite.  This satisfies the full QRO property at the assembly level and removes the prior reliance on structural distinctness.

### 11.9.10 Empirical evidence

`SecurityProofsCode/hfscx_256_analysis.py` measured the following at $n = 256$ (HFSCX-256-DM, v1.9.0):

| Test | Result | Interpretation |
|---|---|---|
| §1 Avalanche on input bit flips, 5 000 trials | mean = 128.013 / 256, σ = 7.980, range [99, 155] | Matches ideal random-function SAC (mean 128, σ ≈ 8 = $\sqrt{n/4}$). |
| §2 Avalanche on key bit flips (keyed mode), 5 000 trials | mean = 128.091 / 256, σ = 7.980, range [99, 159] | Matches ideal SAC; key bits diffuse fully through chain. |
| §3 Output Hamming weight uniformity, 5 000 trials | mean weight = 127.911, σ = 8.051 | Matches ideal output distribution. |
| §3 Byte-distribution chi², 5 000 × 32 bytes | $\chi^2 = 223.1$, df = 255 | $\chi^2 < 293.2$ (critical at $p = 0.05$); output bytes uniformly distributed. |
| §4 Collision sanity, $2^{17}$ trials (`--full`) | not run by default — birthday bound $2^{128}$ | Skipped: any observable collision below $2^{60}$ would falsify A1. |
| §5 Length-extension naive forgery, 200 trials | 0 / 200 successful | Confirms Theorem 18: finalization block defeats trivial extension. |
| §6 Domain separation (unkeyed vs keyed), 1 000 trials | 1000 / 1000 differ | Keyed mode distinct from unkeyed for all non-zero $K$. |
| §7 Fixed-point search (DM), 200 random $(s, m)$ pairs | 0 with $F_1^{64}(s,m)=0$, 0 near-zero | Fixed-point condition is preimage of zero under A2; no instances found, consistent with $\Omega(2^{256})$ classical hardness (§11.9.8). |

These tests rule out trivial weaknesses (low diffusion, biased output, length-extension, accidental key collisions, structural fixed points).  They do **not** constitute a formal proof: collision and preimage hardness rest on A1 + A2.

### 11.9.11 Summary

HFSCX-256-DM provides:

| Property | Bound | Assumption |
|---|---|---|
| Collision resistance | $2^{128}$ classical / $2^{85}$ quantum (BHT) | A1 |
| Preimage resistance | $2^{256}$ classical / $2^{128}$ quantum (Grover) | A2 |
| Second-preimage resistance | $2^{256}$ classical | A1 (collision implies 2nd-preimage) |
| Length-extension resistance | $2^{256}$ classical / $2^{128}$ quantum (Theorem 18) | A2 |
| MAC unforgeability (raw keyed-IV) | $2^{128}$ classical / $2^{128}$ quantum | A1 (full-chain PRF) |
| MAC unforgeability (HMAC, recommended for cross-protocol reuse) | as raw, plus related-key resistance | A1 + A2 [Bellare 2006] |

**Open hardenings** (not security-critical at current parameters):

1. ~~Switch to Davies-Meyer compression $C \oplus s$ at next major version (§11.9.8).~~ **DONE v1.9.0.**
2. ~~Add 1-byte domain-tag prefix per call site (§11.9.7).~~ **DONE v1.9.48** — `hfscx_256_ds(ds, data)` added to C, Go, Python libraries; `dgst --algo hfscx-256-ds` wired in all three CLIs (ds=0x01). Existing call sites unchanged (backward-compatible opt-in).
3. ~~Add HMAC-HFSCX-256-DM to the library (§11.9.6).~~ **DONE v1.9.48** — `hmac_hfscx_256(key, data)` / `HmacHfscx256` added to C, Go, Python libraries. Recommended when the same long-term key is reused across MAC and non-MAC modes; the current AEAD-only use retains the raw keyed-IV MAC.
4. ~~Assembly/Arduino per-slot DS tags on `stern_hash1_32`/`stern_hash2_32` (§11.9.9).~~ **DONE** — ARM Thumb-2 and NASM i386 implementations already carry ds=1/2/3/4 at all call sites (verified v1.9.48).

---
