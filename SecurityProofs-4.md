# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 4

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 4 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (this file): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.19** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections

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

$$\text{HKEX-RNL-128}: \quad n=512, q=65537, p=4096, \eta=1, pp=2$$

Security argument: the BKZ primal attack block-size requirement $\beta_\text{opt}$
scales approximately linearly with the ring dimension $n$ for fixed $(q, p, \eta)$
(Lindner-Peikert 2011; Albrecht et al. 2019).  Calibrating to the known $n=256$
estimate (~110 bits midpoint):

$$\text{Core-SVP}(n) \approx 110 \cdot \frac{n}{256} \quad \text{(classical)},
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

**2026 sparse-secret hybrid-decoding re-check (TODO #157).**  "Careful with the Ring:
Enhanced Hybrid Decoding Attacks against Module/Ring-LWE" [Hou-Jiang, eprint 2026/366]
presents a ring-structure-accelerated hybrid meet-in-the-middle/lattice-decoding attack
that the abstract reports as an $O(N)$ complexity improvement over the prior hybrid
decoding attack "in sparse secret setting", with 17x-114x measured speedups on
previously-broken benchmark instances, and up to 13-bit security-estimate reductions
across 16 named FHE parameter sets (from [JM22], [CCKS23], [BCKS24], [CHKS25], [AKP25]),
12 of which it moves below the 128-bit target.

The full PDF sits behind a Cloudflare challenge this review could not clear, so the
paper's own precise sparsity definition could not be read directly. All five cited
target papers are established CKKS/BFV/BGV **sparse-secret bootstrapping** proposals,
whose defining parameter is a Hamming weight $h$ deliberately kept far below the ring
degree $N$ — published sparse-secret-encapsulation parameter sets use figures like
$h \in \{64, 128, 192\}$ against $N = 2^{15} = 32768$ (density $h/N \approx
0.2\%$–$0.6\%$), chosen specifically to shrink the noise growth during bootstrapping.
This is the same "sparse" regime TODO #1 (now `DONE` in `TODO_DONE.md`, not `DEPRECATED`
as an earlier draft of this item's background section stated) originally flagged for
HKEX-RNL's pre-v1.5.x uniform $\{0,1\}$ sampler.

HKEX-RNL's deployed $\mathrm{CBD}(\eta=1)$ sampler (§11.4.2 above,
$q=65537$, $n=256$) draws each coefficient as $a_0 - b_0$ for independent uniform bits
$a_0, b_0$, giving $\Pr[s_i = 0] = 1/2$ and $\Pr[s_i = \pm1] = 1/4$ each — i.e. **roughly
half the coefficients are nonzero**, an expected Hamming weight of $\approx 128$ out of
$n=256$ ($\approx 50\%$ density). This is over **two orders of magnitude denser** than
the $h/N \lesssim 0.6\%$ regime the cited FHE sparse-secret parameter sets (and, by
inference, this paper's attack) target. Classical and prior hybrid attacks on sparse
secrets (e.g. the Son-Cheon-style hybrid MITM lineage this paper builds on) gain their
speedup specifically from a *reduced guessing space over the nonzero-coefficient
positions* — an asymptotic gain that requires $h \ll N$ and vanishes as $h/N \to 1/2$,
which is exactly HKEX-RNL's regime.

**Threshold-independent resolution.**  Rather than rest on that comparison, the
worksheet `SecurityProofsCode/hkex_rnl_sparse_hybrid_2026.py` removes the dependence on
the paper's unreadable definition entirely, by sweeping *every* plausible threshold and
asking how likely a deployed secret is to satisfy it at all.  Because each CBD($\eta=1$)
coefficient is nonzero independently with probability exactly $1/2$, the Hamming weight
of a deployed secret is exactly binomial — $\mathrm{HW} \sim \mathrm{Binomial}(n=256, p=1/2)$,
with mean $E(\mathrm{HW}) = 128$ and standard deviation $\sigma = 8$, placing the mean
$16$ standard deviations above zero.  Evaluating the exact lower tail
$\Pr(\mathrm{HW} \leq h)$ across the sparse regime:

| Threshold | Density | $\Pr(\mathrm{HW} \leq h)$ |
|---|---|---|
| $h \leq 1$ (the cited FHE regime, scaled to $n=256$) | $0.39\%$ | $2^{-248}$ |
| $h \leq 8$ | $3.1\%$ | $2^{-207}$ |
| $h \leq 16$ | $6.3\%$ | $2^{-173}$ |
| $h \leq 29$ | $11.3\%$ | $2^{-129}$ |
| $h \leq 64$ | $25\%$ | $2^{-52}$ |

The loosest threshold whose escape probability still beats $2^{-128}$ is $h \leq 29$,
i.e. a density of $11.3\%$.  **Any** sparsity definition set below roughly $12\%$ density
is therefore escaped by a deployed HKEX-RNL secret except with probability below the
$128$-bit security target itself — so the conclusion holds for any threshold the paper
could reasonably be using, without needing to read it.  Empirically, over $1000$ secrets
drawn from the deployed sampler the *minimum* Hamming weight observed was $104$.

A second, independent check is the guessing-space entropy that the hybrid attack's
speedup actually monetizes.  CBD($\eta=1$) carries $1.5$ bits of Shannon entropy per
coefficient, or $384$ bits at $n=256$; a sparse ternary secret with $h=1$ nonzero
occupies only $9$ bits, and even $h=16$ only $99$ bits.  The MITM/decoding split gains
over pure lattice decoding precisely when some block is cheap to enumerate, and at
$50\%$ density no such block exists — the attack degenerates to the primal lattice
attack already accounted for in the Core-SVP estimate below.

**Conclusion:** no revision to HKEX-RNL's 105–115-bit Core-SVP estimate is made.  The
stakes were real — the paper's measured maximum improvement is 13 bits, which applied to
HKEX-RNL would mean 92–102 bits — but the attack's precondition fails here by a margin
that no reasonable reading of "sparse" can close.  Unlike the earlier draft of this
re-check, the argument no longer depends on the Cloudflare-gated PDF: it quantifies over
all thresholds rather than comparing against one, so full-text access would not change
the outcome.  "Small" (bounded-magnitude, CBD-style) and "sparse" (few nonzero
positions) are genuinely distinct properties at HKEX-RNL's parameters — the deployed
secret is emphatically small but not sparse — and TODO #1's original deprecation of the
sparse-secret concern (in favor of CBD) stands **unaffected**.

---

### 11.7 Protocol-Level Quantum Security Summary

| Protocol | Security assumption | Classical attack | Quantum attack | Post-quantum security |
|----------|---------------------|------------------|----------------|-----------------------|
| **HKEX-GF** | DLP in $\mathbb{GF}(2^n)^{\ast}$ | **Pohlig–Hellman: ~$2^{36.5}$ at $n=256$** — the group order $2^n - 1$ has a 73-bit largest prime factor (§9.2.4, TODO #212); FFS $L[1/3]$ would give ~80–90 bits but is not the binding attack | Shor's DLP | **None** |
| **HSKE** (key-only) | Exhaustive search | Key search $2^n$; but 126 of 256 plaintext functionals leak from the ciphertext alone at $i = n/4$ — co-rank of the key map, SecurityProofs-1.md §1.3.1 / W9 | Grover $2^{n/2}$ on the key; the linear leak needs no quantum step | $n/2$ bits for the key; **none** for plaintext confidentiality |
| **HSKE** (known-plaintext) | — | 1 KPT pair → full $c_K$, $O(n^2)$ | BV: 1 query | **None** |
| **HPKS** | DLP in $\mathbb{GF}(2^n)^{\ast}$ + non-ROM challenge | Pohlig–Hellman key recovery ~$2^{36.5}$ at $n=256$, then arbitrary forgery (§9.2.4, TODO #212); the signing scalar reduces modulo the same $2^n - 1$ | Shor's DLP | **None** |
| **HPKE** | CDH in $\mathbb{GF}(2^n)^{\ast}$ | CDH $\leq$ DLP: Pohlig–Hellman ~$2^{36.5}$ at $n=256$ (§9.2.4, TODO #212); independently, the FSCX layer leaks 126 plaintext functionals per §1.3.1 / W9 | Shor's CDH | **None** |
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

**HSKE key-only** provides $n/2$ bits of post-quantum security *for the key*, and only
when no plaintext is ever observed.  In any realistic deployment, plaintexts are available
and this bound does not apply.  The NL-FSCX counter-mode and revolve-mode HSKE variants
(§11.3) preserve the same KPT vulnerability; they harden against linear key-recovery but do
not eliminate the 1-pair attack because the underlying structure remains affine.

**Correction (TODO #210).**  The key-only column above was previously read as a
*confidentiality* claim, and it is not one.  Theorem 4.1 (SecurityProofs-1.md §1.3.1) shows
the classical key map $T_i = M \cdot S_i$ has co-rank $2(2^{v_2(i)} - 1)$, which is 126 out of
256 at the deployed $i = n/4$.  Those 126 linear functionals of the plaintext are readable
from the ciphertext with no known plaintext, no chosen plaintext and no key recovery, so
classical HSKE and HPKE have no IND-CPA claim at any key size.  Only the *key search* bound
is $n/2$ post-quantum bits.  This does not extend to HSKE-NL-A1/A2, whose carry
non-linearity breaks the affine identity the argument depends on (see TODO #214 for the
measurement of what, if anything, survives statistically).

**Note on concrete security estimates (2026 landscape review, TODO #71; revised under TODO #212).**
The classical attack column for HKEX-GF previously reflected the FFS $L[1/3]$ result (§9.2.4) at
~80–90 bits, itself a correction from an earlier 128-bit claim.  The binding attack is instead
Pohlig–Hellman at ~$2^{36.5}$, because the group order $2^{256}-1$ has a largest prime factor of
only 73 bits.  Binary-field DLP is deprecated by NIST SP 800-57
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

**Sparse-circuit analysis for ZKBoo/ZKB++ proof-size reduction (TODO #122 Batch 3).**  A natural question is whether replacing the full ripple-carry adder $(A + B) \bmod 2^n$ (with $n-1$ AND gates in the ZKBoo circuit model, since $b_i$ is a public constant so only $a_i \cdot c_{i-1}$ is nonlinear) with a "prefix adder" of length $k \ll n$ (retaining full carry only for bits $0..k-1$; XOR-only for higher bits) could reduce the ZKBoo/ZKB++ proof to the ~180 KB target.

Empirical analysis (`SecurityProofsCode/nl_fscx_sparse_circuit.py`) shows:

- *AND-gate count:* the prefix adder uses $k-1$ AND gates per $F_1$ application, versus $n-1 = 255$ for the full adder.  For the revolve circuit ($r = 64$ steps), total AND gates $= r(k-1)$.
- *Degree preservation:* Theorem 13 is satisfied for prefix $k \geq 4$ provided $\mathrm{wt}(B_{0..k-1}) \geq 2$ (a keygen constraint, analogous to the existing $\mathrm{wt}(B) \geq 2$ requirement).  Empirically confirmed for $n \leq 32$.
- *Proof-size bottleneck:* despite eliminating nearly all AND gates ($k=2$ gives 1 AND gate per step), ZKB++ proof size for the $n=256$ revolve circuit only shrinks from 464 KB to ~29 KB — a $1.6\times$ reduction, not the $\approx 2.5\times$ needed to reach 180 KB.  The bottleneck is the 32-byte per-party secret share (fixed for any $n=256$ circuit) plus 32-byte commitments, which together contribute ~87% of bytes at $k=2$.

The conclusion is that **sparse/prefix-adder circuit design cannot by itself reach 180 KB at $n=256, R=219$**.  Reducing the proof further requires either (a) working at smaller $n$ with a field-extension composition argument, or (b) replacing ZKBoo/ZKB++ with an IOP-based proof (Ligero, Picnic-FS) that achieves $O(n \cdot R \cdot \log n)$ bytes, avoiding the per-bit sharing cost.  This is documented as the revised open direction for TODO #122 items 3–4.

---

---

> **Continued in Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
