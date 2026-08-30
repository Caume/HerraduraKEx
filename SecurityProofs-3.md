# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 3

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 3 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (this file): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.31** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections

---

## 9. Non-Linear Proposals

Theorem 10 establishes that any protocol whose shared secret is derived via a $\mathbb{GF}(2)$-linear iterated map on the exchanged public values is insecure: the same $S_n = 0$ identity that guarantees correctness simultaneously exposes $sk$ as a linear function of $(C, C_2)$. This section develops two concrete non-linear alternatives.

### 9.1 Fix Requirement

A secure replacement must satisfy two competing conditions simultaneously:

1. **Key-exchange correctness.** Two parties with independent secrets $(A, B)$ and $(A_2, B_2)$ must independently compute the same $sk$.
2. **Privacy of $sk$.** The shared secret $sk$ must not be computable from the public wire values $(C, C_2)$ alone.

Theorem 10 shows these two conditions are mutually exclusive under $\mathbb{GF}(2)$-linearity. The escape route is to use a **non-linear** primitive, i.e. a function $F$ such that $F(A \oplus X) \neq F(A) \oplus F(X)$ in general.

The two proposals below attack this from different angles:

- **HKEX-GF** (§9.2): replace the key-exchange step with $\mathbb{GF}(2^n)$ Diffie-Hellman; keep FSCX intact for all symmetric operations.
- **FSCX-CY** (§9.3): replace the XOR inside FSCX with integer addition to introduce carry non-linearity; analyse what is preserved and what breaks.

---

### 9.2 HKEX-GF — Diffie-Hellman over $\mathbb{GF}(2^n)^{\ast}$

#### 9.2.1 Algebraic structure

$\mathbb{GF}(2^n)$ is the field of polynomials over $\mathbb{GF}(2)$ of degree $< n$, reduced modulo a fixed irreducible polynomial $p(x)$ of degree $n$. Two irreducible polynomials used in the implementation:

$$p_{32}(x) = x^{32} + x^{22} + x^2 + x + 1, \qquad p_{64}(x) = x^{64} + x^4 + x^3 + x + 1$$

**Field multiplication** $a \cdot b \in \mathbb{GF}(2^n)$ is carryless polynomial multiplication reduced mod $p(x)$, implementable by the shift-and-XOR loop:

```
result = 0
for i in 0..n-1:
    if b[0] == 1:  result ^= a
    carry = a[n-1]
    a <<= 1
    if carry:      a ^= poly   # XOR with lower n bits of p(x)
    b >>= 1
```

**Operations used:** XOR and left-shift only — no integer multiplication or modular arithmetic.

**Non-linearity over $\mathbb{GF}(2)$:** The map $a \mapsto g^a$ (field exponentiation with fixed generator $g$) is non-linear in $a$ over $\mathbb{GF}(2)$:

$$g^{a \oplus x} \neq g^a \oplus g^x \quad \text{in general}$$

This contrasts with the FSCX map $A \mapsto M^i \cdot A + M \cdot S_i \cdot B$, which is $\mathbb{GF}(2)$-linear in $A$.

#### 9.2.2 Protocol

Pre-agreed public parameters: field size $n$, irreducible polynomial $p(x)$, generator $g \in \mathbb{GF}(2^n)^{\ast}$.

| Step | Alice | Bob |
|------|-------|-----|
| Private | $a \xleftarrow{R} \{1,\ldots,2^n{-}1\}$ | $b \xleftarrow{R} \{1,\ldots,2^n{-}1\}$ |
| Public | $C = g^a \in \mathbb{GF}(2^n)^{\ast}$ | $C_2 = g^b \in \mathbb{GF}(2^n)^{\ast}$ |
| Shared | $sk = C_2^{\,a} = g^{ab}$ | $sk = C^{\,b} = g^{ab}$ |

**Correctness proof:**

$$C_2^{a} = (g^b)^a = g^{ba} = g^{ab} = (g^a)^b = C^{b} \qquad \blacksquare$$

This holds by commutativity and associativity of multiplication in $\mathbb{GF}(2^n)^{\ast}$, which are ring axioms satisfied for any polynomial choice (irreducible or not). Irreducibility is required only for the group to be a field (every non-zero element invertible).

#### 9.2.3 Why Eve's formula fails

Eve's classical attack computes $sk_\text{eve} = S_{r+1} \cdot (C \oplus C_2)$.

Under HKEX-GF, the public values $C = g^a$ and $C_2 = g^b$ are field elements whose XOR $C \oplus C_2 = g^a \oplus g^b$ has no algebraic relationship to $g^{ab}$. Specifically:

$$S_{r+1} \cdot (g^a \oplus g^b) \neq g^{ab} \quad \text{in general}$$

because $S_{r+1}$ is the $\mathbb{GF}(2)$-linear FSCX partial-sum operator acting on XOR-structured vectors, while $g^{ab}$ is determined by field multiplication — a different algebraic structure. The two cannot coincide except by accidental collision (probability $2^{-n}$), confirmed at $0/4000$ over all trials.

#### 9.2.4 Security assumption

The hardness of HKEX-GF reduces to the **Computational Diffie-Hellman (CDH)** problem in $\mathbb{GF}(2^n)^{\ast}$: given $g^a$ and $g^b$, compute $g^{ab}$.

CDH in $\mathbb{GF}(2^n)^{\ast}$ is believed hard for large $n$, under the assumption that the Discrete Logarithm Problem (DLP) in $\mathbb{GF}(2^n)^{\ast}$ is hard.  Known classical attack complexities on the DLP in $\mathbb{GF}(2^n)^{\ast}$:

| Algorithm | Complexity | Notes |
|-----------|------------|-------|
| Baby-step giant-step (BSGS) | $O(2^{n/2})$ time, $O(2^{n/2})$ space | Generic group algorithm |
| Pohlig–Hellman | $O(\sqrt{q_{\max}})$ where $q_{\max}$ = largest prime factor of group order | Dangerous when order is smooth |
| Index calculus (function field sieve) | $L_{2^n}[1/3, c]$ (sub-exponential) | General DLP in $\mathbb{GF}(2^n)^{\ast}$; better constant than GNFS for prime fields |
| **Quasi-polynomial (Barbulescu–Joux–Pierrot 2013)** | $n^{O(\log n)}$ | Specific to characteristic-2 fields; practical for highly composite $n$ |

**Correction (TODO #212): Pohlig–Hellman, not the FFS, is the binding constraint here.**
The row above it in the table is the one that governs. $|\mathbb{GF}(2^n)^{\ast}| = 2^n - 1$ is
never prime, and at every supported $n$ it factors into primes far below the field size, so a
generic DLP algorithm run once per prime factor and recombined by CRT costs the square root of
the *largest prime factor* rather than the square root of the group. At $n = 256$,

$$2^{256} - 1 = 3 \cdot 5 \cdot 17 \cdot 257 \cdot 641 \cdot 65537 \cdot 274177 \cdot 6700417 \cdot 67280421310721 \cdot 59649589127497217 \cdot 5704689200685129054721$$

whose largest prime factor has 73 bits, putting Pohlig–Hellman with Pollard rho at roughly
$2^{36.5}$ group operations in constant memory — some 45 to 55 bits below the FFS figure quoted
below, which was previously reported as the practical bound. `SecurityProofsCode/hkex_gf_pohlig_hellman.py`
verifies the factorisation, computes $\text{ord}(g)$ at each supported $n$, and carries the attack
through end to end at $n = 32$ and $n = 64$ — recovering the private exponent, the HKEX-GF shared
secret, and a forged HPKS signature under the victim's public key. Note also that $g = 3$ is
**primitive** at $n = 64$ and at the deployed $n = 256$, so there the recovered exponent is the
private key itself rather than a representative.

Everything from here to the end of this subsection describes the **function field sieve (FFS)**,
which is the best *asymptotic* attack that does not exploit the factorisation of the group order,
and which was previously presented as the practical binding constraint for $\mathbb{GF}(2^n)^{\ast}$
at cryptographic sizes including $n = 256$.  Its complexity $L_{2^n}[1/3, c]$ is sub-exponential
with a smaller constant $c$ than the number-field sieve for prime-field DLP, making binary-field
DLP systematically weaker than an equal-bit-count prime-field DLP at the same $n$.
The **quasi-polynomial algorithm** (Granger–Kleinjung–Zumbrägel 2014–2016, refining Barbulescu
et al. 2013) achieves even better asymptotic complexity but has only been practically demonstrated
for fields with highly composite extension degree (e.g. $\mathbb{GF}(2^{6120})$,
$\mathbb{GF}(2^{9234})$).  For $\mathbb{GF}(2^{256})$ specifically, the FFS $L[1/3]$ remains the
best of the *sieve* attacks — though not the best attack overall, which is Pohlig–Hellman
at roughly $2^{36.5}$ (see the correction above).  The recommended minimum for $\mathbb{GF}(2^n)^{\ast}$ DLP (if it must be used) is
$n \geq 3000$; NIST SP 800-57 Rev. 5 (2020) and ENISA "Algorithms, Key Sizes and Parameters"
(2022) both **deprecate** $\mathbb{GF}(2^n)^{\ast}$ for new designs.

**Experimental verification at $n = 32$ (demo parameters).**

BSGS was applied to recover the discrete log from the 32-bit HKEX-GF demonstration:

```python
A_PRIV = 0xDEADBEEF   # Alice's private key
C      = 0x5B8AE480   # Public key: gf_pow(3, A_PRIV) in GF(2^32)*

# BSGS recovered:
a_rec  = 0x00CFE112   # Smallest exponent satisfying gf_pow(3, a_rec) == C
# Verification:
gf_pow(3, a_rec) == C         # True: 0x5B8AE480
# Shared secret recovered:
sk_from_dlp = gf_pow(C2, a_rec)   # == 0xD3DB6BC3  (matches actual sk)
# Time: 0.622 s on a single CPU core
```

The recovered $a_\text{rec} \neq A_\text{PRIV}$ because $g = 3$ is not a primitive element of
$\mathbb{GF}(2^{32})^{\ast}$: its order is a proper divisor of $2^{32}-1$.  Multiple exponents share
the same public key; BSGS finds the smallest representative.  The shared secret is nevertheless
fully recovered because $g^{ab}$ is the same regardless of which representative is used.

This last point is specific to $n = 32$ and should not be read as a general property (TODO #212):
$g = 3$ **is** primitive at $n = 64$ and at the deployed $n = 256$, where the attack returns the
private key itself.  `hkex_gf_pohlig_hellman.py` computes $\text{ord}(g)$ at each supported $n$ and
demonstrates exact recovery at $n = 64$ in about 0.15 s, together with the HKEX-GF shared secret
and an HPKS forgery derived from it.

**Effective security:** $n = 32$ is broken in under 1 second.  The quasi-polynomial attack
extends to all practical $n$ values.

**Practical parameters (updated 2026 — TODO #71 landscape review):**

| $n$ | FFS $L[1/3]$ estimate | Largest prime factor of $2^n - 1$ | Pohlig–Hellman + rho | Effective security |
|-----|------|------|------|------|
| 32  | ≪ 40 bits | 17 bits | $2^{8.5}$ | $2^{8.5}$ |
| 64  | ≪ 40 bits | 23 bits | $2^{11.8}$ | $2^{11.8}$ |
| 128 | ≈ 50–60 bits | 46 bits | $2^{23.3}$ | $2^{23.3}$ |
| 256 | ≈ 80–90 bits | 73 bits | $2^{36.5}$ | $\mathbf{2^{36.5}}$ (**deployed**) |
| 512 | ≈ 110–120 bits | 206 bits | $2^{103.3}$ | $2^{103.3}$ |
| 1024 | ≈ 128–140 bits | 329 bits | $2^{164.5}$ | ≈ 128–140 bits (FFS binds) |

The effective-security column is the smaller of the two attacks. Pohlig–Hellman is the binding
constraint at every size up to and including $n = 512$; only at $n = 1024$ does its cost rise
past the FFS and the FFS take over. The reason growing $n$ helps only slowly is structural: the
group order is $2^n - 1$ by construction, so its factorisation rather than the field size sets
the cost. The $n = 512$ and $n = 1024$ rows take their largest prime factor from the Fermat
numbers $F_8 = 2^{256} + 1$ and $F_9 = 2^{512} + 1$ dividing $2^n - 1$; every factorisation in
the table is verified for primality and divisibility by `hkex_gf_pohlig_hellman.py`.

**Wall clock at the deployed parameters.** $2^{36.5}$ group operations at the $1.26 \times 10^5$
multiplications per second measured for `herradura.h`'s `gf_mul_ba` (`-O2`, reference ARM64 host)
is about nine days on a single core. Pollard rho uses constant memory and parallelises linearly,
and a carryless-multiply field implementation on a desktop core is one to two orders of magnitude
faster — so this is hours of commodity compute, not a margin.

**2026 landscape update (TODO #71):** The entry $n = 256 \approx 128$ bits in earlier versions
of this document was incorrect.  Under the FFS $L[1/3]$ attack, $\mathbb{GF}(2^{256})^{\ast}$ DLP
provides approximately 80–90 bits of classical security — well below the 128-bit target.  Reaching
128 bits under $L[1/3]$ requires $n \approx 1000$ or higher (analogous to how 3072-bit prime-field
DH is needed for 128-bit security, not 256-bit).  NIST SP 800-57 Part 1 Rev. 5 (2020) and ENISA
"Algorithms, Key Sizes and Parameters" (2022) deprecate $\mathbb{GF}(2^n)^{\ast}$ for new designs
entirely; the correction here documents the concrete security shortfall at $n = 256$.

**Second correction (TODO #212):** the 80–90 bit figure above is itself an over-estimate of the
*effective* security, because it costs only the FFS. Pohlig–Hellman brings $n = 256$ down to about
$2^{36.5}$, as derived at the top of this subsection. The TODO #71 conclusion — that
$\mathbb{GF}(2^n)^{\ast}$ is unsuitable and the protocols built on it are demo-only — is unchanged
and, if anything, understated: the shortfall is roughly 90 bits below the 128-bit target rather
than 40.

For production use, elliptic curve Diffie-Hellman over a prime-order curve (ECDH) provides better
security-per-bit than any $\mathbb{GF}(2^n)^{\ast}$ construction.  HKEX-GF is a proof-of-concept
demonstrating that the classical structural break (§3) is avoidable; §10.9 explains why
$\mathbb{GF}(2^n)^{\ast}$ is ultimately unsuitable as a production DLP group.

#### 9.2.5 FSCX period preserved

FSCX, fscx\_revolve, and all symmetric protocols (HSKE, HPKS, HPKE) are **unchanged**. Their correctness proofs (Theorems 1–6, Corollaries 1–3) remain valid. The HKEX-GF key exchange produces $sk \in \mathbb{GF}(2^n)^{\ast}$, which is passed to HSKE/HPKS/HPKE as a pre-shared symmetric key — the existing interface.

**Verified experimentally:** `fscx_revolve(fscx_revolve(P, K, i), K, r) = P` for $i + r = n$ holds at 4000/4000 trials across $n \in \{32, 64\}$ (Section I-D of `hkex_nl_proposal.py`).

#### 9.2.6 Migration path — successor group for HKEX-GF, HPKS, and HPKE (TODO #127, v1.9.90)

Given the deprecation documented in §9.2.4, the question is the minimal-change upgrade that preserves the suite's Schnorr algebra — the signing equation `s = (k - a*e) mod ord` and verification `g^s * C^e == R` — so that threshold signing (TODO #98) and Schnorr ring signatures (TODO #78.I) continue to apply.  `SecurityProofsCode/hpks_ristretto_migration.py` evaluates **ristretto255** (RFC 9496, the prime-order quotient of Curve25519, order approximately `2^252`, roughly 128-bit ECDLP) as that successor, using a self-contained pure-Python implementation validated against the RFC 9496 generator test vector.

**Drop-in verification.**  The prototype re-implements HPKS signing verbatim over ristretto255 — only `gf_pow(g, a)` becomes scalar multiplication `a*G` and `gf_mul` becomes point addition; the challenge function is algebra-agnostic and stays HFSCX-256-DM.  Results: 50/50 sign/verify round-trips; tampered message, tampered scalar, and wrong-key signatures all rejected; 3-of-3 additive threshold aggregation verifies against the summed public key; AOS Schnorr ring signatures close for every ring member and reject substituted members.  Notably, the **prime group order removes the order-divisor caveats** that GF(2^n)-star required (BSGS in §9.2.4 recovers non-unique exponent representatives precisely because `g = 3` is non-primitive; in a prime-order group every non-identity element generates the full group).

**Migration impact.**  Group elements are 32 bytes on both sides, so existing PEM/DER SEQUENCE layouts carry over unchanged; only a new algorithm tag (for example `genpkey --algo hpks-r255`) is required.  Scalars re-range from `mod 2^n - 1` to `mod ell`.  Keys are not interoperable between the two groups.  HSKE and the symmetric halves of HPKE are untouched — the derived secret enters them as a pre-shared key exactly as today.

**Post-quantum assessment.**  Ristretto255 is a **classical-security-only** upgrade: Shor's algorithm breaks ECDLP exactly as it breaks GF(2^n)-star DLP.  Migration fixes the classical shortfall (from the roughly $2^{36.5}$ Pohlig–Hellman cost of §9.2.4 — or the 80–90 bits the FFS alone would suggest — up to 128 bits, since a prime-order group has no Pohlig–Hellman structure to exploit) but provides nothing against quantum adversaries.  No quantum-resistant successor group exists for this protocol family: the Schnorr algebra fundamentally requires a group with hard DLP, and every such group is Shor-vulnerable.  The post-quantum path for the suite therefore remains HKEX-RNL (Ring-LWR, §11.4) plus HPKS-Stern-F / HPKE-Stern-KEM (code-based, §11.8.4) exclusively.  Recommendation: document ristretto255 as the classical upgrade path but keep implementation effort on the PQC track.

---

### 9.3 FSCX-CY — Carry-Injection FSCX (Experimental)

#### 9.3.1 Construction

Define the **carry-injection** variant:

$$\text{FSCX-CY}(A, B) = M\left((A + B) \bmod 2^n\right)$$

where $+$ is ordinary integer addition (not $\oplus$), and $M = I \oplus \text{ROL}(1) \oplus \text{ROR}(1)$ is the standard FSCX linear operator.

Compared to standard FSCX:

$$\text{FSCX}(A, B) = M(A \oplus B), \qquad \text{FSCX-CY}(A, B) = M\left((A + B) \bmod 2^n\right)$$

The difference is the **carry term**:

$$\delta(A, B) = (A + B \bmod 2^n) \oplus (A \oplus B)$$

which satisfies $\text{FSCX-CY}(A, B) = \text{FSCX}(A, B) \oplus M(\delta(A, B))$.

**Operations used:** XOR, cyclic rotation, and integer addition (mod $2^n$) — all basic binary operations.

#### 9.3.2 Non-linearity over $\mathbb{GF}(2)$

**Claim.** For fixed $B \neq 0$, the map $A \mapsto \text{FSCX-CY}(A, B)$ is **not** $\mathbb{GF}(2)$-linear.

**Proof.** A $\mathbb{GF}(2)$-linear map $f$ satisfies $f(A \oplus X) = f(A) \oplus f(X)$. For affine maps, $f(A \oplus X) = f(A) \oplus f(X) \oplus f(0)$. We test the affine condition:

$$\text{FSCX-CY}(A \oplus X, B) \stackrel{?}{=} \text{FSCX-CY}(A, B) \oplus \text{FSCX-CY}(X, B) \oplus \text{FSCX-CY}(0, B)$$

The left side equals $M((A \oplus X) + B \bmod 2^n)$. The right side, after simplification using $M$'s linearity, equals $M((A + B \bmod 2^n) \oplus (X + B \bmod 2^n) \oplus B)$. These differ precisely when the carry in $A + B$ and the carry in $X + B$ do not cancel uniformly — which occurs whenever $A \text{ AND } B \neq X \text{ AND } B$ modulo their carry chains. Experimentally: 4998/5000 random triples $(A, X, B)$ violate the affine condition. $\blacksquare$

The carry term $\delta(A, B)$ encodes the full carry chain of $A + B$:

$$\delta(A, B) = 2(A \mathbin{\text{AND}} B) \oplus 2(A \mathbin{\text{AND}} B \oplus A \mathbin{\text{XOR}} B \text{-carry}) \oplus \cdots$$

involving AND operations at every bit position, which are products in $\mathbb{GF}(2)$ — hence non-linear.

#### 9.3.3 HKEX-CY: why correctness fails

The HKEX correctness identity relies on:

$$A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B \tag{FSCX key relation}$$

which follows from the affine closed form $f_B^k(A) = M^k \cdot A + M \cdot S_k \cdot B$ — a consequence of $\mathbb{GF}(2)$-linearity. When $f_B(A) = M((A+B) \bmod 2^n)$, no analogous closed form exists: the carry terms at each iteration step $j$ depend non-linearly on the current state $A_j$, which in turn depends on the private pair $(A, B)$.

Consequently, the telescoping cancellation $M \cdot S_r + M^{r+1} \cdot S_i = S_n = 0$ has no equivalent under FSCX-CY, and $sk_\text{alice} \neq sk_\text{bob}$ in general.

**Verified experimentally:** HKEX-CY with $n = 32$, $i = 8$, $r = 24$ gives $sk_\text{alice} = sk_\text{bob}$ in 0/2000 trials (Section II-C of `hkex_nl_proposal.py`).

#### 9.3.4 HSKE-CY: period structure

For HSKE, correctness requires the iterated map $g_K^T(P) = P$ for a fixed step count $T = i + r$. Under FSCX-CY, the functional period $T(K) = \text{lcm of all cycle lengths of } g_K$ is **key-dependent** and astronomically large:

| $n$ | $K$ | FSCX period | FSCX-CY period |
|-----|-----|-------------|----------------|
| 8 | 0x00 | 4 | 4 |
| 8 | 0x01 | 8 | 20 520 |
| 8 | 0x7F | 8 | 188 404 |
| 16 | 0x0001 | 16 | $\approx 1.14 \times 10^{20}$ |
| 16 | 0x7FFF | 16 | $\approx 5.2 \times 10^{30}$ |

The explosion in period length makes FSCX-CY unsuitable as a direct drop-in replacement for FSCX in HSKE: the encrypt/decrypt step count $T(K)$ would need to be computed per-key (computationally expensive) and would be astronomically large (impractical).

The near-infinite periods are a consequence of the carry operator coupling all bit positions: the iterated map visits an enormous fraction of $\{0, \ldots, 2^n{-}1\}$ before returning to any starting point.

#### 9.3.5 Eve's attack on FSCX-CY

Eve applies $sk_\text{eve} = S_{r+1} \cdot (C \oplus C_2)$ to FSCX-CY public values.

Under FSCX-CY, each public value $C = g_B^i(A)$ encodes private carry terms $\delta(A_j, B)$ accumulated over $i$ steps. These terms depend non-linearly on $(A, B)$ and cannot be separated from $C$ by any $\mathbb{GF}(2)$-linear operator. As a result, $S_{r+1} \cdot (C \oplus C_2) \neq sk_\text{alice}$ in general.

**Verified experimentally:** Eve's formula succeeds 0/2000 times on FSCX-CY sessions (Section II-D of `hkex_nl_proposal.py`). Probability of accidental success $\approx 2^{-32}$ per trial.

---

### 9.4 Summary and Recommendation

| Property | HKEX-GF | FSCX-CY |
|----------|---------|---------|
| Key-exchange correct | **Yes** (proved by field commutativity) | No (S_n = 0 has no carry analog) |
| Non-linear over $\mathbb{GF}(2)$ | Yes (exponentiation) | Yes (carry term) |
| Eve's $S_{r+1}(C \oplus C_2)$ fails | Yes (0/4 000 trials) | Yes (0/2 000 trials) |
| Operations | XOR + left-shift | XOR + rotation + ADD |
| FSCX period preserved | Yes (HSKE/HPKS/HPKE unchanged) | No (key-dependent, exponentially large) |
| Security assumption | DLP in $\mathbb{GF}(2^n)^{\ast}$ | Unknown |
| Copies a known cipher | No (DH is a key-exchange, not a cipher) | No |

**Recommended fix.** Replace the HKEX key-exchange step with HKEX-GF. All symmetric protocols (HSKE, HPKS, HPKE) continue using standard FSCX with no changes. The period structure $M^n = I$, $S_n = 0$ remains valid; all correctness proofs (Theorems 1–6, Corollaries 1–3) are unaffected. The only change is in how the shared symmetric key $sk$ is established: via $\mathbb{GF}(2^n)$ DH rather than via FSCX iteration.

**FSCX-CY as a direction.** Although FSCX-CY cannot replace FSCX directly, it demonstrates that carry-injection creates genuine non-linearity with a minimal code change (one operation: `A ^ B` → `(A + B) mod 2^n`). A future variant could use FSCX-CY for a symmetric cipher where the key-specific period $T(K)$ is precomputed and incorporated into the protocol design.

---

## 10. v1.4.0 Migration: HKEX → HKEX-GF

### 10.1 Change Summary

Version 1.4.0 replaces the broken HKEX key exchange with HKEX-GF across all implementations (Python, Go, C, ARM assembly, NASM i386, Arduino). Two functions are affected:

| Function | v1.3.x (broken) | v1.4.0 (fixed) |
|----------|-----------------|----------------|
| Key exchange | FSCX-based (linear, $sk$ public) | DH over $\mathbb{GF}(2^n)^{\ast}$ |
| `fscx_revolve_n` | Used in HKEX/HPKS/HPKE | **Removed** — nonce cancels identically |
| HSKE | `fscx_revolve_n(P, K, K, i)` | `fscx_revolve(P, K, i)` |
| HPKS | $S = sk \oplus P$, where $sk = \text{FSCX-based}$ | $S = sk \oplus P$, where $sk = g^{ab}$ |
| HPKE | $E = sk \oplus P$, where $sk = \text{FSCX-based}$ | $E = sk \oplus P$, where $sk = g^{ab}$ |

### 10.2 Why `fscx_revolve_n` Was Removed

Theorem 10 (proved in §4.5 / SecurityProofsCode) shows that any nonce $N$ injected during FSCX iteration satisfies:

$$\text{FSCX-REVOLVE-N}(A, B, N, k) = M^k \cdot A \oplus M \cdot S_k \cdot B \oplus S_k \cdot N$$

The nonce contribution $S_k \cdot N$ is the same on both sides of the key exchange equation, so it cancels identically — providing no protection against the classical break. With HKEX-GF, the nonce was derived as $N = C \oplus C_2$ (a public value), making its use circular and pointless. `fscx_revolve_n` is therefore removed rather than kept as dead code.

### 10.3 Primitive Polynomials Used

| $n$ | Primitive polynomial | Hex constant (lower $n$ bits) |
|-----|---------------------|-------------------------------|
| 32  | $x^{32} + x^{22} + x^2 + x + 1$ | `0x00400007` |
| 64  | $x^{64} + x^4 + x^3 + x + 1$ | `0x000000000000001B` |
| 128 | $x^{128} + x^7 + x^2 + x + 1$ | `0x00000000000000000000000000000087` |
| 256 | $x^{256} + x^{10} + x^5 + x^2 + 1$ | `0x0000...0425` |

Generator $g = 3$ (polynomial $x + 1$) for all field sizes.

### 10.4 Experimental Confirmation (v1.4.0 Test Results)

All results from `Herradura_tests.py`, `Herradura_tests.go`, `Herradura_tests.c`:

| Test | Result |
|------|--------|
| HKEX-GF correctness $g^{ab} = g^{ba}$ | 10 000/10 000 (Python), 1 000/1 000 (C) |
| Eve classical attack $S_{r+1}(C \oplus C_2) \neq sk$ | 0/10 000 successes |
| HPKS sign+verify $sk \oplus P \xrightarrow{\text{verify}} P$ | 10 000/10 000 |
| Key sensitivity (flip 1 bit of $a$ → HD in $sk$) | mean $\approx n/2$ (avalanche) |
| FSCX orbit period (unchanged) | $n$ or $n/2$, 0 exceptions |
| FSCX bit-frequency bias | 49.5–50.5% per bit |
| HSKE round-trip $\text{fscx-revolve}^2(P, K, i, r) = P$ | 5 000/5 000 |

### 10.5 Security Status After Migration

| Weakness | v1.3.x | v1.4.0 |
|----------|--------|--------|
| W2: $sk$ computable from $(C, C_2)$ | **ACTIVE** (Thm. 7) | **Mitigated** — $sk = g^{ab}$ requires DLP |
| W3: HPKE no confidentiality | **ACTIVE** | **Mitigated** — $E = sk \oplus P$ with CDH-hard $sk$ |
| W5: Single $(P,S)$ reveals $sk$ | **ACTIVE** | **Mitigated** — $sk$ is CDH-hard to compute |
| W6: No hardness assumption established | **ACTIVE** | **Mitigated** — CDH in $\mathbb{GF}(2^n)^{\ast}$ |
| W4: Bit malleability (no IND-CCA2) | Active | Still active (structural to XOR encryption) |
| W7: Short orbit space | Active | Still active for FSCX; irrelevant for GF DH |
| W8: No authenticated encryption | Active | Still active (no MAC component) |

The key exchange is now provably secure under CDH in $\mathbb{GF}(2^n)^{\ast}$. Remaining weaknesses (W4, W7, W8) are structural to the XOR-based symmetric protocols and are documented; they do not affect the key exchange itself.


---

### 10.6 Classical Security Analysis of v1.4.0 Protocols

#### 10.6.1 HSKE — Known-Plaintext Attack

By Theorem 11 (§11.1): $E = M^i \cdot P \oplus M \cdot S_i \cdot K$.  Defining $c_K \triangleq M \cdot S_i \cdot K$:

$$c_K = E \oplus M^i \cdot P$$

One known-plaintext pair $(P, E)$ immediately yields $c_K$.  At $n = 64$, $i = 16$: $\text{rank}(\Phi) = 64$
(experimentally verified: 0 unconstrained key bits from a single pair), meaning $K$ is uniquely
determined.  **HSKE provides no security under known-plaintext attack at any $n$.**

#### 10.6.2 HPKS — Classical Forgery Resistance

Forgery requires finding $(R^{\ast}, s^{\ast})$ satisfying $g^{s^{\ast}} \cdot C^{e^{\ast}} = R^{\ast}$ where
$e^{\ast} = \text{fscx-revolve}(R^{\ast}_\text{bits}, P^{\ast}, i)$, without knowing the private key $a$.

- If Eve fixes $R^{\ast}$ first: she needs $s^{\ast} = \log_g(R^{\ast} \cdot C^{-e^{\ast}})$ — a DLP instance.
- If Eve fixes $s^{\ast}$ first: she can compute $g^{s^{\ast}} \cdot C^{e^{\ast}}$ for any $e^{\ast}$, but the
  constraint $e^{\ast} = \text{fscx-revolve}(R^{\ast}_\text{bits}, P^{\ast}, i)$ ties $R^{\ast}$ and $e^{\ast}$
  together.  Since fscx\_revolve is an affine bijection in its first argument (see §10.7),
  solving both simultaneously reduces to DLP hardness.

Forgery resistance is equivalent to DLP hardness in $\mathbb{GF}(2^n)^{\ast}$, subject to the
quasi-polynomial attack in §9.2.4 and the challenge-function caveat in §10.7.

#### 10.6.3 HPKE — Classical Attack

Ciphertext is $(R, E) = (g^r, \text{fscx-revolve}(P, g^{ar}, i))$.  Recovering the
plaintext requires $g^{ar}$, which is the CDH problem given $(g^a, g^r)$.
Since CDH $\leq$ DLP, all classical DLP attacks in §9.2.4 apply directly.

Additionally, the affine structure of fscx\_revolve means that given $(g^r, E)$ and a
known-plaintext pair, $c_{\mathit{ek}} = E \oplus M^i \cdot P$ recovers the key constant.
DLP on $\mathit{ek} = C^r$ or $\mathit{ek} = R^a$ may then recover $a$ or $r$.

---

### 10.7 HPKS Challenge Function — Algebraic Properties

The challenge in HPKS uses fscx\_revolve in place of a hash function:
$e = \text{fscx-revolve}(R_\text{bits}, P, i)$.  Two algebraic properties affect
provable security.

**Property 1 — Affine bijection in $R$.**

For fixed $P$ and $i$, the map $R \mapsto M^i \cdot R \oplus M \cdot S_i \cdot P$
is an affine bijection: the linear part $M^i$ is invertible (since $M$ has order $n/2$),
so no two distinct $R$ values produce the same challenge $e$.

*Verified:* 50 000 random $R$ values at $n = 64$, fixed $P$: **0 collisions**.

**Property 2 — Predictable challenge delta.**

By the difference identity (Theorem 11 linearity):

$$e(R_2) \oplus e(R_1) = \text{fscx-revolve}(R_1 \oplus R_2, 0, i) = M^i \cdot (R_1 \oplus R_2)$$

Given any one valid challenge $e(R_1)$, the challenge for any $R_2 = R_1 \oplus \delta$ is
$e(R_2) = e(R_1) \oplus M^i \cdot \delta$ — **publicly computable without oracle access**.

*Verified:* 10 000 random $(R_1, R_2)$ pairs at $n = 64$: delta identity holds **100%**.

**Consequence for Random Oracle Model (ROM) security proofs.**

Standard Schnorr security proofs (Pointcheval–Stern, forking lemma) assume the challenge
hash is a random oracle: an adversary who queries $H$ on one input learns nothing about
outputs on other inputs.  fscx\_revolve violates this: the adversary can predict all
challenges without any oracle query.

The forking lemma requires that rewinding the adversary with a different challenge on the
same $R$ produces an *independent* random challenge.  Here, given $e_1$ for $(R, P)$, an
adversary computes the challenge $e_2$ for $(R, P')$ as $e_2 = e_1 \oplus M^i \cdot (P \oplus P')$.
The rewound challenge is deterministically related to the original — the forking lemma
does not apply in its standard form.

**Practical implication.** The DLP in $\mathbb{GF}(2^n)^{\ast}$ still protects the private key
$a$: Eve cannot recover $a$ from the Schnorr equation without solving DLP.  But the
non-ROM challenge means the standard Schnorr security proof does not carry over, and
subtle attacks exploiting challenge predictability cannot be excluded by proof alone.
The NL-FSCX v1 revolve (§11.2.1) hardens the challenge against linear prediction;
full ROM replacement requires a dedicated cryptographic hash function.

---

### 10.8 Quantum Algorithm Analysis (v1.4.0)

#### 10.8.1 Grover's Algorithm

**HSKE (key-only attack).**  Brute-force key search costs $O(2^n)$ classically and
$O(2^{n/2})$ with Grover.  For $n = 256$: $2^{128}$ post-quantum symmetric security
against key-only attacks.  This bound is vacuous when plaintexts are available — the
classical 1-pair KPT attack recovers the key in $O(n^2)$ regardless.

**HKEX-GF, HPKS, HPKE.**  Security rests on DLP in $\mathbb{GF}(2^n)^{\ast}$.  Shor's
algorithm (§10.8.4) solves DLP in polynomial quantum time and strictly dominates
Grover for all these protocols.  **Grover is irrelevant for the GF-DLP protocols.**

#### 10.8.2 Simon's Algorithm

**Simon's problem:** find the hidden period $s$ of a function $f(x) = f(x \oplus s)$
in $O(n)$ quantum queries, where $s$ is $\mathbb{GF}(2)$-linear.

**Applicability.** The DLP function $f(x) = g^x$ in $\mathbb{GF}(2^n)^{\ast}$ has collisions
determined by the *cyclic* group structure of the exponent: $g^{x_1} = g^{x_2}$ iff
$x_1 \equiv x_2 \pmod{|\langle g \rangle|}$.  This is a $\mathbb{Z}$-linear period, not a
$\mathbb{GF}(2)$-linear period.  Simon's QFT over $\mathbb{GF}(2)^n$ cannot extract it;
the correct tool is Shor's QFT over $\mathbb{Z}_N$.

**Application to HSKE.** HSKE has affine $\mathbb{GF}(2)$ structure, so Simon's hidden
subgroup problem can be applied to the HSKE encryption oracle.  It recovers the kernel of
the affine map — providing no advantage beyond the classical 1-pair KPT attack.

#### 10.8.3 Bernstein–Vazirani Algorithm

**HSKE.**  The encryption map $E = M^i \cdot P \oplus c_K$ is affine in $P$.  With
oracle access (fixed key, variable plaintext), BV recovers $c_K$ in **1 quantum query**,
matching the classical known-plaintext bound.  No asymptotic quantum advantage over the
classical attack.

**HKEX-GF, HPKS, HPKE.** Involve $\mathbb{GF}(2^n)^{\ast}$ exponentiation, which is not
$\mathbb{GF}(2)$-affine in the exponent.  BV does not apply.

#### 10.8.4 Shor's Algorithm — Primary Quantum Threat

Shor's algorithm solves the DLP in any cyclic group $G = \langle g \rangle$ of order $N$
in $O((\log N)^2 \log\log N \cdot \log\log\log N)$ quantum gate operations.  For
$\mathbb{GF}(2^n)^{\ast}$: group order $N = 2^n - 1$, quantum time $O(n^2 \log n)$.

| Adversary | Best DLP attack on $\mathbb{GF}(2^n)^{\ast}$ | Complexity |
|-----------|-----------------------------------------------|------------|
| Classical (practical) | Function field sieve (FFS) | $L_{2^n}[1/3, c]$ — ~80–90 bits at $n=256$ |
| Classical (asymptotic) | Quasi-polynomial (Granger–Kleinjung–Zumbrägel 2014–2016) | $n^{O(\log n)}$ — demonstrated for composite-degree fields |
| Quantum | Shor's algorithm | $O(n^2 \log n)$ — breaks all practical sizes |

Both the FFS (classical) and Shor's algorithm (quantum) break $\mathbb{GF}(2^n)^{\ast}$ DLP at
all practical parameter sizes.  At $n = 256$ the FFS gives approximately 80–90 bits of classical
security (below the 128-bit target); Shor's algorithm reduces this to polynomial time on a
fault-tolerant quantum computer.

**Concrete qubit-count resource estimates (2026 landscape review, TODO #163).** The
complexity classes above are asymptotic; the following gives concrete logical-qubit
figures for context, drawn from 2026 quantum-resource-estimation literature for
**elliptic-curve** DLP (ECDLP) — not $\mathbb{GF}(2^n)^{\ast}$ DLP directly, since no
equivalent space-optimized circuit has been published for the characteristic-2 group
HKEX-GF actually uses (see caveat below):

| Source | Target | Logical qubits | Notes |
|---|---|---|---|
| Häner et al., PQCrypto 2020 | 256-bit ECDLP | 2124 | Prior baseline both papers below improve on |
| Gidney, arXiv 2025 | 3072-bit RSA factoring | 2043 | Comparison point cited by Chevignard–Fouque–Schrottenloher — ECDLP at 256 bits is *more* qubit-expensive than RSA-3072 factoring under the old estimate |
| Chevignard–Fouque–Schrottenloher, EUROCRYPT 2026 (eprint 2026/280) | 256-bit ECDLP | **1193** (space complexity $3.12n + o(n)$; $2^{38.98}$ Toffoli gates/run, 22 independent runs) | Residue-number-system point multiplication + Legendre-symbol single-bit compression, avoiding modular inversion; gate count rises from $O(n^3)$ to $\widetilde O(n^4)$ to buy the qubit reduction |
| Follow-up distributed-quantum variant, eprint 2026/1244 | 256-bit ECDLP, per node | 1094–1154 (zero quantum-communication variant) or 856–1098 (sequential-communication variant, more nodes) | Splits the computation across cooperating quantum processing units rather than one monolithic device |

**Figure-attribution caveat.** Some 2026 secondary coverage of the Chevignard–Fouque–
Schrottenloher paper (e.g. quantumcomputingreport.com) cites **1098** logical qubits for
the 256-bit case rather than 1193. The paper's own eprint page (2026/280) carries an
explicit erratum note — "correction of another typo in the abstract (swap between
numbers for P-224 and P-256)" — so 1098 most likely reflects a since-corrected, swapped
P-224/P-256 attribution rather than a second independent figure; **1193 is the number
this document treats as authoritative**, taken directly from the current eprint abstract
text rather than secondary reporting. This is exactly the kind of slip a documentation
pass citing only a press summary would silently propagate, so it is recorded here rather
than picking a number without flagging the discrepancy.

**Applicability to HKEX-GF specifically.** These figures are for ECDLP over
$\mathbb{GF}(p)$ (prime-field elliptic curves), not HKEX-GF's actual group
$\mathbb{GF}(2^n)^{\ast}$. The two constructions that make the qubit reduction work —
representing point coordinates via a Residue Number System, and collapsing the
point-multiplication result to one bit via the **Legendre symbol** (a quadratic-residue
test specific to $\mathbb{GF}(p)$, $p$ prime) — do not have a published analogue for
characteristic-2 exponentiation. $\mathbb{GF}(2^n)^{\ast}$'s Shor circuit is ordinary
finite-field exponentiation (§10.8.4's $O(n^2 \log n)$ bound already covers it) without
this paper's specific compression trick, so **no qubit-count revision to $O(n^2 \log n)$
follows from this work** — these figures are cited here purely as a "how close is a
practical quantum attack, in general" data point (the same role RSA-3072 comparisons
already served in this section), not as a directly applicable resource estimate for
HKEX-GF's own group. The qualitative conclusion is unchanged either way: Shor's algorithm
in polynomial time breaks $\mathbb{GF}(2^n)^{\ast}$ DLP at every practical $n$, and continued
qubit-count reductions for the ECDLP sibling problem only reinforce that a
cryptographically-relevant fault-tolerant quantum computer is being actively engineered
toward, not that HKEX-GF's own concrete threat model has changed.

**HKEX-GF.** Given $(C, C_2) = (g^a, g^b)$, Shor's algorithm recovers $a$ (or $b$) in
$O(n^2 \log n)$ quantum time; the shared secret $g^{ab} = C_2^a$ follows immediately.

**HPKS.** Shor's algorithm recovers the private signing key $a$ from the public key
$C = g^a$.  With $a$ known, arbitrary signature forgeries are trivial.

**HPKE.** Shor's algorithm recovers the ephemeral exponent $r$ from $R = g^r$,
immediately yielding the encryption key $\mathit{ek} = C^r$.

**HSKE.** Not directly affected — HSKE security does not depend on DLP.

#### 10.8.5 HHL and Quantum Linear Algebra

**HSKE.**  Recovering $K$ from $c_K$ requires solving $\Phi \cdot K = c_K$ over
$\mathbb{GF}(2)$.  HHL solves linear systems over $\mathbb{R}$ or $\mathbb{C}$; it does
not directly apply to $\mathbb{GF}(2)$ systems.  Quantum algorithms for $\mathbb{GF}(2)$
linear algebra offer at most polynomial speedup, but the classical $O(n^{2.37})$ algorithm
already solves the system efficiently.  Since one KPT pair gives full $c_K$ recovery
without solving a linear system at all (direct XOR), HHL is irrelevant.

---

### 10.9 Root Cause: Why GF(2^n)* Is the Wrong Group

The choice of $\mathbb{GF}(2^n)^{\ast}$ as the DLP group introduces weaknesses absent in
standard DLP groups:

1. **Characteristic-2 quasi-polynomial attack** (Barbulescu et al., 2013): exploits
   sparse relations in the function field $\mathbb{GF}(2^n)(t)$, achieving
   $(\log N)^{O(\log\log N)}$ classical complexity.  This does not apply to prime-order
   elliptic curves or $\mathbb{Z}_p^{\ast}$.

2. **Shor's algorithm at $O(n^2 \log n)$**: applies to any cyclic group DLP; the
   characteristic-2 structure provides no resistance.

3. **Generator order**: when $g = 3$ is not a primitive element of $\mathbb{GF}(2^n)^{\ast}$
   (its actual order divides $2^n - 1$), the effective group size is smaller than assumed,
   reducing security further.

**Comparison with alternatives:**

| Group | Classical DLP | Quantum DLP |
|-------|--------------|-------------|
| $\mathbb{GF}(2^n)^{\ast}$ | Quasi-polynomial (weak) | Shor's polynomial |
| $\mathbb{Z}_p^{\ast}$, $p$ prime | Sub-exponential (NFS) | Shor's polynomial |
| Elliptic curve over $\mathbb{GF}(p)$ | Exponential (ECDLP) | Shor's polynomial |
| Ring-LWR ($\mathcal{R}_q$, blinded $m$, §11.4) | Exponential (conjectured) | No known polynomial attack |

Moving the key exchange to a prime-order elliptic curve restores classical DLP hardness
(no known sub-exponential algorithm) but does not address Shor's algorithm.  Only a
lattice, code-based, or isogeny-based construction provides a plausible path to
post-quantum security.  The HKEX-RNL proposal in §11.4 (Ring-LWR with blinded FSCX
polynomial) is the recommended direction within the Herradura suite.

---

> **Continued in Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
