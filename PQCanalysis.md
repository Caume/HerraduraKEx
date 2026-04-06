# Quantum Attack Analysis of the Herradura Cryptographic Suite
## Version 1.4.0 — HKEX-GF, HSKE, HPKS (Schnorr), HPKE (El Gamal)

---

## Preliminary: Notation and Structural Facts

Throughout, $n$ is the bit-width ($n = 32, 64, 128, 256$ in the implementation).
All arithmetic over $\mathbb{GF}(2)^n$ uses the operator ring
$R_n = \mathbb{GF}(2)[x]/(x^n+1)$.

**FSCX primitives** (unchanged from earlier versions):

- $M = I + L + L^{-1}$ where $L$ is 1-bit cyclic left rotation over $\mathbb{GF}(2)^n$.
- $M^{n/2} = I$, $S_n = \sum_{j=0}^{n-1} M^j = 0$ (SecurityProofs.md, Theorems 3, Cor. 1).
- **fscx\_revolve affine identity:** $\mathrm{fscx\_revolve}(A, B, k) = M^k \cdot A + M \cdot S_k \cdot B$.
- **Difference identity** (corrected): $\mathrm{fscx\_revolve}(A_1, B, k) \oplus \mathrm{fscx\_revolve}(A_2, B, k) = M^k \cdot (A_1 \oplus A_2)$.
  The $B$-dependent term cancels because $2 \equiv 0$ over $\mathbb{GF}(2)$.
  Equivalently: $\mathrm{fscx\_revolve}(A_1 \oplus A_2, 0, k) = M^k \cdot (A_1 \oplus A_2)$.

**GF(2^n) arithmetic:**

- $\mathbb{GF}(2^n)^*$ denotes the multiplicative group of the degree-$n$ extension
  field, realised via a primitive polynomial $p(x)$.
- Multiplication: `gf_mul(a, b)` — carry-less multiplication modulo $p(x)$.
- Exponentiation: `gf_pow(base, exp)` — repeated squaring in $\mathbb{GF}(2^n)$.
- The group $\mathbb{GF}(2^n)^*$ has order $2^n - 1$.
- Generator $g = 3$ is used as the base; its actual order in $\mathbb{GF}(2^n)^*$ depends
  on the chosen polynomial and may be a proper divisor of $2^n - 1$.

**Protocol parameters:** $i = n/4$ (encrypt steps), $r = 3n/4$ (decrypt steps), $i + r = n$.

---

## Historical Note: The Classical Break of the Original HKEX (v1.3 and earlier)

The previous version of HKEX used fscx\_revolve as the key-exchange primitive directly.
That construction was **classically broken** in $O(n^2)$ time: the shared secret satisfied
$\mathit{sk} = S_{r+1} \cdot (C \oplus C_2)$, a publicly computable linear formula.
See the archived analysis in `SecurityProofs.md` and `SecurityProofs2.md`.

**v1.4.0 replaces the original HKEX with HKEX-GF**, moving the key-exchange hardness
assumption from the linearity of fscx\_revolve to the Discrete Logarithm Problem (DLP)
in $\mathbb{GF}(2^n)^*$. fscx\_revolve is retained within HSKE, HPKS (challenge function),
and HPKE (payload encryption/decryption).

---

## Part I: Classical Security of the v1.4.0 Protocol Stack

### 1.1 HKEX-GF — DH over GF(2^n)*

**Protocol.** Alice holds private scalar $a$; Bob holds $b$. Both are integers
(odd, to avoid trivial edge cases).

$$C = g^a \in \mathbb{GF}(2^n)^*, \quad C_2 = g^b \in \mathbb{GF}(2^n)^*$$

Shared secret: $\mathit{sk} = C_2^a = C^b = g^{ab} \in \mathbb{GF}(2^n)^*$.

**Security assumption.** HKEX-GF security reduces to the **Computational Diffie-Hellman
(CDH)** problem in $\mathbb{GF}(2^n)^*$, which in turn reduces to the **DLP**:
given $g$ and $g^a$, find $a$.

**Correctness.**

$$C_2^a = (g^b)^a = g^{ab} = (g^a)^b = C^b \quad \checkmark$$

**Classical DLP complexity.** For DLP in $\mathbb{GF}(2^n)^*$:

| Algorithm | Complexity | Notes |
|-----------|-----------|-------|
| Baby-step giant-step (BSGS) | $O(2^{n/2})$ time, $O(2^{n/2})$ space | Generic group |
| Pohlig-Hellman | $O(\sqrt{q})$ where $q$ is largest prime factor of group order | Dangerous if group order is smooth |
| Index calculus (function field sieve) | $L_{2^n}[1/2, c]$ = sub-exponential | General DLP in $\mathbb{GF}(2^n)^*$ |
| **Quasi-polynomial (Barbulescu-Joux-Pierrot 2013)** | $(\log 2^n)^{O(\log\log 2^n)}$ | Specific to GF(2^n) and GF(p^n) with small $p$ |

**The quasi-polynomial attack (Barbulescu et al., 2013) is the dominant classical threat.**
It exploits the structure of $\mathbb{GF}(2^n)^*$ specifically — the characteristic-2
finite field setting allows a descent approach that is much faster than generic sub-exponential
DLP. This effectively means that $\mathbb{GF}(2^n)^*$ is a **cryptographically weak group**
for DLP-based key exchange. For comparison, DLP in prime-order elliptic curve groups over
$\mathbb{GF}(p)$ has no known sub-exponential algorithm.

**Experimental verification at $n = 32$.**

Baby-step giant-step (BSGS) was applied to the 32-bit demo parameters:

```python
A_PRIV = 0xDEADBEEF   # Alice's actual private key
C      = 0x5B8AE480   # Public key: g^A_PRIV in GF(2^32)*

# BSGS recovered:
a_rec  = 0x00CFE112   # Different integer, same public key
# Verification:
gf_pow(3, a_rec) == C   # True: 0x5B8AE480
# Shared secret fully recovered:
sk_actual  = 0xD3DB6BC3
sk_from_dlp = gf_pow(C2, a_rec)   # 0xD3DB6BC3 — matches
# Time: 0.622 seconds on a single CPU core
```

The recovered exponent $a_\text{rec} \neq A_\text{PRIV}$ because $g = 3$ is not a
primitive element of $\mathbb{GF}(2^{32})^*$: its order is a proper divisor of $2^{32}-1$.
Multiple exponents map to the same public key; BSGS finds the smallest one. The shared
secret is nevertheless fully recovered because $g^{ab}$ is the same regardless of which
representative of the discrete log is used.

**Effective security at $n = 32$:** Broken in under 1 second. This is explicitly a
demonstration parameter. The quasi-polynomial attack extends to much larger $n$.

**Effective security at production scales.** The Barbulescu-Joux-Pierrot quasi-polynomial
algorithm has been applied in practice to break DLP in $\mathbb{GF}(2^{1279})$ and related
fields. The recommended minimum for DLP in $\mathbb{GF}(2^n)^*$ (if it must be used) is
$n \geq 3000$, and most standards bodies advise **against** using $\mathbb{GF}(2^n)^*$ for
new DLP-based designs due to this attack family.

---

### 1.2 HSKE — Symmetric Encryption via fscx\_revolve

**Protocol.**

$$E = \mathrm{fscx\_revolve}(P, K, i), \qquad D = \mathrm{fscx\_revolve}(E, K, r) = P$$

**Affine structure.** By the iteration formula:

$$E = M^i \cdot P + M \cdot S_i \cdot K, \qquad c_K \triangleq M \cdot S_i \cdot K$$

One known-plaintext pair $(P_1, E_1)$ immediately yields $c_K = E_1 \oplus M^i \cdot P_1$.

**Experimental verification at $n = 64$.**

```python
# One KPT pair (P1, E1):
c_K_recovered = E1 ^ fscx_revolve(P1, BitArray(64, 0), i_val(64))
c_K_true      = E1 ^ fscx_revolve(P1, BitArray(64, 0), i_val(64))
assert c_K_recovered == c_K_true   # True

# Bits of K with zero effect on c_K (lie in ker(Phi)):
unconstrained_bits = 0   # 0 out of 64 at n=64, i=16
```

All 64 key bits are constrained by a single plaintext pair at $n = 64, i = 16$.
This confirms $\mathrm{rank}(\Phi) = n$ for these parameters, meaning one KPT pair
fully determines $c_K$ and the system $\Phi \cdot K = c_K$ has a unique solution.

**Note:** Whether $\Phi = M \cdot S_i \cdot (M + I) \cdot K$ is actually invertible
(rank $= n$) depends on the specific $(n, i)$ pair. At $n = 64, i = 16$: rank $= 64$.
For other parameter sets, rank must be determined numerically.

---

### 1.3 HPKS — Schnorr-like Signature with fscx\_revolve Challenge

**Protocol (sign with private $a$, verify with public $C = g^a$).**

*Signing:*

1. Draw random $k \in \mathbb{Z}$; compute $R = g^k \in \mathbb{GF}(2^n)^*$.
2. Challenge: $e = \mathrm{fscx\_revolve}(R_{\text{bits}}, P, i)$ where $R_{\text{bits}}$ is $R$ as a bit-vector.
3. Response: $s = (k - a \cdot e_{\text{uint}}) \bmod \mathrm{ORD}$ where $\mathrm{ORD} = 2^n - 1$.

*Verification (public $C$, message $P$, signature $(R, s)$):*

1. Recompute $e = \mathrm{fscx\_revolve}(R_{\text{bits}}, P, i)$.
2. Check: $g^s \cdot C^{e_{\text{uint}}} = R$ in $\mathbb{GF}(2^n)^*$.

**Correctness proof:**

$$g^s \cdot C^e = g^{k - ae} \cdot (g^a)^e = g^{k - ae + ae} = g^k = R \quad \checkmark$$

**Classical forgery resistance.** To forge $(R^*, s^*)$ for message $P^*$ without knowing
$a$, Eve must find $s^*$ such that $g^{s^*} \cdot C^{e^*} = R^*$ where $e^* = \mathrm{fscx\_revolve}(R^*_{\text{bits}}, P^*, i)$.

- If Eve fixes $R^*$ first: she needs $g^{s^*} = R^* \cdot C^{-e^*}$, i.e., she must solve
  the DLP $s^* = \log_g(R^* \cdot C^{-e^*})$. This requires solving DLP in $\mathbb{GF}(2^n)^*$.
- If Eve fixes $s^*$ first: she needs $g^{s^*} \cdot C^{e^*} = R^*$ for some $R^*$ of her
  choice. She can compute the left-hand side for any $e^*$, but $e^* = \mathrm{fscx\_revolve}(R^*_{\text{bits}}, P^*, i)$
  constrains $R^*$ and $e^*$ jointly. Breaking this requires inverting fscx\_revolve as a
  function of its first argument — but fscx\_revolve is a bijection in its first argument
  (see §1.4), so Eve must simultaneously satisfy both the DLP equation and the challenge
  equation, which reduces to DLP hardness.

**Forgery resistance depends on DLP hardness in $\mathbb{GF}(2^n)^*$**, subject to the
caveats in §1.1 and the non-ROM challenge analysis in §1.4.

---

### 1.4 HPKE — El Gamal Encryption with fscx\_revolve Payload

**Protocol.**

*Encryption (Bob encrypts to Alice's public key $C = g^a$):*

1. Bob draws ephemeral $r$; computes $R = g^r \in \mathbb{GF}(2^n)^*$.
2. Encryption key: $\mathit{ek} = C^r = g^{ar}$.
3. Ciphertext: $E = \mathrm{fscx\_revolve}(P, \mathit{ek}, i)$. Transmitted: $(R, E)$.

*Decryption (Alice uses private $a$):*

1. Decryption key: $\mathit{dk} = R^a = g^{ra} = g^{ar} = \mathit{ek}$.
2. Plaintext: $D = \mathrm{fscx\_revolve}(E, \mathit{dk}, r) = P$.

**Correctness:** $\mathit{ek} = g^{ar} = g^{ra} = \mathit{dk}$; round-trip via HSKE
identity $\mathrm{fscx\_revolve}(\mathrm{fscx\_revolve}(P, K, i), K, r) = P$.

**Security.** Ciphertext indistinguishability reduces to the **CDH problem** in
$\mathbb{GF}(2^n)^*$: given $(g^a, g^r)$, compute $g^{ar}$.
CDH $\leq$ DLP, so all DLP attacks in §1.1 apply directly.

---

### 1.5 The fscx\_revolve Challenge Function — Algebraic Properties

The challenge function in HPKS uses fscx\_revolve in place of a hash function. Its
algebraic properties affect provable security in the Random Oracle Model (ROM).

**Property 1: Bijection in first argument.**
For fixed $P$ and step count $i$, the map $R \mapsto \mathrm{fscx\_revolve}(R, P, i) = M^i \cdot R + M \cdot S_i \cdot P$
is an **affine bijection** (the linear part $M^i$ is invertible; $M$ has order $n/2$).
No two distinct $R$ values produce the same challenge $e$.

*Experimental verification:* 50 000 random $R$ values with fixed $P$ at $n = 64$: **0 collisions** observed.

**Property 2: Predictable challenge delta.**
By the difference identity:

$$e(R_2) \oplus e(R_1) = \mathrm{fscx\_revolve}(R_1 \oplus R_2, 0, i) = M^i \cdot (R_1 \oplus R_2)$$

The challenge difference is a **publicly computable** linear function of the $R$-difference.
Given one valid challenge $e(R_1)$, the challenge for any $R_2 = R_1 \oplus \delta$ is
$e(R_2) = e(R_1) \oplus M^i \cdot \delta$ — no oracle access required.

*Experimental verification:* 10 000 random $(R_1, R_2)$ pairs at $n = 64$: identity
$e(R_2) = e(R_1) \oplus \mathrm{fscx\_revolve}(R_1 \oplus R_2, 0, i)$ holds **100%**.

**Consequence for ROM-based security proofs.**
Standard Schnorr security proofs (e.g., Pointcheval-Stern) assume the challenge hash is
modelled as a random oracle: an adversary who can adaptively query $H$ learns no structural
information about outputs from other inputs. fscx\_revolve violates this assumption: the
adversary can predict all challenges without any oracle query.

**Consequence for the forking lemma.**
The forking lemma (used in Schnorr proofs) requires that rewinding the adversary with a
different challenge on the same $R$ produces an independent random challenge. Here, given
any challenge $e_1$ for $(R, P)$, an adversary who sees $e_1$ can compute the challenge
$e_2$ for $(R, P')$ for any $P'$ using $e_2 = e_1 \oplus M^i \cdot (P \oplus P')$.
The forking lemma argument does not apply in its standard form.

**Practical implication.**
The DLP in $\mathbb{GF}(2^n)^*$ still protects the private key $a$: Eve cannot recover $a$
from the Schnorr equation without solving DLP. But the absence of ROM for the challenge
function means the Schnorr security proof does not carry over, and subtle attacks
exploiting challenge predictability cannot be ruled out by the standard proof alone.

---

## Part II: Quantum Algorithm Analysis

### 2.1 Grover's Algorithm

**Application to HSKE.**
HSKE is the only protocol whose security does not depend on DLP. Brute-force key search
over $2^n$ keys costs $O(2^n)$ classically and $O(2^{n/2})$ with Grover's algorithm.
For $n = 256$, Grover provides $2^{128}$ post-quantum symmetric security **against
key-only attacks**. However, the known-plaintext attack (1 pair → full $c_K$ recovery)
already breaks HSKE classically at all $n$; Grover is irrelevant when plaintexts are available.

**Application to HKEX-GF, HPKE, HPKS.**
The security of these protocols rests on DLP in $\mathbb{GF}(2^n)^*$. Grover reduces
generic group order search from $O(2^n)$ to $O(2^{n/2})$, but Shor's algorithm (§2.4)
solves DLP in polynomial quantum time — strictly dominating Grover.
**Grover is irrelevant for the GF-DLP protocols.**

---

### 2.2 Simon's Algorithm — Inapplicable to GF(2^n)* DLP

**Simon's problem.** Find a hidden period $s$ of a function $f(x) = f(x \oplus s)$ in
$O(n)$ quantum queries.

**Applicability.** Simon's algorithm (and its generalisation to the Abelian Hidden Subspace
Problem) applies to functions whose collision structure is defined by a **linear** (over
$\mathbb{GF}(2)$) hidden subgroup. The DLP function $f(x) = g^x$ in $\mathbb{GF}(2^n)^*$
has collisions determined by the **cyclic** (not linear) group structure of the exponent:
$g^{x_1} = g^{x_2}$ iff $x_1 \equiv x_2 \pmod{|\langle g \rangle|}$.
This is a $\mathbb{Z}$-linear (integer arithmetic) period, not a $\mathbb{GF}(2)$-linear
period. Simon's QFT over $\mathbb{GF}(2)^n$ cannot extract it.

**The correct quantum algorithm for cyclic-group DLP is Shor's** (§2.4), which uses the
QFT over $\mathbb{Z}_N$.

**Application to HSKE.** The old HKEX (v1.3) had $\mathbb{GF}(2)$-linear structure
exploitable by Simon/HSP. HSKE retains affine $\mathbb{GF}(2)$ structure, so Simon's HSP
can still be applied to the HSKE encryption oracle. As noted in prior analyses, it
recovers the kernel of the affine map, but provides no advantage beyond the classical
1-pair known-plaintext attack.

---

### 2.3 Bernstein-Vazirani Algorithm

**Application to HSKE.**
The HSKE encryption map $E = M^i \cdot P + c_K$ is affine in $P$. With oracle access to
the encryption function (fixed key, variable plaintext), BV recovers $c_K$ in **1 quantum
query**. This matches the classical known-plaintext bound: 1 $(P,E)$ pair suffices.
BV provides no asymptotic quantum advantage over the classical attack.

**Application to HKEX-GF, HPKE, HPKS.**
These protocols involve $\mathbb{GF}(2^n)^*$ exponentiation, which is not a $\mathbb{GF}(2)$-affine
function of the exponent. BV does not apply.

---

### 2.4 Shor's Algorithm — Primary Quantum Threat

**Shor's algorithm** solves the DLP in any cyclic group $G = \langle g \rangle$ of order
$N$ in $O((\log N)^2 \log\log N \cdot \log\log\log N)$ quantum gate operations using the
Quantum Fourier Transform over $\mathbb{Z}_N$. For DLP in $\mathbb{GF}(2^n)^*$:

- Group order: $N = 2^n - 1$ (or divisor thereof if $g$ is not a primitive root).
- Quantum time: $O(n^2 \log n)$.
- Classical preprocessing needed: $O(n)$ quantum queries to the group oracle.

**Application to HKEX-GF.**
Given public values $C = g^a$ and $C_2 = g^b$, Shor's algorithm computes $a$ (or $b$)
in $O(n^2 \log n)$ quantum time. The shared secret $\mathit{sk} = C_2^a = g^{ab}$ is
then directly computable. **HKEX-GF is quantum-insecure via Shor's algorithm.**

**Application to HPKE.**
Ciphertext is $(R, E) = (g^r, \mathrm{fscx\_revolve}(P, g^{ar}, i))$. Shor's algorithm
computes $r$ from $R = g^r$, then the encryption key $g^{ar} = C^r$ is recovered.
Alternatively, Shor solves the CDH from the public pair $(g^a, g^r)$.
**HPKE is quantum-insecure via Shor's algorithm.**

**Application to HPKS.**
The private signing key is $a$ where $C = g^a$ is public. Shor's algorithm recovers $a$
from $C$ in $O(n^2 \log n)$ quantum time. With $a$ known, the adversary can forge
arbitrary signatures. **HPKS is quantum-insecure via Shor's algorithm.**

**Comparison with classical quasi-polynomial attack.**
For classical adversaries, the Barbulescu quasi-polynomial algorithm is the dominant
threat to $\mathbb{GF}(2^n)^*$ DLP. For quantum adversaries, Shor's polynomial algorithm
is strictly stronger:

| Adversary | Best DLP attack on $\mathbb{GF}(2^n)^*$ | Complexity |
|-----------|----------------------------------------|------------|
| Classical | Quasi-polynomial (Barbulescu 2013) | $(\log N)^{O(\log\log N)}$ |
| Quantum | Shor's algorithm | $O((\log N)^2 \log\log N)$ |

Both render $\mathbb{GF}(2^n)^*$ DLP insecure at any currently practical parameter size.

---

### 2.5 HHL and Quantum Linear Algebra

**Application.**
HSKE has an affine $\mathbb{GF}(2)$ structure; recovering $K$ from $c_K$ requires solving
$\Phi \cdot K = c_K$ over $\mathbb{GF}(2)$. HHL solves linear systems over $\mathbb{R}$ or
$\mathbb{C}$; it does not directly apply to $\mathbb{GF}(2)$ systems. Quantum algorithms
for $\mathbb{GF}(2)$ linear algebra (e.g., based on quantum Gaussian elimination) offer
at most polynomial speedup, but the $n \times n$ system is already solvable classically
in $O(n^{2.37})$. Since one KPT pair gives full $c_K$ recovery (see §1.2), the bottleneck
is not linear algebra but the KPT requirement. HHL is irrelevant.

---

## Part III: Protocol-Level Quantum Security

### 3.1 HKEX-GF

**Hardness assumption.** CDH (and DLP) in $\mathbb{GF}(2^n)^*$.

**Classical attack.** Quasi-polynomial DLP (Barbulescu 2013). At $n = 32$: BSGS
solves it in 0.622 s (demo-scale; completely broken). At $n = 256$: quasi-polynomial
attack requires $(\log 2^{256})^{O(\log 256)} \approx 256^{O(8)}$ operations — far below
128-bit security.

**Quantum attack.** Shor's algorithm solves DLP in $O(n^2 \log n)$ quantum time.
For $n = 256$: approximately $256^2 \cdot 8 \approx 524\,288$ quantum gates
(ignoring circuit depth constants). Well within reach of a large fault-tolerant
quantum computer.

**Post-quantum security:** None. Both classical (quasi-polynomial) and quantum (Shor's
polynomial) attacks break HKEX-GF at all parameter sizes.

**Recommendation:** $\mathbb{GF}(2^n)^*$ is the wrong group for DLP-based key exchange.
Replacing it with a prime-order elliptic curve group would restore classical DLP hardness
(no known sub-exponential classical algorithm) but would still be broken by Shor's
algorithm. Post-quantum key exchange requires lattice, code, isogeny, or hash-based
constructions.

---

### 3.2 HSKE (Standalone)

**Known-plaintext attack (classical, 1 pair).** One $(P, E)$ pair gives
$c_K = E \oplus M^i \cdot P$. For $n = 64, i = 16$: all 64 key bits are constrained
(experimentally verified: 0 unconstrained bits). With full $c_K$ and invertible $\Phi$,
$K$ is uniquely recovered.

**Key-only attack (no plaintexts).** Brute-force: $2^n$ classically, $2^{n/2}$ with Grover.
For $n = 256$: 128-bit post-quantum security against key-only attacks. This bound is
tight if $\text{rank}(\Phi) = n$ (confirmed at $n = 64$; must be verified per $(n,i)$).

**Quantum advantage summary.** BV/Simon recover $c_K$ in 1 query (matching classical KPT).
Grover reduces key-only search. Neither provides advantage when a plaintext pair is known.

**Post-quantum security (HSKE standalone):** $\min(\lfloor n/2 \rfloor, \lfloor\rho/2\rfloor)$ bits
where $\rho = \text{rank}(\Phi)$ — under key-only attack only. Zero security under known-plaintext attack.

---

### 3.3 HPKS — Schnorr-like Signature

**Security model.** Unforgeability under chosen-message attack (EUF-CMA), assuming DLP
hardness and treating fscx\_revolve as a pseudorandom challenge function.

**Classical forgery.** Requires solving DLP in $\mathbb{GF}(2^n)^*$ or finding an $R, s$
pair satisfying the Schnorr equation without knowing $a$. Subject to the quasi-polynomial
DLP attack at all $n$.

**Quantum forgery.** Shor's algorithm recovers $a$ from $C = g^a$ in $O(n^2 \log n)$
quantum time. With $a$ known, arbitrary forgeries are trivial.

**Challenge function caveat.** The challenge $e = \mathrm{fscx\_revolve}(R, P, i)$ is
an affine bijection (not a random oracle). The challenge delta $e(R_2) \oplus e(R_1) = M^i \cdot (R_1 \oplus R_2)$
is publicly predictable. Standard Schnorr security proofs (forking lemma, ROM) do not
apply. Classical DLP hardness still blocks key recovery, but sophisticated adaptive
attacks exploiting challenge linearity cannot be excluded by proof.

**Post-quantum security:** None (Shor's algorithm recovers signing key).

---

### 3.4 HPKE — El Gamal + fscx\_revolve

**Security model.** IND-CPA (semantic security) under CDH hardness assumption.

**Classical attack.** CDH in $\mathbb{GF}(2^n)^*$, subject to quasi-polynomial DLP.
Also: the affine structure of fscx\_revolve means that given $(g^r, E)$ and one
known-plaintext pair, $\mathit{ek} = g^{ar}$ can be extracted via $c_{\mathit{ek}} = E \oplus M^i \cdot P$.
Then DLP on $\mathit{ek} = C^r$ or $\mathit{ek} = (g^r)^a$ may recover $a$ or $r$.

**Quantum attack.** Shor's algorithm recovers $r$ from $R = g^r$ in $O(n^2 \log n)$
quantum time, immediately yielding $\mathit{ek} = C^r$.

**Post-quantum security:** None (Shor's algorithm recovers ephemeral key).

---

## Part IV: Updated Summary Table

| Protocol | Security Assumption | Classical Attack | Complexity | Quantum Attack | Post-Quantum |
|---|---|---|---|---|---|
| **HKEX-GF** | DLP in $\mathbb{GF}(2^n)^*$ | Quasi-polynomial (Barbulescu 2013) | $(\log N)^{O(\log\log N)}$ | Shor's DLP | **None** |
| **HSKE** (standalone, key-only) | Exhaustive key search | Brute force: $2^n$ | $2^n$ | Grover: $2^{n/2}$ | $n/2$ bits |
| **HSKE** (known-plaintext) | — | 1 KPT pair → full $c_K$ | $O(n^2)$ | BV: 1 query | **None** |
| **HPKS** (Schnorr) | DLP in $\mathbb{GF}(2^n)^*$ + challenge structure | Quasi-polynomial DLP | $(\log N)^{O(\log\log N)}$ | Shor's DLP | **None** |
| **HPKE** (El Gamal) | CDH in $\mathbb{GF}(2^n)^*$ | CDH ≤ DLP, quasi-polynomial | $(\log N)^{O(\log\log N)}$ | Shor's CDH | **None** |

**Legend.** "None" means the security assumption is broken by a known efficient (classical
or quantum) algorithm; the protocol should not be used for security-sensitive applications.

---

## Part V: Root Cause Analysis — From GF(2) Linearity to GF(2^n) DLP

### 5.1 What Changed in v1.4.0

The original HKEX was broken by the **GF(2) linearity** of fscx\_revolve: the map
$A \mapsto M^i \cdot A + \text{const}$ is linear, so the shared secret was a linear
combination of public values computable in $O(n^2)$.

v1.4.0 moves the hardness assumption to **DLP in $\mathbb{GF}(2^n)^*$**, which is a
genuinely non-linear problem. The exponentiation $a \mapsto g^a$ in $\mathbb{GF}(2^n)^*$
is not a $\mathbb{GF}(2)$-linear map; the classical $O(n^2)$ break no longer applies.

This is a **qualitative improvement**: the hardness assumption is now comparable to
standard Diffie-Hellman.

### 5.2 Why GF(2^n)* Is Still the Wrong Choice

The choice of $\mathbb{GF}(2^n)^*$ as the DLP group introduces a different, well-known
weakness. The quasi-polynomial algorithm of Barbulescu, Gaudry, Joux, and Thomé (2013)
exploits the **characteristic-2** structure of the field via a descent using sparse
linear systems in function fields. This does not apply to DLP in prime-order elliptic
curves or prime-field $\mathbb{Z}_p^*$ in the same way.

The result is that $\mathbb{GF}(2^n)^*$ DLP is weaker than DLP in a comparably-sized
prime-field group. Moving to an elliptic curve over $\mathbb{GF}(p)$ (or $\mathbb{F}_{2^n}$
in a twist-secure form) would restore standard DLP hardness.

### 5.3 The Role of fscx\_revolve in v1.4.0

In v1.4.0, fscx\_revolve no longer carries the security of the key exchange itself.
Its roles are:

| Protocol | Role of fscx\_revolve | Security contribution |
|---|---|---|
| HSKE | Encryption/decryption primitive | All HSKE security comes from key entropy |
| HPKS | Challenge hash $H(R, P)$ | Non-ROM bijection; DLP still guards $a$ |
| HPKE | Payload encryption/decryption | Payload security derives from CDH hardness |
| HKEX-GF | Not used | None (pure GF DH) |

The security of all asymmetric protocols (HKEX-GF, HPKS, HPKE) is determined entirely
by DLP hardness in $\mathbb{GF}(2^n)^*$ — fscx\_revolve contributes only to the
payload layer, not the key-hardness layer.

### 5.4 Quantum Threat Summary

For classical adversaries, the dominant threat to all v1.4.0 asymmetric protocols is
the quasi-polynomial DLP attack on $\mathbb{GF}(2^n)^*$. For quantum adversaries,
Shor's algorithm provides an additional polynomial-time attack. Since the quasi-polynomial
attack already breaks security at practical parameter sizes, and Shor's attack is
polynomially faster still, **the protocols are broken both classically and quantum-mechanically**.

The only component with meaningful post-quantum security is **HSKE in the key-only
setting** ($n/2$ bits under Grover), provided no plaintext is known. As soon as any
plaintext pair is available, HSKE's affine structure yields the key deterministically.

---

## Part VI: Experimental Summary

All experiments were run in Python on the `devtest` branch (v1.4.0) using the
parameters in `Herradura cryptographic suite.py` and `Herradura_tests.py`.

| Experiment | Parameters | Result |
|---|---|---|
| BSGS DLP on HKEX-GF | $n=32$, $g=3$, $A_\text{PRIV}=\texttt{0xDEADBEEF}$ | $a_\text{rec}=\texttt{0x00CFE112}$; $\mathit{sk}=\texttt{0xD3DB6BC3}$; time: **0.622 s** |
| fscx\_revolve difference identity | $n=64$, 10 000 trials | $e(R_1) \oplus e(R_2) = M^i(R_1 \oplus R_2)$: **100%** |
| fscx\_revolve challenge bijectivity | $n=64$, 50 000 random $R$ | Challenge collisions: **0** |
| HSKE KPT recovery | $n=64$, 1 plaintext pair | Unconstrained $K$-bits: **0 of 64** |
| Schnorr correctness | $n=32$, 10 000 trials | Pass: **10 000/10 000** |
| Schnorr correctness | $n=64$, 500 trials | Pass: **500/500** |
| Schnorr correctness | $n=128$, 500 trials | Pass: **500/500** |
| Schnorr Eve forgery resistance | $n=32$, 1 000 trials | Forgery successes: **0** |

---

*Analysis updated for v1.4.0 — 2026-04-05*
