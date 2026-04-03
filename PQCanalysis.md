# Quantum Attack Analysis of the Herradura Cryptographic Suite

---

## Preliminary: Notation and Structural Facts

Throughout, $n = 2^k$ is the bit-width ($n = 64, 128, 256$ in the implementation). All
arithmetic is in $\mathbb{GF}(2)$; all vectors are elements of $\mathbb{GF}(2)^n$. The
operator ring is $R_n = \mathbb{GF}(2)[x]/(x^n+1)$.

The key facts from SecurityProofs.md are taken as established:

- $M = I + L + L^{-1}$ (where $L$ is 1-bit cyclic left rotation)
- $M^{n/2} = I$ (Theorem 3)
- $S_n = I + M + \cdots + M^{n-1} = 0$ (Corollary 1)
- Fundamental identity: $M \cdot S_r + M^{r+1} \cdot S_i = S_n = 0$ for $i + r = n$ (Theorem 6 proof)
- Affine iteration formula: $g_{B,N}^k(X) = M^k \cdot X + S_k \cdot (M \cdot B \oplus N)$

---

## Part I: A Classical Polynomial-Time Break of HKEX

Before addressing quantum attacks it is necessary to establish that HKEX has a classical
vulnerability, because it shapes the quantum analysis at every level.

**Theorem (Classical Break).** *The HKEX shared secret $\mathit{sk}$ is a known
$\mathbb{GF}(2)$-linear function of the two public values $C$ and $C_2$. Specifically:*

$$\mathit{sk} = S_{r+1} \cdot (C \oplus C_2), \qquad S_{r+1} = I + M + M^2 + \cdots + M^r$$

*where $S_{r+1}$ is a fixed, publicly known linear operator. Therefore $\mathit{sk}$ is
computable by any observer in $O(r \cdot n)$ bit operations.*

**Proof.** Let $i + r = n$ with $i = n/4$, $r = 3n/4$. Alice holds $(A, B)$ and publishes
$C = M^i \cdot A + M \cdot S_i \cdot B$. She computes:

$$\mathit{sk}_A = \underbrace{M^r \cdot C_2 + S_r \cdot M \cdot B \oplus S_r \cdot N}_{\text{FSCX\_REVOLVE\_N}(C_2,\, B,\, N,\, r)} \oplus A, \qquad N = C \oplus C_2$$

From $C = M^i \cdot A + M \cdot S_i \cdot B$ and $M^{-i} = M^{n-i} = M^r$ (since $M^n = I$):

$$A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B \tag{*}$$

Substituting $(*)$ and $N = C \oplus C_2$:

$$\mathit{sk}_A = M^r \cdot C_2 + S_r \cdot M \cdot B \oplus S_r \cdot (C \oplus C_2) \oplus M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$$

Collecting terms:

$$= M^r \cdot (C \oplus C_2) \oplus S_r \cdot (C \oplus C_2) \oplus \underbrace{(S_r \cdot M + M^{r+1} \cdot S_i)}_{=\, S_n\, =\, 0} \cdot B$$

$$= (M^r + S_r) \cdot (C \oplus C_2) = S_{r+1} \cdot (C \oplus C_2) \qquad \blacksquare$$

**Computational verification.** With the test parameters ($n=32$, $i=8$, $r=24$,
$C = \texttt{0x09DD9660}$, $C_2 = \texttt{0xEA1CAE50}$):

$$S_{25} \cdot (C \oplus C_2) = \texttt{0x8D3E039A} = \mathit{sk}$$

Confirmed by direct computation:

```c
// S_{r+1}·X = X ^ M·X ^ M^2·X ^ ... ^ M^r·X
uint32_t sk_direct = 0, cur = C ^ C2;
for (int j = 0; j <= r; j++) { sk_direct ^= cur; cur = M(cur); }
// sk_direct == skA == skB  (verified)
```

**Corollary.** Any passive eavesdropper Eve who observes only $(C, C_2)$ during the key
exchange computes the shared secret as:

$$\mathit{sk} = \bigoplus_{j=0}^{r} M^j \cdot (C \oplus C_2)$$

which costs $O(r \cdot n) = O(n^2)$ bit operations — classical polynomial time, no quantum
resources required.

**Consequence for the protocol stack.** Since $\mathit{sk}$ is publicly computable,
every protocol built on HKEX inherits a complete break:

- **HPKE**: Ciphertext $E = \mathit{sk}_B \oplus A_2 \oplus P$. Both $\mathit{sk}_B$ and
  $A_2$ are computable from public values. Eve recovers $P = E \oplus \mathit{sk} \oplus A_2$.
- **HPKS₂**: Signing key is $\mathit{sk}_A$, which Eve now possesses. She can verify or
  forge signatures.
- **HSKE**: Does not use HKEX; analyzed separately in Part III.

---

## Part II: Quantum Algorithm Analysis

### 2.1 Grover's Algorithm

**Algorithm.** For an $N$-element unstructured search space, Grover's algorithm finds a
marked element in $O(\sqrt{N})$ quantum oracle calls, compared to $O(N)$ classically.
Applied to symmetric key search over an $n$-bit space, it yields security of $n/2$ bits
against quantum adversaries.

**Application to HSKE.** HSKE is the only protocol that does not depend on HKEX. Its
security rests on the difficulty of recovering $K$ from $(E, P)$ pairs. The cipher is:

$$E = M^i \cdot P + S_i \cdot (M + I) \cdot K$$

Classically, brute-force key search costs $2^n$. Grover reduces this to $2^{n/2}$. For
$n = 256$, this gives 128-bit post-quantum symmetric security, which meets the standard
post-quantum recommendation (matching AES-256).

**Formal statement.** Let $\mathcal{A}_G$ be a quantum adversary running Grover's
algorithm. The success probability after $q$ oracle calls satisfies:

$$\Pr[\mathcal{A}_G \text{ succeeds}] = \sin^2\!\bigl((2q+1)\arcsin(1/\sqrt{2^n})\bigr)$$

For $q = O(2^{n/2})$, this approaches 1.

**Limitation.** Grover applies to unstructured search. Since HSKE is an affine cipher
(see §2.3), a cheaper structured classical known-plaintext attack already exists. Grover's
$2^{n/2}$ bound is therefore an overestimate of HSKE's actual quantum security.

**Application to HKEX.** Irrelevant — the classical polynomial-time break ($O(n^2)$) is
already faster than $2^{n/2}$ for all practical $n$.

---

### 2.2 Simon's Algorithm and the Abelian Hidden Subspace Problem

**Simon's problem.** Given oracle access to $f: \{0,1\}^n \to \{0,1\}^n$ satisfying
$f(x) = f(x \oplus s)$ for a hidden $s \neq 0$, find $s$ in $O(n)$ quantum queries
(vs. $O(2^{n/2})$ classically by birthday paradox).

The generalization to $\mathbb{GF}(2)^n$ is the **Abelian Hidden Subspace Problem (HSP)**:
given a function $f: \mathbb{GF}(2)^n \to X$ that is constant and distinct on cosets of a
hidden subgroup $H \leq \mathbb{GF}(2)^n$, recover $H$ in polynomial time using the
Quantum Fourier Transform over $\mathbb{GF}(2)^n$ (i.e., the tensor Hadamard
$H^{\otimes n}$).

**Application to HKEX.** Define:

$$f: \mathbb{GF}(2)^n \times \mathbb{GF}(2)^n \to \mathbb{GF}(2)^n, \qquad f(A, B) = M^i \cdot A + M \cdot S_i \cdot B$$

This is a surjective $\mathbb{GF}(2)$-linear map from $\mathbb{GF}(2)^{2n}$ to
$\mathbb{GF}(2)^n$. Its kernel is:

$$K = \ker f = \{(A, B) : M^i \cdot A = M \cdot S_i \cdot B\} = \{(M^{1-i} \cdot S_i \cdot B,\ B) : B \in \mathbb{GF}(2)^n\}$$

$\dim_{\mathbb{GF}(2)} K = n$. The function $f$ is constant on cosets of $K$ in
$\mathbb{GF}(2)^{2n}$ — this is exactly the abelian HSP. The standard HSP quantum
algorithm recovers $K$ in $O(n)$ quantum queries to $f$ and $O(n^2)$ classical
post-processing via the Hadamard transform.

**What knowing $K$ gives the attacker.** Given the public value $C = f(A, B)$, the set
of consistent private pairs is the coset $(A, B) + K$. For any $(A', B') = (A \oplus a,
B \oplus b)$ with $(a, b) \in K$, the candidate shared key is:

$$\mathit{sk}' = \mathit{sk}_A \oplus (S_r \cdot M + M^{r+1} \cdot S_i) \cdot b = \mathit{sk}_A \oplus S_n \cdot b = \mathit{sk}_A$$

Every element of the coset yields the same $\mathit{sk}$. Knowing $K$ does not directly
yield $\mathit{sk}$ — but neither does it need to, since $\mathit{sk} = S_{r+1} \cdot
(C \oplus C_2)$ is computable classically from public values.

**Conclusion.** Simon's / HSP algorithm recovers the kernel of the HKEX map in
polynomial quantum time, but provides no attack advantage beyond the existing $O(n^2)$
classical formula. The quantum attack is strictly dominated by the classical one.

---

### 2.3 Bernstein-Vazirani Algorithm

**BV problem.** Given oracle access to $f_s(x) = s \cdot x \pmod{2}$ (inner product with
hidden $s \in \{0,1\}^n$), BV recovers $s$ in **1 quantum query** (vs. $n$ classical
queries).

**Application to FSCX and HSKE.** HSKE encryption is:

$$E = g_{K,K}^i(P) = M^i \cdot P + \underbrace{S_i \cdot (M \cdot K \oplus K)}_{\text{const}(K)}$$

This is an affine map in $P$ with known linear part $M^i$ and key-dependent translation
$c_K = S_i \cdot (M+I) \cdot K$. Given one known-plaintext pair $(P_1, E_1)$:

$$c_K = E_1 \oplus M^i \cdot P_1$$

From $c_K = \Phi \cdot K$ where $\Phi = S_i \cdot (M+I)$, recovering $K$ requires
solving a $\mathbb{GF}(2)$ linear system. Note that:

$$M + I = L + L^{-1} = x^{-1}(x+1)^2 \in R_n$$

Since $(x+1)^n = 0$ in $R_n$, the factor $(x+1)^2$ is a zero-divisor, so $\Phi$ is not
invertible. The rank $\rho = \text{rank}(\Phi)$ determines how many key bits are
recoverable from a single plaintext pair.

**Quantum advantage.** A quantum adversary with oracle access to the HSKE encryption
function applies BV to recover $c_K$ in 1 query, then solves $\Phi \cdot K = c_K$
classically. The quantum advantage over the classical 1-pair known-plaintext attack is
marginal: both require exactly 1 query (classical) or 1 oracle call (quantum) to extract
$c_K$. BV adds no asymptotic benefit because the classical known-plaintext attack is
already optimal at 1 pair.

**Structural observation.** The linearity of FSCX means HSKE provides **zero security
under known-plaintext** regardless of quantum resources: one $(P, E)$ pair uniquely
determines $c_K$, constraining $\rho$ bits of $K$. The remaining $n - \rho$ bits of $K$
lie in $\ker\Phi$ and produce no observable difference in any ciphertext.

---

### 2.4 Shor's Algorithm

**Shor's algorithm** solves integer factoring and the discrete logarithm problem (DLP)
in $O((\log N)^2 \log\log N)$ quantum time, exploiting the hidden cyclic subgroup
structure of these problems via the Quantum Fourier Transform over $\mathbb{Z}_N$.

**Application to HKEX.** The HKEX construction superficially resembles Diffie-Hellman:
Alice publishes $C = f_B^i(A)$ and Bob publishes $C_2 = f_{B_2}^i(A_2)$. If one frames
this as a discrete logarithm — given $C$, find $i$ — the problem is trivial
**classically**: $M$ has known order $n/2$ (Theorem 3), so $i$ can be recovered by
iterating $M$ at most $n/2$ times. No quantum resources are needed.

More importantly, since $\mathit{sk} = S_{r+1} \cdot (C \oplus C_2)$ is a linear formula,
there is no DLP to solve. Shor's algorithm is inapplicable.

**Formal statement.** For Shor's algorithm to be relevant, the security must reduce to
an instance of DLP or factoring. The HKEX security assumption reduces to solving an
underdetermined linear system over $\mathbb{GF}(2)$, not a DLP instance. Furthermore,
the actual shared secret is not the solution to that system but a linear function of the
public inputs. Shor's algorithm provides **no advantage** over the $O(n^2)$ classical
attack.

---

### 2.5 Quantum Linear Algebra (HHL and Related Algorithms)

**HHL algorithm** (Harrow-Hassidim-Lloyd, 2009) solves $Ax = b$ for $x$ in time
$O(\kappa^2 \log(n) / \epsilon)$ where $\kappa$ is the condition number, vs.
$O(n^{2.37})$ classically. The speedup is exponential in $n$ but requires quantum RAM
and has significant practical caveats.

**Application.** All hardness assumptions in the Herradura suite reduce to problems of
the form: given a $\mathbb{GF}(2)^n$-linear equation $L \cdot x = b$, recover $x$.
These are instances of linear algebra over $\mathbb{GF}(2)$, not over $\mathbb{R}$ or
$\mathbb{C}$, so HHL does not directly apply. Quantum algorithms for linear algebra over
finite fields with similar speedup profiles exist, but the key observation is:

Classical Gaussian elimination over $\mathbb{GF}(2)$ runs in $O(n^{2.37})$ (via fast
matrix multiplication). The linear systems arising in HKEX are $n \times 2n$
(underdetermined), solvable in $O(n^3)$ classically. Since the shared secret is already
obtainable in $O(n^2)$ without solving any linear system at all, quantum linear algebra
speedup is irrelevant to the overall attack cost.

---

## Part III: Protocol-Level Quantum Security Summary

### 3.1 HKEX

**Theorem (Quantum Insecurity of HKEX).** *For any quantum adversary $\mathcal{A}$ with
access to the public transcript $(C, C_2)$ of an HKEX session, $\mathcal{A}$ can compute
the shared secret $\mathit{sk}$ with probability 1 using the classical algorithm
$\mathit{sk} = S_{r+1} \cdot (C \oplus C_2)$ in $O(n^2)$ time. In particular, HKEX is
not computationally secret against any adversary — classical or quantum — of any
polynomial capability.*

**Proof.** The formula was derived and verified in Part I. The computation is $r + 1 =
3n/4 + 1$ applications of $M$ to $C \oplus C_2$, with XOR accumulation; each step costs
$O(n)$ bit operations. Total: $O(n^2)$. $\blacksquare$

**Quantum resistance level:** None. Classical break dominates.

---

### 3.2 HSKE (Standalone)

For HSKE used with a pre-shared key $K$ not derived from HKEX:

**Known-plaintext attack (classical, 1 pair).** One $(P, E)$ pair yields
$c_K = E \oplus M^i \cdot P$. The key satisfies $\Phi \cdot K = c_K$ where
$\Phi = S_i \cdot (M+I)$. If $\text{rank}(\Phi) = \rho < n$, the attack narrows the key
to an affine subspace of dimension $n - \rho$.

**Grover on key space.** Without any known plaintexts, brute-force key search over $2^n$
keys costs $O(2^n)$ classically and $O(2^{n/2})$ with Grover. For $n = 256$, post-quantum
brute-force security is 128 bits — **if and only if** $\rho \approx n$ and no structural
attack is feasible.

**Effective key entropy.** Since $M + I = x^{-1}(x+1)^2$ is a zero-divisor in $R_n$,
the rank $\rho = \text{rank}(S_i \cdot (M+I)) < n$. The effective key entropy is $\rho$
bits, and post-quantum security against key-only attacks is at most $\lfloor \rho/2
\rfloor$ bits (Grover). The exact value of $\rho$ depends on $n$ and $i$ and must be
computed per parameter set.

**Quantum resistance of HSKE:** $\lfloor\rho/2\rfloor$ bits under Grover on the reduced
key space, assuming no faster structural attack. Exact security requires numerical
determination of $\rho$ for each $(n, i)$.

---

### 3.3 HPKS₂

HPKS₂ inherits the HKEX break: since $\mathit{sk}_A = S_{r+1} \cdot (C \oplus C_2)$ is
publicly computable, Eve can:

1. Compute $\mathit{sk}_A$ from the public key.
2. Forge signatures: $S^* = g_{\mathit{sk}_A,\, \mathit{sk}_A}^i(P^*)$ for any $P^*$.
3. Verify any alleged signature trivially.

HPKS₂ achieves neither unforgeability nor authentication. Quantum resources are
superfluous.

---

### 3.4 HPKE

Ciphertext $E = \mathit{sk}_B \oplus A_2 \oplus P$. Since $\mathit{sk}_B = S_{r+1} \cdot
(C \oplus C_2)$ is computable and $A_2$ is part of the public key, Eve recovers:

$$P = E \oplus \mathit{sk}_B \oplus A_2$$

in $O(n^2)$ bit operations. Quantum resources are superfluous.

---

## Part IV: Summary Table

| Protocol | Classical hardness basis | Classical attack | Best quantum attack | Post-quantum security |
|---|---|---|---|---|
| **HKEX** | Inverting FSCX_REVOLVE | $O(n^2)$: $\mathit{sk} = S_{r+1}(C \oplus C_2)$ | Same $O(n^2)$ (classical dominates) | **None** |
| **HSKE** (standalone) | Inverting FSCX_REVOLVE_N | Known-PT: $O(n^3)$ GE, 1 pair | Grover on $\rho$-bit key: $O(2^{\rho/2})$ | $\lfloor\rho/2\rfloor$ bits |
| **HPKS₂** | HKEX + HSKE | Inherits HKEX break | Inherits HKEX break | **None** |
| **HPKE** | HKEX + perfect OTP | Inherits HKEX break | Inherits HKEX break | **None** |

---

## Part V: Root Cause — Linearity over GF(2)

All of the above flows from one structural fact:

$$\text{FSCX}(A, B) = M \cdot (A \oplus B), \qquad M \in \text{End}_{\mathbb{GF}(2)}(\mathbb{GF}(2)^n)$$

$M$ is a $\mathbb{GF}(2)$-linear map. Every iterate of FSCX_REVOLVE is an **affine map**
in its arguments. The entire Herradura suite is a composition of affine maps over
$\mathbb{GF}(2)$, and any such composition is itself affine.

In a Diffie-Hellman-style exchange the analogous "iteration" is $g \mapsto g^a$ in a
group where the DLP is hard. For DLP to be hard, the exponentiation map must be a
**one-way function**, which requires it to be **non-linear** in the exponent (over
whatever field the adversary works in). In HKEX, the map $A \mapsto M^i \cdot A +
\text{const}(B)$ is linear in $A$. Linearity means the "exponent" (iteration count $i$)
is visible in the output structure, and the resulting key identity $S_n = 0$ causes the
private parameters to cancel out of the shared key expression entirely.

**Quantum algorithms most threatening to classical cryptography** (Shor's DLP attack) are
dangerous precisely because they exploit hidden **cyclic** structure in groups where DLP
is classically hard. In HKEX there is no classical hardness to exploit — the structure is
already fully transparent to classical Gaussian elimination in $O(n^2)$. Quantum
algorithms offer no amplification of an attack that already runs in polynomial classical
time.

The construction where quantum attacks would first become the limiting factor is
**HSKE in the standalone symmetric-key setting** with no available plaintexts. There,
Grover reduces key search from $2^n$ to $2^{\rho/2}$. For $n = 256$, selecting $i = 64$
yields $\rho/2 \approx 128$ bits of post-quantum security — provided $\rho \approx n$,
which requires separate numerical verification for each $(n, i)$ parameter pair.

---

*Analysis by Claude Sonnet 4.6 — 2026-04-02*
