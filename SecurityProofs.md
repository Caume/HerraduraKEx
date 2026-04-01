# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

---

## 1. Algebraic Foundations

### 1.1 The Working Domain

Let $n = 2^k$ ($n = 64, 128,$ or $256$ in the implementation). All operations are over the vector space $\mathbb{GF}(2)^n$ — $n$-bit strings under bitwise XOR ($\oplus$). The ring of $n$-bit operators is

$$R_n = \mathbb{GF}(2)[x] \,/\, (x^n + 1)$$

where $x$ corresponds to the 1-bit cyclic left rotation operator $L$. Since $x^n \equiv 1 \pmod{x^n + 1}$, and in $\mathbb{GF}(2)$ we have $x^n - 1 = x^n + 1$, the ring is not a field — it is the local ring $\mathbb{GF}(2)[x]/(x+1)^n$.

---

### 1.2 FSCX — The Core Primitive

**Definition:**

$$\text{FSCX}(A,\, B) \;=\; A \oplus B \oplus \text{ROL}(A) \oplus \text{ROL}(B) \oplus \text{ROR}(A) \oplus \text{ROR}(B)$$

In operator notation, let $L$ be the 1-bit cyclic left rotation and $L^{-1} = L^{n-1}$ be the right rotation. Define the linear map:

$$M \;=\; I + L + L^{-1}$$

Then:

$$\text{FSCX}(A,\, B) \;=\; M \cdot A \oplus M \cdot B \;=\; M \cdot (A \oplus B)$$

**Theorem 1 — Symmetry:** $\text{FSCX}(A, B) = \text{FSCX}(B, A)$.

*Proof:* $M \cdot (A \oplus B) = M \cdot (B \oplus A)$. $\blacksquare$

---

**Theorem 2 — $M$ is invertible for $n = 2^k$:**

In $R_n = \mathbb{GF}(2)[x]/(x^n+1)$, $M$ corresponds to the element $m = 1 + x + x^{-1} = x^{-1}(x^2 + x + 1)$. Since $x$ is a unit (the ring is local), $m$ is invertible iff $x^2 + x + 1$ is. The polynomial $x^2 + x + 1$ is irreducible over $\mathbb{GF}(2)$; it divides $x^t - 1$ only for $3 \mid t$. For $n = 2^k$, $\gcd(3,\, 2^k) = 1$, so $x^2 + x + 1$ has no root that is also an $n$-th root of unity in $R_n$. Therefore $m$ is a unit in $R_n$. $\blacksquare$

---

**Theorem 3 — Order of $M$:** $M^{n/2} = I$.

*Proof:* We compute using the Frobenius endomorphism in characteristic 2. For any $t = 2^j$:

$$(x^2 + x + 1)^t \;=\; x^{2t} + x^t + 1 \quad (\text{in char } 2)$$

Setting $t = n/2 = 2^{k-1}$:

$$m^{n/2} \;=\; x^{-n/2} \cdot (x^2 + x + 1)^{n/2}
           \;=\; x^{-n/2} \cdot (x^n + x^{n/2} + 1)$$

In $R_n$, $x^n \equiv 1$, so $x^n + x^{n/2} + 1 = 1 + x^{n/2} + 1 = x^{n/2}$. Therefore:

$$m^{n/2} \;=\; x^{-n/2} \cdot x^{n/2} \;=\; 1 \;=\; I \quad \checkmark$$

$\blacksquare$

---

**Corollary 1 — Orbit sum vanishes:**

$$S_n \;=\; I + M + M^2 + \cdots + M^{n-1} \;=\; 0$$

*Proof:* Since $M^{n/2} = I$, the sum splits into two equal halves:

$$S_n \;=\; S_{n/2} + M^{n/2} \cdot S_{n/2} \;=\; S_{n/2} + I \cdot S_{n/2} \;=\; 2 \cdot S_{n/2} \;=\; 0 \pmod{2}$$

$\blacksquare$

**Single-step diffusion:** Since $M \cdot e_k = e_k \oplus e_{k+1} \oplus e_{k-1}$ (cyclically), each bit of the input affects exactly 3 output bits. This is confirmed experimentally with mean $= 3.00/n$ and min $=$ max $= 3$ across all tested bit sizes.

---

### 1.3 FSCX\_REVOLVE — Iterated Application

**Definition:**

$$\text{FSCX}\textunderscore\text{REVOLVE}(A,\, B,\, k) \;=\; f_B^k(A)$$

where $f_B(X) = \text{FSCX}(X, B) = M \cdot X \oplus M \cdot B$ is an affine map over $\mathbb{GF}(2)^n$.

**Standard affine iteration formula:** For $f(X) = T \cdot X + c$ with $T = M$, $c = M \cdot B$:

$$f_B^k(A) \;=\; M^k \cdot A \;+\; S_k \cdot (M \cdot B) \;=\; M^k \cdot A \;+\; M \cdot S_k \cdot B$$

where $S_k = I + M + M^2 + \cdots + M^{k-1}$.

**Theorem 4 — Period divides $n$:**

$$f_B^n(A) \;=\; M^n \cdot A \;+\; M \cdot S_n \cdot B \;=\; I \cdot A \;+\; M \cdot 0 \cdot B \;=\; A$$

*Proof:* $M^n = (M^{n/2})^2 = I^2 = I$, and $S_n = 0$ by Corollary 1. $\blacksquare$

Empirically, the actual orbit period is always $n$ or $n/2$ (from test [3]). The parameter choice $i + r = n$ (with $i = n/4$, $r = 3n/4$) is therefore valid regardless of which case holds.

---

### 1.4 FSCX\_REVOLVE\_N — Nonce-Augmented Variant

**Definition (v1.1):**

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(A,\, B,\, N,\, k) \;:\;
\begin{cases}
X_0 = A \\
X_{j+1} = \text{FSCX}(X_j,\, B) \oplus N \;=\; M \cdot X_j \oplus M \cdot B \oplus N
\end{cases}$$

This is the affine map $g_{B,N}(X) = M \cdot X + (M \cdot B \oplus N)$ with translation $c = M \cdot B \oplus N$.

**Theorem 5 — Period still divides $n$:**

$$g^n_{B,N}(A) \;=\; M^n \cdot A \;+\; S_n \cdot (M \cdot B \oplus N) \;=\; A \;+\; 0 \;=\; A$$

The nonce $N$ does not affect the period, and decryption is still the complementary revolve.

**Nonce propagation linearity:** If $N$ changes by $\delta N$, the change in $\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(\cdot, B, N, k)$ at step $k$ is:

$$\delta\text{Output} \;=\; S_k \cdot \delta N \;=\; (I + M + M^2 + \cdots + M^{k-1}) \cdot \delta N$$

In particular, for $k = n$ this is $S_n \cdot \delta N = 0$, so nonce changes are fully absorbed over a full cycle. For $k = r = 3n/4$, the diffusion of a 1-bit nonce flip gives Hamming distance $r/n \times n = r$ bits (confirmed: test [6] gives $\text{HD} = n/4$ for $k = i = n/4$).

---

## 2. Protocol Analysis

### 2.1 HKEX — Key Exchange

**Protocol:**

$$\begin{aligned}
&\textbf{Alice:}\quad A,\, B \leftarrow \text{random};\quad C = \text{FSCX}\textunderscore\text{REVOLVE}(A,\, B,\, i) \\
&\textbf{Bob:}\quad A_2,\, B_2 \leftarrow \text{random};\quad C_2 = \text{FSCX}\textunderscore\text{REVOLVE}(A_2,\, B_2,\, i)
\end{aligned}$$

$$\text{Alice} \xrightarrow{C} \text{Bob} \qquad \text{Bob} \xrightarrow{C_2} \text{Alice}$$

$$\begin{aligned}
&\textbf{Alice:}\quad sk_A = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2,\, B,\, N,\, r) \oplus A \\
&\textbf{Bob:}\quad sk_B = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C,\, B_2,\, N,\, r) \oplus A_2 \\
&\text{where}\quad N = C \oplus C_2
\end{aligned}$$

**Theorem 6 — Correctness:** $sk_A = sk_B$.

*Proof:* Expand both sides using the affine iteration formula. The condition $sk_A = sk_B$ reduces to:

$$(M^{r+1} \cdot S_i \;+\; M \cdot S_r) \cdot B_2 \;=\; (M^{r+1} \cdot S_i \;+\; M \cdot S_r) \cdot B$$

Computing the coefficient matrix:

$$\begin{aligned}
M \cdot S_r \;+\; M^{r+1} \cdot S_i
&= (M + M^2 + \cdots + M^r) + (M^{r+1} + M^{r+2} + \cdots + M^{r+i}) \\
&= M + M^2 + \cdots + M^{r+i} \quad [M^{r+i} = M^n = I] \\
&= I + M + \cdots + M^{n-1} \;=\; S_n \;=\; 0
\end{aligned}$$

Therefore the condition holds for all $B, B_2$, completing the proof. The nonce $N = C \oplus C_2$ contributes equally to both sides and cancels identically. $\blacksquare$

> **Hardness assumption (unproven):** Security requires that given $C = \text{FSCX}\textunderscore\text{REVOLVE}(A, B, i) = M^i \cdot A + M \cdot S_i \cdot B$, recovering $(A, B)$ is computationally hard. This is a system of $n$ linear equations in $2n$ unknowns over $\mathbb{GF}(2)$. The system is underdetermined (underconstrained by a factor of 2), and no formal reduction to a standard hard problem (DLP, RSA, LWE) has been established.

---

### 2.2 HSKE — Symmetric Key Encryption

**Protocol:**

$$\text{Encrypt:}\quad E = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(P,\, K,\, K,\, i)$$
$$\text{Decrypt:}\quad D = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(E,\, K,\, K,\, r)$$

**Correctness:** From Theorem 5 with $B = K$, $N = K$:

$$g^{i+r}_{K,K}(P) \;=\; g^n_{K,K}(P) \;=\; P$$

So decrypting is applying the same map for the complementary $r$ steps: $g^r(g^i(P)) = g^{r+i}(P) = g^n(P) = P$. $\checkmark$

> **Key and nonce are the same value:** This means the nonce $K$ is the same secret as the revolve parameter $B = K$. The nonce is not independently chosen, which limits the confusion contribution of $N$.

---

### 2.3 HPKS — Public Key Signature

**Protocol** (Alice signs plaintext $P$):

$$\begin{aligned}
&\text{Public key:}\quad (C,\, B_2,\, A_2,\, r) \\
&\text{Private key:}\quad (C_2,\, B,\, A)
\end{aligned}$$

$$\begin{aligned}
&\textbf{Alice:}\quad S = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2,\, B,\, N,\, r) \oplus A \oplus P \quad [= sk_A \oplus P] \\
&\textbf{Bob:}\quad V = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C,\, B_2,\, N,\, r) \oplus A_2 \oplus S \quad [= sk_B \oplus S]
\end{aligned}$$

**Correctness:** $V = sk_B \oplus sk_A \oplus P = P$ (since $sk_A = sk_B$). $\checkmark$

> **Critical property — Signature reveals session key:**
>
> $$S = sk_A \oplus P$$
>
> Given $P$ and $S$, an attacker trivially recovers $sk_A = S \oplus P$. Once $sk_A$ is known, any subsequent message signed with the same key pair is immediately decryptable. This is a one-time signature at best; reusing the same public key for multiple signatures leaks the session key.

---

### 2.4 HPKE — Public Key Encryption

**Protocol:**

$$\begin{aligned}
&\text{Alice publishes:}\quad (C,\, B_2,\, A_2) \text{ as public key} \\
&\text{Alice keeps:}\quad (C_2,\, B,\, A) \text{ as private key} \\
&N = C \oplus C_2 \quad \text{(derivable from public key;}\; C_2 = \text{FSCX}\textunderscore\text{REVOLVE}(A_2,\, B_2,\, i)\text{)}
\end{aligned}$$

$$\begin{aligned}
&\textbf{Bob:}\quad E = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C,\, B_2,\, N,\, r) \oplus A_2 \oplus P \\
&\textbf{Alice:}\quad D = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2,\, B,\, N,\, r) \oplus A \oplus E
\end{aligned}$$

**Correctness:**

$$\begin{aligned}
D &= \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2,\, B,\, N,\, r) \oplus A \oplus E \\
  &= sk_A \oplus \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C,\, B_2,\, N,\, r) \oplus A_2 \oplus P \\
  &= sk_A \oplus sk_B \oplus P \\
  &= P \quad (\text{since } sk_A = sk_B) \quad \checkmark
\end{aligned}$$

**Ciphertext structure:**

$$E = sk_B \oplus A_2 \oplus P$$

This is a one-time pad with pad $= sk_B \oplus A_2$. If $sk_B \oplus A_2$ is uniformly distributed and never reused, HPKE achieves perfect secrecy for the encryption step.

---

## 3. Security Properties Summary

### 3.1 Strengths

| Property | Status |
|---|---|
| Correctness (all protocols) | ✓ Proven: follows from $S_n = 0$ and $M^n = I$ |
| Constant-time implementation | ✓ All operations are bitwise; no data-dependent branches |
| Simplicity and auditability | ✓ The entire primitive is 6 terms |
| Bit-frequency uniformity | ✓ Output bits are balanced to <0.5% deviation |
| $M$ invertible for $n = 2^k$ | ✓ Proven algebraically; no information loss per step |
| Nonce-augmentation preserves orbit period | ✓ Proven; $S_n = 0$ absorbs nonce completely |

---

### 3.2 Weaknesses and Vulnerabilities

**W1 — FSCX is a linear map over $\mathbb{GF}(2)$.**

$$\text{FSCX}(A \oplus X,\, B \oplus X) \;=\; M \cdot (A \oplus B) \;=\; \text{FSCX}(A,\, B) \quad \forall X$$

FSCX is not a nonlinear function. All security comes from iteration count and parameter choices, not from the mixing function itself. A single application of FSCX is trivially invertible given $A$ or $B$.

---

**W2 — HPKE/HPKS are bit-malleable (no IND-CCA2).**

Let $E = sk_B \oplus A_2 \oplus P$. Then:

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2,\, B,\, N,\, r) \oplus A \oplus (E \oplus \delta) \;=\; P \oplus \delta$$

Flipping bit $k$ of $E$ flips bit $k$ of the decrypted plaintext. There is a bijective XOR relationship between ciphertext bits and plaintext bits, which means HPKE has no ciphertext integrity. An active attacker who can submit modified ciphertexts to a decryption oracle can target specific plaintext bits.

> **Formal implication:** HPKE is not IND-CCA2 secure. It may achieve IND-CPA under the hardness assumption, but this is unproven.

---

**W3 — HPKS is not existentially unforgeable under chosen-message attack.**

The signature satisfies:

$$S = sk_A \oplus P \qquad V = sk_B \oplus S = P \quad \text{(verification passes)}$$

Given any two valid signed messages $(P_1, S_1)$ and $(P_2, S_2)$ under the same key:

$$S_1 \oplus S_2 \;=\; P_1 \oplus P_2 \;\implies\; sk_A \;=\; S_1 \oplus P_1 \quad \text{(one message suffices)}$$

One signed message fully reveals $sk_A$. A forger knowing $sk_A$ can sign any message $P'$ as $S' = sk_A \oplus P'$. This breaks one-time security after a single signing query.

> **Implication:** HPKS is not EUF-CMA. It is valid as a one-time signature (sign once, never reuse) only if $sk_A$ is derived freshly per message (new $A$, $B$ each time).

---

**W4 — Hardness assumption is unverified.**

The security of all protocols reduces to: given

$$C \;=\; M^i \cdot A \;+\; M \cdot S_i \cdot B, \quad i = n/4$$

recovering $(A, B) \in \mathbb{GF}(2)^n \times \mathbb{GF}(2)^n$ is hard. This is a single linear equation in $2n$ unknowns over $\mathbb{GF}(2)^n$ — the system is underdetermined with $n^n$ solutions. Security relies on the attacker being unable to exploit the specific structure of $M^i$ and $S_i$. No reduction to DLP, CDH, lattice problems, or any other NIST-standardized hardness assumption exists.

---

**W5 — The nonce $N = C \oplus C_2$ is publicly derivable.**

$$N \;=\; C \oplus C_2 \;=\; \text{FSCX}\textunderscore\text{REVOLVE}(A,\, B,\, i) \oplus \text{FSCX}\textunderscore\text{REVOLVE}(A_2,\, B_2,\, i)$$

Both $C$ and $C_2$ are transmitted as public values. $N$ is not secret, and contributes zero entropy beyond the public key material. The nonce's role is purely structural (enabling the HKEX equality proof), not to introduce unpredictability.

---

**W6 — Short effective key space for meet-in-the-middle.**

$C = \text{FSCX}\textunderscore\text{REVOLVE}(A, B, i)$ with $i = n/4 = 64$ steps. An attacker might attack this by splitting:

$$\text{FSCX}\textunderscore\text{REVOLVE}(A,\, B,\, i) \;=\; f_B^i(A)$$

and searching over $(A, B)$ pairs. Since $M^{n/2} = I$, the orbit has period at most $n/2$, meaning at most $n/2$ distinct values of $C$ can arise from any fixed $B$. This reduces the effective pre-image space compared to a random function over $\mathbb{GF}(2)^n$.

---

**W7 — No authenticated encryption.**

None of HSKE, HPKE, or HPKS provides joint confidentiality + integrity + authentication in a single construction. These properties must be composed externally (e.g., encrypt-then-MAC), and incorrect composition can reintroduce W2-type vulnerabilities.

---

## 4. Summary Table

| Protocol | Correctness | Hardness Basis | IND-CPA | IND-CCA2 | EUF-CMA |
|---|---|---|---|---|---|
| HKEX | ✓ Proven | Unformalized | — | — | — |
| HSKE | ✓ Proven | Unformalized | Unproven | ✗ (malleable) | — |
| HPKS | ✓ Proven | Unformalized | — | — | ✗ (one-time) |
| HPKE | ✓ Proven | Unformalized | Unproven | ✗ (malleable) | — |

---

## 5. Core Identity (the Fundamental Equation)

Everything in the suite ultimately rests on two chained facts:

**Fact A:** In $\mathbb{GF}(2)[x]/(x^n + 1)$ with $n = 2^k$:

$$m^{n/2} = 1 \;\implies\; S_n = 0$$

**Fact B:** For $i + r = n$:

$$M \cdot S_r \;+\; M^{r+1} \cdot S_i \;=\; S_n \;=\; 0$$

Together, these imply that for any $A, B, A_2, B_2 \in \mathbb{GF}(2)^n$ and any nonce $N$:

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}\!\left(\text{FSCX}\textunderscore\text{REVOLVE}(A_2,\, B_2,\, i),\; B,\; N,\; r\right) \oplus A$$
$$=$$
$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}\!\left(\text{FSCX}\textunderscore\text{REVOLVE}(A,\, B,\, i),\; B_2,\; N,\; r\right) \oplus A_2$$

This identity is the mathematical core from which all four protocols derive their correctness. All protocols are **correct**. Whether they are **secure** against computationally bounded adversaries depends on the unformalized hardness of inverting FSCX\_REVOLVE — which currently lacks a proof under any standard cryptographic assumption.
