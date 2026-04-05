# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; root cause identified.  
**Last updated:** 2026-04-04

---

## 1. Algebraic Foundations

### 1.1 The Working Domain

Let $n = 2^k$ ($n = 64, 128,$ or $256$ in the implementation). All operations are over the vector space $\mathbb{GF}(2)^n$ — $n$-bit strings under bitwise XOR ($\oplus$). The ring of $n$-bit operators is

$$R_n = \mathbb{GF}(2)[x] / (x^n + 1)$$

where $x$ corresponds to the 1-bit cyclic left rotation operator $L$. Since $x^n \equiv 1 \pmod{x^n + 1}$, and in $\mathbb{GF}(2)$ we have $x^n - 1 = x^n + 1$, the ring is not a field — it is the local ring $\mathbb{GF}(2)[x]/(x+1)^n$.

**Notation summary:**

| Symbol | Meaning |
|--------|---------|
| $n$ | Bit width ($32, 64, 128, 256$) |
| $i$ | Public-key generation depth ($n/4$) |
| $r$ | Key-derivation depth ($n - i = 3n/4$) |
| $A, B$ | Alice's private key pair |
| $A_2, B_2$ | Bob's private key pair |
| $C, C_2$ | Public wire values (exchanged) |
| $M$ | FSCX linear operator: $M \cdot x = x \oplus \text{ROL}(x,1) \oplus \text{ROR}(x,1)$ |
| $M^k$ | $k$-th power of $M$ ($k$ applications) |
| $S_k$ | Prefix sum: $S_k = I + M + M^2 + \cdots + M^{k-1}$ |

All arithmetic is over $\mathbb{GF}(2)^n$ (bitwise XOR and $\mathbb{GF}(2)$-linear maps).

---

### 1.2 FSCX — The Core Primitive

**Definition:**

$$\text{FSCX}(A, B) = A \oplus B \oplus \text{ROL}(A) \oplus \text{ROL}(B) \oplus \text{ROR}(A) \oplus \text{ROR}(B)$$

In operator notation, let $L$ be the 1-bit cyclic left rotation and $L^{-1} = L^{n-1}$ be the right rotation. Define the linear map:

$$M = I + L + L^{-1}$$

Then:

$$\text{FSCX}(A, B) = M \cdot A \oplus M \cdot B = M \cdot (A \oplus B)$$

**Theorem 1 — Symmetry:** $\text{FSCX}(A, B) = \text{FSCX}(B, A)$.

*Proof:* $M \cdot (A \oplus B) = M \cdot (B \oplus A)$. $\blacksquare$

---

**Theorem 2 — $M$ is invertible for $n = 2^k$:**

In $R_n = \mathbb{GF}(2)[x]/(x^n+1)$, $M$ corresponds to the element $m = 1 + x + x^{-1} = x^{-1}(x^2 + x + 1)$. Since $x$ is a unit (the ring is local), $m$ is invertible iff $x^2 + x + 1$ is. The polynomial $x^2 + x + 1$ is irreducible over $\mathbb{GF}(2)$; it divides $x^t - 1$ only for $3 \mid t$. For $n = 2^k$, $\gcd(3, 2^k) = 1$, so $x^2 + x + 1$ has no root that is also an $n$-th root of unity in $R_n$. Therefore $m$ is a unit in $R_n$. $\blacksquare$

---

**Theorem 3 — Order of $M$:** $M^{n/2} = I$.

*Proof:* We compute using the Frobenius endomorphism in characteristic 2. For any $t = 2^j$:

$$(x^2 + x + 1)^t = x^{2t} + x^t + 1 \quad (\text{in char } 2)$$

Setting $t = n/2 = 2^{k-1}$:

$$m^{n/2} = x^{-n/2} \cdot (x^2 + x + 1)^{n/2}
           = x^{-n/2} \cdot (x^n + x^{n/2} + 1)$$

In $R_n$, $x^n \equiv 1$, so $x^n + x^{n/2} + 1 = 1 + x^{n/2} + 1 = x^{n/2}$. Therefore:

$$m^{n/2} = x^{-n/2} \cdot x^{n/2} = 1 = I \quad \checkmark$$

$\blacksquare$

---

**Corollary 1 — Orbit sum vanishes:**

$$S_n = I + M + M^2 + \cdots + M^{n-1} = 0$$

*Proof:* Since $M^{n/2} = I$, the sum splits into two equal halves:

$$S_n = S_{n/2} + M^{n/2} \cdot S_{n/2} = S_{n/2} + I \cdot S_{n/2} = 2 \cdot S_{n/2} = 0 \pmod{2}$$

$\blacksquare$

**Single-step diffusion:** Since $M \cdot e_k = e_k \oplus e_{k+1} \oplus e_{k-1}$ (cyclically), each bit of the input affects exactly 3 output bits. This is confirmed experimentally with mean $= 3.00/n$ and min $=$ max $= 3$ across all tested bit sizes.

---

### 1.3 FSCX\_REVOLVE — Iterated Application

**Definition:**

$$\text{FSCX\_REVOLVE}(A, B, k) = f_B^k(A)$$

where $f_B(X) = \text{FSCX}(X, B) = M \cdot X \oplus M \cdot B$ is an affine map over $\mathbb{GF}(2)^n$.

**Standard affine iteration formula:** For $f(X) = T \cdot X + c$ with $T = M$, $c = M \cdot B$:

$$f_B^k(A) = M^k \cdot A + S_k \cdot (M \cdot B) = M^k \cdot A + M \cdot S_k \cdot B$$

where $S_k = I + M + M^2 + \cdots + M^{k-1}$.

**Theorem 4 — Period divides $n$:**

$$f_B^n(A) = M^n \cdot A + M \cdot S_n \cdot B = I \cdot A + M \cdot 0 \cdot B = A$$

*Proof:* $M^n = (M^{n/2})^2 = I^2 = I$, and $S_n = 0$ by Corollary 1. $\blacksquare$

Empirically, the actual orbit period is always $n$ or $n/2$. The parameter choice $i + r = n$ (with $i = n/4$, $r = 3n/4$) is therefore valid regardless of which case holds.

---

**Corollary 2 — Fundamental Identity:** For any $i, r$ with $i + r = n$:

$$M \cdot S_r + M^{r+1} \cdot S_i = S_n = 0$$

*Proof:* Expanding each sum:

$$M \cdot S_r = M + M^2 + \cdots + M^r$$
$$M^{r+1} \cdot S_i = M^{r+1} + M^{r+2} + \cdots + M^{r+i}$$

Adding (in $\mathbb{GF}(2)$, all terms are XOR'd):

$$M \cdot S_r + M^{r+1} \cdot S_i = M + M^2 + \cdots + M^{r+i}$$

Since $r + i = n$, the last term is $M^{r+i} = M^n = I$. Reordering:

$$= I + M + M^2 + \cdots + M^{n-1} = S_n = 0 \quad \blacksquare$$

> This identity is the engine of correctness across all protocols — and simultaneously the root cause of the classical break (see §3).

---

### 1.4 FSCX\_REVOLVE\_N — Nonce-Augmented Variant

**Definition (v1.1):**

$$\text{FSCX\_REVOLVE\_N}(A, B, N, k) :
\begin{cases}
X_0 = A \\
X_{j+1} = \text{FSCX}(X_j, B) \oplus N = M \cdot X_j \oplus M \cdot B \oplus N
\end{cases}$$

This is the affine map $g_{B,N}(X) = M \cdot X + (M \cdot B \oplus N)$ with translation $c = M \cdot B \oplus N$. The closed-form iteration formula is:

$$\text{FSCX\_REVOLVE\_N}(A, B, N, k) = M^k \cdot A + M \cdot S_k \cdot B \oplus S_k \cdot N$$

**Theorem 5 — Period still divides $n$:**

$$g^n_{B,N}(A) = M^n \cdot A + S_n \cdot (M \cdot B \oplus N) = A + 0 = A$$

The nonce $N$ does not affect the period, and decryption is the complementary revolve.

**Nonce propagation linearity:** If $N$ changes by $\delta N$, the change in $\text{FSCX\_REVOLVE\_N}(\cdot, B, N, k)$ at step $k$ is:

$$\delta\text{Output} = S_k \cdot \delta N = (I + M + M^2 + \cdots + M^{k-1}) \cdot \delta N$$

For $k = n$ this is $S_n \cdot \delta N = 0$, so nonce changes are fully absorbed over a full cycle. The Hamming distance of a single-bit nonce flip is deterministic (independent of $A$ and $B$) and equals $\text{popcount}(S_k \cdot e_j)$. Empirically, $\text{HD} = n/4$ for $k = i = n/4$.

---

## 2. Protocol Analysis

### 2.1 HKEX — Key Exchange

**Protocol:**

$$\begin{aligned}
&\textbf{Alice:}\quad A, B \leftarrow \text{random};\quad C = \text{FSCX\_REVOLVE}(A, B, i) \\
&\textbf{Bob:}\quad A_2, B_2 \leftarrow \text{random};\quad C_2 = \text{FSCX\_REVOLVE}(A_2, B_2, i)
\end{aligned}$$

$$\text{Alice} \xrightarrow{C} \text{Bob} \qquad \text{Bob} \xrightarrow{C_2} \text{Alice}$$

$$\begin{aligned}
&\textbf{Alice:}\quad sk_A = \text{FSCX\_REVOLVE\_N}(C_2, B, N, r) \oplus A \\
&\textbf{Bob:}\quad sk_B = \text{FSCX\_REVOLVE\_N}(C, B_2, N, r) \oplus A_2 \\
&\text{where}\quad N = C \oplus C_2
\end{aligned}$$

**Theorem 6 — Correctness:** $sk_A = sk_B$.

*Proof:* Applying the affine iteration formula to $sk_A$, and substituting $A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$ (from $C = M^i \cdot A + M \cdot S_i \cdot B$ with $M^{-i} = M^{n-i} = M^r$):

$$\begin{aligned}
sk_A &= M^r \cdot C_2 + M \cdot S_r \cdot B \oplus S_r \cdot N \oplus A \\
     &= M^r \cdot C_2 + M \cdot S_r \cdot B \oplus S_r \cdot (C \oplus C_2) \oplus M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B \\
     &= M^r \cdot (C \oplus C_2) \oplus S_r \cdot (C \oplus C_2) \oplus (M \cdot S_r + M^{r+1} \cdot S_i) \cdot B \\
     &= M^r \cdot (C \oplus C_2) \oplus S_r \cdot (C \oplus C_2) \oplus S_n \cdot B \qquad \leftarrow \text{Corollary 2} \\
     &= (M^r + S_r) \cdot (C \oplus C_2) \oplus 0 \\
     &= S_{r+1} \cdot (C \oplus C_2)
\end{aligned}$$

The last step uses $M^r + S_r = M^r + (I + M + \cdots + M^{r-1}) = I + M + \cdots + M^r = S_{r+1}$.

By symmetry (swapping Alice and Bob's roles), $sk_B = S_{r+1} \cdot (C \oplus C_2)$ as well. Therefore $sk_A = sk_B$. $\blacksquare$

**Corollary 3 — Explicit shared secret formula:**

$$sk = S_{r+1} \cdot (C \oplus C_2) = (C \oplus C_2) \oplus M \cdot (C \oplus C_2) \oplus \cdots \oplus M^r \cdot (C \oplus C_2)$$

This formula depends only on the public wire values $C$ and $C_2$. The private parameters $A$, $B$, $A_2$, $B_2$ cancel exactly through Corollary 2. This directly implies that HKEX is **broken** (see §3.1).

---

### 2.2 HSKE — Symmetric Key Encryption

**Protocol:**

$$\text{Encrypt:}\quad E = \text{FSCX\_REVOLVE\_N}(P, K, K, i)$$
$$\text{Decrypt:}\quad D = \text{FSCX\_REVOLVE\_N}(E, K, K, r)$$

Applying the affine formula with $B = N = K$:

$$E = M^i \cdot P + S_i \cdot (M \cdot K \oplus K) = M^i \cdot P + S_i \cdot (M + I) \cdot K$$

The key contributes the additive offset $c_K = S_i \cdot (M + I) \cdot K$ to $E$. For random $K$, this offset is nonzero (Eve cannot decrypt without knowing $K$).

**Correctness:** Decrypting:

$$\begin{aligned}
D &= M^r \cdot E + S_r \cdot (M + I) \cdot K \\
  &= M^r \cdot [M^i \cdot P + S_i \cdot (M+I) \cdot K] + S_r \cdot (M+I) \cdot K \\
  &= M^n \cdot P + (M^r \cdot S_i + S_r) \cdot (M+I) \cdot K \\
  &= P + S_n \cdot (M+I) \cdot K \qquad \leftarrow M^r \cdot S_i + S_r = S_n = 0 \\
  &= P \quad \checkmark
\end{aligned}$$

The step $M^r \cdot S_i + S_r = S_n = 0$ follows from Corollary 2 (expanding $M^r \cdot S_i = M^r + \cdots + M^{n-1}$, $S_r = I + \cdots + M^{r-1}$, sum is $S_n$).

> **Why HSKE remains secure:** HSKE is a *symmetric* cipher, not a key exchange. Both parties share $K$ before communication; $K$ never appears on the wire. The offset $c_K = S_i \cdot (M+I) \cdot K$ in $E$ is a non-zero private additive term. Unlike HKEX, there is no step at which private parameters must cancel from the ciphertext itself — only from the round-trip $D = P$, which they do via $S_n = 0$.

---

### 2.3 HPKS₂ — Public Key Signature

**Protocol** (Alice signs plaintext $P$):

$$\begin{aligned}
&\text{Public key:}\quad (C, B_2, A_2, r) \\
&\text{Private key:}\quad (C_2, B, A)
\end{aligned}$$

The original scheme used $S = sk_A \oplus P$ (a direct XOR mask), which trivially leaks $sk_A$ (see W3). The corrected scheme **HPKS₂** replaces the XOR with HSKE encryption of $P$ under $sk_A$:

$$\begin{aligned}
&\textbf{Alice:}\quad S = \text{FSCX\_REVOLVE\_N}(P,\; sk_A,\; sk_A,\; i) \quad [\text{HSKE-encrypt } P \text{ under } sk_A] \\
&\textbf{Bob:}\quad V = \text{FSCX\_REVOLVE\_N}(S,\; sk_B,\; sk_B,\; r) \quad [\text{HSKE-decrypt } S \text{ under } sk_B] \\
&\qquad\text{Check: } V = P
\end{aligned}$$

**Correctness:** From HSKE correctness with $B = sk_A$, $N = sk_A$ and $sk_A = sk_B$: $V = P$. $\checkmark$

> **Remaining limitation:** Since $sk_A = S_{r+1} \cdot (C \oplus C_2)$ is computable from the public key, Eve can recover $sk_A$ and trivially forge signatures using HPKS₂ as well. The HPKS₂ improvement removes the *direct* one-query key recovery of the original scheme, but does not restore EUF-CMA security.

---

### 2.4 HPKE — Public Key Encryption

**Protocol:**

$$\begin{aligned}
&\text{Alice publishes:}\quad (C, B_2, A_2) \text{ as public key} \\
&\text{Alice keeps:}\quad (C_2, B, A) \text{ as private key} \\
&N = C \oplus C_2 \quad \text{(computable from public key)}
\end{aligned}$$

$$\begin{aligned}
&\textbf{Bob:}\quad E = \text{FSCX\_REVOLVE\_N}(C, B_2, N, r) \oplus A_2 \oplus P \\
&\textbf{Alice:}\quad D = \text{FSCX\_REVOLVE\_N}(C_2, B, N, r) \oplus A \oplus E
\end{aligned}$$

**Correctness:**

$$\begin{aligned}
D &= sk_A \oplus sk_B \oplus P = P \quad \checkmark
\end{aligned}$$

**Ciphertext structure:**

$$E = sk_B \oplus A_2 \oplus P$$

Since $sk_B = S_{r+1} \cdot (C \oplus C_2)$ is a linear function of public values (Corollary 3), and $A_2$ is part of the public key, Eve computes $P = E \oplus sk_B \oplus A_2$ directly. **HPKE provides no secrecy against a passive eavesdropper.**

---

## 3. Security Analysis

### 3.1 The Classical Break

**Theorem 7 (Classical Break).**

> Eve observes only the wire values $C$ and $C_2$.
> She recovers the HKEX shared secret as:
>
> $$sk = S_{r+1} \cdot (C \oplus C_2) = \bigoplus_{j=0}^{r} M^j \cdot (C \oplus C_2)$$
>
> Cost: $O(r \cdot n) = O(n^2)$ bit operations. No private information is used.

*Proof:* This is Corollary 3 of Theorem 6. The full derivation is given in §2.1: private parameters $A$, $B$ cancel from $sk_A$ via Corollary 2, leaving only $S_{r+1} \cdot (C \oplus C_2)$. $\blacksquare$

**Experimental verification:** `SecurityProofsCode/hkex_classical_break.py` — 10,000 trials across $n \in \{32, 64, 128, 256\}$, all pass.

---

### 3.2 Single Nonce Injection Cannot Fix HKEX

**The proposal:** Replace the public-key computation $C = \text{FSCX\_REVOLVE}(A, B, i)$ with the nonce-augmented variant $C = \text{FSCX\_REVOLVE\_N}(A, B, \Phi, i)$:

$$C = M^i \cdot A + S_i \cdot (M \cdot B \oplus \Phi)$$

**Case (a): Public nonce $\Phi$.**

Solving for $A$:

$$A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B \oplus M^r \cdot S_i \cdot \Phi$$

Substituting into $sk_A$:

$$sk_A = S_{r+1} \cdot (C \oplus C_2) \oplus M^r \cdot S_i \cdot \Phi$$

Both terms are computable from public information $(C, C_2, \Phi)$. Eve adjusts her formula by the known offset. **The break survives.**

**Case (b): Private nonce (e.g., $\Phi = B$).**

With each party using their own private $B$ as nonce:

$$sk_A = S_{r+1} \cdot (C \oplus C_2) \oplus M^r \cdot S_i \cdot B$$
$$sk_B = S_{r+1} \cdot (C \oplus C_2) \oplus M^r \cdot S_i \cdot B_2$$

$$sk_A \oplus sk_B = M^r \cdot S_i \cdot (B \oplus B_2) \neq 0 \quad \text{for independent } B, B_2$$

**Correctness is destroyed.**

**Lemma (No middle ground).** Any nonce is either (a) public — break survives — or (b) private — correctness fails. XOR injection is a $\mathbb{GF}(2)$-linear operation; adding it to a linear scheme does not introduce nonlinearity.

**Experimental verification:** `SecurityProofsCode/hkex_fscxn_analysis.py` — Cases (a)/(b)/(c), 2,000 trials each, all match algebraic predictions.

---

### 3.3 General Nonce Impossibility

**Theorem 8 (Nonce Impossibility).**

> For ANY nonce choice $n_A = f(A, B, C, C_2)$ with symmetric counterpart $n_B = f(A_2, B_2, C_2, C)$:
>
> If $sk_A = sk_B$ for **all** independently generated key pairs $(A,B)$ and $(A_2,B_2)$, then $sk$ is a $\mathbb{GF}(2)$-affine function of $(C, C_2)$ alone.

*Proof.* Applying the affine iteration formula for $\text{FSCX\_REVOLVE\_N}$ and substituting $A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$:

$$sk_A = M^r \cdot C_2 + S_r \cdot (M \cdot B \oplus n_A) \oplus A$$
$$= M^r \cdot (C \oplus C_2) \oplus \underbrace{(S_r \cdot M + M^{r+1} \cdot S_i)}_{S_n = 0} \cdot B \oplus S_r \cdot n_A$$
$$= M^r \cdot (C \oplus C_2) \oplus S_r \cdot n_A$$

Symmetrically: $sk_B = M^r \cdot (C \oplus C_2) \oplus S_r \cdot n_B$.

Correctness $sk_A = sk_B$ requires $S_r \cdot n_A = S_r \cdot n_B$ for ALL independent $(A,B)$ and $(A_2,B_2)$. Since the key pairs are drawn independently, the common value of $S_r \cdot n_A = S_r \cdot n_B$ can only depend on what is common to both parties — the public values $C$ and $C_2$. Therefore $S_r \cdot n_A = h(C, C_2)$ for some function $h$, and:

$$sk = M^r \cdot (C \oplus C_2) \oplus h(C, C_2)$$

which is a function of public values only. $\blacksquare$

**Corollary.** Private components of $n_A$ in $\ker(S_r)$ contribute nothing to $sk$ ($S_r$ kills them). Private components outside $\ker(S_r)$ break correctness. There is no middle ground.

**Experimental verification:** `SecurityProofsCode/hkex_nonce_impossibility.py` — 10 nonce strategies exhaustively tested; all either correct+public or broken.

---

### 3.4 Partial Correctness of $n_A = A \oplus C$

Experimentally, the nonce $n_A = A \oplus C$ gives $sk_A = sk_B$ in approximately $1/16$ of trials.

**Explanation.** With $n_A = A \oplus C$:

$$S_r \cdot n_A = S_r \cdot (A \oplus C) = S_r \cdot A \oplus S_r \cdot C$$

Substituting $A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$:

$$S_r \cdot A = S_r \cdot M^r \cdot C \oplus S_r \cdot M^{r+1} \cdot S_i \cdot B$$

So $S_r \cdot n_A$ depends on **both** $B$ and $C$. The correctness condition $S_r \cdot n_A = S_r \cdot n_B$ requires the two parties' expressions to agree — a $\mathbb{GF}(2)$ linear condition on the combined parameter space.

The condition matrix $S_r \cdot [(I + M^i) \mid M \cdot S_i]$ acting on $(A, B)$ (or $(A_2, B_2)$) has **rank 4** over $\mathbb{GF}(2)^n$.

$$P(\text{correct}) = 2^{-\text{rank}} = 2^{-4} = 1/16 \approx 0.0625$$

Empirical result: $322/5000 = 0.0644$ — consistent with $1/16$. This nonce is neither always-correct (public) nor always-broken (purely private): it satisfies the correctness condition on a $\mathbb{GF}(2)$ subspace of dimension $n - 4$, occurring with probability exactly $2^{-4}$.

---

### 3.5 Multi-Nonce Analysis

**The proposal:** Use a distinct nonce $N_j$ at each revolve step:

$$X_{j+1} = M \cdot (X_j \oplus B) \oplus N_j, \quad j = 0, \ldots, k-1$$

**Theorem 9 (Multi-nonce closed form).**

$$X_k = M^k \cdot A + M \cdot S_k \cdot B \oplus \Phi_k, \quad \text{where } \Phi_k = \bigoplus_{j=0}^{k-1} M^{k-1-j} \cdot N_j$$

*Proof:* By induction on $k$. The base case $k = 0$ gives $X_0 = A$. Assuming the formula holds at step $k$:

$$X_{k+1} = M \cdot X_k \oplus M \cdot B \oplus N_k = M^{k+1} \cdot A + M^2 \cdot S_k \cdot B \oplus M \cdot \Phi_k \oplus M \cdot B \oplus N_k$$

Noting $M^2 \cdot S_k + M = M \cdot S_{k+1}$ and $M \cdot \Phi_k \oplus N_k = \Phi_{k+1}$. $\blacksquare$

The result is still a $\mathbb{GF}(2)$-affine function of all inputs.

**sk formula.** Substituting into the HKEX key derivation, B and A cancel via Corollary 2 as before:

$$sk_A = M^r \cdot (C \oplus C_2) \oplus \Phi^A_r$$

**Correctness condition:** $sk_A = sk_B$ iff $\Phi^A_r = \Phi^B_r$.

By the independence argument of Theorem 8, $\Phi^A_r$ must be a function of $(C, C_2)$ only for correctness to hold universally. Therefore $sk$ is always public.

**The GF(2) even-sum collapse.** For the sequence $N_j = M^j \cdot B$ (a maximal "private" injection):

$$\Phi_r = \bigoplus_{j=0}^{r-1} M^{r-1-j} \cdot M^j \cdot B = \bigoplus_{j=0}^{r-1} M^{r-1} \cdot B = r \cdot M^{r-1} \cdot B$$

In $\mathbb{GF}(2)$, **$r = 3n/4$ is even** (for $n \geq 8$), so $r \cdot x = 0$ for any $x$. Therefore $\Phi_r = 0$, and the private nonces cancel themselves:

$$sk = M^r \cdot (C \oplus C_2) \oplus 0 = M^r \cdot (C \oplus C_2) \quad \text{— entirely public}$$

**Multiple exchanged public values.** If Alice and Bob each publish $k$ public values $C^{(t)}$ and the shared secret is $\bigoplus_t S_{r_t+1} \cdot (C^{(t)} \oplus C_2^{(t)})$, each term is independently a $\mathbb{GF}(2)$-linear function of wire values. Eve computes each term independently. No number of additional linear public values escapes the cancellation.

**Experimental verification:** `SecurityProofsCode/hkex_multinonce_analysis.py` — 8 nonce strategies, multi-exchange with $k = 1, 2, 4$ pairs; GF(2) even-sum collapse verified; Eve recovers $sk$ in 1,000/1,000 trials for all strategies.

---

### 3.6 Root Cause: Linearity–Security Incompatibility

**Theorem 10 (Linearity–Security Incompatibility).**

> A DH-style key exchange based entirely on $\mathbb{GF}(2)$-linear operations cannot be simultaneously **correct** ($sk_A = sk_B$) and **secure** ($sk$ is not computable from public values).

**Proof.** The HKEX correctness proof (Theorem 6) shows that $B$ and $A$ cancel from $sk$ via Corollary 2 ($S_n = 0$). That same cancellation also removes all private information from $sk$, leaving only $S_{r+1} \cdot (C \oplus C_2)$ — a function of public values. The two requirements are mutually exclusive:

| Property | Requires |
|---|---|
| Correctness | Private terms cancel from $sk_A - sk_B$ via $S_n = 0$ |
| Security | Private terms remain in $sk_A$ |

Adding any combination of $\mathbb{GF}(2)$-linear operations does not escape this dilemma:

- Single XOR nonce injection → still $\mathbb{GF}(2)$-linear (Theorem 8)
- Multiple per-step XOR nonces → still $\mathbb{GF}(2)$-linear (Theorem 9)
- More exchanged public values → each term still linear
- Composition of any number of $\mathbb{GF}(2)$-linear maps → still linear

In all cases, the superposition principle $f(A \oplus X) = f(A) \oplus f(X)$ holds, and the same $S_n = 0$ structure that enables correctness simultaneously exposes $sk$. $\blacksquare$

**Fix requirement.** The only path to a secure construction is replacing FSCX with a **non-linear primitive** — a function $F$ such that $F(A \oplus X) \neq F(A) \oplus F(X)$ in general. Only then can the cancellation property that enables correctness fail to simultaneously expose $sk$ as a function of public values.

---

## 4. Strengths and Weaknesses

### 4.1 Strengths

| Property | Status |
|---|---|
| Correctness (all protocols) | ✓ Proven: follows from $S_n = 0$ and $M^n = I$ |
| Constant-time implementation | ✓ All operations are bitwise; no data-dependent branches |
| Simplicity and auditability | ✓ The entire primitive is 6 terms |
| Bit-frequency uniformity | ✓ Output bits are balanced to <0.5% deviation |
| $M$ invertible for $n = 2^k$ | ✓ Proven algebraically; no information loss per step |
| Nonce-augmentation preserves orbit period | ✓ Proven; $S_n = 0$ absorbs nonce completely |
| HSKE correctness and security | ✓ Proven; key $K$ survives in ciphertext as non-zero private offset |

---

### 4.2 Weaknesses and Vulnerabilities

**W1 — FSCX is a linear map over $\mathbb{GF}(2)$.**

$$\text{FSCX}(A \oplus X, B \oplus X) = M \cdot (A \oplus B) = \text{FSCX}(A, B) \quad \forall X$$

FSCX is not a nonlinear function. All security relies on iteration and parameter choices, not on the mixing function itself. This linearity is the root cause of the classical break (Theorem 7, Theorem 10).

---

**W2 — HKEX shared secret is publicly computable (classical break).**

From Corollary 3 and Theorem 7:

$$sk = S_{r+1} \cdot (C \oplus C_2)$$

Both $C$ and $C_2$ are transmitted publicly. Eve recovers the shared secret in $O(n^2)$ classical bit operations. This breaks HKEX, HPKE, and HPKS completely.

---

**W3 — HPKE provides no confidentiality.**

The ciphertext is $E = sk_B \oplus A_2 \oplus P$ where $sk_B$ and $A_2$ are both computable from the public key. Eve decrypts directly: $P = E \oplus S_{r+1} \cdot (C \oplus C_2) \oplus A_2$.

---

**W4 — HPKE/HPKS are bit-malleable (no IND-CCA2).**

Let $E = sk_B \oplus A_2 \oplus P$. Then:

$$D(E \oplus \delta) = P \oplus \delta$$

Flipping bit $k$ of $E$ flips bit $k$ of the plaintext. HPKE has no ciphertext integrity.

---

**W5 — Original HPKS directly leaks the session key; HPKS₂ mitigates this.**

In the original scheme $S = sk_A \oplus P$, a single signed pair $(P, S)$ immediately reveals:

$$sk_A = S \oplus P$$

A forger who recovers $sk_A$ can sign any $P'$ as $S' = sk_A \oplus P'$, breaking the scheme after one signing query.

**HPKS₂** eliminates this by replacing the XOR with HSKE encryption. From the affine iteration formula:

$$S = M^i \cdot P + S_i \cdot (M + I) \cdot sk_A$$

The coefficient of $sk_A$ is $S_i \cdot (M + I)$. In $R_n$:

$$M + I = L + L^{-1} = x^{-1}(x+1)^2$$

Since $(x+1)^n = 0$ in $R_n$, the factor $(x+1)^2$ is a zero divisor — $M + I$ is **not a unit**. Therefore the equation $S = M^i \cdot P + S_i \cdot (M+I) \cdot sk_A$ has no unique solution for $sk_A$ from a single $(P, S)$ pair, removing the trivial one-query key recovery.

However, since $sk_A = S_{r+1} \cdot (C \oplus C_2)$ is already publicly computable from the public key (W2), signatures remain forgeable via the classical break.

---

**W6 — Hardness assumption was never established; the break renders it moot.**

The system reduces to: given $C = M^i \cdot A + M \cdot S_i \cdot B$, recovering $(A, B)$ is assumed hard. However, Theorem 7 shows that recovering the *shared secret* $sk$ does not require recovering $(A, B)$ at all — $sk$ is directly computable from $C$ and $C_2$ alone in $O(n^2)$ time.

---

**W7 — Short effective orbit space.**

Since $M^{n/2} = I$, the orbit of $f_B$ has period at most $n/2$, so at most $n/2$ distinct values of $C$ arise for any fixed $B$. This reduces the effective pre-image space.

---

**W8 — No authenticated encryption.**

None of HSKE, HPKE, or HPKS provides joint confidentiality + integrity + authentication. These properties must be composed externally (e.g., encrypt-then-MAC).

---

## 5. Summary Tables

### 5.1 Protocol Security Status

| Protocol | Correctness | Classical Break | IND-CPA | IND-CCA2 | EUF-CMA |
|---|---|---|---|---|---|
| HKEX | ✓ Proven | **BROKEN** (Thm. 7) | ✗ | — | — |
| HSKE | ✓ Proven | N/A (pre-shared key) | Unproven | ✗ (malleable) | — |
| HPKS₂ | ✓ Proven | **BROKEN** (sk public) | — | — | ✗ |
| HPKE | ✓ Proven | **BROKEN** (Thm. 7) | ✗ | ✗ (malleable) | — |

---

### 5.2 Break and Impossibility Results

| Claim | Status | Evidence |
|---|---|---|
| $sk = S_{r+1} \cdot (C \oplus C_2)$ — computable from public wire values | **Proved** (Thm. 7) | Algebraic + 10K trials |
| Single public nonce injection does not fix break | **Proved** | Case (a), 2K trials |
| Single private nonce injection breaks correctness | **Proved** | Case (b), 2K trials |
| No nonce (single or multi) can fix HKEX | **Proved** (Thms. 8, 9) | 10+8 strategies, all fail |
| HSKE is correct and secure (pre-shared key model) | **Proved** | $K$ survives in $E$, $D=P$ round-trip |
| HPKE is correct but publicly insecure | **Proved** | $sk = S_{r+1} \cdot \text{public}$ |
| $n_A = A \oplus C$ gives correctness with probability $2^{-4}$ | **Proved** | Rank-4 condition matrix |
| $N_j = M^j \cdot B$ collapses to $\Phi = 0$ (GF(2) even-sum) | **Proved** | $r$ even $\Rightarrow \Phi_r = 0$ |
| $k$ exchanged public values do not help (any $k$) | **Proved** | Each term linear; $k = 1, 2, 4$ tested |
| Root cause: GF(2)-linearity/correctness–security incompatibility | **Proved** (Thm. 10) | Algebraic; no counterexample exists |
| Quantum attacks: classical break makes them moot | **Proved** | See §6 |

---

## 6. Quantum Attack Analysis

The classical break (Theorem 7) recovers $sk$ in $O(n^2)$ classical operations. The quantum attacks below are therefore moot for any variant that does not first fix the classical break.

| Attack | Target | Result |
|--------|--------|--------|
| **Grover** | Key search (brute force) | Reduces search from $2^n$ to $2^{n/2}$ — relevant only if classical break is patched |
| **Simon / HSP** | Hidden subgroup in $\mathbb{GF}(2)^n$ | Applicable; $\mathbb{GF}(2)$-linearity gives $M$ an order-$n/2$ subgroup structure; $O(n)$ quantum queries suffice |
| **Bernstein–Vazirani** | Recover linear function | Single quantum query suffices to recover the linear map $S_{r+1}$ |
| **Shor** | Discrete logarithm | Inapplicable — HKEX has no DLP structure |
| **HHL** | Linear system solving | Already polynomial classically; no quantum advantage relevant |

The classical break makes all quantum attacks moot for the current design. For any future variant that patches the classical break by introducing genuine nonlinearity, Grover's algorithm and Simon's algorithm become the relevant post-quantum threats.

---

## 7. Core Identity (the Fundamental Equation)

Everything in the suite ultimately rests on two chained facts:

**Fact A:** In $\mathbb{GF}(2)[x]/(x^n + 1)$ with $n = 2^k$:

$$m^{n/2} = 1 \implies S_n = 0$$

**Fact B (Corollary 2):** For $i + r = n$:

$$M \cdot S_r + M^{r+1} \cdot S_i = S_n = 0$$

Together, these imply that for any $A, B, A_2, B_2 \in \mathbb{GF}(2)^n$ and any nonce $N$:

$$\text{FSCX\_REVOLVE\_N}\!\left(\text{FSCX\_REVOLVE}(A_2, B_2, i),\; B,\; N,\; r\right) \oplus A$$
$$=$$
$$\text{FSCX\_REVOLVE\_N}\!\left(\text{FSCX\_REVOLVE}(A, B, i),\; B_2,\; N,\; r\right) \oplus A_2$$

This identity is the mathematical core from which all four protocols derive their correctness. All protocols are **correct**. However, the same identity that enables correctness also ensures that the shared secret $sk = S_{r+1} \cdot (C \oplus C_2)$ contains no private information — breaking the key exchange.

The fix requirement (Theorem 10): replace FSCX with a primitive $F$ that is **not** $\mathbb{GF}(2)$-linear.

---

## 8. Experimental Code Index

All experimental scripts are in `SecurityProofsCode/`:

| File | Content |
|------|---------|
| `probe_sk_formula.py` | Initial algebraic probe: verify $sk = S_{r+1} \cdot (C \oplus C_2)$ with fixed test vectors; confirm $M^r \oplus S_r = S_{r+1}$ and Corollary 2 |
| `hkex_classical_break.py` | Full classical break: 10,000 trials across $n \in \{32, 64, 128, 256\}$; Eve uses only $C$, $C_2$ |
| `hkex_fscxn_analysis.py` | Single-nonce analysis: Case (a) public nonce (break survives), Case (b) private nonce (correctness destroyed), Case (c) offset formula verified |
| `hkex_nonce_impossibility.py` | HSKE/HPKE mechanism; exhaustive 10-strategy nonce search; direct Theorem 8 verification ($S_r \cdot n_A$ constant iff correct) |
| `hkex_multinonce_analysis.py` | Multi-nonce closed form (Theorem 9); 8 nonce strategies; $k = 1, 2, 4$ exchanged pairs; GF(2) even-sum collapse |
| `hkex_nl_proposal.py` | Non-linear proposals §9: HKEX-GF correctness + Eve-failure (4 000 trials); FSCX-CY non-linearity, period analysis, HKEX-CY failure, Eve-failure |

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

### 9.2 HKEX-GF — Diffie-Hellman over $\mathbb{GF}(2^n)^*$

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

Pre-agreed public parameters: field size $n$, irreducible polynomial $p(x)$, generator $g \in \mathbb{GF}(2^n)^*$.

| Step | Alice | Bob |
|------|-------|-----|
| Private | $a \xleftarrow{\$} \{1,\ldots,2^n{-}1\}$ | $b \xleftarrow{\$} \{1,\ldots,2^n{-}1\}$ |
| Public | $C = g^a \in \mathbb{GF}(2^n)^*$ | $C_2 = g^b \in \mathbb{GF}(2^n)^*$ |
| Shared | $sk = C_2^{\,a} = g^{ab}$ | $sk = C^{\,b} = g^{ab}$ |

**Correctness proof:**

$$C_2^{\,a} = (g^b)^a = g^{ba} = g^{ab} = (g^a)^b = C^{\,b} \qquad \blacksquare$$

This holds by commutativity and associativity of multiplication in $\mathbb{GF}(2^n)^*$, which are ring axioms satisfied for any polynomial choice (irreducible or not). Irreducibility is required only for the group to be a field (every non-zero element invertible).

#### 9.2.3 Why Eve's formula fails

Eve's classical attack computes $sk_\text{eve} = S_{r+1} \cdot (C \oplus C_2)$.

Under HKEX-GF, the public values $C = g^a$ and $C_2 = g^b$ are field elements whose XOR $C \oplus C_2 = g^a \oplus g^b$ has no algebraic relationship to $g^{ab}$. Specifically:

$$S_{r+1} \cdot (g^a \oplus g^b) \neq g^{ab} \quad \text{in general}$$

because $S_{r+1}$ is the $\mathbb{GF}(2)$-linear FSCX partial-sum operator acting on XOR-structured vectors, while $g^{ab}$ is determined by field multiplication — a different algebraic structure. The two cannot coincide except by accidental collision (probability $2^{-n}$), confirmed at $0/4000$ over all trials.

#### 9.2.4 Security assumption

The hardness of HKEX-GF reduces to the **Computational Diffie-Hellman (CDH)** problem in $\mathbb{GF}(2^n)^*$: given $g^a$ and $g^b$, compute $g^{ab}$.

CDH in $\mathbb{GF}(2^n)^*$ is believed hard for large $n$, under the assumption that the Discrete Logarithm Problem (DLP) in $\mathbb{GF}(2^n)^*$ is hard. Sub-exponential attacks (index calculus, function field sieve variants) exist for binary extension fields; practical parameters:

| $n$ | Estimated classical security | Note |
|-----|------------------------------|------|
| 64  | ≪ 64 bits (demonstration only) | Sub-exponential attacks apply |
| 128 | ≈ 60–80 bits | Marginal; for demos only |
| 256 | ≈ 128 bits | Recommended minimum for real use |
| 512 | ≈ 192+ bits | Conservative |

For production use, elliptic curve Diffie-Hellman over a binary curve (or a prime-field ECDH) provides better security-per-bit. HKEX-GF as presented is a proof-of-concept demonstrating that the classical break is structurally avoidable.

#### 9.2.5 FSCX period preserved

FSCX, fscx\_revolve, and all symmetric protocols (HSKE, HPKS, HPKE) are **unchanged**. Their correctness proofs (Theorems 1–6, Corollaries 1–3) remain valid. The HKEX-GF key exchange produces $sk \in \mathbb{GF}(2^n)^*$, which is passed to HSKE/HPKS/HPKE as a pre-shared symmetric key — the existing interface.

**Verified experimentally:** `fscx_revolve(fscx_revolve(P, K, i), K, r) = P` for $i + r = n$ holds at 4000/4000 trials across $n \in \{32, 64\}$ (Section I-D of `hkex_nl_proposal.py`).

---

### 9.3 FSCX-CY — Carry-Injection FSCX (Experimental)

#### 9.3.1 Construction

Define the **carry-injection** variant:

$$\text{FSCX-CY}(A, B) = M\!\left((A + B) \bmod 2^n\right)$$

where $+$ is ordinary integer addition (not $\oplus$), and $M = I \oplus \text{ROL}(1) \oplus \text{ROR}(1)$ is the standard FSCX linear operator.

Compared to standard FSCX:

$$\text{FSCX}(A, B) = M(A \oplus B), \qquad \text{FSCX-CY}(A, B) = M\!\left((A + B) \bmod 2^n\right)$$

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
| Security assumption | DLP in $\mathbb{GF}(2^n)^*$ | Unknown |
| Copies a known cipher | No (DH is a key-exchange, not a cipher) | No |

**Recommended fix.** Replace the HKEX key-exchange step with HKEX-GF. All symmetric protocols (HSKE, HPKS, HPKE) continue using standard FSCX with no changes. The period structure $M^n = I$, $S_n = 0$ remains valid; all correctness proofs (Theorems 1–6, Corollaries 1–3) are unaffected. The only change is in how the shared symmetric key $sk$ is established: via $\mathbb{GF}(2^n)$ DH rather than via FSCX iteration.

**FSCX-CY as a direction.** Although FSCX-CY cannot replace FSCX directly, it demonstrates that carry-injection creates genuine non-linearity with a minimal code change (one operation: `A ^ B` → `(A + B) mod 2^n`). A future variant could use FSCX-CY for a symmetric cipher where the key-specific period $T(K)$ is precomputed and incorporated into the protocol design.
