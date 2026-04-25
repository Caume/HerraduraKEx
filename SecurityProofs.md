# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §12 (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §12.5 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).
**Last updated:** 2026-04-19 (v1.5.4)

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

$$\text{FSCX}\textunderscore\text{REVOLVE}(A, B, k) = f_B^k(A)$$

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

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(A, B, N, k) :
\begin{cases}
X_0 = A \\
X_{j+1} = \text{FSCX}(X_j, B) \oplus N = M \cdot X_j \oplus M \cdot B \oplus N
\end{cases}$$

This is the affine map $g_{B,N}(X) = M \cdot X + (M \cdot B \oplus N)$ with translation $c = M \cdot B \oplus N$. The closed-form iteration formula is:

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(A, B, N, k) = M^k \cdot A + M \cdot S_k \cdot B \oplus S_k \cdot N$$

**Theorem 5 — Period still divides $n$:**

$$g^n_{B,N}(A) = M^n \cdot A + S_n \cdot (M \cdot B \oplus N) = A + 0 = A$$

The nonce $N$ does not affect the period, and decryption is the complementary revolve.

**Nonce propagation linearity:** If $N$ changes by $\delta N$, the change in $\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(\cdot, B, N, k)$ at step $k$ is:

$$\delta\text{Output} = S_k \cdot \delta N = (I + M + M^2 + \cdots + M^{k-1}) \cdot \delta N$$

For $k = n$ this is $S_n \cdot \delta N = 0$, so nonce changes are fully absorbed over a full cycle. The Hamming distance of a single-bit nonce flip is deterministic (independent of $A$ and $B$) and equals $\text{popcount}(S_k \cdot e_j)$. Empirically, $\text{HD} = n/4$ for $k = i = n/4$.

---

## 2. Protocol Analysis

### 2.1 HKEX — Key Exchange

**Protocol:**

$$\begin{aligned}
&\textbf{Alice:}\quad A, B \leftarrow \text{random};\quad C = \text{FSCX}\textunderscore\text{REVOLVE}(A, B, i) \\
&\textbf{Bob:}\quad A_2, B_2 \leftarrow \text{random};\quad C_2 = \text{FSCX}\textunderscore\text{REVOLVE}(A_2, B_2, i)
\end{aligned}$$

$$\text{Alice} \xrightarrow{C} \text{Bob} \qquad \text{Bob} \xrightarrow{C_2} \text{Alice}$$

$$\begin{aligned}
&\textbf{Alice:}\quad sk_A = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2, B, N, r) \oplus A \\
&\textbf{Bob:}\quad sk_B = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C, B_2, N, r) \oplus A_2 \\
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

$$\text{Encrypt:}\quad E = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(P, K, K, i)$$
$$\text{Decrypt:}\quad D = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(E, K, K, r)$$

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
&\textbf{Alice:}\quad S = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(P,\; sk_A,\; sk_A,\; i) \quad [\text{HSKE-encrypt } P \text{ under } sk_A] \\
&\textbf{Bob:}\quad V = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(S,\; sk_B,\; sk_B,\; r) \quad [\text{HSKE-decrypt } S \text{ under } sk_B] \\
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
&\textbf{Bob:}\quad E = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C, B_2, N, r) \oplus A_2 \oplus P \\
&\textbf{Alice:}\quad D = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(C_2, B, N, r) \oplus A \oplus E
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

**The proposal:** Replace the public-key computation $C = \text{FSCX}\textunderscore\text{REVOLVE}(A, B, i)$ with the nonce-augmented variant $C = \text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(A, B, \Phi, i)$:

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

*Proof.* Applying the affine iteration formula for $\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}$ and substituting $A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$:

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

| Protocol | Correctness | Classical Break | IND-CPA | IND-CCA2 | EUF-CMA | Status (v1.4.0) |
|---|---|---|---|---|---|---|
| HKEX (old) | ✓ Proven | **BROKEN** (Thm. 7) | ✗ | — | — | **Removed** |
| HKEX-GF | ✓ Proven (field comm.) | CDH in GF(2ⁿ)* | Unproven | — | — | **Active** |
| HSKE | ✓ Proven | N/A (pre-shared key) | Unproven | ✗ (malleable) | — | Active |
| HPKS₂ | ✓ Proven | N/A (sk via HKEX-GF) | — | — | Unproven | Active |
| HPKE | ✓ Proven | N/A (sk via HKEX-GF) | Unproven | ✗ (malleable) | — | Active |

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
| **HKEX-GF correctness:** $g^{ab} = g^{ba}$ in $\mathbb{GF}(2^n)^*$ | **Proved** (field commutativity) | Algebraic + 5K/1K trials (Python/C) |
| **HKEX-GF Eve resistance:** $S_{r+1}(C \oplus C_2) \neq sk$ | **Proved** | 10K trials — 0 successes |
| **FSCX-CY non-linearity** | **Proved** | 4998/5000 affine-test failures |
| **FSCX-CY HKEX failure** | **Proved** | 0/2000 correctness trials |

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

The classical break makes all quantum attacks moot for the current design. For any future variant that patches the classical break by introducing genuine nonlinearity, Grover's algorithm and Simon's algorithm become the relevant post-quantum threats. For the detailed quantum security analysis of the v1.4.0 suite (HKEX-GF and related protocols), see §10.8.

---

## 7. Core Identity (the Fundamental Equation)

Everything in the suite ultimately rests on two chained facts:

**Fact A:** In $\mathbb{GF}(2)[x]/(x^n + 1)$ with $n = 2^k$:

$$m^{n/2} = 1 \implies S_n = 0$$

**Fact B (Corollary 2):** For $i + r = n$:

$$M \cdot S_r + M^{r+1} \cdot S_i = S_n = 0$$

Together, these imply that for any $A, B, A_2, B_2 \in \mathbb{GF}(2)^n$ and any nonce $N$:

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}\!\left(\text{FSCX}\textunderscore\text{REVOLVE}(A_2, B_2, i),\; B,\; N,\; r\right) \oplus A$$
$$=$$
$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}\!\left(\text{FSCX}\textunderscore\text{REVOLVE}(A, B, i),\; B_2,\; N,\; r\right) \oplus A_2$$

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
| `hkex_gf_test.py` | Standalone HKEX-GF test suite: GF arithmetic (1K trials), DH correctness (5K), Eve resistance (5K), BSGS DLP illustration (n=16), FSCX period preserved (5K), benchmarks |
| `hkex_cy_test.py` | FSCX-CY exhaustive analysis: XOR-translation proof, HKEX-CY failure (5K), period measurements, Eve resistance |

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
| Private | $a \xleftarrow{\textdollar} \{1,\ldots,2^n{-}1\}$ | $b \xleftarrow{\textdollar} \{1,\ldots,2^n{-}1\}$ |
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

CDH in $\mathbb{GF}(2^n)^*$ is believed hard for large $n$, under the assumption that the Discrete Logarithm Problem (DLP) in $\mathbb{GF}(2^n)^*$ is hard.  Known classical attack complexities on the DLP in $\mathbb{GF}(2^n)^*$:

| Algorithm | Complexity | Notes |
|-----------|------------|-------|
| Baby-step giant-step (BSGS) | $O(2^{n/2})$ time, $O(2^{n/2})$ space | Generic group algorithm |
| Pohlig–Hellman | $O(\sqrt{q_{\max}})$ where $q_{\max}$ = largest prime factor of group order | Dangerous when order is smooth |
| Index calculus (function field sieve) | $L_{2^n}[1/2, c]$ (sub-exponential) | General DLP in $\mathbb{GF}(2^n)^*$ |
| **Quasi-polynomial (Barbulescu–Joux–Pierrot 2013)** | $(\log 2^n)^{O(\log\log 2^n)}$ | Specific to characteristic-2 fields |

The **quasi-polynomial algorithm** is the dominant classical threat.  It exploits the
characteristic-2 structure of $\mathbb{GF}(2^n)^*$ via a descent using sparse linear systems in
function fields — a technique with no known analogue for DLP in prime-order elliptic curve groups
or in $\mathbb{Z}_p^*$.  In practice it has broken DLP in $\mathbb{GF}(2^{1279})$ and related
fields.  The recommended minimum for $\mathbb{GF}(2^n)^*$ DLP (if it must be used) is $n \geq 3000$;
most standards bodies advise **against** using $\mathbb{GF}(2^n)^*$ for new DLP-based designs.

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
$\mathbb{GF}(2^{32})^*$: its order is a proper divisor of $2^{32}-1$.  Multiple exponents share
the same public key; BSGS finds the smallest representative.  The shared secret is nevertheless
fully recovered because $g^{ab}$ is the same regardless of which representative is used.

**Effective security:** $n = 32$ is broken in under 1 second.  The quasi-polynomial attack
extends to all practical $n$ values.

**Practical parameters:**

| $n$ | Estimated classical security | Note |
|-----|------------------------------|------|
| 64  | ≪ 64 bits (demonstration only) | Sub-exponential attacks apply |
| 128 | ≈ 60–80 bits | Marginal; for demos only |
| 256 | ≈ 128 bits | Recommended minimum for real use |
| 512 | ≈ 192+ bits | Conservative |

For production use, elliptic curve Diffie-Hellman over a binary curve (or a prime-field ECDH) provides better security-per-bit.  HKEX-GF as presented is a proof-of-concept demonstrating that the classical break is structurally avoidable; the root cause analysis in §10.9 explains why $\mathbb{GF}(2^n)^*$ is ultimately unsuitable for a production key exchange.

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

---

## 10. v1.4.0 Migration: HKEX → HKEX-GF

### 10.1 Change Summary

Version 1.4.0 replaces the broken HKEX key exchange with HKEX-GF across all implementations (Python, Go, C, ARM assembly, NASM i386, Arduino). Two functions are affected:

| Function | v1.3.x (broken) | v1.4.0 (fixed) |
|----------|-----------------|----------------|
| Key exchange | FSCX-based (linear, $sk$ public) | DH over $\mathbb{GF}(2^n)^*$ |
| `fscx_revolve_n` | Used in HKEX/HPKS/HPKE | **Removed** — nonce cancels identically |
| HSKE | `fscx_revolve_n(P, K, K, i)` | `fscx_revolve(P, K, i)` |
| HPKS | $S = sk \oplus P$, where $sk = \text{FSCX-based}$ | $S = sk \oplus P$, where $sk = g^{ab}$ |
| HPKE | $E = sk \oplus P$, where $sk = \text{FSCX-based}$ | $E = sk \oplus P$, where $sk = g^{ab}$ |

### 10.2 Why `fscx_revolve_n` Was Removed

Theorem 10 (proved in §4.5 / SecurityProofsCode) shows that any nonce $N$ injected during FSCX iteration satisfies:

$$\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}(A, B, N, k) = M^k \cdot A \oplus M \cdot S_k \cdot B \oplus S_k \cdot N$$

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
| HSKE round-trip $\text{fscx}\textunderscore\text{revolve}^2(P, K, i, r) = P$ | 5 000/5 000 |

### 10.5 Security Status After Migration

| Weakness | v1.3.x | v1.4.0 |
|----------|--------|--------|
| W2: $sk$ computable from $(C, C_2)$ | **ACTIVE** (Thm. 7) | **Mitigated** — $sk = g^{ab}$ requires DLP |
| W3: HPKE no confidentiality | **ACTIVE** | **Mitigated** — $E = sk \oplus P$ with CDH-hard $sk$ |
| W5: Single $(P,S)$ reveals $sk$ | **ACTIVE** | **Mitigated** — $sk$ is CDH-hard to compute |
| W6: No hardness assumption established | **ACTIVE** | **Mitigated** — CDH in $\mathbb{GF}(2^n)^*$ |
| W4: Bit malleability (no IND-CCA2) | Active | Still active (structural to XOR encryption) |
| W7: Short orbit space | Active | Still active for FSCX; irrelevant for GF DH |
| W8: No authenticated encryption | Active | Still active (no MAC component) |

The key exchange is now provably secure under CDH in $\mathbb{GF}(2^n)^*$. Remaining weaknesses (W4, W7, W8) are structural to the XOR-based symmetric protocols and are documented; they do not affect the key exchange itself.


---

### 10.6 Classical Security Analysis of v1.4.0 Protocols

#### 10.6.1 HSKE — Known-Plaintext Attack

By Theorem 11 (§11.1): $E = M^i \cdot P \oplus M \cdot S_i \cdot K$.  Defining $c_K \triangleq M \cdot S_i \cdot K$:

$$c_K = E \oplus M^i \cdot P$$

One known-plaintext pair $(P, E)$ immediately yields $c_K$.  At $n = 64$, $i = 16$: rank$(\Phi) = 64$
(experimentally verified: 0 unconstrained key bits from a single pair), meaning $K$ is uniquely
determined.  **HSKE provides no security under known-plaintext attack at any $n$.**

#### 10.6.2 HPKS — Classical Forgery Resistance

Forgery requires finding $(R^*, s^*)$ satisfying $g^{s^*} \cdot C^{e^*} = R^*$ where
$e^* = \text{fscx}\textunderscore\text{revolve}(R^*_\text{bits}, P^*, i)$, without knowing the private key $a$.

- If Eve fixes $R^*$ first: she needs $s^* = \log_g(R^* \cdot C^{-e^*})$ — a DLP instance.
- If Eve fixes $s^*$ first: she can compute $g^{s^*} \cdot C^{e^*}$ for any $e^*$, but the
  constraint $e^* = \text{fscx}\textunderscore\text{revolve}(R^*_\text{bits}, P^*, i)$ ties $R^*$ and $e^*$
  together.  Since fscx\_revolve is an affine bijection in its first argument (see §10.7),
  solving both simultaneously reduces to DLP hardness.

Forgery resistance is equivalent to DLP hardness in $\mathbb{GF}(2^n)^*$, subject to the
quasi-polynomial attack in §9.2.4 and the challenge-function caveat in §10.7.

#### 10.6.3 HPKE — Classical Attack

Ciphertext is $(R, E) = (g^r,\, \text{fscx}\textunderscore\text{revolve}(P,\, g^{ar},\, i))$.  Recovering the
plaintext requires $g^{ar}$, which is the CDH problem given $(g^a, g^r)$.
Since CDH $\leq$ DLP, all classical DLP attacks in §9.2.4 apply directly.

Additionally, the affine structure of fscx\_revolve means that given $(g^r, E)$ and a
known-plaintext pair, $c_{\mathit{ek}} = E \oplus M^i \cdot P$ recovers the key constant.
DLP on $\mathit{ek} = C^r$ or $\mathit{ek} = R^a$ may then recover $a$ or $r$.

---

### 10.7 HPKS Challenge Function — Algebraic Properties

The challenge in HPKS uses fscx\_revolve in place of a hash function:
$e = \text{fscx}\textunderscore\text{revolve}(R_\text{bits}, P, i)$.  Two algebraic properties affect
provable security.

**Property 1 — Affine bijection in $R$.**

For fixed $P$ and $i$, the map $R \mapsto M^i \cdot R \oplus M \cdot S_i \cdot P$
is an affine bijection: the linear part $M^i$ is invertible (since $M$ has order $n/2$),
so no two distinct $R$ values produce the same challenge $e$.

*Verified:* 50 000 random $R$ values at $n = 64$, fixed $P$: **0 collisions**.

**Property 2 — Predictable challenge delta.**

By the difference identity (Theorem 11 linearity):

$$e(R_2) \oplus e(R_1) = \text{fscx}\textunderscore\text{revolve}(R_1 \oplus R_2,\; 0,\; i) = M^i \cdot (R_1 \oplus R_2)$$

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

**Practical implication.** The DLP in $\mathbb{GF}(2^n)^*$ still protects the private key
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

**HKEX-GF, HPKS, HPKE.**  Security rests on DLP in $\mathbb{GF}(2^n)^*$.  Shor's
algorithm (§10.8.4) solves DLP in polynomial quantum time and strictly dominates
Grover for all these protocols.  **Grover is irrelevant for the GF-DLP protocols.**

#### 10.8.2 Simon's Algorithm

**Simon's problem:** find the hidden period $s$ of a function $f(x) = f(x \oplus s)$
in $O(n)$ quantum queries, where $s$ is $\mathbb{GF}(2)$-linear.

**Applicability.** The DLP function $f(x) = g^x$ in $\mathbb{GF}(2^n)^*$ has collisions
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

**HKEX-GF, HPKS, HPKE.** Involve $\mathbb{GF}(2^n)^*$ exponentiation, which is not
$\mathbb{GF}(2)$-affine in the exponent.  BV does not apply.

#### 10.8.4 Shor's Algorithm — Primary Quantum Threat

Shor's algorithm solves the DLP in any cyclic group $G = \langle g \rangle$ of order $N$
in $O((\log N)^2 \log\log N \cdot \log\log\log N)$ quantum gate operations.  For
$\mathbb{GF}(2^n)^*$: group order $N = 2^n - 1$, quantum time $O(n^2 \log n)$.

| Adversary | Best DLP attack on $\mathbb{GF}(2^n)^*$ | Complexity |
|-----------|----------------------------------------|------------|
| Classical | Quasi-polynomial (Barbulescu 2013) | $(\log N)^{O(\log\log N)}$ |
| Quantum | Shor's algorithm | $O((\log N)^2 \log\log N)$ |

Both attacks break $\mathbb{GF}(2^n)^*$ DLP at all practical parameter sizes.

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

The choice of $\mathbb{GF}(2^n)^*$ as the DLP group introduces weaknesses absent in
standard DLP groups:

1. **Characteristic-2 quasi-polynomial attack** (Barbulescu et al., 2013): exploits
   sparse relations in the function field $\mathbb{GF}(2^n)(t)$, achieving
   $(\log N)^{O(\log\log N)}$ classical complexity.  This does not apply to prime-order
   elliptic curves or $\mathbb{Z}_p^*$.

2. **Shor's algorithm at $O(n^2 \log n)$**: applies to any cyclic group DLP; the
   characteristic-2 structure provides no resistance.

3. **Generator order**: when $g = 3$ is not a primitive element of $\mathbb{GF}(2^n)^*$
   (its actual order divides $2^n - 1$), the effective group size is smaller than assumed,
   reducing security further.

**Comparison with alternatives:**

| Group | Classical DLP | Quantum DLP |
|-------|--------------|-------------|
| $\mathbb{GF}(2^n)^*$ | Quasi-polynomial (weak) | Shor's polynomial |
| $\mathbb{Z}_p^*$, $p$ prime | Sub-exponential (NFS) | Shor's polynomial |
| Elliptic curve over $\mathbb{GF}(p)$ | Exponential (ECDLP) | Shor's polynomial |
| Ring-LWR ($\mathcal{R}_q$, blinded $m$, §11.4) | Exponential (conjectured) | No known polynomial attack |

Moving the key exchange to a prime-order elliptic curve restores classical DLP hardness
(no known sub-exponential algorithm) but does not address Shor's algorithm.  Only a
lattice, code-based, or isogeny-based construction provides a plausible path to
post-quantum security.  The HKEX-RNL proposal in §11.4 (Ring-LWR with blinded FSCX
polynomial) is the recommended direction within the Herradura suite.

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

$$\text{FSCX}\textunderscore\text{REVOLVE}(X, B, r) = R \cdot X \oplus K \cdot B$$

where $R = M^r$ and $K = M + M^2 + \cdots + M^r \in \mathbb{GF}(2)^{n \times n}$.

*Proof:* By induction.  Base case: $\text{FSCX}(X, B) = M(X \oplus B) = M \cdot X \oplus M \cdot B$.
For step $k+1$: $\text{FSCX}(M^k X \oplus S_k B, B) = M(M^k X \oplus S_k B \oplus B) = M^{k+1} X \oplus M(S_k + I) B = R \cdot X \oplus K \cdot B$. $\blacksquare$

**Consequence.** Eve holding $(X, \text{FSCX}\textunderscore\text{REVOLVE}(X, B, r))$ for a single plaintext–ciphertext pair
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

$$\text{NL-FSCX}(A, B) = \text{FSCX}(A, B) \oplus \text{ROL}\!\left((A + B) \bmod 2^n,\; \frac{n}{4}\right)$$

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
revolve-based decryption identity $\text{FSCX}\textunderscore\text{REVOLVE}(E, K, n/2 - r) = P$ cannot be ported to
NL-FSCX v1.  Counter mode (§11.3.1) is the only applicable HSKE construction.

#### 11.2.2 NL-FSCX v2 (B-only offset, explicit inverse)

$$\text{NL-FSCX}_{v2}(A, B) = \text{FSCX}(A, B) + \text{ROL}\!\left(B \cdot \left\lfloor\frac{B+1}{2}\right\rfloor \bmod 2^n,\; \frac{n}{4}\right) \pmod{2^n}$$

The offset $\delta(B) = \text{ROL}(B \cdot \lfloor(B+1)/2\rfloor \bmod 2^n,\, n/4)$ depends **only on $B$**.

| Property | Value | Verified |
|----------|-------|----------|
| Non-linear over $\mathbb{GF}(2)$ | Yes — $B \cdot \lfloor(B+1)/2\rfloor$ involves integer carry | 500/500 linearity violations (n=32) |
| Bijective in $A$ for fixed $B$ | **Yes** — offset is independent of $A$ | n=8: 0/256 non-bijective |
| Exact closed-form inverse | $A = B \oplus M^{-1}\!\left((Y - \delta(B)) \bmod 2^n\right)$ | 1000/1000 correct (n=32) |
| HSKE revolve enc→dec | Correct | 200/200 round-trips (n=32) |

**Proof of inverse.** $\text{NL-FSCX}_{v2}(A, B) = M(A \oplus B) + \delta(B)$.  Stripping the offset:
$(Y - \delta(B)) \bmod 2^n = M(A \oplus B)$.  Applying $M^{-1}$:
$A \oplus B = M^{-1}\!\big((Y - \delta(B)) \bmod 2^n\big)$, so $A = B \oplus M^{-1}(\cdots)$. $\blacksquare$

**Note on linearity channel.** $A$ still enters $\text{FSCX}(A, B)$ through the linear map $M$.
The non-linearity is in the $B$-channel (key) only.  For HSKE, the adversary observes
$C = P \oplus \text{keystream}$ and never $A$ directly; the key $K$ enters exclusively via $B$,
so the $B$-channel non-linearity is sufficient to defeat linear key-recovery attacks.

---

### 11.3 HSKE Variants

Two secure HSKE constructions are defined; both are chosen depending on API requirements.

#### 11.3.1 HSKE-A1: Counter Mode with NL-FSCX v1

Let $\text{base} = K \oplus N$ where $N$ is a random per-session nonce (transmitted with ciphertext).

$$\text{keystream}[i] = \text{NL-FSCX-REVOLVE}\!\left(\text{ROL}(\text{base},\; n/8),\; \text{base} \oplus i,\; n/4\right)$$
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

$$E = \text{NL-FSCX-REVOLVE}_{v2}(P,\; K,\; r)$$
$$P = \text{NL-FSCX-REVOLVE}_{v2}^{-1}(E,\; K,\; r)$$

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

HKEX-GF relies on the DLP in $\mathbb{GF}(2^n)^*$, which Shor's algorithm solves in polynomial time
on a quantum computer.  The following replacement is proposed.

#### 11.4.1 Ring structure

The FSCX linear map $M = I \oplus \text{ROL} \oplus \text{ROR}$ corresponds to multiplication by the
polynomial $m(x) = 1 + x + x^{n-1}$ in $\mathbb{GF}(2)[x]/(x^n + 1)$.  Lifting the coefficient ring
from $\mathbb{GF}(2)$ to $\mathbb{Z}/q\mathbb{Z}$ for a prime $q$:

$$\mathcal{R}_q = (\mathbb{Z}/q\mathbb{Z})[x]\,/\,(x^n + 1)$$

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

Both use the **same** $m_\text{blind}$.  ($\lfloor \cdot \rceil_p$ denotes rounding from $\mathbb{Z}/q\mathbb{Z}$ to $\mathbb{Z}/p\mathbb{Z}$.)  $\mathrm{CBD}(\eta)$ is the centered binomial distribution: each coefficient $s_i = \sum_{j=0}^{\eta-1}(a_j - b_j)$ where $a_j, b_j \overset{\textdollar}{\leftarrow} \{0,1\}$ independently.  Deployed with $\eta = 1$, giving $s_i \in \{-1, 0, 1\}$ with zero mean and $\Pr[s_i = \pm 1] = 1/4$.  This matches the Kyber/NIST baseline for proper Ring-LWR secret entropy and eliminates the mean bias of the previous uniform $\{0,1\}$ sampler.

**Key agreement:**
$$K_A = \left\lfloor s_A \cdot C_B \right\rceil_{p'} \approx s_A \cdot m_\text{blind} \cdot s_B \in \mathcal R_q$$
$$K_B = \left\lfloor s_B \cdot C_A \right\rceil_{p'} \approx s_B \cdot m_\text{blind} \cdot s_A \in \mathcal R_q$$

Commutativity of $\mathcal R_q$ gives $s_A \cdot m_\text{blind} \cdot s_B = s_B \cdot m_\text{blind} \cdot s_A$, so $K_A \approx K_B$; reconciliation extracts a shared bit-string.

**KDF post-processing.**  The reconciled raw key $K$ is passed through NL-FSCX v1 with a rotated seed:

$$seed = \text{ROL}(K,\; n/8), \qquad sk = \text{NL-FSCX-REVOLVE}_{v1}(seed,\; K,\; n/4)$$

**Rationale.**  The original KDF, $sk = \text{NL-FSCX-REVOLVE}(K, K, n/4)$, suffered a first-step degeneracy: when $A_0 = B = K$, $\text{FSCX}(K, K) = K \oplus K \oplus \ldots = 0$, so the first step reduces to a pure rotation,

$$A_1 = \text{ROL}((K + K) \bmod 2^n,\; n/4) = \text{ROL}(K \ll 1,\; n/4),$$

which is linear in $K$.  Non-linearity accumulates only from step 2 onward.

Setting $seed = \text{ROL}(K, n/8) \neq K$ ensures $\text{FSCX}(seed, K) = M(seed \oplus K) \neq 0$ from the very first step, so full integer-carry non-linearity is active throughout all $n/4$ steps.  The single-pass structure is preserved — a second bijective pass (NL-FSCX v2) would not add one-wayness since it is invertible for fixed $K$.

#### 11.4.3 Security

**Hardness.** The blinding polynomial $a_\text{rand}$ is fresh per session, making $m_\text{blind}$
uniformly random in $\mathcal{R}_q$.  The key-exchange problem then reduces to the
**Ring-LWR (Learning With Rounding)** problem on $\mathcal{R}_q$, which is a standard
Ring-LWE/LWR instance over a power-of-two cyclotomic ring — the same structure as Kyber.
This is believed post-quantum hard; no polynomial-time quantum algorithm is known.

**Naive algebraic attack analysis.**  Without blinding ($m_\text{blind} = m$), Eve computes
$m^{-1} \cdot (C \cdot q/p) \bmod q$ attempting to recover $s$.  The attack fails because
rounding noise $\delta$ (bounded by $q/(2p)$ per coefficient) is amplified by $\|m^{-1}\|_1 \gg q$
before any wrap-around threshold is crossed.  (Verified with $q = 769$, $n = 16$, 200 trials per
$p$ — see `SecurityProofsCode/hkex_nl_verification.py` §2.2.)

| $p$ | $q/p$ | $\|m^{-1}\|_1 \cdot q/(2p)$ | Wraps mod $q$? | Attack success |
|-----|-------|------------------------------|----------------|----------------|
| 4   | 192   | $\approx 73\,728$            | Yes            | 0/200 |
| 64  | 12    | $\approx 14\,922$            | Yes            | 0/200 |
| 256 | 3     | $\approx 3\,730$             | Yes            | 0/200 |

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
| $m(x)$ invertible, $q = 65537$, $n = 32$ | Yes; $\|m^{-1}\|_\infty = 31\,833$, $\|m^{-1}\|_1 = 536\,649$ | Verified in `hkex_nl_verification.py` §2.1 |
| $m(x)$ invertible, $q = 65537$, $n = 256$ | Yes; $\|m^{-1}\|_\infty = 32\,640$, $\|m^{-1}\|_1 = 4\,286\,173$ | Verified in `hkex_nl_verification.py` §2.1 |
| Noise amplification $\|m^{-1}\|_1 \cdot q/(2p)$ for deployed params ($q=65537$, $n=32$, $p=4096$) | $\approx 4\,293\,192 \gg q$ | Wraps mod $q$ — structural protection holds |
| Naive attack: exact $s$ recovery (fixed $m$, $q=769$, $n=16$, $p \in \{4…256\}$) | 0/200 for every $p$ value | Rounding noise too large for naive inversion |
| Noise amplification $\|m^{-1}\|_1 \cdot q/(2p)$ vs. $q$ | Exceeds $q$ for all tested $(q,p)$ | Structural protection against naive inversion |
| Blinded $m$ vs. fixed $m$ (naive attack) | Both 0/200 | Blinding adds standard Ring-LWR hardness beyond structural noise protection |
| **Key-agreement failure rate** ($q=65537$, $n=32$, $p=4096$, $\eta=1$), 10 000 trials | **204 / 10 000 = 2.04%** (95% CI: 1.78–2.34%) | Fails the <1% threshold; reconciliation hints required. Single-bit errors dominate (201/204). `hkex_rnl_failure_rate.py` §1 |
| **Key-agreement failure rate** ($q=65537$, $n=256$, $p=4096$, $\eta=1$), 5 000 trials | **1 862 / 5 000 = 37.24%** (95% CI: 35.9–38.6%) | Completely unusable without reconciliation. Per-coeff error accumulates as $O(\sqrt{n})$ via ring convolution. `hkex_rnl_failure_rate.py` §3 |
| Max per-coeff error $\|e_A - e_B\|_\infty$ ($n=32$, 10 000 trials) | 134 (0.82% of extraction threshold 16 384) | Individual errors are tiny; failures occur only near extraction boundaries. §2 |
| $p$-sensitivity at $n=32$: failure rate vs. $p \in \{512,\ldots,8192\}$ | 14.7% → 8.45% → 4.4% → 2.2% → 0.80% | No tested $p$ achieves <1%; architectural fix (reconciliation hints) required. §4 |

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
- KDF: $\text{seed} = \text{ROL}(K_\text{raw},\; n/8)$; $sk = \text{NL-FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{v1}(\text{seed},\; K_\text{raw},\; n/4)$

*Algebraic verification.* Invertibility of $m(x)$ in $\mathbb{Z}_q[x]/(x^n+1)$ confirmed for
$(q=65537, n \in \{32, 256\})$ by `hkex_nl_verification.py` §2.1.  Noise amplification
$\|m^{-1}\|_1 \cdot q/(2p) \approx 4.3\times10^6 \gg q$ confirms structural protection against
naive algebraic inversion (§11.4.3, §11.5 Q2).

**⚠ Correctness warning — reconciliation hints required.**
Empirical failure-rate measurement (`hkex_rnl_failure_rate.py`, v1.5.15) shows:

| Parameters | Failure rate | 95% CI |
|---|---|---|
| $n=32$, $p=4096$, $\eta=1$, 10 000 trials | **2.04%** | 1.78–2.34% |
| $n=256$, $p=4096$, $\eta=1$, 5 000 trials | **37.24%** | 35.9–38.6% |

Root cause: the per-coefficient error in $K_\text{poly}$ accumulates as $O(\sqrt{n})$ via ring
convolution over $n$ terms (each CBD(1) coefficient × rounding noise $\leq q/(2p) = 8$).
Although individual errors are tiny ($\leq 134$ out of extraction threshold 16 384), extraction
boundaries at $q/4$ and $3q/4$ are crossed frequently when 256 error terms accumulate.
Increasing $p$ alone does not fix the problem: a p-sensitivity sweep at $n=32$ shows 0.80%
failure rate even at $p=8192$.  The $n=256$ case requires architectural correction.

**Required fix:** NewHope-style 1-bit reconciliation hints.  Each party transmits one hint bit per
ring coefficient indicating which side of the nearest extraction boundary their value lies on;
the other party uses the hint to resolve near-boundary cases.  This reduces the failure rate to
effectively zero without changing the security assumptions.  Planned in TODO.md item #13.

**Status.** The NL-FSCX primitives and HKEX-RNL were implemented across all languages in v1.5.0.
The CBD(η=1) secret sampler was deployed in v1.5.3.  Correctness failure characterised in v1.5.15.
Reconciliation hints are required before production use.

---

### 11.7 Protocol-Level Quantum Security Summary

| Protocol | Security assumption | Classical attack | Quantum attack | Post-quantum security |
|----------|---------------------|------------------|----------------|-----------------------|
| **HKEX-GF** | DLP in $\mathbb{GF}(2^n)^*$ | Quasi-polynomial (Barbulescu 2013) | Shor's DLP | **None** |
| **HSKE** (key-only) | Exhaustive search | Brute force $2^n$ | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE** (known-plaintext) | — | 1 KPT pair → full $c_K$, $O(n^2)$ | BV: 1 query | **None** |
| **HPKS** | DLP in $\mathbb{GF}(2^n)^*$ + non-ROM challenge | Quasi-polynomial DLP | Shor's DLP | **None** |
| **HPKE** | CDH in $\mathbb{GF}(2^n)^*$ | CDH $\leq$ DLP, quasi-polynomial | Shor's CDH | **None** |
| **HSKE-NL-A1** (§11.3.1, key-only) | NL-FSCX v1 PRF | Brute force $2^n$ (linear recovery blocked) | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE-NL-A1** (known-plaintext) | — | Linear recovery blocked; 1-pair attack still recovers keystream | BV inapplicable (non-affine) | **None** (keystream recoverable) |
| **HSKE-NL-A2** (§11.3.2, key-only) | NL-FSCX v2 bijection | Brute force $2^n$ (linear recovery blocked) | Grover $2^{n/2}$ | $n/2$ bits |
| **HSKE-NL-A2** (known-plaintext) | — | Linear recovery blocked; 1-pair attack still recovers keystream | BV inapplicable (non-affine) | **None** (keystream recoverable) |
| **HPKS-NL** (§11.2.1) | DLP in $\mathbb{GF}(2^n)^*$ + NL challenge | Quasi-polynomial DLP; challenge non-predictable | Shor's DLP | **None** |
| **HPKE-NL** (§11.2.2) | CDH in $\mathbb{GF}(2^n)^*$ + NL-FSCX v2 | CDH $\leq$ DLP, quasi-polynomial | Shor's CDH | **None** |
| **HKEX-RNL** (§11.4) | Ring-LWR with blinded $m$ | No known sub-exponential attack | No known polynomial-time quantum attack | Conjectured — pending proof |

**HSKE key-only** provides $n/2$ bits of post-quantum security only when no plaintext
is ever observed.  In any realistic deployment, plaintexts are available and this bound
does not apply.  The NL-FSCX counter-mode and revolve-mode HSKE variants (§11.3) preserve
the same KPT vulnerability; they harden against linear key-recovery but do not eliminate
the 1-pair attack because the underlying structure remains affine.
