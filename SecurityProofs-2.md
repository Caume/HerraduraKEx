# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 2

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 2 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (this file): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.22** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections

---

## 2. Protocol Analysis

### 2.1 HKEX — Key Exchange

**Protocol:**

$$\begin{aligned}
&\textbf{Alice:}\quad A, B \leftarrow \text{random};\quad C = \text{FSCX-REVOLVE}(A, B, i) \\
&\textbf{Bob:}\quad A_2, B_2 \leftarrow \text{random};\quad C_2 = \text{FSCX-REVOLVE}(A_2, B_2, i)
\end{aligned}$$

$$\text{Alice} \xrightarrow{C} \text{Bob} \qquad \text{Bob} \xrightarrow{C_2} \text{Alice}$$

$$\begin{aligned}
&\textbf{Alice:}\quad sk_A = \text{FSCX-REVOLVE-N}(C_2, B, N, r) \oplus A \\
&\textbf{Bob:}\quad sk_B = \text{FSCX-REVOLVE-N}(C, B_2, N, r) \oplus A_2 \\
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

$$\text{Encrypt:}\quad E = \text{FSCX-REVOLVE-N}(P, K, K, i)$$
$$\text{Decrypt:}\quad D = \text{FSCX-REVOLVE-N}(E, K, K, r)$$

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

> **Why HSKE is not broken the way HKEX is:** HSKE is a *symmetric* cipher, not a key exchange. Both parties share $K$ before communication; $K$ never appears on the wire. The offset $c_K = S_i \cdot (M+I) \cdot K$ in $E$ is a non-zero private additive term. Unlike HKEX, there is no step at which private parameters must cancel from the ciphertext itself — only from the round-trip $D = P$, which they do via $S_n = 0$.
>
> **Correction (TODO #210):** a non-zero offset is necessary but not sufficient. $c_K$ is confined to the image of the key map, and by Theorem 4.1 (§1.3.1) that image is a proper subspace at every deployed step count — co-rank 128 for this nonce-augmented map $S_i \cdot (M + I)$, and 126 for the map $T_i = M \cdot S_i$ that the shipped `hske_encrypt` actually uses. The complement is unmasked: 126 linear functionals of $P$ are readable from $E$ alone, for every key. See W9 in §4.2.

---

### 2.3 HPKS₂ — Public Key Signature

**Protocol** (Alice signs plaintext $P$):

$$\begin{aligned}
&\text{Public key:}\quad (C, B_2, A_2, r) \\
&\text{Private key:}\quad (C_2, B, A)
\end{aligned}$$

The original scheme used $S = sk_A \oplus P$ (a direct XOR mask), which trivially leaks $sk_A$ (see W3). The corrected scheme **HPKS₂** replaces the XOR with HSKE encryption of $P$ under $sk_A$:

$$\begin{aligned}
&\textbf{Alice:}\quad S = \text{FSCX-REVOLVE-N}(P, sk_A, sk_A, i) \quad [\text{HSKE-encrypt } P \text{ under } sk_A] \\
&\textbf{Bob:}\quad V = \text{FSCX-REVOLVE-N}(S, sk_B, sk_B, r) \quad [\text{HSKE-decrypt } S \text{ under } sk_B] \\
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
&\textbf{Bob:}\quad E = \text{FSCX-REVOLVE-N}(C, B_2, N, r) \oplus A_2 \oplus P \\
&\textbf{Alice:}\quad D = \text{FSCX-REVOLVE-N}(C_2, B, N, r) \oplus A \oplus E
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

**The proposal:** Replace the public-key computation $C = \text{FSCX-REVOLVE}(A, B, i)$ with the nonce-augmented variant $C = \text{FSCX-REVOLVE-N}(A, B, \Phi, i)$:

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

*Proof.* Applying the affine iteration formula for $\text{FSCX-REVOLVE-N}$ and substituting $A = M^r \cdot C \oplus M^{r+1} \cdot S_i \cdot B$:

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

### 3.7 M as a Linear Diffusion Layer — Branch Number and Diffusion Depth

Although M cannot serve as the sole building block of a secure key exchange (§3.6), it is a well-defined $\mathbb{GF}(2)$-linear map that can be evaluated independently as a **diffusion layer** in the SPN sense (Daemen–Rijmen).  This section characterises its branch number and avalanche depth, providing the foundation for the NL-FSCX security arguments in §11.

**Setup.** M = I XOR ROL XOR ROR is a 3-tap circulant map over $\mathbb{GF}(2)^n$.  Define:

$$M^t(x) = M \text{ applied } t \text{ times to } x$$

$$S_t(x) = M(x) \oplus M^2(x) \oplus \cdots \oplus M^t(x)$$

The fscx-revolve map decomposes linearly as:

$$\text{fscx-revolve}(A, B, t) = M^t(A) \oplus S_t(B)$$

so the A-input influence on the output is governed by $M^t$ and the B-input influence by $S_t$.

**Definition (Branch Number, Daemen–Rijmen).** For a $\mathbb{GF}(2)$-linear map $L$:

$$\text{Bn}_d(L) = \min_{a \neq 0}\bigl(\text{wt}(a) + \text{wt}(L(a))\bigr), \qquad \text{Bn}_l(L) = \min_{a \neq 0}\bigl(\text{wt}(a) + \text{wt}(L^T(a))\bigr)$$

A higher branch number forces any differential or linear trail through the layer to activate more bits, increasing trail complexity.

**Theorem 11 (M is self-transposed).** $M = M^T$ as a $\mathbb{GF}(2)$-matrix for all $n$.

*Proof.* M is a symmetric circulant: its first row is $e_0 \oplus e_1 \oplus e_{n-1}$ (by definition of ROL/ROR by 1), and every subsequent row is a cyclic shift of the first.  A circulant matrix over $\mathbb{GF}(2)$ is symmetric iff its generating row is a palindrome.  The row $1 \oplus x \oplus x^{n-1}$ satisfies this since $x \leftrightarrow x^{n-1}$ under reversal.  Therefore $M = M^T$ and $\text{Bn}_d = \text{Bn}_l$ for all powers of M. $\blacksquare$

**Measured branch numbers** (exhaustive at $n \leq 16$; sampled $5 \times 10^5$ random inputs at $n = 32, 64$):

| $n$ | $k$ | $\text{Bn}(M^k)$ | note |
|---|---|---|---|
| 16 | 1 | 4 | exhaustive |
| 16 | 3,5 | 6 | exhaustive |
| 32 | 1 | 10 | sampled lower bound |
| 32 | 3,5 | 12 | sampled lower bound |
| 64 | 1 | $\geq 36$ | sampled lower bound |
| 64 | 5 | $\geq 38$ | sampled lower bound |

For comparison, ASCON's rotation-based linear layers (also 3-tap circulants) have $\text{Bn}(\Sigma_0) = 34$ and $\text{Bn}(\Sigma_1) = 38$ at $n = 64$.  FSCX's M with $\text{Bn} \geq 36$ is structurally comparable.

**Theorem 12 (S_t periodicity).** $S_{n/2}(x) = 0$ for all $x$ and all $n = 2^k$.

*Proof.* M has order $n/2$ (proven in §1: $M^{n/2} = I$).  Therefore $M^1, M^2, \ldots, M^{n/2}$ form a complete cycle.  In $\mathbb{GF}(2)$, each non-identity element appears exactly once in $\{M^j : 1 \leq j \leq n/2\}$, and the identity $I = M^{n/2}$ appears once.  Summing all elements of the cyclic group $\langle M \rangle$ in $\mathbb{GF}(2)$ gives zero (each basis vector is covered an even number of times through the orbit structure).  Hence $S_{n/2} = 0$ and the B-influence is periodic with period dividing $n/2$. $\blacksquare$

**Corollary 3.** Complete diffusion of B (all output bits depend on all B input bits via $S_t$) is never achieved for $n = 2^k$, since $S_{n/2} = 0$ causes the B-influence to collapse before reaching the all-ones matrix.

**Diffusion trajectory** (minimum row weight of $M^t$ and $S_t$; computed by `SecurityProofsCode/fscx_branch_number.py`):

| $n$ | $t$ | $\text{min-wt}(M^t)$ | $\text{mean-wt}(M^t)$ | $\text{min-wt}(S_t)$ | $\text{mean-wt}(S_t)$ |
|---|---|---|---|---|---|
| 32 | 1 | 3 | 3.0 | 3 | 3.0 |
| 32 | 4 | 3 | 3.0 | 5 | 5.0 |
| 32 | **8** (= $n/4$) | 3 | 3.0 | 10 | 10.0 |
| 32 | 15 | 21 | 21.0 | 17 | 17.0 |
| 32 | 16 | 1 | 1.0 | 16 | 16.0 |
| 64 | **16** (= $n/4$) | 3 | 3.0 | 18 | 18.0 |
| 64 | 31 | 43 | 43.0 | 33 | 33.0 |

**A,B-half-coverage threshold.** Define $t_{1/2}(n)$ as the smallest $t$ such that $\text{min-wt}(M^t) \geq n/2$ and $\text{min-wt}(S_t) \geq n/2$ simultaneously.  Empirically: $t_{1/2}(16) = 7$, $t_{1/2}(32) = 15$, $t_{1/2}(64) = 31$ — following the pattern $t_{1/2}(n) = n/2 - 1$.

**Assessment of the suite heuristic $i = n/4$.**

At step $i = n/4$, the B-influence $S_{n/4}$ has mean row weight $n/4$ and minimum row weight $\approx n/4 + 2$.  The A-influence $M^{n/4}$ is a sparse circulant with minimum row weight 3 (the taps of $M$ do not widen significantly due to the GF(2) cancellations in a 3-tap circulant).

The heuristic $i = n/4$ therefore provides:
- **B-input**: approximately 25–30% mean activation per output bit from B at step $n/4$, growing to $\sim 50$% at $n/2 - 1$ steps.
- **A-input**: M is invertible (order $n/2$), so A is always recoverable; the diffusion is limited but sufficient for correctness.
- The choice $i = n/4$ sits at the midpoint before the S_t collapse (Theorem 12), capturing the B-influence before it starts contracting toward zero.

For the symmetric protocols (HSKE, HPKE), security depends on the non-linearity of the integer-carry chain in NL-FSCX rather than on M's diffusion alone.  The revolve count provides avalanche coverage, not indistinguishability by itself.  The NL-FSCX analysis is in §11.

**FSCX-SPN sketch.** An explicit SPN construction alternating the NL-FSCX v1 non-linear step with M provides a principled round structure:

- **Round $r$:** $\text{state} \leftarrow \text{nl-fscx-v1}(\text{state}, K_r, n/4)$ then $\text{state} \leftarrow M(\text{state})$
- **Recommended minimum rounds:** $t_{1/2}(n) = n/2 - 1$ for single-pass security; $2 \times t_{1/2}(n)$ for multi-round trail resistance.
- **Key schedule:** independent round constants $K_0, \ldots, K_{r-1}$ derived from the master key; details are deferred to the #95/#96 analysis.

This construction is the analysable successor to the ad-hoc revolve idiom and provides the diffusion foundation for the sponge-permutation (#95) and DRBG (#96) constructions.

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

**W9 — The key map is singular: HSKE and HPKE ciphertexts leak 126 plaintext bits (TODO #210).**

By Theorem 4.1 (§1.3.1) the key enters `fscx_revolve` only through $T_i = M \cdot S_i$, whose co-rank is $2(2^{v_2(i)} - 1)$ — equal to 126 out of 256 at the deployed $i = n/4 = 64$. Every $\lambda$ in the 126-dimensional left kernel satisfies

$$\lambda \cdot E = \lambda \cdot M^i \cdot P$$

identically in the key, so 126 independent linear functionals of the plaintext are readable from the ciphertext alone. Unlike W2–W5, this needs no public-key material, no known plaintext, and no chosen plaintext: it is a property of the step count. Choosing an odd $i$ makes $T_i$ invertible and removes the leak entirely (TODO #211).

---

## 5. Summary Tables

### 5.1 Protocol Security Status

| Protocol | Correctness | Classical Break | IND-CPA | IND-CCA2 | EUF-CMA | Status (v1.4.0) |
|---|---|---|---|---|---|---|
| HKEX (old) | ✓ Proven | **BROKEN** (Thm. 7) | ✗ | — | — | **Removed** |
| HKEX-GF | ✓ Proven (field comm.) | CDH in GF(2ⁿ)* | Unproven | — | — | **Active** |
| HSKE | ✓ Proven | N/A (pre-shared key) | ✗ (W9, §1.3.1) | ✗ (malleable) | — | Active |
| HPKS₂ | ✓ Proven | N/A (sk via HKEX-GF) | — | — | Unproven | Active |
| HPKE | ✓ Proven | N/A (sk via HKEX-GF) | ✗ (W9, §1.3.1) | ✗ (malleable) | — | Active |

---

### 5.2 Break and Impossibility Results

| Claim | Status | Evidence |
|---|---|---|
| $sk = S_{r+1} \cdot (C \oplus C_2)$ — computable from public wire values | **Proved** (Thm. 7) | Algebraic + 10K trials |
| Single public nonce injection does not fix break | **Proved** | Case (a), 2K trials |
| Single private nonce injection breaks correctness | **Proved** | Case (b), 2K trials |
| No nonce (single or multi) can fix HKEX | **Proved** (Thms. 8, 9) | 10+8 strategies, all fail |
| HSKE is correct; the pre-shared-key security claim does **not** hold as stated | **Corrected** (Thm. 4.1) | $T_i$ has co-rank 126 at $i = n/4$ — see W9 |
| One-time HSKE is Shannon-perfect **iff** the step count is odd; mutual information equals co-rank | **Proved** (Thm. 4.2, Cor. 4.3) | Exhaustive $I(P;E)$ at `n=8`; 200/200 two-time-pad break at `i=65` |
| HPKE is correct but publicly insecure | **Proved** | $sk = S_{r+1} \cdot \text{public}$ |
| $n_A = A \oplus C$ gives correctness with probability $2^{-4}$ | **Proved** | Rank-4 condition matrix |
| $N_j = M^j \cdot B$ collapses to $\Phi = 0$ (GF(2) even-sum) | **Proved** | $r$ even $\Rightarrow \Phi_r = 0$ |
| $k$ exchanged public values do not help (any $k$) | **Proved** | Each term linear; $k = 1, 2, 4$ tested |
| Root cause: GF(2)-linearity/correctness–security incompatibility | **Proved** (Thm. 10) | Algebraic; no counterexample exists |
| Quantum attacks: classical break makes them moot | **Proved** | See §6 |
| **HKEX-GF correctness:** $g^{ab} = g^{ba}$ in $\mathbb{GF}(2^n)^{\ast}$ | **Proved** (field commutativity) | Algebraic + 5K/1K trials (Python/C) |
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

$$\text{FSCX-REVOLVE-N}\left(\text{FSCX-REVOLVE}(A_2, B_2, i), B, N, r\right) \oplus A$$
$$=$$
$$\text{FSCX-REVOLVE-N}\left(\text{FSCX-REVOLVE}(A, B, i), B_2, N, r\right) \oplus A_2$$

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
| `hkex_nl_verification.py` | NL-FSCX v1/v2 properties §11.5: period (Q1), FSCX-LWR algebraic attack (Q2), bijectivity / inversion (Q3); HKEX-RNL setup |
| `hkex_rnl_failure_rate.py` | HKEX-RNL key-agreement failure rate §11.5 Q2: 10K trials at $n=32, 256$; Peikert reconciliation 0/10K verification |
| `nl_fscx_prf_analysis.py` | NL-FSCX v1 PRF tests §11.8.4: 2-query distinguisher, BLR, SAC, higher-order differentials, linear bias, key sensitivity, collisions, cross-key independence |
| `hfscx_256_analysis.py` | HFSCX-256-DM hash empirical tests §11.9: SAC on input/key, output uniformity (chi²), length-extension forgery, domain separation, fixed-point search |
| `hfscx_dm_rf_model.py` | HFSCX-256-DM in the ideal-random-function model §11.9.12 (TODO #215): image-collapse propagation from the non-bijective inner map to the Davies-Meyer compression (exhaustive at `n = 16`), DM fixed points under NL-FSCX v1 (search) vs. v2 (one inversion), a working Joux multicollision and an end-to-end Kelsey-Schneier long-message second preimage against the chain, and the corrected bound table at `n = 256` |
| `nl_fscx_exact_trail_search.py` | Exact differential trail bounds for NL-FSCX v1/v2 §11.20 (TODO #214): the Lipmaa-Moriai xdp+ model validated exhaustively, the reduction of both variants to one xdp+ core, SMT trail search giving proven optima and proven lower bounds at power-of-two widths, the rotation-amount table, the fixed-key vs key-averaged gap that the absent key schedule makes load-bearing, and the carry-degenerate key class cross-check |
| `stern_f_multiround_fs.py` | HPKS-Stern-F's round count under multi-round Fiat-Shamir §11.8.8 (TODO #217): a bit-exact pin of the challenge expansion against the deployed one, the avalanche measurement showing the derivation is one-shot and so immune to KZ-style splitting, the mod-3 reduction bias counted exactly, challenge uniformity as six independent chi-square replications with a 99% bound on the forger's gain, cycle/collapse/drift checks on the non-bijective chain, and end-to-end forgery probabilities against `(2/3)^r` at reduced round counts |
| `qcmdpc_dfr_weak_keys.py` | HPKE-Stern-KEM's QC-MDPC BGF decoder §11.8.7 (TODO #218): bit-exact cross-validation of a bit-sliced decoder against the deployed one, DFR at the deployed parameters with a Clopper-Pearson interval, Sendrier-Vasseur DFR(r) fit and extrapolation, distance-spectrum weak-key gradient vs. what keygen emits, and the GJS reaction-attack distinguisher measured to disjoint confidence intervals |
| `hkex_gf_pohlig_hellman.py` | Pohlig–Hellman against HKEX-GF/HPKS/HPKE §9.2.4 (TODO #212): verified factorisation of $2^n - 1$ and $\text{ord}(g)$ per supported $n$, cost table against the documented FFS figures, end-to-end private-key recovery at $n = 32$ and $n = 64$, HKEX-GF shared-secret recovery and HPKS forgery from the recovered key, and the $n = 256$ wall-clock extrapolation |
| `hske_perfect_secrecy.py` | Perfect secrecy at odd step counts §1.3.2 (TODO #211): key-map invertibility vs. parity of the step count for `n` from 32 to 512, round-trip correctness and equal step cost at `(i, r) = (65, 191)`, exhaustive mutual information over all 65 536 plaintext-key pairs at `n = 8` against the predicted co-rank, the Latin-square view, the two-time-pad break under key reuse, and a timing comparison against a literal one-time pad |
| `fscx_revolve_corank.py` | Co-rank of the classical key map §1.3.1 (TODO #210): measured rank of $T_i = M \cdot S_i$ at $n \in \{64, 128, 256\}$, the closed form $2(2^{v_2(i)} - 1)$ checked against 288 parameter pairs, extraction of the 126-dimensional left kernel and its key-independence over 200 random keys, the parity special case, and the co-rank of the nonce-augmented map of §2.2 |
| `sbox_kex_extension.py` | Does the MFSCX result extend to an S-box layer? §11.22 (TODO #230): the scope condition showing TODO #224 is silent on substitution layers, the characterization theorem (agreement iff the composite is a translation) with its universal transcript-only attack verified against `hkex_classical_break.py` at four widths, the linear-box co-rank identity $\dim \ker Y^{2^{v_2(i)}-1}$ giving 126 -> 64 with 64 proved a floor, the Hamming-distance measurement separating "unrelated" from "noisy but reconcilable", and exhaustive small-width searches refuting the affineness conjecture with 15 360 non-affine agreeing permutations |
| `mfscx_kex_analysis.py` | Seed-masked FSCX revolve as a key exchange §11.21 (TODO #224): the static-mask affine decomposition measured at four widths, `hkex_classical_break.py` re-run against static-mask HKEX (10 000 sessions, full recovery), the secret-P-box residue collapsing to one value, co-rank unchanged from TODO #210 against surjectivity of the secret-injection map, two-party agreement destroyed by a state-dependent mask, the generalized injection-schedule impossibility theorem with both halves of its dichotomy exhibited, cycle lengths of the seed-derived schedule against the random-function expectation, and the Merkle-puzzle honest-work table |
| `hkex_non_byte_key_length_analysis.py` | Non-byte-aligned $n$ analysis §1.2.1 (TODO #204): $M$-invertibility via GF(2)[x] poly-gcd vs. the $\gcd(3,n)$ shortcut, empirical order$(M)$, avalanche diffusion, and throughput at sampled non-byte $n \in \{241, 251, 253, 255, 257, 509\}$ vs. byte-aligned baselines |

---

---

> **Continued in Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
