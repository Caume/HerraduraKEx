# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §6 (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §6 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).  Peikert 1-bit reconciliation deployed in v1.5.16 (§11.4.2, §11.6) — HKEX-RNL correctness now guaranteed.  HFSCX-256 Merkle-Damgård hash finalizer added to stern_hash in v1.6.0 (§11.9); domain-separation parameter added in v1.6.1 (§11.8.4, Theorem 17).  KDF domain constant `_RNL_KDF_DC` added in v1.8.0.  stern_gen_perm PRNG bias eliminated in v1.8.1; H-matrix precomputed once per sign/verify in v1.8.2.  N=128 HPKS-Stern-F implemented in v1.8.7.  Davies-Meyer feed-forward deployed in v1.9.0 (renamed HFSCX-256-DM, §11.9.8).
**Last updated:** 2026-06-04 (v1.9.0)

> **This is Part 1 of a split document.**
>
> - **Part 1 — §1** (this file): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (SecurityProofs-6.md): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.20** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections

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

#### 1.2.1 Non-Byte-Aligned $n$ (TODO #204)

Every implementation in this suite assumes $n$ is a power of 2 (32/64/128/256/...), driven by byte-oriented word types in C/Go/Python and `herradura.h`'s fixed-width big-int backing. `SecurityProofsCode/hkex_non_byte_key_length_analysis.py` investigates whether a non-byte-aligned $n$ (e.g. $n=251$, $255$, $509$ — primes or other irregular sizes) offers any efficiency or security advantage. Two findings sharpen Theorems 2–3 above:

- **Theorem 2 restated:** the proof only actually needs $\gcd(3, n) = 1$, not $n = 2^k$ specifically — but that means invertibility is **not** guaranteed for an arbitrary non-byte $n$. $n=255 = 3 \cdot 5 \cdot 17$ is divisible by 3, so $M$ is singular at $n=255$: FSCX is not even well-defined there, despite 255 being the most natural odd neighbor of the default $n=256$.
- **Theorem 3 does not generalize:** its proof exponentiates by $t = n/2 = 2^{k-1}$ via the Frobenius identity, which requires $t$ itself to be a power of 2. For the invertible non-byte $n$ the script samples, the empirical order of $M$ is $n$, not $n/2$ (or exceeds the script's $8n$-iteration search bound entirely) — every downstream claim keyed to order$(M) = n/2$ would need independent re-derivation per non-power-of-2 $n$.

The script's diffusion and throughput comparisons find no offsetting advantage: avalanche differences at matched relative depth are an artifact of the order$(M)$ mismatch above rather than an independent property of non-byte $n$, and every non-Python target's byte/word-aligned state representation would need bit-slicing or a bignum backend for a non-byte $n$ — strictly slower than, and losing the single-instruction ROL/ROR compilation of, today's word-aligned code.

**Recommendation:** do not add non-byte-aligned key-length support; the byte-aligned status quo remains the only supported parameter family. This is a research/analysis conclusion, not itself a wire-format, CLI, or default-parameter change — see `TODO_DONE.md` #204.

---

### 1.3 FSCX\_REVOLVE — Iterated Application

**Definition:**

$$\text{FSCX-REVOLVE}(A, B, k) = f_B^k(A)$$

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

#### 1.3.1 Rank of the Key Map $M \cdot S_i$ (TODO #210)

The affine iteration formula says that the key $B$ reaches the output through exactly one linear map,

$$T_i = M \cdot S_i$$

and through nothing else. Whatever the image of $T_i$ fails to cover is therefore a linear functional of the *input* $A$ that no value of $B$ can influence: for every $\lambda$ in the left kernel of $T_i$,

$$\lambda \cdot f_B^i(A) = \lambda \cdot M^i \cdot A \text{ for every } B$$

So the security of every classical FSCX construction rests on $T_i$ having full rank at the deployed step count. It does not.

**Theorem 4.1 — Co-rank of the key map:** For $n = 2^k$ and $1 \leq i \leq n$,

$$\text{co-rank}(T_i) = \min(n, 2 \cdot (2^{v_2(i)} - 1))$$

where $v_2(i)$ denotes the 2-adic valuation of $i$. In particular $T_i$ is invertible **if and only if $i$ is odd**.

*Proof.* Identify the rotation algebra with $R = \mathbb{GF}(2)\lbrack X \rbrack / (X^n + 1)$, in which $M$ is multiplication by $m(X) = X^{n-1} + 1 + X$. Since $n = 2^k$ we have $X^n + 1 = (X + 1)^n$, so $R$ is local with maximal ideal generated by $Y = X + 1$: every non-zero element has a valuation $v$ (the largest power of $Y$ dividing it), valuations add under multiplication, and an element of valuation $v$ acts with rank $n - v$.

Evaluation at $X = 1$ is reduction modulo $Y$, so an element is a unit exactly when it has an odd number of terms. Then $m(1) = 1$, so $v(m) = 0$ and $M$ is a unit (Theorem 2), while

$$m + 1 = X^{n-1} + X = X (X^{n/2-1} + 1)^2$$

gives $v(m + 1) = 2$, because $X^{n/2-1} + 1 = (X+1)(1 + X + \cdots + X^{n/2-2})$ and that cofactor has $n/2 - 1$ terms, an odd count for $n \geq 8$.

Now write $i = 2^a u$ with $u$ odd. From $(M + I) S_u = M^u + I$ and $v(S_u) = 0$ — the sum $S_u$ has $u$ terms, an odd count — we get $v(M^u + I) = 2$. Squaring is additive in characteristic 2, so $M^i + I = (M^u + I)^{2^a}$ and $v(M^i + I) = 2^{a+1}$. Finally $(M + I) S_i = M^i + I$ gives $v(S_i) = 2^{a+1} - 2$, and $v(T_i) = v(M) + v(S_i) = 2^{a+1} - 2 = 2(2^a - 1)$. $\blacksquare$

Measured directly from the primitive by `SecurityProofsCode/fscx_revolve_corank.py`, which also checks the closed form against 288 parameter pairs:

| $n$ | $i$ | rank $T_i$ | co-rank | note |
|---|---|---|---|---|
| 64 | 16 | 34 | 30 | $i = n/4$ (encrypt) |
| 64 | 48 | 34 | 30 | $r = 3n/4$ (decrypt) |
| 128 | 32 | 66 | 62 | $i = n/4$ |
| 256 | 64 | 130 | **126** | $i = n/4$, the deployed encrypt parameter |
| 256 | 192 | 130 | **126** | $r = 3n/4$, the deployed decrypt parameter |
| 256 | 65 | 256 | 0 | odd step count |

Every supported parameter set uses $i = n/4$, which is even for all of them — hence the deployed configuration is never the invertible one. The other direction of the theorem is stronger than it looks: at odd $i$ the key map is invertible and one-time HSKE becomes Shannon-perfect. That is §1.3.2 (Theorem 4.2, TODO #211).

**The visible special case is parity.** $M$ has row weight 3, so multiplication by $M$ preserves the parity (Hamming weight modulo 2) of its argument and

$$\text{parity}(\text{FSCX}(A,B)) = \text{parity}(A) \oplus \text{parity}(B)$$

Iterating an even number of times cancels the key contribution: $\text{parity}(f_B^i(A)) = \text{parity}(A)$ for every $B$ whenever $i$ is even. This is the $\lambda = (1,1,\ldots,1)$ member of the 126-dimensional kernel, and it holds in 200/200 trials at $n = 256$, $i = 64$.

**Consequences at $n = 256$.** HSKE ($E = f_K^{n/4}(P)$, `herradura.h`'s `hske_encrypt`) and HPKE ($E = f_{\text{enc-key}}^{n/4}(P)$) both disclose the same 126 independent linear functionals of the plaintext from the ciphertext alone — with no known plaintext, no chosen plaintext, and no key recovery. For HPKS the challenge $e = f_{\text{msg}}^{n/4}(R)$ lies in an affine subspace of dimension 130, so it carries 130 bits of entropy rather than 256 and its remaining 126 coordinates are a public function of $R$.

The non-linear replacements are outside this argument entirely: NL-FSCX's carry chain breaks the affine identity that the whole derivation rests on. Whether any *statistical* remnant survives on the same subspace is a separate question, measured under TODO #214.

---

#### 1.3.2 Perfect Secrecy at Odd $i$ (TODO #211)

Theorem 4.1 is usually read as a negative result, but its other direction is the strongest positive statement anywhere in this suite. An invertible key map is exactly the hypothesis Shannon's theorem needs, and Theorem 4.1 says precisely when we have one.

**Theorem 4.2 — The leak is the mutual information:** Let $n = 2^k$, let $P$ and $K$ be independent and uniform on $\mathbb{GF}(2)^n$, and let $E = f_K^i(P)$. Then

$$I(P; E) = \text{co-rank}(T_i) = \min(n, 2(2^{v_2(i)} - 1)) \text{ bits}$$

*Proof.* $E = M^i \cdot P \oplus T_i \cdot K$. Since $M$ is a unit and $P$ is uniform, $E$ is uniform, so $H(E) = n$. For fixed $P = p$, the map $K \mapsto M^i p \oplus T_i K$ pushes the uniform distribution onto the uniform distribution on the coset $M^i p + \text{im}(T_i)$, which has $2^{\text{rank}(T_i)}$ elements, so $H(E \mid P) = \text{rank}(T_i)$. Then $I(P;E) = H(E) - H(E \mid P) = n - \text{rank}(T_i)$, and Theorem 4.1 evaluates that. $\blacksquare$

**Corollary 4.3 — One-time HSKE is Shannon-perfect exactly when $i$ is odd:** Under the hypotheses of Theorem 4.2, $I(P;E) = 0$ if and only if $i$ is odd, in which case $E$ is uniform and statistically independent of $P$ — Shannon's condition for perfect secrecy, the same one the one-time pad satisfies.

So the 126-bit leak of §1.3.1 and the perfect secrecy here are not two findings but one quantity read at two parities. `SecurityProofsCode/hske_perfect_secrecy.py` measures the mutual information exhaustively over all 65 536 plaintext-key pairs at `n = 8` and reproduces the co-rank exactly for every step count, including the degenerate $i = n$ where $T_n = 0$, the ciphertext equals the plaintext, and the mutual information is the full `n` bits.

**The hypotheses are load-bearing, and one of them fails catastrophically.** Corollary 4.3 needs the key uniform, as wide as the message, and **used once**. The third is not a formality. Two messages under one key give

$$E_1 \oplus E_2 = M^i \cdot (P_1 \oplus P_2)$$

and $M$ is invertible with $M^{-i} = M^{n-i}$, so an eavesdropper recovers the XOR of the two plaintexts from the two ciphertexts with no key material whatsoever — the classical two-time-pad break, reproduced 200/200 at `n = 256`, `i = 65`. HSKE carries no nonce and no integrity check, so nothing in the wire format detects or prevents reuse.

**What the result is worth.** An odd step count does not make HSKE stronger than a one-time pad; it makes it exactly as strong, at `n` rotate-XOR rounds instead of a single XOR (roughly 700 times the cost in the reference Python), and with the same key-as-long-as-the-message burden that makes the pad impractical. This is a ceiling, not a feature: a linear map over $\mathbb{GF}(2)$ applied to an independent uniform key cannot beat the pad, and Theorem 4.1 identifies which step counts fail even to match it.

The usable conclusion is therefore about the parameter rather than the protocol. Correctness constrains only $i + r = n$, so the total work is the same at every choice — the deployed `(64, 192)` and the perfect `(65, 191)` both cost 256 steps and both round-trip 500/500. An even step count buys nothing anywhere in exchange for the bits it leaks; there is no setting in which it is the preferable choice.

**Why this is documented rather than deployed.** Changing the step count changes what every existing HSKE and HPKE ciphertext decrypts to, which is a wire-format break under the versioning rules in `CLAUDE.md`. The symmetric-ciphertext PEM records a format tag and `nbits` but no step count, so a build using an odd step count would decrypt an old ciphertext to silent garbage — HSKE has no integrity check to catch it. Any adoption therefore needs its own format tag (the tag mechanism already distinguishes the plain, nonce-carrying, and AEAD layouts) plus a `MIGRATING.md` entry, and is left to a future major version rather than taken here.

---

### 1.4 FSCX\_REVOLVE\_N — Nonce-Augmented Variant

**Definition (v1.1):**

$$\text{FSCX-REVOLVE-N}(A, B, N, k) :
\begin{cases}
X_0 = A \\
X_{j+1} = \text{FSCX}(X_j, B) \oplus N = M \cdot X_j \oplus M \cdot B \oplus N
\end{cases}$$

This is the affine map $g_{B,N}(X) = M \cdot X + (M \cdot B \oplus N)$ with translation $c = M \cdot B \oplus N$. The closed-form iteration formula is:

$$\text{FSCX-REVOLVE-N}(A, B, N, k) = M^k \cdot A + M \cdot S_k \cdot B \oplus S_k \cdot N$$

**Theorem 5 — Period still divides $n$:**

$$g^n_{B,N}(A) = M^n \cdot A + S_n \cdot (M \cdot B \oplus N) = A + 0 = A$$

The nonce $N$ does not affect the period, and decryption is the complementary revolve.

**Nonce propagation linearity:** If $N$ changes by $\delta N$, the change in $\text{FSCX-REVOLVE-N}(\cdot, B, N, k)$ at step $k$ is:

$$\delta\text{Output} = S_k \cdot \delta N = (I + M + M^2 + \cdots + M^{k-1}) \cdot \delta N$$

For $k = n$ this is $S_n \cdot \delta N = 0$, so nonce changes are fully absorbed over a full cycle. The Hamming distance of a single-bit nonce flip is deterministic (independent of $A$ and $B$) and equals $\text{popcount}(S_k \cdot e_j)$. Empirically, $\text{HD} = n/4$ for $k = i = n/4$.

---

### 1.5 Machine-Checked Verification (Z3/SMT)

The proofs in §1.1–§1.4 are hand-written. This subsection reports **mechanically verified** confirmation of the two central claims — FSCX periodicity (Theorems 2–4, Corollary 1) and the HPKS Schnorr verification identity (§2.3) — using the Z3 SMT solver. These are separate, distinct checks from the hand proofs above: they do not replace the algebraic argument, but they close the gap between "the algebra says this holds" and "a solver confirmed no counterexample exists at the bit level, for the exact rotate/XOR/field operations the C implementation uses."

**Toolchain note:** Cryptol and F\* (the more typical formal-verification languages for this kind of claim) do not ship prebuilt binaries for aarch64 Linux and were not installed. Z3's Python bindings (`python3-z3`) are packaged for `arm64` and were used directly instead — the claims below are expressed as bitvector satisfiability queries (`UNSAT` of the negation of the claim over free symbolic variables, which establishes validity for *every* input at that bit width, not a sampled subset).

**FSCX periodicity — `SecurityProofsCode/fscx_periodicity_z3.py`.** Encodes $M(x) = x \oplus \text{ROL}(x,1) \oplus \text{ROR}(x,1)$ directly as Z3 bitvector rotations and proves, for every power-of-two width $n \in \{8, 16, 32, 64, 128, 256\}$ — including the deployed $n = 256$ — via `UNSAT` of the negation over a free symbolic bitvector:

- Theorem 2 ($M$ invertible): $M(x) = 0 \implies x = 0$, for all $x$.
- Theorem 3 ($M$ has order $n/2$): $M^{n/2}(x) = x$, for all $x$.
- Corollary 1 ($S_n = 0$): $\bigoplus_{j=0}^{n-1} M^j(x) = 0$, for all $x$.
- Theorem 4 (period divides $n$): iterating `FSCX_REVOLVE`$(A, B, n)$ returns $A$, for all $A, B$.

All twenty-four queries (four theorems times six widths) return `PROVED`. A supplementary empirical pass measures the *minimal* orbit period for random $(A, B)$ pairs at each width and confirms it is always exactly $n$ or $n/2$ — this narrower claim (stated as an empirical observation, not a proof, in §1.3) is not given a formal proof here either; only Theorem 4's weaker "period divides $n$" bound is machine-proved.

**HPKS Schnorr identity — `SecurityProofsCode/hpks_schnorr_z3.py`.** Encodes `gf_mul`/`gf_pow` (§2.1's square-and-multiply, same structure as `SecurityProofsCode/hkex_gf_test.py`) as Z3 bitvector circuits and checks $g^s \cdot C^e = R$ where $C = g^a$, $R = g^k$, $s = (k - a \cdot e) \bmod \text{ord}$:

- **$n = 4$:** fully symbolic `UNSAT` proof — holds for every $(a, k, e)$ triple at this width.
- **$n = 8$:** the fully symbolic query does not terminate in reasonable time (the modular exponent reduction is nonlinear bitvector arithmetic that blows up general-purpose SMT search); instead every $(a, e)$ pair is enumerated by direct computation against six representative $k$ values (0, 1, near-midpoint, near-max, max) — 393,216 cases, all pass.
- **$n \in \{32, 64, 256\}$:** 200 random $(a, k, e)$ triples each, including the deployed $n = 256$ with `herradura.h`'s actual `GF_POLY` — all pass.

Only the $n = 4$ result is a formal SMT proof in the strict sense; the $n = 8$ pass is complete enumeration over $(a,e)$ (not full case enumeration including $k$), and the $n \geq 32$ passes are randomized sampling, not exhaustive. The identity itself is a property of exponent arithmetic in any group of order $\text{ord}$ (it holds independent of field size once $g^{\text{ord}} = 1$, which follows from Lagrange's theorem), so the $n=4$ proof and the larger-width spot checks together corroborate that the same code path behaves consistently from the fully-verified case up to the deployed width.

---

> **Continued in Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
