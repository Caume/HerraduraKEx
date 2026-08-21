# Formal Cryptographic Analysis of the Herradura Cryptographic Suite

**Status:** Formal proof of insecurity complete; HKEX-GF fix implemented in v1.4.0.  NL-FSCX non-linearity and PQC extensions implemented in v1.5.0 (§11).  Full quantum algorithm analysis in §6 (merged from PQCanalysis.md, v1.4.1).  Deployed-parameter verification and §6 NL-protocol rows added in v1.5.1.  HKEX-RNL secret sampler upgraded to CBD(eta=1) in v1.5.3 (§11.4.2, §11.6).  HKEX-RNL polynomial multiplication replaced with negacyclic NTT over $\mathbb{Z}_{65537}$ in v1.5.4 (O(n log n), ~32× speedup at n=256).  Peikert 1-bit reconciliation deployed in v1.5.16 (§11.4.2, §11.6) — HKEX-RNL correctness now guaranteed.  HFSCX-256 Merkle-Damgård hash finalizer added to stern_hash in v1.6.0 (§11.9); domain-separation parameter added in v1.6.1 (§11.8.4, Theorem 17).  KDF domain constant `_RNL_KDF_DC` added in v1.8.0.  stern_gen_perm PRNG bias eliminated in v1.8.1; H-matrix precomputed once per sign/verify in v1.8.2.  N=128 HPKS-Stern-F implemented in v1.8.7.  Davies-Meyer feed-forward deployed in v1.9.0 (renamed HFSCX-256-DM, §11.9.8).
**Last updated:** 2026-06-04 (v1.9.0)

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
| `qcmdpc_dfr_weak_keys.py` | HPKE-Stern-KEM's QC-MDPC BGF decoder §11.8.7 (TODO #218): bit-exact cross-validation of a bit-sliced decoder against the deployed one, DFR at the deployed parameters with a Clopper-Pearson interval, Sendrier-Vasseur DFR(r) fit and extrapolation, distance-spectrum weak-key gradient vs. what keygen emits, and the GJS reaction-attack distinguisher measured to disjoint confidence intervals |
| `hkex_gf_pohlig_hellman.py` | Pohlig–Hellman against HKEX-GF/HPKS/HPKE §9.2.4 (TODO #212): verified factorisation of $2^n - 1$ and $\text{ord}(g)$ per supported $n$, cost table against the documented FFS figures, end-to-end private-key recovery at $n = 32$ and $n = 64$, HKEX-GF shared-secret recovery and HPKS forgery from the recovered key, and the $n = 256$ wall-clock extrapolation |
| `hske_perfect_secrecy.py` | Perfect secrecy at odd step counts §1.3.2 (TODO #211): key-map invertibility vs. parity of the step count for `n` from 32 to 512, round-trip correctness and equal step cost at `(i, r) = (65, 191)`, exhaustive mutual information over all 65 536 plaintext-key pairs at `n = 8` against the predicted co-rank, the Latin-square view, the two-time-pad break under key reuse, and a timing comparison against a literal one-time pad |
| `fscx_revolve_corank.py` | Co-rank of the classical key map §1.3.1 (TODO #210): measured rank of $T_i = M \cdot S_i$ at $n \in \{64, 128, 256\}$, the closed form $2(2^{v_2(i)} - 1)$ checked against 288 parameter pairs, extraction of the 126-dimensional left kernel and its key-independence over 200 random keys, the parity special case, and the co-rank of the nonce-augmented map of §2.2 |
| `hkex_non_byte_key_length_analysis.py` | Non-byte-aligned $n$ analysis §1.2.1 (TODO #204): $M$-invertibility via GF(2)[x] poly-gcd vs. the $\gcd(3,n)$ shortcut, empirical order$(M)$, avalanche diffusion, and throughput at sampled non-byte $n \in \{241, 251, 253, 255, 257, 509\}$ vs. byte-aligned baselines |

---


---

> **Continued in Part 2 — §9–§10** (SecurityProofs-2.md): Non-Linear Proposals · v1.4.0 Migration
