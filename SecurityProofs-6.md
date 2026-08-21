# Formal Cryptographic Analysis of the Herradura Cryptographic Suite — Part 6

**Status:** See Part 1 (SecurityProofs-1.md) for full status header.

> **This is Part 6 of a split document.**
>
> - **Part 1 — §1** (SecurityProofs-1.md): Algebraic Foundations
> - **Part 2 — §2–§8** (SecurityProofs-2.md): Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index
> - **Part 3 — §9–§10** (SecurityProofs-3.md): Non-Linear Proposals · v1.4.0 Migration
> - **Part 4 — §11–§11.8.2** (SecurityProofs-4.md): Non-linearity and Post-quantum Extensions · NL-FSCX v1/v2 · HKEX-RNL
> - **Part 5 — §11.8.3–§11.8.8** (SecurityProofs-5.md): PQ Signature Options · HPKE-Stern-KEM
> - **Part 6 — §11.9** (this file): HFSCX-256-DM
> - **Part 7 — §11.10–§11.13, §11.15–§11.20** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections

---

## 11.9 HFSCX-256-DM — Hash function on NL-FSCX v1

HFSCX-256-DM (deployed v1.9.0; originally HFSCX-256 from v1.5.24) is a 256-bit Merkle-Damgård hash built on NL-FSCX v1 with Davies-Meyer feed-forward compression.
It serves three roles in the suite:

- generic digest (the `dgst` subcommand of `HerraduraCli`),
- pre-hash for `sign` / `verify` flows (compresses arbitrary-length messages to a 256-bit input for HPKS / HPKS-NL / HPKS-Stern-F),
- authentication tag for `HSKE-NL-A1-CTR-AEAD` (large-file streaming encryption).

This section formalises the security claims for the deployed Davies-Meyer construction and is backed by `SecurityProofsCode/hfscx_256_analysis.py`.

### 11.9.1 Construction

Let $n = 256$, block size $b = 32$ bytes.  Write $F_1^r(s, m)$ for NL-FSCX v1 iterated $r$ times with state $s$ and message-block parameter $m$.  HFSCX-256-DM takes input bytes $D$ and an optional 256-bit key $K$; it produces a 256-bit digest as follows.

**Compression function (Davies-Meyer).**

$$C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s \in \{0,1\}^{256}.$$

**Initial state.**  Let $\text{IV-const}$ be the 32-byte ASCII constant `HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0` interpreted as a 256-bit integer.  Define

$$s_0 = \begin{cases} \text{IV-const} & \text{(unkeyed)} \cr K \oplus \text{IV-const} & \text{(keyed MAC mode)} \end{cases}$$

**Padding (ISO 7816-4 + finalization).**  Append `0x80` to $D$; zero-fill to a multiple of $b$; append a 32-byte finalization block $\mathit{fin}$:

$$\mathit{fin} = \bigl(8 \cdot |D|\bigr) \oplus s_0 \pmod{2^{256}}.$$

**Iteration.**  For padded message $D' = m_1 \| m_2 \| \cdots \| m_k$ (where the last block is $\mathit{fin}$):

$$s_i = C_{\text{DM}}(s_{i-1}, m_i) = F_1^{64}(s_{i-1}, m_i) \oplus s_{i-1}, \qquad i = 1, \ldots, k.$$

**Output.**  $\text{HFSCX-256-DM}(D, K) = s_k$.

### 11.9.2 Security model and assumptions

The security claims for HFSCX-256-DM are conditional on assumptions already used elsewhere in §11:

**A1 (NL-FSCX v1 PRF, SecurityProofs-5.md §11.8.4).**  For random key $K$, the function $i \mapsto F_1^{64}(K \oplus i, K)$ is computationally indistinguishable from a uniformly random function $\{0,1\}^n \to \{0,1\}^n$ against polynomial-time distinguishers.

**A2 (NL-FSCX v1 OWF, SecurityProofs-5.md §11.8.3, Theorem 16).**  Given $y = F_1^{64}(s, m)$ for known $m$ and unknown $s$, recovering $s$ requires $\Omega(2^n) = \Omega(2^{256})$ classical operations and $\Omega(2^{n/2}) = \Omega(2^{128})$ quantum queries (Grover lower bound; the classical bound is supported by Theorem 13's degree-saturation argument and Corollary 2's Gröbner-immunity result, which show no sub-exponential classical solver exists for the resulting degree-$n$ Boolean system).

**A3 (Symmetric structure).**  $F_1(A, B) = F_1(B, A)$, since

$$F_1(A, B) = M(A \oplus B) \oplus \mathrm{ROL}_{n/4}\bigl((A + B) \bmod 2^n\bigr)$$
is symmetric under the swap $A \leftrightarrow B$.  Consequently, NL-FSCX v1 is non-bijective in $B$ as well as in $A$ (§11.5 Q3, by symmetry); $C(\cdot, m)$ is non-bijective in either input.

A3 is structurally important: HFSCX-256-DM cannot claim ideal-cipher security from $C_{\text{DM}}$ as a pseudorandom permutation.  All hardness claims below are therefore PRF-based, not PRP-based.

### 11.9.3 Collision resistance

**Generic bound.**  For an ideal 256-bit hash, a generic collision search costs $\Theta(2^{n/2}) = \Theta(2^{128})$ classical operations (Pollard rho) or $\Theta(2^{n/3}) = \Theta(2^{85})$ quantum operations (BHT [Brassard-Høyer-Tapp 1997]).

**MD lemma.**  Any internal collision $C(s, m_1) = C(s', m_2)$ with $(s, m_1) \neq (s', m_2)$ propagates to a full hash collision through the standard Merkle-Damgård argument; conversely, every full collision implies an internal collision somewhere along the two chains.

**Heuristic claim.**  Under A1, the compression $C_{\text{DM}}$ is computationally indistinguishable from a random function $\{0,1\}^{256} \times \{0,1\}^{256} \to \{0,1\}^{256}$.  The expected number of evaluations to find a collision in such a function is $\sqrt{\pi \cdot 2^{n} / 2} \approx 2^{128.3}$.  Therefore, under A1, finding any HFSCX-256-DM collision requires $\approx 2^{128}$ work classically.

**Free-start collisions.**  Under the Davies-Meyer construction (§11.9.8), a free-start collision $C_{\text{DM}}(s_1, m_1) = C_{\text{DM}}(s_2, m_2)$ with $s_1 \neq s_2$ requires $F_1^{64}(s_1, m_1) \oplus F_1^{64}(s_2, m_2) = s_1 \oplus s_2$.  Even if $F_1^{64}$ maps both inputs to the same value (exploiting its non-bijectivity), that forces $s_1 = s_2$, contradicting the free-start hypothesis.  The $2^{128}$ bound is therefore structurally tighter than for the earlier plain-MD construction.

### 11.9.4 Preimage and second-preimage resistance

**Preimage.**  Given target digest $h$, find any $D$ with $\text{HFSCX-256-DM}(D) = h$.  Generic bound: $\Theta(2^n)$ classical, $\Theta(2^{n/2})$ quantum (Grover).  Reduction to A2: any preimage attack must invert $C_{\text{DM}}$ on the final compression (else the digest cannot match), contradicting A2.

**Second preimage.**  Given $D$, find $D' \neq D$ with the same digest.  For a *short* $D$ the bound is $\Theta(2^n)$ classical (no birthday speed-up, since one input is fixed), implied by collision resistance under standard hash arguments.  For a **long** $D$ this is not the right bound: like every Merkle-Damgard hash, HFSCX-256-DM admits the Kelsey-Schneier expandable-message attack, which costs about `k` · 2^(n/2+1) + 2^(n-k) against a `2^k`-block target — demonstrated end-to-end against this chain in §11.9.12 (TODO #215).  At n = 256 the corrected figure is ~2^216 for a 32 TiB target and never falls below ~2^200 at any realisable size, so the 128-bit target is unaffected; see §11.9.12 for the derivation and the per-size table.

### 11.9.5 Length-extension resistance via finalization

A plain Merkle-Damgård hash without finalization admits the extension attack: given $h = H(D)$, an attacker can set the chain state to $h$ and continue, producing $H(D \| \mathrm{pad}(D) \| D')$ for arbitrary $D'$ without knowing $D$.

HFSCX-256-DM's finalization block makes the published digest $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$, where $s_{k-1}$ is the state after processing the real message blocks but before finalization.  The attacker is given $s_k$, not $s_{k-1}$.

**Theorem 18 — Length extension is infeasible under A2.**  Any extension attacker who, given $\text{HFSCX-256-DM}(D)$ alone, produces $\text{HFSCX-256-DM}(D \| X)$ for an attacker-chosen $X$ must recover $s_{k-1}$ from $s_k = C_{\text{DM}}(s_{k-1}, \mathit{fin})$ — an inversion of $C_{\text{DM}}$ that requires $\Omega(2^n)$ classical work (or $\Omega(2^{n/2})$ quantum work) under A2. $\blacksquare$

**Empirical confirmation.**  `hfscx_256_analysis.py` §5: 0 successful naive forgeries in 200 trials (the naive forgery treats $h_M$ directly as a chain state and processes one extension block using $C_{\text{DM}}$; this never matches the true digest of $D \| X$).

**Keyed mode bonus.**  In keyed mode the finalization block content is $(8|D|) \oplus K \oplus \text{IV-const}$, which the attacker cannot construct without $K$.  This adds a second layer of length-extension protection independent of A2.

### 11.9.6 Keyed mode and MAC use

HFSCX-256-DM supports a keyed mode by setting $s_0 = K \oplus \text{IV-const}$.  This mode is used by `HerraduraCli` for the `HSKE-NL-A1-CTR-AEAD` authentication tag.  Two MAC constructions are evaluated.

**(a) Raw keyed-IV MAC (deployed).**

$$\mathrm{MAC}(K, D) = \text{HFSCX-256-DM}(D, K).$$

*Properties.*  Under A1, HFSCX-256-DM with secret IV is a PRF: the chain state at every step is unpredictable to an adversary without $K$.  EUF-CMA security follows from the PRF property by standard arguments [Bellare-Canetti-Krawczyk 1996, §3.2].

*Caveat.*  The security claim applies A1 to the entire chain.  If A1 holds for one $F_1^{64}$ application but degrades when chained over many blocks, the raw keyed-IV MAC weakens.  Empirical avalanche tests (§11.9.10 §2) show ideal key-bit diffusion (mean 128.09 / 256 output bits flipped, σ = 7.98) for the deployed parameters, but this is a sanity check, not a chain-length proof.

**(b) HMAC-HFSCX-256-DM (recommended for cross-protocol key reuse).**

$$\mathrm{HMAC}(K, D) = \text{HFSCX-256-DM}\Bigl(\bigl(K \oplus \mathit{opad}\bigr) \| \text{HFSCX-256-DM}\bigl((K \oplus \mathit{ipad}) \| D\bigr)\Bigr)$$

with $\mathit{ipad} = \mathtt{0x36}$ repeated and $\mathit{opad} = \mathtt{0x5C}$ repeated, each 32 bytes.

*Properties.*  Bellare's HMAC proof [Bellare 2006] reduces HMAC security to two assumptions on the underlying compression function:

1. PRF under related-key attacks against the IV input.
2. Collision resistance of the compression.

Both follow from A1 + A2.  HMAC adds resistance against extension and key-recovery attacks even if the compression has minor structural weaknesses, at the cost of one extra hash invocation per MAC.

**Recommendation.**  The current single-purpose AEAD use is well-served by raw keyed-IV.  For protocols intending to reuse the same long-term key across multiple algorithms or modes (e.g. derive both an encryption key and a MAC key from one master), HMAC-HFSCX-256-DM should be preferred.  As of v1.9.48 (TODO #93), `hmac_hfscx_256(key, data)` / `HmacHfscx256` is available in the C, Go, and Python libraries; no existing call site is changed.

**HSKE-NL-AEAD (v1.9.33, TODO #95 option 1).**  The keyed-IV MAC mode is now also deployed as the tag of a general-purpose AEAD, `hske_nl_aead_encrypt` / `hske_nl_aead_decrypt` (C/Go/Python suites; CLI `enc`/`dec --aead`).  The construction is encrypt-then-MAC over the HSKE-NL-A1 CTR keystream with associated-data support: the tag is computed over the domain-separation prefix `HSKE-NL-AEAD-v1`, the nonce, and length-framed AD and ciphertext, with the MAC key derived from the same per-(key, nonce) schedule as the `.hkx` file format but separated from it by the DS prefix.  Because the tag binds the MAC key through the collision-resistant keyed chain, the scheme is *key-committing*: a ciphertext/tag pair cannot verify under two distinct keys without a keyed collision, ruled out by A2 — a property AES-GCM lacks.  Verification is constant-time and decrypt-after-verify.  A single-pass alternative — a MonkeyDuplex-style sponge AEAD using the bijective NL-FSCX v2 family as the duplex permutation (TODO #95 option 2) — remains open research; it requires the differential/linear characterisation of the v2 permutation tracked in TODO #99 before any deployment claim.

**HDRBG (v1.9.34, TODO #96).**  The bare hash mode also serves as the output filter of a forward-secure deterministic random bit generator, `drbg_seed` / `drbg_generate` / `drbg_reseed` (C/Go/Python suites).  The construction follows the fast-key-erasure pattern: each 32-byte output block is `HFSCX-256(state || counter_be8 || "DRBG-OUT")`, after which the state advances one-way via `nl_fscx_revolve_v1(state, DRBG-domain, 64)` and the superseded state is erased (`explicit_bzero` in C; best-effort in Go/Python).  Backtracking resistance reduces to the same NL-FSCX v1 OWF conjecture as Theorem 16.  Because the v1 state walk is non-bijective, walks can collide: `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py` §5 measures the composed-walk image (the 64-step revolve image extrapolates to `2^218.8` at n = 256) and Brent rho/cycle lengths at n = 16–24, giving an expected walk-collision distance of `2^109.7` blocks; the enforced per-seed output limit of `2^20` blocks keeps the collision probability near `2^-180`, below the `2^-128` target.  *Non-goals:* HDRBG is not a NIST SP 800-90A validated DRBG — it has no health tests, prediction-resistance requests, or entropy-source assessment, and is intended only to expand seed material that is already full-entropy.

### 11.9.7 Domain separation across suite call sites

| Site | Role | Effective domain marker |
|---|---|---|
| `dgst` subcommand | generic digest | none — `iv = IV_const` |
| sign / verify pre-hash | message → 256-bit input | none — `iv = IV_const` |
| AEAD authentication tag | per-session MAC | $K \oplus \text{IV-const}$ ($K$ is the per-session MAC key, never zero) |
| `_stern_hash` | Stern commitment hash | distinct construction (rotates message into key slot, no finalization) — see §11.9.9 |

The `dgst` and pre-hash flows share the same effective IV.  This is acceptable when the input distributions cannot collide: the pre-hash flow always operates on attacker-supplied messages, but so does `dgst`, so a true cross-flow collision would only be an issue if (i) one flow appended additional content the other did not, *and* (ii) that content fell on a block boundary that mimicked the other's padding.  Neither holds in the current codebase.

The AEAD tag uses a distinct effective IV via the per-session key.  Cross-flow collision would require either a second-preimage on $\text{HFSCX-256-DM}(\cdot, K)$ for some $K$ (ruled out by collision resistance), or $K = 0$ (ruled out by the AEAD key-derivation step which produces $K$ from a Ring-LWR shared secret with negligible probability of $K = 0$).

**Hardening (v1.9.48, TODO #93).**  A domain-separated variant `hfscx_256_ds(ds, data)` is now available in the C, Go, and Python libraries.  The CLI exposes it as `dgst --algo hfscx-256-ds` with ds=0x01.  For a fully rigorous domain-separation argument that does not depend on collision-resistance reasoning, the suggested prefixes are: `0x01` for `dgst`, `0x02` for sign-pre-hash, `0x03` for AEAD-MAC.  Adoption at existing protocol call sites is a backwards-incompatible wire-format change and remains opt-in.

### 11.9.8 Davies-Meyer compression — DONE v1.9.0 (TODO #72)

As of v1.9.0 the compression function is the Davies-Meyer variant $C_{\text{DM}}(s, m) = F_1^{64}(s, m) \oplus s$ (see §11.9.1).  This section records the security benefits and the wire-format break.

**Benefits gained.**

1. **Fixed-point hardness.**  $C_{\text{DM}}(s, m) = s$ requires $F_1^{64}(s, m) = 0$, which under A2 requires $\Omega(2^n)$ classical work (preimage of zero under A2).  Before v1.9.0, fixed points were orbit-period-64 points of $F_1(\cdot, m)$; no formal lower bound existed, only empirical absence.
2. **Free-start collision hardness.**  As argued in §11.9.3, the Davies-Meyer structure rules out a structural speed-up from the non-bijectivity of $F_1$.
3. ~~**PGV-1 alignment.**  $C_{\text{DM}}$ is one of the 12 provably-secure PGV compression functions [BRS 2002, PGV 1993].~~  **Retracted (TODO #215).**  The PGV/BRS results are proved in the ideal-*cipher* model and require the inner map to be a permutation for every block; `nl_fscx_v1` is non-bijective (A3, §11.9.2), so no PGV row applies to the compression.  Benefits 1 and 2 above are unaffected — they are concrete-structure arguments that do not invoke PGV.  §11.9.12 re-derives the bounds in the ideal-random-*function* model, which the construction does satisfy, and shows every figure in §11.9.11 survives.

**Wire-format note.**  This is a breaking change: all pre-v1.9.0 HFSCX-256 digests, pre-hashed signatures, and AEAD tags are incompatible with HFSCX-256-DM.  The cost per block is one 256-bit XOR (negligible).

### 11.9.9 `_stern_hash` QRO argument (TODO #36 — DONE v1.6.1)

As of v1.6.1 the Stern-F commitment hash is (ds = domain-separation tag):

$$\mathrm{StH}_{\mathrm{ds}}(v_1, \ldots, v_k) = \mathrm{HFSCX\text{-}256\text{-}DM}(h_k)[0{:}n/8], \quad h_0 = \mathrm{ds}, \quad h_i = F_1^{n/4}\bigl(h_{i-1} \oplus v_i, \mathrm{ROL}(v_i, n/8)\bigr)$$

Per-slot tags: ds=1 for c0, ds=2 for c1, ds=3 for c2, ds=4 for the KEM key, ds=0 for the Fiat-Shamir challenge.

**QRO argument.** Under the ROM on HFSCX-256-DM (§11.9.2, assumption A1), distinct per-slot ds values guarantee that c0, c1, c2, and the KEM key each invoke an independent random oracle.  By Unruh's composition theorem [Unruh 2015], this satisfies the QROM requirement for Theorem 17's Fiat-Shamir transform.  The range compression gap from TODO #42 (F_stern maps only ~24% of 2^32 inputs to distinct outputs at n=32) is resolved: the HFSCX-256-DM finalization maps the chained state through a full 256-bit hash before truncation, restoring the ~63.2% distinct-output fraction expected of a random function.

**Assembly/Arduino (n=32 toy demo).** The 32-bit `hfscx_32` finalizer and the KEM call with ds=4 provide the same QRO property for the KEM slot.  As of v1.9.48 (TODO #93), `stern_hash1_32`/`stern_hash2_32` carry explicit per-slot DS tags (ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key) in both the ARM Thumb-2 and NASM i386 implementations — the same tags as the C/Go/Python suite.  This satisfies the full QRO property at the assembly level and removes the prior reliance on structural distinctness.

### 11.9.10 Empirical evidence

`SecurityProofsCode/hfscx_256_analysis.py` measured the following at $n = 256$ (HFSCX-256-DM, v1.9.0):

| Test | Result | Interpretation |
|---|---|---|
| §1 Avalanche on input bit flips, 5 000 trials | mean = 128.013 / 256, σ = 7.980, range [99, 155] | Matches ideal random-function SAC (mean 128, σ ≈ 8 = $\sqrt{n/4}$). |
| §2 Avalanche on key bit flips (keyed mode), 5 000 trials | mean = 128.091 / 256, σ = 7.980, range [99, 159] | Matches ideal SAC; key bits diffuse fully through chain. |
| §3 Output Hamming weight uniformity, 5 000 trials | mean weight = 127.911, σ = 8.051 | Matches ideal output distribution. |
| §3 Byte-distribution chi², 5 000 × 32 bytes | $\chi^2 = 223.1$, df = 255 | $\chi^2 < 293.2$ (critical at $p = 0.05$); output bytes uniformly distributed. |
| §4 Collision sanity, $2^{17}$ trials (`--full`) | not run by default — birthday bound $2^{128}$ | Skipped: any observable collision below $2^{60}$ would falsify A1. |
| §5 Length-extension naive forgery, 200 trials | 0 / 200 successful | Confirms Theorem 18: finalization block defeats trivial extension. |
| §6 Domain separation (unkeyed vs keyed), 1 000 trials | 1000 / 1000 differ | Keyed mode distinct from unkeyed for all non-zero $K$. |
| §7 Fixed-point search (DM), 200 random $(s, m)$ pairs | 0 with $F_1^{64}(s,m)=0$, 0 near-zero | Fixed-point condition is preimage of zero under A2; no instances found, consistent with $\Omega(2^{256})$ classical hardness (§11.9.8). |

These tests rule out trivial weaknesses (low diffusion, biased output, length-extension, accidental key collisions, structural fixed points).  They do **not** constitute a formal proof: collision and preimage hardness rest on A1 + A2.  `SecurityProofsCode/hfscx_dm_rf_model.py` (TODO #215) adds the model-level companion to these: image-collapse propagation, Davies-Meyer fixed points under both inner maps, and working Joux / Kelsey-Schneier attacks against the chain — see §11.9.12.

### 11.9.11 Summary

HFSCX-256-DM provides:

| Property | Bound | Assumption |
|---|---|---|
| Collision resistance | $2^{128}$ classical / $2^{85}$ quantum (BHT) | A1 |
| Preimage resistance | $2^{256}$ classical / $2^{128}$ quantum (Grover) | A2 |
| Second-preimage resistance (short message) | $2^{256}$ classical | A1 (collision implies 2nd-preimage) |
| Second-preimage resistance (`2^k`-block target) | `k` · 2^(n/2+1) + 2^(n-k) — ~2^216 at 32 TiB | Merkle-Damgard mode, unconditional (§11.9.12) |
| Length-extension resistance | $2^{256}$ classical / $2^{128}$ quantum (Theorem 18) | A2 |
| MAC unforgeability (raw keyed-IV) | $2^{128}$ classical / $2^{128}$ quantum | A1 (full-chain PRF) |
| MAC unforgeability (HMAC, recommended for cross-protocol reuse) | as raw, plus related-key resistance | A1 + A2 [Bellare 2006] |

**Open hardenings** (not security-critical at current parameters):

1. ~~Switch to Davies-Meyer compression $C \oplus s$ at next major version (§11.9.8).~~ **DONE v1.9.0.**
2. ~~Add 1-byte domain-tag prefix per call site (§11.9.7).~~ **DONE v1.9.48** — `hfscx_256_ds(ds, data)` added to C, Go, Python libraries; `dgst --algo hfscx-256-ds` wired in all three CLIs (ds=0x01). Existing call sites unchanged (backward-compatible opt-in).
3. ~~Add HMAC-HFSCX-256-DM to the library (§11.9.6).~~ **DONE v1.9.48** — `hmac_hfscx_256(key, data)` / `HmacHfscx256` added to C, Go, Python libraries. Recommended when the same long-term key is reused across MAC and non-MAC modes; the current AEAD-only use retains the raw keyed-IV MAC.
4. ~~Assembly/Arduino per-slot DS tags on `stern_hash1_32`/`stern_hash2_32` (§11.9.9).~~ **DONE** — ARM Thumb-2 and NASM i386 implementations already carry ds=1/2/3/4 at all call sites (verified v1.9.48).


### 11.9.12 The compression is not a block cipher — bound re-derived in the random-function model (TODO #215)

§11.9.8 lists "PGV-1 alignment" among the benefits of the Davies-Meyer feed-forward, citing [BRS 2002, PGV 1993].  **That citation does not apply to this construction.**  The PGV/BRS provable-security results are proved in the ideal-*cipher* model: they require the block-indexed map to be a permutation for every message block.  Assumption A3 (§11.9.2) already records that `nl_fscx_v1` is non-bijective in either argument, so the deployed inner map is not a cipher and no PGV row is available to cite.  §11.9.2 draws the right conclusion in the abstract — "all hardness claims below are therefore PRF-based, not PRP-based" — but §11.9.8 then cites the PRP-based result anyway, and §11.9.4 states a second-preimage bound that no model supports.  This section replaces both with a derivation in the model the construction actually satisfies, and reports the structure search that model does not excuse.  Backed by `SecurityProofsCode/hfscx_dm_rf_model.py`.

**The correct model, and why every number survives.**  Model the inner map as an ideal random function `f` (this is assumption A1, unchanged) and write the compression as `C_DM(s, m) = f(s, m) XOR s`.  For each fixed input pair the feed-forward XORs in a value determined by that input, so `C_DM` is a uniform, independent random value at every point: **`C_DM` is itself an ideal random function.**  Every ideal-random-function bound therefore transfers to it with no loss and no additional assumption.  The consequence is worth stating plainly in both directions — the bounds in the §11.9.11 table are sound, and the Davies-Meyer shape contributes nothing to them.  Its benefit is entirely in the concrete-structure claims of §11.9.8 items 1 and 2, which remain valid on their own terms.

**Non-bijectivity does not propagate to the compression.**  The sharpest form of the objection is quantitative: iterating a non-bijective map contracts its image toward `2/r` of the space, so at the deployed `r = 64` the inner map reaches only about 3% of its range — roughly 5 bits of collapse per block.  Measured exhaustively at n = 16 over all 2^16 states:

| `r` | image of `F_1^r` | image of `C_DM` | `2/r` |
|---|---|---|---|
| 4 | 0.3238 | 0.6342 | 0.5000 |
| 16 | 0.1123 | 0.6311 | 0.1250 |
| 64 (deployed) | 0.0318 | 0.6319 | 0.0312 |

The inner map collapses exactly as the `2/r` law predicts, and the compression does not collapse at all: its image sits at `1 - 1/e = 0.6321`, the random-function value, at every step count.  The reason is structural rather than empirical — for fixed `m` the map `s -> s XOR c` is a bijection, so the feed-forward re-randomises over `s` even where `f` is many-to-one.  **The image collapse that motivates this item is confined to the inner map and is not inherited by the compression function.**

**Bijectivity would make the construction worse, not better.**  The obvious repair — swap in the bijective `nl_fscx_v2` so that the PGV citation becomes literally true — is counterproductive, and this is the least obvious finding of the item.  Davies-Meyer over an *invertible* map has trivially computable fixed points: `s = E_m^{-1}(0)` yields `C_DM(s, m) = s` for any block `m`, which is precisely the structure Dean's 1999 expandable-message attack consumes.  Measured: with `v2` as the inner map, one fixed point per block value is produced by a single inversion in `O(r)` work, confirmed for four blocks at n = 16.  With the deployed `v1` the same question is a preimage-of-zero problem under A2, and the image collapse makes it *harder* still — exhaustively, three of four tested blocks have **no** fixed point at `r = 64`, because 0 simply is not in the image.  The non-bijectivity that breaks the citation is load-bearing for the property the citation would have certified.

**Second preimage: the flat bound in §11.9.4 is wrong for long messages.**  §11.9.4 claims 2^256 classical second-preimage resistance with "no birthday speed-up since one input is fixed".  That reasoning fails against a long target in *any* Merkle-Damgård hash, independent of the compression function or its model: Kelsey-Schneier expandable messages reduce the cost against a `2^k`-block target to about `k` · 2^(n/2+1) + 2^(n-k).  This was demonstrated end-to-end against the deployed chain construction at n = 16 with k = 8 — a distinct message of *identical block length* (so it carries the same finalization block and the match survives padding) matching the target digest for ~3 900 compressions against a generic bound of 2^16, a 16.6x speed-up.  Joux multicollisions were confirmed on the same chain (16 messages sharing a digest for ~2^9.7 work against a generic 2^15).  Corrected figures at n = 256:

| target size | `k` | corrected 2nd-preimage cost |
|---|---|---|
| 32 MiB | 20 | ~2^236 |
| 32 GiB | 30 | ~2^226 |
| 32 TiB | 40 | ~2^216 |
| 32 PiB | 50 | ~2^206 |

The `2^(n-k)` term dominates at every physically realisable size; the expandable message only becomes the bottleneck near `k = 120`, a 2^125-byte target.  The practical margin over the suite's 128-bit target is therefore never threatened — **this is a correction to a stated bound, not a break** — but the claim must read *2^n for short messages, `k` · 2^(n/2+1) + 2^(n-k) against a `2^k`-block target*, and §11.9.4 has been amended accordingly.  No suite call site is affected: the sign/verify pre-hash, the AEAD tag, and the Stern commitments all operate on inputs far below the sizes at which the term matters, and none of them offers an attacker a chosen long target with a fixed digest.

**Recommendation: keep NL-FSCX v1; do not migrate.**  The `v2` swap is rejected on four grounds, in descending weight:

1. It adds free Davies-Meyer fixed points (measured above), importing the Dean-1999 structure the current design denies.
2. It trades a studied idealisation for an unstudied stronger one — "v1 is a PRF" (SecurityProofs-5.md §11.8.3, §11.8.4, and the A2 one-wayness that every other suite protocol already rests on) becomes "v2 is an ideal cipher", a claim about a map whose differential/linear profile is still open (TODO #99, TODO #214).
3. `v2` has a documented degenerate-key class (§11.19.2, `nl_v2_key_is_valid`) where the round collapses to affine.  In an inner-map role the *message block* occupies the key argument, so an attacker selects it freely, and the key-validity screen that protects HSKE-NL-A2 and HPKE-NL cannot be applied to a hash input at all.
4. It breaks the wire format for every artifact carrying a digest — signatures, AEAD tags, Stern commitments, KDF outputs, HCRED proofs — for no bound that is not already available.

Performance is not a factor either way (`v2` measures marginally faster than `v1` at n = 256, its per-key offset being hoisted out of the revolve loop).  Since no change is made, no `MIGRATING.md` entry is created; the migration this item was asked to draft is recorded here as **rejected**, with grounds 1-3 above as the reasons any future proposal to adopt `v2` as the inner map must answer first.

**What remains open.**  The derivation above is conditional on A1 exactly as before, and A1 remains a conjecture about a concrete function rather than a theorem.  This item narrows what is being assumed — the assumption is now stated in the model the construction satisfies, with the empirical case that the inner map's one measurable deviation from ideal does not reach the compression — but it does not discharge it.  The differential/linear characterisation that would put A1 on firmer ground is TODO #214.

---

---

> **Continued in Part 7 — §11.10–§11.13, §11.15–§11.20** (SecurityProofs-7.md): Zero-Knowledge Proof Extensions · Research-Review Sections
