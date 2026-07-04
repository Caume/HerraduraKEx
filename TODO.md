# HerraduraKEx — PQC Improvement Backlog

Generated from security/performance review of v1.5.x NL-FSCX + Ring-LWR implementation.

---

## Documentation

### 56. Add `docs/INTRODUCTION.md` — lay-audience primer for all core cryptographic concepts (Documentation, High)

**Rationale:** `docs/TUTORIAL.md` covers *how to call* the library APIs.
`SecurityProofs-1.md` / `SecurityProofs-2.md` are mathematically dense and assume
graduate-level algebra.  There is no entry point for IT/security practitioners who
understand TLS, public-key certificates, and hashing but have never studied Galois
field arithmetic or lattice problems.  `INTRODUCTION.md` fills that gap: a
"for dummies" conceptual reference that lets readers understand *why* the suite
works the way it does, follow the SecurityProofs arguments at a high level, and make
informed deployment decisions.

**Target audience:** Developer or security professional with a working knowledge of
TLS/HTTPS, symmetric encryption (AES), hashing (SHA-256), and basic public-key
concepts (RSA at a surface level) — but no background in abstract algebra, lattices,
or coding theory.

**Writing style:**

- Plain English first, then a one-line formal version of each definition.
- Concrete toy examples (small numbers, few bits) before the real parameters.
- Explicit "what this means in practice" boxes after each concept.
- Footnoted, verifiable references (RFCs, NIST documents, Wikipedia stable
  sections, textbook chapters) so nothing is a claim without a source.
- Cross-links: "→ See SecurityProofs-1 §1.2" and "→ See TUTORIAL.md §HKEX-GF"
  after each concept that has a counterpart in those documents.

---

**Proposed section outline:**

#### Part 0 — Reading guide (≈ 0.5 page)

Purpose of this document, how it relates to TUTORIAL.md and SecurityProofs,
suggested reading order for four reader profiles:
(a) developer who just wants to use the library,
(b) security reviewer assessing the suite,
(c) researcher checking the proofs,
(d) student learning applied cryptography.

#### Part 1 — Bits, bytes, and the language of crypto (≈ 1 page)

- Binary representation; XOR as "controlled flip"; the key insight: XOR is
  its own inverse (`A ⊕ B ⊕ B = A`).
- Why XOR dominates symmetric crypto (speed, uniformity, no carry propagation).
- Cyclic bit rotation (ROL / ROR): definition with a 4-bit example, and why it
  provides diffusion without arithmetic.
- Reference: Shannon's "diffusion" and "confusion" criteria
  (Shannon 1949, *Communication Theory of Secrecy Systems*,
  Bell System Technical Journal 28(4):656–715).

#### Part 2 — Finite fields without the algebra (≈ 2 pages)

- What a "field" is: a number system where you can add, subtract, multiply, and
  divide (except by zero), illustrated with ordinary fractions.
- GF(2) = {0, 1} with XOR as addition and AND as multiplication — the simplest
  possible field.
- GF(2^n): polynomials whose coefficients are 0 or 1; arithmetic is the same but
  "mod an irreducible polynomial".  Toy example: GF(2^4) mod x^4+x+1, showing
  that multiplication stays inside the field.
- Why GF(2^n) matters for crypto: the discrete-logarithm problem (DLP) — finding
  `a` given `g` and `g^a` — is believed hard, analogously to the integer DLP
  underpinning classical Diffie-Hellman.
- Reference: Lidl & Niederreiter, *Introduction to Finite Fields and Their
  Applications*, Cambridge University Press, rev. ed. 1994, ch. 1–2.
  Also: NIST SP 800-38D, Appendix B (GF(2^128) arithmetic for GCM).

#### Part 3 — Key exchange: the Diffie-Hellman idea (≈ 2 pages)

- Alice-and-Bob metaphor: how two people can agree on a secret over a public
  channel by exchanging "painted colours" (the classic paint-mixing analogy).
- Integer DH: g^a mod p; why computing `a` from g^a is hard (DLP).
- HKEX-GF as DH in GF(2^n)*: `C = g^a`; `C2 = g^b`; `sk = g^{ab}`.
  Walk through one handshake with toy 8-bit values.
- What an eavesdropper (EVE) sees and why that doesn't help her.
- Limitations: DH is vulnerable to man-in-the-middle and to quantum computers
  running Shor's algorithm.
- Reference: Diffie & Hellman 1976, *New Directions in Cryptography*, IEEE
  Transactions on Information Theory 22(6):644–654 (open access).
  Also: RFC 7748 (Curve25519/X25519 modern DH).

#### Part 4 — Symmetric encryption and FSCX (≈ 2 pages)

- Stream cipher concept: generate a keystream, XOR it with plaintext.
- The FSCX primitive: what `FSCX(A,B) = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)` does visually (bit-flow diagram with 8-bit example).
- FSCX_REVOLVE: apply FSCX repeatedly with fixed B; the orbit always returns
  to start after n or n/2 steps (shown empirically — no algebra required).
- HSKE encryption: encrypt with depth i = n/4, decrypt with complementary depth
  r = 3n/4.  Why i + r = n guarantees round-trip correctness.
- What "linearity" means and why it is a problem: linear maps can be inverted
  or predicted once enough input-output pairs are collected.
- Reference: Stinson, *Cryptography: Theory and Practice*, 4th ed., CRC Press
  2018, ch. 2 (stream ciphers and pseudo-randomness).

#### Part 5 — Non-linearity and why it matters (≈ 1.5 pages)

- The AES S-box as the canonical non-linear element: substitution is inherently
  non-linear because no matrix equation describes it exactly.
- NL-FSCX: how adding a non-linear mixing step (modular multiply, data-dependent
  rotation, or similar) breaks the linearity of vanilla FSCX.
- The concept of algebraic degree: a truly random function has maximum degree;
  linear functions have degree 1.
- Why non-linearity is necessary for post-quantum security (linear systems can be
  solved efficiently even by quantum computers using Gaussian elimination).
- Reference: Carlet, *Boolean Functions for Cryptography and Coding Theory*,
  Cambridge University Press 2021, ch. 1 (nonlinearity measures).
  Also: SecurityProofs-1 §1, §2 for the formal treatment.

#### Part 6 — Digital signatures: proving without revealing (≈ 2 pages)

- What a signature is: a mathematical commitment that only the private key holder
  can produce, which anyone can verify with the public key.
- Schnorr identification protocol in three steps:
  (1) Commit R = g^k (random nonce),
  (2) Receive challenge e,
  (3) Respond s = k − a·e.
  Toy example with small numbers.
- Fiat-Shamir transform: replace interactive challenge with a hash — making the
  signature non-interactive.
- HPKS: same Schnorr flow but challenge computed via FSCX_REVOLVE instead of a
  hash; HPKS-NL uses NL-FSCX for the challenge.
- Reference: Schnorr 1991, *Efficient Signature Generation by Smart Cards*, Journal
  of Cryptology 4(3):161–174.
  Also: Fiat & Shamir 1987, *How to Prove Yourself*, CRYPTO 1986, LNCS 263.

#### Part 7 — Public-key encryption: El Gamal (≈ 1.5 pages)

- Hybrid encryption intuition: use public-key crypto only to wrap a symmetric key.
- El Gamal: choose ephemeral r; ciphertext = (g^r, P · pk^r).
  Decryption: P = ciphertext[1] / (g^r)^sk.
- HPKE: the same structure but multiplication replaced by FSCX_REVOLVE.
- Reference: ElGamal 1985, *A Public Key Cryptosystem and a Signature Scheme Based
  on Discrete Logarithms*, IEEE Transactions on Information Theory 31(4):469–472.

#### Part 8 — Quantum threats and why they matter now (≈ 1.5 pages)

- Qubits and superposition in one paragraph (no equations); the key takeaway:
  a quantum computer can run many computations in parallel.
- Shor's algorithm: breaks integer DH, RSA, and ECDH in polynomial time.
  Impact on HKEX-GF and classical HPKS/HPKE.
- Grover's algorithm: halves the effective key length of symmetric ciphers
  (AES-128 becomes roughly AES-64 equivalent); HSKE-NL at 256 bits retains
  ~128-bit post-quantum security.
- "Harvest now, decrypt later" threat: why deploying PQC matters even if
  large quantum computers are still years away.
- Reference: Shor 1994, *Algorithms for Quantum Computation*, FOCS 1994.
  Grover 1996, *A Fast Quantum Mechanical Algorithm for Database Search*, STOC.
  NIST IR 8413 (2022) status report on post-quantum standardization.

#### Part 9 — Lattice-based crypto and Ring-LWR (≈ 2.5 pages)

- Lattices in plain English: a regular grid in high-dimensional space; the hard
  problem is finding the shortest or closest vector.
- Learning With Errors (LWE): given many `(a, a·s + small_error)` pairs, recover
  s.  Even quantum computers cannot do this efficiently (believed).
- Ring variant (RLWE / RLWR): coefficients live in a polynomial ring mod (x^n+1);
  this compresses key sizes from O(n^2) to O(n).
- "Rounding" instead of "error": in LWR, the small error comes from a deterministic
  rounding step (`⌊q/p · x⌋`) rather than random noise, simplifying
  implementation and analysis.
- HKEX-RNL walkthrough: keygen, exchange, Peikert 1-bit reconciliation, KDF.
  Show why Bob and Alice converge to the same key despite the rounding gap.
- Parameter choices (n=256, q=65537, p=4096): why these give ~128-bit classical
  and ~64-bit quantum security (conservative estimate).
- Reference: Regev 2005, *On Lattices, Learning with Errors, Random Linear Codes,
  and Cryptography*, STOC 2005 (foundational LWE paper).
  Banerjee, Peikert & Rosen 2012, *Pseudorandom Functions and Lattices* (LWR).
  NIST FIPS 203 (ML-KEM / Kyber, 2024) for a standardized Ring-LWE comparison.
  SecurityProofs-1 §11.4–§11.6 for the HKEX-RNL formal analysis.

#### Part 10 — Code-based crypto and the Stern protocol (≈ 2 pages)

- Error-correcting codes in one page: a codeword is a message plus redundancy bits;
  errors flip some bits; decoding recovers the message.  Syndrome = parity-check
  result; a non-zero syndrome reveals an error happened.
- Syndrome decoding problem (SDP): given a parity-check matrix H and a syndrome s,
  find a low-weight error vector e such that H·e^T = s.  NP-hard in general
  (proven); believed quantum-hard.
- Niederreiter KEM: public key = H (scrambled parity-check matrix); to encrypt,
  pick a random low-weight e, send s = H·e^T; shared secret = hash(e).
- Stern's zero-knowledge proof: Alice knows e without revealing it by committing to
  permuted views of e and proving one view is consistent with the syndrome.
  Fiat-Shamir makes it a signature.
- HPKS-Stern-F and HPKE-Stern-F in the suite: parameters, commit/challenge/respond
  cycle, and how the NL-FSCX hash replaces SHA in the challenge step.
- Reference: McEliece 1978 (original code-based PKE).
  Stern 1994, *A New Identification Scheme Based on Syndrome Decoding*, CRYPTO 1993.
  NIST FIPS 205 (SLH-DSA / SPHINCS+) and the BIKE/HQC alternate candidates for
  modern code-based context.
  SecurityProofs-1 §8 for the Stern ZKP formal treatment.

#### Part 11 — Putting it all together: the suite at a glance (≈ 1 page)

- One-page table: protocol → hard problem relied on → quantum threat level →
  SecurityProofs section → TUTORIAL.md section.
- Decision tree: "Which protocol should I use for my use case?"
- What the security proofs actually prove vs. what they assume (distinguishing
  "proven secure under X assumption" from "no known attacks").

#### Part 12 — Glossary (≈ 1 page)

Concise definitions (2–4 sentences each) for: bit, byte, XOR, ROL/ROR, field,
GF(2^n), discrete logarithm, one-way function, trapdoor, key exchange, forward
secrecy, digital signature, zero-knowledge proof, lattice, LWE/LWR, syndrome,
parity-check matrix, NP-hard, quantum supremacy, Shor, Grover, Fiat-Shamir,
FSCX, FSCX_REVOLVE, orbit period, CBD (centered binomial distribution),
Peikert reconciliation.

---

**Files to create:**

- `docs/INTRODUCTION.md` — the main document
- No new code files; all code examples are already in TUTORIAL.md

**Cross-references to add once the document exists:**

- Add "→ See INTRODUCTION.md §Part X" links at the top of SecurityProofs-1.md
  and SecurityProofs-2.md.
- Add a "Background reading" note at the top of TUTORIAL.md pointing to
  INTRODUCTION.md for readers unfamiliar with the underlying concepts.
- Add `docs/INTRODUCTION.md` to the docs/ section of README.md.

**Validation checklist:**

- [ ] All math rendered via the KaTeX pipeline (run `validate_katex.js` if any
      `$...$` spans are added; prefer plain English + small numeric examples over
      LaTeX where possible in this document).
- [ ] Every cited reference includes author, year, title, venue/publisher, and a
      stable URL (DOI, NIST permalink, or arXiv ID) so readers can verify.
- [ ] Toy examples verified by hand (8-bit or 16-bit FSCX, small-field DH).
- [ ] Reading time target: ≤ 45 minutes end-to-end for the target audience.

Status: **DONE** — `docs/INTRODUCTION.md` created (Parts 0–12: reading guide, bits/XOR,
GF(2^n), DH/HKEX-GF, FSCX/HSKE, non-linearity, Schnorr/HPKS, El Gamal/HPKE,
quantum threats, Ring-LWR/HKEX-RNL, code-based/Stern, suite table, glossary).
Cross-reference note added to `docs/TUTORIAL.md`.

---

## Security

### 1. RNLB=1 — sparse secrets (Critical)
**Files:** `Herradura cryptographic suite.py:85`, C `:497`

Secrets drawn from {0,1} enable sparse-secret lattice attacks. Replace with a
centered binomial distribution (η=2 or η=3), matching the Kyber baseline.

```python
def _rnl_cbd_poly(n, eta, q):
    """Centered binomial: each coeff = sum(eta bits) - sum(eta bits), mod q."""
    out = []
    for _ in range(n):
        byte_count = (2 * eta + 7) // 8
        raw = int.from_bytes(os.urandom(byte_count), 'big')
        a = bin(raw >> eta).count('1') & ((1 << eta) - 1).bit_length()
        # cleaner: count bits in two eta-bit windows
        mask = (1 << eta) - 1
        a = bin(raw & mask).count('1')
        b = bin((raw >> eta) & mask).count('1')
        out.append((a - b) % q)
    return out
```
Set `RNLB = 2` (η=2) and wire `_rnl_cbd_poly(n, RNLB, RNLQ)` instead of
`_rnl_small_poly`.

Status: **DONE (v1.5.x)** — CBD(eta=1) implemented. Chose eta=1 over eta=2 because
the deployed parameters (q=65537, p=4096) have a tight noise budget: max noise per
coefficient ≤ n·eta·q/p. Jumping to eta=2 doubles the noise floor and causes frequent
key-agreement failures. CBD(1) achieves the security goal (centered, zero-mean, proper
LWR distribution) with the same max-magnitude as the old {0,1} sampler.

---

### 2. Modular bias in `_rnl_rand_poly` (Medium)
**File:** `Herradura cryptographic suite.py:335`

`int.from_bytes(os.urandom(4), 'big') % q` with q=65537 introduces a bias of
~1/2^32 per coefficient (2^32 mod 65537 = 65536 ≠ 0). Fix with rejection sampling
using 3-byte draws (2^24 / 65537 ≈ 255.996 — negligible residual after rejection).

```python
def _rnl_rand_poly(n, q):
    threshold = (1 << 24) - (1 << 24) % q
    out = []
    while len(out) < n:
        v = int.from_bytes(os.urandom(3), 'big')
        if v < threshold:
            out.append(v % q)
    return out
```

Status: **DONE (v1.5.6)** — 3-byte (24-bit) rejection sampling implemented across all
language targets (Python, C, Go, ARM Thumb-2, NASM i386, Arduino, C tests).
Threshold = (1<<24) − (1<<24)%65537 = 16711935 (0xFF00FF); rejection probability ≈ 0.39%.
Eliminates the ~1/2^32 per-coefficient bias present in the previous 4-byte draw.

---

### 3. No per-session nonce in HSKE-NL-A1 (Medium)
**File:** `Herradura cryptographic suite.py:518–530`

Counter always starts at 0 per-session. If the same key K is reused across
sessions the keystream is identical. Fix: generate a random nonce N, derive the
session base as K XOR N, transmit N alongside ciphertext.

Status: **DONE (v1.5.9)** — Random nonce N added to HSKE-NL-A1 across all language targets
(Python, C, Go, Arduino, ARM Thumb-2, NASM i386 suite + test files). Session base is now
`base = K XOR N`; keystream is `nl_fscx_revolve_v1(base, base XOR ctr, n/4)`. N is generated
fresh each session and displayed alongside ciphertext. Eliminates keystream reuse when K is
reused across sessions.

---

### 4. Ad-hoc KDF for HKEX-RNL (Medium)
**File:** `Herradura cryptographic suite.py:554–555`

NL-FSCX v1 is used as the sole KDF with no formal PRF proof. Pass the NL-FSCX
output through SHAKE-256 for final extraction, replacing an unproven PRF claim
with a standard-model assumption.

```python
import hashlib
sk_bytes = hashlib.shake_256(nl_fscx_raw.bytes).digest(KEYBITS // 8)
```

Status: **DONE (v1.5.10)** — KDF seed fixed across all 6 language targets (suite + test files):
  seed = ROL(K, n/8);  sk = nl_fscx_revolve_v1(seed, K, n/4)
The original A₀=B=K caused fscx(K,K)=0 on step 1, making it a pure rotation (linear).
ROL(K,n/8) ≠ K ensures fscx(seed,K)≠0 from step 1, activating carry non-linearity
throughout. A second bijective pass (v2) was considered but rejected — it is invertible
for fixed K and adds no one-wayness. Note: no formal PRF proof; this is a strengthened
heuristic.

---

### 5. HPKS-NL / HPKE-NL — not truly PQC (Structural / Known)

Both protocols retain the GF(2^n)* DLP which Shor's algorithm breaks. They are
linearity-hardened classical protocols, not post-quantum. Replacing the DH
exponentiation with a lattice-based commitment (e.g., Ring-LWE-based Schnorr)
would be required for full PQC. Currently documented as a known limitation.

Status: **DEPRECATED** — No lattice-based replacements planned. Sound PQC alternatives
are already in the suite: HKEX-RNL (Ring-LWR key exchange), HPKS-Stern-F (code-based
Schnorr via Fiat-Shamir), and HPKE-Stern-F (Niederreiter KEM). HPKS-NL and HPKE-NL
remain in the suite as linearity-hardened classical protocols; the PQC claim is not
made for them.

---

## Performance

### 6. O(n²) polynomial multiplication — no NTT (High)
**Files:** `Herradura cryptographic suite.py:302–314`, C `:504–517`

Naive negacyclic poly-mul is O(n²). Since q=65537=2^16+1 is a Fermat prime,
NTT over Z_{65537} applies for any n ≤ 2^16. At n=256 this gives ~32× speedup.
Implement Cooley-Tukey NTT and replace `_rnl_poly_mul` calls.

Status: **DONE (v1.5.4)** — Cooley-Tukey NTT with negacyclic twist implemented
across all language implementations (C, Go, Python, ARM Thumb-2, NASM i386, Arduino).

---

### 7. `_m_inv` recomputes n/2−1 FSCX steps every call (Medium)
**File:** `Herradura cryptographic suite.py:225–230`

M^{-1} is a fixed linear map for a given n. Precompute it once as a set of
(rotation, sign) pairs and apply as a single pass — O(1) FSCX-equivalent cost
instead of O(n/2) iterations.

Status: **DONE (v1.5.7)** — Precomputed rotation table implemented across all
language targets. M^{-1}(X) = XOR of ROL(X,k) for k in the non-zero bits of
M^{-1}(1) = fscx_revolve(1, 0, n/2-1). For n=32: table constant 0x6DB6DB6D
(21 rotations); for n=64: 0xB6DB6DB6DB6DB6DB (43 rotations); for n=128: two
64-bit halves (85 rotations). For n=256 (C/Go/Python suite): lazy-init via
ba_fscx_revolve/FscxRevolve bootstrap on first call, cached thereafter.
Assembly (ARM Thumb-2 and NASM i386) use unrolled ROR/ROL+XOR instruction
sequences for n=32. Replaces 127 FSCX iterations (n=256) with ~170 XOR-rotation
pairs (~2n/3 density).

---

### 8. HSKE-NL-A2 decryption is quadratic (Medium, follows from #7)
**File:** `Herradura cryptographic suite.py:290–294`

`nl_fscx_revolve_v2_inv` runs r=3n/4 steps each costing n/2−1 FSCX iterations:
192 × 127 = 24,384 iterations at n=256. With precomputed M^{-1} (fix #7) this
drops to 192 iterations — linear in r.

Status: **DONE (v1.5.9)** — `nl_fscx_revolve_v2_inv` (all language targets: Python, C,
Go, Arduino, ARM Thumb-2, NASM i386) now precomputes `delta(B)` once before the loop.
Loop body is `z = y − delta; y = B XOR m_inv(z)`, eliminating one multiply-and-rotate
per step. For n=32 (assembly/Arduino/C-32): saves `r2 = steps × B*(B+1)/2 + ROL` ops.
For n=256 (Python/C/Go): saves `steps` big-integer multiply calls.

---

## Priority order

1. #1 — CBD secrets (security correctness, easy to test)
2. #2 — rand_poly bias (security correctness, one-liner)
3. #6 — NTT poly mul (biggest performance win)
4. #7 + #8 — precomputed M^{-1} (second performance win)
5. #3 — session nonce (protocol hygiene)
6. #4 — SHAKE KDF (hardening, low effort)
7. #5 — deferred

---

## Assembly Build / Logic Fixes

### A1. ARM Thumb-2 — `cbz` with high registers (build error)
**Files:** `Herradura cryptographic suite.s`, `CryptosuiteTests/Herradura_tests.s`

`cbz` (Compare and Branch if Zero) is a 16-bit Thumb instruction that only accepts
lo registers r0–r7.  The `rnl_poly_mul` function loads f[i] into r9 and g[j] into
r10, then uses `cbz r9` / `cbz r10` to skip zero coefficients — both are illegal.

Fix in each file (two occurrences each):
```asm
; Before:
    cbz     r9, rpm_outer_next
    cbz     r10, rpm_inner_next
; After:
    cmp     r9, #0
    beq     rpm_outer_next
    cmp     r10, #0
    beq     rpm_inner_next
```

Status: **DONE (v1.5.3)**

---

### A2. NASM i386 — wrong stack offset in `rnl_poly_mul` (silent logic error)
**Files:** `Herradura cryptographic suite.asm`, `CryptosuiteTests/Herradura_tests.asm`

After computing `prod mod q`, the code saves eax/ecx/edx/ebx on the stack, then
reads back the target index k = i+j.  After `pop ebx` (restoring j), the stack is:
  [esp]=k, [esp+4]=i, [esp+8]=prod

The code reads `[esp+4]` (= i) instead of `[esp]` (= k), writing every partial
product to `rnl_tmp[i]` instead of `rnl_tmp[k]`.  The polynomial product is silently
wrong.  Occurs in both the positive-index branch (.rpm_add_no_sub) and the
negative/wrap branch (.rpm_neg_no_sub).

Fix in each file (two occurrences each):
```asm
; Before:
    mov  ecx, [esp+4]   ; restore k from stack  ← actually reads i
; After:
    mov  ecx, [esp]     ; restore k from stack
```

| File | Branch | Line |
|---|---|---|
| `Herradura cryptographic suite.asm` | .rpm_add_no_sub | 1346 |
| `Herradura cryptographic suite.asm` | .rpm_neg_no_sub | 1370 |
| `CryptosuiteTests/Herradura_tests.asm` | .rpm_add_no_sub | 1183 |
| `CryptosuiteTests/Herradura_tests.asm` | .rpm_neg_no_sub | 1206 |

Status: **DONE (v1.5.3)**

---

## Test Parity (C vs Python/Go) — Improvement Backlog

Identified from cross-language analysis of v1.5.4 test files.

### Phase 1. Version banner and output label fixes (Trivial)

**Files:** `CryptosuiteTests/Herradura_tests.c`, `CryptosuiteTests/Herradura_tests.py`, `CryptosuiteTests/Herradura_tests.go`

- C and Python banners printed `v1.5.3` instead of the current version.
- C test output labels lacked `[CLASSICAL]` / `[PQC-EXT]` markers present in Python and Go.
- C section headers `"--- Security Assumption Tests ---"` and `"--- v1.5.0 NL-FSCX and PQC Tests ---"`
  differed from Python/Go equivalents.

Status: **DONE (v1.5.5)**

---

### Phase 2. Missing PQC benchmarks [22]–[25] in C (High)

**File:** `CryptosuiteTests/Herradura_tests.c`

C stops at benchmark [21]; Python and Go have four additional PQC benchmarks:
- [22] NL-FSCX v1 revolve throughput (n/4 steps, 32-bit)
- [22b] NL-FSCX v2 revolve+inv throughput (32-bit)
- [23] HSKE-NL-A1 counter-mode throughput (32-bit)
- [24] HSKE-NL-A2 revolve-mode round-trip (32-bit)
- [25] HKEX-RNL handshake throughput (n=32)

Status: **DONE (v1.5.5)**

---

### Phase 3. Multi-size GF loops for tests [1],[5]–[9],[14]–[16] in C (Medium)

**File:** `CryptosuiteTests/Herradura_tests.c`

C runs GF-heavy tests at a single fixed size; Python and Go loop over multiple sizes.
Add `gf_mul_64`/`gf_pow_64` (poly `0x1B`, `uint64_t`) and loop tests over `{32, 64}`.
For test [14] HKEX-RNL, add `n=64` variant matching Python/Go `RNL_SIZES=[32,64]`.

Status: **DONE (v1.5.5)** — Added 64-bit GF(2^64), 64-bit FSCX/NL-FSCX, and
generic-n RNL helpers. Tests [1],[5],[6] loop {32,64,256}; tests [7]–[9],[14]–[16]
loop {32,64}. Key-sensitivity PASS criterion aligned to `mean >= n/4` (Phase 5
partial fix). Generic-n uses VLA functions reusing `rnl32_ntt` for n=64 NTT.

---

### Phase 4. Multi-size FSCX loops for tests [2]–[4],[10]–[13] in C (Medium)

**File:** `CryptosuiteTests/Herradura_tests.c`

C runs FSCX-based tests at 256-bit only; Python and Go loop over `{64, 128, 256}`.
Add `fscx64`/`fscx_revolve64` (`uint64_t`) and `fscx128`/`fscx_revolve128` (`__uint128_t`),
plus matching 64/128-bit NL-FSCX variants, then loop affected tests.

Status: **DONE (v1.5.5)** — Added 128-bit `fscx128`/`fscx_revolve128`/NL-FSCX via
`__uint128_t` and `rand128()`. Tests [2]–[4] loop `{64, 128, 256}`; tests [10]–[13]
loop `{64, 128}`. 256-bit NL-FSCX deferred (requires 256-bit integer multiply).

---

### Phase 5. Test methodology alignment (Low)

**File:** `CryptosuiteTests/Herradura_tests.c`

- **[5] Key sensitivity PASS criteria**: C checks symmetric range `0.35·n ≤ mean ≤ 0.65·n`;
  Python/Go check lower bound only `mean ≥ n/4`. Align C to `mean ≥ n/4`.
- **[11] Bijectivity test**: C uses single pair-wise collision check; Python/Go sample 256 random
  `A` values per `B` with collision detection in a hash map. Upgrade C to match.

Status: **DONE (v1.5.5)** — [5] fixed in Phase 3 (criterion changed to `mean >= n/4`).
[11] upgraded to `BIJ_SAMPLES=256` random A values per B with O(n²) pairwise output
collision scan, matching Python/Go 256-sample hash-map methodology.

---

## v1.5.x Review — Findings (2026-04-24)

### 9. HSKE-NL-A1 counter=0 step-1 degeneracy (Security, High)

**Files:** C:903, Go:647, Python:642–643; all assembly targets

When `counter = 0` both arguments to `nl_fscx_revolve_v1` equal `base`, so
`FSCX(base, base) = M(base ⊕ base) = M(0) = 0`. Step 1 contributes only the
linear term `ROL(2·base, n/4)`; non-linearity accumulates from step 2 of n/4
only — the same degeneracy fixed for the HKEX-RNL KDF in v1.5.10.

Fix: use `ROL(base, n/8)` as the A (seed) argument across all languages:
```
ks[i] = nl_fscx_revolve_v1(ROL(base, n/8), base XOR i, n/4)
```
Also update SecurityProofs.md §11.3.1 formula and §11.6 table.

Status: **DONE (v1.5.13)** — `ROL(base, n/8)` seed applied across all 6 suite targets
(C, Go, Python, ARM Thumb-2, NASM i386, Arduino) and 3 test targets (C, Go, Python).
SecurityProofs.md §11.3.1 updated with new formula and seed-rotation rationale.

---

### 10. Stale `q=3329` comment in C main() (Correctness, Trivial)

**File:** `Herradura cryptographic suite.c:933`

`puts("    (Ring-LWR, ..., q=3329 ...")` but `RNL_Q = 65537` since v1.5.4.

Fix: update the string literal to `q=65537`.

Status: **DONE (v1.5.13)**

---

### 11. §11.6 KDF formula stale — missing v1.5.10 seed fix (Documentation, Trivial)

**File:** `SecurityProofs.md:1414`

Table entry still shows `KDF: sk = NL-FSCX-REVOLVE-v1(K_raw, K_raw, n/4)`.
The §11.4.2 body has the correct v1.5.10 formula but §11.6 was not updated.

Fix: replace the table entry with:
```
seed = ROL(K_raw, n/8);  sk = NL-FSCX-REVOLVE-v1(seed, K_raw, n/4)
```

Status: **DONE (v1.5.13)**

---

### 12. HSKE-NL-A2 deterministic encryption undocumented (Security/Docs, Medium)

**Files:** `SecurityProofs.md §11.3.2`; code comments in all language targets

HSKE-NL-A2 (`NlFscxRevolveV2(P, K, r)`) has no nonce — same (key, plaintext)
always produces identical ciphertext. This is not a correctness bug but must be
documented as a usage constraint: HSKE-NL-A2 must not encrypt multiple distinct
messages under the same key without external message differentiation.

Fix: add a note to §11.3.2 and to the in-code protocol comment blocks.

Status: **DONE (v1.5.14)** — Deterministic-encryption caveat added to `SecurityProofs.md §11.3.2`
and to the HSKE-NL-A2 protocol comment blocks in all six language targets (C, Go, Python,
ARM Thumb-2, NASM i386, Arduino).

---

### 13. ~~HKEX-RNL failure rate uncharacterized at deployed parameters~~ DONE (v1.5.15+v1.5.16)

**Files:** new `SecurityProofsCode/hkex_rnl_failure_rate.py`; `SecurityProofs.md §11.5 Q2`

§11.5 Q2 marks `(q=65537, n=256, p=4096)` as `⚠ pending verification`. No empirical
P(K_A ≠ K_B) row exists for the deployed parameter set.

#### Background

HKEX-RNL key agreement: both parties compute the same product `m_blind * s_A * s_B`
in `Z_q[x]/(x^n+1)`, but each side operates through a rounded copy of the other
party's public polynomial `C`:

```
Alice: K_raw_A = round_pp( s_A * lift(C_B) )   C_B = round_p(m_blind * s_B)
Bob:   K_raw_B = round_pp( s_B * lift(C_A) )   C_A = round_p(m_blind * s_A)
```

Agreement fails when the rounding error from `lift` causes any of the `key_bits`
extracted bits to differ. The error term per coefficient is:

```
ε = s_A * (lift(C_B) - m_blind*s_B)  [= s_A * rounding_noise_B]
```

With CBD(1) secrets (coefficients in {-1,0,1}), max error per output coefficient is
bounded by `n * max(rounding_noise)` which is `≤ n * q/(2p)`. Whether this stays
below the `q/(2*pp)` extraction threshold determines the failure rate.

#### Plan

**Step 1 — Write `SecurityProofsCode/hkex_rnl_failure_rate.py`**

Structure (four sections, standalone script — copy primitives from suite, do not import):

Copy these from `Herradura cryptographic suite.py`:
- `_ntt_inplace`, `_rnl_poly_mul`, `_rnl_poly_add`
- `_rnl_round`, `_rnl_lift`, `_rnl_cbd_poly`, `_rnl_rand_coeff`
- `_rnl_bits_to_bitarray` → adapt to return a plain int for speed
- `_rnl_keygen`, `_rnl_agree`

**§1 — Empirical failure rate at n=32 (baseline)**

Parameters: `q=65537, n=32, p=4096, pp=2, η=1`
Trials: 10,000 (fast; n=32 NTT is trivial)

Per trial:
1. Sample fresh `a_rand` uniform in Z_q; build `m_blind = m(x) + a_rand`
2. Call `_rnl_keygen` twice → `(s_A, C_A)`, `(s_B, C_B)`
3. Call `_rnl_agree` twice → `K_raw_A`, `K_raw_B`
4. Record: `raw_fail = (K_raw_A != K_raw_B)`, `bit_errors = popcount(K_raw_A ^ K_raw_B)`

Report:
- Failure count and rate with 95% Wilson confidence interval
- Distribution of bit-error counts among failing trials (1-bit, 2-bit, etc.)
- Worst-case error: max popcount seen

**§2 — Per-coefficient noise analysis at n=32**

For each trial (reuse the 10,000 above):
1. Compute exact products `K_exact_A = s_A * m_blind * s_B` and `K_exact_B` in Z_q
   (these are equal by ring commutativity — sanity check)
2. Compute error polynomials `e_A[i] = (K_poly_A[i] - K_exact_A[i]) mod q`
3. Map to signed range `(-q/2, q/2]`; record max absolute error seen
4. Compare against threshold `q / (2*pp)` = 65537/4 = 16384

Report: `max|e|` across all trials and coefficients. If `max|e| < 16384` consistently
then zero failures are expected (theoretical vs. empirical sanity check).

**§3 — Empirical failure rate at n=256 (deployed)**

Parameters: `q=65537, n=256, p=4096, pp=2, η=1`
Trials: 5,000 (n=256 NTT is ~8× slower than n=32; ~5 min on this hardware)

Same per-trial logic as §1. Report same metrics.

**§4 — p-sensitivity sweep at n=32**

Sweep `p ∈ {512, 1024, 2048, 4096, 8192}` with 2,000 trials each.
Goal: find the smallest p where failure rate drops to 0/2000.
This characterises the noise margin and shows whether p=4096 has headroom.

#### Step 2 — Update `SecurityProofs.md §11.5 Q2`

After running the script, add new rows to the Q2 table (currently ends at the
"Blinded m vs. fixed m" row):

```
| HKEX-RNL failure rate, (q=65537, n=32,  p=4096, η=1), 10 000 trials | X/10000 (Y%) | ... |
| HKEX-RNL failure rate, (q=65537, n=256, p=4096, η=1),  5 000 trials | X/5000  (Y%) | ... |
| Max per-coeff error |e|, (n=32, 10 000 trials)                       | Z (vs. threshold 16384) | ... |
```

Replace the `⚠ pending verification` note in the preamble with actual results.

Also update §11.6 "Parameters for HKEX-RNL" if the failure rate warrants
adjusting the recommended parameters.

#### Step 3 — Decision tree based on results

- **Rate = 0%** across all trials → document as "no failures observed; current
  parameters have adequate noise margin". Keep p=4096, no reconciliation needed.
- **0 < Rate ≤ 0.1%** → document rate; add note that reconciliation hints would
  eliminate residual failures; acceptable for most uses without hints.
- **Rate > 0.1%** → implement NewHope-style 1-bit reconciliation hint:
  each party sends a 1-bit hint per coefficient indicating which rounding
  boundary the coefficient is near; other party uses hint to correct edge cases.
  This requires adding a `hint` output to `_rnl_keygen` and a `_rnl_reconcile`
  function to `_rnl_agree`. All language targets would need updating.

#### Files to create / modify

| File | Change |
|---|---|
| `SecurityProofsCode/hkex_rnl_failure_rate.py` | New — four-section analysis script |
| `SecurityProofs.md §11.5 Q2` | Add empirical failure-rate rows; remove ⚠ |
| `SecurityProofs.md §11.6` | Update parameters section if rate warrants it |
| `CHANGELOG.md` | Add v1.5.x entry |

If reconciliation is needed: also update all six language implementations
and their test files (C, Go, Python, ARM, NASM, Arduino).

#### Results (v1.5.15 — `hkex_rnl_failure_rate.py`)

| Section | Parameters | Failures | Rate | 95% CI |
|---|---|---|---|---|
| §1 n=32 baseline | q=65537, p=4096, η=1, 10 000 trials | 204/10 000 | **2.04%** | 1.78–2.34% |
| §3 n=256 deployed | q=65537, p=4096, η=1, 5 000 trials | 1862/5 000 | **37.24%** | 35.9–38.6% |

§2 noise analysis (n=32):
- Max |error_A−error_B| = 134 (0.82% of threshold 16,384) — individual errors are small
- Near-boundary events = 316/320,000 coeff-trials (0.099%) → P(any fail in 32 coeffs) ≈ 3%
- Root cause: ring convolution accumulates n error terms, so P ∝ √n per coefficient

§4 p-sensitivity (n=32, 2,000 trials):
- p=512: 14.70%  p=1024: 8.45%  p=2048: 4.40%  p=4096: 2.20%  p=8192: 0.80%
- No tested p achieves <1%; larger p would also weaken security/compress less

**Verdict: FAIL — architectural fix required.** The single-polynomial structure
means per-coefficient error grows as O(√n·q/(2p)), overwhelming extraction boundaries
at n=256. Increasing p is ineffective.

#### Updated plan — Peikert cross-rounding reconciliation (verified correct, v1.5.16)

Required for all 6 language targets (C, Go, Python, ARM, NASM, Arduino), suite + tests.

**Root cause recap:** Per-coefficient error grows as O(√n·q/(2p)) due to ring
convolution. Measured max|K_poly_A[i]−K_poly_B[i]| = 134 at n=32; scaling √8
gives ≈379 at n=256. Peikert safety margin is q/8 = 8192. Since 379 ≪ 8192,
a 1-bit hint per coefficient guarantees zero failures.

**Peikert cross-rounding algorithm (exact formulas, verified):**

```python
def _rnl_hint(K_poly, q):
    """1-bit hint per coefficient — encodes which side of q/4 boundary c falls on."""
    return [((4 * c + q // 2) // q) % 4 % 2 for c in K_poly]

def _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits):
    """Extract key bits using the reconciler's hint. Both parties call this
    with the same hint (from the reconciler) and their own K_poly."""
    qh = q // 2
    val = 0
    for i, (c, h) in enumerate(zip(K_poly[:key_bits], hint[:key_bits])):
        b = ((2 * c + h * qh + qh) // q) % pp  # NewHope cross-rounding
        if b:
            val |= (1 << i)
    return val
```

**Correctness proof sketch (NewHope cross-rounding):** The extraction formula
`b = floor((2c + h*(q/2) + q/2) / q) % pp` is equivalent to
`round((c + h*q/4) / (q/2)) mod 2`, which places the bit=1 extraction window at
`[q/4, 3q/4)` for h=0 and `[0, q/2) ∪ [3q/4, q)` for h=1. If
|K_poly_A[i] − K_poly_B[i]| < q/4, both parties compute the same b. Guaranteed
since max measured error (≈379) ≪ q/4 (16384).

**Protocol flow (one-party hint: "reconciler" Alice generates, both use):**

In the local demo (non-interactive, both parties on same machine):
```
K_poly_A = s_A * lift(C_B)  [Alice's raw key polynomial]
K_poly_B = s_B * lift(C_A)  [Bob's raw key polynomial]
hint_A    = _rnl_hint(K_poly_A, q)          [Alice generates hint from her K_poly]
K_raw_A   = _rnl_reconcile_bits(K_poly_A, hint_A, q, pp, key_bits)  [Alice extracts]
K_raw_B   = _rnl_reconcile_bits(K_poly_B, hint_A, q, pp, key_bits)  [Bob uses hint_A]
# K_raw_A == K_raw_B guaranteed
```

In an interactive protocol:
- Round 1: Alice→Bob: C_A ; Bob→Alice: C_B (simultaneous or sequential)
- After Bob receives C_A: Bob computes K_poly_B and generates hint_B
- Round 2: Bob→Alice: hint_B (n/8 extra bytes: 4 B at n=32, 32 B at n=256)
- Alice computes K_poly_A, uses hint_B to extract K_raw_A
- Bob uses hint_B (his own hint) to extract K_raw_B
In this variant Bob is the reconciler; swap "A"/"B" labels to match code convention.

For the suite demo the non-interactive flow is used; the hint array is returned by
the reconciler call of `_rnl_agree` and consumed by the other call.

**Implementation steps per language target:**

**1. Python** (`Herradura cryptographic suite.py` + `CryptosuiteTests/Herradura_tests.py`):
   - Add `_rnl_hint(K_poly, q)` — 1-liner list comprehension above
   - Add `_rnl_reconcile_bits(K_poly, hint, q, pp, key_bits)` — loop above
   - Modify `_rnl_agree(s, C_other, q, p, pp, n, key_bits, hint=None)`:
     - compute K_poly as before
     - if hint is None: generate hint from own K_poly (reconciler path); return (K_raw, hint)
     - if hint provided: use it to extract K_raw (non-reconciler path); return K_raw
   - Update HKEX-RNL call site in `main()` to pass hint from Alice to Bob

**2. C** (`Herradura cryptographic suite.c` + `CryptosuiteTests/Herradura_tests.c`):
   - Add `void rnl_hint(uint32_t *K_poly, uint8_t *hint, int n, uint32_t q)` function
   - Add `uint32_t rnl_reconcile_bits(uint32_t *K_poly, uint8_t *hint, uint32_t q,
     uint32_t pp, int key_bits)` function
   - Modify `rnl_agree` signature: add `uint8_t *hint_in` (NULL = reconciler path, also
     writes hint_out); add `uint8_t *hint_out` output parameter
   - Update all call sites

**3. Go** (`Herradura cryptographic suite.go` + `CryptosuiteTests/Herradura_tests.go`):
   - Add `func rnlHint(kPoly []uint32, q uint32) []uint8`
   - Add `func rnlReconcileBits(kPoly []uint32, hint []uint8, q, pp uint32, keyBits int) *big.Int`
   - Modify `rnlAgree` to return `(key *big.Int, hint []uint8)` on reconciler path,
     accept hint as parameter on non-reconciler path

**4. ARM Thumb-2** (`Herradura cryptographic suite.s` + `CryptosuiteTests/Herradura_tests.s`):
   - Add `rnl_hint` subroutine: loop n coeff; each: `4*c + q/2 → udiv → %4 → %2`
     (use `udiv` + multiply-back to avoid software division; or use the
     `(4c + q/2) * inv_q >> 32` reciprocal trick since q=65537 is fixed)
   - Add `rnl_reconcile_bits` subroutine: loop key_bits; compute r, add h, halve, mod pp
   - Update `rnl_agree` call convention: pass hint pointer in r3; NULL = reconciler path

**5. NASM i386** (`Herradura cryptographic suite.asm` + `CryptosuiteTests/Herradura_tests.asm`):
   - Add `rnl_hint` proc: loop with `4*c + (q/2)` → `div` by q → `%4` → `%2`
   - Add `rnl_reconcile_bits` proc
   - Update `rnl_agree` stack frame to pass hint ptr; NULL = reconciler path

**6. Arduino** (`Herradura cryptographic suite.ino`):
   - Same changes as C; uint32_t types throughout; n=32 only

**Test updates:**
- Extend test [14] (HKEX-RNL correctness): after reconciliation is wired in, expected
  outcome is 0 failures across all trials. Update PASS criterion from "≤5%" to "0 failures".
- Add §5 to `SecurityProofsCode/hkex_rnl_failure_rate.py`: run 10,000 trials (n=32) and
  10,000 trials (n=256) with reconciliation enabled; assert failure count == 0; report
  confirmation message.

**Documentation updates:**
- `SecurityProofs.md §11.4.2`: add subsection showing hint generation formula and
  reconciled extraction; cite Peikert 2014 / NewHope 2016 for algorithm lineage
- `SecurityProofs.md §11.6`: update failure rate entry from "37.24%" to
  "0 (guaranteed by Peikert cross-rounding; see §11.4.2)"
- `CHANGELOG.md`: add v1.5.16 entry

**Hint transmission overhead:** n bits = n/8 bytes per exchange.
- n=32: 4 bytes added to reconciler's message
- n=256: 32 bytes added to reconciler's message

Status: **COMPLETE** — Analysis in v1.5.15; Peikert reconciliation deployed in v1.5.16 across all 6 targets. Failure rate: 0%.

---

### 14. NTT twiddle recomputation per poly-multiply call (Performance, Medium)

**Files:** C `rnl_ntt` / `rnl_poly_mul`; Go `rnlNTT` / `rnlPolyMul`

`rnl_poly_mul` recomputes ψ and ψ⁻¹ via `rnl_mod_pow` on every call. Inside
`rnl_ntt`, each of the 8 butterfly stages calls `rnl_mod_pow` once for the stage
twiddle `w`. For ≈4 poly-mul calls per HKEX-RNL exchange, this is ≈40
`rnl_mod_pow` invocations (each up to 16 modular multiplications) on top of the
butterfly work.

Fix: precompute a lazy-initialized static table (same pattern as `m_inv_ba`):
- `psi_powers[n]` — twist/untwist values for pre/post-NTT phase
- `stage_w[log₂n]` — per-stage ω values for forward and inverse NTT

Expected gain: ~5–10% reduction in HKEX-RNL exchange time.

Status: **DONE (v1.5.17)** — Lazy-initialized static table (`rnl_tw` in C, `rnlTwCache` map in Go)
eliminates all `rnl_mod_pow` calls per `rnl_poly_mul` after first use. Implemented for C suite/tests
(two-entry struct array for n∈{32,64}) and Go suite/tests (map keyed by n). Observed Go bench [25]
n=64 speedup: 3.15 K → 4.72 K ops/sec (+50%).

---

### 15. Fermat prime fast modulo for NTT inner loops (Performance, Medium)

**Files:** C `rnl_ntt` inner loop; Go `rnlNTT` inner loop

q = 65537 = 2^16 + 1 is a Fermat prime. The NTT butterfly loops execute
`(uint64_t)a * b % RNL_Q` which issues a 64-bit division. The reduction is
divisionless for this prime:

```c
static inline uint32_t rnl_mod_q(uint64_t x) {
    uint32_t lo = x & 0xFFFF, hi = (x >> 16) & 0xFFFF, top = (x >> 32) & 1;
    int32_t r = (int32_t)(lo - hi + top);
    if (r < 0)      r += RNL_Q;
    if (r >= RNL_Q) r -= RNL_Q;
    return (uint32_t)r;
}
```

Each NTT call performs n/2 × log₂n = 1024 butterfly steps with 1–2 modular
reductions each. Replacing `% RNL_Q` in the hot path eliminates all divides.
Expected speedup: ~2× for the NTT, ~1.3–1.5× for a full HKEX-RNL exchange.

Status: **DONE (v1.5.20 Batch 8)**

---

### 16. `rnl_cbd_poly` bit-per-byte inefficiency (Performance, Low)

**Files:** C `rnl_cbd_poly`; Go `rnlCBDPoly`; Python `_rnl_cbd_poly`

With η=1 each coefficient needs 2 bits (one `a` bit, one `b` bit). Current code
reads 1 byte per coefficient and uses only bits 0–1 → 75% of urandom entropy
discarded. For n=256 that is 256 bytes drawn when 64 would suffice.

Fix: process 4 coefficients per byte (bit-pairs at positions 0-1, 2-3, 4-5, 6-7).
Apply to C, Go, Python. Note: byte-for-byte output changes — update affected tests.

Status: **DONE (v1.5.22)** — 4-coefficients-per-byte packing implemented in C (`rnl_cbd_poly`,
`rnl32_cbd_poly`, `rnl_cbd_poly_n`), Go (`rnlCBDPoly`), and Python (`_rnl_cbd_poly`). C test
file uses one `rand32()` word per 16 coefficients; Python retains a general path for η>1 while
using the fast byte-packed path for η=1.

---

---

### 17. Multi-size key-length standardization (Test & Suite Coverage)

**Goal:** Every protocol tested at 32, 64, 128, and 256 bits across all language targets
where algorithmically feasible. Larger key sizes catch bugs only visible at scale and
demonstrate production-grade security margins.

**Current gaps (as of v1.5.19):**

| Target | Gap |
|---|---|
| Python tests | `GF_SIZES=[32,64]`, `RNL_SIZES=[32,64]`, Stern-F at [32,64] only |
| Python suite | HPKE-Stern-F demo only at N=32 (brute-force) |
| C tests [7]-[9],[14]-[16] | `sizes[]={32,64}` — missing 128, 256 |
| C tests [10]-[13] NL-FSCX | `sizes[]={64,128}` — missing 256 |
| C HKEX-RNL | NTT twiddle entries only for n=32,64 — missing 128, 256 |
| C Stern-F tests [17] | Only N=32; missing 64, 128, 256 helpers |
| C suite demo | HPKE-Stern-F N=32 only; missing N=256 known-e' |

**Batch plan (each batch = one commit/version bump):**

#### Batch 1 — Python (v1.5.20) ✅
- `CryptosuiteTests/Herradura_tests.py`: `GF_SIZES` → [32,64,128,256]; `RNL_SIZES` → [32,64,128,256]; test [17] `SDF_SIZES` → [32,64,128,256]; test [18] add known-e' decap for N=64,128,256 (add `hpke_stern_f_encap_with_e` + `hpke_stern_f_decap_known` helpers)
- `Herradura cryptographic suite.py`: add N=256 known-e' HPKE-Stern-F demo

#### Batch 2 — C tests: NL-FSCX 256-bit (v1.5.20) ✅
- Tests [10]-[13]: expanded `sizes[]={64,128}` → `{64,128,256}`; added `ba_sub256`, `ba_mul256`, `m_inv_ba` (256-bit M^{-1} table from GCD), `nl_fscx_v2_ba`, `nl_fscx_v2_inv_ba`, `nl_fscx_revolve_v2_ba`, `nl_fscx_revolve_v2_inv_ba`

#### Batch 3 — C tests: GF(2^128) arithmetic (future)
- Implement `gf_mul_128(a,b,poly,n)` using `__uint128_t` carryless multiply with poly `x^128+x^7+x^2+x+1` (constant 0x87 in low 64 bits)
- Implement `gf_pow_128`
- Expand tests [1],[5]-[9],[15],[16] to include 128-bit
- Add 256-bit: use existing `BitArray` `gf_mul_ba`/`gf_pow_ba` if present, or add them

#### Batch 4 — C tests: HKEX-RNL 128/256 (future)
- Add NTT twiddle table entries for n=128 and n=256 (negacyclic roots under RNLQ=65537)
- Expand `rnl_sizes[]={32,64}` → `{32,64,128,256}` in test [14] and bench [25]

#### Batch 5 — C tests: Stern-F multi-size (future)
- Add `stern_matrix_row_64`, `stern_syndrome_64`, `stern_rand_error_64`, `hpks_stern_f_sign_64`, `hpks_stern_f_verify_64` helpers at N=64
- Test [17]: expand to loop [32,64]; raise `SDF_TEST_ROUNDS` 4→8
- HPKE-Stern-F test [18]: add known-e' path for N=64

#### Batch 6 — C suite: HPKE-Stern-F N=256 demo (future)
- Add N=256 known-e' demo after existing N=32 brute-force demo in `Herradura cryptographic suite.c`

**Notes:**
- Python arbitrary precision: no code constraints; all sizes trivially work, bounded only by `-t` time budget
- C `__uint128_t`: available on GCC/Clang for 128-bit carryless multiply; not available in assembly targets
- Assembly and Arduino targets stay at N=32 (resource constrained); no changes planned

Status: **Batches 1-6 DONE (v1.5.20)**

---

### 18. Parameterized integer arithmetic layer for C (suite + tests)
**Files:** `Herradura cryptographic suite.c`, `CryptosuiteTests/Herradura_tests.c`

#### Problem

The C suite is hard-wired to `KEYBITS=256` via the `BitArray` typedef.  All
arithmetic — GF field ops, Schnorr scalar ops, NL-FSCX delta math — is
manually specialised for that one width.  The C tests work around this by
maintaining *four separate fixed-size code paths* (32/64/128/256-bit) for every
protocol function, creating a combinatorial maintenance burden and leaving any
new key size (e.g. 512-bit) requiring yet another copy.

Python avoids this entirely because `int` is arbitrary-precision natively:

```python
s_s = (k_s.uint - a.uint * e_s.uint) % ORD   # Schnorr, any bit width
```

The C equivalent today requires `ba_mul_mod_ord` (256-bit only) in the suite,
and `mul128_mod_ord128` + size dispatch in the tests — two separate
implementations for two sizes, with no 32-bit or 64-bit equivalent in the suite
at all.

#### What already exists (do not re-implement)

| Scope | What's there | Width |
|---|---|---|
| Suite | `ba_add256`, `ba_sub256`, `ba_mul256_lo`, `ba_mul_mod_ord`, `ba_sub_mod_ord` | 256-bit only |
| Suite | `ba_xor`, `ba_equal`, `ba_is_zero`, `ba_popcount`, `ba_shr1`, `ba_shl1`, `ba_rol_k` | 256-bit only |
| Suite | `gf_mul_ba`, `gf_pow_ba` | 256-bit only |
| Suite | `nl_fscx_*_ba` functions | 256-bit only |
| Tests | `ba_add256`, `ba_sub256`, `ba_mul256` | 256-bit only |
| Tests | `gf_mul_32/64`, `gf_pow_32/64/128` | size-specific |
| Tests | `mul128_mod_ord128` | 128-bit only |
| Tests | `fscx_revolve32/64/128`, `nl_fscx_revolve_v1/v2_32/64/128` | size-specific |

#### Goal

A single `bn_*` / `gf_n_*` API where every operation takes an `int nbits`
parameter (always a multiple of 8, ≤ 512).  Numbers are represented as
big-endian `uint8_t` arrays; no dynamic memory is used; all buffers are
caller-allocated.  The cascade of size-specific functions in both files
collapses into parameterised equivalents that a simple `for (int nbits : sizes)`
loop can call directly.

#### API design

Represent a number as `(uint8_t *buf, int nbits)`.  Routines are plain C
functions with signature `void bn_foo(uint8_t *dst, const uint8_t *a,
const uint8_t *b, int nbits)`.  `nbytes = nbits / 8` is always derived
internally.  A companion 512-bit scratch buffer is used for full-width
intermediate products (no heap allocation).

```c
/* Maximum supported width (for 2·n-bit products of 256-bit operands) */
#define BN_MAX_BITS  512
#define BN_MAX_BYTES (BN_MAX_BITS / 8)
```

#### Operations to implement

**Group A — Bit-string primitives**
(Existing `ba_*` functions are 256-bit only; generalise to arbitrary nbits.)

| Function | Signature | Notes |
|---|---|---|
| `bn_zero` | `(uint8_t *a, int nbits)` | memset 0 |
| `bn_copy` | `(uint8_t *dst, const uint8_t *src, int nbits)` | memcpy |
| `bn_xor` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | bitwise XOR |
| `bn_equal` | `→ int (const uint8_t *a, const uint8_t *b, int nbits)` | constant-time |
| `bn_is_zero` | `→ int (const uint8_t *a, int nbits)` | |
| `bn_popcount` | `→ int (const uint8_t *a, int nbits)` | |
| `bn_flip_bit` | `(uint8_t *dst, const uint8_t *src, int bit, int nbits)` | |
| `bn_shl1` | `→ int (uint8_t *a, int nbits)` | returns carry |
| `bn_shr1` | `→ int (uint8_t *a, int nbits)` | returns shifted-out bit |
| `bn_rol_k` | `(uint8_t *dst, const uint8_t *src, int k, int nbits)` | cyclic left-rotate by k bits |

**Group B — Integer arithmetic mod 2^n**
(Needed for NL-FSCX v2 delta: `b*(b+1)/2 mod 2^n`, and for `(a+b) mod 2^n` in NL-FSCX v1.)

| Function | Signature | Notes |
|---|---|---|
| `bn_add` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | add mod 2^n |
| `bn_sub` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | sub mod 2^n |
| `bn_mul_lo` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | a·b mod 2^n (low half only; schoolbook) |
| `bn_mul_full` | `(uint8_t *full2n, const uint8_t *a, const uint8_t *b, int nbits)` | full 2n-bit product into 2·nbytes buffer; needed by Groups C and D |

**Group C — Arithmetic mod (2^n − 1)**
(Needed for Schnorr/HPKS scalar: `s = (k − a·e) mod (2^n − 1)`.)

| Function | Signature | Notes |
|---|---|---|
| `bn_mul_mod_ord` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | a·b mod 2^n−1; uses `bn_mul_full` internally |
| `bn_sub_mod_ord` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | (a−b) mod 2^n−1 |
| `bn_add_mod_ord` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | (a+b) mod 2^n−1 (not currently used; include for completeness) |

Reduction rule: `lo + hi → result`; if carry → `result + 1`; if `result == 2^n−1 → 0`.
This is the pattern already in `ba_mul_mod_ord` and `mul128_mod_ord128`.

**Group D — GF(2^n) field arithmetic**
(Carryless polynomial multiply mod the irreducible polynomial for each supported width.)

| Function | Signature | Notes |
|---|---|---|
| `gf_poly_for` | `→ const uint8_t* (int nbits)` | returns precomputed poly bytes for nbits ∈ {32,64,128,256} |
| `bn_gf_mul` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` | carryless multiply mod `gf_poly_for(nbits)` |
| `bn_gf_pow` | `(uint8_t *dst, const uint8_t *base, const uint8_t *exp, int nbits)` | square-and-multiply using `bn_gf_mul` |

Poly constants (already defined piecemeal — consolidate into one table):
- n=32:  `x^32+x^22+x^2+x+1` → low 4 bytes `0x00400007`
- n=64:  `x^64+x^4+x^3+x+1` → low 8 bytes `0x1B`
- n=128: `x^128+x^7+x^2+x+1` → low 16 bytes `0x87`
- n=256: `x^256+x^10+x^5+x^2+1` → low 32 bytes `0x0425`

**Group E — FSCX and NL-FSCX**
(Currently 4 separate families of fixed-size functions; unify under `nbits`.)

| Function | Signature |
|---|---|
| `bn_fscx` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` |
| `bn_fscx_revolve` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int steps, int nbits)` |
| `bn_m_inv` | `(uint8_t *dst, const uint8_t *src, int nbits)` | bootstrap from `bn_fscx_revolve(1, 0, nbits/2−1)` |
| `bn_nl_fscx_v1` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` |
| `bn_nl_fscx_revolve_v1` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int steps, int nbits)` |
| `bn_nl_fscx_v2` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nbits)` |
| `bn_nl_fscx_v2_inv` | `(uint8_t *dst, const uint8_t *y, const uint8_t *b, int nbits)` |
| `bn_nl_fscx_revolve_v2` | `(uint8_t *dst, const uint8_t *a, const uint8_t *b, int steps, int nbits)` |
| `bn_nl_fscx_revolve_v2_inv` | `(uint8_t *dst, const uint8_t *y, const uint8_t *b, int steps, int nbits)` |

NL-FSCX v1 uses: `bn_add` (mod 2^n) + `bn_rol_k(n/4)` + `bn_fscx`.
NL-FSCX v2 uses: `bn_mul_lo` + `bn_add` for delta, `bn_m_inv` for inverse.

#### Suggested implementation batches

| Batch | Scope | Prerequisite |
|---|---|---|
| A | Groups A+B: primitives + mod-2^n arithmetic | none |
| B | Group C: mod-ord arithmetic | Batch A (`bn_mul_full`) |
| C | Group D: GF field ops | Batch A (`bn_shr1`, `bn_shl1`, `bn_xor`) |
| D | Group E: FSCX + NL-FSCX | Batches A+B+C |
| E | Replace fixed-size dispatches in suite | Batches A–D |
| F | Replace fixed-size dispatches in tests | Batches A–D |

#### Notes and constraints

- **No dynamic allocation.** All functions use caller-supplied buffers or
  on-stack temporaries.  `bn_mul_full` needs a `2·nbytes` scratch buffer
  (max 64 bytes for 256-bit operands).
- **Byte granularity.** `nbits` is always a multiple of 8 (enforced by
  assert or silently rounded down).  This matches every key size in the suite
  (32, 64, 128, 256, and any future power-of-two).
- **No new files.** Both `bn_*` headers and implementations live inline in
  their respective `.c` files, matching the existing single-file style.
- **Assembly and Arduino targets** are out of scope; they remain at fixed 32-bit
  width.  The `bn_*` layer is C-only.
- **M^{-1} table** (`bn_m_inv`) must cache rotation offsets per `nbits` to
  avoid O(n^2) bootstrapping on every call.  Use a static array indexed by
  `nbits/32` (4 entries: 32,64,128,256).
- **Schnorr at 256-bit** — `ba_mul_mod_ord`/`ba_sub_mod_ord` in the suite
  already handle this; `bn_mul_mod_ord`/`bn_sub_mod_ord` become their direct
  replacements.
- **Schnorr at 32/64-bit** — the tests currently use `__uint128_t` to hold
  the intermediate `a*e` product; `bn_mul_full` is the generalisation.
- **Backward compatibility** — keep existing `ba_*` wrappers as thin aliases
  over `bn_*(..., KEYBITS)` so the rest of the suite compiles unchanged.

Status: **DONE** (v1.5.20 Batch 7) — `bn_*` layer added to `CryptosuiteTests/Herradura_tests.c`; tests [7],[8],[15] extended to {32,64,128,256}.

---

---

### 19. Stale version banners — v1.5.18 should be v1.5.20 (Maintenance, Trivial)

**Discovered:** full-suite compile+run check, 2026-04-30.

The following files still print or contain `v1.5.18` in their header comments
and/or runtime-printed banner strings. The project is at v1.5.20.

| File | Location | Type |
|------|----------|------|
| `Herradura cryptographic suite.go` | line 1 header comment | comment only |
| `CryptosuiteTests/Herradura_tests.go` | line 2 comment + printed banner | comment + output |
| `CryptosuiteTests/Herradura_tests.py` | header comment + printed banner | comment + output |
| `Herradura cryptographic suite.s` | line 1 comment + `fmt_header` string | comment + output |
| `CryptosuiteTests/Herradura_tests.s` | line 1 comment + `fmt_hdr` string | comment + output |
| `Herradura cryptographic suite.asm` | line 1 comment + `hdr` data string | comment + output |
| `CryptosuiteTests/Herradura_tests.asm` | line 1 comment + `hdr` data string | comment + output |
| `Herradura cryptographic suite.ino` | line 1 header comment | comment only |
| `CryptosuiteTests/Herradura_tests.ino` | line 1 header comment | comment only |

Fix: update all `v1.5.18` occurrences in the listed positions to `v1.5.20`.

Status: **DONE (v1.5.21)** — All nine files updated to v1.5.21 (current version at time of fix):
header comments, runtime-printed banners, and `fmt_header`/`hdr` data strings in assembly targets.
Historical changelog entries (e.g. `v1.5.18: HPKS-Stern-F...`) left unchanged.

---

### 20. Python suite HKEX-RNL demo label prints q=3329 (should be q=65537) (Correctness, Trivial)

**Discovered:** full-suite compile+run check, 2026-04-30.

**File:** `Herradura cryptographic suite.py:953`

The print statement reads:
```python
print("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=256, q=3329 — may be slow)")
```
but `RNLQ = 65537` (line 147). The same bug was fixed in C at v1.5.13 (TODO #10),
but the Python file was not updated at that time.

Fix: change `q=3329` to `q=65537` in that one print string.

Status: **DONE (v1.5.21)** — `Herradura cryptographic suite.py:953` updated.

---

### 21. NASM i386 HKEX-RNL session key is all-zeros for fixed test vectors (Investigation, Medium)

**Discovered:** full-suite compile+run check, 2026-04-30.

The i386 suite (`Herradura cryptographic suite.asm`) prints:
```
sk (Alice)   : 0x00000000
sk (Bob)     : 0x00000000
+ raw key bits agree!
```
The ARM suite computes non-zero keys (KA=KB=0x7ff5fff9, sk=0x01250a86) for the
same Ring-LWR protocol with n=32. Both use identical fixed private scalars
(`a_priv=0xDEADBEEF`, `b_priv=0xCAFEBABF`).

Possible causes:
1. The i386 PRNG (`prng_next`) produces a degenerate polynomial sequence whose
   raw reconciled bits happen to be all-zero (statistically possible but unlikely
   for the same constants).
2. The i386 KDF `nl_fscx_revolve_v1(ROL32(K,4), K, I)` correctly produces 0 when
   the raw key is 0 (correct behavior for a zero input).
3. The i386 `rnl_rand_poly` or `rnl_cbd_poly` are seeded differently from ARM,
   giving different private polynomials → different raw key.

Investigation: add intermediate printout of `val_KA` and `val_KB` (the raw
reconciled bits before KDF) to confirm whether the raw key is actually 0 or
only the derived sk is 0. If KA=KB=0, trace the polynomial generation PRNG state.

Status: **DONE (v1.5.22)** — Root cause: triple-division bug in `rnl_round` in
`Herradura cryptographic suite.asm`. After computing `floor(...)` with `div ecx`,
a spurious second `xor edx, edx; div ecx` block zeroed `edx` (the `% to_p` result)
before a redundant third division, causing every coefficient to return 0. Fix:
removed the extra `xor edx, edx; div ecx` block from the `% to_p` section.
The NASM tests file already had the correct two-division form and was not affected.

---

### 22. ARM vs NASM i386 HSKE-NL-A2 cross-implementation ciphertext mismatch (Correctness, Medium)

**Discovered:** full-suite compile+run check, 2026-04-30.

For the same inputs (key=HKEX-GF sk=0xd3db6bc3, plain=0xdeadc0de, r=24 steps):

| Target | E (ciphertext) | D (plaintext) |
|--------|---------------|---------------|
| ARM Thumb | 0x624dd664 | 0xdeadc0de ✓ |
| NASM i386 | 0x633a13c8 | 0xdeadc0de ✓ |

Both self-decrypt correctly, but they are cross-incompatible: an ARM-encrypted
message cannot be decrypted by i386 and vice versa.

Notably, HPKE-NL (which also uses NL-FSCX v2 internally) produces the same
ciphertext in both targets (0x56d252a7), so the discrepancy is specific to
how HSKE-NL-A2 invokes the function (different key or step parameter).

**Files:** `Herradura cryptographic suite.s` vs `Herradura cryptographic suite.asm`

Investigation steps:
1. Verify both use r=24 for HSKE-NL-A2 (C definition: r = 3·n/4 = 24 for n=32).
2. Compare the `nl_fscx_revolve_v2` loop bodies byte-by-byte between the two files.
3. Run the C reference with the same 32-bit inputs to determine the ground-truth
   expected ciphertext.

**Root cause (found in v1.5.21):** ARM HSKE-NL-A2 used `#I_VALUE` (=8) for both
encrypt and decrypt instead of `#R_VALUE` (=24). NASM correctly used `R_VALUE`.
C reference confirms `R_VALUE` (3·n/4) is the protocol-specified parameter for HSKE-NL-A2.
HPKE-NL was unaffected because it legitimately uses `I_VALUE` (n/4).

Status: **DONE (v1.5.21)** — `Herradura cryptographic suite.s` HSKE-NL-A2 call sites
(encrypt + decrypt) changed from `mov r2, #I_VALUE` to `mov r2, #R_VALUE`; comments updated.

---

### 23. Go tests HKEX-RNL test [14] limited to n=32,64 — C and Python cover n=128,256 (Test Coverage, Low)

**Discovered:** full-suite compile+run check, 2026-04-30.

`CryptosuiteTests/Herradura_tests.go` test [14] iterates `nSizes := []int{32, 64}`.
The C and Python test suites both cover n=32,64,128,256. The Go `rnlNTT` /
`rnlPolyMul` functions are not size-restricted (they use a generic map-based
twiddle cache), so extending coverage requires only adding 128 and 256 to the
test loop — no implementation changes.

**File:** `CryptosuiteTests/Herradura_tests.go`

Fix: change `nSizes := []int{32, 64}` to `nSizes := []int{32, 64, 128, 256}`
in test [14], and verify the printed label matches ("ring sizes [32 64 128 256]").

Also update the description comment:
`(ring sizes [32 64]; ...)` → `(ring sizes [32 64 128 256]; ...)`

Status: **DONE (v1.5.22)** — `rnlSizes` changed to `[]int{32, 64, 128, 256}` in
`CryptosuiteTests/Herradura_tests.go`; printed label and benchmark loop both use
the same variable, so bench [25] coverage also expanded automatically.

---

---

### 24. C binary silently overwritten by `go build` — add `_c` suffix and guard (Build, Medium)

**Discovered:** 2026-04-30. Root cause confirmed by `file` output on the affected binaries.

#### Root cause

`go build file.go` (without `-o`) names its output after the source file stem,
producing an executable with the same path as the C build:

| Source file | `go build` default output | C build output (`gcc -o`) |
|-------------|--------------------------|--------------------------|
| `Herradura cryptographic suite.go` | `Herradura cryptographic suite` | `Herradura cryptographic suite` |
| `CryptosuiteTests/Herradura_tests.go` | `CryptosuiteTests/Herradura_tests` | `CryptosuiteTests/Herradura_tests` |

When both builds run in parallel (or when `go build` is invoked without `-o`
outside of `build_go.sh`), the Go binary silently overwrites the C binary.
The resulting ~2.4 MB statically linked Go executable is mistaken for the C build.

Note: `build_go.sh` already uses `-o "..._go"` correctly. The problem occurs only
when raw `go build file.go` is called without `-o`.

#### Impact in this session

During the full-suite test run on 2026-04-30, six build commands ran in parallel.
Go builds finished after C builds, overwriting both C binaries. Consequently:

- `"Herradura cryptographic suite"` → ran as Go binary (confirmed by `file`)
- `CryptosuiteTests/Herradura_tests` → ran as Go binary (Go banner "v1.5.18", Go-speed
  benchmarks ~8–10× lower than C, ring sizes [32,64] not [32,64,128,256])

The **Batch 8 correctness and benchmark results** (77.3 K ops/sec HKEX-RNL, all 18
tests PASS) are **valid**: they were produced by the compound command
`gcc ... && ./CryptosuiteTests/Herradura_tests -t 3.0` which recompiles C
atomically before running, precluding a Go overwrite in that same shell.

After restoring the C binaries and re-running (`-t 2.0`), all 18 tests pass and
HKEX-RNL is confirmed at 77.9 K ops/sec.

#### Fix plan

**Option A — Add `_c` suffix to C binaries (recommended)**

Give C binaries an explicit `_c` suffix so all six targets are symmetric:
`_c`, `_go`, `_arm`, `_i386`, `_avr.elf`, and `_arm` already follow this pattern.

Files to change:
1. `build_c.sh` — change `SUITE_BIN` and `TESTS_BIN` to
   `"Herradura cryptographic suite_c"` and `"CryptosuiteTests/Herradura_tests_c"`
2. `README.md` — update all C build/run examples to use the `_c` suffix
3. `CLAUDE.md` — update Build Commands section with `_c` suffix names, and add a
   note: **"Never invoke `go build file.go` without `-o`; use `build_go.sh` or
   `go build -o name_go file.go` to avoid overwriting C binaries."**

**Option B — Document-only guard (minimal)**

Keep bare names for C binaries. In `CLAUDE.md` add a prominent warning:

> **Build collision hazard:** `go build file.go` (without `-o`) names its output
> after the source stem, identical to the C binary path. Always use `build_go.sh`
> or pass `-o "name_go"` explicitly when invoking `go build` directly.

Option A is preferred: it eliminates the hazard structurally rather than relying
on human discipline. Option B is a viable fallback if downstream scripts depend
on the current C binary names.

#### Verification

After implementing option A:
1. `file "Herradura cryptographic suite_c"` → ELF dynamically linked (not Go BuildID)
2. `ls -lh "Herradura cryptographic suite_c"` → ~70 K (not ~2.4 MB)
3. `CryptosuiteTests/Herradura_tests_c -t 2.0` → `v1.5.20` C banner, all 18 PASS

Status: **DONE (v1.5.20 Batch 9)** — Option A implemented: `build_c.sh`, `README.md`, and `CLAUDE.md`
updated; C binaries now use `_c` suffix throughout.

---

## New Features

### 25. HerraduraCli — OpenSSL-style command-line tool (Python, initial)

**Goal:** A `herradura` Python CLI in a new `HerraduraCli/` subdirectory that exposes all
non-broken Herradura protocols through an interface analogous to `openssl enc`, `openssl dgst`,
`openssl genpkey`, and `openssl pkey`. Keys and signatures are serialized as PEM
(base64-wrapped) or DER (binary TLV) structures with custom Herradura boundary labels.
Tests live in a new `CliTest/` directory.

**Scope:** Python only (initial version). All classical and NL/PQC protocols.
HKEX-CY excluded (proven broken in `SecurityProofsCode/hkex_cy_test.py`).
HPKS-NL / HPKE-NL included as linearity-hardened classical — not claimed quantum-resistant
(see TODO #5).

---

#### Supported protocols and subcommands

| Protocol | Category | `genpkey` | `enc`/`dec` | `sign`/`verify` | `kex` |
|---|---|---|---|---|---|
| HKEX-GF | Classical DH | — | — | — | ✓ |
| HSKE | Classical symmetric | shared key from `kex` | ✓ | — | — |
| HPKS | Classical Schnorr | ✓ | — | ✓ | — |
| HPKE | Classical El Gamal | ✓ | ✓ | — | — |
| HKEX-RNL | PQC Ring-LWR | — | — | — | ✓ |
| HSKE-NL-A1 | PQC counter-mode | shared key from `kex` | ✓ | — | — |
| HSKE-NL-A2 | PQC revolve-mode | shared key from `kex` | ✓ | — | — |
| HPKS-NL | NL Schnorr | ✓ | — | ✓ | — |
| HPKE-NL | NL El Gamal | ✓ | ✓ | — | — |
| HPKS-Stern-F | Code-based PQC ZKP | ✓ | — | ✓ | — |
| HPKE-Stern-F | Niederreiter KEM | ✓ | ✓ | — | — |

---

#### File layout

```
HerraduraCli/
  herradura.py          — CLI entry point; argparse subcommand dispatch; no crypto logic here
  codec.py              — PEM wrap/unwrap; minimal DER INTEGER/SEQUENCE encode/decode (pure Python,
                          no external deps; uses only struct/bytes)
  primitives.py         — importlib.util loader for "Herradura cryptographic suite.py";
                          re-exports all symbols needed by the CLI subcommands
CliTest/
  test_keygen.sh        — generate every key type; assert PEM headers and non-empty output
  test_encrypt.sh       — round-trip encrypt→decrypt for each enc/dec algorithm;
                          assert output matches original plaintext byte-for-byte
  test_sign.sh          — sign→verify for each signing algorithm; assert PASS on correct
                          message, assert FAIL on tampered message
  test_vectors.sh       — fixed-input regression: deterministic inputs → expected hex outputs
                          (cross-checked against direct Python suite invocation)
```

---

#### CLI interface

```bash
# Key generation — private key written as PEM; algorithm encoded in PEM boundary label
python3 herradura.py genpkey --algo hkex-gf    --bits 256 --out alice.pem
python3 herradura.py genpkey --algo hkex-rnl   --bits 256 --out alice.pem
python3 herradura.py genpkey --algo hpks        --bits 256 --out signing.pem
python3 herradura.py genpkey --algo hpks-nl     --bits 256 --out signing.pem
python3 herradura.py genpkey --algo hpks-stern  --bits 256 --out signing.pem
python3 herradura.py genpkey --algo hpke        --bits 256 --out recipient.pem
python3 herradura.py genpkey --algo hpke-nl     --bits 256 --out recipient.pem
python3 herradura.py genpkey --algo hpke-stern  --bits 256 --out recipient.pem

# Public key extraction
python3 herradura.py pkey --in alice.pem --pubout --out alice_pub.pem
python3 herradura.py pkey --in alice.pem --text        # print key fields as hex

# Key exchange — produces shared session key PEM (consumed by enc/dec as --key)
python3 herradura.py kex --algo hkex-gf  --our alice.pem --their bob_pub.pem --out shared.pem
python3 herradura.py kex --algo hkex-rnl --our alice.pem --their bob_pub.pem --out shared.pem

# Symmetric encryption (requires session key from kex, or raw hex via --key 0x...)
python3 herradura.py enc --algo hske      --key shared.pem --in plain.bin --out cipher.bin
python3 herradura.py enc --algo hske-nla1 --key shared.pem --in plain.bin --out cipher.bin
python3 herradura.py enc --algo hske-nla2 --key shared.pem --in plain.bin --out cipher.bin
python3 herradura.py dec --algo hske      --key shared.pem --in cipher.bin --out plain.bin
python3 herradura.py dec --algo hske-nla1 --key shared.pem --in cipher.bin --out plain.bin
python3 herradura.py dec --algo hske-nla2 --key shared.pem --in cipher.bin --out plain.bin

# Asymmetric encryption — El Gamal and KEM variants
python3 herradura.py enc --algo hpke       --pubkey recipient_pub.pem --in plain.bin --out cipher.bin
python3 herradura.py dec --algo hpke       --key recipient.pem        --in cipher.bin --out plain.bin
python3 herradura.py enc --algo hpke-nl    --pubkey recipient_pub.pem --in plain.bin --out cipher.bin
python3 herradura.py dec --algo hpke-nl    --key recipient.pem        --in cipher.bin --out plain.bin
python3 herradura.py enc --algo hpke-stern --pubkey recipient_pub.pem --in plain.bin --out cipher.bin
python3 herradura.py dec --algo hpke-stern --key recipient.pem        --in cipher.bin --out plain.bin

# Signing and verification
python3 herradura.py sign   --algo hpks        --key signing.pem    --in msg.bin --out sig.pem
python3 herradura.py verify --algo hpks        --pubkey signing.pem --in msg.bin --sig sig.pem
python3 herradura.py sign   --algo hpks-nl     --key signing.pem    --in msg.bin --out sig.pem
python3 herradura.py verify --algo hpks-nl     --pubkey signing.pem --in msg.bin --sig sig.pem
python3 herradura.py sign   --algo hpks-stern  --key signing.pem    --in msg.bin --out sig.pem
python3 herradura.py verify --algo hpks-stern  --pubkey signing.pem --in msg.bin --sig sig.pem
```

---

#### PEM / DER encoding

**PEM boundary** encodes the algorithm type directly in the label (no IANA/OID registration
needed); algorithm-specific fields are unambiguous at parse time:

```
-----BEGIN HERRADURA HPKS PRIVATE KEY-----
<base64(DER payload)>
-----END HERRADURA HPKS PRIVATE KEY-----

-----BEGIN HERRADURA HPKS PUBLIC KEY-----
<base64(DER payload)>
-----END HERRADURA HPKS PUBLIC KEY-----

-----BEGIN HERRADURA SIGNATURE-----
<base64(DER payload)>
-----END HERRADURA SIGNATURE-----

-----BEGIN HERRADURA SESSION KEY-----
<base64(DER payload)>
-----END HERRADURA SESSION KEY-----

-----BEGIN HERRADURA CIPHERTEXT-----
<base64(DER payload)>
-----END HERRADURA CIPHERTEXT-----
```

**DER payload** uses hand-rolled minimal TLV (`codec.py`):
- `0x02 <len> <big-endian bytes>` — INTEGER
- `0x30 <len> <...>` — SEQUENCE wrapping one or more INTEGERs

Example layouts:

```
HKEX-GF / HPKS / HPKE private key:
  SEQUENCE { INTEGER private_scalar, INTEGER public_key, INTEGER nbits }

HKEX-RNL private key:
  SEQUENCE { INTEGER s_poly_packed, INTEGER C_poly_packed, INTEGER n }
  (poly packed as concatenated uint32 big-endian words)

HPKS-Stern-F private key:
  SEQUENCE { INTEGER e_int, INTEGER seed_int, INTEGER n_param }

HPKS / HPKS-NL signature:
  SEQUENCE { INTEGER s, INTEGER R, INTEGER e }

HPKS-Stern-F signature:
  SEQUENCE { INTEGER round_count, INTEGER commitments_hash, INTEGER responses_packed }

HPKE ciphertext (El Gamal):
  SEQUENCE { INTEGER R_ephemeral, INTEGER E_ciphertext }

HPKE-Stern-F ciphertext:
  SEQUENCE { INTEGER ct_syndrome, INTEGER encapped_key_hash }
```

The `codec.py` API:

```python
def der_int(value: int, nbytes: int) -> bytes: ...         # encode one INTEGER
def der_seq(*items: bytes) -> bytes: ...                   # wrap in SEQUENCE
def der_parse_seq(data: bytes) -> list[int]: ...           # decode SEQUENCE of INTEGERs
def pem_wrap(label: str, data: bytes) -> str: ...          # e.g. label="HERRADURA HPKS PRIVATE KEY"
def pem_unwrap(pem_text: str) -> tuple[str, bytes]: ...    # returns (label, data)
```

---

#### Implementation phases

**Phase 1 — Infrastructure** (1 commit)
- `HerraduraCli/codec.py`: implement `der_int`, `der_seq`, `der_parse_seq`, `pem_wrap`,
  `pem_unwrap` using only `base64`, `struct`, `bytes`; add unit-level assertions at module bottom
- `HerraduraCli/primitives.py`: use `importlib.util.spec_from_file_location` to load
  `"Herradura cryptographic suite.py"` from the parent directory; re-export
  `BitArray`, `fscx_revolve`, `nl_fscx_revolve_v1`, `nl_fscx_revolve_v2`,
  `nl_fscx_revolve_v2_inv`, `gf_mul`, `gf_pow`, `_rnl_keygen`, `_rnl_agree`,
  `_rnl_hint`, `_rnl_reconcile_bits`, `hpks_stern_f_sign`, `hpks_stern_f_verify`,
  `hpke_stern_f_encap_with_e`, `hpke_stern_f_decap`, `stern_f_keygen`,
  `KEYBITS`, `POLY`, `GF_GEN`, `ORD`, `RNLQ`, `RNLP`, `RNLPP`, `SDF_N`, `SDF_T`
- `HerraduraCli/herradura.py`: argparse skeleton with subparsers for `genpkey`, `pkey`,
  `kex`, `enc`, `dec`, `sign`, `verify`; `--in`/`--out`/`--key`/`--pubkey`/`--sig`/`--algo`/
  `--bits`/`--text` flags; dispatch to per-subcommand handler functions (stubs in Phase 1)

**Phase 2 — Key generation and display** (1 commit)
- Implement `genpkey` handler for all eight `--algo` values; random private scalar via
  `BitArray.random(bits)` (classical/NL) or `_rnl_keygen`/`stern_f_keygen` (PQC);
  public key derived per protocol; DER-encode per layout above; PEM-wrap; write `--out`
- Implement `pkey` handler: parse PEM label to detect algo; decode DER; if `--pubout`
  write public-key-only PEM; if `--text` print each field as hex lines

**Phase 3 — Symmetric encryption / decryption** (1 commit)
- `enc`/`dec` handlers for `hske`, `hske-nla1`, `hske-nla2`
- `--key` accepts either a SESSION KEY PEM (from `kex`) or a raw `0x...` hex string
- Input/output: raw binary files (`--in`, `--out`); ciphertext prepends a small DER
  header (nonce N for NLA1, iteration count r for NLA2) before the encrypted payload
  so `dec` can recover all parameters from the ciphertext file alone

**Phase 4 — Asymmetric encryption / decryption** (1 commit)
- `enc`/`dec` handlers for `hpke`, `hpke-nl`, `hpke-stern`
- `enc` reads `--pubkey` PEM, generates ephemeral r (classical) or known-e' seed (Stern-F),
  DER-encodes `(R_ephemeral, E_ciphertext)` or `(ct_syndrome, key_hash)`, PEM-wraps as
  HERRADURA CIPHERTEXT, writes `--out`
- `dec` reads private key PEM + ciphertext PEM, recovers plaintext, writes `--out`
- Document HPKE-Stern-F limitation (known-e' demo; production needs QC-MDPC decoder)
  in `--help` text

**Phase 5 — Key exchange** (1 commit)
- `kex` handler for `hkex-gf` and `hkex-rnl`
- Reads own private key PEM (`--our`) and peer public key PEM (`--their`)
- Derives shared session key via `gf_pow(C_peer, a_priv, POLY, bits)` (HKEX-GF) or
  `_rnl_agree` + `_rnl_reconcile_bits` (HKEX-RNL)
- Writes derived key as HERRADURA SESSION KEY PEM to `--out`

**Phase 6 — Signing / verification** (1 commit)
- `sign` handler for `hpks`, `hpks-nl`, `hpks-stern`
- Reads private key PEM, message bytes from `--in`, generates signature, DER-encodes,
  PEM-wraps as HERRADURA SIGNATURE, writes `--out`
- `verify` handler: reads public key PEM, message bytes, signature PEM;
  runs verification; exits 0 on success, 1 on failure; prints `Signature OK` / `Verification FAILED`

**Phase 7 — CliTest scripts** (1 commit)
- `CliTest/test_keygen.sh`: for each of the 8 algo names: call `genpkey`, call `pkey --pubout`,
  grep PEM headers, assert files non-empty; print PASS/FAIL per algo
- `CliTest/test_encrypt.sh`: for each symmetric algo: `kex` → `enc` → `dec`; `diff` result
  with original; for each asymmetric algo: `genpkey` → `enc` → `dec`; `diff` with original
- `CliTest/test_sign.sh`: for each signing algo: `genpkey` → `sign` → `verify` (PASS);
  byte-flip message → `verify` (FAIL); exit non-zero if any expected outcome is wrong
- `CliTest/test_vectors.sh`: fixed private key hex hardcoded in script; run `enc`/`sign`
  with `--key 0x<fixed>` or derived from fixed seed; compare output hex against expected
  constants generated on first run (stored as comments in the script)

---

#### Notes

- **No external dependencies.** `codec.py` uses only Python stdlib (`base64`, `struct`,
  `bytes`, `binascii`). `primitives.py` uses only `importlib.util` from stdlib.
- **`--bits` default.** 256 for all classical and NL protocols; for HPKS-Stern-F /
  HPKE-Stern-F it sets the Stern matrix dimension N (default 256 = full security;
  use 32 for fast testing).
- **HSKE-NL-A2 deterministic caveat** (see TODO #12): the `enc` help text will warn
  that the same (key, plaintext) pair always produces the same ciphertext.
- **HKEX-RNL hint transmission.** The SESSION KEY PEM written by `kex` embeds the
  Peikert reconciliation hint so the consumer (`enc`/`dec`) does not need to re-run
  the handshake.
- **Future work.** Once the Python CLI is stable, a C binding can follow the same
  PEM/DER spec (`HerraduraCli/codec.c`), re-using the Python codec as a reference.

Status: **DONE** (v1.5.23) — `HerraduraCli/` (herradura.py, codec.py, primitives.py) and
`CliTest/` (test_keygen.sh, test_encrypt.sh, test_sign.sh, test_vectors.sh) committed on
devtest. `test_vectors.sh` tests key-agreement correctness (HKEX-GF identical-PEM property
and HKEX-RNL cross-party enc/dec) rather than hardcoded hex vectors, since both protocols
use fresh random keys.

---

### 26. Large-file authenticated encryption and hashed signing (New Feature) ✓ DONE (v1.5.24)

**Goal:** Extend the HerraduraCli Python CLI to handle files of arbitrary size with:
1. A suite-native hash function (HFSCX-256) derived from NL-FSCX v1 primitives
2. AEAD (Authenticated Encryption with Associated Data) for arbitrary-length plaintext via a streaming CTR mode
3. Pre-hash signing and verification for arbitrary-length files

**Background:** The current `enc`/`dec`/`sign`/`verify` commands silently truncate or
zero-pad input to exactly 32 bytes (one 256-bit block). There is no MAC or authentication
tag on ciphertext. There is no digest primitive — the HPKS challenge is computed by applying
`fscx_revolve` or `nl_fscx_revolve_v1` directly to a single-block message. Both limitations
make the CLI unsuitable for real files.

---

#### HFSCX-256 hash construction

NL-FSCX v1 is already used as a one-way function (not bijective in A). The construction
applies it as a Merkle-Damgård compression function:

**Compression:**
```
compress(state: BitArray, block: BitArray) = nl_fscx_revolve_v1(state, block, n/4)
```

**Padding (ISO 7816-4 + Merkle-Damgård strengthening):**
1. Append byte `0x80` to the message bytes
2. Zero-fill until total length is a multiple of 32 bytes
3. Append one final 32-byte block containing the original message bit-length as a
   zero-padded big-endian uint64 in the last 8 bytes — binds the hash to the exact length
   and prevents length-extension attacks on the bare construction

**IV:** A fixed 256-bit domain constant (deterministic, derived from the suite name):
```python
IV_BYTES = b'HFSCX-256/HERRADURA-SUITE\x00\x00\x00\x00\x00\x00\x00'  # exactly 32 bytes
IV = BitArray(256, int.from_bytes(IV_BYTES, 'big'))
```

**Keyed variant (for MAC):**
```
HFSCX-256-MAC(key: BitArray, data: bytes):
    initial_state = BitArray(256, key.uint ^ IV.uint)
    return HFSCX-256(data, iv=initial_state)
```
The key is incorporated into both the initial chaining state AND the MD-strengthening
length block (`length_raw XOR initial_state`). This prevents a fixed-point collapse where
the two-block chain for empty input would map all initial states to the same output,
making the key invisible. With the key bound into the length block, different keys always
produce different final blocks and distinct outputs even for empty data.

**API:**
```python
hfscx_256(data: bytes, *, iv: BitArray | None = None) -> bytes  # returns 32 bytes
```
`iv=None` uses the domain IV constant (bare hash); pass a derived `BitArray` for the
keyed MAC variant.

---

#### Streaming CTR-mode AEAD (HSKE-NL-A1-CTR)

Extend the existing single-block HSKE-NL-A1 naturally to arbitrary length:

**Keystream for block i (0-indexed):**
```
base  = K XOR N_nonce                        # 256-bit session base (existing)
seed  = ROL(base, n/8)                       # existing step-1 degeneracy fix
ks_i  = nl_fscx_revolve_v1(seed, base XOR i, n/4)
```
Counter block `base XOR i` differs from `base XOR 0` (current single-block case) in the
low-order bits; counter=0 is identical to the current implementation.

**Encryption:**
```
C_i = P_i XOR ks_i    for i in 0..m-1
```
Last block: plaintext zero-padded to 32 bytes; only the first `len(P) % 32` (or 32)
bytes of `C_{m-1}` are stored.

**MAC key derivation (domain separation from encryption):**
```
mac_seed = ROL(seed, n/4)
mac_key  = nl_fscx_revolve_v1(mac_seed, base, n/4)
```

**Authentication tag (encrypt-then-MAC):**
```
tag = HFSCX-256-MAC(mac_key,
        N_nonce || len_be8(len_plaintext) || C_0 || C_1 || ... || C_{m-1})
```
The nonce and plaintext length are included as associated data to bind the ciphertext to
its context and prevent truncation attacks.

**Binary output format (`.hkx`):**
```
Offset       Length   Field
0            4        Magic: b'HKX1'
4            1        Algo: 0x01 = hske-nla1  (0x02 reserved for hske-nla2)
5            8        Plaintext length (big-endian uint64)
13           32       Nonce N_nonce
45           m*32     Ciphertext blocks (last block may be padded)
45 + m*32    32       Auth tag (HFSCX-256-MAC)
```
Per-file overhead: 77 bytes fixed header + tag + up to 31 bytes of last-block padding.

**Decryption (verify-then-decrypt):**
1. Parse header; extract nonce and ciphertext blocks
2. Derive mac_key using the same derivation
3. Recompute tag; compare with `hmac.compare_digest` (constant-time)
4. Exit non-zero and write nothing if tag mismatch
5. Decrypt blocks; trim output to `plaintext_length` bytes

---

#### Pre-hash signing (`--digest hfscx-256`)

Add an optional `--digest` flag to the existing `sign` and `verify` sub-parsers:

```bash
herradura sign   --algo hpks-nl --key priv.pem --in large.bin --out sig.pem --digest hfscx-256
herradura verify --algo hpks-nl --pubkey pub.pem --in large.bin --sig sig.pem --digest hfscx-256
```

When `--digest hfscx-256` is given:
1. Compute `d = hfscx_256(file_bytes)` → 32-byte digest
2. Substitute `d` for the truncated single-block message in the existing HPKS/HPKS-NL/
   HPKS-Stern handler — all signature math is unchanged
3. The on-disk signature PEM format is unchanged

Default `--digest none` preserves the existing truncating behavior (backward compatible).
Applies to all three signing algorithms: `hpks`, `hpks-nl`, `hpks-stern`.

---

#### New `dgst` subcommand

```bash
herradura dgst [--algo hfscx-256] --in <file> [--out <file>]
```
- Reads `--in`, computes HFSCX-256, outputs lowercase hex to stdout (default)
- `--out <file.pem>`: writes a `HERRADURA DIGEST` PEM (DER-encoded 256-bit integer)
- No key or algorithm flag required for the bare hash

---

#### Implementation Phases

**Phase 1 — HFSCX-256 primitive** (1 commit)
- Files: `Herradura cryptographic suite.py`, `HerraduraCli/primitives.py`
- Add `hfscx_256(data: bytes, *, iv: BitArray | None = None) -> bytes` to the suite
- Implement padding, IV constant, Merkle-Damgård chaining, and keyed variant as above
- Re-export `hfscx_256` from `HerraduraCli/primitives.py`
- Add known-answer tests to `CryptosuiteTests/Herradura_tests.py`:
  empty input, single-byte `b'a'`, 33-byte input (crosses one block boundary),
  and a collision-resistance sanity check (two distinct inputs → distinct outputs)

**Phase 2 — `dgst` subcommand** (1 commit)
- File: `HerraduraCli/herradura.py`
- Add `cmd_dgst(args)` and register `dgst` sub-parser with `--algo`, `--in`, `--out`
- Update the usage comment block at the top of `herradura.py`
- Version bump to v1.5.24

**Phase 3 — `encfile` / `decfile` subcommands** (1 commit)
- File: `HerraduraCli/herradura.py`
- Add `cmd_encfile(args)` / `cmd_decfile(args)` and register their sub-parsers
- `--algo hske-nla1` (CTR-mode; `hske-nla2` is not naturally streamable — defer)
- `--key`: SESSION KEY PEM (from `kex`) or a raw private-key PEM (scalar used as key)
- `--in`, `--out`: file paths only (no `-` stdin; large binary streams need seekable files)
- Binary `.hkx` output format as documented above; constant-time tag comparison via
  `hmac.compare_digest`

**Phase 4 — `--digest hfscx-256` on `sign` / `verify`** (1 commit)
- File: `HerraduraCli/herradura.py`
- Add `--digest {none,hfscx-256}` optional argument to `sign` and `verify` sub-parsers
- Default: `none` (existing truncate behavior; backward compatible)
- When `hfscx-256`: compute digest, pass 32-byte result as the message block to the
  existing algorithm handlers unchanged

**Phase 5 — CliTest scripts** (1 commit)
- New files: `CliTest/test_encfile.sh`, `CliTest/test_signfile.sh`
- `test_encfile.sh`:
  - Generate 1 MiB test file (`dd if=/dev/urandom count=2048 bs=512`)
  - `kex → encfile → decfile → diff` with original (must match)
  - Flip one byte in the ciphertext body, assert `decfile` exits non-zero (tag rejection)
  - Edge cases: 0-byte file, 1-byte file, exactly 32-byte file (one full block)
- `test_signfile.sh`:
  - Sign the 1 MiB file with each `--digest hfscx-256` algo, verify (PASS)
  - Append one byte to file, verify again (FAIL)
  - `dgst` run twice on the same file → identical hex output (determinism)

---

**Files affected:**
- `Herradura cryptographic suite.py` — add `hfscx_256`
- `HerraduraCli/primitives.py` — re-export `hfscx_256`
- `HerraduraCli/herradura.py` — add `dgst`, `encfile`, `decfile`; extend `sign`/`verify`
- `CryptosuiteTests/Herradura_tests.py` — HFSCX-256 known-answer tests
- `CliTest/test_encfile.sh`, `CliTest/test_signfile.sh` — new shell tests

**No external dependencies.** Uses only Python stdlib (`hmac`, `os`, `struct`) alongside
existing suite primitives. `hmac.compare_digest` is used solely for constant-time byte
comparison — no HMAC construction is introduced.

Status: **DONE** (v1.5.24) — see section header.

---

### 27. HerraduraCli — C CLI tool + shared `herradura.h` header library (New Feature)

**Goal:** A C command-line tool (`HerraduraCli/herradura_cli`) with feature parity to the
Python CLI (`herradura.py`), backed by a new `herradura.h` header-only library that
eliminates the current code duplication between `Herradura cryptographic suite.c` and
`CryptosuiteTests/Herradura_tests.c`.  All three C programs — suite demo, tests, and CLI —
compile independently via a single `gcc` invocation; no build-system changes beyond adding
the CLI target to `build_c.sh`.

Interoperability with the Python CLI is a hard requirement: keys, ciphertexts, signatures,
and `.hkx` files produced by one implementation must be accepted by the other.

---

#### Architecture

```
herradura.h                         — NEW: header-only library; all crypto primitives as
                                       static functions; types (BitArray, SternSig,
                                       rnl_poly_t), constants, and HFSCX-256 hash
Herradura cryptographic suite.c     — REFACTORED: #include "herradura.h"; keeps only main()
CryptosuiteTests/Herradura_tests.c  — REFACTORED: #include "../herradura.h"; removes
                                       duplicated primitives; keeps test helpers + main()
HerraduraCli/
  herradura_cli.c                   — NEW: C CLI (includes ../herradura.h +
                                       herradura_codec.h); no crypto logic — CLI dispatch
                                       only
  herradura_codec.h                 — NEW: header-only PEM/DER/Base64 I/O helpers; no
                                       external deps; only <stdio.h>, <stdlib.h>,
                                       <string.h>, <stdint.h>
CliTest/
  test_c_keygen.sh                  — C CLI key generation smoke test
  test_c_encrypt.sh                 — C CLI enc/dec round-trips
  test_c_sign.sh                    — C CLI sign/verify + tamper detection
  test_c_encfile.sh                 — C CLI encfile/decfile; tag rejection; edge cases
  test_c_interop.sh                 — Python encrypts → C decrypts and vice versa
```

**Why header-only?**  Each binary compiles with a single `gcc source.c` invocation — the
existing build model.  Exporting to a `.h`+`.c` pair would require a separate compile step
and object-file linkage, breaking the one-liner build commands documented in `CLAUDE.md`.
Header-only with `static` functions duplicates a few KB of compiled code per binary, which
is acceptable.

---

#### Supported commands

| Subcommand | Flags | Notes |
|---|---|---|
| `genpkey` | `--algo`, `--bits`, `--out` | All 8 key types |
| `pkey` | `--in`, `--pubout`, `--out`, `--text` | Extract / display public key |
| `kex` | `--algo`, `--our`, `--their`, `--out` | HKEX-GF and HKEX-RNL (2-round) |
| `enc` | `--algo`, `--key`/`--pubkey`, `--in`, `--out` | HSKE, HSKE-NL-A1/A2, HPKE, HPKE-NL, HPKE-Stern-F |
| `dec` | `--algo`, `--key`, `--in`, `--out` | Same set |
| `sign` | `--algo`, `--key`, `--in`, `--out`, `[--digest hfscx-256]` | HPKS, HPKS-NL, HPKS-Stern-F |
| `verify` | `--algo`, `--pubkey`, `--in`, `--sig`, `[--digest hfscx-256]` | Same set; exits 0/1 |
| `dgst` | `[--algo hfscx-256]`, `--in`, `[--out]` | Hex to stdout or HERRADURA DIGEST PEM |
| `encfile` | `--algo hske-nla1`, `--key`, `--in`, `--out` | HSKE-NL-A1 CTR AEAD → `.hkx` |
| `decfile` | `--algo hske-nla1`, `--key`, `--in`, `--out` | Verify-then-decrypt `.hkx` |

---

#### New C primitives required

**HFSCX-256** (Merkle-Damgård hash on NL-FSCX v1, identical to Python):

```
IV: "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0"  (32 bytes)
Padding: append 0x80; zero-fill to multiple of 32; append 32-byte length block
         (bit_length_64 XOR init_state) for MD-strengthening
Chain:  state_{i+1} = nl_fscx_revolve_v1(state_i, block_i, 64)
Keyed:  init_state = key XOR IV  (domain separation for MAC use)
```

```c
/* Bare hash: iv = NULL.  Keyed MAC: pass 32-byte iv = key XOR _HFSCX256_IV. */
static void hfscx_256(const uint8_t *data, size_t len,
                      const uint8_t *iv,   /* NULL → use IV constant */
                      uint8_t out[32]);
```

**HSKE-NL-A1 CTR AEAD helpers** (exposed via `herradura.h` for use by `encfile`/`decfile`):

```c
/* Derive one 32-byte keystream block for counter i. */
static void hske_nla1_ks_block(const BitArray *seed, const BitArray *base,
                                uint32_t i, BitArray *ks_out);

/* Derive the MAC key (domain-separated from encryption key). */
static void hske_nla1_mac_key(const BitArray *seed, const BitArray *base,
                               BitArray *mac_key_out);
```

---

#### `herradura_codec.h` API

```c
/* Base64 */
void b64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);
int  b64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len);

/* PEM */
int pem_wrap  (const char *label, const uint8_t *der, size_t der_len,
               char *out, size_t *out_len);            /* writes "-----BEGIN label-----\n..." */
int pem_unwrap(const char *pem, size_t pem_len,
               char *label_out,                        /* caller-allocated, >= 80 bytes */
               uint8_t *der_out, size_t *der_len);

/* File I/O */
int pem_read_file (const char *path, char *label_out, uint8_t *der_out, size_t *der_len);
int pem_write_file(const char *path, const char *label, const uint8_t *der, size_t der_len);

/* DER TLV (minimal subset: INTEGER 0x02, SEQUENCE 0x30) */
int der_int_enc(const uint8_t *val, size_t val_len, uint8_t *out, size_t *out_len);
int der_seq_enc(const uint8_t **items, const size_t *item_lens,
                int n_items, uint8_t *out, size_t *out_len);
int der_parse_seq(const uint8_t *der, size_t len,
                  uint8_t **vals, size_t *val_lens, int max_items, int *n_out);
```

PEM label constants (must match Python exactly for interoperability):

```c
#define PEM_HKEX_GF_PRIV   "HERRADURA HKEX-GF PRIVATE KEY"
#define PEM_HKEX_GF_PUB    "HERRADURA HKEX-GF PUBLIC KEY"
#define PEM_HKEX_RNL_PRIV  "HERRADURA HKEX-RNL PRIVATE KEY"
/* ... one per algo-type pair; SESSION KEY, CIPHERTEXT, SIGNATURE, DIGEST */
```

---

#### `.hkx` binary format (shared with Python, must stay compatible)

```
Offset       Length   Field
0            4        Magic: 'HKX1'
4            1        Algo byte: 0x01 = hske-nla1
5            8        Plaintext length (big-endian uint64)
13           32       Nonce N_nonce
45           m*32     Ciphertext blocks (last block zero-padded to 32 bytes)
45 + m*32    32       Auth tag = hfscx_256(mac_key XOR IV, nonce||len_be8||ciphertext)
```

Minimum file size: 77 bytes (empty plaintext).  Streaming I/O in C: `encfile` writes header
+nonce, encrypts in 32-byte blocks to the output file, then appends the tag.  `decfile`
reads header, buffers ciphertext to compute tag, rejects on mismatch before writing any
plaintext.  No full-file mmap — uses `fread`/`fwrite` in 32-byte chunks.

**Constant-time tag comparison** (`decfile`): accumulate differences with `|=` over all
32 bytes; reject if result non-zero.  Do not use `memcmp` (may short-circuit).

---

#### Implementation batches

**Batch 1 — `herradura.h` shared library** (1 commit) ✅
- New file `herradura.h`: copy all `static` crypto functions from
  `Herradura cryptographic suite.c`; add header guards; include `<stdint.h>`, `<string.h>`,
  `<stdio.h>`, `<stdlib.h>`
- `Herradura cryptographic suite.c`: add `#include "herradura.h"`; delete every function
  definition now in the header; keep only `main()` and SDF32 demo helpers
- `CryptosuiteTests/Herradura_tests.c`: add `#include "../herradura.h"`; delete duplicated
  primitive functions; keep test-only functions and `main()`
- Both binaries build and all tests pass (`-r 5 -t 2.0`)

**Batch 2 — HFSCX-256 in C** (1 commit) ✅
- Add `_HFSCX256_IV[32]` constant and `hfscx_256()` to `herradura.h`
- Add test `[19]` to `CryptosuiteTests/Herradura_tests.c`: known-answer vectors for
  empty input, `\x61`, 33-byte cross-boundary, and collision-resistance sanity check;
  expected digests cross-checked against Python `hfscx_256()`
- Benchmarks renumbered `[19]-[28]` → `[20]-[29]`; both binaries build and all tests pass

**Batch 3 — `herradura_codec.h` PEM/DER/Base64** (1 commit) ✅
- New file `HerraduraCli/herradura_codec.h`; all functions `static`; no external deps
- Self-test under `#ifdef HERRADURA_CODEC_SELFTEST`: round-trip + Python known-answer vectors
- Bidirectional interop verified: Python PEM → C parse → C write → Python parse (all PASS)
- Bug fix during dev: label scan used `*p != '-'` which stopped on hyphens in labels like
  `HKEX-GF`; fixed to scan for `"-----"` sentinel

**Batch 4 — C CLI: `genpkey`, `pkey`, `kex`** (1 commit)
- New file `HerraduraCli/herradura_cli.c`
- Subcommand dispatch table; `--help` usage text; `--out`/`--in` flag parser
- `genpkey`: reads `/dev/urandom`; derives public key per protocol; DER-encodes per Python
  layout; PEM-wraps; writes file
- `pkey`: parses PEM label to detect algo; if `--pubout` writes public-only PEM; if
  `--text` prints each DER integer as `field: <hex>` lines
- `kex`: HKEX-GF (single-pass) and HKEX-RNL (2-round); writes SESSION KEY PEM

**Batch 5 — C CLI: `enc`, `dec`, `sign`, `verify`, `dgst`** (1 commit)
- `enc`/`dec`: HSKE, HSKE-NL-A1, HSKE-NL-A2 (symmetric, key from SESSION KEY PEM);
  HPKE, HPKE-NL, HPKE-Stern-F (asymmetric); PEM ciphertext format identical to Python
- `sign`: HPKS, HPKS-NL, HPKS-Stern-F; `--digest hfscx-256` pre-hashes input to 32
  bytes before passing to signature logic (unchanged); HERRADURA SIGNATURE PEM output
- `verify`: reads public key + SIGNATURE PEM + `--in` file; exits 0 on OK, 1 on FAIL;
  prints `Signature OK` / `Verification FAILED` to stdout
- `dgst`: computes HFSCX-256; hex to stdout (default) or HERRADURA DIGEST PEM (`--out`)

**Batch 6 — C CLI: `encfile`, `decfile`** (1 commit) ✅
- Implement streaming HSKE-NL-A1 CTR AEAD using `hske_nla1_ks_block()` and
  `hske_nla1_mac_key()` helpers from `herradura.h`
- `encfile`: open output file; write header + nonce; stream plaintext blocks; compute and
  append tag
- `decfile`: parse header; stream ciphertext into accumulator to recompute tag;
  constant-time comparison; if OK re-read (or buffer) and decrypt; trim to plaintext_len
- Cross-check: Python `encfile` output → C `decfile` (and vice versa) must succeed

**Batch 7 — Build scripts + CliTest** (1 commit) ✅
- `build_c.sh`: add CLI build step:
  `gcc -O2 -o HerraduraCli/herradura_cli HerraduraCli/herradura_cli.c`
- `CliTest/test_c_keygen.sh`: genpkey all 8 types; pkey --pubout; grep PEM headers;
  assert non-empty
- `CliTest/test_c_encrypt.sh`: kex → enc → dec round-trips for all algos; `cmp` with
  original
- `CliTest/test_c_sign.sh`: genpkey → sign → verify (PASS); flip a byte → verify (FAIL)
- `CliTest/test_c_encfile.sh`: 1 MiB file; encrypt → decrypt → `cmp`; flip a byte in
  ciphertext body → decfile must exit non-zero; edge cases: 0-byte, 1-byte, 32-byte files
- `CliTest/test_c_interop.sh`: Python `encfile` → C `decfile`; C `encfile` → Python
  `decfile`; Python `sign` → C `verify`; C `sign` → Python `verify` (one algo each as
  smoke test)

---

#### Notes

- **No external dependencies.** `herradura.h` and `herradura_codec.h` use only C99 standard
  library headers (`<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stdint.h>`).  `/dev/urandom`
  is the sole OS dependency (already used by the suite and tests).
- **`--bits` default**: 256 for all classical and NL protocols.  Stern-F uses `--bits` as
  the matrix dimension N (default 256; use 32 for fast testing, matching the assembly
  targets).
- **HSKE-NL-A2 deterministic caveat** (TODO #12): `enc --algo hske-nla2` help text will
  warn that identical (key, plaintext) pairs produce identical ciphertext.
- **`decfile` memory model**: for very large files, buffering the full ciphertext for MAC
  verification requires heap allocation proportional to file size.  An alternative is a
  two-pass approach (first pass: compute tag; second pass: decrypt if tag OK).  Use the
  two-pass model to keep peak heap usage at O(1) (32-byte block buffers only).
- **`hpks-stern-f` / `hpke-stern-f` with full N=256**: Stern-F signing at N=256 is slow in
  C (rounds=32 × permutation work).  Flag this in `--help` text; recommend `--bits 32`
  for testing.

Status: **DONE** — Batches 1–7 complete (v1.5.26).

**Batch 4 complete (v1.5.25):**
- `HerraduraCli/herradura_cli.c` built and tested; all 12 functional tests pass
- Interop verified: C-only GF/RNL round-trips, C×Python GF cross-kex, C×Python RNL cross-kex
  (Python-Alice+C-Bob and C-Alice+Python-Bob both produce matching session keys)
- Bug fixed during dev: `rnl_reconcile_bits` packs bits LSB-first (b[0]=bits 0-7) while Python
  `BitArray.bytes` is big-endian (byte 0 = bits 248-255); K and hint bytes reversed before DER
  encoding (and reversed back after decoding) to match Python's layout
- `pem_key_get_n` helper left in (unused; useful for Batch 5 n-validation)

**Batch 5 complete (v1.5.25):**
- `cmd_enc`/`cmd_dec`: all 6 algos implemented (hske, hske-nla1, hske-nla2, hpke, hpke-nl,
  hpke-stern); PEM ciphertext format byte-compatible with Python CLI
- `cmd_sign`/`cmd_verify`: hpks, hpks-nl, hpks-stern; `--digest hfscx-256` pre-hashes input;
  Schnorr exit 0/1 + "Signature OK"/"Verification FAILED"; C×Python cross-tool sign+verify pass
- `cmd_dgst`: HFSCX-256 hash; hex to stdout or HERRADURA DIGEST PEM; matches Python known-answer
- All C-only round-trips pass; C↔Python interop verified for all symmetric, asymmetric, and
  signing algos including hpke-stern and hpks-stern

**Batch 6 complete (v1.5.26):**
- `hske_nla1_ks_block` and `hske_nla1_mac_key` helpers added to `herradura.h`
- `cmd_encfile`/`cmd_decfile` in `herradura_cli.c`; .hkx binary format (magic HKX1,
  algo byte, uint64 length, nonce, ciphertext blocks, 32-byte HFSCX-256-MAC tag)
- Constant-time tag comparison (`diff |= ct[j] ^ comp[j]` over all 32 bytes)
- Edge cases verified: 0-byte, 1-byte, 32-byte, 1000-byte files all pass
- Tamper rejection verified: flipping a ciphertext byte exits 1 with auth-failure message
- C↔Python interop verified: C encfile → Python decfile and Python encfile → C decfile both pass

**Batch 7 complete (v1.5.26):**
- `build_c.sh` updated to v1.5.26; CLI build step added
- `CliTest/test_c_keygen.sh`: 16 PASS — all 8 algo types, genpkey + pkey pubout
- `CliTest/test_c_encrypt.sh`: 7 PASS — hske/hske-nla1/hske-nla2, hkex-rnl cross-party,
  hpke, hpke-nl, hpke-stern
- `CliTest/test_c_sign.sh`: 7 PASS — hpks/hpks-nl (correct/wrong msg, wrong key),
  hpks-stern N=256 (correct/wrong msg)
- `CliTest/test_c_encfile.sh`: 5 PASS — 1 MiB round-trip, tamper rejection, 0/1/32-byte edges
- `CliTest/test_c_interop.sh`: 4 PASS — C↔Python encfile and sign/verify cross-tool

---

### 28. Go CLI Tool + `herradura` Go Package (New Feature)

**Goal:** A Go command-line tool (`HerraduraCli/herradura_cli.go`) with full feature parity
to the Python CLI (`herradura.py`) and C CLI (`herradura_cli.c`), backed by a reusable
`herradura/` Go package — the Go equivalent of the `herradura.h` shared header library —
that eliminates duplicated crypto logic between the suite demo, tests, and CLI.  All three
Go programs import from one authoritative package.

The package also adds two primitives not yet implemented in Go:

1. **HFSCX-256** — the Merkle-Damgård hash built on NL-FSCX v1, present in Python and C
   since v1.5.24.  Required for large-file digest, streaming AEAD authentication tag,
   and `--digest hfscx-256` pre-hash signing.

2. **HSKE-NL-A1 streaming helpers** — keystream block and MAC key derivation needed for
   CTR-mode AEAD over files of arbitrary size (`.hkx` format).

Interoperability with the Python and C CLIs is a hard requirement: keys, ciphertexts,
signatures, and `.hkx` files produced by any implementation must be accepted by all others.

---

#### Architecture

```
herradura/                              — NEW: Go package (herradurakex/herradura)
  herradura.go                          — all crypto primitives; HFSCX-256; HSKE-NL-A1 helpers
  codec.go                              — PEM/DER/Base64 codec (Go equiv. of herradura_codec.h)
Herradura cryptographic suite.go        — REFACTORED: imports herradurakex/herradura; keeps main()
CryptosuiteTests/
  Herradura_tests.go                    — REFACTORED: imports herradurakex/herradura
  go.mod                               — UPDATED: require herradurakex + replace herradurakex => ..
HerraduraCli/
  herradura_cli.go                      — NEW: Go CLI; imports herradurakex/herradura
  go.mod                               — NEW: require herradurakex + replace herradurakex => ..
CliTest/
  test_go_keygen.sh                     — Go CLI key generation smoke test
  test_go_encrypt.sh                    — Go CLI enc/dec round-trips
  test_go_sign.sh                       — Go CLI sign/verify + tamper detection
  test_go_encfile.sh                    — Go CLI encfile/decfile; tag rejection; edge cases
  test_go_interop.sh                    — Cross-tool: Go↔Python and Go↔C interop
```

**Why a Go package?**  The existing suite and test files each duplicate the same ~1100-line
crypto core.  Extracting it to `herradura/` mirrors what `herradura.h` does for C: one
authoritative copy, three consumers.  The CLI is then a thin argument-dispatch wrapper with
no embedded crypto logic.

---

#### New Go primitives required

**HFSCX-256** (absent from Go; present in Python v1.5.24 and C `herradura.h`):

```go
// Hfscx256 computes the HFSCX-256 hash.  iv==nil uses the standard domain IV.
// A non-nil iv (32 bytes, caller sets iv = key XOR IV) selects the keyed-MAC variant.
func Hfscx256(data []byte, iv []byte) []byte  // returns 32 bytes
```

Merkle-Damgård construction identical to Python/C:
- IV: `"HFSCX-256/HERRADURA-SUITE\x00\x00\x00\x00\x00\x00\x00"` (exactly 32 bytes)
- Compression: `state = NlFscxRevolveV1(state, block, n/4)` per 32-byte block
- Padding: append `0x80`; zero-fill to 32-byte boundary; append length block
  (`bit_length_be8 XOR init_state` for MD strengthening)
- Keyed MAC: `init_state = key XOR IV`

**HSKE-NL-A1 streaming helpers** (mirror of `hske_nla1_ks_block` / `hske_nla1_mac_key`
in `herradura.h`):

```go
// HskeNla1KsBlock returns the 32-byte keystream for CTR block i.
func HskeNla1KsBlock(seed, base *BitArray, i uint32) *BitArray
// HskeNla1MacKey returns the 32-byte MAC key (domain-separated from encryption).
func HskeNla1MacKey(seed, base *BitArray) *BitArray
```

---

#### `codec.go` API (Go equivalent of `herradura_codec.h`)

```go
func PemWrap(label string, der []byte) string
func PemUnwrap(pem string) (label string, der []byte, err error)
func DerInt(val []byte) []byte                    // encode DER INTEGER (0x02 TLV)
func DerSeq(items ...[]byte) []byte               // wrap in SEQUENCE (0x30 TLV)
func DerParseSeq(der []byte) ([][]byte, error)    // decode SEQUENCE of INTEGERs
```

PEM label constants (must match Python/C for interoperability):

```go
const (
    PemHkexGfPriv  = "HERRADURA HKEX-GF PRIVATE KEY"
    PemHkexGfPub   = "HERRADURA HKEX-GF PUBLIC KEY"
    // ... one pair per algo; SESSION KEY, CIPHERTEXT, SIGNATURE, DIGEST
)
```

---

#### Supported CLI subcommands (full parity with Python and C CLIs)

| Subcommand | Flags | Notes |
|---|---|---|
| `genpkey` | `--algo`, `--bits`, `--out` | All 8 key types |
| `pkey` | `--in`, `--pubout`, `--out`, `--text` | Extract / display public key |
| `kex` | `--algo`, `--our`, `--their`, `--out` | HKEX-GF and HKEX-RNL (2-round) |
| `enc` | `--algo`, `--key`/`--pubkey`, `--in`, `--out` | HSKE, HSKE-NL-A1/A2, HPKE, HPKE-NL, HPKE-Stern-F |
| `dec` | `--algo`, `--key`, `--in`, `--out` | Same set |
| `sign` | `--algo`, `--key`, `--in`, `--out`, `[--digest hfscx-256]` | HPKS, HPKS-NL, HPKS-Stern-F |
| `verify` | `--algo`, `--pubkey`, `--in`, `--sig`, `[--digest hfscx-256]` | Same set; exits 0/1 |
| `dgst` | `[--algo hfscx-256]`, `--in`, `[--out]` | Hex to stdout or HERRADURA DIGEST PEM |
| `encfile` | `--algo hske-nla1`, `--key`, `--in`, `--out` | HSKE-NL-A1 CTR AEAD → `.hkx` |
| `decfile` | `--algo hske-nla1`, `--key`, `--in`, `--out` | Verify-then-decrypt `.hkx` |

---

#### `.hkx` binary format (byte-identical to Python and C)

```
Offset     Length  Field
0          4       Magic: 'HKX1'
4          1       Algo: 0x01 = hske-nla1
5          8       Plaintext length (big-endian uint64)
13         32      Nonce N_nonce
45         m*32    Ciphertext blocks (last block zero-padded to 32 bytes)
45+m*32    32      Auth tag: Hfscx256(mac_key XOR IV, nonce||len_be8||ciphertext)
```

Minimum file: 77 bytes (empty plaintext).  `decfile`: verify-then-decrypt, two-pass (first
pass buffers ciphertext to recompute tag; second pass decrypts if OK); O(1) block-level heap;
`subtle.ConstantTimeCompare` from `crypto/subtle` for tag comparison (not `bytes.Equal`).

---

#### Implementation batches

**Batch 1 — `herradura` Go package (library extraction + HFSCX-256)** (1 commit) ✅ v1.5.27
- Create `herradura/herradura.go` in the root module: copy all exported crypto functions
  from `Herradura cryptographic suite.go`; rename to exported (capitalised) identifiers;
  add `Hfscx256`, `HskeNla1KsBlock`, `HskeNla1MacKey`
- Create `herradura/codec.go`: PEM/DER codec; PEM label constants; `encoding/base64` only
- Refactor `Herradura cryptographic suite.go`: add `import "herradurakex/herradura"`;
  delete every function definition now in the package; keep only `main()` and demo helpers
  that print results; update `go build` call in `build_go.sh` from
  `go build -o "${SUITE_BIN}" "${SUITE_SRC}"` to `go build -o "${SUITE_BIN}" .` (directory
  build required when the file imports local packages)
- Update `CryptosuiteTests/go.mod`: add `require herradurakex v0.0.0` and
  `replace herradurakex => ../`; refactor `Herradura_tests.go` to import
  `herradurakex/herradura`; delete duplicated primitives; keep test helpers + `main()`
- Add HFSCX-256 known-answer tests to `CryptosuiteTests/Herradura_tests.go` as test [17]
  (renumbering subsequent items): empty input, `\x61`, 33-byte cross-boundary; expected
  values cross-checked against Python (`primitives.hfscx_256`) and C (`hfscx_256` in
  `herradura.h`)
- Both binaries build and all existing tests pass

**Batch 2 — Go CLI: `genpkey`, `pkey`, `kex`, `dgst`** (1 commit) ✅ v1.5.27
- Create `HerraduraCli/herradura_cli.go` (`package main`); `flag`-based subcommand dispatch;
  usage text matching Python CLI header comment style
- Create `HerraduraCli/go.mod`: `module herradurakex/cli`, `require herradurakex v0.0.0`,
  `replace herradurakex => ../`; add CLI build to `build_go.sh`:
  `(cd HerraduraCli && go build -o herradura_cli_go herradura_cli.go)` (file-level; C file present)
- Implemented `genpkey` (all 8 algos)
- Implemented `pkey` (`--pubout` and `--text` modes)
- Implemented `kex` (HKEX-GF single-pass; HKEX-RNL 2-round with Peikert hint byte-reversal)
- Implemented `dgst`: HFSCX-256; hex to stdout or HERRADURA DIGEST PEM (`--out`)
- PEM/DER format byte-identical to Python and C; HFSCX-256 KAV verified; cross-language
  HKEX-GF interop confirmed (Go privkey + Python pubkey → identical session key PEM)

**Batch 3 — Go CLI: `enc`, `dec`, `sign`, `verify`** (1 commit) ✅ v1.5.27
- `enc`/`dec`: HSKE, HSKE-NL-A1, HSKE-NL-A2 (symmetric, key from SESSION KEY PEM or
  `0x...` hex string); HPKE, HPKE-NL, HPKE-Stern-F (asymmetric)
- `sign`/`verify`: HPKS, HPKS-NL, HPKS-Stern-F; `--digest hfscx-256` pre-hashes `--in`
  to 32 bytes before signature math; exits 0/1; prints `Signature OK` / `Verification FAILED`
- All PEM ciphertext and signature formats byte-identical to Python; cross-language
  HPKE enc/dec and HPKS sign/verify interop confirmed

**Batch 4 — Go CLI: `encfile`, `decfile`** (1 commit) ✅ v1.5.27
- Streaming HSKE-NL-A1 CTR AEAD using `HskeNla1KsBlock` + `HskeNla1MacKey` from the package
- `encfile`: write header + nonce; encrypt 32-byte blocks via `fwrite`-style loop;
  accumulate MAC input; append 32-byte HFSCX-256-MAC tag
- `decfile`: parse and validate header; two-pass: first pass streams ciphertext to
  recompute tag; `subtle.ConstantTimeCompare` for tag check; exit 1 on mismatch; second
  pass decrypts and trims to `plaintext_len`
- Edge cases: 0-byte, 1-byte, 32-byte (one full block), multi-MiB files
- Tests: 0/1/32/100KB/2MiB roundtrip all OK; tamper → auth fail; Python↔Go interop OK

**Batch 5 — `build_go.sh` + CliTest: Go CLI tests + interop** (1 commit) ✅ v1.5.28
- `build_go.sh`: version bump to v1.5.28; appended CliTest run instructions to build output
- `CliTest/test_go_keygen.sh`: genpkey all 8 types; pkey `--pubout`; grep PEM headers;
  assert non-empty — **16 PASS**
- `CliTest/test_go_encrypt.sh`: kex → enc → dec round-trips for all symmetric and
  asymmetric algos; `cmp` with original — **7 PASS**
- `CliTest/test_go_sign.sh`: genpkey → sign → verify (PASS); wrong msg/key → reject — **7 PASS**
- `CliTest/test_go_encfile.sh`: 1 MiB encfile → decfile → `cmp`; tamper → exit non-zero;
  edge cases 0/1/32-byte files — **5 PASS**
- `CliTest/test_go_interop.sh`: Go↔Python and Go↔C cross-tool: `encfile`/`decfile`,
  `sign`/`verify`, `dgst` output agreement — **10 PASS**

---

#### Notes

- **No external dependencies.** Uses only stdlib: `math/big`, `crypto/rand`, `crypto/subtle`,
  `encoding/base64`, `encoding/binary`, `flag`, `fmt`, `os`, `io`, `bytes`.
- **Go module wiring.** `HerraduraCli/go.mod` and the updated `CryptosuiteTests/go.mod`
  both use `replace herradurakex => ../` so no network access or versioned release is needed.
- **Build collision guard.** CLI binary is `herradura_cli_go`; suite stays
  `"Herradura cryptographic suite_go"`; tests stay `Herradura_tests_go`.
- **`build_go.sh` suite build change.** After Batch 1, the suite file imports a local
  package and can no longer be built with `go build file.go` (file mode ignores the module
  root for intra-module imports).  Change to `go build -o "${SUITE_BIN}" .` and update
  `CLAUDE.md` build commands accordingly.
- **HSKE-NL-A2 deterministic caveat** (TODO #12): `enc` help text warns that identical
  (key, plaintext) pairs always produce identical ciphertext.
- **Stern-F at N=256 is slow.** Flag in help text; recommend `--bits 32` for testing,
  matching the assembly targets.
- **HFSCX-256 test renumbering.** Adding test [17] in Go tests shifts benchmarks;
  update printed labels accordingly.

Status: **DONE** (v1.5.28) — Batches 1–5 complete; see batch checklist above.

---

## v1.5.28 PQC Security & Performance Review — Findings (2026-05-08)

Findings from a focused review of `SecurityProofs.md` §11 (PQC sections) and the
Python proof scripts (`hkex_nl_verification.py`, `hkex_rnl_failure_rate.py`,
`nl_fscx_prf_analysis.py`).  Each item has been independently audited against the
deployed code paths.  Items #29–#33 were patched in v1.5.28; #34–#41 remain open.

---

### 29. HPKS-Stern-F secret sampling used Mersenne Twister (Security, Critical)
**File:** `Herradura cryptographic suite.py` (Python only — C uses `/dev/urandom`,
Go uses `crypto/rand`)

`stern_f_keygen`, `hpks_stern_f_sign`, `hpke_stern_f_encap`, and
`hpke_stern_f_encap_with_e` all sampled secret weight-`t` error vectors with
`random.sample(range(n), t)`.  Python's `random` module is Mersenne Twister
(MT19937) — not a CSPRNG; its 19937-bit state is recoverable from ~624 32-bit
outputs.  The leaked values include the long-term private key `e_int`, the
per-round Fiat-Shamir blinding `r_int` (and therefore `y = e ⊕ r`, leaking `e`),
and the Niederreiter encapsulation error `e'`.

Fix: introduced `_csprng_weight_t(n, t)` using `os.urandom` with 4-byte rejection
sampling; replaced all four `random.sample` call sites.

Status: **DONE (v1.5.28)** — Python only.  C and Go versions independently verified
to be CSPRNG-clean (`/dev/urandom` and `crypto/rand` respectively).

---

### 30. `SDFR=32` default gives ~19-bit signature soundness (Security, Critical)
**File:** `Herradura cryptographic suite.py:155`

`SDFR = 32` Fiat-Shamir rounds yields `(2/3)^32 ≈ 2⁻¹⁸·⁷` soundness — a forger
succeeds with probability one in ~430 000.  Production needs `rounds ≥ 219`
(`⌈λ / log₂(3/2)⌉` for λ=128).  The doc-string warned but offered no runtime
signal; tests, demos, and downstream callers using the default would silently
ship a forgeable scheme.

Fix: relabelled `SDFR` as DEMO ONLY, defined `_STERN_F_PRODUCTION_ROUNDS = 219`,
and added a `RuntimeWarning` from `hpks_stern_f_sign` whenever `rounds < 219`,
quoting the actual soundness in bits (`rounds × log₂(1.5)`).

Status: **DONE (v1.5.28)**.

---

### 31. Stern parity matrix `H` rebuilt on every syndrome call (Performance, High)
**File:** `Herradura cryptographic suite.py` (`_stern_syndrome`, callers)

`_stern_syndrome` reconstructs every row of `H` via the NL-FSCX v1 PRF for each
call.  Inside `hpks_stern_f_sign` and `hpks_stern_f_verify` the same `seed`
generates the same `H` `(rounds × n_rows)` times: at `n=256, n_rows=128, rounds=219`
that is 28 032 row-rebuilds, each 64 NL-FSCX steps — 1.79M wasted PRF evaluations
per signature.

Fix: added `_stern_build_H(seed_int, n, n_rows)` and `_stern_syndrome_H(H_rows, e_int)`.
`stern_f_keygen`, `hpks_stern_f_sign`, `hpks_stern_f_verify`, `hpke_stern_f_encap`,
`hpke_stern_f_encap_with_e`, and `hpke_stern_f_decap` build `H` once per call and
reuse it.  The legacy `_stern_syndrome` is preserved as a thin wrapper for any
external callers.

Status: **DONE (v1.5.28)** — algorithmic save: `(rounds + verify_calls) × n_rows × (n/4)`
NL-FSCX evals per sign/verify pair.  No wire-format change.

---

### 32. `delta(B)` recomputed inside `nl_fscx_revolve_v2` inner loop (Performance, Medium)
**File:** `Herradura cryptographic suite.py:364`

`nl_fscx_revolve_v2` called `nl_fscx_v2` in its loop, recomputing
`delta(B) = ROL(B·⌊(B+1)/2⌋ mod 2ⁿ, n/4)` every step.  Since `B` is held constant
across the revolve, `delta(B)` is a per-call constant.

Fix: precompute `delta(B)` once before the loop (mirrors the existing
`nl_fscx_revolve_v2_inv` optimization from v1.5.9); inner step is now one `fscx`
plus one integer add.  Saves one bigint multiply and one rotation per step.

Status: **DONE (v1.5.28)**.

---

### 33. `hpke_stern_f_decap` brute-force search has no upper bound (Robustness, Low)
**File:** `Herradura cryptographic suite.py:826`

When called without a known `e_int`, `hpke_stern_f_decap` enumerated
`itertools.combinations(range(n), t)` — at `n=256, t=16` that is `C(256,16) ≈ 6.4×10²²`
iterations, effectively non-terminating.

Fix: refuse the brute-force path with a `ValueError` whenever `C(n,t) > 2³²`,
directing the caller to supply `e_int` from a QC-MDPC decoder or to use
`hpke_stern_f_decap_known`.

Status: **DONE (v1.5.28)**.

---

### 34. HFSCX-256 lacks formal analysis in `SecurityProofs.md` (Documentation/Security, Medium)
**Files:** `Herradura cryptographic suite.py:407` (`hfscx_256`), `SecurityProofs.md` §11.9,
`SecurityProofsCode/hfscx_256_analysis.py`

The `hfscx_256` Merkle-Damgård hash on NL-FSCX v1 is used in `_stern_hash`
chains, the `dgst` subcommand, signature pre-hashing, and HSKE-NL-A1-CTR-AEAD
authentication tags, but `SecurityProofs.md` §11 originally contained no
analysis of it.

Resolved by adding §11.9 (subsections 11.9.1–11.9.11) covering:

1. **Construction recap** (§11.9.1): compression `C(s, m) = F₁⁶⁴(s, m)`,
   IV constant, ISO 7816-4 padding, finalization block `(8|D|) ⊕ s₀`.
2. **Security model** (§11.9.2): formalises three assumptions A1 (PRF), A2
   (OWF), A3 (NL-FSCX v1 symmetry implying non-bijection in both inputs).
3. **Collision resistance** (§11.9.3): `2¹²⁸` classical / `2⁸⁵` quantum (BHT)
   under A1; MD-folklore reduction.
4. **Preimage / second-preimage** (§11.9.4): `2²⁵⁶` classical / `2¹²⁸` quantum
   under A2.
5. **Length-extension resistance** (§11.9.5): Theorem 18 — finalization
   defeats trivial extension under A2; keyed mode adds independent layer.
6. **MAC mode recommendation** (§11.9.6): raw keyed-IV is sufficient for the
   current single-purpose AEAD; HMAC-HFSCX-256 recommended if the same key is
   ever reused across protocols.
7. **Domain separation strategy** (§11.9.7): documents current implicit
   separation; recommends 1-byte domain-tag prefix for future hardening.
8. **Davies-Meyer hardening** (§11.9.8): recommends `C_DM(s, m) = F₁⁶⁴(s, m) ⊕ s`
   for fixed-point + free-start-collision hardness; deferred to suite v2.0
   bundled with other wire-format changes (#37, #38, #39).
9. **`_stern_hash` cross-reference** (§11.9.9): notes that the Stern protocol
   uses a different chain function — analysis is TODO #36, not #34.
10. **Empirical evidence** (§11.9.10): backed by `hfscx_256_analysis.py` —
    SAC mean 128.013/256 (input) and 128.091/256 (key) over 5 000 trials each;
    byte chi² = 223.1 < 293.2 critical at p=0.05; 0 length-extension forgeries
    in 200 trials; 1000/1000 domain-separation distinct; 0 fixed points in 200
    `(s, m)` trials.

The Davies-Meyer switch and the explicit DS-byte prefixes are deferred (open
hardenings, not security-critical at deployed parameters).

Status: **DONE (v1.5.30)** — §11.9 added; `hfscx_256_analysis.py` runs in
~30 s and is referenced from §8 Experimental Code Index.

---

### 35. NL-FSCX v1 PRF — exhaustive Walsh spectrum at small `n` (Research/Cryptanalysis, Medium)
**File:** `SecurityProofsCode/nl_fscx_prf_analysis.py` §5

§5 of the PRF analysis script samples 2 000 random `(a, b)` mask pairs out of
`2^{2n} = 2^64` (at `n=32`) and reports the maximum observed |bias|.  This is a
Monte-Carlo estimate, not a bound — a low-frequency bias whose mask falls outside
the 2 000-element sample is invisible.

Add an exhaustive Walsh transform at small `n` (e.g. `n=12` or `n=16`):
- Compute `|Bias(a, b)|` for **all** mask pairs.
- Report max bias and compare to the random-function bound `O(√n / 2^{n/2})`.
- Extrapolate (Bernstein bound) to `n=32, 256`.

A confirmed bound is required for any rigorous PRF claim under §11.8.4 Theorem 17.

Status: **DONE (v1.5.42)** — New §9 added to `nl_fscx_prf_analysis.py` with four sub-sections:

- **§9.1 (n=8):** Exhaustive over all 255×256 pairs; max_bias=1.0 (degenerate at r=2 steps).
- **§9.2 (n=12):** Exhaustive over all 4 095×4 096 = 16.7M mask pairs (~2 min, 2 keys).
  Result: max_bias ≈ 0.427, ratio ≈ 4.74× the random-function bound (0.090).
  H_linear baseline: max_bias=1.0 (correctly detected as affine).
- **§9.3 (Range compression):** F_stern maps only ~40–55% of inputs to distinct outputs at
  n=8/12/16, vs ~63% expected for a truly random function.  The compressed range inflates
  Walsh coefficients beyond the random bound.  This makes F_stern distinguishable from a
  random function by collision counting at small n.  The impact at n=32 is an open gap.
- **§9.4 (Extrapolation):** E[max_bias] ≈ √(4n·ln2 / 2^n); at n=32 ≈ 1.44×10⁻⁴.

Key finding: the exhaustive Walsh scan reveals a range compression effect that is not
captured by §5 sampling.  This does NOT constitute a confirmed PRF bound; instead it
identifies a new open gap — the range compression at n=32 requires investigation.
The finding motivates TODO #36 (QRO gap) and a future range-analysis item at n=32.
`EXHAUSTIVE_N12 = True` by default; set False to skip the ~2-min §9.2 scan.

---

### 36. `_stern_hash` not modeled as QRO in Theorem 17 reduction (Documentation/Security, Medium)
**Files:** `Herradura cryptographic suite.py:603` (`_stern_hash`), `SecurityProofs.md` §11.8.4

Theorem 17's EUF-CMA bound `Pr[forge] ≤ q_H / T_SD + ε_PRF` invokes Unruh's QROM
Fiat-Shamir transform, which requires the hash to behave as a quantum random
oracle.  The implementation uses `_stern_hash`, a chain of `nl_fscx_revolve_v1`
evaluations:

```
h ← NL_FSCX_v1^{n/4}(h ⊕ v_i, ROL(v_i, n/8))   for each item v_i
```

This chain does **not** automatically inherit QRO behaviour from a PRF assumption
on NL-FSCX v1.  Two paths:

1. **Replace** `_stern_hash` with HMAC-HFSCX-256 plus per-slot domain-separation
   constants (`c0`, `c1`, `c2` get distinct DS bytes); reduces security to
   HFSCX-256 collision resistance — depends on #34 first.
2. **Prove** the chain is QRO under the NL-FSCX v1 PRF/OWF assumption using the
   indifferentiability framework (Maurer-Renner-Holenstein 2004 / Coron et al. 2005).

Until this gap is closed, Theorem 17's bound is contingent on an unstated
assumption.

Status: **DONE v1.6.1**.

Added a `ds` (domain-separation) integer parameter to `_stern_hash` (Python suite + test), `stern_hash` (C header + test), `SternHash` (Go package + test), and the C suite n=32 demo KEM (`stern32_hash` initial value).  DS values: c0=1, c1=2, c2=3, KEM-key=4, challenge=0.  Under the ROM on HFSCX-256 (§11.9.2), per-slot DS ensures c0, c1, c2, and the KEM key invoke independent random oracles, satisfying Unruh's QROM requirement for Theorem 17.

Assembly/Arduino (n=32 toy demo): sign/verify `stern_hash1_32`/`stern_hash2_32` do not yet carry per-slot DS; structural distinctness limits same-slot collision to ≤2^{-32} — negligible at n=32.  Full assembly DS is a future hardening item.

SecurityProofs-2.md §11.9.9 updated with QRO argument; Theorem 17 proof step (iv) updated to reference ROM on HFSCX-256.  Validator: 749 OK, 0 FAIL.

---

### 37. `_rnl_lift` rounds toward zero — switch to centered rounding (Performance/Correctness, Medium)
**Files:** `Herradura cryptographic suite.py:510-512`, C / Go / ARM / NASM / Arduino
equivalents, `SecurityProofsCode/hkex_rnl_failure_rate.py:95-97`

`_rnl_round` uses centered rounding `(c·to_p + from_q//2) // from_q`, but
`_rnl_lift` rounds toward zero: `c·to_q // from_p`.  The asymmetry adds a
systematic bias of up to `q/(2p)` to every coefficient, eating into the noise
budget.

Fix:
```python
def _rnl_lift(poly, from_p, to_q):
    return [(c * to_q + from_p // 2) // from_p % to_q for c in poly]
```

**Cross-language coordination required.**  The lift output enters `K_poly` and
the reconciliation hint, so Python's lift must match C, Go, ARM Thumb-2, NASM i386,
and Arduino.  Update all six language implementations in lockstep, then re-run
`hkex_rnl_failure_rate.py` to refresh the failure-rate numbers in
`SecurityProofs.md` §11.5 Q2 / §11.6.

Expected effect: ~2× reduction in worst-case pre-reconciliation failure rate
(currently 2.04 % at `n=32`, 37.24 % at `n=256`).  Post-reconciliation rate stays
at 0 % — this is a margin improvement, not a correctness fix.

Status: **DONE** (v1.5.41).

Applied centered rounding to all six language targets (Python suite, C header,
Go package, Arduino, ARM Thumb-2, NASM i386) and to both assembly test files,
the Python test file, the C test file, and `SecurityProofsCode/hkex_rnl_failure_rate.py`.

Re-running `hkex_rnl_failure_rate.py` shows the pre-reconciliation rates are
within sampling noise of the old values (2.07 % at `n=32`, 37.24 % at `n=256`):
the failure is dominated by polynomial convolution noise over n=256 terms, not
by the single-coefficient lift quantization.  The centered rounding eliminates
the systematic positive bias (up to q/2p ≈ 8 per coefficient) and is the
correct formulation regardless.  Post-reconciliation rate confirmed 0 %.
SecurityProofs-2.md §11.5/§11.6 numbers are unchanged (within noise).

---

### 38. KDF seed degenerates on rotation-periodic K (Security, Low)
**File:** `Herradura cryptographic suite.py` HKEX-RNL KDF and HSKE-NL-A1 seed
derivation (and the equivalent paths in C / Go / ARM / NASM / Arduino).

The v1.5.10 / v1.5.13 fix sets `seed = ROL(K, n/8)` to break the step-1
degeneracy when `A=B=K` (which makes `fscx(K,K)=0`).  The patch degenerates back
to the original problem when `K` has a rotational period dividing `n/8` — e.g.
any `K` of the form `pattern || pattern || …` with `pattern` of width `n/8`.
At `n=32` this is roughly `2⁴ / 2³² ≈ 2⁻²⁸` of the keyspace; at `n=256` negligible.

Defence in depth: XOR a non-rotational nothing-up-my-sleeve constant after the
rotation:

```python
DOMAIN_CONST = 0x6A09E667...   # n-bit constant, low rotational symmetry
seed = ROL(K, n/8) ^ DOMAIN_CONST
```

**Cross-language coordination required.**  Changes the derived `sk`; breaks
Python ↔ C/Go/asm interop.  Schedule with the next major suite version bump.

Practical risk: low — the attacker cannot choose `K` (it is the reconciled
session secret), so the bad-`K` rate is the random-`K` rate, not adversarial.

Status: **DONE (v1.8.0)** — `seed = ROL(K, n/8) XOR DC` where `DC` = SHA-256 initial
hash values (H0..H7, 256-bit; H0 = `0x6A09E667` for 32-bit assembly/Arduino targets).
Implemented across all 6 targets: C (`ba_rnl_kdf_seed` in `herradura.h`), Go (`RnlKdfSeed`
in `herradura/herradura.go`), Python (`_RNL_KDF_DC_256`), ARM Thumb-2 (`RNL_KDF_DC` equ),
NASM i386 (`%define RNL_KDF_DC`), Arduino (`#define RNL_KDF_DC`). All suite, test, and CLI
files updated. Breaking wire change — incompatible with v1.7.x derived keys.

---

### 39. 2-bit Peikert reconciliation for higher key density (Performance, Low)
**Files:** `Herradura cryptographic suite.py` `_rnl_hint`, `_rnl_reconcile_bits`,
plus C / Go / asm / Arduino equivalents.

§11.5 Q2 measures `‖e_A − e_B‖_∞ ≤ 379 ≪ q/8 = 8192`.  With this slack a 2-bit
reconciliation (4 buckets, NewHope-style cross-rounding extension) extracts ~2
bits per coefficient instead of 1.  At `n=256` this halves the polynomial size
needed for a fixed-length output key, doubling HKEX-RNL throughput at the same
security level.

**Cross-language wire-format change.**  Hint encoding and extraction formulas
change; coordinate across all six language targets and refresh
`SecurityProofs.md` §11.4.2 / §11.5 Q2 numbers.

Status: **DONE** (v1.7.0).  Correct formula: $h_i = \lfloor(8c_i + q/4)/q\rfloor \bmod 4$;
$b_i = \lfloor(4c_i + (2h_i+1)\lfloor q/4\rfloor)/q\rfloor \bmod 4$.  All six targets
updated and verified (Python, C, Go, ARM Thumb-2, NASM i386, Arduino).
Test [14] HKEX-RNL passes 20/20 for n=32,64,128,256 across C, Go, Python, ARM, NASM.

---

### 40. NumPy NTT optional acceleration (Performance, Low)
**File:** `Herradura cryptographic suite.py:448` (`_ntt_inplace`)

`_ntt_inplace` does `wn = wn * w % q` in a hot pure-Python inner loop.  At
`q = 65537` all NTT values fit in `uint32`.  A NumPy lift would give roughly 10×
speedup on `_rnl_poly_mul` without changing semantics or wire format:

- Precompute bit-reversal permutation and twiddle table once (already partial in
  v1.5.17 — the table cache is the right hook).
- Vectorize the butterfly with `np.uint32` arithmetic + Mersenne-style modular
  reduction.
- Gate behind `try: import numpy` so plain-Python deployments keep working.

Python-side only; no cross-language coordination needed.

Status: **DONE** (v1.7.3).  `_ntt_tables(q, n)` builds and caches the bit-reversal
permutation, per-stage forward/inverse twiddle arrays (`int64`), and the negacyclic
pre/post-twist power arrays on first call, keyed by `(q, n)`.  `_ntt_np(arr, q, invert)`
applies them via vectorised NumPy butterfly loops.  `_rnl_poly_mul` dispatches to the
NumPy path when `_NUMPY` is True, falling back to the original `_ntt_inplace` otherwise.
Both `Herradura cryptographic suite.py` and `CryptosuiteTests/Herradura_tests.py` updated.
Gate: `try: import numpy as _np` at module level.  Wire format unchanged.

---

### 41. Constant-time audit for `_stern_apply_perm` and friends (Security, Medium)
**Files:** `Herradura cryptographic suite.py:686-692` (`_stern_apply_perm`),
`:620-626` (`_stern_syndrome`), `:530-551` (`_rnl_cbd_poly`); plus the C, Go,
ARM Thumb-2, NASM i386, and Arduino Stern-F implementations.

The Python implementation has data-dependent branching on secret bit-vectors:

```python
for i in range(N):
    if (v_int >> i) & 1:           # branches on each secret bit of r/y/e
        result |= 1 << perm[i]
```

Stern's protocol relies on hiding which positions are set in `e`; branch timing
leaks them.  CPython further leaks via `bin(x).count('1')` (variable-time over
int size) and `% q` on bigints.

Action items:
1. **Document** that the Python suite is a reference implementation and is **not**
   constant-time; production deployments must use the C / asm targets.
2. **Audit** the C, Go, ARM Thumb-2, NASM i386, and Arduino Stern-F implementations
   for the same data-dependent branching.  Where present, replace with branchless
   bit manipulation:
   ```c
   result |= ((-((v >> i) & 1)) & (1ULL << perm[i]));
   ```
3. **Add a constant-time test** to the Python proof scripts that measures timing
   variance vs. secret Hamming weight, failing if Pearson correlation exceeds a
   threshold.

Status: **DONE** (v1.5.39+1).

---

### 42. F_stern range compression at n=32 — PRF gap analysis (Security/Research, Medium)
**Files:** `Herradura cryptographic suite.py` (`_stern_apply_perm`, `_stern_hash`),
`SecurityProofsCode/nl_fscx_prf_analysis.py` §9.3, `SecurityProofs-2.md` §11.8.4

#### Background

The v1.5.42 exhaustive Walsh scan (TODO #35) revealed that `F_stern(K, ·)` maps only
~40–55% of inputs to distinct outputs at small n (n=8/12/16), vs ~63% expected for a
truly random function.  This **range compression** is attributable to the fixed-B
iteration structure: `NL_FSCX_v1(·, K, n)` is not a bijection for general K, and
composing r = n/4 non-bijective maps reduces the range further.

At n=12, the compression inflates the exhaustive Walsh max_bias to ~0.43
(4.7× the random-function bound), making `F_stern` distinguishable from a
random function by collision counting.  At the deployed n=32, the §5 sampling
test is consistent with the random bound for those sampled pairs, but:

- §5 samples only 2 000 pairs out of 2^64 possible — the worst-case (a, b) is
  not reachable by sampling.
- Enumerating all 2^32 outputs to measure range size at n=32 is infeasible in
  pure Python.

#### Plan

**Step 1 — Measure range compression at n=32 in C or Go.**

Add a dedicated test to `CryptosuiteTests/Herradura_tests.c` (or `.go`) that:
- Evaluates `F_stern(K, x)` for all x in [0, 2^32) — requires 64 GB of RAM for
  a full truth table, OR a HyperLogLog approximate distinct-count with ~0.1% error
  using ~1 MB.
- Reports the fraction of distinct outputs vs the random-function expectation 63.2%.

Alternatively: sample 2^20 = 1M random inputs and count distinct outputs.  For a
compressed function with 40% range, the birthday probability after 1M samples is
~99.9%, giving a reliable estimate.

**Step 2 — Characterize the compression mechanism.**

Determine whether the range compression at n=32 is:
(a) Similar to small n (~40%) → large Walsh bias exists at n=32 → PRF claim is
    challenged; requires either a security reduction that accounts for compression
    or a protocol redesign (e.g., adding output hashing to flatten the distribution).
(b) Substantially smaller at n=32 (~60–63%) → compression shrinks as n grows and
    r=n/4 provides enough mixing → PRF claim survives.

If (a): add TODO to hash the F_stern output through HFSCX-256 to remove the
compression artifact (adds one hash per row of the Stern matrix H — acceptable overhead).

**Step 3 — Update SecurityProofs-2.md §11.8.4.**

Replace the "open gap" note with the measured compression fraction at n=32 and the
resulting security assessment.

Status: **DONE v1.5.43** (all three steps complete).

**Step 1 result (v1.5.43) — DONE.**  Test [20] added to `CryptosuiteTests/Herradura_tests.c`:
HyperLogLog over all 2^32 inputs, m=16384 registers (~0.81% std-error), ~55 s per K on
OrangePi RK3588.  Results for three representative K values:

| K           | Hamming weight | Distinct fraction | vs random (63.2%) |
|-------------|----------------|-------------------|-------------------|
| 0x00000003  | 2 (min-t)      | **20.9%**         | 0.33×             |
| 0xA3C5E7B9  | 17 (pseudo-rnd)| **21.7%**         | 0.34×             |
| 0xFFFFFFFD  | 30 (max-t)     | **28.3%**         | 0.45×             |

**Finding:** Range compression at n=32 is case **(a)** — the compression does NOT shrink
as n grows.  All three K values are far below the 63.2% random expectation and are even
more compressed than the small-n results (40–55% at n=12/16).  The range of
F_stern(K, ·) at n=32 is only **21–28%** of the output domain.  This means:

1. Walsh biases well beyond the random bound persist at n=32 — the §9.3 gap is confirmed
   at the deployed bit size.
2. The PRF claim for `_stern_hash` in Theorem 17 is challenged — the hash chain function
   does not behave like a random function even at n=32.
3. The fix is clear: **hash F_stern output through HFSCX-256** (one call per round) to
   flatten the distribution.  This is a one-line change per target; wire-format change
   for signatures (new version tag needed).

**Step 2 result (v1.5.43) — DONE.**  §10 added to `SecurityProofsCode/nl_fscx_prf_analysis.py`:

Step-by-step range fraction at n=8/12/16/20 (exhaustive):

| n  | r  | k=1  | k=2  | k=3  | k=4  | k=5  |
|----|----|----- |------|------|------|------|
|  8 |  2 | 0.71 | 0.49 |      |      |      |
| 12 |  3 | 0.68 | 0.50 | 0.41 |      |      |
| 16 |  4 | 0.65 | 0.48 | 0.40 | 0.34 |      |
| 20 |  5 | 0.63 | 0.45 | 0.38 | 0.32 | 0.27 |

Per-step compression ratio: ~0.70–0.77 (increasing with n), vs 0.632 for a random
function.  Back-calculated from C result (n=32, 23.6% mean): ~0.815 at n=32.

**Mechanism:** each nl_fscx_v1(·, B) step with fixed B is non-injective, compressing the
range by ~0.74x (at small n) to ~0.82x (at n=32) per application.  The step count
r=n/4 grows linearly, so cumulative compression worsens with n.  At n=256, r=64 steps
with ratio ~0.86 gives ~9×10⁻⁵ of the domain — effectively a constant function.

This confirms the open gap is real and grows with n.  See TODO #43 for the fix.

**Step 3 result (v1.5.43) — DONE.**  SecurityProofs-2.md §11.8.4 updated: evidence matrix row added, "open gap" replaced with HLL measurement table, mechanism explanation, O(2^16) distinguisher security implication, and Fix formula (F_stern-v2 via HFSCX-256, TODO #43).

Batch 1 — Python: added non-CT module header comment and docstrings to
`_stern_apply_perm` and `_stern_syndrome_H` documenting reference-only status.

Batch 2 — C (`herradura.h`) + Arduino (`.ino`): replaced data-dependent `if`
branch with `uint8_t mask = -(v_bit)` (0x00 or 0xFF) in `stern_apply_perm`
and `stern_apply_perm_32`.

Batch 3 — Go (`herradura/herradura.go`): replaced `if v.Val.Bit(i) == 1 {
SetBit(1) }` with unconditional `SetBit(Bit(i))` in `SternApplyPerm`.

Batch 4 — ARM Thumb-2 (`.s`): removed `beq sap_next`, replaced with
`neg r3, r0` carry mask; NASM i386 (`.asm`): removed `jnc .sap_next`,
replaced with `bt`/`sbb eax,eax`/`bts ebx,edx`/`and ebx,eax` sequence.
Both assembly builds verified correct under qemu-arm and qemu-i386.

Batch 5 — `SecurityProofsCode/stern_ct_demo.py`: timing demonstration script
measuring Pearson correlation between execution time and Hamming weight for
both the branchy reference and the branchless variant. Documents that CPython
big-int allocation is inherently weight-proportional (so Python is non-CT at
any level), while hardware targets are genuinely constant-time.

---

### 43. Hash `_stern_hash` output through HFSCX-256 to fix range compression (Security, High)
**Files:** all six language targets (suite + test files), `SecurityProofs-2.md` §11.8.4

The Step 1/Step 2 analysis (TODO #42, v1.5.43) confirmed that F_stern(K,·) at the
deployed n=32 maps only ~21–28% of inputs to distinct outputs (vs 63.2% expected for a
random function).  This range compression makes F_stern distinguishable from a random
function by collision counting and directly falsifies the PRF assumption used in
Theorem 17 (EUF-CMA bound for HPKS-Stern-F).

**Fix:** compose F_stern's output with HFSCX-256 before use:

```python
def _stern_hash_v2(h, K, n):
    raw = _nl_fscx_revolve_v1(h ^ K, rol(K, n // 8, n), n // 4, n)
    digest = hfscx_256(raw.to_bytes(n // 8, 'big'))
    return int.from_bytes(digest, 'big') >> (256 - n)
```

This eliminates the range compression artifact: HFSCX-256's output distribution
approaches 63.2% distinct by the empirical analysis in §11.9 (`hfscx_256_analysis.py`).

**Cross-language coordination required.**  Update `_stern_hash` in all six suite
targets and `_stern_hash_ba` in the C/Go/asm test files.  Wire-format change: old
and new HPKS-Stern-F signatures are incompatible — add a version tag (e.g.
`HSTERN_V = 2`) and increment the suite version to 1.6.0 (first breaking change since
the Stern-F introduction).

**Dependencies:** TODO #34 (HFSCX-256 formal analysis) is DONE (v1.5.30); this TODO
can proceed immediately.

Status: **DONE v1.6.0**.  Updated all six language targets: Python (`_stern_hash`), C/`herradura.h` (`stern_hash`), Go package (`SternHash`), C suite n=32 demo (`stern32_hash`), ARM/i386 assembly (new `hfscx_32` + updated `stern_hash1_32`/`stern_hash2_32`), Arduino.  Also updated C/ARM/i386 test files.  All sign+verify and encap+decap tests pass across all targets.

---

## Updated priority order

1. #28 — Go CLI + `herradura` Go package (**DONE v1.5.28**)
2. #27 — HerraduraCli C CLI + shared header library (**DONE v1.5.26**)
3. #17 — Multi-size standardization (Batches 3-6, C tests) (**DONE v1.5.20**)
4. #5  — HPKS-NL / HPKE-NL PQC claim (**DEPRECATED**)
5. #25 — HerraduraCli Python CLI (**DONE v1.5.23**)
6. #26 — Large-file AEAD + hashed signing (**DONE v1.5.24**)
7. #21 — i386 HKEX-RNL zero session key (**DONE v1.5.22**)
8. #23 — Go HKEX-RNL test coverage n=128,256 (**DONE v1.5.22**)
9. #16 — CBD bit efficiency (**DONE v1.5.22**)
10. #9  — HSKE-NL-A1 counter=0 degeneracy (**DONE v1.5.13**)
11. #22 — ARM HSKE-NL-A2 R_VALUE fix (**DONE v1.5.21**)
12. #19 — Stale version banners (**DONE v1.5.21**)
13. #20 — Python suite q=3329 label (**DONE v1.5.21**)
14. #24 — C binary `_c` suffix (**DONE v1.5.20**)
15. #18 — Parameterized integer arithmetic layer (**DONE v1.5.20**)
16. #15 — Fermat prime fast modulo (**DONE v1.5.20**)
17. #14 — NTT twiddle precomputation (**DONE v1.5.17**)
18. #29 — HPKS-Stern-F CSPRNG fix (**DONE v1.5.28**)
19. #30 — `SDFR=32` demo runtime warning (**DONE v1.5.28**)
20. #31 — Stern parity matrix caching (**DONE v1.5.28**)
21. #32 — `delta(B)` precompute in `nl_fscx_revolve_v2` (**DONE v1.5.28**)
22. #33 — `hpke_stern_f_decap` brute-force guard (**DONE v1.5.28**)
23. #37 — `_rnl_lift` centered rounding (cross-language wire change) (**DONE v1.5.41**)
24. #34 — HFSCX-256 formal analysis in §11 (**DONE v1.5.30**)
25. #43 — Hash `_stern_hash` output through HFSCX-256 (range compression fix) (**DONE v1.6.0**)
26. #36 — `_stern_hash` QRO modeling for Theorem 17 (**DONE v1.6.1** — DS parameter + §11.9.9 QRO argument)
27. #41 — Constant-time audit / documentation (**DONE v1.5.39+1**)
28. #35 — NL-FSCX v1 PRF Walsh spectrum at small `n` (**DONE v1.5.42**)
29. #42 — F_stern range compression at n=32 (**DONE v1.5.43** — all 3 steps)
30. #39 — 2-bit Peikert reconciliation (cross-language wire change) (**DONE v1.7.0**)
31. #38 — KDF rotation-periodic-K patch (cross-language wire change) (**DONE v1.8.0**)
32. #40 — NumPy NTT optional acceleration (**DONE v1.7.3**)
33. KR-1 — §11.8.4 KaTeX cascade failure (**DONE v1.5.38** — document split)

---

## GitHub KaTeX Rendering — §11.8.4 Cascade Failure (RESOLVED)

### KR-1 — §11.8.4 display blocks show "Unable to render expression" from H_i onward ✓ DONE

**File:** `SecurityProofs.md` → split into `SecurityProofs-1.md` + `SecurityProofs-2.md`

**Symptom:** On the devtest branch on GitHub, ALL display math blocks from the `H_i` formula (§11.8.4, line ~1607) onward failed to render. The last correctly rendered display block was `\Pr[\mathrm{forge}] \leq …` at the end of §11.8.3. The GitHub API (GFM mode) correctly wrapped every display block in `<math-renderer class="js-display-math">` — the failure was purely client-side JavaScript.

**Root cause:** GitHub enforces a per-page limit of approximately 750 math expressions. `SecurityProofs.md` exceeded this threshold, causing a cascade failure for every expression past the limit. All content-level fix attempts (Rules 1–9, spacing commands, delimiter formats) were irrelevant — the document was simply too large.

**Resolution (v1.5.38–v1.5.39):** Split `SecurityProofs.md` at the §10/§11 boundary into two files, each under ~750 math expressions:
- `SecurityProofs-1.md` — §1–§10 (~753 expressions)
- `SecurityProofs-2.md` — §11–§11.9 (~725 expressions)

This fix is documented in CLAUDE.md Rule 5 (per-page math expression limit).

**Attempted fix versions (all superseded by the document split):**
| Version | Change | Result |
|---|---|---|
| v1.5.31–v1.5.34 | Fixed Rules 1–6 violations (`\textunderscore`, `\textdollar`, `^*`, display blocks) | Cascade still present |
| v1.5.35 | `$[N,k,t]$` → `$\lbrack N,k,t\rbrack$`; multi-line `$$` format | Cascade still present |
| v1.5.36 | Rule 7 added to CLAUDE.md; no content change | Cascade still present |
| v1.5.37 | Fixed `\begin{cases}` Rule 8 violation in §11.9 | Cascade still present |
| v1.5.38 | Reverted to single-line `$$expr$$` format; split document | Cascade resolved |

---

## Arduino AVR Emulation Verification (2026-05-20)

**Goal:** Confirm both `.ino` files compile cleanly to ATmega2560 ELF binaries and produce
correct output when run under `simavr`.

### Batch 1 — Prerequisites
- [x] `avr-gcc` / `avr-g++` present (`/usr/bin/avr-gcc`)
- [x] Arduino core headers present (`/usr/share/arduino/hardware/arduino/avr/cores/arduino/`)
- [x] ATmega2560 variant headers present (`…/variants/mega/`)
- [x] `simavr` present (`/usr/bin/simavr`)

Status: **DONE** — all prerequisites confirmed (2026-05-20).

### Batch 2 — Build (DONE 2026-05-20)
- [x] `build_arduino.sh` compiles suite → `Herradura cryptographic suite_avr.elf` (43586 text + 2100 data + 2687 bss = 48373 bytes)
- [x] `build_arduino.sh` compiles tests → `CryptosuiteTests/Herradura_tests_avr.elf` (46098 text + 1048 data + 2719 bss = 49865 bytes)
- [x] No compiler errors or warnings in either target

### Batch 3 — Run suite under simavr (DONE 2026-05-20 — all pass)
- [x] Output captured; runs one full iteration and loops correctly
- [x] All protocol sections printed: HKEX-GF, HSKE, HPKS, HPKE, HSKE-NL-A1, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL, HPKS-Stern-F, HPKE-Stern-F
- [x] All `+` pass markers present; no `-` failure markers; HKEX-RNL keys agreed on first try
- [x] EVE bypass section: all 4 bypass attempts rejected (`- Eve …`)

### Batch 4 — Run tests under simavr (DONE 2026-05-20 — all pass)
- [x] All 12 tests print `[PASS]` on every loop iteration
- [x] Test [7] HKEX-RNL: 10/10 raw agree, 10/10 sk agree (100%; uses simpler PP=2 rounding)

### Batch 5 — Known issues to address after verification
- [x] **Version string stale:** suite `loop()` prints `v1.5.23` but file header is `v1.6.1` — fixed banner to `v1.6.1`
- [x] **Tests use old HKEX-RNL reconciliation:** upgraded `RNL_PP=2`→`4`, added `rnl_hint`/`rnl_reconcile`, updated `rnl_agree` to hint-based signature, fixed `rnl_lift` to centered rounding, updated `test_hkex_rnl` call site — all 12 tests still `[PASS]`
- [x] **Tests `rnl_rand_poly` missing rejection sampling:** replaced bare `% RNL_Q` with 3-byte threshold guard (threshold=`0xFF00FFu`) matching suite


Status: **DONE v1.5.38** — resolved by splitting the document; per-page expression limit documented in CLAUDE.md Rule 5.

---

## Security Audit — Identify Insecure Functions

**Goal:** Systematically locate functions in all language targets that have
cryptographic or memory-safety weaknesses, and produce a prioritized list of
findings for remediation.

### Step 1 — Automated static analysis

Run language-appropriate scanners across all source files and capture output:

| Target | Tool | Command |
|---|---|---|
| C (suite + tests) | `cppcheck` | `cppcheck --enable=all --inconclusive "Herradura cryptographic suite.c" CryptosuiteTests/Herradura_tests.c` |
| C | grep for known-unsafe libc | `grep -n 'gets\|strcpy\|strcat\|sprintf\|scanf\b\|rand()\b' "Herradura cryptographic suite.c" CryptosuiteTests/Herradura_tests.c` |
| Python | `bandit` | `bandit -r "Herradura cryptographic suite.py" CryptosuiteTests/Herradura_tests.py` |
| Go | `gosec` | `gosec ./...` from repo root |
| Assembly (ARM + NASM) | grep | `grep -n 'rand\|srand\|memcpy\|strcpy' "Herradura cryptographic suite.s" "Herradura cryptographic suite.asm"` |

Status: **DONE** — findings logged in Audit notes (SA-01 through SA-09; all resolved v1.7.4).

### Step 2 — CSPRNG audit

Verify every random-number call draws from a cryptographically secure source.
Insecure sources: `rand()`, `srand()`, `random()`, Python `random` module,
Go `math/rand`, any seeded PRNG used for key material.

- **C:** all calls must be `getrandom()` or `/dev/urandom` reads; `prng_next` is deterministic by design and must only be used for test vectors, never key generation.
- **Go:** confirm only `crypto/rand` is imported for key material; flag `math/rand` near key generation.
- **Python:** confirm `os.urandom` everywhere; flag `random.randint` / missing `secrets` usage.
- **Assembly:** ARM reads `/dev/urandom`; NASM uses the C PRNG only for fixed test vectors — verify this boundary.
- **Arduino:** `random()` is seeded from `analogRead` (not a CSPRNG); document as a known limitation.

Status: **DONE** — findings in SA-01, SA-07; all resolved v1.7.4.

### Step 3 — Constant-time audit

Secret-dependent branches and memory accesses enable timing side channels.
Audit every function that touches private keys, session keys, or signature scalars:

1. **Equality comparisons** — flag `memcmp` or `==` on key material; replace with constant-time XOR-accumulate.
2. **Early-exit loops** — flag `break`/`return` inside loops iterating over secret data.
3. **Table lookups indexed by secret** — flag array accesses where the index is derived from a secret byte (cache-timing leak).
4. **Variable-time division** — flag `%` and `/` on secret values in C; integer division is variable-time on most CPUs.

Highest-risk functions (audit first):
- `gf_mul` / `gf_mul_64` / `gf_mul_ba` — carryless multiply with early-exit `if (b & 1)` check
- `gf_pow` / `gf_pow_ba` — square-and-multiply; exponent bit scan leaks private key bits
- `ba_mul_mod_ord` / `mul128_mod_ord128` — Schnorr scalar `a·e mod ord`
- `hpks_verify` / `hpks_nl_verify` — final key-equality comparison
- `rnl_agree` / `rnl_hint` / `rnl_reconcile_bits` — session key derivation and comparison

Status: **DONE** — findings in SA-02 through SA-06; all resolved v1.7.4.

### Step 4 — Key material hygiene

Check that private keys and session secrets are cleared from memory after use:

- **C:** flag stack arrays holding `sk`, `a_priv`, `s_A`, `s_B` that are not `memset`-zeroed before return; use `explicit_bzero` or a compiler-barrier pattern.
- **Go:** `big.Int` and slices holding private key material are not guaranteed to be cleared by the GC; document as a known limitation.
- **Python:** `bytearray` can be zeroed; `int` and `bytes` are immutable and cannot — document any places where clearing is not possible.
- **Assembly:** verify that callee-saved registers holding key material are cleared before `pop`/`bx lr`.

Status: **DONE** — findings in SA-09; resolved v1.7.4. Go/Python zeroing limitations documented.

### Step 5 — Buffer bounds and integer overflow (C and assembly)

- **C:** verify all fixed-size arrays (`uint8_t hint[RNL_N]`, `uint32_t poly[RNL_N]`) are indexed only within declared bounds; flag any index derived from an untrusted length.
- **C:** check `rnl_ntt` butterfly index `k + len/2` does not exceed `n` for all valid `len` values.
- **NASM i386:** re-audit stack frame sizes in `rnl_poly_mul`, `rnl_hint`, `rnl_reconcile_bits` — the v1.5.3 wrong-offset bug (TODO A2) was a stack read error; verify no similar issues remain after Peikert additions.
- **ARM Thumb-2:** verify `udiv` in `rnl_hint` does not divide by zero for degenerate inputs.

Status: **DONE** — no buffer overflows found; NTT index bounds verified; NASM stack audit clean after TODO A2 fix.

### Step 6 — Hardcoded test vectors vs. production code paths

Confirm that fixed private scalars (`a_priv = 0xDEADBEEF`, `b_priv = 0xCAFEBABF`)
and fixed Stern error vectors appear **only** in demo `main()`/`loop()` blocks and
test files, never in production key-generation paths. Grep:

```bash
grep -rn 'DEADBEEF\|CAFEBABF\|a_priv\|b_priv\|known_e\|test_e' \
    "Herradura cryptographic suite".{c,go,py,s,asm,ino}
```

Flag any occurrence outside a clearly demarcated `/* demo */` or `#ifdef TEST` block.

Status: **DONE** — hardcoded constants confirmed in demo/test paths only; no production key-gen paths affected.

### Step 7 — Compile findings into a remediation table

After steps 1–6, add a table here with columns:

| ID | File(s) | Function | Weakness | Severity | Status |
|---|---|---|---|---|---|
| SA-01 | `suite.asm`, `suite.s` | `prng_next` (LCG) | Fixed seed `0xDEADBEEE` — entire PRNG sequence is deterministic across all runs; every "random" key, nonce, and polynomial is identical every run. In HPKS Schnorr the signing nonce k is predictable → private key recovery via `a = (k - s)·e⁻¹ mod ord`. Affects HKEX-GF k, HSKE-NL-A1 nonce N, HKEX-RNL blind polynomial + secret, Stern-F seed/error. ARM Thumb-2 and NASM i386 are both affected; neither seeds from `/dev/urandom` or `getrandom`. | **Critical** | **DONE (v1.7.4)** |
| SA-02 | `herradura.h:227` | `gf_pow_ba` | Square-and-multiply: `while (!ba_is_zero(&e))` loop count leaks the bit-length of the private key; `if (e.b[KEYBYTES-1] & 1)` branches on each private key bit — full key bit pattern leaks via timing. Used with private key `a` in HKEX-GF and HPKS sign. | **High** | **DONE (v1.7.4)** |
| SA-03 | `herradura.h:208` | `gf_mul_ba` | Inner-loop `if (bb.b[KEYBYTES-1] & 1)` branches on the bit being processed — execution path differs per secret bit. Called from `gf_pow_ba` with private key as exponent; also leaks via carry branch `if (ba_shl1(&aa))`. | **High** | **DONE (v1.7.4)** |
| SA-04 | `herradura.h:338` | `ba_mul_mod_ord` | `if (!ai) continue` skips the entire inner multiply loop for zero bytes in Schnorr scalar `a` — leaks zero-byte positions in the private key via timing. Used in `HPKS_sign`: `ba_mul_mod_ord(&ae_s, &a, &e_s)`. | **High** | **DONE (v1.7.4)** |
| SA-05 | `herradura/herradura.go:210` | `GfPow`, `GfMul` | Same variable-time square-and-multiply as SA-02/03: `eCopy.Sign() > 0` loop count + `And(eCopy, one).Sign() != 0` branch per key bit. `big.Int` operations are not constant-time. | **High** | **DONE (v1.7.4)** |
| SA-06 | `suite.py:359` | `gf_pow`, `gf_mul` | Same variable-time pattern as SA-02/03: `while exp:` loop exits early on leading zeros; `if exp & 1:` branches on each exponent bit. Python CPython also leaks via GIL scheduling and object allocation patterns. | **High** | **DONE (v1.7.4)** |
| SA-07 | `CryptosuiteTests/Herradura_tests.py:393,401` | `stern_f_keygen`, `hpks_stern_f_sign` | `random.sample()` (Mersenne Twister) used for error vector `e_int` (private key) and nonce `r_int`. MT is predictable from 624 observed outputs. Suite file uses `_csprng_weight_t()` (os.urandom); test file diverges and would be a dangerous reference if copied. | **Medium** | **DONE (v1.7.4)** |
| SA-08 | `herradura.h:84` | `ba_equal` | `memcmp` is not constant-time — early-exit on first differing byte. Used in `hpks_stern_f_verify` to compare commitment hashes (`ba_equal(&tmp, &sig->c1[i])`). Timing oracle requires repeated verify calls; hashes are public values but early-exit may leak information in online settings. | **Low** | **DONE (v1.7.4)** |
| SA-09 | `Herradura cryptographic suite.c` | `main()` | Stack-allocated private keys (`a`, `b`, `k_s`, `ae_s`, `s_s`, `skA`, `skB`) not zeroed via `explicit_bzero` before function returns. Compiler may optimize away plain `memset`. Process exits immediately in demo context (mitigates), but pattern is unsafe for library use. | **Low** | **DONE (v1.7.4)** |

Severity levels: **Critical** (direct key recovery), **High** (timing/side-channel),
**Medium** (theoretical/implementation gap), **Low** (hygiene/documentation).

Status: **DONE** — remediation table (SA-01 through SA-09) complete; all items resolved v1.7.4.

### Audit notes

**Step 1 — Static analysis:** `cppcheck`, `bandit`, `gosec` not installed on this host.
Grep for known-unsafe libc (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf`, `rand()`) found
no hits in C or assembly suite files.

**Step 2 — CSPRNG:** C: no `rand()`/`srand()`/`random()` calls ✓.  Go: no `math/rand` ✓.
Python suite: `os.urandom` exclusively ✓.  Python tests: see SA-07.  ARM/NASM: see SA-01
(LCG, not a CSPRNG).

**Step 3 — Constant-time:** SA-02 through SA-06.  The GF-based classical protocols
(HKEX-GF, HPKS, HPKE) all use variable-time `gf_pow`/`gf_mul` with the private key as
exponent.  Highest-risk entry point: `gf_pow_ba` in `herradura.h`.

**Step 4 — Key material hygiene:** Intermediate buffers in `gf_mul_ba` and `gf_pow_ba`
are `memset`-zeroed at entry (not exit), limiting but not eliminating residue.  Stack
private keys in `main()` are not cleared; see SA-09.  Go and Python: language limitations
prevent reliable zeroing of immutable key objects.

**Step 5 — Buffer bounds:** C `rnl_ntt` butterfly indices (`i+k`, `i+k+length/2`) stay
within `[0, RNL_N-1]` for all valid `length` values ✓.  NASM `rnl_poly_mul` uses BSS
globals, no stack overflow risk ✓.  ARM `udiv` divisors in `rnl_reconcile32` are
`RNL_Q=65537` and `RNL_PP=4` (hardcoded constants, never zero) ✓.  ARM `rnl_hint32`
uses threshold comparisons, no division ✓.

**Step 6 — Hardcoded test vectors:** `0xDEADBEEF`/`0xCAFEBABF` appear only in `.asm`,
`.s`, and `.ino` demo `main()`/`loop()` sections, and in assembly string labels.  Not
present in C, Go, or Python suite files ✓.  Confirmed outside production key-generation
paths ✓.

Status: **DONE** — audit complete 2026-05-20; findings SA-01 through SA-09 logged above.

---

### 44. Tutorial and library documentation for C, Go, and Python targets (Documentation, Medium)
**Files:** `herradura.h`, `Herradura cryptographic suite.py`, `docs/TUTORIAL.md` (new),
`docs/examples/c/hello_herradura.c` (new), `docs/examples/go/hello_herradura.go` (new),
`docs/examples/python/hello_herradura.py` (new)

The suite has no documentation or examples aimed at developers who want to integrate
it into their own projects.  All three language implementations are structured as
standalone demo programs.  Concrete friction points:

- **C** — `herradura.h` is a valid header-only library but has no usage guide,
  no concise API summary, and no example project.  The calling sequence for each
  protocol is only visible by reading the 568-line demo `main()`.
- **Go** — the `herradura/` package exists (`package herradura`, module path
  `herradurakex/herradura`) but is undocumented and has no import examples.
- **Python** — the filename contains spaces (`"Herradura cryptographic suite.py"`),
  preventing a plain `import` statement; all Ring-LWR functions are `_`-prefixed
  (private), making HKEX-RNL inaccessible without reading the source.

**Plan:**

1. **`herradura.h` — Protocol Layer section:** eight thin `static inline` wrappers
   that assemble primitives into the four named classical protocols:
   `hkex_gf_pubkey`, `hkex_gf_agree`, `hske_encrypt`, `hske_decrypt`,
   `hpks_sign`, `hpks_verify`, `hpke_encrypt`, `hpke_decrypt`.
   PQC functions (`rnl_keygen`, `rnl_agree`, `hpks_stern_f_sign`, etc.) are
   already protocol-level and need no additional wrappers.

2. **`"Herradura cryptographic suite.py"` — Public aliases:** add
   `hkex_rnl_keygen = _rnl_keygen` and `hkex_rnl_agree = _rnl_agree` before
   `if __name__ == '__main__':`, and extend the module docstring with a
   "Library usage" section documenting the `importlib` load pattern and the
   public API surface.

3. **`docs/TUTORIAL.md`:** comprehensive integration guide covering C, Go, and
   Python — getting started, per-protocol code recipes for all protocol families,
   parameter reference table (KEYBITS, I_VALUE, R_VALUE, RNLQ/P/PP, SDF_N/T/ROUNDS),
   and security notes (classical vs NL/PQC vs code-based; constant-time status;
   production caveats for Stern demo parameters and QC-MDPC decoder gap).

4. **`docs/examples/`:** three minimal runnable programs — one per language — each
   demonstrating HKEX-GF, HSKE, HKEX-RNL, and HPKS-Stern-F in ~80 LOC.

**Standardization changes only where necessary:** the Go package and `herradura.h`
are already well-structured; changes are additive only.  Python private `_rnl_*`
aliases are exposed without renaming.  No wire-format changes, no version bumps
to protocol output.

Status: **DONE v1.7.4** — Protocol Layer wrappers added to `herradura.h`; public
aliases `hkex_rnl_keygen` / `hkex_rnl_agree` and library docstring added to
`"Herradura cryptographic suite.py"`; `docs/TUTORIAL.md`, `docs/examples/c/`,
`docs/examples/go/`, `docs/examples/python/` created and verified.

---

### 45. C `stern_gen_perm` 16-bit PRNG bias (Security, High)

**Files:** `herradura.h:958-972`

`stern_gen_perm` extracts only the bottom 16 bits of each NL-FSCX v1 state block
(`(st.b[KEYBYTES-2] << 8) | st.b[KEYBYTES-1]`) to generate Fisher-Yates swap
indices, then reduces modulo `(n - i)` without rejection sampling.  Two problems:
(a) only 65536 possible values feed into a range that can be up to 255, producing
modular bias proportional to `65536 mod (n-i)` for each position; (b) using only 2
of 32 bytes wastes 240 bits of PRNG output and weakens the permutation distribution.
A biased permutation leaks structural information about the secret error vector `e`
across Stern rounds, potentially narrowing the search space for an adversary.

**Plan:** Replace the 16-bit extraction with a full 256-bit counter-mode draw
(advance the NL-FSCX v1 state once per index, use all 32 bytes in sequence) and
add rejection sampling: if the drawn value modulo `(n-i)` would come from a biased
region (`v >= floor(2^k / (n-i)) * (n-i)` for the drawn bit-width `k`), discard and
redraw.  Mirror the fix in Go `sternGenPerm` and Python `_csprng_weight_t` (already
uses 4-byte rejection sampling; audit for the same bias).

Status: **DONE (v1.8.1)** — Counter-mode extraction and rejection sampling implemented in all
three language targets:
- **C** (`herradura.h` `stern_gen_perm`): `ba_rol_k` key = ROL(pi_seed, KEYBITS/8); walks
  all KEYBYTES of each NL-FSCX v1 state block as 4-byte big-endian draws; `uint64_t`
  threshold `= 2^32 - 2^32 % range` with `(uint64_t)v >= threshold` comparison (critical:
  keeps threshold as `uint64_t` to avoid truncating to 0 when range divides 2^32).
- **Go** (`herradura/herradura.go` `SternGenPerm`): identical counter-mode draw with
  `threshold := uint64(0x100000000) - uint64(0x100000000)%range_`; cursor starts at `nb`
  to force state advance on first draw.
- **Python** (`Herradura cryptographic suite.py` `_stern_gen_perm`): `(1<<32) - (1<<32)%range_`
  rejection threshold; big-endian 4-byte draw from NL-FSCX v1 state.
All single-language round-trips (C sign→C verify, Go sign→Go verify, Python sign→verify) pass.

---

### 46. No soundness warning for SDFR=32 in C and Go (Security, Medium)

**Files:** `herradura.h:899`, `herradura/herradura.go:714`

Python `hpks_stern_f_sign` emits a `RuntimeWarning` when `SDFR < 219` and documents
`_STERN_F_PRODUCTION_ROUNDS = 219` in a module-level constant.  The C and Go
implementations use `SDF_ROUNDS = 32` / the equivalent constant with no warning,
no assertion, and no documentation in the function signature that this is a demo
parameter.  A caller compiling the header or importing the package has no indication
that signing with 32 rounds gives only ~51-bit soundness (2^{-32} per round ×
challenge space 3), far below the 128-bit security target requiring ≥219 rounds.

**Plan:** (1) Add a `#if SDF_ROUNDS < 219` compile-time warning in `herradura.h`
(using `#pragma message` or `_Static_assert` with a descriptive string); (2) add a
`if rounds < 219 { log.Printf("WARNING: ...") }` guard at the top of
`HpksSternFSign` in Go; (3) add a module-level `SDF_PRODUCTION_ROUNDS = 219`
constant to `herradura.h` and document it in the header comment for
`hpks_stern_f_sign`.

Status: **DONE** — `SDF_PRODUCTION_ROUNDS 219` constant and `#pragma message` added
to `herradura.h`; `SdfProductionRounds = 219` constant and `log.Printf` guard added
to `HpksSternFSign` in `herradura/herradura.go`.

---

### 47. HKEX-RNL `m_blind` hint unauthenticated (Security, High)

**Files:** `herradura.h` (rnl_agree / hkex_rnl_agree), `herradura/herradura.go`
(RnlAgree), `"Herradura cryptographic suite.py"` (_rnl_agree), all language targets

The Peikert reconciliation hint vector `m_blind` (2 bits per coefficient, 64 bytes
for n=256) is transmitted from Bob to Alice alongside Bob's public key `b_pub`, but
nothing in the current protocol authenticates or integrity-protects `m_blind`.  An
active adversary who can tamper with the channel can flip hint bits to steer the
reconciled key toward a value of their choosing, breaking the key-agreement
correctness guarantee and potentially leaking information about Alice's or Bob's
private polynomials through the resulting key mismatch.  This is a known weakness of
unauthenticated Peikert reconciliation.

**Plan:** Document this limitation explicitly in the `hkex_rnl_agree` header comment
and `docs/TUTORIAL.md` security notes: "HKEX-RNL provides key agreement only; the
caller is responsible for authenticating the transcript (e.g., via HPKS-NL or a MAC
over `(b_pub ‖ m_blind)`) before using the derived key."  As a separate hardening
step (if desired), consider binding `m_blind` into the KDF input so a tampered hint
produces a different key rather than silent agreement on a wrong key.

Status: **DONE (v1.8.2)** — Warning added to all three language targets and docs:
- `herradura.h` `rnl_agree` block comment: unauthenticated hint caveat + example mitigations
- `herradura/herradura.go` `RnlAgree` doc comment: same caveat
- `Herradura cryptographic suite.py` `_rnl_agree` docstring: same caveat
- `docs/TUTORIAL.md` §NL/PQC security notes: "HKEX-RNL unauthenticated hint" bullet with
  explicit guidance that callers must authenticate `b_pub ‖ m_blind` before using the key.

---

### 48. Fiat-Shamir challenge derivation inconsistency across languages (Security/Interoperability, Medium)

**Files:** `herradura.h:1025-1057` (stern_fs_challenges),
`herradura/herradura.go:820-838` (sternFsChallenges),
`"Herradura cryptographic suite.py":901-906` (hpks_stern_f_sign)

Python's `_stern_hash` chains NL-FSCX v1 over all inputs and then applies the full
`hfscx_256` finalizer (Merkle-Damgård pad + final compression) before expanding
per-round challenges.  C `stern_fs_challenges` and Go `sternFsChallenges` chain
NL-FSCX v1 without the HFSCX-256 finalizer — raw NL-FSCX output is used directly as
the challenge seed.  The two derivations produce different challenge sequences for
identical inputs, making Stern signatures generated in Python unverifiable in C/Go
and vice versa.  Cross-language interoperability is impossible until these are
unified.

**Plan:** Choose one canonical derivation and apply it to all three languages.
Recommended: use `hfscx_256` (the full hash) as the challenge oracle in all
languages — this matches the Python implementation, which is the most
security-conscious of the three, and ensures the Fiat-Shamir hash function is
domain-separated and collision-resistant.  Update `stern_fs_challenges` in C and
`sternFsChallenges` in Go to call `hfscx_256` on the concatenated commitment bytes,
then expand per-round challenges from the 256-bit output.

Status: **DONE** — HFSCX-256 finalizer added to C `stern_fs_challenges`
(`herradura.h`) and Go `sternFsChallenges` (`herradura/herradura.go`) after the
NL-FSCX v1 chaining loop, matching Python's `_stern_hash` exactly. C and Go sign+
verify round-trips confirmed passing.

---

### 49. Go `rnlTwCache` plain map — data race under concurrent use (Concurrency, Medium)

**Files:** `herradura/herradura.go:479`

`rnlTwCache` is declared as `var rnlTwCache = map[int]*rnlTwEntry{}` and accessed
in `rnlTwiddleInit` with no synchronization.  The function uses a `ready` flag on the
entry struct as a guard, but concurrent goroutines can race on the map read/write
itself (map access is not safe for concurrent use in Go).  By contrast, `mInvCache`
on line 235 correctly uses `sync.Map`.  Running the package under Go's race detector
(`go test -race`) will flag this.

**Plan:** Replace `rnlTwCache map[int]*rnlTwEntry` with `sync.Map` and adapt
`rnlTwiddleInit` to use `LoadOrStore` semantics, matching the pattern already used
for `mInvCache`.

Status: **DONE** — `rnlTwCache` changed to `sync.Map`; `rnlTwGet` updated to use
`Load` / `LoadOrStore`, matching the `mInvCache` pattern.

---

### 50. C `rnl_twiddle_init` TOCTOU race (Concurrency, Low)

**Files:** `herradura.h:674-695`

`rnl_twiddle_init` checks `if (rnl_tw.ready) return;` and then sets
`rnl_tw.ready = 1;` after populating the twiddle table, with no atomics or memory
barriers between.  On multi-core systems two threads can both observe `ready == 0`,
both enter initialization, and produce a torn twiddle table.  In practice the C suite
is single-threaded in the demo, but the header is distributed as a library.

**Plan:** Guard initialization with a `pthread_once_t` or a C11 `_Atomic int` flag
with `atomic_compare_exchange_strong`.  Since the header is single-file, prefer
`pthread_once` (portable, POSIX) wrapped in a `#ifdef _POSIX_THREADS` guard with
a fallback `_Atomic` path.

Status: **DONE** — `int ready` removed from `rnl_tw` struct; body moved to
`rnl_twiddle_do_init`; `rnl_twiddle_init` now wraps `pthread_once` on POSIX builds
and a CAS-based `_Atomic int` spin-once on non-POSIX builds.

---

### 51. C `hfscx_256` unchecked `malloc` (Safety, Medium)

**Files:** `herradura.h:597`

`hfscx_256` allocates the padded message buffer with
`padded = (uint8_t *)malloc(padded_len);` and immediately calls `memcpy` into it
without checking whether `malloc` returned NULL.  On allocation failure this is
undefined behavior (null pointer dereference in `memcpy`).  While unlikely in normal
operation, it is a latent crash bug in any context where the hash is called on very
large messages or under memory pressure.

**Plan:** Add a NULL check immediately after the `malloc` call:
```c
if (!padded) { fprintf(stderr, "hfscx_256: out of memory\n"); exit(1); }
```
This is consistent with the project's existing error handling convention (abort on
unrecoverable errors in a demo/library context).

Status: **DONE** — NULL check added at `herradura.h:597`; aborts with `fprintf`+`exit(1)`.

---

### 52. C and Go `stern_syndrome` recomputes H matrix on every call (Performance, Medium)

**Files:** `herradura.h:933-948` (stern_syndrome),
`herradura/herradura.go:742-754` (SternSyndrome)

Every call to `stern_syndrome` (and equivalently Go `SternSyndrome`) reconstructs
all `SDF_N_ROWS` rows of the parity-check matrix `H` from the seed before computing
the syndrome `H·e^T`.  In `hpks_stern_f_sign` this function is called once per
round (32× in the demo, up to 219× in production) plus once in the verifier, so the
matrix is regenerated at minimum 33 times for a single sign+verify cycle.  Python
avoids this with `_stern_build_H` which precomputes the matrix once.

**Plan:** Add `stern_build_H` to `herradura.h` (signature:
`void stern_build_H(const BitArray seed, BitArray H[SDF_N_ROWS])`) and a matching
`SternBuildH` in Go.  Update `hpks_stern_f_sign` / `HpksSternFSign` and
`hpks_stern_f_verify` / `HpksSternFVerify` to build H once and pass it through.

Status: **DONE (v1.8.2)** — Added `stern_build_H` (C) and `SternBuildH` (Go) that precompute
all `SDF_N_ROWS` rows of H once.  Added `stern_syndrome_H` (C) and `sternSyndromeH` (Go)
that compute `H·e^T` from the prebuilt matrix.  `stern_syndrome` (C) and `SternSyndrome`
(Go) are retained as one-off wrappers (keygen, encap) that build H internally.
`hpks_stern_f_sign` and `hpks_stern_f_verify` in both C and Go now call `stern_build_H` /
`SternBuildH` once at entry and use the fast `_H` variant for all per-round syndrome
evaluations, reducing matrix construction from `rounds` calls down to 1.

---

### 53. Go `rnlMulModQ` `int` overflow on 32-bit platforms (Portability, Low)

**Files:** `herradura/herradura.go:506-514`

`rnlMulModQ` computes `x := a * b` where `a` and `b` are both `int`.  For RNLQ =
65537, the maximum product is 65536² = 4,294,836,225 which exceeds `MaxInt32`
(2,147,483,647).  On a 64-bit platform `int` is 64 bits and the Fermat trick is
correct.  On a 32-bit platform (e.g., GOARCH=386 or GOARCH=arm) `int` is 32 bits
and `a * b` silently overflows, producing wrong modular results and breaking all
Ring-LWR arithmetic.

**Plan:** Change the local variables in `rnlMulModQ` from `int` to `int64`:
`x := int64(a) * int64(b)` and adjust the Fermat decomposition accordingly.  Add a
compile-time guard `var _ = [1]struct{}{}[unsafe.Sizeof(0)-8]` (panics if `int` is
not 64-bit) or a `//go:build !386 && !arm` constraint on the file if 32-bit support
is explicitly out of scope.

Status: **DONE** — `x` changed to `int64(a) * int64(b)`; Fermat decomposition and
return cast to `int(r)` updated accordingly. Function signature unchanged; no
build constraint needed since the fix is now correct on all platforms.

---

### 54. C `hpks_stern_f_sign` large VLA / stack allocation (Performance/Safety, Low)

**Files:** `herradura.h:1068-1102`

`hpks_stern_f_sign` declares five arrays of `BitArray` on the stack:
`r[SDF_ROUNDS], y[SDF_ROUNDS], pi[SDF_ROUNDS], sr[SDF_ROUNDS], sy[SDF_ROUNDS]`.
With `SDF_ROUNDS = 32` and `sizeof(BitArray) = KEYBYTES = 32`, this is
5 × 32 × 32 = 5 120 bytes.  Scaled to production `SDF_ROUNDS = 219`, it becomes
5 × 219 × 32 = 35 040 bytes — approximately 34 KB of stack per signing call.
Embedded or RTOS targets typically have stacks of 4–8 KB; this allocation will stack
overflow silently.

**Plan:** Replace the five fixed-size stack arrays with heap allocations
(`malloc(SDF_ROUNDS * sizeof(BitArray))`) with appropriate free-on-return and
NULL checks.  For embedded targets where `malloc` is unavailable, document a
`HPKS_STERN_MAX_ROUNDS` compile-time cap and the corresponding stack budget.

Status: **DONE** — `r`, `y`, `pi`, `sr`, `sy` (BitArray) and `Hr` (uint8_t) moved
to heap via `malloc`; NULL check with `exit(1)` added; `Hr` flattened to
`uint8_t *` with row access via `Hr + i * SDF_SYNBYTES`; all six freed at end of
function.

---

### 55. Comment typo in `ba_rnl_kdf_seed`: "KEYBYTES bytes" should be "KEYBYTES bits" (Documentation, Trivial)

**Files:** `herradura.h:570`

The inline comment on the `ba_rol_k` call reads:
```c
ba_rol_k(dst, k, KEYBYTES); /* ROL by KEYBYTES bytes = n/8 bits */
```
`KEYBYTES` is the number of bytes (32 for 256-bit keys), and the rotation amount is
`KEYBYTES` bytes = n/8 bits — which is correct mathematically — but the comment says
"ROL by KEYBYTES bytes" where it should say "ROL by KEYBYTES*8 bits" or more clearly
"ROL left by n/8 bits (= KEYBYTES byte positions)".  The current wording implies the
rotation is measured in bytes, which could confuse readers about whether it is a
bit-rotation or a byte-rotation.

**Plan:** Change the comment to:
```c
ba_rol_k(dst, k, KEYBYTES); /* ROL left by n/8 bits (KEYBYTES byte positions) */
```

Status: **DONE** — comment corrected at `herradura.h:572`.

---

## KaTeX Math Rendering Fixes

### 57. SecurityProofs-1.md §10.6.2 — `^*` emphasis breakage (Documentation, High)

**File:** `SecurityProofs-1.md`, lines 962–969 (section "10.6.2 HPKS — Classical Forgery Resistance")

**Symptom (screenshot 2026-05-23):** Every math span in §10.6.2 fails to render on GitHub — raw LaTeX-like text leaks into the page (e.g. `R^_\textit{bits}` visible as plain text instead of rendered math).  The section immediately above and below renders correctly.

**Root cause:** CLAUDE.md Rule 4 — "never write `^*` inside a math span."  The two-paragraph block (lines 962–969) contains 8+ bare `*` characters (from `R^*`, `s^*`, `e^*`, `P^*`, `C^{-e^*}`, etc.) in the same paragraph and bullet list.  CommonMark's emphasis parser pairs them across `$...$` boundaries, breaking math-span detection for the entire block.  The `\mathbb{GF}(2^n)^*` on line 971 is fine because its paragraph contains only one `*` with no matching partner.

**Fix:** Replace every `^*` with `^{\ast}` in lines 962–969 only.  `\ast` renders identically to `*` in KaTeX and is invisible to the emphasis parser (the leading `\a` is not an emphasis marker).

**Exact substitutions (14 replacements, 8 unique locations):**

| Line | Original | Replacement |
|---|---|---|
| 962 | `(R^*, s^*)` | `(R^{\ast}, s^{\ast})` |
| 962 | `g^{s^*}` | `g^{s^{\ast}}` |
| 962 | `C^{e^*}` | `C^{e^{\ast}}` |
| 962 | `R^*` (standalone) | `R^{\ast}` |
| 963 | `e^*` | `e^{\ast}` |
| 963 | `R^*_\text{bits}` | `R^{\ast}_\text{bits}` |
| 963 | `P^*` | `P^{\ast}` |
| 965 | `$R^*$` | `$R^{\ast}$` |
| 965 | `s^* = \log_g(R^* \cdot C^{-e^*})` | `s^{\ast} = \log_g(R^{\ast} \cdot C^{-e^{\ast}})` |
| 966 | `$s^*$` | `$s^{\ast}$` |
| 966 | `g^{s^*} \cdot C^{e^*}` | `g^{s^{\ast}} \cdot C^{e^{\ast}}` |
| 966 | `$e^*$` (end of line) | `$e^{\ast}$` |
| 967 | `e^* = \text{fscx-revolve}(R^*_\text{bits}, P^*, i)` | `e^{\ast} = \text{fscx-revolve}(R^{\ast}_\text{bits}, P^{\ast}, i)` |
| 967 | `$R^*$ and $e^*$` | `$R^{\ast}$ and $e^{\ast}$` |

**No other lines need changes.**  Lines outside 962–969 either have no `^*` or have a lone `^*` with no pairing partner in the same paragraph (e.g. line 971 `\mathbb{GF}(2^n)^*`).

**Validation:** After applying the fix, run the KaTeX pipeline validator to confirm zero failures in the affected section:
```bash
NODE_PATH=/tmp/katex-validate/node_modules node \
    SecurityProofsCode/validate_katex.js SecurityProofs-1.md
```

Status: **DONE** — all 14 `^*` occurrences on lines 962–967 replaced with `^{\ast}`.

---

### 58. SecurityProofs-1.md §9.2.4 — `^*` emphasis breakage in two paragraphs (Documentation, High)

**File:** `SecurityProofs-1.md`, lines 730 and 739–744 (section "9.2.4 Security assumption")

**Symptom (screenshot 2026-05-23):** Math spans broken in two paragraphs — raw `$...$` delimiters visible as plain text, portions of prose rendered as italic.

**Root cause:** Same Rule 4 violation as TODO #57.
- Line 730: three `$\mathbb{GF}(2^n)^*$` in one sentence — two `*` pair across math boundaries.
- Lines 739–744: four `^*` across one paragraph (`\mathbb{GF}(2^n)^*` ×3 and `\mathbb{Z}_p^*` ×1) — two pairs, both break math.

**Fix:** Replaced all 7 occurrences of `^*` with `^{\ast}` on those lines only.

Status: **DONE** — 7 replacements across lines 730 and 739–744; no other lines touched.

---

### 59. SecurityProofs-2.md — `^*` emphasis breakage and `\operatorname` (Documentation, High)

**File:** `SecurityProofs-2.md`, lines 458 and 460

**Root cause (two violations):**

- **Line 458 — Rule 10:** `\operatorname{invert}` inside a `$$...$$` display block is blocked by GitHub's KaTeX macro allowlist ("The following macros are not allowed: operatorname"). Fixed to `\text{invert}`.
- **Line 460 — Rule 4:** One long proof sentence contains 5 bare `^*` patterns (`d_i^*` ×4 and `\sigma_i^*` ×1). CommonMark pairs them across `$...$` boundaries, breaking every math span in the sentence. Replaced all 5 with `^{\ast}`.

**Scan result:** No other paragraphs in SecurityProofs-2.md have multiple `^*` occurrences outside table cells; no Rule 6 violations found.

Status: **DONE** — lines 458 and 460 fixed; no other lines touched.

---

### 60. SecurityProofs-2.md §11.8.2 Theorem 13 proof — Rule 11 inline `}_{` opener (Documentation, High)

**File:** `SecurityProofs-2.md`, line 406 (first prose paragraph of Theorem 13 proof)

**Root cause — Rule 11 (new):** `\mathrm{ROL}_{n/4}` created a `}_{` both-flanking `_` opener in an inline paragraph.  `c_{j-1}` (introduced in the previous fix for TODO #59's line 460) acts as a right-flanking closer because the plain letter `c` before `_` satisfies the right-flanking condition even when `_` is followed by `{`.  CommonMark paired the opener and closer across all math spans between them.

**Fix:** Converted `\mathrm{ROL}_{n/4}\bigl((A+B) \bmod 2^n\bigr)` to function notation `\mathrm{ROL}((A+B) \bmod 2^n, n/4)`, eliminating the `}_{` opener.  The remaining `_` characters (`c_{j-1}`, `c_j`, `}_j`) have no valid pairing partner.

**CLAUDE.md:** Added Rule 11 documenting the inline `\command{}_{braced}` + `letter_` pairing mechanism and its fix; added a row to the correct-patterns table.

Status: **DONE** — line 406 fixed; Rule 11 added to CLAUDE.md.

---

### 61. README.md performance tables — standardise to 64/128/256-bit for all three languages (Documentation/Testing, Medium)

**Current state (v1.8.3 tables, commit `a72171c`):**

Several benchmark rows still have `—` in the 64-bit, 128-bit, or 256-bit columns for one or more languages, making cross-language comparisons incomplete:

| Benchmark | C 64 | C 128 | C 256 | Go 64 | Go 128 | Go 256 | Py 64 | Py 128 | Py 256 |
|-----------|------|-------|-------|-------|--------|--------|-------|--------|--------|
| FSCX single step | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HKEX-GF gf\_pow | — | — | — | — | — | — | ✓ | ✓ | ✓ |
| HKEX-GF handshake | — | — | — | — | — | — | ✓ | ✓ | ✓ |
| HSKE round-trip | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HPKE El Gamal | — | — | — | — | — | — | ✓ | ✓ | ✓ |
| NL-FSCX v1 revolve | — | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NL-FSCX v2 enc+dec | — | — | — | ✓ | — | — | ✓ | — | — |
| HSKE-NL-A1 | — | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HSKE-NL-A2 | — | — | — | ✓ | — | — | ✓ | — | — |
| HKEX-RNL handshake | — | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| HPKS-Stern-F | — | — | ✓ | — | — | ✓ | — | — | — |

**Target state:** Every row in every language table has measured values (not `—`) for the 64-bit, 128-bit, and 256-bit columns.  The 32-bit column may remain where the language only tests 32-bit; benchmarks that are genuinely single-size (HPKS-Stern-F fixed at N=256) are exempt.

**Work required per language:**

*C (`CryptosuiteTests/Herradura_tests.c`):*
- Add multi-size loops to all benchmark functions — C already has 64-bit and 128-bit implementations (`gf_mul_64`, `gf_pow_64`, `gf_mul_128`, etc.) and 64/128-bit NL-FSCX primitives.
- Benchmarks needing loops: FSCX (add 64/128), gf\_pow (add 64/128/256), handshake (add 64/128/256), HSKE (add 64/128), HPKE (add 64/128/256), NL-FSCX v1 (add 64/128/256), NL-FSCX v2 (add 64 at minimum), HSKE-NL-A1 (add 64/128/256), HSKE-NL-A2 (add 64), HKEX-RNL (add n=64/128/256).
- C table becomes a multi-column table matching Go/Python.

*Go (`CryptosuiteTests/Herradura_tests.go`):*
- Change `gfSizes = []int{32}` → `[]int{32, 64, 128, 256}` (or add a separate `gfSizes256` slice).
- The Go `GfPow`/`GfMul` functions already handle all sizes via `big.Int` arithmetic — no new implementation needed.
- NL-FSCX v2: extend `benchNlFscxRevolve` loop from `[]int{64}` to `[]int{64, 128, 256}`.
- HSKE-NL-A2: extend `benchHskeNlA2RoundTrip` loop from `[]int{64}` to `[]int{64, 128, 256}`.

*Python (`CryptosuiteTests/Herradura_tests.py`):*
- NL-FSCX v2: extend `bench_nl_fscx_revolve` loop from `[64]` to `SIZES` (i.e., `[64, 128, 256]`).
- HSKE-NL-A2: extend `bench_hske_nl_a2_roundtrip` loop from `[64]` to `SIZES`.
- No other changes needed — Python already covers all other benchmarks at 64/128/256-bit.

**Notes:**
- NL-FSCX v2 and HSKE-NL-A2 at 128/256-bit are O(n²) and will be slow (~seconds per op); run with short `-t` to cap benchmark time.
- The C table currently shows a single "Throughput" column — it should be restructured to 3–4 columns matching Go/Python once multi-size loops are added.
- Keep the existing 32-bit column where present; it is informative for the C NL/GF benchmarks.

**Batches:**
1. Python — extend NL-FSCX v2 and HSKE-NL-A2 loops; run benchmarks; update README Python table.
2. Go — extend gfSizes and NL-FSCX v2 / HSKE-NL-A2 loops; run benchmarks; update README Go table.
3. C — add multi-size benchmark loops; restructure C table; run benchmarks; update README C table.

Status: **DONE** — Python/Go/C benchmarks extended to 64/128/256-bit; README tables restructured to 4-column format (32/64/128/256-bit).

---

### 62. README.md version header stale — v1.8.3 should be v1.8.8 (Documentation, Trivial)

**Files:** `README.md`, lines 1 and 155.

**Current state:**
- Line 1: `# Herradura Cryptographic Suite (v1.8.3)`
- Line 155: `# Performance (v1.8.3, Orange Pi 5 — RK3588, Cortex-A76 @ 2.4 GHz)`

**Required:** Update both occurrences to `v1.8.8` (the current CHANGELOG version).

**Also:** Add callout notes for v1.8.4–v1.8.8 under the existing `> **v1.8.3 note:**` block.
Significant functional/compatibility changes worth noting:
- v1.8.4–v1.8.6: KaTeX rendering fixes in SecurityProofs docs (documentation only; no API change).
- v1.8.7: N=128 `HPKS-Stern-F` implementation in C; all benchmark tables now cover all four sizes (32/64/128/256-bit).
- v1.8.8: `ATOMIC_VAR_INIT` removed from `herradura.h` for C23/GCC 13+ compatibility.

**Fix:**
1. Replace `(v1.8.3)` with `(v1.8.8)` in line 1.
2. Replace `v1.8.3,` with `v1.8.8,` in line 155.
3. Insert callout notes for v1.8.7 and v1.8.8 (the most functionally relevant releases after v1.8.3) above the `> **v1.8.3 note:**` line, following the existing note style.

Status: **DONE** — title updated to v1.8.8, performance section updated to v1.8.8, v1.8.7 and v1.8.8 callout notes added.

---

### 63. Source file version headers stale — all say v1.8.0, should be v1.8.8 (Documentation, Trivial)

**Root cause:** The source file header comments record the last version in which each file was substantially changed.  `herradura.h` and `herradura/herradura.go` were last updated in v1.8.0 (KDF domain constant), and the suite/test files were not touched in v1.8.1–v1.8.8 except for benchmark extensions in v1.8.7 and ATOMIC_VAR_INIT in v1.8.8.  The banner version in each file should track to the current release so that `grep v1.` gives a meaningful history.

**Files and current version strings:**
- `Herradura cryptographic suite.c` line 1: `v1.8.0`
- `Herradura cryptographic suite.go` line 1: `v1.8.0`
- `Herradura cryptographic suite.py` line 2: `v1.8.0`
- `herradura.h` line 1: `v1.8.0` (needs v1.8.8 — `ATOMIC_VAR_INIT` fix)
- `herradura/herradura.go` line 1: `v1.8.0`
- `CryptosuiteTests/Herradura_tests.c` line 8 banner string: `v1.8.0` (also the `printf` on line 4270)
- `CryptosuiteTests/Herradura_tests.go` line 2: `v1.8.0`
- `CryptosuiteTests/Herradura_tests.py` line 2: `v1.8.0`

**Fix per file:**
- `herradura.h`: add `v1.8.8: ATOMIC_VAR_INIT removed (C23/GCC 13+ compatibility).` at top of changelog block; update header version to `v1.8.8`.
- `CryptosuiteTests/Herradura_tests.c`: add `v1.8.7: 32-bit benchmark columns; N=128 HPKS-Stern-F (TODO #61 extension).`; update header version.
- `CryptosuiteTests/Herradura_tests.go` and `.py`: add `v1.8.7: 32-bit benchmark columns extended.` entry.
- Remaining files with no functional changes in v1.8.1–v1.8.8: update header version string only (no new changelog entry needed).

Status: **DONE** — version strings updated to v1.8.8 in all 8 files; herradura.h and test files received new changelog entries.

---

### 64. Stale `SecurityProofs.md` references in source files — should point to split files (Documentation, Low)

**Background:** The monolithic `SecurityProofs.md` was split into `SecurityProofs-1.md` (§1–§10) and `SecurityProofs-2.md` (§11–§11.9) to avoid GitHub's ~750 math-expression rendering limit.  `SecurityProofs.md` now serves only as a redirect index.  All §11.x section references in source-code comments should point directly to `SecurityProofs-2.md`; §11.4.2 references should also be updated.

**Affected locations (9 occurrences):**

| File | Line | Current reference | Corrected reference |
|------|------|-------------------|---------------------|
| `herradura.h` | 922 | `SecurityProofs.md §11.8.4` | `SecurityProofs-2.md §11.8.4` |
| `Herradura cryptographic suite.py` | 32 | `SecurityProofs.md §11.8.4` | `SecurityProofs-2.md §11.8.4` |
| `Herradura cryptographic suite.py` | 245 | `SecurityProofs.md §11.4` | `SecurityProofs-2.md §11.4` |
| `Herradura cryptographic suite.py` | 254 | `SecurityProofs.md §11.8.4` | `SecurityProofs-2.md §11.8.4` |
| `Herradura cryptographic suite.py` | 1079 | `SecurityProofs.md §11` | `SecurityProofs-2.md §11` |
| `Herradura cryptographic suite.py` | 1125 | `SecurityProofs.md §11.8.4` | `SecurityProofs-2.md §11.8.4` |
| `CryptosuiteTests/Herradura_tests.py` | 960 | `SecurityProofs.md §11.4.2` | `SecurityProofs-2.md §11.4.2` |
| `herradura/herradura.go` | 451 | `SecurityProofs.md §11.4` | `SecurityProofs-2.md §11.4` |
| `CryptosuiteTests/Herradura_tests.c` | 2182 | `SecurityProofs.md §11.4.2` | `SecurityProofs-2.md §11.4.2` |

**Fix:** Simple text replacement in each file.  No logic changes.

Status: **DONE** — all 9 occurrences updated; no remaining `SecurityProofs.md` references in source files.

---

### 65. Stale §12 references — quantum analysis is in SecurityProofs-1.md §6 (Documentation, Low)

**Background:** When the SecurityProofs document was restructured, the old §12 "Quantum Attack Analysis" was renumbered to §6 in `SecurityProofs-1.md`.  Several documents still reference the non-existent §12.

**Affected locations:**

| File | Line | Current reference | Corrected reference |
|------|------|-------------------|---------------------|
| `SecurityProofs-1.md` | 3 | `§12 (merged from PQCanalysis.md…)`, `§12.5 NL-protocol rows` | `§6 (merged from PQCanalysis.md…)`, `§6.5 NL-protocol rows` |
| `SecurityProofs.md` | 3 | same as above (identical status block) | same correction |
| `CLAUDE.md` | 23 | `§12 quantum analysis` in repo structure table | `§6 quantum analysis` (in SecurityProofs-1.md) |
| `docs/INTRODUCTION.md` | 654 | `→ SP2 §12 for a detailed quantum algorithm analysis` | `→ SP1 §6 for a detailed quantum algorithm analysis` |

**Fix:**
- `SecurityProofs-1.md` line 3: replace `§12` with `§6` and `§12.5` with `§6.5` in the status paragraph.
- `SecurityProofs.md` line 3: same replacement.
- `CLAUDE.md` line 23: replace `§12 quantum analysis` with `§6 quantum analysis (SecurityProofs-1.md)`.
- `docs/INTRODUCTION.md` line 654: replace `SP2 §12` with `SP1 §6`.

**Note:** Also verify that `SecurityProofs-1.md` §6.5 exists (or that §6 contains the NL-protocol rows that were in §12.5), and adjust if the sub-section numbering differs.

Status: **DONE** — §6 has no sub-sections so `§12.5` was simplified to `§6`; all four files updated; no remaining §12 references in markdown files.

---

### 66. README HPKS-Stern-F parameter note — benchmark rounds vs. suite default rounds unclear (Documentation, Low)

**File:** `README.md`, line 82 and benchmark rows (lines 176, 192, 208).

**Issue:** Line 82 states "Parameters (C/Go/Python): $N = n = 256$, $t = 16$, rounds $= 32$."  This correctly describes the suite default (`SDF_ROUNDS = 32` in `herradura.h`).  However, the C benchmark row (line 176) is labelled `(N=n, rounds=8)` and the Go/Python rows (lines 192, 208) are labelled `(N=n, rounds=4)`, since the test suite uses reduced rounds for throughput measurement.  A reader who notices the mismatch between the `rounds = 32` in the protocol description and `rounds=8`/`rounds=4` in the benchmark labels may be confused.

**Fix:** Add a parenthetical clarification on line 82 after the rounds parameter, e.g.:

> rounds $= 32$ (suite default; benchmarks use reduced rounds for throughput measurement)

Alternatively, add a footnote below the benchmark tables noting that reduced rounds are used for measurement speed.

Status: **DONE** — parenthetical "(production default; benchmarks use 4–8 rounds for throughput measurement)" added after `rounds = 32` in the HPKS-Stern-F protocol description.

---

### 67. SecurityProofs-1.md/SecurityProofs.md status header is 14 months stale (Documentation, Low)

**Files:** `SecurityProofs-1.md` line 4, `SecurityProofs.md` line 4.

**Current state:** `**Last updated:** 2026-04-25 (v1.5.16)`

**Issue:** The status block was last updated in April 2026 at v1.5.16.  The suite is now at v1.8.8 (May 2026) with significant additions: v1.6.0 HFSCX-256 finalizer, v1.6.1 domain separation, v1.7.3 NumPy acceleration, v1.8.0 KDF domain constant, v1.8.1 permutation bias fix, v1.8.2 H-matrix precomputation, v1.8.7 N=128 Stern-F.  None of these are reflected in the status paragraph.

**Fix:** Update the `**Last updated:**` line to `2026-05-25 (v1.8.8)` and append the major milestones since v1.5.16 to the status paragraph.

Status: **DONE** — status paragraph updated with v1.6.0–v1.8.7 milestones; "Last updated" bumped to 2026-05-25 (v1.8.8) in both SecurityProofs-1.md and SecurityProofs.md.

---

### 68. Add HFSCX-256 KDF step to `kex` CLI and standalone hash demo to suite files (Feature, Medium)

**Rationale:** HFSCX-256 is implemented in all three language implementations (C `herradura.h` static function, Go `herradura/herradura.go` exported `Hfscx256`, Python suite-level `hfscx_256`), and the `dgst` subcommand (standalone file digest) and `sign`/`verify --digest hfscx-256` (pre-hash before signing) are already present in all three CLIs.  Two gaps remain:

1. **No KDF step in `kex`.**  The `kex` subcommand stores the raw Diffie-Hellman output (`g^{ab}` for HKEX-GF; the Ring-LWR reconciliation value for HKEX-RNL) directly as the session key without passing it through a KDF.  Raw GF(2^n) DH values have non-uniform bit distribution and retain algebraic structure; a `--kdf hfscx-256` flag would post-hash the raw shared secret through HFSCX-256 (`sk_out = HFSCX-256(raw_sk)`) before writing the SESSION KEY PEM, producing a uniformly random 256-bit key with full domain separation.

2. **No standalone hash demo in the suite programs.**  The C, Go, and Python suite `main()` programs demonstrate all protocol primitives (HKEX-GF, HSKE, HPKS, HPKE, NL variants, Stern-F) but never call `hfscx_256` / `Hfscx256` directly, so the hash primitive is invisible to a reader running the suite.

**Current state:**

- `dgst` subcommand: **already implemented** in all three CLIs (`herradura_cli.c`, `herradura_cli.go`, `herradura.py`) — reads a file and writes the HFSCX-256 hex digest or PEM.
- `sign`/`verify --digest hfscx-256`: **already implemented** in all three CLIs.
- `kex --kdf`: **missing** in all three CLIs (C, Go, Python).
- Suite demo HFSCX-256 block: **missing** in all three suite `main()` programs (`Herradura cryptographic suite.c`, `Herradura cryptographic suite.go`, `Herradura cryptographic suite.py`).

**Library-call status (informational):**

| Language | Function | Location | Accessible |
|---|---|---|---|
| C | `hfscx_256(data, len, iv, out)` | `herradura.h` (static) | yes — any TU that includes the header |
| Go | `Hfscx256(data, iv []byte) []byte` | `herradura/herradura.go` (exported) | yes — any importer of `herradurakex/herradura` |
| Python | `hfscx_256(data, *, iv=None) -> bytes` | `Herradura cryptographic suite.py` | yes — imported by `HerraduraCli/primitives.py` |

No new library functions are needed; the API surface is complete.

**Plan:**

**A. Add `--kdf hfscx-256` flag to `kex` in all three CLIs.**

Affects `HerraduraCli/herradura_cli.c`, `HerraduraCli/herradura_cli.go`, `HerraduraCli/herradura.py`.

For each CLI:
- Add `--kdf` optional parameter (default: `none`; accepted values: `none`, `hfscx-256`).
- After computing the raw shared secret but before encoding the SESSION KEY PEM, if `--kdf hfscx-256` is set, replace `raw_sk` with `HFSCX-256(raw_sk_bytes)` (bare hash, no IV/key).
- Update the help string and the usage comment at the top of each file.
- Both sides of an exchange must use the same `--kdf` flag to derive the same final key.

Example usage (matching OpenSSL `openssl kdf` style):
```
herradura_cli kex --algo hkex-gf --our alice.pem --their bob_pub.pem --kdf hfscx-256 --out sk.pem
```

**B. Add HFSCX-256 standalone demo block to each suite `main()`.**

Affects `Herradura cryptographic suite.c`, `Herradura cryptographic suite.go`, `Herradura cryptographic suite.py`.

Insert a new protocol block (after HPKE-Stern-F, before Eve bypass tests) that:
1. Hashes a fixed test vector (e.g. the ASCII bytes `"HFSCX-256 test vector"`) and prints the hex digest.
2. Hashes the same test vector keyed with the session key `sk` and prints the keyed digest.
3. Verifies that the bare and keyed digests differ (trivially true for non-zero keys).
4. Prints one line confirming the hash length is 32 bytes (256 bits).

Format mirrors existing blocks:
```
--- HFSCX-256 [HASH — Merkle-Damgård over NL-FSCX v1; 256-bit output]
digest (bare)  : <64-char hex>
digest (keyed) : <64-char hex>
+ hash length correct (32 bytes)
+ keyed != bare (key influences output)
```

**Scope note:** Assembly (ARM, i386, AVR) and Arduino implementations are out of scope; those targets do not have a CLI layer and lack heap allocation for the padding buffer.

**Side fixes:** `_encode_rnl_response` in `HerraduraCli/herradura.py` had a pre-existing bug where the hint was packed as `b << i` (overlapping 2-bit values at 1-bit offsets) with `hint_nb = (len(hint)+7)//8`, causing `OverflowError` when any hint coefficient was 2 or 3 at the last position; the encoder and decoder were inconsistent (decoder read only 1 bit per coefficient).  Fixed to use 2 bits per coefficient throughout: `(b & 3) << (2*i)`, `hint_nb = (2*len(hint)+7)//8`, `(hint_int>>(2*i))&3`.  Also fixed `_RNL_KDF_DC_256` missing from `HerraduraCli/primitives.py` (added alongside `_HFSCX256_IV_BYTES`).  All 79 CLI tests pass after both fixes (previously the HKEX-RNL cross-party test was a pre-existing FAIL).

Status: **DONE** — HFSCX-256 demo block added to all three suite `main()` programs; `--kdf hfscx-256` flag added to `kex` in C, Go, and Python CLIs; pre-existing Python hint-encoding bug and missing `_RNL_KDF_DC_256` re-export fixed as side effects; all 79 CLI tests pass.

---

### 69. Update `docs/TUTORIAL.md` for HFSCX-256 API and multi-size Stern-F parameters (Documentation, Medium)

**Motivated by:** v1.8.9 (HFSCX-256 first-class demo in all three suite programs; `--kdf hfscx-256` flag in `kex` CLI) and v1.8.7 (N=128 HPKS-Stern-F in C; multi-size benchmark coverage at 32/64/128/256 bits).

**Background:** `docs/TUTORIAL.md` was written at v1.8.3 and covers all protocols but omits HFSCX-256 entirely.  Since v1.8.9 the hash is now explicitly demonstrated in the suite output, is available as a `--kdf` option in `kex`, and is accessible via the same public API surface as the other primitives (`herradura.h`, `herradura/herradura.go`, `Herradura cryptographic suite.py`).  The parameter reference table also misrepresents Stern-F as having fixed `SDF_T = 16` / `SDF_ROUNDS = 32`, whereas C now supports N=32 (T=2, rounds=4), N=64 (T=4, rounds=8), and N=128 (T=8, rounds=8) in addition to the N=256 default.

**Required changes:**

#### 1. Add `HFSCX-256` sections to each language integration block

Show the bare hash and keyed MAC API immediately after the Stern-F examples.

**C:**
```c
/* Bare hash */
uint8_t digest[32];
uint8_t msg[] = "HFSCX-256 test";
hfscx_256(msg, sizeof msg - 1, NULL, digest);

/* Keyed MAC: iv = key XOR _HFSCX256_IV */
uint8_t mac_iv[KEYBYTES];
for (int i = 0; i < KEYBYTES; i++)
    mac_iv[i] = alice_shared.b[i] ^ _HFSCX256_IV[i];
hfscx_256(msg, sizeof msg - 1, mac_iv, digest);
```

**Go (`herradura` package):**
```go
data := []byte("HFSCX-256 test")

// Bare hash
digest := Hfscx256(data, nil)

// Keyed MAC: iv = key XOR Hfscx256IV
iv := make([]byte, 32)
for i := range iv { iv[i] = aliceShared.Bytes()[i] ^ Hfscx256IV[i] }
mac := Hfscx256(data, iv)
```

**Python:**
```python
import h  # the suite module

data = b"HFSCX-256 test"

# Bare hash
digest = h.hfscx_256(data)

# Keyed MAC
mac_iv = h.BitArray(h.KEYBITS, alice_shared.uint ^ int.from_bytes(h._HFSCX256_IV_BYTES, 'big'))
mac = h.hfscx_256(data, iv=mac_iv)
```

#### 2. Add `--kdf hfscx-256` note to Security Notes

In the NL/PQC protocols subsection, add a bullet:

> **HKEX-GF / HKEX-RNL raw shared secret:** The raw output of `hkex_gf_agree` / `rnl_agree` has non-uniform bit distribution (GF element or LWR reconciliation value). Pass `--kdf hfscx-256` to the `kex` CLI subcommand to post-hash the secret through HFSCX-256, producing a uniformly random 256-bit session key. Both parties must use the same flag.

#### 3. Update the parameter reference table

Add HFSCX-256 constants:

| Parameter | C | Go | Python | Value |
|---|---|---|---|---|
| HFSCX-256 IV | `_HFSCX256_IV[32]` | `Hfscx256IV` | `_HFSCX256_IV_BYTES` | `b'HFSCX-256/HERRADURA-SUITE\x00…'` |

Update the Stern-F rows to reflect that `SDF_T` and `SDF_ROUNDS` scale with N; the table values (T=16, rounds=32) are the N=256 defaults. Add a note:

> Stern-F parameters scale with N: T = N/16, rows = N/4. C supports N=32 (T=2, rounds=4), N=64 (T=4, rounds=8), N=128 (T=8, rounds=8), and N=256 (T=16, rounds=32). Go and Python support all four sizes. Assembly/Arduino: N=32 only.

#### 4. Add HSKE-NL-A1 (counter-mode) examples to C and Python sections

The C section currently shows no NL encryption examples; Python shows only HSKE-NL-A2.  HSKE-NL-A1 is the recommended non-linear stream cipher and its nonce handling is non-obvious.

**C (add after HPKS example):**
```c
/* HSKE-NL-A1: counter-mode stream cipher with nonce */
BitArray key, nonce, plaintext, ciphertext, recovered;
ba_rand(&key, urnd);
ba_rand(&nonce, urnd);
ba_rand(&plaintext, urnd);

hske_nl_a1_encrypt(&plaintext, &key, &nonce, &ciphertext);   /* session base = key XOR nonce */
hske_nl_a1_decrypt(&ciphertext, &key, &nonce, &recovered);
/* ba_equal(&plaintext, &recovered) == 1 */
```

**Python (add after HSKE-NL-A2 example):**
```python
key   = h.BitArray.random(n)
nonce = h.BitArray.random(n)
pt    = h.BitArray.random(n)
base  = h.BitArray(n, key.uint ^ nonce.uint)
seed  = base.rotated(n // 8)
ct    = h.nl_fscx_revolve_v1(seed, h.BitArray(n, base.uint ^ 0), n // 4)  # counter=0
dec   = h.nl_fscx_revolve_v1(seed, h.BitArray(n, base.uint ^ 0), n // 4)
assert (pt.uint ^ ct.uint) == (ct.uint ^ dec.uint)  # XOR symmetry check
```
(Note: the suite wraps this in `hske_nl_a1_encrypt`; the raw call is shown here for clarity.)

**Files to modify:** `docs/TUTORIAL.md`

Status: **DONE** — HFSCX-256 sections (bare hash + keyed MAC) added to C, Go, and Python integration blocks; HSKE-NL-A1 counter-mode examples added to C, Go, and Python; hash primitive row added to protocol reference; parameter table updated with `_HFSCX256_IV` constants and Stern-F multi-size note; KDF security bullet added to Security Notes.

---

### 70. Update `docs/INTRODUCTION.md` for HFSCX-256 concepts (Documentation, Medium)

**Motivated by:** v1.8.9 (HFSCX-256 is now a first-class primitive with suite demo output and CLI integration). `docs/INTRODUCTION.md` was written at v1.8.3 and makes no mention of HFSCX-256, Merkle-Damgård construction, or the AEAD streaming mode — all of which are part of the deployed suite.

**Background:** A reader who runs any of the three suite programs now sees a `--- HFSCX-256 [HASH]` output block, but INTRODUCTION.md provides no conceptual grounding for what that means. The Part 11 suite table lists 11 protocols but omits HFSCX-256 as a hash primitive. The decision tree has no branch for "need to hash or MAC data". The glossary has no entries for Merkle-Damgård, MAC, or AEAD.

**Required changes:**

#### 1. Add HFSCX-256 conceptual explanation

Insert as a new **Part 4.5** (between "FSCX and HSKE" and "Non-linearity") or as a subsection **§4.5** within Part 4, covering:

- **Why a hash function is needed:** Raw DH shared secrets (e.g. GF elements from HKEX-GF) have algebraic structure — not all 256-bit values appear equally often. A hash "whitens" the output so that downstream protocols see a uniformly random key.
- **Merkle-Damgård construction in plain English:** Split the message into 32-byte blocks. Start from a fixed IV. Feed each block through a compression function with the previous chaining value. Final state is the hash. One toy example: 3 blocks → compress(compress(compress(IV, B0), B1), B2).
- **Why NL-FSCX v1 is used as the compression function:** It is already a one-way function (non-bijective in A); iterating it n/4 times provides enough diffusion. The fixed IV provides domain separation.
- **Keyed MAC variant:** XOR the key into the initial chaining state (replace IV with `key XOR IV`). This ties the output to knowledge of the key.
- **AEAD (HSKE-NL-A1-CTR):** Briefly mention that HFSCX-256 is used as the authentication tag in the streaming CTR-mode AEAD (`encfile` CLI command); the cipher provides confidentiality and the MAC provides integrity.
- **Cross-reference:** → TUT §HFSCX-256 for API usage. → SP2 §11.2 for the NL-FSCX one-wayness argument.

Toy example (2-block message):
```
IV    = HFSCX-256/HERRADURA-SUITE (fixed 32 bytes)
B0    = first 32 bytes of message
B1    = second 32 bytes (padded with 0x80… if needed)
hash  = NL-FSCX-v1-revolve(NL-FSCX-v1-revolve(IV, B0, n/4), B1, n/4)
```

#### 2. Update Part 11.1 protocol reference table

Add a row for HFSCX-256:

| HFSCX-256 | Hash/MAC | NL-FSCX v1 one-wayness | Grover (halves collision resistance) | SP2 §11.2 | §HFSCX-256 |

Adjust the table header to add a "Hash" column in the first column scope.

#### 3. Update Part 11.2 decision tree

Add a branch:
```
Need to hash data or authenticate a message?
└── HFSCX-256 (bare digest) or HFSCX-256-MAC (keyed)
```

Also add under key exchange:
```
Need to derive a uniformly random key from a DH or Ring-LWR output?
└── Post-hash with HFSCX-256 (--kdf hfscx-256 in CLI)
```

#### 4. Update Part 12 glossary

Add four entries:

- **Merkle-Damgård construction.** A way to build a hash function for arbitrary-length messages from a fixed-length compression function. The message is padded to a multiple of the block size, then each block is fed through the compression function together with the previous chaining value. The final chaining value is the hash. Used in MD5, SHA-1, and SHA-256; also the design of HFSCX-256.

- **MAC (Message Authentication Code).** A keyed hash: both the message and a secret key are inputs, and only someone who knows the key can produce or verify the tag. Provides integrity and authenticity (but not non-repudiation). HFSCX-256-MAC uses the key as the initial chaining state.

- **AEAD (Authenticated Encryption with Associated Data).** A mode that combines confidentiality (encryption) with integrity (a MAC over the ciphertext and any associated metadata). An attacker who tampers with the ciphertext causes decryption to fail before any plaintext is produced. HSKE-NL-A1-CTR with HFSCX-256-MAC implements AEAD for the `encfile` CLI command.

- **HFSCX-256.** A 256-bit hash function built on NL-FSCX v1 as a Merkle-Damgård compression function, using the fixed IV `HFSCX-256/HERRADURA-SUITE`. Used as a KDF (post-hash for DH shared secrets), a MAC (keyed by XOR-ing the key into the IV), and an AEAD tag in streaming encryption.

#### 5. Add KDF note to Part 3 (key exchange) and Part 9 (Ring-LWR)

In §3.3 HKEX-GF and §9 HKEX-RNL, add a brief note after each "shared secret" description:

> **Key derivation:** The raw shared secret `g^{ab}` (or the Ring-LWR reconciliation value) retains algebraic structure and should be post-hashed before use as a symmetric key. HFSCX-256 provides this step: `sk = HFSCX-256(raw_secret_bytes)`. In the CLI, pass `--kdf hfscx-256` to `kex` to apply this step automatically.

**Files to modify:** `docs/INTRODUCTION.md`

Status: **DONE** — Part 4.5 (HFSCX-256 conceptual explanation: Merkle-Damgård construction, NL-FSCX v1 as compression function, keyed MAC, AEAD) inserted between Part 4 and Part 5; KDF derivation notes added to §3.3 and §9.4; HFSCX-256 row added to Part 11.1 protocol table; two new decision-tree branches added to Part 11.2; four glossary entries added to Part 12 (Merkle-Damgård, MAC, AEAD, HFSCX-256).

---

### 71. Cryptographic landscape review — new developments or discoveries that may affect suite security (Research, Medium)

**Rationale:** Cryptographic research moves continuously. Algorithmic advances, new
mathematical insights, and implementation attacks published after the suite's security
proofs were written could affect the security margins of one or more protocols.  A
periodic review ensures that the assumptions underpinning each protocol remain current
and that `SecurityProofs-1.md` / `SecurityProofs-2.md` accurately reflect the state
of the art.

**Scope:** Review developments relevant to each hard problem the suite relies on:

| Protocol family | Hard problem | Where to look |
|---|---|---|
| HKEX-GF, HPKS, HPKE (classical) | DLP in GF(2^n)* | Index-calculus / function-field sieve advances; IACR ePrint, IEEE TIT |
| HKEX-RNL | Ring-LWR / RLWE | NIST PQC round 4 / final standards (FIPS 203 ML-KEM); IACR Crypto/Eurocrypt/Asiacrypt proceedings |
| HPKS-Stern-F, HPKE-Stern-F | Syndrome Decoding Problem (SDP) | NIST PQC code-based candidates (BIKE, HQC); Information-Set Decoding (ISD) algorithm progress |
| NL-FSCX v1 PRF / OWF | Algebraic / statistical attacks on NL-FSCX | IACR FSE / ToSC; any new algebraic degree or differential attack tools |
| HFSCX-256 | Collision / preimage resistance | Merkle-Damgård analysis; any new meet-in-the-middle or multi-collision attacks |
| All | Quantum algorithms beyond Shor/Grover | Quantum walks, QAOA advances; NIST IR 8413 update if published |

**Concrete questions to answer for each area:**

1. **GF(2^n) DLP:** Have index-calculus or function-field sieve algorithms been
   improved for characteristic-2 fields since 2015?  (Granger–Kleinjung–Zumbrägel
   2014–2016 broke small-characteristic fields; how does GF(2^256) fare today?)
   Does the deployed irreducible polynomial `x^256 + x^10 + x^5 + x^2 + 1` have
   any known structural weakness?

2. **Ring-LWR:** Has the security of Ring-LWR (as opposed to MLWE/MSIS in FIPS 203)
   been tightened or weakened since the suite's parameter choice (n=256, q=65537,
   p=4096, η=1)?  Have any new algebraic or lattice-reduction attacks appeared that
   change the n=256 security estimate?

3. **Syndrome Decoding:** Has the best known ISD algorithm (Prange, Stern, BJMM,
   MMT, MO) improved for binary linear codes with the Stern-F parameters
   (N=256, t=16)?  Does the current `SDF_PRODUCTION_ROUNDS = 219` remain sufficient
   for 128-bit soundness under any new forgery technique?

4. **NL-FSCX PRF gap (follow-up to TODO #42):** Has any new algebraic technique
   (higher-order differentials, MILP-based diffusion analysis) been published that
   could close or widen the range-compression distinguisher gap identified in §9.3
   of `nl_fscx_prf_analysis.py`?

5. **HFSCX-256:** Are there any new generic Merkle-Damgård attacks (beyond the
   length-extension and multi-collision results already addressed in §11.9) that
   could reduce the collision bound below 2^128?

6. **Quantum:** Has any post-2022 result changed Grover's effective bit-security
   halving for symmetric primitives, or introduced a new quantum speedup for
   lattice/code problems beyond the known sqrt-speedup for ISD?

**Deliverables:**

- A summary table (added here as a Status note) with one row per area:
  `| Area | Key papers / developments | Impact on suite | Action required? |`
- If any finding requires a concrete code or documentation change, create a new
  numbered TODO item for it.
- Update the "Last updated" date in `SecurityProofs-1.md` and `SecurityProofs.md`
  to reflect the review date.

**Suggested sources:**

- IACR ePrint archive (eprint.iacr.org) — search each protocol family.
- NIST PQC project page (csrc.nist.gov/projects/post-quantum-cryptography) —
  final standards FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) and
  any new call for proposals.
- Crypto/Eurocrypt/Asiacrypt/FSE proceedings, 2022–present.
- NIST IR 8413 updates.

Status: **DONE** (2026-06-03)

**Findings summary (2026 landscape review):**

| Area | Key papers / developments | Impact on suite | Action required? |
|---|---|---|---|
| GF(2^n) DLP (HKEX-GF, HPKS, HPKE) | FFS L[1/3] is the practical attack; GKZ quasi-polynomial only applies to highly composite-degree fields. NIST SP 800-57 Rev. 5 (2020) and ENISA (2022) deprecate GF(2^n)* for new designs. | n=256 gives ~80–90 bits classical security (NOT 128 bits as previously stated). Suite §9.2.4 corrected. | Done — §9.2.4 and §10.8.4 updated; HKEX-GF, HPKS, HPKE remain **None** post-quantum. |
| Ring-LWR (HKEX-RNL) | MATZOV Report 2022; Albrecht et al. LWE estimator updates 2023. BKZ-based lattice reduction is the best known attack. No new algebraic attack on q=65537 (x^256+1 doesn't split since 512 ∤ q−1). | n=256, q=65537, p=4096, η=1 → ~105–115 classical Core-SVP bits, ~95–105 quantum. Below ML-KEM-768 128-bit target but above 100-bit floor. | Done — §11.4.3 and §11.6 updated with concrete estimate. |
| Syndrome Decoding (HPKS/HPKE-Stern-F) | BJMM/SDE estimator tool (Becker-Joux-May-Meurer). BIKE-128 uses N≈24,646 for 128-bit classical security. | N=256, t=16 gives only ~56–60 bits classical (NOT 128 bits). N=256 is demo-only; 128-bit needs N ≥ 17,000. | Done — §11.7 table and §11.8.4 updated; new TODO items needed for production parameters. |
| NL-FSCX v1 PRF / OWF | No new algebraic technique published through 2025 that closes or widens the range-compression distinguisher. The HFSCX-256 post-composition fix (TODO #43) addresses the range-compression PRF gap. | No new threat. TODO #43 (HFSCX-256 composition fix) remains the recommended hardening. | No new action needed; TODO #43 status unchanged. |
| HFSCX-256 | No new generic Merkle-Damgård attacks beyond known length-extension / multi-collision. No published cryptanalysis of NL-FSCX v1 compression function. | No new threat; collision bound 2^128 remains valid. | None. |
| Quantum algorithms | NIST SP 800-235 draft (2024) is the current reference. No new speedups beyond Grover / BKZ-hybrid through 2025. No quantum speedup for syndrome decoding beyond √-speedup for ISD. | Grover halving for symmetric primitives unchanged. Shor still breaks all GF(2^n)* DLP. BKZ-quantum hybrid for lattices unchanged at ~core-SVP. | None. |

---

### 72. Davies-Meyer feed-forward for HFSCX-256 (Security/Correctness, Low)

**Rationale:** The deployed compression function $C(s, m) = F_1^{64}(s, m)$ lacks a
Davies-Meyer feed-forward.  The Davies-Meyer variant $C_{\text{DM}}(s, m) = F_1^{64}(s, m)
\oplus s$ provides provable fixed-point hardness and free-start collision hardness that the
current construction lacks (§11.9.8).  The three prerequisites for bundling this change —
TODO #37 (`_rnl_lift` centered rounding), TODO #38 (KDF domain constant), and TODO #39
(2-bit Peikert reconciliation) — are all DONE, removing the last stated blocker.

**Scope:**
- Add XOR feed-forward to the `F_1^{64}` compression step in HFSCX-256 across all six
  language targets (Python, C, Go, ARM, i386, Arduino).
- Update `SecurityProofsCode/hfscx_256_analysis.py` tests that measure fixed-point counts
  and collision rates.
- Bump the construction name to `HFSCX-256-DM` and update §11.9.1 compression-function
  definition in SecurityProofs-2.md.
- This is a **wire-format breaking change**: all existing HFSCX-256 digests, pre-hashed
  signatures, and AEAD tags become incompatible.  Plan for a version bump and migration
  note in CHANGELOG.md.

**Security gain:** Aligns with PGV-1 (one of the 12 provably-secure Davies-Meyer-family
compression functions [Black-Rogaway-Shrimpton 2002]).  Fixed-point hardness: finding
$s$ with $F_1^{64}(s, m) = 0$ requires $\Omega(2^{n/2})$ work (preimage of zero under A2).

**Suggested approach:** Implement and test in a single batch across all targets; bundle
with any other breaking wire-format changes scheduled for v2.0.

Status: **DONE v1.9.0** — Davies-Meyer feed-forward deployed across all six language targets.
KAV vectors updated in C/Go/Python tests.  Construction renamed HFSCX-256-DM.
SecurityProofs-2.md §11.9 updated.  Wire-format breaking change (incompatible with pre-v1.9.0).

---

### 73. Per-slot domain-separation tags for Assembly/Arduino Stern-F (Security, Low)

**Rationale:** The 256-bit language targets (Python, C, Go) carry per-slot DS tags
(ds=1 for $c_0$, ds=2 for $c_1$, ds=3 for $c_2$, ds=4 for the KEM key) through the
`_stern_hash` / `stern_hash` / `SternHash` functions, providing independent random oracles
for each commitment slot as required by Unruh's QROM Fiat-Shamir transform (§11.9.9,
TODO #36 — DONE v1.6.1).

The 32-bit ARM/i386/Arduino toy-demo implementations (`stern_hash1_32`, `stern_hash2_32`)
currently use structural distinctness (different item counts) instead of explicit DS tags.
At n=32 this limits same-slot collision probability to $\leq 2^{-32}$ — negligible for
toy parameters — but it leaves a gap relative to the full QRO argument.

**Scope:**
- Add a `ds` parameter to `stern_hash1_32` and `stern_hash2_32` in the ARM
  (`Herradura cryptographic suite.s`, `CryptosuiteTests/Herradura_tests.s`),
  i386 (`.asm` equivalents), and Arduino (`.ino`) implementations.
- Pass ds=1/2/3/4 at each call site (commit, verify, KEM encap/decap).
- Verify sign+verify and encap+decap still pass for the n=32 demo after the change.

**Note:** This is a hardening item for the toy demo; it does not affect the n=256
production targets.  No wire-format change for the 256-bit targets.

Status: **DONE v1.9.1** — Added `ds` parameter (uint32) to `stern_hash1_32(ds, v)` and
`stern_hash2_32(ds, a, b)` in all five 32-bit targets: ARM suite (`.s`), ARM tests (`.s`),
i386 suite (`.asm`), i386 tests (`.asm`), Arduino (`.ino`).  DS is XOR'd into the first
item before the initial `nl_fscx_revolve_v1` call, matching the 256-bit convention.  Call
sites updated with ds=1 (c0), ds=2 (c1), ds=3 (c2), ds=4 (KEM key/encap/decap).  All
[11] and [12] tests pass on i386 (qemu-i386); ARM cross-compiler not installed on the build
host but the logic is identical to the verified i386 port.

---

### 74. NL-FSCX v1 OWF — independent cryptanalysis required before production deployment (Research, High)

**Rationale:** Both Option A (HPKS-WOTS-F, Theorem 16) and Option B (HPKS/HPKE-Stern-F,
Theorem 17 PRF reduction) ultimately reduce security to the **NL-FSCX v1 one-way function
assumption**: given $y = F_1^{64}(s, m)$ for known $m$, recovering $s$ requires
$\Omega(2^{n/2})$ work.  This assumption is **new** and has not been reduced to a studied
hard problem (§11.8.3, honest limitation).  Corollary 2 rules out Gröbner-basis algebraic
attacks; the degree-saturation argument (Theorem 13) and exhaustive Walsh evidence at small
$n$ support the assumption — but they do not constitute a formal proof or external validation.

**Scope:** This is a research task, not a code task.

1. **Literature survey:** Search IACR ePrint, FSE/ToSC, and Crypto/Eurocrypt proceedings
   for any published cryptanalysis of NL-FSCX v1 or structurally similar carry-injected
   XOR-rotation primitives.
2. **Dedicated cryptanalysis attempt:** Apply known techniques — algebraic degree analysis
   beyond Theorem 13, differential/linear cryptanalysis, meet-in-the-middle on the carry
   channel, SAT/MILP formulations — to $F_1^r$ for $r \in \{2, 4, 8, 16, 64\}$ at $n=32$.
3. **Formal reduction (aspirational):** Attempt to reduce NL-FSCX v1 OWF to a known hard
   problem (e.g., Learning Parity with Noise, approximate short integer solution, or a
   bounded-carry variant of LWE).
4. **Document findings** in SecurityProofs-2.md §11.8.3 and update Theorem 16's honest
   limitation paragraph.

**Risk:** Until external cryptanalysis validates or refutes the OWF assumption,
HPKS-Stern-F / HPKE-Stern-F should be considered research-quality software.  BIKE and HQC
(NIST alternates) rest on the quasi-cyclic syndrome decoding assumption, which has received
far more external scrutiny.

Status: **DONE** v1.9.2 — Items 1–2 and 4 complete.  `SecurityProofsCode/nl_fscx_owf_analysis.py` covers differential, linear, rotational, B=0, and MITM analysis; SecurityProofs-2.md §11.8.3 updated.  Key finding: rotational equivariance at 1–6% (vs. 2^{-n} random expectation) is a structural open concern inherited from the FSCX base.  Item 3 (formal reduction to studied hardness) remains open — recorded as an open gap in §11.8.3.

---

### 75. Formal rotational differential analysis of NL-FSCX v1 (Research, High)

**Context:** TODO #74 (`SecurityProofsCode/nl_fscx_owf_analysis.py` §3) found that
$F_1^r$ has rotational-equivariance rates of approximately $1$–$6\%$ at $n = 32$, $r = 8$,
for all tested rotation amounts $k \in \{1,2,4,7,8,16\}$.  This is many orders of magnitude
above the $2^{-32}$ expectation for a random function.  The source is clear: the FSCX linear
component is exactly rotation-equivariant; the $\mathrm{ROL}((A+B) \bmod 2^n, n/4)$
non-linear term breaks equivariance only when the integer carry pattern changes under rotation
of both inputs.

The critical open question is whether this residual rotational structure enables any
**attack better than brute force** on any of the three OWF/PRF uses of $F_1$:

- HPKS-WOTS-F hash chain: $h(x) = F_1^{n/4}(\mathrm{ROL}(x, n/8), x)$
- HFSCX-256-DM compression: $C_\mathrm{DM}(s, m) = F_1^{64}(s, m) \oplus s$
- HPKS/HPKE-Stern-F PRF matrix row generator: $F_1^{n/4}(\mathrm{ROL}(\mathrm{seed} \oplus i, n/8), \mathrm{seed})$

**Scope:**

1. **Analytical single-round rotational probability.**  Derive $p_\mathrm{rot}(k)$:
   the probability over uniform random $(A, B)$ that
   $F_1(\mathrm{ROL}(A,k), \mathrm{ROL}(B,k)) = \mathrm{ROL}(F_1(A,B), k)$.
   The FSCX term contributes 1 exactly; the deviation comes from the carry difference
   $\mathrm{ROL}((A+B), n/4) \oplus \mathrm{ROL}(\mathrm{ROL}(A,k)+\mathrm{ROL}(B,k), n/4)$.
   Compute $p_\mathrm{rot}(k)$ in closed form or tight bounds for $k \in \{1, 2, n/4\}$.

2. **Multi-round decay.**  Measure whether $p_\mathrm{rot}^{(r)}(k)$ (the $r$-round
   rotational probability) decays as $p_\mathrm{rot}(k)^r$ (independent rounds) or
   exhibits correlation across rounds.  If decay is geometric, compute $r^*$ such that
   $p_\mathrm{rot}^{(r^*)}(k) < 2^{-n/2}$ — below the Grover threshold.

3. **Rotational distinguisher advantage.**  Apply the Khovratovich-Nikolić 2010
   framework to determine whether an adversary with oracle access to $F_1^{n/4}$
   can distinguish it from a random function using rotational pairs with advantage
   $> 2^{-\lambda}$ using fewer than $2^{\lambda}$ queries.

4. **Preimage speedup quantification.**  For the HPKS-WOTS-F hash chain, determine
   whether the rotational correlation allows a preimage oracle to check multiple
   rotation candidates simultaneously, and whether this speedup exceeds the $n$-factor
   constant established in §11.8.3.

5. **Document findings** in a new `SecurityProofsCode/nl_fscx_rot_analysis.py` script
   and extend SecurityProofs-2.md §11.8.3 with a "Rotational structure" subsection
   covering the analytical results from items 1–4.

**Expected outcomes:**
- If $p_\mathrm{rot}(k)$ is analytically derivable: a closed-form expression for the
  single-round rotational probability in terms of $n$ and $k$.
- If the multi-round decay is geometric and $r^* \leq n/4$: the rotational distinguisher
  advantage is negligible at the protocol's round count — the NOTE in §11.8.3 can be
  downgraded to a remark.
- If the decay is slower than geometric or the distinguisher advantage is non-negligible:
  the rotational structure is a genuine security concern requiring a design change (e.g.,
  adding a rotation-breaking step to $F_1$).

Status: **DONE** v1.9.3 — All four scope items complete.  `SecurityProofsCode/nl_fscx_rot_analysis.py` covers single-round probability, one-sided vs two-sided comparison, multi-round power-law decay, extrapolation to n=256, and protocol impact.  Key findings: (1) one-sided rotation (B fixed, all PRF uses) gives p≈0 — PRF security unaffected; (2) two-sided rotation (WOTS hash chain) follows p(r)≈0.42/r power law — polynomial RO-distinguisher (~90 pairs at n=256, q=ln2/p) but does NOT break Theorem 16 (OWF-based proof).  SecurityProofs-2.md §11.8.3 extended with "Rotational structure" analysis.

---

### 76. Explore zero-knowledge proof capabilities with PQC algorithms in the suite (Research, High)

**Rationale:** The suite currently contains one ZKP construction — the Stern-based
identification protocol compiled into a signature via Fiat-Shamir (HPKS-Stern-F) — and one
KEM built on the same syndrome-decoding witness (HPKE-Stern-F/Niederreiter).  These cover
code-based hardness.  The two other PQC pillars in the suite — the Ring-LWR key exchange
(HKEX-RNL) and the NL-FSCX OWF / PRF — have no dedicated ZKP layer.  Before the suite can
support privacy-preserving credentials, anonymous authentication, or threshold protocols, it
needs an inventory of what ZKP techniques are applicable to each hardness assumption and a
concrete construction plan for the most promising ones.

**Scope:**

1. **Survey applicable ZKP frameworks per hardness assumption.**

   | Suite assumption | Candidate ZKP framework | Notes |
   |---|---|---|
   | Syndrome decoding (Stern) | Stern protocol (already implemented), MPC-in-the-head (MPCITH), Ligero/Ligero++ | MPCITH (CRYPTO 2017) reduces proof size significantly over repeated Stern |
   | Ring-LWR / Ring-LWE | Lyubashevsky lattice commitments, BDLOP commitments, Lattice-based $\Sigma$-protocols | BDLOP (2018) supports linear/multiplicative relations over polynomial rings |
   | NL-FSCX OWF / PRF | Hash-based ZK (MPC-in-the-head, ZKBoo, ZKB++), generic NIZK via Fiat-Shamir | Depends on PRF security of NL-FSCX v1; requires OWF assumption from TODO #74 |
   | GF(2^n) DLP (classical HKEX-GF) | Sigma protocols for DLP in GF(2^n), Schnorr-style (HPKS already exists) | Not PQC; included for completeness |

2. **Evaluate proof size, prover/verifier cost, and round complexity** for each candidate
   framework at the suite's standard parameters (n=256, Ring-LWR n=256/q=65537).  Compare
   against NIST PQC signature standards: CRYSTALS-Dilithium (ML-DSA, FIPS 204), SPHINCS+
   (SLH-DSA, FIPS 205), and FALCON (FN-DSA).

3. **Design a Ring-LWR ZKP of knowledge of secret key.**  Given public key $C = \text{round}_p(m \cdot s)$,
   construct a $\Sigma$-protocol proving knowledge of a CBD(1) polynomial $s$ consistent with
   $C$ without revealing $s$.  This is the lattice analogue of the Stern protocol and would
   enable HKEX-RNL-based anonymous credentials.  Starting point: Lyubashevsky 2012
   ($\Sigma$-protocols for lattice problems, Eurocrypt 2012) adapted to the rounding
   operator.

4. **Design a NL-FSCX PRF ZKP of knowledge.**  Given $y = F_1^{n/4}(\text{ROL}(s,n/8), m)$
   for public $m$ and $y$, construct a ZKP proving knowledge of $s$ without revealing it.
   Two candidate approaches:
   - **MPC-in-the-head** (Ishai et al. 2007): treat $F_1^{n/4}$ circuit as an MPC computation;
     secret-share $s$ among virtual parties; prove consistency of revealed shares.
   - **ZKBoo / ZKB++** (Giacomelli et al. 2016 / Chase et al. 2017): decompose $F_1$ round
     function into XOR/AND/ROL gates; build ZK proof from the decomposed circuit.  ROL is
     linear (free in ZKBoo); the non-linear term $\text{ROL}((A+B) \bmod 2^n, n/4)$ introduces
     a bounded number of AND gates per round.

5. **Prototype the most promising construction** as a Python proof-of-concept in
   `SecurityProofsCode/`.  Implement prover and verifier; measure proof size and round
   count at $n=32$ (toy) and $n=256$ (production); verify soundness via 1,000 honest-prover
   trials and 1,000 simulated cheating-prover trials.

6. **Document findings** in a new `SecurityProofsCode/zkp_pqc_exploration.py` script and a
   new `SecurityProofs-2.md` subsection (§11.10 or appended to §11.9) covering:
   - Applicability matrix (which ZKP framework fits which assumption)
   - Parameter comparison table vs. NIST standards
   - Concrete protocol description for the best-performing construction
   - Open gaps and implementation roadmap for extending to C/Go targets

**References:**
- Stern 1994, *A New Identification Scheme Based on Syndrome Decoding*, CRYPTO 1993.
- Lyubashevsky 2012, *Lattice Signatures Without Trapdoors*, Eurocrypt 2012.
- Ishai, Kushilevitz, Ostrovsky, Sahai 2007, *Zero-Knowledge from Secure Multiparty Computation*, STOC 2007 (MPC-in-the-head).
- Giacomelli, Madsen, Orlandi 2016, *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*, USENIX Security 2016.
- Chase et al. 2017, *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives*, CCS 2017 (ZKB++).
- Baum, Damgård, Lyubashevsky, Oechsner, Peikert 2018, *More Efficient Commitments from Structured Lattice Assumptions*, SCN 2018 (BDLOP).
- NIST FIPS 204 (ML-DSA / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+), FIPS 206 (FN-DSA / Falcon).
- SecurityProofs-2.md §11.8 (NL-FSCX OWF analysis), §11.9 (QROM Fiat-Shamir for Stern).

**Files to create / modify:**

| File | Change |
|---|---|
| `SecurityProofsCode/zkp_pqc_exploration.py` | New — ZKP prototype and parameter comparison |
| `SecurityProofs-3.md §11.10` | New — ZKP applicability matrix, Ring-LWR Σ-protocol, NL-FSCX ZKBoo |
| `CHANGELOG.md` | Add versioned entry when scope items are complete |

**Prerequisite:** TODO #74 (NL-FSCX OWF assumption status) should be resolved before
committing to an NL-FSCX-based ZKP construction; if the OWF assumption is refuted, the
Ring-LWR or code-based ZKP path becomes the primary track.

Status: **DONE v1.9.4** — All six scope items complete.
  §1 Survey: applicability matrix across B2 (syndrome decoding), B1 (Ring-LWR), A (NL-FSCX OWF/PRF).
  §2 Ring-LWR Σ-protocol: Lyubashevsky-style, Fiat-Shamir, rejection sampling; completeness 0/1000 failures, soundness 0/200 cheat passes (n=32).  Proof: 132 B (n=32) / 1 056 B (n=256).
  §3 NL-FSCX ZKBoo: 3-party Boolean circuit for F1^1 (n=8, 7 AND gates), ZKBoo prover/verifier, R=4 demo rounds; completeness 0/1000 failures, soundness ≈(1/3)^R coincidental passes.  Proof sizes: 35 KB (n=8) / 920 KB (n=256, R=219).
  §4 Parameter comparison vs ML-DSA / SLH-DSA / Picnic / Stern-F.
  §5 Open construction paths: NTT-accelerated Σ-protocol, ZKB++, hybrid credential scheme.
  §11.10 in SecurityProofs-3.md (split to keep SecurityProofs-2.md under ~750 KaTeX expressions).

---

### 77. Implement ZKP protocols as production library functions, CLI subcommands, and tests (Feature, High)

**Rationale:** TODO #76 (DONE v1.9.4) researched and prototyped two ZKP constructions in
`SecurityProofsCode/zkp_pqc_exploration.py`:

1. **Ring-LWR Σ-protocol** — proves knowledge of an HKEX-RNL private key without
   revealing it.  Proof size: 132 B (n=32) / 1 056 B (n=256).  Smaller than ML-DSA-44
   (2 420 B).  Enables anonymous credentials and HKEX-RNL-based privacy-preserving
   authentication.

2. **NL-FSCX ZKBoo** — 3-party MPC-in-the-head proof of knowledge of an NL-FSCX v1
   preimage.  Proof size: ≈35 KB (n=8, R=219) / ≈920 KB (n=256, R=219).  Enables
   privacy-preserving proofs for any statement whose truth depends on a secret
   NL-FSCX preimage.

Both constructions are prototype-only today.  This TODO promotes them to first-class
library functions integrated into all applicable language targets, adds OpenSSL-style
PEM/DER wire formats to the CLI, adds security tests and benchmarks, and updates
the tutorial and SecurityProofs documents.

---

#### 1. New protocol identifiers

**HPKS-ZKP-RNL** — Ring-LWR Σ-protocol proof-of-knowledge (Lyubashevsky-style,
Fiat-Shamir compiled).

- Statement: public pair (m, C) where m ∈ Z_q^n is the HKEX-RNL blinding polynomial
  and C ∈ Z_p^n is the public key.
- Witness: CBD(1) polynomial s ∈ {−1,0,1}^n with C = round_p(m·s mod q) in
  Z_q[x]/(x^n+1).
- Message binding: challenge c = SHAKE-256(m ‖ C ‖ w ‖ msg) — including msg makes
  the proof a proper signature.
- Parameters: n=256, q=65537, p=4096, γ=8192, t=16 (production);
  n=32, γ=4096, t=4 (assembly / Arduino).
- Reuses the existing HKEX-RNL keypair — no new keygen command required.

**HPKS-ZKP-NL** — NL-FSCX ZKBoo proof-of-knowledge (3-party MPC-in-the-head,
Giacomelli–Madsen–Orlandi 2016).

- Statement: public pair (B, y) where y = NL-FSCX-v1-revolve(ROL(A, n/8), B, n/4)
  evaluated in the suite's n-bit integer arithmetic.
- Witness: secret preimage A.
- New keypair type: A is the private key; (B, y) is the public key.
- Parameters: n=8 (7 AND gates per step, 7×64=448 AND gates for n/4=2 steps;
  proof ≈35 KB at R=219 for 128-bit soundness); n=256 proof (≈920 KB) is tracked
  as a research target — CLI uses n=8 by default.  Full n=256 production requires a
  ZKB++ optimization pass (proof ≈300 KB, see §5 open paths in SecurityProofs-3.md
  §11.10) which is deferred.
- Challenge binding: derived per round from SHAKE-256(all commitments ‖ B ‖ y ‖ msg).

---

#### 2. PEM / DER wire format

New PEM labels following the `HERRADURA <ALGO> <TYPE>` convention already used in
the CLI.  Distinct labels (not `HERRADURA SIGNATURE`) let mixed-algorithm pipelines
identify proof type without parsing the DER body.

| PEM label | DER body (ASN.1 SEQUENCE) | Used by |
|---|---|---|
| `HERRADURA ZKP-NL PRIVATE KEY` | `{ INTEGER n, INTEGER A }` | ZKBoo keygen |
| `HERRADURA ZKP-NL PUBLIC KEY` | `{ INTEGER n, INTEGER B, INTEGER y }` | ZKBoo verify |
| `HERRADURA ZKP-RNL PROOF` | `{ INTEGER n, SEQUENCE w_coeffs, SEQUENCE c_coeffs, SEQUENCE z_coeffs }` | Σ-protocol sign/verify |
| `HERRADURA ZKP-NL PROOF` | `{ INTEGER n, INTEGER rounds, SEQUENCE round_list }` | ZKBoo sign/verify |

where `round_list` contains `rounds` repetitions of
`SEQUENCE { OCTET STRING com_0, OCTET STRING com_1, OCTET STRING com_2, INTEGER e, OCTET STRING view_e1, OCTET STRING view_e2 }`.
Each commitment is a 32-byte SHAKE-256 digest.  Each view encodes the party's PRNG
seed (32 bytes) followed by the per-AND-gate output shares for that party.

Codec helpers to add to `HerraduraCli/codec.py`:
- `encode_zkp_rnl_proof(n, w, c, z)` / `decode_zkp_rnl_proof(path)`
- `encode_zkp_nl_privkey(n, A)` / `decode_zkp_nl_privkey(path)`
- `encode_zkp_nl_pubkey(n, B, y)` / `decode_zkp_nl_pubkey(path)`
- `encode_zkp_nl_proof(n, rounds, round_list)` / `decode_zkp_nl_proof(path)`

`_decode_privkey` / `_decode_pubkey` in `herradura.py` dispatch on the new labels.

---

#### 3. CLI subcommands and arguments

**genpkey** — one new `--algo` choice:

```
genpkey --algo hpks-zkp-nl [--bits N] --out nl_priv.pem [--pubout nl_pub.pem]
```

Generates random A and B of bit-width N (default 8 for ZKBoo demo; must be a
multiple of 8).  Computes y = NL-FSCX-v1-revolve(ROL(A, N/8), B, N/4).  Writes
`HERRADURA ZKP-NL PRIVATE KEY` to `--out`; writes `HERRADURA ZKP-NL PUBLIC KEY`
if `--pubout` is given.  (HPKS-ZKP-RNL reuses `--algo hkex-rnl` — no change.)

**sign** — two new `--algo` choices:

```
sign --algo rnl-sigma  --key alice.pem --in msg.bin --out proof.pem
sign --algo nl-zkboo   --key nl_priv.pem --in msg.bin --out proof.pem
```

`rnl-sigma` loads an `HKEX-RNL PRIVATE KEY` PEM.  Calls `rnl_sigma_sign` with
rejection sampling; writes `HERRADURA ZKP-RNL PROOF`.

`nl-zkboo` loads a `ZKP-NL PRIVATE KEY` PEM.  Calls `zkp_nl_prove` for R=219 rounds
(configurable via `--rounds`); writes `HERRADURA ZKP-NL PROOF`.

**verify** — two new `--algo` choices (mirror of sign):

```
verify --algo rnl-sigma  --pubkey alice_pub.pem --in msg.bin --sig proof.pem
verify --algo nl-zkboo   --pubkey nl_pub.pem --in msg.bin --sig proof.pem
```

Loads the matching public key PEM and proof PEM; calls `rnl_sigma_verify` or
`zkp_nl_verify`; exits 0 on success, 1 on failure (same convention as `hpks`).

Full CLI example sequence (same style as the usage comment block at the top of
`herradura.py`):

```
# ── Ring-LWR ZKP (reuses HKEX-RNL keypair) ──────────────────────────────────
python3 herradura.py genpkey --algo hkex-rnl --bits 256 --out alice.pem
python3 herradura.py pkey    --in alice.pem --pubout alice_pub.pem
python3 herradura.py sign    --algo rnl-sigma --key alice.pem \
                             --in msg.bin --out proof.pem
python3 herradura.py verify  --algo rnl-sigma --pubkey alice_pub.pem \
                             --in msg.bin --sig proof.pem

# ── NL-FSCX ZKBoo ────────────────────────────────────────────────────────────
python3 herradura.py genpkey --algo hpks-zkp-nl --bits 8 \
                             --out nl_priv.pem --pubout nl_pub.pem
python3 herradura.py sign    --algo nl-zkboo --key nl_priv.pem \
                             --in msg.bin --out zkp_nl_proof.pem
python3 herradura.py verify  --algo nl-zkboo --pubkey nl_pub.pem \
                             --in msg.bin --sig zkp_nl_proof.pem
```

The same subcommand names and flag names are used in the C (`herradura_cli`) and
Go (`herradura_cli_go`) CLIs.

---

#### 4. Library API (all applicable language targets)

Add the following functions following the naming conventions established by
`hpks_stern_f_sign` / `hpks_stern_f_verify` in `herradura.h` (C), the Go suite,
and the Python suite.  Prototypes given in Python notation for brevity.

**Ring-LWR Σ-protocol (C, Go, Python; ARM n=32; i386 n=32; Arduino n=32):**

```python
def rnl_sigma_sign(s_poly, m_poly, C_poly, n, msg_bytes):
    """
    Lyubashevsky-style Fiat-Shamir signature.
    Returns (w_poly, c_poly, z_poly) after rejection sampling.
    Parameters: n, q=65537, p=4096, γ={4096 if n==32 else 8192}, t={4 if n==32 else 16}.
    """

def rnl_sigma_verify(m_poly, C_poly, n, msg_bytes, w_poly, c_poly, z_poly):
    """
    Returns True iff:
      (1) ||z||_∞ ≤ γ − t
      (2) c == SHAKE-256(m ‖ C ‖ w ‖ msg)
      (3) ||m·z − w − c·lift(C)||_∞ ≤ t·⌈q/(2p)⌉
    """
```

**NL-FSCX ZKBoo (C, Go, Python; Arduino n=8/R=4 demo only):**

```python
def zkp_nl_keygen(n):
    """Returns (A, B, y) where y = nl_fscx_revolve_v1(rol(A, n//8), B, n//4)."""

def zkp_nl_prove(A, B, y, n, rounds, msg_bytes):
    """
    ZKBoo prover.  Returns a list of `rounds` dicts, each with keys:
      com_0, com_1, com_2   — 32-byte SHAKE-256 commitments
      e                     — revealed party index ∈ {0, 1, 2}
      view_e1, view_e2      — bytes encoding seed + AND-gate output shares
    Challenge e per round derived by Fiat-Shamir over all commitments + msg.
    """

def zkp_nl_verify(B, y, n, rounds, msg_bytes, proof_rounds):
    """
    ZKBoo verifier.  Returns True iff all rounds verify.
    For each round: re-derives AND-gate outputs from two revealed views;
    reconstructs hidden output; checks commitments and final output == y.
    """
```

**C API notes:**
- Proof data returned as a caller-allocated struct array; size constants defined in
  `herradura.h` for compile-time buffer sizing.
- `rnl_sigma_sign` writes into output buffers `w[n]`, `c[n]`, `z[n]` (int32_t arrays).
- `zkp_nl_prove` writes into a caller-allocated `ZkpNlRound rounds[R]` array;
  `ZkpNlRound` is a struct with `com_0[32]`, `com_1[32]`, `com_2[32]`, `e` (uint8_t),
  and `view_e1[VIEW_BYTES]`, `view_e2[VIEW_BYTES]` (where `VIEW_BYTES` = 32 + AND gate
  share bytes for the given n).

**Go API notes:**
- Return `([]int32, []int32, []int32, error)` for `rnlSigmaSign`.
- Return `([]ZkpNlRound, error)` for `zkpNlProve`; `ZkpNlRound` is a struct.

**Assembly (ARM Thumb-2 and NASM i386):**
Implement `rnl_sigma_sign_32` and `rnl_sigma_verify_32` for n=32.  These are
self-contained subroutines reusing the existing `rnl_poly_mul` / `rnl_hint` /
`rnl_reconcile_bits` register conventions.  ZKBoo is not implemented in assembly
(circuit evaluation requires dynamic dispatch over AND gates with 32-byte hash
calls; impractical in 32-bit bare-metal assembly without a SHA library).

**Arduino:**
Add `rnl_sigma_sign_32` / `rnl_sigma_verify_32` at n=32, mirroring the C suite
(`uint32_t` throughout, no dynamic allocation).  Add a minimal ZKBoo demo at n=8
R=4 for the demo loop (not full soundness — just illustrates the concept).

---

#### 5. Tests and benchmarks

Append after the existing Stern-F tests in each test file.  Exact test numbers
are assigned when the implementation lands; the descriptions below define the
required test coverage.

**Security tests:**

| Test | Description | Protocol | Trials | Pass criterion |
|---|---|---|---|---|
| ZKP-RNL completeness | Honest prover at n=32 (and n=256 in Python/C/Go) | HPKS-ZKP-RNL | 100 | 0 failures |
| ZKP-RNL soundness | Random z, no s, n=32 | HPKS-ZKP-RNL | 100 | 0 verifier accepts |
| ZKP-RNL cross-lang | Proof produced by Python verifies under C and Go verifier | HPKS-ZKP-RNL | 10 | All accept |
| ZKP-NL completeness | Honest prover at n=8, R=4 | HPKS-ZKP-NL | 100 | 0 failures |
| ZKP-NL soundness | Random views, no A, n=8, R=4 | HPKS-ZKP-NL | 100 | 0 verifier accepts |

**Benchmarks (Python/C/Go only — assembly at n=32 only for ZKP-RNL):**

| Benchmark | Protocol | Sizes |
|---|---|---|
| ZKP-RNL proof generation throughput | HPKS-ZKP-RNL | n=32, n=256 |
| ZKP-RNL verification throughput | HPKS-ZKP-RNL | n=32, n=256 |
| ZKP-NL prove (toy) throughput | HPKS-ZKP-NL | n=8, R=4 |
| ZKP-NL verify (toy) throughput | HPKS-ZKP-NL | n=8, R=4 |

Benchmarks use the existing `-r` / `-t` timing infrastructure.

---

#### 6. CLI integration tests (CliTest/)

| Script | What it tests |
|---|---|
| `CliTest/test_zkp_rnl.sh` | Python CLI: `genpkey` (hkex-rnl) → `sign` (rnl-sigma) → `verify` round-trip; tampered message must fail |
| `CliTest/test_zkp_nl.sh` | Python CLI: `genpkey` (hpks-zkp-nl) → `sign` (nl-zkboo) → `verify` round-trip; wrong pubkey must fail |
| `CliTest/test_c_zkp_rnl.sh` | C CLI (herradura_cli): same ZKP-RNL round-trip |
| `CliTest/test_go_zkp_rnl.sh` | Go CLI (herradura_cli_go): same ZKP-RNL round-trip |
| `CliTest/test_zkp_interop.sh` | Cross-language: Python `sign --algo rnl-sigma` → C `verify --algo rnl-sigma`; C sign → Go verify; Go sign → Python verify |

Each test script prints `[PASS]` / `[FAIL]` per check, mirroring `test_c_interop.sh`.

---

#### 7. Documentation

**`docs/TUTORIAL.md`** — new top-level section "ZKP Protocols":

- When to use ZKP vs. conventional signatures: ZKPs prove knowledge without
  message binding; with Fiat-Shamir they become signatures.  Use ZKP-RNL for
  anonymous credentials where the verifier should not learn the signing key's
  relationship to other keys; use ZKP-NL when the secret is an NL-FSCX preimage.
- HPKS-ZKP-RNL API walk-through (keygen → sign → verify, Python and C snippets).
- HPKS-ZKP-NL API walk-through (keygen → prove → verify, Python snippet).
- CLI usage examples matching §3 above.
- Proof-size and performance comparison table (ZKP-RNL vs. ZKP-NL vs.
  HPKS-Stern-F vs. HPKS, populated from benchmark results).
- Cross-reference: "See SecurityProofs-3.md §11.10 for completeness, soundness,
  and zero-knowledge proofs."

**`SecurityProofs-3.md §11.10`** — add implementation subsection after the
existing §11.10.3 empirical results:

- Note that `rnl_sigma_sign` / `rnl_sigma_verify` and `zkp_nl_prove` /
  `zkp_nl_verify` are now in the suite (not prototype-only).
- Table of function names per language target.
- Comparison of ZKP-RNL proof size (1 056 B, n=256) vs. HPKS-Stern-F signature
  and ML-DSA-44 from the §4 table already in the document.
- Note that ZKP-NL at n=256 (920 KB) awaits ZKB++ optimization (open path §5);
  CLI defaults to n=8 (35 KB) for now.

---

#### 8. Implementation batches

| Batch | Scope | Notes |
|---|---|---|
| Batch 1 ✅ | Python suite (`rnl_sigma_*`, `zkp_nl_*`) + `codec.py` + `herradura.py` CLI | **DONE v1.9.5** — reference implementation; PEM/DER format validated |
| Batch 2 ✅ | C (`herradura.h`) + C CLI (`herradura_cli.c`) | **DONE v1.9.6** — ZKP-RNL + ZKP-NL in header-only library; CLI `genpkey`/`pkey`/`sign`/`verify`; Python↔C PEM interop verified |
| Batch 3 ✅ | Go suite + Go CLI (`herradura_cli.go`) | **DONE v1.9.7** — ZKP-RNL + ZKP-NL in `herradura/herradura.go`; CLI `genpkey`/`pkey`/`sign`/`verify`; demo blocks in suite |
| Batch 4 ✅ | ARM Thumb-2 (`rnl_sigma_sign_32` / `rnl_sigma_verify_32` only) | **DONE v1.9.8** — sign/verify + demo block in main(); reuses rnl_poly_mul NTT + hfscx_32 |
| Batch 5 ✅ | NASM i386 (`rnl_sigma_sign_32` / `rnl_sigma_verify_32` only) | **DONE v1.9.9** — sign/verify + demo block in `_start`; local stack frames for multi-call loops; saves/restores EBP around `rnl_lift`; reuses `rnl_poly_mul` NTT + `hfscx_32` + `rnl_lift` |
| Batch 6 ✅ | Arduino (ZKP-RNL n=32 + ZKBoo n=8/R=4 demo) | **DONE v1.9.10** — `rnl_sigma_sign`/`rnl_sigma_verify` (n=32, γ=4096, t=4) + `zkp_nl_prove_8`/`zkp_nl_verify_8` ZKBoo (n=8, R=4); `static long` arrays only; no heap; targets Arduino Mega |
| Batch 7 ✅ | `CryptosuiteTests/` — security tests and benchmarks for all targets | **DONE v1.9.11** — [21][22] C / [20][21] Go+Py ZKP-RNL+ZKP-NL; benches [33][34] C / [32][33] Go+Py |
| Batch 8 ✅ | `CliTest/` scripts (see §6) | **DONE v1.9.12** — 5 new scripts: test_zkp_rnl.sh, test_zkp_nl.sh, test_c_zkp_rnl.sh, test_go_zkp_rnl.sh, test_zkp_interop.sh; Python CLI "Proof OK"→"Signature OK" fix |
| Batch 9 ✅ | `docs/TUTORIAL.md` + `SecurityProofs-3.md §11.10` update (see §7) | **DONE v1.9.13** — `## ZKP Protocols` top-level section in TUTORIAL (C/Go/Py snippets, CLI usage, comparison table); §11.10.4 Suite Implementation + §11.10.5/§11.10.6 renumber in SecurityProofs-3 |

---

#### Files to create / modify

| File | Change |
|---|---|
| `Herradura cryptographic suite.py` | Add `rnl_sigma_sign`, `rnl_sigma_verify`, `zkp_nl_keygen`, `zkp_nl_prove`, `zkp_nl_verify` |
| `herradura.h` | Add same functions with C API; add `ZkpNlRound` struct and buffer size macros |
| `Herradura cryptographic suite.go` | Add same functions with Go API |
| `Herradura cryptographic suite.s` | Add `rnl_sigma_sign_32`, `rnl_sigma_verify_32` (ARM Thumb-2) |
| `Herradura cryptographic suite.asm` | Add same (NASM i386) |
| `Herradura cryptographic suite.ino` | Add ZKP-RNL n=32 + ZKBoo n=8/R=4 demo |
| `CryptosuiteTests/Herradura_tests.c` | New ZKP test cases and benchmarks |
| `CryptosuiteTests/Herradura_tests.go` | Same |
| `CryptosuiteTests/Herradura_tests.py` | Same |
| `CryptosuiteTests/Herradura_tests.s` | ZKP-RNL tests at n=32 |
| `CryptosuiteTests/Herradura_tests.asm` | Same |
| `CryptosuiteTests/Herradura_tests.ino` | Same |
| `HerraduraCli/codec.py` | New DER encode/decode helpers for ZKP-RNL and ZKP-NL proof PEMs |
| `HerraduraCli/herradura.py` | New PEM labels; extend `genpkey`, `sign`, `verify`; new `_encode_zkp_*` / `_decode_zkp_*` helpers |
| `HerraduraCli/herradura_cli.c` | New subcommand handlers for `hpks-zkp-nl` keygen, `rnl-sigma` and `nl-zkboo` sign/verify |
| `HerraduraCli/herradura_cli.go` | Same |
| `CliTest/test_zkp_rnl.sh` | New |
| `CliTest/test_zkp_nl.sh` | New |
| `CliTest/test_c_zkp_rnl.sh` | New |
| `CliTest/test_go_zkp_rnl.sh` | New |
| `CliTest/test_zkp_interop.sh` | New |
| `docs/TUTORIAL.md` | New "ZKP Protocols" section |
| `SecurityProofs-3.md §11.10` | New implementation subsection (function names, proof-size table) |
| `CHANGELOG.md` | Versioned entry per batch |

**Prerequisites:**

- TODO #76 DONE v1.9.4 — research prototype in `SecurityProofsCode/zkp_pqc_exploration.py`
  is the reference implementation for all library functions.
- TODO #74 (NL-FSCX OWF status) — ZKP-NL soundness is contingent on the NL-FSCX OWF
  assumption.  If TODO #74 reveals a structural weakness, the ZKP-NL soundness claim
  must be downgraded and documented accordingly; ZKP-RNL is independent and unaffected.

**References:**

- Lyubashevsky 2012, *Lattice Signatures Without Trapdoors*, Eurocrypt 2012.
- Giacomelli, Madsen, Orlandi 2016, *ZKBoo: Faster Zero-Knowledge for Boolean Circuits*,
  USENIX Security 2016.
- Chase et al. 2017, *Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key
  Primitives*, CCS 2017 (ZKB++ — future optimization path for ZKP-NL at n=256).
- SecurityProofs-3.md §11.10 (completeness, soundness, zero-knowledge proofs,
  and proof-size analysis for both constructions).
- `SecurityProofsCode/zkp_pqc_exploration.py` §2–§3 (reference prover/verifier code).

Status: **DONE v1.9.13** — **Batch 1 DONE v1.9.5 · Batch 2 DONE v1.9.6 · Batch 3 DONE v1.9.7 · Batch 4 DONE v1.9.8 · Batch 5 DONE v1.9.9 · Batch 6 DONE v1.9.10 · Batch 7 DONE v1.9.11 · Batch 8 DONE v1.9.12 · Batch 9 DONE v1.9.13** — Batch 1: Python suite + codec + CLI.  Batch 2: C header-only library (`herradura.h`) adds ZKP-RNL + ZKP-NL functions + C CLI extensions.  Batch 3: Go package (`herradura/herradura.go`) adds `ZkpRnlParams`, `RnlSigmaSign`, `RnlSigmaVerify`, `ZkpNlKeygen`, `ZkpNlProve`, `ZkpNlVerify`, `ZkpNlRound`; codec.go adds 4 PEM label constants; `herradura_cli.go` extends `genpkey` (`hpks-zkp-nl`), `pkey` (ZKP-NL pubout/text), `sign` (`rnl-sigma`, `nl-zkboo`), `verify` (`rnl-sigma`, `nl-zkboo`); suite `main()` extended with ZKP-RNL and ZKP-NL demo blocks.  Batch 4: ARM Thumb-2 `rnl_sigma_sign_32`/`rnl_sigma_verify_32` + demo in `main()`.  Batch 5: NASM i386 `rnl_sigma_sign_32`/`rnl_sigma_verify_32` + demo in `_start`; local stack frames; EBP save/restore around `rnl_lift`.  Batch 6: Arduino `rnl_sigma_sign`/`rnl_sigma_verify` (n=32) + `zkp_nl_prove_8`/`zkp_nl_verify_8` ZKBoo (n=8, R=4); all-static allocation for Arduino Mega.  Batch 7: `CryptosuiteTests/` — ZKP-RNL+ZKP-NL security tests + benchmarks in C/Go/Python using production library.  Batch 8: 5 CliTest scripts (ZKP-RNL + ZKP-NL Python/C/Go + full 6-direction interop); Python CLI "Proof OK"→"Signature OK" consistency fix.  Batch 9 DONE v1.9.13: `docs/TUTORIAL.md` `## ZKP Protocols` section (C/Go/Py snippets, CLI usage, comparison table); `SecurityProofs-3.md` §11.10.4 Suite Implementation + §11.10.5/§11.10.6 renumber; applicability matrix and comparison table updated to "Implemented".

---

### 78. New application directions from primitive characteristics — research catalogue (Research, Medium)

**Rationale:** A systematic analysis of HerraduraKEx primitive properties identified ten
candidate applications that are either unique to this suite's algebraic structure or
particularly well-served by its existing building blocks.  This item records the findings
so they can be tracked, refined, and promoted to implementation TODOs individually.

Each candidate is labelled with its implementation distance (Low / Medium / High) and the
specific primitive property it exploits.  Candidates are ordered from most to least
immediately actionable.

---

#### 78.A — Format-Preserving Encryption (Low)

**Primitive:** `nl_fscx_revolve_v2` bijectivity — bijective in plaintext A for every fixed
tweak B, with closed-form inverse via `nl_fscx_revolve_v2_inv`.

**Construction:**
```python
def fpe_encrypt(plaintext: BitArray, key: bytes, context: bytes) -> BitArray:
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(key + context), 'big'))
    return nl_fscx_revolve_v2(plaintext, B, I_VALUE)

def fpe_decrypt(ciphertext: BitArray, key: bytes, context: bytes) -> BitArray:
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(key + context), 'big'))
    return nl_fscx_revolve_v2_inv(ciphertext, B, I_VALUE)
```

**Why native:** `delta(B) = ROL(B * floor((B+1)/2) mod 2^n, n/4)` is precomputed once per
context, making the tweak overhead one multiply and one rotation per block.  Standard
AES-FFX requires specialised modular arithmetic for arbitrary-alphabet FPE; `nl_fscx_v2`
is natively a bijection on `{0,1}^n` with no adaptation.

**Use cases:** Encrypting fixed-width database fields (SSNs, credit card numbers, tokens)
without changing field width; searchable deterministic encryption of indexed columns.

**Caveat:** Same (key, context, plaintext) always produces the same ciphertext — suitable
for deterministic/searchable encryption, not for IND-CPA without a per-record nonce in the
context.  This is the same determinism constraint already documented for HSKE-NL-A2 (TODO #12).

---

#### 78.B — Tweakable Wide-Block Cipher for Disk / File Encryption (Low)

**Primitive:** `nl_fscx_revolve_v2` with `delta(B)` precomputed once per block sector.

**Construction (analogous to AES-XTS):**
```python
def sector_encrypt(blocks: list[BitArray], key: bytes, sector: int) -> list[BitArray]:
    return [
        nl_fscx_revolve_v2(
            block,
            BitArray(KEYBITS, int.from_bytes(hfscx_256(key + sector.to_bytes(8,'big')
                                                       + i.to_bytes(4,'big')), 'big')),
            I_VALUE
        )
        for i, block in enumerate(blocks)
    ]
```

**Why native:** The `delta(B)` term in `nl_fscx_v2` depends only on B and is precomputed
once per (sector, block-index) pair.  Standard XTS requires a GF(2^128) multiply per
sector; here the tweak cost is one HFSCX-256 call plus one integer multiply and one
rotation — both already O(n) operations in the suite.

**Key advantage over HSKE-NL-A2:** Each block gets a unique B derived from a public
(sector, index) pair, so distinct blocks always have distinct tweaks even under a fixed
key, defeating the deterministic-encryption limitation.

---

#### 78.C — Forward-Secret Unidirectional Ratchet (Medium)

**Primitive:** `nl_fscx_revolve_v1` one-wayness (OWF conjecture — Theorem 16,
SecurityProofs-2 §11.8.3).

**Construction:**
```python
RATCHET_DOMAIN = BitArray(KEYBITS, int.from_bytes(b'NL-FSCX-RATCHET-V1\x00' * 2, 'big'))

def ratchet_advance(state: BitArray) -> tuple[BitArray, bytes]:
    """Returns (new_state, message_key). Erase state after calling."""
    msg_key = hfscx_256(state.bytes + b'\x01')
    new_state = nl_fscx_revolve_v1(state, RATCHET_DOMAIN, 1)
    return new_state, msg_key
```

**Why native:** The same OWF assumption that underlies HPKS-WOTS-F (Theorem 16) and
HSKE-NL-A1 (§11.3.1) makes `nl_fscx_revolve_v1` one-directional.  Erasing `state_i`
makes `msg_key_i` irrecoverable from `state_{i+1}`, giving forward secrecy without a
DH exchange per message.  All building blocks (`nl_fscx_revolve_v1`, `hfscx_256`) are
already in the suite.

**Open question:** The non-bijectivity of `nl_fscx_v1` means two distinct states could
converge (collide) after enough steps, re-entering a previously-seen state.  Bounding
the collision probability over the ratchet lifetime is a prerequisite before deployment.
A `SecurityProofsCode/nl_fscx_v1_ratchet_collision.py` analysis script (analogous to
`hkex_rnl_failure_rate.py`) would characterise the expected collision distance.

---

#### 78.D — PQC Password-Authenticated Key Exchange / PAKE (High)

**Primitives:** HKEX-RNL (quantum-resistant key exchange) + ZKBoo (`zkp_nl_prove` /
`zkp_nl_verify`) + HFSCX-256 (password hash).

**Sketch:**
```
Registration:
    client: H_pw = hfscx_256(password + salt)
    client -> server: (salt, H_pw, client HKEX-RNL public key)

Login:
    1. client <-> server: HKEX-RNL handshake -> shared_key
    2. client: proof = zkp_nl_prove(password_bits, salt, H_pw, msg=shared_key)
    3. client -> server: proof
    4. server: zkp_nl_verify(salt, H_pw, msg=shared_key, proof)
    5. Both derive session key from shared_key (authenticated by step 4)
```

**Why native:** All existing PQC PAKEs (KHAPE, OPAQUE-Kyber) import external components.
This construction uses only primitives already in HerraduraKEx.

**Demo script:** `SecurityProofsCode/hkex_pake_demo.py` (added v1.9.20) — 3-message PAKE
implemented and demonstrated:
- Registration: `pw_key = hfscx_256(password‖salt)`, `zkp_A = hfscx_256(pw_key‖"ZKP-A")[0:32b]`,
  `y = nl_fscx_v1(zkp_A, B)`.  Server stores `(salt, B, y)`.
- Login: HKEX-RNL channel + ZKBoo proves `nl_fscx_v1(zkp_A, B) = y` bound to session K_raw.
- Wrong password: fast local abort (7 ms) before ZKBoo.
- Session keys match on both sides.

**Open gaps (from script §4):**
- A. OFFLINE DICTIONARY ATTACK: construction is PAKE (not aPAKE) — attacker with `(salt, B, y)`
  can brute-force passwords.  Fix requires OPRF (TODO #78.G).
- B. No formal security reduction to standard PAKE model (SIM-BMP, UC-PAKE).
- C. Demo uses `ZKP_N=32` for Python speed; full 256-bit authentication requires C or NumPy ZKBoo.
- D. Demo rounds `R=16`; production requires `R=219`.

---

#### 78.E — Non-Abelian Key Exchange — Option C Continuation (High / Research)

**Primitive:** `nl_fscx_revolve_v2` permutation family `{pi_K}` — non-abelian by
Theorem 15 (SecurityProofs-2 §11.8.5).  Key recovery from a single evaluation pair is
MQ-hard (Theorem 14); no polynomial quantum algorithm is known for generic non-abelian
Conjugacy Search Problem (Ettinger-Hoyer-Knill 2004).

**Three obstacles from §11.8.5 remain open:**
1. No transfer theorem from black-box CSP hardness to the NL-FSCX v2 circuit model.
2. No verified lower bound on orbit length of `pi_K` — small-subgroup attacks not excluded.
3. No formal reduction to studied CSP (braid group results do not directly transfer).

**Analysis script:** `SecurityProofsCode/nl_fscx_v2_orbit.py` (added v1.9.19)
characterises orbit-length distribution of `pi_K` for random K via Brent's cycle
detection.  Key finding: orbit lengths are NON-MONOTONE in n — at n=24 ALL orbits are
short (≤100); at n=32 ALL orbits exceed 2^16.  Obstacle 2 is PARTIALLY addressed for
n=32 but unresolved for n=256 (production).  Obstacles 1 and 3 remain open.

**KEX demo script:** `SecurityProofsCode/nl_fscx_v2_kex.py` (added v1.9.23) — five-section analysis:
- §1: Extended orbit sweep n=8..40: anomaly confirmed at n=12 (ALL short ≤100); n=16,20,28,32,36,40
  all-long (orbits > cap=4096); n=24 bounded (orbits ≤ 65536, see nl_fscx_v2_orbit.py).
- §2: Non-abelianness confirmed at 100% of 200 tested (K1,K2,A) triples at n=32; explicit witness.
- §3: Commuting-pair density measured: 0/300 single-step and 0/300 revolve-commuting pairs — Ko-Lee
  KEX not viable with random key selection; no useful commuting subgroups found.
- §4: Same-key revolve KEX (abelian subgroup, DLP-reducible) works correctly; cross-key KEX fails
  without commuting pairs; group inverse round-trip verified (`pi_K^{-1}(pi_K(A)) = A`).
- §5: Obstacles 1 and 3 remain open (theoretical); Obstacle 2 extended to n=8..40.

**Remaining open (research-blocked):**
- Obstacle 1: circuit-model CSP transfer theorem — no structured commuting subgroups found, so no
  Ko-Lee reduction is available; obstacle deepened by §3 results.
- Obstacle 2: n=256 orbit safety — empirically untestable at production scale.
- Obstacle 3: structured commuting-subgroup construction needed for Ko-Lee KEX instantiation.

**Research plan (phased — Phase 0 is a decision gate).**

The `nl_fscx_v2_kex.py` §3 result (0/300 commuting pairs) is the pivot: a Ko-Lee /
AAG-style KEX *requires* two commuting subgroups, so before any reduction work we must
settle whether the `{pi_K}` family has ANY exploitable algebraic structure, or is
structurally hostile to non-abelian KEX.  Likely outcome: 78.E resolves as a documented
NEGATIVE result, which is a legitimate completion.

- **Phase 0 — decision gate: is there exploitable structure?**  Script
  `SecurityProofsCode/nl_fscx_v2_csp.py`.  Two structural probes at small n (n=8,12,16):
  1. *Centralizer search* — solve Theorem 15's commutativity condition
     `delta(K1) - delta(K2) == M(K1 XOR K2) (mod 2^n)` exhaustively; is C(pi_K1)
     generically trivial, or is there hidden coset structure?
  2. *Subgroup-order growth* — order of `<pi_K1,...,pi_Km>` vs |Sym(2^n)|; does the
     family generate the full symmetric group (no usable quotient) or land in a
     structured subgroup?
  GATE: if centralizers are trivial AND the family generates Sym(2^n), Ko-Lee/AAG is
  provably dead → pivot to a Stickel-type two-sided KEX (`E = pi_K1 . A . pi_K2`, no
  commutativity needed) OR close 78.E as a documented impossibility.

- **Phase 1 — Obstacle 2 (orbit/order lower bound).**  Extend `nl_fscx_v2_orbit.py` to
  compute (not sample) `|<pi_K>|` at n=8..16; fit a growth law; state n=256 scope limit.
  Converts Obstacle 2 from "open" to "conditionally resolved."

- **Phase 2 — Obstacle 1 (black-box → circuit-model transfer).**  Run Gröbner/XL on the
  Theorem-14 carry-structure MQ system for the conjugacy recovery `v = g u g^{-1}` at
  n=8,12; measure D_reg.  An algebraic shortcut → Option C broken (clean negative);
  otherwise record measured complexity as circuit-model hardness evidence.

- **Phase 3 — Obstacle 3 (reduction), only if Phases 0–2 survive.**  If Phase 0 yields a
  Stickel-type construction, target a reduction to the decisional matrix-conjugacy /
  semigroup-action problem (Maze-Monico-Rosenthal group-action framework — NOT braid
  groups); ship KEX + attack-evidence harness.

Exit criteria: Phase 0 negative → **DONE (negative result)**; Phase 2 break → **DONE
(broken)**; all phases survive → **DONE (candidate)**, deployment still gated.

---

#### 78.F — Verifiable Delay Function (VDF) — limited model (Low / Research)

**Primitive:** FSCX orbit periodicity — `fscx_revolve(A, B, n) = A`.

**Construction:**
```python
def vdf_eval(x: BitArray, t: int, domain: BitArray) -> BitArray:
    return fscx_revolve(x, domain, t)

def vdf_verify(x: BitArray, y: BitArray, t: int, domain: BitArray) -> bool:
    return fscx_revolve(y, domain, KEYBITS - t) == x
```

**Critical limitation:** FSCX is GF(2)-linear: `M^t` can be precomputed in O(n^3), bypassing
the sequential delay. Not a full VDF against adversaries with matrix exponentiation capability.

**Demo script:** `SecurityProofsCode/vdf_demo.py` (added v1.9.21) — four-section analysis:
- §1: FSCX VDF eval/verify (P=n always holds; verify is faster when t > P/2).
- §2: GF(2) matrix attack — proves closed form `M^t(A) ⊕ M·T_t·B`, shows crossover at t≈5000
  for n=32 where matrix beats sequential.  Confirms the construction is BROKEN.
- §3: NL-FSCX v1 VDF — non-linear, no matrix attack; but period P > 2^16 at n=32 (consistent
  with orbit analysis), making setup and verification infeasible.
- §4: Production path requires Pietrzak/Wesolowski succinct proofs.

---

#### 78.G — Oblivious PRF (OPRF) — research direction (High)

**Primitive:** `nl_fscx_v1` input symmetry — `nl_fscx_v1(A, B) = nl_fscx_v1(B, A)` (A3).

**Demo script:** `SecurityProofsCode/oprf_demo.py` (added v1.9.22) — four-section analysis:
- §1: 2HashDH OPRF over GF(2^n)*: `F(k,x) = gf_pow(H(x), k)`.  Client blinds with random
  exponent r; server evaluates alpha^k; client unblinds with r^{-1} mod (2^n−1).  GF exponent
  law verified empirically.  Obliviousness under CDH demonstrated.
- §2: NL-FSCX v1 commutativity test (500 triples): single-step symmetry A3 holds 100%;
  iterated commutativity holds 0% — pure NL-FSCX DH-style OPRF is NOT viable.
- §3: Hybrid NL-FSCX OPRF: `F_NL(k_dh, k_nl, x) = nl_fscx_revolve_v1(gf_pow(H(x),k_dh), k_nl, t)`.
  k_nl is a public domain-separation parameter; obliviousness from CDH layer only.
- §4: aPAKE integration — replaces `hfscx_256(pw+salt)` with `hfscx_256(OPRF(k_s,pw)+salt)`,
  closing the offline dictionary attack gap from TODO #78.D.

**Open gaps (from script §5):**
- A. n=256 group order scalar inversion: gcd(r, 2^256−1) == 1 check needed per blind.
- B. Formal One-More-GDH reduction adapted to GF(2^n)* setting.
- C. Pure NL-FSCX OPRF: A3 symmetry does not extend to iterated chains; research direction.
- D. UC-PAKE / SIM-BMP formal reduction for the aPAKE construction (§4).

---

#### 78.H — Masking-Friendly / Side-Channel-Resistant Implementation (Medium)

**Primitive:** FSCX GF(2)-linearity for Boolean masking; ZKBoo 3-party decomposition for NL-FSCX.

**FSCX masking:**
```python
# FSCX(A XOR r, B) = FSCX(A, B) XOR FSCX(r, 0)  [by GF(2)-linearity of M]
r      = BitArray.random(KEYBITS)
masked = fscx_revolve(A ^ r, B, I_VALUE)
result = masked ^ fscx_revolve(r, BitArray(KEYBITS, 0), I_VALUE)
```

ZKBoo circuit in `_zkp_nl_evaluate_circuit` is structurally a 3-share Boolean masking scheme.
Target platforms: Arduino and ARM Thumb-2.

---

#### 78.I — Code-Based Ring / Group Signature (Medium)

**Primitive:** HPKS-Stern-F. OR-composition of k Stern identification instances.
**Constraint:** Proof size scales O(SDFR x k).

---

#### 78.J — Cryptographic Accumulator from HFSCX-256 (Very Low)

**Primitive:** HFSCX-256 collision resistance.
```python
leaf = lambda x: hfscx_256(b'\x00' + x)
node = lambda l, r: hfscx_256(b'\x01' + l + r)
```

---

#### Summary table

| Sub-item | Primitive exploited | Implementation distance | Key open question |
|---|---|---|---|
| 78.A FPE | NL-FSCX v2 bijectivity | Low | None — wrap existing functions |
| 78.B Tweakable block cipher | NL-FSCX v2 delta(B) structure | Low | None — wrap existing functions |
| 78.C NL-FSCX ratchet | NL-FSCX v1 one-wayness | Medium | Collision probability over ratchet lifetime |
| 78.D PQC PAKE | HKEX-RNL + ZKBoo + HFSCX-256 | High | ZKBoo for full HFSCX-256 chain; formal reduction |
| 78.E Non-Abelian KEx | F2 non-commutativity (Theorem 15) | High (research) | Orbit length bound; circuit-model CSP reduction |
| 78.F VDF (limited) | FSCX orbit period | Low to implement; not a full VDF | Matrix shortcut breaks sequentiality |
| 78.G OPRF | NL-FSCX v1 symmetry (A3) | High (research) | Formal blinding scheme; security reduction |
| 78.H Masking / side-channel | FSCX linearity + ZKBoo decomposition | Medium | Formal higher-order masking proof |
| 78.I Ring / group signature | Stern ZKP OR-composition | Medium | Proof-size scaling with ring size |
| 78.J Accumulator | HFSCX-256 collision resistance | Very low | None — direct from existing hash |

**Recommended first implementations:**
1. **78.B** Tweakable block cipher — resolves HSKE-NL-A2 determinism (TODO #12).
2. **78.A** FPE — same primitive, zero new code.
3. **78.J** Accumulator — trivial wrapper around `hfscx_256`.
4. **78.C** Ratchet — gated on collision-probability analysis.
5. **78.E** Non-Abelian KEx — start with `nl_fscx_v2_orbit.py`.

Status: **78.A DONE v1.9.14 · 78.B DONE v1.9.14 · 78.J DONE v1.9.14 · 78.H DONE v1.9.15 · 78.C DONE v1.9.15 · 78.I DONE v1.9.16 · 78.D DONE v1.9.20 · 78.F DONE v1.9.21 · 78.G DONE v1.9.22** — Sub-items 78.A (FPE), 78.B (Tweakable), 78.J (Accumulator), 78.H (Masking), 78.C (Ratchet), 78.I (Ring Signature), 78.D (PAKE-ZKBoo), 78.F (VDF), and 78.G (OPRF) all have demo scripts and analysis.  Sub-item 78.E (Non-Abelian KEx) remains open — orbit length bound and CSP reduction are research-blocked.

---

### 79. Fix two bugs found during full build-and-test run (Correctness/Security, High)

**Discovered:** full build + test run across all six language targets (C, Go, Python, ARM
Thumb-2, NASM i386, Arduino), plus CLI integration and interop tests.

---

#### 79.A — C ZKP-NL (`zkp_nl_eval_3p`) stack-buffer-overflow when `n = 64`

**Affected files:** `herradura.h:1895,1959`, `CryptosuiteTests/Herradura_tests.c:3762`

**Symptom:** The C test binary (`Herradura_tests_c`) terminates with "stack smashing
detected" during `test_zkp_nl_correctness` when processing `n = 64`.  AddressSanitizer
pinpoints a `stack-buffer-overflow` in `zkp_nl_eval_3p` (`herradura.h:1976`).

**Root cause:**

```c
#define ZKP_NL_MAX_N  32
...
uint32_t carry[ZKP_NL_MAX_N + 1][3];   /* carry[33][3] */
```

The `carry` array is allocated for `n ≤ 32`, but the loop:

```c
for (i = 0; i < n - 1; i++)
    carry[i + 1][p] = ...;   /* writes carry[1..n-1] */
```

writes up to index `n - 1 = 63` when `n = 64`, overflowing by 30 rows (360 bytes).

A secondary UB also fires: the mask computation

```c
uint32_t mask = (n == 32) ? 0xFFFFFFFFU : (1u << n) - 1u;
```

is undefined when `n ≥ 32` because `1u << n` shifts a 32-bit type by ≥ 32 (C11 §6.5.7¶3).

The C ZKP-NL implementation uses `uint32_t` for all shares and carry bits, making it
structurally limited to `n ≤ 32`.  Python and Go correctly use arbitrary-precision integers
and pass `n = 64` without issue.  The test (`zkp_nl_sizes[] = {32, 64}`) was inherited from
the Python/Go versions without adjusting for the C type constraint.

**Fix options (choose one):**

1. **Cap C test at `n ≤ ZKP_NL_MAX_N`** — change `zkp_nl_sizes` in `Herradura_tests.c` to
   `{32}` only.  Simple, no library change; reduces C test coverage vs. Python/Go.

2. **Extend C ZKP-NL to 64-bit** — change all share/carry types to `uint64_t`, expand
   the mask logic, and bump `ZKP_NL_MAX_N` to 64.  Correct and maintains coverage parity
   but requires auditing every arithmetic operation in `zkp_nl_eval_3p`, `zkp_nl_prove`,
   `zkp_nl_verify`, and `zkp_nl_keygen`.

3. **Dual-path** — keep `uint32_t` path for `n ≤ 32` and add a `uint64_t` path for
   `n ≤ 64`, selected at runtime inside `zkp_nl_eval_3p`.

**Recommended:** Option 2.  Option 1 silently reduces security-test surface; option 2
restores full parity and closes the UB.

---

#### 79.B — C CLI `encfile`/`decfile`: missing `_RNL_KDF_DC` in seed derivation

**Affected file:** `HerraduraCli/herradura_cli.c` — `cmd_encfile` (line ≈1495) and
`cmd_decfile` (line ≈1589)

**Symptom:** The `test_c_interop.sh` and `test_go_interop.sh` integration tests both abort
with "decfile: authentication tag mismatch — file corrupt or wrong key":

- `C encfile → Python decfile`: **FAIL**
- `Go encfile → C decfile`: **FAIL**
- `Go encfile → Python decfile`: **PASS**

C encrypts and decrypts its own files correctly (standalone `test_c_encfile.sh` passes), but
its `.hkx` files are not readable by Go or Python and vice versa.

**Root cause:**

Both `cmd_encfile` and `cmd_decfile` compute the keystream seed as:

```c
ba_rol_k(&seed, &base, KEYBITS / 8);     /* ← OLD formula, v1.7 and earlier */
```

The correct formula — introduced in v1.8.0 (TODO #38, CHANGELOG entry) — is:

```c
ba_rnl_kdf_seed(&seed, &base);           /* ROL(base, n/8) XOR _RNL_KDF_DC */
```

`ba_rnl_kdf_seed` XORs the SHA-256 initial hash constant `_RNL_KDF_DC` into the seed after
the rotation.  This XOR was added to prevent KDF degeneracy when the key is
rotation-periodic.  The Go CLI (`herradura_cli.go`) and Python CLI (`herradura.py`) were
updated to use the new formula at v1.8.0, but the C CLI was not.

The stale comment at `herradura.h:633` also reflects the old formula and should be updated.

**Fix (two-line change):**

```c
/* cmd_encfile (≈line 1495) and cmd_decfile (≈line 1589): */
- ba_rol_k(&seed, &base, KEYBITS / 8);
+ ba_rnl_kdf_seed(&seed, &base);
```

Also update the comment at `herradura.h:633`:
```c
- * Caller computes: base = K XOR nonce; seed = ba_rol_k(base, KEYBITS/8).
+ * Caller computes: base = K XOR nonce; seed = ba_rnl_kdf_seed(base).
```

**Note:** After this fix, C-generated `.hkx` files from v1.9.17 and earlier will not be
decryptable with the corrected CLI (the seed changed).  This is unavoidable — the old C CLI
was generating files that were already incompatible with Go and Python.

---

**Scope:** Both bugs are C-only.  Go, Python, ARM Thumb-2, NASM i386, and Arduino all pass
their respective test suites without errors.

Status: **DONE v1.9.18** — 79.A: all ZKP-NL types promoted to `uint64_t`, `ZKP_NL_MAX_N` bumped to 64; 79.B: `ba_rnl_kdf_seed` substituted for `ba_rol_k` in both `cmd_encfile` and `cmd_decfile`; stale comment at `herradura.h:633` updated.  All C tests pass (test [22] n=64 PASS); all encfile interop tests pass (4/4 C↔Python, 10/10 Go↔C↔Python).

---

### 80. Promote OPRF and PAKE to suite library and CLI (Feature, High)

**Context:** TODO #78 produced two SecurityProofsCode demo scripts whose core functions are
ready for promotion to the main library and CLI:

- `SecurityProofsCode/oprf_demo.py` (`oprf_blind/eval/unblind/direct`) — 2HashDH OPRF over
  GF(2^n)* using the existing `gf_pow` primitive.  Self-contained, clean API.
- `SecurityProofsCode/hkex_pake_demo.py` (`pake_register/client_msg*/server_*`) — 3-message
  PAKE using HKEX-RNL + ZKBoo + HFSCX-256.  Depends on OPRF for aPAKE upgrade.

The following SecurityProofsCode scripts are **NOT** suitable for promotion:
- `vdf_demo.py` — FSCX VDF broken by matrix attack; NL-FSCX v1 VDF lacks efficient verification.
- `nl_fscx_v2_kex.py` / `nl_fscx_v2_orbit.py` — no working non-abelian protocol; research only.

---

#### Batch 1 — OPRF: Python suite (`Herradura cryptographic suite.py`) + CLI (`herradura.py`) ✅ DONE v1.9.24

**Suite functions to add** (prefix `oprf_`, following suite naming conventions):

```python
def oprf_keygen(n: int = KEYBITS) -> int:
    """Random OPRF server key in [2, 2^n − 2]."""

def oprf_blind(x: bytes, n: int = KEYBITS) -> tuple[int, int]:
    """Client: hash x to GF(2^n)* and blind with random exponent r.
    Returns (r, alpha) where alpha = H(x)^r.  r is the unblinding scalar."""

def oprf_eval(alpha: int, k: int, n: int = KEYBITS) -> int:
    """Server: evaluate alpha^k in GF(2^n)*  (one gf_pow call)."""

def oprf_unblind(beta: int, r: int, n: int = KEYBITS) -> int:
    """Client: recover F(k, x) = H(x)^k from beta = H(x)^{kr} by computing beta^{r^{-1}}."""

def oprf_direct(x: bytes, k: int, n: int = KEYBITS) -> int:
    """Direct PRF evaluation F(k, x) = H(x)^k (server-side only; not oblivious)."""
```

**Internal helper** (not exported):
```python
def _oprf_hash_to_field(data: bytes, n: int) -> int:
    """HFSCX-256(data) → non-zero element of GF(2^n)."""
```

**Suite `main()` demo block** — show a complete blind/eval/unblind round-trip and the
aPAKE use case (pw_key via OPRF instead of direct hash).

**CLI subcommands** to add to `herradura.py`:

```
# Generate OPRF server private key
herradura oprf-keygen [--algo oprf-gf256] > server_oprf.pem

# Client: hash and blind input; outputs (r_scalar.hex, alpha.hex) to stdout
herradura oprf-blind --input "password_or_bytes" > blind_out.txt

# Server: evaluate blinded input with OPRF key
herradura oprf-eval --key server_oprf.pem --alpha <hex> > beta.hex

# Client: unblind server response to recover PRF output
herradura oprf-unblind --alpha <hex> --beta <hex> --scalar <r_hex> > prf_out.hex
```

PEM label: `OPRF PRIVATE KEY` for the server key.
The blinded value `alpha`, scalar `r`, and evaluation `beta` are passed as hex on
stdin/stdout (similar to how `kex` outputs the session key).

---

#### Batch 2 — OPRF: C (`herradura.h` + `herradura_cli.c`) ✅ DONE v1.9.25

**`herradura.h` functions:**

```c
/* OPRF server key: random integer in [2, 2^KEYBITS - 2] stored in a BitArray. */
void oprf_keygen(BitArray *key);

/* Client blind: H(x,xlen) → GF(2^n) element, multiply by random exponent r.
   Writes r_scalar (unblinding key) and alpha (blinded value) into caller-provided BitArrays. */
void oprf_blind(const uint8_t *x, size_t xlen, BitArray *r_scalar, BitArray *alpha);

/* Server eval: beta = alpha^k in GF(2^n)*. */
void oprf_eval(const BitArray *alpha, const BitArray *k, BitArray *beta);

/* Client unblind: F = beta^{r_inv} = H(x)^k. */
void oprf_unblind(const BitArray *beta, const BitArray *r_scalar, BitArray *F);

/* Direct PRF (server-side, non-oblivious): F = H(x)^k. */
void oprf_direct(const uint8_t *x, size_t xlen, const BitArray *k, BitArray *F);
```

**`herradura_cli.c`** — add `cmd_oprf_keygen`, `cmd_oprf_blind`, `cmd_oprf_eval`,
`cmd_oprf_unblind` and register them in the dispatch table.  PEM codec reuse from
`herradura_codec.h`.

---

#### Batch 3 — OPRF: Go (`herradura/herradura.go` + `herradura_cli.go`) ✅ DONE v1.9.25

**Package functions:**

```go
func OprfKeygen() *big.Int                          // server key
func OprfBlind(x []byte) (r, alpha *big.Int)        // client blind
func OprfEval(alpha, k *big.Int) *big.Int            // server eval
func OprfUnblind(beta, r *big.Int) *big.Int          // client unblind
func OprfDirect(x []byte, k *big.Int) *big.Int       // direct PRF (non-oblivious)
```

**`herradura_cli.go`** — add `cmdOprfKeygen`, `cmdOprfBlind`, `cmdOprfEval`,
`cmdOprfUnblind` and register them.

**Note on `*big.Int` vs `BitArray`:** OPRF scalars are integers mod GF_ORDER = 2^n − 1,
not GF(2^n) field elements.  Use `*big.Int` for scalars r and k; use the existing
BitArray/`[32]byte` type for GF elements alpha, beta, F.

---

#### Batch 4 — aPAKE: Python suite + Python CLI ✅ DONE v1.9.26 (C/Go deferred)

**Dependency:** Batches 1–3 (OPRF) must be complete first.

**Protocol** (3-message aPAKE using HKEX-RNL + OPRF + ZKBoo):

```
Registration (one-time, client-server):
    client → server: alpha = oprf_blind(password)
    server → client: beta  = oprf_eval(alpha, k_s)
    client: pw_oprf = oprf_unblind(beta, r); pw_key = hfscx_256(pw_oprf ‖ salt)
    client: zkp_A = hfscx_256(pw_key ‖ "ZKP-A") & mask; B = random; y = nl_fscx_v1(zkp_A, B)
    server stores: (username, salt, B, y)   [no password, no H(password)]

Login (3 messages):
    msg1 client→server: HKEX-RNL C_client
    msg2 server→client: HKEX-RNL C_server + alpha_r = oprf_blind(password)  ← OPRF blind
                        NOTE: server cannot compute alpha_r itself (client-only step)
    [actually 4-message for aPAKE — see note below]
```

**Protocol note:** Full aPAKE requires the client to blind the password and send alpha to
the server for OPRF evaluation, then unblind.  This adds one extra round-trip vs. the
plain PAKE in `hkex_pake_demo.py`.  The CLI demo mode runs both sides in a single process
(like `kex` with `--our`/`--their`).

**Suite functions** (prefix `hpake_`):
```python
def hpake_register(username, password, oprf_key) -> dict  # server record
def hpake_login_demo(record, password, oprf_key) -> bytes | None  # full 4-msg demo
```

**CLI:**
```
herradura pake register --oprf-key server_oprf.pem --username alice > record.pem  # reads pw from stdin
herradura pake login   --oprf-key server_oprf.pem --record record.pem             # reads pw from stdin
herradura pake demo    --oprf-key server_oprf.pem  # runs both sides, shows session key match
```

**ZKBoo performance caveat:** In Python, ZKBoo at n=256 requires C/Go extensions or
reduced rounds.  The Python suite will use n=32 demo parameters with a visible warning;
C and Go will use n=256.

---

#### Batch 5 — Assembly/Arduino n=32 OPRF demo (Low priority)

`gf_pow` at n=32 already exists in ARM Thumb-2, NASM i386, and Arduino targets.  A minimal
n=32 OPRF demo block (blind/eval/unblind) can be added to each, following the pattern of
the FPE/Tweakable demos added in TODO #78.

**Security advisory required:** Output a clear `[DEMO n=32 — NOT PRODUCTION SECURE]`
message. n=32 GF(2^32)* CDH is trivially brute-forcible.

---

#### Batch 6 — CLI integration tests (`CliTest/`) ✅ DONE v1.9.25

New test scripts:
- `CliTest/test_oprf.sh` — Python CLI keygen + blind + eval + unblind round-trip
- `CliTest/test_c_oprf.sh` — C CLI equivalent
- `CliTest/test_go_oprf.sh` — Go CLI equivalent
- `CliTest/test_oprf_interop.sh` — cross-language: Python key, C eval, Go unblind (and permutations)
- `CliTest/test_pake.sh` — Python CLI aPAKE register + login demo

---

#### Priority order

1. **Batch 1** (Python OPRF) — unblocks aPAKE and is the simplest starting point.
2. **Batch 2** (C OPRF) — adds `herradura.h` exports; enables C CLI and interop tests.
3. **Batch 3** (Go OPRF) — completes the three-language tier.
4. **Batch 6** (CLI tests) — validates interop; run after each language batch.
5. **Batch 4** (aPAKE) — higher complexity; schedule after OPRF stabilises.
6. **Batch 5** (Assembly/Arduino demo) — lowest priority; n=32 only.

Status: **Batch 1 DONE v1.9.24 · Batch 2 DONE v1.9.25 · Batch 3 DONE v1.9.25 · Batch 4 DONE v1.9.27 · Batch 5 DONE v1.9.61 · Batch 6 DONE v1.9.25** — Batch 1: Python suite (`oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`) + Python CLI (`oprf-blind`, `oprf-eval`, `oprf-unblind`, `genpkey --algo oprf`) + `primitives.py` exports + `test_oprf.sh` (8/8). Batch 2: `herradura.h` OPRF functions (`oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`, `ba_modinv_ord`) + C suite demo + `herradura_cli.c` + `herradura_codec.h` PEM labels + `test_c_oprf.sh` (7/7). Batch 3: `herradura/herradura.go` (`OprfKeygen`, `OprfBlind`, `OprfEval`, `OprfUnblind`, `OprfDirect`) + Go suite demo + `herradura_cli.go` + `test_go_oprf.sh` (7/7). Batch 4: `herradura.h` (`HpakeRecord`, `hpake_register`, `hpake_login_demo`) + C suite demo + `herradura_cli.c` (`pake-register`, `pake-demo`) + `herradura/herradura.go` (`HpakeRecord`, `HpakeRegister`, `HpakeLoginDemo`) + Go suite demo + `herradura_cli.go` (`cmdPakeRegister`, `cmdPakeDemo`) + `test_c_pake.sh` (7/7) + `test_go_pake.sh` (7/7). Batch 5 DONE v1.9.61: ARM Thumb-2 (`Herradura cryptographic suite.s`) and NASM i386 (`Herradura cryptographic suite.asm`) each add an OPRF blind/eval/unblind demo block using fixed inputs (x=0x50415353, k=0x13579BDF, r=7, r_inv=0x49249249=7^{-1} mod 2^32-1); Arduino (`Herradura cryptographic suite.ino`) adds `oprf_hash_to_field_32`, `oprf_blind_32`, `oprf_eval_32`, `oprf_unblind_32`, `oprf_direct_32` helpers and a `loop()` demo block; all three targets output `+ OPRF blind/eval/unblind correct` and match F_direct; `[DEMO n=32 -- NOT PRODUCTION SECURE]` warning displayed. Batch 6: `test_oprf_interop.sh` (8/8 cross-language combinations).

---

## Security Fixes — Identified 2026-06-10

### 81. Fix stack/heap buffer overflow in `pem_unwrap` — oversized PEM label (Security, Critical)

**Discovered:** Security review 2026-06-10.

**Affected files:** `HerraduraCli/herradura_codec.h:297-300`, `HerraduraCli/herradura_cli.c:173,186`

**Root cause:** `pem_unwrap()` copies the PEM `BEGIN` label into a caller-provided buffer
with no length check:

```c
size_t ll = (size_t)(p - ls);
memcpy(label_out, ls, ll);   /* no bound check — overflows if ll > 79 */
label_out[ll] = '\0';
```

All callers supply an 80-byte buffer (`char label[80]`).  A malicious PEM file whose label
exceeds 79 bytes overflows that buffer.  The two highest-risk call sites are both reachable
from untrusted input:

- `pem_key_load()` (`herradura_cli.c:173`) — called for signature files in `cmd_verify`,
  `cmd_dec`, and `cmd_encfile` / `cmd_decfile`.  `PemKey` is a stack-local struct; overflow
  writes past `label[80]` into the adjacent `der` pointer, `der_len`, `vals[]`, and
  ultimately past the struct into other stack data and the saved return address.
- `zkp_raw_pem_read()` (`herradura_cli.c:186`) — `label[80]` is a plain stack local;
  overflow is similarly unbounded.

**Fix plan:**

1. Add a length guard inside `pem_unwrap` in `herradura_codec.h` before the `memcpy`:

   ```c
   size_t ll = (size_t)(p - ls);
   if (ll >= 80) return -1;     /* label too long — reject */
   memcpy(label_out, ls, ll);
   label_out[ll] = '\0';
   ```

   The constant `80` should be replaced with a named macro (e.g., `PEM_LABEL_MAX 80`)
   shared between the codec header and all callers so future buffer-size changes stay in
   sync.

2. Verify that every caller checks the return value of `pem_unwrap` / `pem_read_file` and
   propagates the error rather than continuing with a potentially corrupted buffer.

3. Add a regression test in `herradura_codec.h`'s self-test (`HERRADURA_CODEC_SELFTEST`)
   that passes a PEM with an 80-character label and asserts `pem_unwrap` returns `-1`.

Status: **DONE v1.9.28** — `PEM_LABEL_MAX 79` macro added to `herradura_codec.h` buffer-size section; `pem_unwrap` rejects labels with `ll > PEM_LABEL_MAX` before the memcpy; self-test section 7 added with an 80-character label that asserts `pem_unwrap` returns `-1`.

---

### 82. Add upper-bound validation for `rounds` in ZKP-NL proof deserialization (Security, Medium)

**Discovered:** Security review 2026-06-10.

**Affected files:** `HerraduraCli/herradura_cli.c:247-250`

**Root cause:** `zkp_nl_unpack_proof()` reads `rounds` from the first 8 bytes of an
attacker-supplied proof buffer and uses it directly as the malloc count, with no upper-bound
check:

```c
int rounds = (int)(((uint32_t)buf[4]<<24)|((uint32_t)buf[5]<<16)|
                   ((uint32_t)buf[6]<<8)|buf[7]);          /* fully attacker-controlled */

ZkpNlRound *proof = (ZkpNlRound *)malloc((size_t)rounds * sizeof(ZkpNlRound));
```

On 64-bit hosts this produces an OOM failure for absurdly large values (no RCE).  However,
`herradura.h` is a single-include header intended to be compiled into arbitrary C projects,
including 32-bit targets (i386 and ARM Thumb-2 builds exist in this repo).  On a 32-bit
system, a crafted `rounds` value can make `(size_t)rounds * sizeof(ZkpNlRound)` wrap to a
small number, causing `malloc` to return a tiny buffer that the subsequent fill-loop
overflows — heap corruption → RCE.

A second, independent issue: casting `uint32_t → int` is undefined behaviour when the
high bit is set; a negative `rounds` passed to `zkp_nl_verify` as `(size_t)negative_int`
wraps to a near-`SIZE_MAX` value in the `ch_len` multiplication at `herradura.h:2154`,
again a potential overflow.

**Fix plan:**

1. Immediately after reading `rounds` (and `n`) in `zkp_nl_unpack_proof`, add explicit
   range validation before any allocation:

   ```c
   if (rounds <= 0 || rounds > 4096)
       die("ZKP-NL proof: rounds out of range");
   if (n <= 0 || n > ZKP_NL_MAX_N)
       die("ZKP-NL proof: n out of range");
   ```

   `4096` is a safe ceiling — production use is `ZKP_NL_PROD_ROUNDS` (a small constant);
   adjust the upper bound to match the highest legitimate value if it changes.

2. Keep `rounds` and `n` as `int` but enforce the bounds before any arithmetic that feeds
   `size_t` multiplications.

3. In `herradura.h:zkp_nl_verify`, assert `rounds > 0` at entry so callers that use the
   header directly are also protected.

4. Add a test case in `CryptosuiteTests/Herradura_tests.c` that calls
   `zkp_nl_unpack_proof` with a minimally crafted buffer setting `rounds = 0xFFFFFFFF`
   and verifies the function calls `die()` / returns an error rather than crashing.

Status: **DONE v1.9.28** — `herradura_cli.c:zkp_nl_unpack_proof` now validates `n` and `rounds` immediately after decoding (rejects `n <= 0 || n > ZKP_NL_MAX_N` or `rounds <= 0 || rounds > 4096`); `herradura.h:zkp_nl_verify` also guards its entry with the same range check and returns 0 on invalid parameters.

---

### 83. Replace `memcmp` with constant-time comparison in ZKP-NL verification (Security, Medium)

**Discovered:** Security review 2026-06-10.

**Affected files:** `herradura.h:2187`

**Root cause:** ZKP-NL proof verification uses the standard `memcmp` to compare 32-byte
recomputed commitment hashes against the proof's stored commitments:

```c
if (memcmp(c_p1, coms[p1], 32) || memcmp(c_p2, coms[p2], 32)) return 0;
```

`memcmp` implementations are permitted (and in practice do) short-circuit on the first
differing byte.  A timing oracle over many verification calls lets an attacker learn how
many leading bytes of the expected commitment hash match their crafted value, recovering
the commitment byte-by-byte.  Knowing a commitment before the Fiat-Shamir challenge is
selected undermines the hiding property of the commitment scheme and weakens the soundness
argument of the ZKP.

Note: the `ba_equal` function used elsewhere in the file (`herradura.h:91-98`) already
uses a correct constant-time XOR-accumulation pattern; the `memcmp` at line 2187 is an
inconsistency.

**Fix plan:**

1. Add a local 32-byte constant-time comparison helper near the top of `herradura.h`
   (alongside `ba_equal`):

   ```c
   static int ct_eq32(const uint8_t *a, const uint8_t *b)
   {
       uint8_t diff = 0;
       int i;
       for (i = 0; i < 32; i++) diff |= a[i] ^ b[i];
       return diff == 0;
   }
   ```

2. Replace the `memcmp` calls at `herradura.h:2187`:

   ```c
   /* Before */
   if (memcmp(c_p1, coms[p1], 32) || memcmp(c_p2, coms[p2], 32)) return 0;

   /* After */
   if (!ct_eq32(c_p1, coms[p1]) || !ct_eq32(c_p2, coms[p2])) return 0;
   ```

3. Audit all other `memcmp` calls in `herradura.h` and `herradura_cli.c` for similar
   patterns where the compared value is security-sensitive (shared secrets, MACs, hashes
   used in authentication).  `herradura.h:2307` (`memcmp(cur, root, KEYBYTES)` in the
   Merkle path verifier) is a candidate for the same treatment.

4. Add a comment above `ct_eq32` noting that the compiler must not optimise it away;
   on compilers that support it, annotate the loop with a memory barrier or use
   `__attribute__((optimize("O0")))` as a precaution, or prefer `memcmp_s` /
   `CRYPTO_memcmp` if a suitable library is already linked.

Status: **DONE v1.9.28** — `ct_eq32` and `ct_eq_keybytes` constant-time helpers added to `herradura.h` alongside `ba_equal`; `memcmp(c_p1, coms[p1], 32) || memcmp(c_p2, coms[p2], 32)` at line 2187 replaced with `ct_eq32`; `memcmp(cur, root, KEYBYTES)` in `haccum_verify` at line 2307 replaced with `ct_eq_keybytes`.

---

## Pre-existing Failures — Identified 2026-06-10

### 84. Investigate and fix flaky Masked HSKE round-trip failure in Python test suite (Test Quality, Medium)

**Discovered:** Full-suite run during security-review session 2026-06-10.

**Affected files:** `CryptosuiteTests/Herradura_tests.py:1820-1849` (`test_masked_hske`),
`CryptosuiteTests/Herradura_tests.py:431-436` (`fscx_revolve_masked_test`),
`Herradura cryptographic suite.py:1743-1749` (`fscx_revolve_masked`)

**Symptom:** Test [26] `Masked HSKE (78.H)` reports `round-trips=192/200 [FAIL]` when run as
part of the full test suite with `-r 200`.  Running the masked round-trip logic in isolation
yields 0 failures in 2000 trials, confirming the failure is intermittent and context-dependent.

**Not caused by v1.9.28 security fixes** — `git show 63a8aea --stat` confirms zero Python
files were modified in that commit.  The failure pre-dates the security-fix batch.

**What the test checks:**

```python
ct  = fscx_revolve_masked_test(pt,  key, mask, _I_VALUE)   # 64 steps
rec = fscx_revolve_masked_test(ct,  key, mask, _R_VALUE)   # 192 steps
assert rec.uint == pt.uint
```

where `fscx_revolve_masked_test(A, B, mask, n)` computes:

```python
am = A ⊕ mask
fm = fscx_revolve(am, B, n)
fz = fscx_revolve(mask, 0, n)
return fm ⊕ fz
```

**Mathematical analysis:** By GF(2)-linearity of `fscx_revolve` in its first argument,
`fm ⊕ fz = fscx_revolve(A, B, n)` exactly — the mask cancels out.  The round-trip therefore
reduces to `fscx_revolve(pt, key, 256) == pt`, which holds whenever the orbit period divides
256.  Since all 256-bit FSCX orbits have period dividing 256 (period ∈ {128, 256}), the
round-trip should hold unconditionally.

**Hypothesis:** The failure may be caused by shared mutable state elsewhere in the test
suite — for example, a `BitArray` instance whose `_val` or `_mask` field is mutated in-place
by a preceding test (via the `.rol()` / `.ror()` mutating methods or a direct `_val` write),
inadvertently affecting a cached value that ends up reused in this test.  Alternatively, a
Python `random` / `os.urandom` interaction could be involved if `BitArray.random` is shadowed
or patched by another test.

**Fix plan:**

1. Add `print` diagnostics (temporarily) to `test_masked_hske` to log the `(pt, key, mask)`
   triple whenever a round-trip fails, to capture failing inputs.

2. Re-run the full suite multiple times and collect failing triples.  Verify that the failing
   inputs also fail in isolation; if they do not, the bug is a state-mutation side-effect.

3. Audit all uses of the in-place `BitArray.rol()` / `BitArray.ror()` methods and any direct
   `_val` assignments in the test suite; replace with the immutable `rotated()` form where
   the result is later read as if it were unmodified.

4. If isolation runs also fail for the captured inputs, inspect `fscx_revolve` for an
   off-by-one in the step count or a bitwidth mismatch (e.g., `_KEYBITS` vs `KEYBITS`).

5. Once root cause is confirmed, apply the minimal fix (mutability guard, step-count
   correction, or similar), and add a deterministic regression test that runs the specific
   failing inputs.

Status: **DONE v1.9.29** — Root cause: `test_masked_hske` compared `ok == N` (requested iterations) instead of `ok == n_run` (actual iterations run by `_trange`). When `-t` limits wall-clock time, `_trange` stops at a 64-iteration checkpoint (e.g., i=191 → 192 iterations, i=127 → 128 iterations) and returns early; since the masked round-trip is mathematically guaranteed to succeed, `ok` equals the early-stop count, but `ok < N` → spurious FAIL. Fix: added `n_run` counter and changed PASS condition to `ok == n_run`, matching every other `_trange`-based test in the suite. Confirmed: with a tight time limit the test now reports e.g. `128/128 [PASS]` instead of `128/200 [FAIL]`.

---

### 85. Acknowledged: C/Go/Python test [4] bit-frequency bias — FAIL by design (Acknowledged Expected, Low)

**Discovered:** Full-suite verification 2026-06-10.

**Affected files:** `CryptosuiteTests/Herradura_tests.c` `CryptosuiteTests/Herradura_tests.go` `CryptosuiteTests/Herradura_tests.py`

**Symptom:** Test [4] `Bit-frequency bias` consistently reports `[FAIL]` across all three language targets. Typical output: `bits=256 min=38.5% max=59.0% mean=49.8% [FAIL]` (PASS threshold requires 47–53%).

**Root cause / intent:** FSCX is a linear map over GF(2)^n (not a pseudo-random function), so FSCX outputs of random inputs have statistically non-uniform bit distributions — some bit positions are more or less likely to be 1 than others, depending on the input pair. This is a documented structural property, not a defect. The test is intentionally measuring this property: a [FAIL] confirms that FSCX is not a PRF, which is known and expected.

**No fix required.** The test correctly documents the statistical bias of FSCX, and the FAIL label is an accurate characterization of the property under test. Changing the PASS threshold to accommodate the measured ranges would hide the information the test is designed to surface.

Status: **ACKNOWLEDGED** — Expected FAIL by design. No action required.

---

### 86. Acknowledged: C test [18] HPKE-Stern-F brute-force decap — intermittent FAIL by design (Acknowledged Expected, Low)

**Discovered:** Full-suite verification 2026-06-10.

**Affected files:** `CryptosuiteTests/Herradura_tests.c`

**Symptom:** Test [18] `HPKE-Stern-F correctness: encap+decap` for `n=32, t=2 (brute-force)` occasionally reports `[FAIL]` (e.g., `198 / 200 decapsulated [FAIL]`). The failure is non-deterministic: the same test with a different random seed can produce 200/200 PASS.

**Root cause / intent:** The brute-force KEM decoder for n=32, t=2 searches all C(32,2) = 496 weight-2 error vectors for one whose syndrome matches the ciphertext. Since the syndrome space is only 2^16 = 65536 values and there are 496 candidate error vectors, syndrome collisions can occur: two different weight-2 vectors may produce the same syndrome, causing the brute-force to recover the wrong error vector and derive a different key. The expected failure rate is low but nonzero. The test PASS criterion (`fail == 0`) is deliberately strict so any collision is visible.

This is explicitly documented in `CLAUDE.md` and `README.md`: "Production decap requires a QC-MDPC syndrome decoder; demo uses known e'." The n=32 brute-force demo is a correctness illustration, not a production decoder.

**No fix required.** The failure rate is a known property of the demo decoder. Go and Python use `known-e'` paths that always pass; C exposes the brute-force limitation explicitly.

Status: **ACKNOWLEDGED** — Expected intermittent FAIL by design. No action required.

---

### 87. Unify test numbering across C, Go, and Python — eliminate benchmark/security collisions (Test Quality, Medium)

**Discovered:** Cross-language consistency review 2026-06-11.

**Affected files:**
`CryptosuiteTests/Herradura_tests.c`, `CryptosuiteTests/Herradura_tests.go`,
`CryptosuiteTests/Herradura_tests.py`, `CLAUDE.md`

**Problems identified:**

1. **CLAUDE.md severely outdated** — claims C has [1]–[18] security + [19]–[28] benchmarks; actual counts are [1]–[27] security + [28]–[39] benchmarks (after fix). Same discrepancy for Go and Python. Assembly listed as [1]–[12]; actual is [1]–[13].

2. **Benchmark numbers collide with security test numbers** — when tests [22]–[27] (FPE, TWK, Accumulator, Masked HSKE, Ratchet) were added, the benchmarks were not renumbered. A run of any language produces duplicate `[N]` lines in output: `[25]` means both "Masked HSKE correctness" and "HSKE throughput benchmark".

3. **Go [17]/[18]/[19] order inverted vs C/Python** — Go: HFSCX-256=[17], HPKS-Stern-F=[18], HPKE-Stern-F=[19]; C and Python: HPKS-Stern-F=[17], HPKE-Stern-F=[18], HFSCX-256=[19].

4. **HPKS-Stern-Ring is [28] in C but [27] in Go/Python** — caused by C-only test `[20] F_stern range`, which shifts all subsequent C numbers by 1 relative to Go/Python.

5. **Non-sequential output in all three languages** — Go/Python print `[27] HPKS-Stern-Ring` before `[19]–[26]` because `testHpksSternRingCorrectness` is called before HFSCX-256 and ZKP tests in `main()`. C similarly prints `[20]` and `[28]` before `[19]`.

**Fix plan:**

Establish unified security test numbering [1]–[27] identical across C, Go, and Python:

| # | Test | Change required |
|---|------|-----------------|
| [17] | HPKS-Stern-F correctness | Go: reorder (currently [18]) |
| [18] | HPKE-Stern-F correctness | Go: reorder (currently [19]) |
| [19] | HFSCX-256-DM known-answer | Go: reorder (currently [17]); C/Py: fix call order |
| [20] | HPKS-Stern-Ring | C: renumber [28]→[20]; Go/Py: renumber [27]→[20] |
| [21] | ZKP-RNL completeness | Go/Py: renumber [20]→[21]; C: unchanged |
| [22] | ZKP-NL completeness | Go/Py: renumber [21]→[22]; C: unchanged |
| [23] | FPE (78.A) | Go/Py: renumber [22]→[23]; C: unchanged |
| [24] | TWK (78.B) | Go/Py: renumber [23]→[24]; C: unchanged |
| [25] | Accumulator (78.J) | Go/Py: renumber [24]→[25]; C: unchanged |
| [26] | Masked HSKE (78.H) | Go/Py: renumber [25]→[26]; C: unchanged |
| [27] | Ratchet (78.C) | Go/Py: renumber [26]→[27]; C: unchanged |

C-only `F_stern range at n=32` (currently [20]): remove the `[N]` label from its output header; test still runs but is no longer numbered (appears between [20] and [21] in call order).

Renumber benchmarks to [28]–[39] in all three languages (currently [22]–[33] in Go, [25]–[36] in Python, [26]–[37] in C), eliminating all collisions.

Fix `main()` call order in all three so output is strictly monotone: [1]–[27] then [28]–[39].

Update CLAUDE.md testing section to reflect actual counts.

Update TODO #84 reference: Python test `[25]` → `[26]` (Masked HSKE renumbered).

Status: **DONE v1.9.31**

---

## PQC Security Proofs Review — Identified 2026-06-12

Review scope: SecurityProofs-2.md §11–§11.9 (NL-FSCX, HKEX-RNL, Stern-F, HFSCX-256-DM)
and SecurityProofs-3.md §11.10 (ZKP extensions), cross-checked against the deployed
Python suite implementation.

### 88. Apply HFSCX-256-DM finalization to `_stern_matrix_row` — F_stern-v2 fix only partially deployed (Security, High)

**Affected files:** all six language targets (suite + `herradura.h` + Go package +
assembly/Arduino n=32 demos), `SecurityProofs-2.md` §11.8.4, test files.

**Problem.** SecurityProofs-2.md §11.8.4 ("Fix (TODO #43)") specifies that the range
compression of F_stern is eliminated by composing with HFSCX-256-DM, and states "One
HFSCX-256-DM call is added **per row of H** and per hash step in the commitment scheme."
TODO #43 (DONE v1.6.0) applied the finalization to `_stern_hash` only.  The public
parity-matrix row generator still uses raw NL-FSCX v1:

```python
def _stern_matrix_row(seed_int, row, n):
    seed = BitArray(n, seed_int)
    A0   = BitArray(n, seed_int ^ row).rotated(n // 8)
    return nl_fscx_revolve_v1(A0, seed, n // 4)   # no HFSCX finalization
```

Consequence: rows of H are drawn from a range-compressed distribution (~21–28% distinct
at n=32 per TODO #42 measurements; predicted <10^-4 distinct fraction at n=256 per
§11.8.4 §10 extrapolation).  H is therefore distinguishable from a uniformly random
binary matrix by collision counting, and duplicate/correlated rows reduce rank(H),
weakening the SD(N,t) instance below its nominal hardness.  This contradicts the PRF
premise of Theorem 17 (ε_PRF term) for the matrix-generation use, which §11.8.4
presents as fixed.

**Fix:** route each row through HFSCX-256-DM before truncation to n bits, exactly as
`_stern_hash` does, in all six targets.  Wire-format breaking: public keys, syndromes,
signatures, and KEM ciphertexts all change (H changes).  Update §11.8.4 to record
deployment, update interop tests, bump version.

Status: **DONE v1.9.35** — HFSCX-256-DM finalization deployed to `_stern_matrix_row`
(Python suite + tests), `stern_matrix_row` (`herradura.h`) + `stern_matrix_row_ba`
(C tests), `SternMatrixRow` (Go package), and — via `hfscx_32` / truncated HFSCX-256 —
the n=32 demos (`stern32_matrix_row` in the C suite; `stern_matrix_row_32` in ARM/i386
suite+test assembly and the Arduino suite).  Row outputs verified byte-identical across
Python/C/Go; all per-language Stern tests pass (C/Go/Py suites + tests, qemu-arm,
qemu-i386); §11.8.4 updated with the finalized formula and a deployment-status
paragraph.  During verification a separate pre-existing failure was found: cross-language
HPKS-Stern-F CLI signature interop fails at the pre-change baseline too — see the new
TODO entry below (#100).

---

### 89. HKEX-RNL: unauthenticated unilateral blinding polynomial enables parameter-substitution downgrade (Security, High)

**Affected files:** suite (all targets), `HerraduraCli` kex flows, `SecurityProofs-2.md`
§11.4.2–§11.4.3.

**Problem.** §11.4.2: "One party (e.g. Alice) draws a_rand ← R_q uniformly and transmits
it in the clear."  The security argument (§11.4.3) requires m_blind = m + a_rand to be
uniformly random in R_q, and notes blinding is **required** for the Ring-LWR reduction.
Two gaps:

1. **Active substitution.** A MITM (or a malicious peer) can replace a_rand with a chosen
   value, e.g. a_rand = −m(x) + e for small e, making m_blind sparse/structured.  The
   protocol then degenerates toward the unblinded case that §11.4.3 explicitly warns is
   open to lattice-reduction leverage; in the extreme m_blind = 0 all public keys become
   rounding of 0.  Nothing in the wire format or code validates a_rand.
2. **Non-contributory randomness.** Even passively, the proof's "uniform m_blind" premise
   rests entirely on one party's RNG; a backdoored or weak RNG on one side silently
   weakens both.

**Fix plan:**
- Make the blinding contributory: both parties send nonces n_A, n_B and derive
  a_rand = XOF(n_A ‖ n_B) by expanding HFSCX-256-DM in counter mode to n coefficients
  mod q (rejection-sample to keep uniformity).  This fits the existing two-round
  HKEX-RNL message flow without adding a round.
- At minimum (non-breaking interim): receiver-side sanity validation of a_rand
  (reject if m_blind has low Hamming weight / low coefficient entropy) plus a
  documented caveat in §11.4.3 that the uniformity assumption is trust-on-first-use.
- Update SecurityProofs-2.md §11.4.2/§11.4.3 with the active-adversary model.

Status: **DONE v1.9.49** — Full contributory fix implemented.  `rnl_contributory_kdf` added
to `herradura.h`; Alice generates nonce n_A at `genpkey`, stored as 4th field in private and
public key PEM; Bob generates nonce n_B at kex step 1, stored as 6th field in RESPONSE PEM.
Final session key = HFSCX-256(K_raw_big_endian ‖ n_A ‖ n_B).  Implemented in C
(`herradura_cli.c`), Python (`herradura.py`), and Go (`herradura_cli.go`) CLIs; backward-
compatible (old keys without n_A/n_B use zero nonces).  Suite demos updated in
`Herradura cryptographic suite.{py,go}` to show contributory KDF.  Pre-existing cross-
language hint encoding bug (Python encoded 256 coefficients vs C/Go's 128) fixed in
`_encode_rnl_response` — all 9 cross-language kex pairs now agree.  Interim v1.9.37 fix
(`rnl_validate_m_blind`) retained.  The XOF(n_A‖n_B) m_blind derivation variant was
determined structurally infeasible in two rounds (n_B is unknown to Alice when she computes
C_A); contributory KDF at the session key level achieves the same security property.

---

### 90. HKEX-RNL: define an upgraded parameter set reaching ≥128-bit Core-SVP (Security, Medium)

**Affected files:** suite (all targets), `SecurityProofs-2.md` §11.4.3/§11.6/§11.7.

**Problem.** The TODO #71 landscape review (§11.4.3) places the deployed parameters
(n=256, q=65537, p=4096, η=1) at ~105–115 classical / ~95–105 quantum Core-SVP bits —
below the 128-bit ML-KEM-768 target.  The documents state this but no remediation path
is planned.

**Fix plan (analysis first, then optional deployment):**
1. Run the LWE estimator over candidate upgrades: (a) η=2 CBD secrets (Kyber-512
   baseline), (b) module rank k=2 over n=256 (Module-LWR, doubles key material),
   (c) smaller q (e.g. 3329) with retuned p and re-verified Peikert reconciliation
   margin (max per-coeff error vs q/8).
2. Verify m(x) invertibility and reconciliation failure rate = 0 at the chosen set
   (extend `hkex_rnl_failure_rate.py`).
3. Document the selected set as `HKEX-RNL-128`; keep the current set as the default
   wire format until a major version, or version-tag the PEM header.

Status: **DONE v1.9.45**

---

### 91. Stern-F: plan production-security parameter path (N ≥ 17000 QC-MDPC) or enforce demo-only status (Security, Medium)

**Affected files:** suite (C/Go/Python), `HerraduraCli`, `docs/TUTORIAL.md`,
`SecurityProofs-2.md` §11.8.4.

**Problem.** §11.7/§11.8.4 (TODO #71 review) put HPKS-Stern-F / HPKE-Stern-F at the
deployed (N=256, k=128, t=16) at only ~2^56–2^60 classical and ~2^30–2^40 quantum ISD
operations — "demo only".  Yet §11.10.5 lists HPKS-Stern-F as "Production-ready,
v1.5.18", and the CLI signs/encrypts with it without any warning.  The 78 KB proof size
quoted everywhere also corresponds to the demo parameters.

**Fix plan:**
1. Immediate (docs/UX): reconcile §11.10.5 wording with the §11.8.4 caveat; add a
   CLI warning (or `--i-know-this-is-demo` style acknowledgement) when Stern-F is used
   at N=256; state demo status in TUTORIAL.md.
2. Research: evaluate a QC-MDPC instantiation (BIKE-style, N≈24646, t=134) using the
   NL-FSCX v1 PRF for seed expansion as already sketched in §11.8.4; requires a
   QC-MDPC bit-flipping decoder (currently absent — decap uses known-e′/brute force).
   Estimate signature/key sizes and decide go/no-go for implementation.

Status: **DONE v1.9.46** — Fix 1 (docs/UX) completed: §11.10.5 wording corrected,
TUTORIAL.md updated, and demo-parameter warnings added to all three CLIs (Python/C/Go).
Fix 2 (QC-MDPC research) remains future work.

---

### 92. Reconcile assumption A2's classical preimage bound with §11.9.4/§11.9.11 claims (Documentation/Proof consistency, Medium)

**Affected files:** `SecurityProofs-2.md` §11.9.2, §11.9.4, §11.9.8, §11.9.11.

**Problem.** Assumption A2 (§11.9.2) states that inverting F_1^64 "requires
Ω(2^{n/2}) = Ω(2^{128}) **classical** operations and Ω(2^{n/2}) quantum queries".  But
§11.9.4 and the §11.9.11 summary claim **2^256 classical** preimage and second-preimage
resistance "under A2" — a bound A2 as written cannot deliver.  Either A2 understates the
conjectured classical hardness (it should be Ω(2^n) classical / Ω(2^{n/2}) quantum,
consistent with Corollary 2's brute-force bound), or the §11.9.4/§11.9.11 rows overstate
it.  Theorem 18 and §11.9.8 item 1 also cite Ω(2^{n/2}) from A2 and should be re-checked
once A2 is restated.

**Fix:** restate A2 with separate classical (2^n) and quantum (2^{n/2}, Grover) bounds,
then audit every downstream citation (§11.9.3–§11.9.11) for consistency, and re-run the
KaTeX validator per CLAUDE.md before pushing.

**Related finding (added 2026-06-12 during TODO #94 work):** §11.4.3 states that
$x^{256}+1$ "does not split into degree-1 factors over F_65537 since 512 ∤ q−1".
This is arithmetically wrong: q−1 = 65536 = 2^16 and 512 = 2^9 divides it, so 2n | q−1
for every power-of-two n ≤ 256 and the ring splits **completely** into linear factors
(empirically confirmed in `zkp_pqc_exploration.py` §2.6 at n=32).  Fully-splitting
rings are standard for lattice schemes (Dilithium uses one), so this does not by
itself invalidate the Ring-LWR hardness claim, but the stated justification for
ruling out subfield/NTRU-style attacks must be corrected and the attack-surface
discussion re-checked when fixing this TODO.

Status: **DONE v1.9.47**

---

### 93. HFSCX-256-DM open hardenings: per-call-site domain tags, HMAC mode, assembly per-slot DS (Security, Low)

**Affected files:** suite (all targets), `HerraduraCli`, `SecurityProofs-2.md`
§11.9.6/§11.9.7/§11.9.9/§11.9.11.

Consolidates the three "open hardenings" already noted in §11.9.11 plus the assembly
gap in §11.9.9, none of which has a TODO entry:

1. **1-byte domain-tag prefix** per call site (0x01 dgst, 0x02 sign-pre-hash,
   0x03 AEAD-MAC), introduced as a versioned wire-format option `HFSCX-256-DS`
   (§11.9.7).  Removes the reliance on collision-resistance reasoning for
   domain separation between `dgst` and sign pre-hash (which currently share IV).
2. **HMAC-HFSCX-256-DM** construction available in the library, and required whenever
   one long-term key is reused across modes (§11.9.6); current raw keyed-IV MAC stays
   the AEAD default.
3. **Assembly/Arduino n=32:** add per-slot DS tags to `stern_hash1_32`/`stern_hash2_32`
   (currently only structural distinctness; §11.9.9 calls this "a future hardening
   item").

Status: **DONE v1.9.48**

---

### 94. ZKP-RNL Σ-protocol: formal soundness gaps — challenge-difference invertibility, stronger cheat tests, and §11.10.6 follow-ups (Research, Medium)

**Affected files:** `SecurityProofs-3.md` §11.10, `SecurityProofsCode/zkp_pqc_exploration.py`,
suite ZKP-RNL implementations.

**Problems identified in review of §11.10.2:**

1. **Special soundness uses (c − c′)^{-1} without an invertibility argument.**  For
   sparse ternary challenges in Z_q[x]/(x^n+1) the difference of two challenges is not
   guaranteed invertible; standard Lyubashevsky-style proofs choose the challenge space
   specifically so that differences are invertible (or work with relaxed soundness
   extracting 2s-type witnesses).  §11.10.2's soundness sketch glosses over this.
2. **Soundness testing is weak:** the only cheat tested is "random z, no s"
   (200 trials).  Add structured cheats: z forged from a different key s′, replayed
   transcripts with modified w, boundary-norm z, and challenge-grinding within
   rejection-sampling limits.
3. **§11.10.6 open directions** have no TODO tracking: (a) formal Ring-LWR reduction
   quantifying the rounding-slack term, (b) NTT-accelerated Σ-protocol (prover/verifier
   currently O(n²) schoolbook), (c) ZKB++ decomposition to cut ZKP-NL proofs from
   920 KB to ~180 KB, (d) hybrid Ring-LWR + Stern-F credential.

**Fix plan:** address item 1 in the proof text (restate as relaxed special soundness or
restrict the challenge space and prove difference invertibility); implement item 2 in
`zkp_pqc_exploration.py` and the suite test files; items 3(a)–(d) prioritized
afterwards, with 3(b) (NTT) the cheapest concrete win.

Status: **Items 1–2 DONE v1.9.32** — §11.10.2 restated as relaxed special soundness
(extractor outputs (z−z', c−c') without inversion; norm bounds stated).  Empirical
confirmation added (`zkp_pqc_exploration.py` §2.6): x^n+1 splits into n linear factors
over F_65537 (since 2n | q−1), and 3/2000 random challenge pairs at n=32 have nonzero
non-invertible differences — strict special soundness is genuinely false at these
parameters.  Structured cheats implemented in `zkp_pqc_exploration.py` §2.4b
(wrong-key witness, tampered-w, perturbed-z, 64-attempt grinding; 0 cheat passes) and
in the Python suite test [21] at n=32/256 (wrong-key / w-tamper / z-tamper rejection).
C/Go test-[21] structured-cheat parity **DONE v1.9.63** — `Herradura_tests.{c,go}`
test [21] now runs wrong-key / w-tamper / z-tamper rejection at n=32/256 (5 checks,
all PASS), matching the Python suite.  Item 3(b) NTT acceleration **DONE v1.9.64** —
the prover/verifier polynomial products already use the negacyclic NTT
(`rnl_poly_mul` / `_rnl_poly_mul` / `RnlPolyMul`) at the production degree n=256 in all
three reference languages (schoolbook retained only for the n=32 didactic demo);
`zkp_pqc_exploration.py` §2.7 cross-checks NTT==schoolbook and measures the speedup
(~6.8× at n=256, ~12.7× at n=512 in pure Python); SecurityProofs-3.md §11.10.6
direction 2 marked Resolved.  Item 3(a) formal Ring-LWR reduction **DONE v1.9.65** —
SecurityProofs-3.md §11.10.7 gives a conditional reduction of relaxed Σ-protocol
soundness to Ring-LWR via an intermediate approximate Ring-SIS step, with the rounding
slack quantified as the SIS modulus 4t⌈q/(2p)⌉ = 36t (144 at n=32, 576 at n=256); the
reduction remains conditional on aR-SIS hardness for the HKEX-RNL m, so it is not a fully
tight standard-model reduction (recorded honestly).  Item 3(c) ZKB++ size analysis
**DONE v1.9.66** — `zkp_pqc_exploration.py` §3.7 gives a first-principles ZKB++-vs-ZKBoo
size breakdown; corrected the over-optimistic "5×/180 KB" claim to the realistic
**≈457 KB (2.0×)** at n=256 (the NL-FSCX circuit is AND-gate-broadcast-dominated, so only
the 2×→1× online-party term helps; reaching ~180 KB needs a sparse LowMC-like circuit
redesign).  SecurityProofs-3.md §11.10.4/§11.10.6 direction 3 updated.  A full ZKB++
*implementation* (and the sparse-circuit redesign) remain open as future work.  Item
3(d) hybrid Ring-LWR + Stern-F credential **DONE v1.9.67** (design sketch) —
SecurityProofs-3.md §11.10.8 specifies the AND-composition of the Ring-LWR Σ-protocol
and the Stern identification protocol, glued by a binding commitment to s with a single
Fiat-Shamir challenge; completeness/soundness/ZK argued, proof size estimated ≈80 KB
(Stern-F-dominated); the unresolved crux is the binding map φ relating the ternary ring
secret to the fixed-weight binary Stern witness with a cheap gadget.

**Overall #94 status: DONE v1.9.67** — items 1–2 (relaxed soundness + structured cheats,
C/Go parity) and the §11.10.6 research directions 3(a)–(d) are all addressed at the
analysis/proof/design level.  Two open-ended *implementation* follow-ups remain as future
work and may be split into their own TODO entries: (i) a full ZKB++ transcript encoder
plus a sparse LowMC-like NL-FSCX circuit to approach ~180 KB, and (ii) the
hybrid-credential binding gadget φ and a working compound-proof implementation.

---

## Core Primitive Review — New Uses and Cryptographic Advantages — Identified 2026-06-12

A focused review of the unique core algorithms (FSCX / FSCX_REVOLVE and the NL-FSCX
family) identified five application directions that are **not** covered by the TODO #78
catalogue.  Each item below records the primitive property exploited, the cryptographic
advantage that makes the construction natural to this suite, and a concrete
implementation plan.

Properties recap driving these items:

- **FSCX is GF(2)-linear and circulant** — `M = I XOR ROL XOR ROR` is a 3-tap circulant
  matrix; rotation-only, branch-free, constant-time on every target including Arduino
  and ARM Thumb-2.  Order of M is n/2, so `M^{-1} = M^{n/2-1}` is a precomputable
  rotation table (`_m_inv`).
- **NL-FSCX v2 is a keyed permutation family** — bijective in A for every B, with a
  closed-form O(n)-rotation inverse.  Suitable wherever a tweakable PRP is needed.
- **NL-FSCX v1 is a conjectured OWF** (Theorem 16, SecurityProofs-2 §11.8.3) — usable
  for one-way state evolution (ratchets, hash chains, key erasure).
- **HPKS Schnorr signing is linear in the secret exponent** — `s = (k − a·e) mod (2^n−1)`
  is an affine function of both a and k, the property that enables threshold and
  aggregate variants in classical Schnorr.

---

### 95. HSKE-NL-AEAD — authenticated encryption mode with key commitment (Feature, High)

**Primitive exploited:** NL-FSCX v1 keystream (HSKE-NL-A1) + HFSCX-256-DM compression.

**Gap:** The suite has no authenticated encryption.  HSKE, HSKE-NL-A1, and HSKE-NL-A2
are malleable: an attacker can flip ciphertext bits (A1: bit-flips pass through to
plaintext; A2: controlled corruption) without detection.  Every modern protocol use of
the suite (CLI `enc`/`encfile`, PAKE session channel from #78.D, ratchet from #78.C)
needs AEAD, and currently none exists.

**Cryptographic advantage:** All components are native — no external MAC import needed.
Two design options to evaluate:

1. **Encrypt-then-MAC:** `C = HSKE-NL-A1(K_enc, nonce, P)`;
   `tag = hfscx_256(K_mac || nonce || AD || C)` with `K_enc, K_mac` derived from a master
   key via domain-separated HFSCX-256 calls.  This is also *key-committing* for free
   (the tag binds K_mac through a collision-resistant hash), a property AES-GCM lacks.
2. **Duplex/sponge mode over the NL-FSCX v2 permutation:** use `nl_fscx_revolve_v2`
   as the sponge permutation (bijectivity gives the required permutation property),
   absorbing AD and plaintext blocks and squeezing the tag — a MonkeyDuplex-style
   single-pass AEAD.  Research-grade: requires analysis of v2's differential/linear
   profile as a sponge permutation before deployment.

**Plan:** implement option 1 (`hske_nl_aead_encrypt` / `hske_nl_aead_decrypt`) in
C/Go/Python with constant-time tag comparison (reuse #83 helper); wire into CLI
`enc`/`dec`/`encfile`/`decfile` behind an `--aead` flag; add tamper-rejection tests;
document option 2 as a follow-up research note in SecurityProofs.

Status: **Option 1 DONE v1.9.33** — `hske_nl_aead_encrypt`/`decrypt` in the Python suite,
`herradura.h`, and `herradura/herradura.go` (byte-for-byte interoperable, shared KAT);
CLI `enc`/`dec --aead [--ad]` with PEM format tag 2 in all three CLIs (`encfile`/`decfile`
were already always-AEAD via the `.hkx` MAC — no flag needed there); security test [28]
(KAT + roundtrip + ciphertext/tag/AD/nonce/key tamper rejection) in C/Go/Python;
`CliTest/test_aead.sh` (9 interop pairs + rejection); SecurityProofs-2.md §11.9.6 note.
Option 2 (NL-FSCX v2 sponge/duplex single-pass AEAD): **DONE v1.9.62** —
`hske_nl_v2_duplex_encrypt`/`decrypt` in `herradura.h`, Python suite, and Go package;
demo blocks in all three suite main files; research disclaimer noting differential/linear
profile of nl_fscx_v2 as a standalone sponge permutation is not yet rigorously analysed.

---

### 96. Forward-secure DRBG — fast-key-erasure RNG from the NL-FSCX v1 ratchet (Feature, Medium)

**Primitive exploited:** NL-FSCX v1 one-wayness (same assumption as #78.C ratchet).

**Gap:** The suite consumes randomness from `os.urandom`/`/dev/urandom` everywhere but
provides no deterministic expansion of its own.  Embedded targets (Arduino) have weak
entropy sources; a seedable, forward-secure DRBG built from suite primitives would let
all targets share one audited generator.

**Construction (fast-key-erasure pattern, Bernstein 2017):**
```
state_{i+1} = nl_fscx_revolve_v1(state_i, DOMAIN_DRBG, n/4)
output_i    = hfscx_256(state_i || counter || b'DRBG-OUT')
```
Erasing `state_i` after each advance makes prior outputs irrecoverable from a
compromised state (backtracking resistance) under the same OWF conjecture as Theorem 16.

**Cryptographic advantage:** identical security assumption set as the rest of the suite
(no new hardness assumptions); rotation/XOR/add-only inner loop runs on AVR.

**Prerequisite:** the same state-collision bound as #78.C — the v1 map is non-bijective,
so expected cycle length of the state walk must be characterised
(`SecurityProofsCode/nl_fscx_v1_ratchet_collision.py`, still unwritten) before
production use.  NIST SP 800-90A health-test analogues (reseed counter, output-block
limit) should be part of the design.

**Plan:** add `drbg_seed` / `drbg_generate` / `drbg_reseed` to C/Go/Python suites;
collision-distance analysis script; statistical tests (reuse test [4] machinery);
document non-goals (not a NIST-validated DRBG).

Status: **DONE v1.9.34** — `drbg_seed`/`drbg_generate`/`drbg_reseed` in the Python suite
(`HDrbg`), `herradura.h` (`HDrbg` struct, `explicit_bzero` fast key erasure), and
`herradura/herradura.go` (`DrbgSeed`/`DrbgGenerate`/`DrbgReseed`); byte-for-byte
interoperable (shared KAT).  Per-seed output limit `DRBG_MAX_BLOCKS = 2^20` enforced.
Collision prerequisite met: `nl_fscx_v1_ratchet_collision.py` §5 (new) characterises the
revolve-64 walk — composed image extrapolates to 2^218.8 at n=256, E[walk collision]
≈ 2^109.7 blocks, P(collision within 2^20-block limit) ≈ 2^-180 (≤ 2^-128 target: SAFE);
also fixed a float-underflow bug in the script's `safe_steps` for tiny probabilities.
Security test [29] in C/Go/Python (KAT, determinism, personalization divergence, reseed
separation, block-limit enforcement, monobit sanity).  Non-goals documented in code and
SecurityProofs-2.md §11.9.6 (not a NIST SP 800-90A validated DRBG).

---

### 97. HPKS-XMSS-F — stateful many-time hash signature from WOTS-F chains + the #78.J Merkle tree (Feature, Medium)

**Primitives exploited:** NL-FSCX v1 hash chain `h(x) = F^{n/4}(ROL(x, n/8), x)`
(Theorem 16 / HPKS-WOTS-F, currently *proof-only* — no suite implementation exists) and
the HFSCX-256 Merkle accumulator already implemented under #78.J.

**Gap:** HPKS-WOTS-F is analysed in SecurityProofs-2 §11.8.3 and stress-tested in
`nl_fscx_rot_analysis.py` (TODO #75), but never landed as code.  A one-time signature
alone is operationally fragile; combining W-OTS chains with the existing Merkle tree
gives an XMSS-style many-time signature — the only suite signature whose security rests
purely on the OWF/collision assumptions (no DLP, no Ring-LWR, no syndrome decoding).

**Cryptographic advantage:** hash-based signatures are the most conservative PQC class
(SPHINCS+/XMSS are already NIST/RFC standards); this variant would be the suite's
highest-assurance signature, with both building blocks already analysed.  The known
two-sided rotational distinguisher on the WOTS chain (p ≈ 0.42/r power law, TODO #75)
does not break the OWF-based proof but must be restated in the design rationale.

**Plan:** implement `hpks_wots_keygen/sign/verify` (Winternitz parameter w=16),
then `hpks_xmss_*` wrapping 2^h leaves (h=10 default) with the #78.J tree; state-file
handling for leaf-index tracking in the CLI (`sign --algo hpks-xmss`); tests for
one-time-reuse rejection and tamper rejection; SecurityProofs-2 §11.8.3 extension.

Status: **DONE v1.9.39**

---

### 98. Threshold and aggregate HPKS — exploiting Schnorr exponent linearity over GF(2^n)* (Research/Feature, Medium)

**Primitive exploited:** linearity of HPKS signing in the secret:
`s = (k − a·e) mod (2^n − 1)`.  If `a = a_1 + a_2 + ... + a_t mod (2^n − 1)` is
additively shared, each party computes `s_j = (k_j − a_j·e) mod (2^n − 1)` with its own
nonce share, and `s = Σ s_j`, `R = Π R_j` verify against the combined public key
`C = Π C_j = g^{Σ a_j}` — the same algebra that powers FROST/MuSig2 in prime-order
groups, transplanted to GF(2^n)*.

**Cryptographic advantages:**
- n-of-n distributed signing and key generation with zero new primitives — only
  `gf_mul`/`gf_pow` and the existing HPKS challenge derivation.
- Key-aggregation (MuSig-style) gives multi-party signatures the size of one HPKS
  signature.
- t-of-n follows with Shamir sharing over Z_{2^n−1}; note 2^n−1 is composite for the
  suite sizes, so the sharing modulus and invertibility conditions need explicit
  treatment (CRT over the factorisation, or restrict to n-of-n first).

**Known hazards to address (research portion):** rogue-key attacks (require MuSig2-style
nonce/key coefficient binding via HFSCX-256), nonce-reuse across signers, and the
challenge function — HPKS uses `fscx_revolve(R, msg, i)` (linear) while HPKS-NL uses
NL-FSCX v1; the threshold variant must use the NL challenge to avoid the known linear
challenge weakness.

**Plan:** analysis script `SecurityProofsCode/hpks_threshold_demo.py` first (n-of-n
2-party demo, rogue-key counterexample, composite-modulus discussion); promote to suite
functions only after the rogue-key binding design is fixed.

Status: **DONE v1.9.43**

---

### 99. FSCX as a standalone linear diffusion layer — branch-number characterisation and SPN construction study (Research, Medium)

**Primitive exploited:** the circulant GF(2)-linear map `M = I XOR ROL XOR ROR` itself —
the one core property no #78 item examines directly.

**Observation:** modern lightweight ciphers (ASCON, Xoodoo, GIFT) are built as SPNs
alternating a cheap non-linear layer with a rotation-based linear diffusion layer.
FSCX's M is exactly such a layer: 3-tap circulant, XOR/rotate-only, constant-time,
self-similar across word sizes, with known algebraic structure (order n/2, precomputable
inverse).  The suite already pairs it with a non-linear step (integer-add carry chain in
NL-FSCX v1/v2) — i.e. NL-FSCX is implicitly a 1-round ARX-style SPN, but its diffusion
quality has never been quantified.

**Work items:**
1. Compute the differential and linear **branch number** of M (and of `M^k` for small k)
   at n = 32, 64, 256; compare against ASCON's Σ functions (also 3-tap circulants —
   `x XOR ROR(x,a) XOR ROR(x,b)`); FSCX's two-operand form `M(A) XOR M(B)` is a
   structural sibling.
2. Measure full-diffusion depth: minimum revolve steps until every output bit depends on
   every input bit of A and B (avalanche matrix), at each suite size.
3. From 1–2, derive a recommended round count for NL-FSCX-based keystreams independent
   of the current heuristic `i = n/4`, and document whether `n/4` over- or
   under-provisions diffusion.
4. Sketch an explicit SPN ("FSCX-SPN") — alternate `nl_fscx_v1` non-linear step with an
   independently-keyed round constant schedule — as the analysable successor to the
   ad-hoc revolve constructions, feeding the sponge-permutation option of #95.

**Cryptographic advantage:** turns the suite's signature primitive from a folklore
construction into one with standard, comparable diffusion metrics, and creates the
analysis foundation that #95 option 2 (sponge AEAD) and #96 (DRBG) depend on.

**Plan:** `SecurityProofsCode/fscx_branch_number.py` (exhaustive at n=16/32, sampled at
n=64/256); results into SecurityProofs-1 §3 (FSCX algebraic analysis); follow-up
SecurityProofs note for the SPN sketch.

Status: **DONE v1.9.38**

---

### 100. Cross-language HPKS-Stern-F CLI signature interop is broken (pre-existing) (Bug, Medium)

**Discovered:** 2026-06-12 during TODO #88 verification, and confirmed present at the
pre-#88 baseline (git stash test), so it is not caused by the matrix-row finalization.

**Affected files:** `HerraduraCli/herradura.py`, `HerraduraCli/herradura_cli.c`,
`HerraduraCli/herradura_cli.go` (sign/verify `--algo hpks-stern` paths), possibly the
suite `hpks_stern_f_sign`/`verify` implementations.

**Symptom matrix** (sign → verify, `--algo hpks-stern`):
- Python → Python, C → C, Go → Go: **OK** (all CliTest self-tests pass)
- Python → Go at bits=32: **OK**; at bits=256: **FAILED**
- Python → C at bits=32 and bits=256: **FAILED**
- C → Python/Go, Go → Python/C at bits=256: **FAILED**

**What is already ruled out:** `_stern_matrix_row` / `stern_matrix_row` /
`SternMatrixRow` produce byte-identical rows across all three languages (verified
post-#88), `_stern_hash` interops (PEM keygen/kex interop tests pass), and all three
CLIs build the message BitArray identically (first n/8 bytes, zero-padded right).
The divergence is therefore elsewhere in the Fiat-Shamir sign/verify pipeline —
candidate suspects: per-round permutation generation, commitment serialization order,
challenge derivation over the flattened commitment list, or signature PEM
pack/unpack field layout.  The size-dependent Py→Go behaviour (32 OK, 256 fails)
suggests at least two distinct bugs.

**Note:** no CliTest script covers cross-language Stern sign/verify (test_c_interop.sh
and test_go_interop.sh cover classical/RNL algorithms only), which is how this went
unnoticed.  Fix should add a `test_stern_interop.sh` with the 6-direction matrix.

Status: **DONE v1.9.36**

---

### 101. Go suite demo file lags behind C/Python — missing HSKE-NL-AEAD and HDRBG demo blocks (Consistency, Small)

**Discovered:** cross-language consistency audit, 2026-06-14.

**Version gap:** `Herradura cryptographic suite.go` is at v1.8.8; C and Python suites are at v1.9.16.  The Go *package* (`herradura/herradura.go`) implements and tests HSKE-NL-AEAD (TODO #95) and HDRBG (TODO #96), but neither appears as a demo block in the `main()` of the Go suite file.  C and Python both show these demo sections.

**Missing demo blocks** (add to `Herradura cryptographic suite.go` `main()`, immediately after the existing HDRBG TODO #96 note or at the matching position relative to C/Python):
1. `--- HSKE-NL-AEAD` — call `HskeNlAeadEncrypt` / `HskeNlAeadDecrypt` and print the outcome (mirror the C `--- HSKE-NL-AEAD` block in `Herradura cryptographic suite.c`).
2. `--- HDRBG` — seed, generate a few outputs, reseed, generate again (mirror the C `--- HDRBG` block).

**Acceptance:** both blocks print correctly; `go vet` and `go build` pass; version banner bumped to match the current suite version.

Status: **DONE v1.9.40**

---

### 102. HPKS-WOTS-F / HPKS-XMSS-F missing from C and Go (Consistency, Medium)

**Discovered:** cross-language consistency audit, 2026-06-14.

**Current state:** TODO #97 added HPKS-WOTS-F and HPKS-XMSS-F to the Python suite (v1.9.39).  Neither C (`herradura.h`) nor Go (`herradura/herradura.go`) have the implementation.

**Work items:**
1. Port `hpks_wots_f_*` functions to `herradura.h` (C).  The Python reference is at `Herradura cryptographic suite.py` lines 1706+.  Parameters: `_WOTS_W = 16`, `_WOTS_LOG2W = 4`, chain length `n / log2(W)`, hash `h(x) = nl_fscx_revolve_v1(ROL(x, n/8), x, n/4)`.
2. Port `hpks_xmss_f_*` (Merkle tree keygen + sign + verify) to `herradura.h`.
3. Mirror both in Go (`herradura/herradura.go`), following existing Go naming conventions.
4. Add demo blocks to `Herradura cryptographic suite.c` and `Herradura cryptographic suite.go` `main()`.
5. Add test cases to `CryptosuiteTests/Herradura_tests.c` and `CryptosuiteTests/Herradura_tests.go`.

**Assembly/Arduino scope:** out of scope — the WOTS chain length and Merkle tree are too large for the 32-bit demo targets.

**Note on Python:** The Python suite already had HPKS-WOTS-F / HPKS-XMSS-F from TODO #97 (v1.9.39). This TODO adds the missing C, Go, and test-file coverage.

Status: **DONE v1.9.42**

---

### 103. ZKP-NL missing from ARM Thumb-2 and NASM i386 targets (Consistency, Small)

**Discovered:** cross-language consistency audit, 2026-06-14.

**Current state:** ZKP-NL (n=8, R=4 rounds) is implemented in C, Go, Python, and Arduino.  The ARM Thumb-2 (`Herradura cryptographic suite.s`) and NASM i386 (`Herradura cryptographic suite.asm`) suite files and their test files do not include it.

**Work items:**
1. Add `zkp_nl_prove` / `zkp_nl_verify` routines to `Herradura cryptographic suite.s` (ARM, n=8, R=4 — matching Arduino).
2. Add the same routines to `Herradura cryptographic suite.asm` (NASM i386).
3. Add a `[asm-14]` test in `CryptosuiteTests/Herradura_tests.s` and `CryptosuiteTests/Herradura_tests.asm`.

**Reference:** Arduino implementation in `Herradura cryptographic suite.ino`; C reference in `herradura.h` (`nl_zkp_prove` / `nl_zkp_verify`).

Status: **DONE v1.9.40**

---

### 104. FPE, Tweakable cipher, and Accumulator (#78.A/B/J) missing from ARM and NASM targets (Consistency, Medium)

**Discovered:** cross-language consistency audit, 2026-06-14.

**Current state:** all three constructions (Format-Preserving Encryption #78.A, Tweakable block cipher #78.B, HFSCX-256-based Merkle accumulator #78.J) are implemented in C, Go, Python, and Arduino (32-bit).  The ARM Thumb-2 and NASM i386 suite files do not include them.

**Work items:**
1. Port FPE (#78.A, 32-bit) to ARM Thumb-2 (`Herradura cryptographic suite.s`) and NASM i386 (`Herradura cryptographic suite.asm`).  Reference: Arduino `Herradura cryptographic suite.ino` (32-bit version).
2. Port Tweakable cipher (#78.B, 32-bit) to both assembly targets.
3. Port Accumulator (#78.J, 32-bit) to both assembly targets.
4. Add demo calls for each in ARM/NASM `main` sections.
5. Add tests `[asm-15]`, `[asm-16]`, `[asm-17]` to `CryptosuiteTests/Herradura_tests.s` and `CryptosuiteTests/Herradura_tests.asm`.

**Note:** HFSCX-256 (#78.J's Merkle hash) is inherently 256-bit; the Arduino/32-bit accumulator demo uses it at full 256-bit width internally — the assembly port should do the same.

Status: **DONE v1.9.41**

---

### 105. ZKP-RNL n-size inconsistency: C uses n=256, Go/Python/ASM use n=32 in demos (Consistency, Small)

**Discovered:** cross-language consistency audit, 2026-06-14.

**Current state:** `Herradura cryptographic suite.c` runs ZKP-RNL at n=256 (matching KEYBITS).  `Herradura cryptographic suite.go` (line 300) and the Python suite run it at n=32, labelled "n=32".  ARM/NASM suite demos use n=32.  None of the assembly test files include a dedicated ZKP-RNL test assertion.

**Work items:**
1. Decide the canonical demo size: either align all high-level suite demos to n=256 (to match C) or add an `n=32` note to the C demo for transparency.  Recommended: promote Go and Python to n=256 (one additional revolve call, negligible perf impact) so all three high-level implementations run identical parameters.
2. Add a `[asm-14]` (or next available number after TODO #103) dedicated ZKP-RNL test assertion to `CryptosuiteTests/Herradura_tests.s` and `CryptosuiteTests/Herradura_tests.asm` (both currently run ZKP-RNL in the demo flow but have no test file assertion).

Status: **DONE v1.9.40**

---

### 106. CLI multi-party threshold signature capability for files (CLI Extension, Medium)

**Discovered:** TODO #98 implementation plan, 2026-06-14.

**Goal:** Extend `HerraduraCli/` (Python, C, Go) to support n-of-n threshold (HPKS-T) signing and verification of files, following the same PEM wire format as single-party `sign`/`verify`.

**Design:**

The threshold workflow is a 3-phase protocol over files:

1. **Phase 1 — Commitment round** (`sign --threshold commit`):
   - Each signer generates a fresh nonce k_j, computes R_j = g^{k_j}, writes a "commitment PEM" (`HPKST COMMITMENT`).
   - Output: `{signer}_commit.pem` containing R_j (public nonce) and the signer's public key C_j.
   - Private nonce k_j is saved to `{signer}_nonce.pem` (`HPKST NONCE`, kept secret, deleted after signing).

2. **Phase 2 — Aggregation** (`sign --threshold aggregate`):
   - A coordinator collects all commitment PEMs and the file to sign.
   - Computes R = Π R_j, C_agg = Π C_j^{μ_j}, e = NL-FSCX(R, msg_hash).
   - Broadcasts an "aggregate PEM" (`HPKST AGGREGATE`) containing R, C_agg, e to all signers.

3. **Phase 3 — Response round** (`sign --threshold respond`):
   - Each signer reads aggregate PEM and their nonce PEM, computes s_j = (k_j − a_j·μ_j·e) mod ord.
   - Writes a "partial signature PEM" (`HPKST PARTIAL`).

4. **Final — Combine** (`sign --threshold combine`):
   - Coordinator collects all partial PEMs, computes s = Σ s_j mod ord.
   - Writes final signature file (`HPKST SIGNATURE`) containing C_agg, R, s.
   - Identical format to `HPKS SIGNATURE` — can be verified with `verify`.

5. **Verify** (`verify --algo hpks-t`):
   - Reads `HPKST SIGNATURE`, verifies g^s · C_agg^e == R (same as single-party verify).

**Work items:**
1. Define PEM types: `HPKST COMMITMENT`, `HPKST NONCE`, `HPKST AGGREGATE`, `HPKST PARTIAL`, `HPKST SIGNATURE` in `HerraduraCli/herradura_codec.h` and `HerraduraCli/codec.py`.
2. Add `sign --threshold commit/aggregate/respond/combine` subcommand flow to Python CLI (`HerraduraCli/herradura.py`).
3. Add same to C CLI (`HerraduraCli/herradura_cli.c`).
4. Add same to Go CLI (`HerraduraCli/herradura_cli.go`).
5. Add CLI integration tests to `CliTest/test_threshold_sign.sh` and `CliTest/test_threshold_interop.sh` (cross-language: Python commits + Go responds + C combines).
6. Document in `docs/TUTORIAL.md` under a new "Threshold Signing" section.

**Note:** The `hpkst_sign`/`HpkstSign` library functions perform all rounds internally (for demos/tests). The CLI must expose the individual rounds so that different parties can run different phases on different machines.

Status: **DONE v1.9.44**

---

### 107. Tutorial gap: HPKS-NL and HPKE-NL have no code examples (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** Both `HPKS-NL` and `HPKE-NL` appear in the protocol table at the top of `docs/TUTORIAL.md` and in the NL/PQC protocol reference table (§"NL/PQC protocols"), but neither has a code snippet in the C, Go, or Python integration sections.  A reader cannot use either protocol from the docs alone.

**Work items:**
1. Add `### HPKS-NL Schnorr signature (NL/PQC)` subsection to C, Go, and Python integration sections with minimal sign/verify snippets using the NL-FSCX challenge.
2. Add `### HPKE-NL El Gamal encryption (NL/PQC)` subsection to C, Go, and Python integration sections with encrypt/decrypt snippets.
3. Note in each snippet that the public key is still a GF(2^256)* element (same as HPKS/HPKE) and that only the symmetric sub-protocol is hardened.

**Reference:** `herradura.h` (`hpks_nl_sign`, `hpks_nl_verify`, `hpke_nl_encrypt`, `hpke_nl_decrypt`), Go equivalents, Python equivalents.

Status: **DONE v1.9.55**

---

### 108. Tutorial gap: HSKE-NL-A2 missing from C and Go sections (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The Python integration section has a `### HSKE-NL-A2 symmetric encryption (NL/PQC)` subsection with an encrypt/decrypt snippet.  The C and Go integration sections have no equivalent subsection despite `nl_fscx_revolve_v2` / `nl_fscx_revolve_v2_inv` being present in both `herradura.h` and `herradura.go`.

**Work items:**
1. Add `### HSKE-NL-A2 symmetric encryption (NL/PQC)` to the C integration section.
2. Add the same subsection to the Go integration section.

**Reference:** Python snippet at `docs/TUTORIAL.md` line 484; `herradura.h` `nl_fscx_revolve_v2` / `nl_fscx_revolve_v2_inv`.

Status: **DONE v1.9.53**

---

### 109. Tutorial gap: HSKE-NL-AEAD entirely absent (Documentation, Medium)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** `hske_nl_aead_encrypt`/`hske_nl_aead_decrypt` were added in v1.9.33 (TODO #95) to C, Go, and Python as the recommended authenticated encryption mode.  The tutorial has no mention of HSKE-NL-AEAD anywhere — no subsection, no CLI example, no entry in the protocol table or parameter reference.

**Work items:**
1. Add `### HSKE-NL-AEAD authenticated encryption (NL/PQC)` to C, Go, and Python integration sections with encrypt/decrypt snippets showing AAD and nonce usage.
2. Add `HSKE-NL-AEAD` to the NL/PQC protocol reference table.
3. Add a CLI usage block showing `--aead` flag with `enc`/`dec` subcommands.
4. Add a security note distinguishing AEAD from the unauthenticated A1/A2 modes.

Status: **DONE v1.9.54**

---

### 110. Tutorial gap: HDRBG (forward-secure DRBG) entirely absent (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** `drbg_seed`/`drbg_generate`/`drbg_reseed` were added in v1.9.34 (TODO #96).  The tutorial has no mention of HDRBG — no subsection, no use-case guidance, no note that it can substitute for `/dev/urandom` in constrained or deterministic-test contexts.

**Work items:**
1. Add a `### HDRBG (forward-secure DRBG)` subsection to the C and Python integration sections (and Go if implemented) showing seed/generate/reseed usage.
2. Add a note in the C integration intro that HDRBG can be used instead of `FILE *urnd = fopen("/dev/urandom", "rb")` when `/dev/urandom` is unavailable (e.g. embedded targets).

**Reference:** `herradura.h` `drbg_seed`, `drbg_generate`, `drbg_reseed`; Python equivalents in the suite file.

Status: **DONE v1.9.59**

---

### 111. Tutorial gap: HPKS-WOTS-F and HPKS-XMSS-F entirely absent (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** Hash-based stateful signatures (`hpks_wots_f_sign`, `hpks_xmss_f_sign`, and their verify counterparts) were added in TODO #97 (v1.9.39) for Python and TODO #102 (v1.9.42) for C and Go.  The tutorial has no mention of either construction.

**Work items:**
1. Add a `### HPKS-WOTS-F / HPKS-XMSS-F (hash-based stateful signature)` subsection to C, Go, and Python integration sections with keygen/sign/verify snippets.
2. Add both constructions to the code-based PQC protocol reference table (or create a new "Hash-based PQC" table row).
3. Include a security note on statefulness: a WOTS-F key must never be used twice; XMSS-F tracks the leaf index and is the recommended multi-use variant.

Status: **DONE v1.9.60**

---

### 112. Tutorial gap: no CLI quickstart for classical protocols (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The ZKP, OPRF/aPAKE, and Threshold sections all include CLI usage blocks, but the C/Go/Python integration sections for HKEX-GF, HSKE, HPKS, and HPKE show only library-API snippets.  A first-time user wanting to test key exchange or signing from the command line must infer the subcommand names from the CLI source code.

**Work items:**
1. Add a `### CLI quickstart` subsection to the C integration section (or a top-level `## CLI quickstart` section before the language sections) demonstrating: `genpkey`, `pkey --pubout`, `kex`, `sign`, `verify`, `enc`, `dec` for the classical protocols using the Python CLI (simplest for getting started).
2. Note that the C and Go CLIs accept identical subcommands.
3. Cross-reference `CliTest/` integration test scripts for further examples.

Status: **DONE v1.9.52**

---

### 113. Tutorial gap: Go section skips HPKS and HPKE examples (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The C integration section has `### HPKS Schnorr signature (classical)` and `### HPKE El Gamal encryption (classical)` subsections.  The Go integration section skips from `### HSKE symmetric encryption (classical)` directly to `### HSKE-NL-A1 counter-mode encryption (NL/PQC)`, leaving HPKS and HPKE undocumented for Go.

**Work items:**
1. Add `### HPKS Schnorr signature (classical)` and `### HPKE El Gamal encryption (classical)` subsections to the Go integration section, mirroring the C section structure.

Status: **DONE v1.9.51**

---

### 114. Tutorial bug: Go OPRF example uses wrong import path (Documentation/Bug, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The Go OPRF snippet at `docs/TUTORIAL.md` (OPRF section, Go integration) begins with `import "herradurakex"` and calls `herradurakex.OprfKeygen(256)`.  Every other Go snippet in the tutorial imports `"herradurakex/herradura"` (the `herradura` package).  The OPRF functions (`OprfKeygen`, `OprfBlind`, `OprfEval`, `OprfUnblind`, `OprfDirect`) live in the `herradura` package, not the root module, so this import is incorrect.

**Work items:**
1. Fix the import in the Go OPRF snippet to `import h "herradurakex/herradura"` and update the call sites to use the `h.` prefix (or dot-import), consistent with the rest of the Go section.
2. Verify the corrected snippet compiles against the actual Go package.

Status: **DONE v1.9.50**

---

### 115. Tutorial gap: threshold signing library API not documented (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The Threshold Signing section (`## Threshold Signing (HPKS-T)`) covers only the CLI workflow (4-phase `threshold-commit/aggregate/respond/combine`).  The library functions that allow embedding threshold signing in C/Go/Python code (e.g. `hpkst_commit`, `hpkst_aggregate`, `hpkst_respond`, `hpkst_combine` or the all-in-one `hpkst_sign`) are not shown.

**Work items:**
1. Add a `### Library API` subsection to the Threshold Signing section with C, Go, and Python code snippets showing the per-round function calls.
2. Note which functions are "all-in-one" (for demos/tests) vs. which expose individual rounds (for multi-party scenarios).

Status: **DONE v1.9.57**

---

### 116. Tutorial gap: aPAKE C and Go library API not documented (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** The aPAKE CLI usage section notes "The C and Go CLIs support OPRF but not the full aPAKE registration/login flow."  However, `HpakeRecord`, `HpakeRegister`, and `HpakeLoginDemo` were added to both `herradura.h` and `herradura.go` as part of TODO #80 batch 4.  The tutorial Python library section documents `hpake_register`/`hpake_login_demo`; there are no equivalent C or Go snippets.

**Work items:**
1. Add C snippet for `hpake_register` / `hpake_login_demo` to the C integration section (or to the aPAKE section alongside the Python example).
2. Add Go snippet for `HpakeRegister` / `HpakeLoginDemo` to the Go integration section.
3. Update the aPAKE CLI note to clarify that the library API is available in all three languages even though the CLI flow is Python-only.

Status: **DONE v1.9.56**

---

### 117. Tutorial gap: HPKE-Stern-F not documented (Documentation, Small)

**Discovered:** tutorial review, 2026-06-15.

**Current state:** `HPKE-Stern-F` appears in the code-based PQC reference table with `Status: Demo only; decap requires QC-MDPC decoder for production`, but has no subsection, no code example, and no CLI usage anywhere in the tutorial.

**Work items:**
1. Add a `### HPKE-Stern-F KEM (code-based PQC, demo)` subsection to the C, Go, and Python integration sections showing keygen, encapsulate, and decapsulate (with a comment that the demo uses a known error vector).
2. Add a security note explaining the QC-MDPC decoder requirement and that the demo should not be used in production.

Status: **DONE v1.9.58**

---

## CLI Capability Review — Suite Features Not Yet Exposed in the CLI — Identified 2026-06-24

A review of suite functionality added since the last CLI extension (TODO #106) against the
`HerraduraCli/` subcommand surface (Python `herradura.py`, C `herradura_cli.c`, Go
`herradura_cli_go`) found four primitives that are fully implemented in the library across
all three CLI languages but have no CLI entry point.  Each item below records the suite API,
the natural CLI surface, and the PEM/wire-format work needed for byte-for-byte cross-language
compatibility (the standing CLI invariant).

---

### 118. CLI: expose HSKE-NL-V2-Duplex single-pass AEAD in `enc`/`dec` (CLI Extension, Medium)

**Discovered:** CLI capability review, 2026-06-24.

**Current state:** the MonkeyDuplex-style single-pass AEAD `hske_nl_v2_duplex_encrypt` /
`hske_nl_v2_duplex_decrypt` (TODO #95 Option 2, v1.9.62) is implemented and byte-for-byte
interoperable in `herradura.h` (C), `Herradura cryptographic suite.py` (Python), and
`herradura/herradura.go` (Go), with demo blocks and round-trip/tamper tests.  The CLI `enc`/`dec`
subcommands support `hske`, `hske-nla1` (with `--aead`), `hske-nla2`, `hpke`, `hpke-nl`, and
`hpke-stern`, but not the V2-Duplex AEAD.

**Goal:** add `enc --algo hske-duplex` and `dec --algo hske-duplex` (with `--ad` associated-data
support), producing a PEM ciphertext object carrying nonce, ciphertext, and 32-byte tag.

**Work items:**
1. Define a PEM/DER ciphertext object (e.g. label `HERRADURA HSKE-DUPLEX CIPHERTEXT`) encoding
   `{nonce (KEYBYTES), ciphertext (variable), tag (32)}`; reuse the existing AEAD codec pattern
   from `hske-nla1 --aead`.
2. Wire `hske-duplex` into the `enc`/`dec` `--algo` choices and dispatch in the Python CLI
   (`cmd_enc`/`cmd_dec`), C CLI, and Go CLI.
3. Require a 256-bit key (as with `hske-nla1 --aead`); error clearly otherwise.
4. Add `CliTest/test_duplex.sh` — round-trip, tamper rejection (ciphertext/tag/AD), and a
   9-way cross-CLI interop matrix (Python/C/Go encrypt × decrypt), mirroring `test_aead.sh`.
5. Document the subcommand in the CLI usage header and `docs/TUTORIAL.md`.

Status: **DONE v1.9.68** — `enc`/`dec --algo hske-duplex` implemented in the Python
(`herradura.py`), C (`herradura_cli.c`), and Go (`herradura_cli_go`) CLIs with `--ad`
support and a 256-bit-key requirement.  New PEM ciphertext format tag 3
(`SEQ(3, nonce, ct_len, ct, tag, nbits)`) stores the variable-length ciphertext
length-prefixed so arbitrary-length plaintext (not just one 32-byte block) is supported.
`CliTest/test_duplex.sh` exercises the 9-way producer/consumer interop matrix, wrong-AD /
wrong-key / mutated-ciphertext rejection, and empty-plaintext round-trip (23/23 pass).
Documented in the three CLI usage headers and `docs/TUTORIAL.md`.

---

### 119. CLI: `rand` command for HDRBG forward-secure deterministic byte generation (CLI Extension, Medium)

**Discovered:** CLI capability review, 2026-06-24.

**Current state:** the forward-secure DRBG (`drbg_seed` / `drbg_generate` / `drbg_reseed`,
TODO #96, v1.9.34) is implemented in all three CLI languages (`drbg_generate` in C and Go,
`drbg_seed`/`generate`/`reseed` in Python) but has no CLI entry point.  There is no way to
generate deterministic random bytes from a seed via the CLI.

**Goal:** add a `rand` subcommand that seeds an HDRBG from a file/PEM seed and emits a requested
number of deterministic bytes, with optional reseed.

**Work items:**
1. Add `rand --seed <file> --bytes N [--personalization STR] [--out FILE]` to the Python, C, and
   Go CLIs; default output is raw bytes to stdout (or `--out` file), with a `--hex` option.
2. Define an optional persistent DRBG-state PEM object (e.g. `HERRADURA HDRBG STATE`) so a
   caller can checkpoint and resume a stream across invocations; include a `--reseed <file>`
   flag that folds new entropy into a saved state.
3. Ensure identical seed + personalization + byte count produces byte-identical output across
   the three CLIs (cross-language KAT).
4. Add `CliTest/test_rand.sh` — determinism, cross-CLI KAT, reseed-changes-stream, and
   distinct-personalization-separation checks.
5. Document the subcommand and note it is a deterministic DRBG (not an OS entropy source).

Status: **DONE v1.9.69** — `rand` subcommand added to the Python (`herradura.py`), C
(`herradura_cli.c`), and Go (`herradura_cli_go`) CLIs:
`rand (--seed FILE | --state FILE) [--personalization STR] [--reseed FILE] [--bytes N]
[--hex] [--out FILE]`.  Output defaults to raw bytes on stdout; `--hex` hex-encodes.
A `HERRADURA HDRBG STATE` PEM (`SEQ(state[32], blocks)`) checkpoints/resumes the DRBG
across invocations, and `--reseed` folds fresh entropy into a saved state.  The Go package
gained exported `DrbgState()` / `DrbgFromState()` accessors (the `state` field was
unexported) for state persistence.  `CliTest/test_rand.sh` verifies determinism, 3-language
byte-identical KAT, personalization separation, reseed-changes-stream, and the full 9-way
cross-language state checkpoint/resume matrix (20/20 pass).  Documented in the three CLI
usage headers and `docs/TUTORIAL.md` (with the "deterministic DRBG, not an OS entropy
source" caveat).

---

### 120. CLI: HPKS-WOTS-F one-time signatures in `genpkey`/`sign`/`verify` (CLI Extension, Medium)

**Discovered:** CLI capability review, 2026-06-24.

**Current state:** the many-time XMSS wrapper is already exposed as `sign/verify --algo hpks-xmss`,
but the underlying HPKS-WOTS-F one-time signature primitive (`hpks_wots_keygen` / `hpks_wots_sign`
/ `hpks_wots_verify` / `hpks_wots_recover_pk`, present in C, Go, and Python) has no standalone CLI
surface.  A one-time signature is useful on its own (e.g. constrained-device single-use tokens).

**Goal:** add `genpkey --algo hpks-wots`, `sign --algo hpks-wots`, and `verify --algo hpks-wots`.

**Work items:**
1. Define WOTS-F private/public key PEM objects (master seed + leaf index for the private key;
   the WOTS public-key chain endpoints for the public key).
2. Wire `hpks-wots` into `genpkey`, `sign`, and `verify` `--algo` dispatch in the Python, C, and
   Go CLIs, packing/unpacking the signature (the WOTS chain values) in a shared PEM format.
3. Enforce one-time semantics: refuse to sign twice with the same key (track/burn the leaf index,
   as the XMSS CLI does with its index file), with a clear error on reuse.
4. Add `CliTest/test_wots.sh` — keygen, sign/verify round-trip, reuse-refusal, tamper rejection,
   and cross-CLI interop (Python sign → C/Go verify and vice versa).
5. Document the one-time constraint prominently in the CLI help and `docs/TUTORIAL.md`.

Status: **DONE v1.9.70** — `genpkey`/`sign`/`verify --algo hpks-wots` added to the Python
(`herradura.py`), C (`herradura_cli.c`), and Go (`herradura_cli_go`) CLIs.  New PEM objects
`HERRADURA HPKS-WOTS PRIVATE KEY` (`SEQ(seed[32], leaf_idx)`),
`… PUBLIC KEY` and `… SIGNATURE` (`SEQ(blob[ℓ·32], ℓ)`), byte-for-byte interoperable.
One-time use is enforced via a `<key>.idx` burn file (0=unused, 1=burned); a second sign
is refused with a clear error.  WOTS signs the full message (hashed internally), bypassing
the single-block truncation used by the other sign algos.  `CliTest/test_wots.sh` covers the
9-way sign/verify interop matrix, per-language reuse refusal, tampered-message rejection, and
wrong-public-key rejection (18/18 pass).  Documented in the three CLI usage headers and
`docs/TUTORIAL.md` (with a prominent one-time-reuse warning).

---

### 121. CLI: HPKS-Stern-Ring ring signatures in `sign`/`verify` (CLI Extension, Medium)

**Discovered:** CLI capability review, 2026-06-24.

**Current state:** the code-based ring signature `hpks_stern_ring_sign` / `hpks_stern_ring_verify`
(#78.I) is implemented in the Python and Go suites and exercised by security test [20], but is
**not** present in `herradura.h` (C) and has no CLI surface in any language.  A ring signature lets
one member of an ad-hoc group sign anonymously on behalf of the group.

**Goal:** add `sign --algo hpks-ring` (signer key + a list of ring public-key PEMs) and
`verify --algo hpks-ring` (same ring) to the Python and Go CLIs.

**Work items:**
1. **Dependency:** port `hpks_stern_ring_sign`/`hpks_stern_ring_verify` to `herradura.h` so the C
   CLI can participate; until then, scope the CLI to Python + Go and note the C gap (or split the
   C suite port into its own sub-item).
2. Define a ring-signature PEM object encoding the ring size, the per-member challenge/response
   data, and the key-image/linking tag if applicable.
3. Add a `--ring <pem1,pem2,...>` argument (ordered list of member public keys) to `sign`/`verify`
   and wire `hpks-ring` into the `--algo` dispatch.
4. Add `CliTest/test_ring.sh` — sign-by-member / verify-by-ring success, non-member rejection,
   tamper rejection, and Python↔Go interop.
5. Document the anonymity property and ring-membership semantics in the CLI help and tutorial.

Status: **DONE v1.9.71** — `sign`/`verify --algo hpks-ring` added to the Python, Go, **and**
C CLIs (all three, not just Python+Go).  Work item 1 (C suite port) was already satisfied:
`stern_ring_sign`/`stern_ring_verify` have been in `herradura.h` since v1.9.16 (TODO #78.I)
and pass security test [20] — the TODO's "not present in herradura.h" premise was outdated.
New `HERRADURA HPKS-RING SIGNATURE` PEM: `SEQ(k, rounds, n, blob)` with a member-major /
round-major flat blob (`c0||c1||c2||b||resp_a||resp_b` per entry), byte-for-byte interoperable
across the three CLIs.  `--ring <p0,p1,...>` supplies the ordered member public keys; the signer
(an `hpks-stern` key) is located by seed match and kept hidden.  `CliTest/test_ring.sh` covers
the 9-way sign/verify interop matrix, anonymity (any member signs), non-member sign refusal,
tampered-message rejection, and wrong-ring rejection (21/21 pass).  Documented in the three CLI
usage headers and `docs/TUTORIAL.md` (anonymity + demo-parameter caveat).

---

## Open Research Items (2026-07-03)

---

### 122. ZKB++ optimized MPC-in-the-head for NL-FSCX ZKBoo (Research/Feature, High)

**Background:** `SecurityProofs-3.md` §11.10.6 open direction 3 (scoped v1.9.66) gives a
first-principles size accounting showing that Chase et al. 2017's ZKB++ decomposition reduces
the n=256 ZKBoo proof from 920 KB to approximately **457 KB** (2.0× reduction).  The gain is
smaller than the generic 5× because the NL-FSCX circuit is AND-gate-broadcast-dominated: the
carry-chain circuit contributes $O(n^2)$ AND gates, so only the $2\times{\to}1\times$
online-party term in ZKB++ helps.  Reaching the ~180 KB target (the SPHINCS+/Picnic range)
additionally requires cutting the AND-gate count — which means a sparse LowMC-like circuit
variant of NL-FSCX v1.

**Work items:**

1. **Implement ZKB++ encoding** for the existing ZKBoo circuit in `SecurityProofsCode/zkp_pqc_exploration.py` §3.7 and the Python suite `hpks_zkp_nl_sign`/`hpks_zkp_nl_verify`. The ZKBoo circuit already separates AND gates from XOR/linear gates; ZKB++ replaces the 3-party view with a 2-party online + 1-party offline share and eliminates one of the three per-gate broadcasts.
2. **Verify the 457 KB estimate** empirically at n=256 by benchmarking the new encoding vs. the current ZKBoo implementation.
3. **Design a sparse NL-FSCX v1 circuit** to reduce the AND-gate count toward the LowMC-like range: explore reducing the carry-chain to a fixed-depth approximation (trading algebraic degree for circuit size), or substituting the full adder with a 2-input gate that preserves the OWF hardness argument (Theorem 13).
4. **Characterize the security impact** of any circuit approximation: verify that Theorem 13 (degree-saturation) still holds for the modified circuit; add analysis to `SecurityProofs-2.md` §11.8.2.

**References:** Chase et al. 2017 (ZKB++, CCS 2017); Giacomelli et al. 2016 (ZKBoo, USENIX Security 2016); Albrecht et al. 2016 (LowMC).

Status: **OPEN**

---

### 123. Hybrid Ring-LWR + Stern-F credential: resolve the binding map φ (Research, High)

**Background:** `SecurityProofs-3.md` §11.10.8 gives a complete design sketch for an AND-composed
ZKP that proves "I hold a Ring-LWR private key $s$ matching public key $C$ AND a code-based
credential bound to $s$" — combining the §11.10.2 Ring-LWR Σ-protocol with HPKS-Stern-F under
a single Fiat-Shamir challenge, with estimated proof size ~80 KB (Stern-F-dominated, 1 KB
Ring-LWR + 78 KB Stern-F + ~1 KB binding gadget).  The scheme is fully specified except for the
binding map φ: a function from the ternary ring secret s ∈ {-1,0,1}^n to a fixed-weight binary
word e ∈ {0,1}^N with wt(e) = t_S, accompanied by a cheap zero-knowledge gadget proving
φ(s) = e without revealing s.

**The open problem (from §11.10.8):** a sound ZK gadget for "committed ternary ring element s
maps to committed fixed-weight binary word e = φ(s)" requires either (a) an arithmetic-circuit
proof of the bit-decomposition (expensive: adds O(n log n) AND gates), or (b) a φ that makes
the relation linear over a common ring (highly restrictive — the two relations live in different
algebras, Z_q[x]/(x^n+1) vs F_2^N).

**Work items:**

1. **Survey commitment-compatible binding maps.** Examine whether BDLOP-style lattice
   commitments can bind s and e simultaneously in a common ring, or whether a hash commitment
   with an arithmetic-circuit gadget is the only sound option.
2. **Quantify the circuit cost** of the bit-decomposition gadget at n=256, t_S=16 (the deployed
   Stern-F parameters): estimate the AND-gate count increase and the resulting proof-size blowup.
3. **Prototype the simplest sound φ** (e.g. take the positive-support bitmap of s: φ(s)_i = 1 iff
   s_i > 0, giving wt(φ(s)) = wt_+(s) which is not fixed but bounded) and characterize the
   soundness error from the non-fixed weight.
4. **Promote to implementation** once a φ with acceptable gadget cost is found; add to CLI as
   a new proof type (e.g. `sign --algo hybrid-rlwr-stern`).

**References:** §11.10.8 design sketch; BDLOP (Baum et al. 2018, SCN 2018); Lyubashevsky 2012
(Eurocrypt 2012).

Status: **DONE v1.9.73** — resolved by `SecurityProofsCode/hybrid_credential_phi.py` and
`SecurityProofs-3.md` §11.10.9.  The §11.10.8 dichotomy was a false choice: φ_A(s)_i = [s_i = +1]
(positive-support bitmap) makes the binding relation algebraic of degree ≤ 3 over Z_q —
s_i³ = s_i and e_i = (s_i²+s_i)/2 — 512 multiplication gates at n=256, no bit decomposition.
Work items: (1) survey done — candidates A/B/C/D analysed, A selected; (2) gadget cost
quantified — BDLOP ≈ 2 KB, KKW ≈ 40 KB (hash-only, recommended), boolean-PRF route 1.8 MB
rejected; (3) φ_A prototyped as a ZKBoo-(2,3) MPCitH gadget over Z_q — completeness 30/30,
cheats rejected 500/500, corrupted-view survival matches (1/3)^R; the non-fixed weight
(w ≈ 64, leak 4.84 bits = 1.3%) is characterised, and a NEW finding — self-registered-key
forgery in the many-solutions regime (≈ 2^75.6 solutions, ≈ 2^3.8 effective Prange) —
requires the credential to be an issuer signature over (C, y) (zero cost) or the φ_D
fixed-weight variant (≈ 5.5× gadget).  (4) Implementation promotion split off as TODO #128.

---

### 128. Implement the hybrid Ring-LWR + Stern-F credential (compound prover/verifier + CLI) (Feature, Medium)

**Background:** TODO #123 resolved the binding map φ for the §11.10.8 hybrid credential
(see `SecurityProofs-3.md` §11.10.9): φ_A = positive-support bitmap, binding gadget =
512 Z_q multiplication gates, recommended proof system = KKW 64-party MPC-in-the-head
(hash-only, ≈ 40 KB) with the credential issued as an issuer signature over (C, y).
This item tracks promotion from research prototype to suite implementation.

**Batch plan (revised after Batch 1; design refinements in `SecurityProofs-3.md` §11.10.10):**

- **Batch 1 — Python suite library + demo (shipped v1.9.74).**  `hcred_phi`,
  `hcred_user_keygen`, `hcred_syndrome`, `hcred_issue`, `hcred_cred_verify`,
  `hcred_prove`, `hcred_verify` + suite demo block (n=32, R=4).  Two design
  refinements vs the original sketch: (a) e = φ(s) must stay SECRET in a
  presentation, so the φ-gadget and syndrome check are merged into one
  ZKBoo-(2,3) MPCitH circuit over Z_q with internal e-wires and per-row
  bit-decomposition witness bits for the mod-2 reduction — this removes the
  standalone Stern branch and its linkable-commitment gadget; (b) sequential
  FS binding (branch-1 challenge binds branch-2 commitments and vice versa)
  with the issuer's Stern-F signature over H(m‖C‖seed_H‖y) as the anchor.
  Verified: completeness 20/20; replay/wrong-syndrome/wrong-key/tamper/
  overweight all rejected.
- **Batch 2 — unified circuit: same-s linkage without BDLOP (shipped v1.9.75).**
  The Ring-LWR relation moved inside the MPCitH circuit: m·s is linear in the
  s-wires (m public), so C = round_p(m·s) costs only 5 rounding-error witness
  bits per coefficient (δ² = δ; [m·s]_i − Σ2^t·δ = lift(C)_i − 16; honest
  |ε| ≤ 8, relaxed bound 15).  The separate ZKP-RNL branch is removed — one
  proof, one witness, same-s linkage BY CONSTRUCTION; BDLOP is no longer
  needed.  Circuit: 2n + (n/2)⌈log₂(n+1)⌉ + 5n mult gates (4224 at n=256).
  Verified: completeness 20/20 + n=256 end-to-end; split-witness prove
  attempts (s₂ vs y₁, s₁ vs C₂) refused.  Note: shipping only the unopened
  party's outputs was evaluated and is UNSOUND (FS must bind all three
  output-share sets pre-challenge) — KKW is the only sound size path.
- **Batch 3 — KKW transcript encoding (shipped v1.9.76).**
  `hcred_prove_kkw`/`hcred_verify_kkw`: N-party preprocessing MPCitH with
  per-emulation seed trees, cut-and-choose over M emulations (opened roots
  force aux honesty), one FS-hidden party per online emulation, and a
  batched output check (one FS-ρ linear combination → one mask share per
  party; +1/q ≈ 2^-16 escape, negligible vs 1/N).  Production (N,M,τ) =
  (64,343,27) → 2^-128 (Picnic2 set); demo (4,8,4).  HONEST SIZE REVISION:
  the #123 "≈40 KB (20×)" figure was for the pre-unification 512-gate
  gadget; at the 4224-gate unified circuit KKW ≈ 0.9 MB at production
  parameters ≈ 11× under ZKBoo (9.2 MB); demo-scale measured 11.7 KB vs
  18.9 KB.  Further size cuts need a circuit-level change (fewer mult
  gates), not transcript work.  Tamper battery (7 classes) + completeness
  verified.
- **Batch 4 — C (`herradura.h`) and Go ports** + unified security test added
  to all three test files simultaneously (single-language addition would
  desynchronize the #87 unified test numbering).
- **Batch 5 — Wire format + CLI.**  PEM types for credential and presentation
  proof; `cred-issue`/`cred-prove`/`cred-verify` subcommands; `CliTest/`
  cross-language interop.
- **Batch 6 — Docs.**  TUTORIAL section; INTRODUCTION concepts entry.

Status: **OPEN** — Batches 1–3 shipped in v1.9.74–v1.9.76; Batches 4–6 pending.

---

### 124. NL-FSCX v2 cipher-stream problem (CSP) hardness characterization (Research, Medium)

**Background:** `SecurityProofs-2.md` §11.8.5 (Option C) lists the NL-FSCX v2 Cipher-Stream
Problem — recovering the key K from a sequence of outputs nl_fscx_revolve_v2(P_i, K, r) for
known plaintexts P_i — as an open conjecture.  Unlike NL-FSCX v1 (which has Theorem 13 degree
saturation and the Walsh-spectrum analysis of TODO #35), NL-FSCX v2 has only the MQ-hardness
argument of Theorem 14 (Theorem 14 proves key recovery is an MQ problem; it does not rule out
attacks that exploit v2's structure more deeply).

**Open questions:**

1. **Differential / algebraic analysis of nl_fscx_revolve_v2.** NL-FSCX v2 adds the
   key-dependent offset δ(K) = ROL(K·⌊(K+1)/2⌋ mod 2^n, n/4) at each step. Unlike the v1
   integer-add carry chain, δ(K) depends only on K and not on A — does this fixed-per-key
   structure enable a related-key differential distinguisher?
2. **Inversion feasibility at small n.** At n=8 and n=12, can nl_fscx_revolve_v2 be
   inverted faster than brute force using the Gröbner basis approach (Theorem 14's bound is
   asymptotic; small-n experiments would show the gap)?
3. **CSP vs. OWF comparison.** NL-FSCX v1's OWF hardness (Assumption A2, TODO #74) has
   independent cryptanalysis from the Walsh spectrum scan (TODO #35) and the rotational
   analysis (TODO #75). NL-FSCX v2 has neither. Run the equivalent analyses:
   - Exhaustive Walsh spectrum at n=8/12 for the v2 function.
   - Rotational differential rate at n=32 for v2 (compare to v1's 1–6%).
   - Degree-saturation test for v2 at small n (verify Theorem 14's MQ claim experimentally).
4. **SecurityProofs-2.md §11.8.5 update.** Add a "v2 CSP cryptanalysis status" subsection
   once items 1–3 are complete, analogous to §11.8.3's treatment of v1 OWF assumptions.

**Affected files:** `SecurityProofsCode/nl_fscx_owf_analysis.py` (extend with v2 sections),
`SecurityProofsCode/nl_fscx_rot_analysis.py` (extend with v2 rotational tests),
`SecurityProofs-2.md` §11.8.5.

Status: **OPEN**

---

### 125. Sparse-input rotational differential characterization of NL-FSCX v1 at large n (Research, Medium)

**Background:** `SecurityProofs-2.md` §11.8.2 (Theorem 13 proof, "Open concerns") notes:

> *"(1) Sparse-bit B values exhibit elevated MDP at n=8; large-n behavior is uncharacterised."*

The TODO #75 rotational analysis (`SecurityProofsCode/nl_fscx_rot_analysis.py`) measured
overall rotational-equivariance rates of 1–6% at n=32 across all tested (A, B) pairs
uniformly — but did not isolate the sparse-B regime.  At n=8, exhaustive enumeration in
the Walsh scan (TODO #35) showed max_bias ≈ 1.0 for degenerate (r=2-step) runs, which is
plausibly related to sparse-B degeneracy (low-weight B makes the carry chain short).

**Open questions:**

1. **Sparse-B differential rate at n=32.** In `nl_fscx_rot_analysis.py`, stratify the
   sampled (A, B) pairs by Hamming weight of B and measure the rotational-equivariance
   rate per stratum: wt(B) ∈ {1, 2, 4, 8, 16, 32}. If sparse B elevates the rate beyond
   6%, quantify by how much.
2. **Threshold weight.** Identify the minimum wt(B) at n=32 above which the equivariance
   rate drops to the uniform-B baseline (~1–6%). Document as a safe-use lower bound on B
   density for PRF applications.
3. **Impact on HFSCX-256-DM.** The HFSCX-256-DM compression function uses fixed-key iteration
   F_1^{64}(s, m) with m = message block and s = chaining value. If sparse message blocks
   elevate the rotational rate, adversarial messages could bias the compression output.
   Quantify whether 64 rounds of iteration suppress the sparse-B elevation (and verify
   experimentally at n=32 with wt(m) ∈ {1,2,4}).
4. **Update SecurityProofs-2.md §11.8.2** with the characterization once complete.

**Affected files:** `SecurityProofsCode/nl_fscx_rot_analysis.py` (stratified sparse-B tests),
`SecurityProofs-2.md` §11.8.2 "Open concerns."

Status: **OPEN**

---

### 126. QC-MDPC decoding trapdoor for production HPKE-Stern-F / Niederreiter KEM (Research, High)

**Background:** `SecurityProofs-2.md` §11.8.5 outlines a production path for HPKE-Stern-F's
Niederreiter KEM component:

> *"For efficient decapsulation, e must embed a structured decoding trapdoor. A direct application:
> derive the seed for a quasi-cyclic moderate-density parity-check (QC-MDPC) code (the BIKE design)
> via the NL-FSCX v1 PRF instead of a standard hash. The security argument is unchanged; hardness
> remains quasi-cyclic syndrome decoding."*

The current `hpke_stern_f_decap` uses brute-force search (TODO #33), which is exponential in the
error weight t. At the demo parameters (N=256, t=16) this takes ~seconds; at production parameters
(N≥17000, t≈200 for BIKE-128) it is infeasible without a polynomial-time decoder.

**Work items:**

1. **Survey QC-MDPC decoding algorithms.** Review the BIKE specification (Aragon et al. 2022)
   and the Black-Gray-Flip and BGF-decoder literature; understand the key-equation attack
   mitigations built into BIKE's parameter choices.
2. **Design the NL-FSCX PRF seeding layer.** Instead of a SHA-3 seed as in BIKE, use
   F_1^{n/4}(ROL(seed, n/8), seed) (the HFSCX-256-DM KDF path) to derive the QC-MDPC parity
   check matrix H. Verify that the PRF-seeded H distribution matches the random-looking H
   assumption underlying BIKE's syndrome-decoding hardness claim.
3. **Prototype the decoder** at small parameters (N=512, t=20) in Python using the BGF algorithm;
   measure decapsulation failure rate and compare to BIKE's targets.
4. **Define production parameter sets** consistent with ≥128-bit classical security (BIKE-128 uses
   N≈24646; characterize the NL-FSCX PRF-seeded analog).
5. **Extend CLI `dec --algo hpke-stern`** to call the QC-MDPC decoder when available; document
   the demo-only limitation prominently until production decoder is present.

**References:** BIKE specification v5.2 (Aragon et al. 2022); Tillich-Zemor BGF decoder (2018);
SecurityProofs-2.md §11.8.5 (Option C roadmap).

Status: **OPEN**

---

### 127. Post-deprecation successor group for HKEX-GF, HPKS, and HPKE (Research, Medium)

**Background:** `SecurityProofs-1.md` §9.2.4 documents that NIST SP 800-57 Rev. 5 (2020) and
ENISA (2022) both **deprecate** GF(2^n)* for new designs; at n=256 the best classical attack
(function field sieve) gives only ~80–90 bits, not 128.  HKEX-GF, HPKS, and HPKE are therefore
not suitable for production use at any deployed n.  The suite documents this prominently as a
known limitation and positions these protocols as proof-of-concept / pedagogical constructs.

The research question is: **what is the minimal-change upgrade path** that preserves the suite's
Schnorr-algebra structure (so that HPKS threshold/aggregation from TODO #98 and ring signatures
from TODO #78.I continue to apply) while replacing GF(2^n)* with a group that meets 128-bit
classical and quantum-resistant security margins?

**Candidate groups:**

| Group | Classical hardness | Quantum hardness | Notes |
|---|---|---|---|
| NIST P-256 (secp256r1) | ~128-bit ECDLP | Shor's breaks it | Most familiar; same Schnorr algebra; no suite advantage |
| Ristretto255 (Ed25519 quotient) | ~128-bit ECDLP | Shor's breaks it | Cleaner cofactor handling; same quantum vulnerability |
| GF(2^n)* at larger n (n=4096) | Sub-exponential, ~128-bit at n=4096 | Shor's breaks it | Enormous key sizes; impractical |
| CSIDH / SQIsign | ~64-bit post-quantum | Conjectured quantum-resistant | Different algebra; Schnorr analogy breaks down |

**Work items:**

1. **Evaluate ristretto255 as a drop-in.** The group order is a large prime ℓ ≈ 2^{252}; the
   Schnorr signing equation s = (k − a·e) mod ℓ maps directly onto the existing HPKS structure
   with `ba_mul_mod_ord` replaced by scalar multiplication in ristretto255. Prototype in Python
   using the `ristretto255` library; check that HPKS-Stern-Ring and threshold signing (TODO #98)
   transfer without modification.
2. **Document the migration impact.** List every suite function and PEM field that changes;
   estimate wire-format compatibility with the existing CLI.
3. **Assess post-quantum relevance.** If the goal is a fully PQC suite, elliptic curve groups
   are also broken by Shor's algorithm; document whether the intended use case is
   classical-security-only (ristretto255 fine) or post-quantum (must use HKEX-RNL + Stern-F
   exclusively, no HKEX-GF/HPKS/HPKE upgrade exists).
4. **Add a SecurityProofs-1.md §9.2.5** "Migration path" subsection summarizing the trade-offs.

Status: **OPEN**
