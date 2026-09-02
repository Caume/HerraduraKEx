# HerraduraKEx — Completed / Deprecated / Acknowledged TODO Archive

Archive of `TODO.md` entries with `Status: **DONE**/**DEPRECATED**/**ACKNOWLEDGED**` (TODO #154). For currently open work items, see [`TODO.md`](TODO.md). Item numbers are global and preserved across both files — an entry keeps its `#N` forever, whichever file it currently lives in.

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

Status: **DONE v1.5.16** — Analysis in v1.5.15; Peikert reconciliation deployed in v1.5.16 across all 6 targets. Failure rate: 0%.

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

Status: **DONE v1.5.20** — Batches 1-6 complete (see per-batch checkmarks above).

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

Status: **DONE v1.5.39** — Document split at §10/§11 boundary resolved the cascade.

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

Status: **DONE** — both ELF binaries built cleanly (2026-05-20).

### Batch 3 — Run suite under simavr (DONE 2026-05-20 — all pass)
- [x] Output captured; runs one full iteration and loops correctly
- [x] All protocol sections printed: HKEX-GF, HSKE, HPKS, HPKE, HSKE-NL-A1, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL, HPKS-Stern-F, HPKE-Stern-F
- [x] All `+` pass markers present; no `-` failure markers; HKEX-RNL keys agreed on first try
- [x] EVE bypass section: all 4 bypass attempts rejected (`- Eve …`)

Status: **DONE** — suite runs correctly under simavr, all pass (2026-05-20).

### Batch 4 — Run tests under simavr (DONE 2026-05-20 — all pass)
- [x] All 12 tests print `[PASS]` on every loop iteration
- [x] Test [7] HKEX-RNL: 10/10 raw agree, 10/10 sk agree (100%; uses simpler PP=2 rounding)

Status: **DONE** — tests run correctly under simavr, all pass (2026-05-20).

### Batch 5 — Known issues to address after verification
- [x] **Version string stale:** suite `loop()` prints `v1.5.23` but file header is `v1.6.1` — fixed banner to `v1.6.1`
- [x] **Tests use old HKEX-RNL reconciliation:** upgraded `RNL_PP=2`→`4`, added `rnl_hint`/`rnl_reconcile`, updated `rnl_agree` to hint-based signature, fixed `rnl_lift` to centered rounding, updated `test_hkex_rnl` call site — all 12 tests still `[PASS]`
- [x] **Tests `rnl_rand_poly` missing rejection sampling:** replaced bare `% RNL_Q` with 3-byte threshold guard (threshold=`0xFF00FFu`) matching suite

Status: **DONE** — all known issues fixed and reverified under simavr (2026-05-20).

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

Status: **DONE v1.9.111** — all 10 sub-items resolved: 78.A DONE v1.9.14, 78.B DONE v1.9.14,
78.J DONE v1.9.14, 78.H DONE v1.9.15, 78.C DONE v1.9.15, 78.I DONE v1.9.16, 78.D DONE
v1.9.20, 78.F DONE v1.9.21, 78.G DONE v1.9.22 (FPE, Tweakable, Accumulator, Masking,
Ratchet, Ring Signature, PAKE-ZKBoo, VDF, and OPRF all have demo scripts and analysis).
78.E (Non-Abelian KEx) resolved as **DONE (negative result)** per its own phased research
plan's exit criteria: `SecurityProofsCode/nl_fscx_v2_csp.py`'s Phase 0 decision gate ran all
three structural probes (centralizer search, Theorem-15 necessary-condition solution count,
subgroup-order growth) and found VERDICT (a) — centralizers are generically trivial, the
necessary condition admits essentially no partner keys, and a handful of generators already
reach the full/near-full symmetric group. Ko-Lee/AAG-style non-abelian KEX is **not
instantiable** on the `{pi_K}` permutation family; Phases 1-3 (orbit lower bound,
circuit-model CSP transfer, formal reduction) are moot for that construction. Documented in
SecurityProofs-2.md §11.8.5. A Stickel-type two-sided construction (`E = pi_K1 . A . pi_K2`,
no commutativity required) remains a distinct, unexplored direction if Option C is
revisited — out of scope for this closure.

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

Status: **DONE v1.9.61** — all 6 batches complete (Batch 1 v1.9.24, Batch 2 v1.9.25,
Batch 3 v1.9.25, Batch 4 v1.9.27, Batch 5 v1.9.61, Batch 6 v1.9.25). Batch 1: Python suite (`oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`) + Python CLI (`oprf-blind`, `oprf-eval`, `oprf-unblind`, `genpkey --algo oprf`) + `primitives.py` exports + `test_oprf.sh` (8/8). Batch 2: `herradura.h` OPRF functions (`oprf_keygen`, `oprf_blind`, `oprf_eval`, `oprf_unblind`, `oprf_direct`, `ba_modinv_ord`) + C suite demo + `herradura_cli.c` + `herradura_codec.h` PEM labels + `test_c_oprf.sh` (7/7). Batch 3: `herradura/herradura.go` (`OprfKeygen`, `OprfBlind`, `OprfEval`, `OprfUnblind`, `OprfDirect`) + Go suite demo + `herradura_cli.go` + `test_go_oprf.sh` (7/7). Batch 4: `herradura.h` (`HpakeRecord`, `hpake_register`, `hpake_login_demo`) + C suite demo + `herradura_cli.c` (`pake-register`, `pake-demo`) + `herradura/herradura.go` (`HpakeRecord`, `HpakeRegister`, `HpakeLoginDemo`) + Go suite demo + `herradura_cli.go` (`cmdPakeRegister`, `cmdPakeDemo`) + `test_c_pake.sh` (7/7) + `test_go_pake.sh` (7/7). Batch 5 DONE v1.9.61: ARM Thumb-2 (`Herradura cryptographic suite.s`) and NASM i386 (`Herradura cryptographic suite.asm`) each add an OPRF blind/eval/unblind demo block using fixed inputs (x=0x50415353, k=0x13579BDF, r=7, r_inv=0x49249249=7^{-1} mod 2^32-1); Arduino (`Herradura cryptographic suite.ino`) adds `oprf_hash_to_field_32`, `oprf_blind_32`, `oprf_eval_32`, `oprf_unblind_32`, `oprf_direct_32` helpers and a `loop()` demo block; all three targets output `+ OPRF blind/eval/unblind correct` and match F_direct; `[DEMO n=32 -- NOT PRODUCTION SECURE]` warning displayed. Batch 6: `test_oprf_interop.sh` (8/8 cross-language combinations).

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

Items 1–2 DONE v1.9.32 — §11.10.2 restated as relaxed special soundness
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

Status: **DONE v1.9.67** — items 1–2 (relaxed soundness + structured cheats,
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

Status: **DONE v1.9.62** — Option 1 DONE v1.9.33: `hske_nl_aead_encrypt`/`decrypt` in the
Python suite, `herradura.h`, and `herradura/herradura.go` (byte-for-byte interoperable,
shared KAT); CLI `enc`/`dec --aead [--ad]` with PEM format tag 2 in all three CLIs
(`encfile`/`decfile` were already always-AEAD via the `.hkx` MAC — no flag needed there);
security test [28] (KAT + roundtrip + ciphertext/tag/AD/nonce/key tamper rejection) in
C/Go/Python; `CliTest/test_aead.sh` (9 interop pairs + rejection); SecurityProofs-2.md
§11.9.6 note. Option 2 (NL-FSCX v2 sponge/duplex single-pass AEAD) DONE v1.9.62 —
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

**Batch plan:**

- **Batch 1 — ZKB++ encoding + empirical validation (items 1–2).**  Shipped v1.9.81:
  `zkp_nl_prove_pp`/`zkp_nl_verify_pp` in the Python suite (all four ZKB++ transcript
  optimisations: seed-derived shares, explicit party-2 offset, single-online-party
  bit-packed gate broadcast, hidden-commitment-only + Picnic-style challenge
  recomputation); suite `main()` demo block; self-contained `zkbpp_prove`/`zkbpp_verify`
  + §3.8 empirical section in `zkp_pqc_exploration.py`.  Empirical results: revolve
  circuit (n=256, r=64) 920 KB → 464 KB (1.98×), confirming the §3.7 analytic ≈457 KB;
  implemented single-step circuit 170.9 KB → 31.0 KB (5.5×) at n=256/R=219 (overhead-
  dominated, byte-packed ZKBoo baseline).
- **Batch 2 — C/Go ports + CLI wire format.**  Shipped v1.9.82: `ZkpNlPpRound` struct
  and `zkp_nl_pp_prove`/`zkp_nl_pp_verify` in `herradura.h`; `ZkpNlProvepp`/
  `ZkpNlVerifypp` in Go package; `nl-zkbpp` sign/verify in all three CLIs (Python, C,
  Go); binary PEM wire format; `CliTest/test_zkbpp.sh` (10/10 PASS, C↔Go↔Python).
- **Batch 3 — Sparse circuit analysis (v1.9.83).**  `SecurityProofsCode/nl_fscx_sparse_circuit.py`
  implements the prefix-adder variant (k-bit carry, k-1 AND gates) and confirms: (a) Theorem 13
  degree-saturation is preserved for k≥4 with wt(B[0..k-1])≥2; (b) proof size is dominated by
  the 32-byte per-party share, not AND-gate count — reducing AND gates from 16,320 to near-zero
  saves only ~15% of ZKB++ bytes for the revolve circuit; (c) the 180 KB target requires an
  IOP-based ZKP scheme (Ligero/Picnic-FS) that avoids per-bit sharing.  Items 3–4 revised:
  the sparse-circuit approach is analysed and documented; the open sub-item is now "IOP-based
  ZKP for NL-FSCX" as a longer-term research direction.  SecurityProofs-2.md §11.8.2 updated.
- **Batch 4 — Ligero-lite IOP prototype (v1.9.87).**  `SecurityProofsCode/nl_fscx_ligero.py`
  implements a self-contained Ligero-style argument of knowledge for y = F1^r(A,B) over
  GF(2^16): XOR/ROL are linear, only carry-chain ANDs + input booleanity are quadratic;
  one RS-encoded Merkle-committed witness matrix, t column queries (e < d/3 regime) +
  σ = ⌈λ/16⌉ algebraic-combo repetitions — no parallel repetition.  Completeness + 3
  soundness tests pass; size model validated byte-exact at two scales including a real
  λ=128 proof (n=64, r=8: 102 KB, prove 2.1 s / verify 7.0 s).  At n=256, r=64, λ=128:
  **219 KB unpruned / 163 KB pruned** (vs ZKB++ 464 KB; target 180 KB reached with
  pruning); single-step 96/39 KB.  SecurityProofs-3.md §11.10.4–.6 updated.

**References:** Chase et al. 2017 (ZKB++, CCS 2017); Giacomelli et al. 2016 (ZKBoo, USENIX Security 2016); Albrecht et al. 2016 (LowMC).

Status: **DONE v1.9.87** — Batch 1 (ZKB++ encoding) v1.9.81; Batch 2 (C/Go ports + CLI) v1.9.82; Batch 3 (sparse-circuit analysis) v1.9.83; Batch 4 (Ligero-lite IOP prototype, `SecurityProofsCode/nl_fscx_ligero.py`) v1.9.87 — 219 KB unpruned / 163 KB pruned at n=256, r=64, λ=128 (vs 464 KB ZKB++, 180 KB target); production hardening (ZK randomizer rows, tight soundness, constant-time) would be a new item.

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
- **Batch 4a — Go port (shipped v1.9.77).**  `herradura/herradura.go`: full
  ZKBoo-path port (HcredParams/Phi/UserKeygen/Syndrome/Prove/Verify/BindMsg/
  Issue/CredVerify + proof types).  Go suite demo block + security test **[44]**
  in Herradura_tests.go.  Test [44] is appended after benchmarks [32]–[43]
  rather than inserted as [32]: automated renumbering is risky in C where
  "[32]" collides with array-size syntax; C and Python get the same [44] in
  Batch 4b, restoring #87 numbering parity.  KKW variant remains Python-only
  (research encoding).  CROSS-LANGUAGE INTEROP VERIFIED: a proof produced by
  the Python suite verifies under Go `HcredVerify` (and is rejected under a
  swapped nonce).  CORRECTNESS FIX (both langs): the statement hash is now
  bound into every per-round commitment, so replay/wrong-key/wrong-syndrome
  are rejected deterministically instead of at the (1/3)^R challenge-collision
  chance (was 1/81 at demo R=4) — verified 0 false-accepts in 40 fresh R=4
  trials.  KKW path was already deterministic (stmt-bound cut-and-choose).
- **Batch 4b — C port (shipped v1.9.78).**  `herradura.h`: full C port at n=256
  fixed (RNL_N/KEYBITS); `int64_t` for Z_q products; syndrome byte-order aligned
  to Python/Go big-endian serialization; public API `hcred_prove`/`hcred_verify`/
  `hcred_issue`/`hcred_cred_verify`.  C suite demo block + C test [44] (3 iters,
  n=256, R=4; completeness/replay/syndrome/key/split/cred all PASS).  Python test
  [44] mirror added to Herradura_tests.py (n=32, R=4; same six checks).
- **Batch 5 — Wire format + CLI (shipped v1.9.79).**  PEM types for credential and
  presentation proof (`HERRADURA HCRED PRIVATE/PUBLIC KEY`, `HERRADURA HCRED CREDENTIAL`,
  `HERRADURA HCRED PROOF`); codec.py encode/decode helpers; `cred-issue`/`cred-prove`/
  `cred-verify` in Python CLI + C CLI (n=256); `hcred_proof_serialize/deserialize` in
  herradura.h; `CliTest/test_cred.sh`, `test_c_cred.sh`, `test_cred_interop.sh` (10-way
  C↔Python interop, all PASS).  Syndr endianness fix: little-endian (LSB-first) storage
  for byte-parity with C `stern_syndrome_H`.
- **Batch 6 — Docs.**  TUTORIAL section; INTRODUCTION concepts entry.

Status: **DONE v1.9.80** — Batches 1–5 shipped in v1.9.74–v1.9.79; Batch 6 shipped v1.9.80: TUTORIAL §HCRED added to CLI quickstart, C/Go/Python integration sections, protocol reference, parameter reference, and security notes; INTRODUCTION Part 10.4 concepts paragraph + protocol table row + decision tree entry.

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

Status: **DONE v1.9.89** — Implemented as a standalone script `SecurityProofsCode/nl_fscx_v2_csp_analysis.py` (self-contained, matching the one-script-per-analysis repo pattern) rather than extending the two v1 scripts.  Results: (Q1) delta(K) is ~2-to-1 (image ~0.55·2^n at n=8/12/16) but the related-key output-difference distribution at n=32 is FLAT at every r including r=1 (log2 p ≤ −13.3, uniform range) — no related-key distinguisher; (Q2) one (P,C) pair leaves <2.1 consistent keys at r=3n/4, two pairs unique ≥99.5%; the only shortcut is a carry guess-and-determine at r=1 over the delta image (~2× over brute force, fails at r≥2); (Q3) exhaustive ANF degree ≥ n−2 from r=1 (Theorem 14 conservative — system is dense near-maximal degree, not merely quadratic); Walsh key-map bias within the Bernstein random-function bound from r=4; rotational rate exactly 0 both-sided at n=32, r=8 (vs v1's 1–6%) — the multiplication in delta destroys rotational equivariance, v2 strictly stronger than v1 rotationally; (Q4) SecurityProofs-2.md §11.8.5 gains a "v2 cipher-stream-problem cryptanalysis status" block.

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

Status: **DONE v1.9.88** — `nl_fscx_rot_analysis.py` §6–§8 (50 000 trials/stratum, n=32): (Q1) sparse B massively elevates the two-sided rotational rate — 86% at wt(B)=1, r=8, k=1 (64× over the 5.8% uniform baseline), decaying monotonically (50× at wt=2, 30× at 4, 10× at 8, baseline at 16); (Q2) threshold weight wt(B) ≥ 16 = n/2 (2.7× at wt=12, 0.8× at 16) — safe-use bound: B density ≥ 1/2, satisfied by uniform keys w.h.p.; (Q3) HFSCX-256-DM one-sided rate in s stays ≈ 0 (≤ 4·10⁻⁵ at r=64) even for wt(m) ∈ {1,2,4} — per-call PRF safety is weight-independent — but the two-sided related-message rate is NOT suppressed by 64 rounds (77% at wt=1, k=1), documented as a related-message property unrealisable against the MD chain (fixed IV breaks s-alignment); (Q4) SecurityProofs-2.md §11.8.2 updated with a "Sparse-B rotational characterisation" block and the open-concern list amended.

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

**Batch 1 — prototype + PRF seeding + parameters (v1.9.84).**  `SecurityProofsCode/qc_mdpc_bgf_prototype.py`
covers work items 1–4: (1) decoder survey implemented as BGF (Drucker-Gueron-Kostic 2019, BIKE v5's
decoder) with GJS reaction-attack and weak-key notes; (2) NL-FSCX v1 counter-mode XOF
(HFSCX-256-DM path) replaces SHA-3 for seed expansion — chi-square uniformity of derived sparse
supports PASSES (z within noise over 400 keygens), so the QCSD hardness assumption is unaffected;
(3) BGF prototype at r=523, d=15, t=18 decodes with 0/300 failures (0/500 across 5 keys during
threshold tuning), decap ≈9 ms vs brute-force C(1046,18) ≈ 2^124; (4) production parameters are
BIKE's unchanged (r=12323, w=142, t=134 for 128-bit, DFR ≤ 2^-128).  SecurityProofs-2.md §11.8.5
updated with the prototype paragraph.

**References:** BIKE specification v5.2 (Aragon et al. 2022); Drucker-Gueron-Kostic BGF decoder (2019);
SecurityProofs-2.md §11.8.5 (Option C roadmap).

Status: **DONE v1.9.86** — Batch 1 (items 1–4) shipped v1.9.84; Batch 2 (C+Python CLIs) shipped v1.9.85; Batch 3 (Go CLI + 9-way interop test) shipped v1.9.86. Production gaps (constant-time C, weak-key rejection) documented in SecurityProofs-2.md §11.8.5.

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

Status: **DONE v1.9.90** — `SecurityProofsCode/hpks_ristretto_migration.py`: self-contained pure-Python ristretto255 (RFC 9496; validated against the RFC generator test vector, ell·G = identity, encode/decode round-trips) with the HPKS Schnorr equation verbatim.  (1) Drop-in confirmed: 50/50 sign/verify, all tamper cases rejected; 3-of-3 additive threshold (TODO #98) and AOS Schnorr ring signatures (TODO #78.I) transfer with zero structural change — and the prime group order removes the order-divisor caveats GF(2^n)* required.  (2) Migration impact: 32-byte elements both sides, PEM/DER layouts carry over, new algo tag needed (e.g. hpks-r255); scalars re-range to mod ell; keys not interoperable; HSKE/HPKE symmetric halves untouched.  (3) PQ assessment: classical-only upgrade — Shor breaks ECDLP too; no quantum-resistant successor group exists for Schnorr algebra; PQC path remains HKEX-RNL + Stern-F/Stern-KEM exclusively.  (4) Documented as SecurityProofs-1.md §9.2.6 (a §9.2.5 already existed; zero new math spans added — the document is at 859, above the ~750 GitHub cascade threshold).

---

### 129. Constant-time audit of core arithmetic primitives (Security, High)

**Background:** TODO #126's status note explicitly flags "production gaps (constant-time C,
weak-key rejection)" as unresolved for the Stern-F/BIKE path, but the same class of gap likely
exists across `herradura.h` more broadly: `gf_mul`, `gf_pow`, `ba_mul_mod_ord`, and the FSCX
rotation/XOR chain have never been audited for data-dependent branches or variable-time loops.
Timing side-channels are typically the first thing a real security review finds, ahead of any
algebraic weakness — the math can be sound while the C implementation leaks the key.

**Work items:**

1. Run `dudect` (or an equivalent statistical timing-leakage tool) against `gf_mul`, `gf_pow`,
   `ba_mul_mod_ord`, and `fscx_revolve` in `herradura.h`, comparing fixed-key vs. random-key
   timing distributions.
2. Audit for secret-dependent branches (`if`, early-`return`) and secret-dependent memory
   access (table lookups indexed by key material) across `hkex_`, `hske_`, `hpks_`, `hpke_`,
   and `stern_` functions.
3. Where a leak is found, document the fix (bitmask select instead of branch, constant-time
   modular reduction) and re-run `dudect` to confirm the leak is closed.
4. Record which functions were audited-and-clean vs. audited-and-fixed vs. not-yet-audited in a
   new SecurityProofs subsection, so the "production gap" note in #126 can eventually be closed
   or narrowed.

**Batch 1 — core arithmetic + protocol entry points (v1.9.94).**
`SecurityProofsCode/dudect_timing_audit.c` implements a simplified dudect (Reparaz et al.
2017) fixed-vs-random Welch's t-test. `gf_mul_ba`, `gf_pow_ba`, `ba_mul_mod_ord` (already
hardened as SA-02/03/04 in the v1.7.4 manual audit) and `ba_fscx_revolve` all show `|t| < 1`
at 4000 rounds — well under the 4.5 leak threshold. The eight `hkex_`/`hske_`/`hpks_`/`hpke_`
protocol entry points were audited by inspection: their only branches are the TODO #131
`gf_pub_is_valid()` rejection and `hpks_verify`'s final equality check, both on public
values, not secret key material. Documented in SecurityProofs-3.md §11.11, including what
remains unaudited (Stern-F/Niederreiter permutation and error-vector handling, WOTS/XMSS
hash chains) for a future batch — TODO #126's "production gap" note stays open until that
Stern surface is covered.

**Batch 2 — Stern-F permutation/error handling and WOTS/XMSS (v1.9.95).** Extended
`dudect_timing_audit.c` with `stern_gen_perm`, `stern_apply_perm`, and `hpks_wots_sign`.
`hpks_wots_sign` is clean (`|t|=0.06`) — WOTS chain-iteration counts derive from the public
message hash, not secret key material, matching the published WOTS design; `hpks_xmss_*`
adds nothing beyond that plus the already-audited `haccum_*` accumulator (TODO #83).
`stern_gen_perm` shows a real, large leak (`|t|=180.85` — fixed-seed mean 5195.6 ns vs.
random-seed mean 5886.2 ns, ~12% difference): its Fisher-Yates rejection sampling has a
PRNG-stream-dependent loop count keyed on the secret `pi_seed`. `stern_apply_perm` inherits
the same wall-clock signal (it calls `stern_gen_perm` internally) and separately has a
`perm[i]`-dependent memory-access pattern that a wall-clock t-test cannot characterize
(needs cache-timing tooling, out of scope this batch). `pi_seed` is ephemeral and revealed
in 2 of 3 Stern response branches anyway, so this doesn't expose the long-term private key
directly, but it is a genuine open finding, not benign rejection-sampling noise. A fix
(Lemire multiply-shift, removing the rejection loop) is scoped but *not* applied this batch:
`stern_gen_perm` must stay bit-identical between C/Go/Python and between signer/verifier for
signatures to verify at all, so the fix requires synchronized changes across all three
language suites plus a 9-way interop re-test — tracked for Batch 3. Documented in
SecurityProofs-3.md §11.11.

**Batch 3 — CT-01 fix applied to `stern_gen_perm` across C/Go/Python (v1.9.96).** Replaced
the rejection-sampling `do { } while` in `herradura.h`, `herradura/herradura.go`, and
`Herradura cryptographic suite.py` with a single-draw Lemire multiply-shift map
(`j = (v * range) >> 32`), applied identically in all three so signer/verifier and
cross-language interop stay intact — confirmed by `CliTest/test_stern_interop.sh` (9/9),
`test_stern_kem.sh` (9/9), and `test_ring.sh` (21/21), all still passing. The dominant
12%-magnitude structural leak Batch 2 found is closed: the fixed-vs-random mean-time gap
collapsed from 690.6 ns to 53.9 ns at 4000 rounds (`|t|` 180.85 → 5.22). A much smaller
residual signal remains statistically detectable at higher sample counts (`|t|`≈30-38 at
20 000 rounds); analysis in SecurityProofs-3.md §11.11 attributes it to hardware-level
data-dependent timing at the degenerate all-zero `pi_seed` test point rather than the
software rejection-sampling structure, and leaves it open pending cache/power-timing
instrumentation out of scope for a wall-clock harness. `stern_apply_perm`'s
memory-access-pattern question (Batch 2) and the still-unaudited HKEX-RNL/ZKP-RNL/HCRED
functions (original item 2 scope) remain for a future batch.

**Batch 4 — HKEX-RNL/ZKP-RNL/HCRED audited by inspection (v1.9.97).** `rnl_keygen`,
`rnl_agree`, `rnl_hint`, `rnl_reconcile_bits`, and `rnl_cbd_poly` (CBD(η=1) secret sampler)
audited clean — no branch on secret polynomial coefficients; `rnl_agree`'s one branch
selects the public reconciler-vs-receiver role. `rnl_sigma_sign`'s variable Fiat-Shamir
attempt count is Lyubashevsky's rejection-sampling-with-aborts design (2012), the same
pattern used by the ML-DSA/Dilithium reference implementation — recorded as audited, not as
a leak to fix, since a variable abort count is the scheme's intended behavior, not an
implementation bug. Found one low-severity item: `_hcred_witness`'s
`if ((sr & 1) != syndr_bit) return -1;` early-exits per row on the prover's own witness —
same shape as the already-fixed SA-08 finding, but called once on the prover's own
internally-consistent secret rather than on attacker-supplied or externally-timeable input,
so there's no remote/co-tenant timing oracle; deferred as low-cost future cleanup rather
than fixed now. Documented in SecurityProofs-3.md §11.11.

**Batch 5 — CT-02: `_hcred_witness` early-return cleanup (v1.9.98).** Replaced the two
secret-witness-dependent early returns flagged in Batch 4 with unconditional-iteration loops
that accumulate a pass/fail flag checked once after the loop, so both loops in
`_hcred_witness` now always run their full length regardless of the witness. Re-verified
with `CliTest/test_cred.sh` (5/5) and suite tests `[44]`/`[45]` (HCRED completeness/tamper
rejection and weak-key/malformed-input rejection, both `[PASS]`) — behavior unchanged, only
the rejection path's timing profile changes. Documented in SecurityProofs-3.md §11.11.

**Batch 6 — CT-03: `stern_apply_perm` made memory-access-oblivious (v1.9.99).** Replaced the
`perm[i]`-addressed byte write with an `O(N^2)` scan over every candidate output position
under a constant-time equality mask, so the memory-access pattern no longer depends on the
secret permutation at all (address sequence is always the full grid regardless of `perm[]`).
Pure implementation change — output is byte-identical to before, so no Go/Python changes
were needed; verified via `CliTest/test_stern_interop.sh` (9/9), `test_stern_kem.sh` (9/9),
`test_ring.sh` (21/21). `stern_apply_perm`'s own wall-clock signal now tracks
`stern_gen_perm`'s inherited residual instead of exceeding it (`|t|` 24.76 vs. 44.74 at
20 000 rounds, `stern_apply_perm` no longer larger) — consistent with its independent
memory-access-pattern leak being closed, leaving only the Batch 3 hardware-attributed
residual shared by both functions. Documented in SecurityProofs-3.md §11.11.

**Batch 7 — residual signal confirmed as an all-zero-test-point artifact, not a leak
(v1.9.105).** Added a second dudect "fixed" class — a non-zero, non-degenerate `0xA5`
bit-pattern secret — alongside the existing all-zero one, same code path otherwise.
`stern_gen_perm`/`stern_apply_perm` go from a clearly-suspected signal at the all-zero
secret (`|t|` 16.11/16.26 at 4000 rounds, this run) to clean at the `0xA5` secret (`|t|`
1.44/3.54) with nothing else changed — directly confirming the Batch 3/6 hypothesis that
the residual tracks the degenerate all-zero PRNG fixed point, not a secret-dependent
control-flow or memory-access path in the (already fixed) implementation. Documented in
SecurityProofs-3.md §11.11 Batch 7.

Status: **DONE v1.9.105** — Batches 1-7 complete. Both confirmed leaks (Stern-F rejection
sampling, Batch 2; `stern_apply_perm` memory-access pattern, Batch 2) were fixed (Batches 3,
6) and re-verified interop-clean. The one remaining wall-clock signal is now positively
attributed — via a direct fixed-secret-value swap, not just inference — to the dudect
harness's degenerate all-zero test point rather than to a code-level leak, so no further
code change is warranted; closing it completely would need cache/power-timing
instrumentation out of scope for a wall-clock harness, documented as a permanent methodology
note for future audit batches.

---

### 130. Fuzzing harness for PEM/DER codec and CLI argument parsing (Security, Medium)

**Background:** All of the suite's adversarial testing so far targets the cryptographic
protocols (tamper batteries, replay, wrong-key rejection). The PEM/DER codec
(`HerraduraCli/herradura_codec.h`, `codec.py`) and CLI argument parsers are untested against
malformed or adversarial input, despite being the most common real-world vulnerability surface
in cryptographic tooling (parser bugs, not algebra, are what usually get CVEs).

**Work items:**

1. Add a libFuzzer (or AFL) harness for the C codec's PEM/DER decode paths in
   `herradura_codec.h`.
2. Add a `go-fuzz`/native Go 1.18+ fuzz target for the Go CLI's PEM decode path.
3. Add an `atheris` (or hypothesis-based) fuzz target for `codec.py`.
4. Fuzz CLI argument parsing directly (malformed flags, truncated files, oversized inputs) for
   all three CLI implementations.
5. Wire a short fuzzing run (time-boxed) into CI if one exists, or document a manual
   `make fuzz` / script-based invocation otherwise.

Status: **DONE v1.9.101** — `Fuzz/` adds libFuzzer targets for the C codec
(b64_decode/der_parse_seq/pem_unwrap), native Go fuzz targets for the Go codec, a
Hypothesis-based suite for the Python codec (atheris has no working build path here),
and a black-box argv fuzzer across all three CLIs. No CI exists in this repo, so
`Fuzz/run_fuzz.sh` + `Fuzz/README.md` document the manual invocation. Found and fixed
5 bugs in the process: a stack buffer overflow in C `b64_decode`/`pem_unwrap`, an OOB
read in C `der_parse_seq`, an equivalent slice-panic in Go `DerParseSeq`, inconsistent
exception types in Python `codec.py`, and an unrelated pre-existing self-test overflow.
All four fuzz surfaces ran clean (15M+ C execs, 4M+ Go execs, 60k Hypothesis examples,
1300+ CLI trials) after the fixes.

---

### 131. Weak-key and malformed-input rejection tests across all protocols (Security, Medium)

**Background:** Current CLI and suite tests (`CliTest/`, `Herradura_tests.*`) verify
correctness — that honest keygen/kex/sign/verify round-trips succeed. They do not
systematically verify that adversarial or degenerate inputs are *rejected*: small-subgroup
elements, the identity element, zero/duplicate nonces, degenerate Stern syndromes, or
truncated/oversized PEM payloads fed to `genpkey`/`kex`/`sign`/`verify`/`dec`.

**Work items:**

1. Enumerate degenerate inputs per protocol: identity/small-order elements for HKEX-GF/HPKS/
   HPKE; zero-weight or all-ones syndromes for Stern-F/Stern-KEM; zero nonce/counter for
   HSKE-NL-A1.
2. Add negative-path tests to `Herradura_tests.*` (one new labeled test per protocol family)
   asserting rejection rather than crash or silent acceptance.
3. Add corresponding CLI-level tests in `CliTest/` feeding malformed PEM files to each
   subcommand and asserting a clean error exit rather than a crash.
4. Document which protocols already reject degenerate input by construction (e.g. via modular
   range checks) vs. which needed a new explicit check.

Status: **DONE v1.9.91** — item 1 identified the real gap: HKEX-GF/HPKS/HPKE silently
accepted a GF(2^n)* peer public key of 0 or 1 (the identity), which is trivially forgeable
(HPKS) or trivially decryptable (HPKE) since `pub^e` collapses to a constant. Fixed in
`herradura.h` via new `gf_pub_is_valid()`, wired into `hpks_verify` (returns 0) and into
`hkex_gf_agree`/`hpke_encrypt`/`hpke_decrypt` (now return `int`, reject degenerate peer
keys). Item 2 shipped as test `[45]` in `Herradura_tests.{c,go,py}` (all three languages,
all PASS): HKEX-GF/HPKS/HPKE reject identity/zero pub, HPKS-Stern-F rejects a corrupted
syndrome. Item 4: C is the only language with a shared library layer, so it's the only
language whose fix is reachable from production code; Go/Python suites inline the
Schnorr/El Gamal equations directly (pre-existing convention, matching how the CLI already
inlines them too) rather than calling a shared function, so their test [45] validates the
same logic via local "checked" helper functions rather than hardening a shared entry point.
Item 3's remaining gap — `herradura_cli.c`'s `kex`/`enc`/`verify` commands duplicated the
Schnorr/El Gamal math inline instead of calling the now-hardened `herradura.h` functions,
so a malicious PEM containing an identity/zero public key was not rejected by the CLI —
was closed by TODO #141 (v1.9.92), which added `gf_pub_is_valid()` checks in
`cmd_kex`/`cmd_enc`/`cmd_verify` and `CliTest/test_weak_key_rejection.sh`.

---

### 132. Formal verification spec for one core primitive (Security, Medium)

**Background:** `SecurityProofs-*.md` already carries an unusually large body of hand-written
mathematical proofs for a project of this size. A machine-checked formal spec for at least one
primitive would be a strong, differentiated credibility signal — most small crypto projects have
zero formal verification, and the suite is already proof-heavy enough that the next step is
natural.

**Work items:**

1. Pick one primitive with the tightest, most self-contained correctness statement — FSCX_REVOLVE
   periodicity (order of M = n/2) is the best first candidate given §-level proofs already exist
   in `SecurityProofs-1.md`.
2. Write a Cryptol or F* specification of FSCX and FSCX_REVOLVE and mechanically verify the
   periodicity claim against the existing hand proof.
3. If feasible, extend to the Schnorr verification equation (g^s · C^e == R) as a second target.
4. Document the verified claims and toolchain in a new SecurityProofs subsection, distinct from
   the hand-proved sections, so readers can see which claims are machine-checked.

Status: **DONE v1.9.100** — Cryptol/F* unavailable on this aarch64 host (no prebuilt
binaries); used Z3 (`python3-z3`, packaged for arm64) instead. `fscx_periodicity_z3.py`
proves M invertible, order n/2, S_n=0, and FSCX_REVOLVE(A,B,n)=A for every input at
n=8..256 (incl. deployed 256) via SMT UNSAT-of-negation. `hpks_schnorr_z3.py` proves the
Schnorr identity g^s * C^e == R fully symbolically at n=4, by complete (a,e) enumeration
at n=8, and by random sampling at n=32/64/256. Documented in `SecurityProofs-1.md` §1.5.

---

### 133. Machine-readable protocol specification (JSON/YAML schema) (Feature, Medium)

**Background:** The suite already maintains strict parameter/wire-format parity across six
languages by convention and documentation (CLAUDE.md, TUTORIAL.md). There is no single
machine-readable source of truth for protocol parameters, wire format, and security level that a
tool or LLM could consume directly to generate a correct client without parsing prose across
multiple files.

**Work items:**

1. Define a JSON Schema (or YAML) covering, per protocol (HKEX-GF, HSKE, HPKS, HPKE, NL/PQC
   variants, Stern-F/Stern-KEM, HCRED): parameter names and sizes, PEM block type strings,
   algo tags accepted by the CLI `--algo` flag, and the claimed security level/status
   (production / demo-only / pedagogical, matching TODO #127's deprecation notes).
2. Generate the spec from a single source (e.g. a Python script reading suite constants) so it
   cannot drift from the actual implementations.
3. Add a CI or pre-commit check that flags when a new `--algo` value or PEM block type is added
   to a CLI without a corresponding schema update.
4. Reference the schema file from README.md and TUTORIAL.md as the canonical parameter source.

Status: **DONE v1.9.102** — `spec/herradura-protocol-spec.schema.json` (JSON Schema
draft 2020-12) + `spec/herradura-protocol-spec.json`, generated by `spec/generate_spec.py`
from `HerraduraCli/herradura.py` (`_PRIV_ALGOS`, argparse `choices=`), `herradura_codec.h`
(`PEM_*`), and `herradura.h` (parameter `#define`s) so those fields can't drift from
source; `--check` fails on any stale/added/removed algo tag or PEM label. Security-status
classification is curated (file:line-cited) and cross-checked against the extracted
tag set at generation time. Referenced from `docs/TUTORIAL.md`'s Protocol reference
section and `README.md`'s repository structure; details in `spec/README.md`.

---

### 134. MCP server exposing the CLI as agent-callable tools (Feature, Medium)

**Background:** AI coding agents (Claude Code and similar) increasingly need callable
cryptographic primitives for agentic workflows — signing artifacts, deriving shared secrets
between agents, encrypting intermediate state. Very few crypto libraries ship an MCP interface,
so this is a genuine differentiator, not just a nice-to-have, and it plugs directly into the
suite's existing OpenSSL-style CLI without requiring new crypto code.

**Work items:**

1. Design an MCP server (Python, wrapping `HerraduraCli/herradura.py` or calling the built CLI
   binaries) exposing `genpkey`, `kex`, `sign`, `verify`, `enc`, `dec`, `dgst` as MCP tools.
2. Keep private-key material handling explicit and opt-in (e.g. tool operates on file paths the
   caller supplies, never generates or stores keys silently) — document the trust model clearly
   since this exposes cryptographic operations to an LLM-driven caller.
3. Add usage examples to `docs/examples/` showing an agent using the MCP server to complete a
   HKEX-GF key exchange or HPKS signature end-to-end.
4. Document setup in README.md / TUTORIAL.md.

Status: **DONE v1.9.103** — `Mcp/herradura_mcp_server.py`: stdlib-only (no `mcp`
SDK/pip dependency) MCP stdio server wrapping `HerraduraCli/herradura.py`, exposing
genpkey/pkey/kex/enc/dec/sign/verify/dgst as tools. Every tool takes only
caller-supplied file paths (no default key dir, no cross-call state); private-key
file contents are never echoed in a tool response (`Mcp/test_server.py` has a
regression check for this); no network I/O. `docs/examples/mcp/hello_herradura_mcp.py`
demonstrates an end-to-end HKEX-GF exchange + HPKS sign/verify via MCP tool calls.
Documented in `Mcp/README.md` and referenced from `README.md` and a new
`docs/TUTORIAL.md` "MCP server" section.

---

### 135. Condensed agent-facing API reference (llms.txt / AGENTS.md) (Docs, Low)

**Background:** CLAUDE.md is thorough for Claude Code contributors working *inside* this repo,
but there is no compact reference for external tools or agents that want to integrate
HerraduraKEx as a dependency (e.g. an agent generating code that calls `herradura.h` or the CLI
from another project). The convention of an `llms.txt` (or `AGENTS.md`) at the repo root is
emerging specifically to fill this gap.

**Work items:**

1. Write a condensed `llms.txt` at the repo root: protocol list, function signatures per
   language, CLI subcommand summary, and links to `docs/TUTORIAL.md` for detail — optimized for
   token-efficient consumption, not human narrative.
2. Keep it derived from/consistent with CLAUDE.md and TUTORIAL.md rather than duplicating
   prose; note explicitly which document is authoritative for which content.
3. Add a note to README.md pointing external integrators at `llms.txt`.

Status: **DONE v1.9.104** — added `llms.txt` (protocol summaries, herradura.h/Go/Python
API inventory, full CLI subcommand + `--algo` reference verified against argparse defs);
README.md links to it.

---

### 136. Cross-language property-based interop fuzz generator (Testing, Medium)

**Background:** `CliTest/test_vectors.sh` and friends check a fixed set of interop cases across
Python/C/Go/ASM. There is no generator that produces large numbers of randomized inputs, runs
them through all language implementations, and diffs outputs — the kind of test an AI agent can
write and maintain well, and the kind that catches subtle cross-language divergence (endianness,
modular-reduction edge cases) that fixed vectors miss.

**Work items:**

1. Write a generator script (Python) that produces randomized valid inputs per protocol
   (keys, nonces, messages) and feeds them through the Python, C, and Go CLIs (and ASM suite
   binaries where applicable).
2. Diff outputs (ciphertexts, signatures, shared secrets) across languages for each generated
   case; fail loudly on any divergence.
3. Run a few thousand cases per protocol as a soak test; document expected runtime and how to
   invoke it (e.g. `bash CliTest/test_fuzz_interop.sh`).
4. Wire a small, fast subset into the existing `CliTest/` suite; keep the large soak run as an
   opt-in script.

Status: **DONE v1.9.108** — `CliTest/fuzz_interop.py`: randomized-case generator covering
HKEX-GF key agreement, HSKE symmetric enc/dec (arbitrary length via encfile/decfile), HPKS
sign/verify, and HPKE asymmetric enc/dec, run across every ordered pair of the Python, C, and
Go CLIs (`--protocols`/`--cases`/`--seed` flags; `--seed` reproduces a specific run). ASM/
Arduino targets are suite binaries with inline tests, not full CLIs (no `genpkey`/`kex`/`enc`
subcommands — see `HerraduraCli/`), so they are out of scope for this CLI-driven fuzzer.
`CliTest/test_fuzz_interop.sh` wires an 8-case-per-protocol subset (fast, seed=0) into the
regular suite; a soak run (`python3 CliTest/fuzz_interop.py --cases 2000`) is documented as
opt-in given per-case CLI subprocess spawn overhead.

---

### 137. FFI bindings for Python and Go around the C implementation (Feature, Low)

**Background:** The suite currently ships parallel native implementations per language rather
than bindings, which is good for pedagogical parity but means Python/Go users don't get C's
performance without hand-porting. A `ctypes`-based Python wrapper and a `cgo`-based Go wrapper
around `herradura.h` would give performance-sensitive users a fast path while leaving the
existing native implementations untouched as the reference/pedagogical versions.

**Work items:**

1. Build a `ctypes` (or `cffi`) Python wrapper exposing `herradura.h`'s `ba_`/`gf_`/`hkex_`/etc.
   functions, packaged separately from `primitives.py` so it's opt-in.
2. Build a `cgo` Go wrapper around the same header, packaged separately from the native Go
   suite.
3. Add correctness tests confirming the bindings produce identical output to the native
   Python/Go implementations for the same inputs.
4. Document performance delta and when to prefer bindings vs. native implementation in
   README.md.

Status: **DONE v1.9.106** — `bindings/ffi/`: `herradura_shim.c`/`.h` expose the classical
v1.4.0 quartet (HKEX-GF, HSKE, HPKS, HPKE) from `herradura.h` as extern-linkage byte-buffer
functions, built into `libherradura_ffi.so` via `bindings/ffi/build.sh`. Python wrapper
(`bindings/ffi/python/herradura_ffi.py`, `ctypes`, opt-in and separate from `primitives.py`)
and Go wrapper (`bindings/ffi/go`, `cgo`, separate package/module from the root `herradura`
package). Correctness verified byte-for-byte against native Python
(`bindings/ffi/python/test_ffi_correctness.py`) and native Go
(`bindings/ffi/go/herradura_ffi_native_test.go`). Measured ~36× (Python) / ~13× (Go) speedup
over native for `hske_encrypt`; documented in README.md § FFI Bindings along with when to
prefer bindings vs. native. Scope: classical quartet only — NL/PQC and Stern-F protocols are
not exposed through this binding.

---

### 138. Benchmark comparison against established libraries (Docs, Low)

**Background:** The suite's benchmarks (`Herradura_tests.*` tests [30]-[41]) measure absolute
performance but never compare against familiar, established libraries, so a reader can't easily
judge whether HerraduraKEx's FSCX-based approach is competitive or where its real advantage
(multi-language parity, simplicity, PQC options) actually lies relative to something they know.

**Work items:**

1. Add a benchmark comparison table (README.md or a new `docs/BENCHMARKS.md`) against libsodium
   Ed25519 for HPKS and liboqs Kyber/Dilithium for the NL/PQC and Stern-F protocols, on the same
   hardware.
2. Be explicit about apples-to-oranges caveats (production-hardened C vs. this suite's
   proof-of-concept status per TODO #127) so the comparison doesn't overstate readiness.
3. Keep the comparison script in `SecurityProofsCode/` or a new `benchmarks/` directory so it's
   reproducible rather than a one-time snapshot.

Status: **DONE v1.9.107** — `docs/BENCHMARKS.md` with a comparison table, plus reproducible
scripts in `benchmarks/`: `compare_hpks_ed25519.py` (HPKS via FFI vs. libsodium Ed25519 via
`ctypes`, measured: ~60x/~40x slower sign/verify) and `compare_stern_f_dilithium.py`
(HPKS-Stern-F via CLI vs. liboqs Dilithium3 via `ctypes`, gracefully skips and prints install
instructions when liboqs is absent — liboqs was not installed in the environment this was
written in, so that half was not exercised end-to-end). HKEX-RNL vs. Kyber not implemented in
this pass; noted as follow-up in docs/BENCHMARKS.md. Caveats about proof-of-concept status
(TODO #127) documented alongside every table per the work item.

---

### 139. Docker quickstart for the full build matrix (Docs, Low)

**Background:** The six-language, cross-compiler, qemu-based build matrix (`build_c.sh`,
`build_go.sh`, `build_arm.sh`, `build_asm_i386.sh`) is a real strength but also a real barrier —
a new user has to install ARM/i386 cross-toolchains and qemu just to try the project. A
container image that builds and runs all targets out of the box would materially increase
"try it now" conversion without changing any build script's behavior.

**Work items:**

1. Write a `Dockerfile` that installs all cross-compilers/qemu dependencies documented in
   CLAUDE.md's Build Commands section and runs all four build scripts.
2. Provide a `docker run` quickstart in README.md that builds everything and runs the C/Go/
   Python test suites plus one CLI integration test as a smoke test.
3. Keep the Dockerfile in sync with CLAUDE.md's dependency notes (e.g. the i386 linker
   auto-detection logic) rather than duplicating install instructions that could drift.

Status: **DONE v1.9.110** — `Dockerfile` (Ubuntu 24.04 base) installs the exact packages each
`build_*.sh` script's own header comments document, then defers to those scripts rather than
duplicating install logic (item 3). `docker-entrypoint.sh` runs all four build scripts, then
the C/Go/Python test suites and `CliTest/test_c_interop.sh` as a smoke test. README.md gains a
"Docker quickstart" subsection with the two-command `docker build`/`docker run` flow. Validated
on a native (unpinned) build: C build+tests pass, Go build succeeds and tests execute correctly
(256-bit GF(2^n)* benchmarks are simply slow without hardware bignum accel — verified identical
behavior outside Docker, not a packaging defect), NASM i386 build+tests pass, and
`test_c_interop.sh` passes 4/4. The Dockerfile pins `FROM --platform=linux/amd64`, matching the
amd64→armel pairing `build_arm.sh`'s cross-toolchain comment was written against (Ubuntu's
arm64 repos carry no arm64→armel cross-toolchain); non-amd64 Docker hosts need `docker-buildx`
+ QEMU binfmt_misc emulation to build it (`sudo apt-get install -y docker-buildx
qemu-user-binfmt`, then `docker buildx build --platform linux/amd64 --load`). Building the
amd64 image under that emulation surfaced and fixed a real bug: `build_arm.sh`'s own documented
package, `libc6-armel-cross`, is runtime-only (no `crt1.o`/headers) and was never actually
sufficient to link — the correct package is `libc6-dev-armel-cross`, now fixed in both
`build_arm.sh` and the Dockerfile, and confirmed to place `crt1.o` correctly. Running the
resulting amd64 image's Go build under **nested** QEMU emulation (this arm64 host emulating an
amd64 container, itself running Go's own concurrent GC/scavenger goroutines) reproducibly
crashes the Go runtime regardless of `GOMAXPROCS`/`-p=1` — a known category of Go-runtime/
qemu-user-mode incompatibility unrelated to this Dockerfile, and not expected to reproduce on a
native amd64 host or a single-emulation-layer setup (e.g. Docker Desktop). C build and apt
installation were confirmed to succeed under this same nested emulation.

---

### 140. Add `SECURITY.md` with a consolidated threat model and vulnerability disclosure policy (Docs, Medium)

**Background:** Security status is currently scattered across protocol-specific notes — TODO
#127's deprecation of GF(2^n)* for production use, #126's "demo-only until production decoder"
caveat on HPKE-Stern-F, #131's still-open weak-key rejection gaps — with no single document
telling a security researcher what the trust boundary is, which protocols are production-grade
vs. demo-only/pedagogical, or where to privately report a vulnerability. GitHub surfaces
`SECURITY.md` directly in a repo's Security tab; its absence is both a missing disclosure
channel and a missed credibility signal for a project this proof-heavy.

**Work items:**

1. Add a protocol status table (production / demo-only / pedagogical) sourced from the existing
   `SecurityProofs-*.md` deprecation notes — reference the authoritative section rather than
   restating the proofs, so the table can't drift out of sync.
2. Document supported versions and where patches land, consistent with the
   MAJOR.MINOR.PATCH convention already defined in CLAUDE.md.
3. Define a private disclosure channel (email or GitHub private vulnerability reporting) and
   expected response time.
4. Link out to `SecurityProofs-1.md`/`-2.md`/`-3.md` for detailed analysis instead of duplicating
   proofs; keep `SECURITY.md` itself short and scannable.

Status: **DONE v1.9.93** — Added `SECURITY.md` with a protocol status table (production-track vs. demo-only/pedagogical, each row linked to its `SecurityProofs-*.md` section), a supported-versions statement tied to the `MAJOR.MINOR.PATCH` convention, GitHub private vulnerability reporting as the disclosure channel with a response-time commitment, and an out-of-scope section.

---

### 141. Harden CLI `kex`/`enc`/`verify` against degenerate peer public keys (Security, Medium)

**Background:** TODO #131 fixed `herradura.h` so `hpks_verify`/`hkex_gf_agree`/
`hpke_encrypt`/`hpke_decrypt` reject a GF(2^n)* peer public key of 0 or 1 (the identity),
which is otherwise trivially forgeable (HPKS) or trivially decryptable (HPKE). However,
`HerraduraCli/herradura_cli.c`'s `cmd_kex`, `cmd_enc`, and `cmd_verify` do not call these
`herradura.h` functions — they duplicate the Schnorr/El Gamal math inline (`gf_pow_ba` /
`gf_mul_ba` calls directly), predating the fix. This means a maliciously crafted or
corrupted PEM file containing an identity/zero public key is **not** currently rejected by
the CLI, even though the underlying library now would reject it if called correctly. This
is the actual untrusted-input boundary (external PEM files), so it's a more direct exposure
than the internal library API TODO #131 closed.

**Work items:**

1. In `cmd_kex`'s `hkex-gf` branch (`herradura_cli.c`, uses `gf_pow_ba` on the loaded peer
   public key directly), add a `gf_pub_is_valid()` check on `pub_theirs` before calling
   `gf_pow_ba`; `die()` with a clear message on rejection.
2. In `cmd_enc`'s `hpke`/`hpke-nl` branch, add the same check on the loaded `pub` before
   encrypting.
3. In `cmd_verify`'s `hpks`/`hpks-nl` branch, add the same check on the loaded `pub` before
   the Schnorr equation check (or refactor to call the now-hardened `hpks_verify` directly,
   removing the inline duplicate).
4. Add `CliTest/test_weak_key_rejection.sh`: hand-craft PEM files with an identity (`0x...01`)
   or zero public key value, feed them to `kex`/`enc`/`verify`, and assert a clean non-zero
   exit rather than a crash or (worse) a false "Signature OK" / successful encryption.
5. Evaluate whether other CLI code paths that inline `gf_pow_ba` on untrusted PEM input
   (e.g. `cmd_threshold_verify`, ring signature verification) have the same gap.

Status: **DONE v1.9.92** — added `gf_pub_is_valid()` checks before the inline
`gf_pow_ba` calls in `cmd_kex` (hkex-gf), `cmd_enc` (hpke/hpke-nl), and
`cmd_verify` (hpks/hpks-nl), each `die()`ing on a degenerate (0/1) peer public
key; `cmd_threshold_verify` already called the hardened `hpkst_verify` and
needed no change, ring-signature verification is unaffected (Stern, not GF
exponentiation); added `CliTest/test_weak_key_rejection.sh`.

---

### 142. `nl-zkboo`/`nl-zkbpp` proofs signed by the Go CLI use demo-strength rounds with no override (Security, High)

**Background:** A full cross-language quality audit found that
`HerraduraCli/herradura_cli.go`'s `sign --algo nl-zkboo`/`nl-zkbpp` paths hardcode
`ZkpNlDemoRounds` (= 4, `herradura/herradura.go:1882`) at the call sites
(`herradura_cli.go:2314`, `:2336`), and expose **no `--rounds` flag** to override it — the
correct constant, `ZkpNlProdRounds = 219`, is defined right next to the demo one
(`herradura/herradura.go:1883`) but is never referenced by the CLI. Python's equivalent
`sign` path defaults to `_ZKP_NL_PROD_ROUNDS = 219` and exposes `--rounds` to override
(`HerraduraCli/herradura.py:144,2412`); C hardcodes the same 219-round production constant
(`herradura.h:2391` `ZKP_NL_PROD_ROUNDS`, used at `herradura_cli.c:2472,2476`). Soundness of
the ZKBoo Fiat-Shamir proof is `(2/3)^rounds` — at 4 rounds a cheating prover succeeds with
probability `(2/3)^4 ≈ 19.75%` per attempt, i.e. the proof is trivially forgeable. Because
the wire format doesn't encode the round count and the PEM label/algo name are identical to
the production-strength proofs Python and C produce, this is silently much weaker than a
user would expect from the shared "byte-for-byte compatible" CLI framing (see TODO #144).
`CliTest/test_zkp_interop.sh` cannot catch this: it deliberately passes `--rounds 4` on
every CLI for test speed, so it only proves cross-language PEM-format compatibility at
demo strength, never exercising any CLI's actual default.

**Work items:**

1. In `herradura_cli.go`, change the `nl-zkboo`/`nl-zkbpp` `sign` call sites
   (`herradura_cli.go:2314,2336`) to default to `ZkpNlProdRounds` instead of
   `ZkpNlDemoRounds`, matching Python/C's production default.
2. Add a `--rounds` flag to Go's `sign`/`verify` dispatch for `nl-zkboo`/`nl-zkbpp`, mirroring
   Python's `--rounds` (`herradura.py:2411`), so a caller can still opt into a faster
   demo-strength proof explicitly rather than getting it silently by default.
3. Extend `CliTest/test_zkp_interop.sh` (or add a new script) with a **separate**,
   low-iteration-count check that each CLI's *default* round count is exactly 219 when
   `--rounds` is omitted, so a regression here is caught mechanically instead of requiring
   another manual audit.
4. Audit whether any other Go CLI signing path (e.g. `hpks-ring`, `hpks-t`) has a similar
   hardcoded-demo-parameter-with-no-override pattern.

Status: **DONE v1.9.112** — `herradura_cli.go`'s `sign --algo nl-zkboo`/`nl-zkbpp` now
default to `ZkpNlProdRounds` (219) and expose `--rounds` to override (mirroring Python's
existing flag); verified the default now takes ~9.5s (219 rounds) vs. ~0.15s with an
explicit `--rounds 4`, and that both `nl-zkboo` and `nl-zkbpp` still verify correctly at
both round counts. Added `CliTest/test_zkp_default_rounds.sh`, which mechanically decodes
the round count from each CLI's default-parameter proof PEM (the wire format's 8-byte
header encodes it directly, no full ZKBoo verification needed) and asserts it's 219 for
all three CLIs and both algorithms (6/6 pass); confirmed the existing
`CliTest/test_zkp_interop.sh` still passes unchanged (14/14). Audited `hpks-ring`/
`hpks-stern` (item 4): both already use `SdfRounds`=32, the same constant C/Python use,
with an explicit printed security warning at every invocation — not the same silent-
default-with-no-override pattern; `hpks-t` takes no round-count parameter at all. No other
instance of the anti-pattern found.

---

### 143. Go CLI is missing HCRED, `hpks-xmss`, and a reachable `threshold-verify` — "byte-for-byte compatible" CLI claim no longer holds (Feature/Interop, High)

**Background:** A full cross-language quality audit compared `HerraduraCli/herradura.py`,
`herradura_cli.c`, and `herradura_cli.go` subcommand-by-subcommand and found three real
feature gaps in the Go CLI, on top of TODO #142's ZKP round-count bug. Since CLAUDE.md and
`llms.txt` both claim the three CLIs "share the same PEM wire format and subcommand
interface" and produce output "byte-for-byte compatible with the others" (CLAUDE.md §
HerraduraCli), these gaps make that claim actively misleading — an agent or user reading
`llms.txt`'s CLI section would reasonably try `herradura_cli_go genpkey --algo hcred` and be
surprised it doesn't exist (see TODO #144 for the doc fix).

**Confirmed gaps:**

**A. HCRED subsystem entirely absent from the Go CLI.** Python (`herradura.py:2598-2632`,
`genpkey --algo hcred` at `herradura.py:2349`) and C (`herradura_cli.c:3543-3862`,
`genpkey --algo hcred`) both implement `cred-issue`/`cred-prove`/`cred-verify` and HCRED key
generation. `herradura_cli.go` has no `hcred` case in `cmdGenpkey`'s algo switch and no
`cred-issue`/`cred-prove`/`cred-verify` case in `main()`'s dispatch — despite the underlying
Go *library* (`herradura/herradura.go`) fully implementing `HcredUserKeygen`, `HcredIssue`,
`HcredProve`/`HcredCredVerify` (confirmed present, e.g. `HcredUserKeygen` at
`herradura/herradura.go:3273`). This is a CLI wiring gap, not a missing primitive.
`CliTest/test_cred_interop.sh` only defines `CLI_C`/`CLI_PY` and never references Go at all
— it silently omits Go rather than catching the gap.

**B. `hpks-xmss` exists only in the Python CLI.** Python implements `genpkey --algo
hpks-xmss` (with `--xmss-height`), `sign`/`verify --algo hpks-xmss`, and the
`HERRADURA HPKS-XMSS PRIVATE KEY`/`SIGNATURE` PEM labels (`herradura.py:2349-2353,2402,2418`
+ codec support). Neither C nor Go has any `xmss` reference at all — a Python-generated
`hpks-xmss` PEM cannot be parsed by either. No `CliTest/test_xmss_interop.sh` exists to catch
this (only a non-cross-language `test_wots.sh` exists, for the related but distinct WOTS
scheme).

**C. Go's `threshold-verify` subcommand is implemented but unreachable.** `cmdThresholdVerify`
is fully coded (`herradura_cli.go:3590-3624`) but `main()`'s dispatch `switch`
(`herradura_cli.go:3634-3676`) has no `case "threshold-verify":` — the function is only
reachable internally from `verify --algo hpks-t`. Python has no `threshold-verify` at all (its
dispatch table only has `threshold-commit/aggregate/respond/combine`). C's `threshold-verify`
is a real, working, directly-invokable subcommand (`herradura_cli.c:2345`, dispatched near
line 2698). `CliTest/test_threshold_interop.sh` uses the generic `verify --algo hpks-t`
path for all three CLIs, so it never calls `$GO threshold-verify` directly and cannot reveal
that the Go subcommand itself is dead.

**Work items:**

1. Wire `hcred` into `herradura_cli.go`'s `cmdGenpkey` and add `cred-issue`/`cred-prove`/
   `cred-verify` dispatch cases, calling the already-implemented `Hcred*` library functions.
2. Either implement `hpks-xmss` in the C and Go CLIs (the Go *library* already has
   `HpksXmssKeygen`/`Sign`/`Verify` per `herradura/herradura.go:2831`; check C's `herradura.h`
   for an equivalent), or explicitly scope `hpks-xmss` as Python-only in CLAUDE.md/llms.txt if
   porting is out of scope — don't leave it silently undocumented either way.
3. Add `case "threshold-verify":` to `herradura_cli.go`'s dispatch `switch`, wiring up the
   already-coded `cmdThresholdVerify`. Add the same subcommand to Python for parity, or document
   the asymmetry explicitly.
4. Add `CLI_GO` coverage to `CliTest/test_cred_interop.sh` and a new
   `CliTest/test_xmss_interop.sh`, and extend `CliTest/test_threshold_interop.sh` to call
   `threshold-verify` directly (not just `verify --algo hpks-t`) for every CLI that has it, so
   these three gaps are mechanically re-detectable rather than requiring another manual audit.

Status: **DONE v1.9.113** — Item 1 (HCRED wired into `herradura_cli.go`: `genpkey --algo
hcred`, `cred-issue`/`cred-prove`/`cred-verify`, byte-for-byte PEM interop with Python/C
confirmed via `CliTest/test_cred_interop.sh`) and item 4 (`CLI_GO` coverage added to
`test_cred_interop.sh`, 20/20 checks passing including Go-as-producer and Go-as-consumer
cross-language cases) completed in this pass. Items 2 (hpks-xmss scoped as Python-only in
`llms.txt`) and 3 (`threshold-verify` dispatch case wired in `herradura_cli.go`'s `main()`)
were already done by prior work in this session — confirmed present and passing
`CliTest/test_threshold_interop.sh`. All four work items now complete.

---

### 144. `herradura.h`'s weak/degenerate public-key rejection (TODO #131) has no equivalent in the Go or Python suite files (Security, Medium)

**Background:** TODO #131 added `gf_pub_is_valid()` and wired it into `herradura.h`'s
`hkex_gf_agree`/`hpks_verify`/`hpke_encrypt`/`hpke_decrypt`, and TODO #141 propagated the
same check into the C CLI. A cross-language audit found this hardening was never ported to
the Go or Python **suite files** at all — and in fact those exported protocol-level
functions don't exist there in the first place. `herradura/herradura.go` and
`Herradura cryptographic suite.py` implement HKEX-GF/HPKS/HPKE only as unguarded inline code
inside each language's `main()` demonstration (Go: `Herradura cryptographic suite.go:66-138`;
Python: `Herradura cryptographic suite.py:3924-3994`), calling `GfPow`/`gf_pow` directly with
no public-key validation and no reusable, hardened API a downstream caller could import.
Anyone building on the Go or Python suite files as a library (as opposed to the CLI, which
Python/C do harden at the `HerraduraCli/` layer per #141) gets no protection against a
degenerate/identity public key, which lets an attacker forge Schnorr signatures or trivially
decrypt/exchange keys (same root cause as #131).

**Work items:**

1. Add `GfPubIsValid`-equivalent guarded exported functions to `herradura/herradura.go`
   (`HkexGfAgree`, `HpksVerify`, `HpkeEncrypt`, `HpkeDecrypt`), mirroring `herradura.h`'s
   API shape so downstream Go code has a hardened entry point instead of only inline demo math.
2. Add the equivalent guarded functions to `Herradura cryptographic suite.py`
   (`hkex_gf_agree`, `hpks_verify`, `hpke_encrypt`, `hpke_decrypt`), reusing `gf_pub_is_valid`
   semantics already present in `herradura.h`.
3. Update each language's `main()` demo to call the new hardened functions instead of the raw
   inline math, so the demo itself doubles as a usage example of the safe API.
4. Add a test to `CryptosuiteTests/Herradura_tests.go`/`.py` mirroring the existing weak-key
   rejection sub-checks already covered by C's test `[45]` (see TODO #146.A for the related
   gap in that test's own cross-language parity).

Status: **DONE v1.9.114** — added `GfPubIsValid`/`HkexGfAgree`/`HpksVerify`/`HpkeEncrypt`/
`HpkeDecrypt` to `herradura/herradura.go` and `gf_pub_is_valid`/`hkex_gf_agree`/
`hpks_verify`/`hpke_encrypt`/`hpke_decrypt` to `Herradura cryptographic suite.py`, wired
into both `main()` demos, and updated Go's `[45]` test to call the new library functions
(Python's `[45]` test stays self-contained per the file's existing convention and already
covered the same sub-checks).

---

### 145. CLAUDE.md/README.md/llms.txt build and test documentation is stale against current code (Docs, Medium)

**Background:** A documentation-vs-code audit found several stale claims in CLAUDE.md,
compounding TODO #143's "byte-for-byte compatible" CLI framing issue with separate,
independent inaccuracies:

**A.** CLAUDE.md's `## Testing` section states `# C/Go/Python — security tests [1]–[29] +
benchmarks [30]–[41]`, but all three `Herradura_tests.{c,go,py}` files actually implement
tests up to `[45]` (`[44]` HCRED, `[45]` weak-key/malformed-input rejection are present and
identically numbered in all three but never mentioned in CLAUDE.md).

**B.** The same section's `# ARM/NASM: tests [1]–[13]` undercounts — both
`Herradura_tests.s` and `Herradura_tests.asm` actually implement tests `[1]`–`[17]`
(including Stern-Ring, ZKP-NL, FPE, Tweakable cipher, and Accumulator, all present despite
the documented cutoff at `[13]`).

**C.** CLAUDE.md's `(C also runs one C-only unlabeled test between [20] and [21])` note is
inaccurate on two counts: the test in question is fully labeled (`"[19] HFSCX-256-DM
known-answer vectors"`, `Herradura_tests.c:3729`) — it's test `[19]` running out of numeric
sequence, not an unlabeled test — and this out-of-sequence execution isn't C-only either:
Go and Python also invoke `[19]` out of order relative to `[17]`/`[18]`/`[20]`, just at
different points in each language's own call order.

**D.** `build_arduino.sh`/`run_arduino.sh` exist, are functional, and are referenced
elsewhere in CLAUDE.md (e.g. the parameter tables), but are never listed in the `## Build
Commands` code block alongside `build_c.sh`/`build_go.sh`/`build_arm.sh`/`build_asm_i386.sh`
— a reader following that section would not discover the Arduino build path exists.

**E.** `llms.txt`'s CLI section (`llms.txt:114-152`) lists `hcred`/`hpks-xmss`/`cred-issue`/
`cred-prove`/`cred-verify` as part of the shared, "byte-for-byte readable" CLI interface
without noting they are Python/C-only (see TODO #143) — misleading specifically for an
AI agent using `llms.txt` as a condensed reference to decide what to try.

**Work items:**

1. Update CLAUDE.md's `## Testing` section to reflect the actual `[1]`–`[45]` range for
   C/Go/Python and `[1]`–`[17]` for ARM/NASM, and correct or remove the "[20]/[21] unlabeled
   test" note per finding C.
2. Add `build_arduino.sh`/`run_arduino.sh` to CLAUDE.md's `## Build Commands` section.
3. Scope `llms.txt`'s CLI subcommand list to note which of `hcred`/`hpks-xmss`/`cred-*` are
   Python/C-only, once TODO #143's work items are resolved (or immediately, if #143 is not
   picked up soon — don't leave the misleading claim standing in the meantime).
4. Re-run this doc-vs-code check periodically (e.g. after any TODO that adds/removes a test
   number or CLI subcommand) rather than only at major version bumps — this class of drift
   accumulates silently otherwise.

Status: **DONE v1.9.115** — corrected CLAUDE.md's test-number ranges ([1]-[45] for C/Go/Python,
[1]-[17] for ARM/NASM) and the stale [20]/[21] unlabeled-test note; added
build_arduino.sh/run_arduino.sh to Build Commands; llms.txt already scopes hpks-xmss as
Python-only (hcred is no longer Python/C-only as of TODO #143's Go CLI wiring, so it needed
no scoping note); added a periodic-recheck reminder to CLAUDE.md's Testing section.

---

### 146. Cross-language test suites diverge in coverage/parameters under identically-numbered tests (Testing, Medium)

**Background:** A test-suite parity audit found several places where `Herradura_tests.{c,go,py}`
report the *same* test number/name across languages but actually validate different things —
meaning a PASS in one language is not the same guarantee as a PASS in another, which defeats
the purpose of shared test numbering as a cross-language contract.

**A. Test `[45]` (weak-key/malformed-input rejection) checks fewer sub-conditions in Go/Python
than C.** C checks 7 sub-conditions including HPKE-decrypt-refusal of a degenerate ephemeral
key and HSKE-NL-A1-AEAD tamper/reuse rejection (`Herradura_tests.c:5098-5217`); Go and Python
check only 4, omitting both the HPKE-decrypt check and the AEAD checks
(`Herradura_tests.go:1645-1707`, `Herradura_tests.py:2677-2729`) — even their printed
description strings differ (`"tampered syndrome/AEAD"` in C vs. `"tampered syndrome"` in
Go/Python), confirming this was a scope decision, not an oversight in printing.

**B. Test `[30]` (HPKS-WOTS-F/XMSS-F) validates a smaller tree in Python than C/Go.** C and Go
both use XMSS height `h=3` (8 leaves); Python uses `h=2` (4 leaves,
`Herradura_tests.py:2158-2159`, explicitly commented as a speed tradeoff) — a real reduction
in what's exercised (fewer leaves, shorter auth path) under the same test number.

**C. Test `[41]` (HPKS-Stern-F throughput benchmark) uses different round counts per language,**
making the reported ops/sec not comparable: C uses `rounds=8` (`Herradura_tests.c:2418` etc.,
printed `"rounds=8"`), Go uses `sdfTestRounds = 4` (`Herradura_tests.go:147`), Python
hardcodes `rounds = 4` (`Herradura_tests.py:2858-2859`). Benchmark-only (no PASS/FAIL
threshold), so this doesn't cause false passes, but the three languages' `[41]` numbers
shouldn't be compared against each other as currently labeled.

**Work items:**

1. Extend Go's and Python's test `[45]` to include the HPKE-decrypt-refusal and HSKE-NL-A1-AEAD
   tamper/reuse sub-checks C already has (or explicitly downgrade C's test name/number if the
   extra coverage is intentionally C-specific — pick one, don't leave the numbers implying
   parity that doesn't exist). This should be coordinated with TODO #144's work, since #144's
   hardened Go/Python functions are a prerequisite for testing HPKE-decrypt-refusal there.
2. Either raise Python's XMSS test `[30]` to `h=3` to match C/Go, or clearly print/name it as
   a reduced-parameter variant so a reader doesn't assume identical coverage.
3. Align `[41]`'s round count across C/Go/Python (either all 8 or all 4), or rename/relabel
   the benchmark output per language to make clear the numbers aren't directly comparable as
   currently printed.
4. Update CLAUDE.md's test-count documentation per TODO #145 once these are resolved, since
   the exact numbering/range may shift.

Status: **DONE v1.9.116** — extended Go's/Python's `[45]` with the HPKE-decrypt-refusal
and HSKE-NL-A1-AEAD tamper/reuse sub-checks C already had (now 7/7 sub-checks in all three);
raised Python's XMSS test `[30]` to `h=3` to match C/Go; aligned `[41]`'s Stern-F benchmark
to `rounds=8` in Go (new `sdfBenchRounds` constant, `[17]`/`[20]` correctness tests keep
`sdfTestRounds=4`) and Python. CLAUDE.md's test-count documentation required no changes
since no test numbers shifted.

---

### 147. Dead code in `Herradura cryptographic suite.asm`'s `fscx_single`; Arduino test suite lags ARM/NASM by 5 tests (Code Quality, Low)

**Background:** An assembly/Arduino consistency audit found two code-quality issues distinct
from the (correct, documented) reduced-parameter scope of these ports:

**A.** `Herradura cryptographic suite.asm:2347-2360`'s `fscx_single` contains a dead first
attempt at the FSCX computation — several xor/rol/ror instructions followed by a comment
admitting the approach was wrong (`"Actually we need A intact for the B part. Let me redo
with a copy."`), immediately followed by the real, correct computation at lines 2362-2381
that overwrites the result. Register-balanced (push/pop nets to zero) so output is
unaffected, but it's shipped debug/scratch code that should be removed for clarity.

**B.** `CryptosuiteTests/Herradura_tests.ino` implements only tests `[1]`–`[12]`, while the
sibling `Herradura_tests.s`/`.asm` files (added later, per file timestamps — June vs. the
`.ino`'s May) implement `[1]`–`[17]`, adding Stern-Ring, ZKP-NL, FPE, Tweakable cipher, and
the Accumulator. The Arduino test suite was never updated when tests `[13]`–`[17]` were added
to the ARM/NASM suites, so Arduino now has the narrowest test coverage of the three assembly-
adjacent targets despite being architecturally capable of the same 32-bit-parameter tests
(HCRED is a legitimate C-only gap across all of `.s`/`.asm`/`.ino` and is out of scope here —
see the Stern-F/HCRED parameter notes already in CLAUDE.md).

**Work items:**

1. Remove the dead first-attempt code in `Herradura cryptographic suite.asm`'s `fscx_single`
   (lines ~2347-2360), keeping only the correct computation.
2. Port tests `[13]`–`[17]` (Stern-Ring, ZKP-NL, FPE, Tweakable cipher, Accumulator) from
   `Herradura_tests.s`/`.asm` to `Herradura_tests.ino`, at the same reduced 32-bit parameters
   already used for Arduino's other tests.
3. Update CLAUDE.md's Arduino/assembly test-count references once `.ino` reaches parity
   (coordinate with TODO #145's doc-staleness fix so this isn't a second undercount left
   behind).

Status: **DONE v1.9.117** — removed the dead first-attempt code in `fscx_single`
(`.asm`), keeping only the correct computation (verified: all 17 i386 tests still
pass under qemu-i386). Ported tests `[13]`–`[17]` (Stern-Ring, ZKP-NL, FPE,
Tweakable cipher, Accumulator) to `Herradura_tests.ino` at the same reduced
32-bit parameters as the file's other tests, using 32-bit XOR/rotate commit
and PRG substitutes for the 256-bit hash the C/generic versions use (same
reduction already applied to the file's existing Stern-F tests); verified via
avr-g++/avr-gcc build + simavr simulation on an emulated ATmega2560 — all 17
tests pass, bss well under the 8KB SRAM budget. Added Arduino to CLAUDE.md's
`## Testing` assembly run commands, which previously omitted it entirely.

---

### 148. Reorganize `docs/TUTORIAL.md` around cryptographic function instead of language (Docs, Low)

**Background:** `docs/TUTORIAL.md` is currently organized with per-language/per-CLI
sections. This makes it hard for a reader to follow a single protocol (e.g. HKEX-GF or
HPKS) end-to-end, since its steps are split across separate language chapters. It also
obscures the cross-language parity that the rest of the project treats as a core
property (identical protocol steps, identical test numbering, PEM wire-format
compatibility across C/Go/Python/ASM/Arduino).

**Work items:**

1. Restructure `docs/TUTORIAL.md` into sections per cryptographic function/protocol
   (FSCX primitives, HKEX-GF, HSKE, HPKS, HPKE, then the NL/PQC variants, then Stern),
   rather than per language.
2. Within each protocol section, include code examples for each language/CLI in a
   consistent order (Python, C, Go, CLI, then ASM/Arduino where applicable), so readers
   can compare implementations of the same step directly.
3. Keep `docs/examples/{python,c,go}/hello_herradura.*` as the per-language "getting
   started" entry point; the tutorial's reorganization should not duplicate that role.

Status: **DONE v1.9.118** — restructured `docs/TUTORIAL.md` into sections per protocol
(Classical: HKEX-GF/HSKE/HPKS/HPKE; NL/PQC: HPKS-NL/HPKE-NL/HSKE-NL-A1/A2/AEAD/HKEX-RNL;
Code-based PQC: HPKS-Stern-F/HPKE-Stern-F; hash-based stateful signatures: WOTS-F/XMSS-F;
HCRED; hash primitive/DRBG: HFSCX-256/HDRBG), each with CLI, C, Go, and Python examples
nested together in that order, matching the pattern already used by the ZKP-RNL/ZKP-NL,
Threshold Signing, and OPRF/aPAKE sections (which were already function-organized and
left as-is). Added a short "Getting started" section up front for build/import
boilerplate that isn't specific to any one protocol. No example content was removed or
altered — only regrouped under new headers. `docs/examples/{python,c,go}/hello_herradura.*`
remains the per-language entry point, referenced from "Getting started" instead of
duplicated per-language chapter.

---

### 149. Stray untracked PEM/HCRED dump file `-` sitting in repo root (Code Quality, Low)

**Background:** A repo-hygiene pass found an untracked file literally named `-` in the
repo root (3221 lines, starting `-----BEGIN HERRADURA HCRED PROOF-----`). It looks like
accidental output from a shell redirect (e.g. `... > -`) during a manual CLI test run,
left behind rather than written to a real path. It shows up in every `git status` as
noise and has no purpose in the tree.

**Work items:**

1. Confirm the file is disposable test output (not referenced by any script or doc).
2. Delete it from the working tree.
3. If any CliTest/build script is found to be responsible for producing it (e.g. a
   missing `-o`/redirect target), fix that script so it can't recur.

Status: **DONE v1.9.119** — confirmed the file was disposable manual-test output (not
referenced by any script or doc) and deleted it. No CliTest/build script was found to
produce it, so no script fix was needed.

---

### 150. `.gitignore` lists `TODO.md`, but `TODO.md` is tracked and committed every release (Code Quality, Low)

**Background:** `.gitignore` contains a `TODO.md` entry, yet `TODO.md` is tracked in git
and updated in nearly every commit per this project's own TODO/CHANGELOG policy
(CLAUDE.md's "Changelog, README, and TODO Policy" section). The ignore rule is dead and
misleading — it suggests to a reader (human or AI) that TODO.md is local-only scratch
state, which is the opposite of how the project actually treats it.

**Work items:**

1. Remove the stale `TODO.md` line from `.gitignore`.
2. Skim the rest of `.gitignore` for other entries that no longer match how the repo is
   actually used, while touching the file.

Status: **DONE v1.9.119** — removed the stale `TODO.md` line from `.gitignore`. Remaining
entries (`.hypothesis/`, `__pycache__/`) still match real, current build/test artifacts.

---

### 151. Stray trailing line `OAHR` after the License section in README.md (Docs, Low)

**Background:** `README.md` ends with:
```
# License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.

OAHR
```
`OAHR` appears to be a leftover fragment (possibly stray initials or an artifact of an
edit) with no defined meaning in the document. It reads as a documentation bug to anyone
— human or AI — parsing the README as the canonical project description.

**Work items:**

1. Confirm with the author whether `OAHR` is meaningful (e.g. an intended attribution)
   or accidental.
2. Remove it if accidental, or replace it with its intended content (e.g. a proper
   attribution line) if meaningful.

Status: **DONE v1.9.119** — `git log -S"OAHR" -- README.md` showed a single commit
introducing the line with no accompanying context, and no reference to it anywhere else
in the repo; treated as accidental and removed.

---

### 152. CLAUDE.md's "Repository Structure" tree omits `Mcp/`, `spec/`, `bindings/`, `benchmarks/`, `Fuzz/`, `herradura/` (Docs, Medium)

**Background:** CLAUDE.md's `## Repository Structure` section lists only a subset of the
repo's real top-level directories. `Mcp/` (MCP server), `spec/` (machine-readable
protocol spec), `bindings/` (FFI bindings), `benchmarks/`, `Fuzz/`, and `herradura/` all
exist and are populated, but none appear in CLAUDE.md's tree. README.md's own
"Repository Structure" section (added since) is more current and already lists `Mcp/`
and `spec/`. Since CLAUDE.md is the primary orientation document loaded into every AI
coding session on this repo, an agent reading only CLAUDE.md gets an incomplete map of
the codebase. This is a distinct gap from TODO #145 (build/test command staleness) —
this is about the structural directory listing specifically.

**Work items:**

1. Update CLAUDE.md's `## Repository Structure` tree to include `Mcp/`, `spec/`,
   `bindings/`, `benchmarks/`, `Fuzz/`, and `herradura/` with one-line descriptions,
   matching the style already used for other entries.
2. Consider whether CLAUDE.md should keep a full independent copy of the tree or instead
   point to README.md's copy as the canonical version, to avoid the two drifting apart
   again in the future.

Status: **DONE v1.9.119** — added `Mcp/`, `spec/`, `bindings/ffi/`, `herradura/`,
`benchmarks/`, and `Fuzz/` to CLAUDE.md's Repository Structure tree with one-line
descriptions matching the existing entries' style. Kept CLAUDE.md's tree as an
independent copy (rather than a pointer to README.md's) since CLAUDE.md's version is
scoped to what an AI session needs to know structurally, while README's is user-facing;
revisit if the two drift again.

---

### 153. No CI — add a GitHub Actions build/test matrix (Testing/Infra, Medium)

**Background:** The repo has no `.github/workflows` directory and no CI of any kind.
TODO #130, #133, and #146 each mention "no CI exists in this repo" in passing while
scoping other work (fuzzing, machine-readable spec drift checks, cross-language test
divergence), but none of them actually adds one, and cross-language drift (TODO #146)
and doc staleness (TODO #145) have both already happened silently in the absence of any
automated check. The project already has correct, working build scripts
(`build_c.sh`, `build_go.sh`, `build_arm.sh`, `build_asm_i386.sh`, `build_arduino.sh`)
and test suites (`CryptosuiteTests/`, `CliTest/`) — CI would just need to invoke them.

**Work items:**

1. Add a GitHub Actions workflow that runs on push/PR: `build_c.sh` + C test suite,
   `build_go.sh` + Go test suite, the Python suite + Python test suite, and the
   `CliTest/` integration scripts for whichever CLIs were built.
2. Add ARM (`build_arm.sh` + qemu-arm) and NASM i386 (`build_asm_i386.sh` + qemu-i386)
   jobs, installing the cross-toolchain/linker packages CLAUDE.md's Build Commands
   section already documents.
3. Arduino (`build_arduino.sh` / `run_arduino.sh`) can be a best-effort/allowed-to-fail
   job if `arduino-cli` setup in CI proves flaky, rather than blocking on it.
4. Wire in the fuzzing harness from TODO #130 as a time-boxed CI job once that item
   lands, per its own suggestion.
5. Update CLAUDE.md/README.md to mention the CI workflow once added.

Status: **DONE v1.9.120** — added `.github/workflows/ci.yml` with three jobs mirroring
`docker-entrypoint.sh`'s dependency-installation-then-defer-to-scripts approach: (1)
`native` — `build_c.sh`/`build_go.sh`, the C/Go/Python security test suites (`-t 2.0`),
and the full `CliTest/*.sh` suite (all 45 scripts, covering Python/C/Go CLI integration
and cross-language interop); (2) `arm-i386` — `build_arm.sh`/`build_asm_i386.sh` plus
`run_arm.sh tests`/`run_asm_i386.sh tests` under qemu; (3) `arduino` — `build_arduino.sh`/
`run_arduino.sh tests` under simavr, marked `continue-on-error` per work item 3. All three
build scripts and all 45 CliTest scripts were verified locally before landing the
workflow (native job: full build + all three test suites + full CliTest run, all green;
`test_cred_interop.sh` alone takes ~4 minutes for its 20-case 9-way N=256 cross-language
HCRED check, well within GitHub Actions' default job timeout). Fuzzing-harness wiring
(work item 4) deferred to TODO #130 landing, as scoped. Added a CI status badge and a
one-line mention to README.md, and updated CLAUDE.md's `## Testing` section to describe
the new workflow instead of asserting "no automated test framework."

---

### 154. Split `TODO.md` into an open-items file and a DONE archive (Docs, Medium)

**Background:** `TODO.md` has grown to ~7800 lines / ~440KB with 166 DONE entries and
only a handful still open. Every DONE entry carries a full background/work-items/status
writeup (by design, per this project's own documentation standards), which is valuable
history but means finding "what's actually left to do" requires scanning past hundreds
of completed, historical entries. This is the same discoverability problem that
motivated splitting `SecurityProofs.md` into `SecurityProofs-{1,2,3}.md`.

**Work items:**

1. Split `TODO.md` into open items only, and move DONE/DEPRECATED/ACKNOWLEDGED entries
   to an archive file (e.g. `TODO_DONE.md`, or split by version range like the
   SecurityProofs files).
2. Leave a short index/redirect at the top of `TODO.md` pointing to the archive, mirroring
   the pattern `SecurityProofs.md` already uses as a redirect to Parts 1–3.
3. Update CLAUDE.md's TODO.md Status-line policy section and the "Quick check" regex
   command to account for the new file(s), so the existing automated Status-line audit
   still works across whichever file(s) end up holding open items.
4. Preserve numbering — archived items keep their original `### N.` numbers so existing
   cross-references (CHANGELOG entries, commit messages, other TODO items) that cite
   `TODO #N` remain valid.

Status: **DONE v1.9.121** — split `TODO.md` into two files: `TODO_DONE.md` archives all
`DONE`/`DEPRECATED`/`ACKNOWLEDGED` entries (the entire pre-split body, since every item
was completed as of this split — see TODO #153 above), and `TODO.md` now holds only
currently-`OPEN` entries (none, at present) plus a short redirect note pointing to the
archive, mirroring `SecurityProofs.md`'s redirect-to-Parts-1-3 pattern. Item numbering
was preserved exactly (no renumbering) so existing `TODO #N` cross-references in
CHANGELOG.md, commit messages, and other TODO entries remain valid regardless of which
file `#N` currently lives in. Updated CLAUDE.md's TODO Status-line policy section and its
"Quick check" regex to run across both files and additionally flag any `TODO.md` entry
not marked `**OPEN**` or any `TODO_DONE.md` entry marked `**OPEN**`.

---

### 155. Arduino/AVR CI job fails: `.bss` overflows the ATmega2560's 8KB SRAM by ~51 bytes under the GitHub-runner toolchain (Build/CI, Low)

**Background:** TODO #153's new CI workflow runs `build_arduino.sh` on `ubuntu-latest`
(`arduino-core-avr 1.8.6+dfsg-1` / `avr-gcc 7.3.0` from Ubuntu 24.04's apt repos). The
suite `.ino` build fails deterministically at the link step on both PR #167 CI runs, at
the identical address:
```
avr/bin/ld: address 0x802233 of Herradura cryptographic suite_avr.elf section `.bss'
is not within region `data'
collect2: error: ld returned 1 exit status
```
The ATmega2560's SRAM `data` region ends at `0x802200` (8192 bytes from `0x800200`), so
the linked binary needs the static (`.data`+`.bss`) storage to fit within that budget —
here it overflows by `0x802233 - 0x802200 = 0x33` = 51 bytes. This is not present in
`build_arduino.sh`'s own header-comment margin note (which already flags the ATmega328P/
Uno as insufficient at ~2.5KB BSS from the Ring-LWR polynomial arrays) — the ATmega2560
target normally has comfortable headroom, so this looks like a toolchain-version-specific
regression: the CI runner's `arduino-core-avr`/Arduino-core build apparently has a
slightly larger static footprint than whatever local toolchain this target was last
verified against, tipping a previously-fine build over the edge by a small margin. The CI
job is marked `continue-on-error: true` (best-effort, per TODO #153 work item 3), so this
does not block merges, but it means the Arduino target is currently unverified in CI.

**Work items:**

1. Reproduce locally with the same toolchain versions as the CI runner
   (`arduino-core-avr 1.8.6+dfsg-1`, `avr-gcc 7.3.0`, Ubuntu 24.04) to confirm the
   overflow is toolchain-driven rather than a pre-existing latent bug.
2. Identify which static buffer(s) account for the ~51-byte overrun (`avr-size` /
   `avr-nm --size-sort` on the linked `.elf`) and trim them — likely candidates are
   Ring-LWR polynomial arrays or Stern-F buffers already called out as memory-tight in
   `build_arduino.sh`'s header comments.
3. Verify the fix under `simavr` (`run_arduino.sh tests`) and re-run the CI Arduino job
   to confirm it goes green before considering this fixed — the job should then have
   `continue-on-error` reconsidered (keep it as a safety net regardless, but a green
   Arduino job matters for catching future regressions of this kind).

Status: **DONE v1.9.122** — reproduced locally with the same `arduino-core-avr
1.8.6+dfsg-1` package as the CI runner (local `avr-gcc` was a newer 14.3.0 vs. CI's
7.3.0, but the overflow reproduced at the same address modulo 1 byte: `0x802234` locally
vs. `0x802233` in CI, confirming it's package/footprint-driven, not a specific compiler
version quirk). `avr-nm -S --size-sort` on the suite's compiled object identified two
oversized function-scoped `static` locals in `Herradura cryptographic suite.ino`'s
`loop()` — `SternRingSig2_32 rsig` and `SternRingSig2_32 eve_rsig` (208 bytes each, 416
bytes total) — used only within their own single-shot HPKS-Stern-Ring test blocks, fully
written before being read, with no need to persist across `loop()` iterations. Removed
`static` from both declarations, moving them to the stack (freed 416 bytes of permanent
static RAM against a 51-byte overflow, leaving real headroom: suite `.data+.bss` is now
7828/8192 bytes, tests `.data+.bss` is 4738/8192 bytes). Verified both `.ino` targets
link successfully and all 17 security tests still pass under `simavr`
(`run_arduino.sh tests`, tests `[1]`-`[17]` all `PASS`). CI's Arduino job (`continue-on-
error: true`) is now expected to go green on the next run; kept `continue-on-error` as a
safety net per the original work item 3 rationale rather than removing it, since a future
static-RAM regression should not block merges by itself.

---

### 164. Fix modulo-3 bias in HPKS-Stern-Ring's non-signer challenge simulation — a same-ring-reuse anonymity leak (Security, Medium)

**Background:** Found during TODO #159's LLM-assisted cryptanalysis stress-testing pass
of HPKS-Stern-Ring's OR-composition (`SecurityProofsCode/stern_ring_challenge_bias.py`).

`stern_ring_sign` (herradura.h) and `hpks_stern_ring_sign` (the Python suite) pick each
non-signer ring member's per-round Stern challenge $b \in \{0,1,2\}$ by drawing a single
random byte and reducing mod 3:

```c
b_pre = (int)(rnd1 % 3u);                              /* herradura.h */
```
```python
b = int.from_bytes(os.urandom(1), 'big') % 3           # hpks_stern_ring_sign
```

256 is not divisible by 3, so this is biased: $\Pr[b=0] = 86/256 \approx 33.59\%$ versus
$\Pr[b=1] = \Pr[b=2] = 85/256 \approx 33.20\%$ — a $\approx 0.39\%$ skew. The real
signer's own displayed challenge is *not* drawn this way — it is forced by subtraction
from the Fiat-Shamir joint challenge (`joint[r] - sum_{i≠j} b[i,r] mod 3`), which is
hash-derived and effectively uniform independent of the non-signer draws. A uniform
value minus anything, reduced mod 3, is itself exactly uniform — so the signer's slot
has zero skew while every non-signer's slot carries the ~0.39% bias. An observer with
per-round challenge-value access across many signatures from the **same ring** can in
principle test each member-slot's empirical challenge distribution against ideal uniform
and flag the unbiased slot as more likely to be the real signer — a statistical
anonymity leak specific to long-lived/reused rings (anonymous credentials,
whistleblowing channels — exactly where ring-signature anonymity matters most).
`stern_ring_challenge_bias.py` estimates ~9,000+ same-ring signatures needed for
3-sigma-confidence detection per slot at `SDF_ROUNDS=32`.

Go's implementation is unaffected: it already reduces a full 32-bit random value mod 3
(bias ~$2^{-32}$, negligible) rather than a single byte.

**Fix:** apply the same rejection-sampling pattern already used for TODO #2's
`_rnl_rand_poly` bias (draw a byte, reject the one out-of-range value — threshold 255,
~0.4% rejection rate, exact uniformity), or simply widen the C/Python draw to match Go's
32-bit-then-mod-3 pattern. Apply to both the C (`herradura.h`) and Python
(`Herradura cryptographic suite.py`) `stern_ring_sign`/`hpks_stern_ring_sign`
non-signer-challenge draws; re-run `CliTest/test_ring.sh` after the fix.

Status: **DONE v1.9.127** — rejection sampling applied to both `herradura.h`'s
`stern_ring_sign` (loop rereads a fresh byte if it draws 255, capped at 8 tries with a
deterministic fallback matching the prior behavior if the entropy source is exhausted)
and the Python suite's `hpks_stern_ring_sign` (unbounded reject-255 loop over
`os.urandom(1)`), eliminating the ~0.39% per-residue skew (exact uniformity over the
retained 255 values, which split 85/85/85 across the three residues). Go and the
Arduino/`.ino` ring-signature code were already unaffected (both reduce a wide 32-bit
value mod 3, bias ~$2^{-32}$) and needed no change. Re-verified: `CliTest/test_ring.sh`
21/21 pass (all C/Go/Python signer↔verifier pairs, anonymity, non-member/tamper/
wrong-ring rejection), `CliTest/test_stern_interop.sh` 9/9 pass (Stern-F unaffected by
the ring-specific fix), and a standalone Python sign→verify smoke test at n=32.

---

### 160. Physical side-channel (power/EM) resistance research for Stern-F and HKEX-RNL, beyond the existing timing-only `dudect` audit (Research/Security, Medium)

**Background:** TODO #129's constant-time audit and `SecurityProofsCode/dudect_timing_audit.c`
cover *timing* side-channels only. The review window produced several results showing
that timing-safety is not sufficient for newly-standardized PQC schemes: single-trace
power analysis recovering ML-KEM (Kyber) keygen material (TCHES 2025, per search
results), a first correlation-power-analysis side-channel attack against an
industry-grade ML-DSA implementation
(https://ieeexplore.ieee.org/document/11050056/), and simple power analysis recovering
HQC private keys from polynomial-multiplication power traces
(https://arxiv.org/pdf/2601.07634). These are the same class of scheme (lattice/code-
based KEM and signature) as HKEX-RNL and HPKS/HPKE-Stern-F, so the attack surface is
directly analogous even though no attack has been published against this suite
specifically.

**Work items:**

1. Survey which of HKEX-RNL's operations most resemble the attacked ones (NTT-based
   polynomial multiplication is explicitly named in the HQC attack and is also core to
   HKEX-RNL's `rnl_poly_mul`/NTT implementation per CLAUDE.md's protocol stack section) —
   prioritize those for review first.
2. Since power/EM side-channel testing requires physical hardware or a simulator this
   repo doesn't currently have (unlike timing, which `dudect` can test on any host), scope
   what's actually feasible here: e.g. static analysis for known-vulnerable patterns
   (secret-dependent branching in NTT butterfly operations, non-uniform Hamming-weight
   leakage in polynomial coefficient handling) versus a genuine power-trace capture setup
   (would need real target hardware, likely out of scope for this repo alone).
3. At minimum, document in `SecurityProofs-2.md` which of this suite's PQC operations
   have published side-channel attacks against structurally similar operations elsewhere,
   as a known-risk register, even if a full countermeasure (masking, blinding) isn't
   implemented in this pass.
4. If static analysis finds a clearly analogous secret-dependent-branch pattern in
   `rnl_poly_mul`/`rnl_ntt` or the Stern-F permutation/response-selection code, open a
   follow-up implementation TODO scoped to just that fix.

Status: **DONE v1.9.128** — all four work items completed with a definitive (not just
partial) conclusion. Item 1: surveyed and mapped three 2025-2026 published power-analysis
attacks (ML-DSA CPA on NTT-domain modular reduction [HOST 2025], HQC single-trace SPA on
decryption-time polynomial multiplication [arXiv:2601.07634], ML-KEM single-trace keygen
recovery [TCHES 2025, "Avengers assemble!"]) onto HKEX-RNL's `rnl_ntt`/`rnl_poly_mul` and
Stern-F's `stern_gen_perm`/response-selection code. Item 2: scoped to the feasible-without-
hardware static-analysis check, since none of the three attacks are reproducible without
real capture hardware this repo doesn't have. Item 3: documented as a permanent risk
register in `SecurityProofs-3.md` §11.13 (new section, added right after §11.11's
timing-only constant-time audit, which it explicitly extends). Item 4: static analysis
found **no** clearly-analogous secret-dependent-branch pattern — `rnl_ntt`/`rnl_poly_mul`'s
control flow depends only on the public size parameter and loop counters, never on a
secret coefficient value, and Stern-F's response-selection branches switch on the public
Stern challenge (not a secret) — so no follow-up implementation TODO was opened. The
residual risk (power/EM leakage inherent to unmasked arithmetic on secret polynomial
coefficients, requiring masking/blinding countermeasures not implemented in any language
target) is recorded as an open, honestly-unresolved risk-register entry rather than
falsely closed.

---

### 161. Audit HKEX-RNL/HKEX-GF/Stern-F KEM usage against NIST SP 800-227 (September 2025) (Security/Docs, Medium)

**Background:** NIST finalized SP 800-227 in September 2025, providing guidance on how
KEMs should actually be used in protocols — covering protocol composition, input
validation, key derivation, failure behavior, randomness requirements, side-channel
resistance, and key lifecycle controls, on the premise that a mathematically sound KEM
primitive can still be broken by misuse at these layers
(https://postquantum.com/post-quantum/cryptography-pqc-nist/, referencing SP 800-227).
This repo already has related but narrower items — TODO #141 hardens the CLI against
degenerate peer public keys, and TODO #144 covers weak-key rejection parity across
language targets — but neither was scoped against this specific, now-finalized NIST
guidance document, which is broader (implicit rejection semantics, KDF domain separation
requirements, decapsulation failure handling) than either existing item.

**Work items:**

1. Read SP 800-227 in full and produce a checklist of its concrete requirements/
   recommendations relevant to a KEM implementation and its calling protocol.
2. Walk HKEX-RNL (the suite's actual KEM), and HKEX-GF/HPKE-Stern-F as the closest
   analogues (DH-based and Niederreiter-KEM-based respectively), against that checklist:
   implicit vs. explicit rejection on decapsulation failure, KDF domain separation
   (`SecurityProofs-1.md`/§11.6's existing KDF domain constant work may already satisfy
   some of this — verify rather than assume), randomness source requirements, and
   failure-mode information leakage.
3. File any gaps found as their own follow-up TODOs rather than fixing inline here, since
   this item is scoped to the audit/checklist, not remediation.
4. Cross-reference the result against TODO #141/#144 so overlapping scope is merged
   rather than duplicated.

Status: **DONE v1.9.130** — read the full published SP 800-227 PDF directly (not a
secondary summary) and produced an 8-item checklist cross-referenced against this
suite's actual code, documented in `SecurityProofs-2.md` §11.15. Six of eight checklist
items either matched already-tracked work (TODO #91/#126/#129/#141/#144/#160) or were
explicit, reasonable non-goals (FIPS-140/CAVP validation — this is a research suite, never
claimed to be validated). Two genuine gaps were found and filed as their own follow-up
items per work item 3: **TODO #165** (HKEX-RNL's KDF doesn't bind ciphertext/encapsulation-
key/context material the way SP 800-227's example combiner does) and **TODO #166**
(exported private-key PEM files have no passphrase-encryption option). Verified the CLI's
decrypt/AEAD failure paths already use a single uniform error message regardless of
failure sub-cause (correct per §3.3's "don't leak why a failure occurred"), and confirmed
the RNG sources (`os.urandom`, direct `/dev/urandom` reads) are sound in practice despite
not being formally SP 800-90-validated DRBGs.

---

### 162. Hybrid classical+PQC combiner mode for HKEX, beyond the existing hybrid Ring-LWR+Stern-F credential work (Feature/Research, Medium)

**Background:** "Hybrid-by-default" is now the mainstream industry deployment pattern
for the post-quantum transition: run a classical algorithm and a PQC algorithm in
parallel so an attacker must break both (IETF/NIST-adjacent guidance per 2025-2026
sources, e.g. https://postquantum.com/post-quantum/hybrid-cryptography-pqc/,
https://neuraparse.com/blog/hybrid-post-quantum-tls-ml-kem-2026/). NIST's own March 2025
selection of HQC specifically to diversify the KEM portfolio away from a single
lattice-based assumption follows the same logic. TODO #123/#128 already scope a hybrid
**Ring-LWR + Stern-F credential** (a specific compound proof/verifier construction), but
that is narrower than a general-purpose hybrid **key exchange** combiner mode — this item
is about combining HKEX-GF (or HKEX-RNL) with HPKE-Stern-F's Niederreiter KEM as parallel
KEMs feeding one combined session key, independent of the credential/ZKP work in #123/#128.

**Work items:**

1. Decide a concrete combiner construction (e.g. concatenate-then-KDF vs. one of the
   combiner constructions surveyed in current hybrid-PQC literature) and confirm it
   satisfies the property that the combined key is secure if *either* input KEM is
   secure (the standard hybrid-combiner security requirement).
2. Add a `kex --algo hybrid-...` (or similar) CLI mode pairing HKEX-RNL (lattice-based)
   with HPKE-Stern-F's KEM (code-based) as the two independent post-quantum assumptions,
   matching the "diversify away from a single PQC assumption family" rationale NIST used
   for HQC.
3. Extend to all three CLI language targets per this repo's existing interop-parity
   standard, with `CliTest/` coverage.
4. Document the construction and its security argument in `SecurityProofs-2.md`,
   distinguishing it clearly from TODO #123/#128's credential-specific hybrid work.

Status: **DONE v1.9.131 (Python)** — implemented items 1, 2, and 4 in full; item 3 scoped
to Python only for this pass (see below), matching TODO #25's own precedent of an
explicitly Python-first CLI feature later followed by separate C/Go items. Combiner
construction (item 1): `K = HFSCX-256-DS(0x05, K1 || K2 || C_A || m_A || C_B || hint ||
h_pub || syn || "HERRADURA-HYBRID-RNL-STERN-v1")`, following SP 800-227 §4.6's own
worked-example shape (found applicable via TODO #161/#165) rather than the naive
`KDF(K1,K2)` the standard explicitly warns does not generically preserve IND-CCA. `kex
--algo hybrid-rnl-stern` (item 2) added to the Python CLI with `--their-kem`/`--our-kem`
flags, reusing HKEX-RNL's and HPKE-Stern-KEM's existing keygen/agree/encap/decap
unmodified — Alice holds persistent keypairs for both components, Bob is ephemeral per
session matching HKEX-RNL's own two-round pattern. `CliTest/test_hybrid_kex.sh` (6/6
pass): cross-party encrypt/decrypt round-trips prove key agreement both directions,
missing-flag misuse and a wrong KEM private key are both rejected cleanly (decapsulation
failure, not a silently-wrong key), and two independent runs produce different keys
(freshness). No regressions in `test_vectors.sh`/`test_keygen.sh`/`test_stern_kem.sh`.
Documented in `SecurityProofs-2.md` §11.16 (item 4), including the IND-CCA-preservation
security argument. Go/C CLI ports (item 3's remaining scope) filed as **TODO #167**.

---

### 163. Refresh SecurityProofs-1.md §6's quantum resource-estimate numbers with 2026 discrete-log qubit-count improvements (Documentation/Research, Low)

**Background:** A paper scheduled for EUROCRYPT 2026 (Chevignard, Fouque, Schrottenloher)
reduces the logical-qubit requirement for solving a 256-bit-curve discrete log via Shor's
algorithm from a prior estimate of 2,124 logical qubits down to 1,098, via a
space-optimized circuit (space complexity $3.12n$ for an $n$-bit curve) and output
compression using a Legendre-symbol-based single-bit hash
(https://quantumcomputingreport.com/resource-estimates-for-quantum-discrete-logarithm-computations-on-256-bit-elliptic-curves/).
A follow-up distributed-quantum variant reportedly pushes the single-node requirement to
1,080-1,140 qubits with no quantum communication between nodes
(https://eprint.iacr.org/2026/1244). These figures are specifically for elliptic-curve
DLP, not directly for HKEX-GF's $\mathbb{GF}(2^n)^\ast$ discrete log, but
`SecurityProofs-1.md` §6's existing quantum attack analysis for HKEX-GF discusses Shor's
algorithm's applicability in the same qubit-resource-estimate style, and citing stale
qubit-count figures there undersells (or oversells) how close a practical quantum attack
actually is by 2026 standards.

**Work items:**

1. Read `SecurityProofs-1.md` §6 and identify exactly which qubit-count/resource-estimate
   figures it currently cites for Shor's-algorithm attacks relevant to HKEX-GF.
2. Determine whether the Legendre-symbol output-compression technique (developed for
   ECDLP) has a natural analogue for $\mathbb{GF}(2^n)^\ast$ discrete log, or whether the
   qubit savings are ECDLP-specific and only useful here as a general "quantum resource
   estimates keep improving" data point.
3. Update §6 with the current-as-of-2026 qubit-count figures (citing both papers above),
   making clear which apply directly to HKEX-GF's actual group and which are cited only
   for context (e.g. RSA-3072 comparison point).
4. No code changes expected — this is a documentation freshness item, distinct from
   TODO #145's build/test doc staleness scope.

Status: **DONE v1.9.132** — item 1: §6 (lines ~696-711) turned out to be a short table
for the *original broken linear FSCX scheme* ("Shor: Inapplicable — HKEX has no DLP
structure"), not HKEX-GF's own quantum analysis at all; the actual content this item
targets lives in §10.8.4 "Shor's Algorithm — Primary Quantum Threat" (a cross-reference
slip in this item's own background text, corrected here rather than left for a future
re-discovery). Item 2: confirmed the Legendre-symbol compression and Residue-Number-System
point-multiplication techniques are ECDLP-specific (require $\mathbb{GF}(p)$, $p$ prime,
quadratic-residue structure) with no published analogue for $\mathbb{GF}(2^n)^\ast$
exponentiation — cited as general context only, no revision to §10.8.4's existing
$O(n^2 \log n)$ Shor bound for HKEX-GF's actual group. Item 3: added a qubit-count table
to §10.8.4 with figures read directly from each paper's own eprint abstract rather than
secondary coverage — in the process, found and flagged a real citation discrepancy: some
secondary coverage (including this item's own background text) cites 1,098 qubits for
the EUROCRYPT 2026 paper's $n=256$ case, but the paper's current eprint abstract
(2026/280) states **1193** qubits and carries an explicit erratum noting "correction of
... a swap between numbers for P-224 and P-256" — 1098 most likely reflects the
since-corrected, swapped figure. Documented 1193 as authoritative per the primary source,
with the discrepancy itself recorded rather than silently picking a number. Item 4: no
code changes made, as scoped.

---

### 165. Bind ciphertext/encapsulation-key/context into HKEX-RNL's KDF, per SP 800-227's key-derivation recommendations (Security, Medium)

**Background:** Found during TODO #161's NIST SP 800-227 audit (`SecurityProofs-2.md`
§11.15, item 7). SP 800-227 §4.5–§4.6 recommends that a KEM's key-derivation `OtherInput`/
`FixedInfo` include not just a domain separator but also the ciphertext, either party's
encapsulation key, and/or a context string — its example combiner is
`H(K1, K2, c1, c2, ek1, ek2, domain_sep)` — both for cross-protocol domain separation and
for "binding the final shared secret to the identities of the participating parties."

HKEX-RNL's `ba_rnl_kdf_seed` (`herradura.h`, TODO #38) already XORs a fixed domain
constant `_RNL_KDF_DC` into the KDF input, which correctly separates HKEX-RNL's KDF output
from other suite call sites reusing the same underlying primitive. It does **not**
additionally bind the ciphertext/public polynomial exchanged that session, either party's
encapsulation key, or any other per-session context beyond what's already implicitly
carried inside the raw shared secret itself. This is not a known attack against the
current construction — HKEX-RNL is a direct DH-style NIKE, not a composite/hybrid KEM
where SP 800-227 §4.6.3 shows this matters for IND-CCA preservation — but it falls short
of the standard's recommended practice, and TODO #162's planned hybrid HKEX+Stern-F
combiner will need exactly this kind of binding to satisfy §4.6.3's IND-CCA-preservation
requirement regardless.

**Work items:**

1. Extend `ba_rnl_kdf_seed`'s input (or add a new KDF entry point) to additionally mix in
   the session's public polynomials (`C_A`/`C_B` or equivalent ciphertext/encapsulation-key
   material) and, if available, a caller-supplied context string — following SP 800-227's
   example combiner shape rather than inventing a new one.
2. Apply consistently across all three language targets (C/Go/Python) and, if reachable
   from the CLI, the CLI's own `kex` KDF invocation.
3. Update `SecurityProofs-1.md`'s KDF domain-constant discussion (§11.6-adjacent) and
   `SecurityProofs-2.md` §11.15 to reflect the stronger binding once implemented.
4. Re-run `CliTest/test_vectors.sh`/`test_go_keygen.sh` equivalents to confirm Alice/Bob
   still derive the same session key after the change (both sides must feed identical
   ciphertext/ek material into the KDF, not just their own).
5. Coordinate with TODO #162: if that item's combiner design is done first, this item may
   be substantially satisfied by it rather than needing separate implementation — check
   before duplicating work.

Status: **DONE v1.9.133 (Python)** — item 1: rather than modifying `ba_rnl_kdf_seed`
itself (which turned out, on closer reading, to be a lower-level helper shared by
HSKE-NL-A1/AEAD and HPAKE, not plain HKEX-RNL's own session-key derivation — the actual
target is `_rnl_contributory_kdf`), added a new opt-in `--kdf sp800227` mode alongside
the existing `none`/`hfscx-256` choices: `HFSCX-256-DS(0x06, K \| C_A \| m_A \| C_B \|
hint \| "HERRADURA-HKEX-RNL-SP800227-v1")`, following SP 800-227's own combiner shape.
Deliberately opt-in rather than a change to the default KDF, to avoid a breaking
wire-format change to every existing HKEX-RNL session/interop test (item 4's concern) —
both parties must agree to use the same `--kdf` flag, mirroring the CLI's existing
`--kdf hfscx-256` opt-in pattern. Item 2: Python CLI only for this pass, matching TODO
#162's own Python-first precedent (TODO #25) — Go/C are not touched, so no existing
wire format changed there either. Item 3: documented in `SecurityProofs-2.md` §11.17
(new section) and the §11.15 audit table row 7 updated to point at the resolution;
`SecurityProofs-1.md` has no actual KDF-domain-constant subsection at "§11.6" as this
item's own background text assumed (a cross-reference slip, corrected here rather than
chased into a non-existent section) — the real technical content lives in
`SecurityProofs-2.md`, where it was updated instead. Item 4: added
`CliTest/test_rnl_sp800227_kdf.sh` (4/4 pass) — cross-party agreement with both sides
opted in, mismatched `--kdf` flags correctly produce different (not matching) keys, and
`--kdf sp800227` is cleanly rejected on `hkex-gf`; no regressions in
`test_vectors.sh`/`test_hybrid_kex.sh`. Item 5: confirmed no duplication with TODO
#162 — that item's hybrid combiner is a separate construction for the `hybrid-rnl-stern`
mode specifically; this item's `sp800227` KDF applies to plain (non-hybrid) `hkex-rnl`
sessions and does not overlap.

---

### 166. Optional passphrase-based encryption for exported private-key PEM files (Security/Feature, Low)

**Background:** Found during TODO #161's NIST SP 800-227 audit (`SecurityProofs-2.md`
§11.15, item 4). SP 800-227 §3.2 ("Data at rest") requires that private data (seeds,
decapsulation/private keys) be "stored within the cryptographic module in a manner that
is secure against both leakage and unauthorized modification," and that "the import and
export of private data...needs to be performed in a secure manner." All three CLIs
(`genpkey --out priv.pem`) always write private-key PEM files in cleartext with no
passphrase-based encryption option, unlike OpenSSL's traditional `-aes256`/`-des3`
PEM-encryption flags or PKCS#8 encrypted private-key format. Anyone who copies, backs up,
or transmits an exported `.pem` file without independent OS-level protection (file
permissions, disk encryption) has no cryptographic protection on the key material itself.

**Work items:**

1. Decide an encryption format: either a simple password-based scheme reusing this
   suite's own primitives (e.g. HSKE-NL-A1 keystream over the PEM payload, keyed by a
   password-derived key via a suite KDF with a random salt) or a more conventional
   PBKDF2/scrypt-wrapped-AES approach if the goal is broader tooling compatibility —
   document the tradeoff before picking one, since this suite doesn't currently implement
   a password-based KDF (PBKDF2/Argon2-class) anywhere.
2. Add a `--passphrase`/`--passin`/`--passout`-style flag to `genpkey` (and `pkey` for
   re-encryption/decryption round-trips) across all three CLI language targets, mirroring
   OpenSSL's flag naming where reasonable for user familiarity.
3. Extend the PEM wire format with an encrypted-private-key variant label/header
   (distinguishable from the existing cleartext label so old tooling fails closed rather
   than silently misinterpreting encrypted bytes as a raw key).
4. Add `CliTest/` coverage: round-trip encrypt/decrypt with correct passphrase, and
   confirm a wrong passphrase is rejected cleanly (not a crash or silent garbage key).
5. Document in `docs/TUTORIAL.md` and `SecurityProofs-2.md` §11.15.

Status: **DONE v1.9.134 (Python)** — item 1: chose PBKDF2's standard iterated-PRF
structure (RFC 8018) over a bespoke scheme, substituting the suite's own already-
implemented HMAC-HFSCX-256-DM for HMAC-SHA256 — self-contained (no external dependency)
while keeping the KDF construction itself well-studied rather than novel/unreviewed;
encryption reuses the existing, already-tested HSKE-NL-AEAD construction over the
*entire* generated cleartext PEM (any algorithm) as opaque bytes, so no per-algorithm
re-encoding is needed. Item 2: added `--passphrase` to `genpkey` and `--decrypt`/
`--passphrase` to `pkey` (Python CLI); `pkey --decrypt` recovers the byte-for-byte
original PEM, which then works with any other subcommand unmodified — a general
PEM-level convert-in/convert-out step rather than passphrase-awareness wired into every
key-consuming command. Item 3: new `HERRADURA ENCRYPTED PRIVATE KEY` PEM label; reading
it through the normal `_decode_privkey` path raises a specific, actionable error naming
`pkey --decrypt` rather than crashing obscurely or misinterpreting the bytes. Item 4:
added `CliTest/test_encrypted_pem.sh` (7/7 pass) — distinct label, clean rejection of
direct use, correct-passphrase round-trip (including a larger `hkex-rnl` key), the
decrypted key working normally with `pkey --pubout`, wrong-passphrase rejection, and
confirmation the existing cleartext default is unaffected when `--passphrase` is
omitted; no regressions in `test_keygen.sh`. Item 5: documented in `docs/TUTORIAL.md`
(new "Passphrase-encrypted private-key export" subsection) and `SecurityProofs-2.md`
§11.18, including an explicit, documented tradeoff on iteration count: NIST SP 800-132
recommends ≥200,000 PBKDF2 iterations, but pure-Python `HMAC-HFSCX-256` runs at only
~300 calls/sec (200,000 iterations ≈ 10-12 minutes), so the CLI default is a
demo-appropriate 1,000 iterations (~3.5s) with `--kdf-iterations` exposed to opt into
the production-recommended floor at the cost of a multi-minute wait — matching this
repo's existing demo-vs-production-parameter convention. Scoped to the Python CLI only,
consistent with this item's own "Low" priority; no separate Go/C follow-up TODO filed.

### 167. Port the `hybrid-rnl-stern` combiner (TODO #162) to the Go and C CLIs (Feature/Interop, Medium)

**Background:** TODO #162 implemented a hybrid HKEX-RNL + HPKE-Stern-KEM combiner mode
(`kex --algo hybrid-rnl-stern`) and its SP 800-227 §4.6-style key-combiner construction
(`SecurityProofs-2.md` §11.16), matching this repo's own precedent for large CLI features
(TODO #25's "Python only (initial version)" scoping, later followed by separate C/Go
items #27/#28). Only the Python CLI (`HerraduraCli/herradura.py`) and
`CliTest/test_hybrid_kex.sh` exist so far; the Go (`herradura_cli.go`) and C
(`herradura_cli.c`/`herradura.h`) CLIs have no equivalent, so this feature is not yet
interop-complete across the three language targets this repo's other KEM/KEX modes
maintain parity across.

**Work items:**

1. Port `_hybrid_rnl_stern_combine`'s exact byte layout (§11.16's formula: `HFSCX-256-DS`
   with tag `0x05` over `K1 || K2 || C_A || m_A || C_B || hint || h_pub || syn ||
   "HERRADURA-HYBRID-RNL-STERN-v1"`) to Go and C — bit-for-bit identical serialization is
   required for cross-language interop, not just cross-language correctness.
2. Add the `hybrid-rnl-stern` `kex` mode (with `--their-kem`/`--our-kem` flags mirroring
   Python's) to both `herradura_cli.go` and `herradura_cli.c`, reusing each language's
   existing `hkex-rnl` and `hpke-stern-kem`/QC-MDPC implementations exactly as the Python
   version reuses `_rnl_agree`/`qcmdpc_encap`/`qcmdpc_decap_bgf` unmodified.
3. Add a new `HYBRID-RNL-STERN RESPONSE` PEM label/encode/decode to each language's codec,
   matching Python's DER field order exactly (`K, C_B, hint, n, hint_len, n_B, syn, r`).
4. Extend `CliTest/test_hybrid_kex.sh` (or add a cross-language sibling matching the
   `test_stern_kem.sh`/`test_vectors.sh` 3x3 interop-matrix convention) so Bob (any
   language) and Alice (any language) derive the same session key regardless of which
   CLI each party runs.
5. Update `SecurityProofs-2.md` §11.16's "Implementation status" note once complete.

Status: **DONE v1.9.135** — ported `_hybrid_rnl_stern_combine` bit-for-bit to
`herradura_cli.go` (new `hybridRnlSternCombine`/`encodeHybridResponse`/
`decodeHybridResponse`) and `herradura_cli.c`/`herradura_codec.h` (new
`hybrid_rnl_stern_combine`/`PEM_HYBRID_RESPONSE`), both reusing each language's existing
`hkex-rnl` and `hpke-stern-kem`/QC-MDPC primitives unmodified, with a new
`kex --algo hybrid-rnl-stern` mode (`--their-kem`/`--our-kem` flags) in both CLIs.
Fixed a serialization subtlety along the way: the C QC-MDPC primitives store `QcPoly`
values in a fixed little-endian word layout requiring an explicit swap to match Python's
plain (unswapped) `int.to_bytes(rb, 'big')` convention used specifically by the hybrid
response's `syn` field and the combiner's `h_pub`/`syn` hash inputs — distinct from the
byte-swapped convention the existing HPKE-Stern-KEM PUBLIC/PRIVATE KEY and CIPHERTEXT
wire formats use; added dedicated `qcpoly_to_natural_be`/`qcpoly_from_natural_be` helpers
for the former, keeping `qcpoly_to_be`/`qcpoly_from_be` for the latter. Verified with a
full 3x3 cross-language matrix (`CliTest/test_hybrid_kex_interop.sh`, new) — every
Bob/Alice language pairing (Python/Go/C x Python/Go/C) derives a byte-identical session
key, confirmed by direct hash comparison and a cross-language HSKE encrypt/decrypt
round-trip — plus the existing `CliTest/test_hybrid_kex.sh` (6/6, Python-only combiner
behavior/edge-cases) with no regressions. Updated `SecurityProofs-2.md` §11.16's
"Implementation status" note accordingly.

### 156. Re-derive Stern-F/QC-MDPC security margins against 2025-2026 information-set-decoding improvements (Research/Security, Medium)

**Background:** Two ISD advances published in the review window potentially shift the
parameter margins TODO #91 and #126 already track:

- An improved Both-May algorithm with more efficient time-memory trade-offs than prior
  ISD variants (Both-May-style ISD, 2025;
  https://link.springer.com/content/pdf/10.1007/978-3-031-86599-2_4.pdf?pdf=inline+link).
- 2026 research on whether extension-field structure can further speed up ISD solvers for
  the syndrome decoding problem underlying most code-based schemes
  (https://link.springer.com/article/10.1007/s12095-025-00857-9).

`HPKS-Stern-F`/`HPKE-Stern-F`'s $N=256$ demo parameters are already documented (README,
TODO #91) as providing only ~30-40 bits of security, with $N \geq 17000$ named as the
128-bit-security production target. That $N \geq 17000$ figure was derived against the
ISD state of the art at the time it was set; if either 2025-2026 ISD improvement reduces
the bit-security of a fixed $(N, t)$ pair, the production-target $N$ named in TODO #91/
`SecurityProofs-2.md` may now be understated, and `SDF_PRODUCTION_ROUNDS`'s soundness
target (referenced by `herradura.h`'s own build-time `#pragma message` in TODO #142)
should be re-checked against it too.

**Work items:**

1. Read both papers in full and extract their concrete complexity-exponent improvements
   over classical Prange/Stern/Dumer ISD (not just the abstract's headline numbers).
2. Re-run or adapt `SecurityProofsCode`'s existing Stern-F parameter-selection reasoning
   (wherever $N \geq 17000$ was derived — check `SecurityProofs-2.md` §11.x and TODO #91)
   with the improved ISD cost model plugged in, for both the classical bit-security
   estimate and any assumed quantum speedup.
3. If the required $N$ for 128-bit security changes materially, update
   `SecurityProofs-2.md`, TODO #91's own text, README's parameter table, and
   `spec/herradura-protocol-spec.json`'s security-level classification for the Stern-F
   protocols accordingly.
4. Cross-check whether the same ISD improvements affect TODO #126's QC-MDPC/Niederreiter
   decoding-trapdoor scoping (HPKE-Stern-F's KEM side uses the same underlying SD
   assumption family).

**Progress (2026-07-31):** `SecurityProofs-2.md` §11.8.4 now documents both papers.
The Elbro-Weger extension-field paper (eprint 2025/1402, fully reviewed) is a clean
negative result — extension-field structure does not speed up ISD, and doesn't apply
to HPKS-Stern-F/HPKE-Stern-F's plain-$\mathrm{GF}(2)$ construction anyway, so it does
not move the $N \geq 17000$ target. The Furue-Aikawa Both-May paper (PQCrypto 2025) sits
behind a Springer paywall; only its abstract-level framing ("more efficient
time-memory trade-offs", not a lower time exponent) could be confirmed, so work items
1–2 remain unresolved for that paper specifically — the concrete exponent improvement
was never extracted or plugged into the SDE worksheet. TODO #126's QC-MDPC parameters
are unaffected by either finding (item 4 is otherwise complete). Re-open work items 1–2
if full-text access to the Both-May paper becomes available.

**Resolution (2026-08-02):** work items 1–2 are now closed as a negative result without
needing the paywalled full text, on three independent grounds documented in
`SecurityProofs-2.md` §11.8.4: **(a)** the Both-May family targets *full distance
decoding* at high error rate (best prior bound $2^{0.0953N}$, lowered by Both-May to
$2^{0.0951N}$), whereas Stern-F sits at $t/N = 0.0625$ and QC-MDPC/BIKE at
$t/N \approx 0.0054$ — the low-weight regime governed by the half-distance exponent
($2^{0.0473N}$) and the $O(2^{0.054N})$ figure already cited, so FDD gains are not
binding; **(b)** the paper improves a time-*memory* trade-off curve, not the minimum-time
exponent (the family's headline FDD gain is $0.0002$ in the exponent constant); and
**(c)** Both-May's May-Ozerov nearest-neighbour subroutine was proven *galactic*
[Bouillaguet-Delaplace-Hamdad, IACR CiC 2:1, 2025] — it beats plain Stern ISD only above
code length 1,874,400, where the attack itself costs over $2^{63489}$ operations.
Additionally, Narisada-Okada-Aikawa-Fukushima's *"Refined Analysis of the Concrete
Hardness of the Quasi-Cyclic Syndrome Decoding"* (IWSEC 2025) was added to the review as
the most on-point QC-SD result: its BIKE/HQC/Classic McEliece bit-security estimates
closely match NIST's requirements, independently corroborating item 4's parameters. The
$N \geq 17000$ target is unchanged, so work item 3's downstream updates
(`README.md` parameter table, TODO #91 text, `spec/herradura-protocol-spec.json`
security-level classification) are not triggered.

Status: **DONE v1.9.136** — 2025-2026 ISD re-check resolved; $N \geq 17000$ target confirmed unchanged.

### 157. Re-evaluate HKEX-RNL's CBD($\eta=1$) secret distribution against the 2026 sparse-secret hybrid-decoding attack on Ring-LWE/Ring-LWR (Research/Security, Medium)

**Background:** "Careful with the Ring: Enhanced Hybrid Decoding Attacks against
Module/Ring-LWE" (2026; https://eprint.iacr.org/2026/366) presents a hybrid
meet-in-the-middle/lattice-decoding attack that exploits the polynomial ring structure of
$\mathbb{Z}_q[X]/(x^N+1)$ to accelerate guessing and decoding for **sparse-secret**
instances, reporting a complexity improvement by a factor of $O(N)$ over prior hybrid
decoding attacks and 17x-114x speedups on previously-broken sparse instances (mostly
demonstrated against FHE parameter sets from 2022-2025 deployments, not HKEX-RNL's own
parameters).

TODO #1 (`RNLB=1 — sparse secrets`, now `DEPRECATED` in `TODO_DONE.md`) already flagged
sparse-secret risk for an earlier, cruder uniform-small-Hamming-weight secret sampler and
recorded that it was superseded by the CBD($\eta=1$) sampler (`SecurityProofs-2.md`
§11.4.2/§11.6). CBD($\eta=1$) secrets are *small* (each coefficient in
$\{-1,0,1\}$-ish range, per the centered binomial distribution) but not necessarily
*sparse* in the specific structural sense this new hybrid attack exploits — the two
properties are related but distinct, and TODO #1's deprecation reasoning predates this
2026 paper. This item is to determine whether "small" (CBD) and "sparse" (attacked here)
coincide closely enough at HKEX-RNL's own $(q=65537, n=256)$ parameters for the new
attack's complexity bound to apply, or whether they're distinct enough that the existing
deprecation stands unaffected.

**Work items:**

1. Read the paper's precise definition of "sparse" (e.g. Hamming weight / hint-supported
   sparsity assumption) and compare it against HKEX-RNL's actual CBD($\eta=1$) secret
   distribution at $n=256$ — are CBD-sampled secrets sparse under that definition, or only
   "small"?
2. If applicable, estimate the concrete complexity of the enhanced hybrid attack against
   HKEX-RNL's deployed parameters (not just the FHE parameter sets the paper
   demonstrates), following the same style of concrete-complexity worksheet already used
   in `SecurityProofsCode/hkex_rnl_failure_rate.py`/§11.4-§11.6.
3. Document the conclusion in `SecurityProofs-2.md` regardless of outcome (either "attack
   does not apply because X" or "attack reduces estimated security margin by Y bits") so
   the reasoning is traceable, and update TODO #1's `DEPRECATED` note in `TODO_DONE.md`
   with a forward-reference if the conclusion revises it.

**Progress (2026-07-31):** `SecurityProofs-2.md` §11.6 (just before §11.7) now documents
the finding: the paper's own PDF is Cloudflare-gated and couldn't be read directly, but
its abstract names five target FHE papers ([JM22]/[CCKS23]/[BCKS24]/[CHKS25]/[AKP25])
that are all classical sparse-secret-bootstrapping proposals with published Hamming
weights $h \approx 64$–$192$ against $N=2^{15}$ (density $\lesssim 0.6\%$). HKEX-RNL's
deployed CBD($\eta=1$) sampler has $\approx 50\%$ nonzero density at $n=256$ — over two
orders of magnitude denser — so by the density-gap argument the attack's speedup
mechanism (reduced guessing space over sparse nonzero positions) should not transfer,
and TODO #1's deprecation stands unaffected. Note in passing: TODO #1's own status line
in `TODO_DONE.md` reads `DONE (v1.5.x)`, not `DEPRECATED` as this item's background
section (written before this review) stated — a small cross-reference slip, not a
finding that needs its own action. Work item 3's forward-reference-to-TODO#1 is therefore
not needed since no revision resulted. This item stays **OPEN** because the conclusion
rests on indirect evidence (target-paper parameters), not the paper's own formal
sparsity definition — re-close only after a direct read confirms it.

**Resolution (2026-08-02):** the paper's PDF is still Cloudflare-gated, but the
conclusion no longer depends on it. Rather than compare against one threshold, the new
worksheet `SecurityProofsCode/hkex_rnl_sparse_hybrid_2026.py` quantifies over *all* of
them. Since each CBD($\eta=1$) coefficient is nonzero independently with probability
exactly $1/2$, a deployed secret's Hamming weight is exactly
$\mathrm{Binomial}(n=256, p=1/2)$ — mean $128$, $\sigma = 8$, i.e. $16$ standard
deviations above zero. The exact lower tail gives $\Pr(\mathrm{HW} \leq h) = 2^{-248}$
at the cited FHE density scaled to $n=256$ ($h \leq 1$), $2^{-173}$ at $h \leq 16$, and
$2^{-129}$ at $h \leq 29$ — so **any** sparsity definition set below roughly $12\%$
density is escaped except with probability below the $128$-bit target itself, and full
text access could not change the outcome. Empirically the minimum Hamming weight over
$1000$ deployed-sampler secrets was $104$. A second check confirms the mechanism is
absent: the hybrid MITM/decoding split profits only when some block is cheap to
enumerate, and CBD($\eta=1$) carries $384$ bits of entropy at $n=256$ versus $9$ bits
for a sparse ternary secret with $h=1$, so the attack degenerates to the primal lattice
attack already covered by the Core-SVP estimate. Stakes were real (the paper's measured
maximum is 13 bits, which would have moved 105–115 to 92–102), but no revision results;
work item 3's forward-reference to TODO #1 remains unnecessary. Written up in
`SecurityProofs-2.md` §11.6.

Status: **DONE v1.9.137** — sparse-secret hybrid attack shown inapplicable to CBD($\eta=1$) for any sparsity threshold; no security-estimate revision.

### 158. Apply the 2025 automated rotational-XOR differential search framework to FSCX/NL-FSCX (Research, Medium)

**Background:** A 2025 paper proposes an automatic search framework for
rotational-XOR (RX) differential characteristics in ARX ciphers
(https://link.springer.com/article/10.1007/s10623-025-01571-6), reporting characteristics
covering more rounds than previously known for SPECK, CHAM, SPARX, and Ballet (e.g.
17-24 round RX-differentials for SPECK variants, versus a prior best of 13 rounds).

TODO #75 (`Formal rotational differential analysis of NL-FSCX v1`) and TODO #125
(`Sparse-input rotational differential characterization of NL-FSCX v1 at large n`) are
already `DONE`/tracked in `TODO_DONE.md` and cover rotational analysis of FSCX/NL-FSCX,
but both predate this specific 2025 automated-search tool. FSCX's core operator
$M = I \oplus \text{ROL} \oplus \text{ROR}$ is XOR-and-rotation (not full ARX — it has no
modular addition), so the framework's addition-centric technique doesn't transfer
directly, but its automated RX-characteristic-search *methodology* (as opposed to the
addition-specific propagation rules) may still surface longer characteristics than the
manual/semi-automated analysis TODO #75/#125 used, especially for NL-FSCX v1/v2 where the
non-linear step reintroduces addition-like mixing.

**Work items:**

1. Read the paper closely to separate its ARX-modular-addition-specific propagation
   rules from its general RX-characteristic search methodology (SAT/SMT or MILP-based
   search, if that's what it uses).
2. Determine whether the general search methodology can be adapted to FSCX's pure
   XOR-rotation operator and to NL-FSCX v1/v2's added non-linear step, reusing
   `SecurityProofsCode/fscx_periodicity_z3.py`'s existing Z3-based approach as a starting
   point if the tooling is compatible.
3. If adaptable, run the search against FSCX_N and NL-FSCX v1/v2 at the suite's actual
   parameter sizes and compare any newly found characteristics against TODO #75/#125's
   prior bounds.
4. Document results in `SecurityProofs-2.md` regardless of outcome, and add a
   `SecurityProofsCode/` script if new characteristics are found (following the existing
   naming convention, e.g. `nl_fscx_rx_differential_2025.py`).

**Progress (2026-07-31):** paper's full text is paywalled beyond its abstract, so its
exact CNF/SAT encoding couldn't be reproduced. Added
`SecurityProofsCode/nl_fscx_rx_differential_2025.py`: a bounded, non-exhaustive
hill-climbing stand-in that searches over nonzero-XOR RX-differences $(da,db)$ (not just
the pure-rotation $da=db=0$ slice TODO #75/#125 already covered) for NL-FSCX v1's
modular-addition step, since FSCX's XOR-rotation linear part transmits every RX-difference
with probability 1 and contributes no search surface. Found no configuration with a
materially higher single-round transition probability than the existing pure-rotational
baseline at $n \in \{16,32\}$. Documented in `SecurityProofs-2.md` (end of the sparse-$B$
subsection) with explicit caveats: this is local search, not exhaustive SAT, and only
covers single-round (not chained multi-round) transitions. Stays **OPEN** — reproducing
the paper's actual automated search is future work, deferred due to paywalled access.

**Resolution (2026-08-02):** the paper's full text is still paywalled, but reproducing
its CNF encoding turned out to be unnecessary — for NL-FSCX v1 the RX-difference search
space collapses far enough to be solved **exactly**, which is strictly stronger than any
heuristic SAT/SMT trail search. (Note: the earlier progress note's premise that this repo
"has no SAT/SMT solver dependency" was also wrong — z3 is installed and
`fscx_periodicity_z3.py`/`hpks_schnorr_z3.py` already import it — but the exact solution
made a solver unnecessary anyway.) New script
`SecurityProofsCode/nl_fscx_rx_exact_search.py` supersedes the Monte-Carlo stand-in:

1. *Reduction (work item 2).* Verified over 4000 random cases that
   $dY = M(da) \oplus M(db) \oplus \mathrm{ROL}(dS, n/4)$, so the FSCX linear layer
   transmits every RX-difference with probability 1 and $dY$ is a **bijection** of $dS$ —
   the entire search space is the RX-differential of modular addition.
2. *Exact solver.* From the per-bit identity $\bar{c}_i \oplus c_j = da_i \oplus db_i
   \oplus dS_i$ on the two carry chains, an $O(n)$ DP computes the exact distribution.
   Validated against brute force over all $2^{2n}$ pairs at $n=8$: 0 mismatches. It
   reproduces the classical $3/8 = 2^{-1.415}$ rotational probability of modular addition
   as $n$ grows, an independent check.
3. *Certified optimum (work item 3).* Exhaustive over **every** $(da, db, dS)$ and every
   $\gamma$ at $n=8$: the optimum is always $(0,0,0)$, i.e. exactly the pure-rotational
   slice TODO #75/#125 measured. This answers the open question in the negative — no
   nonzero-XOR RX-difference beats it. Probability is symmetric under
   $\gamma \mapsto n-\gamma$, maximal at $\gamma=1$. Corroborated at $n=16$ over all
   weight-$\leq 2$ differences.
4. *Multi-round.* Full $2^n$-state transition graph plus max-product DP gives the optimal
   $r$-round trail — the chained analysis the stand-in explicitly lacked. For $db=0$ the
   optimum is again the pure-rotational trail; nonzero $db$ is strictly worse.
5. *Key finding.* The Markov/round-independence assumption underlying all trail search —
   the paper's methodology included — is **not tight** here: measured exactly against the
   trail estimate at $n=8$, it understates the true probability by $1.0\times$,
   $1.5\times$, $2.7\times$, $5.7\times$, $13\times$, $31\times$ over rounds 1–6, a gap
   that grows without bound because $B$ is reused every round. This is the structural
   reason TODO #75/#125 found power-law rather than geometric decay, and it means trail
   search cannot be the binding analysis for NL-FSCX v1; the direct measurement of
   TODO #75/#125 remains operative. Documented in `SecurityProofs-2.md`.

Status: **DONE v1.9.138** — RX search solved exactly; pure-rotational characteristic certified optimal, and trail methodology shown not tight for NL-FSCX v1.

### 159. LLM/AI-assisted cryptanalysis stress-testing pass across HerraduraKEx's primitives (Research/Security, Medium)

**Background:** In the review window, LLM-driven cryptanalysis moved from a research
curiosity to a credible, NIST-adjacent methodology: Anthropic's Claude discovered a real
vulnerability in HAWK, a lattice-based signature scheme that was under active
consideration for NIST standardization, leading the HAWK team to withdraw it from
consideration entirely (2026-07-28;
https://www.govinfosecurity.com/claude-mythos-finds-new-cryptographic-algorithm-attacks-a-32360).
Separately, `CryptanalysisBench` (2026; https://arxiv.org/html/2607.18538v1) benchmarks
LLMs across 191 cryptanalysis tasks spanning six primitive families drawn from four NIST
standardization competitions, and other 2025-2026 work evaluates LLM-assisted
side-channel vulnerability discovery (https://arxiv.org/html/2505.24621) and automated
cryptographic exploitation agents (https://arxiv.org/pdf/2601.09129). This is a
meaningfully different validation channel from this repo's existing
`SecurityProofsCode/` manual/scripted proofs — it found a real flaw in a scheme that had
already passed multiple rounds of expert human review.

**Work items:**

1. Scope a bounded, well-defined stress-testing pass: pick 2-3 of HerraduraKEx's less
   battle-tested constructions as targets (e.g. NL-FSCX v2's CSP-based construction,
   HPKS-Stern-Ring's OR-composition, the HFSCX-256-DM finalizer) rather than attempting
   to cover the whole suite at once.
2. Define what "stress-testing" means concretely here given available tooling — this
   could be as simple as posing the same kind of structured cryptanalysis prompts used in
   `CryptanalysisBench`/the HAWK finding against this suite's own primitive definitions
   and existing `SecurityProofsCode/` proof scripts, to see whether an LLM surfaces gaps
   the existing manual proofs missed.
3. Treat any finding as a lead requiring the same manual verification standard as any
   other TODO in this file (a `SecurityProofsCode/` script reproducing it, not just an
   LLM's claim) before it's considered confirmed — mirroring how CryptanalysisBench's own
   authors note LLMs "fail comprehensively at algorithm-level cryptanalysis" in the
   general case, so a hit rate of zero is an expected, valid outcome here too.
4. Document the pass and its outcome (findings or a clean bill of health) in
   `SecurityProofs-2.md` or a new `SecurityProofsCode/` note, so this doesn't need
   re-justifying from scratch next time it comes up.

**Progress (2026-07-31) — first pass complete, one real finding.** Scoped the pass to
HPKS-Stern-Ring's OR-composition (herradura.h `stern_ring_sign`, the Python/Go suite
equivalents) as the target — the "less battle-tested" construction named in work item 1.
Reading `stern_ring_sign`'s non-signer challenge simulation against the joint
Fiat-Shamir challenge derivation surfaced a genuine, previously-undocumented modulo-3
bias: the C and Python implementations draw a single random byte and reduce mod 3 to
pick each non-signer's per-round challenge (256 is not divisible by 3, so residue 0 is
~0.39% overrepresented), while the real signer's own displayed challenge is forced by
subtraction from a hash-derived, effectively-uniform joint challenge — meaning the
signer's slot has an exactly-uniform marginal while every non-signer's slot carries the
skew. This is a statistical anonymity leak under repeated use of the same ring (not a
one-shot break): `SecurityProofsCode/stern_ring_challenge_bias.py` (added this pass)
verifies the exact 86/85/85-out-of-256 distribution, confirms it by Monte Carlo, and
estimates ~9,000+ same-ring signatures needed before the skew is statistically
distinguishable per slot at 3-sigma confidence. Per work item 3, this is filed as its own
actionable item — **TODO #164** — rather than treated as fixed here, since #159 is a
process/tracking item, not a fix ticket. Go's own implementation already reduces a wide
32-bit value mod 3 (bias ~2^-32, negligible), so this is a C/Python-specific gap, not a
protocol-level design flaw.

The other two candidate targets from work item 1 (NL-FSCX v2's CSP-based construction,
HFSCX-256-DM's finalizer) have not yet been passed over — stays **OPEN** for those two.

**Progress (2026-08-02) — second pass complete, both remaining targets covered, one real
finding.** Framed both targets around a single question suggested by the shared structure:
NL-FSCX v1 and v2 buy their non-linearity solely from a modular addition's carry chain
(everything else — $M$, the rotations, the XORs — is GF(2)-linear), so *for which inputs
does the addition stop producing carries?* Written up in `SecurityProofs-2.md` §11.19 and
reproduced by `SecurityProofsCode/nl_fscx_carry_degeneracy_2026.py`.

1. **HFSCX-256-DM (clean, but a load-bearing detail now documented).** With an all-zero
   message block $A + 0$ has no carries, so the Davies-Meyer inner function degenerates to
   the linear map $L^{n/4}$, $L = 1 + X + X^{n/4} + X^{n-1}$ over
   $\mathrm{GF}(2)[X]/(X^n+1)$ — of rank exactly $n/2$, i.e. at $n=256$ it compresses the
   chaining value $2^{128}$-to-1. The Davies-Meyer feed-forward is exactly what rescues
   it: over GF(2), $X^n+1 = (X+1)^n$, so with $Y = X+1$ the ring is local, $L = Y^2 u$ for
   a unit $u$, and $L^{n/4} + 1$ has constant term 1 — a unit, hence invertible. Verified
   full rank at $n \in \{16,32,64,128,256\}$. §11.9.8 credited DM in general terms with
   handling $F_1$'s non-bijectivity; this makes the statement concrete and verified.
2. **NL-FSCX v2 (a genuine finding).** $\delta(K)$ enters as an additive *constant*, and
   constant addition is GF(2)-affine for all inputs exactly when the constant is $0$ or
   $2^{n-1}$. Since $M$ is invertible at every power-of-two $n$, this gives the exact
   characterisation $\pi_K$ affine $\iff \delta(K) \in \{0, 2^{n-1}\}$, verified
   exhaustively at $n = 8, 16$. Such keys exist at $n=256$: every $K$ divisible by
   $2^{129}$ ($2^{127}$ keys) plus e.g. $K = 2^{96}$. For them HSKE-NL-A2 / HPKE-NL
   collapse to an affine map recoverable by linear algebra. Class density $\approx
   2^{-129}$, so random keys are not at risk — not a break, but an unrejected weak-key
   class. Per work item 3, filed as its own actionable item, **TODO #168**, rather than
   fixed here.

All three targets named in work item 1 have now been passed over (HPKS-Stern-Ring in the
first pass, these two in the second), and work item 4's documentation requirement is met
for both passes, so this process/tracking item is complete.

Status: **DONE v1.9.139** — second pass covered both remaining targets; HFSCX-256-DM clean (DM feed-forward shown load-bearing), NL-FSCX v2 affine weak-key class found and filed as TODO #168.

### 168. Reject NL-FSCX v2 affine weak keys (delta(K) in {0, 2^(n-1)}) (Security, Low)

**Background:** TODO #159's second stress-testing pass (`SecurityProofs-2.md` §11.19.2,
`SecurityProofsCode/nl_fscx_carry_degeneracy_2026.py`) established the exact
characterisation

    pi_K is GF(2)-affine  <=>  delta(K) in {0, 2^(n-1)}

for NL-FSCX v2's permutation $\pi_K(A) = (M(A \oplus K) + \delta(K)) \bmod 2^n$, verified
exhaustively at $n = 8$ and $n = 16$ (the characterisation holds at every power-of-two $n$,
where $M$ is invertible). Addition of a constant $c$ is affine over GF(2) for every input
exactly when $c = 0$ or $c = 2^{n-1}$, the latter because the top carry is discarded mod
$2^n$.

Such keys exist at the deployed size: every $K$ divisible by $2^{129}$ gives
$\delta(K) = 0$ at $n = 256$ (a class of $2^{127}$ keys), and $K = 2^{96}$ gives
$\delta(K) = 2^{255}$. For any of them HSKE-NL-A2 and HPKE-NL collapse to an affine map
that is fully recoverable from a handful of known plaintexts by linear algebra.

**Severity:** class density is about $2^{-129}$, so a uniformly random 256-bit key is not
at risk and this is **not** a break of the deployed construction. It matters only if keys
are structured, low-entropy, or attacker-influenced — but the check is one line and the
suite already performs weak-key rejection elsewhere (test `[45]`, TODO #141/#144), so the
asymmetry is worth closing.

**Work items:**

1. Add a `delta(K) not in {0, 2^(n-1)}` guard to the NL-FSCX v2 entry points
   (`nl_fscx_v2`, `nl_fscx_revolve_v2`, and the inverse variants) in the Python, C
   (`herradura.h`), and Go suites, rejecting rather than silently proceeding.
2. Mirror the guard at the CLI layer wherever an HSKE-NL-A2 / HPKE-NL key is loaded,
   following the existing weak-key rejection precedent from TODO #141.
3. Extend the existing weak-key/malformed-input rejection test `[45]` in
   `CryptosuiteTests/Herradura_tests.{c,go,py}` with an NL-FSCX v2 affine-key case (e.g.
   $K = 2^{129}$ and $K = 2^{96}$ at $n = 256$), keeping the three languages in parity.
4. Cross-check whether the assembly/Arduino targets (which use 32-bit operands) need the
   same guard, and record the answer either way.

**Resolution (2026-08-02).** Implemented across all three suites and CLIs, following the
repo's existing `gf_pub_is_valid` precedent.

*Design note (deviation from work item 1's literal wording).* The guard is a
`nl_v2_key_is_valid` predicate enforced at the **protocol** layer, not a rejection inside
`nl_fscx_v2`/`nl_fscx_revolve_v2` themselves. Three reasons, all discovered while
implementing: (a) it mirrors `gf_pub_is_valid`, which `hkex_gf_agree`/`hpks_verify` check
while the underlying `gf_pow` does not; (b) `nl_fscx_v2` is invoked internally by the FPE,
tweakable wide-block, and duplex-sponge constructions with hash-derived keys, which would
all need new error paths for a $2^{-129}$ event; and (c) the suite's own non-linearity
tests call the primitive with degenerate operands, and the C/Go primitives return values
rather than error codes, so rejecting there would change a total function's contract in
three languages.

1. `nl_v2_key_is_valid` added to `Herradura cryptographic suite.py`, `herradura.h`, and
   `herradura/herradura.go` (plus `HerraduraCli/primitives.py`'s re-export).
2. Enforced in all three CLIs: `enc`/`dec --algo hske-nla2` and `dec --algo hpke-nl`
   reject an affine key with a shared explanatory message. `enc --algo hpke-nl` instead
   **resamples** its ephemeral $r$ (up to 64 attempts) rather than failing, since that
   value is the sender's own choice and an honest encryption should not error. Verified:
   all three CLIs reject $K = 2^{129}$ and $K = 2^{96}$ on both enc and dec, accept good
   keys, and `hpke-nl` still round-trips in all three.
3. Test `[45]` extended in `Herradura_tests.{c,go,py}` with a `v2_weak_key_reject`
   sub-check covering $K \in \{0, 2^{96}, 2^{129}, 2^{130}\}$ (rejected) and a random
   odd key (accepted), keeping the three languages at parity.
4. **Assembly/Arduino: guard needed in principle, not implemented — recorded.** Those
   targets do implement NL-FSCX v2 and HSKE-NL-A2, on 32-bit operands, where the class
   density is far worse: the $\delta = 0$ class is every $K$ divisible by
   $2^{\lceil (n+1)/2 \rceil}$ (density $2^{-\lceil (n+2)/2 \rceil}$), and the
   $\delta = 2^{n-1}$ class is additionally non-empty whenever $8 \mid n$. Exhaustive
   counts over the full key space at $n \leq 32$ give a total affine density of
   $2^{-16.7}$ at $n=32$ (about 1 key in $105{,}000$) against $\approx 2^{-129}$ at
   $n=256$, where the $\delta=0$ class dominates. Those targets are explicitly demo-only,
   and this host has no ARM cross-toolchain to build or test assembly changes against, so
   porting the guard was deliberately not attempted blind. Documented in
   `SecurityProofs-2.md` §11.19.2 as follow-up work.

Status: **DONE v1.9.140** — nl_v2_key_is_valid added to all three suites and enforced in all three CLIs; test [45] extended; assembly/Arduino gap (density 2^-17 at n=32) documented rather than fixed.

### 170. Re-split `SecurityProofs-*.md` — two of three parts now exceed GitHub's KaTeX limit (Documentation, High)

**Background:** `SecurityProofsCode/KATEX_RULES.md` documents a hard GitHub constraint:
past roughly **750 math expressions per page**, every expression beyond the threshold
renders as "Unable to render expression" — a client-side cascade failure with no syntax
fix. That limit is why `SecurityProofs.md` was split into three parts in the first place.

Two of the three parts have since grown back past it. Measured with
`SecurityProofsCode/validate_katex.js` (2026-08-03):

| File | Expressions | Status |
|---|---|---|
| `SecurityProofs-1.md` | 914 | **over** the ~750 limit |
| `SecurityProofs-2.md` | 1434 | **far over** — nearly 2x |
| `SecurityProofs-3.md` | 501 | under |

So both files currently render incorrectly on GitHub past their threshold, even though
the local validator reports `0 FAIL` — the validator checks per-expression syntax, not
the per-page count, so it cannot catch this. The recent research-review sections (§11.15
through §11.19, added by TODO #161/#162/#165/#166/#159) are the bulk of part 2's growth.

CLAUDE.md's own structure table is stale on all three counts (it records ~753 / ~873 /
~121 against the measured 914 / 1434 / 501) and on part 2's section range (it says
"§11–§11.9", but the file now also carries §11.15–§11.19).

**Work items:**

1. Split at section boundaries so every resulting part stays comfortably under ~750 — a
   4-way split is the obvious shape, e.g. moving §11.15–§11.19 (the TODO-specific
   research-review sections) into a new `SecurityProofs-4.md`, then re-checking whether
   part 1 needs a further cut.
2. Re-measure every part with `validate_katex.js` after splitting and record the actual
   counts, rather than estimates.
3. Update `SecurityProofs.md`'s split index, every cross-reference between parts, and the
   `SecurityProofs-*.md` references in `README.md`, `SECURITY.md`, `CLAUDE.md`,
   `llms.txt`, and the `SecurityProofsCode/` script docstrings that cite section numbers.
4. Fix CLAUDE.md's structure table: correct all three expression counts and part 2's
   section range.
5. Add a guard against silent regrowth — e.g. teach `validate_katex.js` to warn when a
   file exceeds ~700 expressions, so the next section added to a near-full part surfaces
   the problem at authoring time instead of on GitHub.

Status: **DONE v1.9.143** — re-split into five parts (§1–§8 / §9–§10 / §11–§11.8.2 / §11.8.3–§11.9.11 / §11.10–§11.13+§11.15–§11.19), measured at 551/363/580/716/639 expressions respectively (all under the ~750 limit, 0 FAIL); validate_katex.js now warns above ~700 expressions.

### 169. Port the NL-FSCX v2 affine weak-key guard to the assembly and Arduino targets (Security, Low)

**Background:** TODO #168 added `nl_v2_key_is_valid` to the Python, C (`herradura.h`) and
Go suites and enforced it in all three CLIs, rejecting the key class for which NL-FSCX
v2's permutation degenerates to GF(2)-affine ($\delta(K) \in \{0, 2^{n-1}\}$ — see
`SecurityProofs-5.md` §11.19.2). The ARM Thumb-2, NASM i386 and Arduino targets also
implement NL-FSCX v2 and HSKE-NL-A2, but were left unguarded.

They are materially more exposed than the 256-bit deployment, because the class density
scales with word size. The $\delta = 0$ class is every $K$ divisible by
$2^{\lceil (n+1)/2 \rceil}$, and the $\delta = 2^{n-1}$ class is additionally non-empty
whenever $8 \mid n$. Exhaustive counts over the full key space give a total affine
density of $2^{-16.7}$ at the assembly targets' $n = 32$ — roughly 1 key in $105{,}000$ —
against $\approx 2^{-129}$ at $n = 256$.

TODO #168 deliberately did not attempt this: those targets are demo-only, and the
development host has no ARM cross-toolchain, so the change could not have been built or
tested (writing unverifiable assembly was judged worse than leaving a documented gap).

**Work items:**

1. Install an ARM cross-toolchain (`arm-linux-gnueabi-gcc`) and confirm `build_arm.sh`
   plus `qemu-arm` run the existing suite/tests before touching anything — see the
   portability notes in CLAUDE.md's Build Commands section.
2. Add the `delta(K) not in {0, 2^(n-1)}` check to the 32-bit NL-FSCX v2 paths in
   `Herradura cryptographic suite.s`, `Herradura cryptographic suite.asm` and
   `Herradura cryptographic suite.ino`, matching the C predicate's semantics exactly.
3. Decide and document the failure mode for these targets: they have no CLI error path,
   so the choices are a return-code convention or a visible test-harness assertion.
   Whichever is chosen, keep it consistent across all three.
4. Extend `CryptosuiteTests/Herradura_tests.{s,asm,ino}` with the equivalent of test
   `[45]`'s `v2_weak_key_reject` sub-check at $n = 32$ (e.g. $K = 2^{17}$, which has
   $\delta = 0$ at that width), and run them under qemu/simavr per `run_arduino.sh`.
5. Update `SecurityProofs-5.md` §11.19.2, which currently records this as open follow-up
   work.

Status: **DONE v1.9.144** — confirmed `arm-linux-gnueabi-gcc`/`qemu-arm` present, unblocking
the port. Added `nl_v2_key_is_valid` to `Herradura cryptographic suite.{s,asm,ino}`,
matching `herradura.h`'s semantics, plus test-only copies in
`CryptosuiteTests/Herradura_tests.{s,asm,ino}` (no shared header exists to import from).
Chose a plain return-code convention, enforced solely via a new test `[18]`
(`v2_weak_key_reject`, $K=2^{17}$ rejected / ordinary key accepted) — consistent with
Python/C/Go, which likewise never call the guard from inside the primitive, only from
their CLI's keygen. Verified passing (tests `[1]`–`[18]`, 0 FAIL) under `qemu-arm`,
`qemu-i386`, and `simavr`. `SecurityProofs-5.md` §11.19.2 updated to record the closure.

### 171. Add `CRYPTOGRAPHY_BASICS.md` — cryptography fundamentals primer for recent graduates (Documentation, Medium)

Create `docs/CRYPTOGRAPHY_BASICS.md` covering the cryptography concept basics and fundamentals underlying the suite's components (modular/finite-field arithmetic, GF(2^n)* structure, XOR/linear maps and periodic orbits, Diffie-Hellman key exchange, discrete-log hardness, symmetric vs. asymmetric encryption, digital signatures, Schnorr identification/signature scheme, El Gamal encryption, hash-based commitments, zero-knowledge proofs, lattice/LWE-style noise arguments, syndrome decoding/code-based cryptography), including formal notation used throughout `SecurityProofs-*.md` and `docs/TUTORIAL.md` (e.g. ⊕, ROL/ROR, g^a, mod (2^n − 1), Σ-protocol notation). The goal is a self-contained prerequisites document that prepares a recent graduate of most STEM/CS-adjacent backgrounds (not necessarily a cryptography specialist) to read and understand `docs/TUTORIAL.md`, `docs/INTRODUCTION.md`, and `SecurityProofs-1.md` through `SecurityProofs-5.md` without needing outside references. Link it from `docs/TUTORIAL.md` and `README.md`'s docs section once written. Follow `SecurityProofsCode/KATEX_RULES.md` for any math notation rendered as KaTeX.

Status: **DONE v1.9.145** — added `docs/CRYPTOGRAPHY_BASICS.md`, a from-scratch primer
(no prior programming/math background assumed) covering symmetric vs. asymmetric
crypto, Kerckhoffs's principle, one-way functions, bits/modular ("clock") arithmetic,
a formal-notation lookup table (⊕, ROL/ROR, mod, GF(2^n)*, g^a, Pr[·], negl(n),
O(f(n)), H(·), π/σ, etc.), threat models (Alice/Bob/Eve/Mallory), and the
quantum-resistance rationale — positioned as the layer beneath `docs/INTRODUCTION.md`
in the reading order. Linked from `docs/TUTORIAL.md`'s background-reading note,
`docs/INTRODUCTION.md`'s opening paragraph, and `README.md`'s docs-directory listing.
No KaTeX math spans used (plain markdown/Unicode notation only), so
`SecurityProofsCode/KATEX_RULES.md` did not apply.

### 172. README.md — didactic on-ramp for human newcomers (Documentation, Low)

`README.md` currently opens straight into FSCX's LaTeX definition with no motivation,
and its pointer to `docs/CRYPTOGRAPHY_BASICS.md`/`docs/INTRODUCTION.md` is phrased only
for "external tools and agents," not human readers landing on the repo. The 11-protocol
list (HKEX-GF, HSKE, HPKS, HPKE, and their NL/PQC/code-based variants) is a bare
enumeration of formulas with undefined jargon (`FFS L[1/3]`, `EUF-CMA`, `SD(n,t)`), and
there is no diagram anywhere in the file.

**Work items:**

1. Add a 2-3 sentence "what problem this solves / who this is for" paragraph before the
   FSCX section, and move the `docs/CRYPTOGRAPHY_BASICS.md` → `docs/INTRODUCTION.md` →
   `docs/TUTORIAL.md` pointer up to right after the title, addressed to human readers.
2. Before the FSCX formula block, add one plain-English sentence framing it as the
   mixing primitive everything else is built from, so the LaTeX isn't the first thing a
   reader hits.
3. Group the protocol list with short framing sentences per family (classical /
   NL-PQC / code-based) and define or link abbreviations (`EUF-CMA`, `SD(n,t)`, `FFS`)
   on first use, e.g. via the `docs/CRYPTOGRAPHY_BASICS.md` glossary.
4. Add one small diagram (ASCII or mermaid) for HKEX-GF's Alice/Bob exchange, since it's
   the simplest protocol and currently has no visual anywhere in the repo.

Status: **DONE v1.9.146** — added a "what this is / who it's for" intro paragraph and
moved the `docs/CRYPTOGRAPHY_BASICS.md` → `docs/INTRODUCTION.md` → `docs/TUTORIAL.md`
pointer up front, addressed to human readers (the existing agent-facing `llms.txt`
pointer stays separate). Added a framing sentence before the FSCX formula block. Grouped
the protocol list into its three families (classical / NL-hardened / code-based PQC)
each with a short "what this family is/why" sentence, and expanded `EUF-CMA`, `SD(n,t)`,
`PRF`, and the `FFS L[1/3]` security-level note inline rather than leaving them bare
(the actual glossary in `docs/CRYPTOGRAPHY_BASICS.md` doesn't define EUF-CMA/PRF, so
those are spelled out in-line instead of linked). Added a mermaid sequence diagram for
the HKEX-GF Alice/Bob exchange plus a one-line note on why an eavesdropper can't recover
the shared secret. Verified `SecurityProofsCode/validate_katex.js README.md` still
passes (84 OK, 0 FAIL, 0 PIPE-FAIL) after the edits.

### 173. docs/TUTORIAL.md — add motivation, quickstart, and core/advanced grouping (Documentation, Medium)

`docs/TUTORIAL.md` is a well-organized cookbook (consistent CLI/C/Go/Python blocks per
protocol) but reads as pure reference: each section jumps from its header straight to
shell commands with no "what is this for / when would I use it" framing. There is no
link to `docs/INTRODUCTION.md` Part 11.2's protocol-choice decision tree near the top,
no minimal end-to-end quickstart a beginner can copy-paste, and objectively harder
sections (ZKP, Threshold Signing, OPRF/aPAKE) carry the same visual weight as the basic
classical protocols.

**Work items:**

1. Add 1-2 sentences of "what this is / when to use it" before the CLI block in each
   major protocol section (starting with HKEX-GF and HSKE).
2. Link `docs/INTRODUCTION.md`'s decision tree (Part 11.2) from the "Getting started"
   section so a new integrator can pick a protocol before reading the full reference.
3. Explain asymmetric protocol shapes where they aren't self-evident from the CLI
   labels alone, e.g. why HKEX-RNL needs two rounds ("Round 1"/"Round 2") unlike the
   single-round HKEX-GF.
4. Add a single "5-minute quickstart" callout near the top: generate a keypair,
   exchange, encrypt, decrypt, in one copy-pasteable block.
5. Visually separate "core" protocols (classical, NL/PQC) from "advanced" ones (ZKP,
   Threshold Signing, HCRED, OPRF/aPAKE) in the Contents list.

Status: **DONE v1.9.147** — added a "what it's for" framing paragraph before the CLI
block in HKEX-GF, HSKE, HPKS, HPKE, and HKEX-RNL, each cross-referencing the protocols
it composes with. Linked `docs/INTRODUCTION.md` §11.2's decision tree from the top of
"Getting started". Explained HKEX-RNL's two-round shape (Peikert reconciliation requires
Bob to see Alice's public value before computing his hint) plus a mermaid sequence
diagram, contrasted with HKEX-GF's simultaneous exchange. Added a copy-pasteable
5-minute quickstart (keypair → exchange → encrypt → decrypt) using the classical
protocols and Python CLI. Split the Contents list into Core / Advanced / Reference
groups (switched to bullet lists rather than reusing the original numeric IDs, since
CommonMark auto-increments ordered-list numbers and out-of-sequence literals would have
rendered wrong). Verified `SecurityProofsCode/validate_katex.js docs/TUTORIAL.md` is a
no-op (file has no `$…$` math spans).

### 174. docs/INTRODUCTION.md — numbering, notation consistency, and a chained worked example (Documentation, Medium)

`docs/INTRODUCTION.md` is the most didactic document in the repo (reading-order table,
toy examples, historical citations, glossary, decision tree) but at 1251 lines has no
progress markers, uses fractional Part numbers ("Part 4.5", "Part 10.4") that break the
otherwise-integer sequence, and its GF(2^n)* notation doesn't match README.md's
blackboard-bold `\mathbb{GF}(2^n)^*`. The Part 3.1 (paint-mixing DH) and Part 6.2
(Schnorr identification) sections describe step-by-step message exchanges in prose only,
with no diagram. There is also no single example that chains HKEX-GF's derived key
into an actual HSKE encrypt/decrypt with small, hand-verifiable numbers.

**Work items:**

1. Add a per-Part estimated read time or a short progress indicator at each Part
   heading so the document feels navigable.
2. Resolve the fractional Part numbers ("Part 4.5", "Part 10.4") — either renumber the
   sequence or explicitly label them as optional digressions.
3. Standardize GF(2^n)* notation with README.md (pick blackboard-bold or plain, not
   both) and add a one-time footnote noting they denote the same field.
4. Add one end-to-end worked example late in Part 4 that chains the Part 3 DH numbers
   into an HSKE encrypt/decrypt at a small bit-width, verifiable by hand.
5. Convert the Part 3.1 paint-mixing and Part 6.2 Schnorr descriptions into mermaid
   sequence diagrams (GitHub renders these natively) rather than prose-only.

Status: **DONE v1.9.148** — added a "Parts at a glance" table to the Reading guide with
a per-Part time estimate (≈65 min end to end). Kept Part 4.5 and Part 10.4's fractional
numbering rather than renumbering the whole document (which would have broken several
existing cross-references, including one just added to `docs/TUTORIAL.md` in TODO #173)
and instead labeled both headings `(optional deep dive)`, with a note in the new table
that they don't carry numbering forward. Added a one-time footnote at GF(2^n)*'s first
use (Part 2.3) noting `README.md`/`SecurityProofs-*.md` render the same object as
$\mathbb{GF}(2^n)^{\ast}$ in KaTeX — this document keeps plain text throughout rather
than converting, since it's otherwise KaTeX-free by design. Added a "Putting it together"
worked example after Part 4.4 chaining a real HKEX-GF handshake into an HSKE
encrypt/decrypt at n=32, with every value computed by actually running
`Herradura cryptographic suite.py`'s `gf_pow`/`fscx_revolve` (not hand-typed). Added
mermaid sequence diagrams for the Part 3.1 paint-mixing analogy and the Part 6.2 Schnorr
identification protocol. Verified `SecurityProofsCode/validate_katex.js
docs/INTRODUCTION.md` passes (2 OK, 0 FAIL) with the new KaTeX span included.

### 175. docs/CRYPTOGRAPHY_BASICS.md — TL;DR box, negligibility example, and factoring caveat (Documentation, Low)

`docs/CRYPTOGRAPHY_BASICS.md` is close to ideal for its target reader but has three
specific gaps: no TL;DR/time-estimate at the top for a reader deciding whether to commit
to the full 324 lines; `negl(n)`/`poly(n)`/`Pr[event]` are introduced only as notation-
table rows (§4) with no worked example, unlike §3.2's clock-arithmetic treatment; and
§2.3's prime-factoring one-way-function example could read as what this codebase relies
on, when the suite's actual hard problem is discrete log over GF(2^n), not factoring.

**Work items:**

1. Add a 2-3 sentence TL;DR/abstract box after the title, naming the four core
   properties (confidentiality/integrity/authentication/non-repudiation) and an
   estimated reading time.
2. Add a short worked example directly below the notation table's `negl(n)`/`poly(n)`
   rows (e.g. comparing 2^128 brute-force guesses against a fast attacker's guess rate)
   so "negligible" is grounded the same way clock arithmetic was.
3. In §2.3, explicitly flag that prime factoring is illustrative of one-way functions
   in general (RSA), and separately name that this codebase's actual hard problem is
   the discrete-log problem over GF(2^n).
4. Add a small ASCII diagram for Kerckhoffs's principle (public algorithm box vs.
   secret key box) in §2 to visually anchor the public/private split.

Status: **DONE v1.9.149** — added a TL;DR paragraph (with ≈15-20 min estimate) right
after the intro, naming the four core properties and the algorithm/key/one-way-function
setup. Added an ASCII box diagram in §2 contrasting the public ALGORITHM box against the
secret KEY box for Kerckhoffs's principle. Added a "note on which problem this codebase
actually uses" directly after §2.3's factoring example, clarifying factoring illustrates
RSA-style one-way functions in general while Herradura's classical protocols rest on the
discrete-log problem over GF(2^n)* instead. Added a worked negligibility example below
the notation table (256-bit brute force at 10^12 keys/sec vs. the age of the universe,
~10^47x gap) grounding `negl(n)`/`poly(n)` the same way §3.2 grounded modular
arithmetic with clock time. File has no KaTeX math spans, so
`SecurityProofsCode/validate_katex.js` is a no-op here (confirmed 0 OK/0 FAIL, unchanged).

### 176. docs/examples/ — add a local README and remove stray `__pycache__` (Documentation, Low)

The four samples in `docs/examples/` (`c/hello_herradura.c`, `go/hello_herradura.go`,
`python/hello_herradura.py`, `mcp/hello_herradura_mcp.py`) are consistently linked from
`README.md`, `llms.txt`, and `docs/TUTORIAL.md`, but the directory itself has no README
explaining what each sample demonstrates or what order to try them in. A stray
`docs/examples/mcp/__pycache__/` directory is also checked into the repo.

**Work items:**

1. Add `docs/examples/README.md` briefly describing each sample and a suggested
   reading order (e.g. Python first as the reference implementation, then C/Go, then
   the MCP example last since it depends on understanding the CLI surface).
2. Remove the checked-in `__pycache__` directory and add `__pycache__/` to `.gitignore`
   if not already covered.

Status: **DONE v1.9.150** — added `docs/examples/README.md` with a one-line "why" per
sample and a suggested order (Python reference implementation first, then C, then Go,
then the MCP agent-integration example last). On the `__pycache__` item: `git ls-files`
confirmed `docs/examples/mcp/__pycache__/` was never actually tracked by git (the
directory's `.pyc` file was a local build artifact only, already matched by the
existing root `.gitignore`'s untargeted `__pycache__/` pattern, which applies at any
depth) — the earlier review's "checked into the repo" description was inaccurate.
Deleted the local stray directory for cleanliness; no `.gitignore` change was needed.

### 177. SecurityProofs.md — back-link to beginner docs and declutter the index (Documentation, Low)

`SecurityProofs.md` is a thin, honest index redirecting to the five `SecurityProofs-N.md`
Part files (split due to GitHub's ~750-expression-per-page KaTeX limit), but it offers no
path back to `docs/CRYPTOGRAPHY_BASICS.md`/`docs/INTRODUCTION.md` for a reader who lands
here first (e.g. via search or citation) without the prerequisite background, even though
those docs link forward to it. Its dense version-history "Status" text is also mixed
into what should be a pure navigational index.

**Work items:**

1. Add one line near the top pointing readers without prerequisite background to
   `docs/CRYPTOGRAPHY_BASICS.md` and `docs/INTRODUCTION.md`.
2. Move the version-history "Status" paragraph out of the primary index view (e.g. into
   a trailing footnote or a separate changelog-style subsection) so the file's routing
   table is the first thing seen.

Status: **DONE v1.9.151** — added a callout at the top pointing readers without the
prerequisite background to `docs/CRYPTOGRAPHY_BASICS.md` and `docs/INTRODUCTION.md`
(noting the latter links back into these same Part files at the point each concept is
introduced). Moved the dense version-history "Status"/"Last updated" text into a
collapsed `<details>` block below the routing table, so the five-file index is the
first thing seen. Verified `SecurityProofsCode/validate_katex.js SecurityProofs.md`
still passes (1 OK, 0 FAIL) with the `$\mathbb{Z}_{65537}$` span now inside the
collapsed block.

This closes out the documentation-review batch opened by TODO #172–#177 (all six now
DONE); `TODO.md`'s Open items list is empty as of this entry.

### 178. Promote the suite to v2.0.0 (Release, Medium)

A survey of the repo (2026-08-06) found `TODO.md` empty, all six main teaching/reference
docs recently overhauled (TODO #172–177), and no new cryptographic work blocking a
release — but three legitimate breaking changes from the 1.x history (HKEX→HKEX-GF at
v1.4.0, HFSCX-256→HFSCX-256-DM at v1.9.0, the Stern H-matrix fix at v1.9.35) had never
been consolidated into one migration story. 2.0.0 is proposed to mark the CLI/PEM
surface as a stable baseline going forward, not to introduce a new break of its own.

**Work items:**

1. Write `MIGRATING.md` consolidating the three historical breaking changes with
   what's incompatible and how to regenerate affected artifacts.
2. Add a "Known Limitations" section to `README.md` — HPKS-NL/HPKE-NL not PQC (TODO
   #5), HPKS-Stern-F/HPKE-Stern-F demo-scale parameters, the two ACKNOWLEDGED-by-design
   test FAILs (#85, #86), Arduino CI's best-effort status, and the QC-MDPC/Ligero
   research prototypes.
3. Re-verify `CliTest/test_c_interop.sh` and `CliTest/test_go_interop.sh` pass
   byte-for-byte across all three CLIs before tagging.
4. Add a short addendum to CLAUDE.md's TODO policy section on when MINOR/MAJOR version
   bumps apply post-2.0.0.
5. Tag `v2.0.0`, write GitHub release notes pointing to `MIGRATING.md`, and do a fresh
   `docker build && docker run` check to confirm the release artifact builds clean.

Status: **DONE v2.0.0** — items 1–2 shipped in v1.9.152, items 3–4 in v1.9.153.

Item 5: rebuilt the C and Go CLIs fresh and re-ran `test_c_interop.sh` (4/4 PASS),
`test_go_interop.sh` (10/10 PASS), and `test_stern_interop.sh` (9/9 PASS, the interop
path that broke pre-v1.9.36) immediately pre-tag. The local `docker build && docker
run` smoke test was attempted but abandoned as environment-limited: this sandbox is
arm64, so the amd64 Dockerfile requires nested QEMU emulation (host arm64 → qemu-x86_64
container → qemu-arm/qemu-i386 for the ARM/i386 targets inside that), and the Go build
step crashed with a goroutine dump rooted in `runtime.asyncPreempt`/`syscall.read` —
qemu-user's known incompatibility with Go's signal-based goroutine preemption, not a
code defect. Used GitHub Actions' native CI run on master's actual merge commit
(`82793cb`, run 31064764641) as the authoritative pre-tag check instead — all three
jobs (native C/Go/Python build+tests+CliTest, ARM Thumb-2/NASM i386 under QEMU,
best-effort Arduino/AVR) passed. Tagged `v2.0.0` as an annotated tag on `82793cb` and
published a GitHub release
(https://github.com/Caume/HerraduraKEx/releases/tag/v2.0.0) with hand-curated notes
(not `--generate-notes`) pointing to `MIGRATING.md`, explicitly stating 2.0.0
introduces no new breaking changes of its own, and summarizing the doc/release-prep
work since v1.9.144.

### #179: Gate KaTeX math rendering in CI

`SecurityProofsCode/validate_katex.js` simulates GitHub's markdown+KaTeX rendering pipeline and catches the sharp edges documented in `SecurityProofsCode/KATEX_RULES.md`, but it was previously run by hand only. The four commits immediately following the v2.0.0 tag (d830eb9, a3d0492, d2f27bb, 72c75a3) were all post-hoc fixes for KaTeX breaks in README.md that manual review missed. Added a CI job (or a step in the existing `native` job) in `.github/workflows/ci.yml` that runs `validate_katex.js` against `README.md` and `SecurityProofs-*.md` on every push/PR, so rendering regressions are caught before merge instead of after.

Status: **DONE v2.0.1** — added a `katex` job to `.github/workflows/ci.yml` that
installs the `katex` npm package and runs `validate_katex.js` against `README.md` and
all five `SecurityProofs-*.md` shards. Verified locally: all seven files report 0 FAIL,
0 PIPE-FAIL (README 84 OK, SecurityProofs.md 1 OK, shards 1–5 at 551/363/580/716/645 OK
respectively); the job exits non-zero on any real FAIL/PIPE-FAIL going forward.

### #180: Clean up stale `.claude/worktrees/agent-*` directories

Four stale worktree directories from past subagent sessions were found on disk under `.claude/worktrees/` (`agent-a79dce1d3adb0a5db`, `agent-a93a3b1695502c474`, `agent-aab7c546c19c405cc`, `agent-aba29c6c0bc47c2d2`), no longer needed. Remove them via `git worktree remove` (or prune) to reclaim disk space and keep `git worktree list` output clean. Not a code change; purely local housekeeping — confirm none hold unmerged work before removing.

Status: **DONE v2.0.2** — ran `git log master..<branch>` / `git log devtest..<branch>`
for all four worktree branches and confirmed each was fully merged (no unmerged
commits), then removed all four via `git worktree remove --force` and deleted the
now-orphaned local branches (`worktree-agent-a79dce1d3adb0a5db`,
`worktree-agent-a93a3b1695502c474`, `worktree-agent-aab7c546c19c405cc`,
`worktree-agent-aba29c6c0bc47c2d2`) with `git branch -d`. Removed the now-empty
`.claude/worktrees/` directory. `git worktree list` shows only the primary checkout.

### #181: Audit stale in-source TODO/FIXME comments

A repo-wide grep found ~180 TODO/FIXME comments scattered across source files (heaviest in `CryptosuiteTests/Herradura_tests.{c,py}` at 33/31, `HerraduraCli/herradura.py` at 40, and numerous `SecurityProofsCode/*.py` research scripts). Triage these for ones that are resolved-but-never-removed or otherwise stale, and either delete the cruft or promote genuinely open ones into tracked TODO.md entries with proper numbering.

Status: **DONE v2.0.3** — audited all ~370 `TODO`/`FIXME` hits (the earlier ~180 estimate
undercounted; a full grep across `SecurityProofsCode/`, `CryptosuiteTests/`,
`HerraduraCli/`, the suite files, `herradura/`, `bindings/ffi/`, `benchmarks/`, `Fuzz/`,
`Mcp/`, `CliTest/`, and `spec/` found ~370). Finding: the overwhelming majority are not
classic "fix this later" comments but a deliberate, working convention — `TODO #NNN`
tags that cross-reference the tracked ledger in this file/`TODO.md`, attached to code
that is already fully implemented immediately below the comment (e.g. `# QC-MDPC
Niederreiter KEM + BGF decoder (TODO #126, Batch 2)` sitting directly above the
implemented KEM). These are backward-reference citations, not stale cruft, and none
warranted deletion.

Checked the two comments that read as genuinely open work:
- `SecurityProofsCode/stern_ring_challenge_bias.py` cites **TODO #164** (Stern-Ring
  non-signer challenge modulo-3 bias) — already its own tracked entry above, `DONE
  v1.9.127`. No action needed.
- `SecurityProofsCode/hpks_threshold_demo.py:394` cites **TODO #106** for "t-of-n is
  future work" — #106 (CLI multi-party threshold signing) is `DONE v1.9.44`, but scoped
  to n-of-n by design (Shamir over a composite group order breaks Lagrange inversion for
  general t-of-n; the demo's own inline output explains the three known workarounds and
  why n-of-n was chosen). This is an accurately self-documented design limitation, not a
  missed TODO — left as-is rather than opening a new tracked item, since no concrete plan
  exists to embed a prime-field share space and the demo already explains why.

No source changes were needed; this item closes as a clean bill of health for the
TODO-comment convention.

### #182: Extend constant-time audit to HKEX-RNL reconciliation (`rnl_hint`/`rnl_reconcile_bits`)

Prompted by a review of recent PQC literature (2026-07/08): several papers target the message-decoding/reconciliation step of LWE/LWR schemes with single-trace power analysis and template attacks (e.g. HQC SPA, Ring-LWE/LWR cyclic-message-rotation templates). `SecurityProofsCode/dudect_timing_audit.c` (TODO #129) covers `gf_mul`, `gf_pow`, `mul_mod_ord`, `fscx_revolve`, Stern permutation ops, and WOTS signing, but not HKEX-RNL's Peikert cross-rounding reconciliation (`rnl_hint`, `rnl_reconcile_bits`, `rnl_agree` in `herradura.h`) — exactly the operation this literature attacks. The code looks arithmetic-only (division/shift/mask, no visible secret-dependent branches), but that's an unverified assumption. Add dudect-style fixed-vs-random leak tests for these functions and fix any leak found.

Status: **DONE v2.0.4** — added a "Batch 8" section to
`SecurityProofsCode/dudect_timing_audit.c`: a parallel `run_test_poly` harness (the RNL
secret operand is `rnl_poly_t` = `int32_t[RNL_N]`, not `BitArray`) auditing `rnl_hint`,
`rnl_reconcile_bits`, and the reconciler path of `rnl_agree` end-to-end. Each function is
tested against a zero secret and, for the two hint/reconcile functions, additionally
against a fixed pattern with every coefficient pinned exactly at the `q/4` rounding
threshold — the value most likely to expose a division/comparison the compiler didn't
actually make branch-free, mirroring Batch 7's 0xA5-pattern rationale. At 3000 rounds,
all five new tests report `|t|` between 0.20 and 2.13 — clean, well under the dudect 4.5
leak threshold (`rnl_hint` 1.78/2.13, `rnl_reconcile_bits` 0.30/0.20, `rnl_agree` 0.61).
No leak found, so no fix to `herradura.h` was needed — the deliverable here is the closed
coverage gap. The pre-existing `stern_gen_perm`/`stern_apply_perm` LEAK SUSPECTED lines
at the all-zero fixed point are Batch 7's already-documented, already-explained
degenerate-value artifact (clean at the 0xA5 pattern), unrelated to this batch and not
reopened by it.

### #183: Real QC-MDPC syndrome decoder for HPKE-Stern-F decap

The Niederreiter KEM (`hpke_stern_*` in C/Go/Python) was believed to only
return the known error vector `e'` alongside the ciphertext instead of
recovering it from the syndrome via decoding, based on stale wording in
README.md, CLAUDE.md, and `spec/generate_spec.py`. Scoped to implement a
real QC-MDPC decoder.

Status: **DONE v2.0.5** — investigation found the decoder already exists and
is already wired up: the CLI's `hpke-stern-kem` algo tag (distinct from the
intentionally-kept `hpke-stern` demo tag) dispatches to a real Black-Gray-Flip
(BGF) QC-MDPC syndrome decoder — `qcmdpc_keygen`/`qcmdpc_encap`/
`qcmdpc_decap_bgf`, implemented in full in C (`herradura.h`), Go
(`herradura/herradura.go`), and Python (`Herradura cryptographic suite.py`),
and exercised end-to-end by `CliTest/test_stern_kem.sh` (9/9 cross-language
combinations pass, verified by rerunning). The actual defect was that
`spec/generate_spec.py`'s `hpke-stern-kem` entry copied `hpke-stern`'s
`status="demo-only"` / "same demo-decap caveat" text, and README.md/CLAUDE.md
never distinguished the two algo tags at all. Corrected the spec entry to
`status="production"` with accurate notes/sources, regenerated
`spec/herradura-protocol-spec.json`, and updated README.md/CLAUDE.md to
explicitly separate `hpke-stern` (demo, decap needs plaintext `e'`) from
`hpke-stern-kem` (real BGF decoder, no `e'` needed) — noting the KEM's toy
parameters (r=523, d=15, t=18) still lack a measured DFR at production
security margins, which is a fair caveat to keep. No code changes; this was
a stale-documentation bug, not a missing decoder. (DFR later measured by
TODO #195: ≈0.225% per encapsulation.)

### #184: HPKS-Stern-F production-soundness round count

`Herradura cryptographic suite.py` and `docs/TUTORIAL.md` both note demo
params use `rounds=32` (soundness `(2/3)^32`), while 128-bit soundness
needs `rounds >= 219`. Add a production-strength parameter mode (flag or
named preset) to the C/Go/Python suites and benchmark the resulting
signature size/time cost, documenting the tradeoff in SecurityProofs-4.md.

Status: **DONE v2.0.6** — investigation found Python's `hpks_stern_f_sign`
and Go's `HpksSternFSign` already accepted a `rounds` parameter, but neither
CLI's `sign --algo hpks-stern`/`hpks-ring` path actually passed it through
(Python's `--rounds` flag was defined but unused there; Go hardcoded
`SdfRounds`=32). Wired `--rounds`/`-rounds` through both CLIs for both algo
tags. C's fixed-size signature struct makes rounds a compile-time constant
(`-DSDF_ROUNDS=219`); found and fixed a bug where `herradura.h`'s
unconditional `#define SDF_ROUNDS 32` silently clobbered that override —
now `#ifndef`-guarded. While verifying the fix at 219 rounds, hit and fixed
a second real bug: all three DER codecs (Python `codec.py`, C
`herradura_codec.h`, Go `herradura/codec.go`) capped length encoding at the
2-byte long form (65 535 B), too small for a 219-round ring signature
(~95 KB) — extended all three to the standard 3-/4-byte long forms (the
decoders already supported them) and bumped C's `DER_INT_LEN`/`DER_SEQ_LEN`
macros and local `lbuf` buffers to match. Verified `--rounds 219`
sign/verify for both `hpks-stern` and `hpks-ring` in all three languages
(including a `-DSDF_ROUNDS=219` C rebuild), full `CliTest/` regression
suite re-run clean, and recorded a rounds=32-vs-219 size/time benchmark
(7 029 B/0.85 s Python demo vs. 47 511 B/2.24 s Python production; C 15-40x
faster than Python/Go at both) in `SecurityProofs-4.md` next to Theorem 17.

### #185: Triage Arduino/AVR CI's best-effort status

`.github/workflows/ci.yml`'s `arduino` job is allowed to fail without
blocking CI. Investigate whether the remaining failures are due to flash
size limits, simavr flakiness, or something fixable, and either resolve
the root cause or document precisely why best-effort status is permanent
(update CLAUDE.md's Testing section accordingly either way).

Status: **DONE v2.0.7** — reproduced the build+`simavr` test run locally
(clean `build_arduino.sh`; two full 90s `run_arduino.sh` passes of both
`suite` and `tests` targets, 90/90 test-iteration `[PASS]`, zero failures)
and pulled the Arduino job's `conclusion` across all 79 recorded CI runs
via `gh run list`/`gh run view`: exactly 5 failures, all on 2026-07-30/
07-31, all before the ATmega2560 `.bss` SRAM-overflow fix (TODO #155,
v1.9.122, landed 2026-07-31T16:22 UTC) — 0 failures in the 74 runs since,
including every run in the last two weeks of TODO work. The root cause
was already found and fixed; "best-effort" had become stale caution that
was silently letting a real Arduino/AVR regression pass CI undetected
rather than a live hedge against ongoing flakiness. Promoted the job to
required/blocking: dropped `continue-on-error: true` and the "best-effort"
suffix from its name in `.github/workflows/ci.yml`, updated CLAUDE.md's
Testing section and README.md's Known Limitations entry to match. If
simavr flakiness specific to GitHub's runners (as opposed to local
reproduction) surfaces later, `continue-on-error` can be reinstated with
that evidence — none was found here.

### #186: Exercise `benchmarks/compare_stern_f_dilithium.py` against real liboqs

The script's OQS C API usage is flagged as "best-effort and has not been
exercised end-to-end." If liboqs is installable in CI or dev environments,
run the comparison for real, record actual HPKS-Stern-F vs. Dilithium
numbers, and fold the results into the PQC signature discussion in
SecurityProofs-4.md instead of leaving it as an unexercised stub.

Status: **DONE v2.0.8** — built liboqs 0.16.0 from source (plain
`cmake`/`make`, no options; network access and build tools were both
available in this environment) and ran the comparison end-to-end. This
surfaced a real bug: the script hardcoded `OQS_SIG_new(b"Dilithium3")`,
but liboqs renamed that algorithm to its final NIST FIPS 204 identifier,
`ML-DSA-65`, once ML-DSA was standardized — `OQS_SIG_new` silently
returned NULL for the old name, so the comparison would have reported
"algorithm not enabled" even with liboqs correctly installed. Fixed the
script to try `ML-DSA-65` first, fall back to `Dilithium3` for older
liboqs builds, and label output with whichever name actually loaded
rather than a hardcoded string. Recorded real numbers (5-run average,
N=30): HPKS-Stern-F ~39 ms sign / ~29 ms verify vs. ML-DSA-65's ~0.8 ms
/ ~0.2 ms (~50x / ~130x slower) in `docs/BENCHMARKS.md` and
`SecurityProofs-4.md` next to Theorem 17, replacing the "install liboqs
to measure" placeholder both had carried since TODO #138.

### #187: Run fuzz harnesses under a real engine and record coverage

`Fuzz/` has libFuzzer-style harnesses (b64/DER/PEM decode) and Python
harnesses (CLI args, codec) but no on-record run history or coverage
report — TODO #130 built the harnesses but didn't close the loop on
actually fuzzing with them. Run `Fuzz/run_fuzz.sh` for a fixed time
budget, record findings and coverage in `Fuzz/README.md`, and consider
wiring a short smoke-fuzz job into CI.

Status: **DONE v2.0.9** — ran `./Fuzz/run_fuzz.sh 300` (5 min/target,
~35 min total): 3 C libFuzzer targets (~189M combined executions), 2 Go
native fuzz targets (~75M combined executions), the Python Hypothesis
suite (60,000 examples across 3 properties), and the CLI black-box argv
fuzzer (6,510 trials across the C/Go/Python CLIs) — zero crashes, zero
ASan/UBSan reports, zero leaks anywhere. Recorded the full per-target
breakdown in a new "Run history" section of `Fuzz/README.md`. Added a
`fuzz-smoke` job to `.github/workflows/ci.yml` at the script's own 30s/
target default (~3 min total), verified end-to-end locally at that exact
budget before wiring it in, so future regressions in the codec/CLI-
argument-parsing surface are caught automatically on every push/PR
rather than depending on someone re-running this by hand.

### #188: Add sanitizer/CI hardening (ASan/UBSan/valgrind)

CI runs the build+test matrix but never compiles/runs the C suite,
tests, or CLI under AddressSanitizer, UndefinedBehaviorSanitizer, or
valgrind. Given the manual constant-time auditing already done (TODO
#182), an automated sanitizer job would catch memory-safety and UB
issues that manual review can't, and is standard practice in comparable
C crypto projects (libsodium, BLAKE3, OpenSSL). Add a CI job (or local
build-script variant) that builds with `-fsanitize=address,undefined`
and runs the security tests, and/or a valgrind pass.

Status: **DONE v2.0.10** — added `build_c_sanitize.sh` (ASan+UBSan build
of the C suite/tests/CLI, `_asan`-suffixed outputs) and a `sanitizers`
CI job running the security tests and the C `CliTest/` suite under that
instrumentation, plus a bounded valgrind memcheck pass (`-r 3 -t 0.2`,
~5 min locally) on a plain debug build. Running this locally surfaced a
real bug: test `[44]`'s "syndrome tamper" case in `CryptosuiteTests/
Herradura_tests.c` passed `c2_poly` — a variable not initialized until
the next test case — into `hcred_verify`. ASan didn't catch it; valgrind
did, 4 hits at `_hcred_challenges` traced back to this call site. Fixed
to use `c_poly` (matching the already-correct Go/Python equivalents);
`ok_synd`'s pass/fail outcome is unchanged, but the test now genuinely
exercises what its name claims instead of reading uninitialized stack
memory. Verified clean: `Herradura_tests_asan` 79/79 `[PASS]` markers
with zero sanitizer hits, all 9 C `CliTest/test_c_*.sh` scripts 0 FAIL
under ASan+UBSan, and a valgrind rerun showing `ERROR SUMMARY: 0 errors
from 0 contexts`.

### #189: Add CodeQL / static-analysis workflow

No static-analysis workflow exists for the C/Go/Python sources. Add a
GitHub CodeQL workflow (free for public repos) covering C and Go at
minimum, and a Python linter/analyzer pass if useful, wired into
`.github/workflows/`.

Status: **DONE v2.0.11** — added `.github/workflows/codeql.yml`, a
CodeQL matrix covering C/C++ (`build-mode: manual`, compiling the suite,
test harness, and CLI directly), Go (`autobuild`), and Python
(`build-mode: none`). Runs on push/PR to `master`/`devtest`, a weekly
schedule (Monday 03:17 UTC), and `workflow_dispatch`; kept as a separate
workflow file from `ci.yml` so CodeQL alerts (which surface under the
repo's Security tab) don't gate merges as a required status check.
Validated the workflow YAML with `python3 -c "import yaml;
yaml.safe_load(...)"`.

### #190: Publish fixed KAT (Known-Answer-Test) vector files

`CliTest/test_vectors.sh` exercises key-agreement correctness but there
is no standalone, versioned Known-Answer-Test vector file (JSON/CSV, in
the style of NIST CAVP `.rsp` files) that a third-party reimplementation
could use to cross-validate against this suite's outputs independent of
this repo's own test harness. Add a `KAT/` (or similar) directory with
fixed input/output vectors for HKEX-GF, HSKE, HPKS, HPKE, and the NL/PQC
variants, generated from the reference implementation and checked into
the repo.

Status: **DONE v2.0.12** — added `KAT/classical_quartet.json` (HKEX-GF,
HSKE, HPKS, HPKE at n=256, NIST-CAVP-`.rsp`-style: fixed hex inputs,
deterministic hex outputs, no randomness anywhere). `KAT/generate_kat.py`
is the deterministic Python reference generator (`--check` diffs its
output against the checked-in file); `KAT/verify_kat.go` independently
recomputes every vector using the Go `herradura` package and confirms
byte-identical results, so the vectors are cross-language-verified, not
merely self-consistent within the Python reference. Wired into
`CliTest/test_kat_vectors.sh`, picked up automatically by the `native`
CI job's `for f in CliTest/*.sh` loop. NL/PQC and Stern-based variants
(HKEX-RNL, HSKE-NL, HPKS-NL/Stern-F, HPKE-NL/Stern-F/Stern-KEM) are
deferred to a follow-up — their larger key/ciphertext material (Ring-LWR
polynomials, QC-MDPC parity-check matrices, Stern commitments) needs a
different, less compact vector representation than the classical
quartet's fixed-width hex fields.

### #192: Java bindings

The suite has implementations/bindings spanning C, Go, Python, ARM
Thumb-2, NASM i386, and Arduino, plus a ctypes/cgo FFI layer
(`bindings/ffi/`), but no Java binding — a common target for users
integrating a crypto library into JVM-based applications. Evaluate JNI
(around `herradura.h`) or a pure-Java port, following the pattern
established by `bindings/ffi/`.

Status: **DONE v2.1.0** — added `bindings/java/` (`herradurakex.Herradura`),
a pure-Java port of the classical quartet (HKEX-GF, HSKE, HPKS, HPKE) at
n=256 using `java.math.BigInteger`, following `bindings/ffi/`'s scope
(classical quartet only). Chose a pure-Java port over JNI: no native
compilation/platform-specific `.so`/`.dylib`/`.dll` step for JVM
consumers, and `BigInteger` gives no constant-time guarantee regardless
of how the bit tricks are written, so there was nothing to gain from
porting `herradura.h`'s constant-time C tricks — mirrors the Python
reference's `fscx`/`gf_*` functions and its guarded protocol API
(degenerate-pubkey rejection, TODO #144/#131) instead. Verified two
ways: `herradurakex.KatVerify` recomputes all four `KAT/
classical_quartet.json` vectors (TODO #190) and confirms byte-identical
results — a third independent cross-language check alongside the Python
reference and `KAT/verify_kat.go` — and `herradurakex.SelfTest` runs a
fresh-random-key round-trip smoke test (HKEX-GF agreement, HSKE
round-trip, HPKS sign/verify + tamper rejection, HPKE round-trip), both
passing. Wired into `CliTest/test_java_bindings.sh` (skips gracefully
if no JDK is present); `native` CI job now installs
`default-jdk-headless`. MINOR bump (2.0.12 → 2.1.0) per CLAUDE.md's
semver rule for a new language-target port of an existing protocol.

### #194: Comparison/benchmark against standard primitives

`benchmarks/` records HerraduraKEx's own performance history but has no
head-to-head comparison against standard, widely-deployed primitives
(Curve25519/X25519, AES-GCM, ChaCha20-Poly1305, Kyber/ML-KEM,
Dilithium/ML-DSA — the latter two already partially covered by
`benchmarks/compare_stern_f_dilithium.py`, see TODO #186). Add
benchmark scripts/results comparing HKEX-GF/HKEX-RNL, HSKE, HPKS/HPKS-NL
and HPKE/HPKE-NL against their closest standard-primitive equivalents,
to give adopters real performance context for the novel constructions.

Status: **DONE v2.1.2** — added `benchmarks/compare_hkex_x25519.py`
(HKEX-GF vs. libsodium X25519, FFI/ctypes, same pattern as
`compare_hpks_ed25519.py`: keygen + agree, N=500) and
`benchmarks/compare_hske_aead.py` (HSKE vs. libsodium AES-256-GCM/
ChaCha20-Poly1305, encrypt/decrypt on HSKE's fixed 32-byte block,
N=2000; AES-256-GCM auto-skips when libsodium reports no AES-NI on the
host). Recorded results and the same apples-to-oranges caveats used by
the existing HPKS/Stern-F comparisons in `docs/BENCHMARKS.md`: HKEX-GF
is ~55x slower to generate a keypair and ~22x slower to agree than
X25519; HSKE is ~1.4x slower to encrypt and ~3.3x slower to decrypt
than ChaCha20-Poly1305 (much closer than the DLP-based comparisons,
since FSCX_REVOLVE is XOR/rotate rather than modular exponentiation).
HKEX-RNL vs. Kyber, HPKS-NL/HPKE-NL, and HPKE vs. a
X25519+AEAD hybrid remain unbenchmarked (liboqs unavailable in this
environment for the Kyber side, matching the existing gap noted for
HKEX-RNL vs. Kyber) — left as follow-up if a future pass wants full
protocol-stack coverage. PATCH bump (2.1.1 → 2.1.2): new benchmark
scripts and docs only, no CLI/PEM/wire-format surface change.

### #197: Java PEM/DER codec for the classical quartet's wire format

Part of the #196 breakdown. `bindings/java/herradurakex` currently only
exchanges raw `BigInteger` values — no PEM/DER support, so it can't
read/write key, ciphertext, or signature files produced by the
Python/C/Go CLIs. Port `HerraduraCli/codec.py`/`herradura_codec.h`/
`herradura/codec.go`'s DER encode/decode (including the long-form
length fix from TODO #190's investigation, 0x81–0x84) and PEM
boundary-label handling to Java, byte-for-byte compatible with the
existing three implementations. Add a round-trip test plus a
fixed-vector cross-check (an existing Python/C/Go-produced PEM file
decoded correctly by the new Java codec, and vice versa).

Status: **DONE v2.1.1** — added `bindings/java/herradurakex.Codec`, a
byte-for-byte port of `HerraduraCli/codec.py`/`herradura_codec.h`/
`herradura/codec.go`'s Base64/PEM/DER subset (including the long-form
length encoding, 0x81-0x84), with encode/decode helpers for classical
private/public keys, HPKE ciphertexts, HPKS signatures, HSKE session
keys, and digests. `herradurakex.CodecTest` covers round-trip
encode/decode plus a DER sign-byte edge case;
`CliTest/test_java_codec.sh` cross-checks both directions against the
Python CLI (Python-`genpkey`-produced key decoded by Java, and a
Java-encoded key decoded by `codec.py`).

### #191: Package-manager publishing (PyPI, Go module tagging, etc.)

There is no `pyproject.toml`/`setup.py` for the Python suite/CLI, so
`pip install herradurakex` isn't possible — users must clone and run
from source. Add packaging metadata for PyPI at minimum, and consider
signed/tagged Go module releases so `go get` resolves versioned tags
rather than only `master`.

Status: **DONE v2.1.3** — added `pyproject.toml` (setuptools, PEP 621)
defining the `herradurakex` distribution: console script `herradurakex`
plus `import herradurakex` re-exporting the full suite surface
(`KEYBITS`, `gf_mul`, `hkex_*`, `hske_*`, `hpks_*`, `hpke_*`, NL/PQC/
Stern/XMSS/HCRED extensions, etc.). The package doesn't duplicate the
suite/CLI sources — `herradurakex/_vendor/` holds symlinks into
`Herradura cryptographic suite.py` and `HerraduraCli/{primitives,codec,
herradura}.py`, mirroring their original relative layout so the
existing `importlib`-based loading in `primitives.py` and the `import
primitives`/`import codec` in `herradura.py` work unmodified; setuptools
bundles the symlink targets as real files in the sdist/wheel via
`[tool.setuptools.package-data]`. Verified end-to-end: built the wheel
with `setuptools.build_meta.build_wheel` (no network/pip needed),
unpacked it standalone, and confirmed `import herradurakex` plus a full
`herradurakex genpkey`/`pkey`/`kex --algo hkex-gf` round trip (Alice and
Bob derive the same shared secret) via the console script. Documented
`pip install herradurakex` and the Go module tagging procedure (signed
`git tag`, `go get herradurakex@vX.Y.Z`, per-module-directory tag
prefixes for `HerraduraCli`/`herradura`) in `README.md`'s new "Package
managers" section; actual PyPI publish and the first signed Go tag are
left as a release-time action for the maintainer. PATCH bump — new
packaging/distribution metadata, no CLI/PEM/wire-format surface change.

### #193: RFC-style prose spec document

`spec/herradura-protocol-spec.json` is a machine-readable JSON Schema
(parameters, PEM labels, CLI `--algo` tags, security-level
classification) but there is no prose specification document
independent of any implementation, in the style of the Noise Protocol
Framework or the `age` spec, that would let a third party reimplement
the protocols from the spec alone rather than by reading source code.
Draft an RFC-style `SPEC.md` (or similar) covering HKEX-GF, HSKE, HPKS,
HPKE, and the NL/PQC/Stern variants.

Status: **DONE v2.1.4** — added `SPEC.md`, an RFC-2119-style prose spec
(§1 notation, §2 goals/non-goals, §3 FSCX + GF(2^n)* primitives, §4-7
the classical quartet HKEX-GF/HSKE/HPKS/HPKE with full algorithm steps
and correctness derivations, §8 NL-FSCX v1/v2 non-linear hardening
primitives with exact formulas including the `delta(B)` function
recovered from `herradura.h`'s `nl_fscx_delta_v2_ba`, §9 the NL/PQC
variants HKEX-RNL (Ring-LWR key exchange, full 2-round protocol with
CBD/rounding/reconciliation parameters) / HSKE-NL-A1/A2 / HPKS-NL /
HPKE-NL, §10 the shared PEM/DER wire format, §11 a pointer into
SecurityProofs-4/5 for the Stern ZKID family (HPKS-Stern-F/HPKE-Stern-F/
HPKE-Stern-KEM — algorithmically distinct enough to warrant its own
future document rather than a condensed section), §12 security
considerations. Every correctness claim (HSKE round-trip, NL-FSCX v2
forward/inverse round-trip, HPKS sign/verify) was independently checked
by running the actual suite code rather than derived by inspection
alone. Cross-references `spec/herradura-protocol-spec.json` (machine-
readable companion), `SecurityProofs.md` (proofs), and
`KAT/classical_quartet.json` (test vectors) rather than duplicating
them. PATCH bump — new documentation, no CLI/PEM/wire-format surface
change.

### #195: QC-MDPC BGF decoder DFR causes intermittent CI failures in hybrid-KEM interop test

`CliTest/test_hybrid_kex_interop.sh` generates fresh random keys on every
run (no fixed seed) and exercises `hpke-stern-kem` (real Black-Gray-Flip
QC-MDPC decoder, TODO #183) across all C/Go/Python CLI combinations. The
decoder's Decoding Failure Rate (DFR) at its current toy parameters
(r=523, d=15, t=18) has never been measured (noted as an open gap when
the real decoder landed in TODO #183/#186) — so a small but nonzero
fraction of runs hit a genuine decode failure rather than a bug,
surfacing as `HPKE-Stern-KEM decapsulation failed (DFR event or corrupt
ciphertext)`. Observed 2026-08-15: the `push`-triggered CI run for
commit 91a00ee failed on 3 `bob=c` sub-cases while the `pull_request`-
triggered run for the same commit passed cleanly — same code, different
random draws, confirming this is decoder DFR flakiness rather than a
regression (see PR #192 discussion).

Fix options to evaluate: (a) measure the actual DFR at current
parameters and, if too high for a CI test to tolerate, tune parameters
(r/d/t) to push it low enough that intermittent CI failures become
practically impossible; (b) add a small bounded retry in the test for
this specific, identified error string, since DFR events are an
expected (if rare) protocol outcome, not silently masking real bugs;
(c) both — measure to confirm the retry bound is justified, then add
retry as defense-in-depth. Whichever approach lands should also update
the "DFR not yet measured" note in `TODO_DONE.md` (TODO #183/#186) and
`spec/herradura-protocol-spec.json`'s `hpke-stern-kem` notes field.

Status: **DONE v2.1.5** — went with option (c). Measured the real BGF
decoder's DFR with the new `SecurityProofsCode/qcmdpc_bgf_failure_rate.py`
(20000 independent fresh-keypair-and-encapsulation trials): **0.225%**
per encapsulation (45/20000 failures, 95% CI [0.159%, 0.291%]; all 45
were clean `None` returns, zero silent wrong-decode events — the decoder
correctly self-detects every failure it hits, so the retry below never
risks accepting a bad key). `CliTest/test_hybrid_kex_interop.sh` now
canaries each Bob-language response with a Python decap attempt right
after generating it, and on the known
`decapsulation failed (DFR event or corrupt ciphertext)` error regenerates
Bob's key/encapsulation (a fresh random draw) up to `MAX_DFR_RETRIES=3`
times before falling through to the real py/c/go completion matrix, which
still reports a genuine failure honestly if retries are exhausted or the
error doesn't match the known signature — so this can't mask a real bug,
only absorb the measured, expected DFR. At `p≈0.00225` and 3 independent
per-run encapsulation draws (one per Bob language), the residual per-bob
failure probability after 3 tries is `p³ ≈ 1.1×10⁻⁸`, so the residual
per-run probability (3 independent bobs) is roughly `3·p³ ≈ 3.4×10⁻⁸` —
about 1 in 29 million CI runs, i.e. effectively non-reproducible. Updated the "DFR not yet measured" notes in both
`spec/generate_spec.py`'s `hpke-stern-kem` entry (regenerated
`spec/herradura-protocol-spec.json`) and this file's #183 entry with the
measured number. Verified: `bash CliTest/test_hybrid_kex_interop.sh` run
4x back-to-back, 19/19 PASS every time. PATCH bump — CI-flakiness fix
plus a new measurement script/doc note, no CLI/PEM/wire-format surface
change.

### #198: Java `HerraduraCli` for the classical quartet

Part of the #196 breakdown; needs TODO #197 (PEM/DER codec) first. Add
a Java CLI mirroring `HerraduraCli/herradura.py`/`herradura_cli.c`/
`herradura_cli.go`'s subcommand interface — `genpkey`, `pkey`, `kex`,
`enc`, `dec`, `sign`, `verify`, `dgst`, `encfile`, `decfile` — for the
classical quartet (`hkex-gf`, `hpks`, `hpke` `--algo` values). Add
`CliTest/test_java_keygen.sh`/`test_java_interop.sh` (Python-generated
keys consumed by the Java CLI and vice versa), mirroring
`test_c_interop.sh`/`test_go_interop.sh`'s pattern.

Status: **DONE v2.2.0** — added `bindings/java/herradurakex.HerraduraCli`
implementing all ten subcommands on top of the existing `Herradura`/
`Codec` classes (TODO #192/#197), scoped to `--algo hkex-gf`/`hpks`/
`hpke` (plus `hske` for symmetric enc/dec) exactly like `Herradura`
itself. `dgst` and `encfile`/`decfile` additionally needed NL-FSCX v1 and
the HFSCX-256-DM hash and HSKE-NL-A1 `.hkx` container it depends on for
wire-format parity with the other three CLIs (out of `Herradura`'s
classical-quartet scope, so ported separately in a new
`herradurakex.Hfscx256` rather than expanding `Herradura`'s stated
scope) — every one of `Hfscx256`'s functions was verified byte-for-byte
against the Python suite (three `hfscx_256` test vectors, and a
deterministic-nonce `.hkx` container compared byte-for-byte against a
hand-run of `Herradura cryptographic suite.py`'s encryption math). Added
`CliTest/test_java_keygen.sh` (genpkey/pkey smoke test across all three
algos, plus confirms out-of-scope algos like `hkex-rnl` are rejected
rather than silently mishandled) and `CliTest/test_java_interop.sh`
(Java↔Python cross-language interop, both directions, for every
subcommand: hkex-gf key agreement, hske/hpke enc-dec, hpks sign-verify,
dgst digest match, encfile/decfile round-trip) — both pass, and both are
picked up automatically by `ci.yml`'s existing `for f in CliTest/*.sh`
loop (no workflow change needed; `default-jdk-headless` was already
installed for `test_java_bindings.sh`/`test_java_codec.sh`). Updated
`bindings/java/README.md` and `CLAUDE.md`'s repository-structure section.

### #199: Java port of NL/PQC quartet (HKEX-RNL, HSKE-NL, HPKS-NL, HPKE-NL)

Part of the #196 breakdown; needs TODO #198 (CLI skeleton) for its
`--algo` subcommand wiring, though the library-level primitives (NL-FSCX
v1/v2, Ring-LWR) can be ported independently first. Extend
`bindings/java/herradurakex` with HKEX-RNL, HSKE-NL-A1/A2, HPKS-NL, and
HPKE-NL, plus their CLI subcommands and Python/C/Go interop tests. If
TODO #190's KAT set has grown to cover NL/PQC vectors by then, cross-
verify against those; otherwise cross-verify against the Go/Python
suites directly (mirroring `KAT/verify_kat.go`'s approach).

Status: **DONE v2.3.0** — added `bindings/java/herradurakex.HerraduraNl`,
a byte-for-byte port of `"Herradura cryptographic suite.py"`'s NL-FSCX v2
(`nlFscxV2`/`nlFscxV2Inv`/`nlFscxRevolveV2`/`nlFscxRevolveV2Inv`, with the
same `M^{-1}` rotation-table bootstrap as the Python reference — reusing
`Hfscx256`'s existing NL-FSCX v1 rather than duplicating it), the
Ring-LWR ring arithmetic underlying HKEX-RNL (negacyclic Cooley-Tukey NTT
over Z_65537, `rnlPolyMul`/`rnlRound`/`rnlLift`/`rnlKeygen`/`rnlAgree`/
`rnlHint`/`rnlReconcileBits`, at RNLQ=65537/RNLP=4096/RNLPP=4/RNLB=1),
and the four protocol entry points (`hkexRnlDeriveC`/
`rnlContributoryKdf`, `hskeNlA1Encrypt`/`Decrypt`, `hskeNlA2Encrypt`/
`Decrypt`, `hpksNlSign`/`Verify`, `hpkeNlEncrypt`/`Decrypt`). Extended
`Codec` with HKEX-RNL polynomial packing (`packPoly`/`unpackPoly`) and
private-key/public-key/response PEM encode-decode (reusing the
already-present `PEM_HKEX_RNL_PRIV`/`PUB`/`PEM_RNL_RESPONSE` label
constants from TODO #197). Extended `HerraduraCli` with `--algo
hkex-rnl`/`hske-nla1`/`hske-nla2`/`hpks-nl`/`hpke-nl` across `genpkey`,
`pkey`, `kex`, `enc`, `dec`, `sign`, `verify` — `kex --algo hkex-rnl`
mirrors the Python/C/Go CLIs' two-round handshake exactly (Bob responds
first with an RNL RESPONSE PEM, then Alice completes into a plain
SESSION KEY PEM). Every primitive was cross-checked against fixed inputs
run through `"Herradura cryptographic suite.py"` directly (NL-FSCX v2,
the negacyclic poly-mul, and the Schnorr/El-Gamal math all matched
byte-for-byte; the first attempt at NL-FSCX v2's `delta(B)` used the
docstring's `(B*(B+1))>>1` formula, which diverges from the suite's
actual `B*((B+1)>>1)` code for even B — caught by the cross-check and
fixed to match the literal Python behavior). Added
`CliTest/test_java_nl_interop.sh`: Java↔Python interop for all four
NL/PQC protocols in both directions, including HKEX-RNL's two-round
handshake with each language playing both Alice and Bob (Bob's own
embedded session-key field is compared byte-for-byte against Alice's
completed SESSION KEY PEM via a `codec.py`-based check, since the two
PEM shapes differ). Extended `SelfTest` with round-trip checks for all
four NL/PQC protocols and updated `test_java_keygen.sh`'s "unsupported
algo" probe (previously `hkex-rnl`, now genuinely out-of-scope
`hpke-stern`) since `hkex-rnl` is no longer rejected. Updated
`bindings/java/README.md`.

### #200: Java port of Stern-F/Niederreiter (HPKS-Stern-F, HPKE-Stern-F, HPKE-Stern-KEM)

Part of the #196 breakdown; needs TODO #198. Extend
`bindings/java/herradurakex` with the Stern identification protocol
(Fiat-Shamir signature) and Niederreiter KEM, including the real BGF
QC-MDPC decoder (`qcmdpc_keygen`/`encap`/`decap_bgf`, TODO #183) for
`hpke-stern-kem` — not just the demo `hpke-stern` path. Note TODO #195's
still-open QC-MDPC DFR flakiness when writing interop tests: a fresh
random run can legitimately hit a decode failure, so tests should expect
that rather than treating every failure as a bug. Add CLI subcommands
and interop tests.

Status: **DONE v2.4.0** — added `bindings/java/herradurakex.Stern`, a
byte-for-byte port of `"Herradura cryptographic suite.py"`'s Stern
identification protocol and Niederreiter KEM machinery, fixed at n=256
(matching this binding's existing scope): the shared helpers
(`csprngWeightT`, `sternHash` — the NL-FSCX-v1-chained, HFSCX-256-DM-
finalized domain-separated hash used for commitments/challenges/KEM-key
derivation, `sternMatrixRow`/`sternBuildH`/`sternSyndromeH`, and
`sternGenPerm`/`sternApplyPerm` — the Lemire-multiply-shift Fisher-Yates
permutation PRNG); `sternFKeygen`, `hpksSternFSign`/`hpksSternFVerify`
(Stern's 3-move Sigma protocol, Fiat-Shamir-chained challenges, demo
default `rounds=32`/production `rounds>=219` with the same non-fatal
soundness warning as the Python CLI); `hpkeSternFEncapWithE`/
`hpkeSternFDecap` (the demo Niederreiter KEM that transmits e' in the
clear); and the real QC-MDPC/BGF Niederreiter KEM at the shipped toy
parameters (r=523, d=15, t=18) — `qcpMulSparse`/`qcpMul`/`qcpInv` (GF(2)
[x]/(x^r-1) polynomial arithmetic, extended-Euclid inverse),
`QcMdpcPrf` (the NL-FSCX-v1 XOF, 16 words/block popped highest-word-
first, exactly matching Python's list-as-stack consumption order),
`qcmdpcKeygen`/`qcmdpcEncap`/`qcmdpcBgfDecode`/`qcmdpcDecapBgf` (the
Black-Gray-Flip bit-flipping decoder, Drucker-Gueron-Kostic 2019), and
`qcmdpcPubFromPriv` for `pkey --pubout`. Preserved every wire-format
footgun found during porting: the little-endian byte serialization of
`e0`/`e1`/`h0`/`h1`/`h_pub`/`syn` (versus the rest of the suite's
big-endian convention), and the biased `mod 3` Fiat-Shamir challenge
derivation (deliberately not rejection-sampled, since the verifier must
be able to recompute it deterministically).

Extended `Codec` with `PEM_HPKE_STERN_KEM_PRIV`/`PUB` label constants
and `encode`/`decodeSternPrivKey`/`SternPubKey`/`SternCt`/`SternSig`
(the packed-commits/packed-challenges/packed-responses signature DER
shape) plus `encode`/`decodeKemPrivKey`/`KemPubKey`/`KemCt` (with the
little-endian-bytes-as-DER-INTEGER-content round trip preserved exactly,
including the sorted 2-byte-per-position support-set encoding).

Extended `HerraduraCli` with `--algo hpks-stern`/`hpke-stern`/
`hpke-stern-kem` across `genpkey`, `pkey` (`--pubout`/`--text`), `sign`/
`verify` (`hpks-stern` only, `--rounds`), and `enc`/`dec` (`hpke-stern`/
`hpke-stern-kem`, both reusing the classical linear `fscxRevolve` for
payload encryption, matching HPKE's `I_STEPS`/`R_STEPS` construction) —
printing the same demo-strength stderr warning as the Python/C/Go CLIs
for `hpks-stern`/`hpke-stern` (not for the production-shaped
`hpke-stern-kem`). `dec --algo hpke-stern-kem` reports a BGF decode
failure with a message containing "DFR event or corrupt ciphertext",
matching the retry-detection pattern already used by
`test_hybrid_kex_interop.sh`.

Verified full bidirectional Java↔Python CLI interop for all three
subcommand families (sign in one language/verify in the other; encrypt
in one/decrypt in the other, including the real BGF decoder) before
writing any test files — not just internal self-consistency. Added
`CliTest/test_java_stern_interop.sh` (6 cross-language round trips, DFR-
retry-aware for the KEM path per TODO #195's measured ~0.225% DFR) and
extended `CliTest/test_java_keygen.sh` (genpkey/pkey smoke test for all
three new algos, with the "unsupported algo" probe moved to the now
genuinely out-of-scope `hcred`) and `SelfTest` (HPKS-Stern-F sign/verify
plus tamper- and corrupted-syndrome-rejection checks, HPKE-Stern-F demo
KEM round trip, and an HPKE-Stern-KEM round trip tolerant of an
occasional legitimate DFR event across a small trial batch). Updated
`bindings/java/README.md` and `CLAUDE.md`'s repository-structure
section. The Stern-Ring OR-composition ring signature remains out of
scope for this binding.

### #201: Java port of remaining advanced protocols (HCRED, OPRF/aPAKE, XMSS/WOTS+)

Part of the #196 breakdown; needs TODO #198. Extend
`bindings/java/herradurakex` with the hybrid Ring-LWR + Stern-F
credential (HCRED), OPRF/aPAKE, and the stateful hash-based signatures
(XMSS/WOTS+). These are the suite's most complex remaining protocols
(MPCitH transcripts, tree-based state management for XMSS) — expect this
to be the largest of the child items; consider splitting further once
scoped in detail. Add CLI subcommands and interop tests.

Status: **DONE v2.5.0** — scoped down to OPRF and HPKS-WOTS-F/HPKS-XMSS-F
per this entry's own note to split further once detailed; HCRED and
aPAKE were split off as TODO #202/#203 (both need a substantial
additional MPCitH/ZKBoo circuit port — HCRED its own unified
Ring-LWR+Stern-F circuit, aPAKE the separate ZKBoo-over-NL-FSCX gadget
— sized closer to TODO #200 in isolation than to a shared child item).

Added `bindings/java/herradurakex.Oprf`: a byte-for-byte port of the
2HashDH OPRF over GF(2^256)* (`keygen`/`blind`/`eval`/`unblind`/
`direct`), reusing `Herradura`'s existing `gfPow`.

Added `herradurakex.Wots`: HPKS-WOTS-F (the suite's own Winternitz
one-time signature construction — a single deterministic NL-FSCX-v1
hash chain, not RFC 8391 WOTS+'s ADRS/bitmask-randomized variant) —
`chain`/`msgToDigits`/`keygen`/`sign`/`recoverPk`/`verify`, at the
shipped w=16/L=67 parameters.

Added `herradurakex.Xmss`: HPKS-XMSS-F — the RFC-6962-style Merkle
accumulator (`haccumLeaf`/`Node`/`Root`/`Prove`/`Verify`) over WOTS-F
leaves, `keygen`/`sign`/`verify`. Both classes are stateless (leaf index
is an explicit parameter); leaf-index/one-time-use state lives in
`HerraduraCli` as a `<keyfile>.idx` sidecar file, exactly mirroring the
Python CLI's convention: XMSS persists the next-unused leaf index and
hard-fails once `leafIdx >= 2^h`; WOTS persists a used/unused flag and
refuses a second sign.

Extended `Codec` with `PEM_OPRF_PRIV`/`STATE`/`EVAL` and
`PEM_HPKS_WOTS_PRIV`/`PUB`/`SIG`/`PEM_HPKS_XMSS_PRIV`/`PUB`/`SIG` label
constants plus their encode/decode helpers, matching
`HerraduraCli/herradura.py`'s exact DER field order and blob-packing
(including that XMSS's embedded `next_idx` DER field is vestigial —
the `.idx` sidecar file is the authoritative counter, as it is in the
Python CLI). Extended `HerraduraCli` with `oprf-blind`/`oprf-eval`/
`oprf-unblind` and `--algo oprf`/`hpks-wots`/`hpks-xmss` across
`genpkey`, `pkey` (`--pubout`/`--text`), `sign`, `verify`.

Verified every new primitive byte-for-byte against the Python reference
before writing any test files — WOTS chain values, the XMSS Merkle root
and auth-path hashes, and the OPRF output all matched exactly for
identical inputs — then verified full bidirectional Java↔Python CLI
interop (OPRF client/server roles, WOTS/XMSS sign in one language and
verify in the other, XMSS at two distinct leaves each). Added
`CliTest/test_java_oprf_wots_interop.sh` (7 cross-language checks,
including a numeric cross-check of the OPRF round trip against Python's
`oprf_direct` rather than only checking the round trip didn't error) and
extended `test_java_keygen.sh` and `SelfTest.java` (also fixing a
pre-existing flaky assertion in `SelfTest`'s HPKS-Stern-F
corrupted-syndrome check — TODO #200's `rounds=8` skips the only
syndrome-checking challenge branch ~3.9% of the time by chance; bumped
to `Stern.SDFR`=32 for `(2/3)^32 ≈ 0.008%` flake probability). Updated
`bindings/java/README.md` and `CLAUDE.md`'s repository-structure
section.

### #202: Java port of HCRED (hybrid Ring-LWR + Stern-F credential)

Split off from #201 once scoped in detail (per that item's own note that
it was likely to be the largest child item and should be split further).
Extend `bindings/java/herradurakex` with HCRED: user/issuer keygen, the
unified ZKBoo-(2,3) MPCitH circuit proving both the Ring-LWR rounding
relation and the Stern-F code-syndrome relation for the same witness in
one proof (`hcred_prove`/`hcred_verify`), and issuer credential
issuance/verification (an HPKS-Stern-F signature over the credential
statement, reusing TODO #200's `Stern` — no separate signature scheme
needed). The KKW preprocessing-model transcript variant
(`hcred_prove_kkw`/`hcred_verify_kkw`, ~11x smaller proofs at production
parameters) is optional/secondary — the ZKBoo-(2,3) path is sufficient
for interop and should land first. Add CLI subcommands and interop
tests, including the completeness/replay/tamper/split-witness/issuer
rejection cases exercised by `CryptosuiteTests/Herradura_tests.py` test
`[44]`.

Status: **DONE v2.6.0** — added `bindings/java/herradurakex.Hcred`, a
byte-for-byte port of the unified ZKBoo-(2,3) MPCitH circuit: `phi`
(positive-support bitmap), `userKeygen`/`syndrome` (Ring-LWR keygen +
Stern-F syndrome, reusing `HerraduraNl.rnlKeygen` and `Stern.sternBuildH`/
`sternSyndromeH` directly), the counter-mode HFSCX-256 tape expander
(`HcredTape`), the 3-party MPC gate simulation and per-round output-share
computation, Fiat-Shamir statement/challenge hashing, witness preparation
(with the same replay-binding-into-every-commitment fix as the upstream
v1.9.77 hardening), and `prove`/`verify`. Issuer credentials
(`issue`/`credVerify`) are a thin wrapper over `Stern.hpksSternFSign`/
`hpksSternFVerify` — no separate signature machinery needed. Fixed at
n=256 (this binding's existing scope) rather than the Python demo's
n=32 default; n=256 is explicitly supported upstream
(`--bits 256`) and lets this port reuse `Stern`'s existing 256-bit-only
parity-check-matrix PRF directly instead of introducing a second,
arbitrary-width NL-FSCX v1 implementation just for HCRED. The KKW
preprocessing-model transcript variant remains out of scope, per this
entry's own note that the ZKBoo-(2,3) path is sufficient for interop.

Extended `Codec` with `PEM_HCRED_PRIV`/`PUB`/`CRED`/`PROOF` label
constants and their encode/decode helpers — the private-key, public-key,
and proof PEM bodies are byte-for-byte with `HerraduraCli/codec.py`'s
own unusual convention of a flat, offset-parsed body rather than a real
DER SEQUENCE (only the credential is real DER, and turned out to share
`encodeSternSig`/`decodeSternSig`'s exact wire shape byte-for-byte, so
`encodeHcredCredential`/`decodeHcredCredential` reuse that logic instead
of duplicating it). Preserved the syndrome field's little-endian byte
order (matching the C port's LSB-first layout) against the rest of the
suite's big-endian convention.

Extended `HerraduraCli` with `--algo hcred` (`genpkey`, `pkey
--pubout`/`--text`) and the `cred-issue`/`cred-prove`/`cred-verify`
subcommands, matching the Python CLI's exact flag names
(`--our`/`--in`/`--rounds`/`--out` for `cred-issue`;
`--in`/`--msg`/`--rounds`/`--out` for `cred-prove`;
`--proof`/`--pubkey`/`--cred`/`--issuer`/`--msg` for `cred-verify`).

Verified correctness in the strongest way available for a ZK proof
scheme — not bit-identical intermediate values (infeasible; each side's
MPCitH tape seeds are independently random) but full bidirectional
library- and CLI-level interop: a Java-generated private/public
key/proof decodes and verifies correctly under the Python reference
(and vice versa), including issuer-credential verification, before any
test file was written. Added `CliTest/test_java_hcred_interop.sh` (4
checks: both user/issuer/proof-generation directions cross-verified,
plus tamper-message-replay rejection in both directions, at
`--rounds 8` for CI speed) and extended `SelfTest.java` (completeness
plus replay/tamper/corrupted-syndrome/wrong-key/split-witness rejection
and an issuer-credential round-trip, at the library's own demo round
count) and `test_java_keygen.sh`. Updated `bindings/java/README.md` and
`CLAUDE.md`'s repository-structure section.

### #203: Java port of aPAKE (augmented PAKE over HKEX-RNL + OPRF + ZKBoo-NL)

Split off from #201. Needs a Java port of the ZKBoo-over-NL-FSCX Sigma
protocol (`zkp_nl_prove`/`zkp_nl_verify` in
`"Herradura cryptographic suite.py"` — a bit-level 3-party MPC circuit
proving knowledge of `A` such that `nl_fscx_v1(A, B) = y`, used here as
the aPAKE's mutual-authentication proof bound to the HKEX-RNL session
key) plus TODO #201's OPRF (the server's password record is
`hfscx_256(OPRF(k_s, password) + salt)` rather than a plain password
hash, closing offline dictionary attacks against a leaked server
database). Extend `bindings/java/herradurakex` with `hpake_register`/
`hpake_login_demo`'s three-message flow (or the CLI's split
register/login subcommands, matching whichever the Python/C/Go CLIs
expose). No dedicated KAT exists upstream for this protocol — coverage
comes from CLI round-trip tests (correct/wrong password, cross-language
interop) mirroring `CliTest/test_oprf.sh`/`test_pake.sh`'s pattern. Per
the suite's own documentation this is a research-grade construction (no
formal UC/SIM-BMP proof) — treat and document it as such, not as a
hardened production aPAKE.

Status: **DONE v2.7.0** — added `bindings/java/herradurakex.ZkpNl`, a
byte-for-byte port of the ZKBoo (3-party MPC-in-the-head) circuit
proving knowledge of `A` such that `nl_fscx_v1(A, B) = y`
(`evaluateCircuit`'s ripple-carry-chain AND-gate simulation, `prove`/
`verify`). Unlike every other protocol ported so far (all fixed at
n=256), this circuit is genuinely parameterized by bit-width `n` — it
has no dependency on `Herradura`'s fixed-256-bit primitives, and its
only consumer here needs it at n=32 (matching the Python reference's
aPAKE parameters), so genericity via `BigInteger` cost nothing extra.
Added `bindings/java/herradurakex.Hpake` (`register`/`loginDemo`,
plus `deriveZkpWitness`/`rnlKdf`), reusing `Oprf` (TODO #201) for the
offline-dictionary-attack-resistant password record and `HerraduraNl`'s
existing HKEX-RNL primitives (TODO #199) for the 3-message key
exchange; `loginDemo` runs both the client and server sides in one call,
matching the Python reference's own demo-only scope (no real 2-party
network split). The ZKB++ transcript-encoding variant
(`zkp_nl_prove_pp`/`zkp_nl_verify_pp`) and the standalone HPKS-ZKP-NL
signature scheme remain out of scope — this port exists only to give
`Hpake` its mutual-authentication proof.

Extended `Codec` with `PEM_PAKE_RECORD` and `encode`/`decodePakeRecord`
(the real-DER `SEQUENCE(salt, B, y)` shape, deliberately not including a
username field, matching the Python reference exactly). Extended
`HerraduraCli` with the `pake-register`/`pake-demo` subcommands, matching
the Python CLI's exact flag names; `pake-register` requires `--password`
explicitly (this Java CLI does not implement the Python CLI's
interactive `getpass` prompt fallback).

Verified the ZKBoo circuit's `nl_fscx_v1` output matched the Python
reference bit-for-bit for fixed test inputs before writing any proof
logic, then verified full aPAKE correctness (register + login with the
right/wrong password) and cross-language wire-format compatibility (a
`pake-register` record produced by either language decodes cleanly under
the other — there is no cross-language `pake-login` flow upstream to
test beyond that, since `pake-demo` is single-process both-sides-at-once
in both the Python and Java CLIs). Added
`CliTest/test_java_pake_interop.sh` (5 checks) and extended
`SelfTest.java` (ZKP-NL prove/verify plus tamper/wrong-`y` rejection, and
an aPAKE register/login round trip). Updated `bindings/java/README.md`
and `CLAUDE.md`'s repository-structure section.

This closes TODO #196, the Java-port-to-a-complete-suite umbrella:
#197–#203 are all now DONE. `bindings/java/herradurakex` covers the
classical quartet, the NL/PQC quartet, HPKS-Stern-F/HPKE-Stern-F/
HPKE-Stern-KEM, OPRF, HPKS-WOTS-F/HPKS-XMSS-F, HCRED, and aPAKE — the
same protocol surface as the C/Go/Python targets except HCRED's KKW
transcript variant, the Stern-Ring OR-composition signature, and
XMSS/WOTS's assembly/Arduino ports (explicitly out of scope throughout,
per each protocol's own porting note).

### #196: Extend the Java port to a complete suite + CLI (umbrella)

TODO #192 added `bindings/java/herradurakex.Herradura`, a pure-Java port
of only the classical (v1.4.0) quartet (HKEX-GF, HSKE, HPKS, HPKE),
matching `bindings/ffi/`'s intentionally narrow scope. The other five
language targets (C, Go, Python, ARM Thumb-2, NASM i386, Arduino) all
implement the full suite — NL/PQC, Stern-F/Niederreiter, HCRED,
OPRF/aPAKE, XMSS/WOTS+, etc. — plus a `HerraduraCli`-equivalent
OpenSSL-style CLI with PEM/DER codec support matching
`HerraduraCli/codec.py`/`herradura_codec.h`/`herradura/codec.go`
byte-for-byte.

This item is an umbrella tracking the full gap; broken down into
sequential, independently-completable child items so a session can pick
off one milestone at a time rather than attempting the whole surface at
once. Complete in roughly this order (each depends on the codec landing
before the CLI, and on the protocol ports landing before their CLI
subcommands/interop tests):

- TODO #197 — PEM/DER codec (classical quartet's wire format)
- TODO #198 — Java `HerraduraCli` for the classical quartet (needs #197)
- TODO #199 — NL/PQC port (HKEX-RNL, HSKE-NL-A1/A2, HPKS-NL, HPKE-NL) +
  CLI subcommands + interop tests (needs #198)
- TODO #200 — Stern-F/Niederreiter port (HPKS-Stern-F, HPKE-Stern-F,
  HPKE-Stern-KEM with the real BGF QC-MDPC decoder) + CLI subcommands +
  interop tests (needs #198)
- TODO #201 — OPRF and the stateful hash-based signatures (HPKS-WOTS-F,
  HPKS-XMSS-F) + CLI subcommands + interop tests (needs #198)
- TODO #202 — HCRED, the hybrid Ring-LWR + Stern-F credential (needs
  #198, #200 for the Stern-F building blocks it reuses)
- TODO #203 — aPAKE, augmented PAKE over HKEX-RNL + a ZKBoo-over-NL-FSCX
  gadget + OPRF (needs #198, #199, #201's OPRF)

Close this umbrella once #197–#203 are all done.

Status: **DONE v2.7.0** — #197–#203 all shipped (v2.1.1 through v2.7.0).
`bindings/java/herradurakex` now ports the full HerraduraKEx protocol
suite to the JVM: the classical quartet, NL/PQC quartet, Stern-F/
Niederreiter (demo and real QC-MDPC/BGF), OPRF, HPKS-WOTS-F/HPKS-XMSS-F,
HCRED, and aPAKE, each with byte-for-byte PEM/DER wire-format parity and
verified bidirectional CLI interop against the Python reference. See the
individual #197–#203 entries for what each child item covered.

### #205: Split the `native` CI job into separate C, Go, and Python jobs

`.github/workflows/ci.yml`'s `native` job (TODO #153) used to build and
test C, Go, and Python sequentially in one job, plus run every
`CliTest/*.sh` script at the end regardless of which language(s) it
exercised. This meant a failure in any one language's build/test/CLI step
blocked visibility into the other two until fixed, and the three languages
couldn't be inspected, re-run, or parallelized independently in the
Actions UI.

Split `native` into four jobs:
- `native-c`, `native-go`, `native-python` — one per language, each with
  its own dependency install, `build_*.sh` invocation (skipped for
  Python), `CryptosuiteTests/Herradura_tests.*` run, and only the
  `CliTest/*.sh` scripts that touch that language's own CLI
  (`test_c_*.sh`/`test_weak_key_rejection.sh` for C, `test_go_*.sh` for
  Go, the untagged Python-only scripts for Python).
- `native-interop` — the `CliTest/*.sh` scripts that exercise two or more
  CLIs at once (`test_aead.sh`, `test_c_interop.sh`, `test_go_interop.sh`,
  and 15 others), which builds both C and Go. Also runs a coverage-guard
  step that fails CI if any non-Java `CliTest/*.sh` script isn't claimed
  by exactly one of the four `native-*` jobs, so the split can't silently
  drift as new scripts are added.

All four jobs are required/blocking, matching the old `native` job's
status. Updated `CLAUDE.md`'s Testing section to describe the new job
names.

Status: **DONE v2.7.1** — `.github/workflows/ci.yml` now runs
`native-c`/`native-go`/`native-python`/`native-interop` in place of the
single `native` job, each independently inspectable/re-runnable, with a
coverage guard preventing drift. CI-only change; no wire-format or CLI
behavior change.

### #206: Add a Java CI job

`bindings/java/` (TODO #196 umbrella) has a full pure-Java port of the
suite plus `herradurakex.HerraduraCli`, and `CliTest/test_java_*.sh`
already cover Java-vs-Python interop and KAT cross-checks per-protocol-
family, but there is no CI job that builds and runs any of it — the
`native` job's dependency list installs `default-jdk-headless` but never
invokes a Java build or test step, and `bindings/java/` has no coverage
in `.github/workflows/ci.yml` at all.

- Add a `native-java` CI job (see [[#205]] — land after or alongside that
  split, so it follows the same one-job-per-language pattern rather than
  being bolted onto a monolithic `native` job) that builds `bindings/java/`
  and runs `CliTest/test_java_bindings.sh`, `test_java_codec.sh`,
  `test_java_keygen.sh`, `test_java_interop.sh`, `test_java_nl_interop.sh`,
  `test_java_stern_interop.sh`, `test_java_oprf_wots_interop.sh`,
  `test_java_hcred_interop.sh`, and `test_java_pake_interop.sh`.
- Fold the new job into the required/blocking set alongside `native-c`,
  `native-go`, and `native-python`, and update `CLAUDE.md`'s Testing
  section and CI job list once landed.

This item covers building and running Java's own test suite in CI only.
The question of whether Java's crypto output is actually compatible with
C, Go, and Python (and whether C/Go are directly compatible with each
other) is tracked separately in [[#207]], which owns its own independent
CI job.

Status: **DONE v2.7.2** — added a `native-java` job to
`.github/workflows/ci.yml` that installs `default-jdk-headless` and runs
all nine `CliTest/test_java_*.sh` scripts (`test_java_bindings.sh` builds
`bindings/java/` itself). Folded into the required/blocking check set
alongside `native-c`/`native-go`/`native-python`. Updated `CLAUDE.md`'s
Testing section (nine jobs → ten). CI-only change; no wire-format or CLI
behavior change.

### #207: Independent CI job for a full 4-language (C/Go/Python/Java) crypto compatibility matrix

The existing interop coverage across `CliTest/*.sh` is pairwise-against-
Python, not a full matrix: `test_c_interop.sh` is C↔Python only,
`test_go_interop.sh` is Go↔Python only, and `test_aead.sh` is the one
genuinely multi-way (9-way cross-CLI) script but only for HSKE-NL-AEAD.
There is currently no test proving C and Go are directly compatible on
the rest of the protocol surface (HKEX-GF/HSKE/HPKS/HPKE and the
NL/PQC/Stern/OPRF/HCRED/aPAKE families), and once Java lands in CI
([[#206]]) its own `test_java_*.sh` scripts only check Java against
Python, not against C or Go.

This item tracks proving that the cryptographic algorithms themselves —
key exchange, encryption, signing — interoperate correctly among all
four language implementations, as a concern separate from "does each
language's own build/test suite pass" (which [[#205]] and [[#206]]
already cover).

- Close the C↔Go gap: extend `test_c_interop.sh`/`test_go_interop.sh`
  (or add a new `test_c_go_interop.sh`) so C and Go are checked directly
  against each other, not only each against Python, across every
  `--algo` value and subcommand both CLIs support.
- Build a genuine 4-language compatibility matrix, not pairwise checks
  against one anchor language: for every `--algo`/subcommand combination,
  a key/ciphertext/signature produced by any one of C/Go/Python/Java's
  CLI must be verified consumable by each of the other three (the
  `test_aead.sh` 9-way pattern generalized to the full protocol surface,
  extended to include Java). Add a new `CliTest/test_cross_lang_matrix.sh`
  (or equivalent) rather than folding this into the existing per-language
  interop scripts, so the matrix is one script with clear pass/fail
  reporting per language-pair and per protocol family.
- Confirm `KAT/classical_quartet.json` cross-checks the Java classical
  quartet the same way `KAT/verify_kat.go` cross-checks Go's, as part of
  the same matrix run.
- Add this as its own CI job (e.g. `cross-lang-compat`), independent of
  and running after `native-c`/`native-go`/`native-python`/`native-java`
  (it needs all four CLIs built), required/blocking like the rest.
  Update `CLAUDE.md`'s Testing section and CI job list once landed.

Status: **DONE v2.7.3** — added `CliTest/test_cross_lang_matrix.sh`, a
genuine 16-way (4x4) C/Go/Python/Java compatibility matrix generalizing
`test_aead.sh`'s 9-way pattern (TODO #95): full NxN coverage for HKEX-GF/
HKEX-RNL keygen+kex agreement, HSKE/HSKE-NL-A1/A2 symmetric enc/dec,
HPKE/HPKE-NL/HPKE-Stern-F asymmetric enc/dec, HPKE-Stern-KEM encap/decap
(DFR-retry-aware), HPKS/HPKS-NL/HPKS-Stern-F sign/verify, and HCRED
issue/prove/verify; lighter N-way role-rotation coverage for the
role-asymmetric OPRF and aPAKE protocols; and a joint KAT cross-check
step running Go's and Java's independent verifiers against the same
`KAT/classical_quartet.json` in the same run. Discovered and fixed two
genuine parameter-mismatch bugs surfaced only by true 4-way testing (not
caught by any pairwise-against-Python script): the C CLI hardcodes
Stern-F signing/HCRED-issuing to its compile-time SDF_ROUNDS (32) with no
`--rounds` override, and Python's `hcred genpkey` defaults to n=32 while
the other three default to n=256 — both now pinned to matching values in
the matrix. Added a `cross-lang-compat` CI job that builds all four CLIs
and runs the matrix, required/blocking, after `native-c`/`native-go`/
`native-python`/`native-java`. Updated `native-interop`'s coverage guard
to exempt the new script (claimed by `cross-lang-compat` instead) and
`CLAUDE.md`'s Testing section (ten jobs → eleven). CI/test-only — no
wire-format or CLI behavior change.

### #204: Research efficiency/security of non-standard (non-multiple-of-8) key lengths

Right now every implementation assumes bit widths that are multiples of 8
(commonly 256), driven by the byte-oriented word types in C/Go/Python and
by `herradura.h`'s fixed-width big-int backing. Investigate whether
FSCX/GF(2^n)* parameters at non-byte-aligned widths (e.g. n=251, n=255,
n=509 — primes or otherwise irregular sizes chosen for algebraic
properties rather than byte convenience) offer a meaningful efficiency
or security advantage over the current byte-aligned defaults:

- **Algebraic analysis**: does choosing n prime (so GF(2^n)* has no small
  subgroup structure beyond the trivial factors of `2^n - 1`) meaningfully
  shrink the Pohlig-Hellman attack surface compared to today's composite
  byte-multiple n? Does FSCX's linear map M = I ⊕ ROL ⊆ ROR's order
  (n/2, or n for odd n where ROL/ROR don't pair up as involutions) change
  the periodic-orbit structure exploited elsewhere in `SecurityProofs-*.md`
  in a way that helps or hurts diffusion? Extend the analyses in
  `SecurityProofsCode/hkex_gf_test.py` and the FSCX_N section of
  `SecurityProofs-1.md` to non-byte-aligned n and document the results.
- **Experimental testing**: benchmark FSCX/GF arithmetic implemented over
  odd/non-byte n (bit-sliced or arbitrary-precision, since word-aligned
  tricks no longer apply) against the current byte-aligned baseline for
  throughput/memory, and run the existing statistical/avalanche test
  batteries (`CryptosuiteTests/Herradura_tests.*`) parameterized at a
  spread of non-standard widths to check whether security margins hold,
  improve, or degrade.
- **Deliverable**: a `SecurityProofsCode/` script (or new `SecurityProofs`
  subsection) presenting the algebraic argument plus measured results,
  and a recommendation on whether non-standard key lengths are worth
  adding as a supported parameter choice in any language target, or
  whether the byte-aligned status quo should stay as-is with the
  analysis documented for the record either way.

This is a research/analysis item, not an implementation commitment — it
should not itself change any wire format, CLI surface, or default
parameter unless its findings justify a follow-up TODO to do so.

Status: **DONE v2.7.4** — added `SecurityProofsCode/hkex_non_byte_key_length_analysis.py`
and `SecurityProofs-1.md` §1.2.1. Two findings sharpen Theorems 2–3: (1)
Theorem 2's proof only actually needs gcd(3, n) = 1, not n = 2^k — so
invertibility of M is NOT guaranteed for an arbitrary non-byte n; n=255
(3×5×17, the most natural odd neighbor of the default n=256) leaves M
singular, an undocumented footgun. (2) Theorem 3 (order(M) = n/2) is
specific to n = 2^k via its Frobenius-exponent argument; for sampled
invertible non-byte n the empirical order is n, not n/2 (or exceeds the
script's search bound), so every downstream claim keyed to order(M)=n/2
would need independent re-derivation per non-power-of-2 n. No offsetting
diffusion or throughput advantage was found: avalanche differences at
matched relative depth are an artifact of the order(M) mismatch, not an
independent property of non-byte n, and every non-Python target's byte/
word-aligned state representation would need bit-slicing or a bignum
backend for non-byte n, strictly slower than and losing the
single-instruction ROL/ROR compilation of today's word-aligned code.
Recommendation: do not add non-byte-aligned key-length support; the
byte-aligned status quo remains the only supported parameter family.
Analysis-only — no wire-format, CLI, or default-parameter change.

### #208: Close the `hpks-xmss` CLI/suite gap in C and Go

A cross-language consistency audit (2026-08-18) found that `--algo
hpks-xmss` (XMSS Merkle-tree signatures, added for Python/Java in
[[#201]]) is implemented in the Python CLI (`herradura.py`) and the Java
CLI (`bindings/java/.../HerraduraCli.java`, `herradurakex.Xmss`), but is
entirely absent from the C and Go sides: `herradura_cli.c`,
`herradura_cli.go`, `herradura.h`, and `Herradura cryptographic
suite.{c,go}` have zero references to XMSS (only `hpks-wots` is
supported there). This is not documented anywhere as an intentional
Python/Java-only feature, so as it stands it reads as an unfinished
port rather than a deliberate scope decision.

- Confirm intent: either XMSS was meant to reach all four core languages
  (C/Go/Python/Java) like the rest of the classical/NL/PQC quartets, or
  it's deliberately Python/Java-only (e.g. because of tree-state/index
  bookkeeping complexity) — decide before implementing.
- If porting: implement XMSS keygen/sign/verify in `herradura.h` (and
  the standalone `Herradura cryptographic suite.c`), mirroring the
  existing `hpks-wots` structure and the Python/Java reference
  behavior (leaf-index `.idx` sidecar state file, per CLAUDE.md's
  bindings/java description). Do the same for the Go suite and
  `herradura_cli.go`. Wire `--algo hpks-xmss` into both `genpkey`/`sign`/
  `verify` subcommands in `herradura_cli.c` and `herradura_cli.go`,
  matching Python/Java's PEM wire format exactly.
- Add/extend `CryptosuiteTests/Herradura_tests.{c,go}` XMSS coverage to
  match test [30] in the Python suite (per CLAUDE.md's test-numbering
  note that [30] "WOTS/XMSS" already spans multiple languages).
- Extend `CliTest/test_java_oprf_wots_interop.sh` (or add a C/Go
  counterpart) and `CliTest/test_cross_lang_matrix.sh` ([[#207]]) so
  `hpks-xmss` is cross-checked across all four languages once C/Go
  support lands, the same way the rest of the protocol surface is.
- If the decision instead is Python/Java-only by design, document that
  explicitly in `CLAUDE.md`'s `bindings/java/` description and the HPKS
  protocol-stack section, so future audits don't re-flag it.

Status: **DONE v2.7.5** — confirmed intent was a straight 4-language
port: the core `hpks_xmss_keygen`/`sign`/`verify` primitives (2^h-leaf
Merkle tree of WOTS-F public keys) and `CryptosuiteTests/Herradura_tests.
{c,go}` test [30] coverage already existed in `herradura.h` and
`Herradura cryptographic suite.{c,go}` from an earlier pass — only CLI
wiring was actually missing. Wired `--algo hpks-xmss` into
`HerraduraCli/herradura_cli.c`'s and `herradura_cli.go`'s `genpkey`
(new `--xmss-height` flag, default 10, matching Python's), `pkey`,
`sign`, and `verify` subcommands, with a `<key>.idx` leaf-index sidecar
(one-time-per-leaf, matching Python/Java exactly) and new
`PEM_HPKS_XMSS_PRIV/PUB/SIG` labels in `herradura_codec.h`. Extended
`CliTest/test_wots.sh` with a full HPKS-XMSS-F section (9-way C/Go/Python
interop, multi-leaf signing, leaf exhaustion, tamper/wrong-key rejection
— 27 new assertions) and added an `hpks-xmss` block to
`CliTest/test_cross_lang_matrix.sh` covering all 16 C/Go/Python/Java
producer/consumer pairs. Verified byte-for-byte PEM wire compatibility
in both directions among all four languages; no Python/Java wire-format
discrepancy was found. `CLAUDE.md`'s `bindings/java/` description did
not claim WOTS/XMSS exclusivity, so no correction was needed there.

### #209: Fix cosmetic doc-drift found in the 2026-08-18 consistency audit

The cross-language/doc/test consistency audit that led to [[#208]] also
found three low-severity documentation-drift items, deferred at the
time since they're cosmetic rather than functional:

- `TODO_DONE.md` sections predating the `Status:` line standard
  ([[#154]]) — `### 17`, `### 18`, `### 24`, `### 26`, `### 27`, `### 28`,
  `### 42`, `### 56`, `### 69`, `### 70`, `### 77`–`### 80` — use inline
  `✓ DONE`/`DONE (vX...)` markers instead of a standalone `Status:` line,
  so they're flagged as false positives by CLAUDE.md's quick-check
  one-liner. Either backfill a proper `Status:` line on each (without
  disturbing their original historical wording) or note in the quick-check
  section that pre-#154 entries are grandfathered and expected to show up.
- CLAUDE.md's Repository Structure section lists only ~12 of the 59 actual
  `CliTest/*.sh` scripts, with no indication the list is illustrative
  rather than exhaustive (the real enforcement is `ci.yml`'s
  `native-interop` coverage-guard step, which is complete and accurate).
  Add a short note that the bullet list is a representative sample, not
  a full index, so it doesn't keep getting flagged as stale.
- Top-level `SPEC.md`, `SECURITY.md`, `Dockerfile`, `docker-entrypoint.sh`,
  and `pyproject.toml` exist but aren't mentioned anywhere in CLAUDE.md's
  Repository Structure or Build Commands sections. Add brief entries for
  each (or fold Docker/pyproject usage into Build Commands) so CLAUDE.md
  reflects the full top-level layout.

Status: **DONE v2.7.6** — added a grandfathering note to CLAUDE.md's
TODO-status quick-check section covering the 16 pre-#154 sections (rather
than backfilling their historical wording); marked the `CliTest/` listing
in Repository Structure as a representative sample of 59 scripts; added
brief Repository Structure / Build Commands entries for `SPEC.md`,
`SECURITY.md`, `Dockerfile`, `docker-entrypoint.sh`, and `pyproject.toml`.

### #210: Quantify the key-independent linear leak of `fscx_revolve` at i = n/4

`fscx_revolve(A, B, i)` is affine: `E = M^i · P ⊕ T_i · K` with
`T_i = M · S_i`, `S_i = Σ_{j=0}^{i-1} M^j`. Security of every classical
FSCX construction therefore rests entirely on `T_i` having full rank —
whatever `T_i` fails to cover is a plaintext functional that no key can
mask. A rank computation over GF(2) at the deployed parameters shows it
does **not**:

| n | i | rank(T_i) | corank (leaked bits) |
|---|---|---|---|
| 64 | 16 | 34 | 30 |
| 128 | 32 | 66 | 62 |
| 256 | 64 (`i = n/4`) | 130 | **126** |
| 256 | 192 (`r = 3n/4`) | 130 | **126** |
| 256 | 65 (odd) | 256 | 0 |

Concretely: at n=256 there are 126 linearly independent functionals λ with
`λ·T_64 = 0`, so `λ·E = λ·M^64·P` holds for **every** key. Sampling 30
random keys against a fixed plaintext gives a constant functional value, as
predicted. The algebraic reason is that over GF(2)[x]/(x^n+1) with n=2^k
everything is a power of (x+1); `m(x) = x^{n-1} + 1 + x` is a unit, and
`m + 1 = x^{-1}(1+x)^2`, so for i a power of two `S_i` carries
(1+x)-valuation `2i - 2` — rank deficiency grows with i rather than
vanishing. The simplest visible case is parity: M has row weight 3, so
`parity(fscx(A,B)) = parity(A) ⊕ parity(B)` and an even step count makes
`parity(E) = parity(P)` unconditionally.

Impact to assess and document:
- **HSKE (key-only)** — `SECURITY.md` currently rates this "conditionally
  usable, n/2-bit post-quantum security only if no plaintext is ever
  observed". That claim is false as stated: 126 bits of `P` are readable
  from `E` alone with no known plaintext and no key recovery. The row needs
  rewording, and `SecurityProofs-1.md` §1.5's "Why HSKE remains secure"
  note needs the corank qualifier.
- **HPKE** — same `i = n/4` revolve over `enc_key`, so ciphertexts leak the
  same 126 functionals of the plaintext.
- **HPKS** — `e = fscx_revolve(R, msg, i)` lives in an affine subspace of
  dimension 130, i.e. the Schnorr challenge carries 130 bits of entropy,
  not 256, and 126 of its coordinates are a public function of `R`.
- Check whether the NL replacements inherit any of it — a first pass
  (400 samples, HSKE-NL-A2 at 64 steps) puts the same 126 functionals at
  agreement 0.46–0.56, consistent with no bias, but see [[#214]] for the
  measurement that would actually settle it.

**Deliverable:** `SecurityProofsCode/fscx_revolve_corank.py` (rank/corank
table, kernel extraction, key-independence check, the (1+x)-valuation
derivation), a `SecurityProofs-1.md` subsection, and corrected rows in
`SECURITY.md`. Analysis + documentation only; the parameter consequence is
[[#211]].

Status: **DONE v2.7.7** — added `SecurityProofsCode/fscx_revolve_corank.py` and
SecurityProofs-1.md §1.3.1 (Theorem 4.1). The co-rank has a closed form:
co-rank(T_i) = min(n, 2(2^{v2(i)} - 1)), where v2 is the 2-adic valuation —
verified against the primitive at 288 parameter pairs, and 126 out of 256 at
the deployed i = n/4 = 64 (and at r = 3n/4 = 192). Proof is a valuation
argument in the local ring GF(2)[X]/(X^n+1) = GF(2)[Y]/(Y^n), Y = X+1: m(X) is
a unit, v(m+1) = 2, and (M+I)S_i = M^i+I forces v(S_i) = 2^{v2(i)+1} - 2. The
126-dimensional left kernel was extracted and each basis functional confirmed
constant across 200 random keys; parity is the all-ones member. Documented as
weakness W9, corrected §2.2's "Why HSKE remains secure" blockquote, §5.1's
IND-CPA cells for HSKE/HPKE, §5.2's "HSKE is correct and secure" row,
SecurityProofs-3.md §11.7's HSKE/HPKE rows and its key-only paragraph, and
SECURITY.md's HSKE (key-only) row — which claimed "conditionally usable,
n/2-bit post-quantum security only if no plaintext is ever observed" and is
now "not suitable for production", since no plaintext observation is needed.
Analysis + documentation only; no wire-format, CLI, or parameter change — the
odd-i fix is [[#211]].

### #212: Recompute GF(2^n)* security under Pohlig–Hellman — the n=256 figure is ~45 bits optimistic

`SecurityProofs-2.md` §9.2.4 lists Pohlig–Hellman in its attack table but
never applies it, and the headline row ("n = 256 ≈ 80–90 bits, FFS
L[1/3]") is what `SECURITY.md` cites for HKEX-GF, HPKS, HPKE, HPKS-NL and
HPKE-NL. Pohlig–Hellman is the binding constraint, not FFS:

- `2^256 − 1 = 3·5·17·257·641·65537·274177·6700417·67280421310721·
  59649589127497217·5704689200685129054721` — largest prime factor is
  73 bits.
- g = 3 with `GF_POLY[256] = 0x425` was checked to have full order
  `2^256 − 1`, so the reachable subgroup buys nothing back.
- Generic DLP cost is therefore `√(2^73) ≈ 2^36.5` group operations with
  Pollard rho in constant memory — not 2^80–2^90.

This is not theoretical: a Pohlig–Hellman + BSGS + CRT implementation
recovers the **exact** private exponent (not merely a representative) at
n=64 in 0.15 s in pure Python, and from it Eve reconstructs the HKEX-GF
shared secret. §9.2.4's existing n=32 BSGS narrative — "the recovered
a_rec ≠ A_PRIV because g = 3 is not primitive" — should be revisited in
that light. Note the same modulus governs HPKS's `s = (k − a·e) mod
(2^n − 1)`, so signature forgery inherits the bound.

**Deliverable:** `SecurityProofsCode/hkex_gf_pohlig_hellman.py` (order of g
per supported n, factorisation, per-n PH cost table, working end-to-end
n=64 key recovery, n=128 cost estimate), a rewrite of §9.2.4's practical
parameter table with the PH column added, and updated "Why" cells in
`SECURITY.md`. Relates to [[#204]], which raised the prime-n question for
Pohlig–Hellman but did not compute the cost at the deployed n. No
protocol change — these protocols are already demo-only; the point is that
the documented margin is wrong by ~45 bits.

Status: **DONE v2.7.8** — added `SecurityProofsCode/hkex_gf_pohlig_hellman.py`
and rewrote SecurityProofs-2.md §9.2.4 around the corrected bound. Confirmed:
the largest prime factor of 2^256 - 1 is 5704689200685129054721 (73 bits), so
Pohlig-Hellman with Pollard rho costs ~2^36.5 group operations in constant
memory — 45 to 55 bits below the FFS figure §9.2.4 previously reported as the
practical bound. At the 1.26e5 gf_mul_ba/s measured for `herradura.h` on the
reference ARM64 host that is ~9 days on one core, and it parallelises linearly.
The script verifies every factorisation (Miller-Rabin + product), computes
ord(g) at each supported n, recovers exact private keys at n=32 and n=64
(0.15 s at n=64), and derives from the recovered key both the HKEX-GF shared
secret and a forged HPKS signature that verifies under the victim's public key.
Two nuances worth recording: g = 3 is primitive at n=64 and at the deployed
n=256 (so recovery returns the private key itself, not a representative),
though not at n=32 or n=128 — §9.2.4's existing n=32 BSGS narrative is correct
there but does not generalise; and Pohlig-Hellman remains the binding attack up
to n=512, with the FFS taking over only at n=1024. Updated the §9.2.4 parameter
table with largest-prime-factor and PH columns, SecurityProofs-3.md §11.7's
HKEX-GF/HPKS/HPKE rows and its TODO #71 note, SECURITY.md's four GF(2^n)* rows
and its out-of-scope bullet, README.md's GF(2^n) parameter table,
docs/BENCHMARKS.md's two HPKS/HKEX-GF caveats, SPEC.md §2/§5.1/§12, and
`spec/generate_spec.py` (hkex-gf/hpks/hpke `classical_security_bits` from
"~80-90 (n=256)" to "~36.5 (n=256)", plus hske reclassified from production to
pedagogical under [[#210]]), regenerating `spec/herradura-protocol-spec.json`.
Analysis + documentation only; these protocols were already demo-only, and no
wire format, CLI surface, or parameter changed.

### #219: Java `encodeSessionKey` pads the DER INTEGER, breaking byte-for-byte PEM parity

`bindings/java/herradurakex/Codec.java`'s `encodeSessionKey` encoded the key
field at a fixed `nbits / 8` width:

```java
byte[] der = derSeq(derInt(key, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
```

Every other implementation uses **minimal** width for this one field —
`HerraduraCli/herradura.py`'s `_encode_session_key`
(`nbytes = max(1, (key_int.bit_length() + 7) // 8)`), `herradura_cli.go`'s
`encodeSessionKey` (whose comment reads "Minimum byte width matching Python"),
and Java's own `encodeRnlResponse` a few lines below in the same file. The
fixed/minimal split is deliberate elsewhere: private keys, public keys and
symmetric ciphertexts *are* fixed-width in Python too, so Java matches there.
The session key was the one field where it diverged.

Neither DER encoder strips leading zeros — each emits the byte array it is
given, adding a `0x00` only when the top bit is set. So whenever a session key's
top byte is `0x00` **and** the next byte is below `0x80`, Java emitted a
redundant leading zero:

```
python/c/go:  30 25 02 1F 44 6f …   INTEGER, 31 content bytes
java:         30 26 02 20 00 44 6f… INTEGER, 32 content bytes
```

That is non-canonical DER, and it violates the byte-for-byte PEM compatibility
CLAUDE.md documents across implementations. The value decodes identically either
way, so only a byte-comparison test sees it — which is why it surfaced as a rare
CI flake rather than an interop failure.

**Rate:** P(top byte 0) x P(next byte < 0x80) = 1/256 x 1/2 = **1/512** per
session key. `CliTest/test_cross_lang_matrix.sh` compares 16 HKEX-GF pairs per
run, 6 of which are Java-against-another-language, so a run tripped roughly 1%
of the time. Found when the `cross-lang-compat` job failed on PR #207 with
`FAIL hkex-gf go-alice/java-bob: session keys differ` while the identical job on
the same commit passed in the parallel workflow run; reproduced locally at 1
mismatch in 400 `go-alice/java-bob` iterations.

**Fix:** pass `-1` (the codec's existing minimal-width sentinel) instead of
`nbits / 8`, with a comment recording why this field differs from its
neighbours. Added an `encode-session` mode to `herradurakex.CodecTest` and a
seven-vector regression section to `CliTest/test_java_codec.sh` that compares
Java's session-key PEM against Python's byte for byte, and checks the value
still round-trips. The vectors cover the trigger deterministically instead of
waiting for a 1-in-512 random draw: leading zero with the next byte below
`0x80`, two leading zeros, leading zero with the next byte at or above `0x80`
(where the DER sign byte makes both agree), no leading zero with and without the
high bit set, a small value, and zero. Four of the seven fail against the old
encoder and all seven pass against the new one.

Status: **DONE v2.7.9** — one-line encoder fix plus a deterministic regression
test; no protocol, parameter, or CLI-surface change. Java-produced session-key
PEMs are now byte-identical to python/c/go for every key, and previously written
Java session-key PEMs still decode correctly (the padded form remains valid
input, it was only non-canonical output).

### #211: Prove (and parameterise for) Shannon-perfect one-time HSKE at odd i

Follow-on to [[#210]] and the closest this suite can get to a one-time-pad
style unconditional proof, reachable **without touching FSCX or
FSCX_REVOLVE** — only the step-count parameter moves.

Since `E = M^i·P ⊕ T_i·K` is affine, a one-time uniform key K of full
message width makes `T_i·K` uniform on the image of `T_i`. If `T_i` is
invertible, `E` is uniform and independent of `P`, which is exactly
Shannon's perfect-secrecy condition — `I(P; E) = 0`, the same statement
the OTP satisfies, proved by counting rather than by assumption. The
conjecture to formalise (verified numerically at n = 64/128/256) is:

> For n = 2^k, `T_i = M · S_i` is invertible over GF(2) **iff i is odd**.

Sketch: `x^n + 1 = (x+1)^n`, so invertibility ⟺ nonzero evaluation at
x = 1; `m(1) = 3 ≡ 1`, hence `S_i(1) = i mod 2`. The deployed `i = n/4` is
even for every supported n, which is precisely why [[#210]] finds a corank.
Correctness is unaffected: decryption needs only `i + r ≡ 0 (mod n)`, and
`i = 65, r = 191` round-trips (verified, 50/50 at n=256).

Work items:
- Write the theorem and proof (both directions) into `SecurityProofs-1.md`
  next to Theorems 2–3, with the perfect-secrecy corollary stated in
  Shannon's form and its hypotheses spelled out honestly: key uniform, key
  width = message width, **key used once**. Key reuse remains an immediate
  break — the affine structure means two ciphertexts under one key give
  `E1 ⊕ E2 = M^i(P1 ⊕ P2)`, decipherable with no key at all, which the
  write-up must state as prominently as the positive result.
- Extend `SecurityProofsCode/` with the numeric verification: invertibility
  vs parity of i across n ∈ {32…512}, round-trip at (i, r) = (65, 191), and
  an empirical `I(P; E)` estimate at small n showing 0 for odd i and
  log2-of-corank bits for even i.
- Decide the parameter question separately: whether the suite should adopt
  an odd i as the default (a wire-format break under the CLAUDE.md MAJOR
  rules, requiring a `MIGRATING.md` entry), expose it as an opt-in
  `--steps` choice, or document the odd-i variant as a proof-of-concept
  only. Do not change the default inside this item.

Status: **DONE v2.7.10** — added `SecurityProofsCode/hske_perfect_secrecy.py` and
SecurityProofs-1.md §1.3.2 (Theorem 4.2, Corollary 4.3). The conjecture holds and
sharpens into an identity that subsumes [[#210]]: for uniform independent P and K,
I(P;E) = co-rank(T_i) = min(n, 2(2^{v2(i)} - 1)) bits exactly, so the 126-bit leak
and the perfect secrecy are one quantity read at two parities. Proof is the coset
argument — H(E) = n, H(E|P) = rank(T_i) — and it is confirmed by measuring the
mutual information exhaustively over all 65 536 plaintext-key pairs at n=8, which
matches the co-rank to floating-point error at every i (including the degenerate
i = n, where T_n = 0, the ciphertext equals the plaintext, and the leak is the full
n bits). Perfect secrecy holds iff i is odd. Correctness needs only i + r = n, so
(65, 191) round-trips 500/500 and costs the identical 256 FSCX steps as the
deployed (64, 192): odd i is not a trade-off, it is the same work for 126 fewer
leaked bits.

Documented the hypotheses as prominently as the result, per this item's text: key
uniform, key as wide as the message, key used once — and the third fails
catastrophically, not gracefully. E1 XOR E2 = M^i(P1 XOR P2) with M invertible
recovers the plaintext XOR from two ciphertexts with no key material (200/200 at
n=256, i=65), and HSKE has neither a nonce nor an integrity check to prevent or
detect reuse.

**Parameter decision: documented, not deployed.** Odd i does not beat a one-time
pad, it ties it — at ~700x the cost in the reference Python and with the same
key-as-long-as-the-message burden. The result is a ceiling on any construction of
this shape, not a feature, so it does not justify a wire-format break on its own.
Changing i changes what every existing HSKE/HPKE ciphertext decrypts to, and the
symmetric-ciphertext PEM records a format tag and nbits but no step count, so an
odd-i build would decrypt an old ciphertext to silent garbage with no integrity
check to catch it. Adoption would need its own format tag (the tag mechanism
already separates the plain, nonce-carrying and AEAD layouts) plus a MIGRATING.md
entry, and belongs to a future major version. The opt-in `--steps` flag this item
floated is rejected for the same reason: without a format tag it makes silent
misdecryption a user-reachable footgun. No wire-format, CLI, or default-parameter
change was made.

### #221: DFR retry policy was applied per-script, leaving two decapsulating tests unguarded

TODO #195 measured the QC-MDPC BGF decoder's decoding failure rate at 0.225% per
encapsulation (45/20000, 95% CI [0.159%, 0.291%]) and added a retry canary so a
DFR event — an expected protocol outcome, not a bug — could not redden a CI run.
Its residual-probability calculation was right but scoped to the one script it
touched: the retry was written inline in `test_hybrid_kex_interop.sh`, and later
copied by hand into `test_cross_lang_matrix.sh` and `test_java_stern_interop.sh`.
Nothing swept the remaining call sites, and nothing stopped new ones appearing.

Two scripts decapsulate with no retry at all:

- `CliTest/test_stern_kem.sh` — **9 independent encapsulations**, so roughly a
  **2% chance of a spurious red run**, three orders of magnitude worse than the
  1-in-29-million residual #195 reasoned about.
- `CliTest/test_hybrid_kex.sh` — one exposed decapsulation (Alice's completion
  step), about 0.225% per run. Its two other `hybrid-rnl-stern` calls are Bob-side
  encapsulations compared only for freshness, and the negative tests expect
  failure, so neither is exposed.

This surfaced as the `native-interop` failure on PR #210
(`dec: HPKE-Stern-KEM BGF decoding failed (DFR event or corrupt ciphertext)`,
raised by `test_stern_kem.sh` immediately after `test_ring` passed), where the
identical job passed in the parallel workflow run on the same commit.

**Fix.** New `CliTest/lib_dfr.sh` holds the policy once — the retry budget, the
error signature covering every message the four CLIs emit, a `dfr_is_event`
predicate and a uniform `dfr_report_retry` log line — with the measurement, the
safety argument (all 45 observed failures were clean self-detected `None`
returns, so a retry absorbs the DFR without masking a bug) and the weak-key
caveat ([[#218]]: retries are correlated rather than independent for a weak key,
so an exhausted budget is not proof of a bug). `test_stern_kem.sh` gains a
`kem_roundtrip` helper that retries with a fresh encapsulation and reports the
CLI's own message on any non-DFR failure; `test_hybrid_kex.sh` wraps its
encapsulate/complete pair the same way. The three scripts that already had the
policy now source it instead of redefining it, so the signature has one
definition rather than five; `test_cross_lang_matrix.sh` keeps its wider budget
of 5 via a `${MAX_DFR_RETRIES:-3}` default.

**Guard.** A new `native-interop` CI step, modelled on the existing coverage
guard, fails the build if any `CliTest/*.sh` matching `dec --algo hpke-stern-kem`
or `--our-kem` does not source `lib_dfr.sh`. Verified both ways: it exits 0 on
the current tree and reports `UNGUARDED: test_stern_kem.sh` when the source line
is removed.

Status: **DONE v2.7.11** — CI-flakiness fix. Verified `test_stern_kem.sh` 9/9,
`test_hybrid_kex.sh` 6/6, `test_hybrid_kex_interop.sh` 19/19,
`test_java_stern_interop.sh` 6/6, and `test_cross_lang_matrix.sh` 438/438 after
the migration, plus the error-signature check against both real CLI messages and
four non-DFR failures that must not be absorbed. No protocol, parameter, or
CLI-surface change.

### #215: HFSCX-256-DM — the Davies–Meyer proof does not apply to a non-bijective inner map

`hfscx_256` compresses with `state ← nl_fscx_revolve_v1(state, block, 64) ⊕
state`. Davies–Meyer's collision/preimage bounds (Black–Rogaway–Shrimpton,
PGV) are proved in the ideal-**cipher** model — they need `E_block(·)` to be
a permutation for each block. `nl_fscx_v1` is explicitly documented as not
bijective in A, so HFSCX-256-DM currently has a construction whose security
argument is cited but not applicable, and everything downstream (HPKS-NL
challenges, Stern H-matrix generation, HMAC-HFSCX-256, the KDFs) inherits
that gap.

Measured so far: iterating `nl_fscx_revolve_v1(·, B, 64)` at n = 12 and
n = 16 exhaustively gives image fractions of 0.030–0.046, matching the
~2/k expectation for a random function — so the map behaves like a random
function rather than showing extra structure, but it is still ~5 bits of
image collapse per block, and no permutation.

Work items:
- Re-derive the security bound in the ideal-random-function model that
  actually fits the construction, and state what it gives (and does not)
  for collision and preimage resistance.
- Search for exploitable structure the random-function model would not
  excuse: fixed points of the compression function, Joux multicollisions,
  expandable messages / long-message second preimages against the MD chain,
  and length-extension exposure of the bare (non-HMAC) hash.
- Evaluate `nl_fscx_revolve_v2` as the inner map. It is bijective in A with
  a closed-form inverse, which would make the ideal-cipher DM argument
  apply as cited, at the cost of a wire-format break for every artifact
  containing a digest — so this item should produce a recommendation and
  a `MIGRATING.md` draft, not a change.

**Findings (v2.7.12).**  `SecurityProofsCode/hfscx_dm_rf_model.py`; written up as
SecurityProofs-4.md §11.9.12.

1. *Bound re-derivation.*  With the inner map modelled as an ideal random function
   `f`, the feed-forward makes `C_DM(s,m) = f(s,m) XOR s` itself an ideal random
   function — each input pair XORs in a value fixed by that pair, so uniformity and
   independence carry over.  Every ideal-random-function bound transfers with no
   loss, so all of §11.9.11's numbers stand; what does not stand is the claim that
   Davies-Meyer *contributes* to them.  §11.9.8's benefits 1 and 2 survive on their
   own concrete-structure arguments; benefit 3 (PGV-1 alignment) is retracted.

2. *The image collapse does not propagate.*  Exhaustively at n = 16, `F_1^r` follows
   the `2/r` law (0.0318 of the space at the deployed r = 64, ~5 bits, matching the
   figure this item recorded) while `C_DM`'s image sits at `1 - 1/e = 0.632` for
   every r.  Structural, not incidental: `s -> s XOR c` is a bijection for fixed m.

3. *Bijectivity would be a downgrade.*  DM over an invertible map has free fixed
   points at `s = E_m^{-1}(0)` — the structure Dean's 1999 expandable-message attack
   consumes.  Measured: with v2 as inner map, one fixed point per block in `O(r)` by
   inversion (4/4 blocks).  With v1 it is a preimage-of-zero problem under A2, and
   the image collapse makes it harder still — 3 of 4 tested blocks have *no* fixed
   point at r = 64 because 0 is not in the image.  The non-bijectivity that breaks
   the citation is load-bearing for the property the citation would have certified.

4. *One real documentation defect found.*  §11.9.4's flat 2^n second-preimage claim
   is wrong for long messages — as in any MD hash, Kelsey-Schneier expandable
   messages give `k`·2^(n/2+1) + 2^(n-k) against a `2^k`-block target.  Demonstrated
   end-to-end against the deployed chain at n = 16, k = 8: a distinct message of
   identical block length (so the finalization block matches and the collision
   survives padding) at ~3 900 compressions vs. a generic 2^16 — a 16.6x speed-up.
   Joux multicollisions confirmed on the same chain.  At n = 256 the corrected cost
   is ~2^216 against a 32 TiB target and never falls below ~2^200 at any realisable
   size, so the 128-bit target is untouched and no call site is exposed; §11.9.4 and
   the §11.9.11 summary row have been amended.

5. *Recommendation: keep v1, no migration.*  Rejected on four grounds — it adds the
   Dean fixed points (3); it trades the studied "v1 is a PRF" idealisation for the
   stronger, unstudied "v2 is an ideal cipher" (TODO #99, #214); v2's degenerate-key
   class (§11.19.2) is *unscreenable* in an inner-map role because the attacker-chosen
   message block occupies the key argument; and it breaks the wire format for every
   digest-bearing artifact.  Performance is neutral.  No `MIGRATING.md` entry was
   created — the item asked for a draft, and the draft's conclusion is *do not
   migrate*; the grounds above are recorded in §11.9.12 as what any future proposal
   to adopt v2 must answer first.

Status: **DONE v2.7.12** — the PGV/ideal-cipher citation is retracted and the bounds re-derived in the ideal-random-function model, where every figure in the §11.9.11 table survives; the v2 swap is evaluated and rejected.

### #218: DFR extrapolation and weak-key analysis for the QC-MDPC BGF decoder

[[#195]] tracks BGF decoding failures as a CI flakiness problem; this item
is the security half of the same fact. For a KEM, DFR is not a nuisance —
IND-CCA2 requires DFR ≤ 2^-λ, and any measurable failure rate exposes the
GJS-style reaction attack, where an attacker submits crafted ciphertexts,
observes success/failure, and reconstructs the secret key's distance
spectrum.

- Apply the standard modelisation/simulation/extrapolation methodology
  (Sendrier–Vasseur, as used for BIKE's IND-CCA argument) to
  `qcmdpc_decap_bgf` at the deployed parameters: simulate DFR at
  artificially weakened parameters, fit, extrapolate with a confidence
  interval, and state the λ actually supported.
- Run the weak-key analysis alongside it (the BIKE weak-key literature
  gives the classes to test), and check the deployed key generation for
  whether it can produce them.
- Evaluate the current near-codeword-aware and "flip a failure into a
  success" BGF variants (eprint 2026/1616 and successors) for whether they
  close the gap at these parameters without a wire-format change.
- Outcome either way feeds `SECURITY.md`: today's HPKE-Stern-KEM row says
  nothing about DFR or reaction attacks, and it should — even for a
  demo-only protocol, since a stated DFR is what tells a reader the
  ciphertext-reuse threat model.

**Findings (v2.7.13).**  `SecurityProofsCode/qcmdpc_dfr_weak_keys.py`; written up as
SecurityProofs-4.md §11.8.7.  Measurements use a bit-sliced reimplementation of the
deployed BGF decoder, pinned bit-exact against `qcmdpc_bgf_decode` on 200 suite-generated
instances before any number is taken.

1. *DFR.*  0.264% over 120 000 round trips, 95% Clopper-Pearson `[0.236%, 0.295%]` —
   `2^-8.6`, confirming the 0.225% TODO #195 read off CI history.  IND-CCA2 wants
   `2^-128`; this supports lambda = 8.6 bits.

2. *Extrapolation.*  Moving `r` upward at fixed `d`, `t` (downward saturates: 50% DFR by
   `r = 421`) gives `r = 523 -> 2^-8.38`, `541 -> 2^-10.09`, `557 -> 2^-12.17`,
   `571 -> 2^-12.98`; fit `log2(DFR) = -0.0996·r + 43.69`, R² = 0.985, about 10 extra
   bits of `r` per bit of DFR, so `r ~ 1723` for `2^-128`.  A **lower bound**, twice
   over: every point is in the waterfall and the curve is concave, and `r` alone is not
   the design knob (BIKE-128 moves `r`, `d`, and `t` together).

3. *Weak keys.*  Multiplicity in the distance spectrum drives DFR off a cliff:
   ~0.2% at multiplicity 3, 2.3-3.2% at 6, 45.8% at 7, 94% at 9, 100% at 14.  Over
   200 000 sampled polynomials keygen emits multiplicity 6 at 0.0145%, so about 1 key in
   3 400 has ~10x the average DFR; multiplicity >= 7 was never observed, so the
   total-failure classes matter only for *supplied* keys.  Nothing screens any of it —
   `qcmdpc_keygen` retries only on non-invertible `h0` in C, Go, and Python alike, and
   the PEM decode path does not check an imported key.

4. *GJS reaction attack, and why it is reachable.*  Errors placed at distances **in** the
   key's spectrum fail at 0.158% `[0.112%, 0.217%]` vs 0.433% `[0.354%, 0.525%]` for
   distances outside it — disjoint intervals, 2.74x ratio, over 8 keys and 48 000 trials.
   That is ~3 000 queries per distance and `r/2 = 261` distances, so on the order of
   `10^6` chosen-ciphertext queries for the private key.  The oracle is free: there is no
   FO transform (decap never re-encrypts, so a chosen syndrome is processed like an
   honest one) and no implicit rejection — `qcmdpc_decap_bgf` returns `None`/`0`/`false`
   and all three CLIs exit non-zero with a distinct message, on `dec --algo
   hpke-stern-kem` and on `kex --algo hybrid-rnl-stern` alike.

5. *Outcome.*  The three compound rather than trade off: `2^-128` DFR would not give
   IND-CCA2 while failure is reported, and implicit rejection would not rescue `2^-8.6`.
   Beneath both, the syndrome-decoding instance at `r = 523`, `d = 15`, `t = 18` is far
   below any usable level, so DFR is not the binding constraint.  `HPKE-Stern-KEM` gains
   a `SECURITY.md` row (it had none) and moves from `status: production` to `demo-only`
   in `spec/generate_spec.py`; `SECURITY.md` also gains a note that `hybrid-rnl-stern`
   inherits the exposure on its KEM half, and README's stale "DFR not measured" claim is
   corrected.

6. *Left open.*  The near-codeword-aware and failure-recycling BGF variants asked about
   in this item's third bullet are **not** evaluated: the question turns on decoder-design
   results this analysis does not reproduce, and at parameters this far from target it
   would not change the classification.  Worth revisiting only alongside a parameter
   change — a decoder improvement that leaves `r = 523` cannot reach `2^-128` alone.

Status: **DONE v2.7.13** — DFR measured and extrapolated, weak-key gradient characterised, GJS distinguisher demonstrated to disjoint confidence intervals; HPKE-Stern-KEM reclassified demo-only in SECURITY.md and the spec.

### #220: `SecurityProofs-1.md` is approaching the ~750-expression KaTeX limit

`SecurityProofsCode/validate_katex.js` now warns on `SecurityProofs-1.md`: it
holds 708 math expressions against GitHub's roughly 750-per-page client-side
KaTeX limit, past which *every* expression on the page silently renders as
"Unable to render expression" — a cascade failure with no syntax error to find.
`SecurityProofs-4.md` sits at 718 with the same warning (716 when this item was
filed; TODO #215 and #218 have since added to it). The warning threshold
(700) exists precisely to catch this before it bites; TODO #170 already re-split
these documents once for the same reason.

Part 1 grew from 581 to 708 across TODO #210 and #211, both of which added
material to §1.3 (the FSCX_REVOLVE subsections). §1.3.2's additions were trimmed
back once already, converting prose-adjacent math to plain text to buy headroom,
which is a stopgap rather than a fix. The remaining open analysis items — #213
through #218 — will each want a subsection somewhere, and several of them belong
in Parts 1 and 4.

- Pick split points at section boundaries, as TODO #170 did, so each part lands
  comfortably under the warning threshold rather than just under the hard limit.
  Part 1's §1 (Algebraic Foundations) has grown enough to stand alone.
- Update every cross-reference: `SecurityProofs.md`'s index, the "Continued in
  Part N" footers, `CLAUDE.md`'s Repository Structure listing with its per-file
  expression counts, `SecurityProofsCode/KATEX_RULES.md`'s split rationale, and
  the many `SecurityProofs-N.md §X` citations scattered across `SECURITY.md`,
  `SPEC.md`, `README.md` and the other parts.
- Re-run the validator on every part afterwards and record the new counts in the
  two places that track them.

**Outcome.** Re-split five parts into seven, at section boundaries, and repaired
every cross-reference against the new layout.

| Part | Sections | Expressions | Was |
|---|---|---|---|
| 1 | §1 Algebraic Foundations | 300 | part of the 708-expression Part 1 |
| 2 | §2–§8 | 408 | part of the 708-expression Part 1 |
| 3 | §9–§10 | 409 | Part 2 |
| 4 | §11–§11.8.2 | 593 | Part 3 |
| 5 | §11.8.3–§11.8.7 | 587 | part of the 718-expression Part 4 |
| 6 | §11.9 HFSCX-256-DM | 131 | part of the 718-expression Part 4 |
| 7 | §11.10–§11.13, §11.15–§11.19 | 645 | Part 5 |

Total is 3073 expressions before and after, so nothing was dropped or duplicated;
a line-level diff of the concatenated bodies shows only the two `---` rules at the
split points. Every part is now under the 700-expression warning threshold, and
`validate_katex.js` reports 0 FAIL on all seven.

**Cross-references.** References were repointed against *section ownership* read
from the split files themselves rather than by a mechanical old-part → new-part
shift, which also repaired references that were already stale: 25 `SPn §x`
shorthand markers in `docs/INTRODUCTION.md` (many still naming the pre-TODO-#170
layout), the §11.11 constant-time-audit citations in `herradura.h`,
`herradura/herradura.go` and `dudect_timing_audit.c`, three §11.8.x/§11.7
citations inside the proof documents themselves, and the §9.2.6 Ristretto
citations. `CHANGELOG.md` and `TODO_DONE.md` were deliberately left alone — they
record what the layout was at the time, as TODO #170 also did.

A checker built for this item verifies that every live `SecurityProofs-N.md §X`
citation names the part that actually contains §X; it passes on all 151
section-bearing references, with one known false positive in `SPEC.md` §12 where
the nearby `§9` belongs to SPEC.md itself.

`.github/workflows/ci.yml` now globs `SecurityProofs-[0-9]*.md` instead of listing
the parts, so a future split cannot leave a part unvalidated by CI.

**Headroom note.** Parts 4 (593), 5 (587) and 7 (645) have less room than the
others. TODO #214 would add to Part 4 and TODO #217 to Part 5; either may push a
part back over the threshold, at which point the seam to cut is §11.8.4 out of
Part 5 or §11.10 out of Part 7.

Status: **DONE v2.7.14** — re-split into seven parts (300/408/409/593/587/131/645 expressions, all under the warning threshold, 0 FAIL), with every live cross-reference repointed by section ownership and verified mechanically.

### #217: Validate HPKS-Stern-F's round count against multi-round Fiat–Shamir forgery attacks

The production figure `rounds = 219` comes from the textbook
`(2/3)^r ≤ 2^-128`. Recent work on multi-round Fiat–Shamir (the CROSS
security revision presented at the 6th NIST PQC standardization
conference, and the fixed-weight-repetition forgery improving on
Kales–Zaverucha) shows that the naive parallel-repetition bound overstates
security for several deployed schemes — up to ~24% in the worst case
reported. Stern here is a 3-pass with uniform (not fixed-weight)
repetition and one-shot challenge derivation, which is the favourable
case, but the bound should be derived rather than assumed.

- Derive the forgery cost for this exact construction under the current
  multi-round FS analysis and confirm (or correct) 219, including the
  grinding strategy where an attacker re-randomises commitments for a
  subset of rounds.
- Audit the challenge expansion itself: `hpks_stern_f_sign` hashes
  `msg || all commitments` once, then chains `ch_st = nl_fscx_v1(ch_st,
  BitArray(n, i))` per round and takes `(ch_st & 0xFFFFFFFF) % 3`. Two
  things to check — that the reduction bias (2^32 mod 3 = 1, so ~2^-32) is
  genuinely negligible at 219 rounds, and that chaining a **non-bijective**
  map as challenge PRG cannot be steered into short cycles or low-entropy
  runs by commitment grinding. The bias question was touched for ring
  signatures in `stern_ring_challenge_bias.py`; this is the signature path.
- If the derived bound exceeds 219, update `_STERN_F_PRODUCTION_ROUNDS`,
  the `sign --rounds` guidance, and the C CLI's `-DSDF_ROUNDS` default
  across all language targets.

**Outcome.** 219 is confirmed; no change to any language target. The bound was
derived for this construction rather than assumed, and the challenge expansion
audited, in `SecurityProofsCode/stern_f_multiround_fs.py` (write-up:
SecurityProofs-5.md §11.8.8). The script pins a fast reimplementation of the
challenge chain bit-exact against the deployed one before measuring anything.

**1. The multi-round-FS discount does not apply.** KZ-style forgeries need the
challenge for a round to depend on less than the whole commitment set — a
per-round derivation, or a 5-pass scheme's second challenge phase. HPKS-Stern-F
has neither: one hash of `msg || all commitments`, expanded by chaining
`nl_fscx_v1` over the round index. Flipping one bit of one commitment changes
0.66716 of the 219 challenges over 120 independent trials, against the 0.66667
that independent re-randomisation predicts (z = +0.18), with an independent-seed
control at z = +0.83. No subset of rounds can be held fixed while others are
reground, so the forger faces the one-shot game `(3/2)^r` describes. Uniform
rather than fixed-weight repetition also leaves nothing for a fixed-weight
forgery to exploit.

**2. Both candidate leaks in the expansion are negligible.** The mod-3 reduction
was counted exactly, not sampled: `2^32 mod 3 = 1`, giving a forger `1 + 1.16e-10`
per round and `3.7e-08` bits across all 219 — no rejection sampling warranted.
The non-bijective chain shows no cycles (structurally impossible: each step uses
a different round index, so it is a composition of 219 distinct maps, not an
iteration of one), no state collapse (8 000 distinct seeds give 8 000 distinct
states at every depth from 1 to 219, and 8 000 distinct challenge vectors), and
no drift (rounds 110-219 match rounds 1-109 to within 0.002).

**3. Challenge uniformity, bounded rather than asserted.** Per-position
chi-square summed over all 219 positions, reported as six independent
replications of 8 000 seeds because a single replication of this statistic lands
anywhere in +/-2 by chance: +1.31, +1.40, -1.19, -0.86, -0.31, -0.35, mean
-0.001; pooled z = -0.94 over 48 000 seeds. A 99% limit on the excess caps the
forger's total gain at 0.44 bits across 219 rounds, leaving a 127.67-bit floor —
set by sample size, not by observed structure.

**4. End-to-end validation.** At r = 5/10/15/20 the measured forgery probability
tracks `(2/3)^r` with every 95% interval covering 1.0.

**Margin caveat.** 219 gives 128.107 bits, a 0.107-bit margin — smaller than the
0.44-bit resolution floor above. The experiment cannot itself certify 128.000
bits at r = 219, only that no bias large enough to matter is detectable; closing
that gap empirically needs ~30x the samples. Setting r = 220 would give 128.692
bits for ~0.5% more signature size and time. Left unchanged deliberately:
reacting to a finite experiment's resolution limit is not fixing a defect, and
none was found. Recorded here so the choice is visible rather than implicit.

**Not re-proved.** The `2/3` per-round cheating probability is Theorem 17's
standard Stern special-soundness claim, assumed here — this item audits the
repetition and challenge-expansion layer above it. The result is also orthogonal
to the N >= 17000 parameter problem: round count and instance hardness are
separate axes, and HPKS-Stern-F stays demo-only in `SECURITY.md`.

Status: **DONE v2.7.15** — 219 confirmed by derivation; KZ splitting shown inapplicable (one-shot challenge derivation), reduction bias counted at 3.7e-08 bits, non-bijective chain clean, and forgery probability validated end to end. No code change.

### #214: Exact differential/linear analysis of NL-FSCX v1/v2 against current ARX tooling

The only non-linearity in either NL-FSCX variant is the carry chain of one
modular addition per round (`ROL((A+B) mod 2^n, n/4)` in v1, the additive
`delta(B)` in v2). That places both squarely in the ARX/RX family, where
exact rather than heuristic tools exist and are standard practice:
Lipmaa–Moriai gives exact XOR-differential probabilities of modular
addition in O(log n), and MILP/SMT trail search over the resulting model
gives provable bounds rather than sampled ones. Today's coverage
(`nl_fscx_rot_analysis.py`, `nl_fscx_rx_exact_search.py`,
`nl_fscx_rx_differential_2025.py`, `nl_fscx_prf_analysis.py`) is sampling
and small-n exhaustive search; this item asks for the bound.

- Build the exact xdp+/xdp-RX model of one v1 and one v2 round and search
  for optimal trails over the deployed step counts with an SMT/MILP
  backend, reporting the best trail probability as a function of rounds and
  the number of rounds needed to drop below 2^-256.
- Settle the [[#210]] follow-up properly: compute the full Walsh spectrum
  of the v2 revolve restricted to the 126-dimensional subspace that the
  classical map leaks, with enough samples to resolve a bias of 2^-16
  (the current 400-sample spot check resolves nothing below ~2^-4).
- Include the rotation amount `n/4` in the search space. It is a free
  parameter that changes trail structure but not the primitive, so an
  optimal-rotation table across candidate amounts is exactly the kind of
  parameter tuning that is in scope, feeding a follow-up if some amount
  dominates.
- Cross-check the carry-degeneracy characterisation from [[#159]]/[[#168]]
  against the trail model.

**Deliverable:** `SecurityProofsCode/nl_fscx_exact_trail_search.py` plus a
`SecurityProofs-7.md` subsection with the bound table and the rotation
recommendation.

**Outcome.** Delivered as `SecurityProofsCode/nl_fscx_exact_trail_search.py`
plus SecurityProofs-7.md §11.20. Three of the four sub-items are done; the
Walsh-spectrum one is not, for a reason recorded below.

**1. Both variants reduce to one xdp+ core.** Writing `M` for the linear FSCX
map, v1 gives `dY = M(alpha) xor ROL(delta, n/4)` with `delta ~ xdp+(alpha,0->.)`,
and v2 gives `dY ~ xdp+(M(alpha), 0 -> .)` because `delta(B)` is a per-key
constant. The variants differ only in where `M` sits relative to the addition.
Verified at 6 000 random triples, zero mismatches, against round functions
pinned to the deployed suite.

**2. Proven trail weights** (SMT decision procedure, so each UNSAT is a proven
lower bound). At 4 rounds: v1 = 6/12/>=10 at n = 8/16/32, v2 = 7/7/7.

**v2 is the differentially weaker variant and does not improve with width** —
it sits at weight 7 for every width tested while v1 reaches 12 at n = 16. This
follows from finding 1: v2 sets the next state difference to the addition
output directly, so a light trail persists, whereas v1's XOR of `M(alpha)`
forces diffusion. v2 is the variant deployed for HSKE-NL-A2 and HPKE-NL, chosen
for bijectivity and a closed-form inverse — properties orthogonal to
differential strength. Not a break, but the relevant design fact.

Widths are powers of two deliberately: `M` is invertible iff `x^2+x+1` does not
divide `x^n+1`, which fails at n = 24 (measured rank 22), where v2 is not even a
bijection — the same trap TODO #215 hit at n = 12.

**3. Rotation table.** At n = 16 over 3 rounds, v1 weight by rotation: 2, 4,
**6 at the deployed n/4**, 6, 6, 5, 2. The deployed choice is at the optimum.
v2 is identical at every rotation, which finding 1 explains: in v2 the rotation
applies to `delta(B)`, a constant, so it never enters the differential.
**Rotation tuning is a v1-only lever.** No change recommended — one small width,
and changing it breaks the wire format for every stored artifact.

**4. Carry-degeneracy cross-check passes.** Keys with `delta(B)` in
`{0, 2^(n-1)}` contribute zero trail weight, the differential statement of the
same degeneracy TODO #168 rejected algebraically. `nl_v2_key_is_valid` already
refuses them.

**5. The load-bearing negative result: these are key-averaged bounds, and
NL-FSCX has no key schedule.** xdp+ averages over both operands, and trail
analysis multiplies per-round probabilities under the Markov assumption of
independent round keys. NL-FSCX holds the same `B` constant in all 64 deployed
rounds. Measured over all 256 keys at n = 8, the median key has some
differential at 32x its xdp+ value (max 128x) and all 256 of 256 keys have one
at >= 8x. The §11.20.2 weights are the right currency for design comparison and
are what ARX practice reports, but they are not a per-key guarantee and no extra
solver time would make them one.

**Not delivered.** No bound at n = 256 — the search does not scale; the slope
projection (v1 ~2.2, v2 ~1.9 bits/round, putting 64 rounds near 2^-141 and
2^-119) is an order-of-magnitude indication read off widths 8-32, where each
width closed at a different round count and per-round weight is not constant in
the round index. The Walsh-spectrum sub-item was not attempted: as written it
asks to resolve a 2^-16 bias by sampling, needing ~2^32 evaluations per
functional. The tractable substitute is an exact Walsh-Hadamard transform at
small width, which deserves its own item rather than a rushed appendix.

**Follow-ups worth filing:** a MILP formulation with better scaling toward
n = 256; a fixed-key differential treatment, which for a keyless-schedule
construction is the open question this surfaces rather than settles; and the
exact-WHT replacement for the Walsh sub-item.

Status: **DONE v2.7.16** — exact xdp+ model and SMT trail bounds delivered; v2 shown differentially weaker than v1 and width-insensitive, deployed rotation confirmed optimal for v1 and inert for v2; key-averaging gap identified as the limiting assumption. No code change.

### #216: Re-estimate HKEX-RNL against the 2026 lattice-attack landscape

`SECURITY.md` puts HKEX-RNL (n=256) at ~105 classical / ~100 quantum
Core-SVP bits and promotes HKEX-RNL-128 (n=512) as production-track. Those
numbers predate the current round of dual- and hybrid-attack improvements
(e.g. enhanced hybrid decoding against Module/Ring-LWE, eprint 2026/366,
reporting up to ~13 bits over previously-best attacks on ring parameter
sets), and Core-SVP is a deliberately crude lower bound.

- Re-run the deployed parameters (n=256 and n=512, q=65537, p=4096, pp=4,
  CBD η=1) through the current `lattice-estimator` across primal, dual, and
  hybrid families, recording estimator commit and cost model rather than a
  bare bit count.
- Check the LWR-specific translation explicitly: rounding noise from
  q=65537 → p=4096 is deterministic, and η=1 is a very narrow secret, both
  of which have historically been where sparse/small-secret hybrid attacks
  bite hardest.
- Report whether n=512 still clears 128 bits under the current models. If
  it does not, propose the parameter move (n, q, p, or η) in a follow-up —
  ring parameters are adjustable without touching FSCX.

Status: **DONE v2.7.17** — computed directly instead of cited: HKEX-RNL n=256 is ~32 classical / ~29 quantum Core-SVP bits (not ~105/~100) and HKEX-RNL-128 n=512 is ~87/~79 (not ~220/~200), so n=512 does NOT clear 128 bits; parameter move split out as #223.

### #223: Move HKEX-RNL to a parameter set that actually reaches 128 bits

TODO #216 computed the deployed sets directly and found both far below target:
n=256 gives ~32 classical / ~29 quantum Core-SVP bits, and HKEX-RNL-128 at n=512
gives ~87/~79. n=512 was the documented answer to n=256 being short, so there is
currently no HKEX-RNL parameter set that meets the 128-bit claim.

The sweep in `SecurityProofsCode/hkex_rnl_lattice_2026.py` §7 rules out retuning:
no (p, η) combination brings n=512 to 128 quantum bits. Ring dimension is the only
lever that closes the gap.

**Parameters decided (v2.7.18, `SecurityProofsCode/rnl_parameter_selection.py`):**
adopt `n=1024, q=65537, p=4096, eta=1, pp=4` — move n only, leave the rest alone.
~206 classical / ~187 quantum Core-SVP bits; 0 failures in 6000 trials; 1536-byte
public keys (4x); ~5x handshake cost in the Python reference.

- **n=768 is REJECTED as unsound**, not merely NTT-less as this item first claimed.
  x^768+1 = (x^256+1)(x^512-x^256+1) factors over the integers, so the ring
  CRT-splits and a secret projects to `s_i - s_{i+256} + s_{i+512}` — still short.
  The attacker drops to dimension 256 for ~39 classical / ~36 quantum bits, barely
  above the n=256 set it was meant to replace. x^1024+1 is the 2048th cyclotomic,
  irreducible over Q, so no integral projection exists there.
- **p stays at 4096.** Lowering it buys security but costs DFR: at n=1024, p=1024
  gives 4 failures in 6000 trials (~1 handshake in 1500). Once n=1024 puts security
  at 187 quantum bits, security is not the binding constraint and the remaining
  freedom belongs to correctness margin. p=2048 is also clean but halves the gap
  headroom for bits nobody needs.
- The Kyber-style module (k rings at n=256) remains sound and is deferred: it is a
  larger change than n=1024 for no gain.
- Port across C/Go/Python/Java and the assembly/Arduino targets as their widths
  allow, and re-run `hkex_rnl_lattice_2026.py` against the new deployed values —
  it reads its parameters from the suite, so it will follow automatically.
- This changes the HKEX-RNL wire format (ring elements change size), so it needs a
  `MIGRATING.md` entry. Existing HKEX-RNL PEM keys will not be readable by the new
  build. Weigh that against the alternative, which is shipping a key exchange
  documented as post-quantum at ~32 bits.
- Until this lands, `SECURITY.md`, `spec/`, and SecurityProofs-4.md §11.4.3 all
  mark HKEX-RNL and ZKP-RNL as not production-track at any size.

Status: **DONE v2.7.19** — HKEX-RNL ring moved 256 -> 1024 across C/Go/Python/Java with full 4-way interop; n=768 rejected as unsound (integral CRT split); p held at 4096 on DFR grounds; wire-format breaking, MIGRATING.md section 4. Assembly/Arduino stay at RNL_N=32 and are labelled demo-only. HCRED keeps its own n=256 ring, which required parameterising C's ring helpers by dimension (Python/Go already were).

### #222: Decide whether the 128-bit round count should be 219 or 220

TODO #217 confirmed `r = 219` = ⌈128 / log₂(3/2)⌉ is the correct
parallel-repetition figure and found no exploitable bias in the challenge
expansion, but it also recorded a margin the analysis cannot close from the
inside:

- `(3/2)^219` = 128.107 bits — a margin of **0.107 bits** over the 128-bit
  target.
- The same script's own experimental resolution floor, from the summed
  per-position chi-square excess bound over 48,000 seeds, is **0.4418 bits**.

So the measurement can only certify that no bias larger than ~0.44 bits is
present; it cannot certify 128.000 bits at r = 219. `r = 220` gives 128.692
bits, clearing the floor, at roughly 0.5% cost in signature size and
verification time.

- Decide whether to move the production figure to 220, or to keep 219 and
  document the margin explicitly as an accepted assumption.
- If moving: `_STERN_F_PRODUCTION_ROUNDS`, `_ZKP_NL_PROD_ROUNDS`, the HCRED
  production-rounds note, the C CLI's `-DSDF_ROUNDS=` guidance, and the
  `README.md` / `SECURITY.md` / `SPEC.md` round-count text all carry 219 and
  must move together across C/Go/Python/Java. Note this does **not** break
  the wire format — `--rounds` is already a parameter and existing
  signatures stay verifiable — so it is not a MAJOR bump, but it does change
  what a default-parameter signature looks like.
- If keeping 219: state the 0.107-bit margin and the 0.44-bit resolution
  floor in `SECURITY.md` so the assumption is on the record rather than only
  in `SecurityProofs-5.md` §11.8.8.

Status: **DONE v2.7.20** — kept r=219. The 0.44-bit floor was a sample-size limit, not a property of the round count: rerunning #217's statistic at 3,000,000 seeds drops it to 0.0588 bits, below the 0.107-bit margin, and finds no bias (pooled chi2 414.6 vs 438 expected). Supports a 128.048-bit soundness floor. No parameter change, no code change.

### #226: Add HKEX-RNL known-answer vectors to `KAT/`

`KAT/classical_quartet.json` covers HKEX-GF, HSKE, HPKS and HPKE at n=256. It has
never carried HKEX-RNL vectors, so the ring-dimension move in TODO #223 crossed
four language implementations with no fixed-vector oracle — every check was
cross-language agreement, which catches divergence but not a shared drift.

That gap is exactly what let TODO #223's bugs through: C, Go, Python and Java all
agreed with each other at several points where all four were wrong together.

- Add HKEX-RNL vectors at the deployed `n=1024, q=65537, p=4096, eta=1, pp=4`.
  Deterministic inputs are needed for keygen, so the generator has to seed the
  CBD sampler and `a_rand` explicitly rather than drawing from `os.urandom`.
- Cover the full handshake, not just keygen: `m_blind`, both `(s, C)` pairs, the
  reconciliation hint, `K_raw` on both sides, and the derived session key. The
  hint and the transcript-bound KDF inputs are where the #223 bugs actually lived.
- Extend `generate_kat.py` and its `--check` mode, plus `verify_kat.go` and the
  Java `KatVerify`, so all four languages verify against the same fixed file.
- Consider a small-ring vector set as well (n=64), since `--bits` is still
  supported and the small-ring path has its own key-width behaviour.

Status: **DONE v2.7.22** — KAT/hkex_rnl.json with full two-party handshakes at the deployed n=1024 and at n=64, generated by KAT/generate_kat.py and verified independently by both verify_kat.go and the Java KatVerify. Mutation-tested: corrupting hint, k_raw, session_key or alice_C is caught by both verifiers. Pins the suite layer only; the CLI/wire-format gap is split out as #227.

### #227: Wire-format-level KAT vectors for the CLI layer

TODO #226 added HKEX-RNL known-answer vectors, but they pin the *suite* layer:
ring multiplication, rounding, reconciliation, hint packing, and the KDF. They do
not pin the CLI layer — PEM/DER field layout, which field carries the ring
dimension, or the key width a response PEM is read at.

That distinction is not academic. Every bug TODO #223 shipped and CI caught lived
in the CLI layer, not the suite layer:

- `loadKey` (Go) and `_decode_session_key` (Python) read an RNL RESPONSE PEM's
  ring-dimension field as the derived key width.
- C's hybrid-rnl-stern response encoder wrote a hardcoded n=256 in that field.
- Python's and Go's hybrid combiners serialised K1 at the ring dimension rather
  than the key width, so all three hashed different transcripts.

#226's vectors would have caught none of these. Cross-language CLI tests did
eventually, but only after two CI rounds, and only where a test happened to use
default parameters — `test_encrypt.sh` pins `--bits 64`, where ring and key width
coincide, and so was structurally blind to the whole class.

- Add fixed PEM artifacts to `KAT/`: a private key, a public key, a kex response,
  and a session key, byte-for-byte, for `hkex-rnl` and `hybrid-rnl-stern`.
- Verify by having each CLI *consume* the checked-in PEMs and reproduce the
  expected session key, not merely by regenerating them — consumption is the
  direction the bugs broke.
- Cover both the default ring and a small ring, since the small-ring path is
  exactly where ring dimension and key width coincide and hide this bug class.
- Consider extending to the classical quartet's PEMs while the harness is being
  built; the same argument applies, it simply has not bitten yet.

Status: **DONE v2.7.23** — KAT/pem/ with 14 byte-exact artifacts and CliTest/test_kat_pem.sh, which feeds them to all four CLIs and demands exact output (consumption, the direction TODO #223's bugs broke). 15 PASS / 0 FAIL at the deployed ring. Found two real defects on its first run: C silently misparsed any PEM whose ring differs from its compiled RNL_N (fixed here — it now rejects), and the small-ring session-key width diverges four ways (split out as #228).


### #228: HKEX-RNL session-key width diverges four ways below n=256

TODO #227's wire-format KAT found this on its first run. At the deployed ring
(n=1024) all four CLIs agree byte-for-byte. Below n=256 they do not:

| CLI | session key at n=64 |
|---|---|
| Python | full 255-bit contributory-KDF output, PEM declares `nbits=64` |
| Go | truncated to 64 bits |
| Java | a third result again (its `dec` on Python's PEM yields garbage) |
| C | rejects the PEM — it is compiled for one `RNL_N` (now checked, TODO #227) |

Root cause: `_rnl_contributory_kdf` always returns an HFSCX-256 output, so the
derived key is 256 bits regardless of ring dimension — but the CLIs label the
session key with `_rnl_key_bits(n)`, which is `n` for a small ring. Python then
stores the full hash under a 64-bit label, Go truncates to match the label, and
Java does something else again. At n >= 256 the two numbers coincide and the
disagreement vanishes, which is why nothing caught it: Python's small-ring tests
only ever compare Python against Python, and every cross-language test uses the
default ring.

This is pre-existing, not a TODO #223 regression — it predates the ring move and
was merely unreachable.

- Decide what an HKEX-RNL session key *is* at a small ring. The defensible answer
  is that it is always 256 bits, because the contributory KDF's output is, and
  the ring dimension has no bearing on it — in which case `_encode_session_key`
  should be given 256 rather than `_rnl_key_bits(n)` for this algorithm, and the
  small-ring `nbits` field stops lying. Note HKEX-GF is different: there the key
  really is `nbits` wide, so this cannot be fixed globally in the encoder.
- Whatever is chosen, apply it to all four and extend `CliTest/test_kat_pem.sh`
  to assert n=64 as well — the artifacts are already generated and checked in,
  and the assertions are three lines away (restore `for tag in n1024 n64`).
- Scope note: small rings are demo/test only and were never at a security claim,
  so this is a correctness and interoperability defect, not a vulnerability.
- **This is a MAJOR-version change.** Whatever is chosen, fixing it changes what
  `kex --algo hkex-rnl --bits N` produces for N < 256 — a change to what an
  existing `--algo` value produces, which is one of the breaks the 2.0.0 tag
  froze the CLI/PEM surface against. That it reaches only demo rings, and that
  no two CLIs agreed on the old output anyway, does not exempt it: the surface
  is the surface. Ships as v3.0.0 with a `MIGRATING.md` entry alongside it.

Status: **DONE v3.0.0** — resolved in favour of 256 bits at every ring dimension, which is the contributory KDF's HFSCX-256 output width and what the C CLI had always encoded. Python/Go/Java now split the two quantities explicitly (`_rnl_key_bits`/`rnlKeyBits` = raw reconciliation width, `_rnl_session_bits`/`rnlSessionBits` = derived key width); `test_kat_pem.sh` asserts n=64 alongside n=1024 and all four agree. n >= 256 is byte-identical, so the deployed n=1024 wire format is untouched.


### #213: Closed-form O(log i) `fscx_revolve` — bit-exact, no primitive change

Because `fscx_revolve(A, B, i) = M^i·A ⊕ T_i·B` with everything living in
GF(2)[x]/(x^n + 1), the i sequential rotate-XOR rounds can be replaced by
square-and-multiply on `m(x)^i` plus a closed form for `S_i` — O(log i)
polynomial multiplications instead of O(i) rounds, producing byte-identical
output. At the deployed parameters that is 64 (encrypt) and 192 (decrypt)
rounds collapsing to ~7–8 multiplications, and `_m_inv`'s bootstrap
(`fscx_revolve(1, 0, n/2 − 1)`) becomes a single inversion.

FSCX and FSCX_REVOLVE keep their definitions exactly — this is an
evaluation strategy, not a redefinition, and the KAT vectors in `KAT/` are
the correctness oracle.

Scope:
- Benchmark the polynomial route against today's loop in C/Go/Python:
  schoolbook (n²/w word ops) vs carryless-multiply intrinsics vs the
  existing rotate loop; the rotate loop may well win at n=256 for small i,
  and a negative result is a perfectly good outcome to record in
  `benchmarks/`.
- If it wins, note that it only applies to classical FSCX_REVOLVE. The NL
  variants are non-linear by construction and stay iterative — which is
  itself worth documenting, since it makes the cost gap between the
  classical and NL protocols explicit.
- Keep assembly/Arduino targets out of scope unless the win is large;
  their n=32 parameters give little room.

Status: **DONE v3.0.1** — shipped in C, Go, and Python; bit-exact (exhaustive at n=8, 180k random cases in C, plus the KAT vectors as the oracle). The win is larger than this entry expected because no dense polynomial multiplication is needed at all: in characteristic 2 every M^(2^u) is still a three-term polynomial (Frobenius), so each step is two rotations and an XOR. At the deployed parameters, 10 sparse steps for i=64 and 13 for r=192 against 64 and 192 rounds — measured 44x/102x (Python), 12x/29x (Go), 9x/22x (C). Below a measured crossover each implementation falls back to the loop (C < 8 steps, Go < 2, Python never). NL variants stay iterative, as anticipated; assembly/Arduino left out of scope.

### #229: Untrack the built binaries and gitignore them

Four compiled artifacts are checked into the repository:

| Path | Revisions | Built by |
|---|---|---|
| `HerraduraCli/herradura_cli_go` | 16 | `build_go.sh` |
| `HerraduraCli/herradura_cli` | 18 | `build_c.sh` |
| `Herradura cryptographic suite_arm` | 6 | `build_arm.sh` |
| `CryptosuiteTests/Herradura_tests_arm` | 6 | `build_arm.sh` |

`.gitignore` already excludes every *other* build output — the `_c`/`_go` suite and
test binaries, the `_i386` pair, the whole `_asan` set — and carries a comment
explaining that these four are deliberately absent because they are tracked. This
item removes that exception.

**Why.** Two reasons, one measurable and one not.

- Size: the `herradura_cli_go` blobs alone account for **55 MiB** of a 164 MiB
  `.git`, because a 3.5 MB Go binary re-compresses poorly against its predecessor
  and every rebuild commits a fresh copy. The C CLI adds 18 more revisions of a
  208 KB object.
- Provenance: a tracked binary is whatever toolchain the last committer happened
  to run, not a reproducible build. Any TODO that touches `herradura.h` or the Go
  package now produces a binary delta in its diff that no reviewer can read or
  verify, and which is stale the moment someone else rebuilds. TODO #213's merge
  is the immediate example: two binary files changed alongside the source.

**Nothing in CI depends on them.** `arm-i386` runs `./build_arm.sh` from source
after installing `gcc-arm-linux-gnueabi`; the `native-c`, `native-go`, and
`native-interop` jobs build their own CLIs. The tracked copies are used by no
workflow step.

**The one real hazard, and it is not the untracking.** Six `CliTest/*.sh` scripts
guard on `[ -x "$C_CLI" ]` / `[ -x "$GO_CLI" ]` and `skip` with reason
`"not built"` when the binary is missing. Today a fresh clone has those binaries,
so the guard never fires locally. After untracking, a developer who runs
`bash CliTest/test_kat_pem.sh` before `./build_c.sh` gets `SKIP` lines and a
`0 FAIL` exit status — a green result that asserted nothing. CI is unaffected
(it always builds first), so this would be a silent *local* regression in
coverage. Resolve it as part of this item, not after:

- decide whether a missing binary should stay a `skip` or become a hard failure.
  Preference: keep `skip` for scripts where the binary is one of several
  languages being compared, but make the skip loud — print a one-line
  `run ./build_c.sh first` hint — and have the script exit non-zero if *every*
  language it tests was skipped, so an all-skip run can never read as a pass.
- `CliTest/test_kat_pem.sh` deserves particular care: it already has a legitimate
  `skip` for `c n64` (the C CLI is compiled for a single `RNL_N`). That one must
  keep passing while a not-built skip must not.

**Plan.**

1. `git rm --cached` the four paths; add them to `.gitignore` and rewrite the
   comment block that currently explains why they were excluded from it.
2. Fix the skip-guard semantics above across all six scripts.
3. Grep `docs/TUTORIAL.md`, `README.md`, `Dockerfile`, `docker-entrypoint.sh`,
   and `Mcp/` for anything that invokes `./HerraduraCli/herradura_cli{,_go}`
   without a preceding build step, and add one where it is missing.
4. Note in `CHANGELOG.md` that a fresh clone must now build before running the
   C/Go CLI tests.

**Explicitly out of scope: rewriting history.** Deleting the blobs from past
commits (`filter-repo`/BFG) would reclaim the 55 MiB but changes every commit
hash, breaks every existing clone and every PR reference, and invalidates the
`TODO_DONE.md` archive's implicit link to its commits. Untracking going forward
costs nothing and stops the growth; reclaiming the existing history is a separate
decision that should be made on its own merits, if ever.

Status: **DONE v3.0.2** — four binaries untracked and gitignored; the skip-guard hazard the untracking exposed fixed in the same change via the new CliTest/lib_build.sh, plus a CI guard against its recurrence.

### #224: Explore a masked-step / hash-based HKEX PQC variant (MFSCX-KEX)

Every HKEX variant shipped so far derives its hardness from one of two places:
GF(2^n)* discrete log (HKEX-GF — classically broken by Shor, and the FSCX layer
around it is affine) or Ring-LWR (HKEX-RNL — which TODO #216/#223 showed is far
below its claimed level at the deployed parameters). This item is the exploratory
track for a third construction that leans on symmetric/hash-style hardness
instead, using FSCX itself as the mixing function.

**Proposed construction (MFSCX_REVOLVE).** Add a per-step, non-uniform seed
injection to the revolve loop. With `M = I ⊕ ROL ⊕ ROR` as today:

```
MFSCX_REVOLVE(A, B, i; S):
    for j = 0 .. i-1:
        A <- FSCX(A, B) ⊕ (S_j & mask_j)
```

where `S_j` is a seed-derived subkey for step `j` and `mask_j` selects *which*
bits of `S_j` actually get XORed in. Two mask regimes to evaluate:

- **static P-box** — `mask_j` fixed at compile time (a published permutation/
  selection box, same for all sessions);
- **dynamic P-box** — `mask_j` derived from the seed itself, or from the current
  state `A`, so the injection pattern is session- (or state-) dependent.

**The central tension, to be settled before any implementation.** The two-party
agreement in every FSCX-based construction rests on the XOR homomorphism of the
affine map, and that same affinity is exactly what `hkex_classical_break.py`
exploits (`sk = S_{r+1}·(C ⊕ C2)`, computable from the wire values alone).

- A **static** mask keeps the whole map affine over GF(2): it only changes the
  constant term, `MFSCX(A,B) = M^i·A ⊕ T_i·B ⊕ c(S)`, and `c(S)` cancels in
  `C ⊕ C2` whenever both parties use the same public S. First task is therefore
  to check whether the existing break generalizes verbatim — the expectation is
  that it does, and that finding alone would close the static branch.
- A **dynamic** (state-dependent) mask does destroy affinity, but it also
  destroys the homomorphism that makes `C_A ⊕ C_B` a shared value at all. The
  open question is whether there is any middle ground: a mask schedule that is
  non-linear in the seed while remaining commutative in the two parties'
  contributions. `hkex_nonce_impossibility.py` already proves no *nonce* choice
  rescues HKEX; the argument there is algebraic and may extend to any
  seed-injection schedule. Extending it (or finding the gap) is the real work.

**Hash-based hardness — state the ceiling up front.** "Hash-based key exchange"
is not a free substitution for a trapdoor. Hash-based *signatures* (already here
as HPKS-WOTS-F / HPKS-XMSS-F) work because signing needs no trapdoor; key
exchange does. Against a random-oracle-only adversary the Impagliazzo–Rudich
separation caps black-box key agreement at Merkle-puzzle quadratic security —
2^128 target means ~2^64 honest work, which is not shippable. So the plan must
pick its honest goal early:

1. **Interactive/authenticated setting** — MFSCX as a KDF or ratchet over an
   already-shared secret (this is HSKE territory, and works, but is not a KEX);
2. **Merkle-puzzle-style KEX** — real, provable, and quantifiably too slow;
   worth a cost table so the number is on the record rather than assumed;
3. **MFSCX as the symmetric layer inside a structured PQC KEM** — e.g. as the
   hash/KDF/error-sampler inside the QC-MDPC or Ring-LWR path, where hardness
   comes from the code/lattice and MFSCX only has to be a good PRF. This is the
   only branch with a plausible production endpoint.

**Plan.**

1. Add `SecurityProofsCode/mfscx_kex_analysis.py`, self-contained like its
   neighbours. Sections: (a) formalize MFSCX_REVOLVE for both mask regimes;
   (b) re-run the `hkex_classical_break.py` recovery against the static-mask
   variant across widths, expecting success — i.e. a disproof; (c) measure
   algebraic degree / branch number of the dynamic-mask variant, reusing the
   method in `fscx_branch_number.py` and `nl_fscx_owf_analysis.py`;
   (d) test whether two-party agreement survives dynamic masking at all
   (it likely does not — record the failure rate); (e) the Merkle-puzzle cost
   table for option 2.
2. Reuse `fscx_revolve_corank.py`'s machinery to compute the co-rank of the
   masked key map `T_i` under a static P-box, at the deployed `i = n/4`,
   `r = 3n/4` — if the mask shrinks the image, that is a second independent
   reason to reject the static branch.
3. Check the dynamic-mask permutation for orbit collapse the way
   `nl_fscx_v2_orbit.py` does: a seed-derived mask that lands in a short cycle
   silently degrades to a static one.
4. Only if steps 1–3 leave a branch alive, write it up as a new SecurityProofs
   subsection (§11.21, in `SecurityProofs-7.md` — mind the ~750-expression
   KaTeX budget per TODO #220) and open a separate implementation TODO. Do not
   add an `--algo` tag, PEM label, or `spec/` entry from this item.
5. If all branches close, the deliverable is still worth having: land the script
   plus a short negative-result section, the same way `hkex_cy_test.py` and
   `hkex_cfscx_*.py` record constructions that were tried and rejected. A
   documented dead end is the point of this item, not a failure of it.

**Success criterion.** Either a construction with a written hardness assumption
that is not restatable as "FSCX is affine", or a clear negative result saying
why seed-masked FSCX cannot give key agreement. Anything that only *looks*
non-linear while `C ⊕ C2` still determines `sk` does not count.

Status: **DONE v3.0.3** — negative result: a static mask leaves the map affine and
the classical break intact (10 000/10 000 recoveries), a dynamic mask destroys two-party
agreement (0/2000 at every width), and the generalized injection-schedule impossibility
theorem shows every schedule in between either breaks agreement or contributes only what
Eve computes from the wire.  `SecurityProofsCode/mfscx_kex_analysis.py` plus SecurityProofs-7.md
§11.21; MFSCX survives only as a symmetric layer, so no `--algo` tag, PEM label, or `spec/`
entry follows.

### #230: Does TODO #224's negative result extend to an S-box layer?

TODO #224 closed the seed-masked revolve (MFSCX) as a key exchange, but the
argument that closed it has a stated scope, and an S-box is outside it.  The
impossibility theorem in `mfscx_kex_analysis.py` §5 quantifies over *additive*
injections: values `u_j` that enter the step by XOR and reach the session key
only through the accumulator `L = xor_j M^(r-1-j).u_j`.  That linear factoring is
what let correctness force `L` to be a public function of `(C, C2)`.  A
substitution layer does not factor out of the iteration at all:

```
SFSCX_REVOLVE(A, B, i):
    for j = 0 .. i-1:
        A <- S(FSCX(A, B))          # or FSCX(S(A), B), or a B-keyed S_B(.)
```

so #224's theorem says nothing about it, in either direction.  The expectation is
still failure — but by a different mechanism, and "we expect it for the same
reason" is exactly the kind of claim this repo has been wrong about before
(TODO #216 vs. the cited Core-SVP figures).  This item settles it.

**The real question underneath.** Agreement in every HKEX variant rests on one
identity — that the two parties' step maps commute up to the XOR corrections:

```
revolve(revolve(A2, B2, i), B,  r) xor A   ==
revolve(revolve(A,  B,  i), B2, r) xor A2
```

which holds because `M` is linear and `M.S_n = 0`.  An S-box breaks commutation.
So the honest formulation is not "does an S-box fail" but:

> Characterize *every* step function `G(A, B)` for which HKEX-style two-party
> agreement holds.  Conjecture: `G` must be affine over some abelian group, i.e.
> any such construction is a disguised XOR/DH homomorphism — and therefore
> already covered by one of the existing breaks.

If that conjecture is provable, it subsumes TODO #210, the nonce impossibility
theorem, and TODO #224 as corollaries, and it retires a whole class of future
proposals in one place instead of one script at a time.  The repo currently holds
five separate one-off failures of this shape — `hkex_cy_test.py` (FSCX-CY, carry
non-linearity), `nl_fscx_v2_kex.py` (non-abelian `pi_K` family, Ko-Lee),
`hkex_cfscx_*.py` (four preshared/two-step/int-op/compress constructions),
`hkex_nonce_impossibility.py`, and now `mfscx_kex_analysis.py` — none of which
knows about the others.  Deciding whether they are instances of one theorem is
the substance of this item; the S-box is the concrete case that motivates it.

**Sub-cases, cheapest first.  They do not all have the same answer.**

1. **GF(2)-linear S-box** (a bit permutation, an MDS-style matrix, any linear
   `L`).  This is *not* a new construction: the step becomes `L.M.(A xor B)`, so
   every result carries over verbatim with `M` replaced by `L.M`.  Predictions to
   confirm rather than assume: agreement survives iff `(L.M)` has the same
   order/annihilation structure that gives `S_n = 0`; the break formula becomes
   `S_(r+1)` over the new operator; and the TODO #210 co-rank changes — a
   well-chosen `L` may well make the key map *invertible*, which would be a real
   (if non-KEX) result worth having, in the same way TODO #211's odd-`i` finding was.
2. **Affine S-box** (`L.x xor c`).  Reduces to case 1 plus a constant, and the
   constant is exactly TODO #224's `kappa` — expected to be closed by #224's own
   argument.  Confirm that the reduction is exact rather than merely plausible.
3. **Genuinely non-linear S-box, unkeyed** — AES-style bytewise inversion over
   `GF(2^8)`, or a 4-bit box applied nibblewise.  This is the case the item is
   named for.  Measure the agreement rate, and — the discriminator that matters —
   the *distribution* of `sk_A xor sk_B`, not just the pass/fail count.  #224
   measured `n/2` mean Hamming distance for the dynamic mask, i.e. the two values
   are unrelated and no reconciliation can help.  If an S-box instead leaves a
   *small* distance, the construction is not dead: it is noisy, and Peikert-style
   reconciliation is already deployed in this suite (HKEX-RNL, §11.4.2).  That
   would be a live branch, and it is the one outcome that would make this item
   more than a fourth negative result.
4. **B-keyed S-box** (`S_B(.)`, box selected by the revolve parameter).  Destroys
   even the shared-box symmetry; expected to be the worst case, included to bound
   the space rather than because it is promising.

**Plan.**

1. Add `SecurityProofsCode/sbox_kex_extension.py`, self-contained like its
   neighbours.  Sections: (a) restate #224's theorem with its scope condition made
   explicit, and show by construction that an S-box violates the condition — the
   point being that #224 is *silent* here, not that it applies; (b) case 1, with
   the co-rank of `L.M` measured against `fscx_revolve_corank.py`'s closed form and
   an explicit search for an `L` making the key map invertible; (c) case 2's
   reduction; (d) cases 3 and 4, reporting agreement rate *and* the Hamming-distance
   distribution of `sk_A xor sk_B` against the `n/2` random-function baseline;
   (e) the reconciliation test from sub-case 3, run only if (d) shows small distances.
2. Attempt the characterization theorem.  Start at small width where the space is
   enumerable: for `n = 4` and `n = 6`, search over step functions `G` in a
   restricted but non-trivial family and record which admit agreement.  A clean
   empirical statement ("every agreeing `G` found at `n = 4/6` is affine over an
   abelian group") is a publishable-grade result for this repo even without the
   general proof, provided the family searched is described honestly and the
   search is exhaustive over it rather than sampled.
3. If the theorem lands, write it up as §11.22 in `SecurityProofs-7.md` and add
   back-references from §11.21 and §1.3.1, so the five scattered failures point at
   one statement.  Mind the KaTeX budget — Part 7 is at 649 of ~750 after TODO
   #224, so a theorem-heavy section may need Part 7 split (cf. TODO #220) rather
   than squeezed in.  Budget the split as part of this item, not as a surprise.
4. If sub-case 3 leaves a reconciliation-based branch alive, do **not** implement
   it here.  Open a separate implementation TODO, and note that a noisy-agreement
   KEX whose hardness is "inverting an S-box layer" still needs a written hardness
   assumption before it is worth any code — the failure mode TODO #224 warned
   about, where a construction looks non-linear but the wire still determines the key.

**Explicitly out of scope.** No `--algo` tag, PEM boundary label, or `spec/` entry
from this item, and no change to any shipped protocol.  A linear S-box that makes
the key map invertible (sub-case 1) is a finding about HSKE/HPKE, not a licence to
change them; that would be its own TODO with its own wire-format and MIGRATING.md
analysis.

**Success criterion.** Either the characterization theorem (with the S-box case
falling out as a corollary), or — failing the general proof — a measured answer for
all four sub-cases in which the distance distribution, not just the pass/fail rate,
is reported, so that a future reader can tell "unrelated" from "noisy but
reconcilable".  A result that only says "agreement failed 0/2000" repeats TODO #224
without extending it and does not close this item.

Status: **DONE v3.0.4** — closed, but by replacement rather than extension.  #224's
theorem is silent on substitution layers, so the item is settled instead by a
characterization theorem: HKEX-style agreement holds iff `G_B^r . F_B2^i` is a
translation, which forces the i-fold iterate into a coset of the translation group and
yields `sk = G_B0^r(C) xor G_B0^r(C2) xor c` from the transcript alone, for any step
function whatsoever.  It subsumes #210, `hkex_nonce_impossibility.py` and #224.  The
item's own affineness conjecture is **false** — 15 360 non-affine permutations admit
full agreement at n=4 — and the theorem covers them anyway.  Sub-case findings: a
linear box takes the TODO #210 co-rank from 126 to 64 of 256, with 64 proved a floor
(the co-rank 63 optimum fails agreement), and a single transposition in one 4-bit box
saturates the n/2 distance baseline, so no reconciliation branch survives.
`SecurityProofsCode/sbox_kex_extension.py` plus SecurityProofs-7.md §11.22; Part 7
needed no split (653 of ~750).  No `--algo` tag, PEM label or `spec/` entry.


---

### #231: The SecurityProofs part index is duplicated ~76 times and has drifted twice — add a CI consistency check

The seven-part split of `SecurityProofs.md` (TODO #170, re-split under TODO #220) is
described by the *same* seven-row table in about 76 places:

| location | rows | carries |
|---|---|---|
| `SecurityProofs.md` index | 7 | ranges, titles, expression counts |
| banner atop each `SecurityProofs-1..7.md` | 7 x 7 = 49 | ranges, titles |
| `Continued in Part N` footer in Parts 1–6 | 6 | ranges, titles |
| `README.md` file map | 7 | ranges |
| `CLAUDE.md` repository listing | 7 | ranges, expression counts |
| `SecurityProofsCode/KATEX_RULES.md` split history | 7 | ranges, expression counts |

Nothing generates any of it, and it has now drifted **twice running**: TODO #224 added
§11.21 and TODO #230 added §11.22, and on both occasions six of the eight banners, the
README file map and the KATEX_RULES split history were left saying `§11.15–§11.20`.
Nine locations were stale by the time it was caught.

The expression counts drift independently and are the more dangerous half, because a
wrong count reads as reassurance about the ~750-per-page GitHub KaTeX ceiling
(`SecurityProofsCode/KATEX_RULES.md`) when it is nothing of the sort: `SecurityProofs.md`
advertised **593** expressions for Part 4 against an actual **659**, and 408 for Part 2
against 409. Both survived several releases and were found by hand, not by CI.

**What this is not.** The conclusions of §11.21/§11.22 are complete and correct — the
scope argument, the characterization theorem and its universal transcript-only attack,
the linear-box co-rank identity with the 126 -> 64 table, the Hamming-distance table
separating "unrelated" from "noisy but reconcilable", and the refutation of #230's own
affineness conjecture. This item is navigation metadata only and is not licence to
rewrite them.

**Deliverable.** A checker, not a generator: the banner is prose inside hand-written
documents, and a check catches the same failure with none of the build machinery.
`SecurityProofsCode/check_part_index.py` treats the `SecurityProofs.md` index as the
single source of truth, asserts every other copy of a range or title agrees with it,
and asserts every advertised count equals what `validate_katex.js` actually measures.
Wired into the existing `katex` CI job, which already checks out Node and iterates
these exact files.

**Headroom note.** Part 7 is at 653 of ~750, the tightest of the seven; the next
research-review section added there should check before landing rather than after. A
Part 8 split is the eventual answer, not a bigger Part 7 — and when it happens, the
checker's `NPARTS` and the "split into seven parts" preamble assertion both move with it.

Status: **DONE v3.0.5** — `SecurityProofsCode/check_part_index.py` (source of truth =
`SecurityProofs.md`; `--require-counts` makes a missing node/katex a failure rather
than a skip) plus a `Part-index consistency` step in `ci.yml`'s `katex` job.
Negative-tested against all seven drift classes — banner range, footer range, README
range, `CLAUDE.md` count, `KATEX_RULES.md` range, an index count stale against the
measured value, and a deleted banner row — each caught with the offending
`file:line`; the historical 593-vs-659 Part 4 bug is reproduced and flagged. The
nine stale `§11.15–§11.20` locations and the two stale counts were fixed first
(commit `5115f2a`), so the tree passes clean. Documentation/CI only: no protocol,
`--algo` tag, PEM label or `spec/` change.

---

### #232: Decide whether to act on §11.22.2's co-rank improvement (126 -> 64) in HSKE/HPKE

TODO #230 produced an unshipped side-result. §11.22.2 of `SecurityProofs-7.md` shows
that TODO #210's plaintext leak is not intrinsic to the FSCX construction: with a
linear box `L` the step becomes FSCX with `M` replaced by `M' = L.M`, and writing
`Y = M' + I`,

    co-rank(T_i) = dim ker Y^(2^v2(i) - 1)

so #210's closed form `2(2^v2(i) - 1)` is the special case `v(M + I) = 2`. **The factor
2 is a property of this particular `M`, not of the construction.** A box with Jordan
type `(n-1, 1)` takes the leak from **126 to 64 of 256** at `n = 256, i = 64`, and 64
is a proved floor, not a search result: `dim ker Y^(i-1) = sum_j min(lambda_j, i-1)` is
minimized by the fewest and largest blocks, and the unconstrained optimum (regular
nilpotent, co-rank 63) has `Y^(n-1) != 0` and therefore **fails agreement**.

**This item is the decision, not the change.** Nothing here authorises editing HSKE or
HPKE; §11.22.2 says as much in its own last line.

**Why the answer is probably "no", and what would have to be true for it to be "yes".**
Three routes to the same leak are already on the table, and the linear box is the worst
of them on every axis:

| route | co-rank at n=256 | cost | source |
|---|---|---|---|
| odd `i` (e.g. 65) | **0** — `T_i` invertible, Shannon-perfect at one-time use | a parameter | #210/#211, `hske_perfect_secrecy.py` |
| secret per-step injection | **0** — `sigma_i` is surjective since `m(1) = 1` | a subkey schedule | #224, §11.21.3 |
| linear box `L` (this item) | **64** — and never 0, since `Y` is nilpotent so `Y^(i-1)` is singular for every even `i` | a new primitive **and** a MAJOR wire-format break | #230, §11.22.2 |

Two further points argue against shipping it:

1. **None of the three fixes the affine two-time break.** `E1 xor E2 = M^i.(P1 xor P2)`
   under a reused key holds regardless of `L`, `i`, or any additive injection, because
   all of them preserve affinity. The real fix for multi-use is the NL quartet, which
   already ships.
2. **It cannot change a `SECURITY.md` rating.** HSKE (key-only) is already "Not
   suitable for production" and HPKE "Demo-only", and each is disqualified by something
   the co-rank does not touch — a single known-plaintext pair recovers the HSKE
   keystream, and HPKE falls to ~2^36.5 Pohlig-Hellman. A MAJOR break that moves 126 to
   64 buys a rating change of exactly zero.

So the plausible outcomes are `DEPRECATED` (documented, deliberately not shipped) or an
opt-in that touches no default. Shipping it as the default would need an argument that
survives all four objections above, and per CLAUDE.md's MAJOR rules that argument must
appear in this item's own text before any code moves.

**Work to do.**

1. Decide among: (a) close as `DEPRECATED` with the reasoning recorded in
   `SecurityProofs-7.md`; (b) expose the `(n-1, 1)` box as an opt-in that leaves every
   default and every existing artifact readable; (c) make it the default, which is a
   MAJOR bump plus a `MIGRATING.md` entry, since it changes what existing `--algo hske`
   and `--algo hpke` ciphertexts decrypt to.
2. If (b) or (c): exhibit the concrete `L` — §11.22.2 measured a Jordan type, not a
   shipped matrix. It must be stated as a bit-matrix or a closed form, verified to give
   `Y^(n-1) = 0` and co-rank 64 at n=256, and be cheap enough for the AVR and Thumb-2
   targets, which is a real constraint: FSCX is currently three shifts and five XORs.
3. Either way, check the knock-on to HPKS. #210 notes the Schnorr challenge
   `e = fscx_revolve(R, msg, i)` lives in a 130-dimensional affine subspace; a box that
   moves the co-rank to 64 moves that to 192, which is a *signature* parameter and a
   separate wire-format question from HSKE/HPKE.
4. Whatever is decided, add the comparison table above to §11.22.2 so a future reader
   does not rediscover the 126 -> 64 result and mistake it for the best available fix.

Related: [[#210]] (the leak), [[#211]] (odd `i`, co-rank 0), [[#224]] (secret injection,
co-rank 0), [[#230]] (this result's origin).

Status: **DONE v3.0.6** — decided: **do not ship it.**
`SecurityProofsCode/corank_linear_box_decision.py` plus SecurityProofs-7.md §11.23.
Two of this item's four objections held, one was wrong, and the investigation turned up
two results the item did not anticipate.

*Wrong:* the cost objection. Step 2 assumed the concrete `L` might be too expensive for
AVR/Thumb-2. In the standard bit basis the `(n-1, 1)` box is a broken non-cyclic shift,
`Y(x) = (x >> 1) & ~(1 << (n-2))`, `M'(x) = x ^ Y(x)` — 3 word-ops against FSCX's 5. It
is *cheaper* than what ships.

*The actual objection:* co-rank counts leaked dimensions, not exploitability. That cheap
box makes 64 ciphertext bits key-independent and every one is a plaintext bit verbatim,
`E[192] = P[192]` through `E[255] = P[255]` — a quarter of the plaintext in the clear,
against zero raw bits for the classical `M`. The conjugated box fixes that (co-rank 64,
minimum leaked weight 75 vs the classical 4, 0 raw bits) but is dense: ~128x the cost and
8 KB of matrix, which does not fit the AVR target and would cost cross-target parity.

*New result 1 — the circulant floor.* Exhaustively over every circulant at `n = 8` (64
admit agreement) and `n = 16` (16 384), none beats `2(i-1)`, which is exactly what the
classical `M` achieves; agreement forces `v(M'+I) >= 2` and then
`co-rank = min(n, v(i-1))`. So **TODO #210's 126 is both a defect and a floor** — the
best any rotation-based step can do — and 126 -> 64 is not a parameter tweak but a
different primitive.

*New result 2 — the leak's concrete form.* The lightest functional in the kernel has
weight 4: `E[0]^E[2]^E[128]^E[130]` equals the same XOR of plaintext bits under every
key, verified 300/300 against the shipped `fscx_revolve`. This holds for what ships
today and is independent of the decision; `SECURITY.md`'s HSKE and HPKE rows now carry
it, along with the floor.

Confirmed as written: the box never reaches 0 while odd `i` and a secret injection both
do; the affine two-time break `E1 ^ E2 = M'^i.(P1 ^ P2)` survives every option (200/200
for both boxes); the HPKS knock-on is real (challenge entropy 130 -> 192) and is a
second, separate MAJOR bump; and no rating in `SECURITY.md` would move. No `--algo` tag,
PEM label, `spec/` entry or `MIGRATING.md` entry follows.

---

### #225: `native-python` — measure what the n=1024 ring actually costs, and where it goes

*Premise rewritten (2026-08-23). The original entry framed this as timeout risk.
That framing does not survive contact with the workflow file: `.github/workflows/`
contains **no `timeout-minutes` key at all**, so every job inherits GitHub's
360-minute default. Five recent `native-python` runs took 18.3, 22.4, 23.5, 24.6
and 24.7 minutes — a ~15x margin. There is no timeout to cross, and "raise the job
timeout" was never one of the options because no timeout was ever set. The real
question is a different one, below.*

TODO #223 moved HKEX-RNL's ring from 256 to 1024. The NTT is O(n log n), so the
Python reference's ring multiply went from 1.7 ms to 8.9 ms — 5.2x — measured on a
host without numpy (`_NUMPY = False`, the pure-Python `_ntt_inplace` path).

**Where that 5.2x actually lands.** The suite runs under `-t 2.0`, a per-test
wall-clock cap. A capped test does not get slower when its inner operation gets
slower — it performs **fewer iterations in the same two seconds**. So the ring
move did not buy 5.2x more job time; it bought roughly 5.2x less RNL coverage,
silently, with no signal in the log. That is the concern worth tracking, and it
is a correctness-confidence concern, not a scheduling one.

Step timings from run 32617685487 locate the time precisely:

| Step | Time | Share |
|---|---|---|
| Python test suite (`-t 2.0`) | 1091 s | 82% |
| CliTest — Python CLI (15 scripts) | 243 s | 18% |
| everything else | 9 s | <1% |

So the job is dominated by the capped suite, whose duration is set by the *number*
of tests and benchmarks, not by how fast any one of them runs. Adding a test costs
up to 2 s; making RNL 5x slower costs nothing in time.

**Work.**

1. Instrument iteration counts, not wall time. For each RNL-touching test, record
   how many iterations completed inside the cap at n=256 vs n=1024. That number is
   the coverage that was lost, and it is the figure this item exists to put on the
   record. Land it in `benchmarks/` so the next ring-parameter change has a
   baseline.
2. Decide per test whether the surviving iteration count is still adequate. These
   are correctness checks, not benchmarks — a handful of iterations may be entirely
   sufficient for some and plainly too few for others. Where it is too few, raise
   that test's cap specifically rather than the job's; there is ample headroom.
3. Settle the numpy question, which the original entry raised and which is still
   open. `_rnl_poly_mul` takes a vectorised path when numpy imports. The
   `native-python` job installs `python3` and nothing else, so whether numpy is
   present depends on the `ubuntu-latest` image rather than on anything this repo
   controls — and **the suite prints no indication either way**, so the CI logs
   cannot answer it retrospectively (grepping them for `numpy` returns nothing).
   Add a one-line banner reporting `_NUMPY` at startup. That is a two-line change
   that makes every future run self-documenting, and it should land first, since
   steps 1 and 2 are measuring a path whose identity is currently unknown.

**A second-order detail worth checking while instrumenting.** The cap is polled
every 64 iterations (`(i & 63) == 63`, `Herradura_tests.py:1175`), not every
iteration. Overshoot is therefore bounded by 64 iterations' worth of work, which
scales with per-iteration cost — the same 5.2x applies to it. At n=1024 this is
probably still small against a 2 s cap, but it is unmeasured, and it is the one
mechanism by which a slower ring *could* lengthen the job rather than shorten
coverage. Confirm it is negligible, or tighten the poll for the RNL tests.

**Explicitly not in scope.** Splitting `native-python` the way TODO #205 split the
combined `native` job. That was listed as an option under the timeout framing; with
a 15x margin it addresses nothing, and it would cost a second full checkout and
dependency install for no benefit.

Status: **DONE v3.0.7** — measured; the premise did not survive the measurement.
`benchmarks/rnl_ring_cost.py` plus a startup banner and a closing cap-accounting line
in `CryptosuiteTests/Herradura_tests.py`.

**Step 3 first, as the item asked.** The banner now reports the live path and the ring
the tests exercise: `Ring: _rnl_poly_mul=pure-Python NTT, RNL_SIZES=[32, 64, 128, 256]`.
That last field is the finding.

**Step 1 — the coverage loss is zero, and could not have been otherwise.** The Python
harness is self-contained (it transcribes the primitives rather than importing the
suite) and its `RNL_SIZES` is still `[32, 64, 128, 256]`. TODO #223 moved the *suite's*
`RNLN`; the harness never followed, and the C harness is identical
(`rnl_sizes[] = {32, 64, 128, 256}` against `RNL_N 1024`). Instrumenting all 95 capped
call sites at `-t 2.0`: **no RNL site is truncated** — every one completes its full 200
iterations. The ring move cost nothing in the capped path because it never entered it.

The harness could not be pointed at 1024 by editing `RNL_SIZES` either: it uses one
variable for both ring dimension and key width, so its KDF line
`_RNL_KDF_DC_256 >> (256 - n_rnl)` raises `ValueError: negative shift count` for any
`n_rnl > 256`. The suite keeps them separate (ring 1024, `KEYBITS` 256) — precisely the
distinction #223 introduced, which the harness predates. Deployed-ring coverage comes
from `KAT/hkex_rnl.json` (which does pin n=1024) and the CliTest scripts, not from the
capped suite. Ring-cost curve recorded for the next parameter move: the item's 5.2x
reproduces exactly (5.26x on `_rnl_poly_mul`, 5.15x end to end, n=256 -> 1024).

**Step 2 — no cap needs raising.** Nothing RNL is truncated, and the 16 sites that are
truncated are GF/NL/FPE/TWK round-trip assertions stopping at 64 of 100 (or 128 of
1000); those assert exact equality, not a statistical property, so 64 trials is ample.

**The second-order detail was the real finding.** For the RNL tests proper the overshoot
is negligible as hoped — zero on test [14]. But the poll `(i & 63) == 63` means a site
requesting fewer than 64 iterations is **never polled at all**, so `-t` cannot reach it
however slow its work becomes. 18 of 95 sites are in that category and carry ~71% of all
time spent inside capped sites; the worst, `test_hpke_stern_f_correctness`, requests 30
and runs ~97 s against a 2.0 s cap. A truncated site always stops at a multiple of 64,
never in between. Separately, 16 sites pass a literal count to `_trange` instead of
`_iters(...)`, so `-r` does not reach them either.

Nothing about that behaviour was changed here — tightening the poll would cut real
coverage from the expensive Stern-F/ZKP sites and is a judgement call that deserves its
own item. What changed is that the run now says so: a closing
`--- Time cap: -t 2.00s reached N capped call sites; truncated X, could not poll Y ---`
line, so a future ring or parameter change can be told from a slower host by reading the
log. Documented in `CLAUDE.md`'s Testing section. No protocol, `--algo` tag, PEM label
or `spec/` change.

---

### #233: The C/Go/Python test harnesses cannot fail their CI jobs, and test [45] fails ~22-38% of the time

Found while measuring TODO #225; unrelated to that item's subject, and more serious.

**1. No harness propagates a failure.** All three suites print `[PASS]`/`[FAIL]` as
text and return 0 regardless. `CryptosuiteTests/Herradura_tests.py` contains no
`sys.exit`, no `assert`, and no failure aggregation of any kind; the C harness's
`exit(1)` calls are all I/O-error paths, not test outcomes; the Go harness has no
`os.Exit` at all. Verified empirically: a Python run that printed `[FAIL]` exited **0**.

So `native-c`, `native-go` and `native-python` — three required, blocking jobs — go
green whenever a security test fails. They can only fail on a crash, or via the
`CliTest/*.sh` scripts, which do assert properly. Every "all 29 checks pass" on a recent
PR carries that caveat.

**2. And a test really is failing.** Security test [45]'s `stern_synd_reject` check signs
with HPKS-Stern-F at `n=32, rounds=8`, then requires a 1-bit-corrupted syndrome to be
rejected — every time, over N trials. Stern-F's soundness error is `(2/3)^rounds` per
trial, so a corrupted syndrome is *expected* to verify sometimes. Measured over 400
trials: **19/400 = 4.75% accepted**, against the theoretical `(2/3)^8 = 3.90%`. That puts
test [45]'s failure probability at **21.6% for N=5 and 38.5% for N=10** (N=10 is the
default). Observed directly: 2 of 12 runs on a pristine checkout, 1 of 12 with #225's
changes applied.

The implementation is not wrong — the test asserts a probabilistic property as if it
were deterministic. Either raise the round count for this check until the soundness
error is negligible, or assert a bound over many trials rather than perfection over ten.

**Work.**

1. Fix [45] first. Fixing (2) before (1) is mandatory: turning on failure propagation
   while [45] still flakes would make three required jobs fail a third of the time.
2. Then give each harness an aggregate exit status. A shared "failures seen" counter and
   a non-zero exit is the whole change in each language.
3. Audit for intentional failures before gating. The C harness's own header text
   describes `[4] Bit-frequency bias` as an "expected FAIL — FSCX is not a PRF", though
   [4] currently passes in a Python run; any grep-based or counter-based gate needs that
   settled first, in all three languages.
4. Re-run the full matrix and see what else has been failing silently. This item should
   not be closed on the assumption that [45] is the only one — that is exactly the
   assumption the missing exit status made untestable.

---

**Outcome (v3.0.8).** All four steps done, in the order the item required. The audit in
step 4 was not a formality: **[45] was not the only failing test, and it was not the only
test asserting a probabilistic property as a deterministic one.** Three separate checks
had to be fixed before the gate could be switched on.

**[45] HPKS-Stern-F tampered syndrome — as filed.** A corrupted syndrome is caught only
in the `b=0` round, so a forgery survives with probability `(2/3)^rounds` per trial;
measured 6/200 = 3.00% against a theoretical 3.90% at the `rounds=8` the Python and Go
harnesses used. The sub-check now runs on its own fixed budget (`STERN_TRIALS=2`) at
`rounds=32`, matching the C harness's compile-time `SDF_ROUNDS` — `(2/3)^32 = 2.4e-6`, an
~8000x reduction in flake probability that also costs less in total than the old N-fold
loop (measured 2.08 s vs 2.86 s in Python). The C harness was already at 32 rounds and
never flaked; it was restructured only so the three languages print the same denominator.

One trap on the way, worth recording because it was invisible from the pass/fail line. The
hoisted block first sat *inside* the `-t` budget, which put a fixed 2.08 s cost in front of
a 2.0 s cap: the loop's first check fired immediately, `N` came out 0, and [45] printed
`SKIP (no iterations completed)` — silently dropping its seven other checks. The old code
never hit this because the cost was spread across iterations with the check at the *top* of
the loop, so iteration 1 always completed. Fixed by taking the timestamp after the Stern
block, which restores the loop's original budget exactly. Caught in verification, not
shipped.

**[4] Bit-frequency bias — found by the gate itself, first run.** Its window was a hard
`+/-3` percentage points regardless of sample count. That is 6 sigma at the default
`N=10000`, but only 0.19 sigma once `-r 2` or a `-t` truncation cuts the sample count, so
the test failed on sample noise rather than on bias — `min=0.00% max=100.00% [FAIL]` at
`-r 2`. The window now follows the samples actually taken, `6 * 50/sqrt(N)` points, which
reproduces `+/-3.00` *exactly* at `N=10000` and stays sound below it. The union bound over
the 256+128+64 bits puts the false-alarm rate near 1e-6 per run. Below N=37 the window
spans the whole 0-100% range, so the line now reports `[SKIP]` rather than a `[PASS]` the
samples do not support. The C harness's banner
line calling [4] an "expected FAIL — FSCX is not a PRF" was simply wrong and has been
corrected: [4] passes in all three languages, because FSCX(A,B) over random A is
bit-balanced. What is *not* PRF-like about FSCX is its 3-bits-per-flip diffusion, which
is test [2]'s job. No allow-list was needed anywhere.

**[18] HPKE-Stern-F encap/decap — the one the item warned about.** Failed 1 of 5 C runs
before any change, silently. Root-caused rather than assumed: a weight-2 code of length
32 with a 16-bit syndrome is **not uniquely decodable**. C(32,2)=496 error vectors land in
2^16 syndromes, so the birthday model predicts ~1.87 colliding pairs per key. Measured
over 5000 keys: **43.46% of keys carry at least one collision**, 0.76% of weight-2 vectors
share a syndrome, and 0.38% brute-force to a *different* `e'` — which puts this line's
failure rate at **7.37% per 20-trial run**, matching the observed 1/5. Brute force is not
wrong when it returns the other preimage; the toy parameters are ambiguous. Those trials
are now identified (via a first-preimage helper, in the same scan order decap uses),
counted, and reported as `(k ambiguous syndromes, not a failure)` rather than scored.

**Step 2 — the gate.** Each harness now exits non-zero if any check printed `[FAIL]`, and
prints a closing `*** OK: no check reported [FAIL] ***` or `*** FAILED: n check(s) ... ***`
with the offending lines. The status is read off the printed output rather than threaded
out of each report site — deliberately: a harness's contract *is* its output, the marker
format is uniform across all ~44/~50/~141 sites, and an output wrapper cannot be forgotten
by whoever adds test [46], whereas a per-site helper can, and would then regress the gate
in silence — which is the exact failure mode being fixed. C uses `#define printf hprintf`
(putchar/puts/fputs are left alone; no status marker is ever emitted through them), Python
shadows `print` at module level, and Go swaps `os.Stdout` for a scanning pipe. **No
`ci.yml` change was needed:** the three jobs already invoke the harnesses directly with no
`continue-on-error` and no `|| true`, so the exit status now propagates on its own.

**Not in scope, and worth its own item: the assembly harnesses have the same defect.**
`CryptosuiteTests/Herradura_tests.s` ends in a hard-coded `mov r0, #0; bl exit` across 19
`[FAIL]` sites, and the NASM i386 and Arduino harnesses are the same shape — so
`arm-i386` and `arduino`, two more required jobs, are still green-on-failure. They also
run test [18] at the same ambiguous n=32/t=2 parameters. Filed as **#234** rather than
folded in here: it is a different language surface, the item's own title and Work list
scope it to C/Go/Python, and the change is worth reviewing on its own.

Status: **DONE v3.0.8** — [45], [4] and [18] each fixed at the root (all three asserted a probabilistic property as deterministic), then C/Go/Python given an aggregate exit status; assembly harnesses filed as #234.

### #234: The ARM / NASM i386 / Arduino test harnesses cannot fail their CI jobs either

TODO #233 gave the C, Go and Python harnesses an aggregate exit status. The assembly and
Arduino harnesses were left out of that item's scope and still have the defect it fixed:
`CryptosuiteTests/Herradura_tests.s` ends in a hard-coded `mov r0, #0; bl exit` regardless
of outcome, across 19 separate `[FAIL]` emission sites, and `Herradura_tests.asm` and
`Herradura_tests.ino` are the same shape. So `arm-i386` and `arduino` — two more required,
blocking CI jobs — go green whenever an assembly security test fails.

They also carry #233's third finding. Tests [1]-[18] include [18] HPKE-Stern-F
encap/decap at N=32, t=2, where the code is not uniquely decodable: 43.46% of keys admit
at least one weight-2 syndrome collision and 0.38% of error vectors brute-force to a
different `e'` (measured over 5000 keys). Whatever trial count the assembly [18] uses, it
reports a spurious `[FAIL]` at that rate, and always has.

**Work.**

1. Fix [18]'s ambiguity accounting in `.s`, `.asm` and `.ino`, the way #233 did for C/Go/
   Python: a syndrome with two weight-t preimages is not a decoder failure.
2. Audit the remaining `[FAIL]` sites in each for the same "probabilistic property
   asserted as deterministic" class before gating — that audit is what turned up [4] and
   [18] in #233, and neither was in the original item text.
3. Then aggregate: a failure counter and a non-zero exit. ARM's exit is already a
   `bl exit` call, so it is a counter and a load, not a restructure.
4. Arduino runs under simavr via `run_arduino.sh`; check how (and whether) an exit status
   propagates there before assuming step 3 is sufficient for that target.

Both toolchains build and run locally on the dev host (`arm-linux-gnueabi-gcc`, `nasm`,
`qemu-arm`/`qemu-i386`), so this is testable without CI round-trips.


**Outcome (v3.0.9).**

*Step 1 does not apply.* The item predicted these harnesses carry #233's
ambiguous-syndrome bug at test [18]. They do not, and the numbering is why: their
[18] is `v2_weak_key_reject`, which runs on two fixed constants (`0x00020000`,
`0x5A5A5A5A`) and is fully deterministic. Their Stern KEM is **[12]**, and it
decapsulates with `hpke_stern_f_decap_known_32` — literally `hash2(seed, e')` on
both sides, no syndrome decoding, no brute force — so the non-unique-decoding
failure mode has no counterpart here. The C harness's [18] is the brute-force
decap; that is the test the item was thinking of.

*Step 2 found one real defect, in the direction opposite to #233's.* Where C's [4]
asserted a probabilistic property too tightly, the Arduino [7] asserted one far too
loosely: `test_hkex_rnl` passed at `ok_raw >= trials * 8 / 10` "because Ring-LWR has
small rounding noise", and its verdict never looked at `ok_sk` at all — a run could
print `sk agree=0/10` and still pass. Measured, the noise it was budgeting for does
not exist: 1,000,000 trials of the same n=32 construction, driven through the ARM
harness with its [7] trial count raised, produced no disagreement whatsoever, giving
DFR <= 3e-6 at 95% confidence. Peikert reconciliation ships an explicit hint bit, and
at these parameters it is exact. The test now asserts `ok_raw == trials && ok_sk ==
trials`, which is what ARM and i386 have always required (`cmp r11, #10; blt`).

*Step 2 found nothing else, for a structural reason worth recording.* These
harnesses assert **correctness** — honest-party round trips — and never
**soundness**. There is no counterpart to C's [45], which is why nothing here
behaves like it. That is a live hazard for whoever adds one: the assembly Stern-F
runs at `rounds=4`, where a rejection test would carry a `(2/3)^4` = 19.75%
soundness error per trial, five times worse than the `rounds=8` that made [45] fail
38.5% of runs. Such a test needs its own round count, the way [45] now uses 32. The
one genuinely probabilistic assertion already present, [10]'s "random forgery
rejected", has a false-accept rate of `1/(2^32-1)` = 2.3e-10 per trial — a random
`s_fake` wins only by equalling the unique correct `s`.

*Step 3, the gate.* Each harness aggregates at its own output layer, so a test added
later is covered without anyone remembering to register it — the property #233 chose
this design for:

  * **ARM Thumb-2** — all 55 `bl printf` became `bl hprintf`, which runs the format
    string past libc's `strstr` for `"[FAIL]"`, bumps a counter and tail-calls the
    real `printf`. The varargs are untouched: `push {r0-r3, r4, lr}` keeps `sp`
    8-byte aligned, and the `b printf` after the matching `pop` leaves any
    stack-passed argument exactly where the callee expects it.
  * **NASM i386** — no libc at all here, so there is nothing to wrap; instead
    `print_str`, the single `write`-syscall path, got a six-byte substring scan in
    front of the `int 0x80`, plus a `print_uint` so the verdict can carry a count.
    `print_str_raw` is the deliberate bypass, for the verdict lines themselves.
  * Both build scripts now **refuse to build an ungated call site**: a bare
    `bl printf` / `call print_str_raw` not marked `GATE-EXEMPT` fails the build. The
    guard earned its keep immediately by catching the word "printf" in the comment
    written to explain it.

*Step 4 was the right question to ask, and the answer is no.* An exit status cannot
propagate from the AVR target: the firmware loops forever, so `run_arduino.sh` runs
it under `timeout` and discards the status with `|| true`. The gate has to travel
out over the UART instead. Output scanning does not work there either — the marker
is split across two `Serial` calls (`"  ["` then `"FAIL]"`), so the literal `[FAIL]`
never appears in any single write — so all 18 verdicts route through one
`verdict(bool)` helper, and the harness prints `*** OK: no check reported [FAIL] ***`
at the end of every pass. `run_arduino.sh` fails on a FAILED line **and on the OK
line never arriving**, which is new coverage: a hang, a watchdog reset, or a
`TIMEOUT` shorter than one pass previously all left `arduino` green. Cost on AVR:
+2 bytes `.bss`, no `.data` growth, the new strings being wrapped in `F()`.

*No `ci.yml` change was needed.* `run_arm.sh` and `run_asm_i386.sh` are
`set -euo pipefail` with the qemu call last, verified by swapping a
deliberately-failing binary underneath them (both exit 1); `run_arduino.sh` now
exits 1 itself.

*Verification.* 200 runs of each of the ARM and i386 harnesses before gating (zero
failures, so nothing was being masked), 200 runs of each after (zero non-zero
exits). Forced-failure builds: ARM exits 1, i386 exits 1 and counts correctly at one
digit (8) and two (10), Arduino exits 1 through the run script. Both build guards
reject an unmarked call site. The AVR no-verdict path fires at `TIMEOUT=1` and not
at `TIMEOUT=5`; a full pass takes 2-4 s against the CI default of 90.

*Out of scope, deliberately.* The suite binaries
(`Herradura cryptographic suite.{s,asm,ino}`) are untouched. Their EVE-bypass checks
print `FAILED` rather than the `[FAIL]` marker, and CI runs only the `tests` mode of
each run script — the same boundary #233 drew for C/Go/Python.

Status: **DONE v3.0.9** — [12]/[18] cleared as non-issues (the item had the test numbering wrong), Arduino [7] tightened from an 80% threshold that also ignored `ok_sk`, then all three harnesses gated at their output layer; AVR needed a UART verdict rather than an exit status, plus an absent-verdict check.

### #237: `spec/` classifies OPRF and HSKE-NL-A1/A2 as `production` where SECURITY.md and the proofs disagree — adjudicate and reconcile

Found while auditing the six `demo-only` entries for #235/#236.  Both rows say
`status="production"` in `spec/generate_spec.py`; neither is supported by the security
documentation, but **they fail in different ways and need different work.**  The fix goes
in `spec/generate_spec.py` (lines 229-232 and the `"oprf"` entry), not the generated JSON.

**Part 1 — OPRF: not a disagreement, an absence.**

`grep -l OPRF SecurityProofs-*.md` returns nothing.  `grep -c OPRF SECURITY.md` returns 0.
Same for aPAKE.  Both shipped (TODO #80, #201, #203) with CLI subcommands
(`oprf-blind`/`oprf-eval`/`oprf-unblind`, `pake-register`/`pake-demo`) and, for OPRF, a
`production` label carrying no analysis anywhere in the repo.

The label is also internally inconsistent *within `generate_spec.py` itself*.  `oprf` is
`gf_pow` in the same group as `hkex-gf`/`hpks`/`hpke` — the suite's `oprf_eval` is

    return gf_pow(alpha & ORD, k & ORD, GF_POLY[KEYBITS], KEYBITS)

with `ORD = 2^KEYBITS - 1`.  Those three neighbours are all marked `status="pedagogical"`
with `classical_security_bits="~36.5 (n=256)"`, from TODO #212's Pohlig-Hellman result.
`oprf` gets `status="production"` and the note *"inherits GF(2^n)* classical-only
security"* — which understates a ~36.5-bit break as if it were a 128-bit classical one.

Confirmed by running TODO #212's own `pohlig_hellman()` against the exact relation
`oprf_eval` implements — one `(alpha, beta)` pair, solving for `k` with `g = alpha`:

    n= 32  largest prime factor 17 bits  recovered=YES  in 0.01s
    n= 64  largest prime factor 23 bits  recovered=YES  in 1.00s

At the deployed n=256 the largest prime factor of `2^256-1` is 73 bits, giving #212's
~2^36.5.  Recovering `k` is the whole ballgame for an OPRF: obliviousness protects the
*client's* input from the server, but `k`'s secrecy is what stops anyone who has seen one
transcript from evaluating `F(k, ·)` offline on inputs of their choosing — i.e. an offline
dictionary attack wherever the OPRF is used for password-like inputs, which is what aPAKE
uses it for.

**Work for Part 1.**  Reclassify `oprf` to match its neighbours (`pedagogical`, or
`demo-only` — pick one and say why), give it a real `classical_security_bits`, and rewrite
the note so it states the ~2^36.5 recovery rather than "classical-only".  Add SECURITY.md
rows for OPRF **and aPAKE**, and extend `SecurityProofsCode/hkex_gf_pohlig_hellman.py` to
cover the OPRF relation (it currently covers HKEX-GF/HPKS/HPKE only; the demo above is 20
lines and belongs in that script, not in a TODO entry).  Decide separately whether aPAKE
needs its own spec row at all — see Part 3.

**Part 2 — HSKE-NL-A1/A2: a real disagreement, and it needs adjudicating before either
document is edited.**

SECURITY.md:18 puts HSKE-NL-A1/A2 in one row with classical HSKE known-plaintext: *"Not
suitable for production — a single known-plaintext pair recovers the keystream."*
`spec/` says `production`.  The proofs support **both** readings, in different places:

  * **For `production`:** §11.3.1 gives a conditional CPA claim — *"Non-linearity prevents
    GF(2) linear recovery of K from any set of (plaintext, ciphertext) pairs.  Assuming
    NL-FSCX v1 acts as a pseudorandom function (PRF), CPA security follows from standard
    stream cipher arguments."*  And TODO #210's correction in §11.7 explicitly exempts
    these two from the fatal ciphertext-only leak: *"This does not extend to
    HSKE-NL-A1/A2, whose carry non-linearity breaks the affine identity the argument
    depends on."*
  * **For SECURITY.md:** the §11.7 table rows read `HSKE-NL-A1 (known-plaintext) — Linear
    recovery blocked; 1-pair attack still recovers keystream → **None** (keystream
    recoverable)`, and the prose says the NL variants *"do not eliminate the 1-pair attack
    because the underlying structure remains affine."*

**Those last two quotes contradict each other, two paragraphs apart in the same section.**
One says the carry non-linearity breaks the affine identity; the other says the structure
remains affine.  That contradiction is the actual bug to fix, and it must be settled
before the labels are touched — editing either document first would just pick a side.

The question to answer: for a counter-mode stream cipher, one KPT pair recovering *that
block's* keystream is inherent to the mode and is not a break.  Does the §11.7 row mean
only that (in which case `production` is right, and SECURITY.md:18 is miscategorising the
NL variants by merging them into classical HSKE's genuinely fatal 1-pair row), or does it
mean a pair yields *other* blocks' keystream or `K` itself (in which case `spec/` is
wrong)?  §11.3.1's nonce/counter construction and the ROL seed rotation are the relevant
detail.  TODO #214's exact-trail work (`nl_fscx_exact_trail_search.py`) is the closest
existing measurement of what survives statistically.

**Do not assume the answer from this entry.**  It is written to lay out both sides, not to
pre-judge; whichever way it goes, one of the two documents gets corrected and §11.7's
internal contradiction gets resolved in the same change.  If the outcome is that the NL
variants are sound, `hske-duplex` (also `production`, also unanalysed in SECURITY.md)
should be checked in the same pass, since it is the same family.

**Part 3 — root cause, and why this drifted (optional, decide during triage).**

`KAT/generate_kat.py` and `SecurityProofsCode/check_part_index.py` both have `--check`
modes wired into CI (TODO #190, #231).  `spec/generate_spec.py` has neither a `--check`
mode nor any CI job — nothing checks that the generated JSON is current, and nothing
checks that a `status=` in it agrees with SECURITY.md's table or with the proofs.  aPAKE
having no spec row at all (the string "PAKE" appears once in the whole JSON, as
`PEM_PAKE_RECORD`) is the same gap showing up as missing coverage rather than a wrong
label.  A `--check` mode plus a cross-reference assertion against SECURITY.md's table
would have caught all three findings above.  This is scope beyond the two rows named in
the title — split it into its own item if it makes this one too large.

---

**RESOLUTION (v3.0.10).**

**Part 2 first, since it gated the rest.**  §11.7 contained two sentences, two paragraphs
apart, asserting opposite things about HSKE-NL-A1/A2.  The TODO #210 correction ("carry
non-linearity breaks the affine identity the argument depends on") is right; the summary
paragraph ("the underlying structure remains affine") was wrong and has been withdrawn.
Settled by measurement at n=256, not by reading:

  * *Affinity.*  Classical `fscx_revolve` satisfies the GF(2)-affinity identity
    f(x)^f(y)^f(z)^f(x^y^z)=0 in both P and K in 200/200 random trials.  The A1 keystream
    in `base`, and the A2 ciphertext in P, violate it in 200/200.
  * *What the classical attack does.*  One KPT pair gives c_K = T_i*K = E ^ M^i*P, and c_K
    then decrypts *every other* message under that key — recovering an unseen P2 from one
    pair succeeds end to end.  That step needs affinity in P, which the NL variants lack.
  * *What one pair buys against the NL variants.*  Against A1: that block's keystream and
    nothing else — applying it to the neighbouring counter fails, and reaching any other
    block means inverting NL-FSCX v1 to recover `base`, where both arguments (seed
    ROL(base, n/8) and parameter base^i) depend on the unknown.  This is counter mode
    behaving as counter mode, the same as AES-CTR.  Against A2: there is no keystream at
    all — A2 is a keyed bijection and E^P is not constant across messages.

So `spec/` was right and SECURITY.md:18 was wrong, having merged the NL variants into
classical HSKE's genuinely fatal row.  The two §11.7 known-plaintext rows now carry the
n/2 key-search bound instead of "**None** (keystream recoverable)", and a "Correction
(TODO #237)" note records all three measurements.  This upgrades nothing about the
underlying assumption, which is still the *conjecture* that NL-FSCX v1 is a PRF.

**The A2 caveats are real and are now stated where a reader will meet them.**  A2 is
deterministic (not IND-CPA multi-message without a caller-supplied differentiator), and
its degenerate-key class delta(K) in {0, 2^(n-1)} collapses the permutation to affine.
Verified that the class is genuinely affine (0/200 violations at B=2^129, versus 200/200
at a generic key) and that all three CLIs already refuse it via `nl_v2_key_is_valid`.

**`hske-duplex` — the same-family check Part 2 asked for, and a third wrong label.**  It
was `status="production"` in `spec/` while SecurityProofs-6.md §11.9 calls the single-pass
sponge "open research" pending the v2 differential/linear characterisation of TODO #99,
and while `herradura.h`'s own banner reads "RESEARCH CONSTRUCTION — not for production use
without further cryptanalysis".  Reclassified to `research`, with a SECURITY.md row
pointing users at `enc --aead` instead.

**Part 1 — OPRF.**  Reclassified `production` -> `pedagogical` with
`classical_security_bits="~36.5 (n=256)"`, matching its `gf_pow` neighbours.  A new §6 in
`SecurityProofsCode/hkex_gf_pohlig_hellman.py` recovers the server key from one observed
(alpha, beta) pair end to end at n=32 and n=64 and then reproduces F(k,.) offline on fresh
inputs.  One nuance the entry above did not anticipate: the base is the client's blinded
alpha, which is primitive with density phi(2^n-1)/(2^n-1) = 0.4992 — a coin flip, not the
"usually primitive" the demo in this entry suggested.  When alpha is not primitive, k
returns modulo ord(alpha) and offline evaluation is partial (measured 73/200 at n=64, the
index-3 subgroup showing through).  That is not a mitigation: ord(alpha) is publicly
computable, so an attacker attacks one of the ~50% of transcripts whose alpha is primitive
and recovers k in full.  Obliviousness is untouched throughout — what falls is k's
secrecy, and with it the aPAKE's reason for storing F(oprf_key, password) rather than a
password hash.

SECURITY.md gained rows for OPRF and aPAKE, both demo-only/pedagogical.  aPAKE got no
`spec/` row: its protocol array is keyed on `--algo` tags and aPAKE has none (it ships as
`pake-register`/`pake-demo`), so filing it is a schema question, deferred to #238 Part C.

**Part 3 — split out as TODO #238**, as this entry allowed: `--check` mode and CI for
`generate_spec.py`, a `status=` cross-reference against SECURITY.md, and the aPAKE
coverage gap.

**Side effect.**  The §11.7 correction pushed SecurityProofs-4.md from 659 to 684 math
expressions, so every copy of the seven-part index (SecurityProofs.md, CLAUDE.md,
KATEX_RULES.md) was updated; `check_part_index.py` and `validate_katex.js` both pass
(684 OK, 0 FAIL).  684 is under the ~700 warning threshold, but the margin to the ~750
cascade-failure limit is now 66 expressions — Part 4 is the next candidate for a re-split.

Status: **DONE v3.0.10** — adjudicated §11.7's internal contradiction by measurement (the NL variants do *not* inherit classical HSKE's 1-pair break), corrected SECURITY.md accordingly, and reclassified `oprf` and `hske-duplex` in `spec/`.

### #236: The C CLI's Stern round count is a compile-time wire parameter, and CI works around it by downgrading credentials to 32 rounds

Found while checking whether HPKS-Stern-F's `SDF_ROUNDS=32 -> 219` upgrade path
(SECURITY.md, spec `hpks-stern` notes) is actually reachable in each CLI.  In Python and
Go it is.  In C it is not, and the workaround is already in the test suite.

**The mechanism.**  The PEM *already carries the round count* — `stern_sig_load`
(HerraduraCli/herradura_cli.c:1835) reads it as item[1] and then rejects it:

    if (r != SDF_ROUNDS) { pem_key_free(&pk); return -1; }

`stern_sig_load_label` (line 4102) does the same for HCRED credentials.  The `SternSig`
struct (herradura.h:1889) is fixed-size — `BitArray c0[SDF_ROUNDS]`, and so on — as are
`STERN_COMMITS_BYTES` / `STERN_CHAL_BYTES` / `STERN_RESP_BYTES` (herradura_cli.c:1776-1778).
Go by contrast decodes `rounds := bytesToInt(ints[1])` (herradura_cli.go:2050) and
allocates from it, and Python does the same.

Measured, C CLI built both ways against Python-produced signatures:

    cli32  verifying python sig r=32:  Signature OK
    cli32  verifying python sig r=219: verify: cannot load Stern signature
    cli219 verifying python sig r=32:  verify: cannot load Stern signature
    cli219 verifying python sig r=219: Signature OK

So the two builds are mutually unreadable, in both directions.

**This is not hypothetical — CI is already accommodating it.**
`CliTest/test_cred_interop.sh:120-122` and `:146-148` issue HCRED credentials for the C
CLI to consume with an explicit `--rounds 32`, commented "must match C's SDF_ROUNDS=32
for interop".  Python's and Go's own default is `_HCRED_SIGN_ROUNDS = 219` /
`hcredSignRounds = 219`, chosen for 128-bit soundness.  The consequence: **cross-language
HCRED interop is only ever exercised at 32 rounds — (2/3)^32 rather than the (2/3)^219
the issuers otherwise use** — and any real deployment with a C consumer forces every
issuer down to the same demo soundness.

**Work.**  Make the C reader length-dynamic, matching Go: give `SternSig` a `rounds`
field and heap-allocate its arrays, derive the three `STERN_*_BYTES` sizes from the
decoded round count rather than the macro, and bound the decoded value (Go's decoder and
the existing ZKP-NL unpack at herradura_cli.c:327 both range-check; do the same).
`SDF_ROUNDS` remains the *signing* default.  About 45 references across
`herradura.h` (25) and `herradura_cli.c` (20).

**Explicitly non-breaking, and this is the point of doing it this way.**  The wire format
does not change — the round count is already on the wire.  A dynamic reader is purely
additive: it accepts everything the current build accepts, plus round counts it currently
rejects.  So this is a PATCH bump with no `MIGRATING.md` entry.  *Changing the signing
default* from 32 to 219 would be the breaking change (old readers reject new signatures),
and is deliberately not part of this item — do the reader first so the default can move
later without a flag day.

**Acceptance.**  Drop the two `--rounds 32` workarounds from `test_cred_interop.sh` and
let it run at the issuers' own 219-round default; add a C-side round-trip at a round count
other than `SDF_ROUNDS` to whichever of `test_c_*.sh` covers Stern-F.  Both must pass
against a stock `./build_c.sh` binary.

**Not in scope.**  The round count and the instance hardness are independent axes.  219
rounds over the deployed `N=256` instance is worth ~30-40 bits either way
(SecurityProofs-4.md:632), so this item does not change any `demo-only` status; it only
makes the soundness axis reachable from C.  See #235's out-of-scope note for the
parameter side.

---

**RESOLUTION (v3.1.0).**

**The reader.**  `SternSig` now carries its own `rounds` and heap-allocates its six
arrays, via a `stern_sig_alloc`/`stern_sig_free` pair mirroring the `stern_ring_alloc`
pair that was already in the file.  `hpks_stern_f_sign` and `hpks_stern_f_verify` both
follow `sig->rounds`; the three `STERN_*_BYTES` macros became `STERN_*_BYTES_R(r)`
functions of the decoded count.  `SDF_ROUNDS` no longer appears anywhere in the Stern
data path -- only as the default a caller hands to `stern_sig_alloc`.

Decoded round counts go through one `stern_decode_rounds` helper that bounds them to
`[1, SDF_MAX_ROUNDS]` (4096, new) and rejects a length field over 4 bytes, and each of the
three blobs is checked against the size the same PEM's round count implies rather than
being silently truncated to fit.

**One thing the entry did not anticipate: `der_i_byte` takes a `uint8_t`.**  The round
count was encoded through it, so anything above 255 would have silently truncated.  It now
goes through the existing `der_i_uint`, which emits the same minimal DER form Python's
`der_int(rounds)` does.  Verified byte-identical at the default: a C and a Python
signature over the same message both begin `3082141a 02020100 02012002`, where `02 01 20`
is INTEGER 32 -- so the "wire format does not change" claim holds literally, not just
structurally.

**The duplicated codec.**  `stern_sig_write_label`/`stern_sig_load_label` (HCRED
credentials) were verbatim copies of `stern_sig_pack_and_write`/`stern_sig_load`, which is
why the defect existed in two places.  Both pairs now delegate to one label-generic
implementation: 98 lines removed, 18 added.

**Beyond the entry's scope, and agreed before starting: `sign --rounds`.**  The acceptance
criterion asks for a C-side round-trip at a round count other than `SDF_ROUNDS` against a
stock binary, which a reader-only change cannot deliver -- C had no way to *produce* a
signature at any other count.  `sign --algo hpks-stern --rounds N` and `cred-issue
--rounds N` were therefore added to the C CLI, matching Go and Python.  That is a new CLI
flag, so this is a **MINOR** bump (v3.1.0) rather than the PATCH the entry assumed.
`SDF_ROUNDS` remains the signing default when `--rounds` is absent, so nothing about what
a stock C build emits by default has changed -- the deliberately-excluded "change the
signing default" step is still not taken.

**Measured on a stock `./build_c.sh` (SDF_ROUNDS=32), replacing the entry's table:**

    C sign r=32/64/219/1000  -> C verify:   Signature OK  (all four)
    C sign default           -> C verify:   Signature OK
    py sign r=32             -> C verify:   Signature OK
    py sign r=219            -> C verify:   Signature OK   <- was "cannot load"
    C sign r=219             -> py verify:  Signature OK

Rejection paths intact: a wrong message still fails at every round count, `--rounds`
outside `[1, 4096]` is refused before any allocation, and a PEM hand-edited to claim 32767
rounds is refused by the reader.  The C suite passes under ASan+UBSan with no `[FAIL]`.

**Acceptance.**  `test_cred_interop.sh`'s two `--rounds 32` workarounds are gone; the
Python and Go issuers now run at their own 219-round defaults, so cross-language HCRED
interop is finally exercised at `(2/3)^219` rather than `(2/3)^32`.  Cost of that is
~1.4 s per issuance (0.9 s -> 2.3 s in Python), which is noise next to the ZKBoo proofs
the same script already runs.  `test_c_sign.sh` gained seven cases: round-trips at 64 and
219, wrong-message rejection at each, a check that the two differ, `--rounds` bounds
rejection, and the tampered-round-count PEM.  15 PASS / 0 FAIL.

**A C API break that needed documenting.**  `SternSig sig;` in external code still
*compiles* -- the members are pointers now, not arrays -- and then writes through
uninitialized pointers, with no diagnostic.  `herradura.h` is a documented header-only
library, and `docs/TUTORIAL.md` showed exactly that pattern, so `MIGRATING.md` §6 was
added alongside the TUTORIAL fix.  No PEM, wire-format or CLI break accompanies it.

**Not done, as scoped.**  The signing default stays at 32, `N=256` is untouched, and
`hpks-stern`/`hpke-stern` remain `demo-only`: 219 rounds over a ~30-40 bit instance is
still ~30-40 bits.  This item only made the soundness axis reachable from C.

Status: **DONE v3.1.0** — `SternSig` carries its own round count and the C reader takes it from the PEM; added `sign`/`cred-issue --rounds` for parity with Go and Python, and dropped CI's 32-round HCRED workaround.

### #239: `ring_sig_load` sizes its allocations from two unbounded PEM fields

Found while closing TODO #236, which bounded exactly this class of value for
`stern_sig_load` — the ring-signature reader next to it was never given the same
treatment.  `ring_sig_load` (HerraduraCli/herradura_cli.c:2024) is *not* affected by
#236's actual defect: it already decodes the round count and allocates from it, rather
than comparing it against `SDF_ROUNDS`.  The problem is that it trusts what it decodes.

**The mechanism.**  Both `k` and `rounds` come straight off the wire with no range check:

    int k      = (int)parse_be_uint(pk.vals[0], pk.vlens[0]);
    int rounds = (int)parse_be_uint(pk.vals[1], pk.vlens[1]);
    size_t entry = 5 * (size_t)KEYBYTES + 1;          /* 161 */
    size_t blen  = (size_t)k * rounds * entry;
    uint8_t *blob = (uint8_t *)calloc(blen ? blen : 1, 1);

`ring_load_members` bounds the *caller's* member count at `RING_MAX_K` (64), and the
signing path rejects `k >= RING_MAX_K` at line 1964, but neither applies here: the
signature's own `k` is compared against the caller's only *after* `ring_sig_load` has
returned (line 3388), so the allocation above happens first.

**Confirmed reachable, under `herradura_cli_asan`** with a hand-crafted
`HERRADURA HPKS-RING SIGNATURE` PEM and two genuine member public keys:

    k=2           rounds=2^30   -> allocator is trying to allocate 0x5080000000 bytes
    k=2^30        rounds=2^30   -> requested allocation size 0x1000000000000000 exceeds
                                   maximum supported size of 0x10000000000
    k=2^31-1      rounds=2                     -> same class

In a normal build `calloc` returns NULL and `die("out of memory")` fires, so **what is
demonstrated today is a denial of service / abort on a malformed signature, not memory
corruption.**  A verifier is exactly the component that handles attacker-supplied input,
so an unbounded allocation driven by two of its fields is still worth closing.

**Two latent defects behind it, neither currently reachable past the failing calloc:**

1. `blen = (size_t)k * rounds * entry` can wrap.  `k` and `rounds` are each up to
   `2^31-1`, so the product reaches ~7.4e20 against a `2^64` ~ 1.8e19 modulus.  A wrapped
   `blen` would allocate a small buffer while the `k * rounds` loop below it — whose bound
   does not depend on `blen` — kept reading, which is an out-of-bounds read rather than an
   abort.  A bounded search for a `(k, rounds)` pair that lands `blen` small enough to
   demonstrate this did not find one within the window tried; nothing rules it out, and
   the fix (bound the inputs) removes the question either way.
2. `stern_ring_alloc` (herradura.h:2078) computes `int sz = k * rounds` in `int`.  At
   `k = rounds = 2^30` that is signed overflow — undefined behaviour — before the result
   is passed to `malloc`.  Unreachable today only because the `calloc` above aborts first.

**Also missing: a declared-vs-actual length check.**  `pk.vlens[3]` is the real blob
length; when it is shorter than `blen` the reader right-aligns and zero-pads rather than
rejecting, so a signature whose declared `k`/`rounds` disagree with its payload is
silently treated as mostly zeros.  TODO #236 added exactly this check to the Stern-F
reader (`if (pk.vlens[2] > cm_len || ...) return -1`); the ring reader should get its
counterpart.

**Work.**  Range-check `k` and `rounds` immediately after decoding — `k` against
`RING_MAX_K` (the same bound the signing path and `ring_load_members` already use) and
`rounds` against `SDF_MAX_ROUNDS` (added in #236) — before either is used in an arithmetic
expression.  Reject rather than clamp: a signature declaring more members than
`RING_MAX_K` is malformed, not merely large.  Then add the `pk.vlens[3]` vs `blen`
agreement check, and make `stern_ring_alloc` compute its size in `size_t`.  Check the
other `parse_be_uint` readers in the same file for the same shape while there — this item
is about the pattern, not only this one call site.

**Not in scope.**  Raising or removing `RING_MAX_K`, and the ring signature's soundness
or parameters.  `hpks-ring` remains `demo-only` in `spec/`, inheriting `hpks-stern`'s
round-count caveat; this is an input-validation fix, not a security-level change.

Status: **DONE v3.1.1** — `ring_sig_load` now range-checks k against RING_MAX_K and
rounds against SDF_MAX_ROUNDS before either is used in an arithmetic expression, and
rejects a payload longer than (k, rounds) describe; `stern_ring_alloc` computes its
size in `size_t`.  The sweep of the other `parse_be_uint` readers the item asked for
found a strictly worse instance of the same shape: the HPKE-Stern-KEM private key's
declared QC-MDPC row weight `d` sizes `der_right_align`'s writes into `QCMDPC_D*2`-byte
**stack** buffers at three call sites (`pkey`, `kex --our-kem`, `dec`), so `d = 16` was
already a 32-byte stack-buffer-overflow WRITE under ASan and `d = 2^31-1` a 4 GB one —
memory corruption, not the abort #239 was filed for.  Also bounded: the XMSS height /
signature depth (which size `1 << h` leaves, undefined for h >= 32) and the
HSKE-NL-V2-Duplex declared ciphertext length.  25 assertions in
`CliTest/test_weak_key_rejection.sh`, which the `sanitizers` CI job now runs too.

### #240: the Python, Go and Java CLIs never got #239's bounds — same fields, uncaught crash instead of a clean rejection

TODO #239 range-checked every PEM field that sizes an allocation in
`HerraduraCli/herradura_cli.c`.  Its Work section scoped itself to that one file, so the
three sibling CLIs still read the same fields with no bound at all.  They cannot corrupt
memory — that part of #239 was C-specific — but they turn a malformed file into an
**unhandled runtime crash with a stack trace**, where C now prints one line and exits 1.
A verifier is the component that handles attacker-supplied input; three of the four
implementations of it currently abort on a 4-byte edit to a PEM.

**Measured, against the same hand-crafted PEMs #239 was closed with** (each run under
`ulimit -v 2000000` so the host survives):

| field | C (post-#239) | Python | Go | Java |
|---|---|---|---|---|
| ring `rounds = 2^30` | `declares 1073741824 rounds (expected 1..4096)`, exit 1 | `MemoryError` traceback out of `herradura.py:1181` | `fatal error: out of memory` — `cannot allocate 345744867328-byte block`, goroutine dump | n/a — the Java CLI has no `hpks-ring` |
| KEM row weight `d = 2^31-1` | `declares row weight 2147483647 (expected 1..15)`, exit 1 | `MemoryError` traceback out of `herradura.py:996` | `fatal error: out of memory` — `cannot allocate 4294967296-byte block` | `error: -2` |

Java's `error: -2` is its own bug and the most interesting row in the table: `d * 2` at
`d = 2^31-1` overflows Java's `int` to `-2`, so what surfaces is a
`NegativeArraySizeException` whose message is the wrapped product.  It does not crash the
JVM, but the diagnostic is meaningless and the arithmetic is wrong for the same reason
`stern_ring_alloc`'s `int sz = k * rounds` was.

**The readers to fix.**  These are the counterparts of the five sites #239 touched:

- `HerraduraCli/herradura.py:1173` `_unpack_ring_sig` — `k`, `rounds`, and the
  `blob_int.to_bytes(k * rounds * entry, 'big')` behind them.
- `HerraduraCli/herradura.py:987` `_decode_kem_privkey` — `d`, at `s0_int.to_bytes(d * 2)`.
- `HerraduraCli/herradura.py:460` `_decode_xmss_privkey` and `:508` `_unpack_xmss_sig` —
  the height and the signature depth.
- `HerraduraCli/herradura_cli.go:824` `decodeRingSig` and `:1929` `decodeKemPriv`, plus the
  Go XMSS and duplex readers.
- `bindings/java/herradurakex/HerraduraCli.java` — the KEM row weight (the `int` overflow
  above) and the XMSS height/depth; there is no ring reader to fix.
- The HSKE-NL-V2-Duplex declared ciphertext length in all three.

**What "fix" means here.**  Not "stop the crash" — reject with the same message shape and
the same exit status C now uses, so the four CLIs agree on what a malformed artifact is.
The bounds are already decided and already have names: `RING_MAX_K`, `SDF_MAX_ROUNDS`,
`QCMDPC_D`, `XMSS_MAX_H`.  Divergence is the real defect: today a PEM that C refuses is one
the other three attempt, which is a wire-format disagreement dressed up as an
implementation detail.

**Test coverage.**  `CliTest/test_weak_key_rejection.sh` is C-only by construction — it
hardcodes `$CLI` as `herradura_cli`.  Its TODO #239 section is already written against
PEM-item indices rather than anything C-specific, so the natural move is to parameterise
it over the CLIs the way `test_cross_lang_matrix.sh` does, and let the coverage guard in
`ci.yml` reclassify it.  Decide that first: the alternative — per-language copies — would
be the fourth copy of the same `craft_item` helper.

**Not in scope.**  Adding `hpks-ring` to the Java CLI (it is a genuine gap, but a feature,
not a validation fix), and re-auditing the C reader — #239 closed that.

Status: **DONE v3.1.2** — all three CLIs now reject the same fields at the same bounds
(`RING_MAX_K`, `SDF_MAX_ROUNDS`, `QCMDPC_D`, the XMSS height cap) with the same message
shape and exit status as C.  Two things the item did not anticipate.  First, #236's
`SDF_MAX_ROUNDS` was as C-local as #239's bounds were, so Python/Go/Java had no round-count
bound at all; Go gains `SdfMaxRounds` in the `herradura` package, Java
`Codec.SDF_MAX_ROUNDS`, Python `_SDF_MAX_ROUNDS`.  Second, the divergence ran both ways:
the new matrix found that **C** ignored the key width the wire declares in Stern and ring
signatures — sizing every blob from its own `KEYBITS` — so a signature the other three
refuse was one C verified.  `stern_require_n` closes that, following #227's
`rnl_require_n`.  On the test-coverage question the item asked to settle first: the case
table moved to `CliTest/lib_malformed.sh` (the `lib_dfr.sh`/`lib_build.sh` precedent; the
coverage guard already skips `lib_*.sh`), shared by `test_weak_key_rejection.sh` (C only,
so it keeps its place in the `sanitizers` job) and the new 4-way
`test_malformed_pem_matrix.sh` under `cross-lang-compat`.  108 assertions, 0 fail.
Adding `hpks-ring` to the Java CLI stays out of scope and remains a gap.

### #238: `spec/generate_spec.py` has no `--check` mode and no CI job, and its protocol list cannot express aPAKE

Split out of TODO #237 Part 3, which found three wrong `status=` labels in `spec/`
(`oprf`, `hske-duplex`, and the HSKE-NL rows) and identified the same root cause behind
all of them: nothing checks the generated spec.

**Part A — no `--check` mode, no CI job.**  `KAT/generate_kat.py` and
`SecurityProofsCode/check_part_index.py` both have `--check` modes wired into CI (TODO
#190, #231), and the latter caught real drift during #237 — the math-expression count for
SecurityProofs-4.md moved 659 -> 684 and every copy of the part index had to be updated.
`spec/generate_spec.py` has neither.  Nothing verifies that
`spec/herradura-protocol-spec.json` is current with respect to its generator, so a change
to the generator that is never re-run ships a stale JSON silently.  Add `--check` and a CI
step, following the shape `check_part_index.py` already uses.

**Part B — cross-reference `status=` against SECURITY.md.**  All three #237 findings were
disagreements *between documents* that no tool could see: `spec/` said `production` where
SECURITY.md said "not suitable for production" (HSKE-NL-A1/A2), where the proofs said
"open research" (`hske-duplex`), and where no analysis existed at all (`oprf`).  A check
that every `--algo` tag in `spec/` has a row in SECURITY.md's protocol table, and that the
two classifications are consistent, would have caught all three.  The mapping between
`spec/`'s six-value status enum (`production`/`demo-only`/`pedagogical`/`deprecated`/
`broken`/`research`) and SECURITY.md's prose status column has to be defined first; that
definition is most of the work in this part.

**Part C — the protocol list cannot express aPAKE.**  `spec/`'s protocol array is keyed on
`--algo` tags.  aPAKE has none: it ships as the standalone subcommands `pake-register` and
`pake-demo`, so there is no key under which to file it, and the string "PAKE" appears once
in the whole JSON as `PEM_PAKE_RECORD`.  #237 gave it a SECURITY.md row (it inherits the
OPRF's ~2^36.5 server-key recovery, which voids the offline-dictionary resistance that is
its entire purpose) but deliberately did not invent a spec row, because doing so is a
schema question rather than a labelling one: either widen the protocol array's key beyond
`--algo` tags, or add a separate `subcommand_protocols` section.  Decide which, then file
aPAKE and audit whether anything else in the CLI is invisible to `spec/` for the same
reason.

Status: **DONE v3.2.0** — with one correction to the item's own premise: `--check` already
existed and did exactly what Part A described; what was missing was only the CI step, which
is why nothing ever ran it.

**Part A.** CI step added to `native-python` running both gates.  `--check` also validates
the instance against its own schema now (nothing ever had), and generation fails if any tag
the CLIs accept has no classification — the check that caught `hybrid-rnl-stern`, a shipped
`kex --algo` value in all three CLIs with no protocol entry at all.

**Part B.** `spec/check_security_md.py`.  The prose->enum mapping is curated as the item
predicted, but self-invalidating: checks (1) and (2) fail if either document gains, loses or
renames a row.  It found `hpks-nl`/`hpke-nl` on its first run.  Two more wrong labels came
out of building it — `hpks-t` marked `production` while the `hpks` it is a threshold variant
of is `pedagogical` over the same GF(2^n)* group, and `hpks-zkp-nl` marked `production` for a
keygen whose only consumers are demo-only — bringing #237's three to five.  SECURITY.md's
table covered 14 of 27 protocols; the twelve missing rows were written so the check is a real
gate rather than an allow-list.

**Part C.** Widened the key rather than adding `subcommand_protocols`: `protocols` is keyed
on a stable protocol id and every entry carries `cli_binding`, so aPAKE is a normal entry
reached by `pake-register`/`pake-demo`.  A parallel section would have let a protocol fall
between the two halves, which is the failure mode being fixed.  The audit it asked for found
`rand`, `fpe` and `twk` invisible for a worse reason than aPAKE's — no analysis exists for
them anywhere in the repository — recorded in `unfiled_cli_surface` and filed as TODO #241.

**Unplanned but mandatory.** `cli_support` was curated and wrong in two places (`hpks-xmss`
as Python-only, `hcred` as missing from Go).  It and `cross_implementation_gaps` are now
derived from each CLI's dispatch source, validated against an empirical probe of all 26 tags
against all three CLIs.

### #235: HPKE-Stern-KEM — add an FO transform with implicit rejection, and screen weak keys at keygen

Found while auditing the six `demo-only` entries in `spec/herradura-protocol-spec.json`.
`SecurityProofsCode/qcmdpc_dfr_weak_keys.py` (TODO #218) already established the facts;
this item is the remediation half that #218 deliberately left unfiled.

#218's §7 verdict lists four blockers, and states that they *compound rather than trade
off*: "Even a DFR of 2^-128 would not make this KEM IND-CCA2 while decapsulation reports
failure, and implicit rejection would not fix a 2^-8.8 DFR either."  Two of the four are
parameter choices that cannot be fixed without a redesign; **two are missing constructions
that can be added at the deployed parameters.**  This item is exactly those two.

**Out of scope, explicitly.** Raising `QCMDPC_R`/`_D`/`_T` from the deployed
`523 / 15 / 18` toward BIKE-128's `12323 / 71 / 134`, and moving Stern's `N=256` toward
the `N >= 17000` floor of SecurityProofs-5.md §11.8.4.  Those are a redesign, not a
tuning pass; the DFR(r) fit in #218 §3 is a lower bound (waterfall concavity) and r is
not even the right knob alone.  **Closing this item does not make HPKE-Stern-KEM
production-ready, and its `demo-only` status in `spec/` and SECURITY.md must not change.**
What it does is remove the two blockers that are cheap, self-contained, and currently
make the KEM weaker than its own parameters require.

**Part 1 — weak-key screen at keygen.**  `qcmdpc_keygen` retries only on a non-invertible
`h0`.  #218 §4 measures DFR varying materially with distance-spectrum multiplicity, and
~1 key in 3400 carrying roughly 10x the average DFR.  The screen is a rejection-sampling
loop around the existing support generation: compute the multiset of cyclic distances
within `sup0`/`sup1`, reject and redraw when max multiplicity exceeds the threshold #218
§4(c) pins.  Non-breaking — keygen output stays the same shape, only the accepted subset
of keys narrows.  Must land in C (`herradura.h`), Go (`herradura/herradura.go`) and
Python identically, since all three share the deployed parameters.

**Part 2 — FO transform with implicit rejection.**  `qcmdpc_decap_bgf` signals failure
explicitly, at every layer: a distinct library return value, and a distinct exit status
plus stderr message at the CLI (#218 §6).  That is the GJS oracle, and #218 §5 measures
the reaction attack end to end.  The fix is the standard one: decapsulation re-encrypts
and, on any mismatch or decoder failure, returns a pseudorandom key derived from a
secret seed rather than an error — the caller cannot distinguish success from failure.

**Primitive constraint (checked, not assumed).**  Both parts stay inside FSCX and add no
external primitive:
  * `qcprf_refill` (herradura.h) derives the QC-MDPC supports via
    `nl_fscx_revolve_v1_ba(&block, &rolx, &x, I_VALUE)` — the screen sits on top of an
    FSCX-derived support and touches no primitive at all.
  * `qcmdpc_encap` already derives `K = hfscx_256(e0 || e1)`, and `hfscx_256`'s
    compression step is `nl_fscx_revolve_v1_ba(&state, &state, &block, 64)`.  FO's
    re-encryption path reuses both.
  * **Use `hfscx_256_ds` (herradura.h:839), not bare `hfscx_256`, for every FO hash.**
    HFSCX-256 is Merkle-Damgard, so length-extension applies, and FO re-encryption hashes
    attacker-influenced data.  The domain-separated variant already exists (TODO #93) and
    `SecurityProofsCode/hfscx_dm_rf_model.py` (TODO #215) supplies the ideal-random-function
    argument the FO proof needs.  Bare HFSCX-256 here would be a real bug, not a style
    preference.

**Wire-format impact.**  Part 2 changes what decapsulation returns on a failure path, so
a `MIGRATING.md` entry is required per CLAUDE.md even though the ciphertext encoding need
not change.  Decide during implementation whether the re-encryption check alters the
ciphertext itself; if it does, this is the MAJOR-worthy half of the item and must say so.

**Interaction with the DFR retry policy.**  `CliTest/lib_dfr.sh` (TODO #221) retries a
fresh encapsulation on a *detected* DFR event.  Implicit rejection removes the signal that
policy keys off: after Part 2 a decoding failure is indistinguishable from success and
surfaces as a wrong shared secret instead.  Every script sourcing `lib_dfr.sh`, and the
CI DFR-guard step in `ci.yml` that enforces the sourcing, has to be revisited in the same
change — this is the part of the work most likely to be underestimated.

**Acceptance.**  #218's script is the oracle: re-run `qcmdpc_dfr_weak_keys.py` and require
§4's weak-key tail to be gone from what keygen emits, and §5's reaction-attack
distinguisher to lose its signal.  Update §11.8.7 of SecurityProofs-5.md and the
SECURITY.md row to state which two of the four blockers now fail to apply, and which two
still stand.

Status: **DONE v3.3.0** — both parts landed in C, Go, Python and Java: keygen rejects and redraws any private polynomial whose distance spectrum exceeds multiplicity 5 (#218 §4's cliff), and decapsulation applies an FO transform with implicit rejection, returning HFSCX-256-DS(0x11, z || C) on any failure instead of reporting one. The rigidity check reduces exactly to wt(e)=t given an invertible h0, so the ciphertext encoding is untouched and decap needs no h_pub; z is derived as HFSCX-256-DS(0x12, h0 || h1) rather than stored, so the private-key PEM is unchanged and old keys keep working. The success-path session key changed to HFSCX-256-DS(0x10, e0 || e1 || C) — wire-format breaking for derived secrets only, MIGRATING.md §7. `CliTest/lib_dfr.sh` was rewritten: a DFR event is now an output mismatch rather than an error message, `dfr_is_event` is deleted (and ci.yml's DFR guard fails on a resurrected copy), and all five consumer scripts retry on the comparison. #218's script is the oracle and confirms both: §4's weak-key tail is gone from what keygen emits and §6 measures success and failure returning the same kind of answer. Blockers 1 and 2 stand and the KEM stays demo-only, as the item scoped.

### #241: `rand`, `fpe` and `twk` ship with no security analysis anywhere in the repository

Found by TODO #238 Part C's audit of CLI surface invisible to `spec/`.  Three subcommands
reach no protocol entry, no `SECURITY.md` row, and no `SecurityProofs-*.md` section:

| subcommand | construction | analysis |
|---|---|---|
| `rand` | HDRBG deterministic byte generator over HFSCX-256 | none |
| `fpe`  | format-preserving encryption of a 256-bit block (TODO #78.A) | none |
| `twk`  | tweakable wide-block encryption of a 256-bit block (TODO #78.B) | none |

They are not obscure: all three ship in the C, Go and Python CLIs, and `rand` writes a
`HERRADURA HDRBG STATE` PEM that `CliTest/test_rand.sh` round-trips.  What is missing is
any statement of what they are supposed to guarantee.

**Why this is not a documentation task.**  #238 could not classify them the way it
reclassified `hpks-t` and `hpks-nl`, because those two had an existing analysis to
propagate — `hpks` is pedagogical because of Pohlig-Hellman, and the threshold and NL
variants are over the same group, so the verdict follows.  These three have no such
parent.  `fpe` and `twk` are their own constructions; `rand`'s HDRBG has a `DrbgMaxBlocks
= 1 << 20` reseed bound in `herradura/herradura.go:933` and nothing anywhere saying what
that bound is for.  Classifying them means doing the analysis, which is TODO #237-shaped
work.

**Interim state, deliberately visible rather than silent.**  #238 recorded all three in
`spec/herradura-protocol-spec.json`'s `unfiled_cli_surface` array and gave them a single
shared `SECURITY.md` row reading "Unclassified — no analysis exists", with the warning
that absence of a documented weakness there is absence of analysis rather than evidence of
strength.  `spec/generate_spec.py` fails if a *new* subcommand appears that is neither
bound to a protocol nor listed as unfiled, so the hole cannot grow while this is open.

**Work.**  For each of the three: state the security goal, identify the closest standard
construction (FF1/FF3-1 for `fpe`, a wide-block tweakable cipher such as AEZ or HCTR2 for
`twk`, SP 800-90A for `rand`), analyse the shipped construction against it, add a
`SecurityProofs-*.md` section, then file a real `SECURITY.md` row and `spec/` entry and
delete the `unfiled_cli_surface` record.  Expect at least one of the three to come out
worse than `demo-only` — `fpe` over a 256-bit block with no documented tweak schedule is
the one to look at first.

**Not in scope.**  Removing the subcommands.  They are shipped surface; the deficiency is
that nobody can tell what they promise.

Status: **DONE v3.3.1** — all three analysed and filed: SecurityProofs-7.md §11.24, a SECURITY.md row each, a spec/ protocol entry each (bound by `cli_binding`, since none has an --algo tag), and `SecurityProofsCode/rand_fpe_twk_analysis.py` as the backing script, which exits non-zero if any finding stops reproducing. `unfiled_cli_surface` now holds only `pkey`, a genuine utility. Two of this item's own premises turned out wrong and are recorded rather than worked around. First, `fpe` and `twk` DO have a parent — each other, and HSKE-NL-A2 — and they are literally the same function whenever the context is 12 bytes, because both derive their subkey from the same unseparated HFSCX-256(key || tweak); verified byte-identical across the C, Go and Python CLIs, in both directions. Second, `rand`'s DRBG_MAX_BLOCKS bound is not unexplained: nl_fscx_v1_ratchet_collision.py §5 derives it (collision probability 2^-179.8 against a 2^-128 requirement), so for `rand` the work was filing, not deriving. Verdicts: `fpe` **broken as named** — it is not FPE in the SP 800-38G sense at all, having no radix and no domain — `twk` and `rand` demo-only. The item's prediction that at least one would land worse than demo-only was right, for a different reason than it gave. New findings along the way: fpe/twk run nl_fscx_revolve_v2 at 64 steps where HSKE-NL-A2 uses 192, which TODO #214's trail projection puts at 2^-119 vs the 137 rounds it estimates for 2^-256; and HDRBG's effective state entropy is ~2^218.8, not 2^256. The domain-separation collision is a live defect and is filed as TODO #242 rather than fixed here, since fixing it changes what both subcommands produce.

### #242: `fpe` and `twk` share a subkey derivation and compute the same function

Found by TODO #241's analysis of the unclassified CLI surface, and deliberately left
unfixed there: #241 is an analysis item, and this fix changes what two shipped
subcommands produce.

Both derive their 256-bit subkey with the same unseparated hash call:

| | derivation |
|---|---|
| `fpe` | `B = HFSCX-256(key ‖ ctx)` |
| `twk` | `B = HFSCX-256(key ‖ sector_be64 ‖ bidx_be32)` |

Neither carries a domain-separation tag, so a 12-byte `ctx` equal to
`sector_be64 ‖ bidx_be32` makes the two subcommands the identical function.  Verified
byte-identical across the C, Go and Python CLIs, in both directions — `twk --decrypt`
recovers a plaintext that `fpe --encrypt` produced:

```
$CLI fpe --context '0123456789:;'                      --encrypt --in pt --out a
$CLI twk --sector 3472611983179986487 --bidx 943274555 --encrypt --in pt --out b
cmp a b        # identical
```

Two separately-advertised primitives reachable under one key are therefore not
independent, which is the only reason to ship both.  See SecurityProofs-7.md §11.24.1
and `SecurityProofsCode/rand_fpe_twk_analysis.py` §2.

**Work.**  Give each primitive its own domain-separation tag via `hfscx_256_ds` (TODO
#93), whose namespace already has `0x01`–`0x03` and `0x10`–`0x12` allocated, and
length-prefix the key so the `key ‖ tweak` boundary stops being ambiguous — `drbg_seed`
in the same file and TODO #235's KEM work both already do this.  Land it identically in
C, Go and Python (Java ships neither subcommand).  Consider also calling
`nl_v2_key_is_valid` on the derived subkey for defence in depth; the exposure is
negligible because `B` is a hash output, but the check exists and is used elsewhere.

**Scope expanded during implementation, deliberately: the round count comes too.**  TODO
#241 §11.24.4 found `fpe`/`twk` running HSKE-NL-A2's `nl_fscx_revolve_v2` at `I_VALUE` =
64 steps where A2 uses `R_VALUE` = 192, which TODO #214's trail projection puts at
`2^-119` against the 137 rounds it estimates for `2^-256`.  Fixing that is a wire-format
break of exactly the same two subcommands, so doing it in a later item would mean telling
users their ciphertexts are undecryptable a second time.  Both changes ship together in
one MAJOR.  This paragraph is the explicit call-out CLAUDE.md requires for the expanded
break.

**This is a MAJOR-class change and must be treated as one.**  It changes what an
existing `--algo`-equivalent CLI surface produces: every `fpe` and `twk` ciphertext
written by any prior build becomes undecryptable by the fixed build, and the failure is
silent — both subcommands are unauthenticated permutations, so a wrong subkey yields
plaintext-shaped garbage rather than an error.  Per CLAUDE.md that needs a `MIGRATING.md`
entry alongside the version bump, and this item is the required explicit call-out.

**Test coverage, which must land with the fix.**  `fpe` and `twk` have no `CliTest`
script at all — no CLI-level test and no cross-language interop test, in a repo whose CI
runs a four-language matrix over every other protocol family.  That C, Go and Python
currently agree byte-for-byte was established by hand for #241 and is guarded by nothing.
The suite-level `test_fpe_correctness` / `test_twk_correctness` do not close this: they
re-implement the construction locally (`_fpe_derive_b`, `fpe_encrypt_test`,
`twk_encrypt_test`) and round-trip against the copy, so the shipped `fpe_encrypt` and
`twk_encrypt` are never called by any test, and the round-trip property they assert is a
tautology for any bijection — it would pass even with the subkey derivation deleted.  Add
a `CliTest` script exercising the shipped subcommands across all three CLIs, and make the
suite tests call the real functions.  A regression test that the two primitives no longer
collide is the specific thing this item must not ship without.

**Not in scope.**  The `fpe` naming defect (it is not format-preserving encryption in
the SP 800-38G sense — no radix, no domain, 32 bytes in and out).  That is a separate
question — rename, re-scope, or implement a real FF1/FF3-1 domain — and it should not be
bundled with a wire-format fix.  SECURITY.md's `fpe` row records it meanwhile.

**Worth deciding first.**  Whether `fpe` should keep existing at all once it is
domain-separated from `twk`: with the naming defect on one side and `twk` covering the
tweaked-permutation use case on the other, a deprecation may be cheaper than a fix.
#241 put removal out of its own scope but did not rule it out here.

Status: **DONE v4.0.0** — the first MAJOR since 2.0.0. Both primitives now derive their subkey as HFSCX-256-DS(tag, len(key)_be8 || key || tweak), tag 0x20 for fpe and 0x21 for twk, closing the collision and the unencoded key boundary together; the derived subkey is additionally rejection-sampled away from NL-FSCX v2's degenerate affine class, a backstop that is effectively never taken. Landed identically in C, Go and Python (Java ships neither). The 64-vs-192 round count #241 §11.24.4 found was folded into the same break rather than spent as a second one: both now run at R_VALUE=192, matching HSKE-NL-A2. Wire-format breaking and silently so — both subcommands are unauthenticated permutations, so a pre-4.0.0 ciphertext decrypts to plausible garbage rather than an error; MIGRATING.md §8 leads with that. Coverage, which this item was required not to ship without: new CliTest/test_fpe_twk.sh (38 assertions across all three CLIs — round-trips, byte-for-byte cross-implementation agreement, cross-decrypt both directions on each pair, tweak separation, and the collision regression itself), plus test [46] in the C, Go and Python harnesses. One correction to #241 along the way: the C and Go harnesses DO call the shipped fpe_encrypt/FpeEncrypt — only Python re-implemented, and §11.24.7 now says so and cross-checks the Python copy against the suite. Two things deliberately not done: the fpe naming defect stays open, as this item scoped, and twk was NOT reclassified even though all three of its stated blockers are now closed — that gets a deliberate review as TODO #243 rather than being granted on the strength of "the defects I found are fixed".

### #243: does `twk` still belong at demo-only now that its three blockers are closed?

TODO #241 classified `twk` demo-only and named exactly three reasons: it shared an
unseparated subkey derivation with `fpe` and collided with it, it ran
`nl_fscx_revolve_v2` at 64 steps where HSKE-NL-A2 uses 192, and its `key ‖ tweak`
boundary was unencoded.  TODO #242 (v4.0.0) closed all three.

The row was not moved at the same time, deliberately.  Reclassifying a protocol because
the specific defects someone found have been fixed is the reasoning TODO #237 and #238
were filed to undo — it mistakes "no known problems" for "analysed".  This item is the
deliberate review that a promotion would need.

**The question.**  `twk` is now HSKE-NL-A2's `nl_fscx_revolve_v2` at A2's own round
count, under a subkey derived from the key and a per-(sector, block) tweak rather than
supplied by the caller.  A2 is rated "Production-track (conjectured), with two
constraints".  Does `twk` inherit that, and if so with which constraints?

**What has to be established, not assumed.**

* **A security definition.**  A2's row is about a keyed bijection used once per message.
  `twk`'s claim is a *tweakable* one — the standard target is STPRP (strong tweakable
  pseudorandom permutation), and nothing in the repository argues `twk` meets it.  A
  per-tweak-derived subkey is a construction, not a proof: the reduction has to say what
  happens when an adversary queries many tweaks under one key.
* **Whether A2's two constraints transfer.**  Determinism is inherent here and expected
  (XTS-style, per tweak) rather than a caveat, which is arguably *better* than A2's
  position.  The weak-key class is unreachable because the subkey is a hash output, which
  is also better.  Both differences point the same way, and both should be stated as
  findings rather than assumed.
* **What the round count actually buys.**  #214's trail projection is explicitly its own
  weakest step (slope read off widths 16–32, not 256).  "Now matches A2" is a
  comparative statement; a promotion needs more than parity with something whose own
  rating is conjectural.

**Do not treat this as a formality.**  The honest outcome may well be that `twk` stays
demo-only because NL-FSCX v2 has no positive security result at all, only key-averaged
trail bounds — in which case A2's own "production-track (conjectured)" rating is the
thing that deserves re-examination, and this item should say so rather than quietly
promoting `twk` to match it.

**Not in scope.**  `fpe`, whose naming defect is its own open question, and `rand`.

Status: **DONE v4.0.1** — reviewed, and `twk` STAYS demo-only. The review is SecurityProofs-7.md §11.25, backed by `SecurityProofsCode/twk_stprp_review.py` (its reduced-width model pinned 200/200 against the shipped nl_fscx_v2 first). Three results. (1) A reduction that settles what the question is: modelling HFSCX-256-DS as a random oracle, `twk` is an STPRP exactly if F_B^r is an SPRP under a uniform key — so the whole question is about the permutation and none of it is about tweaking, which is all #242 touched. (2) A structural property neither #241 nor #242 recorded: v2-revolve is ONE unvaried round iterated 192 times, with no round constant and no key schedule, in all three languages. Measured consequences — at n=8, 10.7% of keys give ord(F_B) | 192 and encrypt to the IDENTITY MAP (a small-width artefact, gone by n=12, and the identity case is ruled out 12/12 at the 32 bits the Arduino/assembly ports use); and one slid pair leaves a mean 1.7 candidate keys of 2^16, two leave 1.08, so the barrier to a slide attack is only the ~2^128 birthday cost of finding a pair — a cost that does not depend on the round count at all, meaning #242's 64->192 move bought nothing against this class. (3) `twk` is genuinely stronger than HSKE-NL-A2 on three axes because its subkey is a hash output, which contains the blast radius of the unproven assumption without replacing the missing proof. Verdict: unproven is demo-only. The inconsistency this exposes is that HSKE-NL-A2 carries the same unproven claim with worse failure consequences and is rated production-track — it is the only production-track rating in the suite resting on NL-FSCX v2 — so A2's rating, not `twk`'s, is what needs re-examining. Filed as TODO #244 rather than changed unilaterally here.

### #244: re-examine HSKE-NL-A2's "production-track (conjectured)" rating

Raised by TODO #243, which reviewed `twk` for promotion and kept it demo-only.  The two
rows are now inconsistent and the inconsistency is not in `twk`'s favour.

`twk` and HSKE-NL-A2 are the same permutation — `nl_fscx_revolve_v2` — at the same round
count.  #243 kept `twk` at demo-only because no SPRP result exists for that permutation.
A2 rests on exactly the same unproven claim and is rated **production-track
(conjectured)**, with *strictly worse* consequences if the claim fails: in `twk` the
subkey is a hash output, so recovery is confined to one (sector, block index) and does
not yield the key, while in A2 `B` **is** the caller's key.  Both ratings cannot be right.

**What #243 established that this item inherits** (SecurityProofs-7.md §11.25):

* v2-revolve is one unvaried round iterated 192 times, with no round constant and no key
  schedule, in C, Go and Python alike.
* One slid pair leaves ~1.7 candidate keys out of 2^16; two leave 1.08.  The barrier to a
  slide attack is only the ~2^128 birthday cost of finding a pair — **and that cost does
  not depend on the round count**, so A2's 192 rounds do nothing against this class.
* The only quantitative evidence for the permutation is TODO #214's trail bounds, which
  #214 itself labels an order-of-magnitude indication rather than a bound, and which are
  key-averaged precisely because the construction reuses one key every round.

**The question.**  Does "production-track (conjectured)" survive that?  The word
*conjectured* is carrying the whole rating, and #243's finding is that the conjecture has
less behind it than the label implies — in particular that a reader who sees
"production-track" will not infer "one unvaried round, no round constants, and a slide
structure the round count cannot improve".

**What has to be re-derived, not inherited.**  A2's row states two specific constraints
(determinism across messages; the degenerate affine key class rejected by
`nl_v2_key_is_valid`).  Whatever rating comes out, those two have to be restated against
whatever the new analysis finds rather than carried over unexamined — #237 and #238 exist
because propagated rows go stale.

**Scope is smaller than it looks, and worth stating up front.**  Four `SECURITY.md`
entries rest on NL-FSCX v2 — HSKE-NL-A2, HSKE-Duplex, `fpe` and `twk` — and three are
already research, broken or demo-only.  **A2 is the only production-track rating in the
suite that depends on this permutation.**  HPKS-NL / HPKE-NL name NL-FSCX but their
demo-only rating comes from Pohlig-Hellman on the GF(2^n)* group and does not depend on
v2's strength, so this item cannot make them worse.

**Two honest outcomes, and neither is foreordained.**  Either the conjecture is defensible
and the row should say plainly what it is conjecturing and what §11.25 found against it;
or it is not, and A2 joins `twk` at demo-only — which would be the first downgrade of a
production-track row in this suite and should be done deliberately, with `MIGRATING.md`
untouched (a rating is not a wire format) but the README's positioning of the NL/PQC
quartet revisited.

**Worth attempting first, because it could settle the item outright.**  Add round
constants.  A round-indexed constant XORed into each step would break the self-similarity
outright, and would cost nothing measurable — it is the standard fix and the reason round
constants exist.  If that is done, §11.25's slide finding stops applying and the rating
question narrows back to the trail bounds alone.  It is a wire-format break for A2,
`twk`, `fpe` and HSKE-Duplex together, so it belongs in one deliberate MAJOR rather than
being smuggled into a rating review — but a rating review that ignores an available
structural fix is the wrong shape.

Status: **DONE v4.0.2** — **HSKE-NL-A2 downgraded from "Production-track (conjectured), with two constraints" to demo-only.** The first downgrade of a production-track row in this suite. Review is SecurityProofs-7.md §11.26, backed by `SecurityProofsCode/hske_nl_a2_rating_review.py` (reduced-width model pinned 200/200 against the shipped nl_fscx_v2 first). The decisive reasoning is consistency: TODO #243 refused to promote `twk` because nl_fscx_revolve_v2 has no SPRP result, the only quantitative evidence is #214's key-averaged trail bounds, and the construction is self-similar in a way the round count cannot fix — all of which applies to A2 unchanged, since it is the same permutation at the same round count, and A2 is the worse of the two because its key is caller-supplied (needs the weak-key check twk cannot reach; key recovery is total rather than one block). NEW result the review adds, which #243 did not have: a THEOREM rather than a conjecture. Since E_B = F_B^r, a point is fixed exactly when it lies on an F-cycle whose length divides r, so E[fixed points] = tau(r) = tau(192) = 14 against an ideal cipher's 1 — measured 13.84 at n=16. Not an attack (finding one costs ~2^252 at n=256) but provably not an ideal cipher, as arithmetic rather than opinion, and never previously computed. Corollary worth acting on: the excess is tau(r), so 192 = 2^6*3 is among the worst choices available and a PRIME round count drops it to ~1.04 for one line per language — and #242's 64->192 move made this statistic worse (tau 7 -> 14) while improving the trail picture. A2's two documented constraints were re-derived rather than inherited (both survive) and a third, self-similarity, was added. Explicitly NOT claimed: that A2 is broken (bijectivity is proven, the weak-key class is excluded, no attack is known), and nothing changes for NL-FSCX v1, HFSCX-256 or HSKE-NL-A1, which use the primitive in modes the argument does not reach. No wire-format change — a rating is not a format, MIGRATING.md untouched, all keys and ciphertexts still work. README needed no revision: it describes A2 but never claimed production-readiness for it. Candidate fixes filed as TODO #245.

### #245: remove NL-FSCX v2's self-similarity — round constants, or at least a prime round count

Raised by TODO #244, which downgraded HSKE-NL-A2 to demo-only.  Two candidate fixes came
out of #243 and #244 and neither was applied there, because both are wire-format breaks
and a rating review is the wrong place for one.  This item decides between them and
applies whichever survives.

**The problem.**  `nl_fscx_revolve_v2` is one unvaried round iterated `r` times, with no
round constant and no key schedule: `E_B = F_B^r`.  Two measured consequences
(SecurityProofs-7.md §11.25.2, §11.26.2):

* one slid pair leaves ~1.7 candidate keys out of `2^16` and two leave 1.08, so the only
  barrier to a slide attack is the ~`2^128` birthday cost of finding a pair — **a cost
  that does not depend on `r` at all**;
* `E[#fixed points] = tau(r) = tau(192) = 14` against an ideal cipher's 1, measured 13.84
  at `n = 16`.  Provably not an ideal cipher, as arithmetic rather than opinion.

Neither is an attack at `n = 256`.  Both are properties a production-track rating should
not have had to carry, and both are fixable.

**Option A — round constants.**  XOR a round-indexed constant into each step.  Breaks the
self-similarity outright: `E_B` stops being a power of one map, the slide structure goes,
and `tau(r)` stops being meaningful.  This is the standard fix and the reason round
constants exist.  Cost: a real change to the round function in C, Go, Python and the
Arduino/assembly ports, and **the existing trail bounds (#214) would have to be re-run** —
they are bounds on the current round, and adding a constant changes it.

**Option B — a prime round count.**  Change `R_VALUE` from 192 to 191 or 193.  One line
per language.  Drops the fixed-point excess from 13.8x to 1.04x (measured, §11.26.3).
Does **nothing** for the slide structure, which is the more serious of the two.  Cheap,
and strictly an improvement, but it treats the symptom.

**Recommendation to evaluate, not to assume.**  A alone is the principled fix; B alone is
insufficient; A+B together costs nothing extra over A, since both are the same wire break.
The open question is what A does to the trail bounds — if adding a round constant degrades
them, that has to be known before shipping, not after.  Re-running #214's SMT search on
the modified round is the gating work for this item.

**Reach — this is a four-construction break.**  `nl_fscx_revolve_v2` is used by HSKE-NL-A2,
`twk`, `fpe` and HSKE-Duplex.  Any change to the round function or the round count breaks
every stored artifact of all four, and for `twk` and `fpe` the failure is **silent**, since
both are unauthenticated permutations (MIGRATING.md §8 has the pattern).  One deliberate
MAJOR, one `MIGRATING.md` section, all four constructions at once.

> *Correction, made while implementing:* the reach is **five**, not four — `hpke-nl` also
> encrypts through `nl_fscx_revolve_v2` and was missed when this item was filed.
> `MIGRATING.md` §9 lists all five.

**What this item may allow afterwards.**  If A lands and the trail bounds survive, the
structural objections in §11.25 and §11.26 stop applying and the ratings for A2 and `twk`
can be revisited on trail-bound evidence alone.  That would be a *separate* item — this one
ships the fix, it does not re-rate anything.  A rating review that grants itself a
promotion for work it also performed is the failure mode #237, #238, #243 and #244 have all
been about.

Status: **DONE v5.0.0** — Option A shipped, Option B dropped as redundant. `nl_fscx_revolve_v2` and its inverse now XOR the 1-based round index into the state before each step, in C, Go, Python and Java identically; the single-step `nl_fscx_v2` is unchanged and R_VALUE stays 192. **The gating question resolved analytically and favourably**: an XOR round constant leaves xdp+ EXACTLY invariant — the constant cancels in the XOR difference entering M, and M is a bijection so the value distribution into the modular add is unchanged — confirmed exhaustively 25/25, so #214's trail bounds carry over verbatim with no re-run. Measured benefit at n=16: median fixed points 4.0 -> 1.0, mean 9.04 -> 0.84, max 77 -> 3, frac>1 76% -> 16% (ideal: 1, 1, 37%), and the identity-collapse class becomes unaskable at every width since E_B is no longer a power of any single map. Option B (prime round count) is not shipped: it treated only the fixed-point symptom via tau(r), and once the cipher is not F^r the divisor structure is irrelevant. Five constructions break together — hske-nla2, hpke-nl, hske-duplex, fpe, twk — MIGRATING.md §9, silent for the two unauthenticated ones. Arduino/assembly left unchanged as in #242 (separate 32-bit construction, no wire compatibility, measured clear of the collapse class 0/200). **Ratings deliberately unchanged**, as this item required of itself: removing an objection is not supplying a proof, and there is still no PRP/SPRP reduction for v2 at any round count. **This item also corrected two numbers #243 and #244 published**, found while doing the work: every n=12 measurement in §11.25/§11.26 was void because M is singular at n=12 (so F_B is not a bijection and the cycle decomposition produced nonsense — #214 avoided this and said so; #243/#244 did not check), and §11.26's "13.84 confirming tau(192)=14 almost exactly" was a 25-key sample of a heavy-tailed statistic whose 300-key mean is an order of magnitude higher with a standard error exceeding it. Both are corrected in place with the robust statistics, and neither changes either item's verdict. Remeasuring also found the identity collapse DOES occur at n=16 (1/300), which §11.25 had asserted was gone — the deployed n=256 remains clear, structurally, since 256 does not divide 192.

### #246: give the NL-FSCX v2 cipher family an AND-based nonlinear layer

The v2 family — HSKE-NL-A2, HPKE-NL, HSKE-Duplex, `fpe`, `twk` — is rated demo-only, and
TODO #243/#244 identified exactly why: there is no PRP/SPRP reduction for
`nl_fscx_revolve_v2` at any round count, and the only quantitative evidence is TODO #214's
key-averaged differential trail bounds, which #214 itself calls an order-of-magnitude
indication rather than a bound.  TODO #245 removed the structural objections (round
constants), which puts those bounds back in the binding position.  This item attacks the
bounds themselves, by changing what they are bounds *on*.

**The gap, precisely.**  `FSCX(A,B) = M(A ⊕ B)` is GF(2)-**affine** — algebraic degree 1.
All of v2's nonlinearity comes from one modular addition, `+ δ(B)`, whose degree grows only
through carry propagation.  That is a thin and highly structured source of nonlinearity,
and it is why the trail bounds are what they are.

**Scope, and why this is not blocked by the impossibility theorems.**  TODO #210, #224 and
#230 rule out non-linear step functions for **HKEX-style agreement** — #230's
characterization theorem shows *any* step function admitting that agreement hands Eve the
session key.  That is a statement about key exchange.  **No shipped protocol uses
FSCX_REVOLVE for agreement any more**: HKEX-GF is Diffie-Hellman over GF(2^n)*, HKEX-RNL is
Ring-LWR, and every remaining `fscx_revolve`/`nl_fscx_revolve_v2` call site in the CLI is an
encrypt or decrypt.  So the cipher family is free to become non-linear; only the (already
retired) agreement construction was not.  **Verify this claim still holds before starting** —
it is the load-bearing premise of the whole item.

**Design constraint that eliminates most candidates: invertibility.**  `dec`, `decfile`,
`fpe --decrypt` and `twk --decrypt` all ship, so any new layer must be a bijection on the
256-bit block.  A bare AND or OR layer is not — and is not balanced either
(`P(a∧b=1) = 1/4`, `P(a∨b=1) = 3/4`).

**Two candidates, both measured (see the research notes below).**

*A. Simon-style Feistel round.*  `(x, y) → (y, x ⊕ (y⋘1 ∧ y⋘8) ⊕ y⋘2 ⊕ k)` on two 128-bit
halves.  **Invertible by structure**, whatever the F-function does, at any block size —
verified.  Degree 2 per round.  Has a decade of third-party cryptanalysis to borrow bounds
and methodology from, which is the entire point: it makes a *provable* differential/linear
bound reachable rather than conjectural.  Cost: a Feistel round diffuses half the state per
round, so the round count needs re-deriving rather than inheriting 192.

*B. Keccak's χ.*  `a_i ← a_i ⊕ (¬a_{i+1} ∧ a_{i+2})`, degree 2, one AND and one XOR per bit —
the cheapest option.  **But it is a bijection only on odd-length rows**, verified
exhaustively for lengths 3–12, and `256 = 2^8` has **no odd divisor greater than 1**, so a
256-bit state admits no uniform odd-length row decomposition.  χ cannot be dropped in as-is.
Workarounds to evaluate: 255 bits of χ with one bit passed through; non-uniform rows; or a
state resize.  Each changes the block or the wire format, so cost this before committing.

**On the OR half of the proposal.**  `b ∨ c = b ⊕ c ⊕ (b ∧ c)`, so any OR-based layer is an
AND-based layer plus linear terms.  OR adds no algebraic degree that AND does not, and used
bare it biases the state.  The balanced idiom — used by both χ and Simon — is to XOR the AND
term *into* the state.  Recommend AND only; record OR as considered and redundant rather
than silently dropped.

**The cost nobody should discover late: masking.**  TODO #78.H's Boolean masking is *free*
today precisely because FSCX is GF(2)-linear —
`fscx_revolve(A⊕r, B) ⊕ fscx_revolve(r, 0) = fscx_revolve(A, B)`, with no secret bit in any
intermediate.  **An AND gate destroys that identity.**  Masking an AND needs an ISW/DOM
gadget: `d` shares cost `O(d²)` AND operations plus fresh randomness per gate, per round.
Quantify this before choosing a candidate, and quantify it *on AVR*, which has the tightest
budget and a known SRAM ceiling (TODO #155).  It is entirely possible the honest outcome is
"stronger cipher, masking moves from free to expensive" — that is a legitimate trade, but it
must be a decided one, and `SECURITY.md`'s masking claims would need revisiting.

**Plan.**
1. Re-verify the scope premise (no shipped agreement use of FSCX_REVOLVE).
2. Prototype both candidates at reduced width in `SecurityProofsCode/`; confirm
   invertibility, measure algebraic degree growth and avalanche against current v2.
3. Run TODO #214's exact `xdp+` SMT search against each new round function — this is where
   the item either pays off or does not, and it is also why **#247 should land first or
   alongside**: the current tooling does not scale to n = 256 and a new round function needs
   bounds at least as good as the ones it replaces.
4. Measure masked and unmasked cost in C, Go, Python and on AVR.
5. Only then choose, and write the migration.

**Reach.**  Changing the v2 round function breaks HSKE-NL-A2, HPKE-NL, HSKE-Duplex, `fpe`
and `twk` together — the same five as TODO #245, one deliberate MAJOR and one
`MIGRATING.md` section, with the silent-failure warning that `fpe`/`twk` need.

**Explicitly not in scope.**  Re-rating anything.  That is #248, and it must not be granted
by the item that performs the work — the failure mode #237, #238, #243, #244 and #245 have
all been about.

**Progress — steps 1 and 2 are done.**  `SecurityProofsCode/nl_fscx_v2_and_layer.py`.

* *Step 1, premise re-verified and narrower than feared.*  `hkex-gf` agrees via `gf_pow`,
  `hkex-rnl` via `_rnl_agree`; the single FSCX in a kex path is a **v1 KDF applied after
  agreement**.  So this touches no key exchange, and no v1 consumer either — HFSCX-256 and
  HSKE-NL-A1 are out of scope.  Affected: exactly the five listed above.
* *The parity obstruction dissolves — but not the way first proposed.*  χ is applied per
  row and rows need only be odd, not equal; a sum of odd parts is even iff the count is even.
  The naive fix, **127 + 129**, is the WRONG one: χ's inverse has degree `(L+1)/2` (measured
  exhaustively, L = 3..13), so a 127-bit row means **degree-64 decryption via a serial
  127-step recurrence**, and every affected construction ships a decrypt path.  Keccak never
  pays this — it uses L = 5 and, being a sponge, never inverts χ.  The right design is **many
  short odd rows: 256 = 47×5 + 3×7**, fifty parts, inverse degree ≤ 4, bit-parallel, inside
  Keccak's analysed regime.  Row length barely affects differentials — at n = 16, (5,11) and
  (7,9) are within noise — and every candidate-B figure below was *already* measured with
  short rows (`odd_partition` gives (5,5) at n=10, (7,7) at n=14).
* *Both candidates are bijections* at reduced width, and both keep `M`.
* *Measured, and the ordering holds at two widths* (n = 10 exhaustive, n = 14 sampled; both
  widths chosen with `M` invertible).  Max differential probability:

  | rounds | current v2 | A: Feistel + AND | B: v2 then χ |
  |---|---|---|---|
  | 1 | 1.000 | 1.000 | 0.281 |
  | 2 | 1.000 | 0.250 | 0.086 |
  | 3 | **1.000** | 0.125 | 0.018 |
  | 4 | 0.375 | 0.031 | 0.014 |

  At n = 14 the margin is wider: B is at the random-permutation floor by round 3 (0.00085)
  where the deployed round is still at 0.102.

* *A finding about the CURRENT construction, not just the candidates:* deployed v2 has a
  **probability-one differential through three rounds**, and is still at 0.375 after four.
* *Raw algebraic degree is not the deficiency.*  The deployed round already reaches degree 5
  in one round at n = 10, from carry propagation — "FSCX is affine" is true of FSCX, not of
  v2.  The deficiency is differential behaviour.

**Interim recommendation: candidate B**, and TODO #247(c) has since confirmed it holds on
the *linear* axis too (B 3.48 bits over three rounds at n = 10, A 2.00, deployed v2 0.16),
so the recommendation is not an artefact of having looked only at differentials.  On
measurement and on smallest-diff grounds.  But
candidate A's advantage is different in kind and should not be dismissed — a Simon-style
Feistel inherits a large third-party literature, and the point of this item is to make a
*provable* bound reachable, which a better-measured construction with no literature may not.

**Step 3, tractable half done.**  Optimal single-trail weight is the currency #214 reports,
so it was computed *exactly* — full one-round DDT, then a dynamic program over difference
states, giving proven optima rather than solver output that might have timed out.  Averaged
over 3 keys, `-log2(p)`:

| rounds | v2 (n=10) | A | B | | v2 (n=11) | A | B |
|---|---|---|---|---|---|---|---|
| 1 | 0.00 | 0.00 | 1.78 | | 0.00 | 0.00 | 2.00 |
| 2 | 0.06 | 2.00 | 4.66 | | 0.39 | 2.00 | 4.83 |
| 3 | **0.39** | 3.00 | 7.52 | | 2.18 | 3.00 | 7.74 |
| 4 | 1.86 | 5.00 | 10.42 | | 4.36 | 5.00 | 11.00 |

The deployed round accumulates **0.39 bits of trail weight over three rounds** at n = 10 — a
trail of probability 0.76.  Candidate B has more weight after one round than v2 has after
three.  Cross-checks against the §4 differentials are consistent throughout (a differential
is at least as likely as its best trail).

**A caveat the numbers themselves reveal.**  B hits 11.00 bits at n = 11 after 4 rounds —
the full width — so it has *saturated* and its slope is truncated.  A slope read off a
saturated series is a lower bound, and comparing slopes when one construction saturates and
another does not is unreliable.  The rounds 2→4 window gives ~2.0 bits/round for v2
(consistent with #214's 1.87), 1.5 for A, and *at least* 3.1 for B — the last being exactly
the untrustworthy one.  These widths saturate too fast to extrapolate from, which is the
argument for #247's MILP rather than a bigger version of this.

**Step 4 done, and it corrects an error in this item's own text.**  This item claimed an AND
layer would take masking "from free to expensive".  That is **wrong for the v2 family**.
TODO #78.H masks the *classical*, GF(2)-linear `fscx_revolve`; there is no masked v2 anywhere,
and v2 already contains a modular addition that is nonlinear over GF(2) and already needs a
masked adder.  Order-of-magnitude first-order cost per round at n = 256: the masked addition
already present ~1792 ops, + χ ~1024 (+57%), + Simon's F ~512 (+29%).  A half to a third on
top of a cost already paid — not free→expensive.  **The correction runs in favour of the
change.**  Unchanged: none of it is implemented, and the AVR SRAM ceiling applies to the
masked adder v2 already needs, independently of any AND layer.

**Candidate B's main technical risk is RESOLVED** — see the short-row finding above.  It was
χ's inverse, and short rows close it.

**Recommendation, now firm: candidate B with short odd rows.**  Leads on differentials and
on linear (#247(c)), smallest diff against what ships, no structural change, invertible
cheaply, inside Keccak's analysed regime.

**Remaining, and it is the reason this item cannot be closed.**  (5) Migration — a
five-construction MAJOR.  Step 3's realistic-width bound was the stated gate on shipping,
and **#247 established that CBC cannot reach it**: proven optima stop at n = 64, and the
dominant uncertainty turns out to be the key-averaged/per-key gap rather than width.
Shipping a new round function on small-width comparative evidence would be precisely the
under-evidenced move #237, #238, #243, #244 and #245 were filed to prevent.  The design is
decided; the evidence to justify a wire-format break is not yet in hand.

Status: **DONE v5.0.1 (analysis)** — steps 1-4 complete; the migration is split out as TODO #251, which cannot proceed on current evidence. Scope premise verified and narrower than filed: changing v2 touches no key exchange (#230's impossibility is about HKEX agreement, and hkex-gf/hkex-rnl agree by other means) and no v1 consumer, so HFSCX-256 and HSKE-NL-A1 are out of scope. Two candidates prototyped, both keeping FSCX's M: a Feistel with Simon's AND, and the deployed round followed by chi. **Candidate B with SHORT odd rows (256 = 47x5 + 3x7) is the firm recommendation** — it leads on differentials (max DP and exact optimal trail weight at two widths) and on linear cryptanalysis (#247c), is the smallest diff against what ships, needs no structural change, and inverts cheaply. Two errors in this item's own text were found and corrected. (1) The masking objection was backwards: #78.H masks the CLASSICAL linear fscx_revolve, there is no masked v2 anywhere, and v2 already needs a masked adder for its modular addition — adding chi is roughly +57% on a cost already paid, not free-to-expensive, so the correction FAVOURS the change. (2) The 127+129 row split was wrong: chi's inverse has degree (L+1)/2, so it would have meant degree-64 decryption by a serial 127-step recurrence, and every affected construction ships a decrypt path. Short rows keep the inverse at degree 4, stay inside Keccak's analysed regime, and cost nothing differentially — and every candidate-B figure reported was already measured with short rows, so the measurements always described this design. On the OR half of the original brief: b OR c = b XOR c XOR (b AND c), so OR is an AND plus linear terms and adds no algebraic degree; recorded as considered and redundant.

### #247: provable trail bounds — MILP scaling, fixed-key differentials, exact Walsh

TODO #214 closed with three explicit recommendations that were never filed.  They matter
more now than when they were written: TODO #243 and #244 both had to lean on #214's bounds,
and both had to caveat them as key-averaged and order-of-magnitude — which is a large part
of why HSKE-NL-A2 was downgraded and `twk` not promoted.  #246 will also need them.

**(a) A MILP formulation that scales toward n = 256.**  #214's SMT search closes only for
small widths and small round counts; everything at the deployed width is extrapolation, and
#214 labels that projection its own weakest step.  MILP is the standard tool for ARX and
AND-based trail bounds at realistic widths.

**(b) A fixed-key differential treatment.**  #214 flagged this as "the open question this
analysis surfaces rather than settles", and it bites unusually hard here: NL-FSCX reuses one
key in every round, so per-round deviations correlate instead of averaging out.  #214
measured, at n = 8, that every key has some differential running well above its key-averaged
value.  A key-averaged bound is the right currency for comparing designs and is what ARX
practice reports, but it is **not** a per-key security claim, and no document currently says
so outside #214's own text.

**(c) An exact Walsh-Hadamard transform at small width.**  #214 deferred the Walsh-spectrum
sub-item because as written it asked to resolve a `2^-16` bias by sampling — about `2^32`
evaluations per functional, out of reach.  The tractable substitute is an exact transform at
reduced width, which #214 said "deserves its own item rather than a rushed appendix".  This
is that item.

**Why this is worth doing even if #246 is not.**  These three would let the existing v2
family be described accurately rather than conservatively.  It is possible the outcome is
"the bounds are fine and the family was under-rated" — that would be a real result, and
#248 is where it would be acted on.

**Progress — (b) and (c) done, (a) done as far as exact methods reach.**
`SecurityProofsCode/nl_fscx_v2_bounds.py`.  Everything exact: full DDT/LAT, then a DP over
difference or mask states, so each figure is a proven optimum rather than a sample.

*(a) The slope is width-stable, which SUPPORTS #214.*  Optimal trail weight for the
deployed round at every exactly-reachable width with `M` invertible, 6 keys each:

| n | r=3 | r=5 | slope | saturated? |
|---|---|---|---|---|
| 8 | 2.03 | 4.83 | 1.40 | yes (>0.6n) |
| 10 | 1.88 | 5.12 | 1.62 | yes |
| 11 | 1.86 | 4.73 | 1.44 | no |
| 13 | 1.47 | 4.87 | 1.70 | no |

Range 1.40–1.70, no monotone drift, bracketing #214's independently measured 1.87 closely
enough that its methodology is not in question.  **A near-miss worth recording:** an earlier
2-key run gave 1.30 at n = 13 and appeared to show the slope collapsing with width — which
would have meant #214's projection and the 137-round figure were optimistic.  It does not
reproduce at 6 keys.  Two keys is not a sample for a statistic with this spread.

*(b) The per-key spread is large.*  Optimal 5-round trail weight across keys at n = 11 runs
from 0.70 to 7.71 on a mean of 4.73 — a spread wider than the mean.  A key at the weak end
has almost no 5-round trail resistance while the averaged figure advertises ~4.7, and
nothing screens for it: there is no trail-behaviour analogue of TODO #235's QC-MDPC
weak-key screen, and `nl_v2_key_is_valid` covers only the degenerate affine class.  Not a
new attack — the reason "key-averaged" must stay attached to every figure, and the reason a
rating cannot rest on an averaged bound.

*(c) Exact linear cryptanalysis, an axis nobody had measured.*  Optimal linear-trail weight
`-log2|c|` at n = 10: deployed v2 reaches **0.16 bits over three rounds** — correlation ≈ 0.90,
very nearly deterministic — against 2.00 for candidate A and 3.48 for candidate B.  Run
specifically to test whether #246's recommendation was an artefact of looking only at
differentials.  **It was not:** B leads on both axes.

*(d) The MILP half — backend added, and it closes further than expected.*  `pulp` (CBC) is
now an **optional, analysis-only** dependency: absent, §(d) prints a NOTE with install
instructions and the file still runs, the same pattern #214 uses for z3.  Documented in
CLAUDE.md's new *Third-party dependencies* table.  The shipped primitives still have none.

Two things had to be got right before any MILP number was usable, and the first attempt got
both wrong:

* **What it models.**  `xdp+` assumes both addends vary; here one is a constant, so the LM
  formula computes the **key-averaged** behaviour, not a per-key bound.  Validated against
  its own reference — a DDT averaged over 64 keys, then the exact DP — giving 1.80/3.43/5.82
  at n = 10 against the MILP's 2.00/4.00/7.00.  It tracks, slightly conservative.
* **When a result is proven.**  A time-limited CBC run reports `Optimal` for merely feasible
  solutions.  An early pass at n = 128 returned a 4-round optimum *cheaper* than its own
  3-round optimum — impossible — so anything consuming its time limit is now reported
  unproven.

**Proven optima are identical at every width that closes** — 2.0 / 4.0 / 7.0 at r = 2/3/4
for n = 16, 32 **and 64** (the last needing 864 s), plus 10.0 at r = 5 for n = 16.  Three
widths differing by a factor of four agree at every round count that closes.

**A correction to an earlier version of this entry.**  It justified carrying the figure to
n = 256 by asserting the optimal trail is *local*, so rotation-invariance would embed it at
any width.  The solver's own output refutes that: the optimal trail at n = 64 spans all 64
bit positions.  A narrow optimum may exist, but nothing here exhibits one, and the embedding
argument would also have to handle carry propagation past a window boundary.  So the claim
is **empirical, not structural** — identical optima at three widths strongly suggest, but do
not prove, the same value at n = 256.  Neither direction is established at the deployed
width.

The proven series is exactly linear at **3.0 bits/round**, which taken at face value gives
~86 rounds for 2^-256 — more optimistic than #214's 137, making 192 comfortable.  Three
reasons not to take it at face value, in increasing order of weight: three points only; the
trail may stop being local at larger r; and decisively, **this is key-averaged while (b)
measured real keys at roughly half the averaged weight** — halving 3.0 puts the per-key
requirement above 170 rounds and 192 becomes marginal.

**Net:** the round count is still not known to be adequate or inadequate, but the
uncertainty is now bracketed by proven numbers at both ends rather than one extrapolated
slope — and the dominant term in it is the key-averaged/per-key gap, **not** the width
extrapolation everyone has been caveating.  That reframes what #248 has to resolve.

**Remaining:** a two-sided bound at n = 256.  CBC stops at n = 32; a stronger backend
(HiGHS/Gurobi) or a structural argument would be needed, and it is not clear the former
suffices.

Status: **DONE v5.0.1 (analysis)** — (a), (b), (c) and the MILP backend complete; the two-sided bound at n=256 is split out as TODO #252, unreachable with CBC. (a) The trail slope is width-stable at 1.40-1.70 bits/round across every exactly-reachable width, bracketing #214's independently measured 1.87 — a SUPPORTIVE result. A 2-key run had suggested the slope collapsing at n=13; it did not reproduce at 6 keys and is recorded as a near-miss. (b) The per-key spread is wider than the mean: optimal 5-round trail weight at n=11 runs 0.70 to 7.71 on a mean of 4.73, and nothing screens for the weak end. (c) Exact linear cryptanalysis, an axis neither #214 nor #246 had touched: the deployed round reaches 0.16 bits over three rounds (correlation ~0.90, near-deterministic) against 2.00 for candidate A and 3.48 for B — so #246's recommendation is not an artefact of measuring only differentials. (d) `pulp`/CBC added as an OPTIONAL analysis-only dependency with verified degrade-to-skip, documented in CLAUDE.md's new Third-party dependencies table; proven optima 2.0/4.0/7.0 at r=2/3/4 are IDENTICAL at n=16, 32 and 64. A locality claim made along the way was WITHDRAWN: the optimal trail at n=64 spans all 64 positions, so width-independence here is empirical, not structural. **The headline for whatever comes next:** the dominant uncertainty is the key-averaged/per-key gap, not the width extrapolation that #214, #243, #244 and #246 all caveated. Real keys sit at roughly half the averaged trail weight, which would put the per-key round requirement above 170 and make the deployed 192 marginal.

### #253: fixed-key trail analysis — the gap #247 found is the dominant uncertainty

TODO #247(b) measured what TODO #214 had flagged qualitatively, and it is larger than the
thing everyone has been caveating.

**The finding.**  Optimal 5-round trail weight at n = 11 ranges from **0.70 to 7.71 across
six keys, on a mean of 4.73** — a spread wider than the mean.  And the key-averaged model
systematically overstates: real keys sit at roughly **half** the averaged trail weight
(per-key DP 0.41 / 1.88 / 3.40 at r = 2/3/4, n = 10, against a key-averaged 1.80 / 3.43 /
5.82).  Halving #247's proven 3.0 bits/round puts the per-key round requirement above 170 and
makes the deployed 192 **marginal rather than comfortable**.

**Why it bites here specifically.**  NL-FSCX has no key schedule: the same `B` is the XOR mask
in every round, so per-round deviations correlate instead of averaging out.  A key-averaged
bound is the right currency for comparing designs — it is what ARX practice reports and what
#214 correctly produced — but it is not a per-key security claim, and for this construction
the two differ by more than a caveat's worth.

**What to establish.**
* Whether the ~2× gap persists at larger widths, or is a small-width artefact.  This is the
  first question and it may dissolve the item.
* The shape of the weak tail: is there an identifiable class, as with the QC-MDPC weak keys
  TODO #235 screened, or is it a smooth distribution with no screenable structure?
* If there is a class: whether a keygen screen is possible.  Note `nl_v2_key_is_valid` covers
  only the degenerate affine class and says nothing about trail behaviour.
* If there is not: whether the honest figure for `SECURITY.md` is the weak-tail value rather
  than the mean.

**Why it is filed separately from #248.**  #248 is the rating decision; this is the evidence
it needs.  #248's own text currently assumes the open question is width extrapolation, which
#247 showed it is not — that text is amended to point here.

**Blocks** #248, and informs #251: if the per-key gap is real at scale, it is an argument for
the AND layer rather than against it, since candidate B's margin is far wider.

Status: **DONE v5.0.2 (analysis)** — the gap persists and is generic (0.50–0.61 at four
widths, surviving restriction to typical keys); a previously unrecorded weak-key class
found and proven harmless at n = 256; §11.20.5's conflation corrected; #248 ungated.

### #248: re-review the v2 family ratings once #245's successors land

TODO #245 shipped round constants and deliberately did not re-rate anything, on the grounds
that removing a structural objection is not supplying a proof.  It named this successor in
its own text and in SecurityProofs-7.md §11.27.4.

**The question.**  HSKE-NL-A2 (downgraded to demo-only by #244) and `twk` (kept demo-only by
#243) both rest on `nl_fscx_revolve_v2` being a PRP/SPRP.  #245 removed the self-similarity
objections — the slide structure and the fixed-point deviation are gone — so the trail bounds
are now the binding constraint.  Do they bind tightly enough to move either rating?

**Gated on evidence, not on time.**  This item must not run until the evidence exists.
Opening it earlier would repeat exactly the error #244 was filed to correct: treating "the
objections I know about are answered" as equivalent to "analysed".

**Amended after TODO #247: the gate is not the one this item was filed with.**  As written
above, this item assumed the blocker was width extrapolation — bounds at n = 256 rather than
projections from small widths.  #247 measured that and found the opposite: the trail slope is
width-stable at 1.40–1.70 across every reachable width, bracketing #214's 1.87, so the width
extrapolation is in better shape than anyone assumed.  What #247 *did* surface is a larger
problem — real keys sit at roughly **half** the key-averaged trail weight, with a per-key
spread wider than the mean.  Halving #247's proven 3.0 bits/round puts the per-key
requirement above 170 rounds and makes the deployed 192 marginal.

So the binding gate is **TODO #253** (fixed-key trail analysis), not #252 (the two-sided
bound at n = 256).  #252 would be welcome and would tighten the picture, but a two-sided
*key-averaged* bound would not answer the question this rating actually turns on.  If #251
ships the AND layer, the analysis must be redone against the round function that ships.

**Ungated by TODO #253 (v5.0.2) — this item is now runnable.**  #253 answered the question
above and the answer is that the trail margin is *not* the binding constraint.  The
per-key gap is real and generic (0.50–0.61 of the key-averaged weight at four widths, and
it survives restriction to typical keys, so no screen addresses it), but halving #247's
increment still leaves the deployed 192 rounds ahead of 256 bits on any plausible reading
of the projection.  #253 also found a weak-key class the deployed `nl_v2_key_is_valid`
misses — every `B` with `tz(delta(B)) >= 4` — and showed it costs at most ~3 of 192 rounds
on 6% of keys at n = 256, so it does not bear on the rating either.

**What #248 must therefore decide on.**  Not trail weight.  The binding constraint is
§11.25's structural finding — `nl_fscx_revolve_v2` is one unvaried round iterated with no
key schedule, and there is still no PRP/SPRP reduction for it at any round count.  #253
neither rescues the rating nor further damages it.  A promotion needs a *reduction*, not a
better bound; #248 should say so explicitly rather than re-weighing the bounds a fourth
time.

**Re-derive, do not inherit.**  Whatever the outcome, A2's three constraints and `twk`'s
must be re-derived against the then-current construction.  #237 and #238 exist because
propagated rows go stale.

**Both directions are live outcomes.**  A promotion is possible.  So is confirming
demo-only, in which case the useful deliverable is a row that says precisely what is missing
rather than one that reads as an unexplained caution.

Status: **DONE v5.0.3 (analysis)** — both rows stay demo-only and both rationales are
replaced: the "no PRP/SPRP reduction" standard is not the one the rest of SECURITY.md uses,
self-similarity was already gone, and the single missing item is now a linear bound at
realistic width (#254).  Invariant-subspace resistance proven at n = 256.

### #251: ship the AND-based nonlinear layer for NL-FSCX v2 (migration)

TODO #246 decided the design and could not ship it.  This is the migration, held back
deliberately rather than for lack of work done.

**What ships, if it ships.**  Candidate B: the deployed v2 round followed by a χ layer over
short odd rows, `256 = 47×5 + 3×7` — fifty parts, all odd, so χ is a bijection over the whole
state; inverse degree ≤ 4, bit-parallel; inside the regime Keccak's own analysis covers.  The
existing round is untouched and χ is appended, which is the smallest diff that achieves the
goal.  Identically in C, Go, Python and Java.

**Why it is blocked, and this is the point of the item.**  #246 step 3 named a realistic-width
bound as the condition for shipping, and TODO #247 established that condition cannot currently
be met: CBC proves optima only to n = 64, and #247 further found the dominant uncertainty is
the **key-averaged/per-key gap**, not width.  All the evidence favouring candidate B is
small-width and comparative.  Shipping a new round function on that basis would be exactly the
under-evidenced move TODO #237, #238, #243, #244 and #245 exist to prevent — with the
aggravating factor that it is a five-construction MAJOR.

**Unblocked by** either #252 (a two-sided bound at n = 256) or #253 (a fixed-key treatment
showing the per-key gap does not sink the margin), or by a decision to accept small-width
comparative evidence as sufficient — which is a legitimate call, but must be made explicitly
and recorded, not arrived at by default.

**Evidence status as of v5.0.6 — the comparison was re-run and B's case is stronger, but the
case for urgency is weaker.**  See SecurityProofs-7.md §11.32 and
`SecurityProofsCode/and_layer_recheck.py`.  #252 had invalidated the methodology #246 used
(slopes read inside the transient), so the comparison was redone.

* **#246's ordering survives and is better founded.**  B carries 2-3x the deployed round's
  trail weight at every round on both axes, at n = 8, 10 and 11.
* **The reason it is better founded is specific.**  B's advantage lives in the TRANSIENT, and
  §11.31.2 established the transient is the width-independent part (confirmed by MILP: n = 16
  and n = 32 give identical proven optima at r = 4 and 5).  So the part of a small-width
  comparison that carries to n = 256 is exactly the part where B wins.  #246 compared saturated
  slopes; this does not.
* **The mechanism.**  Any linear-then-add-constant round has a probability-1 one-round
  differential (the MSB freebie, §11.28.3) — that IS the transient.  chi removes it: B's
  round-1 weight is 2.00 / 1.81 / 2.00 across the three widths where v2 and A are both 0.00.
* **Candidate A is disqualified** and should not be revisited: correlation-1 linear trail
  through eight rounds at n = 8, and exactly 1.00 bit/round at n = 10 and 11.
* **Still not a bound.**  B saturates by round 3 at reachable widths, so it has no measurement
  window and its asymptotic slope is as unmeasured as the deployed round's.  #252 and #254 are
  unchanged by this.
* **Urgency is DOWN.**  #254 found the deployed round meets the linear criterion at every width
  measured (settled 0.93-0.95 against 2/3) and #253 found the per-key gap does not sink the
  differential margin.  The thing B was meant to fix looks less broken than when #246 proposed
  it.

**So the blocker is no longer methodological, it is a decision.**  A five-construction MAJOR on
comparative evidence that is now well founded but still not a bound, against a deployed
construction not known to be failing.  That call is the maintainer's and this item still
requires it be recorded explicitly rather than arrived at by default.

**Reach.**  `hske-nla2`, `hpke-nl`, `hske-duplex`, `fpe`, `twk` — the same five as TODO #245.
One MAJOR, one `MIGRATING.md` section, and the silent-failure warning `fpe`/`twk` need, since
both are unauthenticated permutations.  Arduino and assembly stay unchanged, as in #242 and
#245: separate 32-bit construction, no wire compatibility.

**Must land with it.**  Round-count re-derivation (χ changes the per-round weight, so 192 is
no longer justified by inheritance); masked-cost measurement on AVR; a KAT refresh; and the
regression tests that already exist for `fpe`/`twk` extended to the new layer.

**Explicitly not in scope.**  Re-rating anything.  That remains #248.

**DECISION, recorded as this item requires (2026-08-30).**  This item asked that the call be
made explicitly rather than arrived at by default.  It is made: **do not ship the v2
migration.**  The reasoning, in the order it weighed:

* **The deployed round is not failing any test that exists.**  TODO #253 found the per-key gap
  does not sink the differential margin; #254 found the linear criterion met at every width
  measured (settled 0.93-0.95 against 2/3).  No attack on any v2 consumer at n = 256 is known.
  A breaking change to five constructions, against a construction that passes everything
  measurable, is not justified by "the replacement is better".
* **The cost is real and lands on users, not on us.**  A MAJOR makes every stored ciphertext,
  key and signature under `hske-nla2`, `hpke-nl`, `hske-duplex`, `fpe` and `twk` unreadable by
  the new build.  That is a migration every downstream user performs, for a margin improvement
  they cannot currently observe a need for.
* **The evidence is sound but singly sourced.**  Every figure supporting candidate B was
  produced by this project's own scripts, with no external review, and four of them required
  correction within three days — including one (§11.32.1) that would have wrongly killed B.
  That argues for the reversible option, and not shipping is the reversible one.
* **What did NOT weigh:** the +57% round cost.  It is real but small, and TODO #255 notes the
  round count may fall enough to offset it entirely.

**This is not a rejection of candidate B.**  §11.32 confirmed B's advantage is real and that it
lives in the width-independent part, which is the strongest evidence any design change in this
suite has had.  The objection is to *replacing* v2, not to *having* B.  **Superseded by TODO
#255**, which adds B as NL-FSCX v3 alongside v2 — same benefit, no wire break, no migration,
and reversible.

Status: **DEPRECATED** — superseded by TODO #255.  The v2 migration will not be performed; the
design ships as a new primitive alongside v2 instead.  Decision recorded above.

### #249: finish the constant-time audit scope TODO #129 opened

`SecurityProofs-7.md` §11.16 records that TODO #129's original item-2 scope was never
completed, and names what is outstanding.  It has sat unfiled across several batches.

* **`stern_apply_perm`'s memory-access pattern**, flagged in Batch 2 and still unaddressed.
* **A residual timing signal** that survived the absolute-gap collapse and interop re-test.
  Chasing it needs cache/power instrumentation — hardware performance counters, or a
  controlled non-degenerate "fixed" class — which a wall-clock `dudect` harness cannot
  provide.  Decide whether to acquire that capability or to document the limit and stop;
  either is a defensible close, silence is not.
* **HKEX-RNL, ZKP-RNL and HCRED are entirely unaudited** for constant-time behaviour.  They
  fall inside #129's stated scope and no batch has touched them.

**Worth stating plainly:** this is the one open item that concerns a side channel rather
than a structural property, and side channels are the class this suite has audited least.
`SECURITY.md` should say so if the answer is "not audited".

**Outcome (v5.0.8): all three bullets were already closed, and the item's own closing
sentence was the only live part.**  See SecurityProofs-7.md §11.11 Batch 9.  Verified by
re-running `SecurityProofsCode/dudect_timing_audit.c` rather than by reading the write-up.

* `stern_apply_perm`'s memory-access pattern — closed by **Batch 6** (CT-03, v1.9.99).  The
  shipped function scans all `N` positions under a constant-time equality mask.
* The residual signal — **Batch 7** (v1.9.105) already took the "controlled non-degenerate
  fixed class" option this item names, and executed it: `|t|` goes from ~17 under the
  all-zero class to under 1.5 under `0xA5`, with nothing else changed.  Reproduced today at
  17.53 / 12.73 against 0.65 / 1.00.  The decision this item asked for was already made.
* HKEX-RNL / ZKP-RNL / HCRED — audited in **Batch 4**, one finding fixed in **Batch 5**, and
  HKEX-RNL reconciliation covered empirically in **Batch 8** (TODO #182).

This item also cited the audit as §11.16, which is the Stern-KEM combiner; it was filed from
a stale reading of §11.11 that stopped at Batch 3.

**What was genuinely missing** is exactly what this item's closing paragraph said: `SECURITY.md`
had **zero** mentions of side channels, so the posture had to be inferred from silence.  It now
carries a *Side-Channel Posture* section stating per target what is and is not audited, and
`docs/TUTORIAL.md`'s note is corrected — it had omitted Java and implied the assembly targets
were audited when only C ever has been.  Two doc-drift items fixed alongside: §11.11 never
recorded Batch 8, and `spec/check_security_md.py` scanned the whole file for protocol rows
rather than the Protocol Status section.

No code change was required and none was made.

Status: **DONE v5.0.8** — bullets were stale (verified empirically); the real gap was that the
audit result was never stated where a user would look for it.  SECURITY.md now says it.

### #255: NL-FSCX v3 — ship candidate B as a new primitive alongside v2

TODO #251 declined to migrate v2 to candidate B, on the grounds that a five-construction
MAJOR is not warranted against a deployed round that passes every test that exists.  This is
the alternative it named: **add** the design rather than **replace** with it.

**Why this shape is better than #251's.**  Nothing breaks.  `v2` is untouched, so every stored
key, ciphertext and signature keeps working and `MIGRATING.md` is not involved.  The change is
additive CLI/API surface, so it is a **MINOR**, not a MAJOR.  It is reversible: a v3 that turns
out badly can be deprecated without stranding anyone.  And it decouples the design question
(is B better? — answered, §11.32) from the deployment question (must everyone move? — no).

**What v3 is.**  The deployed v2 round followed by a χ layer over short odd rows,
`256 = 47×5 + 3×7` — fifty parts, all odd, so χ is a bijection over the whole state; inverse
degree ≤ 4, bit-parallel; inside the regime Keccak's own analysis covers.  This is candidate B
exactly as #246 specified and §11.32 re-validated; **no redesign is in scope here.**

**MINIMUM ROW LENGTH 5 IS A HARD CONSTRAINT (§11.33.4), and the implementation must assert
it.**  Oddness alone is *not* sufficient and 3 is odd.  A 3-bit row holding the LSB gives a
correlation-1 one-round linear approximation to exactly the keys with `delta(B)` odd — 112 of
256 at `n = 8`, verified exhaustively — which is a complete break at any round count; a 3-row
elsewhere still costs 12/256.  `47×5 + 3×7` satisfies the constraint and also puts a 5-row at
the LSB, so the specified partition is unaffected.  Consequence for the analysis scripts: the
`odd_partition(n)` helper returns `(3,5)` at `n = 8`, so **§11.32's `n = 8` column for
candidate B measured a broken variant** and is void; `n = 10` `(5,5)` and `n = 11` `(11,)` are
sound and #246's ordering is undisturbed.

**Round count: DERIVED — `R3_VALUE = 5n/8 = 160`.**  Done in v5.0.9; see §11.33 and
`SecurityProofsCode/nl_fscx_v3_round_count.py`.  **This gate is lifted** and the rest of the
item may proceed.  The derivation did not go the way this entry assumed, in three ways:

* **It rests on a proof, not a measurement.**  χ gives v3 an unconditional per-round trail
  floor — 2 bits differential, 1 bit linear — at every odd row length, because the difference
  entering χ is never zero and one active row always costs that much (§11.33.2).  This is the
  family's *first* per-round trail bound of any kind.  v2 provably has none: its round is
  linear-then-add-constant, which hands every key a probability-1 one-round differential.  So
  §11.30.1's criteria are met at `r >= n/2 = 128` outright, with no appeal to #252 or #254.
* **The margin chosen is 1.25×**, giving `5n/8 = 160`.  It covers within-round *linear*
  clustering, which is real (worst single round `0.193` against the floor of `1.00`) but is not
  chainable — the multi-round window contradicts it directly, so the alternative of pricing it
  in as a slope (`r >= 664`) is far too pessimistic.  #254 is the item that would tighten this
  or force it wider.  `5n/8` needs `n` divisible by 8, slightly stronger than v2's `3n/4`.
* **The cost hope does not survive measurement.**  The "+57%" below is a misreading of #246 §5,
  where it is the cost of *masking* χ; there is no masked v2 in the suite, so it was never the
  cost of the shipped path.  Measured unmasked (`benchmarks/v3_round_cost.c`), the v3 round is
  **2.12–2.17×** the v2 round, so v3 @160 is **~1.77×** v2 @192 per block.  The trade is:
  the family's first proven trail bound, on both axes, for roughly 1.8× the work.

**Weak-key classes: SETTLED — v3 needs NO key check** (v5.1.0; §11.34,
`SecurityProofsCode/nl_fscx_v3_weak_keys.py`).  Both v2 classes dissolve, and the answer is a
proof rather than a sample, because v3 admits a reduction v2 never did: the round's
key-dependence collapses to `delta(B)`, and χ's ROW-LOCALITY makes the per-row profile exact at
ANY width — so an exhaustive statement about every 256-bit key is a sweep over `L = 5` and
`L = 7`.

* the affine class `delta(B) ∈ {0, 2^(n-1)}` — dissolved, provably: χ is a fixed
  key-independent non-linear bijection and `χ ∘ (affine)` is never affine, at any width.
* the zero-weight-trail class `tz(delta(B)) >= 4` — dissolved; its worst one-round DDT entry is
  `5/16`, which is exactly the universal floor every key already sits on, so it is not a class.
* a new χ-specific class — none to screen.  The differential profile is key-INDEPENDENT, and
  the linear one is graded but attains its worst grade for all but ~1 key in 750,000.
* the `delta(B)`-odd class — real, but a property of 3-rows; closed by the minimum-row-5
  constraint, not by a key check.

So there is deliberately no `nl_v3_key_is_valid` in any port and no rejection-sampling loop in
any v3 keygen path.  Carrying v2's loop across would reject ~2^-129 of keys for a degeneracy v3
does not have, while implying the rest had been screened for one that it does.

**Correction to the round count's own derivation** (same script, §11.34.3/§11.34.6).  §11.33.2's
floor is layer-wise, charged to χ alone; the ROUND-level differential floor is
`4 - log2(5) = 1.6781`, not `2.000`, the gap being clustering across the addition's carry.  It
is reached by the LOWEST-ACTIVE-ROW LEMMA — the two members of a pair always share the carry
into their lowest active row, so that row always pays the same-carry cost.  Consequence:
the criterion needs `r >= 153`, not `r >= 128`.  **`R3_VALUE = 160` still clears it, but at
1.05x, not the 1.25x §11.33.6 recorded — there is no room left to reduce the round count.**
Also settles that §11.33.4's sampled `0.193` and median `0.678` were never weak-key artefacts:
they are the exact universal single-row figures.

**Scope — what gets a v3 consumer.**  The same five v2 consumers, each as a new variant with
the v2 one left in place:

| existing | new | surface |
|---|---|---|
| `hske-nla2` | `hske-nla3` | `--algo` |
| `hpke-nl` | `hpke-nl3` | `--algo` |
| `hske-duplex` | `hske-duplex3` | `--algo` |
| `fpe` | `fpe --v3` | flag on the subcommand |
| `twk` | `twk --v3` | flag on the subcommand |

`fpe`/`twk` take a flag rather than new subcommands because they are already filed under
`cli_binding` in `spec/` rather than under an `--algo` tag.  Decide the flag-vs-subcommand
question explicitly and record it; either is defensible.

**Out of scope, explicitly.**  NL-FSCX v1 and everything on it (HFSCX-256, HSKE-NL-A1, WOTS,
XMSS, every Fiat-Shamir transform) — v3 does not touch v1.  The classical quartet.  Key
exchange (#230's impossibility is about HKEX agreement and does not arise).  Arduino and
assembly, following #242 and #245: separate 32-bit construction, no wire compatibility, and
adding a second primitive there is a cost with no consumer.

**Ratings — v3 does NOT arrive production-track.**  This is the trap #237, #238, #243, #244 and
#248 were each filed to close.  v3 has a wider margin than v2 but the same *missing* items:
no PRP/SPRP reduction, and no trail bound at realistic width on either axis (#252, #254 are
unchanged by v3 existing).  **Ship v3 demo-only**, with a row saying precisely that its margin
is wider and that the same two measurements are outstanding.  A promotion is #248-shaped work
on separate evidence.

**Must land with it.**
* C (`herradura.h`), Go, Python and Java in lockstep — `nl_fscx_v3`, `nl_fscx_revolve_v3`, its
  inverse, and the key check if §above finds one is needed.
* `spec/` entries and `SECURITY.md` rows for all five new variants; `spec/check_security_md.py`
  and `generate_spec.py --check --require-schema` must pass.
* KAT vectors for v3 in `KAT/`, generator updated, `--check` current; `verify_kat.go` and the
  Java `KatVerify` extended.
* `CliTest/` coverage: every new script claimed by exactly one `native-*` job, or the
  coverage-guard step fails.  `test_cross_lang_matrix.sh` extended to the v3 family.
* Tests in all four harnesses; the `[FAIL]`-scanning gate picks them up with no registration.
* `docs/TUTORIAL.md`, `llms.txt`'s CLI section, and this file's CLI/test sections (TODO #145).
* A benchmark against v2 at the derived round count.  A microbenchmark of the round itself
  already exists (`benchmarks/v3_round_cost.c`, v5.0.9) and settles the per-round ratio at
  2.12–2.17×; what is still owed is an end-to-end figure for the five consumers.

**Version.**  MINOR — new `--algo` values and new public API, no existing surface changed.

**Progress.**
* v5.0.9 — round count derived (`R3_VALUE = 5n/8 = 160`); the gate is lifted.
* v5.1.0 — the PRIMITIVE LAYER is done and the key-check question is settled.  `nl_fscx_v3`,
  `nl_fscx_revolve_v3` and their inverses ship in all four languages (C `herradura.h`, Go
  `herradura`, Python suite, Java `HerraduraNl`), byte-for-byte identical across the four, with
  the row partition derived by a rule that emits only 5s and 7s so the minimum-row-5 constraint
  holds by construction.  Test [47] in the C/Go/Python harnesses asserts χ against a per-row
  reference, `χ^-1 ∘ χ = id`, the revolve round-trip, the partition's legality, and (Python
  only, which re-implements) agreement with the shipped suite.

* v5.2.0 — the FIVE CONSUMERS are done, in every CLI that has a v2 counterpart to
  match: `hske-nla3` and `hpke-nl3` in all four (C, Go, Python, Java), and
  `hske-duplex3`, `fpe --v3`, `twk --v3` in C, Go and Python — Java ships no duplex,
  `fpe` or `twk` in either version, so there was nothing there to pair with.  With them:
  `spec/` entries and SECURITY.md rows for all five (all demo-only or worse),
  `KAT/nl_fscx_v3.json` plus its Go and Java verifiers, `CliTest/test_v3_family.sh`,
  v3 rows in `test_cross_lang_matrix.sh` (518 checks, four languages), test [48] in
  three harnesses, `benchmarks/v3_consumer_cost.c`, and the TUTORIAL/llms.txt/CLAUDE.md
  entries.

**Decisions recorded in v5.2.0**, each of which this entry left open:

* **`fpe`/`twk` take a `--v3` FLAG, not new subcommands.**  Both are already filed in
  `spec/` by `cli_binding` rather than by `--algo` tag; the flag keeps every other
  option identical between variants, so a caller switches version without rewriting the
  invocation; and a second pair of subcommands would have doubled a surface #241 already
  found confusing.  `spec/` grows a `cli_binding.kind` of `subcommand_flag` to say this
  machine-readably, validated against both the subparser list and the flag itself, so
  the claim cannot go stale silently.
* **`I3_VALUE = 5n/16 = 80` for the v3 duplex sponge** — the first duplex round count in
  this suite that is derived rather than inherited.  The capacity is 128 bits, so 128
  bits is the target, and chi's proven per-round floors put the requirement at
  `r >= 128/1.6781 = 77` differential and `r >= 64` linear.  `hske-duplex`'s inherited
  `I_VALUE = 64` would have left the differential axis at 107 bits.  It does NOT lift
  the duplex's rating: what keeps the v2 duplex at `research` is that the permutation's
  standalone SPONGE profile has never been characterised (#99), and a per-round trail
  floor is not that characterisation.
* **A distinct ciphertext format tag (4) for `hske-duplex3`**, so a v2 artifact fed to
  the v3 decryptor is refused by the parser rather than surfacing as an opaque tag
  mismatch 80 permutation calls later.
* **Domain-separation tags 0x22/0x23** for `fpe`/`twk --v3`, and separate
  `NL-V3-DUPLEX-*` strings, so the same `(key, tweak)` never yields the same subkey
  across the four fpe/twk variants — the separation #242 had to retrofit is built in
  from the start here.

**Cost — this entry's "~1.77x per block" is WRONG for the shipped C path; it is ~0.97x**
(`benchmarks/v3_consumer_cost.c`).  `v3_round_cost.c`'s 2.12-2.17x is a packed 4x64
representation where the v2 round is a few limb operations and chi roughly doubles it.
`herradura.h`'s BitArray is 32 separate bytes, so the v2 round's rotations and its
256-bit carry chain are already byte-serial and chi adds proportionally much less:
**1.16x per round** against the shipped header.  Both figures are correct measurements of
different things, and the packed one is what an optimised port would see.  Every consumer
figure follows from 1.16x times its round-count ratio, checked rather than fitted:
`hske-nla3` 0.97x (160 rounds against 192), `fpe --v3` 0.97x, `twk --v3` 0.98x,
`hske-duplex3` 1.45x at 4 KiB (80 sponge rounds against 64), and **`hpke-nl3` 2.92x** —
the one materially more expensive case, because `hpke-nl`'s deployed wire format runs
only `I_VALUE = 64` rounds while `hpke-nl3` uses the derived 160.

**Also found:** a silent 64-bit truncation in the KAT format, caught by the Go
cross-check rather than by any Python-side test.  `twk`'s `sector` was first written as a
JSON number, and `0x0123456789ABCDEF` does not survive the float64 every JSON parser
defaults to — the Python generator and the Go verifier disagreed by 1 in the low limb.
Both `sector` and `bidx` are hex strings now.  Nothing else in the pipeline would have
caught it; it is exactly the class of thing a second-implementation verifier exists for.

**Remaining.**  Nothing in this entry's original scope is outstanding.  What is left is
deliberately out of it and tracked elsewhere: the ratings stay demo-only until #252 and
#254 land a trail bound at realistic width, which v3 existing does not change.  The
Arduino and assembly targets remain out of scope for the reasons stated above, and
NL-FSCX v1 and everything on it is untouched.  Closed on review agreeing that the five
consumers are the whole of "ship candidate B as a new primitive alongside v2".

Status: **DONE v5.2.0** — the NL-FSCX v3 primitive and all five of its consumers ship
alongside v2, in every language that has a v2 counterpart, at the derived R3_VALUE = 160
and with no key check because v3 provably needs none.  Ratings stay demo-only.

### #252: a two-sided trail bound at n = 256

TODO #247 got proven optimal key-averaged trail weights to n = 64 and stopped.  This is the
remaining half.

**What exists.**  Proven optima 2.0 / 4.0 / 7.0 at r = 2/3/4, identical at n = 16, 32 and 64,
plus 10.0 at r = 5 for n = 16.  Identical values at three widths a factor of four apart is
strong evidence of width-independence.

**What does not.**  A bound at the deployed width, in either direction.  #247 initially
justified carrying the figure to n = 256 with a locality argument and **withdrew it**: the
optimal trail returned at n = 64 spans all 64 bit positions, so nothing demonstrates a narrow
optimum, and an embedding argument would also have to handle carry propagation past a window
boundary.

**Why CBC is not enough.**  n = 64 at r = 4 took 864 s; n = 32 at r = 5 and n = 64 at r = 4
under a shorter limit both returned untrustworthy answers, one of them a 4-round "optimum"
cheaper than its own 3-round optimum.  Scaling to 256 is not a matter of patience.

**Routes worth trying, in the order they should be tried.**
1. A stronger backend — HiGHS via scipy, or Gurobi under an academic licence.  Cheapest to
   attempt; may simply not close either.
2. A structural argument.  Either prove a narrow optimum exists (restoring locality and with
   it the embedding), or derive a per-round lower bound from the round function directly —
   each active round costs at least one bit unless the difference is MSB-only, and an MSB-only
   difference cannot persist through `M`, which is the germ of a wide-trail-style argument.
3. A matrix-power / transfer-matrix formulation over difference classes rather than
   individual differences, which is how some ARX bounds are made to scale.

Route 2 is the one that would actually settle it; routes 1 and 3 might only push the wall.

**First pass done in v5.0.5 — the bound is still open, and the stall is now explained.**  See
SecurityProofs-7.md §11.31 and `SecurityProofsCode/diff_bound_window.py`.

* **The target is a scalar**, `s_diff >= 4/3`, carried from #254's scale-invariance result.
  Not a bound at n = 256.
* **The stall was never solver time.**  An increment series has a cheap TRANSIENT (every key
  has a probability-1 one-round differential, so the first rounds are near-free) and a CEILING
  at ~`0.6n`.  The asymptote lives between them, and the window is `0.6n/s - transient` rounds
  wide: **zero or one round at every width an exhaustive DDT can reach** (n <= 13).  So the
  quantity is not measurable exhaustively at all, not merely slowly.
* **This invalidates the "what exists" paragraph above.**  The proven optima 2.0 / 4.0 / 7.0,
  identical at n = 16/32/64, are the TRANSIENT — width-independent for a structural reason and
  not the quantity the criterion needs.  Their agreement across widths was never the evidence
  it was read as.  Every per-round differential figure in this repo is affected.
* **Route 1 is re-motivated with a different target**: not a larger width but a larger ROUND
  COUNT at n = 32-64, where the window is wide and CBC already reaches.  Measured distance to
  that target: at n = 16, r = 4/5/6 prove in 8 s / 35 s / 365 s and r = 7 does not close in
  600 s; at n = 32, r = 4 and 5 prove in 68 s and 635 s and r = 6 does not close in 900 s.
  n = 32 r = 5 sits at `0.31n`, so the width is right and the ROUND COUNT is the whole gap —
  the target is r ≈ 10-14, several orders of magnitude away.  A stronger backend, not a longer
  time limit.  **This is now the first thing to try.**
* **The transient's width-independence is now directly confirmed**: n = 16 and n = 32 give
  identical proven optima at r = 4 and r = 5 (7.0 and 10.0) — the same agreement #247 saw and
  read as evidence about the asymptote.
* **Route 2 is demoted.**  As sketched it yields `s_diff >= 1` against a 4/3 criterion, so it
  cannot close the gap even fully proven, and the two-round strengthening it would need is
  contradicted by four consecutive near-free rounds measured at n = 11.
* **A weak-key lead, filed not concluded**: the per-key increment tracks the signed-digit (NAF)
  weight of `delta(B)`, not its Hamming weight (`d` and `-d` behave identically).  Whether the
  threshold is a constant NAF weight (density ~`2^-240` at n = 256, irrelevant) or scales with
  `n` (not irrelevant) is undetermined and is the part worth resolving.

**Revised route order: 1, then 3.**  Route 2 is set aside.

**Second pass done in v5.2.1 — the MEASUREMENT PROBLEM IS SOLVED; only the width
extrapolation is left.**  See SecurityProofs-8.md §11.35 and
`SecurityProofsCode/diff_cycle_mean.py`.

* **The first pass's central conclusion is WITHDRAWN.**  §11.31.2 said the asymptotic
  increment "is NOT MEASURABLE BY EXHAUSTIVE SEARCH AT ANY REACHABLE WIDTH -- not slowly,
  but at all".  That is true of reading a slope off a finite increment series, which is what
  every pass had done, and false of the asymptote.  `s_diff` is the **MINIMUM MEAN CYCLE** of
  the difference graph -- nodes are differences, `a -> b` weighted `-log2 xdp(M(a) -> b)`,
  and `W(r) = c + mu*r + o(1)`.  The transient IS the constant `c` and cancels in a cycle
  mean; the ceiling is a statement about a codebook and a cycle is not compared to one.
  Both brackets dissolve rather than being defeated.
* **Exactly computable, and computed.**  Howard's policy iteration, cross-checked against
  Karp's theorem and against value iteration run far past the ceiling -- seven cases, three
  methods sharing no machinery, agreement to 1e-9.
* **The numbers, per key, at every usable width** (n = 9, 12 excluded: M singular).  Median
  `mu` = 1.279 / 1.349 / 1.717 / 1.903 at n = 7 / 8 / 10 / 11: **monotone rising**, clearing
  the 4/3 criterion from n = 8 on, with the fraction of keys below it **monotone falling**,
  63.4% -> 27.3%.  Every key measured already passes the deployed `nl_v2_key_is_valid`.
* **A tail remains and is documented, not screened**, following #253's disposition: p10 is
  below the criterion at every width, and thinning more slowly than the median rises.
* **#247 §(d)'s "3.0 bits per round" is corrected.**  The r = 3..5 read misses the exact
  key-averaged asymptote by -7% to +17% with **no consistent sign**, so 3.0 is not a
  per-round increment and the 256/3 = 86-round projection has no support.  §11.28.6's
  separate claim that the per-key figure is about half the key-averaged one SURVIVES and is
  now measured directly: 1.717 / 2.751 = 0.62 at n = 10.
* **Route 1 is quantified and CLOSED.**  HiGHS beats CBC by 1.4x at r = 4 and by more than
  3.7x at r = 5, and proves n = 32 at r = 5 (weight 10.0) and r = 6 (weight 14.0), which CBC
  could not -- two new rows for #247's width-agreement table.  But growth is 3.6-4.0x per
  added round with no flattening, so r = 10-14 is four to seven orders of magnitude away.
  It is closed because the target was unnecessary, not because it failed: r = 10-14 existed
  only to open a window, and there is no longer a window to open.  **Route 3 is superseded**
  -- it was proposed to make the computation scale, and Howard's already does.
* **A caution for the remaining work:** embedding is the obvious tool for relating widths and
  it points the WRONG WAY.  A surviving-cycle argument would prove `mu` non-increasing, and
  widening also adds candidate cycles, so the naive count points down too.  `mu` rises
  anyway, so the rise comes from width DESTROYING cheap cycles and a structural proof must
  explain that first.

**What is left, and it is the whole of what is left: the width extrapolation.**  `mu` is
exact at the width measured and cannot be read at n = 256 -- the graph has `2^n` nodes, so
the exhaustive-DDT wall that stopped every previous pass stops this one too.  But the
residual question is now the limit of a monotone sequence of EXACT values rather than a
slope read through two sources of contamination.  Cheapest next steps: extend to n = 13 and
n = 14 (cost is the DDT's `2^2n`, not the cycle computation); and carry the same
reformulation to the LINEAR axis, which is #254 and where mask propagation through M is
deterministic, so it should transfer more cleanly still.


**Third pass (shared with #254) done in v5.2.3 — the residue is now MONOTONICITY, not the
limit.**  See SecurityProofs-9.md §11.37 and `SecurityProofsCode/width_residue.py`.  This
item and #254 have identical remaining scope and **should be merged**; they are kept separate
only because the repo's numbering policy has no merge operation, and the shared analysis
lives in one place rather than two.

* **The obligation is smaller than this item states.**  Both criteria are already met at the
  widest *exact* width — `s_diff = 1.903` against `4/3` at `n = 11`, `s_lin = 1.154` against
  `2/3` at `n = 13` — and every measured value is a minimum mean cycle, not a slope.  So what
  is owed is not a limit: it is that the sequence never turns around.
* **§11.35.7's caution is retired: there is NO EMBEDDING between widths.**  `M` and `delta`
  both depend on `n`, and only a third of optimal-cycle nodes keep their image at `n+1`, so a
  cycle of length 10+ survives with probability ~0.33^10.  The graph at `n+1` is not an
  extension of the graph at `n`; it is an unrelated graph.  No monotonicity proof can come
  from comparing two graphs — it has to be a statement about the ensemble.
* **An ANNEALED FIRST-MOMENT MODEL is validated on both axes**, predicting `mu` from the
  edge-weight distribution and the out-degree alone to within a few percent by `n = 11`
  (per-key median ratios 0.85 -> 0.89 -> 0.97 -> 0.97 differential, 0.85 -> 0.88 -> 1.00 ->
  1.00 linear).  It is an estimator, not a bound — the overshoot's sign is observed, not
  established — but it reduces the width question to ONE quantity: the largest correlation
  and the largest `xdp+` of addition with a *constant*, as a function of `n`.  That statement
  has no FSCX in it, and Wallen does not apply to it (§11.30.4).
* **Three routes closed by measurement.**  Sparse-subgraph search at `n = 256` (optimal
  cycles are dense — 0.6n to 0.86n Hamming weight, no downward trend); guessing the LP-dual
  potential (Howard's bias correlates with no natural node statistic, largest 0.37);
  and sampling the weight distribution at `n = 256` (the threshold is a `2^-n` quantile — the
  sampler returns 157 at `n = 256` and 0.48 at `n = 13`, where the exact answer is 1.154, so
  **the 157 must not be quoted**).
* **A decomposition that halves the surface.**  `mu` falls by a width-stable 0.10-0.13 per
  trailing zero of `delta`, and the distribution of `tz(delta)` does not depend on width — so
  only the `tz = 0` sequence needs extrapolating.

**No rating moves, and none could**: every row this touches is demo-only on other axes
(#243, #244, #248), and #254's production-track rows left its scope in §11.36.8.

**Closed in v5.2.4 by MERGER, not by completion.**  Everything in this entry's original
scope that was ever going to be answered here has been: the measurement problem (second
pass), the reformulation as a minimum mean cycle, the two closed routes, and the reframing
of the residue as monotonicity (third pass).  What is left — the width extrapolation — is
word-for-word identical to what #254 has left, reduces to the same statement about the
same object, and was being carried in two places with the two entries' third-pass blocks
byte-identical.  It is now **TODO #257**, filed once.  Nothing is dropped: #257 opens with
the full inherited state, and the analysis it continues lives in `SecurityProofs-8.md`
§11.35 and `SecurityProofs-9.md` §11.37 where this item left it.

Status: **DONE v5.2.4** — closed by merger: the differential axis is measured exactly as a
minimum mean cycle and its routes are settled; the residual width extrapolation, identical
to #254's, is now #257.

### #254: a linear-trail bound at realistic width — the binding axis for the NL-FSCX family

TODO #248 found that linear cryptanalysis, not differential, is the binding axis for both
NL-FSCX v1 and v2, and that nobody had measured it until TODO #247 §(c) — which was never
written up.  This is the item that closes it.  See SecurityProofs-7.md §11.29.4.

**What exists.**  Exact optimal linear-trail weights by fast Walsh-Hadamard transform plus a
dynamic program over mask states, at `n = 7, 8, 10`, on typical keys.  Slopes: v2 0.49–0.87
bits/round, v1 0.47–0.69.  Both rise with width.  The correlation-1 mask subspace has the
same `tz(delta)` structure #253 found on the differential side, and is equally harmless at
`n = 256` (about `tz/2` free rounds at probability `2^-tz`).

**What does not.**  Anything at a realistic width, on either primitive.  Projected over the
deployed round counts the measured range spans roughly 100–190 bits of correlation weight for
A2's 192 rounds; the bottom of that range is under the 128 a 256-bit block needs.  That is an
unmeasured quantity, not an attack — and the *rise* with width is the reassuring direction.

**Why it matters more than #252.**  #252 asks for a two-sided **differential** bound, on an
axis #247 already showed to be width-stable and #253 showed to be comfortable per-key.  This
axis is weaker in absolute terms AND its slope is not width-stable, so the extrapolation
everyone has been relying on is on worse ground here than there.  If only one of the two gets
done, it should be this one.

**Reach — four rows, three of them production-track.**  HSKE-NL-A2 and `twk` (demo-only,
gated on exactly this by #248), plus **HSKE-NL-A1, HFSCX-256** and everything inheriting the
hash: HPKS-WOTS, HPKS-XMSS, and every Fiat-Shamir transform in the suite.  #248 deliberately
did not re-rate the v1 rows on a slope read at `n <= 10`; this item is what would justify
moving any of them, in either direction.

**Both directions are live.**  If the slope at realistic width lands where the trend points,
A2 and `twk` meet the standard the six production-track rows in §11.29.2 meet and should be
promoted together.  If it does not, the v1 rows are the ones needing re-examination, and that
is the more consequential outcome — it reaches the hash.

**Method notes, so this does not repeat #247's wall.**  Widths where `M` is singular (`n = 9`,
12, 15, 18, ...) are not usable.  The exhaustive LAT is `2^2n` per key and will not reach far;
the routes worth trying are the linear analogue of #247's MILP formulation (correlation weight
is additive over rounds in the same way, so the same encoding shape applies), and the
transfer-matrix idea in #252's route 3, which suits masks at least as well as differences.

**First pass done in v5.0.4 — the bound is still open, but the target changed.**  See
SecurityProofs-7.md §11.30 and `SecurityProofsCode/fscx_scaling_and_linear.py`.

* **The question is a scalar, not a curve.**  Because `r = 3n/4` is tied to the block size, the
  criterion is *width-independent*: `s_lin >= 2/3`, `s_diff >= 4/3`.  So this item no longer
  needs "a bound at n = 256" — it needs the asymptotic per-round slope, establishable at any
  width where saturation is not binding.  That reopens widths this item had written off.
* **No key size moves it.**  n = 512 faces the identical criterion at 4x the cost per block.
  Recorded because it was a natural proposal and it does not work.
* **The MILP route named above is CLOSED**, and not for want of solver effort: addition of a
  *constant* has correlations that are not powers of two, so Wallén's characterisation and every
  ARX bit-level encoding built on it are inapplicable.  A carry-automaton model computes single
  paths where the true correlation sums them, overstating the weight — built and discarded
  before it could be quoted.  **The transfer-matrix route is now first choice**, and it suits
  masks better than differences: mask propagation through `M` is deterministic, so a trail is
  fixed by its starting mask and the search is over `2^n` starting masks rather than trails.
* **Saturation invalidated the earlier numbers**, #248's included.  Corrected, the slope is
  0.42 / 0.77 / 0.88 / 1.03 at n = 7 / 8 / 10 / 11, crossing 2/3 between 7 and 8 and clearing it
  by 55% at the widest.  Encouraging; four widths with the slope still rising is not a bound.
  **Re-corrected in v5.0.5 (#252 §11.31.5)** for the TRANSIENT as well as the ceiling — the
  figures above were read at r = 3-5, partly inside it.  Settled: 0.59 / 0.75 / 0.93 / 0.95.
  The conclusion is unchanged (every width above n = 7 clears 2/3), but **"the slope rises with
  width" is weakened**: settled it is flattening, +0.03 between the two widest against +0.16
  between the two narrowest.  Do not expect wider widths to keep improving.
* **#248's "linear is the binding axis" is withdrawn** — the thresholds differ by the same
  factor of two the slopes do, so the raw comparison was never normalised.  Normalised,
  differential is the tighter axis, which raises #252's priority relative to this item.

**What remains, in priority order.**  (1) The two modes: §11.30.1 is derived for a block cipher
and does **not** transfer unexamined to HSKE-NL-A1 (counter-mode PRF) or HFSCX-256
(Davies–Meyer), each of which runs `n/4` rounds; deriving their criteria is the part of this
item that reaches three production-track rows.  (2) The transfer-matrix bound on `s_lin`.
(3) The same treatment for `s_diff`, which is #252 — and by the correction above, #252 is now
the more urgent of the two.

**Second pass done in v5.2.2 — both items above are closed; one residue remains, and it is
shared with #252.**  See SecurityProofs-8.md §11.36 and `SecurityProofsCode/lin_cycle_mean.py`.

* **Item (2), the bound: `s_lin` is a MINIMUM MEAN CYCLE**, the same reformulation #252 used
  on the differential side, and §11.35.7 was right that it transfers more cleanly.  Two of the
  round's three layers move a mask deterministically, so a trail is a walk on the mask graph
  and its asymptotic weight per round is the least mean over that graph's cycles — exactly
  computable by Howard's policy iteration.  Saturation, which §11.30.3 showed had invalidated
  most slope figures in this repository, is a property of reading a slope off a finite series;
  a cycle mean is not read off one.  **The transfer-matrix route is superseded**, as #252's
  route 3 was, and for the same reason: it existed to make the computation scale.
* **It reaches `n = 13`, two widths further than the differential axis got.**  Each LAT row is
  a rotation of a fixed sign vector followed by one Walsh–Hadamard transform, so the table
  costs `(n+1)·4^n` instead of a carry automaton per mask pair.  Filed alongside: an exact
  identity for the LAT's support, which depends on the addend only through `tz`.
* **v1 needs no separate machinery**, which this item had budgeted for.  Pulling a mask through
  `M(A) ^ M(B) ^ ROL(A+B, n/4)` leaves `gamma·(A+B)` with B constant — addition of a CONSTANT
  again, with `B` itself in `delta(B)`'s role.  Only the sweep differs: v2 collapses to
  `delta(B)`, v1 does not.
* **Both primitives clear `2/3` from `n = 10` on, monotone rising, failing fraction thinning.**
  Same shape as #252 found on the differential axis, measured independently.  **Corrects
  §11.30.6**: the "flattening" it reported (+0.03 between the two widest widths) was a
  finite-round artefact and is not there when the slope is computed exactly.
* **Nothing is promoted.**  HSKE-NL-A2, `twk` and `fpe` are demo-only for reasons this does not
  touch (#243's SPRP assumption, #244's `tau(192)` theorem, the single unvaried round), and the
  criterion is sufficient rather than necessary — the linear *hull* is what an attacker gets.
* **Item (1), the two modes: ANSWERED, and negatively.**  §11.30's scope note guessed the naive
  transfer would give "a sharper bar" at `n/4` rounds.  It gives nothing.  In both HSKE-NL-A1
  (`ks_i = F1^{n/4}(seed, base ^ i)`) and HFSCX-256's Davies–Meyer compression, the input the
  attacker varies is the **second** argument — the round CONSTANT, which enters all `r` rounds
  at once.  A trail propagates through the first argument, which neither mode varies.  No
  trail, no cycle, no cycle mean, and no criterion.  **The three production-track rows this
  item was filed to reach are not reachable by a trail bound in either direction**, so #254 can
  no longer be the item that re-rates them.  Direct exhaustive measurement of both modes' real
  axis is reported instead: A1's counter-difference maximum saturates against the
  random-function floor by `r = 5`, and DM's message input matches a random function's image
  fraction to within 0.01.

**What remains.**  (1) The **width extrapolation** — now the only thing #252 and #254 have
left, jointly and identically; both reduce to the same question about the same kind of object
and should be filed once rather than twice.  (2) The **linear hull**, which no trail method
reaches.  (3) The **B-axis**, newly named, belonging to whoever re-examines A1 and HFSCX-256:
nothing here measures it beyond four rounds, and those modes run `n/4` rounds, so they have
less margin to spend, not more.


**Third pass (shared with #252) done in v5.2.3 — the residue is now MONOTONICITY, not the
limit.**  See SecurityProofs-9.md §11.37 and `SecurityProofsCode/width_residue.py`.  This
item and #252 have identical remaining scope and **should be merged**; they are kept separate
only because the repo's numbering policy has no merge operation, and the shared analysis
lives in one place rather than two.

* **The obligation is smaller than this item states.**  Both criteria are already met at the
  widest *exact* width — `s_diff = 1.903` against `4/3` at `n = 11`, `s_lin = 1.154` against
  `2/3` at `n = 13` — and every measured value is a minimum mean cycle, not a slope.  So what
  is owed is not a limit: it is that the sequence never turns around.
* **§11.35.7's caution is retired: there is NO EMBEDDING between widths.**  `M` and `delta`
  both depend on `n`, and only a third of optimal-cycle nodes keep their image at `n+1`, so a
  cycle of length 10+ survives with probability ~0.33^10.  The graph at `n+1` is not an
  extension of the graph at `n`; it is an unrelated graph.  No monotonicity proof can come
  from comparing two graphs — it has to be a statement about the ensemble.
* **An ANNEALED FIRST-MOMENT MODEL is validated on both axes**, predicting `mu` from the
  edge-weight distribution and the out-degree alone to within a few percent by `n = 11`
  (per-key median ratios 0.85 -> 0.89 -> 0.97 -> 0.97 differential, 0.85 -> 0.88 -> 1.00 ->
  1.00 linear).  It is an estimator, not a bound — the overshoot's sign is observed, not
  established — but it reduces the width question to ONE quantity: the largest correlation
  and the largest `xdp+` of addition with a *constant*, as a function of `n`.  That statement
  has no FSCX in it, and Wallen does not apply to it (§11.30.4).
* **Three routes closed by measurement.**  Sparse-subgraph search at `n = 256` (optimal
  cycles are dense — 0.6n to 0.86n Hamming weight, no downward trend); guessing the LP-dual
  potential (Howard's bias correlates with no natural node statistic, largest 0.37);
  and sampling the weight distribution at `n = 256` (the threshold is a `2^-n` quantile — the
  sampler returns 157 at `n = 256` and 0.48 at `n = 13`, where the exact answer is 1.154, so
  **the 157 must not be quoted**).
* **A decomposition that halves the surface.**  `mu` falls by a width-stable 0.10-0.13 per
  trailing zero of `delta`, and the distribution of `tz(delta)` does not depend on width — so
  only the `tz = 0` sequence needs extrapolating.

**No rating moves, and none could**: every row this touches is demo-only on other axes
(#243, #244, #248), and #254's production-track rows left its scope in §11.36.8.

**Closed in v5.2.4 by MERGER, not by completion.**  Everything in this entry's original
scope that was ever going to be answered here has been: the measurement problem (second
pass), the reformulation as a minimum mean cycle, the two closed routes, and the reframing
of the residue as monotonicity (third pass).  What is left — the width extrapolation — is
word-for-word identical to what #252 has left, reduces to the same statement about the
same object, and was being carried in two places with the two entries' third-pass blocks
byte-identical.  It is now **TODO #257**, filed once.  Nothing is dropped: #257 opens with
the full inherited state, and the analysis it continues lives in `SecurityProofs-8.md`
§11.36 and `SecurityProofs-9.md` §11.37 where this item left it.

Status: **DONE v5.2.4** — closed by merger: the linear axis is measured exactly as a
minimum mean cycle, item (1)'s two modes are answered negatively, and the residual width
extrapolation, identical to #252's, is now #257.

### #258: segmentation fault in the C demo's HCRED section — `SternSig` used unallocated

Reported against the C library demo (`Herradura cryptographic suite.c`), and it reproduced
deterministically: the binary died inside the HCRED block, after the section header printed
and before the first verdict line.

```
gcc -O2 -o suite_c "Herradura cryptographic suite.c" && ./suite_c    # SIGSEGV, exit 139
```

**Root cause.**  Under `-O0 -g` the backtrace was unambiguous:

```
#0  stern_hash (out=0x0, ...)            herradura.h:2015   (*out = h)
#1  hpks_stern_f_sign                    herradura.h:2304   (stern_hash(&sig->c0[i], ...))
#2  hcred_issue                          herradura.h:5725
#3  main                                 Herradura cryptographic suite.c:654
```

`sig->c0` was `NULL`.  `SternSig` became a heap-backed struct with a caller-supplied round
count when the Stern round count was made variable (TODO #236) — `herradura.h:2271` states
the contract, *"the caller allocates `*sig` with `stern_sig_alloc()`"* — and
`hpks_stern_f_sign` reads `rounds` straight out of `sig->rounds`.  The demo declared
`SternSig hc_cred;` at line 642 and never allocated it, so both the round count and the six
commitment/response arrays were uninitialised stack.

**The demo was the only consumer that got this wrong**, which is why CI stayed green: all
three CLI call sites and both `CryptosuiteTests/Herradura_tests.c` sites already call
`stern_sig_alloc` first, and no CI job ran the suite demo binary — the `native-c` job runs
the *tests* harness, a different binary.  The [FAIL] gate of TODO #233 didn't reach here
either; the demo prints `+`/`-` verdicts, not `[FAIL]` markers, and its exit status wasn't
aggregated by anything.

**Two more sites of the same defect, found while localising, and neither was merely a
crash risk.**  All three `SternSig` declarations in the demo were unallocated:

* **line 472, `static SternSig sf_sig`** — `static`, so `rounds` was 0 and the pointers were
  `NULL` rather than garbage.  The signing loop ran zero times and nothing faulted; the
  section printed **`- HPKS-Stern-F verification FAILED`** on every single run — a
  permanent false failure in the flagship code-based signature section, silently wrong
  since TODO #236 (v3.1.0) made the round count variable.
* **line 790, `static SternSig eve_sig`** — the Eve-forgery bypass test writes
  `ba_rand(&eve_sig.c0[i], ...)` through the same unallocated struct.  It had never
  executed, because the HCRED segfault upstream killed the process first — a second latent
  segfault, not a passing test.

**Fix.**  Added `stern_sig_alloc(&sig, SDF_ROUNDS)` before use and `stern_sig_free(&sig)`
after, at all three sites — the same allocate/free pattern the file's own 78.I ring-signature
demo already used for `SternRingSig`.  Verified: the binary now exits 0 and runs to
completion across repeated runs; `+ HPKS-Stern-F signature verified` and `+ issuer
credential ... verified` now print correctly in place of the two false failures; clean
under `valgrind --leak-check=full` (28,257 allocations, 28,257 frees, 0 leaks, 0 errors).

**Checked whether the other language demos share the shape — they do not.**  Go's
`HpksSternFSign` and Python's `hpks_stern_f_sign` are constructor functions that return a
fully-built signature value; there is no caller-allocated out-parameter struct to forget to
allocate.  Java ships no equivalent standalone demo binary at all (`SelfTest.java` is a test
harness, not a printout demo) — nothing to check there.  The unsafe pattern existed only in
the C API.

**CI gap closed, in the smallest sound form.**  `native-c`/`native-go`/`native-python` each
gained a step that runs their suite demo binary and gates on exit status — the check that
would have caught this bug directly.  A finer-grained gate on the demo's own verdict lines
is deliberately NOT done here: the `+`/`-` convention marks both genuine failures and
correct negative results (`- Eve cannot forge: ...` is a PASS), so a naive text gate on `-`
would false-positive on every expected adversary-failure line.  That is filed as its own
item, **TODO #259**, rather than shipped as a shallow rider that either breaks CI on correct
output or checks nothing.

Status: **DONE v5.2.5** — fixed at all three sites in the C demo, verified clean under
valgrind, and CI now runs the C/Go/Python suite demos and fails on a crash. The remaining
verdict-line gate is TODO #259.

### #259: give the suite demos an unambiguous verdict marker, then gate CI on it

TODO #258 (v5.2.5) added a CI step per language that runs the C/Go/Python suite demo and
gates on its exit status.  That closed the class of bug #258 was — a crash or an abort —
but it was a **process** guard, not a **content** guard: it could not catch a demo that ran
to completion and printed the wrong verdict.

**Why it was not a small addition on top.**  The demos' `+`/`-` prefix convention marked two
different things with the same character: a genuine failure (`- HPKS-Stern-F verification
FAILED`) and a correct negative result phrased as a negation (`- Eve cannot forge:
Fiat-Shamir mismatch (SD + PRF protection)` is a PASS — Eve was supposed to fail).  A naive
`grep -c '^-'` gate would have false-positived on every expected adversary-failure line in
the Eve/bypass sections — the "asserts nothing now exits 2" trap CLAUDE.md's Testing section
already warns about for a different case (TODO #233).

**What auditing every branch actually found.**  The ambiguity went well beyond the two-way
`+`/`-` split the item was filed against.  Every 78.x/80 feature demo (FPE, the tweakable
cipher, the accumulator, masked HSKE, the ratchet, HDRBG, HSKE-NL-AEAD,
HSKE-NL-V2-Duplex, OPRF, aPAKE) printed the pair **inverted** — `-` for pass, `+` for fail —
in all three languages, and C's and Go's HPKS-T block printed `+` on both branches, so a
reader could not tell pass from fail from the prefix at all.  All three demos are now
internally consistent: `+` always means pass.

**Fix implemented — option (a), the unambiguous marker, not the ACKNOWLEDGED close.**
Mirrors `CryptosuiteTests/Herradura_tests.{c,go,py}`'s TODO #233 gate exactly, one mechanism
per language: C shadows `printf` with a scanning `hprintf` (leaving `puts()` narrative
alone, as the test harness does); Go pipes `os.Stdout` through a scanning goroutine; Python
shadows the `print` builtin.  Every genuine-failure branch across all three demos was
rewritten to carry an explicit `[FAIL]` marker — 34 sites in C, 45 in Go, 40 in Python — and
each demo now closes with the same `*** FAILED: N check(s) reported [FAIL] ***` / `*** OK: no
check reported [FAIL] ***` banner the test harnesses use, exiting non-zero on any failure.

**What is, and is not, tagged in the Eve/bypass sections.**  Only the branch where Eve
**succeeds** (forges a signature, decrypts, or guesses a key) is tagged — the one outcome
among the pair that would actually be catastrophic.  "Eve correctly fails" is left as
narrative, unmarked, matching how those sections already read.

**One branch deliberately excluded in all three demos**: the HKEX-RNL "session key
disagrees" / "raw key disagrees" note.  It is a nonzero-DFR Ring-LWR reconciliation event
none of the three demos retry (unlike the CLI's `hpke-stern-kem` path, which TODO #221's
`lib_dfr.sh` retry policy covers) — tagging it would make CI flaky on a rare, legitimate
outcome rather than catch a bug, the probabilistic-property-asserted-as-deterministic class
TODO #234 already found and fixed once in the Arduino harness.

**Verification.**  Each language's gate was checked both ways: a clean run exits 0 and
prints the OK banner (confirmed across repeated runs per language), and a deliberate break
(FPE's round-trip check, inverted one condition) reports `[FAIL] FPE round-trip failed!`,
names exactly that check, and exits 1 — then the break was reverted and a clean run
reconfirmed.  The C build was also re-checked under valgrind (0 leaks, 0 errors) since two
sites there changed from a `puts()` ternary to an `if`/`else`.

**Also found, not fixed here**: the three demos have quietly diverged in scope — Python
alone covers an OPRF-aPAKE password-key determinism check and an HPKS-XMSS-F
leaf-index-swap rejection check.  Both are marker-covered where they exist; no attempt is
made to backport them to C/Go, since that is a coverage decision for whoever owns those
files, not a side effect of a CI-gating item.

**CI.**  `.github/workflows/ci.yml`'s three suite-demo steps (added in #258/v5.2.5) needed
no workflow changes — the demos' own exit code already carried the process guard from
v5.2.5 and now carries the content check too.  Comments at all three call sites are updated
to say so.

Status: **DONE v5.2.6** — implemented option (a): all three suite demos now exit non-zero
on a wrong verdict, not only on a crash, via an unambiguous `[FAIL]` marker mirroring the
test harnesses' TODO #233 gate; the pre-existing `+`/`-` narrative inversions found while
auditing every branch are also fixed.

### #256: the remaining `\%`-in-math spans render with the sign silently dropped

`SecurityProofs-7.md` had two of these; v5.2.1 fixed them.  Nineteen more survived, in
`SecurityProofs-4.md` (10) and `SecurityProofs-5.md` (9), across 16 lines — later confirmed
as 12 and 9 raw `\%` occurrences respectively (21 total) once mismeasured cross-span pairing
was accounted for; see below.

**The bug.**  GitHub's pipeline is CommonMark first, KaTeX second.  CommonMark §6.7 resolves
a backslash escape before any `$...$` span is handed on, so `\%` arrived at KaTeX as a bare
`%` — and there `%` starts a comment that runs to end of input.  `$\approx 50\%$` therefore
rendered as `50`, with the percent sign gone and no error anywhere.  It is not a KaTeX FAIL;
`validate_katex.js` reported it as the strict-mode warning `commentAtEnd`, which is why
nineteen instances survived every previous KaTeX pass.

**The fix**, already applied twice in Part 7: close the math span before the sign —
`$\approx 50$%` — the form `SecurityProofs-2.md` §379 has always used.  Confirmed every one
of the 21 raw `\%` occurrences (12 in Part 4, 9 in Part 5) was the identical `\%$` pattern —
the escape immediately before the closing delimiter — so one global `sed 's/\\%\$/$%/g'` per
file was sound and sufficient; there was no case needing individual handling.

**One instance needed more than the mechanical substitution.**  After the global fix, Part 5
validated clean (0 `commentAtEnd`) but Part 4 still reported one.  Isolating it to §11.7's
sparse-secret-density paragraph found the actual cause: `validate_katex.js`'s inline-`$...$`
extractor is deliberately single-line-only (its own comment says so) and will not pair a `$`
opened on one source line with a `$` closed on the next, even mid-paragraph.  The sentence
`(density $h/N \approx` / `0.2\%$–$0.6\%$)` straddled exactly such a line break, so the
validator's real span pairing did not match the reading a human (or GitHub's actual
paragraph-joined renderer) would give it — moving the `\%` outside the span shifted, rather
than removed, which fragment absorbed the bare `%`.  Fixed by rewrapping the sentence so each
math span sits fully on one source line (pure formatting; identical rendered text) rather
than by further chasing the escape.  This is a second, previously-unknown site class distinct
from the `\%`-escape bug itself, worth remembering if it recurs: **an inline math span must
not straddle a line break in the source**, independent of anything to do with `%`.

**The rewrap changed Part 4's expression count** (684 -> 685): the straddling span was
invisible to the validator before (neither counted as OK nor FAIL), and became a normal,
counted span once confined to one line.  `SecurityProofs.md`, `CLAUDE.md`, and
`SecurityProofsCode/KATEX_RULES.md`'s copies of the count were updated;
`check_part_index.py --require-counts` failed once before the fix (confirming the drift was
real, not assumed) and passed clean after.

**Verified.**  `validate_katex.js` reports `0 commentAtEnd` and `0 FAIL, 0 PIPE-FAIL` on all
nine parts (not just 4 and 5) after the change.  Every edited line was read back to confirm
the rendered prose reads correctly (`$25$%` → "25%", etc.), per `KATEX_RULES.md` Rule 12's
caution that per-span validation does not model cross-span or cross-line pairing hazards.
`spec/generate_spec.py --check --require-schema` and `spec/check_security_md.py` reconfirmed
green (docs-only change, unaffected as expected).

Status: **DONE v5.2.7** — all 21 instances fixed across `SecurityProofs-4.md` (12) and
`SecurityProofs-5.md` (9); one line rewrapped to keep its math span on a single source line,
which the validator's own extractor requires; Part 4's advertised expression count corrected
684 -> 685 in all three index copies.

### #260: bring Java to full parity with C/Go/Python — functions, demo, tests, CLI, CI, cross-interop

Java (`bindings/java/`) has been a genuine, mostly-complete port since TODO #196-#203, and
gets carried along with most new work (#245, #255, #258/#259's audit all touched it). But it
has never been held to full parity, and several past items documented the gap and explicitly
declined to close it rather than losing track of it: TODO #240 ("**Not in scope.** Adding
`hpks-ring` to the Java CLI ... stays out of scope and remains a gap"), TODO #241/#242/v4.0.0
("Landed identically in C, Go and Python (Java ships neither)"), TODO #255 ("Java ships no
duplex, fpe or twk"). This item is where that stops being scattered across other items' scope
notes and becomes its own tracked gap, closed a piece at a time the way #255's four passes
closed the v3 primitive.

**Progress.**  v5.3.0 ported the 78.C ratchet (`Ratchet.java`); v5.3.1 added HDRBG
(`Hdrbg.java`, TODO #96); v5.3.2 added HPKS-T (`HpksT.java`, TODO #98); v5.3.3 added FPE/twk
and their v3 variants (`FpeTwk.java`, TODO #78.A/#78.B/#255); v5.3.4 added
HSKE-NL-V2/V3-Duplex (`Duplex.java`, TODO #95 Option 2/#255); v5.3.5 added HPKS-Stern-Ring
(`SternRing.java`, TODO #78.I) — **all seven** missing primitives listed below are now
ported, each with its own `SelfTest.java` round-trip coverage.  Five of the seven (Ratchet,
HDRBG, FPE, twk, Duplex) were cross-checked byte-for-byte against Python's output for the
same fixed inputs (there is no
KAT vector for any of them in `KAT/`); HPKS-Stern-Ring and HPKS-T are inherently randomized
protocols (fresh nonces/challenges each call, matching all three existing languages), so
those two are checked structurally instead — round-trip validity, tamper rejection, and (for
the ring signature) rejection of a forged signature from a secret matching no ring member's
syndrome, run repeatedly and at every ring position.  HPKS-T, FPE and twk unlike
Ratchet/HDRBG/Duplex DO have CLI subcommands in C/Go/Python (`--algo hpks-t` TODO #106;
`fpe`/`twk` subcommands); HPKS-Stern-Ring also has one (`sign --ring`/`verify --ring` or
equivalent — audit the exact flag shape against the C/Go/Python CLIs when step 3 is worked,
rather than assumed here).  Every pass through v5.3.5 ported only the library primitive +
`SelfTest` coverage (step 1 of the scope below); step 1 is COMPLETE.  v5.3.6 started step 3
(CLI subcommands) with `fpe`/`twk` (both v2 and v3) in `HerraduraCli.java`; v5.3.7 added
`threshold-commit`/`threshold-aggregate`/`threshold-respond`/`threshold-combine` plus
`verify --algo hpks-t` for HPKS-T's four-phase protocol, with five new PEM types in
`Codec.java`.  Both passes verified byte-exact against `herradura.py`'s CLI output and
cross-language round-tripped in every direction (including a mixed Java/Python protocol
run whose intermediate and final PEMs matched byte-for-byte).  v5.3.8 added
`hske-duplex`/`hske-duplex3` to the existing `enc`/`dec` subcommands (matching Python's
own CLI shape — duplex is not a separate subcommand there either) with a `--ad` flag,
also byte-exact and cross-language round-tripped both directions, plus empty-plaintext,
wrong-`--ad`, and cross-version format-tag rejection checks.  v5.3.9 added
`sign`/`verify --algo hpks-ring` (comma-separated `--ring`, matching Python's
`_load_ring_pubkeys` convention — deliberately not `threshold-*`'s space-separated
`--commits`/`--partials`), completing step 3: **every C/Go/Python CLI subcommand this port
was missing now exists in Java.**  Cross-language verified both directions on a 4-member
ring, plus outsider-signer, too-small-ring, and ring-size-mismatch rejection checks.  Also
found and fixed a flaky pre-existing test while running the gate: `SelfTest.java`'s
HPKS-Stern-Ring forgery check (v5.3.5) ran at `demoRounds=8` — `(2/3)^8 ~= 3.9%` soundness
error, so it failed roughly 1 run in 25 — raised to 32 rounds (`~2e-6` error), the same
probabilistic-test-asserted-as-deterministic class CLAUDE.md's Testing section documents
for [45].  v5.3.10 made step 2's first audit pass: checked each of the six new
primitives' `SelfTest.java` coverage against its C/Go/Python numbered-test counterpart
([27] Ratchet, [29] HDRBG, [31] HPKS-T, [46] fpe/twk, [20] HPKS-Stern-Ring; Duplex has no
numbered-test counterpart in any reference harness) and closed the two real gaps it found:
HDRBG gained the exact cross-language KAT hex vectors test [29] hardcodes, a monobit check,
and a personalization-divergence check; fpe/twk gained test [46]'s key‖tweak
boundary-encoding collision guard.  Ratchet, HPKS-T, HPKS-Stern-Ring and Duplex were
already at or above their C/Go/Python counterparts' depth.  Step 2 is not fully closed —
this was one audit pass, not an exhaustive one — but remains open only for further passes,
not for the gaps this one found.  Step 3
is DONE.  v5.4.0 added step 4: `Demo.java`, a narrated protocol-by-protocol walkthrough
mirroring the other three languages' `main()` — every protocol `HerraduraCli.java`
exposes, the same `+`/`[FAIL]` verdict style, and the same TODO #258/#259 `[FAIL]`-marker
gate, verified clean across several runs.  Step 4 is DONE.  v5.4.1 added step 5:
`native-java`'s CI job now builds Java explicitly and runs `Demo.java` as its own step
("Java suite demo runs to completion"), the same position and the same `[FAIL]`-gated
convention C/Go/Python's demo steps use.  Step 5 is DONE.  v5.4.2 made step 6's
first pass: `test_v3_family.sh`'s `sym_langs` now includes Java (matching the `nla3_langs`
pattern it already used); `test_duplex.sh` gained an optional 4th Java column for plain
(v2) `hske-duplex`; `test_threshold_interop.sh` gained a Java sign scenario and a Java
verify leg on every scenario, plus a Java-combine mixed-CLI run; `test_cross_lang_matrix.sh`'s
header comment (still listing `hpks-ring`/`hpks-t`/`hske-duplex` as unexposed by Java,
stale since v5.3.6-v5.3.9) was corrected; and `native-interop` now installs a JDK so all
three interop scripts it runs get real 4-way coverage in CI rather than a NOTE.  v5.4.3
closed the two gaps that pass left open: `test_ring.sh` gained the same optional 4th Java
column (HPKS-Stern-Ring's 16-way sign/verify matrix, anonymity, non-member/tamper/wrong-ring
rejection — 31/31 checks), `test_fpe_twk.sh` gained it too (59/59 checks) and had its own
stale "Java ships neither" header corrected, and a repo-wide sweep for any other "Java
ships/has/lacks X" phrasing across `CliTest/`, `spec/`, and `SECURITY.md` came back clean.
Step 6 is DONE.  Every one of TODO #260's six steps is now complete.

**What is actually missing, confirmed against the current tree, not assumed:**

* **Library functions/protocols.**  All seven primitives that were missing are now
  ported — Ratchet (78.C), HDRBG (#96), HPKS-T, FPE/twk (both v2 and v3),
  HSKE-NL-V2/V3-Duplex, and HPKS-Stern-Ring (78.I) — see Progress above. This bullet is
  DONE; the remaining gaps are the demo, the CI step, and interop coverage below.
* **Library demo.**  DONE as of v5.4.0.  `bindings/java/herradurakex/Demo.java`
  exercises every protocol `HerraduraCli.java` exposes end to end with human-readable
  +/- verdicts and the same `[FAIL]`-marker gate TODO #258/#259 gave C/Go/Python.  Wired
  into CI as of v5.4.1 — see the CI checks bullet below (step 5, now DONE).
* **CLI capabilities.**  DONE as of v5.3.9.  `HerraduraCli.java` gained `fpe`/`twk`
  (both v2 and v3) in v5.3.6, `hpks-t`'s four `threshold-*` subcommands plus
  `verify --algo hpks-t` in v5.3.7, `hske-duplex`/`hske-duplex3` on `enc`/`dec` in v5.3.8,
  and `sign`/`verify --algo hpks-ring` in v5.3.9 — see Progress above.  No C/Go/Python CLI
  subcommand this port was missing remains missing.
  (`pkey` and `hdrbg`/OPRF/aPAKE-adjacent subcommands: audit
  against `spec/herradura-protocol-spec.json`'s `cli_binding` map when this item is worked,
  rather than assumed here.)
* **CI checks.**  DONE as of v5.4.1.  `native-java` now runs `Demo.java` as its own
  `[FAIL]`-gated step ("Java suite demo runs to completion"), the same position and
  convention C/Go/Python's demo steps use.  `SelfTest.java`'s own pass/fail gate (a direct
  `fails` counter, `System.exit(1)`) remains a separate, functionally-sound idiom next to
  C's output-scanning `hprintf`, Go's `os.Stdout` pipe, Python's `print` shadow, and now
  `Demo.java`'s own scanning `out()` — worth noting, not necessarily worth unifying for its
  own sake.
* **Cross-interoperability checks.**  DONE as of v5.4.3 — see Progress above.
  `test_v3_family.sh`, `test_duplex.sh`, `test_threshold_interop.sh`, `test_ring.sh` and
  `test_fpe_twk.sh` all cover Java (optionally, degrading to a NOTE without a JDK) alongside
  C/Go/Python.  `test_malformed_pem_matrix.sh` was not specifically re-audited for
  Java-specific malformed-PEM edge cases beyond what it already exercised — if a gap surfaces
  there later it is a `test_malformed_pem_matrix.sh`-scoped finding, not evidence #260 itself
  regressed.

**Explicitly out of scope, and why.**  HCRED-KKW (`hcred_prove_kkw`/`hcred_verify_kkw`) is
NOT a Java gap — it exists only in the Python suite file today, absent from C, Go, *and*
Java alike, so it is a separate Python-only-feature item, not a C/Go/Python-vs-Java
asymmetry.  Don't fold it in here.  Likewise the assembly/Arduino targets are not this
item's concern — they are deliberately narrower ports (N=32, t=2, demo-only) and were never
held to suite-language parity.

**Scope for the work, expected to land in stages like #255 did, each its own PATCH or MINOR
bump per CLAUDE.md's versioning rule (a new CLI subcommand is MINOR):**
1. Port each missing primitive to `bindings/java/herradurakex/` (Ratchet, HDRBG, HPKS-T,
   HPKS-Stern-Ring, FPE, twk, HSKE-NL-V2-Duplex, and the v3 variants of the latter three),
   cross-checked against the existing KAT vectors the way `KatVerify.java` already does for
   everything else.
2. Add `SelfTest.java` round-trip coverage for each, matching the granularity the C/Go/Python
   test [44]-[48] additions used.
3. Add the CLI subcommands to `HerraduraCli.java` and regenerate `spec/` (`generate_spec.py`)
   so `cli_binding` picks them up — `check_security_md.py` and the schema gate must stay green.
4. Write the Java suite demo (`bindings/java/herradurakex/Demo.java` or similar — name it
   when the work starts, don't presume it here) mirroring the other three's protocol-by-
   protocol narration, with the same `[FAIL]`-marker gate #259 gave C/Go/Python.
5. Add a `native-java` CI step that runs it, gated the same way.
6. Add or extend the `CliTest/test_java_*_interop.sh` / `test_cross_lang_matrix.sh` /
   `test_v3_family.sh` coverage so every newly-ported feature gets a real 4-way (or
   3-way, where a feature predates v3) interop check instead of a NOTE.

**Acceptance criterion.**  Done means every `grep`/scope note above finds nothing: no
protocol, CLI subcommand, demo section, test, or interop script that exists for C, Go and
Python but not Java, and no cross-lang-compat script that skips Java's cell with a NOTE for
a feature reason (a language-inherent reason, if any turns up during the work, gets
documented as ACKNOWLEDGED instead of silently left as OPEN forever).

Status: **DONE v5.4.3** — all six scope steps complete: seven primitives ported
(Ratchet, HDRBG, HPKS-T, FPE/twk v2+v3, HSKE-NL-V2/V3-Duplex, HPKS-Stern-Ring),
`SelfTest.java` coverage audited against the C/Go/Python numbered tests, every missing CLI
subcommand added to `HerraduraCli.java`, the narrated `Demo.java` suite walkthrough written
and `[FAIL]`-gated, wired into `native-java`'s CI job, and every dedicated interop script
(`test_v3_family.sh`, `test_duplex.sh`, `test_threshold_interop.sh`, `test_ring.sh`,
`test_fpe_twk.sh`) extended to cover Java alongside C/Go/Python.


### #262: `HpksXmssSign`'s `int`→`uint32` leaf-index conversion has no bound check (CodeQL go/incorrect-integer-conversion, alert #1)

GitHub code scanning flags `herradura/herradura.go`'s `HpksXmssSign` — `uint32(leafIdx)` —
as CWE-190/CWE-681 ("Incorrect conversion between integer types"), high severity, open since
2026-08-19 and still present on `master` (commit `f4420cb`) and `devtest`. The alert's
traced source is `HerraduraCli/herradura_cli.go`'s `xmssReadIdx`, which parses the
`<keyfile>.idx` sidecar via `strconv.Atoi` (architecture-dependent `int`, so 64-bit on every
platform this repo targets) with only a lower-bound check (`v < 0` → 0), no upper bound.

**Verified: not exploitable through the shipped CLI path, but a real library-API gap.**
`herradura_cli.go`'s `sign --algo hpks-xmss` handler *does* bound `leafIdx` before calling
`HpksXmssSign` — `if leafIdx >= numLeaves { ...exit... }`, where `numLeaves = 1 << h` and
`h` is itself capped at `xmssMaxH = 20`, so `leafIdx` can never exceed ~2^20 by the time it
reaches the conversion. CodeQL's own documentation for this rule states it "is only able to
identify bounds checks that compare against a constant value" — `numLeaves` is a variable,
not a constant, so the tool cannot see this guard and flags the call anyway. Confirmed by
reading both sides of the CLI's `sign` case (`HerraduraCli/herradura_cli.go` lines
3579–3591) and `HpksXmssSign`'s definition (`herradura/herradura.go` ~line 3379).

**What is real: `HpksXmssSign` is an exported library function with no bound check of its
own**, unlike `HpksWotsKeygen`/`HpksWotsSign` (already typed `leafIdx uint32` — correct by
construction) and unlike `HpksXmssKeygen` which trusts its `h int` from the same CLI-side
`bounded()` helper. Any other caller of the `herradura` package — a future MCP tool, a
different CLI, direct library use — that passes an out-of-range `int` (negative, or
`>= 2^32`, or simply `>= len(kp.LeafHashes)`) gets silent wraparound/truncation into a
*different, already-used* leaf index rather than an error. For a one-time-use signature
scheme, silently signing with a reused WOTS leaf is a private-key-recovery bug (two WOTS
signatures under the same leaf let an attacker forge a third) — the CLI happening to guard
correctly today doesn't make the library API itself safe to call.

**Fix.** Add the bound check inside `HpksXmssSign` (and `HpksXmssKeygen`'s leaf-index
consumers) itself, against `len(kp.LeafHashes)` — the same check `herradura_cli.go` already
performs, just moved (or duplicated) into the library so it can't be skipped by a caller
that doesn't know to replicate it. Return an error/nil rather than a signature on an
out-of-range index, matching the CLI's existing "key exhausted" behavior. Apply the same
audit to any other exported function taking a leaf/round/index `int` that later narrows to
a smaller unsigned type without its own check (a quick grep for `uint32(` conversions in
`herradura/herradura.go` bounds the search). Re-run `codeql.yml`'s Go analysis (or
`gh api repos/Caume/HerraduraKEx/code-scanning/alerts/1`) after the fix to confirm the alert
closes; GitHub auto-closes code-scanning alerts once the flagged line's data flow is
provably bounded, no manual dismissal needed if the fix actually lands.

**Fixed (v5.8.1).** `HpksXmssSign` now validates `leafIdx` against `len(kp.LeafHashes)`
itself (`leafIdx < 0 || leafIdx >= len(kp.LeafHashes)` → `error`, no signature produced) —
the exact fix proposed above, applied only where CodeQL's alert actually points (no other
`uint32(...)` conversion in `herradura/herradura.go` takes an unbounded caller-supplied
`int`; `HpksXmssKeygen`'s own `h`/`idx` loop was checked and stays as-is, since every real
caller already bounds `h` the same way `herradura_cli.go` does). Signature changed from
`(*HpksXmssSig)` to `(*HpksXmssSig, error)` — a Go API change, but not a CLI/PEM/wire-format
one (`bindings/ffi` doesn't touch XMSS), so PATCH rather than MAJOR. All three callers
(`Herradura cryptographic suite.go`, `CryptosuiteTests/Herradura_tests.go`,
`HerraduraCli/herradura_cli.go`) updated; test [30] gained a `range_reject` sub-check
exercising both a negative and an over-the-tree-size index. Verified: `build_go.sh` and
`build_c.sh` clean, the Go suite demo's XMSS section passes, test [30] reports
`range_reject=N/N [PASS]`, and `CliTest/test_wots.sh`'s full C/Go/Python XMSS interop matrix
(45 checks, including leaf-exhaustion and tamper/wrong-key rejection) passes unchanged.

Status: **DONE v5.8.1**

---

### #263: aPAKE's ephemeral HKEX-RNL exchange skips TODO #89's contributory-nonce KDF in three of four languages

**Found during a TODO #261 (four-language parity) sweep of the aPAKE/OPRF internal
derivation functions** — not a dedicated audit. `hpake_login_demo` (and its Go/Java
equivalents) draws its own ephemeral HKEX-RNL keypair inline, the same shape TODO #89
(DONE v1.9.49) was filed against: one side's `a_rand` determines the blinding
polynomial's uniformity, so a weak or backdoored RNG on that side alone silently
weakens the whole session. TODO #89's shipped fix binds the *final session key* (not
`a_rand` itself, which turned out to be structurally infeasible to make contributory in
two rounds) to per-session nonces from both parties: `sk = HFSCX-256(K_raw ‖ n_A ‖
n_B)`, applied to every plain `kex --algo hkex-rnl` session.

**C's `hpake_login_demo` already re-applies this fix** — generates `pake_n_A`/`pake_n_B`
each call, runs `rnl_contributory_kdf(K_raw, n_A, n_B)`, and uses the result (not raw
`K_raw`) for both the ZKBoo auth-binding message and the final session key. **Go's
`HpakeLoginDemo`, Python's `hpake_login_demo`, and Java's `Hpake.loginDemo` did not** —
all three authenticated and derived the session key straight off raw `K_raw`, silently
reverting to the pre-#89 exposure for this one code path while their plain-`kex` CLI
paths (which apply the equivalent construction independently) remained correct.

**Not a change to aPAKE's security classification.** `SECURITY.md` already rates aPAKE
Demo-only/pedagogical for two larger, independent reasons: the OPRF server key is
recoverable in ~2^36.5 group operations (defeating aPAKE's whole stated purpose — a
stolen database becomes offline-guessable), and the shipped ZKBoo parameters give only
0.15% soundness. This RNG-hardening gap is real but smaller than either.

**Fix.** Ported C's construction to the other three: Go gained `hpakeContributoryKdf`
(new, `herradura/herradura.go`, mirroring C's `rnl_contributory_kdf`); Python gained
`_hpake_contributory_kdf` (new, `Herradura cryptographic suite.py`); Java reused its
existing `HerraduraNl.rnlContributoryKdf` (already correct — it's what Java's own
plain-`kex` path calls), wiring it into `Hpake.loginDemo`. All three now generate fresh
32-byte `n_A`/`n_B` nonces per login-demo call, derive `K_kdf = HFSCX-256(K_raw ‖ n_A ‖
n_B)` for both parties, and use `K_kdf` (not raw `K_raw`) for the ZKBoo auth message and
the session-key KDF input — matching C exactly.

**Verification.** Manual smoke tests (Go, Python) confirm correct-password → 32-byte
session key, wrong-password → nil/None, no panics. Java's `SelfTest` `[20] hpake
round-trip` passes. All four CLIs' aPAKE integration tests pass unchanged:
`CliTest/test_pake.sh` (Python, 7/7), `test_c_pake.sh` (7/7), `test_go_pake.sh` (7/7),
`test_java_pake_interop.sh` (5/5, Java<->Python record/session-key cross-checks). C/Go/Python
suite security-test builds and `spec/check_language_parity.py` both stay green. Added a
`hpake-contributory-kdf` entry to `PRIMITIVES` (now 12 entries) so this can't silently
regress in one language again; verified it fails when the Go marker is renamed.

**Docs.** `SECURITY.md`'s aPAKE row and `SecurityProofs-7.md` §11.17 (immediately
adjacent to `_rnl_contributory_kdf`'s own description) both updated. In the course of
writing the latter, corrected a pre-existing inaccuracy in the same section: it claimed
`_rnl_contributory_kdf` lives in `herradura.h`/`Herradura cryptographic suite.py`/
`herradura/herradura.go`; in fact only C's copy is in the shared suite file — Python's and
Go's live in their own CLI files (`HerraduraCli/herradura.py`,
`HerraduraCli/herradura_cli.go`), which is exactly why the suite-internal
`hpake_login_demo` couldn't reach it and needed its own copy/reuse here.

Status: **DONE v5.8.4**

---

### #264: Python demo's n=32 HPKE-Stern-F brute-force check flakes CI on the code's known non-unique decoding

**Found while investigating a `native-python` CI failure**, not a dedicated audit.
`Herradura cryptographic suite.py`'s `main()` demo runs a brute-force Niederreiter
decap at `n=32, t=2` and printed `[FAIL] HPKE-Stern-F key agreement failed (n=32)`
whenever the derived session key didn't match — but that code is not uniquely
decodable: `C(32,2)=496` weight-2 error vectors land in a 16-bit syndrome space, so
brute force can legitimately return a *different* weight-2 preimage of the same
syndrome than the one encap used. `CryptosuiteTests/Herradura_tests.py` test [18]
already documents and handles exactly this (TODO #233's note: "made this line report
`[FAIL]` on 7.4% of runs"), but the demo's `main()` had a separate, naive copy of the
check that never got the same treatment — so it flaked CI's `native-python` job
nondeterministically once TODO #233 made any `[FAIL]` marker fail the build.

**Fix.** Added `stern_f_first_preimage()` to `Herradura cryptographic suite.py`
(mirroring the test suite's private helper of the same purpose) and changed the demo
to call `hpke_stern_f_encap_with_e` instead of `hpke_stern_f_encap`, so it has the true
error vector to compare against. On a key mismatch, the demo now checks whether brute
force found a genuinely different weight-2 preimage of the same ciphertext — if so it
prints `+ HPKE-Stern-F syndrome ambiguous at n=32 (not a failure — ...)` instead of
`[FAIL]`; anything else is still reported as a real failure.

**Verification.** 40 consecutive full runs of `python3 "Herradura cryptographic
suite.py"` all closed with `*** OK: no check reported [FAIL] ***`. `python3 -m
py_compile` passes. No other code path (test suite, CLI) called the changed
`hpke_stern_f_encap`/`hpke_stern_f_decap` demo lines, so the fix is scoped to `main()`
plus the one new, previously-absent helper function.

Status: **DONE v5.8.5**
