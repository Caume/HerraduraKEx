# HerraduraKEx — PQC Improvement Backlog

Generated from security/performance review of v1.5.x NL-FSCX + Ring-LWR implementation.

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

Status: **TODO**

---

### 5. HPKS-NL / HPKE-NL — not truly PQC (Structural / Known)

Both protocols retain the GF(2^n)* DLP which Shor's algorithm breaks. They are
linearity-hardened classical protocols, not post-quantum. Replacing the DH
exponentiation with a lattice-based commitment (e.g., Ring-LWE-based Schnorr)
would be required for full PQC. Currently documented as a known limitation.

Status: **KNOWN / DEFERRED**

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
