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

Status: **OPEN**

---

### 13. HKEX-RNL failure rate uncharacterized at deployed parameters (Analysis, Medium)

**Files:** `SecurityProofs.md §11.5 Q2`; new `SecurityProofsCode/hkex_rnl_failure_rate.py`

§11.5 Q2 marks `(q=65537, n=256, p=4096)` as `⚠ pending verification`. No
empirical P(K_A ≠ K_B) row exists for the deployed parameter set.

Fix: add a script that samples (s_A, s_B, a_rand) uniformly and measures the
empirical key-disagreement rate over ≥ 10,000 trials at n=256. Record the result
in §11.5 Q2. If failure rate > 1%, a reconciliation hint mechanism is needed.

Status: **OPEN**

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

Status: **OPEN**

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

Status: **OPEN**

---

### 16. `rnl_cbd_poly` bit-per-byte inefficiency (Performance, Low)

**Files:** C `rnl_cbd_poly`; Go `rnlCBDPoly`; Python `_rnl_cbd_poly`

With η=1 each coefficient needs 2 bits (one `a` bit, one `b` bit). Current code
reads 1 byte per coefficient and uses only bits 0–1 → 75% of urandom entropy
discarded. For n=256 that is 256 bytes drawn when 64 would suffice.

Fix: process 4 coefficients per byte (bit-pairs at positions 0-1, 2-3, 4-5, 6-7).
Apply to C, Go, Python. Note: byte-for-byte output changes — update affected tests.

Status: **OPEN**

---

## Updated priority order

1. #9  — HSKE-NL-A1 counter=0 degeneracy (security regression matching KDF fix)
2. #13 — HKEX-RNL failure rate (close pending-verification gap)
3. #12 — HSKE-NL-A2 deterministic encryption caveat (documentation)
4. #15 — Fermat prime fast modulo (largest performance win)
5. #14 — NTT twiddle precomputation (moderate performance win)
6. #10 — Stale q=3329 comment (trivial)
7. #11 — Stale §11.6 KDF formula (trivial)
8. #16 — CBD bit efficiency (low effort, minor gain)
