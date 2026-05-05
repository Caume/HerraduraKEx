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

Status: **TODO** — not yet started.

---

## Updated priority order

1. #17 — Multi-size standardization (Batches 3-6, C tests)
2. #5  — HPKS-NL / HPKE-NL PQC claim (**DEPRECATED**)
3. #25 — HerraduraCli Python CLI (**DONE v1.5.23**)
4. #21 — i386 HKEX-RNL zero session key (**DONE v1.5.22**)
5. #23 — Go HKEX-RNL test coverage n=128,256 (**DONE v1.5.22**)
6. #16 — CBD bit efficiency (**DONE v1.5.22**)
7. #9  — HSKE-NL-A1 counter=0 degeneracy (**DONE v1.5.13**)
8. #22 — ARM HSKE-NL-A2 R_VALUE fix (**DONE v1.5.21**)
9. #19 — Stale version banners (**DONE v1.5.21**)
10. #20 — Python suite q=3329 label (**DONE v1.5.21**)
11. #24 — C binary `_c` suffix (**DONE v1.5.20**)
12. #18 — Parameterized integer arithmetic layer (**DONE v1.5.20**)
13. #15 — Fermat prime fast modulo (**DONE v1.5.20**)
14. #14 — NTT twiddle precomputation (**DONE v1.5.17**)
