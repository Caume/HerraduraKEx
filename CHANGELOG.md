# Changelog

All notable changes to the Herradura Cryptographic Suite are documented here.

---

## [1.5.21] - 2026-04-30

### Fix — ARM HSKE-NL-A2 used wrong step count (TODO #22)

**Root cause:** `Herradura cryptographic suite.s` called `nl_fscx_revolve_v2` and
`nl_fscx_revolve_v2_inv` with `#I_VALUE` (= n/4 = 8 steps) for HSKE-NL-A2, while
the protocol specifies `r = 3n/4 = R_VALUE = 24 steps`. NASM i386 and C were correct.
HPKE-NL was unaffected — it legitimately uses `I_VALUE` (n/4).

**Impact:** ARM and NASM i386 HSKE-NL-A2 ciphertexts were cross-incompatible; both
self-decrypted correctly (symmetric use of the wrong step count) so the bug was silent.

**Fix:** Changed both HSKE-NL-A2 call sites in `Herradura cryptographic suite.s`
(encrypt and decrypt) from `mov r2, #I_VALUE` to `mov r2, #R_VALUE`. Updated the
inline comments to match.

### Fix — Python HKEX-RNL demo banner printed q=3329 (TODO #20)

`Herradura cryptographic suite.py` line 953 printed `q=3329` (Kyber's modulus),
but `RNLQ = 65537` since v1.5.4. The same banner was fixed in C at v1.5.13 but the
Python file was missed. Changed to `q=65537`.

### Maintenance — Version-banner sync (TODO #19)

Nine files still carried `v1.5.18` in header comments and/or runtime-printed banner
strings; the project was at v1.5.20. Updated all header comments and printed banners
to v1.5.21 across:

- `Herradura cryptographic suite.go` (header comment)
- `CryptosuiteTests/Herradura_tests.go` (header changelog + printed banner)
- `CryptosuiteTests/Herradura_tests.py` (argparse description + printed banner)
- `Herradura cryptographic suite.s` / `CryptosuiteTests/Herradura_tests.s` (header + `.asciz` string)
- `Herradura cryptographic suite.asm` / `CryptosuiteTests/Herradura_tests.asm` (header + `db` string)
- `Herradura cryptographic suite.ino` / `CryptosuiteTests/Herradura_tests.ino` (header + `Serial.println`)

Historical changelog entries inside file headers (e.g. `v1.5.18: HPKS-Stern-F...`)
were left unchanged.

---

## [1.5.20] - 2026-04-30

### Performance — Fermat prime fast modulo for NTT inner loops (Batch 8 / TODO #15)

Replaces all `(uint64_t)a * b % RNL_Q` operations in the NTT hot paths with a
divisionless Fermat-prime reduction: since q = 65537 = 2^16+1, we have
2^16 ≡ −1 and 2^32 ≡ 1 (mod q), so for x = a·b: x ≡ (x & 0xFFFF) − ((x>>16) & 0xFFFF) + (x>>32) (mod q).
The result r ∈ [−65535, 65536], so at most one conditional add (`if r < 0 r += 65537`) is needed;
the `r ≥ q` branch is dead code (max r = 65536 < 65537).

#### New helpers

- C: `static inline uint32_t rnl_mulmodq(uint32_t a, uint32_t b)` — added to `Herradura cryptographic suite.c` and `CryptosuiteTests/Herradura_tests.c`
- Go: `func rnlMulModQ(a, b int) int` — added to `Herradura cryptographic suite.go` and `CryptosuiteTests/Herradura_tests.go`

#### Call sites replaced

- `rnl_ntt` / `rnl32_ntt` butterfly (3 multiplications): `* wn % q`, `* w % q`, invert-path `* inv_n % q`
- `rnl_poly_mul` / `rnl32_poly_mul` / `rnl_poly_mul_n` (4–9 multiplications): ψ-twist pre/post and pointwise product
- `rnlNTT` and `rnlPolyMul` in both Go files

#### Benchmark result (gcc -O2, `-t 3.0`, n=32)

| Benchmark | Before | After | Δ |
|-----------|--------|-------|---|
| HKEX-RNL handshake (n=32) | 65.7 K ops/sec | 77.3 K ops/sec | +17.6% |

#### Files changed

- `Herradura cryptographic suite.c` — `rnl_mulmodq` helper; `rnl_ntt` + `rnl_poly_mul` updated
- `CryptosuiteTests/Herradura_tests.c` — `rnl_mulmodq` helper; `rnl32_ntt` + `rnl32_poly_mul` + `rnl_poly_mul_n` updated
- `Herradura cryptographic suite.go` — `rnlMulModQ` helper; `rnlNTT` + `rnlPolyMul` updated
- `CryptosuiteTests/Herradura_tests.go` — `rnlMulModQ` helper; `rnlNTT` + `rnlPolyMul` updated

#### Test results (gcc -O2, `-t 3.0`)

- All 18 security tests pass [PASS]

---

### Feature — Parameterised integer arithmetic layer: bn_* (Batch 7 / TODO #18)

Adds a self-contained `bn_*` big-endian byte-array arithmetic library (Groups A–E) inside `CryptosuiteTests/Herradura_tests.c`, enabling protocol tests to run at any supported key width without per-size dispatch. Uses this to extend tests [7] (HPKS Schnorr), [8] (Schnorr Eve), and [15] (HPKS-NL) from `{32,64,128}` to `{32,64,128,256}` bits — previously blocked by the absence of a 256-bit scalar multiplication mod ord.

#### New functions (Groups A–E)

- **Group A** (bit primitives): `bn_zero`, `bn_copy`, `bn_xor_n`, `bn_equal_n`, `bn_is_zero_n`, `bn_popcount_n`, `bn_shl1_n`, `bn_shr1_n`, `bn_rol_k_n`
- **Group B** (mod 2^n): `bn_add_n`, `bn_sub_n`, `bn_mul_lo_n`, `bn_mul_full_n`
- **Group C** (mod 2^n−1): `bn_mul_mod_ord_n`, `bn_sub_mod_ord_n`, `bn_add_mod_ord_n`
- **Group D** (GF(2^n)): `gf_poly_for_n`, `bn_gf_mul_n`, `bn_gf_pow_n`
- **Group E** (FSCX + NL-FSCX): `bn_fscx_n`, `bn_fscx_revolve_n`, `bn_m_inv_n` (bootstrapped from M^{n/2−1}(e₀), lazy-cached per nbits), `bn_nl_fscx_v1_n`, `bn_nl_fscx_revolve_v1_n`, `bn_nl_delta_v2_n`, `bn_nl_fscx_v2_n`, `bn_nl_fscx_v2_inv_n`, `bn_nl_fscx_revolve_v2_n`, `bn_nl_fscx_revolve_v2_inv_n`
- **Utilities**: `bn_rand_n`, `bn_set_gen`

#### Tests extended to 256-bit

| Test | Old sizes | New sizes |
|------|-----------|-----------|
| [7] HPKS Schnorr correctness | {32,64,128} | {32,64,128,256} |
| [8] HPKS Schnorr Eve resistance | {32,64,128} | {32,64,128,256} |
| [15] HPKS-NL correctness | {32,64,128} | {32,64,128,256} |

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — `bn_*` section inserted; tests [7],[8],[15] rewritten using `bn_*`

#### Test results (gcc -O2, `-r 10 -t 5.0`)

- [7] 10/10 verified at all four sizes [PASS]
- [8] 0/10 Eve wins at all four sizes [PASS]
- [15] 10/10 verified at all four sizes [PASS]
- All other tests unchanged [PASS]

---

### Feature — Multi-size key-length standardization: C suite HPKE-Stern-F N=32 demo (Batch 6)

Adds N=32 brute-force HPKE-Stern-F demo to `Herradura cryptographic suite.c`, completing parity with the Python suite. New helpers: `s32_fscx`, `s32_nl_revolve`, `stern32_matrix_row`, `stern32_syndrome`, `stern32_hash`, `stern32_rand_error`, `hpke_stern_f_encap_32`, `hpke_stern_f_decap_32`. The demo now prints two blocks: N=32 brute-force (C(32,2)=496 candidates) then N=256 known-e'. Both success messages updated to specify size and path.

#### Files changed

- `Herradura cryptographic suite.c` — N=32 Stern-F helpers + N=32 demo block; N=256 success message updated
- `README.md` — v1.5.20 note updated

#### Test results

- N=32 brute-force: `K (encap) == K (decap)` [PASS]
- N=256 known-e': `K (encap) == K (decap)` [PASS]

---

### Feature — Multi-size key-length standardization: C tests Stern-F N=32/64 (Batch 5)

Expands Stern-F tests [17] and [18] to cover N=32 and N=64 parameter sets alongside the existing N=256. Adds N=32 HPKS-Stern-F sign/verify helpers (`stern32_gen_perm`, `stern32_apply_perm`, `stern32_hash_n`, `stern_fs_challenges_32`, `SternSig32T`, `hpks_stern_f_sign_32`, `hpks_stern_f_verify_32`) and a full N=64 Stern-F layer (`stern_hash_64`, `stern_matrix_row_64`, `stern_syndrome_64`, `stern_rand_error_64`, `stern64_rand_seed`, `stern_gen_perm_64`, `stern_apply_perm_64`, `stern_hash_64_n`, `stern_fs_challenges_64`, `SternSig64T`, `hpks_stern_f_sign_64`, `hpks_stern_f_verify_64`, `hpke_stern_f_encap_64`, `hpke_stern_f_decap_known_64`). Raises `SDF_TEST_ROUNDS` from 4 to 8 for all sizes.

#### Parameter sets

| N  | n_rows | t  | synbytes | rounds |
|----|--------|----|----------|--------|
| 32 | 16     | 2  | 2        | 8      |
| 64 | 32     | 4  | 4        | 8      |
| 256| 128    | 16 | 16       | 8      |

- Test [17]: loop `{32, 64, 256}` — HPKS-Stern-F sign+verify at each parameter set
- Test [18]: N=32 brute-force C(32,2)=496 + N=64 known-e' fast path (direct key derivation from e')

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — N=32 HPKS helpers, N=64 full Stern-F layer, tests [17] and [18] expanded; `SDF_TEST_ROUNDS` 4→8

#### Test results (gcc -O2, `-t 3.0`)

- [17] HPKS-Stern-F: 5/5 verified at N=32/64/256, rounds=8 [PASS]
- [18] HPKE-Stern-F: 20/20 decapsulated at N=32 (brute-force), 20/20 at N=64 (known-e') [PASS]

---

### Feature — Multi-size key-length standardization: C tests HKEX-RNL n=128/256 (Batch 4)

Expands HKEX-RNL to ring sizes n=128 and n=256 in C test [14]. The NTT twiddle table is extended from `n∈{32,64}` to `n∈{32,64,128,256}` (`psi_pow[256]`, `stage_w_fwd[8]`). Adds `rnl_hint_128`/`rnl_reconcile_128`/`rnl_agree_128` using `__uint128_t` keys, and `rnl_hint_ba`/`rnl_reconcile_ba`/`rnl_agree_ba` using `BitArray` keys with bit-packed hint representation.

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — NTT table + 4 new RNL helper functions; test [14] expanded to `{32,64,128,256}`

#### Test results (gcc -O2, `-t 3.0`)

- [14] HKEX-RNL: 200/200 raw agree + 200/200 sk agree at n=32/64/128/256 [PASS]

---

### Feature — Multi-size key-length standardization: C tests GF(2^128) (Batch 3)

Adds GF(2^128) arithmetic and expands C tests [1],[5]–[9],[15],[16] to include 128-bit (and 256-bit where scalar arithmetic is not required). Implements `gf_mul_128`, `gf_pow_128`, `mul128_mod_ord128`, and `s_op128` as `__uint128_t` helpers.

#### Expansion summary

- Tests [1],[5],[6]: `{32,64,256}` → `{32,64,128,256}` (HKEX-GF correctness, key sensitivity, Eve resistance)
- Tests [7],[8],[15]: `{32,64}` → `{32,64,128}` (HPKS Schnorr and HPKS-NL; 256-bit skipped — scalar `a·e mod 2^256−1` would require 512-bit intermediates)
- Tests [9],[16]: `{32,64}` → `{32,64,128,256}` (HPKE El Gamal and HPKE-NL; no scalar arithmetic needed)

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — `gf_mul_128`, `gf_pow_128`, `mul128_mod_ord128`, `s_op128`; tests [1],[5]–[9],[15],[16] expanded

#### Test results (gcc -O2, `-t 2.0`)

- [1] HKEX-GF correctness: 100/100 at 32/64/128 bits; 80/80 at 256 bits [PASS]
- [5] Key sensitivity: mean HD ≥ n/4 at 32/64/128/256 bits [PASS]
- [6] Eve resistance: 0 successes at 32/64/128/256 bits [PASS]
- [7] HPKS Schnorr: 100/100 verified at 32/64/128 bits [PASS]
- [8] HPKS Schnorr Eve: 0/100 wins at 32/64/128 bits [PASS]
- [9] HPKE El Gamal: 100/100 decrypted at 32/64/128/256 bits [PASS]
- [15] HPKS-NL: 100/100 verified at 32/64/128 bits [PASS]
- [16] HPKE-NL: 100/100 decrypted at 32/64/128/256 bits [PASS]

---

### Feature — Multi-size key-length standardization: C tests NL-FSCX 256-bit (Batch 2)

Adds 256-bit (BitArray) support to C tests [10]–[13] for all NL-FSCX v1/v2 protocols. Implements `ba_sub256`, `ba_mul256`, `m_inv_ba`, `nl_fscx_v2_ba`, `nl_fscx_v2_inv_ba`, `nl_fscx_revolve_v2_ba`, and `nl_fscx_revolve_v2_inv_ba` as BitArray helpers. The `M^{-1}` polynomial table for n=256 was derived by GCD computation: `(1+x+x^255)^{-1}` in `GF(2)[x]/(x^256+1)` yields the four-word table `{0xb6db6db6db6db6db, 0xdb6db6db6db6db6d, 0x6db6db6db6db6db6, 0xb6db6db6db6db6db}`.

#### Files changed

- `CryptosuiteTests/Herradura_tests.c` — new BitArray v2 helpers; tests [10]–[13] expanded to `{64,128,256}`; `NL_I256=64`, `NL_R256=192` macros added

#### Test results (gcc -O2, `-r 20 -t 10.0`)

- [10] NL-FSCX v1 non-linearity: 20/20 violations + no-period at 64/128/256 bits [PASS]
- [11] NL-FSCX v2 bijectivity: 0 collisions, 20/20 inv, 20/20 nonlinear at 64/128/256 bits [PASS]
- [12] HSKE-NL-A1 counter-mode: 20/20 at 64/128/256 bits [PASS]
- [13] HSKE-NL-A2 revolve-mode: 20/20 at 64/128/256 bits [PASS]

---

### Feature — Multi-size key-length standardization: Python tests and suite (Batch 1)

Expands protocol coverage to all four standard key sizes (32, 64, 128, 256 bits) in the Python test suite and adds an N=256 HPKE-Stern-F demo to the Python suite.

#### Test coverage changes (`CryptosuiteTests/Herradura_tests.py`)

- `GF_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — affects tests [7]–[9] (HKEX-GF, HPKS, HPKE) and tests [15]–[16] (HPKS-NL, HPKE-NL) and benchmarks
- `RNL_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — affects test [14] (HKEX-RNL) and benchmark
- Test [17] `SDF_SIZES` expanded from `[32, 64]` to `[32, 64, 128, 256]` — HPKS-Stern-F sign/verify at all four sizes
- Test [18] adds known-e' decap path for N=32,64,128,256 alongside the existing N=32 brute-force path; new helpers `hpke_stern_f_encap_with_e` and `hpke_stern_f_decap_known` added

#### Suite changes (`Herradura cryptographic suite.py`)

- Added N=256 known-e' HPKE-Stern-F demo after the existing N=32 brute-force demo
- `hpke_stern_f_decap` now supports two paths: known-e' (`e_int != 0`) and brute-force (`e_int = 0`)
- `hpke_stern_f_encap_with_e` helper added (returns `(K, ct, e_p)` for test/demo use)
- Version bumped to v1.5.20 in suite and tests headers

#### Files changed

- `CryptosuiteTests/Herradura_tests.py`
- `Herradura cryptographic suite.py`

---

## [1.5.19] - 2026-04-29

### Feature — HPKS-Stern-F and HPKE-Stern-F: Arduino implementation

Adds HPKS-Stern-F and HPKE-Stern-F to the Arduino target, completing the six-language suite started in v1.5.18. Parameters: SDF_N=32, SDF_T=2, SDF_NROWS=16, SDF_ROUNDS=4 (same as ARM Thumb-2 and NASM i386).

#### Files changed

- `Herradura cryptographic suite.ino` — `stern_hash1_32`, `stern_hash2_32`, `stern_matrix_row_32`, `stern_syndrome_32`, `stern_gen_perm_32`, `stern_apply_perm_32`, `stern_rand_error_32`, `SternSig32` struct, `stern_fs_challenges_32`, `hpks_stern_f_sign_32`, `hpks_stern_f_verify_32`, `hpke_stern_f_encap_32`, `hpke_stern_f_decap_32`; demo section + Eve tests in `loop()`; banner updated to v1.5.18
- `CryptosuiteTests/Herradura_tests.ino` — same 13 helper definitions + test [11] HPKS-Stern-F sign+verify (5 trials), test [12] HPKE-Stern-F encap+decap (5 trials); banner updated to v1.5.18

#### Test results

- [11] HPKS-Stern-F: 5/5 sign+verify correct (compile-verified via g++ mock)
- [12] HPKE-Stern-F: 5/5 encap+decap keys match (compile-verified via g++ mock)

---

## [1.5.18] - 2026-04-28

### Feature — HPKS-Stern-F and HPKE-Stern-F: code-based PQC across all 6 targets

Adds two new protocols based on the Stern identification scheme (ZKP for syndrome decoding), providing code-based post-quantum hardness independent of lattice assumptions. Both protocols are implemented in five language targets: Python, Go, C, ARM Thumb-2, and NASM i386. Arduino added in v1.5.19.

#### HPKS-Stern-F — Code-Based Signature (EUF-CMA)

3-challenge Fiat-Shamir transformed Stern ZKP for syndrome decoding. Parameters: N=32, t=2, nRows=16, rounds=4 (assembly targets use 32-bit operands for KEYBITS=32; C/Go/Python use 256-bit).

- **Commit phase** (per round): generate random r (weight t), y = e ⊕ r, permutation π; compute c0 = hash(π, H·r^T), c1 = hash(σ(r)), c2 = hash(σ(y)) where σ = apply(π, ·)
- **Challenge** (Fiat-Shamir via NL-FSCX): b ∈ {0, 1, 2} derived from H(msg, c0, c1, c2)
- **Response**: b=0 → (σ(r), σ(y)); b=1 → (π, r); b=2 → (π, y)
- **Verify**: consistency of commitments and weight-t checks per challenge branch
- Security: EUF-CMA under the Syndrome Decoding assumption

#### HPKE-Stern-F — Code-Based KEM (Niederreiter)

Niederreiter-style KEM with syndrome as ciphertext and NL-FSCX hash as session key.

- **Encap**: sample e' (weight t); ct = H·e'^T; K = hash(seed, e')
- **Decap** (known-e' demo): K = hash(seed, e'); production requires a QC-MDPC syndrome decoder

#### NL-FSCX primitives

Both protocols share `sternHash` (NL-FSCX v1 with ROL(v,4) key schedule, 8 steps) and `sternMatrixRow` (same construction for parity-check matrix H). Fisher-Yates permutation generation uses `nl_fscx_v1` as PRNG.

#### Files changed

- `Herradura cryptographic suite.py` — `stern_hash1/2`, `stern_matrix_row`, `stern_syndrome`, `stern_popcount_eq2`, `stern_gen_perm`, `stern_apply_perm`, `stern_rand_error`, `stern_fs_challenges`, `hpks_stern_f_sign/verify`, `hpke_stern_f_encap/decap_known`; demo + Eve tests in main
- `CryptosuiteTests/Herradura_tests.py` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.go` — same 13 functions (`SternHash1`, etc.); demo + Eve tests
- `CryptosuiteTests/Herradura_tests.go` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.c` — same 13 functions; demo + Eve tests
- `CryptosuiteTests/Herradura_tests.c` — tests [17]–[18] (Stern-F sign+verify, KEM), benchmark [28]
- `Herradura cryptographic suite.s` (ARM Thumb-2) — 13 Stern-F functions + demo + Eve tests; SDF_N=32
- `CryptosuiteTests/Herradura_tests.s` (ARM Thumb-2) — tests [11]–[12]
- `Herradura cryptographic suite.asm` (NASM i386) — 13 Stern-F functions + demo + Eve tests; SDF_N=32
- `CryptosuiteTests/Herradura_tests.asm` (NASM i386) — tests [11]–[12]

#### Test results

All targets produce passing correctness tests:
- Assembly targets (ARM/NASM, N=32): [11] 3/3 verified, [12] 3/3 keys match
- C/Go/Python (N=256): [17] sign+verify, [18] encap+decap KEM, plus Eve-resistance tests in main

---

## [1.5.17] - 2026-04-26

### Performance — NTT twiddle precomputation eliminates `rnl_mod_pow` calls per `rnl_poly_mul` (C, Go)

Adds a lazy-initialized static twiddle table to the NTT used by HKEX-RNL, eliminating all
`rnl_mod_pow` invocations from the hot path after the first `rnl_poly_mul` call.

#### What was recomputed on every call

Each `rnl_poly_mul` call previously executed:
- 2 `rnl_mod_pow` calls for ψ and ψ⁻¹ (pre/post-twist powers)
- 3 × `log₂n` `rnl_mod_pow` calls inside the three `rnl_ntt` invocations (one per butterfly stage)
- 1 additional `rnl_mod_pow` for n⁻¹ inside the inverse NTT

Total: ~27 modular exponentiations (each up to 16 multiplications) per `rnl_poly_mul`.

#### What is precomputed

- `psi_pow[n]` / `psi_inv_pow[n]` — ψ^i and ψ^{-i} for pre/post-twist
- `stage_w_fwd[log₂n]` / `stage_w_inv[log₂n]` — per-stage ω for forward/inverse NTT
- `inv_n` — n⁻¹ mod q for INTT scaling

Initialized on first use (same lazy-init pattern as `m_inv_ba`). After initialization the per-call
cost is ~3 table lookups per stage (replacing 3 `rnl_mod_pow` calls).

#### Files changed

- `Herradura cryptographic suite.c` — `rnl_twiddle_init`, `rnl_tw` struct; `rnl_ntt` and `rnl_poly_mul` use precomputed table
- `CryptosuiteTests/Herradura_tests.c` — `rnl32_tw_init`, `rnl32_tw` (2-entry array for n∈{32,64}); `rnl32_ntt`, `rnl32_poly_mul`, `rnl_poly_mul_n` use precomputed table
- `Herradura cryptographic suite.go` — `rnlTwEntry` struct, `rnlTwCache` map, `rnlTwGet`; `rnlNTT` and `rnlPolyMul` use precomputed table
- `CryptosuiteTests/Herradura_tests.go` — same

#### Observed speedup

Go bench [25] HKEX-RNL handshake (n=64): **3.15 K → 4.72 K ops/sec (+50%)**.
C bench [25] (n=32): 66.6 K ops/sec (single size; n=64 path also optimized via `rnl_poly_mul_n`).

---

## [1.5.16] - 2026-04-25

### Fix — HKEX-RNL: Peikert 1-bit reconciliation eliminates key-agreement failures (all targets)

Implements Peikert cross-rounding reconciliation for HKEX-RNL across all six language
targets (C, Go, Python, ARM Thumb-2, NASM i386, Arduino) in both suite and test files.
Reduces key-agreement failure rate from 2.04% (n=32) / 37.24% (n=256) to **0%**.

#### Protocol change

Alice (reconciler) generates a 1-bit hint per ring coefficient from her raw product
polynomial $K_\text{poly,A}$ and transmits it alongside her public key:
$$h_i = \left\lfloor \frac{4c_i + \lfloor q/2 \rfloor}{q} \right\rfloor \bmod 2$$
Both parties use Alice's hint to extract each key bit (NewHope cross-rounding):
$$b_i = \left\lfloor \frac{2c_i + h_i \cdot \lfloor q/2 \rfloor + \lfloor q/2 \rfloor}{q} \right\rfloor \bmod p'$$
Because `max|K_poly_A[i] − K_poly_B[i]| ≤ 379 ≪ q/4 = 16384`, the hint always
resolves boundary crossings exactly.  Security assumptions are unchanged.

#### Test criterion change

Test [14]/[7] pass criterion raised from ≥ 90% to **100%** agreement.

#### Files changed

- `Herradura cryptographic suite.py` — `_rnl_hint`, `_rnl_reconcile_bits`; `_rnl_agree` returns `(K_raw, hint)` on reconciler path, `K_raw` on receiver path
- `CryptosuiteTests/Herradura_tests.py` — same helpers; test [14] criterion 100%; bench [25] updated
- `Herradura cryptographic suite.c` — `rnl_hint`, `rnl_reconcile_bits`; `rnl_agree(…, hint_in, hint_out)` with NULL sentinel
- `CryptosuiteTests/Herradura_tests.c` — `rnl32_hint`, `rnl32_reconcile`, `rnl32_agree`; `rnl_hint_n`, `rnl_reconcile_n`, `rnl_agree_n`; test [14] criterion 100%
- `Herradura cryptographic suite.go` — `rnlHint`, `rnlReconcileBits`; `rnlAgree(…, hintIn []byte) (*BitArray, []byte)`
- `CryptosuiteTests/Herradura_tests.go` — same; test [14] criterion 100%; bench [25] updated
- `Herradura cryptographic suite.ino` — `rnl_hint`, `rnl_reconcile`; `rnl_agree(…, hint_in, hint_out)` with NULL sentinel
- `Herradura cryptographic suite.s` — `rnl_hint32`, `rnl_reconcile32`, `rnl_agree_full`, `rnl_agree_recv`; call site updated
- `CryptosuiteTests/Herradura_tests.s` — same four subroutines; test [7] criterion 10/10
- `Herradura cryptographic suite.asm` — `rnl_hint32`, `rnl_reconcile32`, `rnl_agree_full` (EAX=s,EBX=C_other→EAX=key,EDX=hint), `rnl_agree_recv` (ECX=hint); call site updated
- `CryptosuiteTests/Herradura_tests.asm` — same; test [7] criterion 10/10
- `SecurityProofs.md §11.4.2` — new "Peikert reconciliation" subsection with hint/extraction formulas and correctness guarantee
- `SecurityProofs.md §11.5 Q2` — two new rows confirming 0 failures at n=32 and n=256
- `SecurityProofs.md §11.6` — replaced ⚠ Correctness warning with confirmation table; status updated
- `SecurityProofsCode/hkex_rnl_failure_rate.py` — §5 added; `_rnl_hint`, `_rnl_reconcile_bits`, `_rnl_exchange_reconciled`; asserts 0 failures at both n=32 and n=256

---

## [1.5.15] - 2026-04-25

### Analysis — HKEX-RNL key-agreement failure rate characterized (all deployed parameters)

New script `SecurityProofsCode/hkex_rnl_failure_rate.py` measures the empirical
key-disagreement rate P(K_A ≠ K_B) at deployed parameters across four sections.

#### Results

| Parameters | Failures | Rate | 95% CI |
|---|---|---|---|
| n=32, p=4096, η=1, 10 000 trials | 204/10 000 | **2.04%** | 1.78–2.34% |
| n=256, p=4096, η=1, 5 000 trials | 1 862/5 000 | **37.24%** | 35.9–38.6% |

Single-bit errors dominate (201/204 at n=32; 1456/1862 at n=256). Maximum bit-error
count: 2 at n=32, 5 at n=256.

#### Root-cause analysis (§2)

Per-coefficient error (`max|eA−eB| = 134`) is tiny relative to the extraction threshold
(16 384 = q/4), yet failures occur at extraction boundaries.  Root cause: ring convolution
over n coefficients accumulates error as O(√n), so at n=256 boundary crossings are frequent.
A p-sensitivity sweep (§4) confirms no p value below q fixes the problem (0.80% at p=8192).

#### Verdict

**Reconciliation hints required.** The single-polynomial structure of HKEX-RNL (vs. the
k×k matrix in Kyber) gives insufficient noise averaging at n=256.  NewHope-style 1-bit
reconciliation hints are needed; they add n/8 bytes of public data per party and reduce the
failure rate to effectively zero.  Architectural fix planned (TODO.md item #13).

#### Files changed

- `SecurityProofsCode/hkex_rnl_failure_rate.py` — new; four-section analysis script
- `SecurityProofs.md §11.5 Q2` — four new rows; removed ⚠ pending-verification note;
  added p-sensitivity table
- `SecurityProofs.md §11.6` — replaced stale "reliable without reconciliation" claim with
  correctness-warning block; added failure-rate table and reconciliation-hint requirement

---

## [1.5.14] - 2026-04-25

### Documentation — HSKE-NL-A2 deterministic encryption caveat (all targets)

HSKE-NL-A2 carries no nonce: the same (plaintext, key) pair always produces the
same ciphertext.  It does not achieve IND-CPA security in the multi-message sense
unless an external session differentiator is embedded in the plaintext before
encryption.  This usage constraint was undocumented; added in all seven locations:

- **`SecurityProofs.md §11.3.2`** — new paragraph after the cost analysis:
  explains the IND-CPA gap, contrasts with HSKE-NL-A1's per-session nonce, and
  gives concrete guidance (embed sequence number / nonce / session ID in plaintext).
- **`Herradura cryptographic suite.py`** — `CAUTION:` line added to the HSKE-NL-A2
  protocol comment block.
- **`Herradura cryptographic suite.c`** — same `CAUTION:` added to the block comment.
- **`Herradura cryptographic suite.go`** — one-liner in the protocol list expanded to
  note determinism and multi-message constraint.
- **`Herradura cryptographic suite.s`** (ARM Thumb-2) — `CAUTION:` line added inside
  the block comment preceding the HSKE-NL-A2 section.
- **`Herradura cryptographic suite.asm`** (NASM i386) — `CAUTION:` comment added
  above the `mov eax, hske_nl2_hdr` instruction.
- **`Herradura cryptographic suite.ino`** (Arduino) — `CAUTION:` comment added inside
  the banner block.

**No functional code changes.**

---

## [1.5.13] - 2026-04-24

### Fixed — HSKE-NL-A1 counter=0 step-1 degeneracy (security, all targets)

**Root cause.** The HSKE-NL-A1 keystream call `nl_fscx_revolve_v1(base, base XOR ctr, n/4)`
passes `A = B = base` when `ctr = 0`.  With `A = B`, `FSCX(A, B) = M(A ⊕ B) = M(0) = 0`, so
step 1 contributes only the linear term `ROL(2·base, n/4)`.  Non-linearity accumulates only
from step 2 onward — the same degeneracy fixed for the HKEX-RNL KDF in v1.5.10.

**Fix.** Replace the A (seed) argument with `ROL(base, n/8)` across all language targets:

```
ks[i] = nl_fscx_revolve_v1(ROL(base, n/8), base XOR i, n/4)
```

For n=256 (C/Go/Python): `ROL(base, 32)`.
For n=32 (ARM Thumb-2, NASM i386, Arduino): `ROL(base, 4)` — implemented as `ROR(base, 28)` on ARM.

**Files changed (9):**
- `Herradura cryptographic suite.c` — seed via `ba_rol_k(&seed_a1, &base_a1, KEYBYTES)` (n/8=32)
- `Herradura cryptographic suite.go` — `baseA1.RotateLeft(n/8)`
- `Herradura cryptographic suite.py` — `base_a1.rotated(KEYBITS // 8)`
- `Herradura cryptographic suite.s` — `ror r0, r0, #28` before `bl nl_fscx_revolve_v1`
- `Herradura cryptographic suite.asm` — `rol eax, 4` before `call nl_fscx_revolve_v1`
- `Herradura cryptographic suite.ino` — `_rol32(base, 4)`
- `CryptosuiteTests/Herradura_tests.c` — inline ROL in test [12] for n=64 and n=128
- `CryptosuiteTests/Herradura_tests.go` — `base.RotateLeft(size/8)` in test [12]
- `CryptosuiteTests/Herradura_tests.py` — `base.rotated(size // 8)` in test [12] and bench [23]

**Documentation updated:**
- `SecurityProofs.md §11.3.1` — updated keystream formula and added seed-rotation rationale
- `SecurityProofs.md §11.6` — updated KDF table entry to reflect v1.5.10 seed fix (was stale)
- `Herradura cryptographic suite.c:933` — fixed stale `q=3329` comment (should be `q=65537` since v1.5.4)

**TODO.md items closed:** #9 (degeneracy fix), #10 (stale q comment), #11 (stale §11.6 KDF formula).

---

## [1.5.12] - 2026-04-24

### Changed — `SecurityProofs.md`: §12 integrated into earlier sections

`§12 (Classical and Quantum Security Analysis)` was a late appendix holding
analysis that logically belonged alongside the earlier protocol-development sections.
Content redistributed to match the development timeline:

- **§9.2.4** — expanded with full DLP attack taxonomy (BSGS, Pohlig–Hellman, index
  calculus, quasi-polynomial), n=32 BSGS experimental verification, and cross-reference
  to §10.9.
- **§6** — added cross-reference to §10.8 for post-fix quantum analysis.
- **§10.6** — classical security analysis of v1.4.0 protocols (HSKE known-plaintext,
  HPKS forgery resistance, HPKE CDH attack path).
- **§10.7** — HPKS challenge function algebraic properties (affine bijection,
  predictable delta identity, ROM gap for EUF-CMA).
- **§10.8** — quantum algorithm analysis for v1.4.0 (Grover, Simon, Bernstein–Vazirani,
  Shor, HHL).
- **§10.9** — root-cause analysis of GF(2^n)* as DLP group; comparison table across
  GF(2^n)*, Z_p*, ECDLP, Ring-LWR; motivation for HKEX-RNL.
- **§11.7** — protocol-level quantum security summary table (all protocols).
- **§12 removed** — no content lost; every subsection relocated.

**Files changed (1):** `SecurityProofs.md`.

---

## [1.5.11] - 2026-04-23

### Fixed — KaTeX rendering errors in `SecurityProofs.md` §11

Four incremental fixes resolving three distinct parse failures in §11.4:

1. **`\$` inside inline math** (§11.4.2, line 1065): GitHub's Markdown parser treats
   `\$` as closing the `$...$` span, leaving `\overset{` with an unclosed brace.
   Fix: `\overset{\$}` → `\overset{\textdollar}`.

2. **`\{`/`\}` inside italic span** (§11.4.1, line 1039): `\{`/`\}` inside `*...*`
   italic markup are Markdown-escaped to bare `{`/`}` before KaTeX sees them, making
   set braces invisible.
   Fix: `\{` → `\lbrace`, `\}` → `\rbrace` (letter-prefixed; not a Markdown escape).

3. **Italic span blocking math** (§11.4.1): the `*Verified for ...*` span prevented
   GitHub's math extension from parsing `$...$` delimiters inside it.
   Fix: removed the `*...*` italic markers; `\{`/`\}` reverted from `\lbrace`/`\rbrace`
   (not needed outside italic context).

4. **Nested parentheses breaking math span** (§11.4.2, KDF formula): formula
   `($sk = \text{NL-FSCX-REVOLVE}(K, K, n/4)$)` — the inner `(K, K, n/4)` parens
   satisfy GitHub's link-paren-depth tracker before the `$` math span closes.
   Fix: outer `(` `$...$` `)` rewritten as `, where $sk = ...,$` (no wrapping parens).

**Files changed (1):** `SecurityProofs.md`.

---

## [1.5.10] - 2026-04-22

### Changed — HKEX-RNL KDF simplified to single-pass with ROL(K, n/8) seed

The KDF seed degeneracy (`fscx(K, K) = 0` on step 1 when A₀ = B = K`) was the root
cause.  Two-pass chain (v1.5.10-initial) was simplified to a single pass once the v2
second pass was shown to be bijective for fixed K — adding no one-wayness.

**Final KDF (all targets):**
```
seed = ROL(K, n/8);  sk = nl_fscx_revolve_v1(seed, K, n/4)
```

For n=256 (C/Go/Python): `ROL(K, 32)`.
For n=32 (assembly/Arduino/C-tests): `ROL(K, 4)`.

`SecurityProofs.md §11.4` updated with algebraic rationale and revised table.

**Files changed (12):** all language targets (suite + tests) and `SecurityProofs.md`.

**TODO.md item closed:** #4 (HKEX-RNL KDF degeneracy fix).

---

## [1.5.9] - 2026-04-22

### Changed — `nl_fscx_revolve_v2_inv`: precompute δ(B) once; HSKE-NL-A1 per-session nonce

Two independent improvements across all language targets:

#### Performance — precompute δ(B) in `nl_fscx_revolve_v2_inv`

`delta(B)` was recomputed on every iteration even though B is constant throughout the
loop.  Now computed once before the loop; inner body becomes `z = y − delta; y = B ⊕ m_inv(z)`.
Eliminates one multiply-and-rotate (or big-integer multiply for n=256) per step in
Python, C (32/64/128-bit), Go, Arduino, ARM Thumb-2, and NASM i386.

**Files changed (12):** all language targets (suite + tests). Closes TODO #8.

#### Security — HSKE-NL-A1 per-session nonce

Added random nonce N to HSKE-NL-A1 counter-mode so the keystream changes each session
even when K is reused.  Session base becomes `K ⊕ N`; N is generated fresh per run and
displayed alongside ciphertext.  Applied to Python, C, Go, Arduino, ARM Thumb-2, and
NASM i386 suite + test files.

**Files changed (9):** suite and test files for all targets. Closes TODO #3.

---

## [1.5.8] - 2026-04-21

### Added — build and run scripts for all language targets

Eight shell scripts added to the repository root:

| Script | Purpose |
|---|---|
| `build_c.sh` | Build C suite and tests; checks for `gcc` |
| `build_go.sh` | Build Go suite and tests; checks for `go` |
| `build_arm.sh` | Build ARM Thumb-2 binaries; checks for `arm-linux-gnueabi-gcc` |
| `build_asm_i386.sh` | Build NASM i386 binaries; checks for `nasm` + linker |
| `build_arduino.sh` | Build Arduino firmware; checks for `arduino-cli` |
| `run_arm.sh` | Run ARM binaries via `qemu-arm`; usage instructions |
| `run_asm_i386.sh` | Run i386 binaries via `qemu-i386`; usage instructions |
| `run_arduino.sh` | Run Arduino firmware via `simavr`; usage instructions |

Each build script prints `apt-get install` instructions for any missing tool.

**Files changed (8):** new scripts only.

---

## [1.5.7] - 2026-04-21

### Changed — precomputed M⁻¹ rotation table for `nl_fscx_v2_inv`; Arduino banner fix

#### Performance — precomputed M⁻¹ rotation table

`M⁻¹(X) = M^{n/2−1}(X)` is now applied via a precomputed rotation table: XOR of
`ROL(X, k)` for each `k` where bit `k` of `M⁻¹(1)` is set.

- **n=256 (C/Go/Python):** table bootstrapped once on first call via the old
  `fscx_revolve` path (lazy init, cached per bit-size).
- **n=32 (assembly/Arduino/C-tests):** constant `0x6DB6DB6D` hardcoded
  (21 rotations, analytically verified).
- **n=64/128 (C test file):** 64-bit constants hardcoded.

Reduces each `nl_fscx_v2_inv` step from 127 FSCX iterations (n=256) to ~170
XOR-rotation pairs (~2n/3 density). All language targets updated: C, Go, Python,
Arduino (unrolled helper), ARM Thumb-2 (ROR+EOR pairs), NASM i386 (ROL+XOR pairs).

**Files changed (12):** all language targets (suite + tests).

#### Fixed — stale v1.5.3 version banner in Arduino `loop()`

`loop()` in both `.ino` files still printed `v1.5.3`; corrected to `v1.5.7`.

**Files changed (2):** `Herradura cryptographic suite.ino`, `CryptosuiteTests/Herradura_tests.ino`.

---

## [1.5.6] - 2026-04-20

### Fixed — modular bias in `rnl_rand_poly` — 3-byte rejection sampling

The previous 4-byte draw followed by naive `% Q` had ~1/2³² per-coefficient bias
(value 0 appeared once more than all others over the full 32-bit cycle).

**Fix (all targets):** 24-bit rejection-sampling loop with threshold
`(1<<24) − (1<<24)%65537 = 16711935`. Rejection probability ≈ 0.39%.

Added `rnl_rand_coeff()` helper to C tests (replaces `rand32()%Q` in
`rnl32_rand_poly` and `rnl_rand_poly_n`).

Applied to: Python, C, Go, ARM Thumb-2, NASM i386, Arduino.

**Files changed (9):** `Herradura cryptographic suite.{c,go,py,s,asm,ino}`,
`CryptosuiteTests/Herradura_tests.{c,go,py}`.

---

## [1.5.5] - 2026-04-20

### Changed — C test suite: multi-size loops, PQC benchmarks, output alignment (Phases 1–5)

Five-phase expansion bringing `Herradura_tests.c` to full parity with Python and Go:

#### Phase 1–2 (earlier) — infrastructure

Generalized `BitArray` with `int nbits`/`int nbytes` fields; added `ba_add` (mod 2ⁿ
addition) required by NL-FSCX at non-32-bit widths. Added `gf_mul_64`/`gf_pow_64`
(GF(2⁶⁴), poly `0x1B`) and corresponding 64-bit FSCX/NL-FSCX primitives.

#### Phase 3 — GF/NL multi-size loops (tests [1],[5]–[9],[14]–[16])

- Tests [1],[5],[6]: loop over `{32, 64, 256}`.
- Tests [7]–[9],[14]–[16]: loop over `{32, 64}`.
- Key-sensitivity PASS criterion aligned to `mean ≥ n/4` (matching Python/Go).
- 64-bit Schnorr uses `__uint128_t` for `(a·e) mod (2⁶⁴−1)` overflow safety.

#### Phase 4 — FSCX/NL-FSCX multi-size loops (tests [2]–[4],[10]–[13])

Added 128-bit FSCX primitives (`fscx128`/`fscx_revolve128` via `__uint128_t`) and full
128-bit NL-FSCX v1/v2/inv suite; `rol128_32` for n/4=32-bit shift; `rand128()` helper.

- Tests [2]–[4]: loop `{64, 128, 256}` using `fscx64`/`fscx128`/`ba_fscx` dispatch.
- Tests [10]–[13]: loop `{64, 128}` using 64/128-bit NL-FSCX scalar functions.
  (256-bit NL-FSCX deferred — requires 256-bit integer multiply.)
- `popcount128()` helper for 128-bit Hamming distance in test [2].

#### Phase 5 — test [11] bijectivity methodology alignment

Upgraded test [11] bijectivity sub-test to match Python/Go: sample
`BIJ_SAMPLES=256` random A values per B and detect output collisions via O(n²)
pairwise scan (vs. prior single-pair draw).

#### Output and benchmarks alignment

- Version banner bumped to v1.5.5 in `Herradura_tests.c`, `.py`, `.go`.
- C test labels: added `[CLASSICAL]` tag to tests [1]–[9] and `[PQC-EXT]` to
  [10]–[16], matching existing Python/Go output.
- C section headers renamed to match Python/Go.
- PQC benchmarks [22]–[25] ported from Python/Go to C:
  - [22] NL-FSCX v1 revolve throughput (32-bit, n/4=8 steps)
  - [22b] NL-FSCX v2 revolve+inv throughput (32-bit, r_val=24 steps)
  - [23] HSKE-NL-A1 counter-mode throughput (32-bit, ctr=0)
  - [24] HSKE-NL-A2 revolve-mode round-trip (32-bit, r_val=24 steps)
  - [25] HKEX-RNL full handshake throughput (n=32)

**Files changed (3):** `CryptosuiteTests/Herradura_tests.{c,go,py}`.

---

## [1.5.4] - 2026-04-20

### Changed — replace O(n²) polynomial multiplication with negacyclic NTT in all implementations

Cooley-Tukey NTT over Z₆₅₅₃₇ (Fermat prime) with negacyclic twist
`ψ = 3^{(q−1)/(2n)} mod q` replaces the naive O(n²) `_rnl_poly_mul` in every
language implementation and test suite. ~32× speedup at n=256; ~6× at n=32.

| Target | Change |
|---|---|
| C, Go, Python | `rnl_ntt`/`rnlNTT`/`_ntt_inplace` + NTT-based `poly_mul` |
| ARM Thumb-2 (.s) | Precomputed tables + `rnl_ntt` subroutine (`umull` + fast Fermat mod) |
| NASM i386 (.asm) | Precomputed tables + `rnl_ntt` (stack-frame cdecl) + NTT `poly_mul` |
| Arduino (.ino) | Same NTT using `uint64_t` multiply |

`SecurityProofs.md` status line updated with v1.5.4 NTT note.

**Files changed (13):** all language targets (suite + tests) and `SecurityProofs.md`.

---

## [1.5.3] - 2026-04-19

### Changed — HKEX-RNL secret sampler upgraded to CBD(η=1); assembly bug fixes

#### Security — CBD(η=1) secret polynomial sampler

Replaced the uniform `{0,1}` secret polynomial sampler (`rnl_small_poly` /
`rnlSmallPoly` / `_rnl_small_poly`) with centered binomial distribution CBD(η=1)
across all language targets.

CBD(1) samples each coefficient as `(a − b) mod q` where `a, b` are independent
uniform bits, producing values in `{−1, 0, 1}` with zero mean and `P(±1) = 1/4`.
This matches the Kyber/NIST PQC baseline secret distribution and eliminates the
positive mean bias of the previous `{0,1}` sampler — a prerequisite for standard
Ring-LWR hardness arguments. The max coefficient magnitude (1) is unchanged, so
the noise budget and parameter set `(n, q, p, p', η)` are unaffected.

`SecurityProofs.md §11.4.2` and `§11.6` updated to document CBD(η=1) and its rationale.

**Files changed (13):** all language targets (suite + tests) and `SecurityProofs.md`.

#### Fixed — ARM `cbz` hi-register and NASM `poly_mul` stack offset

- **ARM Thumb-2:** `cbz` only accepts lo-registers r0–r7; replaced `cbz r9`/`cbz r10`
  with `cmp`+`beq` pairs in both `.s` files.
- **NASM i386:** after `pop ebx` in `rnl_poly_mul`, `[esp]` = k and `[esp+4]` = i;
  the code was reading `[esp+4]` (= i) to get k, writing every partial product to
  `rnl_tmp[i]` instead of `rnl_tmp[k]`. Fixed to `[esp]` in both `.rpm_add_no_sub`
  and `.rpm_neg_no_sub` branches in both `.asm` files.

**Files changed (4):** `Herradura cryptographic suite.{asm,s}`,
`CryptosuiteTests/Herradura_tests.{asm,s}`.

---

## [1.5.2] - 2026-04-18

### Fixed — KaTeX rendering in `SecurityProofs.md` (`^*` and `\mathcal{R}_q` cross-span emphasis)

Three more broken rendering regions in `SecurityProofs.md` fixed:

- **`^*` cross-span `*`-emphasis** (lines 726, 1202–1206, 1249–1254): `*` (U+002A)
  between `^` and `$`/`,`/`}` (all CommonMark punctuation) is both-flanking — it can
  open AND close `*`-emphasis.  When multiple `$...\mathbb{GF}(2^n)^*...$` spans appear
  in the same paragraph, or when the forgery section packs many `$R^*$`, `$s^*$`,
  `$e^*$` spans together, opener/closer pairs form across span boundaries, consuming
  the intervening `$` math delimiters and garbling all affected text.
  Fix: replace `*` (U+002A) with `∗` (U+2217, ASTERISK OPERATOR) in each
  problematic span — only the three affected paragraphs, not the many safe
  single-occurrence spans elsewhere.  U+2217 is not a CommonMark emphasis delimiter;
  KaTeX renders it identically to `*` in math mode.
- **Lines 1068–1069** (`$$K_A$$`/`$$K_B$$` display math): `\mathcal{R}_q` (where `}`
  precedes `_q`) across the two consecutive display-math blocks creates a cross-block
  `_`-emphasis opener/closer pair; fixed with `\mathcal R_q`.

---

### Fixed — KaTeX rendering in `SecurityProofs.md` (cross-span emphasis collision)

Six formulas in `SecurityProofs.md` rendered as raw source code on GitHub due to
cmark-gfm processing emphasis `_` delimiters before detecting `$...$` inline math spans.

Root cause: `_` preceded by `}` (a CommonMark punctuation character) satisfies the
left-flanking delimiter rule and can open an emphasis run.  When a matching
right-flanking `_` appears in a later math span on the same line or paragraph,
GitHub's parser consumes both underscores as emphasis, destroying the enclosing
`$` math spans.

Fixes applied:

- **Lines 1062–1063** (`\mathcal{R}_q`, `\mathcal{R}_p`) — dropping the braces around
  the single-character `\mathcal` argument (`\mathcal R_q`) means `_q` is now preceded
  by the alphanumeric `R`, which is not left-flanking and cannot open emphasis.
- **Line 1171** (`\text{NL-FSCX-REVOLVE}_{v1}`) — `}_{v1}` still has `_` preceded by
  `}`, so the entire subscripted name is rewritten using `\textunderscore` separators:
  `\text{NL-FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{v1}`.
- **Lines 1057–1059** (§11.4.2 shared polynomial setup) — same `\mathcal{R}_q` →
  `\mathcal R_q` fix; opener `_q` on line 1057 was pairing with `m_\text{blind}`
  closer on line 1059 across the paragraph boundary of two `$...$` spans.
- **Line 1071** (§11.4.2 commutativity sentence) — `\mathcal{R}_q` opener at start
  of line paired with `m_\text{blind}` closer in the adjacent span on the same line;
  fixed with `\mathcal R_q`.

---

### Proposed — multi-size key-length tests for `Herradura_tests.c`

Analysis of the gap between the Python and C test suites: `Herradura_tests.py`
loops each test over `SIZES = [64, 128, 256]` (FSCX tests) and `GF_SIZES = [32, 64]`
(GF protocol tests), while `Herradura_tests.c` runs each test at a single hardcoded
size (256-bit for tests [1]–[6], 32-bit for tests [7]–[16]).

Three structural changes proposed for a follow-up implementation commit:

1. **Generalize `BitArray`** — add `int nbits; int nbytes;` fields (max buffer stays
   32 bytes); thread `nbits` through all `ba_*` and `ba_fscx*` functions; add `ba_add`
   (mod 2^n addition) required by NL-FSCX v1/v2 at non-32-bit widths.

2. **Add 64-bit GF layer** — `gf_mul_64` / `gf_pow_64` (poly `0x1BULL`,
   GF(2^64)); `fscx64` / `fscx_revolve64`; `nl_fscx_v1_64` / `nl_fscx_v2_64` and
   their inverses, mirroring the existing `_32` helpers.

3. **Loop tests over multiple sizes**:
   ```c
   static const int SIZES[]    = {64, 128, 256}; /* tests 2,3,4,10,11,12,13 */
   static const int GF_SIZES[] = {32, 64};        /* tests 1,5,6,7,8,9,15,16 */
   ```

Version strings bumped to v1.5.2 in `Herradura_tests.c`, `Herradura_tests.py`,
and `Herradura_tests.go`.

---

## [1.5.1] - 2026-04-16

### Fixed / Added

#### Test execution limits (C, Python, Go)

- `CryptosuiteTests/Herradura_tests.c` — `--rounds`/`-r` and `--time`/`-t` CLI flags;
  `HTEST_ROUNDS` / `HTEST_TIME` environment variable fallbacks; wall-clock timeout
  via `CLOCK_MONOTONIC`; all 16 security tests scale iteration counts and pass
  thresholds to actual runs completed.
- `CryptosuiteTests/Herradura_tests.py` — same flags via `argparse`; `_trange()`
  generator checks `time.monotonic()` every 64 iterations.
- `CryptosuiteTests/Herradura_tests.go` — same flags via `flag` package;
  `timeExceeded()` helper with `time.Since()`.

#### Documentation — KaTeX rendering fixes (README.md, SecurityProofs.md)

Two separate KaTeX errors resolved (both caused by v1.5.0 content not applying
the conventions established in earlier fix commits):

- **`'_' allowed only in math mode`** — `\_` inside `\text{}` is rejected in
  text mode.  Fix: place `\_` in math mode between separate `\text{}` groups.
- **`Double subscripts: use braces to clarify`** — `\text{X}\_\text{Y}\_\text{Z}`
  parses `\_` as the subscript operator twice on the same base.  Fix: use
  `\textunderscore` (a text/math command that produces a literal `_` glyph) in
  place of `\_`.

Final correct pattern (58 occurrences across both files):
`\text{FSCX}\textunderscore\text{REVOLVE}` /
`\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}` /
`\text{fscx}\textunderscore\text{revolve}`.
`README.md`: also `\mathit{enc}\textunderscore\mathit{key}` and
`\mathit{dec}\textunderscore\mathit{key}`.

- **`Missing close brace`** (`SecurityProofs.md` line 702) — `\xleftarrow{\$}`
  inside `$...$` inline math: GitHub's markdown parser treats `\$` as closing
  the math span, leaving `\xleftarrow{` with no matching `}`.  Fix: replace
  `\$` with `\textdollar` (KaTeX's dollar-sign command, contains no literal
  `$` character).

#### Documentation and code inconsistency review

Cross-file audit of documentation vs. implementation; all inconsistencies resolved.

**CLAUDE.md:**
- Test count corrected: `9 security tests` → `16 security tests` (reflects v1.5.0 tests [1]–[16]).
- Repository structure: removed `SecurityProofs2.md` (never existed) and `PQCanalysis.md`
  (removed in v1.4.1, merged into `SecurityProofs.md §12`).
- Protocol stack section updated from v1.4.0 to v1.5.0; added five NL/PQC protocol entries
  (HSKE-NL-A1, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL).

**README.md:**
- Version in title updated to v1.5.1.

**`CryptosuiteTests/Herradura_tests.c`:**
- Stale block comments on benchmark functions corrected: `[11]`–`[14]` → `[18]`–`[21]`
  (printf statements already printed the correct numbers; only the block comments lagged).

#### PQC proofs and tests review

**`SecurityProofs.md`:**
- §11 section header: `(v1.4.0)` → `(v1.5.0)`; opening sentence updated to "documents
  the verified fixes implemented in v1.5.0" (was "proposes verified fixes").
- §11.4.2 HKEX-RNL protocol: clarified that `m_blind = m(x) + a_rand` is a **shared**
  public polynomial (one party generates `a_rand` and transmits it; both use the same
  `m_blind`).  Previous wording "Bob generates analogously" implied independent polynomials,
  which breaks key agreement by commutativity.
- §11.4.3 attack table: added `(q=769, n=16, 200 trials…)` attribution — the q value
  used for the table was previously unstated.
- §11.5 Q1 table: first row description `B=0` corrected to `random B` (the verification
  script generates random B per trial, not a fixed B=0).
- §11.5 Q2 table: replaced two "not yet verified" rows with confirmed results for the
  deployed parameters `(q=65537, n=32)` and `(q=65537, n=256)`.
- §11.6: updated recommended parameters from `q=3329/p=1024/p'=32` to the deployed
  `q=65537/p=4096/pp=2`; replaced stale "code migration planned" status note with
  v1.5.0 implementation status and noise-amplification verification summary.
- §12.5 protocol summary table: added six new rows covering the v1.5.0 NL protocols
  (HSKE-NL-A1, HSKE-NL-A2 — both key-only and known-plaintext cases; HPKS-NL; HPKE-NL;
  HKEX-RNL).

**`SecurityProofsCode/hkex_nl_verification.py`:**
- §2.1 extended to verify `m(x)` invertibility for deployed parameters `(q=65537, n=32)`
  and `(q=65537, n=256)` — both confirmed invertible with `m·m⁻¹ = 1`.
- §2.3 extended to compute noise amplification `‖m⁻¹‖₁ · q/(2p)` for deployed
  `q=65537, n=32, p=4096` (result: ≈4.3×10⁶ ≫ q — structural protection confirmed).

**`CryptosuiteTests/Herradura_tests.{c,go,py}` — test [14] HKEX-RNL:**
- All three implementations now report both raw agreement (`K_A == K_B`) and
  KDF-processed agreement (`sk_A == sk_B`) — previously only the Go file checked both.
- Added explanatory comment describing the shared-polynomial protocol structure.
- Go benchmark [25]: same structural consistency (was already correct; comment added).

---

## [1.5.0] - 2026-04-11

### Added — NL-FSCX v2, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL across all implementations

Version 1.5.0 adds non-linear extensions to FSCX (breaking GF(2)-linearity and period structure)
and a post-quantum key exchange (HKEX-RNL via Ring-LWR), porting them to every language
including C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

#### New primitives

- **NL-FSCX v1** — `nl_fscx(A,B) = fscx(A,B) ⊕ ROL(A+B, n/4)`: integer carry injection
  breaks GF(2) linearity and orbit periods; used as KDF/commitment function.
- **NL-FSCX v2** — `nl_fscx_v2(A,B) = fscx(A,B) + δ(B) mod 2^n`,
  where `δ(B) = ROL(B·⌊(B+1)/2⌋ mod 2^n, n/4)`: bijective in A for all B;
  closed-form inverse `A = B ⊕ M⁻¹((Y − δ(B)) mod 2^n)` (`M⁻¹ = fscx_revolve(·, 0, n/2−1)`).

#### New protocols

- **HSKE-NL-A1** (counter-mode): `ks = nl_fscx_revolve_v1(K, K⊕ctr, i)`;
  `E = P ⊕ ks`; `D = E ⊕ ks = P`.
- **HSKE-NL-A2** (revolve-mode): `E = nl_fscx_revolve_v2(P, K, r)`;
  `D = nl_fscx_revolve_v2_inv(E, K, r) = P`.
- **HKEX-RNL** (Ring-LWR key exchange; conjectured quantum-resistant):
  shared `m_blind = m(x) + a_rand` in `Z_q[x]/(x^n+1)`;
  Alice/Bob derive `C = round_p(m_blind · s)` with small secret `s`;
  agreement via `K = round_pp(s · lift(C_other))`; final `sk = nl_fscx_revolve_v1(K, K, i)`.
  Parameters: `n=256` (C/Go/Python), `n=32` (assembly/Arduino/C-tests); `q=65537`, `p=4096`.
- **HPKS-NL** (NL-hardened Schnorr): challenge `e = nl_fscx_revolve_v1(R, P, i)`.
- **HPKE-NL** (NL-hardened El Gamal): `E = nl_fscx_revolve_v2(P, enc_key, i)`;
  `D = nl_fscx_revolve_v2_inv(E, dec_key, i)`.

#### Files updated (all languages)

- `Herradura cryptographic suite.py` — NL-FSCX v1/v2, all five new protocols, Eve bypass tests.
- `CryptosuiteTests/Herradura_tests.py` — tests [10]–[16] (NL-FSCX, HSKE-NL-A1/A2, HKEX-RNL,
  HPKS-NL, HPKE-NL); benchmarks renumbered [17]–[25].
- `Herradura cryptographic suite.go` — same protocol additions as Python.
- `CryptosuiteTests/Herradura_tests.go` — same test additions.
- `Herradura cryptographic suite.c` — NL-FSCX v1/v2 (256-bit BitArray), HKEX-RNL (n=256),
  HPKS-NL, HPKE-NL; `ba_add256`, `ba_sub256`, `ba_mul256_lo`, `ba_rol64_256`, `m_inv_ba` added.
- `CryptosuiteTests/Herradura_tests.c` — tests [10]–[16] (32-bit NL-FSCX and RNL, n=32);
  benchmarks renumbered [17]–[21].
- `Herradura cryptographic suite.asm` — NASM i386: `nl_fscx_delta_v2`, `nl_fscx_v1/v2/v2_inv`,
  `nl_fscx_revolve_v1/v2/v2_inv`, `m_inv_32`; RNL poly helpers (n=32); new protocol sections.
- `CryptosuiteTests/Herradura_tests.asm` — NASM i386: tests [1]–[10] (v1.4.0 tests [1]–[4]
  plus new [5]–[10] for NL/RNL protocols); memory-variable loop counters; EBP pass counter.
- `Herradura cryptographic suite.s` — ARM Thumb-2: same additions as NASM; `umull`/`udiv`/`mls`
  for mod-65537 ring arithmetic; `.ltorg` after every subroutine.
- `CryptosuiteTests/Herradura_tests.s` — ARM Thumb-2: tests [1]–[10]; r10/r11 loop
  counter/pass count (callee-saved); `it`/conditional suffix pattern for modular arithmetic.
- `Herradura cryptographic suite.ino` — Arduino: NL-FSCX v1/v2/inverse, HKEX-RNL (n=32),
  HPKS-NL, HPKE-NL; LCG PRNG for RNL poly generation.
- `CryptosuiteTests/Herradura_tests.ino` — Arduino: tests [1]–[10], 30-second rerun loop.

#### Security proofs (SecurityProofs.md)

- **§11** — NL-FSCX non-linearity and PQC extensions (Theorems 11–12; HKEX-RNL,
  HSKE-NL-A1/A2, HPKS-NL, HPKE-NL; C3 hybrid recommendation).
- **§12** — Classical and quantum security analysis (merged from PQCanalysis.md in v1.4.1).

---

## [1.4.1] - 2026-04-08

### Documentation — PQCanalysis.md merged into SecurityProofs.md

`PQCanalysis.md` is removed.  All content has been integrated into `SecurityProofs.md`
as **§12 (Classical and Quantum Security Analysis)**, with duplicate sections eliminated
and the most up-to-date data retained.

#### Content added to SecurityProofs.md (§12)

- **§12.1 Classical DLP attacks on GF(2^n)*** — full attack complexity table (BSGS,
  Pohlig–Hellman, index calculus, Barbulescu quasi-polynomial); BSGS n=32 experiment
  (`A_PRIV=0xDEADBEEF`, solved in 0.622 s); effective-security discussion.
- **§12.2 Classical security of HSKE / HPKS / HPKE** — known-plaintext attack on HSKE
  (1 pair → full $c_K$, 0 unconstrained bits at n=64); classical forgery analysis for
  HPKS; CDH attack path for HPKE.
- **§12.3 HPKS challenge function — algebraic properties** — affine bijection proof
  (0 collisions in 50 000 trials); predictable challenge delta identity
  $e(R_2) \oplus e(R_1) = M^i \cdot (R_1 \oplus R_2)$ (100% verified); consequence for
  ROM-based security proofs and the forking lemma.
- **§12.4 Quantum algorithm analysis** — Grover (symmetric key-only), Simon (inapplicable
  to GF DLP, applicable to HSKE affine structure), Bernstein–Vazirani (HSKE 1-query
  recovery), Shor (primary quantum threat: O(n² log n) DLP for HKEX-GF/HPKS/HPKE),
  HHL (irrelevant — GF(2) systems already classically efficient).
- **§12.5 Protocol-level quantum security summary** — updated table including HKEX-RNL
  (§11.4) as the proposed PQC replacement.
- **§12.6 Root cause: why GF(2^n)* is the wrong group** — comparison table across
  GF(2^n)*, Z_p*, ECDLP, and Ring-LWR; motivation for the §11.4 HKEX-RNL proposal.

#### Files removed

- `PQCanalysis.md` — superseded by SecurityProofs.md §12.

#### Status update

- `SecurityProofs.md` header updated to reference §12.
- Last-updated date updated to 2026-04-08.

---

## [1.4.0] - 2026-04-06

### BREAKING CHANGE — HKEX replaced with HKEX-GF; HPKS upgraded to Schnorr; HPKE upgraded to El Gamal

The classical HKEX key exchange is **broken**: the shared secret `sk = S_{r+1}·(C⊕C2)` is directly computable from the two public wire values alone (proved in SecurityProofs.md, Theorem 7). Version 1.4.0 replaces it with Diffie-Hellman over `GF(2^n)*`, and replaces the trivially-reversible HPKS/HPKE XOR constructions with standard Schnorr signatures and El Gamal encryption.

#### Protocol changes (all languages)

- **HKEX-GF** replaces HKEX in every implementation:
  - Alice: private scalar `a`, public `C = g^a` (GF exponentiation)
  - Bob: private scalar `b`, public `C2 = g^b`
  - Shared: `sk = C2^a = C^b = g^{ab}` (field commutativity)
  - Arithmetic: carryless polynomial multiplication mod irreducible `p(x)` — XOR and left-shift only
- **`fscx_revolve_n` removed** from all files. The nonce contribution `S_k·N` cancels identically from both sides of the key-exchange equation (Theorem 8), providing zero security benefit.
- **HSKE** simplified to `fscx_revolve(P, key, i)` / `fscx_revolve(E, key, r)` (previously used `fscx_revolve_n`; functionally equivalent, now simplified).
- **HPKS** replaced with a **Schnorr-style signature** (32-bit GF parameters):
  - Sign: choose nonce `k`; `R = g^k`; challenge `e = fscx_revolve(R, msg, i)`; response `s = (k - a·e) mod (2^32-1)`
  - Verify: `g^s · C^e == R`
  - The 32-bit field is used because the Schnorr response requires modular integer arithmetic over the group order; at 256-bit this requires GMP-style big integers not available in plain C or assembly.
- **HPKE** replaced with **El Gamal + HSKE** (32-bit GF parameters):
  - Bob: ephemeral `r`; `R = g^r`; `enc_key = C^r = g^{ar}`; `E = fscx_revolve(P, enc_key, i)`
  - Alice: `dec_key = R^a = g^{ra}`; `D = fscx_revolve(E, dec_key, r) = P`
  - Correctness: `g^{ar} = g^{ra}` by field commutativity.

#### Security

| n | Primitive polynomial | Classical security |
|---|---------------------|-------------------|
| 32 | x³²+x²²+x²+x+1 = 0x00400007 | demo only |
| 64 | x⁶⁴+x⁴+x³+x+1 = 0x1B | ~40 bits |
| 128 | x¹²⁸+x⁷+x²+x+1 = 0x87 | ~60–80 bits |
| 256 | x²⁵⁶+x¹⁰+x⁵+x²+1 = 0x425 | ~128 bits (recommended) |

Generator `g = 3` (polynomial `x+1`) for all field sizes.

#### Files updated

- `Herradura cryptographic suite.py` — GF arithmetic added, HKEX-GF implemented, `fscx_revolve_n` removed, HPKS Schnorr and HPKE El Gamal implemented, Eve bypass tests updated.
- `Herradura_tests.py` — test [1] updated for HKEX-GF; tests [7] Schnorr correctness, [8] Schnorr Eve-resistance, [9] El Gamal correctness added; benchmarks renumbered [10]–[14].
- `Herradura cryptographic suite.go` — `GfMul`/`GfPow` added (`math/big`), `FscxRevolveN` removed, HPKS Schnorr and HPKE El Gamal implemented.
- `Herradura_tests.go` — same structural updates as Python tests.
- `Herradura cryptographic suite.c` — `gf_mul_ba`/`gf_pow_ba` added for GF(2^256) and `gf_mul_32`/`gf_pow_32` for 32-bit GF; `ba_fscx_revolve_n` removed; HPKS Schnorr and HPKE El Gamal implemented with 32-bit GF operands.
- `Herradura_tests.c` — tests [7] Schnorr (1000 trials), [8] Schnorr Eve-resistance, [9] El Gamal (1000 trials); benchmarks [10]–[14] updated.
- `Herradura cryptographic suite.s` — ARM Thumb-2: `gf_mul_32`/`gf_pow_32` and LCG PRNG added; `fscx_revolve_n` removed; Schnorr and El Gamal sections implemented using `umull`/`adds`/`addcs`/`subs`/`subcc` for 32-bit modular arithmetic.
- `Herradura_tests.s` — ARM Thumb-2: test_hpks (Schnorr, 20 trials) and test_hpke (El Gamal, 20 trials) added.
- `Herradura cryptographic suite.asm` — NASM i386: `gf_mul_32`/`gf_pow_32` and LCG PRNG added; `FSCX_revolve_n` removed; Schnorr and El Gamal sections using `mul`/`add`/`adc`/`sub`/`dec` for modular arithmetic.
- `Herradura_tests.asm` — NASM i386: test_hpks (Schnorr, 20 trials) and test_hpke (El Gamal, 20 trials) added.
- `Herradura cryptographic suite.ino` — Arduino: LCG PRNG added, HPKS Schnorr and HPKE El Gamal implemented.
- `Herradura_tests.ino` — Arduino: test_hpks and test_hpke replaced with Schnorr and El Gamal correctness tests.

#### Security proofs added (SecurityProofsCode/)

- `hkex_gf_test.py` — standalone HKEX-GF test suite (GF arithmetic, DH correctness 5K, Eve resistance 5K, BSGS DLP illustration, benchmarks).
- `hkex_cy_test.py` — FSCX-CY exhaustive analysis (non-linearity, HKEX-CY failure, period explosion, Eve resistance).

#### Files removed

- `Herradura_KEx.c` — basic HKEX-only C implementation (superseded by the full suite).
- `Herradura_KEx.go` — basic HKEX-only Go implementation (superseded by the full suite).
- `Herradura_KEx.py` — basic HKEX-only Python implementation (superseded by the full suite).
- `Herradura_KEx_bignum.c` — arbitrary-precision HKEX using GNU MP (superseded by the full suite with GF arithmetic).
- `HKEX_arm_linux.s` — basic HKEX-only ARM assembly example (superseded by `Herradura cryptographic suite.s`).
- `Herradura_AEn.c` — HAEN asymmetric encryption (deprecated since v1.0; superseded by HSKE).
- `HAEN.asm` — HAEN in NASM i386 assembly (deprecated).
- `FSCX_HAEN1.ino` — Arduino HAEN proof of concept (16-bit; deprecated).
- `FSCX_HAEN1_ulong.ino` — Arduino HAEN proof of concept (32-bit; deprecated).

#### Repository reorganised

- `CryptosuiteTests/` folder created. All `Herradura_tests.*` source files moved here.
- `CryptosuiteTests/go.mod` added (`module herradurakex/tests`, no external dependencies).
- The repository now contains only: cryptographic suite implementations, their tests, and security proof code/documentation.

#### Documentation updated

- `README.md` — rewritten for v1.4.0: HKEX-GF protocol description, Schnorr/El Gamal protocol summary, updated build instructions and performance table, repository structure diagram.
- `CLAUDE.md` — updated build commands, repository structure, and protocol stack description.
- `SecurityProofs.md` — Section 9 (non-linear proposals), Section 10 (v1.4.0 migration summary), Section 5.1/5.2 tables updated.
- `PQCanalysis.md` — fully revised for v1.4.0 protocols (HKEX-GF, HPKS Schnorr, HPKE El Gamal, HSKE).

#### Non-linearity and PQC analysis (SecurityProofsCode/, SecurityProofs.md §11)

This work addresses the two remaining structural weaknesses of v1.4.0:
FSCX GF(2)-linearity (linear key-recovery attacks) and the quantum vulnerability of
HKEX-GF (Shor's algorithm solves GF(2^n)* DLP).

**SecurityProofs.md §11** — NL-FSCX non-linearity and PQC extensions:
- Theorem 11: formal proof that fscx_revolve is GF(2)-affine (linear key-recovery
  attack surface) with closed-form `R·X ⊕ K·B`.
- **NL-FSCX v1** — `nl_fscx(A,B) = fscx(A,B) ⊕ ROL((A+B) mod 2^n, n/4)`: integer
  carry injection breaks GF(2) linearity; verified non-bijective (collisions at n=8
  and n=32); no consistent period.
- **NL-FSCX v2** — `nl_fscx_v2(A,B) = fscx(A,B) + ROL(B·⌊(B+1)/2⌋ mod 2^n, n/4)`:
  B-only offset; bijective (0/256 non-bijective at n=8); exact closed-form inverse
  `A = B ⊕ M⁻¹((Y − δ(B)) mod 2^n)`; verified correct 1000/1000.
- **HSKE-A1** (counter mode, v1) and **HSKE-A2** (revolve mode, v2) constructions.
- Theorem 12: m(x) = 1+x+x^{n-1} is invertible in Z_q[x]/(x^n+1); ‖m⁻¹‖_1 >> q
  (dense inverse amplifies rounding noise; naive algebraic attack 0/200 for all p).
- **HKEX-RNL** (B2): PQC key exchange via Ring-LWR with blinded FSCX polynomial
  `m_blind = m + a_rand`; reduces to standard Ring-LWR hardness (NIST-adjacent);
  NL-FSCX v1 used as KDF post-processor.
- **C3 hybrid** recommendation: v1 for one-way roles (KDF, HPKS commitment, counter
  HSKE); v2 for invertible roles (revolve HSKE, HPKE payload).

**SecurityProofsCode/hkex_nl_verification.py** (new) — three-part verification script:
- Q1: nl_fscx period analysis (n=8: 938/1024 no period; n=32: 500/500 no period);
  HSKE counter-mode correctness 200/200.
- Q2: negacyclic circulant matrix construction; invertibility for q ∈ {257…12289};
  algebraic attack 0/200 for all p; noise amplification analysis.
- Q3: v1 non-bijectivity (n=8: 256/256; n=32: collision A=0x4dbde3c0/A'=0x2a48fe58);
  iterative inverse divergence 500/500; v2 bijectivity + inverse 1000/1000.

**SecurityProofsCode/hkex_cfscx_preshared.py** (new) — preshared-value FSCX constructions
PS-1 through PS-5 (integer expansion); security analysis of each scheme.

**SecurityProofsCode/hkex_cfscx_twostep.py** (new) — two-step FSCX constructions with
compression/expansion; R2-CB (weakest: no S needed), R2-EC (B-cancellation proven).

**SecurityProofsCode/hkex_cfscx_intops.py** (new) — integer-operation schemes (padlock,
asymmetric, hash-like); includes AK-2 zero-matrix finding (S drops out entirely:
(I⊕R⊕R²⊕R³)=0) and PL-1 null-space finding (rank((R⊕I)·K)=2 → 25% commutativity).

**SecurityProofsCode/hkex_cfscx_compress.py** and **hkex_cfscx_blong.py** (new) —
cfscx_compress algebraic analysis and long-block construction variants.

---

## [1.3.7] - 2026-04-01

### Added — NASM i386, ARM Thumb, and Arduino implementations

Six new source files bring full HKEX + HSKE + HPKS + HPKE coverage to assembly
and embedded platforms.

#### `Herradura cryptographic suite.asm` (new — NASM i386)

- Full four-protocol suite (HKEX, HSKE, HPKS, HPKE) in NASM i386 assembly.
- Pure Linux syscall interface (`int 0x80`); no libc or `asm_io` dependency.
- 32-bit operands: `KEYBITS=32`, `I_VALUE=8`, `R_VALUE=24`.
- Fixed test values: A=0xDEADBEEF, B=0xCAFEBABE, A2=0x12345678, B2=0xABCDEF01,
  key=0x5A5A5A5A, plaintext=0xDEADC0DE.
- Build: `nasm -f elf32 … -o suite32.o && x86_64-linux-gnu-ld -m elf_i386 -o … suite32.o`
- Run: `qemu-i386 "./Herradura cryptographic suite_i386"` (or natively on x86/x86_64)

#### `Herradura_tests.asm` (new — NASM i386)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- LCG PRNG: Numerical Recipes constants (multiplier 1664525, addend 1013904223,
  seed 0x12345678).
- Outer loops use `dec ecx / jnz near` to avoid the ±127-byte limit of `loop`.
- All four tests verified: 100/100 passed.

#### `Herradura cryptographic suite.s` (new — GAS ARM 32-bit Thumb)

- Full four-protocol suite in ARM Thumb-2 assembly (`.cpu cortex-a7`).
- Defines both `fscx_revolve` and `fscx_revolve_n` (the existing
  `HKEX_arm_linux.s` calls `fscx_revolve_n` but never defines it).
- `.thumb_func` annotations required for ARM/Thumb interworking.
- Build: `arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"`
- Run: `qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"`

#### `Herradura_tests.s` (new — GAS ARM 32-bit Thumb)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- All four tests verified: 100/100 passed on qemu-arm.

#### `Herradura cryptographic suite.ino` (new — Arduino)

- Full four-protocol suite for Arduino (32-bit `unsigned long`).
- `Serial` output at 9600 baud; `printHex` / `printHexLine` helpers for
  zero-padded hex display.
- Compatible with boards using `unsigned long` as a 32-bit type (Uno, Nano,
  Mega, etc.).

#### `Herradura_tests.ino` (new — Arduino)

- Four correctness tests × 100 LCG-random trials each (HKEX, HSKE, HPKS, HPKE).
- Results printed over Serial; `loop()` reruns every 30 seconds.

#### `README.md`

- Updated Assembly build section with commands for the new NASM and ARM suite
  and test binaries.
- Added Arduino section with `arduino-cli` compile-check command.

---

## [1.3.6] - 2026-04-01

### Added — HPKS sign+verify correctness test across all three test files

#### `Herradura_tests.c`, `Herradura_tests.go`, `Herradura_tests.py`

- **Security test [7] — HPKS sign+verify correctness** added to all three test
  files. Each of 10 000 trials generates fresh random keys (A, B, A2, B2) and a
  random plaintext, then checks:

  ```
  C  = fscx_revolve(A, B, i)
  C2 = fscx_revolve(A2, B2, i)
  hn = C ⊕ C2
  S  = fscx_revolve_n(C2, B, hn, r) ⊕ A ⊕ P   (sign)
  V  = fscx_revolve_n(C,  B2, hn, r) ⊕ A2 ⊕ S  (verify)
  assert V == P
  ```

  Correctness follows from the HKEX equality: both sides of the shared-key
  computation equal `fscx_revolve_n(·, ·, hn, r) ⊕ A[2]`, so the XOR terms
  cancel and `V = P` holds for all valid key pairs. Expected: 10 000/10 000.

- **Benchmarks renumbered [8–12]** (were [7–11]) to accommodate the new test.

- **Version comment** updated to v1.3.6 in each test file header.

---

## [1.3.5] - 2026-04-01

### Added — README: guidance on when to use FSCX_REVOLVE vs FSCX_REVOLVE_N

#### `README.md`

- New subsection **'When to use FSCX_REVOLVE vs FSCX_REVOLVE_N'** added under
  the existing FSCX_REVOLVE_N section. Includes a per-operation reference table
  covering HKEX key setup, HKEX key derivation, HSKE, HPKS, and HPKE, with the
  function to use and the security rationale for each choice.

---

## [1.3.4] - 2026-04-01

### Fixed — SecurityProofs.md: formula corrections and HPKS₂ protocol

#### `SecurityProofs.md`

- **§1.4 nonce propagation (formula error):** Removed the unsupported claim
  "HD = r/n × n = r bits" for k = r = 3n/4. That expression was a tautology,
  not a derived result, and "HD = k" is false in general (counterexample:
  k = 3 gives HD = 4 via S₃·e₀ = e₁⊕e₂⊕e_(n-2)⊕e_(n-1)). Replaced with the
  correct statement: HD = popcount(S_k · e_j), which is deterministic, and the
  empirically confirmed result HD = n/4 for k = i = n/4 (test [6]).

- **§W4 solution count (formula error):** "n^n solutions" corrected to "2^n
  solutions". The map φ(A,B) = M^i·A + M·S_i·B is linear from GF(2)^(2n) to
  GF(2)^n; its kernel has dimension n, giving 2^n elements in every preimage.

- **§2.3 HPKS → HPKS₂ (theoretical protocol fix):** The original scheme
  S = sk_A ⊕ P trivially leaks sk_A from a single (P, S) pair. The corrected
  scheme HPKS₂ replaces the XOR with HSKE encryption of P under sk_A:

    Alice:  S = FSCX_REVOLVE_N(P, sk_A, sk_A, i)   [HSKE-encrypt]
    Bob:    V = FSCX_REVOLVE_N(S, sk_B, sk_B, r)   [HSKE-decrypt]; check V = P

  Correctness follows from HSKE (Theorem 5). The trivial key-recovery attack is
  eliminated because the coefficient of sk_A in the equation is S_i·(M+I) =
  S_i·x⁻¹(x+1)², which is a zero divisor in R_n (not a unit), so the equation
  has no unique solution for sk_A. The scheme remains GF(2)-linear in sk_A, so
  full EUF-CMA requires a non-linear primitive beyond the current suite.

- **§Summary table:** HPKS row updated to HPKS₂ with revised EUF-CMA status.

---

## [1.3.3] - 2026-03-30

### Added — HPKE performance benchmark across all three test files

#### `Herradura_tests.c`, `Herradura_tests.go`, `Herradura_tests.py`

- **Benchmark [11] — HPKE encrypt+decrypt round-trip** added to all three test
  files. Each iteration performs the full HPKE protocol cycle:
  1. Key setup: `C = fscx_revolve(A, B, i)`, `C2 = fscx_revolve(A2, B2, i)`,
     `hn = C ⊕ C2`
  2. Bob encrypts: `E = fscx_revolve_n(C, B2, hn, r) ⊕ A2 ⊕ P`
  3. Alice decrypts: `D = fscx_revolve_n(C2, B, hn, r) ⊕ A ⊕ E`

  Throughput on Raspberry Pi 5 (ARM Cortex-A76):

  | Implementation | 64-bit | 128-bit | 256-bit |
  |----------------|--------|---------|---------|
  | C (`gcc -O2`)  | — | — | 21.1 K ops/sec |
  | Go (`go run`)  | 2.80 K | 1.29 K | 0.61 K ops/sec |
  | Python 3       | 1.20 K | 604 | 303 ops/sec |

  HPKE throughput is comparable to HKEX because both require the same compute:
  2× `fscx_revolve(i)` for key setup and 2× `fscx_revolve_n(r)` for the
  encrypt/decrypt pair.

- **Version comment** added to each test file header referencing v1.3.3.

---

## [1.3.2] - 2026-03-29

### Changed — performance, readability, and cross-language structural consistency

#### All suite files (`Herradura cryptographic suite.{c,go,py}`)
- **Version headers** updated to v1.3.2; prior v1.1/v1.2 labels corrected to v1.3.

#### C — `Herradura cryptographic suite.c` and `Herradura_tests.c`
- **`ba_fscx` — fused single-pass**: ROL and ROR are now computed inline from
  adjacent bytes in a single loop, eliminating 4 temporary `BitArray` stack
  allocations and reducing 5 separate memory passes to 1.
  A `#if KEYBYTES < 2 #error` guard documents the KEYBITS ≥ 16 requirement.
- **`ba_fscx_revolve` / `ba_fscx_revolve_n` — double-buffering**: two local
  buffers alternate with `idx ^= 1`, eliminating one full `BitArray` struct
  copy per iteration step.
- **`ba_popcount` — hardware `__builtin_popcount`** (tests only): replaces the
  manual bit-shift loop; compiles to a single `POPCNT` instruction on x86-64/ARM.
- **`ba_xor_into` removed** (suite only): every call site replaced by
  `ba_xor(dst, dst, src)`, which is correct since `ba_xor` handles aliasing.
- **`ba_rol1` / `ba_ror1` removed**: rotation logic is now inlined inside
  `ba_fscx`; these helpers are no longer part of the API.

#### Go — `Herradura cryptographic suite.go` and `Herradura_tests.go`
- **`Fscx` rewritten**: replaces the parameter-shadowing style
  (`ba = ba.RotateLeft(1)`) with a direct formula expression — each of the six
  terms maps one-to-one to `A⊕B⊕ROL(A)⊕ROL(B)⊕ROR(A)⊕ROR(B)`.
- **Naming — suite file**: `Fscx_revolve` → `FscxRevolve`, `Fscx_revolve_n` →
  `FscxRevolveN`, `New_rand_bitarray` → `NewRandBitArray`; removes non-idiomatic
  underscores in exported Go names, consistent with the tests file.
- **Naming — tests file**: `New_rand_bitarray` → `newRandBitArray` (unexported).
- **Local variables in `main`**: `r_value`/`i_value` → `rValue`/`iValue`,
  `hkex_nonce` → `hkexNonce` (idiomatic Go camelCase).
- **`Popcount` — `math/bits.OnesCount8`** (tests only): replaces the manual
  bit-shift loop; compiles to a hardware popcount instruction.
- **`FlipBit` simplified** (tests only): `if cur == 0 / else` replaced by
  the one-liner `SetBit(&v, pos, v.Bit(pos)^1)`.

#### Python — `Herradura_KEx.py` (basic key-exchange demo)
- **`BitArray.rotated(n)`** added: same non-mutating rotation method as the suite
  and tests files; brings the basic demo into structural parity with those files.
- **`fscx` rewritten** using `rotated()`; no longer mutates its inputs.
- **`keybits` parameter removed** from `fscx`, `fscx_revolve`, and `fscx_revolve_n`:
  the parameter was unused in all three functions (size is carried by the
  `BitArray` object itself); callers in `main()` updated accordingly.

#### Python — `Herradura cryptographic suite.py` and `Herradura_tests.py`
- **`BitArray.rotated(n)`** — new non-mutating rotation method (both files):
  returns a new `BitArray` rotated left by `n` bits (right if `n < 0`).
  Positive and negative rotations share one method, matching `RotateLeft` in Go.
- **`fscx` rewritten** (both files): replaces the copy-then-mutate pattern
  (`a.ror(1); a.rol(2)`) with a direct expression using `rotated()`.
  No input mutation occurs — the function is now a pure transformation.
- **`BitArray.random()` classmethod added** (suite only): the suite now uses the
  same `BitArray.random(size)` interface as the tests file; `new_rand_bitarray()`
  is removed.
- **`main()` function and `if __name__ == '__main__':` guard** (suite only):
  protocol demonstration code is wrapped in `main()`, consistent with Go and C
  which have explicit entry-point functions.
- **`fscx` defined before `fscx_revolve`** (suite only): declaration order now
  matches C and Go (definition before first use).
- **Module-level constants** (suite only): `KEYBITS = 256`, `I_VALUE`,
  `R_VALUE` defined at module scope, matching the C `#define` names.

#### Not applicable — `Herradura_KEx.{c,go}`, `Herradura_KEx_bignum.c`, `HAEN.asm`, `HKEX_arm_linux.s`
The v1.3.2 optimisations do not apply to these files:
- The C and Go basic KEx files and the GMP bignum file implement FSCX via a
  bit-by-bit extraction loop (`BITX`/`BIT` helpers) rather than byte-parallel
  ROL/ROR operations, so the fused single-pass `ba_fscx` is architecturally
  inapplicable. Their `FSCX_REVOLVE` loops operate on scalar or GMP values
  with no per-step struct copy to eliminate.
- The x86 NASM and ARM assembly files are fixed instruction sequences; none of
  the language-level improvements (compiler hints, Python integer arithmetic,
  Go struct layout) apply.

---

## [1.3.1] - 2026-03-29

### Changed
- **`Herradura_tests.c`**, **`Herradura_tests.go`**, **`Herradura_tests.py`**:

  - **Test [1] (non-commutativity)**: switched from `fscx_revolve` to
    `fscx_revolve_n` with a random nonce per trial, confirming
    `FSCX_REVOLVE_N(A,B,N,n) ≠ FSCX_REVOLVE_N(B,A,N,n)` in general.
    The nonce term `T_n(N)` cancels from both sides so commutativity depends
    only on A and B; the test remains 0/10000.

  - **New test [6] — FSCX_REVOLVE_N nonce-avalanche**: flip 1 bit of the nonce
    N while keeping A and B constant and measure the output Hamming distance.
    The change equals `T_n(e_k)` where `T_n = I + L + … + L^(n-1)`, which
    is independent of A and B (deterministic, so min = max = mean).
    For `n = size/4` (i_val): `HD = size/4` exactly — 16/32/64 bits for
    64/128/256-bit parameters respectively — far above the 3-bit single-step
    FSCX diffusion.  Pass criterion: `HD ≥ size/4`.

  - **Benchmark [7]** (was [6]): FSCX throughput — unchanged.
  - **Benchmark [8]** (was [7]): renamed from *FSCX_REVOLVE throughput* to
    **FSCX_REVOLVE_N throughput**; benchmark now calls `fscx_revolve_n` with
    a random nonce.
  - **Benchmarks [9–10]** (were [8–9]): HKEX handshake and HSKE round-trip —
    unchanged, renumbered.

---

## [1.3] - 2026-03-29

### Changed
- **`Herradura_tests.c`**: replaced fixed 64-bit integers with the same `BitArray`
  type used in `Herradura cryptographic suite.c`. Default key size is now **256 bits**
  (`KEYBITS = 256`, `I_VALUE = 64`, `R_VALUE = 192`), matching the Go and Python
  test files. Added `ba_popcount`, `ba_get_bit`, and `ba_flip_bit` helpers.
  Benchmarks now run for a fixed wall-clock target (`BENCH_SEC = 1.0`) and report
  M ops/sec or K ops/sec, matching the Go test style.

  All five security tests pass at 256-bit:
  1. Non-commutativity — 0 / 10000 commutative pairs
  2. Linear diffusion  — mean exactly 3 bits per flip (min=3, max=3)
  3. Orbit period      — all periods are 256 or 128
  4. Bit-frequency     — each bit set 47–53% of the time
  5. Key sensitivity   — mean Hamming distance exactly 1 bit per A-flip

- **`Herradura cryptographic suite.c`**: replaced fixed 64-bit integers with a
  `BitArray` type — a fixed-width bit string backed by a big-endian byte array —
  matching the Python and Go implementations. Default key size is now **256 bits**
  (`KEYBITS = 256`, `I_VALUE = 64`, `R_VALUE = 192`), controlled by a single
  `#define KEYBITS` at the top of the file. All four protocols (HKEX, HSKE, HPKS,
  HPKE) and the EVE bypass tests operate on `BitArray` operands.

  `BitArray` API:
  - `ba_rand`          — fill from `/dev/urandom`
  - `ba_xor` / `ba_xor_into` — bitwise XOR (out-of-place / in-place)
  - `ba_rol1` / `ba_ror1`    — rotate left/right by 1 bit (big-endian)
  - `ba_equal`         — constant-time-style `memcmp` equality
  - `ba_print_hex`     — zero-padded hex output
  - `ba_fscx`          — Full Surroundings Cyclic XOR
  - `ba_fscx_revolve`  — iterate FSCX n times
  - `ba_fscx_revolve_n` — nonce-augmented FSCX_REVOLVE (v1.1)

  Build: `gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"`

---

## [1.2] - 2026-03-29

### Added
- **`Herradura cryptographic suite.c`**: C equivalent of the Go/Python cryptographic
  suites, implementing all four protocols (HKEX, HSKE, HPKS, HPKE) with
  `FSCX_REVOLVE_N` and the full EVE bypass test suite. Uses 64-bit integers
  (`uint64_t`) and `/dev/urandom` for randomness.
  Build: `gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"`

- **`Herradura_tests.c`**, **`Herradura_tests.py`**, **`Herradura_tests.go`**:
  Security assumption tests and performance benchmarks, self-contained (no external
  dependencies). Tests run across 64/128/256-bit operand sizes (Python and Go) and
  64-bit (C), covering:
  1. FSCX_REVOLVE non-commutativity (expected: 0 / 10000 commutative pairs)
  2. FSCX single-step linear diffusion (expected: exactly 3 bits per flip —
     consequence of FSCX being a GF(2) linear map; L = Id ⊕ ROL ⊕ ROR)
  3. Orbit period (expected: period = P or P/2 for all random inputs)
  4. Bit-frequency balance (expected: each output bit set 47–53% of the time)
  5. HKEX session key XOR construction (expected: exactly 1-bit change per
     single-bit A flip — algebraic nonce cancellation property)
  Plus benchmarks for FSCX throughput, FSCX_REVOLVE throughput, full HKEX
  handshake, and HSKE round-trip (encrypt + decrypt).

### Changed
- **`Herradura cryptographic suite.go`** and **`Herradura cryptographic suite.py`**:
  replaced external `go-bitarray` / `bitstring` library dependencies with
  self-contained `BitArray` implementations backed by `math/big.Int` (Go) and
  Python `int` (Python), eliminating all third-party runtime dependencies.

- **`go.mod`** / **`go.sum`**: removed `github.com/tunabay/go-bitarray` dependency.

### Fixed
- **`Herradura cryptographic suite.go`** line 380: `%x` format argument was `V2`
  (a variable from the HSKE section) instead of `D2` (the HKEX public value for
  the EVE HPKE test). This caused the wrong value to be printed in the Eve HPKE
  output line.

### Mathematical notes
- FSCX(A,B) = FSCX(B,A) for all A, B (the formula is symmetric under swap).
  Non-commutativity arises only in FSCX_REVOLVE, where B is held constant across
  iterations.
- For FSCX as a polynomial over GF(2): `L(x) = (1 + t + t⁻¹)x`. By the Frobenius
  endomorphism, `L^(2^k) = 1 + t^(2^k) + t^(-2^k)`, so any power-of-2 step count
  (including i_value = P/4 when P is a power of 2) always produces exactly 3-bit
  single-step diffusion.
- In the HKEX XOR construction `sk = FSCX_REVOLVE_N(C2, B, hn, r) ⊕ A`, flipping
  one bit of A changes the session key by exactly 1 bit. The nonce term
  `S_r · L^i(e_k)` cancels algebraically to zero, leaving only the direct XOR
  contribution.

---

## [1.1] - 2026

### Added
- **`FSCX_REVOLVE_N`** primitive in `Herradura cryptographic suite` (Go and Python).
  Each iteration XORs a nonce N into the result:
  ```
  result = FSCX(result, B) ⊕ N
  ```
  This converts `FSCX_REVOLVE` from a purely GF(2)-linear function to an affine
  function, breaking per-step linearity while preserving the HKEX equality and
  orbit properties. See the [FSCX_REVOLVE_N section in the README](README.md)
  for the mathematical proof.

- **Session-specific nonce derivation** (no new secrets required):
  - HKEX, HPKS, HPKE: `hkex_nonce = C ⊕ C2`, computable from the public key
    since A2 and B2 are public (C2 = fscx_revolve(A2, B2, i)).
  - HSKE: nonce = preshared key, injecting the key at every revolve step rather
    than only at the input/output boundaries.

### Changed
- `Herradura cryptographic suite.go` and `Herradura cryptographic suite.py`:
  replaced all `fscx_revolve` calls (except the initial public-value generation
  of C and C2) with `fscx_revolve_n` using the appropriate nonce.
- Copyright year ranges updated across all source files to include 2026.

---

## [1.0] - 2024

### Added
- Initial release of `Herradura cryptographic suite` (Go and Python) implementing:
  - **HKEX** – key exchange in the style of Diffie-Hellman, using `FSCX_REVOLVE`.
  - **HSKE** – symmetric key encryption: `E = fscx_revolve(P, key, i)`;
    decrypt with `P = fscx_revolve(E, key, r)`.
  - **HPKS** – public key signature (must be composed with HSKE to be secure).
  - **HPKE** – public key encryption.
  - EVE bypass test suite covering all four protocols.

---

## Earlier history

### ARM assembly example – 2023
- Added `HKEX_arm_linux.s`: HKEX in ARM 32-bit assembly for Linux (Cortex-A7,
  thumb mode), runnable via QEMU.

### Bug fixes and cleanup – 2024
- Fixed `getMax` function in the C sample (`Herradura_KEx.c`).
- General code cleanup across C implementations.

### Python HKEX refactor – 2024
- Refactored `Herradura_KEx.py` for clarity and correctness (argument parsing,
  type hints, secure random generation with `secrets.randbits`).

---

## Original samples – 2017

- `Herradura_KEx.c` – reference C implementation of HKEX (64-bit integers).
- `Herradura_KEx_bignum.c` – arbitrary-precision HKEX using GNU MP (libgmp).
- `Herradura_KEx.go` – Go HKEX sample using `math/big`.
- ~~`Herradura_AEn.c`~~ – removed in v1.4.0 (HAEN deprecated; superseded by HSKE).
- ~~`FSCX_HAEN1.ino`~~ / ~~`FSCX_HAEN1_ulong.ino`~~ – removed in v1.4.0.
- ~~`HAEN.asm`~~ – removed in v1.4.0.
