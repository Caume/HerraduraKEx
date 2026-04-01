# Changelog

All notable changes to the Herradura Cryptographic Suite are documented here.

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
- `Herradura_AEn.c` – HAEN asymmetric encryption (deprecated; use HSKE instead).
- `Herradura_KEx.go` – Go HKEX sample using `math/big`.
- `FSCX_HAEN1.ino` / `FSCX_HAEN1_ulong.ino` – Arduino proofs of concept (16/32-bit).
- `HAEN.asm` – HAEN in Intel x86 32-bit NASM assembly.
