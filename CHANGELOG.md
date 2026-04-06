# Changelog

All notable changes to the Herradura Cryptographic Suite are documented here.

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
