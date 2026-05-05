# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HerraduraKEx is a cryptographic suite implementing four protocols — HKEX-GF (key exchange), HSKE (symmetric encryption), HPKS (Schnorr signature), and HPKE (El Gamal encryption) — built on the FSCX (Full Surroundings Cyclic XOR) primitive and Diffie-Hellman arithmetic over GF(2^n)*. Implementations exist in C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

## Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite, one file per language
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}              — security tests & benchmarks
  go.mod
SecurityProofsCode/                                 — standalone Python proof/analysis scripts:
  hkex_gf_test.py          — HKEX-GF DH correctness + BSGS DLP illustration
  hkex_nl_verification.py  — NL-FSCX period analysis, Ring-LWR invertibility/noise, v2 bijectivity
  hkex_cy_test.py          — FSCX-CY exhaustive non-linearity & HKEX-CY failure proof
  hkex_cfscx_*.py          — preshared-value, two-step, integer-op, compress/blong constructions
  hkex_classical_break.py  — classical algebraic break proofs
  hkex_*_analysis.py       — FSCX_N, multi-nonce, and nonce-impossibility analyses
SecurityProofs.md                                   — algebraic analysis (incl. §11 NL/PQC, §12 quantum analysis)
```

## Build Commands

### C
```bash
# Full cryptographic suite
gcc -O2 -o "Herradura cryptographic suite_c" "Herradura cryptographic suite.c"

# Security & performance tests
gcc -O2 -o CryptosuiteTests/Herradura_tests_c CryptosuiteTests/Herradura_tests.c
```

> **Build collision hazard:** `go build file.go` (without `-o`) names its output
> after the source filename stem — identical to the old unsuffixed C binary path.
> The `_c` suffix makes all six target binaries distinct: `_c`, `_go`, `_arm`,
> `_i386`, `_avr.elf`. Always use `build_go.sh` or pass `-o name_go` explicitly
> when invoking `go build` directly. Never run bare `go build file.go`.

### Go
```bash
go run "Herradura cryptographic suite.go"
cd CryptosuiteTests && go run Herradura_tests.go
```
Two `go.mod` files: root-level (`module herradurakex`, suite only) and `CryptosuiteTests/go.mod` (`module herradurakex/tests`). Neither has external dependencies.

### Python
```bash
python3 "Herradura cryptographic suite.py"
python3 CryptosuiteTests/Herradura_tests.py
```
No external dependencies.

### Assembly
```bash
# ARM Thumb-2
arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"
arm-linux-gnueabi-gcc -o CryptosuiteTests/Herradura_tests_arm CryptosuiteTests/Herradura_tests.s
qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"

# NASM i386
nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
nasm -f elf32 CryptosuiteTests/Herradura_tests.asm -o tests32.o
x86_64-linux-gnu-ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
x86_64-linux-gnu-ld -m elf_i386 -o CryptosuiteTests/Herradura_tests_i386 tests32.o
qemu-i386 "./Herradura cryptographic suite_i386"
```

## Testing

No automated test framework. Tests are manual: run each program and verify console output.

```bash
# C — tests [1]–[18] (security) + benchmarks [19]–[28]
./CryptosuiteTests/Herradura_tests_c
./CryptosuiteTests/Herradura_tests_c -r 500        # cap each test at 500 iterations
./CryptosuiteTests/Herradura_tests_c -t 2.0        # cap wall-clock per test/bench at 2 s
HTEST_ROUNDS=200 HTEST_TIME=1.5 ./CryptosuiteTests/Herradura_tests_c  # env-var equivalents

# Go — tests [1]–[16] + benchmarks [17]–[28]
cd CryptosuiteTests && go run Herradura_tests.go
cd CryptosuiteTests && go run Herradura_tests.go -r 500 -t 2.0

# Python — tests [1]–[19] (security) + benchmarks [20]–[29]
python3 CryptosuiteTests/Herradura_tests.py
python3 CryptosuiteTests/Herradura_tests.py -r 500 -t 2.0

# Assembly — build first (see Build Commands), then run:
# ARM/NASM: tests [1]–[12]
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
```

The `-r`/`--rounds` flag caps iterations per security test; `-t`/`--time` sets the wall-clock limit for both tests and benchmarks. CLI flags override `HTEST_ROUNDS`/`HTEST_TIME` env vars.

The suite files run EVE (eavesdropper) bypass tests inline on every execution.

## Core Cryptographic Architecture

### Primitives

**FSCX(A, B):**
```
C = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```
Linear map M = I ⊕ ROL ⊕ ROR; order of M is n/2. Iterating FSCX creates periodic orbits of length P or P/2 (P = bit size).

**FSCX_REVOLVE(A, B, n):** Iterates FSCX n times, keeping B constant.

**GF(2^n) arithmetic:** `gf_mul` (carryless multiply mod irreducible polynomial), `gf_pow` (square-and-multiply). Generator g = 3.

### Protocol Stack (v1.5.0)

**Classical (v1.4.0):**
```
FSCX_REVOLVE + GF(2^n)* arithmetic
├── HKEX-GF  — C = g^a; C2 = g^b; sk = C2^a = C^b = g^{ab}
├── HSKE     — E = fscx_revolve(P, key, i); D = fscx_revolve(E, key, r) = P
├── HPKS     — Schnorr: R = g^k; e = fscx_revolve(R, msg, i);
│              s = (k - a·e) mod (2^n-1); verify: g^s · C^e == R
└── HPKE     — El Gamal: enc_key = C^r = g^{ar};
               E = fscx_revolve(P, enc_key, i);
               dec_key = R^a = g^{ra};
               D = fscx_revolve(E, dec_key, r) = P
```

**NL/PQC (v1.5.0):**
```
NL-FSCX primitives + Ring-LWR
├── HSKE-NL-A1 — counter-mode: ks = nl_fscx_revolve_v1(K, K⊕ctr, i); E = P ⊕ ks
├── HSKE-NL-A2 — revolve-mode: E = nl_fscx_revolve_v2(P, K, r); D = inverse
├── HKEX-RNL   — Ring-LWR key exchange (conjectured quantum-resistant)
├── HPKS-NL    — Schnorr with NL-FSCX v1 challenge: e = nl_fscx_revolve_v1(R, msg, i)
└── HPKE-NL    — El Gamal with NL-FSCX v2: E = nl_fscx_revolve_v2(P, enc_key, i)
```

**Code-Based PQC (v1.5.18):**
```
Stern identification protocol (ZKP for syndrome decoding)
├── HPKS-Stern-F — Fiat-Shamir signature (C/Go/Python: N=n=256, t=16, rounds=32;
│                  assembly/Arduino: N=32, t=2, rounds=4)
│                  commit: c0=hash(π,H·r^T), c1=hash(σ(r)), c2=hash(σ(y))
│                  challenge b∈{0,1,2} via NL-FSCX hash of msg+commitments
│                  response reveals permuted r, y=e⊕r, or permutation π
└── HPKE-Stern-F — Niederreiter KEM: ct=H·e'^T; K=hash(seed,e')
                   (demo uses known e'; production needs QC-MDPC decoder)
```

Parameters: i = n/4, r = 3n/4. GF arithmetic uses 32-bit operands in assembly/Arduino; 256-bit in C/Go/Python suite. HSKE and FSCX tests always use 256-bit.

## KaTeX Rendering Rules for Markdown Files

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX. Three classes of errors have been fixed and **must not be reintroduced**:

### 1. `'_' allowed only in math mode`
**Cause:** `\_` inside a `\text{}` block — KaTeX rejects `\_` in text mode.
**Wrong:** `\text{FSCX\_REVOLVE}`, `\mathit{enc\_key}`
**Correct:** use `\textunderscore` to produce a literal underscore glyph in math mode:
- `\text{FSCX}\textunderscore\text{REVOLVE}\textunderscore\text{N}`
- `\mathit{enc}\textunderscore\mathit{key}`

### 2. `Double subscripts: use braces to clarify`
**Cause:** using `\_` as the subscript operator between `\text{}` groups creates two subscripts on the same base.
**Wrong:** `\text{FSCX}\_\text{REVOLVE}\_\text{N}` (the intermediate "fix" for error 1)
**Correct:** same as above — `\textunderscore` is not a subscript operator, so it is safe for multi-segment names.

### 3. `Missing close brace`
**Cause:** `\xleftarrow{\$}` — GitHub's markdown parser treats `\$` as closing the inline math span `$...$`, so KaTeX receives an unclosed brace.
**Wrong:** `\xleftarrow{\$}`
**Correct:** `\xleftarrow{\textdollar}` — `\textdollar` is the KaTeX dollar-sign glyph command with no literal `$`.

### Summary table

| Pattern to avoid | Correct replacement | Error prevented |
|---|---|---|
| `\text{FOO\_BAR}` | `\text{FOO}\textunderscore\text{BAR}` | `'_' allowed only in math mode` |
| `\mathit{foo\_bar}` | `\mathit{foo}\textunderscore\mathit{bar}` | `'_' allowed only in math mode` |
| `\text{A}\_\text{B}\_\text{C}` | `\text{A}\textunderscore\text{B}\textunderscore\text{C}` | `Double subscripts` |
| `\xleftarrow{\$}` | `\xleftarrow{\textdollar}` | `Missing close brace` |

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
