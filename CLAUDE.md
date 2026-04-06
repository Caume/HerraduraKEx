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
SecurityProofsCode/                                 — formal break proofs (Python scripts)
SecurityProofs.md / SecurityProofs2.md              — algebraic analysis
PQCanalysis.md                                      — classical & post-quantum analysis
```

## Build Commands

### C
```bash
# Full cryptographic suite
gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"

# Security & performance tests
gcc -O2 -o CryptosuiteTests/Herradura_tests CryptosuiteTests/Herradura_tests.c
```

### Go
```bash
go run "Herradura cryptographic suite.go"
cd CryptosuiteTests && go run Herradura_tests.go
```
No external dependencies (go.sum is empty).

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
./CryptosuiteTests/Herradura_tests          # C — 9 security tests + 5 benchmarks
cd CryptosuiteTests && go run Herradura_tests.go
python3 CryptosuiteTests/Herradura_tests.py
```

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

### Protocol Stack (v1.4.0)

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

Parameters: i = n/4, r = 3n/4. GF arithmetic uses 32-bit operands in assembly/Arduino; 256-bit in C/Go/Python suite. HSKE and FSCX tests always use 256-bit.

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
