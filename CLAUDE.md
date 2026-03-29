# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HerraduraKEx (HKEX) is a cryptographic suite implementing a Diffie-Hellman-style key exchange scheme based on the FSCX (Full Surroundings Cyclic XOR) function. It provides multiple protocols: HKEX (key exchange), HSKE (symmetric encryption), HPKS (public key signature), and HPKE (public key encryption). Implementations exist in C, Go, Python, ARM/x86 assembly, and Arduino.

## Build Commands

### C
```bash
# Basic 64-bit
gcc -DINTSZ=64 -o HKEX Herradura_KEx.c

# With bignum (requires libgmp-dev)
gcc -DINTSZ=256 -o HKEX_bignum Herradura_KEx_bignum.c -lgmp

# x86 NASM assembly (requires asm_io.o library)
nasm -f elf HAEN.asm
gcc -m32 -o HAEN HAEN.o asm_io.o

# ARM assembly (requires arm-linux-gnueabi-gcc)
arm-linux-gnueabi-gcc -o HKEX_arm HKEX_arm_linux.s
qemu-arm ./HKEX_arm  # Run on non-ARM host
```

### Go
```bash
go run Herradura_KEx.go
go run "Herradura cryptographic suite.go"
```
Dependency: `github.com/tunabay/go-bitarray v1.3.1`

### Python
```bash
python3 Herradura_KEx.py -b 64 -v
python3 "Herradura cryptographic suite.py"
```
Dependency: `bitstring` package

## Testing

There is no automated test framework. Tests are manual: run each program and verify console output. The C programs include a `VERBOSE` compilation flag that enables brute-force attack simulations and intermediate value printing:
```bash
gcc -DINTSZ=64 -DVERBOSE -o HKEX Herradura_KEx.c
```

The Go and Python "cryptographic suite" files run EVE (eavesdropper) bypass tests inline on every execution.

## Core Cryptographic Architecture

### Primitives

**FSCX(A, B):**
```
C = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```
Non-commutative: `FSCX(A,B) ≠ FSCX(B,A)`. Iterating FSCX creates periodic orbits of length P or P/2 (P = bit size).

**FSCX_REVOLVE(A, B, n):** Iterates FSCX n times, keeping B constant:
```
FSCX_REVOLVE(A, B, n) = FSCX(FSCX(...FSCX(A,B)..., B), B)
```

### HKEX Protocol (key exchange)

1. Alice and Bob each generate secret pairs `(A, B)` and `(A2, B2)`
2. Each computes a public value: `D = FSCX_REVOLVE(A, B, i)` where `i ≈ P/4`
3. Each derives the shared key using the other's public value:
   - Alice: `FA = FSCX_REVOLVE(D2, B, r) ⊕ A` where `r = P - i`
   - Bob: `FA2 = FSCX_REVOLVE(D, B2, r) ⊕ A2`
   - Result: `FA == FA2`

### Protocol Stack
```
FSCX_REVOLVE (core primitive)
├── HKEX  — key exchange
├── HSKE  — symmetric encryption: E = FSCX_REVOLVE(plaintext, key, i); decrypt with r
├── HPKS  — public key signature (requires HKEX + HSKE)
└── HPKE  — public key encryption (builds on HKEX parameters)
```

Note: HAEN (older asymmetric encryption scheme in `Herradura_AEn.c`) is deprecated in favor of HSKE.

## Codebase Structure

Each language provides equivalent implementations at two levels:
- **Basic HKEX only**: `Herradura_KEx.{c,go,py}`
- **Full protocol suite**: `Herradura cryptographic suite.{go,py}`, `Herradura_AEn.c`

The `INTSZ` macro in C controls bit width (typically 64; use 256 with GMP).

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
