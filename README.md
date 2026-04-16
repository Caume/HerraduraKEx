# Herradura Cryptographic Suite (v1.5.1)

The Herradura Cryptographic Suite implements cryptographic protocols built on the FSCX (Full Surroundings Cyclic XOR) primitive, Diffie-Hellman key exchange over GF(2^n)*, and a post-quantum Ring-LWR key exchange.

> **v1.4.0 note:** The original HKEX key exchange (based directly on FSCX_REVOLVE) was classically broken — the shared secret was directly computable from the two public wire values alone. v1.4.0 replaced it with **HKEX-GF**, a standard Diffie-Hellman construction over the multiplicative group of GF(2^n). See `SecurityProofs.md` for the formal proof.
>
> **v1.5.0 note:** FSCX is GF(2)-linear, making HSKE vulnerable to linear key-recovery attacks, and HKEX-GF is broken by Shor's algorithm. v1.5.0 adds **NL-FSCX** (non-linear extension breaking GF(2)-linearity and orbit periods) and **HKEX-RNL** (Ring-LWR key exchange conjectured quantum-resistant). See `SecurityProofs.md §11` for proofs and analysis.

---

# FSCX — The Core Primitive

Let $A$, $B$, $C$ be bitstrings of size $P$, where $A_i$ is the $i$-th bit (from left to right), and $i \in \{0,\ldots,P-1\}$. Let $\oplus$ denote bitwise XOR and let $\circlearrowleft$, $\circlearrowright$ denote 1-bit cyclic left and right rotations respectively.

$$\text{FSCX}(A, B) = A \oplus B \oplus \circlearrowleft\!A \oplus \circlearrowleft\!B \oplus \circlearrowright\!A \oplus \circlearrowright\!B$$

Equivalently, defining the linear operator $M = I \oplus \text{ROL} \oplus \text{ROR}$:

$$\text{FSCX}(A, B) = M \cdot (A \oplus B)$$

**FSCX_REVOLVE(A, B, n)** iterates FSCX $n$ times with $B$ held constant:

$$\text{FSCX}\textunderscore\text{REVOLVE}(A, B, n) = \text{FSCX}^{\circ n}(A, B)$$

For bitstrings of size $P = 2^k$, the orbit period is always $P$ or $P/2$, so $\text{FSCX}\textunderscore\text{REVOLVE}(A, B, P) = A$ for all $A$, $B$.

---

# HKEX-GF — Key Exchange over GF(2^n)*

HKEX-GF is a standard Diffie-Hellman key exchange over the multiplicative group $\mathbb{GF}(2^n)^*$.

1. **Setup.** Both parties agree on an irreducible polynomial $p(x)$ of degree $n$ and a generator $g = 3$.
2. **Key generation.** Alice draws a private scalar $a$; Bob draws $b$.
3. **Public values.** Alice publishes $C = g^a$; Bob publishes $C_2 = g^b$ (all arithmetic in $\mathbb{GF}(2^n)$).
4. **Shared secret.** Alice computes $\mathit{sk} = C_2^a = g^{ab}$; Bob computes $\mathit{sk} = C^b = g^{ba}$. By commutativity of field multiplication, $g^{ab} = g^{ba}$.

| $n$ | Primitive polynomial | Classical security |
|-----|---------------------|-------------------|
| 32  | $x^{32}+x^{22}+x^2+x+1$ (`0x00400007`) | demo only |
| 64  | $x^{64}+x^4+x^3+x+1$ (`0x1B`) | ~40 bits |
| 128 | $x^{128}+x^7+x^2+x+1$ (`0x87`) | ~60–80 bits |
| 256 | $x^{256}+x^{10}+x^5+x^2+1$ (`0x425`) | ~128 bits (recommended) |

---

# Herradura Cryptographic Suite

The suite builds protocols on top of HKEX-GF, FSCX_REVOLVE, and the v1.5.0 NL-FSCX extensions:

**Classical (v1.4.0):**

1. **HKEX-GF** — key exchange (DH over $\mathbb{GF}(2^n)^*$, as above)
2. **HSKE** — symmetric encryption: $E = \text{FSCX}\textunderscore\text{REVOLVE}(P, \mathit{key}, i)$; decrypt with $D = \text{FSCX}\textunderscore\text{REVOLVE}(E, \mathit{key}, r)$
3. **HPKS** — Schnorr-style public key signature: $R = g^k$; $e = \text{FSCX}\textunderscore\text{REVOLVE}(R, P, i)$; $s = (k - a \cdot e) \bmod (2^n - 1)$; verify $g^s \cdot C^e = R$
4. **HPKE** — El Gamal public key encryption: $R = g^r$; $\mathit{enc}\textunderscore\mathit{key} = C^r$; $E = \text{FSCX}\textunderscore\text{REVOLVE}(P, \mathit{enc}\textunderscore\mathit{key}, i)$; Alice decrypts with $\mathit{dec}\textunderscore\mathit{key} = R^a$

**Post-quantum / NL-hardened (v1.5.0):**

5. **HSKE-NL-A1** — counter-mode with NL-FSCX v1: $\mathit{ks} = \text{NL-FSCX-revolve-v1}(K, K \oplus \mathit{ctr}, i)$; $E = P \oplus \mathit{ks}$
6. **HSKE-NL-A2** — revolve-mode with NL-FSCX v2: $E = \text{NL-FSCX-revolve-v2}(P, K, r)$; $D = \text{NL-FSCX-revolve-v2-inv}(E, K, r)$
7. **HKEX-RNL** — Ring-LWR key exchange (conjectured quantum-resistant): shared $m_\text{blind}$ in $\mathbb{Z}_q[x]/(x^n+1)$; parties derive $C = \text{round}_p(m_\text{blind} \cdot s)$; agreement $K = \text{round}_{pp}(s \cdot \text{lift}(C_\text{other}))$
8. **HPKS-NL** — NL-hardened Schnorr: $e = \text{NL-FSCX-revolve-v1}(R, P, i)$
9. **HPKE-NL** — NL-hardened El Gamal: $E = \text{NL-FSCX-revolve-v2}(P, \mathit{enc}\textunderscore\mathit{key}, i)$; $D = \text{NL-FSCX-revolve-v2-inv}(E, \mathit{dec}\textunderscore\mathit{key}, i)$

Implementations are provided in C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

---

# Build & Run Instructions

## C

```bash
# Full cryptographic suite (HKEX-GF + HSKE + HPKS Schnorr + HPKE El Gamal)
gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c"
./"Herradura cryptographic suite"

# Security & performance tests (in CryptosuiteTests/)
gcc -O2 -o CryptosuiteTests/Herradura_tests CryptosuiteTests/Herradura_tests.c
./CryptosuiteTests/Herradura_tests
```

## Go

```bash
# Full cryptographic suite
go run "Herradura cryptographic suite.go"

# Security & performance tests (in CryptosuiteTests/)
cd CryptosuiteTests && go run Herradura_tests.go
```

## Python

```bash
# Full cryptographic suite
python3 "Herradura cryptographic suite.py"

# Security & performance tests (in CryptosuiteTests/)
python3 CryptosuiteTests/Herradura_tests.py
```

## Assembly

```bash
# ARM Linux — full suite + tests (HKEX-GF + HSKE + HPKS Schnorr + HPKE El Gamal, 32-bit Thumb)
arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"
arm-linux-gnueabi-gcc -o CryptosuiteTests/Herradura_tests_arm CryptosuiteTests/Herradura_tests.s
qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm

# NASM i386 — full suite + tests (pure Linux syscalls, no libc)
# Requires: nasm, x86_64-linux-gnu-ld (or ld with elf_i386 support), qemu-i386
nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
nasm -f elf32 CryptosuiteTests/Herradura_tests.asm -o tests32.o
x86_64-linux-gnu-ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
x86_64-linux-gnu-ld -m elf_i386 -o CryptosuiteTests/Herradura_tests_i386 tests32.o
qemu-i386 "./Herradura cryptographic suite_i386"
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
# On a native x86/x86_64 Linux host the binaries run directly without qemu-i386
```

## Arduino

The `.ino` files require the Arduino IDE or `arduino-cli` with the AVR board package installed. Open in the IDE and upload to a board with a serial monitor at 9600 baud, or:

```bash
# Compile-check only (requires arduino-cli with arduino:avr board package)
arduino-cli compile --fqbn arduino:avr:uno "Herradura cryptographic suite.ino"
arduino-cli compile --fqbn arduino:avr:uno CryptosuiteTests/Herradura_tests.ino
```

---

# Performance (v1.5.0, Raspberry Pi 5 — ARM Cortex-A76)

Benchmarks from `CryptosuiteTests/Herradura_tests.{c,go,py}`.
GF arithmetic benchmarks use 32-bit parameters; FSCX/HSKE benchmarks use 256-bit parameters.

## C (gcc -O2)

| Benchmark | Throughput |
|-----------|-----------|
| FSCX single step (256-bit) | 11.1 M ops/sec |
| gf_pow throughput (32-bit) | 22,533 M ops/sec |
| HKEX-GF full handshake (32-bit) | 2,255 M ops/sec |
| HSKE encrypt+decrypt round-trip (256-bit) | 43.5 K ops/sec |
| HPKE El Gamal round-trip (32-bit) | 2,258 M ops/sec |

## Go (go run) — v1.3.3 reference, 256-bit parameters

| Benchmark | 64-bit | 128-bit | 256-bit |
|-----------|--------|---------|---------|
| FSCX single step | 372 K ops/sec | 383 K ops/sec | 318 K ops/sec |
| HKEX-GF full handshake | 2.75 K | 1.33 K | 0.58 K ops/sec |
| HSKE encrypt+decrypt round-trip | 5.30 K | 2.46 K | 1.20 K ops/sec |

## Python 3 — v1.3.3 reference, 256-bit parameters

| Benchmark | 64-bit | 128-bit | 256-bit |
|-----------|--------|---------|---------|
| FSCX single step | 166 K ops/sec | 165 K ops/sec | 156 K ops/sec |
| HKEX-GF full handshake | 1.16 K | 585 | 290 ops/sec |
| HSKE encrypt+decrypt round-trip | 2.28 K | 1.16 K | 563 ops/sec |

---

# Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite implementations
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}              — security tests & benchmarks
  go.mod
SecurityProofsCode/                                 — formal break proofs (Python)
SecurityProofs.md                                   — algebraic security analysis (incl. §11 NL/PQC, §12 quantum analysis)
SecurityProofs2.md                                  — additional break proofs
```

---

# License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.

OAHR
