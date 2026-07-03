# Herradura Cryptographic Suite (v1.9.72)

The Herradura Cryptographic Suite implements cryptographic protocols built on the FSCX (Full Surroundings Cyclic XOR) primitive, Diffie-Hellman key exchange over GF(2^n)*, and a post-quantum Ring-LWR key exchange.

---

# FSCX — The Core Primitive

Let $A$, $B$, $C$ be bitstrings of size $P$, where $A_i$ is the $i$-th bit (from left to right), and $i \in \{0,\ldots,P-1\}$. Let $\oplus$ denote bitwise XOR and let $\circlearrowleft$, $\circlearrowright$ denote 1-bit cyclic left and right rotations respectively.

$$\text{FSCX}(A, B) = A \oplus B \oplus \circlearrowleft A \oplus \circlearrowleft B \oplus \circlearrowright A \oplus \circlearrowright B$$

Equivalently, defining the linear operator $M = I \oplus \text{ROL} \oplus \text{ROR}$:

$$\text{FSCX}(A, B) = M \cdot (A \oplus B)$$

**FSCX_REVOLVE(A, B, n)** iterates FSCX $n$ times with $B$ held constant:

$$\text{FSCX-REVOLVE}(A, B, n) = \text{FSCX}^{\circ n}(A, B)$$

For bitstrings of size $P = 2^k$, the orbit period is always $P$ or $P/2$, so $\text{FSCX-REVOLVE}(A, B, P) = A$ for all $A$, $B$.

---

# HKEX-GF — Key Exchange over GF(2^n)*

HKEX-GF is a standard Diffie-Hellman key exchange over the multiplicative group $\mathbb{GF}(2^n)^{\ast}$.

1. **Setup.** Both parties agree on an irreducible polynomial $p(x)$ of degree $n$ and a generator $g = 3$.
2. **Key generation.** Alice draws a private scalar $a$; Bob draws $b$.
3. **Public values.** Alice publishes $C = g^a$; Bob publishes $C_2 = g^b$ (all arithmetic in $\mathbb{GF}(2^n)$).
4. **Shared secret.** Alice computes $\mathit{sk} = C_2^a = g^{ab}$; Bob computes $\mathit{sk} = C^b = g^{ba}$. By commutativity of field multiplication, $g^{ab} = g^{ba}$.

| $n$ | Primitive polynomial | Classical security |
|-----|---------------------|-------------------|
| 32  | $x^{32}+x^{22}+x^2+x+1$ (`0x00400007`) | demo only |
| 64  | $x^{64}+x^4+x^3+x+1$ (`0x1B`) | ~40 bits |
| 128 | $x^{128}+x^7+x^2+x+1$ (`0x87`) | ~60–80 bits |
| 256 | $x^{256}+x^{10}+x^5+x^2+1$ (`0x425`) | ~80–90 bits (FFS L[1/3]; deprecated NIST/ENISA — see §9.2.4) |

---

# Herradura Cryptographic Suite

The suite builds protocols on top of HKEX-GF, FSCX_REVOLVE, and the v1.5.0 NL-FSCX extensions:

**Classical (v1.4.0):**

1. **HKEX-GF** — key exchange (DH over $\mathbb{GF}(2^n)^{\ast}$, as above)
2. **HSKE** — symmetric encryption: $E = \text{FSCX-REVOLVE}(P, \mathit{key}, i)$; decrypt with $D = \text{FSCX-REVOLVE}(E, \mathit{key}, r)$
3. **HPKS** — Schnorr-style public key signature: $R = g^k$; $e = \text{FSCX-REVOLVE}(R, P, i)$; $s = (k - a \cdot e) \bmod (2^n - 1)$; verify $g^s \cdot C^e = R$
4. **HPKE** — El Gamal public key encryption: $R = g^r$; $\text{enc-key} = C^r$; $E = \text{FSCX-REVOLVE}(P, \text{enc-key}, i)$; Alice decrypts with $\text{dec-key} = R^a$

**Post-quantum / NL-hardened (v1.5.0):**

5. **HSKE-NL-A1** — counter-mode with NL-FSCX v1: $\mathit{ks} = \text{NL-FSCX-revolve-v1}(K, K \oplus \mathit{ctr}, i)$; $E = P \oplus \mathit{ks}$
6. **HSKE-NL-A2** — revolve-mode with NL-FSCX v2: $E = \text{NL-FSCX-revolve-v2}(P, K, r)$; $D = \text{NL-FSCX-revolve-v2-inv}(E, K, r)$
7. **HKEX-RNL** — Ring-LWR key exchange (conjectured quantum-resistant): shared $m_\text{blind}$ in $\mathbb{Z}_q[x]/(x^n+1)$; parties derive $C = \text{round}_p(m_\text{blind} \cdot s)$; agreement $K = \text{round}_{pp}(s \cdot \text{lift}(C_\text{other}))$
8. **HPKS-NL** — NL-hardened Schnorr: $e = \text{NL-FSCX-revolve-v1}(R, P, i)$
9. **HPKE-NL** — NL-hardened El Gamal: $E = \text{NL-FSCX-revolve-v2}(P, \text{enc-key}, i)$; $D = \text{NL-FSCX-revolve-v2-inv}(E, \text{dec-key}, i)$

**Code-based PQC (v1.5.18):**

10. **HPKS-Stern-F** — Fiat-Shamir Stern ZKP signature (EUF-CMA ≤ SD($n$,$t$) + NL-FSCX v1 PRF): commit $(c_0, c_1, c_2)$; challenge $b \in \{0,1,2\}$ via NL-FSCX hash; response reveals permuted $r$, $y = e \oplus r$, or permutation $\pi$. Parameters (C/Go/Python): $N = n = 256$, $t = 16$, rounds $= 32$ (production default; benchmarks use 4–8 rounds for throughput measurement). Assembly/Arduino: $N = 32$, $t = 2$, rounds $= 4$.
11. **HPKE-Stern-F** — Niederreiter KEM: $\mathit{ct} = H \cdot e'^T$; $K = \text{hash}(\mathit{seed}, e')$. Production decap requires a QC-MDPC syndrome decoder; demo uses known $e'$.

Implementations are provided in C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino (all six targets at v1.5.19).

---

# Build & Run Instructions

## C

```bash
# Full cryptographic suite (all protocols: classical, NL/PQC, Stern-F code-based)
gcc -O2 -o "Herradura cryptographic suite_c" "Herradura cryptographic suite.c"
./"Herradura cryptographic suite_c"

# Security & performance tests (in CryptosuiteTests/)
gcc -O2 -o CryptosuiteTests/Herradura_tests_c CryptosuiteTests/Herradura_tests.c
./CryptosuiteTests/Herradura_tests_c
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
# ARM Linux — full suite + tests (32-bit Thumb; classical + NL/PQC + Stern-F protocols)
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

# Performance (v1.8.9, Orange Pi 5 — RK3588, Cortex-A76 @ 2.4 GHz)

Benchmarks from `CryptosuiteTests/Herradura_tests.{c,go,py}` with `-t 1.5`.
Columns correspond to operand bit-width; for HKEX-RNL the column header is the ring degree $n$.

## C (gcc -O2)

C benchmarks use native types per size: `uint32_t` / `uint64_t` / `__uint128_t` / `BitArray`.

| Benchmark | 32-bit | 64-bit | 128-bit | 256-bit |
|-----------|--------|--------|---------|---------|
| FSCX single step | 20,118 M | 20,125 M | 20,134 M | 10.56 M ops/sec |
| HKEX-GF gf\_pow | 19,916 M | 1,990 M | 19.52 M | 124 ops/sec |
| HKEX-GF full handshake | 1,924 M | 19.60 M | 19.67 M | 30.6 ops/sec |
| HSKE round-trip | 15.75 M | 10.27 M | 5.13 M | 41.61 K ops/sec |
| HPKE El Gamal round-trip | 1,988 M | 19.84 M | 19.71 M | 40.9 ops/sec |
| NL-FSCX v1 revolve (n/4 steps) | 20,173 M | 20,184 M | 4,037 M | 105.64 K ops/sec |
| NL-FSCX v2 enc+dec | 20,185 M | 2,017 M | 20.19 M | 475.58 ops/sec |
| HSKE-NL-A1 counter-mode | 10.54 M | 6.81 M | 3.39 M | 103.40 K ops/sec |
| HSKE-NL-A2 revolve-mode | 15.73 M | 10.17 M | 4.02 M | 474.88 ops/sec |
| HKEX-RNL full handshake (n=…) | 92.3 K | 40.9 K | 18.5 K | 8.35 K ops/sec |
| HPKS-Stern-F sign+verify (N=n, rounds=8) | 198 K ops/sec | 504 ops/sec | 467 ops/sec | 52.9 ops/sec |

## Go (go run)

| Benchmark | 32-bit | 64-bit | 128-bit | 256-bit |
|-----------|--------|--------|---------|---------|
| FSCX single step | 134 K | 125 K | 104 K | 97.8 K ops/sec |
| HKEX-GF gf\_pow | 800 | 234 | 51.0 | 10.9 ops/sec |
| HKEX-GF full handshake | 222 | 53.8 | 11.4 | 2.77 ops/sec |
| HSKE round-trip | 3.99 K | 2.12 K | 769 | 397 ops/sec |
| HPKE El Gamal round-trip | 199 | 52.6 | 11.6 | 2.82 ops/sec |
| NL-FSCX v1 revolve (n/4 steps) | 12.4 K | 5.47 K | 2.50 K | 1.15 K ops/sec |
| NL-FSCX v2 enc+dec | 760 | 191 | 46.9 | 11.5 ops/sec |
| HSKE-NL-A1 counter-mode | 11.0 K | 5.27 K | 2.29 K | 1.11 K ops/sec |
| HSKE-NL-A2 revolve-mode | 630 | 195 | 49.5 | 12.1 ops/sec |
| HKEX-RNL full handshake (n=…) | 11.3 K | 7.02 K | 2.72 K | 1.42 K ops/sec |
| HPKS-Stern-F sign+verify (N=n, rounds=4) | 21.8 ops/sec | 16.5 ops/sec | 8.28 ops/sec | 3.28 ops/sec |

## Python 3

| Benchmark | 32-bit | 64-bit | 128-bit | 256-bit |
|-----------|--------|--------|---------|---------|
| FSCX single step | 156 K | 161 K | 160 K | 158 K ops/sec |
| HKEX-GF gf\_pow | 1.90 K | 484 | 120 | 27.6 ops/sec |
| HKEX-GF full handshake | 504 | 118 | 28.0 | 6.70 ops/sec |
| HSKE round-trip | 4.82 K | 2.53 K | 1.27 K | 628 ops/sec |
| HPKE El Gamal round-trip | 457 | 113 | 27.5 | 6.61 ops/sec |
| NL-FSCX v1 revolve (n/4 steps) | 14.4 K | 7.49 K | 3.75 K | 1.85 K ops/sec |
| NL-FSCX v2 enc+dec | 1.04 K | 294 | 80.7 | 20.5 ops/sec |
| HSKE-NL-A1 counter-mode | 13.0 K | 7.05 K | 3.65 K | 1.83 K ops/sec |
| HSKE-NL-A2 revolve-mode | 1.04 K | 296 | 80.8 | 20.5 ops/sec |
| HKEX-RNL full handshake (n=…) | 1.12 K | 543 | 256 | 119 ops/sec |
| HPKS-Stern-F sign+verify (N=n, rounds=4) | 26.7 ops/sec | 15.6 ops/sec | 6.11 ops/sec | 1.82 ops/sec |

---

# Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite (all six language targets)
herradura.h                                         — header-only C library (Protocol Layer wrappers)
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}              — security tests & benchmarks
  go.mod
HerraduraCli/                                       — Python CLI (genpkey/pkey/kex/enc/dec/sign/verify)
SecurityProofsCode/                                 — standalone Python proof and analysis scripts
SecurityProofs-1.md                                 — formal analysis §1–§10 (algebraic foundations,
                                                      protocol security, quantum attack analysis,
                                                      v1.4.0 migration)
SecurityProofs-2.md                                 — formal analysis §11–§11.9 (NL-FSCX,
                                                      Ring-LWR, Stern-F, HFSCX-256 hash)
SecurityProofs.md                                   — split index (redirects to the two files above)
docs/
  INTRODUCTION.md                                   — plain-language cryptographic concepts primer
  TUTORIAL.md                                       — integration tutorial (C/Go/Python API recipes)
  examples/                                         — minimal runnable examples (C, Go, Python)
```

---

# License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.

OAHR
