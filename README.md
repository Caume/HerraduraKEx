# Herradura Cryptographic Suite (v1.8.3)

The Herradura Cryptographic Suite implements cryptographic protocols built on the FSCX (Full Surroundings Cyclic XOR) primitive, Diffie-Hellman key exchange over GF(2^n)*, and a post-quantum Ring-LWR key exchange.

> **v1.4.0 note:** The original HKEX key exchange (based directly on FSCX_REVOLVE) was classically broken — the shared secret was directly computable from the two public wire values alone. v1.4.0 replaced it with **HKEX-GF**, a standard Diffie-Hellman construction over the multiplicative group of GF(2^n). See `SecurityProofs-1.md §3` for the formal proof.
>
> **v1.5.0 note:** FSCX is GF(2)-linear, making HSKE vulnerable to linear key-recovery attacks, and HKEX-GF is broken by Shor's algorithm. v1.5.0 adds **NL-FSCX** (non-linear extension breaking GF(2)-linearity and orbit periods) and **HKEX-RNL** (Ring-LWR key exchange conjectured quantum-resistant). See `SecurityProofs-1.md §6` (quantum analysis) and `SecurityProofs-2.md §11` (NL/PQC proofs) for analysis.
>
> **v1.8.3 note:** Comprehensive cryptographic concepts primer (`docs/INTRODUCTION.md`) — plain-language guide to all core concepts (GF(2^n), FSCX, DH, Schnorr, El Gamal, quantum threats, Ring-LWR, Stern ZKP) with toy examples, verified references, and cross-links to TUTORIAL.md and the SecurityProofs documents.
>
> **v1.7.4 note:** Developer integration tutorial (`docs/TUTORIAL.md`) — per-protocol API recipes in C, Go, and Python; `herradura.h` Protocol Layer wrappers; public Python aliases `hkex_rnl_keygen`/`hkex_rnl_agree`; runnable examples in `docs/examples/`. Full CSPRNG and constant-time audit (SA-01–SA-09): nine findings resolved across all six language targets.
>
> **v1.5.40 note:** Constant-time audit (TODO #41): `stern_apply_perm` / `SternApplyPerm` made branchless across all targets (C, Go, ARM Thumb-2, NASM i386, Arduino) using arithmetic mask `-(bit)` to eliminate data-dependent branches that leaked the Hamming weight of secret error vectors. Python reference implementation documented as non-CT; `SecurityProofsCode/stern_ct_demo.py` added to demonstrate the timing correlation empirically.
>
> **v1.5.23 note:** HerraduraCli — an OpenSSL-style Python CLI (`HerraduraCli/`) exposing all non-broken Herradura protocols via `genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, and `verify` subcommands. Keys and ciphertexts use PEM-wrapped minimal DER. A `CliTest/` shell test suite covers key generation, encrypt/decrypt round-trips, sign/verify, and HKEX-GF/HKEX-RNL key-agreement correctness.
>
> **v1.5.22 note:** NASM i386 HKEX-RNL now produces correct non-zero session keys (triple-division bug in `rnl_round` fixed). `rnl_cbd_poly` reads 4 coefficients per byte for η=1 (was 1 byte/coeff, discarding 75% of entropy). Go test [14] HKEX-RNL expanded from n∈{32,64} to n∈{32,64,128,256}, matching C and Python test coverage.
>
> **v1.5.20 note:** Python tests and suite expanded to cover all four standard key sizes (32, 64, 128, 256 bits) for GF, HKEX-RNL, and Stern-F protocols. `hpke_stern_f_decap` now supports a known-e' fast path in addition to brute-force; N=256 HPKE-Stern-F demo added to the Python suite. C test [17] loops {32,64,256} and test [18] covers N=32 brute-force and N=64 known-e'. C suite now demos both N=32 brute-force and N=256 known-e' for HPKE-Stern-F. `bn_*` parameterised big-endian arithmetic layer added to C tests, extending Schnorr and HPKS-NL tests to 256-bit. NTT inner loops now use Fermat-prime fast modulo (`rnl_mulmodq`/`rnlMulModQ`), eliminating hardware divides in the HKEX-RNL hot path (+17.6% on n=32 in C).
>
> **v1.5.18 note:** HPKS-NL and HPKE-NL remain quantum-vulnerable because their security still depends on the GF(2^n)* discrete-log base that Shor's algorithm breaks. v1.5.18 adds **HPKS-Stern-F** (Fiat-Shamir Stern ZKP signature) and **HPKE-Stern-F** (Niederreiter KEM), whose security reduces to Syndrome Decoding (NP-complete) and the NL-FSCX v1 PRF. See `SecurityProofs-2.md §11.8.4` for the formal reduction (Theorem 17).

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
| 256 | $x^{256}+x^{10}+x^5+x^2+1$ (`0x425`) | ~128 bits (recommended) |

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

10. **HPKS-Stern-F** — Fiat-Shamir Stern ZKP signature (EUF-CMA ≤ SD($n$,$t$) + NL-FSCX v1 PRF): commit $(c_0, c_1, c_2)$; challenge $b \in \{0,1,2\}$ via NL-FSCX hash; response reveals permuted $r$, $y = e \oplus r$, or permutation $\pi$. Parameters (C/Go/Python): $N = n = 256$, $t = 16$, rounds $= 32$. Assembly/Arduino: $N = 32$, $t = 2$, rounds $= 4$.
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

# Performance (v1.8.3, Orange Pi 5 — RK3588, Cortex-A76 @ 2.4 GHz)

Benchmarks from `CryptosuiteTests/Herradura_tests.{c,go,py}` with `-t 1.5`.
C benchmarks run at fixed sizes (32-bit GF/NL, 256-bit FSCX/HSKE).
Go/Python columns correspond to operand bit-width; for HKEX-RNL the column header is the ring degree $n$.

## C (gcc -O2)

| Benchmark | Throughput |
|-----------|-----------|
| FSCX single step (256-bit) | 10.6 M ops/sec |
| gf\_pow throughput (32-bit) | 20,260 M ops/sec |
| HKEX-GF full handshake (32-bit) | 2,027 M ops/sec |
| HSKE round-trip (256-bit) | 41.8 K ops/sec |
| HPKE El Gamal round-trip (32-bit) | 2,021 M ops/sec |
| NL-FSCX v1 revolve (32-bit, n/4 steps) | 2,027 M ops/sec |
| NL-FSCX v2 enc+dec (32-bit) | 2,021 M ops/sec |
| HSKE-NL-A1 counter-mode (32-bit) | 10.5 M ops/sec |
| HSKE-NL-A2 revolve-mode (32-bit) | 15.6 M ops/sec |
| HKEX-RNL full handshake (n=32) | 92.2 K ops/sec |
| HPKS-Stern-F sign+verify (N=256, t=16, rounds=8) | 53.3 ops/sec |

## Go (go run)

| Benchmark | 32-bit | 64-bit | 128-bit | 256-bit |
|-----------|--------|--------|---------|---------|
| FSCX single step | — | 80.0 K | 65.5 K | 53.3 K ops/sec |
| HKEX-GF gf\_pow | 630 ops/sec | — | — | — |
| HKEX-GF full handshake | 160 ops/sec | — | — | — |
| HSKE round-trip | — | 1.32 K | 570 | 240 ops/sec |
| HPKE El Gamal round-trip | 150 ops/sec | — | — | — |
| NL-FSCX v1 revolve (n/4 steps) | — | 3.64 K | 1.42 K | 610 ops/sec |
| NL-FSCX v2 enc+dec | — | 130 ops/sec | — | — |
| HSKE-NL-A1 counter-mode | — | 3.65 K | 1.24 K | 720 ops/sec |
| HSKE-NL-A2 revolve-mode | — | 120 ops/sec | — | — |
| HKEX-RNL full handshake (n=…) | 8.05 K | 5.02 K | 2.17 K | 1.05 K ops/sec |
| HPKS-Stern-F sign+verify (N=256, rounds=4) | — | — | — | 1.78 ops/sec |

## Python 3

| Benchmark | 32-bit | 64-bit | 128-bit | 256-bit |
|-----------|--------|--------|---------|---------|
| FSCX single step | — | 161 K | 160 K | 158 K ops/sec |
| HKEX-GF gf\_pow | 1.90 K | 484 | 120 | 27.6 ops/sec |
| HKEX-GF full handshake | 504 | 118 | 28.0 | 6.70 ops/sec |
| HSKE round-trip | — | 2.53 K | 1.27 K | 628 ops/sec |
| HPKE El Gamal round-trip | 457 | 113 | 27.5 | 6.61 ops/sec |
| NL-FSCX v1 revolve (n/4 steps) | — | 7.49 K | 3.75 K | 1.85 K ops/sec |
| NL-FSCX v2 enc+dec | — | 298 ops/sec | — | — |
| HSKE-NL-A1 counter-mode | — | 7.05 K | 3.65 K | 1.83 K ops/sec |
| HSKE-NL-A2 revolve-mode | — | 298 ops/sec | — | — |
| HKEX-RNL full handshake (n=…) | 1.12 K | 543 | 256 | 119 ops/sec |
| HPKS-Stern-F sign+verify (N=32, rounds=4) | 26.7 ops/sec | — | — | — |

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
