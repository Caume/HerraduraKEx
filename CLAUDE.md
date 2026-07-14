# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HerraduraKEx is a cryptographic suite implementing four protocols — HKEX-GF (key exchange), HSKE (symmetric encryption), HPKS (Schnorr signature), and HPKE (El Gamal encryption) — built on the FSCX (Full Surroundings Cyclic XOR) primitive and Diffie-Hellman arithmetic over GF(2^n)*. Implementations exist in C, Go, Python, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

## Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite, one file per language
herradura.h                                         — header-only C library (shared by CLI and external code)
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}              — security tests & benchmarks
  go.mod                                            — module herradurakex/tests
HerraduraCli/
  herradura.py / herradura_cli.c / herradura_cli.go — OpenSSL-style CLI (Python, C, Go)
  herradura_codec.h / codec.py                      — PEM/DER encode-decode helpers
  primitives.py                                     — suite import shim for Python CLI
  go.mod                                            — module herradurakex/cli (replaces ../go.mod)
CliTest/
  test_keygen.sh  test_vectors.sh  test_sign.sh     — Python CLI integration tests
  test_encrypt.sh test_encfile.sh  test_signfile.sh
  test_c_*.sh  test_go_*.sh  test_c_interop.sh      — C / Go CLI tests and cross-language interop
SecurityProofsCode/                                 — standalone Python proof/analysis scripts:
  hkex_gf_test.py          — HKEX-GF DH correctness + BSGS DLP illustration
  hkex_nl_verification.py  — NL-FSCX period analysis, Ring-LWR invertibility/noise, v2 bijectivity
  hkex_cy_test.py          — FSCX-CY exhaustive non-linearity & HKEX-CY failure proof
  hkex_cfscx_*.py          — preshared-value, two-step, integer-op, compress/blong constructions
  hkex_classical_break.py  — classical algebraic break proofs
  hkex_*_analysis.py       — FSCX_N, multi-nonce, and nonce-impossibility analyses
  validate_katex.js         — pipeline simulator for GitHub KaTeX rendering
SecurityProofs.md                                   — split index (redirects to Parts 1–3; quantum analysis is in SecurityProofs-1.md §6)
SecurityProofs-1.md                                 — §1–§10: Algebraic Foundations … v1.4.0 Migration (~753 math expressions)
SecurityProofs-2.md                                 — §11–§11.9: NL-FSCX PQC extensions · HFSCX-256 (~873 math expressions)
SecurityProofs-3.md                                 — §11.10: ZKP extensions · Ring-LWR Σ-protocol · NL-FSCX ZKBoo (~121 math expressions)
docs/
  TUTORIAL.md               — API usage guide per protocol and language
  INTRODUCTION.md           — lay-audience primer for all core concepts
  examples/{python,c,go}/   — hello_herradura.* integration examples
```

Three `go.mod` files: root-level (`module herradurakex`), `CryptosuiteTests/` (`module herradurakex/tests`), and `HerraduraCli/` (`module herradurakex/cli`, uses `replace herradurakex => ../`). None has external dependencies.

## Changelog, README, and TODO Policy

All notable changes are documented in `CHANGELOG.md` only.  Do **not** add version notes, release blurbs, or change summaries to `README.md`.  The README describes the current state of the project; the CHANGELOG tracks its history.  When a feature or fix is completed, add a new versioned entry to `CHANGELOG.md` and update the version number in the `README.md` title line — nothing else.

Work items are tracked in `TODO.md` as numbered entries (#1–#N) with a `Status:` line.  When completing a TODO, update its `Status:` line to `**DONE vX.Y.Z**` with the release version, then add the corresponding `CHANGELOG.md` entry.  Version numbers follow `MAJOR.MINOR.PATCH`; each TODO completion is typically one PATCH bump.

### TODO.md Status line standard

Every `### ` section in `TODO.md` must end with exactly one `Status:` line using one of these keywords:

| Keyword | Meaning | Format example |
|---|---|---|
| `DONE` | Implemented and shipped | `Status: **DONE vX.Y.Z** — one-line summary.` |
| `OPEN` | Pending — not yet started or in progress | `Status: **OPEN**` |
| `DEPRECATED` | Will not be fixed; reason documented | `Status: **DEPRECATED** — reason.` |
| `ACKNOWLEDGED` | Known issue, accepted by design, no action planned | `Status: **ACKNOWLEDGED** — reason.` |

Rules:
- The `Status:` keyword starts at column 0 with no leading `**`.
- The keyword (`DONE`, `OPEN`, etc.) is bold: `**KEYWORD**`.
- For `DONE`, append the version tag and a dash-separated summary: `**DONE vX.Y.Z** — summary.`
- No item should be left without a `Status:` line.  A missing Status line means "open" only by convention; always add an explicit `Status: **OPEN**` when creating a new item.
- When parsing programmatically, match `^Status: \*\*` at the start of a line within the section.

**Quick check:** `python3 -c "import re,sys; [print(m.group()) for m in re.finditer(r'(?m)^### .+\n(?:(?!^Status:)[\s\S])*?(?=^###|\Z)', open('TODO.md').read()) if 'Status:' not in m.group()]"` — prints any `###` section that is missing a Status line.

## Build Commands

Use the build scripts when building everything; they apply the correct flags, output names, and dependency checks.

```bash
./build_c.sh          # compiles suite, tests, and HerraduraCli/herradura_cli
./build_go.sh         # compiles suite, tests, and HerraduraCli/herradura_cli_go
./build_arm.sh        # ARM Thumb-2 suite + tests (requires arm-linux-gnueabi-gcc)
./build_asm_i386.sh   # NASM i386 suite + tests (auto-detects elf_i386-capable linker)
```

### C

Use `build_c.sh`. Manual equivalent: `gcc -O2 -o <output> <source.c>` per target (suite, tests, CLI).

> **Build collision hazard:** `go build file.go` (without `-o`) names its output
> after the source filename stem — identical to the old unsuffixed C binary path.
> The `_c` suffix makes all six target binaries distinct: `_c`, `_go`, `_arm`,
> `_i386`, `_avr.elf`. Always use `build_go.sh` or pass `-o name_go` explicitly
> when invoking `go build` directly. Never run bare `go build file.go`.

### Go
```bash
go run "Herradura cryptographic suite.go"
cd CryptosuiteTests && go run Herradura_tests.go

# CLI
cd HerraduraCli && go build -o herradura_cli_go .
```

### Python
```bash
python3 "Herradura cryptographic suite.py"
python3 CryptosuiteTests/Herradura_tests.py
```
No external dependencies.

### Assembly

Use `build_arm.sh` / `build_asm_i386.sh`. To run: `qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"` or `qemu-i386 "./Herradura cryptographic suite_i386"`.

> **i386 linker portability:** `x86_64-linux-gnu-ld -m elf_i386` fails on ARM64 hosts
> (e.g. Raspberry Pi 5 / Ubuntu) with "unrecognized emulation mode: elf_i386" because the
> native `ld` (aarch64) has no i386 emulation.  `build_asm_i386.sh` auto-detects the first
> available linker with `elf_i386` support.  If none is found, install one:
> - `sudo apt-get install -y binutils-x86-64-linux-gnu`  (provides `x86_64-linux-gnu-ld`)
> - `sudo apt-get install -y binutils-i686-linux-gnu`    (provides `i686-linux-gnu-ld`)

## Testing

No automated test framework. Tests are manual: run each program and verify console output.

```bash
# C/Go/Python — security tests [1]–[29] + benchmarks [30]–[41]
# (C also runs one C-only unlabeled test between [20] and [21])
./CryptosuiteTests/Herradura_tests_c
./CryptosuiteTests/Herradura_tests_c -r 500        # cap each test at 500 iterations
./CryptosuiteTests/Herradura_tests_c -t 2.0        # cap wall-clock per test/bench at 2 s
HTEST_ROUNDS=200 HTEST_TIME=1.5 ./CryptosuiteTests/Herradura_tests_c  # env-var equivalents

cd CryptosuiteTests && go run Herradura_tests.go
cd CryptosuiteTests && go run Herradura_tests.go -r 500 -t 2.0

python3 CryptosuiteTests/Herradura_tests.py
python3 CryptosuiteTests/Herradura_tests.py -r 500 -t 2.0

# Assembly — build first (see Build Commands), then run:
# ARM/NASM: tests [1]–[13]
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
```

The `-r`/`--rounds` flag caps iterations per security test; `-t`/`--time` sets the wall-clock limit for both tests and benchmarks. CLI flags override `HTEST_ROUNDS`/`HTEST_TIME` env vars.

The suite files run EVE (eavesdropper) bypass tests inline on every execution.

### CLI integration tests (CliTest/)

```bash
# Python CLI — build not required (python3 used directly)
bash CliTest/test_keygen.sh
bash CliTest/test_vectors.sh   # key-agreement correctness: Alice+Bob derive same secret
bash CliTest/test_sign.sh
bash CliTest/test_encrypt.sh
bash CliTest/test_encfile.sh
bash CliTest/test_signfile.sh
bash CliTest/test_aead.sh      # HSKE-NL-AEAD enc/dec --aead, 9-way cross-CLI interop (needs C+Go CLIs built)

# C CLI — requires HerraduraCli/herradura_cli (build_c.sh)
bash CliTest/test_c_keygen.sh
bash CliTest/test_c_interop.sh # Python-generated keys consumed by C CLI and vice versa

# Go CLI — requires HerraduraCli/herradura_cli_go (build_go.sh)
bash CliTest/test_go_keygen.sh
bash CliTest/test_go_interop.sh
```

### SecurityProofsCode scripts

Each script in `SecurityProofsCode/` is self-contained (no imports from the suite).  Run them to reproduce the analysis results cited in `SecurityProofs-*.md`:

```bash
python3 SecurityProofsCode/hkex_gf_test.py          # DH correctness + DLP
python3 SecurityProofsCode/hkex_rnl_failure_rate.py  # HKEX-RNL failure-rate analysis
python3 SecurityProofsCode/nl_fscx_owf_analysis.py   # NL-FSCX OWF cryptanalysis
python3 SecurityProofsCode/nl_fscx_rot_analysis.py   # rotational differential analysis
```

## Core Cryptographic Architecture

### Primitives

**FSCX(A, B):**
```
C = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```
Linear map M = I ⊕ ROL ⊕ ROR; order of M is n/2. Iterating FSCX creates periodic orbits of length P or P/2 (P = bit size).

**FSCX_REVOLVE(A, B, n):** Iterates FSCX n times, keeping B constant.

**GF(2^n) arithmetic:** `gf_mul` (carryless multiply mod irreducible polynomial), `gf_pow` (square-and-multiply). Generator g = 3.

### Protocol Stack

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

### herradura.h — header-only C library

`herradura.h` exposes the entire suite as a single-include header.  External C code (including `HerraduraCli/herradura_cli.c`) includes it directly; there is no separate compilation step.  All exported symbols are prefixed `ba_`, `gf_`, `nl_`, `rnl_`, `hkex_`, `hske_`, `hpks_`, `hpke_`, `stern_`, or `hpks_stern_`/`hpke_stern_`.

### HerraduraCli — OpenSSL-style CLI

Three parallel implementations (`herradura.py`, `herradura_cli.c`, `herradura_cli_go`) share the same PEM wire format and subcommand interface: `genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, `verify`, `dgst`, `encfile`, `decfile`.  PEM files produced by any implementation are byte-for-byte compatible with the others.

- Python CLI (`herradura.py`) imports the suite via `primitives.py`, which uses `importlib` to load the space-named suite file.
- C CLI (`herradura_cli.c`) `#include`s `../herradura.h` and `herradura_codec.h` for PEM/DER encode-decode.
- HKEX-RNL key exchange is two-round: Bob responds first (`kex --algo hkex-rnl --our bob.pem --their alice_pub.pem`), then Alice completes using Bob's response PEM.
- `docs/examples/` contains minimal `hello_herradura.{py,c,go}` integration samples.  The Python example shows the `importlib` pattern required because the suite filename contains spaces.

## KaTeX Rendering Rules for Markdown Files

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX, and the rendering pipeline (markdown/CommonMark first, then KaTeX) has ~11 sharp edges around `_`, `$`, `*`, spacing commands, and a ~750-expression per-page limit that silently breaks math past that threshold.

Before editing any `$...$`/`$$...$$` math span in this repo, read `SecurityProofsCode/KATEX_RULES.md` in full — it documents every rule, the correct-pattern table, and the local validation script (`SecurityProofsCode/validate_katex.js`). Do not guess at KaTeX-safe syntax from general LaTeX knowledge; GitHub's pipeline rejects several constructs that are valid in standalone KaTeX.

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
