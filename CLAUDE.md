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

## Build Commands

Use the build scripts when building everything; they apply the correct flags, output names, and dependency checks.

```bash
./build_c.sh          # compiles suite, tests, and HerraduraCli/herradura_cli
./build_go.sh         # compiles suite, tests, and HerraduraCli/herradura_cli_go
./build_arm.sh        # ARM Thumb-2 suite + tests (requires arm-linux-gnueabi-gcc)
./build_asm_i386.sh   # NASM i386 suite + tests (auto-detects elf_i386-capable linker)
```

### C
```bash
# Full cryptographic suite
gcc -O2 -o "Herradura cryptographic suite_c" "Herradura cryptographic suite.c"

# Security & performance tests
gcc -O2 -o CryptosuiteTests/Herradura_tests_c CryptosuiteTests/Herradura_tests.c

# CLI
gcc -O2 -o HerraduraCli/herradura_cli HerraduraCli/herradura_cli.c
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
```bash
# ARM Thumb-2
arm-linux-gnueabi-gcc -o "Herradura cryptographic suite_arm" "Herradura cryptographic suite.s"
arm-linux-gnueabi-gcc -o CryptosuiteTests/Herradura_tests_arm CryptosuiteTests/Herradura_tests.s
qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"

# NASM i386 — use the build script (it selects a linker with elf_i386 support)
./build_asm_i386.sh
qemu-i386 "./Herradura cryptographic suite_i386"

# Manual linker invocation (ld must support elf_i386 — see portability note below)
nasm -f elf32 "Herradura cryptographic suite.asm" -o suite32.o
nasm -f elf32 CryptosuiteTests/Herradura_tests.asm -o tests32.o
x86_64-linux-gnu-ld -m elf_i386 -o "Herradura cryptographic suite_i386" suite32.o
x86_64-linux-gnu-ld -m elf_i386 -o CryptosuiteTests/Herradura_tests_i386 tests32.o
```

> **i386 linker portability:** `x86_64-linux-gnu-ld -m elf_i386` fails on ARM64 hosts
> (e.g. Raspberry Pi 5 / Ubuntu) with "unrecognized emulation mode: elf_i386" because the
> native `ld` (aarch64) has no i386 emulation.  `build_asm_i386.sh` auto-detects the first
> available linker with `elf_i386` support.  If none is found, install one:
> - `sudo apt-get install -y binutils-x86-64-linux-gnu`  (provides `x86_64-linux-gnu-ld`)
> - `sudo apt-get install -y binutils-i686-linux-gnu`    (provides `i686-linux-gnu-ld`)

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

### CLI integration tests (CliTest/)

```bash
# Python CLI — build not required (python3 used directly)
bash CliTest/test_keygen.sh
bash CliTest/test_vectors.sh   # key-agreement correctness: Alice+Bob derive same secret
bash CliTest/test_sign.sh
bash CliTest/test_encrypt.sh
bash CliTest/test_encfile.sh
bash CliTest/test_signfile.sh

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

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX.  The pipeline is **markdown (CommonMark/GFM) first, then KaTeX**: backslash escapes inside math spans are resolved by the markdown layer **before** KaTeX sees the input.  Every patch below is verified against this pipeline (not against pure KaTeX) — see the validation script section.

### Rule 1 — never put `_` between `\text{}` blocks

CommonMark resolves `\_` inside math spans to a literal `_`, which KaTeX then parses as the **subscript operator**.  Two implications:

- `\text{A}\_\text{B}` becomes `\text{A}_\text{B}` after markdown — a single subscript that *renders* but visually attaches `B` underneath `A`.
- `\text{A}\_\text{B}\_\text{C}` becomes `\text{A}_\text{B}_\text{C}` — two subscripts on the same base, which KaTeX rejects with **"Double subscripts: use braces to clarify"**.

`\textunderscore` is also wrong — it is a text-mode-only command in KaTeX 0.16+, and rejected wherever the parser is in math mode (which includes positions between `\text{}` blocks).

### Rule 2 — never put a bare `_` inside `\text{}`

CommonMark resolves `\_` inside `\text{...}` to `_` as well.  KaTeX then sees `\text{FOO_BAR}` and rejects with **`"_" allowed only in math mode`**.

### Rule 3 — never use `\$` or `\textdollar` in math mode

`\$` inside `$...$` is consumed by markdown (the second `$` closes the span and KaTeX gets an unclosed brace).  `\textdollar` is text-mode-only in KaTeX 0.16+ and rejected anywhere in math mode.

### Rule 4 — never write `^*` inside a math span

A literal `*` in math mode is paired by markdown's emphasis parser with any other `*` later in the same paragraph (across math-span boundaries). The first `*` opens `<em>` mid-span, breaking math recognition entirely.  Use `^{\ast}` instead — `\ast` renders identically to `*` and the leading `\a` is not a markdown emphasis marker.

### Rule 5 — display `$$...$$` blocks must be on their own line with blank lines before and after

GitHub's renderer only emits `<math-renderer class="js-display-math">` when the `$$` block is on its own line (surrounded by blank lines).  **Only one valid format** is reliably rendered on GitHub:

```
$$expr$$
```

Single-line or content-attached multi-line are both valid:
- **Single-line:** `$$expr$$` — entire expression on one line.
- **Content-attached multi-line:** `$$first-content-line\n...\nlast-content-line$$` — the `$$` delimiters are attached to the first and last content lines respectively (not on separate blank lines).

**INVALID — standalone `$$` delimiter lines are not rendered by GitHub:**
```
$$
expr
$$
```
A bare `$$` on its own line is never correctly rendered as display math; use the content-attached form instead.

When a `$$` block follows immediately after prose (e.g. `**Compression function.**\n$$C(s,m) = ...$$`), GitHub fails to wrap it and the `$$...$$` is emitted as literal text with backslash escapes stripped — the visible "Unable to render expression" symptom.

Inside numbered/bulleted lists, avoid `$$` display blocks — move them before or after the list, or use inline `$...$` inside the item.

**CRITICAL — GitHub has a per-page math expression limit of approximately 750 expressions.**  Documents with more than ~750 math spans show a cascade failure: every math expression past the threshold renders as "Unable to render expression".  The root cause is a client-side rendering limit, not any specific syntax error.  The only fix is to split the document at a section boundary so that each part stays under ~750 math expressions.  SecurityProofs.md was split into SecurityProofs-1.md (§1–§10, ~753 spans) and SecurityProofs-2.md (§11–§11.9, ~725 spans) for this reason.

### Rule 6 — never place `$...$` directly after a non-space character

GitHub's math regex requires that the opening `$` be preceded by whitespace, start of line, or punctuation **other than** `-`/`)`/`.`/etc.  `degree-$k$` does **not** render; `degree $k$` does.  Same rule for the closing `$`: it must be followed by whitespace or end-of-line, not an alphanumeric.

### Rule 7 — never open a math span with `$[`

GitHub processes GFM link references (`[text](url)`) **before** math spans.  When a math span opens with `$[`, the link parser may consume the `[...]` portion before the math parser sees it, leaving orphaned `$` delimiters that prevent the following display block from being recognized.  Use `\lbrack`/`\rbrack` instead of bare `[`/`]` at the start of a math span.

### Rule 8 — never repeat `\command{...}_{...}` in multiple rows of a display environment

The sequence `}_{` (closing brace of a LaTeX command followed by an opening braced subscript) is treated by CommonMark as a **both-flanking** `_` delimiter — one that can both open AND close emphasis.  When this sequence appears in two or more rows of a `\begin{cases}` or `\begin{aligned}` environment, the `_` from row 1 opens emphasis and the `_` from row 2 closes it, creating an `<em>` span that crosses row boundaries and breaks the display math block.  The symptom is double-encoded `&amp;amp;` and spurious blank lines inserted between rows.

The trigger is specifically `\command{...}` (any backslash command with `{}` argument) followed by `_{...}` (subscript with braces) — e.g. `\mathrm{IV}_{\text{const}}`.  The same command with an **unbraced** single-character subscript (`\mathrm{IV}_c`) does **not** trigger emphasis (that `_` is only left-flanking, not right-flanking).

Fix: avoid repeating `\command{...}_{...}` across multiple rows.  Use either:
- **Text with hyphen:** `\text{IV-const}` instead of `\mathrm{IV}_{\text{const}}`
- **Unbraced subscript:** `\mathrm{IV}_c` (only safe for single-character subscripts)

### Rule 9 — never use any explicit spacing commands in math spans

**Both** families of spacing commands fail on GitHub's KaTeX pipeline:

- **Punctuation form** (`\;` `\!` `\,` `\:`): CommonMark resolves all `\<ASCII-punctuation>` sequences to the bare character before KaTeX sees the input (spec §6.7).  `\;` → `;`, `\!` → `!`, `\,` → `,`, `\:` → `:` — bare punctuation inside spacing position causes KaTeX to fail.
- **Alphabetic form** (`\thickspace` `\negthinspace` `\thinspace` `\medspace`): not stripped by CommonMark, but GitHub's client-side KaTeX renders these incorrectly (visible artifacts or wrong spacing) in multiple locations throughout the document.

The fix is to **omit spacing commands entirely**.  KaTeX automatically applies correct spacing to binary operators (`+`, `-`, `\oplus`, `=`, `\neq`, `\leq`, etc.) and relation operators without any explicit hints.  For negative spacing before big delimiters (`\bigl`, `\left`), simply omit the spacing command — `F^r\bigl(` renders correctly without `\!` or `\negthinspace`.

### Rule 10 — never use `\operatorname` (blocked by GitHub's KaTeX allowlist)

`\operatorname` is not in GitHub's KaTeX macro allowlist and produces the error "The following macros are not allowed: operatorname".  Use `\text{name}` instead — it renders identically for named operators (rank, ker, im, span, etc.) and is always permitted.

### Rule 11 — in inline paragraphs, `\command{}_{braced}` pairs with any downstream `letter_` as an emphasis span

Rule 8 covers display environments.  The same `}_{` mechanism also breaks **inline** paragraphs whenever a `\command{...}_{braced}` opener is followed anywhere in the same paragraph by a `letter_{...}` or `letter_letter` subscript that acts as a closer:

- **`\command{...}_{braced}`** (e.g. `\mathrm{ROL}_{n/4}`) — both-flanking: `}` (punctuation) before `_`, `{` (punctuation) after `_` → valid opener **and** closer.
- **`letter_{braced}`** (e.g. `c_{j-1}`) — right-flanking closer only: the plain letter before `_` satisfies the not-preceded-by-punctuation condition, so `_` is right-flanking and can **close** a preceding opener — even though `_` is not left-flanking and cannot itself open.
- **`letter_letter`** (e.g. `a_j`, `b_j`, `c_j`) — both-flanking: valid opener **and** closer.

CommonMark pairs the first opener with the first valid closer that follows, creating an `<em>` span that crosses all `$...$` boundaries between them and breaks every math span in the paragraph.

**Fix:** convert `\command{...}_{braced}` subscripts to function notation so the subscript `}_{` disappears entirely.  For example, `\mathrm{ROL}_{n/4}\bigl(x\bigr)` → `\mathrm{ROL}(x, n/4)`.  An unbraced single-character subscript `\command{...}_k` is also safe (left-flanking only, cannot close), but function notation is preferred for multi-character parameters.

### Correct patterns

The only pattern that survives both rules is **dashes inside a single `\text{}` block** for compound names, and **explicit subscript syntax** when the visual is genuinely a subscript.

| Pattern to avoid | Correct replacement |
|---|---|
| `\text{FOO}\textunderscore\text{BAR}` | `\text{FOO-BAR}` |
| `\text{FOO}\_\text{BAR}` | `\text{FOO-BAR}` |
| `\text{FOO\_BAR}` | `\text{FOO-BAR}` |
| `\text{A}\textunderscore\text{B}\textunderscore\text{C}` | `\text{A-B-C}` |
| `\text{A}\_\text{B}\_\text{C}` | `\text{A-B-C}` |
| `\mathit{IV}\textunderscore\text{const}` | `\mathrm{IV}_{\text{const}}` (subscript form) |
| `\mathrm{HFSCX\textunderscore 256}` | `\text{HFSCX-256}` |
| `C\textunderscore\text{DM}` | `C_{\text{DM}}` |
| `\xleftarrow{\textdollar}` / `\xleftarrow{\$}` | `\xleftarrow{R}` |
| `\overset{\textdollar}{\leftarrow}` / `\overset{\$}{\leftarrow}` | `\overset{R}{\leftarrow}` |
| `\mathbb{GF}(2^n)^*` | `\mathbb{GF}(2^n)^{\ast}` |
| `(R^*, s^*)` | `(R^{\ast}, s^{\ast})` |
| `**Bold.**\n$$x = y$$` (no blank line) | `**Bold.**\n\n$$x = y$$\n\n…` |
| `1. item\n\n    $$x = y$$\n\n    follow-up` (4-space indent in list) | **Never indent** — move `$$x = y$$` to before/after the entire list (cascade if indented; also cascade if column 0 between items) |
| `degree-$k$ Boolean` (no space before `$`) | `degree $k$ Boolean` |
| `$[N, k, t]$-code` (`[` right after `$`) | `$(N, k, t)$-code` (parentheses) or `[N, k, t]-code` (plain text) |
| `\mathrm{IV}_{\text{const}}` repeated in 2+ rows of `\begin{cases}` | `\text{IV-const}` (no subscript, hyphen in text) |
| `\mathrm{ROL}_{n/4}\bigl(x\bigr)` in a paragraph that also has `c_{j-1}` | `\mathrm{ROL}(x, n/4)` — function notation removes `}_{` opener (Rule 11) |
| `$$\nexpr\n$$` (standalone `$$` delimiter lines) | `$$expr$$` or `$$first-line\n...\nlast-line$$` |
| `\operatorname{rank}(\Phi)` | `\text{rank}(\Phi)` — `\operatorname` blocked by GitHub allowlist |
| `\;` / `\!` / `\,` / `\:` in math | (omit — rely on KaTeX auto-spacing) |
| `\thickspace` / `\negthinspace` / `\thinspace` / `\medspace` in math | (omit — renders incorrectly on GitHub's KaTeX) |
| `F^r\!\bigl(` or `F^r\negthinspace\bigl(` | `F^r\bigl(` (no spacing before big delimiter) |

The "uniformly random sample" arrow conventionally has a dollar sign on top; `R` (for "Random") is the standard alternative used in cryptography texts that need ASCII-safe LaTeX.

### Validation

Before pushing changes that add or modify math, simulate GitHub's pipeline locally:

```bash
mkdir -p /tmp/katex-validate && cd /tmp/katex-validate && npm install katex
NODE_PATH=/tmp/katex-validate/node_modules node \
    /path/to/HerraduraKEx/SecurityProofsCode/validate_katex.js \
    /path/to/HerraduraKEx/SecurityProofs-1.md
NODE_PATH=/tmp/katex-validate/node_modules node \
    /path/to/HerraduraKEx/SecurityProofsCode/validate_katex.js \
    /path/to/HerraduraKEx/SecurityProofs-2.md
# Expect: "753 OK, 0 FAIL" and "724 OK, 0 FAIL" (counts vary as the documents grow)
```

The validator at `SecurityProofsCode/validate_katex.js` extracts every `$...$` and `$$...$$` math span, applies CommonMark backslash escape resolution (all `\<ASCII-punctuation>` → bare character) to **both** inline and display spans — matching GitHub's actual pipeline — and then renders each through KaTeX in the correct display/inline mode.  It also flags `\;`/`\!`/`\,`/`\:` as PIPE-FAIL violations in both inline and display contexts.

Pure-KaTeX validation (`katex.renderToString` without escape resolution) **will give false positives** because it does not see the markdown layer; always use the pipeline simulator above.

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
