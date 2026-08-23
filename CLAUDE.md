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
CliTest/                                             (59 scripts; this list is a representative
                                                      sample, not a full index — the real
                                                      enforcement is ci.yml's native-interop
                                                      coverage-guard step)
  test_keygen.sh  test_vectors.sh  test_sign.sh     — Python CLI integration tests
  test_encrypt.sh test_encfile.sh  test_signfile.sh
  test_c_*.sh  test_go_*.sh  test_c_interop.sh      — C / Go CLI tests and cross-language interop
  test_kat_vectors.sh                               — checks KAT/ is current + cross-verified (TODO #190)
  lib_dfr.sh                                        — shared QC-MDPC DFR retry policy sourced by
                                                       every script that decapsulates (TODO #221)
  lib_build.sh                                      — shared "is the CLI binary built?" policy
                                                       (TODO #229).  The compiled CLIs are not
                                                       tracked in git, so run ./build_c.sh and
                                                       ./build_go.sh before the C/Go CliTest
                                                       scripts; a run that asserts nothing now
                                                       exits 2 instead of 0
  test_java_bindings.sh                             — builds + runs bindings/java/ (TODO #192)
  test_java_codec.sh                                — Java PEM/DER codec cross-check vs
                                                       Python CLI, both directions (TODO #197)
  test_java_keygen.sh                               — Java CLI genpkey/pkey smoke test (TODO #198, #200)
  test_java_interop.sh                              — Java <-> Python CLI cross-language interop
                                                       for the classical quartet (TODO #198)
  test_java_nl_interop.sh                           — Java <-> Python CLI cross-language interop
                                                       for the NL/PQC quartet (TODO #199)
  test_java_stern_interop.sh                        — Java <-> Python CLI cross-language interop
                                                       for HPKS-Stern-F/HPKE-Stern-F/HPKE-Stern-KEM,
                                                       DFR-retry-aware for the BGF KEM (TODO #200)
  test_java_oprf_wots_interop.sh                    — Java <-> Python CLI cross-language interop
                                                       for OPRF/HPKS-WOTS-F/HPKS-XMSS-F (TODO #201)
  test_java_hcred_interop.sh                        — Java <-> Python CLI cross-language interop
                                                       for HCRED (TODO #202)
  test_java_pake_interop.sh                         — Java <-> Python CLI cross-language interop
                                                       for aPAKE (TODO #203)
KAT/                                                 — fixed Known-Answer-Test vectors (TODO #190, #226):
  classical_quartet.json    — HKEX-GF/HSKE/HPKS/HPKE vectors at n=256, NIST-CAVP-.rsp-style
  hkex_rnl.json              — HKEX-RNL two-party handshakes at the deployed n=1024
                               and at n=64: m_blind, both (s,C) pairs, the transmitted
                               hint, K_raw and the session key (TODO #226).  Pins the
                               suite layer only — the CLI/PEM layer is TODO #227
  pem/                       — byte-exact wire-format artifacts: keys, a kex response,
                               a session key and an HSKE ciphertext, which each CLI must
                               CONSUME and reproduce (TODO #227).  Pins the CLI layer that
                               hkex_rnl.json does not, at n=1024 and n=64 (TODO #228
                               settled the small-ring session-key width at 256 bits,
                               so all four CLIs now agree there; the C CLI is skipped
                               at n=64, being compiled for a single RNL_N)
  generate_kat.py            — deterministic reference generator (Python) for both JSON
                               files; --check verifies currency
  generate_pem_kat.py        — generator for pem/; --check verifies currency
  verify_kat.go               — independent cross-check against the Go herradura package
                               (bindings/java KatVerify does the same for Java)
SecurityProofsCode/                                 — standalone Python proof/analysis scripts:
  hkex_gf_test.py          — HKEX-GF DH correctness + BSGS DLP illustration
  hkex_nl_verification.py  — NL-FSCX period analysis, Ring-LWR invertibility/noise, v2 bijectivity
  hkex_cy_test.py          — FSCX-CY exhaustive non-linearity & HKEX-CY failure proof
  hkex_cfscx_*.py          — preshared-value, two-step, integer-op, compress/blong constructions
  hkex_classical_break.py  — classical algebraic break proofs
  fscx_revolve_corank.py   — co-rank of the classical FSCX_REVOLVE key map (TODO #210)
  fscx_revolve_closed_form.py — closed-form O(log i) FSCX_REVOLVE: the telescoping
                             identity, the Frobenius argument that keeps every
                             factor sparse, bit-exactness against the loop, and
                             why the NL variants cannot use it (TODO #213)
  hkex_gf_pohlig_hellman.py — Pohlig-Hellman cost/recovery vs. HKEX-GF/HPKS/HPKE (TODO #212)
  hske_perfect_secrecy.py  — Shannon-perfect one-time HSKE at odd step counts (TODO #211)
  hfscx_dm_rf_model.py     — HFSCX-256-DM re-derived in the ideal-random-function
                             model; Joux/Kelsey-Schneier demos (TODO #215)
  qcmdpc_dfr_weak_keys.py  — QC-MDPC BGF DFR extrapolation, weak keys, and the
                             GJS reaction attack (TODO #218)
  hkex_rnl_lattice_2026.py — HKEX-RNL/HKEX-RNL-128 Core-SVP re-estimated directly
                             (primal/dual/hybrid), pinned to published Kyber and
                             Saber figures; supersedes the cited ~105/~220 bit
                             numbers with ~32/~87 (TODO #216)
  rnl_parameter_selection.py — picks HKEX-RNL's replacement parameters: rejects
                             n=768 (x^768+1 CRT-splits over Z, so it projects to
                             ~39 bits), measures the DFR floor, and lands on
                             n=1024 with p unchanged (TODO #223)
  mfscx_kex_analysis.py    — seed-masked FSCX revolve (MFSCX) as a key
                             exchange: static mask stays affine and the
                             classical break generalizes verbatim, dynamic
                             mask destroys two-party agreement, and the
                             generalized injection-schedule impossibility
                             theorem closes the middle ground.  Negative
                             result (TODO #224)
  stern_f_multiround_fs.py — HPKS-Stern-F round count vs. multi-round
                             Fiat-Shamir forgery; challenge-expansion audit
                             (TODO #217)
  stern_f_round_count_resolution.py — reruns #217's uniformity statistic at
                             3M seeds, dropping the resolution floor 0.4418 ->
                             0.0588 bits and settling r=219 vs 220 (TODO #222)
  nl_fscx_exact_trail_search.py — exact xdp+ trail bounds for NL-FSCX v1/v2
                             via SMT; rotation table; key-averaging gap
                             (TODO #214)
  hkex_*_analysis.py       — FSCX_N, multi-nonce, and nonce-impossibility analyses
  validate_katex.js         — pipeline simulator for GitHub KaTeX rendering
SecurityProofs.md                                   — split index (redirects to Parts 1–7; quantum analysis is in SecurityProofs-2.md §6)
SecurityProofs-1.md                                 — §1: Algebraic Foundations (300 math expressions)
SecurityProofs-2.md                                 — §2–§8: Protocol Analysis · Security Analysis · Summary Tables · Quantum Attack Analysis · Experimental Code Index (408 math expressions)
SecurityProofs-3.md                                 — §9–§10: Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
SecurityProofs-4.md                                 — §11–§11.8.2: Non-linearity/PQC extensions · NL-FSCX v1/v2 · HKEX-RNL (659 math expressions)
SecurityProofs-5.md                                 — §11.8.3–§11.8.8: PQ signature options · HPKE-Stern-KEM (587 math expressions)
SecurityProofs-6.md                                 — §11.9: HFSCX-256-DM (131 math expressions)
SecurityProofs-7.md                                 — §11.10–§11.13, §11.15–§11.21: ZKP extensions · Ring-LWR Σ-protocol · NL-FSCX ZKBoo · research-review sections (649 math expressions)
docs/
  TUTORIAL.md               — API usage guide per protocol and language
  INTRODUCTION.md           — lay-audience primer for all core concepts
  examples/{python,c,go}/   — hello_herradura.* integration examples
Mcp/                                                 — MCP server exposing the CLI (genpkey/pkey/kex/
                                                      enc/dec/sign/verify/dgst) as agent-callable tools
                                                      over stdio; see Mcp/README.md for the trust model
spec/                                                — machine-readable protocol spec (JSON Schema):
                                                      parameters, PEM wire-format labels, CLI --algo
                                                      tags, and security-level classification per
                                                      protocol; generate_spec.py regenerates it
SPEC.md                                              — human-readable prose companion to
                                                      spec/herradura-protocol-spec.json
SECURITY.md                                          — security policy: protocol maturity levels,
                                                      vulnerability reporting process
Dockerfile / docker-entrypoint.sh                    — quickstart image building/smoke-testing the
                                                      C/Go/Python/ARM/i386 targets (TODO #139); see
                                                      Build Commands
pyproject.toml                                       — packaging metadata for the Python CLI/suite
                                                      (setuptools build backend, no runtime deps)
bindings/ffi/                                        — opt-in ctypes/cgo FFI bindings around
                                                      herradura.h's classical v1.4.0 quartet, for
                                                      performance-sensitive Python/Go callers
bindings/java/                                       — complete pure-Java port of the HerraduraKEx suite
                                                      (TODO #196 umbrella, closed): the classical
                                                      v1.4.0 quartet (herradurakex.Herradura), the
                                                      NL/PQC quartet (herradurakex.HerraduraNl, TODO
                                                      #199), HPKS-Stern-F/HPKE-Stern-F/HPKE-Stern-KEM
                                                      (herradurakex.Stern, TODO #200), OPRF/
                                                      HPKS-WOTS-F/HPKS-XMSS-F (herradurakex.Oprf/
                                                      Wots/Xmss, TODO #201), HCRED
                                                      (herradurakex.Hcred, TODO #202), and aPAKE
                                                      (herradurakex.ZkpNl/Hpake, TODO #203), for JVM
                                                      integrations; cross-checked against
                                                      KAT/classical_quartet.json.
                                                      herradurakex.HerraduraCli (TODO #198-#203) mirrors
                                                      HerraduraCli's genpkey/pkey/kex/enc/dec/sign/
                                                      verify/dgst/encfile/decfile/oprf-blind/oprf-eval/
                                                      oprf-unblind/cred-issue/cred-prove/cred-verify/
                                                      pake-register/pake-demo subcommand interface for
                                                      --algo hkex-gf/hpks/hpke (plus hske), hkex-rnl/
                                                      hske-nla1/hske-nla2/hpks-nl/hpke-nl,
                                                      hpks-stern/hpke-stern/hpke-stern-kem,
                                                      oprf/hpks-wots/hpks-xmss (the latter two use a
                                                      <keyfile>.idx sidecar file for one-time-use/
                                                      leaf-index state, matching the Python CLI), hcred,
                                                      and aPAKE
herradura/                                            — root-level Go package (herradura.go, codec.go)
                                                      used by the FFI Go binding and its fuzz tests
benchmarks/                                          — recorded benchmark output/history;
                                                      compare_*.py drivers, incl.
                                                      compare_fscx_revolve_closed_form.py
                                                      (TODO #213, C/Go/Python)
Fuzz/                                                — fuzzing harnesses (see TODO #130)
```

Three `go.mod` files: root-level (`module herradurakex`), `CryptosuiteTests/` (`module herradurakex/tests`), and `HerraduraCli/` (`module herradurakex/cli`, uses `replace herradurakex => ../`). None has external dependencies.

## Changelog, README, and TODO Policy

All notable changes are documented in `CHANGELOG.md` only.  Do **not** add version notes, release blurbs, or change summaries to `README.md`.  The README describes the current state of the project; the CHANGELOG tracks its history.  When a feature or fix is completed, add a new versioned entry to `CHANGELOG.md` and update the version number in the `README.md` title line — nothing else.

Work items are tracked as numbered entries (#1–#N) with a `Status:` line, split across two files (TODO #154): **`TODO.md`** holds only currently-`OPEN` entries; **`TODO_DONE.md`** archives everything else (`DONE`/`DEPRECATED`/`ACKNOWLEDGED`), in original numeric/chronological order. Numbering is global and never reused across the two files — an item keeps its `#N` forever, whichever file it currently lives in. When completing a TODO, update its `Status:` line to `**DONE vX.Y.Z**` with the release version, move the whole entry from `TODO.md` to the end of `TODO_DONE.md`, then add the corresponding `CHANGELOG.md` entry. Version numbers follow `MAJOR.MINOR.PATCH`; each TODO completion is typically one PATCH bump. When creating a new item, add it to `TODO.md` with `Status: **OPEN**`.

**MINOR vs. PATCH (post-2.0.0):** bump MINOR, not PATCH, for a TODO that adds a new
protocol, CLI subcommand, or public API surface without breaking any existing one (e.g.
a new `--algo` variant, a new language-target port of an existing protocol). Bump PATCH
for everything else — bug fixes, documentation, internal refactors, parameter tuning,
new tests. This mirrors ordinary semver practice; `TODO_DONE.md`'s pre-2.0.0 history
used PATCH almost everywhere (matching this project's fast, incremental TODO cadence)
and that history is not being renumbered retroactively.

**MAJOR (post-2.0.0):** reserved for changes that break the stable CLI/PEM/wire-format
surface 2.0.0 establishes — a PEM boundary label change, a CLI flag rename or removal,
a change to what an existing `--algo` value produces or accepts, or any change that
makes an existing key/ciphertext/signature file unreadable by a newer build. Any TODO
that would require one of these must call it out explicitly in its own text (not just
in the `Status:` line) and get a `MIGRATING.md` entry alongside the version bump —
follow the format already used there. Internal changes with no effect on stored
artifacts or the CLI surface (e.g. an internal hash construction upgrade that also
changes wire format, like the HFSCX-256-DM and Stern H-matrix changes predating 2.0.0)
are wire-format breaking but not necessarily MAJOR-worthy on their own; use judgment
and err toward documenting in `MIGRATING.md` regardless of which version-component
changes.

### TODO.md / TODO_DONE.md Status line standard

Every `### ` section in `TODO.md` or `TODO_DONE.md` must end with exactly one `Status:` line using one of these keywords:

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

**Quick check:** `python3 -c "import re,sys; [print(m.group()) for f in ('TODO.md','TODO_DONE.md') for m in re.finditer(r'(?m)^### .+\n(?:(?!^Status:)[\s\S])*?(?=^###|\Z)', open(f).read()) if 'Status:' not in m.group()]"` — prints any `###` section (in either file) that is missing a Status line. `TODO.md` sections should additionally all say `**OPEN**`, and `TODO_DONE.md` sections should never say `**OPEN**` — a mismatch means an entry wasn't moved when its status changed. Sections predating the `Status:` line standard (TODO #154) — `TODO_DONE.md`'s `### 13`, `### 17`, `### 18`, `### 24`–`### 28`, `### 42`, `### 56`, `### 69`, `### 70`, `### 77`–`### 80` (16 sections in all) — carry no `Status:` line at all. Two of them (`### 13`, `### 26`) mark completion with an inline `✓ DONE`/`DONE (vX...)` marker in the heading; the other fourteen record it only by living in `TODO_DONE.md` and having a `CHANGELOG.md` entry. All 16 are grandfathered rather than backfilled, so the quick-check flagging them is expected and not itself a bug.

## Build Commands

Use the build scripts when building everything; they apply the correct flags, output names, and dependency checks.

```bash
./build_c.sh          # compiles suite, tests, and HerraduraCli/herradura_cli
./build_go.sh         # compiles suite, tests, and HerraduraCli/herradura_cli_go
./build_arm.sh        # ARM Thumb-2 suite + tests (requires arm-linux-gnueabi-gcc)
./build_asm_i386.sh   # NASM i386 suite + tests (auto-detects elf_i386-capable linker)
./build_arduino.sh    # Arduino/AVR suite + tests; run_arduino.sh runs them under simulation
./build_c_sanitize.sh # C suite/tests/CLI under ASan+UBSan (requires clang); see Testing
```

### Docker

`docker build -t herradurakex .` builds a quickstart image (TODO #139) covering the
C/Go/Python/ARM Thumb-2/NASM i386 targets (Arduino is excluded — needs `arduino-cli`
and a board target). `docker-entrypoint.sh` builds every host-portable target and runs
a smoke test (the C/Go/Python security test suites plus a CLI interop test) on
container start.

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

No unit-test framework in the traditional sense — tests are pass/fail assertions printed
to the console by the suite/CLI binaries themselves. `.github/workflows/ci.yml` runs eleven
jobs on every push/PR, all required/blocking: `native-c`, `native-go`, `native-python`
(one job per language — build/no-build + suite tests + that language's own `CliTest/*.sh`
scripts, split from a single combined `native` job in TODO #205), `native-interop`
(the `CliTest/*.sh` scripts that exercise two or more CLIs at once — builds both C and Go —
plus a coverage-guard step that fails if any non-Java, non-cross-lang-matrix `CliTest/*.sh`
script isn't claimed by exactly one of these four `native-*` jobs, and a DFR-guard step that
fails if a script which decapsulates `hpke-stern-kem` doesn't source `CliTest/lib_dfr.sh`,
TODO #221), `native-java` (builds/
runs the `bindings/java/` port and all `CliTest/test_java_*.sh` scripts — Java-vs-Python
interop and KAT cross-checks per-protocol-family, TODO #206), `cross-lang-compat` (builds
all four CLIs and runs `CliTest/test_cross_lang_matrix.sh` — a genuine 4-way C/Go/Python/
Java compatibility matrix across the classical quartet, the NL/PQC quartet, the Stern
family, HCRED, OPRF, and aPAKE, proving every pair of languages interoperates directly
rather than only each against Python; runs after the four `native-*` jobs, TODO #207),
`arm-i386` (ARM Thumb-2/NASM i386 under qemu), `katex` (math-rendering validation, TODO
#179), `arduino` (Arduino/AVR under simavr — ran `continue-on-error: true` until TODO #185
promoted it after confirming 100% pass history since its one known failure mode, an SRAM
overflow, was fixed in TODO #155), `fuzz-smoke` (30s/target libFuzzer/go-fuzz/Hypothesis/
CLI-argv run, TODO #187), and `sanitizers` (C suite/tests/CLI under ASan+UBSan plus a
bounded valgrind memcheck pass, TODO #188). Locally, run the same scripts by hand as
described below.

`.github/workflows/codeql.yml` runs a separate, non-blocking CodeQL static-analysis
matrix (C/C++, Go, Python) on every push/PR plus a weekly schedule (TODO #189); alerts
surface under the repo's Security tab rather than as a required check.

Whenever a TODO adds or removes a test number or CLI subcommand, re-check this section (and `llms.txt`'s CLI section) for drift rather than waiting for the next major-version doc audit — see TODO #145.

```bash
# C/Go/Python — security tests [1]–[29] + benchmarks [30]–[41]
# ([44] HCRED, [45] weak-key/malformed-input rejection appended after the
#  benchmarks to avoid renumbering; all three languages also run test [19]
#  "HFSCX-256-DM known-answer vectors" out of strict numeric sequence)
./CryptosuiteTests/Herradura_tests_c
./CryptosuiteTests/Herradura_tests_c -r 500        # cap each test at 500 iterations
./CryptosuiteTests/Herradura_tests_c -t 2.0        # cap wall-clock per test/bench at 2 s
HTEST_ROUNDS=200 HTEST_TIME=1.5 ./CryptosuiteTests/Herradura_tests_c  # env-var equivalents

cd CryptosuiteTests && go run Herradura_tests.go
cd CryptosuiteTests && go run Herradura_tests.go -r 500 -t 2.0

python3 CryptosuiteTests/Herradura_tests.py
python3 CryptosuiteTests/Herradura_tests.py -r 500 -t 2.0

# Assembly — build first (see Build Commands), then run:
# ARM/NASM/Arduino: tests [1]–[18]
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
./run_arduino.sh tests    # simavr; TIMEOUT env var, default 90s

# C sanitizers (TODO #188) — build first with build_c_sanitize.sh, then run:
./build_c_sanitize.sh
./CryptosuiteTests/Herradura_tests_asan -t 2.0   # ASan+UBSan; aborts on first issue found
./HerraduraCli/herradura_cli_asan --help         # CLI under the same instrumentation

# Valgrind memcheck (slow — use small -r/-t; a plain, non-sanitized debug build,
# since ASan and valgrind's own instrumentation conflict):
gcc -O0 -g -o /tmp/herr_tests_valgrind CryptosuiteTests/Herradura_tests.c
valgrind --leak-check=full --show-leak-kinds=definite,indirect \
  /tmp/herr_tests_valgrind -r 3 -t 0.2
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

Each script in `SecurityProofsCode/` is standalone — runnable on its own with no third-party dependencies.  Many (about 20, including `fscx_revolve_corank.py` and `fscx_revolve_closed_form.py`) do load the suite via `importlib`, deliberately: a script that verifies a claim about the shipped implementation has to test the shipped implementation.  Run them to reproduce the analysis results cited in `SecurityProofs-*.md`:

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
├── HPKS-Stern-F — Fiat-Shamir signature (C/Go/Python: N=n=256, t=16, rounds=32 demo
│                  default, 219 for 128-bit Fiat-Shamir soundness — Python/Go CLI:
│                  `sign --rounds 219`; C CLI: rebuild with `-DSDF_ROUNDS=219`;
│                  assembly/Arduino: N=32, t=2, rounds=4)
│                  commit: c0=hash(π,H·r^T), c1=hash(σ(r)), c2=hash(σ(y))
│                  challenge b∈{0,1,2} via NL-FSCX hash of msg+commitments
│                  response reveals permuted r, y=e⊕r, or permutation π
└── HPKE-Stern-F — Niederreiter KEM: ct=H·e'^T; K=hash(seed,e')
                   (`--algo hpke-stern`: demo, decap uses known e'; `--algo hpke-stern-kem`:
                   real BGF QC-MDPC decoder, qcmdpc_keygen/encap/decap_bgf in C/Go/Python)
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
