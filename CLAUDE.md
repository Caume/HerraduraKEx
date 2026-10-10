# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It is a working guide, not a history.  The reasoning behind every rule below lives in
`CHANGELOG.md` and `TODO_DONE.md` under the TODO number cited; read the entry before
reversing a decision.  Coverage counts the checkers print about themselves are in
`spec/COVERAGE_COUNTS.md` (held to the tools by `spec/check_docs_consistency.py` check E).

## Project Overview

HerraduraKEx is a cryptographic suite implementing four protocols — HKEX-GF (key exchange), HSKE (symmetric encryption), HPKS (Schnorr signature), and HPKE (El Gamal encryption) — built on the FSCX (Full Surroundings Cyclic XOR) primitive and Diffie-Hellman arithmetic over GF(2^n)*, plus NL-FSCX, Ring-LWR (HKEX-RNL), code-based (Stern-F, QC-MDPC KEM), ZKP, credential, OPRF and PAKE extensions. Implementations exist in C, Go, Python, Java, ARM Thumb-2 assembly, NASM i386 assembly, and Arduino.

## Repository Structure

```
Herradura cryptographic suite.{c,go,py,s,asm,ino}  — protocol suite, one file per language
herradura.h                — header-only C library (shared by CLI and external code)
herradura/                 — root-level Go package (herradura.go, codec.go); used by the Go
                             FFI binding and fuzz tests
bindings/java/             — complete pure-Java port incl. herradurakex.HerraduraCli (all
                             --algo tags).  Entry points: SelfTest ([1]–[35]), Demo
                             (walkthrough), KatVerify / VerifyBitArray (vector consumers),
                             Bench ([36], the QC-MDPC KEM benchmark)
bindings/ffi/              — opt-in ctypes/cgo bindings around herradura.h's classical quartet
CryptosuiteTests/
  Herradura_tests.{c,go,py,s,asm,ino}  — security tests & benchmarks
  go.mod                               — module herradurakex/tests
HerraduraCli/
  herradura.py / herradura_cli.c / herradura_cli.go — OpenSSL-style CLIs (Java's is in
                                         bindings/java)
  herradura_codec.h / codec.py         — PEM/DER encode-decode helpers
  primitives.py                        — suite import shim for the Python CLI
  go.mod                               — module herradurakex/cli
CliTest/                   — CLI integration + cross-language interop scripts.  ci.yml's
                             native-interop coverage guard is the real index: every script
                             must be claimed by exactly one native-* job.  Shared libs:
  lib_dfr.sh               — QC-MDPC DFR retry policy; every script that decapsulates
                             hpke-stern-kem must source it (ci.yml DFR guard).  Implicit
                             rejection means `dec` always exits 0, so compare BYTES
  lib_build.sh             — "is the CLI built?"; run ./build_c.sh and ./build_go.sh first
                             (compiled CLIs are not in git); a run asserting nothing exits 2
  lib_malformed.sh         — malformed-PEM case table (test_weak_key_rejection.sh,
                             test_malformed_pem_matrix.sh)
KAT/                       — Known-Answer-Test vectors and their consumers:
  classical_quartet.json, hkex_rnl.json, nl_fscx_v3.json — regenerable by generate_kat.py
                             (--check verifies currency)
  hcred_kkw.json (+ hcred_kkw_vector.h) — PINNED, verify-side only (KKW proofs are random);
                             --capture-kkw re-captures, --emit-kkw-header rebuilds the .h
  pem/                     — byte-exact CLI wire artifacts every CLI must consume and
                             reproduce (generate_pem_kat.py).  test_kat_pem.sh is EXEMPT from
                             the DFR guard: a pinned key/ciphertext has nothing to retry
  bitarray.json (+ bitarray_vector.h) — BITARRAY.md conformance; all four ports consume it
                             (verify_bitarray_{c.c,go.go,py.py}, Java VerifyBitArray).
                             generate_bitarray_kat.py holds the reference implementation.
                             Two cases exceed 2^53: decode JSON integers exactly
  sampler_replay.json / operation_replay.json — fixed-stream replays pinning randomised
                             samplers and whole operations across all four ports
  verify_kat.go, verify_kat_c.c — Go / C cross-checks (Java: KatVerify)
SecurityProofsCode/        — standalone proof/analysis scripts backing SecurityProofs-*.md.
                             `run_findings_gates.py --list` is the index: every script is
                             either a findings gate (exits non-zero if its finding stops
                             reproducing) or declared in NON_GATING with a reason.  Each
                             script's own header documents its findings and caveats.  Also:
  validate_katex.js, check_part_index.py, KATEX_RULES.md — math-rendering tooling
  certified_cycle_mean.c, local_certificate_dp.c, hull_exact.c — standalone C helpers
                             (no herradura.h) driven by their .py scripts
SecurityProofs.md          — split index (redirects to Parts 1–10)
SecurityProofs-1.md        — §1: Algebraic Foundations (300 math expressions)
SecurityProofs-2.md        — §2–§8: Protocol, security and quantum analysis · summary tables (409 math expressions)
SecurityProofs-3.md        — §9–§10: Non-Linear Proposals · v1.4.0 Migration (409 math expressions)
SecurityProofs-4.md        — §11–§11.8.2: NL-FSCX v1/v2 · HKEX-RNL (693 math expressions)
SecurityProofs-5.md        — §11.8.3–§11.8.10: PQ signature options · HPKE-Stern-KEM (672 math expressions)
SecurityProofs-6.md        — §11.9: HFSCX-256-DM (131 math expressions)
SecurityProofs-7.md        — §11.10–§11.13, §11.15–§11.33: ZKP extensions · research reviews (698 math expressions)
SecurityProofs-8.md        — §11.34–§11.36: NL-FSCX v3 · asymptotic slopes (435 math expressions)
SecurityProofs-9.md        — §11.37–§11.42: width residue · annealed / quenched / exact ladders (726 math expressions)
SecurityProofs-10.md       — §11.43–§11.49: local certificate · linear hull · coupled ladder (90 math expressions)
spec/                      — machine-readable protocol spec (generate_spec.py; --check gates
                             it) and the cross-document / cross-language checkers; see
                             spec/README.md:
  check_security_md.py     — protocol status vs. SECURITY.md
  check_docs_consistency.py — README/INTRODUCTION/CHANGELOG vs. spec and herradura.h
  check_language_parity.py — four-way parity: numbered tests, primitive manifest,
                             parameters, randomness/replay censuses, sampled-test rates
  measure_sampled_rates.py — instrument behind the recorded rate mechanisms (NOT run in CI)
  COVERAGE_COUNTS.md       — the coverage counts the checkers print, held to them by check E
tools/                     — poison_build.sh (run-time BitArray width poisoning over every C
                             TU), check_runnable_coverage.py, check_rate_format.py,
                             check_docker_mirror.py, check_ba_width_guard.c
benchmarks/                — cost measurements (host-specific; figures do not belong in CI,
                             but CI checks they still build/run).  rnl_deployed_ring_cost.*
                             is the deployed HKEX-RNL ring (benchmark [40] uses retired rings)
Mcp/                       — MCP server exposing the CLI as agent tools; see Mcp/README.md
                             for the trust model.  Validates arguments against input_schema
Fuzz/                      — fuzzing harnesses (Fuzz/README.md, run_fuzz.sh)
docs/                      — TUTORIAL.md, INTRODUCTION.md, BENCHMARKS.md, examples/
SPEC.md                    — prose companion to spec/herradura-protocol-spec.json
BITARRAY.md                — NORMATIVE BitArray spec, implemented by all four ports.  Read §3
                             before touching width-taking code: binary ops REQUIRE equal
                             widths (E_MIXED_WIDTH, never coerced); truncation takes the HIGH
                             bits (§4.4).  Assembly/Arduino stay fixed-width
SECURITY.md                — protocol maturity levels, vulnerability reporting
Dockerfile / docker-entrypoint.sh — quickstart image (see Build Commands)
pyproject.toml             — packaging metadata (no runtime deps)
```

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

The `Status:` line format for `TODO.md` / `TODO_DONE.md` sections, and the list of
grandfathered pre-#154 entries, live in the `todo-status` skill
(`.claude/skills/todo-status/SKILL.md`) — load it when opening or closing a TODO.

## Third-party dependencies

The shipped primitives and CLIs have **none**, in any language, and that is a property
worth preserving — `./build_c.sh`, `./build_go.sh` and every `HerraduraCli/` entry point
run against a bare toolchain.  Four optional packages exist, all analysis- or
tooling-only.  Most consumers degrade to a printed NOTE rather than failing; `z3-solver`
and `highspy` are the documented exceptions, for the reasons in their rows (TODO #290,
TODO #257's sixth pass).

| package | used by | absent ⇒ | install |
|---|---|---|---|
| `jsonschema` | `spec/generate_spec.py` schema validation | NOTE, but CI passes `--require-schema` so a skipped validation cannot pass | `pip install jsonschema` |
| `z3-solver` | `SecurityProofsCode/nl_fscx_exact_trail_search.py` (TODO #214), `fscx_periodicity_z3.py`, `hpks_schnorr_z3.py` | **the gate FAILS** — those last two are z3 from top to bottom, so there is no section left to skip and a printed NOTE plus exit 0 would report a finding as reproducing that was never checked.  All three print the install line and exit non-zero; CI's `analysis-findings` job installs the package for exactly this reason (TODO #290) | `pip install z3-solver` |
| `pulp` (CBC) | `SecurityProofsCode/nl_fscx_v2_bounds.py` §(d) MILP bounds (TODO #247) | section skipped | `sudo apt-get install -y python3-pulp`, or a venv: `python3 -m venv ~/.venvs/herradura-milp && ~/.venvs/herradura-milp/bin/pip install pulp` |
| `highspy` | the same §(d) model under a stronger backend (TODO #252 §11.35.6); and `SecurityProofsCode/local_potential_certificate.py` / `local_certificate_n256.py` / `live_region_certificate.py` (TODO #257, sixth, seventh and ninth passes), where every bound is an LP optimum | in `nl_fscx_v2_bounds.py`, CBC is used instead and reaches one round fewer; in `local_potential_certificate.py`, `local_certificate_n256.py` and `live_region_certificate.py` **the gate FAILS**, on z3's reasoning -- the solver is the whole gate, so there is nothing left to skip.  CI's `analysis-findings` job installs it beside z3-solver | `pip install highspy` (pulls in numpy), or `~/.venvs/herradura-milp/bin/pip install highspy` (PuLP finds it as the `HiGHS` solver) |

Never add one to a shipped primitive.  If an analysis script needs a solver, it imports it
inside a `try`/`except ImportError` and prints what to install — and then decides its exit
status by what is left: non-zero if the solver WAS the gate, zero with a NOTE if the gate
survives without it.

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

`docker build -t herradurakex .` builds a quickstart image (TODO #139) covering five
language targets — C/Go/Python/ARM Thumb-2/NASM i386.  Arduino is excluded (needs
`arduino-cli` and a board target) and Java is excluded (the image installs no JDK); both
exclusions are checked by `tools/check_docker_mirror.py` (TODO #326).
`docker-entrypoint.sh` builds every included target and runs a smoke test on container
start — **~75–90 min on an ARM SBC**; `HERRADURA_SMOKE_ROUNDS` / `HERRADURA_SMOKE_TIME`
cap it.  The `docker` CI job builds the image and runs the entrypoint at reduced caps.

### C

Use `build_c.sh`. Manual equivalent: `gcc -O2 -o <output> <source.c>` per target (suite, tests, CLI).

> **Build collision hazard:** `go build file.go` (without `-o`) names its output
> after the source filename stem — identical to the old unsuffixed C binary path.
> The `_c` suffix makes all six target binaries distinct: `_c`, `_go`, `_arm`,
> `_i386`, `_avr.elf`. Always use `build_go.sh` or pass `-o name_go` explicitly
> when invoking `go build` directly. Never run bare `go build file.go`.

### Go and Python

Use `build_go.sh`.  The Python targets need no build step, and neither language
target has external dependencies.  Never run bare `go build file.go` — see the
build-collision hazard above.

### Assembly

Use `build_arm.sh` / `build_asm_i386.sh`. To run: `qemu-arm -L /usr/arm-linux-gnueabi "./Herradura cryptographic suite_arm"` or `qemu-i386 "./Herradura cryptographic suite_i386"`.

> **i386 linker portability:** `x86_64-linux-gnu-ld -m elf_i386` fails on ARM64 hosts
> (e.g. Raspberry Pi 5 / Ubuntu) with "unrecognized emulation mode: elf_i386" because the
> native `ld` (aarch64) has no i386 emulation.  `build_asm_i386.sh` auto-detects the first
> available linker with `elf_i386` support.  If none is found, install one:
> - `sudo apt-get install -y binutils-x86-64-linux-gnu`  (provides `x86_64-linux-gnu-ld`)
> - `sudo apt-get install -y binutils-i686-linux-gnu`    (provides `i686-linux-gnu-ld`)

## Testing
## Testing

No unit-test framework — tests are pass/fail assertions printed by the suite/CLI binaries
themselves, and **any `[FAIL]` fails the build**.

### How a run is gated

- **C/Go/Python (TODO #233):** each harness aggregates the `[FAIL]` markers in its own
  output (`#define printf hprintf` in C, a `print` shadow in Python, an `os.Stdout` scanning
  pipe in Go) and exits non-zero, closing with `*** OK: ... ***` or `*** FAILED: n ... ***`.
  There is no allow-list and nothing to register: a new test is gated by printing `[FAIL]`.
- **ARM / NASM i386 (TODO #234):** route output through `bl hprintf` / `call print_str`.
  `build_arm.sh` and `build_asm_i386.sh` fail the build on a call site that bypasses the
  wrapper without a `GATE-EXEMPT` marker.
- **Arduino:** all verdicts go through one `verdict(bool)` helper (the marker is split
  across two `Serial` calls, so output scanning cannot work).  The firmware never exits, so
  `run_arduino.sh` fails on a `*** FAILED:` line **or on the OK line never arriving**.
- **Java:** `SelfTest` asserts; `Demo` is `[FAIL]`-gated like the C/Go/Python demos.
- **Findings gates (TODO #289, #291):** `SecurityProofsCode/run_findings_gates.py`
  DISCOVERS every script whose exit status is its verdict; there is no list to add to.
  Every `.py` there is a gate or is in `NON_GATING` with a reason; skipping a gate needs a
  reason in `EXCLUDED`.  Both tables fail on stale entries.

### Rules for writing tests (each learned from a real defect)

- **A probabilistic subject gets a threshold that follows its statistic**, never a fixed
  one against a fresh sample (#233, #299).  Prefer making the verdict exact: separate the
  ambiguous branch from the failure branch (`[18]`), or CONSTRUCT the bad input instead of
  sampling until one appears (`[53]`, #310).  Retrying until a sample passes, or
  conditioning the assertion on the sample, is a vacuous pass.
- **Count every term of a sampled test's rate** — two can hide each other (#310).
- **Stern rejection tests need their own round count.**  The assembly harnesses run Stern-F
  at `rounds=4`, i.e. a `(2/3)^4` = 19.75% soundness error per trial.
- **Every rejection test needs an accept-control first**, or a broken implementation that
  refuses everything passes (#234, #313).
- **Every negative control must be shown to FIRE**, and a hiding test's control must keep
  the true witness inside the candidate set (#298, #301).
- **A section that did not run is never scored as a pass** — report it as `n/a` (#291).
- **Cross-port checks cannot see a property all four ports get wrong**; that needs an
  assertion about ONE implementation (#298).  Where the property can be a VERIFIER
  invariant, enforce it there instead of in a test.
- **Run new code at a second width / parameter** — #313's divergence sat under a green
  518-assertion matrix because everything ran at 256 bits.
- **Adding a test, constant, randomness consumer or primitive trips the `spec/`
  censuses** (`check_language_parity.py`): numbered-test contiguity, the primitive
  manifest, `PARAMETERS`, parameter-use, the randomness/replay censuses, `_TEST_DRAWS`,
  verdict fingerprints and sampled-test rates.  That is intended — file the row it asks for
  rather than working around it.  Rates in `_SAMPLED_TEST_RATES` are EXPRESSIONS over
  constants read from source; do not hand-compute them.
- **If a gate flakes, fix that gate's threshold** (replicate per #299) — never add
  `continue-on-error` to make a red run pass.
- When a TODO adds or removes a test number or CLI subcommand, re-check this section and
  `llms.txt`'s CLI section for drift (TODO #145).

### CI

`.github/workflows/ci.yml` runs thirteen jobs on every push/PR, **all required**:
`native-c`, `native-go`, `native-python` (build + suite tests + that language's own
`CliTest/` scripts), `native-interop` (multi-CLI scripts, plus the CliTest coverage guard
and the DFR guard), `native-java`, `cross-lang-compat` (4×4 matrices:
`test_cross_lang_matrix.sh`, `test_malformed_pem_matrix.sh`, and others), `arm-i386`
(qemu), `katex` (+ part-index check), `arduino` (simavr), `fuzz-smoke`, `sanitizers`
(ASan+UBSan + valgrind), `analysis-findings` (`run_findings_gates.py`) and `docker`
(image build + reduced-cap entrypoint).  The two QC-MDPC gates also run in `native-python`
on purpose (defense in depth, TODO #336).  `.github/workflows/codeql.yml` is a separate,
non-blocking CodeQL matrix (TODO #189).

### Commands

Test numbering (C/Go/Python share one): security tests `[1]–[31]`, benchmarks
`[32]–[43]`, security tests `[44]–[53]` appended after the benchmarks, benchmark `[54]`
(the QC-MDPC KEM, with a correctness control).  `[19]` runs out of sequence.  Java:
`SelfTest` `[1]–[35]`, `Bench` `[36]`.  ARM/NASM/Arduino: `[1]–[18]`.

```bash
./CryptosuiteTests/Herradura_tests_c
./CryptosuiteTests/Herradura_tests_c -r 500        # cap each test at 500 iterations
./CryptosuiteTests/Herradura_tests_c -t 2.0        # cap wall-clock per test/bench at 2 s
HTEST_ROUNDS=200 HTEST_TIME=1.5 ./CryptosuiteTests/Herradura_tests_c  # env-var equivalents

cd CryptosuiteTests && go run Herradura_tests.go -r 500 -t 2.0
python3 CryptosuiteTests/Herradura_tests.py -r 500 -t 2.0

java -cp bindings/java herradurakex.SelfTest
java -cp bindings/java herradurakex.Bench [-r N] [-t S]

# Assembly — build first (see Build Commands):
qemu-arm -L /usr/arm-linux-gnueabi ./CryptosuiteTests/Herradura_tests_arm
qemu-i386 ./CryptosuiteTests/Herradura_tests_i386
./run_arduino.sh tests    # simavr; TIMEOUT env var, default 90s

# C sanitizers:
./build_c_sanitize.sh
./CryptosuiteTests/Herradura_tests_asan -t 2.0
./HerraduraCli/herradura_cli_asan --help

# Valgrind (plain debug build; ASan and valgrind conflict):
gcc -O0 -g -o /tmp/herr_tests_valgrind CryptosuiteTests/Herradura_tests.c
valgrind --leak-check=full --show-leak-kinds=definite,indirect \
  /tmp/herr_tests_valgrind -r 3 -t 0.2

# C run-time width poisoning over every C translation unit:
bash tools/poison_build.sh
```

`-r`/`--rounds` caps iterations per security test; `-t`/`--time` caps wall-clock for tests
and benchmarks; CLI flags override `HTEST_ROUNDS`/`HTEST_TIME`.  In the Python harness,
`_trange` only polls the time cap every 64 iterations, so a site requesting fewer than 64
is never truncated; each run prints a closing `--- Time cap: ... ---` summary.  `[14]`
exercises `RNL_SIZES` (retired rings), not the deployed `RNLN = 1024`.

### CLI integration tests (CliTest/)

```bash
# Python CLI — no build needed
bash CliTest/test_keygen.sh
bash CliTest/test_vectors.sh   # Alice+Bob derive the same secret
bash CliTest/test_sign.sh
bash CliTest/test_encrypt.sh
bash CliTest/test_aead.sh      # 4x4 cross-CLI (needs C+Go built)

# C / Go CLIs — run ./build_c.sh / ./build_go.sh first
bash CliTest/test_c_interop.sh
bash CliTest/test_go_interop.sh
bash CliTest/test_cross_lang_matrix.sh   # all four CLIs
```

### SecurityProofsCode scripts

Each script is standalone and needs no build; a few need the optional packages listed
under Third-party dependencies.  About 20 load the shipped suite via `importlib` on
purpose, so they test what ships.

```bash
python3 SecurityProofsCode/hkex_gf_test.py
python3 SecurityProofsCode/qcmdpc_bgf_variants.py --quick   # ~11 min; --full ~72 min
python3 SecurityProofsCode/run_findings_gates.py --list     # the set, incl. NON_GATING
python3 SecurityProofsCode/run_findings_gates.py            # all gates, --quick; ~120 min on an aarch64 SBC
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
│                  default, 219 for 128-bit Fiat-Shamir soundness — all three CLIs
│                  take `sign --rounds 219` and `cred-issue --rounds 219` since
│                  v3.1.0 (TODO #236); the round count travels in the PEM, so a
│                  reader accepts any count in [1, SDF_MAX_ROUNDS] regardless of
│                  its own SDF_ROUNDS, which remains only the signing default.
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

Four parallel implementations (`herradura.py`, `herradura_cli.c`, `herradura_cli_go`, and Java's `herradurakex.HerraduraCli`) share the same PEM wire format and subcommand interface — `genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, `verify`, `dgst`, `encfile`, `decfile` and more (see `--help`; deliberate per-CLI flag differences are listed in `spec/`'s `cli_surface_gaps`).  PEM files produced by any implementation are byte-for-byte compatible with the others.

- Python CLI (`herradura.py`) imports the suite via `primitives.py`, which uses `importlib` to load the space-named suite file.
- C CLI (`herradura_cli.c`) `#include`s `../herradura.h` and `herradura_codec.h` for PEM/DER encode-decode.
- HKEX-RNL key exchange is two-round: Bob responds first (`kex --algo hkex-rnl --our bob.pem --their alice_pub.pem`), then Alice completes using Bob's response PEM.
- `docs/examples/` contains minimal `hello_herradura.{py,c,go}` integration samples.  The Python example shows the `importlib` pattern required because the suite filename contains spaces.

## KaTeX Rendering Rules for Markdown Files

GitHub renders math in `README.md`, `SecurityProofs.md`, and similar files via KaTeX, and the rendering pipeline (markdown/CommonMark first, then KaTeX) has ~11 sharp edges around `_`, `$`, `*`, spacing commands, and a ~750-expression per-page limit that silently breaks math past that threshold.

Before editing any `$...$`/`$$...$$` math span in this repo, read `SecurityProofsCode/KATEX_RULES.md` in full — it documents every rule, the correct-pattern table, and the local validation script (`SecurityProofsCode/validate_katex.js`). Do not guess at KaTeX-safe syntax from general LaTeX knowledge; GitHub's pipeline rejects several constructs that are valid in standalone KaTeX.

## License

Dual-licensed under GPL v3.0 and MIT. Users may choose either.
