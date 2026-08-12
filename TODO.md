# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### #188: Add sanitizer/CI hardening (ASan/UBSan/valgrind)

CI runs the build+test matrix but never compiles/runs the C suite,
tests, or CLI under AddressSanitizer, UndefinedBehaviorSanitizer, or
valgrind. Given the manual constant-time auditing already done (TODO
#182), an automated sanitizer job would catch memory-safety and UB
issues that manual review can't, and is standard practice in comparable
C crypto projects (libsodium, BLAKE3, OpenSSL). Add a CI job (or local
build-script variant) that builds with `-fsanitize=address,undefined`
and runs the security tests, and/or a valgrind pass.

Status: **OPEN**

### #189: Add CodeQL / static-analysis workflow

No static-analysis workflow exists for the C/Go/Python sources. Add a
GitHub CodeQL workflow (free for public repos) covering C and Go at
minimum, and a Python linter/analyzer pass if useful, wired into
`.github/workflows/`.

Status: **OPEN**

### #190: Publish fixed KAT (Known-Answer-Test) vector files

`CliTest/test_vectors.sh` exercises key-agreement correctness but there
is no standalone, versioned Known-Answer-Test vector file (JSON/CSV, in
the style of NIST CAVP `.rsp` files) that a third-party reimplementation
could use to cross-validate against this suite's outputs independent of
this repo's own test harness. Add a `KAT/` (or similar) directory with
fixed input/output vectors for HKEX-GF, HSKE, HPKS, HPKE, and the NL/PQC
variants, generated from the reference implementation and checked into
the repo.

Status: **OPEN**

### #191: Package-manager publishing (PyPI, Go module tagging, etc.)

There is no `pyproject.toml`/`setup.py` for the Python suite/CLI, so
`pip install herradurakex` isn't possible — users must clone and run
from source. Add packaging metadata for PyPI at minimum, and consider
signed/tagged Go module releases so `go get` resolves versioned tags
rather than only `master`.

Status: **OPEN**

### #192: Java bindings

The suite has implementations/bindings spanning C, Go, Python, ARM
Thumb-2, NASM i386, and Arduino, plus a ctypes/cgo FFI layer
(`bindings/ffi/`), but no Java binding — a common target for users
integrating a crypto library into JVM-based applications. Evaluate JNI
(around `herradura.h`) or a pure-Java port, following the pattern
established by `bindings/ffi/`.

Status: **OPEN**

### #193: RFC-style prose spec document

`spec/herradura-protocol-spec.json` is a machine-readable JSON Schema
(parameters, PEM labels, CLI `--algo` tags, security-level
classification) but there is no prose specification document
independent of any implementation, in the style of the Noise Protocol
Framework or the `age` spec, that would let a third party reimplement
the protocols from the spec alone rather than by reading source code.
Draft an RFC-style `SPEC.md` (or similar) covering HKEX-GF, HSKE, HPKS,
HPKE, and the NL/PQC/Stern variants.

Status: **OPEN**

### #194: Comparison/benchmark against standard primitives

`benchmarks/` records HerraduraKEx's own performance history but has no
head-to-head comparison against standard, widely-deployed primitives
(Curve25519/X25519, AES-GCM, ChaCha20-Poly1305, Kyber/ML-KEM,
Dilithium/ML-DSA — the latter two already partially covered by
`benchmarks/compare_stern_f_dilithium.py`, see TODO #186). Add
benchmark scripts/results comparing HKEX-GF/HKEX-RNL, HSKE, HPKS/HPKS-NL
and HPKE/HPKE-NL against their closest standard-primitive equivalents,
to give adopters real performance context for the novel constructions.

Status: **OPEN**

### #187: Run fuzz harnesses under a real engine and record coverage

`Fuzz/` has libFuzzer-style harnesses (b64/DER/PEM decode) and Python
harnesses (CLI args, codec) but no on-record run history or coverage
report — TODO #130 built the harnesses but didn't close the loop on
actually fuzzing with them. Run `Fuzz/run_fuzz.sh` for a fixed time
budget, record findings and coverage in `Fuzz/README.md`, and consider
wiring a short smoke-fuzz job into CI.

Status: **OPEN**
