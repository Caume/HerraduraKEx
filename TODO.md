# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

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

