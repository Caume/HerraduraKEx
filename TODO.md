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

### #195: QC-MDPC BGF decoder DFR causes intermittent CI failures in hybrid-KEM interop test

`CliTest/test_hybrid_kex_interop.sh` generates fresh random keys on every
run (no fixed seed) and exercises `hpke-stern-kem` (real Black-Gray-Flip
QC-MDPC decoder, TODO #183) across all C/Go/Python CLI combinations. The
decoder's Decoding Failure Rate (DFR) at its current toy parameters
(r=523, d=15, t=18) has never been measured (noted as an open gap when
the real decoder landed in TODO #183/#186) — so a small but nonzero
fraction of runs hit a genuine decode failure rather than a bug,
surfacing as `HPKE-Stern-KEM decapsulation failed (DFR event or corrupt
ciphertext)`. Observed 2026-08-15: the `push`-triggered CI run for
commit 91a00ee failed on 3 `bob=c` sub-cases while the `pull_request`-
triggered run for the same commit passed cleanly — same code, different
random draws, confirming this is decoder DFR flakiness rather than a
regression (see PR #192 discussion).

Fix options to evaluate: (a) measure the actual DFR at current
parameters and, if too high for a CI test to tolerate, tune parameters
(r/d/t) to push it low enough that intermittent CI failures become
practically impossible; (b) add a small bounded retry in the test for
this specific, identified error string, since DFR events are an
expected (if rare) protocol outcome, not silently masking real bugs;
(c) both — measure to confirm the retry bound is justified, then add
retry as defense-in-depth. Whichever approach lands should also update
the "DFR not yet measured" note in `TODO_DONE.md` (TODO #183/#186) and
`spec/herradura-protocol-spec.json`'s `hpke-stern-kem` notes field.

Status: **OPEN**

### #196: Extend the Java port to a complete suite + CLI (beyond the classical quartet)

TODO #192 added `bindings/java/herradurakex.Herradura`, a pure-Java port
of only the classical (v1.4.0) quartet (HKEX-GF, HSKE, HPKS, HPKE),
matching `bindings/ffi/`'s intentionally narrow scope. The other five
language targets (C, Go, Python, ARM Thumb-2, NASM i386, Arduino) all
implement the full suite — NL/PQC (HKEX-RNL, HSKE-NL-A1/A2, HPKS-NL,
HPKE-NL), Stern-F/Niederreiter (HPKS-Stern-F, HPKE-Stern-F,
HPKE-Stern-KEM with the real BGF QC-MDPC decoder), HCRED, OPRF/aPAKE,
XMSS/WOTS+, etc. — plus a `HerraduraCli`-equivalent OpenSSL-style CLI
(`genpkey`/`pkey`/`kex`/`enc`/`dec`/`sign`/`verify`/`dgst`/`encfile`/
`decfile`) with PEM/DER codec support matching `HerraduraCli/codec.py`
/`herradura_codec.h`/`herradura/codec.go` byte-for-byte.

Scope for this item: extend `bindings/java/herradurakex` from a
quartet-only library into a complete port — every protocol variant the
other language targets implement, a Java `HerraduraCli` mirroring the
existing three (`genpkey`, `pkey`, `kex`, `enc`, `dec`, `sign`, `verify`,
`dgst`, `encfile`, `decfile`), and a PEM/DER codec compatible with the
existing wire format so keys/ciphertexts/signatures produced by any
implementation are byte-for-byte interchangeable with the Java one (per
CLAUDE.md's `HerraduraCli` cross-compatibility guarantee). Cross-verify
against `KAT/classical_quartet.json` (extend the KAT set to the NL/PQC
variants per TODO #190's deferred follow-up, if that lands first) and
add `CliTest/test_java_*.sh` / `test_java_interop.sh` scripts mirroring
the C/Go CLI test pattern.

Status: **OPEN**

