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

### #196: Extend the Java port to a complete suite + CLI (umbrella)

TODO #192 added `bindings/java/herradurakex.Herradura`, a pure-Java port
of only the classical (v1.4.0) quartet (HKEX-GF, HSKE, HPKS, HPKE),
matching `bindings/ffi/`'s intentionally narrow scope. The other five
language targets (C, Go, Python, ARM Thumb-2, NASM i386, Arduino) all
implement the full suite — NL/PQC, Stern-F/Niederreiter, HCRED,
OPRF/aPAKE, XMSS/WOTS+, etc. — plus a `HerraduraCli`-equivalent
OpenSSL-style CLI with PEM/DER codec support matching
`HerraduraCli/codec.py`/`herradura_codec.h`/`herradura/codec.go`
byte-for-byte.

This item is an umbrella tracking the full gap; broken down into
sequential, independently-completable child items so a session can pick
off one milestone at a time rather than attempting the whole surface at
once. Complete in roughly this order (each depends on the codec landing
before the CLI, and on the protocol ports landing before their CLI
subcommands/interop tests):

- TODO #197 — PEM/DER codec (classical quartet's wire format)
- TODO #198 — Java `HerraduraCli` for the classical quartet (needs #197)
- TODO #199 — NL/PQC port (HKEX-RNL, HSKE-NL-A1/A2, HPKS-NL, HPKE-NL) +
  CLI subcommands + interop tests (needs #198)
- TODO #200 — Stern-F/Niederreiter port (HPKS-Stern-F, HPKE-Stern-F,
  HPKE-Stern-KEM with the real BGF QC-MDPC decoder) + CLI subcommands +
  interop tests (needs #198)
- TODO #201 — remaining advanced protocols (HCRED, OPRF/aPAKE,
  XMSS/WOTS+) + CLI subcommands + interop tests (needs #198)

Close this umbrella once #197–#201 are all done.

Status: **OPEN**

### #198: Java `HerraduraCli` for the classical quartet

Part of the #196 breakdown; needs TODO #197 (PEM/DER codec) first. Add
a Java CLI mirroring `HerraduraCli/herradura.py`/`herradura_cli.c`/
`herradura_cli.go`'s subcommand interface — `genpkey`, `pkey`, `kex`,
`enc`, `dec`, `sign`, `verify`, `dgst`, `encfile`, `decfile` — for the
classical quartet (`hkex-gf`, `hpks`, `hpke` `--algo` values). Add
`CliTest/test_java_keygen.sh`/`test_java_interop.sh` (Python-generated
keys consumed by the Java CLI and vice versa), mirroring
`test_c_interop.sh`/`test_go_interop.sh`'s pattern.

Status: **OPEN**

### #199: Java port of NL/PQC quartet (HKEX-RNL, HSKE-NL, HPKS-NL, HPKE-NL)

Part of the #196 breakdown; needs TODO #198 (CLI skeleton) for its
`--algo` subcommand wiring, though the library-level primitives (NL-FSCX
v1/v2, Ring-LWR) can be ported independently first. Extend
`bindings/java/herradurakex` with HKEX-RNL, HSKE-NL-A1/A2, HPKS-NL, and
HPKE-NL, plus their CLI subcommands and Python/C/Go interop tests. If
TODO #190's KAT set has grown to cover NL/PQC vectors by then, cross-
verify against those; otherwise cross-verify against the Go/Python
suites directly (mirroring `KAT/verify_kat.go`'s approach).

Status: **OPEN**

### #200: Java port of Stern-F/Niederreiter (HPKS-Stern-F, HPKE-Stern-F, HPKE-Stern-KEM)

Part of the #196 breakdown; needs TODO #198. Extend
`bindings/java/herradurakex` with the Stern identification protocol
(Fiat-Shamir signature) and Niederreiter KEM, including the real BGF
QC-MDPC decoder (`qcmdpc_keygen`/`encap`/`decap_bgf`, TODO #183) for
`hpke-stern-kem` — not just the demo `hpke-stern` path. Note TODO #195's
still-open QC-MDPC DFR flakiness when writing interop tests: a fresh
random run can legitimately hit a decode failure, so tests should expect
that rather than treating every failure as a bug. Add CLI subcommands
and interop tests.

Status: **OPEN**

### #201: Java port of remaining advanced protocols (HCRED, OPRF/aPAKE, XMSS/WOTS+)

Part of the #196 breakdown; needs TODO #198. Extend
`bindings/java/herradurakex` with the hybrid Ring-LWR + Stern-F
credential (HCRED), OPRF/aPAKE, and the stateful hash-based signatures
(XMSS/WOTS+). These are the suite's most complex remaining protocols
(MPCitH transcripts, tree-based state management for XMSS) — expect this
to be the largest of the child items; consider splitting further once
scoped in detail. Add CLI subcommands and interop tests.

Status: **OPEN**

