# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

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

