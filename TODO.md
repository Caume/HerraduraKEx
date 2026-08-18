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
- TODO #201 — OPRF and the stateful hash-based signatures (HPKS-WOTS-F,
  HPKS-XMSS-F) + CLI subcommands + interop tests (needs #198)
- TODO #202 — HCRED, the hybrid Ring-LWR + Stern-F credential (needs
  #198, #200 for the Stern-F building blocks it reuses)
- TODO #203 — aPAKE, augmented PAKE over HKEX-RNL + a ZKBoo-over-NL-FSCX
  gadget + OPRF (needs #198, #199, #201's OPRF)

Close this umbrella once #197–#203 are all done.

Status: **OPEN**

### #203: Java port of aPAKE (augmented PAKE over HKEX-RNL + OPRF + ZKBoo-NL)

Split off from #201. Needs a Java port of the ZKBoo-over-NL-FSCX Sigma
protocol (`zkp_nl_prove`/`zkp_nl_verify` in
`"Herradura cryptographic suite.py"` — a bit-level 3-party MPC circuit
proving knowledge of `A` such that `nl_fscx_v1(A, B) = y`, used here as
the aPAKE's mutual-authentication proof bound to the HKEX-RNL session
key) plus TODO #201's OPRF (the server's password record is
`hfscx_256(OPRF(k_s, password) + salt)` rather than a plain password
hash, closing offline dictionary attacks against a leaked server
database). Extend `bindings/java/herradurakex` with `hpake_register`/
`hpake_login_demo`'s three-message flow (or the CLI's split
register/login subcommands, matching whichever the Python/C/Go CLIs
expose). No dedicated KAT exists upstream for this protocol — coverage
comes from CLI round-trip tests (correct/wrong password, cross-language
interop) mirroring `CliTest/test_oprf.sh`/`test_pake.sh`'s pattern. Per
the suite's own documentation this is a research-grade construction (no
formal UC/SIM-BMP proof) — treat and document it as such, not as a
hardened production aPAKE.

Status: **OPEN**

