# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Open items

### #204: Research efficiency/security of non-standard (non-multiple-of-8) key lengths

Right now every implementation assumes bit widths that are multiples of 8
(commonly 256), driven by the byte-oriented word types in C/Go/Python and
by `herradura.h`'s fixed-width big-int backing. Investigate whether
FSCX/GF(2^n)* parameters at non-byte-aligned widths (e.g. n=251, n=255,
n=509 — primes or otherwise irregular sizes chosen for algebraic
properties rather than byte convenience) offer a meaningful efficiency
or security advantage over the current byte-aligned defaults:

- **Algebraic analysis**: does choosing n prime (so GF(2^n)* has no small
  subgroup structure beyond the trivial factors of `2^n - 1`) meaningfully
  shrink the Pohlig-Hellman attack surface compared to today's composite
  byte-multiple n? Does FSCX's linear map M = I ⊕ ROL ⊆ ROR's order
  (n/2, or n for odd n where ROL/ROR don't pair up as involutions) change
  the periodic-orbit structure exploited elsewhere in `SecurityProofs-*.md`
  in a way that helps or hurts diffusion? Extend the analyses in
  `SecurityProofsCode/hkex_gf_test.py` and the FSCX_N section of
  `SecurityProofs-1.md` to non-byte-aligned n and document the results.
- **Experimental testing**: benchmark FSCX/GF arithmetic implemented over
  odd/non-byte n (bit-sliced or arbitrary-precision, since word-aligned
  tricks no longer apply) against the current byte-aligned baseline for
  throughput/memory, and run the existing statistical/avalanche test
  batteries (`CryptosuiteTests/Herradura_tests.*`) parameterized at a
  spread of non-standard widths to check whether security margins hold,
  improve, or degrade.
- **Deliverable**: a `SecurityProofsCode/` script (or new `SecurityProofs`
  subsection) presenting the algebraic argument plus measured results,
  and a recommendation on whether non-standard key lengths are worth
  adding as a supported parameter choice in any language target, or
  whether the byte-aligned status quo should stay as-is with the
  analysis documented for the record either way.

This is a research/analysis item, not an implementation commitment — it
should not itself change any wire format, CLI surface, or default
parameter unless its findings justify a follow-up TODO to do so.

Status: **OPEN**

### #207: Independent CI job for a full 4-language (C/Go/Python/Java) crypto compatibility matrix

The existing interop coverage across `CliTest/*.sh` is pairwise-against-
Python, not a full matrix: `test_c_interop.sh` is C↔Python only,
`test_go_interop.sh` is Go↔Python only, and `test_aead.sh` is the one
genuinely multi-way (9-way cross-CLI) script but only for HSKE-NL-AEAD.
There is currently no test proving C and Go are directly compatible on
the rest of the protocol surface (HKEX-GF/HSKE/HPKS/HPKE and the
NL/PQC/Stern/OPRF/HCRED/aPAKE families), and once Java lands in CI
([[#206]]) its own `test_java_*.sh` scripts only check Java against
Python, not against C or Go.

This item tracks proving that the cryptographic algorithms themselves —
key exchange, encryption, signing — interoperate correctly among all
four language implementations, as a concern separate from "does each
language's own build/test suite pass" (which [[#205]] and [[#206]]
already cover).

- Close the C↔Go gap: extend `test_c_interop.sh`/`test_go_interop.sh`
  (or add a new `test_c_go_interop.sh`) so C and Go are checked directly
  against each other, not only each against Python, across every
  `--algo` value and subcommand both CLIs support.
- Build a genuine 4-language compatibility matrix, not pairwise checks
  against one anchor language: for every `--algo`/subcommand combination,
  a key/ciphertext/signature produced by any one of C/Go/Python/Java's
  CLI must be verified consumable by each of the other three (the
  `test_aead.sh` 9-way pattern generalized to the full protocol surface,
  extended to include Java). Add a new `CliTest/test_cross_lang_matrix.sh`
  (or equivalent) rather than folding this into the existing per-language
  interop scripts, so the matrix is one script with clear pass/fail
  reporting per language-pair and per protocol family.
- Confirm `KAT/classical_quartet.json` cross-checks the Java classical
  quartet the same way `KAT/verify_kat.go` cross-checks Go's, as part of
  the same matrix run.
- Add this as its own CI job (e.g. `cross-lang-compat`), independent of
  and running after `native-c`/`native-go`/`native-python`/`native-java`
  (it needs all four CLIs built), required/blocking like the rest.
  Update `CLAUDE.md`'s Testing section and CI job list once landed.

Status: **OPEN**

