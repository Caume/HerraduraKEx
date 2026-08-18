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

