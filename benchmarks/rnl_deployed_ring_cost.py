#!/usr/bin/env python3
"""TODO #292: the Python column of the deployed-ring table.

See benchmarks/rnl_deployed_ring_cost.c for why the table exists: both test
harnesses stop at n = 256 while the suite ships RNLN = 1024, so benchmark [40]'s
C column reports a ring TODO #223 retired, and nothing measured the deployed one
in a compiled language at all.

This is NOT benchmarks/rnl_ring_cost.py, which is TODO #225's item and asks a
different question -- where the `native-python` job's time goes, and whether the
`-t` cap truncates RNL call sites (it does not; they are unpollable for an
unrelated reason).  This one measures the shipped suite's own
`_rnl_keygen` / `_rnl_agree` at RNLN so the three languages read one table.

IT GATES, like its siblings: a throughput figure for a key exchange whose two
sides do not agree is not a slow handshake, it is no handshake, so the control
runs first and this exits non-zero before timing anything if it fails.

WHICH NTT PATH -- the number is meaningless without it.  The suite picks numpy
or a pure-Python NTT at import and its startup banner reports which (TODO #225).
The two differ by more than an order of magnitude, so this prints the live path
in its header line and any figure quoted from it must carry that label.

Run:
    python3 benchmarks/rnl_deployed_ring_cost.py
    python3 benchmarks/rnl_deployed_ring_cost.py --iters 5   # faster, noisier

RECORDED (ARM64 SBC, PURE-PYTHON NTT -- no numpy on that host), at v7.0.11,
i.e. AFTER TODO #293:

    keygen (s, C)                        9.78 ms
    agree, reconciler side (+hint)       9.61 ms
    agree, receiver side                 9.48 ms
    _rnl_poly_mul alone (NTT)            9.28 ms
    m_blind derivation (rand+add)        0.59 ms
    full two-party handshake            39.36 ms   (25 /s)

which is 78x the C sibling's 0.505 ms.  That factor is the interpreted NTT and
nothing else: _rnl_poly_mul is 9.28 ms of a 9.61 ms agree, i.e. 97% of it.  On a
host with numpy the same script reports the numpy path and a much smaller
factor -- which is the point of printing the path rather than the figure alone.

The m_blind row carried a finding that was invisible from this column alone.
_rnl_rand_poly called os.urandom(3) once per rejection-sampling draw, ~1028 of
them per polynomial, which was 0.70 ms of its 1.01 ms -- but 1.01 ms against a
39.96 ms handshake is 1.8%, so nothing here would ever have pointed at it.  The
same shape in Go was 40% of a handshake, because there the NTT is fast enough
for it to surface.  TODO #293 buffered all three affected ports and the row is
now 0.59 ms.

READ THAT 1.8% BEFORE CONCLUDING PYTHON DID NOT NEED IT.  The fraction is small
here for one reason -- the NTT above it is the interpreted one -- and the
fraction, not the saving, is what the pure-Python path makes small.  The
ABSOLUTE saving is 0.42 ms on this row and 0.54 ms measured on the sampler
alone, within 7% of Go's 0.58 ms, for the same five-line change.  What the
fraction becomes on a numpy host is NOT recorded here, because this host has no
numpy and a Python RNL figure without a live path label is not a figure -- the
one rule this file exists to enforce.  #293 buffered Python on the absolute
saving and on the fact that a three-way split in sampling strategy is invisible
to every checker in the repo (spec/check_language_parity.py compares declared
constants and primitive presence, not read patterns), not on a projection.

USE --iters, and here is why it exists.  A first draft timed with 10 iterations
and reported keygen at 25.2 ms against poly_mul's 9.4, which is impossible --
a keygen is one poly_mul plus sampling and rounding.  The excess was one-off
setup amortised over too few runs.  At the default it disappears (9.78 against
9.32) and the row is consistent with the rest of the table.  A benchmark whose
parts do not add up is reporting its own warm-up; check the arithmetic before
quoting any row here.
"""

import argparse
import importlib.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_SUITE = os.path.join(_HERE, "..", "Herradura cryptographic suite.py")

BENCH_SECS = 2.0
CONTROL_ITERS = 5


def _load_suite():
    """Load the space-named suite file (the importlib pattern of docs/examples)."""
    spec = importlib.util.spec_from_file_location("herradura_suite", _SUITE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bench(label, fn, min_iters):
    ops = 0
    t0 = time.perf_counter()
    while True:
        fn()
        ops += 1
        secs = time.perf_counter() - t0
        if secs >= BENCH_SECS and ops >= min_iters:
            break
    print("  %-34s %8.3f ms   %9.1f /s" % (label, 1000 * secs / ops, ops / secs))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iters", type=int, default=3,
                    help="minimum iterations per row (default 3); the pure-Python "
                         "NTT path is slow enough that BENCH_SECS alone would give 1")
    args = ap.parse_args()

    h = _load_suite()
    n, q, p, pp, eta = h.RNLN, h.RNLQ, h.RNLP, h.RNLPP, h.RNLB
    key_bits = h.KEYBITS
    path = "numpy" if h._NUMPY else "pure-Python"

    print("HKEX-RNL at the DEPLOYED ring -- RNLN=%d q=%d p=%d eta=%d, "
          "session key %d bits" % (n, q, p, eta, key_bits))
    print("  NTT path: %s   (TODO #225 -- a figure without this label is not a figure)"
          % path)

    m_base = h._rnl_m_poly(n)
    m_blind = h._rnl_poly_add(m_base, h._rnl_rand_poly(n, q), q)

    disagreed = 0
    for _ in range(CONTROL_ITERS):
        s_a, c_a = h._rnl_keygen(m_blind, n, q, p, eta)
        s_b, c_b = h._rnl_keygen(m_blind, n, q, p, eta)
        k_a, hint = h._rnl_agree(s_a, c_b, q, p, pp, n, key_bits)
        k_b = h._rnl_agree(s_b, c_a, q, p, pp, n, key_bits, hint)
        if k_a.uint != k_b.uint:
            disagreed += 1
    print("  control: %d/%d handshakes reconcile to the same key%s\n"
          % (CONTROL_ITERS - disagreed, CONTROL_ITERS,
             "  <-- FAIL" if disagreed else ""))
    if disagreed:
        print("*** FAILED: %d of %d handshakes disagreed at the deployed ring "
              "-- timing not run ***" % (disagreed, CONTROL_ITERS), file=sys.stderr)
        return 1

    k = args.iters
    _bench("keygen (s, C)", lambda: h._rnl_keygen(m_blind, n, q, p, eta), k)
    _bench("agree, reconciler (+hint)",
           lambda: h._rnl_agree(s_a, c_b, q, p, pp, n, key_bits), k)
    _bench("agree, receiver",
           lambda: h._rnl_agree(s_b, c_a, q, p, pp, n, key_bits, hint), k)
    _bench("_rnl_poly_mul alone (NTT)", lambda: h._rnl_poly_mul(m_blind, s_a, q, n), k)
    _bench("m_blind derivation (rand+add)",
           lambda: h._rnl_poly_add(m_base, h._rnl_rand_poly(n, q), q), k)

    def handshake():
        mb = h._rnl_poly_add(m_base, h._rnl_rand_poly(n, q), q)
        sa, ca = h._rnl_keygen(mb, n, q, p, eta)
        sb, cb = h._rnl_keygen(mb, n, q, p, eta)
        _, hh = h._rnl_agree(sa, cb, q, p, pp, n, key_bits)
        h._rnl_agree(sb, ca, q, p, pp, n, key_bits, hh)

    _bench("full two-party handshake", handshake, k)

    print("\n  CryptosuiteTests/Herradura_tests.py's RNL_SIZES stops at 256, the "
          "RETIRED\n  ring; it cannot follow the suite to 1024 for TODO #225's "
          "reason (one\n  variable serves as both ring dimension and key width).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
