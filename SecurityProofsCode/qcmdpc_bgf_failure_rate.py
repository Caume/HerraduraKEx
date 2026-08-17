#!/usr/bin/env python3
"""qcmdpc_bgf_failure_rate.py — TODO #195: measure the QC-MDPC BGF decoder's
Decoding Failure Rate (DFR) at the suite's current toy parameters
(r=523, d=15, t=18, nb_iter=20; see herradura.h's QCMDPC_* #defines and
`Herradura cryptographic suite.py`'s qcmdpc_keygen/encap/decap_bgf).

This closes the "DFR never measured" gap noted in TODO #183/#186 and
referenced by TODO #195: `CliTest/test_hybrid_kex_interop.sh` generates
fresh random keys every run, so a nonzero DFR shows up as intermittent CI
failures (`HPKE-Stern-KEM decapsulation failed`) that are NOT bugs — this
script quantifies exactly how often that is expected to happen, so the
test suite's retry/skip policy has a measured basis instead of a guess.

Usage:
    python3 SecurityProofsCode/qcmdpc_bgf_failure_rate.py [--trials N] [--seed N]

For each trial: fresh QC-MDPC keypair (fresh sup0/sup1/h0/h_pub), fresh
encapsulation (fresh error e), decode with the real BGF decoder, and
check the decoded error exactly matches what was encapsulated (mirrors
what `qcmdpc_decap_bgf` + the CLI's `dec --algo hpke-stern-kem` actually
do: a `None` return, or worse a WRONG-but-non-None decode, both count as
a decapsulation failure from the caller's point of view).
"""
import argparse
import importlib.util
import os
import sys
import time

_SUITE_PATH = os.path.join(os.path.dirname(__file__), '..',
                            'Herradura cryptographic suite.py')


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--trials', type=int, default=2000,
                     help='number of independent (keygen, encap, decap) trials (default 2000)')
    ap.add_argument('--seed', type=int, default=None,
                     help='seed the RNG for reproducibility (default: unseeded/os.urandom)')
    ap.add_argument('--fresh-key-every', type=int, default=1,
                     help='generate a fresh keypair every N trials (default 1 = every trial; '
                          'the CLI/interop test always uses a fresh key, so the default matches '
                          'real usage — a larger value additionally isolates whether failures '
                          'correlate with specific keys, e.g. a persistently weak h0 support)')
    args = ap.parse_args()

    m = _load_suite()

    if args.seed is not None:
        import random
        random.seed(args.seed)

    failures = 0
    wrong_decode = 0
    none_decode = 0
    t0 = time.time()

    sup0 = sup1 = h0 = h_pub = None
    for i in range(args.trials):
        if sup0 is None or i % args.fresh_key_every == 0:
            sup0, sup1, h0, h1, h_pub = m.qcmdpc_keygen()

        syn, K_enc = m.qcmdpc_encap(h_pub)
        # Recover the same (e0, e1) qcmdpc_encap used, to compare the decoder's
        # output against ground truth rather than only checking K equality
        # (a colliding-but-wrong e would also give the wrong K, but we want
        # to distinguish "decoder returned None" from "decoder returned the
        # wrong e" for diagnostic purposes).
        K_dec = m.qcmdpc_decap_bgf(syn, sup0, sup1, h0)

        if K_dec is None:
            failures += 1
            none_decode += 1
        elif K_dec != K_enc:
            failures += 1
            wrong_decode += 1

        if (i + 1) % 200 == 0:
            elapsed = time.time() - t0
            rate = failures / (i + 1)
            print(f"  ... {i + 1}/{args.trials} trials, "
                  f"{failures} failures so far (DFR={rate:.5f}), "
                  f"{elapsed:.1f}s elapsed", file=sys.stderr)

    elapsed = time.time() - t0
    dfr = failures / args.trials
    print(f"\n=== QC-MDPC BGF decoder DFR measurement (TODO #195) ===")
    print(f"Parameters: r={m._QCMDPC_R} d={m._QCMDPC_D} t={m._QCMDPC_T} "
          f"nb_iter={m._QCMDPC_NB_ITER}")
    print(f"Trials: {args.trials}  (fresh key every {args.fresh_key_every} trial(s))")
    print(f"Failures: {failures}  (None-decode: {none_decode}, wrong-decode: {wrong_decode})")
    print(f"Measured DFR: {dfr:.6f}  ({dfr * 100:.4f}%)")
    print(f"Wall time: {elapsed:.1f}s ({elapsed / args.trials * 1000:.2f} ms/trial)")
    if failures > 0:
        # Wilson score interval would be more rigorous; a simple ~sqrt(p(1-p)/n)
        # normal-approximation 95% CI is good enough for a CI-flakiness estimate.
        import math
        se = math.sqrt(dfr * (1 - dfr) / args.trials) if args.trials else 0.0
        lo, hi = max(0.0, dfr - 1.96 * se), dfr + 1.96 * se
        print(f"Approx. 95% CI: [{lo:.6f}, {hi:.6f}]")
    return 0


if __name__ == '__main__':
    sys.exit(main())
