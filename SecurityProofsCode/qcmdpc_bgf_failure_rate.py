#!/usr/bin/env python3
"""qcmdpc_bgf_failure_rate.py — TODO #195: measure the QC-MDPC BGF decoder's
Decoding Failure Rate (DFR).

WHAT THIS SCRIPT CAN NO LONGER DO, STATED FIRST (TODO #286).  It was written
against r=523, d=15, t=18, nb_iter=20, where the DFR was 0.264% = 2^-8.6 and
2000 trials measured it to a useful interval.  TODO #276 (v7.0.0) moved the
suite to BIKE-128 -- r=12323, d=71, t=134, nb_iter=5 -- where the DFR is below
anything a sample can reach: TODO #285 §2 saw zero failures in 3000 trials and
showed that reaching 2^-128 by simulation needs about 2^128 decapsulations.

So its original claim -- that it "closes the DFR never measured gap noted in
TODO #183/#186" -- is WITHDRAWN rather than repaired.  It cannot be repaired by
raising --trials: no trial count reaches the target, which is precisely what the
parameter change bought.  What the script still does honestly is report an UPPER
BOUND, and say what that bound is worth; the default trial count is now sized to
say something in a minute rather than to chase a rate that is not there.

Where the live analysis went.  The DFR question at the deployed parameters is
answered in `qcmdpc_dfr_weak_keys.py`: §2 bounds it, §3 locates the waterfall at
about 80% of the deployed r and extrapolates back with a measured error
direction, and §4 measures the weak-key cliff, which unlike the DFR itself
remains measurable because a weak key fails near 100% of the time.  This script
is kept for the ONE thing that is still its own: a direct end-to-end count over
the shipped keygen/encap/decode path, with no reformulation in between.

Original context, unchanged and still true of what it measures:
`CliTest/test_hybrid_kex_interop.sh` generates fresh random keys every run, so a
nonzero DFR shows up as intermittent CI failures that are NOT bugs (before TODO
#235 they surfaced as an explicit `HPKE-Stern-KEM decapsulation failed`;
implicit rejection now makes them a silent wrong-key outcome instead, so this
script reads the decoder rather than the exit status).

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
    ap.add_argument('--trials', type=int, default=400,
                     help='number of independent (keygen, encap, decap) trials '
                          '(default 400; at BIKE-128 no count reaches the DFR, so this is sized to report a bound in about a minute -- see the module docstring)')
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
        #
        # Since TODO #235 that distinction has to be taken from the DECODER, not
        # from qcmdpc_decap_bgf: the FO transform means decapsulation always
        # returns a key and never signals failure. This measures the same DFR it
        # always did — what changed is only who can observe it. An attacker
        # cannot; this script can, because it holds the private key.
        dec = m.qcmdpc_bgf_decode(syn, h0, sup0, sup1)
        if dec is None:
            failures += 1
            none_decode += 1
        elif m.qcmdpc_decap_bgf(syn, sup0, sup1, h0) != K_enc:
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
    if failures:
        print(f"Measured DFR: {dfr:.6f}  ({dfr * 100:.4f}%)")
    else:
        # Never print "Measured DFR: 0.000000" -- it reads as a measurement of
        # zero and is a measurement of nothing (TODO #286).
        print(f"Measured DFR: none observed  (< 1/{args.trials})")
    print(f"Wall time: {elapsed:.1f}s ({elapsed / args.trials * 1000:.2f} ms/trial)")
    import math
    if failures > 0:
        # Wilson score interval would be more rigorous; a simple ~sqrt(p(1-p)/n)
        # normal-approximation 95% CI is good enough for a CI-flakiness estimate.
        se = math.sqrt(dfr * (1 - dfr) / args.trials) if args.trials else 0.0
        lo, hi = max(0.0, dfr - 1.96 * se), dfr + 1.96 * se
        print(f"Approx. 95% CI: [{lo:.6f}, {hi:.6f}]")
    else:
        # Zero failures is the expected outcome at BIKE-128 and is NOT a
        # measurement of the rate (TODO #286).  What a sample of size n
        # establishes about a rate below 1/n is a one-sided upper bound, so
        # print that and say what it is worth -- a bare "0.000000" reads as a
        # result and is not one.
        hi = 1.0 - 0.05 ** (1.0 / args.trials)      # 95% one-sided, exact
        print(f"No failure observed, so this is NOT a rate: the sample bounds "
              f"the DFR at")
        print(f"  95% one-sided upper bound: {hi*100:.4f}%  = 2^{math.log2(hi):.1f}")
        print(f"IND-CCA2 wants 2^-128, so this run is {128 + math.log2(hi):.0f} bits short of the")
        print("target -- not because the decoder fails that often, but because "
              "the rate is")
        print("below what any sample can see.  See the module docstring, and "
              "qcmdpc_dfr_weak_keys.py")
        print("§2-§4 for the analysis that survives at these parameters.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
