#!/usr/bin/env python3
"""
qcmdpc_dfr_weak_keys.py — DFR, weak keys, and reaction attacks against
HPKE-Stern-KEM's QC-MDPC BGF decoder (TODO #218, §11.8.6).

TODO #195/#221 treat BGF decoding failures as CI flakiness.  This is the security
half of the same fact.  For a KEM, IND-CCA2 needs DFR <= 2^-lambda, and any
*observable* failure exposes the GJS reaction attack [Guo-Johansson-Stankovski
2016]: submit crafted ciphertexts, watch which ones fail, reconstruct the private
key's distance spectrum.

  §1  The shipped decoder vs. an independent per-position reference
  §2  DFR at the deployed parameters — what a sample can and cannot say
  §3  DFR(r) at the deployed (d, t), and which way the extrapolation errs
  §4  Weak keys — distance-spectrum multiplicity vs. DFR, and the cliff
  §5  GJS reaction attack — the distinguisher, at a reachable instance
  §6  Failure signalling: is the oracle actually reachable?
  §7  Verdict and the SECURITY.md row

Deployed parameters, read from the suite rather than written here: BIKE-128's
r = 12323, d = 71, t = 134, NB_ITER = 5, adopted verbatim together with BIKE's
decoder by TODO #276.  They replaced a toy r = 523, d = 15, t = 18.

WHAT TODO #276 DID TO THIS SCRIPT (TODO #285).  Every section below was written
at the toy set, and the parameter change split them in two.  §2 and §3 measured
a DFR of 2^-8.6 and fitted a curve through it; at BIKE-128 that rate is not
observable at any sample size, which is what the change bought, so §2 now
reports a BOUND and says plainly that the deployed claim is inherited from
BIKE, and §3 inverts — it holds the deployed (d, t) and comes DOWN from r until
the waterfall is reachable, which it is at about 80% of the deployed r, then
extrapolates back.  §4 and §5, by contrast, survive intact, and for a reason
worth knowing: both are about the SHAPE of the failure rate rather than its
size.  A weak key fails near 100% of the time, so §4 measures the cliff at the
deployed parameters directly and finds it has moved from multiplicity 6-7 to
about 31-34 -- which re-derives the constant #276 had to record on a stated
retry budget.  §5 needs two observable rates to difference, so it moves to §3's
reachable instance.

The script also no longer carries its own decoder.  It had one because the
shipped decoder was per-position and too slow for these sample sizes; #276 made
the shipped one bit-sliced, so the twin bought nothing and had already diverged
twice (four bitplanes, valid only at d <= 15, and the pre-#276 threshold rule).
§1 now pins the shipped decoder against a per-position REFERENCE instead.

Runtime: ~15 min at default settings, ~3.5 min under --quick (measured: 926 s
and 208 s).  --quick cuts every sample count and is enough to reproduce every
qualitative finding, but not §5's disjoint intervals -- they overlap at that
sample size, which is a statement about the sample and not about the attack.
CI runs --quick (TODO #285); the numbers quoted in SecurityProofs-5.md §11.8.7
are from a default run.
Exits non-zero if a finding stops reproducing.
"""

import argparse
import contextlib
import importlib.util
import math
import os
import random
import sys
import time
from collections import Counter


# ── Load suite via importlib (suite filename has a space) ──────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SPEC = importlib.util.spec_from_file_location(
    's', os.path.join(_ROOT, 'Herradura cryptographic suite.py'))
_SUITE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SUITE)

# Read from the suite, never written here — TODO #276 moved all four and the
# comments that used to name their values went stale in place.
R_DEP  = _SUITE._QCMDPC_R          # 12323
D_DEP  = _SUITE._QCMDPC_D          # 71
T_DEP  = _SUITE._QCMDPC_T          # 134
NB_DEP = _SUITE._QCMDPC_NB_ITER    # 5

SEP  = "═" * 74
SEP2 = "─" * 74


# ═══════════════════════════════════════════════════════════════════════════
# The decoder under measurement, and an independent reference for it
#
# Until TODO #285 this script carried its own bit-sliced BGF decoder, because
# the SHIPPED one was per-position and ~40x slower than the measurements here
# need.  TODO #276 removed that reason: qcmdpc_bgf_decode is itself bit-sliced
# now, and one decapsulation at the deployed r = 12323 costs about 10 ms here
# against the 6.0 s the per-position version takes (both measured in §1).
#
# So the twin is gone rather than plane-sized.  A second copy of a decoder is a
# place for a divergence to hide -- it is the reason §1 had to exist at all --
# and this copy had in fact diverged twice over: four fixed bitplanes (correct
# only at d <= 15, and #276 moved d to 71) AND the pre-#276 threshold schedule,
# a constant in d where the deployed rule is affine in the SYNDROME WEIGHT.
# Every section below measures the function that ships.
#
# What §1 pins is therefore no longer a twin against the deployed decoder, but
# the deployed BIT-SLICED decoder against a per-position REFERENCE written here
# -- an independent opinion about the same specification, in the representation
# the suite moved away from.
# ═══════════════════════════════════════════════════════════════════════════

@contextlib.contextmanager
def at_params(r, d, nb_iter=None):
    """Point the suite's decoder at another (r, d, NB_ITER).

    qcmdpc_bgf_decode reads its parameters from suite module scope, so this is
    how one aims it at a non-deployed instance -- §3 varies r, §5 works at the
    reachable waterfall.  The threshold constants are deliberately NOT swapped:
    QCMDPC_TH_SLOPE/OFFSET/MIN and QCMDPC_TAU are BIKE Level 1's rule, and the
    rule is part of what is being measured.
    """
    saved = (_SUITE._QCMDPC_R, _SUITE._QCMDPC_D, _SUITE._QCMDPC_NB_ITER)
    _SUITE._QCMDPC_R = r
    _SUITE._QCMDPC_D = d
    if nb_iter is not None:
        _SUITE._QCMDPC_NB_ITER = nb_iter
    try:
        yield
    finally:
        (_SUITE._QCMDPC_R, _SUITE._QCMDPC_D,
         _SUITE._QCMDPC_NB_ITER) = saved


def decode(syn_pub, sup0, sup1, h0):
    """The shipped decoder, at whatever at_params() currently says."""
    return _SUITE.qcmdpc_bgf_decode(syn_pub, h0, set(sup0), set(sup1))


def ref_decode(syn_pub, sup0, sup1, r, d, nb_iter):
    """Per-position BGF reference — the same decoder without bitplanes.

    Counters are interpreted popcounts over one position at a time, which is
    the representation the suite used before TODO #276 and is what makes this
    an independent check rather than a restatement.  Same threshold rule (BIKE
    L1, affine in the syndrome weight), same tau-wide gray band, same
    iteration-0 second pass at the masked-pass floor.  About 600x slower than
    the shipped decoder at the deployed parameters, so §1 uses it sparingly.
    """
    full = (1 << r) - 1

    def rol(x, k):
        return x if k == 0 else ((x << k) | (x >> (r - k))) & full

    def counts(s, sup):
        """Unsatisfied-parity count per position, one position at a time."""
        out = [0] * r
        for k in sup:
            v = rol(s, r - k) if k else s      # right-rotate by k
            while v:
                b = (v & -v).bit_length() - 1
                out[b] += 1
                v &= v - 1
        return out

    s = 0
    for k in sup0:
        s ^= rol(syn_pub, k)
    e0 = e1 = 0
    th_floor = (d + 1) // 2 + 1
    tau = _SUITE._QCMDPC_TAU

    for it in range(nb_iter):
        if s == 0:
            break
        th = max(int(_SUITE._QCMDPC_TH_SLOPE * bin(s).count('1')
                     + _SUITE._QCMDPC_TH_OFFSET), _SUITE._QCMDPC_TH_MIN)
        c0, c1 = counts(s, sup0), counts(s, sup1)
        b0 = [j for j in range(r) if c0[j] >= th]
        b1 = [j for j in range(r) if c1[j] >= th]
        g0 = [j for j in range(r) if th - tau <= c0[j] < th]
        g1 = [j for j in range(r) if th - tau <= c1[j] < th]
        for j in b0:
            e0 ^= 1 << j
            for k in sup0:
                s ^= 1 << ((j + k) % r)
        for j in b1:
            e1 ^= 1 << j
            for k in sup1:
                s ^= 1 << ((j + k) % r)
        if it == 0:
            for gr0, gr1 in ((b0, b1), (g0, g1)):
                f0, f1 = counts(s, sup0), counts(s, sup1)
                for j in gr0:
                    if f0[j] >= th_floor:
                        e0 ^= 1 << j
                        for k in sup0:
                            s ^= 1 << ((j + k) % r)
                for j in gr1:
                    if f1[j] >= th_floor:
                        e1 ^= 1 << j
                        for k in sup1:
                            s ^= 1 << ((j + k) % r)
    return (e0, e1) if s == 0 else None


# ── instance generation (independent of the suite PRF, so r can vary) ──────
def _inv_poly(h, r):
    """h^-1 mod (x^r - 1); None if not invertible."""
    a, b = (1 << r) | 1, h
    u0, u1 = 0, 1
    while b:
        da, db = a.bit_length() - 1, b.bit_length() - 1
        if da < db:
            a, b = b, a
            u0, u1 = u1, u0
            da, db = db, da
        sh = da - db
        a ^= b << sh
        u0 ^= u1 << sh
    if a != 1:
        return None
    for i in range(r, u0.bit_length()):
        if (u0 >> i) & 1:
            u0 ^= (1 << i) ^ (1 << (i - r))
    return u0


def _mul_poly(a, b, r):
    full = (1 << r) - 1
    acc = 0
    while b:
        j = (b & -b).bit_length() - 1
        b &= b - 1
        acc ^= ((a << j) | (a >> (r - j))) & full
    return acc


def keygen(rng, r, d):
    while True:
        sup0 = sorted(rng.sample(range(r), d))
        sup1 = sorted(rng.sample(range(r), d))
        h0 = sum(1 << j for j in sup0)
        h1 = sum(1 << j for j in sup1)
        h0i = _inv_poly(h0, r)
        if h0i is None:
            continue
        return sup0, sup1, h0, h1, _mul_poly(h1, h0i, r)


def syndrome_of(e0, e1, h_pub, r):
    return e0 ^ _mul_poly(e1, h_pub, r)


def random_error(rng, r, t):
    sup = rng.sample(range(2 * r), t)
    e0 = sum(1 << j for j in sup if j < r)
    e1 = sum(1 << (j - r) for j in sup if j >= r)
    return e0, e1


def trial(rng, r, d, t, nb_iter, key=None):
    """One encapsulate/decapsulate round trip.  True = decoded correctly.

    Callers that run many trials at one (r, d) should hold at_params() open
    around the loop rather than paying the swap per trial.
    """
    if key is None:
        key = keygen(rng, r, d)
    sup0, sup1, h0, h1, h_pub = key
    e0, e1 = random_error(rng, r, t)
    syn = syndrome_of(e0, e1, h_pub, r)
    with at_params(r, d, nb_iter):
        got = decode(syn, sup0, sup1, h0)
    return got == (e0, e1)


# ── statistics ─────────────────────────────────────────────────────────────
def _betacf(a, b, x, itmax=300, eps=3e-16):
    """Continued fraction for the incomplete beta (Numerical Recipes betacf)."""
    tiny = 1e-30
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, itmax + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < eps:
            break
    return h


def betainc(a, b, x):
    """Regularised incomplete beta I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def _beta_quantile(target, a, b):
    """Invert I_x(a, b) = target by bisection."""
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if betainc(a, b, mid) < target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def clopper_pearson(k, n, alpha=0.05):
    """Exact binomial confidence interval (no scipy)."""
    low = 0.0 if k == 0 else _beta_quantile(alpha / 2.0, k, n - k + 1)
    high = 1.0 if k == n else _beta_quantile(1.0 - alpha / 2.0, k + 1, n - k)
    return low, high


def fmt_rate(p):
    if p <= 0:
        return "0"
    return f"{p:.3e} (2^{math.log2(p):.1f})"


# ═══════════════════════════════════════════════════════════════════════════
# §1 — cross-validation
# ═══════════════════════════════════════════════════════════════════════════
def section1(n_wf, n_deployed, r_wf=9600):
    print(SEP)
    print("§1  The shipped decoder vs. an independent per-position reference")
    print(SEP)
    print("Every measurement below calls the decoder the suite ships.  That")
    print("removes the divergence risk the old twin carried but not the question")
    print("of whether the shipped bit-sliced decoder implements the decoder it")
    print("says it does, so pin it against a per-position reference first --")
    print("interpreted popcounts, one position at a time, the representation")
    print("TODO #276 moved away from.")
    print()
    print("Two instances, for two reasons.  The DEPLOYED one because that is what")
    print("the verdict is about.  And §3's waterfall instance -- the deployed d")
    print(f"and t at r = {r_wf} -- because at BIKE-128 a decoding failure essentially")
    print("never happens, and agreement on FAILURES is the half that matters.")
    print("Both carry the deployed d: BIKE Level 1's threshold rule has a floor of")
    print(f"{_SUITE._QCMDPC_TH_MIN} unsatisfied checks, which a row of weight 15 cannot reach at all,")
    print("so the retired parameters are not a usable cross-check instance for")
    print("this decoder (SecurityProofs-5.md §11.8.9 measures that failure mode:")
    print("the deployed rule fails 150 times out of 150 at d = 15).\n")

    rng = random.Random(218)
    ok = True
    print(f"  {'instance':>28}  {'trials':>7}  {'identical':>11}  {'failures':>9}  "
          f"{'shipped':>9}  {'reference':>10}")
    print(SEP2)

    for label, r, d, t, n, via_suite in (
            (f"r={r_wf}, d={D_DEP} (§3 waterfall)", r_wf, D_DEP, T_DEP, n_wf, False),
            (f"r={R_DEP}, d={D_DEP} (deployed)", R_DEP, D_DEP, T_DEP, n_deployed, True)):
        agree = fails = 0
        t_ship = t_ref = 0.0
        for _ in range(n):
            if via_suite:
                sup0, sup1, h0, h1, h_pub = _SUITE.qcmdpc_keygen()
                syn, _K = _SUITE.qcmdpc_encap(h_pub)
                sup0, sup1 = sorted(sup0), sorted(sup1)
            else:
                sup0, sup1, h0, h1, h_pub = keygen(rng, r, d)
                e0, e1 = random_error(rng, r, t)
                syn = syndrome_of(e0, e1, h_pub, r)
            with at_params(r, d, NB_DEP):
                t0 = time.time()
                got = decode(syn, sup0, sup1, h0)
                t_ship += time.time() - t0
                t0 = time.time()
                ref = ref_decode(syn, sup0, sup1, r, d, NB_DEP)
                t_ref += time.time() - t0
            agree += (got == ref)
            fails += (got is None)
        ok &= agree == n
        print(f"  {label:>28}  {n:>7}  {agree:>5}/{n:<5}  {fails:>9}  "
              f"{t_ship/n*1e3:>7.1f}ms  {t_ref/n*1e3:>8.0f}ms")
    print(SEP2)
    print()
    print("  The cost column is why the twin this script used to carry is gone:")
    print("  the shipped decoder is now the fast one, by about the same factor")
    print("  the twin used to buy, so a second implementation bought nothing and")
    print("  cost a divergence it had already suffered twice (four bitplanes,")
    print("  valid only at d <= 15, and the pre-#276 threshold rule).")
    print()
    print(f"  VERDICT: {'agreement is exact — measurements below are valid' if ok else 'MISMATCH — every number below is void'}")
    return ok


# ═══════════════════════════════════════════════════════════════════════════
# §2 — DFR at the deployed parameters
# ═══════════════════════════════════════════════════════════════════════════
def section2(n_trials):
    print("\n" + SEP)
    print("§2  DFR at the deployed parameters")
    print(SEP)
    print(f"r = {R_DEP}, d = {D_DEP}, t = {T_DEP}, NB_ITER = {NB_DEP}")
    print("Fresh key per trial, so this is the DFR a user meets averaged over")
    print("keygen — not the DFR of one fixed key, which §4 shows varies.\n")
    print("This section reported 0.264% = 2^-8.6 until TODO #276 moved the")
    print("parameters.  It cannot report a rate any more, and that is the point")
    print("of the change rather than a regression: what a sample of size n can")
    print("establish about a rate below 1/n is an UPPER BOUND, so an upper bound")
    print("is what this prints.\n")

    rng = random.Random(1218)
    fails = 0
    t0 = time.time()
    with at_params(R_DEP, D_DEP, NB_DEP):
        for _ in range(n_trials):
            key = keygen(rng, R_DEP, D_DEP)
            e0, e1 = random_error(rng, R_DEP, T_DEP)
            syn = syndrome_of(e0, e1, key[4], R_DEP)
            if decode(syn, key[0], key[1], key[2]) != (e0, e1):
                fails += 1
    dt = time.time() - t0
    p = fails / n_trials
    lo, hi = clopper_pearson(fails, n_trials)
    print(f"  trials             : {n_trials}   ({dt:.0f}s, {dt/n_trials*1e3:.1f} ms/trial)")
    print(f"  failures           : {fails}")
    if fails:
        print(f"  DFR                : {p:.4%}  = {fmt_rate(p)}")
        print(f"  95% CI (Clopper-Pearson): [{lo:.4%}, {hi:.4%}]")
    else:
        print(f"  DFR                : none observed  (< 1/{n_trials})")
        print(f"  95% one-sided upper bound: {hi:.4%} = 2^{math.log2(hi):.1f}")
    print()
    print(f"  IND-CCA2 needs DFR <= 2^-128.  This sample bounds it at 2^{math.log2(hi):.1f},")
    print(f"  which is {128 + math.log2(hi):.0f} bits short of the target — not because the")
    print("  decoder fails that often, but because 2^-128 is not a measurable")
    print("  quantity.  Reaching it by simulation needs ~2^128 decapsulations at")
    print(f"  {dt/n_trials*1e3:.0f} ms each; the age of the universe is about 2^59 seconds.")
    print()
    print("  So the deployed DFR claim is INHERITED from BIKE's published")
    print("  analysis of exactly these parameters, not established here.  That is")
    print("  the same position SECURITY.md's row takes, and it is one of the two")
    print("  reasons the protocol stays demo-only: what ships is a")
    print("  reimplementation of BIKE's decoder, and §1 pins it against a")
    print("  reference rather than against BIKE.  §3 is what can still be")
    print("  measured about the curve this point sits on.")
    return p if fails else None, hi


# ═══════════════════════════════════════════════════════════════════════════
# §3 — DFR(r) at the deployed (d, t), and which way the extrapolation errs
# ═══════════════════════════════════════════════════════════════════════════
def section3(scale, quick):
    print("\n" + SEP)
    print("§3  DFR(r) fit, and the direction of its error")
    print(SEP)
    print("Sendrier-Vasseur: measure DFR where simulation is affordable, fit")
    print("log2(DFR) against the block size, extrapolate.  This section used to")
    print("hold the toy d = 15, t = 18 and move r UPWARD from 523, asking what r")
    print("that decoder would need.  #276 answered that question by adopting")
    print("BIKE-128 whole, so the useful question inverted: hold the DEPLOYED")
    print(f"d = {D_DEP}, t = {T_DEP} and come DOWN from r = {R_DEP} to where the")
    print("waterfall is reachable, then extrapolate back up to the deployed r.")
    print("That produces a bound on the quantity §2 cannot measure.\n")
    print("Trial counts rise as r rises, to keep the failure count usable as the")
    print("rate falls — the whole difficulty of a DFR measurement.\n")

    grid = [(9600, 400), (9700, 600), (9800, 1200), (9900, 2600)]
    if quick:
        grid = [(9600, 120), (9700, 180), (9800, 400), (9900, 900)]
    grid = [(r, max(60, int(n * scale))) for r, n in grid]

    rng = random.Random(3218)
    pts = []
    print(f"{'r':>6}  {'trials':>8}  {'fails':>7}  {'DFR':>11}  {'log2 DFR':>9}  {'95% CI (log2)':>18}")
    print(SEP2)
    for r, n in grid:
        fails = 0
        with at_params(r, D_DEP, NB_DEP):
            for _ in range(n):
                key = keygen(rng, r, D_DEP)
                e0, e1 = random_error(rng, r, T_DEP)
                syn = syndrome_of(e0, e1, key[4], r)
                if decode(syn, key[0], key[1], key[2]) != (e0, e1):
                    fails += 1
        if fails == 0:
            print(f"{r:>6}  {n:>8}  {fails:>7}  {'< 1/n':>11}  {'—':>9}  {'—':>18}")
            continue
        p = fails / n
        lo, hi = clopper_pearson(fails, n)
        pts.append((r, math.log2(p)))
        ci = f"[{math.log2(lo):.1f}, {math.log2(hi):.1f}]" if lo > 0 else f"[-inf, {math.log2(hi):.1f}]"
        print(f"{r:>6}  {n:>8}  {fails:>7}  {p:>11.4%}  {math.log2(p):>9.2f}  {ci:>18}")

    if len(pts) < 3:
        print("\n  fewer than three usable points — fit skipped")
        return None

    n_p = len(pts)
    sx = sum(x for x, _ in pts); sy = sum(y for _, y in pts)
    sxx = sum(x * x for x, _ in pts); sxy = sum(x * y for x, y in pts)
    slope = (n_p * sxy - sx * sy) / (n_p * sxx - sx * sx)
    icept = (sy - slope * sx) / n_p
    ybar = sy / n_p
    ss_tot = sum((y - ybar) ** 2 for _, y in pts)
    ss_res = sum((y - (slope * x + icept)) ** 2 for x, y in pts)
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else float('nan')

    print(SEP2)
    print(f"  waterfall located  : between r = {pts[0][0]} and r = {pts[-1][0]} at the")
    print(f"                       deployed (d, t) = ({D_DEP}, {T_DEP}) — 78-80% of the")
    print(f"                       deployed r, so the curve IS reachable, which is")
    print("                       what makes this section possible at all")
    print(f"  least-squares fit  : log2(DFR) = {slope:.5f}·r + {icept:.1f}   (R² = {r2:.4f})")
    print(f"  waterfall slope    : {1/abs(slope):.1f} extra bits of r per bit of DFR")
    at_dep = slope * R_DEP + icept
    print(f"  extrapolated to the deployed r = {R_DEP}: 2^{at_dep:.0f}")

    # Which way does the straight line err?  Measure the curvature instead of
    # asserting it: successive secant slopes over the grid.
    secants = [((pts[i+1][1] - pts[i][1]) / (pts[i+1][0] - pts[i][0]))
               for i in range(len(pts) - 1)]
    steepening = all(secants[i+1] <= secants[i] for i in range(len(secants) - 1))
    print()
    print("  Curvature, measured rather than assumed (successive secant slopes,")
    print("  log2(DFR) per unit r):")
    for i, sc in enumerate(secants):
        print(f"    r {pts[i][0]} -> {pts[i+1][0]}: {sc:+.5f}")
    print(f"  monotonely steepening: {steepening}")
    print()
    if steepening:
        print("  The curve bends DOWNWARD faster than linear over the measured")
        print("  range, so the straight line above sits ABOVE the true curve to")
        print(f"  the right of it and 2^{at_dep:.0f} is a conservative UPPER BOUND on the")
        print("  deployed DFR — the direction Sendrier-Vasseur's methodology")
        print("  claims, established here by measurement.  Note that the old")
        print("  version of this section argued the opposite direction, on the")
        print("  strength of an error FLOOR flattening the curve at large r.")
        print("  Both effects are real; which dominates is a statement about the")
        print("  regime, and nothing measurable here settles it above r = 9900.")
        print("  So this bound is a bound on the WATERFALL's continuation, not a")
        print("  proof about the deployed instance.")
    else:
        print("  The curvature is NOT monotone over the measured range, so the")
        print("  linear extrapolation cannot be signed and the figure above is a")
        print("  fit, not a bound.  Treat it as such.")
    print()
    print(f"  What this does NOT do is reach 2^-128: the bound is 2^{at_dep:.0f}, which is")
    print(f"  {abs(-128 - at_dep):.0f} bits away, and closing that gap by simulation is the")
    print("  thing §2 shows is impossible.  BIKE's own 2^-128 for these")
    print("  parameters is an extrapolation too — a longer one, over more points,")
    print("  with their decoder.  This section says the shipped decoder's")
    print("  waterfall is in the right place and falls in the right direction; it")
    print("  does not say the inherited figure is reproduced.")
    return slope, icept, at_dep, steepening


# ═══════════════════════════════════════════════════════════════════════════
# §4 — weak keys
# ═══════════════════════════════════════════════════════════════════════════
def distance_spectrum(sup, r):
    """Multiset of cyclic distances within a support."""
    c = Counter()
    sl = sorted(sup)
    for i in range(len(sl)):
        for j in range(i + 1, len(sl)):
            dd = (sl[j] - sl[i]) % r
            c[min(dd, r - dd)] += 1
    return c


def key_multiplicity(sup0, sup1, r):
    return max(max(distance_spectrum(sup0, r).values()),
               max(distance_spectrum(sup1, r).values()))


def _ap_key(rng, r, d, j, step=7):
    """Key whose h0 puts j of its d positions in an arithmetic progression,
    the rest random — a dial for spectrum multiplicity."""
    for _ in range(400):
        sup0 = set((i * step) % r for i in range(j))
        while len(sup0) < d:
            sup0.add(rng.randrange(r))
        sup0 = sorted(sup0)
        h0 = sum(1 << x for x in sup0)
        inv = _inv_poly(h0, r)
        if inv is None:
            continue
        sup1 = sorted(rng.sample(range(r), d))
        h1 = sum(1 << x for x in sup1)
        return sup0, sup1, h0, h1, _mul_poly(h1, inv, r)
    return None


def section4(n_spectra, n_per_key, quick):
    print("\n" + SEP)
    print("§4  Weak keys — spectrum multiplicity vs. DFR")
    print(SEP)
    print("The BIKE weak-key classes (Drucker-Gueron-Kostic) are structural")
    print("properties of the private polynomials.  The one a bit-flipping decoder")
    print("feels is multiplicity in the distance spectrum: when a distance recurs,")
    print("the parity checks covering it stop being independent and the decoder's")
    print("per-position estimates degrade together.")
    print()
    print("THIS is the axis that survives TODO #276 intact, and the reason is")
    print("worth stating: a weak key does not have a SMALL failure rate, it has a")
    print("failure rate near 1.  Nothing here needs to resolve a probability")
    print("below 1/n, so unlike §2 and §3 this section measures at the deployed")
    print(f"parameters directly — r = {R_DEP}, d = {D_DEP}, t = {T_DEP}.\n")

    rng = random.Random(4218)
    screen = getattr(_SUITE, '_QCMDPC_MAX_MULT', None)

    # (a) what a raw draw looks like — spectrum only, no decoding, so this is cheap
    print("  (a) Multiplicity of one private polynomial, as DRAWN")
    hist = Counter()
    for _ in range(n_spectra):
        hist[max(distance_spectrum(rng.sample(range(R_DEP), D_DEP), R_DEP).values())] += 1
    print(f"      {n_spectra} samples at d = {D_DEP}, r = {R_DEP}")
    for k in sorted(hist):
        print(f"        max multiplicity {k:>2}: {hist[k]:>8}  {hist[k]/n_spectra:>9.4%}")
    print(f"      (At the retired d = 15, r = 523 the same draw gave a mode of 3")
    print(f"       and never exceeded 6 in 200 000 samples.  {D_DEP} positions put")
    print(f"       {D_DEP*(D_DEP-1)//2} distances into {R_DEP//2} buckets rather than 105 into 261,")
    print(f"       so the whole distribution moved.)")

    # (a′) what keygen now EMITS — the screen TODO #235 Part 1 added
    print("\n  (a′) ... and as keygen EMITS it, after the weak-key screen")
    rej_key = None
    if screen is None:
        print("      NO SCREEN FOUND in the suite (_QCMDPC_MAX_MULT is absent).")
        print("      This section's verdict below assumes TODO #235 Part 1 is")
        print("      deployed; without it, read (a) as the emitted distribution.")
    else:
        print(f"      Deployed bound: _QCMDPC_MAX_MULT = {screen}"
              f"  (accept iff both polynomials are <= {screen})")
        emitted = Counter({k: v for k, v in hist.items() if k <= screen})
        n_emit = sum(emitted.values())
        for k in sorted(emitted):
            print(f"        max multiplicity {k:>2}: {emitted[k]:>8}  "
                  f"{emitted[k]/n_emit:>9.4%}")
        rej_poly = 1 - n_emit / n_spectra
        rej_key = 1 - (n_emit / n_spectra) ** 2
        print(f"      Rejected polynomials: {rej_poly:.4%};  rejected key draws: "
              f"{rej_key:.4%}"
              + (f"  (~1 in {1/rej_key:,.0f})" if rej_key > 0 else ""))
        print("      The screen sits before the inversion, the expensive half of")
        print("      a draw, so this is close to free.")

    # (b) the DFR gradient, driven by construction
    print("\n  (b) DFR as multiplicity is dialled up (h0 partly an arithmetic")
    print("      progression, the rest random — h1 always random)")
    print(f"      {'AP positions':>13}  {'max mult':>9}  {'screened':>9}  "
          f"{'trials':>7}  {'fails':>6}  {'DFR':>9}")
    print(SEP2)
    gradient = []
    js = [2, 8, 16, 31, 32, 33, 34, 35, 37, 48, D_DEP]
    if quick:
        js = [2, 16, 32, 34, 37, D_DEP]
    for j in js:
        key = _ap_key(rng, R_DEP, D_DEP, j)
        if key is None:
            continue
        mult = max(distance_spectrum(key[0], R_DEP).values())
        strong = (_SUITE.qcmdpc_key_is_strong(set(key[0]), set(key[1]))
                  if hasattr(_SUITE, 'qcmdpc_key_is_strong') else None)
        n = n_per_key
        fails = 0
        with at_params(R_DEP, D_DEP, NB_DEP):
            for _ in range(n):
                e0, e1 = random_error(rng, R_DEP, T_DEP)
                syn = syndrome_of(e0, e1, key[4], R_DEP)
                if decode(syn, key[0], key[1], key[2]) != (e0, e1):
                    fails += 1
        gradient.append((mult, fails / n, strong))
        tag = 'rejected' if strong is False else ('accepted' if strong else '?')
        print(f"      {j:>13}  {mult:>9}  {tag:>9}  {n:>7}  {fails:>6}  "
              f"{fails/n:>9.3%}")

    # (c) tie the two together
    print(SEP2)
    print("\n  (c) Putting (a) and (b) together — where the cliff actually is")
    if screen is not None and rej_key is not None:
        p_over = sum(v for k, v in hist.items() if k > screen) / n_spectra
        print(f"      P(one polynomial exceeds the screen bound {screen}) = {p_over:.4%}")
        print(f"      P(a key draw is rejected)                     = {rej_key:.4%}")

    # Locate the cliff from the gradient: the lowest multiplicity whose DFR
    # exceeds a tenth, and the highest that stays under a thousandth.
    benign = [m for m, p, _ in gradient if p <= 1e-3]
    broken = [m for m, p, _ in gradient if p >= 0.10]
    cliff_lo = max(benign) if benign else None
    cliff_hi = min(broken) if broken else None
    print()
    if cliff_lo is not None and cliff_hi is not None:
        print(f"      The cliff sits between multiplicity {cliff_lo} and {cliff_hi}: at or below")
        print(f"      {cliff_lo} the DFR is under 1/1000 and indistinguishable from an")
        print(f"      ordinary key at this sample size, at {cliff_hi} and above the key is")
        print("      substantially or entirely non-functional.")
        print()
        print("      AT THE RETIRED PARAMETERS THAT CLIFF WAS AT 6 -> 7.  It has")
        print(f"      moved to about {cliff_lo} -> {cliff_hi}, which is the single most useful")
        print("      number this section now produces, because:")
        print()
        if screen is not None:
            print(f"      * The deployed bound _QCMDPC_MAX_MULT = {screen} is a factor of about")
            print(f"        {cliff_hi/screen:.0f} BELOW the cliff, so it is conservative by a wide")
            print("        margin rather than tuned to an edge.  TODO #276 could not")
            print("        say this: it recorded the bound on a stated retry budget")
            print("        precisely because the DFR was no longer measurable, and")
            print("        SecurityProofs-5.md §11.8.9 says the screen \"cannot be")
            print("        re-derived the way it was derived\".  That is true of the")
            print("        method it used -- resolving DFR DIFFERENCES among ordinary")
            print("        keys -- and not of the constant: a cliff at DFR ~ 1 needs")
            print(f"        no such resolution, and {n_per_key} trials per point find it.")
            print(f"      * The tail the screen removes was never near the cliff.  The")
            print(f"        keys it rejects -- multiplicity {screen+1} upward, {p_over:.4%} of draws --")
            print("        decode indistinguishably from accepted ones here.  The")
            print("        screen is cheap insurance against a class this decoder")
            print("        at these parameters tolerates, not a fix for a measured")
            print("        weakness, and that is a change from the retired set where")
            print("        multiplicity 6 was the highest honest keygen reached AND")
            print("        carried about ten times the average DFR.")
    else:
        print("      The gradient did not bracket a cliff at this sample size.")
        print("      Widen `js` or raise --trials before reading anything into it.")
    print()
    print("      Still true, and NOT fixed by the screen: nothing in the PEM")
    print("      decode path checks the spectrum of an IMPORTED private key.")
    print("      The library exposes the predicate (qcmdpc_key_is_strong /")
    print("      QcMdpcKeyIsStrong / qcmdpcKeyIsStrong) but the CLI readers do")
    print("      not call it.  A supplied key can still be an arithmetic")
    print("      progression, and (b)'s last row is what that costs: every")
    print("      decapsulation fails.  That is a self-inflicted denial of")
    print("      service rather than a confidentiality break, which is why it is")
    print("      recorded rather than filed as a blocker.")
    return hist, gradient, (cliff_lo, cliff_hi)


# ═══════════════════════════════════════════════════════════════════════════
# §5 — GJS reaction attack
# ═══════════════════════════════════════════════════════════════════════════
def section5(n_per_class, n_keys, r_probe=9800):
    print("\n" + SEP)
    print("§5  GJS reaction attack — the distinguisher, measured")
    print(SEP)
    print("GJS: the failure probability depends on whether distances in the error")
    print("support appear in the private key's distance spectrum.  An attacker who")
    print("submits chosen ciphertexts and observes success/failure reads the")
    print("spectrum off the failure rates, and the spectrum pins down h0 up to a")
    print("cyclic shift — full private-key recovery.\n")
    print("Nothing about the attacker's side is exotic: it picks e, computes")
    print("syn = e0 + e1·h_pub from the PUBLIC key, and submits it.\n")
    print("MEASURED AT r = %d, NOT AT THE DEPLOYED r = %d, and the reason is the"
          % (r_probe, R_DEP))
    print("finding rather than a limitation.  This statistic is a DIFFERENCE")
    print("between two failure rates, so it needs both to be observable; §2 shows")
    print("that at the deployed r neither is, at any sample size.  §3 located the")
    print("waterfall, so the distinguisher is measured there — the same substitute")
    print("-instance move SecurityProofs-5.md §11.8.10 makes for the decoder")
    print(f"comparison — at the deployed d = {D_DEP} and t = {T_DEP}.\n")

    rng = random.Random(5218)
    tot_in = tot_out = fail_in = fail_out = 0
    t0 = time.time()

    with at_params(r_probe, D_DEP, NB_DEP):
        for _ in range(n_keys):
            sup0, sup1, h0, h1, h_pub = keygen(rng, r_probe, D_DEP)
            spec = distance_spectrum(sup0, r_probe)
            in_d = sorted(spec)
            out_d = sorted(set(range(1, r_probe // 2 + 1)) - set(in_d))

            for dists, tag in ((in_d, 'in'), (out_d, 'out')):
                for _ in range(n_per_class):
                    e0 = 0
                    placed = 0
                    guard = 0
                    while placed < T_DEP and guard < 4000:
                        guard += 1
                        dd = rng.choice(dists)
                        a_ = rng.randrange(r_probe)
                        b_ = (a_ + dd) % r_probe
                        if (e0 >> a_) & 1 or (e0 >> b_) & 1:
                            continue
                        e0 |= (1 << a_) | (1 << b_)
                        placed += 2
                    if placed != T_DEP:
                        continue
                    syn = syndrome_of(e0, 0, h_pub, r_probe)
                    ok = decode(syn, sup0, sup1, h0) == (e0, 0)
                    if tag == 'in':
                        tot_in += 1;  fail_in += (not ok)
                    else:
                        tot_out += 1; fail_out += (not ok)

    p_in = fail_in / tot_in if tot_in else float('nan')
    p_out = fail_out / tot_out if tot_out else float('nan')
    lo_i, hi_i = clopper_pearson(fail_in, tot_in) if tot_in else (0, 0)
    lo_o, hi_o = clopper_pearson(fail_out, tot_out) if tot_out else (0, 0)

    print(f"  {n_keys} keys, error weight {T_DEP} placed as pairs at chosen "
          f"distances  ({time.time()-t0:.0f}s)\n")
    print(f"  {'error distances':>18}  {'trials':>8}  {'fails':>6}  {'DFR':>9}  {'95% CI':>22}")
    print(SEP2)
    print(f"  {'IN key spectrum':>18}  {tot_in:>8}  {fail_in:>6}  {p_in:>9.3%}  "
          f"[{lo_i:>8.3%}, {hi_i:>8.3%}]")
    print(f"  {'NOT in spectrum':>18}  {tot_out:>8}  {fail_out:>6}  {p_out:>9.3%}  "
          f"[{lo_o:>8.3%}, {hi_o:>8.3%}]")
    print(SEP2)

    separated = hi_i < lo_o or hi_o < lo_i
    if p_in > 0 and p_out > 0:
        print(f"  ratio              : {max(p_in,p_out)/min(p_in,p_out):.2f}x "
              f"({'lower' if p_in < p_out else 'higher'} when the distance is in the spectrum)")
    print(f"  95% intervals disjoint : {separated}")
    diff = abs(p_in - p_out)
    if diff > 0:
        pbar = (p_in + p_out) / 2
        nq = math.ceil(2 * (1.96 ** 2) * pbar * (1 - pbar) / (diff ** 2))
        print(f"  queries to resolve one distance at 95%: ~{nq:,}")
        print(f"  distances to classify: r/2 = {r_probe // 2}")
        print(f"  order of magnitude for the full spectrum: ~{nq * (r_probe // 2):.1e} queries")
    print()
    if separated:
        print("  Reading: at this instance the failure rate CARRIES the private")
        print("  key.  The mechanism is present in the decoder that ships, using")
        print("  ciphertexts built from public data alone.")
    else:
        print("  Reading: the gap is visible in the point estimates but the")
        print("  intervals still overlap at this sample size.  That is a statement")
        print("  about the sample, not evidence against the attack.")
    print()
    print("  WHAT THIS DOES AND DOES NOT SAY ABOUT THE DEPLOYED KEM.  It says the")
    print("  decoder's failure rate is key-dependent in the way GJS needs, and")
    print("  that this property did not go away with the parameter change — it is")
    print("  a property of bit-flipping decoding, not of r.  It does NOT say the")
    print("  attack is reachable as deployed, and two independent things stop it:")
    print(f"  at r = {R_DEP} the rate an attacker would have to sample is the one §2")
    print("  cannot bound anywhere near the target, and since TODO #235 there is")
    print("  no signal to sample at all (§6).  Either alone is sufficient; the")
    print("  first is a consequence of #276 and the second predates it.")
    return p_in, p_out, separated


# ═══════════════════════════════════════════════════════════════════════════
# §6 — is the oracle reachable?
# ═══════════════════════════════════════════════════════════════════════════
def section6():
    print("\n" + SEP)
    print("§6  Failure signalling — is the oracle reachable?")
    print(SEP)
    print("A reaction attack needs the failure to be OBSERVABLE.  The standard")
    print("defence is implicit rejection: on decoding failure return a")
    print("pseudorandom key derived from a secret and the ciphertext, so the")
    print("attacker cannot tell failure from success.  BIKE does this; it is the")
    print("reason its DFR argument is about IND-CCA2 rather than about UX.\n")

    print("  Original finding (before TODO #235): the failure was signalled")
    print("  explicitly at every layer — qcmdpc_decap_bgf returned None / 0 /")
    print("  false, and each CLI exited nonzero with a distinct stderr message.")
    print("  There was no FO transform: decapsulation never checked that the")
    print("  ciphertext had been honestly generated, so an attacker's chosen")
    print("  syndrome was processed exactly like a real one, and the oracle §5")
    print("  needs was not merely present in theory, it was the documented")
    print("  interface.\n")

    print("  Deployed behaviour now — measured here, not asserted:\n")

    sup0, sup1, h0, h1, h_pub = _SUITE.qcmdpc_keygen()
    # An honest ciphertext for a DIFFERENT key: well-formed, but this key cannot
    # decode it.  That is the adversary's chosen-ciphertext input, and the one
    # that used to produce the oracle's "failure" answer.
    s2, s3, h0b, _h1b, h_pub_b = _SUITE.qcmdpc_keygen()
    syn_foreign, _K_foreign = _SUITE.qcmdpc_encap(h_pub_b)
    syn_honest,  K_honest   = _SUITE.qcmdpc_encap(h_pub)

    decoded_foreign = _SUITE.qcmdpc_bgf_decode(syn_foreign, h0, sup0, sup1)
    K_good      = _SUITE.qcmdpc_decap_bgf(syn_honest,  sup0, sup1, h0)
    K_bad       = _SUITE.qcmdpc_decap_bgf(syn_foreign, sup0, sup1, h0)
    K_bad2      = _SUITE.qcmdpc_decap_bgf(syn_foreign, sup0, sup1, h0)
    K_bad_other = _SUITE.qcmdpc_decap_bgf(syn_foreign, s2, s3, h0b)

    print("    decoder on the foreign ciphertext         : "
          f"{'FAILS (as expected)' if decoded_foreign is None else 'decoded'}")
    print("    decap on the honest ciphertext            : returns a key, "
          f"correct = {K_good == K_honest}")
    print("    decap on the foreign ciphertext           : "
          f"{'returns a key (no None, no exception)' if K_bad is not None else 'SIGNALS FAILURE'}")
    print(f"    ... differing from the honest key         : {K_bad != K_good}")
    print(f"    ... deterministic in (key, ciphertext)    : {K_bad == K_bad2}")
    print(f"    ... and different under a different key   : {K_bad != K_bad_other}")
    print()

    oracle_gone = (K_bad is not None and K_bad != K_good and K_bad == K_bad2
                   and K_bad != K_bad_other)
    if oracle_gone:
        print("  The two answers the oracle needed to tell apart — success and")
        print("  failure — are now the same answer: a 32-byte key.  On the failure")
        print("  path it is HFSCX-256-DS(0x11, z || C), with z = HFSCX-256-DS(0x12,")
        print("  h0 || h1) a secret the attacker does not hold.  Nothing in the")
        print("  return value, the exit status, or the stderr of any of the four")
        print("  CLIs separates the cases.")
        print()
        print("  Note what did NOT change: the decoder's DFR, and therefore §5's")
        print("  statistic, are exactly as measured above.  §5 is a property of")
        print("  the decoder; §6 was what made it observable.  Removing the signal")
        print("  removes the attack without touching the failure rate — which is")
        print("  also why blocker 1 in §7 still stands entirely on its own.")
        print()
        print("  Residual, deliberately not claimed away: this is protocol-level")
        print("  indistinguishability only.  Neither the decoder nor the branch")
        print("  selecting the rejection key is constant time, so an attacker with")
        print("  a local timing channel can still separate the two.  At these")
        print("  parameters that is not the binding constraint.")
    else:
        print("  *** The oracle is still reachable — TODO #235 Part 2 is not")
        print("  *** deployed, or has regressed.  Treat §7's blocker 4 as OPEN.")
    return oracle_gone


# ═══════════════════════════════════════════════════════════════════════════
# §7 — verdict
# ═══════════════════════════════════════════════════════════════════════════
def section7(dfr_obs, dfr_bound, fit, cliff, oracle_gone=False):
    screen = getattr(_SUITE, '_QCMDPC_MAX_MULT', None)
    print("\n" + SEP)
    print("§7  Verdict")
    print(SEP)
    print(f"  1. DFR at the deployed parameters is NOT MEASURABLE.  {'A rate below' if dfr_obs is None else 'Observed'}")
    if dfr_obs is None:
        print(f"     2^{math.log2(dfr_bound):.1f} is all a sample of this size can establish (§2), and")
        print("     IND-CCA2 needs 2^-128.  The claim at these parameters is")
        print("     INHERITED from BIKE's published analysis of the same (r, d, t),")
        print("     not established here.  This is the intended consequence of")
        print("     TODO #276, not a gap it opened: the previous parameters had a")
        print("     measurable DFR precisely because it was 2^-8.6.")
    else:
        print(f"     {dfr_obs:.4%} = 2^{math.log2(dfr_obs):.1f}, which should not happen at BIKE-128")
        print("     and means either the decoder or the parameters have regressed.")
    if fit:
        _slope, _icept, at_dep, steepening = fit
        print(f"  2. The waterfall IS reachable at the deployed (d, t) — §3 puts it")
        print(f"     just under r = 9900, 80% of the deployed {R_DEP} — and the fitted")
        print(f"     continuation bounds the deployed DFR at 2^{at_dep:.0f}, with the measured")
        print("     curvature running in the conservative direction"
              + ("." if steepening else " — NO LONGER TRUE,"))
        if not steepening:
            print("     so the figure is a fit rather than a bound.")
        print(f"     That is {abs(-128 - at_dep):.0f} bits short of the target and cannot be closed")
        print("     by measurement.")
    else:
        print("  2. §3's fit did not produce three usable points — no bound.")
    if screen is None:
        print( "  3. Weak keys are not screened: keygen retries only on a")
        print( "     non-invertible h0.  DFR varies materially across keys (§4).")
    else:
        lo, hi = cliff
        print(f"  3. CLOSED by TODO #235 Part 1, and now MEASURED at the deployed")
        print(f"     parameters rather than inherited from the retired ones.  Keygen")
        print(f"     rejects any polynomial above multiplicity {screen}; §4 puts the DFR")
        print(f"     cliff at {lo} -> {hi}, so the bound is conservative by a factor of")
        print(f"     about {hi/screen:.0f} rather than tuned to an edge.  #276 recorded that")
        print("     constant on a retry budget because it believed the cliff could")
        print("     not be re-measured; §4(c) is the correction.  An IMPORTED key is")
        print("     still unscreened — a self-inflicted denial of service, not a")
        print("     confidentiality break.")
    if not oracle_gone:
        print( "  4. The GJS precondition holds — failures are explicitly signalled,")
        print( "     with no FO transform or implicit rejection (§5, §6).")
    else:
        print( "  4. CLOSED by TODO #235 Part 2.  Decapsulation applies an FO")
        print( "     transform with implicit rejection: it checks rigidity (the")
        print( "     re-encryption identity, which reduces exactly to wt(e) = t")
        print( "     given an invertible h0) and returns HFSCX-256-DS(0x11, z || C)")
        print( "     on any failure.  §6 measures success and failure returning the")
        print( "     same kind of answer.  §5's mechanism survives the parameter")
        print( "     change — it is a property of bit-flipping decoding — but at")
        print( "     the deployed r there is neither an observable failure nor a")
        print( "     signal, so two independent things now block the attack.")
    print()
    print( "  HOW THIS VERDICT CHANGED SHAPE UNDER TODO #276.  Blockers 1 and 2")
    print( "  used to be measurements: a 2^-8.6 DFR and a syndrome-decoding")
    print( "  instance worth about 2^21 operations, both of them numbers produced")
    print( "  here.  #276 replaced the parameters with BIKE-128's, which removes")
    print( "  the second blocker outright (§11.8.9 costs the new instance at")
    print( "  BIKE's own level) and converts the first from a measured failure")
    print( "  into an inherited claim.  The KEM stays demo-only, and the reason")
    print( "  is now about PROVENANCE rather than about parameters: what ships is")
    print( "  a reimplementation of BIKE's decoder, drawing from a suite-specific")
    print( "  FSCX-based PRF, whose equivalence to the analysed object rests on")
    print( "  testing (§1 here, CliTest/test_stern_kem.sh, KAT/pem/ since #284)")
    print( "  rather than on proof.  That is a weaker claim than BIKE makes and a")
    print( "  much stronger one than the toy set supported.")
    print()
    print( "  Recommended SECURITY.md row — cross-check against the deployed one:")
    print( "    HPKE-Stern-KEM | Demo-only | Runs at BIKE-128's parameters")
    print( "    (r=12323, d=71, t=134) since TODO #276, adopted verbatim together")
    print( "    with BIKE's decoder.  The DFR at these parameters is not")
    print( "    measurable here, so 2^-128 is inherited from BIKE's published")
    print( "    analysis while what ships is a reimplementation whose equivalence")
    print( "    is established by testing rather than proof.  Decapsulation")
    print( "    applies an FO transform with implicit rejection and keygen screens")
    print( "    the weak-key classes, so the GJS reaction attack has no oracle; an")
    print( "    imported private key is still unscreened.  A decoding failure is")
    print( "    silent.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='small sample counts (~4 min) — qualitative only')
    args = ap.parse_args()
    q = args.quick

    t0 = time.time()
    print(SEP)
    print("QC-MDPC BGF: DFR, weak keys, reaction attacks — TODO #218, #285")
    print(SEP)
    print(f"deployed: r = {R_DEP}, d = {D_DEP}, t = {T_DEP}, NB_ITER = {NB_DEP}"
          f"  (BIKE-128, since TODO #276)")

    if not section1(6 if q else 20, 2 if q else 6):
        print("\nAborting: the shipped decoder does not match the reference.")
        return 1
    dfr_obs, dfr_bound = section2(400 if q else 3000)
    fit = section3(1.0, q)
    _hist, _grad, cliff = section4(5000 if q else 100000,
                                   60 if q else 200, q)
    section5(120 if q else 400, 2 if q else 3)
    oracle_gone = section6()
    section7(dfr_obs, dfr_bound, fit, cliff, oracle_gone)

    # ── findings gate ──────────────────────────────────────────────────────
    # Every section above is a claim this script is the evidence for, so a
    # claim that stops reproducing has to fail the run rather than print
    # quietly.  §1 already aborts; these are the rest.
    problems = []
    if dfr_obs is not None:
        problems.append(f"§2: a DFR of {dfr_obs:.2%} is observable at BIKE-128 "
                        "parameters — decoder or parameter regression")
    if fit is None:
        problems.append("§3: the waterfall did not yield three usable points, "
                        "so no bound on the deployed DFR was produced")
    elif not fit[3]:
        problems.append("§3: the measured curvature is no longer monotone, so "
                        "the extrapolation can no longer be signed")
    screen = getattr(_SUITE, '_QCMDPC_MAX_MULT', None)
    if cliff[0] is None or cliff[1] is None:
        problems.append("§4: the multiplicity gradient no longer brackets a "
                        "cliff — the screen bound cannot be placed against it")
    elif screen is not None and cliff[1] <= screen:
        problems.append(f"§4: the DFR cliff is at multiplicity {cliff[1]}, at or "
                        f"below the deployed screen bound {screen} — the screen "
                        "is no longer conservative")
    if not oracle_gone:
        problems.append("§6: the failure oracle is reachable — TODO #235 Part 2 "
                        "has regressed")

    print("\n" + SEP)
    if problems:
        print("FINDINGS THAT STOPPED REPRODUCING:")
        for pr in problems:
            print("  * " + pr)
        print(SEP)
        return 1
    print(f"done in {time.time() - t0:.0f}s — every finding reproduced")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
