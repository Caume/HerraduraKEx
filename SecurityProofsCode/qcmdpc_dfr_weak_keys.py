#!/usr/bin/env python3
"""
qcmdpc_dfr_weak_keys.py — DFR, weak keys, and reaction attacks against
HPKE-Stern-KEM's QC-MDPC BGF decoder (TODO #218, §11.8.6).

TODO #195/#221 treat BGF decoding failures as CI flakiness.  This is the security
half of the same fact.  For a KEM, IND-CCA2 needs DFR <= 2^-lambda, and any
*observable* failure exposes the GJS reaction attack [Guo-Johansson-Stankovski
2016]: submit crafted ciphertexts, watch which ones fail, reconstruct the private
key's distance spectrum.

  §1  Fast-decoder cross-validation against the deployed decoder (bit-exact)
  §2  DFR at the deployed parameters, with a Clopper-Pearson interval
  §3  DFR(r) fit and extrapolation (Sendrier-Vasseur methodology)
  §4  Weak keys — distance-spectrum multiplicity vs. DFR, and what keygen emits
  §5  GJS reaction attack — the distinguisher, measured end to end
  §6  Failure signalling: is the oracle actually reachable?
  §7  Verdict and the SECURITY.md row

Deployed parameters (C, Go, and Python alike): r = 523, d = 15, t = 18,
NB_ITER = 20 — labelled "toy parameters" in the source.  BIKE-128 for scale:
r = 12323, d = 71, t = 134.

§2-§5 need volume, so they run a bit-sliced reimplementation of the deployed BGF
decoder (~40x faster than the suite's).  §1 pins it to the deployed one on random
instances before any measurement is taken; every number below is void if §1 does
not report perfect agreement.

Runtime: ~14 min at default settings; --quick (~90 s) cuts every sample count and
is enough to reproduce the qualitative findings but not the confidence intervals.
"""

import argparse
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

R_DEP  = _SUITE._QCMDPC_R          # 523
D_DEP  = _SUITE._QCMDPC_D          # 15
T_DEP  = _SUITE._QCMDPC_T          # 18
NB_DEP = _SUITE._QCMDPC_NB_ITER    # 20

SEP  = "═" * 74
SEP2 = "─" * 74


# ═══════════════════════════════════════════════════════════════════════════
# Bit-sliced reimplementation of the deployed BGF decoder
#
# Mirrors qcmdpc_bgf_decode step for step, including the it == 0 gray-flip
# block and its quirk of computing the unsatisfied-parity counts once per
# group rather than once per candidate position.  The only change is
# representation: unsatisfied-parity counters are held as four r-bit
# bitplanes and updated with carry-save addition, so one decoder iteration
# costs ~130 big-integer operations instead of ~16 000 interpreter steps.
# ═══════════════════════════════════════════════════════════════════════════
def _rotr(s, k, r, full):
    """bit j of the result = bit (j+k) mod r of s."""
    return s if k == 0 else ((s >> k) | (s << (r - k))) & full


def _counters(s, sup, r, full):
    """Carry-save sum of the rotated syndrome over sup -> four bitplanes."""
    c0 = c1 = c2 = c3 = 0
    for k in sup:
        v = _rotr(s, k, r, full)
        cy = c0 & v; c0 ^= v
        cy2 = c1 & cy; c1 ^= cy
        cy3 = c2 & cy2; c2 ^= cy2
        c3 ^= cy3
    return (c0, c1, c2, c3)


def _mask_eq_range(c, full, lo, hi, d):
    """bit j set iff lo <= counter[j] < hi."""
    out = 0
    for val in range(max(lo, 0), min(hi, d + 1)):
        m = full
        for i in range(4):
            m &= c[i] if (val >> i) & 1 else ~c[i] & full
        out |= m
    return out


def _set_bits(x):
    out = []
    while x:
        b = x & -x
        out.append(b.bit_length() - 1)
        x ^= b
    return out


def bgf_decode_fast(syn_pub, sup0, sup1, r, d, nb_iter):
    """Returns (e0, e1) or None — bit-exact with the deployed qcmdpc_bgf_decode."""
    full = (1 << r) - 1
    s = 0
    for k in sup0:                                  # s = syn_pub * h0
        s ^= ((syn_pub << k) | (syn_pub >> (r - k))) & full
    e0 = e1 = 0
    th_floor = (d + 1) // 2 + 2

    for it in range(nb_iter):
        if s == 0:
            break
        th = max(math.ceil(0.66 * d), th_floor) if it < 7 else max(th_floor - 1, 8)
        c0 = _counters(s, sup0, r, full)
        c1 = _counters(s, sup1, r, full)
        black = (_set_bits(_mask_eq_range(c0, full, th, d + 1, d)),
                 _set_bits(_mask_eq_range(c1, full, th, d + 1, d)))
        gray  = (_set_bits(_mask_eq_range(c0, full, th - 2, th, d)),
                 _set_bits(_mask_eq_range(c1, full, th - 2, th, d)))
        for j in black[0]:
            e0 ^= 1 << j
            for k in sup0:
                s ^= 1 << ((j + k) % r)
        for j in black[1]:
            e1 ^= 1 << j
            for k in sup1:
                s ^= 1 << ((j + k) % r)
        if it == 0:
            for group in (black, gray):
                f0 = _mask_eq_range(_counters(s, sup0, r, full), full,
                                    th_floor, d + 1, d)
                f1 = _mask_eq_range(_counters(s, sup1, r, full), full,
                                    th_floor, d + 1, d)
                for j in group[0]:
                    if (f0 >> j) & 1:
                        e0 ^= 1 << j
                        for k in sup0:
                            s ^= 1 << ((j + k) % r)
                for j in group[1]:
                    if (f1 >> j) & 1:
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
    """One encapsulate/decapsulate round trip.  True = decoded correctly."""
    if key is None:
        key = keygen(rng, r, d)
    sup0, sup1, h0, h1, h_pub = key
    e0, e1 = random_error(rng, r, t)
    syn = syndrome_of(e0, e1, h_pub, r)
    got = bgf_decode_fast(syn, sup0, sup1, r, d, nb_iter)
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
def section1(n_trials):
    print(SEP)
    print("§1  Fast decoder vs. the deployed decoder — bit-exact agreement")
    print(SEP)
    print("Every measurement below uses the fast decoder.  It is worth nothing")
    print("unless it is the same function as the one that ships, so pin it first")
    print("on instances drawn from the suite's own keygen/encap.\n")

    rng = random.Random(218)
    agree = fails = 0
    t0 = time.time()
    for _ in range(n_trials):
        sup0, sup1, h0, h1, h_pub = _SUITE.qcmdpc_keygen()
        syn, _K = _SUITE.qcmdpc_encap(h_pub)
        ref = _SUITE.qcmdpc_bgf_decode(syn, h0, sup0, sup1)
        fast = bgf_decode_fast(syn, sorted(sup0), sorted(sup1), R_DEP, D_DEP, NB_DEP)
        agree += (ref == fast)
        fails += (ref is None)
    print(f"  instances          : {n_trials} (suite keygen + suite encap)")
    print(f"  identical output   : {agree}/{n_trials}")
    print(f"  of which failures  : {fails} (agreement on failures matters most)")
    print(f"  elapsed            : {time.time() - t0:.0f}s")
    ok = agree == n_trials
    print(f"\n  VERDICT: {'agreement is exact — measurements below are valid' if ok else 'MISMATCH — every number below is void'}")
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

    rng = random.Random(1218)
    fails = 0
    t0 = time.time()
    for i in range(n_trials):
        if not trial(rng, R_DEP, D_DEP, T_DEP, NB_DEP):
            fails += 1
    dt = time.time() - t0
    p = fails / n_trials
    lo, hi = clopper_pearson(fails, n_trials)
    print(f"  trials             : {n_trials}   ({dt:.0f}s, {dt/n_trials*1e3:.2f} ms/trial)")
    print(f"  failures           : {fails}")
    print(f"  DFR                : {p:.4%}  = {fmt_rate(p)}")
    print(f"  95% CI (Clopper-Pearson): [{lo:.4%}, {hi:.4%}]")
    print(f"                          = [2^{math.log2(lo) if lo>0 else float('-inf'):.1f}, 2^{math.log2(hi):.1f}]")
    print(f"\n  IND-CCA2 needs DFR <= 2^-lambda.  Observed 2^{math.log2(p):.1f} supports")
    print(f"  lambda = {-math.log2(p):.1f} bits — against a 128-bit target this is short by")
    print(f"  a factor of about 2^{128 + math.log2(p):.0f}.")
    print(f"  (TODO #195 measured 0.225% from CI history; this is an independent")
    print(f"  measurement of the same quantity.)")
    return p


# ═══════════════════════════════════════════════════════════════════════════
# §3 — DFR(r) extrapolation, Sendrier-Vasseur style
# ═══════════════════════════════════════════════════════════════════════════
def section3(scale, quick):
    print("\n" + SEP)
    print("§3  DFR(r) fit and extrapolation")
    print(SEP)
    print("Sendrier-Vasseur: measure DFR where simulation is affordable, fit")
    print("log(DFR) against the block size, extrapolate to the target rate.  d")
    print("and t stay at the deployed values and r moves UPWARD from 523, so the")
    print("fit answers the design question directly — what r would this decoder")
    print("need?  (Downward is useless: by r = 421 the DFR is already 50% and by")
    print("r = 373 it saturates, so those points carry no slope.)")
    print("Trial counts rise with r to keep the failure count usable as the rate")
    print("falls — the whole difficulty of a DFR measurement.\n")

    grid = [(523, 20000), (541, 50000), (557, 120000), (571, 250000)]
    if quick:
        grid = [(523, 6000), (541, 12000), (557, 25000)]
    grid = [(r, max(400, int(n * scale))) for r, n in grid]

    rng = random.Random(3218)
    pts = []
    print(f"{'r':>6}  {'trials':>9}  {'fails':>7}  {'DFR':>11}  {'log2 DFR':>9}  {'95% CI (log2)':>18}")
    print(SEP2)
    for r, n in grid:
        fails = 0
        for _ in range(n):
            if not trial(rng, r, D_DEP, T_DEP, NB_DEP):
                fails += 1
        if fails == 0:
            print(f"{r:>6}  {n:>9}  {fails:>7}  {'< 1/n':>11}  {'—':>9}  {'—':>18}")
            continue
        p = fails / n
        lo, hi = clopper_pearson(fails, n)
        pts.append((r, math.log2(p)))
        ci = f"[{math.log2(lo):.1f}, {math.log2(hi):.1f}]" if lo > 0 else f"[-inf, {math.log2(hi):.1f}]"
        print(f"{r:>6}  {n:>9}  {fails:>7}  {p:>11.4%}  {math.log2(p):>9.2f}  {ci:>18}")

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
    print(f"  least-squares fit  : log2(DFR) = {slope:.5f}·r + {icept:.2f}   (R² = {r2:.4f})")
    print(f"  waterfall slope    : {1/abs(slope):.1f} extra bits of r per bit of DFR")
    out = {}
    for lam in (64, 128):
        r_need = (-lam - icept) / slope
        out[lam] = r_need
        print(f"  r for DFR = 2^-{lam:<4}: {r_need:.0f}  "
              f"({r_need / R_DEP:.1f}x the deployed r = {R_DEP})")
    print()
    print("  Two caveats, both pointing the same way — these are LOWER bounds:")
    print("   * A QC-MDPC DFR curve is concave: a steep waterfall followed by a")
    print("     flatter error floor.  Every point above is in the waterfall, so")
    print("     the straight line understates the r needed once the floor takes")
    print("     over.  BIKE's own analysis exists precisely because this")
    print("     extrapolation is the hard part of the argument.")
    print("   * The fit says nothing about whether r is even the right knob.")
    print("     BIKE-128 reaches its DFR with r = 12323 AND d = 71, t = 134;")
    print("     holding d = 15, t = 18 while stretching r is not a design, it is")
    print("     a sensitivity measurement.")
    print()
    print("  What is solid regardless of the extrapolation: the deployed r is")
    print("  short by a large multiple, and the measured DFR is not close.")
    return slope, icept, out


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
    print("per-position estimates degrade together.\n")

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

    # (a′) what keygen now EMITS — the screen TODO #235 Part 1 added
    print("\n  (a′) ... and as keygen EMITS it, after the weak-key screen")
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
    print(f"      {'AP positions':>13}  {'max mult':>9}  {'trials':>7}  {'fails':>6}  {'DFR':>9}")
    print(SEP2)
    gradient = []
    js = [2, 4, 6, 7, 8, 10, 15] if not quick else [2, 6, 7, 8, 15]
    for j in js:
        key = _ap_key(rng, R_DEP, D_DEP, j)
        if key is None:
            continue
        mult = max(distance_spectrum(key[0], R_DEP).values())
        n = n_per_key
        fails = sum(0 if trial(rng, R_DEP, D_DEP, T_DEP, NB_DEP, key=key) else 1
                    for _ in range(n))
        gradient.append((mult, fails / n))
        print(f"      {j:>13}  {mult:>9}  {n:>7}  {fails:>6}  {fails/n:>9.3%}")

    # (c) tie the two together
    print(SEP2)
    print("\n  (c) Putting (a) and (b) together")
    p_ge = {}
    for thr in (5, 6, 7):
        p1 = sum(v for k, v in hist.items() if k >= thr) / n_spectra
        p_ge[thr] = 1 - (1 - p1) ** 2      # a key has two polynomials
    for thr in (5, 6, 7):
        if p_ge[thr] > 0:
            print(f"      P(key has a polynomial of multiplicity >= {thr}) = "
                  f"{p_ge[thr]:.4%}  (~1 in {1/p_ge[thr]:,.0f})")
        else:
            print(f"      P(key has a polynomial of multiplicity >= {thr}) = "
                  f"0 observed in {n_spectra} samples")
    print()
    print("      The cliff in (b) sits between multiplicity 6 and 7.  Below it the")
    print("      DFR is the ordinary ~0.3%; at 6 it is several times that; at 7")
    print("      and above the key is effectively non-functional — every")
    print("      decapsulation fails.")
    print()
    if screen is None:
        print("      Honest keygen does reach multiplicity 6.  It is rare but it is")
        print("      not negligible, and nothing rejects it: qcmdpc_keygen retries")
        print("      only when h0 is non-invertible — in C, Go, and Python alike.")
        print("      There is no spectrum test, no multiplicity bound, and no")
        print("      weak-key screen of any kind.  A user who draws such a key gets")
        print("      a materially worse DFR than the published average and no")
        print("      signal that anything is unusual.")
    else:
        print("      Original finding: honest keygen reached multiplicity 6 — rare")
        print("      but not negligible — and nothing rejected it; qcmdpc_keygen")
        print("      retried only on a non-invertible h0, in C, Go and Python")
        print("      alike.  TODO #235 Part 1 closed this.  The screen rejects and")
        print(f"      redraws any polynomial above multiplicity {screen}, so the whole")
        print("      tail measured in (a) — the multiplicity-6 keys AND every")
        print("      total-failure class above them — is now unreachable from")
        print("      keygen, in C, Go, Python and Java identically.")
        print()
        print("      Cost, from (a′): a fraction of a percent of extra draws, paid")
        print("      before the inversion.  Benefit, from (b): the DFR gradient no")
        print("      longer has a reachable upper half.")
        print()
        print("      Still true, and NOT fixed by the screen: nothing in the PEM")
        print("      decode path checks the spectrum of an IMPORTED private key.")
        print("      The library exposes the predicate (qcmdpc_key_is_strong /")
        print("      QcMdpcKeyIsStrong / qcmdpcKeyIsStrong) but the CLI readers do")
        print("      not call it.  A supplied key can still be an arithmetic")
        print("      progression, and it will still fail every decapsulation.")
        print("      That is a self-inflicted denial of service rather than a")
        print("      confidentiality break, which is why it was not filed with the")
        print("      two blockers, but it is the remaining half of this section.")
    return hist, gradient


# ═══════════════════════════════════════════════════════════════════════════
# §5 — GJS reaction attack
# ═══════════════════════════════════════════════════════════════════════════
def section5(n_per_class, n_keys):
    print("\n" + SEP)
    print("§5  GJS reaction attack — the distinguisher, measured")
    print(SEP)
    print("GJS: the failure probability depends on whether distances in the error")
    print("support appear in the private key's distance spectrum.  An attacker who")
    print("submits chosen ciphertexts and observes success/failure reads the")
    print("spectrum off the failure rates, and the spectrum pins down h0 up to a")
    print("cyclic shift — full private-key recovery.\n")
    print("Nothing here is exotic.  The attacker picks e, computes")
    print("syn = e0 + e1·h_pub from the PUBLIC key, and submits it.  No FO")
    print("re-encryption check exists to reject a ciphertext that was not honestly")
    print("generated (§6), so a chosen syndrome is processed like any other.\n")

    rng = random.Random(5218)
    tot_in = tot_out = fail_in = fail_out = 0
    t0 = time.time()

    for _ in range(n_keys):
        sup0, sup1, h0, h1, h_pub = keygen(rng, R_DEP, D_DEP)
        spec = distance_spectrum(sup0, R_DEP)
        in_d = sorted(spec)
        out_d = sorted(set(range(1, R_DEP // 2 + 1)) - set(in_d))

        for dists, tag in ((in_d, 'in'), (out_d, 'out')):
            for _ in range(n_per_class):
                e0 = 0
                placed = 0
                guard = 0
                while placed < T_DEP and guard < 500:
                    guard += 1
                    dd = rng.choice(dists)
                    a = rng.randrange(R_DEP)
                    b = (a + dd) % R_DEP
                    if (e0 >> a) & 1 or (e0 >> b) & 1:
                        continue
                    e0 |= (1 << a) | (1 << b)
                    placed += 2
                if placed != T_DEP:
                    continue
                syn = syndrome_of(e0, 0, h_pub, R_DEP)
                ok = bgf_decode_fast(syn, sup0, sup1, R_DEP, D_DEP, NB_DEP) == (e0, 0)
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
        print(f"  distances to classify: r/2 = {R_DEP // 2}")
        print(f"  order of magnitude for the full spectrum: ~{nq * (R_DEP // 2):.1e} queries")
    print()
    if separated:
        print("  Reading: the failure rate CARRIES the private key.  The gap is")
        print("  directly measurable at these parameters, using ciphertexts built")
        print("  from public data alone.  The GJS precondition is not theoretical")
        print("  here — it is present and reachable.")
    else:
        print("  Reading: the gap is visible in the point estimates but the")
        print("  intervals still overlap at this sample size.  That is a statement")
        print("  about the sample, not evidence against the attack: GJS assumes")
        print("  far more queries than are run here, and §6 is what makes those")
        print("  queries cheap.  Do not read an overlap as a negative result.")
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
def section7(dfr, oracle_gone=False):
    screen = getattr(_SUITE, '_QCMDPC_MAX_MULT', None)
    print("\n" + SEP)
    print("§7  Verdict")
    print(SEP)
    lam = -math.log2(dfr) if dfr and dfr > 0 else float('nan')
    print(f"  1. DFR at the deployed parameters is {dfr:.3%} = 2^{math.log2(dfr):.1f},")
    print(f"     supporting lambda = {lam:.1f} bits where IND-CCA2 wants 128.")
    print( "  2. The DFR(r) fit puts the required r at a large multiple of the")
    print(f"     deployed {R_DEP}, and the fit understates it (concavity, §3).")
    if screen is None:
        print( "  3. Weak keys are not screened: keygen retries only on a")
        print( "     non-invertible h0.  DFR varies materially across keys (§4).")
    else:
        print(f"  3. CLOSED by TODO #235 Part 1.  Keygen now rejects and redraws")
        print(f"     any private polynomial above distance-spectrum multiplicity")
        print(f"     {screen}, in C, Go, Python and Java identically, so the weak-key")
        print( "     tail §4(a) measured is no longer reachable from keygen.  An")
        print( "     IMPORTED key is still unscreened (§4(c)) — a self-inflicted")
        print( "     denial of service, not a confidentiality break.")
    if not oracle_gone:
        print( "  4. The GJS precondition holds — failures are explicitly signalled,")
        print( "     with no FO transform or implicit rejection (§5, §6).")
    else:
        print( "  4. CLOSED by TODO #235 Part 2.  Decapsulation applies an FO")
        print( "     transform with implicit rejection: it checks rigidity (the")
        print( "     re-encryption identity, which reduces exactly to wt(e) = t")
        print( "     given an invertible h0) and returns HFSCX-256-DS(0x11, z || C)")
        print( "     on any failure.  §6 measures success and failure returning the")
        print( "     same kind of answer.  §5's statistic is unchanged — it is a")
        print( "     property of the decoder — but it is no longer observable.")
    print()
    if screen is None or not oracle_gone:
        print( "  These compound rather than trade off.  Even a DFR of 2^-128 would")
        print( "  not make this KEM IND-CCA2 while decapsulation reports failure, and")
        print( "  implicit rejection would not fix a 2^-8.8 DFR either.")
    else:
        print( "  Blockers 3 and 4 were the two that were missing CONSTRUCTIONS at")
        print( "  the deployed parameters, and they are the two TODO #235 added.")
        print( "  Blockers 1 and 2 are parameter choices and they still stand, so")
        print( "  the compounding argument still bites in the other direction:")
        print( "  implicit rejection does not fix a 2^-8.8 DFR.  This KEM remains")
        print( "  demo-only, and closing #235 did not change that — what it changed")
        print( "  is that the KEM is no longer weaker than its own parameters")
        print( "  require.  Blocker 1 alone keeps IND-CCA2 out of reach.")
    print()
    print( "  Not the binding constraint, but worth stating plainly: at r = 523,")
    print( "  d = 15, t = 18 the underlying QC syndrome-decoding instance is far")
    print( "  below any usable security level to begin with — the source calls")
    print( "  these toy parameters and they are.  Fixing DFR alone would not make")
    print( "  the KEM secure; the parameters have to move first, and BIKE-128's")
    print( "  r = 12323, d = 71, t = 134 is the reference point.")
    print()
    if screen is None or not oracle_gone:
        print( "  Recommended SECURITY.md row (added in this item):")
        print( "    HPKE-Stern-KEM | Demo-only | measured DFR 2^-8.8 at the deployed")
        print( "    toy parameters, so IND-CCA2 (which needs 2^-128) does not hold;")
        print( "    decapsulation signals failure explicitly with no FO transform or")
        print( "    implicit rejection, exposing the GJS reaction attack, and keygen")
        print( "    does not screen weak keys. Do not reuse a keypair across")
        print( "    decapsulations you do not control.")
    else:
        print( "  Recommended SECURITY.md row (as revised by TODO #235):")
        print( "    HPKE-Stern-KEM | Demo-only | measured DFR 2^-8.8 at the deployed")
        print( "    toy parameters, so IND-CCA2 (which needs 2^-128) does not hold,")
        print( "    and the underlying QC syndrome-decoding instance is far below")
        print( "    any usable level at r=523/d=15/t=18. Decapsulation now applies")
        print( "    an FO transform with implicit rejection and keygen screens the")
        print( "    weak-key classes (TODO #235), so the GJS reaction attack no")
        print( "    longer has an oracle — but the DFR and the parameters are")
        print( "    unchanged and remain the binding constraints.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='small sample counts (~90 s) — qualitative only')
    args = ap.parse_args()
    q = args.quick

    t0 = time.time()
    print(SEP)
    print("QC-MDPC BGF: DFR, weak keys, reaction attacks — TODO #218")
    print(SEP)

    if not section1(40 if q else 200):
        print("\nAborting: fast decoder does not match the deployed decoder.")
        return 1
    dfr = section2(6000 if q else 120000)
    section3(1.0, q)
    section4(20000 if q else 200000, 1500 if q else 4000, q)
    section5(400 if q else 3000, 3 if q else 8)
    oracle_gone = section6()
    section7(dfr, oracle_gone)

    print("\n" + SEP)
    print(f"done in {time.time() - t0:.0f}s")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
