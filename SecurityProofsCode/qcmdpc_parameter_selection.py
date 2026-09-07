#!/usr/bin/env python3
"""
qcmdpc_parameter_selection.py — picking HPKE-Stern-KEM's replacement
parameters (TODO #276, §11.8.7).

TODO #218 measured the deployed QC-MDPC set (r = 523, d = 15, t = 18) at a DFR
of 2^-8.6 where IND-CCA2 wants 2^-128, and fitted log2(DFR) = -0.0996r + 43.69
to land on r ~ 1723.  That fit is the only replacement figure the repository has
carried, and this script's first two findings are that it answers the wrong
question and names an inadmissible value:

  * The underlying syndrome-decoding instance has NEVER been costed.  §11.8.7
    and SECURITY.md both say "far below any usable security level" with no
    number; the only concrete ISD figure in the repository (2^56-2^60) is for
    the Stern-F SIGNATURE at (N, k, t) = (256, 128, 16), a different instance
    at ten times the relative distance.  §1 supplies the missing number.
  * r is the DFR knob and ALMOST NOTHING ELSE.  §3 shows the weight t needed
    for 128-bit security moves by 6 over a 12x range of r, and the row weight d
    by 2 -- so t and d are fixed by ISD essentially on their own, and no value
    of r rescues t = 18.  At r = 1723 with d and t unchanged the instance is
    worth 2^25.

  §1  What the deployed instance is actually worth (the missing number)
  §2  Calibrating the estimator against BIKE's three published levels
  §3  The frontier: t and d are the ISD knobs, r is the DFR knob
  §4  The structural constraint on r, and why 1723 is inadmissible twice over
  §5  Correctness at the candidate -- the waterfall, measured
  §6  The weak-key screen's constant, re-derived at the new d
  §7  Cost, and the one blocker
  §8  Recommendation, and what the change touches

Nothing here is extrapolated silently: every DFR statement is either a measured
count with its trial number, or is labelled a bound and attributed.

Runtime: ~3 min at default settings (§5 and §7 dominate); --quick (~1 min) cuts
every trial count and is enough for the qualitative picture but not the margins.
"""

import argparse
import importlib.util
import math
import os
import random
import sys
import time
from collections import Counter
from math import comb, log2

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def load(name, path, argv=None):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    saved, sys.argv = sys.argv, (argv or [name])
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = saved
    return mod


def rule(title):
    print()
    print('=' * 78)
    print(title)
    print('=' * 78)


def lg(x):
    return log2(x) if x > 0 else float('-inf')


# ═══════════════════════════════════════════════════════════════════════════
# Information-set decoding cost models
#
# Two estimators, both closed-form, both over GF(2) at rate 1/2:
#
#   Prange   the original ISD.  Rigorous and by far the weakest, so it is an
#            UPPER bound on the security of the instance, not a lower one.
#   Dumer    the standard meet-in-the-middle refinement (Stern's algorithm in
#            its usual modern presentation), minimised over its two internal
#            parameters p and l.  Representative of what is actually run.
#
# BJMM/MMT improve on Dumer by a handful of bits at these sizes; §2 measures
# that gap against BIKE's published levels rather than modelling it, which is
# the same move hkex_rnl_lattice_2026.py makes against Kyber and Saber.
#
# Quasi-cyclicity is worth a further speedup and it is NOT the same on the two
# attacks: a decoding attack may target any of the r cyclic shifts of the
# syndrome at once, which is DOOM [Sendrier 2011] and pays sqrt(r); a key
# recovery accepts any of the r shifts of the private polynomial as an answer,
# which pays the full r.
# ═══════════════════════════════════════════════════════════════════════════

def _gauss(n, k):
    """Column operations for one Gaussian elimination on the parity check."""
    return (n - k) ** 2 * (n + k) / 2.0


def prange(n, k, t):
    """(log2 cost, log2 iterations)."""
    it = lg(comb(n, t)) - lg(comb(n - k, t))
    return it + lg(_gauss(n, k)), it


def dumer(n, k, t, lmax=120, pmax=24):
    """(log2 cost, p, l, log2 iterations) minimised over p and l."""
    best = None
    for l in range(0, min(n - k, lmax) + 1):
        h = (k + l) // 2
        for p in range(2, min(t, pmax) + 1, 2):
            if p // 2 > h or not 0 <= t - p <= n - k - l:
                continue
            L = comb(h, p // 2)
            good = 2 * lg(L) + lg(comb(n - k - l, t - p)) - lg(comb(n, t))
            if good > 0:          # one iteration already succeeds; degenerate
                continue
            it = -good
            per = lg(_gauss(n, k) + 2.0 * L + (L * L) / float(1 << l) * (n - k))
            if best is None or it + per < best[0]:
                best = (it + per, p, l, it)
    return best


def quantum_prange(n, k, t):
    """Bernstein's quantum ISD: Grover over the iteration space only."""
    it = lg(comb(n, t)) - lg(comb(n - k, t))
    return it / 2 + lg(_gauss(n, k))


def instance(r, d, t):
    """Both attacks on a QC-MDPC instance.  Returns a dict of log2 costs."""
    n, k = 2 * r, r
    msg, key = dumer(n, k, t), dumer(n, k, 2 * d)
    return {
        'msg_prange': prange(n, k, t)[0],
        'msg_dumer': msg[0], 'msg_pl': (msg[1], msg[2]),
        'msg_doom': msg[0] - 0.5 * lg(r),
        'msg_quantum': quantum_prange(n, k, t) - 0.5 * lg(r),
        'key_prange': prange(n, k, 2 * d)[0],
        'key_dumer': key[0], 'key_pl': (key[1], key[2]),
        'key_qc': key[0] - lg(r),
        'key_quantum': quantum_prange(n, k, 2 * d) - lg(r),
    }


BIKE = {128: (12323, 71, 134), 192: (24659, 103, 199), 256: (40973, 137, 264)}


# ═══════════════════════════════════════════════════════════════════════════
# §1  What the deployed instance is actually worth
# ═══════════════════════════════════════════════════════════════════════════

def section1(dep):
    rule('1  The deployed instance, costed')
    r, d, t = dep
    print(f"""
  Deployed: r = {r}, d = {d}, t = {t}, so the syndrome-decoding instance is
  (N, k, t) = ({2*r}, {r}, {t}) over GF(2), quasi-cyclic of order 2.

  The brute-force count C({2*r}, {t}) = 2^{lg(comb(2*r, t)):.1f} appears in §11.8.7 and is
  not an attack cost -- ISD does not enumerate error vectors.  Two attacks
  matter and they must both be costed, because a QC-MDPC private key is itself
  a low-weight codeword:

    message recovery   find e of weight {t} from its syndrome        (breaks one session)
    key recovery       find the weight-{2*d} private polynomial pair  (breaks the key)
""")
    I = instance(r, d, t)
    def cell(v):
        return f"2^{v:.1f}"
    print(f"    {'attack':>18} {'Prange':>10} {'Dumer':>10} {'+ QC':>10} {'quantum':>10}")
    print('    ' + '-' * 62)
    for lbl, pre in (('message', 'msg'), ('key', 'key')):
        qc = I[pre + ('_doom' if pre == 'msg' else '_qc')]
        print(f"    {lbl:>18} {cell(I[pre+'_prange']):>10} {cell(I[pre+'_dumer']):>10} "
              f"{cell(qc):>10} {cell(I[pre+'_quantum']):>10}")
    worst = min(I['msg_doom'], I['key_qc'])
    print(f"""
  Before §2's calibration, and taking the WEAKER-attacker reading at every
  step, the deployed instance is worth about 2^{worst:.0f} classical operations -- and
  §2 takes another 8 bits off that.  A desktop reaches it.  "Far below any
  usable security level" was right; the number it was standing in for is in
  the twenties, not the fifties.

  It is also, notably, BELOW the 2^56-2^60 that §11.8.3 records for the Stern-F
  SIGNATURE at (256, 128, 16) -- despite this instance having four times the
  length.  That is the regime effect §11.8.3's own caveat warns about: ISD cost
  is driven by the relative distance t/N, and {t}/{2*r} = {t/(2*r):.4f} against the
  signature's 16/256 = 0.0625 is a factor of {0.0625/(t/(2*r)):.1f} in the direction that makes
  decoding cheap -- enough to more than cancel the length.  The signature
  figure could not have been carried over, and §11.8.3's caveat says so
  explicitly.  (TODO #276's filing text called that factor "an order of
  magnitude"; it is {0.0625/(t/(2*r)):.1f}x.  The conclusion is unchanged and the overstatement
  is corrected here.)
""")
    return worst, I


# ═══════════════════════════════════════════════════════════════════════════
# §2  Calibration
# ═══════════════════════════════════════════════════════════════════════════

def section2(dep):
    rule('2  Calibrating the estimator against BIKE')
    print("""
  Dumer is not the best known ISD, so §1's figures are optimistic about the
  instance's security by whatever BJMM/MMT gain at these sizes.  Rather than
  model that gain, measure it: BIKE's three parameter sets are published WITH
  their claimed levels, and were chosen against the full modern estimator
  suite.  The offset between this script's Dumer figure and BIKE's claim is
  the correction, and if the model is sound the offset is stable across levels.
""")
    print(f"    {'BIKE level':>12} {'r':>7} {'d':>5} {'t':>5} | "
          f"{'msg+DOOM':>10} {'key+QC':>9} {'min':>7} {'offset':>8}")
    print('    ' + '-' * 72)
    offs = []
    for lam in sorted(BIKE):
        r, d, t = BIKE[lam]
        I = instance(r, d, t)
        m = min(I['msg_doom'], I['key_qc'])
        offs.append(m - lam)
        print(f"    {lam:>12} {r:>7} {d:>5} {t:>5} | 2^{I['msg_doom']:>7.1f} "
              f"2^{I['key_qc']:>6.1f} 2^{m:>4.1f} {m - lam:>+8.1f}")
    spread = max(offs) - min(offs)
    cal = sum(offs) / len(offs)
    print(f"""
  The offset is +{cal:.1f} bits with a spread of {spread:.1f} bits across a 3.3x range of r
  and a 2x range of t.  A model that tracked the published levels only by
  accident would not hold to {spread:.1f} bits over that range, so the estimator is
  used below with a flat -{cal:.1f} bit correction and no other adjustment.

  Applied to §1: the deployed instance is worth about 2^{min(instance(*dep)['msg_doom'], instance(*dep)['key_qc']) - cal:.0f}.
""")
    return cal, spread


# ═══════════════════════════════════════════════════════════════════════════
# §3  The frontier
# ═══════════════════════════════════════════════════════════════════════════

def section3(cal, target=128):
    rule('3  The frontier — which knob is which')
    print(f"""
  For each r, the smallest t whose message attack reaches {target} bits after
  calibration, and the smallest d whose key attack does.  If r were a security
  parameter in its own right these columns would fall steeply as r grows.

  The r values here are spaced to span the range, NOT proposed as candidates:
  §4 rejects three of the six on a ground this table cannot see.
""")
    print(f"    {'r':>8} | {'min t':>7} {'cost':>9} | {'min d':>7} {'cost':>9}")
    print('    ' + '-' * 50)
    rows = []
    for r in (2003, 4801, 8191, 12323, 16001, 24659):
        n, k = 2 * r, r
        mt = next(t for t in range(10, 400)
                  if dumer(n, k, t)[0] - 0.5 * lg(r) - cal >= target)
        md = next(w for w in range(10, 400, 2)
                  if dumer(n, k, w)[0] - lg(r) - cal >= target) // 2
        rows.append((r, mt, md))
        print(f"    {r:>8} | {mt:>7} 2^{dumer(n,k,mt)[0]-0.5*lg(r)-cal:>6.1f} | "
              f"{md:>7} 2^{dumer(n,k,2*md)[0]-lg(r)-cal:>6.1f}")
    t_span = rows[0][1] - rows[-1][1]
    d_span = rows[0][2] - rows[-1][2]
    print(f"""
  Over a {rows[-1][0]/rows[0][0]:.1f}x range of r, min t moves by {t_span} and min d by {d_span}.  The
  dependence is the DOOM/QC speedup and nothing else: r enters the ISD cost
  only through sqrt(r) and r divisors, which is logarithmic in the exponent.

  So the parameters separate cleanly, and this is the finding that reframes
  the whole item:

      t and d are set by ISD, essentially independently of r.
      r is then set by DFR alone.

  Two consequences.  First, at r = 12323 the frontier lands on t = {rows[3][1]} and
  d = {rows[3][2]}, and BIKE-128 is (t, d) = (134, 71) -- this script reproduces BIKE's
  own choice to the unit, from an independent direction.  Second, TODO #218's
  fitted r = 1723 leaves t = 18 and d = 15 in place, and no entry in the table
  above is anywhere near either.  Costed directly:
""")
    for r in (523, 1723):
        I = instance(r, 15, 18)
        print(f"      r = {r:>5}, d = 15, t = 18:  2^{min(I['msg_doom'], I['key_qc']) - cal:.0f} classical")
    print(f"""
  Raising r from 523 to 1723 buys {min(instance(1723,15,18)['msg_doom'],instance(1723,15,18)['key_qc']) - min(instance(523,15,18)['msg_doom'],instance(523,15,18)['key_qc']):.0f} bits.  It was never a security fix and was
  never offered as one -- #218 fitted it to the DFR curve and labelled it a
  lower bound.  The error would have been to read it as a parameter proposal.
""")
    return rows, t_span, d_span


# ═══════════════════════════════════════════════════════════════════════════
# §4  The structural constraint on r
# ═══════════════════════════════════════════════════════════════════════════

def _is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    f = 3
    while f * f <= n:
        if n % f == 0:
            return False
        f += 2
    return True


def _ord2(r):
    o, x = 1, 2 % r
    while x != 1:
        x = x * 2 % r
        o += 1
    return o


def section4():
    rule('4  The structural constraint on r')
    print("""
  x^r - 1 over GF(2) factors as (x - 1) * f_1 * ... * f_m, and each f_i gives a
  ring homomorphism the attacker may push the instance through -- the same
  shape of hazard that made TODO #223 reject n = 768 for HKEX-RNL, where
  x^768 + 1 splits over the integers.  The standard defence, and BIKE's stated
  requirement, is to admit only r for which m = 1: r prime with 2 a primitive
  root mod r, so that x^r - 1 has exactly two irreducible factors and the only
  quotients are the whole ring and GF(2).
""")
    print(f"    {'r':>8} {'prime':>7} {'ord_2(r)':>10} {'r - 1':>8}  admissible")
    print('    ' + '-' * 54)
    verdicts = {}
    for r in (523, 1723, 2003, 4801, 8191, 12323, 24659, 40973):
        p = _is_prime(r)
        o = _ord2(r) if p else None
        ok = bool(p and o == r - 1)
        verdicts[r] = ok
        print(f"    {r:>8} {str(p):>7} {str(o) if o else '-':>10} {r-1:>8}  "
              f"{'yes' if ok else 'NO'}")
    print(f"""
  r = 1723 is prime, but ord_2(1723) = {_ord2(1723)}, a proper divisor of 1722
  (1722 = 2 * 3 * 7 * 41, and {_ord2(1723)} = 2 * 7 * 41).  So x^1723 - 1 has
  {1722 // _ord2(1723) + 1} irreducible factors over GF(2), not 2, and the ring has proper
  quotients.  **#218's fitted value is inadmissible on structural grounds as
  well as on §3's** -- two independent reasons, neither of which was visible
  from the DFR fit that produced it.  r = 8191 = 2^13 - 1 fails the same way
  and for the same reason it is a Mersenne prime.

  This is not a hypothetical: it is exactly why a QC-MDPC parameter set cannot
  be picked by fitting one curve.  Any candidate r must be checked here first.
""")
    if verdicts[1723] or not verdicts[12323]:
        return None
    return verdicts


# ═══════════════════════════════════════════════════════════════════════════
# Bit-sliced BGF decoder, valid at ANY d
#
# qcmdpc_dfr_weak_keys.py carries one of these too, but it holds the
# unsatisfied-parity counters in exactly FOUR bitplanes, so it saturates at 15
# and is correct only at the deployed d = 15.  That is fine where it is used
# and silently wrong anywhere else -- at d = 71 the saturated decoder reports
# 20 failures out of 20 at parameters that in fact decode perfectly.  This one
# sizes the planes from d, and a guard has been added to that script's copy.
# ═══════════════════════════════════════════════════════════════════════════

def _counters(s, sup, r, full, nb):
    c = [0] * nb
    for k in sup:
        v = s if k == 0 else ((s >> k) | (s << (r - k))) & full
        for i in range(nb):
            cy = c[i] & v
            c[i] ^= v
            v = cy
            if v == 0:
                break
    return c


def _mask_ge(c, full, th, nb):
    """bit j set iff the counter at j is >= th, by MSB-first comparison."""
    gt, eq = 0, full
    for i in range(nb - 1, -1, -1):
        ci = c[i]
        if (th >> i) & 1:
            eq &= ci
        else:
            gt |= eq & ci
            eq &= ~ci & full
    return (gt | eq) & full


def _bits(x):
    out = []
    while x:
        b = x & -x
        out.append(b.bit_length() - 1)
        x ^= b
    return out


def bgf_decode(syn_pub, sup0, sup1, r, d, nb_iter, thfun, tau=3):
    full = (1 << r) - 1
    nb = max(4, d.bit_length())
    s = 0
    for k in sup0:
        s ^= ((syn_pub << k) | (syn_pub >> (r - k))) & full
    e0 = e1 = 0
    th_floor = (d + 1) // 2 + 1

    for it in range(nb_iter):
        if s == 0:
            break
        th = thfun(bin(s).count('1'), d)
        c0, c1 = _counters(s, sup0, r, full, nb), _counters(s, sup1, r, full, nb)
        b0, b1 = _mask_ge(c0, full, th, nb), _mask_ge(c1, full, th, nb)
        g0 = _mask_ge(c0, full, th - tau, nb) & ~b0 & full
        g1 = _mask_ge(c1, full, th - tau, nb) & ~b1 & full
        black, gray = (_bits(b0), _bits(b1)), (_bits(g0), _bits(g1))
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
                f0 = _mask_ge(_counters(s, sup0, r, full, nb), full, th_floor, nb)
                f1 = _mask_ge(_counters(s, sup1, r, full, nb), full, th_floor, nb)
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


# The rule the suite ships: affine in d, ignoring the syndrome entirely.
def th_deployed(_syndrome_weight, d):
    return max(math.ceil(0.66 * d), (d + 1) // 2 + 2)


# BIKE Level 1's rule: affine in the SYNDROME WEIGHT (BIKE spec, §2.4.2).
def th_bike_l1(sw, _d):
    return max(int(0.0069722 * sw + 13.530), 36)


# ═══════════════════════════════════════════════════════════════════════════
# §5  Correctness at the candidate
# ═══════════════════════════════════════════════════════════════════════════

def section5(Q, dep, quick):
    rule('5  Correctness at the candidate — the waterfall, measured')
    r, d, t0 = BIKE[128]
    N = 30 if quick else 150
    print(f"""
  DFR at 2^-128 is not measurable and this section does not pretend otherwise.
  What IS measurable is where the decoder's waterfall begins in the error
  weight t, holding (r, d) = ({r}, {d}) fixed.  The margin between the chosen
  t and the onset is the quantity BIKE's own extrapolation rests on, and it is
  a direct check that the parameters and the decoder are matched.

  Two threshold rules, because they are not interchangeable:

    deployed   th = max(ceil(0.66 d), (d+1)/2 + 2), 20 iterations.  Ignores the
               syndrome weight.  At d = {d} this is th = {th_deployed(0, d)}.
    BIKE L1    th = max(floor(0.0069722 |s| + 13.530), 36), 5 iterations.
               Adapts to the syndrome as decoding progresses.

  Each cell is failures out of {N} trials, fresh key and error per trial.
""")
    rng = random.Random(2718)
    print(f"    {'t':>6} {'deployed (20 it)':>18} {'BIKE L1 (5 it)':>16}")
    print('    ' + '-' * 44)
    grid = {}
    for t in (134, 142, 150, 154, 158):
        row = []
        for thf, nb in ((th_deployed, 20), (th_bike_l1, 5)):
            f = 0
            for _ in range(N):
                key = Q.keygen(rng, r, d)
                e0, e1 = Q.random_error(rng, r, t)
                syn = Q.syndrome_of(e0, e1, key[4], r)
                if bgf_decode(syn, key[0], key[1], r, d, nb, thf) != (e0, e1):
                    f += 1
            row.append(f)
        grid[t] = tuple(row)
        print(f"    {t:>6} {f'{row[0]}/{N}':>18} {f'{row[1]}/{N}':>16}", flush=True)

    dep_onset = min((t for t in grid if grid[t][0] > 0), default=None)
    bike_onset = min((t for t in grid if grid[t][1] > 0), default=None)
    dep_tot = sum(v[0] for v in grid.values())
    bike_tot = sum(v[1] for v in grid.values())

    # The converse control, measured rather than asserted: BIKE L1's rule at
    # the DEPLOYED d, where its floor of 36 exceeds the row weight entirely.
    dr, dd, dt = dep
    conv = 0
    for _ in range(N):
        key = Q.keygen(rng, dr, dd)
        e0, e1 = Q.random_error(rng, dr, dt)
        syn = Q.syndrome_of(e0, e1, key[4], dr)
        if bgf_decode(syn, key[0], key[1], dr, dd, 5, th_bike_l1) != (e0, e1):
            conv += 1
    print(f"""
  Three results.

  (a) The chosen t = 134 sits about {(dep_onset - 134) / 134 * 100:.0f}% below the onset of failure at
      t = {dep_onset}.  Neither rule fails at the operating point in {N} trials, so this
      does not measure the DFR -- it confirms the operating point is on the
      flat part of the curve, which is the precondition for BIKE's published
      extrapolation to 2^-128 to be the relevant claim.  That extrapolation is
      BIKE's and is cited, not reproduced: it needs ~10^9 decodings per point.

  (b) The syndrome-adaptive rule is better across the transition -- {bike_tot} failures
      against {dep_tot} over the whole table -- at FOUR TIMES FEWER ITERATIONS.  The
      deployed rule's threshold is a constant once d is fixed, so as the
      syndrome thins out it
      keeps demanding {th_deployed(0, d)} of {d} unsatisfied checks and stops making progress;
      BIKE's drops with the syndrome and keeps flipping.  A parameter change
      must therefore carry the threshold rule with it -- the DFR claim belongs
      to BIKE's decoder, not to BIKE's (r, d, t) under an arbitrary decoder.

  (c) The deployed rule is nonetheless FUNCTIONAL at d = {d}, which was not
      obvious: it decodes t = 134 without failure.  So this is a parameter
      choice being made on measured margin, not a forced rewrite.

  The converse does NOT hold, which is the trap in the other direction.  BIKE
  L1's rule has a hard floor of 36, so at the deployed d = {dd} it demands more
  unsatisfied checks than a row contains.  Measured at (r, d, t) = ({dr}, {dd}, {dt}):
  {conv}/{N} failures -- it decodes nothing at all.  The constants belong to a
  parameter set, so both halves of the pair move together or neither does.

""")
    return grid, dep_onset, bike_onset, conv


# ═══════════════════════════════════════════════════════════════════════════
# §6  The weak-key screen
# ═══════════════════════════════════════════════════════════════════════════

def _spectrum_max(sup, r):
    c = Counter()
    for i in range(len(sup)):
        for j in range(i + 1, len(sup)):
            dd = abs(sup[i] - sup[j])
            c[min(dd, r - dd)] += 1
    return max(c.values())


def section6(dep, quick):
    rule('6  The weak-key screen, re-derived')
    N = 2000 if quick else 20000
    rd, dd, _ = dep
    br, bd, _ = BIKE[128]
    print(f"""
  QCMDPC_MAX_MULT = 5 rejects a key whose distance spectrum has any multiplicity
  above 5.  TODO #218 read that constant off a measured DFR cliff at d = {dd},
  r = {rd}: multiplicity 6 is where the failure rate departs from the ordinary
  one.  The cliff is a property of the distribution, and the distribution is a
  property of (r, d) -- {dd} positions give {dd*(dd-1)//2} pairwise distances over {rd//2}
  buckets, while {bd} positions give {bd*(bd-1)//2} over {br//2}.  Carrying the
  constant across is not a null change.

  Sampled max-multiplicity, {N} random supports at each parameter set:
""")
    rng = random.Random(31337)
    dists = {}
    for r, d in ((rd, dd), (br, bd)):
        c = Counter(_spectrum_max(sorted(rng.sample(range(r), d)), r)
                    for _ in range(N))
        dists[(r, d)] = c
        tot = sum(c.values())
        acc = 0
        print(f"    r = {r}, d = {d}:")
        for k in sorted(c):
            acc += c[k]
            print(f"        multiplicity {k}: {c[k]/tot*100:6.2f}%    "
                  f"<= {k}: {acc/tot*100:6.2f}%")
        print()

    def reject(c, lim):
        tot = sum(c.values())
        return sum(v for k, v in c.items() if k > lim) / tot

    old = reject(dists[(rd, dd)], 5)
    new5 = reject(dists[(br, bd)], 5)
    # Criterion, stated rather than fitted: the smallest limit whose rejection
    # rate stays under 0.5%, i.e. under one keygen retry in 200.  An exact
    # quantile match to the deployed 0.03% is NOT used -- that rate sits at the
    # sampling floor here, and the answer it gives flips between 6 and 7 with
    # the trial count, which is not a basis for a shipped constant.
    BUDGET = 0.005
    match = min((lim for lim in range(2, 12)
                 if reject(dists[(br, bd)], lim) < BUDGET), default=None)
    print(f"""  At d = {dd} the constant 5 sits in the far tail: it rejects {old*100:.2f}% of keys.
  At d = {bd} the SAME constant rejects {new5*100:.2f}% -- multiplicity 4 is now the mode
  and 5 is barely above the median.  The screen has changed character: from
  "discard a freak" to "discard a common key".

  Setting it again.  The principled route is to re-measure the cliff, and that
  route is closed: it means locating the multiplicity at which DFR departs, at
  parameters whose DFR is below anything measurable.  #218 could do it at
  r = {rd} precisely BECAUSE the DFR was 2^-8.6.  The measurement that justified
  the constant is the one the parameter change exists to eliminate.

  So a surrogate, stated in advance rather than fitted: keep the screen a tail
  cut that costs under one keygen retry in 200, i.e. a rejection rate under
  {BUDGET*100:.1f}%.  That gives **MAX_MULT = {match}** ({reject(dists[(br,bd)], match)*100:.2f}% rejected), and it excludes
  5 ({new5*100:.2f}%) by a factor of {new5/BUDGET:.1f} that no sample size of this order can
  move.  An exact quantile match to the deployed {old*100:.2f}% was tried first and
  discarded: {old*100:.2f}% is at this sampler's resolution floor ({1/N*100:.3f}% per
  observation), and the limit it selects flips between 6 and 7 with the trial
  count.  A constant that depends on how long the script ran is not a
  constant.

  So MAX_MULT = {match} is recorded as a retry-budget choice and NOT as a
  re-measured cliff -- and the cliff question
  handed to TODO #250, which is the item that owns decoder behaviour and which
  now has a reason to look at it.  Note also that BIKE ships no such screen at
  all: at r = {br} the GJS reaction attack needs a query volume that the
  large r already denies, so the screen is this suite's own belt-and-braces
  and its constant is this suite's to justify.

  What no existing check would catch: the constant is duplicated in four
  languages (herradura.h QCMDPC_MAX_MULT, Go qcMdpcMaxMult, Python
  _QCMDPC_MAX_MULT, Stern.java QCMDPC_MAX_MULT) and spec/ reads herradura.h
  alone, so a partial update is invisible.  Test [51] additionally pins its
  supports at d = {dd} with the accept case sitting exactly ON the threshold, so
  all four pinned vectors are void at any other d.
""")
    return old, new5, match


# ═══════════════════════════════════════════════════════════════════════════
# §7  Cost
# ═══════════════════════════════════════════════════════════════════════════

def section7(S, Q, dep, quick):
    rule('7  Cost, and the one blocker')
    rng = random.Random(9)
    print("""
  Decapsulation in the SHIPPED Python decoder, which computes its unsatisfied-
  parity counts with a Python-level loop over r * d positions.
""")
    sets = [dep, (2003, 25, 40), BIKE[128]] if quick else \
           [dep, (2003, 25, 40), (4813, 45, 90), BIKE[128]]
    print(f"    {'r':>7} {'d':>5} {'t':>5} {'pk/ct':>8} {'ms/decap':>11} {'vs now':>9}")
    print('    ' + '-' * 50)
    base = None
    for r, d, t in sets:
        S._QCMDPC_R, S._QCMDPC_D, S._QCMDPC_T = r, d, t
        reps = 1 if r > 8000 else (3 if r > 2500 else 10)
        tot = 0.0
        for _ in range(reps):
            key = Q.keygen(rng, r, d)
            e0, e1 = Q.random_error(rng, r, t)
            syn = Q.syndrome_of(e0, e1, key[4], r)
            t0 = time.time()
            S.qcmdpc_bgf_decode(syn, key[2], set(key[0]), set(key[1]))
            tot += time.time() - t0
        ms = tot / reps * 1000
        base = base or ms
        print(f"    {r:>7} {d:>5} {t:>5} {(r+7)//8:>7}B {ms:>11.1f} {ms/base:>8.0f}x",
              flush=True)
    S._QCMDPC_R, S._QCMDPC_D, S._QCMDPC_T = dep

    # the bit-sliced decoder, same instance
    r, d, t = BIKE[128]
    reps = 2 if quick else 6
    tot = 0.0
    for _ in range(reps):
        key = Q.keygen(rng, r, d)
        e0, e1 = Q.random_error(rng, r, t)
        syn = Q.syndrome_of(e0, e1, key[4], r)
        t0 = time.time()
        bgf_decode(syn, key[0], key[1], r, d, 5, th_bike_l1)
        tot += time.time() - t0
    fast_ms = tot / reps * 1000
    print(f"""
  Keys and ciphertexts grow from 66 to {(r+7)//8} bytes, which is unremarkable --
  BIKE's own sizes, and smaller than most of what this suite already emits.

  The decode time is the blocker.  Multi-second decapsulation would put the
  Python CLI outside every CliTest script's patience and outside any plausible
  use, and it is not intrinsic: the same instance under the bit-sliced
  representation §5 uses -- counters as bitplanes over big integers, carry-save
  updated -- decodes in {fast_ms:.0f} ms in the same interpreter.

  So the parameter change carries a REWRITE of the Python decoder with it, and
  that rewrite is a prerequisite rather than a follow-up.  C and Go compute the
  same counts over uint8 arrays and scale as r * d with a small constant; they
  need no representation change, though C's qcmdpc_bgf_decode holds four
  uint16_t[r] work arrays plus two uint8_t[r] on the stack, which is ~123 KB at
  r = {r} against ~7 KB today -- fine on a desktop, worth a deliberate look
  before assuming it.
""")
    return fast_ms


# ═══════════════════════════════════════════════════════════════════════════
# §8  Recommendation
# ═══════════════════════════════════════════════════════════════════════════

def section8(cal, worst_dep, match_mult, fast_ms):
    rule('8  Recommendation')
    r, d, t = BIKE[128]
    I = instance(r, d, t)
    print(f"""
  Adopt BIKE-128 verbatim:  r = {r}, d = {d}, t = {t}, with BIKE's
  syndrome-adaptive threshold rule and NbIter = 5.

    security     2^{I['msg_doom']-cal:.0f} classical message recovery, 2^{I['key_qc']-cal:.0f} key recovery,
                 2^{I['msg_quantum']:.0f} / 2^{I['key_quantum']:.0f} quantum, against a 128-bit target
    correctness  waterfall onset measured at t ~ 150 for t = 134 deployed;
                 DFR <= 2^-128 is BIKE's published extrapolation, CITED
    sizes        {(r+7)//8}-byte keys and ciphertexts, up from 66
    cost         ~{fast_ms:.0f} ms decapsulation in Python once the decoder is
                 bit-sliced; multi-second without that rewrite

  Rejected, with reasons:

    r = 1723, d = 15, t = 18   #218's DFR fit.  Worth 2^{min(instance(1723,15,18)['msg_doom'],instance(1723,15,18)['key_qc'])-cal:.0f} (§3), and
                 structurally inadmissible because ord_2(1723) != 1722 (§4).
    a new set    §3's frontier at r = {r} lands on exactly BIKE's (t, d).
                 There is nothing left to choose: a set derived here would be
                 BIKE-128 with a different r, and r's only remaining job is the
                 DFR, which is precisely the quantity this repository cannot
                 measure and BIKE has already published.  Inventing a set means
                 owning a DFR extrapolation with no data behind it.
    BIKE-192/256 correct but 2x and 3.3x the r for a target nothing else in the
                 suite claims; the classical quartet is a 256-bit-block design
                 with far weaker guarantees.
    keep 523     the row is demo-only and honestly labelled, so this is a real
                 option.  It is rejected because the label is now the ONLY
                 thing standing between a 2^{worst_dep-cal:.0f} instance and a caller who
                 reads "KEM" -- and because §3 shows the fix is not a research
                 problem, it is a constant change plus a decoder rewrite.

  MAJOR, with a MIGRATING.md entry: r sizes the wire format, so every
  HPKE-STERN-KEM key and ciphertext and every HYBRID-RNL-STERN artifact
  carrying one becomes unreadable.  Nothing is deployed and the row has no
  compatibility claim, so this is bookkeeping, not breakage.

  What the change touches, beyond the four constants:

    the threshold rule     in all four languages, and it is not a constant --
                           it is a different FUNCTION of a different argument
                           (§5).  NB_ITER 20 -> 5 comes with it.
    the Python decoder     rewrite to bitplanes, prerequisite (§7).
    QCMDPC_MAX_MULT        5 -> {match_mult} on a quantile match, in four languages that
                           nothing cross-checks (§6).
    test [51]              pinned supports are all at d = 15; four languages.
    KAT/                   any pinned Stern-KEM artifact.
    CliTest/lib_dfr.sh     its retries become dead code at the new DFR.  That
                           is the desired end state, but ci.yml's guard then
                           mandates sourcing a policy that can never fire, and
                           should be re-justified rather than left asserting
                           nothing.
    spec/, SECURITY.md     the demo-only classification and its stated reason,
                           which check_security_md.py holds to each other.
    .s / .asm / .ino       already at r = 32 and far below any claim; leave
                           them and label demo-only, as #223 did for RNL.

  On #250.  It asked whether better BGF variants close the DFR gap and
  deprioritised itself pending this item.  §5(b) is a partial answer already:
  the threshold rule alone is worth several t of margin at four times fewer
  iterations, which is a decoder change with no parameter cost.  #250 should be
  re-pointed at the new parameters, and inherits §6's cliff question.
""")


# ═══════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='fewer trials in §5-§7 (~70 s)')
    args = ap.parse_args()
    print(__doc__.split('\n', 1)[1].split('  §1')[0].strip())

    S = load('suite', os.path.join(_ROOT, 'Herradura cryptographic suite.py'))
    Q = load('dfr', os.path.join(_HERE, 'qcmdpc_dfr_weak_keys.py'))
    dep = (S._QCMDPC_R, S._QCMDPC_D, S._QCMDPC_T)

    fail = []
    worst, _ = section1(dep)
    if worst > 64:
        fail.append('§1: deployed instance no longer costs below 2^64')

    cal, spread = section2(dep)
    if spread > 3.0:
        fail.append(f'§2: calibration offset spread {spread:.1f} bits > 3')

    rows, t_span, d_span = section3(cal)
    if t_span > 20 or d_span > 6:
        fail.append(f'§3: frontier moved with r (t {t_span}, d {d_span})')
    if (rows[3][1], rows[3][2]) != (BIKE[128][2], BIKE[128][1]):
        fail.append(f'§3: frontier at r=12323 is {rows[3][1:]} not BIKE-128\'s')

    if section4() is None:
        fail.append('§4: admissibility of 1723 / 12323 changed')

    grid, dep_onset, bike_onset, conv = section5(Q, dep, args.quick)
    if grid[134] != (0, 0):
        fail.append('§5: t=134 no longer decodes without failure')
    if dep_onset is None or bike_onset is None:
        fail.append('§5: no waterfall onset reached inside the sampled range')
    elif sum(v[1] for v in grid.values()) > sum(v[0] for v in grid.values()):
        fail.append('§5: BIKE threshold no longer beats the deployed rule')
    if conv < 0.9 * (30 if args.quick else 150):
        fail.append(f'§5: BIKE L1 threshold no longer fails at d=15 ({conv} fails)')

    old, new5, match = section6(dep, args.quick)
    if not (old < 0.01 <= new5):
        fail.append(f'§6: rejection rates {old:.4f}/{new5:.4f} no longer straddle 1%')
    if match != 6:
        fail.append(f'§6: retry-budget MAX_MULT is {match}, not 6')

    fast_ms = section7(S, Q, dep, args.quick)
    section8(cal, worst, match, fast_ms)

    print()
    if fail:
        print('*** FAILED: findings did not reproduce ***')
        for f in fail:
            print('   ', f)
        return 1
    print('*** OK: every finding reproduced ***')
    return 0


if __name__ == '__main__':
    sys.exit(main())
