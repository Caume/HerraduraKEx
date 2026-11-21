#!/usr/bin/env python3
"""
stern_f_parameter_selection.py -- what Stern-F's syndrome-decoding instance is worth,
and the smallest N at which it reaches 128 bits (TODO #382, SecurityProofs-5.md
§11.8.3).

Stern-F's shape is fixed by the suite: a random [N, k = N/2] binary code expanded
from a seed, and an error of weight t = N/16.  Forging a signature, or recovering
the key, is finding a weight-t e with H e^T = s for the one public syndrome s --
a single syndrome-decoding instance, with no quasi-cyclic structure to exploit
(the H rows are seed-expanded independently), so neither DOOM's sqrt(r) nor a
key-recovery rotation factor applies.

Until v16.0.0 the documents carried two figures this script does not reproduce:

  * "BJMM/SDE ~2^56-2^60 at N = 256" (SecurityProofs-4.md §11.7's table,
    SecurityProofs-5.md §11.8.3).  Every estimator below puts N = 256 under
    2^40 -- BJMM at about 2^24 -- which matches SECURITY.md's own "~30-40 bits"
    within its loose end and contradicts the 2^56-2^60.
  * "128-bit classical security needs N >= 17000", carried over from BIKE-128's
    N ~ 24646.  BIKE's error weight is ~sqrt(N) (t/N = 0.0054); Stern-F's is
    linear (t/N = 0.0625), and ISD cost tracks the relative distance, so each bit
    of N buys far more here.  N = 17000 is worth over 2^1000; 128 bits is reached
    near N ~ 2150.

THE MODEL.  Four closed-form estimators over GF(2), costs in log2 bit operations,
memory unconstrained:

  Prange   the original ISD; an upper bound on the instance's security.
  Dumer    Stern's meet-in-the-middle refinement, minimised over (p, l) --
           the same model as qcmdpc_parameter_selection.py.
  BJMM     depth-2 representation ISD minimised over (p, e1, l), with l1 set to
           the representation count; e1 = 0 is MMT, e1 > 0 BJMM's 1+1=0 overlaps.
  quantum  Bernstein's Grover-over-Prange (the iteration count square-rooted).

Calibration, not trust: BIKE's three published levels were chosen against the
modern estimator suite, so §1 runs the message attack at BIKE's parameters (with
DOOM's -0.5 log2 r, which BIKE's message attack does get) and requires BJMM to
land within 2 bits of every claimed level.  Dumer lands ~8 bits high, which is
the gap qcmdpc_parameter_selection.py corrects for with a flat offset; BJMM needs
no offset.  The CryptographicEstimators package was not available on the machine
this was written on, so it is not cross-checked here; the BIKE calibration is
the check.

CAVEATS.  Depth-3 BJMM, May-Ozerov and Both-May are not modelled.  The last two
are galactic at these lengths (§11.8.3's TODO #156 review); depth-3 BJMM gains at
most a few bits at rate 1/2.  Polynomial factors are the usual ones (Gaussian
elimination as (n-k)^2 (n+k)/2, list elements costed at one operation, final
candidates at n-k).  The figures are a parameter-selection guide with a few bits
of model error, which is why §3 recommends N with a margin rather than the
smallest N at which BJMM crosses 128.

  §1  Calibration against BIKE's published levels
  §2  The deployed N = 256, and the documented 2^56-2^60
  §3  The smallest N for 128 bits, the documented N >= 17000, and a recommendation

Findings gate: exits non-zero if any finding stops reproducing.  Runtime: ~10 s.
"""

import math
import sys
from math import lgamma, log

LN2 = log(2)


def lc(n, k):
    """log2 C(n, k)."""
    if k < 0 or k > n:
        return float('-inf')
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / LN2


def l2(x):
    return math.log2(x) if x > 0 else float('-inf')


def ladd(*xs):
    """log2 of a sum of terms given as log2 values."""
    m = max(xs)
    return m + math.log2(sum(2.0 ** (x - m) for x in xs))


def gauss(n, k):
    return l2((n - k) ** 2 * (n + k) / 2.0)


def prange(n, k, t):
    return lc(n, t) - lc(n - k, t) + gauss(n, k)


def quantum_prange(n, k, t):
    return (lc(n, t) - lc(n - k, t)) / 2 + gauss(n, k)


PMAX, EMAX = 64, 12


def dumer(n, k, t):
    """(log2 cost, p, l)."""
    best = None
    for l in range(0, min(n - k, 300) + 1):
        h = (k + l) // 2
        for p in range(2, min(t, PMAX) + 1, 2):
            if t - p > n - k - l:
                continue
            L = lc(h, p // 2)
            it = max(0.0, lc(n, t) - 2 * L - lc(n - k - l, t - p))
            c = it + ladd(gauss(n, k), 1 + L, 2 * L - l + l2(n - k))
            if best is None or c < best[0]:
                best = (c, p, l)
    return best


def bjmm(n, k, t, lmax=400):
    """(log2 cost, p, e1, l, l1): depth-2 representations."""
    best = None
    for p in range(4, min(t, PMAX) + 1, 2):
        for e1 in range(0, EMAX + 1):
            p1 = p // 2 + e1
            if p1 % 2:
                continue
            p2 = p1 // 2
            for l in range(0, min(n - k, lmax) + 1, 2):
                K = k + l
                if t - p > n - K or p1 > K:
                    continue
                R1 = lc(p, p // 2) + lc(K - p, e1)        # representations of e_K
                l1 = min(l, max(0, int(R1)))
                L0 = lc(K // 2, p2)
                L1 = 2 * L0 - l1
                L2 = 2 * L1 - (l - l1)
                good = lc(K, p) + lc(n - K, t - p) - lc(n, t) + min(0.0, R1 - l1)
                c = max(0.0, -good) + ladd(gauss(n, k), 2 + L0, 1 + L1, L2 + l2(n - k))
                if best is None or c < best[0]:
                    best = (c, p, e1, l, l1)
    return best


def stern_f(N):
    k, t = N // 2, N // 16
    return {'N': N, 'k': k, 't': t, 'prange': prange(N, k, t), 'dumer': dumer(N, k, t),
            'bjmm': bjmm(N, k, t), 'quantum': quantum_prange(N, k, t),
            'solutions': lc(N, t) - (N - k)}


BIKE = {128: (12323, 71, 134), 192: (24659, 103, 199), 256: (40973, 137, 264)}
DOCUMENTED_N256 = (56, 60)     # the figure §11.7 / §11.8.3 carried until v16.0.0
DOCUMENTED_BAR = 17000         # "128-bit classical needs N >= 17000"
RECOMMENDED = 2304             # 9 x 256, t = 144


FAILS = []


def check(ok, what):
    print(f"  [{'PASS' if ok else 'FAIL'}] {what}")
    if not ok:
        FAILS.append(what)


def rule(title):
    print('\n' + '=' * 78 + '\n' + title + '\n' + '=' * 78)


def section1():
    rule('1  Calibration: the message attack at BIKE\'s published levels')
    print(f"\n    {'level':>6} {'r':>6} {'t':>4} | {'Dumer':>8} {'offset':>7} | "
          f"{'BJMM':>8} {'offset':>7}")
    offs_b, offs_d = [], []
    for lam, (r, _d, t) in sorted(BIKE.items()):
        doom = 0.5 * l2(r)
        D = dumer(2 * r, r, t)[0] - doom
        B = bjmm(2 * r, r, t, lmax=200)[0] - doom
        offs_d.append(D - lam); offs_b.append(B - lam)
        print(f"    {lam:>6} {r:>6} {t:>4} | 2^{D:>6.1f} {D - lam:>+7.1f} | 2^{B:>6.1f} {B - lam:>+7.1f}")
    print()
    check(all(abs(o) <= 2.0 for o in offs_b),
          f"BJMM lands within 2 bits of every BIKE level (offsets "
          f"{', '.join(f'{o:+.1f}' for o in offs_b)})")
    check(all(o >= 5.0 for o in offs_d),
          "Dumer lands at least 5 bits high at every level (the model distinguishes them)")


def section2():
    rule('2  The deployed N = 256, k = 128, t = 16')
    S = stern_f(256)
    print(f"""
    Prange 2^{S['prange']:.1f}   Dumer 2^{S['dumer'][0]:.1f} (p, l) = {S['dumer'][1:]}
    BJMM   2^{S['bjmm'][0]:.1f} (p, e1, l, l1) = {S['bjmm'][1:]}   quantum 2^{S['quantum']:.1f}
    expected spurious solutions: 2^{S['solutions']:.1f} (the planted e is the only answer)

  The documents carried "BJMM/SDE ~2^{DOCUMENTED_N256[0]}-2^{DOCUMENTED_N256[1]}" here.  Even Prange, the
  weakest attack, is under that.
""")
    check(S['prange'] < DOCUMENTED_N256[0] - 10,
          f"Prange at N = 256 is more than 10 bits under the documented 2^{DOCUMENTED_N256[0]}")
    check(S['bjmm'][0] < 30, "BJMM at N = 256 is under 2^30")
    check(S['prange'] > S['dumer'][0] > S['bjmm'][0], "Prange > Dumer > BJMM at N = 256")


def section3():
    rule('3  The smallest N for 128 bits classical')
    print(f"\n    {'N':>6} {'t':>4} | {'Prange':>8} {'Dumer':>8} {'BJMM':>8} {'quantum':>8} | BJMM (p, e1, l, l1)")
    rows = {}
    for N in list(range(256, 2048, 256)) + list(range(2048, 2400, 32)) + [3072]:
        S = stern_f(N)
        rows[N] = S
        print(f"    {N:>6} {S['t']:>4} | 2^{S['prange']:>6.1f} 2^{S['dumer'][0]:>6.1f} "
              f"2^{S['bjmm'][0]:>6.1f} 2^{S['quantum']:>6.1f} | {S['bjmm'][1:]}")
    first = min(N for N, S in rows.items() if N >= 2048 and S['bjmm'][0] >= 128)
    R, B17 = rows[RECOMMENDED], stern_f(DOCUMENTED_BAR)
    print(f"""
  BJMM first reaches 2^128 at N = {first} (step 32).  That is a model's crossing, not a
  margin: the recommendation is N = {RECOMMENDED} (9 x 256, k = {R['k']}, t = {R['t']}), worth
  2^{R['bjmm'][0]:.1f} by BJMM and 2^{R['quantum']:.1f} quantum, about {R['bjmm'][0] - 128:.0f} bits above the crossing.
  Its expected spurious solutions number 2^{R['solutions']:.0f}: the planted e is the only answer.

  The documented bar N >= {DOCUMENTED_BAR} is worth 2^{B17['bjmm'][0]:.0f} by BJMM (t = {B17['t']}): about
  {DOCUMENTED_BAR / first:.1f}x the length 128 bits needs.
""")
    check(2048 <= first <= 2304, f"BJMM crosses 2^128 between N = 2048 and 2304 (at {first})")
    check(rows[2048]['bjmm'][0] < 128, "N = 2048 is short of 128 bits by BJMM")
    check(R['bjmm'][0] >= 135, f"N = {RECOMMENDED} has at least 7 bits over 128 by BJMM")
    check(R['quantum'] >= 100, f"N = {RECOMMENDED} is worth at least 2^100 to Grover-over-Prange")
    check(R['bjmm'][1] < PMAX and R['bjmm'][2] < EMAX,
          f"the BJMM optimum at N = {RECOMMENDED} is inside the searched p and e1 ranges")
    check(B17['bjmm'][0] > 1000, f"N = {DOCUMENTED_BAR} is worth over 2^1000")
    costs = [rows[N]['bjmm'][0] for N in sorted(rows)]
    check(all(a < b for a, b in zip(costs, costs[1:])), "BJMM cost rises with N over the table")


def main():
    section1()
    section2()
    section3()
    print()
    if FAILS:
        print(f"*** FAILED: {len(FAILS)} finding(s) did not reproduce ***")
        return 1
    print("*** OK: every finding reproduced ***")
    return 0


if __name__ == '__main__':
    sys.exit(main())
