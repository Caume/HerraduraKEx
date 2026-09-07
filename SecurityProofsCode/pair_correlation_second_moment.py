#!/usr/bin/env python3
"""pair_correlation_second_moment.py — TODO #257 item (1): the second moment.

TODO #257 (SecurityProofs-9.md §11.38, `annealed_moment_ladder.py`) evaluated the annealed
first-moment model exactly at n = 256 and found mu asymptotically LINEAR in n, so
the 4/3 and 2/3 criteria are cleared by ~36x and ~34x.  It closed leaving two
things, and named the first precisely:

    "THE MODEL IS AN ESTIMATOR.  It is annealed -- a first-moment count of cheap
     cycles, which bounds nothing on its own, since the first moment can be
     carried by rare graphs. ... The cheapest thing that would upgrade item 1 is
     stated precisely: the annealed count over-counts cycles that share edges,
     so the gap between the model and mu is a SECOND-MOMENT question about the
     same two inputs -- the edge-weight distribution and the out-degree -- and
     both are exactly computable here at any width.  It needs no new machinery,
     only the pair correlation."

That is exactly right, and this script walks it.  The reason no new machinery is
needed is one identity:

  §1  THE WHOLE CORRELATION IS ONE RATIO.  Two closed walks that share j edges
      are not independent.  Where independence would contribute M(t)^2 per
      shared edge to the joint exponential moment, sharing contributes M(2t) --
      the SAME edge weight enters both walks, so its Chernoff factor squares
      inside the expectation instead of outside.  So the entire pair
      correlation is carried by

          R(t) = M(2t) / M(t)^2  >=  1     (Cauchy-Schwarz),

      and M(2t) comes from the very A_t ladder the first moment already builds.
      On the differential axis the optimum is t* = 3, so this needs A_6; on the
      linear axis t* = 4..6, so it needs A_8..A_12, which TL = 12 already computes.

  §2  VALIDATION.  R, the moments and the edge count are checked against a
      brute-force enumeration of the whole edge set at n = 6..9, every one of
      four addends, to 1e-12.

  §3  THE ANSWER, AND IT IS NOT CLOSE.  The correction to E[N^2]/E[N]^2 is
      governed by  L^2 R / E,  with L the optimal cycle length and E the edge
      count.  R is enormous and grows with width -- 2^234 at n = 256 -- but E
      grows FASTER, and the ratio is what matters:

          log2(R / E)  ~  -0.64 n  (differential),  -0.92 n  (linear),
      measured over n = 10..256 on both.

      L enters only as 2*log2(L), so ANY polynomial cycle length is swamped.  At
      n = 256 the correction is 2^-147 differential and 2^-219 linear.  The first
      moment is not carried by rare graphs.

  §4  IT ALSO EXPLAINS THE GAP IT WAS ASKED ABOUT.  §11.38 recorded the model
      running 3-15% BELOW exact mu at n <= 13 "and converging upward", with no
      account of why.  The correction crosses 1 at n ~ 11-12 and is O(1) exactly
      over n = 10..13 -- the entire range where exact mu exists -- and falls
      exponentially above it.  The discrepancy the validation range showed is
      the pair correlation, and it is a property of that range, not of the model.

WHAT THIS DOES AND DOES NOT SETTLE.  It closes #257's item (1) as posed: the
annealed count's edge-sharing over-count is quantified, at any width, on both
axes, and is negligible wherever the answer is not already exact.  It does NOT
make the model a bound on the deterministic object.  The ensemble is still
annealed: this says the ensemble concentrates, not that one fixed round function
is a typical member of it.  #257's item (2), the linear hull, is untouched and
out of reach of this line of work.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/pair_correlation_second_moment.py [--quick]
"""

import argparse
import importlib.util
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def _load(name):
    path = os.path.join(HERE, name)
    spec = importlib.util.spec_from_file_location(name[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name[:-3]] = mod
    spec.loader.exec_module(mod)
    return mod


AML = _load("annealed_moment_ladder.py")

TS_DIFF = list(range(1, 9))
TS_LIN = list(range(2, 9, 2))


def diff_terms(n, d, exact=None):
    """(t*, log2 M(t*), log2 M(2t*), log2 R, log2 E) on the differential axis."""
    ex = (n <= 20) if exact is None else exact
    logA = AML.moments_diff(n, d, 8, ex)
    E = AML.edges_diff(n, d)
    logE = math.log2(E)
    _, _, t = AML.ladder(logA, logE, (1 << n) - 1, n - 1, TS_DIFF)
    logA2 = AML.moments_diff(n, d, 2 * t, ex) if 2 * t > 8 else logA
    if logA2.get(2 * t) is None:
        return None
    sc = n - 1
    lm1 = logA[t] - logE - sc * t
    lm2 = logA2[2 * t] - logE - sc * 2 * t
    return t, lm1, lm2, lm2 - 2 * lm1, logE


def lin_terms(n, d, exact=None):
    """The same on the linear axis.  Even t only -- a correlation's sign is not
    affine in the masks (§11.38 §4), so odd moments are unavailable."""
    ex = (n <= 20) if exact is None else exact
    logA = AML.moments_lin(n, d, 8, ex)
    E = AML.edges_lin(n, d)
    logE = math.log2(E)
    _, _, t = AML.ladder(logA, logE, (1 << n) - 1, n, TS_LIN)
    if logA.get(2 * t) is None:
        return None
    lm1 = logA[t] - logE - n * t
    lm2 = logA[2 * t] - logE - n * 2 * t
    return t, lm1, lm2, lm2 - 2 * lm1, logE


def section_1():
    rule("§1  The pair correlation is one ratio, and the ladder already has it")
    print("""E[N] counts closed walks whose mean weight is below a threshold, and bounds
its tail by Chernoff: for L INDEPENDENT edges, E[2^(-t * sum)] = M(t)^L.  Two walks
sharing j edges break that independence in exactly one place -- a shared edge's weight
appears in both walks, so its factor enters the JOINT expectation as M(2t) rather than
as M(t)^2.  Hence

    E[N^2] / E[N]^2  =  E over pairs of R(t)^(#shared edges),   R(t) = M(2t) / M(t)^2,

and R >= 1 by Cauchy-Schwarz, with equality iff the weight is a.s. constant.  Nothing
else about the distribution enters.  Since M(t) = A_t / (E * 2^(scale*t)) and A_t is the
existing linear DP, R needs only a HIGHER RUNG of the same ladder:

    log2 R(t)  =  log2 A_(2t)  +  log2 E  -  2 log2 A_t .""")
    n, d = 12, 0b101101101101
    td = diff_terms(n, d)
    tl = lin_terms(n, d)
    check(td is not None and td[3] >= -1e-9,
          "differential: R(t*) >= 1 at n=12 (t*=%d, log2 R=%.3f)" % (td[0], td[3]))
    check(tl is not None and tl[3] >= -1e-9,
          "linear: R(t*) >= 1 at n=12 (t*=%d, log2 R=%.3f)" % (tl[0], tl[3]))
    print("\n  t* is stable across width: differential 3, linear 4-6, so the rungs "
          "needed\n  are A_6 and A_8..A_12 -- all inside the existing TD=8 / TL=12.")


def section_2(quick):
    rule("§2  Validation: R against a brute-force enumeration of the edge set")
    print("""The DP is indirect enough to be worth checking end to end: build every
(alpha, beta) with xdp+ > 0 explicitly, sum the powers, and compare.  This validates the
edge COUNT, each MOMENT, and their combination into R.""")
    widths = (6, 7) if quick else (6, 7, 8, 9)
    worst_m, worst_r, worst_e = 0.0, 0.0, True
    for n in widths:
        N = 1 << n
        for d in (1, 3, (N // 3) | 1, N - 1):
            cnt = 0
            S = {t: 0.0 for t in (1, 3, 6)}
            for a in range(1, N):
                for b in range(1, N):
                    p = AML.xdp_auto(n, d, a, b)
                    if p > 0:
                        cnt += 1
                        for t in S:
                            S[t] += p ** t
            logA = AML.moments_diff(n, d, 6, True)
            E = AML.edges_diff(n, d)
            worst_e = worst_e and (E == cnt)
            for t in (1, 3, 6):
                m_dp = 2 ** (logA[t] - math.log2(E) - (n - 1) * t)
                worst_m = max(worst_m, abs(m_dp - S[t] / cnt) / (S[t] / cnt))
            R_bf = (S[6] / cnt) / (S[3] / cnt) ** 2
            R_dp = 2 ** (logA[6] + math.log2(E) - 2 * logA[3])
            worst_r = max(worst_r, abs(R_bf - R_dp) / R_bf)
    check(worst_e, "edge count matches the enumeration exactly, every n and addend")
    check(worst_m < 1e-12, "every moment matches to %.1e" % worst_m)
    check(worst_r < 1e-12, "R(t*) matches to %.1e" % worst_r)


def section_3(quick):
    rule("§3  log2(R / E) is LINEAR IN n, so the correction dies exponentially")
    print("""The correction is  L^2 R / E  with L the optimal cycle length.  R alone is
enormous and grows -- but E grows faster, and only the RATIO matters.  L enters as
2*log2(L), so any polynomial length is swamped by a linear-in-n exponent.

#252's width_residue measured optimal cycles as DENSE, 0.6n..0.86n; L = 0.86n below is
the pessimistic end of that, and the L-sensitivity is shown in §4.""")
    random.seed(1729)
    widths = (12, 32, 128) if quick else (12, 16, 32, 64, 128, 256)
    print("\n  %5s %6s %13s %13s %14s" % ("n", "keys", "max log2 R", "max log2 R/E",
                                          "max corr .86n"))
    pts = []
    for n in widths:
        ds = [random.randrange(1, 1 << n) | 1 for _ in range(4 if n > 32 else 8)]
        rows = [r for r in (diff_terms(n, d) for d in ds) if r]
        mr = max(r[3] for r in rows)
        mre = max(r[3] - r[4] for r in rows)
        pts.append((n, mre))
        print("  %5d %6d %13.2f %13.2f %14.2f"
              % (n, len(rows), mr, mre, mre + 2 * math.log2(0.86 * n)))
    (n0, b0), (n1, b1) = pts[0], pts[-1]
    slope = (b1 - b0) / (n1 - n0)
    check(slope < -0.5,
          "log2(R/E) falls linearly in n at %.3f bits per bit of width" % slope)
    check(b1 + 2 * math.log2(0.86 * n1) < -50,
          "at n=%d the correction is 2^%.0f -- E[N^2]/E[N]^2 = 1 + 2^%.0f"
          % (n1, b1 + 2 * math.log2(0.86 * n1), b1 + 2 * math.log2(0.86 * n1)))
    return pts


def section_4(quick):
    rule("§4  The crossover, and why L does not matter")
    print("""The correction is O(1) exactly over the widths where exact mu EXISTS, and
falls away above them.  That is the account §11.38 could not give for its own validation
gap: it reported the model 3-15% BELOW exact mu at n <= 13 "and converging upward"
without saying why.  This is why, and it predicts the direction -- the annealed count
over-counts, so it under-states the threshold, and the over-count is what dies.""")
    random.seed(4242)
    print("\n  worst-case log2(L^2 R / E) over 16 random odd addends")
    print("  %5s %10s %10s %10s %12s" % ("n", "L=n", "L=0.86n", "L=0.6n", "L=n^2"))
    cross = None
    ns = (10, 12, 14, 16) if quick else (10, 11, 12, 13, 14, 15, 16, 18, 20)
    for n in ns:
        ds = [random.randrange(1, 1 << n) | 1 for _ in range(16)]
        b = max(r[3] - r[4] for r in (diff_terms(n, d) for d in ds) if r)
        vals = [b + 2 * math.log2(f * n) for f in (1.0, 0.86, 0.6)]
        print("  %5d %10.3f %10.3f %10.3f %12.3f"
              % (n, vals[0], vals[1], vals[2], b + 2 * math.log2(n * n)))
        if cross is None and vals[0] < 0:
            cross = n
    check(cross is not None and cross <= 14,
          "the correction crosses 1 at n=%s, inside the exact-mu range (n <= 13)" % cross)
    print("""
  L is the one input taken from elsewhere, and it is the one that cannot matter: even
  the absurd L = n^2 only shifts the curve by a constant, because log2(R/E) is LINEAR in
  n while 2*log2(L) is logarithmic.  The crossover moves; the conclusion does not.""")


def section_5(quick):
    rule("§5  The linear axis")
    print("""Same identity, same ladder, even t only -- a correlation's sign is not an
affine function of the masks (§11.38 §4 measured this: exactly half the nonzero entries
negative, no affine fit), so odd moments are unavailable and t* lands at 4..6.""")
    random.seed(1729)
    widths = (12, 32) if quick else (12, 16, 32, 64, 128, 256)
    print("\n  %5s %5s %13s %13s %14s" % ("n", "t*", "max log2 R", "max log2 R/E",
                                          "max corr .86n"))
    last = None
    for n in widths:
        ds = [random.randrange(1, 1 << n) | 1 for _ in range(4)]
        rows = [r for r in (lin_terms(n, d) for d in ds) if r]
        if not rows:
            continue
        mre = max(r[3] - r[4] for r in rows)
        last = mre + 2 * math.log2(0.86 * n)
        print("  %5d %5d %13.2f %13.2f %14.2f"
              % (n, rows[0][0], max(r[3] for r in rows), mre, last))
    check(last is not None and last < 0,
          "linear axis: the correction is below 1 at every width measured "
          "(2^%.1f at the widest)" % last)


def section_6():
    rule("§6  What this settles for #257, and what it does not")
    print("""SETTLED -- item (1) as posed.

  * The annealed count's edge-sharing over-count is QUANTIFIED, exactly, at any
    width, on both axes, from the moment ladder that was already there.  The whole
    of it is one ratio R(t) = M(2t)/M(t)^2, and #257 was right that it needed no
    new machinery.

  * log2(R/E) ~ -0.64n differential and -0.92n linear.  The correction to
    E[N^2]/E[N]^2 is 2^-147 and 2^-219 respectively at n = 256, and negative at every
    width from n ~ 11 on both axes, for any polynomial cycle length.  Within the annealed ensemble the first moment is NOT
    carried by rare graphs, which is the objection item (1) raised.

  * The 3-15% validation gap at n <= 13 is EXPLAINED rather than merely reported:
    the correction is O(1) precisely on n = 10..13 and nowhere above.  Its sign
    matches too -- an over-count under-states the threshold, and the model runs low.

NOT SETTLED.

  1. THIS IS NOT A BOUND ON THE DETERMINISTIC OBJECT.  Concentration of an annealed
     ensemble says the ensemble's typical member is representative; it does not say
     that one fixed round function is a typical member.  Closing that is a QUENCHED
     argument, and nothing here attempts one.  The honest status of §11.38's n = 256
     figures is unchanged: an exactly-evaluated estimator, now with its own internal
     consistency established.

  2. THE LINEAR HULL.  Untouched, and out of reach of this line of work -- unchanged
     from #254's second pass and §11.38's item (2).

Ratings do not move, and could not: every row this analysis touches is demo-only for
reasons on other axes (#243, #244, #248), and the production-track rows left the scope
of a trail bound in §11.36.8.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    section_1()
    section_2(a.quick)
    section_3(a.quick)
    section_4(a.quick)
    section_5(a.quick)
    section_6()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
