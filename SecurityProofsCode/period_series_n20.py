#!/usr/bin/env python3
"""period_series_n20.py — TODO #257 (fourteenth pass): one more period, to n = 20, in
the n = 2 (mod 3) series -- E[mu] still rises, the fall goes on, and the two residue
classes now fall by the SAME factor per period.

§11.50 (period_series_n19.py) measured P(n) = E[mu_{n+3}] - E[mu_n] to n = 19 and
found the per-period increment falling faster than §11.49 had read.  This pass adds
the period that starts at n = 17 -- one exact solve at n = 20 per pair, ~1-2 min and
up to 4.1 GB each -- so that both residue classes reach the same depth.

  §1  THE PINNED SAMPLE.  500 pairs per axis from period_series_n19.py's own draws()
      (seed 2257, start n = 17), pinned in period_series_n20.json because the cell is
      ~26 h of CPU.  The gate shows the file is the WHOLE seeded sample and re-solves
      a prefix of it.

  §2  THE SERIES TO n = 20.
      (a) E[mu_17] agrees between two independent samples -- the end of P(14)
          (period_series_n19.json) and the start of P(17) (this file).
      (b) E[mu] still RISES over the new period: P(17) is 27 / 33 standard errors
          above zero.
      (c) P falls again in the n = 2 (mod 3) series, on both axes (9.4 and 5.4
          standard errors).
      (d) The two series fall by the SAME factor per period: P(16)/P(13) and
          P(17)/P(14) agree on both axes (0.68 / 0.68 differential, 0.79 / 0.83
          linear).
      (e) In the n = 2 series the differential exponent now steepens too, -0.80 to
          -2.17 -- the step §11.50 printed as NOT steepening.
      E[mu_20] = 2.67 / 1.35: 2.00x and 2.03x the 4/3 and 2/3 criteria.

  §3  WHERE A CONSTANT RATIO WOULD LEAVE E[mu].  Printed, not scored: if every later
      period kept the measured ratio, E[mu] would level near 3.1 differential and
      2.0 linear.  This is a scenario, not a bound -- §11.50 already saw the ratio
      itself fall once.

  §4  WHAT THIS CHANGES.  Prose.

The verdicts are computed from the two pinned files, so they cannot flake; the
re-solves use the certified C solver, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/period_series_n20.py [--quick | --full]
      --quick      : re-solve 1 pinned pair per axis         (~3 min on an aarch64 SBC)
      default      : re-solve 4 per axis                     (~12 min)
      --full       : re-solve every pinned pair              (~26 h single-core)
      --regenerate : rebuild period_series_n20.json in parallel, then exit (~7 h on
                     4 cores; one differential n = 20 solve can need 4.1 GB, so
                     keep --workers x 4.1 GB under the free memory)
"""

import argparse
import importlib.util
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "period_series_n20.json")
FAIL = []

N0, K = 17, 500
NAME = {0: "differential", 1: "linear"}
CRITERION = {0: 4 / 3, 1: 2 / 3}


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
    argv, sys.argv = sys.argv, [name]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


PS = _load("period_series_n19.py")   # draws(), period_stats(), load_pinned(), curvature()
PE = PS.PE                           # exponent()
ESL = PS.ESL                         # the certified C solver


def regenerate(workers):
    from multiprocessing import Pool
    ESL.build()
    cells = []
    with Pool(workers) as pool:
        for axis in (0, 1):
            jobs = [(N0, axis, d, e, ESL.EXE) for d, e in PS.draws(N0, K, axis)]
            mus = pool.map(PS._solve, jobs, chunksize=1)
            cells.append({"n": N0, "axis": axis,
                          "mu": [[round(a, 9), round(b, 9)] for a, b in mus]})
            print("  n = %d, %s: %d pairs" % (N0, NAME[axis], K), flush=True)
    what = ("TODO #257 fourteenth pass: exact mu (certified_cycle_mean.c) of each "
            "(delta, three-bit insertion) pair drawn by period_series_n19.py's draws() "
            "(seed %d) for the period starting at n = %d, in draw order: "
            "[mu_%d(delta), mu_%d(inserted)]." % (PS.SEED, N0, N0, N0 + 3))
    with open(PINNED, "w") as f:
        f.write('{"what": %s,\n "seed": %d,\n "cells": [\n' % (json.dumps(what), PS.SEED))
        f.write(",\n".join('  {"n": %d, "axis": %d, "mu": %s}'
                           % (c["n"], c["axis"], json.dumps(c["mu"], separators=(",", ":")))
                           for c in cells))
        f.write("\n ]}\n")


def load_pinned():
    with open(PINNED) as f:
        doc = json.load(f)
    return doc["seed"], {(c["n"], c["axis"]): c["mu"] for c in doc["cells"]}


def mean_se(v):
    m = sum(v) / len(v)
    return m, math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1) / len(v))


# ═══════════════════════════════════════════════════════════════════════════
# §1  the pinned sample is the seeded sample, and the solver reproduces it
# ═══════════════════════════════════════════════════════════════════════════
def section_1(seed, pinned, resolve):
    rule("§1  The pinned sample is the seeded sample, and the solver reproduces it")
    print("""Every pair below was drawn by period_series_n19.py's draws() -- the same seed and
the same coupling as §11.50 -- and solved exactly by §11.42's certified C solver.
One n = 20 solve takes 1-2 min, so the cell is pinned in period_series_n20.json;
this section shows that the file holds the WHOLE seeded sample, in draw order, and
re-solves a prefix of it.
""")
    check(seed == PS.SEED and set(pinned) == {(N0, 0), (N0, 1)}
          and all(len(v) == K for v in pinned.values()),
          "the pinned file is seed %d's period starting at n = %d, %d pairs on each "
          "axis -- no pair was dropped" % (PS.SEED, N0, K))
    worst, done = 0.0, 0
    for axis in (0, 1):
        k = K if resolve is None else min(resolve, K)
        for (d, e), (m0, m3) in list(zip(PS.draws(N0, K, axis), pinned[(N0, axis)]))[:k]:
            worst = max(worst, abs(ESL.cmu(N0, d, axis)[0] - m0),
                        abs(ESL.cmu(N0 + 3, e, axis)[0] - m3))
            done += 1
    check(worst < 1e-8,
          "re-solving %d pinned pairs (the first %s on each axis) reproduces both mu "
          "values (max |diff| %.1e)" % (done, "all" if resolve is None else resolve,
                                        worst))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the series to n = 20
# ═══════════════════════════════════════════════════════════════════════════
def section_2(old, new):
    rule("§2  The series to n = 20")
    print("""P(n) = E[mu_{n+3}] - E[mu_n] with §11.50's estimator (run-count control variate at
its exact mean).  Periods 7 -> 19 are §11.50's pinned sample; 17 -> 20 is new.
""")
    plan = PS.PLAN + ((N0, K),)
    cells = dict(old)
    cells.update(new)
    P = {}
    for axis in (0, 1):
        print("  %s" % NAME[axis].upper())
        print("  %9s  %6s  %8s  %7s" % ("period", "pairs", "cv P", "se"))
        for n, k in plan:
            _, _, pc, ec = PS.period_stats(n, PS.draws(n, k, axis), cells[(n, axis)])
            P[(n, axis)] = (pc, ec)
            print("  %3d -> %2d  %6d  %8.4f  %7.4f%s"
                  % (n, n + 3, k, pc, ec, "   <- new" if n == N0 else ""))
        print()
    for axis in (0, 1):
        nm = NAME[axis]
        ma, sa = mean_se([m3 for _, m3 in cells[(14, axis)]])
        mb, sb = mean_se([m0 for m0, _ in cells[(N0, axis)]])
        z = abs(ma - mb) / math.hypot(sa, sb)
        check(z < 3, "%s: E[mu_17] from two independent samples agrees -- the end of "
              "P(14), %.4f +- %.4f, and the start of P(17), %.4f +- %.4f (%.1f sigma)"
              % (nm, ma, sa, mb, sb, z))
        p, e = P[(N0, axis)]
        check(p / e > 10, "%s: E[mu] still RISES over the new period -- P(17) = %.4f, "
              "%.0f standard errors above zero" % (nm, p, p / e))
        p14, e14 = P[(14, axis)]
        z = (p14 - p) / math.hypot(e14, e)
        check(z > 4, "%s, n = 2 (mod 3): P falls again, P(14) = %.3f to P(17) = %.3f "
              "(%.1f standard errors)" % (nm, p14, p, z))
    ratios = {}
    for axis in (0, 1):
        nm = NAME[axis]
        rr = []
        for a, b in ((13, 16), (14, 17)):
            (pa, ea), (pb, eb) = P[(a, axis)], P[(b, axis)]
            r = pb / pa
            rr.append((r, r * math.hypot(ea / pa, eb / pb)))
        (r1, s1), (r2, s2) = rr
        z = abs(r1 - r2) / math.hypot(s1, s2)
        ratios[axis] = ((r1 / s1 ** 2 + r2 / s2 ** 2) / (1 / s1 ** 2 + 1 / s2 ** 2), rr)
        check(z < 2, "%s: the two residue classes fall by the SAME factor over their "
              "last period -- P(16)/P(13) = %.3f +- %.3f, P(17)/P(14) = %.3f +- %.3f "
              "(%.1f sigma apart)" % (nm, r1, s1, r2, s2, z))
    for axis in (0, 1):
        nm = NAME[axis]
        rows = [(n,) + P[(n, axis)] for n in (11, 14, N0)]
        x1, x2, dx, se = PS.curvature(rows)
        print("  %s, n = 2 (mod 3): exponent %+.2f over 11 -> 14, %+.2f over 14 -> 17, "
              "change %+.2f +- %.2f" % (nm, x1, x2, dx, se))
        if axis == 0:
            check(dx < -3 * se,
                  "differential, n = 2 (mod 3): the fall now STEEPENS in this series "
                  "too -- the exponent moves from %+.2f to %+.2f, %.1f standard errors "
                  "(§11.50 printed this series' earlier step as not steepening)"
                  % (x1, x2, -dx / se))
        else:
            print("    linear: %.1f standard errors -- printed, not scored" % (-dx / se))
    print()
    m20 = {}
    for axis in (0, 1):
        nm = NAME[axis]
        m, s = mean_se([m3 for _, m3 in cells[(N0, axis)]])
        m20[axis] = m
        print("  %s: E[mu_20] = %.3f +- %.3f, %.2fx the %s criterion; the last period "
              "adds %.3f per bit" % (nm, m, s, m / CRITERION[axis],
                                     "4/3" if axis == 0 else "2/3", P[(N0, axis)][0] / 3))
        check(m > 1.9 * CRITERION[axis],
              "%s: E[mu_20] is still about twice the criterion (%.2fx)"
              % (nm, m / CRITERION[axis]))
    return P, ratios, m20


# ═══════════════════════════════════════════════════════════════════════════
# §3  where a constant ratio would leave E[mu] -- printed, not scored
# ═══════════════════════════════════════════════════════════════════════════
def section_3(P, ratios, m20):
    rule("§3  Where a constant ratio would leave E[mu] -- a scenario, not a bound")
    print("""If every later period kept the ratio measured over the last one, the remaining
increments would form a geometric series and E[mu] would level at
E[mu_20] + P(17) r / (1 - r) in the n = 2 series.  This is printed and NOT scored:
§11.50 already saw the ratio fall once (P(13)/P(10) was 0.93 differential), so a
constant ratio is the optimistic end, not a floor.
""")
    for axis in (0, 1):
        r, _ = ratios[axis]
        lim = m20[axis] + P[(N0, axis)][0] * r / (1 - r)
        print("  %-12s pooled ratio %.3f -> E[mu] would level near %.2f, %.2fx the "
              "criterion" % (NAME[axis], r, lim, lim / CRITERION[axis]))
    print("""
The pessimistic end is open: if the ratio keeps falling, P reaches zero within a
few periods and E[mu] levels at about 2x the criteria, or below that if P turns
negative, which nothing measured here excludes.""")


def section_4():
    rule("§4  What this changes for #257")
    print("""CONFIRMED: §11.50's steeper fall was not a fluctuation of one cell.  The n = 2
(mod 3) series, one period further, falls by the same factor per period as the
n = 1 series (0.68 differential, about 0.8 linear), and its differential exponent
now steepens as well.

UNCHANGED: monotonicity.  E[mu] rises over every period measured, now to n = 20,
and E[mu_20] is about twice both criteria -- the same margin as at n = 19.

NARROWED: what #257 owes.  Both residue classes now fall by the same ratio over
their latest period.  If that ratio held, E[mu] would level near 3.1 / 2.0 (about
2.3x / 3.0x the criteria); if it keeps falling, as it did once in the n = 1 series,
E[mu] levels near the present 2x or lower.  Which holds is the next period's
question, and the next period is out of reach of this solver on this host: peak
memory grew about 5x from n = 19 to n = 20 on the differential axis (0.83 GB to
4.1 GB), and P(19) needs n = 22.

No rating moves: every row this touches is demo-only on other axes (§11.38.7).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    if a.regenerate:
        regenerate(a.workers)
        return 0
    print(__doc__)
    ESL.build()
    seed, new = load_pinned()
    section_1(seed, new, None if a.full else (1 if a.quick else 4))
    P, ratios, m20 = section_2(PS.load_pinned(), new)
    section_3(P, ratios, m20)
    section_4()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        return 1
    print("*** OK: every finding reproduced ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
