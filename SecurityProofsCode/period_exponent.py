#!/usr/bin/env python3
"""period_exponent.py — TODO #257 (twelfth pass): the per-period increment of E[mu],
RESOLVED, and the eleventh pass's "flat from n = 10" withdrawn.

The eleventh pass (coupled_width_increment.py) coupled the widths exactly and found
E[mu] rising at every step; summed over a period of three widths (the period of M's
singularity) its increment read 0.364 / 0.370 differential and 0.206 / 0.209 linear over
n = 10 -> 13 -> 16, "flat within errors", and it said that agreed with §11.42's LEVELLED
reading.  Two things were wrong with that, and this pass is both corrections.

  §1  THE ERRORS WERE UNDERSTATED, AND A BETTER ESTIMATOR EXISTS.
      (a) The eleventh pass drew m insertions per base delta and divided by
          sqrt(pairs).  The m pairs share mu(delta), so they are not independent:
          clustered by key the errors are 1.4-1.6x larger (coupled_width_increment.py
          now prints both, and is corrected).
      (b) The coupling is exact for ANY number of inserted bits, so a whole period
          is ONE pair: insert three uniform bits into a uniform delta at n and the
          result is uniform at n + 3 -- checked exhaustively.  One solver call per
          pair at n + 3 instead of two, and no error from adding two separately
          estimated steps.  No valid delta can produce a degenerate output (both
          degenerate values have only degenerate preimages), so no rejection
          perturbs the coupling -- also checked exhaustively.
      (c) A CONTROL VARIATE with an EXACTLY known mean: the change in delta's run
          count.  Over all n-bit strings its mean is k/2 for k inserted bits; over
          the sampled ensemble (the two degenerate deltas excluded) it is that,
          corrected by the two excluded strings' own exact contributions --
          computed, and checked against brute force.  It is correlated with the
          increment because mu is paid at run boundaries (§11.46.2), and cuts the
          error by ~10-20%.

  §2  THE PERIOD SERIES, RESOLVED.  P(n) = E[mu_{n+3}] - E[mu_n] at n = 7, 10 (and
      13 in the default mode), thousands of keys per period, both axes.  FINDINGS,
      replicated on independent seeds with ~8000 pairs per period.
      (a) P FALLS on both axes from 7 -> 10: local exponent d log P / d log n of
          -0.55 +- 0.05 (differential) and -0.31 +- 0.04 (linear).
      (b) It goes on falling from 10 -> 13: differential -0.23 +- 0.06 in the
          replication and -0.40 +- 0.08 at this file's seeds, 4.0 and 5.3 standard
          errors below a LEVELLED rate (0) -- SCORED; linear -0.18 +- 0.05 in the
          replication (3.5 sigma) but -0.14 +- 0.07 here (1.9), ~4 combined -- NOT
          scored, since a check that passes on one sample and fails on the other
          is #299's defect.
          The eleventh pass's 0.364 / 0.370 sat inside its own (understated)
          errors and could not see a 5-9% decline per period; this can.
      (c) And neither of §11.42's readings describes it.  A power law has ONE
          exponent; in the replication the differential one moves from -0.55 to
          -0.23 between two adjacent intervals (~3.6 sigma, the shared P(10)
          included), so the decline is itself slowing.
          The linear 10 -> 13 value sits on the power law's -0.16, but its
          7 -> 10 value does not.  The scored check is the levelled rejection,
          which holds on both axes; the power-law distance is printed, not
          scored, because a local exponent that drifts cannot confirm a model
          whose exponent does not.  (At this file's own seeds the drift is
          -0.53 -> -0.40, not resolved; it rests on the replication.)

  §3  WHAT THIS CHANGES.  Prose.

Fixed seeds throughout (every delta, every insertion), so the verdict is a
deterministic computation and cannot flake.  Drives exact_slope_ladder.py's C solver,
which IS the gate, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/period_exponent.py [--quick | --full]
      --quick : P(7), P(10)                        (~4 min on an aarch64 SBC)
      default : P(10) at 8000 pairs, adds P(13) at 3000 (~75 min)
      --full  : P(13) at 6000 pairs per axis         (~2.5 h)
"""

import argparse
import collections
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
    argv, sys.argv = sys.argv, [name]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


CWI = _load("coupled_width_increment.py")   # insert, degenerate, pushforward, cluster_se
ESL = CWI.ESL                               # the C solver (cmu), build(), nruns
nruns = ESL.nruns
NAME = {0: "differential", 1: "linear"}
POWER = {0: 0.63, 1: 0.84}     # §11.42's power-law exponents (exact_slope_ladder.py)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the three-bit coupling and its control variate
# ═══════════════════════════════════════════════════════════════════════════
def insertions(d, n, k):
    """Every (equally likely) result of k sequential uniform insertions into d."""
    level = [(d, n)]
    for _ in range(k):
        level = [(CWI.insert(x, w, p, b), w + 1) for x, w in level
                 for p in range(w + 1) for b in (0, 1)]
    return [x for x, _ in level]


def control_mean(n, k):
    """E[runs(after) - runs(before)] for the SAMPLED ensemble: delta uniform on the
    n-bit strings other than the two degenerate ones, then k uniform insertions.
    Over ALL strings E[runs] = (n + 1) / 2, so the sum over all d of the expected
    change is 2^n * k / 2 exactly; the two excluded strings' contributions are
    computed by enumeration and removed."""
    total = (1 << n) * k / 2
    for d in (0, 1 << (n - 1)):
        outs = insertions(d, n, k)
        total -= sum(nruns(e, n + k) for e in outs) / len(outs) - nruns(d, n)
    return total / ((1 << n) - 2)


def section_1():
    rule("§1  The three-bit coupling, and a control variate with an exact mean")
    for n, k in ((4, 3), (5, 3)):
        c = CWI.pushforward(n, k)
        vals = set(c.values())
        check(len(c) == 1 << (n + k) and len(vals) == 1,
              "exhaustive at n = %d, %d insertions: every one of the 2^%d outputs is "
              "reached exactly %d times -- a whole period is ONE paired draw"
              % (n, k, n + k, next(iter(vals))))
    bad = 0
    for n in (6, 7):
        for d in range(1 << n):
            if CWI.degenerate(d, n):
                continue
            bad += sum(CWI.degenerate(e, n + 3) for e in insertions(d, n, 3))
    check(bad == 0,
          "no valid delta has a degenerate output (exhaustive at n = 6, 7, three "
          "insertions), so the sampler's rejection loop never changes the coupling")
    worst = 0.0
    for n in (6, 7, 8):
        brute, cnt = 0.0, 0
        for d in range(1 << n):
            if CWI.degenerate(d, n):
                continue
            outs = insertions(d, n, 3)
            brute += sum(nruns(e, n + 3) for e in outs) / len(outs) - nruns(d, n)
            cnt += 1
        worst = max(worst, abs(brute / cnt - control_mean(n, 3)))
    check(worst < 1e-12,
          "the control variate's mean (change in run count) is EXACT: the closed form "
          "plus the two excluded strings matches brute force at n = 6, 7, 8 "
          "(max |diff| %.1e)" % worst)


# ═══════════════════════════════════════════════════════════════════════════
# §2  the period series
# ═══════════════════════════════════════════════════════════════════════════
def period(n, K, axis, seed=1257):
    """P(n) from K keys, two three-bit insertions each.  (plain, se, cv, se_cv, pairs)"""
    rnd = random.Random(seed * 1000 + n * 10 + axis)
    y, x = [], []
    for _ in range(K):
        d = rnd.getrandbits(n)
        while CWI.degenerate(d, n):
            d = rnd.getrandbits(n)
        m0 = ESL.cmu(n, d, axis)[0]
        r0 = nruns(d, n)
        for _ in range(2):
            e, w = d, n
            for _ in range(3):
                e = CWI.insert(e, w, rnd.randrange(w + 1), rnd.getrandbits(1))
                w += 1
            y.append(ESL.cmu(n + 3, e, axis)[0] - m0)
            x.append(nruns(e, n + 3) - r0)
    cm = control_mean(n, 3)
    mx, my = sum(x) / len(x), sum(y) / len(y)
    b = (sum((a - mx) * (c - my) for a, c in zip(x, y))
         / sum((a - mx) ** 2 for a in x))
    adj = [c - b * (a - cm) for a, c in zip(x, y)]
    return (my, CWI.cluster_se(y, 2), sum(adj) / len(adj), CWI.cluster_se(adj, 2),
            len(y))


def exponent(n1, p1, e1, n2, p2, e2):
    """Local exponent d log P / d log n between two periods, at their midpoints."""
    L = math.log((n2 + 1.5) / (n1 + 1.5))
    return math.log(p2 / p1) / L, math.hypot(e1 / p1, e2 / p2) / L


def power_exponent(axis):
    return POWER[axis] - 1


def section_2(plan):
    rule("§2  The period series, resolved")
    print("""P(n) = E[mu_{n+3}] - E[mu_n], one three-bit insertion per pair, errors clustered by
key.  "cv" subtracts the run-count control variate at its exact mean.  The local
exponent compares two periods: a levelled per-bit rate predicts 0, §11.42's power
law (mu ~ n^0.63 differential, n^0.84 linear) predicts -0.37 / -0.16.
""")
    out = {}
    for axis in (0, 1):
        nm = NAME[axis]
        print("\n  %s" % nm.upper())
        print("  %9s  %6s  %8s  %7s  %8s  %7s" % ("period", "pairs", "plain", "se", "cv",
                                                   "se"))
        rows = []
        for n, K in plan:
            p, e, pc, ec, N = period(n, K, axis)
            rows.append((n, pc, ec, e))
            print("  %3d -> %2d  %6d  %8.4f  %7.4f  %8.4f  %7.4f"
                  % (n, n + 3, N, p, e, pc, ec), flush=True)
        out[axis] = rows
        check(all(r[2] < r[3] for r in rows),
              "%s: the control variate cuts the error at every period (by %s)"
              % (nm, ", ".join("%.0f%%" % (100 * (1 - r[2] / r[3])) for r in rows)))
        pl = power_exponent(axis)
        for (n1, p1, e1, _), (n2, p2, e2, _) in zip(rows, rows[1:]):
            ex, ee = exponent(n1, p1, e1, n2, p2, e2)
            print("  %s: local exponent over %d -> %d: %+.3f +- %.3f   (levelled 0: %.1f "
                  "sigma; power law %+.2f: %.1f sigma)"
                  % (nm, n1, n2, ex, ee, abs(ex) / ee, pl, abs(ex - pl) / ee))
            if n1 == 7:
                check(ex < -4 * ee,
                      "%s: P FALLS from the period at 7 to the one at 10 (local exponent %+.3f +- %.3f, %.1f "
                      "standard errors below a levelled rate)" % (nm, ex, ee, -ex / ee))
            elif n1 == 10 and axis == 1:
                # NOT SCORED: at this file's sample size the linear 10 -> 13 exponent
                # sits ~2 sigma from a levelled rate (an independent replication with
                # ~8000 pairs per period puts it at 3.5, ~4 combined).  A check that
                # passes or fails on which of those samples ran is #299's defect.
                print("  %s: 10 -> 13 is %.1f standard errors below a levelled rate at "
                      "this sample size -- not scored; see §11.49.2 for the "
                      "replication" % (nm, -ex / ee))
            elif n1 == 10:
                check(ex < -3 * ee,
                      "%s: and goes on falling from the period at 10 to the one at 13 -- "
                      "local exponent %+.3f +- %.3f, %.1f standard errors below a LEVELLED "
                      "rate (and %.1f from §11.42's power law, %+.2f): the eleventh "
                      "pass's \"flat from n = 10\" is WITHDRAWN"
                      % (nm, ex, ee, -ex / ee, abs(ex - pl) / ee, pl))
    return out


def section_3():
    rule("§3  What this changes for #257")
    print("""WITHDRAWN: the eleventh pass's "the per-period increment is flat from n = 10", on
both axes, and with it that pass's agreement with §11.42's levelled reading.  Its two
periods sat inside errors that were themselves understated (they ignored the
clustering of insertions by key); resolved, the increment falls on both axes.

MEASURED: the local exponent of the per-period increment.  A levelled rate (exponent
0) is rejected over 10 -> 13 on the differential axis in both samples and on the
linear axis in the larger one -- so §11.42's higher n = 256 reading (~33
differential, ~17 linear), which assumed one, loses its premise.  The power law is not
confirmed either: on the differential axis the exponent drifts from -0.55 to -0.23
across two adjacent intervals, so the decline is slowing and no fixed exponent
describes it.  The n = 256 value sits between the two readings and nothing here pins
it.

STILL A READING, NOT A BOUND: a local exponent at n = 10-16 says how E[mu] is curving
there, not what it does at 256.  The monotonicity #257 owes is unaffected and still
measured (every step rises), and the lower reading (~13 / ~11) is still ~10x the
criteria, so nothing here threatens 4/3 or 2/3.

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    ESL.build()
    section_1()
    plan = [(7, 1500), (10, 1500 if a.quick else 4000)]
    if not a.quick:
        plan.append((13, 3000 if a.full else 1500))
    section_2(plan)
    section_3()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
