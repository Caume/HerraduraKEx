#!/usr/bin/env python3
"""coupled_width_increment.py — TODO #257 (eleventh pass): the distributional
monotonicity the tenth pass left, MEASURED by an exact coupling between widths.

The tenth pass (width_lift_closure.py) showed that no pointwise chain of local
operations on delta is monotone in exact mu, and re-stated #257's obligation as
a DISTRIBUTIONAL one: E[mu] over typical keys, as width grows.  Every earlier
pass compared that expectation across widths with INDEPENDENT key samples, and
the fifth pass could not tell "levelling" from "still falling" that way.  This
pass couples the widths instead.

  §1  THE COUPLING IS EXACT.  Insert one uniform bit at a uniform position
      p in {0..n} of a uniform n-bit delta: the result is a UNIFORM (n+1)-bit
      delta, because for a fixed output and a fixed p exactly one (delta, bit)
      produces it.  So
          E[mu_{n+1}] - E[mu_n] = E[ mu(insert(delta)) - mu(delta) ]
      EXACTLY, and the right side is a mean of PAIRED differences.  Two
      insertions take n to n + 2, which is how the singular widths (3 | n,
      where M is not invertible) are stepped over.  Checked exhaustively at
      small n, not argued.  The deployed key map B -> delta(B) over odd B is
      injective onto a pseudo-random HALF of delta-space, whose run-count
      distribution is within 1% (total variation) of uniform delta's at
      n = 13, 14, 16 -- exhaustively -- so uniform delta is the right ensemble
      for a statement about deployed keys whose mu grows through run boundaries.

  §2  THE COUPLED LADDER.  Every valid step from n = 4 to 17, both axes, with
      exact mu from the fifth pass's certified C solver on both sides of every
      pair.  FINDINGS.
      (a) E[mu] RISES AT EVERY STEP MEASURED, on both axes -- nine steps each,
          the smallest lower 3-sigma bound on any step +0.04 -- while single
          pairs fall on up to 49% (differential) / 36% (linear) of draws.  That
          is the distributional monotonicity #257 owes, as a measurement over a
          width range and nothing more.
      (b) Pairing is what makes it measurable: the paired standard error is a
          median 4.2x smaller than the unpaired one built from the same numbers,
          which is why independent ladders (the fifth pass) could not resolve the
          per-bit trend.
      (c) The mechanism survives the coupling: draws that add two boundaries
          raise mu more than draws that add none, at every step, on both axes.

  §3  SINGLE STEPS ARE NOT STATIONARY; PERIODS OF THREE WIDTHS ARE.
      (a) A single step's per-bit increment moves between neighbours by 4.6-5.9
          standard errors (differential 7 -> 8 at 0.094 against 8 -> 10 at
          0.183; linear 10 -> 11 at 0.095 against 11 -> 13 at 0.056), so E[mu_n]
          carries a width-specific term no density-1/2 run statistic sees.
      (b) Summed over a PERIOD of three widths -- a one-bit step plus the two-bit
          step over the next singular width, the period of M's singularity -- the
          term cancels: differential 0.364 / 0.370 over 10 -> 13 -> 16, linear
          0.206 / 0.209 (and 0.202 over 7 -> 10).  Flat within errors, at 0.122
          and 0.069 per bit -- within 5% of the fifth pass's levelled per-bit
          medians (0.128, 0.067), reached by an independent method.
      (c) What it does NOT do is choose between §11.42's two n = 256 readings.  A
          power law with the fifth pass's exponents predicts the last period at
          0.92x / 0.96x the one before; measured 1.02 +- 0.09 / 1.01 +- 0.08, so
          1.2 / 0.6 standard errors from the power law and 0.2 from a levelled
          rate.  Carried flat, the series reads ~32 / ~18 at n = 256: a
          reading, not a bound.

  §4  WHAT THIS CHANGES.  Prose.

  Also found on the way, and fixed in the solver this pass drives: SPFA in
  certified_cycle_mean.c (and its Python twin, certified_cycle_ladder.py) ran on
  w - mu' with Howard's mu' a cycle's sum / length, and on n = 17,
  delta = 0x1f6ef the two roundings disagree by < 1e-11, so the optimal cycle is a
  NEGATIVE cycle to SPFA and it never terminates.  Every fixed seed before this
  pass happened to miss such a key; uniform sampling met one within ~180 calls at
  n = 17.  Both
  solvers now run SPFA at mu' - 1e-9, with a relaxation budget that turns a
  genuine negative cycle into an error rather than a hang.

Fixed seeds throughout (every delta, every insertion), so the verdict is a
deterministic computation and cannot flake.  Drives exact_slope_ladder.py's C
solver, which IS the gate, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/coupled_width_increment.py [--quick | --full]
      --quick : steps n = 4 .. 14                      (~3 min on an aarch64 SBC)
      default : adds 14 -> 16 and 16 -> 17              (~25 min)
      --full  : adds 17 -> 19                           (~1.5 h)
"""

import argparse
import collections
import importlib.util
import math
import os
import random
import statistics
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


ESL = _load("exact_slope_ladder.py")   # the C solver (cmu), build(), nruns
FK = ESL.CCL.QEL.FK                    # delta(n, B), the deployed key map
nruns = ESL.nruns
NAME = {0: "differential", 1: "linear"}
POWER = {0: 0.63, 1: 0.84}     # §11.42's power-law exponents (exact_slope_ladder.py)
PERIOD_FROM = 10


def insert(d, n, p, x):
    """delta with bit x inserted at position p (0 = below the LSB, n = above the MSB)."""
    return (d & ((1 << p) - 1)) | (x << p) | ((d >> p) << (p + 1))


def degenerate(d, n):
    return d in (0, 1 << (n - 1))


# ═══════════════════════════════════════════════════════════════════════════
# §1  the coupling is exact
# ═══════════════════════════════════════════════════════════════════════════
def pushforward(n, k):
    """Multiplicity of each (n+k)-bit string under k uniform insertions into every
    n-bit string, every position sequence and every bit sequence."""
    cnt = collections.Counter()
    level = [(d, n) for d in range(1 << n)]
    for _ in range(k):
        level = [(insert(d, w, p, x), w + 1) for d, w in level
                 for p in range(w + 1) for x in (0, 1)]
    for d, _ in level:
        cnt[d] += 1
    return cnt


def section_1():
    rule("§1  The coupling is exact")
    print("""Insert a uniform bit at a uniform position of a uniform delta.  For a fixed output
and a fixed position exactly one (delta, bit) produces it, so the output is uniform
one width up, and E[mu_{n+1}] - E[mu_n] is a mean of PAIRED differences.
""")
    for n, k in ((6, 1), (7, 1), (5, 2)):
        c = pushforward(n, k)
        vals = set(c.values())
        check(len(c) == 1 << (n + k) and len(vals) == 1,
              "exhaustive at n = %d, %d insertion(s): every one of the 2^%d outputs is "
              "reached exactly %d times" % (n, k, n + k, next(iter(vals))))

    print("\n  deployed keys: delta(B) over odd B (quenched_exact_ladder.keys' ensemble)")
    for n in (13, 14, 16):
        img = [FK.delta(n, B) for B in range(1, 1 << n, 2)]
        h = collections.Counter(nruns(d, n) for d in img)
        N = len(img)
        tv = sum(abs(h.get(r, 0) / N - math.comb(n - 1, r - 1) / 2 ** (n - 1))
                 for r in range(1, n + 1)) / 2
        check(len(set(img)) == N and tv < 0.02,
              "n = %d: delta is injective on odd B (2^%d values, half of delta-space) and "
              "its run-count law is %.4f (total variation) from uniform delta's"
              % (n, n - 1, tv))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the coupled ladder
# ═══════════════════════════════════════════════════════════════════════════
def step(n, k, K, m, axis, seed=257):
    """K uniform deltas at width n, m k-bit insertions each.  Rows of
    (mu after - mu before, boundaries added, mu before)."""
    rnd = random.Random(seed * 1000 + n * 10 + axis)
    rows, base = [], []
    for _ in range(K):
        d = rnd.getrandbits(n)
        while degenerate(d, n):
            d = rnd.getrandbits(n)
        m0 = ESL.cmu(n, d, axis)[0]
        base.append(m0)
        for _ in range(m):
            while True:
                e, w = d, n
                for _ in range(k):
                    e = insert(e, w, rnd.randrange(w + 1), rnd.getrandbits(1))
                    w += 1
                if not degenerate(e, w):
                    break
            m1 = ESL.cmu(n + k, e, axis)[0]
            rows.append((m1 - m0, nruns(e, n + k) - nruns(d, n), m1))
    return rows, base


def summarise(n, k, rows, base):
    D = [r[0] for r in rows]
    mean = statistics.mean(D)
    se = statistics.stdev(D) / math.sqrt(len(D))
    # what an unpaired comparison of the same numbers would have had to resolve
    lifted = [r[2] for r in rows]
    se_un = math.sqrt(statistics.variance(base) / len(base)
                      + statistics.variance(lifted) / len(lifted))
    by = collections.defaultdict(list)
    for dm, db, _ in rows:
        by[db].append(dm)
    return dict(n=n, k=k, mean=mean, se=se, se_un=se_un, N=len(D),
                base=statistics.mean(base),
                neg=sum(x < -1e-9 for x in D) / len(D),
                b0=statistics.mean(by[0]) if by[0] else None,
                b2=statistics.mean(by[2]) if by[2] else None)


def plan(quick, full):
    p = [(4, 1, 60, 8), (5, 2, 60, 8), (7, 1, 60, 8), (8, 2, 60, 8),
         (10, 1, 48, 6), (11, 2, 40, 6), (13, 1, 40, 6)]
    if not quick:
        p += [(14, 2, 30, 6), (16, 1, 24, 5)]
    if full:
        p += [(17, 2, 15, 4)]
    return p


def section_2(steps):
    rule("§2  The coupled ladder: E[mu_{n+k}] - E[mu_n], measured pairwise")
    print("""Exact mu on both sides of every pair.  "mean" is the per-STEP increment (k bits),
"se" its paired standard error, "unpaired" the standard error a comparison of
independent samples of the same size would carry, "falls" the share of single
pairs where mu went DOWN, and the last two columns split the mean by whether the
insertion added no boundary or two.
""")
    out = {}
    for axis in (0, 1):
        print("\n  %s" % NAME[axis].upper())
        print("  %9s  %5s  %7s  %6s  %8s  %6s  %8s  %8s"
              % ("step", "pairs", "mean", "se", "unpaired", "falls", "+0 bnd", "+2 bnd"))
        res = []
        for n, k, K, m in steps:
            s = summarise(n, k, *step(n, k, K, m, axis))
            res.append(s)
            print("  %3d -> %2d  %5d  %7.3f  %6.3f  %8.3f  %5.0f%%  %8.3f  %8.3f"
                  % (n, n + k, s["N"], s["mean"], s["se"], s["se_un"], 100 * s["neg"],
                     s["b0"], s["b2"]), flush=True)
        out[axis] = res
        nm = NAME[axis]
        lo = min(s["mean"] - 3 * s["se"] for s in res)
        check(lo > 0,
              "%s: E[mu] RISES at every one of the %d steps n = %d..%d -- the smallest "
              "lower 3-sigma bound on a step's increment is %+.3f"
              % (nm, len(res), res[0]["n"], res[-1]["n"] + res[-1]["k"], lo))
        mx = max(s["neg"] for s in res)
        check(mx >= 0.2,
              "%s: ...while single pairs FALL on up to %.0f%% of draws -- monotone in "
              "expectation, not pointwise (the tenth pass's finding, from the other "
              "side)" % (nm, 100 * mx))
        gain = statistics.median(s["se_un"] / s["se"] for s in res)
        check(gain > 2,
              "%s: pairing cuts the standard error by a median %.1fx against an "
              "unpaired comparison of the same numbers" % (nm, gain))
        ok = [s for s in res if s["b2"] is not None and s["b2"] > s["b0"]]
        check(len(ok) == len(res),
              "%s: an insertion that adds two boundaries raises mu more than one that "
              "adds none, at %d of %d steps" % (nm, len(ok), len(res)))
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §3  the increment is not stationary
# ═══════════════════════════════════════════════════════════════════════════
def section_3(out):
    return_periods = {}
    rule("§3  Single steps are not stationary; periods of three widths are")
    print("""Per BIT, single steps; and per PERIOD of three widths (a one-bit step followed by
the two-bit step over the next singular width), which is the smoother series.
""")
    for axis in (0, 1):
        res = out[axis]
        nm = NAME[axis]
        per_bit = [s["mean"] / s["k"] for s in res]
        print("  %s per bit: %s" % (nm, "  ".join("%d:%.3f" % (s["n"], v)
                                                for s, v in zip(res, per_bit))))
        periods = []
        for a, b in zip(res, res[1:]):
            if a["k"] == 1 and b["k"] == 2 and b["n"] == a["n"] + 1:
                periods.append((a["n"], a["mean"] + b["mean"],
                                math.hypot(a["se"], b["se"])))
        print("  %s per period of 3: %s" % (nm, "  ".join(
            "%d->%d:%.3f+-%.3f" % (p, p + 3, v, e) for p, v, e in periods)))
        # (a) neighbouring single steps past the small-n transient, on their own errors
        z, pair = 0.0, None
        for a, b in zip(res, res[1:]):
            if a["n"] < 7:
                continue
            zz = abs(a["mean"] / a["k"] - b["mean"] / b["k"]) / math.hypot(
                a["se"] / a["k"], b["se"] / b["k"])
            if zz > z:
                z, pair = zz, (a, b)
        a, b = pair
        check(z > 4,
              "%s: single steps are NOT stationary -- neighbouring steps disagree per bit "
              "by %.1f standard errors (%d -> %d: %.3f, %d -> %d: %.3f)"
              % (nm, z, a["n"], a["n"] + a["k"], a["mean"] / a["k"], b["n"],
                 b["n"] + b["k"], b["mean"] / b["k"]))
        # (b) the period-of-3 series from n = 10 on
        late = [p for p in periods if p[0] >= PERIOD_FROM]
        if len(late) < 2:
            print("  %s: one period from n = %d only -- flatness NOT measured in this mode "
                  "(not scored)" % (nm, PERIOD_FROM))
            return_periods[axis] = periods
            continue
        worst = max(abs(x[1] - y[1]) / math.hypot(x[2], y[2])
                    for x, y in zip(late, late[1:]))
        check(worst < 2.5,
              "%s: summed over a period of three widths the increment is FLAT from n = %d: "
              "%s (largest consecutive gap %.1f standard errors)"
              % (nm, PERIOD_FROM, ", ".join("%.3f" % p[1] for p in late), worst))
        # (c) what that is and is not evidence for, against §11.42's two readings
        (p1, v1, e1), (p2, v2, e2) = late[-2], late[-1]
        r, re = v2 / v1, (v2 / v1) * math.hypot(e1 / v1, e2 / v2)
        al = POWER[axis]
        pl = (((p2 + 3) ** al - p2 ** al) / ((p1 + 3) ** al - p1 ** al))
        flat = statistics.mean(p[1] for p in late)
        last = res[-1] if res[-1]["k"] == 1 else res[-2]
        reading = last["base"] + (256 - last["n"]) / 3 * flat
        print("  %s: ratio of the last two periods %.3f +- %.3f; a power law n^%.2f "
              "(§11.42) predicts %.3f, a levelled per-bit rate 1.000 -- %.1f standard "
              "errors from the first, %.1f from the second"
              % (nm, r, re, al, pl, abs(r - pl) / re, abs(r - 1) / re))
        print("  %s: per bit %.3f; carried flat from E[mu_%d] = %.2f it would read %.0f at "
              "n = 256 -- a READING, not a bound, and the ratio above does not yet "
              "choose it" % (nm, flat / 3, last["n"], last["base"], reading))
        return_periods[axis] = periods
    return return_periods


def section_4():
    rule("§4  What this changes for #257")
    print("""MEASURED: the distributional monotonicity the tenth pass re-stated #257 as owing.
An exact coupling turns E[mu_{n+1}] - E[mu_n] into a mean of paired differences,
and it is positive at every step from n = 4 to 17 on both axes, while single pairs
fall on up to half of all draws.  A measurement over a range of widths, not a proof
for every n: nothing here bounds the increment away from zero as n grows.

MEASURED: the per-period increment is flat from n = 10 to 16 on both axes, at 0.122 and
0.069 per bit, matching the fifth pass's levelled per-bit medians by a different
route.  Single steps are not; the width-specific term has period three, the period
of M's singularity, and cancels over a period.

NOT DECIDED: §11.42's two n = 256 readings.  The power law and a levelled rate predict
the last period ratio 0.92-0.96 and 1.00; the measurement is 1.2 and 0.6 standard errors
from the first.  Deciding it needs more periods, and the next costs exact mu at
n = 19 and 20 per pair (--full reaches 17 -> 19 only).

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    ESL.build()
    section_1()
    out = section_2(plan(a.quick, a.full))
    section_3(out)
    section_4()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
