#!/usr/bin/env python3
"""v2_gap_curve.py — TODO #343 (thirteenth pass): NL-FSCX v2's per-round cost at a fixed
GAP n - arc, the diagonal where typical keys sit.

§11.64 (v2_arc_curve.py) found that at a fixed arc of delta mu FALLS with the width, and
that a typical key's arc is a few bits short of n (mean gap n - arc ~ 4.5 at n = 20,
growing like log n).  It left the question for those keys open: mu at a FIXED GAP as n
grows, and whether the cost of a gap bit stays bounded.  No solves: every key here is
already pinned -- the 1243 random keys of v2_transient_series.json (n = 10..20), the 76
of v2_series_n22.json and v2_tail_n22.json (n = 22), and as an independent replicate the
162 arc-drawn keys of v2_arc_curve.json -- so the verdicts cannot flake.

  §1  THE CELLS.  Random keys by gap and width; mean mu per cell, both axes.

  §2  AT A FIXED GAP, mu RISES WITH THE WIDTH, at the full random-key rate.
      (a) Fixed-effects slope, one intercept per gap, over the random keys with
          gap <= 4 (where typical keys sit): +0.111 +/- 0.003 per bit differential and
          +0.065 +/- 0.002 linear -- not below random keys' own +0.107 / +0.061.  So
          E[mu]'s growth with n is growth AT A FIXED GAP; none of it is carried by the
          gap moving.
      (b) Not the stratification: with one intercept per (gap, t) stratum cell, and on
          the t = 0 stratum alone, the slope stays above 15 SE on both axes.
      (c) Replicated on the independent arc-drawn keys (gap <= 10): +0.135 +/- 0.008 /
          +0.069 +/- 0.004.
      This and §11.64 are one surface read along two lines: at a fixed gap the arc
      grows one-for-one with n, and a bit of arc is worth more than the fixed-arc fall.

  §3  THE COST OF A GAP BIT FALLS WITH THE WIDTH.  At each width, the slope of mu on the
      gap (gaps 2..10) is negative -- a gap bit costs -- and it shrinks: -0.21 per bit
      differential at n = 10-11, -0.11 at n = 20-22; -0.094 -> -0.072 linear.  Relative
      to the width's mean mu it falls from 13-14% per bit to 5-6%.  So §11.64's fall is
      a cost per gap bit that is bounded, and shrinking, over n = 10..22.
      PRINTED, NOT SCORED: at n = 22, moving a key from gap 4 to the ~8 bits §11.64
      extrapolates for n = 256 costs about 4 such bits.

  CAVEATS.  Keys are stratified on t, not on the gap, so cells are unweighted means
  (§2b checks the composition does not drive the slope).  Gaps 0-1 are rare (at most 13
  keys per width) and not monotone, so §3 fits from gap 2.  Every trend is measured over
  n = 10..22, not proved; nothing says how it continues.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_gap_curve.py
      about 3 s on an aarch64 SBC
"""

import importlib.util
import json
import math
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
NAME = {0: "differential", 1: "linear"}
GTYP = 4                          # typical keys' gap at n <= 22 (§11.64.4)
GTOP = 10                         # widest gap fit
GLO = 2                           # §3 fits from here: gaps 0-1 are rare and not monotone
LOW, HIGH = (10, 11), (20, 22)    # the widths §3 compares


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


AC = _load("v2_arc_curve.py")         # PINNED; TL (arc(), S22, PINNED), TS, SW, AUD
TL, TS, SW, AUD = AC.TL, AC.TS, AC.SW, AC.AUD
KQ = TL.KQ


def keys():
    """[(n, gap, t, mu_d, mu_l)] over every pinned random key, n = 10..22."""
    out = []
    with open(TS.PINNED) as fh:
        rec = json.load(fh)
    src = [(n, r[1], r[2][0], r[3][0]) for n, _ in TS.PLAN for r in rec["widths"][str(n)]]
    for f in (TL.S22.PINNED, TL.PINNED):
        with open(f) as fh:
            src += [(22, r[1], r[2][0], r[3][0]) for r in json.load(fh)["rows"]]
    for n, B, md, ml in src:
        out.append((n, n - TL.arc(AUD.delta(B, n), n), KQ.tz_p(B, n), md, ml))
    return out, rec


def section_1(K):
    rule("§1  The cells: %d random keys, mean mu by gap n - arc and width" % len(K))
    ns = sorted({k[0] for k in K})
    for axis in (0, 1):
        print("\n  %s: mean mu [keys]" % NAME[axis])
        print("   gap " + "".join("%12d" % n for n in ns))
        for g in range(0, GTOP + 1):
            row = ""
            for n in ns:
                v = [k[3 + axis] for k in K if k[:2] == (n, g)]
                row += "  %5.2f [%3d]" % (st.mean(v), len(v)) if v else " " * 12
            print("  %4d %s" % (g, row))
    check(all(sum(1 for k in K if k[0] == n and k[1] <= GTYP) >= 20 for n in ns),
          "every width holds 20 or more keys with gap <= %d" % GTYP)


def section_2(K, M):
    rule("§2  At a fixed gap, mu rises with the width")
    for axis in (0, 1):
        nm = NAME[axis]
        gen = SW.rand_slope(M, axis)
        pts = [(k[1], k[0], k[3 + axis]) for k in K if k[1] <= GTYP]
        b, se = SW.fe_slope(pts)
        print("  %s: fixed gap <= %d, %d keys: %+.4f +/- %.4f per bit; random keys %+.4f "
              "+/- %.4f" % (nm, GTYP, len(pts), b, se, gen[0], gen[1]))
        check(b > 10 * se, "%s: at a fixed gap mu rises with n, %+.4f +/- %.4f per bit"
              % (nm, b, se))
        check(b > gen[0] - 2 * math.hypot(se, gen[1]), "%s: and not below random keys' "
              "%+.4f -- E[mu]'s growth is growth at a fixed gap" % (nm, gen[0]))
        b1, s1 = SW.fe_slope([((k[1], k[2]), k[0], k[3 + axis]) for k in K if k[1] <= GTOP])
        b0, s0 = SW.fe_slope([(k[1], k[0], k[3 + axis]) for k in K
                              if k[1] <= GTOP and k[2] == 0])
        check(b1 > 15 * s1 and b0 > 15 * s0, "%s: not the stratification -- one intercept "
              "per (gap, t): %+.4f +/- %.4f; the t = 0 stratum alone: %+.4f +/- %.4f"
              % (nm, b1, s1, b0, s0))
        with open(AC.PINNED) as fh:
            A = json.load(fh)["rows"]
        pa = [(r[0] - r[1], r[0], r[3 + axis][0]) for r in A if r[0] - r[1] <= GTOP]
        b2, s2 = SW.fe_slope(pa)
        check(b2 > 10 * s2, "%s: replicated on the %d independent arc-drawn keys with "
              "gap <= %d: %+.4f +/- %.4f" % (nm, len(pa), GTOP, b2, s2))


def gap_slope(K, n, axis):
    return SW.fe_slope([(0, k[1], k[3 + axis]) for k in K if k[0] == n
                        and GLO <= k[1] <= GTOP])


def section_3(K):
    rule("§3  The cost of a gap bit falls with the width")
    ns = sorted({k[0] for k in K})
    for axis in (0, 1):
        nm = NAME[axis]
        g = {n: gap_slope(K, n, axis) for n in ns}
        m = {n: st.mean(k[3 + axis] for k in K if k[0] == n) for n in ns}
        print("\n  %s: slope of mu on the gap (gaps %d..%d), and relative to the width's "
              "mean mu" % (nm, GLO, GTOP))
        for n in ns:
            print("    n = %2d   %+.4f +/- %.4f   %+.3f" % (n, g[n][0], g[n][1],
                                                         g[n][0] / m[n]))
        check(all(-g[n][0] > 5 * g[n][1] for n in ns), "%s: at every width a gap bit "
              "costs (each slope below -5 SE)" % nm)

        def pool(ws):
            return (st.mean(g[n][0] for n in ws),
                    math.sqrt(sum(g[n][1] ** 2 for n in ws)) / len(ws),
                    st.mean(g[n][0] / m[n] for n in ws))
        lo, hi = pool(LOW), pool(HIGH)
        z = (hi[0] - lo[0]) / math.hypot(lo[1], hi[1])
        check(z > 3, "%s: and the cost shrinks, %+.3f per bit at n = %d-%d to %+.3f at "
              "n = %d-%d (%.1f SE)" % (nm, lo[0], LOW[0], LOW[-1], hi[0], HIGH[0], HIGH[-1],
                                       z))
        check(hi[2] > lo[2] / 2, "%s: relative to mean mu it falls by more than half, "
              "%.1f%% -> %.1f%% per gap bit" % (nm, -100 * lo[2], -100 * hi[2]))
        print("  PRINTED, NOT SCORED: at n = 22, gap %d -> 8 costs about %.2f of mu %.2f"
              % (GTYP, -(8 - GTYP) * g[22][0], m[22]))


def main():
    print(__doc__)
    K, rec = keys()
    M = TS.measures(rec)
    section_1(K)
    section_2(K, M)
    section_3(K)
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
