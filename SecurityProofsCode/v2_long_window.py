#!/usr/bin/env python3
"""v2_long_window.py — TODO #343 (ninth pass): NL-FSCX v2's keys with windows of 13 bits
and more -- the window curve, and how much of the width trend it carries.

§11.59 (v2_short_window.py) CONSTRUCTED keys with windows w = n - tz(p) <= 12 and found
that with the window fixed mu does not grow with n, so the window and not the width caps
a short-window key's per-round cost.  It left windows of 13 bits and more unmeasured.
They need no construction: §11.55's sampler stratifies on t = tz(p) exactly, so every
stratum t < 8 of v2_transient_series.json is a uniform sample of the keys with window
w = n - t, and the 1243 pinned keys hold 8 or more keys in every (w, n) cell with
w = 13..20 that the plan reaches.  No solves: every verdict is computed from the two
pinned files, so it cannot flake.

  §1  THE CELLS.  Keys of both pinned files by window and width; mean mu per cell.

  §2  MOSTLY THE WINDOW, NOT QUITE ONLY.  A fixed-effects slope of mu on n (one
      intercept per window) over the random keys with w = 13..20 is +0.023 +/- 0.010
      per bit differential and +0.016 +/- 0.005 linear.
      (a) It is far below random keys' own slope, +0.107 / +0.061 (8 SE apart, both
          axes): most of E[mu]'s growth with n is the window growing with n.
      (b) It is not negative: what is left of the width effect, at 2.2 / 3.0 SE, only
          helps.  At w <= 12 (§11.59) the constructed keys showed none at all.

  §3  THE WINDOW CURVE.  f(w) = the mean over widths of the cell means, w = 1..20, both
      pinned files.
      (a) It rises block by block (w = 1-4, 5-8, 9-12, 13-16, 17-20), both axes.
      (b) Every window from 13 bits has mean margin y = W(floor(3n/4)) / (bar * n)
          above 1 -- at least 1.21 differential and 1.15 linear.
      (c) The share of keys below the bar falls with the window: 23% / 26% at w = 13-14,
          4% / 7% at w = 17-20.  Long-window keys still fail, at the rate ordinary
          keys of those widths do.
      PRINTED: the curve's block increments shrink (+0.46 then +0.24 differential, +0.24 then +0.16 linear) -- the
      levelling question of TODO #257, asked of the window instead of the width.

  §4  WHAT IT CHANGES.  At n = 256 every window measured here is negligible:
      P(w <= 20) is about 2^-119, and 93% of keys have w >= 250.  So the item "windows
      of 13 bits and more" closes as far as widths n <= 20 can close it: up to 20 bits
      they behave as ordinary keys of that many bits, and above that a w-bit window IS
      the width question at w.  With a non-negative width effect (§2b), a key at
      n = 256 is read as no weaker than a key of its window measured at width w; that
      is a reading of n <= 20, not a bound.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_long_window.py
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
WLONG = 13                        # the windows §11.59 left unmeasured
WTOP = 20                         # the widest window the plan reaches
BLOCKS = ((1, 4), (5, 8), (9, 12), (13, 16), (17, 20))


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


SW = _load("v2_short_window.py")      # fe_slope(), rand_slope(), PINNED (constructed keys)
TS = SW.TS                            # PLAN, BAR, PINNED (random keys), measures()
KQ = SW.KQ                            # p_tail(), tz_p()
WIDTHS = [n for n, _ in TS.PLAN]


def keys():
    """[(src, n, w, (mu_d, mu_l), (y_d, y_l))] from both pinned files."""
    out = []
    with open(TS.PINNED) as fh:
        rec = json.load(fh)
    for n in WIDTHS:
        r0 = 3 * n // 4
        for r in rec["widths"][str(n)]:
            w = n - KQ.tz_p(r[1], n)
            out.append(("R", n, w, (r[2][0], r[3][0]),
                        tuple(r[2 + a][1][r0 - 1] / (TS.BAR[a] * n) for a in (0, 1))))
    with open(SW.PINNED) as fh:
        for r in json.load(fh)["rows"]:
            n, w = r[0], r[1]
            out.append(("C", n, w, (r[4][0], r[5][0]),
                        tuple(r[4 + a][1] / (TS.BAR[a] * n) for a in (0, 1))))
    return out, rec


def cells(K, w):
    c = {}
    for k in K:
        if k[2] == w:
            c.setdefault(k[1], []).append(k)
    return c


# ═══════════════════════════════════════════════════════════════════════════
def section_1(K):
    rule("§1  The cells: keys (random + constructed) and mean mu by window and width")
    for axis in (0, 1):
        print("\n  %s: mean mu [keys]" % NAME[axis])
        print("     w  " + "".join("%12d" % n for n in WIDTHS))
        for w in range(1, WTOP + 1):
            c = cells(K, w)
            print("  %4d  %s" % (w, "".join(
                "  %5.2f [%3d]" % (st.mean(k[3][axis] for k in c[n]), len(c[n]))
                if n in c else " " * 12 for n in WIDTHS)))
    thin = [(w, n) for w in range(WLONG, WTOP + 1) for n, v in cells(K, w).items()
            if len([k for k in v if k[0] == "R"]) < 8]
    check(not thin, "every (w, n) cell with w = %d..%d holds 8 or more random keys %s"
          % (WLONG, WTOP, "" if not thin else "(thin: %s)" % thin))


def section_2(K, M):
    rule("§2  Mostly the window, not quite only: mu at a fixed long window")
    for axis in (0, 1):
        nm = NAME[axis]
        pts = [(k[2], k[1], k[3][axis]) for k in K if k[0] == "R" and k[2] >= WLONG]
        b, se = SW.fe_slope(pts)
        gen = SW.rand_slope(M, axis)
        z = (gen[0] - b) / math.hypot(se, gen[1])
        print("  %s: fixed window w = %d..%d, %d keys: %+.4f +/- %.4f per bit; random keys"
              " %+.4f +/- %.4f" % (nm, WLONG, WTOP, len(pts), b, se, gen[0], gen[1]))
        check(z > 5, "%s: the fixed-window slope is far below random keys' (%.0f SE) -- "
              "most of E[mu]'s growth with n is the window growing" % (nm, z))
        check(b > 0, "%s: what is left of the width effect is not negative (%+.4f, %.1f SE "
              "above zero) -- it only helps" % (nm, b, b / se))


def section_3(K):
    rule("§3  The window curve f(w) = mean over widths of the cell means, w = 1..%d" % WTOP)
    for axis in (0, 1):
        nm = NAME[axis]
        f, yb, sh = {}, {}, {}
        for w in range(1, WTOP + 1):
            c = cells(K, w)
            f[w] = st.mean(st.mean(k[3][axis] for k in v) for v in c.values())
            yb[w] = st.mean(st.mean(k[4][axis] for k in v) for v in c.values())
            ys = [k[4][axis] for v in c.values() for k in v]
            sh[w] = (sum(y < 1 for y in ys), len(ys))
        print("\n  %s:" % nm)
        print("     w   f(w)   mean y   below bar")
        for w in range(1, WTOP + 1):
            print("  %4d  %5.2f   %5.2f    %3d of %3d" % (w, f[w], yb[w], sh[w][0], sh[w][1]))
        blk = [st.mean(f[w] for w in range(a, b + 1)) for a, b in BLOCKS]
        check(all(y > x for x, y in zip(blk, blk[1:])), "%s: f rises block by block (%s)"
              % (nm, " -> ".join("%.2f" % x for x in blk)))
        lo = min(yb[w] for w in range(WLONG, WTOP + 1))
        check(lo > 1, "%s: every window from %d bits has mean margin y above the bar (at "
              "least %.2f)" % (nm, WLONG, lo))

        def share(a, b):
            k = sum(sh[w][0] for w in range(a, b + 1))
            return k / sum(sh[w][1] for w in range(a, b + 1))
        s1, s2 = share(WLONG, WLONG + 1), share(17, WTOP)
        check(s2 < s1 / 2, "%s: the share below the bar falls with the window: %.0f%% at "
              "w = %d-%d, %.0f%% at w = 17-%d" % (nm, 100 * s1, WLONG, WLONG + 1, 100 * s2,
                                                  WTOP))
        inc = [y - x for x, y in zip(blk, blk[1:])]
        print("  PRINTED: block increments of f %s -- the levelling question, asked of the "
              "window" % " ".join("%+.2f" % x for x in inc))


def section_4():
    rule("§4  What it changes: the measured windows at n = 256")
    n = 256
    P20 = KQ.p_tail(n, n - WTOP)
    P13 = P20 - KQ.p_tail(n, n - WLONG + 1)
    print("  P(w <= %d) = 2^%.1f;  P(%d <= w <= %d) = 2^%.1f;  P(w >= 250) = %.3f"
          % (WTOP, math.log2(P20), WLONG, WTOP, math.log2(P13), 1 - KQ.p_tail(n, 7)))
    check(P20 < 2.0 ** -110 and 1 - KQ.p_tail(n, 7) > 0.93,
          "at n = 256 every window measured here is negligible (2^%.0f), and 93%% of keys "
          "have windows of 250 bits or more -- the rest is the width question"
          % math.log2(P20))


def main():
    print(__doc__)
    K, rec = keys()
    M = TS.measures(rec)
    section_1(K)
    section_2(K, M)
    section_3(K)
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
