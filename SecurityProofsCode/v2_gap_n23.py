#!/usr/bin/env python3
"""v2_gap_n23.py — TODO #343 (fourteenth pass): NL-FSCX v2 at a fixed gap n - arc, one
width further, at n = 23.

§11.65 (v2_gap_curve.py) found over n = 10..22 that at a fixed gap n - arc mu rises with
the width at the full random-key rate, and that the cost of a gap bit shrinks.  Both were
measured to n = 22 only.  This pass solves the next non-singular width: at n = 23, for
gaps 2, 4, 6 and 8, 6 keys drawn uniformly from the keys with that exact gap, distinct
deltas, seed 3431.  24 keys, mu and W(floor(3n/4)) on both axes, pinned in
v2_gap_n23.json (11 h 43 min at four solves in parallel, 32 min to 5 h 23 min per key,
up to 2.2 GB each).  The default run reads the pinned file, so its verdicts cannot flake.

  §1  THE SAMPLE is exactly plan()'s draw, every delta has its claimed gap, and the
      deltas within each gap are distinct.

  §2  THE FIXED-GAP RISE CONTINUES ONE CLASS STEP.  From n = 20 to n = 23 -- the same
      residue class mod 3 -- with one intercept per gap: +0.097 +/- 0.022 per bit
      differential and +0.061 +/- 0.013 linear (4.4 / 4.8 SE), within 1.2 SE of §11.65's
      n = 10..22 slope (+0.122 / +0.068 over gaps 2..8).
      PRINTED, NOT SCORED: the single step 22 -> 23 is flat within its error
      (-0.007 +/- 0.065 / +0.011 +/- 0.043); one bit, across residue classes, and the
      n = 22 cells at gaps 2 and 8 hold 3 keys each, so it resolves nothing.

  §3  A GAP BIT STILL COSTS AT n = 23, and less than at n = 10-11.  The slope of mu on the
      gap is -0.093 +/- 0.019 differential and -0.070 +/- 0.013 linear (4.9 / 5.6 SE),
      against -0.228 / -0.107 at n = 10-11 over the same gaps (6.2 / 2.7 SE smaller).
      PRINTED, NOT SCORED: it did not shrink further from n = 22 (-0.090 / -0.069), and
      on the linear axis it has been flat since n = 20 (-0.072).  As a share of the
      sample's mean mu it is 3.4% / 4.9% per bit.

  §4  THE MARGIN.  23 of the 24 keys clear the deployed criterion on both axes; the one
      that does not is a gap-8 key, below the bar on both (y = 0.97 / 0.83).  The sample
      is drawn by gap, not by key, so that is not a population share.

  CAVEATS.  Six keys per gap at one width.  E[mu] at n = 23 is not estimated: the sample
  covers four gaps, not the gap distribution.  Every trend is measured, not proved.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_gap_n23.py [--regenerate]
      default      : verdicts from the pinned file (about 30 s; the exhaustive gap
                     enumeration at n = 23 is most of it)
      --regenerate : rebuild v2_gap_n23.json in parallel, resumable (about 12 h)
"""

import argparse
import importlib.util
import json
import math
import os
import random
import statistics as st
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_gap_n23.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
N = 23                            # the next non-singular width past n = 22
GAPS = (2, 4, 6, 8)               # the gaps held fixed; §11.65.2 fits gaps 2..10
KPER = 6                          # keys per gap, distinct deltas
JOBS = 4                          # parallel solves: ~2.2 GB peak each at n = 23


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


GC = _load("v2_gap_curve.py")         # keys(), gap_slope(); AC, TL, TS, SW, AUD, KQ
AC, TL, TS, SW, AUD = GC.AC, GC.TL, GC.TS, GC.SW, GC.AUD
KS = TL.KS


def by_gap(n):
    """{gap: [B]} over every key of width n with a non-affine delta, in key order."""
    aff = KS.affine(n)
    out = {g: [] for g in GAPS}
    for B in range(1 << n):
        d = AUD.delta(B, n)
        if d in aff:
            continue
        g = n - TL.arc(d, n)
        if g in out:
            out[g].append(B)
    return out


def draw(g, keys):
    """KPER keys drawn uniformly from the keys of gap g, skipping repeated deltas."""
    rnd = random.Random(KS.SEED * 1000 + N * 31 + 100 + g)
    seen, out = set(), []
    for B in rnd.sample(keys, len(keys)):
        d = AUD.delta(B, N)
        if d not in seen:
            seen.add(d)
            out.append(B)
            if len(out) == KPER:
                break
    return out


def plan():
    K = by_gap(N)
    return [(g, B) for g in GAPS for B in draw(g, K[g])]

LOW = (10, 11)                    # the widths §3 compares n = 23 against
STEP = 20                         # the previous width of n = 23's residue class


def section_1(rows):
    rule("§1  The sample: %d keys at n = %d, gaps %s" % (len(rows), N,
                                                     "/".join(map(str, GAPS))))
    check([(r[0], r[1]) for r in rows] == plan(), "the pinned rows are exactly plan()'s "
          "seeded draw: %d keys per gap, uniform over the keys of each gap" % KPER)
    check(all(N - TL.arc(AUD.delta(r[1], N), N) == r[0] for r in rows),
          "every key's delta has the gap its row claims")
    check(all(len({AUD.delta(r[1], N) for r in rows if r[0] == g}) == KPER for g in GAPS),
          "the deltas within each gap are distinct")


def fixed_gap_step(K, rows, n0, axis):
    pts = [(k[1], n0, k[3 + axis]) for k in K if k[0] == n0 and k[1] in GAPS]
    return SW.fe_slope(pts + [(r[0], N, r[2 + axis][0]) for r in rows])


def section_2(K, rows):
    rule("§2  The fixed-gap rise continues one class step, n = %d -> %d" % (STEP, N))
    for axis in (0, 1):
        nm = NAME[axis]
        print("\n  %s: mean mu by gap" % nm)
        print("    gap    n = 19   n = 20   n = 22   n = 23")
        for g in GAPS:
            c = [[k[3 + axis] for k in K if k[:2] == (n, g)] for n in (19, 20, 22)]
            v = [r[2 + axis][0] for r in rows if r[0] == g]
            print("  %5d   %s   %.3f +/- %.3f" % (g, "   ".join(
                "%6.3f" % st.mean(x) for x in c), st.mean(v), st.stdev(v) / math.sqrt(len(v))))
        b, se = fixed_gap_step(K, rows, STEP, axis)
        b0, s0 = SW.fe_slope([(k[1], k[0], k[3 + axis]) for k in K
                              if GC.GLO <= k[1] <= GAPS[-1]])
        check(b > 3 * se, "%s: at a fixed gap mu rises from n = %d to %d, %+.4f +/- %.4f per "
              "bit (%.1f SE)" % (nm, STEP, N, b, se, b / se))
        check(abs(b - b0) < 2 * math.hypot(se, s0), "%s: in line with the n = 10..22 "
              "fixed-gap slope over gaps %d..%d, %+.4f +/- %.4f" % (nm, GC.GLO, GAPS[-1],
                                                                   b0, s0))
        b1, s1 = fixed_gap_step(K, rows, 22, axis)
        print("  PRINTED, NOT SCORED: the single step 22 -> %d, %+.4f +/- %.4f per bit -- one "
              "bit, across residue classes" % (N, b1, s1))


def section_3(K, rows):
    rule("§3  A gap bit still costs at n = %d" % N)
    for axis in (0, 1):
        nm = NAME[axis]
        b, se = SW.fe_slope([(0, r[0], r[2 + axis][0]) for r in rows])
        m = st.mean(r[2 + axis][0] for r in rows)
        lo = [SW.fe_slope([(0, k[1], k[3 + axis]) for k in K if k[0] == n
                           and GC.GLO <= k[1] <= GAPS[-1]]) for n in LOW]
        lb = st.mean(x[0] for x in lo)
        ls = math.sqrt(sum(x[1] ** 2 for x in lo)) / len(lo)
        z = (b - lb) / math.hypot(se, ls)
        check(-b > 4 * se, "%s: at n = %d the slope of mu on the gap is %+.4f +/- %.4f "
              "(%.1f SE below zero)" % (nm, N, b, se, -b / se))
        check(z > 2, "%s: and smaller than at n = %d-%d over the same gaps, %+.4f (%.1f SE)"
              % (nm, LOW[0], LOW[-1], lb, z))
        prev = {n: SW.fe_slope([(0, k[1], k[3 + axis]) for k in K if k[0] == n
                                and GC.GLO <= k[1] <= GAPS[-1]])[0] for n in (20, 22)}
        print("  PRINTED, NOT SCORED: n = 20 %+.4f, n = 22 %+.4f, n = %d %+.4f per gap bit; "
              "%.1f%% of the sample's mean mu" % (prev[20], prev[22], N, b, -100 * b / m))


def section_4(rows):
    rule("§4  The margin at n = %d" % N)
    bad = {}
    for axis in (0, 1):
        bar = TS.BAR[axis] * N
        bad[axis] = [r for r in rows if r[2 + axis][1] < bar]
        print("  %s: %d of %d below the bar; least y = %.3f" % (
            NAME[axis], len(bad[axis]), len(rows), min(r[2 + axis][1] / bar for r in rows)))
    same = [r[1] for r in bad[0]] == [r[1] for r in bad[1]]
    check(len(bad[0]) == len(bad[1]) == 1 and same and bad[0][0][0] == GAPS[-1],
          "%d of %d keys clear the criterion on both axes; the one that does not is a "
          "gap-%d key, below on both" % (len(rows) - 1, len(rows), GAPS[-1]))


def regenerate():
    TS.ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                B, x, y = json.loads(ln)
                done[B] = (x, y)
    rows = plan()
    # dearest first (short gaps are long arcs), so the pool does not end on one slow solve
    jobs = sorted([r for r in rows if r[1] not in done], key=lambda r: r[0])
    print("%d keys at n = %d, %d to solve" % (len(rows), N, len(jobs)), flush=True)
    lock = threading.Lock()

    def one(job):
        g, B = job
        t0 = time.time()
        x, y = AC.solve(N, B)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, x, y]) + "\n")
            done[B] = (x, y)
            print("  %s gap %d, B = %d: mu %.4f / %.4f in %.0f s (%d done)"
                  % (time.strftime("%H:%M"), g, B, x[0], y[0], time.time() - t0, len(done)),
                  flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 trail weights at a fixed gap n - arc of "
                   "delta, n = %d; rows are [gap, key B, [mu_diff, W_diff(floor(3n/4))], "
                   "[mu_lin, W_lin]]" % N,
                   "seed": KS.SEED, "n": N, "kper": KPER,
                   "rows": [[g, B] + list(done[B]) for g, B in rows]},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return 0
    print(__doc__)
    with open(PINNED) as fh:
        rows = json.load(fh)["rows"]
    K, _ = GC.keys()
    section_1(rows)
    section_2(K, rows)
    section_3(K, rows)
    section_4(rows)
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
