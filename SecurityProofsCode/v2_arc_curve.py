#!/usr/bin/env python3
"""v2_arc_curve.py — TODO #343 (twelfth pass): NL-FSCX v2's per-round cost at a fixed ARC
of the round constant, across the widths n = 10..22.

§11.63 (v2_tail_n22.py) found that delta's cyclic arc -- n minus its longest cyclic run of
zero bits -- and not the window n - tz(p) is what sets a key's margin, and left the arc
curve open because every pinned sample was stratified on t, not on the arc.  This pass
draws by the arc: for arcs 4, 8, 12 and 16 and every non-singular width n = 10..22 (3 | n
is skipped: M is not invertible there and mu is identically 0), 6 keys uniformly from the
keys with that exact arc, distinct deltas, seed 3431.  162 keys in 27 cells, mu and
W(floor(3n/4)) on both axes, pinned in v2_arc_curve.json (the n = 22 cells took 1 h 50
min at seven solves in parallel, the rest 23 min).  The default run reads the pinned
file, so its verdicts cannot flake.

  §1  THE SAMPLE is exactly plan()'s draw, every delta has its claimed arc, and no width
      is singular.  CONTROL: at n = 12, mu = 0 on both axes for arc-8 keys.

  §2  AT A FIXED ARC, mu FALLS WITH THE WIDTH.
      (a) Fixed-effects slope, one intercept per arc: -0.030 +/- 0.007 per bit
          differential (4.4 SE) and -0.013 +/- 0.003 linear (4.0 SE), against random
          keys' +0.107 / +0.061.  So random keys' growth with n is the arc growing with
          n, which more than offsets the fall.
      (b) Not a residue-class mix: at arc 8 it falls in both classes n = 1 and 2 (mod 3).
      (c) Replicated on the 1368 earlier pinned keys with arc <= 12 (random and §11.59's
          constructed): -0.025 +/- 0.003 / -0.007 +/- 0.001 per bit.
      PRINTED: at arc 8 differential mu falls 1.89 -> 1.33 from n = 10 to 22 (-30%),
      with no levelling visible.  This WITHDRAWS §11.61.3's reading that a key at
      n = 256 is no weaker than a key of its window measured at width w: that rested on
      a positive fixed-window slope, and the window mixes arcs.

  §3  AT A FIXED WIDTH, mu RISES WITH THE ARC, 4 < 8 < 12 < 16 at every width, both axes.
      Every arc-4 key fails the deployed criterion at every width; no arc-16 key does.

  §4  WHERE TYPICAL KEYS SIT.  Counted exhaustively at n = 13..20, the gap n - arc has
      mean 4.0 -> 4.5 and median 3-4: a random key's arc is a few bits short of n, and
      the gap grows like the longest zero run of a random string (~0.9 bits per doubling
      of n).  PRINTED, NOT SCORED: at n = 256 that reads about 8 bits.  So typical keys
      sit near the diagonal arc ~ n, where §2's fall is a cost of a few gap bits, not of
      the width; the n = 256 question for them is still the width question.

  CAVEATS.  Six keys per cell; arc 16 is measured only at n = 19, 20 and 22.  The fall is
  a measured slope over n = 10..22, not a law; nothing says how it continues.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_arc_curve.py [--regenerate]
      default      : verdicts from the pinned file (about 30 s; the exhaustive arc
                     enumerations are most of it)
      --regenerate : rebuild v2_arc_curve.json in parallel, resumable (about 2 h 15 min)
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
PINNED = os.path.join(HERE, "v2_arc_curve.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
ARCS = (4, 8, 12, 16)             # the arcs held fixed
NLO, NHI = 10, 22                 # every non-singular width: 3 | n is skipped, since M
                                  # is not invertible there and mu is identically 0
KPER = 6                          # keys per (n, arc), distinct deltas
JOBS = 7                          # parallel solves: ~0.87 GB each at n = 22
GAPW = (13, 14, 16, 17, 19, 20)   # widths whose n - arc is counted exhaustively


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


TL = _load("v2_tail_n22.py")          # arc(), keyset(), fe_r2(); S22, TS, KS, SW, KQ
TS = TL.TS
KS = TL.KS
SW = TL.SW
AUD = TL.S22.AUD


def cells():
    return [(n, a) for n in widths() for a in ARCS if a <= n - 2]


def widths():
    return [n for n in range(NLO, NHI + 1) if n % 3]


def by_arc(n):
    """{arc: [B]} over every key of width n with a non-affine delta, in key order."""
    aff = KS.affine(n)
    out = {a: [] for a in ARCS}
    for B in range(1 << n):
        d = AUD.delta(B, n)
        if d in aff:
            continue
        a = TL.arc(d, n)
        if a in out:
            out[a].append(B)
    return out


def draw(n, a, keys):
    """KPER keys drawn uniformly from the keys of arc a, skipping repeated deltas."""
    rnd = random.Random(KS.SEED * 1000 + n * 31 + a)
    seen, out = set(), []
    for B in rnd.sample(keys, len(keys)):
        d = AUD.delta(B, n)
        if d not in seen:
            seen.add(d)
            out.append(B)
            if len(out) == KPER:
                break
    return out


def plan():
    out = []
    for n in widths():
        K = by_arc(n)
        out += [(n, a, B) for a in ARCS if a <= n - 2 for B in draw(n, a, K[a])]
    return out


def solve(n, B):
    d = AUD.delta(B, n)
    out = []
    for axis in (0, 1):
        mu, W, _ = TS.trail(n, d, axis, 3 * n // 4)
        out.append([round(mu, 9), round(W[-1], 9)])
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section_1(rec):
    rule("§1  The sample: %d keys, arcs %s, every non-singular n = %d..%d"
         % (len(rec["rows"]), "/".join(map(str, ARCS)), NLO, NHI))
    rows = rec["rows"]
    check([(r[0], r[1], r[2]) for r in rows] == plan(), "the pinned rows are exactly plan()'s "
          "seeded draw: %d cells of %d keys, uniform over the keys of each arc" % (len(cells()),
                                                                              KPER))
    check(all(TL.arc(AUD.delta(r[2], r[0]), r[0]) == r[1] for r in rows),
          "every key's delta has the arc its row claims")
    check(all(len({AUD.delta(r[2], r[0]) for r in rows if (r[0], r[1]) == c}) == KPER
              for c in cells()), "the deltas within each cell are distinct")
    check(all(r[0] % 3 for r in rows) and min(r[3 + a][0] for r in rows for a in (0, 1)) > 0,
          "no width is singular (3 | n) and no row has mu = 0")
    # CONTROL: why 3 | n is skipped -- there M is not invertible and mu is 0 on every key
    n = 12
    aff = KS.affine(n)
    B12 = [B for B in range(1 << n) if AUD.delta(B, n) not in aff
           and TL.arc(AUD.delta(B, n), n) == 8][:3]
    TS.ESL.build()
    z = [solve(n, B) for B in B12]
    check(all(x[0][0] == 0 and x[1][0] == 0 for x in z), "CONTROL: at the singular width "
          "n = %d, mu = 0 on both axes for %d arc-8 keys -- the reason 3 | n is left out"
          % (n, len(z)))


def section_2(rows, M):
    rule("§2  At a fixed arc, mu FALLS with the width")
    for axis in (0, 1):
        nm = NAME[axis]
        print("\n  %s: mean mu by arc (rows) and width (columns)" % nm)
        print("     a  " + "".join("%7d" % n for n in widths()))
        for a in ARCS:
            print("  %4d  %s" % (a, "".join(
                "%7.3f" % st.mean(r[3 + axis][0] for r in rows if r[:2] == [n, a])
                if any(r[:2] == [n, a] for r in rows) else "%7s" % "." for n in widths())))
        b, se = SW.fe_slope([(r[1], r[0], r[3 + axis][0]) for r in rows])
        gen = SW.rand_slope(M, axis)
        print("  fixed-arc slope, one intercept per arc: %+.4f +/- %.4f per bit; random keys "
              "%+.4f +/- %.4f" % (b, se, gen[0], gen[1]))
        check(-b > 3 * se, "%s: at a fixed arc mu falls with n, %+.4f +/- %.4f per bit "
              "(%.1f SE)" % (nm, b, se, -b / se))
        check((gen[0] - b) / math.hypot(se, gen[1]) > 10, "%s: random keys' %+.3f per bit "
              "is then the arc growing with n, more than offsetting the fixed-arc fall"
              % (nm, gen[0]))
        cls = [SW.fe_slope([(8, r[0], r[3 + axis][0]) for r in rows
                            if r[1] == 8 and r[0] % 3 == c]) for c in (1, 2)]
        check(all(-x > 2.5 * e for x, e in cls), "%s: not a residue-class mix -- at arc 8 it "
              "falls in both classes, %+.4f +/- %.4f (n = 1 mod 3) and %+.4f +/- %.4f "
              "(n = 2 mod 3)" % ((nm,) + cls[0] + cls[1]))
        # the independent replicate: §11.63's random keys and §11.59's constructed ones
        pts = [(k[2], k[0], k[5 + axis]) for k in replicate() if k[2] <= 12]
        b2, se2 = SW.fe_slope(pts)
        check(-b2 > 5 * se2, "%s: replicated on the %d pinned random and constructed keys "
              "with arc <= 12: %+.4f +/- %.4f per bit" % (nm, len(pts), b2, se2))
    a8 = {n: st.mean(r[3][0] for r in rows if r[:2] == [n, 8]) for n in (NLO, NHI)}
    print("  PRINTED: at arc 8, differential mu goes %.2f -> %.2f from n = %d to %d (%.0f%%); "
          "no levelling is visible" % (a8[NLO], a8[NHI], NLO, NHI,
                                       100 * (a8[NHI] / a8[NLO] - 1)))


def replicate():
    """[(n, w, arc, y_d, y_l, mu_d, mu_l)] over the earlier pinned files."""
    out = []
    old = json.load(open(TS.PINNED))
    for n, _ in TS.PLAN:
        for r in old["widths"][str(n)]:
            out.append((n, None, TL.arc(AUD.delta(r[1], n), n), None, None, r[2][0], r[3][0]))
    for f in (TL.S22.PINNED, TL.PINNED):
        for r in json.load(open(f))["rows"]:
            out.append((NHI, None, TL.arc(AUD.delta(r[1], NHI), NHI), None, None, r[2][0],
                        r[3][0]))
    for r in json.load(open(SW.PINNED))["rows"]:
        out.append((r[0], r[1], TL.arc(r[3], r[0]), None, None, r[4][0], r[5][0]))
    return out


def section_3(rows):
    rule("§3  At a fixed width, mu rises with the arc")
    for axis in (0, 1):
        nm = NAME[axis]
        up = True
        for n in widths():
            ms = [st.mean(r[3 + axis][0] for r in rows if r[:2] == [n, a])
                  for a in ARCS if a <= n - 2]
            up &= all(x < y for x, y in zip(ms, ms[1:]))
        check(up, "%s: at every width the cell means rise with the arc, %s" % (
            nm, " < ".join(map(str, ARCS))))
        f = {a: (sum(r[3 + axis][1] < TS.BAR[axis] * r[0] for r in rows if r[1] == a),
                 sum(1 for r in rows if r[1] == a)) for a in ARCS}
        print("  %s below the bar: %s" % (nm, ", ".join("arc %d: %d of %d" % ((a,) + f[a])
                                                         for a in ARCS)))
        check(f[ARCS[0]][0] == f[ARCS[0]][1] and f[ARCS[-1]][0] == 0,
              "%s: every arc-%d key fails, at every width; no arc-%d key does"
              % (nm, ARCS[0], ARCS[-1]))


def section_4():
    rule("§4  What it changes: where typical keys sit, n - arc")
    print("     n   mean n - arc   median   P(n - arc <= 3)")
    g = {}
    for n in GAPW:
        aff = KS.affine(n)
        c = {}
        for B in range(1 << n):
            d = AUD.delta(B, n)
            if d not in aff:
                k = n - TL.arc(d, n)
                c[k] = c.get(k, 0) + 1
        tot = sum(c.values())
        g[n] = sum(k * v for k, v in c.items()) / tot
        acc, med = 0, None
        for k in sorted(c):
            acc += c[k]
            if med is None and acc >= tot / 2:
                med = k
        print("  %4d   %.3f          %d        %.3f" % (n, g[n], med,
              sum(v for k, v in c.items() if k <= 3) / tot))
    slope = (g[GAPW[-1]] - g[GAPW[0]]) / math.log2(GAPW[-1] / GAPW[0])
    check(0 < g[GAPW[-1]] - g[GAPW[0]] < 1, "a typical key sits a few bits below the "
          "diagonal, and the gap grows slowly: mean n - arc %.2f at n = %d, %.2f at n = %d"
          % (g[GAPW[0]], GAPW[0], g[GAPW[-1]], GAPW[-1]))
    print("  PRINTED, NOT SCORED: per doubling of n the mean gap grows %.2f bits -- the "
          "longest zero run of a random string, ~log2 n; at n = 256 that reads about %.1f "
          "bits, an extrapolation" % (slope, g[GAPW[-1]] + slope * math.log2(256 / GAPW[-1])))


def regenerate():
    TS.ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                n, B, x, y = json.loads(ln)
                done[(n, B)] = (x, y)
    rows = plan()
    # dearest first (wide, long arcs), so the pool does not end on one slow solve
    jobs = sorted([r for r in rows if (r[0], r[2]) not in done], key=lambda r: (-r[0], -r[1]))
    print("%d keys in %d cells, %d to solve" % (len(rows), len(cells()), len(jobs)), flush=True)
    lock = threading.Lock()

    def one(job):
        n, a, B = job
        t0 = time.time()
        x, y = solve(n, B)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([n, B, x, y]) + "\n")
            done[(n, B)] = (x, y)
            print("  %s n = %d, arc %d, B = %d: mu %.4f / %.4f in %.0f s (%d done)"
                  % (time.strftime("%H:%M"), n, a, B, x[0], y[0], time.time() - t0,
                     len(done)), flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 trail weights at a fixed arc of delta, "
                   "n = %d..%d; rows are [n, arc, key B, [mu_diff, W_diff(floor(3n/4))], "
                   "[mu_lin, W_lin]]" % (NLO, NHI),
                   "seed": KS.SEED, "kper": KPER,
                   "rows": [[n, a, B] + list(done[(n, B)]) for n, a, B in rows]},
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
        rec = json.load(fh)
    with open(TS.PINNED) as fh:
        M = TS.measures(json.load(fh))
    section_1(rec)
    section_2(rec["rows"], M)
    section_3(rec["rows"])
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
