#!/usr/bin/env python3
"""width_lift_closure.py — TODO #257 (tenth pass): two routes to n = 256 that use
no potential, and why neither gets there.

The ninth pass (live_region_certificate.py) closed the local-potential route and
said a bound at the deployed width needs an argument about CYCLES.  Two such
routes do not need a certificate at all, and this pass walks both.

  §1  THE UPPER BOUND, BY CONSTRUCTION.  Every lower bound in #257 has so far
      been compared with extrapolations, and the fifth pass left two of them
      standing at n = 256 (a power law, ~13, and a levelled per-bit median,
      ~33).  A lower bound cannot separate them.  An UPPER bound can: one
      explicit cycle with mean below 33 at n = 256 would refute the levelled
      reading for that key.  The cheapest-edge map u -> argmin_v w(u, v) is a
      function on the 2^n differences, so iterating it from any start must
      close a cycle, and every edge it uses is a real edge -- the cycle's mean
      is a sound upper bound on mu, checked against exact mu at n = 13 and 14.
      FINDING, in two parts.
      (a) The walk closes after EXPONENTIALLY many steps: log2 of the rho length
          (tail plus cycle) grows a third to a half of a bit per bit of width
          over n = 14..26 (a random mapping's is 0.5), which puts closure at
          n = 256 somewhere past 2^80 steps.  Breadth-first exploration does no
          better: 20 000 nodes at n = 32 or 64 contained no cycle at all.
      (b) And where it DOES close, the cycle is loose: 1.3-2.0x exact mu at
          n = 13-14, and about 0.2-0.3 n at n = 20-26 against exact mu's
          0.13-0.15 n.  So even a walk that closed at n = 256 could refute the
          levelled reading (~33) only if the truth were near the power law's ~13
          -- it would confirm a low value, never establish a high one.
      No constructive upper bound on mu(256) is available by search.

  §2  THE LIFT BETWEEN WIDTHS.  §11.37 recorded that there is NO EMBEDDING
      between widths, because M and delta both depend on n -- and that is true
      of the graphs.  It is not true of the KEYS: inserting one bit inside a
      run of delta, equal to that run, is a natural map from width n to n + 1
      that keeps delta's boundary sequence, and the strongest form of the
      monotonicity #257 owes would be "mu never decreases along it".  If it
      held, mu(256) >= 4/3 would follow from a short chain of lifts plus
      boundary insertions from a width where mu is exact.
      FINDING: it does not hold, and how it fails is the information.
      (a) Stretching a run LOWERS exact mu on a substantial fraction of
          (key, run) pairs, on both axes, at n = 13 and n = 16.
      (b) What decides the sign is the RUN LENGTH.  Stretching a run of
          length 1 -- which turns a single-bit run into a two-bit one and moves
          the boundary above it one position away -- raises mu by about
          0.1-0.2; stretching a run of length >= 3 changes it by ~0 on average.
          Width that adds no boundary adds no cost, which is §11.46.2's
          "the cost is at delta's run boundaries" seen as a statement about n.
      (c) Stretching the LOWEST run of zeros -- deepening tz(delta), #253's
          weak class -- moves mu by ~0 either way: those bits are never paid for
          (§11.46.2), so adding one is neither a cost nor a saving.  A first draft
          claimed it LOWERS mu "most often"; true at n = 13 (8 of 12 keys), false
          at n = 16 (3 of 7), and withdrawn before it shipped.
      (d) At FIXED width, flipping one interior bit of a run of length >= 3 --
          which adds two boundaries -- raises mu on most keys (all 16 at n = 16
          on the differential axis), but not on every key at every width.
      So exact mu grows with n only through the boundaries a typical delta
      carries, about n/2; neither local operation is monotone key by key, and
      monotonicity, if it holds, is a DISTRIBUTIONAL statement about typical
      keys, not a pointwise one along any natural lift.

  §3  WHAT THIS CHANGES.  Prose.

Fixed seeds throughout (every key, every run choice), so the verdict is a
deterministic computation and cannot flake.  §2 drives exact_slope_ladder.py's
C solver, which IS the gate there, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/width_lift_closure.py [--quick | --full]
      --quick : closure n = 14..22; lift at n = 13       (~1.5 min on an aarch64 SBC)
      default : closure n = 14..26; lift at n = 13, 16    (~17 min)
      --full  : adds the lift at n = 19                   (~1 h)
"""

import argparse
import heapq
import importlib.util
import math
import os
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


ESL = _load("exact_slope_ladder.py")   # the C solver (cmu), build()
CCL = ESL.CCL                          # DIFF_T, diff_row, keys
DT = CCL.DIFF_T


def Mx(x, n):
    m = (1 << n) - 1
    return (x ^ (((x << 1) | (x >> (n - 1))) & m) ^ (((x >> 1) | (x << (n - 1))) & m)) & m


# ═══════════════════════════════════════════════════════════════════════════
# the cheapest out-edge, at any width
# ═══════════════════════════════════════════════════════════════════════════
def cheapest(n, d, a):
    """The least-weight out-edge a -> b of the difference graph, and its weight.

    Best-first over the carry-pair automaton (the same DIFF_T the certified solver
    uses).  At depth i the partial count can at most double per remaining bit,
    so i - log2(count) is a lower bound on the final weight and is
    non-decreasing along a branch: the first complete edge popped is optimal.
    Ties are broken by the output difference, so the map is a function."""
    al = Mx(a, n)
    top = n - 1
    h = [(0.0, 0, 0, 0, 1.0, 0.0)]
    while h:
        pr, e, i, cls, v0, v1 = heapq.heappop(h)
        if i == top:
            return al ^ e, top - math.log2(v0 + v1)
        di, ai = (d >> i) & 1, (al >> i) & 1
        for ec in (0, 1):
            m00, m01, m10, m11 = DT[(di, ai, cls, ec)]
            w0, w1 = m00 * v0 + m01 * v1, m10 * v0 + m11 * v1
            if w0 + w1 > 0:
                heapq.heappush(h, (i + 1 - math.log2(w0 + w1),
                                   e | (ec << (i + 1)), i + 1, ec, w0, w1))
    raise RuntimeError("no out-edge")


def walk(n, d, a, maxs):
    """Iterate the cheapest-edge map from a.  (cycle length, cycle mean, tail)."""
    pos, ws = {}, []
    while a not in pos and len(ws) < maxs:
        pos[a] = len(ws)
        a, w = cheapest(n, d, a)
        ws.append(w)
    if a not in pos:
        return None
    i = pos[a]
    cyc = ws[i:]
    return len(cyc), sum(cyc) / len(cyc), i


def starts(n):
    return [(1 << s) | (1 << (n - 1 - s)) for s in range(4)]


# ═══════════════════════════════════════════════════════════════════════════
# §1  the upper bound, by construction
# ═══════════════════════════════════════════════════════════════════════════
def section_1(quick):
    rule("§1  A constructive upper bound: the cheapest-edge map, and when it closes")
    print("""Iterate u -> its cheapest out-edge.  It is a function on 2^n differences, so it
closes a cycle, and that cycle's mean bounds mu from ABOVE -- the only kind of
bound that could refute an extrapolation rather than merely sit under one.
""")
    # (a) the enumerator is the solver's edge set
    worst, nodes = 0.0, 0
    for d in CCL.keys(10, 3):
        Ma = [Mx(x, 10) for x in range(1 << 10)]
        for a in range(1, 1 << 10, 7):
            _, ws = CCL.diff_row(10, d, a, 10.0, Ma)
            _, w = cheapest(10, d, a)
            worst = max(worst, abs(w - min(ws)))
            nodes += 1
    check(worst < 1e-9,
          "the best-first enumerator returns the least edge weight of the certified "
          "solver's row on %d nodes at n = 10, three keys (max |diff| %.1e)"
          % (nodes, worst))

    # (b) soundness and quality against exact mu
    print("\n  %3s  %10s  %8s  %8s  %6s" % ("n", "delta", "exact", "greedy", "ratio"))
    ratios = []
    for n in (13, 14):
        for d in CCL.keys(n, 4):
            ex = ESL.cmu(n, d, 0)[0]
            best = min(r[1] for r in (walk(n, d, s, 1 << 16) for s in starts(n)) if r)
            ratios.append(best / ex)
            print("  %3d  %#10x  %8.4f  %8.4f  %6.3f" % (n, d, ex, best, best / ex))
    check(min(ratios) >= 1 - 1e-9,
          "every greedy cycle's mean is >= exact mu (it is a real cycle): minimum "
          "ratio %.3f over 8 keys at n = 13, 14" % min(ratios))
    check(statistics.median(ratios) > 1.2,
          "and it is a LOOSE one -- median ratio %.2f to exact mu"
          % statistics.median(ratios))

    # (c) the closure law
    ns = (14, 16, 20, 22) if quick else (14, 16, 20, 22, 24, 26)
    print("\n  %3s  %12s  %8s  %10s  %8s" % ("n", "median rho", "log2", "cycle mean",
                                             "per bit"))
    xs, ys, cmeans = [], [], []
    for n in ns:
        rho, cm = [], []
        for d in CCL.keys(n, 4):
            for s in starts(n):
                r = walk(n, d, s, 1 << 20)
                if r:
                    rho.append(r[0] + r[2])
                    cm.append(r[1])
        mr = statistics.median(rho)
        xs.append(n)
        ys.append(math.log2(mr))
        cmeans.append(statistics.median(cm))
        print("  %3d  %12.1f  %8.2f  %10.3f  %8.3f"
              % (n, mr, math.log2(mr), statistics.median(cm), statistics.median(cm) / n))
    slope = statistics.linear_regression(xs, ys)[0]
    check(slope > 0.25,
          "the walk closes after EXPONENTIALLY many steps: log2(median rho) grows %.2f "
          "bits per bit of width over n = %d..%d (a random mapping: 0.5), so at n = 256 "
          "closure is ~2^%d steps away" % (slope, xs[0], xs[-1], round(slope * 256)))
    print("  greedy cycle mean per bit at n = %d: %.3f (exact mu: ~0.13-0.15 there, "
          "fifth pass)" % (ns[-1], cmeans[-1] / ns[-1]))
    return slope


# ═══════════════════════════════════════════════════════════════════════════
# §2  the lift between widths
# ═══════════════════════════════════════════════════════════════════════════
def runs(d, n):
    """(start, length, bit) of each maximal run of delta, lowest first."""
    out, s = [], 0
    for i in range(1, n + 1):
        if i == n or ((d >> i) & 1) != ((d >> (i - 1)) & 1):
            out.append((s, i - s, (d >> s) & 1))
            s = i
    return out


def stretch(d, pos, bit, k):
    """Insert k copies of `bit` at position pos (inside a run of that bit)."""
    lo = d & ((1 << pos) - 1)
    return lo | ((((1 << k) - 1) if bit else 0) << pos) | ((d >> pos) << (pos + k))


def lift(axis, n, cnt):
    """Stretch every run of every key by one bit (two where n + 1 is a multiple of
    3, where M is singular), and flip one interior bit of one long run per key."""
    k = 2 if (n + 1) % 3 == 0 else 1
    st, fl = [], []
    for j, d in enumerate(CCL.keys(n, cnt)):
        m0 = ESL.cmu(n, d, axis)[0]
        R = runs(d, n)
        for i, (s, L, b) in enumerate(R):
            m1 = ESL.cmu(n + k, stretch(d, s, b, k), axis)[0]
            st.append(dict(L=L, low0=(i == 0 and b == 0), dmu=m1 - m0))
        longr = [(s, L) for s, L, _ in R if L >= 3]
        if longr:
            s, L = longr[j % len(longr)]
            p = s + 1 + (j % (L - 2))
            fl.append(ESL.cmu(n, d ^ (1 << p), axis)[0] - m0)
    return st, fl, k


def section_2(widths):
    rule("§2  The lift between widths: stretch a run of delta by one bit")
    print("""Insert one bit inside a run of delta, equal to the run: width n -> n + 1, the same
boundary sequence.  Every run of every key is stretched in turn, and exact mu is
compared before and after.  "flip" is the other local operation, at FIXED width:
one interior bit of a run of length >= 3 is flipped, adding two boundaries.
""")
    NAME = {0: "differential", 1: "linear"}
    for axis in (0, 1):
        for n, cnt in widths:
            st, fl, k = lift(axis, n, cnt)
            nm = "%s, n = %d -> %d" % (NAME[axis], n, n + k)
            neg = [r for r in st if r["dmu"] < -1e-9]

            def mean(rows):
                return sum(r["dmu"] for r in rows) / len(rows)
            l1 = [r for r in st if r["L"] == 1]
            l3 = [r for r in st if r["L"] >= 3]
            lz = [r for r in st if r["low0"]]
            print("\n  %s: %d (key, run) lifts, %d keys" % (nm.upper(), len(st), cnt))
            print("    lowers mu: %d (%.0f%%), largest drop %.3f"
                  % (len(neg), 100 * len(neg) / len(st), min(r["dmu"] for r in st)))
            print("    mean change: run length 1 %+.3f (%d)   length >= 3 %+.3f (%d)   "
                  "lowest run of zeros %+.3f (%d)"
                  % (mean(l1), len(l1), mean(l3), len(l3), mean(lz), len(lz)))
            print("    flip at fixed width: median %+.3f, lowers mu on %d of %d keys"
                  % (statistics.median(fl), sum(x < -1e-9 for x in fl), len(fl)))
            check(len(neg) >= len(st) // 10 and min(r["dmu"] for r in st) < -0.02,
                  "%s: the lift is NOT monotone -- it lowers exact mu on %d of %d "
                  "(key, run) pairs" % (nm, len(neg), len(st)))
            gap = 0.08 if axis == 0 else 0.03
            check(mean(l1) > mean(l3) + gap and abs(mean(l3)) < 0.06,
                  "%s: the sign is set by RUN LENGTH -- stretching a length-1 run adds "
                  "%+.3f, a run of length >= 3 %+.3f (width without a new boundary "
                  "adds ~nothing)" % (nm, mean(l1), mean(l3)))
            check(abs(mean(lz)) < 0.05,
                  "%s: stretching the lowest run of zeros (deepening tz, #253's weak "
                  "class) moves mu by %+.3f on average -- those bits are never paid "
                  "for, so one more is neither cost nor saving" % (nm, mean(lz)))
            check(statistics.median(fl) > 0.05
                  and sum(x > 0 for x in fl) >= 0.75 * len(fl),
                  "%s: adding two boundaries at fixed width raises mu on %d of %d keys "
                  "(median %+.3f)"
                  % (nm, sum(x > 0 for x in fl), len(fl), statistics.median(fl)))


# ═══════════════════════════════════════════════════════════════════════════
# §3  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_3():
    rule("§3  What this changes for #257")
    print("""CLOSED: a constructive upper bound on mu(256).  The cheapest-edge map closes like
a random mapping, so no cycle can be exhibited at the deployed width by search, and
the cycles it does close are loose (1.3-2.0x exact mu at n = 13-14; 0.21-0.30 n at
n = 20-26 against exact mu's ~0.13-0.15 n).  The two n = 256 readings of
§11.42 -- ~13 and ~33 -- stay unseparated; nothing short of exact mu separates them.

CLOSED: monotonicity along the natural lift.  §11.37's "no embedding" is true of the
graphs and not of the keys: stretching a run of delta is a natural map n -> n + 1.
Exact mu is NOT monotone along it -- it falls on a large minority of lifts, on both
axes -- and the fixed-width boundary insertion, though it raises mu on nearly every
key, is not monotone either.  So the monotonicity #257
owes cannot be pointwise along any chain of these operations; if it holds, it holds
for TYPICAL keys, as a distributional statement.

MEASURED: width that adds no boundary adds no cost.  Stretching a run of length >= 3
moves mu by ~0 on average; a length-1 run adds 0.1-0.2.  Exact mu grows with n through
delta's boundary count (about n/2 for a typical key), which is §11.46.2's mechanism
stated as a statement about width.  It moves the question, not the answer: what #257
owes is how mu behaves as BOUNDARIES are added at density 1/2, and the per-boundary
cost falls as boundaries crowd (§11.46.2).

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    ESL.build()
    section_1(a.quick)
    widths = [(13, 24)]
    if not a.quick:
        widths.append((16, 16))
    if a.full:
        widths.append((19, 8))
    section_2(widths)
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
