#!/usr/bin/env python3
"""live_region_certificate.py — TODO #257 (ninth pass): where the optimal cycles pay,
and why telling the local certificate does not help.

#257 owes MONOTONICITY of exact mu, the minimum mean cycle of the NL-FSCX v2 difference
(and mask) graph, in n.  The seventh pass (local_certificate_n256.py, §11.44) solved the
window certificate at n = 256 -- positive, below 4/3 -- and said what a window misses:
"a LIGHT difference cannot stay light around a whole cycle", so the next route had to
carry non-local information about how a difference moves.  This pass finds such a fact,
measures where the optimal cycles actually pay, gives that information to the
certificate, and finds that it does not help -- with a control that says why.

  §1  THE LIVE-REGION LEMMA, checked exhaustively.  Addition with a CONSTANT preserves
      the LOWEST active bit of a difference exactly (below it the two carries agree),
      and M = I ^ ROL ^ ROR moves it down by exactly one -- unless the difference's
      MSB is set, when ROL wraps it to bit 0.  XOR constants do not touch a
      difference.  So in every round the lowest active bit descends one position for
      free or RESETS to 0, and a cycle must reset.  The linear axis is the mirror:
      addition with a constant has a nonzero correlation only when the input and
      output masks share their HIGHEST bit.  Everything above the extreme bit is the
      LIVE REGION; everything below it is dead.

  §2  WHERE THE OPTIMAL CYCLES PAY.  The exact solver's optimal cycle per key
      (certified_cycle_mean.c, n = 13..17), every edge split bit by bit by the chain
      rule along the carry automaton -- an exact decomposition, checked to sum to the
      solver's edge weight.  (a) Cycles alternate between rounds at the bottom (live
      region = the whole word) and EXCURSIONS that descend one bit per round; the
      excursions' share of rounds GROWS with n (0.25 -> 0.64 over n = 13..17).  (b) The cost
      is at delta's RUN BOUNDARIES, not at the wrap: most of it is paid on or just
      above a boundary, where the carry turns from near-deterministic (inside a run)
      to a fresh random bit; delta's trailing ZEROS are never paid for (no carry can
      form under them) -- #253's tz(delta) >= 4 weak class, seen from the cycle side.  (c) mu per
      boundary is ~0.31 differential and ~0.15 linear over these widths, but it is
      not a constant: it falls as boundaries crowd (they share cost), so it is NOT
      carried to n = 256.  (d) No per-round bound of that shape exists: single
      rounds with many live boundaries cost ~0, so any argument must amortise.

  §3  THE CERTIFICATE, TOLD.  The sixth/seventh pass's window LP plus a table
      g(feature) for features of the live region -- the extreme bit's position,
      the number of delta boundaries in the live region (§2's quantity), both
      extreme bits, and windows ANCHORED at the extreme bit.  Every one leaves the
      certified share FALLING with n, and none clears a CONTROL: a RANDOM labelling
      with the same number of classes ties the two n-class features (within 0.02)
      and beats every richer one.  So what the structured
      features buy is their class count -- at small n extra classes let the LP
      approach a value per node, which IS mu -- and not their content; at n = 256
      a random labelling has no structure for the bit-position DP to evaluate.
      Without the control, an anchored feature reaching 1.000 at n = 8 reads as
      progress; it has 4096 classes for 256 nodes.

  §4  WHAT THIS CHANGES.  Prose.

Fixed keys, an exact solver, a deterministic LP and a seeded control, so the verdict
cannot flake.  Needs a C compiler (exact_slope_ladder.py's solver IS §2) and highspy
with numpy (the LP IS §3); absent means FAIL, on those files' precedent.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/live_region_certificate.py [--quick]
      --quick : §2 at n = 13, 14, 16; §3 at n = 8, 10 (2 keys)   (~4 min on an aarch64 SBC)
      default : §2 adds n = 17 and more keys; §3 6 keys at n = 10 (~15 min)
"""

import argparse
import importlib.util
import math
import os
import random
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []

try:
    import highspy  # noqa: F401  (imported for the clear failure message; LPC uses it)
    import numpy as np
except ImportError:
    print("This gate needs the HiGHS LP solver and numpy:")
    print("    pip install highspy numpy")
    print("They ARE §3 (every certified share is an LP optimum), so a missing")
    print("solver is a failure, not a skip.")
    sys.exit(1)


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


ESL = _load("exact_slope_ladder.py")          # fifth pass: the C solver, cmu(), keys
LC = _load("local_certificate_n256.py")       # seventh pass: global_bound, quotient_mu
LPC = LC.LPC                                  # sixth pass: graph(), local_bound
CCL = ESL.CCL
DT, LT = CCL.DIFF_T, CCL.LIN_T
keys, med = ESL.keys, statistics.median


def low(x):
    return (x & -x).bit_length() - 1


def hi(x):
    return x.bit_length() - 1


def m_tab(n):
    m = (1 << n) - 1
    return [(x ^ ((x << 1 | x >> (n - 1)) & m) ^ ((x >> 1 | x << (n - 1)) & m)) & m
            for x in range(1 << n)]


def boundaries(d, n):
    """Positions i >= 1 where delta's bit differs from the one below: run boundaries."""
    return [i for i in range(1, n) if ((d >> i) & 1) != ((d >> (i - 1)) & 1)]


# ═══════════════════════════════════════════════════════════════════════════
# §1  the live-region lemma
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The live-region lemma, checked exhaustively")
    n = 10
    N, MASK = 1 << n, (1 << n) - 1
    x = np.arange(N, dtype=np.int64)
    bad_add = 0
    ks = keys(n, 6)
    for d in ks:
        for a in range(1, N):
            o = ((x + d) & MASK) ^ (((x ^ a) + d) & MASK)
            lo = np.log2(o & -o).astype(np.int64)
            bad_add += int(np.count_nonzero(lo != low(a)))
    check(bad_add == 0,
          "addition with a constant preserves the LOWEST active bit of a difference: "
          "0 violations over every alpha and every x, %d keys at n = %d" % (len(ks), n))

    bad_m = 0
    for n2 in (10, 16):
        Ma = m_tab(n2)
        for a in range(1, 1 << n2):
            j, msb = low(a), a >> (n2 - 1)
            if j >= 2 and low(Ma[a]) != (0 if msb else j - 1):
                bad_m += 1
            if j == 1 and not msb and low(Ma[a]) != 0:
                bad_m += 1
    check(bad_m == 0,
          "M moves the lowest active bit down by exactly one, or RESETS it to 0 when "
          "the MSB is set (ROL wraps it): 0 violations over every alpha at n = 10, 16")

    n = 8
    N, MASK = 1 << n, (1 << n) - 1
    xs = np.arange(N)
    H = np.array([[1 - 2 * (bin(a & v).count("1") & 1) for v in range(N)]
                  for a in range(N)], dtype=np.int64)
    bad_lin = 0
    for d in (0, 1, 5, 37, 128, 201, 255):
        Pm = np.zeros((N, N), dtype=np.int64)
        Pm[xs, (xs + d) & MASK] = 1
        C = H @ Pm @ H                      # C[a, b] = sum_x (-1)^(a.x ^ b.(x+d))
        for a in range(1, N):
            for b in np.nonzero(C[a])[0]:
                if b and hi(int(b)) != hi(a):
                    bad_lin += 1
    check(bad_lin == 0,
          "linear dual: addition with a constant has a nonzero correlation only when "
          "the input and output masks share their HIGHEST bit (0 violations, every "
          "mask pair at n = 8, seven constants including 0 and 2^(n-1))")
    print("""
So the difference's lowest active bit (the mask's highest) walks one position per
round for free, or resets at the wrap, and every cycle must reset.  The bits beyond
it are DEAD: the carry difference is zero there.  The rest is the LIVE REGION.""")


# ═══════════════════════════════════════════════════════════════════════════
# §2  where the optimal cycles pay
# ═══════════════════════════════════════════════════════════════════════════
def diff_profile(n, d, a, b, Ma):
    """Chain-rule split of w(a -> b) over bit positions, LSB to MSB.  Each term is
    1 - log2(S_{i+1}/S_i) for the carry automaton's path mass S, so it is >= 0 and
    the terms sum to exactly the edge weight."""
    al = Ma[a]
    e = al ^ b
    v0, v1, cls = 1.0, 0.0, 0
    c = []
    for i in range(n - 1):
        ec = (e >> (i + 1)) & 1
        m = DT[((d >> i) & 1, (al >> i) & 1, cls, ec)]
        S = v0 + v1
        v0, v1 = m[0] * v0 + m[1] * v1, m[2] * v0 + m[3] * v1
        c.append(1 - math.log2((v0 + v1) / S))
        cls = ec
    c.append(0.0)
    return c


def lin_profile(n, d, u, t, Minv):
    """The same split on the mask axis, by the l1 norm of the carry vector (signs
    cancel only at the end, so the last term carries log2(l1 / |sum|))."""
    w = Minv[t]
    v0, v1 = 1.0, 0.0
    c = []
    for i in range(n):
        m = LT[((d >> i) & 1, (u >> i) & 1, (w >> i) & 1)]
        S = abs(v0) + abs(v1)
        v0, v1 = m[0] * v0 + m[1] * v1, m[2] * v0 + m[3] * v1
        c.append(-math.log2((abs(v0) + abs(v1)) / S))
    c[-1] += math.log2((abs(v0) + abs(v1)) / abs(v0 + v1))
    return c


def anatomy(n, d, axis, Ma, Minv):
    m, _, _, cyc = ESL.cmu(n, d, axis, cycle=True)
    nodes = [v for v, _ in cyc]
    ws = [w for _, w in cyc]
    L = len(nodes)
    P = [0.0] * n
    worst = 0.0
    steps = []
    bnd = boundaries(d, n)
    for k, a in enumerate(nodes):
        b = nodes[(k + 1) % L]
        c = diff_profile(n, d, a, b, Ma) if axis == 0 else lin_profile(n, d, a, b, Minv)
        worst = max(worst, abs(sum(c) - ws[k]))
        for i in range(n):
            P[i] += c[i]
        p = low(a) if axis == 0 else n - 1 - hi(a)
        live = (sum(1 for i in bnd if i > low(a)) if axis == 0
                else sum(1 for i in bnd if i <= hi(a)))
        steps.append((p, live, ws[k]))
    pos = [s[0] for s in steps]
    lem = sum(1 for k in range(L) if pos[k] >= 2 and
              pos[(k + 1) % L] not in (pos[k] - 1, 0))
    tot = sum(P)
    S0 = set(bnd)
    S1 = {i + 1 for i in bnd if i + 1 < n}
    tz = bnd[0] if bnd else n
    return dict(d=d, mu=m, L=L, runs=len(bnd) + 1, worst=worst, lem=lem,
                at=sum(P[i] for i in S0) / tot, above=sum(P[i] for i in S1) / tot,
                band=sum(P[i] for i in S0 | S1) / tot, frac=len(S0 | S1) / n,
                lowrun=sum(P[:tz]) / tot,
                pb=[P[i] / L for i in range(n) if i in S1],
                po=[P[i] / L for i in range(n) if i not in S1],
                exc=sum(1 for s in steps if s[0] >= 3) / L,
                steps=steps)


def section_2(plan):
    rule("§2  Where the optimal cycles pay")
    print("""The exact solver's optimal cycle for each key, every edge split bit by bit by
the chain rule along the carry automaton.  'band' = positions on or one above a
run boundary of delta; 'excursion' = a round whose extreme bit is >= 3 from the
wrap, i.e. whose live region has lost its lowest three positions.
""")
    recs = {0: {}, 1: {}}
    for n, cnt in plan:
        Ma = m_tab(n)
        Minv = [0] * (1 << n)
        for xx, y in enumerate(Ma):
            Minv[y] = xx
        for d in keys(n, cnt):
            for axis in (0, 1):
                recs[axis].setdefault(n, []).append(anatomy(n, d, axis, Ma, Minv))
    print("  %-12s %3s %4s  %6s %6s %6s %6s  %8s %8s  %6s  %6s" %
          ("axis", "n", "keys", "band", "size", "at+1", "lowrun", "c/pos@+1",
           "c/pos else", "mu/bnd", "excurs"))
    S = {}
    for axis in (0, 1):
        for n in sorted(recs[axis]):
            R = recs[axis][n]
            s = S[(axis, n)] = dict(
                band=med(r["band"] for r in R), size=med(r["frac"] for r in R),
                above=med(r["above"] for r in R), lowrun=med(r["lowrun"] for r in R),
                pb=statistics.mean(x for r in R for x in r["pb"]),
                po=statistics.mean(x for r in R for x in r["po"]),
                kap=med(r["mu"] / (r["runs"] - 1) for r in R if r["runs"] > 1),
                exc=med(r["exc"] for r in R))
            print("  %-12s %3d %4d  %6.2f %6.2f %6.2f %6.3f  %8.3f %8.3f  %6.3f  %6.2f" %
                  (("differential", "linear")[axis], n, len(R), s["band"], s["size"],
                   s["above"], s["lowrun"], s["pb"], s["po"], s["kap"], s["exc"]))
    allr = [r for ax in (0, 1) for n in recs[ax] for r in recs[ax][n]]
    ns = sorted(recs[0])

    check(max(r["worst"] for r in allr) < 1e-6,
          "the per-position split is EXACT: it sums to the solver's edge weight on every "
          "edge of every optimal cycle (worst gap %.1e)" % max(r["worst"] for r in allr))
    check(sum(r["lem"] for r in allr) == 0,
          "every step of every optimal cycle obeys §1: away from the bottom the extreme "
          "bit descends by one or resets to 0")
    check(all(S[(0, n)]["band"] >= S[(0, n)]["size"] + 0.10 for n in ns) and
          all(S[(0, n)]["band"] >= 0.80 for n in ns),
          "differential cost sits at delta's RUN BOUNDARIES: median %s of each cycle's "
          "weight is on or one above a boundary, against %s of the positions"
          % ("/".join("%.2f" % S[(0, n)]["band"] for n in ns),
             "/".join("%.2f" % S[(0, n)]["size"] for n in ns)))
    check(all(S[(0, n)]["pb"] >= 2.5 * S[(0, n)]["po"] for n in ns) and
          all(S[(1, n)]["pb"] >= 1.2 * S[(1, n)]["po"] for n in ns),
          "a position one above a boundary costs %s x an ordinary one per round "
          "(differential) and %s x (linear): the carry is a fresh bit there and "
          "near-deterministic inside a run"
          % ("/".join("%.1f" % (S[(0, n)]["pb"] / S[(0, n)]["po"]) for n in ns),
             "/".join("%.1f" % (S[(1, n)]["pb"] / S[(1, n)]["po"]) for n in ns)))
    z = [r for n in ns for r in recs[0][n] if not r["d"] & 1]
    o = [r for n in ns for r in recs[0][n] if r["d"] & 1]
    zp = sum(1 for r in z if r["lowrun"] > 1e-9)
    op = sum(1 for r in o if r["lowrun"] > 1e-9)
    check(z and zp == 0 and op > 0,
          "delta's TRAILING ZEROS are never paid for (%d of %d keys whose lowest run is "
          "zeros pay nothing there: with no carry in and a 0 addend no carry can form) "
          "while a lowest run of ONES is paid in %d of %d -- #253's tz(delta) weak "
          "class, seen from the cycle side" % (len(z) - zp, len(z), op, len(o)))
    kd = [S[(0, n)]["kap"] for n in ns]
    kl = [S[(1, n)]["kap"] for n in ns]
    check(all(0.25 <= k <= 0.40 for k in kd) and all(0.12 <= k <= 0.20 for k in kl),
          "mu per boundary of delta is %s (differential) and %s (linear) -- a scale, "
          "not a law: see the next check" % ("/".join("%.2f" % k for k in kd),
                                             "/".join("%.2f" % k for k in kl)))
    corr = []
    for axis in (0, 1):
        R = [r for n in ns for r in recs[axis][n] if r["runs"] > 1]
        dens = [(r["runs"] - 1) / len(r["pb"] + r["po"]) for r in R]
        rat = [r["mu"] / (r["runs"] - 1) for r in R]
        corr.append(statistics.correlation(dens, rat))
    check(all(c < -0.3 for c in corr),
          "mu per boundary FALLS as boundaries crowd (correlation with boundary density "
          "%.2f differential, %.2f linear): boundaries share cost, so the scale is NOT "
          "carried to n = 256, where a typical delta has ~128 of them" % tuple(corr))
    zero_many = 0
    for axis in (0, 1):
        for n in ns:
            for r in recs[axis][n]:
                zero_many += sum(1 for p, live, w in r["steps"] if live >= 3 and w < 0.05)
    check(zero_many > 0,
          "NO per-round bound of that shape exists: %d rounds of optimal cycles cost "
          "under 0.05 bits with three or more boundaries live.  Any argument has to "
          "AMORTISE across rounds, which is what a potential does" % zero_many)
    ex = [S[(0, n)]["exc"] for n in ns]
    print("""
  Excursions: the median share of rounds spent away from the bottom is %s on the
  differential axis over n = %s: they become MORE common as n grows, so a picture of
  cycles pinned at the wrap -- a finite problem at the boundary -- does not hold.""" %
          ("/".join("%.2f" % e for e in ex), "/".join(map(str, ns))))
    return S


# ═══════════════════════════════════════════════════════════════════════════
# §3  the certificate, told
# ═══════════════════════════════════════════════════════════════════════════
def features(n, d):
    bnd = boundaries(d, n)

    def anch(v):
        def f(x):
            p, win = low(x), 0
            for k in range(v):
                win |= ((x >> ((p + k) % n)) & 1) << k
            return p * (1 << v) + win
        return f, n << v
    return [
        ("lowest bit", lambda x: low(x), n),
        ("live boundaries", lambda x: sum(1 for i in bnd if i > low(x)), n),
        ("lowest+highest", lambda x: low(x) * n + hi(x), n * n),
        ("anchored 3-bit", ) + anch(3),
        ("anchored 5-bit", ) + anch(5),
    ]


def random_feature(n, K, seed):
    r = random.Random(seed)
    tab = [r.randrange(K) for _ in range(1 << n)]
    return lambda x: tab[x]


def section_3(plan):
    rule("§3  The certificate, told where the live region is")
    print("""Median share of exact mu certified by the window LP (w = 3, 5) with a table
g(feature) added, against the same LP with a RANDOM labelling of the nodes into the
same number of classes.  Exhaustive graphs.
""")
    W = (3, 5)
    T = {}
    names = None
    for n, cnt in plan:
        for d in keys(n, cnt):
            mu, E = LPC.graph(n, d)
            fs = features(n, d)
            names = [f[0] for f in fs]
            for w in W:
                T.setdefault((n, w, "windows only"), []).append(
                    LPC.local_bound(n, w, E)[0] / mu)
                for j, (name, f, K) in enumerate(fs):
                    T.setdefault((n, w, name), []).append(
                        LC.global_bound(n, w, E, f, K) / mu)
                    g = random_feature(n, K, 1000003 * n + 7919 * j + d)
                    T.setdefault((n, w, name + " [rand]"), []).append(
                        LC.global_bound(n, w, E, g, K) / mu)
    ns = [n for n, _ in plan]
    print("  %-22s %8s   " % ("feature", "classes") +
          "   ".join("w=%d n=%s" % (w, "->".join(map(str, ns))) for w in W))
    rows = ["windows only"] + names
    for name in rows:
        for tag in ("", " [rand]"):
            if name == "windows only" and tag:
                continue
            key = name + tag
            K = {"windows only": "-", "lowest bit": "n", "live boundaries": "n",
                 "lowest+highest": "n^2", "anchored 3-bit": "8n",
                 "anchored 5-bit": "32n"}[name]
            print("  %-22s %8s   " % (key if not tag else "  random, same classes", K) +
                  "   ".join(" -> ".join("%.3f" % med(T[(n, w, key)]) for n in ns)
                             + " " * 4 for w in W))
    n0, n1 = ns[0], ns[-1]
    fall = all(med(T[(n1, w, nm)]) < med(T[(n0, w, nm)]) for w in W for nm in rows)
    check(fall,
          "every feature leaves the certified share FALLING from n = %d to %d, at both "
          "windows -- the stop rule set before the run" % (n0, n1))
    slack = [(n, w, nm, med(T[(n, w, nm)]) - med(T[(n, w, nm + " [rand]")]))
             for n in ns for w in W for nm in names]
    worst = max(x[3] for x in slack)
    big = [x for x in slack if x[2] in names[2:]]
    check(worst <= 0.025 and all(x[3] < 0 for x in big),
          "a RANDOM labelling with the same number of classes does as well: the two "
          "n-class features beat it by at most %+.3f, and every richer feature "
          "(n^2, 8n, 32n classes) is BEATEN by it, by %.3f-%.3f -- what the features "
          "buy is their class count, not their content"
          % (worst, min(-x[3] for x in big), max(-x[3] for x in big)))
    gain = max(med(T[(n1, w, nm)]) - med(T[(n1, w, "windows only")])
               for w in W for nm in names[:2])
    check(gain < 0.06,
          "the two features §2 points at -- the extreme bit's position and the number "
          "of boundaries in the live region -- add at most %.3f to the share at n = %d"
          % (gain, n1))
    print("""
  An anchored window reaches 1.000 at n = 8 with 4096 classes for 256 nodes when
  paired with the highest bit; that is the class count talking, and the control is
  what says so.  At n = 256 a random labelling cannot be evaluated by the
  bit-position DP at all, so it is a bar the usable features had to clear, not a
  candidate.""")
    return T


# ═══════════════════════════════════════════════════════════════════════════
# §4  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_4():
    rule("§4  What this changes")
    print("""* A STRUCTURAL FACT about the round, exact at every width: the live region of a
  difference (a mask) moves one bit per round or resets at the wrap.  It is the
  non-local information the seventh pass asked for, and it is TRUE -- every step of
  every optimal cycle obeys it.

* WHERE mu IS PAID: at delta's run boundaries, about one bit above each, while
  delta's trailing zeros are free.  That is the mechanism behind the fifth pass's "mu rises with
  the run count", which until now was a regression.  mu per boundary is ~0.31 / ~0.15
  and falls as boundaries crowd, so it is a description and not a figure for n = 256.

* THE LOCAL-POTENTIAL ROUTE IS CLOSED.  Three passes have now given the window
  certificate non-local information -- windows alone (sixth), global statistics and
  two-round paths (seventh), the live region's position and windows anchored to it
  (this one) -- and each leaves the certified share falling.  This one adds the
  control the others lacked: a random labelling of equal size does as well (ties
  the smallest features, beats the rest),
  so a potential whose class count stays small against the graph carries nothing a
  DP at n = 256 could use.  A bound at the deployed width needs an argument about
  CYCLES, not about edge-local potentials.

* #257 is unchanged in status: (1''') monotonicity of exact mu, and (2') the hull's
  share above n = 16.  No rating moves.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    ESL.build()
    section_1()
    if a.quick:
        section_2([(13, 8), (14, 8), (16, 6)])
        section_3([(8, 6), (10, 2)])
    else:
        section_2([(13, 16), (14, 16), (16, 12), (17, 12)])
        section_3([(8, 6), (10, 6)])
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
