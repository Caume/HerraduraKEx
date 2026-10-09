#!/usr/bin/env python3
"""certified_cycle_ladder.py — TODO #257 (fourth pass): exact mu on BOTH axes, to n = 20.

v9.5.24 (quenched_exact_ladder.py) found the annealed model of §11.38 crossing the
exact minimum mean cycle on the DIFFERENTIAL axis between n = 11 and 13, and left two
things open that were both limits of construction rather than of the question:

  * the LINEAR axis stopped at n = 11, because lin_cycle_mean.py builds every LAT row,
    (n+1)*4^n work, and there the ratio was still above 1 (1.08);
  * the differential axis stopped at n = 17, because the automaton builder enumerates
    EVERY out-edge -- n = 19 passed 4.6 GB without finishing -- so whether the falling
    ratio SETTLES was not measured.

Both close the same way, and this file is that one idea.  The minimum mean cycle is
decided by cheap edges; an edge of weight 12 bits does not sit on a cycle of mean 1.
So build only the edges below a per-node threshold W_u, solve that subgraph, and then
PROVE the omitted edges irrelevant rather than hoping:

  CERTIFICATE.  Let G' keep every edge of weight <= W_u out of each node u, with every
  node keeping at least one.  Its minimum mean cycle mu' is >= mu(G).  Let p be the
  shortest-path potential of the reduced weights w - mu' from a zero-weight virtual
  source (well defined: G' has no negative cycle), so p <= 0 and
  p(v) <= p(u) + w(u,v) - mu' on G'.  An omitted edge has w(u,v) > W_u, so if
  W_u >= mu' - p(u) then p(u) + w - mu' > 0 >= p(v): p is a feasible potential on ALL
  of G, every cycle of G has mean >= mu', and mu(G) = mu'.  Where a node fails the
  test its threshold is raised to mu' - p(u) and the subgraph re-solved; the loop ends
  only when every node passes, so a returned value is EXACT, not an estimate.

  PRUNING IS SOUND because the weight of a partial edge only grows.  Linear: the
  correlation of x -> x + d is a product of 2x2 carry matrices whose columns have l1
  norm <= 1, so the l1 norm of the partial vector bounds |C| from above.  Differential:
  the carry-pair automaton has two choices of x per step, so the partial path count
  can at most double per remaining bit.  A branch whose bound already exceeds W_u is
  cut, so a row costs (edges kept x n), not 2^n.

Measured: the pruned graph keeps ~3-25 edges per node where the full linear graph has
~2^n / 3, and the exact answer takes about two minutes per key per axis at n = 17 and
under an hour at n = 20.

  §1  THE CERTIFICATE, CHECKED.  Against the exhaustive builders on both axes, and a
      NEGATIVE CONTROL: with the raising loop switched off, a fixed small W gives a
      WRONG mu on some key, and the certificate test flags exactly those keys.

  §2  THE DIFFERENTIAL LADDER, CONTINUED -- AND IT DOES NOT SETTLE.  v9.5.24 read the
      median exact/annealed ratio as slowing near 0.93 (6 keys at n = 17).  At 8 keys
      it is 0.90 at n = 17, and the certificate takes it on to 0.81 at n = 19 and 0.75 at
      n = 20 (--full).  What IS flat is the exact value itself: median mu/n stays at
      0.14-0.16 from n = 13 to 20, while the model's lambda*/n climbs from 0.14 to 0.2.
      Within one width, exact mu rises only ~0.6 per unit of lambda*: the keys the model
      rates strongest are the ones it over-states most.

  §3  THE LINEAR AXIS, PAST n = 11.  It crosses too, between n = 13 and 14, and then
      falls the same way about half as fast: 1.02 at n = 13, 0.98 at 14 and 16, 0.93 at
      17, 0.87 at 19, 0.82 at 20.  Exact mu/n stays at 0.07-0.08 throughout.

  §4  WHAT THIS CHANGES.  The model's slope is what is wrong, so no constant-factor
      correction to §11.38's figures is available; the exact slope, flat for eight
      widths, is the quantity left to argue about.  [v9.5.26: the flat exact slope
      is WITHDRAWN by exact_slope_ladder.py.  It rested partly on a run-heavy n = 20
      sample; at a typical run count the differential per-bit median is ~0.13 at
      n = 19-23, down from ~0.15 at 13-14, so the ~36 / ~18 / 27x reading in §4 below
      is withdrawn too.  What survives is that exact mu grows at every width step.
      SecurityProofs-9.md §11.42.]

Every key is drawn from a FIXED seed (quenched_exact_ladder.keys), so the verdict is a
deterministic computation and cannot flake: no fresh sample is drawn.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/certified_cycle_ladder.py [--quick] [--full]
      --quick : n <= 14 at 12 keys, both axes             (~6 min on an aarch64 SBC)
      default : adds n = 16 at 12 keys and n = 17 at 8    (~50 min)
      --full  : adds n = 19 at 6 and n = 20 at 4 keys     (~6 h; ~1 GB per n = 20 key)
"""

import argparse
import importlib.util
import math
import os
import sys
from array import array
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
TOL = 1e-9


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


QEL = _load("quenched_exact_ladder.py")   # keys(), full differential builder, Howard
AML = QEL.AML                             # carry-pair automaton, lam_diff, lam_lin
LCM = QEL.LCM                             # exhaustive linear graph
FK = QEL.FK
keys, howard_csr, med = QEL.keys, QEL.howard_csr, QEL.med


# ═══════════════════════════════════════════════════════════════════════════
# Pruned rows
# ═══════════════════════════════════════════════════════════════════════════
def _lin_mats():
    """V'[c'] = 1/2 sum_c sum_x [maj(x, d_i, c) = c'] (-1)^(u_i(x^d_i^c) ^ w_i x) V[c]."""
    T = {}
    for di in (0, 1):
        for ui in (0, 1):
            for wi in (0, 1):
                A = [[0.0, 0.0], [0.0, 0.0]]
                for c in (0, 1):
                    for x in (0, 1):
                        cp = (x & di) | (x & c) | (di & c)
                        s = -1 if (ui & (x ^ di ^ c)) ^ (wi & x) else 1
                        A[cp][c] += 0.5 * s
                T[(di, ui, wi)] = (A[0][0], A[0][1], A[1][0], A[1][1])
    return T


LIN_T = _lin_mats()
DIFF_T = {k: (v[0][0], v[0][1], v[1][0], v[1][1]) for k, v in AML.NT.items()}


def lin_row(n, d, u, W, Ma):
    """Out-edges u -> M(w) of the v2 mask graph with -log2|C(u <- w)| <= W.

    Same graph as lin_cycle_mean.build_v2(); the l1 norm of the partial carry
    vector is an upper bound on the final |C|, so a branch below 2^-W is cut."""
    thr = 2.0 ** -W - 1e-15
    tb = [(LIN_T[((d >> i) & 1, (u >> i) & 1, 0)],
           LIN_T[((d >> i) & 1, (u >> i) & 1, 1)]) for i in range(n)]
    bs, ws = array('i'), array('d')
    stack = [(0, 1.0, 0.0, 0)]
    while stack:
        i, v0, v1, w = stack.pop()
        if i == n:
            c = abs(v0 + v1)
            if w and c >= thr:
                bs.append(Ma[w])
                ws.append(-math.log2(c))
            continue
        for wi in (0, 1):
            m00, m01, m10, m11 = tb[i][wi]
            a0 = m00 * v0 + m01 * v1
            a1 = m10 * v0 + m11 * v1
            if abs(a0) + abs(a1) >= thr:
                stack.append((i + 1, a0, a1, w | (wi << i)))
    return bs, ws


def diff_row(n, d, a, W, Ma):
    """Out-edges of the v2 difference graph with weight <= W (QEL.build_csr's row,
    pruned): at depth i the partial count can at most double per remaining bit, so a
    branch with count < 2^(i - W) cannot reach weight <= W."""
    al = Ma[a]
    top = n - 1
    tb = [[[DIFF_T[((d >> i) & 1, (al >> i) & 1, c, e)] for e in (0, 1)]
           for c in (0, 1)] for i in range(n)]
    bs, ws = array('i'), array('d')
    stack = [(0, 0, 1, 0, 0)]
    while stack:
        i, cls, v0, v1, e = stack.pop()
        if i == top:
            w = top - math.log2(v0 + v1)
            if w <= W + 1e-12:
                bs.append(al ^ e)
                ws.append(w)
            continue
        row = tb[i][cls]
        lim = 2.0 ** (i + 1 - W) - 1e-9
        for ec in (0, 1):
            m00, m01, m10, m11 = row[ec]
            w0 = m00 * v0 + m01 * v1
            w1 = m10 * v0 + m11 * v1
            if w0 + w1 >= lim:
                stack.append((i + 1, ec, w0, w1, e | (ec << (i + 1))))
    return bs, ws


# ═══════════════════════════════════════════════════════════════════════════
# The certified solver
# ═══════════════════════════════════════════════════════════════════════════
POT_SHIFT = 1e-9


def potentials(BS, WS, m):
    """Shortest paths of w - (m - POT_SHIFT) from a zero-weight virtual source (SPFA).

    The shift, and the relaxation budget, are certified_cycle_mean.c's: Howard's m is
    a cycle's sum / length and SPFA re-adds w - m edge by edge, and where the two
    roundings disagree the optimal cycle is a negative cycle to SPFA, which then never
    terminates (TODO #257, eleventh pass: n = 17, delta = 0x1f6ef).  The certificate
    then gives mu(G) >= m - POT_SHIFT - TOL."""
    N = len(BS)
    m -= POT_SHIFT
    budget = 64 * (sum(map(len, BS)) + N)
    relax = 0
    p = array('d', [0.0]) * N
    inq = bytearray(N)
    dq = deque(range(1, N))
    for v in dq:
        inq[v] = 1
    while dq:
        u = dq.popleft()
        inq[u] = 0
        pu = p[u]
        bs, ws = BS[u], WS[u]
        for j in range(len(bs)):
            v = bs[j]
            nv = pu + ws[j] - m
            if nv < p[v] - 1e-12:
                p[v] = nv
                relax += 1
                if relax > budget:
                    raise RuntimeError("SPFA over budget: negative cycle below m")
                if not inq[v]:
                    inq[v] = 1
                    dq.append(v)
    return p


def certified_mu(n, d, rowf, W0, raise_=True):
    """Exact mu of the full graph from pruned rows plus the certificate.

    Returns (mu, edges kept, rounds, nodes that failed the certificate on the last
    round solved).  With raise_=False it solves ONE round at W0 and reports the
    failing nodes instead of fixing them -- §1's negative control."""
    N = 1 << n
    Ma = FK.m_tab(n)
    Wn = [W0] * N
    BS, WS = [array('i')] * N, [array('d')] * N
    todo = range(1, N)
    rounds = 0
    while True:
        rounds += 1
        for u in todo:
            while True:
                b, w = rowf(n, d, u, Wn[u], Ma)
                if len(b):
                    break
                Wn[u] += 1.0
            BS[u], WS[u] = b, w
        m = howard_csr(BS, WS)
        p = potentials(BS, WS, m)
        todo = [u for u in range(1, N) if Wn[u] < m - p[u] - TOL]
        if not todo or not raise_:
            return m, sum(map(len, BS)), rounds, len(todo)
        for u in todo:
            Wn[u] = m - p[u] + 0.5


def mu_lin(n, d):
    return certified_mu(n, d, lin_row, 2.0)


def mu_diff(n, d):
    return certified_mu(n, d, diff_row, 3.0)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the certificate, checked
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The certificate, against the exhaustive builders")
    print("""Pruned rows plus the potential test must return the SAME number the full
graph does -- lin_cycle_mean.build_v2 (every LAT row) and quenched_exact_ladder.build_csr
(every out-edge) -- on every key, not merely a close one.
""")
    worst, rows = 0.0, []
    for n in (7, 8, 10, 11):
        for d in keys(n, 3):
            ml, el, _, _ = mu_lin(n, d)
            full = LCM.build_v2(n, d)
            rl = LCM.mu(full)
            md, ed, _, _ = mu_diff(n, d)
            rd = howard_csr(*QEL.build_csr(n, d))
            worst = max(worst, abs(ml - rl), abs(md - rd))
            rows.append((n, d, el, sum(map(len, full))))
    for n in (13, 14):
        d = keys(n, 1)[0]
        md, _, _, _ = mu_diff(n, d)
        rd = howard_csr(*QEL.build_csr(n, d))
        worst = max(worst, abs(md - rd))
        print("  n = %d  d = %#x  differential: certified %.9f   full graph %.9f"
              % (n, d, md, rd))
    check(worst < 1e-9,
          "certified mu equals the full-graph mu on both axes at n = 7, 8, 10, 11 "
          "(3 keys each) and on the differential axis at n = 13, 14 (max |diff| %.1e)"
          % worst)
    frac = max(k / f for nn, _, k, f in rows if nn == 11)
    check(frac < 0.10,
          "at n = 11 the linear subgraph keeps at most %.1f%% of the full graph's "
          "edges -- the saving is what reaches n = 20" % (100 * frac))

    print("""
NEGATIVE CONTROL.  The raising loop is what makes the answer exact.  Switch it off and
solve once at a fixed W = 1 bit: a pruned graph can only lose cycles, so it can only
OVER-state mu, and it must do so exactly where the certificate test fails.""")
    wrong = flagged = agree = 0
    for n in (8, 10, 11):
        for d in keys(n, 6):
            m1, _, _, bad = certified_mu(n, d, lin_row, 1.0, raise_=False)
            m, _, _, _ = mu_lin(n, d)
            w = m1 > m + 1e-9
            wrong += w
            flagged += bad > 0
            agree += (not w) or bad > 0
            if m1 < m - 1e-9:
                agree -= 1000          # a pruned graph UNDER-stating mu is impossible
    print("  18 keys at W = 1, no raising: %d wrong, %d flagged by the test" % (wrong, flagged))
    check(wrong > 0 and agree == 18,
          "the control FIRES: %d of 18 keys get a wrong (too large) mu without the "
          "loop, and the certificate test flags every one of them" % wrong)


# ═══════════════════════════════════════════════════════════════════════════
# the ladders
# ═══════════════════════════════════════════════════════════════════════════
def widths(quick, full):
    w = [(7, 12), (8, 12), (10, 12), (11, 12), (13, 12), (14, 12)]
    if not quick:
        w += [(16, 12), (17, 8)]
        if full:
            w += [(19, 6), (20, 4)]
    return w


def ladder(ws, solve, model):
    print("  %3s %4s %8s %7s %8s %7s   %6s %6s %6s   %5s   %s"
          % ("n", "keys", "med mu", "mu/n", "med ann", "ann/n", "r min", "r med",
             "r max", "r<1", "edges/node"))
    rows = {}
    for n, cnt in ws:
        recs = []
        for d in keys(n, cnt):
            m, e, _, _ = solve(n, d)
            lo, _, _ = model(n, d)
            recs.append((d, m, lo, e))
        rows[n] = recs
        r = [m / a for _, m, a, _ in recs]
        print("  %3d %4d %8.4f %7.4f %8.4f %7.4f   %6.3f %6.3f %6.3f   %5.2f   %6.1f"
              % (n, len(recs), med([m for _, m, _, _ in recs]),
                 med([m for _, m, _, _ in recs]) / n, med([a for _, _, a, _ in recs]),
                 med([a for _, _, a, _ in recs]) / n,
                 min(r), med(r), max(r), sum(x < 1 for x in r) / len(r),
                 med([e for *_, e in recs]) / (1 << n)), flush=True)
    return rows


def mr(rows, n):
    return med([m / a for _, m, a, _ in rows[n]])


def mun(rows, n):
    return med([m for _, m, _, _ in rows[n]]) / n


def slope(recs):
    """Least-squares slope of exact mu on the model's lambda* across one width's keys."""
    xs = [a for _, _, a, _ in recs]
    ys = [m for _, m, _, _ in recs]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    return (sum((x - mx) * (y - my) for x, y in zip(xs, ys))
            / sum((x - mx) ** 2 for x in xs))


def common_checks(rows, axis, band):
    ns = sorted(rows)
    hi = [n for n in ns if n >= 14]
    lo, up = band
    check(all(lo <= mun(rows, n) <= up for n in ns if n >= 13),
          "%s: the EXACT median mu/n stays in [%.2f, %.2f] at every width from n = 13 "
          "on (" % (axis, lo, up) + ", ".join("%d: %.3f" % (n, mun(rows, n))
                                            for n in ns if n >= 13) + ")")
    if 17 in rows:
        check(mr(rows, 17) < mr(rows, 14) - 0.02,
              "%s: the median ratio is still FALLING past n = 14 (%s)"
              % (axis, ", ".join("%d: %.3f" % (n, mr(rows, n)) for n in hi)))
        s = slope(rows[17])
        check(s < 0.8,
              "%s: within n = 17, exact mu rises only %.2f per unit of the model's "
              "lambda* -- the keys the model rates strongest are the ones it "
              "over-states most" % (axis, s))
    else:
        print("  %s: n = 17 not run (--quick): the continued fall and the within-width "
              "slope are not scored" % axis)
    for n in (19, 20):
        if n in rows:
            print("  %s: n = %d median ratio %.3f, mu/n %.3f over %d keys (--full)"
                  % (axis, n, mr(rows, n), mun(rows, n), len(rows[n])))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the differential ladder, continued
# ═══════════════════════════════════════════════════════════════════════════
def section_2(quick, full):
    rule("§2  The differential ladder, continued: the ratio does not settle")
    print("""Same keys as quenched_exact_ladder.py §2, so n <= 17 reproduces its table
(n = 17 at 8 keys here against 6 there); the certificate is what reaches past it.
""")
    rows = ladder(widths(quick, full), mu_diff, AML.lam_diff)
    ns = sorted(rows)
    check(all(mr(rows, n) < 1.0 for n in ns if n >= 13),
          "differential: the median ratio is below 1 at EVERY width from n = 13 on")
    common_checks(rows, "differential", (0.13, 0.17))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
# §3  the linear axis, past n = 11
# ═══════════════════════════════════════════════════════════════════════════
def section_3(quick, full, drows):
    rule("§3  The linear axis, past n = 11: it crosses too")
    print("""Against the lower end of §11.38.4's even-moment bracket (lam_lin), as
quenched_exact_ladder.py §4 did to n = 11.
""")
    rows = ladder(widths(quick, full), mu_lin, AML.lam_lin)
    ns = sorted(rows)
    check(all(mr(rows, n) > 1.0 for n in ns if n <= 11),
          "linear: at n <= 11 the median ratio is above 1, as v9.5.24 recorded")
    check(all(mr(rows, n) < 1.0 for n in ns if n >= 14),
          "linear: from n = 14 on it is BELOW 1 (" + ", ".join(
              "%d: %.3f" % (n, mr(rows, n)) for n in ns if n >= 14)
          + ") -- the linear axis crosses, between n = 13 and 14")
    deep = [n for n in ns if n >= 14]
    check(all(mr(rows, n) > mr(drows, n) for n in deep),
          "linear: the crossing is SHALLOWER than the differential one at every width "
          "from n = 14 (" + ", ".join("%d: %.3f vs %.3f" % (n, mr(rows, n), mr(drows, n))
                                      for n in deep) + ")")
    common_checks(rows, "linear", (0.06, 0.09))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
# §4  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_4(drows, lrows):
    rule("§4  What this changes for #257")
    print("  exact medians this run:")
    for n in sorted(drows):
        print("    n = %2d   differential %.3f (mu/n %.3f)   linear %.3f (mu/n %.3f)"
              % (n, med([m for _, m, _, _ in drows[n]]), mun(drows, n),
                 med([m for _, m, _, _ in lrows[n]]), mun(lrows, n)))
    print("""
NOT SETTLED.  v9.5.24 read the differential ratio as slowing near 0.93.  With eight
keys at n = 17 and the certificate reaching n = 19 and 20 it is not slowing: 0.90 at
n = 17, 0.81 at n = 19, 0.75 at n = 20.  The model over-states mu by an amount that
GROWS with width, so no constant-factor correction to §11.38's 48.44 is available.

EXTENDED.  The linear axis crosses too, between n = 13 and 14, and falls the same way
about half as fast: 0.98 at n = 14 and 16, 0.93 at 17, 0.87 at 19, 0.82 at 20.  §11.38's
22.40 is an over-statement on the same footing.

WHAT HOLDS INSTEAD.  The exact values.  Their median mu/n has stayed in a narrow band
from n = 13 to 20 -- 0.14-0.16 differential, 0.07-0.08 linear -- while the model's
lambda*/n climbs from 0.14 to about 0.2.  The exact minimum mean cycle is still growing
linearly in n; what the model gets wrong is the SLOPE, and it gets it most wrong for
the keys it rates strongest.  Read as a slope, the exact band puts n = 256 near
0.14 x 256 = 36 differential and 0.07 x 256 = 18 linear, about 27x the 4/3 and 2/3
criteria.  That is a READING of eight widths, not a bound.  It is the reading the
evidence now supports, and it replaces §11.38's model-based 36x and 34x.
[v9.5.26: WITHDRAWN -- the flatness rested partly on a run-heavy sample at n = 20; at a
typical run count the per-bit median is ~0.13 at n = 19-23, and forms that fit
n = 13..23 read anywhere from ~10x to ~26x at n = 256.  exact_slope_ladder.py,
SecurityProofs-9.md §11.42.]

OWED.  A quenched argument for n = 256.  This pass moves its target: the quantity to
control is the exact slope, flat at 0.14-0.16 over eight widths, not the annealed
model's error, which is not converging.

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    section_1()
    drows = section_2(a.quick, a.full)
    lrows = section_3(a.quick, a.full, drows)
    section_4(drows, lrows)
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
