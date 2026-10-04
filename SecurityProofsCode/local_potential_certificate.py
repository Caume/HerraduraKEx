#!/usr/bin/env python3
"""local_potential_certificate.py — TODO #257 (sixth pass): a rigorous route, built
and measured, and why it does not reach n = 256.

#257 owes MONOTONICITY: that exact mu, the minimum mean cycle of the NL-FSCX v2
difference graph, never decreases between the widest measured width and n = 256.
§11.37 closed every route that compares two graphs (there is no embedding between
widths) and one route that GUESSES a potential (Howard's bias correlates with no
natural node statistic).  This pass tries the route those two leave open: do not
guess the potential, OPTIMISE it, but only over potentials a bit-position DP can
evaluate at any width.

  THE CERTIFICATE.  For ANY function phi on differences, every cycle of the graph
  has mean >= min over edges a -> b of  w(a, b) + phi(a) - phi(b),  because phi
  telescopes around a cycle.  If phi is LOCAL -- a sum over bit positions s of
  G_s(window of w bits at s) -- that minimum is a shortest path along the bit
  positions, the same carry-pair automaton §11.38.1 built, plus the window bits of
  a and b in the state.  So it is evaluable at n = 256 in time linear in n.  With
  w = n the potential is unrestricted and the bound IS mu (LP duality for the
  minimum mean cycle), so the window size is the one parameter.

  THE RELAXATION THAT MAKES IT SCALE.  The weight is -log2 of a path COUNT, a sum
  over carry sequences, which is not additive.  Keeping the carry SLOT in the DP
  state and taking a componentwise max over predecessors is sound (it only
  over-counts) and stays close; dropping the slot is not usable -- §1(c).

  §1  SOUNDNESS.  (a) With w = n the optimised bound equals mu exactly, every key.
      (b) The slot-keeping DP never exceeds the true minimum reduced edge cost, for
      the optimal G and for random ones.  (c) NEGATIVE CONTROL: dropping the carry
      slot gives a relaxed graph whose mu is 0 for every key, so the slot is what
      carries the bound.

  §2  THE WINDOW LADDER.  The optimal local bound rises with w and first reaches
      mu at w* = n-1 (median, n = 7), n-2 (n = 8), n-3 (n = 10): the window the
      certificate needs GROWS with the width, at about 0.7n.

  §3  AT A FIXED WINDOW IT DOES NOT GROW.  With w = 5 the bound captures a FALLING
      share of mu -- median 0.94 at n = 8, 0.87 at 10, 0.81 at 11, 0.71 at 13, 0.70
      at 14 -- and its absolute median is LOWER at n = 13-14 (1.27, 1.32) than at
      n = 10-11 (1.43, 1.50) while exact mu is not (1.79, 1.87 against 1.63, 1.83).
      n = 16 at w = 4 sits at ~1.0-1.4 on three keys (recorded run, not gated).

  §4  WHY.  The LP dual of the bound is a distribution over edges whose LOCAL window
      statistics balance, not a cycle.  Its mass sits on light differences (mean
      popcount ~0.4n at n = 8, falling with n) where the optimal cycles are dense
      (0.6-0.86n, §11.37): the dual can stitch cheap sparse edges together because
      it never sees the support grow beyond w bits, and M grows it every round.
      More width means more cheap places to stitch, so the bound is set by the
      cheapest LOCAL neighbourhoods of delta while mu is a global quantity.

  §5  WHAT THIS CHANGES.  Prose.

Every key is drawn from the FIXED stream (quenched_exact_ladder.keys) and the LP
solver is deterministic, so the verdict cannot flake.  The LP needs highspy (the
HiGHS solver): it IS the gate, so it is a FAILURE when absent, not a skip
(CLAUDE.md's dependency rule, the z3-solver precedent).

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/local_potential_certificate.py [--quick]
      --quick : n <= 11                                    (~7 min on an aarch64 SBC)
      default : adds n = 13 and 14 at w = 5, six keys each, by constraint
                generation                                 (~45 min)
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
    import highspy
    import numpy as np
except ImportError:
    print("This gate needs the HiGHS LP solver and numpy:")
    print("    pip install highspy numpy")
    print("They ARE the gate here (every bound in §1-§4 is an LP optimum), so a")
    print("missing solver is a failure, not a skip.")
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


CCL = _load("certified_cycle_ladder.py")   # pruned rows (diff_row)
QEL = CCL.QEL                             # keys(), build_csr, howard_csr
FK, NT = QEL.FK, QEL.AML.NT
keys, med = QEL.keys, statistics.median


# ═══════════════════════════════════════════════════════════════════════════
# The local-potential LP
# ═══════════════════════════════════════════════════════════════════════════
def windows(n, w):
    """WIN[x, s] = the w-bit window of x starting at bit s (cyclic)."""
    N = 1 << n
    x = np.arange(N, dtype=np.int64)
    WIN = np.zeros((N, n), dtype=np.int64)
    for s in range(n):
        v = np.zeros(N, dtype=np.int64)
        for k in range(w):
            v |= ((x >> ((s + k) % n)) & 1) << k
        WIN[:, s] = v
    return WIN


class LocalLP:
    """max t  s.t.  w(a,b) + phi(a) - phi(b) >= t  for every edge added,
    phi(x) = sum_s G[s][window_s(x)].  wrap=False keeps only windows s <= n-w,
    which is the form the bit-position DP evaluates."""

    def __init__(self, n, w, wrap=True):
        self.n, self.w, self.P = n, w, 1 << w
        self.WIN = windows(n, w)
        P = self.P
        self.h = h = highspy.Highs()
        h.setOptionValue("output_flag", False)
        inf = highspy.kHighsInf
        nv = 1 + n * P
        lo = np.full(nv, -inf)
        hi = np.full(nv, inf)
        lo[0], hi[0] = -1e3, 1e3
        for s in range(n):                      # gauge: G_s(0) = 0
            lo[1 + s * P] = hi[1 + s * P] = 0.0
            if not wrap and s > n - w:
                lo[1 + s * P:1 + (s + 1) * P] = 0.0
                hi[1 + s * P:1 + (s + 1) * P] = 0.0
        h.addVars(nv, lo, hi)
        c = np.zeros(nv)
        c[0] = -1.0
        h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
        self.edges = []
        self.seen = set()

    def add(self, edges):
        P, WIN = self.P, self.WIN
        starts, idx, val, up = [], [], [], []
        for a, b, wt in edges:
            if (a, b) in self.seen:
                continue
            self.seen.add((a, b))
            self.edges.append((a, b, wt))
            pa, pb = WIN[a], WIN[b]
            coef = {0: 1.0}
            for s in np.nonzero(pa != pb)[0]:
                if pa[s]:
                    k = int(1 + s * P + pa[s])
                    coef[k] = coef.get(k, 0.0) - 1.0
                if pb[s]:
                    k = int(1 + s * P + pb[s])
                    coef[k] = coef.get(k, 0.0) + 1.0
            starts.append(len(idx))
            for k, v in coef.items():
                if v:
                    idx.append(k)
                    val.append(v)
            up.append(wt)
        if starts:
            m = len(starts)
            self.h.addRows(m, np.full(m, -highspy.kHighsInf), np.array(up),
                           len(idx), np.array(starts, dtype=np.int32),
                           np.array(idx, dtype=np.int32), np.array(val))

    def solve(self):
        self.h.run()
        sol = np.array(self.h.getSolution().col_value)
        self.G = sol[1:].reshape(self.n, self.P)
        return float(sol[0])

    def phi(self):
        return self.G[np.arange(self.n)[None, :], self.WIN].sum(axis=1)

    def duals(self):
        return np.abs(np.array(self.h.getSolution().row_dual))


def all_edges(BS, WS):
    return [(a, b, wt) for a in range(1, len(BS)) for b, wt in zip(BS[a], WS[a])]


def local_bound(n, w, E, wrap=True):
    lp = LocalLP(n, w, wrap)
    lp.add(E)
    return lp.solve(), lp


def local_bound_cg(n, d, w):
    """The same LP without enumerating every edge (n = 13, 14): start from the cheap
    rows, then add every edge the current phi violates, until none does.  The
    separation is complete because phi(b) <= max phi, so only edges of weight
    <= t - phi(a) + max phi can be violated, and diff_row enumerates exactly those."""
    Ma = FK.m_tab(n)
    lp = LocalLP(n, w)
    init = []
    for a in range(1, 1 << n):
        W0 = 3.0
        while True:
            bs, ws = CCL.diff_row(n, d, a, W0, Ma)
            if len(bs):
                break
            W0 += 1.0
        init += [(a, b, x) for b, x in zip(bs, ws)]
    lp.add(init)
    while True:
        t = lp.solve()
        ph = lp.phi()
        pmax = float(ph[1:].max())
        new = []
        for a in range(1, 1 << n):
            Wa = t - ph[a] + pmax + 1e-9
            if Wa < 0:
                continue
            bs, ws = CCL.diff_row(n, d, a, Wa, Ma)
            for b, x in zip(bs, ws):
                if x + ph[a] - ph[b] < t - 1e-7 and (a, b) not in lp.seen:
                    new.append((a, b, x))
        if not new:
            return t
        lp.add(new)


# ═══════════════════════════════════════════════════════════════════════════
# The bit-position DP (what would run at n = 256)
# ═══════════════════════════════════════════════════════════════════════════
def dp_bound(n, d, w, G):
    """SOUND lower bound on  min over edges a != 0 of w(a,b) + phi(a) - phi(b),
    phi = sum_{s <= n-w} G[s][a_s..a_{s+w-1}] (non-wrapping), in O(n 4^w) time.

    State before bit k: a_{k-w+1..k} (w bits), b_{k-w+1..k-1}, e_k = the carry-class
    bit (beta xor M(alpha) at k), a nonzero flag, and the 2-vector over the carry
    SLOT.  The boundary bits a_{n-1}, a_0 are fixed per outer copy (M is cyclic).
    Merging two states keeps the componentwise MAX of their vectors, which can only
    over-count the path count, so the returned weight can only be too LOW."""
    best = 0.0
    bm = (1 << (w - 1)) - 1
    for A0 in (0, 1):
        for Z in (0, 1):
            cur = {((A0 << (w - 2)) | (Z << (w - 1)), 0, 0, A0 | Z): (1.0, 0.0)}
            for k in range(n):
                nxt = {}
                s0 = k - w + 1
                gk = G[s0] if 0 <= s0 <= n - w else None
                dk = (d >> k) & 1
                for (aw, bw, ek, nz), (v0, v1) in cur.items():
                    gm = ((aw >> (w - 2)) ^ (aw >> (w - 1))) & 1
                    anl = (A0,) if k == n - 2 else (Z,) if k == n - 1 else (0, 1)
                    for anx in anl:
                        g = gm ^ anx
                        bk = g ^ ek
                        sc = 1.0 if gk is None else \
                            2.0 ** (gk[bw | (bk << (w - 1))] - gk[aw])
                        naw = (aw >> 1) | (anx << (w - 1))
                        nbw = ((bw >> 1) | (bk << (w - 2))) & bm
                        nnz = nz | anx
                        if k <= n - 2:
                            for enx in (0, 1):
                                M = NT[(dk, g, ek, enx)]
                                a0 = (M[0][0] * v0 + M[0][1] * v1) * sc
                                a1 = (M[1][0] * v0 + M[1][1] * v1) * sc
                                if a0 == 0 and a1 == 0:
                                    continue
                                key = (naw, nbw, enx, nnz)
                                o = nxt.get(key)
                                nxt[key] = (a0, a1) if o is None else \
                                    (max(o[0], a0), max(o[1], a1))
                        else:
                            key = (naw, nbw, 0, nnz)
                            o = nxt.get(key)
                            a0, a1 = v0 * sc, v1 * sc
                            nxt[key] = (a0, a1) if o is None else \
                                (max(o[0], a0), max(o[1], a1))
                cur = nxt
            for (aw, bw, ek, nz), (v0, v1) in cur.items():
                if nz:
                    best = max(best, v0 + v1)
    return (n - 1) - math.log2(best)


def min_reduced(n, w, E, G):
    """The exact quantity dp_bound lower-bounds, by scanning every edge."""
    WIN = windows(n, w)
    ph = np.asarray(G)[np.arange(n)[None, :], WIN].sum(axis=1)
    return min(x + ph[a] - ph[b] for a, b, x in E)


def slotless_mu(n, d):
    """mu of the graph whose edge weights drop the carry slot: each bit costs
    1 - log2(max column sum of its transfer matrix).  Every true edge is present
    and no lighter, so this is a valid but useless lower bound -- §1(c)."""
    from array import array
    Ma = FK.m_tab(n)
    BS, WS = [array('i')], [array('d')]
    cost = {}
    for k, M in NT.items():
        r = max(M[0][0] + M[1][0], M[0][1] + M[1][1])
        cost[k] = None if r == 0 else 1.0 - math.log2(r)
    for a in range(1, 1 << n):
        al = Ma[a]
        bs, ws = array('i'), array('d')
        stack = [(0, 0, 0.0, 0)]
        while stack:
            i, cls, x, e = stack.pop()
            if i == n - 1:
                bs.append(al ^ e)
                ws.append(x)
                continue
            for ec in (0, 1):
                c = cost[((d >> i) & 1, (al >> i) & 1, cls, ec)]
                if c is not None:
                    stack.append((i + 1, ec, x + c, e | (ec << (i + 1))))
        BS.append(bs)
        WS.append(ws)
    return QEL.howard_csr(BS, WS)


GRAPHS = {}


def graph(n, d):
    if (n, d) not in GRAPHS:
        BS, WS = QEL.build_csr(n, d)
        GRAPHS[(n, d)] = (QEL.howard_csr(BS, WS), all_edges(BS, WS))
    return GRAPHS[(n, d)]


# ═══════════════════════════════════════════════════════════════════════════
# §1  soundness
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The certificate is sound, exact at full width, and needs the slot")
    worst = 0.0
    for n in (7, 8):
        for d in keys(n, 4):
            mu, E = graph(n, d)
            t, _ = local_bound(n, n, E)
            worst = max(worst, abs(t - mu))
    check(worst < 1e-6,
          "(a) with the window as wide as the word the optimised bound IS mu "
          "(max |diff| %.1e, n = 7, 8, four keys each) -- LP duality for the "
          "minimum mean cycle, and a check on the LP itself" % worst)
    rnd = random.Random(257)
    viol, gap = 0, []
    for n, w in ((7, 3), (8, 4), (10, 4)):
        for d in keys(n, 3):
            mu, E = graph(n, d)
            t, lp = local_bound(n, w, E, wrap=False)
            Gs = [lp.G.tolist()] + [[[0.0] + [rnd.uniform(-2, 2) for _ in range(
                (1 << w) - 1)] if s <= n - w else [0.0] * (1 << w)
                for s in range(n)] for _ in range(3)]
            for i, G in enumerate(Gs):
                db, ex = dp_bound(n, d, w, G), min_reduced(n, w, E, G)
                if db > ex + 1e-9:
                    viol += 1
                if i == 0:
                    gap.append(db / ex if ex > 0 else 1.0)
    check(viol == 0,
          "(b) the slot-keeping DP never exceeds the exact minimum reduced edge "
          "cost: 0 violations in 36 (key, G) pairs at n = 7, 8, 10, optimal and "
          "random G (got %d); at the optimal G it recovers a median %.2f of it"
          % (viol, med(gap)))
    zs = []
    for n in (7, 8, 10):
        for d in keys(n, 4):
            zs.append((slotless_mu(n, d), graph(n, d)[0]))
    check(all(z < 1e-9 for z, _ in zs) and all(m > 0.3 for _, m in zs),
          "(c) NEGATIVE CONTROL: dropping the carry slot (each bit costs its best "
          "slot's column sum) gives mu = 0 on all 12 keys whose true mu is %.2f-%.2f"
          " -- the bound lives in the slot, which is why the DP keeps it"
          % (min(m for _, m in zs), max(m for _, m in zs)))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the window ladder
# ═══════════════════════════════════════════════════════════════════════════
def section_2(quick):
    rule("§2  How wide the window must be for the bound to reach mu")
    print("""w* = the smallest window at which the optimised local bound equals mu (to 1e-6).
A local certificate is one whose w* does not grow with n.
""")
    ws_by_n, mono = {}, True
    for n, cnt in ((7, 12), (8, 12), (10, 8 if quick else 12)):
        ws = []
        for d in keys(n, cnt):
            mu, E = graph(n, d)
            prev, wstar, row = -1.0, None, []
            for w in range(3, n + 1):
                t, _ = local_bound(n, w, E)
                row.append(t)
                mono = mono and t >= prev - 1e-7
                prev = t
                if t > mu - 1e-6:
                    wstar = w
                    break
            ws.append(wstar)
        ws_by_n[n] = ws
        print("  n = %2d  w* per key: %s   median %s" % (
            n, " ".join(map(str, ws)), med(ws)))
    check(mono, "the bound never falls as the window widens (a w-window potential "
                "is a (w+1)-window one)")
    m = [med(ws_by_n[n]) for n in (7, 8, 10)]
    check(m[0] < m[2] and all(x <= y for x, y in zip(m, m[1:])) and
          min(mm / n for mm, n in zip(m, (7, 8, 10))) >= 0.6,
          "w* GROWS with the width: median %s, %s, %s at n = 7, 8, 10 (>= 0.6n) -- "
          "the certificate that reaches mu has to see most of the word" % tuple(m))


# ═══════════════════════════════════════════════════════════════════════════
# §3  a fixed window
# ═══════════════════════════════════════════════════════════════════════════
def section_3(quick):
    rule("§3  At a fixed window the bound does not grow with n")
    W = 5
    rows = {}
    for n, cnt in ((8, 12), (10, 12), (11, 8 if quick else 12)):
        rs = []
        for d in keys(n, cnt):
            mu, E = graph(n, d)
            t, _ = local_bound(n, W, E)
            rs.append((t, mu))
        rows[n] = rs
    if not quick:
        for n in (13, 14):
            rs = []
            for d in keys(n, 6):
                mu = CCL.mu_diff(n, d)[0]
                rs.append((local_bound_cg(n, d, W), mu))
            rows[n] = rs
    print("  n   keys  median bound(w=5)  median mu   median bound/mu")
    S = {}
    for n in sorted(rows):
        rs = rows[n]
        S[n] = (med(t for t, _ in rs), med(m for _, m in rs),
                med(t / m for t, m in rs))
        print("  %2d  %4d   %8.3f          %7.3f      %6.3f" % ((n, len(rs)) + S[n]))
    ns = sorted(S)
    fr = [S[n][2] for n in ns]
    check(all(x > y for x, y in zip(fr, fr[1:])),
          "the share of mu a 5-bit window certifies FALLS at every width step "
          "(%s)" % ", ".join("%d: %.2f" % (n, f) for n, f in zip(ns, fr)))
    if quick:
        print("  n = 13, 14 not run (--quick): the falling ABSOLUTE bound is not scored")
        return S
    lo, hi = (S[13][0], S[14][0]), (S[10][0], S[11][0])
    check(max(lo) < min(hi) and min(S[13][1], S[14][1]) >= S[10][1],
          "and the bound itself is LOWER at n = 13, 14 (%.2f, %.2f) than at n = 10, 11 "
          "(%.2f, %.2f), while exact mu is not (%.2f, %.2f against %.2f, %.2f)"
          % (lo + hi + (S[13][1], S[14][1], S[10][1], S[11][1])))
    return S


# ═══════════════════════════════════════════════════════════════════════════
# §4  why
# ═══════════════════════════════════════════════════════════════════════════
def section_4():
    rule("§4  Why: the dual is not a cycle")
    print("""The LP dual is a probability distribution over edges whose source and target
have the same window statistics at every position.  A cycle is one such distribution;
most are not cycles.  Measured: where the optimal dual's mass sits, by the popcount of
the edge's source difference.
""")
    W = 5
    rows = {}
    for n in (8, 10, 11):
        mw, sp = [], []
        for d in keys(n, 6):
            mu, E = graph(n, d)
            t, lp = local_bound(n, W, E)
            du = lp.duals()
            tot = float(du.sum())
            pc = [bin(a).count("1") for a, _, _ in lp.edges]
            mw.append(sum(x * p for x, p in zip(du, pc)) / tot / n)
            sp.append(sum(x for x, p in zip(du, pc) if p <= 2) / tot)
        rows[n] = (med(mw), med(sp))
        print("  n = %2d  median dual-weighted popcount/n %.3f   dual mass on "
              "popcount <= 2: %.2f" % (n, rows[n][0], rows[n][1]))
    ns = sorted(rows)
    check(all(rows[n][0] < 0.5 for n in ns) and rows[ns[-1]][0] < rows[ns[0]][0],
          "the dual lives on LIGHT differences (popcount/n %s), below the 0.6-0.86n "
          "of the optimal cycles (§11.37) and falling with n -- it stitches cheap "
          "sparse edges whose support never has to grow"
          % ", ".join("%.2f" % rows[n][0] for n in ns))


# ═══════════════════════════════════════════════════════════════════════════
# §5  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_5():
    rule("§5  What this changes for #257")
    print("""CLOSED, by measurement, recorded so it is not re-derived: a LOCAL potential
certificate.  It is sound at every width, it is exact when the window covers the word,
and its value is computable at n = 256 by a bit-position DP whose relaxation (the
componentwise max over the carry slot) is measured to be close -- so it is the first
route in #257 that would have been a PROOF at n = 256.  It fails on the quantity that
matters: the window it needs to reach mu grows with n (w* ~ 0.7n), and at any fixed
window the certified share of mu falls with n while mu rises.  Its dual explains why:
a distribution of cheap, light edges whose local statistics balance stands in for a
cycle, and a wider word only offers more places to find them.  The DP costs ~4^w per
bit, so a window that grows with n is not available at n = 256.

The quenched effect again.  §11.40 found the model blind to where the RUNS of delta
sit; this certificate is blind to how the SUPPORT of a difference grows through M.
Both are global properties of one fixed constant and one linear map, and a bound
assembled from local pieces cannot carry either.

What this does NOT change.  Exact mu, measured to n = 23 (§11.42), grows at every
width step, and the criterion holds at n = 256 if it keeps not decreasing.  That
monotonicity residue is unchanged, and the next route has to carry non-local
information -- the support growth of M is the obvious candidate.

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    section_1()
    section_2(a.quick)
    section_3(a.quick)
    section_4()
    section_5()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
