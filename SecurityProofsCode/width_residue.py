#!/usr/bin/env python3
"""width_residue.py — the one question TODO #252 and TODO #254 have left.

Both items have been reduced to the same thing.  #252's second pass computed
the asymptotic DIFFERENTIAL slope exactly, as the minimum mean cycle of the
difference graph (§11.35); #254's second pass did the same for the LINEAR slope
on the mask graph, for v1 and v2 alike (§11.36).  Each ends owing the WIDTH
EXTRAPOLATION and nothing else, and it is the same extrapolation about the same
kind of object.  This script is that shared residue, worked.

It does not close it.  It changes what is being asked, three times over.

  §1  THE RESIDUE IS MONOTONICITY, NOT THE LIMIT.  Both criteria are already
      cleared at the widest width measured -- s_diff = 1.90 against 4/3 at
      n = 11, s_lin = 1.15 against 2/3 at n = 13 -- and every measured width is
      exact.  So any monotone continuation clears them at n = 256.  The open
      question is not "what is the limit", it is "does the sequence ever turn
      around", which is a strictly weaker thing to have to prove.

  §2  THERE IS NO EMBEDDING BETWEEN WIDTHS, and that resolves §11.35.7's
      caution.  M and delta both depend on n, so the graph at width n+1 is not
      an extension of the graph at width n -- it is an unrelated graph.  A cycle
      at width n is not a cheap cycle at width n+1; it is not a walk at all.
      The obvious tool does not point the wrong way, as §11.35.7 feared.  It
      does not apply.

  §3  THREE ROUTES ARE CLOSED, each by measurement rather than by argument:
      restricting to sparse cycles (the optimal cycle is DENSE), guessing a
      potential function for the LP dual (Howard's bias correlates with
      nothing), and sampling the weight distribution at n = 256 (the threshold
      lives in a 2^-n quantile).

  §4  ONE ROUTE IS OPENED AND VALIDATED.  An annealed first-moment model
      predicts mu from the edge-weight distribution and the out-degree alone.
      It under-predicts at the narrow widths and converges towards exact --
      0.845, 0.895, 0.941, 1.002 on the differential axis and 0.858, 0.875,
      0.938, 0.988 on the linear one, independently.  What it needs at n = 256 is one number:
      the maximum correlation, respectively the maximum differential
      probability, of addition with a CONSTANT.  That is a self-contained
      question about modular addition, with no FSCX in it.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/width_residue.py [--quick]
"""

import argparse
import importlib.util
import math
import os
import random
import statistics
import sys
from collections import Counter

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EPS = 1e-12

CRIT_DIFF = 4.0 / 3.0
CRIT_LIN = 2.0 / 3.0


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def _load(name, fn):
    p = os.path.join(ROOT, 'SecurityProofsCode', fn)
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


DC = _load('_dc', 'diff_cycle_mean.py')      # differential graph + Howard/Karp
LC = _load('_lc', 'lin_cycle_mean.py')       # mask graph
FK = DC.FK

AXES = (('differential', DC.build, CRIT_DIFF),
        ('linear', LC.build_v2, CRIT_LIN))


def deltas(n, k, seed=5):
    ds = sorted(x for x in DC.deltas_with_multiplicity(n)
                if not DC.screened(n, x))
    if len(ds) > k:
        ds = random.Random(seed).sample(ds, k)
    return sorted(ds)


def howard_cycle(adj, alive):
    """Howard's policy iteration, returning (mu, the optimal cycle itself).

    The repo's shipped copy returns only mu; §2 and §3 need the cycle, so this
    keeps the cycle each node funnels into and returns the best one."""
    N = len(adj)
    nodes = [v for v in range(N) if alive[v]]
    if not nodes:
        return None, None, None
    pi, pw = {}, {}
    for v in nodes:
        b, w = min(adj[v], key=lambda e: e[1])
        pi[v], pw[v] = b, w
    for _ in range(100000):
        mu, h, cyc_of, colour = {}, {}, {}, {}
        for s in nodes:
            if s in colour:
                continue
            path = []
            v = s
            while v not in colour:
                colour[v] = 0
                path.append(v)
                v = pi[v]
            if colour[v] == 0:
                i = path.index(v)
                cyc = path[i:]
                m = sum(pw[u] for u in cyc) / len(cyc)
                for u in cyc:
                    mu[u] = m
                    cyc_of[u] = cyc
                h[v] = 0.0
                order = []
                u = v
                while True:
                    order.append(u)
                    u = pi[u]
                    if u == v:
                        break
                for u in reversed(order[1:]):
                    h[u] = pw[u] - m + h[pi[u]]
                tail = path[:i]
            else:
                tail = path
            for u in reversed(tail):
                mu[u] = mu[pi[u]]
                h[u] = pw[u] - mu[u] + h[pi[u]]
                cyc_of[u] = cyc_of[pi[u]]
            for u in path:
                colour[u] = 1
        improved = False
        for v in nodes:
            bmu, bh, bb, bw = mu[v], h[v], None, None
            for b, w in adj[v]:
                cmu = mu[b]
                ch = w - cmu + h[b]
                if cmu < bmu - EPS or (abs(cmu - bmu) <= EPS and ch < bh - EPS):
                    bmu, bh, bb, bw = cmu, ch, b, w
            if bb is not None:
                pi[v], pw[v] = bb, bw
                improved = True
        if not improved:
            best = min(nodes, key=lambda v: mu[v])
            return mu[best], cyc_of[best], h
    raise RuntimeError("Howard did not converge")


def hw(x):
    return bin(x).count('1')


def tz(x, n):
    return n if x == 0 else (x & -x).bit_length() - 1


def naf(d, n):
    d %= (1 << n)
    w = 0
    while d:
        if d & 1:
            z = 2 - (d & 3)
            d -= z
            w += 1
        d >>= 1
    return w


def pearson(xs, ys):
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx == 0 or sy == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The residue is monotonicity, not the limit")
    print(f"""Both criteria are already met at the widest width either item reached, and
every measured value is EXACT -- a minimum mean cycle, not a slope read off a
finite series.

    differential   s_diff = 1.903 at n = 11    criterion {CRIT_DIFF:.4f}
    linear         s_lin  = 1.154 at n = 13    criterion {CRIT_LIN:.4f}

Both sequences rise monotonely over every width measured, on both primitives,
with the fraction of keys below the criterion falling to zero for v2's linear
slope by n = 13.  So the extrapolation does not have to produce a limit.  It has
to rule out a turning point:

    if mu(n) is non-decreasing for n >= 13, both criteria hold at n = 256.

That is a strictly weaker obligation than the one #252 and #254 were filed with,
and it is worth stating because the two items have been carrying the harder
version of the question for four passes.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_2(quick):
    rule("§2  There is no embedding between widths")
    print("""§11.35.7 warned that the obvious tool points the wrong way: exhibit a cycle at
width n that survives at width n+1 and you prove mu NON-INCREASING, the opposite
of what is measured.  The warning is unnecessary, and the reason is worth having.

Both of the round's width-dependent objects change with n.  M = I ^ ROL ^ ROR is
built from rotations by 1, so M_n and M_{n+1} disagree on almost every argument;
and delta(B) = ROL(B*floor((B+1)/2) mod 2^n, n/4) changes in the modulus AND in
the rotation amount.  The graph at width n+1 is therefore not an extension of the
graph at width n.  It is a different graph on a different vertex set.

Measured: of the nodes lying on an optimal cycle at width n, the fraction whose
image under M is unchanged at width n+1.""")
    ok = True
    for n in ((7, 10) if quick else (7, 10, 11)):
        if (n + 1) in DC.SINGULAR:
            continue
        Mn, Mn1 = FK.m_tab(n), FK.m_tab(n + 1)
        tot = same = 0
        for d in deltas(n, 4 if quick else 8):
            adj = LC.build_v2(n, d)
            _, cyc, _ = howard_cycle(adj, DC.prune(adj))
            if not cyc:
                continue
            for a in cyc:
                tot += 1
                same += (Mn[a] == Mn1[a])
        frac = same / tot if tot else 0.0
        print(f"      n = {n:2d} -> {n + 1:2d}:  {same}/{tot} nodes keep their "
              f"image  ({frac:.1%})")
        if frac > 0.45:
            ok = False
    check(ok, "optimal-cycle nodes now mostly survive widening")
    print("""
      Around one node in four, so a cycle of length L survives with probability
      about 0.27^L, and §3 measures L >= 4 everywhere.  In practice no cycle
      survives, and the delta of the same key is a different constant besides.

      The consequence is not comfortable, but it is clarifying: there is no
      structural relation between consecutive widths to exploit in either
      direction.  A monotonicity proof cannot come from comparing two graphs.
      It has to come from a statement about the ENSEMBLE, which is §4.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_3(quick):
    rule("§3  Two routes closed by measurement")
    print("""  (a) THE SPARSE-SUBGRAPH ROUTE.  The natural first idea for reaching n = 256
      is to search only low-Hamming-weight differences or masks: the subgraph
      they span is small enough to enumerate at any width, and because a
      subgraph has fewer cycles its minimum mean is an UPPER bound on the true
      one -- so a cheap cycle found there would be a real result at the deployed
      width.  It fails on the input: the optimal cycle is dense.""")
    print(f"\n      {'axis':>13} {'n':>3} {'cycle length':>13} "
          f"{'max Hamming wt':>15} {'as a fraction of n':>19}")
    ok = True
    for name, build, _ in AXES:
        for n in ((7, 10) if quick else (7, 8, 10, 11)):
            Ls, Ws = [], []
            for d in deltas(n, 4 if quick else 10):
                adj = build(n, d)
                _, cyc, _ = howard_cycle(adj, DC.prune(adj))
                if not cyc:
                    continue
                Ls.append(len(cyc))
                Ws.append(max(hw(x) for x in cyc))
            if not Ls:
                continue
            mw = statistics.median(Ws)
            print(f"      {name:>13} {n:3d} {statistics.median(Ls):13.0f} "
                  f"{mw:15.0f} {mw / n:19.2f}")
            if mw / n < 0.5:
                ok = False
    check(ok, "optimal cycles are no longer dense")
    print("""
      Median max-weight runs 0.70n to 0.86n on the differential axis and 0.57n
      to 0.64n on the linear one, at every width, with no downward trend.  At
      n = 256 that is a difference or mask of weight between 150 and 220, while
      the subgraph of weight <= w has C(256, <= w) nodes -- enumerable only for
      w in the single digits.  The optimal cycle is not in any subgraph anyone
      can build, and it is not close.""")

    print(SEP2)
    print("""  (b) THE LP-DUAL ROUTE, which is the only one that could give a THEOREM
      rather than an estimate.  Minimum mean cycle is a linear program, and its
      dual says: if there is a potential h on the nodes with

              w(a -> b) + h(b) - h(a) >= lambda   for every edge,

      then mu >= lambda, unconditionally, at any width.  Howard's algorithm
      already produces the optimal h as its bias, so the question is whether
      that h has a closed form one could write down at n = 256 and verify
      combinatorially.  Measured against every natural statistic of a node:""")
    print(f"\n      {'axis':>13} {'n':>3} {'corr(h, hw)':>12} {'corr(h, tz)':>12} "
          f"{'corr(h, NAF)':>13} {'corr(h, value)':>15}")
    worst = 0.0
    for name, build, _ in AXES:
        for n in ((8,) if quick else (8, 10)):
            acc = [[], [], [], []]
            for d in deltas(n, 3 if quick else 5, seed=11):
                adj = build(n, d)
                m, _, h = howard_cycle(adj, DC.prune(adj))
                if m is None:
                    continue
                xs = sorted(h)
                H = [h[v] for v in xs]
                acc[0].append(pearson([hw(v) for v in xs], H))
                acc[1].append(pearson([tz(v, n) for v in xs], H))
                acc[2].append(pearson([naf(v, n) for v in xs], H))
                acc[3].append(pearson(list(xs), H))
            if not acc[0]:
                continue
            med = [statistics.median(a) for a in acc]
            worst = max(worst, max(abs(x) for x in med))
            print(f"      {name:>13} {n:3d} {med[0]:12.3f} {med[1]:12.3f} "
                  f"{med[2]:13.3f} {med[3]:15.3f}")
    print(f"\n      Largest absolute correlation anywhere in the table: "
          f"{worst:.3f}")
    check(worst < 0.45, "the Howard bias has acquired a simple closed form")
    print("""
      The largest entry anywhere is 0.37 -- Hamming weight, linear axis, n = 8 --
      which accounts for about a seventh of the variance and is not a functional
      form; every differential-axis entry is under 0.11.  The optimal potential
      is not a function of Hamming weight, of trailing zeros, of NAF weight, or
      of the node's value.  A potential must still exist -- LP duality
      guarantees one -- but it cannot be guessed from these, and a potential
      that has to be computed node by node is a 2^256-sized object.""")


# ═══════════════════════════════════════════════════════════════════════════
def _rate(items, tot, lam):
    """I(lam) = sup_{theta >= 0} [-theta*lam - ln E e^{-theta W}], log-sum-exp'd
    so that wide blocks, where the weights are large, do not underflow."""
    best = 0.0
    th = 1e-4
    while th < 2000:
        top = max(-th * w for w, _ in items)
        s = sum(c * math.exp(-th * w - top) for w, c in items)
        v = -th * lam - (top + math.log(s) - math.log(tot))
        if v > best:
            best = v
        th *= 1.12
    return best


def annealed(adj):
    """The annealed threshold: lambda with I(lambda) = ln D."""
    c = Counter()
    live = 0
    for v in range(1, len(adj)):
        if adj[v]:
            live += 1
        for _, w in adj[v]:
            c[round(w, 9)] += 1
    items, tot = list(c.items()), sum(c.values())
    lnD = math.log(tot / live)
    lo, hi = 0.0, max(w for w, _ in items)
    for _ in range(45):
        mid = (lo + hi) / 2
        if _rate(items, tot, mid) > lnD:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2, tot / live


def section_4(quick):
    rule("§4  The route that is open: an annealed first-moment model")
    print("""§2 says a monotonicity proof cannot come from relating two graphs, so it has
to come from treating the graph as a member of an ensemble.  Test that directly.

In a digraph on N nodes where each node has D out-edges to arbitrary targets and
the weights are drawn from a distribution F, the expected number of cycles of
length L with mean weight at most lambda is about

        (D^L / L) * Pr[ W_1 + ... + W_L <= lambda*L ]  ~  exp(L(ln D - I(lambda)))

with I the large-deviation rate function of F.  The exponent changes sign at the
lambda solving I(lambda) = ln D, so THAT lambda is the model's prediction for the
minimum mean cycle -- a quantity depending on nothing but the weight
distribution and the out-degree.  Both are available at any width.

Compared against the exact value, per key, on both axes:""")
    print(f"\n      {'axis':>13} {'n':>3} {'exact mu':>10} {'annealed':>10} "
          f"{'ratio':>7} {'out-degree':>11}")
    ratios = {}
    for name, build, _ in AXES:
        seq = []
        for n in ((7, 8, 10) if quick else (7, 8, 10, 11)):
            R = []
            for d in deltas(n, 4 if quick else 6):
                adj = build(n, d)
                m = DC.howard(adj, DC.prune(adj))
                if m is None:
                    continue
                p, D = annealed(adj)
                R.append((m, p, D))
            if not R:
                continue
            em = statistics.median(r[0] for r in R)
            pm = statistics.median(r[1] for r in R)
            per = sorted(r[1] / r[0] for r in R)
            seq.append(statistics.median(per))
            print(f"      {name:>13} {n:3d} {em:10.4f} {pm:10.4f} "
                  f"{statistics.median(per):7.3f} "
                  f"{statistics.median(r[2] for r in R):11.0f}")
        ratios[name] = seq
    print()
    for name, seq in ratios.items():
        gap = [abs(1 - x) for x in seq]
        closing = gap[-1] <= gap[0] + 0.02
        print(f"      {name:>13}: per-key median ratio "
              f"{' -> '.join(f'{x:.3f}' for x in seq)}   gap closing: {closing}")
        check(closing, f"the annealed ratio stopped converging ({name})")
        check(max(seq) <= 1.20, f"the annealed model drifted far from exact "
                                f"({name})")
    print("""
      At the narrow widths the model UNDER-predicts, which is the direction that
      matters -- an under-prediction of mu over-states the attacker's advantage
      -- and the gap closes as the width grows, to within a few percent by the
      widest width reached.  That is the expected behaviour of a first-moment
      threshold on a graph that becomes locally tree-like: asymptotically tight,
      pulled low at small sizes by the correlations a tree does not have.

      Two cautions before this is leaned on.  The convergence is to within a few
      percent, not to zero, and on a small sample of keys the ratio can overshoot
      one by about a tenth -- so the model is an estimator, not a bound, and a
      claim resting on it would need the sign of the finite-size correction
      established rather than observed.  What it does establish is that mu is
      not an algebraic accident of this cipher: it is close to what the weight
      distribution alone predicts, which is why §5's reduction is worth having.

      This is the first statement in either item that is not confined to the
      width it was measured at.  If it holds, mu at n = 256 is determined by two
      numbers, and neither of them mentions cycles.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_5(quick):
    rule("§5  What the model needs, and why sampling cannot supply it")
    print("""The annealed threshold solves I(lambda) = ln D.  With D of order 2^n/3 on the
linear axis, ln D is about n*ln2, and the lambda that achieves a rate that large
is the quantile of F at about 3*2^-n.  In words: the threshold is set by the
CHEAPEST edges a node has, not by typical ones.  Measured, mu sits between the
tenth percentile and the median of the per-node minimum out-edge weight:""")
    print(f"\n      {'axis':>13} {'n':>3} {'mu':>8} {'p10 min-edge':>13} "
          f"{'median min-edge':>16}")
    ok = True
    for name, build, _ in AXES:
        for n in ((7, 10) if quick else (7, 8, 10, 11)):
            R = []
            for d in deltas(n, 4 if quick else 6):
                adj = build(n, d)
                m = DC.howard(adj, DC.prune(adj))
                if m is None:
                    continue
                mins = sorted(min(w for _, w in adj[v])
                              for v in range(1, len(adj)) if adj[v])
                R.append((m, mins[len(mins) // 10], mins[len(mins) // 2]))
            if not R:
                continue
            a = statistics.median(r[0] for r in R)
            b = statistics.median(r[1] for r in R)
            c = statistics.median(r[2] for r in R)
            print(f"      {name:>13} {n:3d} {a:8.4f} {b:13.4f} {c:16.4f}")
            if not (b - 0.05 <= a <= c + 0.05):
                ok = False
    check(ok, "mu no longer sits between the p10 and the median min-out-edge")
    print("""
      And the median minimum out-edge weight rises with n at about the rate mu
      does.  So the width dependence of the whole construction is inherited from
      one quantity:

          the largest |correlation| of x -> x + d for a fixed output mask,
          and its differential twin, the largest xdp+ for a fixed input
          difference.

      THAT is the residue, stated without any FSCX in it.  It is a question
      about modular addition with a constant, and it is the reason the third
      route -- estimate F at n = 256 by sampling mask pairs and evaluate the
      model -- does not work: uniform sampling reaches the bulk of F, and the
      threshold lives in a tail of measure 2^-n.  A run of this shape at
      n = 256 returns a number near 157, and the same procedure at n = 13
      returns 0.48 where the exact value is 1.15.  The n = 13 control is what
      says the n = 256 figure is an artefact of the sampler, and it is recorded
      here so that nobody quotes the 157.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_6(quick):
    rule("§6  A decomposition that shortens the sequence to extrapolate")
    print("""One more structural fact, cheap and useful.  The slope depends on the key
almost entirely through tz(delta), the trailing-zero count of the additive
constant -- the same statistic #253's differential weak class is defined by, and
the same one §11.30.5's correlation-1 mask subspace is indexed by.  Within a
width, mu falls by a roughly constant amount per trailing zero:""")
    print(f"\n      {'n':>3} " + " ".join(f"{'tz=' + str(k):>8}" for k in range(5))
          + f"  {'per-tz slope':>13}")
    slopes = []
    for n in ((8, 10) if quick else (8, 10, 11)):
        by = {}
        for d in deltas(n, 40 if quick else 90):
            adj = LC.build_v2(n, d)
            m = DC.howard(adj, DC.prune(adj))
            if m is not None:
                by.setdefault(tz(d, n), []).append(m)
        med = {k: statistics.median(v) for k, v in by.items() if len(v) >= 2}
        ks = sorted(k for k in med if k <= 4)
        row = " ".join(f"{med[k]:8.3f}" if k in med else f"{'-':>8}"
                       for k in range(5))
        if len(ks) >= 3:
            s = (med[ks[0]] - med[ks[-1]]) / (ks[-1] - ks[0])
            slopes.append(s)
            print(f"      {n:3d} {row}  {s:13.3f}")
        else:
            print(f"      {n:3d} {row}  {'--':>13}")
    if slopes:
        print(f"\n      The per-trailing-zero cost is {min(slopes):.3f} to "
              f"{max(slopes):.3f} across widths -- flat to within the sample.")
        check(max(slopes) - min(slopes) < 0.12,
              "the per-trailing-zero cost is no longer width-stable")
    print("""
      If that offset is width-independent, and it looks it, then the whole
      per-key distribution at n = 256 follows from ONE sequence -- the tz = 0
      class -- plus a constant, since the distribution of tz(delta) itself does
      not depend on the width.  That halves the extrapolation's surface without
      assuming anything about its limit.""")


# ═══════════════════════════════════════════════════════════════════════════
def section_7():
    rule("§7  Where this leaves the two items")
    print("""  MERGE THEM.  #252 and #254 now have identical remaining scope: the width
  behaviour of a minimum mean cycle over an add-constant transition graph, on
  two axes that share their machinery, their obstacle and their reduction.
  Carrying two items whose open text would be the same paragraph is how the
  disagreement-between-documents class of bug (#237, #238) starts.

  THE OBLIGATION IS SMALLER THAN EITHER ITEM STATES.  §1: both criteria are met
  at the widest exact width, so what is owed is monotonicity, not a limit.

  ROUTES, RANKED, WITH THREE NOW CLOSED.
    1. OPEN, and the only one with a path to n = 256: bound the largest
       correlation and the largest xdp+ of addition with a CONSTANT as a
       function of n (§5).  Self-contained, no FSCX in the statement, and it
       feeds a model already validated to within 1% at n = 11 (§4).  Note that
       Wallen's characterisation does NOT apply -- §11.30.4 closed that for the
       constant-addend case -- so this needs its own argument.
    2. OPEN, weaker: extend the exact sequence.  The linear axis reaches n = 13
       for the cost of an (n+1)*4^n table and n = 14 is a factor of four away;
       the differential axis is stuck at n = 11 on its 2^2n DDT.  More points
       do not prove monotonicity but would make a turning point harder to hide.
    3. CLOSED: sparse-subgraph search at n = 256.  The optimal cycle is dense
       (§3a).
    4. CLOSED: guess the LP-dual potential.  It correlates with nothing (§3b).
    5. CLOSED: sample the weight distribution at n = 256 and evaluate the
       annealed model.  The threshold is a 2^-n quantile and the sampler misses
       it by more than a factor of two at n = 13, where the answer is known
       (§5).

  WHAT WOULD CHANGE A RATING.  Nothing here does, and nothing here could: every
  row this touches is already demo-only for reasons on other axes (#243, #244,
  #248), and the production-track rows #254 hoped to reach were removed from its
  scope by §11.36.8, which showed a trail bound cannot describe them at all.""")


# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='narrower widths and smaller samples')
    args = ap.parse_args()
    section_1()
    section_2(args.quick)
    section_3(args.quick)
    section_4(args.quick)
    section_5(args.quick)
    section_6(args.quick)
    section_7()
    print("\n" + SEP)
    if FAIL:
        print(f"*** FAILED: {len(FAIL)} finding(s) stopped reproducing ***")
        for f in FAIL:
            print(f"  - {f}")
        print(SEP)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")
    print(SEP)


if __name__ == '__main__':
    main()
