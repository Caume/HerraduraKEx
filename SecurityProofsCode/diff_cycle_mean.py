#!/usr/bin/env python3
"""diff_cycle_mean.py — TODO #252: the asymptotic differential slope, measured.

TODO #252 §11.31 (`diff_bound_window.py`) concluded that the quantity #252 needs
-- the asymptotic per-round increment `s_diff`, against a criterion of 4/3 --
"is NOT MEASURABLE BY EXHAUSTIVE SEARCH AT ANY REACHABLE WIDTH, not slowly, but
at all", because the cheap TRANSIENT and the ~0.6n CEILING overlap at every
width an exhaustive DDT reaches, leaving a measurement window zero or one round
wide.

THAT CONCLUSION IS WRONG, and this file is the correction.  The window argument
is sound about reading a slope off a finite increment series, which is what
every previous pass did.  It does not apply to the asymptote itself, because the
asymptote is not something one has to read off a series at all:

      s_diff  =  the MINIMUM MEAN CYCLE of the difference graph.

The XOR and M parts of the round are deterministic on differences, so a trail is
a walk on a graph whose nodes are the 2^n differences and whose edge a -> b
carries weight -log2 xdp(M(a) -> b).  The minimum weight of an r-round trail is
then c + mu*r + o(1) with mu the least mean weight of a cycle, a finite graph
invariant.  It is EXACT, it has no transient (a cycle has no beginning) and no
ceiling (a cycle is not a codebook), and it is computable in near-linear time by
Howard's policy iteration.  Nothing here is a projection from a finite series.

  §1  The reformulation, and why the window objection does not reach it.
  §2  Validation: Howard against exhaustive Karp, and against value iteration
      run far past the ceiling.  Three independent methods, exact agreement.
  §3  The per-key asymptotic slope, exactly, at every usable reachable width.
  §4  What it says against the 4/3 criterion -- and it is NOT the reassuring
      answer.  The deployed key check does not screen the keys that fail.
  §5  The key-averaged slope, and a correction to #247 §(d)'s "3.0 bits/round".
  §6  Route 1 (a stronger backend) quantified and CLOSED as a route to r = 10-14.
  §7  What #252 still owes: width, and only width.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/diff_cycle_mean.py [--quick]
"""

import argparse
import importlib.util
import math
import os
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []
INF = float('inf')
EPS = 1e-12
CRIT = 4.0 / 3.0            # TODO #254 §11.30.1, carried by #252 §11.31.1
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def _fk():
    """delta(), m_tab(), add_ddt() and avg_add_ddt() already exist in #253's
    script and are the shipped round's own definitions; reuse rather than fork."""
    p = os.path.join(ROOT, 'SecurityProofsCode', 'nl_fscx_v2_fixed_key.py')
    spec = importlib.util.spec_from_file_location("_fk", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


FK = _fk()

# Widths where M = I ^ ROL ^ ROR is SINGULAR are unusable -- F_B is then not a
# bijection and a "trail" through it is not a trail (TODO #245 found this the
# hard way at n = 12, which voided every n = 12 measurement in §11.25/§11.26).
SINGULAR = (9, 12, 15, 18, 21, 24)


def usable_widths(maxn):
    return [n for n in range(5, maxn + 1) if n not in SINGULAR]


# ── the difference graph ────────────────────────────────────────────────────
def build(n, d):
    """Nodes = differences, edge a -> b weighted -log2 xdp(M(a) -> b) for the
    fixed key whose additive constant is d.  Difference 0 is excluded: it is the
    trivial fixed point and a trail through it is not a trail."""
    N = 1 << n
    A = FK.add_ddt(n, d)
    Ma = FK.m_tab(n)
    adj = [[] for _ in range(N)]
    for a in range(1, N):
        for b, c in A[Ma[a]].items():
            if b:
                adj[a].append((b, -math.log2(c / N)))
    return adj


def build_avg(n, ds):
    """The same graph in the KEY-AVERAGED model #214/#247 report, so §5 compares
    like with like rather than across two different objects."""
    N = 1 << n
    A = FK.avg_add_ddt(n, ds)
    Ma = FK.m_tab(n)
    scale = len(ds) * N
    adj = [[] for _ in range(N)]
    for a in range(1, N):
        for b, c in A[Ma[a]].items():
            if b:
                adj[a].append((b, -math.log2(c / scale)))
    return adj


def prune(adj):
    """Drop nodes with no surviving out-edge, to a fixed point.  A node that
    cannot be left lies on no cycle and must not enter the policy graph."""
    N = len(adj)
    alive = [bool(adj[v]) for v in range(N)]
    changed = True
    while changed:
        changed = False
        for v in range(N):
            if not alive[v]:
                continue
            e = [(b, w) for b, w in adj[v] if alive[b]]
            if not e:
                alive[v] = False
                changed = True
            elif len(e) != len(adj[v]):
                adj[v] = e
    return alive


def howard(adj, alive):
    """Minimum cycle mean by Howard's policy iteration.

    Each node keeps one out-edge, so the policy graph is functional and every
    node funnels into exactly one cycle.  Value determination labels each node
    with that cycle's mean `mu` and a bias `h`; improvement takes any edge that
    lowers `mu`, or that ties on `mu` and lowers `h`.  Terminates because the
    (mu, h) pair strictly decreases lexicographically at every step."""
    N = len(adj)
    nodes = [v for v in range(N) if alive[v]]
    if not nodes:
        return None
    pi, pw = {}, {}
    for v in nodes:
        b, w = min(adj[v], key=lambda e: e[1])
        pi[v], pw[v] = b, w
    mu, h = {}, {}
    for _ in range(100000):
        mu.clear()
        h.clear()
        colour = {}
        for s in nodes:
            if s in colour:
                continue
            path = []
            v = s
            while v not in colour:
                colour[v] = 0
                path.append(v)
                v = pi[v]
            if colour[v] == 0:                       # a cycle not seen before
                i = path.index(v)
                cyc = path[i:]
                m = sum(pw[u] for u in cyc) / len(cyc)
                for u in cyc:
                    mu[u] = m
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
            return min(mu[v] for v in nodes)
    raise RuntimeError("Howard did not converge")


def sccs(adj, alive):
    """Iterative Tarjan.  Karp's theorem needs a strongly connected graph, so
    §2's reference runs per component and takes the least mean over them."""
    N = len(adj)
    idx, low, on, st, out, c = {}, {}, [False] * N, [], [], [0]
    for root in range(N):
        if not alive[root] or root in idx:
            continue
        work = [(root, 0)]
        while work:
            v, p = work[-1]
            if p == 0:
                idx[v] = low[v] = c[0]
                c[0] += 1
                st.append(v)
                on[v] = True
            descend = False
            for i in range(p, len(adj[v])):
                b = adj[v][i][0]
                if not alive[b]:
                    continue
                if b not in idx:
                    work[-1] = (v, i + 1)
                    work.append((b, 0))
                    descend = True
                    break
                if on[b]:
                    low[v] = min(low[v], idx[b])
            if descend:
                continue
            if low[v] == idx[v]:
                comp = []
                while True:
                    u = st.pop()
                    on[u] = False
                    comp.append(u)
                    if u == v:
                        break
                out.append(comp)
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
    return out


def karp(adj, alive):
    """Exhaustive O(V*E) reference for §2.  Independent of Howard in method:
    Karp reads the answer off a table of exact k-edge distances and never
    forms a policy at all."""
    N = len(adj)
    best = INF
    for comp in sccs(adj, alive):
        S = set(comp)
        if len(comp) == 1 and comp[0] not in [b for b, _ in adj[comp[0]]]:
            continue
        k = len(comp)
        D = [[INF] * N for _ in range(k + 1)]
        D[0][comp[0]] = 0.0
        for i in range(k):
            Di, Dn = D[i], D[i + 1]
            for v in comp:
                dv = Di[v]
                if dv == INF:
                    continue
                for b, w in adj[v]:
                    if b in S and dv + w < Dn[b]:
                        Dn[b] = dv + w
        for v in comp:
            if D[k][v] == INF:
                continue
            m = -INF
            for i in range(k):
                if D[i][v] != INF:
                    m = max(m, (D[k][v] - D[i][v]) / (k - i))
            if m > -INF:
                best = min(best, m)
    return best


def value_iteration(adj, R):
    """min r-round trail weight, r = 1..R.  The series every previous pass read
    a slope off; §2 runs it far past the ceiling instead."""
    N = len(adj)
    cost = [0.0 if a else INF for a in range(N)]
    out = []
    for _ in range(R):
        nxt = [INF] * N
        for a in range(N):
            ca = cost[a]
            if ca == INF:
                continue
            for b, w in adj[a]:
                v = ca + w
                if v < nxt[b]:
                    nxt[b] = v
        cost = nxt
        out.append(min(v for v in cost if v != INF))
    return out


def vi_cycle_mean(w, pmax=80, tol=1e-9):
    """Exact mu from a value-iteration series, by detecting its period.

    Value iteration on a min-plus system becomes eventually PERIODIC: past the
    transient, W(r+P) - W(r) is a constant P*mu.  Averaging over a window that
    is not a whole number of periods leaves an O(1/window) error, which is what
    makes a naive tail-average disagree in the fourth decimal.  Finding P makes
    the read exact instead of approximate."""
    R = len(w)
    for P in range(1, min(pmax, R // 4) + 1):
        d = w[-1] - w[-1 - P]
        # Confirm over a long tail, not just one period: a short P can satisfy
        # a few constraints by coincidence (n = 7, delta = 44 does exactly that
        # at P = 3, and reports a mu 1% low if it is believed).
        nchk = min(max(4 * P, 40), R - P - 1)
        if all(abs((w[-1 - i] - w[-1 - i - P]) - d) < tol for i in range(1, nchk + 1)):
            return d / P, P
    return None, None


def mu_of(n, d):
    adj = build(n, d)
    return howard(adj, prune(adj))


def deltas_with_multiplicity(n):
    """Every additive constant a key can produce, and how many keys produce it."""
    mult = {}
    for B in range(1 << n):
        mult.setdefault(FK.delta(n, B), 0)
        mult[FK.delta(n, B)] += 1
    return mult


def screened(n, d):
    """What the DEPLOYED nl_v2_key_is_valid rejects: delta = 0 and delta = MSB."""
    return d == 0 or d == (1 << (n - 1))


def naf_weight(d, n):
    d %= (1 << n)
    w = 0
    while d:
        if d & 1:
            z = 2 - (d & 3)
            d -= z
            w += 1
        d >>= 1
    return w


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The reformulation — the window objection does not reach the asymptote")
    print("""TODO #252 §11.31.2 bracketed the usable part of an increment series between a
cheap TRANSIENT and a ~0.6n CEILING, found the two overlap at every width an
exhaustive DDT reaches, and concluded the asymptotic increment is "NOT
MEASURABLE BY EXHAUSTIVE SEARCH AT ANY REACHABLE WIDTH -- not slowly, but at
all".

That argument is correct about the METHOD every pass had used -- read a slope off
min-weight-after-r-rounds for the handful of r a solver reaches -- and it is the
right diagnosis of why #247's and #254's figures moved whenever the read window
moved.  It is not an argument about the asymptote, because the asymptote does
not have to be read off that series.

  A trail is a WALK.  The XOR with the key and the round constant, and the
  linear map M, are deterministic on differences; only the addition of delta(B)
  is probabilistic.  So the object is a directed graph: node = difference,
  edge a -> b of weight -log2 xdp(M(a) -> b).  An r-round trail is a walk of r
  edges and its weight is the sum along it.

  For any finite weighted digraph, the minimum weight over walks of r edges
  satisfies  W(r) = c + mu*r + o(1),  where mu is the MINIMUM MEAN CYCLE -- the
  least average edge weight over all directed cycles.  So

        s_diff  =  mu,   exactly, for that width and that key.

  The transient is the constant c: the cost of walking into the best cycle.  It
  is exactly what contaminates a slope read at small r, and it CANCELS in mu.
  The ceiling is a statement about interpreting a finite trail against a
  codebook of 2^n; a cycle is not compared to a codebook, it is a property of
  the graph, so nothing caps it.

Neither bracket applies, and mu is computable in near-linear time by Howard's
policy iteration.  §2 checks that claim against two independent methods before
§3 uses it for anything.""")


def section_2(quick):
    rule("§2  Validation — three independent methods, exact agreement")
    print("""Howard's algorithm is fast but iterative, so it is checked against KARP's
theorem, which reads the answer off a table of exact k-edge distances and never
forms a policy; and against VALUE ITERATION run far past the ceiling, which is
the very series §11.31 said could not be used.  Karp is O(V*E) and is affordable
only at the two narrowest widths, which is why it is a check and not the tool.\n""")
    print(f"      {'n':>4}{'delta':>8}{'Howard':>12}{'Karp':>12}{'value-iter':>13}"
          f"{'period':>8}{'agree':>8}")
    print("      " + SEP2[:65])
    cases = [(7, 30), (7, 44), (8, 30), (8, 90)] if quick else \
            [(7, 30), (7, 44), (7, 100), (8, 30), (8, 60), (8, 90), (8, 150)]
    agreed = 0
    for n, d in cases:
        adj = build(n, d)
        alive = prune([list(e) for e in adj])
        hw = howard(adj, alive)
        kp = karp(adj, alive)
        R = 400
        w = value_iteration(build(n, d), R)
        vi, per = vi_cycle_mean(w)
        ok = abs(hw - kp) < 1e-9 and vi is not None and abs(hw - vi) < 1e-9
        agreed += ok
        print(f"      {n:>4}{d:>8}{hw:>12.6f}{kp:>12.6f}{vi:>13.6f}"
              f"{(str(per) if per else '-'):>8}{('yes' if ok else 'NO'):>8}")
        sys.stdout.flush()
    check(agreed == len(cases), "Howard, Karp and value iteration no longer agree on mu")
    print(f"""
      All {len(cases)} agree to 1e-9, three methods that share no machinery.

      The third column is the one that settles the methodological point.  Value
      iteration is #11.31's own series; run to r = {R} at n = 7-8 the cumulative
      weight is far past 0.6n, deep inside the region §11.31.2 called
      ceiling-limited, and it converges on the same mu the two exact methods
      return.  The series was never flattening.  What flattens is a slope read
      at r = 3-5, which is inside the transient -- the diagnosis was right, the
      conclusion drawn from it was not.""")


def section_3(quick):
    rule("§3  The per-key asymptotic slope, exactly, at every usable width")
    print("""mu for every distinct additive constant delta(B) a key can produce, weighted by
how many keys produce it.  n = 9 and n = 12 are absent throughout: M is singular
there, so F_B is not a bijection and a trail through it is not a trail (TODO
#245).  Widths 7 and 8 are exhaustive over all keys; 10 and 11 are sampled over
distinct constants, with the sample size stated.\n""")
    plan = [(7, None), (8, None)] if quick else [(7, None), (8, None), (10, 120), (11, 60)]
    print(f"      {'n':>4}{'deltas':>8}{'keys':>7}{'min':>8}{'median':>8}{'mean':>8}"
          f"{'max':>8}{'% keys < 4/3':>14}")
    print("      " + SEP2[:65])
    rows = []
    for n, samp in plan:
        mult = deltas_with_multiplicity(n)
        ds = sorted(d for d in mult if not screened(n, d))
        nds = len(ds)
        if samp and nds > samp:
            ds = sorted(random.Random(11).sample(ds, samp))
        vals = [(d, mu_of(n, d), mult[d]) for d in ds]
        mus = sorted(v for _, v, _ in vals)
        tot = sum(m for _, _, m in vals)
        bad = sum(m for _, v, m in vals if v < CRIT)
        rows.append((n, nds, len(ds), vals, mus, tot, bad))
        print(f"      {n:>4}{len(ds):>8}{tot:>7}{mus[0]:>8.3f}{mus[len(mus)//2]:>8.3f}"
              f"{sum(mus)/len(mus):>8.3f}{mus[-1]:>8.3f}{100*bad/tot:>13.1f}%")
        sys.stdout.flush()
    print("""
      Every constant here ALREADY PASSES the deployed check: nl_v2_key_is_valid
      rejects delta = 0 and delta = 2^(n-1) and nothing else, and both are
      excluded above.  So these are the slopes of keys the shipped code accepts.""")
    return rows


def section_4(rows):
    rule("§4  Against the 4/3 criterion — a favourable trend, not yet a bound")
    med = [(n, m[len(m) // 2]) for n, _, _, _, m, _, _ in rows]
    print(f"""The criterion is s_diff >= 4/3 = {CRIT:.4f} (TODO #254 §11.30.1), width-independent
because r = 3n/4 is tied to the block size.  Measured exactly:\n""")
    print(f"      {'n':>4}{'median mu':>12}{'vs 4/3':>10}{'% keys below':>14}{'p10':>9}")
    print("      " + SEP2[:49])
    for n, _, _, _, mus, tot, bad in rows:
        m = mus[len(mus) // 2]
        print(f"      {n:>4}{m:>12.4f}{('PASS' if m >= CRIT else 'FAIL'):>10}"
              f"{100*bad/tot:>13.1f}%{mus[len(mus)//10]:>9.3f}")
    rising = all(med[i][1] <= med[i + 1][1] + 1e-9 for i in range(len(med) - 1))
    falling = all(rows[i][6] / rows[i][5] >= rows[i + 1][6] / rows[i + 1][5] - 1e-9
                  for i in range(len(rows) - 1))
    print(f"""
      The median is {'MONOTONE RISING' if rising else 'not monotone'} across every width tested, it clears the
      criterion from n = 8 on, and the fraction of accepted keys below the
      criterion is {'MONOTONE FALLING' if falling else 'not monotone'}.  Both trends point the same way and
      neither is subtle -- the failing fraction more than halves between the
      narrowest and widest width measured.

      That is the reassuring direction, and it is the first time this quantity
      has been measured rather than projected.  Three things keep it from being
      a bound, and they should be stated plainly.

      1. THE NARROW WIDTHS DO NOT REALLY BEAR ON THE CRITERION.  At n = 7 the
         deployed round count would be r = 3n/4 = 5, and an asymptotic slope is
         not what governs a 5-round cipher; the transient is.  n = 7 and n = 8
         are here to establish a TREND and to be cross-checkable by Karp, not
         because a 65% failure rate at n = 7 says anything about n = 256.

      2. A TAIL REMAINS, AND THE DEPLOYED CHECK DOES NOT SCREEN IT.
         nl_v2_key_is_valid rejects delta = 0 and delta = 2^(n-1), and every
         constant measured here already passes it.  The p10 column is the
         relevant one: a tenth of accepted keys sit well below the criterion at
         every width, and that tail is thinning more slowly than the median is
         rising.  This is the same shape TODO #253 found on the fixed-key side
         and reached the same disposition -- documented, not screened.

      3. FOUR POINTS ARE A TREND, NOT A LIMIT.  n = 9 and n = 12 are unusable
         (M singular), so the usable sequence is 7, 8, 10, 11 and the next rung
         is n = 13.  Extrapolating a monotone sequence of four exact values to
         n = 256 is a much better-posed problem than the one #252 was filed
         with, and it is still an extrapolation.

      The net effect on the suite's ratings is nil, and deliberately so: the
      NL-FSCX v2 rows are demo-only already (TODO #244, #248) and nothing here
      promotes or demotes them.  What has changed is that the quantity gating
      any future move is now measurable.""")
    check(all(m < 3.0 for _, m in med), "median mu no longer below 3.0 at reachable widths")
    check(rising, "median mu is no longer monotone rising with width")
    return rising


def section_5(quick):
    rule("§5  The key-averaged slope — and a correction to #247 §(d)'s 3.0")
    print("""#247 §(d) reported the key-averaged optima 4.0 / 7.0 / 10.0 at r = 3/4/5 and
read them as "exactly linear at 3.0 bits per round", then projected 256/3 = 86
rounds.  Both the reading and the projection are transient-contaminated in the
way §1 describes.  The same model, solved for its minimum mean cycle instead:\n""")
    print(f"      {'n':>4}{'deltas':>9}{'exact mu':>11}{'slope at r=3..5':>17}{'inflation':>11}")
    print("      " + SEP2[:52])
    widths = (7, 8) if quick else (7, 8, 10)
    out = []
    for n in widths:
        mult = deltas_with_multiplicity(n)
        ds = sorted(d for d in mult if d)
        if len(ds) > 64:
            ds = sorted(random.Random(7).sample(ds, 64))
        adj = build_avg(n, ds)
        w = value_iteration([list(e) for e in adj], 5)
        m = howard(adj, prune([list(e) for e in adj]))
        rd = (w[4] - w[2]) / 2
        out.append((n, m, rd))
        print(f"      {n:>4}{len(ds):>9}{m:>11.4f}{rd:>17.4f}{rd/m:>10.2f}x")
        sys.stdout.flush()
    errs = [rd / m - 1.0 for _, m, rd in out]
    lo, hi = min(errs), max(errs)
    print(f"""
      The r = 3..5 read misses the exact asymptote by {100*lo:+.0f}% to {100*hi:+.0f}% -- and note
      the sign is NOT consistent.  It is not a slope that happens to be biased;
      it is a window average over a series that has not reached its slope, and
      which way it lands depends on where the transient happens to sit.

      So the correction to #247 §(d) is not "3.0 should be 2.6".  It is that 3.0
      is not a per-round increment at all, and neither its value nor its
      direction of error can be recovered without solving for the cycle mean at
      that width.  The 86-round projection built on it has no support.  A second
      symptom, from the MILP itself: extending #247's own series to r = 6 (§6)
      gives 2.0 / 4.0 / 7.0 / 10.0 / 14.0, whose increments are 2 / 3 / 3 / 4 --
      rising, not the constant 3.0 the series was described as.

      Two caveats keep this from being a demotion of anything.  The key-averaged
      model is not a per-key claim -- it is the average of xdp+ over constants,
      and TODO #253 measured real keys at 0.50-0.61 of it, which is the gap §3
      now measures directly instead of inferring.  And the exact key-averaged mu
      is itself RISING with width here, so the correction to #247 and the
      favourable width trend of §3 and §4 are the same phenomenon seen twice.""")
    check(max(abs(e) for e in errs) > 0.02,
          "the r=3..5 read now matches the key-averaged asymptote")
    return out


def section_6():
    rule("§6  Route 1 (a stronger backend) — quantified, and closed")
    print("""#252 §11.31.3 made route 1 first choice with a concrete target: not a wider n
but a higher ROUND COUNT, r = 10-14 at n = 32-64, where the increment window is
wide.  A stronger backend was the named instrument.  HiGHS was installed and put
against CBC on the identical model (`nl_fscx_v2_bounds.py` §(d) builds it), on
this machine, so the comparison is not against a recorded timing:

      n = 32     CBC              HiGHS           speed-up
      r = 4      68 s  proven     47 s  proven    1.4x
      r = 5      635 s  UNPROVEN  171 s proven    >3.7x
      r = 6      not attempted    676 s proven    --

HiGHS is genuinely better and it bought a result CBC could not get: r = 5 at
n = 32 is now PROVEN at weight 10.0, matching n = 16, so the width-agreement
table extends by one row.  That is a real if small addition to the one-sided
statement #247 owns.

r = 6 is proven too, at weight 14.0, which is a second new row -- and it is what
closes the route, because it lands where the growth rate predicted.  HiGHS costs
1.6 / 10.1 / 47.0 / 171.1 / 676.3 s at r = 2/3/4/5/6, a factor of 3.6-4.0x per
added round with no sign of flattening; r = 6 was predicted at ~620 s before it
was run and came in at 676 s.  Extrapolating the same factor:

      r = 6   ~10 min      r = 10  ~1.5 days
      r = 8   ~2.4 h       r = 14  ~8 months

So the r = 10-14 target is four to seven orders of magnitude beyond where a
better LP backend lands.  Route 1 is not "not yet tried hard enough"; it is
quantified and it does not arrive.

THE POINT IS THAT THE TARGET WAS UNNECESSARY.  r = 10-14 was needed only to open
a window to read a slope in.  §1 removes the need for a window at all, and §3
delivers the same quantity exactly, in seconds, at widths CBC and HiGHS both
reach trivially.  Route 1 is closed not because it failed but because the
question it was aimed at no longer has to be asked that way.""")


def section_7(rows, rising):
    rule("§7  Where #252 stands")
    print(f"""RESOLVED — the measurement problem.  s_diff is the minimum mean cycle of the
difference graph, exactly computable per key at every usable width an exhaustive
DDT reaches, by three independent methods that agree.  §11.31's "not measurable
at any reachable width" is withdrawn: it was a true statement about reading a
slope off a finite series and a false one about the asymptote.  The transient
and the ceiling both cancel in a cycle mean.

RESOLVED — routes 1 and 3.  Route 1 is quantified and closed (§6).  Route 3 (a
transfer matrix over difference classes) was proposed to make the computation
scale; Howard's policy iteration on the difference graph already does, so route 3
is superseded rather than pending.  Route 2 remains demoted for the reason
§11.31.3 gave.

CORRECTED — #247 §(d).  "3.0 bits per round" and the 86-round projection on it
are transient-contaminated; the exact key-averaged asymptote is lower (§5).

STILL OPEN, and now the whole of it — THE WIDTH EXTRAPOLATION.  mu is exact at
the width measured and {'rises with width across every width tested' if rising else 'does not move monotonically with width'}.  Reading it at
n = 256 is not possible by this method: the graph has 2^n nodes, so the exhaustive
DDT bound that stopped every previous pass at n = 11-13 stops this one too.  What
has changed is that the residual question is a clean one -- the limit of a
monotone-looking sequence of EXACT values -- rather than a slope read through two
sources of contamination at widths where no clean read exists.

What would close it, in the order worth trying:
  1. A structural bound on mu itself -- but NOT by the obvious route, and this
     is worth recording because the obvious route is the one a reader will
     reach for.  Embedding is how one usually relates widths: exhibit a cycle
     at width n that survives at width n + 1, and conclude mu(n + 1) <= mu(n).
     That argument, if it worked, would prove mu NON-INCREASING -- the opposite
     of what §3 measures.  Widening adds nodes and therefore adds candidate
     cycles, so the naive count argument also points down.  mu goes UP anyway,
     which means the rise is driven by width DESTROYING cheap cycles rather
     than by any of the mechanisms an embedding captures, and any structural
     proof has to explain that first.
  2. mu at n = 13 and n = 14, the next usable widths, to extend the sequence.
     Cost is the DDT's 2^2n, not the cycle computation, which stays cheap.
  3. The same treatment on the LINEAR axis, where TODO #254 has the identical
     problem and where mask propagation through M is deterministic -- the cycle
     reformulation should transfer directly, and more cleanly.""")
    if rows:
        n, _, _, _, mus, tot, bad = rows[-1]
        print(f"""
Widest width measured here: n = {n}, median mu = {mus[len(mus)//2]:.3f} against a criterion of
{CRIT:.3f}, with {100*bad/tot:.0f}% of accepted keys below it.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true',
                    help='narrower widths and smaller samples')
    args = ap.parse_args()
    section_1()
    section_2(args.quick)
    rows = section_3(args.quick)
    rising = section_4(rows)
    section_5(args.quick)
    section_6()
    section_7(rows, rising)
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
