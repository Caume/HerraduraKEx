#!/usr/bin/env python3
"""quenched_exact_ladder.py — TODO #257 (1'): the quenched check, by measurement.

TODO #257 closed its second-moment item (SecurityProofs-9.md §11.39) and was left
owing one thing on the trail axes: a QUENCHED statement.  The annealed model of
§11.38 is a first-moment count over an ENSEMBLE of random graphs with the right
edge-weight distribution and out-degree; §11.39 showed that ensemble concentrates.
Neither says that ONE FIXED round function -- the deployed NL-FSCX v2 round under one
key -- is a typical member of it.  §11.38 evaluated the model at n = 256 (48.44 on the
differential axis) and validated it against the exact minimum mean cycle only at
n <= 11 on that axis, where it ran BELOW the truth; §11.39.3 then explained that gap as
an edge-sharing over-count that is O(1) on n = 10..13 and dies above, i.e. it predicted
that the model converges to the exact answer FROM THE SAFE SIDE.

That prediction is testable without any proof, because the exact answer was never
limited by the graph -- only by how it was built.  diff_cycle_mean.py built each edge
set from an exhaustive DDT, 2^(2n) work, which stops at n = 11.  This script builds it
from §11.38.1's carry-pair automaton instead: the out-edges of one difference are the
class sequences with a nonzero path count, enumerated by depth-first search, so the
cost is (out-degree x n) per node and the graph is exact at n = 13, 14, 16 and 17.
(n = 19 is offered under --full but no n = 19 key was completed for v9.5.24: one key
passed 4.6 GB and over half an hour of CPU without finishing.)
(n = 12, 15, 18 are skipped: M is singular there, SINGULAR in diff_cycle_mean.py.)

  §1  THE BUILDER.  The automaton-built graph is checked EDGE FOR EDGE, weight for
      weight, against the exhaustive-DDT graph of diff_cycle_mean.py, and the compact
      Howard used above n = 14 against that file's own Howard.

  §2  THE DIFFERENTIAL LADDER, QUENCHED.  Exact mu per key against the annealed
      lambda* (annealed_moment_ladder.lam_diff) for the SAME key.  FINDING: the ratio
      exact/annealed is not converging to 1 from above.  Its median FALLS at every
      width -- about 1.18 at n = 7, 1.04 at n = 11 -- crosses 1 between n = 11 and 13,
      and is below 1 for EVERY sampled key at n = 14, 16 and 17, at about 0.93 at the
      median.  The fall SLOWS there (0.94 at n = 14, 0.93 at n = 16 and 17), so where it
      settles is not measured.  [v9.5.25: it does not slow.  certified_cycle_ladder.py
      runs 8 keys at n = 17 (0.90) and certifies n = 19 and 20 (0.81, 0.75); what is
      flat is the exact mu/n, not this ratio.  SecurityProofs-9.md §11.41.]  Above n = 11 the annealed model OVER-states the exact
      minimum mean cycle, which is the unsafe direction, and §11.39.3's account of the
      gap is withdrawn: the gap does not close, it inverts.

  §3  THE MECHANISM, as far as it is measured.  The keys the model over-states most
      are the ones whose additive constant has a long run of equal bits or many
      trailing zeros.  In such a run the carry into the next bit is nearly
      deterministic, so a difference living there passes addition almost for free.
      That is a property of the FIXED constant, which a random-graph ensemble with
      independent edges cannot see.  It is the quenched effect itself, observed.

  §4  THE LINEAR AXIS, where exact mu is affordable only to n = 11 here.  [v9.5.25:
      certified_cycle_ladder.py takes it to n = 20, and it crosses between 13 and 14.]  The same
      ratio falls there too, 1.23 at n = 7 to 1.08 at n = 11, still above 1 at the
      median (one key in eight is already below it at n = 10 and 11).

  §5  WHAT THIS CHANGES.  §11.38's n = 256 figures are no longer an estimator of known
      sign.  The per-width margins of the EXACT values over the criteria are
      unchanged, because they were never computed from the model.  But the 36x
      margin at n = 256 rests on a model now observed to OVER-state mu at every
      width from n = 13 to 17, by an amount whose limit is not measured.

Every key is drawn from a FIXED seed, so the verdict is a deterministic computation and
cannot flake: no fresh sample is drawn.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/quenched_exact_ladder.py [--quick] [--full]
      --quick : n <= 14, 8 keys per width               (~4 min on an aarch64 SBC)
      default : n <= 14 at 12 keys, plus n = 16 at 6     (~20 min)
      --full  : adds n = 16 at 12 keys, n = 17 at 6, n = 19 at 3  (hours; n = 19
                needs > 4.6 GB per key and was not completed for v9.5.24)
"""

import argparse
import importlib.util
import math
import os
import random
import sys
from array import array

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
CRIT_DIFF = 4.0 / 3.0
EPS = 1e-9


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


DCM = _load("diff_cycle_mean.py")        # exhaustive-DDT graph, Howard, M table
AML = _load("annealed_moment_ladder.py")  # carry-pair automaton, lam_diff, lam_lin
LCM = _load("lin_cycle_mean.py")          # exact linear mu (LAT rows)
FK = DCM.FK


# ═══════════════════════════════════════════════════════════════════════════
# The graph, built from the automaton rather than from a DDT
# ═══════════════════════════════════════════════════════════════════════════
def build_csr(n, d):
    """Difference graph of the fixed-key v2 round as per-node (targets, weights).

    Edge a -> b iff xdp+(M(a) -> b) > 0 under x -> x + d, weighted -log2 of it --
    exactly diff_cycle_mean.build().  The out-edges of one node are the class
    sequences e (e_0 = 0) with a nonzero carry-pair path count; beta = alpha ^ e.
    The path count is over the n-1 low bits of x, so the weight is
    (n-1) - log2(count)."""
    Ma = FK.m_tab(n)
    T = {k: (v[0][0], v[0][1], v[1][0], v[1][1]) for k, v in AML.NT.items()}
    tb = [[[T[((d >> i) & 1, a, c, e)] for e in (0, 1)] for c in (0, 1)]
          for i in range(n) for a in (0, 1)]
    top = n - 1
    lg = {}
    BS, WS = [array('i')], [array('d')]
    for a in range(1, 1 << n):
        al = Ma[a]
        bs, ws = array('i'), array('d')
        stack = [(0, 0, 1, 0, 0)]
        while stack:
            i, cls, v0, v1, e = stack.pop()
            if i == top:
                c = v0 + v1
                w = lg.get(c)
                if w is None:
                    w = lg[c] = top - math.log2(c)
                bs.append(al ^ e)
                ws.append(w)
                continue
            row = tb[2 * i + ((al >> i) & 1)][cls]
            for ec in (0, 1):
                m00, m01, m10, m11 = row[ec]
                w0 = m00 * v0 + m01 * v1
                w1 = m10 * v0 + m11 * v1
                if w0 or w1:
                    stack.append((i + 1, ec, w0, w1, e | (ec << (i + 1))))
        BS.append(bs)
        WS.append(ws)
    return BS, WS


def howard_csr(BS, WS):
    """diff_cycle_mean.howard() on compact arrays, so n = 16..19 fits in memory.

    No pruning is needed: addition of a constant is a bijection, so a nonzero
    difference never maps to zero and every node 1..2^n-1 keeps an out-edge."""
    N = len(BS)
    nodes = range(1, N)
    pi = array('i', [0]) * N
    pw = array('d', [0.0]) * N
    for v in nodes:
        ws = WS[v]
        j = min(range(len(ws)), key=ws.__getitem__)
        pi[v], pw[v] = BS[v][j], ws[j]
    mu = array('d', [0.0]) * N
    h = array('d', [0.0]) * N
    for _ in range(100000):
        colour = bytearray(N)
        for s in nodes:
            if colour[s]:
                continue
            path = []
            v = s
            while not colour[v]:
                colour[v] = 1
                path.append(v)
                v = pi[v]
            if colour[v] == 1:
                i = path.index(v)
                cyc = path[i:]
                m = sum(pw[u] for u in cyc) / len(cyc)
                for u in cyc:
                    mu[u] = m
                h[v] = 0.0
                for u in reversed(cyc[1:]):
                    h[u] = pw[u] - m + h[pi[u]]
                tail = path[:i]
            else:
                tail = path
            for u in reversed(tail):
                mu[u] = mu[pi[u]]
                h[u] = pw[u] - mu[u] + h[pi[u]]
            for u in path:
                colour[u] = 2
        improved = False
        for v in nodes:
            bmu, bh, bj = mu[v], h[v], -1
            bs, ws = BS[v], WS[v]
            for j in range(len(bs)):
                b = bs[j]
                cmu = mu[b]
                if cmu < bmu - EPS:
                    bmu, bh, bj = cmu, ws[j] - cmu + h[b], j
                elif cmu <= bmu + EPS:
                    ch = ws[j] - cmu + h[b]
                    if ch < bh - EPS:
                        bmu, bh, bj = cmu, ch, j
            if bj >= 0:
                pi[v], pw[v] = bs[bj], ws[bj]
                improved = True
        if not improved:
            return min(mu[v] for v in nodes)
    raise RuntimeError("Howard did not converge")


def keys(n, cnt, seed=4242):
    """A FIXED key stream per width: odd B, the deployed screen applied."""
    rnd = random.Random(seed + n)
    out = []
    while len(out) < cnt:
        d = FK.delta(n, rnd.getrandbits(n) | 1)
        if d not in (0, 1 << (n - 1)):
            out.append(d)
    return out


def tz(d, n):
    t = 0
    while t < n and not (d >> t) & 1:
        t += 1
    return t


def longest_run(d, n):
    best = cur = 0
    prev = None
    for i in range(n):
        b = (d >> i) & 1
        cur = cur + 1 if b == prev else 1
        prev = b
        best = max(best, cur)
    return best


def med(v):
    s = sorted(v)
    return s[len(s) // 2]


# ═══════════════════════════════════════════════════════════════════════════
# §1  the builder
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The builder: automaton enumeration against the exhaustive DDT")
    print("""The exact graph was limited by its CONSTRUCTION, not its size: a DDT is 2^(2n)
work.  Enumerating each node's out-edges as class sequences with a nonzero path count
costs (out-degree x n) instead.  It must reproduce the DDT-built graph exactly.""")
    ok = True
    for n in (8, 10, 11):
        for d in keys(n, 2):
            BS, WS = build_csr(n, d)
            ref = DCM.build(n, d)
            for a in range(1, 1 << n):
                mine = sorted((b, round(w, 9)) for b, w in zip(BS[a], WS[a]))
                theirs = sorted((b, round(w, 9)) for b, w in ref[a])
                if mine != theirs:
                    ok = False
                    break
    check(ok, "every edge and every weight matches diff_cycle_mean.build() at "
              "n = 8, 10, 11, two keys each")
    agree = True
    for n in (11, 13):
        d = keys(n, 1)[0]
        BS, WS = build_csr(n, d)
        adj = [list(zip(BS[a], WS[a])) for a in range(1 << n)]
        a, b = howard_csr(BS, WS), DCM.howard(adj, DCM.prune(adj))
        print("  n = %2d  d = %#x  compact Howard %.9f   reference %.9f" % (n, d, a, b))
        agree = agree and abs(a - b) < 1e-9
    check(agree, "the compact Howard agrees with diff_cycle_mean.howard() to 1e-9")


# ═══════════════════════════════════════════════════════════════════════════
# §2  the differential ladder, quenched
# ═══════════════════════════════════════════════════════════════════════════
def ladder(widths):
    rows = {}
    for n, cnt in widths:
        recs = []
        for d in keys(n, cnt):
            BS, WS = build_csr(n, d)
            mu = howard_csr(BS, WS)
            lo, _, _ = AML.lam_diff(n, d)
            recs.append((d, mu, lo))
        rows[n] = recs
        r = [m / a for _, m, a in recs]
        print("  %3d %4d %8.4f %7.4f %8.4f   %6.3f %6.3f %6.3f   %5.2f   %7.4f %5.2f"
              % (n, len(recs), med([m for _, m, _ in recs]),
                 med([m for _, m, _ in recs]) / n, med([a for _, _, a in recs]),
                 min(r), med(r), max(r), sum(x < 1 for x in r) / len(r),
                 min(m for _, m, _ in recs),
                 sum(m < CRIT_DIFF for _, m, _ in recs) / len(recs)), flush=True)
    return rows


def section_2(quick, full):
    rule("§2  The differential ladder, quenched: exact mu against the model, per key")
    print("""Same key, two numbers: the EXACT minimum mean cycle of the fixed round's
difference graph, and the annealed lambda* of §11.38 (the lattice lower end, which the
bracket closes on).  §11.39.3 predicted the ratio would approach 1 from ABOVE.
""")
    if quick:
        widths = [(7, 8), (8, 8), (10, 8), (11, 8), (13, 8), (14, 8)]
    else:
        widths = [(7, 12), (8, 12), (10, 12), (11, 12), (13, 12), (14, 12), (16, 6)]
        if full:
            widths[-1] = (16, 12)
            widths += [(17, 6), (19, 3)]
    print("  %3s %4s %8s %7s %8s   %6s %6s %6s   %5s   %7s %5s"
          % ("n", "keys", "med mu", "mu/n", "med ann", "r min", "r med", "r max",
             "r<1", "min mu", "<4/3"))
    rows = ladder(widths)

    def mr(n):
        return med([m / a for _, m, a in rows[n]])

    ns = sorted(rows)
    check(all(mr(n) > 1.0 for n in ns if n <= 11),
          "at n <= 11 the median ratio exceeds 1 -- the model runs LOW there, as "
          "§11.38 recorded")
    check(all(m < a for _, m, a in rows[14]),
          "at n = 14 the exact mu is BELOW the model for every sampled key "
          "(%d of %d)" % (sum(m < a for _, m, a in rows[14]), len(rows[14])))
    check(mr(14) < 1.0 and mr(7) - mr(14) > 0.15,
          "the median ratio falls from %.3f at n = 7 to %.3f at n = 14: it crosses 1, "
          "it does not converge to it from above" % (mr(7), mr(14)))
    lo_half = [mr(n) for n in ns if n <= 11]
    hi_half = [mr(n) for n in ns if n >= 13]
    check(min(lo_half) > max(hi_half),
          "every width from n = 13 on has a lower median ratio than every width "
          "up to n = 11 (%.3f < %.3f)" % (max(hi_half), min(lo_half)))
    check(all(min(m for _, m, _ in rows[n]) < CRIT_DIFF for n in ns),
          "at EVERY width some sampled key has exact mu below 4/3 -- the criterion "
          "is met by the median, not by every key")
    if 16 in rows:
        check(all(m < a for _, m, a in rows[16]),
              "at n = 16 too, exact mu is below the model for every sampled key "
              "(%d of %d; median ratio %.3f) -- scored only when n = 16 runs"
              % (sum(m < a for _, m, a in rows[16]), len(rows[16]), mr(16)))
    else:
        print("\n  n = 16 not run (--quick): not scored")
    for n in (17, 19):
        if n in rows:
            print("  n = %d: median ratio %.3f over %d keys (--full only, not gated)"
                  % (n, mr(n), len(rows[n])))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
# §3  the mechanism
# ═══════════════════════════════════════════════════════════════════════════
def section_3(rows):
    rule("§3  Which keys the model over-states: runs in the additive constant")
    print("""In a run of equal bits of d, the carry into the next bit is nearly
deterministic -- Pr[c_i = 1] = (d mod 2^i)/2^i, which a run of ones below i pushes
toward 1 -- so a difference living at the top of a run passes addition at a cost of
about 2^-run rather than one bit.  That is a property of ONE constant.  An annealed
ensemble with independent edges reproduces the weight distribution and not where the
cheap edges sit relative to each other, so it cannot see a cheap CYCLE built out of a
run.  If that is the mechanism, the keys the model over-states most are the ones with
long runs or many trailing zeros.
""")
    pooled = []
    for n in sorted(rows):
        if n < 10:
            continue
        for d, m, a in rows[n]:
            pooled.append((m / a, longest_run(d, n), tz(d, n)))
    if not pooled:
        print("  no rows at n >= 10; section not scored")
        return
    srt = sorted(pooled)
    q = max(1, len(srt) // 4)
    low, high = srt[:q], srt[-q:]

    def avg(v):
        return sum(v) / len(v)

    print("  pooled over n >= 10: %d keys" % len(pooled))
    print("  lowest-ratio quarter : mean ratio %.3f  mean longest run %.2f  mean tz %.2f"
          % (avg([r for r, _, _ in low]), avg([u for _, u, _ in low]),
             avg([t for _, _, t in low])))
    print("  highest-ratio quarter: mean ratio %.3f  mean longest run %.2f  mean tz %.2f"
          % (avg([r for r, _, _ in high]), avg([u for _, u, _ in high]),
             avg([t for _, _, t in high])))
    check(avg([u + t for _, u, t in low]) > avg([u + t for _, u, t in high]),
          "the keys the model over-states most have longer runs and more trailing "
          "zeros in d than the keys it under-states most")
    print("""
  The same mechanism at the DEPLOYED width, where no exact mu exists.  For six fixed
  n = 256 keys: the cheapest two-round trail whose difference is ONE bit of the round
  input, passed through each addition unchanged (beta = alpha, so every active bit
  costs only -log2 Pr[c_i = d_i]).  Exact weights, from the automaton:""")
    n = 256
    m = (1 << n) - 1

    def Mn(a):
        return (a ^ ((a << 1) | (a >> (n - 1))) ^ ((a >> 1) | (a << (n - 1)))) & m

    found = []
    for d in keys(n, 6):
        best = (math.inf, None)
        for p in range(n):
            al = Mn(1 << p)
            p1 = AML.xdp_auto(n, d, al, al)
            if not p1:
                continue
            al2 = Mn(al)
            p2 = AML.xdp_auto(n, d, al2, al2)
            if not p2:
                continue
            w = -math.log2(p1) - math.log2(p2)
            if w < best[0]:
                best = (w, p)
        found.append((best[0], longest_run(d, n)))
        print("    longest run in d %2d   cheapest such trail %.4f bits (input bit %d)"
              % (longest_run(d, n), best[0], best[1]))
    check(max(w for w, _ in found) < 0.5,
          "every one of the six n = 256 keys has an explicit two-round trail of weight "
          "below 0.5 bits (worst %.3f)" % max(w for w, _ in found))
    check(min(found)[1] == max(r for _, r in found),
          "and the cheapest of them belongs to the key with the longest run")
    print("""  That says nothing about mu, which is a CYCLE statement and is all the trail
  criterion asks about; a cheap transient is old news (§11.35's window).  What it shows is
  where the cheap edges are at n = 256: on the runs of one fixed constant.

  This is a CORRELATION over a few dozen keys, not a derivation, and it is offered as
  the measured lead rather than as the account: it is consistent with the over-statement
  being a quenched effect of the run structure of one fixed constant, and it is not yet
  shown to be the whole of it.""")


# ═══════════════════════════════════════════════════════════════════════════
# §4  the linear axis
# ═══════════════════════════════════════════════════════════════════════════
def section_4(quick):
    rule("§4  The linear axis: the same ratio, to n = 11")
    print("""Exact linear mu needs a LAT row per mask -- (n+1)*4^n, lin_cycle_mean.py --
so it stops at n = 11 here.  Against the lower end of §11.38.4's even-moment bracket:
""")
    widths = [(7, 6), (8, 6), (10, 4)] if quick else [(7, 8), (8, 8), (10, 8), (11, 8)]
    meds = {}
    print("  %3s %4s %8s %8s   %6s %6s %6s   %5s" % ("n", "keys", "med mu", "med lo",
                                                     "r min", "r med", "r max", "r<1"))
    for n, cnt in widths:
        recs = []
        for d in keys(n, cnt):
            m = LCM.s_lin_v2(n, d)
            lo, _, _ = AML.lam_lin(n, d)
            recs.append((m, lo))
        r = [m / a for m, a in recs]
        meds[n] = med(r)
        print("  %3d %4d %8.4f %8.4f   %6.3f %6.3f %6.3f   %5.2f"
              % (n, len(recs), med([m for m, _ in recs]), med([a for _, a in recs]),
                 min(r), med(r), max(r), sum(x < 1 for x in r) / len(r)), flush=True)
    top = max(meds)
    check(meds[top] < meds[7] - 0.08,
          "the linear median ratio falls too, %.3f at n = 7 to %.3f at n = %d"
          % (meds[7], meds[top], top))
    check(meds[top] > 1.0,
          "but at n = %d it is still above 1 at the median -- the linear axis has not "
          "been observed to cross" % top)


# ═══════════════════════════════════════════════════════════════════════════
# §5  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_5(rows):
    rule("§5  What this changes for #257")
    print("  exact medians this run:  " + "   ".join(
        "n=%d %.3f (mu/n %.3f)" % (n, med([m for _, m, _ in rows[n]]),
                                   med([m for _, m, _ in rows[n]]) / n)
        for n in sorted(rows)))
    print("""WITHDRAWN.  §11.39.3's account of the validation gap.  It said the model ran
low at n <= 13 because of an edge-sharing over-count that is O(1) there and dies above,
so the model converges to the exact answer from the safe side.  The over-count
arithmetic stands; the convergence does not.  Measured on the fixed round, the gap
closes, crosses zero between n = 11 and 13, and opens again the other way.

DOWNGRADED.  §11.38's n = 256 figures (48.44 differential, 22.40 linear).  They were an
exactly-evaluated estimator whose finite-size error had been OBSERVED to be
conservative.  It is not: on the differential axis the error changes sign between
n = 11 and 13 and stays on the UNSAFE side at every width computed above that, about
7% at the median, with the fall slowing but its limit unmeasured.
[v9.5.25: it is not slowing -- 0.75 by n = 20.  SecurityProofs-9.md §11.41.]  An estimator whose
bias has changed sign, and whose limit is not known, cannot be extrapolated 240 widths
with a sign attached, so the n = 256 margin is no longer supported by anything
measured.  It is not LOST either: losing the 4/3 criterion would take the ratio down
to about 1/36, against 0.93 at the widest width measured.  What is lost is the claim
that the margin is measured.  The linear axis has not crossed, but falls the same way.

UNCHANGED.  Every EXACT number: the per-width medians above clear 4/3 from n = 8 on.
What the new widths add is that the rise is not monotone in the median at this sample
size (n = 13 does not clear n = 11), and that mu/n stays at 0.14-0.16 from n = 13 on --
consistent with linear growth, but the slope that would carry it to n = 256 is exactly
what the falling ratio says the model no longer supplies.

OWED.  Still a QUENCHED argument -- now with a measured reason why the annealed one
cannot stand in for it, and a measured lead (§3) on what one would have to control.
And still the linear hull.

No rating moves, and none could: every row this touches is demo-only on other axes
(#243, #244, #248), and the production-track rows left the scope of a trail bound in
§11.36.8.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    section_1()
    rows = section_2(a.quick, a.full)
    section_3(rows)
    section_4(a.quick)
    section_5(rows)
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
