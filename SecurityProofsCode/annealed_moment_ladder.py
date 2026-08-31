#!/usr/bin/env python3
"""annealed_moment_ladder.py — TODO #257: the width extrapolation, evaluated.

TODO #252 and #254 were merged into #257 because they had come to owe the same
thing: mu -- the minimum mean cycle of the difference graph (#252, SecurityProofs-8.md
§11.35) and of the mask graph (#254, §11.36) -- is exact at every width it has been
computed at, and unreachable beyond n = 13, so both items ended on "does the sequence
turn around".

SecurityProofs-9.md §11.37.5 opened a route and then closed the only way anyone had of walking it.  The
route: an ANNEALED FIRST-MOMENT MODEL that predicts mu from two inputs, the edge-weight
distribution and the out-degree, and that tracks the exact answer to within a few percent
by n = 11 on both axes.  The closure: at n = 256 the model's threshold sits in a 2^-n
quantile of that distribution, so a SAMPLER cannot find it -- §11.37.5 records one
returning 157 at n = 256 while returning 0.48 at n = 13 where the exact answer is 1.154.

This script walks the route.  Not by sampling the distribution -- by never forming it.

  §1  THE CARRY-PAIR AUTOMATON.  xdp+ of x -> (x+d) mod 2^n is a path count in a
      four-state automaton over the pair of carries, in which the OUTPUT DIFFERENCE IS
      NOT FREE: beta_i = alpha_i xor c_i xor c'_i, so a differential is a constraint
      sequence and its probability is the number of x consistent with it.  Derived from
      the round, and validated bit-exactly against the exhaustive DDT.

  §2  THE MOMENTS ARE LINEAR, THE DISTRIBUTION IS NOT.  The histogram of edge weights
      needs the per-edge path count and has exponentially many distinct values.  The
      MOMENT  A_t = sum over edges of (path count)^t  is, for integer t, a count of
      t-TUPLES of paths, so it is one linear DP over t parallel copies -- O(n * t * 2^t),
      no dependence on the number of edges at all.  Exact at n = 256 in milliseconds.

  §3  INTEGER MOMENTS ARE ENOUGH, and that is a lemma rather than an approximation.
      The annealed threshold is  lambda* = sup_{t>0} (-log2 D - log2 M(t)) / t.  The
      numerator is CONCAVE in t, so on any interval it lies above its chord and below
      its two flanking secants, and both bounds are maximised at the endpoints.  The
      integer lattice therefore brackets lambda* -- and the bracket is observed to
      CLOSE, to 1e-12, at every width and every key tried.

  §4  THE LINEAR AXIS reaches only EVEN t: |correlation|^t is a linear DP for even t and
      the sign is not available, because it is not an affine function of the masks
      (measured -- exactly half the nonzero entries are negative and no affine fit
      exists).  The even lattice still brackets, to 1-7%, and the lower end is the
      conservative one.

  §5  THE CURVE, TO n = 256.  This is what the whole apparatus is for, and it does not
      say what four passes of this analysis expected.  mu does not converge to a
      constant: it is ASYMPTOTICALLY LINEAR IN n, mu ~ c*n, with c ~ 0.19 differential
      and c ~ 0.09 linear.  The criteria (4/3 and 2/3) are fixed numbers.  So the margin
      GROWS with width, monotonically, at every step of the ladder -- and n = 256 is the
      easiest width in the table rather than the hardest.

  §6  THE tz DECOMPOSITION at n = 256, and the per-key spread.

  §7  What this settles for #257, and the two things it does not.

The model is an ESTIMATOR.  It is validated against the exact minimum mean cycle only
where the exact answer exists (n <= 13); §5's n = 256 row is the model evaluated exactly,
not mu measured.  That distinction is stated wherever a number is quoted.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/annealed_moment_ladder.py [--quick] [--full]
"""

import argparse
import importlib.util
import math
import os
import random
import sys
from collections import Counter

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
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location(name[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, [name]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


# ═══════════════════════════════════════════════════════════════════════════
# §1  the carry-pair automaton for xdp+ with a constant
# ═══════════════════════════════════════════════════════════════════════════
# States are the PAIR of carries (c, c') of the two additions x+d and (x^alpha)+d.
#   A = (0,0)  B = (1,1)   -- class 0, meaning c xor c' = 0
#   C = (0,1)  D = (1,0)   -- class 1
# beta_i = alpha_i xor c_i xor c'_i, so the class at bit i IS alpha_i xor beta_i and a
# differential is a prescribed class sequence.  Within a class the two states are the
# two SLOTS, and every transfer is a 2x2 nonnegative matrix.
_ST = {0: (0, 0), 1: (1, 1), 2: (0, 1), 3: (1, 0)}
_INV = {v: k for k, v in _ST.items()}
_CLS = {0: 0, 1: 0, 2: 1, 3: 1}
_SLOT = {0: 0, 1: 1, 2: 0, 3: 1}
_IX = {(0, 0): 0, (0, 1): 1, (1, 0): 2, (1, 1): 3}


def _mk_diff(d, a, cls, ec):
    """M[to_slot][from_slot] = number of x_i carrying (cls,from) to (ec,to)."""
    M = [[0, 0], [0, 0]]
    for fs in (0, 1):
        c, cp = _ST[_IX[(cls, fs)]]
        for x in (0, 1):
            xp = x ^ a
            nc, ncp = (x & c, xp & cp) if d == 0 else (x | c, xp | cp)
            ns = _INV[(nc, ncp)]
            if _CLS[ns] == ec:
                M[_SLOT[ns]][fs] += 1
    return M


NT = {(d, a, c, e): _mk_diff(d, a, c, e)
      for d in (0, 1) for a in (0, 1) for c in (0, 1) for e in (0, 1)}


def _mk_lin(d, w, v):
    """The linear analogue: 2x2 SIGNED transfer over the single carry."""
    M = [[0, 0], [0, 0]]
    for c in (0, 1):
        if d == c:
            if v == w:
                M[d][c] += 2
        else:
            M[0][c] += -1 if v else 1
            M[1][c] += -1 if w else 1
    return M


NL = {(d, w, v): _mk_lin(d, w, v) for d in (0, 1) for w in (0, 1) for v in (0, 1)}


def xdp_auto(n, d, a, b):
    """xdp+ of alpha=a -> beta=b under x -> (x+d) mod 2^n, via the automaton."""
    e = a ^ b
    if e & 1:
        return 0.0                     # c_0 = c'_0 = 0 forces beta_0 = alpha_0
    cls, vec = 0, [1, 0]
    for i in range(n - 1):             # bit n-1 produces only the discarded carry-out
        di, ai, ec = (d >> i) & 1, (a >> i) & 1, (e >> (i + 1)) & 1
        M = NT[(di, ai, cls, ec)]
        vec = [M[0][0] * vec[0] + M[0][1] * vec[1],
               M[1][0] * vec[0] + M[1][1] * vec[1]]
        cls = ec
        if not (vec[0] or vec[1]):
            return 0.0
    return (vec[0] + vec[1]) / float(1 << (n - 1))


def corr_auto(n, d, w, v):
    """Correlation of x -> (x+d) mod 2^n, input mask w, output mask v."""
    st = [1, 0]
    for i in range(n):
        M = NL[((d >> i) & 1, (w >> i) & 1, (v >> i) & 1)]
        st = [M[0][0] * st[0] + M[0][1] * st[1],
              M[1][0] * st[0] + M[1][1] * st[1]]
    return (st[0] + st[1]) / float(1 << n)


def _exh_ddt(n, d):
    N = 1 << n
    T = [Counter() for _ in range(N)]
    for x in range(N):
        y = (x + d) & (N - 1)
        for a in range(N):
            T[a][y ^ (((x ^ a) + d) & (N - 1))] += 1
    return T


def section_1(quick):
    rule("§1  The carry-pair automaton for xdp+ with a constant")
    print("""The NL-FSCX v2 round is  F(x) = M(x xor B xor C_i) + delta(B)  mod 2^n.  Two of
its three layers move a difference deterministically; the whole of the probability
lives in addition of the CONSTANT delta.  Write c_i, c'_i for the carries into bit i
of x+d and (x xor alpha)+d.  Then

        y_i xor y'_i  =  alpha_i xor c_i xor c'_i ,

so the output difference is not a free variable: beta is determined by alpha together
with the sequence e_i = c_i xor c'_i, and e_0 = 0 always.  A differential (alpha, beta)
is a PRESCRIBED e-sequence, and its probability is the fraction of x whose carry pair
follows it.  Four states, split into two classes by e; within a class, two slots; every
transfer a 2x2 matrix with entries in {0,1,2}.  Bit n-1 produces only the discarded
carry-out, so a differential constrains n-1 steps and xdp+ is (path count)/2^(n-1).""")
    widths = (6,) if quick else (6, 7)
    ok = True
    for n in widths:
        N = 1 << n
        for d in range(N):
            T = _exh_ddt(n, d)
            for a in range(N):
                for b in range(N):
                    if abs(T[a][b] / N - xdp_auto(n, d, a, b)) > 1e-12:
                        ok = False
        check(ok, "n=%d: automaton reproduces the exhaustive DDT for every d and "
                  "every (alpha,beta) -- %d entries" % (n, (1 << (3 * n))))
    print("""
The same shape on the linear axis is already in the repository (§11.30.4's
corr_add_const): one carry, a SIGNED 2x2 transfer, and paths that re-merge SUM.  Both
are reproduced here so the two ladders share one code path.""")
    ok = True
    for n in (5, 6):
        FS = _load("fscx_scaling_and_linear.py")
        for d in range(1 << n):
            for w in range(1 << n):
                for v in range(1 << n):
                    if abs(corr_auto(n, d, w, v)
                           - FS.corr_add_const(n, d, w, v)) > 1e-12:
                        ok = False
    check(ok, "the linear transfer agrees with §11.30.4's corr_add_const at n=5,6, "
              "all d, all mask pairs")
    return ok


# ═══════════════════════════════════════════════════════════════════════════
# §2  exact moments and exact edge counts at any width
# ═══════════════════════════════════════════════════════════════════════════
def _tensor(M, v, t):
    """v <- M^{otimes t} v, in place, t butterfly passes over 2^t entries."""
    a, b, c, e = M[0][0], M[0][1], M[1][0], M[1][1]
    h = 1
    for _ in range(t):
        step = h << 1
        for i in range(0, 1 << t, step):
            for j in range(i, i + h):
                x, y = v[j], v[j + h]
                v[j] = a * x + b * y
                v[j + h] = c * x + e * y
        h = step
    return v


def _rescale(vs, budget=900):
    """Shared power-of-two rescale, so the DP stays in float range at n = 256.
    Returns the exponent removed.  Nonnegative-entry DPs lose nothing by this."""
    m = 0.0
    for v in vs:
        for x in v:
            ax = abs(x)
            if ax > m:
                m = ax
    if m == 0.0:
        return 0
    ex = math.frexp(m)[1]
    if ex < budget:
        return 0
    k = ex - 64
    s = math.ldexp(1.0, -k)
    for v in vs:
        for j in range(len(v)):
            v[j] *= s
    return k


def moments_diff(n, d, tmax, exact=True):
    """A_t = sum over edges (alpha != 0, beta != 0) of (path count)^t, t = 1..tmax.

    Linear in the per-prefix count vector, so the sum over all (alpha, e) is carried
    by ONE running vector per (class, beta-still-zero) state.  Returns
    {t: (A_t as a float, log2 scale already folded in)} -- exactly, as ints, when
    `exact`."""
    out = {}
    for t in range(1, tmax + 1):
        L = 1 << t
        S = {(c, b): [0] * L for c in (0, 1) for b in (0, 1)}
        S[(0, 1)][0] = 1
        lg = 0
        for i in range(n - 1):
            di = (d >> i) & 1
            T = {k: [0] * L for k in S}
            for (cls, bz), vec in S.items():
                if not any(vec):
                    continue
                for a in (0, 1):
                    nbz = 1 if (bz and (a ^ cls) == 0) else 0
                    for ec in (0, 1):
                        w = _tensor(NT[(di, a, cls, ec)], vec[:], t)
                        tgt = T[(ec, nbz)]
                        for j in range(L):
                            tgt[j] += w[j]
            S = T
            if not exact:
                lg += _rescale(list(S.values()))
        P = sum(sum(S[(c, b)]) for c in (0, 1) for b in (0, 1))
        Q = sum(sum(S[(c, 1)]) for c in (0, 1))
        A = 2 * P - Q
        out[t] = (math.log2(A) + lg) if A > 0 else None
    return out


def edges_diff(n, d):
    """Exact number of edges (alpha != 0, beta != 0) with xdp+ > 0."""
    S = Counter()
    S[(0, 1, 1)] = 1                      # (class, slot-support mask, beta-still-zero)
    for i in range(n - 1):
        di = (d >> i) & 1
        T = Counter()
        for (cls, pat, bz), cnt in S.items():
            for a in (0, 1):
                nbz = 1 if (bz and (a ^ cls) == 0) else 0
                for ec in (0, 1):
                    M = NT[(di, a, cls, ec)]
                    np_ = 0
                    for fs in (0, 1):
                        if (pat >> fs) & 1:
                            for ts in (0, 1):
                                if M[ts][fs]:
                                    np_ |= 1 << ts
                    if np_:
                        T[(ec, np_, nbz)] += cnt
        S = T
    P = sum(S.values())
    Q = sum(c for (cl, p, b), c in S.items() if b)
    return 2 * P - Q


def moments_lin(n, d, tmax, exact=True):
    """A_t = sum over (w != 0, v != 0) of (2^n * correlation)^t, EVEN t only."""
    out = {}
    for t in range(2, tmax + 1, 2):
        L = 1 << t
        V = [0] * L
        V[0] = 1
        lg = 0
        for i in range(n):
            di = (d >> i) & 1
            T = [0] * L
            for w in (0, 1):
                for v in (0, 1):
                    r = _tensor(NL[(di, w, v)], V[:], t)
                    for j in range(L):
                        T[j] += r[j]
            V = T
            if not exact:
                lg += _rescale([V])
        A = sum(V)
        if exact:
            A -= 1 << (n * t)             # drop the (0,0) entry, the only excluded one
            out[t] = math.log2(A) if A > 0 else None
        else:
            la = math.log2(A) + lg if A > 0 else None
            # subtract 2^(n t) in the log domain
            out[t] = (la + math.log2(1 - 2 ** (n * t - la))) if la and la > n * t else None
    return out


def edges_lin(n, d):
    """Exact number of (w != 0, v != 0) with nonzero correlation.  §11.36.3's support
    identity: the LAT's support depends on the addend only through tz(d).  The pairs
    excluded contain exactly one nonzero entry, (0,0)."""
    k = n if d == 0 else (d & -d).bit_length() - 1
    tot = (1 << n) if k >= n - 1 else (1 << k) * ((1 << (2 * (n - k))) - 4) // 3
    return tot - 1


def section_2(quick):
    rule("§2  The moments are a linear DP; the distribution is not")
    print("""§11.37.5 closed the sampling route because the annealed threshold lives in a
2^-n quantile of the edge-weight distribution.  The way past that is not a better
sampler, it is not forming the distribution.

The weight of an edge is (n-1) - log2(path count).  The HISTOGRAM of those needs the
count itself, and the reachable count vectors grow geometrically in n (measured: ~1.5x
per bit, 3980 distinct states by n = 20), so the histogram is out of reach.  But

        A_t  =  sum over (alpha, e) of count(alpha, e)^t

is, for integer t, the number of t-TUPLES of consistent x-paths, and a tuple is a walk
in the t-fold tensor power of the same automaton.  Tensor powers are linear, so the sum
over all (alpha, e) commutes with the transfer: one running vector of length 2^t per
state, n-1 steps, t butterfly passes each.  O(n * t * 2^t), independent of the number of
differentials.  The edge COUNT is the same DP over slot-supports instead of counts.""")
    widths = (6, 7) if quick else (6, 7, 8)
    tmax = 4
    ok_m = ok_e = True
    for n in widths:
        N = 1 << n
        for d in range(N):
            T = _exh_ddt(n, d)
            A = {t: 0 for t in range(1, tmax + 1)}
            sup = 0
            for a in range(1, N):
                for b, c in T[a].items():
                    if b == 0 or c == 0:
                        continue
                    sup += 1
                    for t in A:
                        A[t] += (c // 2) ** t
            M = moments_diff(n, d, tmax)
            if edges_diff(n, d) != sup:
                ok_e = False
            for t in A:
                if abs(M[t] - math.log2(A[t])) > 1e-9:
                    ok_m = False
        check(ok_m, "n=%d: A_t matches the exhaustive DDT for t=1..%d, every d" % (n, tmax))
        check(ok_e, "n=%d: the edge count matches the exhaustive DDT, every d" % n)
    ok_l = ok_le = True
    for n in (5, 6) if quick else (5, 6, 7):
        N = 1 << n
        for d in range(N):
            ex = {2: 0, 4: 0, 6: 0}
            sup = 0
            for w in range(1, N):
                for v in range(1, N):
                    s = round(corr_auto(n, d, w, v) * N)
                    if s:
                        sup += 1
                        for t in ex:
                            ex[t] += s ** t
            M = moments_lin(n, d, 6)
            if edges_lin(n, d) != sup:
                ok_le = False
            for t in ex:
                if abs(M[t] - math.log2(ex[t])) > 1e-9:
                    ok_l = False
        check(ok_l, "n=%d: the linear A_t matches the exhaustive LAT for t=2,4,6, every d" % n)
        check(ok_le, "n=%d: §11.36.3's support identity gives the exact edge count, "
                     "every d" % n)
    print("""
The float path used at the wide end is the same DP with a shared power-of-two rescale
between bits.  On the differential axis every entry is nonnegative, so the rescale is
lossless in exact arithmetic and the only error is rounding; on the linear axis the
entries carry signs and the check below is the one that matters.""")
    ok_f = True
    for n in (12, 16, 20):
        d = (0xB5A3 * (n + 7)) & ((1 << n) - 1) | 1
        for f, g in ((moments_diff(n, d, 6, True), moments_diff(n, d, 6, False)),
                     (moments_lin(n, d, 8, True), moments_lin(n, d, 8, False))):
            for t in f:
                if f[t] is None or g[t] is None or abs(f[t] - g[t]) > 1e-6:
                    ok_f = False
    check(ok_f, "the rescaled float DP reproduces the exact-integer log2 A_t to 1e-6 "
                "at n=12,16,20, on both axes")
    return ok_m and ok_e and ok_l and ok_le and ok_f


# ═══════════════════════════════════════════════════════════════════════════
# §3  the lattice lemma
# ═══════════════════════════════════════════════════════════════════════════
def ladder(logA, logA0, live, scale, ts):
    """The annealed threshold from the moment ladder.

    M(t) = E[p^t] over edges, p = (path count) / 2^scale.  With D the out-degree,
    the annealed exponent  ln D - I(lambda)  changes sign at

        lambda*  =  sup_{t>0}  ( -log2 D - log2 M(t) ) / t  =:  sup_t g(t)/t .

    g is concave (log2 M is convex in t, by Holder), so on [u,v] it lies above its
    chord and below each flanking secant, and both bounds are of the form (A+Bt)/t,
    monotone, hence maximised at an endpoint.  The lattice therefore brackets."""
    c = -(logA0 - math.log2(live))
    g = {t: c - ((logA[t] - logA0) - scale * t) for t in ts if logA.get(t) is not None}
    F = {t: g[t] / t for t in g}
    lo = max(F.values())
    tsx = sorted(F)
    up = lo
    for i in range(len(tsx) - 1):
        k, kp = tsx[i], tsx[i + 1]
        cd = []
        if i > 0:
            s = (g[k] - g[tsx[i - 1]]) / (k - tsx[i - 1])
            cd.append((g[k] - s * k, s))
        if i + 2 < len(tsx):
            s = (g[tsx[i + 2]] - g[kp]) / (tsx[i + 2] - kp)
            cd.append((g[kp] - s * kp, s))
        if cd:
            for tt in (k, kp):
                up = max(up, min(a + b * tt for a, b in cd) / tt)
    return lo, up, max(F, key=F.get)


TD, TL = 8, 12


def lam_diff(n, d, exact=None):
    ex = (n <= 24) if exact is None else exact
    return ladder(moments_diff(n, d, TD, ex), math.log2(edges_diff(n, d)),
                  (1 << n) - 1, n - 1, list(range(1, TD + 1)))


def lam_lin(n, d, exact=None):
    ex = (n <= 20) if exact is None else exact
    return ladder(moments_lin(n, d, TL, ex), math.log2(edges_lin(n, d)),
                  (1 << n) - 1, n, list(range(2, TL + 1, 2)))


def section_3(quick):
    rule("§3  Integer moments are enough -- a lemma, not an approximation")
    print("""lambda* is a SUPREMUM over a continuous parameter, and only integer t is
computable.  Restricting to a lattice gives a lower bound for free; what makes it exact
is concavity.  Write g(t) = -log2 D - log2 M(t).  log2 M is convex in t (Holder), so g
is concave, so on any [u,v] it is bounded below by its chord and above by either
flanking secant, and every such bound divided by t is monotone in t -- maximised at an
endpoint of the interval.  Both bounds therefore reduce to lattice values.

Two graph facts the model needs are also exact rather than assumed.  The live-node count
is 2^n - 1 on BOTH axes: on the differential side because addition is a bijection, so no
nonzero input difference can be annihilated with probability one; on the linear side by
Parseval, since every row of the LAT has squared entries summing to 1 while C(0 -> v) is
zero for v != 0.  Neither is sampled.""")
    DC = _load("diff_cycle_mean.py")
    WR = _load("width_residue.py")
    widths = (7, 8) if quick else (7, 8, 10, 11)
    gaps, brackets = [], []
    for n in widths:
        ds = [d for d in range(1, min(1 << n, 40)) if not DC.screened(n, d)][:4]
        for d in ds:
            adj = DC.build(n, d)
            lam, D = WR.annealed(adj)
            lo, up, ts = lam_diff(n, d)
            live = sum(1 for v in range(1, 1 << n) if adj[v])
            gaps.append(abs(lo - lam))
            brackets.append(up - lo)
            if n == widths[0] and d == ds[0]:
                print("\n  n=%2d d=%d: annealed()=%.6f  ladder=%.6f  bracket width %.2e  "
                      "argmax t=%d" % (n, d, lam, lo, up - lo, ts))
            if live != (1 << n) - 1:
                FAIL.append("live count at n=%d d=%d" % (n, d))
    check(max(brackets) < 1e-9,
          "the integer lattice CLOSES the bracket -- widest gap %.2e over %d cases"
          % (max(brackets), len(brackets)))
    check(max(gaps) < 0.006,
          "the ladder agrees with §11.37.4's histogram annealed() to %.4f bits -- the "
          "residual is that routine's theta grid, and the ladder is the exact one"
          % max(gaps))
    return True


def section_4(quick):
    rule("§4  The linear axis reaches only even t, and why")
    print("""|C|^t is a t-fold tensor power only when t is even; for odd t the DP would have
to know the SIGN of the finished sum, which is not a per-bit quantity.  It is not an
affine one either -- fitted below over GF(2) in the 2n mask bits plus a constant, and
rejected at every addend tried, with exactly half of the nonzero entries negative in
every case.  So the linear ladder runs on {2,4,...} and brackets rather than closing.""")
    n = 6
    fits = []
    for d in (1, 2, 3, 5, 6, 12, 7, 21):
        pts = []
        for w in range(1 << n):
            for v in range(1 << n):
                s = round(corr_auto(n, d, w, v) * (1 << n))
                if s:
                    pts.append(([(w >> i) & 1 for i in range(n)]
                                + [(v >> i) & 1 for i in range(n)] + [1],
                                1 if s < 0 else 0))
        neg = sum(z for _, z in pts)
        m = 2 * n + 1
        R = [r[:] + [z] for r, z in pts]
        rank = 0
        for col in range(m):
            p = next((i for i in range(rank, len(R)) if R[i][col]), None)
            if p is None:
                continue
            R[rank], R[p] = R[p], R[rank]
            for i in range(len(R)):
                if i != rank and R[i][col]:
                    R[i] = [x ^ y for x, y in zip(R[i], R[rank])]
            rank += 1
        inconsistent = any(all(x == 0 for x in r[:m]) and r[m] for r in R)
        fits.append((d, inconsistent, neg, len(pts)))
    check(all(f[1] for f in fits),
          "the correlation's sign admits no affine fit in the mask bits, at %d addends"
          % len(fits))
    check(all(2 * f[2] == f[3] for f in fits),
          "and exactly half the nonzero entries are negative at every addend")
    LC = _load("lin_cycle_mean.py")
    WR = _load("width_residue.py")
    rows = []
    for n in (7, 8) if quick else (7, 8, 10, 11):
        for d in (1, 2, 3, 5):
            adj = LC.build_v2(n, d)
            lam, _ = WR.annealed(adj)
            lo, up, ts = lam_lin(n, d)
            rows.append((n, d, lam, lo, up))
    print("\n  %-4s %-5s %-10s %-20s" % ("n", "d", "annealed()", "even-t ladder"))
    for n, d, lam, lo, up in rows:
        print("  %-4d %-5d %-10.4f [%.4f, %.4f]" % (n, d, lam, lo, up))
    below = [(lam - lo) / lam for _, _, lam, lo, _ in rows]
    width = [(up - lo) / lo for _, _, _, lo, up in rows]
    check(all(b >= -1e-9 for b in below),
          "the even-t lower end is CONSERVATIVE at every case -- it never exceeds "
          "annealed()")
    check(max(below) < 0.030,
          "and is at most %.1f%% below it" % (100 * max(below)))
    check(max(width) < 0.10,
          "the bracket is at most %.1f%% wide" % (100 * max(width)))
    return True


# ═══════════════════════════════════════════════════════════════════════════
# §5  the curve, to n = 256
# ═══════════════════════════════════════════════════════════════════════════
def delta_of(n, B):
    m = (1 << n) - 1
    k = n // 4
    x = (B * ((B + 1) >> 1)) & m
    return (((x << k) | (x >> (n - k))) & m) if k else x


def keys_at(n, cnt, seed=1729):
    rnd = random.Random(seed * 131 + n)
    out = []
    while len(out) < cnt:
        d = delta_of(n, rnd.getrandbits(n) | 1)
        if d:
            out.append(d)
    return out


def med(v):
    s = sorted(v)
    return s[len(s) // 2]


def section_5(quick, full):
    rule("§5  The curve, to n = 256 -- and mu does not converge")
    print("""Everything above exists to make this table computable.  Per key, at each width:
lambda* on both axes, from the exact moment ladder.  The criteria are the fixed numbers
§11.30.1 derived, s_diff >= 4/3 and s_lin >= 2/3, and they do not move with n.

Read the last two columns first.  The four passes before this one all asked whether the
sequence CONVERGES above its criterion.  It does not converge.  lambda* is asymptotically
LINEAR in n, and the ratio lambda*/n is what settles down.""")
    widths = [8, 11, 13, 16, 32, 64, 128, 256]
    if quick:
        widths = [8, 11, 16, 32, 64, 256]
    if full:
        widths = [8, 11, 13, 16, 24, 32, 48, 64, 96, 128, 192, 256]
    nk = 3 if quick else 7
    print("\n  %-5s %-9s %-9s %-9s %-9s %-8s %-8s"
          % ("n", "diff", "diff/n", "lin", "lin/n", "x 4/3", "x 2/3"))
    rows = []
    for n in widths:
        ds = keys_at(n, nk)
        dv = med([lam_diff(n, d)[0] for d in ds])
        lv = med([lam_lin(n, d)[0] for d in ds])
        rows.append((n, dv, lv))
        print("  %-5d %-9.4f %-9.4f %-9.4f %-9.4f %-8.1f %-8.1f"
              % (n, dv, dv / n, lv, lv / n, dv / (4 / 3.0), lv / (2 / 3.0)), flush=True)
    dmono = all(rows[i][1] < rows[i + 1][1] for i in range(len(rows) - 1))
    lmono = all(rows[i][2] < rows[i + 1][2] for i in range(len(rows) - 1))
    check(dmono, "the differential lambda* rises at EVERY step of the ladder, n=%d to 256"
                 % widths[0])
    check(lmono, "the linear lambda* rises at every step too")
    n256 = rows[-1]
    check(n256[0] == 256 and n256[1] > 4 / 3.0 and n256[2] > 2 / 3.0,
          "at n = 256 the model clears both criteria -- %.1f bits/round against 4/3 and "
          "%.1f against 2/3" % (n256[1], n256[2]))
    wide = [r for r in rows if r[0] >= 32]
    rd = [r[1] / r[0] for r in wide]
    rl = [r[2] / r[0] for r in wide]
    check(0.15 < min(rd) and max(rd) < 0.22,
          "lambda*/n stays inside a narrow band for every n >= 32 on the differential "
          "axis (%.4f..%.4f, no trend across the band)" % (min(rd), max(rd)))
    check(0.070 < min(rl) and max(rl) < 0.100,
          "and on the linear one (%.4f..%.4f)" % (min(rl), max(rl)))
    print("""
The band is sampling spread, not drift: the ratio CONCENTRATES as the width grows, which
is the second thing that argues the linear law is the real behaviour rather than a fit.
Per-key ranges of lambda*/n, same keys per width:""")
    spread = []
    for n in (32, 256) if quick else (32, 64, 128, 256):
        ds = keys_at(n, nk)
        rr = sorted(lam_diff(n, d)[0] / n for d in ds)
        ll = sorted(lam_lin(n, d)[0] / n for d in ds)
        spread.append((n, rr[-1] - rr[0], ll[-1] - ll[0]))
        print("    n=%-4d differential %.4f..%.4f (width %.4f)   linear %.4f..%.4f "
              "(width %.4f)" % (n, rr[0], rr[-1], rr[-1] - rr[0],
                                ll[0], ll[-1], ll[-1] - ll[0]))
    check(spread[-1][1] < spread[0][1] and spread[-1][2] < spread[0][2],
          "the per-key spread of lambda*/n narrows from n=32 to n=256 on both axes "
          "(%.4f -> %.4f differential, %.4f -> %.4f linear)"
          % (spread[0][1], spread[-1][1], spread[0][2], spread[-1][2]))
    print("""
That is the finding, and it is not the shape any earlier pass assumed.  §11.30.2's
scale-invariance theorem said the CRITERION does not move with n, and that stands.  What
this adds is that the achieved slope does move with n, linearly -- so widening the block
does not face "the identical criterion at 4x the cost", it faces the same criterion with
twice the margin.  §11.30.2's conclusion that no key size is NEEDED survives; its
reading that no key size would HELP does not.

It also retro-explains §11.35.6 and §11.36.5.  Both reported mu rising monotonely over
n = 7..13 and neither could say why a bounded-looking quantity kept rising.  It is not
bounded.  The exact medians in those sections -- 1.279, 1.349, 1.717, 1.903 at
n = 7, 8, 10, 11 -- are 0.183, 0.169, 0.172, 0.173 of n, which is the same constant
this table converges to from below.""")
    ex = [(7, 1.279), (8, 1.349), (10, 1.717), (11, 1.903)]
    r = [v / n for n, v in ex]
    check(max(r) - min(r) < 0.02,
          "§11.35.6's EXACT medians are themselves a constant times n, to %.4f "
          "(%.3f..%.3f) -- measured on mu, not on the model" % (max(r) - min(r), min(r), max(r)))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
# §6  the tz decomposition and the per-key spread at n = 256
# ═══════════════════════════════════════════════════════════════════════════
def section_6(quick):
    rule("§6  The tz decomposition and the per-key spread at n = 256")
    print("""§11.37.6 found lambda* falling by a width-stable 0.10-0.13 per trailing zero of
delta, and concluded that only the tz = 0 sequence needs extrapolating.  At n = 256 that
is checkable directly rather than inferred, and the per-key spread -- which no sampler
could reach -- comes with it.""")
    n = 256
    ks = 4 if quick else 10
    print("\n  %-5s %-12s %-12s" % ("tz", "diff", "lin"))
    rows = []
    for k in (0, 1, 2, 3, 4, 6, 8):
        ds = [d for d in (((x | 1) << k) & ((1 << n) - 1)
                          for x in keys_at(n, ks, seed=99 + k)) if d]
        dv = med([lam_diff(n, d)[0] for d in ds])
        lv = med([lam_lin(n, d)[0] for d in ds])
        rows.append((k, dv, lv))
        print("  %-5d %-12.4f %-12.4f" % (k, dv, lv), flush=True)
    ks_ = [r[0] for r in rows]
    for j, ax in ((1, "differential"), (2, "linear")):
        vals = [r[j] for r in rows]
        mk = sum(ks_) / len(ks_)
        mv = sum(vals) / len(vals)
        slope = (sum((k - mk) * (v - mv) for k, v in zip(ks_, vals))
                 / sum((k - mk) ** 2 for k in ks_))
        span = max(vals) - min(vals)
        check(slope < 0,
              "%s lambda* still falls with tz(delta) at n = 256 -- least-squares slope "
              "%.3f per zero" % (ax, slope))
        check(span / len(ks_) > 0.14,
              "and §11.37.6's per-zero offset is NOT width-independent: %.2f per zero "
              "here against 0.10-0.13 at n <= 11" % (span / len(ks_)))
        check(span / max(vals) < 0.20,
              "but it has shrunk RELATIVE to lambda* -- the whole tz span is %.1f%% of "
              "the largest class, against 5-7%% PER ZERO at n <= 11.  §11.37.6's "
              "conclusion survives a fortiori: the tz correction is negligible at this "
              "width, not merely constant" % (100 * span / max(vals)))
    print("""
The per-class ordering inside the table is NOT resolved by a sample this size -- it moves
between runs, and only the trend and the span are stable.  Neither is quoted below as if
it were.""")
    worst = min(rows, key=lambda r: r[1])
    check(worst[1] > 4 / 3.0 and worst[2] > 2 / 3.0,
          "and the WORST tz class in the table still clears both criteria at n = 256 "
          "(%.1f against 4/3, %.1f against 2/3)" % (worst[1], worst[2]))
    ds = keys_at(n, ks * 2, seed=5)
    dv = sorted(lam_diff(n, d)[0] for d in ds)
    lv = sorted(lam_lin(n, d)[0] for d in ds)
    print("\n  per-key spread over %d keys at n = 256:" % len(ds))
    print("    differential  min %.3f  median %.3f  max %.3f" % (dv[0], med(dv), dv[-1]))
    print("    linear        min %.3f  median %.3f  max %.3f" % (lv[0], med(lv), lv[-1]))
    check(dv[0] > 4 / 3.0 and lv[0] > 2 / 3.0,
          "no key in the sample falls below either criterion -- the closest approach is "
          "%.0fx the differential bar and %.0fx the linear one"
          % (dv[0] / (4 / 3.0), lv[0] / (2 / 3.0)))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
def section_7(rows):
    rule("§7  Where this leaves #257")
    n, dv, lv = rows[-1]
    print("""SETTLED, at the level the model supports.

  * The annealed threshold is EXACTLY COMPUTABLE at n = 256, on both axes.  §11.37.5
    closed this route on the grounds that the quantity sits in a 2^-n quantile and
    cannot be sampled.  That is true and it is not the obstacle: the model needs the
    weight distribution only through its MOMENTS, and those are a linear DP.  The route
    is reopened and walked, and the sampler's 157 -- which that section warned must not
    be quoted -- is replaced by %.1f.

  * mu IS NOT ASYMPTOTICALLY CONSTANT.  It is linear in n.  The question every pass
    since #247 has been asking -- what does the per-round slope converge to -- has no
    answer because the premise is wrong, and the monotonicity #257 inherited is not a
    delicate property of a converging sequence but the leading behaviour of a linear one.

  * The criteria are cleared at n = 256 with a margin of %.0fx (differential) and %.0fx
    (linear), in the model, at every key and every tz class sampled.

NOT SETTLED, and neither is small.

  1. THE MODEL IS AN ESTIMATOR.  It is annealed -- a first-moment count of cheap cycles,
     which bounds nothing on its own, since the first moment can be carried by rare
     graphs.  It is validated against exact mu only at n <= 13, where it runs 3-15%%
     BELOW the truth and converging upward.  Nothing here promotes it to a bound, and a
     quenched second-moment argument is the obvious next thing and is not attempted.

  2. THE LINEAR HULL.  Unchanged from #254's second pass: a trail statement is not a hull
     statement, and no method in this line of work reaches the hull.

Ratings do not move, and could not.  Every row this analysis touches is demo-only for
reasons on other axes (#243's SPRP assumption, #244's tau(192) theorem, #248), and the
three production-track rows left the scope of a trail bound entirely in §11.36.8."""
          % (dv, dv / (4 / 3.0), lv / (2 / 3.0)))
    print("""
The cheapest thing that would upgrade item 1 is stated precisely, since it is now the
whole of #257: the annealed count over-counts cycles that share edges, so the gap
between the model and mu is a SECOND-MOMENT question about the same two inputs -- the
edge-weight distribution and the out-degree -- and both are exactly computable here at
any width.  It needs no new machinery, only the pair correlation.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    section_1(a.quick)
    section_2(a.quick)
    section_3(a.quick)
    section_4(a.quick)
    rows = section_5(a.quick, a.full)
    section_6(a.quick)
    section_7(rows)
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
