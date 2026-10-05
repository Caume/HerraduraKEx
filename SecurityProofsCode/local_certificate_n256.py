#!/usr/bin/env python3
"""local_certificate_n256.py — TODO #257 (seventh pass): the local certificate,
SOLVED at n = 256 instead of extrapolated to it.

#257 owes MONOTONICITY: that exact mu, the minimum mean cycle of the NL-FSCX v2
difference graph, does not decrease between n = 23 and n = 256.  The sixth pass
(local_potential_certificate.py, §11.43) built the one route that would be a PROOF
at n = 256 -- a potential made of w-bit WINDOW functions, whose bound is a
bit-position DP linear in n -- and measured, at n <= 14, that its window must grow
with n.  It said what was left had to carry NON-LOCAL information.  This pass tries
that, then stops extrapolating and SOLVES the certificate at n = 256.

  §1  SOUNDNESS.  Exact edge weights agree with the graph builder; the DP (now
      renormalised per layer, because the sixth pass's version overflows a double
      at n = 256) never exceeds the exhaustive minimum; the C helper
      (local_certificate_dp.c) agrees with it exactly and traces only real edges.
      NEGATIVE CONTROL: separating with the exact single-carry-path Viterbi ALONE
      overstates the LP and its potential certifies far less -- a single carry
      path under-counts exactly the edges that most need a row.

  §2  NON-LOCAL INFORMATION, at small n.  A global statistic (popcount, run
      count) certifies ~0.3 of mu alone and adds 0.03-0.04 to the windows;
      two-round paths add 0.05-0.07.  In every case the share still FALLS with n.

  §3  THE CERTIFICATE SOLVED AT EACH WIDTH.  Constraint generation without
      enumerating the graph: the sound DP's traces and the Viterbi's propose
      edges, each row is an exact weight, the box on the potential grows in
      stages.  One SHARED table F[a-window][delta context] for every position
      costs 2-7% of the LP against a table per position and keeps the LP one
      size at every width.  Solved, the bound does not grow: median ~1.5 at
      n = 20, ~1.0 at n = 48, while exact mu rises ~0.14 per bit.

  §4  THE PINNED CERTIFICATES, n = 64..256.  The LP is too slow there (n = 64 is
      ~30 min a key and the rows grow faster than n), so a supergradient ascent
      finds F and the sound DP certifies it.  Each table is 16 x 16 numbers in
      local_certificate_n256.json; this section re-verifies them from scratch.
      At n = 256 four keys get mu >= 0.54 / 0.58 / 0.74 / 0.90: the first NONZERO
      lower bound at the deployed width (the trivial one is 0), every one BELOW
      the 4/3 criterion, and flat from n = 64 on.  A table solved jointly at
      n = 24 and carried to n = 256 is NEGATIVE on every unseen key: the
      certificate must be solved per key, at the width.

  §5  WHAT THIS CHANGES.  Prose.

Fixed keys, a deterministic LP and a deterministic ascent, so the verdict cannot
flake.  Needs highspy (the LP IS §2-§3, so absent means FAIL, the z3-solver
precedent) and a C compiler (absent means FAIL, exact_slope_ladder.py's precedent).

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/local_certificate_n256.py [--quick]
      --quick      : §3 at n = 16, 20, 24                    (~5 min on an aarch64 SBC)
      default      : §3 adds n = 32, 48 and exact mu at n = 20 (~25 min)
      --regenerate : rebuild the pinned certificates by ascent, then exit (~1 h)
"""

import argparse
import importlib.util
import json
import math
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CSRC = os.path.join(HERE, "local_certificate_dp.c")
PINNED = os.path.join(HERE, "local_certificate_n256.json")
FAIL = []

try:
    import highspy
    import numpy as np
except ImportError:
    print("This gate needs the HiGHS LP solver and numpy:")
    print("    pip install highspy numpy")
    print("They ARE the gate here (every bound in §2-§3 is an LP optimum), so a")
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


LPC = _load("local_potential_certificate.py")   # sixth pass: graph(), dp_bound, LP
QEL = LPC.QEL
NT, FK, keys, med = LPC.NT, LPC.FK, LPC.keys, statistics.median


# ═══════════════════════════════════════════════════════════════════════════
# Exact edges, the sound DP, the separating Viterbi
# ═══════════════════════════════════════════════════════════════════════════
def mbits(a, n):
    return [((a >> ((k - 1) % n)) ^ (a >> k) ^ (a >> ((k + 1) % n))) & 1
            for k in range(n)]


def exact_w(n, d, a, b):
    """The exact weight (n-1) - log2(count) of the edge a -> b, or None if it is not
    an edge.  e_k = b_k xor M(a)_k is forced, so the count is ONE matrix product."""
    g = mbits(a, n)
    e = [((b >> k) & 1) ^ g[k] for k in range(n)]
    if e[0]:
        return None
    v0, v1 = 1.0, 0.0
    for k in range(n - 1):
        M = NT[((d >> k) & 1, g[k], e[k], e[k + 1])]
        v0, v1 = M[0][0] * v0 + M[0][1] * v1, M[1][0] * v0 + M[1][1] * v1
        if v0 == 0 and v1 == 0:
            return None
    return (n - 1) - math.log2(v0 + v1)


def phi(x, n, w, G):
    return sum(G[s][(x >> s) & ((1 << w) - 1)] for s in range(n - w + 1))


def phi_range(n, w, G):
    """max phi - min phi over every n-bit x, exactly (a chain DP over the windows)."""
    P, out = 1 << w, []
    for sgn in (1, -1):
        cur = {p: sgn * G[0][p] for p in range(P)}
        for s in range(1, n - w + 1):
            nxt = {}
            for p, v in cur.items():
                for nb in (0, 1):
                    q = (p >> 1) | (nb << (w - 1))
                    val = v + sgn * G[s][q]
                    if q not in nxt or val > nxt[q]:
                        nxt[q] = val
            cur = nxt
        out.append(sgn * max(cur.values()))
    return out[0] - out[1]


def dp_sound(n, d, w, G):
    """The sixth pass's dp_bound with a per-layer renormalisation, so a potential of
    any size can be evaluated at n = 256 without overflow.  Merging keeps the
    componentwise MAX over the carry slot, which can only over-count, so the returned
    weight is a SOUND lower bound on  min over edges a != 0 of w + phi(a) - phi(b).
    Pure Python and independent of the C helper: it is what §3 verifies with."""
    best = -1e300
    bm = (1 << (w - 1)) - 1
    for A0 in (0, 1):
        for Z in (0, 1):
            cur = {((A0 << (w - 2)) | (Z << (w - 1)), 0, 0, A0 | Z): (1.0, 0.0)}
            lacc = 0.0
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
                m = max(max(v) for v in nxt.values())
                cur = {kk: (v[0] / m, v[1] / m) for kk, v in nxt.items()}
                lacc += math.log2(m)
            for (aw, bw, ek, nz), (v0, v1) in cur.items():
                if nz and v0 + v1 > 0:
                    best = max(best, lacc + math.log2(v0 + v1))
    return (n - 1) - best


class Passes:
    """The C helper: the same sound DP plus back-pointer traces, and the exact
    single-carry-path Viterbi, for one (n, delta, w), over a persistent pipe."""
    EXE = None

    @classmethod
    def build(cls):
        cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
        if not cc:
            print("  no C compiler found (gcc/cc/clang): this gate cannot run.")
            print("  install one, e.g.  sudo apt-get install -y gcc")
            sys.exit(1)
        exe = os.path.join(tempfile.mkdtemp(prefix="lcdp_"), "local_certificate_dp")
        r = subprocess.run([cc, "-O2", "-o", exe, CSRC, "-lm"],
                           capture_output=True, text=True)
        if r.returncode:
            print(r.stderr)
            print("  local_certificate_dp.c FAILED TO BUILD with a present compiler")
            sys.exit(1)
        cls.EXE = exe

    def __init__(self, n, d, w, ncut):
        self.n, self.w = n, w
        self.p = subprocess.Popen([self.EXE], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
        tab = []
        for dd in (0, 1):
            for g in (0, 1):
                for e in (0, 1):
                    for e2 in (0, 1):
                        M = NT[(dd, g, e, e2)]
                        tab += [M[0][0], M[0][1], M[1][0], M[1][1]]
        self.p.stdin.write("%d %d %d\n%x\n%s\n" % (
            n, w, ncut, d, " ".join(repr(float(x)) for x in tab)))

    def run(self, G):
        P = 1 << self.w
        self.p.stdin.write(" ".join(repr(float(G[s][q])) for s in range(self.n)
                                    for q in range(P)) + "\n")
        self.p.stdin.flush()
        sound = float(self.p.stdout.readline().split()[1])
        out = []
        for _ in range(2):
            k = int(self.p.stdout.readline().split()[1])
            out.append([tuple(int(x, 16) for x in self.p.stdout.readline().split())
                        for _ in range(k)])
        return sound, out[0], out[1]

    def close(self):
        self.p.stdin.close()
        self.p.wait()


# ═══════════════════════════════════════════════════════════════════════════
# The LP at any width: constraint generation, both separators, a growing box
# ═══════════════════════════════════════════════════════════════════════════
def solve(n, d, w, boxes=(0.25, 0.5, 1, 2, 4, 8, 16), ncut=24, sep="both",
          maxit=20000, purge=25, slack=0.5, progress=None):
    """max t s.t. w(a,b) + phi(a) - phi(b) >= t over every edge, phi a sum of
    non-wrapping w-bit windows, without enumerating a single row of the graph.

    Each round, the sound DP's back-pointer traces and the Viterbi's exact traces
    propose (a, b); its EXACT weight is computed and the row is added only if the
    current phi violates it.  The box on G grows in stages: with an unconstrained
    G the first LPs run away to the box edge, and a DP over a runaway potential
    merges so many unrelated prefixes that its traces stop naming violated edges
    (the first version stalled at n >= 32 that way).  sep = "viterbi" uses one
    separator only -- the negative control of §1(d).

    Returns (best SOUND bound over the stages, final LP value, G at the best bound,
    rows added, rounds).  The bound is sound whatever the LP did.

    Every `purge` rounds the rows whose slack exceeds `slack` are deleted: without
    that every HiGHS solve carries every row ever added, and at n = 32 that is ~10x
    slower.  A deleted row that is proposed AGAIN is never deleted twice, so the
    purge cannot cycle.  It does not rescue this LP at large n: at n = 48 it sat at
    the box ceiling for hundreds of rounds with or without the purge, ~4000 free
    variables leaving too many optimal vertices.  §3 therefore runs it only at
    n = 16, 20, as the reference the shared table (solve_ti) is measured against."""
    P, S = 1 << w, n - w + 1
    C = Passes(n, d, w, ncut)
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("presolve", "off")
    h.setOptionValue("solver", "simplex")
    h.setOptionValue("simplex_strategy", 1)
    inf = highspy.kHighsInf
    nv = 1 + S * P
    lo, hi = np.zeros(nv), np.zeros(nv)
    lo[0], hi[0] = -1e3, 1e3
    h.addVars(nv, lo, hi)
    c = np.zeros(nv)
    c[0] = -1.0
    h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
    seen, order = set(), []        # order[i] = the (a, b) of LP row i
    dropped, pinned = set(), set()  # a row dropped once and proposed again stays
    G = [[0.0] * P for _ in range(n)]
    t, best, bestG, its, total = float("inf"), -1e9, None, 0, 0

    def take(sol):
        return [list(sol[1 + s * P:1 + (s + 1) * P]) if s < S else [0.0] * P
                for s in range(n)]

    for box in boxes:
        idx = np.array([1 + s * P + p for s in range(S) for p in range(1, P)],
                       dtype=np.int32)
        h.changeColsBounds(len(idx), idx, np.full(len(idx), -box),
                           np.full(len(idx), box))
        if seen:
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, G = sol[0], take(sol)
        while its < maxit:
            its += 1
            dpv, c1, c2 = C.run(G)
            if dpv > best:
                best, bestG = dpv, [list(map(float, g)) for g in G]
            new = 0
            for a, b in (c2 if sep == "viterbi" else c1 + c2):
                if (a, b) in seen or not a:
                    continue
                x = exact_w(n, d, a, b)
                if x is None or x + phi(a, n, w, G) - phi(b, n, w, G) >= t - 1e-7:
                    continue
                seen.add((a, b))
                order.append((a, b))
                if (a, b) in dropped:
                    pinned.add((a, b))
                total += 1
                co = {0: 1.0}
                for s in range(S):
                    pa, pb = (a >> s) & (P - 1), (b >> s) & (P - 1)
                    if pa != pb:
                        if pa:
                            co[1 + s * P + pa] = co.get(1 + s * P + pa, 0) - 1
                        if pb:
                            co[1 + s * P + pb] = co.get(1 + s * P + pb, 0) + 1
                ix = [q for q, v in co.items() if v]
                h.addRow(-inf, x, len(ix), np.array(ix, dtype=np.int32),
                         np.array([co[q] for q in ix]))
                new += 1
            if not new:
                break
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, G = sol[0], take(sol)
            if progress and its % progress == 0:
                print("    round %d  box %g  lp %.4f  sound %.4f  rows %d/%d" %
                      (its, box, t, dpv, len(order), total), flush=True)
            if purge and its % purge == 0 and order:
                act = np.array(h.getSolution().row_value)
                up = np.array(h.getLp().row_upper_)
                drop = np.array([i for i in np.nonzero(up - act > slack)[0]
                                 if order[i] not in pinned], dtype=np.int64)
                if len(drop):
                    h.deleteRows(len(drop), drop.astype(np.int32))
                    keep = np.ones(len(order), bool)
                    keep[drop] = False
                    for i in drop:
                        seen.discard(order[i])
                        dropped.add(order[i])
                    order = [o for o, k in zip(order, keep) if k]
        dpv = C.run(G)[0]
        if dpv > best:
            best, bestG = dpv, [list(map(float, g)) for g in G]
    C.close()
    return best, t, bestG, total, its


# ═══════════════════════════════════════════════════════════════════════════
# §1  soundness
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  Exact edges, a sound DP, a C helper that agrees, and a control")
    bad = tot = ghost = 0
    for n in (7, 8, 10):
        for d in keys(n, 3):
            E = LPC.graph(n, d)[1]
            have = set()
            for a, b, x in E:
                y = exact_w(n, d, a, b)
                tot += 1
                have.add((a, b))
                bad += y is None or abs(x - y) > 1e-9
            if n <= 8:
                ghost += sum(exact_w(n, d, a, b) is not None
                             for a in range(1, 1 << n) for b in range(1 << n)
                             if (a, b) not in have)
    check(bad == 0 and ghost == 0,
          "(a) exact_w reproduces the graph builder's weight on all %d edges at "
          "n = 7, 8, 10 (got %d mismatches) and gives no weight to any non-edge at "
          "n = 7, 8 (got %d) -- so a row this gate adds at n = 256 is a real edge "
          "at its real weight" % (tot, bad, ghost))
    rnd = random.Random(2571)
    viol = cnt = 0
    for n, w in ((7, 3), (8, 4), (10, 4), (11, 4)):
        for d in keys(n, 3):
            E = LPC.graph(n, d)[1]
            for box in (0.5, 4.0, 20.0):
                G = [[0.0] + [rnd.uniform(-box, box) for _ in range((1 << w) - 1)]
                     if s <= n - w else [0.0] * (1 << w) for s in range(n)]
                cnt += 1
                viol += dp_sound(n, d, w, G) > LPC.min_reduced(n, w, E, G) + 1e-9
    check(viol == 0,
          "(b) the renormalised DP never exceeds the exhaustive minimum reduced "
          "cost: 0 violations in %d (key, G) pairs at n = 7, 8, 10, 11 with |G| up "
          "to 20 (got %d) -- the sixth pass's dp_bound overflows a double at "
          "n = 256 for a potential that size, this one does not" % (cnt, viol))
    worst, ghosts, runs = 0.0, 0, 0
    for n, w in ((10, 4), (32, 4), (64, 4), (256, 4), (32, 5)):
        d = keys(n, 1)[0]
        C = Passes(n, d, w, 16)
        for box in (0.5, 3.0, 20.0):
            G = [[0.0] + [rnd.uniform(-box, box) for _ in range((1 << w) - 1)]
                 if s <= n - w else [0.0] * (1 << w) for s in range(n)]
            s, c1, c2 = C.run(G)
            worst = max(worst, abs(s - dp_sound(n, d, w, G)))
            ghosts += sum(exact_w(n, d, a, b) is None for a, b in c1 + c2)
            runs += 1
        C.close()
    check(worst < 1e-9 and ghosts == 0,
          "(c) the C helper's sound DP equals the Python one (max |diff| %.1e over "
          "%d potentials, n = 10..256) and every pair either C pass traces is a "
          "real edge (got %d that are not)" % (worst, runs, ghosts))
    over, fulls, exact = [], [], 0
    for d in keys(10, 3):
        mu, E = LPC.graph(10, d)
        full, _ = LPC.local_bound(10, 4, E, wrap=False)
        b, t, _, _, _ = solve(10, d, 4)
        _, tv, Gv, _, _ = solve(10, d, 4, sep="viterbi")
        exact += abs(t - full) < 1e-3
        over.append((tv, full, LPC.min_reduced(10, 4, E, Gv)))
        fulls.append(full)
    check(exact == 3 and all(tv > full + 1e-3 and mr < full - 0.3
                             for tv, full, mr in over),
          "(d) with both separators the generated LP equals the full-edge LP at "
          "n = 10 (%d of 3 keys within 1e-3); NEGATIVE CONTROL, the Viterbi alone: "
          "its LP OVERSTATES the optimum (%s against %s) and its potential "
          "certifies only %s when every edge is checked -- a single carry path "
          "under-counts the edges that most need a row, which is why the sound DP "
          "is a separator too"
          % (exact, "/".join("%.2f" % o[0] for o in over),
             "/".join("%.2f" % f for f in fulls),
             "/".join("%.2f" % o[2] for o in over)))


# ═══════════════════════════════════════════════════════════════════════════
# §2  non-local information, added at small n
# ═══════════════════════════════════════════════════════════════════════════
def _pc(x):
    return bin(x).count("1")


def _runs(x, n):
    y = (x >> 1) | ((x & 1) << (n - 1))
    return _pc(x & ~y & ((1 << n) - 1))


def global_bound(n, w, E, feat, K):
    """The sixth pass's local LP (wrapping windows, as there) plus one GLOBAL table
    g[feat(x)] with K classes: phi(x) = sum_s G_s(window) + g(feat(x))."""
    WIN = LPC.windows(n, w)
    P = 1 << w
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    inf = highspy.kHighsInf
    nl = n * P
    nv = 1 + nl + K
    lo, hi = np.full(nv, -inf), np.full(nv, inf)
    lo[0], hi[0] = -1e3, 1e3
    for s in range(n):
        lo[1 + s * P] = hi[1 + s * P] = 0.0
    lo[1 + nl] = hi[1 + nl] = 0.0
    h.addVars(nv, lo, hi)
    c = np.zeros(nv)
    c[0] = -1.0
    h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
    st, ix, vl, up = [], [], [], []
    for a, b, x in E:
        co = {0: 1.0}
        pa, pb = WIN[a], WIN[b]
        for s in np.nonzero(pa != pb)[0]:
            if pa[s]:
                k = int(1 + s * P + pa[s])
                co[k] = co.get(k, 0.0) - 1.0
            if pb[s]:
                k = int(1 + s * P + pb[s])
                co[k] = co.get(k, 0.0) + 1.0
        fa, fb = feat(a), feat(b)
        if fa != fb:
            co[1 + nl + fa] = co.get(1 + nl + fa, 0.0) - 1.0
            co[1 + nl + fb] = co.get(1 + nl + fb, 0.0) + 1.0
        st.append(len(ix))
        for k, v in co.items():
            if v:
                ix.append(k)
                vl.append(v)
        up.append(x)
    m = len(st)
    h.addRows(m, np.full(m, -inf), np.array(up), len(ix),
              np.array(st, dtype=np.int32), np.array(ix, dtype=np.int32),
              np.array(vl))
    h.run()
    return float(h.getSolution().col_value[0])


def quotient_mu(E, f):
    """mu of the graph quotiented by a node statistic f, each class edge weighted by
    its lightest member: phi = g(f(x)) alone, solved exactly (Karp)."""
    W = {}
    for a, b, x in E:
        k = (f(a), f(b))
        if k not in W or x < W[k]:
            W[k] = x
    nodes = sorted({k[0] for k in W} | {k[1] for k in W})
    ix = {v: i for i, v in enumerate(nodes)}
    N, INF = len(nodes), float("inf")
    D = [[INF] * N for _ in range(N + 1)]
    D[0] = [0.0] * N
    ed = [(ix[a], ix[b], x) for (a, b), x in W.items()]
    for k in range(1, N + 1):
        for u, v, x in ed:
            if D[k - 1][u] + x < D[k][v]:
                D[k][v] = D[k - 1][u] + x
    best = INF
    for v in range(N):
        if D[N][v] < INF:
            best = min(best, max((D[N][v] - D[k][v]) / (N - k)
                                 for k in range(N) if D[k][v] < INF))
    return best


def two_round_bound(n, w, W2):
    """The local LP on the TWO-ROUND graph: max t s.t. W2[a,b] + phi(a) - phi(b) >=
    2t, W2 the lightest two-edge path.  Constraint generation over the dense W2."""
    P = 1 << w
    WIN = LPC.windows(n, w)
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    inf = highspy.kHighsInf
    nv = 1 + n * P
    lo, hi = np.full(nv, -inf), np.full(nv, inf)
    lo[0], hi[0] = -1e3, 1e3
    for s in range(n):
        lo[1 + s * P] = hi[1 + s * P] = 0.0
    h.addVars(nv, lo, hi)
    c = np.zeros(nv)
    c[0] = -1.0
    h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
    seen = set()

    def add(pairs):
        for a, b in pairs:
            if (a, b) in seen:
                continue
            seen.add((a, b))
            co = {0: 2.0}
            pa, pb = WIN[a], WIN[b]
            for s in np.nonzero(pa != pb)[0]:
                if pa[s]:
                    k = int(1 + s * P + pa[s])
                    co[k] = co.get(k, 0.0) - 1.0
                if pb[s]:
                    k = int(1 + s * P + pb[s])
                    co[k] = co.get(k, 0.0) + 1.0
            k2 = [k for k, v in co.items() if v]
            h.addRow(-inf, float(W2[a, b]), len(k2), np.array(k2, dtype=np.int32),
                     np.array([co[k] for k in k2]))
    add([(a, int(np.argmin(W2[a]))) for a in range(1, 1 << n)])
    while True:
        h.run()
        sol = np.array(h.getSolution().col_value)
        t = sol[0]
        G = sol[1:].reshape(n, P)
        ph = G[np.arange(n)[None, :], WIN].sum(axis=1)
        R = W2 + ph[:, None] - ph[None, :]
        new = [(int(a), int(b)) for a, b in np.argwhere(R < 2 * t - 1e-7)
               if (int(a), int(b)) not in seen]
        if not new:
            return t
        add(new[:20000])


def two_round_matrix(n, E):
    N = 1 << n
    W = np.full((N, N), np.inf)
    for a, b, x in E:
        W[a, b] = min(W[a, b], x)
    W[0, :] = np.inf
    W[:, 0] = np.inf
    W2 = np.full((N, N), np.inf)
    for m in range(1, N):
        ia = np.nonzero(np.isfinite(W[:, m]))[0]
        jb = np.nonzero(np.isfinite(W[m]))[0]
        if len(ia) and len(jb):
            blk = W[ia, m][:, None] + W[m, jb][None, :]
            W2[np.ix_(ia, jb)] = np.minimum(W2[np.ix_(ia, jb)], blk)
    return W2


def section_2(quick):
    rule("§2  Non-local information, added at small n: it shifts the share, "
         "not its trend")
    print("""Three ways to give the sixth pass's certificate information a w-bit window
cannot see, each measured as a share of exact mu (median over the keys):
  quotient   phi = g(popcount) or g(runs) alone      -- a global statistic only
  +global    local windows + g(popcount, runs)        -- both
  2-round    local windows on the TWO-round graph     -- support growth over 2 rounds
""")
    rows = {}
    for n, cnt in ((8, 6), (10, 6), (11, 4)):
        q, g3, g5, l3, l5, k3, k5, m4 = [], [], [], [], [], [], [], []
        for d in keys(n, cnt):
            mu, E = LPC.graph(n, d)
            f2 = lambda x, n=n: _pc(x) * (n + 1) + _runs(x, n)
            q.append(max(quotient_mu(E, _pc), quotient_mu(E, lambda x, n=n:
                                                             _runs(x, n)),
                         quotient_mu(E, f2)) / mu)
            l3.append(LPC.local_bound(n, 3, E)[0] / mu)
            l5.append(LPC.local_bound(n, 5, E)[0] / mu)
            g3.append(global_bound(n, 3, E, f2, (n + 1) ** 2) / mu)
            g5.append(global_bound(n, 5, E, f2, (n + 1) ** 2) / mu)
            if not (quick and n == 11):
                W2 = two_round_matrix(n, E)
                k3.append(two_round_bound(n, 3, W2) / mu)
                k5.append(two_round_bound(n, 5, W2) / mu)
        rows[n] = [med(v) if v else float("nan")
                   for v in (q, l3, g3, k3, l5, g5, k5)]
        print("  n = %2d  quotient %.2f | w=3: local %.2f  +global %.2f  2-round %.2f"
              " | w=5: local %.2f  +global %.2f  2-round %.2f" % ((n,) + tuple(rows[n])))
    check(all(rows[n][0] < 0.45 for n in rows),
          "a GLOBAL statistic alone certifies little: the best of popcount, run "
          "count and both is a median %s of mu at n = 8, 10, 11 -- a coarse class "
          "admits a self-loop at its lightest same-class edge"
          % "/".join("%.2f" % rows[n][0] for n in rows))
    check(all(0 <= rows[n][5] - rows[n][4] < 0.08 for n in rows)
          and rows[11][5] < rows[8][5],
          "adding it to the windows buys %s at w = 5 and the share still FALLS "
          "(%.2f -> %.2f from n = 8 to 11): the missing information is not density"
          % ("/".join("%+.2f" % (rows[n][5] - rows[n][4]) for n in rows),
             rows[8][5], rows[11][5]))
    nk = [n for n in rows if rows[n][6] == rows[n][6]]
    check(all(rows[n][6] > rows[n][4] + 0.03 for n in nk)
          and rows[nk[-1]][6] < rows[8][6],
          "two-round paths buy more (%s at w = 5) and the share STILL falls "
          "(%.2f -> %.2f): a k-round certificate sees k rounds of support growth, "
          "a fixed amount, while what it must capture grows with n"
          % ("/".join("%+.2f" % (rows[n][6] - rows[n][4]) for n in nk),
             rows[8][6], rows[nk[-1]][6]))
    return rows


# ═══════════════════════════════════════════════════════════════════════════
# The translation-invariant potential: one table for every position
# ═══════════════════════════════════════════════════════════════════════════
def dctx(d, n, s, w, v):
    """The v-bit window of delta centred on the w-bit window at s; bits beyond the
    word read as 0 (the potential is non-wrapping, so the ends are ordinary)."""
    lo = s - (v - w) // 2
    out = 0
    for j in range(v):
        k = lo + j
        if 0 <= k < n:
            out |= ((d >> k) & 1) << j
    return out


def ti_G(F, d, n, w, v):
    P = 1 << w
    return [[float(F[p][dctx(d, n, s, w, v)]) for p in range(P)] if s <= n - w
            else [0.0] * P for s in range(n)]


def solve_ti(n, d, w, v, boxes=(0.25, 0.5, 1, 2, 4, 8), ncut=48, maxit=5000,
             progress=None):
    """The same LP with phi(x) = sum_s F[x_s..x_{s+w-1}][delta context at s]: one
    table of 2^w x 2^v entries, so the LP has the same size at n = 256 as at n = 16
    and constraint generation converges where the per-position LP does not."""
    P, Q, S = 1 << w, 1 << v, n - w + 1
    DC = [dctx(d, n, s, w, v) for s in range(S)]
    C = Passes(n, d, w, ncut)
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("presolve", "off")      # re-solved warm after every round:
    h.setOptionValue("solver", "simplex")    # presolve throws the basis away and
    h.setOptionValue("simplex_strategy", 1)  # cost 0.6 s a solve at n = 96
    inf = highspy.kHighsInf
    nv = 1 + P * Q
    lo, hi = np.zeros(nv), np.zeros(nv)
    lo[0], hi[0] = -1e3, 1e3
    h.addVars(nv, lo, hi)
    c = np.zeros(nv)
    c[0] = -1.0
    h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
    F = np.zeros((P, Q))
    seen, t, best, bestF, its, total = set(), float("inf"), -1e9, None, 0, 0
    for box in boxes:
        idx = np.array([1 + p * Q + q for p in range(1, P) for q in range(Q)],
                       dtype=np.int32)
        h.changeColsBounds(len(idx), idx, np.full(len(idx), -box),
                           np.full(len(idx), box))
        if seen:
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, F = sol[0], sol[1:].reshape(P, Q)
        while its < maxit:
            its += 1
            G = ti_G(F, d, n, w, v)
            dpv, c1, c2 = C.run(G)
            if dpv > best:
                best, bestF = dpv, F.copy()
            new = 0
            for a, b in c1 + c2:
                if (a, b) in seen or not a:
                    continue
                x = exact_w(n, d, a, b)
                if x is None or x + phi(a, n, w, G) - phi(b, n, w, G) >= t - 1e-7:
                    continue
                seen.add((a, b))
                total += 1
                co = {0: 1.0}
                for s in range(S):
                    pa, pb = (a >> s) & (P - 1), (b >> s) & (P - 1)
                    if pa != pb:
                        if pa:
                            k = 1 + pa * Q + DC[s]
                            co[k] = co.get(k, 0) - 1
                        if pb:
                            k = 1 + pb * Q + DC[s]
                            co[k] = co.get(k, 0) + 1
                ix = [k for k, val in co.items() if val]
                h.addRow(-inf, x, len(ix), np.array(ix, dtype=np.int32),
                         np.array([co[k] for k in ix], dtype=float))
                new += 1
            if not new:
                break
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, F = sol[0], sol[1:].reshape(P, Q)
            if progress and its % progress == 0:
                print("    round %d  box %g  lp %.4f  sound %.4f  rows %d" %
                      (its, box, t, dpv, total), flush=True)
        dpv = C.run(ti_G(F, d, n, w, v))[0]
        if dpv > best:
            best, bestF = dpv, F.copy()
    C.close()
    return best, t, bestF, total, its


# ═══════════════════════════════════════════════════════════════════════════
# §3  the ladder, solved at every width
# ═══════════════════════════════════════════════════════════════════════════
ESL = None


def exact_mu(n, d):
    """Exact mu from §11.42's C solver (exact_slope_ladder.py), loaded lazily."""
    global ESL
    if ESL is None:
        ESL = _load("exact_slope_ladder.py")
        ESL.build()
    return ESL.cmu(n, d, 0)[0]


def section_3(quick):
    rule("§3  The certificate SOLVED at each width, not extrapolated to it")
    print("""w = 4 and the delta context v = 4.  'free' is a separate table per position;
'shared' is one table F[a-window][delta context] for every position.  Every
'sound' figure is the DP's bound at the potential found -- a theorem about that
key's graph, whatever the LP did.  mu is exact (§11.42's C solver) where it exists.
""")
    out = {}
    plan = ((16, True), (20, True), (24, False)) if quick else \
        ((16, True), (20, True), (24, False), (32, False), (48, False))
    for n, with_free in plan:
        rows = []
        for d in keys(n, 3):
            sb, st, _, _, _ = solve_ti(n, d, 4, 4)
            fb = ft = float("nan")
            if with_free:
                fb, ft, _, _, _ = solve(n, d, 4, ncut=48)
            mu = exact_mu(n, d) if n <= (16 if quick else 20) else float("nan")
            rows.append((sb, st, fb, ft, mu))
            print("  n = %2d  delta %-14x shared: sound %.3f lp %.3f | free: sound %s"
                  " lp %s | mu %s" % (n, d, sb, st,
                                      "%.3f" % fb if fb == fb else "  -  ",
                                      "%.3f" % ft if ft == ft else "  -  ",
                                      "%.3f" % mu if mu == mu else "  -  "),
                  flush=True)
        out[n] = rows
    fr = [r[1] / r[3] for n in out for r in out[n] if r[3] == r[3]]
    check(min(fr) > 0.9,
          "(a) ONE shared table loses little against a table per position: the "
          "shared LP is %.2f-%.2f of the free one at n = 16, 20 -- which is what "
          "keeps the LP the same size at every width" % (min(fr), max(fr)))
    sh = [r[0] / r[4] for n in out for r in out[n] if r[4] == r[4]]
    gap = [1 - r[0] / r[1] for n in out for r in out[n]]
    check(all(r[0] <= r[1] + 1e-9 for n in out for r in out[n]) and max(sh) < 0.6,
          "(b) every sound bound sits below its LP, and certifies at most %.2f of "
          "exact mu where mu is known (%s) -- the DP's slot-max merge costs "
          "%.0f-%.0f%% of the LP, the window the rest"
          % (max(sh), ", ".join("n = %d" % n for n in out
                                if any(r[4] == r[4] for r in out[n])),
             100 * min(gap), 100 * max(gap)))
    top = max(out)
    m20, mtop = med([r[0] for r in out[20]]), med([r[0] for r in out[top]])
    check(mtop < m20,
          "(c) solved rather than extrapolated, the bound does not grow: median "
          "%.2f at n = 20 and %.2f at n = %d, while exact mu rises ~0.14 per bit "
          "(§11.42)" % (m20, mtop, top))
    return out


def solve_joint(n, ds, w, v, boxes=(0.25, 0.5, 1, 2, 4, 8), ncut=48, maxit=5000,
                progress=None):
    """ONE table F for several keys at once: max t s.t. every key's every edge has
    reduced cost >= t.  F is width-independent, so it can be evaluated at n = 256 on
    keys it never saw -- and the DP's value there is sound whatever F is."""
    P, Q, S = 1 << w, 1 << v, n - w + 1
    DCs = [[dctx(d, n, s, w, v) for s in range(S)] for d in ds]
    Cs = [Passes(n, d, w, ncut) for d in ds]
    h = highspy.Highs()
    h.setOptionValue("output_flag", False)
    h.setOptionValue("presolve", "off")
    h.setOptionValue("solver", "simplex")
    h.setOptionValue("simplex_strategy", 1)
    inf = highspy.kHighsInf
    nv = 1 + P * Q
    lo, hi = np.zeros(nv), np.zeros(nv)
    lo[0], hi[0] = -1e3, 1e3
    h.addVars(nv, lo, hi)
    c = np.zeros(nv)
    c[0] = -1.0
    h.changeColsCost(nv, np.arange(nv, dtype=np.int32), c)
    F = np.zeros((P, Q))
    seen, t, its, total = set(), float("inf"), 0, 0
    for box in boxes:
        idx = np.array([1 + p * Q + q for p in range(1, P) for q in range(Q)],
                       dtype=np.int32)
        h.changeColsBounds(len(idx), idx, np.full(len(idx), -box),
                           np.full(len(idx), box))
        if seen:
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, F = sol[0], sol[1:].reshape(P, Q)
        while its < maxit:
            its += 1
            new = 0
            sounds = []
            for ki, d in enumerate(ds):
                G = ti_G(F, d, n, w, v)
                dpv, c1, c2 = Cs[ki].run(G)
                sounds.append(dpv)
                for a, b in c1 + c2:
                    if (ki, a, b) in seen or not a:
                        continue
                    x = exact_w(n, d, a, b)
                    if x is None or x + phi(a, n, w, G) - phi(b, n, w, G) >= t - 1e-7:
                        continue
                    seen.add((ki, a, b))
                    total += 1
                    co = {0: 1.0}
                    for s in range(S):
                        pa, pb = (a >> s) & (P - 1), (b >> s) & (P - 1)
                        if pa != pb:
                            if pa:
                                k = 1 + pa * Q + DCs[ki][s]
                                co[k] = co.get(k, 0) - 1
                            if pb:
                                k = 1 + pb * Q + DCs[ki][s]
                                co[k] = co.get(k, 0) + 1
                    ix = [k for k, val in co.items() if val]
                    h.addRow(-inf, x, len(ix), np.array(ix, dtype=np.int32),
                             np.array([co[k] for k in ix], dtype=float))
                    new += 1
            if not new:
                break
            h.run()
            sol = np.array(h.getSolution().col_value)
            t, F = sol[0], sol[1:].reshape(P, Q)
            if progress and its % progress == 0:
                print("    round %d  box %g  lp %.4f  min sound %.4f  rows %d" %
                      (its, box, t, min(sounds), total), flush=True)
    for C in Cs:
        C.close()
    return t, F, total, its


def ti_sound(n, d, w, v, F, ncut=1):
    C = Passes(n, d, w, ncut)
    s = C.run(ti_G(F, d, n, w, v))[0]
    C.close()
    return s


def ascend(n, d, w=4, v=4, steps=3000, eta0=0.05, ncut=48, tol=0.05):
    """Supergradient ascent on the shared table, for the widths where the LP is too
    slow (n = 64 takes ~30 min per key by constraint generation, and the rows grow
    faster than n).  Each step: the C passes trace candidate edges, the ones within
    `tol` of the lightest exact reduced cost are the active set, and F moves along
    the mean of their reduced-cost gradients.  It never claims an optimum -- every
    iterate's bound is the sound DP's, and the best is kept."""
    P, Q = 1 << w, 1 << v
    DC = [dctx(d, n, s, w, v) for s in range(n - w + 1)]
    C = Passes(n, d, w, ncut)
    F = np.zeros((P, Q))
    best, bestF = -1e9, F.copy()
    for it in range(steps):
        G = ti_G(F, d, n, w, v)
        s, c1, c2 = C.run(G)
        if s > best:
            best, bestF = s, F.copy()
        rs = []
        for a, b in c1 + c2:
            if a:
                x = exact_w(n, d, a, b)
                if x is not None:
                    rs.append((x + phi(a, n, w, G) - phi(b, n, w, G), a, b))
        m = min(r for r, _, _ in rs)
        act = [(a, b) for r, a, b in rs if r <= m + tol]
        g = np.zeros((P, Q))
        for a, b in act:
            for s_ in range(n - w + 1):
                g[(a >> s_) & (P - 1), DC[s_]] += 1
                g[(b >> s_) & (P - 1), DC[s_]] -= 1
        g[0, :] = 0
        F = F + eta0 / math.sqrt(1 + it / 50) * g / len(act)
    C.close()
    return best, bestF


# ═══════════════════════════════════════════════════════════════════════════
# §4  the pinned certificates, n = 64 .. 256
# ═══════════════════════════════════════════════════════════════════════════
PIN_WIDTHS = (64, 96, 128, 192, 256)


def regenerate():
    """Rebuild local_certificate_n256.json by ascent (~1 h on an aarch64 SBC).  The
    tables are rounded to 1e-6 and their bound RECOMPUTED after rounding, so the file
    records exactly what §4 re-verifies."""
    Passes.build()
    recs = []
    for n in PIN_WIDTHS:
        for i, d in enumerate(keys(n, 4 if n == 256 else 3)):
            t0 = time.time()
            _, F = ascend(n, d)
            F = np.round(F, 6)
            b = dp_sound(n, d, 4, ti_G(F, d, n, 4, 4))
            recs.append({"n": n, "i": i, "delta": "%x" % d, "w": 4, "v": 4,
                         "bound": round(b, 12), "F": F.tolist()})
            print("  n = %3d  key %d  bound %.4f  (%.0fs)" % (n, i, b,
                                                          time.time() - t0),
                  flush=True)
    what = ("TODO #257 seventh pass: shared-table local certificates (w = 4, v = 4),"
            " re-verified by local_certificate_n256.py section 4")
    with open(PINNED, "w") as f:
        f.write('{"what": %s,\n "certificates": [\n' % json.dumps(what))
        f.write(",\n".join("  " + json.dumps(r, separators=(",", ":"))
                            for r in recs))
        f.write("\n ]}\n")


def section_4():
    rule("§4  The pinned certificates: a sound bound on mu at n = 256, re-verified")
    print("""Each entry is a 16 x 16 table F found by ascent (§3 is too slow above n = 48).
This section does not search: it rebuilds phi from F, runs the pure-Python DP of
§1(b) once per key, and checks the recorded bound.  Whatever F is, that number is a
theorem about the key's graph -- every cycle has mean at least that much.
""")
    with open(PINNED) as f:
        recs = json.load(f)["certificates"]
    bad, rows = 0, {}
    for r in recs:
        n, i = r["n"], r["i"]
        d = keys(n, i + 1)[i]
        F = np.array(r["F"])
        G = ti_G(F, d, n, r["w"], r["v"])
        b = dp_sound(n, d, r["w"], G)
        dphi = phi_range(n, r["w"], G)
        ok = "%x" % d == r["delta"] and abs(b - r["bound"]) < 1e-9
        bad += not ok
        rows.setdefault(n, []).append((b, dphi))
        print("  n = %3d  key %d  bound %.4f  phi range %6.1f  %s"
              % (n, i, b, dphi, "" if ok else "<-- DOES NOT RE-VERIFY"))
    allb = [b for n in rows for b, _ in rows[n]]
    check(bad == 0 and set(rows) == set(PIN_WIDTHS),
          "(a) all %d pinned certificates re-verify to their recorded bound (the "
          "key regenerated from the fixed stream, the DP run from scratch; got %d "
          "that do not)" % (len(recs), bad))
    b256 = sorted(b for b, _ in rows[256])
    check(min(allb) > 0,
          "(b) every one is POSITIVE (min %.2f): at n = 256 these keys have mu >= "
          "%s -- the first nonzero lower bound at the deployed width, where the "
          "trivial one is 0 because every key has a probability-1 one-round "
          "differential" % (min(allb), "/".join("%.2f" % b for b in b256)))
    check(max(b256) < 4 / 3,
          "(c) and every one is BELOW the 4/3 criterion (max %.2f at n = 256): "
          "this class proves the criterion at no key measured" % max(b256))
    meds = [med([b for b, _ in rows[n]]) for n in PIN_WIDTHS]
    check(max(meds) < 1.2,
          "(d) the median bound is %s at n = %s: flat to falling, ~0.6-0.8 a round, "
          "while exact mu at n = 256 is read at ~13-33 (§11.42) -- the certified "
          "share falls roughly as 1/n"
          % ("/".join("%.2f" % m for m in meds),
             "/".join(str(n) for n in PIN_WIDTHS)))
    fr = [192 * b - dp for b, dp in rows[256]]
    check(max(fr) < 256,
          "(e) the finite-round corollary is weak: an r-round trail weighs at least "
          "r*t - (max phi - min phi), and phi spans %.0f-%.0f bits, so 192 rounds "
          "are certified at only %.0f-%.0f bits against the 256 the criterion asks "
          "-- the per-round statement is the useful one"
          % (min(dp for _, dp in rows[256]), max(dp for _, dp in rows[256]),
             min(fr), max(fr)))
    return rows


def section_4_transfer(quick):
    print()
    if quick:
        print("  (f) the transfer control runs in default mode only -- not scored here")
        return
    t, F, _, _ = solve_joint(24, keys(24, 6), 4, 4)
    own = [ti_sound(24, d, 4, 4, F) for d in keys(24, 6)]
    far = [ti_sound(256, d, 4, 4, F) for d in keys(256, 6)]
    check(min(own) > 0 and max(far) < 0,
          "(f) TRANSFER CONTROL: one table solved jointly over six keys at n = 24 "
          "certifies %.2f-%.2f on those keys and is NEGATIVE on all six n = 256 keys "
          "(%.1f to %.1f): local configurations it never saw are unconstrained, and "
          "the potential exploits them -- the certificate must be solved per key, "
          "at the width" % (min(own), max(own), min(far), max(far)))


def section_5():
    rule("§5  What this changes")
    print("""A local certificate is SOUND at every width and now SOLVED at the deployed one,
and what it certifies there is ~0.5-0.9 a round on four keys: positive, which
nothing before it was at n = 256, and below 4/3, so it proves the criterion at no
key.  Solved at each width, its value peaks near n = 20 and then sits flat while
exact mu grows ~0.14 per bit, so the share it certifies falls roughly as 1/n.  The
sixth pass read that off n <= 14; §3-§4 measure it to n = 256.

What a window cannot see is not density (§2: a global statistic buys 0.03-0.04) and
not a few rounds of support growth (two-round paths buy 0.05-0.07): it is that a LIGHT
difference cannot stay light around a whole cycle.  The LP dual stitches cheap,
sparse, locally balanced edges together; every real cheap cycle is dense.  Any
next route has to bound how much weight a sparse difference sheds under M per
round, globally -- a statement about the support, not about windows of it.

Unchanged: exact mu, measured to n = 23, grows at every width step; the residue
is monotonicity from n = 23 to 256, and the linear hull.  No rating moves.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--regenerate", action="store_true",
                    help="rebuild the pinned certificates (~1 h), then exit")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return
    print(__doc__)
    Passes.build()
    section_1()
    section_2(a.quick)
    section_3(a.quick)
    section_4()
    section_4_transfer(a.quick)
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
