#!/usr/bin/env python3
"""period_series_n19.py — TODO #257 (thirteenth pass): the per-period increment of
E[mu] one period further, to n = 19, in both residue classes -- and the fall
STEEPENS, so §11.49's "the decline is slowing" is withdrawn.

§11.49 (period_exponent.py) measured P(n) = E[mu_{n+3}] - E[mu_n] at n = 7, 10, 13 and
read the differential local exponent drifting from -0.55 to -0.23: a slowing decline.
This pass adds the period that reaches n = 19 -- one exact solve at n = 19 per pair,
~30 s -- and the n = 2 (mod 3) series beside it.

  §1  THE PINNED SAMPLE.  A period cannot start at a singular width (3 | n: M is not
      invertible, mu is identically 0), so the starts are 7, 10, 13, 16 and 8, 11, 14.
      11 700 pairs per axis, 500 of them at n = 19, pinned in period_series_n19.json
      because the n = 19 cell alone is ~8 h of CPU.  The gate shows the file is the
      WHOLE seeded sample and re-solves a prefix of every cell.

  §2  A HOWARD NON-TERMINATION, FIXED IN ALL FOUR SOLVERS.  The sample hit a key
      (n = 14, delta = 0x1500, linear) on which policy iteration never stops, in the
      C solver and in the Python solvers it transcribes: every node already holds the
      optimal mean, but the bias h was rooted wherever the scan entered a cycle, and
      with several cycles of EQUAL mean those h are not comparable.  Rooting h at the
      cycle's smallest node fixes it; mu and the certificate do not depend on the
      root, and 744 random keys at n = 7..16 give identical mu, edges and rounds.
      NEGATIVE CONTROL: the old root does not terminate in certificate round 2.

  §3  THE SERIES.  On this seed P(13) reproduces §11.49.2's replication (0.9 and 0.1
      sigma), and E[mu_16] agrees between two independent samples.  Then:
      (a) E[mu] rises over EVERY period to n = 19, by 24 standard errors or more.
      (b) P falls over the last step in both residue classes, on both axes (6.7 to
          9.8 standard errors).
      (c) In the n = 1 (mod 3) series §11.49 measured, the local exponent moves from
          -0.32 to -2.02 (differential, 6.2 sigma) and -0.23 to -1.26 (linear, 4.5
          sigma): the fall STEEPENS.  In the n = 2 series it steepens on the linear
          axis and not on the differential one -- printed, not scored.
      E[mu_19] = 2.61 / 1.31: 1.95x and 1.96x the 4/3 and 2/3 criteria.

  §4  WHAT THIS CHANGES.  Prose.

The verdicts are computed from the pinned file, so they cannot flake; the re-solves
use the certified C solver, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/period_series_n19.py [--quick | --full]
      --quick      : re-solve 2 pinned pairs per cell        (~3 min on an aarch64 SBC)
      default      : re-solve 10 per cell                    (~15 min)
      --full       : re-solve every pinned pair              (~10 h single-core)
      --regenerate : rebuild period_series_n19.json in parallel, then exit (~3 h on
                     8 cores)
"""

import argparse
import importlib.util
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "period_series_n19.json")
FAIL = []

SEED = 2257
# (start width, pairs per axis).  A period may not START at a singular width
# (3 | n): M is not invertible there, mu is identically 0, and so is P(n + 3)'s
# partner -- P(15) = mu_18 - mu_15 = 0 - 0.  Hence two residue classes, n = 1 and
# n = 2 (mod 3), each its own series.
PLAN = ((7, 2000), (8, 2000), (10, 2000), (11, 2000), (13, 2000), (14, 1200),
        (16, 500))
NAME = {0: "differential", 1: "linear"}


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


PE = _load("period_exponent.py")     # control_mean(), exponent()
CWI = PE.CWI                         # insert(), degenerate()
ESL = PE.ESL                         # the certified C solver
nruns = ESL.nruns


# ═══════════════════════════════════════════════════════════════════════════
# the sample: one three-bit insertion per key, so pairs are independent
# ═══════════════════════════════════════════════════════════════════════════
def draws(n, K, axis):
    """The K (delta, inserted delta) pairs of one cell, in draw order."""
    rnd = random.Random(SEED * 1000 + n * 10 + axis)
    out = []
    for _ in range(K):
        d = rnd.getrandbits(n)
        while CWI.degenerate(d, n):
            d = rnd.getrandbits(n)
        e, w = d, n
        for _ in range(3):
            e = CWI.insert(e, w, rnd.randrange(w + 1), rnd.getrandbits(1))
            w += 1
        out.append((d, e))
    return out


def _solve(job):
    n, axis, d, e, exe = job
    ESL.EXE = exe
    return ESL.cmu(n, d, axis)[0], ESL.cmu(n + 3, e, axis)[0]


def regenerate(workers):
    from multiprocessing import Pool
    ESL.build()
    cells = []
    with Pool(workers) as pool:
        for n, K in PLAN:
            for axis in (0, 1):
                jobs = [(n, axis, d, e, ESL.EXE) for d, e in draws(n, K, axis)]
                mus = pool.map(_solve, jobs, chunksize=4)
                cells.append({"n": n, "axis": axis,
                              "mu": [[round(a, 9), round(b, 9)] for a, b in mus]})
                print("  n = %d, %s: %d pairs" % (n, NAME[axis], K), flush=True)
    write_pinned(cells)


def write_pinned(cells):
    what = ("TODO #257 thirteenth pass: exact mu (certified_cycle_mean.c) of each "
            "(delta, three-bit insertion) pair drawn by period_series_n19.py's draws() "
            "with seed %d, in draw order: [mu_n(delta), mu_{n+3}(inserted)]." % SEED)
    with open(PINNED, "w") as f:
        f.write('{"what": %s,\n "seed": %d,\n "cells": [\n' % (json.dumps(what), SEED))
        f.write(",\n".join('  {"n": %d, "axis": %d, "mu": %s}'
                           % (c["n"], c["axis"], json.dumps(c["mu"], separators=(",", ":")))
                           for c in cells))
        f.write("\n ]}\n")


def load_pinned():
    with open(PINNED) as f:
        return {(c["n"], c["axis"]): c["mu"] for c in json.load(f)["cells"]}


# ═══════════════════════════════════════════════════════════════════════════
# the estimator: §11.49's, with one insertion per key
# ═══════════════════════════════════════════════════════════════════════════
def period_stats(n, pairs, mus):
    """(plain P, se, control-variate P, se) for one cell."""
    y = [b - a for a, b in mus]
    x = [nruns(e, n + 3) - nruns(d, n) for d, e in pairs]
    N = len(y)
    my, mx = sum(y) / N, sum(x) / N
    sy = math.sqrt(sum((v - my) ** 2 for v in y) / (N - 1))
    bcoef = (sum((a - mx) * (c - my) for a, c in zip(x, y))
             / sum((a - mx) ** 2 for a in x))
    cm = PE.control_mean(n, 3)
    adj = [c - bcoef * (a - cm) for a, c in zip(x, y)]
    ma = sum(adj) / N
    sa = math.sqrt(sum((v - ma) ** 2 for v in adj) / (N - 1))
    return my, sy / math.sqrt(N), ma, sa / math.sqrt(N)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the pinned sample is the seeded sample, and the solver reproduces it
# ═══════════════════════════════════════════════════════════════════════════
def section_1(pinned, resolve):
    rule("§1  The pinned sample is the seeded sample, and the solver reproduces it")
    print("""Every pair below was drawn by draws() from a fixed seed and solved exactly by
§11.42's certified C solver.  P(16) needs one solve at n = 19 per pair (~30 s), so
the full sample is pinned in period_series_n19.json; this section shows that the file
holds the WHOLE seeded sample, in draw order, and re-solves a prefix of every cell.
""")
    want = {(n, a): K for n, K in PLAN for a in (0, 1)}
    check(set(pinned) == set(want)
          and all(len(pinned[c]) == want[c] for c in want),
          "the pinned file has every cell of the plan at its full size (%s pairs per "
          "axis) -- no pair was dropped" % " / ".join(str(K) for _, K in PLAN))
    worst, done = 0.0, 0
    for n, K in PLAN:
        for axis in (0, 1):
            k = K if resolve is None else min(resolve, K)
            for (d, e), (m0, m3) in list(zip(draws(n, K, axis), pinned[(n, axis)]))[:k]:
                worst = max(worst, abs(ESL.cmu(n, d, axis)[0] - m0),
                            abs(ESL.cmu(n + 3, e, axis)[0] - m3))
                done += 1
    check(worst < 1e-8,
          "re-solving %d pinned pairs (the first %s of every cell) reproduces both mu "
          "values (max |diff| %.1e)" % (done, "all" if resolve is None else resolve,
                                        worst))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the Howard non-termination this sample found, fixed
# ═══════════════════════════════════════════════════════════════════════════
STUCK = (14, 0x1500, 1)          # n, delta, axis: draws 1123 and 1930 of P(11), linear


def _howard(BS, WS, canonical, cap):
    """quenched_exact_ladder.howard_csr with the cycle root as a switch and an
    iteration cap.  Returns (converged, iterations, mu)."""
    eps = 1e-9
    N = len(BS)
    nodes = range(1, N)
    pi, pw = [0] * N, [0.0] * N
    for v in nodes:
        j = min(range(len(WS[v])), key=WS[v].__getitem__)
        pi[v], pw[v] = BS[v][j], WS[v][j]
    mu, h = [0.0] * N, [0.0] * N
    for it in range(1, cap + 1):
        colour = bytearray(N)
        for s in nodes:
            if colour[s]:
                continue
            path, v = [], s
            while not colour[v]:
                colour[v] = 1
                path.append(v)
                v = pi[v]
            tail = path
            if colour[v] == 1:
                i = path.index(v)
                cyc = path[i:]
                m = sum(pw[u] for u in cyc) / len(cyc)
                for u in cyc:
                    mu[u] = m
                if canonical:
                    k = cyc.index(min(cyc))
                    cyc = cyc[k:] + cyc[:k]
                h[cyc[0]] = 0.0
                for u in reversed(cyc[1:]):
                    h[u] = pw[u] - m + h[pi[u]]
                tail = path[:i]
            for u in reversed(tail):
                mu[u] = mu[pi[u]]
                h[u] = pw[u] - mu[u] + h[pi[u]]
            for u in path:
                colour[u] = 2
        improved = False
        for v in nodes:
            bmu, bh, bj = mu[v], h[v], -1
            for j in range(len(BS[v])):
                b = BS[v][j]
                cmu = mu[b]
                if cmu < bmu - eps:
                    bmu, bh, bj = cmu, WS[v][j] - cmu + h[b], j
                elif cmu <= bmu + eps:
                    ch = WS[v][j] - cmu + h[b]
                    if ch < bh - eps:
                        bmu, bh, bj = cmu, ch, j
            if bj >= 0:
                pi[v], pw[v] = BS[v][bj], WS[v][bj]
                improved = True
        if not improved:
            return True, it, min(mu[v] for v in nodes)
    return False, cap, min(mu[v] for v in nodes)


def section_2():
    rule("§2  A Howard non-termination this sample found, fixed in all four solvers")
    print("""Draws 1123 and 1930 of P(11), linear, are the same key: n = 14, delta = 0x1500.
On it Howard's policy iteration never terminates -- in certified_cycle_mean.c AND in
the Python solvers it transcribes.  Every node already holds the optimal mean; what
moves is the bias h, because each evaluation rooted h at whichever cycle node the
scan reached first, and with several cycles of EQUAL mean the h of two cycles are
then not comparable, so a "strict improvement" can be undone by the next one.  The
fix roots h at each cycle's smallest node.  mu does not depend on the root, and the
certificate (SPFA at mu' - 1e-9 on the full graph) is what makes the answer exact,
so nothing that already terminated can change -- checked on 744 random keys at
n = 7..16, both axes: mu, edges kept and certificate rounds identical.
""")
    n, d, axis = STUCK
    CCL = ESL.CCL
    cap = 300

    def run(canonical):
        """The certified solver's own rounds, with a capped Howard of either root."""
        log = []

        def capped(BS, WS):
            ok, it, m = _howard(BS, WS, canonical, cap)
            log.append((ok, it))
            if not ok:
                raise RuntimeError("Howard did not terminate")
            return m
        orig = CCL.howard_csr
        CCL.howard_csr = capped
        try:
            CCL.mu_lin(n, d)
        except RuntimeError:
            pass
        finally:
            CCL.howard_csr = orig
        return log
    old, new = run(False), run(True)
    print("  scan-order root : per certificate round (terminated, iterations) %s" % old)
    print("  canonical root  : per certificate round (terminated, iterations) %s" % new)
    check(old and not old[-1][0],
          "NEGATIVE CONTROL: with the old scan-order root, Howard does not terminate "
          "within %d iterations in certificate round %d of this key" % (cap, len(old)))
    check(new and all(ok for ok, _ in new),
          "with the cycle's smallest node as root every round terminates (%s "
          "iterations)" % " / ".join(str(i) for _, i in new))
    c = ESL.cmu(n, d, axis)
    p = CCL.mu_lin(n, d)
    print("  C solver        : mu = %.12f, %d edges, %d rounds" % c)
    print("  Python solver   : mu = %.12f, %d edges, %d rounds" % p[:3])
    check(abs(c[0] - p[0]) < 1e-9 and c[1:] == p[1:3],
          "the fixed C and Python certified solvers now both terminate on it and agree "
          "on mu, edges kept and certificate rounds")


# ═══════════════════════════════════════════════════════════════════════════
# §3  the period series, both residue classes, to n = 19
# ═══════════════════════════════════════════════════════════════════════════
TWELFTH_P13 = {0: (0.362, 0.003), 1: (0.199, 0.002)}   # §11.49.2's replication
CRITERION = {0: 4 / 3, 1: 2 / 3}


def curvature(rows):
    """Change in local exponent between the two intervals of three periods
    (n1, n2, n3), with the shared middle period's error counted once."""
    (n1, p1, e1), (n2, p2, e2), (n3, p3, e3) = rows
    L1 = math.log((n2 + 1.5) / (n1 + 1.5))
    L2 = math.log((n3 + 1.5) / (n2 + 1.5))
    x1 = math.log(p2 / p1) / L1
    x2 = math.log(p3 / p2) / L2
    r1, r2, r3 = e1 / p1, e2 / p2, e3 / p3
    se = math.sqrt((r1 / L1) ** 2 + (r2 * (1 / L1 + 1 / L2)) ** 2 + (r3 / L2) ** 2)
    return x1, x2, x2 - x1, se


def section_3(pinned):
    rule("§3  The period series, both residue classes, to n = 19")
    print("""P(n) = E[mu_{n+3}] - E[mu_n], one three-bit insertion per key (exact coupling,
§11.49.1), the run-count control variate at its exact mean.  Periods start at
n = 1 (mod 3) -- the series §11.49 measured -- and at n = 2 (mod 3).
""")
    P = {}
    for axis in (0, 1):
        print("  %s" % NAME[axis].upper())
        print("  %9s  %6s  %8s  %7s  %8s  %7s" % ("period", "pairs", "plain", "se",
                                                   "cv", "se"))
        for n, K in PLAN:
            mus = pinned[(n, axis)]
            p, e, pc, ec = period_stats(n, draws(n, K, axis), mus)
            P[(n, axis)] = (pc, ec)
            print("  %3d -> %2d  %6d  %8.4f  %7.4f  %8.4f  %7.4f"
                  % (n, n + 3, K, p, e, pc, ec))
        print()
    for axis in (0, 1):
        nm = NAME[axis]
        p13, e13 = P[(13, axis)]
        q, eq = TWELFTH_P13[axis]
        z = abs(p13 - q) / math.hypot(e13, eq)
        check(z < 3, "%s: P(13) on this seed, %.4f +- %.4f, reproduces §11.49.2's "
              "independent replication %.3f +- %.3f (%.1f sigma)" % (nm, p13, e13, q, eq, z))
        a = [m3 for _, m3 in pinned[(13, axis)]]
        b = [m0 for m0, _ in pinned[(16, axis)]]
        ma, mb = sum(a) / len(a), sum(b) / len(b)
        sa = math.sqrt(sum((v - ma) ** 2 for v in a) / (len(a) - 1) / len(a))
        sb = math.sqrt(sum((v - mb) ** 2 for v in b) / (len(b) - 1) / len(b))
        z = abs(ma - mb) / math.hypot(sa, sb)
        check(z < 3, "%s: E[mu_16] from two independent samples agrees -- the end of "
              "P(13), %.4f +- %.4f, and the start of P(16), %.4f +- %.4f (%.1f sigma)"
              % (nm, ma, sa, mb, sb, z))
        low = min((P[(n, axis)][0] / P[(n, axis)][1], n) for n, _ in PLAN)
        check(low[0] > 10,
              "%s: E[mu] RISES over every period to n = 19 -- the least significant is "
              "P(%d) at %.0f standard errors" % (nm, low[1], low[0]))
    out = {}
    for axis in (0, 1):
        nm = NAME[axis]
        for cls, starts in ((1, (7, 10, 13, 16)), (2, (8, 11, 14))):
            rows = [(n,) + P[(n, axis)] for n in starts]
            ex = []
            for (n1, p1, e1), (n2, p2, e2) in zip(rows, rows[1:]):
                x, xe = PE.exponent(n1, p1, e1, n2, p2, e2)
                ex.append("%d->%d %+.2f +- %.2f" % (n1, n2, x, xe))
            print("  %s, n = %d (mod 3): local exponents  %s" % (nm, cls, ";  ".join(ex)))
            first, last = rows[-2], rows[-1]
            z = (first[1] - last[1]) / math.hypot(first[2], last[2])
            check(z > 4, "%s, n = %d (mod 3): P falls over the last step, P(%d) = %.3f "
                  "to P(%d) = %.3f (%.1f standard errors)"
                  % (nm, cls, first[0], first[1], last[0], last[1], z))
            out[(axis, cls)] = rows
        x1, x2, dx, se = curvature(out[(axis, 1)][1:])
        print("  %s, n = 1 (mod 3): exponent %+.2f over 10 -> 13, %+.2f over 13 -> 16, "
              "change %+.2f +- %.2f" % (nm, x1, x2, dx, se))
        check(dx < -3 * se,
              "%s: the fall STEEPENS in the series §11.49 measured -- the local exponent "
              "moves from %+.2f to %+.2f, %.1f standard errors (§11.49's 'the decline is "
              "slowing' is WITHDRAWN)" % (nm, x1, x2, -dx / se))
        x1, x2, dx, se = curvature(out[(axis, 2)])
        print("  %s, n = 2 (mod 3): exponent %+.2f over 8 -> 11, %+.2f over 11 -> 14, "
              "change %+.2f +- %.2f -- printed, not scored" % (nm, x1, x2, dx, se))
        m19 = sum(m3 for _, m3 in pinned[(16, axis)]) / len(pinned[(16, axis)])
        print("  %s: E[mu_19] = %.3f, %.2fx the %s criterion; the last period adds "
              "%.3f per bit\n" % (nm, m19, m19 / CRITERION[axis],
                                   "4/3" if axis == 0 else "2/3", P[(16, axis)][0] / 3))
    return P


def section_4():
    rule("§4  What this changes for #257")
    print("""WITHDRAWN: §11.49's "the decline is itself slowing".  Its differential exponent
drifted from -0.55 to -0.23 over 7 -> 10 -> 13; one period further it is about -2,
on both axes, so the fall STEEPENS.  The n = 2 (mod 3) series, never measured before,
falls at every step too; its exponent does not steepen on the differential axis
(printed above, not scored), so the steepening is shown for the n = 1 series only.

UNCHANGED: monotonicity.  E[mu] rises over every period measured, to n = 19, by more
than ten standard errors each time, and E[mu_19] is about twice both criteria.

WHAT IT DOES TO THE n = 256 READINGS: both lose their premise.  §11.42's power law
assumed a fixed exponent near -0.37 / -0.16; the measured one is not fixed and is now
far steeper.  So P could reach zero within a few more periods -- then E[mu] would
level near twice the criteria, or turn down, and neither is excluded.  #257 is no
longer asking which of two growth curves holds.  It is asking whether E[mu] stays
above 4/3 and 2/3 at all, and the margin at n = 19 is about 2x, not 10x.

No rating moves: every row this touches is demo-only on other axes (§11.38.7).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    a = ap.parse_args()
    if a.regenerate:
        regenerate(a.workers)
        return 0
    print(__doc__)
    ESL.build()
    pinned = load_pinned()
    section_1(pinned, None if a.full else (2 if a.quick else 10))
    section_2()
    section_3(pinned)
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
