#!/usr/bin/env python3
"""nl_fscx_v3_trail_criterion.py — TODO #342: what NL-FSCX v3's trail floors actually
prove against its OWN criterion, axis by axis.

SECURITY.md's five v3 rows (and spec/'s notes for them) said two things that
cannot both hold: that chi gives the v3 round "an unconditional per-round trail
floor of 1.6781 bits differential and 1 bit linear", and that v3 has "no trail
bound at realistic width on either axis".  This script settles which is true.

  §1  THE CRITERION AT v3's ROUND COUNTS.  v3's round count is free, so its bars
      are not v2's 4/3 and 2/3.  At R3 = 5n/8 = 160 (n = 256) a trail is dead once
      s_diff >= 256/160 = 1.6 and s_lin >= 128/160 = 0.8; the duplex at I3 = 80
      against its 128-bit capacity needs the SAME two numbers.

  §2  DIFFERENTIAL: PROVEN, AT EVERY WIDTH.  §11.34.3's floor 4 - log2(5) =
      1.6781 is a ROUND-LEVEL bound -- on the round's own DDT entry, carry
      clustering included -- so every r-round characteristic has weight at least
      1.6781 r.  1.6781 >= 1.6: v3 HAS a differential trail bound at n = 256,
      at 1.049x.  Checked against the exhaustive full-round DDT at n = 10.

  §3  LINEAR: NOT PROVEN.  The "1 bit" is §11.33.2's LAYER-WISE floor, charged
      to chi with the mask between the addition and chi held fixed.  The round's
      own LAT sums over that mask, and its proven round-level floor is §11.34.2's
      0.1926 bits -- below 0.8.  NEGATIVE CONTROL: the full round at n = 10 has
      LAT entries of weight 0.1926, so the layer-wise floor is not a bound on
      the round.

  §4  THE EXACT ASYMPTOTIC SLOPES AT n = 10.  The minimum mean cycle of the
      round-level graph, certified by a potential, per key.  The differential
      slope never falls below §2's proven floor (a consistency check on the
      proof); the linear slope clears 0.8 for EVERY key, least 1.1785 at key
      0x095 (1.47x), median 1.52 -- exhaustive over all 1024 keys with --full,
      and the two worst keys are in every run.  One width, and not a bound.

  §5  WHAT THIS CHANGES.  Prose.

Pure Python, no solver: the gate is exact and cannot flake.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/nl_fscx_v3_trail_criterion.py [--quick | --full]
      --quick : §4 on the 4 pinned keys   (~30 s on an aarch64 SBC)
      default : §4 on 10 keys             (~1 min)
      --full  : §4 on all 1024 keys       (~1.5 h single-core)
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

N256, R3, I3, CAPACITY = 256, 160, 80, 128
FLOOR_DIFF = 4 - math.log2(5)          # §11.34.3, round-level
FLOOR_LIN_ROUND = -math.log2(0.875)    # §11.34.2, round-level
FLOOR_LIN_LAYER = 1.0                  # §11.33.2, layer-wise
# The exhaustive extremes at n = 10 (all 1024 keys, --full): key 0x095 has the
# least linear slope, key 0x009 (one of several) the least differential one.
WORST = ((0x095, 2.5229018448, 1.1784847499), (0x009, 2.5, 1.5981674216))


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


WK = _load("nl_fscx_v3_weak_keys.py")   # Width, fwht
W10 = WK.Width(10, (5, 5))              # smallest legal width (§11.34.4)


def w(p):
    return -math.log2(p) if p > 0 else math.inf


# ═══════════════════════════════════════════════════════════════════════════
# the round-level graphs at n = 10
# ═══════════════════════════════════════════════════════════════════════════
def ddt_graph(T):
    """Edges a -> b, weight -log2 DDT[a][b], over nonzero differences."""
    N = len(T)
    BS, WS = [[]], [[]]
    for a in range(1, N):
        c = Counter(T[x] ^ T[x ^ a] for x in range(N))
        bs = [b for b in c if b]
        BS.append(bs)
        WS.append([w(c[b] / N) for b in bs])
    return BS, WS


def lat_graph(T):
    """Edges u -> v (input mask to output mask), weight -log2 |corr|."""
    N = len(T)
    col = [[0.0] * N for _ in range(N)]          # col[v][u] = |corr(u.x, v.T(x))|
    for v in range(1, N):
        par = [1 if not (bin(v & T[x]).count("1") & 1) else -1 for x in range(N)]
        WK.fwht(par)
        col[v] = [abs(z) / N for z in par]
    BS, WS = [[]], [[]]
    for u in range(1, N):
        bs = [v for v in range(1, N) if col[v][u] > 0]
        BS.append(bs)
        WS.append([w(col[v][u]) for v in bs])
    return BS, WS, max(col[v][u] for v in range(1, N) for u in range(1, N))


def min_mean_cycle(BS, WS, cap=500):
    """Howard's policy iteration (min form, h rooted at each cycle's smallest
    node -- §11.50.3's fix), then a one-pass POTENTIAL CERTIFICATE: if every
    edge u -> v satisfies h[u] <= w - mu + h[v], every cycle has mean >= mu, and
    the policy cycle attains it.  Returns (mu, iterations, certified)."""
    eps = 1e-9
    N = len(BS)
    nodes = range(1, N)
    pi, pw = [0] * N, [0.0] * N
    for v in nodes:
        j = min(range(len(WS[v])), key=WS[v].__getitem__)
        pi[v], pw[v] = BS[v][j], WS[v][j]
    for it in range(1, cap + 1):
        mu, h = [0.0] * N, [0.0] * N
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
            bs, ws = BS[v], WS[v]
            for j in range(len(bs)):
                b = bs[j]
                cmu = mu[b]
                if cmu < bmu - eps:
                    bmu, bh, bj = cmu, ws[j] - cmu + h[b], j
                elif cmu <= bmu + eps:
                    ch = ws[j] - cmu + h[b]
                    if ch < bh - eps:
                        bmu, bh, bj = cmu, ch, j
            if bj >= 0:
                pi[v], pw[v] = BS[v][bj], WS[v][bj]
                improved = True
        if not improved:
            break
    else:
        return None, cap, False
    m = min(mu[v] for v in nodes)
    ok = all(h[u] <= WS[u][j] - m + h[BS[u][j]] + 1e-7
             for u in nodes for j in range(len(BS[u])))
    return m, it, ok


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The criterion at v3's own round counts")
    print("""§11.30.1: a differential trail dies once s_diff * r >= n, a linear one once
s_lin * r >= n/2.  v2's round count is tied to n (3n/4), so its bars collapse to
4/3 and 2/3.  v3's round count is FREE (5n/8), and so are its bars:
""")
    rows = [("hske-nla3 / twk --v3 / fpe --v3 / hpke-nl3", R3, N256),
            ("hske-duplex3 (capacity target)", I3, CAPACITY)]
    for name, r, target in rows:
        print("  %-44s r = %3d, target %3d bits: s_diff >= %.3f, s_lin >= %.3f"
              % (name, r, target, target / r, target / 2 / r))
    check(N256 / R3 == CAPACITY / I3 == 1.6 and N256 / 2 / R3 == CAPACITY / 2 / I3 == 0.8,
          "both v3 round counts need the same two per-round figures: s_diff >= 1.6 "
          "and s_lin >= 0.8 -- NOT v2's 4/3 and 2/3")


def section_2(keys):
    rule("§2  Differential: a proven trail bound, at every width")
    print("""§11.34.3's lowest-active-row lemma bounds the round's OWN DDT entry -- the sum over
every intermediate difference, carry clustering included -- by 5/16, for every key
at every width.  So every r-round characteristic has weight >= %.4f r.
""" % FLOOR_DIFF)
    check(FLOOR_DIFF >= 1.6,
          "the proven round-level floor %.4f clears v3's differential bar 1.6, at "
          "%.3fx: v3 HAS a differential trail bound at n = 256 (%.1f bits over %d "
          "rounds, against %d needed)" % (FLOOR_DIFF, FLOOR_DIFF / 1.6,
                                          FLOOR_DIFF * R3, R3, N256))
    worst = 0.0
    for B in keys:
        T = W10.v3_table(B)
        worst = max(worst, W10.max_ddt(T))
    check(abs(worst - 5 / 16) < 1e-12,
          "the exhaustive full-round DDT at n = 10 never exceeds 5/16 and attains it "
          "(%d keys, all 2^10 input differences each): the floor bounds the round, "
          "and is tight" % len(keys))


def section_3(keys):
    rule("§3  Linear: the 1-bit floor is layer-wise, and the round beats it")
    print("""§11.33.2's linear floor of 1 bit charges chi alone, with the mask between the
addition and chi held FIXED.  The round's own LAT entry sums over that mask, and
the proven round-level floor is §11.34.2's single-row bound, %.4f bits -- %.2fx
too small for the 0.8 bar.
""" % (FLOOR_LIN_ROUND, 0.8 / FLOOR_LIN_ROUND))
    best = 0.0
    for B in keys:
        best = max(best, lat_graph(W10.v3_table(B))[2])
    check(abs(best - 0.875) < 1e-12,
          "NEGATIVE CONTROL: the full round at n = 10 attains |corr| = 0.875, weight "
          "%.4f -- below the layer-wise 1 bit AND below the 0.8 bar in a single "
          "round (%d keys): the layer-wise floor does NOT bound the round"
          % (w(best), len(keys)))
    check(FLOOR_LIN_ROUND * R3 < N256 / 2,
          "the proven round-level linear floor gives only %.1f bits over %d rounds, "
          "against %d needed: v3 has NO proven linear trail bound at n = 256"
          % (FLOOR_LIN_ROUND * R3, R3, N256 // 2))
    check(FLOOR_LIN_LAYER * R3 >= N256 / 2,
          "in the layer-wise model alone it would clear, %d >= %d bits -- which is "
          "the figure the rows were quoting" % (FLOOR_LIN_LAYER * R3, N256 // 2))


def section_4(keys):
    rule("§4  The exact asymptotic slopes at n = 10, per key")
    print("""The minimum mean cycle of the round-level DDT and LAT graphs (1023 nodes, every
edge), by Howard's iteration and certified by a potential: every cycle has mean
at least the figure printed, and one attains it.
""")
    print("  %7s  %10s  %10s  %5s" % ("key", "diff", "linear", "iters"))
    D, L = [], []
    for B in keys:
        T = W10.v3_table(B)
        md, itd, okd = min_mean_cycle(*ddt_graph(T))
        BS, WS, _ = lat_graph(T)
        ml, itl, okl = min_mean_cycle(BS, WS)
        if not (okd and okl):
            check(False, "key 0x%03x: Howard did not terminate or the certificate "
                  "failed" % B)
            continue
        D.append(md)
        L.append(ml)
        print("  0x%03x  %10.4f  %10.4f  %2d/%2d" % (B, md, ml, itd, itl))
    if not D:
        return
    for B, want_d, want_l in WORST:
        if B in keys:
            i = keys.index(B)
            check(abs(D[i] - want_d) < 1e-6 and abs(L[i] - want_l) < 1e-6,
                  "key 0x%03x, pinned as an exhaustive extreme at n = 10, reproduces "
                  "diff %.4f / linear %.4f" % (B, want_d, want_l))
    check(len(D) == len(keys),
          "every slope is CERTIFIED: a potential with h[u] <= w - mu + h[v] on every "
          "edge, so no cycle is cheaper (%d keys, both axes)" % len(keys))
    check(min(D) >= FLOOR_DIFF - 1e-9,
          "no key's differential slope falls below the proven floor %.4f (least "
          "%.4f) -- the measurement agrees with the proof" % (FLOOR_DIFF, min(D)))
    check(min(L) > 0.8,
          "every key's linear slope clears v3's 0.8 bar at n = 10 (least %.4f, "
          "%.2fx)" % (min(L), min(L) / 0.8))
    print("\n  linear slope: least %.4f, median %.4f, %.2fx the bar at the least"
          % (min(L), sorted(L)[len(L) // 2], min(L) / 0.8))


def section_5():
    rule("§5  What this changes")
    print("""CORRECTED, in all five v3 rows of SECURITY.md and spec/'s notes:

  * "1.6781 bits differential and 1 bit linear" quoted two floors of different
    kinds side by side.  1.6781 is round-level; the 1 bit is layer-wise, and the
    round-level linear floor is 0.1926.

  * "no trail bound at realistic width on either axis" was wrong on one axis.
    The differential floor clears v3's own bar (1.6, not v2's 4/3) at every
    width, so v3 has a proven differential TRAIL bound at n = 256 -- at 1.049x,
    so with no room to trim R3.  Differential HULLS are not covered.

  * The linear axis is genuinely open, and it is a different question from
    v2's: the bar is 0.8, not 2/3, and the round is v3's.  At n = 10 the exact
    slope clears it for every one of the 1024 keys, by 1.47x at worst; v2's own
    history (§11.42-§11.51) shows how far small-width figures can be from
    n = 256.  Filed as TODO #257's item (3), beside v2's two axes.

UNCHANGED: every v3 rating.  None of the five rows is demo-only for want of a
trail bound alone; the missing PRP/SPRP reduction and, for the duplex, the
uncharacterised sponge profile (TODO #99) stand.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    fixed = [0b1011010011, 0b0110101101]              # §11.34.6's two keys
    rnd = random.Random(342)
    sample = fixed + [rnd.randrange(W10.N) for _ in range(6)]
    pinned = fixed + [B for B, _, _ in WORST]
    keys4 = (list(range(W10.N)) if a.full else pinned if a.quick
             else pinned + sample[2:])
    section_1()
    section_2(sample)
    section_3(sample)
    section_4(keys4)
    section_5()
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
