#!/usr/bin/env python3
"""nl_fscx_v3_linear_width.py — TODO #257 item (3): NL-FSCX v3's exact linear slope
past n = 10, against v3's own bar s_lin >= 0.8.

TODO #342 (nl_fscx_v3_trail_criterion.py, SecurityProofs-10.md §11.52) left v3's
linear axis open: the round-level floor is only 0.1926 bits, and the exact
asymptotic slope -- the minimum mean cycle of the round's own LAT graph -- had
been measured at n = 10 alone, where it clears 0.8 for all 1024 keys.  This
script takes the same measurement to the next two widths with a legal row
partition and an invertible M, n = 14 (rows 7, 7) and n = 17 (rows 5, 5, 7).

  §1  THE SOLVER, CHECKED.  v3_round_mmc.c holds the graph implicitly and
      certifies every answer with a potential checked against EVERY edge.  It
      must reproduce the Python solver of nl_fscx_v3_trail_criterion.py, and its
      pinned n = 10 extremes, on both axes.

  §2  NEGATIVE CONTROL: THE CERTIFICATE FIRES.  On a subgraph that holds too few
      edges, Howard's answer is wrong; the certificate must find the edges that
      refute it, and the loop must end at the true value.

  §3  n = 14 (rows 7, 7).  Pinned keys of a 2048-key uniform sample reproduce.

  §4  n = 17 (rows 5, 5, 7).  The least-linear key of a 24-key uniform sample
      reproduces (not in --quick, which reports n/a).

  §5  THE LSB-ROW CEILING.  The lowest row of the addition has no carry in.  For
      masks confined to an LSB row of length L, v.T(x) reads only x's bits
      0..L and n-1, so every such LAT entry -- and every cycle through such
      masks -- is a function of delta(B) mod 2^L alone, the SAME at every width
      n >= L + 2.  Its minimum mean cycle is therefore an UPPER bound on the
      key's slope at every width, n = 256 included.  For L = 5 (the deployed
      LSB row) the least such value is 1.4150, at delta(B) = 5 mod 8: the worst
      key's linear margin at n = 256 is AT MOST 1.77x the 0.8 bar.  Checked
      exactly (the full-width LAT entries ARE the local ones) and against every
      key measured.  It bounds the margin from above; it proves no floor.

  §6  THE DISTRIBUTIONS.  The recorded per-width figures, and what they do and
      do not show.  --full re-solves the whole sample and holds it to the record.

Needs a C compiler; absent means FAIL, hull_exact.py's precedent: the helper IS
the gate, so there is nothing left to skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/nl_fscx_v3_linear_width.py [--quick | --full]
      --quick : §1-§3, §5 at n = 10      (~1 min on an aarch64 SBC, 8 threads)
      default : also §4's pinned key, §5 at n = 14   (~5 min)
      --full  : §3-§6 over the whole sample (~6 h)
"""

import argparse
import importlib.util
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CSRC = os.path.join(HERE, "v3_round_mmc.c")
FAIL = []
EXE = None
THREADS = max(1, min(os.cpu_count() or 1, 64))
BAR_LIN, FLOOR_DIFF = 0.8, None          # FLOOR_DIFF set from TC below

ROWS = {10: (5, 5), 14: (7, 7), 17: (5, 5, 7)}
SAMPLE = {14: 2048, 17: 24}              # random.Random(25703 + n).sample
SEED = 25703

# ── the record, from the --full run (v9.5.46) ───────────────────────────────
# per width: keys, (least, 1st percentile, median, most) of each axis, and how
# many keys' linear slope EQUALS their §5 LSB-row value.  n = 10 is
# nl_fscx_v3_trail_criterion.py's exhaustive run (all 1024 keys), not resolved here.
RECORD = {
    10: (1024, (2.5, 2.5, 3.0, 3.6666666667),
         (1.1784847499, 1.2382696281, 1.5243629814, 1.7660149997), 225),
    14: (2048, (3.0, 3.0, 3.0, 4.0),
         (1.6066095426, 1.6780719051, 1.8692275257, 2.0), 1587),
    17: (24, (3.0, 3.0, 3.0, 3.9125371587),
         (1.4150374993, 1.4150374993, 1.6666666667, 2.0), 16),
}
# keys pinned per width: (key, differential mu, linear mu)
PINNED = {
    14: ((0x1c2d, 3.0, 1.6780719051),        # on its 7-row LSB value, the 7-row least
         (0xe7a, 3.0, 1.6066095426),         # the sample's least, BELOW its LSB value
         (0x332d, 3.0, 1.8692275257)),       # the sample's median
    17: ((0x13a7e, 3.0, 1.4150374993),),     # the sample's least, ON the 5-row ceiling
}
CEIL5 = 1.4150374993                         # §5, L = 5, delta(B) = 5 mod 8
CEIL7 = 1.6780719051                         # §5, L = 7


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


TC = _load("nl_fscx_v3_trail_criterion.py")
FLOOR_DIFF = TC.FLOOR_DIFF
WK = TC.WK


def build():
    global EXE
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        print("  no C compiler found (gcc/cc/clang): this gate cannot run.")
        print("  install one, e.g.  sudo apt-get install -y gcc")
        sys.exit(1)
    exe = os.path.join(tempfile.mkdtemp(prefix="v3mmc_"), "v3_round_mmc")
    r = subprocess.run([cc, "-O2", "-o", exe, CSRC, "-lm", "-lpthread"],
                       capture_output=True, text=True)
    if r.returncode:
        print(r.stderr)
        print("  v3_round_mmc.c FAILED TO BUILD with a present compiler")
        sys.exit(1)
    EXE = exe


def solve(n, B, axis, cap=3.0):
    """(mu, rounds, certified, cycle length, round-1 mu, round-1 violators)."""
    r = subprocess.run([EXE, str(n), "%x" % B, str(axis), str(THREADS), str(cap)]
                       + [str(L) for L in ROWS[n]], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("v3_round_mmc %d %x %d: rc=%d %s"
                           % (n, B, axis, r.returncode, r.stderr))
    head = r.stdout.split("\n")[0].split()
    first = [l for l in r.stderr.splitlines() if l.strip().startswith("round 1:")][0]
    mu1 = float(first.split("mu ")[1].split(",")[0])
    viol1 = int(first.split(", ")[-1].split()[0])
    return float(head[0]), int(head[1]), head[2] == "1", int(head[3]), mu1, viol1


def sample_keys(n):
    return random.Random(SEED + n).sample(range(1 << n), SAMPLE[n])


def quantiles(xs):
    s = sorted(xs)
    return s[0], s[len(s) // 100], s[len(s) // 2], s[-1]


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The C solver against the Python one, at n = 10")
    keys = [0b1011010011, 0b0110101101] + [B for B, _, _ in TC.WORST]
    print("  %7s  %12s %12s   %12s %12s" % ("key", "diff (C)", "diff (py)",
                                            "lin (C)", "lin (py)"))
    ok = True
    for B in keys:
        T = TC.W10.v3_table(B)
        pd, _, okd = TC.min_mean_cycle(*TC.ddt_graph(T))
        BS, WS, _ = TC.lat_graph(T)
        pl, _, okl = TC.min_mean_cycle(BS, WS)
        cd = solve(10, B, 0)
        cl = solve(10, B, 1)
        print("  0x%03x  %12.10f %12.10f   %12.10f %12.10f"
              % (B, cd[0], pd, cl[0], pl))
        ok &= okd and okl and cd[2] and cl[2]
        ok &= abs(cd[0] - pd) < 1e-8 and abs(cl[0] - pl) < 1e-8
    check(ok, "v3_round_mmc.c reproduces nl_fscx_v3_trail_criterion.py's certified "
          "minimum mean cycle on both axes, %d keys, every answer certified by both"
          % len(keys))
    for B, want_d, want_l in TC.WORST:
        d, l = solve(10, B, 0)[0], solve(10, B, 1)[0]
        check(abs(d - want_d) < 1e-8 and abs(l - want_l) < 1e-8,
              "key 0x%03x, an exhaustive n = 10 extreme, reproduces diff %.10f / "
              "linear %.10f" % (B, want_d, want_l))


def section_2():
    rule("§2  Negative control: the certificate fires")
    print("""With the cap at 1 bit, the first subgraph G' holds only each node's cheapest
edge and the few under 1 bit.  Howard's optimum there is NOT the graph's: the
certificate pass must find edges that violate the potential, and the loop must
end at the value §1 confirmed.
""")
    B, _, want_l = TC.WORST[1]
    mu, rounds, cert, _, mu1, v1 = solve(10, B, 1, cap=1.0)
    print("  key 0x%03x linear, cap 1: round 1 mu %.10f with %d violators; final "
          "%.10f after %d rounds" % (B, mu1, v1, mu, rounds))
    check(v1 > 0 and mu1 > want_l + 1e-6,
          "on too small a subgraph the first answer is WRONG (%.4f > %.4f) and the "
          "certificate rejects it (%d violating edges)" % (mu1, want_l, v1))
    check(cert and rounds > 1 and abs(mu - want_l) < 1e-8,
          "the loop then ends certified at the true value %.10f" % want_l)


def section_width(n, keys):
    rule("§%d  n = %d, rows %s" % (3 if n == 14 else 4, n, ROWS[n]))
    if not keys:
        print("  n/a: not run in --quick (one key is ~6 min here)")
        return None
    L0 = ROWS[n][0]
    pinned = dict((B, (d, l)) for B, d, l in PINNED.get(n, ()))
    D, L = [], []
    for B in keys:
        d, l = solve(n, B, 0), solve(n, B, 1)
        if not (d[2] and l[2]):
            check(False, "n = %d key 0x%x: the certificate did not close" % (n, B))
            continue
        D.append(d[0])
        L.append(l[0])
        LOCALS.append((n, B, l[0], L0, d_low(n, B, L0)))
        if B in pinned:
            wd, wl = pinned[B]
            check(abs(d[0] - wd) < 1e-8 and abs(l[0] - wl) < 1e-8,
                  "n = %d key 0x%x, pinned, reproduces diff %.10f / linear %.10f"
                  % (n, B, wd, wl))
    if D:
        check(min(D) >= FLOOR_DIFF - 1e-9,
              "no differential slope at n = %d falls below the proven floor %.4f "
              "(least %.4f, %d keys)" % (n, FLOOR_DIFF, min(D), len(D)))
    return D, L


LOCAL = {}           # L -> [min mean cycle of the LSB-row graph, per delta mod 2^L]
LOCALS = []          # (n, key, full linear slope, LSB-row value), from §3-§4;
                     # §3-§4 store (L, delta mod 2^L) in place of the value, §5 resolves it


def d_low(n, B, L):
    """delta(B) mod 2^L at width n -- Width.delta(), low L bits."""
    M = (1 << n) - 1
    p = (B * ((B + 1) >> 1)) & M
    k = n // 4
    return (((p << k) | (p >> (n - k))) & M) & ((1 << L) - 1)


def local_lat(L, dl):
    """|LAT| of the LSB row of length L, as counts out of 2^(L+2).

    Variables z: bit 0 = y_{n-1}, bits 1..L+1 = y_0..y_L, with y = x ^ B.  The
    row's output is chi_L((M y mod 2^L) + dl mod 2^L): no carry enters bit 0, and
    (M y)_i reads y_{i-1}, y_i, y_{i+1}.  Returns C[v][u] for input masks u and
    output masks v on the row's L bits."""
    K = L + 2
    out = []
    for z in range(1 << K):
        m = 0
        for i in range(L):
            m |= (((z >> i) ^ (z >> (i + 1)) ^ (z >> (i + 2))) & 1) << i
        out.append(WK.chi_row((m + dl) & ((1 << L) - 1), L))
    C = [[0] * (1 << L) for _ in range(1 << L)]
    for v in range(1, 1 << L):
        par = [-1 if bin(v & o).count("1") & 1 else 1 for o in out]
        WK.fwht(par)
        for u in range(1, 1 << L):
            C[v][u] = abs(par[u << 1])
    return C, 1 << K


def local_mmc(L, C, N):
    """Certified minimum mean cycle over masks 1..2^L - 1, by
    nl_fscx_v3_trail_criterion.py's Howard + potential.  A mask with no out-edge
    lies on no cycle, so such masks are pruned first (repeatedly), which Howard
    needs: every node must carry a policy."""
    V = 1 << L
    live = set(range(1, V))
    while True:
        dead = {u for u in live if not any(C[v][u] for v in live)}
        if not dead:
            break
        live -= dead
    order = sorted(live)
    idx = {u: i + 1 for i, u in enumerate(order)}
    BS, WS = [[]], [[]]
    for u in order:
        bs = [idx[v] for v in order if C[v][u]]
        BS.append(bs)
        WS.append([TC.w(C[order[j - 1]][u] / N) for j in bs])
    mu, _, ok = TC.min_mean_cycle(BS, WS)
    if not ok:
        check(False, "L = %d: the LSB-row cycle mean was not certified" % L)
    return mu


def full_column_matches(n, B, L, wrong=0):
    """Every full-width LAT entry between masks on the LSB row equals the local
    one.  `wrong` offsets the local table's delta -- the negative control."""
    W = WK.Width(n, ROWS[n])
    T = W.v3_table(B)
    C, NL = local_lat(L, (d_low(n, B, L) + wrong) % (1 << L))
    for v in range(1, 1 << L):
        par = [-1 if bin(v & t).count("1") & 1 else 1 for t in T]
        WK.fwht(par)
        for u in range(1, 1 << L):
            if abs(par[u]) * NL != C[v][u] * W.N:
                return False
    return True


def section_5(quick):
    rule("§5  The LSB-row ceiling")
    print("""The addition's lowest row has no carry in.  An output mask v on an LSB row of
length L reads x's bits 0..L and n-1 only, so the LAT entry between two masks on
that row depends on delta(B) mod 2^L and on nothing else: it is the same entry
at every width n >= L + 2.  Every cycle through such masks is a cycle of the
full round-level graph, with the same mean -- so its minimum mean cycle is an
UPPER bound on the key's linear slope, at every width, n = 256 included.
""")
    for L in (5, 7):
        LOCAL[L] = [local_mmc(L, *local_lat(L, dl)) for dl in range(1 << L)]
        lo = min(LOCAL[L])
        print("  L = %d: least %.10f at delta mod 2^%d in %s, most %.4f"
              % (L, lo, L, [d for d, x in enumerate(LOCAL[L]) if x < lo + 1e-9],
                 max(LOCAL[L])))
    check(abs(min(LOCAL[5]) - CEIL5) < 1e-9 and
          [d for d, x in enumerate(LOCAL[5]) if x < CEIL5 + 1e-9] == [5, 13, 21, 29],
          "the 5-row LSB graph's least cycle mean is %.4f, at delta(B) = 5 mod 8 -- "
          "4 of the 32 classes" % CEIL5)
    check(abs(min(LOCAL[7]) - CEIL7) < 1e-9,
          "the 7-row LSB graph's least cycle mean is %.4f" % CEIL7)
    check(CEIL5 > BAR_LIN,
          "the ceiling clears the bar (%.2fx): it limits the margin, it does not "
          "threaten it" % (CEIL5 / BAR_LIN))
    rnd = random.Random(342)
    seen = [d_low(256, rnd.getrandbits(256), 5) for _ in range(4096)]
    hit = sum(1 for d in seen if d % 8 == 5)
    check(len(set(seen)) == 32 and 0.09 < hit / len(seen) < 0.16,
          "at n = 256, delta(B) mod 32 takes all 32 values over 4096 keys, and "
          "%.1f%% of them are 5 mod 8 (about one key in eight)" % (100.0 * hit / len(seen)))
    print("""
The deployed partition at n = 256 has a 5-row at the LSB, and delta(B) mod 32
takes every value over the keys.  So at n = 256 every key with delta(B) = 5 mod 8
has linear slope AT MOST %.4f: v3's worst-key linear margin over the 0.8 bar is
at most %.2fx, at every width.  A ceiling, not a floor.
""" % (CEIL5, CEIL5 / BAR_LIN))
    cases = [(10, B) for B in (0x095, 0x009, 0b1011010011)]
    if not quick:
        cases += [(14, PINNED[14][0][0])]
    ok = all(full_column_matches(n, B, ROWS[n][0]) for n, B in cases)
    check(ok, "the full-width LAT entries between LSB-row masks EQUAL the local "
          "ones, exactly (%s)" % ", ".join("n = %d key 0x%x" % c for c in cases))
    check(not full_column_matches(10, 0x095, 5, wrong=1),
          "NEGATIVE CONTROL: against the local table of the WRONG delta class the "
          "same comparison fails, so the match is not vacuous")
    T10 = []
    for B in (0x095, 0x009, 0b1011010011, 0b0110101101):
        BS, WS, _ = TC.lat_graph(TC.W10.v3_table(B))
        T10.append((10, B, TC.min_mean_cycle(BS, WS)[0], LOCAL[5][d_low(10, B, 5)]))
    LOCALS[:] = [(n, B, mu, LOCAL[L][dl]) for n, B, mu, L, dl in LOCALS]
    rows = T10 + LOCALS
    bad = [r for r in rows if r[2] > r[3] + 1e-9]
    check(not bad, "no key's full linear slope exceeds its LSB-row value (%d keys "
          "solved in this run, n = %s)" % (len(rows), sorted({r[0] for r in rows})))
    on = [r for r in LOCALS if r[0] == 17 and abs(r[2] - r[3]) < 1e-9]
    if any(r[0] == 17 for r in LOCALS):
        check(bool(on) and abs(on[0][2] - CEIL5) < 1e-9,
              "n = 17's least-linear sampled key sits exactly ON the 5-row ceiling, "
              "%.4f: the ceiling is attained" % CEIL5)


def section_6(full):
    rule("§6  The distributions")
    print("  %3s %-8s %5s  %-35s  %-35s  %s" % (
        "n", "rows", "keys", "differential: least p1 median most",
        "linear: least p1 median most", "on LSB value"))
    for n in sorted(RECORD):
        k, d, l, on = RECORD[n]
        print("  %3d %-8s %5d  %8.4f %8.4f %8.4f %8.4f  %8.4f %8.4f %8.4f %8.4f  %4.0f%%"
              % ((n, "/".join(map(str, ROWS[n])), k) + d + l + (100.0 * on / k,)))
    print("""
The partitions differ, and the figures follow them: n = 14 is all 7-rows, while
n = 10 and n = 17, like the deployed 47 x 5 + 3 x 7, have a 5-row at the LSB.
On the 5-row widths the least slope ROSE from n = 10 (exhaustive) to n = 17
(sampled) and the share of keys whose slope IS their LSB-row value grew; the
least at n = 17 is the ceiling itself.  One exhaustive width and one
sampled one: not a trend.
""")
    for n in sorted(RECORD):
        k, d, l, _ = RECORD[n]
        check(l[0] > BAR_LIN,
              "n = %d: every recorded key's linear slope clears v3's 0.8 bar (least "
              "%.4f, %.2fx; %d keys)" % (n, l[0], l[0] / BAR_LIN, k))
    for n, got in full.items():
        D, L = got
        k, d, l, on = RECORD[n]
        got_on = sum(1 for r in LOCALS if r[0] == n and abs(r[2] - r[3]) < 1e-9)
        check(got_on == on, "--full: %d of the n = %d keys sit on their LSB-row "
              "value, as recorded" % (on, n))
        check(len(D) == k and all(abs(a - b) < 1e-8 for a, b in zip(quantiles(D), d))
              and all(abs(a - b) < 1e-8 for a, b in zip(quantiles(L), l)),
              "--full: the n = %d sample re-solved reproduces the recorded "
              "distribution on both axes" % n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    build()
    section_1()
    section_2()
    full = {}
    for n in (14, 17):
        if a.full:
            keys = sample_keys(n)
        elif a.quick and n == 17:
            keys = []
        else:
            keys = [B for B, _, _ in PINNED.get(n, ())]
            if a.quick:
                keys = keys[:2]
        got = section_width(n, keys)
        if a.full and got:
            full[n] = got
    section_5(a.quick)
    section_6(full)
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
