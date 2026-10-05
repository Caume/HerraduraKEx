#!/usr/bin/env python3
"""hull_exact.py — TODO #257 (eighth pass): the linear hull, MEASURED.

#257 has carried two obligations since it merged #252 and #254.  The first is
monotonicity of exact mu in n, which seven passes have worked on.  The second has
been carried forward unchanged from §11.36.9 by every one of them: every number
in this line of work is a TRAIL weight, while what an attacker gets is the HULL --
the sum over every trail sharing the endpoints, with signs -- and "no method in
this line of work reaches the hull" (§11.38.7, §11.40, §11.41, §11.42, §11.43,
§11.44).  This pass reaches it, at the widths where it can be reached exactly.

The object is not a model.  For a fixed key B, the r-round map

    P_r = F_r o ... o F_1,     F_i(x) = M(x ^ i ^ B) + delta(B)   mod 2^n

-- the SHIPPED round, with TODO #245's round constants, which change only signs on
a trail and so were invisible to every trail measurement -- is built as a table,
and its full correlation and difference tables are scanned for the largest
nontrivial entry.  No trail, no independence, no key averaging, no Markov
assumption: H_lin(r) and H_diff(r) are what the cipher at that width actually
has.  Beside them, the best r-round TRAIL on each axis, T_lin(r) and T_diff(r),
and the ideal-cipher floor (the same scan over uniformly random permutations).

  §1  SOUNDNESS.  The C helper (hull_exact.c) reproduces the shipped
      nl_fscx_revolve_v2 on every input at n = 16; its hulls and trails agree
      with a pure-Python brute force at n = 7; one round has a correlation-1
      and a probability-1 approximation on every key (the MSB freebie, which
      the hull keeps); and the NEGATIVE CONTROL -- the same round with "+"
      replaced by "^", an affine map -- reads 0 bits at every round, so the
      scan can report a failure.

  §2  HULL AGAINST TRAIL, per width.  Before the hull saturates at the floor,
      it runs BELOW the best trail: clustering is real.  It is a SHARE, not
      an offset -- at the last round before saturation the hull keeps a median
      0.91 -> 0.82 of the trail's weight on the linear axis and 0.97 -> 0.90 on
      the differential over n = 10..16 (worst key 0.71) -- and the share FALLS,
      about 0.011 per bit on both axes.  In rounds it costs about ONE at every
      width: the hull reaches the ideal floor at most two rounds, typically one,
      after the best trail does, outside #253's tz(delta) >= 4 class, which is
      slow on the trail already.

  §3  WHAT THE TRAIL MISSES: LATE, NOT STUCK.  Six (key, axis) cells at
      n <= 11 clear the floor on the trail by r = 3n/4 and do NOT on the hull.
      The count is about what an ideal cipher would show at this threshold;
      what is pinned is that every one reaches the floor within two more
      rounds -- §2's one-round lag crossing 3n/4 where 3n/4 leaves no slack.
      Under --full one more appears at n = 16, late by one.

  §4  WHAT THIS CHANGES.  Prose.

What this does NOT do: it does not reach n = 256, or any width a trail
measurement does not already reach -- an exact hull costs n * 4^n -- so the
transfer to n = 256 is NOT available: the share falls with n, so it is a
third extrapolation question shaped like the first.  It turns #257's second
obligation from "unreached" into "measured to n = 14 (16 under --full): a
proportional correction that grows slowly with width".

Fixed keys and an exact computation, so the verdict cannot flake.  Needs a C
compiler (absent means FAIL, exact_slope_ladder.py's precedent: the helper IS
the gate above n = 8).

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/hull_exact.py [--quick | --full]
      --quick : n = 7, 8, 10, 11, 13                   (~1 min on an aarch64 SBC, 8 cores)
      default : adds n = 14                            (~5 min)
      --full  : adds n = 16, eight keys                (~80 min)
"""

import argparse
import importlib.util
import math
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CSRC = os.path.join(HERE, "hull_exact.c")
FAIL = []
EXE = None

# A hull counts as AT THE FLOOR once its largest entry is no larger than the
# largest seen across the random permutations at its width -- i.e. this
# statistic cannot tell it from an ideal cipher.  A fixed tolerance around the
# median does not work: at small n the tables are coarsely quantised and a
# first draft with a 0.25-bit band flagged nine keys that were merely inside
# the random spread.  A round counts as PRE-saturation while the trail is at
# least PRE below the MEDIAN floor and at least LO bits (a ratio of two numbers
# near zero says nothing).
PRE, LO = 0.5, 1.0
EXTRA = 3


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def build():
    global EXE
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        print("  no C compiler found (gcc/cc/clang): this gate cannot run.")
        print("  install one, e.g.  sudo apt-get install -y gcc")
        sys.exit(1)
    exe = os.path.join(tempfile.mkdtemp(prefix="hull_"), "hull_exact")
    r = subprocess.run([cc, "-O2", "-o", exe, CSRC, "-lm"],
                       capture_output=True, text=True)
    if r.returncode:
        print(r.stderr)
        print("  hull_exact.c FAILED TO BUILD with a present compiler")
        sys.exit(1)
    EXE = exe


def run(*args):
    r = subprocess.run([EXE] + [str(a) for a in args],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"hull_exact {args}: rc={r.returncode} {r.stderr}")
    return r.stdout


def rows_of(out):
    return [list(map(float, l.split())) for l in out.strip().splitlines()]


# ── the round, in Python, for the cross-checks ─────────────────────────────
def rol(x, k, n):
    k %= n
    m = (1 << n) - 1
    return ((x << k) | (x >> (n - k))) & m if k else x


def delta(n, B):
    m = (1 << n) - 1
    return rol((B * ((B + 1) >> 1)) & m, n // 4, n)


def Mx(x, n):
    return x ^ rol(x, 1, n) ^ rol(x, n - 1, n)


def perm_py(n, B, r, affine=False):
    N = 1 << n
    d = delta(n, B)
    P = list(range(N))
    for i in range(1, r + 1):
        k = (i ^ B) & (N - 1)
        P = [(Mx(p ^ k, n) ^ d) if affine else ((Mx(p ^ k, n) + d) & (N - 1))
             for p in P]
    return P


def hulls_py(n, P):
    N = 1 << n
    best = 0
    for v in range(1, N):
        for u in range(1, N):
            s = sum(1 - 2 * (bin((u & x) ^ (v & P[x])).count("1") & 1)
                    for x in range(N))
            best = max(best, abs(s))
    bd = 0
    for a in range(1, N):
        c = {}
        for x in range(N):
            b = P[x] ^ P[x ^ a]
            c[b] = c.get(b, 0) + 1
        bd = max(bd, max(c.values()))
    return -math.log2(best / N), -math.log2(bd / N)


def keys_for(n, K):
    """Fixed seeds, the deployed affine-class screen (nl_v2_key_is_valid)."""
    rng = random.Random(1000 + n)
    ks = []
    while len(ks) < K:
        B = rng.randrange(1, 1 << n)
        if delta(n, B) not in (0, 1 << (n - 1)) and B not in ks:
            ks.append(B)
    return ks


def tz(d, n):
    return n if d == 0 else (d & -d).bit_length() - 1


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  Soundness: the shipped round, a brute force, and the controls")

    spec = importlib.util.spec_from_file_location(
        "_suite", os.path.join(ROOT, "Herradura cryptographic suite.py"))
    S = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(S)
    n = 16
    for B in (12345, 40961):
        for r in (1, 3):
            P = list(map(int, run("perm", n, B, r).split()))
            Bb = S.BitArray(n, B)
            bad = sum(1 for x in range(1 << n)
                      if S.nl_fscx_revolve_v2(S.BitArray(n, x), Bb, r).uint != P[x])
            print(f"  (a) n = 16, B = {B:5d}, r = {r}: helper vs shipped "
                  f"nl_fscx_revolve_v2 on all 65536 inputs: {bad} mismatches")
            check(bad == 0, f"§1(a) helper disagrees with the shipped round at "
                            f"B={B} r={r}")

    n = 7
    LC = None
    try:
        p = os.path.join(HERE, "lin_cycle_mean.py")
        spec = importlib.util.spec_from_file_location("_lc", p)
        LC = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(LC)
    except Exception as e:  # pragma: no cover
        print("  cannot load lin_cycle_mean.py:", e)
        check(False, "§1(c) graph builders unavailable")
    for B in (5, 82):
        R = 4
        rows = rows_of(run("hull", n, B, R, R))
        for r in range(1, R + 1):
            P = perm_py(n, B, r)
            hl, hd = hulls_py(n, P)
            row = rows[r - 1]
            ok = abs(hl - row[1]) < 1e-6 and abs(hd - row[2]) < 1e-6
            check(ok, f"§1(b) hull mismatch n=7 B={B} r={r}")
        # trail: Bellman on the two graph builders the earlier passes used
        if LC is not None:
            d = delta(n, B)
            for name, adj, col in (("lin", LC.build_v2(n, d), 3),
                                   ("diff", LC.DC.build(n, d), 4)):
                D = [0.0] * (1 << n)
                D[0] = math.inf
                for r in range(1, R + 1):
                    Dn = [math.inf] * (1 << n)
                    for a in range(1, 1 << n):
                        if D[a] < math.inf:
                            for b, w in adj[a]:
                                if D[a] + w < Dn[b]:
                                    Dn[b] = D[a] + w
                    D = Dn
                    ok = abs(min(D[1:]) - rows[r - 1][col]) < 1e-6
                    check(ok, f"§1(c) {name} trail mismatch n=7 B={B} r={r}")
        print(f"  (b,c) n = 7, B = {B:3d}: hulls (brute force over every (u,v) and "
              f"every a) and best r-round trails (Bellman on lin_cycle_mean's and "
              f"diff_cycle_mean's graphs) agree with the helper for r = 1..{R}")

    ones = []
    for n in (7, 8, 10):
        for B in keys_for(n, 6):
            r1 = rows_of(run("hull", n, B, 1))[0]
            ones.append(r1[1] == 0 and r1[2] == 0)
    print(f"  (d) one round: correlation 1 AND probability 1 on {sum(ones)} of "
          f"{len(ones)} keys -- the MSB freebie survives into the hull, as it must")
    check(all(ones), "§1(d) a key without the one-round freebie")

    aff = [rows_of(run("affine", n, B, 6)) for n, B in ((8, 77), (10, 421))]
    zero = all(r[1] == 0 and r[2] == 0 for rows in aff for r in rows)
    print(f"  (e) NEGATIVE CONTROL: '+' replaced by '^' (an affine map): every "
          f"round reads 0 bits on both axes: {zero}")
    check(zero, "§1(e) the affine control did not read 0 -- the scan cannot "
                "see a failure")


def sweep(widths):
    jobs = []
    for n, K, nr in widths:
        R = -(-3 * n // 4)
        Rt = R if n <= 14 else 9
        # the hull runs EXTRA rounds past r = 3n/4, so a key that is late is
        # measured as late rather than scored as stuck (§3)
        jobs += [("key", n, B, R + EXTRA, Rt) for B in keys_for(n, K)]
        jobs += [("rand", n, s, 0, 0) for s in range(1, nr + 1)]
    jobs.sort(key=lambda j: -j[1])

    def one(j):
        kind, n, B, R, Rt = j
        if kind == "rand":
            return j, rows_of(run("rand", n, B, 1))
        return j, rows_of(run("hull", n, B, R, Rt))

    with ThreadPoolExecutor(os.cpu_count() or 2) as ex:
        return list(ex.map(one, jobs))


def q3(x):
    x = sorted(x)
    return f"{x[0]:.3f} / {statistics.median(x):.3f} / {x[-1]:.3f}" if x else "-"


def section_2(widths):
    rule("§2  Hull against trail, per width")
    res = sweep(widths)
    floor = {}
    for (kind, n, *_), rows in res:
        if kind == "rand":
            floor.setdefault(n, []).append(rows[0][1:3])
    F = {n: (statistics.median(a for a, _ in v), statistics.median(b for _, b in v))
         for n, v in floor.items()}
    Fmin = {n: (min(a for a, _ in v), min(b for _, b in v)) for n, v in floor.items()}

    print("  floor = median (worst) over random permutations of the same scan;\n"
          "  a hull is AT the floor once it is no worse than the worst.  'H/T' is\n"
          "  hull weight over best-trail weight at the LAST round before the\n"
          "  hull saturates (min / median / max over keys); 'gain' the same in\n"
          "  bits; 'excess' how many rounds after the best trail the hull reaches\n"
          "  the floor.\n")
    out = {}
    residue = []
    for n in sorted(F):
        R = -(-3 * n // 4)
        keys = [(j, rows) for j, rows in res if j[0] == "key" and j[1] == n]
        per = {}
        for ax, hc, tc, f, fm in (("lin", 1, 3, F[n][0], Fmin[n][0]),
                                  ("diff", 2, 4, F[n][1], Fmin[n][1])):
            ratio, gain, exc, at_floor = [], [], [], []
            for (_, _, B, _, _), rows in keys:
                pre = [x for x in rows if len(x) > 4 and LO <= x[tc] <= f - PRE]
                if pre:
                    x = pre[-1]
                    ratio.append(x[hc] / x[tc])
                    gain.append(x[tc] - x[hc])
                rh = next((int(x[0]) for x in rows if x[hc] >= fm - 1e-9), None)
                rt = next((int(x[0]) for x in rows
                           if len(x) > 4 and x[tc] >= fm - 1e-9), None)
                if rh and rt:
                    exc.append((B, rh - rt))
                last = rows[R - 1]
                # trail at r = R is read from the longest trail row available
                # (trail weight never falls with r, so clearing at Rt <= R
                # implies clearing at R)
                tl = [x for x in rows if len(x) > 4][-1]
                trail_ok = tl[tc] >= fm - 1e-9
                hull_ok = last[hc] >= fm - 1e-9
                at_floor.append((B, hull_ok, trail_ok, rh, R))
                if trail_ok and not hull_ok:
                    late = next((int(x[0]) for x in rows[R:] if x[hc] >= fm - 1e-9),
                                None)
                    residue.append((n, B, ax, last[hc], tl[tc], fm, R, late))
            per[ax] = dict(ratio=ratio, gain=gain, exc=exc, at_floor=at_floor)
            print(f"  n = {n:2d}  {ax:4s} floor {f:6.3f} ({fm:6.3f})  H/T {q3(ratio):>23s} "
                  f"  gain {q3(gain):>24s}   excess {sorted(e for _, e in exc)}")
        out[n] = per
    return out, residue, F


def section_2_checks(out):
    print()
    for n, per in sorted(out.items()):
        L, D = per["lin"], per["diff"]
        if n >= 10:
            ml, md = statistics.median(L["ratio"]), statistics.median(D["ratio"])
            check(0.80 <= ml <= 0.95, f"§2 n={n}: median linear H/T {ml:.3f} "
                                      f"left [0.80, 0.95]")
            check(0.88 <= md <= 1.00, f"§2 n={n}: median differential H/T "
                                      f"{md:.3f} left [0.88, 1.00]")
        for ax in ("lin", "diff"):
            r = per[ax]["ratio"]
            if r:
                check(min(r) >= 0.70, f"§2 n={n} {ax}: a key keeps only "
                                      f"{min(r):.3f} of its trail weight")
            # TODO #253's class (tz(delta) >= 4 admits a zero-weight trail) is
            # slow on the TRAIL already; its hull lag is reported, not bounded
            weak = [(B, e) for B, e in per[ax]["exc"] if tz(delta(n, B), n) >= 4]
            e = [e for B, e in per[ax]["exc"] if tz(delta(n, B), n) < 4]
            check(e and max(e) <= 2 and statistics.median(e) <= 1,
                  f"§2 n={n} {ax}: rounds-to-floor excess {sorted(e)}")
            for B, x in weak:
                print(f"  n = {n:2d} {ax:4s} B = {B}: tz(delta) = "
                      f"{tz(delta(n, B), n)} (#253's class), hull lag {x}")
        if n >= 13:
            for ax in ("lin", "diff"):
                g = statistics.median(per[ax]["gain"])
                check(g > 0, f"§2 n={n} {ax}: median gain {g:.3f} not positive "
                             f"-- clustering no longer visible")
                miss = [B for B, _h, _t, rh, R in per[ax]["at_floor"]
                        if rh is None or rh > R + 1]
                check(not miss, f"§2 n={n} {ax}: keys {miss} not at the floor "
                                f"by r = 3n/4 + 1")
    # THE TREND.  The share is not a constant: it falls slowly with n on both
    # axes.  A least-squares slope over n >= 10 is printed, and the decline is
    # pinned -- the widest width run must sit below n = 10 on both axes.
    wide = [n for n in sorted(out) if n >= 10]
    for ax in ("lin", "diff"):
        xs = wide
        ys = [statistics.median(out[n][ax]["ratio"]) for n in xs]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        slope = (sum((x - mx) * (y - my) for x, y in zip(xs, ys))
                 / sum((x - mx) ** 2 for x in xs))
        print(f"  median H/T, {ax:4s}: " + "  ".join(
            f"n={x}: {y:.3f}" for x, y in zip(xs, ys)) +
            f"   slope {slope:+.4f} per bit")
        check(ys[-1] < ys[0], f"§2 {ax}: the median share no longer falls from "
                              f"n = {xs[0]} to n = {xs[-1]}")
    print("\n  checked: median linear H/T in [0.80, 0.95] and differential in\n"
          "  [0.88, 1.00] at every n >= 10, and FALLING from n = 10 to the widest\n"
          "  width on both axes; no key below 0.70; the hull reaches the floor at\n"
          "  most 2 (median at most 1) rounds after the best trail, outside\n"
          "  #253's tz(delta) >= 4 class; at n >= 13 the median gain is positive\n"
          "  and every key is at the floor by r = 3n/4 + 1.")


# Measured, deterministic (fixed keys, fixed random-permutation seeds): the
# cells whose trail clears the floor by r = 3n/4 and whose hull is still below
# the worst random permutation there.  All late by 1-2 rounds; the n = 16 one
# (under --full) is a quantised max of 22 against the random permutations' 20.
EXPECTED_RESIDUE = [(7, 5, "diff"), (8, 21, "lin"), (8, 237, "diff"),
                    (10, 619, "lin"), (10, 854, "lin"), (11, 849, "diff"),
                    (16, 22853, "diff")]


def section_3(residue, widths, out):
    rule("§3  What the trail misses: keys that are LATE, not stuck")
    for n, B, ax, h, t, f, R, late in residue:
        d = delta(n, B)
        print(f"  n = {n:2d}  B = {B:5d}  {ax:4s}: at r = 3n/4 = {R} the best trail "
              f"is {t:.2f} bits and the hull {h:.2f} (worst random {f:.2f}); the "
              f"hull reaches it at r = {late}.  delta = {d:0{n}b}")
    cells = {n: sum(1 for ax in ("lin", "diff")
                    for _B, _h, t, _rh, _R in out[n][ax]["at_floor"] if t)
             for n in out}
    tested = sum(cells.values())
    K = {n: nr for n, _k, nr in widths}
    chance = sum(c / (K[n] + 1) for n, c in cells.items())
    print(f"\n  {len(residue)} of {tested} (key, axis) cells whose TRAIL clears the "
          f"floor by r = 3n/4\n  have a HULL that does not.  An ideal cipher lands "
          f"below the worst of K\n  random permutations about once in K + 1, i.e. "
          f"~{chance:.1f} of these cells,\n  so the COUNT is not the finding.  "
          f"What is: every one\n"
          f"  reaches the floor within 2 rounds after r = 3n/4, which is the\n"
          f"  rounds-to-floor lag of §2 crossing 3n/4 at widths too small to absorb\n"
          f"  it.")
    for n, B, ax, h, t, f, R, late in residue:
        check(late is not None and late <= R + 2,
              f"§3 n={n} B={B} {ax}: hull not at the floor by r = 3n/4 + 2")
    got = sorted((n, B, ax) for n, B, ax, *_ in residue)
    reached = {n for n, *_ in widths}
    exp = sorted(e for e in EXPECTED_RESIDUE if e[0] in reached)
    check(got == exp, f"§3 the measured set changed: {got}")


def section_4():
    rule("§4  What this changes")
    print("""\
  The linear hull, owed since §11.36.9, is MEASURED, exactly, for the shipped
  round with its round constants, to n = 14 (n = 16 under --full).  Clustering
  is real and it is a SHARE of the trail weight, not an offset, which GROWS
  slowly with width: the hull keeps a median 0.91 -> 0.82 (linear) and
  0.97 -> 0.90 (differential) of the trail's weight from n = 10 to 16, about
  0.011 less per bit on both axes, worst key 0.71.  In rounds it costs about
  one, at every width.

  So the hull is no longer an unmeasured caveat, and it is also not a fixed
  factor that can be carried to n = 256.  Exact mu at n = 23 is 2.4x the linear
  criterion and 2.2x the differential one (§11.42); the hull eats that margin
  only if its share falls below 0.42 / 0.45.  At n <= 16 it never does (worst
  key 0.71).  A straight line through the medians would reach it near n = 50 --
  an extrapolation of exactly the kind #257 has withdrawn four times, recorded
  as the question it raises and not as an answer.

  Still owed: monotonicity of exact mu in n (#257's first obligation), and now
  the hull share's behaviour above n = 16, which no exact method reaches.""")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--quick", action="store_true")
    g.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    build()
    widths = [(7, 16, 32), (8, 16, 32), (10, 16, 32), (11, 16, 32), (13, 8, 32)]
    if not a.quick:
        widths.append((14, 6, 12))
    if a.full:
        widths.append((16, 8, 32))
    section_1()
    out, residue, _ = section_2(widths)
    section_2_checks(out)
    section_3(residue, widths, out)
    section_4()
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
