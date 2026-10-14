#!/usr/bin/env python3
"""v2_measurement_audit.py — TODO #343 (first pass): an audit of how TODO #257
measures NL-FSCX v2's trail slopes.  Two of its errors make the n = 256 margin look
larger than it is, and a third is a gap in the weak-key screen.

TODO #257's width series (period_series_n19.py, period_series_n20.py) estimates
E[mu_n], the per-round slope of the best trail, by sampling delta UNIFORMLY over
n-bit strings and holds it to mu * r >= n at r = 3n/4 (n/2 on the linear axis).
Both choices are checked here against the object they stand for.

  §1  THE KEY-INDUCED DISTRIBUTION OF delta, IN CLOSED FORM.  A real key gives
      delta(B) = ROL(p, n/4), p = B * ((B+1) >> 1) mod 2^n.  For B = 2^j * u
      (u odd) p = 2^(2j-1) * u^2; for odd B, tz(p) = tz(B+1) - 1.  That gives an
      exact preimage count for every delta: the even branch is a square-root
      count mod 2^(n-k), the odd branch a unique Hensel lift.  Checked against
      brute force over every delta at every n <= 16.  Only about half the deltas are
      reachable, some by 2^(n/2) keys, and long zero runs in p are far likelier
      than for a uniform string: P(tz(p) = t) = 2^-(t+2) + [t odd] 2^-((t+3)/2).

  §2  THE WRONG POPULATION.  Exhaustively at n = 7, 8, 10, 11 (13 by default), the
      mean slope over KEYS is below the mean over uniform delta on both axes, at
      every width, and the 5th percentile is far below it.  The keys behind the
      gap are the long-zero-run keys of §1: their slope falls with t / n.

  §3  THE AFFINE CLASS HAS FOUR MEMBERS, THE SCREEN NAMES TWO.  delta in {0,
      2^(n-1), 2^(n-2), 3 * 2^(n-2)} makes the round GF(2)-affine (exhaustively,
      these and only these at n = 7, 8, 10), so mu = 0.  The CLIs reject the first
      two.  Keys reach 2^(n-2) at n = 11, 14, 17, 19, 20, 22 -- but at n = 256, and
      at every n = 0 (mod 8), §1's count is ZERO for both unscreened values: the
      shipped screen is complete for the deployed widths.

  §4  THE CRITERION IS ON W(r), NOT ON mu * r.  v2_round_transient.c computes the
      exact best r-round trail W(r) from the full DDT / LAT.  Its slope over rounds
      4n..8n reproduces the certified solver's mu; at the deployed r = 3n/4,
      W(r) = mu * r + c with c < 0 for EVERY key measured, c / n near -0.28
      (differential) and -0.15 (linear) at n = 10..13, NOT shrinking.  If that holds
      at n = 256, the bars on mu become (1 - c/n) / (3/4): about 1.71 and 0.87, not
      4/3 and 2/3.

  §5  THE PINNED SERIES, REWEIGHTED.  mu depends on delta alone, so each pinned
      sample can be reweighted by §1's preimage count: the key-weighted E[mu] is
      LOWER than the published one at every one of the 20 (axis, width) points.

  §6  WHAT THIS CHANGES.  The widest pinned width under the old and the corrected
      bars, printed, not scored: it applies §4's c / n beyond where it was measured.

Needs a C compiler (two helpers); absent means FAIL, hull_exact.py's precedent.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_measurement_audit.py [--quick | --full]
      --quick : §2 to n = 11, §4 at n = 10, 11   (~2 min on an aarch64 SBC, 8 threads)
      default : §2 to n = 13, §4 to n = 13        (~9 min)
      --full  : §4 also at n = 14                 (~10 min, 512 MB per helper)
"""

import argparse
import importlib.util
import math
import os
import random
import shutil
import statistics as st
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TSRC = os.path.join(HERE, "v2_round_transient.c")
FAIL = []
THREADS = max(1, min(os.cpu_count() or 1, 64))
SEED = 3430
NAME = {0: "differential", 1: "linear"}
BAR = {0: 1.0, 1: 0.5}          # the criterion: W(3n/4) >= BAR * n


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


PS = _load("period_series_n19.py")   # draws(), the pinned samples' generator
ESL = PS.ESL                         # the certified minimum-mean-cycle solver


def build():
    global TEXE
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        print("  no C compiler found (gcc/cc/clang): this gate cannot run.")
        print("  install one, e.g.  sudo apt-get install -y gcc")
        sys.exit(1)
    ESL.build()
    exe = os.path.join(tempfile.mkdtemp(prefix="v2tr_"), "v2_round_transient")
    r = subprocess.run([cc, "-O2", "-o", exe, TSRC, "-lm"], capture_output=True, text=True)
    if r.returncode:
        print(r.stderr)
        print("  v2_round_transient.c FAILED TO BUILD with a present compiler")
        sys.exit(1)
    TEXE = exe


# ═══════════════════════════════════════════════════════════════════════════
# the key schedule's delta, and its exact preimage count
# ═══════════════════════════════════════════════════════════════════════════
def rol(x, k, n):
    k %= n
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1)


def p_of(B, n):
    return (B * ((B + 1) >> 1)) & ((1 << n) - 1)


def delta(B, n):
    return rol(p_of(B, n), n // 4, n)


def tz(x):
    return (x & -x).bit_length() - 1


def sqrt_count(w, m):
    """Odd u mod 2^m with u^2 = w (mod 2^m); w odd."""
    if m == 1:
        return 1
    if m == 2:
        return 2 if w % 4 == 1 else 0
    return 4 if w % 8 == 1 else 0


def preimages(d, n):
    """#{B < 2^n : delta(B) = d}, without enumerating B.

    p = ROR(d, n/4).  p = 0 is reached by B = 0 and by every B = 2^j u with
    2j - 1 >= n, or odd B with tz(B+1) > n; those are counted directly.
    Otherwise k = tz(p), w = p >> k, m = n - k:
      even B = 2^j u:  p = 2^(2j-1) u^2  ->  needs k = 2j - 1 odd and u^2 = w mod
                       2^m; each root mod 2^m lifts to 2^(j-1) odd u < 2^(n-j).
      odd B, B+1 = 2^(k+1) v (v odd):  p / 2^k = v (2^(k+1) v - 1) mod 2^m, a
                       bijection on odd v (its derivative is odd), so one v0 mod
                       2^m; it counts iff v0 <= 2^(n-k-1), i.e. B < 2^n.
    """
    p = rol(d, n - n // 4, n)
    if p == 0:
        return sum(1 for B in range(1 << n) if p_of(B, n) == 0) if n <= 16 else None
    k, w = tz(p), p >> tz(p)
    m = n - k
    cnt = 0
    if k % 2 == 1:
        j = (k + 1) // 2
        cnt += sqrt_count(w % (1 << m), m) << (j - 1)
    # odd branch: lift v bit by bit, v odd, f(v) = 2^(k+1) v^2 - v = w (mod 2^m)
    v = 1
    for i in range(1, m):
        if (((v * ((v << (k + 1)) - 1)) - w) >> i) & 1:
            v |= 1 << i
    if ((v * ((v << (k + 1)) - 1)) - w) % (1 << m) == 0 and v <= 1 << (n - k - 1):
        cnt += 1
    return cnt


def brute_counts(n):
    c = [0] * (1 << n)
    for B in range(1 << n):
        c[delta(B, n)] += 1
    return c


def section_1():
    rule("§1  the key-induced distribution of delta, in closed form")
    ok, tot = True, 0
    for n in range(4, 17):
        c = brute_counts(n)
        for d in range(1, 1 << n):
            if rol(d, n - n // 4, n) == 0:
                continue
            tot += 1
            if preimages(d, n) != c[d]:
                ok = False
                print("  MISMATCH n=%d d=%x: formula %d, brute force %d"
                      % (n, d, preimages(d, n), c[d]))
                break
    check(ok, "the closed-form preimage count matches brute force for all %d nonzero "
          "deltas at n = 4..16" % tot)
    print("\n     n   reachable deltas   most keys on one delta")
    for n in (11, 13, 16):
        c = brute_counts(n)
        print("  %4d   %8d / %-6d   %6d" % (n, sum(1 for x in c if x), 1 << n, max(c)))
    c = brute_counts(16)
    reach = sum(1 for x in c if x) / (1 << 16)
    check(0.45 < reach < 0.65, "only %.0f%% of deltas are reachable by any key at n = 16"
          % (100 * reach))
    check(max(c) >= 1 << 6, "one delta is reached by %d keys at n = 16" % max(c))
    n = 20
    cnt = [0] * (n + 1)
    for B in range(1 << n):
        p = p_of(B, n)
        cnt[tz(p) if p else n] += 1
    print("\n     t   P(tz(p) = t), n = 20   formula   uniform 2^-(t+1)")
    good = True
    for t in range(0, n - 3):
        f = 2.0 ** -(t + 2) + (2.0 ** -((t + 3) / 2) if t % 2 else 0.0)
        e = cnt[t] / (1 << n)
        if t < 12:
            print("  %4d   %.6f              %.6f  %.6f" % (t, e, f, 2.0 ** -(t + 1)))
        good &= abs(e - f) < 1e-12
    check(good, "P(tz(p) = t) = 2^-(t+2) + [t odd] 2^-((t+3)/2) exactly, t = 0..%d at "
          "n = 20: a heavy tail, ~2^(-t/2) against 2^-(t+1) for uniform delta" % (n - 4))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the key-weighted population
# ═══════════════════════════════════════════════════════════════════════════
def all_mu(n):
    """mu for every delta not screened by the CLIs (0, 2^(n-1)), both axes."""
    ds = [d for d in range(1 << n) if d not in (0, 1 << (n - 1))]
    out = {}
    with ThreadPoolExecutor(THREADS) as ex:
        for axis in (0, 1):
            out[axis] = dict(zip(ds, ex.map(lambda d: ESL.cmu(n, d, axis)[0], ds)))
    return out


def q(xs, f):
    s = sorted(xs)
    return s[int(f * len(s))]


def section_2(widths):
    rule("§2  the wrong population: uniform delta against real keys, exhaustively")
    print("     n  axis          E[mu] uniform   E[mu] keys   shift    p5 uniform  p5 keys")
    by_tz = {}
    shifts = {0: [], 1: []}
    for n in widths:
        mu = all_mu(n)
        c = brute_counts(n)
        for axis in (0, 1):
            m = mu[axis]
            uni = list(m.values())
            keys = [m[delta(B, n)] for B in range(1 << n) if delta(B, n) in m]
            mu_u, mu_k = st.mean(uni), st.mean(keys)
            shifts[axis].append(mu_k / mu_u - 1)
            print("  %4d  %-12s  %.4f          %.4f       %+5.1f%%    %.3f       %.3f"
                  % (n, NAME[axis], mu_u, mu_k, 100 * (mu_k / mu_u - 1),
                     q(uni, .05), q(keys, .05)))
            check(mu_k < mu_u and q(keys, .05) < q(uni, .05),
                  "n = %d %s: the key-weighted mean AND 5th percentile are below the "
                  "uniform ones" % (n, NAME[axis]))
        by_tz[n] = (mu, c)
    for axis in (0, 1):
        check(max(shifts[axis]) < -0.02,
              "%s: the uniform sample overstates E[mu] by %.1f%% to %.1f%%"
              % (NAME[axis], -100 * max(shifts[axis]), -100 * min(shifts[axis])))
    n = widths[-1]
    mu, _ = by_tz[n]
    print("\n  n = %d, differential, by the length t of p's trailing zero run "
          "(key-weighted):" % n)
    print("     t   keys   E[mu]")
    cls = {}
    for B in range(1 << n):
        d = delta(B, n)
        if d in mu[0]:
            p = p_of(B, n)
            cls.setdefault(min(tz(p), n - 2) if p else n - 2, []).append(mu[0][d])
    for t in sorted(cls):
        print("  %4d  %5d   %.3f" % (t, len(cls[t]), st.mean(cls[t])))
    short = [x for t in cls if t <= 2 for x in cls[t]]
    long_ = [x for t in cls if t >= n // 2 for x in cls[t]]
    check(st.mean(long_) < 0.75 * st.mean(short),
          "n = %d: keys with t >= n/2 average %.3f, %.0f%% below keys with t <= 2"
          % (n, st.mean(long_), 100 * (1 - st.mean(long_) / st.mean(short))))


# ═══════════════════════════════════════════════════════════════════════════
# §3  the affine class
# ═══════════════════════════════════════════════════════════════════════════
def M(x, n):
    return x ^ rol(x, 1, n) ^ rol(x, n - 1, n)


def is_affine(n, d):
    mask = (1 << n) - 1
    T = [(M(x, n) + d) & mask for x in range(1 << n)]
    t0 = T[0]
    col = [T[1 << i] ^ t0 for i in range(n)]
    for x in range(1 << n):
        y = t0
        for i in range(n):
            if (x >> i) & 1:
                y ^= col[i]
        if y != T[x]:
            return False
    return True


def section_3():
    rule("§3  the affine class: four members, the screen names two")
    for n in (7, 8, 10):
        aff = [d for d in range(1 << n) if is_affine(n, d)]
        want = sorted({0, 1 << (n - 1), 1 << (n - 2), 3 << (n - 2)})
        check(aff == want, "n = %d: exactly the deltas {0, 2^(n-1), 2^(n-2), 3*2^(n-2)} "
              "make the round affine (exhaustive over all %d)" % (n, 1 << n))
    mus = [ESL.cmu(11, d, ax)[0] for d in (1 << 9, 3 << 9) for ax in (0, 1)]
    check(max(mus) < 1e-9, "n = 11: mu = 0 on both axes at both unscreened deltas")
    print("\n     n   keys reaching 2^(n-2)   keys reaching 3*2^(n-2)")
    reach = []
    for n in range(7, 25):
        if n % 3 == 0:
            continue
        a, b = preimages(1 << (n - 2), n), preimages(3 << (n - 2), n)
        print("  %4d   %6d                  %6d" % (n, a, b))
        if a or b:
            reach.append(n)
    check(reach == [11, 14, 17, 19, 20, 22],
          "keys reach the unscreened affine deltas at n = %s" % reach)
    check(delta(0x40, 17) == 1 << 15 and ESL.cmu(17, 1 << 15, 0)[0] < 1e-9,
          "n = 17: B = 0x40 gives delta = 2^15 and mu = 0 (this review met it sampling keys)")
    zero = [n for n in (8, 16, 24, 32, 64, 128, 256)
            if preimages(1 << (n - 2), n) == 0 and preimages(3 << (n - 2), n) == 0]
    check(zero == [8, 16, 24, 32, 64, 128, 256],
          "n = 8, 16, 24, 32, 64, 128, 256: NO key reaches either unscreened affine "
          "delta -- the CLIs' two-value screen is complete at the deployed width")
    print("  (why, at n = 0 mod 8: p must be 2^k or 3*2^k with k = 3n/4 - 2 EVEN, so no"
          "\n   even B, whose p has odd valuation; and odd B needs v = -1 or -3 mod"
          "\n   2^(n/4+2) with v <= 2^(n/4+1).)")


# ═══════════════════════════════════════════════════════════════════════════
# §4  the transient: W(r) against mu * r
# ═══════════════════════════════════════════════════════════════════════════
AFFINE = lambda n: {0, 1 << (n - 1), 1 << (n - 2), 3 << (n - 2)}


def trail(n, d, axis, R):
    r = subprocess.run([TEXE, str(n), "%x" % d, str(axis), str(R)],
                       capture_output=True, text=True, check=True)
    return [float(l.split()[1]) for l in r.stdout.split("\n") if l]


def section_4(plan):
    rule("§4  the criterion is on W(3n/4), not on mu * 3n/4")
    print("  keys B drawn uniformly (seed %d); W from the full table, mu certified\n" % SEED)
    print("     n   r  axis          E[mu]   E[W(r)]  E[mu*r]   E[c/n]  worst c/n"
          "  W(r)<bar  mu*r<bar")
    cn = {0: {}, 1: {}}
    for n, K in plan:
        rnd = random.Random(SEED + n)
        keys = []
        while len(keys) < K:
            B = rnd.getrandbits(n)
            if delta(B, n) not in AFFINE(n):
                keys.append(B)
        r, R = 3 * n // 4, 8 * n
        for axis in (0, 1):
            jobs = [(delta(B, n), axis) for B in keys]
            with ThreadPoolExecutor(min(THREADS, 4 if n >= 14 else THREADS)) as ex:
                W = list(ex.map(lambda j: trail(n, j[0], j[1], R), jobs))
                mu = list(ex.map(lambda j: ESL.cmu(n, j[0], j[1])[0], jobs))
            slope_ok = all(abs((w[-1] - w[R // 2 - 1]) / (R - R // 2) - m) <= 0.04 * m
                           for w, m in zip(W, mu))
            c = [w[r - 1] - m * r for w, m in zip(W, mu)]
            bar = BAR[axis] * n
            fw = sum(w[r - 1] < bar for w in W)
            fm = sum(m * r < bar for m in mu)
            cn[axis][n] = st.mean(c) / n
            print("  %4d  %2d  %-12s  %.3f   %6.2f   %6.2f    %+.3f    %+.3f     %2d/%d"
                  "     %2d/%d" % (n, r, NAME[axis], st.mean(mu), st.mean(w[r - 1] for w in W),
                                   st.mean(m * r for m in mu), st.mean(c) / n, min(c) / n,
                                   fw, K, fm, K))
            check(slope_ok, "n = %d %s: the slope of W over rounds %d..%d reproduces "
                  "the certified mu within 4%% for every key" % (n, NAME[axis], R // 2, R))
            check(max(c) < 0, "n = %d %s: W(%d) < mu * %d for EVERY key: the transient "
                  "is a discount, never a surcharge" % (n, NAME[axis], r, r))
            check(fw >= fm, "n = %d %s: the true criterion W(r) >= %s fails for at least "
                  "as many keys (%d) as mu * r >= %s does (%d)"
                  % (n, NAME[axis], "n" if axis == 0 else "n/2", fw,
                     "n" if axis == 0 else "n/2", fm))
    for axis, lim in ((0, -0.2), (1, -0.1)):
        xs = cn[axis]
        ns = sorted(xs)
        check(all(xs[n] < lim for n in ns),
              "%s: E[c/n] < %.1f at every width (%s)"
              % (NAME[axis], lim, ", ".join("%+.3f" % xs[n] for n in ns)))
        check(abs(xs[ns[-1]]) > 0.7 * abs(xs[ns[0]]),
              "%s: c/n does not shrink from n = %d to n = %d -- the transient grows "
              "WITH n" % (NAME[axis], ns[0], ns[-1]))
    bars = {}
    for axis in (0, 1):
        f = st.mean(cn[axis].values())
        bars[axis] = (BAR[axis] - f) / 0.75
        print("  %s: with c/n = %+.2f, mu * 3n/4 + c >= %s needs mu >= %.3f, not %.3f"
              % (NAME[axis], f, "n" if axis == 0 else "n/2", bars[axis],
                 BAR[axis] / 0.75))
    return bars


# ═══════════════════════════════════════════════════════════════════════════
# §5  the pinned series, reweighted by preimage count
# ═══════════════════════════════════════════════════════════════════════════
def section_5():
    import json
    rule("§5  the pinned period series, reweighted to the key population")
    cells = []
    for f in ("period_series_n19.json", "period_series_n20.json"):
        with open(os.path.join(HERE, f)) as fh:
            cells += json.load(fh)["cells"]
    counts, acc = {}, {}
    for c in cells:
        n, a = c["n"], c["axis"]
        for k in (n, n + 3):
            if k not in counts:
                counts[k] = brute_counts(k) if k <= 20 else None
        for (d, e), (x, y) in zip(PS.draws(n, len(c["mu"]), a), c["mu"]):
            for k, dd, v in ((n, d, x), (n + 3, e, y)):
                cnt = counts[k][dd] if counts[k] else preimages(dd, k)
                acc.setdefault((a, k), []).append((v, cnt))
    print("  axis          n      N   published     key-weighted   shift   reachable")
    down = 0
    for (a, n) in sorted(acc):
        xs = acc[(a, n)]
        mu_u = st.mean(v for v, _ in xs)
        se_u = st.stdev([v for v, _ in xs]) / math.sqrt(len(xs))
        W = sum(w for _, w in xs)
        mw = sum(v * w for v, w in xs) / W
        se_w = math.sqrt(sum((w * (v - mw)) ** 2 for v, w in xs)) / W
        down += mw < mu_u
        print("  %-12s %3d  %5d   %.4f±%.4f  %.4f±%.4f  %+5.1f%%   %.2f"
              % (NAME[a], n, len(xs), mu_u, se_u, mw, se_w, 100 * (mw / mu_u - 1),
                 sum(1 for _, w in xs if w) / len(xs)))
    check(down == len(acc), "the key-weighted E[mu] is below the published one at %d of "
          "%d (axis, width) points" % (down, len(acc)))
    top = max(n for _, n in acc)
    print("  (noisy: the ~46% of draws no key reaches get weight 0.  Fixing the sampler"
          "\n   -- draw B, not delta -- is TODO #343's next step.)")
    return top, {a: (st.mean(v for v, _ in acc[(a, top)]),
                     sum(v * w for v, w in acc[(a, top)]) / sum(w for _, w in acc[(a, top)]))
                 for a in (0, 1)}


def section_6(bars, top, mus):
    rule("§6  what this changes")
    print("  The widest measured width, n = %d, under the old bars and the corrected ones"
          % top)
    print("  (key-weighted mean from §5, bars from §4's c/n -- measured at n <= 13 and")
    print("  APPLIED at n = %d, which is an extrapolation):\n" % top)
    print("  axis          published E[mu] / old bar    key-weighted / corrected bar")
    for a in (0, 1):
        old = BAR[a] / 0.75
        print("  %-12s  %.3f / %.3f = %.2fx          %.3f / %.3f = %.2fx"
              % (NAME[a], mus[a][0], old, mus[a][0] / old, mus[a][1], bars[a],
                 mus[a][1] / bars[a]))
    print("""
  TODO #257's uniform-delta estimates of E[mu] are high by a few percent, and its
  criterion mu * 3n/4 >= n drops a transient that is a constant FRACTION of n; both
  push the same way.  Whether c / n holds at 192 rounds, and E[mu] over KEYS rather
  than deltas, are TODO #343's next steps; every n = 256 margin TODO #257 states is
  to be read against the corrected bars.  The affine screen is complete at n = 256
  (§3).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    build()
    section_1()
    section_2((7, 8, 10, 11) if a.quick else (7, 8, 10, 11, 13))
    section_3()
    plan = [(10, 8), (11, 8)]
    if not a.quick:
        plan.append((13, 8))
    if a.full:
        plan.append((14, 6))
    bars = section_4(plan)
    top, mus = section_5()
    section_6(bars, top, mus)
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
