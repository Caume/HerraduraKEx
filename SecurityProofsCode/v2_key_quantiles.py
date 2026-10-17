#!/usr/bin/env python3
"""v2_key_quantiles.py — TODO #343 (sixth pass): NL-FSCX v2's deployed trail criterion
over keys by QUANTILE, not only by mean, to n = 20.

§11.55 and §11.57 report means over keys: E[mu], E[c/n], E[W(3n/4)]/n, and the share
of keys that fail.  A mean can rise while its weak tail stays put, and the weak tail is
what a fixed key meets.  This pass reads the per-key criterion margin

    y(B) = W(floor(3n/4)) / (bar * n),   bar = 1 (differential), 1/2 (linear),

y >= 1 meaning that key's exact best trail over the deployed rounds meets the deployed
criterion, from v2_transient_series.json (1243 stratified keys, n = 10..20).  No solves:
every verdict is computed from the pinned file, so it cannot flake.

  §1  THE TAIL WEIGHT, EXACTLY.  delta(B) = ROL(p, n/4), p = B * ((B+1) >> 1) mod 2^n,
      so delta's nonzero bits lie in a cyclic window of w = n - tz(p) bits.  B even with
      tz(B) = s gives tz(p) = 2s - 1; B odd gives tz(p) = tz(B+1) - 1.  So
      P(tz(p) >= 2k - 1) = 2^-k + 4^-k away from the edges, and exactly
      P(tz(p) >= t) = sum over s of 2^-(s+1) [2s-1 >= t] + 2^-(s+1) [s-1 >= t], plus the
      two edge keys B = 0 and B = 2^n - 1.  CHECK: equal to enumeration at
      n = 8..16, every t.

  §2  THE QUANTILES.  The stratified quantiles q5, q10, q25, q50 of y, with standard
      errors from a seeded bootstrap within strata (fixed seed, so deterministic).
      (a) Every one of them rises from n = 10 to n = 20 by more than 5 SE, both axes.
      (b) The median key meets the deployed criterion at every width from n = 14.
      (c) The tail KEEPS PACE: over n = 14..20, q5, q10 and q25 rise at least as fast
          per bit as the median (within 2 SE) -- about +0.06 to +0.08 of the bar per
          bit, both axes.  The distribution moves up whole; its 5-25% tail does not
          lag.  At n = 20, q5 is at the bar (1.03 / 1.00).

  §3  THE BOTTOM DOES NOT MOVE.  The weakest keys are SHORT-WINDOW keys:
      (a) the weakest sampled key at every width has w <= 9;
      (b) keys with w <= 9 reach y < 0.25 at every width, n = 10..20 -- their margin
          does not improve with n;
      (c) from n = 16, every sampled key with w >= 10 has y > 0.25.
      (a) and (b) have teeth only from n = 16: below that, w <= 9 is most keys (75% at
      n = 10).  At n = 16..20 the class holds 16, 8, 6 and 4 sampled keys, all from
      the oversampled t >= 8 stratum, so these are sample minima on few keys.
      So the bottom of the distribution is a class fixed by the window, not by n, and
      its weight is §1's: P(w <= 9) = 1.6% at n = 20 and about 2^-124 at n = 256,
      next to the 2^-129 affine class the CLIs already screen.  That last step is a
      reading, not a measurement: it assumes the window stays what makes a key weak.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_key_quantiles.py [--quick]
      default : about 3 s on an aarch64 SBC (400 bootstrap replicates)
      --quick : 200 replicates
"""

import argparse
import importlib.util
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
NAME = {0: "differential", 1: "linear"}
FS = (0.05, 0.10, 0.25, 0.50)
WMAX = 9                          # the short-window class: w = n - tz(p) <= WMAX
LOW = 0.25                        # "far below the bar"


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


TS = _load("v2_transient_series.py")   # PLAN, BAR, PINNED
KS = TS.KS                             # strata()
AUD = KS.AUD                           # p_of(), tz()


def tz_p(B, n):
    p = AUD.p_of(B, n)
    return AUD.tz(p) if p else n


def p_tail(n, t):
    """P(tz(p) >= t) over all 2^n keys, in closed form."""
    if t <= 0:
        return 1.0
    P = 0.0
    for s in range(1, n):
        P += 2.0 ** -(s + 1) * ((min(2 * s - 1, n) >= t) + (s - 1 >= t))
    P += 2.0 ** -n                       # B = 0: p = 0
    P += 2.0 ** -n * (n - 1 >= t)        # B = 2^n - 1: p = B * 2^(n-1)
    return P


# ═══════════════════════════════════════════════════════════════════════════
# §1  the tail weight
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  P(tz(p) >= t), exactly")
    ok = True
    for n in range(8, 17):
        cnt = [0] * (n + 1)
        for B in range(1 << n):
            cnt[tz_p(B, n)] += 1
        ok &= all(abs(sum(cnt[t:]) / (1 << n) - p_tail(n, t)) < 1e-15 for t in range(n + 1))
    check(ok, "the closed form equals enumeration over every key at n = 8..16, every t")
    k = [(k, p_tail(64, 2 * k - 1), 2.0 ** -k + 4.0 ** -k) for k in (1, 2, 4, 8)]
    check(all(abs(a - b) < 1e-15 for _, a, b in k),
          "away from the edges P(tz(p) >= 2k - 1) = 2^-k + 4^-k (k = 1, 2, 4, 8 at n = 64)")
    for n in (20, 256):
        P = p_tail(n, n - WMAX)
        print("  n = %3d: P(w <= %d) = P(tz(p) >= %d) = %.3g = 2^%.1f"
              % (n, WMAX, n - WMAX, P, math.log2(P)))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the quantiles
# ═══════════════════════════════════════════════════════════════════════════
def wq(pts, f):
    acc = 0.0
    for x, w in pts:
        acc += w
        if acc >= f:
            return x
    return pts[-1][0]


def quantiles(by, w):
    pts = sorted((x, w[t] / len(xs)) for t, xs in by.items() for x in xs)
    return [wq(pts, f) for f in FS]


def slope(xs, ys):
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    return (sum((x - mx) * (y - my) for x, y in zip(xs, ys))
            / sum((x - mx) ** 2 for x in xs))


def sd(xs):
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def margins(rec):
    """y[(n, axis)] = {stratum: [y per key]}, keys[(n, axis)] = [(w, y)], weights[n]."""
    Y, K, Wt = {}, {}, {}
    for n, _ in TS.PLAN:
        S = KS.strata(n)
        tot = sum(len(v) for v in S.values())
        Wt[n] = {t: len(v) / tot for t, v in S.items()}
        r0 = 3 * n // 4
        for axis in (0, 1):
            by, ks = {}, []
            for r in rec["widths"][str(n)]:
                y = r[2 + axis][1][r0 - 1] / (TS.BAR[axis] * n)
                by.setdefault(r[0], []).append(y)
                ks.append((n - tz_p(r[1], n), y))
            Y[(n, axis)], K[(n, axis)] = by, ks
    return Y, K, Wt


def section_2(Y, Wt, reps):
    rule("§2  Quantiles of y = W(floor(3n/4)) / (bar * n) over keys")
    ns = [n for n, _ in TS.PLAN]
    late = [n for n in ns if n >= 14]
    for axis in (0, 1):
        nm = NAME[axis]
        Q, B = {}, {}
        for n in ns:
            by = Y[(n, axis)]
            Q[n] = quantiles(by, Wt[n])
            rnd = random.Random(343000 + 10 * n + axis)
            B[n] = [quantiles({t: [rnd.choice(xs) for _ in xs] for t, xs in by.items()},
                              Wt[n]) for _ in range(reps)]
        se = {n: [sd([b[i] for b in B[n]]) for i in range(len(FS))] for n in ns}
        print("\n  %s (y >= 1: the key meets W(floor(3n/4)) >= %s)"
              % (nm, "n" if axis == 0 else "n/2"))
        print("     n   " + "   ".join("    q%-2d     " % round(100 * f) for f in FS))
        for n in ns:
            print("  %4d   %s" % (n, "   ".join("%.3f ± %.3f" % (Q[n][i], se[n][i])
                                              for i in range(len(FS)))))
        z = [(Q[ns[-1]][i] - Q[ns[0]][i]) / math.hypot(se[ns[0]][i], se[ns[-1]][i])
             for i in range(len(FS))]
        check(min(z) > 5, "%s: q5, q10, q25 and q50 all rise from n = %d to n = %d, by "
              "%.1f SE or more" % (nm, ns[0], ns[-1], min(z)))
        med = [n for n in ns if n >= 14 and Q[n][FS.index(0.50)] < 1]
        check(not med, "%s: the median key meets the deployed criterion at every width "
              "from n = 14 (q50 = %s)" % (nm, ", ".join(
                  "%.2f" % Q[n][FS.index(0.50)] for n in late)))
        sl = [slope(late, [Q[n][i] for n in late]) for i in range(len(FS))]
        ss = [sd([slope(late, [B[n][k][i] for n in late]) for k in range(reps)])
              for i in range(len(FS))]
        print("  slopes over n = %d..%d, per bit: %s" % (late[0], late[-1], ", ".join(
            "q%d %+.4f ± %.4f" % (round(100 * f), sl[i], ss[i]) for i, f in enumerate(FS))))
        im = FS.index(0.50)
        check(all(sl[i] >= sl[im] - 2 * math.hypot(ss[i], ss[im]) for i in range(im)),
              "%s: the tail keeps pace -- over n = %d..%d, q5, q10 and q25 rise at least "
              "as fast per bit as the median, within 2 SE (q5 %+.3f, median %+.3f)"
              % (nm, late[0], late[-1], sl[0], sl[im]))


# ═══════════════════════════════════════════════════════════════════════════
# §3  the bottom
# ═══════════════════════════════════════════════════════════════════════════
def section_3(K):
    rule("§3  The bottom: short-window keys, w = n - tz(p) <= %d" % WMAX)
    ns = [n for n, _ in TS.PLAN]
    print("     n   keys w <= %d   min y (w <= %d)   min y (w >= %d)      diff | lin"
          % (WMAX, WMAX, WMAX + 1))
    lo, hi, worst = {}, {}, {}
    for n in ns:
        for axis in (0, 1):
            ks = K[(n, axis)]
            lo[(n, axis)] = min(y for w, y in ks if w <= WMAX)
            hi[(n, axis)] = min(y for w, y in ks if w > WMAX)
            worst[(n, axis)] = min(ks, key=lambda k: k[1])[0]
        print("  %4d   %8d       %.2f | %.2f       %.2f | %.2f"
              % (n, sum(1 for w, _ in K[(n, 0)] if w <= WMAX), lo[(n, 0)], lo[(n, 1)],
                 hi[(n, 0)], hi[(n, 1)]))
    for axis in (0, 1):
        nm = NAME[axis]
        check(all(worst[(n, axis)] <= WMAX for n in ns),
              "%s: the weakest sampled key at every width has w <= %d (w = %s)"
              % (nm, WMAX, ", ".join(str(worst[(n, axis)]) for n in ns)))
        check(all(lo[(n, axis)] < LOW for n in ns),
              "%s: keys with w <= %d reach y < %.2f at every width, n = %d..%d -- the "
              "bottom does not improve with width" % (nm, WMAX, LOW, ns[0], ns[-1]))
        up = [n for n in ns if n >= 16]
        check(all(hi[(n, axis)] > LOW for n in up),
              "%s: from n = 16, every sampled key with w >= %d has y > %.2f (min %.2f)"
              % (nm, WMAX + 1, LOW, min(hi[(n, axis)] for n in up)))
    print("\n  The short-window class weighs P(w <= %d) = %.2g at n = 20 and 2^%.0f at "
          "n = 256 (§1)." % (WMAX, p_tail(20, 20 - WMAX), math.log2(p_tail(256, 256 - WMAX))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    with open(TS.PINNED) as fh:
        rec = json.load(fh)
    section_1()
    Y, K, Wt = margins(rec)
    section_2(Y, Wt, 200 if a.quick else 400)
    section_3(K)
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
