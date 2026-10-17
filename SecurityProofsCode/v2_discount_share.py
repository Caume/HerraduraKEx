#!/usr/bin/env python3
"""v2_discount_share.py — TODO #343 (eighth pass): NL-FSCX v2's r-round discount as a
SHARE of the trail, and what it leaves of the extrapolation in n = 256's residue class.

§11.57 found that the transient c(r) = W(r) - mu * r is negative on every key, and that
E[c/n] keeps deepening with width (-0.0167 per bit over n = 14..20, differential): c
grows like n^2, so no constant c/n can be read off it, and the bar on mu that §11.57
derives from it (bar - E[c/n]) / (3/4) climbs with n.  This pass reads the same pinned
file (v2_transient_series.json, 1243 stratified keys, n = 10..20, W(1..2n) per key) and
asks what the deepening is made of.  No solves: every verdict is computed from the
pinned file, so it cannot flake.

  §1  c <= 0 IS A THEOREM.  The round graph does not depend on the round (delta(B) is
      fixed per key), and a trail's nonzero state stays nonzero, so the best trail
      weight is SUPERADDITIVE: W(a + b) >= W(a) + W(b).  By Fekete's lemma
      mu = lim W(r) / r = sup W(r) / r, so W(r) <= mu * r, i.e. c(r) <= 0 at EVERY r,
      on every key.  §11.57.3(a)'s "never a surcharge" is that lemma, not a finding.
      CHECK: superadditivity on every pair a + b <= 2n of every pinned key, both axes
      (~10^6 inequalities), and c(r) <= 0 at every r.  CONTROLS: the first check FIRES
      on most keys' W shifted by one bit (W(r) + 1), the second against a mu understated
      by 20% -- the two ways a mis-recorded row could look.

  §2  THE DISCOUNT'S SHARE.  lambda(n) = -E[c(floor(3n/4)) / n] / E[mu], a ratio of
      stratified means (delta-method SE), is the fraction of mu * n the trail saves.
      Over n = 14..20, E[c/n] deepens at -0.0167 (differential) and -0.0060 (linear)
      per bit (13 / 10 SE).  Were that independent of mu, lambda would rise by
      -dE[c/n]/dn / E[mu] = +0.0073 / +0.0052 per bit.  It does not:
      (a) differential, +0.0011 +/- 0.0006 per bit, lambda 0.161-0.168;
      (b) linear, it FALLS, -0.0024 +/- 0.0007 per bit, to 0.169 at n = 20.
      CHECK: lambda's slope, 2 SE up, is under half of the mu-independent figure.
      So most of the deepening of E[c/n] since n = 14 is mu's own growth: the trail saves
      about the same share of a dearer round.  In §11.57's terms the discount does not
      slow, but it is not a separate trend competing with mu.

  §3  NOT A PER-KEY LAW.  Within a width, c/n is not proportional to mu: an OLS fit
      c/n = a + b * mu over a width's keys has b about -0.085 (differential) and -0.06
      (linear), well short of -lambda, and an intercept a < 0 by 6 (9) SE or more at
      every width from n = 14.  lambda is a regularity of the key AVERAGE, not of each key; a key's
      margin still has to be read from its own W.

  §4  THE CLASS n = 1 (mod 3).  n = 256 is in it; its measured widths are 10, 13, 16,
      19 (n = 7 is left out: its r = 5 rounds are all transient).  With the share
      held, the margin at floor(3n/4) = 3n/4 (exact at n = 256) is
          y*(n) = E[mu] * (3/4 - lambda) / bar,
      which removes floor(3n/4)'s own wobble (7/10, 9/13, 12/16, 14/19 of n).
      (a) y* rises at every step of the class, both axes (3 SE or more).
      (b) The bar on mu is then bar / (3/4 - lambda) = 1.71 and 0.865 (lambda pooled
          over n = 14..20), FIXED in n, instead of §11.57's 1.89 / 0.94 at n = 19 that
          climbs with E[c/n].  E[mu] at n = 19 is 1.46x / 1.43x it (22 / 18 SE).
      PRINTED, NOT SCORED: (i) if E[mu] froze at its n = 19 value, y*(256) would be
      1.46 / 1.43; (ii) the criterion fails at n = 256 only if E[mu] falls 31% / 30%
      below its n = 19 value, or lambda rises to about 0.35 -- double any value measured
      from n = 14; (iii) the class-1 increments of y* at their last ratio (0.54) level
      at 1.61 / 1.59.  Each is an extrapolation
      across 79 periods, on the share holding at 237 more bits than were measured.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_discount_share.py
      about 7 s on an aarch64 SBC (the superadditivity pass is most of it)
"""

import importlib.util
import json
import math
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
NAME = {0: "differential", 1: "linear"}
CLASS1 = (10, 13, 16, 19)         # n = 1 (mod 3), n = 7 left out
LATE = 14                         # §11.57.4's split: n = 14..20


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


TS = _load("v2_transient_series.py")   # PLAN, BAR, PINNED, measures(), wfit()
KS = TS.KS                             # strata(), estimate()
WIDTHS = [n for n, _ in TS.PLAN]


# ═══════════════════════════════════════════════════════════════════════════
# §1  superadditivity, and c <= 0 by Fekete
# ═══════════════════════════════════════════════════════════════════════════
def superadditive(W):
    """Number of pairs (a, b), a + b <= len(W), with W(a + b) < W(a) + W(b)."""
    R = len(W)
    return sum(1 for a in range(1, R + 1) for b in range(1, R - a + 1)
               if W[a + b - 1] < W[a - 1] + W[b - 1] - 1e-9)


def section_1(rec):
    rule("§1  c <= 0 is a theorem: W is superadditive, so W(r) <= mu * r (Fekete)")
    for axis in (0, 1):
        pairs = bad = cpos = keys = 0
        for n in WIDTHS:
            for row in rec["widths"][str(n)]:
                mu, W = row[2 + axis]
                R = len(W)
                keys += 1
                pairs += R * (R - 1) // 2
                bad += superadditive(W)
                cpos += sum(1 for r in range(1, R + 1) if W[r - 1] > mu * r + 1e-6)
        print("  %s: %d keys, %d pairs, %d violations, %d rounds with c(r) > 0"
              % (NAME[axis], keys, pairs, bad, cpos))
        check(bad == 0, "%s: W(a + b) >= W(a) + W(b) on all %d pairs a + b <= 2n of all "
              "%d pinned keys" % (NAME[axis], pairs, keys))
        check(cpos == 0, "%s: c(r) = W(r) - mu * r <= 0 at every r = 1..2n of every key "
              "-- Fekete's mu = sup W(r) / r" % NAME[axis])
    # controls: both checks fire on the tables a recording error would leave
    rows = rec["widths"][str(WIDTHS[0])]
    up = sum(1 for r in rows if superadditive([w + 1 for w in r[2][1]]) > 0)
    low = sum(1 for r in rows if any(w > 0.80 * r[2][0] * (i + 1) + 1e-6
                                     for i, w in enumerate(r[2][1])))
    check(up > len(rows) // 2, "CONTROL: superadditivity FIRES on W(r) + 1 at %d of %d "
          "n = %d keys" % (up, len(rows), WIDTHS[0]))
    check(low > len(rows) // 2, "CONTROL: c(r) <= 0 FIRES against a mu understated by 20%% "
          "at %d of %d n = %d keys" % (low, len(rows), WIDTHS[0]))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the discount's share
# ═══════════════════════════════════════════════════════════════════════════
def share(rec, n, axis):
    """lambda = -E[c/n] / E[mu] over the stratified sample, with a delta-method SE."""
    S = KS.strata(n)
    rows = rec["widths"][str(n)]
    r0 = 3 * n // 4
    cn = [-(r[2 + axis][1][r0 - 1] - r[2 + axis][0] * r0) / n for r in rows]
    mu = [r[2 + axis][0] for r in rows]
    Ec = KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, cn)], 0)[0]
    Em = KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, mu)], 0)
    lam = Ec / Em[0]
    res = [c - lam * m for c, m in zip(cn, mu)]
    se = KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, res)], 0)[1] / Em[0]
    return lam, se, Em, cn, mu


def section_2(rec, M):
    rule("§2  The discount's share: lambda = -E[c(3n/4)/n] / E[mu]")
    L = {}
    print("     n    differential: E[c/n]      lambda          linear: E[c/n]      lambda")
    for n in WIDTHS:
        for axis in (0, 1):
            L[(n, axis)] = share(rec, n, axis)
        d, l = L[(n, 0)], L[(n, 1)]
        print("  %4d   %+.3f +/- %.3f   %.4f +/- %.4f      %+.3f +/- %.3f   %.4f +/- %.4f"
              % (n, M[(n, 0)]["c"][0], M[(n, 0)]["c"][1], d[0], d[1],
                 M[(n, 1)]["c"][0], M[(n, 1)]["c"][1], l[0], l[1]))
    for axis in (0, 1):
        nm = NAME[axis]
        ls = TS.wfit([(n, L[(n, axis)][0], L[(n, axis)][1]) for n in WIDTHS if n >= LATE])
        cs = TS.wfit([(n,) + M[(n, axis)]["c"] for n in WIDTHS if n >= LATE])
        print("  %s, n = %d..%d: d(lambda)/dn %+.4f +/- %.4f; d(E[c/n])/dn %+.4f +/- %.4f"
              % (nm, LATE, WIDTHS[-1], ls[0], ls[1], cs[0], cs[1]))
        # if c/n deepened with mu held, lambda would rise by -dE[c/n]/dn / E[mu] per bit
        emu = st.mean(L[(n, axis)][2][0] for n in WIDTHS if n >= LATE)
        free = -cs[0] / emu
        print("  %s: a deepening independent of mu would raise lambda by %+.4f per bit"
              % (nm, free))
        check(-cs[0] > 5 * cs[1], "%s: E[c/n] deepens over n = %d..%d (%+.4f per bit, "
              "%.0f SE) -- §11.57.4's finding, the contrast" % (nm, LATE, WIDTHS[-1], cs[0],
                                                               -cs[0] / cs[1]))
        check(ls[0] + 2 * ls[1] < free / 2, "%s: its SHARE lambda moves %+.4f +/- %.4f per "
              "bit, under half (2 SE up) of the %+.4f a mu-independent deepening would give "
              "-- most of the deepening is mu's own growth" % (nm, ls[0], ls[1], free))
    return L


# ═══════════════════════════════════════════════════════════════════════════
# §3  not a per-key law
# ═══════════════════════════════════════════════════════════════════════════
def ols(xs, ys):
    """(intercept, its SE, slope) of an unweighted least-squares line."""
    k = len(xs)
    mx, my = st.mean(xs), st.mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    s2 = sum((y - a - b * x) ** 2 for x, y in zip(xs, ys)) / (k - 2)
    return a, math.sqrt(s2 * (1 / k + mx * mx / sxx)), b


def section_3(L):
    rule("§3  Not a per-key law: within a width, c/n = a + b * mu with a < 0")
    for axis in (0, 1):
        zs, bs = [], []
        for n in WIDTHS:
            _, _, _, cn, mu = L[(n, axis)]
            a, se, b = ols(mu, [-x for x in cn])
            if n >= LATE:
                zs.append(-a / se)
                bs.append((b, L[(n, axis)][0]))
            print("  %-12s n = %2d: c/n = %+.3f (+/- %.3f) %+.3f mu   (lambda %.3f)"
                  % (NAME[axis], n, a, se, b, L[(n, axis)][0]))
        check(min(zs) > 5, "%s: the intercept is below zero by %.0f SE or more at every "
              "width from n = %d -- the discount is not lambda * mu * n key by key"
              % (NAME[axis], min(zs), LATE))
        check(all(-b < 0.75 * lam for b, lam in bs), "%s: within a width c/n falls with "
              "mu at well under lambda per unit of mu (slope -%.3f at most, against "
              "lambda >= %.3f)" % (NAME[axis], max(-b for b, _ in bs),
                                   min(lam for _, lam in bs)))


# ═══════════════════════════════════════════════════════════════════════════
# §4  the class n = 1 (mod 3)
# ═══════════════════════════════════════════════════════════════════════════
def section_4(L):
    rule("§4  The class n = 1 (mod 3): y*(n) = E[mu] * (3/4 - lambda) / bar")
    for axis in (0, 1):
        nm, bar = NAME[axis], TS.BAR[axis]
        pts = [(n, L[(n, axis)][0], L[(n, axis)][1]) for n in WIDTHS if n >= LATE]
        w = [1 / e ** 2 for _, _, e in pts]
        lam = sum(wi * x for wi, (_, x, _) in zip(w, pts)) / sum(w)
        lse = 1 / math.sqrt(sum(w))
        ys = []
        for n in CLASS1:
            m, mse = L[(n, axis)][2]
            ys.append((n, m * (0.75 - lam) / bar, mse * (0.75 - lam) / bar,
                       m * math.floor(3 * n / 4) / n))
        print("\n  %s: pooled lambda over n = %d..%d = %.4f +/- %.4f"
              % (nm, LATE, WIDTHS[-1], lam, lse))
        for n, y, se, _ in ys:
            print("    n = %2d: E[mu] %.3f   y* = %.3f +/- %.3f   (floor(3n/4)/n = %.3f)"
                  % (n, L[(n, axis)][2][0], y, se, math.floor(3 * n / 4) / n))
        ups = [(b[1] - a[1]) / math.hypot(a[2], b[2]) for a, b in zip(ys, ys[1:])]
        check(min(ups) > 3, "%s: y* rises at every step of the class %s, by %.1f SE or "
              "more" % (nm, "->".join(str(n) for n in CLASS1), min(ups)))
        barmu = bar / (0.75 - lam)
        m19, s19 = L[(CLASS1[-1], axis)][2]
        old = (bar + L[(CLASS1[-1], axis)][0] * m19) / 0.75
        print("    bar on mu with the share held: %.3f (fixed in n); §11.57's at n = %d: "
              "%.3f (climbs with E[c/n])" % (barmu, CLASS1[-1], old))
        check((m19 - barmu) / s19 > 5, "%s: E[mu] at n = %d is %.2fx the share-held bar "
              "%.3f, %.0f SE above it" % (nm, CLASS1[-1], m19 / barmu, barmu,
                                          (m19 - barmu) / s19))
        inc = [b[1] - a[1] for a, b in zip(ys, ys[1:])]
        rho = inc[-1] / inc[-2]
        lev = ys[-1][1] + (inc[-1] * rho / (1 - rho) if 0 < rho < 1 else float("inf"))
        print("    PRINTED, NOT SCORED (extrapolations across %d periods):"
              % ((256 - CLASS1[-1]) // 3))
        print("      (i)   E[mu] frozen at n = %d:       y*(256) = %.2f" % (CLASS1[-1],
                                                                         ys[-1][1]))
        print("      (ii)  break-even: E[mu] %.0f%% below its n = %d value, or lambda "
              "= %.3f" % (100 * (1 - barmu / m19), CLASS1[-1], 0.75 - bar / m19))
        print("      (iii) increments of y* at their last ratio %.2f: y*(256) -> %.2f"
              % (rho, lev))


def main():
    print(__doc__)
    with open(TS.PINNED) as fh:
        rec = json.load(fh)
    M = TS.measures(rec)
    section_1(rec)
    L = section_2(rec, M)
    section_3(L)
    section_4(L)
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
