#!/usr/bin/env python3
"""v2_tail_n22.py — TODO #343 (eleventh pass): NL-FSCX v2's thin strata at n = 22, topped
up -- and the arc that n - tz(p) misses.

§11.62 (v2_series_n22.py) sampled 43 keys at n = 22 and left the tail thin: the strata
t >= 2 held 3-5 keys and the share below the bar was three keys.  This pass draws 33 more,
a second seeded draw disjoint from the first, bringing every stratum t = 2..8 to 8 keys
(the union of two disjoint simple random samples of a stratum is one, so the stratified
estimators carry over).  The run took 4 h 04 min at seven solves in parallel, 5 to 160
min per key; the three fastest were keys with arcs of 1, 5 and 8 bits.  The default run
reads the two pinned files and counts five widths exhaustively, so its verdicts cannot
flake.

  §1  THE TOP-UP is draw2()'s seeded sample, disjoint from §11.62's, and every stratum
      now holds 8 keys or more.  Fekete's c <= 0 holds on every new key.

  §2  THE TAIL AT n = 22, 76 keys.
      (a) E[mu] and lambda move by less than one of §11.62's SEs (2.754 / 1.429; 0.172
          / 0.162).
      (b) The share below the bar is 1.9% +/- 0.8% on both axes, down from 8.3% / 11.7%
          at n = 19 (2.6 / 3.4 SE).
      (c) CORRECTION to §11.62.2: a failing key has t = 4, a window n - tz(p) of 18 bits;
          its round constant's nonzero bits fit in an 8-bit arc.  So "every failure is a
          short window" held for §11.62's sample but not as a reading of the class.
      (d) §11.61's fixed-window slope with the 48 n = 22 keys of w = 15..20 added:
          +0.016 +/- 0.008 / +0.012 +/- 0.004 per bit, still 10 SE below random keys'.

  §3  THE ARC, NOT n - tz(p).  delta's nonzero bits lie in a cyclic arc of n minus its
      longest cyclic zero run; tz(p) is one zero run, so n - tz(p) only bounds the arc
      from above.  Over all 1319 pinned random keys (n = 10..22):
      (a) within a width the arc explains the margin y far better: R^2 0.62 / 0.63
          against 0.37 / 0.38 for the window.  CONTROL: the arcs shuffled within each
          width give 0.001.
      (b) from n = 19, keys with an arc over 12 bits fail 3 of 237 times on both axes,
          against 15 / 20 of 268 for a window over 12: §11.61's long-window failures are
          mostly short arcs.

  §4  WHAT IT CHANGES.  Counted exhaustively at n = 16, 17, 19, 20, 22, the short-arc
      class (arc <= 12) is 2.25-3.63x the short-window class (w <= 12), with no trend
      in n.  PRINTED, NOT SCORED: at that ratio it would weigh about 2^-121 at n = 256,
      against 2^-123 for w <= 12 -- an extrapolation, not a count.  A screen on the weak
      class should test the arc, not tz(p): tz(p) >= n - 12 misses most of it.

  CAVEATS.  The arc is a per-key regularity read off a sample stratified on t, not on the
  arc, so §3's counts are unweighted.  The fail share at n = 22 still rests on six keys.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_tail_n22.py [--regenerate]
      default      : verdicts from the pinned files (about 35 s; the exhaustive counts
                     at n = 22 are most of it)
      --regenerate : rebuild v2_tail_n22.json in parallel, resumable (about 4 h)
"""

import argparse
import math
import statistics as st
import importlib.util
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_tail_n22.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
TOPUP = 8                         # keys per stratum t >= 2 after the top-up
TFROM = 2                         # strata t = 0, 1 already hold 8 and 12


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


S22 = _load("v2_series_n22.py")       # draw(), solve(), measures22(), PINNED, N22, R22
KS = S22.KS
TS = S22.TS
DS = S22.DS
LW = _load("v2_long_window.py")      # keys(), cells(), WLONG, WTOP; SW.fe_slope/rand_slope
N22 = S22.N22
R22 = S22.R22
KQ = LW.KQ
SW = LW.SW
ARC = 12                          # §11.59's weak class, w <= 12, re-read as arc <= 12
EXH = (16, 17, 19, 20, 22)        # widths counted exhaustively in §4


def draw2(S=None):
    """The top-up, [(t, B)]: a second seeded draw from each stratum t >= TFROM, disjoint
    from draw()'s keys, bringing the stratum to TOPUP keys.  The union of two disjoint
    simple random samples of a stratum is itself one, so the estimators are unchanged."""
    import random
    S = S or KS.strata(N22)
    first = S22.draw(S)
    have = {}
    for t, B in first:
        have.setdefault(t, set()).add(B)
    rnd = random.Random(KS.SEED * 100 + N22 + 1)
    out = []
    for t in sorted(S):
        if t < TFROM:
            continue
        need = max(0, min(len(S[t]), TOPUP) - len(have.get(t, ())))
        pool = [B for B in S[t] if B not in have.get(t, ())]
        out += [(t, B) for B in rnd.sample(pool, need)]
    return out


def fail_se(S, rows, axis):
    """Stratified share of keys below the bar, with its SE (indicator variance)."""
    bar = TS.BAR[axis] * N22
    ind = [1.0 if r[2 + axis][1][R22 - 1] < bar else 0.0 for r in rows]
    return KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, ind)], 0)


def section_1(first, top, S):
    rule("§1  The top-up: strata t >= %d brought to %d keys" % (TFROM, TOPUP))
    check([(r[0], r[1]) for r in top] == draw2(S), "the pinned top-up is exactly draw2()'s "
          "seeded sample (%d keys)" % len(top))
    a, b = {r[1] for r in first}, {r[1] for r in top}
    check(not a & b, "it is disjoint from §11.62's %d keys" % len(a))
    k = {t: sum(1 for r in first + top if r[0] == t) for t in S}
    print("  keys per stratum: %s" % ", ".join("t%d: %d" % kv for kv in sorted(k.items())))
    check(all(v >= TOPUP for t, v in k.items()), "every stratum now holds %d keys or more"
          % TOPUP)
    for axis in (0, 1):
        bad = sum(DS.superadditive(r[2 + axis][1]) for r in top)
        cpos = sum(1 for r in top for i, w in enumerate(r[2 + axis][1])
                   if w > r[2 + axis][0] * (i + 1) + 1e-6)
        check(bad == 0 and cpos == 0, "%s: W superadditive and c(r) <= 0 on every top-up "
              "key" % NAME[axis])


def arc(d, n):
    """The cyclic arc of delta: n minus its longest cyclic run of zero bits.  delta's
    nonzero bits all lie in an arc this long; n - tz(p) is only an upper bound on it."""
    if d == 0:
        return 0
    s = format(d, "0%db" % n)
    return n - min(n, max(map(len, (s + s).split("1"))))


def section_2(first, top, S, M):
    rule("§2  The tail at n = %d: %d keys" % (N22, len(first) + len(top)))
    rows = first + top
    M43, M76 = S22.measures22(first, S), S22.measures22(rows, S)
    old = json.load(open(TS.PINNED))
    for axis in (0, 1):
        nm = NAME[axis]
        f43, f76 = fail_se(S, first, axis), fail_se(S, rows, axis)
        S19 = KS.strata(19)
        r19 = old["widths"]["19"]
        bar = TS.BAR[axis] * 19
        ind = [1.0 if r[2 + axis][1][3 * 19 // 4 - 1] < bar else 0.0 for r in r19]
        f19 = KS.estimate(S19, [[r[0], r[1], x, x] for r, x in zip(r19, ind)], 0)
        print("\n  %s:   E[mu]            lambda            below the bar" % nm)
        for lab, e, f in (("43 keys", M43[axis], f43), ("76 keys", M76[axis], f76)):
            print("    %s  %.3f +/- %.3f   %.4f +/- %.4f   %.1f%% +/- %.1f%%"
                  % (lab, e["mu"][0], e["mu"][1], e["lam"][0], e["lam"][1], 100 * f[0],
                     100 * f[1]))
        print("    n = 19   %.3f +/- %.3f                     %.1f%% +/- %.1f%%"
              % (M[(19, axis)]["mu"][0], M[(19, axis)]["mu"][1], 100 * f19[0], 100 * f19[1]))
        check(abs(M76[axis]["mu"][0] - M43[axis]["mu"][0]) < M43[axis]["mu"][1]
              and abs(M76[axis]["lam"][0] - M43[axis]["lam"][0]) < M43[axis]["lam"][1],
              "%s: the top-up leaves §11.62's E[mu] and lambda within one of their SEs"
              % nm)
        z = (f19[0] - f76[0]) / math.hypot(f19[1], f76[1])
        check(z > 2, "%s: the share below the bar falls from n = 19, %.1f%% -> %.1f%% "
              "+/- %.1f%% (%.1f SE)" % (nm, 100 * f19[0], 100 * f76[0], 100 * f76[1], z))
    low = [r for r in rows if r[2][1][R22 - 1] < TS.BAR[0] * N22]
    lw = [(r[0], N22 - KQ.tz_p(r[1], N22), arc(S22.AUD.delta(r[1], N22), N22)) for r in low]
    print("\n  keys below the differential bar (t, w = n - tz(p), arc): %s" % lw)
    check(any(w >= 17 for _, w, _ in lw) and all(a <= ARC for _, w, a in lw if w >= 17),
          "CORRECTION to §11.62.2: a failing key has a window of %d bits by n - tz(p), but "
          "its delta's nonzero bits fit in an arc of %d" % max((w, a) for _, w, a in lw))
    # §11.61's fixed-window slope, with the n = 22 cells w = 15..20 added
    K, _ = LW.keys()
    for axis in (0, 1):
        pts = [(k[2], k[1], k[3][axis]) for k in K if k[0] == "R" and k[2] >= LW.WLONG]
        p22 = [(N22 - r[0], N22, r[2 + axis][0]) for r in rows
               if r[0] < KS.TMAX and LW.WLONG <= N22 - r[0] <= LW.WTOP]
        b, se = SW.fe_slope(pts + p22)
        gen = SW.rand_slope(M, axis)
        z = (gen[0] - b) / math.hypot(se, gen[1])
        check(z > 5, "%s: with %d n = %d keys added, the fixed-window slope is %+.4f +/- "
              "%.4f per bit, still %.0f SE below random keys' %+.4f" % (NAME[axis],
                                                                       len(p22), N22, b,
                                                                       se, z, gen[0]))
    for axis in (0, 1):
        print("  PRINTED: %s mean mu at n = %d by window: %s" % (NAME[axis], N22, ", ".join(
            "w%d %.2f" % (w, st.mean(r[2 + axis][0] for r in rows if N22 - r[0] == w))
            for w in range(N22 - KS.TMAX + 1, N22 + 1))))


def keyset(first, top):
    """[(n, w, arc, y_d, y_l)] over every random key pinned: §11.57's and n = 22's."""
    old = json.load(open(TS.PINNED))
    out = []
    for n, _ in TS.PLAN:
        r0 = 3 * n // 4
        for r in old["widths"][str(n)]:
            out.append((n, n - KQ.tz_p(r[1], n), arc(S22.AUD.delta(r[1], n), n),
                        r[2][1][r0 - 1] / (TS.BAR[0] * n), r[3][1][r0 - 1] / (TS.BAR[1] * n)))
    for r in first + top:
        out.append((N22, N22 - KQ.tz_p(r[1], N22), arc(S22.AUD.delta(r[1], N22), N22),
                    r[2][1][R22 - 1] / (TS.BAR[0] * N22), r[3][1][R22 - 1] / (TS.BAR[1] * N22)))
    return out


def fe_r2(pts):
    """Within-width R^2 of y on x: one intercept per width."""
    g = {}
    for n, x, y in pts:
        g.setdefault(n, []).append((x, y))
    sxx = sxy = syy = 0.0
    for v in g.values():
        mx, my = st.mean(x for x, _ in v), st.mean(y for _, y in v)
        sxx += sum((x - mx) ** 2 for x, _ in v)
        sxy += sum((x - mx) * (y - my) for x, y in v)
        syy += sum((y - my) ** 2 for _, y in v)
    return sxy * sxy / (sxx * syy)


def section_3(K):
    rule("§3  The arc, not n - tz(p): where delta's nonzero bits actually lie")
    print("  %d random keys, n = 10..%d" % (len(K), N22))
    for axis in (0, 1):
        nm = NAME[axis]
        rw = fe_r2([(k[0], k[1], k[3 + axis]) for k in K])
        ra = fe_r2([(k[0], k[2], k[3 + axis]) for k in K])
        check(ra > rw + 0.15, "%s: within a width the arc explains y far better than the "
              "window: R^2 %.2f against %.2f" % (nm, ra, rw))
        # CONTROL: the same arcs, shuffled among the keys of each width, explain nothing
        import random
        rnd, sh = random.Random(KS.SEED), []
        for n in sorted({k[0] for k in K}):
            v = [k for k in K if k[0] == n]
            a = [k[2] for k in v]
            rnd.shuffle(a)
            sh += [(n, x, k[3 + axis]) for k, x in zip(v, a)]
        rs = fe_r2(sh)
        check(rs < rw / 4, "CONTROL: %s: the arcs shuffled within each width give R^2 %.3f"
              % (nm, rs))
        late = [k for k in K if k[0] >= 19]
        lw = [k for k in late if k[1] > ARC]
        la = [k for k in late if k[2] > ARC]
        fw, fa = sum(k[3 + axis] < 1 for k in lw), sum(k[3 + axis] < 1 for k in la)
        print("  %s, n >= 19: window > %d: %d of %d keys fail;  arc > %d: %d of %d"
              % (nm, ARC, fw, len(lw), ARC, fa, len(la)))
        check(fa * len(lw) * 4 < fw * len(la), "%s: from n = 19, keys with an arc over %d "
              "bits fail at under a quarter the rate of keys with a window over %d (%d of %d "
              "against %d of %d) -- §11.61's long-window failures are mostly short arcs"
              % (nm, ARC, ARC, fa, len(la), fw, len(lw)))


def section_4():
    rule("§4  What it changes: the short-arc class, counted exhaustively")
    print("     n   P(arc <= %d)     P(w <= %d)     ratio" % (ARC, ARC))
    rat = []
    for n in EXH:
        aff = KS.affine(n)
        ca = cw = tot = 0
        for B in range(1 << n):
            d = S22.AUD.delta(B, n)
            if d in aff:
                continue
            tot += 1
            ca += arc(d, n) <= ARC
            cw += n - KQ.tz_p(B, n) <= ARC
        rat.append(ca / cw)
        print("  %4d   %.5f (2^%.2f)   %.5f (2^%.2f)   %.2f" % (n, ca / tot,
              math.log2(ca / tot), cw / tot, math.log2(cw / tot), ca / cw))
    check(all(2 <= r <= 4 for r in rat), "the short-arc class is 2-4x the short-window "
          "class at every width n = %s (%s), not a growing multiple"
          % (", ".join(map(str, EXH)), ", ".join("%.2f" % r for r in rat)))
    P = KQ.p_tail(256, 256 - ARC)
    print("  PRINTED, NOT SCORED: at n = 256, P(w <= %d) = 2^%.1f; at the measured ratio "
          "(at most %.1f) P(arc <= %d) would be about 2^%.0f -- an extrapolation, not a count"
          % (ARC, math.log2(P), max(rat), ARC, math.log2(P * max(rat))))


def regenerate():
    S22.ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                B, a, b = json.loads(ln)
                done[B] = (a, b)
    rows = draw2()
    jobs = [(t, B) for t, B in rows if B not in done]
    print("n = %d top-up: %d keys, %d to solve" % (N22, len(rows), len(jobs)), flush=True)
    lock = threading.Lock()

    def one(job):
        import time
        t, B = job
        t0 = time.time()
        a, b = S22.solve(B)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, a, b]) + "\n")
            done[B] = (a, b)
            print("  %s t = %d, B = %d: mu %.4f / %.4f in %.0f s (%d done)"
                  % (time.strftime("%H:%M"), t, B, a[0], b[0], time.time() - t0,
                     len(done)), flush=True)

    with ThreadPoolExecutor(S22.JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 trail weights W(1..3n/4) at n = 22, the "
                   "top-up of strata t >= 2 to %d keys; rows as v2_series_n22.json" % TOPUP,
                   "seed": KS.SEED, "n": N22, "topup": TOPUP,
                   "rows": [[t, B] + list(done[B]) for t, B in rows]},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return 0
    print(__doc__)
    with open(S22.PINNED) as fh:
        first = json.load(fh)["rows"]
    with open(PINNED) as fh:
        top = json.load(fh)["rows"]
    with open(TS.PINNED) as fh:
        M = TS.measures(json.load(fh))
    S = KS.strata(N22)
    section_1(first, top, S)
    section_2(first, top, S, M)
    section_3(keyset(first, top))
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
