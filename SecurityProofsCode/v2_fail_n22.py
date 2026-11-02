#!/usr/bin/env python3
"""v2_fail_n22.py — TODO #257: the share of v2 keys below the bar at n = 22, with an
honest SE.

§11.63 (v2_tail_n22.py) put the share of n = 22 keys below the deployed criterion at
1.9% +/- 0.8% over 76 keys, and read it as falling from n = 19 by 2.6 / 3.4 SE.  That SE
is the plain stratified one, and a stratum with no failure in its sample contributes NO
variance to it, however few keys it holds.  Strata t = 0..3 hold 84% of the keys and had
0 failures in 36; so the 0.8% measured only the tail strata.  This pass gives each
stratum a variance at its Jeffreys-smoothed share (f + 1/2) / (k + 1) -- 3.3% at 76 keys
-- and draws 80 more keys, Neyman-allocated for that SE, as a third seeded sample
disjoint from the first two (28 / 33 / 1 / 14 / 0 / 2 / 0 / 0 / 2 into t = 0..8).  The
run took 14 h 50 min at seven solves in parallel, median 59 min per key, slowest 231.
The default run reads the three pinned files, so its verdicts cannot flake.

  §1  THE DRAW is exactly draw3()'s seeded sample, disjoint from §11.62's and §11.63's
      keys, and the allocation sums to 156.  c(r) <= 0 on every new key.

  §2  THE SHARE AT n = 22, 156 keys: 3.1% +/- 1.1% on both axes (Jeffreys SE 1.5%),
      1.1 of its SEs above §11.63's 1.9% -- the old SE, not the old point, was wrong.
      (a) on the 76 keys the plain SE is under 0.3x the Jeffreys SE; the Neyman draw
          more than halves the Jeffreys SE.  CONTROL: clearing the one t = 1 failure
          lowers the share by exactly W_1 / k_1 = 0.83%, so the estimator counts it.
      (b) CORRECTION to §11.63.3: a key in t = 1, the largest stratum, fails on both axes
          with an arc of 19 of 22 bits (B = 802195, 0.30 / 0.50 below the bar).  The arc
          still predicts -- arcs <= 12 fail 6 of 13, longer ones 3 of 143 -- but a short
          arc is the strongest predictor of a weak key, not the whole class.
      PRINTED: the closest clear key is 0.004 above the differential bar.

  §3  THE FALL FROM n = 19, re-read with the Jeffreys SE.
      (a) CORRECTION to §11.63.1: differential 8.3% -> 3.1% is 1.7 SE, not established
          at 2.  CONTROL: §11.63's own reading (76 keys, plain SE) clears 2 SE, 2.6.
      (b) linear 11.7% -> 3.1% is 2.5 SE, so it survives.
      (c) §11.67's n = 23 shares (1.7% / 2.6%) have the same understatement: plain SE
          0.95% / 0.83% against Jeffreys 3.76% / 3.74%; their fall from n = 19 is
          1.4 / 1.9 SE Jeffreys.  PRINTED, not re-measured.

  §4  E[mu] AND lambda.  E[mu] = 2.726 +/- 0.023 / 1.413 +/- 0.015, less than one of
      §11.63's SEs below it, and 1.59x / 1.63x SECURITY.md's conjectured bars.  lambda
      stays within §11.62's 0.015 of the pooled value (+0.007 / -0.007); the linear one
      moved up 1.1 of §11.63's SEs, toward the pooled value.

  CAVEATS.  The Jeffreys prior is one choice of smoothing, and it is conservative where a
  stratum truly has no failures; it is printed beside the plain SE, not in place of it.
  The share below the bar is not the rating's conjecture, which is on the key-averaged
  E[mu]; no rating moves.  This is a measurement at n = 22, not a bound at n = 256.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_fail_n22.py [--regenerate | --plan | --preview]
      default      : verdicts from the pinned files (about 15 s)
      --regenerate : solve the 80 keys of v2_fail_n22.json, in parallel and resumable
                     (about 15 h at JOBS = 7, ~0.9 GB per solve)
      --plan       : print the allocation and the draw without solving
      --preview    : the verdicts on a run's partial checkpoint
"""

import argparse
import importlib.util
import json
import math
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_fail_n22.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
TOTAL = 156                      # keys at n = 22 after this draw: 76 pinned + 80


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


T22 = _load("v2_tail_n22.py")        # draw2(), fail_se(), arc(), PINNED; S22, KS, TS
S22 = T22.S22                        # draw(), solve(), PINNED, N22, R22, JOBS
KS = T22.KS
TS = T22.TS
N22 = S22.N22
R22 = S22.R22


def pinned76():
    with open(S22.PINNED) as fh:
        first = json.load(fh)["rows"]
    with open(T22.PINNED) as fh:
        top = json.load(fh)["rows"]
    return first, top


def below(r, axis):
    return r[2 + axis][1][R22 - 1] < TS.BAR[axis] * N22


def jeffreys(f, k):
    """The share of a stratum with f of k keys below the bar, smoothed by the Jeffreys
    prior Beta(1/2, 1/2): (f + 1/2) / (k + 1).  Never 0, so a stratum with no failures
    in its sample still carries variance."""
    return (f + 0.5) / (k + 1)


def allocation(S, rows):
    """Neyman allocation of TOTAL keys over the strata, for the stratified share below
    the bar, with each stratum's spread read from the 76 pinned keys under the Jeffreys
    share (the larger of the two axes), and no stratum below the keys it already has."""
    tot = sum(len(v) for v in S.values())
    w = {}
    for t in S:
        rr = [r for r in rows if r[0] == t]
        p = max(jeffreys(sum(below(r, a) for r in rr), len(rr)) for a in (0, 1))
        w[t] = len(S[t]) / tot * math.sqrt(p * (1 - p))
    have = {t: sum(1 for r in rows if r[0] == t) for t in S}
    # A stratum whose Neyman share is under what it holds keeps what it holds; the rest
    # of TOTAL is shared out again among the others, until no share is under its floor.
    fixed = {}
    while True:
        free = [t for t in S if t not in fixed]
        left = TOTAL - sum(fixed.values())
        s = sum(w[t] for t in free)
        share = {t: left * w[t] / s for t in free}
        low = [t for t in free if share[t] < have[t]]
        if not low:
            break
        fixed.update({t: have[t] for t in low})
    # largest remainder, so the counts sum to TOTAL exactly
    out = {**fixed, **{t: int(share[t]) for t in free}}
    rest = TOTAL - sum(out.values())
    for t in sorted(free, key=lambda t: share[t] - int(share[t]), reverse=True)[:rest]:
        out[t] += 1
    return {t: min(len(S[t]), out[t]) for t in S}


def draw3(S=None):
    """The third draw, [(t, B)]: from each stratum, a seeded sample disjoint from
    §11.62's and §11.63's keys, bringing it to allocation()'s count.  The union of
    disjoint simple random samples of a stratum is itself one, so the stratified
    estimators carry over."""
    S = S or KS.strata(N22)
    first, top = pinned76()
    rows = first + top
    have = {}
    for r in rows:
        have.setdefault(r[0], set()).add(r[1])
    alloc = allocation(S, rows)
    rnd = random.Random(KS.SEED * 100 + N22 + 2)
    out = []
    for t in sorted(S):
        pool = [B for B in S[t] if B not in have.get(t, ())]
        out += [(t, B) for B in rnd.sample(pool, alloc[t] - len(have.get(t, ())))]
    return out


def regenerate():
    S22.ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                B, a, b, sec = json.loads(ln)
                done[B] = (a, b, sec)
    rows = draw3()
    jobs = [(t, B) for t, B in rows if B not in done]
    print("n = %d third draw: %d keys, %d to solve, %d in parallel"
          % (N22, len(rows), len(jobs), S22.JOBS), flush=True)
    lock = threading.Lock()

    def one(job):
        t, B = job
        t0 = time.time()
        a, b = S22.solve(B)
        sec = round(time.time() - t0)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, a, b, sec]) + "\n")
            done[B] = (a, b, sec)
            print("  %s t = %d, B = %d: mu %.4f / %.4f in %d s (%d of %d done)"
                  % (time.strftime("%H:%M"), t, B, a[0], b[0], sec, len(done), len(rows)),
                  flush=True)

    with ThreadPoolExecutor(S22.JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #257: exact v2 trail weights W(1..3n/4) at n = 22, a third "
                   "draw Neyman-allocated for the share below the bar; rows are [stratum "
                   "t, key B, [mu_diff, W_diff], [mu_lin, W_lin], solve seconds]",
                   "seed": KS.SEED, "n": N22, "total": TOTAL,
                   "rows": [[t, B] + list(done[B]) for t, B in rows]},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def share(S, rows, n, axis):
    """The stratified share of keys below the bar: (p, SE, Jeffreys SE, {t: (f, k)}).
    The plain SE is KS.estimate's, the sample variance of the indicator per stratum, and
    it is ZERO for a stratum with no failure in its sample however few keys that is.
    The Jeffreys SE puts each stratum's variance at its smoothed share instead.  Both
    carry the finite-population correction; the point estimate is the plain one."""
    r = 3 * n // 4
    tot = sum(len(v) for v in S.values())
    p, var, vj, per = 0.0, 0.0, 0.0, {}
    for t in S:
        xs = [1.0 if x[2 + axis][1][r - 1] < TS.BAR[axis] * n else 0.0
              for x in rows if x[0] == t]
        if not xs:
            continue
        k, f, w = len(xs), int(sum(xs)), len(S[t]) / tot
        fpc = 1 - k / len(S[t])
        p += w * f / k
        if k > 1:
            var += w * w * (f * (k - f) / (k * (k - 1))) / k * fpc
        pj = jeffreys(f, k)
        vj += w * w * pj * (1 - pj) / k * fpc
        per[t] = (f, k)
    return p, math.sqrt(var), math.sqrt(vj), per


def section_1(S, old, new, preview):
    rule("§1  The third draw: %d keys, Neyman-allocated for the share below the bar"
         % len(new))
    al = allocation(S, old)
    print("  allocation (keys per stratum after the draw): %s"
          % ", ".join("t%d: %d" % kv for kv in sorted(al.items())))
    check(sum(al.values()) == TOTAL, "the allocation sums to %d keys" % TOTAL)
    if not preview:
        check([(r[0], r[1]) for r in new] == draw3(S), "the pinned rows are exactly "
              "draw3()'s seeded sample (%d keys)" % len(new))
    check(not {r[1] for r in old} & {r[1] for r in new}, "it is disjoint from §11.62's "
          "and §11.63's %d keys" % len(old))
    for axis in (0, 1):
        cpos = sum(1 for r in new for i, w in enumerate(r[2 + axis][1])
                   if w > r[2 + axis][0] * (i + 1) + 1e-6)
        check(cpos == 0, "%s: c(r) <= 0 on every new key" % NAME[axis])
    sec = sorted(r[4] for r in new)
    print("  solve time per key: median %.0f min, slowest %.0f min"
          % (sec[len(sec) // 2] / 60, sec[-1] / 60))


def section_2(S, old, new):
    rule("§2  The share below the bar at n = %d, %d -> %d keys"
         % (N22, len(old), len(old) + len(new)))
    out = {}
    for axis in (0, 1):
        a, b = share(S, old, N22, axis), share(S, old + new, N22, axis)
        out[axis] = (a, b)
        nm = NAME[axis]
        print("\n  %s:" % nm)
        for lab, x in (("%d keys" % len(old), a), ("%d keys" % len(old + new), b)):
            print("    %-9s %.2f%%   SE %.2f%%   Jeffreys SE %.2f%%"
                  % (lab, 100 * x[0], 100 * x[1], 100 * x[2]))
        print("    failures per stratum (f of k): %s"
              % ", ".join("t%d: %d/%d" % (t, f, k) for t, (f, k) in sorted(b[3].items())))
        check(a[1] < 0.3 * a[2], "%s: on §11.63's 76 keys the plain SE (%.2f%%) is under "
              "0.3x the Jeffreys SE (%.2f%%) -- strata t = 0..3, 84%% of keys, have no "
              "failure and so no plain variance" % (nm, 100 * a[1], 100 * a[2]))
        check(b[2] < 0.5 * a[2], "%s: the Neyman draw more than halves the Jeffreys SE, "
              "%.2f%% -> %.2f%%" % (nm, 100 * a[2], 100 * b[2]))
        check(b[0] > a[0] and (b[0] - a[0]) < 1.5 * b[1], "%s: the share rises to %.2f%% "
              "+/- %.2f%%, %.1f of its SEs above §11.63's %.2f%%: the old SE was the "
              "understatement" % (nm, 100 * b[0], 100 * b[1], (b[0] - a[0]) / b[1],
                                  100 * a[0]))
    # CONTROL: the estimator counts a failure in the largest stratum at its weight.
    tot = sum(len(v) for v in S.values())
    k1 = sum(1 for r in old + new if r[0] == 1)
    flip = [r for r in old + new if not (r[0] == 1 and below(r, 0))]
    flip += [[r[0], r[1], [r[2][0], [99.0] * R22], [r[3][0], [99.0] * R22]]
             for r in old + new if r[0] == 1 and below(r, 0)]
    d = out[0][1][0] - share(S, flip, N22, 0)[0]
    check(abs(d - len(S[1]) / tot / k1) < 1e-12, "CONTROL: clearing the t = 1 failure "
          "lowers the share by exactly W_1 / k_1 = %.2f%%" % (100 * d))
    arcs = {}
    for axis in (0, 1):
        low = [r for r in old + new if below(r, axis)]
        lw = [(r[0], N22 - T22.KQ.tz_p(r[1], N22), T22.arc(S22.AUD.delta(r[1], N22), N22))
              for r in low]
        print("  keys below the %s bar (t, w = n - tz(p), arc): %s" % (NAME[axis], lw))
        arcs[axis] = lw
    rows = old + new
    ak = [T22.arc(S22.AUD.delta(r[1], N22), N22) for r in rows]
    for axis in (0, 1):
        sh_ = [below(r, axis) for r, x in zip(rows, ak) if x <= T22.ARC]
        lo_ = [below(r, axis) for r, x in zip(rows, ak) if x > T22.ARC]
        print("  %s: arc <= %d fails %d of %d; arc > %d fails %d of %d"
              % (NAME[axis], T22.ARC, sum(sh_), len(sh_), T22.ARC, sum(lo_), len(lo_)))
        check(sum(sh_) / len(sh_) > 10 * sum(lo_) / len(lo_), "%s: the arc still predicts: "
              "short arcs fail over 10x as often as long ones" % NAME[axis])
        check(any(t == 1 and a >= 17 for t, w, a in arcs[axis]), "%s: CORRECTION to "
              "§11.63.3 -- a key of the largest stratum fails with an arc of %d of %d bits, "
              "so the short arc is the strongest predictor, not the whole weak class"
              % (NAME[axis], max(a for t, w, a in arcs[axis] if t == 1), N22))
    near = min((r[2][1][R22 - 1] - TS.BAR[0] * N22, r[1]) for r in rows
               if not below(r, 0))
    print("  PRINTED, NOT SCORED: the closest clear is B = %d, %.3f above the "
          "differential bar" % (near[1], near[0]))
    return out


def section_3(S, sh, n_old, n_all):
    rule("§3  The fall from n = 19, re-read with the Jeffreys SE")
    with open(TS.PINNED) as fh:
        r19 = json.load(fh)["widths"]["19"]
    with open(os.path.join(HERE, "v2_series_n23.json")) as fh:
        r23 = json.load(fh)["rows"]
    S19, S23 = KS.strata(19), KS.strata(23)
    for axis in (0, 1):
        nm = NAME[axis]
        c, e = share(S19, r19, 19, axis), share(S23, r23, 23, axis)
        a, b = sh[axis]
        z = [(c[0] - x[0]) / math.hypot(c[i], x[i]) for x in (a, b) for i in (1, 2)]
        print("  %s: n = 19 %.1f%% (SE %.1f%%, Jeffreys %.1f%%)" % (nm, 100 * c[0],
              100 * c[1], 100 * c[2]))
        print("    fall to n = 22, %d keys: %.1f SE plain, %.1f SE Jeffreys; "
              "%d keys: %.1f SE plain, %.1f SE Jeffreys"
              % ((n_old,) + tuple(z[:2]) + (n_all,) + tuple(z[2:])))
        check(z[0] > 2, "%s: CONTROL -- §11.63's reading, 76 keys with the plain SE, "
              "clears 2 SE (%.1f)" % (nm, z[0]))
        z23 = (c[0] - e[0]) / math.hypot(c[2], e[2])
        print("    n = 23 (%d keys) %.1f%%: SE %.2f%%, Jeffreys %.2f%%; fall from n = 19 "
              "%.1f SE Jeffreys" % (len(r23), 100 * e[0], 100 * e[1], 100 * e[2], z23))
        check(e[1] < 0.3 * e[2], "%s: §11.67's n = 23 share has the same understatement, "
              "plain SE %.2f%% against Jeffreys %.2f%%" % (nm, 100 * e[1], 100 * e[2]))
        if axis == 0:
            check(z[3] < 2, "differential: CORRECTION to §11.63.1 -- with the Jeffreys "
                  "SE and 156 keys the fall from n = 19 is %.1f SE, not established at 2"
                  % z[3])
        else:
            check(z[3] > 2, "linear: the fall from n = 19 survives, %.1f SE Jeffreys on "
                  "156 keys" % z[3])


def conjectured_bars():
    """The v2 conjecture's bars, read from SECURITY.md's HSKE-NL-A2 row."""
    import re
    with open(os.path.join(os.path.dirname(HERE), "SECURITY.md"), encoding="utf-8") as fh:
        m = re.search(r"at or above (\d\.\d+) differential and (\d\.\d+) linear",
                      fh.read())
    return float(m.group(1)), float(m.group(2))


def pooled_lambda(axis):
    """§11.62's pooled discount share over n = LATE..: inverse-variance weighted."""
    with open(TS.PINNED) as fh:
        rec = json.load(fh)
    DS = S22.DS
    pts = [DS.share(rec, n, axis)[:2] for n in DS.WIDTHS if n >= DS.LATE]
    wt = [1 / se ** 2 for _, se in pts]
    return (sum(w * x for w, (x, _) in zip(wt, pts)) / sum(wt), 1 / math.sqrt(sum(wt)))


def section_4(S, old, new):
    rule("§4  E[mu] and lambda with the third draw")
    a, b = S22.measures22(old, S), S22.measures22(old + new, S)
    for axis in (0, 1):
        nm = NAME[axis]
        print("  %s: E[mu] %.3f +/- %.3f -> %.3f +/- %.3f;  lambda %.4f -> %.4f"
              % (nm, a[axis]["mu"][0], a[axis]["mu"][1], b[axis]["mu"][0],
                 b[axis]["mu"][1], a[axis]["lam"][0], b[axis]["lam"][0]))
        check(abs(b[axis]["mu"][0] - a[axis]["mu"][0]) < a[axis]["mu"][1],
              "%s: E[mu] moves by less than one of §11.63's SEs (%.1f)"
              % (nm, (b[axis]["mu"][0] - a[axis]["mu"][0]) / a[axis]["mu"][1]))
        lam, lse = pooled_lambda(axis)
        dl = b[axis]["lam"][0] - lam
        print("    lambda moves %+.1f of §11.63's SEs; pooled lambda (n = %d..%d) %.4f, "
              "lambda(22) - pooled = %+.4f" % ((b[axis]["lam"][0] - a[axis]["lam"][0])
                                               / a[axis]["lam"][1], S22.DS.LATE,
                                               S22.DS.WIDTHS[-1], lam, dl))
        check(abs(dl) < 0.015, "%s: the share holds -- lambda(22) within §11.62's 0.015 "
              "of the pooled value (%+.4f)" % (nm, dl))
        bar = conjectured_bars()[axis]
        check(b[axis]["mu"][0] / bar > 1.5, "%s: E[mu] is %.2fx SECURITY.md's conjectured "
              "bar %.3f" % (nm, b[axis]["mu"][0] / bar, bar))


def load_new(preview):
    if not preview:
        with open(PINNED) as fh:
            return json.load(fh)["rows"]
    t = dict((B, t) for t, B in draw3())
    with open(PINNED + ".partial") as fh:
        return [[t[B], B, a, b, sec] for B, a, b, sec in map(json.loads, fh)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--preview", action="store_true",
                    help="read the partial checkpoint of a run in progress")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return 0
    if a.plan:
        S = KS.strata(N22)
        first, top = pinned76()
        al = allocation(S, first + top)
        d = draw3(S)
        print("allocation:", al, "new keys:", len(d))
        print({t: sum(1 for x in d if x[0] == t) for t in S})
        return 0
    print(__doc__)
    S = KS.strata(N22)
    first, top = pinned76()
    old, new = first + top, load_new(a.preview)
    section_1(S, old, new, a.preview)
    sh = section_2(S, old, new)
    section_3(S, sh, len(old), len(old) + len(new))
    section_4(S, old, new)
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
