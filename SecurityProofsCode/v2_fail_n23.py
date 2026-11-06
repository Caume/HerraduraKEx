#!/usr/bin/env python3
"""v2_fail_n23.py — TODO #257 (thirteenth pass): the fall of the v2 fail share from
n = 19 to n = 23, with an honest SE at both ends.

CORRECTED IN PART by v2_fail_n20.py (§11.80): §3's printed flat step from n = 22 to 23
is the residue class changing; within n = 23's class the share falls from n = 20 (450
keys) to 23 by 3.1 / 2.5 SE.

§11.78 (v2_fail_n22.py) found that the plain stratified SE of the share of keys below the
deployed criterion gives a stratum with no failure no variance, and re-read the fall from
n = 19 with Jeffreys-smoothed strata: at n = 23 (§11.67, 50 keys) the 1.7% / 2.6% carry a
Jeffreys SE of about 3.75%, so their fall from n = 19 is 1.4 / 1.9 SE.  Re-drawing n = 23
alone cannot settle it: n = 19's own Jeffreys SE, 2.7% / 3.0% on 113 keys, caps the fall
near 2.4 SE however well n = 23 is measured.  So this pass draws at BOTH ends, each a
Neyman allocation for the Jeffreys SE of the share, seeded and disjoint from every
earlier sample of its width: n = 19 to TOTAL19 keys and n = 23 to TOTAL23.

n = 19 went from 113 to 450 keys (337 new, median 2.2 min per key) and n = 23 from 50 to
150 (100 new, median 165 min, slowest 639), about 2 days 9 h at six solves in parallel.

  §1  THE DRAWS are exactly draw()'s seeded samples, disjoint from the earlier keys, and
      each allocation sums to its TOTAL.  c(r) <= 0 on every new key.

  §2  THE SHARES.  n = 19: 8.4% / 10.3% (Jeffreys SE 1.2% / 1.2%, was 2.7% / 3.0%);
      n = 23: 1.6% / 3.1% (Jeffreys 1.3% / 1.5%, was 3.8% / 3.7%).  At both widths the
      draw more than halves the Jeffreys SE and moves the share by less than one old plain
      SE: the old points held.  CONTROL: clearing one n = 23 failure in t = 8 lowers the
      share by exactly W_8 / k_8.

  §3  THE FALL FROM n = 19 is established: to n = 23 by 4.0 / 3.7 SE Jeffreys.
      CONTROL: on the old samples it is 1.4 / 1.9.  CORRECTION to §11.78.3: the
      differential fall to n = 22 is 2.7 SE with 450 n = 19 keys, so it IS established;
      §11.78's 1.7 came from n = 19's thin sample.  PRINTED: n = 22 -> 23 moves 0.8 / 0.0
      SE, no further fall across that step.

  §4  THE ARC.  Short arcs fail over 10x as often as long ones at both widths (n = 23:
      5 / 7 of 8 against 0 / 1 of 142).  §11.78's correction repeats: an n = 23 key in
      t = 1 fails linear with an arc of 17 of 23 bits, so §11.67's "every key below the bar
      has tz(p) >= 6" was its sample's, not the class's.

  §5  E[mu] AND lambda AT n = 23.  E[mu] = 2.794 +/- 0.019 / 1.464 +/- 0.013, within one of
      §11.67's SEs and 1.63x / 1.69x the conjectured bars; lambda within 0.015 of pooled
      (+0.007 / -0.012).  PRINTED: the linear lambda's margin widens 0.001 -> 0.003.

  CAVEATS.  The Jeffreys prior is one choice of smoothing (§11.78).  n = 22 and 23 sit in
  different residue classes and the share does not fall between them.  The share below
  the bar is not the rating's conjecture, which is on E[mu]; no rating moves.  This is a
  measurement at n <= 23, not a bound at n = 256.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_fail_n23.py [--regenerate | --plan | --preview]
      default      : verdicts from the pinned files (about 25 s)
      --regenerate : solve the new keys of both widths, n = 19 first, in parallel and
                     resumable (n = 19 about 2.5 min per key; n = 23 1-8 h, ~2 GB each)
      --plan       : print the allocations, the draws and the projected SEs, no solving
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
PINNED = os.path.join(HERE, "v2_fail_n23.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
TOTAL = {19: 450, 23: 150}       # keys per width after this draw
JOBS = 6                         # parallel solves: n = 23 peaks near 2.1 GB each


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


F22 = _load("v2_fail_n22.py")        # jeffreys(), share(), the n = 22 156-key sample
S23 = _load("v2_series_n23.py")      # solve(), PINNED, measures23()
T22 = F22.T22                        # arc(), ARC
KS = F22.KS
TS = F22.TS
AUD = TS.AUD


def R(n):
    return 3 * n // 4


def below(r, axis, n):
    return r[2 + axis][1][R(n) - 1] < TS.BAR[axis] * n


def pinned_old(n):
    """The earlier sample at width n: §11.55's n = 19 rows (W cut to 3n/4 rounds, the
    deployed criterion), or §11.67's 50 n = 23 rows."""
    if n == 19:
        with open(TS.PINNED) as fh:
            rows = json.load(fh)["widths"]["19"]
        return [[r[0], r[1], [r[2][0], r[2][1][:R(n)]], [r[3][0], r[3][1][:R(n)]]]
                for r in rows]
    with open(S23.PINNED) as fh:
        return json.load(fh)["rows"]


def allocation(S, rows, n, total):
    """v2_fail_n22.allocation() at width n and a total: Neyman for the stratified share
    below the bar, each stratum's spread at its Jeffreys share (the larger axis), with no
    stratum below the keys it already holds."""
    tot = sum(len(v) for v in S.values())
    w, have = {}, {}
    for t in S:
        rr = [r for r in rows if r[0] == t]
        p = max(F22.jeffreys(sum(below(r, a, n) for r in rr), len(rr)) for a in (0, 1))
        w[t] = len(S[t]) / tot * math.sqrt(p * (1 - p))
        have[t] = len(rr)
    fixed = {}
    while True:
        free = [t for t in S if t not in fixed]
        left = total - sum(fixed.values())
        s = sum(w[t] for t in free)
        share = {t: left * w[t] / s for t in free}
        low = [t for t in free if share[t] < have[t]]
        if not low:
            break
        fixed.update({t: have[t] for t in low})
    out = {**fixed, **{t: int(share[t]) for t in free}}
    rest = total - sum(out.values())
    for t in sorted(free, key=lambda t: share[t] - int(share[t]), reverse=True)[:rest]:
        out[t] += 1
    return {t: min(len(S[t]), out[t]) for t in S}


def projected_se(S, rows, n, al):
    """The Jeffreys SE the allocation al would give if every stratum kept its present
    Jeffreys share: what --plan prints, not a finding."""
    tot = sum(len(v) for v in S.values())
    v = 0.0
    for t in S:
        rr = [r for r in rows if r[0] == t]
        p = max(F22.jeffreys(sum(below(r, a, n) for r in rr), len(rr)) for a in (0, 1))
        v += (len(S[t]) / tot) ** 2 * p * (1 - p) / al[t] * (1 - al[t] / len(S[t]))
    return math.sqrt(v)


def draw(n, S=None):
    """The new keys at width n, [(t, B)]: from each stratum a seeded sample disjoint from
    the earlier ones, bringing it to allocation()'s count."""
    S = S or KS.strata(n)
    old = pinned_old(n)
    have = {}
    for r in old:
        have.setdefault(r[0], set()).add(r[1])
    al = allocation(S, old, n, TOTAL[n])
    rnd = random.Random(KS.SEED * 100 + n + 3)
    out = []
    for t in sorted(S):
        pool = [B for B in S[t] if B not in have.get(t, ())]
        out += [(t, B) for B in rnd.sample(pool, al[t] - len(have.get(t, ())))]
    return out


def solve(n, B):
    if n == 23:
        return S23.solve(B)
    d = AUD.delta(B, n)
    out = []
    for axis in (0, 1):
        mu, W, _ = TS.trail(n, d, axis, R(n))
        out.append([round(mu, 9), [round(x, 9) for x in W]])
    return out


def regenerate():
    TS.ESL.build()
    S23.ESL.build()              # v2_series_n23 loads its own copy of the solver
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                n, B, a, b, sec = json.loads(ln)
                done[(n, B)] = (a, b, sec)
    rows = {n: draw(n) for n in TOTAL}
    jobs = [(n, t, B) for n in sorted(TOTAL) for t, B in rows[n] if (n, B) not in done]
    print("new keys: %s; %d to solve, %d in parallel"
          % (", ".join("%d at n = %d" % (len(rows[n]), n) for n in sorted(TOTAL)),
             len(jobs), JOBS), flush=True)
    lock = threading.Lock()

    def one(job):
        n, t, B = job
        t0 = time.time()
        a, b = solve(n, B)
        sec = round(time.time() - t0)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([n, B, a, b, sec]) + "\n")
            done[(n, B)] = (a, b, sec)
            print("  %s n = %d, t = %d, B = %d: mu %.4f / %.4f in %d s (%d of %d done)"
                  % (time.strftime("%H:%M"), n, t, B, a[0], b[0], sec, len(done),
                     sum(len(v) for v in rows.values())), flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #257: exact v2 trail weights W(1..3n/4) at n = 19 and 23, "
                   "draws Neyman-allocated for the share below the bar; rows are [stratum "
                   "t, key B, [mu_diff, W_diff], [mu_lin, W_lin], solve seconds]",
                   "seed": KS.SEED, "total": {str(n): TOTAL[n] for n in TOTAL},
                   "rows": {str(n): [[t, B] + list(done[(n, B)]) for t, B in rows[n]]
                            for n in sorted(TOTAL)}},
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


def zfall(a, b):
    """The fall a -> b of two shares in Jeffreys SEs."""
    return (a[0] - b[0]) / math.hypot(a[2], b[2])


def rows22():
    first, top = F22.pinned76()
    with open(F22.PINNED) as fh:
        return first + top + json.load(fh)["rows"]


def section_1(S, old, new, preview):
    rule("§1  The draws: n = 19 to %d keys, n = 23 to %d, Neyman-allocated for the "
         "share below the bar" % (TOTAL[19], TOTAL[23]))
    for n in sorted(TOTAL):
        al = allocation(S[n], old[n], n, TOTAL[n])
        print("  n = %d allocation: %s" % (n, ", ".join("t%d: %d" % kv
                                                         for kv in sorted(al.items()))))
        check(sum(al.values()) == TOTAL[n], "n = %d: the allocation sums to %d keys"
              % (n, TOTAL[n]))
        if not preview:
            check([(r[0], r[1]) for r in new[n]] == draw(n, S[n]), "n = %d: the pinned "
                  "rows are exactly draw()'s seeded sample (%d keys)" % (n, len(new[n])))
        check(not {r[1] for r in old[n]} & {r[1] for r in new[n]}, "n = %d: disjoint from "
              "the %d earlier keys" % (n, len(old[n])))
        for axis in (0, 1):
            cpos = sum(1 for r in new[n] for i, w in enumerate(r[2 + axis][1])
                       if w > r[2 + axis][0] * (i + 1) + 1e-6)
            check(cpos == 0, "n = %d, %s: c(r) <= 0 on every new key" % (n, NAME[axis]))
        sec = sorted(r[4] for r in new[n])
        print("  n = %d solve time per key: median %.1f min, slowest %.0f min"
              % (n, sec[len(sec) // 2] / 60, sec[-1] / 60))


def section_2(S, old, new):
    rule("§2  The share below the bar at both ends, before and after the draws")
    out = {}
    for axis in (0, 1):
        nm = NAME[axis]
        print("\n  %s:" % nm)
        for n in sorted(TOTAL):
            a = F22.share(S[n], old[n], n, axis)
            b = F22.share(S[n], old[n] + new[n], n, axis)
            out[(n, axis)] = (a, b)
            for lab, x in (("%d keys" % len(old[n]), a),
                           ("%d keys" % (len(old[n]) + len(new[n])), b)):
                print("    n = %d, %-9s %5.2f%%   SE %.2f%%   Jeffreys SE %.2f%%"
                      % (n, lab, 100 * x[0], 100 * x[1], 100 * x[2]))
            print("      failures per stratum (f of k): %s"
                  % ", ".join("t%d: %d/%d" % (t, f, k) for t, (f, k) in sorted(b[3].items())))
            check(b[2] < 0.5 * a[2], "n = %d, %s: the draw more than halves the Jeffreys "
                  "SE, %.2f%% -> %.2f%%" % (n, nm, 100 * a[2], 100 * b[2]))
            check(abs(b[0] - a[0]) < a[1], "n = %d, %s: the share moves %.2f%% -> %.2f%%, "
                  "less than one old plain SE: the old point held, its SE was the "
                  "understatement" % (n, nm, 100 * a[0], 100 * b[0]))
    # CONTROL: the estimator counts a failure at its stratum's weight (n = 23, t = 8).
    n, rows = 23, old[23] + new[23]
    tot = sum(len(v) for v in S[n].values())
    k8 = sum(1 for r in rows if r[0] == 8)
    hit = next(r for r in rows if r[0] == 8 and below(r, 0, n))
    flip = [r for r in rows if r is not hit]
    flip.append([hit[0], hit[1], [hit[2][0], [99.0] * R(n)], hit[3]])
    d = out[(n, 0)][1][0] - F22.share(S[n], flip, n, 0)[0]
    check(abs(d - len(S[n][8]) / tot / k8) < 1e-12, "CONTROL: clearing one n = 23 failure "
          "in t = 8 lowers the share by exactly W_8 / k_8 = %.2f%%" % (100 * d))
    return out


def section_3(S, sh):
    rule("§3  The fall from n = 19, with the Jeffreys SE at both ends")
    r22 = rows22()
    for axis in (0, 1):
        nm = NAME[axis]
        c0, c = sh[(19, axis)]
        e0, e = sh[(23, axis)]
        d = F22.share(S[22], r22, 22, axis)
        print("  %s: n = 19 %.1f%%, n = 22 %.1f%%, n = 23 %.1f%%"
              % (nm, 100 * c[0], 100 * d[0], 100 * e[0]))
        print("    19 -> 23: %.1f SE on the old samples, %.1f SE on the new; 19 -> 22: "
              "%.1f SE with 113 n = 19 keys, %.1f with %d"
              % (zfall(c0, e0), zfall(c, e), zfall(c0, d), zfall(c, d), TOTAL[19]))
        check(zfall(c0, e0) < 2, "%s: CONTROL -- on the old samples (113 / 50 keys) the "
              "fall from n = 19 to 23 is %.1f SE, not established" % (nm, zfall(c0, e0)))
        check(zfall(c, e) > 3, "%s: the fall from n = 19 to 23 is established: %.1f%% -> "
              "%.1f%%, %.1f SE Jeffreys" % (nm, 100 * c[0], 100 * e[0], zfall(c, e)))
        if axis == 0:
            check(zfall(c0, d) < 2 < zfall(c, d), "differential: CORRECTION to §11.78.3 "
                  "-- the fall from n = 19 to 22 is %.1f SE with %d n = 19 keys, so it IS "
                  "established; §11.78's %.1f came from n = 19's 113, not from n = 22"
                  % (zfall(c, d), TOTAL[19], zfall(c0, d)))
        else:
            check(zfall(c, d) > 2, "linear: the fall from n = 19 to 22 holds, %.1f SE"
                  % zfall(c, d))
        print("    PRINTED, NOT SCORED: n = 22 -> 23 moves %.1f SE: the step after n = 22 "
              "shows no further fall" % zfall(d, e))


def section_4(S, old, new):
    rule("§4  The arc at both ends")
    for n in sorted(TOTAL):
        rows = old[n] + new[n]
        ak = [T22.arc(AUD.delta(r[1], n), n) for r in rows]
        for axis in (0, 1):
            sh_ = [below(r, axis, n) for r, x in zip(rows, ak) if x <= T22.ARC]
            lo_ = [below(r, axis, n) for r, x in zip(rows, ak) if x > T22.ARC]
            longs = [(r[0], x) for r, x in zip(rows, ak) if x > T22.ARC and below(r, axis, n)]
            print("  n = %d, %s: arc <= %d fails %d of %d; arc > %d fails %d of %d %s"
                  % (n, NAME[axis], T22.ARC, sum(sh_), len(sh_), T22.ARC, sum(lo_),
                     len(lo_), "(t, arc) %s" % longs if longs else ""))
            check(sum(sh_) / len(sh_) > 10 * sum(lo_) / len(lo_), "n = %d, %s: short arcs "
                  "fail over 10x as often as long ones" % (n, NAME[axis]))
    rows = old[23] + new[23]
    lng = [(r[0], T22.arc(AUD.delta(r[1], 23), 23)) for r in rows if below(r, 1, 23)
           and T22.arc(AUD.delta(r[1], 23), 23) > T22.ARC]
    check(any(t == 1 and a >= 17 for t, a in lng), "n = 23, linear: §11.78's correction "
          "repeats one width on -- a t = 1 key fails with an arc of %s of 23 bits"
          % max(a for t, a in lng))
    lowt = sorted(r[0] for r in rows if below(r, 1, 23))
    check(lowt[0] < 6, "n = 23, linear: CORRECTION to §11.67.3(d)'s reading -- not every "
          "key below the bar has tz(p) >= 6 (strata %s)" % lowt)


def section_5(S, old, new):
    rule("§5  E[mu] and lambda at n = 23 with %d keys" % TOTAL[23])
    a = S23.measures23(old[23], S[23])
    b = S23.measures23(old[23] + new[23], S[23])
    for axis in (0, 1):
        nm = NAME[axis]
        lam, _ = F22.pooled_lambda(axis)
        dl0, dl = a[axis]["lam"][0] - lam, b[axis]["lam"][0] - lam
        print("  %s: E[mu] %.3f +/- %.3f -> %.3f +/- %.3f;  lambda %.4f -> %.4f "
              "(pooled %.4f: %+.4f -> %+.4f)"
              % (nm, a[axis]["mu"][0], a[axis]["mu"][1], b[axis]["mu"][0], b[axis]["mu"][1],
                 a[axis]["lam"][0], b[axis]["lam"][0], lam, dl0, dl))
        check(abs(b[axis]["mu"][0] - a[axis]["mu"][0]) < a[axis]["mu"][1], "%s: E[mu] "
              "moves by less than one of §11.67's SEs" % nm)
        check(abs(dl) < 0.015, "%s: the share holds -- lambda(23) within §11.62's 0.015 of "
              "the pooled value (%+.4f)" % (nm, dl))
        bar = F22.conjectured_bars()[axis]
        check(b[axis]["mu"][0] / bar > 1.5, "%s: E[mu] is %.2fx SECURITY.md's conjectured "
              "bar %.3f" % (nm, b[axis]["mu"][0] / bar, bar))
    print("  PRINTED, NOT SCORED: the linear lambda's margin to the 0.015 tolerance, "
          "%.4f -> %.4f" % (0.015 - abs(a[1]["lam"][0] - F22.pooled_lambda(1)[0]),
                            0.015 - abs(b[1]["lam"][0] - F22.pooled_lambda(1)[0])))


def load_new(preview):
    if not preview:
        with open(PINNED) as fh:
            return {int(n): v for n, v in json.load(fh)["rows"].items()}
    out = {n: [] for n in TOTAL}
    t = {(n, B): t for n in TOTAL for t, B in draw(n)}
    with open(PINNED + ".partial") as fh:
        for n, B, a, b, sec in map(json.loads, fh):
            out[n].append([t[(n, B)], B, a, b, sec])
    return out


def plan():
    for n in sorted(TOTAL):
        S = KS.strata(n)
        old = pinned_old(n)
        al = allocation(S, old, n, TOTAL[n])
        d = draw(n, S)
        print("n = %d: %d -> %d keys, %d new" % (n, len(old), TOTAL[n], len(d)))
        print("  allocation:", al)
        print("  new per stratum:", {t: sum(1 for x in d if x[0] == t) for t in S})
        for axis in (0, 1):
            p, se, sj, _ = F22.share(S, old, n, axis)
            print("  %s now: %.2f%% (SE %.2f%%, Jeffreys %.2f%%)"
                  % (NAME[axis], 100 * p, 100 * se, 100 * sj))
        print("  projected Jeffreys SE after the draw: %.2f%%"
              % (100 * projected_se(S, old, n, al)))
    return 0


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
        return plan()
    print(__doc__)
    S = {n: KS.strata(n) for n in (19, 22, 23)}
    old = {n: pinned_old(n) for n in TOTAL}
    new = load_new(a.preview)
    section_1(S, old, new, a.preview)
    sh = section_2(S, old, new)
    section_3(S, sh)
    section_4(S, old, new)
    section_5(S, old, new)
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
