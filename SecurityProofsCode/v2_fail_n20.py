#!/usr/bin/env python3
"""v2_fail_n20.py — TODO #257 (fourteenth pass): the v2 fail share at n = 20 with an
honest SE, and the fall within each residue class.

§11.79 (v2_fail_n23.py) established the fall of the share of keys below the deployed
criterion from n = 19 to n = 22 and 23, with Jeffreys-smoothed errors at both ends, and
printed that from n = 22 to 23 the share does not fall.  But n = 22 and 23 sit in
different residue classes of n mod 3, so that step mixes the width with the class.
n = 20 is n = 23's class: its 3.8% / 5.2% (§11.57, 107 keys) carry only the plain SE.
This pass draws n = 20 to TOTAL20 keys, Neyman-allocated for the Jeffreys SE of the share,
seeded and disjoint from §11.57's sample.

The draw added 343 keys (median 6.9 min per key at seven in parallel, slowest 26; about
6 h 15 min).

  §1  THE DRAW is exactly draw()'s seeded sample, disjoint from §11.57's 107 keys, and the
      allocation sums to 450.  c(r) <= 0 on every new key.

  §2  THE SHARE AT n = 20, 450 keys: 6.4% / 7.7% (Jeffreys SE 1.0% / 1.1%, about half of
      2.0% / 2.1%).  CORRECTION to §11.57: the share RISES from 3.8% / 5.2%, by 2.2 / 1.8
      of the old plain SEs and 1.3 / 1.2 of the old Jeffreys SEs -- unlike n = 19, 22 and
      23, the old point itself was low.  t >= 8 fails 24 / 25 of 32.  CONTROL: clearing
      one t = 8 failure lowers the share by exactly W_8 / k_8.

  §3  WITHIN EACH RESIDUE CLASS THE SHARE FALLS.  Class n = 2 (mod 3): n = 20 -> 23,
      6.4% -> 1.6% and 7.7% -> 3.1%, 3.1 / 2.5 SE Jeffreys.  CONTROL: on §11.57's 107 keys
      that fall is 0.9 / 0.8.  Class n = 1: n = 19 -> 22, 2.7 / 3.6 SE (§11.79).  PRINTED:
      across classes 19 -> 20 1.3 / 1.5 SE, 20 -> 22 1.8 / 2.4, 22 -> 23 0.8 / 0.0; so
      one-bit steps are too small to resolve the fall, so §11.79's flat step from n = 22
      to 23 is not the fall stopping.  No class effect is shown either way.

  §4  THE ARC.  Short arcs fail over 10x as often as long ones (39 / 43 of 70 against
      9 / 12 of 380), and long arcs fail too, up to 16 / 18 of 20 bits.

  §5  E[mu] = 2.578 +/- 0.017 / 1.318 +/- 0.010, within one of §11.57's SEs.

  CAVEATS.  Two classes, two widths each: a fall within a class is not a rate.  The share
  below the bar is not the rating's conjecture, which is on E[mu]; no rating moves.  This
  is a measurement at n <= 23, not a bound at n = 256.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_fail_n20.py [--regenerate | --plan | --preview]
      default      : verdicts from the pinned files (about 16 s)
      --regenerate : solve the new keys, in parallel and resumable (3-6 min per key)
      --plan       : print the allocation, the draw and the projected SE, no solving
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
PINNED = os.path.join(HERE, "v2_fail_n20.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
N = 20
TOTAL20 = 450                    # keys at n = 20 after this draw, as at n = 19 (§11.79)
JOBS = 7                         # parallel solves


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


F23 = _load("v2_fail_n23.py")        # allocation(), projected_se(), below(), solve(), R()
F22 = F23.F22                        # jeffreys(), share(), pinned76()
T22 = F23.T22                        # arc(), ARC
KS = F23.KS
TS = F23.TS
AUD = TS.AUD
R = F23.R
below = F23.below


def pinned_old():
    """§11.57's 107 n = 20 rows, W cut to 3n/4 rounds (the deployed criterion)."""
    with open(TS.PINNED) as fh:
        rows = json.load(fh)["widths"][str(N)]
    return [[r[0], r[1], [r[2][0], r[2][1][:R(N)]], [r[3][0], r[3][1][:R(N)]]]
            for r in rows]


def draw(S=None):
    """The new n = 20 keys, [(t, B)]: from each stratum a seeded sample disjoint from
    §11.57's, bringing it to allocation()'s count."""
    S = S or KS.strata(N)
    old = pinned_old()
    have = {}
    for r in old:
        have.setdefault(r[0], set()).add(r[1])
    al = F23.allocation(S, old, N, TOTAL20)
    rnd = random.Random(KS.SEED * 100 + N + 3)
    out = []
    for t in sorted(S):
        pool = [B for B in S[t] if B not in have.get(t, ())]
        out += [(t, B) for B in rnd.sample(pool, al[t] - len(have.get(t, ())))]
    return out


def regenerate():
    TS.ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                B, a, b, sec = json.loads(ln)
                done[B] = (a, b, sec)
    rows = draw()
    jobs = [(t, B) for t, B in rows if B not in done]
    print("n = %d: %d new keys, %d to solve, %d in parallel"
          % (N, len(rows), len(jobs), JOBS), flush=True)
    lock = threading.Lock()

    def one(job):
        t, B = job
        t0 = time.time()
        a, b = F23.solve(N, B)
        sec = round(time.time() - t0)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, a, b, sec]) + "\n")
            done[B] = (a, b, sec)
            print("  %s t = %d, B = %d: mu %.4f / %.4f in %d s (%d of %d done)"
                  % (time.strftime("%H:%M"), t, B, a[0], b[0], sec, len(done), len(rows)),
                  flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #257: exact v2 trail weights W(1..3n/4) at n = 20, a draw "
                   "Neyman-allocated for the share below the bar; rows are [stratum t, key "
                   "B, [mu_diff, W_diff], [mu_lin, W_lin], solve seconds]",
                   "seed": KS.SEED, "n": N, "total": TOTAL20,
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


def zfall(a, b):
    """The fall a -> b of two shares in Jeffreys SEs."""
    return (a[0] - b[0]) / math.hypot(a[2], b[2])


def others():
    """{n: rows} for n = 19, 22, 23 at §11.78 / §11.79's sample sizes."""
    with open(F23.PINNED) as fh:
        n23 = {int(k): v for k, v in json.load(fh)["rows"].items()}
    return {19: F23.pinned_old(19) + n23[19], 22: F23.rows22(),
            23: F23.pinned_old(23) + n23[23]}


def section_1(S, old, new, preview):
    rule("§1  The draw: n = %d from %d to %d keys, Neyman-allocated for the share below "
         "the bar" % (N, len(old), TOTAL20))
    al = F23.allocation(S, old, N, TOTAL20)
    print("  allocation: %s" % ", ".join("t%d: %d" % kv for kv in sorted(al.items())))
    check(sum(al.values()) == TOTAL20, "the allocation sums to %d keys" % TOTAL20)
    if not preview:
        check([(r[0], r[1]) for r in new] == draw(S), "the pinned rows are exactly "
              "draw()'s seeded sample (%d keys)" % len(new))
    check(not {r[1] for r in old} & {r[1] for r in new}, "disjoint from §11.57's %d keys"
          % len(old))
    for axis in (0, 1):
        cpos = sum(1 for r in new for i, w in enumerate(r[2 + axis][1])
                   if w > r[2 + axis][0] * (i + 1) + 1e-6)
        check(cpos == 0, "%s: c(r) <= 0 on every new key" % NAME[axis])
    sec = sorted(r[4] for r in new)
    print("  solve time per key: median %.1f min, slowest %.0f min"
          % (sec[len(sec) // 2] / 60, sec[-1] / 60))


def section_2(S, old, new):
    rule("§2  The share below the bar at n = %d, %d -> %d keys"
         % (N, len(old), len(old) + len(new)))
    out = {}
    for axis in (0, 1):
        nm = NAME[axis]
        a = F22.share(S, old, N, axis)
        b = F22.share(S, old + new, N, axis)
        out[axis] = (a, b)
        print("\n  %s:" % nm)
        for lab, x in (("%d keys" % len(old), a), ("%d keys" % (len(old) + len(new)), b)):
            print("    %-9s %5.2f%%   SE %.2f%%   Jeffreys SE %.2f%%"
                  % (lab, 100 * x[0], 100 * x[1], 100 * x[2]))
        print("    failures per stratum (f of k): %s"
              % ", ".join("t%d: %d/%d" % (t, f, k) for t, (f, k) in sorted(b[3].items())))
        # About half, not under half: the share's rise kept the linear SE above the
        # projection --plan printed (0.97%), which assumed the old strata shares.
        check(b[2] < 0.6 * a[2], "%s: the draw about halves the Jeffreys SE, %.2f%% -> "
              "%.2f%% (%.2fx)" % (nm, 100 * a[2], 100 * b[2], b[2] / a[2]))
        mv = b[0] - a[0]
        check(mv > 1.5 * a[1] and mv < 1.5 * a[2], "%s: CORRECTION to §11.57 -- the share "
              "RISES, %.2f%% -> %.2f%%: %.1f of the old plain SEs, %.1f of the old Jeffreys "
              "SEs, so the old point was low and only the Jeffreys SE covered it"
              % (nm, 100 * a[0], 100 * b[0], mv / a[1], mv / a[2]))
    # CONTROL: the estimator counts a failure at its stratum's weight (t = 8).
    rows = old + new
    tot = sum(len(v) for v in S.values())
    k8 = sum(1 for r in rows if r[0] == 8)
    hit = next(r for r in rows if r[0] == 8 and below(r, 0, N))
    flip = [r for r in rows if r is not hit]
    flip.append([hit[0], hit[1], [hit[2][0], [99.0] * R(N)], hit[3]])
    d = out[0][1][0] - F22.share(S, flip, N, 0)[0]
    check(abs(d - len(S[8]) / tot / k8) < 1e-12, "CONTROL: clearing one failure in t = 8 "
          "lowers the share by exactly W_8 / k_8 = %.2f%%" % (100 * d))
    return out


def section_3(S, sh):
    rule("§3  The fall within each residue class of n mod 3")
    o = others()
    for axis in (0, 1):
        nm = NAME[axis]
        a, b = sh[axis]
        c, d, e = (F22.share(S[n], o[n], n, axis) for n in (19, 22, 23))
        print("  %s: n = 19 %.1f%%, 20 %.1f%%, 22 %.1f%%, 23 %.1f%%"
              % (nm, 100 * c[0], 100 * b[0], 100 * d[0], 100 * e[0]))
        print("    class n = 1 (mod 3): 19 -> 22 %.1f SE;  class n = 2: 20 -> 23 %.1f SE "
              "(%.1f on §11.57's 107 keys)" % (zfall(c, d), zfall(b, e), zfall(a, e)))
        check(zfall(a, e) < 2, "%s: CONTROL -- on §11.57's 107 n = 20 keys the fall to "
              "n = 23 is %.1f SE, not established" % (nm, zfall(a, e)))
        check(zfall(b, e) > 2, "%s: within n = 23's class the share falls from n = 20 to "
              "23, %.1f%% -> %.1f%%, %.1f SE Jeffreys" % (nm, 100 * b[0], 100 * e[0],
                                                          zfall(b, e)))
        check(zfall(c, d) > 2, "%s: within n = 22's class it falls from n = 19 to 22, "
              "%.1f SE (§11.79)" % (nm, zfall(c, d)))
        print("    PRINTED, NOT SCORED: across classes 19 -> 20 %.1f SE, 20 -> 22 %.1f, "
              "22 -> 23 %.1f" % (zfall(c, b), zfall(b, d), zfall(d, e)))


def section_4(old, new):
    rule("§4  The arc at n = %d" % N)
    rows = old + new
    ak = [T22.arc(AUD.delta(r[1], N), N) for r in rows]
    for axis in (0, 1):
        sh_ = [below(r, axis, N) for r, x in zip(rows, ak) if x <= T22.ARC]
        lo_ = [below(r, axis, N) for r, x in zip(rows, ak) if x > T22.ARC]
        longs = sorted(x for r, x in zip(rows, ak) if x > T22.ARC and below(r, axis, N))
        print("  %s: arc <= %d fails %d of %d; arc > %d fails %d of %d, arcs %s"
              % (NAME[axis], T22.ARC, sum(sh_), len(sh_), T22.ARC, sum(lo_), len(lo_),
                 longs))
        check(sum(sh_) / len(sh_) > 10 * sum(lo_) / len(lo_), "%s: short arcs fail over "
              "10x as often as long ones" % NAME[axis])
        check(max(longs) >= 16, "%s: as at n = 22 and 23, long arcs fail too, up to %d of "
              "%d bits" % (NAME[axis], max(longs), N))


def section_5(S, old, new):
    rule("§5  E[mu] at n = %d" % N)
    for axis in (0, 1):
        m0, m = (KS.estimate(S, [[r[0], r[1], r[2 + axis][0], r[2 + axis][0]] for r in x], 0)
                 for x in (old, old + new))
        print("  %s: E[mu] %.3f +/- %.3f -> %.3f +/- %.3f"
              % (NAME[axis], m0[0], m0[1], m[0], m[1]))
        check(abs(m[0] - m0[0]) < m0[1], "%s: E[mu] moves by less than one of §11.57's SEs"
              % NAME[axis])


def load_new(preview):
    if not preview:
        with open(PINNED) as fh:
            return json.load(fh)["rows"]
    t = dict((B, t) for t, B in draw())
    with open(PINNED + ".partial") as fh:
        return [[t[B], B, a, b, sec] for B, a, b, sec in map(json.loads, fh)]


def plan():
    S = KS.strata(N)
    old = pinned_old()
    al = F23.allocation(S, old, N, TOTAL20)
    d = draw(S)
    print("n = %d: %d -> %d keys, %d new" % (N, len(old), TOTAL20, len(d)))
    print("  allocation:", al)
    print("  new per stratum:", {t: sum(1 for x in d if x[0] == t) for t in S})
    for axis in (0, 1):
        p, se, sj, _ = F22.share(S, old, N, axis)
        print("  %s now: %.2f%% (SE %.2f%%, Jeffreys %.2f%%)"
              % (NAME[axis], 100 * p, 100 * se, 100 * sj))
    print("  projected Jeffreys SE after the draw: %.2f%%"
          % (100 * F23.projected_se(S, old, N, al)))
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
    S = {n: KS.strata(n) for n in (19, 20, 22, 23)}
    old, new = pinned_old(), load_new(a.preview)
    section_1(S[N], old, new, a.preview)
    sh = section_2(S[N], old, new)
    section_3(S, sh)
    section_4(old, new)
    section_5(S[N], old, new)
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
