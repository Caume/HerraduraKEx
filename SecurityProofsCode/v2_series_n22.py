#!/usr/bin/env python3
"""v2_series_n22.py — TODO #343 (tenth pass): NL-FSCX v2 over keys at n = 22, the next
width of n = 256's residue class.

§11.60 (v2_discount_share.py) read the class n = 1 (mod 3) at n = 10, 13, 16, 19 and found
the margin y* = E[mu] (3/4 - lambda) / bar rising at every step, with the discount's share
lambda flat; every remaining item of TODO #343 needed a width past 20.  §11.53's implicit
solver (certified_cycle_mean.c mode 2) reaches n = 22: one key costs about 32 min
differential and 12 min linear at ~0.87 GB, so this is a SAMPLE, not a census -- 43 keys
drawn by key_series' rule (max(3, ceil(30 * stratum share)), seed 3431) over the nine
strata of t = tz(p), each solved for W(1..16) = W(floor(3n/4)) on both axes.  The run
took 6 h 17 min at 7 solves in parallel on an aarch64 SBC.  The default run reads the
pinned file, so its verdicts cannot flake.

  §1  THE SAMPLE.  The strata hold all 2^22 keys but key_series' 1536 affine-delta ones,
      and the pinned rows are exactly draw()'s seeded sample.

  §2  FEKETE AT A NEW WIDTH.  W is superadditive and c(r) <= 0 on every round of every
      key, both axes -- §11.60.1's theorem, checked where it has not been looked at.
      CONTROL: it FIRES on W(r) + 1 at 40 of 43 keys.

  §3  THE CLASS ONE STEP ON (10, 13, 16, 19 -> 22).
      (a) E[mu] rises, 2.492 -> 2.757 differential (5.1 SE) and 1.235 -> 1.430 linear
          (6.1 SE), so y* rises with it: 1.457 -> 1.613 and 1.428 -> 1.653.
      (b) The share holds: lambda(22) = 0.172 / 0.161, within 0.015 of §11.60's pooled
          0.165 / 0.172 (+2.0 / -2.8 SE, opposite signs) and under half the break-even
          0.387 / 0.400.
      (c) E[mu] at n = 22 is 1.61x / 1.65x the share-held bar 1.710 / 0.865.
      (d) The share of keys below the bar falls, 8.3% / 11.7% at n = 19 -> 2.3% / 2.3%,
          and every sampled key below it has tz(p) >= 6 (a window of 16 bits or less):
          the failures left are §11.61's short windows.
      PRINTED, NOT SCORED: the class increments of E[mu] are +0.30 +0.41 +0.22 +0.27
      (differential) and +0.16 +0.22 +0.12 +0.20 (linear).  §11.60.4(iii)'s levelling
      reading took the 16 -> 19 step's ratio 0.54 and put y*(256) at 1.61 / 1.59; n = 22
      alone already reaches that, and its step is LARGER than the one before.  The
      increments alternate rather than shrink, so no level can be read off four steps.

  CAVEATS.  43 keys is a thin sample: the fail share 2.3% is three keys, and the strata
  t >= 2 hold 3-5 keys each.  This is still a measurement at n = 22, not a bound at
  n = 256.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_series_n22.py [--full | --regenerate]
      default      : verdicts from the pinned file only (about 15 s; the strata of 2^22
                     keys are most of it)
      --full       : also re-solve every pinned key (about 6 h at JOBS = 7, ~6 GB)
      --regenerate : rebuild v2_series_n22.json in parallel, resumable
"""

import argparse
import importlib.util
import json
import math
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_series_n22.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
N22 = 22
K22 = 30                          # proportional allocation target at n = 22
KMIN22 = 3                        # and the floor per stratum (key_series: 1200 / 8)
JOBS = 7                          # parallel solves: ~0.87 GB each, memory-bound
R22 = 3 * N22 // 4                # W(1..16): the deployed round count (c has settled)


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


TS = _load("v2_transient_series.py")   # trail(), BAR, PINNED, measures(), wfit()
KS = TS.KS                             # strata(), estimate(), SEED, TMAX
AUD = TS.AUD
ESL = TS.ESL
DS = _load("v2_discount_share.py")    # superadditive(), share(), CLASS1, LATE, WIDTHS


def draw(S=None):
    """The seeded stratified sample at n = 22, [(t, B)]: key_series.allocation()'s
    rule, max(KMIN22, ceil(K22 * stratum share)), with key_series' seed."""
    import random
    S = S or KS.strata(N22)
    tot = sum(len(v) for v in S.values())
    rnd = random.Random(KS.SEED * 100 + N22)
    out = []
    for t in sorted(S):
        k = min(len(S[t]), max(KMIN22, math.ceil(K22 * len(S[t]) / tot)))
        out += [(t, B) for B in rnd.sample(S[t], k)]
    return out


def solve(B):
    d = AUD.delta(B, N22)
    out = []
    for axis in (0, 1):
        mu, W, _ = TS.trail(N22, d, axis, R22)
        out.append([round(mu, 9), [round(x, 9) for x in W]])
    return out


def regenerate():
    ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                B, a, b = json.loads(ln)
                done[B] = (a, b)
    rows = draw()
    jobs = [(t, B) for t, B in rows if B not in done]
    print("n = %d: %d keys, %d to solve" % (N22, len(rows), len(jobs)), flush=True)
    lock = threading.Lock()

    def one(job):
        t, B = job
        a, b = solve(B)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, a, b]) + "\n")
            done[B] = (a, b)
            print("  t = %d, B = %d: mu %.4f / %.4f (%d done)"
                  % (t, B, a[0], b[0], len(done)), flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 trail weights W(1..3n/4) at n = 22 over a "
                   "stratified key sample; rows are [stratum t, key B, [mu_diff, W_diff], "
                   "[mu_lin, W_lin]]",
                   "seed": KS.SEED, "n": N22, "kmin": KMIN22,
                   "rows": [[t, B] + list(done[B]) for t, B in rows]},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


# ═══════════════════════════════════════════════════════════════════════════
# the measures, over the stratified sample
# ═══════════════════════════════════════════════════════════════════════════
def measures22(rows, S):
    """{axis: dict of (mean, se)} for mu, c/n, W/n, and lambda (delta-method SE)."""
    out = {}
    tot = sum(len(v) for v in S.values())
    k = {t: sum(1 for r in rows if r[0] == t) for t in S}
    for axis in (0, 1):
        per = {"mu": [], "c": [], "w": []}
        for r in rows:
            mu, W = r[2 + axis]
            per["mu"].append(mu)
            per["c"].append((W[R22 - 1] - mu * R22) / N22)
            per["w"].append(W[R22 - 1] / N22)
        e = {}
        for key, xs in per.items():
            e[key] = KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, xs)], 0)
        lam = -e["c"][0] / e["mu"][0]
        res = [-c - lam * m for c, m in zip(per["c"], per["mu"])]
        e["lam"] = (lam, KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, res)],
                                     0)[1] / e["mu"][0])
        e["fail"] = sum(len(S[r[0]]) / tot / k[r[0]] for r, w in zip(rows, per["w"])
                        if w < TS.BAR[axis])
        e["keys"] = per
        out[axis] = e
    return out


def older(M, n, axis):
    """The same measures at an older width, from v2_transient_series.json."""
    e = M[(n, axis)]
    mu = e["mu"]
    lam = -e["c"][0] / mu[0]
    return {"mu": mu, "c": e["c"], "w": e["w"], "lam": (lam, None), "fail": e["w_fail"]}


# ═══════════════════════════════════════════════════════════════════════════
def section_1(rec, S):
    rule("§1  The sample: n = %d, %d stratified keys" % (N22, len(rec["rows"])))
    rows = rec["rows"]
    tot = sum(len(v) for v in S.values())
    print("     t   keys in stratum   share    sampled")
    for t in sorted(S):
        print("  %4d   %15d   %.4f   %4d" % (t, len(S[t]), len(S[t]) / tot,
                                           sum(1 for r in rows if r[0] == t)))
    aff = sum(1 for B in range(1 << N22) if AUD.delta(B, N22) in KS.affine(N22))
    check(tot + aff == 1 << N22, "the strata partition all 2^%d keys but the %d with an "
          "affine delta (key_series' exclusion)" % (N22, aff))
    check([(r[0], r[1]) for r in rows] == draw(S) and rec["seed"] == KS.SEED,
          "the pinned keys are exactly draw()'s seeded sample (%d keys, seed %d)"
          % (len(rows), KS.SEED))
    check(all(len(r[2 + a][1]) == R22 for r in rows for a in (0, 1)),
          "every row holds W(1..%d) on both axes" % R22)


def section_2(rows):
    rule("§2  Fekete at a new width: W superadditive and c(r) <= 0, r = 1..%d" % R22)
    for axis in (0, 1):
        bad = sum(DS.superadditive(r[2 + axis][1]) for r in rows)
        cpos = sum(1 for r in rows for i, w in enumerate(r[2 + axis][1])
                   if w > r[2 + axis][0] * (i + 1) + 1e-6)
        pairs = len(rows) * R22 * (R22 - 1) // 2
        check(bad == 0 and cpos == 0, "%s: W(a + b) >= W(a) + W(b) on all %d pairs and "
              "c(r) <= 0 at every round of every key" % (NAME[axis], pairs))
    up = sum(1 for r in rows if DS.superadditive([w + 1 for w in r[2][1]]) > 0)
    check(up > len(rows) // 2, "CONTROL: superadditivity FIRES on W(r) + 1 at %d of %d keys"
          % (up, len(rows)))


def section_3(rows, S, rec_old):
    rule("§3  The class n = 1 (mod 3) one step on: %s -> %d"
         % (", ".join(str(n) for n in DS.CLASS1), N22))
    M = TS.measures(rec_old)
    M22 = measures22(rows, S)
    L = {(n, a): DS.share(rec_old, n, a) for n in DS.WIDTHS for a in (0, 1)}
    n19 = DS.CLASS1[-1]
    for axis in (0, 1):
        nm, bar, e = NAME[axis], TS.BAR[axis], M22[axis]
        pts = [(n, L[(n, axis)][0], L[(n, axis)][1]) for n in DS.WIDTHS if n >= DS.LATE]
        wt = [1 / s ** 2 for _, _, s in pts]
        lam = sum(w * x for w, (_, x, _) in zip(wt, pts)) / sum(wt)
        lse = 1 / math.sqrt(sum(wt))
        cls = [(n,) + tuple(M[(n, axis)]["mu"]) + (M[(n, axis)]["w_fail"],)
               for n in DS.CLASS1] + [(N22,) + tuple(e["mu"]) + (e["fail"],)]
        print("\n  %s: pooled lambda over n = %d..%d = %.4f +/- %.4f; at n = %d: "
              "%.4f +/- %.4f" % (nm, DS.LATE, DS.WIDTHS[-1], lam, lse, N22, e["lam"][0],
                                 e["lam"][1]))
        print("       n   E[mu]            y*                fail W")
        for n, m, s, f in cls:
            print("    %4d   %.3f +/- %.3f   %.3f +/- %.3f   %5.1f%%"
                  % (n, m, s, m * (0.75 - lam) / bar, s * (0.75 - lam) / bar, 100 * f))
        m19, s19 = M[(n19, axis)]["mu"]
        m22, s22 = e["mu"]
        z = (m22 - m19) / math.hypot(s19, s22)
        check(z > 3, "%s: E[mu] rises from n = %d to %d, %.3f -> %.3f (%.1f SE), and with "
              "it y*" % (nm, n19, N22, m19, m22, z))
        zl = (e["lam"][0] - lam) / math.hypot(e["lam"][1], lse)
        even = 0.75 - bar / m22
        print("    lambda(%d) - pooled = %+.4f (%+.1f SE); break-even lambda at n = %d: %.3f"
              % (N22, e["lam"][0] - lam, zl, N22, even))
        check(abs(e["lam"][0] - lam) < 0.015 and e["lam"][0] < even / 2,
              "%s: the share holds at a fifth width: lambda(%d) = %.4f, within 0.015 of the "
              "pooled %.4f and under half the break-even %.3f" % (nm, N22, e["lam"][0], lam,
                                                                 even))
        barmu = bar / (0.75 - lam)
        check((m22 - barmu) / s22 > 5, "%s: E[mu] at n = %d is %.2fx the share-held bar "
              "%.3f, %.0f SE above it" % (nm, N22, m22 / barmu, barmu, (m22 - barmu) / s22))
        f19 = M[(n19, axis)]["w_fail"]
        check(e["fail"] < f19, "%s: the share of keys below the bar falls, %.1f%% at n = %d "
              "-> %.1f%% at n = %d" % (nm, 100 * f19, n19, 100 * e["fail"], N22))
        low = [r for r in rows if r[2 + axis][1][R22 - 1] < bar * N22]
        check(all(r[0] >= 6 for r in low), "%s: every sampled key below the bar has "
              "tz(p) >= 6, i.e. a window of %d bits or less (%d keys, strata %s)"
              % (nm, N22 - 6, len(low), sorted(r[0] for r in low)))
        inc = [b[1] - a[1] for a, b in zip(cls, cls[1:])]
        print("    PRINTED, NOT SCORED: class increments of E[mu] %s; the last ratio %.2f "
              "(was %.2f at n = %d) -- no levelling is visible yet"
              % (" ".join("%+.3f" % x for x in inc), inc[-1] / inc[-2], inc[-2] / inc[-3],
                 n19))
        print("    PRINTED, NOT SCORED: E[mu] per bit from n = %d to %d: %+.3f"
              % (DS.WIDTHS[-1], N22, (m22 - M[(DS.WIDTHS[-1], axis)]["mu"][0])
                 / (N22 - DS.WIDTHS[-1])))


def full(rows):
    rule("--full: re-solving all %d pinned keys (%d in parallel)" % (len(rows), JOBS))
    ESL.build()
    with ThreadPoolExecutor(JOBS) as ex:
        got = list(ex.map(lambda r: solve(r[1]), rows))
    bad = [r[1] for r, g in zip(rows, got) if g != r[2:]]
    check(not bad, "every pinned row re-solves to the same mu and W(1..%d) %s"
          % (R22, "" if not bad else "(differs: %s)" % bad))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return 0
    print(__doc__)
    with open(PINNED) as fh:
        rec = json.load(fh)
    with open(TS.PINNED) as fh:
        rec_old = json.load(fh)
    S = KS.strata(N22)
    section_1(rec, S)
    section_2(rec["rows"])
    section_3(rec["rows"], S, rec_old)
    if a.full:
        full(rec["rows"])
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
