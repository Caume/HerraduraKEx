#!/usr/bin/env python3
"""v2_series_n23.py — TODO #343 (fifteenth pass): NL-FSCX v2 over keys at n = 23, the next
width of the class n = 2 (mod 3).

§11.62 (v2_series_n22.py) measured E[mu] and the discount's share lambda over a key
sample at n = 22; §11.66 solved n = 23 keys drawn by gap, which estimates neither.  Since
TODO #344 an n = 23 solve fits in ~1.5 GB, so this pass draws a KEY sample at n = 23:
25 keys by key_series' rule scaled down (max(2, ceil(15 * stratum share)), seed 3431)
over the nine strata of t = tz(p), each solved for W(1..17) = W(floor(3n/4)) on both
axes.  The run took 12 h 9 min at 6 solves in parallel (1.2-5.2 h per key, up to 1.5 GB
each) on an aarch64 SBC.  The default run reads the pinned file, so its verdicts cannot
flake.

  §1  THE SAMPLE.  The strata hold all 2^23 keys but the affine-delta ones, and the
      pinned rows are exactly draw()'s seeded sample.

  §2  FEKETE AT A NEW WIDTH.  W is superadditive and c(r) <= 0 on every round of every
      key, both axes.  CONTROL: it FIRES on W(r) + 1 at 25 of 25 keys.

  §3  THE CLASS ONE STEP ON (11, 14, 17, 20 -> 23).
      (a) E[mu] rises, 2.592 -> 2.814 differential (3.8 SE) and 1.329 -> 1.480 linear
          (3.5 SE), so y* rises with it: to 1.646 / 1.712.
      (b) The share holds: lambda(23) = 0.174 / 0.158, within 0.015 of §11.60's pooled
          0.165 / 0.172 (+2.4 / -3.2 SE, opposite signs, as at n = 22) and under half the
          break-even 0.395 / 0.412.
      (c) E[mu] at n = 23 is 1.65x / 1.71x the share-held bar 1.710 / 0.865.
      (d) The share of keys below the bar falls, 3.8% / 5.2% at n = 20 -> 1.8% / 3.5%,
          and every sampled key below it has tz(p) >= 6 (a window of 17 bits or less).
      PRINTED, NOT SCORED: the class increments of E[mu] are +0.37 +0.38 +0.16 +0.22
      (differential) and +0.21 +0.20 +0.13 +0.15 (linear): the last step is LARGER than
      the one before, as in n = 22's class.  E[mu] per bit from n = 22: +0.056 / +0.051.

  CAVEATS.  25 keys is a thinner sample than n = 22's 43: the strata t >= 2 hold two keys
  each, the fail shares are two and three keys, and the linear lambda sits 0.014 from
  the pooled value, inside the 0.015 tolerance but not by much.  This is still a measurement at
  n = 23, not a bound at n = 256.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_series_n23.py [--full | --regenerate]
      default      : verdicts from the pinned file only (about 30 s; the strata of 2^23
                     keys are most of it)
      --full       : also re-solve every pinned key (about 12 h at JOBS = 6, ~9 GB)
      --regenerate : rebuild v2_series_n23.json in parallel, resumable
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
PINNED = os.path.join(HERE, "v2_series_n23.json")
FAIL = []
NAME = {0: "differential", 1: "linear"}
N = 23
K23 = 15                          # proportional allocation target at n = 23
KMIN23 = 2                        # and the floor per stratum (2: a variance per stratum)
JOBS = 6                          # parallel solves: ~1.2-1.5 GB each since TODO #344
R23 = 3 * N // 4                  # W(1..17): the deployed round count


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


TS = _load("v2_transient_series.py")   # trail(), BAR, PINNED, measures()
KS = TS.KS                             # strata(), estimate(), SEED
AUD = TS.AUD
ESL = TS.ESL
DS = _load("v2_discount_share.py")    # superadditive(), share(), LATE, WIDTHS
S22 = _load("v2_series_n22.py")       # measures22(), PINNED: lambda at n = 22
CLASS2 = (11, 14, 17, 20)             # n = 2 (mod 3), n = 8 left out as in CLASS1


def draw(S=None):
    """The seeded stratified sample at n = 23, [(t, B)]: key_series.allocation()'s
    rule, max(KMIN23, ceil(K23 * stratum share)), with key_series' seed."""
    S = S or KS.strata(N)
    tot = sum(len(v) for v in S.values())
    rnd = random.Random(KS.SEED * 100 + N)
    out = []
    for t in sorted(S):
        k = min(len(S[t]), max(KMIN23, math.ceil(K23 * len(S[t]) / tot)))
        out += [(t, B) for B in rnd.sample(S[t], k)]
    return out


def solve(B):
    d = AUD.delta(B, N)
    out = []
    for axis in (0, 1):
        mu, W, _ = TS.trail(N, d, axis, R23)
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
    print("n = %d: %d keys, %d to solve" % (N, len(rows), len(jobs)), flush=True)
    lock = threading.Lock()

    def one(job):
        t, B = job
        t0 = time.time()
        a, b = solve(B)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps([B, a, b]) + "\n")
            done[B] = (a, b)
            print("  %s t = %d, B = %d: mu %.4f / %.4f in %.0f s (%d done)"
                  % (time.strftime("%H:%M"), t, B, a[0], b[0], time.time() - t0, len(done)),
                  flush=True)

    with ThreadPoolExecutor(JOBS) as ex:
        list(ex.map(one, jobs))
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 trail weights W(1..3n/4) at n = 23 over a "
                   "stratified key sample; rows are [stratum t, key B, [mu_diff, W_diff], "
                   "[mu_lin, W_lin]]",
                   "seed": KS.SEED, "n": N, "k": K23, "kmin": KMIN23,
                   "rows": [[t, B] + list(done[B]) for t, B in rows]},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


# ═══════════════════════════════════════════════════════════════════════════
# the measures, over the stratified sample
# ═══════════════════════════════════════════════════════════════════════════
def measures23(rows, S):
    """{axis: dict of (mean, se)} for mu, c/n, W/n, and lambda (delta-method SE)."""
    out = {}
    tot = sum(len(v) for v in S.values())
    k = {t: sum(1 for r in rows if r[0] == t) for t in S}
    for axis in (0, 1):
        per = {"mu": [], "c": [], "w": []}
        for r in rows:
            mu, W = r[2 + axis]
            per["mu"].append(mu)
            per["c"].append((W[R23 - 1] - mu * R23) / N)
            per["w"].append(W[R23 - 1] / N)
        e = {}
        for key, xs in per.items():
            e[key] = KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, xs)], 0)
        lam = -e["c"][0] / e["mu"][0]
        res = [-c - lam * m for c, m in zip(per["c"], per["mu"])]
        e["lam"] = (lam, KS.estimate(S, [[r[0], r[1], x, x] for r, x in zip(rows, res)],
                                     0)[1] / e["mu"][0])
        e["fail"] = sum(len(S[r[0]]) / tot / k[r[0]] for r, w in zip(rows, per["w"])
                        if w < TS.BAR[axis])
        out[axis] = e
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section_1(rec, S):
    rule("§1  The sample: n = %d, %d stratified keys" % (N, len(rec["rows"])))
    rows = rec["rows"]
    tot = sum(len(v) for v in S.values())
    print("     t   keys in stratum   share    sampled")
    for t in sorted(S):
        print("  %4d   %15d   %.4f   %4d" % (t, len(S[t]), len(S[t]) / tot,
                                           sum(1 for r in rows if r[0] == t)))
    aff = sum(1 for B in range(1 << N) if AUD.delta(B, N) in KS.affine(N))
    check(tot + aff == 1 << N, "the strata partition all 2^%d keys but the %d with an "
          "affine delta (key_series' exclusion)" % (N, aff))
    check([(r[0], r[1]) for r in rows] == draw(S) and rec["seed"] == KS.SEED,
          "the pinned keys are exactly draw()'s seeded sample (%d keys, seed %d)"
          % (len(rows), KS.SEED))
    check(all(len(r[2 + a][1]) == R23 for r in rows for a in (0, 1)),
          "every row holds W(1..%d) on both axes" % R23)


def section_2(rows):
    rule("§2  Fekete at a new width: W superadditive and c(r) <= 0, r = 1..%d" % R23)
    for axis in (0, 1):
        bad = sum(DS.superadditive(r[2 + axis][1]) for r in rows)
        cpos = sum(1 for r in rows for i, w in enumerate(r[2 + axis][1])
                   if w > r[2 + axis][0] * (i + 1) + 1e-6)
        pairs = len(rows) * R23 * (R23 - 1) // 2
        check(bad == 0 and cpos == 0, "%s: W(a + b) >= W(a) + W(b) on all %d pairs and "
              "c(r) <= 0 at every round of every key" % (NAME[axis], pairs))
    up = sum(1 for r in rows if DS.superadditive([w + 1 for w in r[2][1]]) > 0)
    check(up > len(rows) // 2, "CONTROL: superadditivity FIRES on W(r) + 1 at %d of %d keys"
          % (up, len(rows)))


def section_3(rows, S, rec_old, rec22):
    rule("§3  The class n = 2 (mod 3) one step on: %s -> %d"
         % (", ".join(str(n) for n in CLASS2), N))
    M = TS.measures(rec_old)
    M23 = measures23(rows, S)
    M22 = S22.measures22(rec22["rows"], KS.strata(S22.N22))
    L = {(n, a): DS.share(rec_old, n, a) for n in DS.WIDTHS for a in (0, 1)}
    n20 = CLASS2[-1]
    for axis in (0, 1):
        nm, bar, e = NAME[axis], TS.BAR[axis], M23[axis]
        pts = [(n, L[(n, axis)][0], L[(n, axis)][1]) for n in DS.WIDTHS if n >= DS.LATE]
        wt = [1 / s ** 2 for _, _, s in pts]
        lam = sum(w * x for w, (_, x, _) in zip(wt, pts)) / sum(wt)
        lse = 1 / math.sqrt(sum(wt))
        cls = [(n,) + tuple(M[(n, axis)]["mu"]) + (M[(n, axis)]["w_fail"],)
               for n in CLASS2] + [(N,) + tuple(e["mu"]) + (e["fail"],)]
        print("\n  %s: pooled lambda over n = %d..%d = %.4f +/- %.4f; at n = %d: "
              "%.4f +/- %.4f" % (nm, DS.LATE, DS.WIDTHS[-1], lam, lse, N, e["lam"][0],
                                 e["lam"][1]))
        print("       n   E[mu]            y*                fail W")
        for n, m, s, f in cls:
            print("    %4d   %.3f +/- %.3f   %.3f +/- %.3f   %5.1f%%"
                  % (n, m, s, m * (0.75 - lam) / bar, s * (0.75 - lam) / bar, 100 * f))
        m20, s20 = M[(n20, axis)]["mu"]
        m23, s23 = e["mu"]
        z = (m23 - m20) / math.hypot(s20, s23)
        check(z > 3, "%s: E[mu] rises from n = %d to %d, %.3f -> %.3f (%.1f SE), and with "
              "it y*" % (nm, n20, N, m20, m23, z))
        zl = (e["lam"][0] - lam) / math.hypot(e["lam"][1], lse)
        even = 0.75 - bar / m23
        print("    lambda(%d) - pooled = %+.4f (%+.1f SE); break-even lambda at n = %d: %.3f"
              % (N, e["lam"][0] - lam, zl, N, even))
        check(abs(e["lam"][0] - lam) < 0.015 and e["lam"][0] < even / 2,
              "%s: the share holds at a sixth width: lambda(%d) = %.4f, within 0.015 of the "
              "pooled %.4f and under half the break-even %.3f" % (nm, N, e["lam"][0], lam,
                                                                 even))
        barmu = bar / (0.75 - lam)
        check((m23 - barmu) / s23 > 5, "%s: E[mu] at n = %d is %.2fx the share-held bar "
              "%.3f, %.0f SE above it" % (nm, N, m23 / barmu, barmu, (m23 - barmu) / s23))
        f20 = M[(n20, axis)]["w_fail"]
        check(e["fail"] < f20, "%s: the share of keys below the bar falls, %.1f%% at n = %d "
              "-> %.1f%% at n = %d" % (nm, 100 * f20, n20, 100 * e["fail"], N))
        low = [r for r in rows if r[2 + axis][1][R23 - 1] < bar * N]
        check(all(r[0] >= 6 for r in low), "%s: every sampled key below the bar has "
              "tz(p) >= 6, i.e. a window of %d bits or less (%d keys, strata %s)"
              % (nm, N - 6, len(low), sorted(r[0] for r in low)))
        inc = [b[1] - a[1] for a, b in zip(cls, cls[1:])]
        print("    PRINTED, NOT SCORED: class increments of E[mu] %s; the last ratio %.2f "
              "(was %.2f at n = %d)"
              % (" ".join("%+.3f" % x for x in inc), inc[-1] / inc[-2], inc[-2] / inc[-3],
                 n20))
        print("    PRINTED, NOT SCORED: E[mu] per bit from n = %d to %d: %+.3f; "
              "lambda(%d) = %.4f" % (S22.N22, N, (m23 - M22[axis]["mu"][0]) / (N - S22.N22),
                                     S22.N22, M22[axis]["lam"][0]))


def full(rows):
    rule("--full: re-solving all %d pinned keys (%d in parallel)" % (len(rows), JOBS))
    ESL.build()
    with ThreadPoolExecutor(JOBS) as ex:
        got = list(ex.map(lambda r: solve(r[1]), rows))
    bad = [r[1] for r, g in zip(rows, got) if g != r[2:]]
    check(not bad, "every pinned row re-solves to the same mu and W(1..%d) %s"
          % (R23, "" if not bad else "(differs: %s)" % bad))


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
    with open(S22.PINNED) as fh:
        rec22 = json.load(fh)
    S = KS.strata(N)
    section_1(rec, S)
    section_2(rec["rows"])
    section_3(rec["rows"], S, rec_old, rec22)
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
