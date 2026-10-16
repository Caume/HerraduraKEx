#!/usr/bin/env python3
"""v2_transient_series.py — TODO #343 (fourth and fifth passes): the r-round transient
of NL-FSCX v2 over keys, to n = 20, at the deployed round count and past it.

§11.54.4 (v2_measurement_audit.py) found that the deployed criterion is on the exact
r-round trail, W(3n/4) >= n (n/2 linear), not on mu * 3n/4, and that
W(r) = mu * r + c(r) with c NEGATIVE and about -0.3 n (differential) and -0.15 n
(linear).  It measured that on 8 keys per width at n = 10..14, because
v2_round_transient.c holds the round's whole 2^(2n) table.  The corrected bars of
§11.54.4 and the margins of §11.55 rest on it.

  §1  THE TRAIL MODE.  certified_cycle_mean.c's mode 2 computes W(r), r = 1..R,
      without the table: a min-plus recursion that walks only the rows a trail of
      weight <= U(r) can use, bounded by the certified potential (the program's
      header has the argument).  CHECK: equal to v2_round_transient.c's dense
      recursion at every round, n = 7..13 (and 14 by default), 3 keys per width,
      both axes.  CONTROL: the upper bound U(r) from G' alone is above the exact
      W(r) on some key of every width from n = 10, so the full recursion is needed.

  §2  THE PINNED SAMPLE.  key_series.py's stratified key sampler (exact stratum
      weights, affine-delta keys left out), R = 2n rounds, both axes per key, in
      v2_transient_series.json.  The gate shows the file is the whole seeded sample
      and re-solves a prefix of every width.

  §3  THE TRANSIENT OVER KEYS.  1343 keys at n = 10, 11, 13, 14, 16, 17, 19, 20.
      (a) c(floor(3n/4)) < 0 on EVERY key of every width, both axes.
      (b) It has SETTLED by the deployed round count: E[c(2n)]/n is within 0.018
          (differential) and 0.011 (linear) of E[c(3n/4)]/n at every width; the mean
          c(r)/n is deepest within a few rounds of the start.
      (c) It does NOT settle in WIDTH: E[c/n] goes -0.283 -> -0.434 differential and
          -0.160 -> -0.225 linear from n = 10 to 20 (19.6 and 17.6 SE).
      (d) The true criterion W(floor(3n/4)) >= n (n/2) fails on more keys than
          mu * floor(3n/4) does at every width, and on fewer as n grows: 71% -> 4%
          differential, 84% -> 5% linear.
      (e) The discount does NOT SLOW (fifth pass, n = 20): its per-bit slope is
          -0.0167 over n = 14..20 against -0.0104 over n = 10..14 (differential),
          -0.0060 against -0.0052 (linear) -- so c grows like n^2 over this range,
          and no constant c/n can be read off it.  E[W(3n/4)]/n still rises, by
          +0.056 (+0.037 linear) per bit over n = 14..20: mu outpaces the discount.
  §4  WHAT IT CHANGES.  At n = 19 the bars on mu are 1.89 and 0.94, not §11.54.4's
      1.71 and 0.87 (19-22 SE), and §11.55's E[mu] over keys sits 1.32x above both of
      them, not 1.47x / 1.44x; at n = 20 they are 1.91 and 0.97, and 1.34x / 1.36x.
      E[W(floor(3n/4))] is 1.42 n and 1.40 (n/2) at n = 19, 1.51 n and 1.54 (n/2) at 20.

The verdicts on the series are computed from the pinned file, so they cannot flake;
the re-solves use the C solver, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_transient_series.py [--quick | --full]
      --quick      : §1 to n = 13; re-solve 2 pinned keys per width below 19
                     (~1 min on an aarch64 SBC, 8 threads)
      default      : §1 to n = 14; re-solve 3 per width below 19, and 1 at n = 19
                     (~4 min); n = 20 is re-solved only by --full
      --full       : re-solve every pinned key            (~10 h on 8 cores)
      --regenerate : rebuild v2_transient_series.json in parallel, resumable
                     (~6.5 h on 8 cores, n = 20 ~4 h of it)
"""

import argparse
import importlib.util
import json
import math
import os
import re
import statistics as st
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_transient_series.json")
FAIL = []
THREADS = max(1, min(os.cpu_count() or 1, 64))
NAME = {0: "differential", 1: "linear"}
BAR = {0: 1.0, 1: 0.5}          # the deployed criterion: W(3n/4) >= BAR * n
# (width, nominal sample size), drawn by key_series.draw(): every stratum gets >= 8.
# n = 20 (fifth pass) costs ~15 min per key with 8 solves sharing memory bandwidth, so
# its 107 keys are ~4 h by themselves and the default run re-solves none of them; n = 19
# is the widest width of the n = 1 (mod 3) class that n = 256 belongs to
PLAN = ((10, 200), (11, 200), (13, 160), (14, 120), (16, 100), (17, 100), (19, 80), (20, 72))


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


KS = _load("key_series.py")       # strata(), draw(), estimate()
AUD = KS.AUD                      # delta(), build() of v2_round_transient.c, TEXE
ESL = KS.ESL                      # build() of certified_cycle_mean.c, TABLES, keys()


def trail(n, d, axis, R):
    """(mu, [W(1..R)], [U(1..R)]) from the trail mode."""
    w0 = 3.0 if axis == 0 else 2.0
    r = subprocess.run([ESL.EXE], input="%d %d %d %r 0 2 4 %d\n%s\n"
                       % (n, d, axis, w0, R, ESL.TABLES),
                       capture_output=True, text=True, check=True)
    lines = [ln for ln in r.stdout.split("\n") if ln]
    W = [float(ln.split()[1]) for ln in lines[1:]]
    U = [float(x) for x in re.findall(r"round \d+: \d+ live nodes, W [-0-9.]+, U ([-0-9.inf]+)",
                                      r.stderr)]
    return float(lines[0].split()[0]), W, U


def dense(n, d, axis, R):
    return AUD.trail(n, d, axis, R)


def solve(n, B):
    d = AUD.delta(B, n)
    out = []
    for axis in (0, 1):
        m, W, _ = trail(n, d, axis, 2 * n)
        out.append((m, W))
    return out


# ═══════════════════════════════════════════════════════════════════════════
# --regenerate
# ═══════════════════════════════════════════════════════════════════════════
def regenerate():
    ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                n, B, a, b = json.loads(ln)
                done[(n, B)] = (a, b)
    lock = threading.Lock()
    draws = {}
    for n, K in PLAN:
        draws[n] = KS.draw(n, K)
        jobs = [(t, B) for t, B in draws[n] if (n, B) not in done]
        print("n = %d: %d keys to solve" % (n, len(jobs)), flush=True)

        def one(job, n=n):
            t, B = job
            (md, Wd), (ml, Wl) = solve(n, B)
            a = [round(md, 9), [round(x, 9) for x in Wd]]
            b = [round(ml, 9), [round(x, 9) for x in Wl]]
            with lock:
                with open(ck, "a") as fh:
                    fh.write(json.dumps([n, B, a, b]) + "\n")
                done[(n, B)] = (a, b)

        with ThreadPoolExecutor(THREADS) as ex:
            for i, _ in enumerate(ex.map(one, jobs)):
                if (i + 1) % 25 == 0:
                    print("  n = %d: %d / %d" % (n, i + 1, len(jobs)), flush=True)
    widths = {str(n): [[t, B] + list(done[(n, B)]) for t, B in draws[n]] for n, _ in PLAN}
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 r-round trail weights W(1..2n) over "
                   "stratified key samples; rows are [stratum t, key B, [mu_diff, "
                   "W_diff], [mu_lin, W_lin]]",
                   "seed": KS.SEED, "plan": [list(x) for x in PLAN], "widths": widths},
                  fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the trail mode
# ═══════════════════════════════════════════════════════════════════════════
def section_1(widths):
    rule("§1  The trail mode against the dense recursion")
    jobs = [(n, d, axis) for n in widths for d in ESL.keys(n, 3) for axis in (0, 1)]
    with ThreadPoolExecutor(min(THREADS, 4)) as ex:
        got = list(ex.map(lambda j: trail(j[0], j[1], j[2], 2 * j[0]), jobs))
        ref = list(ex.map(lambda j: dense(j[0], j[1], j[2], 2 * j[0]), jobs))
    worst = max(max(abs(a - b) for a, b in zip(g[1], r)) for g, r in zip(got, ref))
    check(worst < 1e-9, "W(r), r = 1..2n, equals v2_round_transient.c's at every round "
          "on all %d solves (n = %s, 3 keys each, both axes): max |diff| %.1e"
          % (len(jobs), ", ".join(map(str, widths)), worst))
    loose = {}
    for (n, _, _), g in zip(jobs, got):
        loose.setdefault(n, 0)
        loose[n] += any(u > w + 1e-6 for u, w in zip(g[2], g[1]))
    print("  solves where G' alone overstates some W(r), per width: %s"
          % ", ".join("n = %d: %d/6" % kv for kv in sorted(loose.items())))
    check(all(v > 0 for n, v in loose.items() if n >= 10),
          "CONTROL: at every width from n = 10, the recursion over G' alone overstates "
          "W(r) on some key -- the bounded walk over the whole graph is needed")


# ═══════════════════════════════════════════════════════════════════════════
# §2  the pinned sample
# ═══════════════════════════════════════════════════════════════════════════
def section_2(rec, per, full):
    rule("§2  v2_transient_series.json: the whole seeded sample, re-solved in part")
    ok = True
    for n, K in PLAN:
        want = [[t, B] for t, B in KS.draw(n, K)]
        ok &= [r[:2] for r in rec["widths"][str(n)]] == want
    check(ok, "every width's rows are exactly key_series.draw(n, K)'s seeded sample, "
          "in order (%s keys)" % "/".join(str(len(rec["widths"][str(n)])) for n, _ in PLAN))
    jobs = []
    for n, _ in PLAN:
        rows = rec["widths"][str(n)]
        k = len(rows) if full else (per if n < 19 else (1 if per > 2 and n == 19 else 0))
        jobs += [(n, r) for r in rows[:k]]
    with ThreadPoolExecutor(THREADS) as ex:
        got = list(ex.map(lambda j: solve(j[0], j[1][1]), jobs))
    bad = 0
    for (n, r), g in zip(jobs, got):
        for axis in (0, 1):
            m, W = g[axis]
            pm, pW = r[2 + axis]
            bad += abs(m - pm) > 3e-9 or max(abs(a - b) for a, b in zip(W, pW)) > 3e-9
    check(not bad, "%d pinned keys re-solve to the recorded mu and W(1..2n) on both axes"
          % len(jobs))


# ═══════════════════════════════════════════════════════════════════════════
# §3  the transient over keys
# ═══════════════════════════════════════════════════════════════════════════
def measures(rec):
    """out[(n, axis)] = dict of stratified (mean, se) per measure, plus per-key lists."""
    out = {}
    for n, _ in PLAN:
        S = KS.strata(n)
        rows = rec["widths"][str(n)]
        r0 = 3 * n // 4
        for axis in (0, 1):
            per = {"c": [], "c2": [], "w": [], "m": [], "mu": []}
            for r in rows:
                mu, W = r[2 + axis]
                per["c"].append((W[r0 - 1] - mu * r0) / n)
                per["c2"].append((W[2 * n - 1] - mu * 2 * n) / n)
                per["w"].append(W[r0 - 1] / n)
                per["m"].append(mu * r0 / n)
                per["mu"].append(mu)
            est = {}
            for k, xs in per.items():
                kr = [[r[0], r[1], x, x] for r, x in zip(rows, xs)]
                est[k] = KS.estimate(S, kr, 0)
                if k in ("w", "m"):
                    est[k + "_fail"] = KS.wshare_below(S, kr, 0, BAR[axis])
            est["keys"] = per
            out[(n, axis)] = est
    return out


def section_3(rec):
    rule("§3  The transient over keys: c(r) = W(r) - mu * r, at r = floor(3n/4) and 2n")
    M = measures(rec)
    for axis in (0, 1):
        print("\n  %s (criterion W(floor(3n/4)) >= %s)" % (NAME[axis], "n" if axis == 0 else "n/2"))
        print("     n  keys   E[mu]   E[c(3n/4)]/n   E[c(2n)]/n   E[W(3n/4)]/n   bar on mu"
              "   fail W   fail mu*r")
        for n, _ in PLAN:
            e = M[(n, axis)]
            print("  %4d  %4d   %.3f   %+.3f ± %.3f  %+.3f ± %.3f   %.3f ± %.3f     %.3f"
                  "     %5.1f%%   %5.1f%%"
                  % (n, len(e["keys"]["c"]), e["mu"][0], e["c"][0], e["c"][1], e["c2"][0],
                     e["c2"][1], e["w"][0], e["w"][1], (BAR[axis] - e["c"][0]) / 0.75,
                     100 * e["w_fail"], 100 * e["m_fail"]))
    ns = [n for n, _ in PLAN]
    for axis in (0, 1):
        nm = NAME[axis]
        neg = all(max(M[(n, axis)]["keys"]["c"]) < 0 for n in ns)
        check(neg, "%s: c(floor(3n/4)) < 0 on EVERY key of every width -- the transient "
              "is a discount, never a surcharge" % nm)
        gap = max(abs(M[(n, axis)]["c2"][0] - M[(n, axis)]["c"][0]) for n in ns)
        check(gap < 0.025, "%s: E[c(2n)]/n is within %.3f of E[c(3n/4)]/n at every width -- "
              "the transient has settled by the deployed round count" % (nm, gap))
        a, b = M[(ns[0], axis)]["c"], M[(ns[-1], axis)]["c"]
        z = (a[0] - b[0]) / math.hypot(a[1], b[1])
        check(z > 5, "%s: the discount GROWS with width: E[c/n] %+.3f at n = %d against "
              "%+.3f at n = %d (%.1f SE)" % (nm, a[0], ns[0], b[0], ns[-1], z))
        fw = [M[(n, axis)]["w_fail"] for n in ns]
        fm = [M[(n, axis)]["m_fail"] for n in ns]
        check(all(x >= y for x, y in zip(fw, fm)),
              "%s: at every width the true criterion W(3n/4) fails for at least as large a "
              "share of keys as mu * 3n/4 does" % nm)
        check(fw[-1] < fw[0] / 2,
              "%s: the share failing the true criterion falls from %.0f%% at n = %d to "
              "%.0f%% at n = %d" % (nm, 100 * fw[0], ns[0], 100 * fw[-1], ns[-1]))
        # (e) the per-bit pace, in two halves that share n = 14
        ec = wfit([(n,) + M[(n, axis)]["c"] for n in ns if n <= 14])
        lc = wfit([(n,) + M[(n, axis)]["c"] for n in ns if n >= 14])
        lw = wfit([(n,) + M[(n, axis)]["w"] for n in ns if n >= 14])
        print("  %s: d(E[c/n])/dn %+.4f +/- %.4f at n = 10..14, %+.4f +/- %.4f at n = 14..%d;"
              " d(E[W(3n/4)]/n)/dn %+.4f +/- %.4f at n = 14..%d"
              % (nm, ec[0], ec[1], lc[0], lc[1], ns[-1], lw[0], lw[1], ns[-1]))
        check(lc[0] <= ec[0] + 2 * math.hypot(ec[1], lc[1]),
              "%s: the discount does NOT slow with width -- its per-bit slope over "
              "n = 14..%d (%+.4f) is no shallower than over n = 10..14 (%+.4f)"
              % (nm, ns[-1], lc[0], ec[0]))
        check(lw[0] > 5 * lw[1],
              "%s: E[W(3n/4)]/n still rises over n = 14..%d (%+.4f per bit, %.0f SE) -- mu's "
              "growth outpaces the discount" % (nm, ns[-1], lw[0], lw[0] / lw[1]))
    return M


def wfit(pts):
    """Weighted least-squares slope (and its SE) of (x, y, se_y) points."""
    w = [1 / e ** 2 for _, _, e in pts]
    S = sum(w)
    Sx = sum(wi * x for wi, (x, _, _) in zip(w, pts))
    Sy = sum(wi * y for wi, (_, y, _) in zip(w, pts))
    Sxx = sum(wi * x * x for wi, (x, _, _) in zip(w, pts))
    Sxy = sum(wi * x * y for wi, (x, y, _) in zip(w, pts))
    D = S * Sxx - Sx * Sx
    return (S * Sxy - Sx * Sy) / D, math.sqrt(S / D)


# ═══════════════════════════════════════════════════════════════════════════
# §4  what it changes
# ═══════════════════════════════════════════════════════════════════════════
BAR_5454 = {0: 1.71, 1: 0.87}    # §11.54.4's bars, from c/n at n = 10..14, 8 keys each


def section_4(M):
    rule("§4  What it changes: the bars on mu, read at n = 19 and 20")
    with open(KS.PINNED) as fh:
        ks = json.load(fh)
    for n, axis in ((n, axis) for n in (19, 20) for axis in (0, 1)):
        S = KS.strata(n)
        e = M[(n, axis)]
        bar = (BAR[axis] - e["c"][0]) / 0.75
        se = e["c"][1] / 0.75
        rows = ks["widths"][str(n)]
        kmu = KS.estimate(S, rows, axis)[0]
        print("  %s: c/n = %+.3f gives a bar on mu of %.3f (+/- %.3f), against §11.54.4's "
              "%.2f;\n    §11.55's E[mu] over keys at n = %d, %.3f, is %.2fx it (%.2fx "
              "the old bar); E[W(3n/4)] / (%s) = %.2f"
              % (NAME[axis], e["c"][0], bar, se, BAR_5454[axis], n, kmu, kmu / bar,
                 kmu / BAR_5454[axis], "n" if axis == 0 else "n/2", e["w"][0] / BAR[axis]))
        check((bar - BAR_5454[axis]) / se > 5,
              "%s: the bar measured at n = %d is above §11.54.4's %.2f by %.0f SE -- "
              "§11.54.4's bars were too low, and §11.55's margins with them"
              % (NAME[axis], n, BAR_5454[axis], (bar - BAR_5454[axis]) / se))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    a = ap.parse_args()
    if a.regenerate:
        regenerate()
        return 0
    print(__doc__)
    ESL.build()
    AUD.build()
    with open(PINNED) as fh:
        rec = json.load(fh)
    section_1((7, 8, 10, 11, 13) if a.quick else (7, 8, 10, 11, 13, 14))
    section_2(rec, 2 if a.quick else 3, a.full)
    section_4(section_3(rec))
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
