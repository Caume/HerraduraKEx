#!/usr/bin/env python3
"""key_series.py — TODO #343 (second pass): NL-FSCX v2's exact trail slope over
KEYS, not over uniform delta, to n = 20, stratified by the zero run of the key
schedule.

§11.54 (v2_measurement_audit.py) showed TODO #257's series sampled the wrong
population: a key gives delta(B) = ROL(p, n/4), p = B * ((B+1) >> 1) mod 2^n, and
p's trailing-zero run has a heavy tail that makes the round cheap.  It could only
reweight the old samples, and ~46% of them got weight zero.  This pass draws keys.

  §1  THE SAMPLER.  Keys are split into strata by t = tz(p), t = 0..7 and t >= 8.
      Each stratum's weight is its exact share of the key space, by enumeration.
      Keys whose delta makes the round affine -- {0, 2^(n-1), 2^(n-2), 3 * 2^(n-2)},
      §11.54.3 -- are left out: the CLIs refuse the first two, and no key reaches the
      other two at n = 256, so leaving them in would weigh a class n = 256 does not
      have.  Within a stratum keys are drawn uniformly; every stratum gets at least
      KMIN of them, so the long-run tail is resolved and not just present.  The
      estimator is the stratum-weighted mean, its error the stratified one.
      CHECK: at n = 10, 11 (and 13 by default) a stratified sample drawn by the same
      code agrees with the EXHAUSTIVE key average within 3 standard errors.

  §2  THE PINNED SAMPLE.  n = 14, 16, 17, 19, 20, both axes on every key, in
      key_series.json (~17 h of CPU, n = 20 up to ~4 GB per solve).  The gate shows
      the file is the whole seeded sample and re-solves a prefix of every width.

  §3  THE SERIES OVER KEYS.  Exhaustive to n = 13, sampled above.
      (a) E[mu] over keys rises at every step of both residue classes, both axes.
      (b) It sits BELOW TODO #257's uniform-delta figure at every pinned width.
      (c) The per-period increments over keys, and the ratios between them.
      (d) Quantiles: the 1st and 5th percentiles, and the share of keys whose slope
          is below §11.54.4's corrected bars (1.71 differential, 0.87 linear) --
          which falls at every step of both classes from n = 10, to ~5% at n = 20.

  §4  WHAT THIS CHANGES.  The widest width of n = 256's class, n = 19, against the
      old and the corrected bars: 1.47x / 1.44x of the corrected ones.

The verdicts on the series are computed from the pinned file, so they cannot flake;
the re-solves use the certified C solver, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/key_series.py [--quick | --full]
      --quick      : §1 at n = 10, 11; re-solve 2 pinned keys per width below 20
                     (~5 min on an aarch64 SBC, 8 threads)
      default      : §1 also at n = 13; re-solve 4 per width, n = 20 included (~10 min)
      --full       : re-solve every pinned key            (~17 h single-core)
      --regenerate : rebuild key_series.json in parallel, resumable, then exit
                     (~5 h on 8 cores; --only 20 and --only 14,16,17,19 may run
                     side by side, then a plain --regenerate assembles the file)
"""

import argparse
import importlib.util
import json
import math
import os
import random
import statistics as st
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "key_series.json")
FAIL = []
THREADS = max(1, min(os.cpu_count() or 1, 64))

SEED = 3431
TMAX = 8                      # strata t = 0 .. TMAX-1, and t >= TMAX
KMIN = 8                      # every stratum gets at least this many keys
# (width, nominal sample size): stratum t gets max(KMIN, ceil(K * weight))
PLAN = ((14, 1200), (16, 800), (17, 600), (19, 300), (20, 80))
EXHAUSTIVE = (7, 8, 10, 11, 13)
NAME = {0: "differential", 1: "linear"}
BAR_OLD = {0: 4 / 3, 1: 2 / 3}
BAR_NEW = {0: 1.71, 1: 0.87}  # SecurityProofs-10.md §11.54.4


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


AUD = _load("v2_measurement_audit.py")   # delta(), p_of(), tz(), all_mu()
ESL = AUD.ESL                            # the certified C solver
PS = AUD.PS                              # period_series_n19: the uniform-delta record


def affine(n):
    return {0, 1 << (n - 1), 1 << (n - 2), 3 << (n - 2)}


# ═══════════════════════════════════════════════════════════════════════════
# the strata, exactly
# ═══════════════════════════════════════════════════════════════════════════
def stratum(B, n):
    p = AUD.p_of(B, n)
    return min(AUD.tz(p), TMAX) if p else TMAX


def strata(n):
    """{t: sorted keys of stratum t}, affine-delta keys removed."""
    aff = affine(n)
    out = {t: [] for t in range(TMAX + 1)}
    for B in range(1 << n):
        if AUD.delta(B, n) not in aff:
            out[stratum(B, n)].append(B)
    return out


def allocation(S, K):
    tot = sum(len(v) for v in S.values())
    return {t: min(len(v), max(KMIN, math.ceil(K * len(v) / tot)))
            for t, v in S.items() if v}


def draw(n, K, S=None):
    """The seeded stratified sample: [(t, B)] in draw order."""
    S = S or strata(n)
    rnd = random.Random(SEED * 100 + n)
    out = []
    for t, k in sorted(allocation(S, K).items()):
        out += [(t, B) for B in rnd.sample(S[t], k)]
    return out


def estimate(S, rows, axis):
    """Stratified mean and its standard error; rows = [(t, B, mu_d, mu_l)]."""
    tot = sum(len(v) for v in S.values())
    m, var = 0.0, 0.0
    for t in S:
        xs = [r[2 + axis] for r in rows if r[0] == t]
        if not xs:
            continue
        w = len(S[t]) / tot
        m += w * st.mean(xs)
        if len(xs) > 1:
            var += w * w * st.variance(xs) / len(xs) * (1 - len(xs) / len(S[t]))
    return m, math.sqrt(var)


def wquantile(S, rows, axis, f):
    tot = sum(len(v) for v in S.values())
    k = {t: sum(1 for r in rows if r[0] == t) for t in S}
    pts = sorted((r[2 + axis], len(S[r[0]]) / tot / k[r[0]]) for r in rows)
    acc = 0.0
    for x, w in pts:
        acc += w
        if acc >= f:
            return x
    return pts[-1][0]


def wshare_below(S, rows, axis, bar):
    tot = sum(len(v) for v in S.values())
    k = {t: sum(1 for r in rows if r[0] == t) for t in S}
    return sum(len(S[r[0]]) / tot / k[r[0]] for r in rows if r[2 + axis] < bar)


def solve(n, B):
    d = AUD.delta(B, n)
    return ESL.cmu(n, d, 0)[0], ESL.cmu(n, d, 1)[0]


# ═══════════════════════════════════════════════════════════════════════════
# --regenerate
# ═══════════════════════════════════════════════════════════════════════════
def regenerate(only=None):
    ESL.build()
    ck = PINNED + ".partial"
    done = {}
    if os.path.exists(ck):
        with open(ck) as fh:
            for ln in fh:
                n, t, B, a, b = json.loads(ln)
                done[(n, B)] = (t, a, b)
    import threading
    lock = threading.Lock()
    for n, K in sorted(PLAN, key=lambda x: x[0]):
        if only and n not in only:
            continue
        jobs = [(t, B) for t, B in draw(n, K) if (n, B) not in done]
        workers = int(os.environ.get("KS_WORKERS20", "2")) if n >= 20 else THREADS
        print("n = %d: %d keys to solve, %d workers" % (n, len(jobs), workers), flush=True)

        def one(job, n=n):
            t, B = job
            a, b = solve(n, B)
            with lock:
                with open(ck, "a") as fh:
                    fh.write(json.dumps([n, t, B, round(a, 9), round(b, 9)]) + "\n")
                done[(n, B)] = (t, a, b)
            return job

        with ThreadPoolExecutor(workers) as ex:
            for i, _ in enumerate(ex.map(one, jobs)):
                if (i + 1) % 50 == 0:
                    print("  n = %d: %d / %d" % (n, i + 1, len(jobs)), flush=True)
    widths = {}
    for n, K in PLAN:
        if only:
            break
        rows = []
        for t, B in draw(n, K):
            tt, a, b = done[(n, B)]
            rows.append([t, B, round(a, 9), round(b, 9)])
        widths[str(n)] = rows
    if only:
        print("solved widths %s; rerun without --only to write %s" % (only, PINNED))
        return
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: exact v2 slopes (differential, linear) over "
                   "stratified key samples; rows are [stratum t, key B, mu_diff, mu_lin]",
                   "seed": SEED, "tmax": TMAX, "kmin": KMIN,
                   "plan": [list(x) for x in PLAN], "widths": widths}, fh, indent=0)
    print("wrote", PINNED)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the sampler against exhaustive truth
# ═══════════════════════════════════════════════════════════════════════════
def exhaustive(n):
    """Exact key averages and the per-key mu table: {axis: (mean, p1, p5)}, rows."""
    mu = AUD.all_mu(n)
    aff = affine(n)
    S = strata(n)
    rows = [(t, B, mu[0][AUD.delta(B, n)], mu[1][AUD.delta(B, n)])
            for t in S for B in S[t] if AUD.delta(B, n) not in aff]
    return S, rows


def section_1(widths):
    rule("§1  the stratified key sampler, against the exhaustive key average")
    exact = {}
    print("     n  axis          exhaustive   stratified sample (K = 300)   z")
    for n in widths:
        S, rows = exhaustive(n)
        by_B = {r[1]: r for r in rows}
        samp = [by_B[B] for _, B in draw(n, 300, S)]
        for axis in (0, 1):
            truth = st.mean(r[2 + axis] for r in rows)
            m, se = estimate(S, samp, axis)
            z = (m - truth) / se
            exact[(n, axis)] = (truth, [r[2 + axis] for r in rows])
            print("  %4d  %-12s  %.4f       %.4f +- %.4f  (%d keys)         %+.2f"
                  % (n, NAME[axis], truth, m, se, len(samp), z))
            check(abs(z) < 3, "n = %d %s: the stratified estimate is within 3 standard "
                  "errors of the exhaustive key average" % (n, NAME[axis]))
    return exact


# ═══════════════════════════════════════════════════════════════════════════
# §2  the pinned sample
# ═══════════════════════════════════════════════════════════════════════════
def section_2(rec, per_width, full):
    rule("§2  the pinned sample")
    ok_draw = True
    for n, K in PLAN:
        rows = rec["widths"][str(n)]
        want = draw(n, K)
        same = [(r[0], r[1]) for r in rows] == want
        ok_draw &= same
        print("  n = %d: %d keys over %d strata%s"
              % (n, len(rows), len({r[0] for r in rows}), "" if same else "  MISMATCH"))
    check(ok_draw and rec["seed"] == SEED and [tuple(x) for x in rec["plan"]] == list(PLAN),
          "key_series.json is exactly the seeded stratified sample of every width")
    for n, K in PLAN:
        rows = rec["widths"][str(n)]
        if full:
            sub = rows
        else:
            # one key from each end of the stratum order: a common and a rare stratum
            k = per_width if (n < 20 or per_width > 2) else 0
            sub = (rows[:k // 2] + rows[-(k - k // 2):]) if k else []
        if not sub:
            print("  n = %d: no re-solve in this mode (n/a)" % n)
            continue
        with ThreadPoolExecutor(2 if n >= 20 else THREADS) as ex:
            got = list(ex.map(lambda r: solve(n, r[1]), sub))
        bad = [(r, g) for r, g in zip(sub, got)
               if abs(g[0] - r[2]) > 1e-6 or abs(g[1] - r[3]) > 1e-6]
        check(not bad, "n = %d: %d pinned keys re-solve to the recorded slopes on both "
              "axes" % (n, len(sub)))


# ═══════════════════════════════════════════════════════════════════════════
# §3  the series over keys
# ═══════════════════════════════════════════════════════════════════════════
def uniform_record():
    """TODO #257's uniform-delta E[mu] by (axis, n), pooled from the pinned files."""
    acc = {}
    for f in ("period_series_n19.json", "period_series_n20.json"):
        with open(os.path.join(HERE, f)) as fh:
            for c in json.load(fh)["cells"]:
                n, a = c["n"], c["axis"]
                for k, i in ((n, 0), (n + 3, 1)):
                    acc.setdefault((a, k), []).extend(x[i] for x in c["mu"])
    return {k: st.mean(v) for k, v in acc.items()}


def section_3(rec, exact):
    rule("§3  the series over keys")
    uni = uniform_record()
    series, shares = {}, {}
    print("     n  axis          E[mu] keys        uniform-delta   p1      p5     "
          "share < corrected bar")
    for n in sorted({n for n, _ in exact} | {n for n, _ in PLAN}):
        for axis in (0, 1):
            if (n, axis) in exact:
                m, xs = exact[(n, axis)]
                se = 0.0
                p1 = sorted(xs)[int(.01 * len(xs))]
                p5 = sorted(xs)[int(.05 * len(xs))]
                below = sum(x < BAR_NEW[axis] for x in xs) / len(xs)
                how = "exhaustive"
            else:
                S = strata(n)
                rows = rec["widths"][str(n)]
                m, se = estimate(S, rows, axis)
                p1 = wquantile(S, rows, axis, .01)
                p5 = wquantile(S, rows, axis, .05)
                below = wshare_below(S, rows, axis, BAR_NEW[axis])
                how = "%d keys" % len(rows)
            series[(n, axis)] = (m, se)
            shares[(n, axis)] = below
            u = uni.get((axis, n))
            print("  %4d  %-12s  %.4f +- %.4f   %s   %.3f   %.3f   %5.1f%%   (%s)"
                  % (n, NAME[axis], m, se, "%.4f" % u if u else "  --  ", p1, p5,
                     100 * below, how))
    ns = sorted({n for n, _ in series})
    for axis in (0, 1):
        for cls in (1, 2):
            seq = [n for n in ns if n % 3 == cls]
            ups = []
            for a, b in zip(seq, seq[1:]):
                (ma, sa), (mb, sb) = series[(a, axis)], series[(b, axis)]
                ups.append((mb - ma) / math.sqrt(sa * sa + sb * sb + 1e-30))
            check(min(ups) > 3, "%s, n = %d (mod 3): E[mu] over keys rises at every "
                  "step %s, by %.1f standard errors or more"
                  % (NAME[axis], cls, "->".join(map(str, seq)), min(ups)))
    for axis in (0, 1):
        for cls in (1, 2):
            seq = [n for n in ns if n % 3 == cls and n >= 10]
            sh = [shares[(n, axis)] for n in seq]
            check(all(b < a for a, b in zip(sh, sh[1:])),
                  "%s, n = %d (mod 3): the share of keys below the corrected bar falls "
                  "at every step from n = %d (%s)" % (NAME[axis], cls, seq[0],
                  " -> ".join("%.1f%%" % (100 * x) for x in sh)))
    lower = [(n, a) for (n, a) in series if (a, n) in uni and n in dict(PLAN)
             and series[(n, a)][0] < uni[(a, n)]]
    want = [(n, a) for (n, a) in series if (a, n) in uni and n in dict(PLAN)]
    check(len(lower) == len(want), "E[mu] over keys is below the uniform-delta record at "
          "%d of %d pinned (width, axis) points" % (len(lower), len(want)))
    print("\n  per-period increments over keys, P(n) = E[mu_(n+3)] - E[mu_n]:")
    for axis in (0, 1):
        for cls in (1, 2):
            seq = [n for n in ns if n % 3 == cls]
            inc = [(a, series[(b, axis)][0] - series[(a, axis)][0],
                    math.hypot(series[(a, axis)][1], series[(b, axis)][1]))
                   for a, b in zip(seq, seq[1:])]
            print("  %-12s n = %d (mod 3): %s" % (NAME[axis], cls, "  ".join(
                "P(%d) = %.3f+-%.3f" % x for x in inc)))
            rat = ["%.2f" % (y[1] / x[1]) for x, y in zip(inc, inc[1:])]
            print("  %-12s %18s ratios %s" % ("", "", " ".join(rat)))
    return series


def section_4(series):
    rule("§4  what this changes")
    top = {a: max(n for n, ax in series if ax == a and n % 3 == 1) for a in (0, 1)}
    for a in (0, 1):
        n = top[a]
        m, se = series[(n, a)]
        print("  %s: at n = %d (the class of 256), E[mu] over keys = %.3f +- %.3f:"
              " %.2fx the old bar %.3f, %.2fx the corrected %.2f"
              % (NAME[a], n, m, se, m / BAR_OLD[a], BAR_OLD[a], m / BAR_NEW[a], BAR_NEW[a]))
    print("""
  TODO #257's series is replaced by one over the population that ships: keys,
  stratified by the zero run that makes them weak.  The rise continues and so does
  its slowing; the margins at the widest widths are the ones above, against bars
  that themselves rest on §11.54.4's c / n, measured to n = 14 only.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--only", default="", help="with --regenerate: comma-separated widths")
    a = ap.parse_args()
    if a.regenerate:
        regenerate({int(x) for x in a.only.split(",") if x} or None)
        return 0
    print(__doc__)
    AUD.build()
    with open(PINNED) as fh:
        rec = json.load(fh)
    widths = (10, 11) if a.quick else (10, 11, 13)
    exact = section_1(widths)
    for n in EXHAUSTIVE:
        if (n, 0) not in exact:
            S, rows = exhaustive(n)
            for axis in (0, 1):
                exact[(n, axis)] = (st.mean(r[2 + axis] for r in rows),
                                    [r[2 + axis] for r in rows])
    section_2(rec, 2 if a.quick else 4, a.full)
    series = section_3(rec, exact)
    section_4(series)
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
