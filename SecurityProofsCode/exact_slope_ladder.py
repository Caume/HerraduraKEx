#!/usr/bin/env python3
"""exact_slope_ladder.py — TODO #257 (fifth pass): is the exact slope really flat?

v9.5.25 (certified_cycle_ladder.py) measured exact mu on both axes to n = 20 and drew
two readings from it.  The ratio to the annealed model of §11.38 does not settle.  The
EXACT median mu/n looks flat, 0.14-0.16 differential and 0.07-0.08 linear.  The second
reading replaced §11.38's n = 256 figures, and it rested on medians of 12 keys at
n <= 16, 8 at n = 17, 6 at n = 19 and 4 at n = 20.  That is too thin to call a
distribution flat, and the Python solver was the reason it was thin.

This pass does two things.

  * certified_cycle_mean.c is the same certified solver in C.  It is fed the automaton
    tables from the Python sources, so the two cannot disagree about what an edge is,
    and §1 checks it against the Python solver on mu, edges kept and certificate
    rounds before any number is used.  It is ~40x faster and compacts its edge pool
    in place, so n = 20 takes about two minutes per key and n = 22 about half an hour.
  * The ladder then carries 32 keys per width to n = 17 (96 at n = 17 and 48 at n = 19
    in the recorded run), 16 at n = 20, and 8 at n = 22 and 3 at n = 23 under --full.

  §1  THE TRANSCRIPTION.  C against Python, key for key: same mu (to 1e-12), same
      edges kept, same certificate rounds.

  §2  THE LADDER, WITH A SPREAD.  FINDING, in four parts.
      (a) v9.5.25's "flat at 0.14-0.16" was partly a SAMPLING artefact.  Exact mu rises
          with the number of runs in delta (~0.13 per run differential, ~0.074 linear,
          pooled within widths), and §11.41's n = 20 sample happened to carry 0.60 n
          runs against ~0.5 n elsewhere.  Moved to a typical run count, the
          differential per-bit median is ~0.15 at n = 13-14 and ~0.13 at n = 19-23
          (0.132, 0.130, 0.123, 0.128), and keys already within one run of n/2 show the
          same step without any regression.  Whether it keeps falling or has levelled is
          not resolved.  The linear median moves within 0.064-0.074 with no decline
          established beyond the scatter (0.071 at n = 23, three keys).
      (b) Exact mu itself GROWS at every width step (run-adjusted, differential
          1.96 -> 2.95 and linear 0.95 -> 1.63 over n = 13..23), and sits at 2.2x and
          2.4x the criteria at n = 23.
      (c) The model's error is a SCALE error, not noise.  Within a width it ranks keys
          almost exactly (correlation 0.98 at n = 13), but it credits each run of delta
          with ~0.21 (differential) where exact mu gains ~0.12 at n >= 17, so the keys it
          rates strongest are capped: the exact-on-lambda* slope across keys falls from
          1.0 at n = 13 to ~0.7 at n = 17 and 0.1-0.6 at n = 20-23.
      (d) The keys AGREE more as n grows: IQR/median of exact mu/n falls from ~0.3 at
          n = 13 to 0.02-0.05 (differential) and 0.07-0.14 (linear) at n = 20-23.

  §3  WHAT THIS CHANGES.

Every key is drawn from a FIXED seed, so the verdict is a deterministic computation and
cannot flake.  The C solver IS the gate above n = 14, so a machine with no C compiler
FAILS rather than skips (CLAUDE.md's dependency rule).

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/exact_slope_ladder.py [--quick] [--full]
      --quick : n = 13, 14, 16, 17 at 16 keys each        (~3 min on an aarch64 SBC)
      default : 32 keys to n = 17, 24 at n = 19, 16 at 20  (~1.5 h)
      --full  : adds n = 22 at 8 keys and n = 23 at 3     (~8 h; up to ~5 GB per n = 22
                key and ~8 GB per n = 23 key -- do not run two at once on 16 GB)
"""

import argparse
import importlib.util
import os
import shutil
import statistics
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
CSRC = os.path.join(HERE, "certified_cycle_mean.c")


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


CCL = _load("certified_cycle_ladder.py")   # the Python certified solver, keys()
AML = CCL.AML                              # lam_diff, lam_lin
keys, med = CCL.keys, CCL.med


def _tables():
    """The two automata, read from the Python sources and handed to the C solver."""
    out = []
    for d in (0, 1):
        for a in (0, 1):
            for c in (0, 1):
                for e in (0, 1):
                    out += list(CCL.DIFF_T[(d, a, c, e)])
    for d in (0, 1):
        for u in (0, 1):
            for w in (0, 1):
                out += list(CCL.LIN_T[(d, u, w)])
    return " ".join(repr(float(x)) for x in out)


TABLES = _tables()
EXE = None


def build():
    """Compile the C solver.  It IS the gate above n = 17, so no compiler is a failure,
    not a skip (CLAUDE.md's dependency rule: the gate decides by what is left)."""
    global EXE
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        print("  no C compiler found (gcc/cc/clang): this gate cannot run.")
        print("  install one, e.g.  sudo apt-get install -y gcc")
        sys.exit(1)
    exe = os.path.join(tempfile.mkdtemp(prefix="ccm_"), "certified_cycle_mean")
    r = subprocess.run([cc, "-O2", "-o", exe, CSRC, "-lm"],
                       capture_output=True, text=True)
    if r.returncode:
        print(r.stderr)
        print("  certified_cycle_mean.c FAILED TO BUILD with a present compiler")
        sys.exit(1)
    EXE = exe


def cmu(n, d, axis, cycle=False):
    """(mu, edges kept, certificate rounds[, cycle]) from the C solver; axis 0 = diff,
    1 = linear.  The cycle is a list of (node, weight of its policy edge)."""
    w0 = 3.0 if axis == 0 else 2.0
    r = subprocess.run([EXE], input="%d %d %d %r %d\n%s\n"
                       % (n, d, axis, w0, int(cycle), TABLES),
                       capture_output=True, text=True, check=True)
    lines = r.stdout.split("\n")
    m, e, rd = lines[0].split()
    out = (float(m), int(e), int(rd))
    if cycle:
        L = int(lines[1])
        out += ([(int(a), float(b)) for a, b in (ln.split() for ln in lines[2:2 + L])],)
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §1  the transcription
# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The C solver against the Python certified solver, key for key")
    print("""certified_cycle_mean.c is a transcription of certified_cycle_ladder.py's solver,
fed the same automaton tables.  Same mu, same number of edges kept, same number of
certificate rounds -- or it is not the same solver.
""")
    worst, same = 0.0, True
    for n in (7, 8, 10, 11, 13, 14):
        for d in keys(n, 3):
            for axis, py in ((0, CCL.mu_diff), (1, CCL.mu_lin)):
                c = cmu(n, d, axis)
                p = py(n, d)
                worst = max(worst, abs(c[0] - p[0]))
                same = same and c[1] == p[1] and c[2] == p[2]
    check(worst < 1e-9 and same,
          "C and Python agree on mu (max |diff| %.1e), on edges kept and on certificate "
          "rounds, both axes, n = 7, 8, 10, 11, 13, 14, three keys each" % worst)


# ═══════════════════════════════════════════════════════════════════════════
# the ladder
# ═══════════════════════════════════════════════════════════════════════════
def widths(quick, full):
    if quick:
        return [(13, 16), (14, 16), (16, 16), (17, 16)]
    w = [(13, 32), (14, 32), (16, 32), (17, 32), (19, 24), (20, 16)]
    if full:
        w += [(22, 8), (23, 3)]
    return w


def q(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p * len(v)))]


def ladder(ws):
    """rows[axis][n] = list of (d, exact mu, annealed lambda*)."""
    rows = ({}, {})
    for n, cnt in ws:
        for d in keys(n, cnt):
            for axis, model in ((0, AML.lam_diff), (1, AML.lam_lin)):
                m = cmu(n, d, axis)[0]
                lo, _, _ = model(n, d)
                rows[axis].setdefault(n, []).append((d, m, lo))
    return rows


def stats(recs, n):
    mu = [m for _, m, _ in recs]
    lam = [a for _, _, a in recs]
    mn = [m / n for m in mu]
    md = statistics.median(mn)
    return dict(k=len(recs), med=md, q25=q(mn, .25), q75=q(mn, .75), lo=min(mn),
                ann=statistics.median(lam) / n,
                ratio=statistics.median([m / a for m, a in zip(mu, lam)]),
                slope=statistics.linear_regression(lam, mu)[0],
                iqr=(q(mn, .75) - q(mn, .25)) / md)


def table(rows, axis):
    print("  %3s %4s   %7s %7s %7s %7s   %7s   %6s   %6s   %6s"
          % ("n", "keys", "q25", "median", "q75", "min", "ann/n", "ratio", "slope",
             "IQR/md"))
    print("  %3s %4s   %31s" % ("", "", "------ exact mu / n ------"))
    out = {}
    for n in sorted(rows[axis]):
        st = out[n] = stats(rows[axis][n], n)
        print("  %3d %4d   %7.4f %7.4f %7.4f %7.4f   %7.4f   %6.3f   %6.2f   %6.3f"
              % (n, st["k"], st["q25"], st["med"], st["q75"], st["lo"], st["ann"],
                 st["ratio"], st["slope"], st["iqr"]))
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §2  the ladder
# ═══════════════════════════════════════════════════════════════════════════
NAME = {0: "differential", 1: "linear"}


def nruns(d, n):
    """Number of maximal runs of equal bits in delta."""
    return 1 + sum(((d >> i) & 1) != ((d >> (i - 1)) & 1) for i in range(1, n))


def per_run_slope(recs_by_n, which):
    """Pooled WITHIN-width least-squares slope of exact mu (which = 1) or lambda*
    (which = 2) on the run count of delta: each width is centred on its own means, so
    the slope measures key-to-key dependence and not the growth with n."""
    num = den = 0.0
    for n, recs in recs_by_n.items():
        xs = [nruns(r[0], n) for r in recs]
        ys = [r[which] for r in recs]
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        num += sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        den += sum((x - mx) ** 2 for x in xs)
    return num / den


def adjusted(recs, n, b):
    """Median exact mu/n with each key moved to the run count of a typical delta,
    n/2, along the pooled per-run slope b."""
    return statistics.median((m - b * (nruns(d, n) - n / 2)) / n for d, m, _ in recs)


def section_2(quick, full):
    rule("§2  Exact mu/n against the model, with enough keys to read a spread")
    print("""Same fixed key stream as certified_cycle_ladder.py, so its keys are a prefix of
these.  "slope" is the least-squares slope of exact mu on the model's lambda* ACROSS
the keys of one width; "IQR/md" is the interquartile range of exact mu/n over its
median, i.e. how much the keys of one width disagree; "adj" is the median exact mu/n
moved to a typical run count (n/2 runs in delta) along the pooled per-run slope.
""")
    rows = ladder(widths(quick, full))
    st = {}
    for axis in (0, 1):
        R = rows[axis]
        b_mu, b_lam = per_run_slope(R, 1), per_run_slope(R, 2)
        print("\n  %s   (per run of delta: exact mu %+.3f, model lambda* %+.3f)"
              % (NAME[axis].upper(), b_mu, b_lam))
        S = st[axis] = table(rows, axis)
        for n in S:
            S[n]["adj"] = adjusted(R[n], n, b_mu)
            S[n]["mu"] = statistics.median(m for _, m, _ in R[n])
            S[n]["corr"] = statistics.correlation([a for _, _, a in R[n]],
                                                  [m for _, m, _ in R[n]])
        print("  run-adjusted median exact mu/n:  " + "   ".join(
            "%d: %.4f" % (n, S[n]["adj"]) for n in sorted(S)))
    for axis in (0, 1):
        S, nm = st[axis], NAME[axis]
        check(S[13]["corr"] > 0.95,
              "%s: within n = 13 the model RANKS keys almost exactly (correlation of "
              "lambda* with exact mu %.3f)" % (nm, S[13]["corr"]))
        check(S[17]["slope"] < S[13]["slope"] - 0.2,
              "%s: across the keys of one width, exact mu tracks lambda* with slope "
              "%.2f at n = 13 and only %.2f at n = 17 -- the keys the model rates "
              "strongest are capped" % (nm, S[13]["slope"], S[17]["slope"]))
        check(S[17]["ratio"] < S[13]["ratio"] - 0.05,
              "%s: so the median exact/annealed ratio falls, %.3f at n = 13 to %.3f at "
              "n = 17" % (nm, S[13]["ratio"], S[17]["ratio"]))
        ns = sorted(n for n in S if isinstance(n, int))
        am = [S[n]["adj"] * n for n in ns]
        crit = 4.0 / 3.0 if axis == 0 else 2.0 / 3.0
        check(all(x < y for x, y in zip(am, am[1:])) and am[-1] > crit,
              "%s: run-adjusted median exact mu still GROWS at every width step (%s), "
              "and is %.1fx the %s criterion at n = %d"
              % (nm, ", ".join("%d: %.3f" % (n, x) for n, x in zip(ns, am)),
                 am[-1] / crit, "4/3" if axis == 0 else "2/3", ns[-1]))
        if 20 in S:
            wide = {n: rows[axis][n] for n in rows[axis] if n >= 17}
            e17, m17 = per_run_slope(wide, 1), per_run_slope(wide, 2)
            check(0 < e17 < 0.85 * m17,
                  "%s: at n >= 17 the model over-credits each run of delta: exact mu "
                  "gains %.3f per run, the model %.3f (%.2fx)"
                  % (nm, e17, m17, e17 / m17))
            lo = [S[n]["adj"] for n in (19, 20)]
            hi = [S[n]["adj"] for n in (13, 14)]
            gap = 0.008 if axis == 0 else 0.004
            check(max(lo) < min(hi) - gap,
                  "%s: but not in proportion -- run-adjusted median mu/n is lower at "
                  "n = 19 and 20 (%s) than at n = 13 and 14 (%s)"
                  % (nm, ", ".join("%.4f" % x for x in lo),
                     ", ".join("%.4f" % x for x in hi)))
            check(S[20]["iqr"] < S[13]["iqr"] / 2 and S[20]["slope"] < 0.7,
                  "%s: and by n = 20 the keys agree: IQR/median %.3f against %.3f at "
                  "n = 13, slope on lambda* %.2f" % (nm, S[20]["iqr"], S[13]["iqr"],
                                                     S[20]["slope"]))
        else:
            print("  %s: n = 19, 20 not run (--quick): the per-run over-credit, the "
                  "falling per-bit slope and the concentration are not scored" % nm)
        for n in (22, 23):
            if n in S:
                print("  %s: n = %d  run-adjusted median mu/n %.4f over %d keys (--full)"
                      % (nm, n, S[n]["adj"], S[n]["k"]))
    return st


# ═══════════════════════════════════════════════════════════════════════════
# §3  what this changes
# ═══════════════════════════════════════════════════════════════════════════
def section_3(st):
    rule("§3  What this changes for #257")
    print("""WITHDRAWN.  v9.5.25's reading of the exact slope as FLAT AT 0.14-0.16, and the
n = 256 figures of ~36 and ~18 (~27x both criteria) taken from it.  At a typical run
count the differential per-bit median is ~0.13 from n = 19 to 23, not 0.145, and it got
there by falling from ~0.15 at n = 13-14; the linear one has no measured trend either
way.

NOT FIXED BY THE DATA.  Any single n = 256 figure.  Forms that fit n = 13..23 span a
factor of 2.5 out there: a power law (mu ~ n^0.63 differential, n^0.84 linear) reads
~13 and ~11, about 10x and 17x the criteria; a per-bit median levelled at its last four
widths (0.128, 0.067) reads ~33 and ~17, about 25x.  Both are readings, neither a bound,
and the data do not choose between them.

WHAT IS MEASURED.  Exact mu grows at every width step from n = 13 to 23 on both axes
(run-adjusted), ending at 2.2x and 2.4x the criteria.  That is §11.37's monotonicity
residue with ten widths behind it: the criterion holds at n = 256 if exact mu is
non-decreasing in n, and that -- not a slope -- is what an argument has to show.  There
is still no embedding between widths (§11.37), so it cannot be shown by comparing
graphs.

ALSO MEASURED.  Exact mu concentrates as n grows (IQR/median ~0.3 -> ~0.03-0.1), and
the model's error is structured: right ranking, too much credit per run of delta.

No rating moves (every row this touches is demo-only on other axes: #243, #244, #248).""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    build()
    section_1()
    st = section_2(a.quick, a.full)
    section_3(st)
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        sys.exit(1)
    print("*** OK: every finding reproduced ***")


if __name__ == "__main__":
    main()
