#!/usr/bin/env python3
"""v2_implicit_solver.py — TODO #343 (third pass): the certified v2 solver with its
graph held IMPLICITLY, so the period series is no longer capped by memory.

certified_cycle_mean.c keeps every edge of weight <= W_u and raises W_u until
W_u >= mu' - p(u).  That bound charges every edge's target the least potential there
is (p(v) <= 0), so it keeps far more than the certificate needs: 76 M edges and ~1 GB
on the heaviest pinned n = 20 key, ~5 GB at n = 22 and ~8 GB at n = 23
(exact_slope_ladder.py).  The solver now has a second mode (header field 6):

  * G' starts as the stored solver's first graph (every edge of weight <= W0).
  * Howard and the potential run on G' exactly as before.
  * A CERTIFY PASS then walks every row again -- the same row walks, to the same bound
    mu' - p(u), so no edge the stored solver would keep is skipped -- and tests each
    edge against the potential at ITS OWN target, p(v) <= p(u) + w - mu' + TOL.  The
    edges that fail join G' (every one when a pass finds at most 2^n of them, else
    each row's 4 worst), and the solve repeats.  A pass that finds none certifies
    mu(G) >= mu' - TOL on the whole graph: the stored solver's certificate, with its
    tolerances, but nothing beyond G' is ever stored.

  §1  THE SAME MU.  Implicit against stored, key for key, both axes, on fixed-seed
      keys at n = 7..16 (and 17 by default): equal to 4e-9.  CONTROL: the first pass
      alone -- G' before any certify pass -- gives a mu ABOVE the certified one on
      keys of every width from n = 10 (at n = 7, 8 the W0 graph is already exact),
      so the certify passes are what makes the answer exact.
  §2  THE PINNED SLOPES.  key_series.json's keys re-solved in the implicit mode
      reproduce the recorded mu (9 digits), and by default the heaviest pinned
      n = 20 key of each axis.
  §3  THE GRAPH HELD.  On the heaviest pinned keys (largest mu, so the largest
      stored graph) the implicit G' holds under half the stored edges in all, and
      under 0.75 on any one key.  Recorded: 0.30 in all over the ten default solves
      (0.10 to 0.57 each; linear keys gain less); at n = 20, 76 M -> 19 M edges
      (differential) and 35 M -> 16 M (linear), peak memory 964 -> 316 MB and
      486 -> 272 MB.  The time stays within about 2x either way: each certify pass
      costs what one of the stored solver's rebuilds costs.
  §4  REACH (--full).  n = 22, one key, both modes: the same mu, and differential
      225 M -> 26 M edges (2.9 GB -> 0.7 GB, 880 -> 649 s), linear 54 M -> 38 M
      (940 -> 778 MB, ~220 s either way).  n = 23 in the implicit mode alone:
      1.2 GB / 23 min (differential) and 1.4 GB / 8 min (linear).
      The LINEAR gain shrinks with width -- 0.25-0.57 at n = 17, 0.45 at n = 20, 0.70
      at n = 22 -- so on that axis most of G' is edges the certificate needs; the
      differential gain does not (0.10-0.29, 0.25, 0.12).

Fixed seeds and pinned keys, so the verdict is a deterministic computation.  The C
solver IS the gate, so no C compiler is a FAILURE, not a skip.  Peak memory is read
from os.wait4 and printed only: it is host-specific, and the gate is on edges.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_implicit_solver.py [--quick | --full]
      --quick : §1 to n = 16, §2 at 3 keys per width to n = 19, §3 at n = 17
                (~5 min on an aarch64 SBC, 8 threads)
      default : §1 to n = 17, §2 at 6 per width plus n = 20's heaviest keys, §3 at
                n = 17 and 20 (~20 min)
      --full  : adds §4 (~3 h; the stored n = 22 solve needs ~5 GB)
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "key_series.json")
FAIL = []
THREADS = max(1, min(os.cpu_count() or 1, 64))
TOL_SAME = 4e-9      # both modes certify mu to within 2e-9 of a cycle mean of G
TOL_PIN = 3e-9       # the pinned file rounds to 9 digits


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


ESL = _load("exact_slope_ladder.py")      # build(), TABLES, keys()
AUD = _load("v2_measurement_audit.py")   # delta()


def solve(n, d, axis, implicit):
    """(mu, edges, rounds, first-pass mu or None, peak MB or None).  The first-pass mu
    is the implicit mode's mu on G' before any certify pass, read from its log."""
    w0 = 3.0 if axis == 0 else 2.0
    with tempfile.TemporaryFile("w+") as err:
        P = subprocess.Popen([ESL.EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=err, text=True)
        P.stdin.write("%d %d %d %r 0 %d\n%s\n" % (n, d, axis, w0, int(implicit), ESL.TABLES))
        P.stdin.close()
        out = P.stdout.read()
        P.stdout.close()
        try:
            _, status, ru = os.wait4(P.pid, 0)
            P.returncode = os.waitstatus_to_exitcode(status)
            mb = ru.ru_maxrss // 1024
        except (AttributeError, ChildProcessError):
            P.wait()
            mb = None
        if P.returncode:
            raise RuntimeError("solver failed: n = %d, d = %#x, axis %d" % (n, d, axis))
        err.seek(0)
        first = re.search(r"pass 1: .* mu ([0-9.]+),", err.read())
    m, e, r = out.split()
    return float(m), int(e), int(r), float(first.group(1)) if first else None, mb


def pmap(f, jobs, threads=THREADS):
    with ThreadPoolExecutor(threads) as ex:
        return list(ex.map(lambda j: f(*j), jobs))


# ═══════════════════════════════════════════════════════════════════════════
# §1  the same mu
# ═══════════════════════════════════════════════════════════════════════════
def section_1(widths):
    rule("§1  Implicit against stored, key for key")
    jobs = [(n, d, axis) for n in widths for d in ESL.keys(n, 4) for axis in (0, 1)]
    st = pmap(lambda n, d, a: solve(n, d, a, False), jobs)
    im = pmap(lambda n, d, a: solve(n, d, a, True), jobs)
    worst = max(abs(s[0] - i[0]) for s, i in zip(st, im))
    check(worst <= TOL_SAME,
          "the implicit mode returns the stored solver's mu on all %d solves (n = %s, "
          "4 keys each, both axes): max |diff| %.1e" % (len(jobs), ", ".join(map(str, widths)), worst))
    above = {}
    for (n, d, a), i in zip(jobs, im):
        above.setdefault(n, 0)
        above[n] += i[3] is not None and i[3] > i[0] + 1e-6
    print("  solves whose first-pass mu is above the certified mu, per width: %s"
          % ", ".join("n = %d: %d/8" % kv for kv in sorted(above.items())))
    check(all(v > 0 for n, v in above.items() if n >= 10),
          "CONTROL: at every width from n = 10, on some key, G' before the first "
          "certify pass overstates mu -- the certify passes change the answer")


# ═══════════════════════════════════════════════════════════════════════════
# §2  the pinned slopes
# ═══════════════════════════════════════════════════════════════════════════
def heaviest(rec, n, axis, k):
    return sorted(rec["widths"][str(n)], key=lambda r: -r[2 + axis])[:k]


def section_2(rec, per, with20):
    rule("§2  key_series.json's keys, re-solved in the implicit mode")
    jobs = []
    for n in (14, 16, 17, 19):
        for r in rec["widths"][str(n)][:per]:
            jobs += [(n, r, 0), (n, r, 1)]
    if with20:
        jobs += [(20, heaviest(rec, 20, a, 1)[0], a) for a in (0, 1)]
    got = pmap(lambda n, r, a: solve(n, AUD.delta(r[1], n), a, True)[0], jobs)
    bad = [(n, r[1], a) for (n, r, a), m in zip(jobs, got) if abs(m - r[2 + a]) > TOL_PIN]
    check(not bad, "%d pinned solves (%d keys per width at n = 14, 16, 17, 19%s) reproduce "
          "the recorded mu%s" % (len(jobs), per, ", and n = 20's heaviest key of each "
                                 "axis" if with20 else "", "" if not bad else ": %s" % bad))
    if not with20:
        print("  n = 20: not re-solved in this mode (n/a)")


# ═══════════════════════════════════════════════════════════════════════════
# §3  the graph held
# ═══════════════════════════════════════════════════════════════════════════
def section_3(rec, plan):
    rule("§3  The graph each mode holds, on the heaviest pinned keys")
    print("  %3s %4s %8s %12s %12s %6s %9s %9s %8s %8s"
          % ("n", "axis", "key", "stored E", "implicit E", "ratio", "stored MB",
             "impl. MB", "stored s", "impl. s"))
    rows = []
    for n, k, threads in plan:
        jobs = [(n, r, a) for a in (0, 1) for r in heaviest(rec, n, a, k)]
        def timed(n, r, a, imp):
            t = time.time()
            out = solve(n, AUD.delta(r[1], n), a, imp)
            return out + (time.time() - t,)
        st = pmap(lambda n, r, a: timed(n, r, a, False), jobs, threads)
        im = pmap(lambda n, r, a: timed(n, r, a, True), jobs, threads)
        for (n_, r, a), s, i in zip(jobs, st, im):
            rows.append((n_, a, s, i))
            mb = lambda x: "n/a" if x is None else "%d" % x
            print("  %3d %4s %8x %12d %12d %6.2f %9s %9s %8.0f %8.0f"
                  % (n_, "diff" if a == 0 else "lin", r[1], s[1], i[1], i[1] / s[1],
                     mb(s[4]), mb(i[4]), s[5], i[5]))
    worst = max(i[1] / s[1] for _, _, s, i in rows)
    tot = sum(i[1] for _, _, s, i in rows) / sum(s[1] for _, _, s, i in rows)
    same = max(abs(s[0] - i[0]) for _, _, s, i in rows)
    check(tot < 0.5 and worst < 0.75 and same <= TOL_SAME,
          "on the %d heaviest-key solves the implicit G' holds %.2f of the stored edges "
          "in all, at most %.2f on any one, at the same mu (max |diff| %.1e)"
          % (len(rows), tot, worst, same))


# ═══════════════════════════════════════════════════════════════════════════
# §4  reach
# ═══════════════════════════════════════════════════════════════════════════
def section_4():
    rule("§4  Reach: n = 22 in both modes, n = 23 in the implicit mode")
    d22 = ESL.keys(22, 1)[0]
    for a in (0, 1):
        t = time.time(); s = solve(22, d22, a, False); ts = time.time() - t
        t = time.time(); i = solve(22, d22, a, True); ti = time.time() - t
        print("  n = 22, d = %#x, %s: stored mu %.9f, %d edges, %s MB, %.0f s; implicit "
              "%d edges, %s MB, %.0f s" % (d22, "diff" if a == 0 else "lin", s[0], s[1],
                                          s[4], ts, i[1], i[4], ti))
        name, bound = (("differential", "under half"), ("linear", "fewer than"))[a]
        check(abs(s[0] - i[0]) <= TOL_SAME and i[1] < s[1] * (0.5 if a == 0 else 1.0),
              "n = 22, %s: same mu, %s the stored edges (%.2f)" % (name, bound, i[1] / s[1]))
    d23 = ESL.keys(23, 1)[0]
    for a in (0, 1):
        t = time.time(); i = solve(23, d23, a, True); ti = time.time() - t
        print("  n = 23, d = %#x, %s: implicit mu %.9f, %d edges, %d passes, %s MB, %.0f s"
              % (d23, "diff" if a == 0 else "lin", i[0], i[1], i[2], i[4], ti))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    print(__doc__)
    ESL.build()
    with open(PINNED) as fh:
        rec = json.load(fh)
    section_1((7, 8, 10, 11, 13, 14, 16) if a.quick else (7, 8, 10, 11, 13, 14, 16, 17))
    section_2(rec, 3 if a.quick else 6, not a.quick)
    section_3(rec, [(17, 2, THREADS)] if a.quick else [(17, 4, THREADS), (20, 1, 2)])
    if a.full:
        section_4()
    else:
        rule("§4  Reach")
        print("  --full only (n/a)")
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
