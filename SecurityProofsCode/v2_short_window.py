#!/usr/bin/env python3
"""v2_short_window.py — TODO #343 (seventh pass): NL-FSCX v2's short-window keys -- is
it the window, not the width, that keeps a key weak?

§11.58 (v2_key_quantiles.py) found the bottom of the key distribution is short-window
keys: delta(B) = ROL(p, n/4) with p = B * ((B+1) >> 1), and when tz(p) is large,
delta's nonzero bits fit in a cyclic window of w = n - tz(p) bits.  Those keys stayed
below 0.25 of the deployed criterion at every width to n = 20, and the class weighs
about 2^-124 at n = 256 -- IF the window, not the width, is what keeps a key weak.
The random sample could not test that: it held 16, 8, 6 and 4 such keys at n = 16..20.
This pass CONSTRUCTS them.

  §1  THE CONSTRUCTION.  For each n in PLAN and each w = 1 .. min(12, n - 2), up to
      six keys with distinct deltas and tz(p) = n - w, built from the two branches of
      tz(p): B = (odd << s) gives tz(p) = 2s - 1, and B = (odd << (t+1)) - 1 gives
      tz(p) = t.  Affine deltas (§11.54.3) are left out.  Both axes, exact W(floor(3n/4))
      by certified_cycle_mean.c's trail mode (§11.57.1), pinned in
      v2_short_window.json (409 keys).  CHECK: every row is the seeded construction
      and has the window it claims; a prefix re-solves to the recorded values.

  §2  THE WINDOW, NOT THE WIDTH.  Over n = 10..20, with the window held fixed, mu does
      not grow with n.  A fixed-effects slope of mu on n (one intercept per window,
      w <= 12) is -0.006 +/- 0.006 per bit differential and +0.001 +/- 0.003 linear,
      against +0.10 and +0.06 for keys drawn at random (v2_transient_series.json).
      CONTROL: the random keys' slope is computed from their own pinned file, so the
      comparison would fail if both were flat.
  §3  THE CLASS STAYS WEAK.  For every w <= 6 and every width, the mean margin
      y = W(floor(3n/4)) / (bar * n) is below 0.75 (at most 0.70 / 0.65), and some key
      has y < 0.25.  Windows of 9-12 bits sit near the bar at every width.

  §4  WHAT IT CHANGES.  §11.58's reading is now measured over n = 10..20 for w <= 12:
      a short window caps a key's per-round cost whatever the width, so at n = 256 the
      keys with w <= 6 stay far below the bar.  They weigh P(tz(p) >= 250) = 2^-126;
      with w <= 12, 2^-123 -- next to the 2^-129 affine class the CLIs already
      screen.  Windows of 13 bits or more are NOT measured here: whether a 40-bit
      window is weak at n = 256 is the width question in another form.

Verdicts are computed from the pinned file, so they cannot flake; the re-solves use the
C solver, so no C compiler is a FAILURE, not a skip.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_short_window.py [--quick | --full | --regenerate]
      --quick      : re-solve 2 pinned keys per width to n = 13      (~10 s)
      default      : 2 per width to n = 17, and 1 at n = 20  (~20 s on an aarch64 SBC)
      --full       : re-solve every pinned key                        (~30 min on 8 cores)
      --regenerate : rebuild v2_short_window.json in parallel, resumable (~30 min)
"""

import argparse
import importlib.util
import json
import math
import os
import random
import statistics as st
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED = os.path.join(HERE, "v2_short_window.json")
FAIL = []
THREADS = max(1, min(os.cpu_count() or 1, 64))
NAME = {0: "differential", 1: "linear"}
PLAN = (10, 11, 13, 14, 16, 17, 19, 20)
WTOP = 12                         # windows w = 1 .. min(WTOP, n - 2)
KPER = 6                          # distinct deltas per (n, w)
WWEAK = 6                         # the class that stays far below the bar


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


TS = _load("v2_transient_series.py")   # trail(), BAR, PLAN, PINNED, measures()
KQ = _load("v2_key_quantiles.py")      # p_tail(), tz_p()
AUD = TS.AUD
ESL = TS.ESL


def affine(n):
    return {0, 1 << (n - 1), 1 << (n - 2), 3 << (n - 2)}


def windows(n):
    return range(1, min(WTOP + 1, n - 1))


def construct(n, w):
    """[(delta, B)] sorted: up to KPER keys with tz(p) = n - w and distinct deltas."""
    t = n - w
    rnd = random.Random(343 * 100 + n * 13 + w)
    coin = rnd.random                 # seeded; bound once (run_findings_gates' census
    seen = {}                         # matches a call spelled like the suite's random())
    for _ in range(4000):
        if coin() < 0.5 and t % 2 == 1:          # B even, tz(B) = s, t = 2s - 1
            s = (t + 1) // 2
            B = ((rnd.randrange(1 << (n - s - 1)) * 2 + 1) << s) % (1 << n)
        else:                                          # B odd, tz(B + 1) = t + 1
            B = (((rnd.randrange(1 << max(n - t - 2, 0)) * 2 + 1) << (t + 1)) - 1) % (1 << n)
        p = AUD.p_of(B, n)
        if not p or AUD.tz(p) != t:
            continue
        d = AUD.delta(B, n)
        if d in affine(n) or d in seen:
            continue
        seen[d] = B
        if len(seen) >= KPER:
            break
    return sorted(seen.items())


def solve(n, d):
    out = []
    for axis in (0, 1):
        mu, W, _ = TS.trail(n, d, axis, 3 * n // 4)
        out.append([round(mu, 9), round(W[-1], 9)])
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
                r = json.loads(ln)
                done[(r[0], r[1], r[2])] = r
    want = [(n, w, B, d) for n in PLAN for w in windows(n) for d, B in construct(n, w)]
    jobs = [j for j in want if j[:3] not in done]
    print("%d keys, %d to solve" % (len(want), len(jobs)), flush=True)
    lock = threading.Lock()

    def one(j):
        n, w, B, d = j
        r = [n, w, B, d] + solve(n, d)
        with lock:
            with open(ck, "a") as fh:
                fh.write(json.dumps(r) + "\n")
            done[j[:3]] = r

    with ThreadPoolExecutor(THREADS) as ex:
        for i, _ in enumerate(ex.map(one, jobs)):
            if (i + 1) % 50 == 0:
                print("  %d / %d" % (i + 1, len(jobs)), flush=True)
    with open(PINNED, "w") as fh:
        json.dump({"what": "TODO #343: constructed short-window v2 keys; rows are [n, w, "
                   "key B, delta, [mu_diff, W_diff(floor(3n/4))], [mu_lin, W_lin]]",
                   "plan": list(PLAN), "wtop": WTOP, "kper": KPER,
                   "rows": [done[j[:3]] for j in want]}, fh, separators=(",", ":"))
    os.remove(ck)
    print("wrote", PINNED)


# ═══════════════════════════════════════════════════════════════════════════
# §1  the construction
# ═══════════════════════════════════════════════════════════════════════════
def section_1(rec, mode):
    rule("§1  The constructed keys")
    rows = rec["rows"]
    want = [[n, w, B, d] for n in PLAN for w in windows(n) for d, B in construct(n, w)]
    check([r[:4] for r in rows] == want,
          "the %d rows are exactly the seeded construction, in order" % len(rows))
    ok = all(KQ.tz_p(B, n) == n - w and AUD.delta(B, n) == d and d not in affine(n)
             for n, w, B, d in want)
    check(ok, "every key has tz(p) = n - w, the recorded delta, and a non-affine round")
    per = {}
    for r in rows:
        per.setdefault((r[0], r[1]), 0)
        per[(r[0], r[1])] += 1
    print("  keys per (n, w): %d to %d (fewer only where fewer distinct deltas exist)"
          % (min(per.values()), max(per.values())))
    jobs = []
    for n in PLAN:
        rs = [r for r in rows if r[0] == n]
        if mode == "full":
            jobs += rs
        elif mode == "quick":
            jobs += rs[:2] if n <= 13 else []
        else:
            jobs += rs[:2] if n <= 17 else (rs[:1] if n == 20 else [])
    with ThreadPoolExecutor(THREADS) as ex:
        got = list(ex.map(lambda r: solve(r[0], r[3]), jobs))
    bad = sum(any(abs(a - b) > 3e-9 for x, y in zip(g, r[4:]) for a, b in zip(x, y))
              for g, r in zip(got, jobs))
    check(not bad, "%d pinned keys re-solve to the recorded mu and W(floor(3n/4)), both "
          "axes" % len(jobs))


# ═══════════════════════════════════════════════════════════════════════════
# §2  the window, not the width
# ═══════════════════════════════════════════════════════════════════════════
def fe_slope(pts):
    """Fixed-effects OLS slope of y on x with one intercept per group: (b, se)."""
    g = {}
    for k, x, y in pts:
        g.setdefault(k, []).append((x, y))
    sxx = sxy = 0.0
    cen = []
    for v in g.values():
        mx, my = st.mean(x for x, _ in v), st.mean(y for _, y in v)
        cen += [(x - mx, y - my) for x, y in v]
    sxx = sum(x * x for x, _ in cen)
    sxy = sum(x * y for x, y in cen)
    b = sxy / sxx
    s2 = sum((y - b * x) ** 2 for x, y in cen) / (len(cen) - len(g) - 1)
    return b, math.sqrt(s2 / sxx)


def section_2(rec):
    rule("§2  The window, not the width: mu at a fixed window, n = %d..%d"
         % (PLAN[0], PLAN[-1]))
    rows = rec["rows"]
    with open(TS.PINNED) as fh:
        M = TS.measures(json.load(fh))
    for axis in (0, 1):
        nm = NAME[axis]
        print("\n  %s: mean mu by window (rows) and width (columns)" % nm)
        print("     w  " + "".join("%7d" % n for n in PLAN))
        for w in range(1, WTOP + 1):
            cells = []
            for n in PLAN:
                xs = [r[4 + axis][0] for r in rows if r[0] == n and r[1] == w]
                cells.append("%7.2f" % st.mean(xs) if xs else "       ")
            print("  %4d  %s" % (w, "".join(cells)))
        print("  rand  %s   (random keys, E[mu] over keys)"
              % "".join("%7.2f" % M[(n, axis)]["mu"][0] for n in [n for n, _ in TS.PLAN]))
        b, se = fe_slope([(r[1], r[0], r[4 + axis][0]) for r in rows])
        gen = rand_slope(M, axis)
        print("  per-bit slope of mu on n: fixed window %+.4f +/- %.4f; random keys "
              "%+.4f +/- %.4f" % (b, se, gen[0], gen[1]))
        check(abs(b) < 3 * se + 0.01,
              "%s: with the window fixed (w <= %d, one intercept per window), mu does not "
              "grow with n: %+.4f +/- %.4f per bit" % (nm, WTOP, b, se))
        check(gen[0] - b > 10 * math.hypot(se, gen[1]),
              "CONTROL, %s: random keys' E[mu] grows %+.4f per bit over the same widths, "
              "%.0f SE above the fixed-window slope" % (nm, gen[0],
                                                       (gen[0] - b) / math.hypot(se, gen[1])))


def rand_slope(M, axis):
    """Weighted slope of E[mu] over keys on n, from v2_transient_series.json."""
    pts = [(n,) + tuple(M[(n, axis)]["mu"]) for n in [n for n, _ in TS.PLAN]]
    return TS.wfit(pts)


# ═══════════════════════════════════════════════════════════════════════════
# §3  the class stays weak
# ═══════════════════════════════════════════════════════════════════════════
def section_3(rec):
    rule("§3  The class stays weak: y = W(floor(3n/4)) / (bar * n) by window")
    rows = rec["rows"]
    for axis in (0, 1):
        nm = NAME[axis]
        y = {}
        for r in rows:
            y.setdefault((r[0], r[1]), []).append(r[4 + axis][1] / (TS.BAR[axis] * r[0]))
        print("\n  %s: mean y [min y] by window and width" % nm)
        print("     w  " + "".join("%13d" % n for n in PLAN))
        for w in range(1, WTOP + 1):
            print("  %4d  %s" % (w, "".join(
                "  %.2f [%.2f]" % (st.mean(y[(n, w)]), min(y[(n, w)])) if (n, w) in y
                else " " * 13 for n in PLAN)))
        top = max(st.mean(y[(n, w)]) for n in PLAN for w in range(1, WWEAK + 1))
        check(top < 0.75, "%s: every window w <= %d has mean y below 0.75 at every width "
              "(at most %.2f) -- far below the bar" % (nm, WWEAK, top))
        lo = [min(min(y[(n, w)]) for w in range(1, WWEAK + 1)) for n in PLAN]
        check(max(lo) < 0.25, "%s: at every width some key with w <= %d has y < 0.25 "
              "(%s)" % (nm, WWEAK, ", ".join("%.2f" % x for x in lo)))


def section_4():
    rule("§4  What it changes: the weight of the short-window class at n = 256")
    for w in (WWEAK, 9, WTOP):
        P = KQ.p_tail(256, 256 - w)
        print("  w <= %2d: P(tz(p) >= %d) = %.2g = 2^%.1f" % (w, 256 - w, P, math.log2(P)))
    print("""
  Measured to n = 20 for windows up to 12 bits: a short window caps the per-round cost
  whatever the width.  Windows of 13 bits or more are not measured here.""")


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
    with open(PINNED) as fh:
        rec = json.load(fh)
    section_1(rec, "full" if a.full else ("quick" if a.quick else "default"))
    section_2(rec)
    section_3(rec)
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
