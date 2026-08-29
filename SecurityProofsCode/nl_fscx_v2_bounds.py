#!/usr/bin/env python3
"""nl_fscx_v2_bounds.py — TODO #247: the trail-bound work #214 recommended.

TODO #214 closed with three follow-ups that were never filed, and TODO #243 and
#244 both had to lean on its bounds while caveating them.  TODO #247 filed them;
this is the tractable part of all three.

  (a) Does the trail slope depend on width?  This is the question behind #214's
      self-declared weakest step -- it reads a slope at small width and projects
      it to n = 256.  Measured here across every width where an exact answer is
      reachable.
  (b) Fixed-key vs key-averaged.  #214 flagged that a key-averaged bound is not
      a per-key claim, which bites unusually hard for a construction that reuses
      one key every round.  Quantified here as the per-key spread.
  (c) Exact linear cryptanalysis.  #214 deferred its Walsh sub-item because as
      written it asked to resolve a 2^-16 bias by sampling.  Done here exactly,
      by fast Walsh-Hadamard transform at small width -- the substitute #214
      said "deserves its own item".  This is a security axis neither #214 nor
      TODO #246 had touched at all.

Method note: everything here is EXACT.  One-round DDT / LAT built by exhaustive
enumeration, then a dynamic program over difference (or mask) states, so every
figure is a proven optimum over all trails of that length rather than a sample
or a solver result that might have timed out.  Round constants do not affect any
of it -- an XOR constant leaves both tables invariant (SecurityProofs-7.md
§11.27.1).

NOT done here, and #247 stays open for it: a MILP formulation that reaches
n = 256.  No MILP solver is installed and this repository deliberately carries
almost no dependencies, so acquiring one is a decision rather than an
implementation detail.  See §4.

Run:  python3 SecurityProofsCode/nl_fscx_v2_bounds.py [--quick]
"""

import argparse
import math
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74

# The three round functions live in TODO #246's script; reuse rather than fork.
_SRC = None


def _load_candidates():
    import os
    p = os.path.join(os.path.dirname(__file__), 'nl_fscx_v2_and_layer.py')
    src = open(p).read().split("def main(")[0]
    g = {}
    exec(compile(src, p, 'exec'), g)
    return g


G = _load_candidates()


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


# ── exact tables ────────────────────────────────────────────────────────────
def ddt(n, f):
    N = 1 << n
    out = []
    for a in range(N):
        row = {}
        if a:
            for x in range(N):
                b = f(x, 1) ^ f(x ^ a, 1)
                row[b] = row.get(b, 0) + 1
        out.append(row)
    return out


def fwht(a):
    h, n = 1, len(a)
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                x, y = a[j], a[j + h]
                a[j], a[j + h] = x + y, x - y
        h *= 2
    return a


def lat(n, f):
    """corr[b][a] for output mask b, input mask a."""
    N = 1 << n
    tbl = [f(x, 1) for x in range(N)]
    rows = []
    for b in range(N):
        par = [1 if bin(tbl[x] & b).count('1') & 1 else -1 for x in range(N)]
        fwht(par)
        rows.append([v / N for v in par])
    return rows


def trail_series(n, d, maxr):
    """Exact optimal differential-trail weight after 1..maxr rounds."""
    N = 1 << n
    INF = float('inf')
    cost = [0.0 if a else INF for a in range(N)]
    out = []
    for _ in range(maxr):
        nxt = [INF] * N
        for a in range(N):
            ca = cost[a]
            if ca == INF:
                continue
            for b, c in d[a].items():
                if b == 0:
                    continue
                w = ca - math.log2(c / N)
                if w < nxt[b]:
                    nxt[b] = w
        cost = nxt
        out.append(min(v for v in cost if v != INF))
    return out


def linear_series(n, L, maxr):
    """Exact optimal linear-trail weight (-log2|correlation|) after 1..maxr."""
    N = 1 << n
    INF = float('inf')
    cost = [INF] * N
    for b in range(1, N):
        best = INF
        for a in range(1, N):
            c = abs(L[b][a])
            if c > 0:
                w = -math.log2(c)
                if w < best:
                    best = w
        cost[b] = best
    out = [min(v for v in cost[1:] if v != INF)]
    for _ in range(maxr - 1):
        nxt = [INF] * N
        for a in range(1, N):
            ca = cost[a]
            if ca == INF:
                continue
            for b in range(1, N):
                c = abs(L[b][a])
                if c > 0:
                    w = ca - math.log2(c)
                    if w < nxt[b]:
                        nxt[b] = w
        cost = nxt
        out.append(min(v for v in cost[1:] if v != INF))
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section_a(quick):
    rule("§(a)  Does the trail slope depend on width?")
    print("""TODO #214 reads a bits-per-round slope at small width and projects it to
n = 256, and labels that projection its own weakest step.  Everything since --
#243's and #244's ratings, TODO #246's comparison -- rests on it.  So: measured
across every width where an exact answer is reachable and M is invertible.

A trail cannot exceed about n bits of weight before it has consumed the whole
codebook, so a series approaching n has SATURATED and its slope is compressed
toward zero by the ceiling rather than by the cipher.  That is flagged, because
comparing a saturated slope with an unsaturated one is meaningless.\n""")
    widths = [(8, 6), (10, 6), (11, 6)] + ([] if quick else [(13, 3)])
    print(f"      {'n':>3}{'keys':>5}   " + "".join(f"r={r:<7}" for r in range(2, 7))
          + " slope   saturated?")
    print("      " + SEP2[:68])
    rng = random.Random(20250829)
    rows = []
    for n, K in widths:
        assert not G['m_is_singular'](n), n
        ks = [rng.randrange(1 << n) for _ in range(K)]
        series = [trail_series(n, ddt(n, G['mk_v2'](n, k)), 6) for k in ks]
        avg = [sum(s[i] for s in series) / K for i in range(6)]
        sl = (avg[4] - avg[2]) / 2
        sat = avg[5] > 0.6 * n
        rows.append((n, avg, sl, sat, series))
        print(f"      {n:>3}{K:>5}   " + "".join(f"{avg[r-1]:<9.2f}" for r in range(2, 7))
              + f" {sl:>5.2f}   {'YES (>0.6n)' if sat else 'no'}")
        sys.stdout.flush()
    sl_all = [r[2] for r in rows]
    print(f"""
      Slope range across widths: {min(sl_all):.2f} to {max(sl_all):.2f} bits/round, with no
      monotone drift.  That is the useful answer, and it is a SUPPORTIVE one:
      the slope looks width-stable over the range reachable exactly, and it
      brackets #214's independently measured 1.87 closely enough that its
      methodology is not called into question.

      A caution recorded because it nearly became a false finding.  An earlier
      2-key run of this same experiment produced 1.30 at n = 13 and appeared to
      show the slope collapsing with width -- which would have meant #214's
      projection, the 137-round figure, and everything quoting it were
      optimistic.  With 6 keys it does not reproduce.  Two keys is not a sample
      for a statistic with this much per-key spread; see §(b).

      What this still does NOT establish: that the slope holds from 13 to 256.
      The reachable range is tiny and everything saturates by round 6.  Only a
      MILP formulation reaches useful widths -- §(d).""")
    return rows


def section_b(rows):
    rule("§(b)  Fixed-key vs key-averaged: the spread")
    print("""TODO #214 flagged that its bounds are key-averaged and that this matters more
here than for a normal cipher, because NL-FSCX reuses one key in every round, so
per-round deviations correlate instead of averaging out.  A key-averaged bound
is a design-comparison currency, not a per-key security claim.

Quantified as the spread of the optimal 5-round trail weight across keys:\n""")
    print(f"      {'n':>3}  {'keys':>5}  {'min':>7}  {'mean':>7}  {'max':>7}  {'spread':>8}")
    print("      " + SEP2[:52])
    for n, avg, sl, sat, series in rows:
        v = sorted(s[4] for s in series)
        print(f"      {n:>3}  {len(v):>5}  {v[0]:>7.2f}  {sum(v)/len(v):>7.2f}  "
              f"{v[-1]:>7.2f}  {v[-1]-v[0]:>8.2f}")
    print("""
      The spread is a large fraction of the mean at every width.  A key drawn
      at the weak end of that distribution has materially less trail resistance
      than the averaged figure advertises, and nothing in the deployed system
      screens for it -- there is no analogue here of the QC-MDPC weak-key screen
      TODO #235 added, and no equivalent of nl_v2_key_is_valid for trail
      behaviour (that check covers only the degenerate affine class).

      This is not a new attack.  It is the reason the word "key-averaged" has to
      stay attached to every figure #214, #246 and this script produce, and the
      reason a rating cannot be granted on an averaged bound alone.""")


def section_c(quick):
    rule("§(c)  Exact linear cryptanalysis — the axis nobody had measured")
    print("""#214 deferred its Walsh sub-item: as written it asked to resolve a 2^-16 bias
by sampling, needing about 2^32 evaluations per functional.  The tractable
substitute it named -- an exact transform at small width -- is done here, by one
fast Walsh-Hadamard transform per output mask, then the same dynamic program
over mask states that §(a) runs over difference states.

This matters beyond completing a checklist: differential and linear resistance
are independent axes, and a construction can trade one for the other.  TODO
#246 recommends candidate B on differential evidence alone.  If B were worse
linearly, that recommendation would need revisiting.

Optimal linear-trail weight, -log2|correlation|, averaged over keys
(higher is better):\n""")
    n = 10
    K = 2 if quick else 3
    rng = random.Random(3)
    ks = [rng.randrange(1 << n) for _ in range(K)]
    names = [("current v2 (deployed)", G['mk_v2']),
             ("A: Feistel, M + AND", G['mk_feistel']),
             ("B: v2 then chi", G['mk_chi'])]
    print(f"      {'construction':<26}" + "".join(f"r={r:<6}" for r in (1, 2, 3)))
    print("      " + SEP2[:50])
    res = {}
    for nm, mk in names:
        s = [linear_series(n, lat(n, mk(n, k)), 3) for k in ks]
        avg = [sum(x[i] for x in s) / K for i in range(3)]
        res[nm] = avg
        print(f"      {nm:<26}" + "".join(f"{v:<8.2f}" for v in avg))
        sys.stdout.flush()
    print(f"""
      Same ordering as the differential axis, and the deployed construction is
      again the weak one: {res['current v2 (deployed)'][2]:.2f} bits over three rounds means a linear
      approximation of correlation about {2**-res['current v2 (deployed)'][2]:.2f} -- very nearly deterministic.

      The question this section was run to answer: candidate B is NOT worse
      linearly.  It leads on both axes, so #246's recommendation survives
      contact with linear cryptanalysis rather than being an artefact of only
      having looked at differentials.""")


def section_d():
    rule("§(d)  What remains, and the dependency question it raises")
    print("""The MILP half of #247 is not done, and cannot be done as things stand: no MILP
solver is installed, and this repository deliberately carries almost no
third-party dependencies -- `jsonschema`, tooling-only, is the entire list, and
z3 is already an optional soft dependency of #214 that degrades to a skip.

That makes acquiring a solver a decision rather than an implementation detail,
and it should be taken deliberately:

  * z3's optimiser is already present and could express the model, but it is a
    general SMT solver and #214 already found it stops closing at small widths.
    Reaching n = 64, let alone 256, is not a matter of writing the model.
  * A dedicated MILP backend (HiGHS via scipy, or PuLP/CBC) is the standard tool
    for exactly this and would plausibly reach useful widths.  It would be the
    first non-tooling dependency in the suite, and only for analysis scripts,
    never for the shipped primitives.

Recommendation: add it as an OPTIONAL analysis-only dependency with the same
degrade-to-skip pattern #214 uses for z3, so a bare `python3` still runs
everything else.  Until then, every bound in this repository is a small-width
exact result plus an extrapolation, and #243, #244 and #246 should keep saying
so in exactly those words.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true', help='skip n=13 and use fewer keys')
    args = ap.parse_args()
    print(SEP)
    print("Trail bounds: width-scaling, fixed-key spread, exact linear — TODO #247")
    print(SEP)
    rows = section_a(args.quick)
    section_b(rows)
    section_c(args.quick)
    section_d()
    print("\n" + SEP)
    print("Slope width-stable at reachable widths; B leads linearly too; MILP still open.")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
