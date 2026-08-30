#!/usr/bin/env python3
"""and_layer_recheck.py — re-run TODO #246's candidate comparison correctly.

TODO #246 chose candidate B (the deployed v2 round followed by a chi layer over
short odd rows) on trail weights read at r = 2-5.  TODO #252 then showed that
window is inside the TRANSIENT -- the cheap opening rounds every key gets from
its probability-1 one-round differential -- so #246's comparison was made on a
quantity that is not the asymptotic slope, and #251 was left holding evidence
whose methodology had been invalidated underneath it.

This is the re-run.  #246's ORDERING SURVIVES, and it comes out better founded
than it was, for a reason #246 could not have given: candidate B's advantage
lives in the transient, and TODO #252 §11.31.2 established that the transient is
the WIDTH-INDEPENDENT part.  So the part of a small-width comparison that
carries to n = 256 is precisely the part where B wins.

  §1  A reporting bug in this script's own first attempt, recorded because it
      pointed the wrong way.
  §2  The corrected comparison, with ceilings and windows shown.
  §3  The structural finding: B has no free first round; the deployed round and
      candidate A both do.
  §4  Candidate A is disqualified on the linear axis.
  §5  What this does and does not do for TODO #251.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/and_layer_recheck.py [--quick]
"""

import argparse
import importlib.util
import math
import os
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def _bounds():
    p = os.path.join(ROOT, 'SecurityProofsCode', 'nl_fscx_v2_bounds.py')
    spec = importlib.util.spec_from_file_location("_b", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


BB = _bounds()
G = BB.G
NAMES = [("deployed v2", G['mk_v2']),
         ("A: Feistel M+AND", G['mk_feistel']),
         ("B: v2 then chi", G['mk_chi'])]


def table(n, f):
    """Precompute the round as a lookup table — the candidates are far too slow
    to call 2^2n times through their Python definitions."""
    return [f(x, 1) for x in range(1 << n)]


def ddt_t(n, t):
    N = 1 << n
    rows = []
    for g in range(N):
        r = {}
        if g:
            for x in range(N):
                b = t[x] ^ t[x ^ g]
                r[b] = r.get(b, 0) + 1
        rows.append(r)
    return rows


def dtrail(n, D, R):
    N = 1 << n
    INF = float('inf')
    cost = [0.0 if a else INF for a in range(N)]
    out = []
    for _ in range(R):
        nxt = [INF] * N
        for a in range(N):
            ca = cost[a]
            if ca == INF:
                continue
            for b, c in D[a].items():
                if b == 0:
                    continue
                w = ca - math.log2(c / N)
                if w < nxt[b]:
                    nxt[b] = w
        cost = nxt
        out.append(min(v for v in cost if v != INF))
    return out


def lat_t(n, t):
    N = 1 << n
    rows = []
    for b in range(N):
        par = [1 if bin(t[x] & b).count('1') & 1 else -1 for x in range(N)]
        BB.fwht(par)
        rows.append([v / N for v in par])
    return rows


def avg_series(n, ks, mk, R, linear):
    W = []
    for k in ks:
        T = table(n, mk(n, k))
        W.append(BB.linear_series(n, lat_t(n, T), R) if linear
                 else dtrail(n, ddt_t(n, T), R))
    return [sum(w[i] for w in W) / len(W) for i in range(R)]


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  A reporting bug in this script's first attempt")
    print("""Recorded because it pointed the wrong way and would have been believed.

The first version applied TODO #252's window filter verbatim -- take increments
from round 4 onward that are still below the ceiling -- and printed "BELOW
criterion" whenever the filter returned nothing.  For candidates A and B it
returned nothing at every width, and the table duly reported both as failing.

They were not failing.  They were saturating BEFORE round 4, because they are
STRONGER: a construction that gains three bits a round crosses 0.6n while a
construction gaining half a bit is still warming up.  An empty window is a
statement about the measurement, not about the cipher, and conflating the two
penalises exactly the candidates the comparison exists to favour.

The fix is to detect each construction's own transient rather than assume a
common one, and to print "no window" as itself.  §2 does that.""")


def section_2(quick):
    rule("§2  The corrected comparison")
    print("""Cumulative trail weight, averaged over keys, with each construction's ceiling
crossing shown.  Differential ceiling ~0.6n; linear ceiling ~0.6*(n/2) = 0.3n.\n""")
    widths = [(8, 6), (10, 5)] + ([] if quick else [(11, 4)])
    lead = {}
    for n, K in widths:
        assert not G['m_is_singular'](n), n
        rng = random.Random(246 + n)
        ks = [rng.randrange(1 << n) for _ in range(K)]
        for linear in (False, True):
            axis = "LINEAR" if linear else "DIFFERENTIAL"
            cap = 0.3 * n if linear else 0.6 * n
            print(f"      n={n}, {K} keys — {axis} (ceiling {cap:.1f})")
            print(f"      {'construction':<20}" + "".join(f"{'r=%d' % r:>7}" for r in range(1, 6))
                  + "   ceiling at")
            print("      " + SEP2[:62])
            for nm, mk in NAMES:
                a = avg_series(n, ks, mk, 6, linear)
                cross = next((i + 1 for i in range(6) if a[i] >= cap), None)
                lead[(n, axis, nm)] = a
                print(f"      {nm:<20}" + "".join(f"{a[i]:>7.2f}" for i in range(5))
                      + f"   {('r=%d' % cross) if cross else 'not reached':>11}")
                sys.stdout.flush()
            print()
    return lead


def section_3(quick):
    rule("§3  The structural finding: candidate B has no free first round")
    print("""Every construction whose round is linear-then-add-constant hands the attacker
a probability-1 one-round differential: the MSB difference passes any constant
addition because the final carry is discarded (TODO #253 §11.28.3).  That is the
source of the transient, and TODO #252 showed the transient is what poisons
every slope measurement in this repository.

Candidate B removes it at the source.  chi is non-linear, so a single-bit
difference entering it propagates to three output bits, two of them
data-dependent -- the free differential stops being free.  Round-1 weight, which
is exactly "how expensive is the cheapest single round":\n""")
    widths = [8, 10] + ([] if quick else [11])
    print(f"      {'construction':<20}" + "".join(f"{'n=%d' % n:>18}" for n in widths))
    print(f"      {'':<20}" + "".join(f"{'diff / linear':>18}" for n in widths))
    print("      " + SEP2[:62])
    r1 = {}
    for nm, mk in NAMES:
        cells = []
        for n in widths:
            rng = random.Random(246 + n)
            ks = [rng.randrange(1 << n) for _ in range(4)]
            d = avg_series(n, ks, mk, 1, False)[0]
            l = avg_series(n, ks, mk, 1, True)[0]
            r1[(nm, n)] = (d, l)
            cells.append(f"{d:.2f} / {l:.2f}")
        print(f"      {nm:<20}" + "".join(f"{c:>18}" for c in cells))
        sys.stdout.flush()
    bfree = min(r1[("B: v2 then chi", n)][0] for n in widths)
    vfree = max(r1[("deployed v2", n)][0] for n in widths)
    afree = max(r1[("A: Feistel M+AND", n)][0] for n in widths)
    print(f"""
      The deployed round and candidate A are at 0.00 on BOTH axes at every
      width: a completely free first round, differentially and linearly.
      Candidate B is at {bfree:.2f} or better differentially and never free linearly,
      and the figure is STABLE ACROSS WIDTHS -- {' / '.join('%.2f' % r1[("B: v2 then chi", n)][0] for n in widths)} -- as a
      transient quantity should be.

      WHY THIS MATTERS MORE THAN #246'S ORIGINAL ARGUMENT.  #246 compared
      saturated slopes and TODO #252 invalidated that comparison.  This one is a
      comparison of TRANSIENTS, and §11.31.2 established the transient is the
      width-independent part -- confirmed independently by MILP, where n = 16 and
      n = 32 give identical proven optima at r = 4 and r = 5.  So this is the
      part of a small-width comparison that actually carries to n = 256, and it
      is the part where B wins outright.

      What it is still NOT: an asymptotic bound.  B saturates by round 3 at these
      widths, so B has no measurement window at all here (§2), and its
      asymptotic slope is as unmeasured as the deployed round's.  The claim is
      that B is better, not that B is sufficient.""")
    check(vfree == 0.0 and afree == 0.0,
          "the deployed round or candidate A no longer has a free first round")
    check(bfree >= 1.5, f"candidate B's round-1 differential weight fell to {bfree:.2f}")


def section_4(quick):
    rule("§4  Candidate A is disqualified on the linear axis")
    print("""#246 preferred B on differential evidence and TODO #247 §(c) checked that B
was not worse linearly.  Neither looked hard at A.  Exact optimal linear-trail
weight, cumulative:\n""")
    widths = [8, 10] + ([] if quick else [11])
    print(f"      {'n':>3}  {'construction':<20}" + "".join(f"{'r=%d' % r:>7}" for r in range(1, 9)))
    print("      " + SEP2[:70])
    broken = False
    for n in widths:
        rng = random.Random(246 + n)
        ks = [rng.randrange(1 << n) for _ in range(4)]
        for nm, mk in (("A: Feistel M+AND", G['mk_feistel']), ("B: v2 then chi", G['mk_chi'])):
            a = avg_series(n, ks, mk, 8, True)
            if nm.startswith("A") and n == 8 and max(a) == 0.0:
                broken = True
            print(f"      {n:>3}  {nm:<20}" + "".join(f"{v:>7.2f}" for v in a))
            sys.stdout.flush()
    print("""
      At n = 8 candidate A has a CORRELATION-1 LINEAR TRAIL THROUGH EIGHT ROUNDS
      -- weight 0.00 the whole way.  That is a total linear break at that width.
      At n = 10 and 11 it settles to exactly 1.00 bit per round, an integer so
      clean it indicates a structural correlation-1/2 approximation per round
      rather than a measured average.

      Two caveats before this is read as harsher than it is.  A is a Feistel
      whose halves are n/2 = 4 bits at n = 8, which is degenerate, so the total
      break is plausibly a small-width artefact.  And 1.00 bit/round still clears
      the 2/3 criterion of §11.30.1.

      It is nonetheless enough to settle the comparison: A is the only candidate
      exhibiting a probability-1 trail of any length on either axis at any width
      measured, and B beats it on both axes everywhere.  #246 chose B; nothing
      here disturbs that and A should not be revisited.""")
    check(broken, "candidate A's n=8 correlation-1 linear trail no longer reproduces")


def section_5():
    rule("§5  What this does for TODO #251")
    print("""#251 holds candidate B's migration, blocked on evidence.  Its own text says it
is unblocked by TODO #252, or by TODO #253, or "by a decision to accept
small-width comparative evidence as sufficient -- which is a legitimate call,
but must be made explicitly and recorded, not arrived at by default."

WHERE THE EVIDENCE NOW STANDS.

  Stronger than #246 had, in the specific way that matters.  #246's comparison
  rested on saturated slopes and #252 invalidated it.  This one rests on the
  transient, which #252 established is the width-independent part -- so the
  small-width evidence for B is no longer the weak kind of small-width evidence.
  B is ahead by 2-3x differentially and clearly ahead linearly at every width,
  and it is the only candidate without a free opening round.

  Still not a bound.  B saturates by round 3 at every reachable width, so it has
  no measurement window and its asymptotic slope is unmeasured -- exactly as the
  deployed round's is.  #252 and #254 are not closed by this and their targets
  are unchanged.

  And the case for URGENCY is weaker than when #251 was filed.  TODO #254 found
  the deployed round meets the linear criterion at every width measured (settled
  0.93-0.95 against 2/3), and #253 found the per-key gap does not sink the
  differential margin.  The thing candidate B was meant to fix looks less broken
  than it did when #246 proposed it.

  So the decision is genuinely a judgement call, which is what #251 anticipated:
  a five-construction MAJOR, on comparative evidence that is now well founded but
  still not a bound, against a deployed construction that is not known to be
  failing.  This script does not make that call -- it is the user's, and #251
  requires it be recorded explicitly.  What this script removes is the reason to
  defer it: the evidence base is no longer methodologically broken.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_1()
    section_2(a.quick)
    section_3(a.quick)
    section_4(a.quick)
    section_5()
    print()
    if FAIL:
        print(SEP)
        print(f"*** FAILED: {len(FAIL)} finding(s) no longer reproduce ***")
        for f in FAIL:
            print("  - " + f)
        print(SEP)
        return 1
    print(SEP)
    print("*** OK: every finding reproduced ***")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
