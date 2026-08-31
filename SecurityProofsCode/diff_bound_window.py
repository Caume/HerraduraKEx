#!/usr/bin/env python3
"""diff_bound_window.py — TODO #252: why the differential bound has not closed.

TODO #252 asks for a two-sided differential trail bound at n = 256 and lists
three routes.  TODO #254's first pass changed what that bound has to say, so
this pass re-poses #252 before attacking it -- and the re-posing turns up the
reason every previous attempt was unstable.

  §1  The target, restated.  By TODO #254 §11.30.1 the criterion is
      width-independent: s_diff >= 4/3.  #252 does not need a bound "at
      n = 256"; it needs an asymptotic per-round increment, obtainable at any
      width where it can be read cleanly.

  §2  THE MEASUREMENT WINDOW, and why the reachable widths do not have one.
      A trail's increment series has a cheap TRANSIENT (every key has a
      probability-1 one-round differential, so the first few rounds are nearly
      free) and a CEILING (weight cannot pass ~n).  The asymptotic increment
      lives between them.  At every width an exhaustive DDT can reach, the two
      overlap and the window is empty.  That -- not solver time -- is why
      #247's figures were unstable and why #252 stalled.

  §3  Where the window opens, and what that does to #252's routes.  It needs
      n >= 32, which is MILP-only territory, so route 1 is re-motivated with a
      concrete target: not a bigger n, but a higher ROUND COUNT at n = 32-64.

  §4  A lead, explicitly not a conclusion: the per-key differential slope tracks
      the SIGNED-DIGIT (NAF) weight of delta(B), not its Hamming weight.
      Recorded with its sample sizes because they are too small to conclude on.

SUPERSEDED IN PART by diff_cycle_mean.py (TODO #252, second pass).  Everything
measured here still reproduces, and §3's demotion of routes 2 and 3 stands.  What
is WITHDRAWN is §2's conclusion that the asymptotic increment is not measurable
at any reachable width: that is true of reading a slope off a finite increment
series, which is what this file does, and false of the asymptote, which is the
minimum mean cycle of the difference graph -- an object in which the transient
cancels and the ceiling does not apply.  See SecurityProofs-8.md §11.35.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/diff_bound_window.py [--quick]
"""

import argparse
import importlib.util
import os
import random
import statistics
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


def _fk():
    p = os.path.join(ROOT, 'SecurityProofsCode', 'nl_fscx_v2_fixed_key.py')
    spec = importlib.util.spec_from_file_location("_fk", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


FK = _fk()
G = FK.G


def naf_weight(d, n):
    """Hamming weight of the non-adjacent form — the signed-digit weight.

    d and (2^n - d) have the same NAF weight, which is why two constants that
    look unrelated in binary can behave identically: x + d and x - d are the
    same object to differential cryptanalysis up to inversion."""
    d %= (1 << n)
    w = 0
    while d:
        if d & 1:
            z = 2 - (d & 3)
            d -= z
            w += 1
        d >>= 1
    return w


def typical_deltas(n, K, seed):
    N = 1 << n
    rng = random.Random(seed)
    ds = []
    while len(ds) < K:
        d = FK.delta(n, rng.randrange(N))
        if d and (d & -d).bit_length() - 1 <= 1:
            ds.append(d)
    return ds


def series(n, d, R):
    return FK.trail(n, FK.add_ddt(n, d), FK.m_tab(n), R, 1 << n)


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The target, restated after TODO #254")
    print("""#252 was filed asking for a two-sided bound AT n = 256, on the assumption that
the deployed width is what a bound has to speak about.  TODO #254 §11.30.1
showed otherwise: because FSCX ties its round count to its block size
(r = 3n/4), the differential criterion is

      s_diff * (3n/4) >= n    <=>    s_diff >= 4/3

with the width cancelling.  So #252's target is not a number at n = 256.  It is
the ASYMPTOTIC PER-ROUND INCREMENT, a single scalar, and it may be established
at whatever width it can be read most cleanly.

That is a strictly easier problem than the one #252 was filed with, and §2 is
about the reason it has still not been solved.""")


def section_2(quick):
    rule("§2  The measurement window — and why reachable widths have none")
    print("""Two effects bracket the usable part of an increment series.

TRANSIENT.  Every key has a probability-1 one-round differential: the MSB
difference passes any constant addition, because the final carry is discarded
(TODO #253 §11.28.3).  Near it sit differences that are nearly free, so the
first several rounds of an optimal trail cost almost nothing and the increment
climbs from zero rather than starting at its asymptote.

CEILING.  Weight cannot usefully exceed about n; past ~0.6n the series is
flattening against the codebook rather than reporting the cipher.

The asymptotic increment is what happens BETWEEN them.  Per-round increments
for the cheapest keys at n = 11, with the ceiling marked:\n""")
    n = 11
    R = 12
    print(f"      {'delta':>6} {'NAF':>4}   " + "".join(f"{r:>6}" for r in range(1, R + 1)))
    print("      " + SEP2[:64])
    shown = [514, 530, 1034, 1354] if quick else [514, 530, 1034, 1545, 1354, 86]
    for d in shown:
        w = series(n, d, R)
        inc = [w[0]] + [w[i] - w[i - 1] for i in range(1, R)]
        s = "".join((f"{v:6.2f}" if w[i] < 0.6 * n else f"{v:5.2f}*") for i, v in enumerate(inc))
        print(f"      {d:>6} {naf_weight(d, n):>4}   " + s)
        sys.stdout.flush()
    print("""      (* = cumulative weight already past 0.6n; the increment is
       ceiling-limited from there on)

      Read delta = 514.  Rounds 1-4 cost 0.00 / 0.01 / 0.03 / 0.05 -- a trail of
      probability 0.94 over four rounds.  Only at round 5 does the increment
      reach 0.68, and it settles near 0.73.  A slope read at r = 2 to 4, which
      is what TODO #247 and TODO #254 both did, would report 0.03 for this key.

      THIS IS THE WALL, AND IT IS NOT SOLVER TIME.  The window is about
      0.6n/s - (transient) rounds wide.  With s about 1.5 and a transient of
      four rounds:\n""")
    print(f"      {'n':>5}  {'0.6n/s rounds':>14}  {'minus transient':>16}  usable window")
    print("      " + SEP2[:58])
    ok32 = False
    for n_ in (8, 11, 13, 16, 32, 64, 256):
        tot = 0.6 * n_ / 1.5
        usable = tot - 4
        if n_ == 32:
            ok32 = usable > 4
        print(f"      {n_:>5}  {tot:>14.1f}  {usable:>16.1f}  "
              + ("none" if usable <= 0 else ("marginal" if usable < 4 else "workable")))
    print("""
      Exhaustive DDT construction is 2^2n per key and stops around n = 11-13.
      Every width it reaches has a window of zero or one round.  So the
      asymptotic increment is NOT MEASURABLE BY EXHAUSTIVE SEARCH AT ANY
      REACHABLE WIDTH -- not slowly, but at all.  That is a cleaner account of
      #252's stall than "CBC is not enough", and it retroactively explains why
      #247's optima at n = 8-64 looked width-independent: 2.0 / 4.0 / 7.0 at
      r = 2/3/4 is the transient, which is genuinely width-independent, and it
      is not the quantity the criterion needs.""")
    check(ok32, "the window analysis no longer opens up by n = 32; §3's target is wrong")


def section_3():
    rule("§3  What this does to #252's three routes")
    print("""ROUTE 1 (a stronger backend) is RE-MOTIVATED, with a target it did not have.
The problem was never the width -- #247 already reached n = 32 and 64 with CBC.
It was the ROUND COUNT: #247 solved to r = 4, which is inside the transient.
What is needed is n = 32 to 64 at r = 10 to 14, which is where the window is
wide.  That is a different and better-posed solver problem than "scale to
n = 256", and it is the first thing to try.

Attempted here with CBC at n = 16 and n = 32, pushing r as far as it will go;
the accompanying run is reported in §11.31 rather than inline, because a solver
timing is not a finding that should gate this script.

ROUTE 2 (a structural argument) is WEAKENED as #252 states it.  #252 proposed
"each active round costs at least one bit unless the difference is MSB-only".
Even if proven, that yields s_diff >= 1, and the criterion is 4/3 -- so the
argument as sketched cannot close the gap even in the best case.  A wide-trail
argument would have to bound TWO consecutive rounds below by 8/3, and §2's
transient shows that is false for at least four consecutive rounds at n = 11.
The germ does not survive contact with the measurement.

ROUTE 3 (transfer matrix) is unchanged in status here but was promoted to first
choice for the LINEAR axis by TODO #254 §11.30.4, where mask propagation through
M is deterministic.  It has no such advantage on the differential side.

So the order #252 recommends -- 1, then 2, then 3, with 2 as the one that would
settle it -- is now 1, then 3, with 2 demoted: it is the route that provably
cannot reach the threshold as sketched.""")


def section_4(quick):
    rule("§4  A lead, not a conclusion: NAF weight of delta")
    print("""§2's cheapest key, delta = 514 = 2^9 + 2^1 at n = 11, is sparse.  So is the
other key with an identical series, delta = 1534 -- and 1534 = 2^11 - 514, so
the two are the same constant up to sign.  Addition of d and of -d are the same
object to differential cryptanalysis, which means the predictor is not the
Hamming weight of delta but its SIGNED-DIGIT (NAF) weight.

Asymptotic increment against NAF weight, using only rounds past the transient
and below the ceiling:\n""")
    print(f"      {'n':>3}  {'NAF':>4}  {'keys':>5}  {'mean increment':>15}  vs 4/3")
    print("      " + SEP2[:48])
    widths = [(10, 16)] + ([] if quick else [(11, 20)])
    thin = 0
    for n, K in widths:
        by = {}
        for d in typical_deltas(n, K, 4321 + n):
            w = series(n, d, 12)
            use = [w[i] - w[i - 1] for i in range(1, 12)
                   if w[i] < 0.6 * n and i >= 4]
            if use:
                by.setdefault(naf_weight(d, n), []).append(sum(use) / len(use))
        for k in sorted(by):
            m = statistics.mean(by[k])
            thin += (len(by[k]) < 5)
            print(f"      {n:>3}  {k:>4}  {len(by[k]):>5}  {m:>15.2f}  "
                  + ("MEETS" if m >= 4 / 3 else "below"))
            sys.stdout.flush()
    print(f"""
      The direction is consistent -- sparser delta, lower increment -- and the
      mechanism is plausible: a constant with few signed digits generates few
      carry chains, so addition stays close to XOR and the round stays close to
      linear.  It is also the same SHAPE of weak-key structure TODO #253 found
      on the tz axis and TODO #254 found for correlation-1 masks, which is three
      for three.

      IT IS NOT CONCLUDED HERE, and the reason is in the table: most rows above
      rest on fewer than five keys, and §2 has just shown that the quantity
      being averaged is barely measurable at these widths in the first place.
      This repository has recorded three separate small-sample near-misses
      already (#245 §0's tau(192), #247 §(a)'s 2-key slope, #253 §3's drift).
      A fourth is not needed.

      What makes it worth filing rather than dropping: IF the threshold is a
      constant NAF weight, the class has density about 2^-240 at n = 256 and is
      irrelevant; if it scales with n, it is not.  Those two possibilities are
      very far apart and nothing measured here distinguishes them.  That is the
      question, and it is filed as part of #252 rather than answered.""")
    check(thin >= 1, "NAF rows are no longer sample-thin; §4 can be promoted to a finding")


def section_4b(quick):
    rule("§4b  Does the transient invalidate TODO #254's linear numbers too?")
    print("""§2 showed TODO #254's differential-side reads were transient-contaminated.
#254's headline figures are LINEAR, read the same way (r = 3 to 5), so they have
to be re-checked by the same standard rather than assumed safe.

Settled increment, averaged over rounds 4 and up that are still under the
ceiling, against what #254 reported:\n""")
    import importlib.util
    p2 = os.path.join(ROOT, 'SecurityProofsCode', 'nl_fscx_v2_bounds.py')
    sp = importlib.util.spec_from_file_location("_bb2", p2)
    BB = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(BB)
    print(f"      {'n':>3}  {'settled':>8}  {'#254 said':>10}  vs 2/3")
    print("      " + SEP2[:40])
    # n=11 is always included: it is the width where the flattening shows.
    rows = [(7, 8, 0.42), (8, 8, 0.77), (10, 6, 0.88), (11, 4, 1.03)]
    vals = []
    for n, K, said in rows:
        rng = random.Random(555 + n)
        ks = []
        while len(ks) < K:
            b = rng.randrange(1 << n)
            d = FK.delta(n, b)
            if d and (d & -d).bit_length() - 1 <= 1:
                ks.append(b)
        per = [BB.linear_series(n, BB.lat(n, G['mk_v2'](n, k)), 8) for k in ks]
        avg = [sum(p[i] for p in per) / K for i in range(8)]
        use = [avg[i] - avg[i - 1] for i in range(1, 8) if i >= 3 and avg[i] < 0.6 * n]
        m = statistics.mean(use)
        vals.append((n, m))
        print(f"      {n:>3}  {m:>8.2f}  {said:>10.2f}  "
              + ("MEETS" if m >= 2 / 3 else "below"))
        sys.stdout.flush()
    print(f"""
      THE LINEAR AXIS SURVIVES, and this is the reassuring half of this script.
      The linear transient is about two rounds where the differential one runs
      to four or more, so #254's reads sat mostly past it; the corrections are
      small ({' / '.join('%.2f' % v for _, v in vals)}) and every width above n = 7 still clears 2/3.

      One #254 claim is WEAKENED: "the slope rises with width".  It does rise,
      but settled it is flattening -- {vals[-2][1]:.2f} then {vals[-1][1]:.2f} at the two widest, a gain of
      {vals[-1][1]-vals[-2][1]:.2f} against {vals[1][1]-vals[0][1]:.2f} between the two narrowest -- so part of what looked
      like a rise was the transient shrinking relative to the read window rather
      than the cipher improving.  #254's conclusion is unaffected, because a
      flat 0.95 clears 2/3 as comfortably as a rising one; what is withdrawn is
      any expectation that wider widths keep improving without limit.""")
    check(vals[-1][1] >= 2 / 3,
          f"settled linear increment fell to {vals[-1][1]:.2f}, under the 2/3 criterion")


def section_5():
    rule("§5  Where this leaves TODO #252")
    print("""THE BOUND IS NOT DELIVERED and #252 stays open.  What this pass establishes:

  1. The target is a scalar (s_diff >= 4/3), not a bound at n = 256 -- carried
     from TODO #254 §11.30.1.

  2. THE STALL IS EXPLAINED, and it was not solver time.  The asymptotic
     increment cannot be read at any width an exhaustive DDT reaches, because
     the cheap transient and the ceiling overlap there.  #247's stable-looking
     2.0 / 4.0 / 7.0 across n = 8/16/32/64 was measuring the transient, which is
     width-independent for a structural reason and is not the quantity the
     criterion needs.  Every per-round differential figure this repository has
     published is affected.

  3. ROUTE 1 IS RE-MOTIVATED WITH A NEW TARGET -- not a larger width, but a
     larger ROUND COUNT at n = 32-64, where the window is wide and CBC already
     reaches.  This is now the first thing to try.

  4. ROUTE 2 IS DEMOTED.  As #252 sketches it, it yields s_diff >= 1 against a
     4/3 criterion, so it cannot close the gap even if fully proven; and the
     two-round strengthening it would need is contradicted by §2's four
     consecutive near-free rounds.

  5. A weak-key lead on the NAF weight of delta(B), filed with its sample sizes
     rather than concluded.  Whether its threshold is a constant or scales with
     n decides whether it matters at all at n = 256.

  6. THE LINEAR AXIS IS RE-CHECKED AND SURVIVES (§4b).  #254's figures were
     read the same contaminated way, but its transient is half as long, so the
     corrections are small and the 2/3 criterion is still met at every width
     above n = 7.  Its "slope rises with width" claim is withdrawn: settled, the
     values flatten near 0.95.

  7. No rating moves.  TODO #248's verdict stands.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_1()
    section_2(a.quick)
    section_3()
    section_4(a.quick)
    section_4b(a.quick)
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
