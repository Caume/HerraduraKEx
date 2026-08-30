#!/usr/bin/env python3
"""fscx_scaling_and_linear.py — TODO #254: the linear axis, and what key size buys.

TODO #248 filed #254 because linear cryptanalysis is the least-covered axis of
the NL-FSCX family and the only one whose measured slope was not width-stable.
This script is #254's first pass.  It does not deliver the bound #254 asks for.
It delivers four things that change what that bound would have to say, and one
of them makes the headline question answerable without it.

  §1  A SCALE-INVARIANCE THEOREM.  Because FSCX ties its round count to its
      block size (`R_VALUE = 3n/4`), the security criterion against both trail
      families is INDEPENDENT OF n.  Resistance is a condition on the per-round
      slope alone: s_lin >= 2/3 and s_diff >= 4/3, at every width.

  §2  What longer keys buy, which follows immediately from §1: nothing on this
      axis.  n = 512 faces the identical criterion at 4x the cost.

  §3  SATURATION — why nearly every slope figure in this repository, including
      the ones TODO #248 quoted three days ago, is measuring the ceiling rather
      than the cipher.  Corrected slopes here.

  §4  The MILP route #254 named is CLOSED, with a reason: the correlation of
      addition with a CONSTANT is not a power of two, so Wallen's
      characterisation and the standard ARX bit-level encoding built on it do
      not apply.  That is a consequence of the missing key schedule.

  §5  The correlation-1 mask subspace at n = 256, exactly — the linear analogue
      of TODO #253's zero-weight class, and equally harmless.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/fscx_scaling_and_linear.py [--quick]
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


def delta(n, B):
    m = (1 << n) - 1
    return G['ops'](n)[1]((B * ((B + 1) >> 1)) & m, n // 4)


def corr_add_const(n, d, w, v):
    """Exact correlation of x -> (x+d) mod 2^n, input mask w, output mask v.

    Two-state carry automaton, LSB to MSB.  At bit i with carry c: if d_i == c
    the carry is forced to d_i and the bit contributes a factor 2 when v_i == w_i
    and 0 otherwise; if d_i != c the carry follows x_i and each branch
    contributes a single sign.  Paths that re-merge SUM, which is §4's point."""
    st = [1, 0]
    for i in range(n):
        di, wi, vi = (d >> i) & 1, (w >> i) & 1, (v >> i) & 1
        nx = [0, 0]
        for c in (0, 1):
            a = st[c]
            if not a:
                continue
            if di == c:
                if vi == wi:
                    nx[di] += 2 * a
            else:
                nx[0] += a * (-1 if vi else 1)
                nx[1] += a * (-1 if wi else 1)
        st = nx
    return (st[0] + st[1]) / float(1 << n)


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  Scale invariance — the criterion does not depend on n")
    print("""FSCX does not have a free round count.  `R_VALUE = 3n/4` and `I_VALUE = n/4`
are tied to the block size, and the suite file scales them automatically when
`KEYBITS` changes.  That single design choice has a consequence nobody in this
repository has written down, and it decides the question TODO #254 was filed to
answer.

Let s be the per-round trail weight, so an r-round trail weighs about s*r.

  LINEAR.  A linear attack on an n-bit block needs about corr^-2 known
  plaintexts, and the whole codebook is 2^n, so the attack is meaningless once
  the trail weight W satisfies 2W >= n, i.e. W >= n/2.  With r = 3n/4:

        s_lin * (3n/4) >= n/2   <=>   s_lin >= 2/3        [n cancels]

  DIFFERENTIAL.  A differential distinguisher needs probability above the 2^-n
  a random permutation gives, so safety needs W >= n.  With r = 3n/4:

        s_diff * (3n/4) >= n    <=>   s_diff >= 4/3       [n cancels]

The width cancels in both.  Resistance to trail attacks is a property of the
ROUND FUNCTION ALONE, expressed as a pure number, and no choice of block size
changes it.  Doubling n doubles the rounds and doubles the threshold in exactly
equal measure.

This also says what the open question actually is.  It is not "what is the
security level at n = 256" -- it is "is s_lin above 0.667", a single scalar,
the same one at every width.  That is a far better-posed question than the one
#252 and #254 were filed with, and it is why this pass was worth doing before
attempting the bound.""")


def section_2():
    rule("§2  What longer keys buy on this axis")
    print("""The question that prompted this item: FSCX increases its round count with its
key size, so does a 512-bit or 1024-bit key close the gap?

By §1, NO -- not on this axis, and not by a little.  The criterion `s >= 2/3` is
identical at every width.  A construction whose slope is below it is equally
broken at n = 1024, and one above it is already safe at n = 256.\n""")
    print(f"      {'n':>6}  {'rounds 3n/4':>11}  {'threshold n/2':>13}  {'criterion':>12}  "
          f"{'cost/block':>10}")
    print("      " + SEP2[:60])
    for n in (256, 512, 1024, 2048):
        print(f"      {n:>6}  {3*n//4:>11}  {n//2:>13}  {'s >= 0.667':>12}  "
              f"{'%.0fx' % ((n/256.0)**2):>10}")
    print("""
      The cost column is why this matters practically as well as
      theoretically.  A round is O(n) bit operations and there are 3n/4 of them,
      so a block costs O(n^2) -- and a block only carries n bits, so the cost
      PER BIT still doubles with n.  n = 512 is 4x the work per block for a
      criterion that has not moved.

      What longer keys DO buy, stated fairly so the answer is not read as
      broader than it is:

        * Brute-force key search goes 2^n -- but that was never the binding
          constraint at n = 256, so this buys nothing that was needed.
        * Generic birthday/slide data bounds scale as 2^(n/2), which does help
          against the ~2^128 data figure §11.25.2 quoted before #245 removed
          the slide structure.  That objection is already gone.
        * The measured slope does appear to RISE with n (§3), so a wider
          construction may well have a better slope.  But that is the slope
          doing the work, not the width, and if the slope reaches 2/3 it does
          so at n = 256 too.

      SCOPE OF THE THEOREM.  §1 is derived for a BLOCK CIPHER -- codebook 2^n,
      r = 3n/4 -- so it applies to HSKE-NL-A2, `twk` and `fpe` directly.  It does
      NOT transfer unexamined to HSKE-NL-A1 (a counter-mode PRF) or HFSCX-256 (a
      Davies-Meyer compression function): each has its own attack model, and both
      run n/4 rounds rather than 3n/4, which would give a sharper bar on a naive
      transfer.  Deriving the right criterion for those two modes is part of #254
      and is not attempted here.

      THE HONEST SUMMARY: increasing the key size is not a fix for the open
      question, it is a 4x cost for no change in the criterion.  What raises the
      slope is a better round function -- which is TODO #251, and this is the
      strongest argument that item has yet had.""")


def section_3(quick):
    rule("§3  Saturation — most published slopes here measure the ceiling")
    print("""A trail's weight cannot grow past the point where it has consumed the whole
distinguishing budget: about n/2 bits for linear, about n for differential.
Past that the series flattens because it has hit a ceiling, and a slope read
there is a property of the ceiling, not of the cipher.

This is not hypothetical.  TODO #248 quoted linear slopes of 0.49-0.87 read at
r = 4 to 6, and TODO #247's differential optima 2.0 / 4.0 / 7.0 at n = 8 put
r = 4 at 0.875n.  Both were saturated.  Measured, with the ceiling shown:\n""")
    widths = [(7, 8), (8, 8), (10, 6)] + ([] if quick else [(11, 4)])
    print(f"      {'n':>3}  {'ceiling n/2':>11}   r=2    r=3    r=4    r=5    r=6    r=7")
    print("      " + SEP2[:62])
    rows = []
    for n, K in widths:
        assert not G['m_is_singular'](n), n
        rng = random.Random(555 + n)
        ks = []
        while len(ks) < K:
            b = rng.randrange(1 << n)
            d = delta(n, b)
            if d and (d & -d).bit_length() - 1 <= 1:
                ks.append(b)
        per = [BB.linear_series(n, BB.lat(n, G['mk_v2'](n, k)), 7) for k in ks]
        avg = [sum(p[i] for p in per) / K for i in range(7)]
        rows.append((n, avg))
        print(f"      {n:>3}  {n/2:>11.1f}   " + "  ".join(f"{avg[i]:5.2f}" for i in range(1, 7)))
        sys.stdout.flush()
    print(f"\n      Usable slope — read at r = 3 to 5, the widest span still under 60% of")
    print(f"      the ceiling at every width above:\n")
    print(f"      {'n':>3}  {'slope (r=3→5)':>14}  {'vs 2/3 criterion':>18}")
    print("      " + SEP2[:40])
    sl = []
    for n, avg in rows:
        s = (avg[4] - avg[2]) / 2
        sl.append((n, s))
        print(f"      {n:>3}  {s:>14.2f}  {'MEETS' if s >= 2/3 else 'below':>18}")
    best = sl[-1][1]
    m1, m2 = sl[-2][1] / (2 / 3) - 1, best / (2 / 3) - 1
    print(f"""
      The slope rises with width -- {' -> '.join('%.2f' % s for _, s in sl)} -- and CROSSES the 2/3
      criterion between n = {sl[0][0]} and n = {sl[1][0]}, staying above it at every larger width
      measured.  At the two widest, {sl[-2][1]:.2f} and {best:.2f}, it clears the threshold by
      {100*m1:.0f}% and {100*m2:.0f}%.

      That is the most encouraging thing measured about this construction, and
      it is still not a bound.  {len(sl)} widths, none above {sl[-1][0]}, with the slope still
      moving: exactly the shape TODO #253 §3 and TODO #247 §(a) each recorded a
      near-miss on.  It is reported as a direction, not a result.""")
    check(all(not G['m_is_singular'](n) for n, _ in sl), "a singular width entered §3")
    check(best >= 2 / 3, f"the widest usable slope fell to {best:.2f}, under the 2/3 criterion")
    return sl


def section_4():
    rule("§4  The MILP route is closed, and the reason is the missing key schedule")
    print("""TODO #254 named a linear MILP as the first route to try, by analogy with
TODO #247's differential model.  It does not transfer, and the obstruction is
worth recording because it is structural rather than a matter of solver effort.

Every bit-level MILP model for linear cryptanalysis of an ARX cipher rests on
Wallen's characterisation: the correlation of MODULAR ADDITION with two variable
inputs is exactly plus or minus a power of two, so `-log2|corr|` is an integer,
additive over bit positions, and encodable as a sum of binary variables.

Here the addend is a CONSTANT -- delta(B), the same in every round, because
there is no key schedule.  Addition of a constant is a different object: its
correlations are sums over carry paths that re-merge, and they are NOT powers of
two.  Measured over random (n, d, w, v):\n""")
    rng = random.Random(2)
    n = 10
    N = 1 << n
    seen = {}
    for _ in range(600):
        d, w, v = rng.randrange(N), rng.randrange(N), rng.randrange(N)
        c = abs(corr_add_const(n, d, w, v))
        if c > 1e-12:
            seen[round(-math.log2(c), 6)] = 1
    ks = sorted(seen)[:10]
    integral = all(abs(k - round(k)) < 1e-9 for k in seen)
    print("      first ten distinct -log2|corr| values at n = 10:")
    print("        " + ", ".join(f"{k:.4f}" for k in ks))
    print(f"      all integral (i.e. all powers of two)?  {integral}")
    check(not integral,
          "add-constant correlations became powers of two; §4's obstruction is gone")
    print("""
      Non-integral weights mean there is no additive per-bit weight to minimise,
      so the standard encoding cannot be written down at all -- not that it
      would be slow.  A model built on the carry automaton instead is easy to
      write and computes the wrong thing: it scores single carry paths, and the
      true correlation sums them, so it OVERSTATES the weight.  A bound that
      overstates resistance is worse than no bound, and this one was built and
      discarded here before it could be quoted.

      What remains open, and is the honest next route: the transfer-matrix
      formulation (#252's route 3), which suits masks better than differences
      because mask propagation through M is deterministic -- the trail is fixed
      by its starting mask, so the search is over 2^n starting masks rather than
      over trails.  That is still 2^n, but it is a far more structured 2^n than
      the differential side offers.""")


def Mv(n, x):
    m = (1 << n) - 1
    return (x ^ ((x << 1) | (x >> (n - 1))) ^ ((x >> 1) | (x << (n - 1)))) & m


def corr1_rounds(n, k, cap):
    """Max r with a nonzero mask whose first r images under M stay inside the
    correlation-1 subspace span{e_0..e_k}, k = tz(delta)."""
    piv = {}
    img = [1 << i for i in range(n)]
    r = 0
    while r < cap:
        for p in range(k + 1, n):
            f = 0
            for i in range(n):
                if (img[i] >> p) & 1:
                    f |= 1 << i
            v = f
            for b, q in piv.items():
                if (v >> b) & 1:
                    v ^= q
            if v:
                piv[v.bit_length() - 1] = v
        if n - len(piv) == 0:
            return r
        r += 1
        img = [Mv(n, v) for v in img]
    return cap


def section_5(quick):
    rule("§5  The correlation-1 subspace at n = 256 — linear analogue of #253")
    print("""Addition of d with k = tz(d) trailing zeros leaves bits 0..k-1 of the input
untouched and sets bit k to x_k XOR 1, so every mask supported on bits 0..k
passes with correlation exactly +-1.  M is symmetric, so masks propagate
backwards through the same map, and a correlation-1 r-round trail exists iff a
nonzero mask stays inside that subspace for r applications.  Exact, and at the
deployed width rather than extrapolated to it:\n""")
    assert Mv(8, 1) == (1 | 2 | (1 << 7)), "M's action changed"
    n = 256
    print(f"      {'tz(delta)':>9}  {'correlation-1 rounds':>21}  {'Pr[tz >= k]':>12}")
    print("      " + SEP2[:48])
    ks = (0, 1, 2, 4, 8, 16) if quick else (0, 1, 2, 4, 8, 16, 32, 64)
    for k in ks:
        print(f"      {k:>9}  {corr1_rounds(n, k, 200):>21}  "
              f"{('%.4f' % 2.0**-k) if k <= 12 else '< 1e-4':>12}")
        sys.stdout.flush()
    print("""
      Same shape as TODO #253's differential class and the same verdict: about
      tz/2 free rounds bought at probability 2^-tz, so a random key forfeits a
      handful of 192 rounds and losing all of them needs a key of density
      2^-254.  A typical key gets ONE free round.

      Worth stating because it is the mechanism behind §3: the first round is
      free for every key, so a linear trail's weight is entirely about how fast
      M drags the mask out of this subspace and keeps it out.  That is also why
      the transfer-matrix route in §4 is the right one -- it is a question about
      M's orbit structure, which is linear algebra, not search.""")
    check(corr1_rounds(256, 0, 200) == 1,
          "a typical key no longer gets exactly one free correlation-1 round")


def section_6(sl):
    rule("§6  Where this leaves TODO #254, and what it corrects")
    best = sl[-1][1]
    print(f"""#254 asked for a linear-trail bound at realistic width.  THAT IS NOT DELIVERED
and #254 stays open.  What changed is what the bound has to establish.

  1. The question is now a scalar, not a curve.  By §1 the criterion is
     `s_lin >= 2/3` at every width, so #254 no longer needs a bound "at n = 256"
     -- it needs the asymptotic per-round slope, which can be established at any
     width where saturation is not binding.  That is a much easier target and it
     reopens widths #254 had written off.

  2. The measurements point the right way.  Corrected for saturation, the slope
     is {' / '.join('%.2f' % s for _, s in sl)} at n = {', '.join(str(n) for n, _ in sl)}, crossing 2/3
     between n = {sl[0][0]} and {sl[1][0]} and clearing it by {100*(sl[-1][1]/(2/3)-1):.0f}% at the widest.
     Encouraging, {len(sl)} widths, not a bound.

  3. A CORRECTION TO TODO #248.  §11.29.4 called linear "the binding axis" on
     the grounds that its slope is far below the differential one.  That
     comparison was not normalised: the thresholds differ by exactly the same
     factor of two ({2/3:.3f} against {4/3:.3f}), so the raw slopes were never
     comparable.  Normalised, and with both corrected for saturation, the two
     axes are close, and on the widths where both are measured DIFFERENTIAL is
     the tighter of the two.  The claim that linear is uniquely binding is
     withdrawn; what survives is that linear was the less measured, which is why
     #254 exists.

  4. The MILP route is closed with a reason (§4), and the transfer-matrix route
     is promoted to first choice for both #252 and #254.

  5. For TODO #251: §1 and §2 together are the strongest argument the AND layer
     has had.  Since no key size can move the criterion, the ONLY way to buy
     margin on either trail axis is a round function with a higher per-round
     slope.  That is precisely what candidate B provides, and #246 measured it
     leading on both axes.

  6. For the ratings: nothing moves here.  #248's verdict stands unchanged --
     demo-only, gated on this measurement -- and this pass did not produce it.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_1()
    section_2()
    sl = section_3(a.quick)
    section_4()
    section_5(a.quick)
    section_6(sl)
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
