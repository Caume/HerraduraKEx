#!/usr/bin/env python3
"""nl_fscx_v3_weak_keys.py — TODO #255: does NL-FSCX v3 need a key check?

TODO #255 cannot fix v3's public API until this is answered: v2 ships
`nl_v2_key_is_valid`, and the item asks whether v3 needs an
`nl_v3_key_is_valid` beside it.  The entry names two inherited classes to
re-derive and one new one to look for.

The answer is NO -- v3 needs no key check -- and it is a proof rather than a
sample, because of a reduction the v2 analysis never had available.

  §1  THE REDUCTION.  The v3 round's key-dependence collapses to delta(B), and
      chi's row-locality makes the per-row profile EXACT AT ANY WIDTH.  A
      256-bit statement is a 2^5 and 2^7 computation.
  §2  The linear axis, exhaustively.  L = 3 admits correlation 1 -- the
      §11.33.4 break, now with its mechanism.  L = 5 -> 0.875, L = 7 -> 0.71875,
      for EVERY key at EVERY width.
  §3  The differential axis, exhaustively, plus the LOWEST-ACTIVE-ROW LEMMA
      that repairs the floor: s_diff = 4 - log2(5) = 1.6781 bits, exactly.
  §4  The two inherited v2 classes, verified dissolved rather than assumed.
  §5  Is there a NEW chi-specific class?  On the differential axis the profile
      is key-INDEPENDENT, so there is nothing to stratify.  On the linear axis
      it is graded by delta, but at n = 256 essentially every key attains the
      worst grade, so the class is everybody and screening is not available.
  §6  CONSEQUENCE FOR THE ROUND COUNT.  §11.33.2's caveat, closed with a
      number.  R3_VALUE = 160 still clears the differential criterion, but at
      1.05x, not the 1.25x §11.33.6 recorded.
  §7  Verdict, and the API decision it settles.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/nl_fscx_v3_weak_keys.py [--quick]
"""

import argparse
import math
import sys
from collections import Counter

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []

# The deployed partition: 256 = 47*5 + 3*7.  Row lengths actually used.
V3_ROW_LENGTHS = (5, 7)
R3_VALUE_256 = 160          # 5n/8 at n = 256, derived in TODO #255 / §11.33.6


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


def w(p):
    return -math.log2(p) if p > 0 else float('inf')


def fwht(a):
    h = 1
    while h < len(a):
        for i in range(0, len(a), h * 2):
            for j in range(i, i + h):
                x, y = a[j], a[j + h]
                a[j], a[j + h] = x + y, x - y
        h *= 2


def chi_row(x, L):
    """Keccak chi on one row of length L."""
    b = [(x >> i) & 1 for i in range(L)]
    o = 0
    for i in range(L):
        o |= (b[i] ^ ((1 - b[(i + 1) % L]) & b[(i + 2) % L])) << i
    return o


# ── §2/§3 exact row kernels ─────────────────────────────────────────────────
def row_linear(L):
    """Exhaustive max |correlation| of one chi row fed by (y + delta + carry).

    Returns (overall_max, {carry: {delta_row: max|corr|}}).
    """
    N = 1 << L
    per = {0: {}, 1: {}}
    overall = 0.0
    for c in (0, 1):
        for d in range(N):
            T = [chi_row((y + d + c) % N, L) for y in range(N)]
            best = 0.0
            for v in range(1, N):
                par = [1 if not (bin(v & T[y]).count('1') & 1) else -1
                       for y in range(N)]
                fwht(par)
                best = max(best, max(abs(z) for z in par) / N)
            per[c][d] = best
            overall = max(overall, best)
    return overall, per


def row_differential(L):
    """Exhaustive max DDT probability of one chi row fed by (y + delta + carry),
    split by whether the two inputs of the pair share a carry-in.

    Returns (max_same_carry, max_differing_carry).
    """
    N = 1 << L
    same = diff = 0.0
    for d in range(N):
        tab = {c: [chi_row((y + d + c) % N, L) for y in range(N)] for c in (0, 1)}
        for c in (0, 1):
            for c2 in (0, 1):
                A, Bt = tab[c], tab[c2]
                for be in range(1, N):
                    m = max(Counter(A[y] ^ Bt[y ^ be]
                                    for y in range(N)).values()) / N
                    if c == c2:
                        same = max(same, m)
                    else:
                        diff = max(diff, m)
    return same, diff


# ── the round itself, at a small legal width, for §4 and §6 ─────────────────
class Width:
    """The v3 round at width n with a given row partition."""

    def __init__(self, n, rows):
        assert sum(rows) == n and all(L % 2 for L in rows)
        self.n, self.rows, self.N, self.M = n, rows, 1 << n, (1 << n) - 1

    def rol(self, x, k):
        return ((x << k) | (x >> (self.n - k))) & self.M

    def ror(self, x, k):
        return ((x >> k) | (x << (self.n - k))) & self.M

    def delta(self, B):
        return self.rol((B * ((B + 1) >> 1)) & self.M, self.n // 4)

    def chi(self, x):
        out, off = 0, 0
        for L in self.rows:
            b = [(x >> (off + i)) & 1 for i in range(L)]
            for i in range(L):
                out |= (b[i] ^ ((1 - b[(i + 1) % L]) & b[(i + 2) % L])) << (off + i)
            off += L
        return out

    def v2_table(self, B):
        d = self.delta(B)
        return [(((x ^ B) ^ self.rol(x ^ B, 1) ^ self.ror(x ^ B, 1)) + d) & self.M
                for x in range(self.N)]

    def v3_table(self, B):
        return [self.chi(v) for v in self.v2_table(B)]

    def is_affine(self, T):
        c = T[0]
        for a in range(self.N):
            Ta = T[a] ^ c
            for b in range(a, self.N):
                if T[a ^ b] ^ c != Ta ^ (T[b] ^ c):
                    return False
        return True

    def max_ddt(self, T):
        return max(max(Counter(T[x] ^ T[x ^ a] for x in range(self.N)).values())
                   for a in range(1, self.N)) / self.N


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true',
                    help='skip the L = 7 sweeps and the multi-round DP')
    ap.add_argument('--long', action='store_true',
                    help='also sweep L = 9, past the deployed row lengths (slow, '
                         'a few minutes).  L = 11 is ~16x that again in pure '
                         'Python and is not included; it was measured once by '
                         'the same code at |corr| = 0.693359 (weight 0.5282).')
    args = ap.parse_args()

    print(SEP)
    print("NL-FSCX v3 weak keys — TODO #255")
    print(SEP)

    # ── §1 ──────────────────────────────────────────────────────────────────
    rule("§1  The reduction: a 256-bit question that is a 2^5 computation")
    print("""
The v3 round is  x -> chi( M(x ^ i ^ B) + delta(B) mod 2^n ).  Two structural
facts collapse it:

  (a) M is invertible and  y -> y + delta  is a bijection, so substituting
      y = M(x ^ i ^ B) is measure-preserving.  Every differential and linear
      property of the round is a property of  g_delta(y) = chi(y + delta)
      ALONE.  The key enters only as delta -- B, i and M drop out entirely.

  (b) chi is row-local, and the low L bits of  y + delta  depend only on the
      low L bits of y and delta plus a one-bit carry-in.  So the profile of
      the row at offset `off` is an exhaustive computation over 2^L inputs,
      2^L row-deltas and 2 carries -- INDEPENDENT OF n.

Together: an exhaustive statement about every 256-bit key is a sweep over
L = 5 and L = 7.  This is the lever the v2 analysis never had; v2's round has
no row structure, which is why TODO #253 had to extrapolate from n <= 11.

Carry bookkeeping is charged conservatively throughout.  For a linear mask,
the carry-in c is a function of y, so |corr| <= max_c |corr(c)|; for a
differential, the pair's two carry-ins may differ, so p <= max_{c,c'} p(c,c').
Both bound the true quantity in the safe direction (weight can only be higher
than reported), so every floor below is sound.""")

    # ── §2 ──────────────────────────────────────────────────────────────────
    rule("§2  The linear axis, exhaustively")
    Ls = (3, 5) if args.quick else ((3, 5, 7, 9) if args.long else (3, 5, 7))
    lin = {}
    print("\n  L   max |corr|   weight    corr-1 cases     status")
    print("  " + SEP2[:66])
    for L in Ls:
        overall, per = row_linear(L)
        lin[L] = (overall, per)
        ones = sum(1 for c in per for d in per[c] if per[c][d] >= 1.0)
        tag = "DEGENERATE" if overall >= 1.0 else "ok"
        print("  %-3d %10.6f  %8.4f   %4d            %s"
              % (L, overall, w(overall), ones, tag))

    check(lin[3][0] >= 1.0,
          "L=3 no longer admits a correlation-1 approximation (§11.33.4)")
    check(abs(lin[5][0] - 0.875) < 1e-12, "L=5 single-row max |corr| != 0.875")
    if 7 in lin:
        check(abs(lin[7][0] - 0.71875) < 1e-12,
              "L=7 single-row max |corr| != 0.71875")

    print("""
  L = 3 is the §11.33.4 break, and the reduction gives it a mechanism: bit 0
  of a sum has no carry-in, so the low bit entering chi is affine in y, and a
  3-row has no room to destroy the resulting correlation.  It is a property of
  the ROW LENGTH, not of the key -- which is why the fix is the minimum-row-5
  constraint and not a key check.

  L = 5 and L = 7 admit none.  -log2(0.875) = %.4f, which is exactly the
  "worst single round 0.193" §11.33.4 reported from 150 sampled keys.  That
  figure was never a weak-key artefact: it is the universal single-row bound,
  and it is attained.""" % w(0.875))

    if 9 in lin:
        print("""
  The sweep past the deployed lengths says something the deployed ones cannot.
  The weight SATURATES: %.4f at L = 5, %.4f at L = 7, %.4f at L = 9, and it
  never approaches chi's own isolated floor of 1.000.  (L = 11 is ~16x L = 9's
  work in pure Python and is left out of this sweep; measured once by this same
  code it gives 0.693359, weight 0.5282 -- another 0.004 bits.)

  So it is the CARRY, not the row length, that caps this axis.  The gain from 5
  to 7 is real and is why the partition spends its remainder on 7-rows; past 7
  there is essentially nothing left to buy, for rows that no longer divide 256
  conveniently.  "Use longer rows" is not available as a future fix for the
  linear bound.""" % (w(lin[5][0]), w(lin[7][0]), w(lin[9][0])))
        check(w(lin[9][0]) > w(lin[7][0]) and w(lin[9][0]) < 0.60,
              "the single-row linear weight stopped saturating just above L=7")

    d5 = lin[5][1][0]
    hist = Counter("%.4f" % v for v in d5.values())
    print("\n  L = 5, distribution over the 32 row-deltas (carry-in 0):")
    for k in sorted(hist, reverse=True):
        print("      |corr| = %s  (weight %6.4f)  ->  %2d of 32 deltas"
              % (k, w(float(k)), hist[k]))
    print("""
  §11.33.4 sampled a MEDIAN of 0.678, which is not the median of this
  three-point distribution (that is 1.000).  It is the median of the induced
  PER-KEY statistic -- the worst row a key actually has, i.e. the minimum
  weight over its rows -- at the two-row width §11.33.4 measured at.  Deriving
  it from the exact row distribution:""")
    ws = sorted({w(v) for v in d5.values()})
    pr = {x: sum(1 for v in d5.values() if abs(w(v) - x) < 1e-12) / len(d5)
          for x in ws}
    tail = {x: sum(pr[y] for y in ws if y >= x) for x in ws}   # P[row weight >= x]
    per_key = {x: tail[x] ** 2 - sum(pr[y] for y in ws if y > x) ** 2 for x in ws}
    print("\n      per-row  P[w = x]        per-key (2 rows)  P[min = x]")
    for x in ws:
        print("        w = %6.4f  %7.4f              %7.4f" % (x, pr[x], per_key[x]))
    cum, med = 0.0, None
    for x in ws:
        cum += per_key[x]
        if med is None and cum >= 0.5:
            med = x
    print("      median of the per-key statistic = %.4f" % med)
    check(abs(med - w(0.625)) < 1e-9,
          "the per-key median at two rows != 0.678 (§11.33.4's sampled median)")
    print("""
  0.678 exactly.  §11.33.4's 150-key sample was measuring this three-point row
  distribution all along, through one width's worth of row structure.""")

    # ── §3 ──────────────────────────────────────────────────────────────────
    rule("§3  The differential axis, and the lowest-active-row lemma")
    print("\n  L   same-carry p    weight    differing-carry p   weight")
    print("  " + SEP2[:66])
    dif = {}
    for L in [x for x in Ls if x <= 7]:
        s, dd = row_differential(L)
        dif[L] = (s, dd)
        print("  %-3d %10.6f  %8.4f    %10.6f     %8.4f"
              % (L, s, w(s), dd, w(dd)))

    check(abs(dif[5][0] - 0.3125) < 1e-12, "L=5 same-carry max DDT p != 5/16")
    check(abs(dif[5][1] - 0.5) < 1e-12, "L=5 differing-carry max DDT p != 1/2")
    if 7 in dif:
        check(abs(dif[7][0] - 0.25) < 1e-12, "L=7 same-carry max DDT p != 1/4")

    print("""
  Taken flat, the differing-carry column would give a floor of only 1.000 bit
  -- below §11.33.2's layer-wise 2.000 -- and at s_diff = 1 the §11.30.1
  criterion s_diff * r >= n would demand r >= 256, which R3_VALUE = 160 fails.

  LOWEST-ACTIVE-ROW LEMMA.  It does not apply to the lowest active row.  Let j
  be the lowest row on which the difference beta = M(alpha) is nonzero.  Every
  bit below row j is EQUAL in y and y ^ beta, so those two values have the same
  low part, hence produce the SAME carry into row j.  The lowest active row is
  therefore always in the same-carry column -- and there is always at least one
  active row, because beta != 0 (M is invertible and alpha != 0).

  So the per-round differential floor is the worst SAME-CARRY entry over the
  deployed row lengths -- the 5-rows, which are weaker than the 7-rows and are
  47 of the 50:""")

    # The floor is set by the WORST deployed row length -- the largest
    # same-carry probability, i.e. the smallest weight.
    s_diff = max(dif[L][0] for L in dif if L in V3_ROW_LENGTHS)
    s_diff_w = w(s_diff)
    print("\n      s_diff = -log2(%s) = %.4f bits   (= 4 - log2 5, exactly)"
          % (("5/16" if abs(s_diff - 0.3125) < 1e-12 else "%.5f" % s_diff),
             s_diff_w))
    check(abs(s_diff_w - (4 - math.log2(5))) < 1e-9,
          "s_diff is no longer 4 - log2(5)")
    print("""
  Key-independent: every one of the 32 (resp. 128) row-deltas gives the same
  same-carry maximum.  There is no differential stratification of the key space
  at all -- see §5.""")

    # ── §4 ──────────────────────────────────────────────────────────────────
    rule("§4  The two inherited v2 classes, verified dissolved")
    W = Width(10, (5, 5))     # smallest legal width: both rows >= 5, M invertible
    print("\n  Width n = 10, partition (5,5) — the smallest width whose partition")
    print("  satisfies the minimum-row-5 constraint.\n")

    aff = [B for B in range(W.N) if W.delta(B) in (0, 1 << (W.n - 1))]
    n_aff_v2 = sum(1 for B in aff if W.is_affine(W.v2_table(B)))
    n_aff_v3 = sum(1 for B in aff if W.is_affine(W.v3_table(B)))
    print("  (a) the affine class  delta(B) in {0, 2^(n-1)}  (§11.19.2)")
    print("      keys in class: %d of %d" % (len(aff), W.N))
    print("      v2 round affine for %d of them;  v3 round affine for %d."
          % (n_aff_v2, n_aff_v3))
    check(n_aff_v2 == len(aff), "the v2 affine class stopped being affine")
    check(n_aff_v3 == 0, "some v3 round is affine — the class did NOT dissolve")
    print("""      DISSOLVED, and provably so rather than by measurement: v3's
      round is chi composed with the v2 round, chi is a fixed key-independent
      NON-LINEAR bijection, and chi . (affine) is non-affine whenever chi is.
      No key can make the v3 round affine, at any width.""")

    def tz(v):
        return (v & -v).bit_length() - 1 if v else W.n
    cls = [B for B in range(W.N) if B and tz(W.delta(B)) >= 4]
    p2 = max(W.max_ddt(W.v2_table(B)) for B in cls)
    p3 = max(W.max_ddt(W.v3_table(B)) for B in cls)
    print("\n  (b) the zero-weight-trail class  tz(delta(B)) >= 4  (§11.28.3)")
    print("      keys in class: %d of %d" % (len(cls), W.N))
    print("      worst one-round DDT probability:  v2 = %.5f (w = %.4f)"
          % (p2, w(p2)))
    print("                                        v3 = %.5f (w = %.4f)"
          % (p3, w(p3)))
    check(p2 >= 1.0, "v2's probability-1 one-round differential vanished")
    check(abs(p3 - 0.3125) < 1e-12,
          "v3's worst DDT entry on that class is no longer 5/16")
    print("""      DISSOLVED.  v2 hands this class a probability-1 one-round
      differential -- the MSB freebie.  v3's worst is 5/16, which is exactly
      §3's same-carry L = 5 bound: the class does not merely improve, it lands
      on the universal floor and so is not a class at all.""")

    # ── §5 ──────────────────────────────────────────────────────────────────
    rule("§5  Is there a NEW chi-specific class?")
    p_bad = sum(1 for v in d5.values() if v >= 0.875) / len(d5)
    p_none = (1 - p_bad) ** 47
    print("""
  Differential: no.  §3's same-carry maximum is identical for every row-delta,
  so the differential profile does not depend on the key at all.  A class needs
  a distinguished subset and there is none.

  Linear: graded, but not screenable.  %d of 32 row-deltas reach the worst
  grade |corr| = 0.875, so a single row is "bad" with probability %.4f.  The
  deployed partition has 47 five-rows, and a key's rows see essentially
  unrelated slices of delta(B), so""" % (int(p_bad * 32), p_bad))
    print("      P[a key has NO worst-grade row]  ~  (1 - %.4f)^47  =  %.2e"
          % (p_bad, p_none))
    print("""
  The worst grade is attained by all but about one key in %s.  A "weak class"
  containing everybody is a property of the design, not a key defect, and
  screening for it is not available -- there is nothing to reject.  This is the
  opposite of v2's situation, where the classes were sparse (~2^-129 affine)
  and screening was one comparison.

  The chi-specific class §11.33.4 DID find -- the delta(B)-odd keys -- exists
  only for partitions with a 3-row, and is closed by the minimum-row-5
  constraint rather than by a key check.  §2 confirms it at L = 3 and its
  absence at L = 5 and 7.""" % ("%.0e" % (1 / p_none)))
    check(p_none < 1e-4,
          "the worst linear grade is no longer near-universal at n=256")

    # ── §6 ──────────────────────────────────────────────────────────────────
    rule("§6  Consequence for the round count")
    r_need = 256 / s_diff_w
    print("""
  §11.33.2 states the floor as a LAYER-WISE trail bound -- 2 bits differential,
  1 bit linear -- charged to chi alone, with the caveat that a trail fixes the
  intermediate difference while the round's own DDT entry sums over it.  §3
  closes that caveat with a number: the round-level differential floor is
  4 - log2(5) = %.4f, not 2.000, the gap being clustering across the carry.

  Evaluated on the round-level figure, §11.30.1's differential criterion
  s_diff * r >= n needs""" % s_diff_w)
    print("      r >= 256 / %.4f = %.1f      R3_VALUE = %d clears it, at %.3fx."
          % (s_diff_w, r_need, R3_VALUE_256, R3_VALUE_256 / r_need))
    check(R3_VALUE_256 >= r_need,
          "R3_VALUE = 160 no longer clears the differential criterion")
    print("""
  THE ROUND COUNT STANDS, BUT THE HEADROOM DOES NOT.  §11.33.6 recorded a 1.25x
  margin over an r >= 128 requirement; the requirement is really r >= %.0f and
  the margin is %.2fx.  160 is the right number for a reason narrower than the
  one on record, and there is no room to reduce it.

  The linear axis is unchanged by this script's findings and unchanged in its
  logic: the round-level figure 0.193 would demand r >= 664 if it were a slope,
  and §11.33.5 declined to price it that way because it is not chainable.""" %
          (math.ceil(r_need), R3_VALUE_256 / r_need))

    if not args.quick:
        print("\n  Re-confirming non-chainability with an exact multi-round")
        print("  trail search (max over all mask paths) at n = 10, (5,5):\n")
        NN = W.N
        for B in (0b1011010011, 0b0110101101):
            T = W.v3_table(B)
            C = []
            for v in range(NN):
                par = [1 if not (bin(v & T[x]).count('1') & 1) else -1
                       for x in range(NN)]
                fwht(par)
                C.append([abs(z) / NN for z in par])
            best = [0.0] * NN
            for v in range(1, NN):
                best[v] = max(C[v][1:])
            print("      key = 0x%03x" % B)
            for r in range(1, 7):
                if r > 1:
                    best = [0.0] + [max(C[v][u] * best[u] for u in range(1, NN))
                                    for v in range(1, NN)]
                m = max(best[1:])
                print("        r = %d   |corr| = %.6f   weight = %6.4f   "
                      "slope = %.4f" % (r, m, w(m), w(m) / r))
            check(w(max(best[1:])) / 6 > 2 / 3,
                  "the multi-round linear slope fell below the 2/3 criterion")
        print("""
      The slope rises to ~1.4 bits/round by r = 6, comfortably above the
      s_lin >= 2/3 bar and seven times the single-round figure.  0.193 is a
      transient, not a slope.""")

    # ── §7 ──────────────────────────────────────────────────────────────────
    rule("§7  Verdict")
    print("""
  v3 NEEDS NO KEY CHECK.  There is to be no `nl_v3_key_is_valid` in any of the
  four language ports, and `hske_nl_a3_keygen` and friends must NOT carry v2's
  rejection-sampling loop.

      * the affine class          — dissolved, provably, at every width (§4a)
      * the zero-weight class     — dissolved; v3 has no zero-weight round for
                                    any key, the floor being 5/16 (§3, §4b)
      * a new chi-specific class  — the differential profile is
                                    key-independent (§5); the linear profile is
                                    graded but attains its worst grade for all
                                    but ~1 key in %s, so there is nothing to
                                    screen (§5)
      * the delta(B)-odd class    — real, but a property of 3-rows; closed by
                                    the minimum-row-5 constraint (§2)

  Carrying v2's loop across anyway would be worse than useless: it would reject
  ~2^-129 of keys for a degeneracy v3 does not have, while implying to a reader
  that the remaining keys had been screened for one that it does.

  Owed to §11.33 as corrections (§6): the round-level differential floor is
  4 - log2(5) = %.4f rather than the layer-wise 2.000, the requirement it
  implies is r >= %.0f rather than r >= 128, and R3_VALUE = 160's margin is
  %.2fx rather than 1.25x.""" % ("%.0e" % (1 / p_none), s_diff_w,
                                 math.ceil(r_need), R3_VALUE_256 / r_need))

    print("\n" + SEP)
    if FAIL:
        print("*** FAILED: %d finding(s) stopped reproducing ***" % len(FAIL))
        for f in FAIL:
            print("      - " + f)
        print(SEP)
        return 1
    print("*** OK: every finding reproduced ***")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
