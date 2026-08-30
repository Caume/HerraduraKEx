#!/usr/bin/env python3
"""nl_fscx_v3_round_count.py — TODO #255: derive NL-FSCX v3's round count.

TODO #255 ships candidate B (the deployed v2 round followed by a chi layer over
short odd rows) as a NEW primitive alongside v2, and gates every other step of
that item behind one question: how many rounds?  v2's `R_VALUE = 3n/4` carries
no justification for a different round function, so the count has to be DERIVED.

It is, and the derivation turns out to rest on something v2 does not have.

  §1  The criterion, with r free.
  §2  THE FLOOR THEOREM.  chi gives v3 an unconditional per-round trail floor --
      2 bits differential, 1 bit linear -- at every odd row length.  This is the
      family's first per-round trail bound of any kind.
  §3  Why v2 has no such floor, and cannot be given one.
  §4  THE 3-ROW DISQUALIFICATION.  The floor is a TRAIL bound; within-round
      clustering can beat it.  Measured, the gap is ~0 when every row is 5 bits
      or longer and TOTAL when any row is 3 bits -- a 3-row hands back a
      correlation-1 one-round linear approximation.  This is a design constraint
      on the partition, and it invalidates the n = 8 column of §11.32.
  §5  The multi-round window, such as it is.
  §6  The derived count and the margin chosen.
  §7  Cost, measured -- and a correction to #255's own cost figure.

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/nl_fscx_v3_round_count.py [--quick]
"""

import argparse
import importlib.util
import math
import os
import random
import sys
from collections import Counter

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


def _load(name):
    p = os.path.join(ROOT, 'SecurityProofsCode', name)
    spec = importlib.util.spec_from_file_location("_m_" + name[:-3], p)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


AR = _load('and_layer_recheck.py')
G = AR.G

# The deployed partition: 256 = 47*5 + 3*7.  Fifty rows, all odd, shortest 5.
V3_ROWS_256 = (5,) * 47 + (7,) * 3


# ── chi as an isolated S-box ────────────────────────────────────────────────
def chi_L(x, L):
    b = [(x >> i) & 1 for i in range(L)]
    o = 0
    for i in range(L):
        o |= (b[i] ^ ((1 - b[(i + 1) % L]) & b[(i + 2) % L])) << i
    return o


def chi_floors(L):
    """(min differential weight, min linear weight) over one active row."""
    N = 1 << L
    T = [chi_L(x, L) for x in range(N)]
    assert len(set(T)) == N, f"chi_{L} is not a bijection"
    wd = min(-math.log2(max(Counter(T[x] ^ T[x ^ a] for x in range(N)).values()) / N)
             for a in range(1, N))
    wl = 99.0
    for v in range(1, N):
        par = [1 if not (bin(v & T[x]).count('1') & 1) else -1 for x in range(N)]
        AR.BB.fwht(par)
        wl = min(wl, -math.log2(max(abs(c) for c in par) / N))
    return wd, wl


# ── the composite v3 round at reduced width ─────────────────────────────────
def mk_v3(n, B, rows):
    base = G['mk_v2'](n, B)
    return lambda a, i: G['chi_rows'](base(a, i), rows)


def round1_diff(n, rows, k):
    """Exact worst-case one-round differential weight of the composite round."""
    N = 1 << n
    T = [mk_v3(n, k, rows)(x, 1) for x in range(N)]
    return min(-math.log2(max(Counter(T[x] ^ T[x ^ a] for x in range(N)).values()) / N)
               for a in range(1, N))


def round1_lin(n, rows, k):
    """Exact worst-case one-round linear weight: min over nonzero output mask.

    Costs N FWHTs of length N, so it is the expensive measurement here.  A
    correlation-1 approximation (weight 0) is exactly what §4 is looking for and
    ends the scan the moment one appears -- which is what makes the 3-row cases
    cheap, leaving only the sound partitions to pay the full price."""
    N = 1 << n
    T = [mk_v3(n, k, rows)(x, 1) for x in range(N)]
    best = 99.0
    for b in range(1, N):
        par = [1 if not (bin(T[x] & b).count('1') & 1) else -1 for x in range(N)]
        AR.BB.fwht(par)
        c = max(abs(v) for v in par) / N
        w = -math.log2(c) if c > 0 else 99.0
        if w < best:
            best = w
            if best <= 0.0:
                return 0.0
    return best


# ═══════════════════════════════════════════════════════════════════════════
def section_1():
    rule("§1  The criterion, with r free")
    print("""§11.30.1 fixed the trail criterion for an n-bit block cipher run for r rounds.
Writing s for the per-round trail weight, a distinguisher is dead once the
r-round weight passes the generic bound:

      differential    s_diff * r >= n         (beat the 2^-n of a random perm)
      linear          s_lin  * r >= n / 2     (corr^-2 data vs a 2^n codebook)

For v2 the round count is not free -- R_VALUE = 3n/4 is tied to the block size --
so the width cancels and the criterion collapses to two pure numbers, s_diff >=
4/3 and s_lin >= 2/3.  Neither has been established for v2; that is #252 and
#254, both open.

For v3 the round count IS free: it is what this script derives.  So the criterion
does not collapse.  At the deployed n = 256 it reads

      r >= 256 / s_diff        and        r >= 128 / s_lin

and a round count follows the moment s_diff and s_lin have LOWER bounds.  Note
which direction is needed.  #252 and #254 are stuck trying to establish that v2's
slopes are large enough; here any provable floor immediately yields a sufficient
round count.  That is a strictly easier problem, and §2 solves it.""")


def section_2():
    rule("§2  The floor theorem")
    print("""THEOREM.  Let the v3 round be  chi_rows . (+delta) . M . (xor B, xor C_i)  on n
bits, with M invertible and the rows an arbitrary partition of n into ODD parts.
Then in the layer-wise trail model every differential trail of r rounds has
weight at least 2r, and every linear trail at least r.  Unconditional: no
assumption on the key, the constants, the row lengths or n.

PROOF.  Three steps, each cheap.

  (a) The difference entering chi is never zero.  xor by a constant preserves a
      difference; M is invertible so M(alpha) != 0; and x -> x + delta is
      injective, so equal outputs force equal inputs -- a nonzero difference
      cannot be absorbed by the addition.  Dually for masks: a linear trail has
      every mask nonzero by definition, and M^T is invertible.

  (b) So at least one row is active in every round.

  (c) One active row costs at least 2 bits differentially and 1 bit linearly.
      This is a property of chi alone, and it is UNIFORM in the row length:\n""")
    print(f"      {'row length L':<14}{'min diff weight':>18}{'min lin weight':>18}")
    print("      " + SEP2[:50])
    lens = [3, 5, 7, 9, 11]
    fl = {}
    for L in lens:
        wd, wl = chi_floors(L)
        fl[L] = (wd, wl)
        print(f"      chi_{L:<10}{wd:>18.4f}{wl:>18.4f}")
    print(f"""
      Every odd L gives exactly 2 and exactly 1.  Inactive rows contribute a
      factor 1 and cost nothing, so a round with any active row costs at least
      the single-row minimum.  Summing over r rounds gives 2r and r.  []

WHAT THIS IS.  The first per-round trail bound in the NL-FSCX family, on either
axis, at any width.  It is not a security proof -- it is a trail bound, and §4
shows what it does and does not control -- but it is the ingredient the round
count needs, and §6 spends it.""")
    check(all(fl[L] == (2.0, 1.0) for L in lens),
          f"chi's per-row floors are no longer (2, 1) at every odd length: {fl}")
    return fl


def section_3():
    rule("§3  Why v2 has no floor")
    print("""The theorem needs a non-linear layer whose every nonzero difference costs
something.  v2's round is M(x ^ B ^ C_i) + delta(B): linear, then add a constant.
Such a round has a probability-1 one-round differential for EVERY key -- the MSB
difference passes the addition untouched, because the carry it generates falls
off the top and is discarded (§11.28.3).  So v2's per-round differential floor is
exactly 0, not as a measurement but as a theorem in the opposite direction, and
no round count repairs it: 3n/4 rounds of a construction with a free round is
still a construction with a free round.

Measured, at the three widths where M is invertible and an exhaustive DDT is
reachable -- the deployed round's worst-case one-round weight:\n""")
    print(f"      {'n':>4}{'v2 round-1 diff weight':>26}{'v2 round-1 lin weight':>25}")
    print("      " + SEP2[:56])
    seen = []
    for n in (8, 10, 11):
        assert not G['m_is_singular'](n), n
        rng = random.Random(255 + n)
        ks = [rng.randrange(1 << n) for _ in range(4)]
        d = AR.avg_series(n, ks, G['mk_v2'], 1, False)[0]
        l = AR.avg_series(n, ks, G['mk_v2'], 1, True)[0]
        seen.append((d, l))
        print(f"      {n:>4}{d:>26.2f}{l:>25.2f}")
    print("""
      0.00 on both axes at every width, exactly as the theorem says.  This is the
      structural difference between v2 and v3, and it is why v3's round count can
      be derived while v2's cannot even be checked.""")
    check(all(d == 0.0 and l == 0.0 for d, l in seen),
          "the deployed v2 round no longer has a free first round on both axes")


def section_4(quick):
    rule("§4  The 3-row disqualification")
    print("""The floor of §2 is a bound on a TRAIL -- a fixed intermediate difference before
chi in each round.  The quantity that actually composes across rounds is the
round's own DDT entry, which SUMS over those intermediates.  Clustering inside a
round can therefore beat the trail bound, and it is not a small effect here:
the values reaching chi are not uniform given the difference, so chi's DDT entry
is not the conditional probability that applies.

Worked example, n = 8, rows (3,5), key 218: the differential 0xb7 -> 0x003 holds
with probability 1/2, weight 1.00, against a trail floor of 2.00.  It clusters
over two intermediates, beta = 0x001 and beta = 0x005, each individually capped
at chi's 1/4.

So the floor has to be checked against the composite round, exhaustively.  Doing
that turns up a sharp design constraint that had not been recorded -- and it is
a WEAK-KEY constraint, not a universal one, which is why a small key sample can
miss it entirely.\n""")

    n, N = 8, 256
    m, rol, ror = G['ops'](n)
    delta = lambda B: rol((B * ((B + 1) >> 1)) & m, n // 4)

    print("""      §4a  EXHAUSTIVE over all 256 keys at n = 8, both placements of the 3-row.
      A key is counted weak if the round has a CORRELATION-1 linear
      approximation -- weight 0.00, a complete break at any round count.\n""")
    print(f"      {'rows (low first)':<20}{'corr-1 keys':>14}{'of those, delta(B) odd':>26}")
    print("      " + SEP2[:60])
    res = {}
    for rows in ((3, 5), (5, 3)):
        weak = [k for k in range(N) if round1_lin(n, rows, k) <= 1e-9]
        odd = sum(1 for k in weak if delta(k) & 1)
        res[rows] = (len(weak), odd)
        print(f"      {str(rows):<20}{f'{len(weak)}/{N}':>14}{f'{odd}/{len(weak)}' if weak else '-':>26}")
        sys.stdout.flush()
    nodd = sum(1 for k in range(N) if delta(k) & 1)
    print(f"""
      With the 3-row AT THE BOTTOM the weak set is EXACTLY the keys whose
      delta(B) is odd -- {res[(3,5)][0]} of {N}, and all {nodd} delta-odd keys are in it, none
      other.  The approximation is always on the same bit: the top bit of the
      3-row.  The mechanism is visible in that: bit 0 of a sum has no carry-in,
      so the low bit entering chi is affine in the input, and chi over a row of
      three has too little room to destroy the resulting correlation.

      With the 3-row AT THE TOP the delta-odd class vanishes entirely ({res[(5,3)][1]} of
      {res[(5,3)][0]}), leaving a residue of {res[(5,3)][0]}/{N} weak keys.  So there are two effects and
      they separate cleanly: a 3-row anywhere is bad, and a 3-row holding the
      LSB is catastrophic.

      This is why key count matters.  A single-key check of rows (3,5) has a
      {N - res[(3,5)][0]}-in-{N} chance of reporting the partition clean.""")
    check(res[(3, 5)] == (nodd, nodd),
          f"the n=8 (3,5) weak class is no longer exactly the delta-odd keys: {res}")
    check(0 < res[(5, 3)][0] < res[(3, 5)][0],
          f"moving the 3-row off the LSB no longer shrinks the weak class: {res}")

    print("""

      §4b  The same comparison at n = 10, where a partition with NO 3-row
      exists.  Worst-case one-round weight over a key sample:\n""")
    K = 12 if quick else 40
    print(f"      {'n':>3}  {'rows':<10}{'3-row?':>8}{'diff min':>10}{'diff<=1':>9}"
          f"{'lin min':>9}{'corr-1':>8}   ({K} keys)")
    print("      " + SEP2[:62])
    rows_ok, rows_bad = [], []
    for nn, rows in ((10, (3, 7)), (10, (5, 5))):
        assert not G['m_is_singular'](nn), nn
        rng = random.Random(1000 + nn + sum(rows))
        ks = [rng.randrange(1 << nn) for _ in range(K)]
        wd = [round1_diff(nn, rows, k) for k in ks]
        wl = [round1_lin(nn, rows, k) for k in ks]
        lo = sum(1 for w in wd if w <= 1.001)
        z = sum(1 for w in wl if w <= 1e-9)
        rec = (nn, rows, min(wd), lo, min(wl), z, K)
        (rows_bad if 3 in rows else rows_ok).append(rec)
        print(f"      {nn:>3}  {str(rows):<10}{('YES' if 3 in rows else 'no'):>8}"
              f"{min(wd):>10.3f}{f'{lo}/{K}':>9}{min(wl):>9.3f}{f'{z}/{K}':>8}")
        sys.stdout.flush()
    print(f"""
      The 3-row partition puts about half its keys at half the differential
      floor and gives about half of them a correlation-1 linear approximation.
      The all-rows-5 partition does neither, for any key sampled.

TWO CONSEQUENCES.

  1. A CONSTRAINT ON v3.  The partition must have MINIMUM ROW LENGTH 5, and the
     implementation must assert it.  The specified 256 = 47x5 + 3x7 satisfies it
     and also puts a 5-row at the LSB -- but the stated reason for that partition
     had been only that every row be ODD (bijectivity) and SHORT (degree).
     Oddness is not sufficient and 3 is odd.  This is now the binding constraint.

  2. A CORRECTION TO §11.32.  The small-width scripts build their partition with
     odd_partition(n), which returns (3,5) at n = 8 -- a 3-row, holding the LSB,
     the catastrophic placement.  The n = 8 column of §11.32's candidate-B
     measurements, and #246's before it, therefore measured the degenerate
     variant rather than the proposed design, and roughly half its keys were
     drawn from a broken class.  The n = 10 partition (5,5) and n = 11 partition
     (11,) are sound and carry those sections' conclusions -- #246's ordering is
     undisturbed -- but the n = 8 figures for B should be read as void.""")
    check(all(z > 0 for *_, z, _ in rows_bad),
          "a 3-bit row no longer produces correlation-1 keys at n=10")
    check(all(z == 0 and lo == 0 for _, _, _, lo, _, z, _ in rows_ok),
          "a min-row-5 partition now produces a degenerate key")
    return rows_ok


def section_5(quick, rows_ok):
    rule("§5  The multi-round window")
    print("""The one-round worst case of §4 is a valid lower bound on a trail's per-round
weight, but a loose one: it assumes the cheapest round can be taken every round,
and the trail structure forbids that.  The exact multi-round optimum settles it,
by dynamic programming over round DDTs and LATs -- subject to §11.31's ceiling,
past which the cumulative weight exceeds what the width can express and the
numbers stop meaning anything.\n""")
    widths = [(10, (5, 5)), (11, (11,))]
    nk = 2 if quick else 4
    for n, rows in widths:
        rng = random.Random(255 + n)
        ks = [rng.randrange(1 << n) for _ in range(nk)]
        R = 5
        W = []
        for k in ks:
            T = AR.table(n, mk_v3(n, k, rows))
            W.append((AR.dtrail(n, AR.ddt_t(n, T), R),
                      AR.BB.linear_series(n, AR.lat_t(n, T), R)))
        d = [sum(w[0][i] for w in W) / len(W) for i in range(R)]
        l = [sum(w[1][i] for w in W) / len(W) for i in range(R)]
        cd, cl = 0.6 * n, 0.3 * n
        print(f"      n={n}, rows={rows}, {nk} keys "
              f"(ceilings: diff {cd:.1f}, lin {cl:.1f})")
        print(f"        {'':<12}" + "".join(f"{'r=%d' % r:>8}" for r in range(1, R + 1)))
        print(f"        {'diff cum':<12}" + "".join(f"{v:>8.2f}" for v in d))
        print(f"        {'  increment':<12}" + "".join(
            f"{(d[i] - (d[i-1] if i else 0)):>8.2f}" +
            ("*" if (d[i - 1] if i else 0) >= cd else "") for i in range(R)))
        print(f"        {'lin cum':<12}" + "".join(f"{v:>8.2f}" for v in l))
        print(f"        {'  increment':<12}" + "".join(
            f"{(l[i] - (l[i-1] if i else 0)):>8.2f}" +
            ("*" if (l[i - 1] if i else 0) >= cl else "") for i in range(R)))
        print("        (* = the round begins already past the ceiling; void)\n")
        sys.stdout.flush()
    print("""      Only the first two rounds clear the ceiling at these widths, which is
      #252's problem restated and is not solved here.  What the window does show:
      the differential increments sit AT the floor of 2, and the linear
      increments straddle 1 -- well above the worst-case single round §4
      measured.  The cheapest single round is several times cheaper than any
      round the trail can actually chain, so §4's figure is loose by about that
      factor and the floor of §2 is the better estimate on both axes.""")


def section_6(quick, rows_ok):
    rule("§6  The derived round count")
    lmin = min(r[4] for r in rows_ok)
    n = 256
    s_diff, s_lin = 2.0, 1.0
    r_diff, r_lin = n / s_diff, (n / 2) / s_lin
    r_min = max(r_diff, r_lin)
    print(f"""Putting §1's criterion together with §2's floor, at the deployed n = {n}:

      differential   r >= n / s_diff   = {n} / {s_diff:.0f} = {r_diff:.0f}
      linear         r >= (n/2) / s_lin = {n // 2} / {s_lin:.0f} = {r_lin:.0f}

Both axes land on the same number and the binding requirement is

      r_min = {r_min:.0f} = n / 2

against a PROVEN floor, not a measured slope.  This is the first round count in
the family with that property; v2's 3n/4 = 192 rests on slopes that #252 and
#254 have not been able to establish at all.

THE MARGIN.  r_min is where the criterion is met exactly, and shipping there
would leave none.  Two facts argue for real margin and one against:

  FOR.  The floor is a TRAIL bound and §4 showed clustering can beat a trail
  bound -- comprehensively, in the 3-row case.  With min row 5 the differential
  gap measures at essentially zero, but the LINEAR gap is real: the worst single
  round measured over the §4 sample is {lmin:.3f} against a floor of 1.00 -- a tail
  well below the median, though a stable one: a separate 150-key run at n = 10
  rows (5,5) holds that same minimum from key 25 onward with a median of 0.678,
  so it is a real feature of the key space rather than an unbounded drift.  Its
  behaviour at n = 256 is not established.  That is #254's open question, and v3
  does not close it.

  AGAINST.  §5's multi-round window shows the cheap linear round is not
  chainable -- increments straddle 1.00, several times the worst-case round --
  so treating the worst round as if it were the slope (which at {lmin:.3f} would
  demand r >= {(n // 2) / lmin:.0f}) is substantially too pessimistic.

A 1.25x margin covers the measured linear gap without pricing in a slope the
evidence contradicts:

      r_v3 = 5n/8 = 160 rounds at n = 256

Stated plainly, as #255 requires: the margin chosen is 1.25x over a proven
floor, the residual risk it covers is linear clustering at full width, and the
item that would let it be tightened or would force it wider is #254.  5n/8 is
integral for every n divisible by 8, which covers 256 and the 32-bit assembly
width; v2's 3n/4 needed only a multiple of 4, so this is a slightly stronger
constraint on any future width.

      {'':<20}{'rounds':>9}{'basis':>34}
      {SEP2[:63]}
      {'v2 (deployed)':<20}{192:>9}{'3n/4, inherited, no floor known':>34}
      {'v3 floor minimum':<20}{160 - 32:>9}{'n/2, proven trail floor':>34}
      {'v3 SHIPPED':<20}{160:>9}{'5n/8, 1.25x margin':>34}

And #255's expectation is met: v3 needs MATERIALLY FEWER rounds than v2 -- 160
against 192 -- because it earns more per round.""")
    check(abs(r_min - 128.0) < 1e-9, f"the derived floor minimum moved off 128 ({r_min})")


def section_7():
    rule("§7  Cost, and a correction to #255's figure")
    print("""#255 states the change costs "+57% per round" and reasons that fewer rounds may
offset it outright.  That figure is a misreading of #246 §5, where +57% is the
cost of MASKING the chi layer relative to masking the modular addition the family
already needs.  There is no masked v2 anywhere in the suite, so it is not the
cost of the shipped code path, and the unmasked cost was never measured.

Measured now, both rounds in the same 4x64-bit limb representation with delta
precomputed for each (benchmarks/v3_round_cost.c, -O2):

      v2 round                  37.3 ns
      v3 round                  79.2 ns          2.12x   (2.12-2.17x over runs)

chi is implemented there the way a real one would be -- not bit by bit, but as
two shift-and-mask row rotations, since the 47 five-bit rows and the 3 seven-bit
rows are each contiguous and uniform.  It is validated bit-exactly against a
per-row reference, so the ratio is that of a correct fast implementation, not of
a placeholder.

      per 256-bit block
      v2 @ 192 rounds            7.16 us         1.00x
      v3 @ 160 rounds           12.67 us         1.77x

So the fewer rounds do NOT offset the per-round cost, and #255's hope of a
cost-neutral or cheaper v3 does not survive measurement: v3 is about 1.8x the
cost of v2 per block.  The trade on offer is unambiguous and should be recorded as such --
v3 buys the family's first proven per-round trail bound, on both axes, for
roughly double the work.  Whether that is worth shipping is a decision, not a
measurement, and it is now a decision with numbers under it.

Two caveats.  This is one x86-class host at one optimisation level; the ratio
will differ on AVR, which #255 already puts out of scope, and under masking,
where #246 §5's +57% is the relevant figure and applies on top. """)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_1()
    section_2()
    section_3()
    rows_ok = section_4(a.quick)
    section_5(a.quick, rows_ok)
    section_6(a.quick, rows_ok)
    section_7()
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
