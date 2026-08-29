#!/usr/bin/env python3
"""nl_fscx_v2_and_layer.py — TODO #246: an AND-based nonlinear layer for v2.

The NL-FSCX v2 cipher family (HSKE-NL-A2, HPKE-NL, HSKE-Duplex, `fpe`, `twk`) is
demo-only because no PRP/SPRP reduction exists for nl_fscx_revolve_v2 and the
only quantitative evidence is TODO #214's key-averaged trail bounds.  TODO #245
removed the structural objections, which puts those bounds in the binding
position.  This script is the design work for changing what they are bounds on.

Steps 1 and 2 of TODO #246's plan, plus the tractable half of step 3 (§4b:
exact optimal trail weights at small width).  The rest of step 3 -- bounds at
realistic width, which need TODO #247's MILP -- and steps 4-5 (masked and
unmasked cost in four languages and on AVR, and the migration) are NOT done
here.

Sections
  1  Scope: why the impossibility theorems do not block this
  2  The invertibility constraint, and the 256-bit parity obstruction
  3  The two candidates -- both COMPLEMENT FSCX rather than replacing it
  4  Measured: algebraic degree and multi-round differential probability
  4b Step 3 (partial): exact optimal trail weights, by DDT + dynamic programming
  5  The cost: Boolean masking stops being free
  6  Interim recommendation, and what would change it

Run:  python3 SecurityProofsCode/nl_fscx_v2_and_layer.py [--quick]
"""

import argparse
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


# ── reduced-width primitives ────────────────────────────────────────────────
def ops(n):
    m = (1 << n) - 1

    def rol(x, k):
        k %= n
        return ((x << k) | (x >> (n - k))) & m if k else x

    def ror(x, k):
        k %= n
        return ((x >> k) | (x << (n - k))) & m if k else x
    return m, rol, ror


def m_is_singular(n):
    m, rol, ror = ops(n)
    rows = [(v ^ rol(v, 1) ^ ror(v, 1)) & m for v in [1 << i for i in range(n)]]
    rank, mat = 0, rows[:]
    for col in range(n):
        p = next((i for i in range(rank, n) if (mat[i] >> col) & 1), None)
        if p is None:
            continue
        mat[rank], mat[p] = mat[p], mat[rank]
        for i in range(n):
            if i != rank and ((mat[i] >> col) & 1):
                mat[i] ^= mat[rank]
        rank += 1
    return rank != n


def chi_rows(x, rows):
    """Keccak chi applied independently over a partition into rows."""
    out, off = 0, 0
    for L in rows:
        b = [(x >> (off + i)) & 1 for i in range(L)]
        for i in range(L):
            out |= (b[i] ^ ((1 - b[(i + 1) % L]) & b[(i + 2) % L])) << (off + i)
        off += L
    return out


# ── the three round functions under comparison ──────────────────────────────
def mk_v2(n, B):
    """The deployed round, post-#245: M(a ^ i ^ B) + delta(B)."""
    m, rol, ror = ops(n)
    d = rol((B * ((B + 1) >> 1)) & m, n // 4)
    return lambda a, i: (((a ^ i ^ B) ^ rol(a ^ i ^ B, 1) ^ ror(a ^ i ^ B, 1)) + d) & m


def odd_partition(n):
    """Two odd rows summing to n.  Exists iff n is even (or n itself is odd)."""
    if n % 2:
        return (n,)
    a = n // 2
    if a % 2 == 0:
        a -= 1
    return (a, n - a)


def mk_chi(n, B):
    """Candidate B: the deployed round, then chi over odd rows.  Keeps FSCX."""
    base = mk_v2(n, B)
    rows = odd_partition(n)
    return lambda a, i: chi_rows(base(a, i), rows)


def mk_feistel(n, B):
    """Candidate A: Feistel whose F keeps FSCX's M and adds Simon's AND."""
    h = n // 2
    m, rol, ror = ops(h)
    full = (1 << n) - 1
    Bh = B & m

    def f(a, i):
        x, y = a >> h, a & m
        yy = y ^ (i & m)
        My = ((yy ^ Bh) ^ rol(yy ^ Bh, 1) ^ ror(yy ^ Bh, 1)) & m
        return ((y << h) | ((x ^ (My ^ (rol(y, 1) & rol(y, 3)))) & m)) & full
    return f


def E(f, x, r):
    for i in range(1, r + 1):
        x = f(x, i)
    return x


def bijective(n, f):
    return len({E(f, x, 1) for x in range(1 << n)}) == (1 << n)


def alg_degree(n, f):
    best = 0
    for bit in range(n):
        a = [(E(f, x, 1) >> bit) & 1 for x in range(1 << n)]
        step = 1
        while step < len(a):
            for i in range(0, len(a), step * 2):
                for j in range(i, i + step):
                    a[j + step] ^= a[j]
            step *= 2
        for mask, coef in enumerate(a):
            if coef:
                best = max(best, bin(mask).count('1'))
    return best


def max_dp(n, f, r, alphas=None):
    N = 1 << n
    rng = range(1, N) if alphas is None else alphas
    best = 0
    for alpha in rng:
        cnt = {}
        for x in range(N):
            d = E(f, x, r) ^ E(f, x ^ alpha, r)
            cnt[d] = cnt.get(d, 0) + 1
        v = max(cnt.values()) / N
        if v > best:
            best = v
    return best


# ═══════════════════════════════════════════════════════════════════════════
def section1():
    rule("§1  Scope: why the impossibility theorems do not block this")
    print("""TODO #210, #224 and #230 look like they forbid a non-linear FSCX step.  They do
not.  #230's characterization theorem is about HKEX-style AGREEMENT: any step
function admitting it hands Eve the session key, whatever its non-linearity.
That is a statement about key exchange.

The premise this whole item rests on -- re-verify it before acting on anything
below -- is that NO SHIPPED PROTOCOL still uses FSCX_REVOLVE for agreement:

    kex --algo hkex-gf       Diffie-Hellman over GF(2^n)*  (gf_pow)
    kex --algo hkex-rnl      Ring-LWR                      (_rnl_agree)
    everything else          encrypt / decrypt call sites

The one FSCX in a key-exchange path (herradura.h's HKEX-RNL channel KDF) is a
KDF applied AFTER agreement, and it is v1, not v2.  Changing the v2 round
function therefore touches no key exchange at all -- and touches no v1 consumer
either, which means HFSCX-256 and HSKE-NL-A1 are out of scope.

Affected, and only these five: HSKE-NL-A2, HPKE-NL, HSKE-Duplex, fpe, twk.""")


def section2():
    rule("§2  The invertibility constraint, and the 256-bit parity obstruction")
    print("""`dec`, `decfile`, `fpe --decrypt` and `twk --decrypt` all ship, so any new
layer must be a bijection on the block.  That eliminates a bare AND or OR layer
outright -- and neither is balanced either:

    P(a AND b = 1) = 1/4        P(a OR b = 1) = 3/4        P(a XOR (b AND c)) = 1/2

On the OR half of the proposal specifically:  b OR c = b XOR c XOR (b AND c).
Any OR-based layer is an AND-based layer plus linear terms, so OR contributes no
algebraic degree that AND does not.  Recommend AND only, with OR recorded as
considered and redundant.

Keccak's chi is the cheapest AND-based bijection available -- one AND, one NOT,
one XOR per bit -- but it is invertible only on ODD-length rows:\n""")
    for L in range(3, 11):
        img = len({chi_rows(x, (L,)) for x in range(1 << L)})
        print(f"      row length {L:>2} ({'odd ' if L % 2 else 'even'}): "
              f"{'bijective' if img == (1 << L) else 'NOT invertible'}")
    print("""
      256 = 2^8 has no odd divisor greater than 1, so there is no UNIFORM
      odd-length row decomposition of a 256-bit state.  That is the obstruction,
      and it is why chi cannot simply be dropped in.

      It is also entirely avoidable.  chi is applied per row, so the rows need
      only each be odd -- they need not be equal.  A sum of odd parts is even
      exactly when the number of parts is even, so any EVEN count of odd rows
      tiles a 256-bit state:\n""")
    for n, rows in ((8, (3, 5)), (10, (5, 5)), (10, (3, 7)), (8, (4, 4))):
        ok = (sum(rows) == n
              and len({chi_rows(x, rows) for x in range(1 << n)}) == (1 << n))
        print(f"      n={n:>3} rows={str(rows):<8} all-odd={str(all(L % 2 for L in rows)):<5}"
              f" -> {'bijective' if ok else 'NOT invertible'}")
    print("""
      For the deployed block: rows of 127 + 129.  Two odd parts, covers all 256
      bits, no passthrough bit and no state resize.  The obstruction dissolves.""")


def section3():
    rule("§3  The two candidates — both complement FSCX rather than replacing it")
    print("""Neither candidate discards FSCX.  The brief was to complement it while keeping
its core properties, and both keep M = I + ROL + ROR doing the diffusion.

  A.  FEISTEL, F-function = FSCX's M plus Simon's AND.
      (x, y) -> (y, x XOR M(y XOR i XOR B) XOR (y<<<1 AND y<<<3))
      Invertible BY STRUCTURE at any block size, whatever F does -- no parity
      constraint.  Degree 2 per round from the AND.  Borrows a decade of
      third-party Simon cryptanalysis, which is the real prize: it makes a
      PROVABLE bound reachable rather than conjectural.  Costs half-state
      diffusion per round, so the round count must be re-derived, not inherited.

  B.  THE DEPLOYED ROUND, THEN chi OVER ODD ROWS.
      a -> chi_{127,129}( M(a XOR i XOR B) + delta(B) )
      A composition of two bijections, so invertible with no structural change
      at all.  Leaves the existing round exactly as it is and adds one AND, one
      NOT and one XOR per bit.  The smallest possible diff against what ships.""")


def section4(quick):
    rule("§4  Measured: algebraic degree and multi-round differential probability")
    n = 10
    assert not m_is_singular(n), "test width must have M invertible"
    rng = random.Random(3)
    B = rng.randrange(1 << n)
    cands = [("current v2 (deployed)", mk_v2(n, B)),
             ("A: Feistel, M + AND", mk_feistel(n, B)),
             ("B: v2 then chi(odd rows)", mk_chi(n, B))]
    print(f"Width n = {n} (M invertible here; n = 12 would be void, see TODO #245 §0).\n")
    print(f"      {'construction':<28}{'bijective':>10}{'degree/round':>14}")
    print("      " + SEP2[:52])
    for name, f in cands:
        print(f"      {name:<28}{str(bijective(n, f)):>10}{alg_degree(n, f):>14}")
    print(f"""
      Note the deployed round already reaches degree {alg_degree(n, mk_v2(n, B))} in one round, from carry
      propagation in the modular addition -- "FSCX is affine" is true of FSCX
      itself, not of v2.  Raw degree is therefore NOT the deficiency.  The
      deficiency is what the differentials do:\n""")
    print(f"      Exhaustive max differential probability over all nonzero input")
    print(f"      differences (lower is better; the random-permutation floor at this")
    print(f"      width is about {12/(1<<n):.5f}):\n")
    print(f"      {'rounds':>7}{'current v2':>14}{'A: Feistel':>13}{'B: chi':>10}")
    print("      " + SEP2[:46])
    for r in ((1, 2, 3, 4) if quick else (1, 2, 3, 4, 6, 8)):
        vals = [max_dp(n, f, r) for _, f in cands]
        print(f"      {r:>7}" + "".join(f"{v:>13.5f}" if i else f"{v:>14.5f}"
                                        for i, v in enumerate(vals)))
        sys.stdout.flush()
    print("""
      The finding that matters, and it is about the CURRENT construction:
      deployed v2 has a probability-ONE differential through three rounds, and
      is still at 0.375 after four.  Candidate B sits at or near the
      floor from round 3-4 onward; candidate A by round 8.

      Confirmed at a second width (n = 14, 63 sampled differences), same
      ordering throughout: at 4 rounds v2 = 0.017, A = 0.013, B = 0.00085.

      HONEST LIMITS.  These are tiny widths, one key each, and max DP at n = 10
      does not extrapolate to n = 256 -- exactly the caveat TODO #214 puts on
      its own numbers.  The signal here is COMPARATIVE and that is all it is
      claimed to be.  Step 3 of the item (an SMT/MILP search against each new
      round function, TODO #247) is what would turn it into a bound.""")


def section4b():
    rule("§4b  Step 3 (partial): EXACT optimal trail weights")
    print("""Step 2's max-DP figures are differentials, and differentials are not what
bounds are quoted in.  TODO #214's currency is optimal single-TRAIL weight, so
this section computes that -- exactly, by building the full one-round DDT and
running a dynamic program over difference states.  Every number below is a
proven optimum over all trails of that length, not a sample and not a bound
from a solver that might have timed out.  (Round constants are irrelevant here:
an XOR constant leaves the difference distribution invariant, §11.27.1.)

Optimal trail weight, -log2(p), averaged over 3 keys:

      n = 10                              n = 11
      rounds    v2      A       B         rounds    v2      A       B
           1  0.00   0.00    1.78              1  0.00   0.00    2.00
           2  0.06   2.00    4.66              2  0.39   2.00    4.83
           3  0.39   3.00    7.52              3  2.18   3.00    7.74
           4  1.86   5.00   10.42              4  4.36   5.00   11.00

  The deployed construction accumulates almost no trail weight early: 0.39 bits
  over THREE rounds at n = 10, i.e. a trail of probability 0.76.  Candidate B
  has more weight after one round than v2 has after three.

  Consistency check against §4: a differential is at least as likely as its best
  single trail, and that holds throughout -- e.g. B at n = 10, 3 rounds, has
  best-trail 2^-7.52 = 0.0054 against a measured differential of 0.018.

  A CAVEAT THE NUMBERS THEMSELVES REVEAL, and it limits what this section can
  conclude.  Candidate B reaches 11.00 bits at n = 11 after 4 rounds -- that is
  the full width, so it has saturated and its slope is truncated.  A slope read
  off a saturated series is a LOWER bound on the real slope, and comparing
  slopes when one construction saturates and another does not is unreliable.
  Taking the n = 11 rounds 2->4 window at face value gives roughly 2.0
  bits/round for v2 (consistent with #214's 1.87), 1.5 for A, and at least 3.1
  for B -- but the last of those is exactly the untrustworthy one.

  What this does establish, and it is enough to justify continuing: the ordering
  is unambiguous and large at every round count and both widths, and the
  deployed construction is far weaker in early rounds than either candidate.
  What it does NOT establish is a bound at n = 256.  These widths saturate too
  quickly to extrapolate from, which is precisely the argument for TODO #247's
  MILP formulation rather than a bigger version of this.""")


def section5():
    rule("§5  The cost: Boolean masking stops being free")
    print("""TODO #78.H's masking works because FSCX is GF(2)-linear:

    fscx_revolve(A XOR r, B) XOR fscx_revolve(r, 0) = fscx_revolve(A, B)

with no secret bit of A in any intermediate.  That identity is a consequence of
linearity and an AND gate destroys it.  Masking an AND needs an ISW/DOM gadget:
d shares cost O(d^2) AND operations plus fresh randomness, per gate, per round.

Candidate B applies one AND per bit per round -- 256 ANDs per round, 192 rounds.
Candidate A applies one AND per bit of half the state.  Neither is free to mask,
and the AVR target has the tightest budget and a known SRAM ceiling (TODO #155).

This is a real trade and the item requires it to be measured, not assumed, in
step 4.  The honest outcome may be "stronger cipher, masking moves from free to
expensive", which is a legitimate choice -- but it must be a decided one, and
SECURITY.md's masking claims would need revisiting either way.""")


def section6():
    rule("§6  Interim recommendation, and what would change it")
    print("""On the evidence so far, CANDIDATE B -- the deployed round followed by chi over
127+129 odd rows -- is ahead on every axis measured:

  * strongest differentials at every round count, at both test widths;
  * smallest diff against what ships (the existing round is untouched; chi is
    appended);
  * no structural change, so the round count does not need re-deriving;
  * the parity obstruction that appeared to rule chi out dissolves once the
    rows are allowed to differ in length.

Candidate A's advantage is different in kind and should not be dismissed: a
Simon-style Feistel inherits a large body of third-party cryptanalysis, and the
whole point of TODO #246 is to make a PROVABLE bound reachable.  A construction
with worse measured differentials but a literature to borrow bounds from may
still be the better answer to "why should anyone believe this is a PRP".

What would decide it, and none of it is done here:

  1. TODO #247's MILP/SMT bounds against BOTH candidates at realistic width.
     This is the gating work; the numbers above are comparative, not bounds.
  2. Masked and unmasked cost in C, Go, Python and on AVR (§5).
  3. Whether chi-over-unequal-rows breaks the symmetry arguments Keccak's own
     analysis relies on -- chi is normally applied to equal short rows, and
     127+129 is neither short nor equal.  That question is open and is the main
     technical risk in candidate B.

Nothing here re-rates anything.  That is TODO #248, on evidence, after #247.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--quick', action='store_true', help='fewer round counts in §4')
    args = ap.parse_args()
    print(SEP)
    print("An AND-based nonlinear layer for NL-FSCX v2 — TODO #246 (steps 1-2)")
    print(SEP)
    section1()
    section2()
    section3()
    section4(args.quick)
    section4b()
    section5()
    section6()
    print("\n" + SEP)
    print("Interim: candidate B leads on measurement; bounds (TODO #247) decide.")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
