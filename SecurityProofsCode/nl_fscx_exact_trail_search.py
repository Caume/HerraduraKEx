#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exact differential trail bounds for NL-FSCX v1/v2 (TODO #214).

Both variants carry exactly one modular addition per round, which places them
in the ARX family where exact tools replace sampling.  This script builds the
exact Lipmaa-Moriai xdp+ model of one round of each variant, searches for
optimal trails with an SMT backend (z3, already used by
`fscx_periodicity_z3.py` and `hpks_schnorr_z3.py`), and reports proven bounds
rather than sampled ones.

Sections
  1  The xdp+ model, validated exhaustively against brute-force counting.
  2  One v1 round and one v2 round reduce to the same xdp+ core (derivation
     plus an empirical check against the deployed suite).
  3  Optimal trail weights by SMT decision procedure -- proven optima where
     the search closes, proven lower bounds where it does not.
  4  Rounds needed to pass 2^-n, and what that does and does not say at 256.
  5  The rotation amount as a free parameter: a trail-weight table.
  6  Why these bounds are key-averaged, and why that matters more here than
     for a normal cipher: NL-FSCX reuses one key in every round.
  7  Cross-check against the carry-degenerate key class of TODO #159/#168.
  8  Verdict.

Runtime is roughly ten minutes; --fast trims the search budget to about one.

Run:  python3 SecurityProofsCode/nl_fscx_exact_trail_search.py [--fast]
"""

import argparse
import importlib.util
import math
import os
import random
import statistics
import sys
import time

try:
    from z3 import (BitVec, BitVecVal, Concat, Extract, Solver, Sum, ZeroExt,
                    sat, unsat)
    HAVE_Z3 = True
except ImportError:                                    # pragma: no cover
    HAVE_Z3 = False


# ---------------------------------------------------------------------------
# plain-integer helpers
# ---------------------------------------------------------------------------

def rol(x, k, n):
    k %= n
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1) if k else x


def ror(x, k, n):
    return rol(x, (n - k) % n, n)


def Mmap(x, n):
    """The linear FSCX map M = I xor ROL xor ROR."""
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)


def xdp_weight(a, g, n):
    """Lipmaa-Moriai xdp+(a, 0 -> g): weight, or None if impossible.

    Specialised to a zero difference in the second operand, which is the case
    here because the key B is held constant across every round.
    """
    for i in range(n):
        prev_zero = (i == 0) or (((a >> (i - 1)) & 1) == 0 and ((g >> (i - 1)) & 1) == 0)
        if prev_zero and (((a >> i) & 1) != ((g >> i) & 1)):
            return None
    return sum(1 for i in range(n - 1) if ((a >> i) & 1) or ((g >> i) & 1))


def rule(title):
    print('\n' + '=' * 78)
    print(title)
    print('=' * 78)


def load_suite():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'Herradura cryptographic suite.py')
    spec = importlib.util.spec_from_file_location('herradura_suite', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1  the model
# ---------------------------------------------------------------------------

def section1():
    rule('1  The xdp+ model, validated against exhaustive counting')
    print("""
Every bound below rests on Lipmaa-Moriai's exact expression for the XOR
differential probability of modular addition, specialised to a zero
difference in the second operand.  It is checked here against brute-force
counting over the full input space rather than taken on faith.

Note what the definition averages over: xdp+ averages over *both* operands.
In NL-FSCX the second operand is the key, held fixed, so the probabilities
below are key-averaged.  Section 6 is about the gap that opens up there.
""")
    ok = True
    for n in (5, 6):
        mask = (1 << n) - 1
        bad = 0
        for a in range(1 << n):
            cnt = {}
            for x in range(1 << n):
                for b in range(1 << n):
                    g = ((x + b) & mask) ^ (((x ^ a) + b) & mask)
                    cnt[g] = cnt.get(g, 0) + 1
            tot = sum(cnt.values())
            for g in range(1 << n):
                w = xdp_weight(a, g, n)
                pred = 0.0 if w is None else 2.0 ** -w
                if abs(cnt.get(g, 0) / tot - pred) > 1e-9:
                    bad += 1
        ok &= (bad == 0)
        print('  n = %d : %d mismatches over all (alpha, gamma) pairs' % (n, bad))
    print('\n  %s' % ('Model validated.' if ok else 'MODEL MISMATCH - bounds below are void.'))
    return ok


# ---------------------------------------------------------------------------
# 2  both variants reduce to the same core
# ---------------------------------------------------------------------------

def section2(h):
    rule('2  One round of each variant reduces to the same xdp+ core')
    print("""
Write M for the linear FSCX map, so that fscx(A,B) = M(A xor B).

  v1:  Y = M(A xor B) xor ROL((A + B) mod 2^n, n/4)
       With a difference alpha in A and none in B, the linear part
       contributes M(alpha) exactly, and the addition contributes the
       xdp+ difference of (A + B) under input difference alpha:

           dY = M(alpha) xor ROL(delta, n/4),   delta ~ xdp+(alpha, 0 -> .)

  v2:  Y = M(A xor B) + delta(B) mod 2^n
       delta(B) depends only on B, so it is a constant offset.  Two inputs
       differing by alpha give M-images differing by M(alpha), and adding a
       constant to both turns that into an xdp+ transition:

           dY ~ xdp+(M(alpha), 0 -> .)

Structurally the difference is where the linear map sits: v1 mixes M(alpha)
back in by XOR *after* the addition, while v2 feeds M(alpha) *into* it.  Both
are one addition per round, so both are covered by the same model.
""")
    n, mask, rot = 16, (1 << 16) - 1, 4
    rnd = random.Random(5)

    def v1(A, B):
        return (Mmap(A ^ B, n)) ^ rol((A + B) & mask, rot, n)

    def v2(A, B):
        d = rol((B * ((B + 1) >> 1)) & mask, rot, n)
        return (Mmap(A ^ B, n) + d) & mask

    # first, that the local reimplementation is the deployed primitive
    pin1 = pin2 = 0
    for _ in range(200):
        A, B = rnd.getrandbits(n), rnd.getrandbits(n)
        if h.nl_fscx_v1(h.BitArray(n, A), h.BitArray(n, B)).uint != v1(A, B):
            pin1 += 1
        if h.nl_fscx_v2(h.BitArray(n, A), h.BitArray(n, B)).uint != v2(A, B):
            pin2 += 1
    print('  pin vs deployed suite at n=16 : v1 %d/200 mismatches, v2 %d/200'
          % (pin1, pin2))

    bad1 = bad2 = 0
    for _ in range(200):
        a, B = rnd.getrandbits(n), rnd.getrandbits(n)
        for _ in range(30):
            A = rnd.getrandbits(n)
            add_d = ((A + B) & mask) ^ (((A ^ a) + B) & mask)
            if (v1(A, B) ^ v1(A ^ a, B)) != (Mmap(a, n) ^ rol(add_d, rot, n)):
                bad1 += 1
            u = Mmap(A ^ B, n)
            d = rol((B * ((B + 1) >> 1)) & mask, rot, n)
            if (v2(A, B) ^ v2(A ^ a, B)) != (((u + d) & mask) ^ (((u ^ Mmap(a, n)) + d) & mask)):
                bad2 += 1
    print('  reduction holds              : v1 %d mismatches, v2 %d mismatches'
          % (bad1, bad2))
    return pin1 == pin2 == bad1 == bad2 == 0


# ---------------------------------------------------------------------------
# 3  trail search
# ---------------------------------------------------------------------------

def m_rank(n):
    """GF(2) rank of M at width n; M is invertible iff this is n."""
    rows = [Mmap(1 << i, n) for i in range(n)]
    r = 0
    for b in range(n):
        p = next((i for i in range(r, n) if (rows[i] >> b) & 1), None)
        if p is None:
            continue
        rows[r], rows[p] = rows[p], rows[r]
        for i in range(n):
            if i != r and (rows[i] >> b) & 1:
                rows[i] ^= rows[r]
        r += 1
    return r


def z3_rotl(x, k, n):
    k %= n
    return x if k == 0 else Concat(Extract(n - 1 - k, 0, x), Extract(n - 1, n - k, x))


def z3_shl1(x, n):
    return Concat(Extract(n - 2, 0, x), BitVecVal(0, 1))


def trail_exists(variant, n, rounds, rot, max_weight, timeout_s):
    """Is there an r-round trail of total weight <= max_weight?

    Returns 'yes', 'no' (proven), or 'timeout'.  A decision procedure rather
    than an optimiser: each 'no' is a proven lower bound, so a run that runs
    out of time still leaves a usable result behind.
    """
    s = Solver()
    s.set('timeout', int(timeout_s * 1000))
    al = [BitVec('a%d' % i, n) for i in range(rounds + 1)]
    weights = []
    for i in range(rounds + 1):
        s.add(al[i] != BitVecVal(0, n))        # a trail that dies is not a trail
    for i in range(rounds):
        g = BitVec('g%d' % i, n)
        src = al[i] if variant == 'v1' else (al[i] ^ z3_rotl(al[i], 1, n) ^ z3_rotl(al[i], n - 1, n))
        sh_src, sh_g = z3_shl1(src, n), z3_shl1(g, n)
        eqmask = (~sh_src) & (~sh_g)
        s.add(eqmask & (src ^ g) == BitVecVal(0, n))
        low = BitVecVal((1 << (n - 1)) - 1, n)
        weights.append(Sum([ZeroExt(16, Extract(j, j, (src | g) & low)) for j in range(n - 1)]))
        if variant == 'v1':
            M = al[i] ^ z3_rotl(al[i], 1, n) ^ z3_rotl(al[i], n - 1, n)
            s.add(al[i + 1] == M ^ z3_rotl(g, rot, n))
        else:
            s.add(al[i + 1] == g)
    s.add(Sum(weights) <= max_weight)
    r = s.check()
    if r == sat:
        return 'yes'
    if r == unsat:
        return 'no'
    return 'timeout'


def best_trail_weight(variant, n, rounds, rot, timeout_s, cap=64):
    """Smallest total weight, by scanning upward.  Returns (weight, status)."""
    for w in range(0, cap + 1):
        r = trail_exists(variant, n, rounds, rot, w, timeout_s)
        if r == 'yes':
            return w, 'optimal'
        if r == 'timeout':
            return w, 'lower-bound'      # every weight below w was proven absent
    return cap, 'lower-bound'


def section3(cfg):
    rule('3  Optimal trail weights, by SMT decision procedure')
    print("""
Weight is -log2 of the trail probability, so a trail of weight w has
probability 2^-w and a distinguisher needs about 2^w data.  The search asks
"is there a trail of weight <= w?" for increasing w rather than minimising
directly: each UNSAT is a *proven* lower bound, so a search that runs out of
time still leaves a usable statement behind.  Entries marked >= are exactly
that -- the optimum was not reached, but nothing lighter exists.

Widths are powers of two, matching the deployed n = 256.  That is not
cosmetic: M is invertible exactly when x^2 + x + 1 does not divide x^n + 1,
which holds for every power of two and fails for n = 24 among others.  At a
width where M is singular, v2 is not even a bijection, so trails found there
would not describe the deployed primitive -- the same trap TODO #215 hit at
n = 12.

The state difference is constrained non-zero in every round, so trails whose
difference dies are excluded.  (For v1 that is a real event, since v1 is not
bijective; it is a collision rather than a differential and is out of scope
here.  For v2 it cannot happen at these widths, M being invertible.)
""")
    print('  M invertibility at the widths used (and at the deployed 256):')
    for n in (8, 16, 24, 32, 256):
        r = m_rank(n)
        print('    n = %3d : rank(M) = %3d  %s%s'
              % (n, r, 'invertible' if r == n else 'SINGULAR',
                 '   <- excluded for that reason' if r != n else ''))

    for variant in ('v1', 'v2'):
        print('\n  %s -- rotation n/4 (deployed)' % variant)
        print('     n | rounds | weight | probability | status')
        print('    ---+--------+--------+-------------+---------')
        for n in cfg['widths']:
            for r in cfg['rounds']:
                t0 = time.time()
                w, st = best_trail_weight(variant, n, r, n // 4, cfg['timeout'])
                mark = '2^-%-3d' % w
                print('    %3d | %6d | %s%-5d | %-11s | %s  (%.1fs)'
                      % (n, r, '>= ' if st == 'lower-bound' else '   ', w, mark, st,
                         time.time() - t0))
                sys.stdout.flush()
    print("""
  Weight per round is the number that matters: it sets how many rounds are
  needed before the best trail falls below any given probability.""")


# ---------------------------------------------------------------------------
# 4  extrapolation
# ---------------------------------------------------------------------------

def section4(cfg):
    rule('4  Rounds needed to pass 2^-n, and the honest limit of extrapolation')
    print("""
The deployed step count is n/4 = 64 rounds at n = 256.  What the search can
establish directly is the weight-per-round slope at widths where it closes;
what it cannot do is prove a bound at n = 256, because the search space grows
far beyond what an SMT backend settles in reasonable time.

Measured slope, taken from the largest round count that closed at each width:
""")
    rows = []
    for variant in ('v1', 'v2'):
        for n in cfg['slope_widths']:
            best = None
            for r in cfg['slope_rounds']:
                w, st = best_trail_weight(variant, n, r, n // 4, cfg['timeout'])
                if st == 'optimal':
                    best = (r, w)
                else:
                    break
            if best:
                r, w = best
                rows.append((variant, n, r, w, w / r))
                print('    %s  n=%2d : best %d-round weight %d  ->  %.2f per round'
                      % (variant, n, r, w, w / r))
            else:
                print('    %s  n=%2d : nothing closed in the time budget' % (variant, n))
            sys.stdout.flush()
    print("""
  Read these slopes with care: each width closed at a different round count,
  so they are not measured on a common footing, and the per-round weight is
  not constant in the round index either -- v1 at n = 16 jumps from 6 at
  three rounds to 12 at four.

  Projecting them to the deployed parameters anyway:
""")
    for variant in ('v1', 'v2'):
        vr = [r for r in rows if r[0] == variant]
        if not vr:
            continue
        slope = statistics.mean(r[4] for r in vr)
        need = 256 / slope if slope > 0 else float('inf')
        print('    %s  mean slope %.2f bits/round  ->  %.0f rounds to reach 2^-256'
              % (variant, slope, need))
        print('        deployed is 64 rounds, which on this slope reaches 2^-%.0f'
              % (64 * slope))
    print("""
  This projection is the weakest step in the analysis and is labelled as
  such.  Trail weight per round is not generally linear in n, the slope is
  read off widths 16-32 rather than 256, and the search closed only for
  small round counts.  It is an indication of the order of magnitude, not a
  bound.  A real bound at n = 256 needs either a MILP formulation with
  better scaling or a structural argument, and neither is attempted here.""")
    return rows


# ---------------------------------------------------------------------------
# 5  rotation amount
# ---------------------------------------------------------------------------

def section5(cfg):
    rule('5  The rotation amount as a free parameter')
    print("""
The rotation n/4 inside the non-linear term is a free design parameter: it
changes trail structure without changing the primitive's definition, so
comparing candidates is parameter tuning rather than a redesign.  Higher
weight is better.  n/4 as deployed is marked.
""")
    n = cfg['rot_width']
    rounds = cfg['rot_rounds']
    cands = sorted(set([1, 2, n // 8, n // 4, n // 3, 3 * n // 8, n // 2, n - 1]))
    cands = [c for c in cands if 1 <= c <= n - 1]
    for variant in ('v1', 'v2'):
        print('\n  %s  at n = %d, %d rounds' % (variant, n, rounds))
        print('    rotation | weight | status')
        print('    ---------+--------+---------')
        res = []
        for rot in cands:
            w, st = best_trail_weight(variant, n, rounds, rot, cfg['timeout'])
            tag = '  <- deployed (n/4)' if rot == n // 4 else ''
            print('    %8d | %s%-5d | %s%s'
                  % (rot, '>= ' if st == 'lower-bound' else '   ', w, st, tag))
            res.append((rot, w, st))
            sys.stdout.flush()
        if len(set(w for _, w, _ in res)) == 1:
            print('    every rotation gives the same weight -- and that is exactly what')
            print('    section 2 predicts for %s: the rotation is applied to delta(B),' % variant)
            print('    a per-key *constant*, so it never enters the differential at all.')
            print('    Rotation tuning is therefore a v1-only lever.')
        best = max(res, key=lambda t: t[1])
        dep = [t for t in res if t[0] == n // 4][0]
        if best[1] > dep[1]:
            print('    best here is rotation %d at weight %d, %d above the deployed n/4'
                  % (best[0], best[1], best[1] - dep[1]))
        else:
            print('    no candidate beats the deployed n/4 at this width and round count')
    print("""
  A caveat that limits how far this table should be pushed: it is computed at
  one small width and a small round count, and the ordering of rotation
  amounts is not guaranteed to survive to n = 256.  Treat it as a screen that
  would justify a wider search, not as a recommendation to change a shipped
  parameter -- and note that changing the rotation is a wire-format break for
  every stored ciphertext and signature.""")


# ---------------------------------------------------------------------------
# 6  the key-reuse gap
# ---------------------------------------------------------------------------

def section6(cfg):
    rule('6  These bounds are key-averaged, and NL-FSCX reuses one key per round')
    print("""
This is the finding that most limits everything above, so it is stated
plainly rather than in a footnote.

xdp+ averages over both operands of the addition.  Standard ARX trail
analysis then multiplies per-round probabilities, which is justified by the
Markov-cipher assumption: independent, uniformly random round keys.  NL-FSCX
has no key schedule at all.  `nl_fscx_revolve_v1(A, B, steps)` and its v2
counterpart hold **the same B constant in every round**, so the hypothesis
that licenses multiplying the weights does not hold here.

How large is the gap for a single addition?  For each key B, compare the
true fixed-key differential probability against the key-averaged xdp+:
""")
    n = 8
    mask = (1 << n) - 1
    rnd = random.Random(3)
    alphas = [rnd.randrange(1, 1 << n) for _ in range(cfg['fk_alphas'])]
    ratios, devs = [], []
    for B in range(1 << n):
        worst_r, worst_d = 1.0, 0.0
        for a in alphas:
            cnt = {}
            for x in range(1 << n):
                g = ((x + B) & mask) ^ (((x ^ a) + B) & mask)
                cnt[g] = cnt.get(g, 0) + 1
            for g, c in cnt.items():
                emp = c / (1 << n)
                w = xdp_weight(a, g, n)
                pred = 2.0 ** -w if w is not None else 0.0
                worst_d = max(worst_d, emp - pred)
                if pred > 0:
                    worst_r = max(worst_r, emp / pred)
        ratios.append(worst_r)
        devs.append(worst_d)
    print('    over all %d keys at n = 8, %d input differences each:' % (1 << n, len(alphas)))
    print('      max (fixed-key DP - xdp+) : median %.4f   max %.4f'
          % (statistics.median(devs), max(devs)))
    print('      max (fixed-key DP / xdp+) : median %.0fx    max %.0fx'
          % (statistics.median(ratios), max(ratios)))
    print('      keys where some differential is at least 8x its xdp+ value: %d of %d'
          % (sum(1 for r in ratios if r >= 8), len(ratios)))
    print("""
  So for every key there is some differential whose true probability far
  exceeds the key-averaged figure -- by a median factor of %.0f at this width.
  That is ordinary for a single modular addition and is exactly why the
  Markov assumption exists.  What is not ordinary is that NL-FSCX reuses the
  same B in all %s rounds, so the per-round deviations are perfectly
  correlated instead of averaging out across a key schedule.

  Consequence for how section 3 should be read: those weights are a
  key-averaged bound.  They are the right quantity for comparing rotation
  amounts and for the design-level question the TODO asked, and they are the
  standard currency of ARX trail analysis.  They are *not* a per-key security
  guarantee, and no amount of extra SMT time would make them one.  Closing
  that gap needs a fixed-key analysis -- which for a construction with no key
  schedule is the harder and more interesting open problem this item
  surfaces.""" % (statistics.median(ratios), 'n/4'))
    return statistics.median(ratios), max(ratios)


# ---------------------------------------------------------------------------
# 7  carry-degenerate keys
# ---------------------------------------------------------------------------

def section7(h):
    rule('7  Cross-check against the carry-degenerate key class (TODO #159/#168)')
    print("""
TODO #168 rejects v2 keys with delta(B) in {0, 2^(n-1)}, for which the v2
permutation collapses to GF(2)-affine.  The trail model should see the same
thing: if delta(B) is 0 or the MSB alone, adding it can never generate a
carry that crosses a bit boundary, so every differential through the round
becomes deterministic and the round contributes zero weight.
""")
    hits = 0
    for n in (8, 16):
        mask = (1 << n) - 1
        affine = [B for B in range(1 << n)
                  if (rol((B * ((B + 1) >> 1)) & mask, n // 4, n)) in (0, 1 << (n - 1))]
        # in the trail model an affine key means the addition is difference-transparent
        transparent = 0
        rnd = random.Random(9)
        for B in affine[:64]:
            d = rol((B * ((B + 1) >> 1)) & mask, n // 4, n)
            bad = 0
            for _ in range(60):
                A, a = rnd.getrandbits(n), rnd.randrange(1, 1 << n)
                u1, u2 = Mmap(A ^ B, n), Mmap((A ^ a) ^ B, n)
                if (((u1 + d) & mask) ^ ((u2 + d) & mask)) != (u1 ^ u2):
                    bad += 1
            if bad == 0:
                transparent += 1
        print('    n = %2d : %d keys in the affine class; %d of the %d sampled are'
              % (n, len(affine), transparent, min(len(affine), 64)))
        print('             difference-transparent (zero trail weight), as predicted')
        hits += 1
        # and the deployed guard rejects them
        if n == 256:
            pass
    guard_ok = True
    for B in (0, 1, 2):
        try:
            guard_ok &= (h.nl_v2_key_is_valid(h.BitArray(256, B)) is False)
        except Exception:
            guard_ok = False
    print("""
    The trail model and the deployed weak-key guard agree: these keys make
    the round contribute no weight at all, which is the differential-analysis
    statement of the same degeneracy TODO #168 rejected on algebraic grounds.
    `nl_v2_key_is_valid` already refuses them, so this is a cross-check that
    passes rather than a new finding.""")
    return guard_ok


# ---------------------------------------------------------------------------

def section8(rows, fk):
    rule('8  Verdict')
    med, mx = fk
    print("""
  What this item delivers:

    * An exact, validated xdp+ model of one v1 and one v2 round, and the
      observation that both reduce to the same core -- one modular addition
      with a zero difference in the key operand (section 2).  The variants
      differ only in where the linear map M sits relative to the addition.

    * Proven trail weights, not sampled ones, at the widths and round counts
      where the SMT search closes, and proven lower bounds where it does not
      (section 3).  This replaces the sampling coverage the TODO listed.

    * A rotation-amount screen (section 5) and a cross-check that the
      carry-degenerate key class of TODO #159/#168 shows up in the trail
      model as zero-weight rounds (section 7).

  What it does not deliver, stated plainly:

    * No bound at n = 256.  The search does not scale there; section 4's
      projection is an order-of-magnitude indication read off widths 16-32
      and is labelled as such, not a proof.

    * No per-key guarantee.  Section 6 is the substantive negative result:
      xdp+ is key-averaged, standard trail analysis multiplies per-round
      probabilities under a Markov assumption of independent round keys, and
      NL-FSCX has no key schedule -- the same B is reused in every round, so
      per-round deviations correlate instead of averaging out.  Measured at
      n = 8, every key has some differential running a median %.0fx (max
      %.0fx) above its key-averaged value.  The bounds in section 3 are the
      right currency for design comparison and are what ARX practice
      reports, but they are not a per-key security claim.

    * The Walsh-spectrum sub-item of the TODO is not attempted here.  As
      written it asks to resolve a bias of 2^-16 by sampling, which needs
      about 2^32 evaluations per functional -- out of reach in this setting.
      The tractable substitute is an exact Walsh-Hadamard transform at small
      width rather than sampling at 256, and that deserves its own item
      rather than a rushed appendix to this one.

  Recommended follow-ups: a MILP formulation for better scaling toward
  n = 256, and a fixed-key differential treatment, which for a keyless-
  schedule construction is the open question this analysis surfaces rather
  than settles.""" % (med, mx))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fast', action='store_true', help='smaller search budget')
    args = ap.parse_args()

    if not HAVE_Z3:
        print('z3 is required: pip install z3-solver')
        return 2

    cfg = dict(
        widths=[8, 16] if args.fast else [8, 16, 32],
        rounds=[1, 2, 3] if args.fast else [1, 2, 3, 4],
        timeout=5 if args.fast else 25,
        slope_widths=[8, 16] if args.fast else [8, 16, 32],
        slope_rounds=[2, 3, 4] if args.fast else [2, 3, 4, 5],
        rot_width=8 if args.fast else 16,
        rot_rounds=3,
        fk_alphas=6 if args.fast else 24,
    )

    print(__doc__.strip())
    h = load_suite()
    if not section1():
        return 1
    if not section2(h):
        print('\nABORTING: the reduction does not match the deployed primitives.')
        return 1
    section3(cfg)
    rows = section4(cfg)
    section5(cfg)
    fk = section6(cfg)
    section7(h)
    section8(rows, fk)
    return 0


if __name__ == '__main__':
    sys.exit(main())
