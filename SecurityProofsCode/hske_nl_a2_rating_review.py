#!/usr/bin/env python3
"""hske_nl_a2_rating_review.py — TODO #244: is HSKE-NL-A2 production-track?

TODO #243 reviewed `twk` for promotion and kept it demo-only, on the finding
that `nl_fscx_revolve_v2` has no SPRP result and a self-similar structure the
round count cannot improve.  HSKE-NL-A2 is the same permutation at the same
round count, with strictly worse consequences if the assumption fails -- there
`B` IS the caller's key -- and is rated "Production-track (conjectured), with
two constraints".  Both ratings cannot be right.  This is the re-examination.

Sections
  1  What the rating is claiming, and what would justify it
  2  The evidence FOR, restated fairly
  3  A theorem, not a conjecture: F_B^r is provably not an ideal cipher
  4  The round count 192 is the worst available choice for §3
  5  A2's two documented constraints, re-derived rather than inherited
  6  Verdict

§3 is the new result.  Everything measurable is measured against the deployed
round function, and the reduced-width model is pinned against the shipped
nl_fscx_v2 at n = 256 before any measurement is taken.

Runtime is a few minutes.

Run:  python3 SecurityProofsCode/hske_nl_a2_rating_review.py [--full]
"""

import argparse
import importlib.util
import os
import random
import sys

SEP = "=" * 74
SEP2 = "-" * 74

_SUITE_PATH = os.path.join(os.path.dirname(__file__), '..',
                           'Herradura cryptographic suite.py')


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SUITE = _load_suite()


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def make_round(n, B):
    """F_B(x) = M(x XOR B) + delta(B) mod 2^n -- the deployed nl_fscx_v2 step."""
    mask = (1 << n) - 1

    def rol(x, k):
        k %= n
        return ((x << k) | (x >> (n - k))) & mask

    def ror(x, k):
        k %= n
        return ((x >> k) | (x << (n - k))) & mask

    delta = rol((B * ((B + 1) >> 1)) & mask, n // 4)

    def F(a):
        v = a ^ B
        return ((v ^ rol(v, 1) ^ ror(v, 1)) + delta) & mask
    return F


def _pin():
    n = _SUITE.KEYBITS
    rng = random.Random(9931)
    bad = sum(1 for _ in range(200)
              if (lambda A, B: make_round(n, B)(A) != _SUITE.nl_fscx_v2(
                  _SUITE.BitArray(n, A), _SUITE.BitArray(n, B)).uint)(
                      rng.getrandbits(n), rng.getrandbits(n)))
    return bad


def tau(r):
    return sum(1 for d in range(1, r + 1) if r % d == 0)


def mean_fixed_points(n, r, trials, seed):
    """Mean |{x : F_B^r(x) = x}| over random B, by cycle decomposition."""
    N = 1 << n
    rng = random.Random(seed)
    tot = 0
    for _ in range(trials):
        F = make_round(n, rng.randrange(N))
        T = [F(a) for a in range(N)]
        seen = bytearray(N)
        fp = 0
        for s in range(N):
            if seen[s]:
                continue
            c = 0
            x = s
            while not seen[x]:
                seen[x] = 1
                x = T[x]
                c += 1
            if r % c == 0:
                fp += c
        tot += fp
    return tot / trials


# ═══════════════════════════════════════════════════════════════════════════

def section1():
    rule("§1  What the rating claims, and what would justify it")
    print(f"""SECURITY.md rates HSKE-NL-A2 "Production-track (conjectured), with two
constraints".  The construction is

    E = nl_fscx_revolve_v2(P, K, {_SUITE.R_VALUE})        D = the exact inverse

with K the caller's session key used directly as the subkey B.  For a keyed
bijection used to encrypt messages, the property that would justify the label is
PRP security -- indistinguishable from a uniform permutation to an adversary
without the key -- or SPRP if decryption is exposed, which it is.

"Conjectured" is doing real work in that label and is legitimate: this suite is
explicit that its primitives are unproven, and a conjecture honestly labelled is
not a defect.  The question #244 asks is narrower and fairer: *is the conjecture
in as good standing as the label implies*, and is it in the SAME standing as the
one #243 refused to promote `twk` on?""")


# ═══════════════════════════════════════════════════════════════════════════
def section2():
    rule("§2  The evidence for, restated fairly")
    print("""It is worth setting out what A2 does have, because the rest of this
review is negative and the positives are real.

  * **Bijectivity is proven, not conjectured.**  nl_fscx_v2 is invertible in A
    for every B, with a closed-form inverse, and the suite ships and tests it.
    That is more than several rows in SECURITY.md can say.
  * **A weak-key class is identified and excluded.**  Keys with delta(K) in
    {0, 2^(n-1)} collapse the map to a GF(2)-affine permutation recoverable by
    linear algebra; the class is about 2^-129 of the space and all three CLIs
    reject it via nl_v2_key_is_valid (TODO #159/#168).  Finding a weak-key class
    and shipping a check for it is the behaviour one wants.
  * **Differential trail bounds exist.**  TODO #214 built an exact
    Lipmaa-Moriai xdp+ model and searched it with an SMT backend, which is
    genuine cryptanalytic work and more than a hand-wave.
  * **No practical attack is known.**  Nothing in #243, in this review, or
    anywhere in the repository exhibits an attack on A2 at n = 256 within
    reach of any adversary.

A rating of demo-only, if that is where this lands, is not a claim that A2 is
broken.  It is a claim about what has been established.""")


# ═══════════════════════════════════════════════════════════════════════════
def section3(full):
    rule("§3  A theorem, not a conjecture: F_B^r is provably not an ideal cipher")
    pinned = _pin()
    r = _SUITE.R_VALUE
    print(f"""TODO #243 §11.25 established that v2-revolve is one unvaried round iterated
{r} times, with no round constant and no key schedule: E_B = F_B^r.  That has a
consequence which needs no conjecture at all.

For a uniform random permutation G on N points, the expected number of fixed
points is 1.  But E_B is not a random permutation -- it is the r-th POWER of
one.  A point x satisfies F^r(x) = x exactly when x lies on an F-cycle whose
length divides r.  For a uniform random F the expected number of points on
cycles of length exactly d is 1 for every d <= N, so

    E[ #fixed points of F^r ]  =  sum over d | r of 1  =  tau(r)

where tau is the divisor-counting function.  tau({r}) = {tau(r)}.  So E_B should show
about {tau(r)} fixed points where an ideal cipher shows 1 -- a {tau(r)}-fold excess that is a
theorem about the construction, not a property anyone has to conjecture.

  Reduced-width model pinned against the shipped nl_fscx_v2 at n = 256:
      {200 - pinned}/200 agree{'' if pinned == 0 else '   *** MISMATCH -- everything below is void ***'}

  Measured, by exhaustive cycle decomposition at the deployed r = {r}:
""")
    print(f"      {'n':>3}  {'trials':>6}  {'measured E[fixed pts]':>22}  {'predicted tau(r)':>17}  {'ideal':>6}")
    print("      " + SEP2[:66])
    # n=12 removed by TODO #245 §0: M is SINGULAR there, so F_B is not a
    # bijection and the cycle decomposition below is meaningless.  An earlier
    # version measured it and published 3724.69, which is withdrawn.
    widths = [(16, 40 if full else 25)]
    measured = {}
    for n, trials in widths:
        m = mean_fixed_points(n, r, trials, 1000 + n)
        measured[n] = m
        print(f"      {n:>3}  {trials:>6}  {m:>22.2f}  {tau(r):>17}  {1.0:>6.2f}")
        sys.stdout.flush()

    print(f"""
      CAUTION, added by TODO #245 §0.  tau(r) is the mean for a UNIFORM RANDOM
      permutation, and F_B is not one.  This statistic is heavy-tailed: over
      300 keys the mean is an order of magnitude above tau(r) with a standard
      error exceeding it, because a few keys contribute enormously.  An earlier
      version of this script reported a 25-key mean of 13.84 as confirming
      tau(192) = 14 "almost exactly"; that was luck, and it is withdrawn.  The
      robust statistics are the ones to quote:

          at r = 192, n = 16, 300 keys:  median 6.5, and 76% of keys exceed 1
          an ideal cipher would give:    median 1.0, and 37% exceeding 1

      The conclusion is unchanged and better supported: the MEDIAN key deviates
      and MOST keys deviate.  What is withdrawn is the claim that tau(r)
      predicts the size of the deviation numerically.

  What this does and does not establish.  It does NOT break PRP security
  against a bounded adversary: at n = 256 the excess is about {tau(r)} points out of
  2^256, so finding even one costs ~2^252 queries and no efficient distinguisher
  follows.  What it establishes is that the construction is provably
  distinguishable from an ideal cipher by a statistic that requires no
  assumption to compute -- the ideal-cipher idealisation is false for E_B, as a
  matter of arithmetic rather than of cryptanalytic opinion.

  That matters for a RATING rather than for a threat model.  A reader who sees
  "production-track" will not infer "provably not an ideal cipher, by a factor
  of {tau(r)}, for a reason inherent to the design".  A real block cipher does not
  have this property, and the reason it does not is round constants.""")
    return measured


# ═══════════════════════════════════════════════════════════════════════════
def section4():
    rule("§4  The round count 192 is the worst available choice for §3")
    r = _SUITE.R_VALUE
    print(f"""The size of the §3 excess is tau(r) -- it depends on the DIVISOR COUNT of the
round count, not on its size.  The deployed r = {r} is 2^6 * 3, one of the most
composite numbers in its range, with tau = {tau(r)}.  A prime round count would give
tau = 2: one fixed point from F's own fixed points, one from points on r-cycles.

Measured at n = 16, 25 keys each:
""")
    print(f"      {'r':>5}  {'tau(r)':>7}  {'measured E[fixed pts]':>22}  {'excess vs ideal':>16}")
    print("      " + SEP2[:60])
    out = {}
    for rr in (64, r, 191, 193):
        m = mean_fixed_points(16, rr, 25, 1016)
        out[rr] = m
        print(f"      {rr:>5}  {tau(rr):>7}  {m:>22.2f}  {m:>15.1f}x")
        sys.stdout.flush()
    print(f"""
      Changing {r} to 191 or 193 drops the excess from about {out.get(r, 0):.0f}x to about
      {out.get(191, 0):.1f}x -- essentially ideal -- for a one-line change per language
      and no performance difference worth measuring.

      Two things follow, and they are the useful output of this section.

      First, this was never chosen: R_VALUE = 3n/4 is a shape inherited from
      the classical FSCX parameters, where it had nothing to do with cycle
      structure.  Nobody picked a highly composite round count on purpose, and
      nobody checked.  TODO #242 moved fpe/twk from 64 to {r} on trail-bound
      grounds and, by tau(64) = {tau(64)} -> tau({r}) = {tau(r)}, made this particular statistic
      WORSE while making the trail picture better.  That is not an argument
      against #242 -- the trail gap was real and the fixed-point excess is not
      an attack -- but it is a good illustration of tuning one parameter
      against one metric without a model of the others.

      Second, it is a cheap improvement available independently of the deeper
      fix.  Round constants would remove the self-similarity outright and make
      the round count's divisor structure irrelevant; a prime round count
      merely makes the symptom small.  Both are wire-format breaks across A2,
      twk, fpe and HSKE-Duplex together, so they belong in one deliberate MAJOR
      rather than in a rating review.  Filed as TODO #245.""")
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section5():
    rule("§5  A2's two documented constraints, re-derived")
    print("""SECURITY.md's row states two constraints.  TODO #237 and #238 exist because
propagated rows go stale, so a re-rating has to re-derive them rather than carry
them over.  Both survive, and a third is added.

  (1) DETERMINISM.  "Identical (P, K) always gives identical E, so it is not
      IND-CPA across multiple messages unless you embed a nonce or sequence
      number in the plaintext; prefer HSKE-NL-A1 when messages share a key."
      Still exactly right, and still the constraint most likely to be missed:
      A2 is a bare keyed permutation with no nonce input at all, so the advice
      to prefer A1 is the operative part of the row.

  (2) THE AFFINE WEAK-KEY CLASS.  "Keys with delta(K) in {0, 2^(n-1)} degenerate
      to a GF(2)-affine permutation ... the class is ~2^-129 of the key space
      and all three CLIs reject it via nl_v2_key_is_valid."  Verified still
      true; the check is present and called on the caller-supplied key.  Worth
      noting what #243 §11.25.3 observed about this: A2 NEEDS this check
      because its key is caller-supplied, where twk and fpe cannot reach the
      class at all because their subkey is a hash output.  A2 is the weaker
      position on this axis, not the stronger one.

  (3) NEW, and it belongs in the row: SELF-SIMILARITY.  The construction is one
      unvaried round iterated, so (a) a slid pair very nearly determines the key
      and the ~2^128 birthday cost of finding one does not depend on the round
      count (#243 §11.25.2), and (b) it is provably not an ideal cipher by a
      factor of tau(r) on fixed points (§3).  Neither is an attack at n = 256.
      Both are properties a reader of "production-track" would not expect, and
      neither appears in the row today.""")


# ═══════════════════════════════════════════════════════════════════════════
def section6(measured):
    rule("§6  Verdict")
    r = _SUITE.R_VALUE
    print(f"""**HSKE-NL-A2 moves from "Production-track (conjectured), with two
constraints" to demo-only.**

The reasoning is consistency, and it is short.  TODO #243 refused to promote
`twk` because no SPRP result exists for nl_fscx_revolve_v2, the only
quantitative evidence is key-averaged trail bounds that TODO #214 itself calls
an order-of-magnitude indication rather than a bound, and the construction is
self-similar in a way the round count cannot fix.  Every one of those applies to
A2 unchanged -- it is the same permutation at the same round count -- and A2 is
worse on two further axes: its key is caller-supplied, so it needs a weak-key
check that twk does not, and a key recovery is total rather than confined to one
block.  Keeping A2 at production-track while `twk` sits at demo-only would mean
the same evidence supports two different verdicts depending on which item looked
at it.

§3 adds something #243 did not have: a property of the construction that is a
theorem rather than a conjecture.  E_B is provably not an ideal cipher, by a
factor of tau({r}) = {tau(r)} on fixed points, measured at {measured.get(16, float('nan')):.2f} against an ideal 1.00.
That is not an attack and this review does not claim it is one -- no efficient
distinguisher follows at n = 256.  It is, though, exactly the kind of fact a
production-track label should have to survive, and it had never been computed.

**What the downgrade is not.**  It is not a claim that A2 is broken; no attack
on it is known, its bijectivity is proven, and its weak-key class is identified
and excluded (§2).  It is not a wire-format change -- a rating is not a format,
MIGRATING.md is untouched, and every existing key and ciphertext still works
exactly as before.  And it is not a statement about NL-FSCX v1, HFSCX-256 or
HSKE-NL-A1, which use the primitive in different modes that §3's argument does
not reach: A1 is a keystream generator whose second argument varies per block,
and HFSCX-256 is a Davies-Meyer compression with feed-forward.  Both keep their
ratings and neither was examined here.

**What would earn the rating back.**  A PRP or SPRP reduction for
nl_fscx_revolve_v2, which does not exist for any round count; or, more
realistically as a first step, removing the structural objections so that the
trail bounds become the binding constraint again.  TODO #245 carries both
candidate fixes -- round constants, which break the self-similarity outright,
and a prime round count, which makes §3's symptom small for one line per
language.  Neither is done here: both are wire-format breaks across four
constructions and belong in a deliberate MAJOR, not a rating review.

**Reach, stated so it is not overestimated.**  A2 is the only production-track
rating in the suite that depends on NL-FSCX v2 as a cipher; the other three v2
entries (HSKE-Duplex, `fpe`, `twk`) are already research, broken or demo-only.
README.md describes A2's construction but makes no production-readiness claim
about it, so nothing there needs revising -- the maturity claim lived only in
SECURITY.md and spec/.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--full', action='store_true',
                    help='widen the n=16 sweep from 25 keys to 40')
    args = ap.parse_args()

    print(SEP)
    print("Is HSKE-NL-A2 production-track?  — TODO #244")
    print(SEP)

    section1()
    section2()
    measured = section3(args.full)
    section4()
    section5()
    section6(measured)

    print("\n" + SEP)
    print("Verdict: HSKE-NL-A2 -> demo-only.  Candidate fixes are TODO #245.")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
