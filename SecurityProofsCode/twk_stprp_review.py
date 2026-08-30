#!/usr/bin/env python3
"""twk_stprp_review.py — TODO #243: should `twk` move off demo-only?

TODO #241 classified `twk` demo-only and named three reasons; TODO #242 (v4.0.0)
closed all three.  The row was deliberately not moved at the same time, because
reclassifying a protocol because the specific defects someone found have been
fixed mistakes "no known problems" for "analysed" -- the reasoning TODO #237 and
#238 were filed to undo.  This script is the review a promotion would need.

Sections
  1  What `twk` is now, and the definition it has to meet (STPRP)
  2  The reduction: in the random-oracle model `twk` is STPRP iff v2-revolve is
     an SPRP under a uniform key.  So the question is entirely about v2.
  3  A structural property of v2 that neither #241 nor #242 recorded: the
     construction is the iterate of ONE key-dependent permutation, with no round
     constant and no key schedule.  Three consequences, measured.
  4  Where `twk` is genuinely stronger than HSKE-NL-A2, and why that is not
     enough to promote it
  5  Verdict -- and the inconsistency it exposes in A2's own rating

Everything measurable here is measured at reduced widths against the same round
function the suite deploys, and the deployed suite is loaded via importlib so
the structural claims are checked against shipped code rather than a paraphrase.

Runtime is a few minutes; --full widens the n=16 order sweep from 10 keys to 25.

Run:  python3 SecurityProofsCode/twk_stprp_review.py [--full]
"""

import argparse
import importlib.util
import math
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


# ── the deployed round function, at reduced width ───────────────────────────
def make_round(n, B):
    """F_B(x) = M(x XOR B) + delta(B) mod 2^n, exactly as nl_fscx_v2 computes it."""
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


def _pin_against_suite():
    """The reduced-width model must agree with the shipped nl_fscx_v2 at n=256."""
    n = _SUITE.KEYBITS
    rng = random.Random(9931)
    bad = 0
    for _ in range(200):
        A = rng.getrandbits(n)
        B = rng.getrandbits(n)
        mine = make_round(n, B)(A)
        theirs = _SUITE.nl_fscx_v2(_SUITE.BitArray(n, A), _SUITE.BitArray(n, B)).uint
        if mine != theirs:
            bad += 1
    return bad


# ═══════════════════════════════════════════════════════════════════════════
def section1():
    rule("§1  What `twk` is now, and the definition it has to meet")
    print(f"""Since v4.0.0 (TODO #242):

    B      = HFSCX-256-DS(0x21, len(key)_be8 || key || sector_be64 || bidx_be32)
    C      = nl_fscx_revolve_v2(P, B, R_VALUE)        R_VALUE = {_SUITE.R_VALUE}

A tweakable block cipher's standard target is **STPRP** -- strong tweakable
pseudorandom permutation.  The adversary picks tweaks and makes both encryption
and decryption queries, adaptively, and must not distinguish the construction
from an independent uniform permutation for each tweak.  "Strong" (both
directions) is the right variant here: `twk --decrypt` is a shipped subcommand,
so the decryption oracle is not hypothetical.

Nothing in the repository has ever argued `twk` meets it.  #241 classified it,
#242 fixed three defects in it, and neither made a positive claim.  A promotion
needs one.""")


# ═══════════════════════════════════════════════════════════════════════════
def section2():
    rule("§2  The reduction: it is entirely a question about v2")
    print("""Model HFSCX-256-DS as a random oracle.  Distinct tweaks then give
independent, uniformly distributed subkeys B, and the adversary cannot steer
any of them without the key: B is a hash output over a length-prefixed,
domain-separated input, so distinct (key, sector, bidx) triples give unrelated
subkeys and no collision is reachable by choosing tweaks.

Under that model `twk` is exactly: one independent instance of
nl_fscx_revolve_v2 under a uniform key, per tweak.  So

    twk is an STPRP   <==>   F_B^r under uniform B is an SPRP

and the whole question reduces to a property of v2 that has nothing to do with
tweaks, sectors, or anything TODO #242 touched.  The reduction is the easy half;
the right-hand side is the part with no answer.

Two things follow immediately, and they point in opposite directions:

  * `twk` cannot be rated ABOVE whatever v2-revolve deserves.  Its own
    machinery adds no security, only isolation (§4).
  * `twk` also should not be rated below it.  The three defects #241 found were
    all in the derivation, and all are gone.

So the honest question is not "has twk earned a promotion" but "what is
v2-revolve actually worth", which is the same question HSKE-NL-A2's rating
already answers -- and §3 is why that answer deserves re-examination.""")


# ═══════════════════════════════════════════════════════════════════════════
def section3(full):
    rule("§3  v2-revolve is the iterate of ONE permutation, with no round constant")
    pinned = _pin_against_suite()
    print(f"""Read off the shipped code, in all three languages:

    C       for (i = 0; i < steps; i++) nl_fscx_v2_ba(&buf[1-idx], &buf[idx], b);
    Go      for i := 0; i < steps; i++ {{ result = NlFscxV2(result, b) }}
    Python  for _ in range(steps): result = fscx(result, B) + delta

The loop index never enters the round function.  Neither does a round constant,
and there is no key schedule -- the same B is the XOR mask in every one of the
{_SUITE.R_VALUE} rounds.  The cipher is therefore F_B^r for a single fixed bijection

    F_B(x) = M(x XOR B) + delta(B) mod 2^n.

This is a design property that block ciphers deliberately avoid, and round
constants exist precisely to avoid it.  #214 noticed the key reuse and flagged
its bounds as key-averaged for that reason; what follows is what the structure
costs beyond the bounds.

  Reduced-width model pinned against the shipped nl_fscx_v2 at n = 256:
      {200 - pinned}/200 agree{'' if pinned == 0 else '   *** MISMATCH -- everything below is void ***'}
""")

    # (a) the catastrophic case: does F^r collapse to the identity?
    print("  (a) Does F_B^r degenerate?  If ord(F_B) divides r, the cipher IS the")
    print("      identity map.  Exhaustive cycle decomposition at small widths:\n")
    print(f"      {'n':>3}  {'trials':>6}  {'min ord':>12}  {'median ord':>18}  {'ord | 192':>10}")
    print("      " + SEP2[:62])
    # n=12 is deliberately absent: M = I + ROL + ROR is SINGULAR at n=12, so
    # F_B is not a bijection there and a cycle decomposition is meaningless.
    # An earlier version of this script measured it anyway and published the
    # result; TODO #245 §0 corrected that.  M is invertible at 8, 16 and 256.
    widths = [(8, 300), (16, 25 if full else 10)]
    degenerate = {}
    for n, trials in widths:
        rng = random.Random(243 + n)
        N = 1 << n
        orders = []
        for _ in range(trials):
            B = rng.randrange(N)
            F = make_round(n, B)
            T = [F(a) for a in range(N)]
            seen = bytearray(N)
            o = 1
            for s in range(N):
                if seen[s]:
                    continue
                c = 0
                x = s
                while not seen[x]:
                    seen[x] = 1
                    x = T[x]
                    c += 1
                o = o * c // math.gcd(o, c)
            orders.append(o)
        orders.sort()
        d = sum(1 for v in orders if _SUITE.R_VALUE % v == 0)
        degenerate[n] = d / trials
        print(f"      {n:>3}  {trials:>6}  {orders[0]:>12}  {orders[len(orders)//2]:>18}  "
              f"{d:>4}/{trials:<5}")
        sys.stdout.flush()

    print(f"""
      At n = 8, {degenerate.get(8, 0):.1%} of keys give ord(F_B) | {_SUITE.R_VALUE} -- for those keys
      encryption is the IDENTITY MAP.  It thins out with width but does NOT
      vanish: remeasured at 300 keys, n = 16 still shows it at about 1/300
      (TODO #245 §3; an earlier 10-key sample here missed it).  It does not
      not a finding against the deployed parameters.  It is a finding about
      reduced-width use of this construction, and the suite HAS reduced-width
      targets: the Arduino and assembly ports run these primitives at 32 bits.""")

    # n = 32 cannot be enumerated, but degeneracy is cheap to DISPROVE: one cycle
    # whose length does not divide r is enough to show ord(F_B) does not either.
    print("      Checking the 32-bit ports directly.  ord(F_B) cannot be computed at")
    print("      n = 32, but one cycle of length not dividing r rules out the")
    print("      identity case:\n")
    rng32 = random.Random(4321)
    r = _SUITE.R_VALUE
    ruled_out = 0
    trials32 = 12
    for _ in range(trials32):
        B = rng32.randrange(1 << 32)
        F = make_round(32, B)
        for _ in range(4):
            x0 = rng32.randrange(1 << 32)
            power = lam = 1
            tortoise = x0
            hare = F(x0)
            capped = False
            while tortoise != hare:
                if power == lam:
                    tortoise = hare
                    power *= 2
                    lam = 0
                hare = F(hare)
                lam += 1
                if lam > 4 * r:
                    capped = True
                    break
            if capped or (r % lam != 0):
                ruled_out += 1
                break
    print(f"      identity case ruled out for {ruled_out}/{trials32} random 32-bit keys")
    if ruled_out == trials32:
        print("      -- the n = 8 degeneracy does not reach the 32-bit ports either.")
    else:
        print("      *** some 32-bit keys were NOT ruled out; investigate before")
        print("      *** running v2-revolve at that width.")

    # (b) slide structure
    print("\n  (b) Self-similarity.  Because every round is the same map, E_B = F_B^r")
    print("      commutes with F_B, and a slid pair (P, F_B(P)) propagates through")
    print("      the whole cipher: C' = F_B(C).  The question is what one slid pair")
    print("      is worth to an attacker who has it.  Brute-forcing B at n = 16:\n")
    n = 16
    N = 1 << n
    rng = random.Random(7)
    one, two = [], []
    for _ in range(12):
        Bt = rng.randrange(N)
        Ft = make_round(n, Bt)
        P1 = rng.randrange(N)
        Q1 = Ft(P1)
        c1 = [B for B in range(N) if make_round(n, B)(P1) == Q1]
        P2 = rng.randrange(N)
        Q2 = Ft(P2)
        c2 = [B for B in c1 if make_round(n, B)(P2) == Q2]
        assert Bt in c2
        one.append(len(c1))
        two.append(len(c2))
    print(f"      candidate keys consistent with 1 slid pair : mean {sum(one)/len(one):.2f} of 2^{n}")
    print(f"      candidate keys consistent with 2 slid pairs: mean {sum(two)/len(two):.2f} of 2^{n}")
    print("""
      One slid pair very nearly determines the key; two determine it.  So the
      information-theoretic barrier to a slide attack is only the cost of
      FINDING a slid pair, which by the birthday bound is about 2^(n/2) known
      plaintexts under one key -- 2^128 at n = 256.

      Two honest qualifications, because this is the point at which it would be
      easy to overclaim.  First, 2^128 data under a single tweak is not a
      practical attack, and at n = 256 it sits at rather than below the
      128-bit target.  Second, "a slid pair determines B" is measured here by
      brute force; it is NOT the same as an efficient algorithm to extract B
      from a slid pair.  Doing that means solving M(P XOR B) + delta(B) = P'
      for B, where delta is quadratic in B over a mixed XOR/add structure.
      This script does not solve it and does not claim it is solvable.  Whether
      the slide attack costs 2^128 or is blocked by that step is open.""")

    # (c) the consequence that matters for the rating
    print(f"""
  (c) The consequence for the round count.  A slide attack's cost does not
      depend on r at all -- 64 rounds, {_SUITE.R_VALUE} rounds, or ten thousand, the
      structure and the birthday bound are identical.  This matters for how
      the last two items should be read:

        * #214's "137 rounds to reach 2^-256" is a statement about differential
          trails, and only about those.
        * #242 moved fpe/twk from 64 to {_SUITE.R_VALUE} rounds on the strength of it.  That
          change is still right -- it closed a real gap against the trail class
          and cost nothing -- but it bought exactly zero against self-similarity,
          and nothing in #241, #242 or #214 says so.

      A cipher whose security stops improving with rounds against a whole
      attack class, because it omits the round constants that would break the
      self-similarity, is not one to rate production-track on the strength of
      a trail bound.""")
    return degenerate


# ═══════════════════════════════════════════════════════════════════════════
def section4():
    rule("§4  Where `twk` is genuinely stronger than HSKE-NL-A2")
    print("""Both are F_B^192 over the same primitive, so §3 applies to both equally.
They differ in where B comes from, and the difference is real and in `twk`'s
favour -- which is worth stating plainly, because the rest of this review is
negative and the asymmetry is not.

  HSKE-NL-A2   B is the caller's key.  Recovering B is total key compromise:
               every message under that key, past and future.
  twk          B = HFSCX-256-DS(0x21, ... || key || sector || bidx).  Recovering
               B compromises ONE (sector, block index) under one key, and does
               not yield the key -- inverting the derivation is a preimage
               problem on HFSCX-256-DS.  Other tweaks are unaffected.

So the 2^128-data slide structure of §3, if it were ever realised as an attack,
buys an attacker one disk block under `twk` and an entire session under A2.
Two further asymmetries point the same way: the degenerate affine key class is
unreachable in `twk` because B is a hash output rather than caller-supplied,
and `twk`'s determinism is per-tweak and expected (XTS-style) where A2's is a
documented constraint on multi-message use.

That is a better security posture on three axes.  It is still not a promotion,
because none of it is evidence that F_B^192 is an SPRP -- it is evidence that
the consequences of it not being one are contained.  Confining the blast radius
of an unproven assumption is worth documenting; it is not worth calling
production-track.""")


# ═══════════════════════════════════════════════════════════════════════════
def section5(degenerate):
    rule("§5  Verdict")
    print(f"""**`twk` stays demo-only.**  Not because the TODO #241 blockers are still
open -- all three are closed -- but because the positive result a promotion
needs does not exist.  By §2 the entire question is whether F_B^r is an SPRP
under a uniform key, and the evidence for that is:

  * key-averaged differential trail bounds (#214), which #214 itself labels as
    an order-of-magnitude indication rather than a bound, and which are
    key-averaged precisely because the construction reuses one key every round;
  * no reduction to a standard definition, of any kind, anywhere;
  * and now §3: a self-similar structure with no round constants, against which
    the round count -- the one parameter anybody has tuned -- does nothing.

The right verdict on that evidence is "unproven", and the right label for
unproven is demo-only.

**The inconsistency this exposes.**  HSKE-NL-A2 is rated "Production-track
(conjectured), with two constraints", and rests on precisely the same
unproven claim about precisely the same permutation at precisely the same round
count -- with strictly worse consequences if the claim fails (§4), since there
B is the key itself.  Those two ratings cannot both be right.  TODO #243
anticipated this outcome and said so: the honest conclusion may be that A2's
rating is the one that needs re-examining, not that `twk` needs promoting.  It
is.

This review does not unilaterally downgrade A2.  A rating change deserves its
own item rather than a paragraph in someone else's, and A2's row carries two
specific constraints that a re-rating has to re-derive rather than inherit.
Filed as TODO #244.

Worth noting how contained that item is, because it is smaller than it sounds.
Four things in SECURITY.md rest on NL-FSCX v2 -- HSKE-NL-A2, HSKE-Duplex,
`fpe` and `twk` -- and three of them are already rated research, broken or
demo-only.  HSKE-NL-A2 is the ONLY production-track rating anywhere in the
suite that depends on this permutation.  (HPKS-NL / HPKE-NL name NL-FSCX too,
but their demo-only rating comes from Pohlig-Hellman on the GF(2^n)* group and
does not depend on v2's strength at all, so #244 cannot make them worse.)

What `twk`'s row should say, and now does: the #241 blockers are closed, what
remains is the absence of a positive result, and the specific missing result is
an SPRP argument for v2-revolve -- shared with HSKE-NL-A2 and tracked there.""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--full', action='store_true',
                    help='widen the n=16 order sweep from 10 keys to 25')
    args = ap.parse_args()

    print(SEP)
    print("Should `twk` move off demo-only?  — TODO #243")
    print(SEP)

    section1()
    section2()
    degenerate = section3(args.full)
    section4()
    section5(degenerate)

    print("\n" + SEP)
    print("Verdict: twk stays demo-only.  A2's rating is the open question (TODO #244).")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
