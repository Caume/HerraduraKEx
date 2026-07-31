#!/usr/bin/env python3
"""
stern_ring_challenge_bias.py — TODO #159 LLM-assisted stress-testing finding, tracked
as TODO #164: modulo-3 bias in HPKS-Stern-Ring's non-signer challenge simulation is a
statistical anonymity leak under repeated use of the same ring.

BACKGROUND

HPKS-Stern-Ring (herradura.h's `stern_ring_sign` / the suite's `hpks_stern_ring_sign`)
OR-composes k Stern identification instances via Fiat-Shamir challenge splitting: for
each round r, the k per-member ternary challenges b[i,r] in {0,1,2} must sum to a joint,
hash-derived challenge mod 3. For every non-signer member i != j, the code pre-chooses
b[i,r] by drawing ONE random byte and reducing mod 3:

    C:      b_pre = (int)(rnd1 % 3u);                          (herradura.h)
    Python: b = int.from_bytes(os.urandom(1), 'big') % 3       ("Herradura cryptographic
                                                                  suite.py", hpks_stern_
                                                                  ring_sign)

256 is not divisible by 3, so this draw is NOT uniform: value 0 occurs with probability
86/256 while values 1 and 2 each occur with probability 85/256 -- a ~0.39% skew. (Go's
implementation reduces a full 32-bit random value mod 3 instead of a single byte, giving
a ~2^-32 bias -- negligible. The C and Python implementations are the ones affected.)

WHY THIS MATTERS FOR ANONYMITY, NOT JUST "A MODULO BIAS"

TODO #2 previously fixed an analogous %q bias in `_rnl_rand_poly` purely for uniformity
of a *secret* value's distribution. This one is different in kind: the *real signer's*
displayed per-round challenge b[j,r] is NOT drawn from this biased process at all -- it
is forced to whatever value makes the round's challenges sum to the joint (Fiat-Shamir,
hash-derived, effectively uniform and independent of the simulation draws) challenge:

    b[j,r] = (joint[r] - sum_{i!=j} b[i,r]) mod 3

Because joint[r] is (modeled as) uniform over {0,1,2} independent of the non-signers'
draws, b[j,r]'s own marginal distribution is *exactly* uniform -- the difference of an
independent uniform value and anything else, reduced mod 3, is uniform. So the real
signer's slot looks perfectly uniform round to round, while every non-signer's slot
carries the small 86/85/85 skew. A verifier (or any observer with per-signature access
to which challenge value appeared in which member-slot) who collects enough signatures
FROM THE SAME RING can in principle test each slot's per-round challenge distribution
against the ideal uniform distribution and flag the one slot that fits "too well" (no
skew) as more likely to be the signer -- a statistical anonymity leak specific to rings
that are reused across many signatures (the scenario ring signatures are meant to protect
identity in, e.g. long-lived anonymous credentials or whistleblowing channels).

This script (1) confirms the exact single-byte %3 distribution and its Monte Carlo
frequency, (2) estimates the number of same-ring signatures required to distinguish a
non-signer slot from the signer's slot at a given confidence, and (3) recommends the
fix already used elsewhere in this codebase for TODO #2 (rejection sampling, or simply
matching Go's wide-value-then-%3 reduction, whose bias is negligible at ~2^-32).

Usage: python3 SecurityProofsCode/stern_ring_challenge_bias.py
"""
import random

SEP = "=" * 72


def section1_exact_distribution():
    print(SEP)
    print("1. Exact distribution of (single random byte) % 3")
    print(SEP)
    counts = [0, 0, 0]
    for v in range(256):
        counts[v % 3] += 1
    total = 256
    for val, c in enumerate(counts):
        print(f"  P(challenge={val}) = {c}/{total} = {c/total:.6f}"
              f"  (ideal 1/3 = {1/3:.6f}, delta={c/total - 1/3:+.6f})")
    return counts


def section2_monte_carlo(trials, rng):
    print()
    print(SEP)
    print(f"2. Monte Carlo confirmation over {trials:,} draws")
    print(SEP)
    tally = [0, 0, 0]
    for _ in range(trials):
        tally[rng.randrange(256) % 3] += 1
    for val, c in enumerate(tally):
        print(f"  empirical P(challenge={val}) = {c/trials:.6f}")


def section3_distinguishing_cost():
    print()
    print(SEP)
    print("3. Same-ring signatures needed to distinguish a non-signer slot")
    print("   (biased 86/85/85) from the signer's slot (exactly uniform)")
    print(SEP)
    p_true = 86 / 256
    p_null = 1 / 3
    delta = p_true - p_null
    for z, conf in ((2.0, "~95%"), (3.0, "~99.7%")):
        n_challenge_draws = (z ** 2) * p_null * (1 - p_null) / delta ** 2
        print(f"  z={z} ({conf} one-tail confidence): "
              f"~{n_challenge_draws:,.0f} challenge draws needed for slot value 0")
    print()
    print("  At SDF_ROUNDS=32 (C/Go/Python production rounds per signature), that is")
    print("  roughly n_challenge_draws / 32 signatures from the SAME ring needed before")
    print("  the skew becomes statistically visible per slot.")


def section4_recommendation():
    print()
    print(SEP)
    print("4. Recommended fix")
    print(SEP)
    print("  Match the already-negligible-bias pattern this codebase uses elsewhere:")
    print("    - Go's own stern-ring code already reduces a full 32-bit random value")
    print("      mod 3 (bias ~2^-32) instead of a single byte -- C/Python should match it,")
    print("      or")
    print("    - Apply the same rejection-sampling fix as TODO #2's _rnl_rand_poly bias")
    print("      (draw byte v, reject v >= 255, i.e. threshold = 255 - 255%3 = 255,")
    print("      leaving exactly 85 acceptable residues per value -- trivial, ~0.4%")
    print("      rejection rate).")
    print("  Tracked as TODO #164.")


def main():
    rng = random.Random(0xC0DE_1590)
    section1_exact_distribution()
    section2_monte_carlo(5_000_000, rng)
    section3_distinguishing_cost()
    section4_recommendation()


if __name__ == "__main__":
    main()
