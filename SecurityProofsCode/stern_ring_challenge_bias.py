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
import os
import random
import re
import sys

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
    print("  At the DEMO default of 32 rounds per signature (production is SDF_ROUNDS")
    print("  = 219, where it takes ~7x fewer signatures), that is")
    print("  roughly n_challenge_draws / 32 signatures from the SAME ring needed before")
    print("  the skew becomes statistically visible per slot.")


def section4_fix_shipped():
    print()
    print(SEP)
    print("4. The fix, and whether it is still in place")
    print(SEP)
    print("  FIXED in v1.9.127 (TODO #164).  Until TODO #291 this section still read")
    print("  \"Recommended fix ... Tracked as TODO #164\" in the present tense, four")
    print("  years of releases after the fix shipped -- so a reader met a live")
    print("  anonymity leak that no longer existed.  What shipped: `stern_ring_sign`")
    print("  (herradura.h) and `hpks_stern_ring_sign` (the Python suite) now REJECT")
    print("  the byte 255 and reduce the rest, giving exactly 85/85/85.")
    print()
    print("  So the useful thing this script can do now is check the fix is still")
    print("  there.  That is a SOURCE check and is stated as one: the biased shape")
    print("  is one byte reduced mod 3 with nothing rejected, and the REJECTION's")
    print("  presence in every port that draws this trit is what is asserted.")
    print()
    print("  TODO #297 moved the anchor and WIDENED the check, and the move is why")
    print("  this gate failed rather than drifting: until then the trit was written")
    print("  INLINE in all four ports, this section grepped two files for two")
    print("  hand-written shapes, and #297 extracted a named sampler in each -- so")
    print("  the literal `if (rnd1 != 255) break;` vanished from herradura.h while")
    print("  the fix it stood for was still there.  A source check anchored on a")
    print("  spelling fails when the spelling moves; that is the failure mode it")
    print("  has, and the repair is to anchor it on the named helper instead.")
    print()
    print("  #297 also RETIRED the other half of this section's old prose.  It said")
    print("  Go and the Arduino code \"were never affected -- they reduce a 32-bit")
    print("  draw, bias ~2^-32\", and both halves were wrong in detail: Go reduced a")
    print("  whole n-BIT draw (n = 256, so bias ~2^-256, and 32 bytes per trit), and")
    print("  the Arduino port draws no challenge trit AT ALL -- its simulated member")
    print("  is hardcoded to b = 0, so it has nothing to bias.  Java drew")
    print("  Random.nextInt(3), unbiased by a different route again.  Three correct")
    print("  schemes and one wrong one for a single trit is the asymmetry #297")
    print("  removed by adopting this rejection sampler in all four.")
    print()
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    # Anchored on the HELPER, not on a spelling of its body: each entry names the
    # file, the regex that finds the extracted sampler's definition, and the
    # rejection that must appear inside it.  A port that loses the helper and a
    # port that keeps the helper but drops the rejection are different failures,
    # and this reports which.  Arduino is absent on purpose -- it draws no trit.
    targets = [
        ("Python suite", "Herradura cryptographic suite.py",
         r"def _stern_ring_trit\b", r"if v != 255", r"\ndef "),
        ("herradura.h", "herradura.h",
         r"stern_ring_trit\s*\(FILE", r"if \(v != 255\)", r"\n\}"),
        ("Go suite", os.path.join("herradura", "herradura.go"),
         r"func sternRingTrit\b", r"if b\[0\] != 255", r"\n\}"),
        ("Java suite", os.path.join("bindings", "java", "herradurakex",
                                    "SternRing.java"),
         r"int ringTrit\s*\(", r"if \(v != 255\)", r"\n    \}"),
    ]
    ok = True
    for label, rel, defpat, rejpat, endpat in targets:
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
        except OSError:
            print(f"  {label:<14} NOT READABLE from here -- not checked this run")
            continue
        mdef = re.search(defpat, src)
        if mdef is None:
            ok = False
            print(f"  {label:<14} sampler NOT FOUND (no match for {defpat!r})")
            continue
        # The helper's body only: from its definition to the start of whatever
        # follows it at top level.  Scoping it matters -- every one of these
        # files contains an unrelated 255 somewhere, so a whole-file search
        # would keep passing after the rejection was deleted.
        mend = re.search(endpat, src[mdef.end():])
        body = src[mdef.end():mdef.end() + (mend.start() if mend else len(src))]
        found = re.search(rejpat, body) is not None
        ok = ok and found
        print(f"  {label:<14} rejection sampling present: {found}")
    return ok


def main():
    rng = random.Random(0xC0DE_1590)
    counts = section1_exact_distribution()
    section2_monte_carlo(5_000_000, rng)
    section3_distinguishing_cost()
    fix_in_place = section4_fix_shipped()

    findings = [
        # The arithmetic the whole item rested on: 256 = 3*85 + 1.
        ("byte % 3 is 86/85/85, not uniform", counts == [86, 85, 85]),
        # And the fix that removed it is still in both files that carried it.
        ("the rejection-sampling fix of TODO #164 is still in place", fix_in_place),
    ]
    bad = [name for name, ok in findings if not ok]
    print()
    if bad:
        print("*** FAILED: %d finding(s) stopped reproducing: %s ***"
              % (len(bad), ", ".join(bad)))
    else:
        print("*** OK: all %d findings reproduce ***" % len(findings))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
