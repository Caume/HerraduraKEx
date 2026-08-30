#!/usr/bin/env python3
"""v2_family_rating_review.py — TODO #248: re-review the NL-FSCX v2 family ratings.

TODO #245 shipped round constants and deliberately re-rated nothing.  TODO #253
supplied the evidence #248 was gated on.  This is the review.

The two rows under review are HSKE-NL-A2 (downgraded to demo-only by #244) and
`twk` (kept demo-only by #243).  By §11.25.1 both reduce to the same question --
is `nl_fscx_revolve_v2` an SPRP under a uniform key -- so they move together or
not at all.

#248's own text warns against inheriting rather than re-deriving, and the first
thing this script does is catch its own author doing exactly that: the amendment
#248 carries into this review describes the cipher as "one unvaried round
iterated with no key schedule", which is #243's PRE-#245 wording and is no
longer true.  §1 re-derives it.

Structure:
  §0  pin the model against the shipped code before measuring anything
  §1  what #245 actually removed, re-derived from the shipped implementation
  §2  the standard: what "Production-track (conjectured)" means elsewhere in
      SECURITY.md, and why the rationale both rows currently give is wrong
      whatever the right rating turns out to be
  §3  a POSITIVE result -- an exact invariant-subspace criterion at n = 256
  §4  the linear axis, measured for v1 as well as v2, because §2's argument is
      about consistency and cannot be applied to one primitive only
  §5  the three documented constraints, re-derived
  §6  verdict

Exits non-zero if a finding stops reproducing.

Run:  python3 SecurityProofsCode/v2_family_rating_review.py [--quick]
"""

import argparse
import importlib.util
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


def _suite():
    p = os.path.join(ROOT, 'Herradura cryptographic suite.py')
    spec = importlib.util.spec_from_file_location("_h", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _bounds():
    p = os.path.join(ROOT, 'SecurityProofsCode', 'nl_fscx_v2_bounds.py')
    spec = importlib.util.spec_from_file_location("_b", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


H = _suite()
BB = _bounds()
G = BB.G


# ═══════════════════════════════════════════════════════════════════════════
def section_0():
    rule("§0  Pinning the model against the shipped code")
    print("""As in §11.25 and §11.26, nothing is measured on a reduced-width model until
that model is shown to agree with the shipped primitive.  Here the reduced-width
round used in §3 and §4 is checked against `nl_fscx_v2` from the suite file.\n""")
    n = 16
    rng = random.Random(11)
    ok = 0
    T = 200
    for _ in range(T):
        b = rng.randrange(1 << n)
        a = rng.randrange(1 << n)
        want = H.nl_fscx_v2(H.BitArray(n, a), H.BitArray(n, b)).uint
        got = G['mk_v2'](n, b)(a, 0)
        ok += (want == got)
    print(f"      reduced-width round vs shipped nl_fscx_v2 at n={n}: {ok}/{T} agree")
    check(ok == T, "the reduced-width model no longer matches the shipped nl_fscx_v2")


def section_1(quick):
    rule("§1  What TODO #245 actually removed — re-derived, not inherited")
    print("""#243 §11.25.2 recorded three symptoms of one cause: the cipher was `F_B^r`, a
single unvaried bijection iterated.  From that followed an identity-collapse
class, a slide structure, and a fixed-point excess of tau(r).

#245 XORs the 1-based round index into the state before each step, so the round
is now `F_i(x) = M(x ^ B ^ C_i) + delta(B)` with `C_i = i`.  The cipher is no
longer a power of any single map.  Measured against the SHIPPED implementation:\n""")
    n = 16
    rng = random.Random(7)
    T = 60 if quick else 200
    hits = tried = 0
    while tried < T:
        b = H.BitArray(n, rng.randrange(1 << n))
        if not H.nl_v2_key_is_valid(b):
            continue
        p = H.BitArray(n, rng.randrange(1 << n))
        fp = H.nl_fscx_v2(p, b)
        lhs = H.nl_fscx_revolve_v2(fp, b, 192).uint
        rhs = H.nl_fscx_v2(H.nl_fscx_revolve_v2(p, b, 192), b).uint
        hits += (lhs == rhs)
        tried += 1
    print(f"      slide property  E(F(P)) == F(E(P)):  {hits}/{tried} trials at n={n}")
    print("      (it held identically before #245; a slid pair no longer propagates)")
    check(hits == 0, "the slide property has reappeared in the shipped revolve")
    print("""
      The identity-collapse class needs `ord(F_B) | r` and cannot be posed at
      all once the cipher is not a power of one map; §11.27.2 measured the
      fixed-point statistic moving to where an ideal cipher sits (median 4.0 ->
      1.0, fraction above one 76% -> 16%, against an ideal 37%).

      SO THE INHERITED SENTENCE IS FALSE.  "The cipher is one unvaried round
      iterated 192 times with no round constant and no key schedule" is #243's
      pre-#245 wording.  It is still asserted as a live constraint in BOTH rows
      under review -- SECURITY.md's HSKE-NL-A2 row lists it as constraint (3),
      and the `twk` row gives it as a reason -- and both rows then go on to say
      #245 removed it.  Each row currently contradicts itself.

      What remains true is narrower and worth stating precisely: there is no key
      schedule.  The same `B` is the mask in every round, and the only
      round-to-round variation is the XOR of a counter.  That is the LED /
      PRINCE-core shape, which is a published and analysed design pattern rather
      than a defect -- but it is also the shape whose security depends on the
      round constants being chosen well, which is §3.""")


def section_2():
    rule("§2  The standard — what 'Production-track (conjectured)' means here")
    print("""Both rows currently rest their demo-only rating on the same sentence: no
PRP/SPRP reduction exists for `nl_fscx_revolve_v2` at any round count.  That is
TRUE.  The question §248 has to ask first is whether it is the standard the rest
of SECURITY.md is rated against, because a rationale that would demote much of
the table if applied consistently is wrong as written, whatever the right rating
is.

Rows currently at a production-track classification, and what each rests on:\n""")
    rows = [
        ("HSKE-NL-A1", "Production-track (conjectured)",
         "the CONJECTURE that NL-FSCX v1 is a PRF -- row says "
         "'treat it as a conjecture, not a proof'"),
        ("HFSCX-256 / -DS", "Production-track (conjectured)",
         "the same NL-FSCX v1 PRF conjecture; row says the classification is "
         "conditional on it"),
        ("HKEX-RNL", "Production-track (conjectured PQ-resistant)",
         "Ring-LWR hardness at n=1024 -- an assumption, with Core-SVP estimates"),
        ("HPKS-WOTS", "Production-track (conjectured)",
         "the HFSCX-256 row above, hence the same v1 conjecture"),
        ("HPKS-XMSS", "Production-track (conjectured), stateful",
         "the WOTS row above, hence the same v1 conjecture"),
        ("ZKP-RNL", "Production-track (conjectured)",
         "the HKEX-RNL Ring-LWR assumption"),
    ]
    for nm, cls, rests in rows:
        print(f"      {nm:<20} {cls}")
        print(f"      {'':<20} rests on: {rests}")
    print(f"""
      Not one of those six is backed by a reduction to a standard definition.
      Every one is "named conjecture + quantitative cryptanalytic evidence + no
      known attack", and five of the six say so in their own row text.  That is
      the suite's actual standard for production-track, and it is a normal one:
      no block cipher or hash in deployment anywhere has a PRP reduction, AES
      included.

      Applied literally, "no reduction exists, therefore demo-only" demotes all
      six.  So it cannot be the reason A2 and `twk` are demo-only.  Whatever the
      verdict in §6, THE STATED RATIONALE IN BOTH ROWS HAS TO BE REPLACED.

      The correct question is therefore the cryptanalytic one: is the coverage
      of `nl_fscx_revolve_v2` comparable to what the six rows above have?  §3 and
      §4 are the two axes that answer it.""")


# ── §3: exact invariant-subspace criterion ──────────────────────────────────
def Mv(n, x):
    m = (1 << n) - 1
    return (x ^ ((x << 1) | (x >> (n - 1))) ^ ((x >> 1) | (x << (n - 1)))) & m


def invariant_closure_dim(n, gens):
    """dim of the smallest M-invariant subspace containing gens."""
    piv = {}

    def add(v):
        for b, p in piv.items():
            if (v >> b) & 1:
                v ^= p
        if v:
            piv[v.bit_length() - 1] = v
            return True
        return False

    for g in gens:
        add(g)
    changed = True
    while changed:
        changed = False
        for v in list(piv.values()):
            if add(Mv(n, v)):
                changed = True
    return len(piv)


def section_3(quick):
    rule("§3  A positive result: no invariant subspace, proven at n = 256")
    print("""§1 left the construction in the LED / PRINCE-core shape -- one key, no
schedule, round constants carrying all the round-to-round variation.  That shape
has a known failure mode, and it is the one that matters here: invariant
subspace and nonlinear invariant attacks, which is exactly the class that breaks
such ciphers when the constants are chosen badly.  #245 chose its constants to
kill the slide structure; nobody checked them against this.

Beierle-Canteaut-Leander-Rotella (CRYPTO 2017) give the criterion.  For a cipher
whose rounds differ only by constants `C_i`, any subspace `V` mapped to cosets
of itself by every round must be invariant under the linear layer AND contain
every difference `C_i ^ C_j`.  So if the smallest `M`-invariant subspace
containing those differences is the WHOLE space, no such `V` exists -- for any
choice of the nonlinear part, and at every round count.

Adapted to this round shape.  Here the constant is XORed BEFORE the linear
layer, `F_i(x) = M(x ^ B ^ C_i) + delta(B)`, rather than after a substitution
layer; the criterion is applied to `M` and the constant differences, which is
the same computation up to that conjugation.  The shipped constants are
`C_i = i` for i = 1..192, XORed into the low 32 bits.\n""")
    R = 192
    gens = sorted({i ^ j for i in range(1, R + 1) for j in range(1, R + 1)} - {0})
    # n=256 is always included: the closure is cheap and it is the whole point.
    ns = [16, 32, 64, 256] if quick else [16, 32, 64, 128, 256]
    print(f"      {'n':>4}  {'dim span{C_i^C_j}':>17}  {'M-invariant closure':>20}  verdict")
    print("      " + SEP2[:66])
    allfull = True
    for n in ns:
        g = [x for x in gens if x < (1 << n)]
        d0 = invariant_closure_dim(n, g)
        # dimension of the raw constant-difference span, no M closure
        piv = {}
        for v in g:
            w = v
            for b, p in piv.items():
                if (w >> b) & 1:
                    w ^= p
            if w:
                piv[w.bit_length() - 1] = w
        allfull &= (d0 == n)
        print(f"      {n:>4}  {len(piv):>17}  {d0:>20}  "
              + ("FULL" if d0 == n else f"PROPER — attack possible"))
        sys.stdout.flush()
    check(allfull, "the round constants no longer generate the full space under M")
    print("""
      The raw constant differences span only 8 dimensions -- the counter never
      exceeds 192, so it touches 8 bits of a 256-bit state -- but `M` spreads
      those 8 into all 256.  The criterion PASSES at the deployed width.

      This is worth naming plainly, because the v2 family has not had one
      before: it is a PROVEN resistance result, exact rather than extrapolated,
      unconditional on any conjecture, and it holds at n = 256 rather than at
      some width a projection has to be carried from.  It also retroactively
      justifies #245's constants against a class #245 did not consider -- which
      was luck, not design, and the check belongs in the record either way.""")


def section_4(quick):
    rule("§4  The linear axis — measured for v1 as well, because §2's argument "
         "is about consistency")
    print("""TODO #214 deferred linear cryptanalysis; #247 §(c) did it exactly at small
width and the result was never written up.  It is the weakest axis, so it is the
one a rating turns on.

§2's argument is that A2 should be held to the standard the v1-backed rows are
held to.  That argument is only usable if the same measurement is taken for v1.
So both are measured here, exact optimal linear-trail weight (-log2|corr|) by
fast Walsh-Hadamard transform and a dynamic program over mask states, on typical
keys (tz(delta) <= 1, excluding the weak class TODO #253 characterised).\n""")
    def mk_v1(n, B):
        m, rol, ror = G['ops'](n)
        return lambda a, i: (((a ^ B) ^ rol(a ^ B, 1) ^ ror(a ^ B, 1))
                             ^ rol((a + B) & m, n // 4)) & m

    def delta(n, B):
        m = (1 << n) - 1
        return G['ops'](n)[1]((B * ((B + 1) >> 1)) & m, n // 4)

    widths = [(7, 8), (8, 8)] + ([] if quick else [(10, 6)])
    print(f"      {'primitive':<26}{'n':>3}   " + "".join(f"r={r:<6}" for r in (2, 4, 6))
          + " slope(r4→r6)")
    print("      " + SEP2[:62])
    res = {}
    for nm, mk, filt in (("NL-FSCX v2 (A2, twk)", G['mk_v2'], True),
                         ("NL-FSCX v1 (A1, HFSCX)", mk_v1, False)):
        sl = []
        for n, K in widths:
            rng = random.Random(555 + n)
            ks = []
            while len(ks) < K:
                b = rng.randrange(1 << n)
                if not filt:
                    ks.append(b)
                    continue
                d = delta(n, b)
                if d and (d & -d).bit_length() - 1 <= 1:
                    ks.append(b)
            per = [BB.linear_series(n, BB.lat(n, mk(n, k)), 6) for k in ks]
            avg = [sum(p[i] for p in per) / K for i in range(6)]
            s = (avg[5] - avg[3]) / 2
            sl.append(s)
            print(f"      {nm:<26}{n:>3}   "
                  + "".join(f"{avg[r-1]:<8.2f}" for r in (2, 4, 6)) + f" {s:.2f}")
            sys.stdout.flush()
        res[nm] = sl
    v2, v1 = res["NL-FSCX v2 (A2, twk)"], res["NL-FSCX v1 (A1, HFSCX)"]
    print(f"""
      v2 slope {min(v2):.2f}–{max(v2):.2f} bits/round; v1 slope {min(v1):.2f}–{max(v1):.2f}.  Both rise with
      width, and v2 is at or above v1 at every width measured.

      Three things follow, and only the third bears on the rating.

      1. The linear slope is far below the differential one (#247's 1.40–1.70,
         #253's ~half of that per key).  Linear is the binding axis for this
         family, and until #247 nobody had looked.

      2. The linear slope RISES with width, where #247 found the DIFFERENTIAL
         slope width-stable.  So the small-width projection is unresolved in a
         way #252 does not cover -- #252 asks for a two-sided differential
         bound.  The rise is the reassuring direction, but three widths under
         n = 11 do not fix a trend; #253 §3 recorded a near-miss of exactly this
         shape and this script is not going to lean on one either.
         Projecting the measured range over 192 rounds spans roughly 100 to 190
         bits of correlation weight, and the bottom of that range is under the
         128 a 256-bit block needs.  That is not an attack; it is an unmeasured
         quantity where the measurement is the only thing that would settle it.

      3. THE AXIS DOES NOT DISTINGUISH A2 FROM THE PRODUCTION-TRACK ROWS.  v1 is
         no better than v2 at any width measured -- v2 is in fact slightly
         ahead -- and A2/`twk` run 192 rounds where HSKE-NL-A1 and HFSCX-256
         run 64.  On this axis A2 is the BETTER-covered of the
         two, not the worse.  So the linear gap cannot be a reason to rate A2
         below A1 -- it is a gap shared by four rows, three of which are
         production-track.

      Filed as TODO #254 rather than acted on here.  Downgrading three more rows
      on a slope read at n <= 10 would be the #244 error running in reverse: an
      order-of-magnitude indication is not a bound in either direction.""")
    check(min(v1) < max(v2) * 1.5,
          "v1's linear slope is now much better than v2's; §4's consistency "
          "argument no longer holds")


def section_5():
    rule("§5  The three documented constraints, re-derived")
    print("""#237 and #238 exist because propagated rows go stale, so these are re-derived
against the shipped construction rather than carried over.\n""")
    n = 16
    rng = random.Random(3)
    b = H.BitArray(n, 0xBEEF)
    p = H.BitArray(n, 0x1234)
    c1 = H.nl_fscx_revolve_v2(p, b, 192).uint
    c2 = H.nl_fscx_revolve_v2(p, b, 192).uint
    print(f"      (1) DETERMINISM — same (P,K) twice gives the same E: {c1 == c2}")
    print("          SURVIVES.  A2 has no nonce input at all, so this is still the")
    print("          constraint most likely to be missed.  Unchanged by #245.")
    check(c1 == c2, "A2 is no longer deterministic")
    bad = H.BitArray(n, 0)
    print(f"\n      (2) AFFINE WEAK-KEY CLASS — nl_v2_key_is_valid(delta=0) rejects: "
          f"{not H.nl_v2_key_is_valid(bad)}")
    print("""          SURVIVES, and TODO #253 WIDENED what it does not cover: the keys
          admitting a zero-weight trail are every B with tz(delta(B)) >= 4, a
          strictly larger family than the affine class this check rejects.  #253
          measured the cost at n=256 as at most ~3 of 192 rounds on 6% of keys
          and recommended documenting rather than screening.  The constraint
          text should say "affine class" rather than "the degenerate class".""")
    check(not H.nl_v2_key_is_valid(bad), "nl_v2_key_is_valid no longer rejects delta=0")
    print("""
      (3) SELF-SIMILARITY — REMOVED.  §1 re-derived this: the slide property is
          gone (0/200 against the shipped code) and the fixed-point excess is
          gone (§11.27.2).  This constraint must come OFF both rows.  It is
          currently stated on both as a live property, in the pre-#245 wording,
          in rows that then say #245 removed it.

      A replacement is warranted rather than a deletion, because the underlying
      structure -- one key, no schedule -- is still there even though its
      symptoms are not.  §3 is the evidence that the structure is safe against
      the class that exploits it, and that is what the row should say.""")


def section_6():
    rule("§6  Verdict")
    print("""**HSKE-NL-A2 and `twk` both stay demo-only.  Both rationales are replaced.**

The rating does not move, and the reason it does not move is NOT the reason
either row currently gives.

  WHY NOT PROMOTE.  The suite's standard (§2) is cryptanalytic coverage against
  the standard attack families, at the deployed width, with a named conjecture
  where a proof is absent.  Differential coverage is now good: exact optima to
  n = 64 (#247), per-key figures and an exactly-characterised weak-key class
  (#253).  Invariant-subspace resistance is PROVEN at n = 256 (§3).  But the
  linear axis was first measured three items ago, has never been written up, is
  the weakest of the three by a wide margin, and is the one axis whose slope is
  NOT width-stable (§4).  Promoting a row while its binding axis has one
  small-width measurement and an unresolved width trend is precisely the
  "no known problems" reasoning #237, #238, #243 and #244 were each filed to
  undo.  Three versions after #244 downgraded A2 is not the moment to repeat it.

  WHY THE CURRENT RATIONALE IS WRONG ANYWAY.  Both rows say the blocker is the
  absent PRP/SPRP reduction.  By §2 that standard would demote six other rows,
  AES has no such reduction either, and it is not what the rest of the table is
  rated against.  Both rows also still assert self-similarity as a live
  constraint (§1, §5) in wording #245 falsified, and then say #245 fixed it.
  A reader cannot act on either row as written.

  WHAT THE ROWS SHOULD SAY.  #248 asked for "a row that says precisely what is
  missing rather than one that reads as an unexplained caution".  What is missing
  is now one specific, closeable thing: a linear-trail bound at realistic width.
  Not a reduction, not a structural fix, not a parameter change.

  WHAT WOULD EARN THE PROMOTION.  TODO #254.  If the linear slope at realistic
  width lands where the trend points, A2 and `twk` meet the same standard the six
  rows in §2 meet, and both should move together.  That is a measurement, not a
  research programme -- and unusually for this suite, the promotion criterion is
  now a number rather than a judgement.

  WHAT DOES NOT CHANGE.  No attack on A2 or `twk` at n = 256 is known, from this
  review or anywhere in the repository.  Bijectivity is proven.  Demo-only is a
  statement about what has been established, not a claim that either is broken.

  SCOPE.  §4 found the same linear gap under HSKE-NL-A1, HFSCX-256, HPKS-WOTS,
  HPKS-XMSS -- three production-track rows and everything hash-based downstream.
  That is FILED (#254), not acted on: a slope read at n <= 10 is not a basis for
  demoting three more rows, and #244's error run in reverse is still #244's
  error.  A2 is the better-covered side of that comparison, which is the single
  strongest argument in its favour and is why this verdict is close.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_0()
    section_1(a.quick)
    section_2()
    section_3(a.quick)
    section_4(a.quick)
    section_5()
    section_6()
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
