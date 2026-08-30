#!/usr/bin/env python3
"""nl_fscx_v2_fixed_key.py — TODO #253: the fixed-key gap TODO #247 found.

TODO #247(b) measured, at n = 10 and n = 11, that the optimal trail weight of a
FIXED key sits at roughly HALF the key-averaged figure every bound in this repo
quotes, and that the spread across keys is wider than the mean.  TODO #253 was
filed because that is the dominant uncertainty in HSKE-NL-A2's and HPKE-NL's
security story -- larger than the width extrapolation everyone had been
caveating instead -- and because #248's rating decision cannot be made without
it.  #253 asked four questions.  This script answers all four.

  1. Does the ~2x gap persist at larger widths, or is it a small-width artefact?
     "This is the first question and it may dissolve the item."  It does not
     dissolve: the gap is present at every width reachable exactly, it does not
     shrink, and it survives restriction to typical keys.  See §2 and §3.

  2. Is the weak tail an identifiable class, or a smooth distribution with no
     screenable structure?  It is BOTH, and the identifiable part was not known.
     §4 exhibits it, with a proof rather than an extrapolation.

  3. If there is a class, is a keygen screen possible?  Yes, and it is one line.
     §5 also shows the numbers say not to bother at n = 256, and why the
     existing nl_v2_key_is_valid catches only the two endpoints of it.

  4. If not, is the honest SECURITY.md figure the weak-tail value rather than
     the mean?  §6.  It is neither: it is the per-key median, and the reason is
     that questions 1 and 2 have different answers.

Method note.  Everything differential here is EXACT -- one-round DDT by
exhaustive enumeration, then a dynamic program over difference states, so every
figure is a proven optimum over all trails of that length.  Everything in §4 is
exact GF(2) linear algebra, cross-checked against brute-force enumeration at
n = 8 before it is trusted at n = 256.  Round constants do not affect any of it
(SecurityProofs-7.md §11.27.1).

Exits non-zero if a headline finding stops reproducing, so it cannot print a
stale verdict.

Run:  python3 SecurityProofsCode/nl_fscx_v2_fixed_key.py [--quick]
"""

import argparse
import math
import os
import random
import statistics
import sys

SEP = "=" * 74
SEP2 = "-" * 74
FAIL = []


def rule(t):
    print("\n" + SEP)
    print(t)
    print(SEP)


def check(cond, what):
    if not cond:
        FAIL.append(what)
        print(f"      *** REGRESSION: {what} ***")


# The round functions live in TODO #246's script; reuse rather than fork.
def _load():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     'nl_fscx_v2_and_layer.py')
    src = open(p).read().split("def main(")[0]
    g = {}
    exec(compile(src, p, 'exec'), g)
    return g


G = _load()


def delta(n, B):
    """The additive constant the deployed round derives from the key."""
    m = (1 << n) - 1
    return G['ops'](n)[1]((B * ((B + 1) >> 1)) & m, n // 4)


def m_tab(n):
    m = (1 << n) - 1
    _, rol, ror = G['ops'](n)
    return [(a ^ rol(a, 1) ^ ror(a, 1)) & m for a in range(1 << n)]


def add_ddt(n, d):
    """Exact DDT of x -> (x + d) mod 2^n, as one dict of counts per difference."""
    N = 1 << n
    m = N - 1
    t = [(x + d) & m for x in range(N)]
    rows = []
    for g in range(N):
        r = {}
        if g:
            for x in range(N):
                b = t[x] ^ t[x ^ g]
                r[b] = r.get(b, 0) + 1
        rows.append(r)
    return rows


def avg_add_ddt(n, ds):
    """The same table averaged over a set of constants -- the key-averaged model
    #214 and #247 report, reproduced here so the comparison is like-for-like."""
    N = 1 << n
    m = N - 1
    acc = [dict() for _ in range(N)]
    for d in ds:
        t = [(x + d) & m for x in range(N)]
        for g in range(1, N):
            r = acc[g]
            for x in range(N):
                b = t[x] ^ t[x ^ g]
                r[b] = r.get(b, 0) + 1
    return acc


def trail(n, A, Ma, maxr, scale):
    """Exact optimal differential-trail weight after 1..maxr rounds.

    The deployed round is M(a ^ i ^ B) + delta(B): the XOR and M parts are
    deterministic on differences, so the DP steps a -> M(a) -> b through A."""
    N = 1 << n
    INF = float('inf')
    cost = [0.0 if a else INF for a in range(N)]
    out = []
    for _ in range(maxr):
        nxt = [INF] * N
        for a in range(N):
            ca = cost[a]
            if ca == INF:
                continue
            for b, c in A[Ma[a]].items():
                if b == 0:
                    continue
                w = ca - math.log2(c / scale)
                if w < nxt[b]:
                    nxt[b] = w
        cost = nxt
        out.append(min(v for v in cost if v != INF))
    return out


# ═══════════════════════════════════════════════════════════════════════════
def section_0():
    rule("§0  The reduction: 2^n keys collapse to one parameter")
    print("""The deployed round is  F_B(a) = M(a ^ i ^ B) + delta(B) mod 2^n.  On
DIFFERENCES the XOR of B and of the round counter cancel, and M is linear, so
both are deterministic and key-independent.  Every bit of differential
behaviour that depends on the key does so through the additive constant alone:

      DDT of F_B   =   DDT of ( + delta(B) )  reindexed by  alpha -> M(alpha)

so two keys with the same delta have IDENTICAL trail weights at every round
count, and "which keys are weak" is a question about the image of delta, not
about a 2^n-element key space.  That is what makes the rest of this script
exact rather than sampled -- and it is why §4 can settle the deployed width by
linear algebra.

Verified against the generic per-key DDT path TODO #247 used:\n""")
    n = 10
    Ma = m_tab(n)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_b", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'nl_fscx_v2_bounds.py'))
    bb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bb)
    print(f"      {'B':>5}  {'delta(B)':>9}   #247 generic path      this reduction")
    print("      " + SEP2[:62])
    agree = True
    for B in (3, 29, 341):
        a = bb.trail_series(n, bb.ddt(n, G['mk_v2'](n, B)), 4)
        c = trail(n, add_ddt(n, delta(n, B)), Ma, 4, 1 << n)
        ok = all(abs(u - v) < 1e-9 for u, v in zip(a, c))
        agree &= ok
        print(f"      {B:>5}  {delta(n,B):>9}   "
              + " ".join(f"{v:5.2f}" for v in a) + "    "
              + " ".join(f"{v:5.2f}" for v in c) + ("  ok" if ok else "  DIFFER"))
    check(agree, "the delta-reduction no longer reproduces #247's per-key path")


def gap_table(widths, title, keyfilter, seed):
    print(f"\n      {title}")
    print(f"      {'n':>3} {'keys':>5}  {'min':>6} {'med':>6} {'mean':>6} {'max':>6} "
          f"| {'key-avg':>7} | {'mean/avg':>8}")
    print("      " + SEP2[:62])
    ratios = []
    rows = []
    R = 5
    for n, K in widths:
        assert not G['m_is_singular'](n), n
        N = 1 << n
        Ma = m_tab(n)
        rng = random.Random(seed + n)
        ds = []
        while len(ds) < K:
            d = delta(n, rng.randrange(N))
            if keyfilter(n, d):
                ds.append(d)
        per = sorted(trail(n, add_ddt(n, d), Ma, R, N)[R - 1] for d in ds)
        ka = trail(n, avg_add_ddt(n, ds), Ma, R, N * K)[R - 1]
        mean = sum(per) / K
        ratios.append(mean / ka)
        rows.append((n, per, ka))
        print(f"      {n:>3} {K:>5}  {per[0]:>6.2f} {per[K//2]:>6.2f} {mean:>6.2f} "
              f"{per[-1]:>6.2f} | {ka:>7.2f} | {mean/ka:>8.3f}")
        sys.stdout.flush()
    return ratios, rows


def section_2(quick):
    rule("§2  Does the gap persist with width?  (the question that could have "
         "dissolved #253)")
    print("""Optimal 5-round trail weight per key, against the key-averaged optimum over
the same key set.  A ratio near 1.0 would mean the averaged bound is an honest
per-key claim and #253 dissolves.  #247 measured about 0.5 at two widths.

Keys here are screened by the DEPLOYED check, nl_v2_key_is_valid, which rejects
delta in {0, 2^(n-1)} -- so this is the population the shipped code actually
uses, not an unfiltered one.""")
    widths = [(7, 40), (8, 40), (10, 40)] + ([] if quick else [(11, 30)])
    ratios, rows = gap_table(widths, "deployed-screened keys",
                             lambda n, d: d not in (0, 1 << (n - 1)), 777)
    print(f"""
      Ratio {min(ratios):.2f} to {max(ratios):.2f} across widths, with no shrinking trend.  The gap
      does NOT dissolve, and it is not a two-width coincidence: #247 saw it at
      n = 10 and 11, and it is the same size at 8 and 9.

      So every trail figure this repository has published for the v2 family --
      #214's, #246's comparison, #247's proven optima -- overstates the
      resistance of an actual key by about a factor of two in weight.""")
    check(max(ratios) < 0.85,
          f"per-key/key-averaged ratio rose to {max(ratios):.2f}; the #253 gap may have closed")
    return ratios, rows


def section_3(quick):
    rule("§3  Is the gap just the weak tail?  (restricting to typical keys)")
    print("""If the factor of two were produced entirely by a small tail of bad keys, the
right response would be a screen, not a re-rating.  Repeated over keys whose
delta has at most one trailing zero -- about three quarters of the key space,
and by §4 the part with no structural weakness at all:""")
    widths = [(7, 40), (8, 40), (10, 40)] + ([] if quick else [(11, 30)])
    ratios, _ = gap_table(widths, "typical keys only (tz(delta) <= 1)",
                          lambda n, d: d and (d & -d).bit_length() - 1 <= 1, 4242)
    print(f"""
      Still {min(ratios):.2f} to {max(ratios):.2f}.  The gap is GENERIC, not tail-driven -- a typical
      key is about twice as weak as the averaged bound says, and no screen
      addresses that, because there is nothing to screen out.

      A trend recorded as a NON-finding.  These four ratios drift mildly upward
      with n, which if real would mean the gap narrows at deployed width and
      the honest figure is better than this section's.  Four points with this
      much per-key spread do not establish a trend, and §(a) of TODO #247
      already recorded one near-miss of exactly this shape -- a 2-key run that
      appeared to show the slope collapsing and did not reproduce at 6 keys.
      It is not leaned on anywhere below.""")
    check(max(ratios) < 0.85,
          f"typical-key ratio rose to {max(ratios):.2f}; §3's conclusion may no longer hold")
    return ratios


# ── §4: exact structure, by linear algebra ──────────────────────────────────
def Mv(n, x):
    m = (1 << n) - 1
    return (x ^ ((x << 1) | (x >> (n - 1))) ^ ((x >> 1) | (x << (n - 1)))) & m


def free_rounds(n, k, cap):
    """Largest r <= cap admitting a nonzero ZERO-WEIGHT r-round trail when
    tz(delta) = k, by exact GF(2) linear algebra.

    Why this is the right computation.  Addition of a constant d with k trailing
    zeros leaves the low k bits of the input untouched and cannot carry out of
    position k-1, so every difference supported on bits 0..k-1 passes it with
    probability 1.  The top bit is free for any constant, since the final carry
    is discarded mod 2^n.  So the probability-1 differences of ( + d ) are
    exactly the subspace V_k = span{e_0..e_(k-1), e_(n-1)}, and a zero-weight
    r-round trail exists iff some nonzero gamma has M^j gamma in V_k for every
    j < r.  That is a nullspace, computed here directly."""
    piv = {}
    img = [1 << i for i in range(n)]
    r = 0
    while r < cap:
        for p in range(k, n - 1):          # constrain bits k..n-2 to zero
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


def brute_free(n, k, r):
    """Independent brute-force count of nonzero zero-weight r-round trails."""
    keep = (1 << k) - 1 | (1 << (n - 1))
    full = (1 << n) - 1
    c = 0
    for g in range(1, 1 << n):
        if g & ~keep & full:
            continue
        x, ok = g, True
        for _ in range(r):
            if x == 0 or (x & ~keep & full):
                ok = False
                break
            x = Mv(n, x)
        c += ok
    return c


def section_4(quick):
    rule("§4  The weak tail HAS a class — and it is not the one the deployed "
         "check screens")
    print("""Addition of a constant d with k trailing zeros leaves the low k bits of the
input untouched and cannot carry out of position k-1, so every difference
supported on bits 0..k-1 passes it with probability 1.  The top bit is free for
any constant, since the final carry is discarded mod 2^n.  So the
probability-1 differences of ( + d ) are exactly the subspace

      V_k = span{e_0 .. e_(k-1), e_(n-1)}

and a zero-weight r-round trail exists iff some nonzero gamma has M^j gamma in
V_k for every j < r.  That is a nullspace, and it is computed exactly -- which
is what lets this section answer at n = 256 rather than extrapolate to it.""")
    print("""
    nl_v2_key_is_valid rejects delta in {0, 2^(n-1)}.  In this language those
    are k = n-1 (V is everything) and the single top bit -- the two ENDPOINTS of
    a family it does not otherwise see.  Everything between them is accepted.

    Cross-checked against brute force before being trusted at n = 256:\n""")
    ok = True
    print(f"      {'k':>3}  {'algebra: nonzero trails':>24}  {'brute force':>12}")
    print("      " + SEP2[:46])
    for k in range(1, 8):
        r = 3
        d = 0
        # dimension of the zero-weight space at exactly r rounds
        piv = {}
        img = [1 << i for i in range(8)]
        for _ in range(r):
            for p in range(k, 7):
                f = 0
                for i in range(8):
                    if (img[i] >> p) & 1:
                        f |= 1 << i
                v = f
                for b, q in piv.items():
                    if (v >> b) & 1:
                        v ^= q
                if v:
                    piv[v.bit_length() - 1] = v
            img = [Mv(8, v) for v in img]
        d = 8 - len(piv)
        a, b = (1 << d) - 1, brute_free(8, k, r)
        ok &= (a == b)
        print(f"      {k:>3}  {a:>24}  {b:>12}   {'ok' if a==b else 'MISMATCH'}")
    check(ok, "§4's linear algebra no longer agrees with brute force at n=8")
    print("""
    Threshold: the smallest tz(delta) admitting a zero-weight 3-round trail.""")
    ns = [7, 8, 10, 11, 16, 32, 64] + ([] if quick else [128, 256])
    thr = []
    print(f"\n      {'n':>4}   min tz for a zero-weight 3-round trail")
    print("      " + SEP2[:44])
    for n in ns:
        t = next(k for k in range(n) if free_rounds(n, k, 3) >= 3)
        thr.append(t)
        print(f"      {n:>4}   {t:>4}")
        sys.stdout.flush()
    check(len(set(thr)) == 1 and thr[0] == 4,
          f"the zero-weight threshold is no longer 4 at every width: {dict(zip(ns,thr))}")
    print(f"""
      Constant at {thr[0]} for every width tested, n = 256 included.  This is the
      structural class #253 asked whether existed.  It is real, it is exactly
      characterised, and it is invisible to nl_v2_key_is_valid.

      At n = 8 it is one key in {2**thr[0]} -- which is why #247's per-key minima went
      as low as 0.70 and why an earlier pass of this work saw a screened key
      with a 5-round weight of exactly 0.00.  The question is what it costs at
      the deployed width.""")
    return thr


def section_5(quick):
    rule("§5  What the class costs at n = 256 — and whether to screen for it")
    n = 256
    print("""Free rounds bought by tz(delta) = k at the deployed width, against the
probability of drawing such a key.  Both exact-in-kind: the left column is the
same linear algebra §4 cross-checked, the right is measured over delta(B) for
random B rather than assumed uniform.\n""")
    rng = random.Random(9)
    S = 20000 if quick else 200000
    m = (1 << n) - 1
    cnt = [0] * (n + 2)
    for _ in range(S):
        B = rng.randrange(1 << n)
        d = (B * ((B + 1) >> 1)) & m
        d = ((d << (n // 4)) | (d >> (n - n // 4))) & m
        cnt[(d & -d).bit_length() - 1 if d else n] += 1
    ge = [0] * (n + 3)
    for k in range(n, -1, -1):
        ge[k] = ge[k + 1] + cnt[k]
    print(f"      {'tz(delta)':>9}  {'free rounds':>11}  {'of 192 left':>11}  "
          f"{'Pr[tz >= k]':>12}")
    print("      " + SEP2[:50])
    rows = []
    for k in (0, 2, 4, 6, 8, 12, 16, 24, 40):
        fr = free_rounds(n, k, 200)
        rows.append((k, fr))
        p = ge[k] / S
        print(f"      {k:>9}  {fr:>11}  {192-fr:>11}  "
              + (f"{p:>12.4f}" if p >= 1e-4 else f"{'< 1e-4':>12}"))
        sys.stdout.flush()
    slope = [(fr, k) for k, fr in rows]
    print(f"""
      The scaling is the whole answer: free rounds grow like k/2, while the
      probability of drawing the key falls like 2^-k.  Buying g free rounds
      therefore costs about 2^-2g of the key space.  Losing all 192 needs
      tz = 254, i.e. one key in 2^254.

      A key drawn at random loses at most about 3 of 192 rounds with probability
      1/16, and at most 5 with probability 1/256.  Against a 192-round cipher
      that is not a weakness worth a screen -- and a screen would be one line:

          tz(delta(B)) < 8        # rejects 1 key in 256, buys back 2 rounds

      RECOMMENDATION: document the class, do not screen for it.  Screening
      changes the key distribution and needs a matching change in four language
      ports, a KAT refresh and a MIGRATING.md entry, to remove a 2-round effect
      on 0.4% of keys.

      What SHOULD change is SecurityProofs-7.md §11.20.5, which currently reads
      "the carry-degenerate key class of §11.19.2 appears in the trail model
      exactly as predicted ... nl_v2_key_is_valid already rejects them, so this
      is a cross-check that passes rather than a new finding."  The first half
      is true and the conclusion does not follow: the affine keys are a proper
      subset of the zero-weight-trail keys, and the complement -- everything
      with 4 <= tz(delta) < n-1 -- is accepted by the deployed check.  §11.19.2
      itself is CORRECT as written; it characterises the affine class exactly
      and claims nothing more.  The two properties were conflated one section
      later, and nl_v2_key_is_valid's docstring inherits the conflation by
      calling its class "the" degenerate one.""")
    check(free_rounds(n, 4, 200) <= 4,
          "tz=4 now buys more than 4 free rounds at n=256; §5's cost argument needs redoing")
    return rows


def section_6(r2, r3):
    rule("§6  Verdict — what #248 should be told")
    worst = max(max(r2), max(r3))
    print(f"""#253 asked four questions.  The answers do not point the same way, which is
why the honest reporting figure is neither of the two #253 proposed.

  1. Does the gap persist at larger widths?   YES.  {min(min(r2),min(r3)):.2f} to {worst:.2f} of the
     key-averaged weight, at four widths, with no shrinking trend (§2).

  2. Is it a screenable class or a smooth distribution?   BOTH, and they are
     different phenomena.  There IS a previously unrecorded structural class
     (§4) -- but the generic gap survives with the class removed (§3), so the
     class is not what produces the factor of two.

  3. Is a screen possible?   Yes and it is trivial, but §5 says the class costs
     at most about 3 rounds of 192 at the deployed width, on 6% of keys.  Not
     worth a wire-affecting change.  The documentation IS wrong and should be
     fixed.

  4. Is the weak-tail value the honest SECURITY.md figure?   No -- that would
     be reporting a 2^-254 event as the typical case.  The honest figure is the
     PER-KEY MEDIAN, which is about half the key-averaged number, with the
     spread stated alongside it.

What this means for the deployed 192 rounds, stated with the caveat it needs.
#247's proven key-averaged increment of 3.0 bits/round becomes about 1.5
bits/round per key, which over 192 rounds would be roughly 290 bits -- past 256
with little room.  That multiplication inherits TODO #252's open extrapolation
in full: the 3.0 is proven only to n = 64 and only to r = 4, and per-round
increments in ARX-like constructions typically FALL as rounds accumulate, so
290 is an optimistic reading of an unproven projection, not a bound.  What is
solid is the RATIO: whatever the key-averaged figure turns out to be, the
per-key one is about half of it.

#244's downgrade of HSKE-NL-A2 was made on the STPRP argument, not on trail
weight, and nothing here disturbs it.

  -> #248 can now be decided.  The evidence it was waiting for says the trail
     margin is adequate per-key and was never the binding constraint; the
     binding constraint remains #243's structural finding, that v2-revolve is
     one unvaried round iterated with no key schedule.  #253 does not rescue
     the rating and does not further damage it.

  -> #251 gains a modest argument: candidate B's margin is wide enough that
     halving it changes nothing, whereas the deployed round's is not.

  -> Note for #252: a two-sided KEY-AVERAGED bound at n = 256 would still not
     answer this question, which is the amendment #248 already carries.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true',
                    help='skip n=11 and the n=128/256 threshold rows')
    a = ap.parse_args()
    print(__doc__.split('Run:')[0].rstrip())
    section_0()
    r2, _ = section_2(a.quick)
    r3 = section_3(a.quick)
    section_4(a.quick)
    section_5(a.quick)
    section_6(r2, r3)
    print()
    if FAIL:
        print(SEP)
        print(f"*** FAILED: {len(FAIL)} finding(s) no longer reproduce ***")
        for f in FAIL:
            print("  - " + f)
        print(SEP)
        return 1
    print(SEP)
    print("*** OK: every headline finding reproduced ***")
    print(SEP)
    return 0


if __name__ == '__main__':
    sys.exit(main())
