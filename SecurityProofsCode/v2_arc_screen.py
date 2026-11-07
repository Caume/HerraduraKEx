#!/usr/bin/env python3
"""v2_arc_screen.py — TODO #354, items 2 and 3: would a short-arc screen on NL-FSCX v2's
B catch the weak keys, and does any site let B be weak?

§11.78-§11.80 found the keys below the deployed criterion mostly in the short-arc class,
arc(delta(B)) <= 12 (arc = n minus delta's longest cyclic zero run), and TODO #354 asks
whether nl_v2_key_is_valid should refuse that class too.  Its item 1 (the threshold at
n = 256) needs new solves; items 2 and 3 do not, and they decide whether item 1 is worth
running.

  §1  ITEM 3 -- WHAT A SCREEN CATCHES, on the pinned samples at n = 19, 20, 22 and 23
      (450, 450, 156 and 150 keys).  The samples are Neyman-allocated, so the short-arc
      strata are over-drawn and a raw count of failures overstates the catch: weighted by
      stratum, a screen at arc <= 12 removes 59-100% of the share below the bar
      (differential) and 59-82% (linear), never all of the linear share, and leaves 0-2.4%
      of keys failing with long arcs.  TODO #354's "5 of 5 / 7 of 8 at n = 23" are raw
      counts; weighted they are 100% / 73%.  No threshold transfers across widths: a cut
      that catches every failure at n = 19 (arc <= 14) rejects 39% of keys there, and at
      n = 22 and 23 no cut up to 16 bits catches every linear failure.  CONTROLS: a cut at
      arc <= n catches exactly all, a cut at 0 none; the stratified catch on a sample whose
      strata all carry the same weight is the raw count.
  §2  ITEM 2 -- WHO CAN MAKE B NON-UNIFORM, site by site (§11.77's census):
        HSKE-NL-A2  the key file.  A SESSION KEY PEM is two DER integers anyone can
                    write, and the Python and Go CLIs also read a raw 0x... hex key; a
                    hand-chosen B such as 2^255 + 1 has arc 3 and passes
                    nl_v2_key_is_valid.  The ONE site where a screen would act, against
                    misuse.  A kex-derived key is uniform and never meets the class.
        HPKE-NL     the sender sets B outright: R = 1 gives B = R^a = 1, arc 1, accepted.
                    But then the key is public, weak or not: the sender harms only its own
                    ciphertext.  A decrypt-side screen is no oracle on a: off the identity
                    no element of a subgroup of order 3 .. 65537 (274177 without --quick)
                    has an arc under 194.
        twk / FPE   B is a hash of the key and context.  Reaching the class (density about
        / duplex    2^-121, §11.63's extrapolation) takes about 2^121 contexts; `twk`'s 96-bit
                    tweak space expects 2^-25 such keys.  For FPE's ctx and the duplex's
                    nonce, both unbounded, the search beats the generic multi-target cost
                    max(T, 256 - T) only if exploiting a short-arc key at n = 256 costs
                    under 256 - 2 * 121 = 14 bits.  That is item 1's question, sharpened.
  §3  VERDICT.  A keygen-only screen protects nothing (every key the suite mints is
      uniform).  A load-time screen protects HSKE-NL-A2 against hand-chosen keys only.

Every statement about cost is in the trail-weight model; the 2^-121 density is §11.63's
extrapolation, not a count.  The n = 256 cost of a short-arc key is not measured here.

The bootstrap SEs are printed, not scored: 5-8% at n = 19 and 20, about 19% at n = 22 and 23,
where 150-156 keys hold 5-9 failures.

Exits non-zero if a finding stops reproducing.  About 80 s (--quick), 2 min without, on an
aarch64 SBC; most of it is enumerating the strata.

Run:  python3 SecurityProofsCode/v2_arc_screen.py [--quick]
"""

import importlib.util
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUICK = "--quick" in sys.argv
FAIL = []
NAME = {0: "differential", 1: "linear"}
WIDTHS = (19, 20, 22, 23)
ARC = 12                         # §11.59's weak class re-read as an arc (§11.63)
CUTS = (8, 10, 12, 14, 16)
LOG2_DENSITY = 121               # §11.63: arc <= 12 at n = 256, about 2^-121 (extrapolated)
TWK_TWEAK_BITS = 96              # `twk`: 64-bit sector, 32-bit block index (§11.77.3)
BOOT = 1000                      # stratified bootstrap replicates for §1's printed SEs


def _load(name, argv=None):
    path = os.path.join(HERE, name)
    spec = importlib.util.spec_from_file_location(name[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    old, sys.argv = sys.argv, [name] + (argv or [])
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = old
    return mod


F20 = _load("v2_fail_n20.py")        # pinned_old(), others(), PINNED
F23 = F20.F23                        # below()
T22 = F20.T22                        # arc()
KS = F20.KS                          # strata(), SEED
AUD = F20.AUD                        # delta()
BS = _load("v2_v3_b_setter.py", ["--quick"])   # ROOT, PY, _load(), delta()


def rule(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def check(cond, what):
    print("  [%s] %s" % ("PASS" if cond else "FAIL", what))
    if not cond:
        FAIL.append(what)
    return cond


def samples():
    """{n: rows} at §11.78-§11.80's sample sizes."""
    rows = F20.others()
    with open(F20.PINNED) as fh:
        rows[20] = F20.pinned_old() + json.load(fh)["rows"]
    return rows


def wshare(S, rows, pred):
    """The stratified share of keys with pred(row): each stratum's sample share at the
    stratum's weight (the point estimate of v2_fail_n22.share)."""
    tot = sum(len(v) for v in S.values())
    s = 0.0
    for t in S:
        xs = [r for r in rows if r[0] == t]
        if xs:
            s += len(S[t]) / tot * sum(1 for r in xs if pred(r)) / len(xs)
    return s


def catch(S, rows, n, axis, cut, arcs):
    """(share below the bar, share below it with arc <= cut, raw failures, raw caught)."""
    fail = lambda r: F23.below(r, axis, n)
    p = wshare(S, rows, fail)
    c = wshare(S, rows, lambda r: fail(r) and arcs[r[1]] <= cut)
    raw = sum(1 for r in rows if fail(r))
    rawc = sum(1 for r in rows if fail(r) and arcs[r[1]] <= cut)
    return p, c, raw, rawc


def boot_se(S, rows, n, axis, arcs, rnd):
    """Stratified bootstrap SE of the caught fraction at arc <= ARC.  Like the plain SE
    of the share, it gives a stratum with no failure in its sample no variance."""
    by = {}
    for r in rows:
        by.setdefault(r[0], []).append(r)
    xs = []
    for _ in range(BOOT):
        bs = [x for v in by.values() for x in (rnd.choice(v) for _ in v)]
        p, c, _, _ = catch(S, bs, n, axis, ARC, arcs)
        if p:
            xs.append(c / p)
    m = sum(xs) / len(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


def section_1(S, rows):
    rule("§1  Item 3: what a short-arc screen catches, n = %s"
         % ", ".join(map(str, WIDTHS)))
    rnd = random.Random(KS.SEED * 100 + 354)
    got = {}
    for n in WIDTHS:
        tot = sum(len(v) for v in S[n].values())
        pop = {}
        for v in S[n].values():
            for B in v:
                a = T22.arc(AUD.delta(B, n), n)
                pop[a] = pop.get(a, 0) + 1
        rej = {A: sum(c for a, c in pop.items() if a <= A) / tot for A in CUTS}
        arcs = {r[1]: T22.arc(AUD.delta(r[1], n), n) for r in rows[n]}
        print("\n  n = %d, %d keys; the cut rejects of ALL keys: %s"
              % (n, len(rows[n]), ", ".join("<=%d %.1f%%" % (A, 100 * rej[A]) for A in CUTS)))
        for axis in (0, 1):
            per = {A: catch(S[n], rows[n], n, axis, A, arcs) for A in CUTS}
            p, c, raw, rawc = per[ARC]
            se = boot_se(S[n], rows[n], n, axis, arcs, rnd)
            got[n, axis] = (p, c, raw, rawc, {A: per[A][1] / per[A][0] for A in CUTS}, rej)
            print("    %-12s below the bar %.2f%%; arc <= %d catches %.0f%% (bootstrap SE "
                  "%.0f%%; raw %d of %d = %.0f%%), leaves %.2f%% of keys"
                  % (NAME[axis], 100 * p, ARC, 100 * c / p, 100 * se, rawc, raw,
                     100 * rawc / raw, 100 * (p - c)))
            print("    %-12s caught by cut: %s" % ("", ", ".join(
                "<=%d %.0f%%" % (A, 100 * per[A][1] / per[A][0]) for A in CUTS)))
    print()
    fr = {k: v[1] / v[0] for k, v in got.items()}
    check(all(v[3] / v[2] >= fr[k] - 1e-12 for k, v in got.items()) and
          sum(v[3] / v[2] > fr[k] + 1e-9 for k, v in got.items()) >= 7,
          "the raw count of caught failures overstates the stratified catch (or equals it) "
          "at every width and axis, strictly at %d of 8: Neyman over-draws short arcs"
          % sum(v[3] / v[2] > fr[k] + 1e-9 for k, v in got.items()))
    lo = {a: min(fr[n, a] for n in WIDTHS) for a in (0, 1)}
    hi = {a: max(fr[n, a] for n in WIDTHS) for a in (0, 1)}
    check(0.55 < lo[0] and lo[1] > 0.55 and abs(hi[0] - 1) < 1e-12 and hi[1] < 0.85,
          "arc <= %d catches %.0f-%.0f%% of the differential share and %.0f-%.0f%% of the "
          "linear share below the bar" % (ARC, 100 * lo[0], 100 * hi[0], 100 * lo[1],
                                          100 * hi[1]))
    check(all(got[n, 1][3] < got[n, 1][2] for n in WIDTHS), "on the linear axis a "
          "long-arc failure exists at every width, so no arc <= %d screen catches all" % ARC)
    res = max(got[k][0] - got[k][1] for k in got)
    check(0.01 < res < 0.03, "the failures it leaves weigh up to %.1f%% of keys" % (100 * res))
    check(abs(fr[23, 0] - 1) < 1e-12 and got[23, 0][2:4] == (5, 5) and
          got[23, 1][2:4] == (8, 7) and abs(fr[23, 1] - 0.73) < 0.01,
          "CORRECTION to TODO #354: n = 23's \"5 of 5 / 7 of 8\" are raw counts; weighted "
          "they are %.0f%% / %.0f%%" % (100 * fr[23, 0], 100 * fr[23, 1]))
    full19 = min(A for A in CUTS if got[19, 0][4][A] == 1 and got[19, 1][4][A] == 1)
    check(got[19, 0][5][full19] > 0.3, "no cut transfers: the first that catches every n = "
          "19 failure (arc <= %d) rejects %.0f%% of all n = 19 keys"
          % (full19, 100 * got[19, 0][5][full19]))
    check(all(got[n, 1][4][16] < 0.8 for n in (22, 23)), "at n = 22 and 23 no cut up to 16 "
          "bits catches every linear failure (%.0f%%, %.0f%%)"
          % (100 * got[22, 1][4][16], 100 * got[23, 1][4][16]))
    # CONTROLS: the cut's ends, and the weighting itself.
    n = 20
    arcs = {r[1]: T22.arc(AUD.delta(r[1], n), n) for r in rows[n]}
    p, c, _, _ = catch(S[n], rows[n], n, 0, n, arcs)
    p0, c0, _, _ = catch(S[n], rows[n], n, 0, 0, arcs)
    check(abs(c - p) < 1e-15 and c0 == 0, "CONTROL: a cut at arc <= n catches exactly all, "
          "a cut at 0 none")
    flat = {t: [None] * sum(1 for r in rows[n] if r[0] == t) for t in S[n]}
    p, c, raw, rawc = catch(flat, rows[n], n, 0, ARC, arcs)
    check(abs(c / p - rawc / raw) < 1e-12 and abs(fr[n, 0] - rawc / raw) > 0.05,
          "CONTROL: weighting each stratum by its own sample size returns the raw count "
          "(%.0f%%), and the stratified catch differs from it (%.0f%%)"
          % (100 * rawc / raw, 100 * fr[n, 0]))
    return fr


def section_2():
    rule("§2  Item 2: who can make B non-uniform, site by site")
    S = BS._load("suite_arc", os.path.join(BS.ROOT, BS.PY))
    N = 256
    arc = lambda B: T22.arc(BS.delta(N, B), N)
    ok = lambda B: S.nl_v2_key_is_valid(S.BitArray(N, B))
    check(all(BS.delta(n, B) == AUD.delta(B, n) for n in (19, 23)
              for B in (1, 3, 12345, (1 << n) - 3)),
          "the two delta() implementations agree")

    print("\n  HSKE-NL-A2: B is the key file's integer.")
    w = (1 << 255) + 1
    check(ok(w) and arc(w) == 3, "a hand-chosen 256-bit key, 0x8000...0001, has arc %d and "
          "passes nl_v2_key_is_valid" % arc(w))
    check(not ok(1 << 255), "CONTROL: 0x8000...0000 is in the affine class and is refused")
    py = BS._src("HerraduraCli/herradura.py")
    go = BS._src("HerraduraCli/herradura_cli.go")
    cc = BS._src("HerraduraCli/herradura_cli.c")
    jv = BS._src("bindings/java/herradurakex/HerraduraCli.java")
    hexpy = "if key_str.startswith('0x') or key_str.startswith('0X'):" in py
    hexgo = 'if strings.HasPrefix(strings.ToLower(s), "0x") {' in go
    check(hexpy and hexgo, "the Python and Go CLIs read a raw 0x... hex key (_load_key, "
          "loadKey), a route for a human-chosen B")
    check("0x" not in cc[cc.index("static void load_sym_key_n"):
                         cc.index("static void load_sym_key(")] and
          "0x" not in jv[jv.index("private static BitArray loadKey"):
                         jv.index("private static BitArray loadKey") + 2500],
          "the C and Java CLIs read only PEM: an undocumented parity gap (TODO #355)")

    print("\n  HPKE-NL: the sender sets B = R^a.")
    check(ok(1) and arc(1) == 1, "R = 1 gives B = 1: arc %d, accepted.  The key is then "
          "public, so a weak B harms only the sender's own ciphertext" % arc(1))
    poly, order = S.GF_POLY[N], (1 << N) - 1
    worst = N
    for d in ((3, 5, 17, 257, 641, 65537) if QUICK else
              (3, 5, 17, 257, 641, 65537, 274177)):
        h = S.gf_pow(S.GF_GEN, order // d, poly, N)
        x, mn = h, N
        for _ in range(d - 1):
            mn = min(mn, arc(x))
            x = S.gf_mul(x, h, poly, N)
        check(x == 1, "order-%d subgroup walked: shortest arc off the identity %d" % (d, mn))
        worst = min(worst, mn)
    check(worst >= 194, "no small-subgroup element but the identity has an arc under %d: a "
          "decrypt-side arc screen at any cut below it is no oracle on a mod d" % worst)

    print("\n  twk / FPE / duplex: B is a hash of the key and the context.")
    exp = TWK_TWEAK_BITS - LOG2_DENSITY
    check(exp < -20, "`twk`'s 2^%d tweaks expect 2^%d keys in the class (density about "
          "2^-%d, §11.63's extrapolation): out of reach" % (TWK_TWEAK_BITS, exp, LOG2_DENSITY))
    T = LOG2_DENSITY
    be = (N - T) - T
    check(be == 14, "with unbounded contexts (FPE's ctx, the duplex nonce), 2^%d queries "
          "find one; the search beats the generic max(T, 256 - T) = %d only if exploiting "
          "that key costs under %d bits -- item 1's question, sharpened" % (T, N - T, be))


def main():
    print(__doc__)
    S = {n: KS.strata(n) for n in WIDTHS}
    section_1(S, samples())
    section_2()
    rule("§3  Verdict")
    print("""
  A keygen-only screen protects nothing: every key the suite mints (a kex output, a DH
  output, a hash) is pseudo-uniform and meets the class with probability about 2^-121.  A
  load-time screen acts at one site, HSKE-NL-A2, and only against a hand-chosen key; it
  would catch most of the weak class there but not the long-arc failures.  Refusing on
  load changes what --algo hske-nla2 accepts (MAJOR, MIGRATING.md).  Whether the
  unbounded-context search matters is item 1's: does a short-arc key cost under 14 bits
  at n = 256?""")
    rule("Summary")
    if FAIL:
        print("*** FAILED: %d finding(s) did not reproduce ***" % len(FAIL))
        for f in FAIL:
            print("    - " + f)
        return 1
    print("*** OK: every finding reproduced ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
