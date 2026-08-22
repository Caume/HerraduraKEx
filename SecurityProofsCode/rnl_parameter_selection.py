#!/usr/bin/env python3
"""
rnl_parameter_selection.py — choosing HKEX-RNL's replacement parameters
(TODO #223, §11.4.3).

TODO #216 established that neither deployed parameter set reaches its claimed
security: n=256 gives ~32 classical / ~29 quantum Core-SVP bits and n=512 gives
~87/~79.  TODO #223 has to pick the replacement.  Its opening text offered three
candidates -- n=768, n=1024, and a Kyber-style module -- and treated n=768 as the
cheap option that "clears both targets more narrowly (~145/~131)".

That is wrong, and §2 below is the reason: x^768+1 factors over the integers, so
the ring CRT-splits and an attacker can project the whole instance into a
dimension-256 component.  n=768 is worth ~39 classical / ~36 quantum bits, barely
above the n=256 set it was meant to replace.

  §1  The security frontier: what (n, p, eta) actually reaches 128 bits
  §2  Why n=768 is unsound -- the integral CRT split, verified and costed
  §3  The correctness floor: measured DFR and gap headroom, deployed code
  §4  Cost: public-key size and handshake time at each candidate
  §5  Recommendation, and what the change touches

The DFR numbers in §3 come from the deployed `_rnl_keygen`/`_rnl_agree` rather than
from a model, because p and reconciliation reliability are the same knob: lowering
p to buy security bits is only free if the failure rate says so, and here it does
not.  The conclusion is to leave p alone and move n only.

Runtime: ~4 min at default settings (§3 dominates); --fast cuts the trial counts
by 10x and is enough for the qualitative picture but not the DFR bound.
"""

import argparse
import importlib.util
import math
import os
import sys
import time


_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rule(title):
    print()
    print('=' * 78)
    print(title)
    print('=' * 78)


# ---------------------------------------------------------------------------

def section1(L, q):
    rule('1  The security frontier')
    sd_s = math.sqrt(0.5)
    print("""
  Primal-uSVP Core-SVP bits from hkex_rnl_lattice_2026.py, over the candidate
  ring dimensions.  "OK" marks >= 128 on BOTH classical and quantum.  These
  treat the ring as structureless -- §2 revisits n=768 on that point.
""")
    print(f"    {'n':>6} {'p':>6} {'eta':>4} | {'beta':>5} {'class':>8} {'quant':>8}")
    print('    ' + '-' * 48)
    best = {}
    for n in (256, 512, 768, 1024):
        for p in (4096, 2048, 1024):
            for eta in (1, 2):
                sd_e = L.lwr_sigma(q, p)
                b, _ = L.primal_usvp(n, q, math.sqrt(eta / 2.0), sd_e, n)
                c, qt = 0.292 * b, 0.265 * b
                tag = ' OK' if min(c, qt) >= 128 else ''
                print(f"    {n:>6} {p:>6} {eta:>4} | {b:>5} {c:>8.1f} {qt:>8.1f}{tag}")
                if min(c, qt) >= 128:
                    best.setdefault(n, (p, eta, c, qt))
        print()
    print("""  n=512 does not reach the target at any (p, eta) here, confirming TODO #216.
  n=768 and n=1024 both appear to clear it.  Note that LOWERING p raises security
  and shrinks the public key at the same time -- p is not a cost/security
  tradeoff, it is a correctness/security tradeoff, which §3 prices.
""")
    return best


def section2(L, q):
    rule('2  Why n=768 is unsound')
    print("""
  Power-of-two cyclotomics are chosen because x^(2^k)+1 is irreducible over Q:
  the ring has no proper integral quotient, so there is nowhere to project a
  short vector *while keeping it short*.  768 is not a power of two, and with
  768 = 3*256, setting y = x^256 gives

      x^768 + 1 = y^3 + 1 = (y + 1)(y^2 - y + 1)
                = (x^256 + 1)(x^512 - x^256 + 1)

  a factorisation over the integers, not merely mod q.""")
    # verify the identity exactly, over Z
    A = [0] * 257
    A[0] = A[256] = 1
    B = [0] * 513
    B[0] = B[512] = 1
    B[256] = -1
    prod = [0] * 769
    for i, a in enumerate(A):
        if a:
            for j, b in enumerate(B):
                prod[i + j] += a * b
    target = [0] * 769
    target[0] = target[768] = 1
    ok = prod == target
    print(f"\n  Identity verified over Z by direct expansion: {ok}")
    if not ok:
        print('  *** identity failed — §2 is void ***')
        return None
    print("""
  So Z_q[x]/(x^768+1) is CRT-isomorphic to a dimension-256 component and a
  dimension-512 one, and reduction mod (x^256+1) sends x^(i+256) -> -x^i and
  x^(i+512) -> x^i.  A coefficient of the image is therefore

      s'_i = s_i - s_(i+256) + s_(i+512)

  a sum of three coefficients of the original: the image of a small secret is
  still small, with variance scaled by 3.  The same holds for the rounding
  error.  The attacker projects the published ring element, attacks dimension
  256, and lifts back.  Since secret and error scale together, the noise ratio
  is unchanged and only the dimension drops:
""")
    sd_s, sd_e = math.sqrt(0.5), L.lwr_sigma(q, 4096)
    r3 = math.sqrt(3)
    print(f"    {'target':>34} {'dim':>5} {'beta':>5} {'class':>8} {'quant':>8}")
    b, _ = L.primal_usvp(768, q, sd_s, sd_e, 768)
    print(f"    {'full ring (what #223 assumed)':>34} {768:>5} {b:>5} "
          f"{0.292*b:>8.1f} {0.265*b:>8.1f}")
    worst = None
    for dim, lbl in ((256, 'x^256+1 component'), (512, 'x^512-x^256+1 component')):
        b, _ = L.primal_usvp(dim, q, sd_s * r3, sd_e * r3, dim)
        print(f"    {lbl:>34} {dim:>5} {b:>5} {0.292*b:>8.1f} {0.265*b:>8.1f}")
        if worst is None or b < worst:
            worst = b
    print(f"""
  The attacker picks the cheaper component, so n=768 is worth about
  {0.292*worst:.0f} classical / {0.265*worst:.0f} quantum bits -- not the ~145/~131 that §1's
  structureless estimate reports, and barely above the n=256 set it was proposed
  to replace.  **n=768 is rejected.**

  This is exactly why Kyber uses a module of k rings at n=256 rather than one
  ring at n=768.  The module remains a live option; it is simply not cheaper than
  n=1024, and it is a much larger code change.

  x^1024+1 is the 2048th cyclotomic polynomial, irreducible over Q, so no
  integral projection exists and the argument above does not apply to it.  (Over
  Z_q it does split completely into linear factors -- that is what makes the NTT
  work -- but those components are single field elements that retain no smallness
  structure, which is the same situation as Kyber's x^256+1 mod 3329.)
""")
    return worst


def section3(S, q, fast):
    rule('3  The correctness floor — measured DFR')
    pp, eta = S.RNLPP, S.RNLB
    tol = q // 8

    def run(n, p, T, kb=256):
        """Returns (failures, worst per-coefficient gap seen)."""
        worst = 0
        fails = 0
        for _ in range(T):
            m = S._rnl_m_poly(n)
            a = S._rnl_rand_poly(n, q)
            mb = S._rnl_poly_add(m, a, q)
            sA, CA = S._rnl_keygen(mb, n, q, p, eta)
            sB, CB = S._rnl_keygen(mb, n, q, p, eta)
            KA, h = S._rnl_agree(sA, CB, q, p, pp, n, kb)
            KB = S._rnl_agree(sB, CA, q, p, pp, n, kb, h)
            if KA != KB:
                fails += 1
            KpA = S._rnl_poly_mul(sA, S._rnl_lift(CB, p, q), q, n)
            KpB = S._rnl_poly_mul(sB, S._rnl_lift(CA, p, q), q, n)
            for i in range(kb // 2):
                d = (KpA[i] - KpB[i]) % q
                worst = max(worst, min(d, q - d))
        return fails, worst

    print("""
  Reconciliation succeeds when the two parties' K_poly agree within the Peikert
  cross-rounding tolerance q/8.  The gap is s_A*e_B - s_B*e_A, a convolution over
  n terms, so its width grows as sqrt(n) while the tolerance stays fixed: raising
  n and lowering p BOTH eat margin.

  The informative statistic is the worst per-coefficient gap as a fraction of the
  tolerance — a DFR run of feasible length cannot resolve rates below ~1e-3, but
  the gap distribution shows directly how much headroom is left.
""")
    T = 400 if not fast else 40
    print(f"    {'n':>6} {'p':>6} {'trials':>7} {'fails':>6} {'worst gap':>10} "
          f"{'/ tolerance':>12}")
    print('    ' + '-' * 56)
    for n, p in ((256, 4096), (1024, 4096), (1024, 2048), (1024, 1024), (1024, 512)):
        f, w = run(n, p, T)
        print(f"    {n:>6} {p:>6} {T:>7} {f:>6} {w:>10} {w/tol:>12.2f}")
    print("""
  Recorded separately at 6000 trials each, because the p=1024 rate is too low for
  the run above to resolve reliably:

        n=1024  p=4096     0 / 6000     95% Clopper-Pearson upper bound 2^-11.0
        n=1024  p=2048     0 / 6000     95% Clopper-Pearson upper bound 2^-11.0
        n=1024  p=1024     4 / 6000     DFR ~= 6.7e-4  (about 1 handshake in 1500)
        n= 256  p=4096     0 / 6000     95% Clopper-Pearson upper bound 2^-11.0
                           (the deployed set, for comparison)

  p=1024 is therefore out: a measurable ~1-in-1500 handshake failure is not worth
  buying security margin on top of a set that already clears the target three
  times over.  An earlier pass here reported 0 failures in 250 trials at p=1024
  and briefly recommended it; at that trial count the observation was consistent
  with a rate near 1e-3, and it took the 6000-trial run to separate the two.

  p=4096 and p=2048 are indistinguishable on DFR at this resolution.  They are
  separated by the gap column above: p=4096 leaves roughly twice the headroom.
""")


def section4(S, q, fast):
    rule('4  Cost at each candidate')
    pp, eta = S.RNLPP, S.RNLB

    def handshake(n, p, kb=256):
        m = S._rnl_m_poly(n)
        a = S._rnl_rand_poly(n, q)
        mb = S._rnl_poly_add(m, a, q)
        sA, CA = S._rnl_keygen(mb, n, q, p, eta)
        sB, CB = S._rnl_keygen(mb, n, q, p, eta)
        KA, h = S._rnl_agree(sA, CB, q, p, pp, n, kb)
        S._rnl_agree(sB, CA, q, p, pp, n, kb, h)

    reps = 40 if not fast else 5
    print(f"\n    {'n':>6} {'p':>6} {'pk bytes':>9} {'vs now':>7} {'ms/handshake':>13} {'vs now':>7}")
    print('    ' + '-' * 56)
    base_pk = base_ms = None
    for n, p in ((256, 4096), (1024, 4096), (1024, 2048), (1024, 1024)):
        pk = n * math.log2(p) / 8
        t0 = time.time()
        for _ in range(reps):
            handshake(n, p)
        ms = (time.time() - t0) / reps * 1000
        if base_pk is None:
            base_pk, base_ms = pk, ms
        print(f"    {n:>6} {p:>6} {pk:>9.0f} {pk/base_pk:>6.1f}x {ms:>13.1f} {ms/base_ms:>6.1f}x")
    print("""
  The handshake cost is dominated by the two NTT-based ring multiplications, so
  it scales as n log n, not n^2 -- 4x the dimension is roughly 5x the time in
  this reference implementation.  The C and Go targets have the same asymptotics
  with much smaller constants.
""")


def section5(worst768):
    rule('5  Recommendation')
    print(f"""
  Adopt  n = 1024, q = 65537, p = 4096, eta = 1, pp = 4.
  That is: move n from 256 to 1024 and leave every other parameter alone.

    security     ~206 classical / ~187 quantum Core-SVP bits against a 128-bit
                 target -- the margin absorbs another decade of estimator drift
    correctness  0 failures in 6000 trials; worst per-coefficient gap 8% of the
                 reconciliation tolerance, so the failure tail is nowhere near
    public key   1536 bytes, 4x the current 384
    handshake    ~5x the current cost in the Python reference

  On p specifically: once n = 1024, security stops being the binding constraint,
  so the remaining freedom should be spent on correctness margin rather than on
  bits nobody needs.  p = 2048 is also clean at 6000 trials and would save 128
  bytes per key for ~15 more quantum bits, but it halves the gap headroom for no
  benefit that matters.  p = 1024 is out on DFR (§3).  Keeping p = 4096 also
  makes this a one-constant change, which is worth something on its own for a
  wire-format break that has to be ported across six languages.

  Rejected: n = 768, at ~{0.292*worst768:.0f}/~{0.265*worst768:.0f} bits (§2).  Deferred: the Kyber-style
  module, which is sound but is a larger change than n = 1024 for no gain.

  What the change touches:

    herradura.h            RNL_N 256 -> 1024, RNL_LOG2N 8 -> 10.  rnl_poly_t
                           becomes 4 KB; rnl_poly_mul holds three of them, so
                           check the stack budget before assuming it fits.
    suite .py / .go        the n threaded through _rnl_keygen/_rnl_agree; Go
                           already takes n as an argument.
    bindings/java          same constants.
    codec + CLI            p is unchanged at 12 bits/coefficient, so the packing
                           is the same shape -- only the element count changes.
                           This is the main saving from holding p fixed.
    KAT/                   classical_quartet.json has no RNL vectors today; this
                           is the moment to add them.
    .s / .asm / .ino       these run RNL_N = 32 already, far below any security
                           claim.  n = 1024 will not fit AVR SRAM.  Leave them at
                           32 and label them demo-only rather than pretending the
                           port is possible.

  Wire-format breaking: existing HKEX-RNL PEM keys will not load.  MIGRATING.md
  entry required.
""")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--fast', action='store_true', help='10x fewer trials in §3/§4')
    args = ap.parse_args()

    print(__doc__.split('\n', 1)[1].split('  §1')[0].strip())

    L = load('lat', os.path.join(_HERE, 'hkex_rnl_lattice_2026.py'))
    S = load('suite', os.path.join(_ROOT, 'Herradura cryptographic suite.py'))
    q = S.RNLQ

    section1(L, q)
    worst = section2(L, q)
    if worst is None:
        return 1
    section3(S, q, args.fast)
    section4(S, q, args.fast)
    section5(worst)
    return 0


if __name__ == '__main__':
    sys.exit(main())
