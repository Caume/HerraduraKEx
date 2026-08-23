#!/usr/bin/env python3
"""
fscx_revolve_closed_form.py — TODO #213: evaluate FSCX_REVOLVE in O(log i)
rotate-XOR steps instead of O(i), bit-for-bit identically.

FSCX and FSCX_REVOLVE keep their definitions exactly.  This is an evaluation
strategy, not a redefinition, and every claim below is checked against the
iterative loop rather than argued from the algebra alone.

Identify an n-bit BitArray with a polynomial in GF(2)[x]/(x^n + 1) — bit j is
the coefficient of x^j — so that ROL(v, s) = x^s . v and ROR(v, s) = x^-s . v.
Writing M = 1 + x + x^(n-1) (the map I XOR ROL XOR ROR),

    FSCX(A, B)            = M . (A + B)
    FSCX_REVOLVE(A, B, i) = M^i . A  +  T_i . B,    T_i = M . S_i

with S_i = sum_{j<i} M^j.  S_i and T_i are named as in fscx_revolve_corank.py,
which uses the same decomposition to measure what T_i fails to cover.

  §1  The telescoping identity, checked against the loop
  §2  Why no dense polynomial multiplication is needed (the Frobenius argument)
  §3  Computing S_i in O(log i) sparse steps
  §4  Bit-exactness: exhaustive at n=8, randomised at the deployed widths
  §5  Operation counts and measured speedup
  §6  Why this does not extend to the NL-FSCX variants

RESULTS

§2  M^(2^u) = 1 + x^(2^u) + x^-(2^u) is a THREE-term polynomial for every u, so
    multiplying by it is two rotations and two XORs — one FSCX step with stride
    2^u instead of 1.  The factor the S_i recurrence uses, 1 + M^(2^u), is
    sparser still at two terms.  Dense polynomial multiplication never appears,
    which is what makes the closed form win rather than merely change the
    asymptotics.

§4  Bit-exact in 2 686 976 exhaustive cases at n=8 and every randomised case at
    n in {24, 40, 64, 96, 128, 256, 512}, steps 0..70 plus the deployed and
    boundary counts.  Non-power-of-two widths included: the identity needs only
    characteristic 2, not n a power of two.

§5  At n=256 the deployed step counts cost 10 sparse steps (i = n/4 = 64,
    encrypt) and 13 (r = 3n/4 = 192, decrypt), against 64 and 192 FSCX rounds.
    Measured Python speedup ~40x and ~100x respectively; see benchmarks/.

§6  The NL-FSCX variants are non-linear by construction, so nothing telescopes
    and they stay iterative.  That is the origin of the cost gap between the
    classical and NL protocols, now explicit rather than incidental.

Self-contained: imports only the suite, like its neighbours.
"""
import importlib.util
import os
import random
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "suite", os.path.join(_ROOT, "Herradura cryptographic suite.py"))
suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(suite)

BitArray = suite.BitArray


# ---------------------------------------------------------------------------
# Reference implementation: the O(i) loop, kept here as the oracle.
# ---------------------------------------------------------------------------

def loop_revolve(A, B, steps):
    """FSCX_REVOLVE by definition — iterate FSCX with B held constant."""
    r = A.copy()
    for _ in range(steps):
        r = suite.fscx(r, B)
    return r


# ---------------------------------------------------------------------------
# §1  The telescoping identity
# ---------------------------------------------------------------------------

def polymul(a, b, n):
    """Schoolbook multiply in GF(2)[x]/(x^n + 1) — reference only, never used
    by the fast path.  This is the dense multiply the closed form avoids."""
    mask = (1 << n) - 1
    r = 0
    while b:
        low = b & -b
        k = low.bit_length() - 1
        r ^= ((a << k) | (a >> (n - k))) & mask if k else a
        b ^= low
    return r


def section1(n=64, trials=200):
    print("§1  FSCX_REVOLVE(A, B, i) = M^i . A + T_i . B, checked against the loop")
    M = 1 | (1 << 1) | (1 << (n - 1))
    rng = random.Random(1)
    bad = 0
    for _ in range(trials):
        A = BitArray(n, rng.getrandbits(n))
        B = BitArray(n, rng.getrandbits(n))
        i = rng.randrange(0, 3 * n)
        Mi, S = 1, 0
        for _ in range(i):                      # M^i and S_i, by definition
            S ^= Mi
            Mi = polymul(Mi, M, n)
        T = polymul(M, S, n)
        want = loop_revolve(A, B, i).uint
        got = polymul(Mi, A.uint, n) ^ polymul(T, B.uint, n)
        bad += (want != got)
    print(f"    n={n}: {trials} random (A, B, i) — mismatches: {bad}")
    print(f"    -> {'identity holds' if bad == 0 else 'IDENTITY FAILED'}\n")
    return bad == 0


# ---------------------------------------------------------------------------
# §2  Why no dense multiplication is needed
# ---------------------------------------------------------------------------

def section2(n=256):
    print("§2  M^(2^u) stays a three-term polynomial (Frobenius, characteristic 2)")
    M = 1 | (1 << 1) | (1 << (n - 1))
    p = M
    ok = True
    for u in range(0, 12):
        s = (1 << u) % n
        # The three monomials XOR: at s = n/2 the outer two coincide and cancel,
        # and at s = 0 all three collapse onto 1.  OR-ing them would be wrong.
        expect = 1 ^ (1 << s) ^ (1 << ((n - s) % n))
        if p != expect:
            ok = False
        note = ""
        if s == 0:
            note = "  <- 1+1+1 = 1"
        elif s == n // 2:
            note = "  <- x^s and x^-s coincide and cancel"
        if u < 5 or note:
            print(f"    u={u:>2}  s=2^u mod n={s:>3}"
                  f"  weight(M^(2^u))={bin(p).count('1')}{note}")
        p = polymul(p, p, n)
    print(f"    -> {'matches 1 + x^s + x^-s at every u' if ok else 'MISMATCH'}")
    print("    so M^(2^u) . v      = v ^ ROL(v, s) ^ ROR(v, s)   (2 rotations, 2 XORs)")
    print("    and (1 + M^(2^u)).v =     ROL(v, s) ^ ROR(v, s)   (2 rotations, 1 XOR)")
    print("    — the constant terms cancel in the second, which is the factor the")
    print("      S_i recurrence actually uses.\n")
    return ok


# ---------------------------------------------------------------------------
# §3 / §4  The fast path, and bit-exactness against the loop
# ---------------------------------------------------------------------------

def section4():
    print("§4  Bit-exactness of the shipped closed form against the loop")

    bad = 0
    total = 0
    for A in range(256):                        # exhaustive at n=8
        a = BitArray(8, A)
        for B in range(256):
            b = BitArray(8, B)
            for i in range(41):
                total += 1
                bad += (loop_revolve(a, b, i).uint
                        != suite.fscx_revolve(a, b, i).uint)
    print(f"    exhaustive n=8, steps 0..40: {total} cases, {bad} mismatches")

    rng = random.Random(4)
    rbad = 0
    rtotal = 0
    for n in (24, 40, 64, 96, 128, 256, 512):   # non-powers of two included
        for _ in range(6):
            a = BitArray(n, rng.getrandbits(n))
            b = BitArray(n, rng.getrandbits(n))
            for i in list(range(0, 71)) + [n // 4, n // 2, 3 * n // 4, n,
                                           2 * n, 191, 192, 255, 1000, 4097]:
                rtotal += 1
                rbad += (loop_revolve(a, b, i).uint
                         != suite.fscx_revolve(a, b, i).uint)
    print(f"    randomised, n in {{24,40,64,96,128,256,512}}: {rtotal} cases,"
          f" {rbad} mismatches")
    print(f"    -> {'bit-exact' if bad == 0 and rbad == 0 else 'NOT BIT-EXACT'}\n")
    return bad == 0 and rbad == 0


# ---------------------------------------------------------------------------
# §5  Operation counts and measured speedup
# ---------------------------------------------------------------------------

def sparse_steps(i, n):
    """Count the sparse multiplies the SHIPPED closed form actually performs.

    Counted by instrumenting the suite's own helpers rather than re-deriving the
    formula, so this cannot drift from the implementation.  Both helpers return
    early when the stride is 0 (which happens once 2^u is a multiple of n), and
    those early returns are exactly why a step count above n costs less than the
    bit length alone would suggest.
    """
    calls = [0]
    real_m, real_1pm = suite._m_pow2_mul, suite._one_plus_m_pow2_mul

    def count_m(v, st, nn, mask):
        if st:
            calls[0] += 1
        return real_m(v, st, nn, mask)

    def count_1pm(v, st, nn, mask):
        if st:
            calls[0] += 1
        return real_1pm(v, st, nn, mask)

    suite._m_pow2_mul, suite._one_plus_m_pow2_mul = count_m, count_1pm
    try:
        suite.fscx_revolve(BitArray(n, 1), BitArray(n, 1), i)
    finally:
        suite._m_pow2_mul, suite._one_plus_m_pow2_mul = real_m, real_1pm
    return calls[0]


def section5(n=256):
    print("§5  Operation counts and measured speedup (n=256)")
    print(f"    {'steps':>6} {'FSCX rounds':>12} {'sparse steps':>13}"
          f" {'loop ms':>9} {'closed ms':>10} {'speedup':>8}")
    rng = random.Random(5)
    A = BitArray(n, rng.getrandbits(n))
    B = BitArray(n, rng.getrandbits(n))
    rows = []
    for i in (1, 2, 4, 8, 16, 32, 64, 192, 1024):
        reps = max(30, min(2000, 40000 // max(i, 1)))
        t0 = time.perf_counter()
        for _ in range(reps):
            loop_revolve(A, B, i)
        tl = (time.perf_counter() - t0) / reps * 1000
        t0 = time.perf_counter()
        for _ in range(reps):
            suite.fscx_revolve(A, B, i)
        tc = (time.perf_counter() - t0) / reps * 1000
        print(f"    {i:>6} {i:>12} {sparse_steps(i, n):>13}"
              f" {tl:>9.4f} {tc:>10.4f} {tl / tc:>7.1f}x")
        rows.append((i, tl, tc))
    print("    deployed: i = n/4 = 64 (encrypt), r = 3n/4 = 192 (decrypt)")
    print("    steps >= n cost less than their bit length: once 2^u is a multiple")
    print("    of n the stride is 0 and the factor is trivial.\n")
    return rows


# ---------------------------------------------------------------------------
# §6  Why the NL variants cannot use this
# ---------------------------------------------------------------------------

def section6(n=64, trials=300):
    print("§6  NL-FSCX is not affine, so nothing telescopes")
    rng = random.Random(6)
    viol = 0
    for _ in range(trials):
        x = BitArray(n, rng.getrandbits(n))
        y = BitArray(n, rng.getrandbits(n))
        k = BitArray(n, rng.getrandbits(n))
        lhs = suite.nl_fscx_revolve_v1(x ^ y, k, n // 4).uint
        rhs = (suite.nl_fscx_revolve_v1(x, k, n // 4).uint
               ^ suite.nl_fscx_revolve_v1(y, k, n // 4).uint
               ^ suite.nl_fscx_revolve_v1(BitArray(n, 0), k, n // 4).uint)
        viol += (lhs != rhs)
    print(f"    affinity in the first argument violated in {viol}/{trials} trials")
    print("    -> no M^i / S_i decomposition exists; the NL variants stay O(i),")
    print("       which is where the classical-vs-NL cost gap comes from\n")
    return viol > 0


def main():
    print(__doc__.split("RESULTS")[0].strip())
    print()
    ok = []
    ok.append(section1())
    ok.append(section2())
    ok.append(section4())
    section5()
    ok.append(section6())
    print("=" * 70)
    print("ALL CHECKS PASSED" if all(ok) else "SOME CHECKS FAILED")
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
