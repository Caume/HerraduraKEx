#!/usr/bin/env python3
"""Machine-checked verification (Z3/SMT) of the HPKS Schnorr identity
(SecurityProofs-1.md Section 2, "HPKS - Public Key Signature"):

    R = g^k              (commitment)
    e = <challenge>       (independent of k algebraically -- treated as a free
                           symbolic scalar here, since the challenge is a hash
                           output and the identity must hold for every possible
                           challenge value)
    s = (k - a*e) mod ord
    verify:  g^s * C^e == R,   where C = g^a

This is a statement about GF(2^n)* exponent arithmetic: g^s * C^e = g^(s + a*e)
and the claim reduces to (s + a*e) mod ord == k mod ord. Rather than trust that
by hand, this script encodes gf_mul/gf_pow bit-for-bit as Z3 bitvector circuits
(same square-and-multiply structure as SecurityProofsCode/hkex_gf_test.py) and
asks Z3 to prove, via UNSAT of the negation over free symbolic a, k, e, that
g^s * C^e == R holds for *every* possible (a, k, e) triple at a given width --
not just sampled ones.

Full 256-bit symbolic square-and-multiply -- especially the modular exponent
reduction (a*e mod ord), which is nonlinear bitvector arithmetic -- is beyond
what a general-purpose SMT solver closes in reasonable time even at n=8,
where the fully symbolic query does not terminate. This script therefore
runs three levels of check, from strongest-but-narrowest to weakest-but-widest:

  1. Fully symbolic SMT proof (UNSAT of the negation, true for *every*
     (a,k,e) at that width) at n=4, where the query is tractable.
  2. Complete enumeration of every (a,e) pair (direct computation, not SMT)
     against a representative set of k values, at n=8.
  3. Randomized sampling at production-relevant widths -- n=32, 64, and the
     deployed n=256 -- since neither symbolic proof nor exhaustive
     enumeration is tractable there.

Only level 1 is a formal proof; levels 2-3 are mechanized but not exhaustive
over the full input space at those widths. The algebraic identity itself is
width-independent (a property of exponent arithmetic in any group of order
`ord`, not of the specific field size), so confirming it at n=4 symbolically
and then spot-checking the identical code path at n=256 corroborates that
the production width behaves the same way.

Usage: python3 SecurityProofsCode/hpks_schnorr_z3.py
"""
import secrets
import z3

# Primitive polynomials for small illustrative widths (lower n bits).
GF_POLY = {
    4: 0x3,    # x^4 + x + 1
    8: 0x1B,   # x^8 + x^4 + x^3 + x + 1 (AES polynomial)
}
G = 3

# Widths for the randomized large-width sanity pass. 32/64 match
# hkex_gf_test.py; 256 is herradura.h's deployed GF_POLY (0x0425 in the
# low bits: x^256 + x^10 + x^5 + x^2 + 1).
GF_POLY_LARGE = {
    32:  0x00400007,
    64:  0x000000000000001B,
    256: 0x0425,
}


def gf_mul_z3(a, b, poly, n):
    """Z3 bitvector encoding of GF(2^n) multiply, identical structure to
    hkex_gf_test.gf_mul's shift-and-XOR loop."""
    result = z3.BitVecVal(0, n)
    high_bit = 1 << (n - 1)
    poly_bv = z3.BitVecVal(poly, n)
    for _ in range(n):
        result = z3.If(z3.Extract(0, 0, b) == 1, result ^ a, result)
        carry = z3.Extract(n - 1, n - 1, a) == 1
        a = a << 1
        a = z3.If(carry, a ^ poly_bv, a)
        b = z3.LShR(b, 1)
    return result


def gf_pow_z3(base, exp, poly, n):
    """Z3 bitvector encoding of GF(2^n)* exponentiation via square-and-multiply,
    identical structure to hkex_gf_test.gf_pow."""
    result = z3.BitVecVal(1, n)
    for _ in range(n):
        result = z3.If(z3.Extract(0, 0, exp) == 1, gf_mul_z3(result, base, poly, n), result)
        base = gf_mul_z3(base, base, poly, n)
        exp = z3.LShR(exp, 1)
    return result


def check_width(n):
    poly = GF_POLY[n]
    ord_val = (1 << n) - 1  # order of GF(2^n)*

    a = z3.BitVec("a", n)
    k = z3.BitVec("k", n)
    e = z3.BitVec("e", n)

    C = gf_pow_z3(z3.BitVecVal(G, n), a, poly, n)
    R = gf_pow_z3(z3.BitVecVal(G, n), k, poly, n)

    # s = (k - a*e) mod ord, computed in a wider bitvector to avoid underflow,
    # then reduced mod ord -- exactly mirroring the Python reference semantics.
    w = 2 * n + 4
    k_w = z3.ZeroExt(w - n, k)
    a_w = z3.ZeroExt(w - n, a)
    e_w = z3.ZeroExt(w - n, e)
    ord_w = z3.BitVecVal(ord_val, w)
    prod = z3.URem(a_w * e_w, ord_w)
    diff = z3.URem(ord_w + k_w - prod, ord_w)  # add ord_w to keep operand non-negative
    s_wide = z3.URem(diff, ord_w)
    s = z3.Extract(n - 1, 0, s_wide)

    lhs = gf_mul_z3(gf_pow_z3(z3.BitVecVal(G, n), s, poly, n),
                     gf_pow_z3(C, e, poly, n), poly, n)

    solver = z3.Solver()
    solver.add(lhs != R)
    result = solver.check()
    ok = result == z3.unsat
    print(f"  n = {n}: g^s * C^e == R for all (a,k,e) -> "
          f"{'PROVED' if ok else f'FAILED ({result})'}")
    return ok


def gf_mul_concrete(a, b, poly, n):
    result = 0
    mask = (1 << n) - 1
    high_bit = 1 << (n - 1)
    for _ in range(n):
        if b & 1:
            result ^= a
        carry = bool(a & high_bit)
        a = (a << 1) & mask
        if carry:
            a ^= poly
        b >>= 1
    return result


def gf_pow_concrete(base, exp, poly, n):
    result = 1
    base &= (1 << n) - 1
    while exp:
        if exp & 1:
            result = gf_mul_concrete(result, base, poly, n)
        base = gf_mul_concrete(base, base, poly, n)
        exp >>= 1
    return result


def check_width_exhaustive(n, k_samples=None):
    """Complete enumeration over every (a, e) pair via direct computation --
    not SMT, but not sampled either for that dimension. k is varied over a
    fixed representative set (0, 1, mid-range, max, and a few others) rather
    than enumerated in full, since s is defined *from* k for each (a,e), so
    varying (a,e) exhaustively is what stresses the identity; k coverage adds
    boundary/wraparound cases on top of that."""
    poly = GF_POLY[n]
    ord_val = (1 << n) - 1
    if k_samples is None:
        k_samples = sorted({0, 1, 2, ord_val // 2, ord_val - 1, ord_val})
    cases = 0
    for a in range(ord_val + 1):
        C = gf_pow_concrete(G, a, poly, n)
        for e in range(ord_val + 1):
            Ce = gf_pow_concrete(C, e, poly, n)
            for k in k_samples:
                R = gf_pow_concrete(G, k, poly, n)
                s = (k - a * e) % ord_val
                lhs = gf_mul_concrete(gf_pow_concrete(G, s, poly, n), Ce, poly, n)
                cases += 1
                if lhs != R:
                    print(f"  n = {n}: COUNTEREXAMPLE a={a} k={k} e={e}")
                    return False
    print(f"  n = {n}: g^s * C^e == R for all (a,e) x k in {k_samples} -> "
          f"VERIFIED ({cases} cases)")
    return True


def check_width_random(n, poly, trials=200):
    ord_val = (1 << n) - 1
    for _ in range(trials):
        a = secrets.randbelow(ord_val + 1)
        e = secrets.randbelow(ord_val + 1)
        k = secrets.randbelow(ord_val + 1)
        C = gf_pow_concrete(G, a, poly, n)
        R = gf_pow_concrete(G, k, poly, n)
        s = (k - a * e) % ord_val
        lhs = gf_mul_concrete(gf_pow_concrete(G, s, poly, n),
                               gf_pow_concrete(C, e, poly, n), poly, n)
        if lhs != R:
            print(f"  n = {n}: COUNTEREXAMPLE a={a} k={k} e={e}")
            return False
    print(f"  n = {n}: g^s * C^e == R for {trials} random (a,k,e) -> OK")
    return True


def main():
    print("Mechanized (Z3/SMT) verification of the HPKS Schnorr identity")
    print("(SecurityProofs-1.md Section 2: g^s * C^e == R)")
    print("=" * 70)
    print("Symbolic SMT proof:")
    all_ok = check_width(4)
    print()
    print("Complete (a,e) enumeration, representative k (not SMT-tractable at this width):")
    all_ok &= check_width_exhaustive(8)
    print()
    print("Randomized sanity pass at production-relevant widths (incl. deployed n=256):")
    for n, poly in GF_POLY_LARGE.items():
        all_ok &= check_width_random(n, poly)
    print()
    print("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
