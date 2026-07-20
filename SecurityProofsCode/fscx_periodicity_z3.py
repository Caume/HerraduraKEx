#!/usr/bin/env python3
"""Machine-checked verification (Z3/SMT) of the FSCX periodicity claims in
SecurityProofs-1.md Section 1 (Theorems 2-4, Corollary 1).

FSCX linear map:      M(x) = x XOR ROL(x,1) XOR ROR(x,1)
FSCX_REVOLVE(A,B,k):  k-fold iteration of X -> FSCX(X,B) = M(X) XOR M(B), starting at A.

For each bit-width n = 2^k (including the deployed n=256), this script asks Z3 to
prove -- as SMT validity via UNSAT of the negation over free symbolic bitvectors,
i.e. true for *all* inputs of that width, not just sampled ones -- that:

  Theorem 2  M is invertible          (injective: M(x)=0 => x=0)
  Theorem 3  M has order n/2          (M^(n/2) = I)
  Corollary 1  S_n := I+M+...+M^(n-1) = 0
  Theorem 4  FSCX_REVOLVE(A,B,n) = A  for all A,B  (period divides n)

It also empirically measures the minimal orbit period of f_B(X)=FSCX(X,B) for random
(A,B) pairs at each width, to check the (separately, only empirically claimed in the
hand proof) observation that the actual period is always n or n/2.

Usage: python3 SecurityProofsCode/fscx_periodicity_z3.py
"""
import random
import z3


def M(x, n):
    return x ^ z3.RotateLeft(x, 1) ^ z3.RotateRight(x, 1)


def M_pow(x, k, n):
    for _ in range(k):
        x = M(x, n)
    return x


def prove_unsat(claim_negation, description):
    solver = z3.Solver()
    solver.add(claim_negation)
    result = solver.check()
    status = "PROVED" if result == z3.unsat else f"FAILED ({result}, model={solver.model() if result == z3.sat else None})"
    print(f"    {description}: {status}")
    return result == z3.unsat


def check_width(n):
    print(f"  n = {n}:")
    ok = True

    # Theorem 2: M invertible <=> injective (linear map) <=> M(x)=0 implies x=0.
    x = z3.BitVec("x", n)
    ok &= prove_unsat(z3.And(x != 0, M(x, n) == 0), "Theorem 2 (M invertible)")

    # Theorem 3: M^(n/2) = I.
    x = z3.BitVec("x", n)
    ok &= prove_unsat(M_pow(x, n // 2, n) != x, "Theorem 3 (M^(n/2) = I)")

    # Corollary 1: S_n(x) = XOR_{j=0}^{n-1} M^j(x) = 0 for all x.
    x = z3.BitVec("x", n)
    s = z3.BitVecVal(0, n)
    cur = x
    for _ in range(n):
        s ^= cur
        cur = M(cur, n)
    ok &= prove_unsat(s != 0, "Corollary 1 (S_n = 0)")

    # Theorem 4: FSCX_REVOLVE(A,B,n) = A for all A,B.
    A = z3.BitVec("A", n)
    B = z3.BitVec("B", n)
    mb = M(B, n)
    cur = A
    for _ in range(n):
        cur = M(cur, n) ^ mb
    ok &= prove_unsat(cur != A, "Theorem 4 (FSCX_REVOLVE(A,B,n) = A)")

    return ok


def empirical_period(n, trials=20):
    mask = (1 << n) - 1

    def rol(v):
        return ((v << 1) | (v >> (n - 1))) & mask

    def ror(v):
        return ((v >> 1) | (v << (n - 1))) & mask

    def fscx(x, b):
        return (x ^ b ^ rol(x) ^ rol(b) ^ ror(x) ^ ror(b)) & mask

    rng = random.Random(1234 + n)
    periods = set()
    for _ in range(trials):
        a = rng.getrandbits(n)
        b = rng.getrandbits(n)
        x = a
        for step in range(1, n + 1):
            x = fscx(x, b)
            if x == a:
                periods.add(step)
                break
        else:
            periods.add(None)  # did not return within n steps (would contradict Theorem 4)
    return periods


def main():
    widths = [8, 16, 32, 64, 128, 256]
    print("Mechanized (Z3/SMT) verification of SecurityProofs-1.md Section 1 claims")
    print("=" * 78)
    all_ok = True
    for n in widths:
        all_ok &= check_width(n)

    print()
    print("Empirical orbit-period check (period is always n or n/2, per hand-proof note):")
    for n in widths:
        periods = empirical_period(n)
        expected = {n, n // 2}
        verdict = "OK" if periods <= expected else f"UNEXPECTED periods {periods - expected}"
        print(f"  n = {n}: observed periods {sorted(p for p in periods if p)} -> {verdict}")

    print()
    print("ALL SMT PROOFS PASSED" if all_ok else "SOME SMT PROOFS FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
