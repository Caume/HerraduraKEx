#!/usr/bin/env python3
"""
nl_fscx_carry_degeneracy_2026.py — TODO #159 second pass: where does the carry
non-linearity degenerate?

Both NL-FSCX variants buy their non-linearity from one place: the carry chain of a
modular addition.  Everything else in the suite's round functions (the FSCX map
M = I XOR ROL XOR ROR, the rotations, the XORs) is GF(2)-linear.  That makes one
question worth asking of each construction:

    for which inputs does the addition stop producing carries?

Wherever the answer is "a non-negligible set", the round function collapses to an affine
map and the construction is only as strong as GF(2) linear algebra.  This script asks
that question of the two targets TODO #159 work item 1 named but the first pass did not
reach — HFSCX-256-DM's finalizer/compression and NL-FSCX v2's CSP construction.

  §1  HFSCX-256-DM, all-zero message block — CLEAN, but not for an obvious reason
  §2  NL-FSCX v2 — a genuine affine weak-key class

RESULTS

§1  With an all-zero message block, A + B has no carries, so the Davies-Meyer inner
    function degenerates to the GF(2)-linear map L^{n/4} with
    L = 1 + X + X^{n/4} + X^{n-1} over GF(2)[X]/(X^n + 1).  Its rank is exactly n/2 —
    at the deployed n=256 the "block cipher" crushes the 256-bit chaining value onto a
    2^128 subspace.  Collision resistance survives only because the Davies-Meyer
    feed-forward makes the compression C(s,0) = L^{n/4}(s) XOR s, and that map is
    invertible: over GF(2), X^n + 1 = (X+1)^n, so with Y = X+1 the ring is local and
    L = Y^2 * u for a unit u, whence L^{n/4} = Y^{n/2} * u^{n/4} and L^{n/4} + 1 has
    constant term 1 — a unit, therefore invertible.  The feed-forward is load-bearing
    here in a way the existing §11.9 analysis does not record.

§2  NL-FSCX v2's offset delta(K) is added as a *constant*, and addition of a constant c
    is GF(2)-affine for every input exactly when c is 0 or 2^{n-1} (the top carry is
    discarded mod 2^n).  So whenever delta(K) lands on one of those two values the whole
    "non-linear" permutation pi_K(A) = M(A XOR K) + delta(K) is affine, and HSKE-NL-A2 /
    HPKE-NL reduce to a linear system solvable from a few known plaintexts.  Such keys
    exist: at n=256, every K divisible by 2^129 gives delta(K)=0 (2^127 keys), and
    K = 2^96 gives delta(K) = 2^255.  Class density is about 2^-129, so a uniformly
    random key is not at risk — but this is a weak-key class that is trivially cheap to
    reject and is currently unrejected.  Filed as TODO #168.

Self-contained (no imports from the suite), per SecurityProofsCode convention; the
primitives below are transcribed from `Herradura cryptographic suite.py`.
"""

import math
import random

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (transcribed from the suite)
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1) if r else x


def M(x, n):
    """FSCX linear map M = I XOR ROL XOR ROR."""
    return x ^ rotl(x, 1, n) ^ rotl(x, n - 1, n)


def nl_fscx_v1(A, B, n):
    """nl_fscx_v1(A,B) = M(A XOR B) XOR ROL((A+B) mod 2^n, n/4)."""
    return M(A ^ B, n) ^ rotl((A + B) & ((1 << n) - 1), n // 4, n)


def delta(K, n):
    """NL-FSCX v2 key offset: ROL(K * floor((K+1)/2) mod 2^n, n/4)."""
    return rotl((K * ((K + 1) >> 1)) & ((1 << n) - 1), n // 4, n)


def pi(A, K, n):
    """NL-FSCX v2 permutation: pi_K(A) = (M(A XOR K) + delta(K)) mod 2^n."""
    return (M(A ^ K, n) + delta(K, n)) & ((1 << n) - 1)


def gf2_rank(rows, n):
    rows = list(rows)
    rk = 0
    for col in range(n):
        piv = None
        for i in range(rk, len(rows)):
            if (rows[i] >> col) & 1:
                piv = i
                break
        if piv is None:
            continue
        rows[rk], rows[piv] = rows[piv], rows[rk]
        for i in range(len(rows)):
            if i != rk and (rows[i] >> col) & 1:
                rows[i] ^= rows[rk]
        rk += 1
    return rk


# ─────────────────────────────────────────────────────────────────────────────
# §1  HFSCX-256-DM under an all-zero message block
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP)
    print("§1  HFSCX-256-DM: the all-zero message block")
    print(SEP)
    print("With B = 0 the sum A + 0 produces no carries, so the compression's inner")
    print("function F(s,0) = nl_fscx_revolve_v1(s, 0, n/4) is GF(2)-LINEAR:")
    print("    L = 1 + X + X^{n/4} + X^{n-1}   over GF(2)[X]/(X^n + 1)")
    print()

    def Lmap(x, n):
        return nl_fscx_v1(x, 0, n)

    print(f"  {'n':>5} {'steps':>6} {'rank F(.,0)':>12} {'kernel':>8} {'rank C_DM(.,0)':>16} {'verdict':>12}")
    print(f"  {'-' * 5} {'-' * 6} {'-' * 12} {'-' * 8} {'-' * 16} {'-' * 12}")
    for n in (16, 32, 64, 128, 256):
        s = n // 4

        def Ls(x, n=n, s=s):
            for _ in range(s):
                x = Lmap(x, n)
            return x

        rank_F = gf2_rank([Ls(1 << j) for j in range(n)], n)
        rank_C = gf2_rank([Ls(1 << j) ^ (1 << j) for j in range(n)], n)
        verdict = "bijective" if rank_C == n else "COLLISIONS"
        print(f"  {n:>5} {s:>6} {rank_F:>12} {n - rank_F:>8} {rank_C:>16} {verdict:>12}")
    print()
    print("  The inner map's rank is exactly n/2 — at n=256 it compresses the chaining")
    print("  value 2^128-to-1. The Davies-Meyer feed-forward is what saves it: over GF(2),")
    print("  X^n + 1 = (X+1)^n, so with Y = X+1 the ring is local and L = Y^2 * u (u a")
    print("  unit); hence L^{n/4} = Y^{n/2} * u^{n/4}, and L^{n/4} + 1 has constant term 1,")
    print("  a unit — therefore invertible. Verified above at every deployed size.")
    print()

    # brute-force cross-check of the algebra at n=16
    n, s = 16, 4

    def Ls16(x):
        for _ in range(s):
            x = Lmap(x, n)
        return x

    img_F = len({Ls16(x) for x in range(1 << n)})
    img_C = len({Ls16(x) ^ x for x in range(1 << n)})
    print(f"  Brute-force check n=16: |image F(.,0)| = {img_F} of {1 << n}; "
          f"|image C_DM(.,0)| = {img_C} of {1 << n}")
    print(f"  => zero-block compression is {'injective (no weakness)' if img_C == (1 << n) else 'NOT injective'}")
    print()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# §2  NL-FSCX v2 affine weak-key class
# ─────────────────────────────────────────────────────────────────────────────

def is_affine(K, n):
    """Exact test: pi_K affine over GF(2) iff L(a) = pi(a) XOR pi(0) is linear."""
    p0 = pi(0, K, n)
    basis = [pi(1 << i, K, n) ^ p0 for i in range(n)]

    def lin(a):
        acc, i = 0, 0
        while a:
            if a & 1:
                acc ^= basis[i]
            a >>= 1
            i += 1
        return acc

    rng = random.Random(K)
    for _ in range(24):                       # quick reject
        a = rng.randrange(1 << n)
        if pi(a, K, n) ^ p0 != lin(a):
            return False
    for a in range(1 << n):                   # exhaustive confirmation
        if pi(a, K, n) ^ p0 != lin(a):
            return False
    return True


def section2():
    print(SEP)
    print("§2  NL-FSCX v2: an affine weak-key class")
    print(SEP)
    print("delta(K) is added as a CONSTANT. Addition of a constant c is GF(2)-affine for")
    print("every input exactly when c is 0 or 2^{n-1} (the top carry is discarded mod 2^n).")
    print("Since M is invertible at every power-of-two n, M(A XOR K) is a bijection and")
    print("    pi_K affine  <=>  delta(K) in {0, 2^{n-1}}")
    print()

    print(f"  {'n':>5} {'rank M':>8} {'affine keys':>12} {'delta=0':>9} {'delta=2^(n-1)':>14} {'characterisation':>17}")
    print(f"  {'-' * 5} {'-' * 8} {'-' * 12} {'-' * 9} {'-' * 14} {'-' * 17}")
    for n in (8, 12, 16):
        N = 1 << n
        rkM = gf2_rank([M(1 << j, n) for j in range(n)], n)
        affine = {K for K in range(N) if is_affine(K, n)}
        d0 = sum(1 for K in range(N) if delta(K, n) == 0)
        dm = sum(1 for K in range(N) if delta(K, n) == 1 << (n - 1))
        pred = {K for K in range(N) if delta(K, n) in (0, 1 << (n - 1))}
        tag = "exact" if affine == pred else "differs (M singular)"
        print(f"  {n:>5} {rkM:>8} {len(affine):>12} {d0:>9} {dm:>14} {tag:>17}")
    print()
    print("  n=12 is the one mismatch and is outside the design regime: M is singular")
    print("  there (rank 10/12), so M(A XOR K) is not surjective and the addition only")
    print("  needs to be affine on a subspace. Every deployed size is a power of two,")
    print("  where M is invertible and the characterisation is exact.")
    print()

    n = 256
    print(f"  Deployed n={n} — concrete weak keys:")
    for lbl, K in (("2^129", 1 << 129), ("2^130", 1 << 130), ("2^96", 1 << 96)):
        d = delta(K, n)
        kind = "delta = 0" if d == 0 else "delta = 2^255"
        print(f"    K = {lbl:<8s} -> {kind:<14s} pi_K is affine: {d in (0, 1 << (n - 1))}")
    print()
    print("  Every K divisible by 2^129 has delta(K) = 0: that alone is 2^127 keys of")
    print("  2^256, a class density of about 2^-129. A uniformly random key is therefore")
    print("  NOT at risk. But for such a key HSKE-NL-A2 / HPKE-NL collapse to an affine")
    print("  map recoverable from a handful of known plaintexts by linear algebra, and")
    print("  the check `delta(K) not in {0, 2^(n-1)}` is one line. Filed as TODO #168.")
    print()

    # demonstrate the break on a weak key at a tractable size
    n = 16
    K = 1 << 9                                # smallest nonzero delta=0 key at n=16
    assert delta(K, n) == 0
    p0 = pi(0, K, n)
    basis = [pi(1 << i, K, n) ^ p0 for i in range(n)]
    rng = random.Random(1)
    ok = 0
    for _ in range(500):
        a = rng.randrange(1 << n)
        acc, t, i = 0, a, 0
        while t:
            if t & 1:
                acc ^= basis[i]
            t >>= 1
            i += 1
        if acc ^ p0 == pi(a, K, n):
            ok += 1
    print(f"  Demonstration at n=16, K=2^9 (delta=0): the map is fully predicted by its")
    print(f"  {n} basis images plus a constant — {ok}/500 random inputs reproduced exactly.")
    print()


def main():
    print()
    print(SEP)
    print("TODO #159 second pass — carry-degeneracy of NL-FSCX v1/v2 constructions")
    print(SEP)
    print()
    section1()
    section2()
    print(SEP)
    print("Summary: §1 HFSCX-256-DM clean (feed-forward load-bearing, now documented);")
    print("         §2 NL-FSCX v2 affine weak-key class -> TODO #168.")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
