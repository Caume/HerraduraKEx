#!/usr/bin/env python3
"""
fscx_revolve_corank.py — TODO #210: how much plaintext does the classical
FSCX_REVOLVE key map fail to cover?

FSCX_REVOLVE is affine.  Writing M = I XOR ROL XOR ROR and S_i = sum_{j<i} M^j,

    fscx_revolve(P, K, i) = M^i . P  XOR  T_i . K        with T_i = M . S_i

so the key contributes nothing outside the *image* of T_i.  Whatever T_i misses is
a linear functional of the plaintext that no key value can mask — readable straight
off the ciphertext, with no known plaintext and no key recovery.  The question this
script asks is therefore the only one that matters for the classical constructions:

    is T_i invertible at the deployed step counts?

It is not.  At the deployed i = n/4 the co-rank is 126 out of 256.

  §1  Rank/co-rank of T_i, measured directly from the primitive
  §2  Closed form for the co-rank, and why it is a 2-adic valuation
  §3  The leak exhibited: 126 functionals that are constant across all keys
  §4  What each classical protocol loses
  §5  The nonce-augmented map of SecurityProofs-2.md §2.2, for completeness

RESULTS

§1  co-rank(T_i) at n=256 is 126 for i = n/4 = 64 (encrypt) and for r = 3n/4 = 192
    (decrypt); rank is 130 in both cases.  It is 0 for i odd.  Same shape at
    n=64 (co-rank 30) and n=128 (co-rank 62).

§2  For n = 2^k the co-rank is exactly

        co-rank(T_i) = min(n, 2 * (2^{v2(i)} - 1))

    where v2(i) is the 2-adic valuation of i.  Over GF(2), X^n + 1 = (X+1)^n, so
    R = GF(2)[X]/(X^n+1) is local with maximal ideal (Y), Y = X+1, and every element
    has a valuation.  m(X) = X^{n-1} + 1 + X is a unit (m(1) = 1) while
    m + 1 = X(X^{n-2} + 1) has valuation 2.  Since (M+1) . S_i = M^i + 1 and
    valuations add, v(S_i) = v(M^i + 1) - 2; writing i = 2^a * u with u odd gives
    M^i + 1 = (M^u + 1)^{2^a} and v(M^u + 1) = 2, hence v(S_i) = 2^{a+1} - 2.
    In particular T_i is invertible **iff i is odd** — the deployed i = n/4 is even
    for every supported n, which is the whole of the problem.  The invertible-i
    consequence is TODO #211.

§3  Extracting the 126-dimensional left kernel and evaluating one functional against
    a fixed plaintext under 200 random keys returns the same bit 200/200 times: the
    ciphertext discloses it unconditionally.  The simplest member is parity — M has
    row weight 3, so parity(fscx(A,B)) = parity(A) XOR parity(B), and an even step
    count leaves parity(E) = parity(P) for every key.

§4  HSKE and HPKE leak 126 independent GF(2)-functionals of the plaintext from the
    ciphertext alone.  HPKS's challenge e = fscx_revolve(R, msg, n/4) carries 130
    bits of entropy rather than 256, the other 126 coordinates being a public
    function of R.

§5  The FSCX-REVOLVE-N map S_i . (M + I) analysed in SecurityProofs-2.md §2.2 is
    worse by exactly the valuation of M + I: co-rank 128 at the same parameters.

Self-contained (no imports from the suite), per SecurityProofsCode convention; the
primitives below are transcribed from `Herradura cryptographic suite.py`.
"""

import random

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (transcribed from the suite)
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1)


def fscx(a, b, n):
    """FSCX(A,B) = A^B^ROL(A)^ROL(B)^ROR(A)^ROR(B) = M.(A^B)."""
    x = a ^ b
    return x ^ rotl(x, 1, n) ^ rotl(x, -1, n)


def fscx_revolve(a, b, steps, n):
    for _ in range(steps):
        a = fscx(a, b, n)
    return a


def parity(x):
    return bin(x).count("1") & 1


# ─────────────────────────────────────────────────────────────────────────────
# GF(2) linear algebra over n-bit column vectors packed into Python ints
# ─────────────────────────────────────────────────────────────────────────────

def key_map_columns(i, n):
    """Columns of T_i: T_i . e_k = fscx_revolve(0, e_k, i)."""
    return [fscx_revolve(0, 1 << k, i, n) for k in range(n)]


def rank_gf2(cols, n):
    rows = list(cols)
    r = 0
    for c in range(n):
        piv = next((j for j in range(r, len(rows)) if (rows[j] >> c) & 1), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for j in range(len(rows)):
            if j != r and (rows[j] >> c) & 1:
                rows[j] ^= rows[r]
        r += 1
    return r


def left_kernel(cols, n):
    """All lambda with lambda . T = 0, as a basis of n-bit masks."""
    # Row j of T, packed over the column index k.
    rows = [sum(((cols[k] >> j) & 1) << k for k in range(n)) for j in range(n)]
    aug = [(rows[j], 1 << j) for j in range(n)]
    r = 0
    for c in range(n):
        piv = next((j for j in range(r, len(aug)) if (aug[j][0] >> c) & 1), None)
        if piv is None:
            continue
        aug[r], aug[piv] = aug[piv], aug[r]
        for j in range(len(aug)):
            if j != r and (aug[j][0] >> c) & 1:
                aug[j] = (aug[j][0] ^ aug[r][0], aug[j][1] ^ aug[r][1])
        r += 1
    return [mask for (row, mask) in aug if row == 0]


def v2(k):
    """2-adic valuation."""
    a = 0
    while k % 2 == 0:
        k //= 2
        a += 1
    return a


# ─────────────────────────────────────────────────────────────────────────────
# §1  Measured rank / co-rank of the deployed key map
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP2)
    print("§1  Rank of T_i, the map by which the key enters fscx_revolve")
    print(SEP2)
    print()
    print("    fscx_revolve(P, K, i) = M^i . P  XOR  T_i . K")
    print()
    print("  n     i            rank(T_i)   co-rank   note")
    for n in (64, 128, 256):
        for i, note in ((n // 4, "i = n/4   (encrypt)"),
                        (3 * n // 4, "r = 3n/4  (decrypt)"),
                        (n // 4 + 1, "n/4 + 1   (odd)")):
            rk = rank_gf2(key_map_columns(i, n), n)
            print(f"  {n:<5} {i:<12} {rk:<11} {n - rk:<9} {note}")
    print()
    print("  The deployed parameters lose 126 of 256 dimensions in both directions.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §2  Closed form, from the (X+1)-adic valuation
# ─────────────────────────────────────────────────────────────────────────────

def section2():
    print(SEP2)
    print("§2  co-rank(T_i) = min(n, 2 * (2^v2(i) - 1))")
    print(SEP2)
    print()
    print("  X^n + 1 = (X+1)^n over GF(2), so GF(2)[X]/(X^n+1) is local in Y = X+1.")
    print("  m(X) = X^{n-1} + 1 + X is a unit; v(m + 1) = 2; (M+1).S_i = M^i + 1;")
    print("  i = 2^a * u with u odd gives v(S_i) = 2^{a+1} - 2, and v(M) = 0.")
    print()
    ok = bad = 0
    for n in (32, 64, 128, 256):
        for i in range(1, min(n, 96) + 1):
            measured = n - rank_gf2(key_map_columns(i, n), n)
            predicted = min(n, 2 * (2 ** v2(i) - 1))
            if measured == predicted:
                ok += 1
            else:
                bad += 1
                print(f"  MISMATCH n={n} i={i}: measured {measured}, predicted {predicted}")
    print(f"  Closed form checked against the primitive: {ok} agree, {bad} disagree.")
    print()
    sample = (1, 2, 4, 16, 64, 65, 192, 255)
    print("  n=256:    i  " + "".join(f"{i:>6}" for i in sample))
    print("      co-rank  " + "".join(
        f"{min(256, 2 * (2 ** v2(i) - 1)):>6}" for i in sample))
    print()
    print("  T_i is invertible exactly when i is odd (v2 = 0).  Every supported")
    print("  n has i = n/4 even, so no deployed parameter set is invertible.")
    print("  The odd-i consequence — Shannon-perfect one-time HSKE — is TODO #211.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  The leak, exhibited
# ─────────────────────────────────────────────────────────────────────────────

def section3(trials=200):
    print(SEP2)
    print("§3  126 functionals of the plaintext that no key can mask")
    print(SEP2)
    print()
    n, i = 256, 64
    ker = left_kernel(key_map_columns(i, n), n)
    print(f"  dim of left kernel of T_{i} at n={n}: {len(ker)}")
    print()
    print("  For lambda in the kernel, lambda . E = lambda . (M^i . P) identically in K.")
    print(f"  Checking the first 8 basis functionals against {trials} random keys each,")
    print("  with the plaintext held fixed:")
    print()
    rng = random.Random(20260820)
    P = rng.getrandbits(n)
    lin = fscx_revolve(P, 0, i, n)          # M^i . P
    for idx, lam in enumerate(ker[:8]):
        vals = set()
        for _ in range(trials):
            K = rng.getrandbits(n)
            E = fscx_revolve(P, K, i, n)
            vals.add(parity(lam & E))
        agree = parity(lam & lin) in vals and len(vals) == 1
        print(f"    lambda_{idx}: observed values {sorted(vals)}"
              f"   matches lambda.(M^i.P): {agree}")
    print()
    print("  Simplest member — parity.  M has row weight 3, so parity is preserved by")
    print("  M and parity(fscx(A,B)) = parity(A) XOR parity(B):")
    same = 0
    for _ in range(trials):
        P2 = rng.getrandbits(n)
        K2 = rng.getrandbits(n)
        if parity(fscx_revolve(P2, K2, 64, n)) == parity(P2):
            same += 1
    print(f"    i=64 (even): parity(E) == parity(P) in {same}/{trials} trials")
    same = 0
    for _ in range(trials):
        P2 = rng.getrandbits(n)
        K2 = rng.getrandbits(n)
        if parity(fscx_revolve(P2, K2, 65, n)) == (parity(P2) ^ parity(K2)):
            same += 1
    print(f"    i=65 (odd):  parity(E) == parity(P) XOR parity(K) in {same}/{trials}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §4  Per-protocol consequence
# ─────────────────────────────────────────────────────────────────────────────

def section4():
    print(SEP2)
    print("§4  What each classical protocol loses at n=256")
    print(SEP2)
    print()
    n = 256
    rk = rank_gf2(key_map_columns(n // 4, n), n)
    print(f"  HSKE   E = fscx_revolve(P, K, n/4)          -> {n - rk} of {n} plaintext")
    print(f"         (herradura.h hske_encrypt, I_VALUE)     functionals readable from E")
    print(f"                                                 with no known plaintext")
    print()
    print(f"  HPKE   E = fscx_revolve(P, enc_key, n/4)    -> same {n - rk} functionals;")
    print(f"                                                 the El Gamal layer protects")
    print(f"                                                 enc_key, not P")
    print()
    print(f"  HPKS   e = fscx_revolve(R, msg, n/4)        -> challenge lies in an affine")
    print(f"                                                 subspace of dimension {rk};")
    print(f"                                                 {n - rk} coordinates are a")
    print(f"                                                 public function of R")
    print()
    print("  The NL replacements are not covered by this argument — their carry")
    print("  non-linearity breaks the affine identity outright.  Whether any residual")
    print("  bias survives on this same subspace is a separate measurement (TODO #214);")
    print("  a 400-sample spot check resolves nothing below about 2^-4 and found nothing.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §5  The nonce-augmented map of SecurityProofs-2.md §2.2
# ─────────────────────────────────────────────────────────────────────────────

def section5():
    print(SEP2)
    print("§5  FSCX-REVOLVE-N's key map S_i . (M + I), for completeness")
    print(SEP2)
    print()
    print("  SecurityProofs-2.md §2.2 analyses HSKE in the nonce-augmented form with")
    print("  B = N = K, giving key map S_i . (M + I) rather than T_i = M . S_i.")
    print("  v(M + I) = 2, so that map is worse by exactly two dimensions:")
    print()
    print("  n     i      co-rank(T_i)   co-rank(S_i.(M+I))")
    for n in (64, 128, 256):
        i = n // 4
        cols_t = key_map_columns(i, n)
        # S_i . (M+I) . e_k  =  fscx_revolve(0, M.e_k ^ e_k, i) applied with M factored out:
        # S_i . x = M^{-1} . T_i . x, but computing directly is simpler and assumption-free:
        # column k = sum_{j<i} M^j . (M+I) . e_k, built by iterating M.
        cols_n = []
        for k in range(n):
            x = (1 << k)
            mx = x ^ rotl(x, 1, n) ^ rotl(x, -1, n)   # M . e_k
            v = mx ^ x                                # (M + I) . e_k
            acc, cur = 0, v
            for _ in range(i):
                acc ^= cur
                cur = cur ^ rotl(cur, 1, n) ^ rotl(cur, -1, n)
            cols_n.append(acc)
        print(f"  {n:<5} {i:<6} {n - rank_gf2(cols_t, n):<14} {n - rank_gf2(cols_n, n)}")
    print()
    print("  So the §2.2 theorem's conclusion — 'the offset c_K is a non-zero private")
    print("  additive term' — is true but not sufficient: a non-zero offset confined to")
    print("  a proper subspace still leaves the complement in the clear.")
    print()


def main():
    print()
    print(SEP)
    print("TODO #210 — co-rank of the classical FSCX_REVOLVE key map")
    print(SEP)
    print()
    section1()
    section2()
    section3()
    section4()
    section5()
    print(SEP)
    print("Summary: co-rank(T_i) = 2(2^v2(i) - 1); at the deployed i = n/4 = 64 that is")
    print("         126 of 256 plaintext functionals leaked from the ciphertext alone,")
    print("         for every key.  Invertible exactly for odd i -> TODO #211.")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
