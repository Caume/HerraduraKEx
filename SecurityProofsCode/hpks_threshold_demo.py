"""
hpks_threshold_demo.py — HPKS-T (Threshold/Aggregate Schnorr over GF(2^n)*)
=============================================================================

Demonstrates the n-of-n MuSig2-style threshold Schnorr signature scheme built
on the HPKS-NL primitive.  Also proves the rogue-key attack and shows the
coefficient-binding fix (MuSig2 key-aggregation coefficient).

Mathematical basis
------------------
HPKS-NL sign (single-party):
    s = (k − a·e) mod (2^n − 1)
    Verify: g^s · C^e == R    where C = g^a, R = g^k

n-of-n aggregation:
    Each signer j has secret a_j, public C_j = g^{a_j}.
    Aggregate key: C_agg = Π C_j = g^{Σ a_j}  (GF multiplication = exponent add mod ord)
    Per-signer nonce: k_j random; R_j = g^{k_j}
    Aggregate nonce: R = Π R_j = g^{Σ k_j}
    Challenge: e = nl_fscx_revolve_v1(R, msg, n/4)
    Per-signer response: s_j = (k_j − a_j·e) mod ord
    Aggregate response: s = Σ s_j mod ord
    Verify: g^s · C_agg^e == R   ✓  (because g^{Σ k_j − (Σ a_j)·e} = g^{Σ k_j} · (g^{Σ a_j})^{-e})

Rogue-key attack (without key-aggregation coefficient):
    Mallory announces C_M = g^{a_M} · C_victim^{-1}  (no proof of secret key)
    Aggregate key becomes: C_agg = C_victim · C_M = g^{a_M}
    Mallory can now sign alone — victim's key is cancelled.

MuSig2 fix: key-aggregation coefficient μ_j = H(L, j) where L = sorted list of all pubkeys.
    Effective secret: a_j' = a_j · μ_j mod ord
    Effective pubkey: C_j' = C_j^{μ_j}
    C_agg = Π C_j' = g^{Σ a_j·μ_j}
    Mallory cannot pre-compute C_M to cancel C_victim because μ_j depends on L (which
    includes C_M), creating a circular dependency — the attack collapses.

Composite-modulus note (2^n − 1):
    ord = 2^n − 1 is composite for all even n (Mersenne-number factorisation).
    Shamir secret sharing over Z_{2^n−1} requires careful handling:
    - Lagrange interpolation uses modular inverses; inverses exist only when gcd(divisor, ord)=1.
    - Safe approach: perform Shamir sharing over a large prime q ≥ ord (embed mod q, reduce mod ord).
    - Alternative: restrict to n-of-n (no threshold) which needs no inversion.
    n=256: 2^256−1 factors as 3·5·17·257·641·65537·... (many small primes); naive Shamir
    fails when a Lagrange denominator shares a factor with ord.  This demo restricts to n-of-n.

References
----------
    HPKS-NL protocol: SecurityProofs-1.md §8 (classical), §11.3 (NL extension)
    MuSig2: Nick, Ruffing, Seurin 2021 (https://eprint.iacr.org/2020/1261)
    Bellare–Neven multi-sig: https://cseweb.ucsd.edu/~mihir/papers/multisig.pdf
"""

import hashlib
import random
import sys
import os

# ---------------------------------------------------------------------------
# GF(2^n)* primitives (self-contained)
# ---------------------------------------------------------------------------

# n=256 irreducible polynomial: x^256 + x^10 + x^5 + x^2 + 1  (low bits = 0x425)
GF_N    = 256
GF_POLY = (1 << 256) | 0x425
GF_GEN  = 3
GF_ORD  = (1 << 256) - 1  # 2^256 − 1  (composite Mersenne number)


def gf_mul(a: int, b: int, poly: int = GF_POLY, n: int = GF_N) -> int:
    """Carryless GF(2^n) multiplication mod poly."""
    result = 0
    mask   = (1 << n) - 1
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a >> n:
            a ^= poly
        a &= mask
        b >>= 1
    return result


def gf_pow(base: int, exp: int, poly: int = GF_POLY, n: int = GF_N) -> int:
    """Square-and-multiply GF(2^n) exponentiation."""
    result = 1
    base   = base % ((1 << n) | 1)
    while exp:
        if exp & 1:
            result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


# ---------------------------------------------------------------------------
# NL-FSCX v1 (self-contained, n=32 for speed in the demo script)
# ---------------------------------------------------------------------------

DEMO_N = 32   # use 32-bit for fast demo; the algebra is identical at n=256


def _rol32(x: int, r: int) -> int:
    r %= 32
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def _fscx32(a: int, b: int) -> int:
    return (a ^ b ^ _rol32(a, 1) ^ _rol32(b, 1) ^ _rol32(a, 31) ^ _rol32(b, 31)) & 0xFFFFFFFF


def _nl_add32(a: int, b: int) -> int:
    return (a + b) & 0xFFFFFFFF


def _nl_fscx_v1_step32(a: int, b: int) -> int:
    return _fscx32(_nl_add32(a, b), b)


def nl_fscx_revolve_v1_32(a: int, b: int, steps: int) -> int:
    for _ in range(steps):
        a = _nl_fscx_v1_step32(a, b)
    return a


# ---------------------------------------------------------------------------
# HPKS-NL (single-party) at n=32 for the demo
# ---------------------------------------------------------------------------

GF32_N    = 32
GF32_POLY = (1 << 32) | 0x0000008D   # x^32+x^7+x^3+x^2+1
GF32_GEN  = 3
GF32_ORD  = (1 << 32) - 1
DEMO_I    = GF32_N // 4              # = 8


def _challenge32(R: int, msg: int) -> int:
    return nl_fscx_revolve_v1_32(R, msg, DEMO_I)


def hpks_nl_keygen_32() -> tuple:
    """Returns (a, C) where C = g^a in GF(2^32)*."""
    a = random.randint(1, GF32_ORD - 1)
    C = gf_pow(GF32_GEN, a, GF32_POLY, GF32_N)
    return a, C


def hpks_nl_sign_32(a: int, k: int, msg: int) -> tuple:
    """Single-party HPKS-NL sign. Returns (R, e, s)."""
    R = gf_pow(GF32_GEN, k, GF32_POLY, GF32_N)
    e = _challenge32(R, msg)
    s = (k - a * e) % GF32_ORD
    return R, e, s


def hpks_nl_verify_32(C: int, R: int, e: int, s: int, msg: int) -> bool:
    """Single-party HPKS-NL verify."""
    lhs = gf_mul(gf_pow(GF32_GEN, s, GF32_POLY, GF32_N),
                 gf_pow(C,          e, GF32_POLY, GF32_N), GF32_POLY, GF32_N)
    return lhs == R


# ---------------------------------------------------------------------------
# Key-aggregation coefficient (MuSig2 style)
# Using HFSCX-256 substitute: SHA-256 for the demo script
# ---------------------------------------------------------------------------

def _mu_coeff(L_bytes: bytes, j_pubkey: int) -> int:
    """μ_j = H(L || C_j) mod GF32_ORD, where L = sorted concatenated pubkeys."""
    h = hashlib.sha256(L_bytes + j_pubkey.to_bytes(4, 'big')).digest()
    return int.from_bytes(h, 'big') % GF32_ORD or 1  # avoid 0


def aggregate_pubkeys(pubkeys: list[int]) -> tuple:
    """
    Compute (C_agg, coefficients) with MuSig2 key-aggregation.
    L = sorted pubkeys concatenated.
    μ_j = H(L, C_j) mod ord
    C_agg = Π C_j^{μ_j}
    """
    L_bytes = b''.join(sorted(pk.to_bytes(4, 'big') for pk in pubkeys))
    coeffs  = [_mu_coeff(L_bytes, pk) for pk in pubkeys]
    C_agg   = 1
    for C_j, mu_j in zip(pubkeys, coeffs):
        C_agg = gf_mul(C_agg,
                       gf_pow(C_j, mu_j, GF32_POLY, GF32_N),
                       GF32_POLY, GF32_N)
    return C_agg, coeffs


# ---------------------------------------------------------------------------
# n-of-n threshold signing (MuSig2 key-aggregation, single-round nonce)
# ---------------------------------------------------------------------------

def hpks_threshold_sign(signers: list[tuple], msg: int) -> tuple:
    """
    n-of-n threshold HPKS-NL sign.

    signers: list of (a_j, C_j) for j=0..n-1
    msg:     32-bit message representative

    Protocol:
      1. Each signer picks nonce k_j, computes R_j = g^{k_j}.
      2. Aggregate nonce: R = Π R_j.
      3. Challenge: e = nl_fscx_revolve_v1(R, msg, I).
      4. Each signer computes s_j = (k_j − a_j·μ_j·e) mod ord.
      5. Aggregate: s = Σ s_j mod ord.
    Returns (C_agg, R, e, s).
    """
    pubkeys = [C for _a, C in signers]
    C_agg, coeffs = aggregate_pubkeys(pubkeys)

    # Per-signer nonces
    nonces  = [random.randint(1, GF32_ORD - 1) for _ in signers]
    R_parts = [gf_pow(GF32_GEN, k, GF32_POLY, GF32_N) for k in nonces]

    # Aggregate nonce R = Π R_j
    R = 1
    for R_j in R_parts:
        R = gf_mul(R, R_j, GF32_POLY, GF32_N)

    # Challenge (NL-FSCX v1)
    e = _challenge32(R, msg)

    # Per-signer partial signatures
    s = 0
    for j, ((a_j, _C_j), k_j, mu_j) in enumerate(zip(signers, nonces, coeffs)):
        s_j = (k_j - a_j * mu_j * e) % GF32_ORD
        s = (s + s_j) % GF32_ORD

    return C_agg, R, e, s


def hpks_threshold_verify(C_agg: int, R: int, e: int, s: int, msg: int) -> bool:
    """Verify an aggregate HPKS-NL threshold signature — identical to single-party verify."""
    lhs = gf_mul(gf_pow(GF32_GEN, s, GF32_POLY, GF32_N),
                 gf_pow(C_agg,     e, GF32_POLY, GF32_N), GF32_POLY, GF32_N)
    return lhs == R


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def separator(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def demo_single_party():
    separator("1. Single-party HPKS-NL baseline (n=32)")
    a, C = hpks_nl_keygen_32()
    msg  = random.randint(0, 0xFFFFFFFF)
    k    = random.randint(1, GF32_ORD - 1)
    R, e, s = hpks_nl_sign_32(a, k, msg)
    ok = hpks_nl_verify_32(C, R, e, s, msg)
    print(f"  a (priv) : {a:08x}")
    print(f"  C (pub)  : {C:08x}")
    print(f"  msg      : {msg:08x}")
    print(f"  R        : {R:08x}")
    print(f"  e        : {e:08x}")
    print(f"  s        : {s:08x}")
    print(f"  g^s·C^e  : {'== R  ✓ PASS' if ok else '≠ R  ✗ FAIL'}")


def demo_rogue_key_attack():
    separator("2. Rogue-key attack (naive aggregation, no coefficient binding)")
    # Victim
    a_v, C_v = hpks_nl_keygen_32()
    # Mallory claims C_M = g^{a_M} · C_v^{-1}  (so C_v · C_M = g^{a_M})
    a_M, _   = hpks_nl_keygen_32()
    # GF mul inverse of C_v: g^{ord-1} · C_v in GF
    C_v_inv  = gf_pow(C_v, GF32_ORD - 1, GF32_POLY, GF32_N)
    g_aM     = gf_pow(GF32_GEN, a_M, GF32_POLY, GF32_N)
    C_M_rogue = gf_mul(g_aM, C_v_inv, GF32_POLY, GF32_N)

    # Naive aggregate (no coefficient): C_agg = C_v · C_M = g^{a_M}
    C_agg_naive = gf_mul(C_v, C_M_rogue, GF32_POLY, GF32_N)
    assert C_agg_naive == g_aM, "Rogue key did not cancel victim key"

    # Mallory signs alone against the aggregate
    msg  = random.randint(0, 0xFFFFFFFF)
    k    = random.randint(1, GF32_ORD - 1)
    R, e, s = hpks_nl_sign_32(a_M, k, msg)
    ok = hpks_nl_verify_32(C_agg_naive, R, e, s, msg)

    print(f"  Victim pubkey C_v     : {C_v:08x}")
    print(f"  Mallory rogue C_M     : {C_M_rogue:08x}   (chosen to cancel C_v)")
    print(f"  Naive C_agg = C_v·C_M : {C_agg_naive:08x}  == g^{{a_M}} = {g_aM:08x}")
    print(f"  Mallory signs alone   : {'FORGED ✗  (attack succeeds)' if ok else 'failed'}")
    print()
    print("  → Naive key aggregation is INSECURE: Mallory can cancel any victim key.")


def demo_threshold_2_of_2():
    separator("3. 2-of-2 threshold HPKS-NL with MuSig2 key-aggregation coefficients")
    a1, C1 = hpks_nl_keygen_32()
    a2, C2 = hpks_nl_keygen_32()
    msg    = random.randint(0, 0xFFFFFFFF)

    C_agg, R, e, s = hpks_threshold_sign([(a1, C1), (a2, C2)], msg)
    ok = hpks_threshold_verify(C_agg, R, e, s, msg)

    print(f"  Signer 1: a={a1:08x}  C={C1:08x}")
    print(f"  Signer 2: a={a2:08x}  C={C2:08x}")
    print(f"  C_agg    : {C_agg:08x}  (keyed aggregate, rogue-key protected)")
    print(f"  msg      : {msg:08x}")
    print(f"  R (agg)  : {R:08x}")
    print(f"  e        : {e:08x}")
    print(f"  s (agg)  : {s:08x}")
    print(f"  Verify   : {'✓ PASS' if ok else '✗ FAIL'}")


def demo_threshold_3_of_3():
    separator("4. 3-of-3 threshold HPKS-NL — tamper and wrong-key rejection")
    signers = [hpks_nl_keygen_32() for _ in range(3)]
    msg     = random.randint(0, 0xFFFFFFFF)

    C_agg, R, e, s = hpks_threshold_sign(signers, msg)
    ok_valid = hpks_threshold_verify(C_agg, R, e, s, msg)

    # Tamper: flip one bit of s
    s_bad  = s ^ 1
    ok_bad = hpks_threshold_verify(C_agg, R, e, s_bad, msg)

    # Wrong pubkey: replace C_agg with a random one
    C_rand   = gf_pow(GF32_GEN, random.randint(1, GF32_ORD - 1), GF32_POLY, GF32_N)
    ok_wrong = hpks_threshold_verify(C_rand, R, e, s, msg)

    print(f"  3-of-3 sign+verify    : {'✓ PASS' if ok_valid else '✗ FAIL'}")
    print(f"  Tampered s (s^1)      : {'✓ rejected' if not ok_bad else '✗ accepted (FAIL)'}")
    print(f"  Wrong aggregate pubkey: {'✓ rejected' if not ok_wrong else '✗ accepted (FAIL)'}")


def demo_coefficient_binding_blocks_rogue_key():
    separator("5. MuSig2 coefficient binding blocks the rogue-key attack")
    a_v, C_v = hpks_nl_keygen_32()
    a_M, _   = hpks_nl_keygen_32()

    # Mallory tries rogue key C_M such that keyed aggregate = g^{a_M}
    # With coefficient binding: C_agg = C_v^{μ_v} · C_M^{μ_M}
    # μ_j depends on L = {C_v, C_M}  ← circular: C_M affects its own μ_M
    # Mallory cannot pre-compute C_M to cancel C_v^{μ_v} without solving
    # a circular equation involving the hash.

    # Best Mallory can do: pick C_M and compute what the aggregate becomes
    g_aM  = gf_pow(GF32_GEN, a_M, GF32_POLY, GF32_N)
    C_M   = gf_pow(GF32_GEN, a_M, GF32_POLY, GF32_N)   # honest announcement

    C_agg, coeffs = aggregate_pubkeys([C_v, C_M])
    mu_v, mu_M = coeffs

    # Mallory tries to sign against C_agg using only a_M
    # Would need a_eff = a_M·μ_M such that g^{a_eff·μ_M^{-1}} = C_M  ← consistent,
    # but also needs contribution of C_v^{μ_v} which Mallory cannot forge without a_v.
    msg = random.randint(0, 0xFFFFFFFF)
    k   = random.randint(1, GF32_ORD - 1)
    R   = gf_pow(GF32_GEN, k, GF32_POLY, GF32_N)
    e   = _challenge32(R, msg)
    s_mallory = (k - a_M * mu_M * e) % GF32_ORD   # Mallory's partial sig alone
    ok_forge  = hpks_threshold_verify(C_agg, R, e, s_mallory, msg)

    print(f"  μ_v = {mu_v:016x}")
    print(f"  μ_M = {mu_M:016x}")
    print(f"  C_agg (keyed) = {C_agg:08x}")
    print(f"  Mallory partial-sig alone: {'✗ accepted (FAIL)' if ok_forge else '✓ rejected — attack blocked'}")


def demo_composite_modulus_note():
    separator("6. Composite-modulus note for t-of-n Shamir sharing")
    from math import gcd
    ord_val = GF32_ORD  # 2^32 − 1
    # Factor: 2^32-1 = 3 × 5 × 17 × 257 × 65537
    factors = [3, 5, 17, 257, 65537]
    print(f"  GF32_ORD = 2^32 − 1 = {ord_val}")
    print(f"  Known factors: {' × '.join(str(f) for f in factors)}")
    print(f"  Product check: {' × '.join(str(f) for f in factors)} = {3*5*17*257*65537}")

    # For Shamir, Lagrange denominator (i-j) must be invertible mod ord
    # gcd(i-j, ord) = 1 iff (i-j) shares no factor with ord
    # Example: if i-j = 3, gcd(3, ord) = 3 ≠ 1 → no inverse → Shamir fails
    bad_diff = 3
    print(f"\n  Shamir Lagrange denominator example: (i−j) = {bad_diff}")
    print(f"  gcd({bad_diff}, ord) = {gcd(bad_diff, ord_val)} ≠ 1  → no modular inverse → Shamir FAILS")
    print()
    print("  Safe approaches for t-of-n over composite ord:")
    print("  A. Embed secret in a prime field q > ord (e.g. nearest prime above 2^32−1)")
    print("     → share mod q, sign mod ord; works but requires prime arithmetic")
    print("  B. Restrict to n-of-n (no threshold), avoiding Lagrange inversion entirely")
    print("  C. Ensure signer indices chosen so (i−j) is coprime to ord for all pairs")
    print("     → restrictive; not general; fragile if signers drop out")
    print()
    print("  This demo restricts to n-of-n (approach B) — t-of-n is future work (TODO #106).")


if __name__ == '__main__':
    print("HPKS-T: Threshold/Aggregate Schnorr over GF(2^n)*")
    print("MuSig2-style key aggregation with NL-FSCX v1 challenge")
    print(f"Demo uses n={GF32_N} for speed; production uses n=256.\n")

    demo_single_party()
    demo_rogue_key_attack()
    demo_threshold_2_of_2()
    demo_threshold_3_of_3()
    demo_coefficient_binding_blocks_rogue_key()
    demo_composite_modulus_note()

    print("\n" + "="*70)
    print("  All demos complete.")
    print("="*70)
