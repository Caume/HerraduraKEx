#!/usr/bin/env python3
"""
hkex_gf_pohlig_hellman.py — TODO #212: what does Pohlig-Hellman actually cost
against HKEX-GF, HPKS and HPKE?

SecurityProofs-3.md §9.2.4 lists Pohlig-Hellman in its table of attacks on the DLP
in GF(2^n)*, then quotes the function field sieve as "the practical binding
constraint" and reports ~80-90 bits at n=256.  Pohlig-Hellman is never actually
costed.  It should have been: the group order of GF(2^n)* is 2^n - 1, which is
never prime and, at every supported n, factors into primes far smaller than the
field.  A generic DLP algorithm run per prime factor and recombined by CRT costs
the square root of the *largest prime factor*, not the square root of the group.

    n=256:  2^256 - 1  has largest prime factor 5704689200685129054721 (73 bits)
            => Pollard rho + CRT costs about 2^36.5 group operations

That is roughly 45 bits below the documented figure, and it is not asymptotic:
this script recovers exact private keys end to end.

  §1  Factorisation of 2^n - 1 at every supported n, and the order of g = 3
  §2  Pohlig-Hellman cost per n, against the documented FFS figures
  §3  End-to-end private-key recovery at n=32 and n=64
  §4  What the recovered key buys: HKEX-GF shared secret, HPKS forgery
  §5  Extrapolation to the deployed n=256

RESULTS

§1  g = 3 is primitive at n=64 and n=256 under the suite's GF_POLY — including at
    the deployed n=256 — and generates a proper subgroup at n=32 (index 15) and
    n=128 (index 3).  Either way the largest prime factor of ord(g) is unchanged,
    so the subgroup structure buys the defender nothing: 17 bits at n=32, 23 bits
    at n=64, 46 bits at n=128, 73 bits at n=256.

§2  Pohlig-Hellman with Pollard rho costs about 2^8.5 / 2^11.8 / 2^23.3 / 2^36.5
    group operations at n = 32 / 64 / 128 / 256 respectively — against documented
    FFS estimates of "much less than 40" (n=32, 64), 50-60 (n=128) and 80-90
    (n=256) bits.  The gap at the deployed n=256 is 45 to 55 bits.

§3  At n=64 the attack returns the signer's actual private exponent — not merely a
    representative — in well under a second of pure Python.  §9.2.4's n=32 narrative
    ("the recovered a_rec != A_PRIV because g = 3 is not a primitive element") is
    correct at n=32, where ord(g) = (2^32 - 1)/15, but it does not generalise: at
    the deployed n=256 g is primitive, so the recovered exponent is the private key
    itself.

§4  From the recovered exponent, Eve reconstructs the HKEX-GF shared secret and
    signs arbitrary messages under the victim's HPKS public key.  Both are shown.

§5  At n=256, 2^36.5 group operations at the 1.3e5 gf_mul/s measured for
    `herradura.h`'s gf_mul_ba on the reference ARM64 host is about nine days on one
    core.  Pollard rho needs constant memory and parallelises linearly, and a
    carryless-multiply implementation on a desktop core is one to two orders of
    magnitude faster.  This is an attack with a wall-clock cost, not a margin.

Self-contained (no imports from the suite), per SecurityProofsCode convention; the
primitives below are transcribed from `Herradura cryptographic suite.py`.
"""

import math
import random
import time

SEP  = "=" * 74
SEP2 = "-" * 74

# Transcribed from the suite: primitive polynomials (low n bits) and generator.
GF_POLY = {32: 0x00400007, 64: 0x0000001B, 128: 0x00000087, 256: 0x00000425}
GF_GEN  = 3

# Known complete factorisations of 2^n - 1 (products of the primitive parts of
# 2^d - 1 for d | n).  Verified below, both for primality and for the product.
FACTORS = {
    32:  [3, 5, 17, 257, 65537],
    64:  [3, 5, 17, 257, 641, 65537, 6700417],
    128: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721],
    256: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
          59649589127497217, 5704689200685129054721],
}

# Documented FFS estimates from SecurityProofs-3.md §9.2.4, for comparison.
DOC_FFS = {32: "<< 40", 64: "<< 40", 128: "50-60", 256: "80-90", 512: "110-120",
           1024: "128-140"}

# Beyond the supported sizes, only the largest prime factor matters, and it comes
# from the Fermat numbers dividing 2^n - 1.  Verified in section2().
#   2^512  - 1 = (2^256 - 1)(2^256 + 1),  F8 = 2^256 + 1 = 1238926361552897 * P62
#   2^1024 - 1 = (2^512 - 1)(2^512 + 1),  F9 = 2^512 + 1 = 2424833 * P49 * P99
F8_SMALL = 1238926361552897
F9_SMALL = 2424833
F9_MID   = 7455602825647884208337395736200454918783366342657


# ─────────────────────────────────────────────────────────────────────────────
# GF(2^n) arithmetic (transcribed from the suite)
# ─────────────────────────────────────────────────────────────────────────────

def gf_mul(a, b, poly, n):
    result = 0
    mask = (1 << n) - 1
    hb = 1 << (n - 1)
    while b:
        if b & 1:
            result ^= a
        carry = a & hb
        a = (a << 1) & mask
        if carry:
            a ^= poly
        b >>= 1
    return result


def gf_pow(base, exp, poly, n):
    result = 1
    base &= (1 << n) - 1
    while exp:
        if exp & 1:
            result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


def fscx_revolve(a, b, steps, n):
    """Needed only for the HPKS challenge in §4."""
    mask = (1 << n) - 1
    for _ in range(steps):
        x = (a ^ b) & mask
        a = x ^ ((x << 1) | (x >> (n - 1))) ^ ((x >> 1) | (x << (n - 1)))
        a &= mask
    return a


# ─────────────────────────────────────────────────────────────────────────────
# Number-theoretic helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_prime(m, rounds=40):
    """Deterministic-enough Miller-Rabin for the sizes here."""
    if m < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if m % p == 0:
            return m == p
    d, s = m - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(212)
    for _ in range(rounds):
        a = rng.randrange(2, m - 1)
        x = pow(a, d, m)
        if x in (1, m - 1):
            continue
        for _ in range(s - 1):
            x = x * x % m
            if x == m - 1:
                break
        else:
            return False
    return True


def element_order(g, n, factors):
    """Order of g in GF(2^n)*, by stripping prime factors of 2^n - 1."""
    poly = GF_POLY[n]
    order = (1 << n) - 1
    for p in factors:
        while order % p == 0 and gf_pow(g, order // p, poly, n) == 1:
            order //= p
    return order


def bsgs(g, h, order, poly, n):
    """Baby-step giant-step for h = g^x in a subgroup of the given prime order."""
    m = math.isqrt(order) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = gf_mul(cur, g, poly, n)
    # (g^m)^{-1} = (g^m)^{order-1} in a group of the given order
    step = gf_pow(gf_pow(g, m, poly, n), order - 1, poly, n)
    y = h
    for i in range(m + 1):
        if y in table:
            return i * m + table[y]
        y = gf_mul(y, step, poly, n)
    raise ValueError("BSGS failed — h is not in the subgroup generated by g")


def pohlig_hellman(h, n, factors, g=GF_GEN, verbose=False):
    """Recover x with g^x = h, by solving one DLP per prime factor and CRT-ing."""
    poly = GF_POLY[n]
    order = element_order(g, n, factors)
    residues = []
    for p in factors:
        if order % p:
            continue
        cof = order // p
        gi = gf_pow(g, cof, poly, n)
        hi = gf_pow(h, cof, poly, n)
        t0 = time.time()
        xi = bsgs(gi, hi, p, poly, n)
        if verbose:
            print(f"      subgroup of order {p:<24} ({p.bit_length():>2} bits): "
                  f"x = {xi:<24} [{time.time() - t0:.3f}s]")
        residues.append((xi, p))
    x, mod = 0, 1
    for r, p in residues:
        while (x - r) % p:
            x += mod
        mod *= p
    return x % mod, order


def rho_cost_bits(factors):
    """log2 of the Pollard-rho + CRT cost: about 1.25 * sum of sqrt(p)."""
    total = sum(1.25 * math.sqrt(p) for p in factors)
    return math.log2(total)


# ─────────────────────────────────────────────────────────────────────────────
# §1  Group order and the order of the generator
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP2)
    print("§1  Factorisation of 2^n - 1, and the order of g = 3")
    print(SEP2)
    print()
    for n, fac in sorted(FACTORS.items()):
        assert math.prod(fac) == (1 << n) - 1, f"factor list wrong at n={n}"
        assert all(is_prime(p) for p in fac), f"non-prime in factor list at n={n}"
        order = element_order(GF_GEN, n, fac)
        primitive = order == (1 << n) - 1
        print(f"  n = {n}")
        print(f"    2^n - 1 factors as: " + " * ".join(str(p) for p in fac))
        print(f"    all factors verified prime, product verified = 2^{n} - 1")
        print(f"    ord(g=3) = {order.bit_length()} bits"
              f"   primitive: {primitive}")
        print(f"    largest prime factor: {max(fac)}  ({max(fac).bit_length()} bits)")
        print()
    print("  g is primitive at n=64 and at the deployed n=256; at n=32 and n=128 it")
    print("  generates a proper subgroup (index 15 and 3).  In every case the largest")
    print("  prime factor of ord(g) is the same as that of 2^n - 1, so the subgroup")
    print("  structure gives the defender no relief.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §2  Cost table
# ─────────────────────────────────────────────────────────────────────────────

def section2():
    print(SEP2)
    print("§2  Pohlig-Hellman cost vs. the documented FFS figures")
    print(SEP2)
    print()
    print("  Pohlig-Hellman solves one DLP per prime factor of the group order and")
    print("  recombines by CRT, so its cost is set by the LARGEST prime factor, not")
    print("  by the field size.  With Pollard rho the memory cost is constant.")
    print()
    print("  n     largest prime factor   PH + rho cost   §9.2.4 FFS estimate (bits)")
    for n, fac in sorted(FACTORS.items()):
        bits = rho_cost_bits(fac)
        print(f"  {n:<5} {max(fac).bit_length():>2} bits"
              f"               2^{bits:<12.1f}  {DOC_FFS[n]}")
    print()
    # Larger n, for the question "does growing the field fix it?"
    f8_big = (2 ** 256 + 1) // F8_SMALL
    f9_big = (2 ** 512 + 1) // (F9_SMALL * F9_MID)
    assert (2 ** 256 + 1) % F8_SMALL == 0 and (2 ** 512 + 1) % (F9_SMALL * F9_MID) == 0
    assert all(is_prime(x) for x in (F8_SMALL, F9_SMALL, F9_MID, f8_big, f9_big))
    for n, big in ((512, f8_big), (1024, f9_big)):
        bits = math.log2(1.25 * math.sqrt(big))
        print(f"  {n:<5} {big.bit_length():>2} bits"
              f"              2^{bits:<12.1f}  {DOC_FFS[n]}")
    print()
    print("  Rows 512 and 1024 use the largest prime factor of the Fermat number")
    print("  dividing 2^n - 1 (F8 and F9 respectively), verified above for primality")
    print("  and divisibility.  Pohlig-Hellman is the binding constraint up to and")
    print("  including n=512; only at n=1024 does the FFS take over.  At the deployed")
    print("  n=256 Pohlig-Hellman undercuts the documented FFS figure by 45 to 55")
    print("  bits, and it governs HKEX-GF, HPKS and HPKE alike.  2^36.5 is not a")
    print("  security margin — see §5 for the wall-clock estimate.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  End-to-end key recovery
# ─────────────────────────────────────────────────────────────────────────────

def section3():
    print(SEP2)
    print("§3  Exact private-key recovery at n=32 and n=64")
    print(SEP2)
    print()
    rng = random.Random(20260820)
    for n in (32, 64):
        poly = GF_POLY[n]
        a = rng.getrandbits(n - 4) | 1           # a private key, as genpkey would draw
        C = gf_pow(GF_GEN, a, poly, n)           # the public key on the wire
        print(f"  n = {n}:  private a = {a}")
        t0 = time.time()
        rec, order = pohlig_hellman(C, n, FACTORS[n], verbose=True)
        dt = time.time() - t0
        print(f"    recovered x = {rec}")
        print(f"    g^x == C: {gf_pow(GF_GEN, rec, poly, n) == C}"
              f"    x == a exactly: {rec == a % order}"
              f"    [{dt:.3f}s total]")
        print()
    print("  Recovery is exact modulo ord(g), which is all an attacker needs — and")
    print("  at n=64 and at the deployed n=256, where g is primitive, that is the")
    print("  private key itself.  §9.2.4's n=32 BSGS narrative attributes a")
    print("  non-matching exponent to g = 3 being non-primitive: true at n=32, where")
    print("  ord(g) = (2^32 - 1)/15, but not a property to rely on at n=256.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §4  What the recovered exponent buys
# ─────────────────────────────────────────────────────────────────────────────

def section4():
    print(SEP2)
    print("§4  Consequences: HKEX-GF shared secret, HPKS forgery")
    print(SEP2)
    print()
    n = 64
    poly = GF_POLY[n]
    order = (1 << n) - 1
    rng = random.Random(4212)

    # --- HKEX-GF -------------------------------------------------------------
    a = rng.getrandbits(n - 4) | 1
    b = rng.getrandbits(n - 4) | 1
    C, C2 = gf_pow(GF_GEN, a, poly, n), gf_pow(GF_GEN, b, poly, n)
    sk_real = gf_pow(C2, a, poly, n)
    a_rec, _ = pohlig_hellman(C, n, FACTORS[n])
    sk_eve = gf_pow(C2, a_rec, poly, n)
    print(f"  HKEX-GF   Alice C = g^a, Bob C2 = g^b, shared sk = C2^a")
    print(f"            Eve sees only C and C2, recovers a, computes C2^a:")
    print(f"            sk matches: {sk_eve == sk_real}")
    print()

    # --- HPKS ----------------------------------------------------------------
    # Sign:   R = g^k, e = fscx_revolve(R, msg, n/4), s = (k - a*e) mod (2^n - 1)
    # Verify: g^s * C^e == R
    def hpks_sign(msg, priv, k):
        R = gf_pow(GF_GEN, k, poly, n)
        e = fscx_revolve(R, msg, n // 4, n)
        s = (k - priv * e) % order
        return R, s

    def hpks_verify(msg, pub, R, s):
        e = fscx_revolve(R, msg, n // 4, n)
        return gf_mul(gf_pow(GF_GEN, s, poly, n),
                      gf_pow(pub, e, poly, n), poly, n) == R

    priv = rng.getrandbits(n - 4) | 1
    pub = gf_pow(GF_GEN, priv, poly, n)
    honest_msg = rng.getrandbits(n)
    R, s = hpks_sign(honest_msg, priv, rng.getrandbits(n - 4) | 1)
    print(f"  HPKS      honest signature verifies: {hpks_verify(honest_msg, pub, R, s)}")

    priv_rec, _ = pohlig_hellman(pub, n, FACTORS[n])
    forged_msg = rng.getrandbits(n)
    Rf, sf = hpks_sign(forged_msg, priv_rec, rng.getrandbits(n - 4) | 1)
    print(f"            Eve recovers the signing key from the public key alone,")
    print(f"            then signs a message she chose:")
    print(f"            forged signature verifies: {hpks_verify(forged_msg, pub, Rf, sf)}")
    print(f"            recovered key == signing key: {priv_rec == priv}")
    print()
    print("  HPKE follows HKEX-GF exactly — the recovered exponent is the El Gamal")
    print("  decryption key.  Note that HPKS reduces its scalar modulo 2^n - 1, the")
    print("  same smooth-ish modulus whose factorisation makes the recovery cheap.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §5  Extrapolation to n=256
# ─────────────────────────────────────────────────────────────────────────────

def section5():
    print(SEP2)
    print("§5  What 2^36.5 group operations costs at n=256")
    print(SEP2)
    print()
    bits = rho_cost_bits(FACTORS[256])
    ops = 2 ** bits
    # Measured for herradura.h's gf_mul_ba, -O2, reference ARM64 host.
    rate_c = 1.26e5
    print(f"  Pollard rho + CRT cost:        2^{bits:.1f} = {ops:.3g} group operations")
    print(f"  Measured gf_mul_ba throughput: {rate_c:.2e} ops/s (herradura.h, -O2,")
    print(f"                                 reference ARM64 host)")
    secs = ops / rate_c
    print(f"  Single-core wall clock:        {secs:.3g} s = {secs / 86400:.1f} days")
    print()
    print("  Pollard rho uses constant memory and parallelises linearly, so this is")
    print("  days on one modest core, hours on a handful, and less again with a")
    print("  carryless-multiply (PCLMULQDQ) field implementation.  For comparison,")
    print("  the documented FFS figure of 2^80-2^90 would be out of reach entirely.")
    print()
    print("  Python cross-check of the same rate, for calibration:")
    t0 = time.time()
    x = GF_GEN
    for _ in range(20000):
        x = gf_mul(x, GF_GEN, GF_POLY[256], 256)
    dt = time.time() - t0
    print(f"    this script's pure-Python gf_mul: {20000 / dt:.2e} ops/s")
    print()


def main():
    print()
    print(SEP)
    print("TODO #212 — Pohlig-Hellman against HKEX-GF / HPKS / HPKE")
    print(SEP)
    print()
    section1()
    section2()
    section3()
    section4()
    section5()
    print(SEP)
    print("Summary: the DLP behind HKEX-GF, HPKS and HPKE costs about 2^36.5 group")
    print("         operations at n=256 via Pohlig-Hellman — roughly 45 bits below")
    print("         the FFS figure documented in SecurityProofs-3.md §9.2.4.")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
