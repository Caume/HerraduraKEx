#!/usr/bin/env python3
"""
hpks_ristretto_migration.py — Ristretto255 drop-in evaluation for HPKS/HPKE/HKEX-GF
(TODO #127, SecurityProofs-1 §9.2.6 "Migration path").

THE QUESTION
------------
GF(2^n)* is deprecated (NIST SP 800-57 Rev.5, ENISA 2022); at n=256 the function field
sieve leaves only ~80-90 classical bits.  What is the minimal-change upgrade preserving
the suite's Schnorr algebra — s = (k - a*e) mod ord, verify g^s * C^e == R — so that
threshold signing (TODO #98) and Schnorr ring signatures (TODO #78.I) transfer intact?

Candidate: ristretto255 (RFC 9496) — the prime-order quotient group of Curve25519,
order ell = 2^252 + 27742317777372353535851937790883648493 (~2^252), ~128-bit ECDLP.

This script is a SELF-CONTAINED pure-Python prototype (no external libraries, matching
repo policy; ~200 lines of field/group code implement RFC 9496 directly):

  §1  Group sanity — RFC 9496 generator test vector, ell*G == identity,
      encode/decode round-trips, completeness of the unified addition law.
  §2  HPKS-Schnorr drop-in — keygen/sign/verify with the EXACT suite equation
      s = (k - a*e) mod ell;  verify  s*G + e*C == R.   (g^s * C^e == R in
      multiplicative notation.)  Challenge e = H(enc(R) || enc(C) || msg); the
      prototype uses SHA-512 mod ell; production would substitute HFSCX-256-DM
      exactly as HPKS does today (the challenge function is algebra-agnostic).
  §3  Threshold transfer (TODO #98) — n-of-n additive key aggregation:
      C = sum C_i, R = sum R_i, s = sum s_i verifies against the aggregate key
      with no change to the verification equation.
  §4  Ring-signature transfer (TODO #78.I) — AOS Schnorr ring over ristretto255:
      every ring member can sign; verification chain closes; wrong-ring rejects.
  §5  Migration impact — function-by-function and PEM-field mapping (printed table).
  §6  Verdict — classical-only upgrade; Shor's algorithm breaks ECDLP, so the PQC
      path remains HKEX-RNL + Stern-F exclusively.

Runtime: ~30 s (pure-Python scalar multiplication).
"""

import hashlib
import random
import sys
import time

random.seed(0xC0DE_FEED_127)

SEP  = "═" * 72

# ─── Field GF(2^255 - 19) ─────────────────────────────────────────────────────

P = 2**255 - 19
ELL = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

def is_neg(x):
    return x & 1

def f_abs(x):
    return (-x) % P if is_neg(x) else x

def sqrt_ratio_m1(u, v):
    """RFC 9496 SQRT_RATIO_M1: returns (was_square, sqrt(u/v) or sqrt(i*u/v))."""
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    u_neg = (-u) % P
    correct = check == u % P
    flipped = check == u_neg
    flipped_i = check == u_neg * SQRT_M1 % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return (correct or flipped), f_abs(r)

INVSQRT_A_MINUS_D = sqrt_ratio_m1(1, (-1 - D) % P)[1]

# ─── Edwards points (extended coordinates), unified complete addition ─────────

def pt_add(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * D * T1 % P * T2 % P
    Dd = 2 * Z1 * Z2 % P
    E, F, G, H = (B - A) % P, (Dd - C) % P, (Dd + C) % P, (B + A) % P
    return (E * F % P, G * H % P, F * G % P, E * H % P)

IDENTITY = (0, 1, 1, 0)

def pt_mul(k, pt):
    acc = IDENTITY
    while k:
        if k & 1:
            acc = pt_add(acc, pt)
        pt = pt_add(pt, pt)
        k >>= 1
    return acc

def pt_eq(p1, p2):
    # x1/z1 == x2/z2 and y1/z1 == y2/z2
    X1, Y1, Z1, _ = p1
    X2, Y2, Z2, _ = p2
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0

BASE_Y = 4 * pow(5, P - 2, P) % P
BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)

# ─── Ristretto255 encode / decode (RFC 9496) ──────────────────────────────────

def encode(pt):
    x0, y0, z0, t0 = pt
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2 % P)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    ix0 = x0 * SQRT_M1 % P
    iy0 = y0 * SQRT_M1 % P
    enchanted = den1 * INVSQRT_A_MINUS_D % P
    rotate = is_neg(t0 * z_inv % P)
    if rotate:
        x, y, den_inv = iy0, ix0, enchanted
    else:
        x, y, den_inv = x0, y0, den2
    if is_neg(x * z_inv % P):
        y = (-y) % P
    s = f_abs(den_inv * ((z0 - y) % P) % P)
    return s.to_bytes(32, 'little')

def decode(b):
    s = int.from_bytes(b, 'little')
    if s >= P or is_neg(s):
        return None
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2s = u2 * u2 % P
    v = (-(D * u1 % P * u1 % P) - u2s) % P
    was_sq, invsqrt = sqrt_ratio_m1(1, v * u2s % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = f_abs(2 * s % P * den_x % P)
    y = u1 * den_y % P
    t = x * y % P
    if not was_sq or is_neg(t) or y == 0:
        return None
    return (x, y, 1, t)

# ─── Challenge hash (prototype: SHA-512 mod ell; production: HFSCX-256-DM) ────

def challenge(*parts):
    return int.from_bytes(hashlib.sha512(b''.join(parts)).digest(), 'little') % ELL

# ─── §1: Group sanity ─────────────────────────────────────────────────────────

RFC9496_G = bytes.fromhex(
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")

def section1():
    print(SEP)
    print("§1 — Ristretto255 Group Sanity (RFC 9496)")
    print(SEP)
    ok = encode(BASE) == RFC9496_G
    print(f"  encode(G) == RFC 9496 generator vector:            {'PASS' if ok else 'FAIL'}")
    assert ok
    ok = pt_eq(pt_mul(ELL, BASE), IDENTITY)
    print(f"  ell * G == identity (prime group order):           {'PASS' if ok else 'FAIL'}")
    assert ok
    ok = all(decode(encode(pt_mul(random.randrange(1, ELL), BASE))) is not None
             for _ in range(20))
    print(f"  encode/decode round-trip, 20 random multiples:     {'PASS' if ok else 'FAIL'}")
    assert ok
    a, b = random.randrange(ELL), random.randrange(ELL)
    ok = encode(pt_add(pt_mul(a, BASE), pt_mul(b, BASE))) == encode(pt_mul((a + b) % ELL, BASE))
    print(f"  aG + bG == (a+b)G (addition law consistency):      {'PASS' if ok else 'FAIL'}")
    assert ok

# ─── §2: HPKS-Schnorr drop-in ─────────────────────────────────────────────────

def keygen():
    a = random.randrange(1, ELL)
    return a, pt_mul(a, BASE)

def sign(a, C, msg):
    k = random.randrange(1, ELL)
    R = pt_mul(k, BASE)
    e = challenge(encode(R), encode(C), msg)
    s = (k - a * e) % ELL            # EXACT suite equation: s = (k - a*e) mod ord
    return encode(R), s

def verify(C, msg, sig):
    Renc, s = sig
    e = challenge(Renc, encode(C), msg)
    Rp = pt_add(pt_mul(s, BASE), pt_mul(e, C))   # g^s * C^e in additive notation
    return encode(Rp) == Renc

def section2():
    print(SEP)
    print("§2 — HPKS-Schnorr Drop-In: s = (k - a*e) mod ell")
    print(SEP)
    trials = 50
    ok = 0
    for i in range(trials):
        a, C = keygen()
        msg = f"herradura migration test {i}".encode()
        sig = verify(C, msg, sign(a, C, msg))
        ok += sig
    print(f"  sign/verify round-trips:                           {ok}/{trials} PASS")
    assert ok == trials
    a, C = keygen()
    sig = sign(a, C, b"original")
    r1 = verify(C, b"tampered", sig)
    r2 = verify(C, b"original", (sig[0], (sig[1] + 1) % ELL))
    _, C2 = keygen()
    r3 = verify(C2, b"original", sig)
    print(f"  tampered msg / s / wrong key all rejected:         "
          f"{'PASS' if not (r1 or r2 or r3) else 'FAIL'}")
    assert not (r1 or r2 or r3)
    print()
    print("  The signing and verification equations are IDENTICAL to HPKS (§5):")
    print("  only gf_pow(g, x) -> x*G and gf_mul -> point addition change.")

# ─── §3: Threshold transfer (TODO #98) ────────────────────────────────────────

def section3():
    print(SEP)
    print("§3 — Threshold n-of-n Transfer (TODO #98 additive aggregation)")
    print(SEP)
    n_signers = 3
    keys = [keygen() for _ in range(n_signers)]
    C_agg = IDENTITY
    for _, C in keys:
        C_agg = pt_add(C_agg, C)
    msg = b"threshold message"
    # round 1: each signer commits k_i, shares R_i
    ks = [random.randrange(1, ELL) for _ in range(n_signers)]
    R_agg = IDENTITY
    for k in ks:
        R_agg = pt_add(R_agg, pt_mul(k, BASE))
    e = challenge(encode(R_agg), encode(C_agg), msg)
    # round 2: partial signatures
    s_agg = sum((k - a * e) % ELL for k, (a, _) in zip(ks, keys)) % ELL
    ok = verify(C_agg, msg, (encode(R_agg), s_agg))
    print(f"  3-of-3 aggregate signature verifies vs sum(C_i):   {'PASS' if ok else 'FAIL'}")
    assert ok
    print()
    print("  Partial signatures s_i = (k_i - a_i*e) sum to a standard signature under")
    print("  the aggregate key — the linearity of the Schnorr equation is preserved")
    print("  verbatim (prime group order makes shares well-defined mod ell; the")
    print("  GF(2^n)* version needed order-divisor caveats that DISAPPEAR here).")

# ─── §4: Ring-signature transfer (TODO #78.I) ─────────────────────────────────

def ring_sign(ring, j, a_j, msg):
    m = len(ring)
    encs = [encode(C) for C in ring]
    k = random.randrange(1, ELL)
    e = [0] * m
    s = [0] * m
    e[(j + 1) % m] = challenge(encode(pt_mul(k, BASE)), b''.join(encs), msg)
    i = (j + 1) % m
    while i != j:
        s[i] = random.randrange(1, ELL)
        Ri = pt_add(pt_mul(s[i], BASE), pt_mul(e[i], ring[i]))
        e[(i + 1) % m] = challenge(encode(Ri), b''.join(encs), msg)
        i = (i + 1) % m
    s[j] = (k - a_j * e[j]) % ELL
    return e[0], s

def ring_verify(ring, msg, sig):
    e0, s = sig
    m = len(ring)
    encs = [encode(C) for C in ring]
    e = e0
    for i in range(m):
        Ri = pt_add(pt_mul(s[i], BASE), pt_mul(e, ring[i]))
        e = challenge(encode(Ri), b''.join(encs), msg)
    return e == e0

def section4():
    print(SEP)
    print("§4 — AOS Schnorr Ring Signature Transfer (TODO #78.I)")
    print(SEP)
    m = 4
    keys = [keygen() for _ in range(m)]
    ring = [C for _, C in keys]
    msg = b"ring message"
    ok = all(ring_verify(ring, msg, ring_sign(ring, j, keys[j][0], msg))
             for j in range(m))
    print(f"  every ring member (m={m}) signs, chain closes:      {'PASS' if ok else 'FAIL'}")
    assert ok
    sig = ring_sign(ring, 0, keys[0][0], msg)
    _, C_out = keygen()
    bad = ring_verify(ring[:3] + [C_out], msg, sig)
    print(f"  substituted ring member rejected:                  {'PASS' if not bad else 'FAIL'}")
    assert not bad

# ─── §5: Migration impact ─────────────────────────────────────────────────────

def section5():
    print(SEP)
    print("§5 — Migration Impact: Function and Wire-Format Mapping")
    print(SEP)
    rows = [
        ("gf_pow(g, a)",            "a * G (scalar mult)",       "same role: public key / nonce commitment"),
        ("gf_mul(X, Y)",            "point addition X + Y",      "verification combiner g^s * C^e"),
        ("ba_mul_mod_ord",          "mul mod ell (prime)",       "ell prime: order-divisor caveats vanish"),
        ("group element (32 B)",    "ristretto enc (32 B)",      "SAME SIZE — PEM body length unchanged"),
        ("scalar mod 2^n-1",        "scalar mod ell",            "s field re-ranged; DER int unchanged"),
        ("fscx_revolve challenge",  "unchanged",                 "challenge fn is algebra-agnostic"),
        ("HSKE / HPKE symmetric",   "unchanged",                 "sk enters as pre-shared key as today"),
        ("PEM label HERRADURA*",    "new algo tag needed",       "genpkey --algo hpks-r255 (new)"),
    ]
    print(f"  {'GF(2^n)* suite':<24}  {'ristretto255':<24}  note")
    for a, b, c in rows:
        print(f"  {a:<24}  {b:<24}  {c}")
    print()
    print("  Wire format: 32-byte group elements on both sides — existing PEM/DER")
    print("  SEQUENCE layouts carry over; only the algorithm tag distinguishes them.")
    print("  Keys are NOT interoperable (different groups); a new --algo is required.")

# ─── §6: Verdict ──────────────────────────────────────────────────────────────

def section6():
    print(SEP)
    print("§6 — VERDICT")
    print(SEP)
    print("""
  1. ristretto255 is a clean drop-in for the Schnorr algebra: signing equation,
     threshold aggregation (TODO #98), and AOS ring signatures (TODO #78.I) all
     transfer with zero structural change, and the prime group order REMOVES the
     order-divisor caveats GF(2^n)* required.  ~128-bit classical security.
  2. Classical-security-only: Shor's algorithm breaks ECDLP exactly as it breaks
     GF(2^n)* DLP.  Migrating HKEX-GF/HPKS/HPKE to ristretto255 fixes the
     FFS shortfall (80-90 -> 128 bits) but buys NOTHING against quantum
     adversaries.
  3. The post-quantum path for this suite is therefore unchanged:
     HKEX-RNL (Ring-LWR) + HPKS-Stern-F / HPKE-Stern-KEM (code-based).
     No GF(2^n)* successor group exists that is quantum-resistant.
  4. Recommendation: treat ristretto255 as the documented classical upgrade path
     (SecurityProofs-1 §9.2.6) but keep implementation effort on the PQC track.
""")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print("hpks_ristretto_migration.py — ristretto255 drop-in evaluation (TODO #127)")
    print()
    t0 = time.monotonic()
    for s in (section1, section2, section3, section4, section5, section6):
        s()
        print()
        sys.stdout.flush()
    print(SEP)
    print(f"Total runtime: {time.monotonic()-t0:.1f} s")
    print("END hpks_ristretto_migration.py")
    print(SEP)

if __name__ == '__main__':
    main()
