"""
hkex_gf_test.py — Standalone HKEX-GF implementation and test suite

HKEX-GF replaces the broken HKEX key exchange with Diffie-Hellman over
GF(2^n)*.  All symmetric protocols (HSKE, HPKS, HPKE) keep standard FSCX
unchanged.

Protocol:
  Pre-agreed: irreducible polynomial p(x), generator g ∈ GF(2^n)*.
  Alice:  private a → public C  = g^a
  Bob:    private b → public C₂ = g^b
  Shared: sk = g^{ab} = C₂^a = C^b     [commutativity of GF(2^n)×]

Arithmetic: carryless polynomial multiplication mod p(x).  Operations: XOR
and left-shift only — no integer multiplication or modular reduction.

Security: CDH in GF(2^n)*.  Hardness = DLP in GF(2^n)* under index-calculus
attacks.  Practical parameters: n ≥ 256 for ≥ 128-bit classical security.
"""

import secrets
import time
import sys
from math import isqrt, gcd

# ─────────────────────────────────────────────────────────────────────────────
# Standard FSCX (unchanged for HSKE/HPKS/HPKE)
# ─────────────────────────────────────────────────────────────────────────────

def rol(x, k, n):
    k %= n
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1)

def ror(x, k, n):
    return rol(x, n - k, n)

def M_op(x, n):
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)

def fscx_revolve(A, B, steps, n):
    for _ in range(steps):
        A = M_op(A ^ B, n)
    return A

def S_op(delta, r, n):
    """Eve's formula: S_{r+1}·delta  (the classical break operator)."""
    acc, cur = 0, delta
    for _ in range(r + 1):
        acc ^= cur
        cur = M_op(cur, n)
    return acc

# ─────────────────────────────────────────────────────────────────────────────
# GF(2^n) arithmetic — XOR + left-shift only
# ─────────────────────────────────────────────────────────────────────────────
#
# Primitive polynomials (lower n bits; degree-n coefficient is implicit):
#   n=32:  x^32 + x^22 + x^2 + x + 1   →  0x00400007
#   n=64:  x^64 + x^4  + x^3 + x + 1   →  0x000000000000001B
#   n=128: x^128 + x^7 + x^2 + x + 1   →  0x00000000000000000000000000000087
#
GF_POLY = {
    32:  0x00400007,
    64:  0x000000000000001B,
    128: 0x00000000000000000000000000000087,
}
# g = 3 (polynomial x+1). DH correctness holds for any non-zero g since
# GF(2^n) multiplication is commutative and associative.
G = 3

def gf_mul(a, b, poly, n):
    """
    Multiply a, b in GF(2^n) = GF(2)[x] / p(x).
    Shift-and-XOR loop, O(n) iterations.  Only XOR and left-shift used.
    """
    result   = 0
    mask     = (1 << n) - 1
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

def gf_pow(base, exp, poly, n):
    """base^exp in GF(2^n)* via repeated squaring.  O(log exp) muls."""
    result = 1
    base &= (1 << n) - 1
    while exp:
        if exp & 1:
            result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result

def gf_order_upper(n):
    """Order of GF(2^n)* = 2^n − 1."""
    return (1 << n) - 1

# ─────────────────────────────────────────────────────────────────────────────
# HKEX-GF protocol
# ─────────────────────────────────────────────────────────────────────────────

def hkex_gf(n):
    """
    One HKEX-GF session in GF(2^n)*.
    Returns (C, C2, sk_alice, sk_bob, a, b).
    """
    poly = GF_POLY[n]
    mask = (1 << n) - 1
    a = (secrets.randbits(n) & mask) | 1    # odd, in [1, 2^n−1]
    b = (secrets.randbits(n) & mask) | 1
    C        = gf_pow(G, a, poly, n)        # g^a
    C2       = gf_pow(G, b, poly, n)        # g^b
    sk_alice = gf_pow(C2, a, poly, n)       # (g^b)^a = g^{ab}
    sk_bob   = gf_pow(C,  b, poly, n)       # (g^a)^b = g^{ab}
    return C, C2, sk_alice, sk_bob, a, b

# ─────────────────────────────────────────────────────────────────────────────
# Baby-step giant-step DLP solver (for small n only — illustrates hardness)
# ─────────────────────────────────────────────────────────────────────────────

def bsgs_dlp(target, g, poly, n, order):
    """
    Solve g^x = target in GF(2^n)* for x in [0, order-1].
    Cost: O(sqrt(order)) time and space.
    Only feasible for small order (e.g., n ≤ 16 in practice).
    """
    m = isqrt(order) + 1
    # Baby steps: table[g^j] = j for j in 0..m-1
    table = {}
    gj = 1
    for j in range(m):
        table[gj] = j
        gj = gf_mul(gj, g, poly, n)
    # Giant steps: find i such that target * (g^m)^{-i} = g^j
    # g^{-m} = (g^m)^{-1} in GF(2^n)* (Fermat: a^{-1} = a^{order-1})
    gm     = gf_pow(g, m, poly, n)
    gm_inv = gf_pow(gm, order - 1, poly, n)
    curr   = target
    for i in range(m + 1):
        if curr in table:
            x = i * m + table[curr]
            if x % order == 0:
                curr = gf_mul(curr, gm_inv, poly, n)
                continue
            return x % order
        curr = gf_mul(curr, gm_inv, poly, n)
    return None   # not found (shouldn't happen if target is in the group)

# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
DIV = "=" * 70

def hdr(s):
    print(f"\n{DIV}\n  {s}\n{DIV}")

def run():
    print(DIV)
    print("  hkex_gf_test.py — HKEX-GF: Diffie-Hellman over GF(2ⁿ)*")
    print(DIV)

    # ── Test 1: GF arithmetic properties ────────────────────────────────────
    hdr("Test 1 — GF(2^n) arithmetic: commutativity, associativity, identity")
    for n in (32, 64):
        poly   = GF_POLY[n]
        errors = 0
        for _ in range(1000):
            a = secrets.randbits(n)
            b = secrets.randbits(n)
            c = secrets.randbits(n)
            if gf_mul(a, b, poly, n) != gf_mul(b, a, poly, n):
                errors += 1                                        # commutativity
            if gf_mul(gf_mul(a, b, poly, n), c, poly, n) != \
               gf_mul(a, gf_mul(b, c, poly, n), poly, n):
                errors += 1                                        # associativity
            if gf_mul(a, 1, poly, n) != a:
                errors += 1                                        # identity
        print(f"  n={n}: 1000 trials — commutativity + associativity + identity  "
              f"{'[PASS]' if errors == 0 else f'[FAIL errors={errors}]'}")

    # ── Test 2: Key exchange correctness ────────────────────────────────────
    hdr("Test 2 — HKEX-GF correctness: g^{ab} = g^{ba}")
    results = {}
    for n in (32, 64):
        TRIALS = 5000
        passed = 0
        for _ in range(TRIALS):
            C, C2, sk_a, sk_b, *_ = hkex_gf(n)
            if sk_a == sk_b:
                passed += 1
        results[n] = (passed, TRIALS)
        print(f"  n={n}: {passed}/{TRIALS}  {'[PASS]' if passed == TRIALS else '[FAIL]'}")

    # ── Test 3: Eve's linear attack resistance ───────────────────────────────
    hdr("Test 3 — Eve's classical attack: sk_eve = S_{r+1}·(C⊕C₂)")
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        TRIALS = 5000
        hits = 0
        for _ in range(TRIALS):
            C, C2, sk_real, *_ = hkex_gf(n)[:4]
            sk_eve = S_op(C ^ C2, r, n)
            if sk_eve == sk_real:
                hits += 1
        rate = hits / TRIALS
        print(f"  n={n}: Eve succeeded {hits}/{TRIALS}  (rate={rate:.2e})  "
              f"{'[PASS — attack fails]' if hits == 0 else f'[WARN: {hits} hits]'}")

    # ── Test 4: DLP hardness illustration (small n only) ────────────────────
    hdr("Test 4 — DLP hardness: baby-step giant-step on small GF(2^n)")
    # Use n=16 for tractable BSGS illustration
    n_small  = 16
    poly16   = 0x1002D          # x^16 + x^5 + x^3 + x + 1  (primitive)
    # Actually, let us use p(x) such that we can verify. Use a known one.
    # We'll test with a concrete private key and verify recovery.
    # For n=16, order = 2^16-1 = 65535 = 3×5×17×257  (smooth — DLP easy here)
    order16 = (1 << n_small) - 1

    a_test = secrets.randbelow(order16 - 1) + 1
    C_test  = gf_pow(G, a_test, GF_POLY[32] if n_small > 16 else 0x1002D, n_small) \
        if n_small <= 16 else None

    # For this illustration we just use the GF_POLY for n=32 but on n=16 values.
    # Better: use a specific n=16 poly.
    # Use known primitive poly for GF(2^16): x^16 + x^5 + x^3 + x + 1 = 0x1002B
    POLY16 = 0x0002B   # lower 16 bits of x^16 + x^5 + x^3 + x + 1
    # (x^5 + x^3 + x + 1 = 32+8+2+1 = 43 = 0x2B)
    order_16 = (1 << 16) - 1   # = 65535

    a_priv   = secrets.randbelow(order_16 - 1) + 1
    C_pub    = gf_pow(G, a_priv, POLY16, 16)
    t0       = time.perf_counter()
    a_recov  = bsgs_dlp(C_pub, G, POLY16, 16, order_16)
    t_bsgs   = time.perf_counter() - t0

    print(f"  n=16: order = {order_16} = 3×5×17×257  (smooth — weak for DLP)")
    if a_recov is not None:
        match = (gf_pow(G, a_recov, POLY16, 16) == C_pub)
        print(f"  Private key = {a_priv}, BSGS recovered = {a_recov}, "
              f"correct = {match}  [{t_bsgs*1000:.1f} ms]")
    else:
        print(f"  BSGS: no solution found (n=16 field arithmetic issue)")

    print()
    print("  DLP cost vs. n (BSGS, O(√(2ⁿ−1)) operations):")
    print(f"  {'n':>5}  {'Group order':>22}  {'BSGS cost':>16}  Classical bits")
    for n in (16, 32, 64, 128, 256):
        order = (1 << n) - 1
        bsgs  = isqrt(order)
        bits  = bsgs.bit_length() - 1
        print(f"  {n:>5}  {order:>22}  {bsgs:>16}  ~{bits} bits  "
              f"{'[DEMO ONLY]' if n < 128 else ''}")

    # ── Test 5: FSCX period preserved (HSKE unchanged) ──────────────────────
    hdr("Test 5 — FSCX period preserved: HSKE still works after HKEX-GF swap")
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        TRIALS = 5000
        passed = sum(
            1 for _ in range(TRIALS)
            if fscx_revolve(fscx_revolve(secrets.randbits(n),
                            secrets.randbits(n), i, n),
                            secrets.randbits(n), r, n) ==
               fscx_revolve(secrets.randbits(n), secrets.randbits(n), 0, n)
            # Note: this would be wrong because K must match.  Fix below.
        )
        # Corrected:
        passed = 0
        for _ in range(TRIALS):
            P = secrets.randbits(n)
            K = secrets.randbits(n)
            E = fscx_revolve(P, K, i, n)
            D = fscx_revolve(E, K, r, n)
            if D == P:
                passed += 1
        print(f"  n={n}: fscx_revolve²(P, K, i, r) = P  "
              f"{passed}/{TRIALS}  {'[PASS]' if passed == TRIALS else '[FAIL]'}")

    # ── Test 6: Performance benchmark ────────────────────────────────────────
    hdr("Test 6 — Performance benchmark")
    for n in (32, 64):
        REPS = 200
        t0 = time.perf_counter()
        for _ in range(REPS):
            hkex_gf(n)
        elapsed = time.perf_counter() - t0
        per_exchange = elapsed / REPS * 1000   # ms
        per_mul      = elapsed / (REPS * 4 * n) * 1e6   # µs per gf_mul
        print(f"  n={n}: {REPS} exchanges in {elapsed*1000:.1f} ms  "
              f"→ {per_exchange:.2f} ms/exchange  "
              f"({per_mul:.3f} µs/gf_mul)")

    # ── Summary ──────────────────────────────────────────────────────────────
    hdr("Summary — HKEX-GF algebraic strength")
    print("""
  Correctness:   g^{ab} = g^{ba}  — proved by field commutativity; no S_n=0 needed.
  Non-linearity: A → g^A is non-linear over GF(2) (exponentiation ≠ linear map).
  Eve's attack:  S_{r+1}·(C⊕C₂) fails — g^a and g^b are field elements, not
                 GF(2)^n vectors with the FSCX orbit structure.
  Hardness:      CDH in GF(2^n)* — reduces to DLP via standard argument.
  Operations:    XOR + left-shift only (carryless polynomial arithmetic).
  FSCX impact:   Zero. HSKE/HPKS/HPKE use standard FSCX; period M^n=I intact.

  Security margins (index calculus / function-field sieve):
    n = 64   : ~40 bits  (demonstration only)
    n = 128  : ~60-80 bits  (marginal)
    n = 256  : ~128 bits  (recommended minimum)
    n = 512  : ~192 bits  (conservative)
""")


if __name__ == "__main__":
    run()
