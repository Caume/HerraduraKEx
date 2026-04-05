"""
hkex_nl_proposal.py — Non-linear HKEX proposals

Theorem 10 (SecurityProofs.md §3) proves that any GF(2)-linear HKEX is
classically broken: sk = S_{r+1}·(C⊕C₂) is computable from public wire
values alone.  The root cause is the GF(2)-linearity–correctness–security
incompatibility:

    S_n = 0  (enables correctness)
          ⟹  sk = linear function of (C, C₂)  (breaks security)

This script tests two non-linear alternatives:

────────────────────────────────────────────────────────────────────────────
I.  HKEX-GF — Diffie-Hellman over GF(2ⁿ)*
    Key exchange: Alice publishes C = g^a, Bob publishes C₂ = g^b.
    Shared key:   sk = g^{ab} = C₂^a = C^b   (commutativity of field ×)
    Arithmetic:   carryless polynomial mult mod irreducible p(x).
    Operations:   XOR + left-shift only — no modular integer arithmetic.
    Non-linearity: g^a is non-linear in a (exponentiation, not linear map).
    Security:     DLP in GF(2ⁿ)*.  For n ≥ 128 use index-calculus margins;
                  for n = 64 this is a DEMONSTRATION only (sub-exponential
                  attacks exist for binary-field DLP).
    FSCX:         unchanged; HSKE/HPKS/HPKE keep period n intact.

II. FSCX-CY — Carry-Injection FSCX  (experimental)
    Primitive:  fscx_cy(A, B) = M( (A+B) mod 2ⁿ )
    vs standard: fscx(A, B)   = M( A ⊕ B )
    Carry term: δ(A,B) = (A+B mod 2ⁿ) ⊕ (A⊕B)  = non-linear over GF(2).
    Analysis:   fscx_cy(A,B) = fscx(A,B) ⊕ M(δ(A,B))
                               where δ involves AND at each bit level.
    Eve attack: S_{r+1}·(C⊕C₂) no longer recovers sk (carry contaminates
                all intermediate states with private-key-dependent non-
                linearity).
    HKEX:       correctness NOT guaranteed algebraically; tested empirically.
    HSKE:       requires finding a step count T with f_K^T = identity;
                T is key-dependent and measured via permutation analysis.
────────────────────────────────────────────────────────────────────────────
"""

import secrets
import sys
from math import gcd


# ════════════════════════════════════════════════════════════════════════════
# Standard FSCX primitives  (unchanged — HSKE/HPKS/HPKE keep these)
# ════════════════════════════════════════════════════════════════════════════

def rol(x, bits, n):
    bits %= n
    return ((x << bits) | (x >> (n - bits))) & ((1 << n) - 1)

def ror(x, bits, n):
    return rol(x, n - bits, n)

def M_op(x, n):
    """GF(2)-linear operator M = I ⊕ ROL(1) ⊕ ROR(1)."""
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)

def fscx(A, B, n):
    return M_op(A ^ B, n)

def fscx_revolve(A, B, steps, n):
    for _ in range(steps):
        A = fscx(A, B, n)
    return A

def S_op(delta, r, n):
    """Eve's classical operator: S_{r+1}·delta = ⊕_{j=0}^{r} M^j·delta."""
    acc, cur = 0, delta
    for _ in range(r + 1):
        acc ^= cur
        cur = M_op(cur, n)
    return acc


# ════════════════════════════════════════════════════════════════════════════
# GF(2ⁿ) arithmetic — operations: XOR + left-shift only
# ════════════════════════════════════════════════════════════════════════════
#
# Irreducible polynomials (lower n bits; the x^n term is implicit):
#   GF(2^32): x^32 + x^22 + x^2 + x + 1  →  lower bits = 0x400007
#   GF(2^64): x^64 + x^4  + x^3 + x + 1  →  lower bits = 0x1B
#
# These are primitive polynomials from published polynomial tables.
# The GF(2^64) polynomial is the same structural form used in standard
# binary-field arithmetic (not specific to any cipher; it is a mathematical
# constant characterising the field).
#
GF_POLY = {
    32: 0x00400007,          # x^32 + x^22 + x^2 + x + 1
    64: 0x000000000000001B,  # x^64 + x^4  + x^3 + x + 1
}

# Generator: g = 3 (polynomial x+1).  DH correctness holds for ANY non-zero
# g because GF(2ⁿ) multiplication is commutative and associative.
GF_GENERATOR = 3


def gf_mul(a, b, poly, n):
    """
    Multiply a, b in GF(2ⁿ) defined by irreducible polynomial poly.
    Algorithm: shift-and-XOR (carryless), O(n) iterations.
    Operations: XOR + left-shift only.
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
            a ^= poly          # reduce mod p(x): XOR with low bits of poly
        b >>= 1
    return result


def gf_pow(base, exp, poly, n):
    """Compute base^exp in GF(2ⁿ)* by repeated squaring. O(log exp) muls."""
    result = 1
    base &= (1 << n) - 1
    while exp:
        if exp & 1:
            result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


# ════════════════════════════════════════════════════════════════════════════
# HKEX-GF: one session
# ════════════════════════════════════════════════════════════════════════════

def hkex_gf_session(n):
    """
    DH key exchange in GF(2ⁿ)*.

    Alice: private a, public C  = g^a
    Bob:   private b, public C₂ = g^b
    Shared: sk = g^{ab} = C₂^a = C^b   (by commutativity of GF(2ⁿ) ×)

    Returns (C, C2, sk_alice, sk_bob).
    """
    poly = GF_POLY[n]
    mask = (1 << n) - 1

    a = (secrets.randbits(n) | 1) & mask        # private, odd (never 0)
    b = (secrets.randbits(n) | 1) & mask

    C  = gf_pow(GF_GENERATOR, a, poly, n)       # g^a
    C2 = gf_pow(GF_GENERATOR, b, poly, n)       # g^b

    sk_alice = gf_pow(C2, a, poly, n)           # (g^b)^a = g^{ab}
    sk_bob   = gf_pow(C,  b, poly, n)           # (g^a)^b = g^{ab}

    return C, C2, sk_alice, sk_bob


# ════════════════════════════════════════════════════════════════════════════
# FSCX-CY: Carry-Injection FSCX
# ════════════════════════════════════════════════════════════════════════════

def carry_term(A, B, n):
    """
    δ(A,B) = (A+B mod 2ⁿ) ⊕ (A⊕B)
    This is the non-linear correction introduced by carry propagation.
    δ = 0 iff A AND B = 0 (no carry anywhere); δ ≠ 0 otherwise.
    δ involves AND at each bit level (full carry chain), making it
    non-linear over GF(2).
    """
    mask = (1 << n) - 1
    return ((A + B) & mask) ^ (A ^ B)

def fscx_cy(A, B, n):
    """
    fscx_cy(A, B) = M( (A+B) mod 2ⁿ )
    = fscx(A, B)  ⊕  M( δ(A,B) )
    The δ term is non-linear over GF(2); for fixed B, the map A→fscx_cy(A,B)
    is NOT GF(2)-linear due to carry propagation from A+B.
    """
    mask = (1 << n) - 1
    return M_op((A + B) & mask, n)

def fscx_cy_revolve(A, B, steps, n):
    for _ in range(steps):
        A = fscx_cy(A, B, n)
    return A


# ════════════════════════════════════════════════════════════════════════════
# Permutation period analysis (small n only)
# ════════════════════════════════════════════════════════════════════════════

def permutation_period(f, n):
    """
    Compute the functional period T = LCM of all cycle lengths in the
    permutation f on {0, …, 2ⁿ−1}.  Only feasible for n ≤ 16.
    """
    size    = 1 << n
    visited = bytearray(size)   # 0 = unvisited
    period  = 1

    for start in range(size):
        if not visited[start]:
            x = start
            cycle_len = 0
            while True:
                visited[x] = 1
                x = f(x)
                cycle_len += 1
                if x == start:
                    break
            period = period * cycle_len // gcd(period, cycle_len)

    return period


# ════════════════════════════════════════════════════════════════════════════
# Main test suite
# ════════════════════════════════════════════════════════════════════════════

DIVIDER = "=" * 70

def section(title):
    print()
    print(DIVIDER)
    print(f"  {title}")
    print(DIVIDER)


def run_part_I():
    """
    Part I — HKEX-GF: GF(2ⁿ) Diffie-Hellman
    """
    section("PART I — HKEX-GF: GF(2ⁿ) Diffie-Hellman")

    # ── I-A: GF arithmetic sanity ────────────────────────────────────────
    print("\n[I-A] GF(2^32) arithmetic sanity (commutativity, associativity)")
    poly = GF_POLY[32]
    n    = 32
    errors = 0
    for _ in range(500):
        a = secrets.randbits(n)
        b = secrets.randbits(n)
        c = secrets.randbits(n)
        # commutativity: a*b == b*a
        if gf_mul(a, b, poly, n) != gf_mul(b, a, poly, n):
            errors += 1
        # associativity: (a*b)*c == a*(b*c)
        ab  = gf_mul(a, b, poly, n)
        bc  = gf_mul(b, c, poly, n)
        abc_L = gf_mul(ab, c, poly, n)
        abc_R = gf_mul(a,  bc, poly, n)
        if abc_L != abc_R:
            errors += 1
    status = "[PASS]" if errors == 0 else f"[FAIL] errors={errors}"
    print(f"  500 trials: commutativity + associativity  {status}")

    # ── I-B: DH correctness ───────────────────────────────────────────────
    TRIALS = 2000
    print(f"\n[I-B] HKEX-GF correctness: g^{{ab}} = g^{{ba}}  ({TRIALS} trials per width)")
    for n in (32, 64):
        passed = 0
        for _ in range(TRIALS):
            C, C2, sk_a, sk_b = hkex_gf_session(n)
            if sk_a == sk_b:
                passed += 1
            else:
                print(f"  [FAIL n={n}] sk_a={sk_a:#x}  sk_b={sk_b:#x}")
        status = "[PASS]" if passed == TRIALS else f"[FAIL] {passed}/{TRIALS}"
        print(f"  n={n:>3}: {passed}/{TRIALS}  {status}")

    # ── I-C: Eve's linear attack fails ───────────────────────────────────
    print("\n[I-C] Eve's classical attack on HKEX-GF")
    print("      Eve tries: sk_eve = S_{r+1}·(C ⊕ C₂)  (the FSCX break formula)")
    print("      Expected:  sk_eve ≠ sk_real for ALL trials")
    for n in (32, 64):
        i = n // 4
        r = n - i
        hits = 0
        TRIALS_EVE = 2000
        for _ in range(TRIALS_EVE):
            C, C2, sk_real, _ = hkex_gf_session(n)
            sk_eve = S_op(C ^ C2, r, n)   # Eve's formula unchanged
            if sk_eve == sk_real:
                hits += 1
        rate = hits / TRIALS_EVE
        # With random 32/64-bit values, accidental match probability ≈ 2^-n
        status = "[PASS — attack fails]" if hits == 0 else f"[WARN] {hits} accidental matches"
        print(f"  n={n:>3}: Eve succeeded {hits}/{TRIALS_EVE} times (rate={rate:.2e})  {status}")

    # ── I-D: FSCX period preserved for HSKE ──────────────────────────────
    print("\n[I-D] FSCX period preserved  (HSKE not broken by HKEX-GF change)")
    print("      Verify: fscx_revolve(fscx_revolve(P, K, i), K, r) = P  for i+r=n")
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        passed = 0
        TRIALS_HSKE = 2000
        for _ in range(TRIALS_HSKE):
            P = secrets.randbits(n)
            K = secrets.randbits(n)
            E = fscx_revolve(P, K, i, n)
            D = fscx_revolve(E, K, r, n)
            if D == P:
                passed += 1
        status = "[PASS]" if passed == TRIALS_HSKE else f"[FAIL] {passed}/{TRIALS_HSKE}"
        print(f"  n={n:>3}: {passed}/{TRIALS_HSKE}  {status}")


def run_part_II():
    """
    Part II — FSCX-CY: Carry-Injection experimental variant
    """
    section("PART II — FSCX-CY: Carry-Injection Non-Linear FSCX")

    # ── II-A: Non-linearity demonstration ────────────────────────────────
    n = 32
    print(f"\n[II-A] Non-linearity of fscx_cy  (n={n})")
    print("       fscx_cy(A,B) = M((A+B) mod 2^n)")
    print("       Carry term δ(A,B) = (A+B mod 2^n) ⊕ (A⊕B)  [non-zero iff A AND B ≠ 0]")
    print()
    nonzero_carry = 0
    fscx_neq_fscxcy = 0
    SAMPLES = 5000
    for _ in range(SAMPLES):
        A = secrets.randbits(n)
        B = secrets.randbits(n)
        d = carry_term(A, B, n)
        if d:
            nonzero_carry += 1
        if fscx_cy(A, B, n) != fscx(A, B, n):
            fscx_neq_fscxcy += 1
    print(f"  {SAMPLES} random (A,B) pairs:")
    print(f"    δ(A,B) ≠ 0  (carry present):     {nonzero_carry}/{SAMPLES}")
    print(f"    fscx_cy(A,B) ≠ fscx(A,B):        {fscx_neq_fscxcy}/{SAMPLES}")
    print()
    # Linearity test: for a linear map f, f(A⊕X, B) = f(A,B) ⊕ f(X,B) ⊕ f(0,B)
    # (the last term accounts for the B offset in the affine case)
    linear_violations = 0
    for _ in range(SAMPLES):
        A = secrets.randbits(n)
        X = secrets.randbits(n)
        B = secrets.randbits(n)
        lhs = fscx_cy(A ^ X, B, n)
        rhs = fscx_cy(A, B, n) ^ fscx_cy(X, B, n) ^ fscx_cy(0, B, n)
        if lhs != rhs:
            linear_violations += 1
    print(f"    Linearity violations (A→fscx_cy for fixed B):")
    print(f"    f(A⊕X,B) ≠ f(A,B)⊕f(X,B)⊕f(0,B):  {linear_violations}/{SAMPLES}")
    status = "[NON-LINEAR confirmed]" if linear_violations > 0 else "[WARNING: appears linear]"
    print(f"    {status}")

    # ── II-B: Period analysis (n=8 and n=16, full permutation) ───────────
    print("\n[II-B] Functional period T = LCM of all cycle lengths")
    print("       Standard FSCX vs FSCX-CY  (full permutation, n=8 and n=16)")
    print()
    for n in (8, 16):
        # Sample several B/K values
        print(f"  n={n}:")
        # Standard FSCX
        fscx_periods = set()
        # FSCX-CY periods
        cy_periods = set()
        test_keys = [0x00, 0x01, 0x7F, 0xFF] if n == 8 else \
                    [0x0001, 0x0100, 0x7FFF, 0xFFFF]
        for key in test_keys:
            T_fscx = permutation_period(lambda x, B=key: fscx(x, B, n), n)
            T_cy   = permutation_period(lambda x, K=key: fscx_cy(x, K, n), n)
            fscx_periods.add(T_fscx)
            cy_periods.add(T_cy)
            print(f"    key={key:#06x}: FSCX period={T_fscx:6d}   FSCX-CY period={T_cy:8d}")
        print(f"    → FSCX periods seen: {sorted(fscx_periods)}")
        print(f"    → FSCX-CY periods seen: {sorted(cy_periods)}")
        # Is FSCX period uniformly n? (expected: n for B≠0 since HSKE uses i+r=n)
        all_cy_uniform = (len(cy_periods) == 1)
        print(f"    → FSCX-CY period uniform across keys: "
              f"{'YES' if all_cy_uniform else 'NO — key-dependent, unsuitable for HSKE as-is'}")
        print()

    # ── II-C: HKEX-CY correctness test ───────────────────────────────────
    n = 32
    i, r = n // 4, 3 * n // 4
    TRIALS = 2000
    print(f"\n[II-C] HKEX-CY correctness test  (n={n}, i={i}, r={r}, {TRIALS} trials)")
    print("       sk_alice = fscx_cy_revolve(C2, B, r) ⊕ A")
    print("       sk_bob   = fscx_cy_revolve(C,  B2, r) ⊕ A2")
    print("       C = fscx_cy_revolve(A, B, i),  C2 = fscx_cy_revolve(A2, B2, i)")
    print()
    matched = 0
    for _ in range(TRIALS):
        A  = secrets.randbits(n)
        B  = secrets.randbits(n)
        A2 = secrets.randbits(n)
        B2 = secrets.randbits(n)
        C  = fscx_cy_revolve(A,  B,  i, n)
        C2 = fscx_cy_revolve(A2, B2, i, n)
        sk_alice = fscx_cy_revolve(C2, B,  r, n) ^ A
        sk_bob   = fscx_cy_revolve(C,  B2, r, n) ^ A2
        if sk_alice == sk_bob:
            matched += 1
    match_rate = matched / TRIALS
    status = ("[PASS — unexpected correctness! Investigate.]" if matched == TRIALS
              else "[EXPECTED FAIL — no algebraic identity guarantees correctness]")
    print(f"  sk_alice == sk_bob:  {matched}/{TRIALS}  (rate={match_rate:.4f})")
    print(f"  {status}")
    if matched > 0 and matched < TRIALS:
        print(f"  Note: partial matches ≈ 2^-n accidental collisions, as expected.")

    # ── II-D: Eve's linear attack on FSCX-CY ────────────────────────────
    n = 32
    i, r = n // 4, 3 * n // 4
    TRIALS_EVE = 2000
    print(f"\n[II-D] Eve's classical attack on FSCX-CY  (n={n}, {TRIALS_EVE} trials)")
    print("       Eve applies: sk_eve = S_{r+1}·(C ⊕ C₂)  [FSCX break formula]")
    print("       C, C₂ are outputs of fscx_cy_revolve (not standard FSCX)")
    print()
    eve_hits = 0
    for _ in range(TRIALS_EVE):
        A  = secrets.randbits(n)
        B  = secrets.randbits(n)
        A2 = secrets.randbits(n)
        B2 = secrets.randbits(n)
        C  = fscx_cy_revolve(A,  B,  i, n)
        C2 = fscx_cy_revolve(A2, B2, i, n)
        # What Alice "intends" as sk (here we use Alice's computation):
        sk_alice = fscx_cy_revolve(C2, B, r, n) ^ A
        # Eve's formula — works exactly on standard HKEX but may fail here
        sk_eve   = S_op(C ^ C2, r, n)
        if sk_eve == sk_alice:
            eve_hits += 1
    rate = eve_hits / TRIALS_EVE
    status = ("[PASS — attack fails]" if eve_hits == 0
              else f"[PARTIAL — {eve_hits} hits, rate={rate:.2e}]")
    print(f"  Eve succeeded: {eve_hits}/{TRIALS_EVE}  (rate={rate:.2e})")
    print(f"  {status}")
    print()
    print("  Root cause of Eve's failure (algebraic):")
    print("  Standard HKEX: C = M^i·A + M·S_i·B  →  sk = M^r·(C⊕C₂)  (all linear)")
    print("  FSCX-CY:       intermediate states include carry terms δ_j that depend")
    print("                 on private (A,B).  The S_{r+1} operator cannot reconstruct")
    print("                 those terms from public (C, C₂) alone.  The classical break")
    print("                 identity sk = S_{r+1}·(C⊕C₂) does not hold.")


def run_summary():
    section("SUMMARY")
    print("""
  ┌─────────────────────────────────┬──────────────┬─────────────────────────┐
  │ Property                        │  HKEX-GF     │  FSCX-CY (experimental) │
  ├─────────────────────────────────┼──────────────┼─────────────────────────┤
  │ Key exchange correct            │  YES (proved)│  NO (algebraic break)   │
  │ Non-linear over GF(2)           │  YES (expnt) │  YES (carry term)       │
  │ Eve linear formula fails        │  YES         │  YES                    │
  │ Basic binary ops only           │  XOR+shift   │  XOR+shift+ADD          │
  │ FSCX period preserved (HSKE)    │  YES         │  Not guaranteed         │
  │ Security assumption             │  DLP GF(2ⁿ) │  Unknown                │
  │ HSKE/HPKS/HPKE unchanged        │  YES         │  Uses modified FSCX     │
  └─────────────────────────────────┴──────────────┴─────────────────────────┘

  Recommendation:
    • HKEX-GF is the theoretically sound fix: replace HKEX key exchange with
      GF(2ⁿ) DH; keep standard FSCX for all symmetric operations.
    • FSCX-CY shows that carry injection breaks the classical formula.
      It cannot replace FSCX directly (no HKEX correctness) but hints at
      an HSKE-CY variant where a key-specific period T(K) is found and used
      as the encrypt/decrypt step count.
    • For n ≥ 128, GF(2ⁿ) DLP is considered harder (index calculus is
      sub-exponential; use n = 256 for ≥ 128-bit classical security).
""")


if __name__ == "__main__":
    print(DIVIDER)
    print("  hkex_nl_proposal.py — Non-Linear HKEX Proposals")
    print("  See SecurityProofs.md §9 for algebraic analysis")
    print(DIVIDER)

    run_part_I()
    run_part_II()
    run_summary()

    sys.exit(0)
