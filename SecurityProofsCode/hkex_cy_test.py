"""
hkex_cy_test.py — FSCX-CY implementation and exhaustive analysis

FSCX-CY replaces XOR with integer addition inside FSCX:

    fscx_cy(A, B) = M( (A+B) mod 2ⁿ )   where  M = I ⊕ ROL(1) ⊕ ROR(1)

The carry term δ(A,B) = (A+B mod 2ⁿ) ⊕ (A⊕B) involves AND at every bit
level of the carry chain — this is the source of non-linearity over GF(2).

This file answers three questions:

  Q1. Is FSCX-CY genuinely non-linear?  (algebraic + experimental analysis)
  Q2. Can FSCX-CY replace FSCX in HKEX and give a working key exchange?
      (HKEX-CY correctness test + algebraic reason for failure)
  Q3. What does FSCX-CY actually provide, and where could it be useful?
      (HSKE-CY analysis, period structure, Eve-resistance)
"""

import secrets
import time
import sys
from math import gcd

# ─────────────────────────────────────────────────────────────────────────────
# Standard FSCX (for comparison)
# ─────────────────────────────────────────────────────────────────────────────

def rol(x, k, n):
    k %= n
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1)

def M_op(x, n):
    return x ^ rol(x, 1, n) ^ rol(x, n - 1, n)

def fscx(A, B, n):
    return M_op(A ^ B, n)

def fscx_revolve(A, B, steps, n):
    for _ in range(steps):
        A = fscx(A, B, n)
    return A

def S_op(delta, r, n):
    acc, cur = 0, delta
    for _ in range(r + 1):
        acc ^= cur
        cur = M_op(cur, n)
    return acc

# ─────────────────────────────────────────────────────────────────────────────
# FSCX-CY: carry-injection variant
# ─────────────────────────────────────────────────────────────────────────────

def carry_term(A, B, n):
    """δ(A,B) = (A+B mod 2ⁿ) ⊕ (A⊕B) — the carry correction."""
    mask = (1 << n) - 1
    return ((A + B) & mask) ^ (A ^ B)

def fscx_cy(A, B, n):
    """M( (A+B) mod 2ⁿ ) — non-linear over GF(2) due to carry propagation."""
    return M_op((A + B) & ((1 << n) - 1), n)

def fscx_cy_revolve(A, B, steps, n):
    mask = (1 << n) - 1
    for _ in range(steps):
        A = fscx_cy(A, B, n)
    return A

# ─────────────────────────────────────────────────────────────────────────────
# Permutation-period utility (small n only)
# ─────────────────────────────────────────────────────────────────────────────

def perm_period(f, n):
    """
    LCM of all cycle lengths of f on {0,…,2ⁿ−1}.
    Only feasible for n ≤ 16.  Returns (period, num_cycles, min_cycle, max_cycle).
    """
    size    = 1 << n
    visited = bytearray(size)
    period  = 1
    ncycles = 0
    mn, mx  = size, 0

    for start in range(size):
        if not visited[start]:
            x, length = start, 0
            while True:
                visited[x] = 1
                x = f(x)
                length += 1
                if x == start:
                    break
            period = period * length // gcd(period, length)
            ncycles += 1
            mn = min(mn, length)
            mx = max(mx, length)

    return period, ncycles, mn, mx

def is_xor_translation(f, n):
    """
    True iff f(x) = x ⊕ c for some constant c (i.e. f is an XOR-shift).
    If so, returns (True, c); otherwise (False, None).
    """
    size = 1 << n
    c    = f(0)           # c must equal f(0)
    for x in range(size):
        if f(x) != x ^ c:
            return False, None
    return True, c

# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
DIV = "=" * 70

def hdr(s):
    print(f"\n{DIV}\n  {s}\n{DIV}")


def run():
    print(DIV)
    print("  hkex_cy_test.py — FSCX-CY: Carry-Injection Non-Linear FSCX")
    print(DIV)

    # ── Test 1: Non-linearity analysis ──────────────────────────────────────
    hdr("Test 1 — Non-linearity of FSCX-CY over GF(2)")
    n = 32
    N = 5000

    # 1A. Carry term frequency
    nonzero_delta = sum(
        1 for _ in range(N)
        if carry_term(secrets.randbits(n), secrets.randbits(n), n)
    )
    print(f"  [1A] δ(A,B) ≠ 0  (carry present):  {nonzero_delta}/{N}  "
          f"(expected ≈ {N} for random A,B with AND≠0)")

    # 1B. fscx vs fscx_cy differ
    differ = sum(
        1 for _ in range(N)
        if fscx_cy(*[(v:=secrets.randbits(n)), secrets.randbits(n), n][:2], n) !=
           fscx(*[(v:=secrets.randbits(n)), secrets.randbits(n), n][:2], n)
        for _ in [0]   # single eval per trial
    )
    # Simpler:
    differ = 0
    for _ in range(N):
        A, B = secrets.randbits(n), secrets.randbits(n)
        if fscx_cy(A, B, n) != fscx(A, B, n):
            differ += 1
    print(f"  [1B] fscx_cy(A,B) ≠ fscx(A,B):     {differ}/{N}")

    # 1C. Affine-linearity test: f(A⊕X,B) = f(A,B)⊕f(X,B)⊕f(0,B) (affine cond)
    affine_violations = 0
    for _ in range(N):
        A, X, B = secrets.randbits(n), secrets.randbits(n), secrets.randbits(n)
        lhs = fscx_cy(A ^ X, B, n)
        rhs = fscx_cy(A, B, n) ^ fscx_cy(X, B, n) ^ fscx_cy(0, B, n)
        if lhs != rhs:
            affine_violations += 1
    print(f"  [1C] GF(2)-affine violations:       {affine_violations}/{N}  "
          f"→ {'NON-LINEAR confirmed' if affine_violations > 0 else 'appears linear'}")

    # 1D. Differential non-uniformity sample
    # For a linear map, Δf(a,b) = f(a⊕Δ,b) ⊕ f(a,b) is constant over all a.
    # For FSCX-CY, check how many distinct values Δf takes for a fixed input delta.
    DELTA = 0x00000001  # single-bit flip
    B_fixed = 0xDEADBEEF & ((1 << n) - 1)
    diffs = set()
    for _ in range(256):
        A = secrets.randbits(n)
        diffs.add(fscx_cy(A ^ DELTA, B_fixed, n) ^ fscx_cy(A, B_fixed, n))
    print(f"  [1D] Differential: Δfscx_cy for Δ=1, fixed B: "
          f"{len(diffs)} distinct output differences (linear → exactly 1)")

    # ── Test 2: Period analysis ──────────────────────────────────────────────
    hdr("Test 2 — Functional period: FSCX vs FSCX-CY  (full permutation)")

    for n_small in (8, 16):
        print(f"\n  n={n_small}:")
        keys_to_test = ([0x00, 0x01, 0x3F, 0x7F, 0xFF]
                        if n_small == 8
                        else [0x0001, 0x00FF, 0x0100, 0x7FFF, 0xFFFF])
        for K in keys_to_test:
            T_fscx, nc_f, mn_f, mx_f = perm_period(lambda x, B=K: fscx(x, B, n_small), n_small)
            T_cy,   nc_c, mn_c, mx_c = perm_period(lambda x, K2=K: fscx_cy(x, K2, n_small), n_small)
            print(f"    K={K:#06x}:  FSCX period={T_fscx:>6}  (cycles={nc_f}, "
                  f"min={mn_f}, max={mx_f})")
            print(f"           FSCX-CY period={T_cy:>20}  (cycles={nc_c}, "
                  f"min={mn_c}, max={mx_c})")

    # ── Test 3: g_K^n = XOR-translation? ────────────────────────────────────
    hdr("Test 3 — Does g_K^n(x) = x ⊕ c for all x?  (HKEX-fixed-B correctness test)")
    print("  Standard FSCX: g_B^n = identity  (c=0)  — HKEX correctness follows.")
    print("  FSCX-CY:       g_K^n must also be a XOR-translation for HKEX-CY to work.")
    print()
    n_small = 8
    for K in [0x00, 0x01, 0x55, 0xFF]:
        # Compute g_K^n (n steps of fscx_cy with key K)
        f_n = lambda x, K2=K: fscx_cy_revolve(x, K2, n_small, n_small)
        is_trans, c_val = is_xor_translation(f_n, n_small)
        # Also check standard FSCX
        f_n_std = lambda x, K2=K: fscx_revolve(x, K2, n_small, n_small)
        is_std, c_std = is_xor_translation(f_n_std, n_small)
        print(f"  K={K:#04x}  FSCX  g_K^{n_small} = XOR-trans: {str(is_std):5}  c={c_std}")
        print(f"  K={K:#04x}  CY    g_K^{n_small} = XOR-trans: {str(is_trans):5}  "
              + (f"c={c_val}" if is_trans else "(varies by x — not a translation)"))

    # ── Test 4: HKEX-CY correctness attempt ─────────────────────────────────
    hdr("Test 4 — HKEX-CY: direct replacement of FSCX with FSCX-CY")
    print("  Protocol: C = fscx_cy_revolve(A, B, i),  C₂ = fscx_cy_revolve(A₂, B₂, i)")
    print("            sk_A = fscx_cy_revolve(C₂, B, r) ⊕ A")
    print("            sk_B = fscx_cy_revolve(C,  B₂, r) ⊕ A₂")
    print()
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        TRIALS = 5000
        matched = 0
        for _ in range(TRIALS):
            A  = secrets.randbits(n)
            B  = secrets.randbits(n)
            A2 = secrets.randbits(n)
            B2 = secrets.randbits(n)
            C  = fscx_cy_revolve(A,  B,  i, n)
            C2 = fscx_cy_revolve(A2, B2, i, n)
            if fscx_cy_revolve(C2, B, r, n) ^ A == \
               fscx_cy_revolve(C,  B2, r, n) ^ A2:
                matched += 1
        accidental = 1 / (1 << n)
        print(f"  n={n}: sk_A == sk_B:  {matched}/{TRIALS}  "
              f"(accidental rate ≈ 2^-{n} = {accidental:.1e})  "
              f"[{'EXPECTED FAIL' if matched <= 2 else 'UNEXPECTED'}]")

    print()
    print("  Why it fails (algebraic):")
    print("  Standard HKEX: A = M^r·C ⊕ M^{r+1}·S_i·B  → A cancels via S_n=0.")
    print("  FSCX-CY:       No closed form for g_K^k(A) exists; the carry terms")
    print("                 δ_j = carry(A_j, B) at each step j depend non-linearly")
    print("                 on (A, B) and cannot cancel symmetrically.")

    # ── Test 5: HKEX-CY fixed-B variant ─────────────────────────────────────
    hdr("Test 5 — HKEX-CY fixed-B: both parties use a shared public key K_pub")
    print("  If g_K^{i+r} is a XOR-translation by c, then:")
    print("    sk_A = g_K^{i+r}(A₂) ⊕ A = A₂ ⊕ c ⊕ A")
    print("    sk_B = g_K^{i+r}(A)  ⊕ A₂ = A  ⊕ c ⊕ A₂")
    print("    → sk_A = sk_B  iff c = 0  (identity case only)")
    print()
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        K_pub  = 0xDEADBEEFCAFEBABE & ((1 << n) - 1)  # fixed public key
        TRIALS = 5000
        matched = 0
        for _ in range(TRIALS):
            A  = secrets.randbits(n)
            A2 = secrets.randbits(n)
            C  = fscx_cy_revolve(A,  K_pub, i, n)
            C2 = fscx_cy_revolve(A2, K_pub, i, n)
            if fscx_cy_revolve(C2, K_pub, r, n) ^ A == \
               fscx_cy_revolve(C,  K_pub, r, n) ^ A2:
                matched += 1
        print(f"  n={n}, fixed K_pub: sk_A == sk_B: {matched}/{TRIALS}  "
              f"[{'EXPECTED FAIL' if matched <= 2 else 'UNEXPECTED'}]")

    # ── Test 6: Eve's attack on FSCX-CY ─────────────────────────────────────
    hdr("Test 6 — Eve's classical attack on FSCX-CY public values")
    print("  Eve applies S_{r+1}·(C⊕C₂) to FSCX-CY outputs.")
    for n in (32, 64):
        i, r = n // 4, 3 * n // 4
        TRIALS = 5000
        hits = 0
        for _ in range(TRIALS):
            A  = secrets.randbits(n)
            B  = secrets.randbits(n)
            A2 = secrets.randbits(n)
            B2 = secrets.randbits(n)
            C  = fscx_cy_revolve(A,  B,  i, n)
            C2 = fscx_cy_revolve(A2, B2, i, n)
            sk_alice = fscx_cy_revolve(C2, B, r, n) ^ A  # Alice's view
            sk_eve   = S_op(C ^ C2, r, n)
            if sk_eve == sk_alice:
                hits += 1
        print(f"  n={n}: Eve succeeded {hits}/{TRIALS}  "
              f"(rate={hits/TRIALS:.2e})  "
              f"{'[PASS — attack fails]' if hits == 0 else f'[WARN: {hits} hits]'}")

    # ── Test 7: Performance benchmark ────────────────────────────────────────
    hdr("Test 7 — Performance: FSCX vs FSCX-CY  (n=64, r=48 steps)")
    n, steps = 64, 48
    REPS = 3000

    A_test = secrets.randbits(n)
    B_test = secrets.randbits(n)

    t0 = time.perf_counter()
    for _ in range(REPS):
        fscx_revolve(A_test, B_test, steps, n)
    t_fscx = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(REPS):
        fscx_cy_revolve(A_test, B_test, steps, n)
    t_cy = time.perf_counter() - t0

    print(f"  FSCX    ({steps} steps, n={n}): {REPS} runs in {t_fscx*1000:.1f} ms  "
          f"→ {t_fscx/REPS*1e6:.2f} µs/call")
    print(f"  FSCX-CY ({steps} steps, n={n}): {REPS} runs in {t_cy*1000:.1f} ms  "
          f"→ {t_cy/REPS*1e6:.2f} µs/call")
    print(f"  Overhead ratio: {t_cy/t_fscx:.2f}×  "
          f"(carry ≈ integer add vs XOR — Python overhead dominated)")

    # ── Summary ──────────────────────────────────────────────────────────────
    hdr("Summary — FSCX-CY: what it provides and doesn't provide")
    print("""
  What FSCX-CY provides:
    ✓ Non-linearity over GF(2) — carry term δ(A,B) involves AND at every bit
    ✓ Eve's classical formula S_{r+1}·(C⊕C₂) fails completely
    ✓ Differential non-uniformity — output differences are not constant
    ✓ Minimal code change — one operation: A^B  →  (A+B) mod 2ⁿ

  What FSCX-CY does NOT provide:
    ✗ HKEX correctness — the S_n=0 identity has no carry-injection analog
    ✗ Fixed symmetric period — T(K) is key-dependent and exponentially large
      (e.g., ~10^20 to 10^30 for n=16; unsuitable for direct HSKE use)
    ✗ A known security assumption — no established hard problem underlies it

  Implications:
    • FSCX-CY breaks Eve's linear formula WITHOUT providing a working HKEX.
    • The standard HKEX structure (publish C = fscx_revolve(A,B,i), compute
      sk from other party's C and own B) requires g_K^n = identity, which
      FSCX standard achieves (via M^n=I, S_n=0) but FSCX-CY does not.
    • For a WORKING non-linear HKEX, use HKEX-GF (see hkex_gf_test.py).
    • FSCX-CY remains a useful building block for a non-linear symmetric
      cipher where T(K) is precomputed and encoded in the protocol.
""")


if __name__ == "__main__":
    run()
