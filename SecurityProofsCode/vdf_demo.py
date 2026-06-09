#!/usr/bin/env python3
"""
vdf_demo.py — FSCX and NL-FSCX Verifiable Delay Functions (TODO #78.F)

Implements and analyses two VDF constructions using HerraduraKEx primitives.

────────────────────────────────────────────────────────────────────────────────
§1  FSCX VDF — limited sequential model (n=32)

      eval(x, domain, t)          = fscx_revolve(x, domain, t)
      verify(x, y, t, domain)     = fscx_revolve(y, domain, P − t) == x

  Period P divides n (= KEYBITS), so P can be taken as n conservatively.
  Verification runs P − t forward steps instead of t — faster when t > P/2.

  Critical limitation (§2): FSCX is GF(2)-linear.  An adversary can bypass the
  sequential delay via matrix exponentiation in O(n³ log t), breaking the VDF.

────────────────────────────────────────────────────────────────────────────────
§2  GF(2) matrix break of the FSCX VDF

  FSCX(A, B) = M(A) ⊕ M(B) where M = I ⊕ ROL ⊕ ROR is a GF(2)-linear map.

  Closed form:
    fscx_revolve(A, B, t) = M^t(A) ⊕ Σ_{k=1}^{t} M^k(B)
                           = M^t(A) ⊕ M·T_t·B

  where T_t = I + M + … + M^{t−1} is the geometric sum matrix.

  Both M^t and T_t can be computed in O(n³ log t) via GF(2) matrix exponentiation.
  For fixed domain B: precompute once, evaluate any input A in O(n²) thereafter.

  Crossover (pure Python, n=32): matrix beats sequential at t ≥ ~2000.
  At n=256: sequential O(t·n) vs matrix O(n³ log t) — break-even at t ~ n² log t.

────────────────────────────────────────────────────────────────────────────────
§3  NL-FSCX v1 VDF — orbit-dependent model (n=32)

      eval(x, domain, t)                = nl_fscx_revolve_v1(x, domain, t)
      setup(x, domain) → P              = Brent's cycle detection
      verify(x, y, t, domain, P)        = nl_fscx_revolve_v1(y, domain, P − t) == x

  Advantage: NL-FSCX v1 is non-linear — no known matrix shortcut.
  Limitation: P is input-dependent; finding P costs O(P) ≥ O(t) — no speedup.
              P must be published as a VDF instance parameter.

────────────────────────────────────────────────────────────────────────────────
§4  Summary

  FSCX VDF: broken by matrix exponentiation — not a VDF in the standard model.
  NL-FSCX v1 VDF: sequential hardness conjectured; verification requires O(P − t)
    steps with no known shortcut → not a proper VDF (efficient verification missing).
  Both require Pietrzak/Wesolowski-style succinct proofs for production use.

Runtime: ~3 s (n=32, modest CPU).
"""

import importlib.util, os, random, sys, time
from pathlib import Path

# ── Load suite ────────────────────────────────────────────────────────────────

_SUITE_PATH = Path(__file__).parent.parent / "Herradura cryptographic suite.py"
_spec = importlib.util.spec_from_file_location("herradura_suite", _SUITE_PATH)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BitArray           = _mod.BitArray
fscx_revolve       = _mod.fscx_revolve
nl_fscx_revolve_v1 = _mod.nl_fscx_revolve_v1

# ── Parameters ────────────────────────────────────────────────────────────────

DEMO_N = 32     # bit-width for all demos

SEP  = "═" * 72
SEP2 = "─" * 72


# ── FSCX VDF ──────────────────────────────────────────────────────────────────

def vdf_eval(x: int, domain: int, t: int, n: int) -> int:
    """Evaluate FSCX VDF: t sequential FSCX steps."""
    return fscx_revolve(BitArray(n, x), BitArray(n, domain), t).uint


def vdf_verify(x: int, y: int, t: int, domain: int, n: int, P: int) -> bool:
    """Verify FSCX VDF: run P − t forward steps from y and compare."""
    return fscx_revolve(BitArray(n, y), BitArray(n, domain), P - t).uint == x


def fscx_period(x: int, domain: int, n: int) -> int:
    """Find orbit period via Brent's cycle detection."""
    mask = (1 << n) - 1
    power, lam = 1, 1
    tortoise = x
    hare = fscx_revolve(BitArray(n, x), BitArray(n, domain), 1).uint
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = fscx_revolve(BitArray(n, hare), BitArray(n, domain), 1).uint
        lam += 1
    return lam


# ── GF(2) matrix operations (for matrix attack) ───────────────────────────────

def _build_M(n: int) -> list[int]:
    """FSCX linear map M: output bit i = x[i] ⊕ x[(i+1)%n] ⊕ x[(i−1)%n].
    Returns M as list of n row integers over GF(2)."""
    return [(1 << i) | (1 << ((i + 1) % n)) | (1 << ((i - 1 + n) % n))
            for i in range(n)]


def _mv(M: list[int], v: int, n: int) -> int:
    """GF(2) matrix-vector multiply."""
    r = 0
    for i in range(n):
        if bin(M[i] & v).count('1') & 1:
            r |= 1 << i
    return r


def _mm(A: list[int], B: list[int], n: int) -> list[int]:
    """GF(2) matrix-matrix multiply."""
    cols = [sum((1 << i) for i in range(n) if (B[i] >> j) & 1) for j in range(n)]
    C = [0] * n
    for i in range(n):
        ai = A[i]
        for j in range(n):
            if bin(ai & cols[j]).count('1') & 1:
                C[i] |= 1 << j
    return C


def _mat_pow(M: list[int], t: int, n: int) -> list[int]:
    """GF(2) matrix exponentiation: M^t via repeated squaring."""
    R = [1 << i for i in range(n)]  # identity
    base = M[:]
    while t:
        if t & 1:
            R = _mm(R, base, n)
        base = _mm(base, base, n)
        t >>= 1
    return R


def _sum_mat(M: list[int], t: int, n: int) -> tuple[list[int], list[int]]:
    """Compute (T_t, M_t) where T_t = I + M + … + M^{t−1}, via doubling.
    Uses: T_{2k} = T_k + M^k · T_k;  M_{2k} = M_k^2."""
    I = [1 << i for i in range(n)]

    def xm(A, B):
        return [a ^ b for a, b in zip(A, B)]

    if t == 0:
        return [0] * n, I
    if t == 1:
        return I[:], M[:]
    T_k, M_k = _sum_mat(M, t // 2, n)
    T_2k = xm(T_k, _mm(M_k, T_k, n))
    M_2k = _mm(M_k, M_k, n)
    if t % 2 == 0:
        return T_2k, M_2k
    return xm(T_2k, M_2k), _mm(M_2k, M, n)


def fscx_matrix_eval(A: int, B: int, t: int, n: int) -> int:
    """Compute fscx_revolve(A, B, t) via matrix exponentiation.

    Closed form: M^t(A) ⊕ M·T_t·B   (O(n³ log t) precompute, O(n²) evaluate).
    Breaks sequential hardness: an adversary with O(n³) capability can bypass
    the intended t-step delay entirely.
    """
    M_rows = _build_M(n)
    M_t    = _mat_pow(M_rows, t, n)
    T_t, _ = _sum_mat(M_rows, t, n)
    # Σ_{k=1}^{t} M^k(B) = M · T_t · B
    S_B = _mv(_mm(M_rows, T_t, n), B, n)
    return _mv(M_t, A, n) ^ S_B


# ── NL-FSCX v1 VDF ───────────────────────────────────────────────────────────

def nl_vdf_eval(x: int, domain: int, t: int, n: int) -> int:
    """Evaluate NL-FSCX v1 VDF: t sequential NL-FSCX steps."""
    return nl_fscx_revolve_v1(BitArray(n, x), BitArray(n, domain), t).uint


def nl_vdf_period(x: int, domain: int, n: int, cap: int = 1 << 16) -> int | None:
    """Find NL-FSCX v1 orbit period via Brent's.  Returns None if > cap."""
    power, lam = 1, 1
    tortoise = x
    hare = nl_fscx_revolve_v1(BitArray(n, x), BitArray(n, domain), 1).uint
    steps = 0
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = nl_fscx_revolve_v1(BitArray(n, hare), BitArray(n, domain), 1).uint
        steps += 1
        if steps > cap:
            return None
    return lam


def nl_vdf_verify(x: int, y: int, t: int, domain: int, P: int, n: int) -> bool:
    """Verify NL-FSCX v1 VDF: run P − t forward steps from y."""
    return nl_fscx_revolve_v1(BitArray(n, y), BitArray(n, domain), P - t).uint == x


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    random.seed(42)
    n    = DEMO_N
    mask = (1 << n) - 1

    print()
    print("vdf_demo.py — FSCX and NL-FSCX Verifiable Delay Functions (TODO #78.F)")
    print(f"  n = {n} bits  (demo; production uses n=256)")
    print()

    t0_total = time.monotonic()

    # ── §1 FSCX VDF ───────────────────────────────────────────────────────
    print(SEP)
    print("§1 — FSCX VDF (limited sequential model)")
    print(SEP)
    print()
    print("  eval(x, d, t)     = fscx_revolve(x, d, t)         — t sequential steps")
    print("  verify(x, y, t, d) = fscx_revolve(y, d, P−t) == x — P−t forward steps")
    print()

    x      = random.randint(1, mask)
    domain = random.randint(1, mask)

    t0 = time.monotonic()
    P  = fscx_period(x, domain, n)
    t_period = time.monotonic() - t0
    print(f"  Period P for (x=0x{x:08x}, d=0x{domain:08x}): P = {P}  [{t_period*1000:.0f} ms]")
    print()

    print(f"  {'t':>6}  {'eval (ms)':>10}  {'verify (ms)':>12}  {'speedup':>8}  correct")
    print(f"  {SEP2}")
    for t in [1, P // 4, P // 2, P - 1]:
        if t < 1:
            continue
        t0 = time.monotonic()
        y       = vdf_eval(x, domain, t, n)
        t_eval  = time.monotonic() - t0

        t0 = time.monotonic()
        ok      = vdf_verify(x, y, t, domain, n, P)
        t_ver   = time.monotonic() - t0

        speedup = t_eval / t_ver if t_ver > 0 else float('inf')
        print(f"  {t:>6}  {t_eval*1000:>10.3f}  {t_ver*1000:>12.3f}  {speedup:>7.1f}x  {ok}")
    print()

    # ── §2 Matrix attack ───────────────────────────────────────────────────
    print(SEP)
    print("§2 — GF(2) matrix exponentiation attack")
    print(SEP)
    print()
    print("  FSCX(A, B) = M(A) ⊕ M(B)  where M = I ⊕ ROL ⊕ ROR  (GF(2)-linear)")
    print("  Closed form: fscx_revolve(A, B, t) = M^t(A) ⊕ M·T_t·B")
    print("               T_t = I + M + … + M^{t−1}  (sum matrix)")
    print()
    print("  Verification of closed form:")
    x2 = random.randint(1, mask)
    d2 = random.randint(1, mask)
    for t in [1, 8, P, 2 * P]:
        seq    = vdf_eval(x2, d2, t, n)
        attack = fscx_matrix_eval(x2, d2, t, n)
        print(f"    t={t:3d}: sequential=0x{seq:08x}  matrix=0x{attack:08x}  match={seq==attack}")
    print()

    print("  Timing comparison (n=32): sequential fscx_revolve vs matrix attack")
    print(f"  {'t':>7}  {'sequential (ms)':>16}  {'matrix (ms)':>13}  {'matrix faster?':>15}")
    print(f"  {SEP2}")
    for t in [100, 500, 1000, 2000, 5000, 10000]:
        xr = random.randint(1, mask)
        dr = random.randint(1, mask)

        t0 = time.monotonic()
        seq = vdf_eval(xr, dr, t, n)
        t_seq = time.monotonic() - t0

        t0 = time.monotonic()
        mat = fscx_matrix_eval(xr, dr, t, n)
        t_mat = time.monotonic() - t0

        assert seq == mat
        faster = "YES" if t_mat < t_seq else "no"
        print(f"  {t:>7}  {t_seq*1000:>16.1f}  {t_mat*1000:>13.1f}  {faster:>15}")
    print()
    print("  Asymptotic: sequential O(t·n), matrix O(n³ log t).")
    print("  For n=256: matrix wins at t > n² = 65536; precomputation amortized over queries.")
    print("  Conclusion: FSCX VDF is BROKEN — not sequentially hard against this attack.")
    print()

    # ── §3 NL-FSCX v1 VDF ─────────────────────────────────────────────────
    print(SEP)
    print("§3 — NL-FSCX v1 VDF (orbit-dependent model)")
    print(SEP)
    print()
    print("  eval(x, d, t)  = nl_fscx_revolve_v1(x, d, t)    — t sequential NL-FSCX steps")
    print("  setup(x, d)    = Brent's cycle detection → P     — O(P) work, must be published")
    print("  verify(x, y, t, d, P) = nl_fscx_revolve_v1(y, d, P−t) == x")
    print()

    x3 = random.randint(1, mask)
    d3 = random.randint(1, mask)

    t0 = time.monotonic()
    P3 = nl_vdf_period(x3, d3, n)
    t_setup = time.monotonic() - t0
    print(f"  Period P for NL-FSCX v1 (x=0x{x3:08x}, d=0x{d3:08x}): P = {P3}  [{t_setup*1000:.0f} ms]")
    print()

    if P3 is None:
        print(f"  Period > 2^16 — orbit did not close within cap.")
        print(f"  (Consistent with nl_fscx_v2_orbit.py §4: all n=32 orbits > 65536.)")
        print()
        print("  Eval timing at t=100 (to demonstrate non-linear cost):")
        t0 = time.monotonic()
        nl_vdf_eval(x3, d3, 100, n)
        t_nl_100 = time.monotonic() - t0
        t0 = time.monotonic()
        vdf_eval(x3, d3, 100, n)
        t_fscx_100 = time.monotonic() - t0
        print(f"    nl_fscx_revolve_v1 t=100: {t_nl_100*1000:.2f} ms  "
              f"(fscx_revolve t=100: {t_fscx_100*1000:.2f} ms)")
        print()
        print("  Verification impossible without P: P > 2^16 → P − t > 65436 steps.")
    elif P3 >= 4:
        print(f"  {'t':>6}  {'eval (ms)':>10}  {'verify (ms)':>12}  {'speedup':>8}  correct")
        print(f"  {SEP2}")
        for t in [1, P3 // 4, P3 // 2, P3 - 1]:
            if t < 1:
                continue
            t0 = time.monotonic()
            y3     = nl_vdf_eval(x3, d3, t, n)
            t_eval = time.monotonic() - t0

            t0 = time.monotonic()
            ok     = nl_vdf_verify(x3, y3, t, d3, P3, n)
            t_ver  = time.monotonic() - t0

            speedup = t_eval / t_ver if t_ver > 0 else float('inf')
            print(f"  {t:>6}  {t_eval*1000:>10.3f}  {t_ver*1000:>12.3f}  {speedup:>7.1f}x  {ok}")
        print()
    print("  No known closed form for nl_fscx_revolve_v1 — matrix attack does not apply.")
    print("  Cost of verification = P − t steps (same order as evaluation).")
    print("  Limitation: P varies per (x, domain); setup cost O(P) ≥ O(t) — no speedup.")
    print()

    # ── §4 Summary ────────────────────────────────────────────────────────
    print(SEP)
    print("§4 — Summary and Deployment Status")
    print(SEP)
    print()
    print("  FSCX VDF (§1):")
    print("    + Fixed, input-independent period P = n (conservative).")
    print("    + Verification can be faster: P − t steps  (fast when t > P/2).")
    print("    ✗ GF(2)-linear: matrix attack computes output in O(n³ log t).")
    print("    ✗ Broken in standard sequential-hardness model.")
    print("    Model: 'limited' — valid only if adversary cannot do matrix exponentiation")
    print("    (sequential RAM with no algebraic shortcuts).  Rarely a safe assumption.")
    print()
    print("  NL-FSCX v1 VDF (§3):")
    print("    + Non-linear — no known algebraic shortcut or matrix attack.")
    print("    + Input–domain orbit hardness conjectured (no polynomial shortcut known).")
    print("    ✗ Period P is input-dependent: setup (Brent's) costs O(P) ≥ O(t).")
    print("    ✗ Verification costs P − t steps — no asymptotic improvement over eval.")
    print("    ✗ No succinct proof of correct evaluation (needed for efficient verify).")
    print()
    print("  PRODUCTION PATH:")
    print("  A production VDF requires one of:")
    print("    A. Succinct proof of correct evaluation (Pietrzak 2018 / Wesolowski 2019).")
    print("       These require a group with hard DL (RSA, class group) or a sequentially")
    print("       hard function with a specific algebraic structure not yet found in FSCX.")
    print("    B. A non-linear periodic map with fixed, input-independent period and")
    print("       no known polynomial shortcut — NL-FSCX v1 approximates this but lacks")
    print("       fixed period and succinct verification.")
    print()
    print("  DEPLOYMENT STATUS: research prototype.  Neither construction is production-ready.")

    elapsed = time.monotonic() - t0_total
    print()
    print(SEP)
    print(f"Total runtime: {elapsed:.1f} s")
    print("END vdf_demo.py")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
