#!/usr/bin/env python3
"""
hkex_rnl_failure_rate.py — Empirical HKEX-RNL key-agreement failure-rate analysis

  §1  Empirical failure rate (n=32,  10 000 trials) — fast baseline
  §2  Per-coefficient noise analysis (n=32, 10 000 trials)
  §3  Empirical failure rate (n=256,  up to 5 000 trials) — deployed parameters
  §4  p-sensitivity sweep (n=32, 2 000 trials per p value)

Deployed parameters: q=65537, p=4096, pp=2, η=1
SecurityProofs.md §11.5 Q2 marks (q=65537, n=256, p=4096) as ⚠ pending verification.
"""

import os
import time
import math
from collections import Counter

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
Q   = 65537   # Fermat prime modulus (deployed)
PP  = 2       # extraction modulus: 1 bit per coefficient
ETA = 1       # CBD(η=1): secret coefficients in {-1, 0, 1}

SEP  = "═" * 70
SEP2 = "─" * 70


# ─────────────────────────────────────────────────────────────────────────────
# Ring-arithmetic primitives (copied verbatim from Herradura cryptographic suite.py)
# ─────────────────────────────────────────────────────────────────────────────

def _ntt_inplace(a, q, invert):
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    length = 2
    while length <= n:
        w = pow(3, (q - 1) // length, q)
        if invert:
            w = pow(w, q - 2, q)
        for i in range(0, n, length):
            wn = 1
            for k in range(length >> 1):
                u = a[i + k]
                v = a[i + k + (length >> 1)] * wn % q
                a[i + k]                     = (u + v) % q
                a[i + k + (length >> 1)]     = (u - v) % q
                wn = wn * w % q
        length <<= 1
    if invert:
        inv_n = pow(n, q - 2, q)
        for i in range(n):
            a[i] = a[i] * inv_n % q


def _poly_mul(f, g, q, n):
    """Multiply f*g in Z_q[x]/(x^n+1) via negacyclic NTT."""
    psi     = pow(3, (q - 1) // (2 * n), q)
    psi_inv = pow(psi, q - 2, q)
    fa, ga  = list(f), list(g)
    pw = 1
    for i in range(n):
        fa[i] = fa[i] * pw % q
        ga[i] = ga[i] * pw % q
        pw = pw * psi % q
    _ntt_inplace(fa, q, False)
    _ntt_inplace(ga, q, False)
    ha = [fa[i] * ga[i] % q for i in range(n)]
    _ntt_inplace(ha, q, True)
    pw_inv = 1
    for i in range(n):
        ha[i]  = ha[i] * pw_inv % q
        pw_inv = pw_inv * psi_inv % q
    return ha


def _poly_add(f, g, q):
    return [(a + b) % q for a, b in zip(f, g)]


def _round_poly(poly, from_q, to_p):
    return [(c * to_p + from_q // 2) // from_q % to_p for c in poly]


def _lift_poly(poly, from_p, to_q):
    return [c * to_q // from_p % to_q for c in poly]


def _m_poly(n):
    """FSCX polynomial m(x) = 1 + x + x^{n-1}."""
    p = [0] * n
    p[0] = p[1] = p[n - 1] = 1
    return p


def _rand_poly(n, q):
    """Uniform random polynomial over Z_q (bias-free 3-byte rejection sampling)."""
    threshold = (1 << 24) - (1 << 24) % q
    out = []
    while len(out) < n:
        v = int.from_bytes(os.urandom(3), 'big')
        if v < threshold:
            out.append(v % q)
    return out


def _cbd_poly(n, eta, q):
    """CBD(η): each coeff = (popcount of η bits) − (popcount of next η bits) mod q."""
    mask       = (1 << eta) - 1
    byte_count = (2 * eta + 7) // 8
    out = []
    for _ in range(n):
        raw = int.from_bytes(os.urandom(byte_count), 'big')
        a   = bin(raw & mask).count('1')
        b   = bin((raw >> eta) & mask).count('1')
        out.append((a - b) % q)
    return out


def _extract_bits(poly, pp, n_bits):
    """Extract 1 bit per coefficient (c >= pp//2 → 1). Returns int."""
    threshold = pp // 2
    val = 0
    for i, c in enumerate(poly[:n_bits]):
        if c >= threshold:
            val |= (1 << i)
    return val


# ─────────────────────────────────────────────────────────────────────────────
# One HKEX-RNL exchange
# ─────────────────────────────────────────────────────────────────────────────

def rnl_exchange(n, q, p, pp, eta):
    """Run one full HKEX-RNL exchange. Returns (K_raw_A, K_raw_B, K_poly_A, K_poly_B, s_A, s_B, m_blind)."""
    m_base  = _m_poly(n)
    a_rand  = _rand_poly(n, q)
    m_blind = _poly_add(m_base, a_rand, q)

    s_A  = _cbd_poly(n, eta, q)
    C_A  = _round_poly(_poly_mul(m_blind, s_A, q, n), q, p)

    s_B  = _cbd_poly(n, eta, q)
    C_B  = _round_poly(_poly_mul(m_blind, s_B, q, n), q, p)

    K_poly_A = _poly_mul(s_A, _lift_poly(C_B, p, q), q, n)
    K_poly_B = _poly_mul(s_B, _lift_poly(C_A, p, q), q, n)

    K_raw_A = _extract_bits(_round_poly(K_poly_A, q, pp), pp, n)
    K_raw_B = _extract_bits(_round_poly(K_poly_B, q, pp), pp, n)

    return K_raw_A, K_raw_B, K_poly_A, K_poly_B, s_A, s_B, m_blind


# ─────────────────────────────────────────────────────────────────────────────
# Statistics helpers
# ─────────────────────────────────────────────────────────────────────────────

def wilson_ci(k, n, z=1.96):
    """Wilson score 95% confidence interval for proportion k/n."""
    if n == 0:
        return (0.0, 1.0)
    p_hat = k / n
    denom  = 1 + z * z / n
    centre = (p_hat + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - margin), centre + margin)


def popcount(x):
    return bin(x).count('1')


# ─────────────────────────────────────────────────────────────────────────────
# §1 — Empirical failure rate (n=32, 10 000 trials)
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP)
    print("§1  Empirical failure rate  (q=65537, n=32, p=4096, pp=2, η=1)")
    print(f"    10 000 trials")
    print(SEP)
    N, P, TRIALS = 32, 4096, 10_000

    failures     = 0
    bit_err_dist = Counter()
    max_bit_err  = 0
    fail_examples = []

    t0 = time.monotonic()
    for trial in range(TRIALS):
        K_A, K_B, *_ = rnl_exchange(N, Q, P, PP, ETA)
        if K_A != K_B:
            err = popcount(K_A ^ K_B)
            failures += 1
            bit_err_dist[err] += 1
            max_bit_err = max(max_bit_err, err)
            if len(fail_examples) < 5:
                fail_examples.append((trial, err, K_A, K_B))
    elapsed = time.monotonic() - t0

    lo, hi = wilson_ci(failures, TRIALS)
    print(f"  Trials        : {TRIALS}")
    print(f"  Failures      : {failures}  ({failures/TRIALS*100:.4f}%)")
    print(f"  95% Wilson CI : [{lo*100:.4f}%, {hi*100:.4f}%]")
    print(f"  Max bit-errors: {max_bit_err}")
    if failures:
        print(f"  Bit-error dist: {dict(sorted(bit_err_dist.items()))}")
        for t, err, ka, kb in fail_examples:
            print(f"    trial {t:5d}: {err} bit(s) wrong  K_A={ka:#010x}  K_B={kb:#010x}")
    else:
        print("  No failures.")
    print(f"  Time          : {elapsed:.1f}s  ({TRIALS/elapsed:.0f} trials/s)")
    print()
    return failures, TRIALS


# ─────────────────────────────────────────────────────────────────────────────
# §2 — Per-coefficient noise analysis (n=32, 10 000 trials)
# ─────────────────────────────────────────────────────────────────────────────

def section2():
    print(SEP2)
    print("§2  Per-coefficient noise analysis  (q=65537, n=32, p=4096, 10 000 trials)")
    print(SEP2)
    N, P, TRIALS = 32, 4096, 10_000
    threshold = Q // (2 * PP)   # = 16384: |error| must be < this for agreement

    max_err_A    = 0
    max_err_B    = 0
    max_err_diff = 0
    near_boundary_events = 0   # coeff-trials where the boundary q/4 or 3q/4 lies
                                # within the error band [min(vA,vB), max(vA,vB)]

    t0 = time.monotonic()
    for _ in range(TRIALS):
        _, _, kp_A, kp_B, s_A, s_B, m_blind = rnl_exchange(N, Q, P, PP, ETA)
        # exact shared polynomial (ring commutativity: s_A·m·s_B == s_B·m·s_A)
        exact = _poly_mul(s_A, _poly_mul(m_blind, s_B, Q, N), Q, N)

        for i in range(N):
            # signed error: map to (-q/2, q/2]
            eA = (kp_A[i] - exact[i]) % Q
            eB = (kp_B[i] - exact[i]) % Q
            if eA > Q // 2: eA -= Q
            if eB > Q // 2: eB -= Q
            max_err_A    = max(max_err_A,    abs(eA))
            max_err_B    = max(max_err_B,    abs(eB))
            max_err_diff = max(max_err_diff, abs(eA - eB))
            # check if either extraction boundary (q/4 or 3q/4) lies in [min,max]
            lo_v = min(kp_A[i], kp_B[i])
            hi_v = max(kp_A[i], kp_B[i])
            for bdry in (Q // 4, 3 * Q // 4):
                if lo_v <= bdry <= hi_v:
                    near_boundary_events += 1
                    break
    elapsed = time.monotonic() - t0

    theory_max = N * (Q // (2 * P))   # n × q/(2p)
    print(f"  Extraction threshold q/(2·pp) : {threshold}")
    print(f"  Theoretical max |error|       : n × q/(2p) = {N} × {Q//(2*P)} = {theory_max}")
    print(f"  Measured max |error_A|        : {max_err_A}  ({max_err_A/threshold*100:.2f}% of threshold)")
    print(f"  Measured max |error_B|        : {max_err_B}  ({max_err_B/threshold*100:.2f}% of threshold)")
    print(f"  Measured max |error_A−error_B|: {max_err_diff}  ({max_err_diff/threshold*100:.2f}% of threshold)")
    print(f"  Near-boundary events          : {near_boundary_events} / {TRIALS*N} coeff-trials  "
          f"({near_boundary_events/(TRIALS*N)*100:.4f}%)")
    print(f"  Time                          : {elapsed:.1f}s")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3 — Empirical failure rate (n=256, deployed)
# ─────────────────────────────────────────────────────────────────────────────

def section3():
    print(SEP)
    print("§3  Empirical failure rate  (q=65537, n=256, p=4096, pp=2, η=1)")
    print(SEP)
    N, P = 256, 4096

    # Time one trial to set TRIALS within a 120s budget
    t0 = time.monotonic()
    rnl_exchange(N, Q, P, PP, ETA)
    t_one = time.monotonic() - t0
    TARGET_SEC = 120
    TRIALS = min(5000, max(500, int(TARGET_SEC / t_one)))
    print(f"  Single trial  : {t_one*1000:.1f}ms  →  running {TRIALS} trials (≤{TARGET_SEC}s cap)")
    print()

    failures     = 0
    bit_err_dist = Counter()
    max_bit_err  = 0
    fail_examples = []

    t0 = time.monotonic()
    for trial in range(TRIALS):
        K_A, K_B, *_ = rnl_exchange(N, Q, P, PP, ETA)
        if K_A != K_B:
            err = popcount(K_A ^ K_B)
            failures += 1
            bit_err_dist[err] += 1
            max_bit_err = max(max_bit_err, err)
            if len(fail_examples) < 5:
                fail_examples.append((trial, err))
        if (trial + 1) % 500 == 0:
            print(f"  ... {trial+1:>5}/{TRIALS}  failures so far: {failures}"
                  f"  ({time.monotonic()-t0:.0f}s)")
    elapsed = time.monotonic() - t0

    lo, hi = wilson_ci(failures, TRIALS)
    print(f"  Trials        : {TRIALS}")
    print(f"  Failures      : {failures}  ({failures/TRIALS*100:.4f}%)")
    print(f"  95% Wilson CI : [{lo*100:.4f}%, {hi*100:.4f}%]")
    print(f"  Max bit-errors: {max_bit_err}")
    if failures:
        print(f"  Bit-error dist: {dict(sorted(bit_err_dist.items()))}")
        for t, err in fail_examples:
            print(f"    trial {t:5d}: {err} bit(s) wrong")
    else:
        print("  No failures.")
    print(f"  Time          : {elapsed:.1f}s  ({TRIALS/elapsed:.2f} trials/s)")
    print()
    return failures, TRIALS


# ─────────────────────────────────────────────────────────────────────────────
# §4 — p-sensitivity sweep (n=32, 2 000 trials per p value)
# ─────────────────────────────────────────────────────────────────────────────

def section4():
    print(SEP2)
    print("§4  p-sensitivity sweep  (q=65537, n=32, pp=2, η=1, 2 000 trials per p)")
    print(SEP2)
    N, TRIALS = 32, 2_000
    P_VALUES  = [512, 1024, 2048, 4096, 8192]

    print(f"  {'p':>6}  {'failures':>10}  {'rate%':>8}  {'95% CI (lo%..hi%)':>26}  {'q/(2p)':>8}")
    print(f"  {'─'*6}  {'─'*10}  {'─'*8}  {'─'*26}  {'─'*8}")
    for p in P_VALUES:
        fails = 0
        for _ in range(TRIALS):
            K_A, K_B, *_ = rnl_exchange(N, Q, p, PP, ETA)
            if K_A != K_B:
                fails += 1
        lo, hi = wilson_ci(fails, TRIALS)
        margin = Q // (2 * p)
        print(f"  {p:>6}  {fails:>10}  {fails/TRIALS*100:>8.4f}  "
              f"[{lo*100:>8.4f}%..{hi*100:>8.4f}%]  {margin:>8}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print()
    print("hkex_rnl_failure_rate.py — HKEX-RNL key-agreement failure-rate analysis")
    print(f"  q={Q}, η={ETA}, pp={PP} (deployed parameters)")
    print()

    f1, t1 = section1()
    section2()
    f3, t3 = section3()
    section4()

    print(SEP)
    print("SUMMARY")
    print(SEP)
    print(f"  n=32  (baseline) : {f1}/{t1} failures  ({f1/t1*100:.4f}%)")
    print(f"  n=256 (deployed) : {f3}/{t3} failures  ({f3/t3*100:.4f}%)")
    print()

    # Decision
    rate32  = f1 / t1
    rate256 = f3 / t3
    worst   = max(rate32, rate256)
    if worst == 0.0:
        verdict = "PASS — zero failures observed; current parameters have adequate noise margin."
    elif worst <= 0.001:
        verdict = "ACCEPTABLE — low failure rate; no reconciliation needed for most uses."
    elif worst <= 0.01:
        verdict = "MARGINAL — consider NewHope-style 1-bit reconciliation hints."
    else:
        verdict = "FAIL — failure rate > 1%; reconciliation hints required before production use."
    print(f"  Verdict: {verdict}")
    print()


if __name__ == '__main__':
    main()
