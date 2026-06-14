"""
fscx_branch_number.py — FSCX linear diffusion layer analysis

Characterises M = I XOR ROL XOR ROR as a standalone GF(2)-linear diffusion
layer, computing:

  1. Differential and linear branch numbers of M^k (k=1..6) at n=16,32,64.
     (Exhaustive for n≤16; sampled for n=32,64.)
  2. Avalanche coverage: minimum row weight of the joint (A,B)→output matrix
     as a function of revolve step count — tracks how quickly each output bit
     picks up dependences on A-bits and B-bits separately.
  3. Minimum revolve steps for the first output bit to depend on ALL input bits
     of A resp. B ("complete" diffusion per half), and steps where coverage
     ≥ n/2 on both halves ("practical" full diffusion).
  4. Assessment of the suite heuristic i=n/4 against these thresholds.
  5. ASCON Σ0/Σ1 comparison.
  6. FSCX-SPN round-count recommendation.

Branch number definitions (Daemen & Rijmen):
  Differential: Bn_d(L) = min_{a≠0}(wt(a) + wt(L(a)))
  Linear:       Bn_l(L) = min_{a≠0}(wt(a) + wt(L^T(a)))
  For M (symmetric circulant): Bn_d = Bn_l (verified below).

Diffusion analysis notes:
  fscx_revolve(A, B, t) = M^t(A) XOR S_t(B)
  where S_t = M + M^2 + ... + M^t (cumulative sum in GF(2)).

  A-influence matrix: M^t  — circulant, weight bounded by structure of M.
  B-influence matrix: S_t  — accumulates over t steps; can grow denser.

  "Complete diffusion for B": min row weight of S_t = n (all-ones rows).
  "Any diffusion from A": min row weight of M^t ≥ 1 (always true since M
   invertible); more informative is the minimum row weight trajectory.
"""

import sys
import time
import random
from math import log2

# ─────────────────────────────────────────────────────────────────────────────
# Core primitives
# ─────────────────────────────────────────────────────────────────────────────

def rol(x, k, n):
    k %= n
    return ((x << k) | (x >> (n - k))) & ((1 << n) - 1)

def ror(x, k, n):
    return rol(x, n - k, n)

def M_op(x, n):
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)

def hamming(x):
    return bin(x).count('1')

# ─────────────────────────────────────────────────────────────────────────────
# GF(2) matrix utilities  (rows = list of n integers, each n-bit wide)
# ─────────────────────────────────────────────────────────────────────────────

def build_matrix(f, n):
    """Column-major build: col j = f(e_j); then row i = bit i of each col."""
    cols = [f(1 << j, n) for j in range(n)]
    rows = []
    for i in range(n):
        row = 0
        for j in range(n):
            if (cols[j] >> i) & 1:
                row |= (1 << j)
        rows.append(row)
    return rows

def mat_vec(mat, v, n):
    result = 0
    for i, row in enumerate(mat):
        if bin(row & v).count('1') & 1:
            result |= 1 << i
    return result

def mat_mul(A, B, n):
    C = []
    for i in range(n):
        row = 0
        for j in range(n):
            col_j = sum(((B[k] >> j) & 1) << k for k in range(n))
            bit = bin(A[i] & col_j).count('1') & 1
            row |= bit << j
        C.append(row)
    return C

def mat_add(A, B, n):
    """GF(2) matrix addition = XOR."""
    return [A[i] ^ B[i] for i in range(n)]

def mat_pow(mat, k, n):
    result = [1 << i for i in range(n)]  # identity
    base = mat[:]
    while k:
        if k & 1:
            result = mat_mul(result, base, n)
        base = mat_mul(base, base, n)
        k >>= 1
    return result

def transpose_mat(mat, n):
    T = [0] * n
    for i in range(n):
        for j in range(n):
            if (mat[i] >> j) & 1:
                T[j] |= (1 << i)
    return T

def is_symmetric(mat, n):
    return transpose_mat(mat, n) == mat

def min_row_weight(mat, n):
    return min(hamming(row) for row in mat)

def mean_row_weight(mat, n):
    return sum(hamming(row) for row in mat) / n

# ─────────────────────────────────────────────────────────────────────────────
# Branch numbers
# ─────────────────────────────────────────────────────────────────────────────

def branch_number_exhaustive(mat, mat_T, n):
    Bn_d = Bn_l = n + 1
    wd = wl = 0
    for a in range(1, 1 << n):
        w = hamming(a) + hamming(mat_vec(mat, a, n))
        if w < Bn_d:
            Bn_d, wd = w, a
        w = hamming(a) + hamming(mat_vec(mat_T, a, n))
        if w < Bn_l:
            Bn_l, wl = w, a
    return Bn_d, Bn_l, wd, wl

def branch_number_sampled(mat, mat_T, n, trials=500_000, seed=42):
    rng = random.Random(seed)
    mask = (1 << n) - 1
    Bn_d = Bn_l = n + 1
    wd = wl = 0
    for _ in range(trials):
        a = rng.randint(1, mask)
        w = hamming(a) + hamming(mat_vec(mat, a, n))
        if w < Bn_d:
            Bn_d, wd = w, a
        w = hamming(a) + hamming(mat_vec(mat_T, a, n))
        if w < Bn_l:
            Bn_l, wl = w, a
    return Bn_d, Bn_l, wd, wl

# ─────────────────────────────────────────────────────────────────────────────
# Diffusion analysis: A-influence (M^t) and B-influence (S_t = M+M^2+...+M^t)
# ─────────────────────────────────────────────────────────────────────────────

def diffusion_trajectory(n, max_steps):
    """
    For each step count t=1..max_steps, compute:
      - min_row_weight and mean_row_weight of M^t  (A-influence)
      - min_row_weight and mean_row_weight of S_t  (B-influence)
    Returns list of (t, min_A, mean_A, min_B, mean_B).
    Also returns:
      - first t where min_B == n  (B complete diffusion, all-ones rows)
      - first t where min_A and min_B >= n//2  (practical half-coverage)
    """
    mat_M = build_matrix(M_op, n)
    Mt = [1 << i for i in range(n)]  # M^0 = I
    St = [0] * n                      # S_0 = 0

    results = []
    t_B_complete = None
    t_half = None

    for t in range(1, max_steps + 1):
        Mt = mat_mul(Mt, mat_M, n)    # M^t
        St = mat_add(St, Mt, n)       # S_t = S_{t-1} + M^t

        mA = min_row_weight(Mt, n)
        eA = mean_row_weight(Mt, n)
        mB = min_row_weight(St, n)
        eB = mean_row_weight(St, n)

        results.append((t, mA, eA, mB, eB))

        if t_B_complete is None and mB == n:
            t_B_complete = t
        if t_half is None and mA >= n // 2 and mB >= n // 2:
            t_half = t

    return results, t_B_complete, t_half

# ─────────────────────────────────────────────────────────────────────────────
# ASCON comparison
# ─────────────────────────────────────────────────────────────────────────────

def ascon_sigma0(x, n=64):
    return x ^ ror(x, 19, n) ^ ror(x, 28, n)

def ascon_sigma1(x, n=64):
    return x ^ ror(x, 61, n) ^ ror(x, 39, n)

# ─────────────────────────────────────────────────────────────────────────────
# Main analysis
# ─────────────────────────────────────────────────────────────────────────────

def section(title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

def analyse_branch_numbers(n, exhaustive):
    mat_M = build_matrix(M_op, n)
    mat_T = transpose_mat(mat_M, n)

    sym = is_symmetric(mat_M, n)
    M_e0_wt = hamming(mat_vec(mat_M, 1, n))

    print(f"  M symmetric (M = M^T): {sym}    M(e_0) weight: {M_e0_wt}/{n}")
    mode = "exhaustive" if exhaustive else "sampled 500k"
    print(f"\n  Branch numbers ({mode}):")
    print(f"  {'k':>3}  {'Bn_d':>8}  {'Bn_l':>8}  {'Bn_d=Bn_l':>10}  {'min_img_wt':>12}")

    for k in range(1, 7):
        mk = mat_pow(mat_M, k, n)
        mk_T = transpose_mat(mk, n)
        if exhaustive:
            Bn_d, Bn_l, _, _ = branch_number_exhaustive(mk, mk_T, n)
        else:
            Bn_d, Bn_l, _, _ = branch_number_sampled(mk, mk_T, n)
        min_img = min(hamming(mat_vec(mk, 1 << j, n)) for j in range(min(n, 64)))
        eq = "✓" if Bn_d == Bn_l else "✗"
        print(f"  {k:>3}  {Bn_d:>8}  {Bn_l:>8}  {eq:>10}  {min_img:>12}")

def analyse_diffusion(n, max_steps=None):
    if max_steps is None:
        max_steps = n + n // 2

    print(f"\n  Diffusion trajectory (A-influence = M^t, B-influence = S_t):")
    print(f"  {'t':>4}  {'min_A':>7}  {'mean_A':>8}  {'min_B':>7}  {'mean_B':>8}  note")

    traj, t_B_complete, t_half = diffusion_trajectory(n, max_steps)
    suite_i = n // 4

    # Print key milestones + suite heuristic
    shown = set()
    milestones = {1, 2, 4, n//8, n//4, n//2, n, t_B_complete, t_half}
    milestones = {t for t in milestones if t and 1 <= t <= max_steps}

    for t, mA, eA, mB, eB in traj:
        note = ""
        if t == suite_i:
            note = f"← suite i=n/4"
        if t == t_B_complete:
            note += " ← B complete diffusion"
        if t == t_half:
            note += " ← A,B ≥ n/2 coverage"
        if t in milestones or note:
            print(f"  {t:>4}  {mA:>7}  {eA:>8.1f}  {mB:>7}  {eB:>8.1f}  {note}")
            shown.add(t)

    print()
    print(f"  Suite heuristic i=n/4={suite_i}:")
    t_row = traj[suite_i - 1]
    _, mA_i, eA_i, mB_i, eB_i = t_row
    print(f"    A-influence at i: min_row_wt={mA_i}, mean={eA_i:.1f}/{n}")
    print(f"    B-influence at i: min_row_wt={mB_i}, mean={eB_i:.1f}/{n}")

    if t_B_complete:
        if suite_i >= t_B_complete:
            print(f"    B complete diffusion at t={t_B_complete}: i=n/4 EXCEEDS threshold ✓")
        else:
            print(f"    B complete diffusion at t={t_B_complete}: i=n/4 BELOW threshold")
    else:
        print(f"    B does not reach complete diffusion within {max_steps} steps")

    if t_half:
        if suite_i >= t_half:
            print(f"    A,B≥n/2 coverage at t={t_half}: i=n/4 EXCEEDS threshold ✓")
        else:
            print(f"    A,B≥n/2 coverage at t={t_half}: i=n/4 BELOW threshold")
    else:
        print(f"    A,B≥n/2 coverage not reached within {max_steps} steps")

    return suite_i, t_B_complete, t_half, traj[suite_i - 1]

def main():
    print("fscx_branch_number.py — FSCX diffusion characterisation")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    summary = {}

    for n, exhaustive in [(16, True), (32, False)]:
        section(f"n = {n}")
        analyse_branch_numbers(n, exhaustive)
        si, t_Bc, t_half, row_i = analyse_diffusion(n)
        summary[n] = (si, t_Bc, t_half, row_i)

    # n=64: branch numbers are expensive to sample per-k; do M^1 only exhaustively-ish
    section("n = 64")
    n = 64
    analyse_branch_numbers(64, exhaustive=False)
    si, t_Bc, t_half, row_i = analyse_diffusion(64, max_steps=100)
    summary[64] = (si, t_Bc, t_half, row_i)

    # ASCON comparison
    section("ASCON comparison (n=64, sampled)")
    for name, fn in [("Σ0", ascon_sigma0), ("Σ1", ascon_sigma1)]:
        n = 64
        mat = build_matrix(fn, n)
        mat_T = transpose_mat(mat, n)
        Bn_d, Bn_l, _, _ = branch_number_sampled(mat, mat_T, n)
        min_img = min(hamming(mat_vec(mat, 1 << j, n)) for j in range(n))
        sym = is_symmetric(mat, n)
        print(f"  ASCON {name}: Bn_d={Bn_d}, Bn_l={Bn_l}, "
              f"min_img_wt={min_img}, symmetric={sym}")

    # Compare M at n=64 to ASCON
    n = 64
    mat_M = build_matrix(M_op, n)
    mat_T = transpose_mat(mat_M, n)
    Bn_d_M, Bn_l_M, _, _ = branch_number_sampled(mat_M, mat_T, n)
    print(f"  FSCX M (n=64): Bn_d≥{Bn_d_M}, Bn_l≥{Bn_l_M} (sampled)")

    # SPN sketch
    section("FSCX-SPN round count recommendation")
    print("""
  fscx_revolve(A, B, t) = M^t(A) XOR S_t(B),  S_t = M + M^2 + ... + M^t.

  For a keyed SPN ("FSCX-SPN") alternating:
    NL step : nl_fscx_v1(state, round_key, n/4) — adds confusion
    L  step : one application of M                — adds diffusion

  The B-input complete diffusion threshold (all output bits depend on all B
  input bits via S_t) is the key benchmark for the linear step budget.
  The A-influence is bounded by M^t structure; min_row_weight tracks it.
""")
    print(f"  {'n':>6}  {'i=n/4':>6}  {'B-complete(t)':>14}  {'A,B≥n/2(t)':>12}  "
          f"{'min_A@i':>8}  {'min_B@i':>8}  {'mean_B@i':>10}")
    for n in [16, 32, 64]:
        si, t_Bc, t_half, (_, mA, eA, mB, eB) = summary[n]
        t_Bc_s = str(t_Bc) if t_Bc else ">max"
        t_half_s = str(t_half) if t_half else ">max"
        print(f"  {n:>6}  {si:>6}  {t_Bc_s:>14}  {t_half_s:>12}  "
              f"{mA:>8}  {mB:>8}  {eB:>10.1f}")

    print(f"""
  Conclusion:
    The suite heuristic i=n/4 is assessed against B-complete-diffusion and
    A,B≥n/2-coverage thresholds.  See above table.

    For a dedicated FSCX-SPN permutation (used by #95 sponge AEAD / #96 DRBG):
      Minimum round count = ceil(B_complete / 1) since each SPN round
      contributes one M-step of diffusion plus NL confusion.
      Conservative choice: 2× B-complete threshold for multi-round trail
      resistance.
""")

    print(f"Done: {time.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
