"""
hkex_cfscx_blong.py — Large B, Short A: Convolution Strategy Analysis

Settings: A = n-bit (short, fixed), B = 4n-bit (long) = B1||B2||B3||B4

Five convolution strategies, two output widths:

  ── n-bit output (256-bit in the suite) ──────────────────────────────────────
  S1  Sequential-B     t ← fscx_r(t, Bᵢ, r) for i=1..4              A=n,B=4n→C=n
  S2  B-fold           fold Bᵢ into state, fixed base B1              A=n,B=4n→C=n
  S3  B-cascade        pair (B2i-1 into state, B2i as base)           A=n,B=4n→C=n

  ── 4n-bit output (1024-bit) ─────────────────────────────────────────────────
  S4  Parallel-expand  Cᵢ = fscx_r(A, Bᵢ, r);  C = C1‖C2‖C3‖C4     A=n,B=4n→C=4n
  S5  Progressive      tᵢ = fscx_r(A ⊕ t_{i-1}, Bᵢ, r); C = ‖tᵢ   A=n,B=4n→C=4n

  ── Degenerate variant ───────────────────────────────────────────────────────
  S4x XOR-reduce of S4: C = C1⊕C2⊕C3⊕C4                             A=n,B=4n→C=n

Key questions (same as previous analysis but with swapped dimensions):
  1. Is each strategy GF(2)-linear in A for fixed B?
  2. Is A uniquely recoverable (n→n square map)?  Overdetermined (n→4n)?
  3. What is the cost of Eve's linear-algebra attack?
  4. B-private role swap: does making B the secret improve matters?
  5. Does XOR-reduce cancel A entirely?
  6. Non-linear GF-mul injection: breaks linearity?

Part I    — Construction overview and algebraic forms
Part II   — Linearity and unique A-recovery for n-bit output strategies (S1–S3)
Part III  — GF(2) matrix attack: full A recovery by linear algebra
Part IV   — 4n-bit output strategies (S4, S5) and overdetermined analysis
Part V    — S4x degenerate: A cancellation in XOR-reduce
Part VI   — Role swap: B as private key, A as public generator
Part VII  — Non-linear GF-injection variant
Part VIII — Summary comparison
"""

import secrets
import sys

DIVIDER = "=" * 72


def section(title):
    print()
    print(DIVIDER)
    print(f"  {title}")
    print(DIVIDER)


# ─────────────────────────────────────────────────────────────────────────────
# FSCX primitives
# ─────────────────────────────────────────────────────────────────────────────

def rol(x, bits, n):
    bits %= n
    return ((x << bits) | (x >> (n - bits))) & ((1 << n) - 1)

def fscx(A, B, n):
    s = A ^ B
    return s ^ rol(s, 1, n) ^ rol(s, n - 1, n)

def fscx_revolve(A, B, steps, n):
    for _ in range(steps):
        A = fscx(A, B, n)
    return A


# ─────────────────────────────────────────────────────────────────────────────
# Chunk helpers
# ─────────────────────────────────────────────────────────────────────────────

CHUNKS = 4

def split_chunks(B_large, n):
    """Split 4n-bit B into [B1, B2, B3, B4], each n bits (MSB first)."""
    mask = (1 << n) - 1
    return [(B_large >> ((CHUNKS - 1 - i) * n)) & mask for i in range(CHUNKS)]

def join_chunks(chunks, n):
    result = 0
    for c in chunks:
        result = (result << n) | (c & ((1 << n) - 1))
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Five convolution strategies (A = n-bit, B = 4n-bit)
# ─────────────────────────────────────────────────────────────────────────────

def s1_sequential(A, B_large, r, n):
    """S1: chain fscx_revolve(t, Bᵢ, r) with successive bases. Output: n-bit."""
    t = A
    for Bi in split_chunks(B_large, n):
        t = fscx_revolve(t, Bi, r, n)
    return t

def s2_bfold(A, B_large, r, n):
    """S2: fold B2,B3,B4 into state, keep B1 as fixed base. Output: n-bit."""
    B1, B2, B3, B4 = split_chunks(B_large, n)
    t = fscx_revolve(A ^ B2, B1, r, n)
    t = fscx_revolve(t ^ B3, B1, r, n)
    t = fscx_revolve(t ^ B4, B1, r, n)
    return t

def s3_cascade(A, B_large, r, n):
    """S3: pair B chunks (Bᵢ into state, B_{i+1} as base). Output: n-bit."""
    B1, B2, B3, B4 = split_chunks(B_large, n)
    t = fscx_revolve(A ^ B1, B2, r, n)
    t = fscx_revolve(t ^ B3, B4, r, n)
    return t

def s4_parallel(A, B_large, r, n):
    """S4: 4 independent revolves, concatenated. Output: 4n-bit."""
    chunks = [fscx_revolve(A, Bi, r, n) for Bi in split_chunks(B_large, n)]
    return join_chunks(chunks, n)

def s5_progressive(A, B_large, r, n):
    """S5: each stage feeds back into next (A ⊕ prev output as start). Output: 4n-bit."""
    Bs = split_chunks(B_large, n)
    outputs = []
    t_prev = 0
    for Bi in Bs:
        t = fscx_revolve(A ^ t_prev, Bi, r, n)
        outputs.append(t)
        t_prev = t
    return join_chunks(outputs, n)

def s4x_xor_reduce(A, B_large, r, n):
    """S4x: XOR-reduce the parallel expansion (S4). Output: n-bit."""
    chunks = [fscx_revolve(A, Bi, r, n) for Bi in split_chunks(B_large, n)]
    result = 0
    for c in chunks:
        result ^= c
    return result


# ─────────────────────────────────────────────────────────────────────────────
# GF(2) matrix tools — for the linear algebra attack
# ─────────────────────────────────────────────────────────────────────────────

def gf2_build_matrix(linear_fn, n_in, n_out):
    """
    Build the GF(2) matrix M (n_out rows) of a linear map f: GF(2)^n_in → GF(2)^n_out.
    M[i][j] = bit i of f(e_j), where e_j = 1 << j.
    """
    M = [0] * n_out
    for j in range(n_in):
        col = linear_fn(1 << j)
        for i in range(n_out):
            if (col >> i) & 1:
                M[i] |= (1 << j)
    return M


def gf2_solve(M, b, n_rows, n_cols):
    """
    Solve M·x = b over GF(2) by Gaussian elimination.
    M is a list of n_rows integers (each n_cols bits wide).
    b is an n_rows-bit integer.
    Returns (x, rank):
      x    — one solution (free variables set to 0), or None if inconsistent.
      rank — rank of M.
    """
    mask_col = (1 << n_cols) - 1
    # Augmented: bit j of aug[i] for j<n_cols is M[i][j]; bit n_cols is b[i]
    aug = [(M[i] & mask_col) | (((b >> i) & 1) << n_cols) for i in range(n_rows)]

    pivot_row = 0
    pivot_cols = []

    for col in range(n_cols):
        # Find pivot in this column
        found = None
        for row in range(pivot_row, n_rows):
            if (aug[row] >> col) & 1:
                found = row
                break
        if found is None:
            continue
        aug[pivot_row], aug[found] = aug[found], aug[pivot_row]
        pivot_cols.append((pivot_row, col))
        for row in range(n_rows):
            if row != pivot_row and (aug[row] >> col) & 1:
                aug[row] ^= aug[pivot_row]
        pivot_row += 1

    rank = pivot_row

    # Consistency check: remaining rows must have b-bit = 0
    for row in range(pivot_row, n_rows):
        if (aug[row] >> n_cols) & 1:
            return None, rank  # Inconsistent — no solution

    # Extract solution (free variables = 0)
    x = 0
    for (pr, col) in pivot_cols:
        if (aug[pr] >> n_cols) & 1:
            x |= (1 << col)
    return x, rank


# ─────────────────────────────────────────────────────────────────────────────
# GF(2^n) arithmetic (for hybrid / non-linear variants)
# ─────────────────────────────────────────────────────────────────────────────

GF_POLY = {8: 0x1B, 16: 0x002B, 32: 0x00400007, 64: 0x0000001B}
GF_GEN  = 3

def gf_mul(a, b, poly, n):
    result = 0; mask = (1 << n) - 1; hb = 1 << (n - 1)
    for _ in range(n):
        if b & 1: result ^= a
        carry = bool(a & hb)
        a = (a << 1) & mask
        if carry: a ^= poly
        b >>= 1
    return result

def gf_pow(base, exp, poly, n):
    result = 1; base &= (1 << n) - 1
    while exp:
        if exp & 1: result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


# ═════════════════════════════════════════════════════════════════════════════
# PART I — Algebraic forms of all strategies
# ═════════════════════════════════════════════════════════════════════════════

def run_part_I(n=32):
    section("PART I — Algebraic Forms of All Strategies")
    r = n // 4

    print(f"""
  Notation: M = I⊕ROL(1)⊕ROR(1),  R = M^r,  K = M + M² + … + M^r.
  fscx_revolve(X, B, r) = R·X ⊕ K·B   [affine in X; linear in B]

  For n={n}, r={r} (= n/4):
    R⁴ = M^{4*r} = M^{(4*r)%n} = {'I (identity)' if (4*r)%n==0 else f'M^{(4*r)%n}'}

  S1  Sequential-B (n-bit output):
    t₁ = R·A ⊕ K·B1
    t₂ = R·t₁ ⊕ K·B2 = R²·A ⊕ R·K·B1 ⊕ K·B2
    t₃ = R³·A ⊕ R²·K·B1 ⊕ R·K·B2 ⊕ K·B3
    C  = R⁴·A ⊕ K·(R³·B1 ⊕ R²·B2 ⊕ R·B3 ⊕ B4)
    R⁴ = I  →  C = A ⊕ (B-only function)   [A uniquely recoverable: A = C ⊕ B-term]

  S2  B-fold (n-bit output):
    t₁ = R·(A⊕B2) ⊕ K·B1 = R·A ⊕ R·B2 ⊕ K·B1
    t₂ = R·t₁ ⊕ R·B3 ⊕ K·B1 = R²·A ⊕ R²·B2 ⊕ (R+I)·K·B1 ⊕ R·B3
    C  = R³·A ⊕ (B-only function)           [A uniquely recoverable via (R³)⁻¹]

  S3  B-cascade (n-bit output):
    t₁ = R·(A⊕B1) ⊕ K·B2 = R·A ⊕ R·B1 ⊕ K·B2
    C  = R·t₁ ⊕ R·B3 ⊕ K·B4 = R²·A ⊕ (B-only function)
    R² = M^{(2*r)%n}  →  A recoverable via (R²)⁻¹

  S4  Parallel-expand (4n-bit output):
    Cᵢ = R·A ⊕ K·Bᵢ  for i=1..4           [same A-coefficient in every component!]
    C  = C1‖C2‖C3‖C4   →  4n-bit output
    Given any single Cᵢ and Bᵢ: A = R⁻¹·(Cᵢ ⊕ K·Bᵢ)   [A uniquely recoverable]
    Eve needs only C1 (first 256 bits of C) — rest of C is redundant.

  S5  Progressive (4n-bit output):
    t₁ = R·A ⊕ K·B1
    t₂ = R·(A⊕t₁) ⊕ K·B2 = (R+R²)·A ⊕ R·K·B1 ⊕ K·B2
    t₃ = R·(A⊕t₂) ⊕ K·B3 = (R+R+R³)·A ⊕ … = (R³)·A ⊕ … [R⊕R cancels]
                             = R³·A ⊕ (B-only)             [for r=n/4: R³ = M^{{3n/4}}]
    t₄ = (R⊕R⁴)·A ⊕ … = (R⊕I)·A ⊕ (B-only)
    Each component linear in A; combined system overdetermined (same conclusion).

  S4x XOR-reduce (n-bit output):
    C = C1⊕C2⊕C3⊕C4 = (R·A⊕K·B1)⊕(R·A⊕K·B2)⊕(R·A⊕K·B3)⊕(R·A⊕K·B4)
      = 4·R·A ⊕ K·(B1⊕B2⊕B3⊕B4)
    Over GF(2): 4·R·A = R·A ⊕ R·A ⊕ R·A ⊕ R·A = 0  [each bit XOR'd 4 times = 0]
    → C = K·(B1⊕B2⊕B3⊕B4)   INDEPENDENT OF A!

  Note on sign of the problem (both roles compared):
    A private, B public:  A uniquely recoverable (n-bit unique preimage)     ← WORSE
    B private, A public:  2^(3n) preimages of B (same as large-A analysis)  ← same
    """)


# ═════════════════════════════════════════════════════════════════════════════
# PART II — Linearity and unique A-recovery for n-bit output (S1–S3)
# ═════════════════════════════════════════════════════════════════════════════

def run_part_II(n=32, trials=2000):
    section("PART II — Linearity and A-recovery for n-bit Output (S1–S3)")
    r = n // 4

    print(f"  Each strategy has the form f_B(A) = M_B·A ⊕ c_B (affine in A).")
    print(f"  The pure linear part is f_lin(a) = f_B(a) ⊕ f_B(0)  (strips constant c_B).")
    print(f"  Affine test: f_B(A⊕A') = f_B(A) ⊕ f_B(A') ⊕ f_B(0)  (0 violations = affine).")
    print()

    strategies = [
        ("S1 Sequential-B", s1_sequential),
        ("S2 B-fold",        s2_bfold),
        ("S3 B-cascade",     s3_cascade),
    ]

    for name, fn in strategies:
        # Affine linearity test: f(A⊕A') = f(A) ⊕ f(A') ⊕ f(0)
        aff_viol = 0
        for _ in range(trials):
            A  = secrets.randbits(n)
            Ap = secrets.randbits(n)
            B  = secrets.randbits(4 * n)
            lhs = fn(A ^ Ap, B, r, n)
            rhs = fn(A, B, r, n) ^ fn(Ap, B, r, n) ^ fn(0, B, r, n)
            if lhs != rhs:
                aff_viol += 1
        aff_status = "affine-linear in A [PASS]" if aff_viol == 0 else f"NOT affine ({aff_viol} viol)"

        # Injectivity: f_B(A) = f_B(A') → A = A'?
        # The pure linear part M_B = f_B(a) ⊕ c_B determines injectivity.
        # Check by testing if two distinct A values collide (prob 1/2^n if injective).
        inject_viol = 0
        for _ in range(min(trials, 500)):
            A  = secrets.randbits(n)
            Ap = secrets.randbits(n)
            B  = secrets.randbits(4 * n)
            if A != Ap and fn(A, B, r, n) == fn(Ap, B, r, n):
                inject_viol += 1
        inject_status = "injective (distinct A → distinct C)" if inject_viol == 0 else f"NOT injective ({inject_viol} collisions)"

        print(f"  {name}:")
        print(f"    Affine-linearity: {aff_status}")
        print(f"    Injectivity    : {inject_status}")
        print()


# ═════════════════════════════════════════════════════════════════════════════
# PART III — Full GF(2) matrix attack: recover A uniquely
# ═════════════════════════════════════════════════════════════════════════════

def run_part_III(n_small=16, trials=500):
    section("PART III — GF(2) Matrix Attack: Recover A Uniquely")

    # Use n_small for full matrix inversion demo; note it scales to n=256 trivially
    n = n_small
    r = n // 4

    print(f"""
  For any n-bit output strategy, the map A ↦ f_B(A) is a GF(2)-linear map
  from GF(2)^n → GF(2)^n (square matrix for fixed B, r).

  Attack: build the n×n GF(2) matrix of f_B, solve M·A = C by row reduction.
  Complexity: O(n³) bit operations.  For n={n} (demo): {n}³ = {n**3} ops (trivial).
  For n=256: 256³ ≈ 16M bit operations — still feasible for Eve.

  Demonstration (n={n}):
    """)

    strategies = [
        ("S1 Sequential-B", s1_sequential),
        ("S2 B-fold",        s2_bfold),
        ("S3 B-cascade",     s3_cascade),
    ]

    for name, fn in strategies:
        ok = 0; rank_sum = 0; singular_count = 0
        for _ in range(trials):
            A_real = secrets.randbits(n)
            B      = secrets.randbits(4 * n)
            C      = fn(A_real, B, r, n)
            c_B    = fn(0, B, r, n)           # affine constant (B-dependent)

            # Build matrix of the PURE LINEAR part: f_lin(a) = fn(a,B,r,n) ⊕ c_B
            def f_lin(a, B=B, r=r, n=n, fn=fn, c_B=c_B):
                return fn(a, B, r, n) ^ c_B

            M_mat = gf2_build_matrix(f_lin, n, n)

            # Check rank
            _, rank = gf2_solve(M_mat, 0, n, n)
            rank_sum += rank
            if rank < n:
                singular_count += 1
                continue

            # Solve M·A = C ⊕ c_B  (strip constant, solve for A)
            A_found, _ = gf2_solve(M_mat, C ^ c_B, n, n)
            if A_found is not None and fn(A_found, B, r, n) == C:
                ok += 1

        avg_rank = rank_sum / trials
        print(f"  {name} (n={n}, r={r}):")
        print(f"    Average matrix rank: {avg_rank:.1f}/{n}")
        print(f"    Singular matrices: {singular_count}/{trials}")
        if singular_count < trials:
            recovered = ok
            total_ns = trials - singular_count
            print(f"    A recovered correctly: {recovered}/{total_ns} (non-singular cases)")
            if recovered == total_ns:
                print(f"    → FULL BREAK: A uniquely recovered in every trial (O(n³) ops).")
            else:
                print(f"    → PARTIAL: {recovered}/{total_ns}.")
        print()

    print(f"""
  Contrast with large-A analysis (hkex_cfscx_compress.py):
    Large A (4n→n): A had 2^(3n) preimages; trivial period attack found ONE.
    Large B (n→n):  A has UNIQUE preimage; O(n³) matrix attack recovers IT.
    The large-B case is STRICTLY WORSE for security: Eve recovers Alice's
    exact private key, not just some valid preimage.
    """)


# ═════════════════════════════════════════════════════════════════════════════
# PART IV — 4n-bit output strategies (S4, S5): overdetermined
# ═════════════════════════════════════════════════════════════════════════════

def run_part_IV(n=32, trials=500):
    section("PART IV — 4n-bit Output Strategies (S4 Parallel, S5 Progressive)")
    r = n // 4

    print(f"""
  S4 (parallel): C = C1‖C2‖C3‖C4 where each Cᵢ = fscx_r(A, Bᵢ, r).
  System:  M·A = Cᵢ ⊕ K·Bᵢ  for each i.
  Each Cᵢ gives an INDEPENDENT linear equation for A.
  All four equations share the SAME solution A (overdetermined, consistent).
  Eve needs only C1 (first n bits of C) → A = R⁻¹·(C1 ⊕ K·B1).

  S5 (progressive): Cᵢ have different A-linear coefficients (R, R+R², R³, R⊕I).
  Still overdetermined; C1 alone gives A = R⁻¹·(C1 ⊕ K·B1) — same cost.
  The extra 3n-bit output adds no security.

  [IV-A] S4 attack: recover A from first n-bit chunk of C  ({trials} trials, n={n}):
    """)

    # For S4, Eve uses only C1 = fscx_revolve(A, B1, r) to recover A
    def s4_attack(C_large, B_large, r, n):
        """Eve: from C = S4-output and B, recover A using only C1."""
        C1 = C_large >> (3 * n)   # top n bits of 4n-bit C
        B1 = B_large >> (3 * n)   # top n bits of 4n-bit B (= B1 chunk)
        c_B1 = fscx_revolve(0, B1, r, n)   # affine constant
        def f_lin(a):
            return fscx_revolve(a, B1, r, n) ^ c_B1
        M = gf2_build_matrix(f_lin, n, n)
        A_found, _ = gf2_solve(M, C1 ^ c_B1, n, n)
        return A_found

    ok4 = 0
    for _ in range(trials):
        A  = secrets.randbits(n)
        B  = secrets.randbits(4 * n)
        C  = s4_parallel(A, B, r, n)
        A_found = s4_attack(C, B, r, n)
        if A_found is not None and A_found == A:
            ok4 += 1

    st = "[FULL BREAK]" if ok4 == trials else f"[partial: {ok4}/{trials}]"
    print(f"  S4 A recovered: {ok4}/{trials}  {st}")
    print(f"  Eve used only the first {n} of {4*n} output bits — the rest add no security.")

    print(f"\n  [IV-B] S5 attack: same approach using only t₁ = fscx_r(A, B1, r)  ({trials} trials):")
    def s5_attack(C_large, B_large, r, n):
        """Eve: from C = S5-output, use first chunk t1 = fscx_r(A, B1, r)."""
        C1 = C_large >> (3 * n)
        B1 = B_large >> (3 * n)
        c_B1 = fscx_revolve(0, B1, r, n)
        def f_lin(a):
            return fscx_revolve(a, B1, r, n) ^ c_B1
        M = gf2_build_matrix(f_lin, n, n)
        A_found, _ = gf2_solve(M, C1 ^ c_B1, n, n)
        return A_found

    ok5 = 0
    for _ in range(trials):
        A = secrets.randbits(n)
        B = secrets.randbits(4 * n)
        C = s5_progressive(A, B, r, n)
        A_found = s5_attack(C, B, r, n)
        if A_found is not None and A_found == A:
            ok5 += 1
    st = "[FULL BREAK]" if ok5 == trials else f"[partial: {ok5}/{trials}]"
    print(f"  S5 A recovered: {ok5}/{trials}  {st}")
    print(f"  Extra output (1024-bit vs 256-bit) provides zero additional security.")


# ═════════════════════════════════════════════════════════════════════════════
# PART V — S4x degenerate: A cancellation in XOR-reduce
# ═════════════════════════════════════════════════════════════════════════════

def run_part_V(n=32, trials=2000):
    section("PART V — S4x Degenerate: A Cancellation in XOR-Reduce")
    r = n // 4

    print(f"""
  S4x: C = fscx_r(A,B1) ⊕ fscx_r(A,B2) ⊕ fscx_r(A,B3) ⊕ fscx_r(A,B4)
         = (R·A⊕K·B1) ⊕ (R·A⊕K·B2) ⊕ (R·A⊕K·B3) ⊕ (R·A⊕K·B4)
         = 4·R·A  ⊕  K·(B1⊕B2⊕B3⊕B4)
         = 0      ⊕  K·(B1⊕B2⊕B3⊕B4)   [over GF(2): 4 copies cancel]
         = K·(B_xor)   where B_xor = B1⊕B2⊕B3⊕B4

  C is INDEPENDENT OF A — A has zero influence on the output.
    """)

    # Verify: changing A does not change C
    independent_count = 0
    for _ in range(trials):
        A1 = secrets.randbits(n)
        A2 = secrets.randbits(n)
        B  = secrets.randbits(4 * n)
        C1 = s4x_xor_reduce(A1, B, r, n)
        C2 = s4x_xor_reduce(A2, B, r, n)
        if C1 == C2:
            independent_count += 1

    print(f"  [V-A] Independence of C from A ({trials} random (A1, A2, B) pairs):")
    print(f"  C(A1, B) == C(A2, B): {independent_count}/{trials}", end="  ")
    if independent_count == trials:
        print("[A has NO effect on output — confirmed]")
    else:
        print(f"[unexpected: {trials - independent_count} pairs differ]")

    # Verify: C depends only on XOR of B chunks
    xor_dep_ok = 0
    for _ in range(trials):
        A   = secrets.randbits(n)
        B   = secrets.randbits(4 * n)
        B1, B2, B3, B4 = split_chunks(B, n)
        B_xor = B1 ^ B2 ^ B3 ^ B4
        C_out = s4x_xor_reduce(A, B, r, n)
        # C should equal fscx_revolve(0, B_xor, r) ... actually K·B_xor ≠ fscx_revolve
        # It equals (M+M²+...+M^r)·B_xor.  Verify C = XOR-reduce with any A:
        A2 = secrets.randbits(n)
        C2 = s4x_xor_reduce(A2, B, r, n)
        if C_out == C2:
            xor_dep_ok += 1

    print(f"  C(A1, B) == C(A2, B) for same B: {xor_dep_ok}/{trials}  [confirmed B-only dependency]")

    # Generalization: even k parallel revolves cancel A, odd k preserve it
    print(f"\n  [V-B] Cancellation depends on parity of parallel count:")
    for k in range(1, 6):
        cancel_count = 0
        for _ in range(500):
            A1 = secrets.randbits(n)
            A2 = secrets.randbits(n)
            B  = secrets.randbits(4 * n)
            Bs = split_chunks(B, n)[:k] + [0] * max(0, k - 4)   # pad with 0 if k > 4
            # Use first min(k, 4) B chunks; for k > 4 repeat
            Bs_k = [split_chunks(B, n)[i % 4] for i in range(k)]
            C1 = 0
            for Bi in Bs_k:
                C1 ^= fscx_revolve(A1, Bi, r, n)
            C2 = 0
            for Bi in Bs_k:
                C2 ^= fscx_revolve(A2, Bi, r, n)
            if C1 == C2:
                cancel_count += 1
        parity = "even" if k % 2 == 0 else "odd"
        expectation = "A cancels" if k % 2 == 0 else "A preserved"
        print(f"    k={k} ({parity:4s}): C(A1)==C(A2) in {cancel_count}/500  → {expectation}")

    print(f"""
  Key insight: parallel XOR-reduce works as a PARITY FILTER on the A contribution.
  Even k: A cancels → C is independent of A (useless as a commitment/trapdoor).
  Odd k:  A survives → C = M^(kr mod n)·A ⊕ (B-term), uniquely recoverable.
  Neither case creates a useful trapdoor.
    """)


# ═════════════════════════════════════════════════════════════════════════════
# PART VI — Role swap: B private, A public generator
# ═════════════════════════════════════════════════════════════════════════════

def run_part_VI(n=32, trials=500):
    section("PART VI — Role Swap: B = Private Key, A = Public Generator")
    r = n // 4

    print(f"""
  Previous analysis (Parts II–V) treated A as the private key.
  Now consider B (4n-bit) as the private key and A as a public generator.

  S1 role-swap:
    C = R⁴·A ⊕ K·(R³·B1 ⊕ R²·B2 ⊕ R·B3 ⊕ B4)
      = A ⊕ G(B)   where G: GF(2)^[4n] → GF(2)^[n] is linear (underdetermined).

  G maps 4n bits → n bits: 2^(3n) preimages per output — same as large-A analysis.
  Eve needs to find ANY B' such that G(B') = C ⊕ A.

  Period attack for S1, B-private:
    Set B1=B2=B3=0; need K·B4 = C ⊕ A.
    With B1=B2=B3=0:
      C = fscx_revolve(M^(3r)·A, B4, r) = R·(R³·A) ⊕ K·B4 = R⁴·A ⊕ K·B4 = A ⊕ K·B4
    So K·B4 = C ⊕ A.
    K = M + M² + … + M^r is a linear map.  Build its GF(2) matrix and solve.

  [VI-A] B-recovery (period + linear algebra, setting B1=B2=B3=0)  ({trials} trials):
    """)

    def recover_B4_from_s1(A, C, r, n):
        """Find B4 s.t. s1_sequential(A, (0,0,0,B4), r) = C, by solving K·B4 = C ⊕ A."""
        # K·B4 = C ⊕ A.  K = linear map that appears in fscx_revolve(0, B4, r) = K·B4.
        # fscx_revolve(0, B4, r) = K·B4  [since R·0 = 0]
        def K_map(b4):
            return fscx_revolve(0, b4, r, n)
        M = gf2_build_matrix(K_map, n, n)
        rhs = C ^ A   # since C = A ⊕ K·B4, need K·B4 = C ⊕ A
        B4_found, rank = gf2_solve(M, rhs, n, n)
        return B4_found, rank

    ok = 0
    rank_total = 0
    for _ in range(trials):
        A  = secrets.randbits(n)
        B  = secrets.randbits(4 * n)   # Alice's full 4n-bit private key
        C  = s1_sequential(A, B, r, n)

        # Eve recovers a VALID B' (not necessarily Alice's B, but maps to same C)
        B4_found, rank = recover_B4_from_s1(A, C, r, n)
        rank_total += rank
        if B4_found is not None:
            B_prime = join_chunks([0, 0, 0, B4_found], n)
            if s1_sequential(A, B_prime, r, n) == C:
                ok += 1

    avg_rank = rank_total / trials
    print(f"  Eve found valid B' with s1(A, B', r) = C: {ok}/{trials}")
    print(f"  Average K matrix rank: {avg_rank:.1f}/{n}")
    print()
    if ok == trials:
        print(f"  → BREAK: Eve finds a valid B' = (0, 0, 0, B4) in O(n³) ops.")
    print(f"  → Note: Eve's B' ≠ Alice's B (2^{3*n} preimages), but she achieves the")
    print(f"    same C (same public value, same shared secret if used in a protocol).")

    # DH commutativity test for role-swap HKEX
    print(f"\n  [VI-B] DH commutativity (B private, A public generator)  ({trials} trials):")
    print(f"         Alice: (B_A, C_A = s1(g, B_A, r));  Bob: (B_B, C_B = s1(g, B_B, r))")
    print(f"         sk_A = s1(C_B, B_A, r);  sk_B = s1(C_A, B_B, r).  sk_A == sk_B?")
    g_val = GF_GEN
    comm = 0
    for _ in range(trials):
        B_A = secrets.randbits(4 * n)
        B_B = secrets.randbits(4 * n)
        C_A = s1_sequential(g_val, B_A, r, n)
        C_B = s1_sequential(g_val, B_B, r, n)
        sk_A = s1_sequential(C_B, B_A, r, n)
        sk_B = s1_sequential(C_A, B_B, r, n)
        if sk_A == sk_B:
            comm += 1
    print(f"  sk_A == sk_B: {comm}/{trials}")
    if comm == trials:
        print(f"""
  → ALWAYS COMMUTATIVE!  Algebraic reason:
    S1 with r = n/4: R⁴ = M^n = I, so s1(X, B, r) = X ⊕ G(B) for linear G.
    sk_A = C_B ⊕ G(B_A) = (g ⊕ G(B_B)) ⊕ G(B_A) = g ⊕ G(B_A) ⊕ G(B_B)
    sk_B = C_A ⊕ G(B_B) = (g ⊕ G(B_A)) ⊕ G(B_B) = g ⊕ G(B_A) ⊕ G(B_B)
    → sk_A = sk_B = g ⊕ G(B_A) ⊕ G(B_B)  for ALL B_A, B_B  [XOR commutativity]

  → BUT Eve computes sk directly:
    G(B_A) = C_A ⊕ g   (from public C_A and known g)
    G(B_B) = C_B ⊕ g
    sk     = g ⊕ (C_A ⊕ g) ⊕ (C_B ⊕ g) = C_A ⊕ C_B ⊕ g  ← PUBLIC VALUES ONLY!

  This is Theorem 10 (SecurityProofs.md) in direct action:
    Correctness (commutativity) ⟹ sk is a linear function of wire values.
    Linear FSCX + commutativity is ALWAYS broken.
    """)

    print(f"  [VI-C] Eve's linear break: sk_eve = C_A ⊕ C_B ⊕ g  ({trials} trials):")
    eve_hits = 0
    for _ in range(trials):
        B_A = secrets.randbits(4 * n)
        B_B = secrets.randbits(4 * n)
        C_A = s1_sequential(g_val, B_A, r, n)
        C_B = s1_sequential(g_val, B_B, r, n)
        sk_real = s1_sequential(C_B, B_A, r, n)
        sk_eve  = C_A ^ C_B ^ g_val             # Eve's formula
        if sk_eve == sk_real:
            eve_hits += 1
    st_eve = "[FULL BREAK]" if eve_hits == trials else f"[{eve_hits}/{trials}]"
    print(f"  Eve recovered sk: {eve_hits}/{trials}  {st_eve}")


# ═════════════════════════════════════════════════════════════════════════════
# PART VII — Non-linear GF-injection variant
# ═════════════════════════════════════════════════════════════════════════════

def run_part_VII(n=32, trials=1000):
    section("PART VII — GF-Injection: Joint Non-Linearity, but Linear in A for Fixed B")
    r = n // 4

    # GF poly chosen for the current n
    def s1_gf(A, B_large, r, n):
        poly_n = GF_POLY.get(n, GF_POLY[32])
        B1, B2, B3, B4 = split_chunks(B_large, n)
        t = fscx_revolve(A, B1, r, n)
        t = fscx_revolve(gf_mul(t, B2, poly_n, n), B3, r, n)
        return fscx_revolve(gf_mul(t, B4, poly_n, n), B1, r, n)

    def s3_gf(A, B_large, r, n):
        poly_n = GF_POLY.get(n, GF_POLY[32])
        B1, B2, B3, B4 = split_chunks(B_large, n)
        t = fscx_revolve(A ^ B1, B2, r, n)
        return fscx_revolve(gf_mul(t, B3, poly_n, n), B4, r, n)

    print(f"""
  Hypothesis: replacing XOR-folding in S1/S3 with GF(2^n) multiplication
  should introduce non-linearity in A and break the matrix attack.

  S1-GF: t₁=fscx_r(A,B1,r); t₂=fscx_r(gf_mul(t₁,B2),B3,r); C=fscx_r(gf_mul(t₂,B4),B1,r)
  S3-GF: t=fscx_r(A^B1,B2,r); C=fscx_r(gf_mul(t,B3),B4,r)

  Key algebraic observation:
    gf_mul(·, Bᵢ) for FIXED Bᵢ is a GF(2)-LINEAR map over GF(2)^n
    (multiplication by a constant element is a linear endomorphism of the field).
    Therefore composing it with fscx_revolve (also linear in its first arg)
    preserves linearity in A for FIXED B.
    Non-linearity exists JOINTLY in (A, B), not in A alone with B fixed.
    """)

    variants = [("S1-GF", s1_gf), ("S3-GF", s3_gf)]

    for name, fn in variants:
        # [VII-a] Affine linearity test (correct test for fixed B)
        aff_viol = 0
        for _ in range(trials):
            A  = secrets.randbits(n)
            Ap = secrets.randbits(n)
            B  = secrets.randbits(4 * n)
            lhs = fn(A ^ Ap, B, r, n)
            rhs = fn(A, B, r, n) ^ fn(Ap, B, r, n) ^ fn(0, B, r, n)
            if lhs != rhs:
                aff_viol += 1

        # [VII-b] Joint (A,B) non-linearity: vary B while A is fixed
        joint_viol = 0
        for _ in range(trials):
            A   = secrets.randbits(n)
            B   = secrets.randbits(4 * n)
            Bp  = secrets.randbits(4 * n)
            # If fn were linear in B for fixed A:
            # fn(A, B^B') = fn(A,B) ^ fn(A,B') ^ fn(A,0)
            lhs_b = fn(A, B ^ Bp, r, n)
            rhs_b = fn(A, B, r, n) ^ fn(A, Bp, r, n) ^ fn(A, 0, r, n)
            if lhs_b != rhs_b:
                joint_viol += 1

        print(f"  {name}:")
        aff_st = "AFFINE in A for fixed B  [PASS — same as linear strategies]" if aff_viol == 0 else f"NOT affine ({aff_viol} violations)"
        print(f"    Affine linearity in A (fixed B): {aff_viol}/{trials} viol  → {aff_st}")
        b_st = "NON-LINEAR in B (joint non-linearity confirmed)" if joint_viol > 0 else "linear in B too"
        print(f"    Linearity in B (fixed A):         {joint_viol}/{trials} viol  → {b_st}")

        # [VII-c] GF(2) matrix attack with correct poly
        ok = 0; sing = 0
        atk_trials = min(trials, 500)
        for _ in range(atk_trials):
            A_real = secrets.randbits(n)
            B      = secrets.randbits(4 * n)
            C      = fn(A_real, B, r, n)
            c_B    = fn(0, B, r, n)
            def f_lin(a, B=B, fn=fn, c_B=c_B):
                return fn(a, B, r, n) ^ c_B
            M_mat = gf2_build_matrix(f_lin, n, n)
            A_found, rank = gf2_solve(M_mat, C ^ c_B, n, n)
            if rank < n:
                sing += 1
            elif A_found is not None and fn(A_found, B, r, n) == C:
                ok += 1
        ns = atk_trials - sing
        atk_st = "[FULL BREAK]" if ok == ns and sing == 0 else f"[{ok}/{ns} non-singular]"
        print(f"    Matrix attack A-recovery: {ok}/{ns}  {atk_st}")

        # [VII-d] DH commutativity (B-private role: sk = fn(C_B, B_A) == fn(C_A, B_B)?)
        comm = 0
        gv = GF_GEN
        for _ in range(min(trials, 500)):
            B_A = secrets.randbits(4 * n)
            B_B = secrets.randbits(4 * n)
            C_A = fn(gv, B_A, r, n)
            C_B = fn(gv, B_B, r, n)
            sk_A = fn(C_B, B_A, r, n)
            sk_B = fn(C_A, B_B, r, n)
            if sk_A == sk_B:
                comm += 1
        comm_st = "[ALWAYS COMMUTATIVE — Eve has linear formula]" if comm == min(trials, 500) else (f"[NO commutativity]" if comm == 0 else f"[{comm} matches]")
        print(f"    DH commutativity (B-private): {comm}/{min(trials,500)}  {comm_st}")
        print()

    print(f"""
  Key finding:
    GF-multiplication by a FIXED element is GF(2)-linear, so S1-GF and S3-GF
    remain AFFINE in A for any fixed B (0 affine violations confirmed).
    The joint non-linearity in (A,B) is irrelevant when B is public: Eve knows
    B and can build the correct linear map via basis-vector evaluation,
    recovering A in O(n³) ops exactly as for S1, S2, S3.

  Theorem 10 still applies:
    S1-GF with r=n/4 gives R⁴=I, so fn(X, B, r) = X ⊕ G_GF(B) for some G_GF.
    DH commutativity follows: sk = fn(C_B, B_A) = C_B ⊕ G_GF(B_A) = g ⊕ G_GF(B_B) ⊕ G_GF(B_A).
    Eve computes: sk = C_A ⊕ C_B ⊕ g  ← public values only.
    (The GF-mul changes G's structure but NOT the commutativity/break pattern.)
    """)


# ═════════════════════════════════════════════════════════════════════════════
# PART VIII — Summary
# ═════════════════════════════════════════════════════════════════════════════

def run_summary():
    section("PART VIII — Summary")
    print("""
  Settings: A = n-bit (short), B = 4n-bit (long), r = n/4.

  ┌──────────────────┬────────┬────────────────────────────┬───────────────────┐
  │ Strategy         │ C size │ A-preimage hardness         │ DH comm.          │
  ├──────────────────┼────────┼────────────────────────────┼───────────────────┤
  │ S1 Sequential-B  │  n     │ UNIQUE — O(n³) matrix atk  │ FAILS             │
  │ S2 B-fold        │  n     │ UNIQUE — O(n³) matrix atk  │ FAILS             │
  │ S3 B-cascade     │  n     │ UNIQUE — O(n³) matrix atk  │ FAILS             │
  │ S4 Parallel      │  4n    │ UNIQUE — Eve uses first n   │ FAILS             │
  │                  │        │ bits of C only             │                   │
  │ S5 Progressive   │  4n    │ UNIQUE — same as S4        │ FAILS             │
  │ S4x XOR-reduce   │  n     │ ZERO — A cancels entirely  │ N/A               │
  ├──────────────────┼────────┼────────────────────────────┼───────────────────┤
  │ S1-GF (non-lin)  │  n     │ UNIQUE (matrix attack works│ FAILS             │
  │                  │        │  even for non-linear maps) │                   │
  │ S3-GF (non-lin)  │  n     │ UNIQUE (same)              │ FAILS             │
  ├──────────────────┼────────┼────────────────────────────┼───────────────────┤
  │ B-private swap   │  n     │ 2^(3n) preimages of B;     │ FAILS             │
  │  (S1, B secret)  │        │ ONE found via O(n³) linalg │                   │
  └──────────────────┴────────┴────────────────────────────┴───────────────────┘

  Comparison with large-A (hkex_cfscx_compress.py):
  ┌──────────────────┬────────────────────────────┬────────────────────────────┐
  │                  │ Large A (4n→n), B fixed     │ Large B (n→4n→n), A fixed  │
  ├──────────────────┼────────────────────────────┼────────────────────────────┤
  │ Preimage count   │ 2^(3n) — underdetermined   │ 1 — square/invertible map  │
  │ Eve's attack     │ O(n) period trick (trivial) │ O(n³) matrix inversion     │
  │ Eve recovers     │ Some valid A' ≠ Alice's A  │ Alice's EXACT private A    │
  │ Security verdict │ BROKEN (trivially)          │ STRICTLY WORSE             │
  └──────────────────┴────────────────────────────┴────────────────────────────┘

  New findings specific to large-B:
    1. The n-bit output square map (n→n) is typically INVERTIBLE over GF(2),
       so Alice's exact private key A is uniquely recovered — not just a preimage.
    2. The 4n-bit expansion (n→4n) gives Eve REDUNDANT equations; she needs only
       one n-bit component.  Larger output strictly benefits Eve (more info).
    3. XOR-reduce of even-k parallel revolves cancels A ENTIRELY, producing an
       output independent of A.  An even-k expansion cannot bind A to C at all.
    4. Even non-linear GF-injection variants (S1-GF, S3-GF) do NOT protect A
       when the output is n-bit: a black-box GF(2) matrix evaluation attack
       recovers A in O(n³) ops regardless of the non-linearity structure.

  Fundamental constraint:
    For a square output (output ≈ input size), the compression factor is 1:
    there is no information loss, and the linear-algebraic inverse exists.
    For a truly hard trapdoor, the DLP in gf_pow is still the only known
    mechanism that is both easy in one direction and hard to invert.
""")


# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(DIVIDER)
    print("  hkex_cfscx_blong.py — Large B, Short A: Convolution Analysis")
    print(DIVIDER)

    N = 32   # main demo size
    run_part_I(N)
    run_part_II(N)
    run_part_III(n_small=16)      # GF(2) matrix attack (full inversion, n=16)
    run_part_IV(N)
    run_part_V(N)
    run_part_VI(N)
    run_part_VII(N)
    run_summary()

    sys.exit(0)
