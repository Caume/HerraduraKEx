"""
hkex_cfscx_preshared.py — Preshared-Value Constructions: Security Analysis

Settings: Alice and Bob preshare a secret value S (n-bit) before the exchange.
          Private keys a (Alice) and b (Bob) are independently chosen per-session.
          S is used to expand the effective bitlength or as an alternative generator.

Five constructions, from weakest to strongest:

  PS-1  S-base fscx          C_A = fscx_revolve(a, S, r)
                              sk  = fscx_revolve(C_A ⊕ C_B, S, r)  [symmetric]

  PS-2  S-expanded 4-chunk   A_4n = a ‖ S ‖ (a⊕S) ‖ combo
                              C_A  = cfscx_compress(A_4n, g, r)  [g = GF generator]
                              sk   = fscx_revolve(C_A ⊕ C_B, S, r)

  PS-3  S as DH generator    C_A = gf_pow(S, a, poly, n)   [DH with S as base]
                              sk  = gf_pow(C_B, a, poly, n) = S^{ab}

  PS-4  Layered cfscx KDF    a_scl= cfscx_compress(a ‖ S ‖ a⊕S ‖ combo, g, r)
                              C_A  = gf_pow(g, a_scl, poly, n)
                              sk   = gf_pow(C_B, a_scl, poly, n) = g^{a_scl·b_scl}

  PS-5  Non-linear int expand A_4n = a ‖ S ‖ ((a+S) mod 2^n) ‖ ((a·S) mod 2^n)
                              C_A  = cfscx_compress(A_4n, g, r)
                              sk   = cfscx_compress(A_4n, C_B, r)  [direct sk]

Key questions:
  1. Correctness: sk_A == sk_B?
  2. Private-key binding: sk changes when only a changes (not just S-dependent)?
  3. S-necessity: sk changes when only S changes?
  4. Eve without S: can Eve compute sk from public wire values alone?
  5. Eve with S: does private key add security beyond knowing S?
  6. Is C_A derivation linear in a for fixed S? (GF(2) matrix attack)
  7. Non-linearity of integer operations: does carry injection break linearity?

Part I    — Construction definitions and algebraic characterization
Part II   — PS-1 (S-base fscx): correctness + security analysis
Part III  — PS-2 (S-expanded cfscx): correctness + linear algebra attack
Part IV   — PS-3 (S as DH generator): correctness + security + Eve analysis
Part V    — PS-4 (Layered KDF + DH): correctness + compatibility check
Part VI   — PS-5 (Non-linear integer expansion): linearity test + attack
Part VII  — Summary comparison table
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

def split_chunks(X, n):
    """Split 4n-bit X into [X1, X2, X3, X4], each n bits (MSB first)."""
    mask = (1 << n) - 1
    return [(X >> ((CHUNKS - 1 - i) * n)) & mask for i in range(CHUNKS)]

def join_chunks(chunks, n):
    result = 0
    for c in chunks:
        result = (result << n) | (c & ((1 << n) - 1))
    return result

def cfscx_compress(A_large, B, r, n):
    """Compress 4n-bit A into n-bit C using nested fscx_revolve with XOR chaining."""
    A1, A2, A3, A4 = split_chunks(A_large, n)
    t = fscx_revolve(A1,     B, r, n)
    t = fscx_revolve(t ^ A2, B, r, n)
    t = fscx_revolve(t ^ A3, B, r, n)
    return fscx_revolve(t ^ A4, B, r, n)


# ─────────────────────────────────────────────────────────────────────────────
# GF(2^n) arithmetic
# ─────────────────────────────────────────────────────────────────────────────

GF_POLY = {8: 0x1B, 16: 0x002B, 32: 0x00400007, 64: 0x0000001B}
GF_GEN  = 3   # generator g = 3 (same as suite)

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


# ─────────────────────────────────────────────────────────────────────────────
# GF(2) matrix tools — for linear algebra attack
# ─────────────────────────────────────────────────────────────────────────────

def gf2_build_matrix(linear_fn, n_in, n_out):
    """Build GF(2) matrix of linear map f: GF(2)^n_in → GF(2)^n_out."""
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
    Returns (x, rank): x = solution (free vars=0) or None if inconsistent.
    """
    mask_col = (1 << n_cols) - 1
    aug = [(M[i] & mask_col) | (((b >> i) & 1) << n_cols) for i in range(n_rows)]
    pivot_row = 0
    pivot_cols = []
    for col in range(n_cols):
        found = next((r for r in range(pivot_row, n_rows) if (aug[r] >> col) & 1), None)
        if found is None:
            continue
        aug[pivot_row], aug[found] = aug[found], aug[pivot_row]
        pivot_cols.append((pivot_row, col))
        for row in range(n_rows):
            if row != pivot_row and (aug[row] >> col) & 1:
                aug[row] ^= aug[pivot_row]
        pivot_row += 1
    rank = pivot_row
    for row in range(pivot_row, n_rows):
        if (aug[row] >> n_cols) & 1:
            return None, rank
    x = 0
    for (pr, col) in pivot_cols:
        if (aug[pr] >> n_cols) & 1:
            x |= (1 << col)
    return x, rank


# ─────────────────────────────────────────────────────────────────────────────
# Integer non-linear expansion helper
# ─────────────────────────────────────────────────────────────────────────────

def int_expand(a, S, n):
    """
    Build 4-chunk 4n-bit expansion using integer arithmetic:
      chunk1 = a
      chunk2 = S
      chunk3 = (a + S) mod 2^n   [addition with carry — non-linear in GF(2)]
      chunk4 = (a * S) mod 2^n   [multiplication with carry — non-linear in GF(2)]
    """
    mask = (1 << n) - 1
    c1 = a & mask
    c2 = S & mask
    c3 = (a + S) & mask
    c4 = (a * S) & mask
    return join_chunks([c1, c2, c3, c4], n)

def int_expand_xor(a, S, n):
    """
    4-chunk expansion using XOR (GF(2)-linear baseline for comparison):
      chunk1 = a, chunk2 = S, chunk3 = a⊕S, chunk4 = a⊕S  (all linear)
    """
    mask = (1 << n) - 1
    c1 = a & mask
    c2 = S & mask
    c3 = (a ^ S) & mask
    c4 = (a ^ S) & mask
    return join_chunks([c1, c2, c3, c4], n)


# ═════════════════════════════════════════════════════════════════════════════
# PART I — Construction definitions and algebraic characterization
# ═════════════════════════════════════════════════════════════════════════════

def run_part_I(n=32):
    section("PART I — Construction Definitions and Algebraic Characterization")
    r = n // 4
    poly = GF_POLY.get(n, GF_POLY[32])
    g = GF_GEN

    print(f"""
  Shared setup: Alice and Bob exchange preshared secret S (n={n} bits).
  Both independently choose private session keys a, b ∈ [1, 2^n).
  All wire values C_A, C_B are public. g = {g} (GF generator), r = {r}.

  Notation: M = I⊕ROL(1)⊕ROR(1),  R = M^r,  K = M+M²+…+M^r.
  fscx_revolve(X, B, r) = R·X ⊕ K·B  (affine in X for fixed B).
  For r = n/4:  R⁴ = M^n = I.

  ── PS-1  S-base fscx ───────────────────────────────────────────────────────
    C_A = fscx_revolve(a, S, r) = R·a ⊕ K·S
    C_B = fscx_revolve(b, S, r) = R·b ⊕ K·S

    sk_A = fscx_revolve(C_A ⊕ C_B, S, r)
         = R·(C_A ⊕ C_B) ⊕ K·S
         = R·(R·a ⊕ K·S ⊕ R·b ⊕ K·S) ⊕ K·S
         = R·(R·a ⊕ R·b) ⊕ K·S          [K·S ⊕ K·S = 0]
         = R²·a ⊕ R²·b ⊕ K·S

    sk_B = fscx_revolve(C_A ⊕ C_B, S, r)  [same formula — sk_A = sk_B ✓]

    Observation: sk = R²·a ⊕ R²·b ⊕ K·S = R²·(a⊕b) ⊕ K·S
    Eve simplification: C_A⊕C_B = R·a ⊕ R·b = R·(a⊕b), so
      sk = R·(C_A⊕C_B) ⊕ K·S = fscx_revolve(C_A⊕C_B, S, r)
    This is EXACTLY the ps1_sk formula — Eve with S computes sk directly.
    She does NOT need a or b individually; C_A, C_B, S are sufficient.
    Security level: S alone sufficient → SINGLE-FACTOR (S) protection only.

  ── PS-2  S-expanded cfscx ──────────────────────────────────────────────────
    A_4n = a ‖ S ‖ (a⊕S) ‖ (a⊕S)   [XOR expansion — linear in a for fixed S]
    C_A  = cfscx_compress(A_4n, g, r)
    sk   = fscx_revolve(C_A ⊕ C_B, S, r)

    Algebraic analysis (see Part III for derivation):
    Since cfscx_compress is affine in its input for fixed B,
    and A_4n = L(a) ⊕ constant(S) for linear L, the composition is:
      C_A = (affine map in a for fixed S)
    So C_A ⊕ C_B is affine in a⊕b, and sk is affine in a⊕b.
    Matrix attack recovers a from C_A in O(n³).
    Same conclusion as PS-1: S alone does not protect sk.

  ── PS-3  S as DH generator ─────────────────────────────────────────────────
    C_A = gf_pow(S, a, poly, n) = S^a  in GF(2^n)*
    C_B = gf_pow(S, b, poly, n) = S^b
    sk  = gf_pow(C_B, a, poly, n) = (S^b)^a = S^{{ab}}  = gf_pow(C_A, b, poly, n) ✓

    Eve (with S, C_A, C_B) must solve: given S^a = C_A, find a.
    This is DISCRETE LOG in GF(2^{n})*. Requires both S AND DLP hardness.
    Eve without S: still needs DLP with unknown generator — DOUBLE protection.

  ── PS-4  Layered cfscx KDF + DH ────────────────────────────────────────────
    A_4n  = a ‖ S ‖ (a⊕S) ‖ (a⊕S)
    a_scl = cfscx_compress(A_4n, g, r)  [KDF: maps 4n-bit → n-bit scalar]
    C_A   = gf_pow(g, a_scl, poly, n) = g^{{a_scl}}
    sk    = gf_pow(C_B, a_scl, poly, n) = g^{{a_scl · b_scl}}

    sk is DLP-protected (same as HKEX-CFSCX-GF from hkex_cfscx_compress.py).
    S helps recover original private a beyond a_scl, but sk does NOT depend on S
    directly — it depends only on a_scl. Same security as standard HKEX-CFSCX-GF.
    Layering S: slightly more stable a_scl (S fixes chunks 2-4 of A_4n), but
    Eve with S still faces the same DLP to recover sk.

  ── PS-5  Non-linear integer expansion ──────────────────────────────────────
    A_4n = a ‖ S ‖ ((a+S) mod 2^n) ‖ ((a·S) mod 2^n)
    C_A  = cfscx_compress(A_4n, g, r)
    sk   = cfscx_compress(A_4n, C_B, r)  [C_B used directly as base]

    The map a → A_4n is NOT GF(2)-linear (integer + and × inject carry bits).
    cfscx_compress is affine in A_4n for fixed base, but the composition
    a → A_4n → C_A may NOT be affine in a for fixed S.
    Part VI tests this experimentally and with the GF(2) matrix attack.
    Correctness requires: sk_A = cfscx_compress(A_4n_A, C_B, r)
                                = cfscx_compress(A_4n_B, C_A, r) = sk_B?
    Not guaranteed — sk formula must be redesigned if not symmetric.
""")


# ═════════════════════════════════════════════════════════════════════════════
# PART II — PS-1: S-base fscx
# ═════════════════════════════════════════════════════════════════════════════

def run_part_II(n=32, trials=500):
    section("PART II — PS-1: S-base fscx")
    r = n // 4
    mask = (1 << n) - 1

    def ps1_keygen(a, S):
        C_A = fscx_revolve(a, S, r, n)
        return C_A

    def ps1_sk(C_A, C_B, S):
        return fscx_revolve(C_A ^ C_B, S, r, n)

    print(f"  Parameters: n={n}, r={r}")
    print()

    # II-A: Correctness
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = ps1_keygen(a, S)
        C_B = ps1_keygen(b, S)
        sk_A = ps1_sk(C_A, C_B, S)
        sk_B = ps1_sk(C_A, C_B, S)  # symmetric formula
        if sk_A == sk_B:
            correct += 1
    print(f"  [II-A] Correctness: {correct}/{trials} sk_A==sk_B")

    # II-B: Private-key binding — does sk change when only a changes?
    bound = 0
    for _ in range(trials):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        while a2 == a1:
            a2 = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A1 = ps1_keygen(a1, S)
        C_A2 = ps1_keygen(a2, S)
        C_B  = ps1_keygen(b, S)
        sk1 = ps1_sk(C_A1, C_B, S)
        sk2 = ps1_sk(C_A2, C_B, S)
        if sk1 != sk2:
            bound += 1
    print(f"  [II-B] Private-key binding: {bound}/{trials} sk differs when a changes")

    # II-C: S-necessity
    s_needed = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S1 = secrets.randbelow(mask) + 1
        S2 = secrets.randbelow(mask) + 1
        while S2 == S1:
            S2 = secrets.randbelow(mask) + 1
        C_A = ps1_keygen(a, S1)
        C_B = ps1_keygen(b, S1)
        sk_correct = ps1_sk(C_A, C_B, S1)
        sk_wrong_S = ps1_sk(C_A, C_B, S2)
        if sk_correct != sk_wrong_S:
            s_needed += 1
    print(f"  [II-C] S-necessity: {s_needed}/{trials} sk differs when S changes")

    # II-D: Eve without S — try to compute sk from C_A, C_B only
    eve_no_s = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A = ps1_keygen(a, S)
        C_B = ps1_keygen(b, S)
        sk_real = ps1_sk(C_A, C_B, S)
        # Eve tries all standard r values without knowing S
        # Best naive attempt: use C_A^C_B directly as sk
        sk_eve = C_A ^ C_B
        if sk_eve == sk_real:
            eve_no_s += 1
    print(f"  [II-D] Eve (no S) naive: {eve_no_s}/{trials} correct")

    # II-E: Eve WITH S — algebraic formula from Part I
    # sk_eve = R³·(C_A⊕C_B) ⊕ K·S = fscx_revolve(C_A⊕C_B, S, 3r)
    eve_with_s = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A = ps1_keygen(a, S)
        C_B = ps1_keygen(b, S)
        sk_real = ps1_sk(C_A, C_B, S)
        # Eve knows S, C_A, C_B. sk = fscx_revolve(C_A^C_B, S, r) directly.
        sk_eve = fscx_revolve(C_A ^ C_B, S, r, n)
        if sk_eve == sk_real:
            eve_with_s += 1
    print(f"  [II-E] Eve (with S, algebraic formula): {eve_with_s}/{trials} correct")
    print()
    print("  Algebraic conclusion:")
    print(f"    sk = R·(C_A⊕C_B) ⊕ K·S = fscx_revolve(C_A⊕C_B, S, r)  [same as ps1_sk]")
    print(f"    Eve with S computes: fscx_revolve(C_A⊕C_B, S, r) = sk  [identical formula]")
    print(f"    → PS-1 provides SINGLE-FACTOR protection: S alone determines sk.")
    print(f"    → Private key a is REDUNDANT once S is known to Eve.")


# ═════════════════════════════════════════════════════════════════════════════
# PART III — PS-2: S-expanded cfscx (XOR expansion)
# ═════════════════════════════════════════════════════════════════════════════

def run_part_III(n=32, trials=500):
    section("PART III — PS-2: S-expanded cfscx (XOR-linear expansion)")
    r = n // 4
    mask = (1 << n) - 1
    g = GF_GEN

    def make_A4n(a, S):
        return int_expand_xor(a, S, n)

    def ps2_keygen(a, S):
        A_4n = make_A4n(a, S)
        return cfscx_compress(A_4n, g, r, n)

    def ps2_sk(C_A, C_B, S):
        return fscx_revolve(C_A ^ C_B, S, r, n)

    print(f"  Parameters: n={n}, r={r}, g={g}")
    print(f"  A_4n = a ‖ S ‖ (a⊕S) ‖ (a⊕S)  [XOR expansion — linear in a for fixed S]")
    print()

    # III-A: Correctness
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = ps2_keygen(a, S)
        C_B = ps2_keygen(b, S)
        sk_A = ps2_sk(C_A, C_B, S)
        sk_B = ps2_sk(C_A, C_B, S)
        if sk_A == sk_B:
            correct += 1
    print(f"  [III-A] Correctness: {correct}/{trials} sk_A==sk_B")

    # III-B: Eve WITH S — GF(2) matrix attack to recover a from C_A
    # C_A = cfscx_compress(make_A4n(a, S), g, r)
    # For fixed S: make_A4n(a, S) = L(a) + const(S) where L is linear
    # So C_A is affine in a; matrix attack recovers a
    eve_recover = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A = ps2_keygen(a, S)
        # Build affine attack: strip constant at a=0
        c_0 = ps2_keygen(0, S)
        def f_lin_a(av):
            return ps2_keygen(av, S) ^ c_0
        M_mat = gf2_build_matrix(f_lin_a, n, n)
        a_found, rank = gf2_solve(M_mat, C_A ^ c_0, n, n)
        if a_found is not None and ps2_keygen(a_found, S) == C_A:
            eve_recover += 1
    print(f"  [III-B] Eve (with S) matrix attack on C_A: {eve_recover}/{trials} a recovered")

    # III-C: Eve WITH S — compute sk algebraically once a recovered
    eve_sk = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A = ps2_keygen(a, S)
        C_B = ps2_keygen(b, S)
        sk_real = ps2_sk(C_A, C_B, S)
        # Eve recovers sk directly from public values + S
        sk_eve = ps2_sk(C_A, C_B, S)  # same formula — Eve has S
        if sk_eve == sk_real:
            eve_sk += 1
    print(f"  [III-C] Eve (with S) computes sk directly: {eve_sk}/{trials} correct")
    print()
    print("  Conclusion: PS-2 (XOR expansion) is WEAKER than PS-1.")
    print("  The cfscx compression adds no security vs fscx alone because:")
    print("  A_4n = L(a) ⊕ const(S) is linear in a → C_A is affine in a.")
    print("  With S, Eve recovers a via matrix attack, and sk immediately.")
    print("  Without S: same S-dependency as PS-1 for the sk formula.")


# ═════════════════════════════════════════════════════════════════════════════
# PART IV — PS-3: S as DH generator
# ═════════════════════════════════════════════════════════════════════════════

def run_part_IV(n=32, trials=500):
    section("PART IV — PS-3: S as DH generator (S^{ab})")
    r = n // 4
    mask = (1 << n) - 1
    poly = GF_POLY.get(n, GF_POLY[32])

    def ps3_keygen(a, S):
        return gf_pow(S, a, poly, n)

    def ps3_sk(C_other, a):
        return gf_pow(C_other, a, poly, n)

    print(f"  Parameters: n={n}, poly=0x{poly:X}, r={r}")
    print(f"  C_A = S^a,  C_B = S^b,  sk = C_B^a = S^{{ab}} = C_A^b")
    print()

    # IV-A: Correctness
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = ps3_keygen(a, S)
        C_B = ps3_keygen(b, S)
        sk_A = ps3_sk(C_B, a)
        sk_B = ps3_sk(C_A, b)
        if sk_A == sk_B:
            correct += 1
    print(f"  [IV-A] Correctness: {correct}/{trials} sk_A==sk_B")

    # IV-B: Private-key binding
    bound = 0
    for _ in range(trials):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        while a2 == a1:
            a2 = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A1 = ps3_keygen(a1, S)
        C_A2 = ps3_keygen(a2, S)
        C_B  = ps3_keygen(b, S)
        sk1 = ps3_sk(C_B, a1)
        sk2 = ps3_sk(C_B, a2)
        if sk1 != sk2:
            bound += 1
    print(f"  [IV-B] Private-key binding: {bound}/{trials} sk differs when a changes")

    # IV-C: S-necessity (sk changes when only S changes)
    s_needed = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S1 = secrets.randbelow(mask) + 1
        S2 = secrets.randbelow(mask) + 1
        while S2 == S1:
            S2 = secrets.randbelow(mask) + 1
        C_A1 = ps3_keygen(a, S1)
        C_B1 = ps3_keygen(b, S1)
        C_A2 = ps3_keygen(a, S2)
        C_B2 = ps3_keygen(b, S2)
        sk1 = ps3_sk(C_B1, a)
        sk2 = ps3_sk(C_B2, a)
        if sk1 != sk2:
            s_needed += 1
    print(f"  [IV-C] S-necessity: {s_needed}/{trials} sk differs when S changes")

    # IV-D: Eve with S but WITHOUT a — can she compute sk?
    # DLP: Eve knows C_A = S^a, must find a. No efficient classical algorithm.
    # Here we test Eve's naive attempts (she cannot solve DLP experimentally).
    # We verify she cannot use fscx linearity as a shortcut.
    # Test: is C_A affine in a for fixed S in GF(2)?
    affine_violations = 0
    for _ in range(min(trials, 200)):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C1 = ps3_keygen(a1, S)
        C2 = ps3_keygen(a2, S)
        C0 = ps3_keygen(0,  S)   # gf_pow(S, 0) = 1
        C12 = ps3_keygen(a1 ^ a2, S)
        # Affine test: f(a1^a2) == f(a1) ^ f(a2) ^ f(0)?
        if C12 != (C1 ^ C2 ^ C0):
            affine_violations += 1
    print(f"  [IV-D] Affine-in-a test: {affine_violations}/200 violations")
    print(f"         (>0 violations = non-linear in a → GF(2) matrix attack FAILS)")

    # IV-E: S-generator vs standard-g comparison
    print()
    print(f"  [IV-E] Comparison: S^{{ab}} vs standard g^{{ab}} (g={GF_GEN})")
    with_S  = 0
    with_g  = 0
    for _ in range(min(trials, 200)):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        sk_S = gf_pow(gf_pow(S, a, poly, n), b, poly, n)
        sk_g = gf_pow(gf_pow(GF_GEN, a, poly, n), b, poly, n)
        if sk_S != sk_g:
            with_S += 1
    print(f"    S^{{ab}} ≠ g^{{ab}} in {with_S}/200 cases  (different keys for different generator)")
    print()
    print("  Conclusion: PS-3 provides DOUBLE protection:")
    print("    1. S is required to compute C_A = S^a (wrong S → wrong C_A)")
    print("    2. Even with S and C_A, DLP must be solved to find a")
    print("    3. gf_pow is non-linear in a → GF(2) matrix attack is inapplicable")
    print("    Eve with S and C_A, C_B still faces a full DLP in GF(2^n)*.")


# ═════════════════════════════════════════════════════════════════════════════
# PART V — PS-4: Layered cfscx KDF + DH
# ═════════════════════════════════════════════════════════════════════════════

def run_part_V(n=32, trials=500):
    section("PART V — PS-4: Layered cfscx KDF + DH")
    r = n // 4
    mask = (1 << n) - 1
    poly = GF_POLY.get(n, GF_POLY[32])
    g = GF_GEN

    def make_A4n(a, S):
        return int_expand_xor(a, S, n)

    def ps4_keygen(a, S):
        A_4n   = make_A4n(a, S)
        a_scl  = cfscx_compress(A_4n, g, r, n)
        C_A    = gf_pow(g, a_scl, poly, n)
        return C_A, a_scl

    def ps4_sk(C_other, a_scl):
        return gf_pow(C_other, a_scl, poly, n)

    print(f"  Parameters: n={n}, r={r}, g={g}, poly=0x{poly:X}")
    print(f"  a_scl = cfscx_compress(a‖S‖a⊕S‖a⊕S, g, r)")
    print(f"  C_A   = g^{{a_scl}},  sk = C_B^{{a_scl}} = g^{{a_scl·b_scl}}")
    print()

    # V-A: Correctness
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A, a_scl = ps4_keygen(a, S)
        C_B, b_scl = ps4_keygen(b, S)
        sk_A = ps4_sk(C_B, a_scl)
        sk_B = ps4_sk(C_A, b_scl)
        if sk_A == sk_B:
            correct += 1
    print(f"  [V-A] Correctness: {correct}/{trials} sk_A==sk_B")

    # V-B: Does sk change when only a changes (not S)?
    bound = 0
    for _ in range(trials):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        while a2 == a1:
            a2 = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A1, a_scl1 = ps4_keygen(a1, S)
        C_A2, a_scl2 = ps4_keygen(a2, S)
        C_B,  b_scl  = ps4_keygen(b,  S)
        sk1 = ps4_sk(C_B, a_scl1)
        sk2 = ps4_sk(C_B, a_scl2)
        if sk1 != sk2:
            bound += 1
    print(f"  [V-B] Private-key binding: {bound}/{trials} sk differs when a changes")

    # V-C: Does changing S change sk (all else equal)?
    s_changes_sk = 0
    for _ in range(trials):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S1 = secrets.randbelow(mask) + 1
        S2 = secrets.randbelow(mask) + 1
        while S2 == S1:
            S2 = secrets.randbelow(mask) + 1
        C_A1, a_scl1 = ps4_keygen(a, S1)
        C_B1, b_scl1 = ps4_keygen(b, S1)
        C_A2, a_scl2 = ps4_keygen(a, S2)
        C_B2, b_scl2 = ps4_keygen(b, S2)
        sk1 = ps4_sk(C_B1, a_scl1)
        sk2 = ps4_sk(C_B2, a_scl2)
        if sk1 != sk2:
            s_changes_sk += 1
    print(f"  [V-C] S-changes-sk: {s_changes_sk}/{trials} sk differs when S changes")

    # V-D: Collision test — does different a but same S produce same a_scl?
    scl_collision = 0
    for _ in range(min(trials, 200)):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        while a2 == a1:
            a2 = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        _, scl1 = ps4_keygen(a1, S)
        _, scl2 = ps4_keygen(a2, S)
        if scl1 == scl2:
            scl_collision += 1
    print(f"  [V-D] a_scl collisions (a1≠a2, same S): {scl_collision}/200")

    # V-E: Eve with S — does knowing S let Eve compute sk?
    # Eve needs a_scl to compute sk. a_scl = cfscx_compress(A_4n, g, r).
    # cfscx_compress is affine in A_4n, and A_4n = L(a) for fixed S.
    # So a_scl is affine in a. Matrix attack recovers a, hence a_scl.
    eve_recover = 0
    for _ in range(min(trials, 200)):
        a  = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A, a_scl_real = ps4_keygen(a, S)
        C_B, b_scl_real = ps4_keygen(b, S)
        sk_real = ps4_sk(C_B, a_scl_real)
        # Eve's matrix attack on a_scl (strip affine constant)
        c_0_scl = cfscx_compress(int_expand_xor(0, S, n), g, r, n)
        def f_lin_scl(av):
            A4n = int_expand_xor(av, S, n)
            return cfscx_compress(A4n, g, r, n) ^ c_0_scl
        M_mat = gf2_build_matrix(f_lin_scl, n, n)
        a_found, rank = gf2_solve(M_mat, a_scl_real ^ c_0_scl, n, n)
        if a_found is not None:
            _, a_scl_found = ps4_keygen(a_found, S)
            sk_eve = ps4_sk(C_B, a_scl_found)
            if sk_eve == sk_real:
                eve_recover += 1
    print(f"  [V-E] Eve (with S) matrix attack → sk: {eve_recover}/200 correct")
    print()
    print("  Note: PS-4 sk depends on a_scl, NOT directly on S.")
    print("  Security of sk = DLP of g^{a_scl}. S affects a_scl derivation but")
    print("  sk itself is DLP-protected regardless of whether Eve knows S.")
    print("  Comparison to pure HKEX-CFSCX-GF: equivalent sk security.")
    print("  S adds entropy to a_scl derivation but not cryptographic hardness to sk.")


# ═════════════════════════════════════════════════════════════════════════════
# PART VI — PS-5: Non-linear integer expansion
# ═════════════════════════════════════════════════════════════════════════════

def run_part_VI(n=32, trials=500):
    section("PART VI — PS-5: Non-linear integer expansion (carry injection)")
    r = n // 4
    mask = (1 << n) - 1
    g = GF_GEN

    def ps5_keygen_C(a, S):
        A_4n = int_expand(a, S, n)
        return cfscx_compress(A_4n, g, r, n)

    def ps5_sk(a, S, C_other):
        """sk = cfscx_compress(A_4n_self, C_other, r)."""
        A_4n = int_expand(a, S, n)
        return cfscx_compress(A_4n, C_other, r, n)

    print(f"  Parameters: n={n}, r={r}, g={g}")
    print(f"  A_4n = a ‖ S ‖ ((a+S) mod 2^n) ‖ ((a·S) mod 2^n)")
    print(f"  C_A  = cfscx_compress(A_4n, g, r)")
    print(f"  sk   = cfscx_compress(A_4n_A, C_B, r)  [direct — NOT symmetric a priori]")
    print()

    # VI-A: Correctness check — is sk_A == sk_B?
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = ps5_keygen_C(a, S)
        C_B = ps5_keygen_C(b, S)
        sk_A = ps5_sk(a, S, C_B)
        sk_B = ps5_sk(b, S, C_A)
        if sk_A == sk_B:
            correct += 1
    print(f"  [VI-A] Correctness: {correct}/{trials} sk_A==sk_B")
    print(f"         (cfscx_compress is NOT symmetric in arguments → expect 0)")

    # VI-B: Non-linearity test for C_A in a (for fixed S)
    # Affine test: f(a1^a2) == f(a1) ^ f(a2) ^ f(0)?
    affine_violations = 0
    for _ in range(min(trials, 1000)):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C1 = ps5_keygen_C(a1, S)
        C2 = ps5_keygen_C(a2, S)
        C0 = ps5_keygen_C(0,  S)
        C12 = ps5_keygen_C(a1 ^ a2, S)
        if C12 != (C1 ^ C2 ^ C0):
            affine_violations += 1
    print(f"  [VI-B] Affine-in-a violations: {affine_violations}/1000")
    print(f"         (>0 = non-linear in a — matrix attack inapplicable)")

    # VI-C: Comparison — XOR expansion (linear) vs integer expansion (non-linear)
    xor_violations = 0
    for _ in range(min(trials, 1000)):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        def ps_xor_C(av):
            A4n = int_expand_xor(av, S, n)
            return cfscx_compress(A4n, g, r, n)
        C1  = ps_xor_C(a1)
        C2  = ps_xor_C(a2)
        C0  = ps_xor_C(0)
        C12 = ps_xor_C(a1 ^ a2)
        if C12 != (C1 ^ C2 ^ C0):
            xor_violations += 1
    print(f"  [VI-C] XOR-expand affine violations: {xor_violations}/1000")
    print(f"         (should be 0 — XOR expansion is linear)")

    # VI-D: Try matrix attack on PS-5 C_A — should FAIL due to non-linearity
    eve_recover = 0
    matrix_attempts = min(trials, 200)
    for _ in range(matrix_attempts):
        a  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A = ps5_keygen_C(a, S)
        # Try affine attack as if it were linear
        c_0 = ps5_keygen_C(0, S)
        def f_lin(av):
            return ps5_keygen_C(av, S) ^ c_0
        M_mat = gf2_build_matrix(f_lin, n, n)
        a_found, rank = gf2_solve(M_mat, C_A ^ c_0, n, n)
        if a_found is not None and ps5_keygen_C(a_found, S) == C_A:
            eve_recover += 1
    print(f"  [VI-D] Eve matrix attack on PS-5 C_A: {eve_recover}/{matrix_attempts} a recovered")
    print(f"         (should be <<{matrix_attempts} if non-linear)")

    # VI-E: Can we design a symmetric sk for PS-5?
    # Attempt: sk = cfscx_compress(C_A ^ C_B, S, r)  [uses public values + S]
    print()
    print("  [VI-E] Alternative symmetric sk: cfscx_compress(C_A⊕C_B, S, r)")
    sym_correct = 0
    for _ in range(min(trials, 200)):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = ps5_keygen_C(a, S)
        C_B = ps5_keygen_C(b, S)
        sk_sym_A = cfscx_compress(C_A ^ C_B, S, r, n)
        sk_sym_B = cfscx_compress(C_A ^ C_B, S, r, n)  # symmetric
        if sk_sym_A == sk_sym_B:
            sym_correct += 1
    print(f"    Correctness (trivially symmetric): {sym_correct}/200")
    # Does sk_sym depend on a?
    sk_bound = 0
    for _ in range(min(trials, 200)):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        while a2 == a1:
            a2 = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        C_A1 = ps5_keygen_C(a1, S)
        C_A2 = ps5_keygen_C(a2, S)
        C_B  = ps5_keygen_C(b, S)
        sk1  = cfscx_compress(C_A1 ^ C_B, S, r, n)
        sk2  = cfscx_compress(C_A2 ^ C_B, S, r, n)
        if sk1 != sk2:
            sk_bound += 1
    print(f"    sk_sym changes with a: {sk_bound}/200")
    print()
    print("  Conclusion: PS-5 non-linearity in a→C_A comes from integer +/* carry bits.")
    print("  cfscx_compress is NOT argument-symmetric → direct sk formula fails.")
    print("  Symmetric sk requires using C_A⊕C_B as input (public-value combination).")
    print("  Non-linearity invalidates the GF(2) matrix attack on C_A derivation.")
    print("  However, security still depends only on S for the symmetric-sk variant.")


# ═════════════════════════════════════════════════════════════════════════════
# PART VII — Summary comparison
# ═════════════════════════════════════════════════════════════════════════════

def run_part_VII():
    section("PART VII — Summary Comparison Table")

    print("""
  ┌───────────────────────────────────────────────────────────────────────┐
  │  Construction  │ sk correct │ S req │ Private key adds │ Eve (w/ S)   │
  ├───────────────────────────────────────────────────────────────────────┤
  │ PS-1 fscx-base │    Yes     │  Yes  │  No (redundant)  │ sk directly  │
  │ PS-2 xor-cfscx │    Yes     │  Yes  │  No (redundant)  │ sk directly  │
  │ PS-3 S-gen DH  │    Yes     │  Yes  │  Yes (DLP)       │ needs DLP    │
  │ PS-4 KDF+DH    │    Yes     │  Yes  │  Yes (DLP on sk) │ needs DLP    │
  │ PS-5 int-expand│    No*     │  Yes  │  Non-linear C_A  │  partial†    │
  └───────────────────────────────────────────────────────────────────────┘

  * PS-5 direct sk (cfscx_compress(A_4n_A, C_B)) is NOT symmetric.
    Alternative symmetric sk (cfscx_compress(C_A⊕C_B, S)) is correct
    but provides S-only security (same as PS-1).

  † PS-5 C_A derivation is non-linear in a — matrix attack fails for C_A.
    But symmetric sk is still S-dependent only.

  Key findings:
  ─────────────
  1. PS-1 / PS-2 (fscx-based sk):
     - sk = R²·(a⊕b) ⊕ K·S — computable from S and wire values.
     - Eve with S recovers sk in O(1): fscx_revolve(C_A⊕C_B, S, 3r).
     - Private keys a, b provide NO security beyond what S already gives.
     - Single-factor: S alone determines sk.

  2. PS-3 (S as DH generator, sk = S^{ab}):
     - sk is DLP-protected in GF(2^n)* with generator S.
     - Eve needs: (a) S, and (b) to solve DLP(S, C_A) = a.
     - Using a preshared S as DH generator is VALID.
     - Compatible with HKEX-GF (same gf_pow interface, different base).
     - Security: equivalent to HKEX-GF but with S-dependent public params.
     - Note: if S is compromised, all past sessions also compromised (no PFS
       beyond what HKEX-GF already provides). New S per session = same as g.

  3. PS-4 (cfscx KDF then DH, sk = g^{a_scl·b_scl}):
     - sk is DLP-protected regardless of S. S affects a_scl derivation.
     - Eve needs DLP to attack sk, even if she knows S.
     - Equivalent security to HKEX-CFSCX-GF (hkex_cfscx_compress.py §V).
     - S adds entropy mixing into a_scl but no additional hardness to sk.
     - RECOMMENDED: most compatible with existing suite architecture.

  4. PS-5 (non-linear integer expansion):
     - Integer +/* introduces genuine non-linearity in a → A_4n mapping.
     - cfscx_compress(A_4n, B) is affine in A_4n (verified), but the
       COMPOSITION a → A_4n → C_A is NON-AFFINE in a.
     - GF(2) matrix attack fails on C_A.
     - However: cfscx_compress is NOT argument-symmetric → sk design issue.
     - Any symmetric sk formula relinquishes the non-linearity advantage.
     - Promising direction for future non-linear FSCX constructions.

  Suite compatibility:
  ────────────────────
  PS-3 and PS-4 are compatible with HSKE, HPKS, HPKE using the standard
  (C_A, a_scl) interface (PS-4) or (C_A, a) interface (PS-3).
  PS-1/PS-2 are NOT compatible — they produce sk directly without DLP.
  PS-5 requires a redesigned sk derivation that is non-trivially symmetric.
""")


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    N       = 32
    TRIALS  = 500

    run_part_I(n=N)
    run_part_II(n=N, trials=TRIALS)
    run_part_III(n=N, trials=TRIALS)
    run_part_IV(n=N, trials=TRIALS)
    run_part_V(n=N, trials=TRIALS)
    run_part_VI(n=N, trials=TRIALS)
    run_part_VII()

    print()
    print(DIVIDER)
    print("  DONE")
    print(DIVIDER)
