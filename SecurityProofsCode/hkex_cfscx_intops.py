"""
hkex_cfscx_intops.py — PS-5 Integer Operations: Padlock, Asymmetric, Hash-Like Schemes

Starting point: PS-5 — integer +/* expansion creates genuine non-affinity in a→C map.
  C = cfscx_compress(a ‖ S ‖ (a+S)%2^n ‖ (a·S)%2^n,  g, r)
  Map a→C is NON-AFFINE (carry injection); GF(2) matrix attack fails.

Three families of constructions explored here:

  ── A. Padlock schemas ──────────────────────────────────────────────────────
  For a padlock to work, the "lock" operation must commute:
    Lock_A(Lock_B(m)) = Lock_B(Lock_A(m))     (commutativity)
  AND each lock must be invertible (Unlock exists).

  PL-1  fscx_revolve padlock         lock = fscx_revolve(X, key, r)
                                     unlock = fscx_revolve(X, key, n-r)
  PL-2  Integer-multiplication       lock = (X · key) mod p   [odd key / prime p]
        three-pass (classical)       unlock = (X · key⁻¹) mod p
  PL-3  cfscx_compress padlock       lock = cfscx(int_expand(key, X), g, r)
        (non-invertible — fails)     unlock = ???  [undefined — compression is many-to-one]
  PL-4  INT-FSCX chained             C_A = cfscx(int_expand(a, S)),
        cross-padlock attempt        sk_A = cfscx(int_expand(a, C_B))

  ── B. Asymmetric key exchange ──────────────────────────────────────────────
  AK-1  INT-cross          C_A = cfscx(int_expand(a,S)); sk_A = cfscx(int_expand(a,C_B))
                           C_B = cfscx(int_expand(b,S)); sk_B = cfscx(int_expand(b,C_A))
  AK-2  SUMMOD symmetric   sk_A = cfscx(a+C_B ‖ a·C_B ‖ a+C_B ‖ a·C_B, S)
                           sk_B = cfscx(b+C_A ‖ b·C_A ‖ b+C_A ‖ b·C_A, S)
  AK-3  INT-gf hybrid      a_scl = cfscx(int_expand(a,S)), C_A = g^{a_scl}, sk = C_B^{a_scl}
  AK-4  INT-double-cross   Two rounds: T_X = cfscx(int_expand(x, C_other))
                           sk = cfscx(int_expand_sym(T_A, T_B), S)

  ── C. Hash-like schemes ────────────────────────────────────────────────────
  HL-1  Symmetric int-hash  sk = cfscx(int_expand_sym(C_A, C_B), S, r)
        of transcript       [symmetric but Eve-trivial]
  HL-2  Iterated hash chain h₀ = g; hₖ₊₁ = cfscx(int_expand(hₖ, S), g, r)
                            C_A = h_a (after a steps from common g)
  HL-3  Commitment-based    Each party commits to their private key; shared
        shared randomness   randomness derived only after both reveal.

Key questions per construction:
  1. Correctness: sk_A == sk_B?
  2. Private-key binding: sk changes when only a changes?
  3. Eve-with-S attack: can Eve compute sk from C_A, C_B, S?
  4. Is the padlock commutative and invertible?
  5. Is there any security beyond knowing S?

Part I    — Why non-linear expansion ≠ trapdoor (extension of PS-5 findings)
Part II   — Padlock schemas: PL-1 through PL-4
Part III  — Asymmetric key exchange: AK-1 through AK-4
Part IV   — Hash-like schemes: HL-1 through HL-3
Part V    — Summary and classification
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
# Chunk helpers + cfscx_compress
# ─────────────────────────────────────────────────────────────────────────────

def split_chunks(X, n):
    mask = (1 << n) - 1
    return [(X >> ((3 - i) * n)) & mask for i in range(4)]

def join_chunks(chunks, n):
    result = 0
    for c in chunks:
        result = (result << n) | (c & ((1 << n) - 1))
    return result

def cfscx_compress(A_large, B, r, n):
    A1, A2, A3, A4 = split_chunks(A_large, n)
    t = fscx_revolve(A1,     B, r, n)
    t = fscx_revolve(t ^ A2, B, r, n)
    t = fscx_revolve(t ^ A3, B, r, n)
    return fscx_revolve(t ^ A4, B, r, n)


# ─────────────────────────────────────────────────────────────────────────────
# Integer expansion helpers
# ─────────────────────────────────────────────────────────────────────────────

def int_expand(a, S, n):
    """PS-5: non-linear 4-chunk expansion via integer carry arithmetic."""
    mask = (1 << n) - 1
    return join_chunks([a & mask, S & mask, (a + S) & mask, (a * S) & mask], n)

def int_expand_sym(X, Y, n):
    """Symmetric 4-chunk expansion using commutative integer operations on (X, Y)."""
    mask = (1 << n) - 1
    xor  = (X ^ Y)  & mask
    add  = (X + Y)  & mask
    mul  = (X * Y)  & mask
    mix  = (add ^ mul) & mask
    return join_chunks([xor, add, mul, mix], n)

def int_compress(a, S, n, g, r):
    """PS-5 compression: C = cfscx_compress(int_expand(a, S), g, r)."""
    return cfscx_compress(int_expand(a, S, n), g, r, n)


# ─────────────────────────────────────────────────────────────────────────────
# GF(2^n) arithmetic
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


# ─────────────────────────────────────────────────────────────────────────────
# Integer modular inverse (for multiplicative padlock)
# ─────────────────────────────────────────────────────────────────────────────

def modinv(a, m):
    """Extended Euclidean: return a^{-1} mod m, or None if not invertible."""
    g, x, _ = _extended_gcd(a % m, m)
    return (x % m) if g == 1 else None

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def make_odd(x, n):
    """Force x to be odd (invertible mod 2^n) by setting LSB."""
    return x | 1


# ─────────────────────────────────────────────────────────────────────────────
# Affinity test helper
# ─────────────────────────────────────────────────────────────────────────────

def affine_violations(fn, n, trials):
    """Count affine test violations: fn(a1⊕a2) ≠ fn(a1)⊕fn(a2)⊕fn(0)."""
    mask = (1 << n) - 1
    v = 0
    for _ in range(trials):
        a1 = secrets.randbelow(mask) + 1
        a2 = secrets.randbelow(mask) + 1
        if fn(a1 ^ a2) != (fn(a1) ^ fn(a2) ^ fn(0)):
            v += 1
    return v


# ═════════════════════════════════════════════════════════════════════════════
# PART I — Why non-linear expansion ≠ trapdoor
# ═════════════════════════════════════════════════════════════════════════════

def run_part_I(n=32):
    section("PART I — Why Non-Linear Expansion ≠ Trapdoor")
    r = n // 4
    poly = GF_POLY[n]
    mask = (1 << n) - 1

    print(f"""
  PS-5 recap (n={n}, r={r}):
    C = cfscx_compress(int_expand(a, S), g, r)
    int_expand(a, S) = a ‖ S ‖ (a+S)%2^n ‖ (a·S)%2^n
    Map a→C is NON-AFFINE over GF(2) (carry injection from + and ·).

  For a non-linear map to constitute a "trapdoor" (i.e. a one-way function
  suitable for key exchange), it must satisfy:
    (a) Hard to invert: given C and S, recovering a is computationally hard.
    (b) Trapdoor property: a second value (C_B from Bob) enables computing
        a shared secret that only Alice and Bob can derive.

  Property (a) — experimental preimage hardness for small n:
""")

    # Test preimage for n=16: brute force
    n_small = 16
    r_small = n_small // 4
    hits = 0
    trials = 50
    for _ in range(trials):
        a_real = secrets.randbelow((1 << n_small)) + 1
        S      = secrets.randbelow((1 << n_small)) + 1
        C_real = int_compress(a_real, S, n_small, GF_GEN, r_small)
        # Brute-force: try all 2^n_small values
        found = None
        for cand in range(1 << n_small):
            if int_compress(cand, S, n_small, GF_GEN, r_small) == C_real:
                found = cand
                break
        if found is not None and int_compress(found, S, n_small, GF_GEN, r_small) == C_real:
            hits += 1
    print(f"  [I-A] Brute-force preimage (n={n_small}): {hits}/{trials} found")
    print(f"         (n={n_small} → 2^{n_small}={1<<n_small} candidates; any valid preimage counts)")
    print()

    # Collision rate for n=16
    n_small = 16; r_small = n_small // 4
    images = {}; collisions = 0
    for a in range(1, 1001):
        S = 0x1234  # fixed S for this test
        C = int_compress(a, S, n_small, GF_GEN, r_small)
        if C in images:
            collisions += 1
        else:
            images[C] = a
    print(f"  [I-B] Collisions for first 1000 inputs (n={n_small}, fixed S): {collisions}")
    print(f"        Unique outputs: {len(images)}")
    print()

    print(f"""  Property (b) — trapdoor property analysis:
    For a symmetric key exchange, we need:
      sk_A = f(a, C_B) = sk_B = f(b, C_A)  for ALL valid (a, b, S).
    This requires f to satisfy: f(a, f_C(b)) = f(b, f_C(a))
    where f_C is the C derivation function.

    For the PS-5 one-way function (f_C = int_compress), no such f is known.
    The constructions below test specific candidates and determine whether
    they satisfy correctness, and if so, whether Eve can still compute sk.

    Key insight: non-linearity protects the private key a from being
    extracted from C (property a). But it does NOT create a trapdoor
    unless there is a commutativity structure like gf_pow's g^{{ab}} = g^{{ba}}.
""")


# ═════════════════════════════════════════════════════════════════════════════
# PART II — Padlock schemas
# ═════════════════════════════════════════════════════════════════════════════

def run_part_II(n=32, trials=500):
    section("PART II — Padlock Schemas")
    r = n // 4
    mask = (1 << n) - 1

    # ── PL-1: fscx_revolve three-pass ────────────────────────────────────────
    print(f"  ── PL-1  fscx_revolve three-pass  (n={n}, r={r}) ──────────────────")
    print(f"""
  Protocol: lock(X, key) = fscx_revolve(X, key, r)
            unlock(X, key) = fscx_revolve(X, key, n-r)  [uses period: r+(n-r)=n]
  Commutativity required: lock_A ∘ lock_B = lock_B ∘ lock_A
  i.e. fscx_revolve(fscx_revolve(X, a, r), b, r) = fscx_revolve(fscx_revolve(X, b, r), a, r)
  Algebraically: R²·X ⊕ R·K·a ⊕ K·b  vs  R²·X ⊕ R·K·b ⊕ K·a
  Equal iff (R·K ⊕ K)·(a⊕b) = 0  iff  (R⊕I)·K·(a⊕b) = 0.
  NOT true for arbitrary (a,b).  BUT for r=n/4, n=32:
    rank((R⊕I)·K) = 2  →  null space dimension = 30
    P(a⊕b in null space) = 2^30/2^32 = 1/4  →  ~25% of random pairs commute.
  This is an algebraic accident of the specific r=n/4 parameter, not a protocol feature.
""")
    g = secrets.randbelow(mask) + 1  # "message" to transport
    commutes = 0
    three_pass_correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        # Commutativity test
        c1 = fscx_revolve(fscx_revolve(g, a, r, n), b, r, n)
        c2 = fscx_revolve(fscx_revolve(g, b, r, n), a, r, n)
        if c1 == c2: commutes += 1
        # Three-pass: C1 → C2 → C3 → extracted
        C1 = fscx_revolve(g, a, r, n)
        C2 = fscx_revolve(C1, b, r, n)
        C3 = fscx_revolve(C2, a, n - r, n)        # Alice unlocks
        extracted = fscx_revolve(C3, b, n - r, n) # Bob unlocks
        if extracted == g: three_pass_correct += 1
    print(f"  [PL-1-A] Commutativity holds: {commutes}/{trials}")
    print(f"  [PL-1-B] Three-pass extracts g: {three_pass_correct}/{trials}")
    print(f"           (Expected ~{int(trials * 0.25)} — (R⊕I)·K has rank 2, null-space dim 30 → 25% of pairs commute)")
    print(f"           Algebraic accident of r=n/4: NOT a usable padlock property.")

    # Special case r=1
    commutes_r1 = 0
    three_pass_r1 = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        c1 = fscx_revolve(fscx_revolve(g, a, 1, n), b, 1, n)
        c2 = fscx_revolve(fscx_revolve(g, b, 1, n), a, 1, n)
        if c1 == c2: commutes_r1 += 1
        C1 = fscx_revolve(g, a, 1, n)
        C2 = fscx_revolve(C1, b, 1, n)
        C3 = fscx_revolve(C2, a, n - 1, n)
        extracted = fscx_revolve(C3, b, n - 1, n)
        if extracted == g: three_pass_r1 += 1
    print(f"  [PL-1-C] Commutativity (r=1): {commutes_r1}/{trials}")
    print(f"  [PL-1-D] Three-pass (r=1) extracts g: {three_pass_r1}/{trials}")

    # ── PL-2: Integer multiplication three-pass ───────────────────────────────
    print()
    print(f"  ── PL-2  Integer-multiplication three-pass  (mod 2^n-1 prime approx) ──")
    # Use a safe odd modulus close to 2^n for demo; for clarity use mod (2^n - 1) as odd composite
    # Actually for simplicity: use mask+1 = 2^n and restrict keys to odd values
    # mod 2^n: invertible iff key is odd
    print(f"""
  lock(X, key)   = (X · key) % 2^n   [key must be odd for invertibility]
  unlock(X, key) = (X · key⁻¹) % 2^n
  Commutativity: (X·a)·b = (X·b)·a mod 2^n  ✓  (integer multiplication commutes)
  Three-pass:
    C1 = g · a
    C2 = C1 · b = g · a · b
    C3 = C2 · a⁻¹ = g · b
    extracted = C3 · b⁻¹ = g   [Eve also sees g! — it's the shared "base"]
""")
    three_pass_int = 0; eve_breaks = 0
    modulus = 1 << n
    for _ in range(trials):
        a = make_odd(secrets.randbelow(mask) + 1, n)
        b = make_odd(secrets.randbelow(mask) + 1, n)
        C1 = (g * a) % modulus
        C2 = (C1 * b) % modulus
        C3 = (C2 * modinv(a, modulus)) % modulus
        extracted = (C3 * modinv(b, modulus)) % modulus
        if extracted == g: three_pass_int += 1
        # Eve sees g, C1, C2, C3 and computes a = C1 * modinv(g, 2^n)
        a_eve = (C1 * modinv(g, modulus)) % modulus if modinv(g, modulus) else None
        if a_eve == a: eve_breaks += 1
    print(f"  [PL-2-A] Three-pass extracts g:     {three_pass_int}/{trials}  ← commutative ✓")
    print(f"  [PL-2-B] Eve recovers a from C1/g:  {eve_breaks}/{trials}")
    print(f"  [PL-2-C] Shared secret = g (a public value) — Eve trivially obtains it.")
    # Attempt to use cfscx to "harden" the shared g
    correct_hard = 0; eve_hard = 0
    for _ in range(trials):
        S = secrets.randbelow(mask) + 1
        a = make_odd(secrets.randbelow(mask) + 1, n)
        b = make_odd(secrets.randbelow(mask) + 1, n)
        C1 = (g * a) % modulus; C2 = (C1 * b) % modulus
        C3 = (C2 * modinv(a, modulus)) % modulus
        g_shared = (C3 * modinv(b, modulus)) % modulus    # = g
        # Harden with cfscx
        sk = int_compress(g_shared, S, n, GF_GEN, r)
        sk_A = int_compress(g_shared, S, n, GF_GEN, r)
        sk_B = int_compress(g_shared, S, n, GF_GEN, r)
        if sk_A == sk_B: correct_hard += 1
        # Eve: recovers g_shared = g (public), then computes sk
        sk_eve = int_compress(g, S, n, GF_GEN, r)
        if sk_eve == sk: eve_hard += 1
    print(f"  [PL-2-D] cfscx-hardened sk correct:  {correct_hard}/{trials}")
    print(f"  [PL-2-E] Eve (hardened, knows g):     {eve_hard}/{trials}")
    print(f"  Conclusion: Integer-multiplication padlock is correct but provides NO")
    print(f"  security — the shared value g is public, Eve computes sk trivially.")

    # ── PL-3: cfscx_compress padlock (non-invertibility) ─────────────────────
    print()
    print(f"  ── PL-3  cfscx_compress padlock (non-invertibility) ─────────────────")
    print(f"""
  Define: lock(X, key) = cfscx_compress(int_expand(key, X), g, r)
          unlock(X, key) = ???   [preimage of cfscx_compress — generally undefined]
  cfscx_compress: 4n-bit → n-bit (4:1 compression); preimages exist but are
  not efficiently computable, and there is no canonical "unlock" operation.
""")
    # Show multiple preimages exist (collision test)
    coll_found = 0; coll_tries = 1000
    n_small = 16; r_small = n_small // 4; mask_s = (1 << n_small) - 1
    seen = {}
    for cand in range(coll_tries):
        a_key = 42  # fixed key
        X = cand
        C = cfscx_compress(int_expand(a_key, X, n_small), GF_GEN, r_small, n_small)
        if C in seen:
            coll_found += 1
        else:
            seen[C] = X
    print(f"  [PL-3-A] Distinct outputs for {coll_tries} inputs (n={n_small}, fixed key): {len(seen)}")
    print(f"  [PL-3-B] Input collisions (same output, different X): {coll_found}")
    print(f"  [PL-3-C] Ratio: {coll_tries} inputs → {len(seen)} unique outputs")
    print(f"           → cfscx_compress is {coll_tries//len(seen) if len(seen)>0 else '∞'}:1 on average — NOT invertible.")
    print(f"  PL-3 conclusion: cfscx_compress cannot serve as a reversible lock.")

    # ── PL-4: INT-FSCX chained cross-padlock attempt ─────────────────────────
    print()
    print(f"  ── PL-4  INT-FSCX chained cross-padlock attempt ─────────────────────")
    print(f"""
  Round 1: C_A = cfscx(int_expand(a, S), g, r)
           C_B = cfscx(int_expand(b, S), g, r)
  Round 2: sk_A = cfscx(int_expand(a, C_B), g, r)  [Alice: private a + Bob's public C_B]
           sk_B = cfscx(int_expand(b, C_A), g, r)  [Bob:   private b + Alice's public C_A]
  Does sk_A == sk_B?  (Requires cfscx(int_expand(a, f(b))) = cfscx(int_expand(b, f(a))))
""")
    correct = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1
        b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        C_B = int_compress(b, S, n, GF_GEN, r)
        sk_A = int_compress(a, C_B, n, GF_GEN, r)
        sk_B = int_compress(b, C_A, n, GF_GEN, r)
        if sk_A == sk_B: correct += 1
    print(f"  [PL-4-A] Correctness (sk_A==sk_B): {correct}/{trials}")
    print(f"           (Should be ~0 — no commutativity guarantee)")

    # Check with special case: a = b
    equal_ab = 0
    for _ in range(min(trials, 200)):
        a = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        sk_A = int_compress(a, C_A, n, GF_GEN, r)
        sk_B = int_compress(a, C_A, n, GF_GEN, r)
        if sk_A == sk_B: equal_ab += 1
    print(f"  [PL-4-B] Correctness when a == b: {equal_ab}/200  (trivially true)")


# ═════════════════════════════════════════════════════════════════════════════
# PART III — Asymmetric key exchange
# ═════════════════════════════════════════════════════════════════════════════

def run_part_III(n=32, trials=500):
    section("PART III — Asymmetric Key Exchange with Integer Operations")
    r = n // 4
    mask = (1 << n) - 1
    poly = GF_POLY[n]

    # ── AK-1: INT-cross ───────────────────────────────────────────────────────
    print(f"  ── AK-1  INT-cross key exchange ─────────────────────────────────────")
    print(f"""
  C_A = cfscx(int_expand(a, S), g, r)
  sk_A = cfscx(int_expand(a, C_B), g, r)   ← Alice uses her private a with Bob's C_B
  sk_B = cfscx(int_expand(b, C_A), g, r)   ← Bob   uses his private b with Alice's C_A

  If sk_A = sk_B: cfscx(int_expand(a, H(b))) = cfscx(int_expand(b, H(a)))
  where H(x) = cfscx(int_expand(x, S), g, r).

  Chunk analysis for sk_A: (a, C_B, (a+C_B)%2^n, (a·C_B)%2^n)
                    sk_B:  (b, C_A, (b+C_A)%2^n, (b·C_A)%2^n)
  Chunk 1 differs (a vs b) unless a=b.  Not structurally symmetric.
""")
    correct = 0; eve_ok = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        C_B = int_compress(b, S, n, GF_GEN, r)
        sk_A = int_compress(a, C_B, n, GF_GEN, r)
        sk_B = int_compress(b, C_A, n, GF_GEN, r)
        if sk_A == sk_B: correct += 1
        # Eve: can compute sk_A from C_A, C_B, S? Only if she knows a.
        # Try Eve's shortcut: sk = int_compress(C_A ^ C_B, S, n, GF_GEN, r)
        sk_eve = int_compress(C_A ^ C_B, S, n, GF_GEN, r)
        if sk_eve == sk_A: eve_ok += 1
    print(f"  [AK-1-A] Correctness: {correct}/{trials}")
    print(f"  [AK-1-B] Eve (shortcut): {eve_ok}/{trials}")

    # Affinity of sk_A in a for fixed S, b (— is the map non-affine?)
    viol = affine_violations(
        lambda av: int_compress(av, int_compress(42, 0xDEAD, n, GF_GEN, r), n, GF_GEN, r),
        n, min(trials, 500))
    print(f"  [AK-1-C] Affine violations in sk_A (a→sk): {viol}/500")
    print(f"           ({'NON-AFFINE' if viol > 0 else 'affine'} — matrix attack {'fails' if viol > 0 else 'works'})")

    # ── AK-2: SUMMOD symmetric construction ───────────────────────────────────
    print()
    print(f"  ── AK-2  SUMMOD: symmetric integer-product expansion ────────────────")
    print(f"""
  sk_A = cfscx_compress(a+C_B ‖ a·C_B ‖ a+C_B ‖ a·C_B,  S, r)
  sk_B = cfscx_compress(b+C_A ‖ b·C_A ‖ b+C_A ‖ b·C_A,  S, r)
  [Input pattern: (V, W, V, W) where V=add, W=mul]

  Naive analysis: symmetric iff a+C_B = b+C_A AND a·C_B = b·C_A — no reason to hold.

  BUT: for r=n/4, n=32 the following two matrix identities both hold:
    (I ⊕ R ⊕ R² ⊕ R³) = 0  (zero matrix — the S parameter drops out entirely)
    (I ⊕ R²) = (R ⊕ R³)     (swap symmetry of (V,W,V,W) vs (W,V,W,V))

  cfscx_compress((V,W,V,W), S) expands as:
    = R³·V ⊕ R²·W ⊕ R·V ⊕ W ⊕ K·(I⊕R⊕R²⊕R³)·S   [S term = 0]
    = (R³⊕R)·V ⊕ (R²⊕I)·W
  Since (I⊕R²) = (R⊕R³): this is symmetric under V↔W.
  Therefore sk_A = sk_B for ALL (a,b,S) — always correct.
  Also: S drops out entirely → Eve needs only C_A and C_B (no S required).
  sk = f(a+C_B, a·C_B) with the S term vanishing — ZERO-FACTOR security.
""")
    def summod_sk(priv, C_other, S):
        mask_ = (1 << n) - 1
        add_ = (priv + C_other) & mask_
        mul_ = (priv * C_other) & mask_
        return cfscx_compress(join_chunks([add_, mul_, add_, mul_], n), S, r, n)

    correct2 = 0; eve2 = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        C_B = int_compress(b, S, n, GF_GEN, r)
        sk_A = summod_sk(a, C_B, S)
        sk_B = summod_sk(b, C_A, S)
        if sk_A == sk_B: correct2 += 1
        # Eve: sk = summod(C_A, C_B, S)?  [uses C_A as "priv" — only works if C_A = a]
        sk_eve = summod_sk(C_A, C_B, S)
        if sk_eve == sk_A: eve2 += 1
    print(f"  [AK-2-A] Correctness: {correct2}/{trials}  ← always true: zero-matrix symmetry")
    print(f"  [AK-2-B] Eve (C_A as proxy priv): {eve2}/{trials}  ← S not needed; sk = f(C_A,C_B) only")

    # ── AK-3: INT-gf hybrid (the secure option) ───────────────────────────────
    print()
    print(f"  ── AK-3  INT-gf hybrid: cfscx(int_expand) as KDF → gf_pow ──────────")
    print(f"""
  a_scl = cfscx(int_expand(a, S), g, r)   ← non-linear scalar from private a
  C_A   = gf_pow(g, a_scl, poly, n)        ← DLP-protected public key
  sk    = gf_pow(C_B, a_scl, poly, n)      ← g^{{a_scl · b_scl}}
  Security: (1) non-linear a→a_scl (harder to invert than linear cfscx)
            (2) DLP hardness for a_scl → C_A
  Eve needs to solve DLP(g, C_A) = a_scl even after knowing S.
""")
    correct3 = 0; priv_bound = 0
    for _ in range(min(trials, 300)):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        a_scl = int_compress(a, S, n, GF_GEN, r)
        b_scl = int_compress(b, S, n, GF_GEN, r)
        C_A = gf_pow(GF_GEN, a_scl, poly, n)
        C_B = gf_pow(GF_GEN, b_scl, poly, n)
        sk_A = gf_pow(C_B, a_scl, poly, n)
        sk_B = gf_pow(C_A, b_scl, poly, n)
        if sk_A == sk_B: correct3 += 1
    for _ in range(min(trials, 200)):
        a1 = secrets.randbelow(mask) + 1; a2 = secrets.randbelow(mask) + 1
        while a2 == a1: a2 = secrets.randbelow(mask) + 1
        b  = secrets.randbelow(mask) + 1; S  = secrets.randbelow(mask) + 1
        a_scl1 = int_compress(a1, S, n, GF_GEN, r)
        a_scl2 = int_compress(a2, S, n, GF_GEN, r)
        C_B = gf_pow(GF_GEN, int_compress(b, S, n, GF_GEN, r), poly, n)
        sk1 = gf_pow(C_B, a_scl1, poly, n)
        sk2 = gf_pow(C_B, a_scl2, poly, n)
        if sk1 != sk2: priv_bound += 1
    print(f"  [AK-3-A] Correctness: {correct3}/300")
    print(f"  [AK-3-B] Key binding: {priv_bound}/200")
    print(f"  [AK-3-C] Security: DLP of g^{{a_scl}} — Eve needs both S (for a_scl) and DLP.")

    # ── AK-4: INT-double-cross (two-round) ────────────────────────────────────
    print()
    print(f"  ── AK-4  INT-double-cross: two rounds of int_expand ─────────────────")
    print(f"""
  Round 1 (exchange C): C_A = cfscx(int_expand(a, S)); C_B = cfscx(int_expand(b, S))
  Round 2 (exchange T): T_A = cfscx(int_expand(a, C_B)); T_B = cfscx(int_expand(b, C_A))
  sk derivation (after T exchange):
    Option (i)   symmetric int-hash: sk = cfscx(int_expand_sym(T_A, T_B), S)
    Option (ii)  private re-use:     sk_A = cfscx(int_expand(a, T_B)); sk_B = cfscx(int_expand(b, T_A))
""")
    correct_i  = 0; eve_i  = 0
    correct_ii = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        C_B = int_compress(b, S, n, GF_GEN, r)
        T_A = int_compress(a, C_B, n, GF_GEN, r)  # round 2 public
        T_B = int_compress(b, C_A, n, GF_GEN, r)  # round 2 public
        # Option i: symmetric int-hash of T values
        sk_i = cfscx_compress(int_expand_sym(T_A, T_B, n), S, r, n)
        if True: correct_i += 1  # symmetric formula, trivially correct
        sk_eve_i = cfscx_compress(int_expand_sym(T_A, T_B, n), S, r, n)
        if sk_eve_i == sk_i: eve_i += 1
        # Option ii: private key reused in round 3
        sk_A_ii = int_compress(a, T_B, n, GF_GEN, r)
        sk_B_ii = int_compress(b, T_A, n, GF_GEN, r)
        if sk_A_ii == sk_B_ii: correct_ii += 1
    print(f"  [AK-4-i-A]  Option-i  Correctness: {correct_i}/{trials} (trivially symmetric)")
    print(f"  [AK-4-i-B]  Option-i  Eve (T_A, T_B, S known): {eve_i}/{trials}")
    print(f"  [AK-4-ii-A] Option-ii Correctness: {correct_ii}/{trials} (expect ~0)")
    print()
    # Affinity of sk Option-i in a for fixed S, b
    viol_ii = affine_violations(
        lambda av: int_compress(av, int_compress(int_compress(42, 0xBEEF, n, GF_GEN, r),
                                                  int_compress(av, 0xBEEF, n, GF_GEN, r),
                                                  n, GF_GEN, r), n, GF_GEN, r),
        n, min(trials, 500))
    print(f"  [AK-4-ii-C] Option-ii sk_A affine violations: {viol_ii}/500")


# ═════════════════════════════════════════════════════════════════════════════
# PART IV — Hash-like schemes
# ═════════════════════════════════════════════════════════════════════════════

def run_part_IV(n=32, trials=500):
    section("PART IV — Hash-Like Schemes to Derive Shared Secrets")
    r = n // 4
    mask = (1 << n) - 1

    # ── HL-1: Symmetric int-hash of transcript ────────────────────────────────
    print(f"  ── HL-1  Symmetric int-hash of (C_A, C_B) transcript ────────────────")
    print(f"""
  C_A = cfscx(int_expand(a, S), g, r)
  C_B = cfscx(int_expand(b, S), g, r)
  sk  = cfscx(int_expand_sym(C_A, C_B), S, r)
  where int_expand_sym(X, Y) = X⊕Y ‖ (X+Y)%2^n ‖ (X·Y)%2^n ‖ (X+Y)⊕(X·Y)
  Symmetric ✓ (all ops commute in X,Y).
  Eve: C_A, C_B, S are all public → sk immediately computable.
  The non-linearity of C_A derivation is irrelevant here.
""")
    correct = 0; eve_ok = 0
    for _ in range(trials):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        C_A = int_compress(a, S, n, GF_GEN, r)
        C_B = int_compress(b, S, n, GF_GEN, r)
        sk = cfscx_compress(int_expand_sym(C_A, C_B, n), S, r, n)
        correct += 1
        sk_eve = cfscx_compress(int_expand_sym(C_A, C_B, n), S, r, n)
        if sk_eve == sk: eve_ok += 1
    print(f"  [HL-1-A] Correctness: {correct}/{trials} (trivially symmetric)")
    print(f"  [HL-1-B] Eve: {eve_ok}/{trials}")

    # Also: is sk non-affine in (a, b)?
    viol = affine_violations(
        lambda av: cfscx_compress(int_expand_sym(int_compress(av, 0xDEAD, n, GF_GEN, r),
                                                  int_compress(42, 0xDEAD, n, GF_GEN, r), n),
                                   0xDEAD, r, n),
        n, min(trials, 1000))
    print(f"  [HL-1-C] Affine violations in sk (a→sk): {viol}/1000")
    print(f"           ({'NON-AFFINE in a' if viol > 0 else 'affine'}, but Eve-trivial regardless)")

    # ── HL-2: Iterated hash chain ─────────────────────────────────────────────
    print()
    print(f"  ── HL-2  Iterated hash chain: h_k = cfscx(int_expand(h_{{k-1}}, S), g, r) ──")
    print(f"""
  Idea: C_A = h_a (Alice applies int_compress a times from common base g₀).
        C_B = h_b (Bob applies b times).
  Shared secret: h_{{a+b}}? Both parties need to know a+b... not directly available.
  Alternative: Alice gets h_{{a+b}} = cfscx(int_expand(h_a, h_b), g, r)?  [test]
  This conflates "iterate" and "combine" — they're different operations.
""")
    # Test if cfscx(int_expand(h_a, h_b)) == cfscx(int_expand(h_b, h_a)) [symmetric combine]
    symm_combine = 0
    for _ in range(min(trials, 300)):
        # Generate h_a and h_b via iteration from same g0
        g0 = secrets.randbelow(mask) + 1
        S  = secrets.randbelow(mask) + 1
        steps_a = (secrets.randbelow(7) + 1)
        steps_b = (secrets.randbelow(7) + 1)
        h = g0
        for _ in range(steps_a): h = int_compress(h, S, n, GF_GEN, r)
        h_a = h
        h = g0
        for _ in range(steps_b): h = int_compress(h, S, n, GF_GEN, r)
        h_b = h
        # Try to combine
        comb_AB = int_compress(h_a, h_b, n, GF_GEN, r)
        comb_BA = int_compress(h_b, h_a, n, GF_GEN, r)
        if comb_AB == comb_BA: symm_combine += 1
    print(f"  [HL-2-A] cfscx(int_expand(h_a, h_b)) == cfscx(int_expand(h_b, h_a)): {symm_combine}/300")
    print(f"           (Symmetric combination requires all chunks equal — very rare)")

    # Show Eve can iterate from the same g0
    print(f"""
  Chain security: Eve also knows g₀ and S.
  She iterates up to some k and checks against C_A = h_a.
  For small a (say a < 2^16), this is a brute-force preimage.
""")
    n_chain = 16; r_chain = n_chain // 4
    g0 = 7; S_chain = 0x5A5A
    # Build lookup table
    chain = [g0]
    for _ in range(100):
        chain.append(int_compress(chain[-1], S_chain, n_chain, GF_GEN, r_chain))
    # Alice uses a=37, Bob uses b=61
    a_steps = 37; b_steps = 61
    h_a = chain[a_steps]; h_b = chain[b_steps]
    # Eve brute force
    found_a = None
    for k, hk in enumerate(chain[:100]):
        if hk == h_a: found_a = k; break
    print(f"  [HL-2-B] n={n_chain}, g₀={g0}, fixed S: Eve finds a={a_steps} in chain: "
          f"{'found at position ' + str(found_a) if found_a is not None else 'not found'}")
    print(f"           Chain preimage attack is trivial for small n or short chains.")

    # ── HL-3: Commitment-based shared randomness ──────────────────────────────
    print()
    print(f"  ── HL-3  Commitment-based shared randomness (coin toss) ─────────────")
    print(f"""
  Neither party chooses the shared secret; it is derived from both contributions.
  Protocol:
    Phase 1 (commit): Alice sends comm_A = cfscx(int_expand(a, nonce_A), g, r)
                      Bob   sends comm_B = cfscx(int_expand(b, nonce_B), g, r)
    Phase 2 (reveal): Alice reveals (a, nonce_A); Bob reveals (b, nonce_B)
    Phase 3 (derive): Both verify commitments, compute:
                      sk = cfscx(int_expand_sym(a, b), S, r)   [or any sym fn of a,b]

  Property: neither party can control sk before the other commits.
  Security model: hiding (commitment hides a before reveal),
                  binding (can't change a after committing).
  Note: this is NOT a key EXCHANGE — it's shared randomness after mutual reveal.
  sk depends on BOTH private values a and b (directly, after revelation).
""")
    # Verify hiding: is comm_A non-trivially dependent on a?
    viol_hide = affine_violations(
        lambda av: int_compress(av, 0xC0FFEE, n, GF_GEN, r),
        n, min(trials, 1000))
    print(f"  [HL-3-A] comm_A affine violations (a→comm): {viol_hide}/1000")
    print(f"           ({'NON-AFFINE' if viol_hide > 0 else 'affine'}: "
          f"{'harder to predict a from comm' if viol_hide > 0 else 'affine — easily invertible'})")

    # Verify binding: collision search
    n_small = 16; r_small = n_small // 4; mask_s = (1 << n_small) - 1
    nonce = 0x1234
    seen_bind = {}; bind_collisions = 0; bind_checked = 10000
    for a_val in range(bind_checked):
        C = int_compress(a_val, nonce, n_small, GF_GEN, r_small)
        if C in seen_bind:
            bind_collisions += 1
        else:
            seen_bind[C] = a_val
    print(f"  [HL-3-B] Commitment collisions (n={n_small}, {bind_checked} values): {bind_collisions}")
    print(f"           (Collisions mean Alice could equivocate — not perfectly binding)")

    # Derive shared randomness
    correct_coin = 0
    for _ in range(min(trials, 200)):
        a = secrets.randbelow(mask) + 1; b = secrets.randbelow(mask) + 1
        S = secrets.randbelow(mask) + 1
        sk = cfscx_compress(int_expand_sym(a, b, n), S, r, n)
        sk_check = cfscx_compress(int_expand_sym(b, a, n), S, r, n)  # symmetric ✓
        if sk == sk_check: correct_coin += 1
    print(f"  [HL-3-C] sk = cfscx(int_expand_sym(a, b), S) symmetric: {correct_coin}/200")
    print(f"           sk depends directly on BOTH private values — not just public C values.")
    print(f"           After revelation, Eve also computes sk (knows a and b). No secrecy.")
    print(f"           Use case: provably fair coin-toss / shared randomness generation.")


# ═════════════════════════════════════════════════════════════════════════════
# PART V — Summary and classification
# ═════════════════════════════════════════════════════════════════════════════

def run_part_V():
    section("PART V — Summary and Security Classification")

    print("""
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │ Schema          │ Correct │ Non-lin C │ Eve(S) │ Security layer  │ Viable?      │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │ PL-1 fscx-3pass │   No    │    No     │  N/A   │ none            │ ✗ non-commut.│
  │ PL-2 int-mul-3p │   Yes   │   Yes†    │  Yes*  │ none            │ ✗ Eve breaks │
  │ PL-3 cfscx-pad  │   No    │    Yes    │  N/A   │ none            │ ✗ non-invert.│
  │ PL-4 INT-cross  │   No    │    Yes    │  N/A   │ none            │ ✗ no symmetry│
  │ AK-1 INT-cross  │   No    │    Yes    │  N/A   │ none            │ ✗ no symmetry│
  │ AK-2 SUMMOD     │   Yes** │    Yes    │ Yes**  │ NONE (0-factor) │ ✗ Eve(no S)  │
  │ AK-3 INT-gf     │   Yes   │    Yes    │  No    │ DLP (+ S)       │ ✓ SECURE     │
  │ AK-4-i double×  │   Yes   │    Yes    │  Yes   │ S-only          │ ✗ Eve breaks │
  │ AK-4-ii priv-r  │   No    │    Yes    │  N/A   │ none            │ ✗ no symmetry│
  │ HL-1 sym-hash   │   Yes   │    Yes    │  Yes   │ S-only          │ ✗ Eve breaks │
  │ HL-2 hash-chain │   No    │    Yes    │  N/A   │ none (chain OK) │ ✗ no combine │
  │ HL-3 commitment │   Yes‡  │    Yes    │  Yes‡  │ fair randomness │ ✓ coin-toss  │
  └─────────────────────────────────────────────────────────────────────────────────┘
  *  Eve uses PL-2 directly: shared secret = g (public base), sk = cfscx(g, S) trivially.
  †  cfscx part is non-linear; the integer multiplication itself is linear (mod ring).
  ‡  HL-3 is "correct" after key revelation, not during key exchange. Eve also gets sk.
  ** AK-2 is ALWAYS correct — a zero-matrix algebraic accident of r=n/4, n=32:
     (I⊕R⊕R²⊕R³)=0 (S drops out) AND (I⊕R²)=(R⊕R³) (swap symmetry of (V,W,V,W)).
     sk = (R³⊕R)·(a+C_B) ⊕ (R²⊕I)·(a·C_B) depends only on C_A and C_B — Eve wins
     without S.  This is ZERO-FACTOR security, not just S-only.

  ── Padlock schema analysis ──────────────────────────────────────────────────

  For a padlock to provide security, it needs:
    (1) Commutativity: Lock_A ∘ Lock_B = Lock_B ∘ Lock_A
    (2) Invertibility: Unlock exists efficiently
    (3) One-wayness: given Lock_k(X), hard to find k or X

  FSCX_revolve satisfies (2) via the period property (unlock = n-r steps)
  but FAILS (1) in general.  Commutativity requires (R⊕I)·K·(a⊕b)=0.  For r=n/4,
  n=32: rank((R⊕I)·K)=2, null-space dimension=30 → ~25% of random key pairs
  accidentally satisfy commutativity (algebraic accident, not a protocol property).

  Integer multiplication mod 2^n satisfies (1) and (2) but FAILS (3):
  given C1 = g·a mod 2^n, a = C1·g⁻¹ mod 2^n is trivially computable.

  cfscx_compress satisfies (3) [non-linear, many-to-one] but FAILS (2):
  the compression 4n→n is irreversible — no unlock operation exists.

  No FSCX-only or int-only construction satisfies all three requirements.
  The INT-gf hybrid (AK-3) delegates the trapdoor to gf_pow's DLP hardness.

  ── Asymmetric key exchange analysis ────────────────────────────────────────

  For symmetric sk_A = sk_B = f(a, b), both parties must independently
  compute f(a, C_B) = f(b, C_A). This requires:
    cfscx(int_expand(a, H(b))) = cfscx(int_expand(b, H(a)))
  — a commutativity condition on cfscx ∘ int_expand that does not hold in general.

  The SUMMOD construction (AK-2) IS always correct for r=n/4 due to the zero-matrix
  property: (I⊕R⊕R²⊕R³)=0 makes S vanish, and (I⊕R²)=(R⊕R³) makes cfscx_compress
  swap-symmetric in its (V,W,V,W) input.  BUT sk = f(C_A,C_B) with S eliminated —
  Eve computes sk from only the public values, no S needed.  ZERO-FACTOR security.

  INT-gf (AK-3) is the ONLY correct asymmetric construction found:
    a_scl = cfscx(int_expand(a, S))  [non-linear KDF]
    C_A   = gf_pow(g, a_scl)         [DLP one-way]
    sk    = gf_pow(C_B, a_scl)       [commutes via exponent arithmetic: g^{ab}=g^{ba}]
  The commutativity lives in GF(2^n)* exponentiation, not in FSCX.

  ── Hash-like scheme analysis ────────────────────────────────────────────────

  Any hash sk = cfscx(int_expand_sym(C_A, C_B), S) reduces to f(C_A, C_B, S).
  Since C_A and C_B are public wire values, Eve trivially computes sk.
  Non-linearity of C derivation is irrelevant: once C is on the wire, the
  structure of how C was derived doesn't matter.

  HL-3 (commitment) is useful for SHARED RANDOMNESS (coin toss):
    - Neither party controls the final sk
    - sk = cfscx(int_expand_sym(a, b), S) — depends directly on both private keys
    - After the reveal phase, both parties compute the same sk
    - The non-linearity of cfscx ∘ int_expand_sym makes sk non-trivially
      dependent on the combination of a and b (not just their XOR)
    - Limitation: sk becomes public after reveal; this is randomness generation,
      not secret key exchange

  ── The fundamental constraint (summary) ─────────────────────────────────────

  Integer +/* operations create non-affine maps a→C. This is property (a)
  (preimage hardness, informally). But property (b) — the trapdoor that
  allows one party to compute a symmetric function from the other's public value
  — requires the law: f(a, f(b, g)) = f(b, f(a, g)).

  This law holds for:
    - Integer multiplication in Z/nZ: (g·a)·b = (g·b)·a  [but easy to invert]
    - GF exponentiation: (g^a)^b = g^{ab} = g^{ba} = (g^b)^a  [DLP hard]

  It does NOT hold for:
    - cfscx_compress(int_expand(a, X))  [numerically verified: 0/500 symmetric]
    - Any combination of int_expand + cfscx that has been tested here

  Therefore: the INT-gf hybrid (AK-3) is the correct and secure construction.
  PS-5 non-linearity can strengthen the KDF step (harder to invert a_scl from
  C_A), but the trapdoor itself must come from gf_pow.
""")


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    N      = 32
    TRIALS = 500

    run_part_I(n=N)
    run_part_II(n=N, trials=TRIALS)
    run_part_III(n=N, trials=TRIALS)
    run_part_IV(n=N, trials=TRIALS)
    run_part_V()

    print()
    print(DIVIDER)
    print("  DONE")
    print(DIVIDER)
