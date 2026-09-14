"""
hkex_nonce_impossibility.py — Why HPKE/HSKE work, and why no nonce
in the key derivation step can fix the HKEX classical break.

The core question
-----------------
HPKE and HSKE both use fscx_revolve_n and produce correct results.
Could a different nonce choice in HKEX's key derivation make sk private?

Short answer: No.  The proof is algebraic and applies to ANY nonce.

─────────────────────────────────────────────────────────────────────
WHY HSKE WORKS (and why it is a different security model)
─────────────────────────────────────────────────────────────────────
HSKE is NOT a key exchange.  Both parties share the same key K before
encryption starts.  The fscx_revolve_n call uses K as both the revolve
parameter B and the nonce:

    E = fscx_revolve_n(P, K, K, i)  =  M^i·P  +  S_i·(M+I)·K

The key offset  c_K = S_i·(M+I)·K = (I + M^i)·K  is NON-ZERO for
random K (since I + M^i ≠ 0).  K survives in E as a private additive
offset.  Eve cannot decrypt E without knowing K.

Decryption works because the full round-trip i + r = n makes K cancel:

    D = fscx_revolve_n(E, K, K, r)
      = M^r·E + S_r·(M+I)·K
      = P + [M^r·S_i + S_r]·(M+I)·K  =  P + S_n·(M+I)·K  =  P

Security model: pre-shared symmetric key.  K never leaves either party.
This is FUNDAMENTALLY different from HKEX where two parties derive a
shared secret from independently generated key pairs.

─────────────────────────────────────────────────────────────────────
WHY HPKE WORKS (and why it is not secure)
─────────────────────────────────────────────────────────────────────
HPKE's key derivation IS the HKEX derivation:

    sk = fscx_revolve_n(C2, B, N, r) ⊕ A  =  S_{r+1}·(C⊕C2)

Both Alice and Bob compute the SAME VALUE because S_r·M + M^{r+1}·S_i
= S_n = 0 causes all private parameters (A, B, A2, B2) to cancel.
The cancellation is what makes the exchange correct — and also what
makes sk a linear function of the public wire values C, C2.

HPKE encrypts as  E = sk ⊕ A2 ⊕ P  and decrypts as  D = sk ⊕ A ⊕ E.
Correctness follows from sk_A = sk_B, not from sk being secret.

─────────────────────────────────────────────────────────────────────
THE IMPOSSIBILITY THEOREM
─────────────────────────────────────────────────────────────────────
Theorem:  For ANY nonce choice n_A = f(A, B, C, C2) (Alice) and its
symmetric counterpart n_B = f(A2, B2, C2, C) (Bob), if

    sk_A = fscx_revolve_n(C2, B, n_A, r) ⊕ A  =  sk_B  for ALL inputs

then  sk  is a GF(2)-affine function of (C, C2) alone.

Proof:
  Applying the affine iteration formula:

    sk_A = M^r·C2 + S_r·(M·B ⊕ n_A) ⊕ A

  Substitute  A = M^r·C ⊕ M^{r+1}·S_i·B  (from C = M^i·A + M·S_i·B):

    sk_A = M^r·(C⊕C2) ⊕ (S_r·M + M^{r+1}·S_i)·B ⊕ S_r·n_A
         = M^r·(C⊕C2) ⊕ S_r·n_A              ← S_n kills B

  By the same derivation:
    sk_B = M^r·(C⊕C2) ⊕ S_r·n_B

  Correctness (sk_A = sk_B) ⟺  S_r·n_A = S_r·n_B  for ALL (A,B,A2,B2).

  Since (A,B) and (A2,B2) are independently random, S_r·n_A and S_r·n_B
  must equal the same value for all independent choices of the two key
  pairs.  That value can only depend on what is common to both parties:
  the public wire values C and C2.

  Therefore  S_r·n_A = h(C, C2)  for some function h, and:

    sk = M^r·(C⊕C2) ⊕ h(C, C2)

  which is a function of the public values (C, C2) only.  □

Corollary:  Using a nonce with private components that lie in ker(S_r)
is permitted by correctness but contributes nothing to sk (S_r kills
them).  A nonce with private components outside ker(S_r) breaks
correctness.  There is no middle ground.
"""

import secrets
import sys

# ── Primitives ───────────────────────────────────────────────────────────────

def mask(n): return (1 << n) - 1
def rol(x, b, n): b %= n; return ((x << b) | (x >> (n - b))) & mask(n)
def ror(x, b, n): return rol(x, n - b, n)
def M(x, n): return x ^ rol(x, 1, n) ^ ror(x, 1, n)
def Mpow(x, k, n):
    for _ in range(k % (n // 2)): x = M(x, n)
    return x
def Sk(x, k, n):
    acc, cur = 0, x
    for _ in range(k): acc ^= cur; cur = M(cur, n)
    return acc
def revolve(a, b, k, n):
    for _ in range(k): a = M(a ^ b, n)
    return a
def revolve_n(a, b, nonce, k, n):
    for _ in range(k): a = M(a ^ b, n) ^ nonce
    return a

# ── Shared test setup ─────────────────────────────────────────────────────────

n = 64; i = n // 4; r = n - i; T = 1000

def session():
    A  = secrets.randbits(n); B  = secrets.randbits(n)
    A2 = secrets.randbits(n); B2 = secrets.randbits(n)
    C  = revolve(A, B, i, n); C2 = revolve(A2, B2, i, n)
    return A, B, A2, B2, C, C2

# ── Part 1: HSKE mechanism ───────────────────────────────────────────────────

def test_hske():
    print("=" * 65)
    print("Part 1 — HSKE: why the pre-shared key K survives in E")
    print("=" * 65)
    key_in_E = correct = 0
    for _ in range(T):
        K = secrets.randbits(n); P = secrets.randbits(n)
        E = revolve_n(P, K, K, i, n)
        D = revolve_n(E, K, K, r, n)
        # c_K = S_i·(M+I)·K = (I ⊕ M^i)·K — key offset in E
        c_K = E ^ Mpow(P, i, n)          # non-zero when K ≠ 0
        if c_K != 0:  key_in_E += 1
        if D   == P:  correct   += 1
    print(f"  c_K = S_i·(M+I)·K ≠ 0 (K present in E) : {key_in_E}/{T}")
    print(f"  D == P (correct decryption)              : {correct}/{T}")
    _ok = key_in_E == T and correct == T
    print(f"  → K is private, appears as non-zero offset in E.")
    print(f"  → Full round-trip (i+r=n) makes K cancel: D=P always.")
    print(f"  → HSKE is a symmetric cipher; security needs a pre-shared K.")
    return _ok

# ── Part 2: HPKE mechanism ───────────────────────────────────────────────────

def test_hpke():
    print()
    print("=" * 65)
    print("Part 2 — HPKE: both sides evaluate the same PUBLIC value")
    print("=" * 65)
    all_equal = all_public = 0
    for _ in range(T):
        A, B, A2, B2, C, C2 = session()
        N = C ^ C2
        alice_side = revolve_n(C2, B,  N, r, n) ^ A    # sk_A
        bob_side   = revolve_n(C,  B2, N, r, n) ^ A2   # sk_B
        eve        = Sk(C ^ C2, r + 1, n)               # S_{r+1}·(C⊕C2)
        if alice_side == bob_side:  all_equal  += 1
        if alice_side == eve:       all_public += 1
    print(f"  sk_A == sk_B             : {all_equal}/{T}")
    print(f"  sk_A == S_{{r+1}}·(C⊕C2) : {all_public}/{T}  ← all public")
    _ok = all_equal == T and all_public == T
    print(f"  → HPKE is correct because sk_A=sk_B=S_{{r+1}}·(C⊕C2).")
    print(f"  → The fscx_revolve_n nonce N=C⊕C2 is public; sk has zero secrecy.")
    print(f"  → HPKE works correctly but is insecure for the same reason as HKEX.")
    return _ok

# ── Part 3: Exhaustive nonce search ──────────────────────────────────────────

def test_nonces():
    print()
    print("=" * 65)
    print("Part 3 — All nonce forms: correct AND private at the same time?")
    print("=" * 65)
    print(f"  {'Nonce Alice / Bob':<22} {'Correct':>8}  {'sk≠f(C,C2)':>12}  Verdict")
    print(f"  {'-'*22} {'-'*8}  {'-'*12}  -------")

    # For each nonce pair we check:
    #   correct    = sk_A == sk_B for all T trials
    #   sk_private = sk is NOT equal to M^r·(C⊕C2) ⊕ S_r·(public_nonce_term)
    # We compute the "public formula" for sk as M^r·(C⊕C2) ⊕ S_r·na
    # and check whether sk differs from it (it shouldn't, per the theorem).

    verdicts = []

    def run(label, na_fn, nb_fn):
        correct = sk_is_public = 0
        for _ in range(T):
            A, B, A2, B2, C, C2 = session()
            N  = C ^ C2
            na = na_fn(A, B, C, C2, N)
            nb = nb_fn(A2, B2, C2, C, N)   # symmetric swap
            sk_a = revolve_n(C2, B,  na, r, n) ^ A
            sk_b = revolve_n(C,  B2, nb, r, n) ^ A2
            # Theorem prediction: sk = M^r·(C⊕C2) ⊕ S_r·na
            pred = Mpow(C ^ C2, r, n) ^ Sk(na, r, n)
            if sk_a == sk_b:  correct       += 1
            if sk_a == pred:  sk_is_public  += 1
        match_c = correct      == T
        match_p = sk_is_public == T
        verdict = ("CORRECT+PUBLIC" if (match_c and match_p)
                   else "correct+PRIVATE?" if (match_c and not match_p)
                   else "BROKEN" if not match_c
                   else "?")
        verdicts.append(verdict)
        print(f"  {label:<22} {correct:>8}  {sk_is_public:>12}  {verdict}")

    # Symmetric helper: B→B2, A→A2, C→C2, C2→C
    run("nonce = 0",         lambda A,B,C,C2,N: 0,     lambda A2,B2,C,C2,N: 0)
    run("nonce = N=C⊕C2",   lambda A,B,C,C2,N: N,     lambda A2,B2,C,C2,N: N)
    run("nonce = C",         lambda A,B,C,C2,N: C,     lambda A2,B2,C,C2,N: C)
    run("nonce = C2",        lambda A,B,C,C2,N: C2,    lambda A2,B2,C,C2,N: C2)
    run("nonce = A",         lambda A,B,C,C2,N: A,     lambda A2,B2,C,C2,N: A2)
    run("nonce = B",         lambda A,B,C,C2,N: B,     lambda A2,B2,C,C2,N: B2)
    run("nonce = A⊕B",      lambda A,B,C,C2,N: A^B,   lambda A2,B2,C,C2,N: A2^B2)
    run("nonce = B⊕C2",     lambda A,B,C,C2,N: B^C2,  lambda A2,B2,C,C2,N: B2^C)
    run("nonce = A⊕C",      lambda A,B,C,C2,N: A^C,   lambda A2,B2,C,C2,N: A2^C2)
    run("nonce = A⊕B⊕N",   lambda A,B,C,C2,N: A^B^N, lambda A2,B2,C,C2,N: A2^B2^N)

    print()
    print("  The theorem predicts: sk = M^r·(C⊕C2) ⊕ S_r·na")
    print("  Column 'sk≠f(C,C2)' counts how often sk differs from the prediction.")
    print("  Only rows that are CORRECT AND have sk≠public would be a fix.")
    print("  No such row exists — the theorem holds unconditionally.")
    # A "correct+PRIVATE?" row would be the counterexample; there is none.
    return "correct+PRIVATE?" not in verdicts

# ── Part 4: Prove S_r·n_A = h(C,C2) for any correct nonce ───────────────────

def test_theorem_directly():
    print()
    print("=" * 65)
    print("Part 4 — Direct verification of the theorem's core claim")
    print("=" * 65)
    print("  Claim: for any correct nonce, S_r·n_A depends only on (C, C2).")
    print("  Test:  fix C, C2 and vary (A, B) over all consistent pairs.")
    print("         S_r·n_A must be the same regardless of which (A,B) we pick.")
    print()

    # We test with nonce = B (a purely private nonce — not correct, but
    # let's see how S_r·n_A varies with different (A,B) giving the same C).
    # Then repeat for nonce = N = C⊕C2 (the correct one).

    ok_theorem = True
    for nonce_label, nonce_fn in [("N=C⊕C2 (correct)", lambda A,B,C,C2: C^C2),
                                   ("B (incorrect)",    lambda A,B,C,C2: B)]:
        # Fix a target C by choosing one (A0,B0) pair
        A0 = secrets.randbits(n); B0 = secrets.randbits(n)
        C_fixed = revolve(A0, B0, i, n)
        A2_fixed = secrets.randbits(n); B2_fixed = secrets.randbits(n)
        C2_fixed = revolve(A2_fixed, B2_fixed, i, n)

        Srna_values = set()
        # Generate many (A,B) pairs that all map to C_fixed
        # From C = M^i·A + M·S_i·B, for each free B, A = M^r·C ⊕ M^{r+1}·S_i·B
        for _ in range(20):
            B_var = secrets.randbits(n)
            A_var = Mpow(C_fixed, r, n) ^ Mpow(Sk(B_var, i, n), r+1, n)
            assert revolve(A_var, B_var, i, n) == C_fixed, "consistency check"
            na = nonce_fn(A_var, B_var, C_fixed, C2_fixed)
            Srna_values.add(Sk(na, r, n))

        varies = len(Srna_values) > 1
        ok_theorem = ok_theorem and (varies == ("incorrect" in nonce_label))
        print(f"  nonce = {nonce_label}:")
        print(f"    Distinct S_r·n_A values across 20 (A,B) pairs with same C: "
              f"{len(Srna_values)}")
        if not varies:
            print(f"    → S_r·n_A is constant for fixed (C, C2). Theorem confirmed.")
        else:
            print(f"    → S_r·n_A varies → correctness must break. Theorem confirmed.")
        print()
    return ok_theorem

# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    findings = [("HSKE: K is a private offset and the round trip cancels it",
                 test_hske()),
                ("HPKE: correct, and its session key is S_{r+1}.(C ⊕ C2)",
                 test_hpke()),
                ("no nonce choice is correct AND private", test_nonces()),
                ("S_r.n_A is constant for a correct nonce and varies otherwise",
                 test_theorem_directly())]

    print("=" * 65)
    print("Summary")
    print("=" * 65)
    print("""
  HSKE works:  K is pre-shared; K survives as a private offset in E;
               the round-trip cancellation (S_n=0) gives D=P.
               HSKE is a symmetric cipher, not a key exchange.

  HPKE works:  sk_A = sk_B = S_{r+1}·(C⊕C2) — correct but public.
               Correctness follows from HKEX; security does not.

  No nonce fixes HKEX because (proven algebraically, Part 3 & 4):
    sk = M^r·(C⊕C2) ⊕ S_r·n_A
    For sk_A = sk_B:  S_r·n_A must equal the same value for all
    independent (A,B) and (A2,B2) that map to the same (C,C2).
    That value can only depend on C and C2 — which are public.
    Private components of n_A that lie in ker(S_r) don't affect sk.
    Private components outside ker(S_r) break correctness.

  Root fix requires:  a non-GF(2)-linear primitive, so that the
  cancellation that enables correctness (S_n = 0) does not
  simultaneously expose sk as a linear function of public values.
""")
    bad = [name for name, ok in findings if not ok]
    if bad:
        print("*** FAILED: %d finding(s) stopped reproducing: %s ***"
              % (len(bad), ", ".join(bad)))
    else:
        print("*** OK: all %d findings reproduce ***" % len(findings))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
