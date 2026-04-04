"""
hkex_classical_break.py — Experimental proof that the HKEX shared secret
is directly computable from the two public values (C, C2) alone.

Theorem (proved in PQCanalysis.md):

    sk  =  S_{r+1} · (C ⊕ C2)
        =  (C ⊕ C2)  ⊕  M·(C ⊕ C2)  ⊕  M²·(C ⊕ C2)  ⊕  …  ⊕  Mʳ·(C ⊕ C2)

where M = I + ROL + ROR  (the FSCX linear operator),  r = 3n/4,
and S_{r+1} is a fully public, fixed linear operator.

Eve observes only C and C2 (the values exchanged over the wire).
She never sees A, B, A2, B2.  She still recovers sk exactly.

This script:
  1. Runs 10 000 random HKEX sessions (varied bit widths).
  2. For each session Eve computes sk_eve = S_{r+1}·(C ⊕ C2).
  3. Verifies sk_eve == sk_alice == sk_bob for every trial.
"""

import secrets
import sys


# ---------------------------------------------------------------------------
# Primitive: n-bit integers with cyclic rotation
# ---------------------------------------------------------------------------

def rol(x: int, bits: int, n: int) -> int:
    """Rotate x left by `bits` positions in an n-bit word."""
    bits %= n
    return ((x << bits) | (x >> (n - bits))) & ((1 << n) - 1)

def ror(x: int, bits: int, n: int) -> int:
    return rol(x, n - bits, n)

def M(x: int, n: int) -> int:
    """Apply the FSCX linear operator M = I + ROL(1) + ROR(1)."""
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)

def fscx(a: int, b: int, n: int) -> int:
    return M(a ^ b, n)           # M·(A⊕B)  — same as existing implementation

def fscx_revolve(a: int, b: int, steps: int, n: int) -> int:
    for _ in range(steps):
        a = fscx(a, b, n)
    return a

def fscx_revolve_n(a: int, b: int, nonce: int, steps: int, n: int) -> int:
    for _ in range(steps):
        a = fscx(a, b, n) ^ nonce
    return a


# ---------------------------------------------------------------------------
# Legitimate HKEX: Alice + Bob
# ---------------------------------------------------------------------------

def hkex_alice_bob(n: int):
    """
    Full honest HKEX session.
    Returns (C, C2, sk_alice, sk_bob, A, B, A2, B2)  — private keys included
    so the caller can verify correctness.
    """
    mask = (1 << n) - 1
    i = n // 4
    r = n - i                          # i + r = n

    A  = secrets.randbits(n)
    B  = secrets.randbits(n)
    A2 = secrets.randbits(n)
    B2 = secrets.randbits(n)

    # --- key exchange ---
    C  = fscx_revolve(A,  B,  i, n)   # Alice publishes C
    C2 = fscx_revolve(A2, B2, i, n)   # Bob   publishes C2
    N  = C ^ C2                        # public nonce

    sk_alice = fscx_revolve_n(C2, B,  N, r, n) ^ A
    sk_bob   = fscx_revolve_n(C,  B2, N, r, n) ^ A2

    return C, C2, sk_alice, sk_bob, A, B, A2, B2


# ---------------------------------------------------------------------------
# Eve's attack: observe only C, C2 — recover sk
# ---------------------------------------------------------------------------

def eve_recover_sk(C: int, C2: int, r: int, n: int) -> int:
    """
    Compute sk = S_{r+1} · (C ⊕ C2)
               = ⊕_{j=0}^{r}  M^j · (C ⊕ C2)

    Cost: O(r · n) = O(n²) bit operations.
    No private information used — only the two wire values C, C2.
    """
    delta = C ^ C2       # the only input Eve needs
    acc   = 0
    cur   = delta
    for _ in range(r + 1):   # j = 0 … r  →  r+1 terms
        acc ^= cur
        cur  = M(cur, n)
    return acc


# ---------------------------------------------------------------------------
# Verification loop
# ---------------------------------------------------------------------------

TRIALS_PER_SIZE = 2500
BIT_SIZES       = [32, 64, 128, 256]    # test all supported widths

def run_tests():
    total = passed = 0
    print("=" * 65)
    print("  HKEX Classical Break — Eve recovers sk from (C, C2) only")
    print("=" * 65)

    for n in BIT_SIZES:
        i = n // 4
        r = n - i
        size_pass = 0

        for trial in range(TRIALS_PER_SIZE):
            C, C2, sk_alice, sk_bob, *_private = hkex_alice_bob(n)

            # Eve's computation — no private keys used
            sk_eve = eve_recover_sk(C, C2, r, n)

            ok = (sk_alice == sk_bob == sk_eve)
            if ok:
                size_pass += 1
            else:
                # Print the failing case to aid debugging
                print(f"\n[FAIL] n={n} trial={trial}")
                print(f"  C        = {C:#0{n//4+2}x}")
                print(f"  C2       = {C2:#0{n//4+2}x}")
                print(f"  sk_alice = {sk_alice:#0{n//4+2}x}")
                print(f"  sk_bob   = {sk_bob:#0{n//4+2}x}")
                print(f"  sk_eve   = {sk_eve:#0{n//4+2}x}")

        total  += TRIALS_PER_SIZE
        passed += size_pass
        status  = "[PASS]" if size_pass == TRIALS_PER_SIZE else "[FAIL]"
        print(f"\n  n={n:>3} bits  (i={i}, r={r}):  "
              f"{size_pass}/{TRIALS_PER_SIZE} trials  {status}")
        print(f"    Eve's formula:  sk = S_{{r+1}} · (C ⊕ C2)")
        print(f"    Cost per trial: O({r+1} × {n}) = O({(r+1)*n}) bit ops")

    print()
    print("=" * 65)
    print(f"  Total: {passed}/{total}  {'ALL PASS' if passed == total else 'FAILURES DETECTED'}")
    print("=" * 65)

    # --- Worked example at n=64 ---
    print()
    print("Worked example (n=64, single session):")
    print("-" * 65)
    n = 64
    i, r = n // 4, n - n // 4
    mask = (1 << n) - 1

    C, C2, sk_alice, sk_bob, A, B, A2, B2 = hkex_alice_bob(n)
    sk_eve = eve_recover_sk(C, C2, r, n)

    fmt = f"#0{n//4+2}x"
    print(f"  Private (Alice): A  = {A:{fmt}}  B  = {B:{fmt}}")
    print(f"  Private (Bob):   A2 = {A2:{fmt}}  B2 = {B2:{fmt}}")
    print()
    print(f"  Public  (wire):  C  = {C:{fmt}}")
    print(f"  Public  (wire):  C2 = {C2:{fmt}}")
    print()
    print(f"  sk_alice (legitimate) = {sk_alice:{fmt}}")
    print(f"  sk_bob   (legitimate) = {sk_bob:{fmt}}")
    print(f"  sk_eve   (attack)     = {sk_eve:{fmt}}")
    print()
    print(f"  Eve used: sk = S_{{{r+1}}} · (C ⊕ C2)  "
          f"[only C and C2, zero private information]")
    match = sk_alice == sk_bob == sk_eve
    print(f"  sk_alice == sk_bob == sk_eve : {'YES — break confirmed' if match else 'NO'}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(run_tests())
