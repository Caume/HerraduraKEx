"""
hkex_fscxn_analysis.py — Formal proof that replacing fscx_revolve with
fscx_revolve_n in HKEX key generation does NOT fix the classical break.

The question
------------
The existing HKEX uses fscx_revolve for public-key generation:

    C  = fscx_revolve(A,  B,  i)
    C2 = fscx_revolve(A2, B2, i)

The key derivation already uses fscx_revolve_n:

    sk = fscx_revolve_n(C2, B, N, r) ⊕ A   (Alice)
       = fscx_revolve_n(C,  B2, N, r) ⊕ A2  (Bob)   where N = C ⊕ C2

Would using fscx_revolve_n also in the public-key step close the break?

The answer: No — unconditionally.
The proof
---------
The break originates from the FSCX operator being GF(2)-linear.  This causes
the fundamental identity  S_n = 0  (sum of all powers of M vanishes), which
in turn causes private parameters to cancel from the shared-key expression.
Using fscx_revolve_n introduces an additive nonce term, but that term must
come from one of only two possible sources:

  Case (a) PUBLIC nonce — the nonce is known to Eve.
    Eve adjusts her formula to absorb the nonce contribution, which is still
    computable from public information.  The break survives.

  Case (b) PRIVATE nonce — e.g. nonce = B (Alice's private value).
    Now the nonce term does NOT cancel in the sk_alice - sk_bob difference,
    so  sk_alice ≠ sk_bob  for random independent keys.
    Correctness is destroyed.

There is no third option.  Any nonce is either public (Eve can use it too)
or private (it breaks correctness).  The GF(2)-linearity of M is what makes
these the only two cases, and no variant of nonce injection can escape the
dilemma without introducing a non-linear primitive.

Algebraic detail — Case (a)
---------------------------
Let  Φ_a  be any known (public) nonce.  Then:

    C  = fscx_revolve_n(A,  B,  Φ_a, i)
       = M^i·A + S_i·(M·B ⊕ Φ_a)

Solving for A:
    A  = M^r·C ⊕ M^{r+1}·S_i·B ⊕ M^r·S_i·Φ_a           (*)

Substituting (*) into Alice's sk expression
(sk_a = M^r·C2 + S_r·M·B ⊕ S_r·N ⊕ A, N = C⊕C2):

    sk_a = S_{r+1}·(C⊕C2)
         ⊕  (S_r·M + M^{r+1}·S_i)·B          ← = S_n·B = 0
         ⊕  M^r·S_i·Φ_a

         = S_{r+1}·(C⊕C2)  ⊕  M^r·S_i·Φ_a

Both terms are computable from public information (C, C2, Φ_a).  Eve recovers
sk exactly as before, just with a known offset.

Algebraic detail — Case (b)
---------------------------
Let each party use their own private B as the nonce:

    C  = fscx_revolve_n(A,  B,  B,  i)
       = M^i·A + S_i·(M+I)·B
    C2 = fscx_revolve_n(A2, B2, B2, i)
       = M^i·A2 + S_i·(M+I)·B2

By the same derivation:
    sk_a = S_{r+1}·(C⊕C2)  ⊕  M^r·S_i·B
    sk_b = S_{r+1}·(C⊕C2)  ⊕  M^r·S_i·B2

    sk_a - sk_b = M^r·S_i·(B ⊕ B2)

This is zero only if B = B2 — impossible for independent random keys.
Correctness fails.

Root cause
----------
A DH-style exchange requires a function  f  such that:

    f(a, f(b, g)) = f(b, f(a, g))   [commutativity / shared-key equality]
    f(a, ·) is a one-way function    [security]

FSCX_REVOLVE satisfies the first condition by virtue of S_n = 0.  But S_n = 0
is *also* what makes f linear in its arguments and thus allows the classical
break.  These two properties — correctness by cancellation, and security
against a passive observer — are mutually exclusive under any GF(2)-linear
primitive:

    Correctness requires: private terms cancel from (sk_alice - sk_bob) → 0
    Security requires:    private terms remain in sk_alice

They cannot both hold simultaneously when every operation is a GF(2)-linear
map.  Adding a nonce via fscx_revolve_n does not escape this dilemma because
the nonce injection is itself a linear operation (XOR).

The only path to a secure DH-style construction is to replace the GF(2)-linear
FSCX primitive with a non-linear one — e.g. a function that does not satisfy
the superposition principle  f(A⊕X) = f(A)⊕f(X).
"""

import secrets
import sys

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def mask(n):   return (1 << n) - 1
def rol(x,b,n): b%=n; return ((x<<b)|(x>>(n-b)))&mask(n)
def ror(x,b,n): return rol(x,n-b,n)
def M(x,n):    return x ^ rol(x,1,n) ^ ror(x,1,n)

def revolve(a, b, steps, n):
    for _ in range(steps):
        a = M(a ^ b, n)
    return a

def revolve_n(a, b, nonce, steps, n):
    for _ in range(steps):
        a = M(a ^ b, n) ^ nonce
    return a

def S_k(delta, k, n):
    """S_k · delta  =  delta ⊕ M·delta ⊕ … ⊕ M^{k-1}·delta"""
    acc, cur = 0, delta
    for _ in range(k):
        acc ^= cur
        cur  = M(cur, n)
    return acc

def S_r1(delta, r, n):
    """S_{r+1} · delta  (r+1 terms)"""
    return S_k(delta, r + 1, n)

def Mpow(x, k, n):
    """M^k · x"""
    for _ in range(k % (n // 2)):   # order of M is n/2
        x = M(x, n)
    return x

# ---------------------------------------------------------------------------
# Case (a): public nonce in key generation
# ---------------------------------------------------------------------------

def case_a(n=64, trials=2000):
    """
    Public nonce Φ_a is fixed and known to all parties including Eve.
    Predicted outcome: correctness holds, Eve still recovers sk.
    """
    i, r    = n // 4, n - n // 4
    phi_a   = secrets.randbits(n)   # fixed for this run; public

    correct = eve_ok = 0
    for _ in range(trials):
        A  = secrets.randbits(n);  B  = secrets.randbits(n)
        A2 = secrets.randbits(n);  B2 = secrets.randbits(n)

        C  = revolve_n(A,  B,  phi_a, i, n)
        C2 = revolve_n(A2, B2, phi_a, i, n)
        N  = C ^ C2

        sk_a = revolve_n(C2, B,  N, r, n) ^ A
        sk_b = revolve_n(C,  B2, N, r, n) ^ A2
        if sk_a == sk_b:
            correct += 1

        # Eve's formula: sk = S_{r+1}·(C⊕C2)  ⊕  M^r·S_i·Φ_a
        offset   = Mpow(S_k(phi_a, i, n), r, n)
        sk_eve   = S_r1(C ^ C2, r, n) ^ offset
        if sk_eve == sk_a:
            eve_ok += 1

    return correct, eve_ok, trials

# ---------------------------------------------------------------------------
# Case (b): private nonce (nonce = B)
# ---------------------------------------------------------------------------

def case_b(n=64, trials=2000):
    """
    Each party uses their own private B as the nonce in key generation.
    Predicted outcome: correctness breaks (sk_a ≠ sk_b).
    """
    i, r = n // 4, n - n // 4

    correct = eve_naive_ok = 0
    for _ in range(trials):
        A  = secrets.randbits(n);  B  = secrets.randbits(n)
        A2 = secrets.randbits(n);  B2 = secrets.randbits(n)

        C  = revolve_n(A,  B,  B,  i, n)    # nonce = B (private)
        C2 = revolve_n(A2, B2, B2, i, n)    # nonce = B2 (private)
        N  = C ^ C2

        sk_a = revolve_n(C2, B,  N, r, n) ^ A
        sk_b = revolve_n(C,  B2, N, r, n) ^ A2
        if sk_a == sk_b:
            correct += 1

        # Eve tries: sk = S_{r+1}·(C⊕C2)  (without knowing B or B2)
        if S_r1(C ^ C2, r, n) == sk_a:
            eve_naive_ok += 1

    return correct, eve_naive_ok, trials

# ---------------------------------------------------------------------------
# Case (c): verify algebraic formula for case (b) offset
#   sk_a - sk_b  =?=  M^r·S_i·(B ⊕ B2)
# ---------------------------------------------------------------------------

def case_c_verify_offset(n=64, trials=2000):
    """
    Verifies the algebraic prediction for case (b):
        sk_a ⊕ sk_b  =  M^r · S_i · (B ⊕ B2)
    """
    i, r    = n // 4, n - n // 4
    matches = 0
    for _ in range(trials):
        A  = secrets.randbits(n);  B  = secrets.randbits(n)
        A2 = secrets.randbits(n);  B2 = secrets.randbits(n)

        C  = revolve_n(A,  B,  B,  i, n)
        C2 = revolve_n(A2, B2, B2, i, n)
        N  = C ^ C2

        sk_a = revolve_n(C2, B,  N, r, n) ^ A
        sk_b = revolve_n(C,  B2, N, r, n) ^ A2

        predicted_diff = Mpow(S_k(B ^ B2, i, n), r, n)
        if (sk_a ^ sk_b) == predicted_diff:
            matches += 1

    return matches, trials

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run():
    findings = []
    print("=" * 65)
    print("  Can fscx_revolve_n in key generation fix the HKEX break?")
    print("=" * 65)

    # --- Case (a) ---
    print("\nCase (a) — public nonce Φ_a in key generation:")
    print("  Prediction: correctness holds, Eve still wins")
    c, e, t = case_a()
    print(f"  Correctness  (sk_a == sk_b) : {c}/{t}  {'✓' if c==t else '✗'}")
    print(f"  Eve recovers sk             : {e}/{t}  {'✓' if e==t else '✗'}")
    findings.append(("(a) public nonce: correct, and Eve still wins",
                     c == t and e == t))
    print(f"  Eve's formula: sk = S_{{r+1}}·(C⊕C2) ⊕ M^r·S_i·Φ_a")
    print(f"  ⇒ Break survives. Eve just adds the known nonce offset.")

    # --- Case (b) ---
    print("\nCase (b) — private nonce (nonce = B) in key generation:")
    print("  Prediction: correctness BREAKS, Eve's naive formula fails")
    c, e, t = case_b()
    print(f"  Correctness  (sk_a == sk_b) : {c}/{t}  {'✓' if c==0 else '✗'}")
    print(f"  Eve naive formula works     : {e}/{t}")
    findings.append(("(b) private nonce: the parties disagree", c == 0))
    print(f"  ⇒ Scheme is broken differently: Alice and Bob disagree on sk.")

    # --- Case (c) ---
    print("\nCase (c) — algebraic verification of the case (b) difference:")
    print("  Prediction: sk_a ⊕ sk_b  =  M^r · S_i · (B ⊕ B2)")
    m, t = case_c_verify_offset()
    print(f"  Formula matches            : {m}/{t}  {'✓' if m==t else '✗'}")
    findings.append(("(c) the disagreement is exactly M^r.S_i.(B ⊕ B2)", m == t))
    print(f"  ⇒ The offset is exactly M^r·S_i·(B⊕B2); non-zero unless B=B2.")

    # --- Summary ---
    print()
    print("=" * 65)
    print("  Conclusion")
    print("=" * 65)
    print("""
  The dilemma is inherent and cannot be resolved within the GF(2)-linear
  framework:

    PUBLIC  nonce → Eve absorbs it into her formula. Break survives.
    PRIVATE nonce → sk_a ≠ sk_b. Correctness is destroyed.

  Root cause: the fundamental identity  S_n = 0  (which M^{n/2}=I implies)
  causes private parameters to cancel from (sk_alice − sk_bob), making the
  scheme correct.  But that exact cancellation is also what collapses sk
  into a linear function of the public values.

  fscx_revolve_n is a linear operation (XOR injection). Adding a linear
  operation to a linear scheme does not introduce non-linearity.

  Fix requires: replacing the FSCX linear primitive with a non-linear one
  so that the function f(a, ·) is genuinely one-way — i.e., so that the
  "cancellation trick" that enables correctness cannot simultaneously be
  exploited to compute sk from public values alone.
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
