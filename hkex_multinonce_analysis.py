"""
hkex_multinonce_analysis.py — Algebraic and experimental proof that
using multiple per-step nonces in fscx_revolve cannot fix HKEX.

The proposal
------------
Replace the single nonce variant

    X_{j+1} = M·(X_j ⊕ B) ⊕ N                      (single nonce)

with a sequence of distinct nonces, one per step:

    X_{j+1} = M·(X_j ⊕ B) ⊕ N_j    j = 0 … k-1     (multi-nonce)

Also: could exchanging additional public values help?

Short answer: No to both. The proof is the same for any number of
GF(2)-linear operations — multi-nonce is still GF(2)-linear in all
inputs, and the B-cancellation theorem applies unchanged.

─────────────────────────────────────────────────────────────────────
Closed-form solution of the multi-nonce recurrence
─────────────────────────────────────────────────────────────────────
Iterating  X_{j+1} = M·X_j + M·B + N_j  (all + are XOR in GF(2)):

    X_k = M^k·A  +  M·S_k·B  ⊕  Φ_k

where  Φ_k = Σ_{j=0}^{k-1} M^{k-1-j}·N_j  ("weighted nonce sum")

This is still a GF(2)-AFFINE function of (A, B, N_0, …, N_{k-1}).
Adding more nonces does not introduce nonlinearity.

─────────────────────────────────────────────────────────────────────
The sk formula (same as before, regardless of nonce count)
─────────────────────────────────────────────────────────────────────
Substituting the closed form into the HKEX derivation and applying
A = M^r·C ⊕ M^{r+1}·S_i·B  (solved from C = M^i·A + M·S_i·B):

    sk_A = M^r·C2 + M·S_r·B ⊕ Φ^A_r ⊕ A
         = M^r·(C⊕C2) ⊕ (M·S_r + M^{r+1}·S_i)·B ⊕ Φ^A_r
         = M^r·(C⊕C2) ⊕ Φ^A_r          ← S_n·B = 0 kills B, always

The nonce sum Φ^A_r = Σ_{j=0}^{r-1} M^{r-1-j}·N^A_j is the only
remaining degree of freedom.

─────────────────────────────────────────────────────────────────────
Correctness condition and its consequence
─────────────────────────────────────────────────────────────────────
sk_A = sk_B  ⟺  Φ^A_r = Φ^B_r

For this to hold for ALL independently generated key pairs (A,B) and
(A2,B2), by the same independence argument as the single-nonce proof,
Φ^A_r can only depend on the common public values (C, C2).

Therefore sk = M^r·(C⊕C2) ⊕ h(C,C2) for some h — always public.

─────────────────────────────────────────────────────────────────────
A subtlety: private nonces can collapse to Φ = 0
─────────────────────────────────────────────────────────────────────
Consider N_j = M^j·B (private). Then:

    Φ^A_r = Σ_{j=0}^{r-1} M^{r-1-j}·M^j·B = Σ_{j=0}^{r-1} M^{r-1}·B = r·M^{r-1}·B

In GF(2), r=48 is EVEN, so r·x = 0 for any x.  Φ^A_r = 0.
Result: sk = M^r·(C⊕C2) ⊕ 0 = M^r·(C⊕C2) — public.

The private nonces cancel themselves by GF(2) arithmetic. This is a
direct consequence of the same S_n = 0 machinery that cancels B.

─────────────────────────────────────────────────────────────────────
Does exchanging more public values help?
─────────────────────────────────────────────────────────────────────
Suppose Alice publishes k values:  C^(t) = M^{i_t}·A + M·S_{i_t}·B
for t=1…k, and likewise Bob publishes k values.  The derivation uses
all of them.  Each C^(t) is a GF(2)-linear function of (A,B).

sk is an affine function of all 2k public values.  The fundamental
identity S_n = 0 still cancels B from the expression for sk, because
it holds for every (i_t, r_t) pair satisfying i_t + r_t = n.

No number of additional linear public values can escape the
cancellation that makes sk a linear function of public information.

─────────────────────────────────────────────────────────────────────
"""

import secrets

# ── Primitives ───────────────────────────────────────────────────────────────

def mask(n): return (1 << n) - 1
def rol(x, b, n): b %= n; return ((x << b) | (x >> (n - b))) & mask(n)
def ror(x, b, n): return rol(x, n - b, n)
def M(x, n):     return x ^ rol(x, 1, n) ^ ror(x, 1, n)
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

def revolve_multi(a, b, nonces, n):
    """X_{j+1} = M·(X_j⊕B) ⊕ N_j  for each N_j in nonces."""
    for nj in nonces:
        a = M(a ^ b, n) ^ nj
    return a

def phi(nonces, n):
    """Φ_k = Σ_{j=0}^{k-1} M^{k-1-j}·N_j"""
    r = len(nonces)
    return sum(Mpow(nj, r - 1 - j, n) for j, nj in enumerate(nonces)) % (mask(n) + 1)
    # Use XOR:
def phi_xor(nonces, n):
    r = len(nonces)
    acc = 0
    for j, nj in enumerate(nonces):
        acc ^= Mpow(nj, r - 1 - j, n)
    return acc

n = 64; i = n // 4; r = n - i; T = 1000

# ── Part 1: Verify closed form ───────────────────────────────────────────────

def part1():
    print("=" * 65)
    print("Part 1 — Closed form: output = M^k·A + M·S_k·B ⊕ Φ_k")
    print("=" * 65)
    ok = 0
    for _ in range(T):
        A  = secrets.randbits(n); B = secrets.randbits(n)
        Nv = [secrets.randbits(n) for _ in range(r)]
        direct    = revolve_multi(A, B, Nv, n)
        predicted = Mpow(A, r, n) ^ M(Sk(B, r, n), n) ^ phi_xor(Nv, n)
        if direct == predicted: ok += 1
    print(f"  direct == M^r·A + M·S_r·B ⊕ Φ_r : {ok}/{T}")
    print(f"  → Multi-nonce revolve is still a GF(2)-affine map in all inputs.")

# ── Part 2: B cancels regardless of nonce count ──────────────────────────────

def part2():
    print()
    print("=" * 65)
    print("Part 2 — sk = M^r·(C⊕C2) ⊕ Φ^A_r  for ANY nonce sequence")
    print("=" * 65)
    ok = 0
    for _ in range(T):
        A=secrets.randbits(n); B=secrets.randbits(n)
        A2=secrets.randbits(n); B2=secrets.randbits(n)
        C=revolve(A,B,i,n); C2=revolve(A2,B2,i,n)
        Nv = [secrets.randbits(n) for _ in range(r)]
        sk_a = revolve_multi(C2, B, Nv, n) ^ A
        # Predicted: M^r·(C⊕C2) ⊕ Φ_r  (B and A cancel via S_n=0)
        predicted = Mpow(C ^ C2, r, n) ^ phi_xor(Nv, n)
        if sk_a == predicted: ok += 1
    print(f"  sk_A == M^r·(C⊕C2) ⊕ Φ^A_r : {ok}/{T}")
    print(f"  → B (and A) cancel for ANY nonce sequence.")
    print(f"  → Private info in Φ is the only remaining variable.")

# ── Part 3: Exhaustive nonce strategies ──────────────────────────────────────

def test_strategy(label, na_fn, nb_fn, T=T):
    correct = sk_public = 0
    for _ in range(T):
        A=secrets.randbits(n); B=secrets.randbits(n)
        A2=secrets.randbits(n); B2=secrets.randbits(n)
        C=revolve(A,B,i,n); C2=revolve(A2,B2,i,n); N=C^C2
        nA = na_fn(A,B,C,C2,N); nB = nb_fn(A2,B2,C2,C,N)
        sk_a = revolve_multi(C2, B,  nA, n) ^ A
        sk_b = revolve_multi(C,  B2, nB, n) ^ A2
        # Eve: sk = M^r·(C⊕C2) ⊕ Φ^A_r  — she evaluates Φ^A_r from nA (public) or 0
        phi_a = phi_xor(nA, n)
        phi_b = phi_xor(nB, n)
        eve_sk = Mpow(C^C2, r, n) ^ phi_a   # Eve uses nA's Phi (if nA is public)
        if sk_a == sk_b: correct  += 1
        # sk is "public" if phi_a is computable from only (C,C2)
        # We flag when phi_a == phi_b (both map to same → public by independence)
        if phi_a == phi_b: sk_public += 1
    return correct, sk_public

def part3():
    print()
    print("=" * 65)
    print("Part 3 — Nonce strategies: can any achieve CORRECT + PRIVATE?")
    print("=" * 65)
    print(f"  {'Strategy':<35} {'Correct':>8}  {'Φ^A=Φ^B':>8}  Verdict")
    print(f"  {'-'*35} {'-'*8}  {'-'*8}  -------")

    def show(label, na_fn, nb_fn):
        c, p = test_strategy(label, na_fn, nb_fn)
        verdict = ("CORRECT+PUBLIC" if c==T and p==T
                   else "correct+private?"  if c==T and p<T
                   else "broken" if c==0
                   else f"partial ({c}/{T})+?")
        print(f"  {label:<35} {c:>8}  {p:>8}  {verdict}")

    # All public (same for Alice and Bob)
    pub_seq = [secrets.randbits(n) for _ in range(r)]
    show("same random public seq",
         lambda A,B,C,C2,N: pub_seq,
         lambda A2,B2,C,C2,N: pub_seq)

    show("N_j = C⊕C2 (constant public)",
         lambda A,B,C,C2,N: [N]*r,
         lambda A2,B2,C,C2,N: [N]*r)

    show("N_j = M^j·(C⊕C2) (varying public)",
         lambda A,B,C,C2,N: [Mpow(N,j,n) for j in range(r)],
         lambda A2,B2,C,C2,N: [Mpow(N,j,n) for j in range(r)])

    # Private nonces
    show("N_j = B (constant private)",
         lambda A,B,C,C2,N: [B]*r,
         lambda A2,B2,C,C2,N: [B2]*r)

    show("N_j = M^j·B (GF(2) collapses!)",
         lambda A,B,C,C2,N: [Mpow(B,j,n) for j in range(r)],
         lambda A2,B2,C,C2,N: [Mpow(B2,j,n) for j in range(r)])

    show("N_j = M^j·A (private)",
         lambda A,B,C,C2,N: [Mpow(A,j,n) for j in range(r)],
         lambda A2,B2,C,C2,N: [Mpow(A2,j,n) for j in range(r)])

    show("N_j = alternating B,C⊕C2",
         lambda A,B,C,C2,N: [B if j%2==0 else N for j in range(r)],
         lambda A2,B2,C,C2,N: [B2 if j%2==0 else N for j in range(r)])

    show("N_j = M^j·B ⊕ M^{r-j}·(C⊕C2)",
         lambda A,B,C,C2,N: [Mpow(B,j,n)^Mpow(N,r-j,n) for j in range(r)],
         lambda A2,B2,C,C2,N: [Mpow(B2,j,n)^Mpow(N,r-j,n) for j in range(r)])

    print()
    print("  Key findings:")
    print("  • Public nonces  → Φ^A=Φ^B always → sk = M^r·(C⊕C2) ⊕ public = PUBLIC")
    print("  • N_j=M^j·B      → Φ^A=0 (r is EVEN in GF(2)) → sk = M^r·(C⊕C2) = PUBLIC")
    print("  • Other private  → Φ^A ≠ Φ^B → sk_A ≠ sk_B → BROKEN")
    print("  No strategy is simultaneously CORRECT and PRIVATE.")

# ── Part 4: More exchanged public values ─────────────────────────────────────

def part4():
    print()
    print("=" * 65)
    print("Part 4 — Exchanging k public values instead of 1")
    print("=" * 65)
    print("  Alice publishes C^(t)=revolve(A,B,i_t) for t=1..k")
    print("  sk uses all k pairs of public values in derivation")
    print()

    for k_vals in [1, 2, 4]:
        i_vals = [n // (2**(t+1)) for t in range(k_vals)]   # i1=32, i2=16, i3=8, i4=4
        r_vals = [n - iv for iv in i_vals]

        ok = eve_ok = 0
        for _ in range(T):
            A=secrets.randbits(n); B=secrets.randbits(n)
            A2=secrets.randbits(n); B2=secrets.randbits(n)
            Cs  = [revolve(A,  B,  iv, n) for iv in i_vals]
            C2s = [revolve(A2, B2, iv, n) for iv in i_vals]

            # sk = XOR of all HKEX shared keys across the k pairs
            # Each pair gives sk_t = M^{r_t}·(Cs[t]⊕C2s[t]) (no per-step nonce)
            # Total: sk = XOR of all sk_t
            sk_a = 0
            for t in range(k_vals):
                N_t = Cs[t] ^ C2s[t]
                sk_a ^= revolve(C2s[t], B,  r_vals[t], n) ^ A  # full HKEX derivation
            sk_b = 0
            for t in range(k_vals):
                N_t = Cs[t] ^ C2s[t]
                sk_b ^= revolve(Cs[t],  B2, r_vals[t], n) ^ A2

            # Eve: sk = XOR_{t} M^{r_t}·(Cs[t]⊕C2s[t])  (all public)
            sk_eve = 0
            for t in range(k_vals):
                sk_eve ^= Mpow(Cs[t] ^ C2s[t], r_vals[t], n)

            if sk_a == sk_b: ok    += 1
            if sk_a == sk_eve: eve_ok += 1

        print(f"  k={k_vals} exchanged pairs: correct={ok}/{T}  eve_recovers={eve_ok}/{T}")

    print()
    print("  → Additional linear public values do not help.")
    print("  → Each pair's contribution to sk is M^r·(C⊕C2) — publicly computable.")
    print("  → Eve XORs all contributions together. sk remains public for any k.")

# ── Part 5: The collapse of M^j·B nonces ─────────────────────────────────────

def part5():
    print()
    print("=" * 65)
    print("Part 5 — Why N_j=M^j·B collapses: the GF(2) even-sum effect")
    print("=" * 65)
    print(f"  Φ_r = Σ M^{{r-1-j}}·M^j·B = Σ M^{{r-1}}·B = r·M^{{r-1}}·B")
    print(f"  In GF(2): r={r} is {'EVEN → Φ_r = 0' if r%2==0 else 'ODD → Φ_r ≠ 0'}")
    print()

    ok_zero = 0
    for _ in range(T):
        B = secrets.randbits(n)
        nA = [Mpow(B, j, n) for j in range(r)]
        p  = phi_xor(nA, n)
        if p == 0: ok_zero += 1
    print(f"  Φ_r == 0 for random B: {ok_zero}/{T}  ({'always' if ok_zero==T else 'sometimes'})")
    print()
    print(f"  This is a GF(2) consequence of the same algebra that makes S_n=0.")
    print(f"  Even-length sums of M^j·x always cancel in pairs: M^j ⊕ M^j = 0.")
    print(f"  Trying to 'hide' private data in per-step nonces this way")
    print(f"  produces Φ=0 — identical to using no nonce at all.")

# ── Main ─────────────────────────────────────────────────────────────────────

def run():
    part1()
    part2()
    part3()
    part4()
    part5()
    print()
    print("=" * 65)
    print("Conclusion")
    print("=" * 65)
    print("""
  Multi-nonce fscx_revolve has the closed form:

    output = M^k·A + M·S_k·B ⊕ Φ_k,   Φ_k = Σ M^{k-1-j}·N_j

  This is GF(2)-affine in (A, B, N_0, …, N_{k-1}).

  The HKEX derivation always gives:

    sk = M^r·(C⊕C2) ⊕ Φ^A_r

  because the fundamental identity S_n=0 cancels B and A regardless
  of how many nonces are used or how they are arranged.

  For correctness (sk_A=sk_B for all key pairs):
    Φ^A_r = Φ^B_r, and by the independence argument Φ^A_r must be
    a function of the public values (C, C2) only.

  Two failure modes for private nonces:
    (a) r is even → Φ_r = 0 by GF(2) arithmetic → sk public
    (b) r is odd (not a valid HKEX parameter) → Φ_r ≠ 0 → breaks correctness

  Exchanging more public values also does not help: each additional
  pair (C^(t), C2^(t)) contributes M^{r_t}·(C^(t)⊕C2^(t)) to sk —
  a linear function of the exchanged values, computable by Eve.

  Root cause (unchanged): FSCX is GF(2)-linear. Any composition or
  combination of GF(2)-linear steps — however many, however arranged
  — remains GF(2)-linear. Security requires genuine nonlinearity.
""")

if __name__ == "__main__":
    run()
