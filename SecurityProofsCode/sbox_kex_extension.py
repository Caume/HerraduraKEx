#!/usr/bin/env python3
"""
sbox_kex_extension.py — TODO #230: does TODO #224's negative result extend to an
S-box layer?

It does, but not by extension — by replacement.  TODO #224's impossibility theorem
quantifies over *additive* injections that reach the session key through the
accumulator `L = XOR_j M^{r-1-j} . u_j`; a substitution layer does not factor out of
the iteration, so that theorem is silent here rather than dispositive.  What closes
the S-box case is a stronger statement proved below, which needs no linearity, no
affineness and no assumption about the step function at all:

  THEOREM (characterization).  Let the public phase iterate F_B and the derivation
  phase iterate G_B, both public, with i + r = n.  HKEX-style agreement

      G_B^r(F_{B2}^i(A2)) XOR A  =  G_{B2}^r(F_B^i(A)) XOR A2      for all A,B,A2,B2

  holds **if and only if** for every pair (B, B2) the composite G_B^r . F_{B2}^i is
  the translation x -> x XOR d(B,B2).  Whenever it holds, fixing any B0 gives

      F_B^i(x) = Psi(x XOR e(B)),        G_B^r(y) = Psi^{-1}(y) XOR e(B) XOR c

  for one fixed bijection Psi = (G_{B0}^r)^{-1}, i.e. the entire key-dependence of
  the i-fold iterate is an input XOR translation, and

      sk = Psi^{-1}(C) XOR Psi^{-1}(C2) XOR c
         = G_{B0}^r(C) XOR G_{B0}^r(C2) XOR c,   c = G_{B0}^r(F_{B0}^i(0))

  which any eavesdropper evaluates from the transcript with 2r + i applications of
  the public step function.  (Proof in §2; derivation is four lines.)

So the question "is this S-box non-linear enough?" is the wrong question.  Any step
function whatsoever that admits HKEX-style agreement hands Eve the session key.  The
S-box case is a corollary; so are `hkex_classical_break.py`, the nonce impossibility
theorem, and TODO #224.

  §1  Scope: why TODO #224's theorem does not cover an S-box
  §2  The characterization theorem and the universal attack
  §3  Sub-case 1 — linear S-box: agreement condition and the co-rank it buys
  §4  Sub-case 2 — affine S-box
  §5  Sub-case 3 — non-linear S-box: unrelated, or noisy and reconcilable?
  §6  Sub-case 4 — B-keyed S-box
  §7  Exhaustive small-width search: must an agreeing step function be affine?
  §8  Verdict

RESULTS

§1  TODO #224's class is characterized by `G(A,B) XOR G(A',B)` being independent of
    `B`.  Every additive injection satisfies it on 100% of random triples; a
    substitution layer fails it on 100%.  #224 is silent on the S-box, as claimed.

§2  The characterization is verified in both directions, and the universal attack
    reproduces `hkex_classical_break.py` exactly at all four widths (300/300 each)
    while using only black-box evaluations of the step function — never `M`'s
    linearity, never the closed form `S_{r+1}.(C XOR C2)`.

§3  A linear box `L` is not a new construction: the step becomes `(L.M).(A XOR B)`.
    Writing `Y = L.M + I`, agreement holds iff `Y^{n-1} = 0`, and then

        co-rank(T_i) = dim ker Y^{2^{v2(i)} - 1}

    which recovers TODO #210's `2(2^{v2(i)} - 1)` as the special case `v(M+I) = 2`.
    The factor 2 in #210's closed form is therefore exactly the valuation of `M+I`,
    and a better box removes it: at `n = 256`, `i = 64` the co-rank drops **126 ->
    64**.  It cannot go lower.  The unconstrained optimum is 63 (a regular nilpotent
    `Y`, one Jordan block) but that has `Y^{n-1} != 0` and so **fails agreement**;
    the constrained optimum is Jordan type `(n-1, 1)`, measured at exactly 64 in
    both directions.  It is never 0, because `Y` is nilpotent, so no linear box
    repairs the leak — it halves it.  Eve still wins (§2), so this is a statement
    about HSKE/HPKE, not a key exchange.

§4  An affine box is §3 plus a constant, and the constant is TODO #224's `kappa`:
    both parties add the same one, agreement and the attack are unchanged.  Verified.

§5  This is the sub-case that could have left a branch alive.  It does not.  A
    *single transposition* inside one 4-bit box drives `sk_A XOR sk_B` straight to
    the random-function baseline: mean Hamming distance 32.3 of 64 and 64.3 of 128,
    agreement 0/300, indistinguishable from the PRESENT S-box.  The two values are
    unrelated, not noisy, so Peikert-style reconciliation has nothing to work with —
    the one outcome that would have kept a branch open is measured shut.

§6  A B-keyed box additionally destroys the shared-box symmetry; 0/300 as expected.

§7  The conjecture recorded in TODO #230 — that an agreeing step function must be
    affine over an abelian group — is **false**, and the search refutes it rather
    than supporting it.  For the family `G(A,B) = S(A XOR B)`, exhaustive over all
    permutations at `n = 2` (24) and `n = 3` (40 320), exhaustive over all 322 560
    affine permutations at `n = 4` (25 216 agree), and exhaustive over the 3 025 920
    boxes one transposition away from an agreeing affine box at `n = 4`: **15 360
    non-affine permutations admit full agreement**, confirmed over all 65 536 tuples
    for a 40-box sample.  The universal attack of §2 wins on every one of them.
    Affineness was the wrong lens; the translation-coset condition is the right one,
    and it is what the theorem is stated in terms of.

§8  All four sub-cases closed, and closed by one theorem rather than four
    measurements.  No `--algo` tag, PEM label or `spec/` entry follows; the co-rank
    result of §3 is a finding about HSKE/HPKE and would need its own TODO, with its
    own wire-format and MIGRATING.md analysis, before anything shipped.

Self-contained (no imports from the suite), per SecurityProofsCode convention; the
primitives below are transcribed from `Herradura cryptographic suite.py`.
"""

import itertools
import random

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (transcribed from the suite)
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1)


def M_fun(x, n):
    """The FSCX linear operator M = I XOR ROL XOR ROR."""
    return x ^ rotl(x, 1, n) ^ rotl(x, -1, n)


def iterate(F, x, k):
    for _ in range(k):
        x = F(x)
    return x


# ─────────────────────────────────────────────────────────────────────────────
# GF(2) matrices as n columns packed into Python ints
# ─────────────────────────────────────────────────────────────────────────────

def mat_of(f, n):
    return [f(1 << k, n) for k in range(n)]


def mat_apply(A, x):
    y, k = 0, 0
    while x:
        if x & 1:
            y ^= A[k]
        x >>= 1
        k += 1
    return y


def mat_comp(A, B):
    """A . B (apply B first)."""
    return [mat_apply(A, col) for col in B]


def mat_id(n):
    return [1 << k for k in range(n)]


def mat_add(A, B):
    return [a ^ b for a, b in zip(A, B)]


def mat_pow(A, e, n):
    R = mat_id(n)
    while e:
        if e & 1:
            R = mat_comp(A, R)
        A = mat_comp(A, A)
        e >>= 1
    return R


def rank_gf2(cols, n):
    rows = list(cols)
    r = 0
    for c in range(n):
        piv = next((j for j in range(r, len(rows)) if (rows[j] >> c) & 1), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for j in range(len(rows)):
            if j != r and (rows[j] >> c) & 1:
                rows[j] ^= rows[r]
        r += 1
    return r


def v2(k):
    a = 0
    while k % 2 == 0:
        k //= 2
        a += 1
    return a


def jordan_nilpotent(sizes, n):
    """Nilpotent Y in Jordan form: e_k -> e_{k-1} inside each block."""
    Y = [0] * n
    base = 0
    for s in sizes:
        for t in range(s):
            Y[base + t] = (1 << (base + t - 1)) if t > 0 else 0
        base += s
    return Y


def nil_index(Y, n):
    P = mat_id(n)
    for k in range(1, n + 2):
        P = mat_comp(Y, P)
        if not any(P):
            return k
    return None


# ─────────────────────────────────────────────────────────────────────────────
# The generic HKEX template, parameterized by its two public step functions
# ─────────────────────────────────────────────────────────────────────────────

def hkex_session(n, mk_pub, mk_der, rng):
    """mk_pub(B, N) and mk_der(B, N) each return a one-step map x -> x'."""
    i, r = n // 4, n - n // 4
    A, B, A2, B2 = (rng.getrandbits(n) for _ in range(4))
    C = iterate(mk_pub(B, 0), A, i)
    C2 = iterate(mk_pub(B2, 0), A2, i)
    N = C ^ C2
    sk_a = iterate(mk_der(B, N), C2, r) ^ A
    sk_b = iterate(mk_der(B2, N), C, r) ^ A2
    return C, C2, N, sk_a, sk_b


def eve_universal(C, C2, N, n, mk_pub, mk_der, B0=0):
    """sk = G_B0^r(C) XOR G_B0^r(C2) XOR c,  c = G_B0^r(F_B0^i(0)).

    Black-box: only evaluates the public step functions.  No algebra used."""
    i, r = n // 4, n - n // 4
    Fp, Gd = mk_pub(B0, N), mk_der(B0, N)
    c = iterate(Gd, iterate(Fp, 0, i), r)
    return iterate(Gd, C, r) ^ iterate(Gd, C2, r) ^ c



# ─────────────────────────────────────────────────────────────────────────────
# §1  TODO #224's scope condition, and how an S-box violates it
# ─────────────────────────────────────────────────────────────────────────────

def nibble_sub(box, x, n):
    y = 0
    for k in range(n // 4):
        y |= box[(x >> (4 * k)) & 0xF] << (4 * k)
    return y


PRESENT_SBOX = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]


def section1(trials=2000):
    print(SEP2)
    print("§1  Scope: TODO #224's theorem does not cover a substitution layer")
    print(SEP2)
    print()
    print("  #224 quantifies over additive injections — values u_j that enter by XOR")
    print("  and are independent of the state.  That class is exactly the set of step")
    print("  functions satisfying")
    print()
    print("      G(A,B) XOR G(A',B)  independent of B                     (*)")
    print()
    print("  which is what lets the injections be collected into one accumulator.")
    print("  Fraction of random (A, A', B) triples where (*) FAILS:")
    print()
    print("  n     MFSCX (additive injection)   SFSCX (nibble S-box)")
    rng = random.Random(20260823)
    for n in (32, 64, 128, 256):
        bad_m = bad_s = 0
        for _ in range(trials):
            A, A2, B = rng.getrandbits(n), rng.getrandbits(n), rng.getrandbits(n)
            u = rng.getrandbits(n)
            gm = lambda a, b: M_fun(a ^ b, n) ^ u
            gs = lambda a, b: nibble_sub(PRESENT_SBOX, M_fun(a ^ b, n), n)
            if (gm(A, B) ^ gm(A2, B)) != (gm(A, 0) ^ gm(A2, 0)):
                bad_m += 1
            if (gs(A, B) ^ gs(A2, B)) != (gs(A, 0) ^ gs(A2, 0)):
                bad_s += 1
        print(f"  {n:<5} {100.0 * bad_m / trials:>8.1f}%                     "
              f"{100.0 * bad_s / trials:>8.1f}%")
    print()
    print("  The additive class satisfies (*) identically; the S-box violates it almost")
    print("  everywhere.  So #224 says nothing here, in either direction — which is the")
    print("  premise of this item, not a result.  §2 supplies what does cover it.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §2  The characterization theorem and the universal attack
# ─────────────────────────────────────────────────────────────────────────────

def section2(trials=300):
    print(SEP2)
    print("§2  Characterization of every step function that admits agreement")
    print(SEP2)
    print()
    print("  Agreement reads   G_B^r(F_B2^i(A2)) XOR A = G_B2^r(F_B^i(A)) XOR A2.")
    print("  Fix (B, B2) and write P(A2), Q(A) for the two composites.  The identity")
    print("  says P(A2) XOR A2 = Q(A) XOR A for all A, A2; the left side depends only")
    print("  on A2 and the right only on A, so both equal a constant d(B,B2), and")
    print("  swapping the roles of the parties gives d(B,B2) = d(B2,B) for free:")
    print()
    print("      agreement  <=>  G_B^r . F_B2^i = translation by d(B,B2)      (T)")
    print()
    print("  Fix any B0 and set Psi = (G_B0^r)^{-1}.  Then (T) at B = B0 gives")
    print("  F_B2^i(x) = Psi(x XOR e(B2)) with e(B2) = d(B0,B2); substituting back,")
    print("  G_B^r(y) = Psi^{-1}(y) XOR g(B) with e(B2) XOR d(B,B2) = g(B) independent")
    print("  of B2; and symmetry of d forces g(B) = e(B) XOR c for a constant c.  So")
    print()
    print("      Psi^{-1}(C) = A XOR e(B),      Psi^{-1}(C2) = A2 XOR e(B2)")
    print("      sk = G_B^r(C2) XOR A = A XOR A2 XOR e(B) XOR e(B2) XOR c")
    print("         = Psi^{-1}(C) XOR Psi^{-1}(C2) XOR c.                       []")
    print()
    print("  Eve needs no private value and no algebraic structure — only the public")
    print("  step functions:  sk = G_B0^r(C) XOR G_B0^r(C2) XOR c, c = G_B0^r(F_B0^i(0)).")
    print()
    print("  Verified against the deployed classical HKEX (nonce variant), where it")
    print("  must reproduce hkex_classical_break.py's sk = S_(r+1).(C XOR C2):")
    print()
    print("  n     agreement    (T) holds    universal Eve   matches S_(r+1).(C XOR C2)")
    rng = random.Random(4242)
    for n in (32, 64, 128, 256):
        i, r = n // 4, n - n // 4
        mk_pub = lambda B, N, n=n: (lambda x: M_fun(x ^ B, n))
        mk_der = lambda B, N, n=n: (lambda x: M_fun(x ^ B, n) ^ N)
        agree = won = closed = 0
        for _ in range(trials):
            C, C2, N, sk_a, sk_b = hkex_session(n, mk_pub, mk_der, rng)
            agree += (sk_a == sk_b)
            won += (eve_universal(C, C2, N, n, mk_pub, mk_der) == sk_a == sk_b)
            acc, cur = 0, C ^ C2
            for _ in range(r + 1):
                acc ^= cur
                cur = M_fun(cur, n)
            closed += (acc == sk_a)
        # (T): composite is a translation, checked on random (B, B2)
        tr_ok = 0
        for _ in range(50):
            B, B2, N = rng.getrandbits(n), rng.getrandbits(n), rng.getrandbits(n)
            offs = {iterate(mk_der(B, N), iterate(mk_pub(B2, 0), x, i), r) ^ x
                    for x in (rng.getrandbits(n) for _ in range(8))}
            tr_ok += (len(offs) == 1)
        print(f"  {n:<5} {agree}/{trials:<8} {tr_ok}/50{'':<7} {won}/{trials:<11} {closed}/{trials}")
    print()
    print("  The attack never touches M's linearity or the closed form; it evaluates")
    print("  the published step function 2r + i times.  hkex_classical_break.py is the")
    print("  special case Psi^{-1} = M^r.  TODO #224 is the case where the step carries")
    print("  an additive injection.  The nonce variant is covered by treating N, which")
    print("  is common to both parties, as a public parameter of the step function.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  Sub-case 1 — a linear S-box
# ─────────────────────────────────────────────────────────────────────────────

def corank_key_map(Mp, k, n):
    """co-rank of T_k for the step x -> M'(x XOR B)."""
    cols = []
    for j in range(n):
        B, x = 1 << j, 0
        for _ in range(k):
            x = mat_apply(Mp, x ^ B)
        cols.append(x)
    return n - rank_gf2(cols, n)


def section3():
    print(SEP2)
    print("§3  Sub-case 1 — a GF(2)-linear S-box is not a new construction")
    print(SEP2)
    print()
    print("  The step becomes x -> L.M.(A XOR B), i.e. FSCX with M replaced by")
    print("  M' = L.M.  Writing Y = M' + I, the agreement conditions M'^n = I and")
    print("  M'.S'_n = 0 are together equivalent to Y^{n-1} = 0, and for i = 2^a the")
    print("  binomial sum collapses (Lucas) to S'_i = Y^{i-1}, giving")
    print()
    print("      co-rank(T_i) = dim ker Y^{2^{v2(i)} - 1}.")
    print()
    n, i, r = 256, 64, 192
    Mm = mat_of(M_fun, n)
    I = mat_id(n)
    Ycl = mat_add(Mm, I)
    print(f"  Classical M at n={n}: nilpotency index of M+I ="
          f" {nil_index(Ycl, n)}, v(M+I) = 2, and the predicted")
    print(f"  dim ker Y^63 = {n - rank_gf2(mat_pow(Ycl, 63, n), n)} equals the measured"
          f" co-rank(T_{i}) = {corank_key_map(Mm, i, n)}.")
    print("  So TODO #210's factor 2 in 2(2^{v2(i)} - 1) is exactly v(M+I) — a property")
    print("  of this M, not of the construction.  A different linear box removes it.")
    print()
    print("  Jordan type of Y     agreement   co-rank(T_i)   co-rank(T_r)")
    rows = (([n], "single block (n)"), ([n - 1, 1], "(n-1, 1)"),
            ([n - 2, 2], "(n-2, 2)"), ([n // 2, n // 2], "(n/2, n/2)"))
    for sizes, label in rows:
        Y = jordan_nilpotent(sizes, n)
        Mp = mat_add(I, Y)
        ok = (mat_pow(Mp, n, n) == I) and not any(mat_pow(Y, n - 1, n))
        print(f"  {label:<20} {str(ok):<11} {corank_key_map(Mp, i, n):<14}"
              f" {corank_key_map(Mp, r, n)}")
    print(f"  {'classical M':<20} {'True':<11} {corank_key_map(Mm, i, n):<14}"
          f" {corank_key_map(Mm, r, n)}")
    print()
    print("  Read the first two rows together.  A regular nilpotent Y (one Jordan")
    print("  block) reaches co-rank 63 — but Y^{n-1} != 0 there, so it FAILS")
    print("  agreement: the unconstrained optimum is unreachable by any protocol.")
    print("  The constrained optimum is Jordan type (n-1, 1), at exactly 64, and")
    print("  dim ker Y^{i-1} = sum_j min(lambda_j, i-1) is minimized by the fewest,")
    print("  largest blocks, so 64 is a floor and not merely the best found.")
    print()
    print("  126 -> 64 is a real improvement and still not 0: Y is nilpotent, so")
    print("  Y^{i-1} is singular for every even i.  No linear box repairs the leak.")
    print()
    print("  And the exchange is no more secure for it — the universal attack of §2")
    print("  applies unchanged, since a linear box is still a public step function:")
    rng = random.Random(99)
    Y = jordan_nilpotent([n - 1, 1], n)
    Mp = mat_add(I, Y)
    mk_pub = lambda B, N: (lambda x: mat_apply(Mp, x ^ B))
    mk_der = lambda B, N: (lambda x: mat_apply(Mp, x ^ B) ^ N)
    agree = won = 0
    for _ in range(100):
        C, C2, N, sk_a, sk_b = hkex_session(n, mk_pub, mk_der, rng)
        agree += (sk_a == sk_b)
        won += (eve_universal(C, C2, N, n, mk_pub, mk_der) == sk_a == sk_b)
    print(f"    Jordan-(n-1,1) box at n={n}: agreement {agree}/100, Eve {won}/100")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §4  Sub-case 2 — an affine S-box
# ─────────────────────────────────────────────────────────────────────────────

def section4(trials=200):
    print(SEP2)
    print("§4  Sub-case 2 — an affine S-box is §3 plus TODO #224's kappa")
    print(SEP2)
    print()
    print("  L.x XOR c contributes the constant to the same accumulator #224 analysed,")
    print("  and both parties add the same one.  Agreement and the attack are unchanged:")
    print()
    n = 128
    I = mat_id(n)
    Y = jordan_nilpotent([n - 1, 1], n)
    Mp = mat_add(I, Y)
    rng = random.Random(2024)
    print("  constant   agreement   universal Eve")
    for cst_label, cst in (("0", 0), ("random", rng.getrandbits(n)), ("all-ones", (1 << n) - 1)):
        mk_pub = lambda B, N, cst=cst: (lambda x: mat_apply(Mp, x ^ B) ^ cst)
        mk_der = lambda B, N, cst=cst: (lambda x: mat_apply(Mp, x ^ B) ^ cst ^ N)
        agree = won = 0
        for _ in range(trials):
            C, C2, N, sk_a, sk_b = hkex_session(n, mk_pub, mk_der, rng)
            agree += (sk_a == sk_b)
            won += (eve_universal(C, C2, N, n, mk_pub, mk_der) == sk_a == sk_b)
        print(f"  {cst_label:<10} {agree}/{trials:<11} {won}/{trials}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §5  Sub-case 3 — a genuinely non-linear S-box
# ─────────────────────────────────────────────────────────────────────────────

def perturbed_box(k, seed):
    b = list(range(16))
    rng = random.Random(seed)
    for _ in range(k):
        a, c = rng.randrange(16), rng.randrange(16)
        b[a], b[c] = b[c], b[a]
    return b


def section5(trials=300):
    print(SEP2)
    print("§5  Sub-case 3 — unrelated, or noisy and reconcilable?")
    print(SEP2)
    print()
    print("  The discriminator that matters.  A pass/fail count cannot tell a dead")
    print("  construction from a noisy one: HKEX-RNL also fails exact agreement and is")
    print("  rescued by Peikert reconciliation (§11.4.2).  Reconciliation needs a SMALL")
    print("  Hamming distance.  The random-function baseline is n/2.")
    print()
    boxes = (("identity (linear)", list(range(16))),
             ("1 transposition", perturbed_box(1, 1)),
             ("2 transpositions", perturbed_box(2, 2)),
             ("4 transpositions", perturbed_box(4, 3)),
             ("PRESENT 4-bit S-box", PRESENT_SBOX))
    for n in (64, 128):
        print(f"  n = {n}   (i, r) = ({n // 4}, {n - n // 4})   baseline n/2 = {n // 2}")
        print("    box                      agreement   mean HW(sk_A XOR sk_B)")
        for label, box in boxes:
            rng = random.Random(7)
            agree = hw = 0
            mk_pub = lambda B, N, box=box, n=n: (
                lambda x: nibble_sub(box, M_fun(x ^ B, n), n))
            mk_der = lambda B, N, box=box, n=n: (
                lambda x: nibble_sub(box, M_fun(x ^ B, n) ^ N, n))
            for _ in range(trials):
                C, C2, N, sk_a, sk_b = hkex_session(n, mk_pub, mk_der, rng)
                agree += (sk_a == sk_b)
                hw += bin(sk_a ^ sk_b).count("1")
            print(f"    {label:<24} {agree:>3}/{trials:<7} {hw / trials:>8.1f}")
        print()
    print("  A single transposition in one 4-bit box — the smallest departure from")
    print("  linearity that exists — already saturates the baseline, and is")
    print("  indistinguishable from a real S-box.  The two derived values are")
    print("  unrelated, not noisy.  There is nothing for reconciliation to reconcile,")
    print("  so the one branch that could have survived this item is measured shut.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §6  Sub-case 4 — a B-keyed S-box
# ─────────────────────────────────────────────────────────────────────────────

def section6(trials=300):
    print(SEP2)
    print("§6  Sub-case 4 — a B-keyed S-box")
    print(SEP2)
    print()
    print("  Selecting the box by the revolve parameter removes even the shared-box")
    print("  symmetry.  Included to bound the space, not because it is promising:")
    print()
    print("  n     agreement   mean HW(sk_A XOR sk_B)")
    for n in (64, 128):
        rng = random.Random(11)
        agree = hw = 0
        mk_pub = lambda B, N, n=n: (
            lambda x: nibble_sub(perturbed_box(3, B & 0xFFFF), M_fun(x ^ B, n), n))
        mk_der = lambda B, N, n=n: (
            lambda x: nibble_sub(perturbed_box(3, B & 0xFFFF), M_fun(x ^ B, n) ^ N, n))
        for _ in range(trials):
            C, C2, N, sk_a, sk_b = hkex_session(n, mk_pub, mk_der, rng)
            agree += (sk_a == sk_b)
            hw += bin(sk_a ^ sk_b).count("1")
        print(f"  {n:<5} {agree}/{trials:<9} {hw / trials:.1f} of {n}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §7  Exhaustive small-width search
# ─────────────────────────────────────────────────────────────────────────────

def sbox_iter(S, B, x, k):
    for _ in range(k):
        x = S[x ^ B]
    return x


def sbox_agrees_full(S, n, i, r):
    N = 1 << n
    for A in range(N):
        for B in range(N):
            for A2 in range(N):
                for B2 in range(N):
                    if (sbox_iter(S, B, sbox_iter(S, B2, A2, i), r) ^ A !=
                            sbox_iter(S, B2, sbox_iter(S, B, A, i), r) ^ A2):
                        return False
    return True


def sbox_reduced(S, n):
    """For i = 1 the characterization collapses to (S . tau_B)^n = tau_c, same c."""
    N = 1 << n
    c = None
    for B in range(N):
        offs = {sbox_iter(S, B, x, n) ^ x for x in range(N)}
        if len(offs) != 1:
            return None
        v = offs.pop()
        if c is None:
            c = v
        elif v != c:
            return None
    return c


def is_affine(S, n):
    N = 1 << n
    c = S[0]
    basis = [S[1 << k] ^ c for k in range(n)]
    for x in range(N):
        y = c
        for k in range(n):
            if (x >> k) & 1:
                y ^= basis[k]
        if y != S[x]:
            return False
    return True


def gl_columns(n):
    N = 1 << n
    for cols in itertools.product(range(1, N), repeat=n):
        if rank_gf2(list(cols), n) == n:
            yield cols


def sbox_eve_full(S, n, i, r):
    N = 1 << n
    c = sbox_iter(S, 0, sbox_iter(S, 0, 0, i), r)
    for A in range(N):
        for B in range(N):
            for A2 in range(N):
                for B2 in range(N):
                    C = sbox_iter(S, B, A, i)
                    C2 = sbox_iter(S, B2, A2, i)
                    sk = sbox_iter(S, B, C2, r) ^ A
                    if sbox_iter(S, 0, C, r) ^ sbox_iter(S, 0, C2, r) ^ c != sk:
                        return False
    return True


def section7():
    print(SEP2)
    print("§7  Must an agreeing step function be affine?  No.")
    print(SEP2)
    print()
    print("  Family G(A,B) = S(A XOR B), S a permutation, i + r = n, i = 1.  For i = 1")
    print("  the characterization (T) collapses to a single equation, (S.tau_B)^n =")
    print("  tau_c with one c for every B — verified below to be exactly equivalent to")
    print("  full agreement, which makes the sweep cheap enough to be exhaustive.")
    print()
    print("  n   (i,r)   permutations   agree   (T)-equivalent   affine among agreeing")
    for n, i, r in ((2, 1, 1), (3, 1, 2)):
        N = 1 << n
        surv, red = [], []
        for S in itertools.permutations(range(N)):
            if sbox_agrees_full(S, n, i, r):
                surv.append(S)
            if sbox_reduced(S, n) is not None:
                red.append(S)
        total = 1
        for t in range(2, N + 1):
            total *= t
        print(f"  {n}   ({i},{r})   {total:<14} {len(surv):<7} "
              f"{str(set(surv) == set(red)):<16} {sum(is_affine(S, n) for S in surv)}")
    print()
    print("  n = 3 admits nothing at all, affine included — a degenerate width, not a")
    print("  result about S-boxes.  n = 4 is where the question has content, and 16!")
    print("  is out of reach, so the sweep is exhaustive over two honestly-stated")
    print("  families rather than over all permutations:")
    print()
    n, i, r = 4, 1, 3
    N = 16
    affine_ok = []
    affine_total = 0
    for cols in gl_columns(n):
        for cst in range(N):
            S = [0] * N
            for x in range(N):
                y = cst
                for k in range(n):
                    if (x >> k) & 1:
                        y ^= cols[k]
                S[x] = y
            affine_total += 1
            if sbox_reduced(S, n) is not None:
                affine_ok.append(tuple(S))
    print(f"    all affine permutations:          {affine_total:>9} boxes, "
          f"{len(affine_ok)} agree")
    perturbed_ok = []
    perturbed_total = 0
    for S0 in affine_ok:
        for a in range(N):
            for b in range(a + 1, N):
                S = list(S0)
                S[a], S[b] = S[b], S[a]
                perturbed_total += 1
                if sbox_reduced(S, n) is not None:
                    perturbed_ok.append(tuple(S))
    perturbed_ok = list(dict.fromkeys(perturbed_ok))
    nonaffine = [S for S in perturbed_ok if not is_affine(S, n)]
    print(f"    one transposition off an agreeing")
    print(f"    affine box:                       {perturbed_total:>9} boxes, "
          f"{len(perturbed_ok)} agree ({len(nonaffine)} distinct, all non-affine)")
    rng = random.Random(5)
    base = list(range(N))
    hits = 0
    TRIES = 200000
    for _ in range(TRIES):
        S = base[:]
        rng.shuffle(S)
        if sbox_reduced(S, n) is not None:
            hits += 1
    print(f"    uniform random permutations:      {TRIES:>9} sampled, {hits} agree")
    print()
    sample = nonaffine[:40]
    full = all(sbox_agrees_full(list(S), n, i, r) for S in sample)
    eve = all(sbox_eve_full(list(S), n, i, r) for S in sample)
    print(f"  Cross-checks on {len(sample)} of the non-affine survivors, each over all")
    print(f"  {N ** 4} tuples:  full agreement {full},  universal attack wins {eve}.")
    if nonaffine:
        print(f"  Smallest example: S = {list(nonaffine[0])}")
        print("  — the identity with 0 and 1 swapped.  Not affine, agrees anyway.")
    print()
    print("  So TODO #230's conjecture ('G must be affine over an abelian group') is")
    print("  FALSE, and this search refutes it rather than supporting it.  Affineness")
    print("  was the wrong invariant.  The right one is the translation-coset condition")
    print("  (T), which these boxes satisfy and which is what §2's theorem is stated in")
    print("  terms of — so they are broken by it just the same.  The conjecture turning")
    print("  out false costs the item nothing, which is the point of not having built")
    print("  the argument on it.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §8  Verdict
# ─────────────────────────────────────────────────────────────────────────────

def section8():
    print(SEP2)
    print("§8  Verdict")
    print(SEP2)
    print()
    print("  linear S-box        CLOSED as a KEX by §2.  Not a new construction: it is")
    print("                      FSCX with M -> L.M.  Buys a real co-rank improvement")
    print("                      (126 -> 64 at n=256), provably floored at 64.")
    print()
    print("  affine S-box        CLOSED.  Linear plus TODO #224's kappa (§4).")
    print()
    print("  non-linear S-box    CLOSED.  Agreement destroyed at the random-function")
    print("                      rate by a single transposition; the values are")
    print("                      unrelated, not noisy, so no reconciliation branch (§5).")
    print()
    print("  B-keyed S-box       CLOSED (§6).")
    print()
    print("  ANY step function   CLOSED by §2's characterization: agreement forces the")
    print("                      i-fold iterate into a single coset of the translation")
    print("                      group, and then sk = Psi^{-1}(C) XOR Psi^{-1}(C2) XOR c")
    print("                      is computable from the transcript by anyone who knows")
    print("                      the step function.  This is the answer to TODO #230's")
    print("                      real question, and it subsumes TODO #210,")
    print("                      hkex_nonce_impossibility.py and TODO #224.")
    print()
    print("  Success criterion (TODO #230): the characterization theorem, with the")
    print("  S-box case as a corollary.  Met.  The conjectured form of the theorem was")
    print("  wrong — agreement does not require affineness (§7) — and the corrected")
    print("  form is stronger, since it also covers the non-affine solutions the")
    print("  conjecture would have missed.")
    print()
    print("  Out of scope, as the item specified: no --algo tag, PEM boundary label or")
    print("  spec/ entry.  §3's co-rank result is a finding about HSKE/HPKE and needs")
    print("  its own TODO, with wire-format and MIGRATING.md analysis, before anything")
    print("  ships.")
    print()


def main():
    print()
    print(SEP)
    print("TODO #230 — does TODO #224's negative result extend to an S-box layer?")
    print(SEP)
    print()
    section1()
    section2()
    section3()
    section4()
    section5()
    section6()
    section7()
    section8()
    print(SEP)
    print("Summary: it extends, but not by extension — by replacement.  Any step")
    print("         function admitting HKEX-style agreement forces the i-fold iterate")
    print("         into a coset of the translation group, and the session key is then")
    print("         two evaluations of the public step function away from the wire.")
    print("         Linearity, affineness and S-box choice never enter the argument.")
    print(SEP)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
