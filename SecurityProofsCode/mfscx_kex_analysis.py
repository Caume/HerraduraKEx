#!/usr/bin/env python3
"""
mfscx_kex_analysis.py — TODO #224: can a per-step, seed-masked FSCX revolve
(MFSCX_REVOLVE) carry a key exchange whose hardness is symmetric/hash-style
rather than "GF(2^n)* discrete log" or "Ring-LWR"?

The proposed primitive adds a per-step injection to the revolve loop:

    MFSCX_REVOLVE(A, B, i; S):
        for j = 0 .. i-1:
            A <- FSCX(A, B) XOR u_j,      u_j = S_j AND mask_j

with two mask regimes: *static* (mask_j published, identical for every session)
and *dynamic* (mask_j derived from the seed, or from the running state A).

  §1  MFSCX_REVOLVE formalized; the static-mask affine decomposition, measured
  §2  hkex_classical_break.py re-run against static-mask HKEX
  §3  Co-rank of the masked key map (the fscx_revolve_corank.py machinery)
  §4  Does two-party agreement survive a dynamic, state-dependent mask?
  §5  The generalized impossibility theorem: *any* injection schedule
  §6  Orbit structure of a seed-derived mask schedule
  §7  Merkle-puzzle cost table — the honest work a hash-only KEX really needs
  §8  Verdict, branch by branch

RESULTS

§1  With a static mask the whole map stays GF(2)-affine:

        MFSCX_REVOLVE(A,B,i;S) = M^i . A  XOR  T_i . B  XOR  sigma_i(S)

    where T_i = M . S_i is the *unchanged* classical key map and
    sigma_i(S) = XOR_{j<i} M^{i-1-j} . u_j is a constant in (A,B).  Verified
    to hold identically at n = 32/64/128/256 over random (A,B,S).

§2  The break generalizes verbatim.  Both parties still agree, and Eve still
    computes the session key from the wire alone:

        sk = S_{r+1} . (C XOR C2)  XOR  kappa(S),
        kappa(S) = sigma'_r(S) XOR M^r . sigma_i(S)

    kappa is a public constant — S is published in this regime — so Eve's cost
    is unchanged at O(n^2) bit operations.  10 000 sessions, 4 widths, 0 failures.
    The static branch is closed.

§3  A static mask cannot repair the co-rank leak either: it perturbs only the
    constant term, so co-rank(T_i) is still 2(2^{v2(i)} - 1) = 126 of 256 at the
    deployed i = n/4.  One positive result does fall out: the map from a *secret*
    subkey schedule (u_0,...,u_{i-1}) to sigma_i is surjective (rank n, since M is
    a unit), so a secret per-step injection does close the 126-dimensional
    plaintext leak that TODO #210 found in HSKE/HPKE.  That is a statement about
    the pre-shared-key setting, not about key exchange.

§4  A state-dependent mask destroys agreement outright: sk_A == sk_B in 0/2000
    trials at every width.  The parties' states diverge from step 0, so they
    inject different subkeys and no cancellation identity survives.

§5  The generalization of hkex_nonce_impossibility.py closes the middle ground.
    For any schedule u_{A,j} = f_j(A, B, C, C2) and its symmetric counterpart,
    the accumulated injection L = XOR_j M^{r-1-j} . u_j enters sk additively:

        sk_A = S_{r+1} . (C XOR C2)  XOR  L_A,   sk_B = ...  XOR  L_B

    Correctness for all independently drawn key pairs forces L_A = L_B = h(C, C2).
    So an injection schedule either (a) breaks agreement, or (b) contributes a
    value Eve computes from the wire.  There is no third case.  The "cancelling"
    schedules that correctness *does* permit — private u's whose accumulation is
    zero — are exhibited here: agreement holds and sk is still exactly the
    classical public formula.  They add nothing.  Non-linearity in the seed is
    irrelevant to this argument; only the dependence on per-party private data is.

§6  For completeness (plan step 3): a seed-derived mask schedule iterating
    NL-FSCX v1 does *not* collapse — measured mean cycle length tracks the
    random-function expectation sqrt(pi/8) . 2^{n/2} at n = 16/20/24 (146 vs 160,
    640 vs 642, 2264 vs 2567), with a small tail of degenerate seeds.  Orbit
    collapse is therefore not the reason the dynamic branch fails; §4 and §5 are.

§7  Impagliazzo-Rudich caps black-box key agreement from a random oracle at
    Merkle's quadratic gap.  For 2^128 against a classical adversary the honest
    parties do 2^64 oracle calls and ship ~2^64 puzzles; against a quantum
    adversary the best known classical-honest gap is N^{13/12}, i.e. 2^118 honest
    calls, and even with quantum honest parties (gap N^{3/2}) it is 2^85.  All
    three are printed with their bandwidth figures.  Not shippable — as expected,
    but now on record rather than assumed.

§8  Static branch: closed by §2/§3.  Dynamic branch: closed by §4/§5.  The only
    surviving use of MFSCX is the one that never needed a trapdoor — as a PRF/KDF
    or ratchet over an already-shared secret (TODO #224's option 1), or as the
    symmetric layer inside a structured PQC KEM (option 3), where §3's
    surjectivity result is the useful part.  No new --algo tag follows from this
    item.

Self-contained (no imports from the suite), per SecurityProofsCode convention;
the primitives below are transcribed from `Herradura cryptographic suite.py`.
"""

import math
import random

SEP  = "=" * 74
SEP2 = "-" * 74


# ─────────────────────────────────────────────────────────────────────────────
# Primitives (transcribed from the suite)
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1)


def M(x, n):
    """The FSCX linear operator M = I XOR ROL XOR ROR."""
    return x ^ rotl(x, 1, n) ^ rotl(x, -1, n)


def Mpow(x, k, n):
    for _ in range(k):
        x = M(x, n)
    return x


def fscx(a, b, n):
    """FSCX(A,B) = A^B^ROL(A)^ROL(B)^ROR(A)^ROR(B) = M.(A^B)."""
    return M(a ^ b, n)


def S_op(x, k, n):
    """S_k . x = XOR_{j<k} M^j . x."""
    acc, cur = 0, x
    for _ in range(k):
        acc ^= cur
        cur = M(cur, n)
    return acc


def nl_fscx_v1(A, B, n):
    """Suite's NL-FSCX v1 — used here only as a non-linear seed expander."""
    mask = (1 << n) - 1
    mix = (A + B) & mask
    return fscx(A, B, n) ^ rotl(mix, n // 4, n)


def parity(x):
    return bin(x).count("1") & 1


# ─────────────────────────────────────────────────────────────────────────────
# The proposed primitive
# ─────────────────────────────────────────────────────────────────────────────

def static_masks(seed, i, n):
    """A published, session-independent P-box: (mask_j) fixed once, plus the
    subkeys S_j it selects from.  Returns the effective injections u_j."""
    rng = random.Random(seed)
    return [rng.getrandbits(n) & rng.getrandbits(n) for _ in range(i)]


def mfscx_revolve(a, b, steps, n, inj, nonce=0, off=0):
    """MFSCX_REVOLVE with a *precomputed* injection schedule (static regime).

    inj[off + j] is u_j = S_j AND mask_j; `nonce` reproduces the classical
    fscx_revolve_n used by HKEX's derivation step."""
    for j in range(steps):
        a = fscx(a, b, n) ^ nonce ^ inj[off + j]
    return a


def mfscx_revolve_dyn(a, b, steps, n, seed, nonce=0):
    """Dynamic regime: mask_j is derived from the *running state* a, so the
    injection pattern is state- (hence session-) dependent."""
    mask = (1 << n) - 1
    w = seed
    for _ in range(steps):
        w = nl_fscx_v1(w, a, n)          # mask schedule follows the state
        a = fscx(a, b, n) ^ nonce ^ (w & mask)
    return a


def sigma(inj, steps, n, off=0):
    """sigma = XOR_{j<steps} M^{steps-1-j} . u_j — the constant term."""
    acc = 0
    for j in range(steps):
        acc ^= Mpow(inj[off + j], steps - 1 - j, n)
    return acc


# ─────────────────────────────────────────────────────────────────────────────
# §1  Formalization and the static-mask affine decomposition
# ─────────────────────────────────────────────────────────────────────────────

def section1(trials=400):
    print(SEP2)
    print("§1  MFSCX_REVOLVE, and what a static mask actually changes")
    print(SEP2)
    print()
    print("    MFSCX_REVOLVE(A,B,i;S):  A <- FSCX(A,B) XOR (S_j AND mask_j)")
    print()
    print("  Claim:  MFSCX_REVOLVE(A,B,i;S) = M^i . A  XOR  T_i . B  XOR  sigma_i(S)")
    print("          with T_i = M . S_i unchanged from the classical primitive and")
    print("          sigma_i(S) = XOR_{j<i} M^{i-1-j} . u_j  constant in (A,B).")
    print()
    print("  n     i      order(M)  M^n == I   decomposition holds")
    rng = random.Random(20260823)
    for n in (32, 64, 128, 256):
        i = n // 4
        # order of M, measured
        order, cur = 1, M(1, n)
        while cur != 1:
            cur = M(cur, n)
            order += 1
        mn_is_id = all(Mpow(1 << k, n, n) == (1 << k) for k in range(0, n, max(1, n // 8)))
        ok = 0
        for _ in range(trials):
            A, B = rng.getrandbits(n), rng.getrandbits(n)
            inj = static_masks(rng.getrandbits(32), i, n)
            lhs = mfscx_revolve(A, B, i, n, inj)
            rhs = Mpow(A, i, n) ^ M(S_op(B, i, n), n) ^ sigma(inj, i, n)
            ok += (lhs == rhs)
        print(f"  {n:<5} {i:<6} {order:<9} {str(mn_is_id):<10} {ok}/{trials}")
    print()
    print("  The mask moves the constant term and nothing else.  Every linear part")
    print("  of the classical map survives untouched, which is what §2 and §3 exploit.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §2  The classical break, re-run against static-mask HKEX
# ─────────────────────────────────────────────────────────────────────────────

def mfscx_hkex_session(n, inj_pub, inj_der, rng):
    """One honest static-mask HKEX session.  Both parties use the same published
    schedule: inj_pub for the i public steps, inj_der for the r derivation steps."""
    i, r = n // 4, n - n // 4
    A, B = rng.getrandbits(n), rng.getrandbits(n)
    A2, B2 = rng.getrandbits(n), rng.getrandbits(n)

    C = mfscx_revolve(A, B, i, n, inj_pub)
    C2 = mfscx_revolve(A2, B2, i, n, inj_pub)
    N = C ^ C2

    sk_a = mfscx_revolve(C2, B, r, n, inj_der, nonce=N) ^ A
    sk_b = mfscx_revolve(C, B2, r, n, inj_der, nonce=N) ^ A2
    return C, C2, sk_a, sk_b


def eve_recover(C, C2, n, inj_pub, inj_der):
    """Eve, from the wire values and the *published* schedule only:

        sk = S_{r+1} . (C XOR C2)  XOR  kappa,
        kappa = sigma_r(inj_der) XOR M^r . sigma_i(inj_pub)."""
    i, r = n // 4, n - n // 4
    delta = C ^ C2
    kappa = sigma(inj_der, r, n) ^ Mpow(sigma(inj_pub, i, n), r, n)
    return S_op(delta, r + 1, n) ^ kappa


def section2(trials_per_size=2500):
    print(SEP2)
    print("§2  hkex_classical_break.py against the static-mask variant")
    print(SEP2)
    print()
    print("  Both parties run MFSCX with the same published P-box.  Eve sees C, C2")
    print("  and the P-box (it is published by definition of the static regime).")
    print()
    print("  n     agreement       Eve recovers sk   Eve's cost")
    rng = random.Random(20260823)
    total = passed = agree_total = 0
    for n in (32, 64, 128, 256):
        i, r = n // 4, n - n // 4
        inj_pub = static_masks(0xC0FFEE ^ n, i, n)
        inj_der = static_masks(0xBADCAB ^ n, r, n)
        agree = won = 0
        for _ in range(trials_per_size):
            C, C2, sk_a, sk_b = mfscx_hkex_session(n, inj_pub, inj_der, rng)
            if sk_a == sk_b:
                agree += 1
            if eve_recover(C, C2, n, inj_pub, inj_der) == sk_a == sk_b:
                won += 1
        total += trials_per_size
        passed += won
        agree_total += agree
        print(f"  {n:<5} {agree}/{trials_per_size:<10} {won}/{trials_per_size:<15}"
              f" O({r + 1} x {n}) = O({(r + 1) * n}) bit ops")
    print()
    print(f"  Totals: agreement {agree_total}/{total}, recovery {passed}/{total}")
    print()
    if passed == total:
        print("  DISPROOF (expected).  The seed constant kappa cancels out of nothing")
        print("  and hides nothing: it is public, and even if it were not, both parties")
        print("  add the *same* kappa, so it never enters the C XOR C2 relation that")
        print("  determines sk.  The static branch is closed.")
    else:
        print("  Unexpected: recovery failed somewhere.  Investigate before trusting §8.")
    print()
    return passed == total


def section2b(trials=2000):
    """Sub-experiment: does it help if S is *secret* but shared (pre-distributed)?"""
    print(SEP2)
    print("§2b  What if the P-box seed is secret rather than published?")
    print(SEP2)
    print()
    print("  Then kappa is unknown to Eve, and sk = S_{r+1}.(C XOR C2) XOR kappa is")
    print("  a one-time-pad shift of a value she already knows.  Measured: how much")
    print("  of sk does the public part still pin down, per session?")
    print()
    n = 256
    i, r = n // 4, n - n // 4
    rng = random.Random(4242)
    inj_pub = static_masks(0x5EED, i, n)
    inj_der = static_masks(0x5EEE, r, n)
    kappa = sigma(inj_der, r, n) ^ Mpow(sigma(inj_pub, i, n), r, n)
    diffs = set()
    for _ in range(trials):
        C, C2, sk_a, sk_b = mfscx_hkex_session(n, inj_pub, inj_der, rng)
        diffs.add(sk_a ^ S_op(C ^ C2, r + 1, n))
    print(f"  n=256, {trials} sessions, one fixed secret P-box:")
    print(f"    distinct values of  sk XOR S_(r+1).(C XOR C2) :  {len(diffs)}")
    print(f"    that value equals kappa every time            :  {diffs == {kappa}}")
    print()
    print("  So a secret P-box degenerates to a pre-shared static secret recovered")
    print("  from a single known session key — and a construction that needs a")
    print("  pre-shared secret is HSKE, not a key exchange.  This is TODO #224's")
    print("  option 1, and it is not the branch the item is asking about.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  Co-rank of the masked key map (plan step 2)
# ─────────────────────────────────────────────────────────────────────────────

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


def section3():
    print(SEP2)
    print("§3  Co-rank of the masked key map T_i, at the deployed i and r")
    print(SEP2)
    print()
    print("  A static mask contributes no columns to the key map: it is a constant,")
    print("  not a function of B.  fscx_revolve_corank.py's numbers therefore carry")
    print("  over unchanged.  Measured on MFSCX itself, with the injection subtracted:")
    print()
    print("  n     i       co-rank(T_i)  closed form  r=3n/4  co-rank(T_r)")
    for n in (64, 128, 256):
        i, r = n // 4, 3 * n // 4
        inj_i = static_masks(0xF00D ^ n, i, n)
        inj_r = static_masks(0xF11D ^ n, r, n)
        # column k of the masked key map = MFSCX(0, e_k) XOR MFSCX(0, 0)
        base_i = mfscx_revolve(0, 0, i, n, inj_i)
        cols_i = [mfscx_revolve(0, 1 << k, i, n, inj_i) ^ base_i for k in range(n)]
        base_r = mfscx_revolve(0, 0, r, n, inj_r)
        cols_r = [mfscx_revolve(0, 1 << k, r, n, inj_r) ^ base_r for k in range(n)]
        cr_i = n - rank_gf2(cols_i, n)
        cr_r = n - rank_gf2(cols_r, n)
        pred = min(n, 2 * (2 ** v2(i) - 1))
        print(f"  {n:<5} {i:<7} {cr_i:<13} {pred:<12} {r:<7} {cr_r}")
    print()
    print("  Identical to TODO #210's table.  The mask shrinks nothing and repairs")
    print("  nothing — a second, independent reason to reject the static branch.")
    print()
    print("  The one thing a mask *does* buy, if its subkeys are secret: the map")
    print("  (u_0,...,u_{i-1}) -> sigma_i is surjective, because M is a unit in")
    print("  GF(2)[X]/(X^n+1) (m(1) = 1) so every M^{i-1-j} is invertible.")
    print()
    print("  n     i      min_k rank(M^k), k < i   full rank?")
    for n in (64, 128, 256):
        i = n // 4
        ranks = [rank_gf2([Mpow(1 << c, k, n) for c in range(n)], n) for k in range(i)]
        print(f"  {n:<5} {i:<6} {min(ranks):<23} {min(ranks) == n}")
    print()
    print("  So a *secret* per-step injection closes the 126-dimensional plaintext")
    print("  leak TODO #210 found in HSKE/HPKE.  That is a pre-shared-key result")
    print("  (option 1 / option 3), not a key-exchange one.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §4  Does agreement survive a dynamic, state-dependent mask?
# ─────────────────────────────────────────────────────────────────────────────

def section4(trials=2000):
    print(SEP2)
    print("§4  Two-party agreement under a dynamic (state-dependent) mask")
    print(SEP2)
    print()
    print("  mask_j now follows the running state A, so Alice and Bob inject")
    print("  different subkeys from step 0 onwards.")
    print()
    print("  n     sk_A == sk_B    mean Hamming distance sk_A XOR sk_B")
    rng = random.Random(31337)
    for n in (32, 64, 128, 256):
        i, r = n // 4, n - n // 4
        agree = 0
        hw = 0
        for _ in range(trials):
            A, B = rng.getrandbits(n), rng.getrandbits(n)
            A2, B2 = rng.getrandbits(n), rng.getrandbits(n)
            seed = rng.getrandbits(n)
            C = mfscx_revolve_dyn(A, B, i, n, seed)
            C2 = mfscx_revolve_dyn(A2, B2, i, n, seed)
            N = C ^ C2
            sk_a = mfscx_revolve_dyn(C2, B, r, n, seed, nonce=N) ^ A
            sk_b = mfscx_revolve_dyn(C, B2, r, n, seed, nonce=N) ^ A2
            agree += (sk_a == sk_b)
            hw += bin(sk_a ^ sk_b).count("1")
        print(f"  {n:<5} {agree}/{trials:<12} {hw / trials:.1f} of {n} bits")
    print()
    print("  Agreement is destroyed, at the random-function rate: the two states")
    print("  differ by about n/2 bits, exactly as two unrelated values would.  The")
    print("  homomorphism that made C_A XOR C_B a shared quantity is gone with it.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §5  The generalized impossibility theorem
# ─────────────────────────────────────────────────────────────────────────────

def section5(trials=1000):
    print(SEP2)
    print("§5  No middle ground: any injection schedule, generalized")
    print(SEP2)
    print()
    print("  hkex_nonce_impossibility.py proves it for a single nonce.  The same")
    print("  algebra covers a whole schedule, because the injections enter sk only")
    print("  through one accumulator:")
    print()
    print("      sk_A = M^r.(C XOR C2) XOR S_r.N XOR L_A,   L_A = XOR_j M^{r-1-j}.u_{A,j}")
    print("      sk_B = M^r.(C XOR C2) XOR S_r.N XOR L_B")
    print()
    print("  (B, A2, B2 cancel through M.S_n = 0 exactly as in the unmasked case.)")
    print("  Correctness for all independently drawn key pairs forces L_A = L_B, and")
    print("  a value equal across two independent private inputs can depend only on")
    print("  what is common to them: C and C2.  Hence L = h(C, C2), and")
    print()
    print("      sk = S_{r+1}.(C XOR C2) XOR h(C, C2)   —   a function of the wire.")
    print()
    print("  The seed may enter u_j through any non-linear map whatsoever; the")
    print("  argument never differentiates it.  What matters is only whether u_j")
    print("  depends on per-party private data.  Two corollaries, both measured:")
    print()

    n = 128
    i, r = n // 4, n - n // 4
    rng = random.Random(90210)

    # (a) private injections that cancel: correctness survives, sk unchanged.
    print("  (a) Private injections whose accumulator vanishes.  Alice draws u_0")
    print("      from her own private key and sets u_1 = M.u_0, so that")
    print("      M^{r-1}.u_0 XOR M^{r-2}.u_1 = 0; the rest are zero.  Correctness is")
    print("      permitted — and sk is still the classical public formula.")
    agree = same_as_public = 0
    for _ in range(trials):
        A, B = rng.getrandbits(n), rng.getrandbits(n)
        A2, B2 = rng.getrandbits(n), rng.getrandbits(n)
        C = mfscx_revolve(A, B, i, n, [0] * i)
        C2 = mfscx_revolve(A2, B2, i, n, [0] * i)
        N = C ^ C2
        ia = [0] * r
        ia[0], ia[1] = A, M(A, n)                 # private, but cancels
        ib = [0] * r
        ib[0], ib[1] = A2, M(A2, n)               # symmetric, also cancels
        sk_a = mfscx_revolve(C2, B, r, n, ia, nonce=N) ^ A
        sk_b = mfscx_revolve(C, B2, r, n, ib, nonce=N) ^ A2
        pub = S_op(N, r + 1, n)
        agree += (sk_a == sk_b)
        same_as_public += (sk_a == pub)
    print(f"      n={n}: agreement {agree}/{trials}, sk == S_(r+1).(C XOR C2)"
          f" {same_as_public}/{trials}")
    print("      The permitted schedules are exactly the ones that contribute zero.")
    print()

    # (b) private injections that do not cancel: correctness dies.
    print("  (b) The same private injection without the cancelling partner:")
    agree = 0
    for _ in range(trials):
        A, B = rng.getrandbits(n), rng.getrandbits(n)
        A2, B2 = rng.getrandbits(n), rng.getrandbits(n)
        C = mfscx_revolve(A, B, i, n, [0] * i)
        C2 = mfscx_revolve(A2, B2, i, n, [0] * i)
        N = C ^ C2
        ia = [0] * r
        ia[0] = A
        ib = [0] * r
        ib[0] = A2
        sk_a = mfscx_revolve(C2, B, r, n, ia, nonce=N) ^ A
        sk_b = mfscx_revolve(C, B2, r, n, ib, nonce=N) ^ A2
        agree += (sk_a == sk_b)
    print(f"      n={n}: agreement {agree}/{trials}")
    print()
    print("  (a) and (b) are the whole space.  An injection schedule is either")
    print("  invisible to sk or fatal to agreement; 'non-linear in the seed but")
    print("  commutative in the two contributions' does not name a third option,")
    print("  because commutativity here *is* the requirement that the private part")
    print("  cancel.  TODO #224's success criterion is therefore not met by any")
    print("  seed-masked FSCX revolve.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §6  Orbit structure of a seed-derived mask schedule (plan step 3)
# ─────────────────────────────────────────────────────────────────────────────

def brent_cycle(x0, step, cap):
    """Brent's cycle detection.  Returns (lam, mu) or (None, None) past cap."""
    power = lam = 1
    tortoise, hare = x0, step(x0)
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = step(hare)
        lam += 1
        if lam > cap:
            return None, None
    mu = 0
    tortoise = hare = x0
    for _ in range(lam):
        hare = step(hare)
    while tortoise != hare:
        tortoise, hare = step(tortoise), step(hare)
        mu += 1
    return lam, mu


def section6(seeds=200):
    print(SEP2)
    print("§6  Does the seed-derived mask schedule collapse into a short cycle?")
    print(SEP2)
    print()
    print("  A mask schedule w_{j+1} = NL-FSCX-v1(w_j, B) that lands in a short cycle")
    print("  silently degenerates to the static regime.  Cycle lengths, by Brent:")
    print()
    print("  n     seeds  mean lambda   median   min   E[cycle] = sqrt(pi/8)*2^(n/2)")
    rng = random.Random(777)
    for n in (16, 20, 24):
        cap = 1 << (n // 2 + 6)
        lams = []
        for _ in range(seeds):
            B = rng.getrandbits(n)
            lam, _mu = brent_cycle(rng.getrandbits(n),
                                   lambda w, B=B, n=n: nl_fscx_v1(w, B, n), cap)
            if lam is not None:
                lams.append(lam)
        lams.sort()
        exp = math.sqrt(math.pi / 8) * (2 ** (n / 2))
        print(f"  {n:<5} {len(lams):<6} {sum(lams) / len(lams):<13.1f}"
              f" {lams[len(lams) // 2]:<8} {lams[0]:<5} {exp:.1f}")
    print()
    print("  Degenerate seeds do exist — w = 0 with B = 0 is a fixed point — but the")
    print("  bulk tracks the random-function cycle-length expectation.  Orbit collapse")
    print("  is not what kills the dynamic branch; §4 and §5 already did.")
    print()
    n = 16
    fixed = sum(1 for w in range(1 << n) if nl_fscx_v1(w, 0, n) == w)
    print(f"  n={n}, B=0: {fixed} fixed point(s) out of {1 << n} states.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §7  The Merkle-puzzle ceiling
# ─────────────────────────────────────────────────────────────────────────────

def section7():
    print(SEP2)
    print("§7  What a hash-only key exchange actually costs (option 2)")
    print(SEP2)
    print()
    print("  Impagliazzo-Rudich: relative to a random oracle, black-box key agreement")
    print("  cannot beat Merkle's quadratic gap.  With N puzzles the honest parties do")
    print("  ~N oracle calls; the adversary's best is:")
    print()
    print("    classical honest, classical Eve   N^2       Merkle; Impagliazzo-Rudich")
    print("                                                  makes it a ceiling, not")
    print("                                                  merely the best known")
    print("    classical honest, quantum Eve     N^(13/12)  Brassard-Hoyer-Kalach-")
    print("                                                  Kaplan-Laplante-Salvail;")
    print("                                                  plain Merkle falls to N")
    print("                                                  under Grover")
    print("    quantum honest,   quantum Eve     N^(3/2)    same authors")
    print()
    print("  Honest work and bandwidth to reach a 2^128 adversary bound, at 32 bytes")
    print("  of puzzle on the wire:")
    print()
    print("  setting                          honest calls   wire bytes    feasible")
    rows = [
        ("classical honest / classical Eve", 128 / 2),
        ("classical honest / quantum Eve",   128 * 12 / 13),
        ("quantum honest   / quantum Eve",   128 * 2 / 3),
    ]
    for label, log_n in rows:
        wire_log = log_n + 5                       # 32 bytes = 2^5
        print(f"  {label:<32} 2^{log_n:<12.1f} 2^{wire_log:<11.1f} no")
    print()
    print("  For scale, 2^64 32-byte puzzles is ~5.9e8 TB — more than the installed")
    print("  storage on Earth, per handshake.  The cheapest line still needs 2^85")
    print("  honest oracle calls, and it assumes quantum honest parties.  The exact")
    print("  exponent in the middle row has been nudged upward since 2011 and may")
    print("  move again; nothing that fits between 1 and 2 changes the conclusion.")
    print("  The number is now on the record, which is the point of tabulating it")
    print("  rather than assuming it.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §8  Verdict
# ─────────────────────────────────────────────────────────────────────────────

def section8():
    print(SEP2)
    print("§8  Verdict per branch")
    print(SEP2)
    print()
    print("  static P-box            CLOSED.  Affine; break generalizes verbatim (§2);")
    print("                          co-rank unchanged at 126/256 (§3).")
    print()
    print("  secret shared P-box     NOT A KEX.  kappa is recovered from one known")
    print("                          session key (§2b); needs a pre-shared secret.")
    print()
    print("  dynamic P-box           CLOSED.  Agreement fails at the random-function")
    print("                          rate (§4), and §5 shows the only schedules that")
    print("                          preserve agreement contribute nothing to sk.")
    print()
    print("  hash-only (Merkle)      PROVABLE, UNSHIPPABLE.  2^64 honest calls at best")
    print("                          classically, 2^118 against a quantum Eve (§7).")
    print()
    print("  MFSCX as PRF/KDF        ALIVE, and the only branch that is.  Hardness")
    print("  inside a structured KEM  comes from the code/lattice; MFSCX only has to")
    print("                          mix.  §3's surjectivity result is the useful")
    print("                          piece: a secret per-step injection closes TODO")
    print("                          #210's 126-dimensional plaintext leak.")
    print()
    print("  Success criterion (TODO #224): a negative result.  No seed-masked FSCX")
    print("  revolve gives key agreement whose hardness is anything other than a")
    print("  restatement of 'FSCX is affine'.  No --algo tag, PEM label, or spec/")
    print("  entry follows from this item.")
    print()


def main():
    print()
    print(SEP)
    print("TODO #224 — masked-step / hash-based HKEX variant (MFSCX-KEX)")
    print(SEP)
    print()
    section1()
    ok = section2()
    section2b()
    section3()
    section4()
    section5()
    section6()
    section7()
    section8()
    print(SEP)
    print("Summary: the static mask leaves the map affine and the classical break")
    print("         intact; the dynamic mask destroys two-party agreement; and the")
    print("         generalized impossibility theorem shows every schedule in between")
    print("         either breaks agreement or contributes only what Eve can compute.")
    print("         MFSCX survives as a symmetric layer, not as a key exchange.")
    print(SEP)
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
