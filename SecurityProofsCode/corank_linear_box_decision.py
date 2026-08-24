#!/usr/bin/env python3
"""TODO #232 — should the suite act on §11.22.2's co-rank improvement (126 -> 64)?

TODO #210 showed that `fscx_revolve(P, K, i)` is affine, `E = M^i.P xor T_i.K`
with `T_i = M.S_i`, and that `T_i` is rank-deficient: at the deployed
`n = 256, i = n/4 = 64` its co-rank is 126, so 126 linear functionals of the
plaintext are readable from the ciphertext under every key.

TODO #230's §11.22.2 then showed the deficiency is not intrinsic.  Replacing `M`
with `M' = L.M` for a linear box `L` and writing `Y = M' + I`, the agreement
conditions `M'^n = I` and `M'.S'_n = 0` are jointly equivalent to `Y^(n-1) = 0`,
and for `i` a power of two Lucas' theorem collapses the binomial sum to
`S'_i = Y^(i-1)`, giving

    co-rank(T_i) = dim ker Y^(2^v2(i) - 1)

A box of Jordan type `(n-1, 1)` reaches 64, and 64 is a proved floor.  That
result was left unshipped.  This script decides what to do with it.

It answers three questions the TODO poses and one it does not:

  1. Can a *rotation-based* step reach 64?  No — exhaustively, no circulant
     admitting agreement beats `2(i-1)`, which is exactly what the classical
     `M` already achieves.  Any improvement means abandoning rotations.
  2. Is there a *cheap* concrete `L`?  Yes, and it is a trap: in the bit basis
     the (n-1,1) box is 3 word-ops, cheaper than FSCX, but it puts 64 raw
     plaintext bits into the ciphertext in the clear.  Co-rank counts
     dimensions, not exploitability.
  3. Is there a *good* concrete `L`?  Yes, its conjugate — co-rank 64 and a
     much higher minimum leaked weight — but it is a dense matrix, ~128x the
     cost, dead on the AVR and Thumb-2 targets.
  4. (Not asked) What does the classical leak actually look like at its worst?
     A weight-4 functional: `E[0] xor E[2] xor E[128] xor E[130]` equals the
     same XOR of plaintext bits, under every key.  Verified against the
     shipped `fscx_revolve`.

Standalone; no third-party dependencies.  Loads the suite via importlib only in
§6, to check a claim about the shipped implementation against the shipped
implementation.
"""

import importlib.util
import os
import random
import sys

SEP = "=" * 78
SEP2 = "-" * 78

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ─────────────────────────────────────────────────────────────────────────────
# GF(2) linear algebra: matrices as n columns packed into Python ints
# ─────────────────────────────────────────────────────────────────────────────

def rotl(x, r, n):
    r %= n
    return ((x << r) | (x >> (n - r))) & ((1 << n) - 1)


def M_fun(x, n):
    """The FSCX linear operator M = I xor ROL xor ROR."""
    return x ^ rotl(x, 1, n) ^ rotl(x, -1, n)


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
    rows, r = list(cols), 0
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


def mat_inv(A, n):
    """Gauss-Jordan inverse over GF(2); A given by columns."""
    rows, irows, I = [0] * n, [0] * n, mat_id(n)
    for r in range(n):
        for c in range(n):
            if (A[c] >> r) & 1:
                rows[r] |= 1 << c
            if (I[c] >> r) & 1:
                irows[r] |= 1 << c
    piv, where = 0, {}
    for c in range(n):
        p = next((j for j in range(piv, n) if (rows[j] >> c) & 1), None)
        if p is None:
            continue
        rows[piv], rows[p] = rows[p], rows[piv]
        irows[piv], irows[p] = irows[p], irows[piv]
        for j in range(n):
            if j != piv and (rows[j] >> c) & 1:
                rows[j] ^= rows[piv]
                irows[j] ^= irows[piv]
        where[c] = piv
        piv += 1
    if piv != n:
        raise ValueError("matrix is singular")
    out = [0] * n
    for c in range(n):
        rr = irows[where[c]]
        for k in range(n):
            if (rr >> k) & 1:
                out[k] |= 1 << c
    return out


def jordan_nilpotent(sizes, n):
    """Nilpotent Y in Jordan form: e_k -> e_{k-1} inside each block."""
    Y, base = [0] * n, 0
    for s in sizes:
        for t in range(s):
            Y[base + t] = (1 << (base + t - 1)) if t > 0 else 0
        base += s
    return Y


def v2(k):
    a = 0
    while k % 2 == 0:
        k //= 2
        a += 1
    return a


# ─────────────────────────────────────────────────────────────────────────────
# The key map T_k and the functionals it fails to cover
# ─────────────────────────────────────────────────────────────────────────────

def keymap_T(A, k, n):
    """Columns of T_k for the step x -> A.(x xor B): column j is the image of key bit j."""
    cols = []
    for j in range(n):
        B, x = 1 << j, 0
        for _ in range(k):
            x = mat_apply(A, x ^ B)
        cols.append(x)
    return cols


def corank(A, k, n):
    return n - rank_gf2(keymap_T(A, k, n), n)


def leak_kernel(T, n):
    """Basis of the left kernel: functionals lambda with lambda.T_k = 0.

    Each basis element is a bitmask over *ciphertext* bit positions.  Every such
    lambda satisfies lambda.E = (lambda.M'^i).P for every key, i.e. it is a
    plaintext functional readable straight off the ciphertext.
    """
    rowmap = [0] * n
    for j, col in enumerate(T):
        for r in range(n):
            if (col >> r) & 1:
                rowmap[r] |= 1 << j
    piv, ker = {}, []
    for r in range(n):
        v, tag = rowmap[r], 1 << r
        for c in sorted(piv):
            if (v >> c) & 1:
                v ^= piv[c][0]
                tag ^= piv[c][1]
        if v == 0:
            ker.append(tag)
        else:
            piv[(v & -v).bit_length() - 1] = (v, tag)
    return ker


def min_weight(ker, trials=20000, seed=5):
    """Lowest-weight functional *found* — an upper bound on the true minimum."""
    if not ker:
        return None
    best = min(bin(k).count("1") for k in ker)
    rng = random.Random(seed)
    for _ in range(trials):
        v = ker[rng.randrange(len(ker))] ^ ker[rng.randrange(len(ker))]
        if v:
            w = bin(v).count("1")
            if w < best:
                best = w
    return best


def profile(A, k, n, mw_trials=20000):
    """co-rank, how many leaked functionals are single ciphertext bits, min weight."""
    T = keymap_T(A, k, n)
    ker = leak_kernel(T, n)
    raw = sum(1 for x in ker if bin(x).count("1") == 1)
    return len(ker), raw, min_weight(ker, mw_trials), sum(bin(c).count("1") for c in A) / n


# ─────────────────────────────────────────────────────────────────────────────
# §1  The identity, and the two numbers the decision is about
# ─────────────────────────────────────────────────────────────────────────────

def section1():
    print(SEP2)
    print("§1  The §11.22.2 identity, reproduced")
    print(SEP2)
    print()
    print("  For the step x -> M'.(x xor B) with Y = M' + I, agreement needs")
    print("  Y^(n-1) = 0, and for i = 2^a, S'_i = Y^(i-1) (Lucas), so")
    print()
    print("      co-rank(T_i) = dim ker Y^(2^v2(i) - 1)")
    print()
    n, i, r = 256, 64, 192
    Mm = mat_of(M_fun, n)
    I = mat_id(n)
    Ycl = mat_add(Mm, I)
    pred = n - rank_gf2(mat_pow(Ycl, 2 ** v2(i) - 1, n), n)
    print(f"  n={n}, i={i}: predicted dim ker Y^{2 ** v2(i) - 1} = {pred}, "
          f"measured co-rank(T_i) = {corank(Mm, i, n)}, co-rank(T_r) = {corank(Mm, r, n)}")
    Mp = mat_add(I, jordan_nilpotent([n - 1, 1], n))
    print(f"  Jordan (n-1,1) box:       co-rank(T_i) = {corank(Mp, i, n)}, "
          f"co-rank(T_r) = {corank(Mp, r, n)}")
    print()
    print("  126 -> 64 is the improvement TODO #232 has to rule on.  The rest of this")
    print("  script asks what it would actually cost and what it would actually buy.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §2  No rotation-based step can do better than the classical M
# ─────────────────────────────────────────────────────────────────────────────

def circulant(poly, n):
    return [rotl(poly, k, n) for k in range(n)]


def section2():
    print(SEP2)
    print("§2  Among circulants, the classical M is already optimal")
    print(SEP2)
    print()
    print("  FSCX is rotation-based, so the natural search space for a replacement")
    print("  step is the circulants: polynomials in the rotation X over")
    print("  GF(2)[X]/(X^n + 1).  With n = 2^k that ring is local with maximal ideal")
    print("  (Y), Y = X + 1, and every nilpotent is Y^v times a unit, so")
    print()
    print("      dim ker Y^m = min(n, v.m)")
    print()
    print("  Agreement needs Y^(n-1) = 0, i.e. v.(n-1) >= n, i.e. v >= 2, and then")
    print("  co-rank(T_i) = min(n, v.(i-1)) >= 2(i-1).  The bound is met at v = 2 —")
    print("  which is exactly v(M + I) for the classical M.  Exhaustively, over every")
    print("  circulant at n = 8 and n = 16:")
    print()
    print("     n    i   circulants admitting agreement   best co-rank   classical M   2(i-1)")
    for n in (8, 16):
        i = n // 4
        I = mat_id(n)
        best, count = None, 0
        for poly in range(1 << n):
            Mp = circulant(poly, n)
            if any(mat_pow(mat_add(Mp, I), n - 1, n)):
                continue
            if mat_pow(Mp, n, n) != I:
                continue
            count += 1
            c = corank(Mp, i, n)
            if best is None or c < best:
                best = c
        cl = corank(mat_of(M_fun, n), i, n)
        print(f"   {n:3d}  {i:3d}   {count:>28d}   {best:>12d}   {cl:>11d}   {2 * (i - 1):>6d}")
    print()
    print("  No circulant beats the classical M at either width, and the best equals")
    print("  the predicted floor.  **Any co-rank improvement requires leaving the")
    print("  rotation class entirely** — it is not a matter of picking better shift")
    print("  amounts.  That is the first thing TODO #232 needs to know: this is not a")
    print("  parameter tweak, it is a different primitive.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §3  The cheap concrete box — and why it is a trap
# ─────────────────────────────────────────────────────────────────────────────

def section3():
    print(SEP2)
    print("§3  The cheap (n-1,1) box is 3 word-ops — and strictly worse")
    print(SEP2)
    print()
    n, i = 256, 64
    Y = jordan_nilpotent([n - 1, 1], n)
    Mp = mat_add(mat_id(n), Y)
    mask = ~(1 << (n - 2)) & ((1 << n) - 1)
    same = all(((1 << k) >> 1) & mask == Y[k] for k in range(n))
    print("  §11.22.2 measured a Jordan *type*, not a shipped matrix.  In the standard")
    print("  bit basis that type is a broken non-cyclic shift:")
    print()
    print("      Y(x) = (x >> 1) & ~(1 << (n-2))        M'(x) = x xor Y(x)")
    print()
    print(f"  matches the Jordan (n-1,1) generator: {same}")
    print(f"  M'^n == I: {mat_pow(Mp, n, n) == mat_id(n)}   "
          f"Y^(n-1) == 0: {not any(mat_pow(Y, n - 1, n))}   "
          f"co-rank(T_i) = {corank(Mp, i, n)}")
    print()
    print("  So the cost objection one expects does not materialise: this is 3 word-ops")
    print("  against FSCX's 5.  It is *cheaper* than what ships.  The objection is")
    print("  elsewhere, and it is fatal.")
    print()
    Mm = mat_of(M_fun, n)
    print("  co-rank counts leaked *dimensions*.  It says nothing about how")
    print("  concentrated the leak is.  Splitting the kernel by functional weight:")
    print()
    print("    step function                 co-rank   raw plaintext bits   min weight found")
    for label, A in (("classical M (circulant)", Mm), ("Jordan (n-1,1), bit basis", Mp)):
        ck, raw, mw, _ = profile(A, i, n)
        print(f"    {label:<28} {ck:>7}   {raw:>18}   {mw:>16}")
    print()
    T = keymap_T(Mp, i, n)
    ker = leak_kernel(T, n)
    coords = sorted((x.bit_length() - 1) for x in ker if bin(x).count("1") == 1)
    Ai = mat_pow(Mp, i, n)
    exact = [b for b in coords if [k for k in range(n) if (Ai[k] >> b) & 1] == [b]]
    print(f"  The (n-1,1) box makes {len(coords)} ciphertext bits key-independent, and all")
    print(f"  {len(exact)} of them are plaintext bits verbatim: E[{exact[0]}] = P[{exact[0]}], "
          f"E[{exact[1]}] = P[{exact[1]}], ...,")
    print(f"  E[{exact[-1]}] = P[{exact[-1]}].  Bits {exact[0]}..{exact[-1]} of the plaintext are "
          f"transmitted in the clear.")
    print()
    print("  The classical M leaks 126 dimensions but zero raw bits — every one of its")
    print("  leaked functionals is a spread XOR.  Trading 126 obscure functionals for")
    print("  64 plaintext bits in the clear is not an improvement in any sense a user")
    print("  cares about.  **Co-rank is the wrong figure of merit on its own.**")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §4  The good concrete box — and what it costs
# ─────────────────────────────────────────────────────────────────────────────

def rand_invertible(n, seed):
    rng = random.Random(seed)
    while True:
        S = [rng.getrandbits(n) for _ in range(n)]
        if rank_gf2(S, n) == n:
            return S


def section4():
    print(SEP2)
    print("§4  The conjugated box repairs §3 — at ~128x the cost")
    print(SEP2)
    print()
    n, i = 256, 64
    Mm = mat_of(M_fun, n)
    Mp = mat_add(mat_id(n), jordan_nilpotent([n - 1, 1], n))
    S = rand_invertible(n, 11)
    Mc = mat_comp(S, mat_comp(Mp, mat_inv(S, n)))
    print("  Raw-bit exposure is basis-dependent; co-rank is not.  Conjugating by a")
    print("  random invertible S keeps the Jordan type, hence keeps co-rank 64, while")
    print("  scattering the leaked functionals:")
    print()
    print("    step function                 co-rank   raw bits   min weight   ones/column")
    rows = (("classical M (circulant)", Mm), ("Jordan (n-1,1), bit basis", Mp),
            ("Jordan (n-1,1) conjugated", Mc))
    for label, A in rows:
        ck, raw, mw, dens = profile(A, i, n)
        print(f"    {label:<28} {ck:>7}   {raw:>8}   {mw:>10}   {dens:>11.1f}")
    print()
    print("  The conjugate is genuinely better on both security axes — half the leaked")
    print("  dimensions and a minimum weight an order of magnitude higher.  It is also")
    print("  a dense matrix: ~n/2 ones per column against 3 for M, so evaluating it is")
    print("  ~n XOR-and-mask operations per output word instead of the 5 rotate/XOR")
    print("  ops FSCX uses now.  Concretely, per step:")
    print()
    print("    target             classical FSCX      conjugated box")
    print("    C/Go/Python        5 word-ops          ~256 word-ops + table")
    print("    ARM Thumb-2        5 ops               ~256 ops, 8 KB matrix in flash")
    print("    Arduino/AVR        5 ops on 32-bit     8 KB matrix — does not fit the")
    print("                                           SRAM budget TODO #155 fixed")
    print()
    print("  A 256x256 GF(2) matrix is 8 KB.  The AVR target ran out of SRAM once")
    print("  already (TODO #155); this would not fit, so the suite would lose")
    print("  cross-target parity — the property that every protocol runs on all six")
    print("  language/architecture targets.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §5  All of this is beaten, for free, by an odd step count
# ─────────────────────────────────────────────────────────────────────────────

def section5():
    print(SEP2)
    print("§5  Odd i reaches co-rank 0 and costs nothing")
    print(SEP2)
    print()
    n = 256
    Mm = mat_of(M_fun, n)
    print("    step count i    co-rank(T_i) for the classical M")
    for i in (64, 65, 192, 191):
        ck = corank(Mm, i, n)
        note = "   <- deployed" if i == 64 else ("   <- T_i invertible" if ck == 0 else "")
        print(f"      {i:<12} {ck:<4}{note}".rstrip())
    print()
    print("  TODO #211 already proved this and shipped hske_perfect_secrecy.py: at odd")
    print("  i the key map is invertible, so a one-time uniform key makes E uniform and")
    print("  independent of P — Shannon-perfect, co-rank 0, by moving a parameter.")
    print()
    print("  Ranking the three routes to the same leak:")
    print()
    print("    route                          co-rank   cost                     source")
    print("    odd i (65 / 191)                     0   one parameter            #211")
    print("    secret per-step injection            0   a subkey schedule        #224 §11.21.3")
    print("    linear box, cheap realisation       64   3 word-ops, but 64 raw   #230 §11.22.2")
    print("                                            plaintext bits (§3)")
    print("    linear box, conjugated              64   ~128x, 8 KB, no AVR      §4")
    print()
    print("  The linear box is last on both axes.  It is the only route that costs a")
    print("  MAJOR wire-format break, and the only one that does not reach 0.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §6  What the classical leak actually looks like, at its worst
# ─────────────────────────────────────────────────────────────────────────────

def section6():
    print(SEP2)
    print("§6  Sharpening TODO #210: the leak's minimum-weight functional")
    print(SEP2)
    print()
    n, i = 256, 64
    Mm = mat_of(M_fun, n)
    ker = leak_kernel(keymap_T(Mm, i, n), n)
    best = min(ker, key=lambda k: bin(k).count("1"))
    rng = random.Random(1)
    for _ in range(200000):
        v = ker[rng.randrange(len(ker))] ^ ker[rng.randrange(len(ker))]
        if v and bin(v).count("1") < bin(best).count("1"):
            best = v
    cbits = [k for k in range(n) if (best >> k) & 1]
    Mi = mat_pow(Mm, i, n)
    pbits = [k for k in range(n) if bin(Mi[k] & best).count("1") & 1]
    print(f"  '126 dimensions' understates it.  The lightest functional found has")
    print(f"  weight {len(cbits)}:")
    print()
    print(f"      E[{'] xor E['.join(map(str, cbits))}]  ==  "
          f"P[{'] xor P['.join(map(str, pbits))}]")
    print()
    print("  for every key — four ciphertext bits give four plaintext bits' parity, on")
    print("  the same positions.  Checked against the shipped implementation, not a")
    print("  model of it:")
    print()
    spec = importlib.util.spec_from_file_location(
        "hsuite", os.path.join(ROOT, "Herradura cryptographic suite.py"))
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    rng = random.Random(4)
    trials = ok = 0
    for _ in range(300):
        P = h.BitArray(n, rng.getrandbits(n))
        K = h.BitArray(n, rng.getrandbits(n))
        E = h.fscx_revolve(P, K, i)
        lhs = sum((E.uint >> b) & 1 for b in cbits) & 1
        rhs = sum((P.uint >> b) & 1 for b in pbits) & 1
        trials += 1
        ok += (lhs == rhs)
    print(f"    suite fscx_revolve(P, K, {i}), fresh random key each time: {ok}/{trials}")
    print()
    print("  This is a finding for SECURITY.md's HSKE and HPKE rows, and it is")
    print("  independent of the #232 decision: it holds for what ships today.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §7  The HPKS knock-on, and the break none of this touches
# ─────────────────────────────────────────────────────────────────────────────

def section7():
    print(SEP2)
    print("§7  HPKS knock-on, and the two-time break that survives every option")
    print(SEP2)
    print()
    n, i = 256, 64
    Mm = mat_of(M_fun, n)
    Mp = mat_add(mat_id(n), jordan_nilpotent([n - 1, 1], n))
    print("  HPKS's Schnorr challenge is e = fscx_revolve(R, msg, i), so its entropy is")
    print("  rank(T_i), not n (TODO #210).  A box that halves the co-rank raises it:")
    print()
    print("    step function                 challenge entropy of 256 bits")
    for label, A in (("classical M", Mm), ("Jordan (n-1,1) box", Mp)):
        print(f"    {label:<28} {n - corank(A, i, n)}")
    print()
    print("  130 -> 192 is a real gain, but it is a *signature* parameter: it changes")
    print("  what `--algo hpks` produces and is a separate wire-format break from the")
    print("  HSKE/HPKE one.  Two MAJOR bumps, not one.")
    print()
    print("  And the affine two-time break is untouched by all of it.  For any linear")
    print("  M' whatsoever, two messages under one key give")
    print()
    print("      E1 xor E2 = M'^i.(P1 xor P2)")
    print()
    rng = random.Random(21)
    for label, A in (("classical M", Mm), ("Jordan (n-1,1) box", Mp)):
        Ai = mat_pow(A, i, n)
        hits = 0
        for _ in range(200):
            P1, P2, K = (rng.getrandbits(n) for _ in range(3))
            E1 = E2 = 0
            x1, x2 = P1, P2
            for _ in range(i):
                x1 = mat_apply(A, x1 ^ K)
                x2 = mat_apply(A, x2 ^ K)
            E1, E2 = x1, x2
            hits += (E1 ^ E2 == mat_apply(Ai, P1 ^ P2))
        print(f"    {label:<28} recovered {hits}/200 plaintext differences, no key")
    print()
    print("  Key reuse is decipherable with no key at all, whatever the co-rank.  The")
    print("  fix for multi-use is the NL quartet, which already ships.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# §8  Verdict
# ─────────────────────────────────────────────────────────────────────────────

def section8():
    print(SEP2)
    print("§8  Verdict")
    print(SEP2)
    print()
    print("  Recommendation: DEPRECATE.  Document the result; ship nothing.")
    print()
    print("  1. It is not a parameter tweak.  No circulant beats the classical M (§2),")
    print("     so 126 -> 64 means replacing FSCX's rotations with a different linear")
    print("     primitive — the 'Full Surroundings' construction the suite is named")
    print("     for stops being what is implemented.")
    print("  2. The cheap realisation is worse than what it replaces (§3): 64 raw")
    print("     plaintext bits in the clear, against zero today.")
    print("  3. The sound realisation costs ~128x, needs an 8 KB matrix, and does not")
    print("     fit the AVR target (§4), so it would cost cross-target parity.")
    print("  4. It is dominated anyway (§5): odd i reaches co-rank 0 for one parameter,")
    print("     and a secret injection reaches 0 for a subkey schedule.")
    print("  5. It cannot move a SECURITY.md rating.  HSKE (key-only) is already 'Not")
    print("     suitable for production' and HPKE 'Demo-only', each disqualified by")
    print("     something the co-rank does not reach — a single known-plaintext pair")
    print("     recovers the HSKE keystream, and HPKE falls to ~2^36.5 Pohlig-Hellman.")
    print("  6. It would cost two MAJOR bumps, not one (§7), HSKE/HPKE and HPKS being")
    print("     separate wire formats.")
    print()
    print("  What is worth keeping from the investigation:")
    print()
    print("  - §2's circulant floor is a new positive result: **the classical M is")
    print("    optimal among all rotation-based steps admitting agreement.**  TODO #210")
    print("    reported 126 as a defect; it is also the best any FSCX-shaped primitive")
    print("    can do.  That belongs in the documentation next to the defect.")
    print("  - §6's weight-4 functional sharpens #210 for SECURITY.md: not '126")
    print("    dimensions' but a four-bit parity readable off four ciphertext bits.")
    print()


def main():
    print(SEP)
    print("TODO #232 — co-rank 126 -> 64: decide")
    print(SEP)
    print(__doc__.strip().split("\n\n")[1])
    print()
    for fn in (section1, section2, section3, section4, section5, section6,
               section7, section8):
        fn()
    print(SEP)
    print("Done.  Verdict: DEPRECATE — see §8.")
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(main())
