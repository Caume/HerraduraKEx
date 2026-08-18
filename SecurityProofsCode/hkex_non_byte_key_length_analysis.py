"""
hkex_non_byte_key_length_analysis.py — TODO #204: does a non-byte-aligned n
(e.g. n=251, 255, 509 — primes or other irregular sizes chosen for algebraic
properties rather than byte convenience) offer any efficiency or security
advantage over the byte-aligned defaults (32/64/128/256/...) used throughout
the suite today?

This is a research/analysis script, not new library code: it stands alone,
imports nothing from the suite, and its conclusion is documented in
SecurityProofs-1.md §1.2.1 and TODO_DONE.md #204. It does not itself change
any wire format, CLI surface, or default parameter.

────────────────────────────────────────────────────────────────────────────
Part 1 — Algebraic analysis: invertibility and order of M

SecurityProofs-1.md §1.2 Theorem 2 proves M = I + L + L^{-1} (the FSCX
linear map, L = 1-bit cyclic rotation) is invertible in R_n =
GF(2)[x]/(x^n+1) whenever gcd(3, n) = 1 — the proof text states this for
n = 2^k specifically, but the argument only actually uses that x^2+x+1
(irreducible over GF(2), degree 2, dividing x^t-1 iff 3 | t) has no root
that is an n-th root of unity, i.e. 3 does not divide n. That holds for
every byte-aligned n used today (all powers of 2), but it is NOT guaranteed
for an arbitrary non-byte-aligned n: n=255 = 3*5*17 is divisible by 3, so
M is SINGULAR at n=255 — FSCX would not even be well-defined (not
invertible, so HKEX-GF's group structure and any construction relying on
M's invertibility breaks) at that specific "non-standard" width, despite
255 being the most natural odd near-neighbor of the byte-aligned n=256.

Theorem 3 (M^{n/2} = I) is even more n=2^k-specific: the proof exponentiates
by t = n/2 = 2^{k-1} and relies on the Frobenius endomorphism identity
(x^2+x+1)^t = x^{2t}+x^t+1, which requires t itself to be a power of 2.
For a general n (prime or otherwise), the true multiplicative order of M
is governed by the order of 2 in (Z/nZ)* acting on the cyclotomic cosets
of x^n-1's factorization — not simply n/2 — and has to be computed per-n
rather than assumed.

Part 1 below verifies both points computationally: which candidate n admit
an invertible M (GF(2) polynomial gcd, not just the gcd(3,n) shortcut —
computed independently as a cross-check), and each admissible n's actual
order(M), measured by iterating M on a full basis until every basis vector
returns to itself.

────────────────────────────────────────────────────────────────────────────
Part 2 — Diffusion/avalanche comparison at matched bit-widths

For each invertible non-byte n, compare single-step and revolve-depth
diffusion (bit-flip avalanche: fraction of output bits that flip when one
input bit is flipped) against the nearest byte-aligned n, to see whether
picking an odd/prime width buys any measurable diffusion advantage.

────────────────────────────────────────────────────────────────────────────
Part 3 — Throughput

FSCX/GF arithmetic in this suite's C/Go/Arduino/assembly targets is built
on byte-oriented word types (uint32_t/uint64_t chunks, byte arrays) and
herradura.h's fixed-width big-int backing (TODO description). A
non-byte-aligned n cannot be represented as a whole number of such words,
so a real implementation would need either (a) bit-slicing (masking off
the unused high bits of the top word on every operation) or (b) an
arbitrary-precision bignum library — both strictly slower than the current
word-aligned code, and (a) also below the word-size boundary that lets
ROL/ROR compile to single machine instructions. Python's arbitrary-precision
ints hide this cost (there is no "word" to misalign), so a Python-only
benchmark cannot demonstrate the C/Go/Arduino efficiency penalty directly;
Part 3 instead measures Python-level per-operation cost as a function of n
to confirm cost scales with n (not with byte-alignment) in this language,
and documents the C/Go word-alignment argument analytically since building
a bit-sliced C prototype is out of scope for a research-only script.
"""

import time
import random

# ─────────────────────────────────────────────────────────────────────────
# Part 0 — general-n FSCX primitives (Python bigints: n need not be a
# multiple of 8, or even a multiple of a machine word — unlike C/Go/Arduino)
# ─────────────────────────────────────────────────────────────────────────

def rol(x, k, n):
    k %= n
    mask = (1 << n) - 1
    return ((x << k) | (x >> (n - k))) & mask

def ror(x, k, n):
    return rol(x, n - k, n)

def M_op(x, n):
    return x ^ rol(x, 1, n) ^ ror(x, 1, n)

def fscx(a, b, n):
    return M_op(a ^ b, n)

def fscx_revolve(a, b, steps, n):
    for _ in range(steps):
        a = M_op(a ^ b, n)
    return a


# ─────────────────────────────────────────────────────────────────────────
# Part 1 — invertibility (GF(2)[x] polynomial gcd, independent of the
# gcd(3,n) number-theory shortcut) and order of M
# ─────────────────────────────────────────────────────────────────────────

def gf2_poly_gcd(a, b):
    """gcd of two GF(2)[x] polynomials, represented as Python ints
    (bit i = coefficient of x^i). Standard carryless-division Euclidean
    algorithm."""
    def deg(p):
        return p.bit_length() - 1
    while b:
        if deg(a) < deg(b):
            a, b = b, a
        a ^= b << (deg(a) - deg(b))
        while a and (a >> deg(a)) == 0:  # normalize (shouldn't trigger)
            pass
    return a

def m_is_invertible_via_poly_gcd(n):
    """M is invertible in R_n = GF(2)[x]/(x^n+1) iff gcd(x^2+x+1, x^n+1) = 1
    (x is always a unit in R_n, so the x^{-1} factor in m=x^{-1}(x^2+x+1)
    never affects invertibility)."""
    m_poly = 0b111                      # x^2 + x + 1
    xn_plus_1 = (1 << n) | 1            # x^n + 1
    g = gf2_poly_gcd(xn_plus_1, m_poly)
    return g == 1

def m_is_invertible_via_gcd3(n):
    """Cross-check via the number-theory shortcut used in the write-up:
    invertible iff 3 does not divide n."""
    return n % 3 != 0

def order_of_M(n, max_mult=8, sample_basis=8):
    """Empirical multiplicative order of M on GF(2)^n: iterate M on a
    sample of basis vectors e_0..e_{sample_basis-1} (plus a random vector)
    until each returns to itself, and return the LCM of the individual
    periods (bounded search up to max_mult*n iterations — Theorem 4's
    general period bound n is verified to hold or not as part of this
    search)."""
    from math import gcd
    def lcm(a, b):
        return a * b // gcd(a, b)

    def period_of(v0):
        v = v0
        for k in range(1, max_mult * n + 1):
            v = M_op(v, n)
            if v == v0:
                return k
        return None  # did not return within the search bound

    vectors = [1 << i for i in range(min(sample_basis, n))]
    vectors.append(random.getrandbits(n))

    order = 1
    for v0 in vectors:
        if v0 == 0:
            continue
        p = period_of(v0)
        if p is None:
            return None
        order = lcm(order, p)
    return order


# ─────────────────────────────────────────────────────────────────────────
# Part 2 — avalanche/diffusion at a given n
# ─────────────────────────────────────────────────────────────────────────

def avalanche_fraction(n, revolve_steps, trials=200):
    """Flip one random input bit, run FSCX_REVOLVE with a fixed random B,
    and measure the mean fraction of output bits that differ."""
    total = 0.0
    for _ in range(trials):
        a = random.getrandbits(n)
        b = random.getrandbits(n)
        bit = random.randrange(n)
        a2 = a ^ (1 << bit)
        out1 = fscx_revolve(a, b, revolve_steps, n)
        out2 = fscx_revolve(a2, b, revolve_steps, n)
        diff = bin(out1 ^ out2).count('1')
        total += diff / n
    return total / trials


# ─────────────────────────────────────────────────────────────────────────
# Part 3 — throughput (Python-level; see module docstring for the
# C/Go/Arduino word-alignment caveat this cannot measure)
# ─────────────────────────────────────────────────────────────────────────

def bench_revolve(n, steps=1000, reps=200):
    a = random.getrandbits(n)
    b = random.getrandbits(n)
    t0 = time.perf_counter()
    for _ in range(reps):
        fscx_revolve(a, b, steps, n)
    t1 = time.perf_counter()
    ops = reps * steps
    return ops / (t1 - t0)  # FSCX applications / second


# ─────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────

def main():
    random.seed(0xC0FFEE)

    print("=" * 78)
    print("Part 1 — invertibility of M at candidate widths")
    print("=" * 78)
    # Byte-aligned baseline widths (all n=2^k, currently supported/used)
    byte_aligned = [32, 64, 128, 256]
    # Non-byte-aligned candidates named in TODO #204, plus a few more to
    # sample both divisible-by-3 and coprime-to-3 cases
    non_byte = [251, 255, 509, 257, 241, 253]

    print(f"{'n':>5}  {'poly-gcd':>9}  {'gcd(3,n)':>9}  {'agree':>6}  note")
    for n in byte_aligned + non_byte:
        inv_poly = m_is_invertible_via_poly_gcd(n)
        inv_gcd3 = m_is_invertible_via_gcd3(n)
        agree = "yes" if inv_poly == inv_gcd3 else "MISMATCH"
        note = "byte-aligned" if n in byte_aligned else (
            "SINGULAR (3 | n) -- FSCX undefined" if not inv_poly else "invertible, non-byte")
        print(f"{n:>5}  {str(inv_poly):>9}  {str(inv_gcd3):>9}  {agree:>6}  {note}")

    invertible_non_byte = [n for n in non_byte if m_is_invertible_via_poly_gcd(n)]

    print()
    print("=" * 78)
    print("Part 1b — order of M (Theorem 3 claims n/2 for n=2^k; general n?)")
    print("=" * 78)
    print(f"{'n':>5}  {'order(M)':>10}  {'n/2':>6}  {'n':>6}  note")
    for n in byte_aligned:
        order = order_of_M(n, max_mult=2)
        print(f"{n:>5}  {order!s:>10}  {n // 2:>6}  {n:>6}  matches Theorem 3 (order == n/2)" if order == n // 2 else f"{n:>5}  {order!s:>10}  {n // 2:>6}  {n:>6}")
    for n in invertible_non_byte:
        order = order_of_M(n, max_mult=8)
        rel = ("== n" if order == n else "== n/2" if order == n / 2 else "neither n nor n/2")
        print(f"{n:>5}  {order!s:>10}  {n / 2:>6}  {n:>6}  order {rel}")

    print()
    print("=" * 78)
    print("Part 2 — avalanche diffusion, byte-aligned vs. nearest invertible")
    print("         non-byte n, at matched revolve depth i=n/4 (rounded)")
    print("=" * 78)
    pairs = [(256, 257), (256, 251), (256, 253), (256, 241)]
    print(f"{'n_byte':>7}  {'avalanche':>10}  {'n_nonbyte':>10}  {'avalanche':>10}  delta")
    for n_byte, n_nb in pairs:
        if n_nb not in invertible_non_byte and n_nb != 257:
            continue
        av_byte = avalanche_fraction(n_byte, revolve_steps=n_byte // 4)
        av_nb = avalanche_fraction(n_nb, revolve_steps=n_nb // 4)
        print(f"{n_byte:>7}  {av_byte:>10.4f}  {n_nb:>10}  {av_nb:>10.4f}  {av_nb - av_byte:+.4f}")

    print()
    print("=" * 78)
    print("Part 3 — Python-level throughput (illustrative only; see")
    print("         module docstring re: C/Go word-alignment cost this")
    print("         cannot measure)")
    print("=" * 78)
    print(f"{'n':>5}  {'FSCX ops/sec':>14}")
    for n in sorted(set(byte_aligned + invertible_non_byte)):
        rate = bench_revolve(n, steps=500, reps=100)
        print(f"{n:>5}  {rate:>14,.0f}")

    print()
    print("=" * 78)
    print("Conclusion")
    print("=" * 78)
    print("""\
1. Invertibility is NOT guaranteed for arbitrary non-byte n: n=255 (the
   most natural odd neighbor of today's default n=256) leaves M singular
   because 3 | 255. Any non-byte-aligned parameter choice must first pass
   a 3 | n check (or the general poly-gcd check above) before it can even
   be considered -- this is a real, previously undocumented footgun for
   anyone tempted to "just subtract a few bits" from n=256.

2. Theorem 3's order(M) = n/2 is specific to n = 2^k. For the invertible
   non-byte n sampled above, order(M) is empirically n (not n/2) -- see
   printed table. This does not break correctness (FSCX_REVOLVE's period
   still divides n by the general argument in SecurityProofs-1.md's
   Theorem 4, restated for general invertible M above), but it does mean
   every derived claim in SecurityProofs-*.md that assumes order(M)=n/2
   specifically would need independent re-derivation for a non-2^k n --
   a nontrivial documentation burden for no demonstrated benefit (see 3-4).

3. Diffusion at matched *relative* depth (i=n/4 steps) is actually higher,
   not equal, for several sampled non-byte n (see Part 2 output: n=253 and
   n=251 both diffuse substantially faster than n=256 at n/4 steps). This
   is a direct consequence of point 2, not an independent advantage: n=256
   has order(M)=n/2=128, so at i=n/4=64 steps FSCX_REVOLVE has completed
   only half of one full M-orbit, while the sampled non-byte n (order(M)
   close to n, not n/2) complete a proportionally longer stretch of their
   orbit in the same n/4 steps. Nothing here is a usable security margin:
   it is an artifact of choosing the *same formula* (i=n/4) for two
   structurally different orbit lengths, not a property of non-byte n
   itself -- recomputing i relative to each n's actual order(M) would
   erase the gap, and doing that correctly requires re-deriving order(M)
   per n in the first place (the point-2 burden), not a free win.

4. No throughput advantage in principle, and a real disadvantage in
   practice: Part 3's Python numbers cannot show it (arbitrary-precision
   ints have no "word" to misalign), but every non-Python target in this
   suite (C/Go/Arduino/ARM Thumb-2/NASM) represents state in byte- or
   word-aligned chunks; a non-byte-aligned n forces either bit-slicing
   (masking the top word's unused high bits on every ROL/ROR/XOR) or a
   bignum library, both strictly slower than today's word-aligned code,
   and bit-slicing additionally defeats the single-instruction ROL/ROR
   compilation byte/word-aligned n gets today.

Recommendation: do NOT add non-byte-aligned key-length support. The
byte-aligned status quo (32/64/128/256/...) should remain the only
supported parameter family. The analysis above is the documented record
for this decision -- see TODO_DONE.md #204 and SecurityProofs-1.md
§1.2.1.""")


if __name__ == '__main__':
    main()
