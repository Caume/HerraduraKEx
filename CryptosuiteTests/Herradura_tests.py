'''
    Herradura KEx — Security & Performance Tests (Python)
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n), ~6× speedup at n=32).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.2: proposed multi-size key-length tests for Herradura_tests.c (matching Python).
    v1.5.1: added --rounds/-r and --time/-t CLI options (also HTEST_ROUNDS / HTEST_TIME env).
    v1.5.0: added PQC extension tests [10-16] and benchmarks [22-25].
            benchmarks renumbered [17-21] (were [10-14] in v1.4.0).
    v1.4.0: replaced broken fscx_revolve_n HKEX tests with HKEX-GF tests.
    v1.3.6: added HPKS sign+verify correctness test [7]; benchmarks renumbered [8-12].
    v1.3.3: added HPKE encrypt+decrypt round-trip benchmark [11].

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    Under the terms of the GNU General Public License, please also consider that:

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import argparse
import os
import sys
import time

# ---------------------------------------------------------------------------
# BitArray class (self-contained, do not import from other files)
# ---------------------------------------------------------------------------

class BitArray:
    """Fixed-width bit string backed by a Python int."""

    __slots__ = ('_val', '_size', '_mask')

    def __init__(self, size: int, value: int = 0):
        self._size = size
        self._mask = (1 << size) - 1
        self._val = int(value) & self._mask

    @property
    def uint(self) -> int:
        return self._val

    @uint.setter
    def uint(self, value: int):
        self._val = int(value) & self._mask

    @property
    def bytes(self) -> bytes:
        return self._val.to_bytes(self._size // 8, 'big')

    @bytes.setter
    def bytes(self, data: bytes):
        self._val = int.from_bytes(data, 'big') & self._mask

    @property
    def hex(self) -> str:
        return f'{self._val:0{self._size // 4}x}'

    def copy(self) -> 'BitArray':
        return BitArray(self._size, self._val)

    def rotated(self, n: int) -> 'BitArray':
        n %= self._size
        if n == 0:
            return BitArray(self._size, self._val)
        return BitArray(self._size,
                        ((self._val << n) | (self._val >> (self._size - n))) & self._mask)

    def rol(self, n: int) -> None:
        n %= self._size
        if n:
            self._val = ((self._val << n) | (self._val >> (self._size - n))) & self._mask

    def ror(self, n: int) -> None:
        n %= self._size
        if n:
            self._val = ((self._val >> n) | (self._val << (self._size - n))) & self._mask

    def __xor__(self, other: 'BitArray') -> 'BitArray':
        return BitArray(self._size, self._val ^ other._val)

    def __ixor__(self, other: 'BitArray') -> 'BitArray':
        self._val ^= other._val
        return self

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BitArray):
            return self._size == other._size and self._val == other._val
        return NotImplemented

    def __str__(self) -> str:
        return f'0x{self.hex}'

    def __repr__(self) -> str:
        return f'BitArray({self._size}, 0x{self.hex})'

    @classmethod
    def random(cls, size: int) -> 'BitArray':
        ba = cls(size)
        ba.bytes = os.urandom(size // 8)
        return ba

    def flip_bit(self, pos: int) -> 'BitArray':
        return BitArray(self._size, self._val ^ (1 << pos))

    def popcount(self) -> int:
        return bin(self._val).count('1')


# ---------------------------------------------------------------------------
# FSCX functions (classical — linear map M = I+ROL+ROR over GF(2))
# ---------------------------------------------------------------------------

def fscx(A: BitArray, B: BitArray) -> BitArray:
    return A ^ B ^ A.rotated(1) ^ B.rotated(1) ^ A.rotated(-1) ^ B.rotated(-1)


def fscx_revolve(A: BitArray, B: BitArray, steps: int) -> BitArray:
    result = A.copy()
    for _ in range(steps):
        result = fscx(result, B)
    return result


# ---------------------------------------------------------------------------
# GF(2^n) field arithmetic (classical)
# ---------------------------------------------------------------------------

GF_POLY = {32: 0x00400007, 64: 0x0000001B, 128: 0x00000087, 256: 0x00000425}
GF_GEN  = 3

def gf_mul(a: int, b: int, poly: int, n: int) -> int:
    result = 0; mask = (1 << n) - 1; hb = 1 << (n - 1)
    for _ in range(n):
        if b & 1: result ^= a
        carry = bool(a & hb)
        a = (a << 1) & mask
        if carry: a ^= poly
        b >>= 1
    return result

def gf_pow(base: int, exp: int, poly: int, n: int) -> int:
    result = 1; base &= (1 << n) - 1
    while exp:
        if exp & 1: result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


# ---------------------------------------------------------------------------
# NL-FSCX primitives (v1.5.0 — non-linear; for PQC-hardened protocols)
# ---------------------------------------------------------------------------

def _m_inv(X: BitArray) -> BitArray:
    """M^{-1}(X) = M^{n/2-1}(X).  M^{n/2} = I so M^{-1} = M^{n/2-1}."""
    n    = X._size
    zero = BitArray(n, 0)
    return fscx_revolve(X, zero, n // 2 - 1)


def nl_fscx_v1(A: BitArray, B: BitArray) -> BitArray:
    """NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4).
    Non-linear over GF(2) via integer carry.  NOT bijective in A."""
    n   = A._size
    mix = BitArray(n, (A.uint + B.uint) & A._mask)
    return fscx(A, B) ^ mix.rotated(n // 4)


def nl_fscx_revolve_v1(A: BitArray, B: BitArray, steps: int) -> BitArray:
    result = A.copy()
    for _ in range(steps):
        result = nl_fscx_v1(result, B)
    return result


def nl_fscx_v2(A: BitArray, B: BitArray) -> BitArray:
    """NL-FSCX v2: (fscx(A,B) + delta(B)) mod 2^n.
    delta(B) = ROL(B*(B+1)//2 mod 2^n, n/4).  Bijective in A; exact inverse."""
    n     = A._size
    mask  = A._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    return BitArray(n, (fscx(A, B).uint + delta.uint) & mask)


def nl_fscx_v2_inv(Y: BitArray, B: BitArray) -> BitArray:
    """Exact inverse of one nl_fscx_v2 step: A = B XOR M^{-1}((Y-delta(B)) mod 2^n)."""
    n     = Y._size
    mask  = Y._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    Z     = BitArray(n, (Y.uint - delta.uint) & mask)
    return B ^ _m_inv(Z)


def nl_fscx_revolve_v2(A: BitArray, B: BitArray, steps: int) -> BitArray:
    result = A.copy()
    for _ in range(steps):
        result = nl_fscx_v2(result, B)
    return result


def nl_fscx_revolve_v2_inv(Y: BitArray, B: BitArray, steps: int) -> BitArray:
    result = Y.copy()
    for _ in range(steps):
        result = nl_fscx_v2_inv(result, B)
    return result


# ---------------------------------------------------------------------------
# HKEX-RNL ring-arithmetic helpers (negacyclic Z_q[x]/(x^n+1))
# ---------------------------------------------------------------------------

def _ntt_inplace(a, q, invert):
    n = len(a); j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit: j ^= bit; bit >>= 1
        j ^= bit
        if i < j: a[i], a[j] = a[j], a[i]
    length = 2
    while length <= n:
        w = pow(3, (q - 1) // length, q)
        if invert: w = pow(w, q - 2, q)
        for i in range(0, n, length):
            wn = 1
            for k in range(length >> 1):
                u = a[i + k]; v = a[i + k + (length >> 1)] * wn % q
                a[i + k] = (u + v) % q; a[i + k + (length >> 1)] = (u - v) % q
                wn = wn * w % q
        length <<= 1
    if invert:
        inv_n = pow(n, q - 2, q)
        for i in range(n): a[i] = a[i] * inv_n % q

def _rnl_poly_mul(f, g, q, n):
    psi = pow(3, (q - 1) // (2 * n), q); psi_inv = pow(psi, q - 2, q)
    fa, ga = list(f), list(g); pw = 1
    for i in range(n):
        fa[i] = fa[i] * pw % q; ga[i] = ga[i] * pw % q; pw = pw * psi % q
    _ntt_inplace(fa, q, False); _ntt_inplace(ga, q, False)
    ha = [fa[i] * ga[i] % q for i in range(n)]
    _ntt_inplace(ha, q, True)
    pw_inv = 1
    for i in range(n): ha[i] = ha[i] * pw_inv % q; pw_inv = pw_inv * psi_inv % q
    return ha

def _rnl_poly_add(f, g, q):
    return [(a + b) % q for a, b in zip(f, g)]

def _rnl_round(poly, from_q, to_p):
    return [(c * to_p + from_q // 2) // from_q % to_p for c in poly]

def _rnl_lift(poly, from_p, to_q):
    return [c * to_q // from_p % to_q for c in poly]

def _rnl_m_poly(n):
    p = [0] * n; p[0] = p[1] = p[n - 1] = 1; return p

def _rnl_rand_poly(n, q):
    return [int.from_bytes(os.urandom(4), 'big') % q for _ in range(n)]

def _rnl_cbd_poly(n, q):
    """CBD(eta=1): coeff = (raw&1) - ((raw>>1)&1) mod q. Produces {-1,0,1} with zero mean."""
    out = []
    for _ in range(n):
        v = int.from_bytes(os.urandom(1), 'big')
        out.append((( v & 1) - ((v >> 1) & 1) + q) % q)
    return out

def _rnl_bits_to_bitarray(poly, pp, size):
    val = 0; thr = pp // 2
    for i, c in enumerate(poly[:size]):
        if c >= thr:
            val |= (1 << i)
    return BitArray(size, val)

def _rnl_keygen(m_blind, n, q, p):
    s = _rnl_cbd_poly(n, q)
    C = _rnl_round(_rnl_poly_mul(m_blind, s, q, n), q, p)
    return s, C

def _rnl_agree(s, C_other, q, p, pp, n, key_bits):
    K = _rnl_poly_mul(s, _rnl_lift(C_other, p, q), q, n)
    return _rnl_bits_to_bitarray(_rnl_round(K, q, pp), pp, key_bits)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def i_val(size: int) -> int:
    return size // 4

def r_val(size: int) -> int:
    return size * 3 // 4


SIZES     = [64, 128, 256]      # bit sizes for FSCX-only tests (fast)
GF_SIZES  = [32, 64]            # bit sizes for GfPow tests (Python big-int is slow)
GF_TRIALS = 100                 # trials for GfPow-heavy tests (32=asm target, 64=scaling)
RNL_SIZES = [32, 64]            # ring polynomial degrees for HKEX-RNL tests
                                 # (n=256 is the production size but slow in Python)
RNLQ  = 65537  # Fermat prime (2^16+1); lower noise-to-margin ratio than q=3329
RNLP  = 4096   # public-key rounding modulus
RNLPP = 2      # reconciliation modulus (1 bit per coefficient)
RNLETA = 1     # CBD eta: secret coefficients from CBD(1) in {-1,0,1}

TARGET_SEC = 1.0  # kept for reference; overridden by g_bench_sec at runtime

# --- Runtime limits (set in __main__ via CLI / env vars) -----------------
g_rounds     = 0    # 0 = use per-test default
g_bench_sec  = 1.0  # benchmark duration (seconds)
g_time_limit = 0.0  # per-test wall-clock cap; 0 = none


def _iters(default_n: int) -> int:
    """Effective iteration count: g_rounds if set, otherwise default_n."""
    return g_rounds if g_rounds > 0 else default_n


def _trange(n: int):
    """Like range(n) but stops early when g_time_limit is reached.
    Yields the iteration index so callers can use it as a loop variable."""
    if g_time_limit <= 0:
        yield from range(n)
        return
    t0 = time.monotonic()
    for i in range(n):
        yield i
        if (i & 63) == 63 and time.monotonic() - t0 >= g_time_limit:
            return


# ---------------------------------------------------------------------------
# S_op helper for Eve-resistance test [6]
# ---------------------------------------------------------------------------

def s_op(delta: BitArray, r: int) -> BitArray:
    size = delta._size
    zero = BitArray(size, 0)
    acc  = BitArray(size, 0)
    cur  = delta.copy()
    for _ in range(r + 1):
        acc ^= cur
        cur = fscx(cur, zero)
    return acc


# ---------------------------------------------------------------------------
# Security tests — classical protocols [1-9]
# ---------------------------------------------------------------------------

def test_hkex_gf_correctness():
    print("[1] HKEX-GF correctness: g^{ab} == g^{ba} in GF(2^n)*  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425)
        ok = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a = BitArray.random(size)
            b = BitArray.random(size)
            C  = gf_pow(GF_GEN, a.uint, poly, size)
            C2 = gf_pow(GF_GEN, b.uint, poly, size)
            if gf_pow(C2, a.uint, poly, size) == gf_pow(C, b.uint, poly, size):
                ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:5d} / {n_run} correct  [{status}]")
    print()


def test_avalanche():
    print("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)  [CLASSICAL]")
    for size in SIZES:
        total = 0.0; gmin = size + 1; gmax = -1; n_run = 0
        for _ in _trange(_iters(1000)):
            n_run += 1
            a = BitArray.random(size); b = BitArray.random(size)
            base = fscx(a, b)
            for bit in range(size):
                hd = (fscx(a.flip_bit(bit), b) ^ base).popcount()
                total += hd
                gmin = min(gmin, hd); gmax = max(gmax, hd)
        mean = total / (float(n_run) * size) if n_run > 0 else 0.0
        status = "PASS" if 2.9 <= mean <= 3.1 else "FAIL"
        print(f"    bits={size:3d}  mean={mean:.2f} (expected 3/{size})  min={gmin}  max={gmax}  [{status}]")
    print()


def test_orbit_period():
    print("[3] Orbit period: FSCX_REVOLVE cycles back to A  [CLASSICAL]")
    for size in SIZES:
        cnt_p = 0; cnt_hp = 0; other = 0; cap = 2 * size
        for _ in _trange(_iters(100)):
            a = BitArray.random(size); b = BitArray.random(size)
            cur = fscx(a, b); period = 1
            while cur != a and period < cap:
                cur = fscx(cur, b); period += 1
            if period == size:        cnt_p  += 1
            elif period == size // 2: cnt_hp += 1
            else:                     other  += 1
        status = "PASS" if other == 0 else "FAIL"
        print(f"    bits={size:3d}  period={size}: {cnt_p:3d}  period={size//2}: {cnt_hp:3d}  other: {other}  [{status}]")
    print()


def test_bit_frequency():
    N = _iters(10000)
    print(f"[4] Bit-frequency bias: {N} FSCX outputs per size  [CLASSICAL]")
    for size in SIZES:
        counts = [0] * size; n_run = 0
        for _ in _trange(N):
            n_run += 1
            val = fscx(BitArray.random(size), BitArray.random(size)).uint
            for bit in range(size):
                if (val >> bit) & 1: counts[bit] += 1
        pcts  = [c / n_run * 100.0 for c in counts] if n_run > 0 else [0.0] * size
        mn = min(pcts); mx = max(pcts); mean = sum(pcts) / size
        status = "PASS" if mn > 47.0 and mx < 53.0 else "FAIL"
        print(f"    bits={size:3d}  min={mn:.2f}%  max={mx:.2f}%  mean={mean:.2f}%  [{status}]")
    print()


def test_hkex_gf_key_sensitivity():
    print("[5] HKEX-GF key sensitivity: flip 1 bit of a, measure HD of sk change  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); total = 0.0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a  = BitArray.random(size); b  = BitArray.random(size)
            C2 = gf_pow(GF_GEN, b.uint, poly, size)
            sk1 = gf_pow(C2, a.uint,             poly, size)
            sk2 = gf_pow(C2, a.flip_bit(0).uint, poly, size)
            total += BitArray(size, sk1 ^ sk2).popcount()
        mean = total / float(n_run) if n_run > 0 else 0.0
        status = "PASS" if mean >= size // 4 else "FAIL"
        print(f"    bits={size:3d}  mean HD={mean:.2f} (expected >={size//4})  [{status}]")
    print()


def test_hkex_gf_eve_resistance():
    T = _iters(GF_TRIALS)
    print(f"[6] HKEX-GF Eve resistance: S_op(C^C2, r) != sk for {T} trials  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); rv = r_val(size); successes = 0; n_run = 0
        for _ in _trange(T):
            n_run += 1
            a  = BitArray.random(size); b  = BitArray.random(size)
            C  = BitArray(size, gf_pow(GF_GEN, a.uint, poly, size))
            C2 = BitArray(size, gf_pow(GF_GEN, b.uint, poly, size))
            real_sk = BitArray(size, gf_pow(C2.uint, a.uint, poly, size))
            if s_op(C ^ C2, rv) == real_sk: successes += 1
        status = "PASS" if successes == 0 else "FAIL"
        print(f"    bits={size:3d}  {successes:5d} / {n_run} Eve successes (expected 0)  [{status}]")
    print()


def test_hpks_schnorr_correctness():
    print("[7] HPKS Schnorr correctness: g^s · C^e == R  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); ord_ = (1 << size) - 1; ok = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a     = BitArray.random(size)
            C_int = gf_pow(GF_GEN, a.uint, poly, size)
            pt    = BitArray.random(size)
            k     = BitArray.random(size)
            R_int = gf_pow(GF_GEN, k.uint, poly, size)
            R_b   = BitArray(size, R_int)
            e     = fscx_revolve(R_b, pt, iv)
            s     = (k.uint - a.uint * e.uint) % ord_
            lhs   = gf_mul(gf_pow(GF_GEN, s,      poly, size),
                           gf_pow(C_int,  e.uint,  poly, size), poly, size)
            if lhs == R_int: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:4d} / {n_run} verified  [{status}]")
    print()


def test_hpks_schnorr_eve_resistance():
    print("[8] HPKS Schnorr Eve resistance: random forgery attempts fail  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); wins = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a     = BitArray.random(size)
            C_int = gf_pow(GF_GEN, a.uint, poly, size)
            decoy = BitArray.random(size)
            R_eve = BitArray(size, gf_pow(GF_GEN, BitArray.random(size).uint, poly, size))
            e_eve = fscx_revolve(R_eve, decoy, iv)
            s_eve = BitArray.random(size).uint
            lhs   = gf_mul(gf_pow(GF_GEN, s_eve,      poly, size),
                           gf_pow(C_int,  e_eve.uint,  poly, size), poly, size)
            if lhs == R_eve.uint: wins += 1
        status = "PASS" if wins == 0 else "FAIL"
        print(f"    bits={size:3d}  {wins:4d} / {n_run} Eve wins (expected 0)  [{status}]")
    print()


def test_hpke_roundtrip():
    print("[9] HPKE encrypt+decrypt correctness (El Gamal + fscx_revolve)  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); rv = r_val(size); ok = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a   = BitArray.random(size); pt = BitArray.random(size)
            C   = gf_pow(GF_GEN, a.uint, poly, size)
            r   = BitArray.random(size)
            R   = gf_pow(GF_GEN, r.uint, poly, size)
            enc = BitArray(size, gf_pow(C, r.uint, poly, size))
            E   = fscx_revolve(pt,  enc, iv)
            dec = BitArray(size, gf_pow(R, a.uint, poly, size))
            D   = fscx_revolve(E,   dec, rv)
            if D == pt: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:4d} / {n_run} decrypted  [{status}]")
    print()


# ---------------------------------------------------------------------------
# Security tests — PQC extension [10-16]
# ---------------------------------------------------------------------------

def test_nl_fscx_v1_nonlinearity():
    # NL-FSCX v1 must violate GF(2) linearity: if linear,
    # f(A,B) XOR f(0,B) == fscx(A,0) for all A,B.  Count violations.
    # Also verify period is destroyed: no period found in 4*n steps.
    print("[10] NL-FSCX v1 non-linearity and aperiodicity  [PQC-EXT]")
    for size in SIZES:
        zero = BitArray(size, 0)
        N1 = _iters(1000); N2 = _iters(200)
        # Linearity violations
        violations = 0; n1_run = 0
        for _ in _trange(N1):
            n1_run += 1
            A = BitArray.random(size); B = BitArray.random(size)
            lin_pred = fscx(A, zero) ^ nl_fscx_v1(zero, B)
            if nl_fscx_v1(A, B) != lin_pred:
                violations += 1
        # Period check: no period in 4*n steps
        cap = 4 * size; no_period = 0; n2_run = 0
        for _ in _trange(N2):
            n2_run += 1
            A = BitArray.random(size); B = BitArray.random(size)
            cur = nl_fscx_v1(A, B); found = False
            for _ in range(1, cap):
                cur = nl_fscx_v1(cur, B)
                if cur == A: found = True; break
            if not found: no_period += 1
        status = "PASS" if violations == n1_run and no_period >= n2_run * 95 // 100 else "FAIL"
        print(f"    bits={size:3d}  linearity violations={violations}/{n1_run}  "
              f"no-period={no_period}/{n2_run}  [{status}]")
    print()


def test_nl_fscx_v2_bijective_inverse():
    # NL-FSCX v2 must be bijective in A for all B (non-bijective count = 0),
    # and the closed-form inverse must be correct for N random (A,B) pairs.
    print("[11] NL-FSCX v2 bijectivity and exact inverse  [PQC-EXT]")
    for size in SIZES:
        N1 = _iters(500); N2 = _iters(1000); N3 = _iters(500)
        # Bijectivity: map A -> nl_fscx_v2(A, B) must be injective for fixed B
        non_bij = 0; n1_run = 0
        for _ in _trange(N1):
            n1_run += 1
            B    = BitArray.random(size)
            seen = {}
            for _ in range(min(256, 1 << min(size, 8))):
                A   = BitArray.random(size)
                out = nl_fscx_v2(A, B).uint
                if out in seen and seen[out] != A.uint:
                    non_bij += 1; break
                seen[out] = A.uint
        # Inverse correctness
        inv_ok = 0; n2_run = 0
        for _ in _trange(N2):
            n2_run += 1
            A = BitArray.random(size); B = BitArray.random(size)
            if nl_fscx_v2_inv(nl_fscx_v2(A, B), B) == A:
                inv_ok += 1
        # Non-linearity check
        zero = BitArray(size, 0)
        nl_ok = 0; n3_run = 0
        for _ in _trange(N3):
            n3_run += 1
            A = BitArray.random(size); B = BitArray.random(size)
            if nl_fscx_v2(A, B) != BitArray(size,
               (fscx(A, zero).uint ^ nl_fscx_v2(zero, B).uint)):
                nl_ok += 1
        status = "PASS" if non_bij == 0 and inv_ok == n2_run and nl_ok >= n3_run * 98 // 100 else "FAIL"
        print(f"    bits={size:3d}  collisions={non_bij}/{n1_run}  inv={inv_ok}/{n2_run}  "
              f"nonlinear={nl_ok}/{n3_run}  [{status}]")
    print()


def test_hske_nl_a1_correctness():
    # HSKE-NL-A1 counter-mode: C = P XOR keystream; D = C XOR keystream = P.
    # keystream[i] = nl_fscx_revolve_v1(K, K XOR i, n/4).
    print("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); ok = 0; n_run = 0
        for trial in _trange(_iters(1000)):
            n_run += 1
            K   = BitArray.random(size)
            P   = BitArray.random(size)
            ctr = trial % (1 << min(size, 16))
            B   = BitArray(size, K.uint ^ ctr)
            ks  = nl_fscx_revolve_v1(K, B, iv)
            C   = BitArray(size, P.uint ^ ks.uint)
            D   = BitArray(size, C.uint ^ ks.uint)
            if D == P: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:4d} / {n_run} correct  [{status}]")
    print()


def test_hske_nl_a2_correctness():
    # HSKE-NL-A2 revolve mode: E = nl_fscx_revolve_v2(P, K, r);
    # D = nl_fscx_revolve_v2_inv(E, K, r) must equal P.
    # Default 50 trials: nl_fscx_v2_inv calls M^{n/2-1} per step — O(n^2) fscx ops total.
    print("[13] HSKE-NL-A2 revolve-mode correctness: D == P  [PQC-EXT]")
    for size in SIZES:
        rv = r_val(size); ok = 0; n_run = 0
        for _ in _trange(_iters(50)):
            n_run += 1
            K = BitArray.random(size); P = BitArray.random(size)
            E = nl_fscx_revolve_v2(P, K, rv)
            D = nl_fscx_revolve_v2_inv(E, K, rv)
            if D == P: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:3d} / {n_run:3d} correct  [{status}]")
    print()


def test_hkex_rnl_correctness():
    # HKEX-RNL: both parties must derive equal raw key bits K_raw (near-certainty
    # at the chosen parameters) and equal final sk after NL-FSCX KDF.
    # Uses RNL_SIZES (smaller than KEYBITS) for performance.
    # Production size is n=256; error probability is negligible at n>=64, b=1.
    #
    # Protocol: one party generates a_rand and transmits it in the clear; both
    # derive the shared m_blind = m_base + a_rand and compute individual public keys
    # C = round_p(m_blind · s).  Agreement holds by ring commutativity:
    # s_A·(m_blind·s_B) = s_B·(m_blind·s_A).  See §11.4.2 of SecurityProofs.md.
    print("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]")
    print(f"     (ring sizes {RNL_SIZES}; production size is n=256)")
    for n_rnl in RNL_SIZES:
        m_base = _rnl_m_poly(n_rnl)
        ok_raw = 0; ok_sk = 0; n_run = 0
        for _ in _trange(_iters(200)):
            n_run += 1
            a_rand  = _rnl_rand_poly(n_rnl, RNLQ)
            m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)   # shared public polynomial
            s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            K_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
            K_B = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
            if K_A == K_B: ok_raw += 1
            sk_A = nl_fscx_revolve_v1(K_A, K_A, n_rnl // 4)
            sk_B = nl_fscx_revolve_v1(K_B, K_B, n_rnl // 4)
            if sk_A == sk_B: ok_sk += 1
        status = "PASS" if ok_raw >= n_run * 90 // 100 else "FAIL"
        print(f"    n={n_rnl:3d}  raw agree={ok_raw}/{n_run}  sk agree={ok_sk}/{n_run}  [{status}]")
    print()


def test_hpks_nl_correctness():
    # HPKS-NL: Schnorr with NL-FSCX v1 challenge.
    # Sign:   k random; R=g^k; e=nl_fscx_revolve_v1(R,P,I); s=(k-a*e) mod ord
    # Verify: g^s * C^e == R
    print("[15] HPKS-NL correctness: g^s · C^e == R (NL-FSCX v1 challenge)  [PQC-EXT]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); ord_ = (1 << size) - 1; ok = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a     = BitArray.random(size)
            C_int = gf_pow(GF_GEN, a.uint, poly, size)
            pt    = BitArray.random(size)
            k     = BitArray.random(size)
            R_int = gf_pow(GF_GEN, k.uint, poly, size)
            R_b   = BitArray(size, R_int)
            e     = nl_fscx_revolve_v1(R_b, pt, iv)
            s     = (k.uint - a.uint * e.uint) % ord_
            lhs   = gf_mul(gf_pow(GF_GEN, s,      poly, size),
                           gf_pow(C_int,  e.uint,  poly, size), poly, size)
            if lhs == R_int: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:4d} / {n_run} verified  [{status}]")
    print()


def test_hpke_nl_correctness():
    # HPKE-NL: El Gamal + NL-FSCX v2 encryption.
    # Bob:   enc=C^r; E=nl_fscx_revolve_v2(P, enc, I)
    # Alice: dec=R^a=enc; D=nl_fscx_revolve_v2_inv(E, dec, I) must equal P.
    print("[16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt)  [PQC-EXT]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); ok = 0; n_run = 0
        for _ in _trange(_iters(GF_TRIALS)):
            n_run += 1
            a   = BitArray.random(size); pt = BitArray.random(size)
            C   = gf_pow(GF_GEN, a.uint, poly, size)
            r   = BitArray.random(size)
            R   = gf_pow(GF_GEN, r.uint, poly, size)
            enc = BitArray(size, gf_pow(C, r.uint, poly, size))
            E   = nl_fscx_revolve_v2(pt, enc, iv)
            dec = BitArray(size, gf_pow(R, a.uint, poly, size))
            D   = nl_fscx_revolve_v2_inv(E, dec, iv)
            if D == pt: ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  {ok:3d} / {n_run} decrypted  [{status}]")
    print()


# ---------------------------------------------------------------------------
# Performance benchmarks
# ---------------------------------------------------------------------------

def _bench(label: str, fn):
    for _ in range(10):
        fn()
    t0 = time.perf_counter(); ops = 0
    while True:
        for _ in range(100): fn()
        ops += 100
        elapsed = time.perf_counter() - t0
        if elapsed >= g_bench_sec: break
    rate = ops / elapsed
    if rate >= 1e6:    rate_str = f"{rate/1e6:.2f} M ops/sec"
    elif rate >= 1e3:  rate_str = f"{rate/1e3:.2f} K ops/sec"
    else:              rate_str = f"{rate:.2f} ops/sec"
    print(f"    {label:<44s}: {rate_str}  ({ops} ops in {elapsed:.2f}s)")


def bench_fscx():
    print("[17] FSCX throughput  [CLASSICAL]")
    for size in SIZES:
        a = BitArray.random(size); b = BitArray.random(size)
        def fn():
            nonlocal a; a = fscx(a, b)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hkex_gf_pow():
    print("[18] HKEX-GF gf_pow throughput  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); a = BitArray.random(size)
        def fn(a=a, poly=poly, size=size):
            return gf_pow(GF_GEN, a.uint, poly, size)
        _bench(f"bits={size:3d}  gf_pow(g, a)", fn)
    print()


def bench_hkex_handshake():
    print("[19] HKEX-GF full handshake (4 gf_pow calls)  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425)
        def fn():
            a = BitArray.random(size); b = BitArray.random(size)
            C  = gf_pow(GF_GEN, a.uint, poly, size)
            C2 = gf_pow(GF_GEN, b.uint, poly, size)
            gf_pow(C2, a.uint, poly, size); gf_pow(C, b.uint, poly, size)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hske_roundtrip():
    print("[20] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
    for size in SIZES:
        iv = i_val(size); rv = r_val(size); sink = BitArray(size, 0)
        def fn():
            nonlocal sink
            pt = BitArray.random(size); key = BitArray.random(size)
            sink ^= fscx_revolve(fscx_revolve(pt, key, iv), key, rv) ^ pt
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hpke_roundtrip():
    print("[21] HPKE encrypt+decrypt round-trip (El Gamal + fscx_revolve)  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); iv = i_val(size); rv = r_val(size)
        sink = BitArray(size, 0)
        def fn(size=size, poly=poly, iv=iv, rv=rv):
            nonlocal sink
            a   = BitArray.random(size); pt = BitArray.random(size)
            C   = gf_pow(GF_GEN, a.uint, poly, size)
            r   = BitArray.random(size); R = gf_pow(GF_GEN, r.uint, poly, size)
            enc = BitArray(size, gf_pow(C, r.uint, poly, size))
            dec = BitArray(size, gf_pow(R, a.uint, poly, size))
            sink ^= fscx_revolve(fscx_revolve(pt, enc, iv), dec, rv)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_nl_fscx_revolve():
    print("[22] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); a = BitArray.random(size); b = BitArray.random(size)
        def fn():
            nonlocal a; a = nl_fscx_revolve_v1(a, b, iv)
        _bench(f"bits={size:3d}  v1 n/4 steps", fn)
    print("[22b] NL-FSCX v2 revolve+inv throughput (r_val steps, 64-bit only)  [PQC-EXT]")
    for size in [64]:  # O(n^2) per op; skip 128/256 in benchmark
        rv = r_val(size); a = BitArray.random(size); b = BitArray.random(size)
        def fn(size=size, rv=rv, b=b):
            nonlocal a; E = nl_fscx_revolve_v2(a, b, rv); a = nl_fscx_revolve_v2_inv(E, b, rv)
        _bench(f"bits={size:3d}  v2 enc+dec r_val", fn)
    print()


def bench_hske_nl_a1_roundtrip():
    print("[23] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); sink = BitArray(size, 0)
        def fn(size=size, iv=iv):
            nonlocal sink
            K = BitArray.random(size); P = BitArray.random(size)
            B = BitArray(size, K.uint ^ 0)
            ks = nl_fscx_revolve_v1(K, B, iv)
            sink ^= BitArray(size, P.uint ^ ks.uint)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hske_nl_a2_roundtrip():
    print("[24] HSKE-NL-A2 revolve-mode round-trip (64-bit only)  [PQC-EXT]")
    for size in [64]:  # O(n^2) per op; skip 128/256 in benchmark
        rv = r_val(size); sink = BitArray(size, 0)
        def fn(size=size, rv=rv):
            nonlocal sink
            K = BitArray.random(size); P = BitArray.random(size)
            E = nl_fscx_revolve_v2(P, K, rv)
            sink ^= nl_fscx_revolve_v2_inv(E, K, rv)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hkex_rnl_handshake():
    # Uses RNL_SIZES for speed; production uses n=256.
    print("[25] HKEX-RNL handshake throughput  [PQC-EXT]")
    print(f"     (ring sizes {RNL_SIZES}; n^2 poly-mul — O(n^2) per exchange)")
    for n_rnl in RNL_SIZES:
        m_base = _rnl_m_poly(n_rnl)
        def fn(n_rnl=n_rnl, m_base=m_base):
            a_rand  = _rnl_rand_poly(n_rnl, RNLQ)
            m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
            s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
            _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
        _bench(f"n={n_rnl:3d}  full exchange", fn)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # --- Arg parsing (CLI overrides env vars) ---
    parser = argparse.ArgumentParser(
        description="Herradura KEx v1.5.4 — Security & Performance Tests (Python)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Env vars: HTEST_ROUNDS=N  HTEST_TIME=T  (CLI flags override env)")
    parser.add_argument('-r', '--rounds', type=int, default=0,
                        metavar='N', help='max iterations per security test (default: test-specific)')
    parser.add_argument('-t', '--time', type=float, default=0.0,
                        metavar='T', dest='time_limit',
                        help='benchmark duration and per-test time cap in seconds')
    args = parser.parse_args()

    # env var fallbacks (only if CLI not set)
    _env_r = os.environ.get('HTEST_ROUNDS', '')
    _env_t = os.environ.get('HTEST_TIME', '')
    if args.rounds == 0 and _env_r.isdigit() and int(_env_r) > 0:
        args.rounds = int(_env_r)
    if args.time_limit == 0.0 and _env_t:
        try:
            args.time_limit = float(_env_t)
        except ValueError:
            pass

    # apply to module-level globals (module-level code; no 'global' keyword needed)
    if args.rounds > 0:
        g_rounds = args.rounds
    if args.time_limit > 0:
        g_bench_sec  = args.time_limit
        g_time_limit = args.time_limit

    print("=== Herradura KEx v1.5.3 \u2014 Security & Performance Tests (Python) ===")
    if g_rounds > 0 or g_time_limit > 0:
        parts = []
        if g_rounds > 0:     parts.append(f"rounds={g_rounds}")
        if g_time_limit > 0: parts.append(f"time_limit={g_time_limit:.2f}s")
        print(f"    Config: {', '.join(parts)}")
    print()

    print("--- Security Tests: Classical Protocols ---\n")
    test_hkex_gf_correctness()
    test_avalanche()
    test_orbit_period()
    test_bit_frequency()
    test_hkex_gf_key_sensitivity()
    test_hkex_gf_eve_resistance()
    test_hpks_schnorr_correctness()
    test_hpks_schnorr_eve_resistance()
    test_hpke_roundtrip()

    print("--- Security Tests: PQC Extension (NL-FSCX + HKEX-RNL) ---\n")
    test_nl_fscx_v1_nonlinearity()
    test_nl_fscx_v2_bijective_inverse()
    test_hske_nl_a1_correctness()
    test_hske_nl_a2_correctness()
    test_hkex_rnl_correctness()
    test_hpks_nl_correctness()
    test_hpke_nl_correctness()

    print("--- Performance Benchmarks ---\n")
    bench_fscx()
    bench_hkex_gf_pow()
    bench_hkex_handshake()
    bench_hske_roundtrip()
    bench_hpke_roundtrip()
    bench_nl_fscx_revolve()
    bench_hske_nl_a1_roundtrip()
    bench_hske_nl_a2_roundtrip()
    bench_hkex_rnl_handshake()
