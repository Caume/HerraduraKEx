'''
    Herradura KEx -- Security & Performance Tests (Python)

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

import os
import time

# ---------------------------------------------------------------------------
# BitArray class (self-contained, do not import from other files)
# ---------------------------------------------------------------------------

class BitArray:
    """Fixed-width bit string backed by a Python int.
    Supports XOR, in-place rotation, equality, and hex/bytes/uint I/O.
    Size must be a positive multiple of 8.
    """

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
        """Return a new BitArray rotated left by n bits (right if n < 0)."""
        n %= self._size
        if n == 0:
            return BitArray(self._size, self._val)
        return BitArray(self._size,
                        ((self._val << n) | (self._val >> (self._size - n))) & self._mask)

    def rol(self, n: int) -> None:
        """Rotate left in-place by n bits."""
        n %= self._size
        if n:
            self._val = ((self._val << n) | (self._val >> (self._size - n))) & self._mask

    def ror(self, n: int) -> None:
        """Rotate right in-place by n bits."""
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
        """Return a random BitArray of *size* bits using os.urandom."""
        ba = cls(size)
        ba.bytes = os.urandom(size // 8)
        return ba

    def flip_bit(self, pos: int) -> 'BitArray':
        """Return a new BitArray with bit *pos* (0=LSB) flipped."""
        return BitArray(self._size, self._val ^ (1 << pos))

    def popcount(self) -> int:
        """Return count of set bits."""
        return bin(self._val).count('1')


# ---------------------------------------------------------------------------
# FSCX functions (copy-based, self-contained)
# ---------------------------------------------------------------------------

def fscx(A: BitArray, B: BitArray) -> BitArray:
    """Full Surroundings Cyclic XOR: A ^ B ^ ROL(A) ^ ROL(B) ^ ROR(A) ^ ROR(B).
    Uses rotated() — does not mutate its inputs."""
    return A ^ B ^ A.rotated(1) ^ B.rotated(1) ^ A.rotated(-1) ^ B.rotated(-1)


def fscx_revolve(A: BitArray, B: BitArray, steps: int) -> BitArray:
    result = A.copy()
    for _ in range(steps):
        result = fscx(result, B)
    return result


def fscx_revolve_n(A: BitArray, B: BitArray, nonce: BitArray, steps: int) -> BitArray:
    result = A.copy()
    for _ in range(steps):
        result = fscx(result, B) ^ nonce
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def i_val(size: int) -> int:
    return size // 4


def r_val(size: int) -> int:
    return size * 3 // 4


SIZES = [64, 128, 256]

TARGET_SEC = 1.0


# ---------------------------------------------------------------------------
# Security tests
# ---------------------------------------------------------------------------

def test_noncommutativity():
    # FSCX(A,B) == FSCX(B,A) always (symmetric formula: A^B^ROL(A)^ROL(B)^ROR(A)^ROR(B)).
    # Asymmetry arises in FSCX_REVOLVE_N, where B is held constant across
    # iterations: FSCX_REVOLVE_N(A,B,N,n) != FSCX_REVOLVE_N(B,A,N,n) in general.
    # The nonce term T_n(N) cancels from both sides of the difference, so
    # commutativity is determined solely by the A and B inputs.
    print("[1] FSCX_REVOLVE_N non-commutativity: FSCX_REVOLVE_N(A,B,N,n) != FSCX_REVOLVE_N(B,A,N,n)")
    for size in SIZES:
        iv = i_val(size)
        comm = 0
        for _ in range(10000):
            a = BitArray.random(size)
            b = BitArray.random(size)
            n = BitArray.random(size)
            if fscx_revolve_n(a, b, n, iv) == fscx_revolve_n(b, a, n, iv):
                comm += 1
        status = "PASS" if comm == 0 else "FAIL"
        print(f"    bits={size:3d}  {comm:5d} / 10000 commutative  [{status}]")
    print()


def test_avalanche():
    # FSCX is a linear map over GF(2): output bit i depends only on input bits
    # i-1, i, i+1 (cyclic). Flipping one input bit always changes exactly 3 output
    # bits — the bit and its two cyclic neighbors. Security comes from FSCX_REVOLVE
    # iteration, not single-step diffusion.
    # Frobenius over GF(2): (1+t+t^-1)^(2^k) = 1+t^(2^k)+t^(-2^k), so power-of-2
    # step counts (like i_val = size//4) also give 3-bit diffusion.
    print("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)")
    for size in SIZES:
        total = 0.0
        gmin = size + 1
        gmax = -1
        for _ in range(1000):
            a = BitArray.random(size)
            b = BitArray.random(size)
            base = fscx(a, b)
            for bit in range(size):
                ap = a.flip_bit(bit)
                hd = (fscx(ap, b) ^ base).popcount()
                total += hd
                if hd < gmin:
                    gmin = hd
                if hd > gmax:
                    gmax = hd
        mean = total / (1000.0 * size)
        status = "PASS" if 2.9 <= mean <= 3.1 else "FAIL"
        print(f"    bits={size:3d}  mean={mean:.2f} (expected 3/{size})  min={gmin}  max={gmax}  [{status}]")
    print()


def test_orbit_period():
    print("[3] Orbit period: FSCX_REVOLVE cycles back to A")
    for size in SIZES:
        cnt_p  = 0
        cnt_hp = 0
        other  = 0
        cap = 2 * size
        for _ in range(100):
            a = BitArray.random(size)
            b = BitArray.random(size)
            cur = fscx(a, b)
            period = 1
            while cur != a and period < cap:
                cur = fscx(cur, b)
                period += 1
            if period == size:
                cnt_p += 1
            elif period == size // 2:
                cnt_hp += 1
            else:
                other += 1
        status = "PASS" if other == 0 else "FAIL"
        print(f"    bits={size:3d}  period={size}: {cnt_p:3d}  period={size//2}: {cnt_hp:3d}  other: {other}  [{status}]")
    print()


def test_bit_frequency():
    print("[4] Bit-frequency bias: 100000 FSCX outputs per size")
    N = 100000
    for size in SIZES:
        counts = [0] * size
        for _ in range(N):
            a = BitArray.random(size)
            b = BitArray.random(size)
            out = fscx(a, b)
            val = out.uint
            for bit in range(size):
                if (val >> bit) & 1:
                    counts[bit] += 1
        pcts = [c / N * 100.0 for c in counts]
        mn = min(pcts)
        mx = max(pcts)
        mean = sum(pcts) / size
        status = "PASS" if mn > 47.0 and mx < 53.0 else "FAIL"
        print(f"    bits={size:3d}  min={mn:.2f}%  max={mx:.2f}%  mean={mean:.2f}%  [{status}]")
    print()


def test_key_sensitivity():
    # sk = FSCX_REVOLVE_N(C2, B, hn, r) ^ A
    # Flipping bit k of A changes sk by exactly 1 bit via the direct XOR term.
    # The nonce change propagates L^i(e_k) into hn = C^C2; algebraically
    # S_r * L^i(e_k) cancels to zero, leaving only the 1-bit XOR contribution.
    # This is a structural property of the HKEX XOR construction.
    print("[5] HKEX session key XOR construction (expected: exactly 1-bit direct sensitivity)")
    for size in SIZES:
        total = 0.0
        iv = i_val(size)
        rv = r_val(size)
        for _ in range(10000):
            a  = BitArray.random(size)
            b  = BitArray.random(size)
            a2 = BitArray.random(size)
            b2 = BitArray.random(size)
            c  = fscx_revolve(a, b, iv)
            c2 = fscx_revolve(a2, b2, iv)
            hn = c ^ c2
            key1 = fscx_revolve_n(c2, b, hn, rv) ^ a
            af   = a.flip_bit(0)
            key2 = fscx_revolve_n(c2, b, hn, rv) ^ af
            total += (key1 ^ key2).popcount()
        mean = total / 10000.0
        status = "PASS" if 0.9 <= mean <= 1.1 else "FAIL"
        print(f"    bits={size:3d}  mean Hamming={mean:.2f} (expected 1/{size})  [{status}]")
    print()


def test_avalanche_revolve_n():
    # FSCX_REVOLVE_N nonce-injection avalanche.
    # Flipping 1 bit of the nonce N while keeping A and B constant propagates
    # through all remaining revolve steps.  The change in the output equals
    # T_n(e_k) where T_n = I + L + ... + L^(n-1) and e_k is the unit vector
    # at bit position k.  Unlike the 3-bit diffusion of single-step FSCX or
    # the purely linear FSCX_REVOLVE, T_n accumulates contributions from every
    # step.  HD = popcount(T_n(e_0)) is deterministic (independent of A and B),
    # so min == max == mean.  For n = size/4 (i_val), HD = size/4 exactly.
    print("[6] FSCX_REVOLVE_N nonce-avalanche: flip 1 nonce bit, measure output diffusion")
    for size in SIZES:
        iv = i_val(size)
        expected = size // 4
        total = 0.0
        gmin = size + 1
        gmax = -1
        for _ in range(1000):
            a = BitArray.random(size)
            b = BitArray.random(size)
            n = BitArray.random(size)
            base    = fscx_revolve_n(a, b, n,           iv)
            nf      = n.flip_bit(0)
            flipped = fscx_revolve_n(a, b, nf,          iv)
            hd = (base ^ flipped).popcount()
            total += hd
            if hd < gmin:
                gmin = hd
            if hd > gmax:
                gmax = hd
        mean = total / 1000.0
        status = "PASS" if mean >= expected else "FAIL"
        print(f"    bits={size:3d}  mean HD={mean:.1f} (expected >={expected})  min={gmin}  max={gmax}  [{status}]")
    print()


# ---------------------------------------------------------------------------
# Performance benchmarks
# ---------------------------------------------------------------------------

def _bench(label: str, fn):
    """Run fn in batches of 100 until ~TARGET_SEC elapsed. Return (ops, elapsed)."""
    # warm up
    for _ in range(10):
        fn()
    t0 = time.perf_counter()
    ops = 0
    while True:
        for _ in range(100):
            fn()
        ops += 100
        elapsed = time.perf_counter() - t0
        if elapsed >= TARGET_SEC:
            break
    rate = ops / elapsed
    if rate >= 1e6:
        rate_str = f"{rate/1e6:.2f} M ops/sec"
    elif rate >= 1e3:
        rate_str = f"{rate/1e3:.2f} K ops/sec"
    else:
        rate_str = f"{rate:.2f} ops/sec"
    print(f"    {label:<40s}: {rate_str}  ({ops} ops in {elapsed:.2f}s)")


def bench_fscx():
    print("[7] FSCX throughput")
    for size in SIZES:
        a = BitArray.random(size)
        b = BitArray.random(size)
        def fn():
            nonlocal a
            a = fscx(a, b)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_fscx_revolve_n():
    print("[8] FSCX_REVOLVE_N throughput")
    for size in SIZES:
        for steps, label in [(i_val(size), f"i({i_val(size)})"), (r_val(size), f"r({r_val(size)})")]:
            a = BitArray.random(size)
            b = BitArray.random(size)
            n = BitArray.random(size)
            def fn(a=a, b=b, n=n, steps=steps):
                return fscx_revolve_n(a, b, n, steps)
            _bench(f"bits={size:3d}  steps={label}", fn)
    print()


def bench_hkex_handshake():
    print("[9] HKEX full handshake")
    for size in SIZES:
        iv = i_val(size)
        rv = r_val(size)
        def fn():
            a  = BitArray.random(size)
            b  = BitArray.random(size)
            a2 = BitArray.random(size)
            b2 = BitArray.random(size)
            c  = fscx_revolve(a, b, iv)
            c2 = fscx_revolve(a2, b2, iv)
            hn = c ^ c2
            _keyA = fscx_revolve_n(c2, b,  hn, rv) ^ a
            _keyB = fscx_revolve_n(c,  b2, hn, rv) ^ a2
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hske_roundtrip():
    print("[10] HSKE round-trip: encrypt+decrypt")
    for size in SIZES:
        iv = i_val(size)
        rv = r_val(size)
        sink = BitArray(size, 0)
        def fn():
            nonlocal sink
            pt  = BitArray.random(size)
            key = BitArray.random(size)
            enc = fscx_revolve_n(pt,  key, key, iv)
            dec = fscx_revolve_n(enc, key, key, rv)
            sink ^= dec ^ pt
        _bench(f"bits={size:3d}", fn)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=== Herradura KEx \u2014 Security & Performance Tests (Python) ===\n")

    print("--- Security Assumption Tests ---\n")
    test_noncommutativity()
    test_avalanche()
    test_orbit_period()
    test_bit_frequency()
    test_key_sensitivity()

    test_avalanche_revolve_n()

    print("--- Performance Benchmarks ---\n")
    bench_fscx()
    bench_fscx_revolve_n()
    bench_hkex_handshake()
    bench_hske_roundtrip()
