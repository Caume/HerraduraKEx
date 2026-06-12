'''
    Herradura KEx — Security & Performance Tests (Python) v1.9.32
    v1.9.32: ZKP-RNL test [21] structured cheats — wrong-key, tampered-w, perturbed-z rejection (TODO #94).
    v1.9.31: Unified test numbering [1]–[27] across C/Go/Python; benchmarks [28]–[39] (TODO #87).
            HPKS-Stern-Ring [27]→[20]; ZKP/FPE/TWK/Acc/Masked/Ratchet shifted +1; benchmarks shifted +3.
    v1.9.11: ZKP-RNL + ZKP-NL security tests [20][21] and benchmarks [32][33] (TODO #77 Batch 7);
            benchmarks renumbered [22]-[33].
    v1.8.7: 32-bit benchmark columns; bench_hpks_stern_f loops over all sizes (TODO #61 extension).
    v1.8.0: KDF domain constant (TODO #38) — _RNL_KDF_DC_256 applied to all HSKE-NL-A1 and HKEX-RNL seed sites.
    v1.7.3: NumPy NTT acceleration — ~10× speedup on _rnl_poly_mul (TODO #40).
    v1.5.24: HFSCX-256 hash primitive (TODO #26 Phase 1) — KAT, determinism, collision sanity.
    v1.5.23: HerraduraCli OpenSSL-style CLI (TODO #25); CliTest shell test suite.
    v1.5.20: multi-size standardization — GF/RNL/Stern-F tests at 32,64,128,256 bits.
    v1.5.18: HPKS-Stern-F [17] + HPKE-Stern-F [18] + bench [26] (code-based PQC).
    v1.5.13: HSKE-NL-A1 seed fix — seed=ROL(base,n/8) breaks counter=0 step-1 degeneracy.
    v1.5.10: HKEX-RNL KDF seed fix — seed=ROL(K,n/8) breaks step-1 degeneracy.
    v1.5.9: nl_fscx_revolve_v2_inv precomputes delta(B) once — eliminates per-step multiply.
    v1.5.7: _m_inv uses precomputed rotation table (lazy init, cached per bit-size).
    v1.5.6: rnl_rand_poly bias fix — 3-byte rejection sampling (threshold=16711935).
    v1.5.5: fixed version banner (was stuck at v1.5.3).
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n), ~6× speedup at n=32).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.2: proposed multi-size key-length tests for Herradura_tests.c (matching Python).
    v1.5.1: added --rounds/-r and --time/-t CLI options (also HTEST_ROUNDS / HTEST_TIME env).
    v1.5.0: added PQC extension tests [10-16] and benchmarks [22-25].
            benchmarks renumbered [17-21] (were [10-14] in v1.4.0) (now [22]-[33]).
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
import itertools
import os
import random
import sys
import time

try:
    import numpy as _np
    _NUMPY = True
    _NTT_CACHE = {}   # (q, n) -> (rev, fwd_tw, inv_tw, inv_n, psi_pows, psi_inv_pows)

    def _ntt_tables(q, n):
        key = (q, n)
        if key in _NTT_CACHE:
            return _NTT_CACHE[key]
        bits = n.bit_length() - 1
        tmp = _np.arange(n, dtype=_np.int32)
        rev = _np.zeros(n, dtype=_np.int32)
        for _ in range(bits):
            rev = (rev << 1) | (tmp & 1)
            tmp >>= 1
        def _twiddles(invert):
            tables, length = [], 2
            while length <= n:
                w = pow(3, (q - 1) // length, q)
                if invert:
                    w = pow(w, q - 2, q)
                half = length >> 1
                tw = _np.empty(half, dtype=_np.int64)
                wn = 1
                for k in range(half):
                    tw[k] = wn
                    wn = wn * w % q
                tables.append(tw)
                length <<= 1
            return tables
        fwd_tw = _twiddles(False)
        inv_tw = _twiddles(True)
        inv_n  = pow(n, q - 2, q)
        psi     = pow(3, (q - 1) // (2 * n), q)
        psi_inv = pow(psi, q - 2, q)
        pw, pw_inv = 1, 1
        psi_pows     = _np.empty(n, dtype=_np.int64)
        psi_inv_pows = _np.empty(n, dtype=_np.int64)
        for i in range(n):
            psi_pows[i]     = pw
            psi_inv_pows[i] = pw_inv
            pw     = pw     * psi     % q
            pw_inv = pw_inv * psi_inv % q
        _NTT_CACHE[key] = (rev, fwd_tw, inv_tw, inv_n, psi_pows, psi_inv_pows)
        return _NTT_CACHE[key]

    def _ntt_np(arr, q, invert):
        n = len(arr)
        rev, fwd_tw, inv_tw, inv_n, _, _ = _ntt_tables(q, n)
        tables = inv_tw if invert else fwd_tw
        arr[:] = arr[rev]
        stage, length = 0, 2
        while length <= n:
            half = length >> 1
            A = arr.reshape(n // length, length)
            U = A[:, :half].copy()
            V = A[:, half:] * tables[stage] % q
            A[:, :half] = (U + V) % q
            A[:, half:] = (U - V + q) % q
            length <<= 1
            stage += 1
        if invert:
            arr *= inv_n
            arr %= q

except ImportError:
    _NUMPY = False

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

_m_inv_rotations: dict[int, tuple[int, ...]] = {}

def _m_inv(X: BitArray) -> BitArray:
    """M^{-1}(X) via precomputed rotation table, cached per bit-size."""
    n = X._size
    if n not in _m_inv_rotations:
        unit = BitArray(n, 1)
        zero = BitArray(n, 0)
        v = fscx_revolve(unit, zero, n // 2 - 1)
        _m_inv_rotations[n] = tuple(k for k in range(n) if (v.uint >> k) & 1)
    result = BitArray(n, 0)
    for k in _m_inv_rotations[n]:
        result = result ^ X.rotated(k)
    return result


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
    n     = Y._size
    mask  = Y._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    result = Y.copy()
    for _ in range(steps):
        z      = BitArray(n, (result.uint - delta.uint) & mask)
        result = B ^ _m_inv(z)
    return result


# ---------------------------------------------------------------------------
# HFSCX-256 (self-contained, mirrors suite)
# ---------------------------------------------------------------------------

_HFSCX256_IV_BYTES = b'HFSCX-256/HERRADURA-SUITE\x00\x00\x00\x00\x00\x00\x00'
_RNL_KDF_DC_256 = 0x6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19


def hfscx_256(data: bytes, *, iv: BitArray | None = None) -> bytes:
    """HFSCX-256: 256-bit Merkle-Damgård hash over NL-FSCX v1 (self-contained copy)."""
    n    = 256
    blen = 32
    iv_int   = int.from_bytes(_HFSCX256_IV_BYTES, 'big')
    init_int = iv_int if iv is None else iv.uint
    state    = BitArray(n, init_int)

    padded = bytearray(data) + b'\x80'
    rem = len(padded) % blen
    if rem:
        padded += b'\x00' * (blen - rem)

    # Length block XOR'd with initial state to bind the key into the final block.
    len_raw = int.from_bytes(b'\x00' * (blen - 8) + (len(data) * 8).to_bytes(8, 'big'), 'big')
    padded += (len_raw ^ init_int).to_bytes(blen, 'big')

    # Chain blocks: C_DM(s, m) = F_1^{64}(s, m) ⊕ s (Davies-Meyer feed-forward)
    steps = n // 4  # 64
    for off in range(0, len(padded), blen):
        prev = state
        block = BitArray(n, int.from_bytes(padded[off:off + blen], 'big'))
        state = nl_fscx_revolve_v1(state, block, steps)
        state = BitArray(n, state.uint ^ prev.uint)

    return state.uint.to_bytes(blen, 'big')


# ---------------------------------------------------------------------------
# 78.A FPE / 78.B Tweakable / 78.J Accumulator (self-contained copies)
# ---------------------------------------------------------------------------

_KEYBITS = 256
_I_VALUE = _KEYBITS // 4  # 64

def _fpe_derive_b(key: bytes, ctx: bytes) -> BitArray:
    return BitArray(_KEYBITS, int.from_bytes(hfscx_256(key + ctx), 'big'))

def fpe_encrypt_test(pt: BitArray, key: bytes, ctx: bytes = b'') -> BitArray:
    return nl_fscx_revolve_v2(pt, _fpe_derive_b(key, ctx), _I_VALUE)

def fpe_decrypt_test(ct: BitArray, key: bytes, ctx: bytes = b'') -> BitArray:
    return nl_fscx_revolve_v2_inv(ct, _fpe_derive_b(key, ctx), _I_VALUE)

def twk_encrypt_test(block: BitArray, key: bytes, sector: int, bidx: int) -> BitArray:
    tweak = key + sector.to_bytes(8, 'big') + bidx.to_bytes(4, 'big')
    B = BitArray(_KEYBITS, int.from_bytes(hfscx_256(tweak), 'big'))
    return nl_fscx_revolve_v2(block, B, _I_VALUE)

def twk_decrypt_test(ct: BitArray, key: bytes, sector: int, bidx: int) -> BitArray:
    tweak = key + sector.to_bytes(8, 'big') + bidx.to_bytes(4, 'big')
    B = BitArray(_KEYBITS, int.from_bytes(hfscx_256(tweak), 'big'))
    return nl_fscx_revolve_v2_inv(ct, B, _I_VALUE)

def haccum_leaf_test(data: bytes) -> bytes:
    return hfscx_256(b'\x00' + data)

def haccum_node_test(left: bytes, right: bytes) -> bytes:
    return hfscx_256(b'\x01' + left + right)

def haccum_root_test(leaf_hashes: list) -> bytes:
    n = len(leaf_hashes)
    sz = 1
    while sz < n:
        sz <<= 1
    zero_hash = hfscx_256(b'\x00')
    nodes = [lh for lh in leaf_hashes] + [zero_hash] * (sz - n)
    while len(nodes) > 1:
        nodes = [haccum_node_test(nodes[2*i], nodes[2*i+1]) for i in range(len(nodes) // 2)]
    return nodes[0]

def haccum_prove_test(leaf_hashes: list, idx: int) -> list:
    n = len(leaf_hashes)
    sz = 1
    while sz < n:
        sz <<= 1
    zero_hash = hfscx_256(b'\x00')
    nodes = [lh for lh in leaf_hashes] + [zero_hash] * (sz - n)
    proof = []
    cur = idx
    while len(nodes) > 1:
        sib = cur ^ 1
        if sib < len(nodes):
            proof.append(nodes[sib])
        cur //= 2
        nodes = [haccum_node_test(nodes[2*i], nodes[2*i+1]) for i in range(len(nodes) // 2)]
    return proof

def haccum_verify_test(root: bytes, leaf_hash: bytes, proof: list, idx: int) -> bool:
    cur = leaf_hash
    for sib in proof:
        if idx % 2 == 0:
            cur = haccum_node_test(cur, sib)
        else:
            cur = haccum_node_test(sib, cur)
        idx //= 2
    return cur == root


# ---------------------------------------------------------------------------
# 78.H Masking / 78.C Ratchet (self-contained copies)
# ---------------------------------------------------------------------------

_R_VALUE = _KEYBITS * 3 // 4  # 192

def fscx_revolve_masked_test(A: BitArray, B: BitArray, mask: BitArray, steps: int) -> BitArray:
    zero = BitArray(_KEYBITS, 0)
    am   = BitArray(_KEYBITS, A.uint ^ mask.uint)
    fm   = fscx_revolve(am, B, steps)
    fz   = fscx_revolve(mask, zero, steps)
    return BitArray(_KEYBITS, fm.uint ^ fz.uint)

_RATCHET_DOMAIN_TEST = BitArray(
    _KEYBITS,
    int.from_bytes(b'NL-FSCX-RATCHET-V1\x00NL-FSCX-RATCHET-V'[:_KEYBITS // 8], 'big')
)

def ratchet_init_test(seed: bytes) -> BitArray:
    return BitArray(_KEYBITS, int.from_bytes(hfscx_256(seed + b'\x02'), 'big'))

def ratchet_advance_test(state: BitArray):
    msg_key   = hfscx_256(state.bytes + b'\x01')
    new_state = nl_fscx_revolve_v1(state, _RATCHET_DOMAIN_TEST, 1)
    return new_state, msg_key


# ---------------------------------------------------------------------------
# HPKS-Stern-F / HPKE-Stern-F helpers (self-contained, mirrors suite)
# ---------------------------------------------------------------------------

def _stern_hash(n: int, *items, ds: int = 0) -> 'BitArray':
    """Chain-hash + HFSCX-256 finalizer (v1.6.0). ds: domain-sep tag (TODO #36, v1.6.1)."""
    mask = (1 << n) - 1
    h = BitArray(n, ds & mask)
    for item in items:
        v = item if isinstance(item, BitArray) else BitArray(n, int(item) & mask)
        h = nl_fscx_revolve_v1(h ^ v, v.rotated(n // 8), n // 4)
    digest = hfscx_256(h.bytes)
    return BitArray(n, int.from_bytes(digest, 'big') >> (256 - n))

def _stern_matrix_row(seed_int: int, row: int, n: int) -> 'BitArray':
    seed = BitArray(n, seed_int)
    A0   = BitArray(n, seed_int ^ row).rotated(n // 8)
    return nl_fscx_revolve_v1(A0, seed, n // 4)

def _stern_syndrome(seed_int: int, e_int: int, n: int, n_rows: int) -> int:
    s = 0
    for i in range(n_rows):
        row = _stern_matrix_row(seed_int, i, n)
        s  |= (bin(row.uint & e_int).count('1') & 1) << i
    return s

def _stern_gen_perm(pi_seed: 'BitArray', N: int) -> list:
    n    = pi_seed._size
    key  = pi_seed.rotated(n // 8)
    perm = list(range(N))
    st   = pi_seed.copy()
    for i in range(N - 1, 0, -1):
        st = nl_fscx_v1(st, key)
        perm[i], perm[st.uint % (i + 1)] = perm[st.uint % (i + 1)], perm[i]
    return perm

def _stern_apply_perm(perm: list, v_int: int, N: int) -> int:
    result = 0
    for i in range(N):
        if (v_int >> i) & 1:
            result |= 1 << perm[i]
    return result

def _csprng_weight_t(n: int, t: int) -> int:
    """SA-07: os.urandom-based weight-t bit vector via index sampling.
    Rejection-samples t distinct indices from [0, n) using 4-byte draws with
    bias elimination (threshold method), then sets those bits.
    Replaces random.sample() (Mersenne Twister) for secret material."""
    chosen: set = set()
    threshold = (1 << 32) - (1 << 32) % n
    while len(chosen) < t:
        v = int.from_bytes(os.urandom(4), 'big')
        if v < threshold:
            chosen.add(v % n)
    return sum(1 << p for p in chosen)

def stern_f_keygen(n: int):
    n_rows = n // 2
    t      = max(2, n // 16)
    seed   = BitArray.random(n)
    e_int  = _csprng_weight_t(n, t)
    return seed, e_int, _stern_syndrome(seed.uint, e_int, n, n_rows)

def hpks_stern_f_sign(msg, e_int, seed, syndrome, n, rounds):
    n_rows = n // 2
    t      = max(2, n // 16)
    commits = []; round_data = []
    for _ in range(rounds):
        r_int   = _csprng_weight_t(n, t)           # SA-07: was random.sample()
        y_int   = (e_int ^ r_int) & ((1 << n) - 1)
        pi_seed = BitArray.random(n)
        perm    = _stern_gen_perm(pi_seed, n)
        Hr  = _stern_syndrome(seed.uint, r_int, n, n_rows)
        sr  = _stern_apply_perm(perm, r_int, n)
        sy  = _stern_apply_perm(perm, y_int, n)
        commits.append((_stern_hash(n, pi_seed, BitArray(n, Hr), ds=1),
                        _stern_hash(n, BitArray(n, sr), ds=2),
                        _stern_hash(n, BitArray(n, sy), ds=3)))
        round_data.append((r_int, y_int, pi_seed, Hr, sr, sy))
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = _stern_hash(n, *flat); challenges = []
    for i in range(rounds):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, i))
        challenges.append(ch_st.uint % 3)
    responses = []
    for i, (r_int, y_int, pi_seed, _Hr, sr, sy) in enumerate(round_data):
        b = challenges[i]
        if   b == 0: responses.append((sr, sy))
        elif b == 1: responses.append((pi_seed, r_int))
        else:        responses.append((pi_seed, y_int))
    return (commits, challenges, responses)

def hpks_stern_f_verify(msg, sig, seed, syndrome, n):
    n_rows = n // 2; t = max(2, n // 16)
    commits, challenges, responses = sig
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = _stern_hash(n, *flat)
    for i, b in enumerate(challenges):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, i))
        if ch_st.uint % 3 != b: return False
    for i, b in enumerate(challenges):
        c0, c1, c2 = commits[i]; resp = responses[i]
        if b == 0:
            sr, sy = resp
            if _stern_hash(n, BitArray(n, sr), ds=2) != c1: return False
            if _stern_hash(n, BitArray(n, sy), ds=3) != c2: return False
            if bin(sr).count('1') != t:                     return False
        elif b == 1:
            pi_seed, r_int = resp
            if bin(r_int).count('1') != t:                  return False
            perm = _stern_gen_perm(pi_seed, n)
            Hr   = _stern_syndrome(seed.uint, r_int, n, n_rows)
            if _stern_hash(n, pi_seed, BitArray(n, Hr), ds=1) != c0: return False
            sr   = _stern_apply_perm(perm, r_int, n)
            if _stern_hash(n, BitArray(n, sr), ds=2) != c1: return False
        else:
            pi_seed, y_int = resp
            perm = _stern_gen_perm(pi_seed, n)
            Hy   = _stern_syndrome(seed.uint, y_int, n, n_rows)
            if _stern_hash(n, pi_seed, BitArray(n, Hy ^ syndrome), ds=1) != c0: return False
            sy   = _stern_apply_perm(perm, y_int, n)
            if _stern_hash(n, BitArray(n, sy), ds=3) != c2: return False
    return True

def hpke_stern_f_encap(seed, n):
    n_rows = n // 2; t = max(2, n // 16)
    e_p    = _csprng_weight_t(n, t)  # SA-07: was random.sample()
    ct     = _stern_syndrome(seed.uint, e_p, n, n_rows)
    K      = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return K, ct

def hpke_stern_f_decap(ciphertext, seed, n):
    n_rows = n // 2; t = max(2, n // 16)
    for pos in itertools.combinations(range(n), t):
        e_p = sum(1 << p for p in pos)
        if _stern_syndrome(seed.uint, e_p, n, n_rows) == ciphertext:
            return _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return None

def hpke_stern_f_encap_with_e(seed, n):
    """Like hpke_stern_f_encap but also returns the plaintext error e_p (for tests)."""
    n_rows = n // 2; t = max(2, n // 16)
    e_p = _csprng_weight_t(n, t)  # SA-07: was random.sample()
    ct  = _stern_syndrome(seed.uint, e_p, n, n_rows)
    K   = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return K, ct, e_p

def hpke_stern_f_decap_known(e_int, seed, n):
    """Known-error decap: given the plaintext error e_int, derive K directly."""
    return _stern_hash(n, seed, BitArray(n, e_int & ((1 << n) - 1)), ds=4)


# ---------------------------------------------------------------------------
# HPKS-Stern-Ring: OR-composed ring signature (TODO #78.I)

def _ring_stern_simulate_round(b, seed_int, syndrome, n):
    """HVZK simulator: returns (c0,c1,c2,b,resp) for pre-chosen challenge b."""
    n_rows = n // 2; t = max(2, n // 16)
    if b == 0:
        sr = _csprng_weight_t(n, t)
        sy = int.from_bytes(os.urandom(n // 8), 'big')
        c0 = _stern_hash(n, BitArray(n, 0), BitArray(n, 0), ds=1)
        c1 = _stern_hash(n, BitArray(n, sr), ds=2)
        c2 = _stern_hash(n, BitArray(n, sy), ds=3)
        return (c0, c1, c2), b, (sr, sy)
    elif b == 1:
        pi = BitArray.random(n)
        r  = _csprng_weight_t(n, t)
        perm = _stern_gen_perm(pi, n)
        Hr   = _stern_syndrome(seed_int, r, n, n_rows)
        sr   = _stern_apply_perm(perm, r, n)
        c0   = _stern_hash(n, pi, BitArray(n, Hr), ds=1)
        c1   = _stern_hash(n, BitArray(n, sr), ds=2)
        c2   = _stern_hash(n, BitArray(n, 0), ds=3)
        return (c0, c1, c2), b, (pi, r)
    else:
        pi = BitArray.random(n)
        y  = int.from_bytes(os.urandom(n // 8), 'big')
        perm = _stern_gen_perm(pi, n)
        Hy   = _stern_syndrome(seed_int, y, n, n_rows)
        Hys  = Hy ^ syndrome
        sy   = _stern_apply_perm(perm, y, n)
        c0   = _stern_hash(n, pi, BitArray(n, Hys), ds=1)
        c1   = _stern_hash(n, BitArray(n, 0), ds=2)
        c2   = _stern_hash(n, BitArray(n, sy), ds=3)
        return (c0, c1, c2), b, (pi, y)


def _ring_stern_challenges(rounds, k, msg, all_commits):
    """Fiat-Shamir: derive joint challenges from msg + all k*rounds commits."""
    n = msg._size
    flat = [msg]
    for i in range(k):
        for r in range(rounds):
            c0, c1, c2 = all_commits[i][r]
            flat += [c0, c1, c2]
    ch_st = _stern_hash(n, *flat)
    joint = []
    for r in range(rounds):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, r))
        joint.append(ch_st.uint % 3)
    return joint


def hpks_stern_ring_sign_local(msg, e_int, j, ring_keys, n, rounds):
    """Ring sign as member j (ring_keys = [(seed, syndrome), ...])."""
    k = len(ring_keys); t = max(2, n // 16); n_rows = n // 2
    sim_commits  = [[None] * rounds for _ in range(k)]
    sim_bs       = [[0] * rounds    for _ in range(k)]
    sim_resps    = [[None] * rounds for _ in range(k)]

    # Step 1: simulate non-signers
    for i in range(k):
        if i == j: continue
        seed_i, syn_i = ring_keys[i]
        for r in range(rounds):
            bv = int.from_bytes(os.urandom(1), 'big') % 3
            cmts, bv, resp = _ring_stern_simulate_round(bv, seed_i.uint, syn_i, n)
            sim_commits[i][r] = cmts; sim_bs[i][r] = bv; sim_resps[i][r] = resp

    # Step 2: commit phase for real signer j
    seed_j, _ = ring_keys[j]
    j_r_tmp  = []; j_y_tmp  = []; j_pi_tmp = []
    j_sr_tmp = []; j_sy_tmp = []
    for r in range(rounds):
        rv = _csprng_weight_t(n, t)
        yv = e_int ^ rv
        pi = BitArray.random(n)
        perm = _stern_gen_perm(pi, n)
        Hr   = _stern_syndrome(seed_j.uint, rv, n, n_rows)
        sr   = _stern_apply_perm(perm, rv, n)
        sy   = _stern_apply_perm(perm, yv, n)
        c0   = _stern_hash(n, pi, BitArray(n, Hr), ds=1)
        c1   = _stern_hash(n, BitArray(n, sr), ds=2)
        c2   = _stern_hash(n, BitArray(n, sy), ds=3)
        sim_commits[j][r] = (c0, c1, c2)
        j_r_tmp.append(rv); j_y_tmp.append(yv); j_pi_tmp.append(pi)
        j_sr_tmp.append(sr); j_sy_tmp.append(sy)

    # Step 3: Fiat-Shamir joint challenges
    joint = _ring_stern_challenges(rounds, k, msg, sim_commits)

    # Step 4: assign real signer's challenge via challenge splitting
    for r in range(rounds):
        sim_sum = sum(sim_bs[i][r] for i in range(k) if i != j)
        bv = (joint[r] - sim_sum) % 3
        sim_bs[j][r] = bv
        if bv == 0:
            sim_resps[j][r] = (j_sr_tmp[r], j_sy_tmp[r])
        elif bv == 1:
            sim_resps[j][r] = (j_pi_tmp[r], j_r_tmp[r])
        else:
            sim_resps[j][r] = (j_pi_tmp[r], j_y_tmp[r])

    all_commits  = [[sim_commits[i][r]  for r in range(rounds)] for i in range(k)]
    all_challenges = [[sim_bs[i][r]     for r in range(rounds)] for i in range(k)]
    all_responses  = [[sim_resps[i][r]  for r in range(rounds)] for i in range(k)]
    return all_commits, all_challenges, all_responses


def hpks_stern_ring_verify_local(msg, sig, ring_keys, n):
    """Verify a ring signature (all_commits, all_challenges, all_responses)."""
    all_commits, all_challenges, all_responses = sig
    k = len(ring_keys); rounds = len(all_commits[0]); t = max(2, n // 16); n_rows = n // 2

    joint = _ring_stern_challenges(rounds, k, msg, all_commits)

    for r in range(rounds):
        s = sum(all_challenges[i][r] for i in range(k)) % 3
        if s != joint[r]: return False

    for i in range(k):
        seed_i, syn_i = ring_keys[i]
        for r in range(rounds):
            b = all_challenges[i][r]; resp = all_responses[i][r]
            c0, c1, c2 = all_commits[i][r]
            if b == 0:
                sr, sy = resp
                if _stern_hash(n, BitArray(n, sr), ds=2) != c1: return False
                if _stern_hash(n, BitArray(n, sy), ds=3) != c2: return False
                if bin(sr).count('1') != t:                     return False
            elif b == 1:
                pi_seed, r_int = resp
                if bin(r_int).count('1') != t:                  return False
                perm = _stern_gen_perm(pi_seed, n)
                Hr   = _stern_syndrome(seed_i.uint, r_int, n, n_rows)
                if _stern_hash(n, pi_seed, BitArray(n, Hr), ds=1) != c0: return False
                sr   = _stern_apply_perm(perm, r_int, n)
                if _stern_hash(n, BitArray(n, sr), ds=2) != c1: return False
            else:
                pi_seed, y_int = resp
                perm = _stern_gen_perm(pi_seed, n)
                Hy   = _stern_syndrome(seed_i.uint, y_int, n, n_rows)
                if _stern_hash(n, pi_seed, BitArray(n, Hy ^ syn_i), ds=1) != c0: return False
                sy   = _stern_apply_perm(perm, y_int, n)
                if _stern_hash(n, BitArray(n, sy), ds=3) != c2: return False
    return True


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
    if _NUMPY:
        _, _, _, _, psi_pows, psi_inv_pows = _ntt_tables(q, n)
        fa = _np.array(f, dtype=_np.int64) * psi_pows % q
        ga = _np.array(g, dtype=_np.int64) * psi_pows % q
        _ntt_np(fa, q, False)
        _ntt_np(ga, q, False)
        ha = fa * ga % q
        _ntt_np(ha, q, True)
        return (ha * psi_inv_pows % q).tolist()
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
    return [(c * to_q + from_p // 2) // from_p % to_q for c in poly]

def _rnl_m_poly(n):
    p = [0] * n; p[0] = p[1] = p[n - 1] = 1; return p

def _rnl_rand_poly(n, q):
    return [int.from_bytes(os.urandom(4), 'big') % q for _ in range(n)]

def _rnl_cbd_poly(n, q):
    """CBD(eta=1): 4 coefficients per byte, bit-pairs (0-1),(2-3),(4-5),(6-7)."""
    raw = os.urandom((n + 3) // 4)
    return [(((raw[i >> 2] >> ((i & 3) * 2)) & 1) - ((raw[i >> 2] >> ((i & 3) * 2 + 1)) & 1) + q) % q
            for i in range(n)]

def _rnl_bits_to_bitarray(poly, pp, size):
    val = 0; thr = pp // 2
    for i, c in enumerate(poly[:size]):
        if c >= thr:
            val |= (1 << i)
    return BitArray(size, val)

def _rnl_hint(K_poly, q):
    return [((8 * c + q // 4) // q) % 4 for c in K_poly]

def _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits):
    qq = q // 4
    val = 0
    for i, (c, h) in enumerate(zip(K_poly[:key_bits // 2], hint[:key_bits // 2])):
        b = ((4 * c + (2 * h + 1) * qq) // q) % pp
        val |= (b << (2 * i))
    return val

def _rnl_keygen(m_blind, n, q, p):
    s = _rnl_cbd_poly(n, q)
    C = _rnl_round(_rnl_poly_mul(m_blind, s, q, n), q, p)
    return s, C

def _rnl_agree(s, C_other, q, p, pp, n, key_bits, hint=None):
    K = _rnl_poly_mul(s, _rnl_lift(C_other, p, q), q, n)
    if hint is None:
        hint = _rnl_hint(K, q)
        return BitArray(key_bits, _rnl_reconcile_bits(K, hint, q, pp, key_bits)), hint
    return BitArray(key_bits, _rnl_reconcile_bits(K, hint, q, pp, key_bits))


# ---------------------------------------------------------------------------
# ZKP-RNL Sigma-protocol helpers (self-contained, mirrors suite)
# ---------------------------------------------------------------------------

_SIGMA_GAMMA       = {32: 4096, 64: 8192, 128: 8192, 256: 8192}
_SIGMA_T           = {32: 4,    64: 8,    128: 12,   256: 16}
_SIGMA_MAX_ATTEMPTS = 1000


def _sigma_params(n):
    gamma = _SIGMA_GAMMA.get(n, 8192 if n >= 64 else 4096)
    t     = _SIGMA_T.get(n, max(4, n // 16))
    return gamma, t


def _sigma_poly_bytes(poly):
    return b''.join((c % (1 << 32)).to_bytes(4, 'big') for c in poly)


def _sigma_challenge(m_poly, C_poly, w_poly, n, q, t, msg_bytes):
    seed = hfscx_256(
        n.to_bytes(4, 'big')
        + _sigma_poly_bytes(m_poly)
        + _sigma_poly_bytes(C_poly)
        + _sigma_poly_bytes(w_poly)
        + msg_bytes
    )
    positions = []
    idx = 0
    while len(positions) < t:
        h = hfscx_256(seed + b'pos' + idx.to_bytes(4, 'big'))
        v = int.from_bytes(h[:4], 'big') % n
        if v not in positions:
            positions.append(v)
        idx += 1
    c = [0] * n
    for k, pos in enumerate(positions):
        h = hfscx_256(seed + b'sgn' + k.to_bytes(4, 'big'))
        c[pos] = 1 if (h[0] & 1) == 0 else q - 1
    return c


def _rnl_sigma_sign(s_poly, m_poly, C_poly, n, msg_bytes):
    q     = RNLQ
    gamma, t = _sigma_params(n)
    bound = gamma - t
    h     = q // 2
    for _ in range(_SIGMA_MAX_ATTEMPTS):
        y    = [int.from_bytes(os.urandom(4), 'big') % (2 * gamma + 1) - gamma
                for _ in range(n)]
        y_q  = [yi % q for yi in y]
        my   = _rnl_poly_mul(m_poly, y_q, q, n)
        w    = [c - q if c > h else c for c in my]
        c    = _sigma_challenge(m_poly, C_poly, w, n, q, t, msg_bytes)
        cs   = _rnl_poly_mul(c, s_poly, q, n)
        cs_c = [x - q if x > h else x for x in cs]
        z    = [y[i] + cs_c[i] for i in range(n)]
        if max(abs(zi) for zi in z) <= bound:
            return w, c, z
    raise RuntimeError("_rnl_sigma_sign: rejection limit reached")


def _rnl_sigma_verify(m_poly, C_poly, n, msg_bytes, w_poly, c_poly, z_poly):
    q = RNLQ
    p = RNLP
    gamma, t = _sigma_params(n)
    bound = gamma - t
    slack = t * (q // (2 * p) + 1)
    if max(abs(zi) for zi in z_poly) > bound:
        return False
    if c_poly != _sigma_challenge(m_poly, C_poly, w_poly, n, q, t, msg_bytes):
        return False
    h    = q // 2
    z_q  = [zi % q for zi in z_poly]
    mz   = _rnl_poly_mul(m_poly, z_q, q, n)
    lift = _rnl_lift(C_poly, p, q)
    ct   = _rnl_poly_mul(c_poly, lift, q, n)
    w_q  = [wi % q for wi in w_poly]
    diff = [(mz[i] - ct[i] - w_q[i]) % q for i in range(n)]
    diff_c = [d - q if d > h else d for d in diff]
    return max(abs(d) for d in diff_c) <= slack


# ---------------------------------------------------------------------------
# ZKP-NL ZKBoo helpers (self-contained, mirrors suite)
# ---------------------------------------------------------------------------

def _zkp_nl_h(*args):
    buf = b''
    for a in args:
        if isinstance(a, bytes):
            buf += a
        elif isinstance(a, int):
            buf += a.to_bytes(max(1, (a.bit_length() + 7) // 8), 'big')
        else:
            buf += repr(a).encode()
    return hfscx_256(buf)


def _zkp_nl_prg_bit(tape_key, gate_id):
    h = _zkp_nl_h(tape_key, gate_id.to_bytes(4, 'big'))
    return h[0] & 1


def _zkp_nl_rol(x, r, n):
    m = (1 << n) - 1
    r = r % n
    return ((x << r) | (x >> (n - r))) & m


def _zkp_nl_evaluate_circuit(shares, tapes, B, n):
    mask = (1 << n) - 1
    carry = [[0, 0, 0]] * n
    gate_views = [[], [], []]
    gate_id = 0
    for i in range(n - 1):
        ai = [(shares[p] >> i) & 1 for p in range(3)]
        ci = [carry[i][p] for p in range(3)]
        Bi = (B >> i) & 1
        ri = [_zkp_nl_prg_bit(tapes[p], gate_id) for p in range(3)]
        gate_id += 1
        and_out = [0, 0, 0]
        for p in range(3):
            p1 = (p + 1) % 3
            and_out[p] = ((ai[p] & ci[p]) ^ (ai[p] & ci[p1])
                          ^ (ai[p1] & ci[p]) ^ ri[p] ^ ri[p1])
            gate_views[p].append((ai[p], ci[p], and_out[p]))
        c_next = [(Bi * ai[p]) ^ and_out[p] ^ (Bi * ci[p]) for p in range(3)]
        carry[i + 1] = c_next
    sum_shares = [0, 0, 0]
    for i in range(n):
        for p in range(3):
            bit_i = ((shares[p] >> i) & 1) ^ ((B >> i) & 1) ^ carry[i][p]
            sum_shares[p] ^= bit_i << i
    rot_shares = [_zkp_nl_rol(sum_shares[p], n // 4, n) for p in range(3)]
    B_const = (B ^ _zkp_nl_rol(B, 1, n) ^ _zkp_nl_rol(B, n - 1, n)) & mask
    lin_shares = [0, 0, 0]
    for p in range(3):
        A_terms = (shares[p] ^ _zkp_nl_rol(shares[p], 1, n)
                   ^ _zkp_nl_rol(shares[p], n - 1, n)) & mask
        lin_shares[p] = A_terms
    lin_shares[0] ^= B_const
    out_shares = [(lin_shares[p] ^ rot_shares[p]) & mask for p in range(3)]
    return out_shares, gate_views


def _zkp_nl_keygen(n):
    mask = (1 << n) - 1
    nb   = (n + 7) // 8
    A = int.from_bytes(os.urandom(nb), 'big') & mask
    B = int.from_bytes(os.urandom(nb), 'big') & mask
    y = nl_fscx_v1(BitArray(n, A), BitArray(n, B)).uint
    return A, B, y


def _zkp_nl_prove(A, B, y, n, rounds, msg_bytes):
    mask = (1 << n) - 1
    nb   = (n + 7) // 8
    all_coms  = []
    all_views = []
    com_block = b''
    for j in range(rounds):
        s0 = int.from_bytes(os.urandom(nb), 'big') & mask
        s1 = int.from_bytes(os.urandom(nb), 'big') & mask
        s2 = (A ^ s0 ^ s1) & mask
        shares = [s0, s1, s2]
        tapes  = [os.urandom(32) for _ in range(3)]
        out_shares, gate_views = _zkp_nl_evaluate_circuit(shares, tapes, B, n)
        coms = [
            _zkp_nl_h(j.to_bytes(4, 'big'), bytes([p]),
                      tapes[p], out_shares[p].to_bytes(nb, 'big'))
            for p in range(3)
        ]
        all_coms.append(coms)
        all_views.append((shares, tapes, out_shares, gate_views))
        com_block += b''.join(coms)
    ch_seed = _zkp_nl_h(
        com_block, B.to_bytes(nb, 'big'), y.to_bytes(nb, 'big'), msg_bytes
    )
    def _pack_view(p_idx, shares_l, tapes_l, out_shares_l, gate_views_l):
        view  = shares_l[p_idx].to_bytes(nb, 'big')
        view += tapes_l[p_idx]
        view += out_shares_l[p_idx].to_bytes(nb, 'big')
        for in0, in1, out in gate_views_l[p_idx]:
            view += bytes([in0 | (in1 << 1) | (out << 2)])
        return view
    rounds_out = []
    for j in range(rounds):
        h = _zkp_nl_h(ch_seed, j.to_bytes(4, 'big'))
        e = h[0] % 3
        p1, p2 = (e + 1) % 3, (e + 2) % 3
        shares, tapes, out_shares, gate_views = all_views[j]
        rounds_out.append({
            'com_0':   all_coms[j][0],
            'com_1':   all_coms[j][1],
            'com_2':   all_coms[j][2],
            'e':       e,
            'view_p1': _pack_view(p1, shares, tapes, out_shares, gate_views),
            'view_p2': _pack_view(p2, shares, tapes, out_shares, gate_views),
        })
    return rounds_out


def _zkp_nl_verify(B, y, n, rounds, msg_bytes, proof_rounds):
    mask = (1 << n) - 1
    nb   = (n + 7) // 8
    coms_list  = [[r['com_0'], r['com_1'], r['com_2']] for r in proof_rounds]
    challenges = [r['e'] for r in proof_rounds]
    com_block = b''.join(b''.join(coms) for coms in coms_list)
    ch_seed   = _zkp_nl_h(
        com_block, B.to_bytes(nb, 'big'), y.to_bytes(nb, 'big'), msg_bytes
    )
    for j in range(rounds):
        h = _zkp_nl_h(ch_seed, j.to_bytes(4, 'big'))
        if h[0] % 3 != challenges[j]:
            return False
    def _unpack_view(view_bytes):
        share = int.from_bytes(view_bytes[:nb], 'big')
        tape  = view_bytes[nb:nb + 32]
        out_s = int.from_bytes(view_bytes[nb + 32:nb + 32 + nb], 'big')
        gv = []
        for k in range(n - 1):
            b3 = view_bytes[nb + 32 + nb + k]
            gv.append((b3 & 1, (b3 >> 1) & 1, (b3 >> 2) & 1))
        return share, tape, out_s, gv
    for j, e in enumerate(challenges):
        resp = proof_rounds[j]
        p1, p2 = (e + 1) % 3, (e + 2) % 3
        share_p1, tape_p1, out_p1, gv_p1 = _unpack_view(resp['view_p1'])
        share_p2, tape_p2, out_p2, gv_p2 = _unpack_view(resp['view_p2'])
        c_p1 = _zkp_nl_h(j.to_bytes(4, 'big'), bytes([p1]),
                          tape_p1, out_p1.to_bytes(nb, 'big'))
        c_p2 = _zkp_nl_h(j.to_bytes(4, 'big'), bytes([p2]),
                          tape_p2, out_p2.to_bytes(nb, 'big'))
        if c_p1 != coms_list[j][p1] or c_p2 != coms_list[j][p2]:
            return False
        carry_p1, carry_p2 = 0, 0
        for i in range(n - 1):
            ai_p1 = (share_p1 >> i) & 1
            ai_p2 = (share_p2 >> i) & 1
            ci_p1 = carry_p1
            ci_p2 = carry_p2
            Bi    = (B >> i) & 1
            ri_p1 = _zkp_nl_prg_bit(tape_p1, i)
            ri_p2 = _zkp_nl_prg_bit(tape_p2, i)
            exp_and_p1 = ((ai_p1 & ci_p1) ^ (ai_p1 & ci_p2)
                          ^ (ai_p2 & ci_p1) ^ ri_p1 ^ ri_p2)
            if gv_p1[i][2] != exp_and_p1:
                return False
            carry_p1 = (Bi * ai_p1) ^ exp_and_p1 ^ (Bi * ci_p1)
            carry_p2 = (Bi * ai_p2) ^ gv_p2[i][2] ^ (Bi * ci_p2)
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def i_val(size: int) -> int:
    return size // 4

def r_val(size: int) -> int:
    return size * 3 // 4


SIZES     = [32, 64, 128, 256]  # bit sizes for FSCX/HSKE/NL benchmarks
GF_SIZES  = [32, 64, 128, 256]  # bit sizes for GfPow tests (Python big-int handles all)
GF_TRIALS = 100                 # trials for GfPow-heavy tests
RNL_SIZES = [32, 64, 128, 256]  # ring polynomial degrees for HKEX-RNL tests
RNLQ  = 65537  # Fermat prime (2^16+1); lower noise-to-margin ratio than q=3329
RNLP  = 4096   # public-key rounding modulus
RNLPP = 4      # reconciliation modulus (2 bits per coefficient)
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
    # HSKE-NL-A1 counter-mode with per-session nonce: N random; base = K XOR N.
    # keystream[i] = nl_fscx_revolve_v1(ROL(base, n/8), base XOR i, n/4).
    print("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); ok = 0; n_run = 0
        for trial in _trange(_iters(1000)):
            n_run += 1
            K    = BitArray.random(size)
            N    = BitArray.random(size)                 # per-session nonce
            P    = BitArray.random(size)
            base = BitArray(size, K.uint ^ N.uint)       # session key base
            ctr  = trial % (1 << min(size, 16))
            B    = BitArray(size, base.uint ^ ctr)
            ks   = nl_fscx_revolve_v1(BitArray(size, base.rotated(size // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - size))), B, iv)
            C    = BitArray(size, P.uint ^ ks.uint)
            D    = BitArray(size, C.uint ^ ks.uint)
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
    # s_A·(m_blind·s_B) = s_B·(m_blind·s_A).  See §11.4.2 of SecurityProofs-2.md.
    print("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]")
    print(f"     (ring sizes {RNL_SIZES}; Peikert reconciliation — expect 100% agreement)")
    for n_rnl in RNL_SIZES:
        m_base = _rnl_m_poly(n_rnl)
        ok_raw = 0; ok_sk = 0; n_run = 0
        for _ in _trange(_iters(200)):
            n_run += 1
            a_rand  = _rnl_rand_poly(n_rnl, RNLQ)
            m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)   # shared public polynomial
            s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            K_A, hint_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
            K_B         = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, n_rnl, hint_A)
            if K_A == K_B: ok_raw += 1
            sk_A = nl_fscx_revolve_v1(BitArray(n_rnl, K_A.rotated(n_rnl // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - n_rnl))), K_A, n_rnl // 4)
            sk_B = nl_fscx_revolve_v1(BitArray(n_rnl, K_B.rotated(n_rnl // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - n_rnl))), K_B, n_rnl // 4)
            if sk_A == sk_B: ok_sk += 1
        status = "PASS" if ok_raw == n_run else "FAIL"
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


def test_hpks_stern_f_correctness():
    print("[17] HPKS-Stern-F sign/verify correctness  [CODE-BASED PQC]")
    SDF_SIZES  = [32, 64, 128, 256]
    SDF_ROUNDS = 8        # reduced for speed; 219 needed for 128-bit soundness
    SDF_TRIALS = 20
    for size in SDF_SIZES:
        ok = 0; n_run = 0
        for _ in _trange(_iters(SDF_TRIALS)):
            n_run += 1
            sf_seed, sf_e, sf_syn = stern_f_keygen(size)
            msg = BitArray.random(size)
            sig = hpks_stern_f_sign(msg, sf_e, sf_seed, sf_syn, size, SDF_ROUNDS)
            if hpks_stern_f_verify(msg, sig, sf_seed, sf_syn, size):
                ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d} rounds={SDF_ROUNDS}  {ok:3d}/{n_run} verified  [{status}]")
    # Eve bypass: random signature should not verify
    size = 32; sf_seed, sf_e, sf_syn = stern_f_keygen(size)
    decoy = BitArray.random(size)
    fake_pi = BitArray.random(size); fake_r = _csprng_weight_t(size, max(2, size//16))  # SA-07
    fake_c0 = _stern_hash(size, fake_pi, BitArray(size, 0))
    fake_c1 = _stern_hash(size, BitArray(size, fake_r))
    fake_c2 = _stern_hash(size, BitArray(size, 0))
    fake_commits = [(fake_c0, fake_c1, fake_c2)] * SDF_ROUNDS
    fake_chal = [0] * SDF_ROUNDS
    fake_resp  = [(BitArray(size, fake_r), fake_r)] * SDF_ROUNDS
    eve_sig = (fake_commits, fake_chal, fake_resp)
    eve_ok = hpks_stern_f_verify(decoy, eve_sig, sf_seed, sf_syn, size)
    print(f"    Eve forge attempt: {'PASS (rejected)' if not eve_ok else 'FAIL (accepted!)'}")
    print()


def test_hpke_stern_f_correctness():
    print("[18] HPKE-Stern-F encap/decap correctness  [CODE-BASED PQC]")
    SDF_TRIALS_KEM = _iters(30)
    # N=32: brute-force decap (full decoder path; C(32,2)=496 candidates)
    size = 32; ok = 0; n_run = 0
    for _ in _trange(SDF_TRIALS_KEM):
        n_run += 1
        sf_seed, _sf_e, _sf_syn = stern_f_keygen(size)
        K_enc, ct = hpke_stern_f_encap(sf_seed, size)
        K_dec = hpke_stern_f_decap(ct, sf_seed, size)
        if K_dec is not None and K_dec == K_enc:
            ok += 1
    status = "PASS" if ok == n_run else "FAIL"
    print(f"    bits={size:3d}  brute-force decap  {ok:3d}/{n_run} agreed  [{status}]")
    # N=32,64,128,256: known-e' decap (verifies key derivation at all sizes)
    for size in [32, 64, 128, 256]:
        ok = 0; n_run = 0
        for _ in _trange(_iters(SDF_TRIALS_KEM)):
            n_run += 1
            sf_seed, _sf_e, _sf_syn = stern_f_keygen(size)
            K_enc, ct, e_p = hpke_stern_f_encap_with_e(sf_seed, size)
            K_dec = hpke_stern_f_decap_known(e_p, sf_seed, size)
            if K_dec == K_enc:
                ok += 1
        status = "PASS" if ok == n_run else "FAIL"
        print(f"    bits={size:3d}  known-e' decap     {ok:3d}/{n_run} agreed  [{status}]")
    print()


def test_hpks_stern_ring_correctness():
    N_SDF = 32; SDF_RING_ROUNDS = 4; RING_K = 3
    print(f"[20] HPKS-Stern-Ring correctness: OR-composition, k={RING_K}, N={N_SDF}, rounds={SDF_RING_ROUNDS}  [CODE-BASED RING SIG]")
    n_run = _iters(3); ok = 0
    for i in _trange(n_run):
        ring_keys = []; ring_errors = []
        for ki in range(RING_K):
            seed_i, e_i, syn_i = stern_f_keygen(N_SDF)
            ring_keys.append((seed_i, syn_i))
            ring_errors.append(e_i)
        j = i % RING_K
        e_j = ring_errors[j]
        msg = BitArray.random(N_SDF)
        sig = hpks_stern_ring_sign_local(msg, e_j, j, ring_keys, N_SDF, SDF_RING_ROUNDS)
        if hpks_stern_ring_verify_local(msg, sig, ring_keys, N_SDF):
            ok += 1
    status = "PASS" if ok == n_run else "FAIL"
    print(f"    {ok} / {n_run} ring-verified  [{status}]\n")


def test_hfscx_256():
    print("[19] HFSCX-256-DM hash — output length, known-answer, determinism, "
          "collision sanity, block boundaries, keyed MAC  [HASH]")

    # Known-answer tests (KAT) — pre-computed from the reference implementation
    KAT = [
        (b'',
         'e7082e7f038a6e32e480b5f1d969ea2c'
         '19565d327defb0f8500f6fac8fe246cc'),
        (b'a',
         '73b2d91bbdf0fc000de7cd16ac45d7f3'
         'f41be5609524dbeba30605a89d138ec5'),
        (b'abc',
         '394e2176329b94f4f6704730a01083be'
         'c51a49584bbb54abf05e5fa19cd05bb2'),
        (b'a' * 33,
         '49aee3b6126e44beff589d8288da6ec3'
         'f92f1f763368dfb85fb6b9664bc30adb'),
    ]
    kat_ok = True
    for msg, expected in KAT:
        got = hfscx_256(msg).hex()
        if got != expected:
            print(f"    KAT FAIL for {msg!r}: got {got}")
            kat_ok = False
    print(f"    Known-answer tests ({len(KAT)} vectors) [{'PASS' if kat_ok else 'FAIL'}]")

    # Output length: always 32 bytes regardless of input size
    len_ok = all(len(hfscx_256(b'\xaa' * sz)) == 32 for sz in [0, 1, 31, 32, 33, 63, 64, 65])
    print(f"    Output always 32 bytes [{'PASS' if len_ok else 'FAIL'}]")

    # Determinism: same input always gives same digest
    n_det = _iters(200)
    det_fail = 0
    for _ in _trange(n_det):
        data = os.urandom(random.randint(0, 128))
        if hfscx_256(data) != hfscx_256(data):
            det_fail += 1
    print(f"    Determinism: {n_det - det_fail}/{n_det} consistent "
          f"[{'PASS' if det_fail == 0 else 'FAIL'}]")

    # Collision sanity: distinct random inputs rarely collide
    n_coll = _iters(500)
    collisions = 0
    for _ in _trange(n_coll):
        a = os.urandom(random.randint(0, 64))
        b_bytes = os.urandom(random.randint(0, 64))
        if a != b_bytes and hfscx_256(a) == hfscx_256(b_bytes):
            collisions += 1
    print(f"    Collision sanity: {collisions}/{n_coll} collisions found "
          f"[{'PASS' if collisions == 0 else 'FAIL'}]")

    # Block boundary sensitivity: inputs near 32/64-byte boundaries produce different hashes
    boundary_ok = True
    for ref_len in [31, 32, 33, 63, 64, 65]:
        data = os.urandom(ref_len)
        if hfscx_256(data) == hfscx_256(data + b'\x00'):
            boundary_ok = False
    print(f"    Block boundary sensitivity [{'PASS' if boundary_ok else 'FAIL'}]")

    # Keyed MAC domain separation: keyed hash differs from bare hash and from other keys
    iv_const = int.from_bytes(_HFSCX256_IV_BYTES, 'big')
    mac_sep_ok = True
    same_key_ok = True
    for _ in range(50):
        data = os.urandom(random.randint(0, 64))
        key  = BitArray(256, int.from_bytes(os.urandom(32), 'big'))
        mac_iv = BitArray(256, key.uint ^ iv_const)
        bare   = hfscx_256(data)
        tag1   = hfscx_256(data, iv=mac_iv)
        tag2   = hfscx_256(data, iv=mac_iv)
        if bare == tag1:
            mac_sep_ok = False
        if tag1 != tag2:
            same_key_ok = False
    print(f"    Keyed MAC differs from bare hash [{'PASS' if mac_sep_ok else 'FAIL'}]")
    print(f"    Keyed MAC deterministic (same key) [{'PASS' if same_key_ok else 'FAIL'}]")
    print()


# ---------------------------------------------------------------------------
# Security tests [20]-[21]: ZKP-RNL and ZKP-NL
# ---------------------------------------------------------------------------

ZKP_MSG  = b"Herradura ZKP test"
ZKP_MSG2 = b"Herradura ZKP tamper"


def test_zkp_rnl_correctness():
    print("[21] ZKP-RNL Sigma-protocol completeness + tamper-rejection  [PQC-EXT]")
    for n in [32, 256]:
        N = _iters(5)
        ok_verify = 0; ok_tamper = 0; n_run = 0
        ok_wrongkey = 0; ok_wtamper = 0; ok_ztamper = 0
        m_base = _rnl_m_poly(n)
        for _ in _trange(N):
            n_run += 1
            a_rand  = _rnl_rand_poly(n, RNLQ)
            m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
            s, C    = _rnl_keygen(m_blind, n, RNLQ, RNLP)
            try:
                w, c, z = _rnl_sigma_sign(s, m_blind, C, n, ZKP_MSG)
            except RuntimeError:
                n_run -= 1; continue
            if _rnl_sigma_verify(m_blind, C, n, ZKP_MSG, w, c, z):
                ok_verify += 1
            if not _rnl_sigma_verify(m_blind, C, n, ZKP_MSG2, w, c, z):
                ok_tamper += 1
            # Structured cheats (TODO #94):
            # (a) wrong-key witness: honest signer algorithm run with a fresh
            #     s' != s against the original public key C — must not verify.
            s2, _C2 = _rnl_keygen(m_blind, n, RNLQ, RNLP)
            try:
                w2, c2, z2 = _rnl_sigma_sign(s2, m_blind, C, n, ZKP_MSG)
                if not _rnl_sigma_verify(m_blind, C, n, ZKP_MSG, w2, c2, z2):
                    ok_wrongkey += 1
            except RuntimeError:
                ok_wrongkey += 1   # rejection-limit on a wrong key is also a reject
            # (b) tampered commitment w — must fail Fiat-Shamir re-derivation.
            w_t = list(w); w_t[0] += 1
            if not _rnl_sigma_verify(m_blind, C, n, ZKP_MSG, w_t, c, z):
                ok_wtamper += 1
            # (c) perturbed response z (FS check still passes; the residual
            #     norm check must catch it).
            z_t = list(z); z_t[0] += 1
            if not _rnl_sigma_verify(m_blind, C, n, ZKP_MSG, w, c, z_t):
                ok_ztamper += 1
        all_ok = (ok_verify == n_run and ok_tamper == n_run and
                  ok_wrongkey == n_run and ok_wtamper == n_run and
                  ok_ztamper == n_run)
        status = "PASS" if all_ok else "FAIL"
        print(f"    n={n:3d}  verify={ok_verify}/{n_run}  tamper_reject={ok_tamper}/{n_run}"
              f"  wrongkey_reject={ok_wrongkey}/{n_run}"
              f"  w_tamper={ok_wtamper}/{n_run}  z_tamper={ok_ztamper}/{n_run}"
              f"  [{status}]")
    print()


def test_zkp_nl_correctness():
    print("[22] ZKP-NL (ZKBoo) completeness + tamper-rejection  [PQC-EXT]")
    zkp_nl_rounds = 16
    for n in [32, 64]:
        N = _iters(5)
        ok_verify = 0; ok_tamper = 0; n_run = 0
        for _ in _trange(N):
            n_run += 1
            A, B, y = _zkp_nl_keygen(n)
            proof = _zkp_nl_prove(A, B, y, n, zkp_nl_rounds, ZKP_MSG)
            if _zkp_nl_verify(B, y, n, zkp_nl_rounds, ZKP_MSG, proof):
                ok_verify += 1
            # tamper: flip one bit in com_1[0]
            tampered = [dict(r) for r in proof]
            c1 = bytearray(tampered[0]['com_1'])
            c1[0] ^= 1
            tampered[0] = dict(tampered[0])
            tampered[0]['com_1'] = bytes(c1)
            if not _zkp_nl_verify(B, y, n, zkp_nl_rounds, ZKP_MSG, tampered):
                ok_tamper += 1
        status = "PASS" if (ok_verify == n_run and ok_tamper == n_run) else "FAIL"
        print(f"    n={n:2d}  rounds={zkp_nl_rounds}  verify={ok_verify}/{n_run}"
              f"  tamper_reject={ok_tamper}/{n_run}  [{status}]")
    print()


# Security tests [22]-[24]: FPE / Tweakable / Accumulator (78.A/B/J)
# ---------------------------------------------------------------------------

def test_fpe_correctness():
    print("[23] FPE (78.A) encrypt→decrypt round-trip  [NEW]")
    N = _iters(1000); ok = 0; n_run = 0
    for _ in _trange(N):
        n_run += 1
        P   = BitArray.random(_KEYBITS)
        key = BitArray.random(_KEYBITS).bytes
        ctx = BitArray.random(64).bytes
        C = fpe_encrypt_test(P, key, ctx)
        D = fpe_decrypt_test(C, key, ctx)
        if D.uint == P.uint:
            ok += 1
    status = "PASS" if ok == n_run else "FAIL"
    print(f"    {ok} / {n_run} round-trips correct  [{status}]")
    print()


def test_twk_correctness():
    print("[24] Tweakable wide-block cipher (78.B) encrypt→decrypt round-trip  [NEW]")
    N = _iters(1000); ok = 0; n_run = 0
    for _ in _trange(N):
        n_run += 1
        P      = BitArray.random(_KEYBITS)
        key    = BitArray.random(_KEYBITS).bytes
        sector = random.getrandbits(64)
        bidx   = random.getrandbits(32)
        C = twk_encrypt_test(P, key, sector, bidx)
        D = twk_decrypt_test(C, key, sector, bidx)
        if D.uint == P.uint:
            ok += 1
    status = "PASS" if ok == n_run else "FAIL"
    print(f"    {ok} / {n_run} round-trips correct  [{status}]")
    print()


def test_accumulator_correctness():
    print("[25] Cryptographic Accumulator (78.J) — Merkle proof  [NEW]")
    sizes = [1, 2, 4, 8, 16]
    total = ok_valid = ok_reject = 0
    for n in sizes:
        leaves = [haccum_leaf_test(BitArray.random(64).bytes) for _ in range(n)]
        root   = haccum_root_test(leaves)
        for idx in range(n):
            proof = haccum_prove_test(leaves, idx)
            if haccum_verify_test(root, leaves[idx], proof, idx):
                ok_valid += 1
            # tamper: flip a byte in the first sibling hash
            if proof:
                tampered = [bytearray(s) for s in proof]
                tampered[0][0] ^= 0xFF
                tampered_list = [bytes(s) for s in tampered]
                if not haccum_verify_test(root, leaves[idx], tampered_list, idx):
                    ok_reject += 1
            else:
                ok_reject += 1  # n=1: empty proof, tamper not applicable
            total += 1
    status = "PASS" if ok_valid == total and ok_reject == total else "FAIL"
    print(f"    valid={ok_valid}/{total}  tamper_reject={ok_reject}/{total}  [{status}]")
    print()


def test_masked_hske():
    print("[26] Masked HSKE (78.H) — GF(2)-linearity masking correctness  [NEW]")
    N = _iters(200)
    ok = 0; n_run = 0
    for _ in _trange(N):
        n_run += 1
        pt   = BitArray.random(_KEYBITS)
        key  = BitArray.random(_KEYBITS)
        mask = BitArray.random(_KEYBITS)
        ct  = fscx_revolve_masked_test(pt,  key, mask, _I_VALUE)
        rec = fscx_revolve_masked_test(ct,  key, mask, _R_VALUE)
        if rec.uint == pt.uint:
            ok += 1
    status = "PASS" if ok == n_run else "FAIL"
    print(f"    round-trips={ok}/{n_run}  [{status}]")
    # linearity check: F(A⊕r,B,n) ⊕ F(r,0,n) == F(A,B,n)
    zero = BitArray(_KEYBITS, 0)
    lin_ok = 0
    for _ in range(min(N, 100)):
        A  = BitArray.random(_KEYBITS)
        B  = BitArray.random(_KEYBITS)
        r  = BitArray.random(_KEYBITS)
        direct   = fscx_revolve(A, B, _I_VALUE)
        am       = BitArray(_KEYBITS, A.uint ^ r.uint)
        masked   = BitArray(_KEYBITS,
                            fscx_revolve(am, B, _I_VALUE).uint ^ fscx_revolve(r, zero, _I_VALUE).uint)
        if masked.uint == direct.uint:
            lin_ok += 1
    lin_status = "PASS" if lin_ok == min(N, 100) else "FAIL"
    print(f"    linearity={lin_ok}/{min(N, 100)}  [{lin_status}]")
    print()


def test_ratchet_forward_secrecy():
    print("[27] Ratchet (78.C) — forward secrecy & key uniqueness  [NEW]")
    steps = min(_iters(20), 20)
    seeds_tested = 5; all_ok = True
    for trial in range(seeds_tested):
        seed  = f"test-seed-{trial}".encode()
        state = ratchet_init_test(seed)
        keys  = []
        for _ in range(steps):
            state, mk = ratchet_advance_test(state)
            keys.append(mk)
        if len(set(keys)) < len(keys):
            all_ok = False
            print(f"    trial {trial}: duplicate message key!")
    # forward secrecy: two seeds must not converge in <steps
    state1 = ratchet_init_test(b"seed-alice")
    state2 = ratchet_init_test(b"seed-bob")
    diverge = True
    for _ in range(steps):
        state1, _ = ratchet_advance_test(state1)
        state2, _ = ratchet_advance_test(state2)
        if state1.uint == state2.uint:
            diverge = False
    status = "PASS" if all_ok and diverge else "FAIL"
    print(f"    key_uniqueness={'PASS' if all_ok else 'FAIL'}  "
          f"divergence={'PASS' if diverge else 'FAIL'}  [{status}]")
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
    print("[28] FSCX throughput  [CLASSICAL]")
    for size in SIZES:
        a = BitArray.random(size); b = BitArray.random(size)
        def fn():
            nonlocal a; a = fscx(a, b)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hkex_gf_pow():
    print("[29] HKEX-GF gf_pow throughput  [CLASSICAL]")
    for size in GF_SIZES:
        poly = GF_POLY.get(size, 0x00000425); a = BitArray.random(size)
        def fn(a=a, poly=poly, size=size):
            return gf_pow(GF_GEN, a.uint, poly, size)
        _bench(f"bits={size:3d}  gf_pow(g, a)", fn)
    print()


def bench_hkex_handshake():
    print("[30] HKEX-GF full handshake (4 gf_pow calls)  [CLASSICAL]")
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
    print("[31] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
    for size in SIZES:
        iv = i_val(size); rv = r_val(size); sink = BitArray(size, 0)
        def fn():
            nonlocal sink
            pt = BitArray.random(size); key = BitArray.random(size)
            sink ^= fscx_revolve(fscx_revolve(pt, key, iv), key, rv) ^ pt
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hpke_roundtrip():
    print("[32] HPKE encrypt+decrypt round-trip (El Gamal + fscx_revolve)  [CLASSICAL]")
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
    print("[33] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); a = BitArray.random(size); b = BitArray.random(size)
        def fn():
            nonlocal a; a = nl_fscx_revolve_v1(a, b, iv)
        _bench(f"bits={size:3d}  v1 n/4 steps", fn)
    print("[33b] NL-FSCX v2 revolve+inv throughput (r_val steps)  [PQC-EXT]")
    for size in SIZES:
        rv = r_val(size); a = BitArray.random(size); b = BitArray.random(size)
        def fn(size=size, rv=rv, b=b):
            nonlocal a; E = nl_fscx_revolve_v2(a, b, rv); a = nl_fscx_revolve_v2_inv(E, b, rv)
        _bench(f"bits={size:3d}  v2 enc+dec r_val", fn)
    print()


def bench_hske_nl_a1_roundtrip():
    print("[34] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
    for size in SIZES:
        iv = i_val(size); sink = BitArray(size, 0)
        def fn(size=size, iv=iv):
            nonlocal sink
            K    = BitArray.random(size); P = BitArray.random(size)
            N    = BitArray.random(size)
            base = BitArray(size, K.uint ^ N.uint)
            B    = BitArray(size, base.uint ^ 0)  # counter=0
            ks   = nl_fscx_revolve_v1(BitArray(size, base.rotated(size // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - size))), B, iv)
            sink ^= BitArray(size, P.uint ^ ks.uint)
        _bench(f"bits={size:3d}", fn)
    print()


def bench_hske_nl_a2_roundtrip():
    print("[35] HSKE-NL-A2 revolve-mode round-trip  [PQC-EXT]")
    for size in SIZES:
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
    print("[36] HKEX-RNL handshake throughput  [PQC-EXT]")
    print(f"     (ring sizes {RNL_SIZES}; n^2 poly-mul — O(n^2) per exchange)")
    for n_rnl in RNL_SIZES:
        m_base = _rnl_m_poly(n_rnl)
        def fn(n_rnl=n_rnl, m_base=m_base):
            a_rand  = _rnl_rand_poly(n_rnl, RNLQ)
            m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
            s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP)
            _, hint_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, n_rnl)
            _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, n_rnl, hint_A)
        _bench(f"n={n_rnl:3d}  full exchange", fn)
    print()


def bench_hpks_stern_f():
    print("[37] HPKS-Stern-F sign+verify throughput (N=n, rounds=4)  [CODE-BASED PQC]")
    rounds = 4; sink = [True]
    for size in SIZES:
        sf_seed, sf_e, sf_syn = stern_f_keygen(size)
        msg = BitArray.random(size)
        def fn(s=size, se=sf_seed, e=sf_e, sy=sf_syn, ms=msg):
            sig = hpks_stern_f_sign(ms, e, se, sy, s, rounds)
            sink[0] = hpks_stern_f_verify(ms, sig, se, sy, s)
        _bench(f"bits={size:3d} rounds={rounds}  sign+verify", fn)
    print()


def bench_zkp_rnl():
    n = 256
    print(f"[38] ZKP-RNL sign+verify throughput  (n={n})  [PQC-EXT]")
    m_base  = _rnl_m_poly(n)
    a_rand  = _rnl_rand_poly(n, RNLQ)
    m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
    s, C    = _rnl_keygen(m_blind, n, RNLQ, RNLP)
    def fn():
        try:
            w, c, z = _rnl_sigma_sign(s, m_blind, C, n, ZKP_MSG)
            _rnl_sigma_verify(m_blind, C, n, ZKP_MSG, w, c, z)
        except RuntimeError:
            pass
    _bench(f"n={n:3d}  sign+verify", fn)
    print()


def bench_zkp_nl():
    n = 32; rounds = 16
    print(f"[39] ZKP-NL prove+verify throughput  (n={n}, rounds={rounds})  [PQC-EXT]")
    A, B, y = _zkp_nl_keygen(n)
    def fn():
        proof = _zkp_nl_prove(A, B, y, n, rounds, ZKP_MSG)
        _zkp_nl_verify(B, y, n, rounds, ZKP_MSG, proof)
    _bench(f"n={n:2d}  rounds={rounds}  prove+verify", fn)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # --- Arg parsing (CLI overrides env vars) ---
    parser = argparse.ArgumentParser(
        description="Herradura KEx v1.9.32 — Security & Performance Tests (Python)",
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

    print("=== Herradura KEx v1.9.32 \u2014 Security & Performance Tests (Python) ===")
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

    print("--- Security Tests: Code-Based PQC (Stern-F) ---\n")
    test_hpks_stern_f_correctness()
    test_hpke_stern_f_correctness()

    print("--- Security Tests: Hash (HFSCX-256) ---\n")
    test_hfscx_256()

    print("--- Security Tests: Code-Based PQC (Ring Signatures) ---\n")
    test_hpks_stern_ring_correctness()

    print("--- Security Tests: ZKP (Ring-LWR Sigma + NL-FSCX ZKBoo) ---\n")
    test_zkp_rnl_correctness()
    test_zkp_nl_correctness()

    print("--- Security Tests: FPE / Tweakable / Accumulator (78.A/B/J) ---\n")
    test_fpe_correctness()
    test_twk_correctness()
    test_accumulator_correctness()

    print("--- Security Tests: Masking / Ratchet (78.H/C) ---\n")
    test_masked_hske()
    test_ratchet_forward_secrecy()

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
    bench_hpks_stern_f()
    bench_zkp_rnl()
    bench_zkp_nl()
