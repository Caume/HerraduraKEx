'''
    Herradura Cryptographic Suite v1.9.16

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

    --- v1.9.16: HPKS-Stern-Ring — OR-composed Stern ring signature (TODO #78.I) ---
    --- v1.8.0: KDF domain constant — seed = ROL(K,n/8) XOR _RNL_KDF_DC_256 for HSKE-NL-A1 and HKEX-RNL (TODO #38) ---
    --- v1.7.3: NumPy NTT acceleration — ~10× speedup on _rnl_poly_mul (TODO #40) ---
    --- v1.5.41: rnl_lift centered rounding across all targets (TODO #37) ---
    --- v1.5.40: Constant-time audit — branchless stern_apply_perm + non-CT docs (TODO #41) ---
    --- v1.5.23: HerraduraCli — OpenSSL-style Python CLI (TODO #25); CliTest shell test suite ---
    --- v1.5.20: HPKE-Stern-F N=256 known-e' demo; multi-size standardization ---
    --- v1.5.18: HPKS-Stern-F / HPKE-Stern-F — code-based PQC (SD + NL-FSCX v1 PRF) ---

    Adds HPKS-Stern-F (Stern identification + Fiat-Shamir, §11.8.4) and HPKE-Stern-F
    (Niederreiter KEM). Security of HPKS-Stern-F reduces to SD(N,t) [NP-complete,
    BMvT 1978] plus NL-FSCX v1 PRF — the only complete chain to a studied hard
    problem in the suite (Theorem 17, SecurityProofs-2.md §11.8.4).
    Replaces the GF(2^n)* discrete-log base that Shor's algorithm breaks in HPKS-NL
    and HPKE-NL.  Parameters: N=n, n_rows=n/2, t=n/16 (16 at n=256), SDFR=32 rounds
    (demo; production requires ≥219 for 128-bit soundness).

    --- v1.5.13: HSKE-NL-A1 seed fix — ROL(base, n/8) breaks counter=0 step-1 degeneracy ---

    HSKE-NL-A1 keystream: seed = base.rotated(n/8); ks = nl_fscx_revolve_v1(seed, base^ctr, n/4).
    When A=B=base (counter=0), fscx(base,base)=0 so step 1 was a pure rotation (linear).
    ROL(base,n/8) ensures seed!=base, activating full carry non-linearity from step 1.
    Same degeneracy pattern fixed for HKEX-RNL KDF in v1.5.10; now applied consistently.

    --- v1.5.10: HKEX-RNL KDF seed fix — ROL(K, n/8) breaks step-1 degeneracy ---

    HKEX-RNL KDF now derives the initial state as seed = ROL(K, n/8) instead of
    using K directly:
      seed = ROL(K, n/8)
      sk   = nl_fscx_revolve_v1(seed, K, n/4)
    When A0 = B = K, fscx(K,K) = 0, making step 1 a pure rotation (linear in K).
    ROL(K, n/8) ensures seed != K, so fscx(seed, K) != 0 and full non-linear carry
    mixing is active from the very first step.

    --- v1.5.9: HSKE-NL-A1 per-session nonce; nl_fscx_revolve_v2_inv delta precompute ---

    HSKE-NL-A1 now generates a random per-session nonce N and derives the session
    key base as K XOR N (transmitted alongside ciphertext).  Eliminates keystream
    reuse when the same long-term key K is used across sessions.

    nl_fscx_revolve_v2_inv precomputes delta(B) once before the loop; loop body:
    z = y - delta; y = B XOR _m_inv(z).  Eliminates per-step multiply-and-rotate.

    --- v1.5.7: precomputed M^{-1} for nl_fscx_v2_inv ---

    _m_inv now computes the rotation table for M^{-1} = M^{n/2-1} once on first call
    (bootstrapping from fscx_revolve(1, 0, n/2-1)), caches it per bit-size, then applies
    M^{-1}(X) as XOR of ROL(X,k) for each k in the table.  Reduces each inverse step
    from n/2-1 FSCX iterations to ~2n/3 XOR-rotation pairs.

    --- v1.5.6: rnl_rand_poly bias fix — 3-byte rejection sampling ---

    _rnl_rand_poly now uses 24-bit rejection sampling (threshold = (1<<24) - (1<<24)%q)
    to eliminate the ~1/2^32 modular bias introduced by the previous 4-byte draw.

    --- v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)) ---

    _rnl_poly_mul now uses a Cooley-Tukey NTT over Z_{65537} (a Fermat prime, 2^16+1)
    with a negacyclic twist (ψ = 3^((q-1)/(2n)), primitive 2n-th root of unity).
    Replaces the O(n²) schoolbook multiply: ~32× speedup at n=256.

    --- v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1) ---

    HKEX-RNL secret polynomial now uses a centered binomial distribution CBD(eta=1)
    instead of the previous uniform {0,1} sampler.  CBD(1) produces coefficients in
    {-1, 0, 1} with zero mean and probabilities {1/4, 1/2, 1/4}, matching the Kyber
    baseline for proper Ring-LWR hardness.  The max coefficient magnitude is unchanged
    (1), so the noise budget and parameter set are unaffected.

    --- v1.5.0: NL-FSCX non-linear extension and PQC protocols ---

    Adds two NL-FSCX primitives and five PQC-hardened protocol variants
    alongside the existing classical (non-PQC) algorithms (kept for reference).

    NL-FSCX v1:  nl_fscx_v1(A,B) = fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
      Injects integer-carry non-linearity.  Not bijective in A — for one-way
      use only (counter-mode HSKE, HKEX KDF, HPKS challenge hash).

    NL-FSCX v2:  nl_fscx_v2(A,B) = (fscx(A,B) + ROL(B*(B+1)//2, n/4)) mod 2^n
      B-only additive offset; bijective in A with closed-form inverse.
      Used for revolve-mode HSKE and HPKE where decryption is required.

    PQC protocol variants (C3 hybrid assignment):
      HSKE-NL-A1  — counter-mode HSKE with NL-FSCX v1 keystream
      HSKE-NL-A2  — revolve-mode HSKE with NL-FSCX v2 (invertible)
      HKEX-RNL    — Ring-LWR key exchange (quantum-resistant; replaces HKEX-GF)
      HPKS-NL     — Schnorr with NL-FSCX v1 challenge (linear preimage hardened)
      HPKE-NL     — El Gamal with NL-FSCX v2 encryption/decryption

    Classical protocols (not PQC — kept for reference and comparison):
      HKEX-GF     — Diffie-Hellman over GF(2^n)* (broken by Shor's algorithm)
      HSKE        — fscx_revolve symmetric encryption (linear key recovery)
      HPKS        — Schnorr with fscx_revolve challenge (linear challenge)
      HPKE        — El Gamal + fscx_revolve (linear encryption)

    --- v1.4.0: HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The broken fscx_revolve_n-based HKEX is replaced with HKEX-GF: a correct
    Diffie-Hellman key exchange over the multiplicative group GF(2^n)*.

    HKEX-GF protocol:
    - Pre-agreed: generator g=3 (polynomial x+1), irreducible poly p(x)
    - Alice: private scalar a -> public C = g^a in GF(2^n)*
    - Bob:   private scalar b -> public C2 = g^b
    - Shared key: sk = C2^a = C^b = g^{ab}  (DH commutativity in GF(2^n)*)
    Security rests on the hardness of DLP in GF(2^n)*, not on orbit structure.
    NOTE: DLP in GF(2^n)* is vulnerable to Shor's algorithm on quantum computers.

    --- v1.3.2: performance and readability ---
    --- v1.3: BitArray (multi-byte parameter support) ---

    Library usage
    ─────────────
    This file is importable as a Python module.  Because the filename contains
    spaces, use importlib to load it:

        import importlib.util, pathlib
        _spec = importlib.util.spec_from_file_location(
            "herradura",
            pathlib.Path(__file__).parent / "Herradura cryptographic suite.py")
        h = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(h)

    Public API (no underscore prefix):
        BitArray, fscx, fscx_revolve
        gf_mul, gf_pow
        nl_fscx_v1, nl_fscx_revolve_v1
        nl_fscx_v2, nl_fscx_v2_inv, nl_fscx_revolve_v2, nl_fscx_revolve_v2_inv
        hfscx_256
        stern_f_keygen, hpks_stern_f_sign, hpks_stern_f_verify
        hpke_stern_f_encap, hpke_stern_f_decap
        hkex_rnl_keygen, hkex_rnl_agree  (public aliases added in v1.7.4)
        rnl_sigma_sign, rnl_sigma_verify  (ZKP-RNL: Ring-LWR Σ-protocol)
        zkp_nl_keygen, zkp_nl_prove, zkp_nl_verify  (ZKP-NL: NL-FSCX ZKBoo)

    Key module constants: KEYBITS, I_VALUE, R_VALUE, GF_POLY, GF_GEN, ORD,
        RNLQ, RNLP, RNLPP, RNLB, SDFNR, SDFT, SDFR.

    See docs/TUTORIAL.md for complete per-protocol code examples.
'''

import itertools
import math
import os
import random
import warnings

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
# Global parameters
# ---------------------------------------------------------------------------

# Key size in bits — must be a positive multiple of 8.
# Change to use a different parameter width; I_VALUE and R_VALUE scale automatically.
KEYBITS = 256
I_VALUE = KEYBITS // 4       # 64  for 256-bit
R_VALUE = 3 * KEYBITS // 4   # 192 for 256-bit
ORD     = (1 << KEYBITS) - 1  # order of GF(2^n)* (for Schnorr integer arithmetic)

# HKEX-RNL Ring-LWR parameters (see SecurityProofs-2.md §11.4)
# q=65537 (Fermat prime, fast arithmetic) gives lower noise-to-margin ratio than
# q=3329 (Kyber), ensuring reliable single-block agreement at the cost of larger
# keys.  2-bit Peikert reconciliation doubles extracted bits per coefficient.
RNLQ  = 65537  # prime modulus (2^16 + 1)
RNLP  = 4096   # public-key rounding modulus
RNLPP = 4      # reconciliation modulus (2 bits extracted per ring coefficient)
RNLB  = 1      # centered-binomial eta=1: secret coefficients drawn from CBD(1) in {-1,0,1}

# HPKS-Stern-F / HPKE-Stern-F code-based PQC parameters (SecurityProofs-2.md §11.8.4)
SDFNR = KEYBITS // 2           # parity-check rows (syndrome bits; [N, N/2, t] code, N=KEYBITS)
SDFT  = max(2, KEYBITS // 16)  # error weight t (= 16 at n=256; ≥ 2 at all widths)
SDFR  = 32                     # ⚠ DEMO ONLY: Fiat-Shamir rounds (~19-bit soundness).
                               # Production deployments MUST use rounds ≥ 219 for
                               # 128-bit soundness (⌈λ / log2(3/2)⌉ at λ=128).
                               # Signing emits a RuntimeWarning when called below
                               # the production threshold.

# ZKP-RNL (Ring-LWR Σ-protocol) parameters (SecurityProofs-3.md §11.10.2)
_SIGMA_GAMMA        = {32: 4096, 64: 8192, 128: 8192, 256: 8192}  # mask bound γ per n
_SIGMA_T            = {32: 4,    64: 8,    128: 12,   256: 16}     # challenge weight t per n
_SIGMA_MAX_ATTEMPTS = 1000   # rejection-sampling attempts before RuntimeError

# ZKBoo (NL-FSCX MPC-in-the-head) parameters (SecurityProofs-3.md §11.10.3)
_ZKP_NL_DEFAULT_N   = 8    # default bit-width for CLI (proof ≈35 KB at R=219)
_ZKP_NL_DEMO_ROUNDS = 4    # illustration only: soundness ≈ (2/3)^4 ≈ 20%
_ZKP_NL_PROD_ROUNDS = 219  # ⌈128 / log₂(3/2)⌉ — required for 128-bit soundness


# ---------------------------------------------------------------------------
# BitArray class
# ---------------------------------------------------------------------------

class BitArray:
    """Fixed-width bit string backed by a Python int.
    Supports XOR, rotation, equality, and hex/bytes/uint I/O.
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


# ---------------------------------------------------------------------------
# FSCX functions (classical — linear map M = I + ROL + ROR over GF(2))
# ---------------------------------------------------------------------------

def fscx(A: BitArray, B: BitArray) -> BitArray:
    """Full Surroundings Cyclic XOR: A ^ B ^ ROL(A) ^ ROL(B) ^ ROR(A) ^ ROR(B).
    Uses rotated() — does not mutate its inputs."""
    return A ^ B ^ A.rotated(1) ^ B.rotated(1) ^ A.rotated(-1) ^ B.rotated(-1)


def fscx_revolve(A: BitArray, B: BitArray, steps: int, verbose: bool = False) -> BitArray:
    result = A.copy()
    for step in range(steps):
        result = fscx(result, B)
        if verbose:
            print(f"Step {step + 1}: {result.hex}")
    return result


# ---------------------------------------------------------------------------
# GF(2^n) field arithmetic — XOR + left-shift only (classical)
# ---------------------------------------------------------------------------
# Primitive polynomials (lower n bits; the x^n coefficient is implicit).
GF_POLY = {32: 0x00400007, 64: 0x0000001B, 128: 0x00000087, 256: 0x00000425}
GF_GEN  = 3   # g = x+1 in GF(2^n)[x]; DH correctness holds for any non-zero g

def gf_mul(a: int, b: int, poly: int, n: int) -> int:
    """Carryless polynomial multiply mod p(x) in GF(2^n). O(n) XOR+shift ops."""
    result = 0; mask = (1 << n) - 1; hb = 1 << (n - 1)
    for _ in range(n):
        if b & 1: result ^= a
        carry = bool(a & hb)
        a = (a << 1) & mask
        if carry: a ^= poly
        b >>= 1
    return result

def gf_pow(base: int, exp: int, poly: int, n: int) -> int:
    """base^exp in GF(2^n)* via repeated squaring.
    SA-02/06: iterates exactly n times — no early exit on leading zero bits of
    exp so loop count does not leak exp's bit-length. Residual per-bit branch
    is a known Python/arbitrary-precision int limitation."""
    result = 1; base &= (1 << n) - 1
    for _ in range(n):               # fixed n iterations
        if exp & 1: result = gf_mul(result, base, poly, n)
        base = gf_mul(base, base, poly, n)
        exp >>= 1
    return result


# ---------------------------------------------------------------------------
# NL-FSCX primitives (v1.5.0 — non-linear; for PQC-hardened protocols)
# ---------------------------------------------------------------------------

# Rotation-table cache: maps bit-size n to tuple of rotation offsets k such that
# M^{-1}(X) = XOR of ROL(X, k) for k in the tuple.  Populated lazily on first call.
_m_inv_rotations: dict[int, tuple[int, ...]] = {}

def _m_inv(X: BitArray) -> BitArray:
    """M^{-1}(X): apply precomputed rotation table for M^{n/2-1}.
    Table is bootstrapped once from fscx_revolve(1, 0, n/2-1) and cached per bit-size."""
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
    """NL-FSCX v1: injects integer-carry non-linearity from A+B into FSCX.

    nl_fscx_v1(A,B) = fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)

    Properties: non-linear over GF(2); NOT bijective in A (collisions exist).
    Use for: HSKE counter-mode keystream, HKEX-RNL KDF, HPKS-NL challenge hash.
    """
    n   = A._size
    mix = BitArray(n, (A.uint + B.uint) & A._mask)
    return fscx(A, B) ^ mix.rotated(n // 4)


def nl_fscx_revolve_v1(A: BitArray, B: BitArray, steps: int) -> BitArray:
    """Iterate nl_fscx_v1 *steps* times (B held constant)."""
    result = A.copy()
    for _ in range(steps):
        result = nl_fscx_v1(result, B)
    return result


def nl_fscx_v2(A: BitArray, B: BitArray) -> BitArray:
    """NL-FSCX v2: B-only additive offset; bijective in A with closed-form inverse.

    delta(B) = ROL(B * floor((B+1)/2) mod 2^n, n/4)
    nl_fscx_v2(A,B) = (fscx(A,B) + delta(B)) mod 2^n

    Properties: non-linear over GF(2); bijective in A for all B; exact inverse.
    Use for: HSKE revolve-mode encryption/decryption, HPKE-NL encryption.
    """
    n     = A._size
    mask  = A._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    return BitArray(n, (fscx(A, B).uint + delta.uint) & mask)


def nl_fscx_v2_inv(Y: BitArray, B: BitArray) -> BitArray:
    """Exact inverse of one nl_fscx_v2 step: A = B XOR M^{-1}((Y - delta(B)) mod 2^n).

    Derivation: Y = M(A XOR B) + delta(B)  =>  A XOR B = M^{-1}(Y - delta(B))
    Applying M^{-1} = M^{n/2-1} recovers A XOR B, then XOR with B gives A.
    """
    n     = Y._size
    mask  = Y._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    Z     = BitArray(n, (Y.uint - delta.uint) & mask)
    return B ^ _m_inv(Z)


def nl_fscx_revolve_v2(A: BitArray, B: BitArray, steps: int) -> BitArray:
    """Iterate nl_fscx_v2 *steps* times (B held constant).

    delta(B) is precomputed once before the loop (mirrors nl_fscx_revolve_v2_inv);
    the inner step body becomes one fscx + one integer add. Saves one bigint
    multiply and one rotation per iteration vs. calling nl_fscx_v2 in the loop.
    """
    n     = A._size
    mask  = A._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    result = A.copy()
    for _ in range(steps):
        result = BitArray(n, (fscx(result, B).uint + delta.uint) & mask)
    return result


def nl_fscx_revolve_v2_inv(Y: BitArray, B: BitArray, steps: int) -> BitArray:
    """Invert nl_fscx_revolve_v2: apply nl_fscx_v2_inv *steps* times.
    delta(B) is precomputed once — B is constant throughout the revolve."""
    n     = Y._size
    mask  = Y._mask
    delta = BitArray(n, (B.uint * ((B.uint + 1) >> 1)) & mask).rotated(n // 4)
    result = Y.copy()
    for _ in range(steps):
        z      = BitArray(n, (result.uint - delta.uint) & mask)
        result = B ^ _m_inv(z)
    return result


# ---------------------------------------------------------------------------
# HFSCX-256-DM: Merkle-Damgård hash over NL-FSCX v1, Davies-Meyer compression (v1.9.0)
# ---------------------------------------------------------------------------

# 32-byte ASCII domain constant for the default IV.
_HFSCX256_IV_BYTES = b'HFSCX-256/HERRADURA-SUITE\x00\x00\x00\x00\x00\x00\x00'

# NUMS constant for KDF domain separation (SHA-256 initial hash values H0..H7
# concatenated as big-endian 32-bit words).  For n<256 use top n bits.
# Prevents KDF degeneracy when K is rotation-periodic (TODO #38, v1.8.0).
_RNL_KDF_DC_256 = 0x6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19


def hfscx_256(data: bytes, *, iv: BitArray | None = None) -> bytes:
    """HFSCX-256-DM: 256-bit Merkle-Damgård hash built on NL-FSCX v1, Davies-Meyer compression.

    Compression function (Davies-Meyer):
        state_{i+1} = nl_fscx_revolve_v1(state_i, block_i, 64) ⊕ state_i

    Padding (ISO 7816-4 + Merkle-Damgård strengthening):
        1. Append 0x80 to the message.
        2. Zero-fill until total length is a multiple of 32 bytes.
        3. Append a final 32-byte block: (bit_length_64bit XOR init_state)
           where init_state is the initial chaining value (IV or key^IV).
           XORing the initial state into the length block binds the key into
           the last block's content, preventing fixed-point collapse when the
           message compresses all initial chaining states to a single value
           (which occurs for empty input with B=0 in the length block).

    Bare hash:  iv=None  — initial state is the domain IV constant.
    Keyed MAC:  pass iv = BitArray(256, key.uint ^
                                   int.from_bytes(_HFSCX256_IV_BYTES,'big'))
                The key is incorporated into both the initial chaining state
                and the final length block, so different keys always produce
                different outputs even for empty input.

    Returns 32 bytes (256-bit digest).
    """
    n    = 256
    blen = 32  # bytes per block
    iv_int   = int.from_bytes(_HFSCX256_IV_BYTES, 'big')
    init_int = iv_int if iv is None else iv.uint
    state    = BitArray(n, init_int)

    # Padding: 0x80, then zeros to reach a multiple of 32 bytes
    padded = bytearray(data) + b'\x80'
    rem = len(padded) % blen
    if rem:
        padded += b'\x00' * (blen - rem)

    # MD-strengthening: length block XOR'd with the initial state to bind the
    # key into the final block and prevent fixed-point collapse on short inputs.
    len_raw  = int.from_bytes(b'\x00' * (blen - 8) + (len(data) * 8).to_bytes(8, 'big'), 'big')
    padded  += (len_raw ^ init_int).to_bytes(blen, 'big')

    # Chain blocks: C_DM(s, m) = F_1^{64}(s, m) ⊕ s (Davies-Meyer feed-forward)
    steps = n // 4  # 64
    for off in range(0, len(padded), blen):
        prev = state
        block = BitArray(n, int.from_bytes(padded[off:off + blen], 'big'))
        state = nl_fscx_revolve_v1(state, block, steps)
        state = BitArray(n, state.uint ^ prev.uint)

    return state.uint.to_bytes(blen, 'big')


# ---------------------------------------------------------------------------
# HKEX-RNL ring-arithmetic helpers (negacyclic Z_q[x]/(x^n+1))
# ---------------------------------------------------------------------------

def _ntt_inplace(a, q, invert):
    """Cooley-Tukey iterative NTT over Z_q (in-place). len(a) must be a power of 2.
    Uses primitive root 3; works for q=65537 (Fermat prime, ord(3)=2^16=q-1)."""
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    length = 2
    while length <= n:
        w = pow(3, (q - 1) // length, q)
        if invert:
            w = pow(w, q - 2, q)
        for i in range(0, n, length):
            wn = 1
            for k in range(length >> 1):
                u = a[i + k]
                v = a[i + k + (length >> 1)] * wn % q
                a[i + k]              = (u + v) % q
                a[i + k + (length >> 1)] = (u - v) % q
                wn = wn * w % q
        length <<= 1
    if invert:
        inv_n = pow(n, q - 2, q)
        for i in range(n):
            a[i] = a[i] * inv_n % q


def _rnl_poly_mul(f, g, q, n):
    """Multiply f*g in Z_q[x]/(x^n+1) via negacyclic NTT. O(n log n).
    ψ = 3^((q-1)/(2n)) is a primitive 2n-th root of unity; ψ^n ≡ -1 (mod q)
    encodes the negacyclic wrap without explicit branch logic."""
    if _NUMPY:
        _, _, _, _, psi_pows, psi_inv_pows = _ntt_tables(q, n)
        fa = _np.array(f, dtype=_np.int64) * psi_pows % q
        ga = _np.array(g, dtype=_np.int64) * psi_pows % q
        _ntt_np(fa, q, False)
        _ntt_np(ga, q, False)
        ha = fa * ga % q
        _ntt_np(ha, q, True)
        return (ha * psi_inv_pows % q).tolist()
    psi     = pow(3, (q - 1) // (2 * n), q)
    psi_inv = pow(psi, q - 2, q)
    fa, ga  = list(f), list(g)
    pw = 1
    for i in range(n):
        fa[i] = fa[i] * pw % q
        ga[i] = ga[i] * pw % q
        pw = pw * psi % q
    _ntt_inplace(fa, q, False)
    _ntt_inplace(ga, q, False)
    ha = [fa[i] * ga[i] % q for i in range(n)]
    _ntt_inplace(ha, q, True)
    pw_inv = 1
    for i in range(n):
        ha[i]  = ha[i] * pw_inv % q
        pw_inv = pw_inv * psi_inv % q
    return ha

def _rnl_poly_add(f, g, q):
    return [(a + b) % q for a, b in zip(f, g)]

def _rnl_round(poly, from_q, to_p):
    """Round each coefficient from Z_{from_q} to Z_{to_p} (nearest integer)."""
    return [(c * to_p + from_q // 2) // from_q % to_p for c in poly]

def _rnl_lift(poly, from_p, to_q):
    """Lift from Z_{from_p} to Z_{to_q} with centered rounding (c -> (c*to_q + from_p//2) // from_p)."""
    return [(c * to_q + from_p // 2) // from_p % to_q for c in poly]

def _rnl_m_poly(n):
    """FSCX polynomial m(x) = 1 + x + x^{n-1} as a coefficient list in Z_q."""
    p = [0] * n
    p[0] = p[1] = p[n - 1] = 1
    return p

def _rnl_rand_poly(n, q):
    """Uniform random polynomial in Z_q^n (bias-free: 3-byte rejection sampling)."""
    threshold = (1 << 24) - (1 << 24) % q
    out = []
    while len(out) < n:
        v = int.from_bytes(os.urandom(3), 'big')
        if v < threshold:
            out.append(v % q)
    return out

def _rnl_cbd_poly(n, eta, q):
    """Centered binomial distribution CBD(eta): each coefficient = a - b (mod q).
    For eta=1: 4 coefficients per byte, bit-pairs (0-1),(2-3),(4-5),(6-7).
    For eta>1: general path — popcount of eta bits each side."""
    if eta == 1:
        raw = os.urandom((n + 3) // 4)
        out = []
        for i in range(n):
            shift = (i & 3) * 2
            a = (raw[i >> 2] >> shift) & 1
            b = (raw[i >> 2] >> (shift + 1)) & 1
            out.append((a - b) % q)
        return out
    mask = (1 << eta) - 1
    byte_count = (2 * eta + 7) // 8
    out = []
    for _ in range(n):
        raw = int.from_bytes(os.urandom(byte_count), 'big')
        a   = bin(raw & mask).count('1')
        b   = bin((raw >> eta) & mask).count('1')
        out.append((a - b) % q)
    return out

def _rnl_bits_to_bitarray(poly, pp, size):
    """Extract 1 bit per coefficient (coeff >= pp//2 → bit=1) and pack into BitArray."""
    val = 0
    threshold = pp // 2
    for i, c in enumerate(poly[:size]):
        if c >= threshold:
            val |= (1 << i)
    return BitArray(size, val)

def _rnl_hint(K_poly, q):
    """2-bit Peikert cross-rounding hint per coefficient.
    h[i] = floor((8*c + q/4) / q) % 4  (eighth-bucket index with 1/8-cycle bias)"""
    return [((8 * c + q // 4) // q) % 4 for c in K_poly]

def _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits):
    """Extract key_bits key bits: 2 bits per coefficient from key_bits//2 coefficients.
    Both parties call with the same hint and their own K_poly to guarantee agreement."""
    val = 0
    qq = q // 4
    for i, (c, h) in enumerate(zip(K_poly[:key_bits // 2], hint[:key_bits // 2])):
        b = ((4 * c + (2 * h + 1) * qq) // q) % pp  # pp=4 → b ∈ {0,1,2,3}
        val |= (b << (2 * i))
    return val

def _rnl_keygen(m_blind, n, q, p, b):
    """Generate one party's (s, C) key pair for HKEX-RNL.
    s: private CBD(b) polynomial; C: public rounded polynomial."""
    s  = _rnl_cbd_poly(n, b, q)
    ms = _rnl_poly_mul(m_blind, s, q, n)
    C  = _rnl_round(ms, q, p)
    return s, C

def _rnl_agree(s, C_other, q, p, pp, n, key_bits, hint=None):
    """Compute raw key bits with Peikert cross-rounding reconciliation.
    Reconciler path (hint=None): generate hint, return (K_raw, hint).
    Receiver path (hint provided): use hint, return K_raw.

    SECURITY: the hint vector is transmitted unauthenticated. An active
    adversary who tampers with the hint can steer the reconciled key.
    HKEX-RNL provides key agreement only; the caller must authenticate the
    transcript (e.g. via HPKS-NL or a MAC over b_pub||hint) before use."""
    C_lifted = _rnl_lift(C_other, p, q)
    K_poly   = _rnl_poly_mul(s, C_lifted, q, n)
    if hint is None:
        hint = _rnl_hint(K_poly, q)
        return BitArray(key_bits, _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits)), hint
    return BitArray(key_bits, _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits))


# ---------------------------------------------------------------------------
# HPKS-Stern-F / HPKE-Stern-F — Code-Based PQC (Syndrome Decoding + NL-FSCX PRF)
# Security reduces to SD(N,t) [NP-complete] + NL-FSCX v1 PRF.  See §11.8.4.
#
# TIMING NOTE — this Python implementation is a REFERENCE ONLY and is NOT
# constant-time.  _stern_apply_perm and _stern_syndrome_H branch on secret
# bit values, leaking Hamming-weight via timing.  Production deployments must
# use the C or assembly targets, which use branchless bit-mask operations.
# ---------------------------------------------------------------------------

# Stern-F soundness threshold: ⌈λ / log2(3/2)⌉ for λ=128-bit security.
_STERN_F_PRODUCTION_ROUNDS = 219


def _csprng_weight_t(n: int, t: int) -> int:
    """Sample a uniform weight-t bit vector on n positions using os.urandom.

    Replaces random.sample() (Mersenne Twister — predictable from observed
    outputs, unsuitable for sampling secret error vectors). Used for HPKS-Stern-F
    private keys, per-round Fiat-Shamir blinding, and HPKE-Stern-F encapsulated
    errors. 4-byte rejection sampling eliminates modular bias for any n ≤ 2^32.
    """
    chosen = set()
    threshold = (1 << 32) - (1 << 32) % n
    while len(chosen) < t:
        v = int.from_bytes(os.urandom(4), 'big')
        if v < threshold:
            chosen.add(v % n)
    return sum(1 << p for p in chosen)


def _stern_hash(n: int, *items: 'BitArray', ds: int = 0) -> 'BitArray':
    """Chain-hash items to n bits via NL-FSCX v1, finalized with HFSCX-256 (v1.6.0).
    ds: domain-separation tag initialising the chain state (0=challenge/default,
        1=c0, 2=c1, 3=c2, 4=KEM-key).  Prevents cross-slot collisions (TODO #36)."""
    mask = (1 << n) - 1
    h = BitArray(n, ds & mask)
    for item in items:
        v = item if isinstance(item, BitArray) else BitArray(n, int(item) & mask)
        h = nl_fscx_revolve_v1(h ^ v, v.rotated(n // 8), n // 4)
    digest = hfscx_256(h.bytes)
    return BitArray(n, int.from_bytes(digest, 'big') >> (256 - n))


def _stern_matrix_row(seed_int: int, row: int, n: int) -> 'BitArray':
    """Row *row* of public parity-check matrix H: F_seed(row) via NL-FSCX v1 PRF."""
    seed = BitArray(n, seed_int)
    A0   = BitArray(n, seed_int ^ row).rotated(n // 8)
    return nl_fscx_revolve_v1(A0, seed, n // 4)


def _stern_build_H(seed_int: int, n: int, n_rows: int) -> list:
    """Build all n_rows of the public parity matrix once, returned as int row words.

    Hot paths (sign/verify/keygen/encap) call _stern_syndrome many times against
    the same seed; building H once and reusing it eliminates the rounds × n_rows
    per-call PRF evaluations the original implementation incurred.
    """
    return [_stern_matrix_row(seed_int, i, n).uint for i in range(n_rows)]


def _stern_syndrome_H(H_rows: list, e_int: int) -> int:
    """Compute syndrome H·e^T mod 2 from a precomputed matrix (list of row ints).

    NOT constant-time: bin().count() is variable-time over int size and the
    bit-test inside the loop branches on e_int bits.  Reference only.
    """
    s = 0
    for i, row in enumerate(H_rows):
        s |= (bin(row & e_int).count('1') & 1) << i
    return s


def _stern_syndrome(seed_int: int, e_int: int, n: int, n_rows: int) -> int:
    """Compute n_rows-bit syndrome s = H·e^T mod 2.

    Convenience wrapper that builds H on each call. Hot paths should instead call
    _stern_build_H once and reuse the result via _stern_syndrome_H.
    """
    return _stern_syndrome_H(_stern_build_H(seed_int, n, n_rows), e_int)


def _stern_gen_perm(pi_seed: 'BitArray', N: int) -> list:
    """Fisher-Yates shuffle of [0..N-1] driven by NL-FSCX v1 PRNG.

    Counter-mode extraction: all n/8 bytes of each state block are consumed as
    sequential 32-bit draws before advancing the state (no entropy wasted).
    Rejection sampling (threshold = 2^32 - 2^32%range) eliminates modular bias.
    """
    n       = pi_seed._size
    nb      = n // 8
    key     = pi_seed.rotated(n // 8)
    perm    = list(range(N))
    st      = pi_seed.copy()
    buf     = b'\x00' * nb
    cursor  = nb                               # force state advance on first draw
    for i in range(N - 1, 0, -1):
        range_    = i + 1
        threshold = (1 << 32) - (1 << 32) % range_
        while True:
            if cursor + 4 > nb:
                st     = nl_fscx_v1(st, key)
                buf    = st.bytes
                cursor = 0
            v       = int.from_bytes(buf[cursor:cursor + 4], 'big')
            cursor += 4
            if v < threshold:
                break
        k = v % range_
        perm[i], perm[k] = perm[k], perm[i]
    return perm


def _stern_apply_perm(perm: list, v_int: int, N: int) -> int:
    """Apply permutation perm to N-bit integer v: result[perm[i]] = v[i].

    NOT constant-time: the inner `if` branches on each secret bit of v,
    leaking its Hamming weight via timing.  Reference only; C/asm targets
    use a branchless mask: result |= (-(bit) & (1 << perm[i])).
    """
    result = 0
    for i in range(N):
        if (v_int >> i) & 1:
            result |= 1 << perm[i]
    return result


def _stern_simulate_round(b: int, syndrome: int, H_rows: list, n: int, t: int):
    """HVZK simulator for one Stern round given pre-chosen challenge b ∈ {0,1,2}.

    Returns (c0, c1, c2, resp) where resp is the response tuple matching b:
      b=0 → resp=(sr_sim, sy_sim);  c0 unchecked (random-looking)
      b=1 → resp=(pi_sim, r_sim);   c2 unchecked (random-looking)
      b=2 → resp=(pi_sim, y_sim);   c1 unchecked (random-looking)

    Used in hpks_stern_ring_sign to simulate non-signer ring members.
    """
    mask = (1 << n) - 1
    if b == 0:
        sr_sim = _csprng_weight_t(n, t)
        sy_sim = int.from_bytes(os.urandom(n // 8), 'big') & mask
        pi_dum = BitArray.random(n)
        c0 = _stern_hash(n, pi_dum, BitArray(n, 0), ds=1)          # unchecked
        c1 = _stern_hash(n, BitArray(n, sr_sim), ds=2)
        c2 = _stern_hash(n, BitArray(n, sy_sim), ds=3)
        return c0, c1, c2, (sr_sim, sy_sim)
    elif b == 1:
        pi_sim = BitArray.random(n)
        r_sim  = _csprng_weight_t(n, t)
        perm   = _stern_gen_perm(pi_sim, n)
        Hr_sim = _stern_syndrome_H(H_rows, r_sim)
        sr_sim = _stern_apply_perm(perm, r_sim, n)
        sy_dum = int.from_bytes(os.urandom(n // 8), 'big') & mask
        c0 = _stern_hash(n, pi_sim, BitArray(n, Hr_sim), ds=1)
        c1 = _stern_hash(n, BitArray(n, sr_sim), ds=2)
        c2 = _stern_hash(n, BitArray(n, sy_dum), ds=3)              # unchecked
        return c0, c1, c2, (pi_sim, r_sim)
    else:  # b == 2
        pi_sim = BitArray.random(n)
        y_sim  = int.from_bytes(os.urandom(n // 8), 'big') & mask
        perm   = _stern_gen_perm(pi_sim, n)
        Hy_sim = _stern_syndrome_H(H_rows, y_sim)
        sy_sim = _stern_apply_perm(perm, y_sim, n)
        sr_dum = int.from_bytes(os.urandom(n // 8), 'big') & mask
        c0 = _stern_hash(n, pi_sim, BitArray(n, Hy_sim ^ syndrome), ds=1)
        c1 = _stern_hash(n, BitArray(n, sr_dum), ds=2)              # unchecked
        c2 = _stern_hash(n, BitArray(n, sy_sim), ds=3)
        return c0, c1, c2, (pi_sim, y_sim)


def stern_f_keygen(n: int = None):
    """Stern-F key generation for HPKS-Stern-F and HPKE-Stern-F.

    Returns (seed, e_int, syndrome):
      seed     — n-bit public matrix seed (public)
      e_int    — N-bit weight-t error vector (private key)
      syndrome — n_rows-bit syndrome H·e^T mod 2 (public key component)
    """
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    seed   = BitArray.random(n)
    e_int  = _csprng_weight_t(n, t)
    H_rows = _stern_build_H(seed.uint, n, n_rows)
    return seed, e_int, _stern_syndrome_H(H_rows, e_int)


def hpks_stern_f_sign(msg: 'BitArray', e_int: int, seed: 'BitArray',
                      syndrome: int, n: int = None, rounds: int = None):
    """HPKS-Stern-F: sign msg using Stern's 3-challenge protocol + Fiat-Shamir.

    Correct Stern blinding: prover draws weight-t r and sets y = e ⊕ r so that
    wt(r) = t is verifiable for b=1 and wt(σ(r)) = t for b=0.

    Commits per round:
      c0 = H(σ_seed, H·r^T)   c1 = H(σ(r))   c2 = H(σ(y))
    Responses:
      b=0: (σ(r), σ(y))  → check c1, c2, wt(σ(r))=t
      b=1: (σ_seed, r)   → check c0, c1, wt(r)=t
      b=2: (σ_seed, y)   → check c0 via H(σ_seed, H·y^T⊕s), check c2

    Soundness: (2/3)^rounds; production needs rounds ≥ 219 for 128-bit soundness.
    """
    if n      is None: n      = KEYBITS
    if rounds is None: rounds = SDFR
    n_rows = n // 2
    t      = max(2, n // 16)

    if rounds < _STERN_F_PRODUCTION_ROUNDS:
        bits = rounds * math.log2(1.5)
        warnings.warn(
            f"HPKS-Stern-F: rounds={rounds} gives ~{bits:.1f}-bit soundness; "
            f"production deployments require rounds ≥ {_STERN_F_PRODUCTION_ROUNDS} "
            f"for 128-bit soundness.",
            RuntimeWarning, stacklevel=2,
        )

    H_rows = _stern_build_H(seed.uint, n, n_rows)

    commits    = []
    round_data = []
    for _ in range(rounds):
        r_int   = _csprng_weight_t(n, t)                            # weight-t blinding
        y_int   = (e_int ^ r_int) & ((1 << n) - 1)                # y = e ⊕ r
        pi_seed = BitArray.random(n)
        perm    = _stern_gen_perm(pi_seed, n)
        Hr  = _stern_syndrome_H(H_rows, r_int)
        sr  = _stern_apply_perm(perm, r_int, n)
        sy  = _stern_apply_perm(perm, y_int, n)
        commits.append((_stern_hash(n, pi_seed, BitArray(n, Hr), ds=1),
                        _stern_hash(n, BitArray(n, sr), ds=2),
                        _stern_hash(n, BitArray(n, sy), ds=3)))
        round_data.append((r_int, y_int, pi_seed, Hr, sr, sy))

    # Fiat-Shamir: all challenges from H(msg || all_commits)
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = _stern_hash(n, *flat)
    challenges = []
    for i in range(rounds):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, i))
        challenges.append(ch_st.uint % 3)

    responses = []
    for i, (r_int, y_int, pi_seed, _Hr, sr, sy) in enumerate(round_data):
        b = challenges[i]
        if   b == 0: responses.append((sr, sy))             # reveal (σ(r), σ(y))
        elif b == 1: responses.append((pi_seed, r_int))     # reveal (σ_seed, r)
        else:        responses.append((pi_seed, y_int))     # reveal (σ_seed, y)
    return (commits, challenges, responses)


def hpks_stern_f_verify(msg: 'BitArray', sig, seed: 'BitArray',
                        syndrome: int, n: int = None) -> bool:
    """HPKS-Stern-F: verify signature sig on msg against public (seed, syndrome)."""
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    commits, challenges, responses = sig

    # Re-derive and check Fiat-Shamir challenges
    flat = [msg]
    for c0, c1, c2 in commits:
        flat += [c0, c1, c2]
    ch_st = _stern_hash(n, *flat)
    for i, b in enumerate(challenges):
        ch_st = nl_fscx_v1(ch_st, BitArray(n, i))
        if ch_st.uint % 3 != b:
            return False

    # Build H once: only needed for b ∈ {1, 2} branches but the seed is fixed.
    H_rows = _stern_build_H(seed.uint, n, n_rows)

    for i, b in enumerate(challenges):
        c0, c1, c2 = commits[i]
        resp = responses[i]
        if b == 0:                                        # reveal (σ(r), σ(y))
            sr, sy = resp
            if _stern_hash(n, BitArray(n, sr), ds=2) != c1:          return False
            if _stern_hash(n, BitArray(n, sy), ds=3) != c2:          return False
            if bin(sr).count('1') != t:                               return False
        elif b == 1:                                      # reveal (σ_seed, r)
            pi_seed, r_int = resp
            if bin(r_int).count('1') != t:                            return False
            perm = _stern_gen_perm(pi_seed, n)
            Hr   = _stern_syndrome_H(H_rows, r_int)
            if _stern_hash(n, pi_seed, BitArray(n, Hr), ds=1) != c0: return False
            sr   = _stern_apply_perm(perm, r_int, n)
            if _stern_hash(n, BitArray(n, sr), ds=2) != c1:          return False
        else:                                             # reveal (σ_seed, y)
            pi_seed, y_int = resp
            perm = _stern_gen_perm(pi_seed, n)
            Hy   = _stern_syndrome_H(H_rows, y_int)
            if _stern_hash(n, pi_seed, BitArray(n, Hy ^ syndrome), ds=1) != c0: return False
            sy   = _stern_apply_perm(perm, y_int, n)
            if _stern_hash(n, BitArray(n, sy), ds=3) != c2:          return False
    return True


def hpke_stern_f_encap(seed: 'BitArray', n: int = None):
    """HPKE-Stern-F encapsulation (Niederreiter KEM).

    Returns (K, ciphertext):
      K          — n-bit session key (derived from fresh error e')
      ciphertext — n_rows-bit syndrome H·e'^T (public; hard to invert without decoder)
    """
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    e_p    = _csprng_weight_t(n, t)
    H_rows = _stern_build_H(seed.uint, n, n_rows)
    ct     = _stern_syndrome_H(H_rows, e_p)
    K      = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return K, ct


def hpke_stern_f_decap(ciphertext: int, e_int: int, seed: 'BitArray',
                       n: int = None):
    """HPKE-Stern-F decapsulation.

    Two paths:
    - Known-e' (e_int != 0): derive K directly from the encapsulation error.
      Use when the caller holds the plaintext error (test/demo) or a QC-MDPC
      decoder has already recovered it.
    - Brute-force (e_int == 0): enumerate all weight-t candidates.
      Refuses to enter the brute-force loop above 2^32 candidates; production
      deployments must supply a QC-MDPC decoder instead.
    Returns session key K or None if decode fails.
    """
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    if e_int:
        return _stern_hash(n, seed, BitArray(n, e_int & ((1 << n) - 1)), ds=4)
    if math.comb(n, t) > (1 << 32):
        raise ValueError(
            f"hpke_stern_f_decap: brute-force search infeasible at n={n}, t={t} "
            f"(C(n,t)={math.comb(n, t):.2e} > 2^32). Provide e_int from a "
            f"QC-MDPC decoder or use hpke_stern_f_decap_known."
        )
    H_rows = _stern_build_H(seed.uint, n, n_rows)
    for pos in itertools.combinations(range(n), t):
        e_p = sum(1 << p for p in pos)
        if _stern_syndrome_H(H_rows, e_p) == ciphertext:
            return _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return None


def hpke_stern_f_encap_with_e(seed: 'BitArray', n: int = None):
    """Like hpke_stern_f_encap but also returns the plaintext error e_p."""
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    e_p    = _csprng_weight_t(n, t)
    H_rows = _stern_build_H(seed.uint, n, n_rows)
    ct     = _stern_syndrome_H(H_rows, e_p)
    K      = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)), ds=4)
    return K, ct, e_p


# ---------------------------------------------------------------------------
# 78.I — Code-Based Ring/Group Signature via HPKS-Stern-F OR-composition
# OR-compose k Stern identification instances: prove knowledge of one secret
# key in a ring of k public keys without revealing which one.
# Proof size: O(k × rounds).  Security: EUF-CMA under SD(N,t) per member.
# ---------------------------------------------------------------------------

def hpks_stern_ring_sign(msg: 'BitArray', e_int: int, j: int,
                          ring_keys: list, n: int = None,
                          rounds: int = None):
    """Ring signature: prove knowledge of one HPKS-Stern-F key in a ring.

    ring_keys = [(seed_0, syndrome_0), ..., (seed_{k-1}, syndrome_{k-1})]
      where syndrome_i is the integer returned by stern_f_keygen.
    j         = 0-based index of the actual signer.
    e_int     = signer's weight-t error vector (secret key for ring_keys[j]).

    Returns (all_commits, all_challenges, all_responses):
      all_commits[i][r]   = (c0, c1, c2)  BitArray triples
      all_challenges[i][r] = b ∈ {0,1,2}
      all_responses[i][r]  = response tuple matching b
    """
    if n      is None: n      = KEYBITS
    if rounds is None: rounds = SDFR
    k      = len(ring_keys)
    n_rows = n // 2
    t      = max(2, n // 16)

    all_commits    = [[None] * rounds for _ in range(k)]
    all_challenges = [[0]    * rounds for _ in range(k)]
    all_responses  = [[None] * rounds for _ in range(k)]

    # Step 1 — simulate non-signer members with pre-chosen challenges
    for i in range(k):
        if i == j:
            continue
        seed_i, syn_i = ring_keys[i]
        H_rows_i = _stern_build_H(seed_i.uint, n, n_rows)
        for r in range(rounds):
            b = int.from_bytes(os.urandom(1), 'big') % 3
            all_challenges[i][r] = b
            c0, c1, c2, resp = _stern_simulate_round(b, syn_i, H_rows_i, n, t)
            all_commits[i][r]   = (c0, c1, c2)
            all_responses[i][r] = resp

    # Step 2 — commit phase for real signer j
    seed_j, _ = ring_keys[j]
    H_rows_j  = _stern_build_H(seed_j.uint, n, n_rows)
    mask       = (1 << n) - 1
    round_data_j = []
    for r in range(rounds):
        r_int   = _csprng_weight_t(n, t)
        y_int   = (e_int ^ r_int) & mask
        pi_seed = BitArray.random(n)
        perm    = _stern_gen_perm(pi_seed, n)
        Hr  = _stern_syndrome_H(H_rows_j, r_int)
        sr  = _stern_apply_perm(perm, r_int, n)
        sy  = _stern_apply_perm(perm, y_int, n)
        all_commits[j][r] = (
            _stern_hash(n, pi_seed, BitArray(n, Hr), ds=1),
            _stern_hash(n, BitArray(n, sr), ds=2),
            _stern_hash(n, BitArray(n, sy), ds=3),
        )
        round_data_j.append((r_int, y_int, pi_seed, sr, sy))

    # Step 3 — Fiat-Shamir: hash msg + all k×rounds×3 commits (member-major)
    flat = [msg]
    for i in range(k):
        for r in range(rounds):
            flat += list(all_commits[i][r])
    ch_st = _stern_hash(n, *flat)

    # Step 4 — assign real signer's per-round challenge via challenge splitting
    for r in range(rounds):
        ch_st   = nl_fscx_v1(ch_st, BitArray(n, r))
        joint_b = ch_st.uint % 3
        sim_sum = sum(all_challenges[i][r] for i in range(k) if i != j) % 3
        all_challenges[j][r] = (joint_b - sim_sum) % 3

    # Step 5 — complete real signer's responses
    for r, (r_int, y_int, pi_seed, sr, sy) in enumerate(round_data_j):
        b = all_challenges[j][r]
        if   b == 0: all_responses[j][r] = (sr, sy)
        elif b == 1: all_responses[j][r] = (pi_seed, r_int)
        else:        all_responses[j][r] = (pi_seed, y_int)

    return (all_commits, all_challenges, all_responses)


def hpks_stern_ring_verify(msg: 'BitArray', sig, ring_keys: list,
                             n: int = None) -> bool:
    """Verify an HPKS-Stern-F ring signature.

    Accepts any sig produced by hpks_stern_ring_sign for any member of
    ring_keys without revealing which member signed.
    """
    if n is None: n = KEYBITS
    k      = len(ring_keys)
    n_rows = n // 2
    t      = max(2, n // 16)
    all_commits, all_challenges, all_responses = sig
    rounds = len(all_challenges[0])

    # Re-derive joint Fiat-Shamir challenges
    flat = [msg]
    for i in range(k):
        for r in range(rounds):
            flat += list(all_commits[i][r])
    ch_st = _stern_hash(n, *flat)

    # Check challenge consistency: sum_i b_ir ≡ joint_b_r (mod 3) for all r
    for r in range(rounds):
        ch_st   = nl_fscx_v1(ch_st, BitArray(n, r))
        joint_b = ch_st.uint % 3
        if sum(all_challenges[i][r] for i in range(k)) % 3 != joint_b:
            return False

    # Verify each member's response
    for i in range(k):
        seed_i, syn_i = ring_keys[i]
        H_rows_i = _stern_build_H(seed_i.uint, n, n_rows)
        for r in range(rounds):
            c0, c1, c2 = all_commits[i][r]
            b    = all_challenges[i][r]
            resp = all_responses[i][r]
            if b == 0:
                sr, sy = resp
                if _stern_hash(n, BitArray(n, sr), ds=2) != c1: return False
                if _stern_hash(n, BitArray(n, sy), ds=3) != c2: return False
                if bin(sr).count('1') != t:                      return False
            elif b == 1:
                pi_seed, r_int = resp
                if bin(r_int).count('1') != t:                   return False
                perm = _stern_gen_perm(pi_seed, n)
                Hr   = _stern_syndrome_H(H_rows_i, r_int)
                if _stern_hash(n, pi_seed, BitArray(n, Hr), ds=1) != c0: return False
                sr   = _stern_apply_perm(perm, r_int, n)
                if _stern_hash(n, BitArray(n, sr), ds=2) != c1:  return False
            else:
                pi_seed, y_int = resp
                perm = _stern_gen_perm(pi_seed, n)
                Hy   = _stern_syndrome_H(H_rows_i, y_int)
                if _stern_hash(n, pi_seed, BitArray(n, Hy ^ syn_i), ds=1) != c0: return False
                sy   = _stern_apply_perm(perm, y_int, n)
                if _stern_hash(n, BitArray(n, sy), ds=3) != c2:  return False
    return True


# ---------------------------------------------------------------------------
# ZKP-RNL: Ring-LWR Σ-protocol (Lyubashevsky-style, Fiat-Shamir compiled)
# SecurityProofs-3.md §11.10.2
# ---------------------------------------------------------------------------
#
# Statement : (m, C) — blinding poly m ∈ Z_q^n, public key C ∈ Z_p^n
# Witness   : s ∈ {-1,0,1}^n satisfying C = round_p(m·s mod q) in Z_q[x]/(x^n+1)
# Message   : msg_bytes bound into challenge (Fiat-Shamir → signature)
#
# Sign  : y ← Unif[-γ,γ]^n;  w = m·y mod q (centered);
#         c = challenge(m,C,w,msg); z = y + c·s (centered integers);
#         reject and restart if ||z||∞ > γ − t.
# Verify: (1) ||z||∞ ≤ γ−t; (2) c = challenge(m,C,w,msg);
#         (3) ||m·z − w − c·lift(C)||∞ ≤ t·⌈q/(2p)⌉.
# ---------------------------------------------------------------------------

def _sigma_params(n):
    """Return (gamma, t) for the Ring-LWR Σ-protocol at bit-width n."""
    gamma = _SIGMA_GAMMA.get(n, 8192 if n >= 64 else 4096)
    t     = _SIGMA_T.get(n, max(4, n // 16))
    return gamma, t


def _sigma_poly_bytes(poly):
    """Serialize a polynomial (possibly signed/Z_q) to bytes for hashing (4 B/coeff)."""
    return b''.join((c % (1 << 32)).to_bytes(4, 'big') for c in poly)


def _sigma_challenge(m_poly, C_poly, w_poly, n, q, t, msg_bytes):
    """Fiat-Shamir: derive sparse ternary challenge polynomial from (m, C, w, msg).

    Returns a list of n integers in {0, 1, q-1} with exactly t nonzero entries.
    Nonzero entries are either 1 (= +1) or q-1 (= -1 mod q).
    """
    seed = hfscx_256(
        n.to_bytes(4, 'big')
        + _sigma_poly_bytes(m_poly)
        + _sigma_poly_bytes(C_poly)
        + _sigma_poly_bytes(w_poly)
        + msg_bytes
    )
    # Expand seed to t distinct positions via counter extension
    positions = []
    idx = 0
    while len(positions) < t:
        h = hfscx_256(seed + b'pos' + idx.to_bytes(4, 'big'))
        v = int.from_bytes(h[:4], 'big') % n
        if v not in positions:
            positions.append(v)
        idx += 1
    # Assign ±1 signs (stored as Z_q: +1 or q-1)
    c = [0] * n
    for k, pos in enumerate(positions):
        h = hfscx_256(seed + b'sgn' + k.to_bytes(4, 'big'))
        c[pos] = 1 if (h[0] & 1) == 0 else q - 1
    return c


def rnl_sigma_sign(s_poly, m_poly, C_poly, n, msg_bytes):
    """ZKP-RNL: Ring-LWR Σ-protocol proof of knowledge of s s.t. C = round_p(m·s).

    s_poly: CBD(1) coefficients in Z_q (values in {0, 1, q-1}).
    m_poly, C_poly: from an HKEX-RNL keypair (_rnl_keygen).
    msg_bytes: message to bind (Fiat-Shamir → signature).

    Returns (w_poly, c_poly, z_poly) — the proof triple.
    w_poly: centered Z_q coefficients in (-q/2, q/2].
    c_poly: sparse ternary in Z_q — t entries of {1, q-1}, rest 0.
    z_poly: centered integer list with ||z||∞ ≤ γ − t.

    Raises RuntimeError if rejection limit is reached (extremely rare).
    """
    q     = RNLQ
    p     = RNLP
    gamma, t = _sigma_params(n)
    bound = gamma - t
    h     = q // 2  # centering threshold

    for _ in range(_SIGMA_MAX_ATTEMPTS):
        # Sample mask y ← Unif[-γ, γ]^n
        y = []
        for _ in range(n):
            v = int.from_bytes(os.urandom(4), 'big') % (2 * gamma + 1)
            y.append(v - gamma)

        y_q  = [yi % q for yi in y]
        my   = _rnl_poly_mul(m_poly, y_q, q, n)
        # Center w coefficients into (-q/2, q/2]
        w    = [c - q if c > h else c for c in my]

        c    = _sigma_challenge(m_poly, C_poly, w, n, q, t, msg_bytes)
        cs   = _rnl_poly_mul(c, s_poly, q, n)
        cs_c = [x - q if x > h else x for x in cs]
        z    = [y[i] + cs_c[i] for i in range(n)]

        if max(abs(zi) for zi in z) <= bound:
            return w, c, z

    raise RuntimeError(
        f"rnl_sigma_sign: rejection sampling limit ({_SIGMA_MAX_ATTEMPTS}) reached"
    )


def rnl_sigma_verify(m_poly, C_poly, n, msg_bytes, w_poly, c_poly, z_poly):
    """Verify a ZKP-RNL Ring-LWR Σ-protocol proof.

    Returns True iff (w, c, z) is an accepting transcript for (m, C, msg).
    """
    q = RNLQ
    p = RNLP
    gamma, t = _sigma_params(n)
    bound = gamma - t
    slack = t * (q // (2 * p) + 1)   # t × ⌈q/(2p)⌉ = e.g. 16 × 9 = 144 at n=256

    # (1) Infinity-norm bound on response
    if max(abs(zi) for zi in z_poly) > bound:
        return False

    # (2) Fiat-Shamir consistency
    if c_poly != _sigma_challenge(m_poly, C_poly, w_poly, n, q, t, msg_bytes):
        return False

    # (3) Rounding slack: ||m·z − w − c·lift(C)||∞ ≤ slack
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
# ZKP-NL: NL-FSCX ZKBoo (MPC-in-the-head, 3-party Boolean circuit)
# SecurityProofs-3.md §11.10.3
# ---------------------------------------------------------------------------
#
# Statement : (B, y) — public; B, y ∈ {0,…,2^n-1}
# Witness   : A ∈ {0,…,2^n-1} with nl_fscx_v1(A, B) = y
# Circuit   : F1(A,B) = fscx(A,B) ⊕ ROL((A+B) mod 2^n, n/4)
#   Linear  : fscx(A,B) — free XOR-rotation (linear in A, B constant public)
#   Nonlinear: (A+B) mod 2^n — n−1 AND gates for carry chain (A_i AND c_i)
#
# ZKBoo 3-party AND gate: x,y secret-XOR-shared across parties 0,1,2.
#   z_i = x_i·y_i ⊕ x_i·y_{i+1} ⊕ x_{i+1}·y_i ⊕ r_i ⊕ r_{i+1}  (indices mod 3)
#   z_0 ⊕ z_1 ⊕ z_2 = x · y
#
# Soundness: (2/3)^R per proof; R=219 for 128-bit soundness.
# ---------------------------------------------------------------------------

def _zkp_nl_rol(x, r, n):
    """Cyclic left-rotate n-bit integer x by r positions."""
    m = (1 << n) - 1
    r = r % n
    return ((x << r) | (x >> (n - r))) & m


def _zkp_nl_h(*args):
    """Domain hash for ZKBoo commitments and challenges (HFSCX-256)."""
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
    """One pseudorandom bit from party tape + gate index."""
    h = _zkp_nl_h(tape_key, gate_id.to_bytes(4, 'big'))
    return h[0] & 1


def _zkp_nl_evaluate_circuit(shares, tapes, B, n):
    """Evaluate nl_fscx_v1(A, B) in 3-party ZKBoo decomposition.

    shares: list of 3 n-bit integers (XOR shares of A; A = s0^s1^s2)
    tapes : list of 3 × 32-byte random tapes (one per party)
    B     : public n-bit integer

    Returns (out_shares, gate_views) where:
      out_shares[p] = party p's output share (XOR of all three = nl_fscx_v1(A,B))
      gate_views[p] = list of (a_bit, c_bit, and_out) for each of the n-1 AND gates
    """
    mask = (1 << n) - 1
    carry = [[0, 0, 0]] * n   # carry[0] always 0 (no input carry)
    gate_views = [[], [], []]
    gate_id = 0

    for i in range(n - 1):
        ai = [(shares[p] >> i) & 1 for p in range(3)]
        ci = [carry[i][p] for p in range(3)]
        Bi = (B >> i) & 1

        # c_{i+1} = Bi*Ai XOR (Ai AND ci) XOR Bi*ci
        # Only (Ai AND ci) is a secret-secret AND gate.
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

    # Sum shares: bit i of (A+B) mod 2^n = A_i XOR B_i XOR carry_i (linear)
    sum_shares = [0, 0, 0]
    for i in range(n):
        for p in range(3):
            bit_i = ((shares[p] >> i) & 1) ^ ((B >> i) & 1) ^ carry[i][p]
            sum_shares[p] ^= bit_i << i

    # ROL_{n/4} is a bit-permutation (linear) — apply identically to each share
    rot_shares = [_zkp_nl_rol(sum_shares[p], n // 4, n) for p in range(3)]

    # Linear part L(A,B): fscx(A,B) with B constant
    B_const = (B ^ _zkp_nl_rol(B, 1, n) ^ _zkp_nl_rol(B, n - 1, n)) & mask
    lin_shares = [0, 0, 0]
    for p in range(3):
        A_terms = (shares[p] ^ _zkp_nl_rol(shares[p], 1, n)
                   ^ _zkp_nl_rol(shares[p], n - 1, n)) & mask
        lin_shares[p] = A_terms
    lin_shares[0] ^= B_const   # absorb public constant into party 0 only

    # F1(A,B) = linear XOR rotated-sum
    out_shares = [(lin_shares[p] ^ rot_shares[p]) & mask for p in range(3)]
    return out_shares, gate_views


def zkp_nl_keygen(n=_ZKP_NL_DEFAULT_N):
    """Generate ZKP-NL keypair: (A private, B public, y = nl_fscx_v1(A,B) public).

    n: bit-width; must be a positive multiple of 2. Default: 8 (demo).
    """
    mask = (1 << n) - 1
    nb   = (n + 7) // 8
    A = int.from_bytes(os.urandom(nb), 'big') & mask
    B = int.from_bytes(os.urandom(nb), 'big') & mask
    y = nl_fscx_v1(BitArray(n, A), BitArray(n, B)).uint
    return A, B, y


def zkp_nl_prove(A, B, y, n, rounds, msg_bytes):
    """ZKBoo prover: prove knowledge of A s.t. nl_fscx_v1(A, B) = y.

    Returns a list of `rounds` dicts, each with keys:
      com_0, com_1, com_2  — 32-byte HFSCX-256 commitments
      e                    — hidden party index ∈ {0, 1, 2}
      view_p1, view_p2     — bytes encoding revealed parties' shares, tape, and gate views
    """
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

    # Fiat-Shamir: bind B, y, msg_bytes, and all commitments
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


def zkp_nl_verify(B, y, n, rounds, msg_bytes, proof_rounds):
    """ZKBoo verifier: verify proof that prover knows A s.t. nl_fscx_v1(A, B) = y.

    Returns True iff all rounds verify.
    """
    mask = (1 << n) - 1
    nb   = (n + 7) // 8
    view_size = nb + 32 + nb + (n - 1)   # share + tape + out + gate bits

    coms_list  = [[r['com_0'], r['com_1'], r['com_2']] for r in proof_rounds]
    challenges = [r['e'] for r in proof_rounds]

    # Re-derive Fiat-Shamir challenges and validate
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

        # Hidden party's output share
        out_pe = (y ^ out_p1 ^ out_p2) & mask

        # Verify commitments for revealed parties
        c_p1 = _zkp_nl_h(j.to_bytes(4, 'big'), bytes([p1]),
                          tape_p1, out_p1.to_bytes(nb, 'big'))
        c_p2 = _zkp_nl_h(j.to_bytes(4, 'big'), bytes([p2]),
                          tape_p2, out_p2.to_bytes(nb, 'big'))
        if c_p1 != coms_list[j][p1] or c_p2 != coms_list[j][p2]:
            return False

        # Re-evaluate p1's AND gates using p1 and p2 shares (both revealed)
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
# 78.J — Cryptographic Accumulator (Merkle tree on HFSCX-256) (TODO #78.J)
# Domain separation: 0x00 prefix for leaves, 0x01 for interior nodes (RFC 6962).
# ---------------------------------------------------------------------------

def haccum_leaf(data: bytes) -> bytes:
    """HFSCX-256(0x00 || data) — leaf hash."""
    return hfscx_256(b'\x00' + data)

def haccum_node(left: bytes, right: bytes) -> bytes:
    """HFSCX-256(0x01 || left || right) — interior node hash."""
    return hfscx_256(b'\x01' + left + right)

def haccum_root(leaf_hashes: list) -> bytes:
    """Merkle root of leaf_hashes (each 32 bytes). Pads to next power of 2."""
    n = len(leaf_hashes)
    if n == 0:
        return b'\x00' * 32
    sz = 1
    while sz < n:
        sz <<= 1
    nodes = [leaf_hashes[i] if i < n else b'\x00' * 32 for i in range(sz)]
    while sz > 1:
        nodes = [haccum_node(nodes[2*i], nodes[2*i+1]) for i in range(sz // 2)]
        sz //= 2
    return nodes[0]

def haccum_prove(leaf_hashes: list, idx: int) -> list:
    """Return sibling-hash proof path for leaf at idx."""
    n = len(leaf_hashes)
    sz = 1
    while sz < n:
        sz <<= 1
    nodes = [leaf_hashes[i] if i < n else b'\x00' * 32 for i in range(sz)]
    proof = []
    cur = idx
    while sz > 1:
        proof.append(nodes[cur ^ 1])
        nodes = [haccum_node(nodes[2*i], nodes[2*i+1]) for i in range(sz // 2)]
        sz //= 2
        cur >>= 1
    return proof

def haccum_verify(root: bytes, leaf_hash: bytes, proof: list, idx: int) -> bool:
    """Verify a Merkle membership proof for leaf_hash at idx."""
    cur = leaf_hash
    for sib in proof:
        cur = haccum_node(cur, sib) if idx % 2 == 0 else haccum_node(sib, cur)
        idx >>= 1
    return cur == root


# ---------------------------------------------------------------------------
# 78.A — Format-Preserving Encryption (FPE) (TODO #78.A)
# B = HFSCX-256(key || ctx); C = nl_fscx_revolve_v2(P, B, I_VALUE).
# Deterministic: same (key, ctx, plaintext) → same ciphertext.
# For IND-CPA include a per-record nonce in ctx.
# ---------------------------------------------------------------------------

def fpe_encrypt(pt: BitArray, key: bytes, ctx: bytes = b'') -> BitArray:
    """Format-preserving encrypt pt using nl_fscx_revolve_v2 with key+ctx tweak."""
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(key + ctx), 'big'))
    return nl_fscx_revolve_v2(pt, B, I_VALUE)

def fpe_decrypt(ct: BitArray, key: bytes, ctx: bytes = b'') -> BitArray:
    """Format-preserving decrypt ct — inverse of fpe_encrypt."""
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(key + ctx), 'big'))
    return nl_fscx_revolve_v2_inv(ct, B, I_VALUE)


# ---------------------------------------------------------------------------
# 78.B — Tweakable Wide-Block Cipher (TODO #78.B)
# B = HFSCX-256(key || sector_be64 || bidx_be32); each block gets a unique tweak.
# Resolves HSKE-NL-A2 determinism limitation (TODO #12).
# ---------------------------------------------------------------------------

def twk_encrypt(block: BitArray, key: bytes, sector: int, bidx: int) -> BitArray:
    """Tweakable block-cipher encrypt with per-(sector, block-index) tweak."""
    tweak = key + sector.to_bytes(8, 'big') + bidx.to_bytes(4, 'big')
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(tweak), 'big'))
    return nl_fscx_revolve_v2(block, B, I_VALUE)

def twk_decrypt(ct: BitArray, key: bytes, sector: int, bidx: int) -> BitArray:
    """Tweakable block-cipher decrypt — inverse of twk_encrypt."""
    tweak = key + sector.to_bytes(8, 'big') + bidx.to_bytes(4, 'big')
    B = BitArray(KEYBITS, int.from_bytes(hfscx_256(tweak), 'big'))
    return nl_fscx_revolve_v2_inv(ct, B, I_VALUE)


# ---------------------------------------------------------------------------
# 78.H — Masking-Friendly FSCX (Boolean masking via GF(2) linearity)
#
# FSCX(A⊕r, B, steps) ⊕ FSCX(r, 0, steps) = FSCX(A, B, steps)
# because M = I⊕ROL⊕ROR is GF(2)-linear.  No secret bits of A appear in
# any intermediate value when mask r is uniform random.
# ---------------------------------------------------------------------------

def fscx_revolve_masked(A: BitArray, B: BitArray, mask: BitArray, steps: int) -> BitArray:
    """Masked FSCX revolve: computes fscx_revolve(A, B, steps) without exposing A."""
    zero = BitArray(KEYBITS, 0)
    am   = BitArray(KEYBITS, A.uint ^ mask.uint)
    fm   = fscx_revolve(am,   B,    steps)
    fz   = fscx_revolve(mask, zero, steps)
    return BitArray(KEYBITS, fm.uint ^ fz.uint)


def hske_encrypt_masked(pt: BitArray, key: BitArray) -> tuple:
    """HSKE encrypt with masking.  Returns (ciphertext, mask)."""
    mask = BitArray.random(KEYBITS)
    ct   = fscx_revolve_masked(pt, key, mask, I_VALUE)
    return ct, mask


def hske_decrypt_masked(ct: BitArray, key: BitArray) -> tuple:
    """HSKE decrypt with masking.  Returns (plaintext, mask)."""
    mask = BitArray.random(KEYBITS)
    pt   = fscx_revolve_masked(ct, key, mask, R_VALUE)
    return pt, mask


# ---------------------------------------------------------------------------
# 78.C — Forward-Secret Unidirectional Ratchet
#
# state_{i+1} = nl_fscx_revolve_v1(state_i, RATCHET_DOMAIN, 1)
# msg_key_i   = hfscx_256(state_i.bytes || 0x01)
# ---------------------------------------------------------------------------

_RATCHET_DOMAIN = BitArray(
    KEYBITS,
    int.from_bytes(b'NL-FSCX-RATCHET-V1\x00NL-FSCX-RATCHET-V'[:KEYBITS // 8], 'big')
)


def ratchet_init(seed: bytes) -> BitArray:
    """Derive initial ratchet state from seed via hfscx_256(seed || 0x02)."""
    return BitArray(KEYBITS, int.from_bytes(hfscx_256(seed + b'\x02'), 'big'))


def ratchet_advance(state: BitArray) -> tuple:
    """Advance ratchet by one step.  Returns (new_state, msg_key_bytes).
    Caller MUST discard/zero the old state immediately."""
    msg_key   = hfscx_256(state.bytes + b'\x01')
    new_state = nl_fscx_revolve_v1(state, _RATCHET_DOMAIN, 1)
    return new_state, msg_key


# ---------------------------------------------------------------------------
# Protocol documentation
# ---------------------------------------------------------------------------
'''
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLASSICAL PROTOCOLS (not PQC — broken by Shor's algorithm or linear attacks)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HKEX-GF (key exchange over GF(2^n)*):
  Alice:  C  = g^a;   sk = C2^a = g^{ab}
  Bob:    C2 = g^b;   sk = C^b  = g^{ab}
  Break:  Shor's algorithm recovers a from C=g^a in O(n^2 log n) quantum time.

HSKE (symmetric key encryption, linear):
  Encrypt: E = fscx_revolve(P,  key, i)
  Decrypt: D = fscx_revolve(E,  key, r)  [i = n/4, r = 3n/4]
  Break:   One known-plaintext pair recovers key via GF(2) linear algebra.

HPKS (Schnorr-like signature, linear challenge):
  Sign:    k random; R=g^k; e=fscx_revolve(R,P,I); s=(k-a*e) mod ord
  Verify:  g^s * C^e == R;  C = g^a
  Break:   DLP recovers a; linear challenge is preimage-vulnerable.

HPKE (El Gamal + fscx_revolve, linear encryption):
  Bob:     r random; R=g^r; enc=C^r; E=fscx_revolve(P,enc,I)
  Alice:   dec=R^a=enc;     D=fscx_revolve(E,dec,R)
  Break:   DLP recovers a; HSKE sub-protocol has linear key recovery.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PQC-HARDENED PROTOCOLS (v1.5.0, C3 hybrid — see SecurityProofs-2.md §11)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HSKE-NL-A1 (counter-mode HSKE with NL-FSCX v1):
  Nonce:    N = random(n bits)   [per-session; transmitted alongside ciphertext]
  base      = K XOR N            [session key base]
  keystream[i] = nl_fscx_revolve_v1(ROL(base, n/8), base XOR i, n/4)
  Encrypt:  C = (N, P XOR keystream[0])
  Decrypt:  base = K XOR N; P = C XOR keystream[0]
  Security: per-session nonce ensures distinct keystreams across sessions;
            NL non-linearity defeats linear key-recovery. Assumes NL-FSCX v1 as PRF.

HSKE-NL-A2 (revolve-mode HSKE with NL-FSCX v2):
  Encrypt:  E = nl_fscx_revolve_v2(P, K, r)
  Decrypt:  D = nl_fscx_revolve_v2_inv(E, K, r)  [closed-form inverse]
  Security: B-channel non-linearity defeats linear key-recovery on K.
            API-compatible with classical HSKE (same encrypt/decrypt shape).
  CAUTION:  Deterministic — same (P, K) always yields the same E. Not IND-CPA
            in the multi-message sense without a nonce in P. Prefer HSKE-NL-A1
            when multiple messages may be encrypted under the same key.

HKEX-RNL (Ring-LWR key exchange — quantum-resistant):
  Setup:    a_rand random; m_blind = m(x) + a_rand  [m(x)=1+x+x^{n-1}]
  Alice:    s_A small private; C_A = round_p(m_blind * s_A)
  Bob:      s_B small private; C_B = round_p(m_blind * s_B)
  Agree:    K_poly_A = s_A * lift(C_B);  hint_A = rnl_hint(K_poly_A)
            K_raw_A = reconcile(K_poly_A, hint_A)  [Alice: reconciler]
            K_raw_B = reconcile(K_poly_B, hint_A)  [Bob: uses Alice's hint]
  KDF:      seed = ROL(K_raw, n/8); sk = nl_fscx_revolve_v1(seed, K_raw, n/4)
  Security: Reduces to Ring-LWR on R_q = Z_q[x]/(x^n+1); no known quantum
            polynomial-time attack.  a_rand blinding = standard Ring-LWR hardness.
  Parameters: n=256, q=65537, p=4096, pp=4, eta=1 (CBD(1) secret distribution).

HPKS-NL (Schnorr + NL-FSCX v1 challenge):
  Sign:    k random; R=g^k; e=nl_fscx_revolve_v1(R,P,I); s=(k-a*e) mod ord
  Verify:  g^s * C^e == R;  C = g^a
  Note:    GF(2^n)* DLP still applies (Shor's); NL challenge hardens the
           fscx-specific linear preimage attack on e.

HPKE-NL (El Gamal + NL-FSCX v2):
  Bob:     r random; R=g^r; enc=C^r; E=nl_fscx_revolve_v2(P,enc,I)
  Alice:   dec=R^a=enc;     D=nl_fscx_revolve_v2_inv(E,dec,R)
  Note:    GF(2^n)* DLP still applies; NL encryption hardens the HSKE
           sub-protocol linear key-recovery attack.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CODE-BASED PQC PROTOCOLS (v1.5.18 — Theorem 17, SecurityProofs-2.md §11.8.4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HPKS-Stern-F (Stern syndrome-decoding signature — replaces HPKS-NL):
  KeyGen:  seed random; e ←{wt-t, len-N}; s = H·e^T  (H generated via NL-FSCX v1 PRF)
  Sign:    Stern 3-challenge ZKP of (e: H·e^T=s, wt(e)=t) + Fiat-Shamir in QROM
  Verify:  Re-derive Fiat-Shamir challenges; check one Stern response per round
  Security: EUF-CMA ≤ q_H/T_SD + ε_PRF (Theorem 17); SD(N,t) is NP-complete [BMvT 1978].
  Parameters: N=n=256, n_rows=128, t=16, rounds=32 (demo; production: ≥ 219 rounds).

HPKE-Stern-F (Niederreiter KEM — replaces HPKE-NL):
  KeyGen:  same as HPKS-Stern-F (seed, e, s=H·e^T)
  Encap:   e' ←{wt-t}; K = Hash(seed, e'); ciphertext c = H·e'^T
  Decap:   decode c to find e' (brute-force for demo; QC-MDPC for production); K = Hash(seed, e')
  Security: K indistinguishable from random given c, since finding e' from H·e'^T = c
            is SD(N,t) hardness.  Requires QC-MDPC decoder for production (N=256, t=16).
'''


def main():
    poly = GF_POLY.get(KEYBITS, 0x00000425)

    a         = BitArray.random(KEYBITS)   # Alice's private scalar (GF DH)
    b         = BitArray.random(KEYBITS)   # Bob's private scalar
    preshared = BitArray.random(KEYBITS)
    plaintext = BitArray.random(KEYBITS)
    decoy     = BitArray.random(KEYBITS)   # Eve's random value

    # HKEX-GF key exchange (classical)
    C  = BitArray(KEYBITS, gf_pow(GF_GEN, a.uint, poly, KEYBITS))
    C2 = BitArray(KEYBITS, gf_pow(GF_GEN, b.uint, poly, KEYBITS))
    sk = BitArray(KEYBITS, gf_pow(C2.uint, a.uint, poly, KEYBITS))
    sk_bob_val = gf_pow(C.uint, b.uint, poly, KEYBITS)

    print(f"a         : {a.hex}")
    print(f"b         : {b.hex}")
    print(f"preshared : {preshared.hex}")
    print(f"plaintext : {plaintext.hex}")
    print(f"decoy     : {decoy.hex}")
    print(f"C         : {C.hex}")
    print(f"C2        : {C2.hex}")

    # ── CLASSICAL protocols ──────────────────────────────────────────────────
    print(f"\n--- HKEX-GF [CLASSICAL — not PQC; Shor's algorithm breaks DLP]")
    print(f"    (DH over GF(2^{KEYBITS})*)")
    print(f"sk (Alice): {sk.hex}")
    sk_bob = BitArray(KEYBITS, sk_bob_val)
    print(f"sk (Bob)  : {sk_bob.hex}")
    if sk == sk_bob:
        print("+ session keys agree!")
    else:
        print("- session keys differ!")

    print("\n--- HSKE [CLASSICAL — not PQC; linear key recovery from 1 KPT pair]")
    print("    (fscx_revolve symmetric encryption)")
    E_hske = fscx_revolve(plaintext, preshared, I_VALUE)
    print(f"P (plain) : {plaintext.hex}")
    print(f"E (Alice) : {E_hske.hex}")
    D_hske = fscx_revolve(E_hske, preshared, R_VALUE)
    print(f"D (Bob)   : {D_hske.hex}")
    if D_hske == plaintext:
        print("+ plaintext correctly decrypted")
    else:
        print("- decryption failed!")

    print("\n--- HPKS [CLASSICAL — not PQC; DLP + linear challenge]")
    print("    (Schnorr-like with fscx_revolve challenge)")
    k_s   = BitArray.random(KEYBITS)
    R_s   = BitArray(KEYBITS, gf_pow(GF_GEN, k_s.uint, poly, KEYBITS))
    e_s   = fscx_revolve(R_s, plaintext, I_VALUE)
    s_s   = (k_s.uint - a.uint * e_s.uint) % ORD
    e_v   = fscx_revolve(R_s, plaintext, I_VALUE)
    lhs   = gf_mul(gf_pow(GF_GEN, s_s, poly, KEYBITS),
                   gf_pow(C.uint, e_v.uint, poly, KEYBITS), poly, KEYBITS)
    print(f"P (msg)        : {plaintext.hex}")
    print(f"R [Alice,sign] : {R_s.hex}")
    print(f"e [Alice,sign] : {e_s.hex}")
    print(f"s [Alice,sign] : {s_s:0{KEYBITS//4}x}")
    print(f"  [Bob,verify] : g^s·C^e = {lhs:0{KEYBITS//4}x}")
    if lhs == R_s.uint:
        print(f"  [Bob,verify] : + Schnorr verified: g^s · C^e == R")
    else:
        print(f"  [Bob,verify] : - Schnorr verification failed!")

    print("\n--- HPKE [CLASSICAL — not PQC; DLP + linear HSKE sub-protocol]")
    print("    (El Gamal + fscx_revolve)")
    r_hpke   = BitArray.random(KEYBITS)
    R_hpke   = BitArray(KEYBITS, gf_pow(GF_GEN, r_hpke.uint, poly, KEYBITS))
    enc_key  = BitArray(KEYBITS, gf_pow(C.uint, r_hpke.uint, poly, KEYBITS))
    E_hpke   = fscx_revolve(plaintext, enc_key, I_VALUE)
    dec_key  = BitArray(KEYBITS, gf_pow(R_hpke.uint, a.uint, poly, KEYBITS))
    D_hpke   = fscx_revolve(E_hpke, dec_key, R_VALUE)
    print(f"P (plain) : {plaintext.hex}")
    print(f"E (Bob)   : {E_hpke.hex}")
    print(f"D (Alice) : {D_hpke.hex}")
    if D_hpke == plaintext:
        print("+ plaintext correctly decrypted")
    else:
        print("- decryption failed!")

    # ── PQC-HARDENED protocols ───────────────────────────────────────────────
    print("\n--- HSKE-NL-A1 [PQC-HARDENED — counter-mode with NL-FSCX v1]")
    counter    = 0
    N_a1       = BitArray.random(KEYBITS)                         # per-session nonce
    base_a1    = BitArray(KEYBITS, preshared.uint ^ N_a1.uint)   # K XOR N
    ks_a1      = nl_fscx_revolve_v1(
                    BitArray(KEYBITS, base_a1.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
                    BitArray(KEYBITS, base_a1.uint ^ counter),
                    KEYBITS // 4)
    E_a1 = BitArray(KEYBITS, plaintext.uint ^ ks_a1.uint)
    D_a1 = BitArray(KEYBITS, E_a1.uint ^ ks_a1.uint)
    print(f"N (nonce) : {N_a1.hex}")
    print(f"P (plain) : {plaintext.hex}")
    print(f"E (Alice) : {E_a1.hex}")
    print(f"D (Bob)   : {D_a1.hex}")
    if D_a1 == plaintext:
        print("+ plaintext correctly decrypted")
    else:
        print("- decryption failed!")

    print("\n--- HSKE-NL-A2 [PQC-HARDENED — revolve-mode with NL-FSCX v2]")
    E_a2 = nl_fscx_revolve_v2(plaintext, preshared, R_VALUE)
    D_a2 = nl_fscx_revolve_v2_inv(E_a2, preshared, R_VALUE)
    print(f"P (plain) : {plaintext.hex}")
    print(f"E (Alice) : {E_a2.hex}")
    print(f"D (Bob)   : {D_a2.hex}")
    if D_a2 == plaintext:
        print("+ plaintext correctly decrypted")
    else:
        print("- decryption failed!")

    print("\n--- HKEX-RNL [PQC — Ring-LWR key exchange; conjectured quantum-resistant]")
    print("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=256, q=65537 — may be slow)")
    n_rnl    = KEYBITS
    m_base   = _rnl_m_poly(n_rnl)
    a_rand   = _rnl_rand_poly(n_rnl, RNLQ)         # session random, public
    m_blind  = _rnl_poly_add(m_base, a_rand, RNLQ) # blinded polynomial
    s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP, RNLB)
    s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP, RNLB)
    K_raw_A, hint_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS)
    K_raw_B          = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS, hint_A)
    sk_rnl_A = nl_fscx_revolve_v1(
        BitArray(KEYBITS, K_raw_A.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
        K_raw_A, KEYBITS // 4)
    sk_rnl_B = nl_fscx_revolve_v1(
        BitArray(KEYBITS, K_raw_B.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
        K_raw_B, KEYBITS // 4)
    print(f"sk (Alice): {sk_rnl_A.hex}")
    print(f"sk (Bob)  : {sk_rnl_B.hex}")
    if K_raw_A == K_raw_B:
        print("+ raw key bits agree; shared session key established!")
    else:
        bits_diff = bin(K_raw_A.uint ^ K_raw_B.uint).count('1')
        print(f"- raw key disagrees ({bits_diff} bit(s)) — reconciliation failed!")

    print("\n--- HPKS-NL [NL-hardened Schnorr — NL-FSCX v1 challenge]")
    print("    (GF DLP still present; NL hardens linear challenge preimage)")
    k_nl   = BitArray.random(KEYBITS)
    R_nl   = BitArray(KEYBITS, gf_pow(GF_GEN, k_nl.uint, poly, KEYBITS))
    e_nl   = nl_fscx_revolve_v1(R_nl, plaintext, I_VALUE)
    s_nl   = (k_nl.uint - a.uint * e_nl.uint) % ORD
    e_nl_v = nl_fscx_revolve_v1(R_nl, plaintext, I_VALUE)
    lhs_nl = gf_mul(gf_pow(GF_GEN, s_nl, poly, KEYBITS),
                    gf_pow(C.uint, e_nl_v.uint, poly, KEYBITS), poly, KEYBITS)
    print(f"P (msg)        : {plaintext.hex}")
    print(f"R [Alice,sign] : {R_nl.hex}")
    print(f"e [Alice,sign] : {e_nl.hex}")
    print(f"s [Alice,sign] : {s_nl:0{KEYBITS//4}x}")
    print(f"  [Bob,verify] : g^s·C^e = {lhs_nl:0{KEYBITS//4}x}")
    if lhs_nl == R_nl.uint:
        print(f"  [Bob,verify] : + HPKS-NL verified: g^s · C^e == R")
    else:
        print(f"  [Bob,verify] : - HPKS-NL verification failed!")

    print("\n--- HPKE-NL [NL-hardened El Gamal — NL-FSCX v2 encryption]")
    print("    (GF DLP still present; NL hardens linear HSKE sub-protocol)")
    r_nl     = BitArray.random(KEYBITS)
    R_nl2    = BitArray(KEYBITS, gf_pow(GF_GEN, r_nl.uint, poly, KEYBITS))
    enc_nl   = BitArray(KEYBITS, gf_pow(C.uint, r_nl.uint, poly, KEYBITS))
    E_nl     = nl_fscx_revolve_v2(plaintext, enc_nl, I_VALUE)
    dec_nl   = BitArray(KEYBITS, gf_pow(R_nl2.uint, a.uint, poly, KEYBITS))
    D_nl     = nl_fscx_revolve_v2_inv(E_nl, dec_nl, I_VALUE)
    print(f"P (plain) : {plaintext.hex}")
    print(f"E (Bob)   : {E_nl.hex}")
    print(f"D (Alice) : {D_nl.hex}")
    if D_nl == plaintext:
        print("+ plaintext correctly decrypted")
    else:
        print("- decryption failed!")

    print("\n--- HPKS-Stern-F [PQC — Stern SD signature; EUF-CMA ≤ SD(N,t) + NL-FSCX PRF]")
    print(f"    (n={KEYBITS}, N={KEYBITS}, t={SDFT}, rounds={SDFR}; soundness=(2/3)^{SDFR})")
    sf_seed, sf_e, sf_syn = stern_f_keygen(KEYBITS)
    sf_sig  = hpks_stern_f_sign(plaintext, sf_e, sf_seed, sf_syn)
    sf_ok   = hpks_stern_f_verify(plaintext, sf_sig, sf_seed, sf_syn)
    print(f"seed     : {sf_seed.hex[:32]}…")
    print(f"syndrome : {sf_syn:0{KEYBITS//4}x}"[:50] + "…")
    print(f"msg      : {plaintext.hex[:32]}…")
    print(f"sig      : {len(sf_sig[0])} rounds, challenge bits {sf_sig[1][:8]}…")
    if sf_ok:
        print("+ HPKS-Stern-F signature verified")
    else:
        print("- HPKS-Stern-F verification FAILED")

    print("\n--- HPKE-Stern-F [PQC — Niederreiter KEM; brute-force demo at n=32]")
    print("    (N=32, t=2; C(32,2)=496 candidates; production requires QC-MDPC decoder)")
    sf32_seed, _sf32_e, _sf32_syn = stern_f_keygen(32)
    sf32_K_enc, sf32_ct = hpke_stern_f_encap(sf32_seed, 32)
    sf32_K_dec = hpke_stern_f_decap(sf32_ct, 0, sf32_seed, 32)  # e_int=0 → brute-force
    print(f"K (encap): {sf32_K_enc.hex}")
    print(f"K (decap): {sf32_K_dec.hex if sf32_K_dec else 'decode failed'}")
    if sf32_K_dec is not None and sf32_K_dec == sf32_K_enc:
        print("+ HPKE-Stern-F session keys agree (n=32, brute-force)")
    else:
        print("- HPKE-Stern-F key agreement FAILED (n=32)")

    print("\n--- HPKE-Stern-F [PQC — Niederreiter KEM; known-e' demo at n=256]")
    print(f"    (N={KEYBITS}, t={KEYBITS//16}; known e' passed to decap — production decoder not included)")
    sf256_seed, _sf256_e, _sf256_syn = stern_f_keygen(KEYBITS)
    sf256_K_enc, sf256_ct, sf256_ep = hpke_stern_f_encap_with_e(sf256_seed, KEYBITS)
    sf256_K_dec = hpke_stern_f_decap(sf256_ct, sf256_ep, sf256_seed, KEYBITS)
    print(f"K (encap): {sf256_K_enc.hex[:32]}…")
    print(f"K (decap): {sf256_K_dec.hex[:32] + '…' if sf256_K_dec else 'decode failed'}")
    if sf256_K_dec is not None and sf256_K_dec == sf256_K_enc:
        print("+ HPKE-Stern-F session keys agree (n=256, known-e')")
    else:
        print("- HPKE-Stern-F key agreement FAILED (n=256)")

    print("\n--- HPKS-Stern-Ring [PQC — OR-composed Stern SD ring sig; ring-anonymous, EUF-CMA ≤ SD]")
    _ring_k = 3
    _ring_rounds = SDFR
    print(f"    (n={KEYBITS}, N={KEYBITS}, t={SDFT}, rounds={_ring_rounds}, ring_size={_ring_k})")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _ring_keys = [stern_f_keygen(KEYBITS) for _ in range(_ring_k)]
    _ring_pub = [(s, syn) for s, _, syn in _ring_keys]
    _ring_j   = 1                      # signer is ring member 1
    _ring_e   = _ring_keys[_ring_j][1]  # secret key of member 1
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _ring_sig = hpks_stern_ring_sign(plaintext, _ring_e, _ring_j, _ring_pub)
    _ring_ok  = hpks_stern_ring_verify(plaintext, _ring_sig, _ring_pub)
    print(f"signed as: member {_ring_j} (identity concealed from verifier)")
    print(f"sig: {_ring_k} members × {_ring_rounds} rounds = "
          f"{_ring_k * _ring_rounds} round-triples")
    if _ring_ok:
        print("+ HPKS-Stern-Ring signature verified")
    else:
        print("- HPKS-Stern-Ring verification FAILED")

    # ── HFSCX-256-DM ─────────────────────────────────────────────────────────
    print("\n--- HFSCX-256-DM [HASH — Merkle-Damgård over NL-FSCX v1, Davies-Meyer; 256-bit output]")
    _tv = b"HFSCX-256 test vector"
    _bare = hfscx_256(_tv)
    _mac_iv = BitArray(KEYBITS, preshared.uint ^ int.from_bytes(_HFSCX256_IV_BYTES, 'big'))
    _keyed  = hfscx_256(_tv, iv=_mac_iv)
    print(f"digest (bare)  : {_bare.hex()}")
    print(f"digest (keyed) : {_keyed.hex()}")
    print(f"+ hash length correct ({len(_bare)} bytes)")
    print("+ keyed ≠ bare (key influences output)" if _bare != _keyed
          else "- keyed == bare (unexpected!)")

    # ── ZKP-RNL: Ring-LWR Σ-protocol ────────────────────────────────────────
    print("\n--- ZKP-RNL [PROOF — Ring-LWR Σ-protocol, Fiat-Shamir; n=32]")
    _zkprnl_n = 32
    _zkprnl_q = RNLQ
    _zkprnl_p = RNLP
    _zkprnl_m_base = _rnl_m_poly(_zkprnl_n)
    _zkprnl_a_rand = _rnl_rand_poly(_zkprnl_n, _zkprnl_q)
    _zkprnl_m      = _rnl_poly_add(_zkprnl_m_base, _zkprnl_a_rand, _zkprnl_q)
    _zkprnl_s, _zkprnl_C = _rnl_keygen(_zkprnl_m, _zkprnl_n, _zkprnl_q, _zkprnl_p, RNLB)
    _zkprnl_msg = b"ZKP-RNL test message"
    _zkprnl_w, _zkprnl_c, _zkprnl_z = rnl_sigma_sign(
        _zkprnl_s, _zkprnl_m, _zkprnl_C, _zkprnl_n, _zkprnl_msg)
    _zkprnl_ok = rnl_sigma_verify(
        _zkprnl_m, _zkprnl_C, _zkprnl_n, _zkprnl_msg,
        _zkprnl_w, _zkprnl_c, _zkprnl_z)
    print(f"proof (w[0]={_zkprnl_w[0]}, c-nonzero={sum(1 for x in _zkprnl_c if x)}, "
          f"z[0]={_zkprnl_z[0]})")
    print(f"+ ZKP-RNL proof verified" if _zkprnl_ok else "- ZKP-RNL verify FAILED")

    # ── ZKP-NL: NL-FSCX ZKBoo ───────────────────────────────────────────────
    print(f"\n--- ZKP-NL [PROOF — NL-FSCX ZKBoo, MPC-in-the-head; n={_ZKP_NL_DEFAULT_N}, R={_ZKP_NL_DEMO_ROUNDS}]")
    _zkpnl_A, _zkpnl_B, _zkpnl_y = zkp_nl_keygen(_ZKP_NL_DEFAULT_N)
    _zkpnl_msg = b"ZKP-NL test message"
    _zkpnl_proof = zkp_nl_prove(
        _zkpnl_A, _zkpnl_B, _zkpnl_y,
        _ZKP_NL_DEFAULT_N, _ZKP_NL_DEMO_ROUNDS, _zkpnl_msg)
    _zkpnl_ok = zkp_nl_verify(
        _zkpnl_B, _zkpnl_y, _ZKP_NL_DEFAULT_N,
        _ZKP_NL_DEMO_ROUNDS, _zkpnl_msg, _zkpnl_proof)
    print(f"keypair: A=0x{_zkpnl_A:0{_ZKP_NL_DEFAULT_N//4}x}, "
          f"B=0x{_zkpnl_B:0{_ZKP_NL_DEFAULT_N//4}x}, "
          f"y=0x{_zkpnl_y:0{_ZKP_NL_DEFAULT_N//4}x}")
    print(f"proof rounds: {len(_zkpnl_proof)}, "
          f"view size: {len(_zkpnl_proof[0]['view_p1'])} bytes each")
    print(f"+ ZKP-NL proof verified" if _zkpnl_ok else "- ZKP-NL verify FAILED")
    print(f"  (demo uses R={_ZKP_NL_DEMO_ROUNDS}; production requires R={_ZKP_NL_PROD_ROUNDS} for 128-bit soundness)")

    # ── Eve bypass tests ─────────────────────────────────────────────────────
    print(f"\n\n*** EVE bypass TESTS")

    print(f"*** HPKS-NL — Eve cannot forge Schnorr without knowing private key a")
    R_eve   = BitArray(KEYBITS, gf_pow(GF_GEN,
                                       BitArray.random(KEYBITS).uint, poly, KEYBITS))
    e_eve   = nl_fscx_revolve_v1(R_eve, decoy, I_VALUE)
    s_eve   = BitArray.random(KEYBITS).uint
    lhs_eve = gf_mul(gf_pow(GF_GEN, s_eve,     poly, KEYBITS),
                     gf_pow(C.uint,  e_eve.uint, poly, KEYBITS), poly, KEYBITS)
    if lhs_eve == R_eve.uint:
        print("+ Eve forged HPKS-NL signature (Eve wins)!")
    else:
        print("- Eve could not forge: g^s_eve · C^e_eve ≠ R_eve  (DLP protection)")

    print(f"*** HPKE-NL — Eve cannot decrypt without Alice's private key")
    eve_key = C ^ R_nl2
    D_eve   = nl_fscx_revolve_v2_inv(E_nl, eve_key, I_VALUE)
    if D_eve == plaintext:
        print("+ Eve decrypted plaintext (Eve wins)!")
    else:
        print("- Eve could not decrypt without Alice's private key (CDH + NL protection)")

    print(f"*** HKEX-RNL — Eve cannot derive shared key from public ring polynomials")
    # Eve knows (C_A, C_B, a_rand, m_blind) but not s_A or s_B.
    # Naive attack: lift C_A and try to invert m_blind to recover s_A.
    # The rounding noise amplification (||m_blind^{-1}||_1 >> q) defeats this.
    # For the bypass test we just show that a random BitArray guess does not match.
    eve_rnl_guess = BitArray.random(KEYBITS)
    if eve_rnl_guess == sk_rnl_A:
        print("+ Eve guessed HKEX-RNL shared key (astronomically unlikely)!")
    else:
        print("- Eve random guess does not match shared key (Ring-LWR protection)")

    print(f"*** HPKS-Stern-F — Eve cannot forge without solving SD(N,t)")
    # Eve constructs a fake signature with random responses; must fail verification.
    # (She cannot generate consistent Stern commitments without knowing e.)
    fake_rounds = SDFR
    fake_pi_seed = BitArray.random(KEYBITS)
    fake_y  = int.from_bytes(os.urandom(KEYBITS // 8), 'big') & ((1 << KEYBITS) - 1)
    fake_c1 = _stern_hash(KEYBITS, fake_pi_seed, BitArray(KEYBITS, 0))
    fake_c2 = _stern_hash(KEYBITS, BitArray(KEYBITS, fake_y))
    fake_c3 = _stern_hash(KEYBITS, BitArray(KEYBITS, fake_y ^ 1))
    fake_commits = [(fake_c1, fake_c2, fake_c3)] * fake_rounds
    fake_challenges = [0] * fake_rounds
    fake_responses  = [(fake_pi_seed, fake_y)] * fake_rounds
    eve_sf_sig = (fake_commits, fake_challenges, fake_responses)
    if hpks_stern_f_verify(decoy, eve_sf_sig, sf_seed, sf_syn):
        print("+ Eve forged HPKS-Stern-F (Eve wins)!")
    else:
        print("- Eve could not forge: Fiat-Shamir challenges mismatch  (SD + PRF protection)")

    print(f"*** HPKE-Stern-F — Eve cannot derive session key from syndrome ciphertext")
    # Eve sees (sf32_seed, sf32_ct) but not sf32_e. She guesses K randomly.
    eve_K_guess = BitArray.random(32)
    if sf32_K_dec is not None and eve_K_guess == sf32_K_dec:
        print("+ Eve guessed HPKE-Stern-F session key (astronomically unlikely)!")
    else:
        print("- Eve random guess does not match session key (SD protection)")

    print("*** FPE (78.A) — format-preserving encrypt/decrypt round-trip")
    fpe_key = b"herradura-fpe-key-256bit-example"
    fpe_ctx = b"record:42"
    fpe_plain = BitArray.random(KEYBITS)
    fpe_ct  = fpe_encrypt(fpe_plain, fpe_key, fpe_ctx)
    fpe_rec = fpe_decrypt(fpe_ct,   fpe_key, fpe_ctx)
    if fpe_rec == fpe_plain:
        print("- FPE round-trip correct")
    else:
        print("+ FPE round-trip failed!")

    print("*** Tweakable cipher (78.B) — sector-block encrypt/decrypt")
    twk_key   = b"herradura-twk-key-256bit-example"
    twk_plain = BitArray.random(KEYBITS)
    twk_ct  = twk_encrypt(twk_plain, twk_key, sector=7, bidx=3)
    twk_rec = twk_decrypt(twk_ct,   twk_key, sector=7, bidx=3)
    if twk_rec == twk_plain:
        print("- Tweakable cipher round-trip correct")
    else:
        print("+ Tweakable cipher round-trip failed!")

    print("*** Accumulator (78.J) — Merkle root + proof/verify for 4 leaves")
    leaf_hashes = [haccum_leaf(f"leaf{i}".encode()) for i in range(4)]
    acc_root   = haccum_root(leaf_hashes)
    acc_proof  = haccum_prove(leaf_hashes, 2)
    ok         = haccum_verify(acc_root, leaf_hashes[2], acc_proof, 2)
    ok_wrong   = haccum_verify(acc_root, leaf_hashes[0], acc_proof, 2)
    if ok and not ok_wrong:
        print("- Accumulator proof/verify correct")
    else:
        print("+ Accumulator proof/verify failed!")

    # 78.H — Masked HSKE demo
    hske_plain = BitArray.random(KEYBITS)
    hske_key   = BitArray.random(KEYBITS)
    hske_ct, _  = hske_encrypt_masked(hske_plain, hske_key)
    hske_rec, _ = hske_decrypt_masked(hske_ct,   hske_key)
    if hske_rec.uint == hske_plain.uint:
        print("- Masked HSKE encrypt/decrypt correct")
    else:
        print("+ Masked HSKE encrypt/decrypt failed!")

    # 78.C — Ratchet demo (5 steps)
    ratchet_seed = b"demo-seed-78c"
    state = ratchet_init(ratchet_seed)
    keys  = []
    for _ in range(5):
        state, mk = ratchet_advance(state)
        keys.append(mk)
    if len(set(keys)) == 5:
        print("- Ratchet: 5 distinct message keys")
    else:
        print("+ Ratchet: duplicate message keys!")

    print("*** Ring signature (78.I) — Eve cannot forge without solving SD for any ring member")
    # Eve constructs a fake ring sig with random responses; must fail challenge consistency.
    _eve_ring_pub = _ring_pub    # same public ring from the ring sig demo above
    _eve_all_c = [[(BitArray.random(KEYBITS), BitArray.random(KEYBITS),
                    BitArray.random(KEYBITS)) for _ in range(_ring_rounds)]
                  for _ in range(_ring_k)]
    _eve_all_b = [[0] * _ring_rounds for _ in range(_ring_k)]
    _eve_all_r = [[(BitArray.random(KEYBITS).uint, 0)] * _ring_rounds
                  for _ in range(_ring_k)]
    _eve_ring_sig = (_eve_all_c, _eve_all_b, _eve_all_r)
    if hpks_stern_ring_verify(decoy, _eve_ring_sig, _eve_ring_pub):
        print("+ Eve forged ring signature (Eve wins!)")
    else:
        print("- Eve cannot forge: challenge-sum mismatch  (SD + PRF protection)")


hkex_rnl_keygen = _rnl_keygen   # (m_blind, n, q, p, b) -> (s, C)
hkex_rnl_agree  = _rnl_agree    # (s, C_other, q, p, pp, n, key_bits, hint=None) -> (K, hint) or K

if __name__ == '__main__':
    main()
