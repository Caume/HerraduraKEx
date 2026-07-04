'''
    Herradura Cryptographic Suite v1.9.74

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

    --- v1.9.74: HCRED — hybrid Ring-LWR + Stern-F credential, Batch 1 (TODO #128) ---
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
        hske_nl_aead_encrypt, hske_nl_aead_decrypt  (HSKE-NL-AEAD, TODO #95)
        hske_nl_v2_duplex_encrypt, hske_nl_v2_duplex_decrypt  (HSKE-NL-V2-Duplex, TODO #95 Option 2)
        drbg_seed, drbg_generate, drbg_reseed  (HDRBG forward-secure DRBG, TODO #96)
        stern_f_keygen, hpks_stern_f_sign, hpks_stern_f_verify
        hpke_stern_f_encap, hpke_stern_f_decap
        hkex_rnl_keygen, hkex_rnl_agree  (public aliases added in v1.7.4)
        rnl_sigma_sign, rnl_sigma_verify  (ZKP-RNL: Ring-LWR Σ-protocol)
        zkp_nl_keygen, zkp_nl_prove, zkp_nl_verify  (ZKP-NL: NL-FSCX ZKBoo)
        hcred_phi, hcred_user_keygen, hcred_syndrome, hcred_issue,
        hcred_cred_verify, hcred_prove, hcred_verify  (HCRED hybrid credential, TODO #128)
        oprf_keygen, oprf_blind, oprf_eval, oprf_unblind, oprf_direct  (OPRF: 2HashDH over GF(2^n)*)
        hpake_register, hpake_login_demo  (aPAKE: HKEX-RNL + ZKBoo + OPRF augmented PAKE)

    Key module constants: KEYBITS, I_VALUE, R_VALUE, GF_POLY, GF_GEN, ORD,
        RNLQ, RNLP, RNLPP, RNLB, SDFNR, SDFT, SDFR.

    See docs/TUTORIAL.md for complete per-protocol code examples.
'''

import hmac
import itertools
import math
import os
import random
import secrets
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


def hfscx_256_ds(ds: int, data: bytes, *, iv: 'BitArray | None' = None) -> bytes:
    """HFSCX-256-DS: domain-separated variant — prepends a 1-byte tag before hashing.

    ds=0x01 for generic digest, 0x02 for sign pre-hash, 0x03 for AEAD-MAC.
    Wire-format option (§11.9.7 future hardening, TODO #93).
    """
    return hfscx_256(bytes([ds & 0xFF]) + data, iv=iv)


def hmac_hfscx_256(key: bytes, data: bytes) -> bytes:
    """HMAC-HFSCX-256-DM: HMAC construction over HFSCX-256-DM (§11.9.6).

    Recommended for cross-protocol key reuse.
    HMAC(K, D) = HFSCX-256((K^opad) || HFSCX-256((K^ipad) || D))
    ipad = 0x36 * 32, opad = 0x5C * 32.  Key must be exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("hmac_hfscx_256: key must be 32 bytes")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hfscx_256(ipad + data)
    return hfscx_256(opad + inner)


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
    """Row *row* of public parity-check matrix H: F_seed(row) via NL-FSCX v1 PRF,
    finalized with HFSCX-256 to remove range compression (TODO #88, v1.9.35)."""
    seed = BitArray(n, seed_int)
    A0   = BitArray(n, seed_int ^ row).rotated(n // 8)
    raw  = nl_fscx_revolve_v1(A0, seed, n // 4)
    digest = hfscx_256(raw.bytes)
    return BitArray(n, int.from_bytes(digest, 'big') >> (256 - n))


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
        challenges.append((ch_st.uint & 0xFFFFFFFF) % 3)

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
        if (ch_st.uint & 0xFFFFFFFF) % 3 != b:
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
        joint_b = (ch_st.uint & 0xFFFFFFFF) % 3
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
        joint_b = (ch_st.uint & 0xFFFFFFFF) % 3
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
# HCRED — Hybrid Ring-LWR + Stern-F credential (TODO #128 Batch 1)
# SecurityProofs-3.md §11.10.8 (design), §11.10.9 (binding map φ), §11.10.10
# (implementation notes).
# ---------------------------------------------------------------------------
#
# Statement : "I hold a Ring-LWR secret s matching public key C AND the
#              positive support of s hashes to the issued code syndrome y."
# Public    : (m, C) Ring-LWR pair; (seed_H, y) code statement; weight W.
# Witness   : s ∈ {-1,0,1}^n with C = round_p(m·s) and H·φ(s)^T = y,
#             where φ(s)_i = [s_i = +1] (§11.10.9 positive-support bitmap).
#
# Architecture (two branches, sequential Fiat-Shamir binding):
#   Branch 1 — ZKP-RNL Σ-protocol (rnl_sigma_sign) proves knowledge of s
#              for C; its FS challenge binds the branch-2 commitments.
#   Branch 2 — MPC-in-the-head (ZKBoo-(2,3) over Z_q) proves, WITHOUT
#              revealing e = φ(s):
#                 s_i^3 = s_i                     (ternary membership)
#                 e_i   = (s_i^2 + s_i)·2^{-1}    (support extraction, internal)
#                 Σ_i e_i = W                     (revealed weight, W ≤ w_max)
#                 Σ_i H[r,i]·e_i = Σ_t 2^t·β_{r,t}  (syndrome row sums)
#                 β_{r,t}^2 = β_{r,t},  β_{r,0} = y_r  (parity extraction)
#              e-wires are internal linear wires — never opened; the aux
#              witness bits β (bit-decomposition of the integer row sums,
#              no wraparound since n < q) carry the mod-2 reduction.
#   Issuer   — the credential is an HPKS-Stern-F signature over
#              H(m ‖ C ‖ seed_H ‖ y): forging a presentation for an issued
#              pair requires finding s' satisfying BOTH relations — the
#              §11.10.9 many-solutions attack does not apply.
#
# Batch-1 caveats (SecurityProofs-3.md §11.10.10): the two branches share
# the FS transcript but not a witness commitment — collusion-splitting
# resistance (same-s linkage) requires the BDLOP commitment planned for a
# later batch.  Soundness per branch-2 round is 2/3; production requires
# R = 219 (_ZKP_NL_PROD_ROUNDS).  Demo default n = 32.
# ---------------------------------------------------------------------------

_HCRED_DEFAULT_N      = 32   # demo bit-width (n=256 supported; slow in Python)
_HCRED_DEMO_ROUNDS    = 4    # demo MPCitH repetitions; production: 219


def _hcred_params(n):
    """Return (rows, row_bits, w_max) for HCRED at bit-width n.

    rows     — syndrome rows (n/2, matching the Stern-F demo code rate)
    row_bits — bits to represent an integer row sum in [0, n]
    w_max    — weight acceptance bound: mean + 4σ of Binomial(n, 1/4)
    """
    rows     = n // 2
    row_bits = n.bit_length()          # ceil(log2(n+1)); 6 at n=32, 9 at n=256
    w_max    = int(n / 4 + 4 * math.sqrt(n * 3 / 16))
    return rows, row_bits, w_max


def hcred_phi(s_poly):
    """φ_A: positive-support bitmap of a ternary polynomial (§11.10.9).

    Bit i of the result is 1 iff s_poly[i] == 1 (coefficients stored mod q,
    so -1 is q-1 and never matches)."""
    e = 0
    for i, c in enumerate(s_poly):
        if c == 1:
            e |= 1 << i
    return e


def hcred_user_keygen(m_poly, n):
    """User enrolment keys: Ring-LWR pair (s, C) plus e = φ(s).

    Returns (s_poly, C_poly, e_int)."""
    s, C = _rnl_keygen(m_poly, n, RNLQ, RNLP, RNLB)
    return s, C, hcred_phi(s)


def hcred_syndrome(seed_H, e_int, n):
    """Code syndrome y = H·e^T mod 2 for the credential (rows = n/2).

    seed_H: BitArray public matrix seed (same PRF matrix as Stern-F)."""
    rows = n // 2
    H = _stern_build_H(seed_H.uint, n, rows)
    return _stern_syndrome_H(H, e_int)


def _hcred_ser(vec):
    """Serialize a Z_q coefficient vector for hashing (3 B/coeff)."""
    return b''.join((c % RNLQ).to_bytes(3, 'big') for c in vec)


class _HcredTape:
    """Counter-mode HFSCX-256 expander returning uniform Z_q draws
    (17-bit windows, rejection-sampled)."""

    def __init__(self, seed):
        self._seed = seed
        self._ctr  = 0
        self._buf  = b''
        self._pos  = 0

    def draw(self):
        while True:
            if self._pos + 3 > len(self._buf):
                self._buf = hfscx_256(b'HCRED-tape' + self._seed
                                      + self._ctr.to_bytes(4, 'big'))
                self._ctr += 1
                self._pos = 0
            v = int.from_bytes(self._buf[self._pos:self._pos + 3], 'big') & 0x1FFFF
            self._pos += 3
            if v < RNLQ:
                return v

    def draws(self, k):
        return [self.draw() for _ in range(k)]


def _hcred_mpc_round(s_poly, beta_bits, H_rows, n, rows, row_bits):
    """One MPCitH execution of the branch-2 circuit.

    beta_bits: flat list of rows*row_bits aux witness bits (β values).
    Returns (seeds, sh_s, sh_B, a, b, g, outs) where outs is a dict of
    per-party output-share vectors."""
    q    = RNLQ
    nb   = rows * row_bits
    seeds = [os.urandom(32) for _ in range(3)]
    tp    = [_HcredTape(sd) for sd in seeds]
    sh_s  = [tp[0].draws(n), tp[1].draws(n), None]
    sh_s[2] = [(s_poly[i] - sh_s[0][i] - sh_s[1][i]) % q for i in range(n)]
    sh_B  = [tp[0].draws(nb), tp[1].draws(nb), None]
    sh_B[2] = [(beta_bits[i] - sh_B[0][i] - sh_B[1][i]) % q for i in range(nb)]
    R1 = [t.draws(n) for t in tp]
    R2 = [t.draws(n) for t in tp]
    R3 = [t.draws(nb) for t in tp]

    a = [[0] * n for _ in range(3)]
    b = [[0] * n for _ in range(3)]
    g = [[0] * nb for _ in range(3)]
    for j in range(3):
        k = (j + 1) % 3
        for i in range(n):
            a[j][i] = (sh_s[j][i] * sh_s[j][i] + sh_s[k][i] * sh_s[j][i]
                       + sh_s[j][i] * sh_s[k][i] + R1[j][i] - R1[k][i]) % q
    for j in range(3):
        k = (j + 1) % 3
        for i in range(n):
            b[j][i] = (a[j][i] * sh_s[j][i] + a[k][i] * sh_s[j][i]
                       + a[j][i] * sh_s[k][i] + R2[j][i] - R2[k][i]) % q
        for i in range(nb):
            g[j][i] = (sh_B[j][i] * sh_B[j][i] + sh_B[k][i] * sh_B[j][i]
                       + sh_B[j][i] * sh_B[k][i] + R3[j][i] - R3[k][i]) % q

    outs = _hcred_outputs(sh_s, sh_B, a, b, g, H_rows, n, rows, row_bits)
    return seeds, sh_s, sh_B, a, b, g, outs


def _hcred_outputs(sh_s, sh_B, a, b, g, H_rows, n, rows, row_bits):
    """Per-party linear output shares of the branch-2 circuit."""
    q    = RNLQ
    inv2 = (q + 1) // 2
    outs = {'ter': [], 'bit': [], 'W': [], 'S': [], 'y': []}
    for j in range(3):
        e_j   = [((a[j][i] + sh_s[j][i]) * inv2) % q for i in range(n)]
        o_ter = [(b[j][i] - sh_s[j][i]) % q for i in range(n)]
        o_bit = [(g[j][i] - sh_B[j][i]) % q for i in range(rows * row_bits)]
        o_W   = sum(e_j) % q
        o_S, o_y = [], []
        for r in range(rows):
            acc = 0
            for i in range(n):
                if (H_rows[r] >> i) & 1:
                    acc += e_j[i]
            dec = 0
            for t in range(row_bits):
                dec += (1 << t) * sh_B[j][r * row_bits + t]
            o_S.append((acc - dec) % q)
            o_y.append(sh_B[j][r * row_bits] % q)
        outs['ter'].append(o_ter)
        outs['bit'].append(o_bit)
        outs['W'].append(o_W)
        outs['S'].append(o_S)
        outs['y'].append(o_y)
    return outs


def _hcred_commit(j, seed, aux_s, aux_B, a_j, b_j, g_j, outs, r_idx):
    """Commitment to party j's view in round r_idx."""
    aux = (_hcred_ser(aux_s) + _hcred_ser(aux_B)) if j == 2 else b''
    return hfscx_256(b'HCRED-com' + bytes([j]) + r_idx.to_bytes(2, 'big')
                     + seed + aux + _hcred_ser(a_j) + _hcred_ser(b_j)
                     + _hcred_ser(g_j)
                     + _hcred_ser(outs['ter'][j]) + _hcred_ser(outs['bit'][j])
                     + _hcred_ser([outs['W'][j]]) + _hcred_ser(outs['S'][j])
                     + _hcred_ser(outs['y'][j]))


def _hcred_outputs_ser(outs):
    """Serialize all parties' cleartext output shares for FS hashing."""
    buf = b''
    for j in range(3):
        buf += (_hcred_ser(outs['ter'][j]) + _hcred_ser(outs['bit'][j])
                + _hcred_ser([outs['W'][j]]) + _hcred_ser(outs['S'][j])
                + _hcred_ser(outs['y'][j]))
    return buf


def _hcred_stmt_hash(m_poly, C_poly, seed_H, y_synd, n, msg_bytes):
    """Statement hash binding the full public context (+ presentation msg)."""
    rows = n // 2
    return hfscx_256(b'HCRED-stmt' + n.to_bytes(4, 'big')
                     + _hcred_ser(m_poly) + _hcred_ser(C_poly)
                     + seed_H.bytes + y_synd.to_bytes((rows + 7) // 8, 'big')
                     + msg_bytes)


def _hcred_challenges(stmt, b1_ser, coms_ser, outs_ser, rounds):
    """Branch-2 FS challenge trits, bound to the statement, the branch-1
    transcript, and every branch-2 commitment and output share."""
    seed = hfscx_256(b'HCRED-ch' + stmt + b1_ser + coms_ser + outs_ser)
    out, ctr = [], 0
    while len(out) < rounds:
        blk = hfscx_256(b'HCRED-trit' + seed + ctr.to_bytes(4, 'big'))
        ctr += 1
        for byte in blk:
            if byte < 252 and len(out) < rounds:
                out.append(byte % 3)
    return out


def hcred_prove(s_poly, m_poly, C_poly, seed_H, y_synd, n=None,
                rounds=None, msg_bytes=b''):
    """Produce a compound credential-presentation proof.

    Returns a dict: {'W', 'b1': (w, c, z), 'rounds': [round dicts]}.
    e = φ(s) is never revealed; only its weight W is public.
    Production soundness requires rounds ≥ 219 (_ZKP_NL_PROD_ROUNDS)."""
    if n is None:      n = _HCRED_DEFAULT_N
    if rounds is None: rounds = _HCRED_DEMO_ROUNDS
    rows, row_bits, w_max = _hcred_params(n)
    q = RNLQ

    e_int  = hcred_phi(s_poly)
    W      = bin(e_int).count('1')
    H_rows = _stern_build_H(seed_H.uint, n, rows)
    beta   = []
    for r in range(rows):
        S_r = bin(H_rows[r] & e_int).count('1')
        if (S_r & 1) != ((y_synd >> r) & 1):
            raise ValueError("hcred_prove: witness does not match syndrome y")
        for t in range(row_bits):
            beta.append((S_r >> t) & 1)

    stmt  = _hcred_stmt_hash(m_poly, C_poly, seed_H, y_synd, n, msg_bytes)
    execs = [_hcred_mpc_round(s_poly, beta, H_rows, n, rows, row_bits)
             for _ in range(rounds)]
    coms  = [[_hcred_commit(j, ex[0][j], ex[1][2], ex[2][2],
                            ex[3][j], ex[4][j], ex[5][j], ex[6], ri)
              for j in range(3)] for ri, ex in enumerate(execs)]
    coms_ser = b''.join(b''.join(c) for c in coms)
    outs_ser = b''.join(_hcred_outputs_ser(ex[6]) for ex in execs)

    # Branch 1: ZKP-RNL proof, challenge bound to the branch-2 commitments.
    b1_msg = stmt + hfscx_256(b'HCRED-b1' + coms_ser + outs_ser)
    w1, c1, z1 = rnl_sigma_sign(s_poly, m_poly, C_poly, n, b1_msg)
    b1_ser = (_hcred_ser([x % q for x in w1]) + _hcred_ser(c1)
              + _hcred_ser([x % q for x in z1]))

    chals = _hcred_challenges(stmt, b1_ser, coms_ser, outs_ser, rounds)
    proof_rounds = []
    for ri, ex in enumerate(execs):
        seeds, sh_s, sh_B, a, b, g, outs = ex
        c   = chals[ri]
        cp1 = (c + 1) % 3
        rd  = dict(coms=coms[ri], outs=outs,
                   seed_c=seeds[c], seed_c1=seeds[cp1],
                   a1=a[cp1], b1=b[cp1], g1=g[cp1],
                   aux_s=sh_s[2] if 2 in (c, cp1) else None,
                   aux_B=sh_B[2] if 2 in (c, cp1) else None)
        proof_rounds.append(rd)
    return {'W': W, 'b1': (w1, c1, z1), 'rounds': proof_rounds}


def hcred_verify(m_poly, C_poly, seed_H, y_synd, proof, n=None,
                 rounds=None, msg_bytes=b''):
    """Verify a compound credential-presentation proof."""
    if n is None:      n = _HCRED_DEFAULT_N
    if rounds is None: rounds = _HCRED_DEMO_ROUNDS
    rows, row_bits, w_max = _hcred_params(n)
    q    = RNLQ
    inv2 = (q + 1) // 2
    nb   = rows * row_bits

    W = proof['W']
    if not (1 <= W <= w_max):
        return False
    if len(proof['rounds']) != rounds:
        return False

    stmt = _hcred_stmt_hash(m_poly, C_poly, seed_H, y_synd, n, msg_bytes)
    coms_ser = b''.join(b''.join(rd['coms']) for rd in proof['rounds'])
    outs_ser = b''.join(_hcred_outputs_ser(rd['outs'])
                        for rd in proof['rounds'])

    # Branch 1: ZKP-RNL with the bound challenge message.
    w1, c1, z1 = proof['b1']
    b1_msg = stmt + hfscx_256(b'HCRED-b1' + coms_ser + outs_ser)
    if not rnl_sigma_verify(m_poly, C_poly, n, b1_msg, w1, c1, z1):
        return False
    b1_ser = (_hcred_ser([x % q for x in w1]) + _hcred_ser(c1)
              + _hcred_ser([x % q for x in z1]))

    H_rows = _stern_build_H(seed_H.uint, n, rows)
    chals  = _hcred_challenges(stmt, b1_ser, coms_ser, outs_ser, rounds)

    for ri, rd in enumerate(proof['rounds']):
        c    = chals[ri]
        cp1  = (c + 1) % 3
        outs = rd['outs']
        # 1. Public output sums.
        for i in range(n):
            if (outs['ter'][0][i] + outs['ter'][1][i] + outs['ter'][2][i]) % q:
                return False
        for i in range(nb):
            if (outs['bit'][0][i] + outs['bit'][1][i] + outs['bit'][2][i]) % q:
                return False
        if (outs['W'][0] + outs['W'][1] + outs['W'][2]) % q != W:
            return False
        for r in range(rows):
            if (outs['S'][0][r] + outs['S'][1][r] + outs['S'][2][r]) % q:
                return False
            if ((outs['y'][0][r] + outs['y'][1][r] + outs['y'][2][r]) % q
                    != ((y_synd >> r) & 1)):
                return False
        # 2. Rebuild the two opened parties' tapes and input shares.
        if 2 in (c, cp1) and (rd['aux_s'] is None or rd['aux_B'] is None):
            return False
        t_c, t_c1 = _HcredTape(rd['seed_c']), _HcredTape(rd['seed_c1'])
        sh_s_c  = t_c.draws(n)  if c   != 2 else list(rd['aux_s'])
        sh_B_c  = t_c.draws(nb) if c   != 2 else list(rd['aux_B'])
        sh_s_c1 = t_c1.draws(n)  if cp1 != 2 else list(rd['aux_s'])
        sh_B_c1 = t_c1.draws(nb) if cp1 != 2 else list(rd['aux_B'])
        R1_c,  R2_c,  R3_c  = t_c.draws(n),  t_c.draws(n),  t_c.draws(nb)
        R1_c1, R2_c1, R3_c1 = t_c1.draws(n), t_c1.draws(n), t_c1.draws(nb)
        # 3. Recompute party c's gates using party c+1's wires.
        a_c = [(sh_s_c[i] * sh_s_c[i] + sh_s_c1[i] * sh_s_c[i]
                + sh_s_c[i] * sh_s_c1[i] + R1_c[i] - R1_c1[i]) % q
               for i in range(n)]
        b_c = [(a_c[i] * sh_s_c[i] + rd['a1'][i] * sh_s_c[i]
                + a_c[i] * sh_s_c1[i] + R2_c[i] - R2_c1[i]) % q
               for i in range(n)]
        g_c = [(sh_B_c[i] * sh_B_c[i] + sh_B_c1[i] * sh_B_c[i]
                + sh_B_c[i] * sh_B_c1[i] + R3_c[i] - R3_c1[i]) % q
               for i in range(nb)]
        sh_s3 = [None] * 3; sh_B3 = [None] * 3
        sh_s3[c], sh_s3[cp1] = sh_s_c, sh_s_c1
        sh_B3[c], sh_B3[cp1] = sh_B_c, sh_B_c1
        a3 = [None] * 3; b3 = [None] * 3; g3 = [None] * 3
        a3[c], a3[cp1] = a_c, rd['a1']
        b3[c], b3[cp1] = b_c, rd['b1']
        g3[c], g3[cp1] = g_c, rd['g1']
        # 4. Recompute both opened parties' outputs and commitments.
        for j in (c, cp1):
            e_j   = [((a3[j][i] + sh_s3[j][i]) * inv2) % q for i in range(n)]
            o_ter = [(b3[j][i] - sh_s3[j][i]) % q for i in range(n)]
            o_bit = [(g3[j][i] - sh_B3[j][i]) % q for i in range(nb)]
            o_W   = sum(e_j) % q
            if o_ter != outs['ter'][j] or o_bit != outs['bit'][j] \
                    or o_W != outs['W'][j]:
                return False
            for r in range(rows):
                acc = 0
                for i in range(n):
                    if (H_rows[r] >> i) & 1:
                        acc += e_j[i]
                dec = 0
                for t in range(row_bits):
                    dec += (1 << t) * sh_B3[j][r * row_bits + t]
                if (acc - dec) % q != outs['S'][j][r]:
                    return False
                if sh_B3[j][r * row_bits] % q != outs['y'][j][r]:
                    return False
            aux = ((_hcred_ser(rd['aux_s']) + _hcred_ser(rd['aux_B']))
                   if j == 2 else b'')
            seed_j = rd['seed_c'] if j == c else rd['seed_c1']
            com = hfscx_256(b'HCRED-com' + bytes([j]) + ri.to_bytes(2, 'big')
                            + seed_j + aux + _hcred_ser(a3[j])
                            + _hcred_ser(b3[j]) + _hcred_ser(g3[j])
                            + _hcred_ser(outs['ter'][j])
                            + _hcred_ser(outs['bit'][j])
                            + _hcred_ser([outs['W'][j]])
                            + _hcred_ser(outs['S'][j])
                            + _hcred_ser(outs['y'][j]))
            if com != rd['coms'][j]:
                return False
    return True


def hcred_issue(m_poly, C_poly, seed_H, y_synd, n,
                issuer_e, issuer_seed, issuer_syn,
                issuer_n=None, rounds=None):
    """Issuer: sign the credential pair (m, C, seed_H, y) with HPKS-Stern-F.

    Binding the pair defeats the §11.10.9 self-registered-key forgery:
    a presentation is only accepted for an issuer-signed (C, y)."""
    if issuer_n is None: issuer_n = KEYBITS
    digest = _hcred_stmt_hash(m_poly, C_poly, seed_H, y_synd, n, b'HCRED-issue')
    msg = BitArray(issuer_n, int.from_bytes(digest, 'big') >> (256 - issuer_n))
    return hpks_stern_f_sign(msg, issuer_e, issuer_seed, issuer_syn,
                             issuer_n, rounds)


def hcred_cred_verify(m_poly, C_poly, seed_H, y_synd, n, cred_sig,
                      issuer_seed, issuer_syn, issuer_n=None):
    """Verify the issuer's HPKS-Stern-F signature over (m, C, seed_H, y)."""
    if issuer_n is None: issuer_n = KEYBITS
    digest = _hcred_stmt_hash(m_poly, C_poly, seed_H, y_synd, n, b'HCRED-issue')
    msg = BitArray(issuer_n, int.from_bytes(digest, 'big') >> (256 - issuer_n))
    return hpks_stern_f_verify(msg, cred_sig, issuer_seed, issuer_syn, issuer_n)


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
# 98 — HPKS-T: Threshold / Aggregate Schnorr over GF(2^n)* (TODO #98)
#
# n-of-n MuSig2-style key aggregation with NL-FSCX v1 challenge.
# Rogue-key binding: μ_j = H(L || C_j) mod ord  where L = sorted pubkeys.
# Aggregate key:     C_agg = Π C_j^{μ_j}
# Sign:              R = Π R_j;  e = NL-FSCX v1(R, msg);
#                    s_j = (k_j − a_j·μ_j·e) mod ord;  s = Σ s_j
# Verify:            g^s · C_agg^e == R  (identical to single-party verify)
# ---------------------------------------------------------------------------

def _hpkst_mu_coeff(L_bytes: bytes, C_j: 'BitArray') -> int:
    """μ_j = HFSCX-256(L || C_j_bytes) as integer mod ord."""
    raw = hfscx_256(L_bytes + C_j.uint.to_bytes(KEYBITS // 8, 'big'))
    return int.from_bytes(raw, 'big') % ORD or 1


def hpkst_aggregate_pubkeys(pubkeys: 'list[BitArray]') -> 'tuple[BitArray, list[int]]':
    """
    Compute (C_agg, coefficients) with MuSig2 key-aggregation.
    L = sorted pubkeys byte-strings concatenated.
    C_agg = Π C_j^{μ_j}
    Returns (C_agg BitArray, [μ_j ints]).
    """
    _poly = GF_POLY[KEYBITS]
    L_bytes = b''.join(sorted(pk.uint.to_bytes(KEYBITS // 8, 'big') for pk in pubkeys))
    coeffs  = [_hpkst_mu_coeff(L_bytes, pk) for pk in pubkeys]
    agg_val = 1
    for C_j, mu_j in zip(pubkeys, coeffs):
        agg_val = gf_mul(agg_val,
                         gf_pow(C_j.uint, mu_j, _poly, KEYBITS),
                         _poly, KEYBITS)
    return BitArray(KEYBITS, agg_val), coeffs


def hpkst_sign(secrets: 'list[int]', pubkeys: 'list[BitArray]', msg: 'BitArray') -> 'tuple[BitArray, BitArray, BitArray]':
    """
    n-of-n threshold HPKS-NL sign.

    secrets: [a_j ints] — private scalars for each signer
    pubkeys: [C_j BitArrays] — public keys for each signer
    msg:     BitArray — message (used as second input to NL-FSCX challenge)

    Returns (C_agg, R, s) — the aggregate public key, nonce, and signature scalar.
    Challenge e is implicit (re-derived during verify from R and msg).
    """
    _poly   = GF_POLY[KEYBITS]
    C_agg, coeffs = hpkst_aggregate_pubkeys(pubkeys)
    nonces  = [BitArray.random(KEYBITS) for _ in secrets]
    R_parts = [BitArray(KEYBITS, gf_pow(GF_GEN, k.uint, _poly, KEYBITS)) for k in nonces]
    R_val   = 1
    for R_j in R_parts:
        R_val = gf_mul(R_val, R_j.uint, _poly, KEYBITS)
    R = BitArray(KEYBITS, R_val)
    e = nl_fscx_revolve_v1(R, msg, I_VALUE)
    s_val = 0
    for a_j, k_j, mu_j in zip(secrets, nonces, coeffs):
        s_j = (k_j.uint - a_j * mu_j * e.uint) % ORD
        s_val = (s_val + s_j) % ORD
    return C_agg, R, BitArray(KEYBITS, s_val)


def hpkst_verify(C_agg: 'BitArray', R: 'BitArray', s: 'BitArray', msg: 'BitArray') -> bool:
    """
    Verify a threshold HPKS-NL signature.  Identical to single-party HPKS-NL verify:
    g^s · C_agg^e == R   where e = nl_fscx_revolve_v1(R, msg, I_VALUE).
    """
    _poly = GF_POLY[KEYBITS]
    e   = nl_fscx_revolve_v1(R, msg, I_VALUE)
    lhs = gf_mul(gf_pow(GF_GEN, s.uint, _poly, KEYBITS),
                 gf_pow(C_agg.uint, e.uint, _poly, KEYBITS),
                 _poly, KEYBITS)
    return lhs == R.uint


# ---------------------------------------------------------------------------
# 97 — HPKS-WOTS-F / HPKS-XMSS-F — Hash-based signatures (TODO #97)
#
# Hash chain:  h(x) = nl_fscx_revolve_v1(ROL(x, n/8), x, n/4)
#              (NL-FSCX v1 OWF, Theorem 16, SecurityProofs-2 §11.8.3)
#
# Winternitz parameter w=16 (4 bits per digit):
#   ℓ_msg = ceil(256/4) = 64   (message nibbles)
#   ℓ_cs  = 3                  (checksum in base-16; max = 64*15 = 960 < 16^3)
#   ℓ     = 67                 (total chain count)
#
# XMSS: 2^h Merkle leaves, each leaf is one WOTS keypair.
#   Default h=10 (1024 leaves).  Leaf seed = HFSCX-256(master_seed || idx_be4).
#   Leaf node  = haccum_leaf(pk_0 || pk_1 || ... || pk_{ℓ-1}).
#   XMSS pk    = Merkle root of 2^h leaf nodes.
# ---------------------------------------------------------------------------

_WOTS_W    = 16           # Winternitz width
_WOTS_LOG2W = 4           # log2(_WOTS_W)
_WOTS_L1   = KEYBITS // _WOTS_LOG2W   # 64 — message digits
_WOTS_L2   = 3                         # 3  — checksum digits (ceil(log16(64*15)))
_WOTS_L    = _WOTS_L1 + _WOTS_L2      # 67 — total chains
_XMSS_H    = 10           # default tree height (1024 leaves)


def _wots_h(x: BitArray) -> BitArray:
    """Single WOTS-F hash chain step: h(x) = nl_fscx_revolve_v1(ROL(x,n/8), x, n/4)."""
    n = x._size
    return nl_fscx_revolve_v1(x.rotated(n // 8), x, n // 4)


def _wots_chain(x: BitArray, steps: int) -> BitArray:
    """Apply h exactly `steps` times."""
    for _ in range(steps):
        x = _wots_h(x)
    return x


def _wots_msg_to_digits(msg_hash: bytes) -> list:
    """
    Encode 256-bit message hash as ℓ base-16 digits with checksum.
    Returns list of 67 integers in [0, 15].
    """
    val = int.from_bytes(msg_hash, 'big')
    digits = [(val >> (4 * ((_WOTS_L1 - 1) - i))) & 0xF for i in range(_WOTS_L1)]
    checksum = sum(_WOTS_W - 1 - d for d in digits)
    cs_digits = [(checksum >> (4 * ((_WOTS_L2 - 1) - i))) & 0xF for i in range(_WOTS_L2)]
    return digits + cs_digits


def _wots_leaf_seed(master_seed: bytes, leaf_idx: int, chain_idx: int) -> BitArray:
    """Derive WOTS SK_i for leaf leaf_idx, chain chain_idx from master_seed."""
    raw = hfscx_256(master_seed
                    + leaf_idx.to_bytes(4, 'big')
                    + chain_idx.to_bytes(2, 'big'))
    return BitArray(KEYBITS, int.from_bytes(raw, 'big'))


def hpks_wots_keygen(master_seed: bytes, leaf_idx: int) -> tuple:
    """
    WOTS-F keygen for one leaf.
    Returns (sk_list, pk_list) — each a list of ℓ=67 BitArrays.
    pk_i = h^(w-1)(sk_i).
    """
    sk = [_wots_leaf_seed(master_seed, leaf_idx, i) for i in range(_WOTS_L)]
    pk = [_wots_chain(sk[i], _WOTS_W - 1) for i in range(_WOTS_L)]
    return sk, pk


def hpks_wots_sign(msg: bytes, master_seed: bytes, leaf_idx: int) -> tuple:
    """
    WOTS-F sign.  Returns (sig_list, pk_list).
    sig_i = h^(w-1-d_i)(sk_i); verifier applies h^{d_i} to recover pk_i.
    """
    msg_hash = hfscx_256(msg)
    digits   = _wots_msg_to_digits(msg_hash)
    sk, pk   = hpks_wots_keygen(master_seed, leaf_idx)
    sig      = [_wots_chain(sk[i], _WOTS_W - 1 - digits[i]) for i in range(_WOTS_L)]
    return sig, pk


def hpks_wots_recover_pk(msg: bytes, sig: list) -> list:
    """Apply h^{d_i}(sig_i) to recover the WOTS public key from a signature."""
    msg_hash = hfscx_256(msg)
    digits   = _wots_msg_to_digits(msg_hash)
    return [_wots_chain(sig[i], digits[i]) for i in range(_WOTS_L)]


def hpks_wots_verify(msg: bytes, sig: list, pk: list) -> bool:
    """WOTS-F verify.  Accept iff h^{d_i}(sig_i) == pk_i for all i."""
    recovered = hpks_wots_recover_pk(msg, sig)
    return all(recovered[i].uint == pk[i].uint for i in range(_WOTS_L))


def _wots_pk_bytes(pk: list) -> bytes:
    """Serialise a WOTS public key (list of ℓ BitArrays) to bytes."""
    return b''.join(v.uint.to_bytes(KEYBITS // 8, 'big') for v in pk)


def hpks_xmss_keygen(master_seed: bytes, h: int = _XMSS_H) -> tuple:
    """
    XMSS-F keygen.  Builds a 2^h-leaf Merkle tree of WOTS public keys.
    Returns (master_seed, root_hash, auth_tree) where:
      master_seed — bytes, passed to sign
      root_hash   — 32-byte XMSS public key (Merkle root)
      auth_tree   — list of 2^h leaf hashes (for fast proof generation)
    Caution: slow for large h; demo uses h≤4; production uses h=10.
    """
    num_leaves = 1 << h
    leaf_hashes = []
    for idx in range(num_leaves):
        _, pk = hpks_wots_keygen(master_seed, idx)
        leaf_hashes.append(haccum_leaf(_wots_pk_bytes(pk)))
    root = haccum_root(leaf_hashes)
    return master_seed, root, leaf_hashes


def hpks_xmss_sign(msg: bytes, master_seed: bytes, leaf_hashes: list,
                   leaf_idx: int) -> dict:
    """
    XMSS-F sign at leaf_idx.  Returns signature dict containing:
      leaf_idx  — int
      wots_sig  — list of ℓ BitArrays
      auth_path — list of 32-byte sibling hashes (Merkle proof)
    The WOTS public key is NOT stored in the sig; it is recovered during verify
    by applying the chain h^{d_i}(sig_i).
    """
    wots_sig, _ = hpks_wots_sign(msg, master_seed, leaf_idx)
    auth_path   = haccum_prove(leaf_hashes, leaf_idx)
    return {
        'leaf_idx':  leaf_idx,
        'wots_sig':  wots_sig,
        'auth_path': auth_path,
    }


def hpks_xmss_verify(msg: bytes, sig: dict, root: bytes) -> bool:
    """
    XMSS-F verify.
    1. Recover WOTS pk by applying h^{d_i}(sig_i) for each chain i.
    2. Hash recovered pk bytes into a leaf hash.
    3. Verify Merkle proof against root.
    No stored pk needed — pk is fully determined by (msg, sig).
    """
    recovered_pk = hpks_wots_recover_pk(msg, sig['wots_sig'])
    leaf_hash    = haccum_leaf(_wots_pk_bytes(recovered_pk))
    return haccum_verify(root, leaf_hash, sig['auth_path'], sig['leaf_idx'])


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
# 96 — HDRBG: forward-secure deterministic random bit generator (TODO #96)
#
# Fast-key-erasure pattern (Bernstein 2017) over the NL-FSCX v1 OWF:
#   state_0     = HFSCX-256(b'DRBG-INIT' || len(entropy)_be8 || entropy || pers)
#   output_i    = HFSCX-256(state_i || i_be8 || b'DRBG-OUT')
#   state_{i+1} = nl_fscx_revolve_v1(state_i, DRBG_DOMAIN, n/4)
#   reseed      : state = HFSCX-256(b'DRBG-RESEED' || state || len(entropy)_be8 || entropy)
#
# Backtracking resistance rests on the same OWF conjecture as the #78.C ratchet
# (Theorem 16, SecurityProofs-2 §11.8.3): erasing state_i makes output_i
# irrecoverable from state_{i+1}.  The caller must discard old state objects;
# Python cannot guarantee erasure of immutable ints — for hard erasure
# guarantees use the C implementation.
#
# State-walk collision risk (nl_fscx_v1 is non-bijective) is characterised in
# SecurityProofsCode/nl_fscx_v1_ratchet_collision.py; the per-seed output limit
# DRBG_MAX_BLOCKS keeps walks far below the measured collision distances.
#
# NON-GOALS: this is not a NIST SP 800-90A validated DRBG — no health tests,
# no prediction-resistance requests, no entropy-source assessment.  It is a
# deterministic expander for seeds that are already full-entropy.
# ---------------------------------------------------------------------------

_DRBG_DOMAIN = BitArray(
    KEYBITS,
    int.from_bytes(b'NL-FSCX-DRBG-V1\x00'.ljust(KEYBITS // 8, b'\x00'), 'big')
)
DRBG_MAX_BLOCKS = 1 << 20   # output blocks per seed/reseed (32 MiB) before reseed required


class HDrbg:
    """Forward-secure DRBG state: 256-bit state + output-block counter."""
    __slots__ = ('state', 'blocks')

    def __init__(self, state: BitArray, blocks: int = 0):
        self.state = state
        self.blocks = blocks


def drbg_seed(entropy: bytes, personalization: bytes = b'') -> HDrbg:
    """Instantiate from full-entropy seed material (>= 32 bytes recommended)."""
    h = hfscx_256(b'DRBG-INIT' + len(entropy).to_bytes(8, 'big')
                  + entropy + personalization)
    return HDrbg(BitArray(KEYBITS, int.from_bytes(h, 'big')))


def drbg_generate(drbg: HDrbg, n_bytes: int) -> bytes:
    """Generate n_bytes of output, ratcheting the state once per 32-byte block.
    Raises RuntimeError once DRBG_MAX_BLOCKS is exhausted (reseed required)."""
    n_blocks = (n_bytes + KEYBITS // 8 - 1) // (KEYBITS // 8)
    if drbg.blocks + n_blocks > DRBG_MAX_BLOCKS:
        raise RuntimeError("drbg_generate: output limit reached — call drbg_reseed")
    out = bytearray()
    while len(out) < n_bytes:
        out += hfscx_256(drbg.state.bytes + drbg.blocks.to_bytes(8, 'big')
                         + b'DRBG-OUT')
        drbg.state = nl_fscx_revolve_v1(drbg.state, _DRBG_DOMAIN, I_VALUE)
        drbg.blocks += 1
    return bytes(out[:n_bytes])


def drbg_reseed(drbg: HDrbg, entropy: bytes) -> None:
    """Mix fresh entropy into the state and reset the output-block counter."""
    h = hfscx_256(b'DRBG-RESEED' + drbg.state.bytes
                  + len(entropy).to_bytes(8, 'big') + entropy)
    drbg.state = BitArray(KEYBITS, int.from_bytes(h, 'big'))
    drbg.blocks = 0


# ---------------------------------------------------------------------------
# 95 — HSKE-NL-AEAD: authenticated encryption with associated data (TODO #95)
#
# Encrypt-then-MAC over the HSKE-NL-A1 CTR keystream:
#   base    = K XOR nonce
#   seed    = ROL(base, n/8) XOR RNL_KDF_DC          (KDF degeneracy guard, #38)
#   ks_i    = nl_fscx_revolve_v1(seed, base XOR i, n/4)
#   ct      = pt XOR ks                              (keystream truncated to len(pt))
#   mac_key = nl_fscx_revolve_v1(ROL(seed, n/4), base, n/4)   (domain-separated)
#   tag     = HFSCX-256-MAC(mac_key XOR IV,
#                 DS || nonce || len(ad)_be8 || ad || len(ct)_be8 || ct)
#
# Key-committing: the tag binds mac_key (hence K and nonce) through the
# collision-resistant keyed HFSCX-256-DM, so a ciphertext cannot verify under
# two different keys — a property AES-GCM lacks.  The DS prefix domain-separates
# the tag from the encfile/decfile .hkx MAC, which shares the mac_key schedule.
# Decryption is verify-then-decrypt with a constant-time tag comparison.
# ---------------------------------------------------------------------------

_AEAD_DS = b'HSKE-NL-AEAD-v1'


def _hske_nl_aead_streams(key: BitArray, nonce: BitArray) -> tuple:
    """Derive (base, seed, mac_iv) for one (key, nonce) pair."""
    base    = BitArray(KEYBITS, key.uint ^ nonce.uint)
    seed    = BitArray(KEYBITS, base.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256)
    mac_key = nl_fscx_revolve_v1(seed.rotated(KEYBITS // 4), base, I_VALUE)
    mac_iv  = BitArray(KEYBITS, mac_key.uint ^ int.from_bytes(_HFSCX256_IV_BYTES, 'big'))
    return base, seed, mac_iv


def _hske_nl_aead_xor_keystream(seed: BitArray, base: BitArray, data: bytes) -> bytes:
    """XOR data with the HSKE-NL-A1 CTR keystream (truncated to len(data))."""
    blen = KEYBITS // 8
    out  = bytearray()
    for i in range((len(data) + blen - 1) // blen):
        chunk = data[i * blen:(i + 1) * blen]
        ks    = nl_fscx_revolve_v1(seed, BitArray(KEYBITS, base.uint ^ i), I_VALUE)
        out  += bytes(d ^ k for d, k in zip(chunk, ks.uint.to_bytes(blen, 'big')))
    return bytes(out)


def _hske_nl_aead_tag(mac_iv: BitArray, nonce: BitArray, ad: bytes, ct: bytes) -> bytes:
    """Auth tag over DS || nonce || len(ad) || ad || len(ct) || ct."""
    data = (_AEAD_DS + nonce.uint.to_bytes(KEYBITS // 8, 'big')
            + len(ad).to_bytes(8, 'big') + ad
            + len(ct).to_bytes(8, 'big') + ct)
    return hfscx_256(data, iv=mac_iv)


def hske_nl_aead_encrypt(key: BitArray, pt: bytes, ad: bytes = b'',
                         nonce: 'BitArray | None' = None) -> tuple:
    """AEAD-encrypt pt under key with associated data ad.

    Returns (nonce, ct, tag): nonce is a fresh random 256-bit BitArray unless
    supplied (never reuse a (key, nonce) pair), ct is len(pt) bytes, tag is
    32 bytes."""
    if nonce is None:
        nonce = BitArray.random(KEYBITS)
    base, seed, mac_iv = _hske_nl_aead_streams(key, nonce)
    ct  = _hske_nl_aead_xor_keystream(seed, base, pt)
    tag = _hske_nl_aead_tag(mac_iv, nonce, ad, ct)
    return nonce, ct, tag


def hske_nl_aead_decrypt(key: BitArray, nonce: BitArray, ct: bytes, tag: bytes,
                         ad: bytes = b'') -> 'bytes | None':
    """Verify-then-decrypt.  Returns the plaintext, or None if the tag does not
    authenticate (ct, ad) under (key, nonce).  Tag comparison is constant-time."""
    base, seed, mac_iv = _hske_nl_aead_streams(key, nonce)
    expected = _hske_nl_aead_tag(mac_iv, nonce, ad, ct)
    if not hmac.compare_digest(bytes(tag), expected):
        return None
    return _hske_nl_aead_xor_keystream(seed, base, ct)


# ─────────────────────────────────────────────────────────────────────────────
# 95 Option 2 — HSKE-NL-V2-Duplex: MonkeyDuplex-style single-pass AEAD
#
# Sponge permutation: nl_fscx_revolve_v2(state, tweak, I_VALUE)
#   state: 256-bit, rate=128 bits (first 16 bytes), capacity=128 bits (last 16 bytes)
#   tweak: HFSCX-256("NL-V2-DUPLEX-TWEAK" || key || nonce) — fixed per (key,nonce)
#
# RESEARCH CONSTRUCTION — not for production use without further cryptanalysis.
# Security relies on bijectivity of nl_fscx_revolve_v2 (proven) and the
# branch-number analysis Bn(M^k)>=36 at n=64 (SecurityProofs-1.md §3.4).
# The differential/linear profile of nl_fscx_v2 as a standalone sponge
# permutation has not yet been rigorously analysed (see TODO #95/#99).
# ─────────────────────────────────────────────────────────────────────────────

_V2DPLEX_DS_INIT  = b'NL-V2-DUPLEX-INIT'
_V2DPLEX_DS_TWEAK = b'NL-V2-DUPLEX-TWEAK'
_V2DPLEX_DS_TAG   = b'NL-V2-DUPLEX-TAG'
_V2DPLEX_RATE     = 16   # bytes = 128 bits


def _v2_dplex_perm_bytes(state_b: bytearray, tweak_ba: 'BitArray') -> bytearray:
    """Apply one permutation round: nl_fscx_revolve_v2(state, tweak, I_VALUE)."""
    sa = BitArray(KEYBITS, int.from_bytes(state_b, 'big'))
    r  = nl_fscx_revolve_v2(sa, tweak_ba, I_VALUE)
    return bytearray(r.uint.to_bytes(KEYBITS // 8, 'big'))


def _v2_dplex_init(key: 'BitArray', nonce: 'BitArray') -> tuple:
    """Returns (state: bytearray, tweak: BitArray)."""
    kb = key.uint.to_bytes(KEYBITS // 8, 'big')
    nb = nonce.uint.to_bytes(KEYBITS // 8, 'big')
    state_b = bytearray(hfscx_256(_V2DPLEX_DS_INIT + kb + nb))
    tweak_b = hfscx_256(_V2DPLEX_DS_TWEAK + kb + nb)
    tweak_ba = BitArray(KEYBITS, int.from_bytes(tweak_b, 'big'))
    state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    return state_b, tweak_ba


def _v2_dplex_absorb_ad(state_b: bytearray, tweak_ba: 'BitArray',
                         ad: bytes) -> bytearray:
    """Absorb associated data (length-prefixed, padded) + domain separator."""
    R = _V2DPLEX_RATE
    ad_prefixed = len(ad).to_bytes(8, 'big') + ad
    # Pad to next multiple of R using 0x80 || 0x00...
    rem = len(ad_prefixed) % R
    if rem != 0:
        ad_prefixed += bytes([0x80]) + bytes(R - 1 - rem)
    else:
        ad_prefixed += bytes([0x80]) + bytes(R - 1)
    for i in range(0, len(ad_prefixed), R):
        block = ad_prefixed[i:i + R]
        for j in range(R):
            state_b[j] ^= block[j]
        state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    state_b[R] ^= 0x01          # domain separator: end of AD
    state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    return state_b


def _v2_dplex_enc(state_b: bytearray, tweak_ba: 'BitArray',
                   pt: bytes) -> tuple:
    """Duplex-encrypt pt.  Returns (ct: bytes, state_b: bytearray)."""
    R, ct = _V2DPLEX_RATE, bytearray()
    if not pt:
        state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
        return bytes(ct), state_b
    for off in range(0, len(pt), R):
        block = pt[off:off + R]
        L = len(block)
        ct += bytes(state_b[j] ^ block[j] for j in range(L))
        for j in range(L):
            state_b[j] ^= block[j]
        if L < R:
            state_b[L] ^= 0x80
        state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    return bytes(ct), state_b


def _v2_dplex_dec(state_b: bytearray, tweak_ba: 'BitArray',
                   ct: bytes) -> tuple:
    """Duplex-decrypt ct.  Returns (pt: bytes, state_b: bytearray)."""
    R, pt = _V2DPLEX_RATE, bytearray()
    if not ct:
        state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
        return bytes(pt), state_b
    for off in range(0, len(ct), R):
        block = ct[off:off + R]
        L = len(block)
        pt_block = bytes(state_b[j] ^ block[j] for j in range(L))
        pt += pt_block
        for j in range(L):
            state_b[j] ^= pt_block[j]
        if L < R:
            state_b[L] ^= 0x80
        state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    return bytes(pt), state_b


def _v2_dplex_finalize(state_b: bytearray, tweak_ba: 'BitArray') -> bytes:
    """Apply PT domain separator, final permutation, squeeze 32-byte tag."""
    state_b[_V2DPLEX_RATE] ^= 0x02
    state_b = _v2_dplex_perm_bytes(state_b, tweak_ba)
    return hfscx_256(bytes(state_b) + _V2DPLEX_DS_TAG)


def hske_nl_v2_duplex_encrypt(key: 'BitArray', pt: bytes, ad: bytes = b'',
                               nonce: 'BitArray | None' = None) -> tuple:
    """HSKE-NL-V2-Duplex AEAD encrypt (RESEARCH CONSTRUCTION).

    Returns (nonce, ct, tag).  Never reuse (key, nonce)."""
    if nonce is None:
        nonce = BitArray.random(KEYBITS)
    state_b, tweak_ba = _v2_dplex_init(key, nonce)
    state_b = _v2_dplex_absorb_ad(state_b, tweak_ba, ad)
    ct, state_b = _v2_dplex_enc(state_b, tweak_ba, pt)
    tag = _v2_dplex_finalize(state_b, tweak_ba)
    return nonce, ct, tag


def hske_nl_v2_duplex_decrypt(key: 'BitArray', nonce: 'BitArray', ct: bytes,
                               tag: bytes, ad: bytes = b'') -> 'bytes | None':
    """HSKE-NL-V2-Duplex AEAD decrypt (RESEARCH CONSTRUCTION).

    Returns plaintext or None if tag authentication fails."""
    state_b, tweak_ba = _v2_dplex_init(key, nonce)
    state_b = _v2_dplex_absorb_ad(state_b, tweak_ba, ad)
    pt, state_b = _v2_dplex_dec(state_b, tweak_ba, ct)
    expected = _v2_dplex_finalize(state_b, tweak_ba)
    if not hmac.compare_digest(bytes(tag), expected):
        return None
    return pt


# ---------------------------------------------------------------------------
# 80 — Oblivious PRF (OPRF) over GF(2^n)*  (TODO #80)
#
# F(k, x) = gf_pow(H(x), k)  where  H = HFSCX-256 hash-to-field.
# Oblivious under CDH in GF(2^n)*: the blinded value alpha = H(x)^r
# is computationally indistinguishable from random without knowing x or r.
#
# Protocol: client calls oprf_blind(x) → (r, alpha); sends alpha to server.
#           server calls oprf_eval(alpha, k) → beta; returns beta to client.
#           client calls oprf_unblind(beta, r) → F = H(x)^k = oprf_direct(x, k).
# ---------------------------------------------------------------------------

def oprf_keygen() -> int:
    """Random OPRF server key k in [2, 2^KEYBITS − 2]."""
    while True:
        k = int.from_bytes(os.urandom(KEYBITS // 8), 'big') & ORD
        if 1 < k < ORD:
            return k


def _oprf_hash_to_field(data: bytes) -> int:
    """HFSCX-256(data) → non-zero element of GF(2^KEYBITS)."""
    val = int.from_bytes(hfscx_256(data), 'big') & ORD
    return val if val != 0 else 1


def oprf_blind(x: bytes) -> tuple:
    """Client: hash x and blind with random scalar r.
    Returns (r, alpha) where alpha = H(x)^r in GF(2^KEYBITS)*.
    r is secret (kept by client); alpha is sent to the server."""
    poly = GF_POLY[KEYBITS]
    while True:
        r = int.from_bytes(os.urandom(KEYBITS // 8), 'big') & ORD
        if r > 1 and math.gcd(r, ORD) == 1:
            break
    alpha = gf_pow(_oprf_hash_to_field(x), r, poly, KEYBITS)
    return r, alpha


def oprf_eval(alpha: int, k: int) -> int:
    """Server: evaluate alpha^k in GF(2^KEYBITS)*."""
    return gf_pow(alpha & ORD, k & ORD, GF_POLY[KEYBITS], KEYBITS)


def oprf_unblind(beta: int, r: int) -> int:
    """Client: recover F(k, x) = H(x)^k from beta = H(x)^{kr}.
    Computes beta^{r^{-1} mod ORD}."""
    r_inv = pow(r, -1, ORD)
    return gf_pow(beta & ORD, r_inv, GF_POLY[KEYBITS], KEYBITS)


def oprf_direct(x: bytes, k: int) -> int:
    """Direct PRF evaluation F(k, x) = H(x)^k (server-side; not oblivious)."""
    return gf_pow(_oprf_hash_to_field(x), k & ORD, GF_POLY[KEYBITS], KEYBITS)


# ---------------------------------------------------------------------------
# 80 — aPAKE (augmented PAKE) over HKEX-RNL + ZKBoo + OPRF  (TODO #80 Batch 4)
# OPRF upgrade: server record stores OPRF output F(oprf_key, password) instead
# of a plain password hash, preventing offline dictionary attacks even if the
# server database is compromised (attacker cannot evaluate F without oprf_key).
# ---------------------------------------------------------------------------

_HPAKE_ZKP_N       = 32     # ZKBoo witness width (demo; production: 256)
_HPAKE_ROUNDS      = 16     # ZKBoo rounds (soundness (2/3)^16 ≈ 0.15%; production: 219)
_HPAKE_ZKP_A_LABEL = b"ZKP-A"
_HPAKE_AUTH_LABEL  = b"PAKE-AUTH-v1"
_HPAKE_SESSION_LBL = b"PAKE-SESSION-v1"


def _hpake_derive_zkp_witness(pw_oprf_output: bytes) -> int:
    """Domain-separate a _HPAKE_ZKP_N-bit ZKBoo witness from the OPRF output."""
    mask = (1 << _HPAKE_ZKP_N) - 1
    return int.from_bytes(hfscx_256(pw_oprf_output + _HPAKE_ZKP_A_LABEL), 'big') & mask


def _hpake_rnl_kdf(K_raw: 'BitArray') -> bytes:
    """HKEX-RNL session KDF (matches suite demo pattern)."""
    sk = nl_fscx_revolve_v1(
        BitArray(KEYBITS, K_raw.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
        K_raw, KEYBITS // 4)
    return sk.bytes


def hpake_register(username: str, password: bytes, oprf_key: int) -> dict:
    """
    aPAKE registration.  Returns a server record containing (username, salt, B, y).
    The OPRF output is used as the password hash — server cannot offline-attack
    passwords without the oprf_key.
    username: client identifier (stored in record for lookup).
    password: raw password bytes.
    oprf_key: server OPRF private key (integer from oprf_keygen()).
    """
    salt           = os.urandom(32)
    pw_oprf_out    = oprf_direct(password, oprf_key)
    pw_oprf_bytes  = pw_oprf_out.to_bytes(KEYBITS // 8, 'big')
    zkp_A          = _hpake_derive_zkp_witness(pw_oprf_bytes)
    mask           = (1 << _HPAKE_ZKP_N) - 1
    B              = int.from_bytes(os.urandom(_HPAKE_ZKP_N // 8), 'big') & mask
    y              = nl_fscx_v1(BitArray(_HPAKE_ZKP_N, zkp_A),
                                 BitArray(_HPAKE_ZKP_N, B)).uint
    return {'username': username, 'salt': salt, 'B': B, 'y': y}


def hpake_login_demo(record: dict, password: bytes, oprf_key: int) -> 'bytes | None':
    """
    aPAKE login (both-sides demo — client and server in one call).
    Performs the full 3-message HKEX-RNL + ZKBoo exchange and returns the
    shared session key on success, or None if the password is wrong.
    record:   server record from hpake_register().
    password: raw password bytes (client-side input).
    oprf_key: server OPRF private key (same key used during registration).
    """
    salt, B, y = record['salt'], record['B'], record['y']

    # Client: OPRF evaluation to derive pw_oprf_out
    pw_oprf_out   = oprf_direct(password, oprf_key)
    pw_oprf_bytes = pw_oprf_out.to_bytes(KEYBITS // 8, 'big')
    zkp_A         = _hpake_derive_zkp_witness(pw_oprf_bytes)

    # Fast local verifier check (aborts before ZKBoo if wrong password)
    mask    = (1 << _HPAKE_ZKP_N) - 1
    y_check = nl_fscx_v1(BitArray(_HPAKE_ZKP_N, zkp_A),
                          BitArray(_HPAKE_ZKP_N, B)).uint
    if y_check != y:
        return None

    # Client: ephemeral HKEX-RNL keypair
    m_base  = _rnl_m_poly(KEYBITS)
    a_rand  = _rnl_rand_poly(KEYBITS, RNLQ)
    m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
    s_c, C_c = _rnl_keygen(m_blind, KEYBITS, RNLQ, RNLP, RNLB)

    # Server: ephemeral HKEX-RNL keypair (uses client's m_blind)
    s_s, C_s = _rnl_keygen(m_blind, KEYBITS, RNLQ, RNLP, RNLB)

    # Client: HKEX-RNL reconciliation (generates hint)
    K_raw_c, hint = _rnl_agree(s_c, C_s, RNLQ, RNLP, RNLPP, KEYBITS, KEYBITS)

    # Server: HKEX-RNL reconciliation (uses hint)
    K_raw_s = _rnl_agree(s_s, C_c, RNLQ, RNLP, RNLPP, KEYBITS, KEYBITS, hint)

    # Client: ZKBoo proof of knowledge of zkp_A bound to session key
    auth_msg = K_raw_c.bytes + _HPAKE_AUTH_LABEL
    proof    = zkp_nl_prove(zkp_A, B, y, _HPAKE_ZKP_N, _HPAKE_ROUNDS, auth_msg)

    # Server: ZKBoo verification
    auth_msg_s = K_raw_s.bytes + _HPAKE_AUTH_LABEL
    if not zkp_nl_verify(B, y, _HPAKE_ZKP_N, _HPAKE_ROUNDS, auth_msg_s, proof):
        return None

    # Session key: hfscx_256(KDF(K_raw) ‖ label)
    return hfscx_256(_hpake_rnl_kdf(K_raw_c) + _HPAKE_SESSION_LBL)


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
    n_A              = os.urandom(KEYBITS // 8)   # Alice's contributory nonce
    n_B              = os.urandom(KEYBITS // 8)   # Bob's contributory nonce
    K_raw_A, hint_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS)
    K_raw_B          = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS, hint_A)
    sk_rnl_A = BitArray(KEYBITS, int.from_bytes(
        hfscx_256(K_raw_A.uint.to_bytes(KEYBITS // 8, 'big') + n_A + n_B), 'big'))
    sk_rnl_B = BitArray(KEYBITS, int.from_bytes(
        hfscx_256(K_raw_B.uint.to_bytes(KEYBITS // 8, 'big') + n_A + n_B), 'big'))
    print(f"n_A       : {n_A.hex()}")
    print(f"n_B       : {n_B.hex()}")
    print(f"sk (Alice): {sk_rnl_A.hex}")
    print(f"sk (Bob)  : {sk_rnl_B.hex}")
    if sk_rnl_A == sk_rnl_B:
        print("+ contributory KDF session keys agree!")
    else:
        bits_diff = bin(sk_rnl_A.uint ^ sk_rnl_B.uint).count('1')
        print(f"- session key disagrees ({bits_diff} bit(s)) — reconciliation failed!")

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

    print("\n--- HPKS-T [THRESHOLD — n-of-n MuSig2-style aggregate Schnorr over GF(2^n)*]")
    _t_n = 3  # 3-of-3 demo
    _t_secrets = [BitArray.random(KEYBITS).uint for _ in range(_t_n)]
    _t_pubkeys  = [BitArray(KEYBITS, gf_pow(GF_GEN, a_j, poly, KEYBITS)) for a_j in _t_secrets]
    _t_cagg, _t_R, _t_s = hpkst_sign(_t_secrets, _t_pubkeys, plaintext)
    _t_ok   = hpkst_verify(_t_cagg, _t_R, _t_s, plaintext)
    _t_bad  = hpkst_verify(_t_cagg, _t_R, BitArray(KEYBITS, (_t_s.uint ^ 1)), plaintext)
    if _t_ok and not _t_bad:
        print(f"+ HPKS-T {_t_n}-of-{_t_n} sign/verify correct, tamper rejected")
    else:
        print(f"- HPKS-T FAILED: ok={_t_ok} bad={_t_bad}")

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

    # ── HPKS-XMSS-F (TODO #97, h=3 demo: 8 leaves) ──────────────────────────
    print("\n--- HPKS-XMSS-F [PQC — hash-based many-time sig; WOTS-F chains + Merkle tree]")
    _xmss_seed = secrets.token_bytes(32)
    _xmss_h    = 3   # 8 leaves — fast demo; production uses h=10
    _xmss_sk, _xmss_root, _xmss_leaves = hpks_xmss_keygen(_xmss_seed, _xmss_h)
    _xmss_msg  = b"HPKS-XMSS-F test message"
    _xmss_sig  = hpks_xmss_sign(_xmss_msg, _xmss_sk, _xmss_leaves, leaf_idx=0)
    _xmss_ok   = hpks_xmss_verify(_xmss_msg, _xmss_sig, _xmss_root)
    # tamper rejection: wrong message
    _xmss_bad  = hpks_xmss_verify(b"tampered", _xmss_sig, _xmss_root)
    # second leaf with same tree
    _xmss_sig2 = hpks_xmss_sign(_xmss_msg, _xmss_sk, _xmss_leaves, leaf_idx=1)
    _xmss_ok2  = hpks_xmss_verify(_xmss_msg, _xmss_sig2, _xmss_root)
    # one-time reuse: reusing leaf 0 signature on a different message should fail
    _xmss_reuse = hpks_xmss_verify(b"different message", _xmss_sig, _xmss_root)
    if _xmss_ok and not _xmss_bad and _xmss_ok2 and not _xmss_reuse:
        print(f"+ HPKS-XMSS-F sign/verify correct (h={_xmss_h}, 2 distinct leaves, "
              f"tamper rejected, OTS reuse rejected)")
    else:
        print(f"- HPKS-XMSS-F FAILED: ok={_xmss_ok} bad={_xmss_bad} "
              f"ok2={_xmss_ok2} reuse={_xmss_reuse}")

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
    print(f"\n--- ZKP-RNL [PROOF — Ring-LWR Σ-protocol, Fiat-Shamir; n={KEYBITS}]")
    _zkprnl_n = KEYBITS
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

    # ── HCRED: Hybrid Ring-LWR + Stern-F credential ─────────────────────────
    _hc_n = _HCRED_DEFAULT_N
    print(f"\n--- HCRED [CREDENTIAL — Ring-LWR + code syndrome via φ, MPCitH; "
          f"n={_hc_n}, R={_HCRED_DEMO_ROUNDS}]")
    _hc_m = _rnl_poly_add(_rnl_m_poly(_hc_n),
                          _rnl_rand_poly(_hc_n, RNLQ), RNLQ)
    _hc_seedH = BitArray.random(_hc_n)
    _hc_s, _hc_C, _hc_e = hcred_user_keygen(_hc_m, _hc_n)
    _hc_y = hcred_syndrome(_hc_seedH, _hc_e, _hc_n)
    _hc_iseed, _hc_ie, _hc_isyn = stern_f_keygen(_hc_n)
    _hc_cred = hcred_issue(_hc_m, _hc_C, _hc_seedH, _hc_y, _hc_n,
                           _hc_ie, _hc_iseed, _hc_isyn,
                           issuer_n=_hc_n, rounds=SDFR)
    _hc_cok = hcred_cred_verify(_hc_m, _hc_C, _hc_seedH, _hc_y, _hc_n,
                                _hc_cred, _hc_iseed, _hc_isyn,
                                issuer_n=_hc_n)
    _hc_proof = hcred_prove(_hc_s, _hc_m, _hc_C, _hc_seedH, _hc_y,
                            _hc_n, _HCRED_DEMO_ROUNDS, b"HCRED demo nonce")
    _hc_ok = hcred_verify(_hc_m, _hc_C, _hc_seedH, _hc_y, _hc_proof,
                          _hc_n, _HCRED_DEMO_ROUNDS, b"HCRED demo nonce")
    _hc_replay = hcred_verify(_hc_m, _hc_C, _hc_seedH, _hc_y, _hc_proof,
                              _hc_n, _HCRED_DEMO_ROUNDS, b"other nonce")
    print(f"enrolment: W={_hc_proof['W']} (weight of hidden e=φ(s)), "
          f"y=0x{_hc_y:0{_hc_n // 8}x}")
    print(f"+ issuer credential (Stern-F over (m,C,seed_H,y)) verified"
          if _hc_cok else "- issuer credential verify FAILED")
    print(f"+ HCRED presentation proof verified (e never revealed)"
          if _hc_ok else "- HCRED presentation verify FAILED")
    print(f"+ HCRED replay under different nonce rejected"
          if not _hc_replay else "- HCRED replay NOT rejected")
    print(f"  (demo uses R={_HCRED_DEMO_ROUNDS}; production requires "
          f"R={_ZKP_NL_PROD_ROUNDS}; same-witness linkage across branches "
          f"requires the BDLOP batch — see §11.10.10)")

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

    # 96 — HDRBG demo: determinism + reseed separation + forward ratchet
    d1 = drbg_seed(b'demo-entropy-96', b'pers')
    d2 = drbg_seed(b'demo-entropy-96', b'pers')
    out1 = drbg_generate(d1, 64)
    out2 = drbg_generate(d2, 64)
    drbg_reseed(d2, b'fresh-entropy')
    out3 = drbg_generate(d2, 64)
    if out1 == out2 and out3 != drbg_generate(d1, 64) and len(out1) == 64:
        print("- HDRBG determinism + reseed separation correct")
    else:
        print("+ HDRBG failed!")

    # 95 — HSKE-NL-AEAD demo: round-trip + tamper rejection
    aead_key = BitArray.random(KEYBITS)
    aead_pt  = b"HSKE-NL-AEAD demo plaintext (arbitrary length, 47 B)"
    aead_ad  = b"header-v1"
    aead_nonce, aead_ct, aead_tag = hske_nl_aead_encrypt(aead_key, aead_pt, aead_ad)
    aead_dec = hske_nl_aead_decrypt(aead_key, aead_nonce, aead_ct, aead_tag, aead_ad)
    aead_bad = hske_nl_aead_decrypt(aead_key, aead_nonce,
                                    bytes([aead_ct[0] ^ 1]) + aead_ct[1:],
                                    aead_tag, aead_ad)
    aead_bad_ad = hske_nl_aead_decrypt(aead_key, aead_nonce, aead_ct, aead_tag, b"header-v2")
    if aead_dec == aead_pt and aead_bad is None and aead_bad_ad is None:
        print("- HSKE-NL-AEAD round-trip + tamper/AD rejection correct")
    else:
        print("+ HSKE-NL-AEAD failed!")

    # 95 Option 2 — HSKE-NL-V2-Duplex demo (RESEARCH CONSTRUCTION)
    dplex_key   = BitArray.random(KEYBITS)
    dplex_pt    = b"HSKE-NL-V2-Duplex demo plaintext (47 B)"
    dplex_ad    = b"duplex-header-v1"
    dplex_nonce, dplex_ct, dplex_tag = hske_nl_v2_duplex_encrypt(
        dplex_key, dplex_pt, dplex_ad)
    dplex_dec = hske_nl_v2_duplex_decrypt(
        dplex_key, dplex_nonce, dplex_ct, dplex_tag, dplex_ad)
    dplex_bad = hske_nl_v2_duplex_decrypt(
        dplex_key, dplex_nonce,
        bytes([dplex_ct[0] ^ 1]) + dplex_ct[1:], dplex_tag, dplex_ad)
    dplex_bad_ad = hske_nl_v2_duplex_decrypt(
        dplex_key, dplex_nonce, dplex_ct, dplex_tag, b"duplex-header-v2")
    if dplex_dec == dplex_pt and dplex_bad is None and dplex_bad_ad is None:
        print("- HSKE-NL-V2-Duplex round-trip + tamper/AD rejection correct [RESEARCH]")
    else:
        print("+ HSKE-NL-V2-Duplex FAILED!")

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

    print("*** HPKS-XMSS-F — Eve cannot forge without inverting NL-FSCX v1 OWF")
    # Eve tries to forge a WOTS signature on a different message by randomising sig
    _xmss_eve_sig = {
        'leaf_idx':  _xmss_sig['leaf_idx'],
        'wots_sig':  [BitArray.random(KEYBITS) for _ in range(_WOTS_L)],
        'auth_path': _xmss_sig['auth_path'],
    }
    _xmss_eve_ok = hpks_xmss_verify(b"HPKS-XMSS-F test message", _xmss_eve_sig, _xmss_root)
    if _xmss_eve_ok:
        print("+ Eve forged HPKS-XMSS-F (Eve wins!)")
    else:
        print("- Eve cannot forge HPKS-XMSS-F: OWF inversion required")

    print("*** HPKS-XMSS-F — leaf reuse with wrong auth path cannot verify at different index")
    _xmss_reuse_sig = {k: v for k, v in _xmss_sig.items()}
    _xmss_reuse_sig['leaf_idx'] = 1   # wrong index, stale auth path
    _xmss_reuse_ok = hpks_xmss_verify(b"HPKS-XMSS-F test message", _xmss_reuse_sig, _xmss_root)
    if _xmss_reuse_ok:
        print("+ Index-swap accepted (unexpected — audit Merkle proof)")
    else:
        print("- Index-swap correctly rejected: Merkle proof anchors leaf identity")

    # 80 — OPRF demo (blind / eval / unblind round-trip)
    print("*** OPRF (80) — 2HashDH over GF(2^256)*")
    _oprf_k   = oprf_keygen()
    _oprf_pw  = b"oprf-demo-input"
    _oprf_r, _oprf_alpha = oprf_blind(_oprf_pw)
    _oprf_beta  = oprf_eval(_oprf_alpha, _oprf_k)
    _oprf_F     = oprf_unblind(_oprf_beta, _oprf_r)
    _oprf_check = oprf_direct(_oprf_pw, _oprf_k)
    if _oprf_F == _oprf_check:
        print("- OPRF blind/eval/unblind round-trip correct")
    else:
        print("+ OPRF round-trip failed!")
    # aPAKE: OPRF output replaces direct password hash
    _oprf_salt   = os.urandom(32)
    _oprf_pw_key = hfscx_256(_oprf_F.to_bytes(KEYBITS // 8, 'big') + _oprf_salt)
    _oprf_F2     = oprf_direct(_oprf_pw, _oprf_k)
    _oprf_pw_key2 = hfscx_256(_oprf_F2.to_bytes(KEYBITS // 8, 'big') + _oprf_salt)
    if _oprf_pw_key == _oprf_pw_key2:
        print("- OPRF aPAKE: pw_key derived from OPRF output is deterministic")
    else:
        print("+ OPRF aPAKE pw_key mismatch!")

    # 80 — aPAKE demo (register + login with correct password + wrong password)
    print("*** aPAKE (80) — HKEX-RNL + ZKBoo + OPRF augmented PAKE")
    _pake_key     = oprf_keygen()
    _pake_record  = hpake_register("alice", b"s3cr3t-pw", _pake_key)
    _pake_sk      = hpake_login_demo(_pake_record, b"s3cr3t-pw", _pake_key)
    if _pake_sk is not None:
        print("- aPAKE login with correct password: session key established")
    else:
        print("+ aPAKE login with correct password: FAILED!")
    _pake_sk_bad  = hpake_login_demo(_pake_record, b"wrong-pw", _pake_key)
    if _pake_sk_bad is None:
        print("- aPAKE login with wrong password: correctly rejected")
    else:
        print("+ aPAKE login with wrong password: ACCEPTED (security failure)!")


hkex_rnl_keygen = _rnl_keygen   # (m_blind, n, q, p, b) -> (s, C)
hkex_rnl_agree  = _rnl_agree    # (s, C_other, q, p, pp, n, key_bits, hint=None) -> (K, hint) or K

if __name__ == '__main__':
    main()
