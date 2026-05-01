'''
    Herradura Cryptographic Suite v1.5.20

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

    --- v1.5.20: HPKE-Stern-F N=256 known-e' demo; multi-size standardization ---
    --- v1.5.18: HPKS-Stern-F / HPKE-Stern-F — code-based PQC (SD + NL-FSCX v1 PRF) ---

    Adds HPKS-Stern-F (Stern identification + Fiat-Shamir, §11.8.4) and HPKE-Stern-F
    (Niederreiter KEM). Security of HPKS-Stern-F reduces to SD(N,t) [NP-complete,
    BMvT 1978] plus NL-FSCX v1 PRF — the only complete chain to a studied hard
    problem in the suite (Theorem 17, SecurityProofs.md §11.8.4).
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
'''

import itertools
import os
import random


# ---------------------------------------------------------------------------
# Global parameters
# ---------------------------------------------------------------------------

# Key size in bits — must be a positive multiple of 8.
# Change to use a different parameter width; I_VALUE and R_VALUE scale automatically.
KEYBITS = 256
I_VALUE = KEYBITS // 4       # 64  for 256-bit
R_VALUE = 3 * KEYBITS // 4   # 192 for 256-bit
ORD     = (1 << KEYBITS) - 1  # order of GF(2^n)* (for Schnorr integer arithmetic)

# HKEX-RNL Ring-LWR parameters (see SecurityProofs.md §11.4)
# q=65537 (Fermat prime, fast arithmetic) gives lower noise-to-margin ratio than
# q=3329 (Kyber), ensuring reliable single-block agreement at the cost of larger
# keys.  Production deployment should add reconciliation hints (NewHope-style).
RNLQ  = 65537  # prime modulus (2^16 + 1)
RNLP  = 4096   # public-key rounding modulus
RNLPP = 2      # reconciliation modulus (1 bit extracted per ring coefficient)
RNLB  = 1      # centered-binomial eta=1: secret coefficients drawn from CBD(1) in {-1,0,1}

# HPKS-Stern-F / HPKE-Stern-F code-based PQC parameters (SecurityProofs.md §11.8.4)
SDFNR = KEYBITS // 2           # parity-check rows (syndrome bits; [N, N/2, t] code, N=KEYBITS)
SDFT  = max(2, KEYBITS // 16)  # error weight t (= 16 at n=256; ≥ 2 at all widths)
SDFR  = 32                     # Fiat-Shamir rounds (32 → ~19-bit soundness; production: ≥ 219)


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
    """base^exp in GF(2^n)* via repeated squaring. O(n log exp) ops."""
    result = 1; base &= (1 << n) - 1
    while exp:
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
    """Iterate nl_fscx_v2 *steps* times (B held constant)."""
    result = A.copy()
    for _ in range(steps):
        result = nl_fscx_v2(result, B)
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
    """Lift from Z_{from_p} to Z_{to_q} by integer scaling (c -> c * to_q // from_p)."""
    return [c * to_q // from_p % to_q for c in poly]

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
    """Centered binomial distribution CBD(eta): each coefficient = a - b (mod q)
    where a = popcount of eta random bits, b = popcount of next eta random bits.
    Matches the Kyber/NIST PQC secret-distribution baseline for eta=2 or eta=3."""
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
    """Peikert cross-rounding: 1-bit hint per coefficient.
    h[i] = floor((4*c + q/2) / q) % 4 % 2  (0 if c near 0 or q/2, 1 if near q/4 or 3q/4)"""
    return [((4 * c + q // 2) // q) % 4 % 2 for c in K_poly]

def _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits):
    """Extract key bits using Peikert cross-rounding hint. Both parties call with
    the same hint (from the reconciler) and their own K_poly to guarantee agreement."""
    val = 0
    qh = q // 2
    for i, (c, h) in enumerate(zip(K_poly[:key_bits], hint[:key_bits])):
        b = ((2 * c + h * qh + qh) // q) % pp
        if b:
            val |= (1 << i)
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
    Receiver path (hint provided): use hint, return K_raw."""
    C_lifted = _rnl_lift(C_other, p, q)
    K_poly   = _rnl_poly_mul(s, C_lifted, q, n)
    if hint is None:
        hint = _rnl_hint(K_poly, q)
        return BitArray(key_bits, _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits)), hint
    return BitArray(key_bits, _rnl_reconcile_bits(K_poly, hint, q, pp, key_bits))


# ---------------------------------------------------------------------------
# HPKS-Stern-F / HPKE-Stern-F — Code-Based PQC (Syndrome Decoding + NL-FSCX PRF)
# Security reduces to SD(N,t) [NP-complete] + NL-FSCX v1 PRF.  See §11.8.4.
# ---------------------------------------------------------------------------

def _stern_hash(n: int, *items: 'BitArray') -> 'BitArray':
    """Chain-hash items to n bits: h ← NL-FSCX_v1^{n/4}(h⊕v, ROL(v,n/8)) for each v."""
    mask = (1 << n) - 1
    h = BitArray(n, 0)
    for item in items:
        v = item if isinstance(item, BitArray) else BitArray(n, int(item) & mask)
        h = nl_fscx_revolve_v1(h ^ v, v.rotated(n // 8), n // 4)
    return h


def _stern_matrix_row(seed_int: int, row: int, n: int) -> 'BitArray':
    """Row *row* of public parity-check matrix H: F_seed(row) via NL-FSCX v1 PRF."""
    seed = BitArray(n, seed_int)
    A0   = BitArray(n, seed_int ^ row).rotated(n // 8)
    return nl_fscx_revolve_v1(A0, seed, n // 4)


def _stern_syndrome(seed_int: int, e_int: int, n: int, n_rows: int) -> int:
    """Compute n_rows-bit syndrome s = H·e^T mod 2."""
    s = 0
    for i in range(n_rows):
        row = _stern_matrix_row(seed_int, i, n)
        s  |= (bin(row.uint & e_int).count('1') & 1) << i
    return s


def _stern_gen_perm(pi_seed: 'BitArray', N: int) -> list:
    """Fisher-Yates shuffle of [0..N-1] driven by NL-FSCX v1 PRNG."""
    n    = pi_seed._size
    key  = pi_seed.rotated(n // 8)
    perm = list(range(N))
    st   = pi_seed.copy()
    for i in range(N - 1, 0, -1):
        st = nl_fscx_v1(st, key)
        perm[i], perm[st.uint % (i + 1)] = perm[st.uint % (i + 1)], perm[i]
    return perm


def _stern_apply_perm(perm: list, v_int: int, N: int) -> int:
    """Apply permutation perm to N-bit integer v: result[perm[i]] = v[i]."""
    result = 0
    for i in range(N):
        if (v_int >> i) & 1:
            result |= 1 << perm[i]
    return result


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
    e_int  = sum(1 << p for p in random.sample(range(n), t))
    return seed, e_int, _stern_syndrome(seed.uint, e_int, n, n_rows)


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

    commits    = []
    round_data = []
    for _ in range(rounds):
        r_int   = sum(1 << p for p in random.sample(range(n), t))  # weight-t blinding
        y_int   = (e_int ^ r_int) & ((1 << n) - 1)                # y = e ⊕ r
        pi_seed = BitArray.random(n)
        perm    = _stern_gen_perm(pi_seed, n)
        Hr  = _stern_syndrome(seed.uint, r_int, n, n_rows)
        sr  = _stern_apply_perm(perm, r_int, n)
        sy  = _stern_apply_perm(perm, y_int, n)
        commits.append((_stern_hash(n, pi_seed, BitArray(n, Hr)),
                        _stern_hash(n, BitArray(n, sr)),
                        _stern_hash(n, BitArray(n, sy))))
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

    for i, b in enumerate(challenges):
        c0, c1, c2 = commits[i]
        resp = responses[i]
        if b == 0:                                        # reveal (σ(r), σ(y))
            sr, sy = resp
            if _stern_hash(n, BitArray(n, sr)) != c1:          return False
            if _stern_hash(n, BitArray(n, sy)) != c2:          return False
            if bin(sr).count('1') != t:                        return False
        elif b == 1:                                      # reveal (σ_seed, r)
            pi_seed, r_int = resp
            if bin(r_int).count('1') != t:                     return False
            perm = _stern_gen_perm(pi_seed, n)
            Hr   = _stern_syndrome(seed.uint, r_int, n, n_rows)
            if _stern_hash(n, pi_seed, BitArray(n, Hr)) != c0: return False
            sr   = _stern_apply_perm(perm, r_int, n)
            if _stern_hash(n, BitArray(n, sr)) != c1:          return False
        else:                                             # reveal (σ_seed, y)
            pi_seed, y_int = resp
            perm = _stern_gen_perm(pi_seed, n)
            Hy   = _stern_syndrome(seed.uint, y_int, n, n_rows)
            if _stern_hash(n, pi_seed, BitArray(n, Hy ^ syndrome)) != c0: return False
            sy   = _stern_apply_perm(perm, y_int, n)
            if _stern_hash(n, BitArray(n, sy)) != c2:          return False
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
    e_p    = sum(1 << p for p in random.sample(range(n), t))
    ct     = _stern_syndrome(seed.uint, e_p, n, n_rows)
    K      = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)))
    return K, ct


def hpke_stern_f_decap(ciphertext: int, e_int: int, seed: 'BitArray',
                       n: int = None):
    """HPKE-Stern-F decapsulation.

    Two paths:
    - Known-e' (e_int != 0): derive K directly from the encapsulation error.
      Use when the caller holds the plaintext error (test/demo) or a QC-MDPC
      decoder has already recovered it.
    - Brute-force (e_int == 0): enumerate all weight-t candidates.
      Practical only for N ≤ 64, t ≤ 4.  Production requires QC-MDPC.
    Returns session key K or None if decode fails.
    """
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    if e_int:
        return _stern_hash(n, seed, BitArray(n, e_int & ((1 << n) - 1)))
    for pos in itertools.combinations(range(n), t):
        e_p = sum(1 << p for p in pos)
        if _stern_syndrome(seed.uint, e_p, n, n_rows) == ciphertext:
            return _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)))
    return None


def hpke_stern_f_encap_with_e(seed: 'BitArray', n: int = None):
    """Like hpke_stern_f_encap but also returns the plaintext error e_p."""
    if n is None: n = KEYBITS
    n_rows = n // 2
    t      = max(2, n // 16)
    e_p    = sum(1 << p for p in random.sample(range(n), t))
    ct     = _stern_syndrome(seed.uint, e_p, n, n_rows)
    K      = _stern_hash(n, seed, BitArray(n, e_p & ((1 << n) - 1)))
    return K, ct, e_p


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
PQC-HARDENED PROTOCOLS (v1.5.0, C3 hybrid — see SecurityProofs.md §11)
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
  Parameters: n=256, q=65537, p=4096, pp=2, eta=1 (CBD(1) secret distribution).

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
CODE-BASED PQC PROTOCOLS (v1.5.18 — Theorem 17, SecurityProofs.md §11.8.4)
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
    ks_a1      = nl_fscx_revolve_v1(base_a1.rotated(KEYBITS // 8),  # seed=ROL(base,n/8)
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
    sk_rnl_A = nl_fscx_revolve_v1(K_raw_A.rotated(KEYBITS // 8), K_raw_A, KEYBITS // 4)
    sk_rnl_B = nl_fscx_revolve_v1(K_raw_B.rotated(KEYBITS // 8), K_raw_B, KEYBITS // 4)
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


if __name__ == '__main__':
    main()
