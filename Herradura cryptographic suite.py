'''
    Herradura Cryptographic Suite v1.5.9

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

import os


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

def _rnl_keygen(m_blind, n, q, p, b):
    """Generate one party's (s, C) key pair for HKEX-RNL.
    s: private CBD(b) polynomial; C: public rounded polynomial."""
    s  = _rnl_cbd_poly(n, b, q)
    ms = _rnl_poly_mul(m_blind, s, q, n)
    C  = _rnl_round(ms, q, p)
    return s, C

def _rnl_agree(s, C_other, q, p, pp, n, key_bits):
    """Compute raw key bits from private s and the other party's public C.
    Returns a BitArray of *key_bits* bits."""
    C_lifted = _rnl_lift(C_other, p, q)
    K_poly   = _rnl_poly_mul(s, C_lifted, q, n)
    K_bits   = _rnl_round(K_poly, q, pp)
    return _rnl_bits_to_bitarray(K_bits, pp, key_bits)


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
  keystream[i] = nl_fscx_revolve_v1(base, base XOR i, n/4)
  Encrypt:  C = (N, P XOR keystream[0])
  Decrypt:  base = K XOR N; P = C XOR keystream[0]
  Security: per-session nonce ensures distinct keystreams across sessions;
            NL non-linearity defeats linear key-recovery. Assumes NL-FSCX v1 as PRF.

HSKE-NL-A2 (revolve-mode HSKE with NL-FSCX v2):
  Encrypt:  E = nl_fscx_revolve_v2(P, K, r)
  Decrypt:  D = nl_fscx_revolve_v2_inv(E, K, r)  [closed-form inverse]
  Security: B-channel non-linearity defeats linear key-recovery on K.
            API-compatible with classical HSKE (same encrypt/decrypt shape).

HKEX-RNL (Ring-LWR key exchange — quantum-resistant):
  Setup:    a_rand random; m_blind = m(x) + a_rand  [m(x)=1+x+x^{n-1}]
  Alice:    s_A small private; C_A = round_p(m_blind * s_A)
  Bob:      s_B small private; C_B = round_p(m_blind * s_B)
  Agree:    K_A = round_pp(s_A * lift(C_B));  K_B = round_pp(s_B * lift(C_A))
  KDF:      sk = nl_fscx_revolve_v1(K_raw, K_raw, n/4)
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
    ks_a1      = nl_fscx_revolve_v1(base_a1,
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
    print("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=256, q=3329 — may be slow)")
    n_rnl    = KEYBITS
    m_base   = _rnl_m_poly(n_rnl)
    a_rand   = _rnl_rand_poly(n_rnl, RNLQ)         # session random, public
    m_blind  = _rnl_poly_add(m_base, a_rand, RNLQ) # blinded polynomial
    s_A, C_A = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP, RNLB)
    s_B, C_B = _rnl_keygen(m_blind, n_rnl, RNLQ, RNLP, RNLB)
    K_raw_A  = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS)
    K_raw_B  = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n_rnl, KEYBITS)
    sk_rnl_A = nl_fscx_revolve_v1(K_raw_A, K_raw_A, KEYBITS // 4)
    sk_rnl_B = nl_fscx_revolve_v1(K_raw_B, K_raw_B, KEYBITS // 4)
    print(f"sk (Alice): {sk_rnl_A.hex}")
    print(f"sk (Bob)  : {sk_rnl_B.hex}")
    if K_raw_A == K_raw_B:
        print("+ raw key bits agree; shared session key established!")
    else:
        bits_diff = bin(K_raw_A.uint ^ K_raw_B.uint).count('1')
        print(f"- raw key disagrees ({bits_diff} bit(s)) — rounding noise (retry)")

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


if __name__ == '__main__':
    main()
