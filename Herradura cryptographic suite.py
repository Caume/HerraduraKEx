'''
    Herradura Cryptographic Suite v1.4.0

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

    --- v1.4.0: HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The broken fscx_revolve_n-based HKEX is replaced with HKEX-GF: a correct
    Diffie-Hellman key exchange over the multiplicative group GF(2^n)*.

    fscx_revolve_n has been removed entirely from all protocol code.

    HKEX-GF protocol:
    - Pre-agreed: generator g=3 (polynomial x+1), irreducible poly p(x)
    - Alice: private scalar a -> public C = g^a in GF(2^n)*
    - Bob:   private scalar b -> public C2 = g^b
    - Shared key: sk = C2^a = C^b = g^{ab}  (DH commutativity in GF(2^n)*)
    Security rests on the hardness of DLP in GF(2^n)*, not on orbit structure.

    Protocol stack:
    - HKEX: replaced with GF DH (above)
    - HSKE: fscx_revolve(P, key, i) / fscx_revolve(E, key, r) — unchanged
    - HPKS: Schnorr-like signature with fscx_revolve challenge.
            Sign:   k random; R=g^k; e=fscx_revolve(R,P,I); s=(k-a*e) mod ord
            Verify: g^s * C^e == R  (public key C = g^a; anyone can verify)
    - HPKE: El Gamal + fscx_revolve.
            Bob: r ephemeral; R=g^r; enc_key=C^r=g^{ar}; E=fscx_revolve(P,enc_key,I)
            Alice: dec_key=R^a=g^{ar}; D=fscx_revolve(E,dec_key,R)==P

    --- v1.3.2: performance and readability ---

    - BitArray: added rotated(n) non-mutating rotation method (positive = left,
      negative = right); replaces the copy-then-mutate pattern.
    - BitArray: added random() classmethod, consistent with the tests file.
    - fscx: rewritten using rotated(); each term maps directly to the formula
      A^B^ROL(A)^ROL(B)^ROR(A)^ROR(B). No longer mutates its inputs.
    - fscx defined before fscx_revolve for consistent ordering
      with C and Go (definition before first use).
    - Protocol code wrapped in main() with if __name__ == "__main__" guard,
      consistent with the tests file, C, and Go (each has an explicit entry point).
    - KEYBITS, I_VALUE, R_VALUE defined as module-level constants, matching C.
    - BitArray.random() used throughout main(), consistent with tests file.

    --- v1.3: BitArray (multi-byte parameter support) ---

    The Python implementation now uses 256-bit parameters by default, matching
    the C and Go versions at the same bit width.
'''

import os


# Key size in bits — must be a positive multiple of 8.
# Change to use a different parameter width; I_VALUE and R_VALUE scale automatically.
# Equivalent to 256-bit parameters in the C and Go versions.
KEYBITS = 256
I_VALUE = KEYBITS // 4       # 64  for 256-bit
R_VALUE = 3 * KEYBITS // 4   # 192 for 256-bit
ORD     = (1 << KEYBITS) - 1  # order of GF(2^n)* (for Schnorr integer arithmetic)


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
# FSCX functions
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
# GF(2^n) field arithmetic — XOR + left-shift only
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


'''
HKEX-GF (key exchange over GF(2^n)*)
    Pre-agreed: generator g=GF_GEN, irreducible polynomial GF_POLY[n]
    Alice:  private scalar a (random n-bit integer)
            C = g^a in GF(2^n)*
            send C to Bob and receive C2
            sk = C2^a in GF(2^n)*
    Bob:    private scalar b (random n-bit integer)
            C2 = g^b in GF(2^n)*
            send C2 to Alice and receive C
            sk = C^b in GF(2^n)*
    Result: C2^a = (g^b)^a = g^{ab} = (g^a)^b = C^b  (commutativity of GF mult)

HSKE (symmetric key encryption):
    Alice,Bob:  share preshared key of bitlength n
    Alice:  E = fscx_revolve(P, key, i)
            shares E with Bob
    Bob:    P = fscx_revolve(E, key, r)

HPKS (Schnorr-like public key signature — publicly verifiable)
    Alice:  private scalar a (integer), public C = g^a
    Sign(P):
      k  = random nonce scalar
      R  = g^k  in GF(2^n)*                          (commitment)
      e  = fscx_revolve(R_bits, P, I_VALUE)           (challenge via fscx_revolve)
      s  = (k - a * e.uint) mod (2^n - 1)            (Schnorr response)
      signature = (R, s)
    Verify(P, C, sig=(R, s)):
      e  = fscx_revolve(R_bits, P, I_VALUE)           (recompute challenge)
      check: g^s * C^e == R  in GF(2^n)*
    Correctness: g^s * C^e = g^{k-ae} * g^{ae} = g^k = R  ✓
    Security: forging (R, s) without a requires solving DLP for C = g^a.

HPKE (public key encryption — El Gamal + fscx_revolve)
    Alice:  private scalar a, public C = g^a
    Bob:    picks ephemeral r; R = g^r  (ephemeral public)
            enc_key = C^r = g^{ar}     (from Alice's public + Bob's ephemeral private)
            E = fscx_revolve(P, enc_key, I_VALUE)
            sends (R, E) to Alice
    Alice:  dec_key = R^a = g^{ra} = enc_key
            D = fscx_revolve(E, dec_key, R_VALUE) == P
    Security: Eve has (C, R, E). Deriving enc_key = g^{ar} from g^a and g^r is CDH.
'''


def main():
    # Examples with b = KEYBITS bits:
    poly = GF_POLY.get(KEYBITS, 0x00000425)

    a         = BitArray.random(KEYBITS)   # Alice's private scalar
    b         = BitArray.random(KEYBITS)   # Bob's private scalar
    preshared = BitArray.random(KEYBITS)
    plaintext = BitArray.random(KEYBITS)
    decoy     = BitArray.random(KEYBITS)   # Eve's random value (cannot compute sk)

    # HKEX-GF key exchange
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

    print(f"\n--- HKEX-GF (key exchange over GF(2^{KEYBITS})*)")
    print(f"sk (Alice): {sk.hex}")
    sk_bob = BitArray(KEYBITS, sk_bob_val)
    print(f"sk (Bob)  : {sk_bob.hex}")
    if sk == sk_bob:
        print("+ session keys sk (Alice) and sk (Bob) are equal!")
    else:
        print("- session keys sk (Alice) and sk (Bob) are different!")

    print("\n--- HSKE (symmetric key encryption)")
    E = fscx_revolve(plaintext, preshared, I_VALUE)
    print(f"E (Alice) : {E.hex}")
    D = fscx_revolve(E, preshared, R_VALUE)
    print(f"D (Bob)   : {D.hex}")
    if D == plaintext:
        print("+ plaintext is correctly decrypted from E with preshared key")
    else:
        print("- plaintext is different from decrypted E with preshared key!")

    print("\n--- HPKS (Schnorr-like signature: sign with private, verify with public key)")
    # Sign: Alice picks nonce k, commitment R=g^k,
    #       challenge e = fscx_revolve(R, P, I),  response s = (k - a*e) mod ord
    k_s   = BitArray.random(KEYBITS)
    R_s   = BitArray(KEYBITS, gf_pow(GF_GEN, k_s.uint, poly, KEYBITS))
    e_s   = fscx_revolve(R_s, plaintext, I_VALUE)          # challenge via fscx_revolve
    s_s   = (k_s.uint - a.uint * e_s.uint) % ORD           # Schnorr response
    print(f"R (commit): {R_s.hex}")
    print(f"e (fscx)  : {e_s.hex}")
    print(f"s (resp)  : {s_s:0{KEYBITS//4}x}")
    # Verify: anyone with Alice's public key C checks g^s * C^e == R
    e_v   = fscx_revolve(R_s, plaintext, I_VALUE)
    lhs   = gf_mul(gf_pow(GF_GEN, s_s, poly, KEYBITS),
                   gf_pow(C.uint, e_v.uint, poly, KEYBITS),
                   poly, KEYBITS)
    if lhs == R_s.uint:
        print("+ Schnorr verified: g^s · C^e == R  [public key sufficient]")
    else:
        print("- Schnorr verification failed!")

    print("\n--- HPKS (Schnorr) + HSKE: Alice signs the HSKE ciphertext; Bob verifies then decrypts")
    E_hs  = fscx_revolve(plaintext, preshared, I_VALUE)    # HSKE: Alice encrypts P
    k_hs  = BitArray.random(KEYBITS)
    R_hs  = BitArray(KEYBITS, gf_pow(GF_GEN, k_hs.uint, poly, KEYBITS))
    e_hs  = fscx_revolve(R_hs, E_hs, I_VALUE)              # challenge over ciphertext E
    s_hs  = (k_hs.uint - a.uint * e_hs.uint) % ORD
    print(f"E (HSKE)  : {E_hs.hex}")
    print(f"R (commit): {R_hs.hex}")
    print(f"s (resp)  : {s_hs:0{KEYBITS//4}x}")
    # Bob verifies Schnorr on E, then decrypts via HSKE
    e_hv  = fscx_revolve(R_hs, E_hs, I_VALUE)
    lhs_h = gf_mul(gf_pow(GF_GEN, s_hs, poly, KEYBITS),
                   gf_pow(C.uint, e_hv.uint, poly, KEYBITS),
                   poly, KEYBITS)
    D_hs  = fscx_revolve(E_hs, preshared, R_VALUE)         # HSKE: Bob decrypts
    print(f"D (Bob)   : {D_hs.hex}")
    if lhs_h == R_hs.uint and D_hs == plaintext:
        print("+ Schnorr on ciphertext verified; plaintext decrypted correctly!")
    else:
        print("- Schnorr verification or decryption failed!")

    print("\n--- HPKE (public key encryption, El Gamal + fscx_revolve)")
    # Bob generates ephemeral key pair; derives enc_key from Alice's public C
    r       = BitArray.random(KEYBITS)
    R       = BitArray(KEYBITS, gf_pow(GF_GEN, r.uint, poly, KEYBITS))
    enc_key = BitArray(KEYBITS, gf_pow(C.uint,  r.uint, poly, KEYBITS))  # C^r = g^{ar}
    E = fscx_revolve(plaintext, enc_key, I_VALUE)   # Bob encrypts
    print(f"r   (Bob eph priv): {r.hex}")
    print(f"R   (Bob eph pub) : {R.hex}")
    print(f"E   (Bob)         : {E.hex}")
    # Alice derives the same enc_key using her private scalar a and Bob's ephemeral public R
    dec_key = BitArray(KEYBITS, gf_pow(R.uint, a.uint, poly, KEYBITS))   # R^a = g^{ra}
    D = fscx_revolve(E, dec_key, R_VALUE)           # Alice decrypts
    print(f"D   (Alice)       : {D.hex}")
    if D == plaintext:
        print("+ plaintext is correctly decrypted from E with Alice's private key!")
    else:
        print("- plaintext is different from decrypted E with private key!")

    print(f"\n\n*** EVE bypass TESTS")
    print(f"*** HPKS Schnorr — Eve cannot forge without knowing Alice's private key a")
    # Alice's real signature on plaintext:
    real_R = R_s; real_s = s_s
    # Eve wants to forge (R_e, s_e) for decoy so that g^{s_e} * C^{e_e} == R_e
    # where e_e = fscx_revolve(R_e, decoy, I).  Without a, Eve can't compute s_e.
    # Eve's attempt: pick a random R_e and a random s_e, hope the equation holds.
    R_eve   = BitArray(KEYBITS, gf_pow(GF_GEN, BitArray.random(KEYBITS).uint, poly, KEYBITS))
    e_eve   = fscx_revolve(R_eve, decoy, I_VALUE)
    s_eve   = BitArray.random(KEYBITS).uint          # random guess — Eve doesn't know a
    lhs_eve = gf_mul(gf_pow(GF_GEN, s_eve,     poly, KEYBITS),
                     gf_pow(C.uint,  e_eve.uint, poly, KEYBITS),
                     poly, KEYBITS)
    print(f"R_eve (Eve)  : {R_eve.hex}")
    print(f"lhs_eve      : {BitArray(KEYBITS, lhs_eve).hex}")
    print(f"match R_eve? : {lhs_eve == R_eve.uint}")
    if lhs_eve == R_eve.uint:
        print("+ Eve forged Schnorr signature (Eve wins)!")
    else:
        print("- Eve could not forge: g^s_eve · C^e_eve ≠ R_eve  (DLP protection)")

    print(f"\n*** HPKE — Eve cannot decrypt without Alice's private key")
    # Bob encrypted with enc_key = C^r = g^{ar}; sent (R, E).
    # Eve intercepts (R, E) and knows public values (C, R).
    # Eve tries to reconstruct dec_key = R^a using only public values C and R.
    # Eve's best attempt: use C XOR R as a key guess (no math, just public combination).
    eve_key_guess = C ^ R
    print(f"R (Bob eph pub)  : {R.hex}")
    print(f"E (ciphertext)   : {E.hex}")
    print(f"Eve key guess    : {eve_key_guess.hex}")
    D_eve = fscx_revolve(E, eve_key_guess, R_VALUE)
    print(f"D_eve (Eve)      : {D_eve.hex}")
    if D_eve == plaintext:
        print("+ Eve decrypted plaintext (Eve wins)!")
    else:
        print("- Eve could not decrypt without Alice's private key (CDH protection holds)")


if __name__ == '__main__':
    main()
