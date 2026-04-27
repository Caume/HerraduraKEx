/*  Herradura Cryptographic Suite v1.5.17

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

    --- v1.5.17: NTT twiddle precomputation — lazy-initialized static table eliminates rnl_mod_pow calls per rnl_poly_mul ---

    --- v1.5.13: HSKE-NL-A1 seed fix — ROL(base, n/8) breaks counter=0 step-1 degeneracy ---

    HSKE-NL-A1 keystream: seed = ba_rol_k(base, n/8); ks = nl_fscx_revolve_v1(seed, base^ctr, n/4).
    When A=B=base (counter=0), fscx(base,base)=0 so step 1 was a pure rotation (linear).
    ROL(base,n/8) ensures seed!=base, activating full carry non-linearity from step 1.
    Same degeneracy pattern fixed for HKEX-RNL KDF in v1.5.10; now applied consistently.
    Also fixes stale q=3329 comment (was 65537 since v1.5.4).

    --- v1.5.10: HKEX-RNL KDF seed fix — ROL(K, n/8) breaks step-1 degeneracy ---

    HKEX-RNL KDF: seed = ba_rol_k(K, n/8); sk = nl_fscx_revolve_v1(seed, K, n/4).
    When A0=B=K, fscx(K,K)=0 so step 1 was a pure rotation (linear).
    ROL(K,n/8) ensures seed!=K, activating full carry non-linearity from step 1.

    --- v1.5.9: HSKE-NL-A1 per-session nonce; nl_fscx_revolve_v2_inv_ba delta precompute ---
    HSKE-NL-A1 now generates a random per-session nonce N and derives session base
    = K XOR N (transmitted alongside ciphertext).  Eliminates keystream reuse when
    the same long-term key K is used across sessions.
    nl_fscx_revolve_v2_inv_ba precomputes delta(B) once before the loop.
    Loop body: ba_sub256(z, buf, delta); m_inv_ba(mz, z); ba_xor(buf, b, mz).
    Eliminates one nl_fscx_delta_v2 call (arbitrary-precision mul+rol) per step.

    --- v1.5.7: precomputed M^{-1} for nl_fscx_v2_inv_ba ---
    m_inv_ba now computes the rotation table for M^{-1} = M^{127}(X) once on first call
    (bootstrapping from ba_fscx_revolve(1, 0, 127)), caches the rotation offsets in a
    static array, then applies M^{-1}(X) as XOR of ba_rol_k(X, k) for each k in the
    table.  New ba_rol_k helper performs arbitrary-bit cyclic rotation on 256-bit arrays.

    --- v1.5.6: rnl_rand_poly bias fix — 3-byte rejection sampling ---
    rnl_rand_poly now draws 3 bytes (24-bit) with rejection sampling (threshold =
    (1<<24) - (1<<24)%RNL_Q = 16711935) to eliminate the ~1/2^32 modular bias.

    --- v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)) ---
    rnl_poly_mul now uses Cooley-Tukey NTT over Z_{65537} with negacyclic twist.

    --- v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1) ---

    HKEX-RNL secret polynomial now uses a centered binomial distribution CBD(eta=1)
    instead of the previous uniform {0,1} sampler.  CBD(1) produces coefficients in
    {-1, 0, 1} (stored mod q) with zero mean, matching the Kyber/NIST baseline for
    proper Ring-LWR hardness without changing the noise budget.

    --- v1.5.0: NL-FSCX non-linear extension and PQC extensions ---

    New in v1.5.0:
      - NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
        Breaks additive linearity; used in HSKE-NL-A1 (counter-mode) and HPKS-NL.
      - NL-FSCX v2: fscx(A,B) + delta(B) mod 2^n, with invertible delta(B).
        Fully bijective; used in HSKE-NL-A2 (revolve-mode) and HPKE-NL.
      - HSKE-NL-A1: counter-mode symmetric encryption with NL-FSCX v1 keystream.
      - HSKE-NL-A2: revolve-mode symmetric encryption with NL-FSCX v2 (invertible).
      - HKEX-RNL: Ring-LWR key exchange (n=256; conjectured quantum-resistant).
      - HPKS-NL: NL-hardened Schnorr signature using NL-FSCX v1 challenge.
      - HPKE-NL: NL-hardened El Gamal encryption using NL-FSCX v2.

    All protocols operate at KEYBITS=256 by default.

    --- v1.4.0: HKEX replaced with HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    HKEX-GF replaces HKEX with Diffie-Hellman over GF(2^KEYBITS)*:
      - Alice: private scalar a, public C  = g^a  (GF exponentiation)
      - Bob:   private scalar b, public C2 = g^b
      - Shared: sk = C2^a = C^b = g^{ab}  (field commutativity)

    --- v1.3.2: performance and readability ---
    --- v1.3: BitArray (multi-byte parameter support) ---

    The C implementation uses a BitArray type: a fixed-width bit string backed
    by a big-endian byte array.  Default key size is 256 bits.

    The key size is controlled by KEYBITS (must be a positive multiple of 8
    and >= 16).  Change the #define to use a different bit width; all
    parameters and step counts scale automatically.
*/

/* Build: gcc -O2 -o "Herradura cryptographic suite" "Herradura cryptographic suite.c" */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Key size in bits -- must be a positive multiple of 8 and >= 16.
   Change this to use a different parameter width; I_VALUE and R_VALUE scale
   automatically.  n=256 gives ~128-bit classical DLP security in GF(2^n)*. */
#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)       /* 64  for 256-bit */
#define R_VALUE  (3 * KEYBITS / 4)   /* 192 for 256-bit */

#if KEYBYTES < 2
#  error "KEYBITS must be >= 16"
#endif
#if KEYBITS != 256
#  error "GF polynomial constants are only defined for KEYBITS=256 in this build"
#endif

/* Fixed-width bit array backed by a big-endian byte array.
   b[0] holds the most-significant byte; size is always KEYBYTES. */
typedef struct {
    uint8_t b[KEYBYTES];
} BitArray;

/* Fill dst with KEYBYTES random bytes from /dev/urandom. */
static void ba_rand(BitArray *dst, FILE *urnd)
{
    if (fread(dst->b, 1, KEYBYTES, urnd) != (size_t)KEYBYTES) {
        fputs("ERROR: could not read from /dev/urandom\n", stderr);
        exit(1);
    }
}

/* dst = a XOR b.  Aliasing dst == a or dst == b is safe. */
static void ba_xor(BitArray *dst, const BitArray *a, const BitArray *b)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        dst->b[i] = a->b[i] ^ b->b[i];
}

/* Returns 1 if a == b, 0 otherwise. */
static int ba_equal(const BitArray *a, const BitArray *b)
{
    return memcmp(a->b, b->b, KEYBYTES) == 0;
}

/* Print label + hex representation of a + newline. */
static void ba_print_hex(const char *label, const BitArray *a)
{
    int i;
    printf("%s", label);
    for (i = 0; i < KEYBYTES; i++)
        printf("%02x", a->b[i]);
    putchar('\n');
}

/* Full Surroundings Cyclic XOR:
   result = a XOR b XOR ROL(a) XOR ROL(b) XOR ROR(a) XOR ROR(b)

   Fused single-pass implementation.  Requires KEYBYTES >= 2. */
static void ba_fscx(BitArray *result, const BitArray *a, const BitArray *b)
{
    uint8_t a_msbit = a->b[0] >> 7;
    uint8_t b_msbit = b->b[0] >> 7;
    uint8_t a_lsbit = a->b[KEYBYTES - 1] & 1;
    uint8_t b_lsbit = b->b[KEYBYTES - 1] & 1;
    int i;

    result->b[0] = a->b[0] ^ b->b[0]
        ^ (uint8_t)((a->b[0] << 1) | (a->b[1] >> 7))
        ^ (uint8_t)((b->b[0] << 1) | (b->b[1] >> 7))
        ^ (uint8_t)((a->b[0] >> 1) | (a_lsbit << 7))
        ^ (uint8_t)((b->b[0] >> 1) | (b_lsbit << 7));

    for (i = 1; i < KEYBYTES - 1; i++)
        result->b[i] = a->b[i] ^ b->b[i]
            ^ (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7))
            ^ (uint8_t)((b->b[i] << 1) | (b->b[i + 1] >> 7))
            ^ (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7))
            ^ (uint8_t)((b->b[i] >> 1) | (b->b[i - 1] << 7));

    result->b[KEYBYTES - 1] = a->b[KEYBYTES-1] ^ b->b[KEYBYTES-1]
        ^ (uint8_t)((a->b[KEYBYTES-1] << 1) | a_msbit)
        ^ (uint8_t)((b->b[KEYBYTES-1] << 1) | b_msbit)
        ^ (uint8_t)((a->b[KEYBYTES-1] >> 1) | (a->b[KEYBYTES-2] << 7))
        ^ (uint8_t)((b->b[KEYBYTES-1] >> 1) | (b->b[KEYBYTES-2] << 7));
}

/* FSCX_REVOLVE: iterate fscx(a, b) steps times keeping b constant.
   Double-buffered to avoid copying the result back every step. */
static void ba_fscx_revolve(BitArray *result, const BitArray *a,
                             const BitArray *b, int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&buf[1 - idx], &buf[idx], b);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* ─────────────────────────────────────────────────────────────────────────────
 * GF(2^KEYBITS) arithmetic — carryless polynomial multiplication mod p(x)
 *
 * Primitive polynomial for GF(2^256): p(x) = x^256 + x^10 + x^5 + x^2 + 1
 *   Lower 256 bits = x^10 + x^5 + x^2 + 1 = 0x0425
 *   Big-endian 32-byte repr: bytes 0..29 = 0x00, byte30 = 0x04, byte31 = 0x25
 *
 * Generator g = x+1 = 3.
 * ───────────────────────────────────────────────────────────────────────────── */

static const BitArray GF_POLY = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x04,0x25
}};

static const BitArray GF_GEN = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x03
}};

/* Returns 1 if a is the zero element. */
static int ba_is_zero(const BitArray *a)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        if (a->b[i]) return 0;
    return 1;
}

/* Shift big-endian BitArray left by 1 bit.  Returns the MSB shifted out. */
static int ba_shl1(BitArray *a)
{
    int carry = (a->b[0] >> 7) & 1;
    int i;
    for (i = 0; i < KEYBYTES - 1; i++)
        a->b[i] = (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7));
    a->b[KEYBYTES - 1] <<= 1;
    return carry;
}

/* Shift big-endian BitArray right by 1 bit.  Returns the LSB shifted out. */
static int ba_shr1(BitArray *a)
{
    int carry = a->b[KEYBYTES - 1] & 1;
    int i;
    for (i = KEYBYTES - 1; i > 0; i--)
        a->b[i] = (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7));
    a->b[0] >>= 1;
    return carry;
}

/* GF(2^KEYBITS) multiplication: dst = a * b mod GF_POLY.
   Shift-and-XOR: O(KEYBITS) iterations, XOR and shift only. */
static void gf_mul_ba(BitArray *dst, const BitArray *a, const BitArray *b)
{
    BitArray r, aa, bb;
    int i;
    memset(r.b, 0, KEYBYTES);
    aa = *a;
    bb = *b;
    for (i = 0; i < KEYBITS; i++) {
        if (bb.b[KEYBYTES - 1] & 1)
            ba_xor(&r, &r, &aa);
        if (ba_shl1(&aa))
            ba_xor(&aa, &aa, &GF_POLY);
        ba_shr1(&bb);
    }
    *dst = r;
}

/* GF(2^KEYBITS) exponentiation: dst = base^exp mod GF_POLY.
   Binary repeated squaring: O(KEYBITS) multiplications. */
static void gf_pow_ba(BitArray *dst, const BitArray *base, const BitArray *exp)
{
    BitArray r, b, e;
    memset(r.b, 0, KEYBYTES);
    r.b[KEYBYTES - 1] = 1;   /* multiplicative identity: 1 */
    b = *base;
    e = *exp;
    while (!ba_is_zero(&e)) {
        if (e.b[KEYBYTES - 1] & 1)
            gf_mul_ba(&r, &r, &b);
        gf_mul_ba(&b, &b, &b);
        ba_shr1(&e);
    }
    *dst = r;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 256-bit integer helpers (needed for NL-FSCX v2 and Schnorr arithmetic)
 * ───────────────────────────────────────────────────────────────────────────── */

static void ba_add256(BitArray *dst, const BitArray *a, const BitArray *b)
{
    uint16_t carry = 0;
    int i;
    for (i = KEYBYTES - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a->b[i] + b->b[i] + carry;
        dst->b[i] = (uint8_t)s;
        carry = s >> 8;
    }
}

static void ba_sub256(BitArray *dst, const BitArray *a, const BitArray *b)
{
    int16_t borrow = 0;
    int i;
    for (i = KEYBYTES - 1; i >= 0; i--) {
        int16_t d = (int16_t)(uint16_t)a->b[i] - (uint16_t)b->b[i] + borrow;
        dst->b[i] = (uint8_t)d;
        borrow = d >> 8;
    }
}

/* shr1 of big-endian BitArray (right shift by 1 bit, non-destructive) */
static void ba_shr1_copy(BitArray *dst, const BitArray *src)
{
    int i;
    for (i = KEYBYTES - 1; i > 0; i--)
        dst->b[i] = (uint8_t)((src->b[i] >> 1) | (src->b[i - 1] << 7));
    dst->b[0] = src->b[0] >> 1;
}

/* ROL by 64 bits on 256-bit big-endian array */
static void ba_rol64_256(BitArray *dst, const BitArray *src)
{
    uint8_t tmp[8];
    memcpy(tmp, src->b, 8);
    memcpy(dst->b, src->b + 8, KEYBYTES - 8);
    memcpy(dst->b + KEYBYTES - 8, tmp, 8);
}

/* Cyclic left-rotation by k bits on KEYBYTES big-endian array.
   byte_shift = k/8 positions; bit_shift = k%8 bits within each byte. */
static void ba_rol_k(BitArray *dst, const BitArray *src, int k)
{
    int byte_shift = (k / 8) % KEYBYTES;
    int bit_shift  = k % 8;
    int i;
    if (bit_shift == 0) {
        for (i = 0; i < KEYBYTES; i++)
            dst->b[i] = src->b[(i + byte_shift) % KEYBYTES];
    } else {
        int rshift = 8 - bit_shift;
        for (i = 0; i < KEYBYTES; i++)
            dst->b[i] = (uint8_t)((src->b[(i + byte_shift) % KEYBYTES] << bit_shift)
                                | (src->b[(i + byte_shift + 1) % KEYBYTES] >> rshift));
    }
}

/* Low 256-bit schoolbook multiply: dst = a*b mod 2^256 */
static void ba_mul256_lo(BitArray *dst, const BitArray *a, const BitArray *b)
{
    uint8_t result[KEYBYTES];
    int i, j;
    memset(result, 0, KEYBYTES);
    for (i = 0; i < KEYBYTES; i++) {
        uint8_t ai = a->b[KEYBYTES - 1 - i];
        if (!ai) continue;
        {
            uint16_t carry = 0;
            for (j = 0; j + i < KEYBYTES; j++) {
                uint16_t prod = (uint16_t)ai * b->b[KEYBYTES - 1 - j]
                                + result[i + j] + carry;
                result[i + j] = (uint8_t)prod;
                carry = prod >> 8;
            }
        }
    }
    for (i = 0; i < KEYBYTES; i++)
        dst->b[KEYBYTES - 1 - i] = result[i];
}

/* Full 512-bit schoolbook multiply, then reduce mod (2^256-1).
   Reduction: (lo + hi) mod (2^256-1), where hi*2^256 + lo = a*b. */
static void ba_mul_mod_ord(BitArray *dst, const BitArray *a, const BitArray *b)
{
    uint8_t full[2 * KEYBYTES];   /* little-endian 512-bit product */
    uint8_t lo[KEYBYTES];
    uint16_t carry;
    int i, j, all_ff;

    memset(full, 0, sizeof(full));
    for (i = 0; i < KEYBYTES; i++) {
        uint8_t ai = a->b[KEYBYTES - 1 - i];
        if (!ai) continue;
        carry = 0;
        for (j = 0; j < KEYBYTES; j++) {
            uint16_t prod = (uint16_t)ai * b->b[KEYBYTES - 1 - j]
                            + full[i + j] + carry;
            full[i + j] = (uint8_t)prod;
            carry = prod >> 8;
        }
        /* propagate remaining carry through high half */
        {
            int k;
            for (k = i + KEYBYTES; carry && k < 2 * KEYBYTES; k++) {
                uint16_t s = (uint16_t)full[k] + carry;
                full[k] = (uint8_t)s;
                carry = s >> 8;
            }
        }
    }
    /* full[0..KB-1] = lo (LE); full[KB..2KB-1] = hi (LE) */
    carry = 0;
    for (i = 0; i < KEYBYTES; i++) {
        uint16_t s = (uint16_t)full[i] + full[KEYBYTES + i] + carry;
        lo[i] = (uint8_t)s;
        carry = s >> 8;
    }
    if (carry) {
        /* sum = 2^256 + lo256; mod (2^256-1) = lo256 + 1 */
        carry = 1;
        for (i = 0; i < KEYBYTES && carry; i++) {
            uint16_t s = (uint16_t)lo[i] + carry;
            lo[i] = (uint8_t)s;
            carry = s >> 8;
        }
        if (carry) { memset(lo, 0, KEYBYTES); lo[0] = 1; }
    } else {
        /* if lo == 2^256-1, reduce to 0 */
        all_ff = 1;
        for (i = 0; i < KEYBYTES; i++) if (lo[i] != 0xFF) { all_ff = 0; break; }
        if (all_ff) memset(lo, 0, KEYBYTES);
    }
    for (i = 0; i < KEYBYTES; i++)
        dst->b[KEYBYTES - 1 - i] = lo[i];
}

/* dst = (a - b) mod (2^256-1) */
static void ba_sub_mod_ord(BitArray *dst, const BitArray *a, const BitArray *b)
{
    int16_t borrow = 0;
    int i, all_ff;
    for (i = KEYBYTES - 1; i >= 0; i--) {
        int16_t d = (int16_t)(uint16_t)a->b[i] - (uint16_t)b->b[i] + borrow;
        dst->b[i] = (uint8_t)d;
        borrow = d >> 8;
    }
    if (borrow) {
        /* a < b: result = (a - b + 2^256) - 1 */
        for (i = KEYBYTES - 1; i >= 0; i--) {
            if (dst->b[i] > 0) { dst->b[i]--; break; }
            dst->b[i] = 0xFF;
        }
    }
    /* if result == 2^256-1, reduce to 0 */
    all_ff = 1;
    for (i = 0; i < KEYBYTES; i++) if (dst->b[i] != 0xFF) { all_ff = 0; break; }
    if (all_ff) memset(dst->b, 0, KEYBYTES);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 256-bit NL-FSCX primitives
 * ───────────────────────────────────────────────────────────────────────────── */

static const BitArray ZERO_BA = {{0}};
static const BitArray ONE_BA  = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x01
}};

/* M^{-1}(X): apply precomputed rotation table, bootstrapped once on first call.
   Table = bit positions of fscx_revolve(1, 0, KEYBITS/2-1); M^{-1}(X) = XOR of
   ba_rol_k(X, k) for each k in the table (~2n/3 rotations vs n/2-1 FSCX steps). */
static void m_inv_ba(BitArray *dst, const BitArray *src)
{
    static int initialized = 0;
    static int rotations[KEYBITS];
    static int nrot = 0;
    int i;

    if (!initialized) {
        BitArray unit = {{0}}, tmp;
        int k;
        unit.b[KEYBYTES - 1] = 1;   /* unit = 1 (bit 0 set in big-endian) */
        ba_fscx_revolve(&tmp, &unit, &ZERO_BA, KEYBITS / 2 - 1);
        for (k = 0; k < KEYBITS; k++)
            if (tmp.b[KEYBYTES - 1 - k / 8] & (1u << (k % 8)))
                rotations[nrot++] = k;
        initialized = 1;
    }

    {
        BitArray acc = {{0}}, tmp;
        for (i = 0; i < nrot; i++) {
            ba_rol_k(&tmp, src, rotations[i]);
            ba_xor(&acc, &acc, &tmp);
        }
        *dst = acc;
    }
}

/* NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4) */
static void nl_fscx_v1_ba(BitArray *result, const BitArray *a, const BitArray *b)
{
    BitArray f, s, m;
    ba_fscx(&f, a, b);
    ba_add256(&s, a, b);
    ba_rol64_256(&m, &s);
    ba_xor(result, &f, &m);
}

static void nl_fscx_revolve_v1_ba(BitArray *result, const BitArray *a,
                                   const BitArray *b, int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        nl_fscx_v1_ba(&buf[1 - idx], &buf[idx], b);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* delta(B) = ROL(B * floor((B+1)/2) mod 2^n, n/4) */
static void nl_fscx_delta_v2(BitArray *delta, const BitArray *b)
{
    BitArray bp1, half, raw;
    ba_add256(&bp1, b, &ONE_BA);
    ba_shr1_copy(&half, &bp1);
    ba_mul256_lo(&raw, b, &half);
    ba_rol64_256(delta, &raw);
}

/* NL-FSCX v2: (fscx(A,B) + delta(B)) mod 2^n */
static void nl_fscx_v2_ba(BitArray *result, const BitArray *a, const BitArray *b)
{
    BitArray f, d;
    ba_fscx(&f, a, b);
    nl_fscx_delta_v2(&d, b);
    ba_add256(result, &f, &d);
}

/* NL-FSCX v2 inverse: A = B XOR M^{-1}((Y - delta(B)) mod 2^n) */
static void nl_fscx_v2_inv_ba(BitArray *result, const BitArray *y, const BitArray *b)
{
    BitArray d, z, mz;
    nl_fscx_delta_v2(&d, b);
    ba_sub256(&z, y, &d);
    m_inv_ba(&mz, &z);
    ba_xor(result, b, &mz);
}

static void nl_fscx_revolve_v2_ba(BitArray *result, const BitArray *a,
                                   const BitArray *b, int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        nl_fscx_v2_ba(&buf[1 - idx], &buf[idx], b);
        idx ^= 1;
    }
    *result = buf[idx];
}

static void nl_fscx_revolve_v2_inv_ba(BitArray *result, const BitArray *y,
                                       const BitArray *b, int steps)
{
    BitArray delta, buf[2];
    int idx = 0, i;
    nl_fscx_delta_v2(&delta, b);   /* precompute once — b is constant */
    buf[0] = *y;
    for (i = 0; i < steps; i++) {
        BitArray z, mz;
        ba_sub256(&z, &buf[idx], &delta);
        m_inv_ba(&mz, &z);
        ba_xor(&buf[1 - idx], b, &mz);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HKEX-RNL: Ring-LWR key exchange helpers (n=256, negacyclic Z_q[x]/(x^n+1))
 * ───────────────────────────────────────────────────────────────────────────── */

#define RNL_N  256
#define RNL_Q  65537
#define RNL_P  4096
#define RNL_PP 2
#define RNL_ETA  1  /* CBD eta: secret coeffs from CBD(1) in {-1,0,1} mod q */

typedef int32_t rnl_poly_t[RNL_N];

/* Modular exponentiation (base^exp mod m) for NTT twiddle setup */
static uint32_t rnl_mod_pow(uint32_t base, uint32_t exp, uint32_t m)
{
    uint64_t r = 1, b = base % m;
    for (; exp; exp >>= 1) { if (exp & 1) r = r * b % m; b = b * b % m; }
    return (uint32_t)r;
}

/* Precomputed NTT twiddle tables for n=RNL_N, q=RNL_Q (lazy-initialized on first use). */
#define RNL_LOG2N 8  /* log2(256) */
static struct {
    uint32_t psi_pow[RNL_N];          /* ψ^i for pre-twist */
    uint32_t psi_inv_pow[RNL_N];      /* ψ^{-i} for post-twist */
    uint32_t stage_w_fwd[RNL_LOG2N];  /* per-stage ω, forward NTT */
    uint32_t stage_w_inv[RNL_LOG2N];  /* per-stage ω, inverse NTT */
    uint32_t inv_n;                   /* n^{-1} mod q for INTT scaling */
    int      ready;
} rnl_tw;

static void rnl_twiddle_init(void)
{
    uint32_t psi, psi_inv, pw, pw_inv, w;
    int i, s, length;
    if (rnl_tw.ready) return;
    psi     = rnl_mod_pow(3, (RNL_Q - 1) / (2 * RNL_N), RNL_Q);
    psi_inv = rnl_mod_pow(psi, RNL_Q - 2, RNL_Q);
    pw = pw_inv = 1;
    for (i = 0; i < RNL_N; i++) {
        rnl_tw.psi_pow[i]     = pw;
        rnl_tw.psi_inv_pow[i] = pw_inv;
        pw     = (uint32_t)((uint64_t)pw     * psi     % RNL_Q);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % RNL_Q);
    }
    for (s = 0, length = 2; length <= RNL_N; length <<= 1, s++) {
        w = rnl_mod_pow(3, (RNL_Q - 1) / (uint32_t)length, RNL_Q);
        rnl_tw.stage_w_fwd[s] = w;
        rnl_tw.stage_w_inv[s] = rnl_mod_pow(w, RNL_Q - 2, RNL_Q);
    }
    rnl_tw.inv_n = rnl_mod_pow((uint32_t)RNL_N, RNL_Q - 2, RNL_Q);
    rnl_tw.ready = 1;
}

/* Cooley-Tukey iterative NTT over Z_q (in-place). n must be a power of 2.
   Uses primitive root 3 (valid since q=65537 is a Fermat prime, ord(3)=q-1=2^16). */
static void rnl_ntt(int32_t *a, int n, int q, int invert)
{
    int i, j = 0, length, k, s;
    uint32_t w, wn;
    const uint32_t *sw;
    rnl_twiddle_init();
    sw = invert ? rnl_tw.stage_w_inv : rnl_tw.stage_w_fwd;
    for (i = 1; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { int32_t t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (length = 2, s = 0; length <= n; length <<= 1, s++) {
        w = sw[s];
        for (i = 0; i < n; i += length) {
            wn = 1;
            for (k = 0; k < length >> 1; k++) {
                int32_t u = a[i + k];
                int32_t v = (int32_t)((uint64_t)a[i + k + (length >> 1)] * wn % (uint32_t)q);
                a[i + k]                 = (u + v) % q;
                a[i + k + (length >> 1)] = (u - v + q) % q;
                wn = (uint32_t)((uint64_t)wn * w % (uint32_t)q);
            }
        }
    }
    if (invert) {
        for (i = 0; i < n; i++)
            a[i] = (int32_t)((uint64_t)a[i] * rnl_tw.inv_n % (uint32_t)q);
    }
}

/* Negacyclic multiply: h = f*g in Z_q[x]/(x^n+1) via NTT. O(n log n).
   ψ = 3^((q-1)/(2n)) is a primitive 2n-th root; ψ^n ≡ -1 encodes the wrap. */
static void rnl_poly_mul(rnl_poly_t h, const rnl_poly_t f, const rnl_poly_t g)
{
    int32_t fa[RNL_N], ga[RNL_N], ha[RNL_N];
    int i;
    rnl_twiddle_init();
    for (i = 0; i < RNL_N; i++) {
        fa[i] = (int32_t)((uint64_t)f[i] * rnl_tw.psi_pow[i] % RNL_Q);
        ga[i] = (int32_t)((uint64_t)g[i] * rnl_tw.psi_pow[i] % RNL_Q);
    }
    rnl_ntt(fa, RNL_N, RNL_Q, 0);
    rnl_ntt(ga, RNL_N, RNL_Q, 0);
    for (i = 0; i < RNL_N; i++)
        ha[i] = (int32_t)((uint64_t)fa[i] * ga[i] % RNL_Q);
    rnl_ntt(ha, RNL_N, RNL_Q, 1);
    for (i = 0; i < RNL_N; i++)
        h[i] = (int32_t)((uint64_t)ha[i] * rnl_tw.psi_inv_pow[i] % RNL_Q);
}

static void rnl_poly_add(rnl_poly_t h, const rnl_poly_t f, const rnl_poly_t g)
{
    int i;
    for (i = 0; i < RNL_N; i++) h[i] = (f[i] + g[i]) % RNL_Q;
}

static void rnl_round(int32_t *out, const rnl_poly_t in, int from_q, int to_p)
{
    int i;
    for (i = 0; i < RNL_N; i++)
        out[i] = (int32_t)(((int64_t)in[i] * to_p + from_q / 2) / from_q % to_p);
}

static void rnl_lift(rnl_poly_t out, const int32_t *in, int from_p, int to_q)
{
    int i;
    for (i = 0; i < RNL_N; i++)
        out[i] = (int32_t)((int64_t)in[i] * to_q / from_p % to_q);
}

/* m(x) = 1 + x + x^{n-1} */
static void rnl_m_poly(rnl_poly_t p)
{
    memset(p, 0, sizeof(rnl_poly_t));
    p[0] = p[1] = p[RNL_N - 1] = 1;
}

static void rnl_rand_poly(rnl_poly_t p, FILE *urnd)
{
    static const uint32_t threshold = (1u << 24) - ((1u << 24) % RNL_Q);
    int i = 0;
    while (i < RNL_N) {
        uint8_t buf[3];
        if (fread(buf, 3, 1, urnd) != 1) { fputs("urandom error\n", stderr); exit(1); }
        uint32_t v = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
        if (v < threshold)
            p[i++] = (int32_t)(v % RNL_Q);
    }
}

/* CBD(eta=1): coeff = popcount(low eta bits) - popcount(next eta bits), mod q.
   Produces {-1,0,1} with P(-1)=P(1)=1/4, P(0)=1/2; zero mean. */
static void rnl_cbd_poly(rnl_poly_t p, FILE *urnd)
{
    int i;
    uint8_t v;
    for (i = 0; i < RNL_N; i++) {
        if (fread(&v, 1, 1, urnd) != 1) { fputs("urandom error\n", stderr); exit(1); }
        int a = (int)(v & 1);
        int b = (int)((v >> 1) & 1);
        p[i] = (int32_t)((a - b + RNL_Q) % RNL_Q);
    }
}

/* Extract RNL_N bits into BitArray (coefficient >= pp/2 -> bit=1).
   Bit i maps to byte KEYBYTES-1-i/8, bit position i%8. */
static void rnl_bits_to_ba(BitArray *out, const int32_t *bits_poly)
{
    int i;
    memset(out->b, 0, KEYBYTES);
    for (i = 0; i < RNL_N && i < KEYBITS; i++) {
        if (bits_poly[i] >= RNL_PP / 2)
            out->b[KEYBYTES - 1 - i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* keygen: s=CBD(eta=1) private, C=round_p(m_blind * s) */
static void rnl_keygen(int32_t s_out[RNL_N], int32_t c_out[RNL_N],
                       const rnl_poly_t m_blind, FILE *urnd)
{
    rnl_poly_t ms;
    rnl_cbd_poly(s_out, urnd);
    rnl_poly_mul(ms, m_blind, s_out);
    rnl_round(c_out, ms, RNL_Q, RNL_P);
}

/* Peikert cross-rounding: 1-bit hint per coefficient packed into hint[RNL_N/8]. */
static void rnl_hint(uint8_t hint[RNL_N / 8], const rnl_poly_t K_poly)
{
    int i;
    memset(hint, 0, RNL_N / 8);
    for (i = 0; i < RNL_N; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)4 * c + RNL_Q / 2) / RNL_Q) % 4;
        if (r % 2)
            hint[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* Extract KEYBITS key bits using Peikert cross-rounding hint. */
static void rnl_reconcile_bits(BitArray *out, const rnl_poly_t K_poly,
                                const uint8_t hint[RNL_N / 8])
{
    int i;
    const uint32_t qh = RNL_Q / 2;
    memset(out->b, 0, sizeof(out->b));
    for (i = 0; i < RNL_N && i < KEYBITS; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (hint[i / 8] >> (i % 8)) & 1u;
        uint32_t b = (uint32_t)(((uint64_t)2 * c + (uint64_t)h * qh + qh) / RNL_Q) % RNL_PP;
        if (b)
            out->b[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* agree: compute raw key with Peikert reconciliation.
   Reconciler path (hint_in=NULL, hint_out≠NULL): generate hint, use own hint.
   Receiver path  (hint_in≠NULL):                 use provided hint.           */
static void rnl_agree(BitArray *out, const int32_t s[RNL_N],
                      const int32_t c_other[RNL_N],
                      const uint8_t *hint_in, uint8_t *hint_out)
{
    rnl_poly_t c_lifted, k_poly;
    rnl_lift(c_lifted, c_other, RNL_P, RNL_Q);
    rnl_poly_mul(k_poly, s, c_lifted);
    if (!hint_in) {
        rnl_hint(hint_out, k_poly);
        rnl_reconcile_bits(out, k_poly, hint_out);
    } else {
        rnl_reconcile_bits(out, k_poly, hint_in);
    }
}

/*
HKEX-GF (key exchange — Diffie-Hellman over GF(2^n)*):
    Pre-agreed: irreducible polynomial p(x), generator g.
    Alice:  private a -> public C  = g^a
    Bob:    private b -> public C2 = g^b
    Shared: sk = C2^a = C^b = g^{ab}  (field multiplication is commutative)
    Break:  Shor's algorithm recovers a from C = g^a.

HSKE (symmetric key encryption — FSCX-based, linear):
    share key of bitlength n
    Alice:  E = fscx_revolve(P, key, i)
    Bob:    P = fscx_revolve(E, key, r)  [i+r=n -> orbit closes]
    Break:  One known-plaintext pair recovers key via GF(2) linear algebra.

HPKS (Schnorr public key signature, 256-bit):
    Alice private: a,  public C = g^a,  ORD = 2^256-1
    Sign(P):  k random; R=g^k; e=fscx_revolve(R,P,i); s=(k-a*e) mod ORD
    Verify:   g^s * C^e == R
    Break:  DLP recovers a; linear challenge is preimage-vulnerable.

HPKE (El Gamal public key encryption, 256-bit):
    Alice private: a,  public C = g^a
    Bob encrypts: r random; R=g^r; enc_key=C^r; E=fscx_revolve(P,enc_key,i)
    Alice decrypts: dec_key=R^a; D=fscx_revolve(E,dec_key,r) = P

HSKE-NL-A1 (counter-mode with NL-FSCX v1, 256-bit):
    N = random(256 bits); base = K XOR N  [per-session nonce; N transmitted with ciphertext]
    ks = nl_fscx_revolve_v1(ROL(base, n/8), base XOR counter, I_VALUE)
    E = P XOR ks;  D = E XOR ks = P

HSKE-NL-A2 (revolve-mode with NL-FSCX v2, 256-bit):
    E = nl_fscx_revolve_v2(P, K, R_VALUE)
    D = nl_fscx_revolve_v2_inv(E, K, R_VALUE) = P
    CAUTION: Deterministic — same (P, K) always yields the same E. Embed a nonce
    in P when multiple messages may be encrypted under the same key.

HKEX-RNL (Ring-LWR key exchange, n=256):
    Shared m_blind = m(x) + a_rand in Z_q[x]/(x^n+1)
    Alice: s_A small, C_A = round_p(m_blind * s_A)
    Bob:   s_B small, C_B = round_p(m_blind * s_B)
    K_poly_A = s_A * lift(C_B);  hint_A = rnl_hint(K_poly_A)  [Alice: reconciler]
    K_raw_A = reconcile(K_poly_A, hint_A);  K_raw_B = reconcile(K_poly_B, hint_A)
    KDF: seed=ba_rol_k(K,n/8); sk=nl_fscx_revolve_v1(seed,K,n/4)

HPKS-NL (NL-hardened Schnorr, 256-bit):
    e = nl_fscx_revolve_v1(R, P, I_VALUE)  (NL challenge)

HPKE-NL (NL-hardened El Gamal, 256-bit):
    E = nl_fscx_revolve_v2(P, enc_key, I_VALUE)
    D = nl_fscx_revolve_v2_inv(E, dec_key, I_VALUE)
*/

int main(void)
{
    FILE *urnd;
    BitArray a, b, preshared, plaintext, decoy;
    BitArray C, C2;
    /* saved for Eve tests */
    BitArray E_nl_saved, R_nl2_saved, sk_rnl_A_saved;

    urnd = fopen("/dev/urandom", "rb");
    if (!urnd) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    ba_rand(&a,         urnd);
    ba_rand(&b,         urnd);
    ba_rand(&preshared, urnd);
    ba_rand(&plaintext, urnd);
    ba_rand(&decoy,     urnd);

    /* Precompute GF DH public keys */
    gf_pow_ba(&C,  &GF_GEN, &a);
    gf_pow_ba(&C2, &GF_GEN, &b);

    ba_print_hex("a         : ", &a);
    ba_print_hex("b         : ", &b);
    ba_print_hex("preshared : ", &preshared);
    ba_print_hex("plaintext : ", &plaintext);
    ba_print_hex("decoy     : ", &decoy);
    ba_print_hex("C         : ", &C);
    ba_print_hex("C2        : ", &C2);

    /* --- HKEX-GF [CLASSICAL -- not PQC; Shor's algorithm breaks DLP] */
    printf("\n--- HKEX-GF [CLASSICAL \xe2\x80\x94 not PQC; Shor's algorithm breaks DLP]\n");
    printf("    (DH over GF(2^%d)*)\n", KEYBITS);
    {
        BitArray skA, skB;
        gf_pow_ba(&skA, &C2, &a);
        gf_pow_ba(&skB, &C,  &b);
        ba_print_hex("sk (Alice): ", &skA);
        ba_print_hex("sk (Bob)  : ", &skB);
        if (ba_equal(&skA, &skB))
            puts("+ session keys agree!");
        else
            puts("- session keys differ!");
    }

    /* --- HSKE [CLASSICAL -- not PQC; linear key recovery from 1 KPT pair] */
    printf("\n--- HSKE [CLASSICAL \xe2\x80\x94 not PQC; linear key recovery from 1 KPT pair]\n");
    puts("    (fscx_revolve symmetric encryption)");
    {
        BitArray E_hske, D_hske;
        ba_print_hex("P (plain) : ", &plaintext);
        ba_fscx_revolve(&E_hske, &plaintext, &preshared, I_VALUE);
        ba_print_hex("E (Alice) : ", &E_hske);
        ba_fscx_revolve(&D_hske, &E_hske, &preshared, R_VALUE);
        ba_print_hex("D (Bob)   : ", &D_hske);
        if (ba_equal(&D_hske, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HPKS [CLASSICAL -- not PQC; DLP + linear challenge] */
    printf("\n--- HPKS [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear challenge]\n");
    puts("    (Schnorr-like with fscx_revolve challenge)");
    {
        BitArray k_s, R_s, e_s, ae_s, s_s, gs, Ce, lhs;
        ba_rand(&k_s, urnd);
        gf_pow_ba(&R_s, &GF_GEN, &k_s);
        ba_fscx_revolve(&e_s, &R_s, &plaintext, I_VALUE);
        /* s = (k - a*e) mod (2^256-1) */
        ba_mul_mod_ord(&ae_s, &a, &e_s);
        ba_sub_mod_ord(&s_s, &k_s, &ae_s);
        /* verify: g^s * C^e == R */
        gf_pow_ba(&gs, &GF_GEN, &s_s);
        gf_pow_ba(&Ce, &C, &e_s);
        gf_mul_ba(&lhs, &gs, &Ce);
        ba_print_hex("P (msg)        : ", &plaintext);
        ba_print_hex("R [Alice,sign] : ", &R_s);
        ba_print_hex("e [Alice,sign] : ", &e_s);
        ba_print_hex("s [Alice,sign] : ", &s_s);
        ba_print_hex("  [Bob,verify] : g^s\xc2\xb7""C^e = ", &lhs);
        if (ba_equal(&lhs, &R_s))
            puts("  [Bob,verify] : + Schnorr verified: g^s \xc2\xb7 C^e == R");
        else
            puts("  [Bob,verify] : - Schnorr verification failed!");
    }

    /* --- HPKE [CLASSICAL -- not PQC; DLP + linear HSKE sub-protocol] */
    printf("\n--- HPKE [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear HSKE sub-protocol]\n");
    puts("    (El Gamal + fscx_revolve)");
    {
        BitArray r_hpke, R_hpke, enc_key, E_hpke, dec_key, D_hpke;
        ba_rand(&r_hpke, urnd);
        gf_pow_ba(&R_hpke,  &GF_GEN, &r_hpke);
        gf_pow_ba(&enc_key, &C,      &r_hpke);
        ba_fscx_revolve(&E_hpke, &plaintext, &enc_key, I_VALUE);
        gf_pow_ba(&dec_key, &R_hpke, &a);
        ba_fscx_revolve(&D_hpke, &E_hpke, &dec_key, R_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Bob)   : ", &E_hpke);
        ba_print_hex("D (Alice) : ", &D_hpke);
        if (ba_equal(&D_hpke, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1] */
    printf("\n--- HSKE-NL-A1 [PQC-HARDENED \xe2\x80\x94 counter-mode with NL-FSCX v1]\n");
    {
        BitArray N_a1, base_a1, ks_nl1, E_nl1, D_nl1;
        ba_rand(&N_a1, urnd);                         /* per-session nonce          */
        ba_xor(&base_a1, &preshared, &N_a1);          /* base = K XOR N             */
        BitArray seed_a1;
        ba_rol_k(&seed_a1, &base_a1, KEYBYTES);       /* seed = ROL(base, n/8)      */
        nl_fscx_revolve_v1_ba(&ks_nl1, &seed_a1, &base_a1, I_VALUE); /* counter=0  */
        ba_xor(&E_nl1, &plaintext, &ks_nl1);
        ba_xor(&D_nl1, &E_nl1,    &ks_nl1);
        ba_print_hex("N (nonce) : ", &N_a1);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Alice) : ", &E_nl1);
        ba_print_hex("D (Bob)   : ", &D_nl1);
        if (ba_equal(&D_nl1, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2] */
    printf("\n--- HSKE-NL-A2 [PQC-HARDENED \xe2\x80\x94 revolve-mode with NL-FSCX v2]\n");
    {
        BitArray E_nl2, D_nl2;
        nl_fscx_revolve_v2_ba(&E_nl2, &plaintext, &preshared, R_VALUE);
        nl_fscx_revolve_v2_inv_ba(&D_nl2, &E_nl2, &preshared, R_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Alice) : ", &E_nl2);
        ba_print_hex("D (Bob)   : ", &D_nl2);
        if (ba_equal(&D_nl2, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
    }

    /* --- HKEX-RNL [PQC -- Ring-LWR key exchange; conjectured quantum-resistant] */
    printf("\n--- HKEX-RNL [PQC \xe2\x80\x94 Ring-LWR key exchange; conjectured quantum-resistant]\n");
    puts("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=256, q=65537)");
    {
        rnl_poly_t m_base, a_rand_poly, m_blind;
        rnl_poly_t s_A_poly, s_B_poly;
        int32_t C_A[RNL_N], C_B[RNL_N];
        BitArray KA, KB, skA_nl, skB_nl;
        int i, bits_diff;
        BitArray diff_ba;

        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand_poly, urnd);
        rnl_poly_add(m_blind, m_base, a_rand_poly);
        uint8_t hint_A[RNL_N / 8];
        rnl_keygen(s_A_poly, C_A, m_blind, urnd);
        rnl_keygen(s_B_poly, C_B, m_blind, urnd);
        rnl_agree(&KA, s_A_poly, C_B, NULL, hint_A);   /* Alice: reconciler */
        rnl_agree(&KB, s_B_poly, C_A, hint_A, NULL);   /* Bob: receiver */
        BitArray seedA, seedB;
        ba_rol_k(&seedA, &KA, KEYBYTES);           /* ROL(K, n/8) = ROL(K, 32) */
        nl_fscx_revolve_v1_ba(&skA_nl, &seedA, &KA, I_VALUE);
        ba_rol_k(&seedB, &KB, KEYBYTES);
        nl_fscx_revolve_v1_ba(&skB_nl, &seedB, &KB, I_VALUE);
        ba_print_hex("sk (Alice): ", &skA_nl);
        ba_print_hex("sk (Bob)  : ", &skB_nl);
        if (ba_equal(&KA, &KB)) {
            puts("+ raw key bits agree; shared session key established!");
        } else {
            ba_xor(&diff_ba, &KA, &KB);
            bits_diff = 0;
            for (i = 0; i < KEYBYTES; i++)
                bits_diff += __builtin_popcount(diff_ba.b[i]);
            printf("- raw key disagrees (%d bit(s)) \xe2\x80\x94 rounding noise (retry)\n",
                   bits_diff);
        }
        sk_rnl_A_saved = skA_nl;
    }

    /* --- HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge] */
    printf("\n--- HPKS-NL [NL-hardened Schnorr \xe2\x80\x94 NL-FSCX v1 challenge]\n");
    puts("    (GF DLP still present; NL hardens linear challenge preimage)");
    {
        BitArray k_nl, R_nl, e_nl, ae_nl, s_nl, gs_nl, Ce_nl, lhs_nl;
        ba_rand(&k_nl, urnd);
        gf_pow_ba(&R_nl, &GF_GEN, &k_nl);
        nl_fscx_revolve_v1_ba(&e_nl, &R_nl, &plaintext, I_VALUE);
        ba_mul_mod_ord(&ae_nl, &a, &e_nl);
        ba_sub_mod_ord(&s_nl, &k_nl, &ae_nl);
        /* verify */
        nl_fscx_revolve_v1_ba(&e_nl, &R_nl, &plaintext, I_VALUE);
        gf_pow_ba(&gs_nl, &GF_GEN, &s_nl);
        gf_pow_ba(&Ce_nl, &C, &e_nl);
        gf_mul_ba(&lhs_nl, &gs_nl, &Ce_nl);
        ba_print_hex("P (msg)        : ", &plaintext);
        ba_print_hex("R [Alice,sign] : ", &R_nl);
        ba_print_hex("e [Alice,sign] : ", &e_nl);
        ba_print_hex("s [Alice,sign] : ", &s_nl);
        ba_print_hex("  [Bob,verify] : g^s\xc2\xb7""C^e = ", &lhs_nl);
        if (ba_equal(&lhs_nl, &R_nl))
            puts("  [Bob,verify] : + HPKS-NL verified: g^s \xc2\xb7 C^e == R");
        else
            puts("  [Bob,verify] : - HPKS-NL verification failed!");
    }

    /* --- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption] */
    printf("\n--- HPKE-NL [NL-hardened El Gamal \xe2\x80\x94 NL-FSCX v2 encryption]\n");
    puts("    (GF DLP still present; NL hardens linear HSKE sub-protocol)");
    {
        BitArray r_nl, R_nl2, enc_nl, E_nl, dec_nl, D_nl;
        ba_rand(&r_nl, urnd);
        gf_pow_ba(&R_nl2,  &GF_GEN, &r_nl);
        gf_pow_ba(&enc_nl, &C,      &r_nl);
        nl_fscx_revolve_v2_ba(&E_nl, &plaintext, &enc_nl, I_VALUE);
        gf_pow_ba(&dec_nl, &R_nl2, &a);
        nl_fscx_revolve_v2_inv_ba(&D_nl, &E_nl, &dec_nl, I_VALUE);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Bob)   : ", &E_nl);
        ba_print_hex("D (Alice) : ", &D_nl);
        if (ba_equal(&D_nl, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- decryption failed!");
        /* save for Eve test */
        E_nl_saved   = E_nl;
        R_nl2_saved  = R_nl2;
    }

    /* *** EVE bypass TESTS *** */
    printf("\n\n*** EVE bypass TESTS\n");

    puts("*** HPKS-NL \xe2\x80\x94 Eve cannot forge Schnorr without knowing private key a");
    {
        BitArray rand_exp, R_eve, e_eve, s_eve, gs_eve, Ce_eve, lhs_eve;
        ba_rand(&rand_exp, urnd);
        gf_pow_ba(&R_eve, &GF_GEN, &rand_exp);
        nl_fscx_revolve_v1_ba(&e_eve, &R_eve, &decoy, I_VALUE);
        ba_rand(&s_eve, urnd);
        gf_pow_ba(&gs_eve,  &GF_GEN, &s_eve);
        gf_pow_ba(&Ce_eve,  &C,      &e_eve);
        gf_mul_ba(&lhs_eve, &gs_eve, &Ce_eve);
        if (ba_equal(&lhs_eve, &R_eve))
            puts("+ Eve forged HPKS-NL signature (Eve wins)!");
        else
            puts("- Eve could not forge: g^s_eve \xc2\xb7 C^e_eve \xe2\x89\xa0 R_eve  (DLP protection)");
    }

    puts("*** HPKE-NL \xe2\x80\x94 Eve cannot decrypt without Alice's private key");
    {
        BitArray eve_key, D_eve;
        /* Eve's wrong key: C XOR R_nl2 (should be C^r = GF product) */
        ba_xor(&eve_key, &C, &R_nl2_saved);
        nl_fscx_revolve_v2_inv_ba(&D_eve, &E_nl_saved, &eve_key, I_VALUE);
        if (ba_equal(&D_eve, &plaintext))
            puts("+ Eve decrypted plaintext (Eve wins)!");
        else
            puts("- Eve could not decrypt without Alice's private key (CDH + NL protection)");
    }

    puts("*** HKEX-RNL \xe2\x80\x94 Eve cannot derive shared key from public ring polynomials");
    {
        BitArray eve_rnl_guess;
        ba_rand(&eve_rnl_guess, urnd);
        if (ba_equal(&eve_rnl_guess, &sk_rnl_A_saved))
            puts("+ Eve guessed HKEX-RNL shared key (astronomically unlikely)!");
        else
            puts("- Eve random guess does not match shared key (Ring-LWR protection)");
    }

    fclose(urnd);
    return 0;
}
