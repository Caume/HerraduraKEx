/*  Herradura Cryptographic Suite v1.5.0

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

    --- v1.5.0: NL-FSCX non-linearity and PQC extensions ---

    New in v1.5.0:
      - NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
        Breaks additive linearity; used in HSKE-NL-A1 (counter-mode) and HPKS-NL.
      - NL-FSCX v2: fscx(A,B) + delta(B) mod 2^n, with invertible delta(B).
        Fully bijective; used in HSKE-NL-A2 (revolve-mode) and HPKE-NL.
      - HSKE-NL-A1: counter-mode symmetric encryption with NL-FSCX v1 keystream.
      - HSKE-NL-A2: revolve-mode symmetric encryption with NL-FSCX v2 (invertible).
      - HKEX-RNL: Ring-LWR key exchange (n=32 demo; production size n=256).
        Conjectured quantum-resistant under Ring-LWR hardness assumption.
      - HPKS-NL: NL-hardened Schnorr signature using NL-FSCX v1 challenge.
      - HPKE-NL: NL-hardened El Gamal encryption using NL-FSCX v2.

    --- v1.4.0: HKEX replaced with HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The classical HKEX key exchange is BROKEN: sk = S_{r+1}*(C XOR C2) is a
    publicly computable linear formula (proved in SecurityProofs.md, Theorem 7).
    fscx_revolve_n offered no fix (nonce cancels identically, Theorem 10).

    HKEX-GF replaces HKEX with Diffie-Hellman over GF(2^KEYBITS)*:
      - Alice: private scalar a, public C  = g^a  (GF exponentiation)
      - Bob:   private scalar b, public C2 = g^b
      - Shared: sk = C2^a = C^b = g^{ab}  (field commutativity)
    Security: CDH/DLP in GF(2^n)*. For n=256, classical security ~128 bits
    under the best known index-calculus attacks.

    fscx_revolve_n is removed — it provided no security benefit.
    HSKE, HPKS, HPKE keep standard fscx_revolve unchanged.

    --- v1.3.2: performance and readability ---

    - ba_fscx: fused into a single-pass loop.
    - ba_fscx_revolve: double-buffered with index swap.
    - ba_rol1 / ba_ror1: inlined inside ba_fscx.
    - ba_xor_into: replaced by ba_xor(dst, dst, src).

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
 * 32-bit GF(2^32) arithmetic and FSCX for HPKS Schnorr and HPKE El Gamal.
 *
 * Schnorr requires s = (k - a*e) mod ORD where ORD = 2^32-1.  Using 32-bit
 * parameters keeps this computable with a uint64_t intermediate for a*e.
 *
 * Primitive polynomial for GF(2^32): x^32+x^22+x^2+x+1 = 0x00400007
 * Generator g = 3.
 * ───────────────────────────────────────────────────────────────────────────── */

#define GF_POLY32  0x00400007UL
#define GF_GEN32   3UL
#define I_VALUE32  8             /* 32/4 */
#define R_VALUE32  24            /* 3*32/4 */

static uint32_t gf_mul_32(uint32_t a, uint32_t b)
{
    uint32_t r = 0;
    int i;
    for (i = 0; i < 32; i++) {
        if (b & 1) r ^= a;
        { uint32_t carry = a >> 31; a <<= 1; if (carry) a ^= (uint32_t)GF_POLY32; }
        b >>= 1;
    }
    return r;
}

static uint32_t gf_pow_32(uint32_t base, uint32_t exp)
{
    uint32_t r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_32(r, base);
        base = gf_mul_32(base, base);
        exp >>= 1;
    }
    return r;
}

static uint32_t rol32(uint32_t x) { return (x << 1) | (x >> 31); }
static uint32_t ror32(uint32_t x) { return (x >> 1) | (x << 31); }

static uint32_t fscx32(uint32_t a, uint32_t b)
{
    return a ^ b ^ rol32(a) ^ rol32(b) ^ ror32(a) ^ ror32(b);
}

static uint32_t fscx_revolve32(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = fscx32(a, b);
    return a;
}

static uint32_t rand32(FILE *urnd)
{
    uint32_t v;
    if (fread(&v, 4, 1, urnd) != 1) {
        fputs("ERROR: could not read from /dev/urandom\n", stderr);
        exit(1);
    }
    return v;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 256-bit integer helpers (needed for NL-FSCX v2)
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

/* ─────────────────────────────────────────────────────────────────────────────
 * 256-bit NL-FSCX primitives
 * ───────────────────────────────────────────────────────────────────────────── */

static const BitArray ZERO_BA = {{0}};
static const BitArray ONE_BA  = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x01
}};

/* M^{-1}(X) = M^{127}(X): apply fscx with B=0 for KEYBITS/2-1 = 127 steps */
static void m_inv_ba(BitArray *dst, const BitArray *src)
{
    ba_fscx_revolve(dst, src, &ZERO_BA, KEYBITS / 2 - 1);
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
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *y;
    for (i = 0; i < steps; i++) {
        nl_fscx_v2_inv_ba(&buf[1 - idx], &buf[idx], b);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 32-bit NL-FSCX primitives (for HPKS-NL and HPKE-NL)
 * ───────────────────────────────────────────────────────────────────────────── */

/* M^{-1} at 32 bits: M^{15} = 15 fscx steps with B=0 */
static uint32_t m_inv32(uint32_t x)
{
    int i;
    for (i = 0; i < 15; i++) x = fscx32(x, 0);
    return x;
}

/* NL-FSCX v1 (32-bit): fscx(A,B) XOR ROL((A+B) mod 2^32, 8) */
static uint32_t nl_fscx32_v1(uint32_t a, uint32_t b)
{
    uint32_t mix = a + b; /* mod 2^32 */
    uint32_t rol8 = (mix << 8) | (mix >> 24);
    return fscx32(a, b) ^ rol8;
}

static uint32_t nl_fscx_revolve32_v1(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx32_v1(a, b);
    return a;
}

static uint32_t nl_fscx_delta32_v2(uint32_t b)
{
    uint32_t half = (b + 1) >> 1;
    uint32_t prod = b * half;
    return (prod << 8) | (prod >> 24);
}

static uint32_t nl_fscx32_v2(uint32_t a, uint32_t b)
{
    return fscx32(a, b) + nl_fscx_delta32_v2(b); /* mod 2^32 */
}

static uint32_t nl_fscx32_v2_inv(uint32_t y, uint32_t b)
{
    uint32_t z = y - nl_fscx_delta32_v2(b); /* mod 2^32 */
    return b ^ m_inv32(z);
}

static uint32_t nl_fscx_revolve32_v2(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx32_v2(a, b);
    return a;
}

static uint32_t nl_fscx_revolve32_v2_inv(uint32_t y, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) y = nl_fscx32_v2_inv(y, b);
    return y;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HKEX-RNL: Ring-LWR key exchange helpers (n=32 for practical demo speed)
 * ───────────────────────────────────────────────────────────────────────────── */

#define RNL_N  32
#define RNL_Q  65537
#define RNL_P  4096
#define RNL_PP 2
#define RNL_B  1

typedef int32_t rnl_poly_t[RNL_N];

/* Negacyclic multiply: h = f*g in Z_q[x]/(x^n+1) */
static void rnl_poly_mul(rnl_poly_t h, const rnl_poly_t f, const rnl_poly_t g)
{
    int32_t tmp[RNL_N];
    int i, j;
    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < RNL_N; i++) {
        if (!f[i]) continue;
        for (j = 0; j < RNL_N; j++) {
            int k = i + j;
            int64_t prod = (int64_t)f[i] * g[j];
            if (k < RNL_N)
                tmp[k] = (int32_t)((tmp[k] + prod) % RNL_Q);
            else
                tmp[k - RNL_N] = (int32_t)((tmp[k - RNL_N] - prod % RNL_Q + RNL_Q) % RNL_Q);
        }
    }
    memcpy(h, tmp, sizeof(rnl_poly_t));
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
    int i;
    uint32_t v;
    for (i = 0; i < RNL_N; i++) {
        if (fread(&v, 4, 1, urnd) != 1) { fputs("urandom error\n", stderr); exit(1); }
        p[i] = (int32_t)(v % RNL_Q);
    }
}

static void rnl_small_poly(rnl_poly_t p, FILE *urnd)
{
    int i;
    uint8_t v;
    for (i = 0; i < RNL_N; i++) {
        if (fread(&v, 1, 1, urnd) != 1) { fputs("urandom error\n", stderr); exit(1); }
        p[i] = (int32_t)(v % (RNL_B + 1));
    }
}

/* Extract RNL_N bits into uint32_t (coefficient >= pp/2 -> bit=1) */
static void rnl_bits_to_u32(uint32_t *out, const int32_t *bits_poly)
{
    int i;
    *out = 0;
    for (i = 0; i < RNL_N; i++)
        if (bits_poly[i] >= RNL_PP / 2) *out |= (1u << i);
}

/* keygen: s=small private, C=round_p(m_blind * s) */
static void rnl_keygen(int32_t s_out[RNL_N], int32_t c_out[RNL_N],
                       const rnl_poly_t m_blind, FILE *urnd)
{
    rnl_poly_t ms;
    rnl_small_poly(s_out, urnd);
    rnl_poly_mul(ms, m_blind, s_out);
    rnl_round(c_out, ms, RNL_Q, RNL_P);
}

/* agree: K_bits = round_pp(s * lift(C_other)) */
static uint32_t rnl_agree(const int32_t s[RNL_N], const int32_t c_other[RNL_N])
{
    rnl_poly_t c_lifted, k_poly;
    int32_t k_bits[RNL_N];
    uint32_t result;
    rnl_lift(c_lifted, c_other, RNL_P, RNL_Q);
    rnl_poly_mul(k_poly, s, c_lifted);
    rnl_round(k_bits, k_poly, RNL_Q, RNL_PP);
    rnl_bits_to_u32(&result, k_bits);
    return result;
}

/*
HKEX-GF (key exchange — Diffie-Hellman over GF(2^n)*):
    Pre-agreed: irreducible polynomial p(x), generator g.
    Alice:  private a -> public C  = g^a
    Bob:    private b -> public C2 = g^b
    Shared: sk = C2^a = C^b = g^{ab}  (field multiplication is commutative)

HSKE (symmetric key encryption — FSCX-based, unchanged):
    share key of bitlength n
    Alice:  E = fscx_revolve(P, key, i)
    Bob:    P = fscx_revolve(E, key, r)  [i+r=n -> orbit closes]

HPKS (Schnorr public key signature, 32-bit GF params):
    Alice private: a,  public C = g^a,  ORD = 2^32-1
    Sign(P):  k random; R=g^k; e=fscx_revolve(R,P,i); s=(k-a*e) mod ORD
    Verify:   g^s * C^e == R

HPKE (El Gamal public key encryption, 32-bit GF params):
    Alice private: a,  public C = g^a
    Bob encrypts: r random; R=g^r; enc_key=C^r; E=fscx_revolve(P,enc_key,i)
    Alice decrypts: dec_key=R^a; D=fscx_revolve(E,dec_key,r) = P

HSKE-NL-A1 (counter-mode with NL-FSCX v1, 256-bit):
    ks = nl_fscx_revolve_v1(K, K XOR counter, I_VALUE)
    E = P XOR ks;  D = E XOR ks = P

HSKE-NL-A2 (revolve-mode with NL-FSCX v2, 256-bit):
    E = nl_fscx_revolve_v2(P, K, R_VALUE)
    D = nl_fscx_revolve_v2_inv(E, K, R_VALUE) = P

HKEX-RNL (Ring-LWR key exchange, n=32 demo):
    Shared m_blind = m(x) + a_rand in Z_q[x]/(x^n+1)
    Alice: s_A small, C_A = round_p(m_blind * s_A)
    Bob:   s_B small, C_B = round_p(m_blind * s_B)
    K_A = round_pp(s_A * lift(C_B));  K_B = round_pp(s_B * lift(C_A))
    K_A ~= K_B (with high probability)

HPKS-NL (NL-hardened Schnorr, 32-bit):
    e = nl_fscx_revolve32_v1(R, P, I_VALUE32)

HPKE-NL (NL-hardened El Gamal, 32-bit):
    E = nl_fscx_revolve32_v2(P, enc_key, I_VALUE32)
    D = nl_fscx_revolve32_v2_inv(E, dec_key, I_VALUE32)
*/

int main(void)
{
    FILE *urnd;
    BitArray a_priv, b_priv;
    BitArray C, C2;
    BitArray skeyA, skeyB;
    BitArray preshared, plaintext;
    BitArray E_ba, D_ba;

    uint32_t a32, plain32;
    uint32_t C32;
    uint32_t k32, R32, e32, s32;
    uint32_t r32, R_hpke, enc_key32;
    uint32_t dec_key32, E32, D32;
    uint64_t ae64;
    uint64_t ord32 = 0xFFFFFFFFULL;

    urnd = fopen("/dev/urandom", "rb");
    if (!urnd) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    ba_rand(&a_priv,    urnd);
    ba_rand(&b_priv,    urnd);
    ba_rand(&preshared, urnd);
    ba_rand(&plaintext, urnd);
    a_priv.b[KEYBYTES - 1] |= 1;
    b_priv.b[KEYBYTES - 1] |= 1;

    a32     = rand32(urnd) | 1;
    plain32 = rand32(urnd);
    C32     = gf_pow_32((uint32_t)GF_GEN32, a32);

    ba_print_hex("a_priv    : ", &a_priv);
    ba_print_hex("b_priv    : ", &b_priv);
    ba_print_hex("preshared : ", &preshared);
    ba_print_hex("plaintext : ", &plaintext);

    /* --- HKEX-GF [CLASSICAL — not PQC; Shor's algorithm breaks DLP] */
    printf("\n--- HKEX-GF [CLASSICAL \xe2\x80\x94 not PQC; Shor's algorithm breaks DLP]\n");
    gf_pow_ba(&C,     &GF_GEN, &a_priv);
    gf_pow_ba(&C2,    &GF_GEN, &b_priv);
    gf_pow_ba(&skeyA, &C2,     &a_priv);
    gf_pow_ba(&skeyB, &C,      &b_priv);
    ba_print_hex("C         : ", &C);
    ba_print_hex("C2        : ", &C2);
    ba_print_hex("skeyA     : ", &skeyA);
    ba_print_hex("skeyB     : ", &skeyB);
    if (ba_equal(&skeyA, &skeyB))
        puts("+ session keys skeyA and skeyB are equal!");
    else
        puts("- session keys skeyA and skeyB are different!");

    /* --- HSKE [CLASSICAL — not PQC; linear key recovery from 1 KPT pair] */
    printf("\n--- HSKE [CLASSICAL \xe2\x80\x94 not PQC; linear key recovery from 1 KPT pair]\n");
    ba_print_hex("P (plain) : ", &plaintext);
    ba_fscx_revolve(&E_ba, &plaintext, &preshared, I_VALUE);
    ba_print_hex("E (Alice) : ", &E_ba);
    ba_fscx_revolve(&D_ba, &E_ba, &preshared, R_VALUE);
    ba_print_hex("D (Bob)   : ", &D_ba);
    if (ba_equal(&D_ba, &plaintext))
        puts("+ plaintext correctly decrypted");
    else
        puts("- plaintext is different from decrypted E!");

    /* --- HPKS [CLASSICAL — not PQC; DLP + linear challenge] */
    printf("\n--- HPKS [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear challenge]\n");
    printf("a32       : 0x%08x\n", a32);
    printf("C32 (g^a) : 0x%08x\n", C32);
    k32  = rand32(urnd);
    R32  = gf_pow_32((uint32_t)GF_GEN32, k32);
    e32  = fscx_revolve32(R32, plain32, I_VALUE32);
    ae64 = (uint64_t)a32 * (uint64_t)e32 % ord32;
    s32  = (uint32_t)(((uint64_t)k32 + ord32 - ae64) % ord32);
    printf("P (msg)        : 0x%08x\n", plain32);
    printf("R [Alice,sign] : 0x%08x\n", R32);
    printf("e [Alice,sign] : 0x%08x\n", e32);
    printf("s [Alice,sign] : 0x%08x\n", s32);
    {
        uint32_t gs = gf_pow_32((uint32_t)GF_GEN32, s32);
        uint32_t Ce = gf_pow_32(C32, e32);
        uint32_t lhs = gf_mul_32(gs, Ce);
        printf("  [Bob,verify] : g^s\xc2\xb7""C^e = 0x%08x\n", lhs);
        if (lhs == R32)
            puts("  [Bob,verify] : + Schnorr verified: g^s \xc2\xb7 C^e == R");
        else
            puts("  [Bob,verify] : - Schnorr verification FAILED!");
    }

    /* --- HPKE [CLASSICAL — not PQC; DLP + linear HSKE sub-protocol] */
    printf("\n--- HPKE [CLASSICAL \xe2\x80\x94 not PQC; DLP + linear HSKE sub-protocol]\n");
    r32       = rand32(urnd) | 1;
    R_hpke    = gf_pow_32((uint32_t)GF_GEN32, r32);
    enc_key32 = gf_pow_32(C32, r32);
    E32       = fscx_revolve32(plain32, enc_key32, I_VALUE32);
    dec_key32 = gf_pow_32(R_hpke, a32);
    D32       = fscx_revolve32(E32, dec_key32, R_VALUE32);
    printf("P (plain) : 0x%08x\n", plain32);
    printf("R (g^r)   : 0x%08x\n", R_hpke);
    printf("E (Bob)   : 0x%08x\n", E32);
    printf("D (Alice) : 0x%08x\n", D32);
    if (D32 == plain32)
        puts("+ plaintext correctly decrypted");
    else
        puts("- HPKE El Gamal decryption FAILED!");

    /* --- HSKE-NL-A1 [PQC-HARDENED — counter-mode with NL-FSCX v1] */
    printf("\n--- HSKE-NL-A1 [PQC-HARDENED \xe2\x80\x94 counter-mode with NL-FSCX v1]\n");
    {
        BitArray ks_nl1, E_nl1, D_nl1;
        /* counter=0: B = preshared XOR 0 = preshared */
        nl_fscx_revolve_v1_ba(&ks_nl1, &preshared, &preshared, I_VALUE);
        ba_xor(&E_nl1, &plaintext, &ks_nl1);
        ba_xor(&D_nl1, &E_nl1,    &ks_nl1);
        ba_print_hex("P (plain) : ", &plaintext);
        ba_print_hex("E (Alice) : ", &E_nl1);
        ba_print_hex("D (Bob)   : ", &D_nl1);
        if (ba_equal(&D_nl1, &plaintext))
            puts("+ plaintext correctly decrypted");
        else
            puts("- HSKE-NL-A1 decryption FAILED!");
    }

    /* --- HSKE-NL-A2 [PQC-HARDENED — revolve-mode with NL-FSCX v2] */
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
            puts("- HSKE-NL-A2 decryption FAILED!");
    }

    /* --- HKEX-RNL [PQC — Ring-LWR key exchange; conjectured quantum-resistant] */
    printf("\n--- HKEX-RNL [PQC \xe2\x80\x94 Ring-LWR key exchange; conjectured quantum-resistant]\n");
    printf("    (ring size n=%d; production size is n=256)\n", RNL_N);
    {
        rnl_poly_t m_base, a_rand_poly, m_blind;
        rnl_poly_t s_A_poly, s_B_poly;
        int32_t C_A[RNL_N], C_B[RNL_N];
        uint32_t KA, KB, skA_nl, skB_nl;

        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand_poly, urnd);
        rnl_poly_add(m_blind, m_base, a_rand_poly);
        rnl_keygen(s_A_poly, C_A, m_blind, urnd);
        rnl_keygen(s_B_poly, C_B, m_blind, urnd);
        KA = rnl_agree(s_A_poly, C_B);
        KB = rnl_agree(s_B_poly, C_A);
        printf("K_raw_A   : 0x%08x\n", KA);
        printf("K_raw_B   : 0x%08x\n", KB);
        skA_nl = nl_fscx_revolve32_v1(KA, KA, I_VALUE32);
        skB_nl = nl_fscx_revolve32_v1(KB, KB, I_VALUE32);
        printf("sk_A (NL) : 0x%08x\n", skA_nl);
        printf("sk_B (NL) : 0x%08x\n", skB_nl);
        if (KA == KB)
            puts("+ raw keys agree");
        else
            puts("- raw keys differ (reconciliation error — retry with fresh keys)");
        if (skA_nl == skB_nl)
            puts("+ session keys agree");
        else
            puts("- session keys differ");
    }

    /* --- HPKS-NL [NL-hardened Schnorr — NL-FSCX v1 challenge] */
    printf("\n--- HPKS-NL [NL-hardened Schnorr \xe2\x80\x94 NL-FSCX v1 challenge]\n");
    {
        uint32_t k_nl, R_nl, e_nl, s_nl;
        k_nl  = rand32(urnd);
        R_nl  = gf_pow_32((uint32_t)GF_GEN32, k_nl);
        e_nl  = nl_fscx_revolve32_v1(R_nl, plain32, I_VALUE32);
        ae64  = (uint64_t)a32 * (uint64_t)e_nl % ord32;
        s_nl  = (uint32_t)(((uint64_t)k_nl + ord32 - ae64) % ord32);
        printf("P (msg)        : 0x%08x\n", plain32);
        printf("R [Alice,sign] : 0x%08x\n", R_nl);
        printf("e [Alice,sign] : 0x%08x\n", e_nl);
        printf("s [Alice,sign] : 0x%08x\n", s_nl);
        {
            uint32_t gs_nl = gf_pow_32((uint32_t)GF_GEN32, s_nl);
            uint32_t Ce_nl = gf_pow_32(C32, e_nl);
            uint32_t lhs_nl = gf_mul_32(gs_nl, Ce_nl);
            printf("  [Bob,verify] : g^s\xc2\xb7""C^e = 0x%08x\n", lhs_nl);
            if (lhs_nl == R_nl)
                puts("  [Bob,verify] : + Schnorr verified: g^s \xc2\xb7 C^e == R");
            else
                puts("  [Bob,verify] : - Schnorr verification FAILED!");
        }
    }

    /* --- HPKE-NL [NL-hardened El Gamal — NL-FSCX v2 encryption] */
    printf("\n--- HPKE-NL [NL-hardened El Gamal \xe2\x80\x94 NL-FSCX v2 encryption]\n");
    {
        uint32_t r_nl, R_nl_hpke, enc_nl, E_nl32, dec_nl, D_nl32;
        r_nl      = rand32(urnd) | 1;
        R_nl_hpke = gf_pow_32((uint32_t)GF_GEN32, r_nl);
        enc_nl    = gf_pow_32(C32, r_nl);
        E_nl32    = nl_fscx_revolve32_v2(plain32, enc_nl, I_VALUE32);
        dec_nl    = gf_pow_32(R_nl_hpke, a32);
        D_nl32    = nl_fscx_revolve32_v2_inv(E_nl32, dec_nl, I_VALUE32);
        printf("P (plain) : 0x%08x\n", plain32);
        printf("R (g^r)   : 0x%08x\n", R_nl_hpke);
        printf("E (Bob)   : 0x%08x\n", E_nl32);
        printf("D (Alice) : 0x%08x\n", D_nl32);
        if (D_nl32 == plain32)
            puts("+ plaintext correctly decrypted");
        else
            puts("- HPKE-NL decryption FAILED!");
    }

    /* *** EVE bypass TESTS *** */
    printf("\n\n*** EVE bypass TESTS\n");

    /* Eve attempts HPKS-NL Schnorr forgery */
    printf("\n*** HPKS-NL Schnorr \xe2\x80\x94 Eve cannot forge without DLP solution\n");
    {
        uint32_t r_eve   = rand32(urnd);
        uint32_t s_eve   = rand32(urnd);
        uint32_t e_eve   = nl_fscx_revolve32_v1(r_eve, plain32, I_VALUE32);
        uint32_t gs_eve  = gf_pow_32((uint32_t)GF_GEN32, s_eve);
        uint32_t Ce_eve  = gf_pow_32(C32, e_eve);
        uint32_t lhs_eve = gf_mul_32(gs_eve, Ce_eve);
        printf("R_eve     : 0x%08x\n", r_eve);
        printf("lhs_eve   : 0x%08x\n", lhs_eve);
        if (lhs_eve == r_eve)
            puts("+ Eve forged signature (attack succeeded - UNEXPECTED!)");
        else
            puts("- Eve could not forge signature (NL-DLP protection holds)");
    }

    /* Eve attempts HPKE-NL XOR key guess */
    printf("\n*** HPKE-NL El Gamal \xe2\x80\x94 Eve cannot decrypt without CDH solution\n");
    {
        uint32_t r_nl2, R_nl2, enc_nl2, E_nl2_val, dec_nl2, D_nl2_val;
        r_nl2    = rand32(urnd) | 1;
        R_nl2    = gf_pow_32((uint32_t)GF_GEN32, r_nl2);
        enc_nl2  = gf_pow_32(C32, r_nl2);
        E_nl2_val = nl_fscx_revolve32_v2(plain32, enc_nl2, I_VALUE32);
        uint32_t eve_key = C32 ^ R_nl2; /* wrong: XOR instead of GF product */
        D_nl2_val = nl_fscx_revolve32_v2_inv(E_nl2_val, eve_key, I_VALUE32);
        printf("eve_key   : 0x%08x (C XOR R, not C^r)\n", eve_key);
        printf("D_eve     : 0x%08x\n", D_nl2_val);
        if (D_nl2_val == plain32)
            puts("+ Eve decrypted plaintext (attack succeeded - UNEXPECTED!)");
        else
            puts("- Eve could not decrypt without CDH solution (NL-DLP protection holds)");
    }

    /* Eve attempts HKEX-RNL random 32-bit guess */
    printf("\n*** HKEX-RNL \xe2\x80\x94 Eve random 32-bit key guess\n");
    {
        rnl_poly_t m_base2, a_rand2, m_blind2;
        int32_t C_A2[RNL_N], C_B2[RNL_N];
        rnl_poly_t s_A2, s_B2;
        uint32_t KA2, KB2, eve_guess;
        rnl_m_poly(m_base2);
        rnl_rand_poly(a_rand2, urnd);
        rnl_poly_add(m_blind2, m_base2, a_rand2);
        rnl_keygen(s_A2, C_A2, m_blind2, urnd);
        rnl_keygen(s_B2, C_B2, m_blind2, urnd);
        KA2 = rnl_agree(s_A2, C_B2);
        KB2 = rnl_agree(s_B2, C_A2);
        eve_guess = rand32(urnd);
        printf("KA2       : 0x%08x\n", KA2);
        printf("KB2       : 0x%08x\n", KB2);
        printf("eve_guess : 0x%08x\n", eve_guess);
        if (eve_guess == KA2 || eve_guess == KB2)
            puts("+ Eve guessed key (attack succeeded - UNEXPECTED!)");
        else
            puts("- Eve random guess failed (Ring-LWR protection holds)");
    }

    fclose(urnd);
    return 0;
}
