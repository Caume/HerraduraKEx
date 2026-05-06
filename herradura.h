/*  herradura.h — Herradura Cryptographic Suite, header-only shared library
    v1.5.24

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

    Protocols: HKEX-GF, HSKE, HPKS, HPKE (classical); HSKE-NL-A1/A2, HKEX-RNL,
    HPKS-NL, HPKE-NL (NL/PQC); HPKS-Stern-F, HPKE-Stern-F (code-based PQC).
    All operate at KEYBITS=256.
*/

#ifndef HERRADURA_H
#define HERRADURA_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Key-size parameters
 * ───────────────────────────────────────────────────────────────────────────── */

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

/* ─────────────────────────────────────────────────────────────────────────────
 * BitArray primitives
 * ───────────────────────────────────────────────────────────────────────────── */

/* Fill dst with KEYBYTES random bytes from urnd (/dev/urandom). */
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

/* Popcount of a 256-bit BitArray. */
static int ba_popcount(const BitArray *a)
{
    int i, n = 0;
    for (i = 0; i < KEYBYTES; i++) n += __builtin_popcount(a->b[i]);
    return n;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FSCX primitives
 * ───────────────────────────────────────────────────────────────────────────── */

/* Full Surroundings Cyclic XOR:
   result = a XOR b XOR ROL(a) XOR ROL(b) XOR ROR(a) XOR ROR(b)
   Fused single-pass; requires KEYBYTES >= 2. */
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

/* Shift big-endian BitArray right by 1 bit (in-place).  Returns the LSB shifted out. */
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
   Shift-and-XOR: O(KEYBITS) iterations. */
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
        int16_t s = (int16_t)a->b[i] - (int16_t)b->b[i] - borrow;
        dst->b[i] = (uint8_t)(s & 0xFF);
        borrow = (s < 0) ? 1 : 0;
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
static void ba_mul256(BitArray *dst, const BitArray *a, const BitArray *b)
{
    uint64_t acc[KEYBYTES];
    int i, j;
    memset(acc, 0, sizeof(acc));
    for (i = 0; i < KEYBYTES; i++)
        for (j = 0; j < KEYBYTES - i; j++) {
            int ridx = KEYBYTES - 1 - i - j;
            acc[ridx] += (uint64_t)a->b[KEYBYTES - 1 - i] * b->b[KEYBYTES - 1 - j];
        }
    {
        uint64_t carry = 0;
        for (i = KEYBYTES - 1; i >= 0; i--) {
            uint64_t s = acc[i] + carry;
            dst->b[i] = (uint8_t)s;
            carry = s >> 8;
        }
    }
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
        {
            int k;
            for (k = i + KEYBYTES; carry && k < 2 * KEYBYTES; k++) {
                uint16_t s = (uint16_t)full[k] + carry;
                full[k] = (uint8_t)s;
                carry = s >> 8;
            }
        }
    }
    carry = 0;
    for (i = 0; i < KEYBYTES; i++) {
        uint16_t s = (uint16_t)full[i] + full[KEYBYTES + i] + carry;
        lo[i] = (uint8_t)s;
        carry = s >> 8;
    }
    if (carry) {
        carry = 1;
        for (i = 0; i < KEYBYTES && carry; i++) {
            uint16_t s = (uint16_t)lo[i] + carry;
            lo[i] = (uint8_t)s;
            carry = s >> 8;
        }
        if (carry) { memset(lo, 0, KEYBYTES); lo[0] = 1; }
    } else {
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
        for (i = KEYBYTES - 1; i >= 0; i--) {
            if (dst->b[i] > 0) { dst->b[i]--; break; }
            dst->b[i] = 0xFF;
        }
    }
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

/* M^{-1} polynomial table for n=256: 256-bit bitmask split into four 64-bit words.
   Derived from GCD(1+x+x^255, x^256+1) in GF(2)[x]. */
static const uint64_t MINV256_TBL[4] = {
    UINT64_C(0xb6db6db6db6db6db),  /* k=0..63   */
    UINT64_C(0xdb6db6db6db6db6d),  /* k=64..127 */
    UINT64_C(0x6db6db6db6db6db6),  /* k=128..191 */
    UINT64_C(0xb6db6db6db6db6db)   /* k=192..255 */
};

/* M^{-1}(x): apply precomputed rotation table (MINV256_TBL). */
static void m_inv_ba(BitArray *result, const BitArray *x)
{
    BitArray r, rot;
    int k;
    r = *x;   /* k=0 term */
    for (k = 1; k < KEYBITS; k++) {
        if ((MINV256_TBL[k >> 6] >> (k & 63)) & 1) {
            ba_rol_k(&rot, x, k);
            ba_xor(&r, &r, &rot);
        }
    }
    *result = r;
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
static void nl_fscx_delta_v2_ba(BitArray *delta, const BitArray *b)
{
    BitArray b1, half, prod;
    ba_add256(&b1, b, &ONE_BA);
    half = b1; ba_shr1(&half);
    ba_mul256(&prod, b, &half);
    ba_rol64_256(delta, &prod);
}

/* NL-FSCX v2: (fscx(A,B) + delta(B)) mod 2^n */
static void nl_fscx_v2_ba(BitArray *result, const BitArray *a, const BitArray *b)
{
    BitArray f, d;
    ba_fscx(&f, a, b);
    nl_fscx_delta_v2_ba(&d, b);
    ba_add256(result, &f, &d);
}

/* NL-FSCX v2 inverse: A = B XOR M^{-1}((Y - delta(B)) mod 2^n) */
static void nl_fscx_v2_inv_ba(BitArray *result, const BitArray *y, const BitArray *b)
{
    BitArray d, z, mz;
    nl_fscx_delta_v2_ba(&d, b);
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
    nl_fscx_delta_v2_ba(&delta, b);   /* precompute once — b is constant */
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
 * HFSCX-256: Merkle-Damgård hash on NL-FSCX v1 (v1.5.25)
 * ───────────────────────────────────────────────────────────────────────────── */

/* IV: "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0" (32 bytes) */
static const uint8_t _HFSCX256_IV[32] = {
    'H','F','S','C','X','-','2','5','6','/','H','E','R','R','A','D',
    'U','R','A','-','S','U','I','T','E',0,0,0,0,0,0,0
};

/* HFSCX-256: Merkle-Damgård hash built on NL-FSCX v1.
 * Bare hash: iv = NULL.  Keyed MAC: iv = key XOR _HFSCX256_IV (32 bytes). */
static void hfscx_256(const uint8_t *data, size_t len,
                      const uint8_t *iv, uint8_t out[32])
{
    const uint8_t *init = iv ? iv : _HFSCX256_IV;
    BitArray state, block;
    size_t padded_len, off;
    uint8_t *padded;
    uint64_t bit_len;
    int i;

    memcpy(state.b, init, 32);

    /* ISO 7816-4 padding: data || 0x80 || zeros to 32-byte boundary */
    padded_len = len + 1;
    if (padded_len % 32) padded_len += 32 - padded_len % 32;
    padded_len += 32;  /* MD-strengthening length block */

    padded = (uint8_t *)malloc(padded_len);
    if (len) memcpy(padded, data, len);
    padded[len] = 0x80;
    memset(padded + len + 1, 0, padded_len - len - 1);

    /* Length block: (bit_length_be64 XOR init) in the last 32 bytes.
     * XOR with init binds the key and prevents fixed-point collapse. */
    bit_len = (uint64_t)len * 8;
    {
        uint8_t *lb = padded + padded_len - 32;
        memcpy(lb, init, 32);
        for (i = 0; i < 8; i++)
            lb[24 + i] ^= (uint8_t)((bit_len >> (56 - 8 * i)) & 0xFF);
    }

    /* Chain each 32-byte block through 64 steps of NL-FSCX v1 */
    for (off = 0; off < padded_len; off += 32) {
        memcpy(block.b, padded + off, 32);
        nl_fscx_revolve_v1_ba(&state, &state, &block, 64);
    }

    memcpy(out, state.b, 32);
    free(padded);
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

/* Fermat-prime modular multiply mod 65537 = 2^16+1.
   x = a*b; since 2^16 ≡ -1 and 2^32 ≡ 1 mod q: x ≡ lo - mid + hi (mod q).
   r ∈ [-65535, 65536] so at most one conditional add/subtract needed. */
static inline uint32_t rnl_mulmodq(uint32_t a, uint32_t b)
{
    uint64_t x = (uint64_t)a * b;
    int32_t r = (int32_t)(x & 0xFFFF)
              - (int32_t)((x >> 16) & 0xFFFF)
              + (int32_t)(x >> 32);
    if (r < 0) r += 65537;
    return (uint32_t)r;
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
                int32_t v = (int32_t)rnl_mulmodq((uint32_t)a[i + k + (length >> 1)], wn);
                a[i + k]                 = (u + v) % q;
                a[i + k + (length >> 1)] = (u - v + q) % q;
                wn = rnl_mulmodq(wn, w);
            }
        }
    }
    if (invert) {
        for (i = 0; i < n; i++)
            a[i] = (int32_t)rnl_mulmodq((uint32_t)a[i], rnl_tw.inv_n);
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
        fa[i] = (int32_t)rnl_mulmodq((uint32_t)f[i], rnl_tw.psi_pow[i]);
        ga[i] = (int32_t)rnl_mulmodq((uint32_t)g[i], rnl_tw.psi_pow[i]);
    }
    rnl_ntt(fa, RNL_N, RNL_Q, 0);
    rnl_ntt(ga, RNL_N, RNL_Q, 0);
    for (i = 0; i < RNL_N; i++)
        ha[i] = (int32_t)rnl_mulmodq((uint32_t)fa[i], (uint32_t)ga[i]);
    rnl_ntt(ha, RNL_N, RNL_Q, 1);
    for (i = 0; i < RNL_N; i++)
        h[i] = (int32_t)rnl_mulmodq((uint32_t)ha[i], rnl_tw.psi_inv_pow[i]);
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

/* CBD(eta=1): 4 coefficients per byte — bit-pairs (0-1),(2-3),(4-5),(6-7).
   Produces {-1,0,1} with P(-1)=P(1)=1/4, P(0)=1/2; zero mean. */
static void rnl_cbd_poly(rnl_poly_t p, FILE *urnd)
{
    int i;
    uint8_t buf[(RNL_N + 3) / 4];
    if (fread(buf, 1, sizeof(buf), urnd) != sizeof(buf)) {
        fputs("urandom error\n", stderr); exit(1);
    }
    for (i = 0; i < RNL_N; i++) {
        int off = (i & 3) * 2;
        int a = (buf[i >> 2] >> off) & 1;
        int b = (buf[i >> 2] >> (off + 1)) & 1;
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

/* ─────────────────────────────────────────────────────────────────────────────
 * CODE-BASED PQC: HPKS-Stern-F / HPKE-Stern-F  (v1.5.18)
 * Stern 3-challenge ZKP + Fiat-Shamir in QROM.
 * Security: EUF-CMA <= q_H/T_SD + eps_PRF  (Theorem 17, SecurityProofs.md §11.8.4).
 * N=KEYBITS=256, n_rows=128, t=16, rounds=32  (production: >=219).
 * ───────────────────────────────────────────────────────────────────────────── */

#define SDF_N_ROWS   (KEYBITS / 2)     /* parity-check rows: 128             */
#define SDF_T        (KEYBITS / 16)    /* error weight: 16                   */
#define SDF_ROUNDS   32                /* ZKP rounds (demo; prod >= 219)     */
#define SDF_SYNBYTES (SDF_N_ROWS / 8)  /* syndrome bytes: 16                 */

/* Chain-hash: h <- NL-FSCX_v1^I(h XOR v, ROL(v, n/8)) for each item. */
static void stern_hash(BitArray *out, const BitArray *items, int n_items)
{
    BitArray h = {{0}};
    int i;
    for (i = 0; i < n_items; i++) {
        BitArray hxv, rotv;
        ba_xor(&hxv, &h, &items[i]);
        ba_rol_k(&rotv, &items[i], KEYBITS / 8);
        nl_fscx_revolve_v1_ba(&h, &hxv, &rotv, I_VALUE);
    }
    *out = h;
}

/* H[row] = NL-FSCX_v1^I(ROL(seed XOR row, n/8), seed) */
static void stern_matrix_row(BitArray *out, const BitArray *seed, int row)
{
    BitArray sxr = *seed, a0;
    sxr.b[KEYBYTES - 1] ^= (uint8_t)(row & 0xFF);
    ba_rol_k(&a0, &sxr, KEYBITS / 8);
    nl_fscx_revolve_v1_ba(out, &a0, seed, I_VALUE);
}

/* n_rows-bit syndrome s = H*e^T mod 2 packed into syndr[SDF_SYNBYTES]. */
static void stern_syndrome(uint8_t *syndr, const BitArray *seed,
                            const BitArray *e)
{
    int i;
    memset(syndr, 0, SDF_SYNBYTES);
    for (i = 0; i < SDF_N_ROWS; i++) {
        BitArray row;
        int pc = 0, k;
        stern_matrix_row(&row, seed, i);
        for (k = 0; k < KEYBYTES; k++)
            pc ^= __builtin_popcount(row.b[k] & e->b[k]);
        if (pc & 1)
            syndr[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* Pack syndrome into lower half of a BitArray (upper bytes = 0). */
static void syndr_to_ba(BitArray *out, const uint8_t *syndr)
{
    memset(out->b, 0, KEYBYTES);
    memcpy(out->b + KEYBYTES / 2, syndr, SDF_SYNBYTES);
}

/* Fisher-Yates shuffle [0..N-1] driven by NL-FSCX v1 PRNG. */
static void stern_gen_perm(uint8_t *perm, const BitArray *pi_seed, int N)
{
    BitArray key, st;
    int i;
    for (i = 0; i < N; i++) perm[i] = (uint8_t)i;
    ba_rol_k(&key, pi_seed, KEYBITS / 8);
    st = *pi_seed;
    for (i = N - 1; i > 0; i--) {
        uint32_t v;
        int j;
        nl_fscx_v1_ba(&st, &st, &key);
        v = ((uint32_t)st.b[KEYBYTES - 2] << 8) | st.b[KEYBYTES - 1];
        j = (int)(v % (unsigned)(i + 1));
        { uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp; }
    }
}

/* Apply permutation: out[perm[i]] = v[i] for N bits. */
static void stern_apply_perm(BitArray *out, const uint8_t *perm,
                              const BitArray *v, int N)
{
    int i;
    memset(out->b, 0, KEYBYTES);
    for (i = 0; i < N; i++) {
        int byt = KEYBYTES - 1 - i / 8;
        int bit = i % 8;
        if (v->b[byt] & (uint8_t)(1u << bit)) {
            int ob  = KEYBYTES - 1 - perm[i] / 8;
            int obb = perm[i] % 8;
            out->b[ob] |= (uint8_t)(1u << obb);
        }
    }
}

/* Generate weight-SDF_T error vector via partial Fisher-Yates + /dev/urandom. */
static void stern_rand_error(BitArray *e, FILE *urnd)
{
    uint8_t idx[KEYBITS];
    int i;
    for (i = 0; i < KEYBITS; i++) idx[i] = (uint8_t)i;
    memset(e->b, 0, KEYBYTES);
    for (i = KEYBITS - 1; i >= KEYBITS - SDF_T; i--) {
        unsigned int range = (unsigned int)(i + 1);
        unsigned int thresh = 256 - (256 % range);
        uint8_t rnd;
        int j;
        do {
            if (fread(&rnd, 1, 1, urnd) != 1) {
                fputs("urandom error\n", stderr); exit(1);
            }
        } while ((unsigned int)rnd >= thresh);
        j = (int)(rnd % range);
        { uint8_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; }
        e->b[KEYBYTES - 1 - idx[i] / 8] |= (uint8_t)(1u << (idx[i] % 8));
    }
}

/* Key generation: random seed, weight-t error e, syndrome = H*e^T. */
static void stern_f_keygen(BitArray *seed, BitArray *e, uint8_t *syndr,
                            FILE *urnd)
{
    ba_rand(seed, urnd);
    stern_rand_error(e, urnd);
    stern_syndrome(syndr, seed, e);
}

/* Derive Fiat-Shamir challenges from message and all round commits. */
static void stern_fs_challenges(int *chals, int rounds,
                                 const BitArray *msg,
                                 const BitArray *c0,
                                 const BitArray *c1,
                                 const BitArray *c2)
{
    BitArray ch_st = {{0}};
    int i;

#define _SFS(item) do { \
    BitArray _hxv, _rotv; \
    ba_xor(&_hxv, &ch_st, &(item)); \
    ba_rol_k(&_rotv, &(item), KEYBITS / 8); \
    nl_fscx_revolve_v1_ba(&ch_st, &_hxv, &_rotv, I_VALUE); \
} while (0)

    _SFS(*msg);
    for (i = 0; i < rounds; i++) { _SFS(c0[i]); _SFS(c1[i]); _SFS(c2[i]); }
#undef _SFS

    for (i = 0; i < rounds; i++) {
        BitArray idx_ba = {{0}};
        uint32_t v;
        idx_ba.b[KEYBYTES - 1] = (uint8_t)(i & 0xFF);
        nl_fscx_v1_ba(&ch_st, &ch_st, &idx_ba);
        v = ((uint32_t)ch_st.b[KEYBYTES - 4] << 24)
          | ((uint32_t)ch_st.b[KEYBYTES - 3] << 16)
          | ((uint32_t)ch_st.b[KEYBYTES - 2] << 8)
          |  ch_st.b[KEYBYTES - 1];
        chals[i] = (int)(v % 3u);
    }
}

/* Signature structure for HPKS-Stern-F (SDF_ROUNDS rounds). */
typedef struct {
    BitArray c0[SDF_ROUNDS], c1[SDF_ROUNDS], c2[SDF_ROUNDS];
    int      b[SDF_ROUNDS];
    BitArray resp_a[SDF_ROUNDS]; /* sr (b=0) or pi_seed (b=1,2) */
    BitArray resp_b[SDF_ROUNDS]; /* sy (b=0) or r (b=1) or y (b=2) */
} SternSig;

/* Sign: generate Stern commitments and Fiat-Shamir responses. */
static void hpks_stern_f_sign(SternSig *sig, const BitArray *msg,
                               const BitArray *e, const BitArray *seed,
                               FILE *urnd)
{
    BitArray r[SDF_ROUNDS], y[SDF_ROUNDS], pi[SDF_ROUNDS];
    BitArray sr[SDF_ROUNDS], sy[SDF_ROUNDS];
    uint8_t Hr[SDF_ROUNDS][SDF_SYNBYTES];
    uint8_t perm[KEYBITS];
    int i;

    for (i = 0; i < SDF_ROUNDS; i++) {
        BitArray items[2];
        stern_rand_error(&r[i], urnd);
        ba_xor(&y[i], e, &r[i]);
        ba_rand(&pi[i], urnd);
        stern_syndrome(Hr[i], seed, &r[i]);
        stern_gen_perm(perm, &pi[i], KEYBITS);
        stern_apply_perm(&sr[i], perm, &r[i], KEYBITS);
        stern_apply_perm(&sy[i], perm, &y[i], KEYBITS);
        items[0] = pi[i]; syndr_to_ba(&items[1], Hr[i]);
        stern_hash(&sig->c0[i], items, 2);
        stern_hash(&sig->c1[i], &sr[i], 1);
        stern_hash(&sig->c2[i], &sy[i], 1);
    }

    stern_fs_challenges(sig->b, SDF_ROUNDS, msg,
                        sig->c0, sig->c1, sig->c2);

    for (i = 0; i < SDF_ROUNDS; i++) {
        int bv = sig->b[i];
        if      (bv == 0) { sig->resp_a[i] = sr[i]; sig->resp_b[i] = sy[i]; }
        else if (bv == 1) { sig->resp_a[i] = pi[i]; sig->resp_b[i] = r[i];  }
        else              { sig->resp_a[i] = pi[i]; sig->resp_b[i] = y[i];  }
    }
}

/* Verify: re-derive Fiat-Shamir challenges and check all Stern responses. */
static int hpks_stern_f_verify(const SternSig *sig, const BitArray *msg,
                                const BitArray *seed, const uint8_t *syndr)
{
    int chals[SDF_ROUNDS];
    uint8_t perm[KEYBITS];
    int i;

    stern_fs_challenges(chals, SDF_ROUNDS, msg,
                        sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;

    for (i = 0; i < SDF_ROUNDS; i++) {
        int bv = sig->b[i];
        BitArray tmp;
        if (bv == 0) {
            stern_hash(&tmp, &sig->resp_a[i], 1);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
            stern_hash(&tmp, &sig->resp_b[i], 1);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
            if (ba_popcount(&sig->resp_a[i]) != SDF_T) return 0;
        } else if (bv == 1) {
            uint8_t Hr[SDF_SYNBYTES];
            BitArray items[2], sr2;
            if (ba_popcount(&sig->resp_b[i]) != SDF_T) return 0;
            stern_syndrome(Hr, seed, &sig->resp_b[i]);
            items[0] = sig->resp_a[i]; syndr_to_ba(&items[1], Hr);
            stern_hash(&tmp, items, 2);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm(&sr2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash(&tmp, &sr2, 1);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
        } else {
            uint8_t Hy[SDF_SYNBYTES], Hys[SDF_SYNBYTES];
            BitArray items[2], sy2;
            int k;
            stern_syndrome(Hy, seed, &sig->resp_b[i]);
            for (k = 0; k < SDF_SYNBYTES; k++) Hys[k] = Hy[k] ^ syndr[k];
            items[0] = sig->resp_a[i]; syndr_to_ba(&items[1], Hys);
            stern_hash(&tmp, items, 2);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm(&sy2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash(&tmp, &sy2, 1);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
        }
    }
    return 1;
}

/* Encapsulate: K = hash(seed, e'), ct = H*e'^T; e_out = e' (demo). */
static void hpke_stern_f_encap(BitArray *K_out, uint8_t *ct, BitArray *e_out,
                                const BitArray *seed, FILE *urnd)
{
    BitArray items[2];
    stern_rand_error(e_out, urnd);
    stern_syndrome(ct, seed, e_out);
    items[0] = *seed;
    items[1] = *e_out;
    stern_hash(K_out, items, 2);
}

/* Decapsulate using known e' (demo only; production needs QC-MDPC decoder). */
static void hpke_stern_f_decap_known(BitArray *K_out,
                                      const BitArray *e_p,
                                      const BitArray *seed)
{
    BitArray items[2];
    items[0] = *seed;
    items[1] = *e_p;
    stern_hash(K_out, items, 2);
}

#endif /* HERRADURA_H */
