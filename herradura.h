/*  herradura.h — Herradura Cryptographic Suite, header-only shared library v1.9.16
    v1.9.16: HPKS-Stern-Ring — OR-composed Stern ring signature (TODO #78.I).
    v1.8.8: ATOMIC_VAR_INIT removed — direct = 0 init for C23/GCC 13+ compatibility.
    v1.8.0: KDF domain constant — ba_rnl_kdf_seed: ROL(k,n/8) XOR _RNL_KDF_DC (TODO #38).
    v1.6.1: stern_hash DS parameter — closes QRO gap for Theorem 17 (TODO #36).
    v1.6.0: stern_hash HFSCX-256 finalizer — eliminates range compression (TODO #43).
    v1.5.41: rnl_lift centered rounding (TODO #37).
    v1.5.40: stern_apply_perm made branchless (mask = -(v_bit)) — TODO #41.
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
#ifdef _POSIX_THREADS
#  include <pthread.h>
#else
#  include <stdatomic.h>
#endif

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
/* SA-08: constant-time equality — XOR-accumulate all bytes before comparing. */
static int ba_equal(const BitArray *a, const BitArray *b)
{
    uint8_t diff = 0;
    int i;
    for (i = 0; i < KEYBYTES; i++)
        diff |= a->b[i] ^ b->b[i];
    return diff == 0;
}

/* Constant-time equality for 32-byte buffers. */
/* SA-09: XOR-accumulate all bytes before comparing — no early exit. */
static int ct_eq32(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    int i;
    for (i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Constant-time equality for KEYBYTES-byte buffers. */
/* SA-10: XOR-accumulate all bytes before comparing — no early exit. */
static int ct_eq_keybytes(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    int i;
    for (i = 0; i < KEYBYTES; i++) diff |= a[i] ^ b[i];
    return diff == 0;
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
/* SA-02/03: constant-time GF(2^KEYBITS) multiply.
   All branches replaced with bitmask selects so execution time is
   independent of the value of either operand (private key). */
static void gf_mul_ba(BitArray *dst, const BitArray *a, const BitArray *b)
{
    BitArray r, aa, bb;
    uint8_t bit_mask, carry_mask;
    int i, k;
    memset(r.b, 0, KEYBYTES);
    aa = *a;
    bb = *b;
    for (i = 0; i < KEYBITS; i++) {
        /* CT: XOR aa into r iff LSB of bb is set */
        bit_mask = (uint8_t)(0u - (bb.b[KEYBYTES - 1] & 1u));
        for (k = 0; k < KEYBYTES; k++)
            r.b[k] ^= aa.b[k] & bit_mask;
        /* CT: reduce aa by GF_POLY iff its MSB is set */
        carry_mask = (uint8_t)(0u - (aa.b[0] >> 7));
        ba_shl1(&aa);
        for (k = 0; k < KEYBYTES; k++)
            aa.b[k] ^= GF_POLY.b[k] & carry_mask;
        ba_shr1(&bb);
    }
    *dst = r;
}

/* SA-02: constant-time GF(2^KEYBITS) exponentiation.
   Iterates exactly KEYBITS times (no early exit on leading zeros) and
   uses CT select instead of a conditional call, so loop count and
   branch pattern are independent of the exponent (private key). */
static void gf_pow_ba(BitArray *dst, const BitArray *base, const BitArray *exp)
{
    BitArray r, b, e, tmp;
    uint8_t bit, sel;
    int i, k;
    memset(r.b, 0, KEYBYTES);
    r.b[KEYBYTES - 1] = 1;   /* multiplicative identity */
    b = *base;
    e = *exp;
    for (i = 0; i < KEYBITS; i++) {
        bit = e.b[KEYBYTES - 1] & 1u;
        gf_mul_ba(&tmp, &r, &b);        /* always compute r*b */
        sel = (uint8_t)(0u - bit);      /* 0xFF if bit set, 0x00 if not */
        for (k = 0; k < KEYBYTES; k++) /* CT select: r = bit ? tmp : r */
            r.b[k] = (r.b[k] & ~sel) | (tmp.b[k] & sel);
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

    /* SA-04: removed `if (!ai) continue` — unconditional outer loop so
       execution time does not leak zero bytes in the private key scalar. */
    memset(full, 0, sizeof(full));
    for (i = 0; i < KEYBYTES; i++) {
        uint8_t ai = a->b[KEYBYTES - 1 - i];
        carry = 0;
        for (j = 0; j < KEYBYTES; j++) {
            uint16_t prod = (uint16_t)ai * b->b[KEYBYTES - 1 - j]
                            + full[i + j] + carry;
            full[i + j] = (uint8_t)prod;
            carry = prod >> 8;
        }
        {
            int k;
            /* SA-04: unconditional carry propagation — no early exit on carry==0 */
            for (k = i + KEYBYTES; k < 2 * KEYBYTES; k++) {
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
        /* SA-04: unconditional carry propagation */
        for (i = 0; i < KEYBYTES; i++) {
            uint16_t s = (uint16_t)lo[i] + carry;
            lo[i] = (uint8_t)s;
            carry = s >> 8;
        }
        if (carry) { memset(lo, 0, KEYBYTES); lo[0] = 1; }
    } else {
        /* SA-04: no early-exit break in all_ff scan */
        all_ff = 1;
        for (i = 0; i < KEYBYTES; i++) all_ff &= (lo[i] == 0xFF);
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
        /* SA-04: CT subtract-1 — propagate borrow unconditionally */
        uint16_t sub1 = 1;
        for (i = KEYBYTES - 1; i >= 0; i--) {
            uint16_t d = (uint16_t)dst->b[i] - sub1;
            dst->b[i] = (uint8_t)d;
            sub1 = (d >> 8) & 1u;
        }
    }
    /* SA-04: no early-exit break in all_ff scan */
    all_ff = 1;
    for (i = 0; i < KEYBYTES; i++) all_ff &= (dst->b[i] == 0xFF);
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
 * HFSCX-256-DM: Merkle-Damgård hash on NL-FSCX v1, Davies-Meyer compression (v1.9.0)
 * ───────────────────────────────────────────────────────────────────────────── */

/* IV: "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0" (32 bytes) */
static const uint8_t _HFSCX256_IV[32] = {
    'H','F','S','C','X','-','2','5','6','/','H','E','R','R','A','D',
    'U','R','A','-','S','U','I','T','E',0,0,0,0,0,0,0
};

/* NUMS constant for KDF domain separation (SHA-256 initial hash values H0..H7,
 * big-endian 32-bit words concatenated).  XOR'd into seed after ROL(K, n/8)
 * to prevent KDF degeneracy when K is rotation-periodic (TODO #38, v1.8.0). */
static const uint8_t _RNL_KDF_DC[KEYBYTES] = {
    0x6A,0x09,0xE6,0x67, 0xBB,0x67,0xAE,0x85,
    0x3C,0x6E,0xF3,0x72, 0xA5,0x4F,0xF5,0x3A,
    0x51,0x0E,0x52,0x7F, 0x9B,0x05,0x68,0x8C,
    0x1F,0x83,0xD9,0xAB, 0x5B,0xE0,0xCD,0x19
};

#define _RNL_KDF_DC_32  0x6A09E667U
#define _RNL_KDF_DC_64  0x6A09E667BB67AE85ULL

/* ba_rnl_kdf_seed: compute ROL(k, n/8) XOR _RNL_KDF_DC into dst. */
static void ba_rnl_kdf_seed(BitArray *dst, const BitArray *k)
{
    int i;
    ba_rol_k(dst, k, KEYBYTES);   /* ROL left by n/8 bits (KEYBYTES byte positions) */
    for (i = 0; i < KEYBYTES; i++)
        dst->b[i] ^= _RNL_KDF_DC[i];
}

/* HFSCX-256-DM: Merkle-Damgård hash built on NL-FSCX v1 with Davies-Meyer feed-forward.
 * Compression: C_DM(s,m) = F_1^{64}(s,m) ⊕ s.
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
    if (!padded) { fprintf(stderr, "hfscx_256: out of memory\n"); exit(1); }
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

    /* Chain each 32-byte block: C_DM(s,m) = F_1^{64}(s,m) ⊕ s (Davies-Meyer) */
    for (off = 0; off < padded_len; off += 32) {
        BitArray prev = state;
        memcpy(block.b, padded + off, 32);
        nl_fscx_revolve_v1_ba(&state, &state, &block, 64);
        ba_xor(&state, &state, &prev);
    }

    memcpy(out, state.b, 32);
    free(padded);
}

/* HFSCX-256-DS: domain-separated variant — prepends a 1-byte tag before hashing.
 * ds=0x01 for generic digest, 0x02 for sign pre-hash, 0x03 for AEAD-MAC.
 * Wire-format option HFSCX-256-DS (§11.9.7 future hardening, TODO #93). */
static void hfscx_256_ds(uint8_t ds, const uint8_t *data, size_t len,
                          const uint8_t *iv, uint8_t out[32])
{
    uint8_t *buf = (uint8_t *)malloc(1 + len);
    if (!buf) { fprintf(stderr, "hfscx_256_ds: out of memory\n"); exit(1); }
    buf[0] = ds;
    if (len) memcpy(buf + 1, data, len);
    hfscx_256(buf, 1 + len, iv, out);
    free(buf);
}

/* HMAC-HFSCX-256-DM: HMAC construction over HFSCX-256-DM (§11.9.6).
 * Recommended for cross-protocol key reuse.
 * HMAC(K, D) = HFSCX-256((K^opad) || HFSCX-256((K^ipad) || D))
 * ipad = 0x36 repeated 32 bytes, opad = 0x5C repeated 32 bytes. */
static void hmac_hfscx_256(const uint8_t key[32], const uint8_t *data, size_t len,
                             uint8_t out[32])
{
    uint8_t ipad_key[32], opad_key[32], inner[32], obuf[64];
    uint8_t *ibuf;
    int i;
    for (i = 0; i < 32; i++) {
        ipad_key[i] = key[i] ^ 0x36;
        opad_key[i] = key[i] ^ 0x5C;
    }
    ibuf = (uint8_t *)malloc(32 + len);
    if (!ibuf) { fprintf(stderr, "hmac_hfscx_256: out of memory\n"); exit(1); }
    memcpy(ibuf, ipad_key, 32);
    if (len) memcpy(ibuf + 32, data, len);
    hfscx_256(ibuf, 32 + len, NULL, inner);
    free(ibuf);
    memcpy(obuf, opad_key, 32);
    memcpy(obuf + 32, inner, 32);
    hfscx_256(obuf, 64, NULL, out);
}

/* HSKE-NL-A1 CTR-mode AEAD helpers for encfile/decfile.
 * Caller computes: base = K XOR nonce; seed = ba_rnl_kdf_seed(base).
 * Block counter i is XOR'd into the four least-significant bytes of base. */
static void hske_nla1_ks_block(const BitArray *seed, const BitArray *base,
                                uint32_t i, BitArray *ks_out)
{
    BitArray base_i = *base;
    base_i.b[KEYBYTES-4] ^= (uint8_t)((i >> 24) & 0xFF);
    base_i.b[KEYBYTES-3] ^= (uint8_t)((i >> 16) & 0xFF);
    base_i.b[KEYBYTES-2] ^= (uint8_t)((i >>  8) & 0xFF);
    base_i.b[KEYBYTES-1] ^= (uint8_t)( i        & 0xFF);
    nl_fscx_revolve_v1_ba(ks_out, seed, &base_i, I_VALUE);
}

static void hske_nla1_mac_key(const BitArray *seed, const BitArray *base,
                               BitArray *mac_key_out)
{
    BitArray seed2;
    ba_rol_k(&seed2, seed, KEYBITS / 4);
    nl_fscx_revolve_v1_ba(mac_key_out, &seed2, base, I_VALUE);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HSKE-NL-AEAD: authenticated encryption with associated data (TODO #95)
 *
 * Encrypt-then-MAC over the HSKE-NL-A1 CTR keystream:
 *   base = K XOR nonce; seed = ba_rnl_kdf_seed(base);
 *   ct   = pt XOR ks   (hske_nla1_ks_block, truncated to pt_len);
 *   tag  = HFSCX-256-MAC(mac_key XOR IV,
 *              DS || nonce || ad_len_be8 || ad || ct_len_be8 || ct)
 * Key-committing: the tag binds mac_key (hence K and nonce) through the keyed
 * HFSCX-256-DM.  The DS prefix domain-separates the tag from the .hkx file MAC,
 * which shares the mac_key schedule.  Decryption is verify-then-decrypt with a
 * constant-time tag comparison.  Never reuse a (key, nonce) pair.
 * ───────────────────────────────────────────────────────────────────────────── */

#define _AEAD_DS     "HSKE-NL-AEAD-v1"
#define _AEAD_DS_LEN 15

static void _hske_nl_aead_be64(uint8_t *dst, uint64_t v)
{
    int j;
    for (j = 0; j < 8; j++) dst[j] = (uint8_t)((v >> (56 - 8 * j)) & 0xFF);
}

static void _hske_nl_aead_tag(const BitArray *mac_key, const BitArray *nonce,
                              const uint8_t *ad, size_t ad_len,
                              const uint8_t *ct, size_t ct_len,
                              uint8_t tag_out[32])
{
    uint8_t mac_iv[32];
    size_t len = _AEAD_DS_LEN + KEYBYTES + 8 + ad_len + 8 + ct_len, off;
    uint8_t *buf = (uint8_t *)malloc(len);
    int j;
    if (!buf) { fprintf(stderr, "hske_nl_aead: out of memory\n"); exit(1); }
    for (j = 0; j < 32; j++) mac_iv[j] = mac_key->b[j] ^ _HFSCX256_IV[j];
    memcpy(buf, _AEAD_DS, _AEAD_DS_LEN);
    off = _AEAD_DS_LEN;
    memcpy(buf + off, nonce->b, KEYBYTES);          off += KEYBYTES;
    _hske_nl_aead_be64(buf + off, (uint64_t)ad_len); off += 8;
    if (ad_len) memcpy(buf + off, ad, ad_len);
    off += ad_len;
    _hske_nl_aead_be64(buf + off, (uint64_t)ct_len); off += 8;
    if (ct_len) memcpy(buf + off, ct, ct_len);
    hfscx_256(buf, len, mac_iv, tag_out);
    free(buf);
}

static void _hske_nl_aead_xor_ks(const BitArray *seed, const BitArray *base,
                                 const uint8_t *in, size_t len, uint8_t *out)
{
    BitArray ks;
    size_t off, blk, j;
    uint32_t i = 0;
    for (off = 0; off < len; off += KEYBYTES, i++) {
        blk = (len - off < KEYBYTES) ? len - off : KEYBYTES;
        hske_nla1_ks_block(seed, base, i, &ks);
        for (j = 0; j < blk; j++) out[off + j] = in[off + j] ^ ks.b[j];
    }
}

/* AEAD-encrypt pt_len bytes into ct_out (same length) and tag_out (32 bytes).
 * Caller supplies a fresh random 256-bit nonce (e.g. via ba_rand). */
static void hske_nl_aead_encrypt(const BitArray *key, const BitArray *nonce,
                                 const uint8_t *ad, size_t ad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct_out, uint8_t tag_out[32])
{
    BitArray base, seed, mac_key;
    ba_xor(&base, key, nonce);
    ba_rnl_kdf_seed(&seed, &base);
    _hske_nl_aead_xor_ks(&seed, &base, pt, pt_len, ct_out);
    hske_nla1_mac_key(&seed, &base, &mac_key);
    _hske_nl_aead_tag(&mac_key, nonce, ad, ad_len, ct_out, pt_len, tag_out);
}

/* Verify-then-decrypt.  Returns 1 and writes ct_len bytes to pt_out on
 * success; returns 0 (pt_out untouched) if the tag does not authenticate. */
static int hske_nl_aead_decrypt(const BitArray *key, const BitArray *nonce,
                                const uint8_t *ad, size_t ad_len,
                                const uint8_t *ct, size_t ct_len,
                                const uint8_t tag[32], uint8_t *pt_out)
{
    BitArray base, seed, mac_key;
    uint8_t expected[32];
    ba_xor(&base, key, nonce);
    ba_rnl_kdf_seed(&seed, &base);
    hske_nla1_mac_key(&seed, &base, &mac_key);
    _hske_nl_aead_tag(&mac_key, nonce, ad, ad_len, ct, ct_len, expected);
    if (!ct_eq32(tag, expected)) return 0;
    _hske_nl_aead_xor_ks(&seed, &base, ct, ct_len, pt_out);
    return 1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HDRBG: forward-secure deterministic random bit generator (TODO #96)
 *
 * Fast-key-erasure pattern (Bernstein 2017) over the NL-FSCX v1 OWF:
 *   state_0     = HFSCX-256("DRBG-INIT" || len(entropy)_be8 || entropy || pers)
 *   output_i    = HFSCX-256(state_i || i_be8 || "DRBG-OUT")
 *   state_{i+1} = nl_fscx_revolve_v1(state_i, DRBG_DOMAIN, n/4)
 *   reseed      : state = HFSCX-256("DRBG-RESEED" || state || len_be8 || entropy)
 *
 * Backtracking resistance rests on the same OWF conjecture as the #78.C
 * ratchet (Theorem 16, SecurityProofs-2 §11.8.3); the superseded state is
 * erased with explicit_bzero after every block.  Collision risk of the
 * non-bijective state walk: SecurityProofsCode/nl_fscx_v1_ratchet_collision.py.
 *
 * NON-GOALS: not a NIST SP 800-90A validated DRBG — no health tests, no
 * prediction resistance, no entropy-source assessment.  It deterministically
 * expands seed material that is already full-entropy.
 * ───────────────────────────────────────────────────────────────────────────── */

static const uint8_t _DRBG_DOMAIN_BYTES[KEYBYTES] = {
    'N','L','-','F','S','C','X','-','D','R','B','G','-','V','1',0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
};

#define DRBG_MAX_BLOCKS (1ULL << 20)  /* output blocks per (re)seed (32 MiB) */

typedef struct {
    BitArray state;
    uint64_t blocks;
} HDrbg;

static void _drbg_be64(uint8_t *dst, uint64_t v)
{
    int j;
    for (j = 0; j < 8; j++) dst[j] = (uint8_t)((v >> (56 - 8 * j)) & 0xFF);
}

/* Instantiate from full-entropy seed material (>= 32 bytes recommended). */
static void drbg_seed(HDrbg *d, const uint8_t *entropy, size_t entropy_len,
                      const uint8_t *pers, size_t pers_len)
{
    size_t len = 9 + 8 + entropy_len + pers_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) { fprintf(stderr, "drbg_seed: out of memory\n"); exit(1); }
    memcpy(buf, "DRBG-INIT", 9);
    _drbg_be64(buf + 9, (uint64_t)entropy_len);
    if (entropy_len) memcpy(buf + 17, entropy, entropy_len);
    if (pers_len) memcpy(buf + 17 + entropy_len, pers, pers_len);
    hfscx_256(buf, len, NULL, d->state.b);
    explicit_bzero(buf, len);
    free(buf);
    d->blocks = 0;
}

/* Generate n_bytes of output, ratcheting (and erasing) the state once per
 * 32-byte block.  Returns 1, or 0 if DRBG_MAX_BLOCKS would be exceeded
 * (reseed required; no output is produced). */
static int drbg_generate(HDrbg *d, uint8_t *out, size_t n_bytes)
{
    BitArray dom, next;
    uint8_t buf[KEYBYTES + 8 + 8], block[32];
    size_t off, blk;
    uint64_t n_blocks = (n_bytes + KEYBYTES - 1) / KEYBYTES;

    if (d->blocks + n_blocks > DRBG_MAX_BLOCKS) return 0;
    memcpy(dom.b, _DRBG_DOMAIN_BYTES, KEYBYTES);
    for (off = 0; off < n_bytes; off += KEYBYTES) {
        memcpy(buf, d->state.b, KEYBYTES);
        _drbg_be64(buf + KEYBYTES, d->blocks);
        memcpy(buf + KEYBYTES + 8, "DRBG-OUT", 8);
        hfscx_256(buf, KEYBYTES + 8 + 8, NULL, block);
        blk = (n_bytes - off < KEYBYTES) ? n_bytes - off : KEYBYTES;
        memcpy(out + off, block, blk);
        nl_fscx_revolve_v1_ba(&next, &d->state, &dom, I_VALUE);
        explicit_bzero(d->state.b, KEYBYTES);   /* fast key erasure */
        d->state = next;
        d->blocks++;
    }
    explicit_bzero(buf, sizeof buf);
    explicit_bzero(block, sizeof block);
    return 1;
}

/* Mix fresh entropy into the state and reset the output-block counter. */
static void drbg_reseed(HDrbg *d, const uint8_t *entropy, size_t entropy_len)
{
    size_t len = 11 + KEYBYTES + 8 + entropy_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) { fprintf(stderr, "drbg_reseed: out of memory\n"); exit(1); }
    memcpy(buf, "DRBG-RESEED", 11);
    memcpy(buf + 11, d->state.b, KEYBYTES);
    _drbg_be64(buf + 11 + KEYBYTES, (uint64_t)entropy_len);
    if (entropy_len) memcpy(buf + 11 + KEYBYTES + 8, entropy, entropy_len);
    hfscx_256(buf, len, NULL, d->state.b);
    explicit_bzero(buf, len);
    free(buf);
    d->blocks = 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HKEX-RNL: Ring-LWR key exchange helpers (n=256, negacyclic Z_q[x]/(x^n+1))
 * ───────────────────────────────────────────────────────────────────────────── */

#define RNL_N  256
#define RNL_Q  65537
#define RNL_P  4096
#define RNL_PP 4
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
} rnl_tw;

static void rnl_twiddle_do_init(void)
{
    uint32_t psi, psi_inv, pw, pw_inv, w;
    int i, s, length;
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
}

#ifdef _POSIX_THREADS
static pthread_once_t rnl_tw_once = PTHREAD_ONCE_INIT;
static void rnl_twiddle_init(void) { pthread_once(&rnl_tw_once, rnl_twiddle_do_init); }
#else
/* 0 = uninitialized, 1 = in progress, 2 = done */
static _Atomic int rnl_tw_state = 0;
static void rnl_twiddle_init(void)
{
    int expected = 0;
    if (atomic_load_explicit(&rnl_tw_state, memory_order_acquire) == 2) return;
    if (atomic_compare_exchange_strong_explicit(
            &rnl_tw_state, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        rnl_twiddle_do_init();
        atomic_store_explicit(&rnl_tw_state, 2, memory_order_release);
    } else {
        while (atomic_load_explicit(&rnl_tw_state, memory_order_acquire) != 2) {}
    }
}
#endif

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
        out[i] = (int32_t)(((int64_t)in[i] * to_q + from_p / 2) / from_p % to_q);
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

/* Validate that m_blind plausibly came from a uniform-random draw over Z_q^n.
 * Returns 1 if valid, 0 if the polynomial looks attacker-substituted.
 * Two checks (either failing → reject):
 *   (1) non-zero coefficient count >= n/4  — catches sparse/zero-polynomial attacks
 *   (2) coefficient range (max-min) >= q/4 — catches clustered/small-value attacks
 * A truly random poly over Z_65537 has ~n nonzero coefficients and range ~q. */
static int rnl_validate_m_blind(const rnl_poly_t poly, int n)
{
    int i, nz = 0;
    int32_t mn = poly[0], mx = poly[0];
    for (i = 0; i < n; i++) {
        if (poly[i] != 0) nz++;
        if (poly[i] < mn) mn = poly[i];
        if (poly[i] > mx) mx = poly[i];
    }
    if (nz < n / 4) return 0;
    if (mx - mn < (int32_t)(RNL_Q / 4)) return 0;
    return 1;
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

/* 2-bit Peikert cross-rounding hint for first RNL_N/2 coefficients, packed 2 bits/coeff.
   h[i] = floor((8*c + q/4) / q) % 4 */
static void rnl_hint(uint8_t hint[RNL_N / 8], const rnl_poly_t K_poly)
{
    int i;
    memset(hint, 0, RNL_N / 8);
    for (i = 0; i < RNL_N / 2; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)8 * c + RNL_Q / 4) / RNL_Q) % 4;
        hint[i / 4] |= (uint8_t)(r << ((i % 4) * 2));
    }
}

/* Extract KEYBITS key bits: 2 bits per coefficient from KEYBITS/2 coefficients.
   b[i] = floor((4*c + (2*h+1)*(q/4)) / q) % 4 */
static void rnl_reconcile_bits(BitArray *out, const rnl_poly_t K_poly,
                                const uint8_t hint[RNL_N / 8])
{
    int i;
    const uint32_t qq = RNL_Q / 4;
    memset(out->b, 0, sizeof(out->b));
    for (i = 0; i < KEYBITS / 2; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (hint[i / 4] >> ((i % 4) * 2)) & 3u;
        uint32_t b = (uint32_t)(((uint64_t)4 * c + (uint64_t)(2*h+1) * qq) / RNL_Q) % RNL_PP;
        out->b[i / 4] |= (uint8_t)(b << ((i % 4) * 2));
    }
}

/* agree: compute raw key with Peikert reconciliation.
   Reconciler path (hint_in=NULL, hint_out≠NULL): generate hint, use own hint.
   Receiver path  (hint_in≠NULL):                 use provided hint.
   SECURITY: hint_out (m_blind) is transmitted unauthenticated.  An active
   adversary who tampers with hint_in can steer the reconciled key.  HKEX-RNL
   provides key agreement only; the caller is responsible for authenticating the
   transcript (e.g. via HPKS-NL or a MAC over b_pub||m_blind) before using the
   derived key.                                                                 */
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
 * Security: EUF-CMA <= q_H/T_SD + eps_PRF  (Theorem 17, SecurityProofs-2.md §11.8.4).
 * N=KEYBITS=256, n_rows=128, t=16, rounds=32  (production: >=219).
 * ───────────────────────────────────────────────────────────────────────────── */

#define SDF_N_ROWS          (KEYBITS / 2)  /* parity-check rows: 128             */
#define SDF_T               (KEYBITS / 16) /* error weight: 16                   */
#define SDF_ROUNDS          32             /* ZKP rounds (demo; prod >= 219)     */
#define SDF_PRODUCTION_ROUNDS 219          /* rounds for 128-bit soundness       */
#define SDF_SYNBYTES        (SDF_N_ROWS / 8) /* syndrome bytes: 16               */

#if SDF_ROUNDS < SDF_PRODUCTION_ROUNDS
#pragma message("WARNING: SDF_ROUNDS < SDF_PRODUCTION_ROUNDS (219). " \
    "Stern signatures have sub-128-bit soundness. For production use, " \
    "redefine SDF_ROUNDS to SDF_PRODUCTION_ROUNDS before including this header.")
#endif

/* Chain-hash + HFSCX-256 finalizer: h <- NL-FSCX_v1^I(h XOR v, ROL(v,n/8)) for each
 * item, then h <- HFSCX-256(h) to eliminate range compression (TODO #43, v1.6.0).
 * ds: domain-separation tag (0=challenge, 1=c0, 2=c1, 3=c2, 4=KEM) (TODO #36, v1.6.1). */
static void stern_hash(BitArray *out, const BitArray *items, int n_items, unsigned ds)
{
    BitArray h = {{0}};
    h.b[KEYBYTES - 1] = (uint8_t)(ds & 0xFF); /* DS in LSB (big-endian) */
    int i;
    for (i = 0; i < n_items; i++) {
        BitArray hxv, rotv;
        ba_xor(&hxv, &h, &items[i]);
        ba_rol_k(&rotv, &items[i], KEYBITS / 8);
        nl_fscx_revolve_v1_ba(&h, &hxv, &rotv, I_VALUE);
    }
    {
        uint8_t digest[32];
        hfscx_256(h.b, KEYBYTES, NULL, digest);
        memcpy(h.b, digest, KEYBYTES);
    }
    *out = h;
}

/* H[row] = HFSCX-256(NL-FSCX_v1^I(ROL(seed XOR row, n/8), seed)) truncated to
 * n bits.  HFSCX-256-DM finalization removes the NL-FSCX range compression so H
 * is indistinguishable from a uniform binary matrix (TODO #88, v1.9.35). */
static void stern_matrix_row(BitArray *out, const BitArray *seed, int row)
{
    BitArray sxr = *seed, a0;
    uint8_t digest[32];
    sxr.b[KEYBYTES - 1] ^= (uint8_t)(row & 0xFF);
    ba_rol_k(&a0, &sxr, KEYBITS / 8);
    nl_fscx_revolve_v1_ba(out, &a0, seed, I_VALUE);
    hfscx_256(out->b, KEYBYTES, NULL, digest);
    memcpy(out->b, digest, KEYBYTES);
}

/* Build all SDF_N_ROWS rows of parity-check matrix H from seed.
   Hot paths (sign/verify) call this once and reuse H via stern_syndrome_H. */
static void stern_build_H(BitArray *H, const BitArray *seed)
{
    int i;
    for (i = 0; i < SDF_N_ROWS; i++)
        stern_matrix_row(&H[i], seed, i);
}

/* Syndrome from prebuilt H: s = H*e^T mod 2, packed into syndr[SDF_SYNBYTES]. */
static void stern_syndrome_H(uint8_t *syndr, const BitArray *H,
                              const BitArray *e)
{
    int i;
    memset(syndr, 0, SDF_SYNBYTES);
    for (i = 0; i < SDF_N_ROWS; i++) {
        int pc = 0, k;
        for (k = 0; k < KEYBYTES; k++)
            pc ^= __builtin_popcount(H[i].b[k] & e->b[k]);
        if (pc & 1)
            syndr[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* n_rows-bit syndrome s = H*e^T mod 2 packed into syndr[SDF_SYNBYTES].
   One-off wrapper; hot paths should use stern_build_H + stern_syndrome_H. */
static void stern_syndrome(uint8_t *syndr, const BitArray *seed,
                            const BitArray *e)
{
    BitArray H[SDF_N_ROWS];
    stern_build_H(H, seed);
    stern_syndrome_H(syndr, H, e);
}

/* Pack syndrome into lower half of a BitArray (upper bytes = 0). */
static void syndr_to_ba(BitArray *out, const uint8_t *syndr)
{
    int k;
    memset(out->b, 0, KEYBYTES);
    /* Store syndr[k] (rows k*8..k*8+7) at byte KEYBYTES-1-k so that syndrome
     * bit i lands at integer bit i, matching Python/Go's big.Int convention. */
    for (k = 0; k < SDF_SYNBYTES; k++)
        out->b[KEYBYTES - 1 - k] = syndr[k];
}

/* Fisher-Yates shuffle [0..N-1] driven by NL-FSCX v1 PRNG.
   Counter-mode extraction: all KEYBYTES of each state block are consumed as
   sequential 32-bit draws before the state is advanced, so no entropy is wasted.
   Rejection sampling (threshold = 2^32 - 2^32%range, kept as uint64 to avoid
   truncating to 0 when range divides 2^32) eliminates modular bias. */
static void stern_gen_perm(uint8_t *perm, const BitArray *pi_seed, int N)
{
    BitArray key, st;
    int i, cursor;
    for (i = 0; i < N; i++) perm[i] = (uint8_t)i;
    ba_rol_k(&key, pi_seed, KEYBITS / 8);
    st = *pi_seed;
    cursor = KEYBYTES;                          /* force state advance on first draw */
    for (i = N - 1; i > 0; i--) {
        uint64_t range     = (uint64_t)(i + 1);
        uint64_t threshold = UINT64_C(0x100000000) -
                             (UINT64_C(0x100000000) % range);
        uint32_t v;
        int j;
        do {
            if (cursor + 4 > KEYBYTES) {
                nl_fscx_v1_ba(&st, &st, &key);
                cursor = 0;
            }
            v = ((uint32_t)st.b[cursor    ] << 24) |
                ((uint32_t)st.b[cursor + 1] << 16) |
                ((uint32_t)st.b[cursor + 2] <<  8) |
                 (uint32_t)st.b[cursor + 3];
            cursor += 4;
        } while ((uint64_t)v >= threshold);
        j = (int)(v % (uint32_t)range);
        { uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp; }
    }
}

/* Apply permutation: out[perm[i]] = v[i] for N bits.
   Branchless: mask = -(v_bit) is 0x00 or 0xFF; no branch on secret bits. */
static void stern_apply_perm(BitArray *out, const uint8_t *perm,
                              const BitArray *v, int N)
{
    int i;
    memset(out->b, 0, KEYBYTES);
    for (i = 0; i < N; i++) {
        int byt     = KEYBYTES - 1 - i / 8;
        int bit     = i % 8;
        uint8_t vb  = (v->b[byt] >> bit) & 1u;
        uint8_t mask = (uint8_t)(-(int8_t)vb);  /* 0x00 or 0xFF */
        int ob  = KEYBYTES - 1 - perm[i] / 8;
        int obb = perm[i] % 8;
        out->b[ob] |= mask & (uint8_t)(1u << obb);
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

    {
        uint8_t digest[32];
        hfscx_256(ch_st.b, KEYBYTES, NULL, digest);
        memcpy(ch_st.b, digest, KEYBYTES);
    }

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
    BitArray *r  = (BitArray *)malloc(SDF_ROUNDS * sizeof(BitArray));
    BitArray *y  = (BitArray *)malloc(SDF_ROUNDS * sizeof(BitArray));
    BitArray *pi = (BitArray *)malloc(SDF_ROUNDS * sizeof(BitArray));
    BitArray *sr = (BitArray *)malloc(SDF_ROUNDS * sizeof(BitArray));
    BitArray *sy = (BitArray *)malloc(SDF_ROUNDS * sizeof(BitArray));
    uint8_t  *Hr = (uint8_t  *)malloc(SDF_ROUNDS * SDF_SYNBYTES);
    BitArray H_mat[SDF_N_ROWS];
    uint8_t perm[KEYBITS];
    int i;

    if (!r || !y || !pi || !sr || !sy || !Hr) {
        fprintf(stderr, "hpks_stern_f_sign: out of memory\n"); exit(1);
    }

    stern_build_H(H_mat, seed);

    for (i = 0; i < SDF_ROUNDS; i++) {
        BitArray items[2];
        stern_rand_error(&r[i], urnd);
        ba_xor(&y[i], e, &r[i]);
        ba_rand(&pi[i], urnd);
        stern_syndrome_H(Hr + i * SDF_SYNBYTES, H_mat, &r[i]);
        stern_gen_perm(perm, &pi[i], KEYBITS);
        stern_apply_perm(&sr[i], perm, &r[i], KEYBITS);
        stern_apply_perm(&sy[i], perm, &y[i], KEYBITS);
        items[0] = pi[i]; syndr_to_ba(&items[1], Hr + i * SDF_SYNBYTES);
        stern_hash(&sig->c0[i], items, 2, 1);
        stern_hash(&sig->c1[i], &sr[i], 1, 2);
        stern_hash(&sig->c2[i], &sy[i], 1, 3);
    }

    stern_fs_challenges(sig->b, SDF_ROUNDS, msg,
                        sig->c0, sig->c1, sig->c2);

    for (i = 0; i < SDF_ROUNDS; i++) {
        int bv = sig->b[i];
        if      (bv == 0) { sig->resp_a[i] = sr[i]; sig->resp_b[i] = sy[i]; }
        else if (bv == 1) { sig->resp_a[i] = pi[i]; sig->resp_b[i] = r[i];  }
        else              { sig->resp_a[i] = pi[i]; sig->resp_b[i] = y[i];  }
    }

    free(r); free(y); free(pi); free(sr); free(sy); free(Hr);
}

/* Verify: re-derive Fiat-Shamir challenges and check all Stern responses. */
static int hpks_stern_f_verify(const SternSig *sig, const BitArray *msg,
                                const BitArray *seed, const uint8_t *syndr)
{
    int chals[SDF_ROUNDS];
    BitArray H_mat[SDF_N_ROWS];
    uint8_t perm[KEYBITS];
    int i;

    stern_build_H(H_mat, seed);

    stern_fs_challenges(chals, SDF_ROUNDS, msg,
                        sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;

    for (i = 0; i < SDF_ROUNDS; i++) {
        int bv = sig->b[i];
        BitArray tmp;
        if (bv == 0) {
            stern_hash(&tmp, &sig->resp_a[i], 1, 2);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
            stern_hash(&tmp, &sig->resp_b[i], 1, 3);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
            if (ba_popcount(&sig->resp_a[i]) != SDF_T) return 0;
        } else if (bv == 1) {
            uint8_t Hr[SDF_SYNBYTES];
            BitArray items[2], sr2;
            if (ba_popcount(&sig->resp_b[i]) != SDF_T) return 0;
            stern_syndrome_H(Hr, H_mat, &sig->resp_b[i]);
            items[0] = sig->resp_a[i]; syndr_to_ba(&items[1], Hr);
            stern_hash(&tmp, items, 2, 1);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm(&sr2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash(&tmp, &sr2, 1, 2);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
        } else {
            uint8_t Hy[SDF_SYNBYTES], Hys[SDF_SYNBYTES];
            BitArray items[2], sy2;
            int k;
            stern_syndrome_H(Hy, H_mat, &sig->resp_b[i]);
            for (k = 0; k < SDF_SYNBYTES; k++) Hys[k] = Hy[k] ^ syndr[k];
            items[0] = sig->resp_a[i]; syndr_to_ba(&items[1], Hys);
            stern_hash(&tmp, items, 2, 1);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm(&sy2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash(&tmp, &sy2, 1, 3);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
        }
    }
    return 1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.I — Code-Based Ring Signature via HPKS-Stern-F OR-composition (TODO #78.I)
 *
 * Prove knowledge of one HPKS-Stern-F secret key in a ring of k public keys
 * without revealing which one.  OR-composes k Stern identification instances
 * using HVZK simulation for non-signer members and Fiat-Shamir with challenge
 * splitting (sum_i b_ir ≡ joint_b_r (mod 3) per round r).
 *
 * Proof size: O(k × SDF_ROUNDS) rounds of (c0, c1, c2, b, respA, respB).
 * Security: EUF-CMA under SD(N,t) per ring member.
 *
 * stern_ring_alloc / stern_ring_free  — allocate / free a SternRingSig.
 * stern_ring_sign                     — sign as member j of the ring.
 * stern_ring_verify                   — verify without learning who signed.
 * ───────────────────────────────────────────────────────────────────────────── */

typedef struct {
    int       k;       /* ring size */
    int       rounds;  /* rounds per member */
    /* flat [k * rounds] arrays; index for member i round r: i * rounds + r */
    BitArray *c0, *c1, *c2;
    int      *b;
    BitArray *resp_a, *resp_b;
} SternRingSig;

static void stern_ring_alloc(SternRingSig *sig, int k, int rounds)
{
    int sz = k * rounds;
    sig->k      = k;
    sig->rounds = rounds;
    sig->c0     = (BitArray *)malloc(sz * sizeof(BitArray));
    sig->c1     = (BitArray *)malloc(sz * sizeof(BitArray));
    sig->c2     = (BitArray *)malloc(sz * sizeof(BitArray));
    sig->b      = (int *)     malloc(sz * sizeof(int));
    sig->resp_a = (BitArray *)malloc(sz * sizeof(BitArray));
    sig->resp_b = (BitArray *)malloc(sz * sizeof(BitArray));
    if (!sig->c0 || !sig->c1 || !sig->c2 || !sig->b ||
        !sig->resp_a || !sig->resp_b) {
        fprintf(stderr, "stern_ring_alloc: out of memory\n"); exit(1);
    }
}

static void stern_ring_free(SternRingSig *sig)
{
    free(sig->c0); free(sig->c1); free(sig->c2);
    free(sig->b);  free(sig->resp_a); free(sig->resp_b);
}

/* Derive k rounds of joint challenges from msg + all k*rounds*(c0,c1,c2). */
static void stern_ring_challenges(int *joint_out, int rounds, int k,
                                    const BitArray *msg,
                                    const BitArray *c0,
                                    const BitArray *c1,
                                    const BitArray *c2)
{
    BitArray ch_st, idx_ba;
    uint8_t digest[KEYBYTES];
    uint32_t v;
    int i, r;

    memset(ch_st.b, 0, KEYBYTES);
    /* sfs(msg) */
    {
        BitArray rotm;
        ba_rol_k(&rotm, msg, KEYBITS / 8);
        ba_xor(&ch_st, &ch_st, msg);
        nl_fscx_revolve_v1_ba(&ch_st, &ch_st, &rotm, I_VALUE);
    }
    /* for each member i, round r: sfs(c0), sfs(c1), sfs(c2) */
    for (i = 0; i < k; i++) {
        for (r = 0; r < rounds; r++) {
            int idx = i * rounds + r;
            const BitArray *cx[3] = { &c0[idx], &c1[idx], &c2[idx] };
            int ci;
            for (ci = 0; ci < 3; ci++) {
                BitArray rotc;
                ba_rol_k(&rotc, cx[ci], KEYBITS / 8);
                ba_xor(&ch_st, &ch_st, cx[ci]);
                nl_fscx_revolve_v1_ba(&ch_st, &ch_st, &rotc, I_VALUE);
            }
        }
    }
    hfscx_256(ch_st.b, KEYBYTES, NULL, digest);
    memcpy(ch_st.b, digest, KEYBYTES);
    /* derive one joint challenge per round */
    for (r = 0; r < rounds; r++) {
        memset(idx_ba.b, 0, KEYBYTES);
        idx_ba.b[KEYBYTES - 1] = (uint8_t)(r & 0xFF);
        nl_fscx_v1_ba(&ch_st, &ch_st, &idx_ba);
        v = ((uint32_t)ch_st.b[KEYBYTES - 4] << 24)
          | ((uint32_t)ch_st.b[KEYBYTES - 3] << 16)
          | ((uint32_t)ch_st.b[KEYBYTES - 2] << 8)
          |  ch_st.b[KEYBYTES - 1];
        joint_out[r] = (int)(v % 3u);
    }
}

/* HVZK simulator for one Stern round given pre-chosen challenge b.
 * Fills c0[idx], c1[idx], c2[idx], b[idx], resp_a[idx], resp_b[idx].
 * H_mat must be pre-built for the member's seed (call stern_build_H once). */
static void stern_ring_simulate(SternRingSig *sig, int idx, int b,
                                  const BitArray H_mat[SDF_N_ROWS],
                                  const uint8_t *syndr,
                                  FILE *urnd)
{
    uint8_t  perm[KEYBITS], Hr_sim[SDF_SYNBYTES];
    BitArray items[2], pi_sim, r_sim, y_sim, sr_sim, sy_sim;

    if (b == 0) {
        /* c1 = hash(sr_sim wt-t), c2 = hash(sy_sim random), c0 dummy */
        BitArray zero; memset(zero.b, 0, KEYBYTES);
        stern_rand_error(&sr_sim, urnd);
        ba_rand(&sy_sim, urnd);
        items[0] = zero; items[1] = zero;
        stern_hash(&sig->c0[idx], items, 2, 1);    /* unchecked */
        stern_hash(&sig->c1[idx], &sr_sim, 1, 2);
        stern_hash(&sig->c2[idx], &sy_sim, 1, 3);
        sig->b[idx]      = 0;
        sig->resp_a[idx] = sr_sim;
        sig->resp_b[idx] = sy_sim;
    } else if (b == 1) {
        /* c0 = hash(pi_sim, H*r_sim^T), c1 = hash(sigma(r_sim)), c2 dummy */
        ba_rand(&pi_sim, urnd);
        stern_rand_error(&r_sim, urnd);
        stern_gen_perm(perm, &pi_sim, KEYBITS);
        stern_syndrome_H(Hr_sim, H_mat, &r_sim);
        stern_apply_perm(&sr_sim, perm, &r_sim, KEYBITS);
        ba_rand(&sy_sim, urnd);
        items[0] = pi_sim; syndr_to_ba(&items[1], Hr_sim);
        stern_hash(&sig->c0[idx], items, 2, 1);
        stern_hash(&sig->c1[idx], &sr_sim, 1, 2);
        stern_hash(&sig->c2[idx], &sy_sim, 1, 3);  /* unchecked */
        sig->b[idx]      = 1;
        sig->resp_a[idx] = pi_sim;
        sig->resp_b[idx] = r_sim;
    } else {
        /* c0 = hash(pi_sim, H*y_sim^T XOR s), c2 = hash(sigma(y_sim)), c1 dummy */
        uint8_t Hys[SDF_SYNBYTES];
        int k2;
        ba_rand(&pi_sim, urnd);
        ba_rand(&y_sim,  urnd);
        stern_gen_perm(perm, &pi_sim, KEYBITS);
        stern_syndrome_H(Hr_sim, H_mat, &y_sim);
        for (k2 = 0; k2 < SDF_SYNBYTES; k2++) Hys[k2] = Hr_sim[k2] ^ syndr[k2];
        stern_apply_perm(&sy_sim, perm, &y_sim, KEYBITS);
        ba_rand(&sr_sim, urnd);
        items[0] = pi_sim; syndr_to_ba(&items[1], Hys);
        stern_hash(&sig->c0[idx], items, 2, 1);
        stern_hash(&sig->c1[idx], &sr_sim, 1, 2);  /* unchecked */
        stern_hash(&sig->c2[idx], &sy_sim, 1, 3);
        sig->b[idx]      = 2;
        sig->resp_a[idx] = pi_sim;
        sig->resp_b[idx] = y_sim;
    }
}

/* Sign as ring member j (0-indexed).
 * seeds[i] = i-th member's seed; syndromes_flat[i*SDF_SYNBYTES..] = syndrome. */
static void stern_ring_sign(SternRingSig *sig,
                              const BitArray *msg,
                              const BitArray *e,
                              int j,
                              const BitArray *seeds,
                              const uint8_t  *syndrs_flat,
                              FILE *urnd)
{
    int k      = sig->k;
    int rounds = sig->rounds;
    /* temporaries for real signer */
    BitArray *r_tmp  = (BitArray *)malloc(rounds * sizeof(BitArray));
    BitArray *y_tmp  = (BitArray *)malloc(rounds * sizeof(BitArray));
    BitArray *pi_tmp = (BitArray *)malloc(rounds * sizeof(BitArray));
    BitArray *sr_tmp = (BitArray *)malloc(rounds * sizeof(BitArray));
    BitArray *sy_tmp = (BitArray *)malloc(rounds * sizeof(BitArray));
    uint8_t  *Hr_tmp = (uint8_t  *)malloc(rounds * SDF_SYNBYTES);
    int i, r;

    if (!r_tmp || !y_tmp || !pi_tmp || !sr_tmp || !sy_tmp || !Hr_tmp) {
        fprintf(stderr, "stern_ring_sign: out of memory\n"); exit(1);
    }

    /* Step 1: simulate non-signer members (build H once per member) */
    for (i = 0; i < k; i++) {
        BitArray H_mat_i[SDF_N_ROWS];
        const uint8_t *syn_i = syndrs_flat + i * SDF_SYNBYTES;
        if (i == j) continue;
        stern_build_H(H_mat_i, &seeds[i]);
        for (r = 0; r < rounds; r++) {
            uint8_t rnd1;
            int b_pre;
            if (fread(&rnd1, 1, 1, urnd) != 1) rnd1 = (uint8_t)(i ^ r);
            b_pre = (int)(rnd1 % 3u);
            stern_ring_simulate(sig, i * rounds + r, b_pre,
                                 H_mat_i, syn_i, urnd);
        }
    }

    /* Step 2: commit phase for real signer j */
    {
        BitArray H_mat[SDF_N_ROWS];
        uint8_t perm[KEYBITS];
        stern_build_H(H_mat, &seeds[j]);
        for (r = 0; r < rounds; r++) {
            int idx = j * rounds + r;
            BitArray items[2];
            stern_rand_error(&r_tmp[r], urnd);
            ba_xor(&y_tmp[r], e, &r_tmp[r]);
            ba_rand(&pi_tmp[r], urnd);
            stern_syndrome_H(Hr_tmp + r * SDF_SYNBYTES, H_mat, &r_tmp[r]);
            stern_gen_perm(perm, &pi_tmp[r], KEYBITS);
            stern_apply_perm(&sr_tmp[r], perm, &r_tmp[r], KEYBITS);
            stern_apply_perm(&sy_tmp[r], perm, &y_tmp[r], KEYBITS);
            items[0] = pi_tmp[r]; syndr_to_ba(&items[1], Hr_tmp + r * SDF_SYNBYTES);
            stern_hash(&sig->c0[idx], items, 2, 1);
            stern_hash(&sig->c1[idx], &sr_tmp[r], 1, 2);
            stern_hash(&sig->c2[idx], &sy_tmp[r], 1, 3);
        }
    }

    /* Step 3: Fiat-Shamir joint challenges */
    {
        int *joint = (int *)malloc(rounds * sizeof(int));
        if (!joint) { fprintf(stderr, "stern_ring_sign: out of memory\n"); exit(1); }
        stern_ring_challenges(joint, rounds, k, msg, sig->c0, sig->c1, sig->c2);

        /* Step 4: assign real signer's challenge via challenge splitting */
        for (r = 0; r < rounds; r++) {
            int sim_sum = 0;
            for (i = 0; i < k; i++)
                if (i != j) sim_sum += sig->b[i * rounds + r];
            sig->b[j * rounds + r] = ((joint[r] - sim_sum) % 3 + 3) % 3;
        }
        free(joint);
    }

    /* Step 5: complete real signer's responses */
    for (r = 0; r < rounds; r++) {
        int idx = j * rounds + r;
        int bv  = sig->b[idx];
        if      (bv == 0) { sig->resp_a[idx] = sr_tmp[r]; sig->resp_b[idx] = sy_tmp[r]; }
        else if (bv == 1) { sig->resp_a[idx] = pi_tmp[r]; sig->resp_b[idx] = r_tmp[r];  }
        else              { sig->resp_a[idx] = pi_tmp[r]; sig->resp_b[idx] = y_tmp[r];  }
    }

    free(r_tmp); free(y_tmp); free(pi_tmp); free(sr_tmp); free(sy_tmp); free(Hr_tmp);
}

/* Verify a ring signature.  Returns 1 if valid, 0 if invalid. */
static int stern_ring_verify(const SternRingSig *sig,
                               const BitArray *msg,
                               const BitArray *seeds,
                               const uint8_t  *syndrs_flat)
{
    int k      = sig->k;
    int rounds = sig->rounds;
    int *joint = (int *)malloc(rounds * sizeof(int));
    int i, r;

    if (!joint) { fprintf(stderr, "stern_ring_verify: out of memory\n"); exit(1); }
    stern_ring_challenges(joint, rounds, k, msg, sig->c0, sig->c1, sig->c2);

    /* Check challenge consistency: sum_i b[i,r] mod 3 == joint[r] */
    for (r = 0; r < rounds; r++) {
        int s = 0;
        for (i = 0; i < k; i++) s += sig->b[i * rounds + r];
        if ((s % 3 + 3) % 3 != joint[r]) { free(joint); return 0; }
    }
    free(joint);

    /* Verify each member's responses */
    for (i = 0; i < k; i++) {
        BitArray H_mat[SDF_N_ROWS];
        uint8_t perm[KEYBITS];
        const uint8_t *syn_i = syndrs_flat + i * SDF_SYNBYTES;
        stern_build_H(H_mat, &seeds[i]);
        for (r = 0; r < rounds; r++) {
            int idx = i * rounds + r;
            int bv  = sig->b[idx];
            BitArray tmp;
            if (bv == 0) {
                stern_hash(&tmp, &sig->resp_a[idx], 1, 2);
                if (!ba_equal(&tmp, &sig->c1[idx])) return 0;
                stern_hash(&tmp, &sig->resp_b[idx], 1, 3);
                if (!ba_equal(&tmp, &sig->c2[idx])) return 0;
                if (ba_popcount(&sig->resp_a[idx]) != SDF_T) return 0;
            } else if (bv == 1) {
                uint8_t Hr[SDF_SYNBYTES];
                BitArray items[2], sr2;
                if (ba_popcount(&sig->resp_b[idx]) != SDF_T) return 0;
                stern_syndrome_H(Hr, H_mat, &sig->resp_b[idx]);
                items[0] = sig->resp_a[idx]; syndr_to_ba(&items[1], Hr);
                stern_hash(&tmp, items, 2, 1);
                if (!ba_equal(&tmp, &sig->c0[idx])) return 0;
                stern_gen_perm(perm, &sig->resp_a[idx], KEYBITS);
                stern_apply_perm(&sr2, perm, &sig->resp_b[idx], KEYBITS);
                stern_hash(&tmp, &sr2, 1, 2);
                if (!ba_equal(&tmp, &sig->c1[idx])) return 0;
            } else {
                uint8_t Hy[SDF_SYNBYTES], Hys[SDF_SYNBYTES];
                BitArray items[2], sy2;
                int k2;
                stern_syndrome_H(Hy, H_mat, &sig->resp_b[idx]);
                for (k2 = 0; k2 < SDF_SYNBYTES; k2++) Hys[k2] = Hy[k2] ^ syn_i[k2];
                items[0] = sig->resp_a[idx]; syndr_to_ba(&items[1], Hys);
                stern_hash(&tmp, items, 2, 1);
                if (!ba_equal(&tmp, &sig->c0[idx])) return 0;
                stern_gen_perm(perm, &sig->resp_a[idx], KEYBITS);
                stern_apply_perm(&sy2, perm, &sig->resp_b[idx], KEYBITS);
                stern_hash(&tmp, &sy2, 1, 3);
                if (!ba_equal(&tmp, &sig->c2[idx])) return 0;
            }
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
    stern_hash(K_out, items, 2, 4);
}

/* Decapsulate using known e' (demo only; production needs QC-MDPC decoder). */
static void hpke_stern_f_decap_known(BitArray *K_out,
                                      const BitArray *e_p,
                                      const BitArray *seed)
{
    BitArray items[2];
    items[0] = *seed;
    items[1] = *e_p;
    stern_hash(K_out, items, 2, 4);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Protocol Layer — high-level wrappers for library callers
 *
 * These thin functions assemble the low-level primitives into the four named
 * Herradura protocols.  Include herradura.h in any C translation unit, compile
 * with -O2, and call these directly — no separate library build step needed.
 *
 *   hkex_gf_pubkey / hkex_gf_agree   — HKEX-GF key exchange
 *   hske_encrypt   / hske_decrypt     — HSKE symmetric encryption
 *   hpks_sign      / hpks_verify      — HPKS Schnorr signature
 *   hpke_encrypt   / hpke_decrypt     — HPKE El Gamal encryption
 *
 * For PQC-hardened protocols use: hpks_stern_f_sign / hpks_stern_f_verify
 * (Stern ZKP, code-based), rnl_keygen / rnl_agree (Ring-LWR), and the
 * NL-FSCX revolve primitives directly — they are already protocol-level.
 *
 * See docs/TUTORIAL.md for complete usage examples.
 * ───────────────────────────────────────────────────────────────────────────── */

/* HKEX-GF: derive public key pub = g^priv in GF(2^KEYBITS)*. */
static inline void hkex_gf_pubkey(const BitArray *priv, BitArray *pub)
{
    gf_pow_ba(pub, &GF_GEN, priv);
}

/* HKEX-GF: derive shared secret shared = their_pub^my_priv in GF(2^KEYBITS)*. */
static inline void hkex_gf_agree(const BitArray *my_priv,
                                   const BitArray *their_pub,
                                   BitArray *shared)
{
    gf_pow_ba(shared, their_pub, my_priv);
}

/* HSKE: encrypt pt -> ct using key (I_VALUE steps). */
static inline void hske_encrypt(const BitArray *pt, const BitArray *key,
                                 BitArray *ct)
{
    ba_fscx_revolve(ct, pt, key, I_VALUE);
}

/* HSKE: decrypt ct -> pt using key (R_VALUE steps). */
static inline void hske_decrypt(const BitArray *ct, const BitArray *key,
                                 BitArray *pt)
{
    ba_fscx_revolve(pt, ct, key, R_VALUE);
}

/* HPKS: sign msg with private key priv.
 * Outputs commitment R = g^k and scalar s = (k - priv*e) mod ord.
 * Send (R, s) to the verifier along with the message. */
static inline void hpks_sign(const BitArray *msg, const BitArray *priv,
                               BitArray *R_out, BitArray *s_out, FILE *urnd)
{
    BitArray k, e, ae;
    ba_rand(&k, urnd);
    gf_pow_ba(R_out, &GF_GEN, &k);
    ba_fscx_revolve(&e, R_out, msg, I_VALUE);
    ba_mul_mod_ord(&ae, priv, &e);
    ba_sub_mod_ord(s_out, &k, &ae);
}

/* HPKS: verify Schnorr signature (R, s) on msg under public key pub.
 * Returns 1 if valid, 0 otherwise. */
static inline int hpks_verify(const BitArray *msg, const BitArray *pub,
                                const BitArray *R, const BitArray *s)
{
    BitArray e, gs, Ce, lhs;
    ba_fscx_revolve(&e, R, msg, I_VALUE);
    gf_pow_ba(&gs, &GF_GEN, s);
    gf_pow_ba(&Ce, pub, &e);
    gf_mul_ba(&lhs, &gs, &Ce);
    return ba_equal(&lhs, R);
}

/* HPKE: encrypt pt for the holder of private key corresponding to pub.
 * Outputs ephemeral R (send alongside ciphertext) and ciphertext ct. */
static inline void hpke_encrypt(const BitArray *pt, const BitArray *pub,
                                  BitArray *R_out, BitArray *ct_out, FILE *urnd)
{
    BitArray r, enc_key;
    ba_rand(&r, urnd);
    gf_pow_ba(R_out, &GF_GEN, &r);
    gf_pow_ba(&enc_key, pub, &r);
    ba_fscx_revolve(ct_out, pt, &enc_key, I_VALUE);
}

/* HPKE: decrypt ciphertext ct using private key priv and sender's ephemeral R. */
static inline void hpke_decrypt(const BitArray *ct, const BitArray *R,
                                  const BitArray *priv, BitArray *pt_out)
{
    BitArray dec_key;
    gf_pow_ba(&dec_key, R, priv);
    ba_fscx_revolve(pt_out, ct, &dec_key, R_VALUE);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * ZKP-RNL  Ring-LWR Σ-protocol (Lyubashevsky / Fiat-Shamir)
 * SecurityProofs-3.md §11.10.2
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * A proof-of-knowledge for the relation { (m,C_p ; s) : C_p = round_p(m·s) }
 * in Z_q[x]/(x^n+1).  Proof = (w, c, z); accepted iff:
 *   ‖z‖∞ ≤ γ−t  and  round_p(m·z) ≈ w + c·lift(C_p)  (within slack).
 *
 * Parameters are chosen per polynomial dimension n; for n = RNL_N = 256 the
 * NTT-based rnl_poly_mul is used; for smaller n a naive O(n²) multiply is used.
 * ───────────────────────────────────────────────────────────────────────────── */

#define SIGMA_MAX_ATTEMPTS 1000

static void sigma_params(int n, int *g_out, int *t_out)
{
    *t_out = (n <= 32) ? 4 : (n <= 64) ? 8 : (n <= 128) ? 12 : 16;
    *g_out = (n <= 32) ? 4096 : 8192;
}

/* O(n²) negacyclic poly mul in Z_q[x]/(x^n+1).  Used when n ≠ RNL_N. */
static void sigma_poly_mul_n(int32_t *h, const int32_t *f, const int32_t *g, int n, int q)
{
    int i, j;
    int64_t *tmp = (int64_t *)calloc((size_t)n, sizeof(int64_t));
    if (!tmp) { fputs("sigma_poly_mul_n OOM\n", stderr); exit(1); }
    for (i = 0; i < n; i++) {
        int64_t fi = (uint32_t)f[i];
        for (j = 0; j < n; j++) {
            int k = (i + j) % n;
            int64_t v = fi * (uint32_t)g[j] % q;
            tmp[k] = (i + j >= n) ? (tmp[k] - v + q) % q : (tmp[k] + v) % q;
        }
    }
    for (i = 0; i < n; i++) h[i] = (int32_t)tmp[i];
    free(tmp);
}

/* Serialize n poly coefficients as n×4 big-endian bytes (lower u32 each). */
static void sigma_poly_bytes(uint8_t *out, const int32_t *p, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        uint32_t v = (uint32_t)p[i];
        out[i*4+0] = (uint8_t)(v >> 24); out[i*4+1] = (uint8_t)(v >> 16);
        out[i*4+2] = (uint8_t)(v >>  8); out[i*4+3] = (uint8_t)v;
    }
}

/* Fiat-Shamir: derive a sparse ternary challenge polynomial c from (m, C_p, w, msg).
 * t nonzero coefficients in {1, q-1}.  Matches Python _sigma_challenge exactly. */
static void sigma_challenge(const int32_t *m, const int32_t *Cp, const int32_t *w,
                            int n, int q, int t, const uint8_t *msg, size_t mlen,
                            int32_t *c_out)
{
    uint8_t seed[32];
    /* Hash: 4B n | n×4B m | n×4B C | n×4B w | msg */
    size_t bl = 4 + (size_t)n * 12 + mlen;
    uint8_t *buf = (uint8_t *)malloc(bl);
    if (!buf) { fputs("sigma_challenge OOM\n", stderr); exit(1); }
    buf[0] = (uint8_t)((uint32_t)n >> 24); buf[1] = (uint8_t)((uint32_t)n >> 16);
    buf[2] = (uint8_t)((uint32_t)n >>  8); buf[3] = (uint8_t)n;
    sigma_poly_bytes(buf + 4,          m, n);
    sigma_poly_bytes(buf + 4 + n * 4, Cp, n);
    sigma_poly_bytes(buf + 4 + n * 8,  w, n);
    if (mlen) memcpy(buf + 4 + n * 12, msg, mlen);
    hfscx_256(buf, bl, NULL, seed);
    free(buf);

    /* Position expansion: seed||"pos"||4B_idx → sample t distinct positions in [0,n) */
    int *pos = (int *)malloc((size_t)t * sizeof(int));
    if (!pos) { fputs("sigma_challenge pos OOM\n", stderr); exit(1); }
    uint8_t ext[39], h[32];
    memcpy(ext, seed, 32); memcpy(ext + 32, "pos", 3);
    int np = 0, idx = 0;
    while (np < t) {
        ext[35] = (uint8_t)(idx >> 24); ext[36] = (uint8_t)(idx >> 16);
        ext[37] = (uint8_t)(idx >>  8); ext[38] = (uint8_t)idx;
        hfscx_256(ext, 39, NULL, h);
        uint32_t v = (uint32_t)(((uint32_t)h[0]<<24|(uint32_t)h[1]<<16|
                                  (uint32_t)h[2]<<8|h[3]) % (uint32_t)n);
        int dup = 0, k;
        for (k = 0; k < np; k++) if (pos[k] == (int)v) { dup = 1; break; }
        if (!dup) pos[np++] = (int)v;
        idx++;
    }
    /* Sign expansion: seed||"sgn"||4B_k → ±1 per position */
    memset(c_out, 0, (size_t)n * sizeof(int32_t));
    memcpy(ext + 32, "sgn", 3);
    for (int k = 0; k < t; k++) {
        ext[35] = (uint8_t)(k >> 24); ext[36] = (uint8_t)(k >> 16);
        ext[37] = (uint8_t)(k >>  8); ext[38] = (uint8_t)k;
        hfscx_256(ext, 39, NULL, h);
        c_out[pos[k]] = (h[0] & 1) ? (int32_t)(q - 1) : 1;
    }
    free(pos);
}

/* ZKP-RNL prover.
 * s, m, Cp: n-element arrays in Z_q.  w_out, c_out, z_out: caller-allocated, n each.
 * Returns 0 on success, -1 if SIGMA_MAX_ATTEMPTS exhausted. */
static int rnl_sigma_sign(const int32_t *s, const int32_t *m, const int32_t *Cp,
                          int n, const uint8_t *msg, size_t mlen, FILE *urnd,
                          int32_t *w_out, int32_t *c_out, int32_t *z_out)
{
    int gamma, t;
    sigma_params(n, &gamma, &t);
    int bound = gamma - t, q = RNL_Q;
    int64_t hq = q / 2;
    uint32_t range = (uint32_t)(2 * gamma + 1);
    uint32_t thresh = (1u << 24) - (1u << 24) % range;

    int32_t *y   = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *y_q = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *my  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *ct  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *cs  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    if (!y || !y_q || !my || !ct || !cs) { fputs("OOM\n", stderr); exit(1); }

    int ok = 0, attempt, i;
    for (attempt = 0; attempt < SIGMA_MAX_ATTEMPTS; attempt++) {
        for (i = 0; i < n; i++) {
            uint32_t v;
            do { uint8_t b[3];
                 if (fread(b, 1, 3, urnd) != 3) { fputs("urandom\n", stderr); exit(1); }
                 v = ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
            } while (v >= thresh);
            y[i] = (int32_t)(v % range) - gamma;
        }
        for (i = 0; i < n; i++) y_q[i] = (int32_t)(((int64_t)y[i] % q + q) % q);

        if (n == RNL_N) rnl_poly_mul(my, m, y_q);
        else            sigma_poly_mul_n(my, m, y_q, n, q);

        for (i = 0; i < n; i++)
            w_out[i] = (my[i] > (int32_t)hq) ? (int32_t)(my[i] - q) : my[i];

        sigma_challenge(m, Cp, w_out, n, q, t, msg, mlen, ct);

        if (n == RNL_N) rnl_poly_mul(cs, ct, s);
        else            sigma_poly_mul_n(cs, ct, s, n, q);

        int ok2 = 1;
        for (i = 0; i < n; i++) {
            int32_t csi = (cs[i] > (int32_t)hq) ? (int32_t)(cs[i] - q) : cs[i];
            z_out[i] = y[i] + csi;
            if (z_out[i] > bound || z_out[i] < -bound) ok2 = 0;
        }
        if (ok2) { memcpy(c_out, ct, (size_t)n * sizeof(int32_t)); ok = 1; break; }
    }
    free(y); free(y_q); free(my); free(ct); free(cs);
    return ok ? 0 : -1;
}

/* ZKP-RNL verifier.  Returns 1 if proof is valid, 0 otherwise. */
static int rnl_sigma_verify(const int32_t *m, const int32_t *Cp,
                            int n, const uint8_t *msg, size_t mlen,
                            const int32_t *w, const int32_t *c, const int32_t *z)
{
    int gamma, t;
    sigma_params(n, &gamma, &t);
    int bound = gamma - t, q = RNL_Q, p = RNL_P, i, valid = 1;
    int64_t hq = q / 2, slack = (int64_t)t * (q / (2 * p) + 1);

    for (i = 0; i < n; i++) if (z[i] > bound || z[i] < -bound) return 0;

    int32_t *cc  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *z_q = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *lft = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *mz  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *cL  = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    int32_t *w_q = (int32_t *)malloc((size_t)n * sizeof(int32_t));
    if (!cc || !z_q || !lft || !mz || !cL || !w_q) { fputs("OOM\n", stderr); exit(1); }

    sigma_challenge(m, Cp, w, n, q, t, msg, mlen, cc);
    for (i = 0; i < n; i++) if (cc[i] != c[i]) { valid = 0; goto vdone; }

    for (i = 0; i < n; i++) z_q[i] = (int32_t)(((int64_t)z[i]  % q + q) % q);
    for (i = 0; i < n; i++) lft[i] = (int32_t)((((int64_t)Cp[i] * q) + p/2) / p % q);
    for (i = 0; i < n; i++) w_q[i] = (int32_t)(((int64_t)w[i]  % q + q) % q);

    if (n == RNL_N) { rnl_poly_mul(mz, m, z_q); rnl_poly_mul(cL, c, lft); }
    else            { sigma_poly_mul_n(mz, m, z_q, n, q); sigma_poly_mul_n(cL, c, lft, n, q); }

    for (i = 0; i < n; i++) {
        int64_t d = ((int64_t)mz[i] - cL[i] - w_q[i] + 2LL * q) % q;
        if (d > hq) d -= q;
        if (d > slack || d < -slack) { valid = 0; break; }
    }
vdone:
    free(cc); free(z_q); free(lft); free(mz); free(cL); free(w_q);
    return valid;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * ZKP-NL  NL-FSCX ZKBoo (MPC-in-the-head, 3-party Boolean circuit)
 * SecurityProofs-3.md §11.10.3
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Proves knowledge of A s.t. nl_fscx_v1(A, B) = y (n ≤ ZKP_NL_MAX_N bits).
 * Circuit: F1(A, B) = FSCX(A,B)  XOR  ROL_{n/4}((A+B) mod 2^n).
 * The carry chain of (A+B) contributes n−1 AND gates (each 3-party shared).
 * Soundness: (2/3)^R; R = ZKP_NL_PROD_ROUNDS gives 128-bit security.
 * ───────────────────────────────────────────────────────────────────────────── */

#define ZKP_NL_DEFAULT_N    8
#define ZKP_NL_DEMO_ROUNDS  4
#define ZKP_NL_PROD_ROUNDS  219
#define ZKP_NL_MAX_N        64

typedef struct {
    uint8_t  com_0[32], com_1[32], com_2[32];
    uint8_t  e;          /* hidden party index 0,1,2 */
    uint8_t *view_p1;    /* heap: view of party (e+1)%3 */
    uint8_t *view_p2;    /* heap: view of party (e+2)%3 */
    size_t   view_len;
} ZkpNlRound;

static void zkp_nl_proof_free(ZkpNlRound *proof, int rounds)
{
    int j;
    if (!proof) return;
    for (j = 0; j < rounds; j++) { free(proof[j].view_p1); free(proof[j].view_p2); }
    free(proof);
}

/* n-bit cyclic left-rotate (n ≤ 64). */
static uint64_t zkp_nl_rol(uint64_t x, int r, int n)
{
    uint64_t mask = (n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL;
    r = ((r % n) + n) % n;
    return r ? ((x << r) | (x >> (n - r))) & mask : x & mask;
}

/* Commitment: HFSCX-256( j(4B) || p(1B) || tape(32B) || out_share(nb B) ). */
static void zkp_nl_commit(uint8_t out[32], int j, int p,
                          const uint8_t tape[32], uint64_t out_share, int nb)
{
    uint8_t buf[4 + 1 + 32 + 8];  /* nb ≤ 8 for n ≤ ZKP_NL_MAX_N = 64 */
    int k;
    buf[0]=(uint8_t)(j>>24); buf[1]=(uint8_t)(j>>16); buf[2]=(uint8_t)(j>>8); buf[3]=(uint8_t)j;
    buf[4] = (uint8_t)p;
    memcpy(buf + 5, tape, 32);
    for (k = 0; k < nb; k++) buf[5+32+k] = (uint8_t)(out_share >> (8*(nb-1-k)));
    hfscx_256(buf, (size_t)(5 + 32 + nb), NULL, out);
}

/* One PRG bit from tape and gate index. */
static int zkp_nl_prg_bit(const uint8_t tape[32], int gate_id)
{
    uint8_t buf[36], h[32];
    memcpy(buf, tape, 32);
    buf[32]=(uint8_t)(gate_id>>24); buf[33]=(uint8_t)(gate_id>>16);
    buf[34]=(uint8_t)(gate_id>>8);  buf[35]=(uint8_t)gate_id;
    hfscx_256(buf, 36, NULL, h);
    return h[0] & 1;
}

/* 3-party ZKBoo evaluation of nl_fscx_v1(A, B).
 * shares: XOR shares of A.  tapes: per-party 32-byte tape.  B: public constant.
 * Fills out0/out1/out2 (XOR shares of F1(A,B)) and gv0/gv1/gv2 (gate views, n-1 bytes each). */
static void zkp_nl_eval_3p(
    uint64_t s0, uint64_t s1, uint64_t s2,
    const uint8_t *t0, const uint8_t *t1, const uint8_t *t2,
    uint64_t B, int n,
    uint64_t *out0, uint64_t *out1, uint64_t *out2,
    uint8_t *gv0, uint8_t *gv1, uint8_t *gv2)
{
    uint64_t mask = (n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL;
    uint64_t sh[3] = { s0, s1, s2 };
    const uint8_t *tp[3] = { t0, t1, t2 };
    uint8_t *gv[3] = { gv0, gv1, gv2 };
    uint64_t carry[ZKP_NL_MAX_N + 1][3];
    int i, p;
    memset(carry, 0, sizeof(carry));

    for (i = 0; i < n - 1; i++) {
        int Bi = (int)((B >> i) & 1);
        int ai[3], ci[3], ri[3], ao[3];
        for (p = 0; p < 3; p++) {
            ai[p] = (int)((sh[p] >> i) & 1); ci[p] = (int)carry[i][p];
            ri[p] = zkp_nl_prg_bit(tp[p], i);
        }
        for (p = 0; p < 3; p++) {
            int p1 = (p + 1) % 3;
            ao[p] = (ai[p]&ci[p]) ^ (ai[p]&ci[p1]) ^ (ai[p1]&ci[p]) ^ ri[p] ^ ri[p1];
            gv[p][i] = (uint8_t)(ai[p] | (ci[p] << 1) | (ao[p] << 2));
        }
        for (p = 0; p < 3; p++)
            carry[i+1][p] = (uint64_t)((Bi & ai[p]) ^ ao[p] ^ (Bi & ci[p]));
    }

    uint64_t sum_s[3] = {0, 0, 0};
    for (i = 0; i < n; i++) {
        int Bi = (int)((B >> i) & 1);
        for (p = 0; p < 3; p++) {
            int sb = (int)((sh[p] >> i) & 1) ^ Bi ^ (int)carry[i][p];
            sum_s[p] ^= (uint64_t)sb << i;
        }
    }

    uint64_t rot_s[3], lin_s[3];
    uint64_t Bc = (B ^ zkp_nl_rol(B,1,n) ^ zkp_nl_rol(B,n-1,n)) & mask;
    for (p = 0; p < 3; p++) {
        rot_s[p] = zkp_nl_rol(sum_s[p], n/4, n);
        lin_s[p] = (sh[p] ^ zkp_nl_rol(sh[p],1,n) ^ zkp_nl_rol(sh[p],n-1,n)) & mask;
    }
    lin_s[0] ^= Bc;

    *out0 = (lin_s[0] ^ rot_s[0]) & mask;
    *out1 = (lin_s[1] ^ rot_s[1]) & mask;
    *out2 = (lin_s[2] ^ rot_s[2]) & mask;
}

/* Pack one party's view: share(nb) || tape(32) || out_share(nb) || gate_bytes(n-1). */
static void zkp_nl_pack_view(uint8_t *buf, uint64_t share, const uint8_t tape[32],
                              uint64_t out_share, const uint8_t *gate_bytes, int n, int nb)
{
    int k;
    for (k = 0; k < nb; k++) buf[k] = (uint8_t)(share >> (8*(nb-1-k)));
    memcpy(buf + nb, tape, 32);
    for (k = 0; k < nb; k++) buf[nb+32+k] = (uint8_t)(out_share >> (8*(nb-1-k)));
    if (n > 1) memcpy(buf + nb + 32 + nb, gate_bytes, (size_t)(n-1));
}

/* Unpack a view buffer; returns pointers into buf for tape and gate_bytes. */
static void zkp_nl_unpack_view(const uint8_t *buf, int n, int nb,
                                uint64_t *share_out, const uint8_t **tape_out,
                                uint64_t *out_share_out, const uint8_t **gv_out)
{
    int k; uint64_t v = 0;
    for (k = 0; k < nb; k++) v = (v << 8) | buf[k];
    *share_out = v;
    *tape_out  = buf + nb;
    v = 0;
    for (k = 0; k < nb; k++) v = (v << 8) | buf[nb+32+k];
    *out_share_out = v;
    *gv_out        = buf + nb + 32 + nb;
}

/* Direct evaluation of nl_fscx_v1(A, B) as a scalar (for keygen). */
static uint64_t zkp_nl_f1(uint64_t A, uint64_t B, int n)
{
    uint64_t mask = (n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL;
    uint64_t lin = (A ^ B ^ zkp_nl_rol(A,1,n) ^ zkp_nl_rol(B,1,n)
                    ^ zkp_nl_rol(A,n-1,n) ^ zkp_nl_rol(B,n-1,n)) & mask;
    return (lin ^ zkp_nl_rol((A+B)&mask, n/4, n)) & mask;
}

/* Generate a ZKP-NL keypair (n ≤ ZKP_NL_MAX_N).
 * A is the private witness; (B, y) is the public statement. */
static void zkp_nl_keygen(int n, FILE *urnd, uint64_t *A_out, uint64_t *B_out, uint64_t *y_out)
{
    uint64_t mask = (n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL;
    int nb = (n + 7) / 8, k;
    uint64_t A = 0, B = 0;
    uint8_t rb;
    for (k = 0; k < nb; k++) {
        if (fread(&rb, 1, 1, urnd) != 1) { fputs("urandom\n", stderr); exit(1); }
        A = (A << 8) | rb;
    }
    for (k = 0; k < nb; k++) {
        if (fread(&rb, 1, 1, urnd) != 1) { fputs("urandom\n", stderr); exit(1); }
        B = (B << 8) | rb;
    }
    A &= mask; B &= mask;
    *A_out = A; *B_out = B; *y_out = zkp_nl_f1(A, B, n);
}

/* Prove knowledge of A s.t. F1(A, B) = y.
 * Returns a heap-allocated array of `rounds` ZkpNlRound structs; free with zkp_nl_proof_free. */
static ZkpNlRound *zkp_nl_prove(uint64_t A, uint64_t B, uint64_t y, int n, int rounds,
                                 const uint8_t *msg, size_t mlen, FILE *urnd)
{
    int nb = (n + 7) / 8;
    size_t gv_stride = (n > 1) ? (size_t)(n-1) : 1;
    size_t view_len  = (size_t)(2*nb) + 32 + (n > 1 ? (size_t)(n-1) : 0);
    uint64_t mask = (n >= 64) ? UINT64_MAX : (1ULL << n) - 1ULL;

    ZkpNlRound *proof = (ZkpNlRound *)malloc((size_t)rounds * sizeof(ZkpNlRound));
    uint8_t  *all_coms = (uint8_t *)malloc((size_t)rounds * 3 * 32);
    uint64_t *all_sh   = (uint64_t *)malloc((size_t)rounds * 3 * sizeof(uint64_t));
    uint8_t  *all_tp   = (uint8_t *)malloc((size_t)rounds * 3 * 32);
    uint64_t *all_out  = (uint64_t *)malloc((size_t)rounds * 3 * sizeof(uint64_t));
    uint8_t  *all_gv   = (uint8_t *)malloc((size_t)rounds * 3 * gv_stride);
    if (!proof||!all_coms||!all_sh||!all_tp||!all_out||!all_gv)
        { fputs("zkp_nl_prove OOM\n", stderr); exit(1); }
    memset(all_gv, 0, (size_t)rounds * 3 * gv_stride);

    int j, p, k;
    /* Phase 1: generate shares, tapes, evaluate circuit, commit. */
    for (j = 0; j < rounds; j++) {
        uint64_t s0 = 0, s1 = 0;
        uint8_t rb;
        for (k = 0; k < nb; k++) {
            if (fread(&rb,1,1,urnd)!=1){fputs("urandom\n",stderr);exit(1);} s0=(s0<<8)|rb;
        }
        for (k = 0; k < nb; k++) {
            if (fread(&rb,1,1,urnd)!=1){fputs("urandom\n",stderr);exit(1);} s1=(s1<<8)|rb;
        }
        s0 &= mask; s1 &= mask;
        uint64_t s2 = (A ^ s0 ^ s1) & mask;
        all_sh[j*3+0] = s0; all_sh[j*3+1] = s1; all_sh[j*3+2] = s2;
        for (p = 0; p < 3; p++)
            if (fread(all_tp+(j*3+p)*32, 1, 32, urnd) != 32)
                { fputs("urandom tape\n", stderr); exit(1); }

        zkp_nl_eval_3p(s0, s1, s2,
                        all_tp+(j*3+0)*32, all_tp+(j*3+1)*32, all_tp+(j*3+2)*32,
                        B, n,
                        &all_out[j*3+0], &all_out[j*3+1], &all_out[j*3+2],
                        all_gv+(j*3+0)*gv_stride,
                        all_gv+(j*3+1)*gv_stride,
                        all_gv+(j*3+2)*gv_stride);

        for (p = 0; p < 3; p++)
            zkp_nl_commit(all_coms+(j*3+p)*32, j, p,
                          all_tp+(j*3+p)*32, all_out[j*3+p], nb);
    }

    /* Phase 2: Fiat-Shamir challenge seed = hash(all_coms || B_bytes || y_bytes || msg). */
    size_t ch_len = (size_t)rounds*3*32 + (size_t)nb + (size_t)nb + mlen;
    uint8_t *ch_buf = (uint8_t *)malloc(ch_len);
    if (!ch_buf) { fputs("OOM\n", stderr); exit(1); }
    memcpy(ch_buf, all_coms, (size_t)rounds*3*32);
    for (k = 0; k < nb; k++) ch_buf[rounds*3*32+k]    = (uint8_t)(B >> (8*(nb-1-k)));
    for (k = 0; k < nb; k++) ch_buf[rounds*3*32+nb+k]  = (uint8_t)(y >> (8*(nb-1-k)));
    if (mlen) memcpy(ch_buf+rounds*3*32+nb+nb, msg, mlen);
    uint8_t ch_seed[32];
    hfscx_256(ch_buf, ch_len, NULL, ch_seed);
    free(ch_buf);

    /* Phase 3: derive per-round challenges and pack views. */
    for (j = 0; j < rounds; j++) {
        uint8_t ext[36], h[32];
        memcpy(ext, ch_seed, 32);
        ext[32]=(uint8_t)(j>>24); ext[33]=(uint8_t)(j>>16);
        ext[34]=(uint8_t)(j>>8);  ext[35]=(uint8_t)j;
        hfscx_256(ext, 36, NULL, h);
        int e = h[0] % 3, p1 = (e+1)%3, p2 = (e+2)%3;

        memcpy(proof[j].com_0, all_coms+(j*3+0)*32, 32);
        memcpy(proof[j].com_1, all_coms+(j*3+1)*32, 32);
        memcpy(proof[j].com_2, all_coms+(j*3+2)*32, 32);
        proof[j].e        = (uint8_t)e;
        proof[j].view_len = view_len;
        proof[j].view_p1  = (uint8_t *)malloc(view_len);
        proof[j].view_p2  = (uint8_t *)malloc(view_len);
        if (!proof[j].view_p1 || !proof[j].view_p2)
            { fputs("OOM view\n", stderr); exit(1); }

        zkp_nl_pack_view(proof[j].view_p1, all_sh[j*3+p1], all_tp+(j*3+p1)*32,
                          all_out[j*3+p1], all_gv+(j*3+p1)*gv_stride, n, nb);
        zkp_nl_pack_view(proof[j].view_p2, all_sh[j*3+p2], all_tp+(j*3+p2)*32,
                          all_out[j*3+p2], all_gv+(j*3+p2)*gv_stride, n, nb);
    }
    free(all_coms); free(all_sh); free(all_tp); free(all_out); free(all_gv);
    return proof;
}

/* Verify a ZKBoo proof.  Returns 1 if valid, 0 otherwise. */
static int zkp_nl_verify(uint64_t B, uint64_t y, int n, int rounds,
                          const uint8_t *msg, size_t mlen, ZkpNlRound *proof)
{
    if (n <= 0 || n > ZKP_NL_MAX_N || rounds <= 0 || rounds > 4096) return 0;
    int nb = (n + 7) / 8, j, k;

    /* Recompute FS challenge seed. */
    size_t ch_len = (size_t)rounds*3*32 + (size_t)nb + (size_t)nb + mlen;
    uint8_t *ch_buf = (uint8_t *)malloc(ch_len);
    if (!ch_buf) { fputs("OOM\n", stderr); exit(1); }
    for (j = 0; j < rounds; j++) {
        memcpy(ch_buf+j*3*32+0*32, proof[j].com_0, 32);
        memcpy(ch_buf+j*3*32+1*32, proof[j].com_1, 32);
        memcpy(ch_buf+j*3*32+2*32, proof[j].com_2, 32);
    }
    for (k = 0; k < nb; k++) ch_buf[rounds*3*32+k]    = (uint8_t)(B >> (8*(nb-1-k)));
    for (k = 0; k < nb; k++) ch_buf[rounds*3*32+nb+k]  = (uint8_t)(y >> (8*(nb-1-k)));
    if (mlen) memcpy(ch_buf+rounds*3*32+nb+nb, msg, mlen);
    uint8_t ch_seed[32];
    hfscx_256(ch_buf, ch_len, NULL, ch_seed);
    free(ch_buf);

    for (j = 0; j < rounds; j++) {
        uint8_t ext[36], h[32];
        memcpy(ext, ch_seed, 32);
        ext[32]=(uint8_t)(j>>24); ext[33]=(uint8_t)(j>>16);
        ext[34]=(uint8_t)(j>>8);  ext[35]=(uint8_t)j;
        hfscx_256(ext, 36, NULL, h);
        if (h[0] % 3 != (int)proof[j].e) return 0;

        int e = proof[j].e, p1 = (e+1)%3, p2 = (e+2)%3;
        uint64_t sh_p1, sh_p2, out_p1, out_p2;
        const uint8_t *tp_p1, *tp_p2, *gv_p1, *gv_p2;
        zkp_nl_unpack_view(proof[j].view_p1, n, nb, &sh_p1, &tp_p1, &out_p1, &gv_p1);
        zkp_nl_unpack_view(proof[j].view_p2, n, nb, &sh_p2, &tp_p2, &out_p2, &gv_p2);

        uint8_t c_p1[32], c_p2[32];
        zkp_nl_commit(c_p1, j, p1, tp_p1, out_p1, nb);
        zkp_nl_commit(c_p2, j, p2, tp_p2, out_p2, nb);
        const uint8_t *coms[3] = { proof[j].com_0, proof[j].com_1, proof[j].com_2 };
        if (!ct_eq32(c_p1, coms[p1]) || !ct_eq32(c_p2, coms[p2])) return 0;

        /* Re-evaluate p1's AND gates using both revealed shares/tapes; check gate views. */
        uint64_t carry_p1 = 0, carry_p2 = 0;
        int i;
        for (i = 0; i < n - 1; i++) {
            int ai_p1 = (int)((sh_p1 >> i) & 1), ai_p2 = (int)((sh_p2 >> i) & 1);
            int ci_p1 = (int)carry_p1,             ci_p2 = (int)carry_p2;
            int Bi    = (int)((B >> i) & 1);
            int ri_p1 = zkp_nl_prg_bit(tp_p1, i), ri_p2 = zkp_nl_prg_bit(tp_p2, i);

            int exp_ao_p1 = (ai_p1&ci_p1)^(ai_p1&ci_p2)^(ai_p2&ci_p1)^ri_p1^ri_p2;
            if (((gv_p1[i] >> 2) & 1) != exp_ao_p1) return 0;

            carry_p1 = (uint64_t)((Bi&ai_p1) ^ exp_ao_p1 ^ (Bi&ci_p1));
            int ao_p2 = (gv_p2[i] >> 2) & 1;
            carry_p2 = (uint64_t)((Bi&ai_p2) ^ ao_p2      ^ (Bi&ci_p2));
        }
    }
    return 1;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.J — Cryptographic Accumulator (Merkle tree on HFSCX-256) (TODO #78.J)
 *
 * Domain-separated leaf and node hashes prevent second-preimage cross-layer
 * collisions (0x00 for leaves, 0x01 for interior nodes — RFC 6962 convention).
 *
 * haccum_leaf(data, dlen, out)       HFSCX-256(0x00 || data)
 * haccum_node(left, right, out)      HFSCX-256(0x01 || left || right)
 * haccum_root(hashes, n, out)        builds Merkle tree; pads to next pow-of-2
 * haccum_prove(hashes, n, idx, &d)   returns sibling-hash path (malloc'd)
 * haccum_verify(root, leaf, pth, d, idx)  verifies membership
 * ─────────────────────────────────────────────────────────────────────────── */

static inline void haccum_leaf(const uint8_t *data, size_t dlen,
                                uint8_t out[KEYBYTES])
{
    uint8_t *buf = (uint8_t *)malloc(1 + dlen);
    if (!buf) { fprintf(stderr, "haccum_leaf: out of memory\n"); exit(1); }
    buf[0] = 0x00;
    if (dlen) memcpy(buf + 1, data, dlen);
    hfscx_256(buf, 1 + dlen, NULL, out);
    free(buf);
}

static inline void haccum_node(const uint8_t left[KEYBYTES],
                                const uint8_t right[KEYBYTES],
                                uint8_t out[KEYBYTES])
{
    uint8_t buf[1 + 2 * KEYBYTES];
    buf[0] = 0x01;
    memcpy(buf + 1,           left,  KEYBYTES);
    memcpy(buf + 1 + KEYBYTES, right, KEYBYTES);
    hfscx_256(buf, sizeof(buf), NULL, out);
}

static void haccum_root(const uint8_t (*leaf_hashes)[KEYBYTES], size_t n,
                         uint8_t out[KEYBYTES])
{
    size_t sz = 1, i;
    uint8_t (*nodes)[KEYBYTES];
    while (sz < n) sz <<= 1;
    nodes = (uint8_t (*)[KEYBYTES])malloc(sz * KEYBYTES);
    if (!nodes) { fprintf(stderr, "haccum_root: out of memory\n"); exit(1); }
    for (i = 0; i < n;  i++) memcpy(nodes[i], leaf_hashes[i], KEYBYTES);
    for (     ; i < sz; i++) memset(nodes[i], 0,               KEYBYTES);
    while (sz > 1) {
        for (i = 0; i < sz / 2; i++)
            haccum_node(nodes[2*i], nodes[2*i+1], nodes[i]);
        sz /= 2;
    }
    memcpy(out, nodes[0], KEYBYTES);
    free(nodes);
}

/* Returns a flat array of (depth * KEYBYTES) bytes; caller must free(). */
static uint8_t *haccum_prove(const uint8_t (*leaf_hashes)[KEYBYTES], size_t n,
                              size_t idx, int *depth_out)
{
    size_t sz = 1, i;
    int d = 0;
    uint8_t (*nodes)[KEYBYTES];
    uint8_t *path;
    size_t cur = idx;
    while (sz < n) { sz <<= 1; d++; }
    *depth_out = d;
    nodes = (uint8_t (*)[KEYBYTES])malloc(sz * KEYBYTES);
    if (!nodes) return NULL;
    for (i = 0; i < n;  i++) memcpy(nodes[i], leaf_hashes[i], KEYBYTES);
    for (     ; i < sz; i++) memset(nodes[i], 0,               KEYBYTES);
    path = (uint8_t *)malloc((size_t)d * KEYBYTES);
    if (!path) { free(nodes); return NULL; }
    d = 0;
    while (sz > 1) {
        size_t sib = cur ^ 1;
        memcpy(path + (size_t)d * KEYBYTES, nodes[sib], KEYBYTES);
        d++;
        for (i = 0; i < sz / 2; i++)
            haccum_node(nodes[2*i], nodes[2*i+1], nodes[i]);
        sz /= 2; cur >>= 1;
    }
    free(nodes);
    return path;
}

static int haccum_verify(const uint8_t root[KEYBYTES],
                          const uint8_t leaf_hash[KEYBYTES],
                          const uint8_t *proof, int depth, size_t idx)
{
    uint8_t cur[KEYBYTES], next[KEYBYTES];
    int d;
    memcpy(cur, leaf_hash, KEYBYTES);
    for (d = 0; d < depth; d++) {
        const uint8_t *sib = proof + (size_t)d * KEYBYTES;
        if (idx % 2 == 0) haccum_node(cur, sib, next);
        else               haccum_node(sib, cur, next);
        memcpy(cur, next, KEYBYTES);
        idx >>= 1;
    }
    return ct_eq_keybytes(cur, root);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.A — Format-Preserving Encryption (FPE) (TODO #78.A)
 *
 * Bijective encryption on {0,1}^256: nl_fscx_revolve_v2 with tweak B derived
 * from HFSCX-256(key || context).  Same (key, context, plaintext) always
 * yields the same ciphertext — suitable for deterministic / searchable
 * encryption.  Include a nonce in context for IND-CPA (e.g. record_id||nonce).
 * ─────────────────────────────────────────────────────────────────────────── */

static inline void fpe_derive_b(const uint8_t *key, size_t klen,
                                 const uint8_t *ctx, size_t clen,
                                 BitArray *B)
{
    uint8_t *tbuf = (uint8_t *)malloc(klen + clen);
    uint8_t tweak[KEYBYTES];
    if (!tbuf) { fprintf(stderr, "fpe: out of memory\n"); exit(1); }
    if (klen) memcpy(tbuf,       key, klen);
    if (clen) memcpy(tbuf + klen, ctx, clen);
    hfscx_256(tbuf, klen + clen, NULL, tweak);
    free(tbuf);
    memcpy(B->b, tweak, KEYBYTES);
}

static inline void fpe_encrypt(const BitArray *pt,
                                const uint8_t *key, size_t klen,
                                const uint8_t *ctx, size_t clen,
                                BitArray *ct)
{
    BitArray B;
    fpe_derive_b(key, klen, ctx, clen, &B);
    nl_fscx_revolve_v2_ba(ct, pt, &B, I_VALUE);
}

static inline void fpe_decrypt(const BitArray *ct,
                                const uint8_t *key, size_t klen,
                                const uint8_t *ctx, size_t clen,
                                BitArray *pt)
{
    BitArray B;
    fpe_derive_b(key, klen, ctx, clen, &B);
    nl_fscx_revolve_v2_inv_ba(pt, ct, &B, I_VALUE);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.B — Tweakable Wide-Block Cipher (disk / file encryption) (TODO #78.B)
 *
 * Each block gets a unique tweak B = HFSCX-256(key || sector_be64 || bidx_be32),
 * solving the determinism limitation of HSKE-NL-A2 (TODO #12).
 * Encrypt sector s, block i: C = nl_fscx_revolve_v2(P, B(s,i), I_VALUE).
 * ─────────────────────────────────────────────────────────────────────────── */

static inline void twk_derive_b(const uint8_t *key, size_t klen,
                                  uint64_t sector, uint32_t bidx,
                                  BitArray *B)
{
    uint8_t *tbuf = (uint8_t *)malloc(klen + 12);
    uint8_t tweak[KEYBYTES];
    int i;
    if (!tbuf) { fprintf(stderr, "twk: out of memory\n"); exit(1); }
    if (klen) memcpy(tbuf, key, klen);
    for (i = 7; i >= 0; i--) {
        tbuf[klen + (size_t)i] = (uint8_t)(sector & 0xff);
        sector >>= 8;
    }
    tbuf[klen + 8]  = (uint8_t)((bidx >> 24) & 0xff);
    tbuf[klen + 9]  = (uint8_t)((bidx >> 16) & 0xff);
    tbuf[klen + 10] = (uint8_t)((bidx >>  8) & 0xff);
    tbuf[klen + 11] = (uint8_t)( bidx        & 0xff);
    hfscx_256(tbuf, klen + 12, NULL, tweak);
    free(tbuf);
    memcpy(B->b, tweak, KEYBYTES);
}

static inline void twk_encrypt(const BitArray *block,
                                 const uint8_t *key, size_t klen,
                                 uint64_t sector, uint32_t bidx,
                                 BitArray *ct)
{
    BitArray B;
    twk_derive_b(key, klen, sector, bidx, &B);
    nl_fscx_revolve_v2_ba(ct, block, &B, I_VALUE);
}

static inline void twk_decrypt(const BitArray *ct,
                                 const uint8_t *key, size_t klen,
                                 uint64_t sector, uint32_t bidx,
                                 BitArray *block)
{
    BitArray B;
    twk_derive_b(key, klen, sector, bidx, &B);
    nl_fscx_revolve_v2_inv_ba(block, ct, &B, I_VALUE);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.H — Masking-Friendly FSCX (Boolean masking via GF(2) linearity)
 *
 * FSCX(A⊕r, B, steps) ⊕ FSCX(r, 0, steps) = FSCX(A, B, steps)
 * because M = I⊕ROL⊕ROR is GF(2)-linear, so M^steps(A⊕r) = M^steps(A)⊕M^steps(r).
 *
 * The caller supplies a uniform random mask r; no secret bits of A are
 * exposed in any intermediate value computed by this function.
 *
 * hske_encrypt_masked / hske_decrypt_masked generate their own mask internally
 * and return it in *mask_out so the caller can use or erase it.
 * ───────────────────────────────────────────────────────────────────────────── */

/* fscx_revolve_masked: compute FSCX(A,B,steps) without exposing A.
 * mask must be a uniform random BitArray (caller-supplied).
 * out  = FSCX(A⊕mask, B, steps) ⊕ FSCX(mask, 0, steps)
 *      = FSCX(A, B, steps)  [by GF(2)-linearity of M^steps]. */
static inline void fscx_revolve_masked(const BitArray *A, const BitArray *B,
                                        const BitArray *mask, int steps,
                                        BitArray *out)
{
    BitArray am, zero, fm, fz;
    int i;
    memset(zero.b, 0, KEYBYTES);
    for (i = 0; i < KEYBYTES; i++) am.b[i] = A->b[i] ^ mask->b[i];
    ba_fscx_revolve(&fm, &am,   B,     steps);
    ba_fscx_revolve(&fz, mask, &zero,  steps);
    for (i = 0; i < KEYBYTES; i++) out->b[i] = fm.b[i] ^ fz.b[i];
}

/* hske_encrypt_masked: HSKE encrypt with internal mask generation.
 * Writes ciphertext to *ct and the mask used to *mask_out (caller must
 * erase mask_out after use). */
static inline void hske_encrypt_masked(const BitArray *pt, const BitArray *key,
                                        BitArray *ct, BitArray *mask_out,
                                        FILE *urnd)
{
    ba_rand(mask_out, urnd);
    fscx_revolve_masked(pt, key, mask_out, I_VALUE, ct);
}

/* hske_decrypt_masked: HSKE decrypt with internal mask generation. */
static inline void hske_decrypt_masked(const BitArray *ct, const BitArray *key,
                                        BitArray *pt, BitArray *mask_out,
                                        FILE *urnd)
{
    ba_rand(mask_out, urnd);
    fscx_revolve_masked(ct, key, mask_out, R_VALUE, pt);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 78.C — Forward-Secret Unidirectional Ratchet
 *
 * state_{i+1} = nl_fscx_revolve_v1(state_i, RATCHET_DOMAIN, 1)
 * msg_key_i   = hfscx_256(state_i || 0x01)   [32 bytes, caller frees]
 *
 * Because nl_fscx_v1 is non-bijective, knowing state_{i+1} does not reveal
 * state_i (one-way by Theorem 16 OWF conjecture).  The caller MUST erase
 * state_i after calling ratchet_advance.
 *
 * RATCHET_DOMAIN = first 32 bytes of "NL-FSCX-RATCHET-V1\0" repeated.
 * ───────────────────────────────────────────────────────────────────────────── */

static const uint8_t _RATCHET_DOMAIN_BYTES[KEYBYTES] = {
    /* b'NL-FSCX-RATCHET-V1\x00' repeated, truncated to 32 bytes */
    'N','L','-','F','S','C','X','-','R','A','T','C','H','E','T','-',
    'V','1','\0','N','L','-','F','S','C','X','-','R','A','T','C','H'
};

/* ratchet_init: derive initial state from seed via HFSCX-256(seed || 0x02). */
static inline void ratchet_init(const uint8_t *seed, size_t slen, BitArray *state)
{
    uint8_t *buf = (uint8_t *)malloc(slen + 1);
    if (!buf) { fprintf(stderr, "ratchet_init: out of memory\n"); exit(1); }
    memcpy(buf, seed, slen);
    buf[slen] = 0x02;
    hfscx_256(buf, slen + 1, NULL, state->b);
    free(buf);
}

/* ratchet_advance: advance state by one step.
 * Writes next state to *new_state and 32-byte message key to msg_key[KEYBYTES].
 * Caller MUST call ratchet_erase(state) immediately after. */
static inline void ratchet_advance(const BitArray *state,
                                    BitArray *new_state,
                                    uint8_t msg_key[KEYBYTES])
{
    static const BitArray *domain = NULL;
    static BitArray dom_ba;
    uint8_t buf[KEYBYTES + 1];

    if (!domain) {
        memcpy(dom_ba.b, _RATCHET_DOMAIN_BYTES, KEYBYTES);
        domain = &dom_ba;
    }
    /* msg_key = HFSCX-256(state || 0x01) */
    memcpy(buf, state->b, KEYBYTES);
    buf[KEYBYTES] = 0x01;
    hfscx_256(buf, KEYBYTES + 1, NULL, msg_key);
    /* new_state = nl_fscx_revolve_v1(state, DOMAIN, 1) */
    nl_fscx_revolve_v1_ba(new_state, state, domain, 1);
}

/* ratchet_erase: zero-fill state (explicit, not optimised away). */
static inline void ratchet_erase(BitArray *state)
{
    explicit_bzero(state->b, KEYBYTES);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 80 — Oblivious PRF (OPRF) over GF(2^KEYBITS)*  (TODO #80)
 * Protocol: 2HashDH — F(k, x) = gf_pow(H(x), k)
 *   Client blinds: alpha = H(x)^r   (r random, gcd(r, ORD) == 1)
 *   Server evals:  beta  = alpha^k
 *   Client unblinds: F   = beta^{r^{-1} mod ORD}
 * ───────────────────────────────────────────────────────────────────────────── */

/* ba_cmp256: return -1, 0, +1 for a<b, a==b, a>b (big-endian). */
static int ba_cmp256(const BitArray *a, const BitArray *b)
{
    int i;
    for (i = 0; i < KEYBYTES; i++) {
        if (a->b[i] < b->b[i]) return -1;
        if (a->b[i] > b->b[i]) return  1;
    }
    return 0;
}

/* 33-byte (257-bit) big-endian integer helpers used only by ba_modinv_ord. */
static int _ba33_cmp(const uint8_t *a, const uint8_t *b)
{
    int i;
    for (i = 0; i < 33; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}
static int _ba33_iszero(const uint8_t *a)
{
    int i;
    for (i = 0; i < 33; i++) if (a[i]) return 0;
    return 1;
}

/* ba_modinv_ord: compute dst = a^{-1} mod (2^KEYBITS-1) via binary extended GCD.
   Requires gcd(a, ORD) == 1; result is undefined if gcd != 1.
   ORD = 2^256-1 is all-0xFF bytes.
   Uses 33-byte (257-bit) big-endian arrays for the Bezout coefficients to
   avoid overflow when adding ORD to make them positive. */
static void ba_modinv_ord(BitArray *dst, const BitArray *a)
{
    static const uint8_t ORD33[33] = {
        0x00,
        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
    };
    /* 257-bit big-endian unsigned arithmetic helpers (inline, avoiding recursion) */
#define ADD33(dst33, a33, b33) do { \
        uint16_t _c = 0; int _i; \
        for (_i = 32; _i >= 0; _i--) { \
            uint16_t _s = (uint16_t)(a33)[_i] + (b33)[_i] + _c; \
            (dst33)[_i] = (uint8_t)_s; _c = _s >> 8; \
        } \
    } while(0)
#define SUB33(dst33, a33, b33) do { \
        int16_t _bor = 0; int _i; \
        for (_i = 32; _i >= 0; _i--) { \
            int16_t _s = (int16_t)(a33)[_i] - (int16_t)(b33)[_i] - _bor; \
            (dst33)[_i] = (uint8_t)_s; _bor = (_s < 0) ? 1 : 0; \
        } \
    } while(0)
#define SHR1_33(arr) do { \
        int _i; \
        for (_i = 32; _i > 0; _i--) \
            (arr)[_i] = (uint8_t)(((arr)[_i] >> 1) | ((arr)[_i-1] << 7)); \
        (arr)[0] >>= 1; \
    } while(0)
#define IS_ODD33(arr)  ((arr)[32] & 1u)

    /* non-macro helpers for CMP33 and IS_ZERO33 to avoid GNU statement-expr */
#define CMP33(a33, b33) _ba33_cmp(a33, b33)
#define IS_ZERO33(arr)  _ba33_iszero(arr)


    /* u, v: 33-byte big-endian integers (u = a, v = ORD) */
    uint8_t u[33], v[33], x1[33], x2[33], tmp[33];
    int i;

    /* u = a (zero-extend to 33 bytes) */
    u[0] = 0;
    memcpy(u + 1, a->b, KEYBYTES);
    /* v = ORD */
    memcpy(v, ORD33, 33);
    /* x1 = 1, x2 = 0 */
    memset(x1, 0, 33); x1[32] = 1;
    memset(x2, 0, 33);

    /* Binary extended GCD: invariant a*x1 ≡ u (mod ORD), a*x2 ≡ v (mod ORD) */
    for (i = 0; i < 2 * KEYBITS + 64; i++) {
        if (IS_ZERO33(u)) break;

        if (!IS_ODD33(u)) {
            SHR1_33(u);
            if (IS_ODD33(x1)) { ADD33(tmp, x1, ORD33); memcpy(x1, tmp, 33); }
            SHR1_33(x1);
            continue;
        }
        if (!IS_ODD33(v)) {
            SHR1_33(v);
            if (IS_ODD33(x2)) { ADD33(tmp, x2, ORD33); memcpy(x2, tmp, 33); }
            SHR1_33(x2);
            continue;
        }
        if (CMP33(u, v) >= 0) {
            SUB33(u, u, v);
            /* x1 = (x1 - x2) mod ORD: if x1 < x2, add ORD first */
            if (CMP33(x1, x2) < 0) { ADD33(tmp, x1, ORD33); memcpy(x1, tmp, 33); }
            SUB33(x1, x1, x2);
        } else {
            SUB33(v, v, u);
            if (CMP33(x2, x1) < 0) { ADD33(tmp, x2, ORD33); memcpy(x2, tmp, 33); }
            SUB33(x2, x2, x1);
        }
    }
    /* At exit: if u != 0, gcd was found via u; coefficient is x1.
       Otherwise v == gcd (should be 1) and x2 is the inverse. */
    if (!IS_ZERO33(u))
        memcpy(dst->b, u + 1, KEYBYTES);  /* fallback: shouldn't happen if gcd==1 */
    else
        memcpy(dst->b, x2 + 1, KEYBYTES);

    /* Reduce mod ORD: if result is all-0xFF (== ORD), set to 0
       (ORD ≡ 0 mod ORD; this can't be a valid inverse of any element != 0) */
    { int all_ff = 1;
      for (i = 0; i < KEYBYTES; i++) all_ff &= (dst->b[i] == 0xFF);
      if (all_ff) memset(dst->b, 0, KEYBYTES);
    }

#undef ADD33
#undef SUB33
#undef SHR1_33
#undef CMP33
#undef IS_ZERO33
#undef IS_ODD33
}

/* oprf_hash_to_field: HFSCX-256(data) → non-zero element of GF(2^KEYBITS)*. */
static void oprf_hash_to_field(BitArray *dst, const uint8_t *data, size_t dlen)
{
    hfscx_256(data, dlen, NULL, dst->b);
    if (ba_is_zero(dst))
        dst->b[KEYBYTES - 1] = 1;   /* map 0 → 1 (negligible probability) */
}

/* oprf_keygen: fill key with a random element of [2, 2^KEYBITS-2].
   urnd must be an open handle to /dev/urandom (or equivalent). */
static void oprf_keygen(BitArray *key, FILE *urnd)
{
    do { ba_rand(key, urnd); } while (ba_is_zero(key) || ba_cmp256(key, &ONE_BA) == 0);
}

/* oprf_blind: client step — hash x and blind with random scalar r.
   Outputs r (blinding scalar, keep secret) and alpha = H(x)^r.
   gcd(r, ORD) == 1 is ensured by verifying r * r^{-1} == 1 mod ORD and retrying.
   ORD = 2^256-1 factors include 3, 5, 17, 257, 641 — ~50% of random values are coprime.
   Expected retries: ~2 attempts on average. */
static void oprf_blind(const uint8_t *x, size_t xlen,
                       BitArray *r_out, BitArray *alpha_out, FILE *urnd)
{
    BitArray hx, r_inv, check;
    oprf_hash_to_field(&hx, x, xlen);
    do {
        ba_rand(r_out, urnd);
        if (ba_is_zero(r_out) || ba_cmp256(r_out, &ONE_BA) == 0) continue;
        /* verify gcd(r, ORD) == 1 by checking r * r^{-1} == 1 mod ORD */
        ba_modinv_ord(&r_inv, r_out);
        ba_mul_mod_ord(&check, r_out, &r_inv);
    } while (ba_cmp256(&check, &ONE_BA) != 0);
    gf_pow_ba(alpha_out, &hx, r_out);
}

/* oprf_eval: server step — compute beta = alpha^k. */
static void oprf_eval(BitArray *beta, const BitArray *alpha, const BitArray *k)
{
    gf_pow_ba(beta, alpha, k);
}

/* oprf_unblind: client step — recover F(k,x) = beta^{r^{-1} mod ORD}. */
static void oprf_unblind(BitArray *F, const BitArray *beta, const BitArray *r)
{
    BitArray r_inv;
    ba_modinv_ord(&r_inv, r);
    gf_pow_ba(F, beta, &r_inv);
}

/* oprf_direct: direct PRF evaluation F(k, x) = H(x)^k (server-only, not oblivious). */
static void oprf_direct(BitArray *F, const uint8_t *x, size_t xlen, const BitArray *k)
{
    BitArray hx;
    oprf_hash_to_field(&hx, x, xlen);
    gf_pow_ba(F, &hx, k);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * aPAKE: augmented PAKE using HKEX-RNL + ZKBoo (NL-FSCX) + OPRF  (TODO #80)
 *
 * Registration:
 *   F       = oprf_direct(password, oprf_key)
 *   zkp_A   = lower 32 bits of hfscx_256(F.b || "ZKP-A")
 *   B       = random 32-bit integer
 *   y       = zkp_nl_f1(zkp_A, B, 32)           [one NL-FSCX v1 step at n=32]
 *   record  = { salt[32], B, y }                 [stored on server; no password]
 *
 * Login (both-sides demo):
 *   Recompute zkp_A from password; fast-reject if nl_fscx_v1(zkp_A, B) != y
 *   Ephemeral HKEX-RNL key agreement → K_raw_c, K_raw_s
 *   Client: ZKBoo proof of zkp_A bound to K_raw_c
 *   Server: ZKBoo verify using K_raw_s
 *   Session key = hfscx_256(rnl_kdf(K_raw_c) || "PAKE-SESSION-v1")
 *
 * Demo parameters: HPAKE_ZKP_N=32, HPAKE_ROUNDS=16
 *   Production: HPAKE_ROUNDS >= 219 for 128-bit soundness.
 * ───────────────────────────────────────────────────────────────────────────── */

#define HPAKE_ZKP_N    32   /* ZKBoo witness width (demo; production: 256)     */
#define HPAKE_ROUNDS   16   /* ZKBoo rounds (demo; production: >= 219)         */

typedef struct {
    uint8_t  salt[32];
    uint32_t B;
    uint32_t y;
} HpakeRecord;

/* Derive 32-bit ZKBoo witness: lower 4 bytes of hfscx_256(oprf_out || "ZKP-A"). */
static uint32_t _hpake_zkp_witness(const uint8_t oprf_out[KEYBYTES])
{
    uint8_t buf[KEYBYTES + 5], h[KEYBYTES];
    memcpy(buf, oprf_out, KEYBYTES);
    memcpy(buf + KEYBYTES, "ZKP-A", 5);
    hfscx_256(buf, sizeof buf, NULL, h);
    return ((uint32_t)h[28] << 24) | ((uint32_t)h[29] << 16)
         | ((uint32_t)h[30] <<  8) |  (uint32_t)h[31];
}

/* KDF for HKEX-RNL channel: nl_fscx_revolve_v1(ba_rnl_kdf_seed(K), K, n/4). */
static void _hpake_rnl_kdf(uint8_t out[KEYBYTES], const BitArray *K_raw)
{
    BitArray seed, sk;
    ba_rnl_kdf_seed(&seed, K_raw);
    nl_fscx_revolve_v1_ba(&sk, &seed, K_raw, KEYBITS / 4);
    memcpy(out, sk.b, KEYBYTES);
}

/* hpake_register: create a server-side record for (password, oprf_key). */
static void hpake_register(HpakeRecord *rec,
                            const uint8_t *password, size_t pwlen,
                            const BitArray *oprf_key, FILE *urnd)
{
    uint8_t b_bytes[4];
    BitArray F;
    if (fread(rec->salt, 1, 32, urnd) != 32) { fputs("urnd fail\n", stderr); exit(1); }
    oprf_direct(&F, password, pwlen, oprf_key);
    uint32_t zkp_A = _hpake_zkp_witness(F.b);
    if (fread(b_bytes, 1, 4, urnd) != 4)     { fputs("urnd fail\n", stderr); exit(1); }
    rec->B = ((uint32_t)b_bytes[0] << 24) | ((uint32_t)b_bytes[1] << 16)
           | ((uint32_t)b_bytes[2] <<  8) |  (uint32_t)b_bytes[3];
    rec->y = (uint32_t)zkp_nl_f1((uint64_t)zkp_A, (uint64_t)rec->B, HPAKE_ZKP_N);
}

/* hpake_login_demo: run both sides of the aPAKE login.
   Returns 1 and fills session_key[KEYBYTES] on success; returns 0 on wrong password. */
static int hpake_login_demo(uint8_t session_key[KEYBYTES],
                             const HpakeRecord *rec,
                             const uint8_t *password, size_t pwlen,
                             const BitArray *oprf_key, FILE *urnd)
{
    BitArray F;
    oprf_direct(&F, password, pwlen, oprf_key);
    uint32_t zkp_A = _hpake_zkp_witness(F.b);

    /* Fast reject: wrong password won't satisfy the ZKBoo statement */
    if ((uint32_t)zkp_nl_f1((uint64_t)zkp_A, (uint64_t)rec->B, HPAKE_ZKP_N) != rec->y)
        return 0;

    /* Ephemeral HKEX-RNL */
    rnl_poly_t m_base, a_rand, m_blind, s_c, C_c, s_s, C_s;
    rnl_m_poly(m_base);
    rnl_rand_poly(a_rand, urnd);
    rnl_poly_add(m_blind, m_base, a_rand);
    rnl_keygen(s_c, C_c, m_blind, urnd);
    rnl_keygen(s_s, C_s, m_blind, urnd);

    BitArray K_raw_c, K_raw_s;
    uint8_t hint[RNL_N / 8];
    rnl_agree(&K_raw_c, s_c, C_s, NULL, hint);  /* client: reconciler */
    rnl_agree(&K_raw_s, s_s, C_c, hint, NULL);  /* server: receiver  */

    /* ZKBoo: client proves knowledge of zkp_A bound to session channel */
    uint8_t auth_c[KEYBYTES + 12], auth_s[KEYBYTES + 12];
    memcpy(auth_c, K_raw_c.b, KEYBYTES);  memcpy(auth_c + KEYBYTES, "PAKE-AUTH-v1", 12);
    memcpy(auth_s, K_raw_s.b, KEYBYTES);  memcpy(auth_s + KEYBYTES, "PAKE-AUTH-v1", 12);

    ZkpNlRound *proof = zkp_nl_prove((uint64_t)zkp_A, (uint64_t)rec->B, (uint64_t)rec->y,
                                      HPAKE_ZKP_N, HPAKE_ROUNDS,
                                      auth_c, sizeof auth_c, urnd);
    int ok = zkp_nl_verify((uint64_t)rec->B, (uint64_t)rec->y,
                            HPAKE_ZKP_N, HPAKE_ROUNDS,
                            auth_s, sizeof auth_s, proof);
    zkp_nl_proof_free(proof, HPAKE_ROUNDS);
    if (!ok) return 0;

    /* Session key: hfscx_256(kdf(K_raw_c) || "PAKE-SESSION-v1") */
    uint8_t kdf_bytes[KEYBYTES], sk_in[KEYBYTES + 15];
    _hpake_rnl_kdf(kdf_bytes, &K_raw_c);
    memcpy(sk_in, kdf_bytes, KEYBYTES);
    memcpy(sk_in + KEYBYTES, "PAKE-SESSION-v1", 15);
    hfscx_256(sk_in, sizeof sk_in, NULL, session_key);
    return 1;
}

/* Generator as BitArray alias (value 3, same as GF_GEN). */
#define GF_GEN_BA GF_GEN

/* dst = (a + b) mod (2^256-1) */
static void ba_add_mod_ord(BitArray *dst, const BitArray *a, const BitArray *b)
{
    uint16_t carry = 0;
    int i, all_ff;
    for (i = KEYBYTES - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a->b[i] + (uint16_t)b->b[i] + carry;
        dst->b[i] = (uint8_t)s;
        carry = s >> 8;
    }
    if (carry) {
        /* wrapped: add 1 (because 2^256 mod (2^256-1) = 1) */
        uint16_t add1 = 1;
        for (i = KEYBYTES - 1; i >= 0; i--) {
            uint16_t s = (uint16_t)dst->b[i] + add1;
            dst->b[i] = (uint8_t)s;
            add1 = s >> 8;
            if (!add1) break;
        }
    }
    /* 2^256-1 is the identity for addition mod ord; map it to 0 */
    all_ff = 1;
    for (i = 0; i < KEYBYTES; i++) all_ff &= (dst->b[i] == 0xFF);
    if (all_ff) memset(dst->b, 0, KEYBYTES);
}

/* Aliases used by hpkst_sign */
#define _ba_mod_mul_ord ba_mul_mod_ord
#define _ba_mod_sub_ord ba_sub_mod_ord
#define _ba_mod_add_ord ba_add_mod_ord

/* ─────────────────────────────────────────────────────────────────────────────
 * 98 — HPKS-T: Threshold / Aggregate Schnorr over GF(2^n)* (TODO #98)
 *
 * n-of-n MuSig2-style key aggregation with NL-FSCX v1 challenge.
 * μ_j = HFSCX-256(L || C_j_bytes) mod ord  (rogue-key binding)
 * C_agg = Π C_j^{μ_j}
 * Sign:   R = Π R_j;  e = nl_fscx_revolve_v1(R, msg, n/4);
 *         s_j = (k_j − a_j·μ_j·e) mod ord;  s = Σ s_j mod ord
 * Verify: g^s · C_agg^e == R  (identical to single-party HPKS-NL verify)
 * ─────────────────────────────────────────────────────────────────────────── */

/* Compute μ_j = HFSCX-256(L_bytes, llen || C_j.b) mod ord, result in mu_out.
 * ord = 2^KEYBITS − 1 treated as a big-endian KEYBYTES-byte value. */
static void _hpkst_mu_coeff(const uint8_t *L_bytes, size_t llen,
                              const BitArray *C_j, uint8_t mu_out[KEYBYTES])
{
    uint8_t *buf = (uint8_t *)malloc(llen + KEYBYTES);
    if (!buf) { fprintf(stderr, "_hpkst_mu_coeff: oom\n"); exit(1); }
    memcpy(buf, L_bytes, llen);
    memcpy(buf + llen, C_j->b, KEYBYTES);
    hfscx_256(buf, llen + KEYBYTES, NULL, mu_out);
    free(buf);
    /* mu mod ord: ord = 0xFF...FF (all ones); result is already in [0,2^n-1].
     * If all-zero, set to 1. */
    int all_zero = 1;
    for (int i = 0; i < KEYBYTES; i++) if (mu_out[i]) { all_zero = 0; break; }
    if (all_zero) mu_out[KEYBYTES-1] = 1;
}

/* Compute C_agg = Π C_j^{μ_j} with key-aggregation coefficients.
 * pubkeys: array of n BitArrays.  mu_out: array of n uint8_t[KEYBYTES] (caller allocs).
 * L_bytes must be the sorted concatenation of all pubkey bytes. */
static void _hpkst_aggregate(const BitArray *pubkeys, size_t n,
                               const uint8_t *L_bytes, size_t llen,
                               uint8_t (*mu_out)[KEYBYTES],
                               BitArray *C_agg)
{
    memset(C_agg->b, 0, KEYBYTES);
    C_agg->b[KEYBYTES-1] = 1;  /* start at 1 */
    for (size_t j = 0; j < n; j++) {
        _hpkst_mu_coeff(L_bytes, llen, &pubkeys[j], mu_out[j]);
        BitArray mu_ba, Cj_pow;
        memcpy(mu_ba.b, mu_out[j], KEYBYTES);
        gf_pow_ba(&Cj_pow, &pubkeys[j], &mu_ba);
        gf_mul_ba(C_agg, C_agg, &Cj_pow);
    }
}

/* Build sorted L_bytes from pubkeys array. Caller frees result. */
static uint8_t *_hpkst_build_L(const BitArray *pubkeys, size_t n, size_t *llen_out)
{
    /* collect and sort KEYBYTES-byte representations */
    uint8_t (*sorted)[KEYBYTES] = (uint8_t (*)[KEYBYTES])malloc(n * KEYBYTES);
    if (!sorted) { fprintf(stderr, "_hpkst_build_L: oom\n"); exit(1); }
    for (size_t j = 0; j < n; j++) memcpy(sorted[j], pubkeys[j].b, KEYBYTES);
    /* bubble sort (small n) */
    for (size_t i = 0; i < n; i++)
        for (size_t j = i+1; j < n; j++)
            if (memcmp(sorted[i], sorted[j], KEYBYTES) > 0) {
                uint8_t tmp[KEYBYTES];
                memcpy(tmp, sorted[i], KEYBYTES);
                memcpy(sorted[i], sorted[j], KEYBYTES);
                memcpy(sorted[j], tmp, KEYBYTES);
            }
    *llen_out = n * KEYBYTES;
    return (uint8_t *)sorted;
}

/* HPKS-T n-of-n sign.
 * secrets[n]: private scalars (BitArray, each < ord).
 * pubkeys[n]: corresponding public keys C_j = g^{a_j}.
 * msg:        message BitArray (NL-FSCX v1 challenge input).
 * Outputs: C_agg, R, s.
 * Caller must supply per-signer random nonces in nonces[n] (fresh BitArrays).
 * Pass NULL for nonces to generate internally from /dev/urandom. */
static void hpkst_sign(const BitArray *secrets, const BitArray *pubkeys, size_t n,
                        const BitArray *msg, const BitArray *nonces_in,
                        BitArray *C_agg_out, BitArray *R_out, BitArray *s_out,
                        FILE *urnd)
{
    size_t llen;
    uint8_t *L_bytes = _hpkst_build_L(pubkeys, n, &llen);
    uint8_t (*mu)[KEYBYTES] = (uint8_t (*)[KEYBYTES])malloc(n * KEYBYTES);
    if (!mu) { fprintf(stderr, "hpkst_sign: oom\n"); exit(1); }

    _hpkst_aggregate(pubkeys, n, L_bytes, llen, mu, C_agg_out);

    /* Per-signer nonces */
    BitArray *nonces = (BitArray *)malloc(n * sizeof(BitArray));
    if (!nonces) { fprintf(stderr, "hpkst_sign: oom\n"); exit(1); }
    for (size_t j = 0; j < n; j++) {
        if (nonces_in) nonces[j] = nonces_in[j];
        else           ba_rand(&nonces[j], urnd);
    }

    /* R = Π g^{k_j} */
    memset(R_out->b, 0, KEYBYTES); R_out->b[KEYBYTES-1] = 1;
    for (size_t j = 0; j < n; j++) {
        BitArray R_j;
        gf_pow_ba(&R_j, &GF_GEN_BA, &nonces[j]);
        gf_mul_ba(R_out, R_out, &R_j);
    }

    /* e = nl_fscx_revolve_v1(R, msg, I_VALUE) */
    BitArray e;
    nl_fscx_revolve_v1_ba(&e, R_out, msg, I_VALUE);

    /* s = Σ (k_j − a_j·μ_j·e) mod ord */
    /* Use 512-bit intermediate to avoid overflow: keep mod ord per step */
    uint64_t s_acc[KEYBYTES/8] = {0};  /* simple big-int accumulator */
    /* For simplicity use BitArray arithmetic mod ord (already defined): */
    memset(s_out->b, 0, KEYBYTES);
    for (size_t j = 0; j < n; j++) {
        /* mu_j as BitArray */
        BitArray mu_ba;
        memcpy(mu_ba.b, mu[j], KEYBYTES);
        /* a_j * mu_j mod ord (integer multiply mod 2^n-1) */
        /* Use gf_mul for GF multiply? No — this is integer multiply mod ord. */
        /* Compute via Python-style: (a_j.uint * mu_j.uint * e.uint) mod ord */
        /* We need big-integer multiply mod ord.  Use a helper. */
        /* Strategy: compute via ba_mod_mul helper below. */
        /* s_j = (k_j - a_j*mu_j*e) mod ord */
        /* Since all values fit in KEYBYTES bytes and ord = 2^n-1, we implement
         * the modular multiply as:  a * b mod (2^n-1)  via the identity
         * a * b mod (2^n-1) = ((a*b) >> n) + (a*b & (2^n-1))  iterated. */
        /* For correctness we use __int128 for n=32; for n=256 we need a
         * proper big-int.  Use OpenSSL BN or manual implementation.
         * Since herradura.h has no OpenSSL dep, implement a simple 256-bit
         * multiply-mod-ord using the schoolbook method. */

        /* ---- ba_mod_mul: multiply two KEYBITS-wide values mod 2^KEYBITS-1 ---- */
        /* result = (a * b) mod (2^n - 1) */
        /* We compute via repeated doubling and reduction. */
        /* a_j * mu_ba mod ord */
        BitArray am;
        _ba_mod_mul_ord(&am, &secrets[j], &mu_ba);
        /* am * e mod ord */
        BitArray ame;
        _ba_mod_mul_ord(&ame, &am, &e);
        /* s_j = (k_j - ame) mod ord */
        BitArray s_j;
        _ba_mod_sub_ord(&s_j, &nonces[j], &ame);
        /* s_out += s_j mod ord */
        BitArray tmp;
        _ba_mod_add_ord(&tmp, s_out, &s_j);
        *s_out = tmp;
    }

    free(nonces);
    free(mu);
    free(L_bytes);
}

/* Verify a threshold HPKS-NL signature — identical to single-party verify. */
static int hpkst_verify(const BitArray *C_agg, const BitArray *R,
                         const BitArray *s, const BitArray *msg)
{
    BitArray e, gs, Ce, lhs;
    nl_fscx_revolve_v1_ba(&e, R, msg, I_VALUE);
    gf_pow_ba(&gs, &GF_GEN_BA, s);
    gf_pow_ba(&Ce, C_agg, &e);
    gf_mul_ba(&lhs, &gs, &Ce);
    return ba_equal(&lhs, R);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * 97 — HPKS-WOTS-F / HPKS-XMSS-F — Hash-based signatures (TODO #97/#102)
 *
 * Hash chain step: h(x) = nl_fscx_revolve_v1(ROL(x, n/8), x, n/4)
 * Winternitz w=16: ℓ_msg=64 nibbles, ℓ_cs=3, ℓ=67 total chains.
 * XMSS: 2^H Merkle leaves; leaf = haccum_leaf(pk_0 || … || pk_{ℓ-1}).
 * ─────────────────────────────────────────────────────────────────────────── */

#define WOTS_W     16
#define WOTS_LOG2W  4
#define WOTS_L1    64   /* KEYBITS / log2(W) = 256/4 */
#define WOTS_L2     3   /* checksum digits in base-16 */
#define WOTS_L     67   /* total chain count */

/* Single hash-chain step: h(x) = nl_fscx_revolve_v1(ROL(x, n/8), x, n/4). */
static inline void _wots_h_ba(BitArray *out, const BitArray *x)
{
    BitArray rotx;
    ba_rol_k(&rotx, x, KEYBITS / 8);
    nl_fscx_revolve_v1_ba(out, &rotx, x, KEYBITS / 4);
}

/* Apply _wots_h_ba `steps` times in-place. */
static inline void _wots_chain_ba(BitArray *x, int steps)
{
    BitArray tmp;
    for (int i = 0; i < steps; i++) { _wots_h_ba(&tmp, x); *x = tmp; }
}

/* Derive WOTS SK chain seed from master_seed (32 bytes), leaf_idx, chain_idx. */
static inline void _wots_leaf_seed(BitArray *out,
                                   const uint8_t master_seed[KEYBYTES],
                                   uint32_t leaf_idx, uint16_t chain_idx)
{
    uint8_t buf[KEYBYTES + 6], h[KEYBYTES];
    memcpy(buf, master_seed, KEYBYTES);
    buf[KEYBYTES+0] = (leaf_idx >> 24) & 0xFF;
    buf[KEYBYTES+1] = (leaf_idx >> 16) & 0xFF;
    buf[KEYBYTES+2] = (leaf_idx >>  8) & 0xFF;
    buf[KEYBYTES+3] =  leaf_idx        & 0xFF;
    buf[KEYBYTES+4] = (chain_idx >> 8) & 0xFF;
    buf[KEYBYTES+5] =  chain_idx       & 0xFF;
    hfscx_256(buf, sizeof buf, NULL, h);
    memcpy(out->b, h, KEYBYTES);
}

/* WOTS-F keygen: fills sk[WOTS_L] and pk[WOTS_L]. */
static inline void hpks_wots_keygen(BitArray sk[WOTS_L], BitArray pk[WOTS_L],
                                    const uint8_t master_seed[KEYBYTES],
                                    uint32_t leaf_idx)
{
    for (int i = 0; i < WOTS_L; i++) {
        _wots_leaf_seed(&sk[i], master_seed, leaf_idx, (uint16_t)i);
        pk[i] = sk[i];
        _wots_chain_ba(&pk[i], WOTS_W - 1);
    }
}

/* Encode 32-byte msg_hash as WOTS_L base-16 digits with checksum. */
static inline void _wots_msg_to_digits(int digits[WOTS_L],
                                        const uint8_t msg_hash[KEYBYTES])
{
    for (int i = 0; i < WOTS_L1; i++)
        digits[i] = (msg_hash[i/2] >> (4 * (1 - (i%2)))) & 0xF;
    int cs = 0;
    for (int i = 0; i < WOTS_L1; i++) cs += (WOTS_W - 1 - digits[i]);
    for (int i = 0; i < WOTS_L2; i++)
        digits[WOTS_L1 + i] = (cs >> (4 * (WOTS_L2 - 1 - i))) & 0xF;
}

/* WOTS-F sign: sig[i] = h^(w-1-d_i)(sk[i]). */
static inline void hpks_wots_sign(BitArray sig[WOTS_L],
                                   const uint8_t msg[/* any */], size_t mlen,
                                   const uint8_t master_seed[KEYBYTES],
                                   uint32_t leaf_idx)
{
    uint8_t msg_hash[KEYBYTES];
    hfscx_256(msg, mlen, NULL, msg_hash);
    int digits[WOTS_L];
    _wots_msg_to_digits(digits, msg_hash);
    BitArray sk[WOTS_L], pk_unused[WOTS_L];
    hpks_wots_keygen(sk, pk_unused, master_seed, leaf_idx);
    for (int i = 0; i < WOTS_L; i++) {
        sig[i] = sk[i];
        _wots_chain_ba(&sig[i], WOTS_W - 1 - digits[i]);
    }
}

/* Recover WOTS pk from (msg, sig): pk_i = h^{d_i}(sig_i). */
static inline void hpks_wots_recover_pk(BitArray recovered[WOTS_L],
                                         const uint8_t msg[], size_t mlen,
                                         const BitArray sig[WOTS_L])
{
    uint8_t msg_hash[KEYBYTES];
    hfscx_256(msg, mlen, NULL, msg_hash);
    int digits[WOTS_L];
    _wots_msg_to_digits(digits, msg_hash);
    for (int i = 0; i < WOTS_L; i++) {
        recovered[i] = sig[i];
        _wots_chain_ba(&recovered[i], digits[i]);
    }
}

/* WOTS-F verify: 1 if h^{d_i}(sig_i) == pk_i for all i. */
static inline int hpks_wots_verify(const uint8_t msg[], size_t mlen,
                                    const BitArray sig[WOTS_L],
                                    const BitArray pk[WOTS_L])
{
    BitArray recovered[WOTS_L];
    hpks_wots_recover_pk(recovered, msg, mlen, sig);
    for (int i = 0; i < WOTS_L; i++)
        if (!ba_equal(&recovered[i], &pk[i])) return 0;
    return 1;
}

/* Serialise WOTS pk to byte array (WOTS_L * KEYBYTES bytes). */
static inline void _wots_pk_bytes(uint8_t *out, const BitArray pk[WOTS_L])
{
    for (int i = 0; i < WOTS_L; i++)
        memcpy(out + i * KEYBYTES, pk[i].b, KEYBYTES);
}

/* HPKS-XMSS-F signature. auth_path is a flat malloc'd buffer: depth*KEYBYTES. */
typedef struct {
    uint32_t  leaf_idx;
    BitArray  wots_sig[WOTS_L];
    uint8_t  *auth_path;   /* depth * KEYBYTES contiguous sibling hashes */
    int       depth;
} HpksXmssSig;

/* XMSS-F keygen: builds 2^h leaf hashes from master_seed.
 * Outputs: root[KEYBYTES], flat_leaves (2^h * KEYBYTES, caller frees), num_leaves.
 * flat_leaves is used as the contiguous array required by haccum_prove/verify. */
static void hpks_xmss_keygen(uint8_t root[KEYBYTES],
                              uint8_t **flat_leaves_out, size_t *num_leaves_out,
                              const uint8_t master_seed[KEYBYTES], int h)
{
    size_t num = (size_t)1 << h;
    uint8_t (*flat)[KEYBYTES] = (uint8_t (*)[KEYBYTES])malloc(num * KEYBYTES);
    if (!flat) { fprintf(stderr, "hpks_xmss_keygen: oom\n"); exit(1); }
    for (size_t idx = 0; idx < num; idx++) {
        BitArray sk[WOTS_L], pk[WOTS_L];
        hpks_wots_keygen(sk, pk, master_seed, (uint32_t)idx);
        uint8_t pk_bytes[WOTS_L * KEYBYTES];
        _wots_pk_bytes(pk_bytes, pk);
        haccum_leaf(pk_bytes, WOTS_L * KEYBYTES, flat[idx]);
    }
    haccum_root(flat, num, root);
    *flat_leaves_out = (uint8_t *)flat;
    *num_leaves_out  = num;
}

/* XMSS-F sign: fills sig. sig->auth_path is malloc'd inside (caller frees via
 * hpks_xmss_sig_free). flat_leaves is the array returned by hpks_xmss_keygen. */
static void hpks_xmss_sign(HpksXmssSig *sig,
                             const uint8_t msg[], size_t mlen,
                             const uint8_t master_seed[KEYBYTES],
                             const uint8_t *flat_leaves, size_t num_leaves,
                             uint32_t leaf_idx)
{
    sig->leaf_idx  = leaf_idx;
    hpks_wots_sign(sig->wots_sig, msg, mlen, master_seed, leaf_idx);
    int depth;
    sig->auth_path = haccum_prove((const uint8_t (*)[KEYBYTES])flat_leaves,
                                   num_leaves, (size_t)leaf_idx, &depth);
    sig->depth     = depth;
}

/* Free auth_path inside an HpksXmssSig. */
static inline void hpks_xmss_sig_free(HpksXmssSig *sig)
{
    free(sig->auth_path);
    sig->auth_path = NULL;
}

/* XMSS-F verify: 1 if valid. */
static int hpks_xmss_verify(const uint8_t msg[], size_t mlen,
                              const HpksXmssSig *sig,
                              const uint8_t root[KEYBYTES])
{
    BitArray recovered[WOTS_L];
    hpks_wots_recover_pk(recovered, msg, mlen, sig->wots_sig);
    uint8_t pk_bytes[WOTS_L * KEYBYTES];
    _wots_pk_bytes(pk_bytes, recovered);
    uint8_t leaf_hash[KEYBYTES];
    haccum_leaf(pk_bytes, WOTS_L * KEYBYTES, leaf_hash);
    return haccum_verify(root, leaf_hash, sig->auth_path, sig->depth,
                         (size_t)sig->leaf_idx);
}

#endif /* HERRADURA_H */
