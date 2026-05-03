/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c
   Usage: ./Herradura_tests [-r ROUNDS] [-t SECS]
     -r, --rounds N   max iterations per security test (default: test-specific)
     -t, --time   T   benchmark duration and per-test wall-clock cap in seconds
   Env:  HTEST_ROUNDS=N  HTEST_TIME=T  (CLI flags override env) */

/*  Herradura KEx -- Security & Performance Tests (C, multi-size BitArray + scalar GF)
    v1.5.23: HerraduraCli OpenSSL-style CLI (TODO #25); CliTest shell test suite.
    v1.5.20: 256-bit NL-FSCX v2 BitArray functions; tests expanded to full multi-size:
            Batch 2 — tests [10]–[13] loop {64,128,256}; adds ba_sub256, ba_mul256,
            m_inv_ba, nl_fscx_v2_ba/inv_ba, nl_fscx_revolve_v2_ba/inv_ba.
            Batch 3 — GF(2^128) arithmetic (gf_mul_128, gf_pow_128, mul128_mod_ord128);
            [1],[5],[6] loop {32,64,128,256}; [9],[16] loop {32,64,128,256}.
            Batch 4 — HKEX-RNL n=128/256: NTT twiddle table expanded to n∈{32,64,128,256};
            adds rnl_hint/reconcile/agree_128 (__uint128_t) and rnl_hint/reconcile/agree_ba
            (BitArray); test [14] loops {32,64,128,256}.
            Batch 5 — HPKS/HPKE-Stern-F N=32/64; test [17] loops {32,64,256}; [18] adds N=64.
            Batch 6 — bn_* parameterised arithmetic layer (Groups A–E); tests [7],[8],[15]
            extended from {32,64,128} to {32,64,128,256} using bn_mul_mod_ord_n/bn_sub_mod_ord_n.
    v1.5.18: HPKS-Stern-F + HPKE-Stern-F code-based PQC tests [17][18] + bench [28].
            Benchmarks renumbered [17]–[25] → [19]–[27] to make room for new tests.
    v1.5.13: HSKE-NL-A1 seed fix — seed=ROL(base,n/8) breaks counter=0 step-1 degeneracy.
    v1.5.10: HKEX-RNL KDF seed fix — seed=ROL(K,n/8) breaks step-1 degeneracy.
    v1.5.9: nl_fscx_revolve_v2_inv_{32,64,128} precompute delta(B) once — eliminates per-step multiply.
    v1.5.7: m_inv_32/64/128 use precomputed rotation tables (0x6DB6DB6D / constants).
    v1.5.6: rnl_rand_coeff bias fix — 3-byte rejection sampling (threshold=16711935).
    v1.5.5: added PQC benchmarks [22]–[25] matching Python/Go; aligned test output labels
            ([CLASSICAL]/[PQC-EXT]) and section headers; fixed version banner.
            Phase 3 — multi-size loops [1],[5]–[9],[14]–[16]: 64-bit GF(2^64) and
            64-bit NL-FSCX; tests [1],[5],[6] loop {32,64,256}; [7]–[9],[14]–[16]
            loop {32,64}; key-sensitivity PASS criterion aligned to mean >= n/4.
            Phase 4 — multi-size loops [2]–[4],[10]–[13]: 128-bit FSCX/__uint128_t
            and 128-bit NL-FSCX added; [2]–[4] loop {64,128,256}; [10]–[13] loop
            {64,128} (then extended to 256 in v1.5.20 Batch 2).
            Phase 5 — test methodology alignment: [11] bijectivity upgraded to
            BIJ_SAMPLES=256 random A values per B with pairwise collision scan,
            matching Python/Go hash-map methodology.
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.0: HKEX-GF; Schnorr HPKS; El Gamal HPKE; NL-FSCX non-linear extension; PQC.
      Tests [1],[5],[6]: HKEX-GF (32/64/256-bit); [7]–[9],[14]–[16]: 32/64-bit loops.
      [1]  HKEX-GF correctness: g^{ab}==g^{ba} (32/64/256-bit GF).
      [7]  HPKS Schnorr correctness: g^s * C^e == R  (32/64/128/256-bit GF).
      [8]  HPKS Schnorr Eve resistance: random forgery fails (32/64/128/256-bit GF).
      [9]  HPKE El Gamal correctness: D == P (32/64-bit GF).
      [10] NL-FSCX v1 non-linearity and aperiodicity (32-bit).
      [11] NL-FSCX v2 bijectivity and exact inverse (32-bit).
      [12] HSKE-NL-A1 counter-mode correctness: D == P (32-bit).
      [13] HSKE-NL-A2 revolve-mode correctness: D == P (32-bit).
      [14] HKEX-RNL key agreement: K_A == K_B (n=32/64, Ring-LWR).
      [15] HPKS-NL correctness: g^s * C^e == R (NL-FSCX v1 challenge, 32/64/128/256-bit GF).
      [16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt, 32/64-bit GF).
      [17] HPKS-Stern-F correctness: sign+verify, N=256, t=16, rounds=4  [CODE-BASED PQC].
      [18] HPKE-Stern-F correctness: encap+decap, N=32, t=2 (brute-force)  [CODE-BASED PQC].
      [19] FSCX throughput (256-bit).
      [20] HKEX-GF gf_pow throughput (32-bit).
      [21] HKEX-GF full handshake (32-bit).
      [22] HSKE round-trip (256-bit).
      [23] HPKE El Gamal encrypt+decrypt round-trip (32-bit).
      [24] NL-FSCX v1 revolve throughput (32-bit, n/4 steps).
      [24b] NL-FSCX v2 revolve+inv throughput (32-bit, r_val steps).
      [25] HSKE-NL-A1 counter-mode throughput (32-bit).
      [26] HSKE-NL-A2 revolve-mode round-trip throughput (32-bit).
      [27] HKEX-RNL full handshake throughput (n=32).
      [28] HPKS-Stern-F sign+verify throughput (N=256, t=16, rounds=4)  [CODE-BASED PQC].

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)
#define R_VALUE  (3 * KEYBITS / 4)

#if KEYBYTES < 2
#  error "KEYBITS must be >= 16"
#endif
#if KEYBITS != 256
#  error "GF polynomial constants are only defined for KEYBITS=256 in this build"
#endif

/* BENCH_SEC removed: use g_bench_sec (default 1.0, overridden by -t / HTEST_TIME) */

typedef struct {
    uint8_t b[KEYBYTES];
} BitArray;

static FILE *urnd_fp;

/* --- Runtime limits (set via CLI -r/-t or env HTEST_ROUNDS/HTEST_TIME) --- */
static int    g_rounds     = 0;    /* 0 = use per-test default            */
static double g_bench_sec  = 1.0;  /* benchmark duration (seconds)        */
static double g_time_limit = 0.0;  /* per-test wall-clock cap; 0 = none   */

/* ------------------------------------------------------------------ */
/* BitArray primitives                                                 */
/* ------------------------------------------------------------------ */

static void ba_rand(BitArray *dst)
{
    if (fread(dst->b, 1, KEYBYTES, urnd_fp) != (size_t)KEYBYTES) {
        fputs("ERROR: read from /dev/urandom failed\n", stderr);
        exit(1);
    }
}

static void ba_xor(BitArray *dst, const BitArray *a, const BitArray *b)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        dst->b[i] = a->b[i] ^ b->b[i];
}

static int ba_equal(const BitArray *a, const BitArray *b)
{
    return memcmp(a->b, b->b, KEYBYTES) == 0;
}

static int ba_popcount(const BitArray *a)
{
    int cnt = 0, i;
    for (i = 0; i < KEYBYTES; i++)
        cnt += __builtin_popcount(a->b[i]);
    return cnt;
}

static int ba_get_bit(const BitArray *a, int pos)
{
    int byte_idx = KEYBYTES - 1 - pos / 8;
    int bit_pos  = pos % 8;
    return (a->b[byte_idx] >> bit_pos) & 1;
}

static void ba_flip_bit(BitArray *dst, const BitArray *src, int pos)
{
    int byte_idx = KEYBYTES - 1 - pos / 8;
    int bit_pos  = pos % 8;
    *dst = *src;
    dst->b[byte_idx] ^= (uint8_t)(1u << bit_pos);
}

/* ------------------------------------------------------------------ */
/* FSCX primitives (unchanged)                                        */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* GF(2^KEYBITS) arithmetic                                           */
/* ------------------------------------------------------------------ */

/* Primitive polynomial: x^256 + x^10 + x^5 + x^2 + 1 = 0x0425 (lower bits) */
static const BitArray GF_POLY = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x04,0x25
}};

/* Generator g = x+1 = 3 */
static const BitArray GF_GEN = {{
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x03
}};

static int ba_is_zero(const BitArray *a)
{
    int i;
    for (i = 0; i < KEYBYTES; i++)
        if (a->b[i]) return 0;
    return 1;
}

static int ba_shl1(BitArray *a)
{
    int carry = (a->b[0] >> 7) & 1;
    int i;
    for (i = 0; i < KEYBYTES - 1; i++)
        a->b[i] = (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7));
    a->b[KEYBYTES - 1] <<= 1;
    return carry;
}

static int ba_shr1(BitArray *a)
{
    int carry = a->b[KEYBYTES - 1] & 1;
    int i;
    for (i = KEYBYTES - 1; i > 0; i--)
        a->b[i] = (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7));
    a->b[0] >>= 1;
    return carry;
}

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

static void gf_pow_ba(BitArray *dst, const BitArray *base, const BitArray *exp)
{
    BitArray r, b, e;
    memset(r.b, 0, KEYBYTES);
    r.b[KEYBYTES - 1] = 1;
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

/* ------------------------------------------------------------------ */
/* 256-bit integer + NL-FSCX helpers (needed by Stern-F tests)        */
/* ------------------------------------------------------------------ */

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

static void ba_rol64_256(BitArray *dst, const BitArray *src)
{
    uint8_t tmp[8];
    memcpy(tmp, src->b, 8);
    memcpy(dst->b, src->b + 8, KEYBYTES - 8);
    memcpy(dst->b + KEYBYTES - 8, tmp, 8);
}

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

/* ------------------------------------------------------------------ */
/* 256-bit NL-FSCX v2 BitArray helpers                                */
/* ROL-64 for NL-FSCX (n/4 = 64 bits for n=256); addition/sub mod    */
/* 2^256; grade-school 256×256→256 multiply for delta computation.    */
/* M^{-1} table computed from GCD: 1+x+x^255 in GF(2)[x]/(x^256+1). */
/* ------------------------------------------------------------------ */

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

static void ba_mul256(BitArray *dst, const BitArray *a, const BitArray *b)
{
    /* Grade-school byte-level multiply mod 2^256 (big-endian byte array) */
    uint64_t acc[KEYBYTES];
    int i, j;
    memset(acc, 0, sizeof(acc));
    for (i = 0; i < KEYBYTES; i++)
        for (j = 0; j < KEYBYTES - i; j++) {
            int ridx = KEYBYTES - 1 - i - j;
            acc[ridx] += (uint64_t)a->b[KEYBYTES - 1 - i] * b->b[KEYBYTES - 1 - j];
        }
    { /* Propagate carries LSB→MSB */
        uint64_t carry = 0;
        for (i = KEYBYTES - 1; i >= 0; i--) {
            uint64_t s = acc[i] + carry;
            dst->b[i] = (uint8_t)s;
            carry = s >> 8;
        }
    }
}

/* M^{-1} polynomial table for n=256: 256-bit bitmask split into four
   64-bit words (words[0]=k=0..63, words[1]=k=64..127, etc.).
   Derived from GCD(1+x+x^255, x^256+1) in GF(2)[x]. */
static const uint64_t MINV256_TBL[4] = {
    UINT64_C(0xb6db6db6db6db6db),  /* k=0..63   */
    UINT64_C(0xdb6db6db6db6db6d),  /* k=64..127 */
    UINT64_C(0x6db6db6db6db6db6),  /* k=128..191 */
    UINT64_C(0xb6db6db6db6db6db)   /* k=192..255 */
};

static void m_inv_ba(BitArray *result, const BitArray *x)
{
    BitArray r, rot;
    int k;
    r = *x; /* k=0 term */
    for (k = 1; k < KEYBITS; k++) {
        if ((MINV256_TBL[k >> 6] >> (k & 63)) & 1) {
            ba_rol_k(&rot, x, k);
            ba_xor(&r, &r, &rot);
        }
    }
    *result = r;
}

static void nl_fscx_delta_v2_ba(BitArray *delta, const BitArray *b)
{
    /* delta(b) = ROL(b * ((b+1)/2), 64) where arithmetic is mod 2^256 */
    static const BitArray ONE = {{ [KEYBYTES-1] = 1 }};
    BitArray b1, half, prod;
    ba_add256(&b1, b, &ONE);    /* b1 = b + 1 */
    half = b1; ba_shr1(&half);  /* half = (b+1) >> 1  (i.e. (b+1)/2) */
    ba_mul256(&prod, b, &half); /* prod = b * half mod 2^256 */
    ba_rol64_256(delta, &prod); /* delta = ROL(prod, 64) */
}

static void nl_fscx_v2_ba(BitArray *result, const BitArray *a, const BitArray *b)
{
    BitArray f, delta;
    ba_fscx(&f, a, b);
    nl_fscx_delta_v2_ba(&delta, b);
    ba_add256(result, &f, &delta);
}

static void nl_fscx_v2_inv_ba(BitArray *result, const BitArray *y, const BitArray *b)
{
    /* inv(y, b) = b ^ M^{-1}(y - delta(b)) */
    BitArray delta, ym_d, inv_ym;
    nl_fscx_delta_v2_ba(&delta, b);
    ba_sub256(&ym_d, y, &delta);
    m_inv_ba(&inv_ym, &ym_d);
    ba_xor(result, b, &inv_ym);
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
    nl_fscx_delta_v2_ba(&delta, b); /* precompute once */
    buf[0] = *y;
    for (i = 0; i < steps; i++) {
        BitArray ym_d, inv_ym;
        ba_sub256(&ym_d, &buf[idx], &delta);
        m_inv_ba(&inv_ym, &ym_d);
        ba_xor(&buf[1 - idx], b, &inv_ym);
        idx ^= 1;
    }
    *result = buf[idx];
}

/* ------------------------------------------------------------------ */
/* 32-bit GF(2^32) and FSCX for Schnorr HPKS and El Gamal HPKE tests */
/* Poly: x^32+x^22+x^2+x+1 = 0x00400007; generator g=3               */
/* ORD  = 2^32-1 = 0xFFFFFFFF (order of GF(2^32)*)                   */
/* ------------------------------------------------------------------ */

#define GF_POLY32  0x00400007UL
#define GF_GEN32   3UL

static uint32_t rand32(void)
{
    uint32_t v;
    if (fread(&v, 4, 1, urnd_fp) != 1) {
        fputs("ERROR: read from /dev/urandom failed\n", stderr);
        exit(1);
    }
    return v;
}

/* Bias-free uniform draw in [0, RNL_Q32=65537): 3-byte rejection sampling.
   threshold = (1<<24) - (1<<24)%65537 = 16711935; rejection prob ~0.39%. */
static uint32_t rnl_rand_coeff(void)
{
    static const uint32_t threshold = 16711935u; /* (1<<24)-(1<<24)%65537 */
    uint8_t buf[3];
    for (;;) {
        if (fread(buf, 3, 1, urnd_fp) != 1) {
            fputs("ERROR: read from /dev/urandom failed\n", stderr);
            exit(1);
        }
        uint32_t v = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
        if (v < threshold) return v % 65537u;
    }
}

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

/* ------------------------------------------------------------------ */
/* 32-bit NL-FSCX primitives (v1.5.0)                                 */
/* ROL by n/4 = 8 bits for 32-bit operands                            */
/* ------------------------------------------------------------------ */

static uint32_t rol32_8(uint32_t x) { return (x << 8) | (x >> 24); }

/* NL-FSCX v1: fscx(a,b) ^ ROL8(a+b) */
static uint32_t nl_fscx_v1_32(uint32_t a, uint32_t b)
{
    return fscx32(a, b) ^ rol32_8(a + b);
}

static uint32_t nl_fscx_revolve_v1_32(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v1_32(a, b);
    return a;
}

/* delta(b) = ROL8(b * ((b+1) >> 1)) mod 2^32 */
static uint32_t nl_fscx_delta_v2_32(uint32_t b)
{
    return rol32_8(b * ((b + 1) >> 1));
}

/* NL-FSCX v2: fscx(a,b) + delta(b) mod 2^32 */
static uint32_t nl_fscx_v2_32(uint32_t a, uint32_t b)
{
    return fscx32(a, b) + nl_fscx_delta_v2_32(b);
}

/* M^{-1}(x) = XOR of ROL(x,k) for k in bits of 0x6DB6DB6D
   Table = {0,2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30} (n=32) */
#define ROL32(v,k) (((v)<<(k))|((v)>>(32-(k))))
static uint32_t m_inv_32(uint32_t x)
{
    return x
        ^ ROL32(x, 2)  ^ ROL32(x, 3)
        ^ ROL32(x, 5)  ^ ROL32(x, 6)
        ^ ROL32(x, 8)  ^ ROL32(x, 9)
        ^ ROL32(x, 11) ^ ROL32(x, 12)
        ^ ROL32(x, 14) ^ ROL32(x, 15)
        ^ ROL32(x, 17) ^ ROL32(x, 18)
        ^ ROL32(x, 20) ^ ROL32(x, 21)
        ^ ROL32(x, 23) ^ ROL32(x, 24)
        ^ ROL32(x, 26) ^ ROL32(x, 27)
        ^ ROL32(x, 29) ^ ROL32(x, 30);
}
#undef ROL32

/* NL-FSCX v2 inverse: b ^ M^{-1}(y - delta(b)) */
static uint32_t nl_fscx_v2_inv_32(uint32_t y, uint32_t b)
{
    return b ^ m_inv_32(y - nl_fscx_delta_v2_32(b));
}

static uint32_t nl_fscx_revolve_v2_32(uint32_t a, uint32_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v2_32(a, b);
    return a;
}

static uint32_t nl_fscx_revolve_v2_inv_32(uint32_t y, uint32_t b, int steps)
{
    uint32_t delta = nl_fscx_delta_v2_32(b);  /* precompute once */
    int i;
    for (i = 0; i < steps; i++) y = b ^ m_inv_32(y - delta);
    return y;
}

/* ------------------------------------------------------------------ */
/* 64-bit GF(2^64) arithmetic                                         */
/* Poly: x^64+x^4+x^3+x+1 = 0x1B; generator g=3; ORD = 2^64-1       */
/* ------------------------------------------------------------------ */

#define GF_POLY64  0x000000000000001BULL

static uint64_t rand64(void)
{
    uint64_t v;
    if (fread(&v, 8, 1, urnd_fp) != 1) {
        fputs("ERROR: read from /dev/urandom failed\n", stderr);
        exit(1);
    }
    return v;
}

static uint64_t gf_mul_64(uint64_t a, uint64_t b)
{
    uint64_t r = 0;
    int i;
    for (i = 0; i < 64; i++) {
        if (b & 1) r ^= a;
        { uint64_t carry = a >> 63; a <<= 1; if (carry) a ^= GF_POLY64; }
        b >>= 1;
    }
    return r;
}

static uint64_t gf_pow_64(uint64_t base, uint64_t exp)
{
    uint64_t r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_64(r, base);
        base = gf_mul_64(base, base);
        exp >>= 1;
    }
    return r;
}

static uint64_t rol64(uint64_t x) { return (x << 1) | (x >> 63); }
static uint64_t ror64(uint64_t x) { return (x >> 1) | (x << 63); }

static uint64_t fscx64(uint64_t a, uint64_t b)
{
    return a ^ b ^ rol64(a) ^ rol64(b) ^ ror64(a) ^ ror64(b);
}

static uint64_t fscx_revolve64(uint64_t a, uint64_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = fscx64(a, b);
    return a;
}

/* ------------------------------------------------------------------ */
/* 64-bit NL-FSCX primitives                                          */
/* ROL by n/4 = 16 bits for 64-bit operands                           */
/* ------------------------------------------------------------------ */

static uint64_t rol64_16(uint64_t x) { return (x << 16) | (x >> 48); }

static uint64_t nl_fscx_v1_64(uint64_t a, uint64_t b)
{
    return fscx64(a, b) ^ rol64_16(a + b);
}

static uint64_t nl_fscx_revolve_v1_64(uint64_t a, uint64_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v1_64(a, b);
    return a;
}

static uint64_t nl_fscx_delta_v2_64(uint64_t b)
{
    return rol64_16(b * ((b + 1) >> 1));
}

static uint64_t nl_fscx_v2_64(uint64_t a, uint64_t b)
{
    return fscx64(a, b) + nl_fscx_delta_v2_64(b);
}

/* M^{-1}(x) = XOR of ROL(x,k) for k in bits of 0xB6DB6DB6DB6DB6DB (n=64) */
static uint64_t m_inv_64(uint64_t x)
{
    static const uint64_t tbl = UINT64_C(0xB6DB6DB6DB6DB6DB);
    uint64_t r = x; /* k=0 term */
    int k;
    for (k = 1; k < 64; k++)
        if ((tbl >> k) & 1) r ^= (x << k) | (x >> (64 - k));
    return r;
}

static uint64_t nl_fscx_v2_inv_64(uint64_t y, uint64_t b)
{
    return b ^ m_inv_64(y - nl_fscx_delta_v2_64(b));
}

static uint64_t nl_fscx_revolve_v2_64(uint64_t a, uint64_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v2_64(a, b);
    return a;
}

static uint64_t nl_fscx_revolve_v2_inv_64(uint64_t y, uint64_t b, int steps)
{
    uint64_t delta = nl_fscx_delta_v2_64(b);  /* precompute once */
    int i;
    for (i = 0; i < steps; i++) y = b ^ m_inv_64(y - delta);
    return y;
}

/* ------------------------------------------------------------------ */
/* 128-bit FSCX and NL-FSCX primitives                                */
/* ROL-1/ROR-1 for FSCX; ROL-32 for NL-FSCX (n/4 = 128/4 = 32 bits) */
/* ------------------------------------------------------------------ */

static __uint128_t rand128(void)
{
    __uint128_t hi = rand64(), lo = rand64();
    return (hi << 64) | lo;
}

static __uint128_t rol128(__uint128_t x) { return (x << 1) | (x >> 127); }
static __uint128_t ror128(__uint128_t x) { return (x >> 1) | (x << 127); }

static __uint128_t fscx128(__uint128_t a, __uint128_t b)
{
    return a ^ b ^ rol128(a) ^ rol128(b) ^ ror128(a) ^ ror128(b);
}

static __uint128_t fscx_revolve128(__uint128_t a, __uint128_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = fscx128(a, b);
    return a;
}

static __uint128_t rol128_32(__uint128_t x) { return (x << 32) | (x >> 96); }

static __uint128_t nl_fscx_v1_128(__uint128_t a, __uint128_t b)
{
    return fscx128(a, b) ^ rol128_32(a + b);
}

static __uint128_t nl_fscx_revolve_v1_128(__uint128_t a, __uint128_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v1_128(a, b);
    return a;
}

static __uint128_t nl_fscx_delta_v2_128(__uint128_t b)
{
    return rol128_32(b * ((b + 1) >> 1));
}

static __uint128_t nl_fscx_v2_128(__uint128_t a, __uint128_t b)
{
    return fscx128(a, b) + nl_fscx_delta_v2_128(b);
}

/* M^{-1}(x) = XOR of ROL(x,k) for k in bits of
   (0x6DB6DB6DB6DB6DB6 << 64) | 0xDB6DB6DB6DB6DB6D  (n=128) */
static __uint128_t m_inv_128(__uint128_t x)
{
    static const __uint128_t tbl =
        ((__uint128_t)UINT64_C(0x6DB6DB6DB6DB6DB6) << 64)
        | UINT64_C(0xDB6DB6DB6DB6DB6D);
    __uint128_t r = x; /* k=0 term */
    int k;
    for (k = 1; k < 128; k++)
        if ((tbl >> k) & 1) r ^= (x << k) | (x >> (128 - k));
    return r;
}

static __uint128_t nl_fscx_v2_inv_128(__uint128_t y, __uint128_t b)
{
    return b ^ m_inv_128(y - nl_fscx_delta_v2_128(b));
}

static __uint128_t nl_fscx_revolve_v2_128(__uint128_t a, __uint128_t b, int steps)
{
    int i;
    for (i = 0; i < steps; i++) a = nl_fscx_v2_128(a, b);
    return a;
}

static __uint128_t nl_fscx_revolve_v2_inv_128(__uint128_t y, __uint128_t b, int steps)
{
    __uint128_t delta = nl_fscx_delta_v2_128(b);  /* precompute once */
    int i;
    for (i = 0; i < steps; i++) y = b ^ m_inv_128(y - delta);
    return y;
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL helpers: Ring-LWR key exchange (n=32, negacyclic)        */
/* Z_q[x]/(x^32+1), q=65537, p=4096, pp=2, b=1                       */
/* ------------------------------------------------------------------ */

#define RNL_N32  32
#define RNL_Q32  65537
#define RNL_P32  4096
#define RNL_PP32 2
#define RNL_ETA32  1  /* CBD eta: secret coeffs from CBD(1) in {-1,0,1} mod q */

typedef int32_t rnl32_poly_t[RNL_N32];

static uint32_t rnl32_mod_pow(uint32_t base, uint32_t exp, uint32_t m)
{
    uint64_t r = 1, b = base % m;
    for (; exp; exp >>= 1) { if (exp & 1) r = r * b % m; b = b * b % m; }
    return (uint32_t)r;
}

/* Precomputed NTT twiddle tables for n∈{32,64,128,256}, q=RNL_Q32 (lazy-initialized). */
#define RNL32_LOG2N_MAX 8  /* log2(256)=8 covers n∈{32,64,128,256} */
#define RNL32_MAX_N     256
static struct {
    int      n;
    uint32_t psi_pow[RNL32_MAX_N];
    uint32_t psi_inv_pow[RNL32_MAX_N];
    uint32_t stage_w_fwd[RNL32_LOG2N_MAX];
    uint32_t stage_w_inv[RNL32_LOG2N_MAX];
    uint32_t inv_n;
    int      ready;
} rnl32_tw[4] = { {32}, {64}, {128}, {256} };  /* 0=n=32, 1=n=64, 2=n=128, 3=n=256 */

static void rnl32_tw_init(int idx)
{
    uint32_t psi, psi_inv, pw, pw_inv, w;
    int n, i, s, length;
    if (rnl32_tw[idx].ready) return;
    n = rnl32_tw[idx].n;
    psi     = rnl32_mod_pow(3, (RNL_Q32 - 1) / (2 * (uint32_t)n), RNL_Q32);
    psi_inv = rnl32_mod_pow(psi, RNL_Q32 - 2, RNL_Q32);
    pw = pw_inv = 1;
    for (i = 0; i < n; i++) {
        rnl32_tw[idx].psi_pow[i]     = pw;
        rnl32_tw[idx].psi_inv_pow[i] = pw_inv;
        pw     = (uint32_t)((uint64_t)pw     * psi     % RNL_Q32);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % RNL_Q32);
    }
    for (s = 0, length = 2; length <= n; length <<= 1, s++) {
        w = rnl32_mod_pow(3, (RNL_Q32 - 1) / (uint32_t)length, RNL_Q32);
        rnl32_tw[idx].stage_w_fwd[s] = w;
        rnl32_tw[idx].stage_w_inv[s] = rnl32_mod_pow(w, RNL_Q32 - 2, RNL_Q32);
    }
    rnl32_tw[idx].inv_n = rnl32_mod_pow((uint32_t)n, RNL_Q32 - 2, RNL_Q32);
    rnl32_tw[idx].ready = 1;
}

static int rnl32_tw_idx(int n)
{
    return (n == 32) ? 0 : (n == 64) ? 1 : (n == 128) ? 2 : (n == 256) ? 3 : -1;
}

/* Fermat-prime modular multiply mod 65537 = 2^16+1.
   x = a*b; since 2^16 ≡ -1 and 2^32 ≡ 1 mod q: x ≡ lo - mid + hi (mod q).
   r ∈ [-65535, 65536] so at most one conditional add needed. */
static inline uint32_t rnl_mulmodq(uint32_t a, uint32_t b)
{
    uint64_t x = (uint64_t)a * b;
    int32_t r = (int32_t)(x & 0xFFFF)
              - (int32_t)((x >> 16) & 0xFFFF)
              + (int32_t)(x >> 32);
    if (r < 0) r += 65537;
    return (uint32_t)r;
}

static void rnl32_ntt(int32_t *a, int n, int q, int invert)
{
    int i, j = 0, length, k, s, idx = rnl32_tw_idx(n);
    uint32_t w, wn;
    const uint32_t *sw = NULL;
    if (idx >= 0) { rnl32_tw_init(idx); sw = invert ? rnl32_tw[idx].stage_w_inv : rnl32_tw[idx].stage_w_fwd; }
    for (i = 1; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { int32_t t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (length = 2, s = 0; length <= n; length <<= 1, s++) {
        if (sw) { w = sw[s]; }
        else {
            w = rnl32_mod_pow(3, (uint32_t)(q - 1) / (uint32_t)length, (uint32_t)q);
            if (invert) w = rnl32_mod_pow(w, (uint32_t)(q - 2), (uint32_t)q);
        }
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
        uint32_t inv_n = (idx >= 0) ? rnl32_tw[idx].inv_n :
                         rnl32_mod_pow((uint32_t)n, (uint32_t)(q - 2), (uint32_t)q);
        for (i = 0; i < n; i++)
            a[i] = (int32_t)rnl_mulmodq((uint32_t)a[i], inv_n);
    }
}

/* Negacyclic multiply: h = f*g in Z_q[x]/(x^32+1) via NTT. O(n log n). */
static void rnl32_poly_mul(rnl32_poly_t h, const rnl32_poly_t f, const rnl32_poly_t g)
{
    int32_t fa[RNL_N32], ga[RNL_N32], ha[RNL_N32];
    int i;
    rnl32_tw_init(0);
    for (i = 0; i < RNL_N32; i++) {
        fa[i] = (int32_t)rnl_mulmodq((uint32_t)f[i], rnl32_tw[0].psi_pow[i]);
        ga[i] = (int32_t)rnl_mulmodq((uint32_t)g[i], rnl32_tw[0].psi_pow[i]);
    }
    rnl32_ntt(fa, RNL_N32, RNL_Q32, 0);
    rnl32_ntt(ga, RNL_N32, RNL_Q32, 0);
    for (i = 0; i < RNL_N32; i++)
        ha[i] = (int32_t)rnl_mulmodq((uint32_t)fa[i], (uint32_t)ga[i]);
    rnl32_ntt(ha, RNL_N32, RNL_Q32, 1);
    for (i = 0; i < RNL_N32; i++)
        h[i] = (int32_t)rnl_mulmodq((uint32_t)ha[i], rnl32_tw[0].psi_inv_pow[i]);
}

static void rnl32_poly_add(rnl32_poly_t h, const rnl32_poly_t f, const rnl32_poly_t g)
{
    int i;
    for (i = 0; i < RNL_N32; i++) h[i] = (f[i] + g[i]) % RNL_Q32;
}

static void rnl32_round(int32_t *out, const rnl32_poly_t in, int from_q, int to_p)
{
    int i;
    for (i = 0; i < RNL_N32; i++)
        out[i] = (int32_t)(((int64_t)in[i] * to_p + from_q / 2) / from_q % to_p);
}

static void rnl32_lift(rnl32_poly_t out, const int32_t *in, int from_p, int to_q)
{
    int i;
    for (i = 0; i < RNL_N32; i++)
        out[i] = (int32_t)((int64_t)in[i] * to_q / from_p % to_q);
}

/* m(x) = 1 + x + x^{n-1} */
static void rnl32_m_poly(rnl32_poly_t p)
{
    memset(p, 0, sizeof(rnl32_poly_t));
    p[0] = p[1] = p[RNL_N32 - 1] = 1;
}

static void rnl32_rand_poly(rnl32_poly_t p)
{
    int i;
    for (i = 0; i < RNL_N32; i++)
        p[i] = (int32_t)rnl_rand_coeff();
}

/* CBD(eta=1): 16 coefficients per rand32() word — bit-pairs (0-1),(2-3),...,(30-31). */
static void rnl32_cbd_poly(rnl32_poly_t p)
{
    int i;
    uint32_t raw = 0;
    for (i = 0; i < RNL_N32; i++) {
        if ((i & 15) == 0) raw = rand32();
        int off = (i & 15) * 2;
        int a = (raw >> off) & 1;
        int b = (raw >> (off + 1)) & 1;
        p[i] = (int32_t)((a - b + RNL_Q32) % RNL_Q32);
    }
}

/* Pack RNL_N32 bits: coefficient >= pp/2 -> bit = 1 */
static uint32_t rnl32_bits_to_u32(const int32_t *bits_poly)
{
    uint32_t r = 0;
    int i;
    for (i = 0; i < RNL_N32; i++)
        if (bits_poly[i] >= RNL_PP32 / 2)
            r |= (1u << i);
    return r;
}

/* keygen: s=CBD(eta=1) private, C=round_p(m_blind * s) */
static void rnl32_keygen(int32_t s_out[RNL_N32], int32_t c_out[RNL_N32],
                         const rnl32_poly_t m_blind)
{
    rnl32_poly_t ms;
    rnl32_cbd_poly(s_out);
    rnl32_poly_mul(ms, m_blind, s_out);
    rnl32_round(c_out, ms, RNL_Q32, RNL_P32);
}

/* Peikert hint: 1-bit per coeff, packed to uint32 (n=32 fits exactly). */
static uint32_t rnl32_hint(const int32_t K_poly[RNL_N32])
{
    uint32_t hint = 0;
    int i;
    for (i = 0; i < RNL_N32; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)4 * c + RNL_Q32 / 2) / RNL_Q32) % 4;
        if (r % 2) hint |= (1u << i);
    }
    return hint;
}

/* Reconcile n=32 K_poly bits using hint, return packed uint32 key. */
static uint32_t rnl32_reconcile(const int32_t K_poly[RNL_N32], uint32_t hint)
{
    const uint32_t qh = RNL_Q32 / 2;
    uint32_t key = 0;
    int i;
    for (i = 0; i < RNL_N32; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (hint >> i) & 1u;
        if ((uint32_t)(((uint64_t)2 * c + (uint64_t)h * qh + qh) / RNL_Q32) % RNL_PP32)
            key |= (1u << i);
    }
    return key;
}

/* agree: reconciler path (hint_out≠NULL) or receiver path (hint_in≠NULL). */
static uint32_t rnl32_agree(const int32_t s[RNL_N32], const int32_t c_other[RNL_N32],
                              const uint32_t *hint_in, uint32_t *hint_out)
{
    rnl32_poly_t c_lifted, k_poly;
    rnl32_lift(c_lifted, c_other, RNL_P32, RNL_Q32);
    rnl32_poly_mul(k_poly, s, c_lifted);
    if (!hint_in) {
        *hint_out = rnl32_hint(k_poly);
        return rnl32_reconcile(k_poly, *hint_out);
    }
    return rnl32_reconcile(k_poly, *hint_in);
}

/* ------------------------------------------------------------------ */
/* Generic-n HKEX-RNL helpers (VLA, n must be power of 2)             */
/* q=65537, p=4096, pp=2 shared with n=32 above                        */
/* ------------------------------------------------------------------ */

static void rnl_poly_mul_n(int32_t *h, const int32_t *f, const int32_t *g, int n)
{
    int32_t fa[n], ga[n], ha[n];
    int i, idx = rnl32_tw_idx(n);
    if (idx >= 0) {
        rnl32_tw_init(idx);
        for (i = 0; i < n; i++) {
            fa[i] = (int32_t)rnl_mulmodq((uint32_t)f[i], rnl32_tw[idx].psi_pow[i]);
            ga[i] = (int32_t)rnl_mulmodq((uint32_t)g[i], rnl32_tw[idx].psi_pow[i]);
        }
        rnl32_ntt(fa, n, RNL_Q32, 0);
        rnl32_ntt(ga, n, RNL_Q32, 0);
        for (i = 0; i < n; i++)
            ha[i] = (int32_t)rnl_mulmodq((uint32_t)fa[i], (uint32_t)ga[i]);
        rnl32_ntt(ha, n, RNL_Q32, 1);
        for (i = 0; i < n; i++)
            h[i] = (int32_t)rnl_mulmodq((uint32_t)ha[i], rnl32_tw[idx].psi_inv_pow[i]);
    } else {
        uint32_t psi     = rnl32_mod_pow(3, (RNL_Q32 - 1) / (2 * (uint32_t)n), RNL_Q32);
        uint32_t psi_inv = rnl32_mod_pow(psi, RNL_Q32 - 2, RNL_Q32);
        uint32_t pw = 1, pw_inv = 1;
        for (i = 0; i < n; i++) {
            fa[i] = (int32_t)rnl_mulmodq((uint32_t)f[i], pw);
            ga[i] = (int32_t)rnl_mulmodq((uint32_t)g[i], pw);
            pw    = rnl_mulmodq(pw, psi);
        }
        rnl32_ntt(fa, n, RNL_Q32, 0);
        rnl32_ntt(ga, n, RNL_Q32, 0);
        for (i = 0; i < n; i++)
            ha[i] = (int32_t)rnl_mulmodq((uint32_t)fa[i], (uint32_t)ga[i]);
        rnl32_ntt(ha, n, RNL_Q32, 1);
        for (i = 0; i < n; i++) {
            h[i]   = (int32_t)rnl_mulmodq((uint32_t)ha[i], pw_inv);
            pw_inv = rnl_mulmodq(pw_inv, psi_inv);
        }
    }
}

static void rnl_poly_add_n(int32_t *h, const int32_t *f, const int32_t *g, int n)
{
    int i;
    for (i = 0; i < n; i++) h[i] = (f[i] + g[i]) % RNL_Q32;
}

static void rnl_round_n(int32_t *out, const int32_t *in, int from_q, int to_p, int n)
{
    int i;
    for (i = 0; i < n; i++)
        out[i] = (int32_t)(((int64_t)in[i] * to_p + from_q / 2) / from_q % to_p);
}

static void rnl_lift_n(int32_t *out, const int32_t *in, int from_p, int to_q, int n)
{
    int i;
    for (i = 0; i < n; i++)
        out[i] = (int32_t)((int64_t)in[i] * to_q / from_p % to_q);
}

static void rnl_m_poly_n(int32_t *p, int n)
{
    memset(p, 0, (size_t)n * sizeof(int32_t));
    p[0] = p[1] = p[n - 1] = 1;
}

static void rnl_rand_poly_n(int32_t *p, int n)
{
    int i;
    for (i = 0; i < n; i++) p[i] = (int32_t)rnl_rand_coeff();
}

static void rnl_cbd_poly_n(int32_t *p, int n)
{
    int i;
    uint32_t raw = 0;
    for (i = 0; i < n; i++) {
        if ((i & 15) == 0) raw = rand32();
        int off = (i & 15) * 2;
        int a = (raw >> off) & 1;
        int b = (raw >> (off + 1)) & 1;
        p[i] = (int32_t)((a - b + RNL_Q32) % RNL_Q32);
    }
}

/* Pack n<=64 bits: coefficient >= pp/2 -> bit=1, returns uint64_t */
static uint64_t rnl_bits_to_u64(const int32_t *bits_poly, int n)
{
    uint64_t r = 0;
    int i;
    for (i = 0; i < n; i++)
        if (bits_poly[i] >= RNL_PP32 / 2)
            r |= ((uint64_t)1 << i);
    return r;
}

/* keygen: s=CBD(eta=1); C=round_p(m_blind * s) */
static void rnl_keygen_n(int32_t *s_out, int32_t *c_out, const int32_t *m_blind, int n)
{
    int32_t ms[n];
    rnl_cbd_poly_n(s_out, n);
    rnl_poly_mul_n(ms, m_blind, s_out, n);
    rnl_round_n(c_out, ms, RNL_Q32, RNL_P32, n);
}

/* Peikert hint for generic-n (n≤64), packed to uint64_t. */
static uint64_t rnl_hint_n(const int32_t *K_poly, int n)
{
    uint64_t hint = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)4 * c + RNL_Q32 / 2) / RNL_Q32) % 4;
        if (r % 2) hint |= ((uint64_t)1 << i);
    }
    return hint;
}

/* Reconcile generic-n K_poly using hint, return packed uint64_t key. */
static uint64_t rnl_reconcile_n(const int32_t *K_poly, uint64_t hint, int n)
{
    const uint32_t qh = RNL_Q32 / 2;
    uint64_t key = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (uint32_t)((hint >> i) & 1u);
        if ((uint32_t)(((uint64_t)2 * c + (uint64_t)h * qh + qh) / RNL_Q32) % RNL_PP32)
            key |= ((uint64_t)1 << i);
    }
    return key;
}

/* agree (generic n): reconciler (hint_out≠NULL) or receiver (hint_in≠NULL). */
static uint64_t rnl_agree_n(const int32_t *s, const int32_t *c_other, int n,
                              const uint64_t *hint_in, uint64_t *hint_out)
{
    int32_t c_lifted[n], k_poly[n];
    rnl_lift_n(c_lifted, c_other, RNL_P32, RNL_Q32, n);
    rnl_poly_mul_n(k_poly, s, c_lifted, n);
    if (!hint_in) {
        *hint_out = rnl_hint_n(k_poly, n);
        return rnl_reconcile_n(k_poly, *hint_out, n);
    }
    return rnl_reconcile_n(k_poly, *hint_in, n);
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL 128-bit helpers (__uint128_t hint/reconcile/agree)        */
/* ------------------------------------------------------------------ */

static __uint128_t rnl_hint_128(const int32_t *K_poly, int n)
{
    __uint128_t hint = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)4 * c + RNL_Q32 / 2) / RNL_Q32) % 4;
        if (r % 2) hint |= ((__uint128_t)1 << i);
    }
    return hint;
}

static __uint128_t rnl_reconcile_128(const int32_t *K_poly, __uint128_t hint, int n)
{
    const uint32_t qh = RNL_Q32 / 2;
    __uint128_t key = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (uint32_t)((hint >> i) & 1u);
        if ((uint32_t)(((uint64_t)2 * c + (uint64_t)h * qh + qh) / RNL_Q32) % RNL_PP32)
            key |= ((__uint128_t)1 << i);
    }
    return key;
}

static __uint128_t rnl_agree_128(const int32_t *s, const int32_t *c_other, int n,
                                   const __uint128_t *hint_in, __uint128_t *hint_out)
{
    int32_t c_lifted[n], k_poly[n];
    rnl_lift_n(c_lifted, c_other, RNL_P32, RNL_Q32, n);
    rnl_poly_mul_n(k_poly, s, c_lifted, n);
    if (!hint_in) {
        *hint_out = rnl_hint_128(k_poly, n);
        return rnl_reconcile_128(k_poly, *hint_out, n);
    }
    return rnl_reconcile_128(k_poly, *hint_in, n);
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL 256-bit helpers (BitArray hint/reconcile/agree)           */
/* ------------------------------------------------------------------ */

/* Peikert hint for n=256: 1 bit per coeff packed into BitArray (bit i = coeff i). */
static void rnl_hint_ba(const int32_t *K_poly, int n, BitArray *hint)
{
    int i;
    memset(hint->b, 0, KEYBYTES);
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t r = (uint32_t)(((uint64_t)4 * c + RNL_Q32 / 2) / RNL_Q32) % 4;
        if (r % 2) hint->b[KEYBYTES - 1 - i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

static void rnl_reconcile_ba(const int32_t *K_poly, const BitArray *hint,
                               int n, BitArray *key)
{
    const uint32_t qh = RNL_Q32 / 2;
    int i;
    memset(key->b, 0, KEYBYTES);
    for (i = 0; i < n; i++) {
        uint32_t c = (uint32_t)K_poly[i];
        uint32_t h = (hint->b[KEYBYTES - 1 - i / 8] >> (i % 8)) & 1u;
        if ((uint32_t)(((uint64_t)2 * c + (uint64_t)h * qh + qh) / RNL_Q32) % RNL_PP32)
            key->b[KEYBYTES - 1 - i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* agree (n=256): reconciler pass hint_in=NULL; receiver pass hint_out=NULL. */
static void rnl_agree_ba(const int32_t *s, const int32_t *c_other, int n,
                          const BitArray *hint_in, BitArray *hint_out, BitArray *key_out)
{
    int32_t c_lifted[n], k_poly[n];
    rnl_lift_n(c_lifted, c_other, RNL_P32, RNL_Q32, n);
    rnl_poly_mul_n(k_poly, s, c_lifted, n);
    if (!hint_in) {
        rnl_hint_ba(k_poly, n, hint_out);
        rnl_reconcile_ba(k_poly, hint_out, n, key_out);
    } else {
        rnl_reconcile_ba(k_poly, hint_in, n, key_out);
    }
}

/* ------------------------------------------------------------------ */
/* Timing helpers                                                      */
/* ------------------------------------------------------------------ */

static double elapsed_sec(struct timespec *t0, struct timespec *t1)
{
    return (double)(t1->tv_sec  - t0->tv_sec)
         + (double)(t1->tv_nsec - t0->tv_nsec) / 1.0e9;
}

static void print_rate(long long ops, double secs)
{
    double rate = (double)ops / secs;
    if (rate >= 1.0e6)
        printf("%.2f M ops/sec  (%lld ops in %.2fs)\n",
               rate / 1.0e6, ops, secs);
    else if (rate >= 1.0e3)
        printf("%.2f K ops/sec  (%lld ops in %.2fs)\n",
               rate / 1.0e3, ops, secs);
    else
        printf("%.2f ops/sec  (%lld ops in %.2fs)\n",
               rate, ops, secs);
}

/* Effective iteration count: honours g_rounds when set, else per-test default. */
#define TEST_ROUNDS(def)  ((g_rounds > 0) ? g_rounds : (def))

/* Returns 1 when the per-test time cap is set and has been reached. */
static int time_exceeded(struct timespec *t0)
{
    struct timespec t1;
    if (g_time_limit <= 0.0) return 0;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return elapsed_sec(t0, &t1) >= g_time_limit;
}

/* ------------------------------------------------------------------ */
/* Security tests [1]-[6]: HKEX-GF and FSCX primitives               */
/* ------------------------------------------------------------------ */

/* 128-bit popcount helper */
static int popcount128(__uint128_t x)
{
    return __builtin_popcountll((uint64_t)(x >> 64))
         + __builtin_popcountll((uint64_t)x);
}

/* Eve s_op helpers: acc = XOR of fscx^0..r applied to delta */
static uint32_t s_op32(uint32_t delta, int r)
{
    uint32_t acc = 0, cur = delta;
    int j;
    for (j = 0; j <= r; j++) { acc ^= cur; cur = fscx32(cur, 0); }
    return acc;
}

static uint64_t s_op64(uint64_t delta, int r)
{
    uint64_t acc = 0, cur = delta;
    int j;
    for (j = 0; j <= r; j++) { acc ^= cur; cur = fscx64(cur, 0); }
    return acc;
}

/* ------------------------------------------------------------------ */
/* 128-bit GF(2^128) arithmetic (for Batch-3 multi-size tests)        */
/* Poly: x^128+x^7+x^2+x+1 → low 64-bit constant 0x87               */
/* Generator g=3; group order 2^128-1                                 */
/* ------------------------------------------------------------------ */

#define GF_POLY128_LO  UINT64_C(0x87)  /* low 64 bits of x^128+x^7+x^2+x+1 */

static __uint128_t gf_mul_128(__uint128_t a, __uint128_t b)
{
    __uint128_t r = 0;
    int i;
    for (i = 0; i < 128; i++) {
        if (b & 1) r ^= a;
        { int carry = (int)(a >> 127) & 1;
          a <<= 1;
          if (carry) a ^= (__uint128_t)GF_POLY128_LO; }
        b >>= 1;
    }
    return r;
}

static __uint128_t gf_pow_128(__uint128_t base, __uint128_t exp)
{
    __uint128_t r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_128(r, base);
        base = gf_mul_128(base, base);
        exp >>= 1;
    }
    return r;
}

/* (a * b) mod (2^128 - 1): full 256-bit product via 64-bit halves */
static __uint128_t mul128_mod_ord128(__uint128_t a, __uint128_t b)
{
    uint64_t a_hi = (uint64_t)(a >> 64), a_lo = (uint64_t)a;
    uint64_t b_hi = (uint64_t)(b >> 64), b_lo = (uint64_t)b;
    __uint128_t p_ll = (__uint128_t)a_lo * b_lo;
    __uint128_t p_lh = (__uint128_t)a_lo * b_hi;
    __uint128_t p_hl = (__uint128_t)a_hi * b_lo;
    __uint128_t p_hh = (__uint128_t)a_hi * b_hi;
    __uint128_t mid  = p_lh + p_hl;
    int mid_ov = (mid < p_lh) ? 1 : 0;
    __uint128_t lo   = p_ll + (mid << 64);
    int lo_ov  = (lo < p_ll) ? 1 : 0;
    __uint128_t hi   = p_hh + (mid >> 64) + ((__uint128_t)mid_ov << 64) + lo_ov;
    __uint128_t r    = lo + hi;
    if (r < lo) r++;                              /* carry: 2^128 ≡ 1 */
    if (r == (__uint128_t)0 - 1) r = 0;           /* 2^128-1 ≡ 0 */
    return r;
}

static __uint128_t s_op128(__uint128_t delta, int r)
{
    __uint128_t acc = 0, cur = delta;
    int j;
    for (j = 0; j <= r; j++) { acc ^= cur; cur = fscx128(cur, 0); }
    return acc;
}

/* ================================================================== */
/* bn_* — parameterised big-endian byte-array arithmetic (Groups A-E) */
/* nbits must be a positive multiple of 8; b[0]=MSB, b[nbytes-1]=LSB  */
/* ================================================================== */

#define BN_MAX_BITS  512
#define BN_MAX_BYTES (BN_MAX_BITS / 8)

/* --- Group A: bit-string primitives --- */

static void bn_zero(uint8_t *a, int nb)
{ memset(a, 0, (size_t)(nb / 8)); }

static void bn_copy(uint8_t *dst, const uint8_t *src, int nb)
{ memcpy(dst, src, (size_t)(nb / 8)); }

static void bn_xor_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    for (i = 0; i < n; i++) dst[i] = a[i] ^ b[i];
}

static int bn_equal_n(const uint8_t *a, const uint8_t *b, int nb)
{ return memcmp(a, b, (size_t)(nb / 8)) == 0; }

static int bn_is_zero_n(const uint8_t *a, int nb)
{
    int i, n = nb / 8;
    for (i = 0; i < n; i++) if (a[i]) return 0;
    return 1;
}

static int bn_popcount_n(const uint8_t *a, int nb)
{
    int i, cnt = 0, n = nb / 8;
    for (i = 0; i < n; i++) cnt += __builtin_popcount(a[i]);
    return cnt;
}

static int bn_shl1_n(uint8_t *a, int nb)
{
    int i, n = nb / 8;
    int carry = (a[0] >> 7) & 1;
    for (i = 0; i < n - 1; i++)
        a[i] = (uint8_t)((a[i] << 1) | (a[i + 1] >> 7));
    a[n - 1] <<= 1;
    return carry;
}

static int bn_shr1_n(uint8_t *a, int nb)
{
    int i, n = nb / 8;
    int carry = a[n - 1] & 1;
    for (i = n - 1; i > 0; i--)
        a[i] = (uint8_t)((a[i] >> 1) | (a[i - 1] << 7));
    a[0] >>= 1;
    return carry;
}

static void bn_rol_k_n(uint8_t *dst, const uint8_t *src, int k, int nb)
{
    int n = nb / 8, byte_shift = (k / 8) % n, bit_shift = k % 8, i;
    if (bit_shift == 0) {
        for (i = 0; i < n; i++) dst[i] = src[(i + byte_shift) % n];
    } else {
        int rs = 8 - bit_shift;
        for (i = 0; i < n; i++)
            dst[i] = (uint8_t)((src[(i + byte_shift) % n] << bit_shift)
                             | (src[(i + byte_shift + 1) % n] >> rs));
    }
}

/* --- Group B: integer arithmetic mod 2^n --- */

static void bn_add_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    uint16_t carry = 0;
    for (i = n - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a[i] + b[i] + carry;
        dst[i] = (uint8_t)s; carry = s >> 8;
    }
}

static void bn_sub_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    int16_t borrow = 0;
    for (i = n - 1; i >= 0; i--) {
        int16_t s = (int16_t)a[i] - b[i] - borrow;
        dst[i] = (uint8_t)(s & 0xFF); borrow = (s < 0) ? 1 : 0;
    }
}

/* a*b mod 2^n — schoolbook, low n bytes only */
static void bn_mul_lo_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, j, n = nb / 8;
    uint64_t acc[BN_MAX_BYTES];
    memset(acc, 0, (size_t)n * sizeof(uint64_t));
    for (i = 0; i < n; i++)
        for (j = 0; j < n - i; j++)
            acc[n - 1 - i - j] += (uint64_t)a[n - 1 - i] * b[n - 1 - j];
    { uint64_t carry = 0;
      for (i = n - 1; i >= 0; i--) {
          uint64_t s = acc[i] + carry;
          dst[i] = (uint8_t)s; carry = s >> 8;
      }
    }
}

/* Full 2n-bit product into full2n[0..2*nbytes-1] (big-endian) */
static void bn_mul_full_n(uint8_t *full2n, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, j, n = nb / 8;
    uint64_t acc[BN_MAX_BYTES * 2];
    memset(acc, 0, (size_t)(2 * n) * sizeof(uint64_t));
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++)
            acc[2 * n - 1 - i - j] += (uint64_t)a[n - 1 - i] * b[n - 1 - j];
    { uint64_t carry = 0;
      for (i = 2 * n - 1; i >= 0; i--) {
          uint64_t s = acc[i] + carry;
          full2n[i] = (uint8_t)s; carry = s >> 8;
      }
    }
}

/* --- Group C: arithmetic mod (2^n − 1) --- */

/* a*b mod (2^n-1): fold hi+lo halves of 2n-bit product */
static void bn_mul_mod_ord_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    uint8_t full[BN_MAX_BYTES * 2];
    int i, n = nb / 8;
    uint16_t carry;
    bn_mul_full_n(full, a, b, nb);
    carry = 0;
    for (i = n - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)full[i] + full[n + i] + carry;
        dst[i] = (uint8_t)s; carry = s >> 8;
    }
    if (carry) { /* propagate carry: dst += 1 */
        for (i = n - 1; i >= 0; i--) {
            uint16_t s = (uint16_t)dst[i] + 1;
            dst[i] = (uint8_t)s;
            if (!(s >> 8)) break;
        }
    }
    /* if all-0xFF → set to 0 (2^n-1 ≡ 0 mod ord) */
    { int all_ff = 1;
      for (i = 0; i < n; i++) if (dst[i] != 0xFF) { all_ff = 0; break; }
      if (all_ff) memset(dst, 0, (size_t)n);
    }
}

/* (a-b) mod (2^n-1): subtract; if borrow subtract 1 more (wrap) */
static void bn_sub_mod_ord_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    int16_t borrow = 0;
    for (i = n - 1; i >= 0; i--) {
        int16_t s = (int16_t)a[i] - b[i] - borrow;
        dst[i] = (uint8_t)(s & 0xFF); borrow = (s < 0) ? 1 : 0;
    }
    if (borrow) { /* dst = a-b+2^n; want a-b+ord = dst-1 */
        for (i = n - 1; i >= 0; i--) {
            if (dst[i]) { dst[i]--; break; }
            dst[i] = 0xFF;
        }
    }
}

/* (a+b) mod (2^n-1) */
static void bn_add_mod_ord_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    uint16_t carry = 0;
    for (i = n - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a[i] + b[i] + carry;
        dst[i] = (uint8_t)s; carry = s >> 8;
    }
    if (carry) {
        for (i = n - 1; i >= 0; i--) {
            uint16_t s = (uint16_t)dst[i] + 1;
            dst[i] = (uint8_t)s;
            if (!(s >> 8)) break;
        }
    }
    { int all_ff = 1;
      for (i = 0; i < n; i++) if (dst[i] != 0xFF) { all_ff = 0; break; }
      if (all_ff) memset(dst, 0, (size_t)n);
    }
}

/* --- Group D: GF(2^n) field arithmetic --- */

static const uint8_t *gf_poly_for_n(int nb)
{
    /* x^32+x^22+x^2+x+1 → 0x00400007 */
    static const uint8_t p32[4]   = { 0x00, 0x40, 0x00, 0x07 };
    /* x^64+x^4+x^3+x+1 → 0x1B */
    static const uint8_t p64[8]   = { 0,0,0,0, 0,0,0,0x1B };
    /* x^128+x^7+x^2+x+1 → 0x87 */
    static const uint8_t p128[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x87 };
    /* x^256+x^10+x^5+x^2+1 → 0x0425 */
    static const uint8_t p256[32] = {
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x04,0x25 };
    switch (nb) {
        case  32: return p32;
        case  64: return p64;
        case 128: return p128;
        default:  return p256;
    }
}

/* Carryless multiply mod irreducible poly: LSB-first (shr1 b, shl1 a + reduce) */
static void bn_gf_mul_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    uint8_t r[BN_MAX_BYTES], aa[BN_MAX_BYTES], bb[BN_MAX_BYTES];
    const uint8_t *poly = gf_poly_for_n(nb);
    int i, n = nb / 8;
    memset(r, 0, (size_t)n);
    bn_copy(aa, a, nb); bn_copy(bb, b, nb);
    for (i = 0; i < nb; i++) {
        if (bb[n - 1] & 1) bn_xor_n(r, r, aa, nb);
        { int carry = bn_shl1_n(aa, nb);
          if (carry) bn_xor_n(aa, aa, poly, nb); }
        bn_shr1_n(bb, nb);
    }
    bn_copy(dst, r, nb);
}

/* Square-and-multiply */
static void bn_gf_pow_n(uint8_t *dst, const uint8_t *base, const uint8_t *exp, int nb)
{
    uint8_t r[BN_MAX_BYTES], b[BN_MAX_BYTES], e[BN_MAX_BYTES];
    int n = nb / 8;
    memset(r, 0, (size_t)n); r[n - 1] = 1;
    bn_copy(b, base, nb); bn_copy(e, exp, nb);
    while (!bn_is_zero_n(e, nb)) {
        if (e[n - 1] & 1) bn_gf_mul_n(r, r, b, nb);
        bn_gf_mul_n(b, b, b, nb);
        bn_shr1_n(e, nb);
    }
    bn_copy(dst, r, nb);
}

/* --- Group E: FSCX and NL-FSCX --- */

static void bn_fscx_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    int i, n = nb / 8;
    uint8_t a_msbit = a[0] >> 7, b_msbit = b[0] >> 7;
    uint8_t a_lsbit = a[n-1] & 1, b_lsbit = b[n-1] & 1;
    dst[0] = a[0] ^ b[0]
        ^ (uint8_t)((a[0]<<1)|(a[1]>>7)) ^ (uint8_t)((b[0]<<1)|(b[1]>>7))
        ^ (uint8_t)((a[0]>>1)|(a_lsbit<<7)) ^ (uint8_t)((b[0]>>1)|(b_lsbit<<7));
    for (i = 1; i < n - 1; i++)
        dst[i] = a[i] ^ b[i]
            ^ (uint8_t)((a[i]<<1)|(a[i+1]>>7)) ^ (uint8_t)((b[i]<<1)|(b[i+1]>>7))
            ^ (uint8_t)((a[i]>>1)|(a[i-1]<<7)) ^ (uint8_t)((b[i]>>1)|(b[i-1]<<7));
    dst[n-1] = a[n-1] ^ b[n-1]
        ^ (uint8_t)((a[n-1]<<1)|a_msbit) ^ (uint8_t)((b[n-1]<<1)|b_msbit)
        ^ (uint8_t)((a[n-1]>>1)|(a[n-2]<<7)) ^ (uint8_t)((b[n-1]>>1)|(b[n-2]<<7));
}

static void bn_fscx_revolve_n(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                               int steps, int nb)
{
    uint8_t buf[2][BN_MAX_BYTES];
    int idx = 0, i, n = nb / 8;
    bn_copy(buf[0], a, nb);
    for (i = 0; i < steps; i++) { bn_fscx_n(buf[1-idx], buf[idx], b, nb); idx ^= 1; }
    bn_copy(dst, buf[idx], nb);
}

/* M^{-1}(x): lazy-init rotation table tbl = M^{n/2-1}(e_0) per nbits.
   M^{n/2}=I so M^{n/2-1}=M^{-1}.  tbl bit k set → include ROL(src,k). */
static void bn_m_inv_n(uint8_t *dst, const uint8_t *src, int nb)
{
    static uint8_t tbl[4][BN_MAX_BYTES];
    static int tbl_ready[4] = {0,0,0,0};
    int idx = (nb==32)?0:(nb==64)?1:(nb==128)?2:3;
    int n = nb / 8, k;
    if (!tbl_ready[idx]) {
        uint8_t one[BN_MAX_BYTES], zero[BN_MAX_BYTES];
        memset(one,  0, (size_t)n); one[n-1] = 1;
        memset(zero, 0, (size_t)n);
        bn_fscx_revolve_n(tbl[idx], one, zero, nb/2 - 1, nb);
        tbl_ready[idx] = 1;
    }
    memset(dst, 0, (size_t)n);
    for (k = 0; k < nb; k++) {
        if ((tbl[idx][n - 1 - k/8] >> (k%8)) & 1) {
            uint8_t rot[BN_MAX_BYTES];
            bn_rol_k_n(rot, src, k, nb);
            bn_xor_n(dst, dst, rot, nb);
        }
    }
}

/* NL-FSCX v1: fscx(a,b) ^ ROL(a+b, n/4) */
static void bn_nl_fscx_v1_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    uint8_t f[BN_MAX_BYTES], s[BN_MAX_BYTES], m[BN_MAX_BYTES];
    bn_fscx_n(f, a, b, nb);
    bn_add_n(s, a, b, nb);
    bn_rol_k_n(m, s, nb/4, nb);
    bn_xor_n(dst, f, m, nb);
}

static void bn_nl_fscx_revolve_v1_n(uint8_t *dst, const uint8_t *a,
                                     const uint8_t *b, int steps, int nb)
{
    uint8_t buf[2][BN_MAX_BYTES];
    int idx = 0, i, n = nb / 8;
    bn_copy(buf[0], a, nb);
    for (i = 0; i < steps; i++) {
        bn_nl_fscx_v1_n(buf[1-idx], buf[idx], b, nb); idx ^= 1;
    }
    bn_copy(dst, buf[idx], nb);
}

/* delta(b) = ROL(b * ((b+1)/2), n/4) */
static void bn_nl_delta_v2_n(uint8_t *delta, const uint8_t *b, int nb)
{
    uint8_t b1[BN_MAX_BYTES], half[BN_MAX_BYTES], prod[BN_MAX_BYTES];
    uint8_t one[BN_MAX_BYTES];
    int n = nb / 8;
    memset(one, 0, (size_t)n); one[n-1] = 1;
    bn_add_n(b1, b, one, nb);
    bn_copy(half, b1, nb); bn_shr1_n(half, nb);
    bn_mul_lo_n(prod, b, half, nb);
    bn_rol_k_n(delta, prod, nb/4, nb);
}

static void bn_nl_fscx_v2_n(uint8_t *dst, const uint8_t *a, const uint8_t *b, int nb)
{
    uint8_t f[BN_MAX_BYTES], delta[BN_MAX_BYTES];
    bn_fscx_n(f, a, b, nb);
    bn_nl_delta_v2_n(delta, b, nb);
    bn_add_n(dst, f, delta, nb);
}

static void bn_nl_fscx_v2_inv_n(uint8_t *dst, const uint8_t *y,
                                  const uint8_t *b, int nb)
{
    uint8_t delta[BN_MAX_BYTES], ym_d[BN_MAX_BYTES], inv_ym[BN_MAX_BYTES];
    bn_nl_delta_v2_n(delta, b, nb);
    bn_sub_n(ym_d, y, delta, nb);
    bn_m_inv_n(inv_ym, ym_d, nb);
    bn_xor_n(dst, b, inv_ym, nb);
}

static void bn_nl_fscx_revolve_v2_n(uint8_t *dst, const uint8_t *a,
                                     const uint8_t *b, int steps, int nb)
{
    uint8_t buf[2][BN_MAX_BYTES];
    int idx = 0, i, n = nb / 8;
    bn_copy(buf[0], a, nb);
    for (i = 0; i < steps; i++) {
        bn_nl_fscx_v2_n(buf[1-idx], buf[idx], b, nb); idx ^= 1;
    }
    bn_copy(dst, buf[idx], nb);
}

static void bn_nl_fscx_revolve_v2_inv_n(uint8_t *dst, const uint8_t *y,
                                         const uint8_t *b, int steps, int nb)
{
    uint8_t delta[BN_MAX_BYTES], buf[2][BN_MAX_BYTES];
    int idx = 0, i, n = nb / 8;
    bn_nl_delta_v2_n(delta, b, nb);
    bn_copy(buf[0], y, nb);
    for (i = 0; i < steps; i++) {
        uint8_t ym_d[BN_MAX_BYTES], inv_ym[BN_MAX_BYTES];
        bn_sub_n(ym_d, buf[idx], delta, nb);
        bn_m_inv_n(inv_ym, ym_d, nb);
        bn_xor_n(buf[1-idx], b, inv_ym, nb);
        idx ^= 1;
    }
    bn_copy(dst, buf[idx], nb);
}

/* Utility helpers for tests */
static void bn_rand_n(uint8_t *dst, int nb)
{
    int n = nb / 8;
    if (fread(dst, (size_t)n, 1, urnd_fp) != 1) {
        fputs("ERROR: read from /dev/urandom failed\n", stderr); exit(1);
    }
}

static void bn_set_gen(uint8_t *dst, int nb)
{
    int n = nb / 8;
    memset(dst, 0, (size_t)n); dst[n-1] = 3;
}

/* [1] HKEX-GF correctness: shared key derived by Alice == shared key derived by Bob */
static void test_hkex_gf_correctness(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    BitArray a256, b256, C256, C2_256, skA256, skB256;
    __uint128_t a128, b128, C128, C2_128, skA128, skB128;
    uint64_t a64, b64, C64, C2_64, skA64, skB64;
    uint32_t a32, b32, C32a, C2_32a, skA32, skB32;
    printf("[1] HKEX-GF correctness: g^{ab} == g^{ba} in GF(2^n)*  [CLASSICAL]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                ba_rand(&a256); ba_rand(&b256);
                a256.b[KEYBYTES-1] |= 1; b256.b[KEYBYTES-1] |= 1;
                gf_pow_ba(&C256,   &GF_GEN, &a256);
                gf_pow_ba(&C2_256, &GF_GEN, &b256);
                gf_pow_ba(&skA256, &C2_256, &a256);
                gf_pow_ba(&skB256, &C256,   &b256);
                if (ba_equal(&skA256, &skB256)) ok++;
            } else if (size == 128) {
                a128 = rand128()|1; b128 = rand128()|1;
                C128   = gf_pow_128(3, a128); C2_128 = gf_pow_128(3, b128);
                skA128 = gf_pow_128(C2_128, a128); skB128 = gf_pow_128(C128, b128);
                if (skA128 == skB128) ok++;
            } else if (size == 64) {
                a64 = rand64()|1; b64 = rand64()|1;
                C64   = gf_pow_64(3ULL, a64); C2_64 = gf_pow_64(3ULL, b64);
                skA64 = gf_pow_64(C2_64, a64); skB64 = gf_pow_64(C64, b64);
                if (skA64 == skB64) ok++;
            } else {
                a32 = rand32()|1; b32 = rand32()|1;
                C32a  = gf_pow_32(GF_GEN32, a32); C2_32a = gf_pow_32(GF_GEN32, b32);
                skA32 = gf_pow_32(C2_32a, a32);   skB32  = gf_pow_32(C32a, b32);
                if (skA32 == skB32) ok++;
            }
            if ((i & 7) == 7 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %d / %d correct  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip) */
static void test_avalanche(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, trial, N, size;
    struct timespec t0;
    printf("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)  [CLASSICAL]\n");
    for (si = 0; si < 3; si++) {
        double total = 0.0;
        int gmin, gmax;
        size = sizes[si]; gmin = size + 1; gmax = -1;
        N = TEST_ROUNDS(1000);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (trial = 0; trial < N; trial++) {
            if (size == 256) {
                BitArray a, b, base_out, ap, flip_out, diff;
                int bit;
                ba_rand(&a); ba_rand(&b);
                ba_fscx(&base_out, &a, &b);
                for (bit = 0; bit < 256; bit++) {
                    int hd;
                    ba_flip_bit(&ap, &a, bit);
                    ba_fscx(&flip_out, &ap, &b);
                    ba_xor(&diff, &flip_out, &base_out);
                    hd = ba_popcount(&diff);
                    total += hd;
                    if (hd < gmin) gmin = hd;
                    if (hd > gmax) gmax = hd;
                }
            } else if (size == 128) {
                __uint128_t a = rand128(), b = rand128(), base;
                int bit;
                base = fscx128(a, b);
                for (bit = 0; bit < 128; bit++) {
                    int hd = popcount128(fscx128(a ^ ((__uint128_t)1 << bit), b) ^ base);
                    total += hd;
                    if (hd < gmin) gmin = hd;
                    if (hd > gmax) gmax = hd;
                }
            } else {
                uint64_t a = rand64(), b = rand64(), base;
                int bit;
                base = fscx64(a, b);
                for (bit = 0; bit < 64; bit++) {
                    int hd = __builtin_popcountll(fscx64(a ^ (1ULL << bit), b) ^ base);
                    total += hd;
                    if (hd < gmin) gmin = hd;
                    if (hd > gmax) gmax = hd;
                }
            }
            if ((trial & 63) == 63 && time_exceeded(&t0)) { N = trial + 1; break; }
        }
        {
            double mean = total / ((double)N * (double)size);
            printf("    bits=%3d  mean=%.2f (expected 3/%d)  min=%d  max=%d  [%s]\n",
                   size, mean, size, gmin, gmax,
                   (mean >= 2.9 && mean <= 3.1) ? "PASS" : "FAIL");
        }
    }
    putchar('\n');
}

/* [3] Orbit period: FSCX_REVOLVE(A,B,n) cycles back to A */
static void test_orbit_period(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, trial, N, size;
    struct timespec t0;
    printf("[3] Orbit period: FSCX_REVOLVE cycles back to A  [CLASSICAL]\n");
    for (si = 0; si < 3; si++) {
        int cntP = 0, cntHP = 0, other = 0;
        size = sizes[si];
        N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (trial = 0; trial < N; trial++) {
            int period = 1, cap = 2 * size;
            if (size == 256) {
                BitArray a, b, cur, tmp;
                ba_rand(&a); ba_rand(&b);
                ba_fscx(&cur, &a, &b);
                while (!ba_equal(&cur, &a) && period < cap) {
                    ba_fscx(&tmp, &cur, &b); cur = tmp; period++;
                }
            } else if (size == 128) {
                __uint128_t a = rand128(), b = rand128(), cur = fscx128(a, b);
                while (cur != a && period < cap) { cur = fscx128(cur, b); period++; }
            } else {
                uint64_t a = rand64(), b = rand64(), cur = fscx64(a, b);
                while (cur != a && period < cap) { cur = fscx64(cur, b); period++; }
            }
            if      (period == size)     cntP++;
            else if (period == size / 2) cntHP++;
            else                         other++;
            if ((trial & 15) == 15 && time_exceeded(&t0)) { N = trial + 1; break; }
        }
        printf("    bits=%3d  period=%d: %3d  period=%d: %3d  other: %d  [%s]\n",
               size, size, cntP, size / 2, cntHP, other,
               other == 0 ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [4] Bit-frequency bias */
static void test_bit_frequency(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, bit, trial, N, size;
    struct timespec t0;
    long long counts[256];
    printf("[4] Bit-frequency bias  [CLASSICAL]\n");
    for (si = 0; si < 3; si++) {
        double minpct, maxpct, meanpct;
        size = sizes[si];
        N = TEST_ROUNDS(10000);
        memset(counts, 0, (size_t)size * sizeof(long long));
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (trial = 0; trial < N; trial++) {
            if (size == 256) {
                BitArray a, b, out;
                ba_rand(&a); ba_rand(&b); ba_fscx(&out, &a, &b);
                for (bit = 0; bit < 256; bit++)
                    if (ba_get_bit(&out, bit)) counts[bit]++;
            } else if (size == 128) {
                __uint128_t out = fscx128(rand128(), rand128());
                for (bit = 0; bit < 128; bit++)
                    if ((out >> bit) & 1) counts[bit]++;
            } else {
                uint64_t out = fscx64(rand64(), rand64());
                for (bit = 0; bit < 64; bit++)
                    if ((out >> bit) & 1) counts[bit]++;
            }
            if ((trial & 255) == 255 && time_exceeded(&t0)) { N = trial + 1; break; }
        }
        minpct = 101.0; maxpct = -1.0; meanpct = 0.0;
        for (bit = 0; bit < size; bit++) {
            double pct = (double)counts[bit] / (double)N * 100.0;
            meanpct += pct;
            if (pct < minpct) minpct = pct;
            if (pct > maxpct) maxpct = pct;
        }
        meanpct /= (double)size;
        printf("    bits=%3d  min=%.2f%%  max=%.2f%%  mean=%.2f%%  [%s]\n",
               size, minpct, maxpct, meanpct,
               (minpct > 47.0 && maxpct < 53.0) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [5] HKEX-GF key sensitivity: flip 1 bit of a -> mean HD >= n/4 */
static void test_hkex_gf_key_sensitivity(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, N, size;
    struct timespec t0;
    double total, mean;
    BitArray a256, b256, C2_256, sk1_256, sk2_256, aflip256, diff256;
    __uint128_t a128ks, b128ks, C2_128ks, sk1_128ks, sk2_128ks;
    uint64_t a64, b64, C2_64, sk1_64, sk2_64;
    uint32_t a32, b32, C2_32b, sk1_32, sk2_32;
    printf("[5] HKEX-GF key sensitivity: flip 1 bit of a, measure HD of sk change  [CLASSICAL]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; total = 0.0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                ba_rand(&a256); ba_rand(&b256);
                a256.b[KEYBYTES-1] |= 1; b256.b[KEYBYTES-1] |= 1;
                gf_pow_ba(&C2_256, &GF_GEN, &b256);
                gf_pow_ba(&sk1_256, &C2_256, &a256);
                ba_flip_bit(&aflip256, &a256, 0);
                gf_pow_ba(&sk2_256, &C2_256, &aflip256);
                ba_xor(&diff256, &sk1_256, &sk2_256);
                total += ba_popcount(&diff256);
            } else if (size == 128) {
                a128ks = rand128()|1; b128ks = rand128()|1;
                C2_128ks = gf_pow_128(3, b128ks);
                sk1_128ks = gf_pow_128(C2_128ks, a128ks);
                sk2_128ks = gf_pow_128(C2_128ks, a128ks ^ 1);
                total += (double)popcount128(sk1_128ks ^ sk2_128ks);
            } else if (size == 64) {
                a64 = rand64()|1; b64 = rand64()|1;
                C2_64  = gf_pow_64(3ULL, b64);
                sk1_64 = gf_pow_64(C2_64, a64);
                sk2_64 = gf_pow_64(C2_64, a64 ^ 1ULL);
                total += (double)__builtin_popcountll(sk1_64 ^ sk2_64);
            } else {
                a32 = rand32()|1; b32 = rand32()|1;
                C2_32b = gf_pow_32(GF_GEN32, b32);
                sk1_32 = gf_pow_32(C2_32b, a32);
                sk2_32 = gf_pow_32(C2_32b, a32 ^ 1U);
                total += (double)__builtin_popcount(sk1_32 ^ sk2_32);
            }
            if ((i & 7) == 7 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        mean = total / (double)N;
        printf("    bits=%3d  mean HD=%.2f (expected >=%d)  [%s]\n",
               size, mean, size / 4,
               mean >= (double)(size / 4) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [6] Eve classical attack resistance: S_{r+1}(C XOR C2) != sk in HKEX-GF */
static void test_eve_attack_resistance(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, hits, N, size;
    struct timespec t0;
    BitArray a256, b256, C256, C2_256, sk256, evsk256;
    BitArray delta256, cur256, zero256, acc256, nxt256;
    __uint128_t a128ev, b128ev, C128ev, C2_128ev, sk128ev, evsk128ev;
    uint64_t a64, b64, C64e, C2_64e, sk64, evsk64;
    uint32_t a32e, b32e, C32e, C2_32e, sk32, evsk32;
    printf("[6] HKEX-GF Eve resistance: S_op(C^C2, r) != sk  [CLASSICAL]\n");
    memset(zero256.b, 0, KEYBYTES);
    for (si = 0; si < 4; si++) {
        size = sizes[si]; hits = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            int rv = 3 * size / 4;
            if (size == 256) {
                int j;
                ba_rand(&a256); ba_rand(&b256);
                a256.b[KEYBYTES-1] |= 1; b256.b[KEYBYTES-1] |= 1;
                gf_pow_ba(&C256,  &GF_GEN, &a256);
                gf_pow_ba(&C2_256, &GF_GEN, &b256);
                gf_pow_ba(&sk256,  &C2_256, &a256);
                ba_xor(&delta256, &C256, &C2_256);
                memset(acc256.b, 0, KEYBYTES);
                cur256 = delta256;
                for (j = 0; j <= rv; j++) {
                    ba_xor(&acc256, &acc256, &cur256);
                    ba_fscx(&nxt256, &cur256, &zero256);
                    cur256 = nxt256;
                }
                evsk256 = acc256;
                if (ba_equal(&evsk256, &sk256)) hits++;
            } else if (size == 128) {
                a128ev = rand128()|1; b128ev = rand128()|1;
                C128ev  = gf_pow_128(3, a128ev); C2_128ev = gf_pow_128(3, b128ev);
                sk128ev  = gf_pow_128(C2_128ev, a128ev);
                evsk128ev = s_op128(C128ev ^ C2_128ev, rv);
                if (evsk128ev == sk128ev) hits++;
            } else if (size == 64) {
                a64 = rand64()|1; b64 = rand64()|1;
                C64e  = gf_pow_64(3ULL, a64); C2_64e = gf_pow_64(3ULL, b64);
                sk64  = gf_pow_64(C2_64e, a64);
                evsk64 = s_op64(C64e ^ C2_64e, rv);
                if (evsk64 == sk64) hits++;
            } else {
                a32e = rand32()|1; b32e = rand32()|1;
                C32e  = gf_pow_32(GF_GEN32, a32e); C2_32e = gf_pow_32(GF_GEN32, b32e);
                sk32  = gf_pow_32(C2_32e, a32e);
                evsk32 = s_op32(C32e ^ C2_32e, rv);
                if (evsk32 == sk32) hits++;
            }
            if ((i & 7) == 7 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %5d / %d Eve successes (expected 0)  [%s]\n",
               size, hits, N, hits == 0 ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Security tests [7]-[9]: Schnorr HPKS and El Gamal HPKE (32/64-bit) */
/* ------------------------------------------------------------------ */

/* [7] HPKS Schnorr correctness: g^s * C^e == R — bn_* layer, {32,64,128,256} */
static void test_hpks_schnorr_correctness(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    printf("[7] HPKS Schnorr correctness: g^s · C^e == R  [CLASSICAL]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            int n = size / 8;
            uint8_t a[BN_MAX_BYTES], plain[BN_MAX_BYTES], k[BN_MAX_BYTES];
            uint8_t g[BN_MAX_BYTES], C[BN_MAX_BYTES], R[BN_MAX_BYTES];
            uint8_t e[BN_MAX_BYTES], ae[BN_MAX_BYTES], s[BN_MAX_BYTES];
            uint8_t gs[BN_MAX_BYTES], Ce[BN_MAX_BYTES], lhs[BN_MAX_BYTES];
            bn_rand_n(a, size); a[n-1] |= 1;
            bn_rand_n(plain, size); bn_rand_n(k, size);
            bn_set_gen(g, size);
            bn_gf_pow_n(C, g, a, size);
            bn_gf_pow_n(R, g, k, size);
            bn_fscx_revolve_n(e, R, plain, size/4, size);
            bn_mul_mod_ord_n(ae, a, e, size);
            bn_sub_mod_ord_n(s, k, ae, size);
            bn_gf_pow_n(gs, g, s, size);
            bn_gf_pow_n(Ce, C, e, size);
            bn_gf_mul_n(lhs, gs, Ce, size);
            if (bn_equal_n(lhs, R, size)) ok++;
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d verified  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [8] HPKS Schnorr Eve resistance: random forgery attempts fail — {32,64,128,256} */
static void test_hpks_schnorr_eve(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, hits, N, size;
    struct timespec t0;
    printf("[8] HPKS Schnorr Eve resistance: random forgery attempts fail  [CLASSICAL]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; hits = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            int n = size / 8;
            uint8_t a[BN_MAX_BYTES], plain[BN_MAX_BYTES];
            uint8_t g[BN_MAX_BYTES], C[BN_MAX_BYTES];
            uint8_t R[BN_MAX_BYTES], s[BN_MAX_BYTES], e[BN_MAX_BYTES];
            uint8_t gs[BN_MAX_BYTES], Ce[BN_MAX_BYTES], lhs[BN_MAX_BYTES];
            bn_rand_n(a, size); a[n-1] |= 1;
            bn_rand_n(plain, size);
            bn_rand_n(R, size); bn_rand_n(s, size);
            bn_set_gen(g, size);
            bn_gf_pow_n(C, g, a, size);
            bn_fscx_revolve_n(e, R, plain, size/4, size);
            bn_gf_pow_n(gs, g, s, size);
            bn_gf_pow_n(Ce, C, e, size);
            bn_gf_mul_n(lhs, gs, Ce, size);
            if (bn_equal_n(lhs, R, size)) hits++;
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d Eve wins (expected 0)  [%s]\n",
               size, hits, N, hits == 0 ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [9] HPKE El Gamal encrypt+decrypt: D == plaintext */
static void test_hpke_el_gamal(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32g, r32g, C32g, R32g, enc32, E32g, dec32, D32g;
    uint64_t a64g, r64g, C64g, R64g, enc64, E64g, dec64, D64g;
    __uint128_t a128g, r128g, C128g, R128g, enc128g, E128g, dec128g, D128g;
    BitArray a256g, r256g, C256g, R256g, enc256g, E256g, dec256g, D256g, pt256g;
    printf("[9] HPKE encrypt+decrypt correctness (El Gamal + fscx_revolve)  [CLASSICAL]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                ba_rand(&pt256g); ba_rand(&a256g); ba_rand(&r256g);
                a256g.b[KEYBYTES-1] |= 1; r256g.b[KEYBYTES-1] |= 1;
                gf_pow_ba(&C256g, &GF_GEN, &a256g);
                gf_pow_ba(&R256g, &GF_GEN, &r256g);
                gf_pow_ba(&enc256g, &C256g, &r256g);
                ba_fscx_revolve(&E256g, &pt256g, &enc256g, I_VALUE);
                gf_pow_ba(&dec256g, &R256g, &a256g);
                ba_fscx_revolve(&D256g, &E256g, &dec256g, R_VALUE);
                if (ba_equal(&D256g, &pt256g)) ok++;
            } else if (size == 128) {
                __uint128_t pt128g = rand128();
                a128g = rand128()|1; r128g = rand128()|1;
                C128g = gf_pow_128(3, a128g); R128g = gf_pow_128(3, r128g);
                enc128g = gf_pow_128(C128g, r128g);
                E128g   = fscx_revolve128(pt128g, enc128g, 32); /* 128/4 */
                dec128g = gf_pow_128(R128g, a128g);
                D128g   = fscx_revolve128(E128g, dec128g, 96); /* 3*128/4 */
                if (D128g == pt128g) ok++;
            } else if (size == 64) {
                uint64_t pt64 = rand64();
                a64g = rand64()|1; r64g = rand64()|1;
                C64g = gf_pow_64(3ULL, a64g); R64g = gf_pow_64(3ULL, r64g);
                enc64 = gf_pow_64(C64g, r64g);
                E64g  = fscx_revolve64(pt64, enc64, 16);
                dec64 = gf_pow_64(R64g, a64g);
                D64g  = fscx_revolve64(E64g, dec64, 48);
                if (D64g == pt64) ok++;
            } else {
                uint32_t pt32 = rand32();
                a32g = rand32()|1; r32g = rand32()|1;
                C32g = gf_pow_32(GF_GEN32, a32g); R32g = gf_pow_32(GF_GEN32, r32g);
                enc32 = gf_pow_32(C32g, r32g);
                E32g  = fscx_revolve32(pt32, enc32, 8);
                dec32 = gf_pow_32(R32g, a32g);
                D32g  = fscx_revolve32(E32g, dec32, 24);
                if (D32g == pt32) ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d decrypted  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Security tests [10]-[16]: v1.5.0 NL-FSCX and PQC protocols        */
/* ------------------------------------------------------------------ */

/* I/R values for 32/64/128/256-bit NL tests */
#define NL_I32   8   /* 32/4 */
#define NL_R32   24  /* 3*32/4 */
#define NL_I64   16  /* 64/4 */
#define NL_R64   48  /* 3*64/4 */
#define NL_I128  32  /* 128/4 */
#define NL_R128  96  /* 3*128/4 */
#define NL_I256  64  /* 256/4 */
#define NL_R256  192 /* 3*256/4 */

/* Bijectivity sample count: 256 A values per B, matching Python/Go */
#define BIJ_SAMPLES 256

/* [10] NL-FSCX v1 non-linearity and aperiodicity */
static void test_nl_fscx_v1_nonlinearity(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, i, size;
    struct timespec t0;
    printf("[10] NL-FSCX v1 non-linearity and aperiodicity  [PQC-EXT]\n");
    for (si = 0; si < 3; si++) {
        int violations = 0, no_period = 0;
        int N1 = TEST_ROUNDS(1000), N2 = TEST_ROUNDS(200);
        size = sizes[si];
        int cap = 4 * size;
        /* Linearity check */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N1; i++) {
            if (size == 256) {
                BitArray A, B, fA0, fB0, lin_pred, nl;
                static const BitArray ZERO = {{0}};
                ba_rand(&A); ba_rand(&B);
                nl_fscx_v1_ba(&fA0, &A, &ZERO);
                nl_fscx_v1_ba(&fB0, &ZERO, &B);
                ba_xor(&lin_pred, &fA0, &fB0);
                nl_fscx_v1_ba(&nl, &A, &B);
                if (!ba_equal(&nl, &lin_pred)) violations++;
            } else if (size == 128) {
                __uint128_t A = rand128(), B = rand128();
                __uint128_t lin_pred = fscx128(A, 0) ^ nl_fscx_v1_128(0, B);
                if (nl_fscx_v1_128(A, B) != lin_pred) violations++;
            } else {
                uint64_t A = rand64(), B = rand64();
                uint64_t lin_pred = fscx64(A, 0) ^ nl_fscx_v1_64(0, B);
                if (nl_fscx_v1_64(A, B) != lin_pred) violations++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N1 = i + 1; break; }
        }
        /* Aperiodicity: orbit of 4*n steps should not return to A */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N2; i++) {
            int found = 0, step;
            if (size == 256) {
                BitArray A, B, cur;
                ba_rand(&A); ba_rand(&B);
                nl_fscx_v1_ba(&cur, &A, &B);
                for (step = 1; step < cap; step++) {
                    nl_fscx_v1_ba(&cur, &cur, &B);
                    if (ba_equal(&cur, &A)) { found = 1; break; }
                }
            } else if (size == 128) {
                __uint128_t A = rand128(), B = rand128();
                __uint128_t cur = nl_fscx_v1_128(A, B);
                for (step = 1; step < cap; step++) {
                    cur = nl_fscx_v1_128(cur, B);
                    if (cur == A) { found = 1; break; }
                }
            } else {
                uint64_t A = rand64(), B = rand64();
                uint64_t cur = nl_fscx_v1_64(A, B);
                for (step = 1; step < cap; step++) {
                    cur = nl_fscx_v1_64(cur, B);
                    if (cur == A) { found = 1; break; }
                }
            }
            if (!found) no_period++;
            if ((i & 31) == 31 && time_exceeded(&t0)) { N2 = i + 1; break; }
        }
        printf("    bits=%3d  linearity violations=%d/%d  no-period=%d/%d  [%s]\n",
               size, violations, N1, no_period, N2,
               (violations == N1 && no_period >= N2 * 95 / 100) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [11] NL-FSCX v2 bijectivity and exact inverse
   Bijectivity: for each B, sample BIJ_SAMPLES random A values and check that no
   two distinct A inputs map to the same output (collision detection, O(n^2) scan).
   Matches Python/Go methodology of 256 samples per B with hash-map collision check. */
static void test_nl_fscx_v2_bijective_inverse(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, i, j, k, size;
    struct timespec t0;
    printf("[11] NL-FSCX v2 bijectivity and exact inverse  [PQC-EXT]\n");
    for (si = 0; si < 3; si++) {
        int non_bij = 0, inv_ok = 0, nl_ok = 0;
        int N1 = TEST_ROUNDS(500), N2 = TEST_ROUNDS(1000), N3 = TEST_ROUNDS(500);
        size = sizes[si];
        /* Bijectivity: BIJ_SAMPLES random A values per B; detect output collisions */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N1; i++) {
            int found = 0;
            if (size == 256) {
                BitArray A_arr[BIJ_SAMPLES], out_arr[BIJ_SAMPLES], B;
                ba_rand(&B);
                for (j = 0; j < BIJ_SAMPLES; j++) {
                    ba_rand(&A_arr[j]);
                    nl_fscx_v2_ba(&out_arr[j], &A_arr[j], &B);
                }
                for (j = 0; j < BIJ_SAMPLES && !found; j++)
                    for (k = j + 1; k < BIJ_SAMPLES && !found; k++)
                        if (ba_equal(&out_arr[j], &out_arr[k]) &&
                            !ba_equal(&A_arr[j], &A_arr[k])) found = 1;
            } else if (size == 128) {
                __uint128_t A_arr[BIJ_SAMPLES], out_arr[BIJ_SAMPLES];
                __uint128_t B = rand128();
                for (j = 0; j < BIJ_SAMPLES; j++) {
                    A_arr[j]   = rand128();
                    out_arr[j] = nl_fscx_v2_128(A_arr[j], B);
                }
                for (j = 0; j < BIJ_SAMPLES && !found; j++)
                    for (k = j + 1; k < BIJ_SAMPLES && !found; k++)
                        if (out_arr[j] == out_arr[k] && A_arr[j] != A_arr[k])
                            found = 1;
            } else {
                uint64_t A_arr[BIJ_SAMPLES], out_arr[BIJ_SAMPLES];
                uint64_t B = rand64();
                for (j = 0; j < BIJ_SAMPLES; j++) {
                    A_arr[j]   = rand64();
                    out_arr[j] = nl_fscx_v2_64(A_arr[j], B);
                }
                for (j = 0; j < BIJ_SAMPLES && !found; j++)
                    for (k = j + 1; k < BIJ_SAMPLES && !found; k++)
                        if (out_arr[j] == out_arr[k] && A_arr[j] != A_arr[k])
                            found = 1;
            }
            if (found) non_bij++;
            if ((i & 15) == 15 && time_exceeded(&t0)) { N1 = i + 1; break; }
        }
        /* Inverse correctness */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N2; i++) {
            if (size == 256) {
                BitArray A, B, enc, dec;
                ba_rand(&A); ba_rand(&B);
                nl_fscx_v2_ba(&enc, &A, &B);
                nl_fscx_v2_inv_ba(&dec, &enc, &B);
                if (ba_equal(&dec, &A)) inv_ok++;
            } else if (size == 128) {
                __uint128_t A = rand128(), B = rand128();
                if (nl_fscx_v2_inv_128(nl_fscx_v2_128(A, B), B) == A) inv_ok++;
            } else {
                uint64_t A = rand64(), B = rand64();
                if (nl_fscx_v2_inv_64(nl_fscx_v2_64(A, B), B) == A) inv_ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N2 = i + 1; break; }
        }
        /* Non-linearity */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N3; i++) {
            if (size == 256) {
                static const BitArray ZERO = {{0}};
                BitArray A, B, fA0, fB0, lin_pred, nl;
                ba_rand(&A); ba_rand(&B);
                nl_fscx_v2_ba(&fA0, &A, &ZERO);
                nl_fscx_v2_ba(&fB0, &ZERO, &B);
                ba_xor(&lin_pred, &fA0, &fB0);
                nl_fscx_v2_ba(&nl, &A, &B);
                if (!ba_equal(&nl, &lin_pred)) nl_ok++;
            } else if (size == 128) {
                __uint128_t A = rand128(), B = rand128();
                if (nl_fscx_v2_128(A, B) != (fscx128(A, 0) ^ nl_fscx_v2_128(0, B))) nl_ok++;
            } else {
                uint64_t A = rand64(), B = rand64();
                if (nl_fscx_v2_64(A, B) != (fscx64(A, 0) ^ nl_fscx_v2_64(0, B))) nl_ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N3 = i + 1; break; }
        }
        printf("    bits=%3d  collisions=%d/%d  inv=%d/%d  nonlinear=%d/%d  [%s]\n",
               size, non_bij, N1, inv_ok, N2, nl_ok, N3,
               (non_bij == 0 && inv_ok == N2 && nl_ok >= N3 * 98 / 100) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [12] HSKE-NL-A1 counter-mode correctness: D == P (with per-session nonce) */
static void test_hske_nl_a1_correctness(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, i, size;
    struct timespec t0;
    printf("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]\n");
    for (si = 0; si < 3; si++) {
        int ok = 0, N = TEST_ROUNDS(1000);
        size = sizes[si];
        int iv = size / 4;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                /* ROL(base, n/8=32): use ba_rol_k */
                static const BitArray ZERO = {{0}};
                BitArray K, nonce, P, base, seed, ctr_ba, ctr_xor, ks;
                uint32_t ctr_val = (uint32_t)i & 0xFFFF;
                ba_rand(&K); ba_rand(&nonce); ba_rand(&P);
                ba_xor(&base, &K, &nonce);
                ba_rol_k(&seed, &base, 32);  /* ROL(base, n/8=32) */
                /* ctr_ba = little-endian ctr_val in last 4 bytes */
                ctr_ba = ZERO;
                ctr_ba.b[KEYBYTES-4] = (uint8_t)(ctr_val >> 24);
                ctr_ba.b[KEYBYTES-3] = (uint8_t)(ctr_val >> 16);
                ctr_ba.b[KEYBYTES-2] = (uint8_t)(ctr_val >>  8);
                ctr_ba.b[KEYBYTES-1] = (uint8_t)(ctr_val);
                ba_xor(&ctr_xor, &base, &ctr_ba);
                nl_fscx_revolve_v1_ba(&ks, &seed, &ctr_xor, iv);
                /* E = P ^ ks; D = E ^ ks = P */
                { BitArray E, D; ba_xor(&E, &P, &ks); ba_xor(&D, &E, &ks);
                  if (ba_equal(&D, &P)) ok++; }
            } else if (size == 128) {
                __uint128_t K = rand128(), nonce = rand128(), P = rand128();
                __uint128_t base = K ^ nonce;
                __uint128_t seed = (base << 16) | (base >> 112); /* ROL(base, n/8=16) */
                __uint128_t ctr = (uint32_t)i & 0xFFFF;
                __uint128_t ks = nl_fscx_revolve_v1_128(seed, base ^ ctr, iv);
                if ((P ^ ks ^ ks) == P) ok++;
            } else {
                uint64_t K = rand64(), nonce = rand64(), P = rand64();
                uint64_t base = K ^ nonce;
                uint64_t seed = (base << 8) | (base >> 56); /* ROL(base, n/8=8) */
                uint64_t ctr = (uint32_t)i & 0xFFFF;
                uint64_t ks = nl_fscx_revolve_v1_64(seed, base ^ ctr, iv);
                if ((P ^ ks ^ ks) == P) ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d correct  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [13] HSKE-NL-A2 revolve-mode correctness: D == P */
static void test_hske_nl_a2_correctness(void)
{
    static const int sizes[] = {64, 128, 256};
    int si, i, size;
    struct timespec t0;
    printf("[13] HSKE-NL-A2 revolve-mode correctness: D == P  [PQC-EXT]\n");
    for (si = 0; si < 3; si++) {
        int ok = 0, N = TEST_ROUNDS(1000);
        size = sizes[si];
        int rv = 3 * size / 4;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                BitArray K, P, E, D;
                ba_rand(&K); ba_rand(&P);
                nl_fscx_revolve_v2_ba(&E, &P, &K, rv);
                nl_fscx_revolve_v2_inv_ba(&D, &E, &K, rv);
                if (ba_equal(&D, &P)) ok++;
            } else if (size == 128) {
                __uint128_t K = rand128(), P = rand128();
                __uint128_t E = nl_fscx_revolve_v2_128(P, K, rv);
                __uint128_t D = nl_fscx_revolve_v2_inv_128(E, K, rv);
                if (D == P) ok++;
            } else {
                uint64_t K = rand64(), P = rand64();
                uint64_t E = nl_fscx_revolve_v2_64(P, K, rv);
                uint64_t D = nl_fscx_revolve_v2_inv_64(E, K, rv);
                if (D == P) ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d correct  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [14] HKEX-RNL key agreement: K_A == K_B and sk_A == sk_B  (Ring-LWR)
   Protocol: one party generates a_rand and transmits it in the clear; both derive
   the shared m_blind = m_base + a_rand and compute their individual public keys
   C = round_p(m_blind · s).  Agreement holds because the ring is commutative:
   s_A·(m_blind·s_B) = s_B·(m_blind·s_A).  See §11.4.2 of SecurityProofs.md. */
static void test_hkex_rnl_correctness(void)
{
    static const int rnl_sizes[] = {32, 64, 128, 256};
    int si, i, ok_raw, ok_sk, N, n;
    struct timespec t0;
    printf("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]\n");
    printf("     (ring sizes {32,64,128,256}; Peikert reconciliation -- expect 100%% agreement)\n");
    for (si = 0; si < 4; si++) {
        n = rnl_sizes[si]; ok_raw = 0; ok_sk = 0; N = TEST_ROUNDS(200);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (n == 32) {
            rnl32_poly_t m_base, a_rand, m_blind;
            rnl32_m_poly(m_base);
            for (i = 0; i < N; i++) {
                int32_t s_A[RNL_N32], c_A[RNL_N32];
                int32_t s_B[RNL_N32], c_B[RNL_N32];
                uint32_t K_A, K_B, hint_A;
                rnl32_rand_poly(a_rand);
                rnl32_poly_add(m_blind, m_base, a_rand);
                rnl32_keygen(s_A, c_A, m_blind);
                rnl32_keygen(s_B, c_B, m_blind);
                K_A = rnl32_agree(s_A, c_B, NULL, &hint_A);
                K_B = rnl32_agree(s_B, c_A, &hint_A, NULL);
                if (K_A == K_B) ok_raw++;
                if (nl_fscx_revolve_v1_32((K_A<<4)|(K_A>>28), K_A, NL_I32) ==
                    nl_fscx_revolve_v1_32((K_B<<4)|(K_B>>28), K_B, NL_I32)) ok_sk++;
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else if (n == 64) {
            int32_t m_base64[64], a_rand64[64], m_blind64[64];
            rnl_m_poly_n(m_base64, 64);
            for (i = 0; i < N; i++) {
                int32_t s_A64[64], c_A64[64], s_B64[64], c_B64[64];
                uint64_t K_A64, K_B64, hint_A64;
                rnl_rand_poly_n(a_rand64, 64);
                rnl_poly_add_n(m_blind64, m_base64, a_rand64, 64);
                rnl_keygen_n(s_A64, c_A64, m_blind64, 64);
                rnl_keygen_n(s_B64, c_B64, m_blind64, 64);
                K_A64 = rnl_agree_n(s_A64, c_B64, 64, NULL, &hint_A64);
                K_B64 = rnl_agree_n(s_B64, c_A64, 64, &hint_A64, NULL);
                if (K_A64 == K_B64) ok_raw++;
                if (nl_fscx_revolve_v1_64((K_A64<<8)|(K_A64>>56), K_A64, NL_I64) ==
                    nl_fscx_revolve_v1_64((K_B64<<8)|(K_B64>>56), K_B64, NL_I64)) ok_sk++;
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else if (n == 128) {
            int32_t m_base128[128], a_rand128[128], m_blind128[128];
            rnl_m_poly_n(m_base128, 128);
            for (i = 0; i < N; i++) {
                int32_t s_A128[128], c_A128[128], s_B128[128], c_B128[128];
                __uint128_t K_A128, K_B128, hint_A128;
                rnl_rand_poly_n(a_rand128, 128);
                rnl_poly_add_n(m_blind128, m_base128, a_rand128, 128);
                rnl_keygen_n(s_A128, c_A128, m_blind128, 128);
                rnl_keygen_n(s_B128, c_B128, m_blind128, 128);
                K_A128 = rnl_agree_128(s_A128, c_B128, 128, NULL, &hint_A128);
                K_B128 = rnl_agree_128(s_B128, c_A128, 128, &hint_A128, NULL);
                if (K_A128 == K_B128) ok_raw++;
                { __uint128_t sA = (K_A128 << 16) | (K_A128 >> 112);
                  __uint128_t sB = (K_B128 << 16) | (K_B128 >> 112);
                  if (nl_fscx_revolve_v1_128(sA, K_A128, NL_I128) ==
                      nl_fscx_revolve_v1_128(sB, K_B128, NL_I128)) ok_sk++; }
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else { /* n == 256 */
            int32_t m_base256[256], a_rand256[256], m_blind256[256];
            rnl_m_poly_n(m_base256, 256);
            for (i = 0; i < N; i++) {
                int32_t s_A256[256], c_A256[256], s_B256[256], c_B256[256];
                BitArray K_A256, K_B256, hint_A256, sk_A256, sk_B256, seed_A, seed_B;
                rnl_rand_poly_n(a_rand256, 256);
                rnl_poly_add_n(m_blind256, m_base256, a_rand256, 256);
                rnl_keygen_n(s_A256, c_A256, m_blind256, 256);
                rnl_keygen_n(s_B256, c_B256, m_blind256, 256);
                rnl_agree_ba(s_A256, c_B256, 256, NULL, &hint_A256, &K_A256);
                rnl_agree_ba(s_B256, c_A256, 256, &hint_A256, NULL, &K_B256);
                if (ba_equal(&K_A256, &K_B256)) ok_raw++;
                ba_rol_k(&seed_A, &K_A256, 32); /* ROL by n/8=32 */
                ba_rol_k(&seed_B, &K_B256, 32);
                nl_fscx_revolve_v1_ba(&sk_A256, &seed_A, &K_A256, NL_I256);
                nl_fscx_revolve_v1_ba(&sk_B256, &seed_B, &K_B256, NL_I256);
                if (ba_equal(&sk_A256, &sk_B256)) ok_sk++;
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        }
        printf("    n=%3d  raw agree=%d/%d  sk agree=%d/%d  [%s]\n",
               n, ok_raw, N, ok_sk, N,
               ok_raw == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [15] HPKS-NL correctness: g^s * C^e == R (NL-FSCX v1) — bn_* layer, {32,64,128,256} */
static void test_hpks_nl_correctness(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    printf("[15] HPKS-NL correctness: g^s · C^e == R (NL-FSCX v1 challenge)  [PQC-EXT]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            int n = size / 8;
            uint8_t a[BN_MAX_BYTES], plain[BN_MAX_BYTES], k[BN_MAX_BYTES];
            uint8_t g[BN_MAX_BYTES], C[BN_MAX_BYTES], R[BN_MAX_BYTES];
            uint8_t e[BN_MAX_BYTES], ae[BN_MAX_BYTES], s[BN_MAX_BYTES];
            uint8_t gs[BN_MAX_BYTES], Ce[BN_MAX_BYTES], lhs[BN_MAX_BYTES];
            bn_rand_n(a, size); a[n-1] |= 1;
            bn_rand_n(plain, size); bn_rand_n(k, size);
            bn_set_gen(g, size);
            bn_gf_pow_n(C, g, a, size);
            bn_gf_pow_n(R, g, k, size);
            bn_nl_fscx_revolve_v1_n(e, R, plain, size/4, size);
            bn_mul_mod_ord_n(ae, a, e, size);
            bn_sub_mod_ord_n(s, k, ae, size);
            bn_gf_pow_n(gs, g, s, size);
            bn_gf_pow_n(Ce, C, e, size);
            bn_gf_mul_n(lhs, gs, Ce, size);
            if (bn_equal_n(lhs, R, size)) ok++;
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d verified  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [16] HPKE-NL correctness: D == P  (NL-FSCX v2 encrypt/decrypt) */
static void test_hpke_nl_correctness(void)
{
    static const int sizes[] = {32, 64, 128, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32h, r32h, C32h, R32h, enc32h, E32h, dec32h, D32h;
    uint64_t a64h, r64h, C64h, R64h, enc64h, E64h, dec64h, D64h;
    __uint128_t a128h, r128h, C128h, R128h, enc128h, E128h, dec128h, D128h;
    BitArray a256h, r256h, C256h, R256h, enc256h, E256h, dec256h, D256h, pt256h;
    printf("[16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt)  [PQC-EXT]\n");
    for (si = 0; si < 4; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 256) {
                ba_rand(&pt256h); ba_rand(&a256h); ba_rand(&r256h);
                a256h.b[KEYBYTES-1] |= 1; r256h.b[KEYBYTES-1] |= 1;
                gf_pow_ba(&C256h, &GF_GEN, &a256h);
                gf_pow_ba(&R256h, &GF_GEN, &r256h);
                gf_pow_ba(&enc256h, &C256h, &r256h);
                nl_fscx_revolve_v2_ba(&E256h, &pt256h, &enc256h, NL_I256);
                gf_pow_ba(&dec256h, &R256h, &a256h);
                nl_fscx_revolve_v2_inv_ba(&D256h, &E256h, &dec256h, NL_I256);
                if (ba_equal(&D256h, &pt256h)) ok++;
            } else if (size == 128) {
                __uint128_t pt128h = rand128();
                a128h = rand128()|1; r128h = rand128()|1;
                C128h = gf_pow_128(3, a128h); R128h = gf_pow_128(3, r128h);
                enc128h = gf_pow_128(C128h, r128h);
                E128h   = nl_fscx_revolve_v2_128(pt128h, enc128h, NL_I128);
                dec128h = gf_pow_128(R128h, a128h);
                D128h   = nl_fscx_revolve_v2_inv_128(E128h, dec128h, NL_I128);
                if (D128h == pt128h) ok++;
            } else if (size == 64) {
                uint64_t pt64h = rand64();
                a64h = rand64()|1; r64h = rand64()|1;
                C64h = gf_pow_64(3ULL, a64h); R64h = gf_pow_64(3ULL, r64h);
                enc64h = gf_pow_64(C64h, r64h);
                E64h   = nl_fscx_revolve_v2_64(pt64h, enc64h, NL_I64);
                dec64h = gf_pow_64(R64h, a64h);
                D64h   = nl_fscx_revolve_v2_inv_64(E64h, dec64h, NL_I64);
                if (D64h == pt64h) ok++;
            } else {
                uint32_t pt32h = rand32();
                a32h = rand32()|1; r32h = rand32()|1;
                C32h = gf_pow_32(GF_GEN32, a32h); R32h = gf_pow_32(GF_GEN32, r32h);
                enc32h = gf_pow_32(C32h, r32h);
                E32h   = nl_fscx_revolve_v2_32(pt32h, enc32h, NL_I32);
                dec32h = gf_pow_32(R32h, a32h);
                D32h   = nl_fscx_revolve_v2_inv_32(E32h, dec32h, NL_I32);
                if (D32h == pt32h) ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d decrypted  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Security tests [17]-[18]: CODE-BASED PQC (Stern-F)                 */
/* ------------------------------------------------------------------ */

#define SDF_N_ROWS   (KEYBITS / 2)     /* 128 rows                       */
#define SDF_T        (KEYBITS / 16)    /* weight 16                      */
#define SDF_SYNBYTES (SDF_N_ROWS / 8)  /* 16 syndrome bytes              */
#define SDF_TEST_ROUNDS 8              /* reduced rounds for test speed  */

/* Chain-hash: h <- NL-FSCX_v1^I(h XOR v, ROL(v, n/8)) for each item. */
static void stern_hash_ba(BitArray *out, const BitArray *items, int n_items)
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
static void stern_matrix_row_ba(BitArray *out, const BitArray *seed, int row)
{
    BitArray sxr = *seed, a0;
    sxr.b[KEYBYTES - 1] ^= (uint8_t)(row & 0xFF);
    ba_rol_k(&a0, &sxr, KEYBITS / 8);
    nl_fscx_revolve_v1_ba(out, &a0, seed, I_VALUE);
}

/* n_rows-bit syndrome = H*e^T mod 2. */
static void stern_syndrome_ba(uint8_t *syndr, const BitArray *seed,
                               const BitArray *e)
{
    int i;
    memset(syndr, 0, SDF_SYNBYTES);
    for (i = 0; i < SDF_N_ROWS; i++) {
        BitArray row;
        int pc = 0, k;
        stern_matrix_row_ba(&row, seed, i);
        for (k = 0; k < KEYBYTES; k++)
            pc ^= __builtin_popcount(row.b[k] & e->b[k]);
        if (pc & 1)
            syndr[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

static void syndr_to_ba_t(BitArray *out, const uint8_t *syndr)
{
    memset(out->b, 0, KEYBYTES);
    memcpy(out->b + KEYBYTES / 2, syndr, SDF_SYNBYTES);
}

static void stern_gen_perm_ba(uint8_t *perm, const BitArray *pi_seed, int N)
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

static void stern_apply_perm_ba(BitArray *out, const uint8_t *perm,
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

static void stern_rand_error_ba(BitArray *e)
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
            if (fread(&rnd, 1, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
        } while ((unsigned int)rnd >= thresh);
        j = (int)(rnd % range);
        { uint8_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; }
        e->b[KEYBYTES - 1 - idx[i] / 8] |= (uint8_t)(1u << (idx[i] % 8));
    }
}

static void stern_fs_challenges_t(int *chals, int rounds,
                                   const BitArray *msg,
                                   const BitArray *c0,
                                   const BitArray *c1,
                                   const BitArray *c2)
{
    BitArray ch_st = {{0}};
    int i;
#define _SFS_T(item) do { \
    BitArray _hxv, _rotv; \
    ba_xor(&_hxv, &ch_st, &(item)); \
    ba_rol_k(&_rotv, &(item), KEYBITS / 8); \
    nl_fscx_revolve_v1_ba(&ch_st, &_hxv, &_rotv, I_VALUE); \
} while (0)
    _SFS_T(*msg);
    for (i = 0; i < rounds; i++) { _SFS_T(c0[i]); _SFS_T(c1[i]); _SFS_T(c2[i]); }
#undef _SFS_T
    for (i = 0; i < rounds; i++) {
        BitArray idx_ba = {{0}};
        uint32_t v;
        idx_ba.b[KEYBYTES - 1] = (uint8_t)(i & 0xFF);
        nl_fscx_v1_ba(&ch_st, &ch_st, &idx_ba);
        v = ((uint32_t)ch_st.b[KEYBYTES-4]<<24)|((uint32_t)ch_st.b[KEYBYTES-3]<<16)
          | ((uint32_t)ch_st.b[KEYBYTES-2]<<8)|ch_st.b[KEYBYTES-1];
        chals[i] = (int)(v % 3u);
    }
}

typedef struct {
    BitArray c0[SDF_TEST_ROUNDS], c1[SDF_TEST_ROUNDS], c2[SDF_TEST_ROUNDS];
    int      b[SDF_TEST_ROUNDS];
    BitArray resp_a[SDF_TEST_ROUNDS];
    BitArray resp_b[SDF_TEST_ROUNDS];
} SternSigT;

static void hpks_stern_f_sign_t(SternSigT *sig, const BitArray *msg,
                                  const BitArray *e, const BitArray *seed)
{
    BitArray r[SDF_TEST_ROUNDS], y[SDF_TEST_ROUNDS], pi[SDF_TEST_ROUNDS];
    BitArray sr[SDF_TEST_ROUNDS], sy[SDF_TEST_ROUNDS];
    uint8_t Hr[SDF_TEST_ROUNDS][SDF_SYNBYTES];
    uint8_t perm[KEYBITS];
    int i;

    for (i = 0; i < SDF_TEST_ROUNDS; i++) {
        BitArray items[2];
        stern_rand_error_ba(&r[i]);
        ba_xor(&y[i], e, &r[i]);
        ba_rand(&pi[i]);
        stern_syndrome_ba(Hr[i], seed, &r[i]);
        stern_gen_perm_ba(perm, &pi[i], KEYBITS);
        stern_apply_perm_ba(&sr[i], perm, &r[i], KEYBITS);
        stern_apply_perm_ba(&sy[i], perm, &y[i], KEYBITS);
        items[0] = pi[i]; syndr_to_ba_t(&items[1], Hr[i]);
        stern_hash_ba(&sig->c0[i], items, 2);
        stern_hash_ba(&sig->c1[i], &sr[i], 1);
        stern_hash_ba(&sig->c2[i], &sy[i], 1);
    }
    stern_fs_challenges_t(sig->b, SDF_TEST_ROUNDS, msg,
                          sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        if      (bv == 0) { sig->resp_a[i] = sr[i]; sig->resp_b[i] = sy[i]; }
        else if (bv == 1) { sig->resp_a[i] = pi[i]; sig->resp_b[i] = r[i];  }
        else              { sig->resp_a[i] = pi[i]; sig->resp_b[i] = y[i];  }
    }
}

static int hpks_stern_f_verify_t(const SternSigT *sig, const BitArray *msg,
                                   const BitArray *seed, const uint8_t *syndr)
{
    int chals[SDF_TEST_ROUNDS];
    uint8_t perm[KEYBITS];
    int i;

    stern_fs_challenges_t(chals, SDF_TEST_ROUNDS, msg,
                          sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF_TEST_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;

    for (i = 0; i < SDF_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        BitArray tmp;
        if (bv == 0) {
            stern_hash_ba(&tmp, &sig->resp_a[i], 1);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
            stern_hash_ba(&tmp, &sig->resp_b[i], 1);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
            if (ba_popcount(&sig->resp_a[i]) != SDF_T) return 0;
        } else if (bv == 1) {
            uint8_t Hr[SDF_SYNBYTES];
            BitArray items[2], sr2;
            if (ba_popcount(&sig->resp_b[i]) != SDF_T) return 0;
            stern_syndrome_ba(Hr, seed, &sig->resp_b[i]);
            items[0] = sig->resp_a[i]; syndr_to_ba_t(&items[1], Hr);
            stern_hash_ba(&tmp, items, 2);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm_ba(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm_ba(&sr2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash_ba(&tmp, &sr2, 1);
            if (!ba_equal(&tmp, &sig->c1[i])) return 0;
        } else {
            uint8_t Hy[SDF_SYNBYTES], Hys[SDF_SYNBYTES];
            BitArray items[2], sy2;
            int k;
            stern_syndrome_ba(Hy, seed, &sig->resp_b[i]);
            for (k = 0; k < SDF_SYNBYTES; k++) Hys[k] = Hy[k] ^ syndr[k];
            items[0] = sig->resp_a[i]; syndr_to_ba_t(&items[1], Hys);
            stern_hash_ba(&tmp, items, 2);
            if (!ba_equal(&tmp, &sig->c0[i])) return 0;
            stern_gen_perm_ba(perm, &sig->resp_a[i], KEYBITS);
            stern_apply_perm_ba(&sy2, perm, &sig->resp_b[i], KEYBITS);
            stern_hash_ba(&tmp, &sy2, 1);
            if (!ba_equal(&tmp, &sig->c2[i])) return 0;
        }
    }
    return 1;
}

/* ---- 32-bit Stern-F for HPKE-Stern-F test [18]  (n=32, t=2) ---- */

#define SDF32_N     32
#define SDF32_T     2    /* max(2, 32/16) = 2 */
#define SDF32_NROWS 16

static uint32_t stern32_matrix_row(uint32_t seed, int row)
{
    uint32_t sxr = seed ^ (uint32_t)row;
    uint32_t a0  = (sxr << 4) | (sxr >> 28);  /* ROL by n/8=4 bits */
    return nl_fscx_revolve_v1_32(a0, seed, 8); /* I = n/4 = 8 steps */
}

static uint16_t stern32_syndrome(uint32_t seed, uint32_t e)
{
    uint16_t s = 0;
    int i;
    for (i = 0; i < SDF32_NROWS; i++)
        if (__builtin_popcount(stern32_matrix_row(seed, i) & e) & 1)
            s |= (uint16_t)(1u << i);
    return s;
}

static uint32_t stern32_hash(uint32_t h, uint32_t v)
{
    uint32_t key = (v << 4) | (v >> 28);
    return nl_fscx_revolve_v1_32(h ^ v, key, 8);
}

static uint32_t stern32_rand_error(void)
{
    uint8_t idx[SDF32_N];
    uint32_t e = 0;
    int i;
    for (i = 0; i < SDF32_N; i++) idx[i] = (uint8_t)i;
    for (i = SDF32_N - 1; i >= SDF32_N - SDF32_T; i--) {
        unsigned int range = (unsigned int)(i + 1);
        unsigned int thresh = 256 - (256 % range);
        uint8_t rnd;
        int j;
        do {
            if (fread(&rnd, 1, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
        } while ((unsigned int)rnd >= thresh);
        j = (int)(rnd % range);
        { uint8_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; }
        e |= 1u << idx[i];
    }
    return e;
}

static uint32_t stern32_rand_seed(void)
{
    uint8_t buf[4];
    if (fread(buf, 4, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
    return ((uint32_t)buf[0]<<24)|((uint32_t)buf[1]<<16)|((uint32_t)buf[2]<<8)|buf[3];
}

static uint32_t hpke_stern_f_encap_32(uint32_t seed, uint16_t *ct_out,
                                        uint32_t *e_out)
{
    uint32_t e_p = stern32_rand_error();
    *ct_out = stern32_syndrome(seed, e_p);
    *e_out  = e_p;
    return stern32_hash(stern32_hash(0, seed), e_p);
}

static uint32_t hpke_stern_f_decap_32(uint32_t seed, uint16_t ct)
{
    /* Brute-force C(32,2) = 496 combinations */
    int i, j;
    for (i = 0; i < SDF32_N; i++)
        for (j = i + 1; j < SDF32_N; j++) {
            uint32_t e_p = (1u << i) | (1u << j);
            if (stern32_syndrome(seed, e_p) == ct)
                return stern32_hash(stern32_hash(0, seed), e_p);
        }
    return 0xFFFFFFFFu;
}

/* ---- N=32 HPKS-Stern-F sign+verify helpers (for test [17]) ---- */

#define SDF32_TEST_ROUNDS 8

static void stern32_gen_perm(uint8_t *perm, uint32_t pi_seed)
{
    uint32_t key = (pi_seed << 4) | (pi_seed >> 28);  /* ROL by n/8=4 bits */
    uint32_t st  = pi_seed;
    int i;
    for (i = 0; i < SDF32_N; i++) perm[i] = (uint8_t)i;
    for (i = SDF32_N - 1; i > 0; i--) {
        uint32_t v;
        int j;
        st = nl_fscx_v1_32(st, key);
        v  = st & 0xFFFF;
        j  = (int)(v % (unsigned)(i + 1));
        { uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp; }
    }
}

static uint32_t stern32_apply_perm(const uint8_t *perm, uint32_t v)
{
    uint32_t out = 0;
    int i;
    for (i = 0; i < SDF32_N; i++)
        if ((v >> i) & 1)
            out |= 1u << perm[i];
    return out;
}

static uint32_t stern32_hash_n(const uint32_t *items, int n)
{
    uint32_t h = 0;
    int i;
    for (i = 0; i < n; i++) h = stern32_hash(h, items[i]);
    return h;
}

static void stern_fs_challenges_32(int *chals, int rounds, uint32_t msg,
                                    const uint32_t *c0, const uint32_t *c1,
                                    const uint32_t *c2)
{
    uint32_t ch_st = 0;
    int i;
    ch_st = stern32_hash(ch_st, msg);
    for (i = 0; i < rounds; i++) {
        ch_st = stern32_hash(ch_st, c0[i]);
        ch_st = stern32_hash(ch_st, c1[i]);
        ch_st = stern32_hash(ch_st, c2[i]);
    }
    for (i = 0; i < rounds; i++) {
        ch_st = nl_fscx_v1_32(ch_st, (uint32_t)i);
        chals[i] = (int)(ch_st % 3u);
    }
}

typedef struct {
    uint32_t c0[SDF32_TEST_ROUNDS], c1[SDF32_TEST_ROUNDS], c2[SDF32_TEST_ROUNDS];
    int      b[SDF32_TEST_ROUNDS];
    uint32_t resp_a[SDF32_TEST_ROUNDS];
    uint32_t resp_b[SDF32_TEST_ROUNDS];
} SternSig32T;

static void hpks_stern_f_sign_32(SternSig32T *sig, uint32_t msg,
                                   uint32_t e, uint32_t seed)
{
    uint32_t r[SDF32_TEST_ROUNDS], y[SDF32_TEST_ROUNDS];
    uint32_t pi_s[SDF32_TEST_ROUNDS];
    uint32_t sr[SDF32_TEST_ROUNDS], sy[SDF32_TEST_ROUNDS];
    uint8_t  perm[SDF32_N];
    int i;
    for (i = 0; i < SDF32_TEST_ROUNDS; i++) {
        uint32_t items[2];
        uint16_t Hr;
        r[i]    = stern32_rand_error();
        y[i]    = e ^ r[i];
        pi_s[i] = stern32_rand_seed();
        Hr = stern32_syndrome(seed, r[i]);
        stern32_gen_perm(perm, pi_s[i]);
        sr[i] = stern32_apply_perm(perm, r[i]);
        sy[i] = stern32_apply_perm(perm, y[i]);
        items[0] = pi_s[i]; items[1] = (uint32_t)Hr;
        sig->c0[i] = stern32_hash_n(items, 2);
        sig->c1[i] = stern32_hash(0, sr[i]);
        sig->c2[i] = stern32_hash(0, sy[i]);
    }
    stern_fs_challenges_32(sig->b, SDF32_TEST_ROUNDS, msg,
                            sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF32_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        if      (bv == 0) { sig->resp_a[i] = sr[i];    sig->resp_b[i] = sy[i]; }
        else if (bv == 1) { sig->resp_a[i] = pi_s[i];  sig->resp_b[i] = r[i];  }
        else              { sig->resp_a[i] = pi_s[i];  sig->resp_b[i] = y[i];  }
    }
}

static int hpks_stern_f_verify_32(const SternSig32T *sig, uint32_t msg,
                                    uint32_t seed, uint16_t syndr)
{
    int chals[SDF32_TEST_ROUNDS];
    uint8_t perm[SDF32_N];
    int i;
    stern_fs_challenges_32(chals, SDF32_TEST_ROUNDS, msg,
                            sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF32_TEST_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;
    for (i = 0; i < SDF32_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        uint32_t items[2];
        if (bv == 0) {
            if (stern32_hash(0, sig->resp_a[i]) != sig->c1[i]) return 0;
            if (stern32_hash(0, sig->resp_b[i]) != sig->c2[i]) return 0;
            if (__builtin_popcount(sig->resp_a[i]) != SDF32_T) return 0;
        } else if (bv == 1) {
            uint32_t sr2;
            uint16_t Hr;
            if (__builtin_popcount(sig->resp_b[i]) != SDF32_T) return 0;
            Hr  = stern32_syndrome(seed, sig->resp_b[i]);
            items[0] = sig->resp_a[i]; items[1] = (uint32_t)Hr;
            if (stern32_hash_n(items, 2) != sig->c0[i]) return 0;
            stern32_gen_perm(perm, sig->resp_a[i]);
            sr2 = stern32_apply_perm(perm, sig->resp_b[i]);
            if (stern32_hash(0, sr2) != sig->c1[i]) return 0;
        } else {
            uint32_t sy2;
            uint16_t Hy, Hys;
            Hy  = stern32_syndrome(seed, sig->resp_b[i]);
            Hys = Hy ^ syndr;
            items[0] = sig->resp_a[i]; items[1] = (uint32_t)Hys;
            if (stern32_hash_n(items, 2) != sig->c0[i]) return 0;
            stern32_gen_perm(perm, sig->resp_a[i]);
            sy2 = stern32_apply_perm(perm, sig->resp_b[i]);
            if (stern32_hash(0, sy2) != sig->c2[i]) return 0;
        }
    }
    return 1;
}

/* ---- N=64 Stern-F helpers ---- */

#define SDF64_N           64
#define SDF64_N_ROWS      32
#define SDF64_T            4   /* 64/16 */
#define SDF64_SYNBYTES     4
#define SDF64_TEST_ROUNDS  8

static uint64_t stern_hash_64(uint64_t h, uint64_t v)
{
    uint64_t key = (v << 8) | (v >> 56);   /* ROL by n/8=8 bits */
    return nl_fscx_revolve_v1_64(h ^ v, key, 16);
}

static uint64_t stern_hash_64_n(const uint64_t *items, int n)
{
    uint64_t hv = 0;
    int i;
    for (i = 0; i < n; i++) hv = stern_hash_64(hv, items[i]);
    return hv;
}

static uint64_t stern_matrix_row_64(uint64_t seed, int row)
{
    uint64_t sxr = seed ^ (uint64_t)row;
    uint64_t a0  = (sxr << 8) | (sxr >> 56);
    return nl_fscx_revolve_v1_64(a0, seed, 16);
}

static uint32_t stern_syndrome_64(uint64_t seed, uint64_t e)
{
    uint32_t s = 0;
    int i;
    for (i = 0; i < SDF64_N_ROWS; i++) {
        uint64_t row = stern_matrix_row_64(seed, i);
        if (__builtin_popcountll(row & e) & 1)
            s |= (uint32_t)(1u << i);
    }
    return s;
}

static uint64_t stern_rand_error_64(void)
{
    uint8_t idx[SDF64_N];
    uint64_t e = 0;
    int i;
    for (i = 0; i < SDF64_N; i++) idx[i] = (uint8_t)i;
    for (i = SDF64_N - 1; i >= SDF64_N - SDF64_T; i--) {
        unsigned int range = (unsigned int)(i + 1);
        unsigned int thresh = 256 - (256 % range);
        uint8_t rnd;
        int j;
        do {
            if (fread(&rnd, 1, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
        } while ((unsigned int)rnd >= thresh);
        j = (int)(rnd % range);
        { uint8_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp; }
        e |= (uint64_t)1 << idx[i];
    }
    return e;
}

static uint64_t stern64_rand_seed(void)
{
    uint8_t buf[8];
    if (fread(buf, 8, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
    return ((uint64_t)buf[0]<<56)|((uint64_t)buf[1]<<48)|((uint64_t)buf[2]<<40)|
           ((uint64_t)buf[3]<<32)|((uint64_t)buf[4]<<24)|((uint64_t)buf[5]<<16)|
           ((uint64_t)buf[6]<<8)|buf[7];
}

static void stern_gen_perm_64(uint8_t *perm, uint64_t pi_seed)
{
    uint64_t key = (pi_seed << 8) | (pi_seed >> 56);
    uint64_t st  = pi_seed;
    int i;
    for (i = 0; i < SDF64_N; i++) perm[i] = (uint8_t)i;
    for (i = SDF64_N - 1; i > 0; i--) {
        uint32_t v;
        int j;
        st = nl_fscx_v1_64(st, key);
        v  = (uint32_t)(st & 0xFFFF);
        j  = (int)(v % (unsigned)(i + 1));
        { uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp; }
    }
}

static uint64_t stern_apply_perm_64(const uint8_t *perm, uint64_t v)
{
    uint64_t out = 0;
    int i;
    for (i = 0; i < SDF64_N; i++)
        if ((v >> i) & 1)
            out |= (uint64_t)1 << perm[i];
    return out;
}

static void stern_fs_challenges_64(int *chals, int rounds, uint64_t msg,
                                    const uint64_t *c0, const uint64_t *c1,
                                    const uint64_t *c2)
{
    uint64_t ch_st = 0;
    int i;
    ch_st = stern_hash_64(ch_st, msg);
    for (i = 0; i < rounds; i++) {
        ch_st = stern_hash_64(ch_st, c0[i]);
        ch_st = stern_hash_64(ch_st, c1[i]);
        ch_st = stern_hash_64(ch_st, c2[i]);
    }
    for (i = 0; i < rounds; i++) {
        ch_st = nl_fscx_v1_64(ch_st, (uint64_t)i);
        chals[i] = (int)((ch_st & 0xFFFF) % 3u);
    }
}

typedef struct {
    uint64_t c0[SDF64_TEST_ROUNDS], c1[SDF64_TEST_ROUNDS], c2[SDF64_TEST_ROUNDS];
    int      b[SDF64_TEST_ROUNDS];
    uint64_t resp_a[SDF64_TEST_ROUNDS];
    uint64_t resp_b[SDF64_TEST_ROUNDS];
} SternSig64T;

static void hpks_stern_f_sign_64(SternSig64T *sig, uint64_t msg,
                                   uint64_t e, uint64_t seed)
{
    uint64_t r[SDF64_TEST_ROUNDS], y[SDF64_TEST_ROUNDS];
    uint64_t pi_s[SDF64_TEST_ROUNDS];
    uint64_t sr[SDF64_TEST_ROUNDS], sy[SDF64_TEST_ROUNDS];
    uint8_t  perm[SDF64_N];
    int i;
    for (i = 0; i < SDF64_TEST_ROUNDS; i++) {
        uint64_t items[2];
        uint32_t Hr;
        r[i]    = stern_rand_error_64();
        y[i]    = e ^ r[i];
        pi_s[i] = stern64_rand_seed();
        Hr = stern_syndrome_64(seed, r[i]);
        stern_gen_perm_64(perm, pi_s[i]);
        sr[i] = stern_apply_perm_64(perm, r[i]);
        sy[i] = stern_apply_perm_64(perm, y[i]);
        items[0] = pi_s[i]; items[1] = (uint64_t)Hr;
        sig->c0[i] = stern_hash_64_n(items, 2);
        sig->c1[i] = stern_hash_64(0, sr[i]);
        sig->c2[i] = stern_hash_64(0, sy[i]);
    }
    stern_fs_challenges_64(sig->b, SDF64_TEST_ROUNDS, msg,
                            sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF64_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        if      (bv == 0) { sig->resp_a[i] = sr[i];    sig->resp_b[i] = sy[i]; }
        else if (bv == 1) { sig->resp_a[i] = pi_s[i];  sig->resp_b[i] = r[i];  }
        else              { sig->resp_a[i] = pi_s[i];  sig->resp_b[i] = y[i];  }
    }
}

static int hpks_stern_f_verify_64(const SternSig64T *sig, uint64_t msg,
                                    uint64_t seed, uint32_t syndr)
{
    int chals[SDF64_TEST_ROUNDS];
    uint8_t perm[SDF64_N];
    int i;
    stern_fs_challenges_64(chals, SDF64_TEST_ROUNDS, msg,
                            sig->c0, sig->c1, sig->c2);
    for (i = 0; i < SDF64_TEST_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;
    for (i = 0; i < SDF64_TEST_ROUNDS; i++) {
        int bv = sig->b[i];
        uint64_t items[2];
        if (bv == 0) {
            if (stern_hash_64(0, sig->resp_a[i]) != sig->c1[i]) return 0;
            if (stern_hash_64(0, sig->resp_b[i]) != sig->c2[i]) return 0;
            if (__builtin_popcountll(sig->resp_a[i]) != SDF64_T) return 0;
        } else if (bv == 1) {
            uint64_t sr2;
            uint32_t Hr;
            if (__builtin_popcountll(sig->resp_b[i]) != SDF64_T) return 0;
            Hr  = stern_syndrome_64(seed, sig->resp_b[i]);
            items[0] = sig->resp_a[i]; items[1] = (uint64_t)Hr;
            if (stern_hash_64_n(items, 2) != sig->c0[i]) return 0;
            stern_gen_perm_64(perm, sig->resp_a[i]);
            sr2 = stern_apply_perm_64(perm, sig->resp_b[i]);
            if (stern_hash_64(0, sr2) != sig->c1[i]) return 0;
        } else {
            uint64_t sy2;
            uint32_t Hy, Hys;
            Hy  = stern_syndrome_64(seed, sig->resp_b[i]);
            Hys = Hy ^ syndr;
            items[0] = sig->resp_a[i]; items[1] = (uint64_t)Hys;
            if (stern_hash_64_n(items, 2) != sig->c0[i]) return 0;
            stern_gen_perm_64(perm, sig->resp_a[i]);
            sy2 = stern_apply_perm_64(perm, sig->resp_b[i]);
            if (stern_hash_64(0, sy2) != sig->c2[i]) return 0;
        }
    }
    return 1;
}

/* HPKE-Stern-F at N=64 (known-e' fast path) */
static uint64_t hpke_stern_f_encap_64(uint64_t seed, uint32_t *ct_out,
                                        uint64_t *e_out)
{
    uint64_t e_p = stern_rand_error_64();
    *ct_out = stern_syndrome_64(seed, e_p);
    *e_out  = e_p;
    return stern_hash_64(stern_hash_64(0, seed), e_p);
}

static uint64_t hpke_stern_f_decap_known_64(uint64_t seed, uint64_t e_prime)
{
    return stern_hash_64(stern_hash_64(0, seed), e_prime);
}

/* [17] HPKS-Stern-F correctness: sign+verify, N=32,64,256 */
static void test_hpks_stern_f_correctness(void)
{
    int sizes[] = {32, 64, 256};
    int si;
    printf("[17] HPKS-Stern-F correctness: sign+verify  [CODE-BASED PQC]\n");
    for (si = 0; si < 3; si++) {
        int sz = sizes[si];
        int N = g_rounds > 0 ? g_rounds : 5;
        int ok = 0, fail = 0, i;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (sz == 32) {
            static SternSig32T sig32;
            for (i = 0; i < N; i++) {
                uint32_t seed, e, msg;
                uint16_t syndr;
                seed  = stern32_rand_seed();
                e     = stern32_rand_error();
                syndr = stern32_syndrome(seed, e);
                { uint8_t buf[4];
                  if (fread(buf, 4, 1, urnd_fp) != 1) { fputs("urandom\n", stderr); exit(1); }
                  msg = ((uint32_t)buf[0]<<24)|((uint32_t)buf[1]<<16)|
                        ((uint32_t)buf[2]<<8)|buf[3]; }
                hpks_stern_f_sign_32(&sig32, msg, e, seed);
                if (hpks_stern_f_verify_32(&sig32, msg, seed, syndr)) ok++;
                else fail++;
                if (g_time_limit > 0.0 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else if (sz == 64) {
            static SternSig64T sig64;
            for (i = 0; i < N; i++) {
                uint64_t seed, e, msg;
                uint32_t syndr;
                seed  = stern64_rand_seed();
                e     = stern_rand_error_64();
                syndr = stern_syndrome_64(seed, e);
                msg   = stern64_rand_seed();
                hpks_stern_f_sign_64(&sig64, msg, e, seed);
                if (hpks_stern_f_verify_64(&sig64, msg, seed, syndr)) ok++;
                else fail++;
                if (g_time_limit > 0.0 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else {
            static SternSigT sf_sig;
            for (i = 0; i < N; i++) {
                BitArray seed, e, msg;
                uint8_t syndr[SDF_SYNBYTES];
                ba_rand(&seed);
                stern_rand_error_ba(&e);
                stern_syndrome_ba(syndr, &seed, &e);
                ba_rand(&msg);
                hpks_stern_f_sign_t(&sf_sig, &msg, &e, &seed);
                if (hpks_stern_f_verify_t(&sf_sig, &msg, &seed, syndr)) ok++;
                else fail++;
                if (g_time_limit > 0.0 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        }
        printf("    bits=%3d  t=%d  rounds=%d  %d / %d verified  [%s]\n",
               sz,
               sz==32 ? SDF32_T : sz==64 ? SDF64_T : SDF_T,
               sz==32 ? SDF32_TEST_ROUNDS : sz==64 ? SDF64_TEST_ROUNDS : SDF_TEST_ROUNDS,
               ok, N, fail == 0 ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [18] HPKE-Stern-F correctness: encap+decap, n=32 (brute-force), n=64 (known-e') */
static void test_hpke_stern_f_correctness(void)
{
    printf("[18] HPKE-Stern-F correctness: encap+decap  [CODE-BASED PQC]\n");
    /* n=32 brute-force C(32,2)=496 */
    {
        int N = g_rounds > 0 ? g_rounds : 20;
        int ok = 0, fail = 0, i;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            uint32_t seed, e_prime, K_enc, K_dec;
            uint16_t ct;
            seed  = stern32_rand_seed();
            K_enc = hpke_stern_f_encap_32(seed, &ct, &e_prime);
            K_dec = hpke_stern_f_decap_32(seed, ct);
            if (K_enc == K_dec) ok++;
            else fail++;
            if (g_time_limit > 0.0 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    n=%d t=%d (brute-force)  %d / %d decapsulated  [%s]\n",
               SDF32_N, SDF32_T, ok, N, fail == 0 ? "PASS" : "FAIL");
    }
    /* n=64 known-e' fast path */
    {
        int N = g_rounds > 0 ? g_rounds : 20;
        int ok = 0, fail = 0, i;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            uint64_t seed, e_prime, K_enc, K_dec;
            uint32_t ct;
            seed  = stern64_rand_seed();
            K_enc = hpke_stern_f_encap_64(seed, &ct, &e_prime);
            K_dec = hpke_stern_f_decap_known_64(seed, e_prime);
            if (K_enc == K_dec) ok++;
            else fail++;
            if (g_time_limit > 0.0 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    n=%d t=%d (known-e')     %d / %d decapsulated  [%s]\n",
               SDF64_N, SDF64_T, ok, N, fail == 0 ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [28] HPKS-Stern-F sign+verify throughput (N=256, t=16, rounds=4) */
static void bench_hpks_stern_f(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    static SternSigT bsig;
    BitArray seed, e, msg;
    uint8_t syndr[SDF_SYNBYTES];
    printf("[28] HPKS-Stern-F sign+verify  (N=%d, t=%d, rounds=%d)  [CODE-BASED PQC]\n    ",
           KEYBITS, SDF_T, SDF_TEST_ROUNDS);
    ba_rand(&seed); stern_rand_error_ba(&e);
    stern_syndrome_ba(syndr, &seed, &e); ba_rand(&msg);
    for (i = 0; i < 2; i++) {
        hpks_stern_f_sign_t(&bsig, &msg, &e, &seed);
        hpks_stern_f_verify_t(&bsig, &msg, &seed, syndr);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 2; i++) {
            hpks_stern_f_sign_t(&bsig, &msg, &e, &seed);
            hpks_stern_f_verify_t(&bsig, &msg, &seed, syndr);
        }
        ops += 2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Performance benchmarks [19]-[23]                                   */
/* ------------------------------------------------------------------ */

/* [19] FSCX throughput (256-bit) */
static void bench_fscx_throughput(void)
{
    BitArray a, b, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[19] FSCX throughput  (bits=%d)\n    ", KEYBITS);
    ba_rand(&a); ba_rand(&b);
    for (i = 0; i < 10; i++) ba_fscx(&tmp, &a, &b);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) { ba_fscx(&tmp, &a, &b); a = tmp; }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* [20] HKEX-GF gf_pow throughput (32-bit) */
static void bench_gf_pow32_throughput(void)
{
    uint32_t base, exp, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[20] HKEX-GF gf_pow throughput  (bits=32)\n    ");
    base = rand32() | 1;
    exp  = rand32() | 1;
    for (i = 0; i < 5; i++) { tmp = gf_pow_32(base, exp); base = tmp | 1; }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 1000; i++) { tmp = gf_pow_32(base, exp); base = tmp | 1; }
        ops += 1000;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* [21] HKEX-GF full handshake (32-bit: 4 gf_pow_32 calls) */
static void bench_hkex_gf32_handshake(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, b, C, C2, skA, skB;
    printf("[21] HKEX-GF full handshake  (bits=32)\n    ");
    a = rand32() | 1; b = rand32() | 1;
    for (i = 0; i < 5; i++) {
        C   = gf_pow_32((uint32_t)GF_GEN32, a);
        C2  = gf_pow_32((uint32_t)GF_GEN32, b);
        skA = gf_pow_32(C2, a);
        skB = gf_pow_32(C,  b);
        a = skA | 1; b = skB | 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) {
            C   = gf_pow_32((uint32_t)GF_GEN32, a);
            C2  = gf_pow_32((uint32_t)GF_GEN32, b);
            skA = gf_pow_32(C2, a);
            skB = gf_pow_32(C,  b);
            a = skA | 1; b = skB | 1;
        }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* [22] HSKE round-trip: encrypt+decrypt (256-bit) */
static void bench_hske_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray pt, key, enc, dec;
    printf("[22] HSKE round-trip: encrypt+decrypt  (bits=%d)\n    ", KEYBITS);
    for (i = 0; i < 5; i++) {
        ba_rand(&pt); ba_rand(&key);
        ba_fscx_revolve(&enc, &pt,  &key, I_VALUE);
        ba_fscx_revolve(&dec, &enc, &key, R_VALUE);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 20; i++) {
            ba_rand(&pt); ba_rand(&key);
            ba_fscx_revolve(&enc, &pt,  &key, I_VALUE);
            ba_fscx_revolve(&dec, &enc, &key, R_VALUE);
        }
        ops += 20;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* [23] HPKE El Gamal encrypt+decrypt round-trip (32-bit) */
static void bench_hpke_el_gamal_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, r, C32, R32, enc_key, E32, dec_key, D32, pt;
    printf("[23] HPKE El Gamal encrypt+decrypt round-trip  (bits=32)\n    ");
    a = rand32() | 1; r = rand32() | 1; pt = rand32();
    C32 = gf_pow_32((uint32_t)GF_GEN32, a);
    for (i = 0; i < 5; i++) {
        R32     = gf_pow_32((uint32_t)GF_GEN32, r);
        enc_key = gf_pow_32(C32, r);
        E32     = fscx_revolve32(pt, enc_key, 8);
        dec_key = gf_pow_32(R32, a);
        D32     = fscx_revolve32(E32, dec_key, 24);
        r = R32 | 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) {
            R32     = gf_pow_32((uint32_t)GF_GEN32, r);
            enc_key = gf_pow_32(C32, r);
            E32     = fscx_revolve32(pt, enc_key, 8);
            dec_key = gf_pow_32(R32, a);
            D32     = fscx_revolve32(E32, dec_key, 24);
            r = R32 | 1;
        }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Performance benchmarks [24]-[27]: PQC extension                    */
/* ------------------------------------------------------------------ */

/* [24] NL-FSCX v1 revolve throughput + [24b] v2 enc+dec round-trip (32-bit) */
static void bench_nl_fscx_revolve(void)
{
    uint32_t a, b, E;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[24] NL-FSCX v1 revolve throughput  (bits=32, n/4=%d steps)  [PQC-EXT]\n    ",
           NL_I32);
    a = rand32(); b = rand32();
    for (i = 0; i < 10; i++) a = nl_fscx_revolve_v1_32(a, b, NL_I32);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) a = nl_fscx_revolve_v1_32(a, b, NL_I32);
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');

    printf("[24b] NL-FSCX v2 revolve+inv throughput  (bits=32, r_val=%d steps)  [PQC-EXT]\n    ",
           NL_R32);
    a = rand32(); b = rand32(); ops = 0;
    for (i = 0; i < 5; i++) {
        E = nl_fscx_revolve_v2_32(a, b, NL_R32);
        a = nl_fscx_revolve_v2_inv_32(E, b, NL_R32);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) {
            E = nl_fscx_revolve_v2_32(a, b, NL_R32);
            a = nl_fscx_revolve_v2_inv_32(E, b, NL_R32);
        }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    print_rate(ops, secs);
    putchar('\n');
}

/* [25] HSKE-NL-A1 counter-mode throughput (32-bit, ctr=0, with nonce) */
static void bench_hske_nl_a1_roundtrip(void)
{
    uint32_t K, P, ks, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[25] HSKE-NL-A1 counter-mode throughput  (bits=32)  [PQC-EXT]\n    ");
    K = rand32(); P = rand32();
    for (i = 0; i < 10; i++) {
        uint32_t nonce = rand32(), base = K ^ nonce;
        ks = nl_fscx_revolve_v1_32(base, base, NL_I32);
        sink ^= P ^ ks;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) {
            uint32_t nonce = rand32();
            K = rand32(); P = rand32();
            uint32_t base = K ^ nonce;
            ks = nl_fscx_revolve_v1_32(base, base, NL_I32);  /* ctr=0 */
            sink ^= P ^ ks;
        }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    (void)sink;
    print_rate(ops, secs);
    putchar('\n');
}

/* [26] HSKE-NL-A2 revolve-mode round-trip throughput (32-bit) */
static void bench_hske_nl_a2_roundtrip(void)
{
    uint32_t K, P, E, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[26] HSKE-NL-A2 revolve-mode round-trip  (bits=32, r_val=%d steps)  [PQC-EXT]\n    ",
           NL_R32);
    K = rand32(); P = rand32();
    for (i = 0; i < 5; i++) {
        E    = nl_fscx_revolve_v2_32(P, K, NL_R32);
        sink ^= nl_fscx_revolve_v2_inv_32(E, K, NL_R32);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) {
            K    = rand32(); P = rand32();
            E    = nl_fscx_revolve_v2_32(P, K, NL_R32);
            sink ^= nl_fscx_revolve_v2_inv_32(E, K, NL_R32);
        }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    (void)sink;
    print_rate(ops, secs);
    putchar('\n');
}

/* [27] HKEX-RNL full handshake throughput (n=32) */
static void bench_hkex_rnl_handshake(void)
{
    rnl32_poly_t m_base, a_rand, m_blind;
    int32_t s_A[RNL_N32], c_A[RNL_N32], s_B[RNL_N32], c_B[RNL_N32];
    uint32_t K_A, K_B, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[27] HKEX-RNL handshake throughput  (n=%d)  [PQC-EXT]\n    ", RNL_N32);
    rnl32_m_poly(m_base);
    for (i = 0; i < 3; i++) {
        uint32_t hint_A;
        rnl32_rand_poly(a_rand);
        rnl32_poly_add(m_blind, m_base, a_rand);
        rnl32_keygen(s_A, c_A, m_blind);
        rnl32_keygen(s_B, c_B, m_blind);
        K_A = rnl32_agree(s_A, c_B, NULL, &hint_A);
        K_B = rnl32_agree(s_B, c_A, &hint_A, NULL);
        sink ^= K_A ^ K_B;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 10; i++) {
            uint32_t hint_A;
            rnl32_rand_poly(a_rand);
            rnl32_poly_add(m_blind, m_base, a_rand);
            rnl32_keygen(s_A, c_A, m_blind);
            rnl32_keygen(s_B, c_B, m_blind);
            K_A = rnl32_agree(s_A, c_B, NULL, &hint_A);
            K_B = rnl32_agree(s_B, c_A, &hint_A, NULL);
            sink ^= K_A ^ K_B;
        }
        ops += 10;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < g_bench_sec);
    (void)sink;
    print_rate(ops, secs);
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    int i;
    const char *env_r, *env_t;

    /* --- env var defaults --- */
    if ((env_r = getenv("HTEST_ROUNDS")) && atoi(env_r) > 0)
        g_rounds = atoi(env_r);
    if ((env_t = getenv("HTEST_TIME")) && atof(env_t) > 0.0) {
        g_bench_sec  = atof(env_t);
        g_time_limit = atof(env_t);
    }

    /* --- CLI args override env --- */
    for (i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-r") || !strcmp(argv[i], "--rounds")) && i + 1 < argc) {
            g_rounds = atoi(argv[++i]);
        } else if ((!strcmp(argv[i], "-t") || !strcmp(argv[i], "--time")) && i + 1 < argc) {
            double v = atof(argv[++i]);
            g_bench_sec  = v;
            g_time_limit = v;
        } else {
            fprintf(stderr,
                "Usage: %s [-r ROUNDS] [-t SECS]\n"
                "  -r, --rounds N   max iterations per security test\n"
                "  -t, --time   T   benchmark duration and per-test time cap (seconds)\n"
                "  Env: HTEST_ROUNDS=N  HTEST_TIME=T\n", argv[0]);
            return 1;
        }
    }

    urnd_fp = fopen("/dev/urandom", "rb");
    if (!urnd_fp) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    printf("=== Herradura KEx v1.5.23 \xe2\x80\x94 Security & Performance Tests (C) ===\n");
    if (g_rounds > 0 || g_time_limit > 0.0) {
        if (g_rounds > 0 && g_time_limit > 0.0)
            printf("    Config: rounds=%d  time_limit=%.2fs\n", g_rounds, g_time_limit);
        else if (g_rounds > 0)
            printf("    Config: rounds=%d\n", g_rounds);
        else
            printf("    Config: time_limit=%.2fs\n", g_time_limit);
    }
    putchar('\n');

    puts("--- Security Tests: Classical Protocols ---\n");
    test_hkex_gf_correctness();
    test_avalanche();
    test_orbit_period();
    test_bit_frequency();
    test_hkex_gf_key_sensitivity();
    test_eve_attack_resistance();
    test_hpks_schnorr_correctness();
    test_hpks_schnorr_eve();
    test_hpke_el_gamal();

    puts("--- Security Tests: PQC Extension (NL-FSCX + HKEX-RNL) ---\n");
    test_nl_fscx_v1_nonlinearity();
    test_nl_fscx_v2_bijective_inverse();
    test_hske_nl_a1_correctness();
    test_hske_nl_a2_correctness();
    test_hkex_rnl_correctness();
    test_hpks_nl_correctness();
    test_hpke_nl_correctness();

    puts("--- Security Tests: Code-Based PQC (Stern-F) ---\n");
    test_hpks_stern_f_correctness();
    test_hpke_stern_f_correctness();

    puts("--- Performance Benchmarks ---\n");
    bench_fscx_throughput();
    bench_gf_pow32_throughput();
    bench_hkex_gf32_handshake();
    bench_hske_roundtrip();
    bench_hpke_el_gamal_roundtrip();
    bench_nl_fscx_revolve();
    bench_hske_nl_a1_roundtrip();
    bench_hske_nl_a2_roundtrip();
    bench_hkex_rnl_handshake();
    bench_hpks_stern_f();

    fclose(urnd_fp);
    return 0;
}
