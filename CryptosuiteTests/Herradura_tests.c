/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c
   Usage: ./Herradura_tests [-r ROUNDS] [-t SECS]
     -r, --rounds N   max iterations per security test (default: test-specific)
     -t, --time   T   benchmark duration and per-test wall-clock cap in seconds
   Env:  HTEST_ROUNDS=N  HTEST_TIME=T  (CLI flags override env) */

/*  Herradura KEx -- Security & Performance Tests (C, multi-size BitArray + scalar GF)
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
            {64,128} (256-bit NL-FSCX omitted; 256-bit mul not implemented).
            Phase 5 — test methodology alignment: [11] bijectivity upgraded to
            BIJ_SAMPLES=256 random A values per B with pairwise collision scan,
            matching Python/Go hash-map methodology.
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.0: HKEX-GF; Schnorr HPKS; El Gamal HPKE; NL-FSCX non-linear extension; PQC.
      Tests [1],[5],[6]: HKEX-GF (32/64/256-bit); [7]–[9],[14]–[16]: 32/64-bit loops.
      [1]  HKEX-GF correctness: g^{ab}==g^{ba} (32/64/256-bit GF).
      [7]  HPKS Schnorr correctness: g^s * C^e == R  (32/64-bit GF).
      [8]  HPKS Schnorr Eve resistance: random forgery fails (32/64-bit GF).
      [9]  HPKE El Gamal correctness: D == P (32/64-bit GF).
      [10] NL-FSCX v1 non-linearity and aperiodicity (32-bit).
      [11] NL-FSCX v2 bijectivity and exact inverse (32-bit).
      [12] HSKE-NL-A1 counter-mode correctness: D == P (32-bit).
      [13] HSKE-NL-A2 revolve-mode correctness: D == P (32-bit).
      [14] HKEX-RNL key agreement: K_A == K_B (n=32/64, Ring-LWR).
      [15] HPKS-NL correctness: g^s * C^e == R (NL-FSCX v1 challenge, 32/64-bit GF).
      [16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt, 32/64-bit GF).
      [17] FSCX throughput (256-bit).
      [18] HKEX-GF gf_pow throughput (32-bit).
      [19] HKEX-GF full handshake (32-bit).
      [20] HSKE round-trip (256-bit).
      [21] HPKE El Gamal encrypt+decrypt round-trip (32-bit).
      [22] NL-FSCX v1 revolve throughput (32-bit, n/4 steps).
      [22b] NL-FSCX v2 revolve+inv throughput (32-bit, r_val steps).
      [23] HSKE-NL-A1 counter-mode throughput (32-bit).
      [24] HSKE-NL-A2 revolve-mode round-trip throughput (32-bit).
      [25] HKEX-RNL full handshake throughput (n=32).

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

static void rnl32_ntt(int32_t *a, int n, int q, int invert)
{
    int i, j = 0, length, k;
    uint32_t w, wn;
    for (i = 1; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { int32_t t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (length = 2; length <= n; length <<= 1) {
        w = rnl32_mod_pow(3, (uint32_t)(q - 1) / (uint32_t)length, (uint32_t)q);
        if (invert) w = rnl32_mod_pow(w, (uint32_t)(q - 2), (uint32_t)q);
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
        uint32_t inv_n = rnl32_mod_pow((uint32_t)n, (uint32_t)(q - 2), (uint32_t)q);
        for (i = 0; i < n; i++)
            a[i] = (int32_t)((uint64_t)a[i] * inv_n % (uint32_t)q);
    }
}

/* Negacyclic multiply: h = f*g in Z_q[x]/(x^32+1) via NTT. O(n log n). */
static void rnl32_poly_mul(rnl32_poly_t h, const rnl32_poly_t f, const rnl32_poly_t g)
{
    int32_t fa[RNL_N32], ga[RNL_N32], ha[RNL_N32];
    uint32_t psi     = rnl32_mod_pow(3, (RNL_Q32 - 1) / (2 * RNL_N32), RNL_Q32);
    uint32_t psi_inv = rnl32_mod_pow(psi, RNL_Q32 - 2, RNL_Q32);
    uint32_t pw = 1, pw_inv = 1;
    int i;
    for (i = 0; i < RNL_N32; i++) {
        fa[i] = (int32_t)((uint64_t)f[i] * pw % RNL_Q32);
        ga[i] = (int32_t)((uint64_t)g[i] * pw % RNL_Q32);
        pw    = (uint32_t)((uint64_t)pw * psi % RNL_Q32);
    }
    rnl32_ntt(fa, RNL_N32, RNL_Q32, 0);
    rnl32_ntt(ga, RNL_N32, RNL_Q32, 0);
    for (i = 0; i < RNL_N32; i++)
        ha[i] = (int32_t)((uint64_t)fa[i] * ga[i] % RNL_Q32);
    rnl32_ntt(ha, RNL_N32, RNL_Q32, 1);
    for (i = 0; i < RNL_N32; i++) {
        h[i]   = (int32_t)((uint64_t)ha[i] * pw_inv % RNL_Q32);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % RNL_Q32);
    }
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

/* CBD(eta=1): coeff = (raw&1) - ((raw>>1)&1), stored mod q. Zero-mean {-1,0,1}. */
static void rnl32_cbd_poly(rnl32_poly_t p)
{
    int i;
    for (i = 0; i < RNL_N32; i++) {
        uint32_t raw = rand32();
        int a = (int)(raw & 1);
        int b = (int)((raw >> 1) & 1);
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
    uint32_t psi     = rnl32_mod_pow(3, (RNL_Q32 - 1) / (2 * (uint32_t)n), RNL_Q32);
    uint32_t psi_inv = rnl32_mod_pow(psi, RNL_Q32 - 2, RNL_Q32);
    uint32_t pw = 1, pw_inv = 1;
    int i;
    for (i = 0; i < n; i++) {
        fa[i] = (int32_t)((uint64_t)f[i] * pw % RNL_Q32);
        ga[i] = (int32_t)((uint64_t)g[i] * pw % RNL_Q32);
        pw    = (uint32_t)((uint64_t)pw * psi % RNL_Q32);
    }
    rnl32_ntt(fa, n, RNL_Q32, 0);
    rnl32_ntt(ga, n, RNL_Q32, 0);
    for (i = 0; i < n; i++)
        ha[i] = (int32_t)((uint64_t)fa[i] * ga[i] % RNL_Q32);
    rnl32_ntt(ha, n, RNL_Q32, 1);
    for (i = 0; i < n; i++) {
        h[i]   = (int32_t)((uint64_t)ha[i] * pw_inv % RNL_Q32);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % RNL_Q32);
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
    for (i = 0; i < n; i++) {
        uint32_t raw = rand32();
        int32_t  a   = (int32_t)(raw & 1);
        int32_t  b   = (int32_t)((raw >> 1) & 1);
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

/* [1] HKEX-GF correctness: shared key derived by Alice == shared key derived by Bob */
static void test_hkex_gf_correctness(void)
{
    static const int sizes[] = {32, 64, 256};
    int si, i, ok, N, size;
    struct timespec t0;
    BitArray a256, b256, C256, C2_256, skA256, skB256;
    uint64_t a64, b64, C64, C2_64, skA64, skB64;
    uint32_t a32, b32, C32a, C2_32a, skA32, skB32;
    printf("[1] HKEX-GF correctness: g^{ab} == g^{ba} in GF(2^n)*  [CLASSICAL]\n");
    for (si = 0; si < 3; si++) {
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
    static const int sizes[] = {32, 64, 256};
    int si, i, N, size;
    struct timespec t0;
    double total, mean;
    BitArray a256, b256, C2_256, sk1_256, sk2_256, aflip256, diff256;
    uint64_t a64, b64, C2_64, sk1_64, sk2_64;
    uint32_t a32, b32, C2_32b, sk1_32, sk2_32;
    printf("[5] HKEX-GF key sensitivity: flip 1 bit of a, measure HD of sk change  [CLASSICAL]\n");
    for (si = 0; si < 3; si++) {
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
    static const int sizes[] = {32, 64, 256};
    int si, i, hits, N, size;
    struct timespec t0;
    BitArray a256, b256, C256, C2_256, sk256, evsk256;
    BitArray delta256, cur256, zero256, acc256, nxt256;
    uint64_t a64, b64, C64e, C2_64e, sk64, evsk64;
    uint32_t a32e, b32e, C32e, C2_32e, sk32, evsk32;
    printf("[6] HKEX-GF Eve resistance: S_op(C^C2, r) != sk  [CLASSICAL]\n");
    memset(zero256.b, 0, KEYBYTES);
    for (si = 0; si < 3; si++) {
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

/* [7] HPKS Schnorr correctness: g^s * C^e == R */
static void test_hpks_schnorr_correctness(void)
{
    static const int sizes[] = {32, 64};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32s, plain32, k32, C32s, R32s, e32s, s32s;
    uint64_t a64s, plain64, k64, C64s, R64s, e64s, s64s;
    uint64_t ord32 = 0xFFFFFFFFULL;
    uint64_t ord64 = 0xFFFFFFFFFFFFFFFFULL;
    __uint128_t ae128;
    printf("[7] HPKS Schnorr correctness: g^s · C^e == R  [CLASSICAL]\n");
    for (si = 0; si < 2; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 64) {
                a64s = rand64()|1; plain64 = rand64(); k64 = rand64();
                C64s = gf_pow_64(3ULL, a64s);
                R64s = gf_pow_64(3ULL, k64);
                e64s = fscx_revolve64(R64s, plain64, 16);
                ae128 = (__uint128_t)a64s * e64s % (__uint128_t)ord64;
                s64s  = (uint64_t)(((__uint128_t)k64 + (__uint128_t)ord64
                                    - (uint64_t)ae128) % (__uint128_t)ord64);
                if (gf_mul_64(gf_pow_64(3ULL, s64s),
                              gf_pow_64(C64s, e64s)) == R64s) ok++;
            } else {
                a32s = rand32()|1; plain32 = rand32(); k32 = rand32();
                C32s = gf_pow_32(GF_GEN32, a32s);
                R32s = gf_pow_32(GF_GEN32, k32);
                e32s = fscx_revolve32(R32s, plain32, 8);
                ae128 = (__uint128_t)a32s * e32s % (__uint128_t)ord32;
                s32s  = (uint32_t)(((__uint128_t)k32 + (__uint128_t)ord32
                                    - (uint32_t)ae128) % (__uint128_t)ord32);
                if (gf_mul_32(gf_pow_32(GF_GEN32, s32s),
                              gf_pow_32(C32s, e32s)) == R32s) ok++;
            }
            if ((i & 63) == 63 && time_exceeded(&t0)) { N = i + 1; break; }
        }
        printf("    bits=%3d  %4d / %d verified  [%s]\n",
               size, ok, N, ok == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [8] HPKS Schnorr Eve resistance: random forgery attempts fail */
static void test_hpks_schnorr_eve(void)
{
    static const int sizes[] = {32, 64};
    int si, i, hits, N, size;
    struct timespec t0;
    uint32_t a32e2, C32e2, reve32, seve32, eeve32;
    uint64_t a64e2, C64e2, reve64, seve64, eeve64;
    printf("[8] HPKS Schnorr Eve resistance: random forgery attempts fail  [CLASSICAL]\n");
    for (si = 0; si < 2; si++) {
        size = sizes[si]; hits = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 64) {
                uint64_t plain64e = rand64();
                a64e2 = rand64()|1;
                C64e2 = gf_pow_64(3ULL, a64e2);
                reve64 = rand64(); seve64 = rand64();
                eeve64 = fscx_revolve64(reve64, plain64e, 16);
                if (gf_mul_64(gf_pow_64(3ULL, seve64),
                              gf_pow_64(C64e2, eeve64)) == reve64) hits++;
            } else {
                uint32_t plain32e = rand32();
                a32e2 = rand32()|1;
                C32e2 = gf_pow_32(GF_GEN32, a32e2);
                reve32 = rand32(); seve32 = rand32();
                eeve32 = fscx_revolve32(reve32, plain32e, 8);
                if (gf_mul_32(gf_pow_32(GF_GEN32, seve32),
                              gf_pow_32(C32e2, eeve32)) == reve32) hits++;
            }
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
    static const int sizes[] = {32, 64};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32g, r32g, C32g, R32g, enc32, E32g, dec32, D32g;
    uint64_t a64g, r64g, C64g, R64g, enc64, E64g, dec64, D64g;
    printf("[9] HPKE encrypt+decrypt correctness (El Gamal + fscx_revolve)  [CLASSICAL]\n");
    for (si = 0; si < 2; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 64) {
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

/* I/R values for 32/64/128-bit NL tests */
#define NL_I32   8   /* 32/4 */
#define NL_R32   24  /* 3*32/4 */
#define NL_I64   16  /* 64/4 */
#define NL_R64   48  /* 3*64/4 */
#define NL_I128  32  /* 128/4 */
#define NL_R128  96  /* 3*128/4 */

/* Bijectivity sample count: 256 A values per B, matching Python/Go */
#define BIJ_SAMPLES 256

/* [10] NL-FSCX v1 non-linearity and aperiodicity */
static void test_nl_fscx_v1_nonlinearity(void)
{
    static const int sizes[] = {64, 128};
    int si, i, size;
    struct timespec t0;
    printf("[10] NL-FSCX v1 non-linearity and aperiodicity  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        int violations = 0, no_period = 0;
        int N1 = TEST_ROUNDS(1000), N2 = TEST_ROUNDS(200);
        size = sizes[si];
        int cap = 4 * size;
        /* Linearity check */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N1; i++) {
            if (size == 128) {
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
            if (size == 128) {
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
    static const int sizes[] = {64, 128};
    int si, i, j, k, size;
    struct timespec t0;
    printf("[11] NL-FSCX v2 bijectivity and exact inverse  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        int non_bij = 0, inv_ok = 0, nl_ok = 0;
        int N1 = TEST_ROUNDS(500), N2 = TEST_ROUNDS(1000), N3 = TEST_ROUNDS(500);
        size = sizes[si];
        /* Bijectivity: BIJ_SAMPLES random A values per B; detect output collisions */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N1; i++) {
            int found = 0;
            if (size == 128) {
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
            if (size == 128) {
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
            if (size == 128) {
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
    static const int sizes[] = {64, 128};
    int si, i, size;
    struct timespec t0;
    printf("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        int ok = 0, N = TEST_ROUNDS(1000);
        size = sizes[si];
        int iv = size / 4;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 128) {
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
    static const int sizes[] = {64, 128};
    int si, i, size;
    struct timespec t0;
    printf("[13] HSKE-NL-A2 revolve-mode correctness: D == P  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        int ok = 0, N = TEST_ROUNDS(1000);
        size = sizes[si];
        int rv = 3 * size / 4;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 128) {
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
    static const int rnl_sizes[] = {32, 64};
    int si, i, ok_raw, ok_sk, N, n;
    struct timespec t0;
    printf("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]\n");
    printf("     (ring sizes {32,64}; Peikert reconciliation -- expect 100%% agreement)\n");
    for (si = 0; si < 2; si++) {
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
                K_A = rnl32_agree(s_A, c_B, NULL, &hint_A);   /* reconciler */
                K_B = rnl32_agree(s_B, c_A, &hint_A, NULL);   /* receiver */
                if (K_A == K_B) ok_raw++;
                if (nl_fscx_revolve_v1_32((K_A<<4)|(K_A>>28), K_A, NL_I32) ==
                    nl_fscx_revolve_v1_32((K_B<<4)|(K_B>>28), K_B, NL_I32)) ok_sk++;
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        } else {
            int32_t m_base64[64], a_rand64[64], m_blind64[64];
            rnl_m_poly_n(m_base64, 64);
            for (i = 0; i < N; i++) {
                int32_t s_A64[64], c_A64[64], s_B64[64], c_B64[64];
                uint64_t K_A64, K_B64, hint_A64;
                rnl_rand_poly_n(a_rand64, 64);
                rnl_poly_add_n(m_blind64, m_base64, a_rand64, 64);
                rnl_keygen_n(s_A64, c_A64, m_blind64, 64);
                rnl_keygen_n(s_B64, c_B64, m_blind64, 64);
                K_A64 = rnl_agree_n(s_A64, c_B64, 64, NULL, &hint_A64);  /* reconciler */
                K_B64 = rnl_agree_n(s_B64, c_A64, 64, &hint_A64, NULL);  /* receiver */
                if (K_A64 == K_B64) ok_raw++;
                if (nl_fscx_revolve_v1_64((K_A64<<8)|(K_A64>>56), K_A64, NL_I64) ==
                    nl_fscx_revolve_v1_64((K_B64<<8)|(K_B64>>56), K_B64, NL_I64)) ok_sk++;
                if ((i & 15) == 15 && time_exceeded(&t0)) { N = i + 1; break; }
            }
        }
        printf("    n=%3d  raw agree=%d/%d  sk agree=%d/%d  [%s]\n",
               n, ok_raw, N, ok_sk, N,
               ok_raw == N ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [15] HPKS-NL correctness: g^s * C^e == R  (NL-FSCX v1 challenge) */
static void test_hpks_nl_correctness(void)
{
    static const int sizes[] = {32, 64};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32nl, plain32nl, k32nl, C32nl, R32nl, e32nl, s32nl;
    uint64_t a64nl, plain64nl, k64nl, C64nl, R64nl, e64nl, s64nl;
    uint64_t ord32 = 0xFFFFFFFFULL;
    uint64_t ord64 = 0xFFFFFFFFFFFFFFFFULL;
    __uint128_t ae128nl;
    printf("[15] HPKS-NL correctness: g^s · C^e == R (NL-FSCX v1 challenge)  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 64) {
                a64nl = rand64()|1; plain64nl = rand64(); k64nl = rand64();
                C64nl = gf_pow_64(3ULL, a64nl);
                R64nl = gf_pow_64(3ULL, k64nl);
                e64nl = nl_fscx_revolve_v1_64(R64nl, plain64nl, NL_I64);
                ae128nl = (__uint128_t)a64nl * e64nl % (__uint128_t)ord64;
                s64nl   = (uint64_t)(((__uint128_t)k64nl + (__uint128_t)ord64
                                      - (uint64_t)ae128nl) % (__uint128_t)ord64);
                if (gf_mul_64(gf_pow_64(3ULL, s64nl),
                              gf_pow_64(C64nl, e64nl)) == R64nl) ok++;
            } else {
                a32nl = rand32()|1; plain32nl = rand32(); k32nl = rand32();
                C32nl = gf_pow_32(GF_GEN32, a32nl);
                R32nl = gf_pow_32(GF_GEN32, k32nl);
                e32nl = nl_fscx_revolve_v1_32(R32nl, plain32nl, NL_I32);
                ae128nl = (__uint128_t)a32nl * e32nl % (__uint128_t)ord32;
                s32nl   = (uint32_t)(((__uint128_t)k32nl + (__uint128_t)ord32
                                      - (uint32_t)ae128nl) % (__uint128_t)ord32);
                if (gf_mul_32(gf_pow_32(GF_GEN32, s32nl),
                              gf_pow_32(C32nl, e32nl)) == R32nl) ok++;
            }
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
    static const int sizes[] = {32, 64};
    int si, i, ok, N, size;
    struct timespec t0;
    uint32_t a32h, r32h, C32h, R32h, enc32h, E32h, dec32h, D32h;
    uint64_t a64h, r64h, C64h, R64h, enc64h, E64h, dec64h, D64h;
    printf("[16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt)  [PQC-EXT]\n");
    for (si = 0; si < 2; si++) {
        size = sizes[si]; ok = 0; N = TEST_ROUNDS(100);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (i = 0; i < N; i++) {
            if (size == 64) {
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
/* Performance benchmarks [17]-[21]                                   */
/* ------------------------------------------------------------------ */

/* [17] FSCX throughput (256-bit) */
static void bench_fscx_throughput(void)
{
    BitArray a, b, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[17] FSCX throughput  (bits=%d)\n    ", KEYBITS);
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

/* [18] HKEX-GF gf_pow throughput (32-bit) */
static void bench_gf_pow32_throughput(void)
{
    uint32_t base, exp, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[18] HKEX-GF gf_pow throughput  (bits=32)\n    ");
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

/* [19] HKEX-GF full handshake (32-bit: 4 gf_pow_32 calls) */
static void bench_hkex_gf32_handshake(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, b, C, C2, skA, skB;
    printf("[19] HKEX-GF full handshake  (bits=32)\n    ");
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

/* [20] HSKE round-trip: encrypt+decrypt (256-bit) */
static void bench_hske_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray pt, key, enc, dec;
    printf("[20] HSKE round-trip: encrypt+decrypt  (bits=%d)\n    ", KEYBITS);
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

/* [21] HPKE El Gamal encrypt+decrypt round-trip (32-bit) */
static void bench_hpke_el_gamal_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, r, C32, R32, enc_key, E32, dec_key, D32, pt;
    printf("[21] HPKE El Gamal encrypt+decrypt round-trip  (bits=32)\n    ");
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
/* Performance benchmarks [22]-[25]: PQC extension                    */
/* ------------------------------------------------------------------ */

/* [22] NL-FSCX v1 revolve throughput + [22b] v2 enc+dec round-trip (32-bit) */
static void bench_nl_fscx_revolve(void)
{
    uint32_t a, b, E;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[22] NL-FSCX v1 revolve throughput  (bits=32, n/4=%d steps)  [PQC-EXT]\n    ",
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

    printf("[22b] NL-FSCX v2 revolve+inv throughput  (bits=32, r_val=%d steps)  [PQC-EXT]\n    ",
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

/* [23] HSKE-NL-A1 counter-mode throughput (32-bit, ctr=0, with nonce) */
static void bench_hske_nl_a1_roundtrip(void)
{
    uint32_t K, P, ks, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[23] HSKE-NL-A1 counter-mode throughput  (bits=32)  [PQC-EXT]\n    ");
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

/* [24] HSKE-NL-A2 revolve-mode round-trip throughput (32-bit) */
static void bench_hske_nl_a2_roundtrip(void)
{
    uint32_t K, P, E, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[24] HSKE-NL-A2 revolve-mode round-trip  (bits=32, r_val=%d steps)  [PQC-EXT]\n    ",
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

/* [25] HKEX-RNL full handshake throughput (n=32) */
static void bench_hkex_rnl_handshake(void)
{
    rnl32_poly_t m_base, a_rand, m_blind;
    int32_t s_A[RNL_N32], c_A[RNL_N32], s_B[RNL_N32], c_B[RNL_N32];
    uint32_t K_A, K_B, sink = 0;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[25] HKEX-RNL handshake throughput  (n=%d)  [PQC-EXT]\n    ", RNL_N32);
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

    printf("=== Herradura KEx v1.5.10 \xe2\x80\x94 Security & Performance Tests (C) ===\n");
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

    fclose(urnd_fp);
    return 0;
}
