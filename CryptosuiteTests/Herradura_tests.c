/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c */

/*  Herradura KEx -- Security & Performance Tests (C, 256-bit BitArray + 32-bit GF)
    v1.4.0: HKEX-GF (DH over GF(2^256)*); Schnorr HPKS; El Gamal HPKE.
      Tests [1]-[6]: 256-bit HKEX-GF and FSCX primitives (unchanged).
      [7] HPKS Schnorr correctness: g^s * C^e == R  (32-bit GF).
      [8] HPKS Schnorr Eve resistance: random forgery fails (32-bit GF).
      [9] HPKE El Gamal correctness: D = fscx_revolve(E, R^a, r) == P (32-bit GF).
      [10] FSCX throughput (256-bit).
      [11] HKEX-GF gf_pow throughput (32-bit).
      [12] HKEX-GF full handshake (32-bit).
      [13] HSKE round-trip (256-bit).
      [14] HPKE El Gamal encrypt+decrypt round-trip (32-bit).
      GFPow-heavy tests and benchmarks use 32-bit parameters for practical speed.

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

#define BENCH_SEC 1.0

typedef struct {
    uint8_t b[KEYBYTES];
} BitArray;

static FILE *urnd_fp;

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

/* ------------------------------------------------------------------ */
/* Security tests [1]-[6]: 256-bit HKEX-GF and FSCX primitives       */
/* ------------------------------------------------------------------ */

/* [1] HKEX-GF correctness: shared key derived by Alice == shared key derived by Bob */
static void test_hkex_gf_correctness(void)
{
    int i, ok = 0;
    BitArray a_priv, b_priv, C, C2, skA, skB;
    printf("[1] HKEX-GF correctness: g^{ab} == g^{ba}  (field commutativity)\n");
    for (i = 0; i < 1000; i++) {
        ba_rand(&a_priv);
        ba_rand(&b_priv);
        a_priv.b[KEYBYTES - 1] |= 1;   /* odd exponents */
        b_priv.b[KEYBYTES - 1] |= 1;
        gf_pow_ba(&C,  &GF_GEN, &a_priv);
        gf_pow_ba(&C2, &GF_GEN, &b_priv);
        gf_pow_ba(&skA, &C2, &a_priv);
        gf_pow_ba(&skB, &C,  &b_priv);
        if (ba_equal(&skA, &skB))
            ok++;
    }
    printf("    bits=%d  %d / 1000  [%s]\n",
           KEYBITS, ok, ok == 1000 ? "PASS" : "FAIL");
    putchar('\n');
}

/* [2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip) */
static void test_avalanche(void)
{
    int trial, bit;
    double total = 0.0;
    int gmin = KEYBITS + 1, gmax = -1;
    BitArray a, b, base_out, ap, flip_out, diff;
    printf("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)\n");
    for (trial = 0; trial < 1000; trial++) {
        ba_rand(&a);
        ba_rand(&b);
        ba_fscx(&base_out, &a, &b);
        for (bit = 0; bit < KEYBITS; bit++) {
            int hd;
            ba_flip_bit(&ap, &a, bit);
            ba_fscx(&flip_out, &ap, &b);
            ba_xor(&diff, &flip_out, &base_out);
            hd = ba_popcount(&diff);
            total += hd;
            if (hd < gmin) gmin = hd;
            if (hd > gmax) gmax = hd;
        }
    }
    {
        double mean = total / (1000.0 * (double)KEYBITS);
        printf("    bits=%d  mean=%.2f (expected 3/%d)  min=%d  max=%d  [%s]\n",
               KEYBITS, mean, KEYBITS, gmin, gmax,
               (mean >= 2.9 && mean <= 3.1) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [3] Orbit period: FSCX_REVOLVE(A,B,n) cycles back to A */
static void test_orbit_period(void)
{
    int trial, cntP = 0, cntHP = 0, other = 0;
    int cap = 2 * KEYBITS;
    BitArray a, b, cur, tmp;
    printf("[3] Orbit period: FSCX_REVOLVE(A,B,n) cycles back to A\n");
    for (trial = 0; trial < 100; trial++) {
        int period = 1;
        ba_rand(&a);
        ba_rand(&b);
        ba_fscx(&cur, &a, &b);
        while (!ba_equal(&cur, &a) && period < cap) {
            ba_fscx(&tmp, &cur, &b);
            cur = tmp;
            period++;
        }
        if      (period == KEYBITS)     cntP++;
        else if (period == KEYBITS / 2) cntHP++;
        else                            other++;
    }
    printf("    bits=%d  period=%d: %3d  period=%d: %3d  other: %d  [%s]\n",
           KEYBITS, KEYBITS, cntP, KEYBITS / 2, cntHP, other,
           other == 0 ? "PASS" : "FAIL");
    putchar('\n');
}

/* [4] Bit-frequency bias */
static void test_bit_frequency(void)
{
    int bit, trial;
    long long counts[KEYBITS];
    double minpct, maxpct, meanpct;
    int N = 100000;
    BitArray a, b, out;
    printf("[4] Bit-frequency bias: %d FSCX outputs\n", N);
    memset(counts, 0, sizeof(counts));
    for (trial = 0; trial < N; trial++) {
        ba_rand(&a);
        ba_rand(&b);
        ba_fscx(&out, &a, &b);
        for (bit = 0; bit < KEYBITS; bit++)
            if (ba_get_bit(&out, bit))
                counts[bit]++;
    }
    minpct = 101.0; maxpct = -1.0; meanpct = 0.0;
    for (bit = 0; bit < KEYBITS; bit++) {
        double pct = (double)counts[bit] / (double)N * 100.0;
        meanpct += pct;
        if (pct < minpct) minpct = pct;
        if (pct > maxpct) maxpct = pct;
    }
    meanpct /= (double)KEYBITS;
    printf("    bits=%d  min=%.2f%%  max=%.2f%%  mean=%.2f%%  [%s]\n",
           KEYBITS, minpct, maxpct, meanpct,
           (minpct > 47.0 && maxpct < 53.0) ? "PASS" : "FAIL");
    putchar('\n');
}

/* [5] HKEX-GF key sensitivity: flip 1 bit of private scalar a -> mean HD ~= n/2 */
static void test_hkex_gf_key_sensitivity(void)
{
    int i;
    double total = 0.0;
    BitArray a_priv, b_priv, C2, sk1, sk2, a_flip, diff;
    printf("[5] HKEX-GF key sensitivity: flip 1 bit of a -> mean Hamming(sk1, sk2) ~= %d\n",
           KEYBITS / 2);
    for (i = 0; i < 500; i++) {
        ba_rand(&a_priv);
        ba_rand(&b_priv);
        a_priv.b[KEYBYTES - 1] |= 1;
        b_priv.b[KEYBYTES - 1] |= 1;
        gf_pow_ba(&C2, &GF_GEN, &b_priv);
        gf_pow_ba(&sk1, &C2, &a_priv);
        ba_flip_bit(&a_flip, &a_priv, 0);
        gf_pow_ba(&sk2, &C2, &a_flip);
        ba_xor(&diff, &sk1, &sk2);
        total += ba_popcount(&diff);
    }
    {
        double mean = total / 500.0;
        double lo = KEYBITS * 0.35, hi = KEYBITS * 0.65;
        printf("    bits=%d  mean HD=%.1f (expected ~%d)  [%s]\n",
               KEYBITS, mean, KEYBITS / 2,
               (mean >= lo && mean <= hi) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* [6] Eve classical attack resistance: S_{r+1}(C XOR C2) != sk in HKEX-GF */
static void test_eve_attack_resistance(void)
{
    int i, hits = 0;
    BitArray a_priv, b_priv, C, C2, sk_real, eve_sk;
    BitArray delta, cur, zero, acc, next;
    int j;
    printf("[6] Eve classical attack: S_{r+1}(C XOR C2) != sk  (HKEX-GF resistance)\n");
    memset(zero.b, 0, KEYBYTES);
    for (i = 0; i < 1000; i++) {
        ba_rand(&a_priv);
        ba_rand(&b_priv);
        a_priv.b[KEYBYTES - 1] |= 1;
        b_priv.b[KEYBYTES - 1] |= 1;
        gf_pow_ba(&C,      &GF_GEN, &a_priv);
        gf_pow_ba(&C2,     &GF_GEN, &b_priv);
        gf_pow_ba(&sk_real, &C2,    &a_priv);
        /* Eve: sk_eve = S_{R_VALUE+1}(C ^ C2) */
        ba_xor(&delta, &C, &C2);
        memset(acc.b, 0, KEYBYTES);
        cur = delta;
        for (j = 0; j <= R_VALUE; j++) {
            ba_xor(&acc, &acc, &cur);
            ba_fscx(&next, &cur, &zero);
            cur = next;
        }
        eve_sk = acc;
        if (ba_equal(&eve_sk, &sk_real))
            hits++;
    }
    printf("    bits=%d  Eve succeeded %d / 1000  [%s]\n",
           KEYBITS, hits, hits == 0 ? "PASS - attack fails" : "FAIL");
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Security tests [7]-[9]: Schnorr HPKS and El Gamal HPKE (32-bit)   */
/* ------------------------------------------------------------------ */

/* [7] HPKS Schnorr correctness: g^s * C^e == R  (32-bit GF) */
static void test_hpks_schnorr_correctness(void)
{
    int i, ok = 0;
    uint32_t a, plain, k, C32, R32, e32, s32;
    uint64_t ae, ord = 0xFFFFFFFFULL;
    printf("[7] HPKS Schnorr correctness: g^s * C^e == R  (bits=32)\n");
    for (i = 0; i < 1000; i++) {
        a     = rand32() | 1;
        plain = rand32();
        k     = rand32();
        C32   = gf_pow_32((uint32_t)GF_GEN32, a);
        R32   = gf_pow_32((uint32_t)GF_GEN32, k);
        e32   = fscx_revolve32(R32, plain, 8);
        ae    = (uint64_t)a * (uint64_t)e32 % ord;
        s32   = (uint32_t)(((uint64_t)k + ord - ae) % ord);
        if (gf_mul_32(gf_pow_32((uint32_t)GF_GEN32, s32),
                      gf_pow_32(C32, e32)) == R32)
            ok++;
    }
    printf("    bits=32  %d / 1000  [%s]\n", ok, ok == 1000 ? "PASS" : "FAIL");
    putchar('\n');
}

/* [8] HPKS Schnorr Eve resistance: random (R,s) forgery fails  (32-bit GF) */
static void test_hpks_schnorr_eve(void)
{
    int i, hits = 0;
    uint32_t a, plain, C32, r_eve, s_eve, e_eve;
    printf("[8] HPKS Schnorr Eve resistance: random forgery fails  (bits=32)\n");
    for (i = 0; i < 1000; i++) {
        a      = rand32() | 1;
        plain  = rand32();
        r_eve  = rand32();
        s_eve  = rand32();
        C32    = gf_pow_32((uint32_t)GF_GEN32, a);
        e_eve  = fscx_revolve32(r_eve, plain, 8);
        if (gf_mul_32(gf_pow_32((uint32_t)GF_GEN32, s_eve),
                      gf_pow_32(C32, e_eve)) == r_eve)
            hits++;
    }
    printf("    bits=32  %d / 1000 Eve wins  [%s]\n",
           hits, hits == 0 ? "PASS" : "FAIL");
    putchar('\n');
}

/* [9] HPKE El Gamal encrypt+decrypt: D == plaintext  (32-bit GF) */
static void test_hpke_el_gamal(void)
{
    int i, ok = 0;
    uint32_t a, plain, r, C32, R32, enc_key, E32, dec_key, D32;
    printf("[9] HPKE El Gamal encrypt+decrypt: D == plaintext  (bits=32)\n");
    for (i = 0; i < 1000; i++) {
        a        = rand32() | 1;
        plain    = rand32();
        r        = rand32() | 1;
        C32      = gf_pow_32((uint32_t)GF_GEN32, a);
        R32      = gf_pow_32((uint32_t)GF_GEN32, r);
        enc_key  = gf_pow_32(C32, r);    /* C^r = g^{ar}  (Bob's enc key) */
        E32      = fscx_revolve32(plain, enc_key, 8);
        dec_key  = gf_pow_32(R32, a);    /* R^a = g^{ra}  (Alice's dec key) */
        D32      = fscx_revolve32(E32, dec_key, 24);
        if (D32 == plain) ok++;
    }
    printf("    bits=32  %d / 1000  [%s]\n", ok, ok == 1000 ? "PASS" : "FAIL");
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Performance benchmarks [10]-[14]                                   */
/* ------------------------------------------------------------------ */

/* [10] FSCX throughput (256-bit) */
static void bench_fscx_throughput(void)
{
    BitArray a, b, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[10] FSCX throughput  (bits=%d)\n    ", KEYBITS);
    ba_rand(&a); ba_rand(&b);
    for (i = 0; i < 10; i++) ba_fscx(&tmp, &a, &b);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 100; i++) { ba_fscx(&tmp, &a, &b); a = tmp; }
        ops += 100;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

/* [11] HKEX-GF gf_pow throughput (32-bit) */
static void bench_gf_pow32_throughput(void)
{
    uint32_t base, exp, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    printf("[11] HKEX-GF gf_pow throughput  (bits=32)\n    ");
    base = rand32() | 1;
    exp  = rand32() | 1;
    for (i = 0; i < 5; i++) { tmp = gf_pow_32(base, exp); base = tmp | 1; }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 1000; i++) { tmp = gf_pow_32(base, exp); base = tmp | 1; }
        ops += 1000;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

/* [12] HKEX-GF full handshake (32-bit: 4 gf_pow_32 calls) */
static void bench_hkex_gf32_handshake(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, b, C, C2, skA, skB;
    printf("[12] HKEX-GF full handshake  (bits=32)\n    ");
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
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

/* [13] HSKE round-trip: encrypt+decrypt (256-bit) */
static void bench_hske_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray pt, key, enc, dec;
    printf("[13] HSKE round-trip: encrypt+decrypt  (bits=%d)\n    ", KEYBITS);
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
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

/* [14] HPKE El Gamal encrypt+decrypt round-trip (32-bit) */
static void bench_hpke_el_gamal_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    uint32_t a, r, C32, R32, enc_key, E32, dec_key, D32, pt;
    printf("[14] HPKE El Gamal encrypt+decrypt round-trip  (bits=32)\n    ");
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
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    urnd_fp = fopen("/dev/urandom", "rb");
    if (!urnd_fp) {
        fputs("ERROR: cannot open /dev/urandom\n", stderr);
        return 1;
    }

    printf("=== Herradura KEx \xe2\x80\x94 Security & Performance Tests (C) ===\n\n");

    puts("--- Security Assumption Tests ---\n");
    test_hkex_gf_correctness();
    test_avalanche();
    test_orbit_period();
    test_bit_frequency();
    test_hkex_gf_key_sensitivity();
    test_eve_attack_resistance();
    test_hpks_schnorr_correctness();
    test_hpks_schnorr_eve();
    test_hpke_el_gamal();

    puts("--- Performance Benchmarks ---\n");
    bench_fscx_throughput();
    bench_gf_pow32_throughput();
    bench_hkex_gf32_handshake();
    bench_hske_roundtrip();
    bench_hpke_el_gamal_roundtrip();

    fclose(urnd_fp);
    return 0;
}
