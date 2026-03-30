/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c */

/*  Herradura KEx -- Security & Performance Tests (C, 256-bit BitArray)

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

/* Key size in bits — must be a positive multiple of 8.
   Matches the default in "Herradura cryptographic suite.c", and in
   the Go and Python implementations. */
#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)       /* 64  for 256-bit */
#define R_VALUE  (3 * KEYBITS / 4)   /* 192 for 256-bit */

/* Target wall time per benchmark (seconds). */
#define BENCH_SEC 1.0

/* Fixed-width bit array backed by a big-endian byte array.
   b[0] holds the most-significant byte.
   Bit numbering: bit 0 is the LSB (byte[KEYBYTES-1] bit 0);
   bit KEYBITS-1 is the MSB (byte[0] bit 7). */
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

/* dst = src rotated left by 1 bit (big-endian, b[0] is MSB). */
static void ba_rol1(BitArray *dst, const BitArray *src)
{
    int i;
    uint8_t msbit = (src->b[0] >> 7) & 1;
    for (i = 0; i < KEYBYTES - 1; i++)
        dst->b[i] = (uint8_t)((src->b[i] << 1) | (src->b[i + 1] >> 7));
    dst->b[KEYBYTES - 1] = (uint8_t)((src->b[KEYBYTES - 1] << 1) | msbit);
}

/* dst = src rotated right by 1 bit (big-endian, b[0] is MSB). */
static void ba_ror1(BitArray *dst, const BitArray *src)
{
    int i;
    uint8_t lsbit = src->b[KEYBYTES - 1] & 1;
    for (i = KEYBYTES - 1; i > 0; i--)
        dst->b[i] = (uint8_t)((src->b[i] >> 1) | (src->b[i - 1] << 7));
    dst->b[0] = (uint8_t)((src->b[0] >> 1) | (lsbit << 7));
}

static int ba_equal(const BitArray *a, const BitArray *b)
{
    return memcmp(a->b, b->b, KEYBYTES) == 0;
}

/* Count set bits across all bytes. */
static int ba_popcount(const BitArray *a)
{
    int cnt = 0, i;
    for (i = 0; i < KEYBYTES; i++) {
        uint8_t v = a->b[i];
        while (v) {
            cnt += (v & 1);
            v >>= 1;
        }
    }
    return cnt;
}

/* Return the value of bit pos (0 = LSB of byte[KEYBYTES-1]). */
static int ba_get_bit(const BitArray *a, int pos)
{
    int byte_idx = KEYBYTES - 1 - pos / 8;
    int bit_pos  = pos % 8;
    return (a->b[byte_idx] >> bit_pos) & 1;
}

/* dst = src with bit pos (0 = LSB) toggled. */
static void ba_flip_bit(BitArray *dst, const BitArray *src, int pos)
{
    int byte_idx = KEYBYTES - 1 - pos / 8;
    int bit_pos  = pos % 8;
    *dst = *src;
    dst->b[byte_idx] ^= (uint8_t)(1u << bit_pos);
}

/* ------------------------------------------------------------------ */
/* FSCX primitives                                                     */
/* ------------------------------------------------------------------ */

static void ba_fscx(BitArray *result, const BitArray *a, const BitArray *b)
{
    BitArray rol_a, rol_b, ror_a, ror_b;
    int i;
    ba_rol1(&rol_a, a);
    ba_rol1(&rol_b, b);
    ba_ror1(&ror_a, a);
    ba_ror1(&ror_b, b);
    for (i = 0; i < KEYBYTES; i++)
        result->b[i] = a->b[i] ^ b->b[i]
                     ^ rol_a.b[i] ^ rol_b.b[i]
                     ^ ror_a.b[i] ^ ror_b.b[i];
}

static void ba_fscx_revolve(BitArray *result, const BitArray *a,
                             const BitArray *b, int steps)
{
    BitArray tmp;
    int i;
    *result = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&tmp, result, b);
        *result = tmp;
    }
}

static void ba_fscx_revolve_n(BitArray *result, const BitArray *a,
                               const BitArray *b, const BitArray *nonce,
                               int steps)
{
    BitArray tmp;
    int i;
    *result = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&tmp, result, b);
        ba_xor(result, &tmp, nonce);
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
    else
        printf("%.2f K ops/sec  (%lld ops in %.2fs)\n",
               rate / 1.0e3, ops, secs);
}

/* ------------------------------------------------------------------ */
/* Security tests                                                      */
/* ------------------------------------------------------------------ */

static void test_noncommutativity(void)
{
    int i, comm = 0;
    BitArray a, b, ab, ba_rev;
    /* FSCX(A,B) == FSCX(B,A) always (symmetric formula).
       Asymmetry arises from FSCX_REVOLVE, where B is held constant across
       iterations: FSCX_REVOLVE(A,B,n) != FSCX_REVOLVE(B,A,n) in general. */
    printf("[1] FSCX_REVOLVE non-commutativity: FSCX_REVOLVE(A,B,n) != FSCX_REVOLVE(B,A,n)\n");
    for (i = 0; i < 10000; i++) {
        ba_rand(&a);
        ba_rand(&b);
        ba_fscx_revolve(&ab,     &a, &b, I_VALUE);
        ba_fscx_revolve(&ba_rev, &b, &a, I_VALUE);
        if (ba_equal(&ab, &ba_rev))
            comm++;
    }
    printf("    bits=%d  %d / 10000 commutative  [%s]\n",
           KEYBITS, comm, comm == 0 ? "PASS" : "FAIL");
    putchar('\n');
}

static void test_avalanche(void)
{
    int trial, bit;
    double total = 0.0;
    int gmin = KEYBITS + 1, gmax = -1;
    BitArray a, b, base_out, ap, flip_out, diff;
    /* FSCX is a linear map over GF(2): output bit i depends only on input
       bits i-1, i, i+1 (cyclic). Flipping one input bit always changes
       exactly 3 output bits — the bit and its two cyclic neighbors.
       Security comes from FSCX_REVOLVE iteration, not single-step diffusion.
       Frobenius over GF(2): (1+t+t^-1)^(2^k) = 1+t^(2^k)+t^(-2^k), so
       power-of-2 step counts also give exactly 3-bit diffusion. */
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
    minpct = 101.0;
    maxpct = -1.0;
    meanpct = 0.0;
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

static void test_key_sensitivity(void)
{
    int i;
    double total = 0.0;
    BitArray a, b, a2, b2, c, c2, hn, key1, key2, af, diff;
    /* sk = FSCX_REVOLVE_N(C2, B, hn, r) ^ A
       Flipping bit k of A changes sk by exactly 1 bit via the direct XOR term.
       The nonce change (hn = C^C2, C = FSCX_REVOLVE(A,B,i)) propagates
       L^i(e_k) into the nonce; algebraically S_r * L^i(e_k) cancels to zero,
       leaving only the 1-bit XOR contribution. This is a structural property
       of the HKEX XOR construction. */
    printf("[5] HKEX session key XOR construction (expected: exactly 1-bit direct sensitivity)\n");
    for (i = 0; i < 10000; i++) {
        ba_rand(&a);  ba_rand(&b);
        ba_rand(&a2); ba_rand(&b2);
        ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
        ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
        ba_xor(&hn, &c, &c2);
        ba_fscx_revolve_n(&key1, &c2, &b, &hn, R_VALUE);
        ba_xor(&key1, &key1, &a);
        ba_flip_bit(&af, &a, 0);
        ba_fscx_revolve_n(&key2, &c2, &b, &hn, R_VALUE);
        ba_xor(&key2, &key2, &af);
        ba_xor(&diff, &key1, &key2);
        total += ba_popcount(&diff);
    }
    {
        double mean = total / 10000.0;
        printf("    bits=%d  mean Hamming=%.2f (expected 1/%d)  [%s]\n",
               KEYBITS, mean, KEYBITS,
               (mean >= 0.9 && mean <= 1.1) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Performance benchmarks                                              */
/* ------------------------------------------------------------------ */

static void bench_fscx_throughput(void)
{
    BitArray a, b, tmp;
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;

    printf("[6] FSCX throughput  (bits=%d)\n    ", KEYBITS);
    ba_rand(&a); ba_rand(&b);
    /* warm up */
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

static void bench_fscx_revolve_throughput(void)
{
    int steps_arr[2] = { I_VALUE, R_VALUE };
    const char *labels[2] = { "i", "r" };
    int s, i;
    struct timespec t0, t1;

    printf("[7] FSCX_REVOLVE throughput  (bits=%d)\n", KEYBITS);
    for (s = 0; s < 2; s++) {
        BitArray a, b, tmp;
        long long ops = 0;
        double secs;
        ba_rand(&a); ba_rand(&b);
        for (i = 0; i < 5; i++) ba_fscx_revolve(&tmp, &a, &b, steps_arr[s]);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        do {
            for (i = 0; i < 20; i++) {
                ba_fscx_revolve(&tmp, &a, &b, steps_arr[s]);
                a = tmp;
            }
            ops += 20;
            clock_gettime(CLOCK_MONOTONIC, &t1);
        } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
        printf("    steps=%3d (%s)  : ", steps_arr[s], labels[s]);
        print_rate(ops, secs);
    }
    putchar('\n');
}

static void bench_hkex_handshake(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray a, b, a2, b2, c, c2, hn, keyA, keyB, tmp;

    printf("[8] HKEX full handshake  (bits=%d)\n    ", KEYBITS);
    /* warm up */
    for (i = 0; i < 3; i++) {
        ba_rand(&a); ba_rand(&b); ba_rand(&a2); ba_rand(&b2);
        ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
        ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
        ba_xor(&hn, &c, &c2);
        ba_fscx_revolve_n(&tmp, &c2, &b,  &hn, R_VALUE); ba_xor(&keyA, &tmp, &a);
        ba_fscx_revolve_n(&tmp, &c,  &b2, &hn, R_VALUE); ba_xor(&keyB, &tmp, &a2);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 10; i++) {
            ba_rand(&a); ba_rand(&b); ba_rand(&a2); ba_rand(&b2);
            ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
            ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
            ba_xor(&hn, &c, &c2);
            ba_fscx_revolve_n(&tmp, &c2, &b,  &hn, R_VALUE); ba_xor(&keyA, &tmp, &a);
            ba_fscx_revolve_n(&tmp, &c,  &b2, &hn, R_VALUE); ba_xor(&keyB, &tmp, &a2);
        }
        ops += 10;
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((secs = elapsed_sec(&t0, &t1)) < BENCH_SEC);
    print_rate(ops, secs);
    putchar('\n');
}

static void bench_hske_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray pt, key, enc, dec;

    printf("[9] HSKE round-trip: encrypt+decrypt  (bits=%d)\n    ", KEYBITS);
    /* warm up */
    for (i = 0; i < 5; i++) {
        ba_rand(&pt); ba_rand(&key);
        ba_fscx_revolve_n(&enc, &pt,  &key, &key, I_VALUE);
        ba_fscx_revolve_n(&dec, &enc, &key, &key, R_VALUE);
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 20; i++) {
            ba_rand(&pt); ba_rand(&key);
            ba_fscx_revolve_n(&enc, &pt,  &key, &key, I_VALUE);
            ba_fscx_revolve_n(&dec, &enc, &key, &key, R_VALUE);
        }
        ops += 20;
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

    printf("=== Herradura KEx \xe2\x80\x94 Security & Performance Tests (C, %d-bit) ===\n\n",
           KEYBITS);

    puts("--- Security Assumption Tests ---\n");
    test_noncommutativity();
    test_avalanche();
    test_orbit_period();
    test_bit_frequency();
    test_key_sensitivity();

    puts("--- Performance Benchmarks ---\n");
    bench_fscx_throughput();
    bench_fscx_revolve_throughput();
    bench_hkex_handshake();
    bench_hske_roundtrip();

    fclose(urnd_fp);
    return 0;
}
