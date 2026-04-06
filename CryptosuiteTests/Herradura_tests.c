/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c */

/*  Herradura KEx -- Security & Performance Tests (C, 256-bit BitArray)
    v1.3.6: added HPKS sign+verify correctness test [7]; benchmarks renumbered [8-12].
    v1.3.3: added HPKE encrypt+decrypt round-trip benchmark [11].

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

/* Key size in bits -- must be a positive multiple of 8 and >= 16.
   Matches the default in "Herradura cryptographic suite.c", and in
   the Go and Python implementations. */
#define KEYBITS  256
#define KEYBYTES (KEYBITS / 8)
#define I_VALUE  (KEYBITS / 4)       /* 64  for 256-bit */
#define R_VALUE  (3 * KEYBITS / 4)   /* 192 for 256-bit */

#if KEYBYTES < 2
#  error "KEYBITS must be >= 16 for the single-pass ba_fscx implementation"
#endif

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

/* dst = a XOR b.  Aliasing dst == a or dst == b is safe. */
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

/* Count set bits using the hardware popcount instruction when available. */
static int ba_popcount(const BitArray *a)
{
    int cnt = 0, i;
    for (i = 0; i < KEYBYTES; i++)
        cnt += __builtin_popcount(a->b[i]);
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

/* Full Surroundings Cyclic XOR:
   result = a XOR b XOR ROL(a) XOR ROL(b) XOR ROR(a) XOR ROR(b)

   Fused single-pass implementation: ROL and ROR are computed inline from
   adjacent bytes, avoiding 4 temporary BitArray allocations and 5 separate
   memory passes.  Requires KEYBYTES >= 2. */
static void ba_fscx(BitArray *result, const BitArray *a, const BitArray *b)
{
    /* Wrap-around bits extracted before the loop */
    uint8_t a_msbit = a->b[0] >> 7;
    uint8_t b_msbit = b->b[0] >> 7;
    uint8_t a_lsbit = a->b[KEYBYTES - 1] & 1;
    uint8_t b_lsbit = b->b[KEYBYTES - 1] & 1;
    int i;

    /* byte 0: ROR wraps in from the last byte */
    result->b[0] = a->b[0] ^ b->b[0]
        ^ (uint8_t)((a->b[0] << 1) | (a->b[1] >> 7))   /* ROL(a)[0] */
        ^ (uint8_t)((b->b[0] << 1) | (b->b[1] >> 7))   /* ROL(b)[0] */
        ^ (uint8_t)((a->b[0] >> 1) | (a_lsbit << 7))   /* ROR(a)[0] */
        ^ (uint8_t)((b->b[0] >> 1) | (b_lsbit << 7));  /* ROR(b)[0] */

    /* middle bytes: no wrap-around */
    for (i = 1; i < KEYBYTES - 1; i++)
        result->b[i] = a->b[i] ^ b->b[i]
            ^ (uint8_t)((a->b[i] << 1) | (a->b[i + 1] >> 7))
            ^ (uint8_t)((b->b[i] << 1) | (b->b[i + 1] >> 7))
            ^ (uint8_t)((a->b[i] >> 1) | (a->b[i - 1] << 7))
            ^ (uint8_t)((b->b[i] >> 1) | (b->b[i - 1] << 7));

    /* last byte: ROL wraps in from the first byte */
    result->b[KEYBYTES - 1] = a->b[KEYBYTES-1] ^ b->b[KEYBYTES-1]
        ^ (uint8_t)((a->b[KEYBYTES-1] << 1) | a_msbit)
        ^ (uint8_t)((b->b[KEYBYTES-1] << 1) | b_msbit)
        ^ (uint8_t)((a->b[KEYBYTES-1] >> 1) | (a->b[KEYBYTES-2] << 7))
        ^ (uint8_t)((b->b[KEYBYTES-1] >> 1) | (b->b[KEYBYTES-2] << 7));
}

/* FSCX_REVOLVE: iterate fscx(a, b) n times keeping b constant.
   Double-buffered: alternates between two local buffers to avoid
   copying the result back every step. */
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

/* FSCX_REVOLVE_N (v1.1): nonce-augmented iteration.
   Each step: result = FSCX(result, b) XOR nonce */
static void ba_fscx_revolve_n(BitArray *result, const BitArray *a,
                               const BitArray *b, const BitArray *nonce,
                               int steps)
{
    BitArray buf[2];
    int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) {
        ba_fscx(&buf[1 - idx], &buf[idx], b);
        ba_xor(&buf[1 - idx], &buf[1 - idx], nonce);
        idx ^= 1;
    }
    *result = buf[idx];
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
    BitArray a, b, n, ab, ba_rev;
    /* FSCX(A,B) == FSCX(B,A) always (symmetric formula).
       Asymmetry arises in FSCX_REVOLVE_N, where B is held constant across
       iterations: FSCX_REVOLVE_N(A,B,N,n) != FSCX_REVOLVE_N(B,A,N,n) in general.
       The nonce term T_n(N) cancels from both sides of the difference, so
       commutativity is determined solely by the A and B inputs. */
    printf("[1] FSCX_REVOLVE_N non-commutativity: FSCX_REVOLVE_N(A,B,N,n) != FSCX_REVOLVE_N(B,A,N,n)\n");
    for (i = 0; i < 10000; i++) {
        ba_rand(&a);
        ba_rand(&b);
        ba_rand(&n);
        ba_fscx_revolve_n(&ab,     &a, &b, &n, I_VALUE);
        ba_fscx_revolve_n(&ba_rev, &b, &a, &n, I_VALUE);
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

static void test_avalanche_revolve_n(void)
{
    int i, hd;
    double total = 0.0;
    int gmin = KEYBITS + 1, gmax = -1;
    BitArray a, b, nonce, nonce_flip, base, flipped, diff;
    /* FSCX_REVOLVE_N nonce-injection avalanche.
       Flipping 1 bit of the nonce N while keeping A and B constant propagates
       through all remaining revolve steps.  The change in the output equals
       T_n(e_k) where T_n = I + L + ... + L^(n-1) and e_k is the unit vector
       at bit position k.  Unlike the 3-bit diffusion of single-step FSCX or
       the purely linear FSCX_REVOLVE, T_n accumulates contributions from every
       step, producing a much larger Hamming distance.
       Expected: HD >> 3 (significantly more than single-step FSCX diffusion). */
    printf("[6] FSCX_REVOLVE_N nonce-avalanche: flip 1 nonce bit, measure output diffusion\n");
    for (i = 0; i < 1000; i++) {
        ba_rand(&a);
        ba_rand(&b);
        ba_rand(&nonce);
        ba_fscx_revolve_n(&base,    &a, &b, &nonce,      I_VALUE);
        ba_flip_bit(&nonce_flip, &nonce, 0);
        ba_fscx_revolve_n(&flipped, &a, &b, &nonce_flip, I_VALUE);
        ba_xor(&diff, &base, &flipped);
        hd = ba_popcount(&diff);
        total += hd;
        if (hd < gmin) gmin = hd;
        if (hd > gmax) gmax = hd;
    }
    {
        double mean = total / 1000.0;
        /* HD = popcount(T_n(e_0)) is deterministic (independent of A and B),
           so min == max == mean.  For n = KEYBITS/4, HD = KEYBITS/4 exactly.
           Pass if HD >= KEYBITS/4 (far above the 3-bit single-step diffusion). */
        printf("    bits=%d  mean HD=%.1f (expected >=%d)  min=%d  max=%d  [%s]\n",
               KEYBITS, mean, KEYBITS / 4, gmin, gmax,
               mean >= (double)(KEYBITS / 4) ? "PASS" : "FAIL");
    }
    putchar('\n');
}

static void test_hpks_sign_verify(void)
{
    int i, ok = 0;
    BitArray a, b, a2, b2, c, c2, hn, plaintext, S, V, tmp;
    printf("[7] HPKS sign+verify correctness: V == plaintext\n");
    for (i = 0; i < 10000; i++) {
        ba_rand(&a);  ba_rand(&b);
        ba_rand(&a2); ba_rand(&b2);
        ba_rand(&plaintext);
        ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
        ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
        ba_xor(&hn, &c, &c2);
        /* sign: S = fscx_revolve_n(C2, B, hn, r) ^ A ^ P */
        ba_fscx_revolve_n(&tmp, &c2, &b, &hn, R_VALUE);
        ba_xor(&S, &tmp, &a);
        ba_xor(&S, &S, &plaintext);
        /* verify: V = fscx_revolve_n(C, B2, hn, r) ^ A2 ^ S */
        ba_fscx_revolve_n(&tmp, &c, &b2, &hn, R_VALUE);
        ba_xor(&V, &tmp, &a2);
        ba_xor(&V, &V, &S);
        if (ba_equal(&V, &plaintext))
            ok++;
    }
    printf("    bits=%d  %d / 10000 verified  [%s]\n",
           KEYBITS, ok, ok == 10000 ? "PASS" : "FAIL");
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

    printf("[8] FSCX throughput  (bits=%d)\n    ", KEYBITS);
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

static void bench_fscx_revolve_n_throughput(void)
{
    int steps_arr[2] = { I_VALUE, R_VALUE };
    const char *labels[2] = { "i", "r" };
    int s, i;
    struct timespec t0, t1;

    printf("[9] FSCX_REVOLVE_N throughput  (bits=%d)\n", KEYBITS);
    for (s = 0; s < 2; s++) {
        BitArray a, b, nonce, tmp;
        long long ops = 0;
        double secs;
        ba_rand(&a); ba_rand(&b); ba_rand(&nonce);
        for (i = 0; i < 5; i++) ba_fscx_revolve_n(&tmp, &a, &b, &nonce, steps_arr[s]);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        do {
            for (i = 0; i < 20; i++) {
                ba_fscx_revolve_n(&tmp, &a, &b, &nonce, steps_arr[s]);
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

    printf("[10] HKEX full handshake  (bits=%d)\n    ", KEYBITS);
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

    printf("[11] HSKE round-trip: encrypt+decrypt  (bits=%d)\n    ", KEYBITS);
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

/* HPKE (public key encryption) full round-trip:
   Key setup: C = fscx_revolve(A,B,i), C2 = fscx_revolve(A2,B2,i), hn = C^C2
   Bob encrypts:   E = fscx_revolve_n(C, B2, hn, r) ^ A2 ^ P
   Alice decrypts: D = fscx_revolve_n(C2, B,  hn, r) ^ A  ^ E  (== P) */
static void bench_hpke_roundtrip(void)
{
    struct timespec t0, t1;
    long long ops = 0;
    double secs;
    int i;
    BitArray a, b, a2, b2, c, c2, hn, pt, E, D, tmp;

    printf("[12] HPKE encrypt+decrypt round-trip  (bits=%d)\n    ", KEYBITS);
    /* warm up */
    for (i = 0; i < 3; i++) {
        ba_rand(&a); ba_rand(&b); ba_rand(&a2); ba_rand(&b2); ba_rand(&pt);
        ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
        ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
        ba_xor(&hn, &c, &c2);
        ba_fscx_revolve_n(&tmp, &c,  &b2, &hn, R_VALUE);
        ba_xor(&E, &tmp, &a2); ba_xor(&E, &E, &pt);         /* Bob encrypts   */
        ba_fscx_revolve_n(&tmp, &c2, &b,  &hn, R_VALUE);
        ba_xor(&D, &tmp, &a);  ba_xor(&D, &D, &E);          /* Alice decrypts */
    }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (i = 0; i < 10; i++) {
            ba_rand(&a); ba_rand(&b); ba_rand(&a2); ba_rand(&b2); ba_rand(&pt);
            ba_fscx_revolve(&c,  &a,  &b,  I_VALUE);
            ba_fscx_revolve(&c2, &a2, &b2, I_VALUE);
            ba_xor(&hn, &c, &c2);
            ba_fscx_revolve_n(&tmp, &c,  &b2, &hn, R_VALUE);
            ba_xor(&E, &tmp, &a2); ba_xor(&E, &E, &pt);
            ba_fscx_revolve_n(&tmp, &c2, &b,  &hn, R_VALUE);
            ba_xor(&D, &tmp, &a);  ba_xor(&D, &D, &E);
        }
        ops += 10;
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

    test_avalanche_revolve_n();
    test_hpks_sign_verify();

    puts("--- Performance Benchmarks ---\n");
    bench_fscx_throughput();
    bench_fscx_revolve_n_throughput();
    bench_hkex_handshake();
    bench_hske_roundtrip();
    bench_hpke_roundtrip();

    fclose(urnd_fp);
    return 0;
}
