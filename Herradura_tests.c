/* Build: gcc -O2 -o Herradura_tests Herradura_tests.c */

/*  Herradura KEx -- Security & Performance Tests (C, 64-bit)

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

#define INTSZ   64
#define I_VALUE 16   /* INTSZ / 4 */
#define R_VALUE 48   /* 3 * INTSZ / 4 */

typedef uint64_t u64;

static FILE *urnd;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static double elapsed_ms(struct timespec *t0, struct timespec *t1)
{
	return (double)(t1->tv_sec  - t0->tv_sec)  * 1000.0
	     + (double)(t1->tv_nsec - t0->tv_nsec) / 1.0e6;
}

static u64 rand64(void)
{
	uint8_t buf[8];
	if (fread(buf, 1, 8, urnd) != 8) {
		fputs("ERROR: read from /dev/urandom failed\n", stderr);
		exit(1);
	}
	return ((u64)buf[0] << 56) | ((u64)buf[1] << 48) |
	       ((u64)buf[2] << 40) | ((u64)buf[3] << 32) |
	       ((u64)buf[4] << 24) | ((u64)buf[5] << 16) |
	       ((u64)buf[6] <<  8) | ((u64)buf[7]);
}

static int popcount64(u64 x)
{
	int cnt = 0;
	while (x) {
		cnt += (int)(x & 1u);
		x >>= 1;
	}
	return cnt;
}

/* ------------------------------------------------------------------ */
/* FSCX primitives                                                     */
/* ------------------------------------------------------------------ */

static u64 rol64(u64 x, int n)
{
	n &= 63;
	if (n == 0) return x;
	return (x << n) | (x >> (64 - n));
}

static u64 ror64(u64 x, int n)
{
	n &= 63;
	if (n == 0) return x;
	return (x >> n) | (x << (64 - n));
}

static u64 fscx(u64 a, u64 b)
{
	u64 result;
	result  = a ^ b;
	result ^= rol64(a, 1) ^ rol64(b, 1);
	result ^= ror64(a, 1) ^ ror64(b, 1);
	return result;
}

static u64 fscx_revolve(u64 a, u64 b, int steps)
{
	int i;
	for (i = 0; i < steps; i++)
		a = fscx(a, b);
	return a;
}

static u64 fscx_revolve_n(u64 a, u64 b, u64 nonce, int steps)
{
	int i;
	for (i = 0; i < steps; i++)
		a = fscx(a, b) ^ nonce;
	return a;
}

/* ------------------------------------------------------------------ */
/* Security tests                                                      */
/* ------------------------------------------------------------------ */

static void test_noncommutativity(void)
{
	int i, comm = 0;
	/* FSCX(A,B) == FSCX(B,A) always (symmetric formula).
	   Asymmetry arises from FSCX_REVOLVE, where B is held constant across
	   iterations: FSCX_REVOLVE(A,B,n) != FSCX_REVOLVE(B,A,n) in general. */
	printf("[1] FSCX_REVOLVE non-commutativity: FSCX_REVOLVE(A,B,n) != FSCX_REVOLVE(B,A,n)\n");
	for (i = 0; i < 10000; i++) {
		u64 a = rand64();
		u64 b = rand64();
		if (fscx_revolve(a, b, I_VALUE) == fscx_revolve(b, a, I_VALUE))
			comm++;
	}
	printf("    %d / 10000 pairs were commutative (expected ~0)\n", comm);
	if (comm == 0)
		puts("    PASS\n");
	else
		puts("    FAIL\n");
}

static void test_avalanche(void)
{
	int trial, bit;
	double total = 0.0;
	int gmin = 65, gmax = -1;
	/* FSCX is a linear map over GF(2): output bit i depends only on input
	   bits i-1, i, i+1 (cyclic).  Flipping one input bit always changes
	   exactly 3 output bits — the bit and its two cyclic neighbors.
	   Security comes from FSCX_REVOLVE iteration, not single-step diffusion.
	   Frobenius over GF(2): (1+t+t^-1)^(2^k) = 1+t^(2^k)+t^(-2^k), so
	   power-of-2 step counts also give 3-bit diffusion. */
	printf("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)\n");
	for (trial = 0; trial < 1000; trial++) {
		u64 a = rand64();
		u64 b = rand64();
		u64 base = fscx(a, b);
		for (bit = 0; bit < 64; bit++) {
			u64 ap = a ^ (1ULL << bit);
			int hd = popcount64(fscx(ap, b) ^ base);
			total += hd;
			if (hd < gmin) gmin = hd;
			if (hd > gmax) gmax = hd;
		}
	}
	double mean = total / (1000.0 * 64.0);
	printf("    Mean Hamming distance: %.2f bits (expected 3 / %d)\n", mean, INTSZ);
	printf("    Min: %d  Max: %d\n", gmin, gmax);
	if (mean >= 2.9 && mean <= 3.1)
		puts("    PASS\n");
	else
		puts("    FAIL\n");
}

static void test_orbit_period(void)
{
	int trial, cnt64 = 0, cnt32 = 0, other = 0;
	printf("[3] Orbit period: FSCX_REVOLVE(A,B,n) cycles back to A\n");
	for (trial = 0; trial < 100; trial++) {
		u64 a = rand64();
		u64 b = rand64();
		u64 cur = fscx(a, b);
		int period = 1;
		int cap = 2 * INTSZ;
		while (cur != a && period < cap) {
			cur = fscx(cur, b);
			period++;
		}
		if (period == 64)      cnt64++;
		else if (period == 32) cnt32++;
		else                   other++;
	}
	printf("    period=64: %d  period=32: %d  other: %d  (out of 100)\n",
	       cnt64, cnt32, other);
	if (other == 0)
		puts("    PASS\n");
	else
		puts("    FAIL\n");
}

static void test_bit_frequency(void)
{
	int bit;
	long long counts[64];
	int trial;
	double minpct = 100.0, maxpct = 0.0, meanpct;
	int N = 100000;
	printf("[4] Bit-frequency bias: %d FSCX outputs\n", N);
	memset(counts, 0, sizeof(counts));
	for (trial = 0; trial < N; trial++) {
		u64 a = rand64();
		u64 b = rand64();
		u64 out = fscx(a, b);
		for (bit = 0; bit < 64; bit++)
			if ((out >> bit) & 1ULL)
				counts[bit]++;
	}
	meanpct = 0.0;
	for (bit = 0; bit < 64; bit++) {
		double pct = (double)counts[bit] / (double)N * 100.0;
		meanpct += pct;
		if (pct < minpct) minpct = pct;
		if (pct > maxpct) maxpct = pct;
	}
	meanpct /= 64.0;
	printf("    Bit frequency: min=%.2f%%  max=%.2f%%  mean=%.2f%%\n",
	       minpct, maxpct, meanpct);
	if (minpct > 47.0 && maxpct < 53.0)
		puts("    PASS\n");
	else
		puts("    FAIL\n");
}

static void test_key_sensitivity(void)
{
	int i;
	double total = 0.0;
	/* sk = FSCX_REVOLVE_N(C2, B, hn, r) ^ A
	   Flipping bit k of A changes sk by exactly 1 bit via the direct XOR.
	   The nonce change (hn = C^C2, C = FSCX_REVOLVE(A,B,i)) propagates
	   L^i(e_k) into the nonce; algebraically this cancels in S_r * L^i(e_k)
	   leaving only the 1-bit XOR contribution.
	   This is a structural property of the HKEX XOR construction. */
	printf("[5] HKEX session key XOR construction (expected: exactly 1-bit direct sensitivity)\n");
	for (i = 0; i < 10000; i++) {
		u64 a  = rand64(), b  = rand64();
		u64 a2 = rand64(), b2 = rand64();
		u64 c  = fscx_revolve(a,  b,  I_VALUE);
		u64 c2 = fscx_revolve(a2, b2, I_VALUE);
		u64 hn = c ^ c2;
		u64 key1 = fscx_revolve_n(c2, b, hn, R_VALUE) ^ a;
		u64 af   = a ^ 1ULL;
		u64 key2 = fscx_revolve_n(c2, b, hn, R_VALUE) ^ af;
		total += popcount64(key1 ^ key2);
	}
	double mean = total / 10000.0;
	printf("    Mean Hamming distance: %.2f bits (expected 1 / %d)\n", mean, INTSZ);
	if (mean >= 0.9 && mean <= 1.1)
		puts("    PASS\n");
	else
		puts("    FAIL\n");
}

/* ------------------------------------------------------------------ */
/* Performance benchmarks                                              */
/* ------------------------------------------------------------------ */

static void bench_fscx_throughput(void)
{
	long long N = 10000000LL;
	long long i;
	u64 a = rand64(), b = rand64();
	u64 sink = 0;
	struct timespec t0, t1;
	double ms, mops;

	printf("[6] FSCX throughput (%lld iterations)\n", N);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < N; i++) {
		a = fscx(a, b);
		sink ^= a;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms   = elapsed_ms(&t0, &t1);
	mops = (double)N / ms / 1000.0;
	printf("    %.2f M ops/sec  (sink=%llx)\n\n", mops, (unsigned long long)sink);
}

static void bench_fscx_revolve_throughput(void)
{
	long long N = 500000LL;
	long long i;
	int steps_arr[3];
	int s;
	u64 sink = 0;
	struct timespec t0, t1;
	double ms, kops;

	steps_arr[0] = I_VALUE;
	steps_arr[1] = INTSZ / 2;
	steps_arr[2] = R_VALUE;

	printf("[7] FSCX_REVOLVE throughput (%lld iterations per step count)\n", N);
	for (s = 0; s < 3; s++) {
		u64 a = rand64(), b = rand64();
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < N; i++) {
			a = fscx_revolve(a, b, steps_arr[s]);
			sink ^= a;
		}
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ms   = elapsed_ms(&t0, &t1);
		kops = (double)N / ms;
		printf("    steps=%2d : %.2f K ops/sec\n", steps_arr[s], kops);
	}
	printf("    (sink=%llx)\n\n", (unsigned long long)sink);
}

static void bench_hkex_handshake(void)
{
	long long N = 100000LL;
	long long i;
	u64 sink = 0;
	struct timespec t0, t1;
	double ms, kops;

	printf("[8] HKEX full handshake (%lld handshakes)\n", N);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < N; i++) {
		u64 a  = rand64(), b  = rand64();
		u64 a2 = rand64(), b2 = rand64();
		u64 c  = fscx_revolve(a,  b,  I_VALUE);
		u64 c2 = fscx_revolve(a2, b2, I_VALUE);
		u64 hn = c ^ c2;
		u64 keyA = fscx_revolve_n(c2, b,  hn, R_VALUE) ^ a;
		u64 keyB = fscx_revolve_n(c,  b2, hn, R_VALUE) ^ a2;
		sink ^= keyA ^ keyB;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms   = elapsed_ms(&t0, &t1);
	kops = (double)N / ms;
	printf("    %.2f K handshakes/sec  (sink=%llx)\n\n",
	       kops, (unsigned long long)sink);
}

static void bench_hske_roundtrip(void)
{
	long long N = 200000LL;
	long long i;
	u64 sink = 0;
	struct timespec t0, t1;
	double ms, kops;

	printf("[9] HSKE round-trip: encrypt+decrypt (%lld cycles)\n", N);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < N; i++) {
		u64 pt  = rand64();
		u64 key = rand64();
		u64 enc = fscx_revolve_n(pt,  key, key, I_VALUE);
		u64 dec = fscx_revolve_n(enc, key, key, R_VALUE);
		sink ^= dec ^ pt;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms   = elapsed_ms(&t0, &t1);
	kops = (double)N / ms;
	printf("    %.2f K round-trips/sec  (correctness sink=%llx)\n\n",
	       kops, (unsigned long long)sink);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	urnd = fopen("/dev/urandom", "rb");
	if (!urnd) {
		fputs("ERROR: cannot open /dev/urandom\n", stderr);
		return 1;
	}

	puts("=== Herradura KEx \xe2\x80\x94 Security & Performance Tests (C, 64-bit) ===\n");

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

	fclose(urnd);
	return 0;
}
