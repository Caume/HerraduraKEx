/* rnl_deployed_ring_cost.c — TODO #292: what HKEX-RNL costs at the ring that
 * actually ships, in the languages that actually ship it.
 *
 * THE GAP THIS FILLS.  TODO #223 moved HKEX-RNL from n = 256 to n = 1024 and
 * nothing in the tree has measured the deployed ring in a compiled language
 * since.  Both benchmark harnesses stop short of it, and not by oversight:
 *
 *   CryptosuiteTests/Herradura_tests.c   rnl_sizes[] = {32, 64, 128, 256}
 *   CryptosuiteTests/Herradura_tests.py  RNL_SIZES   = [32, 64, 128, 256]
 *
 * against `RNL_N 1024` in the header those harnesses sit next to.  TODO #225
 * established WHY they cannot simply follow -- each harness transcribes the
 * primitives rather than importing them, and uses ONE variable for both the
 * ring dimension and the key width, so its KDF line computes
 * `_RNL_KDF_DC_256 >> (256 - n_rnl)` and raises on any n > 256.  The suite
 * keeps the two separate (the ring is 1024, the derived session key stays
 * KEYBITS = 256), which is exactly the distinction #223 introduced and the
 * harnesses predate.  #225 then measured the deployed ring in PYTHON
 * (benchmarks/rnl_ring_cost.py) and left the compiled targets alone, because
 * its question was where the `native-python` job's time goes.
 *
 * So the published cost figure for the protocol the suite recommends has been
 * a Python figure at an interpreted NTT, and benchmark [40]'s C column has
 * reported a ring the suite retired.  This file and its .go/.py siblings
 * measure the shipped path -- herradura.h's own rnl_keygen / rnl_agree, not a
 * transcription -- at RNL_N, so the three read the same table.
 *
 * IT GATES.  A throughput number for a key exchange whose two sides do not
 * agree is not a slow handshake, it is no handshake, and a benchmark that
 * asserts nothing exits 0 either way (the class TODO #229 fixed in CliTest).
 * Both sides must reconcile to the same 256-bit key on every control
 * iteration or this exits non-zero before timing anything.
 *
 * Build/run:  gcc -O2 -I. -o /tmp/rnlcost benchmarks/rnl_deployed_ring_cost.c \
 *                 -lpthread && /tmp/rnlcost
 *
 * RECORDED (ARM64 SBC, gcc -O2), per operation:
 *
 *   keygen (s, C)                     0.120 ms
 *   agree, reconciler side (+hint)    0.118 ms
 *   agree, receiver side              0.117 ms
 *   rnl_poly_mul alone (NTT)          0.114 ms
 *   m_blind derivation (rand+add)     0.029 ms
 *   full two-party handshake          0.505 ms   (1979 /s)
 *
 * These are v7.0.11 figures and they are the SAME figures v7.0.10 recorded
 * (0.121 / 0.119 / 0.118 / 0.114 / 0.030 / 0.508).  That is the point of
 * re-running them: TODO #293 buffered the CSPRNG read in Go, Python and Java
 * and deliberately did NOT touch C, which had been amortising all along
 * through a buffered FILE *.  The C column is therefore the CONTROL for that
 * change -- it establishes that the host has not moved between the two
 * releases, so the Go and Python columns below can be compared across them.
 *
 * FOUR THINGS THE TABLE SAYS, and the last two are the ones worth keeping.
 *
 * (1) THE HANDSHAKE IS FOUR NTTs AND ALMOST NOTHING ELSE.  rnl_poly_mul is
 *     0.114 ms and a whole keygen is 0.121, so CBD sampling, rounding, hint
 *     generation and reconciliation together cost ~7 us -- 6% of one keygen.
 *     4 x 0.119 + 0.030 = 0.506 against a measured 0.508 ms handshake, so the
 *     model is checked rather than fitted.  Any future cost work on HKEX-RNL
 *     is NTT work; in C there is nothing else to find.
 *
 * (2) SCALING IS O(n log n), CONFIRMED AGAINST THE HARNESS.  Benchmark [40]
 *     measures 9.08 K handshakes/s at n = 256 (0.110 ms); this measures
 *     0.508 ms at n = 1024.  That is 4.6x for 4x the dimension, not 16x.  The
 *     #223 ring move bought ~32 -> ~206 Core-SVP bits for 4.6x the time.
 *
 * (3) HKEX-RNL IS 32x FASTER THAN THE CLASSICAL PROTOCOL IT REPLACES.  [34]
 *     measures HKEX-GF's full handshake at 62 ops/s at n = 256 in the same C,
 *     against 1970 /s here at n = 1024.  The classical quartet is demo-only on
 *     a ~2^36.5 Pohlig-Hellman break (SECURITY.md), and it is ALSO the slower
 *     construction by a factor of 32 -- so cost is not what keeps it in the
 *     tree, and no cost argument exists for preferring it.
 *
 * (4) THE THREE LANGUAGES DID NOT AGREE ABOUT WHERE THE TIME GOES, which is
 *     what made a three-column table worth more than a C column -- and is
 *     what this file found.  Same host, same ring, per handshake, with the
 *     v7.0.10 measurement that opened TODO #293 and the v7.0.11 one that
 *     closed it:
 *
 *                       C         Go v7.0.10 -> v7.0.11   Python (pure-Py NTT)
 *       poly_mul    0.114 ms      0.197 ->  0.179 ms      9.32  ->  9.28 ms
 *       m_blind     0.029 ms      0.642 ->  0.048 ms      1.01  ->  0.590 ms
 *       handshake   0.505 ms      1.517 ->  1.088 ms     39.96  -> 39.36 ms
 *
 *     In C and Python the handshake was always the NTT.  In Go it was NOT:
 *     m_blind derivation alone was 0.642 ms of a 1.517 ms handshake -- more
 *     than all four NTTs together, and 21x the same step here.  The cause was
 *     the CSPRNG read pattern, and C is the one port that escaped it by
 *     accident: rnl_rand_poly above draws THREE BYTES per rejection-sampling
 *     iteration exactly as Go's RnlRandPoly and Python's _rnl_rand_poly did,
 *     ~1028 of them per polynomial at n = 1024, but it reads them through a
 *     BUFFERED FILE * and they did not.
 *
 *     TODO #293 buffered all three (Go, Python, Java; C needed nothing).
 *     Go's m_blind is now 0.048 ms -- 13.4x cheaper, 4.4% of a handshake
 *     rather than 40% -- and a Go handshake is 2.15x C's rather than 3.0x.
 *     Two numbers in the paragraph above are WORTH CORRECTING rather than
 *     leaving as they were written.  The "factor of 50" was 1028 x
 *     rand.Read(3) against ONE rand.Read(3084), i.e. reads with no sampler
 *     around them; against the buffered sampler actually shipped, arithmetic
 *     and modulo included, it is 19.9x (0.614 -> 0.031 ms), and the residue
 *     is loop cost rather than read cost.  And Java, which #293 expected to
 *     escape because SecureRandom is "a userspace DRBG rather than a kernel
 *     read", escapes for C's reason instead: it resolves to NativePRNG, which
 *     reads /dev/urandom behind a buffer.  Its multiplier is 3.0x (0.163 ->
 *     0.053 ms), the smallest of the four, but the mechanism is buffering,
 *     not the entropy source.
 *
 *     The Python column is the PURE-PYTHON NTT path -- this host has no numpy.
 *     The suite chooses the path at import and its banner reports which one is
 *     live (TODO #225); a Python figure for HKEX-RNL that does not say which
 *     path produced it is not a figure, which is why the .py sibling prints it.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../herradura.h"

#define BENCH_SECS   2.0
#define CONTROL_ITERS 20

static double elapsed(const struct timespec *a, const struct timespec *b)
{
    return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

static void report(const char *label, long long ops, double secs)
{
    printf("  %-34s %8.3f ms   %9.1f /s\n",
           label, 1000.0 * secs / (double)ops, (double)ops / secs);
}

int main(void)
{
    FILE *urnd = fopen("/dev/urandom", "rb");
    rnl_poly_t m_base, a_rand, m_blind, scratch;
    static int32_t s_A[RNL_N], c_A[RNL_N], s_B[RNL_N], c_B[RNL_N];
    uint8_t hint[RNL_N / 8];
    BitArray K_A = BA_INIT, K_B = BA_INIT;
    struct timespec t0, t1;
    long long ops;
    double secs;
    int i, disagreed = 0;

    if (!urnd) { fprintf(stderr, "cannot open /dev/urandom\n"); return 2; }

    printf("HKEX-RNL at the DEPLOYED ring -- RNL_N=%d q=%d p=%d eta=%d, "
           "session key %d bits\n", RNL_N, RNL_Q, RNL_P, RNL_ETA, KEYBITS);

    rnl_m_poly(m_base);

    /* Control.  A rate is meaningless if the two sides do not agree, so this
     * runs first and gates everything after it. */
    for (i = 0; i < CONTROL_ITERS; i++) {
        rnl_rand_poly(a_rand, urnd);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, c_A, m_blind, urnd);
        rnl_keygen(s_B, c_B, m_blind, urnd);
        rnl_agree(&K_A, s_A, c_B, NULL, hint);
        rnl_agree(&K_B, s_B, c_A, hint, NULL);
        if (memcmp(K_A.b, K_B.b, sizeof K_A.b) != 0) disagreed++;
    }
    printf("  control: %d/%d handshakes reconcile to the same key%s\n\n",
           CONTROL_ITERS - disagreed, CONTROL_ITERS,
           disagreed ? "  <-- FAIL" : "");
    if (disagreed) {
        fprintf(stderr, "*** FAILED: %d of %d handshakes disagreed at the "
                        "deployed ring -- timing not run ***\n",
                disagreed, CONTROL_ITERS);
        fclose(urnd);
        return 1;
    }

#define BENCH(label, body)                                                    \
    do {                                                                      \
        ops = 0;                                                              \
        clock_gettime(CLOCK_MONOTONIC, &t0);                                  \
        do { body; ops++; clock_gettime(CLOCK_MONOTONIC, &t1); }              \
        while ((secs = elapsed(&t0, &t1)) < BENCH_SECS);                      \
        report(label, ops, secs);                                             \
    } while (0)

    BENCH("keygen (s, C)",          rnl_keygen(s_A, c_A, m_blind, urnd));
    BENCH("agree, reconciler (+hint)", rnl_agree(&K_A, s_A, c_B, NULL, hint));
    BENCH("agree, receiver",        rnl_agree(&K_B, s_B, c_A, hint, NULL));
    BENCH("rnl_poly_mul alone (NTT)", rnl_poly_mul(scratch, m_blind, s_A));
    BENCH("m_blind derivation (rand+add)", {
        rnl_rand_poly(a_rand, urnd);
        rnl_poly_add(m_blind, m_base, a_rand);
    });
    BENCH("full two-party handshake", {
        rnl_rand_poly(a_rand, urnd);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, c_A, m_blind, urnd);
        rnl_keygen(s_B, c_B, m_blind, urnd);
        rnl_agree(&K_A, s_A, c_B, NULL, hint);
        rnl_agree(&K_B, s_B, c_A, hint, NULL);
    });

#undef BENCH

    printf("\n  A handshake is 4 rnl_poly_mul calls plus ~7 us of everything "
           "else;\n  benchmark [40]'s n=256 column is the RETIRED ring "
           "(TODO #223, #225).\n");
    fclose(urnd);
    return 0;
}
