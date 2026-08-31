/* v3_consumer_cost.c — TODO #255: the END-TO-END cost of the five NL-FSCX v3
 * consumers against their v2 counterparts.
 *
 * benchmarks/v3_round_cost.c settles the PER-ROUND ratio (2.12-2.17x) in a
 * shared limb representation where only chi differs.  That is the right number
 * for the design question and the wrong one for a deployment question, because
 * the two versions do not run the same number of rounds and two of the five
 * consumers are not a single block cipher call:
 *
 *   hske-nla3     R3_VALUE = 160  vs  hske-nla2's   R_VALUE = 192
 *   hpke-nl3      R3_VALUE = 160  vs  hpke-nl's     I_VALUE =  64   (*)
 *   hske-duplex3  I3_VALUE =  80  vs  hske-duplex's I_VALUE =  64,
 *                 per PERMUTATION CALL, and a duplex call is one permutation
 *                 per 16-byte block plus a fixed ~5 for init/AD/finalise
 *   fpe/twk --v3  R3_VALUE = 160  vs  R_VALUE = 192
 *
 * (*) hpke-nl runs I_VALUE, not R_VALUE -- a quirk of the deployed wire format,
 * not a design choice v3 inherits.  hpke-nl3 uses the derived R3_VALUE, so it
 * is 2.5x the rounds on top of the per-round cost.  That is the one place the
 * v3 family is materially more expensive than a round-count-scaled reading of
 * v3_round_cost.c would suggest, and it is reported here rather than buried.
 *
 * This links the SHIPPED code (herradura.h) rather than re-implementing, so the
 * figures are of the code that runs, including its BitArray representation --
 * which is byte-per-limb big-endian, not the packed 4x64 of v3_round_cost.c, so
 * the absolute nanoseconds here are much larger and the RATIOS are what carry.
 *
 * Build/run:  gcc -O2 -I. -o /tmp/v3cons benchmarks/v3_consumer_cost.c && /tmp/v3cons
 *
 * RECORDED (ARM64 SBC, gcc -O2), and the headline is that #255's projected
 * "~1.77x per block" does NOT hold for the shipped C path -- it is ~0.97x:
 *
 *   per round, both at 160        1.16x    <- not v3_round_cost.c's 2.15x
 *   hske-nla2 -> hske-nla3        0.97x    (160 rounds against 192)
 *   fpe       -> fpe --v3         0.97x
 *   twk       -> twk --v3         0.98x
 *   hpke-nl   -> hpke-nl3         2.92x    (160 rounds against I_VALUE's 64)
 *   duplex    -> duplex3, 4 KiB   1.45x    (80 permutation rounds against 64)
 *   duplex    -> duplex3, 64 B    1.38x    (fixed init/AD/tag cost dominates)
 *
 * Every one of those follows from the per-round 1.16x times the round-count
 * ratio -- 1.16 * 160/192 = 0.97, 1.16 * 160/64 = 2.90, 1.16 * 80/64 = 1.45 --
 * so the model is not fitted, it is checked.
 *
 * WHY 1.16x AND NOT 2.15x.  Both are correct measurements of different things.
 * v3_round_cost.c uses a packed 4x64 representation where the v2 round is a few
 * limb operations and chi roughly doubles it.  herradura.h's BitArray is 32
 * separate bytes, so the v2 round's ROL/ROR/XOR and its 256-bit carry chain are
 * already byte-serial and comparatively slow, and chi -- also byte-wise
 * shift-and-mask -- adds proportionally much less.  The packed figure is the
 * one that matters for a future optimised port; this one is the cost today.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../herradura.h"

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* Timing methodology.  This is a ratio benchmark on a machine that may be
 * shared, thermally throttled or frequency-scaled, and a naive "run A for a
 * while, then run B for a while" comparison picks up any drift between the two
 * halves as if it were a difference between the two functions -- badly enough,
 * on the ARM SBC this was developed on, to report v3 as FASTER than v2 at equal
 * round counts, which is impossible: the v3 round is the v2 round plus chi.
 *
 * So: fixed iteration count, the two candidates measured ALTERNATELY within
 * each repetition so drift hits both equally, and the MINIMUM over repetitions
 * taken for each -- the minimum is the standard robust estimator here, since
 * every source of error in a timing loop is additive.
 */
#define REPS  9
#define ITERS 40
#define TIME_IT(label_v2, label_v3, body_v2, body_v3)                        \
    do {                                                                     \
        double best2 = 1e30, best3 = 1e30;                                   \
        int rep_, it_;                                                       \
        for (rep_ = 0; rep_ < REPS; rep_++) {                                \
            double t0, el;                                                   \
            t0 = now_s();                                                    \
            for (it_ = 0; it_ < ITERS; it_++) { body_v2; }                   \
            el = (now_s() - t0) / (double)ITERS;                             \
            if (el < best2) best2 = el;                                      \
            t0 = now_s();                                                    \
            for (it_ = 0; it_ < ITERS; it_++) { body_v3; }                   \
            el = (now_s() - t0) / (double)ITERS;                             \
            if (el < best3) best3 = el;                                      \
        }                                                                    \
        printf("  %-14s %10.2f us   %-14s %10.2f us   ratio %5.2fx\n",       \
               label_v2, best2 * 1e6, label_v3, best3 * 1e6, best3 / best2); \
    } while (0)

int main(void)
{
    BitArray P, K, N, out;
    uint8_t key_b[KEYBYTES];
    FILE *u = fopen("/dev/urandom", "rb");
    if (!u) { fprintf(stderr, "cannot open /dev/urandom\n"); return 1; }
    ba_rand(&P, u); ba_rand(&K, u); ba_rand(&N, u);
    fclose(u);
    memcpy(key_b, K.b, KEYBYTES);

    printf("NL-FSCX v3 consumers vs. their v2 counterparts (TODO #255)\n");
    printf("R_VALUE=%d  R3_VALUE=%d  I_VALUE=%d  I3_VALUE=%d\n\n",
           R_VALUE, R3_VALUE, I_VALUE, I3_VALUE);

    /* Per-round, at EQUAL round counts, so the round-count effect is separated
     * from the per-round one.  This number is NOT v3_round_cost.c's 2.15x and
     * is not meant to be: that measures a packed 4x64 representation where the
     * v2 round is cheap and chi is most of the added work.  herradura.h's
     * BitArray is 32 separate bytes, so the v2 round's carry propagation is
     * already byte-serial and chi -- also byte-wise shift-and-mask -- is a much
     * smaller relative addition. */
    printf("Per-round, both at R3_VALUE=%d rounds:\n", R3_VALUE);
    TIME_IT("v2 @160", "v3 @160",
            nl_fscx_revolve_v2_ba(&out, &P, &K, R3_VALUE),
            nl_fscx_revolve_v3_ba(&out, &P, &K, R3_VALUE));

    printf("\nSingle 256-bit block, each at its own deployed round count:\n");
    TIME_IT("hske-nla2", "hske-nla3",
            nl_fscx_revolve_v2_ba(&out, &P, &K, R_VALUE),
            nl_fscx_revolve_v3_ba(&out, &P, &K, R3_VALUE));
    /* hpke-nl's symmetric layer only -- the GF exponentiation is identical in
     * both and would swamp the difference this benchmark is about. */
    TIME_IT("hpke-nl", "hpke-nl3",
            nl_fscx_revolve_v2_ba(&out, &P, &K, I_VALUE),
            nl_fscx_revolve_v3_ba(&out, &P, &K, R3_VALUE));
    TIME_IT("fpe", "fpe --v3",
            fpe_encrypt(&P, key_b, KEYBYTES, (const uint8_t *)"ctx", 3, &out),
            fpe_v3_encrypt(&P, key_b, KEYBYTES, (const uint8_t *)"ctx", 3, &out));
    TIME_IT("twk", "twk --v3",
            twk_encrypt(&P, key_b, KEYBYTES, 7, 3, &out),
            twk_v3_encrypt(&P, key_b, KEYBYTES, 7, 3, &out));

    /* The duplex is per-message, not per-block: its fixed cost (init + AD +
     * finalise) is ~5 permutation calls, so short messages are dominated by it
     * and the ratio only approaches the per-permutation one as the message
     * grows.  Both sizes are reported for that reason. */
    {
        static uint8_t pt[4096], ct[4096], tag[32];
        const uint8_t *ad = (const uint8_t *)"header";
        size_t i;
        for (i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)i;
        printf("\nDuplex AEAD, whole message (init + AD + body + tag):\n");
        TIME_IT("duplex 64B", "duplex3 64B",
                hske_nl_v2_duplex_encrypt(&K, &N, ad, 6, pt, 64, ct, tag),
                hske_nl_v3_duplex_encrypt(&K, &N, ad, 6, pt, 64, ct, tag));
        TIME_IT("duplex 4KiB", "duplex3 4KiB",
                hske_nl_v2_duplex_encrypt(&K, &N, ad, 6, pt, sizeof pt, ct, tag),
                hske_nl_v3_duplex_encrypt(&K, &N, ad, 6, pt, sizeof pt, ct, tag));
    }

    printf("\nRatios are what carry here; the absolute figures are of the\n"
           "shipped byte-per-limb BitArray, not the packed 4x64 representation\n"
           "benchmarks/v3_round_cost.c times.\n");
    return 0;
}
