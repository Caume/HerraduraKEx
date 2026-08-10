/* TODO #129 (extended by TODO #182 for HKEX-RNL reconciliation): constant-time
 * audit of core arithmetic primitives.
 *
 * A simplified dudect-style leakage test: for each primitive, compare the
 * per-call timing distribution when the secret-position operand is held
 * fixed (all-0x00) against when it is freshly randomized on every call.  A
 * Welch's t-test |t| >= 4.5 on the two distributions is dudect's standard
 * "leak detected" threshold (fixed-vs-random methodology, Reparaz et al.
 * 2017).  Measurements are interleaved and order-randomized per round to
 * cancel drift/thermal effects, and the first samples of each batch are
 * discarded to avoid cold-cache bias.
 *
 * Build: gcc -O2 -o dudect_timing_audit SecurityProofsCode/dudect_timing_audit.c
 * Run:   ./dudect_timing_audit [rounds]
 */
#include "../herradura.h"
#include <time.h>
#include <math.h>

#define N_PER_ROUND 4000
#define WARMUP      50

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void rand_ba(BitArray *a, FILE *urnd) { ba_rand(a, urnd); }

static void welch_t(const double *a, int na, const double *b, int nb,
                     double *t_out, double *mean_a, double *mean_b)
{
    double ma = 0, mb = 0, va = 0, vb = 0;
    int i;
    for (i = 0; i < na; i++) ma += a[i];
    ma /= na;
    for (i = 0; i < nb; i++) mb += b[i];
    mb /= nb;
    for (i = 0; i < na; i++) va += (a[i] - ma) * (a[i] - ma);
    va /= (na - 1);
    for (i = 0; i < nb; i++) vb += (b[i] - mb) * (b[i] - mb);
    vb /= (nb - 1);
    *mean_a = ma; *mean_b = mb;
    *t_out = (ma - mb) / sqrt(va / na + vb / nb);
}

/* Runs one leakage test. setup_fixed/setup_random fill the secret operand;
 * op() is timed. Returns Welch's t statistic. */
typedef void (*setup_fn)(BitArray *secret, FILE *urnd);
typedef void (*op_fn)(const BitArray *secret, const BitArray *pub);

static double run_test(const char *name, int rounds, setup_fn setup_fixed,
                        setup_fn setup_random, op_fn op, FILE *urnd)
{
    double *fixed_t = malloc(sizeof(double) * rounds);
    double *rand_t  = malloc(sizeof(double) * rounds);
    BitArray fixed_secret, rand_secret, pub;
    int i;
    double t, ma, mb;

    setup_fixed(&fixed_secret, urnd);
    ba_rand(&pub, urnd);

    for (i = 0; i < WARMUP; i++) op(&fixed_secret, &pub);

    for (i = 0; i < rounds; i++) {
        uint64_t t0, t1;
        int fixed_first = (i & 1);
        BitArray rs;
        setup_random(&rs, urnd);

        if (fixed_first) {
            t0 = now_ns(); op(&fixed_secret, &pub); t1 = now_ns();
            fixed_t[i] = (double)(t1 - t0);
            t0 = now_ns(); op(&rs, &pub); t1 = now_ns();
            rand_t[i] = (double)(t1 - t0);
        } else {
            t0 = now_ns(); op(&rs, &pub); t1 = now_ns();
            rand_t[i] = (double)(t1 - t0);
            t0 = now_ns(); op(&fixed_secret, &pub); t1 = now_ns();
            fixed_t[i] = (double)(t1 - t0);
        }
    }

    welch_t(fixed_t, rounds, rand_t, rounds, &t, &ma, &mb);
    printf("%-28s  mean_fixed=%.1fns mean_random=%.1fns  |t|=%.2f  %s\n",
           name, ma, mb, fabs(t), fabs(t) >= 4.5 ? "LEAK SUSPECTED" : "clean");
    free(fixed_t); free(rand_t);
    return t;
}

static void setup_zero(BitArray *a, FILE *urnd) { (void)urnd; memset(a->b, 0, KEYBYTES); }
static void setup_rand(BitArray *a, FILE *urnd) { rand_ba(a, urnd); }

/* Batch 7 (TODO #129): Batch 3's residual stern_gen_perm/stern_apply_perm
 * signal was attributed to hardware-level timing at the *degenerate
 * all-zero* pi_seed test point, not to the (already fixed-loop-count,
 * data-independent-branch) Lemire-map algorithm itself. If that attribution
 * is right, swapping the fixed secret for a non-zero, non-degenerate bit
 * pattern should make the residual |t| collapse; if the leak is structural
 * it should persist regardless of which fixed value is used. */
static void setup_pattern(BitArray *a, FILE *urnd)
{ (void)urnd; memset(a->b, 0xA5, KEYBYTES); }

static void op_gf_mul(const BitArray *secret, const BitArray *pub)
{ BitArray d; gf_mul_ba(&d, secret, pub); }

static void op_gf_pow(const BitArray *secret, const BitArray *pub)
{ BitArray d; gf_pow_ba(&d, pub, secret); }

static void op_mul_mod_ord(const BitArray *secret, const BitArray *pub)
{ BitArray d; ba_mul_mod_ord(&d, secret, pub); }

static void op_fscx_revolve(const BitArray *secret, const BitArray *pub)
{ BitArray d; ba_fscx_revolve(&d, pub, secret, I_VALUE); }

/* Batch 2 (TODO #129): Stern-F permutation generation/application and
 * WOTS-F signing. stern_gen_perm's Fisher-Yates draws are rejection-sampled
 * from a PRNG keyed on the (per-round, ephemeral) pi_seed, so its loop count
 * is secret-dependent by construction; stern_apply_perm's *memory access
 * pattern* (not its instruction path — it is already branchless) is
 * secret-permutation-dependent, which a wall-clock t-test cannot detect
 * (it requires cache-timing instrumentation) — see SecurityProofs-3.md
 * §11.11 for the structural discussion. These two tests characterise the
 * wall-clock-visible component only. */
static void op_stern_gen_perm(const BitArray *secret, const BitArray *pub)
{ (void)pub; uint8_t perm[KEYBITS]; stern_gen_perm(perm, secret, KEYBITS); }

static void op_stern_apply_perm(const BitArray *secret, const BitArray *pub)
{
    uint8_t perm[KEYBITS];
    BitArray out;
    stern_gen_perm(perm, secret, KEYBITS);
    stern_apply_perm(&out, perm, pub, KEYBITS);
}

static void op_wots_sign(const BitArray *secret, const BitArray *pub)
{
    BitArray sig[WOTS_L];
    static const uint8_t msg[] = "TODO #129 dudect fixed message";
    hpks_wots_sign(sig, msg, sizeof msg, secret->b, pub->b[0]);
}

/* Batch 8 (TODO #182): HKEX-RNL Peikert reconciliation. Recent literature
 * (single-trace power analysis on HQC decode; Ring-LWE/LWR template attacks
 * via cyclic message rotation) targets exactly this step -- the arithmetic
 * that turns a noisy shared ring element into agreed key bits. rnl_hint and
 * rnl_reconcile_bits both operate on the *secret* K_poly (the raw shared
 * secret polynomial, s*c_lifted); the RNL_N/8-byte hint itself is public
 * (transmitted unauthenticated per herradura.h's own comment) so it is not
 * tested as a secret operand here. Uses rnl_poly_t (int32_t[RNL_N]) secrets,
 * not BitArray, so a parallel run_test_poly harness is used instead of
 * run_test. */
static uint8_t g_hint[RNL_N / 8];
static int32_t g_c_other[RNL_N];

static void poly_setup_zero(rnl_poly_t p, FILE *urnd)
{ (void)urnd; memset(p, 0, sizeof(rnl_poly_t)); }

/* Coefficients pinned exactly at rnl_hint's/rnl_reconcile_bits's rounding
 * thresholds (multiples of q/4), the values most likely to expose a
 * division/comparison that isn't actually constant-time despite RNL_Q being
 * a compile-time constant -- same rationale as Batch 7's 0xA5 pattern test. */
static void poly_setup_boundary(rnl_poly_t p, FILE *urnd)
{ (void)urnd; int i; for (i = 0; i < RNL_N; i++) p[i] = RNL_Q / 4; }

static void poly_setup_rand(rnl_poly_t p, FILE *urnd)
{
    int i;
    for (i = 0; i < RNL_N; i++) {
        uint16_t v = 0;
        if (fread(&v, sizeof v, 1, urnd) != 1) v = 0;
        p[i] = (int32_t)(v % RNL_Q);
    }
}

static void op_rnl_hint(const rnl_poly_t secret)
{ uint8_t hint[RNL_N / 8]; rnl_hint(hint, secret); }

static void op_rnl_reconcile_bits(const rnl_poly_t secret)
{ BitArray out; rnl_reconcile_bits(&out, secret, g_hint); }

/* Exercises rnl_agree's reconciler path end to end (rnl_lift + rnl_poly_mul +
 * rnl_hint + rnl_reconcile_bits together); secret is the private polynomial
 * s, g_c_other stands in for the other party's received (public) c. */
static void op_rnl_agree(const rnl_poly_t secret)
{
    BitArray out;
    uint8_t hint_out[RNL_N / 8];
    rnl_agree(&out, secret, g_c_other, NULL, hint_out);
}

static double run_test_poly(const char *name, int rounds,
                             void (*setup_fixed)(rnl_poly_t, FILE *),
                             void (*setup_random)(rnl_poly_t, FILE *),
                             void (*op)(const rnl_poly_t), FILE *urnd)
{
    double *fixed_t = malloc(sizeof(double) * rounds);
    double *rand_t  = malloc(sizeof(double) * rounds);
    rnl_poly_t fixed_secret;
    int i;
    double t, ma, mb;

    setup_fixed(fixed_secret, urnd);

    for (i = 0; i < WARMUP; i++) op(fixed_secret);

    for (i = 0; i < rounds; i++) {
        uint64_t t0, t1;
        int fixed_first = (i & 1);
        rnl_poly_t rs;
        setup_random(rs, urnd);

        if (fixed_first) {
            t0 = now_ns(); op(fixed_secret); t1 = now_ns();
            fixed_t[i] = (double)(t1 - t0);
            t0 = now_ns(); op(rs); t1 = now_ns();
            rand_t[i] = (double)(t1 - t0);
        } else {
            t0 = now_ns(); op(rs); t1 = now_ns();
            rand_t[i] = (double)(t1 - t0);
            t0 = now_ns(); op(fixed_secret); t1 = now_ns();
            fixed_t[i] = (double)(t1 - t0);
        }
    }

    welch_t(fixed_t, rounds, rand_t, rounds, &t, &ma, &mb);
    printf("%-28s  mean_fixed=%.1fns mean_random=%.1fns  |t|=%.2f  %s\n",
           name, ma, mb, fabs(t), fabs(t) >= 4.5 ? "LEAK SUSPECTED" : "clean");
    free(fixed_t); free(rand_t);
    return t;
}

int main(int argc, char **argv)
{
    int rounds = (argc > 1) ? atoi(argv[1]) : 4000;
    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) { fprintf(stderr, "cannot open /dev/urandom\n"); return 1; }

    printf("dudect-style fixed-vs-random timing audit (TODO #129), rounds=%d\n", rounds);
    printf("Welch |t| >= 4.5 => leak suspected (dudect threshold)\n\n");

    run_test("gf_mul_ba (secret=operand a)",      rounds, setup_zero, setup_rand, op_gf_mul,        urnd);
    run_test("gf_pow_ba (secret=exponent)",        rounds, setup_zero, setup_rand, op_gf_pow,        urnd);
    run_test("ba_mul_mod_ord (secret=operand a)",  rounds, setup_zero, setup_rand, op_mul_mod_ord,   urnd);
    run_test("ba_fscx_revolve (secret=key operand)", rounds, setup_zero, setup_rand, op_fscx_revolve, urnd);
    run_test("stern_gen_perm (secret=pi_seed)",      rounds, setup_zero, setup_rand, op_stern_gen_perm,   urnd);
    run_test("stern_apply_perm (secret=pi_seed)",    rounds, setup_zero, setup_rand, op_stern_apply_perm, urnd);
    run_test("stern_gen_perm (fixed=0xA5 pattern)",   rounds, setup_pattern, setup_rand, op_stern_gen_perm,   urnd);
    run_test("stern_apply_perm (fixed=0xA5 pattern)", rounds, setup_pattern, setup_rand, op_stern_apply_perm, urnd);
    run_test("hpks_wots_sign (secret=master_seed)",  rounds, setup_zero, setup_rand, op_wots_sign,        urnd);

    /* Batch 8 (TODO #182): seed the public-side operands once (a fixed,
     * plausible hint and received-c value; neither is secret, so fixing them
     * doesn't affect the leak test) and audit the reconciliation path. */
    {
        int i;
        for (i = 0; i < RNL_N / 8; i++) g_hint[i] = 0x55;
        for (i = 0; i < RNL_N; i++)     g_c_other[i] = i % RNL_P;
    }
    run_test_poly("rnl_hint (secret=K_poly)",            rounds, poly_setup_zero,     poly_setup_rand, op_rnl_hint,           urnd);
    run_test_poly("rnl_hint (fixed=q/4 boundary)",        rounds, poly_setup_boundary, poly_setup_rand, op_rnl_hint,           urnd);
    run_test_poly("rnl_reconcile_bits (secret=K_poly)",   rounds, poly_setup_zero,     poly_setup_rand, op_rnl_reconcile_bits, urnd);
    run_test_poly("rnl_reconcile_bits (fixed=q/4)",       rounds, poly_setup_boundary, poly_setup_rand, op_rnl_reconcile_bits, urnd);
    run_test_poly("rnl_agree (secret=s)",                 rounds, poly_setup_zero,     poly_setup_rand, op_rnl_agree,          urnd);

    fclose(urnd);
    return 0;
}
