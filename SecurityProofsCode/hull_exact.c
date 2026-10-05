/* hull_exact.c -- the C helper hull_exact.py compiles and drives (TODO #257,
 * eighth pass).  Standalone: no herradura.h, like certified_cycle_mean.c and
 * local_certificate_dp.c, so tools/poison_build.sh does not discover it.
 *
 * For the NL-FSCX v2 round at width n <= 16, with the shipped round constants
 * (TODO #245),
 *
 *     F_i(x) = M(x ^ i ^ B) + delta(B)  mod 2^n,   M = I ^ ROL ^ ROR,
 *
 * it builds the r-round permutation P_r = F_r o ... o F_1 as a table and
 * measures, EXACTLY and with no trail or independence assumption:
 *
 *   H_lin(r)  = -log2 max_{u,v != 0} |corr(u.x, v.P_r(x))|      (the linear hull)
 *   H_diff(r) = -log2 max_{a != 0, b} Pr[P_r(x) ^ P_r(x^a) = b] (the differential)
 *
 * and, for comparison, the best r-ROUND TRAIL on each axis, i.e. the least
 * weight of an r-step walk on the mask / difference graph (round constants
 * change only signs there, so the graph is the same every round):
 *
 *   T_lin(r), T_diff(r).
 *
 * Modes (one result line per round on stdout):
 *   hull  n B Rh Rt   r H_lin H_diff [T_lin T_diff]   (T only for r <= Rt)
 *   perm  n B r       P_r as 2^n decimal integers, for the cross-check
 *   rand  n seed Rh   H_lin H_diff of a uniformly random permutation (r = 1
 *                     line only; Rh is ignored) -- the ideal-cipher floor
 *   affine n B Rh     the same round with + replaced by ^: an AFFINE map, so
 *                     both hulls must read 0 bits at every r -- the negative
 *                     control that shows the measurement can see a failure
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int n;
static uint32_t N, MASK;

static uint32_t rol(uint32_t x, int k)
{
    k %= n;
    if (!k) return x & MASK;
    return ((x << k) | (x >> (n - k))) & MASK;
}

static uint32_t Mx(uint32_t x) { return (x ^ rol(x, 1) ^ rol(x, n - 1)) & MASK; }

static uint32_t delta_of(uint32_t B)
{
    uint64_t p = (uint64_t)B * (uint64_t)((B + 1) >> 1);
    return rol((uint32_t)(p & MASK), n / 4);
}

static void wht(int32_t *g)
{
    for (uint32_t h = 1; h < N; h <<= 1)
        for (uint32_t i = 0; i < N; i += h << 1)
            for (uint32_t j = i; j < i + h; j++) {
                int32_t a = g[j], b = g[j + h];
                g[j] = a + b;
                g[j + h] = a - b;
            }
}

/* max over u,v != 0 of |W| for permutation P, returned as -log2(max/N) */
static double lin_hull(const uint32_t *P, int32_t *g)
{
    int32_t best = 0;
    for (uint32_t v = 1; v < N; v++) {
        for (uint32_t x = 0; x < N; x++)
            g[x] = (__builtin_popcount(v & P[x]) & 1) ? -1 : 1;
        wht(g);
        for (uint32_t u = 1; u < N; u++) {
            int32_t a = g[u] < 0 ? -g[u] : g[u];
            if (a > best) best = a;
        }
    }
    return -log2((double)best / (double)N);
}

static double diff_hull(const uint32_t *P, uint32_t *cnt)
{
    uint32_t best = 0;
    for (uint32_t a = 1; a < N; a++) {
        memset(cnt, 0, sizeof(uint32_t) * N);
        for (uint32_t x = 0; x < N; x++) cnt[P[x] ^ P[x ^ a]]++;
        for (uint32_t b = 0; b < N; b++)
            if (cnt[b] > best) best = cnt[b];
    }
    return -log2((double)best / (double)N);
}

/* One Bellman step of the linear trail DP.  Masks travel backwards through
 * the round: an output mask beta pulls through "+ delta" to w with
 * correlation g[w]/N, then through M (symmetric) to M(w), then through the
 * XOR constants, which change only the sign.  So the edge is beta -> M(w). */
static void lin_step(const double *D, double *Dn, uint32_t d, const uint32_t *Mt,
                     int32_t *s, int32_t *g)
{
    for (uint32_t i = 0; i < N; i++) Dn[i] = INFINITY;
    for (uint32_t beta = 1; beta < N; beta++) {
        if (!isfinite(D[beta])) continue;
        for (uint32_t y = 0; y < N; y++)
            s[y] = (__builtin_popcount(beta & y) & 1) ? -1 : 1;
        for (uint32_t x = 0; x < N; x++) g[x] = s[(x + d) & MASK];
        wht(g);
        for (uint32_t w = 1; w < N; w++) {
            if (!g[w]) continue;
            double c = fabs((double)g[w]) / (double)N;
            double t = D[beta] - log2(c);
            uint32_t to = Mt[w];
            if (t < Dn[to]) Dn[to] = t;
        }
    }
}

static void diff_step(const double *D, double *Dn, uint32_t d, const uint32_t *Mt,
                      uint32_t *cnt)
{
    for (uint32_t i = 0; i < N; i++) Dn[i] = INFINITY;
    for (uint32_t a = 1; a < N; a++) {
        if (!isfinite(D[a])) continue;
        uint32_t al = Mt[a];
        memset(cnt, 0, sizeof(uint32_t) * N);
        for (uint32_t x = 0; x < N; x++)
            cnt[((x + d) & MASK) ^ (((x ^ al) + d) & MASK)]++;
        for (uint32_t b = 1; b < N; b++) {
            if (!cnt[b]) continue;
            double t = D[a] - log2((double)cnt[b] / (double)N);
            if (t < Dn[b]) Dn[b] = t;
        }
    }
}

static double vmin(const double *D)
{
    double m = INFINITY;
    for (uint32_t i = 1; i < N; i++)
        if (D[i] < m) m = D[i];
    return m;
}

static uint64_t rng_s;
static uint64_t xs(void)
{
    rng_s ^= rng_s << 13;
    rng_s ^= rng_s >> 7;
    rng_s ^= rng_s << 17;
    return rng_s;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: hull_exact {hull|perm|rand|affine} n ...\n");
        return 2;
    }
    const char *mode = argv[1];
    n = atoi(argv[2]);
    if (n < 4 || n > 16) { fprintf(stderr, "n out of range\n"); return 2; }
    N = 1u << n;
    MASK = N - 1;
    uint32_t *P = malloc(sizeof(uint32_t) * N);
    uint32_t *Q = malloc(sizeof(uint32_t) * N);
    uint32_t *cnt = malloc(sizeof(uint32_t) * N);
    uint32_t *Mt = malloc(sizeof(uint32_t) * N);
    int32_t *g = malloc(sizeof(int32_t) * N);
    int32_t *s = malloc(sizeof(int32_t) * N);
    if (!P || !Q || !cnt || !Mt || !g || !s) return 3;
    for (uint32_t x = 0; x < N; x++) Mt[x] = Mx(x);

    if (!strcmp(mode, "rand")) {
        rng_s = strtoull(argv[3], 0, 10) * 0x9E3779B97F4A7C15ull + 1;
        for (uint32_t x = 0; x < N; x++) P[x] = x;
        for (uint32_t x = N - 1; x > 0; x--) {
            uint32_t j = (uint32_t)(xs() % (x + 1));
            uint32_t t = P[x]; P[x] = P[j]; P[j] = t;
        }
        printf("1 %.6f %.6f\n", lin_hull(P, g), diff_hull(P, cnt));
        return 0;
    }

    uint32_t B = (uint32_t)strtoul(argv[3], 0, 10) & MASK;
    uint32_t d = delta_of(B);
    int affine = !strcmp(mode, "affine");
    int R = atoi(argv[4]);
    int Rt = (argc > 5) ? atoi(argv[5]) : 0;

    for (uint32_t x = 0; x < N; x++) P[x] = x;
    double *D = 0, *Dn = 0;
    if (Rt > 0) {
        D = malloc(sizeof(double) * N);
        Dn = malloc(sizeof(double) * N);
        if (!D || !Dn) return 3;
    }
    double *E = 0, *En = 0;
    if (Rt > 0) {
        E = malloc(sizeof(double) * N);
        En = malloc(sizeof(double) * N);
        if (!E || !En) return 3;
        for (uint32_t i = 0; i < N; i++) D[i] = E[i] = 0.0;
    }

    for (int r = 1; r <= R; r++) {
        uint32_t k = ((uint32_t)r ^ B) & MASK;
        for (uint32_t x = 0; x < N; x++) {
            uint32_t y = Mt[(P[x] ^ k) & MASK];
            P[x] = affine ? (y ^ d) : ((y + d) & MASK);
        }
        if (!strcmp(mode, "perm")) {
            if (r == R) {
                for (uint32_t x = 0; x < N; x++) printf("%u\n", P[x]);
            }
            continue;
        }
        double hl = lin_hull(P, g), hd = diff_hull(P, cnt);
        if (r <= Rt) {
            lin_step(D, Dn, d, Mt, s, g);
            diff_step(E, En, d, Mt, cnt);
            double *t = D; D = Dn; Dn = t;
            t = E; E = En; En = t;
            printf("%d %.6f %.6f %.6f %.6f\n", r, hl, hd, vmin(D), vmin(E));
        } else {
            printf("%d %.6f %.6f\n", r, hl, hd);
        }
        fflush(stdout);
    }
    return 0;
}
