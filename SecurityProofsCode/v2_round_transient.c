/* v2_round_transient.c -- TODO #343: the exact best r-round trail of ONE NL-FSCX v2
 * round function, for every r up to R, so the deployed criterion W(3n/4) >= n (or
 * n/2 on the linear axis) can be read directly instead of through the slope mu.
 *
 * mu is the minimum mean cycle: the per-round weight a trail pays in the LIMIT.  A
 * trail of r rounds pays W(r) = mu * r + c(r), and the criterion is on W(r), not on
 * mu * r.  This helper measures c.  It is a brute-force reference, not a solver: it
 * stores the whole DDT (differential) or |LAT| (linear) table, 2^(2n) entries of
 * 16 bits, so n <= 14 (512 MB at n = 14).
 *
 * Standalone on purpose, like certified_cycle_mean.c: it does not include
 * herradura.h, because the object is the round as a function, T(x) = M(x) + delta
 * mod 2^n with M = I ^ ROL ^ ROR.  XOR with the key B before M changes neither a
 * difference nor the magnitude of a correlation, so T is the whole round.
 *
 *   argv:   n  delta(hex)  axis(0 = differential, 1 = linear)  R
 *   stdout: R lines "r W(r)", W(r) = the least weight of an r-round trail whose
 *           input is nonzero, in bits: -log2 of the probability (differential)
 *           or of the absolute correlation (linear) of its best characteristic.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *m) { fprintf(stderr, "v2_round_transient: %s\n", m); exit(2); }

int main(int argc, char **argv)
{
    if (argc != 5) die("usage: n delta(hex) axis R");
    int n = atoi(argv[1]), axis = atoi(argv[3]), R = atoi(argv[4]);
    uint32_t d = (uint32_t)strtoul(argv[2], NULL, 16);
    if (n < 3 || n > 14) die("n out of range (3..14)");
    if (axis != 0 && axis != 1) die("axis must be 0 or 1");
    if (R < 1) die("R must be positive");
    uint32_t N = 1u << n, mask = N - 1;
    d &= mask;

    uint32_t *T = malloc(N * sizeof *T);
    uint16_t *tab = calloc((size_t)N * N, sizeof *tab);   /* tab[u * N + v] */
    if (!T || !tab) die("out of memory");
    for (uint32_t x = 0; x < N; x++) {
        uint32_t m = (x ^ (((x << 1) | (x >> (n - 1))) & mask)
                        ^ (((x >> 1) | (x << (n - 1))) & mask)) & mask;
        T[x] = (m + d) & mask;
    }

    if (axis == 0) {
        /* DDT: tab[a][b] = #{x : T(x) ^ T(x ^ a) = b}; tab[0][0] = 2^n is never used */
        for (uint32_t a = 1; a < N; a++) {
            uint16_t *row = tab + (size_t)a * N;
            for (uint32_t x = 0; x < N; x++) row[T[x] ^ T[x ^ a]]++;
        }
    } else {
        /* |LAT|: tab[u][v] = |sum_x (-1)^(u.x ^ v.T(x))|, one Walsh transform per v */
        int32_t *f = malloc(N * sizeof *f);
        if (!f) die("out of memory");
        for (uint32_t v = 1; v < N; v++) {
            for (uint32_t x = 0; x < N; x++) f[x] = __builtin_parity(v & T[x]) ? -1 : 1;
            for (uint32_t h = 1; h < N; h <<= 1)
                for (uint32_t i = 0; i < N; i += h << 1)
                    for (uint32_t j = i; j < i + h; j++) {
                        int32_t a = f[j], b = f[j + h];
                        f[j] = a + b;
                        f[j + h] = a - b;
                    }
            for (uint32_t u = 0; u < N; u++) {
                int32_t c = f[u] < 0 ? -f[u] : f[u];
                if (c > 65535) die("Walsh entry out of range");
                tab[(size_t)u * N + v] = (uint16_t)c;
            }
        }
        free(f);
    }

    /* weight of an entry: n - log2(count) for both axes (probability count / 2^n,
     * correlation |walsh| / 2^n); a zero entry is no edge */
    double *lg = malloc((N + 1) * sizeof *lg);
    double *cur = malloc(N * sizeof *cur), *nxt = malloc(N * sizeof *nxt);
    if (!lg || !cur || !nxt) die("out of memory");
    lg[0] = INFINITY;
    for (uint32_t c = 1; c <= N; c++) lg[c] = n - log2((double)c);

    cur[0] = INFINITY;                                    /* the input is nonzero */
    for (uint32_t u = 1; u < N; u++) cur[u] = 0.0;
    for (int r = 1; r <= R; r++) {
        for (uint32_t v = 0; v < N; v++) nxt[v] = INFINITY;
        for (uint32_t u = 1; u < N; u++) {
            double cu = cur[u];
            if (cu == INFINITY) continue;
            const uint16_t *row = tab + (size_t)u * N;
            for (uint32_t v = 1; v < N; v++) {
                double w = cu + lg[row[v]];
                if (w < nxt[v]) nxt[v] = w;
            }
        }
        double best = INFINITY;
        for (uint32_t v = 1; v < N; v++) if (nxt[v] < best) best = nxt[v];
        printf("%d %.12f\n", r, best);
        double *t = cur; cur = nxt; nxt = t;
    }
    return 0;
}
