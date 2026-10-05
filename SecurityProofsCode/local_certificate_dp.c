/* local_certificate_dp.c -- the two bit-position passes of TODO #257's local
 * certificate (seventh pass), in C, driven by local_certificate_n256.py.
 * Standalone: it reads the carry-pair automaton tables on stdin, so it cannot
 * disagree with the Python sources about what an edge is.
 *
 *   dp   : the SOUND slot-max DP (log-renormalised per layer), plus back-pointer
 *          traces from the best final states.
 *   vit  : the exact single-carry-path Viterbi, used only to separate.
 *
 * Protocol (stdin/stdout, persistent):
 *   init : "n w ncut" / d as hex (MSB first) / 64 doubles = NT[(d,g,e,e2)][to][from]
 *   loop : n*P doubles (G[s][p], s = 0..n-1) -> prints
 *          "sound <v>" / "dp <k>" + k lines "a b" (hex) / "vit <k>" + k lines
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN 512
static int n, w, P, ncut, dbit[MAXN];
static double NT[2][2][2][2][2][2];      /* [d][g][e][e2][to][from] */
static double *G;

static int hexval(int c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static void read_hex(int *bits) {
    char s[MAXN];
    if (scanf("%s", s) != 1) exit(1);
    int L = strlen(s);
    memset(bits, 0, sizeof(int) * MAXN);
    for (int i = 0; i < L; i++) {
        int v = hexval(s[L - 1 - i]);
        for (int j = 0; j < 4 && 4 * i + j < MAXN; j++) bits[4 * i + j] = (v >> j) & 1;
    }
}
static void print_hex(const int *bits) {
    int nib = (n + 3) / 4, started = 0;
    for (int i = nib - 1; i >= 0; i--) {
        int v = 0;
        for (int j = 0; j < 4; j++) if (4 * i + j < n) v |= bits[4 * i + j] << j;
        if (v || started || i == 0) { putchar("0123456789abcdef"[v]); started = 1; }
    }
}

/* state: aw (w bits), bw (w-1 bits), ek, nz [, c] */
#define SIDX(aw, bw, ek, nz) ((((aw) << (w - 1) | (bw)) << 2) | ((ek) << 1) | (nz))

typedef struct { int prev, anx, bk; } Back;

typedef struct { double v; int copy, st; } Fin;
static int fin_cmp(const void *x, const void *y) {      /* descending by v */
    double a = ((const Fin *)x)->v, b = ((const Fin *)y)->v;
    return a < b ? 1 : a > b ? -1 : 0;
}

static void trace(Back *layers, int S, int st, int Z, int *a, int *b) {
    memset(a, 0, sizeof(int) * MAXN);
    memset(b, 0, sizeof(int) * MAXN);
    for (int k = n - 1; k >= 0; k--) {
        Back *bp = &layers[(size_t)k * S + st];
        if (k < n - 1) a[k + 1] = bp->anx;
        b[k] = bp->bk;
        st = bp->prev;
    }
    a[0] = Z;
}

int main(void) {
    if (scanf("%d %d %d", &n, &w, &ncut) != 3) return 1;
    P = 1 << w;
    read_hex(dbit);
    for (int d = 0; d < 2; d++) for (int g = 0; g < 2; g++) for (int e = 0; e < 2; e++)
        for (int e2 = 0; e2 < 2; e2++) for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++)
            if (scanf("%lf", &NT[d][g][e][e2][i][j]) != 1) return 1;
    G = malloc(sizeof(double) * n * P);
    int S = (P << (w - 1)) * 4, S2 = S * 2, bm = (1 << (w - 1)) - 1;
    double *c0 = malloc(sizeof(double) * S), *c1 = malloc(sizeof(double) * S);
    double *n0 = malloc(sizeof(double) * S), *n1 = malloc(sizeof(double) * S);
    double *nsum = malloc(sizeof(double) * S);
    char *on = malloc(S), *non = malloc(S);
    double *vc = malloc(sizeof(double) * S2), *vn = malloc(sizeof(double) * S2);
    Back *L4[4], *V4[4];
    for (int q = 0; q < 4; q++) {
        L4[q] = malloc(sizeof(Back) * (size_t)n * S);
        V4[q] = malloc(sizeof(Back) * (size_t)n * S2);
    }
    Fin *fin = malloc(sizeof(Fin) * 4 * S2);
    int *a = malloc(sizeof(int) * MAXN), *b = malloc(sizeof(int) * MAXN);
    int *seenA = malloc(sizeof(int) * MAXN * (ncut + 1)), *seenB = malloc(sizeof(int) * MAXN * (ncut + 1));

    for (;;) {
        for (int i = 0; i < n * P; i++) if (scanf("%lf", &G[i]) != 1) return 0;
        /* ---------------- the sound DP ---------------- */
        double best = -1e300;
        int nf = 0;
        for (int A0 = 0; A0 < 2; A0++) for (int Z = 0; Z < 2; Z++) {
            int q = A0 * 2 + Z;
            double lacc = 0.0;
            memset(on, 0, S);
            int s0i = SIDX((A0 << (w - 2)) | (Z << (w - 1)), 0, 0, A0 | Z);
            on[s0i] = 1; c0[s0i] = 1.0; c1[s0i] = 0.0;
            for (int k = 0; k < n; k++) {
                memset(non, 0, S);
                int s0 = k - w + 1;
                const double *gk = (s0 >= 0 && s0 <= n - w) ? G + (size_t)s0 * P : NULL;
                int dk = dbit[k];
                Back *bk_l = L4[q] + (size_t)k * S;
                for (int st = 0; st < S; st++) {
                    if (!on[st]) continue;
                    int nz = st & 1, ek = (st >> 1) & 1, bw = (st >> 2) & bm, aw = st >> (w + 1);
                    double v0 = c0[st], v1 = c1[st];
                    int gm = ((aw >> (w - 2)) ^ (aw >> (w - 1))) & 1;
                    int alo = 0, ahi = 1;
                    if (k == n - 2) alo = ahi = A0;
                    if (k == n - 1) alo = ahi = Z;
                    for (int anx = alo; anx <= ahi; anx++) {
                        int g = gm ^ anx, bkk = g ^ ek;
                        double sc = gk ? exp2(gk[bw | (bkk << (w - 1))] - gk[aw]) : 1.0;
                        int naw = (aw >> 1) | (anx << (w - 1));
                        int nbw = ((bw >> 1) | (bkk << (w - 2))) & bm, nnz = nz | anx;
                        for (int enx = 0; enx < (k <= n - 2 ? 2 : 1); enx++) {
                            double a0, a1;
                            int key;
                            if (k <= n - 2) {
                                double (*M)[2] = NT[dk][g][ek][enx];
                                a0 = (M[0][0] * v0 + M[0][1] * v1) * sc;
                                a1 = (M[1][0] * v0 + M[1][1] * v1) * sc;
                                if (a0 == 0 && a1 == 0) continue;
                                key = SIDX(naw, nbw, enx, nnz);
                            } else {
                                a0 = v0 * sc; a1 = v1 * sc;
                                key = SIDX(naw, nbw, 0, nnz);
                            }
                            if (!non[key]) {
                                non[key] = 1; n0[key] = a0; n1[key] = a1; nsum[key] = a0 + a1;
                                bk_l[key].prev = st; bk_l[key].anx = anx; bk_l[key].bk = bkk;
                            } else {
                                if (a0 > n0[key]) n0[key] = a0;
                                if (a1 > n1[key]) n1[key] = a1;
                                if (a0 + a1 > nsum[key]) {
                                    nsum[key] = a0 + a1;
                                    bk_l[key].prev = st; bk_l[key].anx = anx; bk_l[key].bk = bkk;
                                }
                            }
                        }
                    }
                }
                double m = 0.0;
                for (int st = 0; st < S; st++) if (non[st]) {
                    if (n0[st] > m) m = n0[st];
                    if (n1[st] > m) m = n1[st];
                }
                for (int st = 0; st < S; st++) if (non[st]) { c0[st] = n0[st] / m; c1[st] = n1[st] / m; }
                memcpy(on, non, S);
                lacc += log2(m);
            }
            for (int st = 0; st < S; st++) if (on[st] && (st & 1) && c0[st] + c1[st] > 0) {
                double lv = lacc + log2(c0[st] + c1[st]);
                if (lv > best) best = lv;
                fin[nf].v = lv; fin[nf].copy = q; fin[nf].st = st; nf++;
            }
        }
        printf("sound %.17g\n", (n - 1) - best);
        qsort(fin, nf, sizeof(Fin), fin_cmp);
        int k1 = nf < ncut ? nf : ncut;
        printf("dp %d\n", k1);
        for (int i = 0; i < k1; i++) {
            trace(L4[fin[i].copy], S, fin[i].st, fin[i].copy & 1, a, b);
            print_hex(a); putchar(' '); print_hex(b); putchar('\n');
        }
        /* ---------------- the Viterbi ---------------- */
        nf = 0;
        for (int A0 = 0; A0 < 2; A0++) for (int Z = 0; Z < 2; Z++) {
            int q = A0 * 2 + Z;
            for (int i = 0; i < S2; i++) vc[i] = -INFINITY;
            vc[SIDX((A0 << (w - 2)) | (Z << (w - 1)), 0, 0, A0 | Z) * 2] = 0.0;
            for (int k = 0; k < n; k++) {
                for (int i = 0; i < S2; i++) vn[i] = -INFINITY;
                int s0 = k - w + 1;
                const double *gk = (s0 >= 0 && s0 <= n - w) ? G + (size_t)s0 * P : NULL;
                int dk = dbit[k];
                Back *bk_l = V4[q] + (size_t)k * S2;
                for (int st2 = 0; st2 < S2; st2++) {
                    double v = vc[st2];
                    if (v == -INFINITY) continue;
                    int c = st2 & 1, st = st2 >> 1;
                    int nz = st & 1, ek = (st >> 1) & 1, bw = (st >> 2) & bm, aw = st >> (w + 1);
                    int gm = ((aw >> (w - 2)) ^ (aw >> (w - 1))) & 1;
                    int alo = 0, ahi = 1;
                    if (k == n - 2) alo = ahi = A0;
                    if (k == n - 1) alo = ahi = Z;
                    for (int anx = alo; anx <= ahi; anx++) {
                        int g = gm ^ anx, bkk = g ^ ek;
                        double sc = gk ? gk[bw | (bkk << (w - 1))] - gk[aw] : 0.0;
                        int naw = (aw >> 1) | (anx << (w - 1));
                        int nbw = ((bw >> 1) | (bkk << (w - 2))) & bm, nnz = nz | anx;
                        if (k <= n - 2) {
                            for (int enx = 0; enx < 2; enx++) for (int c2 = 0; c2 < 2; c2++) {
                                double me = NT[dk][g][ek][enx][c2][c];
                                if (me <= 0) continue;
                                int key = SIDX(naw, nbw, enx, nnz) * 2 + c2;
                                double val = v + log2(me) + sc;
                                if (val > vn[key]) {
                                    vn[key] = val;
                                    bk_l[key].prev = st2; bk_l[key].anx = anx; bk_l[key].bk = bkk;
                                }
                            }
                        } else {
                            int key = SIDX(naw, nbw, 0, nnz) * 2 + c;
                            double val = v + sc;
                            if (val > vn[key]) {
                                vn[key] = val;
                                bk_l[key].prev = st2; bk_l[key].anx = anx; bk_l[key].bk = bkk;
                            }
                        }
                    }
                }
                memcpy(vc, vn, sizeof(double) * S2);
            }
            for (int i = 0; i < S2; i++) if (vc[i] > -INFINITY && ((i >> 1) & 1)) {
                fin[nf].v = vc[i]; fin[nf].copy = q; fin[nf].st = i; nf++;
            }
        }
        qsort(fin, nf, sizeof(Fin), fin_cmp);
        int got = 0;
        for (int i = 0; i < nf && got < ncut; i++) {
            trace(V4[fin[i].copy], S2, fin[i].st, fin[i].copy & 1, a, b);
            int dup = 0;
            for (int j = 0; j < got && !dup; j++)
                if (!memcmp(seenA + j * MAXN, a, sizeof(int) * n) &&
                    !memcmp(seenB + j * MAXN, b, sizeof(int) * n)) dup = 1;
            if (dup) continue;
            memcpy(seenA + got * MAXN, a, sizeof(int) * n);
            memcpy(seenB + got * MAXN, b, sizeof(int) * n);
            got++;
        }
        printf("vit %d\n", got);
        for (int j = 0; j < got; j++) {
            print_hex(seenA + j * MAXN); putchar(' '); print_hex(seenB + j * MAXN); putchar('\n');
        }
        fflush(stdout);
    }
}
