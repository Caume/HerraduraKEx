/* v3_round_mmc.c -- TODO #257 item (3): the certified minimum mean cycle of the
 * NL-FSCX v3 ROUND's own DDT and LAT graphs, at widths past pure Python's reach.
 *
 * The answer is the same object nl_fscx_v3_trail_criterion.py's min_mean_cycle()
 * computes at n = 10, and nl_fscx_v3_linear_width.py checks this program against
 * that solver's pinned n = 10 extremes before using a single number from it.  What
 * differs is how the graph is held:
 *
 *   * the graph is IMPLICIT.  The round-level LAT at n = 17 is 2^34 entries.  A
 *     full pass recomputes it column by column (one Walsh-Hadamard transform of
 *     (-1)^{v.T(x)} per output mask v), and the DDT row by row, so memory is
 *     O(2^n) plus the kept edges.
 *   * Howard runs on a SUBGRAPH G' of the cheap edges (weight <= the cap), held in
 *     memory.  Its cycle mean m is an upper bound on mu(G), attained by a cycle
 *     of G' and hence of G.
 *   * the CERTIFICATE is a potential p, from shortest paths of w - (m - POT_SHIFT)
 *     on G' (certified_cycle_mean.c's shift, for the same rounding reason).  One full pass checks p(u) <= w - (m - POT_SHIFT) + p(v)
 *     + TOL on EVERY edge of G; if it holds, every cycle of G has mean
 *     >= m - POT_SHIFT - TOL, so mu(G) = m to that tolerance.  An edge that
 *     violates it is added to G' and the solve is repeated, so the loop ends
 *     certified or not at all.
 *
 * Standalone on purpose: it does not include herradura.h, because the object it
 * studies is the round as a function of x for a fixed key B,
 *     T(x) = chi( M(x ^ B) + delta(B)  mod 2^n ),  M = I ^ ROL ^ ROR,
 *     delta(B) = ROL(B * ((B + 1) >> 1), n/4),
 * which is nl_fscx_v3_weak_keys.py's Width.v3_table().  The per-round counter XOR
 * the suite also applies is omitted: an input XOR leaves every |DDT| and |LAT|
 * entry unchanged.  The row partition is passed in, LSB row first.
 *
 *   argv:   n  B(hex)  axis(0 = differential, 1 = linear)  threads  cap  r1 r2 ...
 *           cap = the initial G' weight cap in bits
 *   stdout: mu  rounds  certified(0/1)  cycle_length  edges_kept  max_one_round
 *           then the optimal cycle, one "hex-node weight" pair per edge
 *           (max_one_round is the least edge weight in G: -log2 of the round's
 *           largest |corr| or DDT probability)
 */
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EPS 1e-9
#define TOL 1e-9
#define POT_SHIFT 1e-9
#define HOWARD_CAP 1000
#define MAXT 64

static int n, axis, nthreads, nrows, rows[32];
static uint32_t N, MASK;
static uint32_t *T;
static double *LW;          /* LW[k] = -log2(k / N), k = 0..N; LW[0] = inf */

typedef struct { uint32_t u, v; double w; } edge_t;

typedef struct {
    int id;
    int32_t *col;
    edge_t *e;              /* edges collected by this thread */
    size_t ne, cap;
    double minw;            /* least edge weight seen */
    double *nw;             /* per node: its cheapest out-edge so far */
    uint32_t *nv;
} work_t;
static work_t W[MAXT];

static int pass_mode;       /* 0 = collect edges with w <= wcap; 1 = certify */
static double wcap, mcert;
static double *pot;         /* the potential, during a certify pass */

/* G' in CSR form */
static uint64_t *rs;
static uint32_t *tg;
static double *wt;
static size_t nE;

static void die(const char *s) { fprintf(stderr, "v3_round_mmc: %s\n", s); exit(2); }

static uint32_t rol(uint32_t x, int k) { return ((x << k) | (x >> (n - k))) & MASK; }
static uint32_t ror(uint32_t x, int k) { return ((x >> k) | (x << (n - k))) & MASK; }

static uint32_t chi(uint32_t x)
{
    uint32_t out = 0;
    int off = 0;
    for (int r = 0; r < nrows; r++) {
        int L = rows[r];
        for (int i = 0; i < L; i++) {
            uint32_t b0 = (x >> (off + i)) & 1;
            uint32_t b1 = (x >> (off + (i + 1) % L)) & 1;
            uint32_t b2 = (x >> (off + (i + 2) % L)) & 1;
            out |= (b0 ^ ((1 ^ b1) & b2)) << (off + i);
        }
        off += L;
    }
    return out;
}

static void push(work_t *w, uint32_t u, uint32_t v, double x)
{
    if (w->ne == w->cap) {
        w->cap = w->cap ? 2 * w->cap : 1 << 16;
        w->e = realloc(w->e, w->cap * sizeof *w->e);
        if (!w->e) die("out of memory (edges)");
    }
    w->e[w->ne].u = u; w->e[w->ne].v = v; w->e[w->ne].w = x;
    w->ne++;
}

static void edge(work_t *w, uint32_t u, uint32_t v, double x)
{
    if (x < w->minw) w->minw = x;
    if (pass_mode == 0) {
        if (x <= wcap) push(w, u, v, x);
        if (x < w->nw[u] || (x == w->nw[u] && v < w->nv[u])) { w->nw[u] = x; w->nv[u] = v; }
    } else if (pot[u] > x - mcert + pot[v] + TOL) {
        push(w, u, v, x);   /* violates the potential: goes into G' */
    }
}

/* Walk every edge of G.  Linear: edge u -> s (input mask u, output mask s) has
 * weight LW[|W_s(u)|], so the pass is organised by the output mask s.
 * Differential: edge s -> b has weight LW[DDT count], organised by input s. */
static void *walk(void *arg)
{
    work_t *w = (work_t *)arg;
    int32_t *col = w->col;
    for (uint32_t s = 1 + w->id; s < N; s += nthreads) {
        if (axis == 1) {
            for (uint32_t x = 0; x < N; x++)
                col[x] = (__builtin_popcount(s & T[x]) & 1) ? -1 : 1;
            for (uint32_t len = 1; len < N; len <<= 1)
                for (uint32_t i = 0; i < N; i += len << 1)
                    for (uint32_t j = i; j < i + len; j++) {
                        int32_t a = col[j], b = col[j + len];
                        col[j] = a + b;
                        col[j + len] = a - b;
                    }
            for (uint32_t u = 1; u < N; u++) {
                int32_t c = col[u] < 0 ? -col[u] : col[u];
                if (c) edge(w, u, s, LW[c]);
            }
        } else {
            memset(col, 0, N * sizeof(int32_t));
            for (uint32_t x = 0; x < N; x++)
                col[T[x] ^ T[x ^ s]]++;
            for (uint32_t b = 1; b < N; b++)
                if (col[b]) edge(w, s, b, LW[col[b]]);
        }
    }
    return NULL;
}

static double minw_all;

/* one full pass; the edges it collects are appended to the pending list */
static edge_t *pend;
static size_t npend, cpend;

static void full_pass(void)
{
    pthread_t th[MAXT];
    for (int k = 0; k < nthreads; k++) {
        W[k].ne = 0;
        W[k].minw = INFINITY;
        if (pass_mode == 0)
            for (uint32_t u = 0; u < N; u++) { W[k].nw[u] = INFINITY; W[k].nv[u] = 0; }
        pthread_create(&th[k], NULL, walk, &W[k]);
    }
    for (int k = 0; k < nthreads; k++) pthread_join(th[k], NULL);
    for (int k = 0; k < nthreads; k++) {
        if (W[k].minw < minw_all) minw_all = W[k].minw;
        if (npend + W[k].ne > cpend) {
            cpend = 2 * (npend + W[k].ne);
            pend = realloc(pend, cpend * sizeof *pend);
            if (!pend) die("out of memory (pending)");
        }
        memcpy(pend + npend, W[k].e, W[k].ne * sizeof *pend);
        npend += W[k].ne;
    }
}

static int cmp_edge(const void *a, const void *b)
{
    const edge_t *x = a, *y = b;
    if (x->u != y->u) return x->u < y->u ? -1 : 1;
    if (x->v != y->v) return x->v < y->v ? -1 : 1;
    return 0;
}

/* sort pending edges by (u, v), drop duplicates, rebuild the CSR */
static void build_csr(void)
{
    qsort(pend, npend, sizeof *pend, cmp_edge);
    size_t k = 0;
    for (size_t i = 0; i < npend; i++)
        if (k == 0 || pend[i].u != pend[k - 1].u || pend[i].v != pend[k - 1].v)
            pend[k++] = pend[i];
    npend = k;
    nE = k;
    free(tg); free(wt);
    tg = malloc((nE ? nE : 1) * sizeof *tg);
    wt = malloc((nE ? nE : 1) * sizeof *wt);
    if (!tg || !wt) die("out of memory (csr)");
    memset(rs, 0, (N + 1) * sizeof *rs);
    for (size_t i = 0; i < nE; i++) rs[pend[i].u + 1]++;
    for (uint32_t u = 0; u < N; u++) rs[u + 1] += rs[u];
    for (size_t i = 0; i < nE; i++) { tg[i] = pend[i].v; wt[i] = pend[i].w; }
}

/* Howard on G': policy pi, evaluation (mu, h) rooted at each cycle's smallest node
 * (§11.50.3), improvement by (mu, then h).  Every node of G' must have an
 * out-edge; the caller guarantees it.  Returns iterations, or 0 on HOWARD_CAP. */
static uint32_t *pi, *path;
static double *pw, *mu, *h;
static uint8_t *colour;

static void evaluate(void)
{
    memset(colour, 0, N);
    for (uint32_t s = 1; s < N; s++) {
        if (colour[s]) continue;
        uint32_t len = 0, v = s;
        while (!colour[v]) { colour[v] = 1; path[len++] = v; v = pi[v]; }
        uint32_t tail = len;
        if (colour[v] == 1) {
            uint32_t i = 0;
            while (path[i] != v) i++;
            uint32_t cl = len - i, k = 0;
            double sum = 0;
            for (uint32_t j = i; j < len; j++) {
                sum += pw[path[j]];
                if (path[j] < path[i + k]) k = j - i;
            }
            double m = sum / cl;
            for (uint32_t j = i; j < len; j++) mu[path[j]] = m;
            uint32_t c0 = path[i + k];
            h[c0] = 0.0;
            for (uint32_t q = 1; q < cl; q++) {
                uint32_t u = path[i + (k + cl - q) % cl];
                h[u] = pw[u] - m + h[pi[u]];
            }
            tail = i;
        }
        for (uint32_t j = tail; j-- > 0;) {
            uint32_t u = path[j];
            mu[u] = mu[pi[u]];
            h[u] = pw[u] - mu[u] + h[pi[u]];
        }
        for (uint32_t j = 0; j < len; j++) colour[path[j]] = 2;
    }
}

static int howard(void)
{
    for (uint32_t u = 1; u < N; u++) {
        uint64_t b = rs[u];
        for (uint64_t j = rs[u]; j < rs[u + 1]; j++) if (wt[j] < wt[b]) b = j;
        pi[u] = tg[b]; pw[u] = wt[b];
    }
    for (int it = 1; it <= HOWARD_CAP; it++) {
        evaluate();
        int improved = 0;
        for (uint32_t u = 1; u < N; u++) {
            double bmu = mu[u], bh = h[u];
            int64_t bj = -1;
            for (uint64_t j = rs[u]; j < rs[u + 1]; j++) {
                uint32_t b = tg[j];
                double cmu = mu[b];
                if (cmu < bmu - EPS) {
                    bmu = cmu; bh = wt[j] - cmu + h[b]; bj = (int64_t)j;
                } else if (cmu <= bmu + EPS) {
                    double ch = wt[j] - cmu + h[b];
                    if (ch < bh - EPS) { bh = ch; bj = (int64_t)j; }
                }
            }
            if (bj >= 0) { pi[u] = tg[bj]; pw[u] = wt[bj]; improved = 1; }
        }
        if (!improved) return it;
    }
    return 0;
}

/* The potential: the least p with p(u) <= 0 and p(u) <= w - ms + p(v) on every
 * edge u -> v of G', i.e. shortest paths of w - ms to a zero-weight virtual sink.
 * Gauss-Seidel sweeps to the fixed point; G' has no cycle of negative w - ms
 * because ms is POT_SHIFT below its least cycle mean, so the sweeps converge, and
 * a sweep budget turns a genuine negative cycle into an error, not a hang. */
static int potential(double ms)
{
    for (uint32_t u = 1; u < N; u++) pot[u] = 0.0;
    for (uint64_t sweep = 0; sweep <= (uint64_t)N; sweep++) {
        int changed = 0;
        for (uint32_t u = 1; u < N; u++) {
            double best = pot[u];
            for (uint64_t j = rs[u]; j < rs[u + 1]; j++) {
                double c = wt[j] - ms + pot[tg[j]];
                if (c < best) best = c;
            }
            if (best < pot[u] - 1e-13) { pot[u] = best; changed = 1; }
        }
        if (!changed) return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 7) die("usage: n B(hex) axis threads cap r1 r2 ...");
    n = atoi(argv[1]);
    uint32_t B = (uint32_t)strtoul(argv[2], NULL, 16);
    axis = atoi(argv[3]);
    nthreads = atoi(argv[4]);
    wcap = atof(argv[5]);
    nrows = argc - 6;
    if (n < 4 || n > 20 || nthreads < 1 || nthreads > MAXT || nrows > 32) die("bad args");
    int tot = 0;
    for (int r = 0; r < nrows; r++) {
        rows[r] = atoi(argv[6 + r]);
        if (rows[r] < 3 || !(rows[r] & 1)) die("rows must be odd and >= 3");
        tot += rows[r];
    }
    if (tot != n) die("rows must sum to n");
    N = 1u << n;
    MASK = N - 1;
    B &= MASK;

    T = malloc(N * sizeof *T);
    LW = malloc((N + 1) * sizeof *LW);
    pi = malloc(N * sizeof *pi);
    path = malloc(N * sizeof *path);
    pw = malloc(N * sizeof *pw);
    mu = calloc(N, sizeof *mu);
    h = calloc(N, sizeof *h);
    pot = calloc(N, sizeof *pot);
    colour = malloc(N);
    rs = malloc((N + 1) * sizeof *rs);
    if (!T || !LW || !pi || !path || !pw || !mu || !h || !pot || !colour || !rs)
        die("out of memory");
    for (int k = 0; k < nthreads; k++) {
        W[k].id = k;
        W[k].col = malloc(N * sizeof(int32_t));
        W[k].nw = malloc(N * sizeof(double));
        W[k].nv = malloc(N * sizeof(uint32_t));
        if (!W[k].col || !W[k].nw || !W[k].nv) die("out of memory");
    }

    uint32_t d = rol((uint32_t)(((uint64_t)B * ((B + 1) >> 1)) & MASK), n / 4);
    for (uint32_t x = 0; x < N; x++) {
        uint32_t y = x ^ B;
        T[x] = chi(((y ^ rol(y, 1) ^ ror(y, 1)) + d) & MASK);
    }
    LW[0] = INFINITY;
    for (uint32_t k = 1; k <= N; k++) LW[k] = -log2((double)k / N);

    /* G' = every edge of weight <= cap, plus each node's cheapest out-edge so
     * that every node can carry a policy */
    minw_all = INFINITY;
    npend = 0;
    pass_mode = 0;
    full_pass();
    for (uint32_t u = 1; u < N; u++) {
        double bw = INFINITY;
        uint32_t bv = 0;
        for (int k = 0; k < nthreads; k++)
            if (W[k].nw[u] < bw || (W[k].nw[u] == bw && W[k].nv[u] < bv)) {
                bw = W[k].nw[u]; bv = W[k].nv[u];
            }
        if (!bv) die("a node has no out-edge");
        if (bw > wcap) {
            if (npend == cpend) {
                cpend = 2 * cpend + 1024;
                pend = realloc(pend, cpend * sizeof *pend);
                if (!pend) die("out of memory (pending)");
            }
            pend[npend].u = u; pend[npend].v = bv; pend[npend].w = bw;
            npend++;
        }
    }
    build_csr();

    int rounds = 0, certified = 0, its = 0;
    double m = NAN;
    for (rounds = 1; rounds <= 50; rounds++) {
        its = howard();
        if (!its) die("Howard did not terminate");
        m = INFINITY;
        for (uint32_t u = 1; u < N; u++) if (mu[u] < m) m = mu[u];
        mcert = m - POT_SHIFT;
        if (!potential(mcert)) die("potential did not converge: a negative cycle in G'");
        size_t before = npend;
        pass_mode = 1;
        full_pass();
        fprintf(stderr, "  round %d: |G'| = %zu, Howard %d its, mu %.10f, %zu violators\n",
                rounds, nE, its, m, npend - before);
        if (npend == before) { certified = 1; break; }
        build_csr();
    }

    uint32_t s = 1;
    for (uint32_t u = 1; u < N; u++) if (mu[u] < mu[s]) s = u;
    memset(colour, 0, N);
    while (!colour[s]) { colour[s] = 1; s = pi[s]; }
    uint32_t cl = 0, v = s;
    do { cl++; v = pi[v]; } while (v != s);
    printf("%.10f %d %d %u %zu %.10f\n", m, rounds, certified, cl, nE, minw_all);
    v = s;
    do { printf("%x %.10f\n", v, pw[v]); v = pi[v]; } while (v != s);
    return 0;
}
