/* certified_cycle_mean.c -- TODO #257 (fifth pass): the certified minimum-mean-cycle
 * solver of certified_cycle_ladder.py, in C, so the exact ladder reaches n = 22-23 and
 * carries enough keys per width to read a distribution rather than a median.
 *
 * It is a TRANSCRIPTION, not a new algorithm, and exact_slope_ladder.py checks it
 * against the Python solver key for key before using a single number from it.  The
 * carry automata are NOT re-derived here: the driver passes the 16 differential and 8
 * linear 2x2 transfer matrices on stdin, read from annealed_moment_ladder.py and
 * certified_cycle_ladder.py, so the two solvers cannot disagree about what an edge is.
 *
 * Standalone on purpose: it does not include herradura.h, because the object it
 * studies is the NL-FSCX v2 ROUND as a graph, rebuilt here from M = I ^ ROL ^ ROR and
 * the additive constant delta that the driver derives from the key.
 *
 *   stdin:  n  d  axis(0 = differential, 1 = linear)  W0  want_cycle(0/1)
 *           [implicit(0/1), default 0: see THE IMPLICIT MODE below]
 *           16 x 4 differential entries, indexed [d][a][c][e], then
 *            8 x 4 linear entries, indexed [d][u][w]
 *   stdout: mu  edges  rounds   (implicit: edges = |G'|, rounds = certify passes)
 *           and, if want_cycle, one optimal cycle: its length, then one
 *           "node weight" pair per edge
 *
 * The certificate (certified_cycle_ladder.py's docstring has the proof): solve the
 * subgraph G' of edges with weight <= W_u, take p = shortest paths of w - mu' from a
 * zero-weight virtual source, and raise W_u wherever W_u < mu' - p(u).  When no node
 * fails, p is feasible on the full graph and mu(G') = mu(G).
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EPS 1e-9
#define TOL 1e-9
/* SPFA runs on w - (mu' - POT_SHIFT), not on w - mu'.  Howard's mu' is a cycle's
 * sum / length, and SPFA re-adds the same w - mu' one edge at a time; on n = 17,
 * delta = 0x1f6ef (differential) the two roundings disagree by less than 1e-11 and
 * the optimal cycle is a NEGATIVE cycle to SPFA, which then never terminates (found
 * by TODO #257's eleventh pass, sampling uniform delta; no fixed seed before it had
 * met one).  The shift costs the certificate POT_SHIFT: mu(G) >= mu' - POT_SHIFT -
 * TOL instead of mu' - TOL.  RELAX_BUDGET turns a genuine negative cycle -- Howard
 * wrong by more than the shift -- into an error rather than a hang. */
#define POT_SHIFT 1e-9
#define RELAX_BUDGET(E, N) (64 * ((E) + (uint64_t)(N)))

static int n, axis;
static uint32_t N, dd;
static double DT[2][2][2][2][4];   /* [d][a][cls][ec] -> m00 m01 m10 m11 */
static double LT[2][2][2][4];      /* [d][u][w]       -> m00 m01 m10 m11 */
static uint32_t *Ma;

/* edge pool: node u owns pool[start[u] .. start[u] + len[u]) */
static uint32_t *ptgt;
static double *pw8;
static uint64_t pcap, pused;
static uint64_t *start;
static uint32_t *elen;

static void die(const char *m) { fprintf(stderr, "certified_cycle_mean: %s\n", m); exit(2); }

static void push_edge(uint32_t t, double w)
{
    if (pused == pcap) {
        pcap = pcap ? pcap * 3 / 2 : (uint64_t)N * 8;
        ptgt = realloc(ptgt, pcap * sizeof *ptgt);
        pw8 = realloc(pw8, pcap * sizeof *pw8);
        if (!ptgt || !pw8) die("out of memory");
    }
    ptgt[pused] = t;
    pw8[pused++] = w;
}

/* Every edge a row walk finds goes through emit(): the stored solver pushes it into
 * the pool, the implicit one's certify pass checks it against the potential */
static void (*emit)(uint32_t u, uint32_t t, double w);
static void emit_store(uint32_t u, uint32_t t, double w) { (void)u; push_edge(t, w); }

/* explicit DFS stacks, sized for depth n with two children per level */
typedef struct { int i, cls; double v0, v1; uint32_t e; } DS;
static DS *stk;

static void diff_row(uint32_t a, double W)
{
    uint32_t al = Ma[a];
    int top = n - 1, sp = 0;
    stk[sp++] = (DS){0, 0, 1.0, 0.0, 0};
    while (sp) {
        DS s = stk[--sp];
        if (s.i == top) {
            double w = top - log2(s.v0 + s.v1);
            if (w <= W + 1e-12) emit(a, al ^ s.e, w);
            continue;
        }
        int di = (dd >> s.i) & 1, ai = (al >> s.i) & 1;
        double lim = ldexp(1.0, s.i + 1) * pow(2.0, -W) - 1e-9;
        for (int ec = 0; ec < 2; ec++) {
            const double *m = DT[di][ai][s.cls][ec];
            double w0 = m[0] * s.v0 + m[1] * s.v1, w1 = m[2] * s.v0 + m[3] * s.v1;
            if (w0 + w1 >= lim)
                stk[sp++] = (DS){s.i + 1, ec, w0, w1, s.e | ((uint32_t)ec << (s.i + 1))};
        }
    }
}

static void lin_row(uint32_t u, double W)
{
    double thr = pow(2.0, -W) - 1e-15;
    int sp = 0;
    stk[sp++] = (DS){0, 0, 1.0, 0.0, 0};
    while (sp) {
        DS s = stk[--sp];
        if (s.i == n) {
            double c = fabs(s.v0 + s.v1);
            if (s.e && c >= thr) emit(u, Ma[s.e], -log2(c));
            continue;
        }
        int di = (dd >> s.i) & 1, ui = (u >> s.i) & 1;
        for (int wi = 0; wi < 2; wi++) {
            const double *m = LT[di][ui][wi];
            double a0 = m[0] * s.v0 + m[1] * s.v1, a1 = m[2] * s.v0 + m[3] * s.v1;
            if (fabs(a0) + fabs(a1) >= thr)
                stk[sp++] = (DS){s.i + 1, 0, a0, a1, s.e | ((uint32_t)wi << s.i)};
        }
    }
}

/* Howard's policy iteration, as certified_cycle_ladder / quenched_exact_ladder do it */
static uint32_t *pi, *path;
static double *pwp, *mu, *hh;
static uint8_t *col;

static double howard(void)
{
    for (uint32_t v = 1; v < N; v++) {
        uint64_t s0 = start[v];
        uint32_t best = 0;
        for (uint32_t j = 1; j < elen[v]; j++)
            if (pw8[s0 + j] < pw8[s0 + best]) best = j;
        pi[v] = ptgt[s0 + best];
        pwp[v] = pw8[s0 + best];
    }
    for (int it = 0; it < 1000000; it++) {
        memset(col, 0, N);
        for (uint32_t s = 1; s < N; s++) {
            if (col[s]) continue;
            uint32_t len = 0, v = s;
            while (!col[v]) { col[v] = 1; path[len++] = v; v = pi[v]; }
            uint32_t tail = len;
            if (col[v] == 1) {
                uint32_t i = 0;
                while (path[i] != v) i++;
                double sum = 0;
                for (uint32_t k = i; k < len; k++) sum += pwp[path[k]];
                double m = sum / (len - i);
                for (uint32_t k = i; k < len; k++) mu[path[k]] = m;
                /* Root hh at the cycle's SMALLEST node, not where this scan entered
                 * it: a scan-order root makes hh of two equal-mean cycles
                 * incomparable, and Howard then cycles forever (TODO #257, thirteenth
                 * pass: n = 14, delta = 0x1500, linear).  mu does not depend on it. */
                uint32_t r = i;
                for (uint32_t k = i + 1; k < len; k++) if (path[k] < path[r]) r = k;
                hh[path[r]] = 0.0;
                for (uint32_t k = r; k-- > i;) {
                    uint32_t x = path[k];
                    hh[x] = pwp[x] - m + hh[pi[x]];
                }
                for (uint32_t k = len - 1; k > r; k--) {
                    uint32_t x = path[k];
                    hh[x] = pwp[x] - m + hh[pi[x]];
                }
                tail = i;
            }
            for (uint32_t k = tail; k-- > 0;) {
                uint32_t x = path[k];
                mu[x] = mu[pi[x]];
                hh[x] = pwp[x] - mu[x] + hh[pi[x]];
            }
            for (uint32_t k = 0; k < len; k++) col[path[k]] = 2;
        }
        int improved = 0;
        for (uint32_t v = 1; v < N; v++) {
            double bmu = mu[v], bh = hh[v];
            int64_t bj = -1;
            uint64_t s0 = start[v];
            for (uint32_t j = 0; j < elen[v]; j++) {
                uint32_t b = ptgt[s0 + j];
                double cmu = mu[b];
                if (cmu < bmu - EPS) { bmu = cmu; bh = pw8[s0 + j] - cmu + hh[b]; bj = j; }
                else if (cmu <= bmu + EPS) {
                    double ch = pw8[s0 + j] - cmu + hh[b];
                    if (ch < bh - EPS) { bmu = cmu; bh = ch; bj = j; }
                }
            }
            if (bj >= 0) { pi[v] = ptgt[s0 + bj]; pwp[v] = pw8[s0 + bj]; improved = 1; }
        }
        if (!improved) {
            double m = mu[1];
            for (uint32_t v = 2; v < N; v++) if (mu[v] < m) m = mu[v];
            return m;
        }
    }
    die("Howard did not converge");
    return 0;
}

/* potentials: shortest paths of w - m from a zero-weight virtual source (SPFA) */
static double *pot;
static uint32_t *q;
static uint8_t *inq;

static void potentials(double m)
{
    uint64_t qh = 0, qt = 0, relax = 0, budget = RELAX_BUDGET(pused, N);
    m -= POT_SHIFT;
    for (uint32_t v = 1; v < N; v++) { pot[v] = 0.0; inq[v] = 1; q[qt++ % N] = v; }
    while (qh != qt) {
        uint32_t u = q[qh++ % N];
        inq[u] = 0;
        double pu = pot[u];
        uint64_t s0 = start[u];
        for (uint32_t j = 0; j < elen[u]; j++) {
            uint32_t v = ptgt[s0 + j];
            double nv = pu + pw8[s0 + j] - m;
            if (nv < pot[v] - 1e-12) {
                pot[v] = nv;
                if (++relax > budget) die("SPFA over budget: negative cycle below mu'");
                if (!inq[v]) { inq[v] = 1; q[qt++ % N] = v; }
            }
        }
    }
}

static void build_node(uint32_t u, double *Wn)
{
    for (;;) {
        uint64_t s0 = pused;
        if (axis == 0) diff_row(u, Wn[u]); else lin_row(u, Wn[u]);
        if (pused > s0) { start[u] = s0; elen[u] = (uint32_t)(pused - s0); return; }
        Wn[u] += 1.0;
    }
}

/* drop the edge storage of rebuilt nodes IN PLACE, so the peak is the live graph and
 * not twice it: rows are moved down in order of their current offset, and a row's
 * destination never lies above its source, so memmove never overwrites a row that
 * has not been moved yet */
static uint32_t *order;

static int by_start(const void *a, const void *b)
{
    uint64_t x = start[*(const uint32_t *)a], y = start[*(const uint32_t *)b];
    return (x > y) - (x < y);
}

static void compact(void)
{
    uint64_t live = 0;
    for (uint32_t v = 1; v < N; v++) live += elen[v];
    if (live == pused) return;
    for (uint32_t v = 1; v < N; v++) order[v - 1] = v;
    qsort(order, N - 1, sizeof *order, by_start);
    uint64_t k = 0;
    for (uint32_t i = 0; i < N - 1; i++) {
        uint32_t v = order[i];
        if (start[v] != k) {
            memmove(ptgt + k, ptgt + start[v], elen[v] * sizeof *ptgt);
            memmove(pw8 + k, pw8 + start[v], elen[v] * sizeof *pw8);
            start[v] = k;
        }
        k += elen[v];
    }
    pused = live;
}

/* THE IMPLICIT MODE (TODO #343).  The stored solver keeps every edge of weight
 * <= W_u, and the certificate pushes W_u up to mu' - p(u): with p(v) <= 0 for every
 * v, an edge heavier than that cannot violate p, so the kept graph is certified
 * without looking at the rest.  That bound is loose -- it charges every target the
 * least potential there is -- and at n = 20 the kept graph reaches 4.1 GB.
 *
 * The implicit mode keeps G' = the edges of weight <= W0 plus every edge a check
 * has caught, and checks the rest by WALKING it: one pass regenerates, for each u,
 * the edges of weight below mu' - p(u) (the same row walks, the same bound) and
 * tests each against the potential at its own target,
 *     p(v) <= p(u) + w - mu' + TOL.
 * Every edge that fails joins G' and the solve is repeated.  When a pass finds none,
 * every edge of G -- the walked ones by test, the rest by the bound -- satisfies p,
 * so every cycle of G has mean >= mu' - TOL: the stored solver's certificate, with
 * the stored solver's tolerances, over a graph held only as G'. */
static uint32_t *vu, *vt;
static double *vw, mcert;
static uint64_t nv, vcap, nviol;

/* the row being checked keeps its KMAX worst violators: kt/kw/kx, by excess */
#define KMAX_LIM 64
static int KMAX = 4, nk;
static uint32_t kt[KMAX_LIM];
static double kw[KMAX_LIM], kx[KMAX_LIM];

/* every violator of the pass, while they fit in N entries */
static uint32_t *au, *at;
static double *aw;
static uint64_t na;

static void emit_check(uint32_t u, uint32_t t, double w)
{
    double x = pot[t] - (pot[u] + w - mcert);
    if (x <= TOL) return;
    if (nviol++ < N) { au[na] = u; at[na] = t; aw[na++] = w; }
    int j;
    if (nk < KMAX) j = nk++;
    else {
        j = 0;
        for (int i = 1; i < nk; i++) if (kx[i] < kx[j]) j = i;
        if (kx[j] >= x) return;
    }
    kt[j] = t; kw[j] = w; kx[j] = x;
}

static void push_violator(uint32_t u, uint32_t t, double w)
{
    if (nv == vcap) {
        vcap = vcap ? vcap * 2 : 1 << 16;
        vu = realloc(vu, vcap * sizeof *vu);
        vt = realloc(vt, vcap * sizeof *vt);
        vw = realloc(vw, vcap * sizeof *vw);
        if (!vu || !vt || !vw) die("out of memory (violators)");
    }
    vu[nv] = u; vt[nv] = t; vw[nv++] = w;
}

/* append the violators, which the pass found in increasing u, to their rows.  The
 * rows lie in increasing u (built in that order and never rebuilt), so moving them
 * up from the top row down never overwrites a row that has not been moved yet */
static void merge_violators(void)
{
    uint64_t tot = pused + nv;
    if (tot > pcap) {
        pcap = tot + tot / 4;
        ptgt = realloc(ptgt, pcap * sizeof *ptgt);
        pw8 = realloc(pw8, pcap * sizeof *pw8);
        if (!ptgt || !pw8) die("out of memory");
    }
    uint64_t k = nv;                      /* violators still to place: vu[0 .. k) */
    for (uint32_t u = N - 1; u >= 1; u--) {
        uint64_t j = k;
        while (j > 0 && vu[j - 1] == u) j--;
        uint64_t add = k - j, dst = start[u] + j;
        if (dst != start[u]) {
            memmove(ptgt + dst, ptgt + start[u], elen[u] * sizeof *ptgt);
            memmove(pw8 + dst, pw8 + start[u], elen[u] * sizeof *pw8);
        }
        memcpy(ptgt + dst + elen[u], vt + j, add * sizeof *ptgt);
        memcpy(pw8 + dst + elen[u], vw + j, add * sizeof *pw8);
        start[u] = dst;
        elen[u] += (uint32_t)add;
        k = j;
    }
    pused = tot;
    nv = 0;
}

static double solve_implicit(double *Wn, int *rounds)
{
    double m;
    au = malloc(N * sizeof *au); at = malloc(N * sizeof *at); aw = malloc(N * sizeof *aw);
    if (!au || !at || !aw) die("out of memory");
    emit = emit_store;
    for (uint32_t v = 1; v < N; v++) build_node(v, Wn);
    for (*rounds = 1;; (*rounds)++) {
        m = howard();
        potentials(m);
        mcert = m - POT_SHIFT;
        emit = emit_check;
        nviol = na = 0;
        for (uint32_t u = 1; u < N; u++) {
            nk = 0;
            if (axis == 0) diff_row(u, mcert - pot[u]); else lin_row(u, mcert - pot[u]);
            for (int i = 0; i < nk; i++) push_violator(u, kt[i], kw[i]);
        }
        emit = emit_store;
        if (nviol && nviol <= N) {        /* few enough: take every one of them */
            nv = 0;
            for (uint64_t i = 0; i < na; i++) push_violator(au[i], at[i], aw[i]);
        }
        fprintf(stderr, "  pass %d: |G'| = %llu, mu %.10f, %llu violators, %llu kept\n",
                *rounds, (unsigned long long)pused, m, (unsigned long long)nviol,
                (unsigned long long)nv);
        if (!nviol) return m;
        merge_violators();
    }
}

int main(void)
{
    double W0;
    int want_cycle = 0, implicit = 0;
    char line[256];
    if (!fgets(line, sizeof line, stdin) ||
        sscanf(line, "%d %u %d %lf %d %d %d", &n, &dd, &axis, &W0, &want_cycle, &implicit,
               &KMAX) < 4)
        die("bad header");
    if (KMAX < 1 || KMAX > KMAX_LIM) die("K out of range");
    if (n < 4 || n > 26) die("n out of range");
    for (int d = 0; d < 2; d++) for (int a = 0; a < 2; a++)
        for (int c = 0; c < 2; c++) for (int e = 0; e < 2; e++)
            for (int k = 0; k < 4; k++)
                if (scanf("%lf", &DT[d][a][c][e][k]) != 1) die("bad diff table");
    for (int d = 0; d < 2; d++) for (int u = 0; u < 2; u++)
        for (int w = 0; w < 2; w++) for (int k = 0; k < 4; k++)
            if (scanf("%lf", &LT[d][u][w][k]) != 1) die("bad lin table");

    N = 1u << n;
    uint32_t mask = N - 1;
    Ma = malloc(N * sizeof *Ma);
    for (uint32_t x = 0; x < N; x++)
        Ma[x] = (x ^ (((x << 1) | (x >> (n - 1))) & mask) ^ (((x >> 1) | (x << (n - 1))) & mask)) & mask;
    stk = malloc((size_t)(2 * n + 4) * sizeof *stk);
    start = calloc(N, sizeof *start);
    elen = calloc(N, sizeof *elen);
    pi = malloc(N * sizeof *pi); path = malloc(N * sizeof *path);
    pwp = malloc(N * sizeof *pwp); mu = malloc(N * sizeof *mu); hh = malloc(N * sizeof *hh);
    col = malloc(N); pot = malloc(N * sizeof *pot); q = malloc(N * sizeof *q); inq = malloc(N);
    double *Wn = malloc(N * sizeof *Wn);
    order = malloc(N * sizeof *order);
    uint32_t *todo = malloc(N * sizeof *todo);
    if (!Ma || !stk || !start || !elen || !pi || !path || !pwp || !mu || !hh || !col ||
        !pot || !q || !inq || !Wn || !todo || !order) die("out of memory");

    int rounds = 0;
    double m;
    for (uint32_t v = 0; v < N; v++) Wn[v] = W0;
    if (implicit) {
        m = solve_implicit(Wn, &rounds);
    } else {
        uint32_t nt = 0;
        for (uint32_t v = 1; v < N; v++) todo[nt++] = v;
        emit = emit_store;
        for (;;) {
            rounds++;
            for (uint32_t k = 0; k < nt; k++) build_node(todo[k], Wn);
            compact();
            m = howard();
            potentials(m);
            nt = 0;
            for (uint32_t v = 1; v < N; v++)
                if (Wn[v] < m - pot[v] - TOL) todo[nt++] = v;
            if (!nt) break;
            for (uint32_t k = 0; k < nt; k++) Wn[todo[k]] = m - pot[todo[k]] + 0.5;
        }
    }
    uint64_t E = 0;
    for (uint32_t v = 1; v < N; v++) E += elen[v];
    printf("%.12f %llu %d\n", m, (unsigned long long)E, rounds);
    if (want_cycle) {
        /* Howard's final policy: a node attaining the minimum lies on (or leads into)
         * a policy cycle of that mean; walk N steps to land on the cycle itself */
        uint32_t v = 1;
        for (uint32_t x = 1; x < N; x++) if (mu[x] < mu[v]) v = x;
        for (uint32_t k = 0; k < N; k++) v = pi[v];
        uint32_t len = 0, x = v;
        do { len++; x = pi[x]; } while (x != v);
        printf("%u\n", len);
        do { printf("%u %.12f\n", x, pwp[x]); x = pi[x]; } while (x != v);
    }
    return 0;
}
