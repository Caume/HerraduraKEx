/* KAT/verify_kat_c.c — TODO #266: the C consumer for the HCRED-KKW vector.
 *
 * WHY THIS FILE EXISTS.  Until now C had no KAT verifier of any kind: Python
 * checks its own vectors, KAT/verify_kat.go cross-checks in Go, and
 * herradurakex.KatVerify does it for Java.  C — the language where two of the
 * three KKW port bugs actually were, an under-allocated commitment buffer in
 * hcred_kkw_state_com and a flipped bit convention in hcred_kkw_outmap — was
 * verified only against itself.  Both of those are READER disagreements about a
 * byte layout, which is exactly what consuming another implementation's
 * transcript catches and what a self-round-trip cannot.
 *
 * WHY A GENERATED HEADER RATHER THAN JSON.  The shipped C tree has no
 * third-party dependencies and that property is worth more than the convenience
 * of a parser, so the pinned vector is transposed into C arrays by
 * `python3 KAT/generate_kat.py --emit-kkw-header`.  The header is a pure
 * deterministic transform of KAT/hcred_kkw.json, so `--check` diffs it and a
 * JSON edited without re-emitting the header fails rather than drifting.
 *
 * Only the n=256 set is consumable here: herradura.h fixes HCRED_N at 256, so
 * the n=32 set the Python and Go demos use is not a width this build can
 * represent.  That asymmetry is itself a TODO #266 finding.
 *
 * Build:  gcc -O2 -o KAT/verify_kat_c KAT/verify_kat_c.c
 * Run:    ./KAT/verify_kat_c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../herradura.h"
#include "hcred_kkw_vector.h"
#include "sampler_replay_vector.h"
#include "operation_replay_vector.h"

#if HCRED_N != KKW_KAT_N
#  error "herradura.h's HCRED_N does not match the vector's width"
#endif
#if HCRED_KKW_I != KKW_KAT_I || HCRED_KKW_G != KKW_KAT_G
#  error "circuit dimensions disagree with the vector — regenerate the header"
#endif

static int failures = 0;

static void ok(const char *what)   { printf("PASS %s\n", what); }
static void bad(const char *what)  { printf("FAIL %s\n", what); failures++; }

/* Rebuild the proof struct from the generated arrays.  A fresh copy per case,
 * so a tamper never leaks into the next one. */
static int build_proof(HcredKkwProof *p)
{
    int k, j;
    memset(p, 0, sizeof(*p));
    p->W     = KKW_KAT_W;
    p->n_par = KKW_KAT_N_PAR;
    p->m     = KKW_KAT_M;
    p->tau   = KKW_KAT_TAU;

    p->pre_e    = (int *)calloc((size_t)(KKW_KAT_M - KKW_KAT_TAU), sizeof(int));
    p->pre_root = (uint8_t *)calloc((size_t)(KKW_KAT_M - KKW_KAT_TAU), KEYBYTES);
    p->online_e = (int *)calloc((size_t)KKW_KAT_TAU, sizeof(int));
    p->online   = (HcredKkwOnline *)calloc((size_t)KKW_KAT_TAU, sizeof(HcredKkwOnline));
    if (!p->pre_e || !p->pre_root || !p->online_e || !p->online) return -1;

    for (k = 0; k < KKW_KAT_M - KKW_KAT_TAU; k++) {
        p->pre_e[k] = (int)kkw_kat_pre_e[k];
        memcpy(p->pre_root + (size_t)k * KEYBYTES, kkw_kat_pre_root[k], KEYBYTES);
    }
    for (k = 0; k < KKW_KAT_TAU; k++) {
        HcredKkwOnline *o = &p->online[k];
        p->online_e[k] = (int)kkw_kat_online_e[k];
        o->path_len = (int)kkw_kat_path_len[k];
        for (j = 0; j < o->path_len; j++) {
            o->path[j].l = (int)kkw_kat_path_l[k][j];
            o->path[j].i = (int)kkw_kat_path_i[k][j];
            memcpy(o->path[j].node, kkw_kat_path_node[k][j], KEYBYTES);
        }
        memcpy(o->com_h, kkw_kat_com_h[k], KEYBYTES);
        o->pbar = (int)kkw_kat_pbar[k];
        o->u    = kkw_kat_u[k];
        o->zin  = (int32_t *)malloc(sizeof(int32_t) * HCRED_KKW_I);
        o->t    = (int32_t *)malloc(sizeof(int32_t) * HCRED_KKW_G);
        if (!o->zin || !o->t) return -1;
        memcpy(o->zin, kkw_kat_zin[k], sizeof(int32_t) * HCRED_KKW_I);
        memcpy(o->t,   kkw_kat_t[k],   sizeof(int32_t) * HCRED_KKW_G);
        /* aux is present iff this emulation's hidden party is not N-1.  The
         * Go port shipped this condition INVERTED; keeping the vector's own
         * has_aux flag rather than recomputing it means the C consumer would
         * catch the same mistake here. */
        if (kkw_kat_has_aux[k]) {
            o->aux = (int32_t *)malloc(sizeof(int32_t) * HCRED_KKW_G);
            if (!o->aux) return -1;
            memcpy(o->aux, kkw_kat_aux[k], sizeof(int32_t) * HCRED_KKW_G);
        } else {
            o->aux = NULL;
        }
    }
    return 0;
}

/* Mirrors _kkw_apply_tamper in KAT/generate_kat.py and applyKkwTamper in
 * KAT/verify_kat.go.  All three must agree case for case: a mutation one
 * applies and another does not silently downgrades a rejection test into a
 * second accept test. */
static int apply_tamper(HcredKkwProof *p, const char *which,
                        const uint8_t **msg, size_t *msg_len)
{
    static uint8_t alt_msg[KKW_KAT_MSG_LEN + 1];

    if (strcmp(which, "msg") == 0) {
        memcpy(alt_msg, kkw_kat_msg, KKW_KAT_MSG_LEN);
        alt_msg[KKW_KAT_MSG_LEN] = '!';
        *msg = alt_msg;
        *msg_len = KKW_KAT_MSG_LEN + 1;
        return 0;
    }
    if (strcmp(which, "W") == 0)               { p->W += 1; return 0; }
    if (strcmp(which, "online[0].u") == 0)     { p->online[0].u = (p->online[0].u + 1) % RNL_Q; return 0; }
    if (strcmp(which, "online[0].t[0]") == 0)  { p->online[0].t[0] = (p->online[0].t[0] + 1) % RNL_Q; return 0; }
    if (strcmp(which, "pre[0][0]") == 0)       { p->pre_root[0] ^= 1; return 0; }
    if (strcmp(which, "online[0].pbar") == 0)  { p->online[0].pbar = (p->online[0].pbar + 1) % p->n_par; return 0; }
    return -1;
}

/* ── TODO #296: fixed-stream sampler replay ──────────────────────────────
 *
 * Replays the suite's leaf CSPRNG samplers against the vector's fixed stream.
 * C needs no injection machinery for this and that is not an accident: every
 * sampler here already takes its entropy as a `FILE *`, so fmemopen over the
 * pinned bytes drives the SHIPPED function with no hook, no global and no
 * build flag.  The other three ports each need one (rand.Reader, os.urandom,
 * a SecureRandom subclass).
 *
 * ftell on that stream is the bytes-consumed assertion, and it is the half
 * that catches a port reading ahead of or behind the others -- which is how a
 * buffered read pattern (TODO #293) shows up here at all.
 */
static void replay_cbd(void)
{
    static int32_t got[RPL_CBD_N];
    FILE *f = fmemopen((void *)rpl_cbd_stream, sizeof rpl_cbd_stream, "rb");
    int i, bad_at = -1;

    if (!f) { bad("replay rnl_cbd_poly (fmemopen)"); return; }
    rnl_cbd_poly_dim(got, f, RPL_CBD_N);
    for (i = 0; i < RPL_CBD_N; i++)
        if (got[i] != rpl_cbd_expect[i]) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL replay rnl_cbd_poly: coeff %d is %d, vector says %d\n",
               bad_at, (int)got[bad_at], (int)rpl_cbd_expect[bad_at]);
        failures++;
    } else {
        ok("replay rnl_cbd_poly");
    }
    if (ftell(f) != RPL_CBD_CONSUMED) {
        printf("FAIL replay rnl_cbd_poly: consumed %ld bytes, vector says %d\n",
               ftell(f), RPL_CBD_CONSUMED);
        failures++;
    }
    fclose(f);
}

static void replay_rand_poly(void)
{
    static int32_t got[RPL_RAND_N];
    FILE *f = fmemopen((void *)rpl_rand_stream, sizeof rpl_rand_stream, "rb");
    int i, bad_at = -1;

    if (!f) { bad("replay rnl_rand_poly (fmemopen)"); return; }
    rnl_rand_poly(got, f);
    for (i = 0; i < RPL_RAND_N; i++)
        if (got[i] != rpl_rand_expect[i]) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL replay rnl_rand_poly: coeff %d is %d, vector says %d\n",
               bad_at, (int)got[bad_at], (int)rpl_rand_expect[bad_at]);
        failures++;
    } else {
        ok("replay rnl_rand_poly (output only -- see the header on `consumed`)");
    }
    /* No byte-count assertion here, deliberately, and the generated header
     * emits no RPL_RAND_CONSUMED so one cannot be written by mistake: this
     * port reads 3 bytes per draw while Go, Python and Java read one block
     * (TODO #293).  The byte-to-draw MAPPING is what all four share, and the
     * output above is what pins it. */
    fclose(f);
}

static void replay_weight_t(void)
{
    FILE *f = fmemopen((void *)rpl_wt_stream, sizeof rpl_wt_stream, "rb");
    BitArray e;
    int i, w = 0;

    if (!f) { bad("replay stern_rand_error (fmemopen)"); return; }
    stern_rand_error(&e, f);
    if (memcmp(e.b, rpl_wt_expect, KEYBYTES) != 0)
        bad("replay stern_rand_error");
    else
        ok("replay stern_rand_error");
    for (i = 0; i < KEYBYTES; i++) {
        uint8_t b = e.b[i];
        while (b) { w += b & 1; b >>= 1; }
    }
    if (w != RPL_WT_WEIGHT) {
        printf("FAIL replay stern_rand_error: weight %d, vector says %d\n",
               w, RPL_WT_WEIGHT);
        failures++;
    }
    if (ftell(f) != RPL_WT_CONSUMED) {
        printf("FAIL replay stern_rand_error: consumed %ld bytes, vector says %d\n",
               ftell(f), RPL_WT_CONSUMED);
        failures++;
    }
    fclose(f);
}

static void replay_oprf(void)
{
    FILE *f = fmemopen((void *)rpl_oprf_stream, sizeof rpl_oprf_stream, "rb");
    BitArray r, alpha;

    if (!f) { bad("replay oprf_blind (fmemopen)"); return; }
    oprf_blind(rpl_oprf_input, sizeof rpl_oprf_input, &r, &alpha, f);
    if (memcmp(r.b, rpl_oprf_expect_r, KEYBYTES) != 0)
        bad("replay oprf_blind r");
    else
        ok("replay oprf_blind r");
    if (memcmp(alpha.b, rpl_oprf_expect_alpha, KEYBYTES) != 0)
        bad("replay oprf_blind alpha");
    else
        ok("replay oprf_blind alpha");
    if (ftell(f) != RPL_OPRF_CONSUMED) {
        printf("FAIL replay oprf_blind: consumed %ld bytes, vector says %d\n",
               ftell(f), RPL_OPRF_CONSUMED);
        failures++;
    }
    fclose(f);
}

/* ── TODO #297: fixed-stream OPERATION replay ────────────────────────────
 *
 * One level above the leaf replay above.  A leaf row is one call with scalar
 * arguments; these rows supply a fixed STATEMENT as well as a fixed stream and
 * pin what a whole randomised operation produces -- so the order in which it
 * visits its samplers, and any inline draw loop that is not a callable sampler
 * at all, is pinned across the four ports.  #294's own defect was of the
 * second kind: rnl_sigma_sign's mask draw is written out inside the signing
 * loop.
 *
 * C again needs no injection machinery: every operation here already takes its
 * entropy as a `FILE *`, so fmemopen over the pinned bytes drives the SHIPPED
 * function.  ftell is the bytes-consumed assertion where the vector carries
 * one.
 */
static int cmp_ba(const BitArray *got, const uint8_t *want, const char *what)
{
    if (memcmp(got->b, want, KEYBYTES) != 0) { bad(what); return 0; }
    return 1;
}

static void op_stern_keygen(void)
{
    FILE *f = fmemopen((void *)opr_sfk_stream, sizeof opr_sfk_stream, "rb");
    BitArray seed, e;
    uint8_t syndr[SDF_SYNBYTES];

    if (!f) { bad("op stern_f_keygen (fmemopen)"); return; }
    stern_f_keygen(&seed, &e, syndr, f);
    if (cmp_ba(&seed, opr_sfk_seed, "op stern_f_keygen seed"))
        ok("op stern_f_keygen seed");
    if (cmp_ba(&e, opr_sfk_e, "op stern_f_keygen e"))
        ok("op stern_f_keygen e");
    /* The vector's syndrome is already transposed into this header's byte
     * order by the generator -- see the comment beside opr_sfk_syndrome. */
    if (memcmp(syndr, opr_sfk_syndrome, SDF_SYNBYTES) != 0)
        bad("op stern_f_keygen syndrome");
    else
        ok("op stern_f_keygen syndrome");
    if (ftell(f) != OPR_SFK_CONSUMED) {
        printf("FAIL op stern_f_keygen: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_SFK_CONSUMED);
        failures++;
    }
    fclose(f);
}

static void op_stern_sign(void)
{
    FILE *f = fmemopen((void *)opr_sfs_stream, sizeof opr_sfs_stream, "rb");
    SternSig sig;
    BitArray msg, e, seed;
    int i, bad_at = -1;

    if (!f) { bad("op hpks_stern_f_sign (fmemopen)"); return; }
    memcpy(msg.b, opr_sfs_msg, KEYBYTES);
    memcpy(e.b, opr_sfs_e, KEYBYTES);
    memcpy(seed.b, opr_sfs_seed, KEYBYTES);
    stern_sig_alloc(&sig, OPR_SFS_ROUNDS);
    hpks_stern_f_sign(&sig, &msg, &e, &seed, f);

    for (i = 0; i < OPR_SFS_ROUNDS; i++)
        if (memcmp(sig.c0[i].b, opr_sfs_c0[i], KEYBYTES) != 0 ||
            memcmp(sig.c1[i].b, opr_sfs_c1[i], KEYBYTES) != 0 ||
            memcmp(sig.c2[i].b, opr_sfs_c2[i], KEYBYTES) != 0) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op hpks_stern_f_sign: commitments differ at round %d\n", bad_at);
        failures++;
    } else {
        ok("op hpks_stern_f_sign commitments");
    }

    bad_at = -1;
    for (i = 0; i < OPR_SFS_ROUNDS; i++)
        if (sig.b[i] != opr_sfs_challenge[i]) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op hpks_stern_f_sign: challenge %d is %d, vector says %d\n",
               bad_at, sig.b[bad_at], opr_sfs_challenge[bad_at]);
        failures++;
    } else {
        ok("op hpks_stern_f_sign challenges");
    }

    /* The three challenge values reveal three different pairs, and the
     * vector's stream is chosen so all three occur -- so this one comparison
     * covers all three response branches. */
    bad_at = -1;
    for (i = 0; i < OPR_SFS_ROUNDS; i++)
        if (memcmp(sig.resp_a[i].b, opr_sfs_resp_a[i], KEYBYTES) != 0 ||
            memcmp(sig.resp_b[i].b, opr_sfs_resp_b[i], KEYBYTES) != 0) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op hpks_stern_f_sign: response differs at round %d (b=%d)\n",
               bad_at, sig.b[bad_at]);
        failures++;
    } else {
        ok("op hpks_stern_f_sign responses");
    }

    if (ftell(f) != OPR_SFS_CONSUMED) {
        printf("FAIL op hpks_stern_f_sign: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_SFS_CONSUMED);
        failures++;
    }
    stern_sig_free(&sig);
    fclose(f);
}

static void op_zkp_nl_prove(void)
{
    FILE *f = fmemopen((void *)opr_zk_stream, sizeof opr_zk_stream, "rb");
    ZkpNlRound *proof;
    int i, bad_at = -1;

    if (!f) { bad("op zkp_nl_prove (fmemopen)"); return; }
    proof = zkp_nl_prove(OPR_ZK_A, OPR_ZK_B, OPR_ZK_Y, OPR_ZK_N, OPR_ZK_ROUNDS,
                         opr_zk_msg, sizeof opr_zk_msg, f);
    if (!proof) { bad("op zkp_nl_prove (null proof)"); fclose(f); return; }

    for (i = 0; i < OPR_ZK_ROUNDS; i++)
        if (memcmp(proof[i].com_0, opr_zk_com0[i], 32) != 0 ||
            memcmp(proof[i].com_1, opr_zk_com1[i], 32) != 0 ||
            memcmp(proof[i].com_2, opr_zk_com2[i], 32) != 0) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op zkp_nl_prove: commitments differ at round %d\n", bad_at);
        failures++;
    } else {
        ok("op zkp_nl_prove commitments");
    }

    bad_at = -1;
    for (i = 0; i < OPR_ZK_ROUNDS; i++) {
        if (proof[i].e != (uint8_t)opr_zk_e[i] ||
            proof[i].view_len != (size_t)OPR_ZK_VIEWLEN ||
            memcmp(proof[i].view_p1, opr_zk_view1[i], OPR_ZK_VIEWLEN) != 0 ||
            memcmp(proof[i].view_p2, opr_zk_view2[i], OPR_ZK_VIEWLEN) != 0) {
            bad_at = i; break;
        }
    }
    if (bad_at >= 0) {
        printf("FAIL op zkp_nl_prove: views differ at round %d (e=%d, vector says %d)\n",
               bad_at, proof[bad_at].e, opr_zk_e[bad_at]);
        failures++;
    } else {
        ok("op zkp_nl_prove views");
    }

    if (ftell(f) != OPR_ZK_CONSUMED) {
        printf("FAIL op zkp_nl_prove: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_ZK_CONSUMED);
        failures++;
    }
    zkp_nl_proof_free(proof, OPR_ZK_ROUNDS);
    fclose(f);
}

static void op_rnl_sigma_sign(void)
{
    FILE *f = fmemopen((void *)opr_sigma_stream, sizeof opr_sigma_stream, "rb");
    static int32_t w[OPR_SIGMA_N], c[OPR_SIGMA_N], z[OPR_SIGMA_N];
    int i, bad_at = -1;

    if (!f) { bad("op rnl_sigma_sign (fmemopen)"); return; }
    if (rnl_sigma_sign(opr_sigma_s, opr_sigma_m, opr_sigma_cpub, OPR_SIGMA_N,
                       opr_sigma_msg, sizeof opr_sigma_msg, f, w, c, z) != 0) {
        /* The vector's stream is exactly one buffered block long and is chosen
         * to accept on the FIRST attempt; a port that retries here has already
         * run off the end of the stream. */
        bad("op rnl_sigma_sign (rejection limit or short stream)");
        fclose(f);
        return;
    }
    for (i = 0; i < OPR_SIGMA_N; i++)
        if (w[i] != opr_sigma_w[i] || c[i] != opr_sigma_c[i] ||
            z[i] != opr_sigma_z[i]) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op rnl_sigma_sign: coeff %d is (w=%d c=%d z=%d), "
               "vector says (w=%d c=%d z=%d)\n", bad_at,
               (int)w[bad_at], (int)c[bad_at], (int)z[bad_at],
               (int)opr_sigma_w[bad_at], (int)opr_sigma_c[bad_at],
               (int)opr_sigma_z[bad_at]);
        failures++;
    } else {
        ok("op rnl_sigma_sign (w, c, z) -- output only, see the vector on `consumed`");
    }
    fclose(f);
}

/* The ring row.  Two divergences lived in this operation and neither was
 * visible to any other check: the challenge trit had three schemes across the
 * four ports, and the b = 0 dummy commitment was a CONSTANT in C and Go, which
 * identified the real signer from the public signature.  See
 * stern_ring_simulate in herradura.h. */
static void op_stern_ring_sign(void)
{
    FILE *f = fmemopen((void *)opr_ring_stream, sizeof opr_ring_stream, "rb");
    SternRingSig sig;
    BitArray msg, e, seeds[OPR_RING_K];
    uint8_t syndrs[OPR_RING_K][SDF_SYNBYTES];
    int i, n = OPR_RING_K * OPR_RING_ROUNDS, bad_at = -1;

    if (!f) { bad("op stern_ring_sign (fmemopen)"); return; }
    memcpy(msg.b, opr_ring_msg, KEYBYTES);
    memcpy(e.b, opr_ring_e, KEYBYTES);
    for (i = 0; i < OPR_RING_K; i++) {
        memcpy(seeds[i].b, opr_ring_seeds[i], KEYBYTES);
        memcpy(syndrs[i], opr_ring_syndromes[i], SDF_SYNBYTES);
    }
    stern_ring_alloc(&sig, OPR_RING_K, OPR_RING_ROUNDS);
    stern_ring_sign(&sig, &msg, &e, OPR_RING_J, seeds,
                    (const uint8_t *)syndrs, f);

    for (i = 0; i < n; i++)
        if (memcmp(sig.c0[i].b, opr_ring_c0[i], KEYBYTES) != 0 ||
            memcmp(sig.c1[i].b, opr_ring_c1[i], KEYBYTES) != 0 ||
            memcmp(sig.c2[i].b, opr_ring_c2[i], KEYBYTES) != 0) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op stern_ring_sign: commitments differ at member %d round %d\n",
               bad_at / OPR_RING_ROUNDS, bad_at % OPR_RING_ROUNDS);
        failures++;
    } else {
        ok("op stern_ring_sign commitments");
    }

    bad_at = -1;
    for (i = 0; i < n; i++)
        if (sig.b[i] != opr_ring_challenge[i]) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op stern_ring_sign: challenge at member %d round %d is %d, "
               "vector says %d\n", bad_at / OPR_RING_ROUNDS,
               bad_at % OPR_RING_ROUNDS, sig.b[bad_at], opr_ring_challenge[bad_at]);
        failures++;
    } else {
        ok("op stern_ring_sign challenges");
    }

    bad_at = -1;
    for (i = 0; i < n; i++)
        if (memcmp(sig.resp_a[i].b, opr_ring_resp_a[i], KEYBYTES) != 0 ||
            memcmp(sig.resp_b[i].b, opr_ring_resp_b[i], KEYBYTES) != 0) { bad_at = i; break; }
    if (bad_at >= 0) {
        printf("FAIL op stern_ring_sign: response differs at member %d round %d (b=%d)\n",
               bad_at / OPR_RING_ROUNDS, bad_at % OPR_RING_ROUNDS, sig.b[bad_at]);
        failures++;
    } else {
        ok("op stern_ring_sign responses");
    }

    /* The signature must still VERIFY -- the fix changed a dummy commitment
     * that no verifier checks, and a vector alone would not say so. */
    if (!stern_ring_verify(&sig, &msg, seeds, (const uint8_t *)syndrs)) {
        bad("op stern_ring_sign verifies");
    } else {
        ok("op stern_ring_sign verifies");
    }

    if (ftell(f) != OPR_RING_CONSUMED) {
        printf("FAIL op stern_ring_sign: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_RING_CONSUMED);
        failures++;
    }
    stern_ring_free(&sig);
    fclose(f);
}

int main(void)
{
    HcredKkwProof proof;
    BitArray seed_H;
    const uint8_t *msg;
    size_t msg_len;
    int i;

    memcpy(seed_H.b, kkw_kat_seed_H, KEYBYTES);

    /* 1. C must ACCEPT the pinned Python transcript. */
    if (build_proof(&proof) != 0) {
        fputs("FAIL hcred_kkw: out of memory building the proof\n", stderr);
        return 1;
    }
    if (hcred_verify_kkw(kkw_kat_m_poly, kkw_kat_c_poly, &seed_H,
                         kkw_kat_syndrome, &proof,
                         kkw_kat_msg, KKW_KAT_MSG_LEN))
        ok("hcred_kkw[n256] (C accepts the pinned Python transcript)");
    else
        bad("hcred_kkw[n256]: C REJECTS the pinned Python transcript "
            "— C and the reference disagree on the wire format");
    hcred_kkw_proof_free(&proof);

    /* 2. Each tamper case must be REJECTED.  Without these the accept above is
     * not self-validating: a verifier that returned 1 unconditionally would
     * pass it, which is CliTest/lib_malformed.sh's discipline applied here. */
    for (i = 0; i < KKW_KAT_TAMPER_COUNT; i++) {
        char label[128];
        msg = kkw_kat_msg;
        msg_len = KKW_KAT_MSG_LEN;
        if (build_proof(&proof) != 0) {
            fputs("FAIL hcred_kkw: out of memory building the proof\n", stderr);
            return 1;
        }
        if (apply_tamper(&proof, kkw_kat_tamper_apply[i], &msg, &msg_len) != 0) {
            snprintf(label, sizeof(label), "hcred_kkw[n256] tamper %s (UNKNOWN CASE)",
                     kkw_kat_tamper_name[i]);
            bad(label);
            hcred_kkw_proof_free(&proof);
            continue;
        }
        if (hcred_verify_kkw(kkw_kat_m_poly, kkw_kat_c_poly, &seed_H,
                             kkw_kat_syndrome, &proof, msg, msg_len)) {
            snprintf(label, sizeof(label),
                     "hcred_kkw[n256] tamper %s ACCEPTED", kkw_kat_tamper_name[i]);
            bad(label);
        }
        hcred_kkw_proof_free(&proof);
    }
    if (failures == 0)
        printf("PASS hcred_kkw[n256] tamper (%d/%d rejected)\n",
               KKW_KAT_TAMPER_COUNT, KKW_KAT_TAMPER_COUNT);

    /* 3. The fixed-stream sampler replay (TODO #296). */
    replay_cbd();
    replay_rand_poly();
    replay_weight_t();
    replay_oprf();

    /* 4. The fixed-stream OPERATION replay (TODO #297). */
    op_stern_keygen();
    op_stern_sign();
    op_zkp_nl_prove();
    op_stern_ring_sign();
    op_rnl_sigma_sign();

    if (failures) {
        printf("*** FAILED: %d check(s) reported [FAIL] ***\n", failures);
        return 1;
    }
    puts("*** OK: KAT/hcred_kkw.json[n256], KAT/sampler_replay.json and "
         "KAT/operation_replay.json verified against herradura.h ***");
    return 0;
}
