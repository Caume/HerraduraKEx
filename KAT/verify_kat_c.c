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
    BitArray e = BA_INIT;
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
    BitArray r = BA_INIT, alpha = BA_INIT;

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
    BitArray seed = BA_INIT, e = BA_INIT;
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
    BitArray msg = BA_INIT, e = BA_INIT, seed = BA_INIT;
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

/* HCRED-KKW proving (TODO #303), and the gap TODO #302 §6 found: KKW's PROVER
 * was pinned NOWHERE.  KAT/hcred_kkw.json is verify-side by construction -- one
 * fresh root per emulation, so a proof is not a function of its statement -- and
 * KKW has no CLI surface in any language, so the 4x4 interop matrix does not
 * reach it either.  That left each port's prover checked only against its OWN
 * verifier, which is the shape that let three of the four ports ship a
 * transcription bug under TODO #266, two of them in this language.  A fixed
 * stream makes the prover a function again, and then one pinned transcript is
 * four ports against each other.
 *
 * n is 256 because HCRED_N is a compile-time constant here and in Java, not a
 * choice; (N_par, M, tau) = (4, 4, 2) is a cost choice the generator asserts is
 * still complete -- in particular the two opened emulations straddle the
 * aux-reveal condition, which is the condition the Go port read backwards. */
static void op_hcred_prove_kkw(void)
{
    FILE *f = fmemopen((void *)opr_kkw_stream, sizeof opr_kkw_stream, "rb");
    HcredKkwProof proof;
    BitArray seed_H = BA_INIT;
    int k, i, rc, before;

    if (!f) { bad("op hcred_prove_kkw (fmemopen)"); return; }
    memcpy(seed_H.b, opr_kkw_seed_H, KEYBYTES);
    rc = hcred_prove_kkw(&proof, opr_kkw_s_poly, opr_kkw_m_poly, opr_kkw_c_poly,
                         &seed_H, opr_kkw_syndrome, OPR_KKW_N_PAR, OPR_KKW_M,
                         OPR_KKW_TAU, opr_kkw_msg, OPR_KKW_MSG_LEN, f);
    if (rc != 0) {
        printf("FAIL op hcred_prove_kkw: prover returned %d\n", rc);
        failures++;
        fclose(f);
        return;
    }
    if (ftell(f) != OPR_KKW_CONSUMED) {
        printf("FAIL op hcred_prove_kkw: consumed %ld stream bytes, vector says "
               "%d\n", ftell(f), OPR_KKW_CONSUMED);
        failures++;
    } else {
        ok("op hcred_prove_kkw consumed one 32-byte root per emulation");
    }
    fclose(f);

    before = failures;
    if (proof.W != OPR_KKW_W) {
        printf("FAIL op hcred_prove_kkw: W is %d, vector says %d\n",
               proof.W, OPR_KKW_W);
        failures++;
    }
    /* The unopened set is the cut-and-choose challenge, derived by Fiat-Shamir
     * from every emulation's commitments -- so a divergence in ANY of the M
     * preprocessing emulations, opened or not, moves it. */
    for (k = 0; k < OPR_KKW_M - OPR_KKW_TAU; k++) {
        if (proof.pre_e[k] != opr_kkw_pre_e[k]) {
            printf("FAIL op hcred_prove_kkw: unopened emulation %d is %d, vector "
                   "says %d\n", k, proof.pre_e[k], opr_kkw_pre_e[k]);
            failures++;
        } else if (memcmp(proof.pre_root + (size_t)k * KEYBYTES,
                          opr_kkw_pre_root[k], KEYBYTES) != 0) {
            printf("FAIL op hcred_prove_kkw: pre[%d] root differs\n",
                   proof.pre_e[k]);
            failures++;
        }
    }
    for (k = 0; k < OPR_KKW_TAU; k++) {
        const HcredKkwOnline *o = &proof.online[k];
        int e = proof.online_e[k];
        if (e != opr_kkw_online_e[k]) {
            printf("FAIL op hcred_prove_kkw: opened emulation %d is %d, vector "
                   "says %d\n", k, e, opr_kkw_online_e[k]);
            failures++;
            continue;
        }
        if (o->pbar != opr_kkw_pbar[k]) {
            printf("FAIL op hcred_prove_kkw: online[%d].pbar is %d, vector says "
                   "%d\n", e, o->pbar, opr_kkw_pbar[k]);
            failures++;
        }
        if (o->u != opr_kkw_u[k]) {
            printf("FAIL op hcred_prove_kkw: online[%d].u is %d, vector says "
                   "%d\n", e, o->u, opr_kkw_u[k]);
            failures++;
        }
        if (memcmp(o->com_h, opr_kkw_com_h[k], KEYBYTES) != 0) {
            printf("FAIL op hcred_prove_kkw: online[%d].com_h differs\n", e);
            failures++;
        }
        if (o->path_len != opr_kkw_path_len[k]) {
            printf("FAIL op hcred_prove_kkw: online[%d].path_len is %d, vector "
                   "says %d\n", e, o->path_len, opr_kkw_path_len[k]);
            failures++;
        } else {
            for (i = 0; i < o->path_len; i++)
                if (o->path[i].l != opr_kkw_path_l[k][i] ||
                    o->path[i].i != opr_kkw_path_i[k][i] ||
                    memcmp(o->path[i].node, opr_kkw_path_node[k][i], KEYBYTES) != 0) {
                    printf("FAIL op hcred_prove_kkw: online[%d].path[%d] differs\n",
                           e, i);
                    failures++;
                    break;
                }
        }
        /* aux is revealed exactly when the hidden party is not party N_par-1.
         * Reading that condition the wrong way round is the bug the Go port
         * shipped (TODO #266), so presence is compared before content. */
        if ((o->aux != NULL) != (opr_kkw_has_aux[k] != 0)) {
            printf("FAIL op hcred_prove_kkw: online[%d] %s aux, vector says it "
                   "%s\n", e, o->aux ? "reveals" : "hides",
                   opr_kkw_has_aux[k] ? "reveals" : "hides");
            failures++;
        } else if (o->aux != NULL &&
                   memcmp(o->aux, opr_kkw_aux[k], sizeof(int32_t) * OPR_KKW_G) != 0) {
            printf("FAIL op hcred_prove_kkw: online[%d].aux differs\n", e);
            failures++;
        }
        if (memcmp(o->zin, opr_kkw_zin[k], sizeof(int32_t) * OPR_KKW_I) != 0) {
            printf("FAIL op hcred_prove_kkw: online[%d].zin differs\n", e);
            failures++;
        }
        if (memcmp(o->t, opr_kkw_t[k], sizeof(int32_t) * OPR_KKW_G) != 0) {
            printf("FAIL op hcred_prove_kkw: online[%d].t differs\n", e);
            failures++;
        }
    }
    if (failures == before)
        printf("PASS op hcred_prove_kkw (%d emulations opened, %d unopened)\n",
               OPR_KKW_TAU, OPR_KKW_M - OPR_KKW_TAU);
    hcred_kkw_proof_free(&proof);
}

/* The ring row.  Two divergences lived in this operation and neither was
 * visible to any other check: the challenge trit had three schemes across the
 * four ports, and the b = 0 dummy commitment was a CONSTANT in C and Go, which
 * identified the real signer from the public signature.  See
 * stern_ring_simulate in herradura.h. */
/* The inverse of herradura.h's qcp_to_bytes.  It lives here rather than in the
 * header because the SHIPPED code never needs it -- a public key arrives
 * through the PEM codec, not as a raw QcPoly -- and adding a suite function
 * for a consumer's benefit is what the internal-surface census exists to
 * catch.  The direction under test is still the shipped one: h_pub is compared
 * through qcp_to_bytes. */
static void qcp_from_bytes(QcPoly *p, const uint8_t in[QCMDPC_RBYTES])
{
    int i, k;
    memset(p->w, 0, sizeof p->w);
    for (i = 0; i < QCMDPC_RWORDS; i++)
        for (k = 0; k < 8 && i * 8 + k < QCMDPC_RBYTES; k++)
            p->w[i] |= (uint64_t)in[i * 8 + k] << (k * 8);
}

/* === TODO #307: the four rows #305's coverage census left OWED ==========
 *
 * QC-MDPC keygen is the one row here whose C cell in OPERATION_REPLAY_PINNED
 * is ABSENT rather than named, and the reason is visible in this function:
 * qcmdpc_keygen takes a QcMdpcPrf *, not a FILE *, so the 32-byte seed is a
 * PARAMETER in C where it is a draw in the other three -- it is drawn by
 * herradura_cli.c's cmd_genpkey, which is CLI_DRAW_COVERAGE's
 * qcmdpc_keygen_prf_seed row.  The consumer therefore reads the stream itself
 * and seeds the PRF with it, so the DRAW ORDER inside the loop is still held
 * against the other three ports; what C does not do is read the CSPRNG here.
 *
 * What is pinned is the LOOP.  Numbered test [52] pins the PRF's seed
 * expansion (TODO #277's 3-vs-1 byte-order split) and KAT/pem/'s kem_priv is
 * verify-side, so neither says anything about the order
 * seed -> sup0 -> sup1 -> screen -> inversion.  The stream REJECTS ONCE on the
 * weak-key screen and then accepts, so the reject branch is pinned too -- a
 * branch about one draw in 550 reaches.
 */
static int cmp_sup(const uint16_t *got, const int *want, int d, const char *what)
{
    int i, j, tmp;
    int sorted[QCMDPC_D];
    for (i = 0; i < d; i++) sorted[i] = (int)got[i];
    for (i = 1; i < d; i++) {          /* insertion sort: a support is a SET */
        tmp = sorted[i];
        for (j = i; j > 0 && sorted[j-1] > tmp; j--) sorted[j] = sorted[j-1];
        sorted[j] = tmp;
    }
    for (i = 0; i < d; i++)
        if (sorted[i] != want[i]) { bad(what); return 0; }
    return 1;
}

static void op_qcmdpc_keygen(void)
{
    QcMdpcPrf prf;
    QcMdpcPriv priv;
    QcMdpcPub pub;
    uint8_t hp[QCMDPC_RBYTES];

    qcprf_init(&prf, opr_qkg_stream);
    qcmdpc_keygen(&priv, &pub, &prf);
    if (cmp_sup(priv.sup0, opr_qkg_sup0, QCMDPC_D, "op qcmdpc_keygen sup0"))
        ok("op qcmdpc_keygen sup0");
    if (cmp_sup(priv.sup1, opr_qkg_sup1, QCMDPC_D, "op qcmdpc_keygen sup1"))
        ok("op qcmdpc_keygen sup1");
    /* Already in qcp_to_bytes order in the header -- see opr_qkg_h_pub. */
    qcp_to_bytes(hp, &pub.h_pub);
    if (memcmp(hp, opr_qkg_h_pub, QCMDPC_RBYTES) != 0)
        bad("op qcmdpc_keygen h_pub");
    else
        ok("op qcmdpc_keygen h_pub");
}

static void op_qcmdpc_encap(void)
{
    QcMdpcPrf prf;
    QcMdpcPub pub;
    QcPoly syn;
    BitArray K = BA_INIT;
    uint8_t buf[QCMDPC_RBYTES];

    qcp_from_bytes(&pub.h_pub, opr_qen_h_pub);
    qcprf_init(&prf, opr_qen_stream);
    qcmdpc_encap(&syn, &K, &pub, &prf);
    qcp_to_bytes(buf, &syn);
    if (memcmp(buf, opr_qen_syndrome, QCMDPC_RBYTES) != 0)
        bad("op qcmdpc_encap syndrome");
    else
        ok("op qcmdpc_encap syndrome");
    /* K is a BitArray, whose byte order is the vector's big-endian one --
     * unlike the polynomials above.  See opr_qen_k. */
    if (cmp_ba(&K, opr_qen_k, "op qcmdpc_encap k"))
        ok("op qcmdpc_encap k");
}

/* ZKB++ proving.  NARROWS a claim TODO #302 section 6 makes: its "covered
 * twice over" is true of the CIRCUIT, which neither port carries its own copy
 * of, and does not extend to the SEED DRAW ORDER -- this function's own
 * consumption order, which no row pinned.  Section 2 of that file makes the
 * 16-byte seed a security parameter, so the order is not formatting. */
static void op_zkp_nl_pp_prove(void)
{
    FILE *f = fmemopen((void *)opr_zpp_stream, sizeof opr_zpp_stream, "rb");
    ZkpNlPpRound *pp;
    int j, nb = OPR_ZPP_NB, bad_at = -1;
    const char *bad_field = "";

    if (!f) { bad("op zkp_nl_pp_prove (fmemopen)"); return; }
    pp = zkp_nl_pp_prove(OPR_ZPP_A, OPR_ZPP_B, OPR_ZPP_Y, OPR_ZPP_N,
                         OPR_ZPP_ROUNDS, opr_zpp_msg, OPR_ZPP_MSG_LEN, f);
    if (!pp) { bad("op zkp_nl_pp_prove (alloc)"); fclose(f); return; }
    for (j = 0; j < OPR_ZPP_ROUNDS && bad_at < 0; j++) {
        /* share2 is EMPTY exactly when e == 2, party 2's share being DERIVED
         * rather than seeded (TODO #302 section 2), so the empty case is a
         * field value and not a gap: has_share2 carries it here and a
         * zero-length string carries it in the JSON. */
        int want_len = opr_zpp_share2_len[j];
        if (pp[j].e != opr_zpp_e[j])                              bad_field = "e";
        else if (memcmp(pp[j].com_e, opr_zpp_com_e[j], 32))       bad_field = "com_e";
        else if (memcmp(pp[j].out_e, opr_zpp_out_e[j], (size_t)nb)) bad_field = "out_e";
        else if (memcmp(pp[j].seed_p1, opr_zpp_seed_p1[j], ZKPP_SEED_BYTES))
                                                                  bad_field = "seed_p1";
        else if (memcmp(pp[j].seed_p2, opr_zpp_seed_p2[j], ZKPP_SEED_BYTES))
                                                                  bad_field = "seed_p2";
        else if (memcmp(pp[j].gates_p2, opr_zpp_gates_p2[j], pp[j].gates_len))
                                                                  bad_field = "gates_p2";
        else if ((pp[j].has_share2 ? nb : 0) != want_len)         bad_field = "share2 length";
        else if (want_len && memcmp(pp[j].share2, opr_zpp_share2[j], (size_t)want_len))
                                                                  bad_field = "share2";
        else continue;
        bad_at = j;
    }
    if (bad_at >= 0) {
        printf("FAIL op zkp_nl_pp_prove: round %d differs at %s\n", bad_at, bad_field);
        failures++;
    } else {
        ok("op zkp_nl_pp_prove rounds");
    }
    if (ftell(f) != OPR_ZPP_CONSUMED) {
        printf("FAIL op zkp_nl_pp_prove: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_ZPP_CONSUMED);
        failures++;
    }
    for (j = 0; j < OPR_ZPP_ROUNDS; j++) free(pp[j].gates_p2);
    free(pp);
    fclose(f);
}

/* HCRED's OTHER prover, beside the KKW one above: same file, same witness, and
 * TODO #266's transcription bug was in this family -- three of four ports
 * shipped one.  Numbered test [50] runs each port's prover against ITS OWN
 * verifier, which is precisely the shape that lets a transcription bug pass. */
static int cmp_i32(const int32_t *got, const int32_t *want, int n)
{
    int i;
    for (i = 0; i < n; i++) if (got[i] != want[i]) return 0;
    return 1;
}

static void op_hcred_prove(void)
{
    FILE *f = fmemopen((void *)opr_hcp_stream, sizeof opr_hcp_stream, "rb");
    HcredProof proof;
    BitArray seed_H = BA_INIT;
    uint8_t outs_buf[HCRED_ROUND_OUTS_SER];
    int j, p, bad_at = -1;
    const char *bad_field = "";

    if (!f) { bad("op hcred_prove (fmemopen)"); return; }
    memcpy(seed_H.b, opr_hcp_seed_H, KEYBYTES);
    if (hcred_prove(&proof, opr_hcp_s_poly, opr_hcp_m_poly, opr_hcp_c_poly,
                    &seed_H, opr_hcp_syndrome, OPR_HCP_ROUNDS,
                    opr_hcp_msg, OPR_HCP_MSG_LEN, f) != 0) {
        bad("op hcred_prove (prove failed)");
        fclose(f);
        return;
    }
    if (proof.W != OPR_HCP_W) bad("op hcred_prove W"); else ok("op hcred_prove W");
    for (j = 0; j < OPR_HCP_ROUNDS && bad_at < 0; j++) {
        const HcredRound *rd = &proof.rd[j];
        for (p = 0; p < 3; p++)
            if (memcmp(rd->coms[p], opr_hcp_coms[3*j + p], KEYBYTES)) {
                bad_field = "coms"; bad_at = j; break;
            }
        if (bad_at >= 0) break;
        /* `outs` travels as the suite's OWN serialisation, the one that feeds
         * the FS hash, so this compares one buffer rather than four opinions
         * of a nested layout. */
        _hcred_outs_ser(outs_buf, &rd->outs);
        if (memcmp(outs_buf, opr_hcp_outs[j], OPR_HCP_OUTS_LEN))      bad_field = "outs";
        else if (memcmp(rd->seed_c,  opr_hcp_seed_c[j],  KEYBYTES))   bad_field = "seed_c";
        else if (memcmp(rd->seed_c1, opr_hcp_seed_c1[j], KEYBYTES))   bad_field = "seed_c1";
        else if (!cmp_i32(rd->a1, opr_hcp_a1 + (size_t)j*HCRED_N,  HCRED_N))  bad_field = "a1";
        else if (!cmp_i32(rd->b1, opr_hcp_b1 + (size_t)j*HCRED_N,  HCRED_N))  bad_field = "b1";
        else if (!cmp_i32(rd->g1, opr_hcp_g1 + (size_t)j*HCRED_NB, HCRED_NB)) bad_field = "g1";
        else if (!cmp_i32(rd->h1, opr_hcp_h1 + (size_t)j*HCRED_ND, HCRED_ND)) bad_field = "h1";
        /* has_aux is the aux-reveal condition -- revealed exactly when party 2
         * is one of the two opened -- and it is the condition the Go port read
         * backwards at TODO #266, so it is compared before the vectors are. */
        else if (rd->has_aux != opr_hcp_aux_present[j])          bad_field = "aux reveal condition";
        else if (rd->has_aux &&
                 !cmp_i32(rd->aux_s, opr_hcp_aux_s + (size_t)j*HCRED_N,  HCRED_N))  bad_field = "aux_s";
        else if (rd->has_aux &&
                 !cmp_i32(rd->aux_b, opr_hcp_aux_B + (size_t)j*HCRED_NB, HCRED_NB)) bad_field = "aux_B";
        else if (rd->has_aux &&
                 !cmp_i32(rd->aux_d, opr_hcp_aux_D + (size_t)j*HCRED_ND, HCRED_ND)) bad_field = "aux_D";
        else continue;
        bad_at = j;
    }
    if (bad_at >= 0) {
        printf("FAIL op hcred_prove: round %d differs at %s\n", bad_at, bad_field);
        failures++;
    } else {
        ok("op hcred_prove rounds");
    }
    if (ftell(f) != OPR_HCP_CONSUMED) {
        printf("FAIL op hcred_prove: consumed %ld bytes, vector says %d\n",
               ftell(f), OPR_HCP_CONSUMED);
        failures++;
    }
    if (!hcred_verify(opr_hcp_m_poly, opr_hcp_c_poly, &seed_H,
                      opr_hcp_syndrome, &proof, OPR_HCP_ROUNDS,
                      opr_hcp_msg, OPR_HCP_MSG_LEN))
        bad("op hcred_prove verifies");
    else
        ok("op hcred_prove verifies");
    hcred_proof_free(&proof);
    fclose(f);
}

static void op_stern_ring_sign(void)
{
    FILE *f = fmemopen((void *)opr_ring_stream, sizeof opr_ring_stream, "rb");
    SternRingSig sig;
    BitArray msg = BA_INIT, e = BA_INIT, seeds[OPR_RING_K];
    ba_init_array(seeds, OPR_RING_K);
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
    BitArray seed_H = BA_INIT;
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
    op_hcred_prove_kkw();
    /* TODO #307's four, in the order #305's census listed them. */
    op_qcmdpc_keygen();
    op_qcmdpc_encap();
    op_zkp_nl_pp_prove();
    op_hcred_prove();

    if (failures) {
        printf("*** FAILED: %d check(s) reported [FAIL] ***\n", failures);
        return 1;
    }
    puts("*** OK: KAT/hcred_kkw.json[n256], KAT/sampler_replay.json and "
         "KAT/operation_replay.json verified against herradura.h ***");
    return 0;
}
