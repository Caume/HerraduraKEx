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

    if (failures) {
        printf("*** FAILED: %d check(s) reported [FAIL] ***\n", failures);
        return 1;
    }
    puts("*** OK: KAT/hcred_kkw.json[n256] verified against herradura.h ***");
    return 0;
}
