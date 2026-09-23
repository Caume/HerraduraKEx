/*  KAT/verify_bitarray_c.c — the C consumer for KAT/bitarray.json (TODO #314).
 *
 *  BITARRAY.md is the specification; KAT/generate_bitarray_kat.py carries the
 *  reference implementation and pins its output; this runs the SHIPPED C
 *  BitArray against those pinned answers.
 *
 *  C is pass 2 and therefore the FIRST port in the gating set.  Until a second
 *  port lands, this checks one implementation against one pinned answer, which
 *  is strictly more than currency but less than the cross-implementation check
 *  BITARRAY.md §7 describes — that arrives with pass 3.  Said here rather than
 *  left to look like more than it is.
 *
 *  Reads the GENERATED KAT/bitarray_vector.h rather than the JSON: the C tree is
 *  dependency-free and has no JSON parser (KAT/hcred_kkw_vector.h's precedent,
 *  TODO #266).  `--check` asserts the header and the JSON agree, so the two
 *  cannot drift.
 *
 *  Compiled on demand by CliTest/test_kat_vectors.sh, not tracked (TODO #229).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../herradura.h"
#include "bitarray_vector.h"

static int pass_n = 0, fail_n = 0;

static void ok(int cond, const BaCase *c, const char *detail)
{
    if (cond) {
        pass_n++;
    } else {
        fail_n++;
        printf("FAIL [%s n=%d%s] %s\n", c->op, c->nbits,
               c->mixed_with ? " mixed" : "", detail);
    }
}

/* Build an operand at a stated width from the case's hex. */
static BaStatus load(BitArray *dst, const char *hex, int n)
{
    return ba_try_from_hex(dst, hex, n);
}

static void check_bits(const BaCase *c, BaStatus st, const BitArray *got)
{
    char hex[2 * BA_MAX_BYTES + 1];
    char msg[256];

    if (c->kind == BA_R_ERROR) {
        if (st == BA_OK) {
            snprintf(msg, sizeof msg, "expected %s, got a value", c->want_error);
            ok(0, c, msg);
        } else {
            snprintf(msg, sizeof msg, "expected %s, got %s",
                     c->want_error, ba_status_name(st));
            ok(strcmp(ba_status_name(st), c->want_error) == 0, c, msg);
        }
        return;
    }
    if (st != BA_OK) {
        snprintf(msg, sizeof msg, "expected a value, got %s", ba_status_name(st));
        ok(0, c, msg);
        return;
    }
    ba_to_hex(hex, got);
    snprintf(msg, sizeof msg, "got %s/%d want %s/%d",
             hex, (int)got->nbits, c->want_hex, c->want_nbits);
    ok(got->nbits == c->want_nbits && strcmp(hex, c->want_hex) == 0, c, msg);
}

static void check_int(const BaCase *c, BaStatus st, long long got)
{
    char msg[160];
    if (c->kind == BA_R_ERROR) {
        snprintf(msg, sizeof msg, "expected %s, got %s",
                 c->want_error, st == BA_OK ? "a value" : ba_status_name(st));
        ok(st != BA_OK && strcmp(ba_status_name(st), c->want_error) == 0, c, msg);
        return;
    }
    if (st != BA_OK) {
        snprintf(msg, sizeof msg, "expected a value, got %s", ba_status_name(st));
        ok(0, c, msg);
        return;
    }
    snprintf(msg, sizeof msg, "got %lld want %lld", got, c->want_int);
    ok(got == c->want_int, c, msg);
}

int main(void)
{
    int idx;

    printf("=== KAT/bitarray.json against the shipped C BitArray (TODO #314) ===\n");
    printf("    %d cases, capacity BA_MAX_BITS = %d\n", BA_VECTOR_CASES, BA_MAX_BITS);

    for (idx = 0; idx < BA_VECTOR_CASES; idx++) {
        const BaCase *c = &ba_vector_cases[idx];
        BitArray a = BA_INIT, b = BA_INIT, r = BA_INIT;
        BaStatus st = BA_OK, sa, sb;
        const char *op = c->op;
        int bw = c->mixed_with ? c->mixed_with : c->nbits;

        /* Load operands.  A width the port cannot represent is BA_E_WIDTH, and
           that is a legitimate answer the vector may be pinning. */
        sa = c->a ? load(&a, c->a, c->nbits) : BA_OK;
        sb = c->b ? load(&b, c->b, bw) : BA_OK;

        if (strcmp(op, "zero") == 0) {
            st = ba_try_set_width(&r, c->nbits);
            if (st == BA_OK) ba_zero_w(&r, c->nbits);
            check_bits(c, st, &r);
            continue;
        }
        if (strcmp(op, "from_hex") == 0)  { check_bits(c, sa, &a); continue; }
        if (strcmp(op, "from_bytes") == 0) {
            uint8_t buf[BA_MAX_BYTES];
            size_t len = c->a ? strlen(c->a) / 2 : 0;
            if (c->a) {
                size_t i;
                for (i = 0; i < len && i < sizeof buf; i++) {
                    unsigned v;
                    sscanf(c->a + 2 * i, "%2x", &v);
                    buf[i] = (uint8_t)v;
                }
            }
            st = ba_try_from_bytes(&r, buf, len, c->nbits);
            check_bits(c, st, &r);
            continue;
        }
        if (strcmp(op, "from_uint") == 0) {
            /* The vector's out-of-range case is 2^32 at n = 32; a negative
               value is E_RANGE and is spelled as such rather than wrapped. */
            if (c->iarg < 0) {
                check_bits(c, BA_E_RANGE, &r);
            } else {
                st = ba_try_from_uint(&r, (uint64_t)c->iarg, c->nbits);
                check_bits(c, st, &r);
            }
            continue;
        }

        /* Everything below needs operand a to have loaded. */
        if (c->a && sa != BA_OK) { check_bits(c, sa, &a); continue; }
        if (c->b && sb != BA_OK) { check_bits(c, sb, &b); continue; }

        if (strcmp(op, "to_uint") == 0) {
            uint64_t v = 0;
            st = ba_try_to_uint(&v, &a);
            check_int(c, st, (long long)v);
        } else if (strcmp(op, "popcount") == 0) {
            check_int(c, BA_OK, ba_popcount(&a));
        } else if (strcmp(op, "is_zero") == 0) {
            ok(ba_is_zero(&a) == c->want_bool, c, "is_zero");
        } else if (strcmp(op, "xor") == 0) {
            check_bits(c, ba_try_xor(&r, &a, &b), &r);
        } else if (strcmp(op, "and") == 0) {
            check_bits(c, ba_try_and(&r, &a, &b), &r);
        } else if (strcmp(op, "or") == 0) {
            check_bits(c, ba_try_or(&r, &a, &b), &r);
        } else if (strcmp(op, "not") == 0) {
            check_bits(c, ba_try_not(&r, &a), &r);
        } else if (strcmp(op, "rot_left") == 0) {
            ba_rol_bits(&r, &a, (int)c->iarg);
            check_bits(c, BA_OK, &r);
        } else if (strcmp(op, "rot_right") == 0) {
            ba_ror_bits(&r, &a, (int)c->iarg);
            check_bits(c, BA_OK, &r);
        } else if (strcmp(op, "shl") == 0) {
            check_bits(c, ba_try_shl(&r, &a, (int)c->iarg), &r);
        } else if (strcmp(op, "shr") == 0) {
            check_bits(c, ba_try_shr(&r, &a, (int)c->iarg), &r);
        } else if (strcmp(op, "truncate") == 0) {
            check_bits(c, ba_try_truncate(&r, &a, (int)c->iarg), &r);
        } else if (strcmp(op, "extend") == 0) {
            check_bits(c, ba_try_extend(&r, &a, (int)c->iarg), &r);
        } else if (strcmp(op, "resize_exact") == 0) {
            check_bits(c, ba_try_resize_exact(&r, &a, (int)c->iarg), &r);
        } else if (strcmp(op, "equal") == 0) {
            ok(ba_equal(&a, &b) == c->want_bool, c, "equal");
        } else if (strcmp(op, "compare") == 0) {
            int v = 0;
            st = ba_try_compare(&v, &a, &b);
            check_int(c, st, v);
        } else if (strcmp(op, "bit") == 0) {
            int v = 0;
            st = ba_try_bit(&v, &a, (int)c->iarg);
            check_int(c, st, v);
        } else if (strcmp(op, "fscx") == 0) {
            check_bits(c, ba_try_fscx(&r, &a, &b), &r);
        } else if (strcmp(op, "fscx_revolve") == 0) {
            BitArray cur = a, nxt = BA_INIT;
            long long i;
            st = BA_OK;
            for (i = 0; i < c->iarg && st == BA_OK; i++) {
                st = ba_try_fscx(&nxt, &cur, &b);
                cur = nxt;
            }
            check_bits(c, st, &cur);
        } else if (strcmp(op, "gf_mul") == 0) {
            check_bits(c, ba_try_gf_mul(&r, &a, &b), &r);
        } else if (strcmp(op, "gf_pow") == 0) {
            check_bits(c, ba_try_gf_pow(&r, &a, (uint64_t)c->iarg), &r);
        } else if (strcmp(op, "rnl_kdf_seed") == 0) {
            ba_rnl_kdf_seed(&r, &a);
            check_bits(c, BA_OK, &r);
        } else {
            fail_n++;
            printf("FAIL [%s] no handler in verify_bitarray_c.c — a case the "
                   "consumer does not implement must not read as a pass\n", op);
        }
    }

    printf("\nResults: %d PASS / %d FAIL (of %d cases)\n",
           pass_n, fail_n, BA_VECTOR_CASES);
    if (pass_n + fail_n != BA_VECTOR_CASES) {
        printf("FAIL: %d case(s) were neither passed nor failed — a case that "
               "did not run must not be scored (TODO #291)\n",
               BA_VECTOR_CASES - pass_n - fail_n);
        return 1;
    }
    if (fail_n) {
        printf("*** FAILED: the shipped C BitArray disagrees with BITARRAY.md ***\n");
        return 1;
    }
    printf("*** OK: the shipped C BitArray matches KAT/bitarray.json ***\n");
    return 0;
}
