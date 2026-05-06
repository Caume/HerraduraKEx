/* HerraduraCli/herradura_cli.c — OpenSSL-style CLI for the Herradura Cryptographic Suite
 *
 * Build: gcc -O2 -o HerraduraCli/herradura_cli HerraduraCli/herradura_cli.c
 *
 * Usage:
 *   herradura_cli genpkey --algo hkex-gf  --out alice.pem
 *   herradura_cli pkey    --in alice.pem --pubout --out alice_pub.pem
 *   herradura_cli pkey    --in alice.pem --text
 *   herradura_cli kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --out sk.pem
 *   herradura_cli kex     --algo hkex-rnl --our bob.pem   --their alice_pub.pem --out bob_resp.pem
 *   herradura_cli kex     --algo hkex-rnl --our alice.pem --their bob_resp.pem  --out sk.pem
 *
 * PEM files are byte-for-byte compatible with HerraduraCli/herradura.py.
 */

#include "../herradura.h"
#include "herradura_codec.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * I/O helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static void die(const char *msg) { fputs(msg, stderr); fputc('\n', stderr); exit(1); }
static void dief(const char *fmt, const char *s)
{ fprintf(stderr, fmt, s); fputc('\n', stderr); exit(1); }

static uint8_t *read_binary_file(const char *path, size_t *len_out)
{
    FILE *f = (strcmp(path, "-") == 0) ? stdin : fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open: %s\n", path); exit(1); }
    size_t cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) die("out of memory");
    size_t r;
    while ((r = fread(buf + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) { cap *= 2; uint8_t *nb = realloc(buf, cap);
            if (!nb) { free(buf); die("out of memory"); } buf = nb; }
    }
    if (f != stdin) fclose(f);
    *len_out = n;
    return buf;
}

static void write_pem_file(const char *path, const char *label,
                           const uint8_t *der, size_t der_len)
{
    if (!path || strcmp(path, "-") == 0) {
        size_t llen = strlen(label);
        size_t bufsz = PEM_WRAP_LEN(der_len, llen);
        char *buf = malloc(bufsz);
        if (!buf) die("out of memory");
        pem_wrap(label, der, der_len, buf, NULL);
        fputs(buf, stdout);
        free(buf);
    } else {
        if (pem_write_file(path, label, der, der_len) != 0)
            dief("cannot write: %s", path);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Argument parsing
 * ───────────────────────────────────────────────────────────────────────────── */

static const char *get_arg(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    return NULL;
}
static int has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) return 1;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * BitArray / polynomial packing helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Minimal-byte pointer for a BitArray (skips leading zero bytes). */
static void ba_min_bytes(const BitArray *ba, const uint8_t **start, size_t *len)
{
    size_t i;
    for (i = 0; i < KEYBYTES && ba->b[i] == 0; i++);
    if (i == KEYBYTES) { *start = ba->b + KEYBYTES - 1; *len = 1; }
    else               { *start = ba->b + i; *len = KEYBYTES - i; }
}

/* Right-align src_len bytes into a KEYBYTES-wide BitArray (big-endian). */
static void ba_from_ra(BitArray *ba, const uint8_t *src, size_t src_len)
{
    memset(ba->b, 0, KEYBYTES);
    size_t cp = (src_len < KEYBYTES) ? src_len : KEYBYTES;
    memcpy(ba->b + KEYBYTES - cp, src, cp);
}

/* Pack n Z_q polynomial coefficients into bpc-bytes-per-coeff big-endian blob.
 * bpc=4 for s and m (Z_q, q=65537 ≤ 17 bits); bpc=2 for C (Z_p, p=4096 ≤ 12 bits). */
static void poly_pack(uint8_t *out, const rnl_poly_t p, int bpc)
{
    int i, k;
    for (i = 0; i < RNL_N; i++) {
        uint32_t v = (uint32_t)p[i];
        for (k = bpc - 1; k >= 0; k--) { out[i * bpc + k] = (uint8_t)(v & 0xFF); v >>= 8; }
    }
}

/* Unpack a bpc-bytes-per-coeff big-endian blob into a Z_q polynomial. */
static void poly_unpack(rnl_poly_t p, const uint8_t *src, size_t src_len, int bpc)
{
    uint8_t aligned[RNL_N * 4];
    int total = RNL_N * bpc;
    /* Right-align in case sign byte was stripped (src_len may be total-1). */
    memset(aligned, 0, (size_t)total);
    if ((int)src_len > total) src_len = (size_t)total;
    memcpy(aligned + total - (int)src_len, src, src_len);
    int i, k;
    for (i = 0; i < RNL_N; i++) {
        uint32_t v = 0;
        for (k = 0; k < bpc; k++) v = (v << 8) | aligned[i * bpc + k];
        p[i] = (int32_t)v;
    }
}

/* DER INTEGER for a 32-byte (256-bit) value. */
static int der_i32(const uint8_t bytes[KEYBYTES], uint8_t *out, size_t *olen)
{ return der_int_enc(bytes, KEYBYTES, out, olen); }

/* DER INTEGER for n = 256 (minimal: 0x01 0x00). */
static int der_i_n256(uint8_t *out, size_t *olen)
{ static const uint8_t n[2] = {0x01, 0x00}; return der_int_enc(n, 2, out, olen); }

/* Wrap items into SEQUENCE DER, then PEM-wrap and write. */
static void seq_and_write(const uint8_t **it, const size_t *il, int ni,
                          const char *label, const char *out_path)
{
    size_t body = 0; int i;
    for (i = 0; i < ni; i++) body += il[i];
    size_t der_sz = DER_SEQ_LEN(body);
    uint8_t *der = malloc(der_sz);
    if (!der) die("out of memory");
    size_t der_len;
    if (der_seq_enc(it, il, ni, der, &der_len) != 0) die("DER encode error");
    write_pem_file(out_path, label, der, der_len);
    free(der);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * PEM read helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Read PEM from path or stdin; allocate DER buffer; parse DER SEQUENCE. */
typedef struct {
    char     label[80];
    uint8_t *der;    /* heap-allocated */
    size_t   der_len;
    const uint8_t *vals[16];
    size_t   vlens[16];
    int      n_items;
} PemKey;

static void pem_key_load(PemKey *k, const char *path)
{
    size_t raw_len;
    uint8_t *raw = read_binary_file(path, &raw_len);
    size_t der_cap = raw_len;  /* base64 expands ≤ raw, so DER ≤ raw_len */
    k->der = malloc(der_cap);
    if (!k->der) die("out of memory");
    if (pem_unwrap((char *)raw, raw_len, k->label, k->der, &k->der_len) != 0)
        dief("cannot parse PEM from: %s", path);
    free(raw);
    if (der_parse_seq(k->der, k->der_len, k->vals, k->vlens, 16, &k->n_items) != 0)
        dief("cannot parse DER from: %s", path);
}
static void pem_key_free(PemKey *k) { free(k->der); k->der = NULL; }

/* Get integer n=256 from a val. Returns 0 on success. */
static int pem_key_get_n(const PemKey *k, int idx)
{
    if (idx >= k->n_items || k->vlens[idx] == 0) return -1;
    const uint8_t *v = k->vals[idx];
    size_t vl = k->vlens[idx];
    int n = 0; size_t i;
    for (i = 0; i < vl; i++) n = (n << 8) | v[i];
    return n;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * genpkey
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_genpkey(int argc, char **argv)
{
    const char *algo = get_arg(argc, argv, "--algo");
    const char *out  = get_arg(argc, argv, "--out");
    if (!algo) die("genpkey: --algo required");

    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    /* Classical GF key: (priv, pub=g^priv, n) */
    static const char *const classical[] = {
        "hkex-gf","hpks","hpks-nl","hpke","hpke-nl", NULL };
    static const char *const classical_labels[] = {
        PEM_HKEX_GF_PRIV, PEM_HPKS_PRIV, PEM_HPKS_NL_PRIV,
        PEM_HPKE_PRIV, PEM_HPKE_NL_PRIV };
    for (int ci = 0; classical[ci]; ci++) {
        if (strcmp(algo, classical[ci]) != 0) continue;
        BitArray a, C;
        ba_rand(&a, urnd);
        gf_pow_ba(&C, &GF_GEN, &a);
        uint8_t ia[DER_INT_LEN(KEYBYTES)], iC[DER_INT_LEN(KEYBYTES)], in[8];
        size_t la, lC, ln;
        der_i32(a.b, ia, &la); der_i32(C.b, iC, &lC); der_i_n256(in, &ln);
        const uint8_t *it[3] = {ia, iC, in};
        size_t il[3] = {la, lC, ln};
        seq_and_write(it, il, 3, classical_labels[ci], out);
        fclose(urnd); return;
    }

    if (strcmp(algo, "hkex-rnl") == 0) {
        rnl_poly_t m_base, a_rand, m_blind, s_poly, C_poly;
        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand, urnd);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_poly, C_poly, m_blind, urnd);

        uint8_t s_buf[RNL_N * 4], m_buf[RNL_N * 4];
        poly_pack(s_buf, s_poly, 4);
        poly_pack(m_buf, m_blind, 4);

        size_t is_sz = DER_INT_LEN(sizeof s_buf);
        size_t im_sz = DER_INT_LEN(sizeof m_buf);
        uint8_t *is_der = malloc(is_sz), *im_der = malloc(im_sz);
        uint8_t in_der[8]; size_t ls, lm, ln;
        if (!is_der || !im_der) die("out of memory");
        der_int_enc(s_buf, sizeof s_buf, is_der, &ls);
        der_int_enc(m_buf, sizeof m_buf, im_der, &lm);
        der_i_n256(in_der, &ln);
        const uint8_t *it[3] = {is_der, im_der, in_der};
        size_t il[3] = {ls, lm, ln};
        seq_and_write(it, il, 3, PEM_HKEX_RNL_PRIV, out);
        free(is_der); free(im_der);
        fclose(urnd); return;
    }

    if (strcmp(algo, "hpks-stern") == 0 || strcmp(algo, "hpke-stern") == 0) {
        const char *label = (strcmp(algo,"hpks-stern")==0)
                             ? PEM_HPKS_STERN_PRIV : PEM_HPKE_STERN_PRIV;
        BitArray seed, e;
        uint8_t syndr[SDF_SYNBYTES];
        stern_f_keygen(&seed, &e, syndr, urnd);
        uint8_t ie[DER_INT_LEN(KEYBYTES)], is[DER_INT_LEN(KEYBYTES)], in[8];
        size_t le, ls, ln;
        der_i32(e.b, ie, &le); der_i32(seed.b, is, &ls); der_i_n256(in, &ln);
        const uint8_t *it[3] = {ie, is, in};
        size_t il[3] = {le, ls, ln};
        seq_and_write(it, il, 3, label, out);
        fclose(urnd); return;
    }

    fclose(urnd);
    dief("genpkey: unsupported algorithm: %s", algo);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pkey
 * ───────────────────────────────────────────────────────────────────────────── */

static void print_hex_field(const char *name, const uint8_t *bytes, size_t len)
{
    printf("%-10s: ", name);
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
    putchar('\n');
}

static void cmd_pkey(int argc, char **argv)
{
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    int pubout = has_flag(argc, argv, "--pubout");
    int text   = has_flag(argc, argv, "--text");
    if (!in_path) die("pkey: --in required");
    if (!pubout && !text) die("pkey: specify --pubout or --text");

    PemKey k; pem_key_load(&k, in_path);

    /* Detect algo from label */
    static const struct { const char *priv_label; const char *pub_label;
                          const char *algo; int is_classical; } algos[] = {
        { PEM_HKEX_GF_PRIV,    PEM_HKEX_GF_PUB,    "hkex-gf",    1 },
        { PEM_HPKS_PRIV,       PEM_HPKS_PUB,        "hpks",       1 },
        { PEM_HPKS_NL_PRIV,    PEM_HPKS_NL_PUB,     "hpks-nl",    1 },
        { PEM_HPKE_PRIV,       PEM_HPKE_PUB,        "hpke",       1 },
        { PEM_HPKE_NL_PRIV,    PEM_HPKE_NL_PUB,     "hpke-nl",    1 },
        { PEM_HKEX_RNL_PRIV,   PEM_HKEX_RNL_PUB,   "hkex-rnl",   0 },
        { PEM_HPKS_STERN_PRIV, PEM_HPKS_STERN_PUB, "hpks-stern", 2 },
        { PEM_HPKE_STERN_PRIV, PEM_HPKE_STERN_PUB, "hpke-stern", 2 },
        { NULL, NULL, NULL, 0 }
    };

    int ai = -1;
    for (int i = 0; algos[i].algo; i++) {
        if (strcmp(k.label, algos[i].priv_label) == 0) { ai = i; break; }
    }
    if (ai < 0) dief("pkey: unrecognised PEM label: %s", k.label);

    const char *algo = algos[ai].algo;
    int kind = algos[ai].is_classical;  /* 1=classical, 0=rnl, 2=stern */

    /* ── Classical GF algorithms ─── */
    if (kind == 1) {
        if (k.n_items != 3) die("pkey: malformed classical private key");
        BitArray priv, pub;
        ba_from_ra(&priv, k.vals[0], k.vlens[0]);
        ba_from_ra(&pub,  k.vals[1], k.vlens[1]);

        if (text) {
            printf("%-10s: %s\n", "algorithm", algo);
            printf("%-10s: 256\n", "bits");
            print_hex_field("private", priv.b, KEYBYTES);
            print_hex_field("public",  pub.b,  KEYBYTES);
        } else {
            uint8_t ip[DER_INT_LEN(KEYBYTES)], in[8]; size_t lp, ln;
            der_i32(pub.b, ip, &lp); der_i_n256(in, &ln);
            const uint8_t *it[2] = {ip, in}; size_t il[2] = {lp, ln};
            seq_and_write(it, il, 2, algos[ai].pub_label, out_path);
        }
    }

    /* ── HKEX-RNL ─── */
    else if (kind == 0) {
        if (k.n_items != 3) die("pkey: malformed RNL private key");
        rnl_poly_t s_poly, m_poly, C_poly;
        poly_unpack(s_poly, k.vals[0], k.vlens[0], 4);
        poly_unpack(m_poly, k.vals[1], k.vlens[1], 4);

        if (text) {
            uint8_t s_buf[RNL_N * 4];
            poly_pack(s_buf, s_poly, 4);
            printf("%-10s: %s\n", "algorithm", algo);
            printf("%-10s: 256\n", "n");
            printf("%-10s: ", "s_packed");
            for (size_t j = 0; j < sizeof s_buf; j++) printf("%02x", s_buf[j]);
            putchar('\n');
        } else {
            /* Derive C = round_p(m * s) */
            rnl_poly_t ms;
            rnl_poly_mul(ms, m_poly, s_poly);
            rnl_round(C_poly, ms, RNL_Q, RNL_P);

            uint8_t C_buf[RNL_N * 2], m_buf[RNL_N * 4];
            poly_pack(C_buf, C_poly, 2);
            poly_pack(m_buf, m_poly, 4);

            size_t ic_sz = DER_INT_LEN(sizeof C_buf);
            size_t im_sz = DER_INT_LEN(sizeof m_buf);
            uint8_t *ic_der = malloc(ic_sz), *im_der = malloc(im_sz);
            uint8_t in_der[8]; size_t lc, lm, ln;
            if (!ic_der || !im_der) die("out of memory");
            der_int_enc(C_buf, sizeof C_buf, ic_der, &lc);
            der_int_enc(m_buf, sizeof m_buf, im_der, &lm);
            der_i_n256(in_der, &ln);
            const uint8_t *it[3] = {ic_der, im_der, in_der};
            size_t il[3] = {lc, lm, ln};
            seq_and_write(it, il, 3, PEM_HKEX_RNL_PUB, out_path);
            free(ic_der); free(im_der);
        }
    }

    /* ── Stern-F algorithms ─── */
    else {
        if (k.n_items != 3) die("pkey: malformed Stern private key");
        BitArray e, seed;
        ba_from_ra(&e,    k.vals[0], k.vlens[0]);
        ba_from_ra(&seed, k.vals[1], k.vlens[1]);

        if (text) {
            printf("%-10s: %s\n", "algorithm", algo);
            printf("%-10s: 256\n", "n");
            print_hex_field("e_int", e.b,    KEYBYTES);
            print_hex_field("seed",  seed.b, KEYBYTES);
        } else {
            uint8_t syndr[SDF_SYNBYTES];
            stern_syndrome(syndr, &seed, &e);

            /* Syndrome is SDF_SYNBYTES (16) bytes; encode as 32-byte DER INTEGER
             * matching Python: der_int(syn_int, nbytes) where nbytes=n//8=32. */
            uint8_t syn32[KEYBYTES];
            memset(syn32, 0, KEYBYTES);
            memcpy(syn32 + KEYBYTES - SDF_SYNBYTES, syndr, SDF_SYNBYTES);

            uint8_t isyn[DER_INT_LEN(KEYBYTES)], is[DER_INT_LEN(KEYBYTES)], in[8];
            size_t lsyn, ls, ln;
            der_i32(syn32, isyn, &lsyn);
            der_i32(seed.b, is, &ls);
            der_i_n256(in, &ln);
            const uint8_t *it[3] = {isyn, is, in};
            size_t il[3] = {lsyn, ls, ln};
            seq_and_write(it, il, 3, algos[ai].pub_label, out_path);
        }
    }

    pem_key_free(&k);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * kex
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_kex(int argc, char **argv)
{
    const char *algo      = get_arg(argc, argv, "--algo");
    const char *our_path  = get_arg(argc, argv, "--our");
    const char *their_path = get_arg(argc, argv, "--their");
    const char *out_path  = get_arg(argc, argv, "--out");
    if (!algo || !our_path || !their_path || !out_path)
        die("kex: --algo, --our, --their, --out required");

    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    /* ── HKEX-GF ─── */
    if (strcmp(algo, "hkex-gf") == 0) {
        PemKey our, their;
        pem_key_load(&our,   our_path);
        pem_key_load(&their, their_path);
        if (our.n_items < 1)   die("kex: malformed our private key");
        if (their.n_items < 1) die("kex: malformed their public key");
        BitArray priv, pub_theirs, sk;
        ba_from_ra(&priv,       our.vals[0],   our.vlens[0]);
        ba_from_ra(&pub_theirs, their.vals[0], their.vlens[0]);
        gf_pow_ba(&sk, &pub_theirs, &priv);
        pem_key_free(&our); pem_key_free(&their);

        const uint8_t *sk_start; size_t sk_len;
        ba_min_bytes(&sk, &sk_start, &sk_len);
        uint8_t isk[DER_INT_LEN(KEYBYTES)], in[8]; size_t lsk, ln;
        der_int_enc(sk_start, sk_len, isk, &lsk);
        der_i_n256(in, &ln);
        const uint8_t *it[2] = {isk, in}; size_t il[2] = {lsk, ln};
        seq_and_write(it, il, 2, PEM_SESSION_KEY, out_path);
        fclose(urnd); return;
    }

    /* ── HKEX-RNL ─── */
    if (strcmp(algo, "hkex-rnl") == 0) {
        PemKey their;
        pem_key_load(&their, their_path);

        if (strcmp(their.label, PEM_HKEX_RNL_PUB) == 0) {
            /* ── Step 1: Bob responds to Alice's public key ── */
            PemKey our; pem_key_load(&our, our_path);
            if (our.n_items < 2)   die("kex rnl: malformed our private key");
            if (their.n_items < 2) die("kex rnl: malformed their public key");

            rnl_poly_t s_B, m_A, C_A, C_B, ms;
            poly_unpack(s_B, our.vals[0],   our.vlens[0],   4);
            poly_unpack(C_A, their.vals[0], their.vlens[0], 2);
            poly_unpack(m_A, their.vals[1], their.vlens[1], 4);
            pem_key_free(&our); pem_key_free(&their);

            /* Derive C_B = round_p(m_A * s_B) */
            rnl_poly_mul(ms, m_A, s_B);
            rnl_round(C_B, ms, RNL_Q, RNL_P);

            /* Compute K_B and hint via Peikert reconciliation */
            BitArray K_B;
            uint8_t hint[RNL_N / 8];
            rnl_agree(&K_B, s_B, C_A, NULL, hint);

            /* Encode RESPONSE: K_B, C_B_packed, hint, n, hint_len */
            uint8_t C_B_buf[RNL_N * 2];
            poly_pack(C_B_buf, C_B, 2);

            /* rnl_reconcile_bits packs bit i into b[i/8] bit(i%8) — LSB-first byte
             * order.  Python's BitArray is big-endian, so byte 0 = bits 248-255.
             * Reverse both K and hint bytes before DER encoding to match Python. */
            BitArray K_B_rev; int ri_k;
            for (ri_k = 0; ri_k < KEYBYTES; ri_k++)
                K_B_rev.b[ri_k] = K_B.b[KEYBYTES-1-ri_k];

            uint8_t hint_rev[RNL_N / 8];
            { int ri; for (ri = 0; ri < RNL_N/8; ri++) hint_rev[ri] = hint[RNL_N/8-1-ri]; }

            const uint8_t *kb_start; size_t kb_len;
            ba_min_bytes(&K_B_rev, &kb_start, &kb_len);

            uint8_t ik[DER_INT_LEN(KEYBYTES)];
            size_t ic_sz = DER_INT_LEN(sizeof C_B_buf);
            uint8_t *ic_der = malloc(ic_sz);
            uint8_t ih[DER_INT_LEN(RNL_N / 8)], in1[8], in2[8];
            size_t lk, lc, lh, ln1, ln2;
            if (!ic_der) die("out of memory");
            der_int_enc(kb_start,   kb_len,          ik,    &lk);
            der_int_enc(C_B_buf,   sizeof C_B_buf,  ic_der, &lc);
            der_int_enc(hint_rev,  sizeof hint_rev,  ih,    &lh);
            der_i_n256(in1, &ln1);
            der_i_n256(in2, &ln2);  /* len(hint) == n == 256 */
            const uint8_t *it[5] = {ik, ic_der, ih, in1, in2};
            size_t il[5] = {lk, lc, lh, ln1, ln2};
            seq_and_write(it, il, 5, PEM_RNL_RESPONSE, out_path);
            free(ic_der);

        } else if (strcmp(their.label, PEM_RNL_RESPONSE) == 0) {
            /* ── Step 2: Alice completes the handshake ── */
            PemKey our; pem_key_load(&our, our_path);
            if (our.n_items < 2)   die("kex rnl: malformed our private key");
            if (their.n_items < 5) die("kex rnl: malformed RNL response");

            rnl_poly_t s_A, C_B;
            poly_unpack(s_A, our.vals[0],   our.vlens[0],   4);
            poly_unpack(C_B, their.vals[1], their.vlens[1], 2);

            /* Unpack hint: DER is big-endian (Python: hint[31]=bits0-7 at LSB).
             * Right-align into hint_rev, then reverse to C byte order. */
            uint8_t hint[RNL_N / 8];
            { uint8_t hint_rev[RNL_N / 8]; int ri;
              memset(hint_rev, 0, sizeof hint_rev);
              size_t hl = their.vlens[2];
              if (hl > sizeof hint_rev) hl = sizeof hint_rev;
              memcpy(hint_rev + sizeof hint_rev - hl, their.vals[2], hl);
              for (ri = 0; ri < RNL_N/8; ri++) hint[ri] = hint_rev[RNL_N/8-1-ri]; }
            pem_key_free(&our); pem_key_free(&their);

            BitArray K_A;
            rnl_agree(&K_A, s_A, C_B, hint, NULL);

            /* rnl_agree output is LSB-first; reverse to big-endian for Python compat */
            BitArray K_A_rev; int ri_ka;
            for (ri_ka = 0; ri_ka < KEYBYTES; ri_ka++)
                K_A_rev.b[ri_ka] = K_A.b[KEYBYTES-1-ri_ka];
            const uint8_t *ka_start; size_t ka_len;
            ba_min_bytes(&K_A_rev, &ka_start, &ka_len);
            uint8_t ik[DER_INT_LEN(KEYBYTES)], in[8]; size_t lk, ln;
            der_int_enc(ka_start, ka_len, ik, &lk);
            der_i_n256(in, &ln);
            const uint8_t *it[2] = {ik, in}; size_t il[2] = {lk, ln};
            seq_and_write(it, il, 2, PEM_SESSION_KEY, out_path);

        } else {
            pem_key_free(&their);
            dief("kex hkex-rnl: --their must be RNL PUBLIC KEY or RESPONSE PEM (got %s)",
                 their.label);
        }
        fclose(urnd); return;
    }

    fclose(urnd);
    dief("kex: unsupported algorithm: %s", algo);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Usage
 * ───────────────────────────────────────────────────────────────────────────── */

static void usage(void)
{
    puts(
"Herradura Cryptographic Suite CLI v1.5.25\n"
"\n"
"Usage: herradura_cli <command> [options]\n"
"\n"
"Commands:\n"
"  genpkey --algo ALGO [--out FILE]\n"
"    Generate a private key.  Algorithms: hkex-gf hkex-rnl hpks hpks-nl\n"
"    hpke hpke-nl hpks-stern hpke-stern\n"
"\n"
"  pkey --in FILE (--pubout | --text) [--out FILE]\n"
"    Extract public key (--pubout) or print fields in hex (--text).\n"
"\n"
"  kex --algo ALGO --our PRIV --their PUB --out FILE\n"
"    Key exchange.  Algorithms: hkex-gf hkex-rnl\n"
"    HKEX-RNL is 2-round: Bob runs step 1 (--their=alice_pub.pem),\n"
"    Alice runs step 2 (--their=bob_resp.pem).\n"
"\n"
"PEM output goes to stdout when --out is absent or '-'.\n"
"All keys are 256-bit.\n"
    );
    exit(0);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * main
 * ───────────────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
        usage();

    const char *cmd = argv[1];
    if (strcmp(cmd, "genpkey") == 0) { cmd_genpkey(argc, argv); return 0; }
    if (strcmp(cmd, "pkey")    == 0) { cmd_pkey(argc, argv);    return 0; }
    if (strcmp(cmd, "kex")     == 0) { cmd_kex(argc, argv);     return 0; }

    dief("unknown command: %s", cmd);
    return 1;
}
