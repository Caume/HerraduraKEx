/* HerraduraCli/herradura_cli.c — OpenSSL-style CLI for the Herradura Cryptographic Suite
 *
 * Build: gcc -O2 -o HerraduraCli/herradura_cli HerraduraCli/herradura_cli.c
 *
 * Usage:
 *   herradura_cli genpkey --algo hkex-gf  --out alice.pem
 *   herradura_cli pkey    --in alice.pem --pubout --out alice_pub.pem
 *   herradura_cli pkey    --in alice.pem --text
 *   herradura_cli kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --out sk.pem
 *   herradura_cli kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --kdf hfscx-256 --out sk.pem
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

/* Read raw-binary PEM (no DER parse). Returns heap buffer; *olen = byte count. */
static uint8_t *zkp_raw_pem_read(const char *path, const char *expect_label, size_t *olen)
{
    size_t raw_len;
    uint8_t *raw = read_binary_file(path, &raw_len);
    char label[80] = {0};
    size_t cap = raw_len;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) die("out of memory");
    /* pem_read_file opens the file itself; raw is only for sizing */
    free(raw);
    if (pem_read_file(path, label, buf, &cap) != 0)
        dief("cannot parse PEM from: %s", path);
    if (expect_label && strcmp(label, expect_label) != 0) {
        free(buf);
        fprintf(stderr, "expected PEM label '%s', got '%s'\n", expect_label, label);
        exit(1);
    }
    *olen = cap;
    return buf;
}

/* Peek at a PEM label without DER-parsing the body. */
static void zkp_pem_peek_label(const char *path, char label_out[80])
{
    size_t dummy_len = 4096;
    uint8_t dummy[4096];
    memset(label_out, 0, 80);
    pem_read_file(path, label_out, dummy, &dummy_len);
}

/* Serialize ZkpNlRound[] to raw bytes (matches Python encode_zkp_nl_proof). */
static uint8_t *zkp_nl_pack_proof(const ZkpNlRound *proof, int rounds, int n, size_t *olen)
{
    size_t vl = proof[0].view_len;
    size_t per = 96 + 1 + 2 + vl + 2 + vl;
    size_t total = 8 + (size_t)rounds * per;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) die("out of memory");
    buf[0]=(uint8_t)(n>>24);      buf[1]=(uint8_t)(n>>16);
    buf[2]=(uint8_t)(n>>8);       buf[3]=(uint8_t)n;
    buf[4]=(uint8_t)(rounds>>24); buf[5]=(uint8_t)(rounds>>16);
    buf[6]=(uint8_t)(rounds>>8);  buf[7]=(uint8_t)rounds;
    uint8_t *p = buf + 8;
    int j;
    for (j = 0; j < rounds; j++) {
        memcpy(p, proof[j].com_0, 32); p += 32;
        memcpy(p, proof[j].com_1, 32); p += 32;
        memcpy(p, proof[j].com_2, 32); p += 32;
        *p++ = proof[j].e;
        *p++ = (uint8_t)(vl >> 8); *p++ = (uint8_t)vl;
        memcpy(p, proof[j].view_p1, vl); p += vl;
        *p++ = (uint8_t)(vl >> 8); *p++ = (uint8_t)vl;
        memcpy(p, proof[j].view_p2, vl); p += vl;
    }
    *olen = total;
    return buf;
}

/* Deserialize ZkpNlRound[] from raw bytes. */
static ZkpNlRound *zkp_nl_unpack_proof(const uint8_t *buf, size_t blen,
                                        int *n_out, int *rounds_out)
{
    if (blen < 8) die("ZKP-NL proof too short");
    int n = (int)(((uint32_t)buf[0]<<24)|((uint32_t)buf[1]<<16)|
                  ((uint32_t)buf[2]<<8)|buf[3]);
    int rounds = (int)(((uint32_t)buf[4]<<24)|((uint32_t)buf[5]<<16)|
                       ((uint32_t)buf[6]<<8)|buf[7]);
    if (n <= 0 || n > ZKP_NL_MAX_N)
        die("ZKP-NL proof: n out of range");
    if (rounds <= 0 || rounds > 4096)
        die("ZKP-NL proof: rounds out of range");
    *n_out = n; *rounds_out = rounds;
    ZkpNlRound *proof = (ZkpNlRound *)malloc((size_t)rounds * sizeof(ZkpNlRound));
    if (!proof) die("out of memory");
    const uint8_t *p = buf + 8;
    int j;
    for (j = 0; j < rounds; j++) {
        if (p + 97 + 4 > buf + blen) die("truncated ZKP-NL proof");
        memcpy(proof[j].com_0, p, 32); p += 32;
        memcpy(proof[j].com_1, p, 32); p += 32;
        memcpy(proof[j].com_2, p, 32); p += 32;
        proof[j].e = *p++;
        size_t l1 = ((size_t)p[0] << 8) | p[1]; p += 2;
        if (p + l1 > buf + blen) die("truncated ZKP-NL proof view");
        proof[j].view_p1  = (uint8_t *)malloc(l1);
        if (!proof[j].view_p1) die("out of memory");
        memcpy(proof[j].view_p1, p, l1); p += l1;
        proof[j].view_len = l1;
        size_t l2 = ((size_t)p[0] << 8) | p[1]; p += 2;
        if (p + l2 > buf + blen) die("truncated ZKP-NL proof view");
        proof[j].view_p2  = (uint8_t *)malloc(l2);
        if (!proof[j].view_p2) die("out of memory");
        memcpy(proof[j].view_p2, p, l2); p += l2;
    }
    return proof;
}

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

    /* ZKP-NL keypair: raw binary PEM (A, B, y, n) */
    if (strcmp(algo, "hpks-zkp-nl") == 0) {
        int nl_n = ZKP_NL_DEFAULT_N, nb = (nl_n+7)/8, k;
        uint64_t A, B, y;
        zkp_nl_keygen(nl_n, urnd, &A, &B, &y);
        size_t blen = 4 + (size_t)3*nb;
        uint8_t *body = (uint8_t *)malloc(blen);
        if (!body) die("out of memory");
        body[0]=(uint8_t)(nl_n>>24); body[1]=(uint8_t)(nl_n>>16);
        body[2]=(uint8_t)(nl_n>>8);  body[3]=(uint8_t)nl_n;
        for (k=0;k<nb;k++) body[4+k]       = (uint8_t)(A>>(8*(nb-1-k)));
        for (k=0;k<nb;k++) body[4+nb+k]    = (uint8_t)(B>>(8*(nb-1-k)));
        for (k=0;k<nb;k++) body[4+2*nb+k]  = (uint8_t)(y>>(8*(nb-1-k)));
        if (pem_write_file(out ? out : "-", PEM_ZKP_NL_PRIV, body, blen) != 0)
            die("cannot write ZKP-NL private key");
        free(body); fclose(urnd); return;
    }

    /* OPRF server key: SEQUENCE(INTEGER(k), INTEGER(256)) */
    if (strcmp(algo, "oprf") == 0) {
        BitArray k;
        oprf_keygen(&k, urnd);
        uint8_t ik[DER_INT_LEN(KEYBYTES)], in[8];
        size_t lk, ln;
        der_i32(k.b, ik, &lk);
        der_i_n256(in, &ln);
        const uint8_t *it[2] = {ik, in};
        size_t il[2] = {lk, ln};
        seq_and_write(it, il, 2, PEM_OPRF_PRIV, out);
        explicit_bzero(&k, sizeof(k));
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

    /* ZKP-NL keys use raw binary PEM — handle before DER-based path. */
    {
        char peek[80];
        zkp_pem_peek_label(in_path, peek);
        if (strcmp(peek, PEM_ZKP_NL_PRIV) == 0) {
            size_t blen;
            uint8_t *body = zkp_raw_pem_read(in_path, PEM_ZKP_NL_PRIV, &blen);
            if (blen < 4) die("pkey: malformed ZKP-NL private key");
            int nl_n = (int)(((uint32_t)body[0]<<24)|((uint32_t)body[1]<<16)|
                             ((uint32_t)body[2]<<8)|body[3]);
            int nb = (nl_n+7)/8;
            if ((int)blen < 4+3*nb) die("pkey: malformed ZKP-NL private key (short)");
            uint64_t A=0, B=0, y=0; int k;
            for (k=0;k<nb;k++) A=(A<<8)|body[4+k];
            for (k=0;k<nb;k++) B=(B<<8)|body[4+nb+k];
            for (k=0;k<nb;k++) y=(y<<8)|body[4+2*nb+k];
            free(body);
            if (text) {
                printf("%-10s: %s\n", "algorithm", "hpks-zkp-nl");
                printf("%-10s: %d\n", "n", nl_n);
                printf("%-10s: %0*lx\n", "A_private", 2*nb, (unsigned long)A);
                printf("%-10s: %0*lx\n", "B_public",  2*nb, (unsigned long)B);
                printf("%-10s: %0*lx\n", "y_public",  2*nb, (unsigned long)y);
            } else {
                size_t pub_len = 4 + (size_t)2*nb;
                uint8_t *pub = (uint8_t *)malloc(pub_len);
                if (!pub) die("out of memory");
                pub[0]=(uint8_t)(nl_n>>24); pub[1]=(uint8_t)(nl_n>>16);
                pub[2]=(uint8_t)(nl_n>>8);  pub[3]=(uint8_t)nl_n;
                for (k=0;k<nb;k++) pub[4+k]    = (uint8_t)(B>>(8*(nb-1-k)));
                for (k=0;k<nb;k++) pub[4+nb+k] = (uint8_t)(y>>(8*(nb-1-k)));
                if (pem_write_file(out_path ? out_path : "-", PEM_ZKP_NL_PUB, pub, pub_len) != 0)
                    die("cannot write ZKP-NL public key");
                free(pub);
            }
            return;
        }
    }

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
             * where syndrome bit i (= row i parity) occupies integer bit i.
             * syndr[k] holds rows k*8..k*8+7 as bits 0-7, so syndr[k] goes to
             * byte KEYBYTES-1-k (integer bits k*8..k*8+7) — matching Python/Go. */
            uint8_t syn32[KEYBYTES]; int _sk;
            memset(syn32, 0, KEYBYTES);
            for (_sk = 0; _sk < SDF_SYNBYTES; _sk++)
                syn32[KEYBYTES - 1 - _sk] = syndr[_sk];

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
    const char *algo       = get_arg(argc, argv, "--algo");
    const char *our_path   = get_arg(argc, argv, "--our");
    const char *their_path = get_arg(argc, argv, "--their");
    const char *out_path   = get_arg(argc, argv, "--out");
    const char *kdf        = get_arg(argc, argv, "--kdf");
    if (!algo || !our_path || !their_path || !out_path)
        die("kex: --algo, --our, --their, --out required");
    if (kdf && strcmp(kdf, "hfscx-256") != 0)
        dief("kex: unsupported --kdf value: %s", kdf);

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

        /* Apply KDF if requested: sk = HFSCX-256(sk) */
        if (kdf) {
            uint8_t kdf_out[32];
            hfscx_256(sk.b, KEYBYTES, NULL, kdf_out);
            memcpy(sk.b, kdf_out, 32);
            explicit_bzero(kdf_out, sizeof(kdf_out));
        }

        const uint8_t *sk_start; size_t sk_len;
        ba_min_bytes(&sk, &sk_start, &sk_len);
        uint8_t isk[DER_INT_LEN(KEYBYTES)], in[8]; size_t lsk, ln;
        der_int_enc(sk_start, sk_len, isk, &lsk);
        der_i_n256(in, &ln);
        const uint8_t *it[2] = {isk, in}; size_t il[2] = {lsk, ln};
        seq_and_write(it, il, 2, PEM_SESSION_KEY, out_path);
        explicit_bzero(&sk, sizeof(sk));
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

            if (!rnl_validate_m_blind(m_A, RNL_N))
                die("kex hkex-rnl: peer m_blind failed entropy check — possible substitution attack");

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

            /* Apply KDF if requested: K_B_rev = HFSCX-256(K_B_rev) */
            if (kdf) {
                uint8_t kdf_out[32];
                hfscx_256(K_B_rev.b, KEYBYTES, NULL, kdf_out);
                memcpy(K_B_rev.b, kdf_out, 32);
                explicit_bzero(kdf_out, sizeof(kdf_out));
            }

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

            /* Apply KDF if requested: K_A_rev = HFSCX-256(K_A_rev) */
            if (kdf) {
                uint8_t kdf_out[32];
                hfscx_256(K_A_rev.b, KEYBYTES, NULL, kdf_out);
                memcpy(K_A_rev.b, kdf_out, 32);
                explicit_bzero(kdf_out, sizeof(kdf_out));
            }

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
 * Batch 5 helpers
 * ───────────────────────────────────────────────────────────────────────────── */

/* Write raw bytes to file or stdout. */
static void write_binary_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = (!path || strcmp(path, "-") == 0) ? stdout : fopen(path, "wb");
    if (!f) dief("cannot write: %s", path);
    fwrite(buf, 1, len, f);
    if (f != stdout) fclose(f);
}

/* Load session key (SESSION KEY or RNL RESPONSE, first field) into K. */
static void load_sym_key(BitArray *K, const char *path)
{
    PemKey sk;
    pem_key_load(&sk, path);
    if (sk.n_items < 1) die("key: malformed session key PEM");
    ba_from_ra(K, sk.vals[0], sk.vlens[0]);
    pem_key_free(&sk);
}

/* DER INTEGER for a 1-byte value (format tags 0, 1, rounds=32, etc.). */
static int der_i_byte(uint8_t v, uint8_t *out, size_t *olen)
{ return der_int_enc(&v, 1, out, olen); }

/* Build msg BitArray: first KEYBYTES of data, zero-padded on the right. */
static void make_msg_ba(BitArray *msg, const uint8_t *data, size_t len)
{
    memset(msg->b, 0, KEYBYTES);
    size_t cp = len < KEYBYTES ? len : KEYBYTES;
    memcpy(msg->b, data, cp);
}

/* ─── Stern signature pack / unpack ─── */

#define STERN_COMMITS_BYTES (3 * SDF_ROUNDS * KEYBYTES)   /* 3072 */
#define STERN_CHAL_BYTES    ((SDF_ROUNDS + 3) / 4)        /* 8   */
#define STERN_RESP_BYTES    (2 * SDF_ROUNDS * KEYBYTES)   /* 2048 */

static void stern_sig_pack_and_write(const SternSig *sig, const char *out_path)
{
    uint8_t *commits = malloc(STERN_COMMITS_BYTES);
    uint8_t chal[STERN_CHAL_BYTES];
    uint8_t *resp    = malloc(STERN_RESP_BYTES);
    if (!commits || !resp) die("out of memory");

    /* Commits: c0, c1, c2 per round (each KEYBYTES bytes, big-endian). */
    { int i;
      for (i = 0; i < SDF_ROUNDS; i++) {
          int off = i * 3 * KEYBYTES;
          memcpy(commits + off,              sig->c0[i].b, KEYBYTES);
          memcpy(commits + off + KEYBYTES,   sig->c1[i].b, KEYBYTES);
          memcpy(commits + off + 2*KEYBYTES, sig->c2[i].b, KEYBYTES);
      }
    }
    /* Challenges: 2 bits per round, packed LSB-first within each byte. */
    { int i;
      memset(chal, 0, STERN_CHAL_BYTES);
      for (i = 0; i < SDF_ROUNDS; i++)
          chal[i / 4] |= (uint8_t)((sig->b[i] & 3) << ((i % 4) * 2));
    }
    /* Responses: resp_a then resp_b per round (each KEYBYTES). */
    { int i;
      for (i = 0; i < SDF_ROUNDS; i++) {
          int off = i * 2 * KEYBYTES;
          memcpy(resp + off,          sig->resp_a[i].b, KEYBYTES);
          memcpy(resp + off + KEYBYTES, sig->resp_b[i].b, KEYBYTES);
      }
    }

    /* DER-encode each blob. */
    uint8_t in_der[8], ir_der[8];
    size_t ln, lr;
    size_t ic_sz = DER_INT_LEN(STERN_COMMITS_BYTES);
    size_t ich_sz = DER_INT_LEN(STERN_CHAL_BYTES);
    size_t irs_sz = DER_INT_LEN(STERN_RESP_BYTES);
    uint8_t *ic_der  = malloc(ic_sz);
    uint8_t *ich_der = malloc(ich_sz);
    uint8_t *irs_der = malloc(irs_sz);
    if (!ic_der || !ich_der || !irs_der) die("out of memory");
    size_t lc, lch, lrs;
    der_i_n256(in_der, &ln);
    der_i_byte(SDF_ROUNDS, ir_der, &lr);
    der_int_enc(commits, STERN_COMMITS_BYTES, ic_der,  &lc);
    der_int_enc(chal,    STERN_CHAL_BYTES,    ich_der, &lch);
    der_int_enc(resp,    STERN_RESP_BYTES,    irs_der, &lrs);

    const uint8_t *it[5] = {in_der, ir_der, ic_der, ich_der, irs_der};
    size_t         il[5] = {ln,     lr,     lc,     lch,     lrs};
    seq_and_write(it, il, 5, PEM_SIGNATURE, out_path);

    free(commits); free(resp); free(ic_der); free(ich_der); free(irs_der);
}

static int stern_sig_load(const char *path, SternSig *sig)
{
    PemKey pk;
    pem_key_load(&pk, path);
    if (strcmp(pk.label, PEM_SIGNATURE) != 0 || pk.n_items != 5)
        { pem_key_free(&pk); return -1; }

    /* Verify rounds. */
    { int i, r = 0;
      for (i = 0; i < (int)pk.vlens[1]; i++) r = (r << 8) | pk.vals[1][i];
      if (r != SDF_ROUNDS) { pem_key_free(&pk); return -1; }
    }

    /* Right-align each big-endian blob. */
    uint8_t *commits = malloc(STERN_COMMITS_BYTES);
    uint8_t chal[STERN_CHAL_BYTES];
    uint8_t *resp    = malloc(STERN_RESP_BYTES);
    if (!commits || !resp) die("out of memory");

#define RA_BUF(dst, dlen, vp, vl) do { \
    size_t _l = (vl) < (dlen) ? (vl) : (dlen); \
    memset(dst, 0, dlen); \
    memcpy((uint8_t *)(dst) + (dlen) - _l, vp, _l); \
} while (0)

    RA_BUF(commits, STERN_COMMITS_BYTES, pk.vals[2], pk.vlens[2]);
    RA_BUF(chal,    STERN_CHAL_BYTES,    pk.vals[3], pk.vlens[3]);
    RA_BUF(resp,    STERN_RESP_BYTES,    pk.vals[4], pk.vlens[4]);
#undef RA_BUF

    /* Unpack commits. */
    { int i;
      for (i = 0; i < SDF_ROUNDS; i++) {
          int off = i * 3 * KEYBYTES;
          memcpy(sig->c0[i].b, commits + off,              KEYBYTES);
          memcpy(sig->c1[i].b, commits + off + KEYBYTES,   KEYBYTES);
          memcpy(sig->c2[i].b, commits + off + 2*KEYBYTES, KEYBYTES);
      }
    }
    /* Unpack challenges. */
    { int i;
      for (i = 0; i < SDF_ROUNDS; i++)
          sig->b[i] = (chal[i / 4] >> ((i % 4) * 2)) & 3;
    }
    /* Unpack responses. */
    { int i;
      for (i = 0; i < SDF_ROUNDS; i++) {
          int off = i * 2 * KEYBYTES;
          memcpy(sig->resp_a[i].b, resp + off,            KEYBYTES);
          memcpy(sig->resp_b[i].b, resp + off + KEYBYTES, KEYBYTES);
      }
    }

    free(commits); free(resp);
    pem_key_free(&pk);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * dgst
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_dgst(int argc, char **argv)
{
    const char *algo     = get_arg(argc, argv, "--algo");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!algo) algo = "hfscx-256";
    if (!in_path) die("dgst: --in required");

    if (strcmp(algo, "hfscx-256") != 0)
        dief("dgst: unsupported algorithm: %s", algo);

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);
    uint8_t digest[32];
    hfscx_256(in_buf, in_len, NULL, digest);
    free(in_buf);

    if (!out_path || strcmp(out_path, "-") == 0) {
        /* Hex to stdout. */
        size_t i;
        for (i = 0; i < 32; i++) printf("%02x", digest[i]);
        putchar('\n');
    } else {
        /* HERRADURA DIGEST PEM (SEQUENCE containing single 32-byte INTEGER). */
        uint8_t id[DER_INT_LEN(32)]; size_t ld;
        der_int_enc(digest, 32, id, &ld);
        const uint8_t *it[1] = {id}; size_t il[1] = {ld};
        seq_and_write(it, il, 1, PEM_DIGEST, out_path);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * enc
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_enc(int argc, char **argv)
{
    const char *algo       = get_arg(argc, argv, "--algo");
    const char *key_path   = get_arg(argc, argv, "--key");
    const char *pubkey_path = get_arg(argc, argv, "--pubkey");
    const char *in_path    = get_arg(argc, argv, "--in");
    const char *out_path   = get_arg(argc, argv, "--out");
    if (!algo)    die("enc: --algo required");
    if (!in_path) die("enc: --in required");

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);

    /* Plaintext BitArray: input left-aligned into big-endian block, zero-padded. */
    BitArray P;
    make_msg_ba(&P, in_buf, in_len);
    free(in_buf);

    /* ── Symmetric algos ── */
    if (strcmp(algo, "hske") == 0 || strcmp(algo, "hske-nla1") == 0 ||
        strcmp(algo, "hske-nla2") == 0) {
        if (!key_path) dief("enc: --key required for %s", algo);
        BitArray K;
        load_sym_key(&K, key_path);

        if (strcmp(algo, "hske") == 0) {
            BitArray E;
            ba_fscx_revolve(&E, &P, &K, I_VALUE);
            uint8_t it0[8], itE[DER_INT_LEN(KEYBYTES)], itn[8];
            size_t l0, lE, ln;
            der_i_byte(0, it0, &l0); der_i32(E.b, itE, &lE); der_i_n256(itn, &ln);
            const uint8_t *it[3] = {it0, itE, itn}; size_t il[3] = {l0, lE, ln};
            seq_and_write(it, il, 3, PEM_CIPHERTEXT, out_path);

        } else if (strcmp(algo, "hske-nla1") == 0) {
            int aead = has_flag(argc, argv, "--aead");
            const char *ad = get_arg(argc, argv, "--ad");
            FILE *urnd = fopen("/dev/urandom", "rb");
            if (!urnd) die("cannot open /dev/urandom");
            BitArray N_nonce;
            ba_rand(&N_nonce, urnd);
            fclose(urnd);
            if (ad && !aead) die("enc: --ad requires --aead");

            if (aead) {
                /* AEAD format tag 2: SEQ(2, nonce, E, tag, nbits) — TODO #95 */
                uint8_t ct_buf[KEYBYTES], tag[32];
                hske_nl_aead_encrypt(&K, &N_nonce,
                                     (const uint8_t *)(ad ? ad : ""),
                                     ad ? strlen(ad) : 0,
                                     P.b, KEYBYTES, ct_buf, tag);
                uint8_t it0[8], itn[DER_INT_LEN(KEYBYTES)], itE[DER_INT_LEN(KEYBYTES)];
                uint8_t itt[DER_INT_LEN(KEYBYTES)], itnb[8];
                size_t l0, ln, lE, lt, lnb;
                der_i_byte(2, it0, &l0);
                der_i32(N_nonce.b, itn, &ln);
                der_i32(ct_buf, itE, &lE);
                der_i32(tag, itt, &lt);
                der_i_n256(itnb, &lnb);
                const uint8_t *it[5] = {it0, itn, itE, itt, itnb};
                size_t il[5] = {l0, ln, lE, lt, lnb};
                seq_and_write(it, il, 5, PEM_CIPHERTEXT, out_path);
                return;
            }

            BitArray base, seed, ks, E;
            ba_xor(&base, &K, &N_nonce);
            ba_rnl_kdf_seed(&seed, &base);
            nl_fscx_revolve_v1_ba(&ks, &seed, &base, I_VALUE);
            ba_xor(&E, &P, &ks);
            uint8_t it0[8], itn[DER_INT_LEN(KEYBYTES)], itE[DER_INT_LEN(KEYBYTES)], itnb[8];
            size_t l0, ln, lE, lnb;
            der_i_byte(1, it0, &l0);
            der_i32(N_nonce.b, itn, &ln);
            der_i32(E.b, itE, &lE);
            der_i_n256(itnb, &lnb);
            const uint8_t *it[4] = {it0, itn, itE, itnb};
            size_t il[4] = {l0, ln, lE, lnb};
            seq_and_write(it, il, 4, PEM_CIPHERTEXT, out_path);

        } else { /* hske-nla2 */
            BitArray E;
            nl_fscx_revolve_v2_ba(&E, &P, &K, R_VALUE);
            uint8_t it0[8], itE[DER_INT_LEN(KEYBYTES)], itn[8];
            size_t l0, lE, ln;
            der_i_byte(0, it0, &l0); der_i32(E.b, itE, &lE); der_i_n256(itn, &ln);
            const uint8_t *it[3] = {it0, itE, itn}; size_t il[3] = {l0, lE, ln};
            seq_and_write(it, il, 3, PEM_CIPHERTEXT, out_path);
        }
        return;
    }

    /* ── Asymmetric algos ── */
    if (!pubkey_path) dief("enc: --pubkey required for %s", algo);
    PemKey pub_k;
    pem_key_load(&pub_k, pubkey_path);

    if (strcmp(algo, "hpke") == 0 || strcmp(algo, "hpke-nl") == 0) {
        /* vals[0]=pub (32 bytes), vals[1]=n */
        if (pub_k.n_items < 1) die("enc: malformed public key");
        BitArray pub, r, R, enc_key, E;
        ba_from_ra(&pub, pub_k.vals[0], pub_k.vlens[0]);
        pem_key_free(&pub_k);

        FILE *urnd = fopen("/dev/urandom", "rb");
        if (!urnd) die("cannot open /dev/urandom");
        ba_rand(&r, urnd); fclose(urnd);
        gf_pow_ba(&R, &GF_GEN, &r);
        gf_pow_ba(&enc_key, &pub, &r);
        if (strcmp(algo, "hpke") == 0)
            ba_fscx_revolve(&E, &P, &enc_key, I_VALUE);
        else
            nl_fscx_revolve_v2_ba(&E, &P, &enc_key, I_VALUE);
        uint8_t iR[DER_INT_LEN(KEYBYTES)], iE[DER_INT_LEN(KEYBYTES)], in[8];
        size_t lR, lE, ln;
        der_i32(R.b, iR, &lR); der_i32(E.b, iE, &lE); der_i_n256(in, &ln);
        const uint8_t *it[3] = {iR, iE, in}; size_t il[3] = {lR, lE, ln};
        seq_and_write(it, il, 3, PEM_CIPHERTEXT, out_path);

    } else if (strcmp(algo, "hpke-stern") == 0) {
        /* vals[0]=syn32 (32 bytes), vals[1]=seed (32 bytes), vals[2]=n */
        if (pub_k.n_items < 2) die("enc: malformed Stern public key");
        BitArray seed_ba, K_ba, e_p, E;
        ba_from_ra(&seed_ba, pub_k.vals[1], pub_k.vlens[1]);
        pem_key_free(&pub_k);

        FILE *urnd = fopen("/dev/urandom", "rb");
        if (!urnd) die("cannot open /dev/urandom");
        uint8_t ct_syndr[SDF_SYNBYTES];
        hpke_stern_f_encap(&K_ba, ct_syndr, &e_p, &seed_ba, urnd);
        fclose(urnd);
        ba_fscx_revolve(&E, &P, &K_ba, I_VALUE);

        /* Syndrome: zero-pad SDF_SYNBYTES → KEYBYTES. */
        uint8_t ct32[KEYBYTES];
        memset(ct32, 0, KEYBYTES);
        memcpy(ct32 + KEYBYTES - SDF_SYNBYTES, ct_syndr, SDF_SYNBYTES);

        uint8_t ict[DER_INT_LEN(KEYBYTES)], iep[DER_INT_LEN(KEYBYTES)];
        uint8_t ik[DER_INT_LEN(KEYBYTES)],  iE[DER_INT_LEN(KEYBYTES)], in[8];
        size_t lct, lep, lk, lE, ln;
        der_i32(ct32,   ict, &lct); der_i32(e_p.b, iep, &lep);
        der_i32(K_ba.b, ik,  &lk);  der_i32(E.b,   iE,  &lE); der_i_n256(in, &ln);
        const uint8_t *it[5] = {ict, iep, ik, iE, in};
        size_t         il[5] = {lct, lep, lk, lE, ln};
        seq_and_write(it, il, 5, PEM_CIPHERTEXT, out_path);

    } else {
        pem_key_free(&pub_k);
        dief("enc: unsupported algorithm: %s", algo);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * dec
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_dec(int argc, char **argv)
{
    const char *algo     = get_arg(argc, argv, "--algo");
    const char *key_path = get_arg(argc, argv, "--key");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!algo)    die("dec: --algo required");
    if (!in_path) die("dec: --in required");

    /* Load ciphertext PEM. */
    PemKey ct;
    pem_key_load(&ct, in_path);
    if (strcmp(ct.label, PEM_CIPHERTEXT) != 0)
        dief("dec: expected CIPHERTEXT PEM, got: %s", ct.label);

    /* ── Symmetric algos ── */
    if (strcmp(algo, "hske") == 0 || strcmp(algo, "hske-nla1") == 0 ||
        strcmp(algo, "hske-nla2") == 0) {
        if (!key_path) dief("dec: --key required for %s", algo);
        BitArray K;
        load_sym_key(&K, key_path);

        /* fmt_tag is vals[0][0]; E follows; for nla1 nonce is between them. */
        int fmt = (ct.vlens[0] >= 1) ? ct.vals[0][0] : 0;
        BitArray E, D;

        if (strcmp(algo, "hske-nla1") == 0) {
            if (fmt == 2) {
                /* AEAD format tag 2: SEQ(2, nonce, E, tag, nbits) — TODO #95 */
                const char *ad = get_arg(argc, argv, "--ad");
                BitArray N_nonce, E_ba, tag_ba;
                if (ct.n_items < 5) die("dec: bad hske-nla1 AEAD ciphertext");
                ba_from_ra(&N_nonce, ct.vals[1], ct.vlens[1]);
                ba_from_ra(&E_ba,    ct.vals[2], ct.vlens[2]);
                ba_from_ra(&tag_ba,  ct.vals[3], ct.vlens[3]);
                pem_key_free(&ct);
                if (!hske_nl_aead_decrypt(&K, &N_nonce,
                                          (const uint8_t *)(ad ? ad : ""),
                                          ad ? strlen(ad) : 0,
                                          E_ba.b, KEYBYTES, tag_ba.b, D.b))
                    die("dec: authentication tag mismatch — "
                        "ciphertext corrupt, wrong key, or wrong --ad");
                write_binary_file(out_path, D.b, KEYBYTES);
                return;
            }
            if (fmt != 1 || ct.n_items < 4) die("dec: bad hske-nla1 ciphertext");
            BitArray N_nonce, base, seed, ks;
            ba_from_ra(&N_nonce, ct.vals[1], ct.vlens[1]);
            ba_from_ra(&E,       ct.vals[2], ct.vlens[2]);
            pem_key_free(&ct);
            ba_xor(&base, &K, &N_nonce);
            ba_rnl_kdf_seed(&seed, &base);
            nl_fscx_revolve_v1_ba(&ks, &seed, &base, I_VALUE);
            ba_xor(&D, &E, &ks);
        } else {
            if (ct.n_items < 3) die("dec: bad symmetric ciphertext");
            ba_from_ra(&E, ct.vals[1], ct.vlens[1]);
            pem_key_free(&ct);
            if (strcmp(algo, "hske") == 0)
                ba_fscx_revolve(&D, &E, &K, R_VALUE);
            else
                nl_fscx_revolve_v2_inv_ba(&D, &E, &K, R_VALUE);
        }
        write_binary_file(out_path, D.b, KEYBYTES);
        return;
    }

    /* ── Asymmetric algos ── */
    if (!key_path) dief("dec: --key required for %s", algo);
    PemKey priv_k;
    pem_key_load(&priv_k, key_path);

    if (strcmp(algo, "hpke") == 0 || strcmp(algo, "hpke-nl") == 0) {
        /* CT: vals[0]=R, vals[1]=E, vals[2]=nbits (no format tag) */
        if (ct.n_items < 2) die("dec: malformed HPKE ciphertext");
        if (priv_k.n_items < 1) die("dec: malformed private key");
        BitArray priv, R, E, dec_key, D;
        ba_from_ra(&priv, priv_k.vals[0], priv_k.vlens[0]);
        ba_from_ra(&R,    ct.vals[0],     ct.vlens[0]);
        ba_from_ra(&E,    ct.vals[1],     ct.vlens[1]);
        pem_key_free(&ct); pem_key_free(&priv_k);
        gf_pow_ba(&dec_key, &R, &priv);
        if (strcmp(algo, "hpke") == 0)
            ba_fscx_revolve(&D, &E, &dec_key, R_VALUE);
        else
            nl_fscx_revolve_v2_inv_ba(&D, &E, &dec_key, I_VALUE);
        write_binary_file(out_path, D.b, KEYBYTES);

    } else if (strcmp(algo, "hpke-stern") == 0) {
        /* CT: vals[0]=ct_syn, vals[1]=e_p, vals[2]=K_int, vals[3]=E_int */
        if (ct.n_items < 4) die("dec: malformed HPKE-Stern ciphertext");
        if (priv_k.n_items < 2) die("dec: malformed Stern private key");
        BitArray e_p_ba, E_ba, seed_ba, K_dec, D;
        ba_from_ra(&e_p_ba,  ct.vals[1],       ct.vlens[1]);
        ba_from_ra(&E_ba,    ct.vals[3],       ct.vlens[3]);
        ba_from_ra(&seed_ba, priv_k.vals[1],   priv_k.vlens[1]);
        pem_key_free(&ct); pem_key_free(&priv_k);
        hpke_stern_f_decap_known(&K_dec, &e_p_ba, &seed_ba);
        ba_fscx_revolve(&D, &E_ba, &K_dec, R_VALUE);
        write_binary_file(out_path, D.b, KEYBYTES);

    } else {
        pem_key_free(&ct); pem_key_free(&priv_k);
        dief("dec: unsupported algorithm: %s", algo);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * sign
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_sign(int argc, char **argv)
{
    const char *algo     = get_arg(argc, argv, "--algo");
    const char *key_path = get_arg(argc, argv, "--key");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    const char *digest   = get_arg(argc, argv, "--digest");
    if (!algo)     die("sign: --algo required");
    if (!key_path) die("sign: --key required");
    if (!in_path)  die("sign: --in required");

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);
    uint8_t msg_bytes[KEYBYTES];

    if (digest && strcmp(digest, "hfscx-256") == 0) {
        /* Pre-hash: sign the 32-byte digest. */
        hfscx_256(in_buf, in_len, NULL, msg_bytes);
        in_len = KEYBYTES;
    } else {
        memset(msg_bytes, 0, KEYBYTES);
        size_t cp = in_len < KEYBYTES ? in_len : KEYBYTES;
        memcpy(msg_bytes, in_buf, cp);
        in_len = KEYBYTES;
    }
    free(in_buf);

    BitArray msg;
    memcpy(msg.b, msg_bytes, KEYBYTES);

    /* nl-zkboo uses raw binary PEM — handle before pem_key_load. */
    if (strcmp(algo, "nl-zkboo") == 0) {
        FILE *urnd2 = fopen("/dev/urandom", "rb");
        if (!urnd2) die("cannot open /dev/urandom");
        size_t kblen;
        uint8_t *kbody = zkp_raw_pem_read(key_path, PEM_ZKP_NL_PRIV, &kblen);
        if (kblen < 4) die("sign: malformed ZKP-NL private key");
        int nl_n = (int)(((uint32_t)kbody[0]<<24)|((uint32_t)kbody[1]<<16)|
                         ((uint32_t)kbody[2]<<8)|kbody[3]);
        int nb = (nl_n+7)/8;
        if ((int)kblen < 4+3*nb) die("sign: malformed ZKP-NL private key (short)");
        uint64_t zkA=0, zkB=0, zky=0; int ki;
        for (ki=0;ki<nb;ki++) zkA=(zkA<<8)|kbody[4+ki];
        for (ki=0;ki<nb;ki++) zkB=(zkB<<8)|kbody[4+nb+ki];
        for (ki=0;ki<nb;ki++) zky=(zky<<8)|kbody[4+2*nb+ki];
        free(kbody);
        ZkpNlRound *zk_proof = zkp_nl_prove(zkA, zkB, zky, nl_n, ZKP_NL_PROD_ROUNDS,
                                             msg_bytes, KEYBYTES, urnd2);
        fclose(urnd2);
        size_t pack_len;
        uint8_t *pack = zkp_nl_pack_proof(zk_proof, ZKP_NL_PROD_ROUNDS, nl_n, &pack_len);
        zkp_nl_proof_free(zk_proof, ZKP_NL_PROD_ROUNDS);
        if (pem_write_file(out_path ? out_path : "-", PEM_ZKP_NL_PROOF, pack, pack_len) != 0)
            die("cannot write ZKP-NL proof");
        free(pack);
        return;
    }

    PemKey priv_k;
    pem_key_load(&priv_k, key_path);

    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    if (strcmp(algo, "hpks") == 0 || strcmp(algo, "hpks-nl") == 0) {
        if (priv_k.n_items < 1) die("sign: malformed private key");
        BitArray priv, k_rand, R, e, me, s_ba;
        ba_from_ra(&priv, priv_k.vals[0], priv_k.vlens[0]);
        pem_key_free(&priv_k);

        ba_rand(&k_rand, urnd);
        gf_pow_ba(&R, &GF_GEN, &k_rand);
        if (strcmp(algo, "hpks") == 0)
            ba_fscx_revolve(&e, &R, &msg, I_VALUE);
        else
            nl_fscx_revolve_v1_ba(&e, &R, &msg, I_VALUE);
        /* s = (k - priv * e) mod (2^256-1) */
        ba_mul_mod_ord(&me, &priv, &e);
        ba_sub_mod_ord(&s_ba, &k_rand, &me);

        uint8_t is[DER_INT_LEN(KEYBYTES)], iR[DER_INT_LEN(KEYBYTES)];
        uint8_t ie[DER_INT_LEN(KEYBYTES)], in[8];
        size_t ls, lR, le, ln;
        der_i32(s_ba.b, is, &ls); der_i32(R.b, iR, &lR);
        der_i32(e.b,    ie, &le); der_i_n256(in, &ln);
        const uint8_t *it[4] = {is, iR, ie, in}; size_t il[4] = {ls, lR, le, ln};
        seq_and_write(it, il, 4, PEM_SIGNATURE, out_path);

    } else if (strcmp(algo, "hpks-stern") == 0) {
        if (priv_k.n_items < 2) die("sign: malformed Stern private key");
        BitArray e_ba, seed_ba;
        ba_from_ra(&e_ba,    priv_k.vals[0], priv_k.vlens[0]);
        ba_from_ra(&seed_ba, priv_k.vals[1], priv_k.vlens[1]);
        pem_key_free(&priv_k);

        SternSig sig;
        hpks_stern_f_sign(&sig, &msg, &e_ba, &seed_ba, urnd);
        stern_sig_pack_and_write(&sig, out_path);

    } else if (strcmp(algo, "rnl-sigma") == 0) {
        /* ZKP-RNL: uses hkex-rnl private key, n must equal RNL_N */
        if (priv_k.n_items < 3) die("sign: malformed hkex-rnl private key");
        int sig_n = pem_key_get_n(&priv_k, 2);
        if (sig_n != RNL_N) die("sign: rnl-sigma requires n=256 key");
        rnl_poly_t sig_s, sig_m, sig_ms, sig_Cp;
        poly_unpack(sig_s, priv_k.vals[0], priv_k.vlens[0], 4);
        poly_unpack(sig_m, priv_k.vals[1], priv_k.vlens[1], 4);
        pem_key_free(&priv_k);
        rnl_poly_mul(sig_ms, sig_m, sig_s);
        rnl_round(sig_Cp, sig_ms, RNL_Q, RNL_P);

        rnl_poly_t sig_w, sig_c, sig_z;
        int r = rnl_sigma_sign(sig_s, sig_m, sig_Cp, RNL_N,
                               msg.b, KEYBYTES, urnd, sig_w, sig_c, sig_z);
        if (r != 0) die("sign: rnl-sigma rejection limit reached");

        /* Write raw binary proof: 4B n | n×4B w | n×4B c | n×4B z */
        size_t proof_len = 4 + (size_t)RNL_N * 12;
        uint8_t *pbuf = (uint8_t *)malloc(proof_len);
        if (!pbuf) die("out of memory");
        pbuf[0]=(uint8_t)(RNL_N>>24); pbuf[1]=(uint8_t)(RNL_N>>16);
        pbuf[2]=(uint8_t)(RNL_N>>8);  pbuf[3]=(uint8_t)RNL_N;
        int pi;
        for (pi=0;pi<RNL_N;pi++) {
            uint32_t v;
            v=(uint32_t)sig_w[pi];
            pbuf[4+pi*4+0]=v>>24; pbuf[4+pi*4+1]=v>>16; pbuf[4+pi*4+2]=v>>8; pbuf[4+pi*4+3]=v;
            v=(uint32_t)sig_c[pi];
            pbuf[4+RNL_N*4+pi*4+0]=v>>24; pbuf[4+RNL_N*4+pi*4+1]=v>>16;
            pbuf[4+RNL_N*4+pi*4+2]=v>>8;  pbuf[4+RNL_N*4+pi*4+3]=v;
            v=(uint32_t)sig_z[pi];
            pbuf[4+RNL_N*8+pi*4+0]=v>>24; pbuf[4+RNL_N*8+pi*4+1]=v>>16;
            pbuf[4+RNL_N*8+pi*4+2]=v>>8;  pbuf[4+RNL_N*8+pi*4+3]=v;
        }
        if (pem_write_file(out_path ? out_path : "-", PEM_ZKP_RNL_PROOF, pbuf, proof_len) != 0)
            die("cannot write ZKP-RNL proof");
        free(pbuf);

    } else {
        pem_key_free(&priv_k);
        fclose(urnd);
        dief("sign: unsupported algorithm: %s", algo);
    }

    fclose(urnd);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * verify
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_verify(int argc, char **argv)
{
    const char *algo        = get_arg(argc, argv, "--algo");
    const char *pubkey_path = get_arg(argc, argv, "--pubkey");
    const char *in_path     = get_arg(argc, argv, "--in");
    const char *sig_path    = get_arg(argc, argv, "--sig");
    const char *digest      = get_arg(argc, argv, "--digest");
    if (!algo)        die("verify: --algo required");
    if (!pubkey_path) die("verify: --pubkey required");
    if (!in_path)     die("verify: --in required");
    if (!sig_path)    die("verify: --sig required");

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);
    uint8_t msg_bytes[KEYBYTES];

    if (digest && strcmp(digest, "hfscx-256") == 0) {
        hfscx_256(in_buf, in_len, NULL, msg_bytes);
    } else {
        memset(msg_bytes, 0, KEYBYTES);
        size_t cp = in_len < KEYBYTES ? in_len : KEYBYTES;
        memcpy(msg_bytes, in_buf, cp);
    }
    free(in_buf);

    BitArray msg;
    memcpy(msg.b, msg_bytes, KEYBYTES);

    /* nl-zkboo uses raw binary PEM — handle before pem_key_load. */
    if (strcmp(algo, "nl-zkboo") == 0) {
        size_t pkblen;
        uint8_t *pkbody = zkp_raw_pem_read(pubkey_path, PEM_ZKP_NL_PUB, &pkblen);
        if (pkblen < 4) die("verify: malformed ZKP-NL public key");
        int nl_n = (int)(((uint32_t)pkbody[0]<<24)|((uint32_t)pkbody[1]<<16)|
                         ((uint32_t)pkbody[2]<<8)|pkbody[3]);
        int nb = (nl_n+7)/8;
        if ((int)pkblen < 4+2*nb) die("verify: malformed ZKP-NL public key (short)");
        uint64_t zkB=0, zky=0; int ki;
        for (ki=0;ki<nb;ki++) zkB=(zkB<<8)|pkbody[4+ki];
        for (ki=0;ki<nb;ki++) zky=(zky<<8)|pkbody[4+nb+ki];
        free(pkbody);
        size_t prflen;
        uint8_t *prfbuf = zkp_raw_pem_read(sig_path, PEM_ZKP_NL_PROOF, &prflen);
        int prf_n, prf_rounds;
        ZkpNlRound *zk_proof = zkp_nl_unpack_proof(prfbuf, prflen, &prf_n, &prf_rounds);
        free(prfbuf);
        if (prf_n != nl_n) die("verify: proof n mismatch with pubkey n");
        int ok = zkp_nl_verify(zkB, zky, nl_n, prf_rounds, msg.b, KEYBYTES, zk_proof);
        zkp_nl_proof_free(zk_proof, prf_rounds);
        if (ok) { puts("Signature OK");         exit(0); }
        else    { puts("Verification FAILED");  exit(1); }
    }

    PemKey pub_k;
    pem_key_load(&pub_k, pubkey_path);

    if (strcmp(algo, "hpks") == 0 || strcmp(algo, "hpks-nl") == 0) {
        if (pub_k.n_items < 1) die("verify: malformed public key");
        BitArray pub;
        ba_from_ra(&pub, pub_k.vals[0], pub_k.vlens[0]);
        pem_key_free(&pub_k);

        /* Load Schnorr sig: s, R, e, n */
        PemKey sig_k;
        pem_key_load(&sig_k, sig_path);
        if (strcmp(sig_k.label, PEM_SIGNATURE) != 0 || sig_k.n_items < 3)
            die("verify: invalid signature PEM");
        BitArray s_ba, R, e_stored;
        ba_from_ra(&s_ba,     sig_k.vals[0], sig_k.vlens[0]);
        ba_from_ra(&R,        sig_k.vals[1], sig_k.vlens[1]);
        ba_from_ra(&e_stored, sig_k.vals[2], sig_k.vlens[2]);
        pem_key_free(&sig_k);

        /* Recompute e_v = revolve(R, msg, I_VALUE) */
        BitArray e_v;
        if (strcmp(algo, "hpks") == 0)
            ba_fscx_revolve(&e_v, &R, &msg, I_VALUE);
        else
            nl_fscx_revolve_v1_ba(&e_v, &R, &msg, I_VALUE);

        /* lhs = g^s * pub^e_v; OK if lhs == R */
        BitArray lhs1, lhs2, lhs;
        gf_pow_ba(&lhs1, &GF_GEN, &s_ba);
        gf_pow_ba(&lhs2, &pub,    &e_v);
        gf_mul_ba(&lhs, &lhs1, &lhs2);

        if (ba_equal(&lhs, &R)) { puts("Signature OK");          exit(0); }
        else                    { puts("Verification FAILED");   exit(1); }

    } else if (strcmp(algo, "hpks-stern") == 0) {
        if (pub_k.n_items < 2) die("verify: malformed Stern public key");

        /* Extract syndr (16 bytes) from syn32 (32 bytes, right-aligned).
         * The public key stores syndr[k] at byte KEYBYTES-1-k so that syndrome
         * bit i occupies integer bit i (matching Python/Go convention). */
        uint8_t syn32[KEYBYTES], syndr[SDF_SYNBYTES]; int _sk;
        memset(syn32, 0, KEYBYTES);
        { size_t cl = pub_k.vlens[0] < KEYBYTES ? pub_k.vlens[0] : KEYBYTES;
          memcpy(syn32 + KEYBYTES - cl, pub_k.vals[0], cl); }
        for (_sk = 0; _sk < SDF_SYNBYTES; _sk++)
            syndr[_sk] = syn32[KEYBYTES - 1 - _sk];

        BitArray seed_ba;
        ba_from_ra(&seed_ba, pub_k.vals[1], pub_k.vlens[1]);
        pem_key_free(&pub_k);

        SternSig sig;
        if (stern_sig_load(sig_path, &sig) != 0)
            die("verify: cannot load Stern signature");

        int ok = hpks_stern_f_verify(&sig, &msg, &seed_ba, syndr);
        if (ok) { puts("Signature OK");        exit(0); }
        else    { puts("Verification FAILED"); exit(1); }

    } else if (strcmp(algo, "rnl-sigma") == 0) {
        /* ZKP-RNL verify: pubkey = hkex-rnl public key (C_p, m, n) */
        if (pub_k.n_items < 3) die("verify: malformed hkex-rnl public key");
        int vfy_n = pem_key_get_n(&pub_k, 2);
        if (vfy_n != RNL_N) die("verify: rnl-sigma requires n=256 key");
        rnl_poly_t vfy_Cp, vfy_m;
        poly_unpack(vfy_Cp, pub_k.vals[0], pub_k.vlens[0], 2);
        poly_unpack(vfy_m,  pub_k.vals[1], pub_k.vlens[1], 4);
        pem_key_free(&pub_k);

        /* Read proof */
        size_t plen;
        uint8_t *pbuf = zkp_raw_pem_read(sig_path, PEM_ZKP_RNL_PROOF, &plen);
        if (plen < 4 + (size_t)RNL_N*12) die("verify: truncated ZKP-RNL proof");
        int pn = (int)(((uint32_t)pbuf[0]<<24)|((uint32_t)pbuf[1]<<16)|
                       ((uint32_t)pbuf[2]<<8)|pbuf[3]);
        if (pn != RNL_N) die("verify: proof n mismatch");
        rnl_poly_t vfy_w, vfy_c, vfy_z;
        int pi;
        for (pi=0;pi<RNL_N;pi++) {
            vfy_w[pi]=(int32_t)(((uint32_t)pbuf[4+pi*4]<<24)|((uint32_t)pbuf[4+pi*4+1]<<16)|
                                ((uint32_t)pbuf[4+pi*4+2]<<8)|pbuf[4+pi*4+3]);
            vfy_c[pi]=(int32_t)(((uint32_t)pbuf[4+RNL_N*4+pi*4]<<24)|
                                ((uint32_t)pbuf[4+RNL_N*4+pi*4+1]<<16)|
                                ((uint32_t)pbuf[4+RNL_N*4+pi*4+2]<<8)|
                                pbuf[4+RNL_N*4+pi*4+3]);
            vfy_z[pi]=(int32_t)(((uint32_t)pbuf[4+RNL_N*8+pi*4]<<24)|
                                ((uint32_t)pbuf[4+RNL_N*8+pi*4+1]<<16)|
                                ((uint32_t)pbuf[4+RNL_N*8+pi*4+2]<<8)|
                                pbuf[4+RNL_N*8+pi*4+3]);
        }
        free(pbuf);

        int ok = rnl_sigma_verify(vfy_m, vfy_Cp, RNL_N, msg.b, KEYBYTES,
                                   vfy_w, vfy_c, vfy_z);
        if (ok) { puts("Signature OK");         exit(0); }
        else    { puts("Verification FAILED");  exit(1); }

    } else {
        pem_key_free(&pub_k);
        dief("verify: unsupported algorithm: %s", algo);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * encfile / decfile  (HSKE-NL-A1 CTR-mode AEAD for arbitrary-size files)
 * .hkx format:  magic(4) | algo(1) | len_be8(8) | nonce(32) | ct(n*32) | tag(32)
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_encfile(int argc, char **argv)
{
    const char *algo     = get_arg(argc, argv, "--algo");
    const char *key_path = get_arg(argc, argv, "--key");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!algo)     algo = "hske-nla1";
    if (!key_path) die("encfile: --key required");
    if (!in_path)  die("encfile: --in required");
    if (!out_path) die("encfile: --out required");
    if (strcmp(algo, "hske-nla1") != 0)
        dief("encfile: unsupported algorithm %s", algo);

    BitArray K;
    load_sym_key(&K, key_path);

    size_t plaintext_len;
    uint8_t *plaintext = read_binary_file(in_path, &plaintext_len);

    /* Generate nonce */
    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");
    uint8_t nonce_bytes[32];
    if (fread(nonce_bytes, 1, 32, urnd) != 32) die("urandom read failed");
    fclose(urnd);

    /* Derive base and seed */
    BitArray N_nonce, base, seed;
    ba_from_ra(&N_nonce, nonce_bytes, 32);
    ba_xor(&base, &K, &N_nonce);
    ba_rnl_kdf_seed(&seed, &base);

    /* Encrypt: ks_i = hske_nla1_ks_block(seed, base, i); ct_i = pt_i XOR ks_i */
    size_t n_blocks = (plaintext_len + KEYBYTES - 1) / KEYBYTES;
    uint8_t *ct_buf = n_blocks > 0 ? (uint8_t *)malloc(n_blocks * KEYBYTES) : NULL;
    if (n_blocks > 0 && !ct_buf) die("out of memory");
    {
        size_t bi;
        for (bi = 0; bi < n_blocks; bi++) {
            uint8_t p_blk[32];
            size_t chunk = plaintext_len - bi * KEYBYTES;
            if (chunk > KEYBYTES) chunk = KEYBYTES;
            memcpy(p_blk, plaintext + bi * KEYBYTES, chunk);
            if (chunk < KEYBYTES) memset(p_blk + chunk, 0, KEYBYTES - chunk);
            BitArray ks;
            hske_nla1_ks_block(&seed, &base, (uint32_t)bi, &ks);
            int j;
            for (j = 0; j < KEYBYTES; j++)
                ct_buf[bi * KEYBYTES + j] = p_blk[j] ^ ks.b[j];
        }
    }
    free(plaintext);

    /* MAC key: nl_fscx_revolve_v1(ROL(seed, n/4), base, I_VALUE) */
    BitArray mac_key_ba;
    hske_nla1_mac_key(&seed, &base, &mac_key_ba);
    uint8_t mac_iv[32];
    { int j; for (j = 0; j < 32; j++) mac_iv[j] = mac_key_ba.b[j] ^ _HFSCX256_IV[j]; }

    /* Auth tag: HFSCX-256-MAC(mac_iv, nonce || len_be8 || ciphertext) */
    size_t mac_len = 32 + 8 + n_blocks * KEYBYTES;
    uint8_t *mac_data = (uint8_t *)malloc(mac_len);
    if (!mac_data) die("out of memory");
    memcpy(mac_data, nonce_bytes, 32);
    { int j; uint64_t pl = (uint64_t)plaintext_len;
      for (j = 0; j < 8; j++) mac_data[32+j] = (uint8_t)((pl >> (56 - 8*j)) & 0xFF); }
    if (n_blocks > 0) memcpy(mac_data + 40, ct_buf, n_blocks * KEYBYTES);
    uint8_t tag[32];
    hfscx_256(mac_data, mac_len, mac_iv, tag);
    free(mac_data);

    /* Write .hkx file */
    FILE *out = fopen(out_path, "wb");
    if (!out) dief("encfile: cannot open %s for writing", out_path);
    uint8_t hdr[45];
    hdr[0]='H'; hdr[1]='K'; hdr[2]='X'; hdr[3]='1'; hdr[4]=0x01;
    { int j; uint64_t pl = (uint64_t)plaintext_len;
      for (j = 0; j < 8; j++) hdr[5+j] = (uint8_t)((pl >> (56 - 8*j)) & 0xFF); }
    memcpy(hdr+13, nonce_bytes, 32);
    fwrite(hdr, 1, 45, out);
    if (n_blocks > 0) fwrite(ct_buf, 1, n_blocks * KEYBYTES, out);
    fwrite(tag, 1, 32, out);
    fclose(out);
    free(ct_buf);
}

static void cmd_decfile(int argc, char **argv)
{
    const char *algo     = get_arg(argc, argv, "--algo");
    const char *key_path = get_arg(argc, argv, "--key");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!algo)     algo = "hske-nla1";
    if (!key_path) die("decfile: --key required");
    if (!in_path)  die("decfile: --in required");
    if (!out_path) die("decfile: --out required");
    if (strcmp(algo, "hske-nla1") != 0)
        dief("decfile: unsupported algorithm %s", algo);

    BitArray K;
    load_sym_key(&K, key_path);

    size_t raw_len;
    uint8_t *raw = read_binary_file(in_path, &raw_len);

    /* Parse header */
    if (raw_len < 77) die("decfile: file too short to be a valid .hkx container");
    if (raw[0]!='H'||raw[1]!='K'||raw[2]!='X'||raw[3]!='1')
        die("decfile: invalid magic (expected HKX1)");
    if (raw[4] != 0x01) { char _ab[48]; snprintf(_ab,sizeof _ab,"decfile: unsupported algo byte 0x%02x",raw[4]); die(_ab); }

    uint64_t plaintext_len = 0;
    { int j; for (j = 0; j < 8; j++) plaintext_len = (plaintext_len << 8) | raw[5+j]; }
    const uint8_t *nonce_bytes = raw + 13;
    size_t n_blocks = (size_t)((plaintext_len + KEYBYTES - 1) / KEYBYTES);
    size_t ct_end   = 45 + n_blocks * KEYBYTES;
    if (raw_len < ct_end + 32) die("decfile: file truncated (ciphertext or auth tag missing)");
    const uint8_t *ct_bytes   = raw + 45;
    const uint8_t *tag_stored = raw + ct_end;

    /* Derive base and seed */
    BitArray N_nonce, base, seed;
    ba_from_ra(&N_nonce, nonce_bytes, 32);
    ba_xor(&base, &K, &N_nonce);
    ba_rnl_kdf_seed(&seed, &base);

    /* Compute MAC and compare (verify-then-decrypt) */
    BitArray mac_key_ba;
    hske_nla1_mac_key(&seed, &base, &mac_key_ba);
    uint8_t mac_iv[32];
    { int j; for (j = 0; j < 32; j++) mac_iv[j] = mac_key_ba.b[j] ^ _HFSCX256_IV[j]; }

    size_t mac_len = 32 + 8 + n_blocks * KEYBYTES;
    uint8_t *mac_data = (uint8_t *)malloc(mac_len);
    if (!mac_data) die("out of memory");
    memcpy(mac_data, nonce_bytes, 32);
    { int j; for (j = 0; j < 8; j++) mac_data[32+j] = raw[5+j]; }
    if (n_blocks > 0) memcpy(mac_data + 40, ct_bytes, n_blocks * KEYBYTES);
    uint8_t tag_computed[32];
    hfscx_256(mac_data, mac_len, mac_iv, tag_computed);
    free(mac_data);

    /* Constant-time tag comparison */
    uint8_t diff = 0;
    { int j; for (j = 0; j < 32; j++) diff |= tag_stored[j] ^ tag_computed[j]; }
    if (diff != 0) { free(raw); die("decfile: authentication tag mismatch — file corrupt or wrong key"); }

    /* Decrypt and write plaintext */
    size_t pt_len = (size_t)plaintext_len;
    uint8_t *plaintext = pt_len > 0 ? (uint8_t *)malloc(pt_len) : NULL;
    if (pt_len > 0 && !plaintext) die("out of memory");
    {
        size_t bi;
        for (bi = 0; bi < n_blocks; bi++) {
            BitArray ks;
            hske_nla1_ks_block(&seed, &base, (uint32_t)bi, &ks);
            size_t chunk = pt_len - bi * KEYBYTES;
            if (chunk > KEYBYTES) chunk = KEYBYTES;
            int j;
            for (j = 0; j < (int)chunk; j++)
                plaintext[bi * KEYBYTES + j] = ct_bytes[bi * KEYBYTES + j] ^ ks.b[j];
        }
    }
    free(raw);
    write_binary_file(out_path, plaintext ? plaintext : (const uint8_t *)"", pt_len);
    free(plaintext);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * fpe — format-preserving encrypt / decrypt (78.A)
 *   --encrypt | --decrypt  --key SK --context CTX --in FILE [--out FILE]
 *   Input/output: raw 32-byte block.  Key: HERRADURA SESSION KEY PEM.
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_fpe(int argc, char **argv)
{
    const char *key_path = get_arg(argc, argv, "--key");
    const char *ctx_str  = get_arg(argc, argv, "--context");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    int do_enc = has_flag(argc, argv, "--encrypt");
    int do_dec = has_flag(argc, argv, "--decrypt");
    if (!do_enc && !do_dec) die("fpe: --encrypt or --decrypt required");
    if (!key_path) die("fpe: --key required");
    if (!in_path)  die("fpe: --in required");
    if (!ctx_str)  ctx_str = "";

    BitArray K;
    load_sym_key(&K, key_path);

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);
    BitArray P;
    make_msg_ba(&P, in_buf, in_len);
    free(in_buf);

    BitArray R;
    if (do_enc)
        fpe_encrypt(&P, K.b, KEYBYTES, (const uint8_t *)ctx_str, strlen(ctx_str), &R);
    else
        fpe_decrypt(&P, K.b, KEYBYTES, (const uint8_t *)ctx_str, strlen(ctx_str), &R);

    write_binary_file(out_path, R.b, KEYBYTES);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * twk — tweakable wide-block cipher encrypt / decrypt (78.B)
 *   --encrypt | --decrypt  --key SK --sector N --bidx N --in FILE [--out FILE]
 *   Input/output: raw 32-byte block.  Key: HERRADURA SESSION KEY PEM.
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_twk(int argc, char **argv)
{
    const char *key_path    = get_arg(argc, argv, "--key");
    const char *sector_str  = get_arg(argc, argv, "--sector");
    const char *bidx_str    = get_arg(argc, argv, "--bidx");
    const char *in_path     = get_arg(argc, argv, "--in");
    const char *out_path    = get_arg(argc, argv, "--out");
    int do_enc = has_flag(argc, argv, "--encrypt");
    int do_dec = has_flag(argc, argv, "--decrypt");
    if (!do_enc && !do_dec) die("twk: --encrypt or --decrypt required");
    if (!key_path)   die("twk: --key required");
    if (!in_path)    die("twk: --in required");
    uint64_t sector = sector_str ? (uint64_t)strtoull(sector_str, NULL, 10) : 0;
    uint32_t bidx   = bidx_str   ? (uint32_t)strtoul(bidx_str,   NULL, 10) : 0;

    BitArray K;
    load_sym_key(&K, key_path);

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);
    BitArray P;
    make_msg_ba(&P, in_buf, in_len);
    free(in_buf);

    BitArray R;
    if (do_enc)
        twk_encrypt(&P, K.b, KEYBYTES, sector, bidx, &R);
    else
        twk_decrypt(&P, K.b, KEYBYTES, sector, bidx, &R);

    write_binary_file(out_path, R.b, KEYBYTES);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * oprf-blind / oprf-eval / oprf-unblind  (TODO #80)
 * ───────────────────────────────────────────────────────────────────────────── */

static void cmd_oprf_blind(int argc, char **argv)
{
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!in_path) die("oprf-blind: --in required");

    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    size_t in_len;
    uint8_t *in_buf = read_binary_file(in_path, &in_len);

    BitArray r, alpha;
    oprf_blind(in_buf, in_len, &r, &alpha, urnd);
    free(in_buf);
    fclose(urnd);

    /* CLIENT STATE: SEQUENCE(INTEGER(r), INTEGER(alpha), INTEGER(256)) */
    uint8_t ir[DER_INT_LEN(KEYBYTES)], ialpha[DER_INT_LEN(KEYBYTES)], in[8];
    size_t lr, lalpha, ln;
    der_i32(r.b, ir, &lr);
    der_i32(alpha.b, ialpha, &lalpha);
    der_i_n256(in, &ln);
    const uint8_t *it[3] = {ir, ialpha, in};
    size_t il[3] = {lr, lalpha, ln};
    seq_and_write(it, il, 3, PEM_OPRF_STATE, out_path);

    explicit_bzero(&r, sizeof(r));
}

static void ba_from_der_item(BitArray *dst, const uint8_t *val, size_t vlen)
{
    /* DER INTEGER may have a leading 0x00 pad byte (sign bit); skip it. */
    if (vlen > 0 && val[0] == 0x00) { val++; vlen--; }
    size_t copy = vlen < KEYBYTES ? vlen : KEYBYTES;
    memset(dst->b, 0, KEYBYTES);
    memcpy(dst->b + KEYBYTES - copy, val, copy);
}

static void cmd_oprf_eval(int argc, char **argv)
{
    const char *key_path = get_arg(argc, argv, "--key");
    const char *in_path  = get_arg(argc, argv, "--in");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!key_path) die("oprf-eval: --key required");
    if (!in_path)  die("oprf-eval: --in required");

    /* Load server key: SEQUENCE(INTEGER(k), INTEGER(256)) */
    PemKey kpem; pem_key_load(&kpem, key_path);
    if (strcmp(kpem.label, PEM_OPRF_PRIV) != 0)
        dief("oprf-eval: expected OPRF PRIVATE KEY PEM, got '%s'", kpem.label);
    if (kpem.n_items < 1) die("oprf-eval: malformed OPRF private key");
    BitArray k;
    ba_from_der_item(&k, kpem.vals[0], kpem.vlens[0]);
    pem_key_free(&kpem);

    /* Load CLIENT STATE: SEQUENCE(INTEGER(r), INTEGER(alpha), INTEGER(256)) */
    PemKey spem; pem_key_load(&spem, in_path);
    if (strcmp(spem.label, PEM_OPRF_STATE) != 0)
        dief("oprf-eval: expected OPRF CLIENT STATE PEM, got '%s'", spem.label);
    if (spem.n_items < 2) die("oprf-eval: malformed CLIENT STATE PEM");
    BitArray alpha;
    ba_from_der_item(&alpha, spem.vals[1], spem.vlens[1]);
    pem_key_free(&spem);

    BitArray beta;
    oprf_eval(&beta, &alpha, &k);
    explicit_bzero(&k, sizeof(k));

    /* EVALUATION: SEQUENCE(INTEGER(beta), INTEGER(256)) */
    uint8_t ibeta[DER_INT_LEN(KEYBYTES)], in[8];
    size_t lbeta, ln;
    der_i32(beta.b, ibeta, &lbeta);
    der_i_n256(in, &ln);
    const uint8_t *it[2] = {ibeta, in};
    size_t il[2] = {lbeta, ln};
    seq_and_write(it, il, 2, PEM_OPRF_EVAL, out_path);
}

static void cmd_oprf_unblind(int argc, char **argv)
{
    const char *state_path = get_arg(argc, argv, "--state");
    const char *eval_path  = get_arg(argc, argv, "--eval");
    const char *out_path   = get_arg(argc, argv, "--out");
    if (!state_path) die("oprf-unblind: --state required");
    if (!eval_path)  die("oprf-unblind: --eval required");

    /* Load CLIENT STATE: SEQUENCE(INTEGER(r), INTEGER(alpha), INTEGER(256)) */
    PemKey spem; pem_key_load(&spem, state_path);
    if (strcmp(spem.label, PEM_OPRF_STATE) != 0)
        dief("oprf-unblind: expected OPRF CLIENT STATE PEM, got '%s'", spem.label);
    if (spem.n_items < 1) die("oprf-unblind: malformed CLIENT STATE PEM");
    BitArray r;
    ba_from_der_item(&r, spem.vals[0], spem.vlens[0]);
    pem_key_free(&spem);

    /* Load EVALUATION: SEQUENCE(INTEGER(beta), INTEGER(256)) */
    PemKey epem; pem_key_load(&epem, eval_path);
    if (strcmp(epem.label, PEM_OPRF_EVAL) != 0)
        dief("oprf-unblind: expected OPRF EVALUATION PEM, got '%s'", epem.label);
    if (epem.n_items < 1) die("oprf-unblind: malformed EVALUATION PEM");
    BitArray beta;
    ba_from_der_item(&beta, epem.vals[0], epem.vlens[0]);
    pem_key_free(&epem);

    BitArray F;
    oprf_unblind(&F, &beta, &r);
    explicit_bzero(&r, sizeof(r));

    /* Output: hex string (+ newline) */
    int i;
    char hex[KEYBYTES * 2 + 2];
    for (i = 0; i < KEYBYTES; i++) sprintf(hex + 2*i, "%02x", F.b[i]);
    hex[KEYBYTES * 2] = '\n';
    hex[KEYBYTES * 2 + 1] = '\0';
    write_binary_file(out_path, (const uint8_t*)hex, strlen(hex));
}

/* ─────────────────────────────────────────────────────────────────────────────
 * pake-register / pake-demo  (TODO #80 Batch 4-C)
 * ───────────────────────────────────────────────────────────────────────────── */

static uint32_t _pake_der_uint32(const uint8_t *val, size_t vlen)
{
    if (vlen > 0 && val[0] == 0x00) { val++; vlen--; }
    uint32_t v = 0;
    for (size_t i = 0; i < vlen && i < 4; i++)
        v = (v << 8) | val[i];
    return v;
}

static void cmd_pake_register(int argc, char **argv)
{
    const char *key_path = get_arg(argc, argv, "--key");
    const char *pw_arg   = get_arg(argc, argv, "--password");
    const char *out_path = get_arg(argc, argv, "--out");
    if (!key_path) die("pake-register: --key required");

    PemKey kpem; pem_key_load(&kpem, key_path);
    if (strcmp(kpem.label, PEM_OPRF_PRIV) != 0)
        dief("pake-register: expected OPRF PRIVATE KEY PEM, got '%s'", kpem.label);
    if (kpem.n_items < 1) die("pake-register: malformed OPRF private key");
    BitArray oprf_k;
    ba_from_der_item(&oprf_k, kpem.vals[0], kpem.vlens[0]);
    pem_key_free(&kpem);

    const char *pw = pw_arg ? pw_arg : "demo-password";
    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    HpakeRecord rec;
    hpake_register(&rec, (const uint8_t *)pw, strlen(pw), &oprf_k, urnd);
    fclose(urnd);
    explicit_bzero(&oprf_k, sizeof(oprf_k));

    /* Encode: SEQUENCE(INTEGER(salt,32), INTEGER(B,4), INTEGER(y,4)) */
    uint8_t isalt[DER_INT_LEN(32)], ib[DER_INT_LEN(4)], iy[DER_INT_LEN(4)];
    size_t  lsalt, lb, ly;
    der_int_enc(rec.salt, 32, isalt, &lsalt);
    uint8_t b_bytes[4] = {(uint8_t)(rec.B>>24),(uint8_t)(rec.B>>16),(uint8_t)(rec.B>>8),(uint8_t)rec.B};
    uint8_t y_bytes[4] = {(uint8_t)(rec.y>>24),(uint8_t)(rec.y>>16),(uint8_t)(rec.y>>8),(uint8_t)rec.y};
    der_int_enc(b_bytes, 4, ib, &lb);
    der_int_enc(y_bytes, 4, iy, &ly);
    const uint8_t *it[3] = {isalt, ib, iy};
    size_t il[3] = {lsalt, lb, ly};
    seq_and_write(it, il, 3, PEM_PAKE_RECORD, out_path);
}

static void cmd_pake_demo(int argc, char **argv)
{
    const char *key_path = get_arg(argc, argv, "--key");
    const char *pw_arg   = get_arg(argc, argv, "--password");
    if (!key_path) die("pake-demo: --key required");

    PemKey kpem; pem_key_load(&kpem, key_path);
    if (strcmp(kpem.label, PEM_OPRF_PRIV) != 0)
        dief("pake-demo: expected OPRF PRIVATE KEY PEM, got '%s'", kpem.label);
    if (kpem.n_items < 1) die("pake-demo: malformed OPRF private key");
    BitArray oprf_k;
    ba_from_der_item(&oprf_k, kpem.vals[0], kpem.vlens[0]);
    pem_key_free(&kpem);

    const char *pw = pw_arg ? pw_arg : "demo-password";
    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) die("cannot open /dev/urandom");

    HpakeRecord rec;
    hpake_register(&rec, (const uint8_t *)pw, strlen(pw), &oprf_k, urnd);

    uint8_t sk[KEYBYTES];
    if (hpake_login_demo(sk, &rec, (const uint8_t *)pw, strlen(pw), &oprf_k, urnd)) {
        int i;
        printf("- aPAKE login succeeded; session key: ");
        for (i = 0; i < KEYBYTES; i++) printf("%02x", sk[i]);
        putchar('\n');
    } else {
        puts("+ aPAKE login failed!");
        explicit_bzero(&oprf_k, sizeof(oprf_k));
        fclose(urnd);
        exit(1);
    }

    uint8_t sk2[KEYBYTES];
    if (!hpake_login_demo(sk2, &rec, (const uint8_t *)"wrong-password", 14, &oprf_k, urnd))
        puts("- aPAKE correctly rejects wrong password");
    else
        puts("+ aPAKE accepted wrong password! (security failure)");

    explicit_bzero(&oprf_k, sizeof(oprf_k));
    explicit_bzero(sk,  sizeof(sk));
    explicit_bzero(sk2, sizeof(sk2));
    fclose(urnd);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Usage
 * ───────────────────────────────────────────────────────────────────────────── */

static void usage(void)
{
    puts(
"Herradura Cryptographic Suite CLI v1.5.26\n"
"\n"
"Usage: herradura_cli <command> [options]\n"
"\n"
"Commands:\n"
"  genpkey --algo ALGO [--out FILE]\n"
"    Generate a private key.  Algorithms: hkex-gf hkex-rnl hpks hpks-nl\n"
"    hpke hpke-nl hpks-stern hpke-stern hpks-zkp-nl\n"
"\n"
"  pkey --in FILE (--pubout | --text) [--out FILE]\n"
"    Extract public key (--pubout) or print fields in hex (--text).\n"
"\n"
"  kex --algo ALGO --our PRIV --their PUB --out FILE [--kdf hfscx-256]\n"
"    Key exchange.  Algorithms: hkex-gf hkex-rnl\n"
"    HKEX-RNL is 2-round: Bob runs step 1 (--their=alice_pub.pem),\n"
"    Alice runs step 2 (--their=bob_resp.pem).\n"
"    --kdf hfscx-256: post-hash the raw shared secret with HFSCX-256.\n"
"    Both sides must use the same --kdf flag to derive the same final key.\n"
"\n"
"  enc --algo ALGO (--key SK | --pubkey PUB) --in FILE [--out FILE] [--aead [--ad STR]]\n"
"    Encrypt.  Symmetric (--key): hske hske-nla1 hske-nla2\n"
"    Asymmetric (--pubkey): hpke hpke-nl hpke-stern\n"
"    --aead (hske-nla1 only): HSKE-NL-AEAD authenticated encryption; --ad binds\n"
"    optional associated data into the tag (must match at dec).\n"
"\n"
"  dec --algo ALGO --key KEY --in CT_FILE [--out FILE] [--ad STR]\n"
"    Decrypt.  Symmetric: key=SESSION KEY PEM.  Asymmetric: key=PRIVATE KEY PEM.\n"
"    AEAD ciphertexts (format tag 2) are verified before decryption.\n"
"\n"
"  encfile --algo hske-nla1 --key SK --in FILE --out FILE.hkx\n"
"    Stream-encrypt an arbitrary-size file (HSKE-NL-A1 CTR-AEAD).\n"
"\n"
"  decfile --algo hske-nla1 --key SK --in FILE.hkx --out FILE\n"
"    Verify-then-decrypt a .hkx file.  Exits non-zero on auth failure.\n"
"\n"
"  sign --algo ALGO --key PRIV --in FILE --out SIG [--digest hfscx-256]\n"
"    Sign.  Algorithms: hpks hpks-nl hpks-stern rnl-sigma nl-zkboo\n"
"    rnl-sigma: key = hkex-rnl private key (n=256); produces ZKP-RNL PROOF PEM.\n"
"    nl-zkboo:  key = hpks-zkp-nl private key;      produces ZKP-NL PROOF PEM.\n"
"    --digest hfscx-256: pre-hash input before signing.\n"
"\n"
"  verify --algo ALGO --pubkey PUB --in FILE --sig SIG [--digest hfscx-256]\n"
"    Verify signature.  Exits 0 on OK, 1 on failure.\n"
"    rnl-sigma: pubkey = hkex-rnl public key; sig = ZKP-RNL PROOF PEM.\n"
"    nl-zkboo:  pubkey = hpks-zkp-nl public key; sig = ZKP-NL PROOF PEM.\n"
"\n"
"  dgst --in FILE [--algo hfscx-256] [--out FILE]\n"
"    Compute HFSCX-256 digest.  Without --out: hex to stdout.\n"
"    With --out FILE: HERRADURA DIGEST PEM.\n"
"\n"
"  fpe (--encrypt|--decrypt) --key SK --context CTX --in FILE [--out FILE]\n"
"    Format-preserving encrypt/decrypt a 32-byte block (78.A).\n"
"    Key: HERRADURA SESSION KEY PEM.  CTX: arbitrary context string.\n"
"\n"
"  twk (--encrypt|--decrypt) --key SK [--sector N] [--bidx N] --in FILE [--out FILE]\n"
"    Tweakable wide-block cipher (78.B).  Unique tweak per (sector, block-index).\n"
"    Key: HERRADURA SESSION KEY PEM.\n"
"\n"
"  oprf-blind --in FILE [--out FILE]\n"
"    OPRF client step 1: hash input and blind with random scalar r.\n"
"    Outputs HERRADURA OPRF CLIENT STATE PEM; send alpha field to server.\n"
"\n"
"  oprf-eval --key OPRF_KEY --in STATE_PEM [--out FILE]\n"
"    OPRF server step: evaluate alpha^k and output HERRADURA OPRF EVALUATION PEM.\n"
"    Key: HERRADURA OPRF PRIVATE KEY PEM.\n"
"\n"
"  oprf-unblind --state STATE_PEM --eval EVAL_PEM [--out FILE]\n"
"    OPRF client step 2: recover F(k,x) and output as 64-char hex.\n"
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
    if (strcmp(cmd, "enc")     == 0) { cmd_enc(argc, argv);     return 0; }
    if (strcmp(cmd, "dec")     == 0) { cmd_dec(argc, argv);     return 0; }
    if (strcmp(cmd, "sign")    == 0) { cmd_sign(argc, argv);    return 0; }
    if (strcmp(cmd, "verify")  == 0) { cmd_verify(argc, argv);  return 0; }
    if (strcmp(cmd, "dgst")    == 0) { cmd_dgst(argc, argv);    return 0; }
    if (strcmp(cmd, "encfile") == 0) { cmd_encfile(argc, argv); return 0; }
    if (strcmp(cmd, "decfile") == 0) { cmd_decfile(argc, argv); return 0; }
    if (strcmp(cmd, "fpe")          == 0) { cmd_fpe(argc, argv);          return 0; }
    if (strcmp(cmd, "twk")          == 0) { cmd_twk(argc, argv);          return 0; }
    if (strcmp(cmd, "oprf-blind")    == 0) { cmd_oprf_blind(argc, argv);    return 0; }
    if (strcmp(cmd, "oprf-eval")     == 0) { cmd_oprf_eval(argc, argv);     return 0; }
    if (strcmp(cmd, "oprf-unblind")  == 0) { cmd_oprf_unblind(argc, argv);  return 0; }
    if (strcmp(cmd, "pake-register") == 0) { cmd_pake_register(argc, argv); return 0; }
    if (strcmp(cmd, "pake-demo")     == 0) { cmd_pake_demo(argc, argv);     return 0; }

    dief("unknown command: %s", cmd);
    return 1;
}
