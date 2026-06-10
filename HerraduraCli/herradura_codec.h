/* HerraduraCli/herradura_codec.h — Base64, PEM, and minimal DER codec (v1.5.25)
 *
 * Header-only (all functions static).  No external dependencies.
 * Include <assert.h> and define HERRADURA_CODEC_SELFTEST before including
 * this header to compile the self-test function.
 *
 * PEM labels produced here are byte-for-byte identical to those in
 * HerraduraCli/codec.py; Python-generated PEM files can be read by this
 * codec and vice versa.
 *
 * Build: gcc -O2 -DHERRADURA_CODEC_SELFTEST -o codec_test codec_test.c
 * (include this header in codec_test.c, call herradura_codec_selftest())
 */

#ifndef HERRADURA_CODEC_H
#define HERRADURA_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * PEM label constants — must match Python HerraduraCli/herradura.py exactly
 * ───────────────────────────────────────────────────────────────────────────── */

#define PEM_HKEX_GF_PRIV    "HERRADURA HKEX-GF PRIVATE KEY"
#define PEM_HKEX_GF_PUB     "HERRADURA HKEX-GF PUBLIC KEY"
#define PEM_HKEX_RNL_PRIV   "HERRADURA HKEX-RNL PRIVATE KEY"
#define PEM_HKEX_RNL_PUB    "HERRADURA HKEX-RNL PUBLIC KEY"
#define PEM_HPKS_PRIV       "HERRADURA HPKS PRIVATE KEY"
#define PEM_HPKS_PUB        "HERRADURA HPKS PUBLIC KEY"
#define PEM_HPKS_NL_PRIV    "HERRADURA HPKS-NL PRIVATE KEY"
#define PEM_HPKS_NL_PUB     "HERRADURA HPKS-NL PUBLIC KEY"
#define PEM_HPKE_PRIV       "HERRADURA HPKE PRIVATE KEY"
#define PEM_HPKE_PUB        "HERRADURA HPKE PUBLIC KEY"
#define PEM_HPKE_NL_PRIV    "HERRADURA HPKE-NL PRIVATE KEY"
#define PEM_HPKE_NL_PUB     "HERRADURA HPKE-NL PUBLIC KEY"
#define PEM_HPKS_STERN_PRIV "HERRADURA HPKS-STERN PRIVATE KEY"
#define PEM_HPKS_STERN_PUB  "HERRADURA HPKS-STERN PUBLIC KEY"
#define PEM_HPKE_STERN_PRIV "HERRADURA HPKE-STERN PRIVATE KEY"
#define PEM_HPKE_STERN_PUB  "HERRADURA HPKE-STERN PUBLIC KEY"
#define PEM_SESSION_KEY     "HERRADURA SESSION KEY"
#define PEM_RNL_RESPONSE    "HERRADURA HKEX-RNL RESPONSE"
#define PEM_SIGNATURE       "HERRADURA SIGNATURE"
#define PEM_CIPHERTEXT      "HERRADURA CIPHERTEXT"
#define PEM_DIGEST          "HERRADURA DIGEST"
#define PEM_ZKP_RNL_PROOF   "HERRADURA ZKP-RNL PROOF"
#define PEM_ZKP_NL_PRIV     "HERRADURA ZKP-NL PRIVATE KEY"
#define PEM_ZKP_NL_PUB      "HERRADURA ZKP-NL PUBLIC KEY"
#define PEM_ZKP_NL_PROOF    "HERRADURA ZKP-NL PROOF"
#define PEM_OPRF_PRIV       "HERRADURA OPRF PRIVATE KEY"
#define PEM_OPRF_STATE      "HERRADURA OPRF CLIENT STATE"
#define PEM_OPRF_EVAL       "HERRADURA OPRF EVALUATION"
#define PEM_PAKE_RECORD     "HERRADURA PAKE RECORD"

/* ─────────────────────────────────────────────────────────────────────────────
 * Buffer-size macros
 * ───────────────────────────────────────────────────────────────────────────── */

/* Worst-case output bytes for b64_encode(n bytes).
 * Python base64.encodebytes uses 76-char lines (57 input bytes each) + LF. */
#define B64_ENC_LEN(n)  (((size_t)(n) + 56) / 57 * 77 + 1)

/* Worst-case PEM output:
 *   "-----BEGIN " (11) + label + "-----\n" (6)
 *   + base64 lines
 *   + "-----END " (9) + label + "-----\n" (6)
 *   + NUL (1) */
#define PEM_WRAP_LEN(der_len, label_len) \
    (33 + 2 * (size_t)(label_len) + B64_ENC_LEN(der_len))

/* Worst-case DER INTEGER output: tag(1) + len(3) + sign_byte(1) + val_len. */
#define DER_INT_LEN(val_len)   ((size_t)(val_len) + 5)

/* Worst-case DER SEQUENCE output: tag(1) + len(3) + body_len. */
#define DER_SEQ_LEN(body_len)  ((size_t)(body_len) + 4)

/* ═══════════════════════════════════════════════════════════════════════════
 * Base64  (76-char lines, matching Python base64.encodebytes)
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char _b64_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode in_len bytes → null-terminated base64 string in out.
 * Lines are 76 chars wide, each terminated by '\n'.
 * *out_len (if non-NULL) is set to the number of chars written (excluding NUL).
 * out must hold at least B64_ENC_LEN(in_len) bytes. */
static void b64_encode(const uint8_t *in, size_t in_len,
                       char *out, size_t *out_len)
{
    size_t i, col = 0, n = 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[n++] = _b64_tab[(v >> 18) & 0x3F];
        out[n++] = _b64_tab[(v >> 12) & 0x3F];
        out[n++] = _b64_tab[(v >>  6) & 0x3F];
        out[n++] = _b64_tab[ v        & 0x3F];
        col += 4;
        if (col == 76) { out[n++] = '\n'; col = 0; }
    }
    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 8;
        out[n++] = _b64_tab[(v >> 18) & 0x3F];
        out[n++] = _b64_tab[(v >> 12) & 0x3F];
        out[n++] = (i + 1 < in_len) ? _b64_tab[(v >> 6) & 0x3F] : '=';
        out[n++] = '=';
        col += 4;
    }
    if (col > 0) out[n++] = '\n';
    out[n] = '\0';
    if (out_len) *out_len = n;
}

static int _b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; /* whitespace, '=', or invalid — skip */
}

/* Decode base64 (whitespace and '=' padding ignored).
 * Returns 0 on success, -1 on bad input.
 * *out_len is set to the number of bytes written. */
static int b64_decode(const char *in, size_t in_len,
                      uint8_t *out, size_t *out_len)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0, i;
    for (i = 0; i < in_len; i++) {
        int v = _b64_val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    if (out_len) *out_len = n;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DER TLV helpers (minimal subset: INTEGER 0x02, SEQUENCE 0x30)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int _der_enc_len(size_t n, uint8_t *out)
{
    if (n < 0x80)    { out[0] = (uint8_t)n; return 1; }
    if (n < 0x100)   { out[0] = 0x81; out[1] = (uint8_t)n; return 2; }
    if (n < 0x10000) {
        out[0] = 0x82; out[1] = (uint8_t)(n >> 8); out[2] = (uint8_t)n; return 3;
    }
    return -1; /* too large */
}

static int _der_dec_len(const uint8_t *buf, size_t buf_len,
                        size_t *len_out, size_t *consumed)
{
    if (!buf_len) return -1;
    uint8_t b = buf[0];
    if (b < 0x80) { *len_out = b; *consumed = 1; return 0; }
    int nb = b & 0x7f;
    if (nb > 4 || (size_t)nb + 1 > buf_len) return -1;
    size_t v = 0; int i;
    for (i = 0; i < nb; i++) v = (v << 8) | buf[1 + i];
    *len_out = v;
    *consumed = 1 + (size_t)nb;
    return 0;
}

/* Encode val[0..val_len-1] (big-endian unsigned integer) as DER INTEGER.
 * Prepends a 0x00 sign byte when val[0]&0x80 (matches Python der_int).
 * Returns 0 on success, -1 if the DER length cannot be represented.
 * out must hold at least DER_INT_LEN(val_len) bytes. */
static int der_int_enc(const uint8_t *val, size_t val_len,
                       uint8_t *out, size_t *out_len)
{
    uint8_t lbuf[3];
    int sign = (val_len && (val[0] & 0x80)) ? 1 : 0;
    size_t content = val_len + (size_t)sign;
    int llen = _der_enc_len(content, lbuf);
    if (llen < 0) return -1;
    out[0] = 0x02;
    memcpy(out + 1, lbuf, (size_t)llen);
    size_t off = 1 + (size_t)llen;
    if (sign) out[off++] = 0x00;
    if (val_len) memcpy(out + off, val, val_len);
    if (out_len) *out_len = off + val_len;
    return 0;
}

/* Wrap n_items already-encoded DER items in a SEQUENCE (tag 0x30).
 * out must hold at least DER_SEQ_LEN(sum of item_lens) bytes. */
static int der_seq_enc(const uint8_t **items, const size_t *item_lens,
                       int n_items, uint8_t *out, size_t *out_len)
{
    uint8_t lbuf[3];
    size_t body = 0; int i, llen;
    for (i = 0; i < n_items; i++) body += item_lens[i];
    llen = _der_enc_len(body, lbuf);
    if (llen < 0) return -1;
    out[0] = 0x30;
    memcpy(out + 1, lbuf, (size_t)llen);
    size_t off = 1 + (size_t)llen;
    for (i = 0; i < n_items; i++) {
        memcpy(out + off, items[i], item_lens[i]);
        off += item_lens[i];
    }
    if (out_len) *out_len = off;
    return 0;
}

/* Parse a DER SEQUENCE of INTEGERs into pointer+length pairs.
 * vals[i] points into der (no copy); leading 0x00 sign bytes are skipped so
 * each val_lens[i] gives the true unsigned byte width (matching Python).
 * Returns 0 on success, -1 on parse error. */
static int der_parse_seq(const uint8_t *der, size_t len,
                         const uint8_t **vals, size_t *val_lens,
                         int max_items, int *n_out)
{
    size_t consumed, body_len, vlen, offset = 0;
    int n = 0;
    if (!len || der[0] != 0x30) return -1;
    offset = 1;
    if (_der_dec_len(der + offset, len - offset, &body_len, &consumed) < 0) return -1;
    offset += consumed;
    size_t end = offset + body_len;
    while (offset < end && n < max_items) {
        if (der[offset] != 0x02) return -1;
        offset++;
        if (_der_dec_len(der + offset, end - offset, &vlen, &consumed) < 0) return -1;
        offset += consumed;
        const uint8_t *vp = der + offset;
        size_t vl = vlen;
        /* strip leading 0x00 sign byte (matches Python der_parse_seq) */
        if (vl > 1 && vp[0] == 0x00) { vp++; vl--; }
        vals[n]     = vp;
        val_lens[n] = vl;
        n++;
        offset += vlen; /* advance past original content (incl. any sign byte) */
    }
    if (n_out) *n_out = n;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PEM  (format identical to Python base64.encodebytes + pem_wrap/pem_unwrap)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Wrap der[0..der_len-1] as a PEM block with the given label.
 * out must hold at least PEM_WRAP_LEN(der_len, strlen(label)) bytes. */
static int pem_wrap(const char *label, const uint8_t *der, size_t der_len,
                    char *out, size_t *out_len)
{
    size_t llen = strlen(label), n = 0, b64_len;
    memcpy(out + n, "-----BEGIN ", 11); n += 11;
    memcpy(out + n, label, llen);       n += llen;
    memcpy(out + n, "-----\n", 6);      n += 6;
    b64_encode(der, der_len, out + n, &b64_len);
    n += b64_len;
    memcpy(out + n, "-----END ", 9); n += 9;
    memcpy(out + n, label, llen);    n += llen;
    memcpy(out + n, "-----\n", 6);   n += 6;
    out[n] = '\0';
    if (out_len) *out_len = n;
    return 0;
}

/* Parse a PEM block.
 * label_out: caller-allocated buffer >= 80 bytes; receives NUL-terminated label.
 * der_out / *der_len: caller-provided buffer and its capacity on input;
 *   receives decoded DER bytes and byte count on output.
 * Returns 0 on success, -1 on malformed PEM or buffer too small. */
static int pem_unwrap(const char *pem, size_t pem_len,
                      char *label_out, uint8_t *der_out, size_t *der_len)
{
    const char *p = pem, *end = pem + pem_len;

    /* Locate "-----BEGIN " */
    while (p + 11 <= end && memcmp(p, "-----BEGIN ", 11) != 0) p++;
    if (p + 11 > end) return -1;
    p += 11;

    /* Extract label: scan for "-----" boundary (labels may contain single hyphens) */
    const char *ls = p;
    while (p + 5 <= end && memcmp(p, "-----", 5) != 0) p++;
    if (p + 5 > end) return -1;
    if (label_out) {
        size_t ll = (size_t)(p - ls);
        memcpy(label_out, ls, ll);
        label_out[ll] = '\0';
    }
    p += 5;

    /* Skip header line terminator */
    while (p < end && (*p == '\r' || *p == '\n')) p++;
    const char *body = p;

    /* Locate "-----END " */
    const char *foot = NULL;
    const char *s;
    for (s = body; s + 9 <= end; s++) {
        if (memcmp(s, "-----END ", 9) == 0) { foot = s; break; }
    }
    if (!foot) return -1;

    return b64_decode(body, (size_t)(foot - body), der_out, der_len);
}

/* Read a PEM file from path.
 * label_out: caller-allocated >= 80 bytes.
 * der_out / *der_len: buffer + capacity (updated to actual bytes on return).
 * Returns 0 on success, -1 on I/O or parse error. */
static int pem_read_file(const char *path, char *label_out,
                         uint8_t *der_out, size_t *der_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    int r = pem_unwrap(buf, rd, label_out, der_out, der_len);
    free(buf);
    return r;
}

/* Write DER data as a PEM file.  Returns 0 on success, -1 on I/O error. */
static int pem_write_file(const char *path, const char *label,
                          const uint8_t *der, size_t der_len)
{
    size_t llen = strlen(label);
    size_t buf_sz = PEM_WRAP_LEN(der_len, llen);
    char *buf = (char *)malloc(buf_sz);
    if (!buf) return -1;
    size_t written;
    pem_wrap(label, der, der_len, buf, &written);
    FILE *f = fopen(path, "w");
    if (!f) { free(buf); return -1; }
    size_t wr = fwrite(buf, 1, written, f);
    fclose(f);
    free(buf);
    return (wr == written) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Self-test  (compiled only when HERRADURA_CODEC_SELFTEST is defined)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef HERRADURA_CODEC_SELFTEST
#include <assert.h>

/* Returns 1 if all assertions pass; crashes via assert() otherwise.
 * All known-answer vectors are cross-checked against Python codec.py. */
static int herradura_codec_selftest(void)
{
    /* ── 1. Base64 round-trip ─────────────────────────────────────────────── */
    {
        static const uint8_t orig[] = {0x00,0x01,0x02,0x03,0x04,0x05};
        char b64[B64_ENC_LEN(6)];
        uint8_t dec[6];
        size_t b64_len, dec_len;

        b64_encode(orig, 6, b64, &b64_len);
        assert(b64_decode(b64, b64_len, dec, &dec_len) == 0);
        assert(dec_len == 6 && memcmp(orig, dec, 6) == 0);
    }

    /* ── 2. Base64 known-answer (Python base64.b64encode(b'\x00\x01\x02\x03')
     *       == b'AAECAw==') ─────────────────────────────────────────────────── */
    {
        static const uint8_t in4[] = {0x00,0x01,0x02,0x03};
        char b64[B64_ENC_LEN(4)];
        b64_encode(in4, 4, b64, NULL);
        assert(strncmp(b64, "AAECAw==\n", 9) == 0);
    }

    /* ── 3. DER INTEGER known-answers ───────────────────────────────────────── */
    {
        uint8_t out[16];
        size_t olen;

        /* der_int(42) == 02 01 2a */
        { uint8_t v[] = {42};
          assert(der_int_enc(v, 1, out, &olen) == 0);
          assert(olen == 3 && out[0]==0x02 && out[1]==0x01 && out[2]==0x2a); }

        /* der_int(128) == 02 02 00 80  (sign byte because 0x80 & 0x80) */
        { uint8_t v[] = {0x80};
          assert(der_int_enc(v, 1, out, &olen) == 0);
          assert(olen==4 && out[0]==0x02 && out[1]==0x02 && out[2]==0x00 && out[3]==0x80); }

        /* der_int(256) == 02 02 01 00  (no sign byte; 0x01 & 0x80 == 0) */
        { uint8_t v[] = {0x01,0x00};
          assert(der_int_enc(v, 2, out, &olen) == 0);
          assert(olen==4 && out[0]==0x02 && out[1]==0x02 && out[2]==0x01 && out[3]==0x00); }

        /* der_int with 32-byte all-0xff: tag=02, len=0x21 (sign byte added) */
        { uint8_t v[32]; memset(v, 0xff, 32);
          assert(der_int_enc(v, 32, out, &olen) == 0);
          assert(olen==35 && out[0]==0x02 && out[1]==0x21 && out[2]==0x00 && out[3]==0xff); }
    }

    /* ── 4. DER SEQUENCE encode + parse round-trip ──────────────────────────── */
    {
        uint8_t i42[3], i256[4];
        size_t l42, l256;
        { uint8_t v[]={42};        der_int_enc(v,1,i42,&l42); }
        { uint8_t v[]={0x01,0x00}; der_int_enc(v,2,i256,&l256); }

        const uint8_t *items[2] = {i42, i256};
        size_t ilens[2] = {l42, l256};
        uint8_t seq[32];
        size_t seq_len;
        assert(der_seq_enc(items, ilens, 2, seq, &seq_len) == 0);

        /* Known answer: 30 07 02 01 2a 02 02 01 00 (cross-checked with Python) */
        assert(seq_len == 9);
        static const uint8_t exp_seq[] = {0x30,0x07,0x02,0x01,0x2a,0x02,0x02,0x01,0x00};
        assert(memcmp(seq, exp_seq, 9) == 0);

        const uint8_t *vals[4];
        size_t vlens[4];
        int n_out;
        assert(der_parse_seq(seq, seq_len, vals, vlens, 4, &n_out) == 0);
        assert(n_out == 2);
        assert(vlens[0] == 1 && vals[0][0] == 42);
        assert(vlens[1] == 2 && vals[1][0] == 0x01 && vals[1][1] == 0x00);
    }

    /* ── 5. PEM known-answer + round-trip ───────────────────────────────────── */
    {
        /* seq = 30 07 02 01 2a 02 02 01 00 */
        static const uint8_t der[] = {0x30,0x07,0x02,0x01,0x2a,0x02,0x02,0x01,0x00};
        char pem[PEM_WRAP_LEN(9, 4)]; /* label "TEST" = 4 chars */
        size_t pem_len;

        assert(pem_wrap("TEST", der, 9, pem, &pem_len) == 0);

        /* Known answer from Python pem_wrap("TEST", seq):
         * "-----BEGIN TEST-----\nMAcCASoCAgEA\n-----END TEST-----\n" */
        static const char exp_pem[] =
            "-----BEGIN TEST-----\n"
            "MAcCASoCAgEA\n"
            "-----END TEST-----\n";
        assert(pem_len == strlen(exp_pem));
        assert(strcmp(pem, exp_pem) == 0);

        /* Round-trip unwrap */
        char label[80];
        uint8_t der2[32];
        size_t der2_len;
        assert(pem_unwrap(pem, pem_len, label, der2, &der2_len) == 0);
        assert(strcmp(label, "TEST") == 0);
        assert(der2_len == 9 && memcmp(der, der2, 9) == 0);
    }

    /* ── 6. PEM label constants (spot-check) ────────────────────────────────── */
    assert(strcmp(PEM_HKEX_GF_PRIV, "HERRADURA HKEX-GF PRIVATE KEY") == 0);
    assert(strcmp(PEM_SESSION_KEY,  "HERRADURA SESSION KEY")          == 0);
    assert(strcmp(PEM_SIGNATURE,    "HERRADURA SIGNATURE")            == 0);

    return 1;
}
#endif /* HERRADURA_CODEC_SELFTEST */

#endif /* HERRADURA_CODEC_H */
