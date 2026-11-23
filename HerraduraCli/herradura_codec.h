/* HerraduraCli/herradura_codec.h — Base64, PEM, and minimal DER codec
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
#ifndef _WIN32
#include <fcntl.h>   /* hkx_fopen_out: open(O_CREAT, 0600), TODO #395 */
#include <unistd.h>
#endif

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
#define PEM_HPKE_NL3_PRIV   "HERRADURA HPKE-NL3 PRIVATE KEY"  /* TODO #255 */
#define PEM_HPKE_NL3_PUB    "HERRADURA HPKE-NL3 PUBLIC KEY"
#define PEM_HPKS_STERN_PRIV "HERRADURA HPKS-STERN PRIVATE KEY"
#define PEM_HPKS_STERN_PUB  "HERRADURA HPKS-STERN PUBLIC KEY"
#define PEM_HPKE_STERN_PRIV "HERRADURA HPKE-STERN PRIVATE KEY"
#define PEM_HPKE_STERN_PUB  "HERRADURA HPKE-STERN PUBLIC KEY"
#define PEM_SESSION_KEY     "HERRADURA SESSION KEY"
#define PEM_RNL_RESPONSE    "HERRADURA HKEX-RNL RESPONSE"
#define PEM_HYBRID_RESPONSE "HERRADURA HYBRID-RNL-STERN RESPONSE"
#define PEM_SIGNATURE       "HERRADURA SIGNATURE"
#define PEM_CIPHERTEXT      "HERRADURA CIPHERTEXT"
#define PEM_DIGEST          "HERRADURA DIGEST"
#define PEM_ZKP_RNL_PROOF   "HERRADURA ZKP-RNL PROOF"
#define PEM_ZKP_NL_PRIV     "HERRADURA ZKP-NL PRIVATE KEY"
#define PEM_ZKP_NL_PUB      "HERRADURA ZKP-NL PUBLIC KEY"
#define PEM_ZKP_NL_PROOF    "HERRADURA ZKP-NL PROOF"
#define PEM_ZKP_NL_PP_SIG        "HERRADURA ZKP-NL-PP SIGNATURE"
#define PEM_HPKE_STERN_KEM_PRIV  "HERRADURA HPKE-STERN-KEM PRIVATE KEY"
#define PEM_HPKE_STERN_KEM_PUB   "HERRADURA HPKE-STERN-KEM PUBLIC KEY"
#define PEM_HPKE_STERN_KEM_CT    "HERRADURA HPKE-STERN-KEM CIPHERTEXT"
#define PEM_OPRF_PRIV       "HERRADURA OPRF PRIVATE KEY"
#define PEM_OPRF_STATE      "HERRADURA OPRF CLIENT STATE"
#define PEM_OPRF_EVAL       "HERRADURA OPRF EVALUATION"
#define PEM_PAKE_RECORD     "HERRADURA PAKE RECORD"
#define PEM_HPKST_COMMIT    "HERRADURA HPKST COMMITMENT"
#define PEM_HPKST_NONCE     "HERRADURA HPKST NONCE"
#define PEM_HPKST_AGGREGATE "HERRADURA HPKST AGGREGATE"
#define PEM_HPKST_PARTIAL   "HERRADURA HPKST PARTIAL"
#define PEM_HPKST_SIG       "HERRADURA HPKST SIGNATURE"
#define PEM_HDRBG_STATE     "HERRADURA HDRBG STATE"
/* TODO #166 / #268: passphrase-encrypted private-key envelope. */
#define PEM_ENC_PRIV        "HERRADURA ENCRYPTED PRIVATE KEY"
#define PEM_HPKS_WOTS_PRIV  "HERRADURA HPKS-WOTS PRIVATE KEY"
#define PEM_HPKS_WOTS_PUB   "HERRADURA HPKS-WOTS PUBLIC KEY"
#define PEM_HPKS_WOTS_SIG   "HERRADURA HPKS-WOTS SIGNATURE"
#define PEM_HPKS_XMSS_PRIV  "HERRADURA HPKS-XMSS PRIVATE KEY"
#define PEM_HPKS_XMSS_PUB   "HERRADURA HPKS-XMSS PUBLIC KEY"
#define PEM_HPKS_XMSS_SIG   "HERRADURA HPKS-XMSS SIGNATURE"
#define PEM_HPKS_RING_SIG   "HERRADURA HPKS-RING SIGNATURE"
#define PEM_HCRED_PRIV      "HERRADURA HCRED PRIVATE KEY"
#define PEM_HCRED_PUB       "HERRADURA HCRED PUBLIC KEY"
#define PEM_HCRED_CRED      "HERRADURA HCRED CREDENTIAL"
#define PEM_HCRED_PROOF     "HERRADURA HCRED PROOF"

/* ─────────────────────────────────────────────────────────────────────────────
 * Buffer-size macros
 * ───────────────────────────────────────────────────────────────────────────── */

/* Maximum PEM label length (excluding NUL). All callers allocate PEM_LABEL_MAX+1 bytes. */
#define PEM_LABEL_MAX   79

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

/* Worst-case DER INTEGER output: tag(1) + len(5) + sign_byte(1) + val_len. */
#define DER_INT_LEN(val_len)   ((size_t)(val_len) + 7)

/* Worst-case DER SEQUENCE output: tag(1) + len(5) + body_len. */
#define DER_SEQ_LEN(body_len)  ((size_t)(body_len) + 6)

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
    return -1;
}

/* b64_decode's refusals (TODO #398).  One base64 grammar for every reader:
 * the alphabet A-Z a-z 0-9 + /, with space, tab, CR and LF allowed anywhere
 * between characters (RFC 7468's lax form; every writer emits LF lines, and a
 * CRLF file must still read).  Padding is REQUIRED: the characters number a
 * multiple of 4 and '=' appears only as the last one or two of them.  The bits
 * the padding leaves over must be zero, so one DER has exactly one body (the
 * base64 counterpart of TODO #373's canonical DER).  Anything else is refused by
 * name, with the same text in all four CLIs. */
#define B64_ERR_CAP      (-1)   /* output would exceed out_cap */
#define B64_ERR_CHAR     (-2)
#define B64_ERR_PAD      (-3)
#define B64_ERR_LEN      (-4)
#define B64_ERR_BITS     (-5)

/* The shared text for a b64_decode / pem_unwrap return code, or NULL when the
 * code is not a base64 refusal. */
static const char *b64_strerror(int rc)
{
    switch (rc) {
    case B64_ERR_CHAR: return "PEM body is not valid base64: invalid character";
    case B64_ERR_PAD:  return "PEM body is not valid base64: misplaced padding";
    case B64_ERR_LEN:  return "PEM body is not valid base64: length is not a multiple of 4";
    case B64_ERR_BITS: return "PEM body is not valid base64: non-zero bits after the last byte";
    default:           return NULL;
    }
}

/* Decode base64 under the grammar above into out, which holds at most out_cap
 * bytes.  Returns 0 on success, B64_ERR_CAP if the decoded output would exceed
 * out_cap (nothing beyond out[0..out_cap-1] is written), or a B64_ERR_* code
 * for input outside the grammar.  *out_len is set only on success. */
static int b64_decode(const char *in, size_t in_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint32_t acc = 0;
    int bits = 0, pad = 0;
    size_t n = 0, chars = 0, i;
    for (i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') {
            /* '=' completes the last quad: only at its third or fourth place. */
            if (++pad > 2 || (chars % 4) < 2) return B64_ERR_PAD;
            chars++;
            continue;
        }
        int v = _b64_val(c);
        if (v < 0) return B64_ERR_CHAR;
        if (pad) return B64_ERR_PAD;      /* data after the padding */
        chars++;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_cap) return B64_ERR_CAP;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    if (chars % 4) return B64_ERR_LEN;
    if (pad && (acc & ((1u << bits) - 1u))) return B64_ERR_BITS;
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
    if (n < 0x1000000) {
        out[0] = 0x83; out[1] = (uint8_t)(n >> 16); out[2] = (uint8_t)(n >> 8);
        out[3] = (uint8_t)n; return 4;
    }
#if SIZE_MAX > 0xffffffffu
    if (n < 0x100000000ULL) {
#else
    {
#endif
        out[0] = 0x84; out[1] = (uint8_t)(n >> 24); out[2] = (uint8_t)(n >> 16);
        out[3] = (uint8_t)(n >> 8); out[4] = (uint8_t)n; return 5;
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
    uint8_t lbuf[5];
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
    uint8_t lbuf[5];
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

/* Bytes after the outer DER SEQUENCE in der[0..len-1]: >= 0, or -1 when der
 * does not start with a well-formed SEQUENCE header whose body fits.  Every
 * CLI refuses a non-zero count (TODO #372), so an artifact has one encoding. */
static long der_seq_trailing(const uint8_t *der, size_t len)
{
    size_t consumed, body_len;
    if (!len || der[0] != 0x30) return -1;
    if (_der_dec_len(der + 1, len - 1, &body_len, &consumed) < 0) return -1;
    if (body_len > len - 1 - consumed) return -1;
    return (long)(len - 1 - consumed - body_len);
}

/* TODO #373: how each INTEGER of a DER SEQUENCE is ENCODED, which
 * der_parse_seq's sign-byte strip forgets.  For item i: ew[i] is its encoded
 * width (content length less a 0x00 the set top bit needs) and lz[i] is 1 when
 * it starts with a 0x00 the sign does not need, 2 when with a sign byte.  Returns 0; 1 when a length
 * (the SEQUENCE's or an item's) is not in its shortest form; 2 when item *bad
 * is negative (top bit set, no sign byte); 3 when item *bad is empty; -1 on a
 * structure der_parse_seq refuses anyway.  Every CLI refuses 1-3, so a
 * SEQUENCE has one encoding of its lengths and signs. */
static int _der_len_minimal(const uint8_t *buf, size_t buf_len)
{
    if (!buf_len || buf[0] < 0x80) return 1;
    int nb = buf[0] & 0x7f;
    if (nb == 0 || (size_t)nb + 1 > buf_len || buf[1] == 0) return 0;
    return nb == 1 ? buf[1] >= 0x80 : 1;
}
static int der_seq_scan(const uint8_t *der, size_t len, size_t *ew,
                        unsigned char *lz, int max_items, int *bad)
{
    size_t consumed, body_len, vlen, offset = 1, end;
    int n = 0;
    if (!len || der[0] != 0x30) return -1;
    if (_der_dec_len(der + 1, len - 1, &body_len, &consumed) < 0) return -1;
    if (!_der_len_minimal(der + 1, len - 1)) return 1;
    offset += consumed;
    if (body_len > len - offset) return -1;
    end = offset + body_len;
    while (offset < end && n < max_items) {
        if (der[offset] != 0x02) return -1;
        offset++;
        if (offset >= end) return -1;
        if (_der_dec_len(der + offset, end - offset, &vlen, &consumed) < 0) return -1;
        if (!_der_len_minimal(der + offset, end - offset)) return 1;
        offset += consumed;
        if (vlen > end - offset) return -1;
        if (bad) *bad = n;
        if (vlen == 0) return 3;
        if (der[offset] & 0x80) return 2;
        int sign = vlen > 1 && der[offset] == 0 && (der[offset + 1] & 0x80);
        ew[n] = vlen - (size_t)sign;
        lz[n] = (unsigned char)(sign ? 2 : (vlen > 1 && der[offset] == 0) ? 1 : 0);
        n++;
        offset += vlen;
    }
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
    /* Reject a claimed SEQUENCE body that runs past the actual buffer --
     * without this check `end` is attacker-controlled and every access below
     * (der[offset], vp[0], etc.) can read out of bounds. */
    if (body_len > len - offset) return -1;
    /* Nothing may follow the SEQUENCE (TODO #372). */
    if (body_len != len - offset) return -1;
    size_t end = offset + body_len;
    while (offset < end && n < max_items) {
        if (der[offset] != 0x02) return -1;
        offset++;
        if (offset > end) return -1;
        if (_der_dec_len(der + offset, end - offset, &vlen, &consumed) < 0) return -1;
        offset += consumed;
        /* Reject a claimed INTEGER length that runs past the SEQUENCE body. */
        if (vlen > end - offset) return -1;
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
 * label_out: caller-allocated buffer of at least PEM_LABEL_MAX+1 bytes; receives
 *   NUL-terminated label.  Returns -1 if the label exceeds PEM_LABEL_MAX characters.
 * der_out / der_cap: caller-provided buffer and its capacity.
 * *der_len: receives the decoded byte count on success.
 * Returns 0 on success, -1 on malformed PEM, oversized label, or buffer too small
 * (der_cap exceeded -- nothing beyond der_out[0..der_cap-1] is ever written), or
 * a B64_ERR_* code for a body outside the base64 grammar (b64_strerror names it). */
static int pem_unwrap(const char *pem, size_t pem_len,
                      char *label_out, uint8_t *der_out, size_t der_cap,
                      size_t *der_len)
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
        if (ll > PEM_LABEL_MAX) return -1;
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

    return b64_decode(body, (size_t)(foot - body), der_out, der_cap, der_len);
}

/* Read a PEM file from path.
 * label_out: caller-allocated >= 80 bytes.
 * der_out / der_cap: buffer + capacity; *der_len receives the actual byte
 *   count on success.
 * Returns 0 on success, -1 on I/O, parse error, or buffer too small. */
static int pem_read_file(const char *path, char *label_out,
                         uint8_t *der_out, size_t der_cap, size_t *der_len)
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
    int r = pem_unwrap(buf, rd, label_out, der_out, der_cap, der_len);
    free(buf);
    return r;
}

/* Open an output file for writing (mode "w" or "wb"), creating it 0600 (TODO
 * #395).  Every file a CLI writes -- private keys, plaintext, shared secrets,
 * state sidecars, and public outputs too -- comes through here, so no output
 * is world-readable under the default umask.  A file that already exists keeps
 * its mode: O_CREAT's mode applies only on creation, as with OpenSSL. */
static FILE *hkx_fopen_out(const char *path, const char *mode)
{
#ifdef _WIN32
    return fopen(path, mode);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
#endif
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
    /* TODO #399: "-" is stdout, as everywhere else in the CLI.  Before #399 it
     * was opened as a FILE NAMED "-", so every raw-body PEM written without
     * --out (ZKP-NL and HCRED keys and proofs, ZKP-RNL proofs) landed there. */
    int to_stdout = strcmp(path, "-") == 0;
    FILE *f = to_stdout ? stdout : hkx_fopen_out(path, "w");
    if (!f) { free(buf); return -1; }
    size_t wr = fwrite(buf, 1, written, f);
    if (to_stdout) fflush(f); else fclose(f);
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
        assert(b64_decode(b64, b64_len, dec, sizeof(dec), &dec_len) == 0);
        assert(dec_len == 6 && memcmp(orig, dec, 6) == 0);
    }

    /* ── 1b. b64_decode rejects output that would exceed the capacity ──────── */
    {
        static const uint8_t orig[] = {0x00,0x01,0x02,0x03,0x04,0x05};
        char b64[B64_ENC_LEN(6)];
        uint8_t dec[3]; /* too small for the 6 decoded bytes */
        size_t b64_len;

        b64_encode(orig, 6, b64, &b64_len);
        assert(b64_decode(b64, b64_len, dec, sizeof(dec), NULL) == -1);
    }

    /* ── 1c. the base64 grammar (TODO #398): accept-controls, then refusals ── */
    {
        uint8_t dec[8];
        size_t dl;
        assert(b64_decode("AAECAw==", 8, dec, sizeof(dec), &dl) == 0 && dl == 4);
        assert(b64_decode("AA EC\r\nAw\t==\n", 13, dec, sizeof(dec), &dl) == 0 && dl == 4);
        assert(b64_decode("AAEC", 4, dec, sizeof(dec), &dl) == 0 && dl == 3);
        assert(b64_decode("AA!CAw==", 8, dec, sizeof(dec), NULL) == B64_ERR_CHAR);
        assert(b64_decode("AA\vECAw==", 9, dec, sizeof(dec), NULL) == B64_ERR_CHAR);
        assert(b64_decode("AA=CAw==", 8, dec, sizeof(dec), NULL) == B64_ERR_PAD);
        assert(b64_decode("AAECAw===", 9, dec, sizeof(dec), NULL) == B64_ERR_PAD);
        assert(b64_decode("AAECAw==AAAA", 12, dec, sizeof(dec), NULL) == B64_ERR_PAD);
        assert(b64_decode("AAECA===", 8, dec, sizeof(dec), NULL) == B64_ERR_PAD);
        assert(b64_decode("AAECAw", 6, dec, sizeof(dec), NULL) == B64_ERR_LEN);
        assert(b64_decode("AAECAx==", 8, dec, sizeof(dec), NULL) == B64_ERR_BITS);
        assert(b64_strerror(B64_ERR_CAP) == NULL && b64_strerror(B64_ERR_CHAR) != NULL);
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
        uint8_t out[DER_INT_LEN(32)]; /* must fit the 32-byte-input case below */
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
        assert(pem_unwrap(pem, pem_len, label, der2, sizeof(der2), &der2_len) == 0);
        assert(strcmp(label, "TEST") == 0);
        assert(der2_len == 9 && memcmp(der, der2, 9) == 0);
    }

    /* ── 5b. pem_unwrap rejects DER output that would exceed der_cap ────────── */
    {
        static const uint8_t der[] = {0x30,0x07,0x02,0x01,0x2a,0x02,0x02,0x01,0x00};
        char pem[PEM_WRAP_LEN(9, 4)];
        size_t pem_len;
        assert(pem_wrap("TEST", der, 9, pem, &pem_len) == 0);

        char label[80];
        uint8_t der2[4]; /* too small for the 9-byte DER payload */
        assert(pem_unwrap(pem, pem_len, label, der2, sizeof(der2), NULL) == -1);
    }

    /* ── 6. PEM label constants (spot-check) ────────────────────────────────── */
    assert(strcmp(PEM_HKEX_GF_PRIV, "HERRADURA HKEX-GF PRIVATE KEY") == 0);
    assert(strcmp(PEM_SESSION_KEY,  "HERRADURA SESSION KEY")          == 0);
    assert(strcmp(PEM_SIGNATURE,    "HERRADURA SIGNATURE")            == 0);

    /* ── 7. pem_unwrap rejects labels longer than PEM_LABEL_MAX ─────────────── */
    {
        /* Craft a PEM whose label is exactly PEM_LABEL_MAX+1 characters. */
        char long_label[PEM_LABEL_MAX + 2];
        memset(long_label, 'A', PEM_LABEL_MAX + 1);
        long_label[PEM_LABEL_MAX + 1] = '\0';

        /* Build "-----BEGIN AAA...A (80 A's)-----\nMAcCASoCAgEA\n-----END AAA...A-----\n" */
        char bad_pem[512];
        int bp = 0;
        memcpy(bad_pem + bp, "-----BEGIN ", 11); bp += 11;
        memcpy(bad_pem + bp, long_label, PEM_LABEL_MAX + 1); bp += PEM_LABEL_MAX + 1;
        memcpy(bad_pem + bp, "-----\nMAcCASoCAgEA\n-----END ", 27); bp += 27;
        memcpy(bad_pem + bp, long_label, PEM_LABEL_MAX + 1); bp += PEM_LABEL_MAX + 1;
        memcpy(bad_pem + bp, "-----\n", 6); bp += 6;

        char lout[PEM_LABEL_MAX + 1];
        uint8_t dout[32];
        size_t dlen;
        assert(pem_unwrap(bad_pem, (size_t)bp, lout, dout, sizeof(dout), &dlen) == -1);
    }

    return 1;
}
#endif /* HERRADURA_CODEC_SELFTEST */

#endif /* HERRADURA_CODEC_H */
