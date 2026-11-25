package herradurakex;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * TODO #197: pure-Java PEM/DER codec for the classical quartet's wire
 * format — a byte-for-byte port of {@code HerraduraCli/codec.py} /
 * {@code herradura_codec.h} / {@code herradura/codec.go}'s Base64, PEM, and
 * minimal DER (INTEGER 0x02 / SEQUENCE 0x30) subset, including the
 * long-form length fix (0x81-0x84) from TODO #190's investigation.
 *
 * Scope matches TODO #192/{@link Herradura}: the classical (v1.4.0) quartet
 * only (HKEX-GF, HSKE, HPKS, HPKE). PEM label constants for the rest of the
 * suite are included for parity with the Go/C label tables (harmless, and
 * saves duplicated work for TODO #199-201), but no encode/decode helpers
 * are provided beyond the classical quartet's key/ciphertext/signature/
 * session-key/digest formats.
 */
public final class Codec {
    private Codec() { }

    // -----------------------------------------------------------------
    // PEM label constants — must match Python herradura.py, herradura_codec.h,
    // and herradura/codec.go
    // -----------------------------------------------------------------

    public static final String PEM_HKEX_GF_PRIV = "HERRADURA HKEX-GF PRIVATE KEY";
    public static final String PEM_HKEX_GF_PUB = "HERRADURA HKEX-GF PUBLIC KEY";
    public static final String PEM_HKEX_RNL_PRIV = "HERRADURA HKEX-RNL PRIVATE KEY";
    public static final String PEM_HKEX_RNL_PUB = "HERRADURA HKEX-RNL PUBLIC KEY";
    public static final String PEM_HPKS_PRIV = "HERRADURA HPKS PRIVATE KEY";
    public static final String PEM_HPKS_PUB = "HERRADURA HPKS PUBLIC KEY";
    public static final String PEM_HPKS_NL_PRIV = "HERRADURA HPKS-NL PRIVATE KEY";
    public static final String PEM_HPKS_NL_PUB = "HERRADURA HPKS-NL PUBLIC KEY";
    public static final String PEM_HPKE_PRIV = "HERRADURA HPKE PRIVATE KEY";
    public static final String PEM_HPKE_PUB = "HERRADURA HPKE PUBLIC KEY";
    public static final String PEM_HPKE_NL_PRIV = "HERRADURA HPKE-NL PRIVATE KEY";
    public static final String PEM_HPKE_NL_PUB = "HERRADURA HPKE-NL PUBLIC KEY";
    public static final String PEM_HPKE_NL3_PRIV = "HERRADURA HPKE-NL3 PRIVATE KEY"; // TODO #255
    public static final String PEM_HPKE_NL3_PUB = "HERRADURA HPKE-NL3 PUBLIC KEY";
    public static final String PEM_HPKS_STERN_PRIV = "HERRADURA HPKS-STERN PRIVATE KEY";
    public static final String PEM_HPKS_STERN_PUB = "HERRADURA HPKS-STERN PUBLIC KEY";
    public static final String PEM_HPKE_STERN_PRIV = "HERRADURA HPKE-STERN PRIVATE KEY";
    public static final String PEM_HPKE_STERN_PUB = "HERRADURA HPKE-STERN PUBLIC KEY";
    public static final String PEM_HPKE_STERN_KEM_PRIV = "HERRADURA HPKE-STERN-KEM PRIVATE KEY";
    public static final String PEM_HPKE_STERN_KEM_PUB = "HERRADURA HPKE-STERN-KEM PUBLIC KEY";
    public static final String PEM_OPRF_PRIV = "HERRADURA OPRF PRIVATE KEY";
    public static final String PEM_OPRF_STATE = "HERRADURA OPRF CLIENT STATE";
    public static final String PEM_OPRF_EVAL = "HERRADURA OPRF EVALUATION";
    public static final String PEM_HPKS_WOTS_PRIV = "HERRADURA HPKS-WOTS PRIVATE KEY";
    public static final String PEM_HPKS_WOTS_PUB = "HERRADURA HPKS-WOTS PUBLIC KEY";
    public static final String PEM_HPKS_WOTS_SIG = "HERRADURA HPKS-WOTS SIGNATURE";
    public static final String PEM_HPKS_XMSS_PRIV = "HERRADURA HPKS-XMSS PRIVATE KEY";
    public static final String PEM_HPKS_XMSS_PUB = "HERRADURA HPKS-XMSS PUBLIC KEY";
    public static final String PEM_HPKS_XMSS_SIG = "HERRADURA HPKS-XMSS SIGNATURE";
    public static final String PEM_HCRED_PRIV = "HERRADURA HCRED PRIVATE KEY";
    public static final String PEM_HCRED_PUB = "HERRADURA HCRED PUBLIC KEY";
    public static final String PEM_HCRED_CRED = "HERRADURA HCRED CREDENTIAL";
    public static final String PEM_HCRED_PROOF = "HERRADURA HCRED PROOF";
    public static final String PEM_PAKE_RECORD = "HERRADURA PAKE RECORD";
    public static final String PEM_SESSION_KEY = "HERRADURA SESSION KEY";
    public static final String PEM_RNL_RESPONSE = "HERRADURA HKEX-RNL RESPONSE";
    public static final String PEM_SIGNATURE = "HERRADURA SIGNATURE";
    public static final String PEM_CIPHERTEXT = "HERRADURA CIPHERTEXT";
    /** TODO #166 / #268: passphrase-encrypted private-key envelope. */
    public static final String PEM_ENC_PRIV = "HERRADURA ENCRYPTED PRIVATE KEY";
    public static final String PEM_DIGEST = "HERRADURA DIGEST";

    public static final String PEM_ZKP_RNL_PROOF = "HERRADURA ZKP-RNL PROOF";
    public static final String PEM_HPKST_COMMIT = "HERRADURA HPKST COMMITMENT";
    public static final String PEM_HPKST_NONCE = "HERRADURA HPKST NONCE";
    public static final String PEM_HPKST_AGGREGATE = "HERRADURA HPKST AGGREGATE";
    public static final String PEM_HPKST_PARTIAL = "HERRADURA HPKST PARTIAL";
    public static final String PEM_HPKST_SIG = "HERRADURA HPKST SIGNATURE";
    public static final String PEM_HPKS_RING_SIG = "HERRADURA HPKS-RING SIGNATURE";
    public static final String PEM_ZKP_NL_PRIV = "HERRADURA ZKP-NL PRIVATE KEY";
    public static final String PEM_ZKP_NL_PUB = "HERRADURA ZKP-NL PUBLIC KEY";
    public static final String PEM_ZKP_NL_PROOF = "HERRADURA ZKP-NL PROOF";
    // TODO #261 (v6.0.0): the labels the Java CLI's newly-ported tags need.
    public static final String PEM_ZKP_NL_PP_SIG = "HERRADURA ZKP-NL-PP SIGNATURE";
    public static final String PEM_HYBRID_RESPONSE = "HERRADURA HYBRID-RNL-STERN RESPONSE";
    /** TODO #269: the HDRBG checkpoint `rand --state` reads and writes. */
    public static final String PEM_HDRBG_STATE = "HERRADURA HDRBG STATE";

    // -----------------------------------------------------------------
    // Base64 (76-char lines, matching Python base64.encodebytes)
    // -----------------------------------------------------------------

    /** Encodes data as base64 with 76-char lines, each terminated by '\n'. */
    static String b64Encode(byte[] data) {
        String raw = Base64.getEncoder().encodeToString(data);
        StringBuilder sb = new StringBuilder(raw.length() + raw.length() / 76 + 2);
        int off = 0;
        while (raw.length() - off > 76) {
            sb.append(raw, off, off + 76).append('\n');
            off += 76;
        }
        if (off < raw.length()) {
            sb.append(raw, off, raw.length()).append('\n');
        }
        return sb.toString();
    }

    /**
     * Decodes a PEM body under the one base64 grammar every CLI reads (TODO #398):
     * the alphabet A-Z a-z 0-9 + /, with space, tab, CR and LF allowed anywhere
     * between characters (RFC 7468's lax form).  Padding is REQUIRED: the
     * characters number a multiple of 4 and '=' is only the last one or two of
     * them.  The bits the padding leaves over must be zero, so one DER has one
     * body.  Hand-written rather than java.util.Base64, whose basic decoder
     * accepts a body with no padding and non-zero trailing bits, so that the four
     * CLIs run the same loop and refuse the same files with the same words.
     */
    static byte[] b64Decode(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(s.length() * 3 / 4 + 1);
        int acc = 0, bits = 0, pad = 0, chars = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            if (c == '=') {
                pad++;
                if (pad > 2 || chars % 4 < 2) throw new IllegalArgumentException(B64_PAD);
                chars++;
                continue;
            }
            int v = b64Val(c);
            if (v < 0) throw new IllegalArgumentException(B64_CHAR);
            if (pad > 0) throw new IllegalArgumentException(B64_PAD);
            chars++;
            acc = ((acc << 6) | v) & 0xFFFF;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >> bits) & 0xFF);
            }
        }
        if (chars % 4 != 0) throw new IllegalArgumentException(B64_LEN);
        if (pad > 0 && (acc & ((1 << bits) - 1)) != 0) throw new IllegalArgumentException(B64_BITS);
        return out.toByteArray();
    }

    static final String B64_PREFIX = "PEM body is not valid base64: ";
    private static final String B64_CHAR = B64_PREFIX + "invalid character";
    private static final String B64_PAD  = B64_PREFIX + "misplaced padding";
    private static final String B64_LEN  = B64_PREFIX + "length is not a multiple of 4";
    private static final String B64_BITS = B64_PREFIX + "non-zero bits after the last byte";

    private static int b64Val(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    // -----------------------------------------------------------------
    // PEM
    // -----------------------------------------------------------------

    /** Wraps der as a PEM block with the given label. */
    public static String pemWrap(String label, byte[] der) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(label).append("-----\n");
        sb.append(b64Encode(der));
        sb.append("-----END ").append(label).append("-----\n");
        return sb.toString();
    }

    public static final class PemBlock {
        public final String label;
        public final byte[] der;
        public PemBlock(String label, byte[] der) { this.label = label; this.der = der; }
    }

    /** The longest PEM label any reader accepts (TODO #400). */
    public static final int PEM_LABEL_MAX = 79;

    private static boolean pemWs(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

    private static IllegalArgumentException pemErr(String m) { return new IllegalArgumentException(m); }

    /**
     * Parses the one PEM block that is the whole of pem, returning its label and
     * DER bytes.  One framing for every reader (TODO #400), the same scan in C, Go
     * and Python: only whitespace (space, tab, CR, LF) before the BEGIN line and
     * after the END line, so a file holds exactly one block; the BEGIN line is
     * {@code -----BEGIN <label>-----}, then only spaces or tabs, the label 1 to 79
     * printable ASCII characters; the END line starts a line and repeats the label; the body
     * decodes under b64Decode's grammar (TODO #398) to at least one byte.
     */
    public static PemBlock pemUnwrap(String t) {
        int end = t.length(), p = 0;
        while (p < end && pemWs(t.charAt(p))) p++;
        if (!t.startsWith("-----BEGIN ", p)) {
            if (t.indexOf("-----BEGIN ", p) >= 0) throw pemErr("PEM: text before the BEGIN line");
            throw pemErr("PEM: missing BEGIN marker");
        }
        p += 11;
        int ls = p;
        while (p < end && t.charAt(p) != '\r' && t.charAt(p) != '\n' && !t.startsWith("-----", p)) {
            char c = t.charAt(p);
            if (c < 0x20 || c > 0x7E) throw pemErr("PEM: malformed BEGIN line");
            p++;
        }
        String label = t.substring(ls, p);
        if (!t.startsWith("-----", p) || label.isEmpty() || label.length() > PEM_LABEL_MAX) {
            throw pemErr("PEM: malformed BEGIN line");
        }
        p += 5;
        while (p < end && (t.charAt(p) == ' ' || t.charAt(p) == '\t')) p++;
        if (p >= end || (t.charAt(p) != '\r' && t.charAt(p) != '\n')) {
            throw pemErr("PEM: malformed BEGIN line");
        }
        int body = p;
        int foot = t.indexOf("-----END ", body);
        if (foot < 0) throw pemErr("PEM: missing END marker");
        if (t.charAt(foot - 1) != '\r' && t.charAt(foot - 1) != '\n') throw pemErr("PEM: malformed END line");
        p = foot + 9;
        int es = p;
        while (p < end && t.charAt(p) != '\r' && t.charAt(p) != '\n' && !t.startsWith("-----", p)) p++;
        if (!t.startsWith("-----", p)) throw pemErr("PEM: malformed END line");
        String el = t.substring(es, p);
        if (!el.equals(label)) {
            if (el.length() > PEM_LABEL_MAX) el = el.substring(0, PEM_LABEL_MAX);
            // Echoed with every character outside 0x20-0x7E as '?' (TODO #403): the
            // END label was never screened, and raw it reached stderr differently
            // per CLI.  readString's US-ASCII read makes each non-ASCII byte one U+FFFD.
            StringBuilder shown = new StringBuilder(el.length());
            for (int i = 0; i < el.length(); i++) {
                char c = el.charAt(i);
                shown.append(c >= 0x20 && c <= 0x7E ? c : '?');
            }
            el = shown.toString();
            throw pemErr("PEM: END label '" + el + "' does not match BEGIN label '" + label + "'");
        }
        p += 5;
        while (p < end && pemWs(t.charAt(p))) p++;
        if (p != end) throw pemErr("PEM: text after the END line");
        byte[] der = b64Decode(t.substring(body, foot));
        if (der.length == 0) throw pemErr("PEM: empty body");
        return new PemBlock(label, der);
    }

    // -----------------------------------------------------------------
    // DER (minimal subset: INTEGER 0x02 and SEQUENCE 0x30)
    // -----------------------------------------------------------------

    private static byte[] derEncLen(int n) {
        if (n < 0x80) {
            return new byte[] { (byte) n };
        } else if (n < 0x100) {
            return new byte[] { (byte) 0x81, (byte) n };
        } else if (n < 0x10000) {
            return new byte[] { (byte) 0x82, (byte) (n >> 8), (byte) n };
        } else if (n < 0x1000000) {
            return new byte[] { (byte) 0x83, (byte) (n >> 16), (byte) (n >> 8), (byte) n };
        } else {
            return new byte[] { (byte) 0x84, (byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8), (byte) n };
        }
    }

    private static final class Len {
        final int length;
        final int consumed;
        Len(int length, int consumed) { this.length = length; this.consumed = consumed; }
    }

    private static Len derDecLen(byte[] buf, int off) {
        if (off >= buf.length) throw new IllegalArgumentException("DER: empty length field");
        int b = buf[off] & 0xff;
        if (b < 0x80) return new Len(b, 1);
        int nb = b & 0x7f;
        if (nb > 4 || off + 1 + nb > buf.length) {
            throw new IllegalArgumentException("DER: length field too large");
        }
        int v = 0;
        for (int i = 0; i < nb; i++) {
            v = (v << 8) | (buf[off + 1 + i] & 0xff);
        }
        return new Len(v, 1 + nb);
    }

    /**
     * Encodes val as a DER INTEGER (tag 0x02). val is treated as an unsigned
     * big-endian magnitude of the given byte width; a 0x00 sign byte is
     * prepended when the high bit is set (matches Python der_int / C
     * der_int_enc / Go DerIntEnc). Pass nbytes &lt; 0 to use the minimal
     * non-zero byte width, matching der_int's default.
     */
    public static byte[] derInt(BigInteger value, int nbytes) {
        if (value.signum() < 0) throw new IllegalArgumentException("Negative integers not supported");
        if (nbytes < 0) {
            nbytes = Math.max(1, (value.bitLength() + 7) / 8);
        }
        byte[] val = new byte[nbytes];
        byte[] raw = value.toByteArray(); // two's-complement, may have leading 0x00
        int rawStart = 0;
        while (rawStart < raw.length - 1 && raw[rawStart] == 0) rawStart++;
        int rawLen = raw.length - rawStart;
        if (rawLen > nbytes) {
            throw new IllegalArgumentException("DER: value does not fit in " + nbytes + " bytes");
        }
        System.arraycopy(raw, rawStart, val, nbytes - rawLen, rawLen);
        return derInt(val);
    }

    /** Encodes val (big-endian unsigned integer bytes) as a DER INTEGER. */
    public static byte[] derInt(byte[] val) {
        boolean sign = val.length > 0 && (val[0] & 0x80) != 0;
        int content = val.length + (sign ? 1 : 0);
        byte[] lenb = derEncLen(content);
        byte[] out = new byte[1 + lenb.length + content];
        out[0] = 0x02;
        System.arraycopy(lenb, 0, out, 1, lenb.length);
        int off = 1 + lenb.length;
        if (sign) {
            out[off] = 0x00;
            off++;
        }
        System.arraycopy(val, 0, out, off, val.length);
        return out;
    }

    /** Wraps already-encoded DER items in a SEQUENCE (tag 0x30). */
    public static byte[] derSeq(byte[]... items) {
        int body = 0;
        for (byte[] it : items) body += it.length;
        byte[] lenb = derEncLen(body);
        byte[] out = new byte[1 + lenb.length + body];
        out[0] = 0x30;
        System.arraycopy(lenb, 0, out, 1, lenb.length);
        int off = 1 + lenb.length;
        for (byte[] it : items) {
            System.arraycopy(it, 0, out, off, it.length);
            off += it.length;
        }
        return out;
    }

    /**
     * Parses a DER SEQUENCE of INTEGERs into unsigned {@link BigInteger}
     * values (leading 0x00 sign bytes stripped, matching Python
     * der_parse_seq / C der_parse_seq / Go DerParseSeq).
     */
    public static List<BigInteger> derParseSeq(PemBlock b) {
        // TODO #367: the item count, against the generated table, before any
        // decoder indexes the list.  Same text in all four CLIs.
        String bad = derSeqCheck(b.label, b.der);             // TODO #405
        if (bad != null) throw new IllegalArgumentException(bad);
        List<BigInteger> ints = derParseSeq(b.der);
        DerEnc enc = derSeqScan(b.der, b.label);              // TODO #373
        for (String[] r : KeyLabelTable.DER_ITEMS) {
            if (!r[0].equals(b.label)) continue;
            int lo = Integer.parseInt(r[1]), hi = Integer.parseInt(r[2]);
            if (ints.size() < lo || ints.size() > hi) {
                throw new IllegalArgumentException("malformed PEM '" + b.label + "': "
                    + ints.size() + " DER items, expected " + (lo == hi ? "" + lo : lo + ".." + hi));
            }
            break;
        }
        // TODO #372: no field wider than its writer pads it to; #373: each
        // field encoded the one way its writer does, and its value in range.
        String msg = KeyLabelTable.fieldCheck(b.label, ints, enc.width, enc.lead);
        if (msg != null) throw new IllegalArgumentException(msg);
        return ints;
    }

    /** TODO #373: how each INTEGER is ENCODED, which derParseSeq forgets:
     *  width[i] is its encoded width (content length less a 0x00 the set top
     *  bit needs), lead[i] 1 when it starts with a 0x00 the sign does not
     *  need, 2 when with a sign byte. */
    static final class DerEnc {
        final int[] width;
        final int[] lead;
        DerEnc(int[] w, int[] z) { width = w; lead = z; }
    }

    private static boolean derLenMinimal(byte[] d, int off) {
        int b = d[off] & 0xff;
        if (b < 0x80) return true;
        int nb = b & 0x7f;
        if (nb == 0 || off + nb >= d.length || d[off + 1] == 0) return false;
        return nb > 1 || (d[off + 1] & 0xff) >= 0x80;
    }

    /** The encodings of a SEQUENCE derParseSeq has accepted.  Throws, in the
     *  text every CLI prints, on a length not in its shortest form or a
     *  negative or empty INTEGER: a SEQUENCE has one encoding of its lengths
     *  and signs (TODO #373). */
    static DerEnc derSeqScan(byte[] der, String label) {
        String where = "malformed PEM '" + label + "': ";
        if (!derLenMinimal(der, 1)) throw new IllegalArgumentException(where + "DER length not in its shortest form");
        Len l = derDecLen(der, 1);
        int offset = 1 + l.consumed, end = offset + l.length;
        List<int[]> items = new ArrayList<>();
        while (offset < end) {
            offset++;
            if (!derLenMinimal(der, offset)) {
                throw new IllegalArgumentException(where + "DER length not in its shortest form");
            }
            Len vl = derDecLen(der, offset);
            offset += vl.consumed;
            int n = items.size();
            if (vl.length == 0) throw new IllegalArgumentException(where + "field " + n + " is an empty INTEGER");
            int c0 = der[offset] & 0xff;
            if ((c0 & 0x80) != 0) throw new IllegalArgumentException(where + "field " + n + " is a negative INTEGER");
            int c1 = vl.length > 1 ? der[offset + 1] & 0xff : 0;
            boolean sign = vl.length > 1 && c0 == 0 && (c1 & 0x80) != 0;
            boolean lz = vl.length > 1 && c0 == 0 && (c1 & 0x80) == 0;
            items.add(new int[]{vl.length - (sign ? 1 : 0), sign ? 2 : lz ? 1 : 0});
            offset += vl.length;
        }
        int[] w = new int[items.size()];
        int[] z = new int[items.size()];
        for (int i = 0; i < w.length; i++) { w[i] = items.get(i)[0]; z[i] = items.get(i)[1]; }
        return new DerEnc(w, z);
    }

    /** A raw-body PEM (ZKP-NL, ZKP-RNL, HCRED) ends at its last field
     * (TODO #372); same text in all four CLIs. */
    static void rawEnd(String label, byte[] body, int off) {
        if (off < body.length) {
            throw new IllegalArgumentException("malformed PEM '" + label + "': "
                + (body.length - off) + " bytes after its last field");
        }
    }

    /** A per-round length byte other than the size n fixes: a shorter field was
     * read past (TODO #407), a longer one carried bytes nothing reads, a second
     * encoding (TODO #408).  Refused at the length byte, before the truncation
     * checks.  Same text in all four CLIs. */
    static void rawLen(String label, int round, String field, int got, int n, int need) {
        if (got != need) {
            throw new IllegalArgumentException("malformed PEM '" + label + "': round " + round
                + " " + field + " is " + got + " bytes, n=" + n + " needs " + need);
        }
    }

    /** TODO #408: an nb-byte big-endian field of an n-bit value has no bit above
     * n; the writers mask every one and nothing reads the extra bits, so a set
     * one is a second encoding.  round < 0 for a key field. */
    static void rawBits(String label, int round, String field, byte[] b, int off, int n) {
        int spare = (n + 7) / 8 * 8 - n;
        if (spare != 0 && ((u8(b, off) >> (8 - spare)) != 0)) {
            throw new IllegalArgumentException("malformed PEM '" + label + "': "
                + (round >= 0 ? "round " + round + " " : "") + field + " has bits above n=" + n);
        }
    }

    /** TODO #408: every HCRED coefficient is written reduced, Z_q (3 bytes) below
     * q = 65537 and Z_p (2 bytes) below p = 4096.  Checks cnt values of width w
     * from off; returns the offset after them. */
    static int hcredVals(String label, byte[] b, int off, int cnt, int w) {
        int lim = w == 3 ? 65537 : 4096;
        for (int i = 0; i < cnt; i++) {
            if ((long) off + w > b.length) return off;   // the reader's own truncation check
            int v = ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
            if (w == 3) v = (v << 8) | (b[off + 2] & 0xff);
            if (v >= lim)
                throw new IllegalArgumentException("malformed PEM '" + label + "': value " + v
                    + " at byte " + off + " is not below " + lim);
            off += w;
        }
        return off;
    }

    /** The 4-byte n a raw-body PEM leads with, or -1 if the body is shorter. */
    public static int rawBodyN(String pem) {
        byte[] body = pemUnwrap(pem).der;
        return body.length >= 4 ? rd4(body, 0) : -1;
    }

    /** One body byte, or the wire-format error a truncated body gets (TODO #407):
     * never a raw JDK index message. */
    private static int u8(byte[] b, int off) {
        if (off < 0 || off >= b.length) throw new IllegalArgumentException("PEM body truncated");
        return b[off] & 0xff;
    }

    /** TODO #405: the DER length field at d[p], read no further than lim:
     *  {fault, length, bytes taken}, fault 0 well formed and minimal, 1
     *  truncated, 2 longer than 4 bytes, 3 not in its shortest form.  The
     *  length is a long: a 4-byte one past 2^31 does not fit an int. */
    private static long[] derReadLen(byte[] d, int p, int lim) {
        if (p >= lim) return new long[]{1, 0, 0};
        int b = d[p] & 0xff;
        if (b < 0x80) return new long[]{0, b, 1};
        int nb = b & 0x7f;
        if (nb > 4) return new long[]{2, 0, 0};
        if (nb > lim - p - 1) return new long[]{1, 0, 0};
        long x = 0;
        for (int i = 0; i < nb; i++) x = (x << 8) | (d[p + 1 + i] & 0xff);
        boolean minimal = nb != 0 && d[p + 1] != 0 && !(nb == 1 && x < 0x80);
        return new long[]{minimal ? 0 : 3, x, 1 + nb};
    }

    private static final String[] DER_LEN_TEXT = {"", "DER length field truncated",
        "DER length field longer than 4 bytes", "DER length not in its shortest form"};

    /** TODO #405: the DER reader's refusal, specified (SPEC.md section 10.2).
     *  One left-to-right walk of a SEQUENCE of INTEGERs; the first fault met
     *  is the refusal, in the text all four CLIs print.  Returns null for a
     *  well-formed SEQUENCE; derParseSeq and derSeqScan cannot fail after it. */
    static String derSeqCheck(String label, byte[] der) {
        String where = "malformed PEM '" + label + "': ";
        if (der.length == 0 || der[0] != 0x30) return where + "not a DER SEQUENCE";
        long[] r = derReadLen(der, 1, der.length);
        if (r[0] != 0) return where + DER_LEN_TEXT[(int) r[0]];
        long off = 1 + r[2];
        if (r[1] > der.length - off) return where + "DER SEQUENCE body truncated";
        if (r[1] < der.length - off) return where + (der.length - off - r[1]) + " bytes after the DER SEQUENCE";
        for (int n = 0; off < der.length; n++) {
            int o = (int) off;
            if (der[o] != 0x02) {
                return where + String.format("field %d is not an INTEGER (tag 0x%02x)", n, der[o] & 0xff);
            }
            r = derReadLen(der, o + 1, der.length);
            if (r[0] != 0) return where + DER_LEN_TEXT[(int) r[0]];
            off += 1 + r[2];
            if (r[1] > der.length - off) return where + "field " + n + " runs past the DER SEQUENCE";
            if (r[1] == 0) return where + "field " + n + " is an empty INTEGER";
            if ((der[(int) off] & 0x80) != 0) return where + "field " + n + " is a negative INTEGER";
            off += r[1];
        }
        return null;
    }

    /** Parses a DER SEQUENCE of INTEGERs; {@link #derParseSeq(PemBlock)} also
     * checks the item count for the block's label. */
    public static List<BigInteger> derParseSeq(byte[] der) {
        if (der.length == 0 || der[0] != 0x30) {
            throw new IllegalArgumentException("DER: not a SEQUENCE");
        }
        Len l = derDecLen(der, 1);
        int offset = 1 + l.consumed;
        if (l.length < 0 || l.length > der.length) {
            throw new IllegalArgumentException("DER: SEQUENCE body truncated");
        }
        int end = offset + l.length;
        if (end > der.length) throw new IllegalArgumentException("DER: SEQUENCE body truncated");
        if (end < der.length) {   // TODO #372: nothing may follow the SEQUENCE
            throw new IllegalArgumentException("DER: " + (der.length - end) + " bytes after the DER SEQUENCE");
        }

        List<BigInteger> out = new ArrayList<>();
        while (offset < end) {
            if (der[offset] != 0x02) {
                throw new IllegalArgumentException(
                    String.format("DER: expected INTEGER tag at offset %d, got 0x%02x", offset, der[offset]));
            }
            offset++;
            Len vl = derDecLen(der, offset);
            offset += vl.consumed;
            // vl.length < 0: a 4-byte length past 2^31, read into an int.  It
            // used to reach new byte[-1] (NegativeArraySizeException; the CLI
            // printed "error: -1").  C, Go and Python read it as the large
            // length it is and refuse it here (TODO #404).
            if (vl.length < 0 || vl.length > end - offset) {
                throw new IllegalArgumentException("DER: INTEGER length exceeds SEQUENCE body");
            }
            byte[] vp = new byte[vl.length];
            System.arraycopy(der, offset, vp, 0, vl.length);
            out.add(new BigInteger(1, vp)); // unsigned; matches sign-byte stripping
            offset += vl.length;
        }
        return out;
    }

    // -----------------------------------------------------------------
    // Classical quartet: key / ciphertext / signature / session-key /
    // digest encode-decode (TODO #197)
    // -----------------------------------------------------------------

    private static final int NBYTES = Herradura.N / 8; // 32

    /** Encodes a classical private key: SEQUENCE(priv, pub, nbits). */
    public static String encodePrivKey(String label, BigInteger priv, BigInteger pub) {
        return encodePrivKey(label, priv, pub, Herradura.N);
    }

    /** The same at width nbits (TODO #384). */
    public static String encodePrivKey(String label, BigInteger priv, BigInteger pub, int nbits) {
        byte[] der = derSeq(derInt(priv, nbits / 8), derInt(pub, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(label, der);
    }

    public static final class PrivKey {
        public final BigInteger priv;
        public final BigInteger pub;
        public final int nbits;
        PrivKey(BigInteger priv, BigInteger pub, int nbits) { this.priv = priv; this.pub = pub; this.nbits = nbits; }
    }

    public static PrivKey decodePrivKey(String pem, String expectedLabel) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(expectedLabel)) {
            throw new IllegalArgumentException("Expected " + expectedLabel + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new PrivKey(ints.get(0), ints.get(1), gfWidth(ints.get(2), b.label));
    }

    /** Encodes an HDRBG checkpoint: SEQUENCE(state[32], blocks) (TODO #269).
     *
     *  `state` is a FIXED 32-byte INTEGER and `blocks` a minimal-width one,
     *  matching Python's `der_int(drbg.state.uint, KEYBITS // 8), der_int(
     *  drbg.blocks)` and C's write_hdrbg_state exactly -- the widths are the
     *  wire format here, not a formatting choice, and a state encoded at
     *  minimal width would be unreadable by the other three CLIs whenever its
     *  top byte happened to be zero. */
    public static String encodeHdrbgState(BigInteger state, long blocks) {
        byte[] der = derSeq(derInt(state, NBYTES),
                            derInt(BigInteger.valueOf(blocks), -1));
        return pemWrap(PEM_HDRBG_STATE, der);
    }

    public static final class HdrbgState {
        public final BigInteger state;
        public final long blocks;
        HdrbgState(BigInteger state, long blocks) { this.state = state; this.blocks = blocks; }
    }

    public static HdrbgState decodeHdrbgState(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HDRBG_STATE)) {
            throw new IllegalArgumentException("Expected " + PEM_HDRBG_STATE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        if (ints.size() < 2) {
            throw new IllegalArgumentException("HDRBG STATE: expected SEQUENCE(state, blocks)");
        }
        return new HdrbgState(ints.get(0), ints.get(1).longValueExact());
    }

    /** Encodes a classical public key: SEQUENCE(pub, nbits). */
    public static String encodePubKey(String label, BigInteger pub) {
        return encodePubKey(label, pub, Herradura.N);
    }

    public static String encodePubKey(String label, BigInteger pub, int nbits) {
        byte[] der = derSeq(derInt(pub, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(label, der);
    }

    public static final class PubKey {
        public final BigInteger pub;
        public final int nbits;
        PubKey(BigInteger pub, int nbits) { this.pub = pub; this.nbits = nbits; }
    }

    public static PubKey decodePubKey(String pem, String expectedLabel) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(expectedLabel)) {
            throw new IllegalArgumentException("Expected " + expectedLabel + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new PubKey(ints.get(0), gfWidth(ints.get(1), b.label));
    }

    /** Encodes an HPKE ciphertext: SEQUENCE(R, E, nbits). */
    public static String encodeAsymCt(BigInteger r, BigInteger e, int nbits) {
        byte[] der = derSeq(derInt(r, nbits / 8), derInt(e, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(PEM_CIPHERTEXT, der);
    }

    public static final class AsymCt {
        public final BigInteger r;
        public final BigInteger e;
        public final int nbits;
        AsymCt(BigInteger r, BigInteger e, int nbits) { this.r = r; this.e = e; this.nbits = nbits; }
    }

    public static AsymCt decodeAsymCt(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_CIPHERTEXT)) {
            throw new IllegalArgumentException("Expected " + PEM_CIPHERTEXT + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new AsymCt(ints.get(0), ints.get(1), gfWidth(ints.get(2), b.label));
    }

    /** Encodes an HPKS (Schnorr) signature: SEQUENCE(s, R, e, nbits). */
    public static String encodeSchnorrSig(BigInteger s, BigInteger r, BigInteger e, int nbits) {
        int nbytes = nbits / 8;
        byte[] der = derSeq(derInt(s, nbytes), derInt(r, nbytes), derInt(e, nbytes),
                             derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(PEM_SIGNATURE, der);
    }

    public static final class SchnorrSig {
        public final BigInteger s;
        public final BigInteger r;
        public final BigInteger e;
        public final int nbits;
        SchnorrSig(BigInteger s, BigInteger r, BigInteger e, int nbits) {
            this.s = s; this.r = r; this.e = e; this.nbits = nbits;
        }
    }

    public static SchnorrSig decodeSchnorrSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_SIGNATURE)) {
            throw new IllegalArgumentException("Expected " + PEM_SIGNATURE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new SchnorrSig(ints.get(0), ints.get(1), ints.get(2), gfWidth(ints.get(3), b.label));
    }

    /** Encodes an HSKE session key: SEQUENCE(key, nbits).
     *
     * The key field uses MINIMAL byte width, not the fixed nbits/8 used for
     * private/public keys and symmetric ciphertexts. This matches
     * HerraduraCli/herradura.py's _encode_session_key
     * ("nbytes = max(1, (key_int.bit_length() + 7) // 8)"), herradura_cli.go's
     * encodeSessionKey, and encodeRnlResponse below. Padding to a fixed width
     * here emits a redundant leading 0x00 whenever the key's top byte is zero
     * and the next byte is below 0x80 — non-canonical DER, and byte-different
     * from every other implementation for about 1 session key in 512 (TODO #219). */
    public static String encodeSessionKey(BigInteger key, int nbits) {
        byte[] der = derSeq(derInt(key, -1), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(PEM_SESSION_KEY, der);
    }

    public static PubKey decodeSessionKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_SESSION_KEY)) {
            throw new IllegalArgumentException("Expected " + PEM_SESSION_KEY + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new PubKey(ints.get(0), ints.get(1).intValueExact());
    }

    // -----------------------------------------------------------------
    // HKEX-RNL (TODO #199): polynomial packing + key/response encode-decode.
    // Mirrors HerraduraCli/codec.py's pack_poly/unpack_poly and
    // herradura.py's _encode_rnl_privkey/_encode_rnl_pubkey/_encode_rnl_response.
    // -----------------------------------------------------------------

    /** Packs a coefficient array into one big integer (fixed bytesPerCoeff each,
     * big-endian, concatenated) plus its total byte width. */
    public static byte[] packPoly(int[] coeffs, int bytesPerCoeff) {
        byte[] raw = new byte[coeffs.length * bytesPerCoeff];
        for (int i = 0; i < coeffs.length; i++) {
            int c = coeffs[i];
            for (int j = 0; j < bytesPerCoeff; j++) {
                raw[i * bytesPerCoeff + j] = (byte) (c >>> (8 * (bytesPerCoeff - 1 - j)));
            }
        }
        return raw;
    }

    /** Inverse of {@link #packPoly}. */
    public static int[] unpackPoly(BigInteger packed, int n, int bytesPerCoeff) {
        int total = n * bytesPerCoeff;
        byte[] raw = new byte[total];
        byte[] src = packed.toByteArray();
        int srcStart = 0;
        while (srcStart < src.length - 1 && src[srcStart] == 0) srcStart++;
        int copyLen = Math.min(total, src.length - srcStart);
        System.arraycopy(src, src.length - copyLen, raw, total - copyLen, copyLen);
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            int v = 0;
            for (int j = 0; j < bytesPerCoeff; j++) {
                v = (v << 8) | (raw[i * bytesPerCoeff + j] & 0xff);
            }
            out[i] = v;
        }
        return out;
    }

    private static final int RNL_NA_BYTES = 32;

    /** Encodes an HKEX-RNL private key: SEQUENCE(s_packed, m_blind_packed, n[, n_a]). */
    public static String encodeRnlPrivKey(int[] s, int[] mBlind, int n, byte[] nA) {
        byte[] sPacked = packPoly(s, 4);
        byte[] mPacked = packPoly(mBlind, 4);
        byte[] der;
        if (nA == null) {
            der = derSeq(derInt(sPacked), derInt(mPacked),
                          derInt(BigInteger.valueOf(n), -1));
        } else {
            der = derSeq(derInt(sPacked), derInt(mPacked),
                          derInt(BigInteger.valueOf(n), -1), derInt(nA));
        }
        return pemWrap(PEM_HKEX_RNL_PRIV, der);
    }

    public static final class RnlPrivKey {
        public final int[] s;
        public final int[] mBlind;
        public final int n;
        public final byte[] nA;
        RnlPrivKey(int[] s, int[] mBlind, int n, byte[] nA) {
            this.s = s; this.mBlind = mBlind; this.n = n; this.nA = nA;
        }
    }

    public static RnlPrivKey decodeRnlPrivKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HKEX_RNL_PRIV)) {
            throw new IllegalArgumentException("Expected " + PEM_HKEX_RNL_PRIV + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int n = rnlN(ints.get(2), "pkey");
        int[] s = unpackPoly(ints.get(0), n, 4);
        int[] mBlind = unpackPoly(ints.get(1), n, 4);
        byte[] nA = (ints.size() >= 4) ? toFixedBytes(ints.get(3), RNL_NA_BYTES) : new byte[RNL_NA_BYTES];
        return new RnlPrivKey(s, mBlind, n, nA);
    }

    /** Encodes an HKEX-RNL public key: SEQUENCE(C_packed, m_blind_packed, n[, n_a]). */
    public static String encodeRnlPubKey(int[] c, int[] mBlind, int n, byte[] nA) {
        byte[] cPacked = packPoly(c, 2);
        byte[] mPacked = packPoly(mBlind, 4);
        byte[] der;
        if (nA == null) {
            der = derSeq(derInt(cPacked), derInt(mPacked),
                          derInt(BigInteger.valueOf(n), -1));
        } else {
            der = derSeq(derInt(cPacked), derInt(mPacked),
                          derInt(BigInteger.valueOf(n), -1), derInt(nA));
        }
        return pemWrap(PEM_HKEX_RNL_PUB, der);
    }

    public static final class RnlPubKey {
        public final int[] c;
        public final int[] mBlind;
        public final int n;
        public final byte[] nA;
        RnlPubKey(int[] c, int[] mBlind, int n, byte[] nA) {
            this.c = c; this.mBlind = mBlind; this.n = n; this.nA = nA;
        }
    }

    public static RnlPubKey decodeRnlPubKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HKEX_RNL_PUB)) {
            throw new IllegalArgumentException("Expected " + PEM_HKEX_RNL_PUB + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int n = rnlN(ints.get(2), "kex");
        int[] c = unpackPoly(ints.get(0), n, 2);
        int[] mBlind = unpackPoly(ints.get(1), n, 4);
        byte[] nA = (ints.size() >= 4) ? toFixedBytes(ints.get(3), RNL_NA_BYTES) : new byte[RNL_NA_BYTES];
        return new RnlPubKey(c, mBlind, n, nA);
    }

    /** Encodes Bob's HKEX-RNL response: SEQUENCE(K_B, C_B_packed, hint_packed, n, hint_len[, n_b]). */
    public static String encodeRnlResponse(BigInteger kB, int[] cB, int[] hint, int n, byte[] nB) {
        byte[] cPacked = packPoly(cB, 2);
        int hintLen = Math.min(hint.length, n / 2);
        BigInteger hintInt = BigInteger.ZERO;
        for (int i = 0; i < hintLen; i++) {
            hintInt = hintInt.or(BigInteger.valueOf(hint[i] & 3).shiftLeft(2 * i));
        }
        byte[] fields0 = derInt(kB, Math.max(1, (kB.bitLength() + 7) / 8));
        byte[] fields1 = derInt(cPacked);
        byte[] fields2 = derInt(hintInt, Math.max(1, (2 * hintLen + 7) / 8));
        byte[] fields3 = derInt(BigInteger.valueOf(n), -1);
        byte[] fields4 = derInt(BigInteger.valueOf(hintLen), -1);
        byte[] der;
        if (nB == null) {
            der = derSeq(fields0, fields1, fields2, fields3, fields4);
        } else {
            byte[] fields5 = derInt(nB);
            der = derSeq(fields0, fields1, fields2, fields3, fields4, fields5);
        }
        return pemWrap(PEM_RNL_RESPONSE, der);
    }

    public static final class RnlResponse {
        public final BigInteger k;
        public final int[] cB;
        public final int[] hint;
        public final int n;
        public final byte[] nB;
        RnlResponse(BigInteger k, int[] cB, int[] hint, int n, byte[] nB) {
            this.k = k; this.cB = cB; this.hint = hint; this.n = n; this.nB = nB;
        }
    }

    public static RnlResponse decodeRnlResponse(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_RNL_RESPONSE)) {
            throw new IllegalArgumentException("Expected " + PEM_RNL_RESPONSE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        BigInteger k = ints.get(0);
        int n = rnlN(ints.get(3), "kex");
        int hintLen = bounded(ints.get(4), 0, n, "hint length", "kex");   // n, not n/2: Go writes n (TODO #367)
        int[] cB = unpackPoly(ints.get(1), n, 2);
        BigInteger hintInt = ints.get(2);
        int[] hint = new int[hintLen];
        for (int i = 0; i < hintLen; i++) {
            hint[i] = hintInt.shiftRight(2 * i).and(BigInteger.valueOf(3)).intValueExact();
        }
        byte[] nB = (ints.size() >= 6) ? toFixedBytes(ints.get(5), RNL_NA_BYTES) : new byte[RNL_NA_BYTES];
        return new RnlResponse(k, cB, hint, n, nB);
    }

    // ── Bounds on PEM fields that size an allocation (TODO #240) ───────────
    //
    // TODO #239 range-checked these fields in the C CLI and stopped there.  The
    // decoders below still took counts straight off the wire and multiplied
    // them into a toFixedBytes() length.  Java cannot corrupt memory over it,
    // but `d * 2` at d = 2^31-1 wraps to -2, so what surfaced was a
    // NegativeArraySizeException whose message was the wrapped product — and,
    // more importantly, an artifact the C CLI refuses was one this CLI tried.
    //
    // Reject rather than clamp, inside the decoder, before the arithmetic.

    /** herradura_cli.c XMSS_MAX_H; also genpkey's --xmss-height cap. */
    public static final int XMSS_MAX_H = 20;
    /** herradura.h SDF_MAX_ROUNDS (TODO #236). */
    public static final int SDF_MAX_ROUNDS = 4096;
    /** herradura_cli.c RING_MAX_K (TODO #260). */
    public static final int RING_MAX_K = 64;

    /** Returns v, or throws if it falls outside [lo, hi].  {@code what} names
     * the field as the wire calls it; {@code where} is the subcommand, so the
     * message shape matches the C, Go and Python CLIs'. */
    /** TODO #371: a width the artifact DECLARES must be the width this port runs.
     * GF arithmetic here is fixed at Herradura.N and the QC-MDPC code at
     * Stern.QCMDPC_R, so any other value used to reach the arithmetic and fail
     * inside it (E_MIXED_WIDTH, E_RANGE).  Worded as in the C CLI. */
    static int runWidth(BigInteger v, int want, String what, String label) {
        if (v.signum() < 0 || v.bitLength() > 31) {
            throw new IllegalArgumentException("PEM '" + label + "': " + what
                + " is wider than 32 bits (this CLI runs " + what + " = " + want + ")");
        }
        int got = v.intValueExact();
        if (got != want) {
            throw new IllegalArgumentException("PEM '" + label + "': " + what + " is " + got
                + " (this CLI runs " + what + " = " + want + ")");
        }
        return got;
    }

    /** TODO #384: a GF(2^n)-family or Stern-F width is any width with a GF(2^n)
     * polynomial (BITARRAY.md 4.6: 32, 64, 128, 256), as in the C CLI
     * (gf_width_ok) and worded as its refusal is. */
    static boolean gfWidthOk(int n) {
        try { BitArray.gfPoly(n); return true; } catch (BaException e) { return false; }
    }

    static int gfWidth(BigInteger v, String label) {
        if (v.signum() < 0 || v.bitLength() > 31)
            throw new IllegalArgumentException("PEM '" + label + "': n is wider than 32 bits "
                + "(this CLI runs n = 32, 64, 128 or 256)");
        int got = v.intValueExact();
        if (!gfWidthOk(got))
            throw new IllegalArgumentException("PEM '" + label + "': n is " + got
                + " (this CLI runs n = 32, 64, 128 or 256)");
        return got;
    }

    private static int bounded(BigInteger value, int lo, int hi, String what, String where) {
        // intValueExact() already refuses anything too wide for an int; the
        // range check below is what stops the in-range-but-absurd values.
        int v;
        try {
            v = value.intValueExact();
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(where + ": " + what + " is " + value
                + " (expected " + lo + ".." + hi + ")");
        }
        if (v < lo || v > hi) {
            throw new IllegalArgumentException(where + ": " + what + " is " + v
                + " (expected " + lo + ".." + hi + ")");
        }
        return v;
    }

    /** Bounds a wire-supplied HKEX-RNL ring dimension: a power of two from 8 to
     * the deployed RNLN (TODO #367).  It sizes every polynomial unpacked after
     * it; Go and Python bound it the same way, C requires RNLN exactly. */
    static int rnlN(BigInteger value, String where) {
        int v = bounded(value, 8, HerraduraNl.RNLN, "ring dimension n", where);
        if ((v & (v - 1)) != 0) {
            throw new IllegalArgumentException(where + ": ring dimension n is " + v
                + " (expected a power of two)");
        }
        return v;
    }

    /** Bounds a wire-supplied bit width: a multiple of 8, no wider than the
     * suite's own key width. */
    /** A Stern-F key's n: gfWidth's widths, or the long form's 2304 (TODO #382). */
    static int sternWidth(BigInteger v, String label) {
        if (v.equals(BigInteger.valueOf(SternL.STERN_LONG_N))) return SternL.STERN_LONG_N;
        return gfWidth(v, label);
    }

    /** boundedN for a Stern-F code length, which may be the long form's 2304. */
    private static int boundedSternN(BigInteger value, String where) {
        if (value.equals(BigInteger.valueOf(SternL.STERN_LONG_N))) return SternL.STERN_LONG_N;
        return boundedN(value, where);
    }

    /** Commitment bytes: min(n, 256) / 8 (TODO #382). */
    static int commitBytes(int n) { return Math.min(n, 256) / 8; }

    private static int boundedN(BigInteger value, String where) {
        int v = bounded(value, 8, Herradura.N, "n", where);
        if (v % 8 != 0) {
            throw new IllegalArgumentException(where + ": n is " + v
                + " (expected a multiple of 8)");
        }
        return v;
    }

    private static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    /** Encodes an HFSCX-256 digest: SEQUENCE(digest as 32-byte INTEGER). */

    // =================================================================
    // TODO #261 (v6.0.0) — wire formats for the five algo tags the Java
    // CLI was missing.  All of these are RAW-BINARY bodies (no DER)
    // except the hybrid response, which is DER like the other kex
    // responses; each layout below is transcribed from
    // HerraduraCli/codec.py so the four CLIs stay byte-compatible.
    // =================================================================

    // ── ZKP-NL keypair ──────────────────────────────────────────────
    //   PRIVATE: 4B n | nb A | nb B | nb y     (nb = ceil(n/8))
    //   PUBLIC : 4B n | nb B | nb y

    private static byte[] be4(int v) {
        return new byte[] { (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v };
    }

    private static int rd4(byte[] b, int off) {
        if (off < 0 || (long) off + 4 > b.length) throw new IllegalArgumentException("PEM body truncated");
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
             | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    private static byte[] fixed(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int start = Math.max(0, raw.length - nbytes);
        int len = Math.min(raw.length - start, nbytes);
        System.arraycopy(raw, raw.length - len, out, nbytes - len, len);
        return out;
    }

    private static byte[] sub(byte[] b, int off, int len) {
        if (off + len > b.length) throw new IllegalArgumentException("PEM body truncated");
        byte[] out = new byte[len];
        System.arraycopy(b, off, out, 0, len);
        return out;
    }

    private static byte[] join(java.util.List<byte[]> parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, off, p.length); off += p.length; }
        return out;
    }

    public static String encodeZkpNlPrivKey(BigInteger a, BigInteger b, BigInteger y, int n) {
        int nb = (n + 7) / 8;
        java.util.List<byte[]> parts = new ArrayList<>();
        parts.add(be4(n)); parts.add(fixed(a, nb)); parts.add(fixed(b, nb)); parts.add(fixed(y, nb));
        return pemWrap(PEM_ZKP_NL_PRIV, join(parts));
    }

    /** ZKP-NL private key: {A, B, y} plus n. */
    public static final class ZkpNlPrivKey {
        public final BigInteger a, b, y;
        public final int n;
        ZkpNlPrivKey(BigInteger a, BigInteger b, BigInteger y, int n) {
            this.a = a; this.b = b; this.y = y; this.n = n;
        }
    }

    public static ZkpNlPrivKey decodeZkpNlPrivKey(String pem) {
        PemBlock blk = pemUnwrap(pem);
        if (!blk.label.equals(PEM_ZKP_NL_PRIV)) {
            throw new IllegalArgumentException("Unexpected PEM label: " + blk.label);
        }
        byte[] body = blk.der;
        int n = rd4(body, 0);
        if (n <= 0 || n > 1 << 20) throw new IllegalArgumentException("ZKP-NL: bad n " + n);
        int nb = (n + 7) / 8;
        rawEnd(PEM_ZKP_NL_PRIV, body, 4 + 3 * nb);
        rawBits(PEM_ZKP_NL_PRIV, -1, "A", body, 4, n);           // TODO #408
        rawBits(PEM_ZKP_NL_PRIV, -1, "B", body, 4 + nb, n);
        rawBits(PEM_ZKP_NL_PRIV, -1, "y", body, 4 + 2 * nb, n);
        return new ZkpNlPrivKey(new BigInteger(1, sub(body, 4, nb)),
                                new BigInteger(1, sub(body, 4 + nb, nb)),
                                new BigInteger(1, sub(body, 4 + 2 * nb, nb)), n);
    }

    public static String encodeZkpNlPubKey(BigInteger b, BigInteger y, int n) {
        int nb = (n + 7) / 8;
        java.util.List<byte[]> parts = new ArrayList<>();
        parts.add(be4(n)); parts.add(fixed(b, nb)); parts.add(fixed(y, nb));
        return pemWrap(PEM_ZKP_NL_PUB, join(parts));
    }

    /** ZKP-NL public key: {B, y} plus n. */
    public static final class ZkpNlPubKey {
        public final BigInteger b, y;
        public final int n;
        ZkpNlPubKey(BigInteger b, BigInteger y, int n) { this.b = b; this.y = y; this.n = n; }
    }

    public static ZkpNlPubKey decodeZkpNlPubKey(String pem) {
        PemBlock blk = pemUnwrap(pem);
        if (!blk.label.equals(PEM_ZKP_NL_PUB)) {
            throw new IllegalArgumentException("Unexpected PEM label: " + blk.label);
        }
        byte[] body = blk.der;
        int n = rd4(body, 0);
        if (n <= 0 || n > 1 << 20) throw new IllegalArgumentException("ZKP-NL: bad n " + n);
        int nb = (n + 7) / 8;
        rawEnd(PEM_ZKP_NL_PUB, body, 4 + 2 * nb);
        rawBits(PEM_ZKP_NL_PUB, -1, "B", body, 4, n);            // TODO #408
        rawBits(PEM_ZKP_NL_PUB, -1, "y", body, 4 + nb, n);
        return new ZkpNlPubKey(new BigInteger(1, sub(body, 4, nb)),
                               new BigInteger(1, sub(body, 4 + nb, nb)), n);
    }

    // ── ZKBoo proof (nl-zkboo) ──────────────────────────────────────
    //   4B n | 4B rounds | per round:
    //     32B com0 | 32B com1 | 32B com2 | 1B e
    //     | 2B len_p1 | view_p1 | 2B len_p2 | view_p2

    public static String encodeZkpNlProof(java.util.List<ZkpNl.ProofRound> rounds, int n) {
        java.util.List<byte[]> parts = new ArrayList<>();
        parts.add(be4(n)); parts.add(be4(rounds.size()));
        for (ZkpNl.ProofRound r : rounds) {
            parts.add(r.com0); parts.add(r.com1); parts.add(r.com2);
            parts.add(new byte[] { (byte) r.e });
            parts.add(new byte[] { (byte) (r.viewP1.length >>> 8), (byte) r.viewP1.length });
            parts.add(r.viewP1);
            parts.add(new byte[] { (byte) (r.viewP2.length >>> 8), (byte) r.viewP2.length });
            parts.add(r.viewP2);
        }
        return pemWrap(PEM_ZKP_NL_PROOF, join(parts));
    }

    /** Decoded ZKBoo proof: the rounds plus the n they were made at. */
    public static final class ZkpNlProof {
        public final java.util.List<ZkpNl.ProofRound> rounds;
        public final int n;
        ZkpNlProof(java.util.List<ZkpNl.ProofRound> rounds, int n) { this.rounds = rounds; this.n = n; }
    }

    public static ZkpNlProof decodeZkpNlProof(String pem) {
        PemBlock blk = pemUnwrap(pem);
        if (!blk.label.equals(PEM_ZKP_NL_PROOF)) {
            throw new IllegalArgumentException("Unexpected PEM label: " + blk.label);
        }
        byte[] body = blk.der;
        int off = 0;
        int n = rd4(body, off); off += 4;
        int r = rd4(body, off); off += 4;
        if (n <= 0 || n > ZkpNl.MAX_N || r <= 0 || r > ZkpNl.MAX_ROUNDS)
            throw new IllegalArgumentException("ZKP-NL proof: bad header (n=" + n + ", rounds=" + r + ")");
        java.util.List<ZkpNl.ProofRound> rounds = new ArrayList<>(r);
        int nbv = (n + 7) / 8;
        int viewNeed = 2 * nbv + 32 + n - 1;   // the view the verifier reads
        for (int j = 0; j < r; j++) {
            ZkpNl.ProofRound pr = new ZkpNl.ProofRound();
            pr.com0 = sub(body, off, 32); off += 32;
            pr.com1 = sub(body, off, 32); off += 32;
            pr.com2 = sub(body, off, 32); off += 32;
            pr.e = u8(body, off); off += 1;
            int l1 = (u8(body, off) << 8) | u8(body, off + 1); off += 2;
            rawLen(PEM_ZKP_NL_PROOF, j, "view_p1", l1, n, viewNeed);
            pr.viewP1 = sub(body, off, l1);
            rawBits(PEM_ZKP_NL_PROOF, j, "view_p1 share", body, off, n);
            rawBits(PEM_ZKP_NL_PROOF, j, "view_p1 out", body, off + nbv + 32, n);
            off += l1;
            int l2 = (u8(body, off) << 8) | u8(body, off + 1); off += 2;
            rawLen(PEM_ZKP_NL_PROOF, j, "view_p2", l2, n, viewNeed);
            pr.viewP2 = sub(body, off, l2);
            rawBits(PEM_ZKP_NL_PROOF, j, "view_p2 share", body, off, n);
            rawBits(PEM_ZKP_NL_PROOF, j, "view_p2 out", body, off + nbv + 32, n);
            off += l2;
            rounds.add(pr);
        }
        rawEnd(PEM_ZKP_NL_PROOF, body, off);
        return new ZkpNlProof(rounds, n);
    }

    // ── ZKB++ proof (nl-zkbpp) ──────────────────────────────────────
    //   4B n | 4B rounds | per round:
    //     32B com_e | 1B e | nb out_e | 16B seed_p1 | 16B seed_p2
    //     | 1B gates_len | gates_p2 | 1B has_share2 | [nb share2]

    public static String encodeZkpNlPpProof(java.util.List<ZkpNl.PpRound> rounds, int n) {
        java.util.List<byte[]> parts = new ArrayList<>();
        parts.add(be4(n)); parts.add(be4(rounds.size()));
        for (ZkpNl.PpRound r : rounds) {
            parts.add(r.comE);
            parts.add(new byte[] { (byte) r.e });
            parts.add(r.outE);
            parts.add(r.seedP1);
            parts.add(r.seedP2);
            parts.add(new byte[] { (byte) r.gatesP2.length });
            parts.add(r.gatesP2);
            boolean has = r.share2.length > 0;
            parts.add(new byte[] { (byte) (has ? 1 : 0) });
            if (has) parts.add(r.share2);
        }
        return pemWrap(PEM_ZKP_NL_PP_SIG, join(parts));
    }

    /** Decoded ZKB++ proof: the rounds plus the n they were made at. */
    public static final class ZkpNlPpProof {
        public final java.util.List<ZkpNl.PpRound> rounds;
        public final int n;
        ZkpNlPpProof(java.util.List<ZkpNl.PpRound> rounds, int n) { this.rounds = rounds; this.n = n; }
    }

    public static ZkpNlPpProof decodeZkpNlPpProof(String pem) {
        PemBlock blk = pemUnwrap(pem);
        if (!blk.label.equals(PEM_ZKP_NL_PP_SIG)) {
            throw new IllegalArgumentException("Unexpected PEM label: " + blk.label);
        }
        byte[] body = blk.der;
        int off = 0;
        int n = rd4(body, off); off += 4;
        int r = rd4(body, off); off += 4;
        if (n <= 0 || n > ZkpNl.MAX_N || r <= 0 || r > ZkpNl.MAX_ROUNDS)
            throw new IllegalArgumentException("ZKB++ proof: bad header (n=" + n + ", rounds=" + r + ")");
        int nb = (n + 7) / 8;
        int gatesNeed = (Math.max(n - 1, 1) + 7) / 8;   // the gate bytes the verifier reads
        java.util.List<ZkpNl.PpRound> rounds = new ArrayList<>(r);
        for (int j = 0; j < r; j++) {
            ZkpNl.PpRound pr = new ZkpNl.PpRound();
            pr.comE = sub(body, off, 32); off += 32;
            pr.e = u8(body, off); off += 1;
            rawBits(PEM_ZKP_NL_PP_SIG, j, "out_e", body, off, n);
            pr.outE = sub(body, off, nb); off += nb;
            pr.seedP1 = sub(body, off, ZkpNl.ZKPP_SEED_BYTES); off += ZkpNl.ZKPP_SEED_BYTES;
            pr.seedP2 = sub(body, off, ZkpNl.ZKPP_SEED_BYTES); off += ZkpNl.ZKPP_SEED_BYTES;
            int gl = u8(body, off); off += 1;
            rawLen(PEM_ZKP_NL_PP_SIG, j, "gates_p2", gl, n, gatesNeed);
            pr.gatesP2 = sub(body, off, gl); off += gl;
            int has = u8(body, off); off += 1;
            int needS2 = pr.e != 2 ? 1 : 0;   // the writer sends share2 exactly when e != 2 (TODO #408)
            if (has != needS2)
                throw new IllegalArgumentException("malformed PEM '" + PEM_ZKP_NL_PP_SIG + "': round " + j
                    + " has_share2 is " + has + ", e=" + pr.e + " needs " + needS2);
            if (has != 0) {
                pr.share2 = sub(body, off, nb);
                rawBits(PEM_ZKP_NL_PP_SIG, j, "share2", body, off, n);
                off += nb;
            }
            else pr.share2 = new byte[0];
            rounds.add(pr);
        }
        rawEnd(PEM_ZKP_NL_PP_SIG, body, off);
        return new ZkpNlPpProof(rounds, n);
    }

    // ── ZKP-RNL Sigma proof (rnl-sigma) ─────────────────────────────
    //   4B n | n x s32be w | n x u32be c | n x s32be z

    private static void putS32(java.util.List<byte[]> parts, int[] vals) {
        byte[] out = new byte[vals.length * 4];
        for (int i = 0; i < vals.length; i++) {
            int v = vals[i];
            out[4 * i] = (byte) (v >>> 24); out[4 * i + 1] = (byte) (v >>> 16);
            out[4 * i + 2] = (byte) (v >>> 8); out[4 * i + 3] = (byte) v;
        }
        parts.add(out);
    }

    public static String encodeZkpRnlProof(int[] w, int[] c, int[] z, int n) {
        java.util.List<byte[]> parts = new ArrayList<>();
        parts.add(be4(n));
        putS32(parts, w); putS32(parts, c); putS32(parts, z);
        return pemWrap(PEM_ZKP_RNL_PROOF, join(parts));
    }

    /** Decoded Sigma proof triple plus its n. */
    public static final class ZkpRnlProof {
        public final int[] w, c, z;
        public final int n;
        ZkpRnlProof(int[] w, int[] c, int[] z, int n) { this.w = w; this.c = c; this.z = z; this.n = n; }
    }

    public static ZkpRnlProof decodeZkpRnlProof(String pem) {
        PemBlock blk = pemUnwrap(pem);
        if (!blk.label.equals(PEM_ZKP_RNL_PROOF)) {
            throw new IllegalArgumentException("Unexpected PEM label: " + blk.label);
        }
        byte[] body = blk.der;
        int n = rd4(body, 0);
        if (n <= 0 || n > 1 << 20) throw new IllegalArgumentException("ZKP-RNL: bad n " + n);
        if (body.length < 4 + 12 * n) throw new IllegalArgumentException("ZKP-RNL: body truncated");
        int[] w = new int[n], c = new int[n], z = new int[n];
        int off = 4;
        for (int i = 0; i < n; i++) { w[i] = rd4(body, off); off += 4; }   // signed
        for (int i = 0; i < n; i++) { c[i] = rd4(body, off); off += 4; }   // unsigned (< 2^31)
        for (int i = 0; i < n; i++) { z[i] = rd4(body, off); off += 4; }   // signed
        rawEnd(PEM_ZKP_RNL_PROOF, body, off);
        return new ZkpRnlProof(w, c, z, n);
    }


    // ── hybrid-rnl-stern response (TODO #261) ───────────────────────
    //   DER SEQUENCE(K, C_B_packed, hint_packed, n, hint_len, n_B, syn, r_qc)
    //   Eight fields, all mandatory — unlike the plain HKEX-RNL response,
    //   whose n_B is optional for pre-TODO-#89 compatibility.

    public static String encodeHybridResponse(BigInteger k, int[] cB, int[] hintUsed,
                                               int n, byte[] nB, BigInteger syn, int rQc) {
        byte[] cPacked = packPoly(cB, 2);
        BigInteger hintInt = BigInteger.ZERO;
        for (int i = 0; i < hintUsed.length; i++) {
            hintInt = hintInt.or(BigInteger.valueOf(hintUsed[i] & 3).shiftLeft(2 * i));
        }
        int rb = (rQc + 7) / 8;
        byte[] der = derSeq(
            derInt(k, Math.max(1, (k.bitLength() + 7) / 8)),
            derInt(cPacked),
            derInt(hintInt, Math.max(1, (2 * hintUsed.length + 7) / 8)),
            derInt(BigInteger.valueOf(n), -1),
            derInt(BigInteger.valueOf(hintUsed.length), -1),
            derInt(new BigInteger(1, nB), nB.length),
            derInt(syn, rb),
            derInt(BigInteger.valueOf(rQc), -1));
        return pemWrap(PEM_HYBRID_RESPONSE, der);
    }

    /** Decoded hybrid-rnl-stern response. */
    public static final class HybridResponse {
        public final BigInteger k, syn;
        public final int[] cB, hint;
        public final int n, rQc;
        public final byte[] nB;
        HybridResponse(BigInteger k, int[] cB, int[] hint, int n, byte[] nB,
                       BigInteger syn, int rQc) {
            this.k = k; this.cB = cB; this.hint = hint; this.n = n;
            this.nB = nB; this.syn = syn; this.rQc = rQc;
        }
    }

    public static HybridResponse decodeHybridResponse(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HYBRID_RESPONSE)) {
            throw new IllegalArgumentException("Expected " + PEM_HYBRID_RESPONSE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        if (ints.size() < 8) {
            throw new IllegalArgumentException("HYBRID-RNL-STERN RESPONSE: expected 8 fields, got " + ints.size());
        }
        int n = rnlN(ints.get(3), "kex");
        int hintLen = bounded(ints.get(4), 0, n, "hint length", "kex");   // n, not n/2: Go writes n (TODO #367)
        int rQc = runWidth(ints.get(7), Stern.QCMDPC_R, "r", b.label);   // TODO #371
        // Bound every field that sizes an allocation before it is used (TODO #240).
        if (n <= 0 || n > 1 << 16) throw new IllegalArgumentException("HYBRID response: bad n " + n);
        if (hintLen < 0 || hintLen > n) {
            throw new IllegalArgumentException("HYBRID response: bad hint_len " + hintLen);
        }
        if (rQc <= 0 || rQc > 1 << 20) throw new IllegalArgumentException("HYBRID response: bad r " + rQc);
        int[] cB = unpackPoly(ints.get(1), n, 2);
        BigInteger hintInt = ints.get(2);
        int[] hint = new int[hintLen];
        for (int i = 0; i < hintLen; i++) {
            hint[i] = hintInt.shiftRight(2 * i).and(BigInteger.valueOf(3)).intValueExact();
        }
        byte[] nB = toFixedBytes(ints.get(5), RNL_NA_BYTES);
        return new HybridResponse(ints.get(0), cB, hint, n, nB, ints.get(6), rQc);
    }

    public static String encodeDigest(BigInteger digest) {
        byte[] der = derSeq(derInt(digest, 32));
        return pemWrap(PEM_DIGEST, der);
    }

    public static BigInteger decodeDigest(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_DIGEST)) {
            throw new IllegalArgumentException("Expected " + PEM_DIGEST + ", got " + b.label);
        }
        return derParseSeq(b).get(0);
    }

    // -----------------------------------------------------------------
    // HPKS-Stern-F / HPKE-Stern-F (TODO #200): key / ciphertext / signature
    // encode-decode, byte-for-byte with HerraduraCli/herradura.py's
    // _encode_stern_privkey/_encode_stern_pubkey/_encode_stern_ct/
    // _pack_stern_sig / _unpack_stern_sig.
    // -----------------------------------------------------------------

    /** Encodes a Stern-F private key: SEQUENCE(e, seed, n). */
    public static String encodeSternPrivKey(String label, BigInteger e, BigInteger seed) {
        return encodeSternPrivKey(label, e, seed, Herradura.N);
    }

    public static String encodeSternPrivKey(String label, BigInteger e, BigInteger seed, int n) {
        byte[] der = derSeq(derInt(e, n / 8), derInt(seed, n / 8), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(label, der);
    }

    public static final class SternPrivKey {
        public final BigInteger e;
        public final BigInteger seed;
        public final int nbits;
        SternPrivKey(BigInteger e, BigInteger seed, int nbits) { this.e = e; this.seed = seed; this.nbits = nbits; }
    }

    public static SternPrivKey decodeSternPrivKey(String pem, String expectedLabel) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(expectedLabel)) {
            throw new IllegalArgumentException("Expected " + expectedLabel + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new SternPrivKey(ints.get(0), ints.get(1), sternWidth(ints.get(2), b.label));
    }

    /** Encodes a Stern-F public key: SEQUENCE(syndrome, seed, n). */
    public static String encodeSternPubKey(String label, BigInteger syndrome, BigInteger seed) {
        return encodeSternPubKey(label, syndrome, seed, Herradura.N);
    }

    public static String encodeSternPubKey(String label, BigInteger syndrome, BigInteger seed, int n) {
        byte[] der = derSeq(derInt(syndrome, n / 8), derInt(seed, n / 8), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(label, der);
    }

    public static final class SternPubKey {
        public final BigInteger syndrome;
        public final BigInteger seed;
        public final int nbits;
        SternPubKey(BigInteger syndrome, BigInteger seed, int nbits) { this.syndrome = syndrome; this.seed = seed; this.nbits = nbits; }
    }

    public static SternPubKey decodeSternPubKey(String pem, String expectedLabel) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(expectedLabel)) {
            throw new IllegalArgumentException("Expected " + expectedLabel + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new SternPubKey(ints.get(0), ints.get(1), sternWidth(ints.get(2), b.label));
    }

    /**
     * Encodes an HPKS-Stern-F signature: SEQUENCE(n, rounds, commits_packed,
     * challenges_packed, responses_packed). commits_packed is
     * (c0||c1||c2) per round; challenges_packed is 2 bits/round packed
     * 4-per-byte LSB-first; responses_packed is (resp0||resp1) per round.
     */
    public static String encodeSternSig(Stern.SternSignature sig) { return encodeSternSig(sig, Herradura.N); }

    public static String encodeSternSig(Stern.SternSignature sig, int n) {
        int rounds = sig.rounds();
        byte[] commits = packSternTriples(sig.c0, sig.c1, sig.c2, rounds, commitBytes(n));
        byte[] challenges = packChallenges(sig.challenges);
        byte[] responses = packSternPairs(sig.resp0, sig.resp1, rounds, n / 8);
        byte[] der = derSeq(derInt(BigInteger.valueOf(n), -1), derInt(BigInteger.valueOf(rounds), -1),
                             derInt(commits), derInt(challenges), derInt(responses));
        return pemWrap(PEM_SIGNATURE, der);
    }

    public static final class SternSigDecoded {
        public final int nbits;
        public final Stern.SternSignature sig;
        SternSigDecoded(int nbits, Stern.SternSignature sig) { this.nbits = nbits; this.sig = sig; }
    }

    public static SternSigDecoded decodeSternSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_SIGNATURE)) {
            throw new IllegalArgumentException("Expected " + PEM_SIGNATURE + ", got " + b.label);
        }
        return decodeSternSigDer(b);
    }

    /** Shared DER body parser for {@link #decodeSternSig} and
     * {@link #decodeHcredCredential} (identical wire shape, different label). */
    private static SternSigDecoded decodeSternSigDer(PemBlock blk) {
        List<BigInteger> ints = derParseSeq(blk);
        int nbits = boundedSternN(ints.get(0), "verify");
        int rounds = bounded(ints.get(1), 1, SDF_MAX_ROUNDS, "round count", "verify");
        int nbytes = nbits / 8;
        int cb = commitBytes(nbits);
        byte[] commits = toFixedBytes(ints.get(2), 3 * rounds * cb);
        byte[] challenges = toFixedBytes(ints.get(3), (rounds + 3) / 4);
        byte[] responses = toFixedBytes(ints.get(4), 2 * rounds * nbytes);

        BigInteger[] c0 = new BigInteger[rounds], c1 = new BigInteger[rounds], c2 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            c0[i] = new BigInteger(1, slice(commits, (3 * i) * cb, cb));
            c1[i] = new BigInteger(1, slice(commits, (3 * i + 1) * cb, cb));
            c2[i] = new BigInteger(1, slice(commits, (3 * i + 2) * cb, cb));
        }
        int[] ch = unpackChallenges(challenges, rounds);
        BigInteger[] resp0 = new BigInteger[rounds], resp1 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            resp0[i] = new BigInteger(1, slice(responses, (2 * i) * nbytes, nbytes));
            resp1[i] = new BigInteger(1, slice(responses, (2 * i + 1) * nbytes, nbytes));
        }
        return new SternSigDecoded(nbits, new Stern.SternSignature(c0, c1, c2, ch, resp0, resp1));
    }

    private static byte[] packSternTriples(BigInteger[] a, BigInteger[] b, BigInteger[] c, int rounds, int nbytes) {
        byte[] out = new byte[3 * rounds * nbytes];
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(toFixedBytes(a[i], nbytes), 0, out, (3 * i) * nbytes, nbytes);
            System.arraycopy(toFixedBytes(b[i], nbytes), 0, out, (3 * i + 1) * nbytes, nbytes);
            System.arraycopy(toFixedBytes(c[i], nbytes), 0, out, (3 * i + 2) * nbytes, nbytes);
        }
        return out;
    }

    private static byte[] packSternPairs(BigInteger[] a, BigInteger[] b, int rounds, int nbytes) {
        byte[] out = new byte[2 * rounds * nbytes];
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(toFixedBytes(a[i], nbytes), 0, out, (2 * i) * nbytes, nbytes);
            System.arraycopy(toFixedBytes(b[i], nbytes), 0, out, (2 * i + 1) * nbytes, nbytes);
        }
        return out;
    }

    private static byte[] packChallenges(int[] challenges) {
        byte[] out = new byte[(challenges.length + 3) / 4];
        for (int i = 0; i < challenges.length; i++) {
            out[i / 4] |= (byte) ((challenges[i] & 3) << ((i % 4) * 2));
        }
        return out;
    }

    private static int[] unpackChallenges(byte[] packed, int rounds) {
        int[] out = new int[rounds];
        for (int i = 0; i < rounds; i++) {
            out[i] = (packed[i / 4] >> ((i % 4) * 2)) & 3;
        }
        return out;
    }

    private static byte[] slice(byte[] src, int off, int len) {
        if (len < 0 || off < 0 || (long) off + (long) len > src.length)
            throw new IllegalArgumentException("packed body truncated");
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    // -----------------------------------------------------------------
    // HPKE-Stern-KEM (TODO #200): real QC-MDPC/BGF Niederreiter KEM key /
    // ciphertext encode-decode, byte-for-byte with HerraduraCli/herradura.py's
    // _encode_kem_privkey/_encode_kem_pubkey/_encode_kem_ct. h0/h1/h_pub are
    // serialized little-endian (unlike the rest of the suite's big-endian
    // convention) — the DER INTEGER's raw content bytes ARE the little-endian
    // byte string, per herradura.py's h0.to_bytes(rb,'little') reinterpreted
    // as a big-endian DER integer.
    // -----------------------------------------------------------------

    private static final int QCMDPC_RB = (Stern.QCMDPC_R + 7) / 8; // 1541

    public static String encodeKemPrivKey(BigInteger h0, BigInteger h1, int[] sup0, int[] sup1) {
        byte[] der = derSeq(
            derInt(Stern.toFixedBytesLE(h0, QCMDPC_RB)),
            derInt(Stern.toFixedBytesLE(h1, QCMDPC_RB)),
            derInt(encodeSupportSet(sup0)),
            derInt(encodeSupportSet(sup1)),
            derInt(BigInteger.valueOf(Stern.QCMDPC_R), -1),
            derInt(BigInteger.valueOf(Stern.QCMDPC_D), -1));
        return pemWrap(PEM_HPKE_STERN_KEM_PRIV, der);
    }

    public static final class KemPrivKey {
        public final BigInteger h0, h1;
        public final int[] sup0, sup1;
        public final int r, d;
        KemPrivKey(BigInteger h0, BigInteger h1, int[] sup0, int[] sup1, int r, int d) {
            this.h0 = h0; this.h1 = h1; this.sup0 = sup0; this.sup1 = sup1; this.r = r; this.d = d;
        }
    }

    public static KemPrivKey decodeKemPrivKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKE_STERN_KEM_PRIV)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKE_STERN_KEM_PRIV + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        // r and d each size a toFixedBytes() below; d additionally indexes the
        // support arrays, and `d * 2` overflowed int before this bound existed.
        int r = runWidth(ints.get(4), Stern.QCMDPC_R, "r", b.label);   // TODO #371: exact, not 1..R
        int d = bounded(ints.get(5), 1, Stern.QCMDPC_D, "QC-MDPC row weight d", "pkey");
        int rb = (r + 7) / 8;
        BigInteger h0 = leReverseToInt(toFixedBytes(ints.get(0), rb));
        BigInteger h1 = leReverseToInt(toFixedBytes(ints.get(1), rb));
        int[] sup0 = decodeSupportSet(toFixedBytes(ints.get(2), d * 2), d);
        int[] sup1 = decodeSupportSet(toFixedBytes(ints.get(3), d * 2), d);
        return new KemPrivKey(h0, h1, sup0, sup1, r, d);
    }

    public static String encodeKemPubKey(BigInteger hPub) {
        byte[] der = derSeq(derInt(Stern.toFixedBytesLE(hPub, QCMDPC_RB)), derInt(BigInteger.valueOf(Stern.QCMDPC_R), -1));
        return pemWrap(PEM_HPKE_STERN_KEM_PUB, der);
    }

    public static final class KemPubKey {
        public final BigInteger hPub;
        public final int r;
        KemPubKey(BigInteger hPub, int r) { this.hPub = hPub; this.r = r; }
    }

    public static KemPubKey decodeKemPubKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKE_STERN_KEM_PUB)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKE_STERN_KEM_PUB + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int r = runWidth(ints.get(1), Stern.QCMDPC_R, "r", b.label);   // TODO #371: exact, not 1..R
        int rb = (r + 7) / 8;
        BigInteger hPub = leReverseToInt(toFixedBytes(ints.get(0), rb));
        return new KemPubKey(hPub, r);
    }

    /** Encodes an HPKE-Stern-KEM ciphertext: SEQUENCE(syn, E, r). */
    public static String encodeKemCt(BigInteger syn, BigInteger e) {
        byte[] der = derSeq(derInt(Stern.toFixedBytesLE(syn, QCMDPC_RB)), derInt(e, NBYTES),
                             derInt(BigInteger.valueOf(Stern.QCMDPC_R), -1));
        return pemWrap(PEM_CIPHERTEXT, der);
    }

    public static final class KemCt {
        public final BigInteger syn;
        public final BigInteger e;
        public final int r;
        KemCt(BigInteger syn, BigInteger e, int r) { this.syn = syn; this.e = e; this.r = r; }
    }

    public static KemCt decodeKemCt(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_CIPHERTEXT)) {
            throw new IllegalArgumentException("Expected " + PEM_CIPHERTEXT + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int r = runWidth(ints.get(2), Stern.QCMDPC_R, "r", b.label);
        int rb = (r + 7) / 8;
        BigInteger syn = leReverseToInt(toFixedBytes(ints.get(0), rb));
        return new KemCt(syn, ints.get(1), r);
    }

    private static byte[] encodeSupportSet(int[] sup) {
        int[] sorted = sup.clone();
        java.util.Arrays.sort(sorted);
        byte[] out = new byte[sorted.length * 2];
        for (int i = 0; i < sorted.length; i++) {
            out[2 * i] = (byte) (sorted[i] >> 8);
            out[2 * i + 1] = (byte) sorted[i];
        }
        return out;
    }

    private static int[] decodeSupportSet(byte[] raw, int d) {
        int[] out = new int[d];
        for (int i = 0; i < d; i++) {
            out[i] = ((raw[2 * i] & 0xff) << 8) | (raw[2 * i + 1] & 0xff);
        }
        return out;
    }

    /** Given bytes that ARE a little-endian serialization of some value,
     * reverses them and reads big-endian to recover that value. */
    private static BigInteger leReverseToInt(byte[] leBytes) {
        byte[] rev = new byte[leBytes.length];
        for (int i = 0; i < leBytes.length; i++) rev[i] = leBytes[leBytes.length - 1 - i];
        return new BigInteger(1, rev);
    }

    // -----------------------------------------------------------------
    // OPRF (TODO #201): key / client-state / evaluation encode-decode,
    // byte-for-byte with HerraduraCli/herradura.py's genpkey --algo oprf,
    // cmd_oprf_blind/cmd_oprf_eval.
    // -----------------------------------------------------------------

    /** Encodes an OPRF private key: SEQUENCE(k, nbits) — same shape as a
     * classical public key, so {@link #decodePubKey} reads it back too. */
    public static String encodeOprfPrivKey(BigInteger k, int nbits) {
        return encodePubKey(PEM_OPRF_PRIV, k, nbits);
    }

    public static PubKey decodeOprfPrivKey(String pem) {
        return decodePubKey(pem, PEM_OPRF_PRIV);
    }

    /** Encodes an OPRF client state: SEQUENCE(r, alpha, nbits). */
    public static String encodeOprfState(BigInteger r, BigInteger alpha, int nbits) {
        byte[] der = derSeq(derInt(r, nbits / 8), derInt(alpha, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(PEM_OPRF_STATE, der);
    }

    public static final class OprfState {
        public final BigInteger r;
        public final BigInteger alpha;
        public final int nbits;
        OprfState(BigInteger r, BigInteger alpha, int nbits) { this.r = r; this.alpha = alpha; this.nbits = nbits; }
    }

    public static OprfState decodeOprfState(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_OPRF_STATE)) {
            throw new IllegalArgumentException("Expected " + PEM_OPRF_STATE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new OprfState(ints.get(0), ints.get(1), gfWidth(ints.get(2), b.label));   // TODO #385
    }

    /** Encodes an OPRF evaluation: SEQUENCE(beta, nbits) — same shape as a
     * classical public key. */
    public static String encodeOprfEval(BigInteger beta, int nbits) {
        return encodePubKey(PEM_OPRF_EVAL, beta, nbits);
    }

    public static PubKey decodeOprfEval(String pem) {
        return decodePubKey(pem, PEM_OPRF_EVAL);
    }

    // -----------------------------------------------------------------
    // HPKS-WOTS-F (TODO #201): private key / public key / signature
    // encode-decode, byte-for-byte with HerraduraCli/herradura.py's
    // _encode_wots_privkey/_encode_wots_pubkey/_pack_wots_sig.
    // -----------------------------------------------------------------

    public static String encodeWotsPrivKey(byte[] masterSeed, int leafIdx) {
        byte[] der = derSeq(derInt(masterSeed), derInt(BigInteger.valueOf(leafIdx), -1));
        return pemWrap(PEM_HPKS_WOTS_PRIV, der);
    }

    public static final class WotsPrivKey {
        public final byte[] masterSeed;
        public final int leafIdx;
        WotsPrivKey(byte[] masterSeed, int leafIdx) { this.masterSeed = masterSeed; this.leafIdx = leafIdx; }
    }

    public static WotsPrivKey decodeWotsPrivKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_WOTS_PRIV)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_WOTS_PRIV + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        byte[] seed = toFixedBytes(ints.get(0), 32);
        return new WotsPrivKey(seed, ints.get(1).intValueExact());
    }

    /** Public key PEM: the L=67 chain endpoints (L*32 bytes) + L. */
    public static String encodeWotsPubKey(BigInteger[] pk) {
        byte[] blob = Wots.pkBytes(pk);
        byte[] der = derSeq(derInt(blob), derInt(BigInteger.valueOf(pk.length), -1));
        return pemWrap(PEM_HPKS_WOTS_PUB, der);
    }

    public static BigInteger[] decodeWotsPubKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_WOTS_PUB)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_WOTS_PUB + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        // The shipped parameters fix the chain count, so anything else is
        // malformed rather than merely large.
        int ell = bounded(ints.get(1), Wots.L, Wots.L, "WOTS chain count", "verify");
        int nbytes = Herradura.N / 8;
        byte[] blob = toFixedBytes(ints.get(0), ell * nbytes);
        return chunkToInts(blob, ell, nbytes);
    }

    /** Signature PEM: the L=67 chain values (L*32 bytes) + L. */
    public static String encodeWotsSig(BigInteger[] sig) {
        byte[] blob = Wots.pkBytes(sig);
        byte[] der = derSeq(derInt(blob), derInt(BigInteger.valueOf(sig.length), -1));
        return pemWrap(PEM_HPKS_WOTS_SIG, der);
    }

    public static BigInteger[] decodeWotsSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_WOTS_SIG)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_WOTS_SIG + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        // The shipped parameters fix the chain count, so anything else is
        // malformed rather than merely large.
        int ell = bounded(ints.get(1), Wots.L, Wots.L, "WOTS chain count", "verify");
        int nbytes = Herradura.N / 8;
        byte[] blob = toFixedBytes(ints.get(0), ell * nbytes);
        return chunkToInts(blob, ell, nbytes);
    }

    // -----------------------------------------------------------------
    // HPKS-XMSS-F (TODO #201): private key / public key / signature
    // encode-decode, byte-for-byte with HerraduraCli/herradura.py's
    // _encode_xmss_privkey/_encode_xmss_pubkey/_pack_xmss_sig. The next-
    // unused leaf index is authoritative in the CLI's <keyfile>.idx sidecar
    // file, not this PEM's embedded next_idx field (kept for wire-format
    // parity with the Python/C/Go CLIs).
    // -----------------------------------------------------------------

    public static String encodeXmssPrivKey(byte[] masterSeed, int h, int nextIdx, List<byte[]> leafHashes) {
        byte[] blob = concatAll(leafHashes);
        byte[] der = derSeq(derInt(masterSeed), derInt(BigInteger.valueOf(h), -1),
                             derInt(BigInteger.valueOf(nextIdx), -1), derInt(blob));
        return pemWrap(PEM_HPKS_XMSS_PRIV, der);
    }

    public static final class XmssPrivKey {
        public final byte[] masterSeed;
        public final int h;
        public final int nextIdx;
        public final List<byte[]> leafHashes;
        public final byte[] root;
        XmssPrivKey(byte[] masterSeed, int h, int nextIdx, List<byte[]> leafHashes, byte[] root) {
            this.masterSeed = masterSeed; this.h = h; this.nextIdx = nextIdx;
            this.leafHashes = leafHashes; this.root = root;
        }
    }

    public static XmssPrivKey decodeXmssPrivKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_XMSS_PRIV)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_XMSS_PRIV + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        byte[] seed = toFixedBytes(ints.get(0), 32);
        // h sizes `1 << h` leaves and the 32-bytes-per-leaf blob behind them.
        int h = bounded(ints.get(1), 1, XMSS_MAX_H, "XMSS height", "pkey");
        int nextIdx = ints.get(2).intValueExact();
        int numLeaves = 1 << h;
        byte[] blob = toFixedBytes(ints.get(3), 32 * numLeaves);
        List<byte[]> leafHashes = new ArrayList<>(numLeaves);
        for (int i = 0; i < numLeaves; i++) leafHashes.add(slice(blob, i * 32, 32));
        byte[] root = Xmss.haccumRoot(leafHashes);
        return new XmssPrivKey(seed, h, nextIdx, leafHashes, root);
    }

    /** Public key PEM: just the 32-byte Merkle root + h. */
    public static String encodeXmssPubKey(byte[] root, int h) {
        byte[] der = derSeq(derInt(root), derInt(BigInteger.valueOf(h), -1));
        return pemWrap(PEM_HPKS_XMSS_PUB, der);
    }

    public static final class XmssPubKey {
        public final byte[] root;
        public final int h;
        XmssPubKey(byte[] root, int h) { this.root = root; this.h = h; }
    }

    public static XmssPubKey decodeXmssPubKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_XMSS_PUB)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_XMSS_PUB + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new XmssPubKey(toFixedBytes(ints.get(0), 32),
                              bounded(ints.get(1), 1, XMSS_MAX_H, "XMSS height", "pkey"));
    }

    /** SEQUENCE(leaf_idx, wots_sig_blob, auth_path_blob, h, n). */
    public static String encodeXmssSig(Xmss.Signature sig) {
        byte[] sigBlob = Wots.pkBytes(sig.wotsSig);
        byte[] pathBlob = concatAll(sig.authPath);
        byte[] der = derSeq(derInt(BigInteger.valueOf(sig.leafIdx), -1), derInt(sigBlob), derInt(pathBlob),
                             derInt(BigInteger.valueOf(sig.authPath.size()), -1), derInt(BigInteger.valueOf(Herradura.N), -1));
        return pemWrap(PEM_HPKS_XMSS_SIG, der);
    }

    public static Xmss.Signature decodeXmssSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_XMSS_SIG)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_XMSS_SIG + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int leafIdx = ints.get(0).intValueExact();
        int h = bounded(ints.get(3), 1, XMSS_MAX_H, "XMSS signature depth", "verify");
        int n = boundedN(ints.get(4), "verify");
        int nbytes = n / 8;
        byte[] sigBlob = toFixedBytes(ints.get(1), Wots.L * nbytes);
        byte[] pathBlob = toFixedBytes(ints.get(2), h * 32);
        BigInteger[] wotsSig = chunkToInts(sigBlob, Wots.L, nbytes);
        List<byte[]> authPath = new ArrayList<>(h);
        for (int i = 0; i < h; i++) authPath.add(slice(pathBlob, i * 32, 32));
        return new Xmss.Signature(leafIdx, wotsSig, authPath);
    }

    private static byte[] concat(byte[]... parts) {
        return concatAll(Arrays.asList(parts));
    }

    private static byte[] concatAll(List<byte[]> parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static BigInteger[] chunkToInts(byte[] blob, int count, int chunkLen) {
        BigInteger[] out = new BigInteger[count];
        for (int i = 0; i < count; i++) out[i] = new BigInteger(1, slice(blob, i * chunkLen, chunkLen));
        return out;
    }

    // -----------------------------------------------------------------
    // HCRED (TODO #202): key / credential / proof encode-decode,
    // byte-for-byte with HerraduraCli/codec.py's encode_hcred_privkey/
    // encode_hcred_pubkey/encode_hcred_credential/encode_hcred_proof.
    //
    // Unlike every other format in this file, HCRED's private-key,
    // public-key, and proof PEM bodies are NOT DER (no SEQUENCE/INTEGER
    // tags) — they are a flat, offset-parsed byte layout, matching the
    // Python reference exactly (only the credential uses real DER, via
    // the same layout as {@link #encodeSternSig}).  Since TODO #384 the
    // width is the header's n, any of 32, 64, 128 and 256, and every field
    // is sized from it; the body length must then match exactly (rawEnd), so a
    // SMALLER n than the body holds is still refused (TODO #275).
    // -----------------------------------------------------------------

    /** TODO #384: HCRED runs at every GF width (32, 64, 128, 256), as C's
     * hcred_n_ok does since #383 stage 3; the seed and syndrome sizes follow n. */
    private static int hcredN(int n, String what) {
        if (!gfWidthOk(n))
            throw new IllegalArgumentException(what + ": n must be 32, 64, 128 or 256, got " + n);
        return n;
    }
    private static int hcredSeedNb(int n) { return n / 8; }
    private static int hcredSyndrNb(int n) { return (n / 2 + 7) / 8; }

    private static byte[] ser3(int[] vec) {
        byte[] out = new byte[vec.length * 3];
        for (int i = 0; i < vec.length; i++) {
            int c = ((vec[i] % 65537) + 65537) % 65537;
            out[3 * i] = (byte) (c >> 16);
            out[3 * i + 1] = (byte) (c >> 8);
            out[3 * i + 2] = (byte) c;
        }
        return out;
    }

    private static int[] deser3(byte[] data, int off, int count) {
        // Report a truncated packed body as a wire-format error rather than
        // letting a raw JDK index message escape (TODO #275).
        if (count < 0 || off < 0 || (long) off + (long) 3 * count > data.length)
            throw new IllegalArgumentException("packed body truncated");
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            out[i] = ((data[off] & 0xff) << 16) | ((data[off + 1] & 0xff) << 8) | (data[off + 2] & 0xff);
            off += 3;
        }
        return out;
    }

    private static byte[] ser2(int[] vec) {
        byte[] out = new byte[vec.length * 2];
        for (int i = 0; i < vec.length; i++) {
            int c = ((vec[i] % 4096) + 4096) % 4096;
            out[2 * i] = (byte) (c >> 8);
            out[2 * i + 1] = (byte) c;
        }
        return out;
    }

    private static int[] deser2(byte[] data, int off, int count) {
        // Report a truncated packed body as a wire-format error rather than
        // letting a raw JDK index message escape (TODO #275).
        if (count < 0 || off < 0 || (long) off + (long) 2 * count > data.length)
            throw new IllegalArgumentException("packed body truncated");
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            out[i] = ((data[off] & 0xff) << 8) | (data[off + 1] & 0xff);
            off += 2;
        }
        return out;
    }

    private static byte[] be32(int v) {
        return new byte[] { (byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v };
    }

    private static int readBe32(byte[] data, int off) {
        if (off < 0 || (long) off + 4 > data.length) throw new IllegalArgumentException("packed body truncated");
        return ((data[off] & 0xff) << 24) | ((data[off + 1] & 0xff) << 16)
             | ((data[off + 2] & 0xff) << 8) | (data[off + 3] & 0xff);
    }

    /** Little-endian fixed-width serialization — HCRED's syndrome field is
     * stored little-endian (matching the C port's LSB-first byte layout),
     * unlike every other integer in the suite's wire format. */
    private static byte[] toFixedBytesLE(BigInteger v, int nbytes) {
        byte[] be = toFixedBytes(v, nbytes);
        byte[] le = new byte[nbytes];
        for (int i = 0; i < nbytes; i++) le[i] = be[nbytes - 1 - i];
        return le;
    }

    private static BigInteger fromLE(byte[] data, int off, int nbytes) {
        if (off < 0 || (long) off + nbytes > data.length) throw new IllegalArgumentException("packed body truncated");
        byte[] rev = new byte[nbytes];
        for (int i = 0; i < nbytes; i++) rev[i] = data[off + nbytes - 1 - i];
        return new BigInteger(1, rev);
    }

    public static String encodeHcredPrivKey(int[] s, int[] c, int[] m, BigInteger seedH, BigInteger syndr) {
        int n = s.length;   // the polynomial's own length is the width (TODO #384)
        byte[] body = concat(be32(n), ser3(s), ser2(c), ser3(m),
                              toFixedBytes(seedH, hcredSeedNb(n)), toFixedBytesLE(syndr, hcredSyndrNb(n)));
        return pemWrap(PEM_HCRED_PRIV, body);
    }

    public static final class HcredPrivKey {
        public final int[] s, c, m;
        public final BigInteger seedH, syndr;
        public final int n;
        HcredPrivKey(int[] s, int[] c, int[] m, BigInteger seedH, BigInteger syndr, int n) {
            this.s = s; this.c = c; this.m = m; this.seedH = seedH; this.syndr = syndr; this.n = n;
        }
    }

    public static HcredPrivKey decodeHcredPrivKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HCRED_PRIV)) {
            throw new IllegalArgumentException("Expected " + PEM_HCRED_PRIV + ", got " + b.label);
        }
        byte[] body = b.der;
        int n = readBe32(body, 0);
        // The packed HCRED framings size every field from this one
        // header, so it is bounded before anything is allocated;
        // rounds == 0 additionally makes verification vacuous (TODO #275).
        hcredN(n, "HCRED private key");
        int off = 4;
        int[] s = deser3(body, off, n); off += n * 3;
        int[] c = deser2(body, off, n); off += n * 2;
        int[] m = deser3(body, off, n); off += n * 3;
        BigInteger seedH = new BigInteger(1, slice(body, off, hcredSeedNb(n))); off += hcredSeedNb(n);
        BigInteger syndr = fromLE(body, off, hcredSyndrNb(n));
        rawEnd(PEM_HCRED_PRIV, body, off + hcredSyndrNb(n));
        hcredVals(PEM_HCRED_PRIV, body, hcredVals(PEM_HCRED_PRIV, body,
                  hcredVals(PEM_HCRED_PRIV, body, 4, n, 3), n, 2), n, 3);   // s, C, m (TODO #408)
        return new HcredPrivKey(s, c, m, seedH, syndr, n);
    }

    public static String encodeHcredPubKey(int[] c, int[] m, BigInteger seedH, BigInteger syndr) {
        int n = c.length;
        byte[] body = concat(be32(n), ser2(c), ser3(m),
                              toFixedBytes(seedH, hcredSeedNb(n)), toFixedBytesLE(syndr, hcredSyndrNb(n)));
        return pemWrap(PEM_HCRED_PUB, body);
    }

    public static final class HcredPubKey {
        public final int[] c, m;
        public final BigInteger seedH, syndr;
        public final int n;
        HcredPubKey(int[] c, int[] m, BigInteger seedH, BigInteger syndr, int n) {
            this.c = c; this.m = m; this.seedH = seedH; this.syndr = syndr; this.n = n;
        }
    }

    public static HcredPubKey decodeHcredPubKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HCRED_PUB)) {
            throw new IllegalArgumentException("Expected " + PEM_HCRED_PUB + ", got " + b.label);
        }
        byte[] body = b.der;
        int n = readBe32(body, 0);
        // The packed HCRED framings size every field from this one
        // header, so it is bounded before anything is allocated;
        // rounds == 0 additionally makes verification vacuous (TODO #275).
        hcredN(n, "HCRED public key");
        int off = 4;
        int[] c = deser2(body, off, n); off += n * 2;
        int[] m = deser3(body, off, n); off += n * 3;
        BigInteger seedH = new BigInteger(1, slice(body, off, hcredSeedNb(n))); off += hcredSeedNb(n);
        BigInteger syndr = fromLE(body, off, hcredSyndrNb(n));
        rawEnd(PEM_HCRED_PUB, body, off + hcredSyndrNb(n));
        hcredVals(PEM_HCRED_PUB, body, hcredVals(PEM_HCRED_PUB, body, 4, n, 2), n, 3);   // C, m (TODO #408)
        return new HcredPubKey(c, m, seedH, syndr, n);
    }

    /** Same DER shape as {@link #encodeSternSig}/{@link #decodeSternSig}
     * (SEQUENCE(n, rounds, commits, challenges, responses)), just under
     * the HCRED CREDENTIAL label — the issuer credential is literally an
     * HPKS-Stern-F signature over the credential statement. */
    public static String encodeHcredCredential(Stern.SternSignature sig) { return encodeHcredCredential(sig, Herradura.N); }

    /** At the issuer key's width n (TODO #384). */
    public static String encodeHcredCredential(Stern.SternSignature sig, int n) {
        int rounds = sig.rounds();
        byte[] commits = packSternTriples(sig.c0, sig.c1, sig.c2, rounds, commitBytes(n));
        byte[] challenges = packChallenges(sig.challenges);
        byte[] responses = packSternPairs(sig.resp0, sig.resp1, rounds, n / 8);
        byte[] der = derSeq(derInt(BigInteger.valueOf(n), -1), derInt(BigInteger.valueOf(rounds), -1),
                             derInt(commits), derInt(challenges), derInt(responses));
        return pemWrap(PEM_HCRED_CRED, der);
    }

    public static SternSigDecoded decodeHcredCredential(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HCRED_CRED)) {
            throw new IllegalArgumentException("Expected " + PEM_HCRED_CRED + ", got " + b.label);
        }
        return decodeSternSigDer(b);
    }

    private static byte[] outsToBytes(Hcred.Outputs outs) {
        byte[][] parts = new byte[3 * 7][];
        int idx = 0;
        for (int j = 0; j < 3; j++) {
            parts[idx++] = ser3(outs.ter[j]);
            parts[idx++] = ser3(outs.bit[j]);
            parts[idx++] = ser3(outs.del[j]);
            parts[idx++] = ser3(new int[] { outs.W[j] });
            parts[idx++] = ser3(outs.S[j]);
            parts[idx++] = ser3(outs.y[j]);
            parts[idx++] = ser3(outs.rnd[j]);
        }
        return concat(parts);
    }

    private static final class OutsOffset { Hcred.Outputs outs; int off; }

    private static OutsOffset outsFromBytes(byte[] data, int off, int n, int rows, int rowBits) {
        int nb = rows * rowBits, nd = n * Hcred.EPS_BITS;
        Hcred.Outputs outs = new Hcred.Outputs();
        outs.ter = new int[3][]; outs.bit = new int[3][]; outs.del = new int[3][];
        outs.W = new int[3]; outs.S = new int[3][]; outs.y = new int[3][]; outs.rnd = new int[3][];
        for (int j = 0; j < 3; j++) {
            outs.ter[j] = deser3(data, off, n); off += n * 3;
            outs.bit[j] = deser3(data, off, nb); off += nb * 3;
            outs.del[j] = deser3(data, off, nd); off += nd * 3;
            outs.W[j] = deser3(data, off, 1)[0]; off += 3;
            outs.S[j] = deser3(data, off, rows); off += rows * 3;
            outs.y[j] = deser3(data, off, rows); off += rows * 3;
            outs.rnd[j] = deser3(data, off, n); off += n * 3;
        }
        OutsOffset result = new OutsOffset();
        result.outs = outs; result.off = off;
        return result;
    }

    public static String encodeHcredProof(Hcred.Proof proof) {
        int n = proof.n, rows = Hcred.rowsFor(n), rowBits = Hcred.rowBitsFor(n);
        int nb = rows * rowBits, nd = n * Hcred.EPS_BITS;
        List<byte[]> parts = new ArrayList<>();
        parts.add(be32(n));
        parts.add(be32(proof.W));
        parts.add(be32(proof.rounds.size()));
        for (Hcred.ProofRound rd : proof.rounds) {
            parts.add(rd.coms[0]); parts.add(rd.coms[1]); parts.add(rd.coms[2]);
            parts.add(outsToBytes(rd.outs));
            parts.add(rd.seedC); parts.add(rd.seedC1);
            parts.add(ser3(rd.a1)); parts.add(ser3(rd.b1)); parts.add(ser3(rd.g1)); parts.add(ser3(rd.h1));
            boolean hasAux = rd.auxS != null;
            parts.add(new byte[] { (byte) (hasAux ? 1 : 0) });
            if (hasAux) {
                parts.add(ser3(rd.auxS));
                parts.add(ser3(rd.auxB));
                parts.add(ser3(rd.auxD));
            }
        }
        byte[] body = concat(parts.toArray(new byte[0][]));
        return pemWrap(PEM_HCRED_PROOF, body);
    }

    public static Hcred.Proof decodeHcredProof(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HCRED_PROOF)) {
            throw new IllegalArgumentException("Expected " + PEM_HCRED_PROOF + ", got " + b.label);
        }
        byte[] body = b.der;
        int n = readBe32(body, 0);
        int w = readBe32(body, 4);
        int rounds = readBe32(body, 8);
        // The packed HCRED framings size every field from this one
        // header, so it is bounded before anything is allocated;
        // rounds == 0 additionally makes verification vacuous (TODO #275).
        hcredN(n, "HCRED proof");
        if (w <= 0 || w > Herradura.N)   // Python's bound: the widest n (codec.py _HCRED_MAX_N)
            throw new IllegalArgumentException("HCRED proof: W out of range (" + w + ")");
        if (rounds <= 0 || rounds > ZkpNl.MAX_ROUNDS)
            throw new IllegalArgumentException("HCRED proof: rounds out of range (" + rounds + ")");
        int rows = Hcred.rowsFor(n), rowBits = Hcred.rowBitsFor(n);
        int off = 12;
        List<Hcred.ProofRound> rds = new ArrayList<>(rounds);
        for (int i = 0; i < rounds; i++) {
            byte[][] coms = new byte[3][];
            for (int j = 0; j < 3; j++) { coms[j] = slice(body, off, 32); off += 32; }
            OutsOffset oo = outsFromBytes(body, off, n, rows, rowBits);
            off = oo.off;
            byte[] seedC = slice(body, off, 32); off += 32;
            byte[] seedC1 = slice(body, off, 32); off += 32;
            int[] a1 = deser3(body, off, n); off += n * 3;
            int[] b1 = deser3(body, off, n); off += n * 3;
            int nb = rows * rowBits, nd = n * Hcred.EPS_BITS;
            int[] g1 = deser3(body, off, nb); off += nb * 3;
            int[] h1 = deser3(body, off, nd); off += nd * 3;
            boolean hasAux = u8(body, off) != 0; off += 1;
            int[] auxS = null, auxB = null, auxD = null;
            if (hasAux) {
                auxS = deser3(body, off, n); off += n * 3;
                auxB = deser3(body, off, nb); off += nb * 3;
                auxD = deser3(body, off, nd); off += nd * 3;
            }
            Hcred.ProofRound rd = new Hcred.ProofRound();
            rd.coms = coms; rd.outs = oo.outs; rd.seedC = seedC; rd.seedC1 = seedC1;
            rd.a1 = a1; rd.b1 = b1; rd.g1 = g1; rd.h1 = h1;
            rd.auxS = auxS; rd.auxB = auxB; rd.auxD = auxD;
            rds.add(rd);
        }
        Hcred.Proof proof = new Hcred.Proof();
        proof.W = w; proof.rounds = rds; proof.n = n;
        rawEnd(PEM_HCRED_PROOF, body, off);
        hcredProofVals(body, n, rounds);                        // TODO #408
        return proof;
    }

    /** TODO #408: an accepted HCRED proof body walked in wire order: every Z_q
     * value below q, each has_aux 0 or 1. */
    private static void hcredProofVals(byte[] b, int n, int rounds) {
        int rows = Hcred.rowsFor(n), nb = rows * Hcred.rowBitsFor(n), nd = n * Hcred.EPS_BITS;
        int off = 12;
        for (int r = 0; r < rounds; r++) {
            off += 96;
            for (int j = 0; j < 3; j++)
                for (int c : new int[] { n, nb, nd, 1, rows, rows, n })
                    off = hcredVals(PEM_HCRED_PROOF, b, off, c, 3);
            off += 64;
            off = hcredVals(PEM_HCRED_PROOF, b, off, 2 * n + nb + nd, 3);
            if (off >= b.length) return;
            int ha = b[off] & 0xff;
            if (ha > 1)
                throw new IllegalArgumentException("malformed PEM '" + PEM_HCRED_PROOF + "': round " + r
                    + " has_aux is " + ha + ", expected 0 or 1");
            off += 1;
            if (ha == 1) off = hcredVals(PEM_HCRED_PROOF, b, off, n + nb + nd, 3);
        }
    }

    // -----------------------------------------------------------------
    // aPAKE (TODO #203): server record encode-decode, byte-for-byte with
    // HerraduraCli/herradura.py's cmd_pake_register / _load_pake_record.
    // SEQUENCE(salt[32B], B[4B], y[4B]) — B/y are 4 bytes since
    // Hpake.ZKP_N=32. Username is deliberately not part of the wire
    // format, matching the Python reference exactly.
    // -----------------------------------------------------------------

    public static String encodePakeRecord(byte[] salt, BigInteger b, BigInteger y) {
        byte[] der = derSeq(derInt(salt), derInt(b, 4), derInt(y, 4));
        return pemWrap(PEM_PAKE_RECORD, der);
    }

    public static Hpake.Record decodePakeRecord(String pem) {
        PemBlock block = pemUnwrap(pem);
        if (!block.label.equals(PEM_PAKE_RECORD)) {
            throw new IllegalArgumentException("Expected " + PEM_PAKE_RECORD + ", got " + block.label);
        }
        List<BigInteger> ints = derParseSeq(block);
        byte[] salt = toFixedBytes(ints.get(0), 32);
        return new Hpake.Record("", salt, ints.get(1), ints.get(2));
    }

    // -----------------------------------------------------------------
    // HPKS-T (threshold, TODO #106/#260): encode-decode for the five
    // phase PEMs, byte-for-byte with HerraduraCli/herradura.py's
    // encode_hpkst_commit / _nonce / _aggregate / _partial / _sig. All are
    // DER SEQUENCE of INTEGERs, with n itself DER-encoded as a fixed
    // 4-byte field (not the minimal-width default) so every field but n
    // is nbits/8 bytes wide.
    //   HPKST COMMITMENT  — SEQUENCE(R_j, C_j, n)
    //   HPKST NONCE       — SEQUENCE(k_j, n)
    //   HPKST AGGREGATE   — SEQUENCE(R, C_agg, e, n)
    //   HPKST PARTIAL     — SEQUENCE(s_j, n)
    //   HPKST SIGNATURE   — SEQUENCE(C_agg, R, s, n)
    // -----------------------------------------------------------------

    public static String encodeHpkstCommit(BigInteger rJ, BigInteger cJ, int n) {
        int nb = n / 8;
        byte[] der = derSeq(derInt(rJ, nb), derInt(cJ, nb), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(PEM_HPKST_COMMIT, der);
    }

    public static final class HpkstCommit {
        public final BigInteger rJ;
        public final BigInteger cJ;
        public final int nbits;
        HpkstCommit(BigInteger rJ, BigInteger cJ, int nbits) { this.rJ = rJ; this.cJ = cJ; this.nbits = nbits; }
    }

    public static HpkstCommit decodeHpkstCommit(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKST_COMMIT)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKST_COMMIT + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new HpkstCommit(ints.get(0), ints.get(1), runWidth(ints.get(2), Herradura.N, "n", b.label));
    }

    public static String encodeHpkstNonce(BigInteger kJ, int n) {
        int nb = n / 8;
        byte[] der = derSeq(derInt(kJ, nb), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(PEM_HPKST_NONCE, der);
    }

    public static final class HpkstNonce {
        public final BigInteger kJ;
        public final int nbits;
        HpkstNonce(BigInteger kJ, int nbits) { this.kJ = kJ; this.nbits = nbits; }
    }

    public static HpkstNonce decodeHpkstNonce(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKST_NONCE)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKST_NONCE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new HpkstNonce(ints.get(0), runWidth(ints.get(1), Herradura.N, "n", b.label));
    }

    public static String encodeHpkstAggregate(BigInteger r, BigInteger cAgg, BigInteger e, int n) {
        int nb = n / 8;
        byte[] der = derSeq(derInt(r, nb), derInt(cAgg, nb), derInt(e, nb), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(PEM_HPKST_AGGREGATE, der);
    }

    public static final class HpkstAggregate {
        public final BigInteger r;
        public final BigInteger cAgg;
        public final BigInteger e;
        public final int nbits;
        HpkstAggregate(BigInteger r, BigInteger cAgg, BigInteger e, int nbits) {
            this.r = r; this.cAgg = cAgg; this.e = e; this.nbits = nbits;
        }
    }

    public static HpkstAggregate decodeHpkstAggregate(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKST_AGGREGATE)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKST_AGGREGATE + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new HpkstAggregate(ints.get(0), ints.get(1), ints.get(2), runWidth(ints.get(3), Herradura.N, "n", b.label));
    }

    public static String encodeHpkstPartial(BigInteger sJ, int n) {
        int nb = n / 8;
        byte[] der = derSeq(derInt(sJ, nb), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(PEM_HPKST_PARTIAL, der);
    }

    public static final class HpkstPartial {
        public final BigInteger sJ;
        public final int nbits;
        HpkstPartial(BigInteger sJ, int nbits) { this.sJ = sJ; this.nbits = nbits; }
    }

    public static HpkstPartial decodeHpkstPartial(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKST_PARTIAL)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKST_PARTIAL + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new HpkstPartial(ints.get(0), runWidth(ints.get(1), Herradura.N, "n", b.label));
    }

    public static String encodeHpkstSig(BigInteger cAgg, BigInteger r, BigInteger s, int n) {
        int nb = n / 8;
        byte[] der = derSeq(derInt(cAgg, nb), derInt(r, nb), derInt(s, nb), derInt(BigInteger.valueOf(n), -1));
        return pemWrap(PEM_HPKST_SIG, der);
    }

    public static final class HpkstSig {
        public final BigInteger cAgg;
        public final BigInteger r;
        public final BigInteger s;
        public final int nbits;
        HpkstSig(BigInteger cAgg, BigInteger r, BigInteger s, int nbits) {
            this.cAgg = cAgg; this.r = r; this.s = s; this.nbits = nbits;
        }
    }

    public static HpkstSig decodeHpkstSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKST_SIG)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKST_SIG + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        return new HpkstSig(ints.get(0), ints.get(1), ints.get(2), runWidth(ints.get(3), Herradura.N, "n", b.label));
    }

    // -----------------------------------------------------------------
    // HPKS-Stern-Ring (TODO #78.I/#121/#260): encode-decode, byte-for-byte
    // with herradura.py's _pack_ring_sig/_unpack_ring_sig. Member-major,
    // round-major flat blob; per (member, round) entry:
    //   c0 || c1 || c2 || b(1 byte) || resp0 || resp1   (each n-bit value nbits/8 B)
    // PEM: SEQUENCE(k, rounds, n, blob).
    // -----------------------------------------------------------------

    public static String encodeRingSig(SternRing.RingSignature sig, int n) {
        int k = sig.ringSize();
        int rounds = sig.rounds();
        int nb = n / 8;
        int cb = commitBytes(n);
        byte[] blob = new byte[k * rounds * (3 * cb + 2 * nb + 1)];
        int off = 0;
        for (int i = 0; i < k; i++) {
            for (int r = 0; r < rounds; r++) {
                System.arraycopy(toFixedBytes(sig.c0[i][r], cb), 0, blob, off, cb); off += cb;
                System.arraycopy(toFixedBytes(sig.c1[i][r], cb), 0, blob, off, cb); off += cb;
                System.arraycopy(toFixedBytes(sig.c2[i][r], cb), 0, blob, off, cb); off += cb;
                blob[off] = (byte) sig.challenges[i][r]; off += 1;
                System.arraycopy(toFixedBytes(sig.resp0[i][r], nb), 0, blob, off, nb); off += nb;
                System.arraycopy(toFixedBytes(sig.resp1[i][r], nb), 0, blob, off, nb); off += nb;
            }
        }
        byte[] der = derSeq(derInt(BigInteger.valueOf(k), -1), derInt(BigInteger.valueOf(rounds), -1),
                             derInt(BigInteger.valueOf(n), -1), derInt(blob));
        return pemWrap(PEM_HPKS_RING_SIG, der);
    }

    public static final class RingSigDecoded {
        public final SternRing.RingSignature sig;
        public final int nbits;
        RingSigDecoded(SternRing.RingSignature sig, int nbits) { this.sig = sig; this.nbits = nbits; }
    }

    public static RingSigDecoded decodeRingSig(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_HPKS_RING_SIG)) {
            throw new IllegalArgumentException("Expected " + PEM_HPKS_RING_SIG + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b);
        int k = bounded(ints.get(0), 2, RING_MAX_K, "ring member count", "verify");
        int rounds = bounded(ints.get(1), 1, SDF_MAX_ROUNDS, "round count", "verify");
        int n = boundedSternN(ints.get(2), "verify");
        int nb = n / 8;
        int cb = commitBytes(n);
        int entry = 3 * cb + 2 * nb + 1;
        int blen = k * rounds * entry;
        BigInteger blobInt = ints.get(3);
        if (blobInt.bitLength() > blen * 8) {
            throw new IllegalArgumentException("verify: HPKS-RING signature payload exceeds k=" + k
                + " rounds=" + rounds + " n=" + n + "'s declared " + blen + " bytes");
        }
        byte[] blob = toFixedBytes(blobInt, blen);

        BigInteger[][] c0 = new BigInteger[k][rounds];
        BigInteger[][] c1 = new BigInteger[k][rounds];
        BigInteger[][] c2 = new BigInteger[k][rounds];
        int[][] challenges = new int[k][rounds];
        BigInteger[][] resp0 = new BigInteger[k][rounds];
        BigInteger[][] resp1 = new BigInteger[k][rounds];
        int off = 0;
        for (int i = 0; i < k; i++) {
            for (int r = 0; r < rounds; r++) {
                c0[i][r] = new BigInteger(1, Arrays.copyOfRange(blob, off, off + cb)); off += cb;
                c1[i][r] = new BigInteger(1, Arrays.copyOfRange(blob, off, off + cb)); off += cb;
                c2[i][r] = new BigInteger(1, Arrays.copyOfRange(blob, off, off + cb)); off += cb;
                challenges[i][r] = blob[off] & 0xFF; off += 1;
                resp0[i][r] = new BigInteger(1, Arrays.copyOfRange(blob, off, off + nb)); off += nb;
                resp1[i][r] = new BigInteger(1, Arrays.copyOfRange(blob, off, off + nb)); off += nb;
            }
        }
        return new RingSigDecoded(new SternRing.RingSignature(c0, c1, c2, challenges, resp0, resp1), n);
    }
}
