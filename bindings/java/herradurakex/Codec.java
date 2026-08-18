package herradurakex;

import java.math.BigInteger;
import java.util.ArrayList;
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
    public static final String PEM_HPKS_STERN_PRIV = "HERRADURA HPKS-STERN PRIVATE KEY";
    public static final String PEM_HPKS_STERN_PUB = "HERRADURA HPKS-STERN PUBLIC KEY";
    public static final String PEM_HPKE_STERN_PRIV = "HERRADURA HPKE-STERN PRIVATE KEY";
    public static final String PEM_HPKE_STERN_PUB = "HERRADURA HPKE-STERN PUBLIC KEY";
    public static final String PEM_HPKE_STERN_KEM_PRIV = "HERRADURA HPKE-STERN-KEM PRIVATE KEY";
    public static final String PEM_HPKE_STERN_KEM_PUB = "HERRADURA HPKE-STERN-KEM PUBLIC KEY";
    public static final String PEM_SESSION_KEY = "HERRADURA SESSION KEY";
    public static final String PEM_RNL_RESPONSE = "HERRADURA HKEX-RNL RESPONSE";
    public static final String PEM_SIGNATURE = "HERRADURA SIGNATURE";
    public static final String PEM_CIPHERTEXT = "HERRADURA CIPHERTEXT";
    public static final String PEM_DIGEST = "HERRADURA DIGEST";

    public static final String PEM_ZKP_RNL_PROOF = "HERRADURA ZKP-RNL PROOF";
    public static final String PEM_ZKP_NL_PRIV = "HERRADURA ZKP-NL PRIVATE KEY";
    public static final String PEM_ZKP_NL_PUB = "HERRADURA ZKP-NL PUBLIC KEY";
    public static final String PEM_ZKP_NL_PROOF = "HERRADURA ZKP-NL PROOF";

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

    /** Strips whitespace then decodes standard base64. */
    static byte[] b64Decode(String s) {
        StringBuilder clean = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
                clean.append(c);
            }
        }
        return Base64.getDecoder().decode(clean.toString());
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

    /** Parses a single PEM block, returning its label and DER bytes. */
    public static PemBlock pemUnwrap(String pem) {
        final String beginMark = "-----BEGIN ";
        int bi = pem.indexOf(beginMark);
        if (bi < 0) throw new IllegalArgumentException("PEM: missing BEGIN marker");
        String rest = pem.substring(bi + beginMark.length());

        int ei = rest.indexOf("-----");
        if (ei < 0) throw new IllegalArgumentException("PEM: malformed BEGIN line");
        String label = rest.substring(0, ei);
        rest = rest.substring(ei + 5);
        int i = 0;
        while (i < rest.length() && (rest.charAt(i) == '\r' || rest.charAt(i) == '\n')) i++;
        rest = rest.substring(i);

        int endIdx = rest.indexOf("-----END ");
        if (endIdx < 0) throw new IllegalArgumentException("PEM: missing END marker");
        byte[] der;
        try {
            der = b64Decode(rest.substring(0, endIdx));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("PEM: base64 decode: " + e.getMessage(), e);
        }
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
    public static List<BigInteger> derParseSeq(byte[] der) {
        if (der.length == 0 || der[0] != 0x30) {
            throw new IllegalArgumentException("DER: not a SEQUENCE");
        }
        Len l = derDecLen(der, 1);
        int offset = 1 + l.consumed;
        int end = offset + l.length;
        if (end > der.length) throw new IllegalArgumentException("DER: SEQUENCE body truncated");

        List<BigInteger> out = new ArrayList<>();
        while (offset < end) {
            if (der[offset] != 0x02) {
                throw new IllegalArgumentException(
                    String.format("DER: expected INTEGER tag at offset %d, got 0x%02x", offset, der[offset]));
            }
            offset++;
            Len vl = derDecLen(der, offset);
            offset += vl.consumed;
            if (vl.length > end - offset) {
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
        byte[] der = derSeq(derInt(priv, NBYTES), derInt(pub, NBYTES), derInt(BigInteger.valueOf(Herradura.N), -1));
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new PrivKey(ints.get(0), ints.get(1), ints.get(2).intValueExact());
    }

    /** Encodes a classical public key: SEQUENCE(pub, nbits). */
    public static String encodePubKey(String label, BigInteger pub) {
        byte[] der = derSeq(derInt(pub, NBYTES), derInt(BigInteger.valueOf(Herradura.N), -1));
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new PubKey(ints.get(0), ints.get(1).intValueExact());
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new AsymCt(ints.get(0), ints.get(1), ints.get(2).intValueExact());
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new SchnorrSig(ints.get(0), ints.get(1), ints.get(2), ints.get(3).intValueExact());
    }

    /** Encodes an HSKE session key: SEQUENCE(key, nbits). */
    public static String encodeSessionKey(BigInteger key, int nbits) {
        byte[] der = derSeq(derInt(key, nbits / 8), derInt(BigInteger.valueOf(nbits), -1));
        return pemWrap(PEM_SESSION_KEY, der);
    }

    public static PubKey decodeSessionKey(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_SESSION_KEY)) {
            throw new IllegalArgumentException("Expected " + PEM_SESSION_KEY + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b.der);
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
        List<BigInteger> ints = derParseSeq(b.der);
        int n = ints.get(2).intValueExact();
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
        List<BigInteger> ints = derParseSeq(b.der);
        int n = ints.get(2).intValueExact();
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
        List<BigInteger> ints = derParseSeq(b.der);
        BigInteger k = ints.get(0);
        int n = ints.get(3).intValueExact();
        int hintLen = ints.get(4).intValueExact();
        int[] cB = unpackPoly(ints.get(1), n, 2);
        BigInteger hintInt = ints.get(2);
        int[] hint = new int[hintLen];
        for (int i = 0; i < hintLen; i++) {
            hint[i] = hintInt.shiftRight(2 * i).and(BigInteger.valueOf(3)).intValueExact();
        }
        byte[] nB = (ints.size() >= 6) ? toFixedBytes(ints.get(5), RNL_NA_BYTES) : new byte[RNL_NA_BYTES];
        return new RnlResponse(k, cB, hint, n, nB);
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
    public static String encodeDigest(BigInteger digest) {
        byte[] der = derSeq(derInt(digest, 32));
        return pemWrap(PEM_DIGEST, der);
    }

    public static BigInteger decodeDigest(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_DIGEST)) {
            throw new IllegalArgumentException("Expected " + PEM_DIGEST + ", got " + b.label);
        }
        return derParseSeq(b.der).get(0);
    }

    // -----------------------------------------------------------------
    // HPKS-Stern-F / HPKE-Stern-F (TODO #200): key / ciphertext / signature
    // encode-decode, byte-for-byte with HerraduraCli/herradura.py's
    // _encode_stern_privkey/_encode_stern_pubkey/_encode_stern_ct/
    // _pack_stern_sig / _unpack_stern_sig.
    // -----------------------------------------------------------------

    /** Encodes a Stern-F private key: SEQUENCE(e, seed, n). */
    public static String encodeSternPrivKey(String label, BigInteger e, BigInteger seed) {
        byte[] der = derSeq(derInt(e, NBYTES), derInt(seed, NBYTES), derInt(BigInteger.valueOf(Herradura.N), -1));
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new SternPrivKey(ints.get(0), ints.get(1), ints.get(2).intValueExact());
    }

    /** Encodes a Stern-F public key: SEQUENCE(syndrome, seed, n). */
    public static String encodeSternPubKey(String label, BigInteger syndrome, BigInteger seed) {
        byte[] der = derSeq(derInt(syndrome, NBYTES), derInt(seed, NBYTES), derInt(BigInteger.valueOf(Herradura.N), -1));
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
        List<BigInteger> ints = derParseSeq(b.der);
        return new SternPubKey(ints.get(0), ints.get(1), ints.get(2).intValueExact());
    }

    /** Encodes an HPKE-Stern-F (demo) ciphertext: SEQUENCE(ct_syn, e_p, K, E, n). */
    public static String encodeSternCt(BigInteger ctSyn, BigInteger eP, BigInteger k, BigInteger e) {
        byte[] der = derSeq(derInt(ctSyn, NBYTES), derInt(eP, NBYTES), derInt(k, NBYTES), derInt(e, NBYTES),
                             derInt(BigInteger.valueOf(Herradura.N), -1));
        return pemWrap(PEM_CIPHERTEXT, der);
    }

    public static final class SternCt {
        public final BigInteger ctSyn;
        public final BigInteger eP;
        public final BigInteger k;
        public final BigInteger e;
        public final int nbits;
        SternCt(BigInteger ctSyn, BigInteger eP, BigInteger k, BigInteger e, int nbits) {
            this.ctSyn = ctSyn; this.eP = eP; this.k = k; this.e = e; this.nbits = nbits;
        }
    }

    public static SternCt decodeSternCt(String pem) {
        PemBlock b = pemUnwrap(pem);
        if (!b.label.equals(PEM_CIPHERTEXT)) {
            throw new IllegalArgumentException("Expected " + PEM_CIPHERTEXT + ", got " + b.label);
        }
        List<BigInteger> ints = derParseSeq(b.der);
        return new SternCt(ints.get(0), ints.get(1), ints.get(2), ints.get(3), ints.get(4).intValueExact());
    }

    /**
     * Encodes an HPKS-Stern-F signature: SEQUENCE(n, rounds, commits_packed,
     * challenges_packed, responses_packed). commits_packed is
     * (c0||c1||c2) per round; challenges_packed is 2 bits/round packed
     * 4-per-byte LSB-first; responses_packed is (resp0||resp1) per round.
     */
    public static String encodeSternSig(Stern.SternSignature sig) {
        int rounds = sig.rounds();
        byte[] commits = packSternTriples(sig.c0, sig.c1, sig.c2, rounds);
        byte[] challenges = packChallenges(sig.challenges);
        byte[] responses = packSternPairs(sig.resp0, sig.resp1, rounds);
        byte[] der = derSeq(derInt(BigInteger.valueOf(Herradura.N), -1), derInt(BigInteger.valueOf(rounds), -1),
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
        List<BigInteger> ints = derParseSeq(b.der);
        int nbits = ints.get(0).intValueExact();
        int rounds = ints.get(1).intValueExact();
        int nbytes = nbits / 8;
        byte[] commits = toFixedBytes(ints.get(2), 3 * rounds * nbytes);
        byte[] challenges = toFixedBytes(ints.get(3), (rounds + 3) / 4);
        byte[] responses = toFixedBytes(ints.get(4), 2 * rounds * nbytes);

        BigInteger[] c0 = new BigInteger[rounds], c1 = new BigInteger[rounds], c2 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            c0[i] = new BigInteger(1, slice(commits, (3 * i) * nbytes, nbytes));
            c1[i] = new BigInteger(1, slice(commits, (3 * i + 1) * nbytes, nbytes));
            c2[i] = new BigInteger(1, slice(commits, (3 * i + 2) * nbytes, nbytes));
        }
        int[] ch = unpackChallenges(challenges, rounds);
        BigInteger[] resp0 = new BigInteger[rounds], resp1 = new BigInteger[rounds];
        for (int i = 0; i < rounds; i++) {
            resp0[i] = new BigInteger(1, slice(responses, (2 * i) * nbytes, nbytes));
            resp1[i] = new BigInteger(1, slice(responses, (2 * i + 1) * nbytes, nbytes));
        }
        return new SternSigDecoded(nbits, new Stern.SternSignature(c0, c1, c2, ch, resp0, resp1));
    }

    private static byte[] packSternTriples(BigInteger[] a, BigInteger[] b, BigInteger[] c, int rounds) {
        int nbytes = NBYTES;
        byte[] out = new byte[3 * rounds * nbytes];
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(toFixedBytes(a[i], nbytes), 0, out, (3 * i) * nbytes, nbytes);
            System.arraycopy(toFixedBytes(b[i], nbytes), 0, out, (3 * i + 1) * nbytes, nbytes);
            System.arraycopy(toFixedBytes(c[i], nbytes), 0, out, (3 * i + 2) * nbytes, nbytes);
        }
        return out;
    }

    private static byte[] packSternPairs(BigInteger[] a, BigInteger[] b, int rounds) {
        int nbytes = NBYTES;
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

    private static final int QCMDPC_RB = (Stern.QCMDPC_R + 7) / 8; // 66

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
        List<BigInteger> ints = derParseSeq(b.der);
        int r = ints.get(4).intValueExact();
        int d = ints.get(5).intValueExact();
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
        List<BigInteger> ints = derParseSeq(b.der);
        int r = ints.get(1).intValueExact();
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
        List<BigInteger> ints = derParseSeq(b.der);
        int r = ints.get(2).intValueExact();
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
}
