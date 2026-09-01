package herradurakex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * TODO #260: pure-Java port of TODO #95 Option 2 (HSKE-NL-V2-Duplex) and its
 * NL-FSCX v3 counterpart (HSKE-NL-V3-Duplex, TODO #255) — a MonkeyDuplex-
 * style single-pass AEAD built directly on the NL-FSCX v2/v3 permutations.
 * C/Go/Python have carried this since it was added ("Herradura
 * cryptographic suite.{c,go,py}"'s #95 Option 2 section); Java had neither
 * the primitive nor a demo/test for it until this file.
 *
 * <p><b>RESEARCH CONSTRUCTION — not for production use without further
 * cryptanalysis.</b> Security relies on bijectivity of nl_fscx_revolve_v2
 * (proven) and the branch-number analysis Bn(M^k)&gt;=36 at n=64
 * (SecurityProofs-2.md §3.4). The differential/linear profile of
 * nl_fscx_v2 as a standalone sponge permutation has not yet been rigorously
 * analysed (see TODO #95/#99).
 *
 * <pre>
 *   state: 256-bit, rate = 128 bits (first 16 bytes), capacity = 128 bits (last 16 bytes)
 *   permutation: nl_fscx_revolve_v2(state, tweak, I_VALUE)   [v3: nl_fscx_revolve_v3(..., I3_VALUE)]
 *   tweak: HFSCX-256(DS_TWEAK || key || nonce) — fixed per (key, nonce)
 * </pre>
 *
 * v2 and v3 use distinct domain-separation strings throughout, so a v2 and a
 * v3 session under the same (key, nonce) share no state, tweak, or tag
 * input.
 */
public final class Duplex {
    private Duplex() { }

    private static final int N = Herradura.N;               // 256
    private static final int BLOCK = N / 8;                  // 32 bytes
    private static final int RATE = 16;                      // bytes = 128 bits
    private static final int I_VALUE = Herradura.I_STEPS;    // 64 (v2 sponge rounds)
    private static final int I3_VALUE = 5 * N / 16;           // 80 (v3 sponge rounds)

    private static final byte[] V2_DS_INIT = ascii("NL-V2-DUPLEX-INIT");
    private static final byte[] V2_DS_TWEAK = ascii("NL-V2-DUPLEX-TWEAK");
    private static final byte[] V2_DS_TAG = ascii("NL-V2-DUPLEX-TAG");
    private static final byte[] V3_DS_INIT = ascii("NL-V3-DUPLEX-INIT");
    private static final byte[] V3_DS_TWEAK = ascii("NL-V3-DUPLEX-TWEAK");
    private static final byte[] V3_DS_TAG = ascii("NL-V3-DUPLEX-TAG");

    private static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
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

    private static byte[] be8(long v) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return out;
    }

    /** One permutation call: nl_fscx_revolve_v{2,3}(state, tweak, I_{,3}_VALUE). */
    private static byte[] perm(byte[] stateB, BigInteger tweak, boolean v3) {
        BigInteger sa = new BigInteger(1, stateB);
        BigInteger r = v3
            ? HerraduraNl.nlFscxRevolveV3(sa, tweak, I3_VALUE)
            : HerraduraNl.nlFscxRevolveV2(sa, tweak, I_VALUE);
        return Hfscx256.toFixedBytes(r, BLOCK);
    }

    /** {@code {state (32 bytes), tweak}}. */
    private static Object[] init(byte[] keyBytes, byte[] nonceBytes, boolean v3) {
        byte[] dsInit = v3 ? V3_DS_INIT : V2_DS_INIT;
        byte[] dsTweak = v3 ? V3_DS_TWEAK : V2_DS_TWEAK;
        byte[] state = Hfscx256.hash(concat(dsInit, keyBytes, nonceBytes), null);
        byte[] tweakBytes = Hfscx256.hash(concat(dsTweak, keyBytes, nonceBytes), null);
        BigInteger tweak = new BigInteger(1, tweakBytes);
        state = perm(state, tweak, v3);
        state = perm(state, tweak, v3);
        return new Object[] { state, tweak };
    }

    /** Absorb associated data (length-prefixed, 0x80-then-zero padded to a
     * multiple of RATE) plus a domain separator marking the end of AD. */
    private static byte[] absorbAd(byte[] state, BigInteger tweak, byte[] ad, boolean v3) {
        byte[] adPrefixed0 = concat(be8(ad.length), ad);
        int rem = adPrefixed0.length % RATE;
        byte[] pad = (rem != 0)
            ? concat(new byte[] { (byte) 0x80 }, new byte[RATE - 1 - rem])
            : concat(new byte[] { (byte) 0x80 }, new byte[RATE - 1]);
        byte[] adPrefixed = concat(adPrefixed0, pad);
        for (int i = 0; i < adPrefixed.length; i += RATE) {
            for (int j = 0; j < RATE; j++) state[j] ^= adPrefixed[i + j];
            state = perm(state, tweak, v3);
        }
        state[RATE] ^= 0x01; // domain separator: end of AD
        state = perm(state, tweak, v3);
        return state;
    }

    /** {@code {ct (byte[]), state (32 bytes)}}. */
    private static Object[] duplexEncrypt(byte[] state, BigInteger tweak, byte[] pt, boolean v3) {
        if (pt.length == 0) {
            state = perm(state, tweak, v3);
            return new Object[] { new byte[0], state };
        }
        java.io.ByteArrayOutputStream ct = new java.io.ByteArrayOutputStream();
        for (int off = 0; off < pt.length; off += RATE) {
            int len = Math.min(RATE, pt.length - off);
            for (int j = 0; j < len; j++) {
                byte c = (byte) (state[j] ^ pt[off + j]);
                ct.write(c);
                state[j] ^= pt[off + j];
            }
            if (len < RATE) state[len] ^= (byte) 0x80;
            state = perm(state, tweak, v3);
        }
        return new Object[] { ct.toByteArray(), state };
    }

    /** {@code {pt (byte[]), state (32 bytes)}}. */
    private static Object[] duplexDecrypt(byte[] state, BigInteger tweak, byte[] ct, boolean v3) {
        if (ct.length == 0) {
            state = perm(state, tweak, v3);
            return new Object[] { new byte[0], state };
        }
        java.io.ByteArrayOutputStream pt = new java.io.ByteArrayOutputStream();
        for (int off = 0; off < ct.length; off += RATE) {
            int len = Math.min(RATE, ct.length - off);
            byte[] ptBlock = new byte[len];
            for (int j = 0; j < len; j++) ptBlock[j] = (byte) (state[j] ^ ct[off + j]);
            pt.write(ptBlock, 0, len);
            for (int j = 0; j < len; j++) state[j] ^= ptBlock[j];
            if (len < RATE) state[len] ^= (byte) 0x80;
            state = perm(state, tweak, v3);
        }
        return new Object[] { pt.toByteArray(), state };
    }

    /** Apply the end-of-plaintext domain separator, a final permutation,
     * and squeeze a 32-byte tag. */
    private static byte[] finalizeTag(byte[] state, BigInteger tweak, boolean v3) {
        state[RATE] ^= 0x02;
        state = perm(state, tweak, v3);
        byte[] dsTag = v3 ? V3_DS_TAG : V2_DS_TAG;
        return Hfscx256.hash(concat(state, dsTag), null);
    }

    /** Result of an encrypt call: nonce, ciphertext, tag. */
    public static final class EncResult {
        public final BigInteger nonce;
        public final byte[] ct;
        public final byte[] tag;
        EncResult(BigInteger nonce, byte[] ct, byte[] tag) {
            this.nonce = nonce;
            this.ct = ct;
            this.tag = tag;
        }
    }

    private static EncResult encrypt(BigInteger key, byte[] pt, byte[] ad, BigInteger nonce, boolean v3, SecureRandom rng) {
        if (nonce == null) nonce = new BigInteger(N, rng).and(Herradura.MASK);
        byte[] keyBytes = Hfscx256.toFixedBytes(key.and(Herradura.MASK), BLOCK);
        byte[] nonceBytes = Hfscx256.toFixedBytes(nonce, BLOCK);
        Object[] initRes = init(keyBytes, nonceBytes, v3);
        byte[] state = (byte[]) initRes[0];
        BigInteger tweak = (BigInteger) initRes[1];
        state = absorbAd(state, tweak, ad, v3);
        Object[] encRes = duplexEncrypt(state, tweak, pt, v3);
        byte[] ct = (byte[]) encRes[0];
        state = (byte[]) encRes[1];
        byte[] tag = finalizeTag(state, tweak, v3);
        return new EncResult(nonce, ct, tag);
    }

    /** Returns null (authentication failure) or the recovered plaintext. */
    private static byte[] decrypt(BigInteger key, BigInteger nonce, byte[] ct, byte[] tag, byte[] ad, boolean v3) {
        byte[] keyBytes = Hfscx256.toFixedBytes(key.and(Herradura.MASK), BLOCK);
        byte[] nonceBytes = Hfscx256.toFixedBytes(nonce, BLOCK);
        Object[] initRes = init(keyBytes, nonceBytes, v3);
        byte[] state = (byte[]) initRes[0];
        BigInteger tweak = (BigInteger) initRes[1];
        state = absorbAd(state, tweak, ad, v3);
        Object[] decRes = duplexDecrypt(state, tweak, ct, v3);
        byte[] pt = (byte[]) decRes[0];
        state = (byte[]) decRes[1];
        byte[] expected = finalizeTag(state, tweak, v3);
        if (!Hfscx256.constantTimeEquals(tag, expected)) return null;
        return pt;
    }

    // -----------------------------------------------------------------
    // HSKE-NL-V2-Duplex (RESEARCH CONSTRUCTION). Never reuse (key, nonce).
    // -----------------------------------------------------------------

    public static EncResult v2Encrypt(BigInteger key, byte[] pt, byte[] ad, BigInteger nonce, SecureRandom rng) {
        return encrypt(key, pt, ad, nonce, false, rng);
    }

    public static EncResult v2Encrypt(BigInteger key, byte[] pt, byte[] ad, SecureRandom rng) {
        return encrypt(key, pt, ad, null, false, rng);
    }

    public static byte[] v2Decrypt(BigInteger key, BigInteger nonce, byte[] ct, byte[] tag, byte[] ad) {
        return decrypt(key, nonce, ct, tag, ad, false);
    }

    // -----------------------------------------------------------------
    // HSKE-NL-V3-Duplex (RESEARCH CONSTRUCTION, TODO #255). Identical to
    // the v2 duplex but over nl_fscx_revolve_v3 at I3_VALUE = 80, with its
    // own domain-separation strings. Never reuse (key, nonce).
    // -----------------------------------------------------------------

    public static EncResult v3Encrypt(BigInteger key, byte[] pt, byte[] ad, BigInteger nonce, SecureRandom rng) {
        return encrypt(key, pt, ad, nonce, true, rng);
    }

    public static EncResult v3Encrypt(BigInteger key, byte[] pt, byte[] ad, SecureRandom rng) {
        return encrypt(key, pt, ad, null, true, rng);
    }

    public static byte[] v3Decrypt(BigInteger key, BigInteger nonce, byte[] ct, byte[] tag, byte[] ad) {
        return decrypt(key, nonce, ct, tag, ad, true);
    }
}
