package herradurakex;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * TODO #201: pure-Java port of HPKS-WOTS-F, the suite's Winternitz
 * one-time signature scheme (TODO #97/#102/#120).
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s
 * _wots_h / _wots_chain / _wots_msg_to_digits / _wots_leaf_seed /
 * hpks_wots_keygen / hpks_wots_sign / hpks_wots_recover_pk /
 * hpks_wots_verify / _wots_pk_bytes.
 *
 * <b>Not RFC 8391 WOTS+</b>: this is the suite's own construction — a
 * single deterministic hash chain (no ADRS/bitmask randomization layer).
 * The suite's own naming ("HPKS-WOTS-F") is preserved rather than implying
 * standard-compliance.
 *
 * <b>One-time only</b>: signing twice with the same (master_seed, leafIdx)
 * pair leaks enough hash-chain values to forge signatures for other
 * messages. This class is stateless and takes leafIdx explicitly; state
 * (a used/unused flag, or — for {@link Xmss} — a next-leaf-index counter)
 * is the caller's responsibility, matching the Python CLI's `.idx`
 * sidecar-file convention (see {@link HerraduraCli}).
 */
public final class Wots {
    private Wots() { }

    private static final int N = Herradura.N; // 256
    static final int W = 16;          // Winternitz width
    private static final int LOG2W = 4;
    static final int L1 = N / LOG2W;  // 64 — message digits
    static final int L2 = 3;          // checksum digits
    static final int L = L1 + L2;     // 67 — total chains

    /** Single WOTS-F hash chain step: h(x) = nl_fscx_revolve_v1(ROL(x,n/8), x, n/4). */
    static BigInteger h(BigInteger x) {
        return Hfscx256.nlFscxRevolveV1(Herradura.rol(x, N / 8), x, N / 4);
    }

    static BigInteger chain(BigInteger x, int steps) {
        BigInteger v = x;
        for (int i = 0; i < steps; i++) v = h(v);
        return v;
    }

    /** Encodes a 256-bit message hash as L=67 base-16 digits with checksum. */
    static int[] msgToDigits(byte[] msgHash) {
        BigInteger val = new BigInteger(1, msgHash);
        int[] digits = new int[L];
        for (int i = 0; i < L1; i++) {
            digits[i] = val.shiftRight(4 * (L1 - 1 - i)).and(BigInteger.valueOf(0xF)).intValue();
        }
        int checksum = 0;
        for (int i = 0; i < L1; i++) checksum += (W - 1 - digits[i]);
        for (int i = 0; i < L2; i++) {
            digits[L1 + i] = (checksum >> (4 * (L2 - 1 - i))) & 0xF;
        }
        return digits;
    }

    static BigInteger leafSeed(byte[] masterSeed, int leafIdx, int chainIdx) {
        byte[] buf = new byte[masterSeed.length + 4 + 2];
        System.arraycopy(masterSeed, 0, buf, 0, masterSeed.length);
        int off = masterSeed.length;
        buf[off] = (byte) (leafIdx >>> 24); buf[off + 1] = (byte) (leafIdx >>> 16);
        buf[off + 2] = (byte) (leafIdx >>> 8); buf[off + 3] = (byte) leafIdx;
        off += 4;
        buf[off] = (byte) (chainIdx >>> 8); buf[off + 1] = (byte) chainIdx;
        return new BigInteger(1, Hfscx256.hash(buf));
    }

    public static final class Keypair {
        public final BigInteger[] sk; // length L, private
        public final BigInteger[] pk; // length L, public
        Keypair(BigInteger[] sk, BigInteger[] pk) { this.sk = sk; this.pk = pk; }
    }

    /** WOTS-F keygen for one leaf: pk_i = h^(w-1)(sk_i). */
    public static Keypair keygen(byte[] masterSeed, int leafIdx) {
        BigInteger[] sk = new BigInteger[L];
        BigInteger[] pk = new BigInteger[L];
        for (int i = 0; i < L; i++) {
            sk[i] = leafSeed(masterSeed, leafIdx, i);
            pk[i] = chain(sk[i], W - 1);
        }
        return new Keypair(sk, pk);
    }

    public static final class Signature {
        public final BigInteger[] sig; // length L
        Signature(BigInteger[] sig) { this.sig = sig; }
    }

    /** WOTS-F sign: sig_i = h^(w-1-d_i)(sk_i). */
    public static Signature sign(byte[] msg, byte[] masterSeed, int leafIdx) {
        byte[] msgHash = Hfscx256.hash(msg);
        int[] digits = msgToDigits(msgHash);
        Keypair kp = keygen(masterSeed, leafIdx);
        BigInteger[] sig = new BigInteger[L];
        for (int i = 0; i < L; i++) sig[i] = chain(kp.sk[i], W - 1 - digits[i]);
        return new Signature(sig);
    }

    /** Applies h^{d_i}(sig_i) to recover the WOTS public key from a signature. */
    public static BigInteger[] recoverPk(byte[] msg, BigInteger[] sig) {
        byte[] msgHash = Hfscx256.hash(msg);
        int[] digits = msgToDigits(msgHash);
        BigInteger[] pk = new BigInteger[L];
        for (int i = 0; i < L; i++) pk[i] = chain(sig[i], digits[i]);
        return pk;
    }

    /** WOTS-F verify: accept iff h^{d_i}(sig_i) == pk_i for all i. */
    public static boolean verify(byte[] msg, BigInteger[] sig, BigInteger[] pk) {
        BigInteger[] recovered = recoverPk(msg, sig);
        return Arrays.equals(recovered, pk);
    }

    /** Serializes a WOTS public key (L values) to L*(N/8) bytes. */
    public static byte[] pkBytes(BigInteger[] pk) {
        int nbytes = N / 8;
        byte[] out = new byte[L * nbytes];
        for (int i = 0; i < L; i++) {
            System.arraycopy(toFixedBytes(pk[i], nbytes), 0, out, i * nbytes, nbytes);
        }
        return out;
    }

    static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }
}
