package herradurakex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TODO #198: pure-Java port of the NL-FSCX v1 primitive, the HFSCX-256
 * Merkle-Damgard/Davies-Meyer hash built on it, and the HSKE-NL-A1
 * counter-mode AEAD used by the CLI's {@code encfile}/{@code decfile}.
 *
 * These are strictly NL/PQC-family building blocks (out of {@link Herradura}'s
 * classical-quartet-only scope), but the CLI's {@code dgst} and
 * {@code encfile}/{@code decfile} subcommands need them for parity with
 * {@code HerraduraCli/herradura.py}/{@code herradura_cli.c}/
 * {@code herradura_cli.go} — this file exists only to give
 * {@link HerraduraCli} that parity, not as a general NL-FSCX port (that is
 * TODO #199's scope).
 *
 * Byte-for-byte port of "Herradura cryptographic suite.py"'s nl_fscx_v1,
 * nl_fscx_revolve_v1, hfscx_256, and HerraduraCli/herradura.py's
 * cmd_encfile/cmd_decfile (the .hkx container format).
 */
public final class Hfscx256 {
    private Hfscx256() { }

    private static final int N = Herradura.N;               // 256
    private static final int NL_V1_SHIFT = N / 4;            // 64
    private static final BigInteger MASK = Herradura.MASK;

    /** "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0" as an integer, matching
     * Python's {@code _HFSCX256_IV_BYTES}. */
    public static final BigInteger IV_CONST =
        new BigInteger(1, "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0".getBytes(StandardCharsets.US_ASCII));

    /** Matches Python's {@code _RNL_KDF_DC_256} domain constant. */
    public static final BigInteger RNL_KDF_DC_256 =
        new BigInteger("6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", 16);

    // -----------------------------------------------------------------
    // NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
    // -----------------------------------------------------------------

    public static BigInteger nlFscxV1(BigInteger a, BigInteger b) {
        BigInteger sum = a.add(b).and(MASK);
        return Herradura.fscx(a, b).xor(Herradura.rol(sum, NL_V1_SHIFT));
    }

    public static BigInteger nlFscxRevolveV1(BigInteger a, BigInteger b, int steps) {
        BigInteger result = a.and(MASK);
        for (int i = 0; i < steps; i++) {
            result = nlFscxV1(result, b);
        }
        return result;
    }

    // -----------------------------------------------------------------
    // HFSCX-256-DM: Merkle-Damgard hash, Davies-Meyer compression over
    // nl_fscx_revolve_v1
    // -----------------------------------------------------------------

    private static final int BLOCK = 32; // bytes

    /** Bare hash (iv == null) or keyed MAC (iv = key XOR IV_CONST, per the
     * suite's convention — see "Herradura cryptographic suite.py"'s hfscx_256
     * docstring). Returns 32 bytes. */
    public static byte[] hash(byte[] data, BigInteger iv) {
        BigInteger initState = (iv == null) ? IV_CONST : iv.and(MASK);
        BigInteger state = initState;

        // Padding: 0x80, then zero-fill to a multiple of 32 bytes.
        int padLen = data.length + 1;
        int rem = padLen % BLOCK;
        if (rem != 0) padLen += BLOCK - rem;
        byte[] padded = new byte[padLen + BLOCK]; // + final length block
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        // (rest already zero-initialized by `new byte[]`)

        // MD-strengthening length block, XORed with the initial state.
        BigInteger bitLen = BigInteger.valueOf((long) data.length * 8);
        byte[] lenBlock = new byte[BLOCK];
        byte[] bitLenBytes = bitLen.toByteArray();
        // Right-align bitLenBytes (up to 8 bytes) into the low 8 bytes of lenBlock.
        int copyLen = Math.min(8, bitLenBytes.length);
        System.arraycopy(bitLenBytes, bitLenBytes.length - copyLen, lenBlock, BLOCK - copyLen, copyLen);
        BigInteger lenRaw = new BigInteger(1, lenBlock);
        BigInteger lenXored = lenRaw.xor(initState).and(MASK);
        byte[] lenXoredBytes = toFixedBytes(lenXored, BLOCK);
        System.arraycopy(lenXoredBytes, 0, padded, padLen, BLOCK);

        int steps = N / 4; // 64
        for (int off = 0; off < padded.length; off += BLOCK) {
            BigInteger prev = state;
            byte[] chunk = Arrays.copyOfRange(padded, off, off + BLOCK);
            BigInteger block = new BigInteger(1, chunk);
            state = nlFscxRevolveV1(state, block, steps);
            state = state.xor(prev).and(MASK);
        }
        return toFixedBytes(state, BLOCK);
    }

    public static byte[] hash(byte[] data) {
        return hash(data, null);
    }

    /** HFSCX-256-DS: domain-separated variant — prepends a 1-byte tag before
     * hashing.  ds=0x01 generic digest, 0x02 sign pre-hash, 0x03 AEAD-MAC,
     * 0x10/0x11/0x12 the QC-MDPC KEM's FO hashes (TODO #235).  Mirrors
     * herradura.h's hfscx_256_ds. */
    public static byte[] hashDs(int ds, byte[] data) {
        byte[] buf = new byte[1 + data.length];
        buf[0] = (byte) ds;
        System.arraycopy(data, 0, buf, 1, data.length);
        return hash(buf, null);
    }

    /** Package-visible so {@link Ratchet} and other NL-family callers can
     * render a masked BigInteger state to fixed-width bytes without each
     * re-implementing the same left-zero-pad logic. */
    static byte[] toFixedBytes(BigInteger v, int nbytes) {
        byte[] raw = v.and(MASK).toByteArray();
        byte[] out = new byte[nbytes];
        int rawStart = Math.max(0, raw.length - nbytes);
        int copyLen = raw.length - rawStart;
        System.arraycopy(raw, rawStart, out, nbytes - copyLen, copyLen);
        return out;
    }

    // -----------------------------------------------------------------
    // HSKE-NL-A1 (.hkx container): CTR-mode encryption + HFSCX-256-MAC,
    // matching HerraduraCli/herradura.py's cmd_encfile/cmd_decfile
    // -----------------------------------------------------------------

    private static final byte[] HKX_MAGIC = { 'H', 'K', 'X', '1' };
    private static final int HKX_ALGO_NLA1 = 0x01;
    private static final int HKX_BLOCK = 32;

    /** Encrypts plaintext into the .hkx container format (magic, algo byte,
     * length, nonce, ciphertext blocks, 32-byte auth tag). key must be a
     * 256-bit value (already masked or not — masked internally). */
    public static byte[] encFile(BigInteger key, byte[] plaintext, SecureRandom rng) {
        BigInteger K = key.and(MASK);
        BigInteger nonce = new BigInteger(N, rng).and(MASK);
        return encFile(K, nonce, plaintext);
    }

    /** Deterministic form (explicit nonce) for KAT/test use. */
    static byte[] encFile(BigInteger key, BigInteger nonce, byte[] plaintext) {
        int steps = N / 4;
        BigInteger base = key.xor(nonce).and(MASK);
        // seed = rol(base, n/8) XOR (RNL_KDF_DC_256 >> (256 - n)); n == 256 here so the
        // shift is 0 and RNL_KDF_DC_256 is used as-is.
        BigInteger seed = Herradura.rol(base, N / 8).xor(RNL_KDF_DC_256).and(MASK);

        int plaintextLen = plaintext.length;
        int nBlocks = (plaintextLen + HKX_BLOCK - 1) / HKX_BLOCK;
        byte[] ctBlocks = new byte[nBlocks * HKX_BLOCK];
        for (int i = 0; i < nBlocks; i++) {
            int off = i * HKX_BLOCK;
            int len = Math.min(HKX_BLOCK, plaintextLen - off);
            BigInteger ks = nlFscxRevolveV1(seed, base.xor(BigInteger.valueOf(i)).and(MASK), steps);
            byte[] ksBytes = toFixedBytes(ks, HKX_BLOCK);
            for (int j = 0; j < HKX_BLOCK; j++) {
                byte p = (j < len) ? plaintext[off + j] : 0;
                ctBlocks[off + j] = (byte) (p ^ ksBytes[j]);
            }
        }

        BigInteger macKey = nlFscxRevolveV1(Herradura.rol(seed, N / 4), base, steps);
        BigInteger macIv = macKey.xor(IV_CONST).and(MASK);
        byte[] nonceBytes = toFixedBytes(nonce, HKX_BLOCK);
        byte[] macData = new byte[nonceBytes.length + 8 + ctBlocks.length];
        System.arraycopy(nonceBytes, 0, macData, 0, nonceBytes.length);
        writeBe64(macData, nonceBytes.length, plaintextLen);
        System.arraycopy(ctBlocks, 0, macData, nonceBytes.length + 8, ctBlocks.length);
        byte[] tag = hash(macData, macIv);

        byte[] out = new byte[4 + 1 + 8 + HKX_BLOCK + ctBlocks.length + 32];
        int off = 0;
        System.arraycopy(HKX_MAGIC, 0, out, off, 4); off += 4;
        out[off] = (byte) HKX_ALGO_NLA1; off += 1;
        writeBe64(out, off, plaintextLen); off += 8;
        System.arraycopy(nonceBytes, 0, out, off, HKX_BLOCK); off += HKX_BLOCK;
        System.arraycopy(ctBlocks, 0, out, off, ctBlocks.length); off += ctBlocks.length;
        System.arraycopy(tag, 0, out, off, 32);
        return out;
    }

    /** Decrypts a .hkx container produced by {@link #encFile}. Throws
     * IllegalArgumentException on any structural or authentication failure. */
    public static byte[] decFile(BigInteger key, byte[] raw) {
        if (raw.length < 77) {
            throw new IllegalArgumentException("decfile: file too short to be a valid .hkx container");
        }
        for (int i = 0; i < 4; i++) {
            if (raw[i] != HKX_MAGIC[i]) {
                throw new IllegalArgumentException("decfile: invalid magic (expected HKX1)");
            }
        }
        if ((raw[4] & 0xff) != HKX_ALGO_NLA1) {
            throw new IllegalArgumentException(
                String.format("decfile: unsupported algo byte 0x%02x", raw[4] & 0xff));
        }
        long plaintextLen = readBe64(raw, 5);
        byte[] nonceBytes = Arrays.copyOfRange(raw, 13, 13 + HKX_BLOCK);
        int nBlocks = (int) ((plaintextLen + HKX_BLOCK - 1) / HKX_BLOCK);
        int ctEnd = 45 + nBlocks * HKX_BLOCK;
        if (raw.length < ctEnd + 32) {
            throw new IllegalArgumentException("decfile: file truncated (ciphertext blocks or auth tag missing)");
        }
        byte[] ctBytes = Arrays.copyOfRange(raw, 45, ctEnd);
        byte[] tagStored = Arrays.copyOfRange(raw, ctEnd, ctEnd + 32);

        BigInteger K = key.and(MASK);
        BigInteger nonce = new BigInteger(1, nonceBytes);
        BigInteger base = K.xor(nonce).and(MASK);
        BigInteger seed = Herradura.rol(base, N / 8).xor(RNL_KDF_DC_256).and(MASK);

        int steps = N / 4;
        BigInteger macKey = nlFscxRevolveV1(Herradura.rol(seed, N / 4), base, steps);
        BigInteger macIv = macKey.xor(IV_CONST).and(MASK);
        byte[] macData = new byte[nonceBytes.length + 8 + ctBytes.length];
        System.arraycopy(nonceBytes, 0, macData, 0, nonceBytes.length);
        writeBe64(macData, nonceBytes.length, plaintextLen);
        System.arraycopy(ctBytes, 0, macData, nonceBytes.length + 8, ctBytes.length);
        byte[] tagComputed = hash(macData, macIv);

        if (!constantTimeEquals(tagStored, tagComputed)) {
            throw new IllegalArgumentException("decfile: authentication tag mismatch — file corrupt or wrong key");
        }

        byte[] plaintext = new byte[(int) plaintextLen];
        for (int i = 0; i < nBlocks; i++) {
            int off = i * HKX_BLOCK;
            BigInteger ks = nlFscxRevolveV1(seed, base.xor(BigInteger.valueOf(i)).and(MASK), steps);
            byte[] ksBytes = toFixedBytes(ks, HKX_BLOCK);
            int len = Math.min(HKX_BLOCK, plaintext.length - off);
            for (int j = 0; j < len; j++) {
                plaintext[off + j] = (byte) (ctBytes[off + j] ^ ksBytes[j]);
            }
        }
        return plaintext;
    }

    private static void writeBe64(byte[] buf, int off, long v) {
        for (int i = 0; i < 8; i++) {
            buf[off + i] = (byte) (v >>> (8 * (7 - i)));
        }
    }

    private static long readBe64(byte[] buf, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (buf[off + i] & 0xffL);
        }
        return v;
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
