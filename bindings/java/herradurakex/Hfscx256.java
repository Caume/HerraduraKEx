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
    private static final BigInteger MASK = Herradura.MASK;

    /** "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0" as an integer, matching
     * Python's {@code _HFSCX256_IV_BYTES}. */
    public static final BitArray IV_CONST = BitArray.fromBytes(
        "HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0".getBytes(StandardCharsets.US_ASCII), N);

    /** Matches Python's {@code _RNL_KDF_DC_256} domain constant.  The value
     * now lives in {@link BitArray#RNL_KDF_DC_256}, with the ONE truncation
     * (BITARRAY.md §4.4) beside it; this alias is kept for callers. */
    public static final BitArray RNL_KDF_DC_256 = BitArray.RNL_KDF_DC_256;

    // -----------------------------------------------------------------
    // NL-FSCX v1: fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
    // -----------------------------------------------------------------

    /** The rotation is n/4 at the OPERAND's width.  It was a static
     * {@code NL_V1_SHIFT = N / 4} — correct at 256 and at no other width — and
     * that constant is what kept this port's HSKE-NL-A1 keystream disagreeing
     * with C, Go and Python below 256 bits AFTER the BitArray itself conformed
     * (TODO #314 pass 6).  Conforming to the type is not the same as consuming
     * it at the value's width. */
    public static BitArray nlFscxV1(BitArray a, BitArray b) {
        return Herradura.fscx(a, b).xor(a.addMod2n(b).rotLeft(a.size() / 4));
    }

    public static BitArray nlFscxRevolveV1(BitArray a, BitArray b, int steps) {
        BitArray result = a;
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
    public static byte[] hash(byte[] data, BitArray iv) {
        BitArray initState = (iv == null) ? IV_CONST : iv;
        BitArray state = initState;

        // Padding: 0x80, then zero-fill to a multiple of 32 bytes.
        int padLen = data.length + 1;
        int rem = padLen % BLOCK;
        if (rem != 0) padLen += BLOCK - rem;
        byte[] padded = new byte[padLen + BLOCK]; // + final length block
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        // (rest already zero-initialized by `new byte[]`)

        // MD-strengthening length block, XORed with the initial state.
        long bitLen = (long) data.length * 8;
        byte[] lenBlock = new byte[BLOCK];
        for (int i = 0; i < 8; i++) lenBlock[BLOCK - 1 - i] = (byte) (bitLen >>> (8 * i));
        BitArray lenXored = BitArray.fromBytes(lenBlock, N).xor(initState);
        System.arraycopy(lenXored.toBytes(), 0, padded, padLen, BLOCK);

        int steps = N / 4; // 64
        for (int off = 0; off < padded.length; off += BLOCK) {
            BitArray prev = state;
            BitArray block = BitArray.fromBytes(Arrays.copyOfRange(padded, off, off + BLOCK), N);
            state = nlFscxRevolveV1(state, block, steps);
            state = state.xor(prev);
        }
        return state.toBytes();
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
    /**
     * HMAC-HFSCX-256-DM (SecurityProofs-6.md 11.9.6), the suite's keyed PRF:
     * {@code HMAC(K, D) = HFSCX-256((K^opad) || HFSCX-256((K^ipad) || D))}
     * with ipad = 0x36 and opad = 0x5C repeated 32 times.  The key must be
     * exactly 32 bytes -- an over-length key is the CALLER's to hash down, as
     * it is in C, Go and Python, so that all four reject the same inputs.
     *
     * Ported by TODO #268; TODO #261's manifest carried this as Java's one
     * acknowledged missing hash primitive.
     */
    public static byte[] hmacHfscx256(byte[] key, byte[] data) {
        if (key.length != 32) {
            throw new IllegalArgumentException("hmacHfscx256: key must be 32 bytes");
        }
        byte[] ipadKey = new byte[32];
        byte[] opadKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            ipadKey[i] = (byte) (key[i] ^ 0x36);
            opadKey[i] = (byte) (key[i] ^ 0x5C);
        }
        byte[] inner = new byte[32 + data.length];
        System.arraycopy(ipadKey, 0, inner, 0, 32);
        System.arraycopy(data, 0, inner, 32, data.length);
        byte[] innerHash = hash(inner);
        byte[] outer = new byte[64];
        System.arraycopy(opadKey, 0, outer, 0, 32);
        System.arraycopy(innerHash, 0, outer, 32, 32);
        return hash(outer);
    }

    /**
     * Right-align a BigInteger into a fixed-width buffer.
     *
     * <p>THIS IS THE RE-WIDENING STEP BITARRAY.md §1.1 WARNS ABOUT, written out
     * by hand: {@code toByteArray()} normalises leading zero octets away — the
     * very information a width carries — so every value that leaves an integer
     * has to be re-padded, and every site that forgets is a silent bug.  It
     * survives for the BigInteger values the specification does not govern
     * (DER INTEGERs, syndromes, scalars).  A BitArray needs none of it:
     * {@link BitArray#toBytes()} is a copy of the stored octets.
     */
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
    public static byte[] encFile(BitArray key, byte[] plaintext, SecureRandom rng) {
        BitArray K = key;
        BitArray nonce = BitArray.random(N, rng);
        return encFile(K, nonce, plaintext);
    }

    /** Deterministic form (explicit nonce) for KAT/test use. */
    static byte[] encFile(BitArray key, BitArray nonce, byte[] plaintext) {
        int steps = N / 4;
        BitArray base = key.xor(nonce);
        // TODO #314 pass 5: ONE named truncation, in one place.  This site used
        // to transcribe `rol(base, n/8) XOR RNL_KDF_DC_256` with a comment
        // explaining that the shift is 0 at n = 256 — the shape TODO #312 found
        // in Python, and the reason this port could not have "exactly one
        // truncation" however carefully each copy was written.
        BitArray seed = BitArray.rnlKdfSeed(base);

        int plaintextLen = plaintext.length;
        int nBlocks = (plaintextLen + HKX_BLOCK - 1) / HKX_BLOCK;
        byte[] ctBlocks = new byte[nBlocks * HKX_BLOCK];
        for (int i = 0; i < nBlocks; i++) {
            int off = i * HKX_BLOCK;
            int len = Math.min(HKX_BLOCK, plaintextLen - off);
            byte[] ksBytes = nlFscxRevolveV1(seed, base.xorUint(i), steps).toBytes();
            for (int j = 0; j < HKX_BLOCK; j++) {
                byte p = (j < len) ? plaintext[off + j] : 0;
                ctBlocks[off + j] = (byte) (p ^ ksBytes[j]);
            }
        }

        BitArray macKey = nlFscxRevolveV1(seed.rotLeft(N / 4), base, steps);
        BitArray macIv = macKey.xor(IV_CONST);
        byte[] nonceBytes = nonce.toBytes();
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
    public static byte[] decFile(BitArray key, byte[] raw) {
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

        BitArray K = key;
        BitArray nonce = BitArray.fromBytes(nonceBytes, N);
        BitArray base = K.xor(nonce);
        BitArray seed = BitArray.rnlKdfSeed(base);      // the one truncation

        int steps = N / 4;
        BitArray macKey = nlFscxRevolveV1(seed.rotLeft(N / 4), base, steps);
        BitArray macIv = macKey.xor(IV_CONST);
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
            byte[] ksBytes = nlFscxRevolveV1(seed, base.xorUint(i), steps).toBytes();
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

    /** Package-visible so {@link Duplex} (and any other NL-family AEAD) can
     * share one constant-time tag comparison instead of each re-implementing
     * it. */
    static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
