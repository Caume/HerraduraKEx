package herradurakex;

import java.math.BigInteger;

/**
 * TODO #260: pure-Java port of TODO #78.A/#78.B (as fixed by #241/#242) and
 * their NL-FSCX v3 variants (TODO #255) — the FPE ("format-preserving
 * encryption", not FPE in the SP 800-38G sense — see {@link #fpeEncrypt})
 * and tweakable wide-block-cipher subcommands. C/Go/Python have carried
 * these since #241/#242 landed; Java had neither until this file.
 *
 * <p>Both primitives are {@code nl_fscx_revolve_v2} (or v3) under a subkey
 * derived from the key and a tweak, and share one derivation helper —
 * historically (before #241/#242) they derived the SAME subkey from an
 * unseparated {@code key || tweak} concatenation whenever a 12-byte FPE
 * {@code ctx} equalled a twk {@code sector_be64 || bidx_be32}, so the two
 * subcommands computed the identical function and decrypted each other's
 * output. Fixed by a per-primitive domain-separation tag in
 * {@link Hfscx256#hashDs}'s namespace, plus an 8-byte big-endian key
 * length before the key so the key/tweak boundary is unambiguous.
 *
 * <pre>
 *   B (v2) = HFSCX-256-DS(ds, len(key)_be8 || key || tweak), rejected to a
 *            non-degenerate NL-FSCX v2 subkey (nlV2KeyIsValid)
 *   B (v3) = HFSCX-256-DS(ds, len(key)_be8 || key || tweak), no rejection --
 *            v3 has no affine-degenerate class to screen for
 *   fpe:  C = nl_fscx_revolve_v{2,3}(P, B, R_VALUE / R3_VALUE);  tweak = ctx
 *   twk:  C = nl_fscx_revolve_v{2,3}(P, B, R_VALUE / R3_VALUE);
 *         tweak = sector_be64 || bidx_be32
 * </pre>
 */
public final class FpeTwk {
    private FpeTwk() { }

    private static final int N = Herradura.N;               // 256
    private static final int R_VALUE = 3 * N / 4;             // 192
    private static final BigInteger MASK = Herradura.MASK;

    private static final int FPE_DS = 0x20;
    private static final int TWK_DS = 0x21;
    private static final int FPE_V3_DS = 0x22;
    private static final int TWK_V3_DS = 0x23;

    private static byte[] be8(long v) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return out;
    }

    private static byte[] be4(int v) {
        return new byte[] { (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v };
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

    /** {@code sector_be64 || bidx_be32} — the twk tweak encoding. */
    private static byte[] twkTweak(long sector, int bidx) {
        return concat(be8(sector), be4(bidx));
    }

    /** B = HFSCX-256-DS(ds, len(key)_be8 || key || tweak), rejected to a
     * non-degenerate NL-FSCX v2 subkey. Deriving B from a hash is what
     * makes the ~2^-129 affine-degenerate class practically unreachable —
     * an attacker cannot steer a hash output without the key — so the
     * rejection loop is defence in depth, effectively never taken. */
    private static BigInteger deriveB(int ds, byte[] key, byte[] tweak) {
        byte[] h = Hfscx256.hashDs(ds, concat(be8(key.length), key, tweak));
        BigInteger b = new BigInteger(1, h).and(MASK);
        while (!HerraduraNl.nlV2KeyIsValid(b)) {
            h = Hfscx256.hashDs(ds, h);
            b = new BigInteger(1, h).and(MASK);
        }
        return b;
    }

    /** Same derivation, no rejection loop: NL-FSCX v3 has no affine-degenerate
     * subkey class to screen for (SecurityProofs-8.md §11.34.4). */
    private static BigInteger deriveBv3(int ds, byte[] key, byte[] tweak) {
        byte[] h = Hfscx256.hashDs(ds, concat(be8(key.length), key, tweak));
        return new BigInteger(1, h).and(MASK);
    }

    // -----------------------------------------------------------------
    // 78.A — FPE. NOTE: despite the name this is NOT format-preserving
    // encryption in the SP 800-38G (FF1/FF3-1) sense -- there is no radix
    // and no domain, only a 256-bit block. Deterministic: same
    // (key, ctx, plaintext) -> same ciphertext. For IND-CPA include a
    // per-record nonce in ctx.
    // -----------------------------------------------------------------

    public static BigInteger fpeEncrypt(BigInteger pt, byte[] key, byte[] ctx) {
        return HerraduraNl.nlFscxRevolveV2(pt, deriveB(FPE_DS, key, ctx), R_VALUE);
    }

    public static BigInteger fpeDecrypt(BigInteger ct, byte[] key, byte[] ctx) {
        return HerraduraNl.nlFscxRevolveV2Inv(ct, deriveB(FPE_DS, key, ctx), R_VALUE);
    }

    // -----------------------------------------------------------------
    // 78.B — tweakable wide-block cipher: each (sector, block-index) gets
    // a unique tweak, resolving HSKE-NL-A2's determinism limitation.
    // -----------------------------------------------------------------

    public static BigInteger twkEncrypt(BigInteger block, byte[] key, long sector, int bidx) {
        BigInteger b = deriveB(TWK_DS, key, twkTweak(sector, bidx));
        return HerraduraNl.nlFscxRevolveV2(block, b, R_VALUE);
    }

    public static BigInteger twkDecrypt(BigInteger ct, byte[] key, long sector, int bidx) {
        BigInteger b = deriveB(TWK_DS, key, twkTweak(sector, bidx));
        return HerraduraNl.nlFscxRevolveV2Inv(ct, b, R_VALUE);
    }

    // -----------------------------------------------------------------
    // 78.A/78.B over NL-FSCX v3 (TODO #255). Same constructions, same wire
    // shape, v3 in place of v2. Distinct DS tags from 0x20/0x21, so the
    // same (key, ctx) never produces the same subkey across the v2/v3
    // variants.
    // -----------------------------------------------------------------

    public static BigInteger fpeV3Encrypt(BigInteger pt, byte[] key, byte[] ctx) {
        return HerraduraNl.nlFscxRevolveV3(pt, deriveBv3(FPE_V3_DS, key, ctx), HerraduraNl.R3_VALUE);
    }

    public static BigInteger fpeV3Decrypt(BigInteger ct, byte[] key, byte[] ctx) {
        return HerraduraNl.nlFscxRevolveV3Inv(ct, deriveBv3(FPE_V3_DS, key, ctx), HerraduraNl.R3_VALUE);
    }

    public static BigInteger twkV3Encrypt(BigInteger block, byte[] key, long sector, int bidx) {
        BigInteger b = deriveBv3(TWK_V3_DS, key, twkTweak(sector, bidx));
        return HerraduraNl.nlFscxRevolveV3(block, b, HerraduraNl.R3_VALUE);
    }

    public static BigInteger twkV3Decrypt(BigInteger ct, byte[] key, long sector, int bidx) {
        BigInteger b = deriveBv3(TWK_V3_DS, key, twkTweak(sector, bidx));
        return HerraduraNl.nlFscxRevolveV3Inv(ct, b, HerraduraNl.R3_VALUE);
    }
}
